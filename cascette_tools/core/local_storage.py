"""Local CASC storage implementation matching Battle.net structure.

This module implements the official CASC directory structure:
- Data/data/ - Local CASC archives (bucket-based)
- Data/indices/ - CDN archive indices
- Data/config/ - Configuration files
- Data/shmem/ - Shared memory files

Key concepts:
1. 16 hash buckets (0x00-0x0F): Encoding key's first byte & 0x0F
2. Index files (.idx): Map 9-byte truncated keys to archive locations
3. Data files (.data): Sequential content storage
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import structlog

logger = structlog.get_logger()


# CASC directory constants
DATA_DIR = "data"
INDICES_DIR = "indices"
CONFIG_DIR = "config"
SHMEM_DIR = "shmem"


@dataclass
class LocalIndexEntry:
    """Entry in a local index file (18-byte format).

    Format:
    - 9 bytes: Truncated encoding key
    - 5 bytes: Archive location (1 byte high + 4 bytes packed)
    - 4 bytes: Size (little-endian)
    """
    key: bytes  # 9 bytes truncated encoding key
    archive_id: int  # Archive file number
    archive_offset: int  # Offset within archive
    size: int  # Content size

    def to_bytes(self) -> bytes:
        """Serialize entry to 18 bytes."""
        # Key (9 bytes)
        key_bytes = self.key[:9].ljust(9, b'\x00')

        # Archive location (5 bytes)
        # High byte: upper bits of archive_id
        index_high = (self.archive_id >> 2) & 0xFF
        # Low 4 bytes: lower 2 bits of archive_id in top 2 bits + 30-bit offset
        archive_low = self.archive_id & 0x03
        index_low = (archive_low << 30) | (self.archive_offset & 0x3FFFFFFF)

        # Pack as big-endian
        location_bytes = struct.pack('>B', index_high) + struct.pack('>I', index_low)

        # Size (4 bytes, little-endian)
        size_bytes = struct.pack('<I', self.size)

        return key_bytes + location_bytes + size_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> LocalIndexEntry:
        """Parse entry from 18 bytes."""
        if len(data) < 18:
            raise ValueError(f"Entry data too small: {len(data)} < 18")

        key = data[:9]

        # Parse archive location (5 bytes)
        index_high = data[9]
        index_low = struct.unpack('>I', data[10:14])[0]

        # Extract archive ID and offset
        archive_id = (index_high << 2) | (index_low >> 30)
        archive_offset = index_low & 0x3FFFFFFF

        # Parse size (little-endian)
        size = struct.unpack('<I', data[14:18])[0]

        return cls(key=key, archive_id=archive_id, archive_offset=archive_offset, size=size)


@dataclass
class LocalIndexHeader:
    """Header for local index file (V7 format).

    Format (16 bytes):
    - 4 bytes: Block size (little-endian)
    - 4 bytes: Block hash (Jenkins)
    - 2 bytes: Version (0x07)
    - 1 byte: Bucket (0x00-0x0F)
    - 1 byte: Extra bytes (0)
    - 1 byte: Encoded size length (4)
    - 1 byte: Storage offset length (5)
    - 1 byte: EKey length (9)
    - 1 byte: File offset bits (30)
    """
    version: int = 7
    bucket: int = 0
    extra_bytes: int = 0
    encoded_size_length: int = 4
    storage_offset_length: int = 5
    ekey_length: int = 9
    file_offset_bits: int = 30

    def to_bytes(self) -> bytes:
        """Serialize header to 16 bytes (without guarded block header)."""
        return struct.pack(
            '<HBBBBBB',
            self.version,
            self.bucket,
            self.extra_bytes,
            self.encoded_size_length,
            self.storage_offset_length,
            self.ekey_length,
            self.file_offset_bits
        )


def compute_bucket(encoding_key: bytes) -> int:
    """Compute bucket ID from encoding key.

    Args:
        encoding_key: Encoding key (at least 1 byte)

    Returns:
        Bucket ID (0x00-0x0F)
    """
    if not encoding_key:
        return 0
    return encoding_key[0] & 0x0F


def format_idx_filename(bucket: int, generation: int = 1) -> str:
    """Format index filename for a bucket.

    Args:
        bucket: Bucket ID (0x00-0x0F)
        generation: File generation number

    Returns:
        Filename like "0000000001.idx" or "0f00000001.idx"
    """
    return f"{bucket:02x}{generation:08d}.idx"


def format_data_filename(archive_id: int) -> str:
    """Format data filename for an archive.

    Args:
        archive_id: Archive ID

    Returns:
        Filename like "data.000" or "data.001"
    """
    return f"data.{archive_id:03d}"


class LocalStorage:
    """Manages local CASC storage structure."""

    def __init__(self, base_path: Path):
        """Initialize local storage.

        Args:
            base_path: Base installation directory (e.g., /path/to/wow)
        """
        self.base_path = base_path
        self.data_path = base_path / "Data" / DATA_DIR
        self.indices_path = base_path / "Data" / INDICES_DIR
        self.config_path = base_path / "Data" / CONFIG_DIR
        self.shmem_path = base_path / "Data" / SHMEM_DIR

        # Track current archive state
        self.current_archive_id = 0
        self.current_archive_offset = 0
        self.bucket_entries: dict[int, list[LocalIndexEntry]] = {i: [] for i in range(16)}

        # Track generation numbers for each bucket (starts at 1)
        self.bucket_generations: dict[int, int] = {i: 1 for i in range(16)}

    def initialize(self) -> None:
        """Create directory structure matching Battle.net."""
        logger.info(f"Initializing CASC storage at {self.base_path}")

        # Create directories
        for path in [self.data_path, self.indices_path, self.config_path, self.shmem_path]:
            path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {path}")

        # Detect existing generation numbers from index files
        self._detect_existing_generations()

    def _detect_existing_generations(self) -> None:
        """Detect existing index file generations and set next generation."""
        import re

        if not self.data_path.exists():
            return

        # Pattern: {bucket:02x}{generation:08d}.idx
        idx_pattern = re.compile(r'^([0-9a-f]{2})(\d{8})\.idx$', re.IGNORECASE)

        for idx_file in self.data_path.glob('*.idx'):
            match = idx_pattern.match(idx_file.name)
            if match:
                bucket = int(match.group(1), 16)
                generation = int(match.group(2))
                # Set to next generation (increment existing max)
                if generation >= self.bucket_generations[bucket]:
                    self.bucket_generations[bucket] = generation + 1

        logger.debug(f"Detected generations: {self.bucket_generations}")

    def _write_empty_index(self, path: Path, bucket: int) -> None:
        """Write an empty index file for a bucket."""
        header = LocalIndexHeader(bucket=bucket)
        header_data = header.to_bytes()

        # Calculate Jenkins hash of header
        header_hash = jenkins_hash(header_data)

        # Write guarded block header + header data
        with open(path, 'wb') as f:
            f.write(struct.pack('<I', len(header_data)))  # Block size
            f.write(struct.pack('<I', header_hash))  # Block hash
            f.write(header_data)

        logger.debug(f"Created empty index: {path}")

    def write_content(self, encoding_key: bytes, data: bytes) -> LocalIndexEntry:
        """Write content to local storage.

        Args:
            encoding_key: Full encoding key (16 bytes)
            data: Content data to write

        Returns:
            Index entry for the written content
        """
        # Determine bucket
        bucket = compute_bucket(encoding_key)

        # Write to current data file
        data_path = self.data_path / format_data_filename(self.current_archive_id)

        # Check if we need a new archive (1GB limit)
        if self.current_archive_offset + len(data) > 0x40000000:
            self.current_archive_id += 1
            self.current_archive_offset = 0
            data_path = self.data_path / format_data_filename(self.current_archive_id)

        # Write content
        with open(data_path, 'ab') as f:
            f.write(data)

        # Create index entry
        entry = LocalIndexEntry(
            key=encoding_key[:9],
            archive_id=self.current_archive_id,
            archive_offset=self.current_archive_offset,
            size=len(data)
        )

        # Update offset and track entry
        self.current_archive_offset += len(data)
        self.bucket_entries[bucket].append(entry)

        return entry

    def flush_indices(self) -> None:
        """Write all bucket entries to index files."""
        for bucket in range(16):
            entries = self.bucket_entries[bucket]
            if not entries:
                continue

            generation = self.bucket_generations[bucket]
            idx_path = self.data_path / format_idx_filename(bucket, generation)
            self._write_index_file(idx_path, bucket, entries)
            logger.info(f"Wrote index {idx_path.name}: {len(entries)} entries")

        # Create shmem file
        self._write_shmem_file()

    def _write_shmem_file(self) -> None:
        """Write the shmem file with generation numbers."""
        shmem_file = self.data_path / "shmem"

        # Build the shmem content
        # Format based on analysis of real Battle.net shmem files:
        # - 4 bytes: Version (5)
        # - 4 bytes: Path string length
        # - Variable: Path string "Global\{path}"
        # - Padding to offset 0x100
        # - Various metadata
        # - At offset 0x110: 16 x 4-byte generation numbers

        # Create path string (Windows-style for compatibility)
        data_path_str = str(self.data_path).replace('/', '\\')
        path_string = f"Global\\{data_path_str}"
        path_bytes = path_string.encode('utf-8')

        # Start building the shmem content
        shmem_size = 0x5000  # 20KB like real installations
        shmem = bytearray(shmem_size)

        # Version (offset 0x00)
        struct.pack_into('<I', shmem, 0, 5)

        # Path string length (offset 0x04)
        struct.pack_into('<I', shmem, 4, len(path_bytes) + 1)

        # Path string (offset 0x08)
        shmem[8:8 + len(path_bytes)] = path_bytes

        # Generation numbers at offset 0x110 (16 x 4-byte little-endian)
        for bucket in range(16):
            offset = 0x110 + (bucket * 4)
            struct.pack_into('<I', shmem, offset, self.bucket_generations[bucket])

        # Some additional fields observed in real shmem files
        # Offset 0x108: Archive count (seems to be number of data files)
        struct.pack_into('<I', shmem, 0x108, self.current_archive_id + 1)

        # Offset 0x10C: Something (often 0x1000 = 4096)
        struct.pack_into('<I', shmem, 0x10C, 0x1000)

        # Offset 0x150: Number of buckets (3) and archive ID
        struct.pack_into('<I', shmem, 0x150, 3)
        struct.pack_into('<I', shmem, 0x154, 1)

        # Write the file
        shmem_file.write_bytes(bytes(shmem))
        logger.info(f"Created shmem file: {shmem_file}")

    def _write_index_file(self, path: Path, bucket: int, entries: list[LocalIndexEntry]) -> None:
        """Write index file with entries."""
        header = LocalIndexHeader(bucket=bucket)
        header_data = header.to_bytes()

        # Serialize entries
        entries_data = b''.join(entry.to_bytes() for entry in entries)

        # Calculate hashes
        header_hash = jenkins_hash(header_data)
        entries_hash = jenkins_hash(entries_data)

        with open(path, 'wb') as f:
            # Write header block
            f.write(struct.pack('<I', len(header_data)))
            f.write(struct.pack('<I', header_hash))
            f.write(header_data)

            # Write entries block
            f.write(struct.pack('<I', len(entries_data)))
            f.write(struct.pack('<I', entries_hash))
            f.write(entries_data)

    def save_cdn_index(self, archive_hash: str, data: bytes) -> Path:
        """Save a downloaded CDN archive index.

        Args:
            archive_hash: Archive hash
            data: Index file data

        Returns:
            Path to saved file
        """
        path = self.indices_path / f"{archive_hash.lower()}.index"
        path.write_bytes(data)
        return path

    def save_config(self, config_hash: str, data: bytes) -> Path:
        """Save a configuration file.

        Args:
            config_hash: Config hash
            data: Config file data

        Returns:
            Path to saved file
        """
        # Create hash-based subdirectory structure
        h = config_hash.lower()
        subdir = self.config_path / h[:2] / h[2:4]
        subdir.mkdir(parents=True, exist_ok=True)

        path = subdir / h
        path.write_bytes(data)
        return path

    def get_statistics(self) -> dict:
        """Get storage statistics."""
        stats = {
            'base_path': str(self.base_path),
            'total_entries': sum(len(entries) for entries in self.bucket_entries.values()),
            'buckets': {},
        }

        for bucket in range(16):
            entries = self.bucket_entries[bucket]
            if entries:
                total_size = sum(e.size for e in entries)
                stats['buckets'][f'{bucket:02x}'] = {
                    'count': len(entries),
                    'total_size': total_size
                }

        return stats


def jenkins_hash(data: bytes) -> int:
    """Compute Jenkins one-at-a-time hash.

    Args:
        data: Data to hash

    Returns:
        32-bit hash value
    """
    hash_value = 0
    for byte in data:
        hash_value += byte
        hash_value += (hash_value << 10) & 0xFFFFFFFF
        hash_value ^= (hash_value >> 6)
        hash_value &= 0xFFFFFFFF

    hash_value += (hash_value << 3) & 0xFFFFFFFF
    hash_value ^= (hash_value >> 11)
    hash_value += (hash_value << 15) & 0xFFFFFFFF
    hash_value &= 0xFFFFFFFF

    return hash_value
