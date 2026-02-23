"""Local CASC storage implementation matching Battle.net structure.

This module implements the official CASC directory structure:
- Data/data/ - Local CASC archives (bucket-based)
- Data/indices/ - CDN archive indices
- Data/config/ - Configuration files
- Data/shmem/ - Shared memory files

Key concepts:
1. 16 hash buckets (0x00-0x0F): XOR-fold of first 9 encoding key bytes
2. Index files (.idx): Map 9-byte truncated keys to archive locations
3. Data files (.data): Sequential content storage
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from cascette_tools.core.integrity import IntegrityError
from cascette_tools.crypto.jenkins import hashlittle, hashlittle2

logger = structlog.get_logger()


# CASC directory constants
DATA_DIR = "data"
INDICES_DIR = "indices"
CONFIG_DIR = "config"
SHMEM_DIR = "shmem"
ECACHE_DIR = "ecache"


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
class UpdateEntry:
    """Entry in the update section of a V7 index file (24-byte format).

    The update section uses an LSM-tree structure with 512-byte pages.
    Each entry is 24 bytes:
    - 4 bytes: Hash guard (LE) — hashlittle(entry_bytes[4:24], 0) | 0x80000000
    - 9 bytes: Truncated encoding key
    - 5 bytes: Archive location (same packing as LocalIndexEntry)
    - 4 bytes: Size (LE)
    - 1 byte: Status (0=normal, 3=delete, 6=hdr-nonres, 7=data-nonres)
    - 1 byte: Padding
    """

    hash_guard: int  # 4 bytes LE
    key: bytes  # 9 bytes truncated encoding key
    archive_id: int
    archive_offset: int
    size: int  # 4 bytes LE
    status: int  # 1 byte

    def to_bytes(self) -> bytes:
        """Serialize entry to 24 bytes."""
        key_bytes = self.key[:9].ljust(9, b'\x00')

        # Archive location (5 bytes, same as LocalIndexEntry)
        index_high = (self.archive_id >> 2) & 0xFF
        archive_low = self.archive_id & 0x03
        index_low = (archive_low << 30) | (self.archive_offset & 0x3FFFFFFF)
        location_bytes = struct.pack('>B', index_high) + struct.pack('>I', index_low)

        return (
            struct.pack('<I', self.hash_guard)
            + key_bytes
            + location_bytes
            + struct.pack('<I', self.size)
            + struct.pack('BB', self.status, 0)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> UpdateEntry:
        """Parse entry from 24 bytes."""
        if len(data) < 24:
            raise ValueError(f"Update entry data too small: {len(data)} < 24")

        hash_guard = struct.unpack('<I', data[0:4])[0]
        key = data[4:13]

        # Parse archive location (5 bytes)
        index_high = data[13]
        index_low = struct.unpack('>I', data[14:18])[0]
        archive_id = (index_high << 2) | (index_low >> 30)
        archive_offset = index_low & 0x3FFFFFFF

        size = struct.unpack('<I', data[18:22])[0]
        status = data[22]

        return cls(
            hash_guard=hash_guard,
            key=key,
            archive_id=archive_id,
            archive_offset=archive_offset,
            size=size,
            status=status,
        )

    @classmethod
    def from_index_entry(cls, entry: LocalIndexEntry, status: int = 0) -> UpdateEntry:
        """Create an UpdateEntry from a LocalIndexEntry.

        Computes the hash guard automatically.
        """
        # Build the 20 bytes after the hash guard to compute the guard
        key_bytes = entry.key[:9].ljust(9, b'\x00')
        index_high = (entry.archive_id >> 2) & 0xFF
        archive_low = entry.archive_id & 0x03
        index_low = (archive_low << 30) | (entry.archive_offset & 0x3FFFFFFF)
        location_bytes = struct.pack('>B', index_high) + struct.pack('>I', index_low)
        payload = key_bytes + location_bytes + struct.pack('<I', entry.size) + struct.pack('BB', status, 0)
        hash_guard = hashlittle(payload, 0) | 0x80000000

        return cls(
            hash_guard=hash_guard,
            key=entry.key[:9],
            archive_id=entry.archive_id,
            archive_offset=entry.archive_offset,
            size=entry.size,
            status=status,
        )


# Update section constants
UPDATE_PAGE_SIZE = 512  # Bytes per update page
UPDATE_SECTION_MIN_SIZE = 0x7800  # Minimum update section size (60 pages)


@dataclass
class LocalIndexHeader:
    """Header for local index file (V7 format).

    Format (16 bytes):
    - 2 bytes: Version (0x07)
    - 1 byte: Bucket (0x00-0x0F)
    - 1 byte: Extra bytes (0)
    - 1 byte: Encoded size length (4)
    - 1 byte: Storage offset length (5)
    - 1 byte: EKey length (9)
    - 1 byte: File offset bits (30)
    - 8 bytes: Segment size (little-endian uint64)
    """
    version: int = 7
    bucket: int = 0
    extra_bytes: int = 0
    encoded_size_length: int = 4
    storage_offset_length: int = 5
    ekey_length: int = 9
    file_offset_bits: int = 30
    segment_size: int = 0x40000000  # 1 GB default

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
            self.file_offset_bits,
        ) + struct.pack('<Q', self.segment_size)


def compute_bucket(encoding_key: bytes, seed: int = 0) -> int:
    """Compute bucket ID from encoding key using XOR-fold.

    Agent.exe formula:
      xor = ekey[0] ^ ekey[1] ^ ... ^ ekey[8]
      bucket = (((xor >> 4) ^ xor) + seed) & 0x0F

    Args:
        encoding_key: Encoding key (at least 9 bytes)
        seed: Hash seed (0 = key lookup, 1 = segment header reconstruction)

    Returns:
        Bucket ID (0x00-0x0F)
    """
    xor_val = 0
    for i in range(min(9, len(encoding_key))):
        xor_val ^= encoding_key[i]
    return (((xor_val >> 4) ^ xor_val) + seed) & 0x0F


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


def _local_index_entry_list() -> list[LocalIndexEntry]:
    """Factory function for creating typed empty list of LocalIndexEntry."""
    return []


def _update_entry_list() -> list[UpdateEntry]:
    """Factory function for creating typed empty list of UpdateEntry."""
    return []


@dataclass
class LocalIndexFileInfo:
    """Parsed information from a local index file."""

    version: int
    bucket: int
    ekey_length: int
    storage_offset_length: int
    encoded_size_length: int
    file_offset_bits: int
    segment_size: int
    entries: list[LocalIndexEntry] = field(default_factory=_local_index_entry_list)
    update_entries: list[UpdateEntry] = field(default_factory=_update_entry_list)


def parse_local_idx_file(data: bytes) -> LocalIndexFileInfo:
    """Parse a local .idx file (V7 format with guarded blocks).

    V7 file layout:
      0x00: Guarded block header (8 bytes) — header block
      0x08: File header (16 bytes)
      0x18: Padding (8 bytes, zeros) — align to 0x20
      0x20: Guarded block header (8 bytes) — sorted section block
      0x28: Sorted entries (N * 18 bytes)
      Pad to 0x10000 boundary
      0x10000: Update section (24-byte entries in 512-byte pages)

    Args:
        data: Raw .idx file bytes

    Returns:
        LocalIndexFileInfo with parsed header, sorted entries, and update entries

    Raises:
        ValueError: If data is too short or format is invalid
    """
    if len(data) < 40:
        raise ValueError(f"Data too short for local idx file: {len(data)} < 40")

    # Parse header guarded block (8 bytes)
    header_block_size = struct.unpack('<I', data[0:4])[0]
    header_block_hash = struct.unpack('<I', data[4:8])[0]

    # Validate header hash
    header_data = data[8:8 + header_block_size]
    actual_header_hash = hashlittle(header_data, 0)
    if actual_header_hash != header_block_hash:
        logger.warning(
            "Header block hash mismatch",
            expected=f"{header_block_hash:#010x}",
            actual=f"{actual_header_hash:#010x}",
        )

    # Parse IndexHeaderV2 (16 bytes starting at offset 8)
    version = struct.unpack('<H', data[8:10])[0]
    bucket = data[10]
    # extra_bytes = data[11]  # unused
    encoded_size_length = data[12]
    storage_offset_length = data[13]
    ekey_length = data[14]
    file_offset_bits = data[15]
    segment_size = struct.unpack('<Q', data[16:24])[0]

    if version not in (7, 8):
        logger.warning(f"Unexpected index version: {version} (expected 7 or 8)")

    if ekey_length not in (9, 16):
        raise ValueError(f"Invalid key size: {ekey_length}")

    # Entry size: key + location + size
    entry_size = ekey_length + storage_offset_length + encoded_size_length

    # Entry block starts at offset 0x20 (after header block + padding)
    entry_block_offset = 0x20

    # Parse entry block guarded header (8 bytes)
    entry_block_size = struct.unpack('<I', data[entry_block_offset:entry_block_offset + 4])[0]
    entry_block_hash = struct.unpack('<I', data[entry_block_offset + 4:entry_block_offset + 8])[0]

    # Entry data starts at offset 0x28
    entry_data_start = entry_block_offset + 8
    entry_data = data[entry_data_start:entry_data_start + entry_block_size]

    # Validate sorted section hash using iterative hashlittle2
    pc, pb = 0, 0
    offset = 0
    while offset + entry_size <= len(entry_data):
        chunk = entry_data[offset:offset + entry_size]
        pc, pb = hashlittle2(chunk, pc, pb)
        offset += entry_size
    if pc != entry_block_hash:
        logger.warning(
            "Entry block hash mismatch",
            expected=f"{entry_block_hash:#010x}",
            actual=f"{pc:#010x}",
        )

    # Parse sorted entries
    entries: list[LocalIndexEntry] = []
    offset = 0

    while offset + entry_size <= len(entry_data):
        entry_bytes = entry_data[offset:offset + entry_size]

        # Skip empty entries (all zeros in key)
        if entry_bytes[:ekey_length] == b'\x00' * ekey_length:
            offset += entry_size
            continue

        try:
            entry = LocalIndexEntry.from_bytes(entry_bytes)
            entries.append(entry)
        except ValueError:
            pass

        offset += entry_size

    # Parse update section (starts at 0x10000 if file is large enough)
    update_entries: list[UpdateEntry] = []
    update_section_offset = 0x10000

    if len(data) > update_section_offset:
        update_data = data[update_section_offset:]
        uoffset = 0

        while uoffset + 24 <= len(update_data):
            entry_bytes = update_data[uoffset:uoffset + 24]

            # Skip empty entries (zero hash guard means unused slot)
            if entry_bytes[:4] == b'\x00\x00\x00\x00':
                uoffset += 24
                continue

            try:
                uentry = UpdateEntry.from_bytes(entry_bytes)
                # Validate hash guard
                payload = entry_bytes[4:24]
                expected_guard = hashlittle(payload, 0) | 0x80000000
                if uentry.hash_guard != expected_guard:
                    logger.warning(
                        "Update entry hash guard mismatch",
                        expected=f"{expected_guard:#010x}",
                        actual=f"{uentry.hash_guard:#010x}",
                    )
                update_entries.append(uentry)
            except ValueError:
                pass

            uoffset += 24

    return LocalIndexFileInfo(
        version=version,
        bucket=bucket,
        ekey_length=ekey_length,
        storage_offset_length=storage_offset_length,
        encoded_size_length=encoded_size_length,
        file_offset_bits=file_offset_bits,
        segment_size=segment_size,
        entries=entries,
        update_entries=update_entries,
    )


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
        self.ecache_path = base_path / "Data" / ECACHE_DIR

        # Track current archive state
        self.current_archive_id = 0
        self.current_archive_offset = 0
        self.bucket_entries: dict[int, list[LocalIndexEntry]] = {i: [] for i in range(16)}

        # Track generation numbers for each bucket (starts at 1)
        self.bucket_generations: dict[int, int] = dict.fromkeys(range(16), 1)

        # Deduplication: track (truncated_key, size) of written entries
        self._written_keys: dict[bytes, int] = {}

    def initialize(self) -> None:
        """Create directory structure matching Battle.net."""
        logger.info(f"Initializing CASC storage at {self.base_path}")

        # Create directories
        for path in [self.data_path, self.indices_path, self.config_path, self.shmem_path, self.ecache_path]:
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
        self._write_index_file(path, bucket, [])
        logger.debug(f"Created empty index: {path}")

    def write_content(
        self,
        encoding_key: bytes,
        data: bytes,
        *,
        expected_ckey: bytes | None = None,
    ) -> LocalIndexEntry:
        """Write content to local storage.

        Args:
            encoding_key: Full encoding key (16 bytes)
            data: Content data to write (raw BLTE-encoded bytes)
            expected_ckey: If provided, verify decompressed content MD5
                matches this content key. Only meaningful when data is
                the decompressed content, not the raw BLTE blob.

        Returns:
            Index entry for the written content

        Raises:
            IntegrityError: If expected_ckey is provided and MD5
                of data does not match
        """
        truncated_key = encoding_key[:9]

        # Deduplication: skip if already written with same size
        if truncated_key in self._written_keys:
            existing_size = self._written_keys[truncated_key]
            if existing_size == len(data):
                logger.debug(
                    "Skipping duplicate write",
                    ekey=encoding_key.hex(),
                    size=len(data),
                )
                # Return a dummy entry pointing to the existing data
                # (the real entry is already in bucket_entries)
                bucket = compute_bucket(encoding_key)
                for entry in self.bucket_entries[bucket]:
                    if entry.key == truncated_key:
                        return entry
                # Fallthrough: key tracked but entry not found (shouldn't happen)

        # Verify content key if provided
        if expected_ckey is not None:
            actual_md5 = hashlib.md5(data).digest()
            if actual_md5 != expected_ckey:
                raise IntegrityError(
                    f"Content key mismatch for ekey {encoding_key.hex()}: "
                    f"expected {expected_ckey.hex()}, got {actual_md5.hex()}",
                    expected=expected_ckey.hex(),
                    actual=actual_md5.hex(),
                    key_hex=encoding_key.hex(),
                )

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
            key=truncated_key,
            archive_id=self.current_archive_id,
            archive_offset=self.current_archive_offset,
            size=len(data)
        )

        # Update offset and track entry
        self.current_archive_offset += len(data)
        self.bucket_entries[bucket].append(entry)
        self._written_keys[truncated_key] = len(data)

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
        """Write index file with correct V7 layout.

        Layout:
          0x00: Guarded block header (8 bytes) — header block
          0x08: File header (16 bytes)
          0x18: Padding (8 bytes, zeros) — align to 0x20
          0x20: Guarded block header (8 bytes) — sorted section block
          0x28: Sorted entries (N * 18 bytes)
          Pad to 0x10000 boundary
          0x10000: Update section (empty pages, min 0x7800 bytes)
        """
        header = LocalIndexHeader(bucket=bucket)
        header_data = header.to_bytes()  # 16 bytes

        # Serialize sorted entries
        entries_data = b''.join(entry.to_bytes() for entry in entries)

        # Header hash: hashlittle of header data
        header_hash = hashlittle(header_data, 0)

        # Sorted section hash: iterative hashlittle2 per entry
        pc, pb = 0, 0
        for entry in entries:
            pc, pb = hashlittle2(entry.to_bytes(), pc, pb)
        entries_hash = pc

        with open(path, 'wb') as f:
            # 0x00: Header guarded block (8 bytes)
            f.write(struct.pack('<I', len(header_data)))
            f.write(struct.pack('<I', header_hash))

            # 0x08: Header data (16 bytes)
            f.write(header_data)

            # 0x18: Padding to 0x20 (8 bytes)
            f.write(b'\x00' * 8)

            # 0x20: Entry guarded block header (8 bytes)
            f.write(struct.pack('<I', len(entries_data)))
            f.write(struct.pack('<I', entries_hash))

            # 0x28: Sorted entries
            f.write(entries_data)

            # Pad sorted section to 0x10000 boundary
            current_pos = 0x28 + len(entries_data)
            padding_needed = 0x10000 - current_pos
            if padding_needed > 0:
                f.write(b'\x00' * padding_needed)

            # 0x10000: Update section (empty, minimum 0x7800 bytes)
            f.write(b'\x00' * UPDATE_SECTION_MIN_SIZE)

    def insert_entry(self, bucket: int, entry: LocalIndexEntry, status: int = 0) -> None:
        """Append an UpdateEntry to the update section of a bucket's .idx file.

        This writes a single entry to the update section without rewriting the
        sorted section. Used for marking entries as non-resident or adding
        single entries incrementally.

        Args:
            bucket: Bucket ID (0x00-0x0F)
            entry: Index entry to insert
            status: Update entry status (0=normal, 3=delete, 6=hdr-nonres, 7=data-nonres)
        """
        generation = self.bucket_generations[bucket]
        idx_path = self.data_path / format_idx_filename(bucket, generation)

        if not idx_path.exists():
            logger.warning(f"Index file not found for bucket {bucket}: {idx_path}")
            return

        update_entry = UpdateEntry.from_index_entry(entry, status)
        update_bytes = update_entry.to_bytes()

        # Read existing file to find first empty slot in update section
        file_data = idx_path.read_bytes()
        update_offset = 0x10000

        if len(file_data) < update_offset:
            logger.warning(f"Index file too small for update section: {idx_path}")
            return

        # Scan for first empty 24-byte slot
        pos = update_offset
        while pos + 24 <= len(file_data):
            if file_data[pos:pos + 4] == b'\x00\x00\x00\x00':
                break
            pos += 24
        else:
            # No empty slot found; extend the file
            pos = len(file_data)

        # Write the update entry at the found position
        with open(idx_path, 'r+b') as f:
            f.seek(pos)
            f.write(update_bytes)

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

    def get_statistics(self) -> dict[str, Any]:
        """Get storage statistics.

        Returns:
            Dictionary with storage statistics including:
            - base_path: Base installation path as string
            - total_entries: Total number of index entries across all buckets
            - buckets: Per-bucket statistics with count and total_size
        """
        buckets_stats: dict[str, dict[str, int]] = {}

        for bucket in range(16):
            entries = self.bucket_entries[bucket]
            if entries:
                total_size = sum(e.size for e in entries)
                buckets_stats[f'{bucket:02x}'] = {
                    'count': len(entries),
                    'total_size': total_size
                }

        stats: dict[str, Any] = {
            'base_path': str(self.base_path),
            'total_entries': sum(len(entries) for entries in self.bucket_entries.values()),
            'buckets': buckets_stats,
        }

        return stats


