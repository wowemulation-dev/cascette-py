"""Encoding cache (ecache) for CKey→EKey resolution without the encoding file.

Agent.exe maintains a Data/ecache/ directory that stores CKey→EKey mappings
using the same 16-bucket V7 .idx format as Data/data/. On subsequent runs,
the ecache provides CKey→EKey resolution without re-downloading the encoding
file. The ecache is populated during BLTE decode (WriteEHeader at 0x710492)
and managed by casc::PreservationSet.

This implementation uses a custom 36-byte entry format instead of the standard
18-byte LocalIndexEntry:
  - 16 bytes: Full content key (CKey)
  - 16 bytes: Full encoding key (EKey)
  - 4 bytes: ESpec index (little-endian uint32)

Bucket assignment uses ckey[0] & 0x0F, same as LocalStorage.
Index files use the V7 guarded-block format with Jenkins hash checksums.
"""

from __future__ import annotations

import struct
from bisect import bisect_left
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from cascette_tools.core.local_storage import (
    LocalIndexHeader,
    format_idx_filename,
)
from cascette_tools.crypto.jenkins import hashlittle

logger = structlog.get_logger()

ECACHE_ENTRY_SIZE = 36


@dataclass
class EncodingCacheEntry:
    """Entry in the encoding cache (36-byte format).

    Format:
    - 16 bytes: Full content key (CKey)
    - 16 bytes: Full encoding key (EKey)
    - 4 bytes: ESpec index (little-endian)
    """

    content_key: bytes  # 16 bytes
    encoding_key: bytes  # 16 bytes
    espec_index: int  # uint32

    def to_bytes(self) -> bytes:
        """Serialize entry to 36 bytes."""
        return (
            self.content_key[:16].ljust(16, b"\x00")
            + self.encoding_key[:16].ljust(16, b"\x00")
            + struct.pack("<I", self.espec_index)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> EncodingCacheEntry:
        """Parse entry from 36 bytes."""
        if len(data) < ECACHE_ENTRY_SIZE:
            raise ValueError(f"Entry data too small: {len(data)} < {ECACHE_ENTRY_SIZE}")

        content_key = data[:16]
        encoding_key = data[16:32]
        espec_index = struct.unpack("<I", data[32:36])[0]

        return cls(
            content_key=content_key,
            encoding_key=encoding_key,
            espec_index=espec_index,
        )


@dataclass
class EncodingCache:
    """Manages the encoding cache (Data/ecache/) for CKey→EKey resolution.

    The ecache stores full CKey→EKey mappings so that subsequent runs can
    resolve content keys without re-downloading the encoding file.
    """

    base_path: Path
    buckets: dict[int, list[EncodingCacheEntry]] = field(
        default_factory=lambda: {i: [] for i in range(16)}
    )
    generation: int = 1

    def initialize(self) -> None:
        """Create ecache directory and detect existing generations."""
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._detect_generation()

    def _detect_generation(self) -> None:
        """Detect existing index file generation and set next generation."""
        import re

        if not self.base_path.exists():
            return

        idx_pattern = re.compile(r"^([0-9a-f]{2})(\d{8})\.idx$", re.IGNORECASE)
        max_gen = 0

        for idx_file in self.base_path.glob("*.idx"):
            match = idx_pattern.match(idx_file.name)
            if match:
                gen = int(match.group(2))
                if gen > max_gen:
                    max_gen = gen

        if max_gen > 0:
            self.generation = max_gen + 1

    def write_entry(
        self, ckey: bytes, ekey: bytes, espec_index: int = 0
    ) -> None:
        """Add a CKey→EKey mapping to the cache.

        Args:
            ckey: Full 16-byte content key
            ekey: Full 16-byte encoding key
            espec_index: ESpec table index
        """
        bucket = ckey[0] & 0x0F
        entry = EncodingCacheEntry(
            content_key=ckey[:16],
            encoding_key=ekey[:16],
            espec_index=espec_index,
        )
        self.buckets[bucket].append(entry)

    def lookup(self, ckey: bytes) -> EncodingCacheEntry | None:
        """Look up CKey in the cache using binary search.

        Args:
            ckey: Full 16-byte content key

        Returns:
            EncodingCacheEntry if found, None otherwise
        """
        bucket = ckey[0] & 0x0F
        entries = self.buckets[bucket]
        if not entries:
            return None

        # Binary search on sorted content keys
        keys = [e.content_key for e in entries]
        idx = bisect_left(keys, ckey[:16])
        if idx < len(entries) and entries[idx].content_key == ckey[:16]:
            return entries[idx]
        return None

    def flush(self) -> None:
        """Sort entries and write all buckets to index files."""
        for bucket in range(16):
            entries = self.buckets[bucket]
            if not entries:
                continue

            # Sort by content key for binary search
            entries.sort(key=lambda e: e.content_key)
            self.buckets[bucket] = entries

            idx_path = self.base_path / format_idx_filename(bucket, self.generation)
            self._write_index_file(idx_path, bucket, entries)
            logger.info(
                "Wrote ecache index",
                file=idx_path.name,
                entries=len(entries),
            )

    def _write_index_file(
        self,
        path: Path,
        bucket: int,
        entries: list[EncodingCacheEntry],
    ) -> None:
        """Write index file with guarded blocks."""
        header = LocalIndexHeader(bucket=bucket)
        header_data = header.to_bytes()

        entries_data = b"".join(entry.to_bytes() for entry in entries)

        header_hash = hashlittle(header_data)
        entries_hash = hashlittle(entries_data)

        with open(path, "wb") as f:
            # Header guarded block
            f.write(struct.pack("<I", len(header_data)))
            f.write(struct.pack("<I", header_hash))
            f.write(header_data)

            # Entries guarded block
            f.write(struct.pack("<I", len(entries_data)))
            f.write(struct.pack("<I", entries_hash))
            f.write(entries_data)

    def entry_count(self) -> int:
        """Return total number of entries across all buckets."""
        return sum(len(entries) for entries in self.buckets.values())

    @classmethod
    def load(cls, base_path: Path) -> EncodingCache | None:
        """Load an existing ecache from disk.

        Args:
            base_path: Path to Data/ecache/ directory

        Returns:
            Loaded EncodingCache or None if no index files exist
        """
        if not base_path.exists():
            return None

        idx_files = list(base_path.glob("*.idx"))
        if not idx_files:
            return None

        cache = cls(base_path=base_path)
        loaded = 0

        for idx_file in idx_files:
            try:
                data = idx_file.read_bytes()
                entries = _parse_ecache_idx(data)
                for entry in entries:
                    bucket = entry.content_key[0] & 0x0F
                    cache.buckets[bucket].append(entry)
                loaded += len(entries)
            except (ValueError, struct.error) as e:
                logger.warning(
                    "Failed to parse ecache index",
                    file=idx_file.name,
                    error=str(e),
                )

        if loaded == 0:
            return None

        # Sort each bucket for binary search
        for bucket in range(16):
            cache.buckets[bucket].sort(key=lambda e: e.content_key)

        cache._detect_generation()
        logger.info("Loaded ecache", entries=loaded)
        return cache


def _parse_ecache_idx(data: bytes) -> list[EncodingCacheEntry]:
    """Parse an ecache .idx file (V7 guarded-block format with 36-byte entries).

    Args:
        data: Raw .idx file bytes

    Returns:
        List of parsed entries
    """
    if len(data) < 24:
        raise ValueError(f"Data too short for ecache idx: {len(data)} < 24")

    # Skip header guarded block (8 bytes header + variable header data)
    header_block_size = struct.unpack("<I", data[0:4])[0]
    # Skip header block: 8 (guarded header) + header_block_size
    entries_offset = 8 + header_block_size

    if entries_offset + 8 > len(data):
        raise ValueError("Data too short for entries block header")

    # Parse entries guarded block
    entry_block_size = struct.unpack("<I", data[entries_offset : entries_offset + 4])[0]
    entry_block_hash = struct.unpack(
        "<I", data[entries_offset + 4 : entries_offset + 8]
    )[0]

    entry_data = data[entries_offset + 8 : entries_offset + 8 + entry_block_size]

    # Verify hash
    actual_hash = hashlittle(entry_data)
    if actual_hash != entry_block_hash:
        logger.warning(
            "Ecache entry block hash mismatch",
            expected=f"{entry_block_hash:#010x}",
            actual=f"{actual_hash:#010x}",
        )

    entries: list[EncodingCacheEntry] = []
    offset = 0

    while offset + ECACHE_ENTRY_SIZE <= len(entry_data):
        chunk = entry_data[offset : offset + ECACHE_ENTRY_SIZE]

        # Skip empty entries (all-zero content key)
        if chunk[:16] == b"\x00" * 16:
            offset += ECACHE_ENTRY_SIZE
            continue

        entry = EncodingCacheEntry.from_bytes(chunk)
        entries.append(entry)
        offset += ECACHE_ENTRY_SIZE

    return entries
