"""CDN archive index format parser.

This parser handles both types of CDN archive indices:
1. Regular CDN archive indices (4-byte offsets)
   - Used for individual archive files
   - Maps encoding keys to offsets within a single archive

2. Archive-groups (6-byte offsets: 2-byte archive index + 4-byte offset)
   - Client-generated mega-indices combining multiple CDN archives
   - Maps encoding keys to (archive_index, offset) pairs
   - Archive indices use hash-based assignment (0-65535)

The format is detected automatically based on the offset_bytes field in the footer.
Note: This is different from the legacy chunked archive format in archive.py.
"""

from __future__ import annotations

import struct
from io import BytesIO
from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class CdnArchiveEntry(BaseModel):
    """CDN archive index entry."""

    encoding_key: bytes = Field(description="Encoding key (variable length)")
    archive_index: int | None = Field(default=None, description="Archive index (only for archive-groups)")
    offset: int = Field(description="Offset in archive data file")
    size: int = Field(description="Compressed size")


class CdnArchiveFooter(BaseModel):
    """CDN archive index footer."""

    toc_hash: bytes = Field(description="MD5 hash of table of contents (first 8 bytes)")
    version: int = Field(description="Index format version")
    reserved: bytes = Field(description="Reserved bytes")
    page_size_kb: int = Field(description="Page size in KB")
    offset_bytes: int = Field(description="Offset field size (4 for archives, 6 for archive-groups)")
    size_bytes: int = Field(description="Compressed size field size")
    key_bytes: int = Field(description="Key length in bytes")
    footer_hash_bytes: int = Field(description="Footer hash length")
    entry_count: int = Field(description="Number of entries")
    footer_hash: bytes = Field(description="Footer hash")

    @property
    def is_archive_group(self) -> bool:
        """Check if this is an archive-group (6-byte offsets)."""
        return self.offset_bytes == 6


class CdnArchiveIndex(BaseModel):
    """Complete CDN archive index structure."""

    footer: CdnArchiveFooter = Field(description="Index footer")
    entries: list[CdnArchiveEntry] = Field(description="Archive entries")


class CdnArchiveParser(FormatParser[CdnArchiveIndex]):
    """Parser for CDN archive index and archive-group formats."""

    FOOTER_SIZE = 28  # Footer is always 28 bytes

    def parse(self, data: bytes | BinaryIO) -> CdnArchiveIndex:
        """Parse CDN archive index or archive-group file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed CDN archive index
        """
        if isinstance(data, (bytes, bytearray)):
            all_data = bytes(data)
        else:
            # It's a stream
            current_pos = data.tell()
            all_data = data.read()
            data.seek(current_pos)

        # Parse footer first to determine format
        footer = self._parse_footer(all_data)

        # Parse entries based on format
        entries = self._parse_entries(all_data, footer)

        return CdnArchiveIndex(footer=footer, entries=entries)

    def _parse_footer(self, data: bytes) -> CdnArchiveFooter:
        """Parse archive index footer from end of file."""
        if len(data) < self.FOOTER_SIZE:
            raise ValueError(f"Data too short for footer: {len(data)} < {self.FOOTER_SIZE}")

        # Footer is exactly 28 bytes at the end
        footer_data = data[-self.FOOTER_SIZE:]

        # Parse footer structure
        toc_hash = footer_data[0:8]  # First 8 bytes of MD5 hash
        version = footer_data[8]
        reserved = footer_data[9:11]
        page_size_kb = footer_data[11]
        offset_bytes = footer_data[12]  # 4 for archives, 6 for archive-groups
        size_bytes = footer_data[13]
        key_bytes = footer_data[14]  # Key length (variable: 9, 16, etc.)
        footer_hash_bytes = footer_data[15]

        # Entry count is little-endian (special case!)
        entry_count = struct.unpack('<I', footer_data[16:20])[0]

        # Footer hash (last 8 bytes)
        footer_hash = footer_data[20:28]

        logger.debug(
            "Parsed footer",
            version=version,
            offset_bytes=offset_bytes,
            key_bytes=key_bytes,
            entry_count=entry_count,
            is_archive_group=(offset_bytes == 6)
        )

        return CdnArchiveFooter(
            toc_hash=toc_hash,
            version=version,
            reserved=reserved,
            page_size_kb=page_size_kb,
            offset_bytes=offset_bytes,
            size_bytes=size_bytes,
            key_bytes=key_bytes,
            footer_hash_bytes=footer_hash_bytes,
            entry_count=entry_count,
            footer_hash=footer_hash
        )

    def _parse_entries(self, data: bytes, footer: CdnArchiveFooter) -> list[CdnArchiveEntry]:
        """Parse all entries from the archive index."""
        entries: list[CdnArchiveEntry] = []

        # Calculate entry size
        entry_size = footer.key_bytes + footer.offset_bytes + footer.size_bytes

        # Data section is everything except footer
        data_section_size = len(data) - self.FOOTER_SIZE

        # Start parsing from beginning
        pos = 0

        for i in range(footer.entry_count):
            if pos + entry_size > data_section_size:
                logger.warning(f"Entry {i} would exceed data section, stopping")
                break

            # Parse encoding key
            encoding_key = data[pos:pos + footer.key_bytes]
            pos += footer.key_bytes

            # Parse offset (4 or 6 bytes)
            if footer.is_archive_group:
                # Archive-group: 2 bytes archive index + 4 bytes offset
                archive_index = struct.unpack('>H', data[pos:pos + 2])[0]
                offset = struct.unpack('>I', data[pos + 2:pos + 6])[0]
                pos += 6
            else:
                # Regular archive: 4 bytes offset
                archive_index = None
                offset = struct.unpack('>I', data[pos:pos + 4])[0]
                pos += 4

            # Parse size (always 4 bytes)
            size = struct.unpack('>I', data[pos:pos + 4])[0]
            pos += 4

            # Skip any zero entries
            if encoding_key == b'\x00' * footer.key_bytes:
                continue

            entry = CdnArchiveEntry(
                encoding_key=encoding_key,
                archive_index=archive_index,
                offset=offset,
                size=size
            )
            entries.append(entry)

        logger.info(
            f"Parsed {'archive-group' if footer.is_archive_group else 'archive index'}",
            total_entries=len(entries),
            expected_entries=footer.entry_count
        )

        return entries

    def find_entry(self, obj: CdnArchiveIndex, encoding_key: bytes) -> CdnArchiveEntry | None:
        """Find entry by encoding key.

        Args:
            obj: Parsed archive index
            encoding_key: Encoding key to find

        Returns:
            Found entry or None
        """
        # Truncate or pad key to match stored key length
        key_bytes = obj.footer.key_bytes
        if len(encoding_key) > key_bytes:
            search_key = encoding_key[:key_bytes]
        elif len(encoding_key) < key_bytes:
            search_key = encoding_key + (b'\x00' * (key_bytes - len(encoding_key)))
        else:
            search_key = encoding_key

        for entry in obj.entries:
            if entry.encoding_key == search_key:
                return entry

        return None

    def get_archive_indices(self, obj: CdnArchiveIndex) -> dict[int, int]:
        """Get archive index distribution (for archive-groups only).

        Args:
            obj: Parsed archive-group

        Returns:
            Dictionary of archive_index -> count
        """
        if not obj.footer.is_archive_group:
            return {}

        distribution: dict[int, int] = {}
        for entry in obj.entries:
            if entry.archive_index is not None:
                if entry.archive_index not in distribution:
                    distribution[entry.archive_index] = 0
                distribution[entry.archive_index] += 1

        return distribution

    def get_statistics(self, obj: CdnArchiveIndex) -> dict[str, Any]:
        """Get statistics about the archive index.

        Args:
            obj: Parsed archive index

        Returns:
            Statistics dictionary
        """
        stats: dict[str, Any] = {
            'format': 'archive-group' if obj.footer.is_archive_group else 'archive-index',
            'version': obj.footer.version,
            'key_bytes': obj.footer.key_bytes,
            'offset_bytes': obj.footer.offset_bytes,
            'total_entries': len(obj.entries),
            'expected_entries': obj.footer.entry_count,
        }

        if obj.footer.is_archive_group:
            # Add archive-group specific stats
            distribution: dict[int, int] = self.get_archive_indices(obj)
            stats['unique_archive_indices'] = len(distribution)
            stats['archive_distribution'] = dict(sorted(distribution.items())[:10])  # Top 10

            if distribution:
                stats['min_archive_index'] = min(distribution.keys())
                stats['max_archive_index'] = max(distribution.keys())

        # Size statistics
        if obj.entries:
            sizes: list[int] = [entry.size for entry in obj.entries]
            stats['min_size'] = min(sizes)
            stats['max_size'] = max(sizes)
            stats['avg_size'] = sum(sizes) / len(sizes)
            stats['total_size'] = sum(sizes)

        return stats

    def build(self, obj: CdnArchiveIndex) -> bytes:
        """Build CDN archive index binary data from structure.

        Args:
            obj: Archive index structure

        Returns:
            Binary archive index data
        """
        result = BytesIO()

        footer = obj.footer
        entry_size = footer.key_bytes + footer.offset_bytes + footer.size_bytes

        # Write entries
        for entry in obj.entries:
            # Write encoding key
            result.write(entry.encoding_key[:footer.key_bytes])

            # Write offset
            if footer.is_archive_group:
                # Archive-group: 2 bytes archive index + 4 bytes offset
                archive_idx = entry.archive_index if entry.archive_index is not None else 0
                result.write(struct.pack('>H', archive_idx))
                result.write(struct.pack('>I', entry.offset))
            else:
                # Regular archive: 4 bytes offset
                result.write(struct.pack('>I', entry.offset))

            # Write size
            result.write(struct.pack('>I', entry.size))

        # Pad if necessary (some indices have padding)
        current_size = result.tell()
        expected_size = len(obj.entries) * entry_size
        if current_size < expected_size:
            result.write(b'\x00' * (expected_size - current_size))

        # Write footer
        result.write(footer.toc_hash)
        result.write(struct.pack('B', footer.version))
        result.write(footer.reserved)
        result.write(struct.pack('B', footer.page_size_kb))
        result.write(struct.pack('B', footer.offset_bytes))
        result.write(struct.pack('B', footer.size_bytes))
        result.write(struct.pack('B', footer.key_bytes))
        result.write(struct.pack('B', footer.footer_hash_bytes))
        result.write(struct.pack('<I', footer.entry_count))  # Little-endian!
        result.write(footer.footer_hash)

        return result.getvalue()


def is_archive_group(data: bytes) -> bool:
    """Check if data is an archive-group (6-byte offsets).

    Args:
        data: Data to check

    Returns:
        True if data is an archive-group
    """
    if len(data) < 28:
        return False

    try:
        offset_bytes = data[-16]  # offset_bytes field in footer
        return offset_bytes == 6
    except Exception:
        return False


def is_cdn_archive_index(data: bytes) -> bool:
    """Check if data is a CDN archive index or archive-group.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a CDN archive index
    """
    if len(data) < 28:
        return False

    try:
        footer_data = data[-28:]
        version = footer_data[8]
        offset_bytes = footer_data[12]
        size_bytes = footer_data[13]

        # Valid if version is 1, size_bytes is 4, and offset_bytes is 4 or 6
        return (version == 1 and
                size_bytes == 4 and
                offset_bytes in [4, 6])
    except Exception:
        return False
