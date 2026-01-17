"""Legacy chunked archive index format parser for NGDP/CASC.

This handles the older chunked archive index format with multiple chunks
and a table of contents. For modern CDN archive indices (including
archive-groups), use cdn_archive.py instead.
"""

from __future__ import annotations

import hashlib
import struct
from io import BytesIO
from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class ArchiveIndexEntry(BaseModel):
    """Archive index entry."""

    ekey: bytes = Field(description="Encoding key (truncated to 9 bytes)")
    offset: int = Field(description="Offset in archive data file")
    size: int = Field(description="Compressed size")


class ArchiveIndexFooter(BaseModel):
    """Archive index footer."""

    toc_hash: bytes = Field(description="MD5 hash of table of contents")
    version: int = Field(description="Index format version")
    reserved: bytes = Field(description="Reserved bytes")
    page_size_kb: int = Field(description="Page size in KB")
    offset_bytes: int = Field(description="Archive offset field size")
    size_bytes: int = Field(description="Compressed size field size")
    ekey_length: int = Field(description="Encoding key length")
    footer_hash_bytes: int = Field(description="Footer hash length")
    element_count: int = Field(description="Number of chunks")
    footer_hash: bytes = Field(description="Footer hash")


class ArchiveIndexChunk(BaseModel):
    """Archive index chunk."""

    chunk_index: int = Field(description="Chunk index")
    entries: list[ArchiveIndexEntry] = Field(description="Chunk entries")
    last_key: bytes = Field(description="Last key in chunk (for TOC)")


class ArchiveIndex(BaseModel):
    """Complete archive index structure."""

    footer: ArchiveIndexFooter = Field(description="Index footer")
    chunks: list[ArchiveIndexChunk] = Field(description="Data chunks")
    toc: list[bytes] = Field(description="Table of contents")


class ArchiveIndexParser(FormatParser[ArchiveIndex]):
    """Parser for archive index format."""

    CHUNK_SIZE = 4096  # 4KB chunks
    ENTRY_SIZE = 24    # Each entry is 24 bytes
    MAX_ENTRIES_PER_CHUNK = CHUNK_SIZE // ENTRY_SIZE  # 170 entries
    FOOTER_SIZE = 28   # CASC footer is 28 bytes
    TRUNCATED_KEY_SIZE = 9  # Truncated encoding key size

    def parse(self, data: bytes | BinaryIO) -> ArchiveIndex:
        """Parse archive index file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed archive index
        """
        if isinstance(data, (bytes, bytearray)):
            all_data = bytes(data)
        else:
            # It's a stream
            current_pos = data.tell()
            all_data = data.read()
            data.seek(current_pos)

        # Parse footer first to get structure info
        footer = self._parse_footer(all_data)

        # Parse chunks and TOC
        chunks, toc = self._parse_chunks_and_toc(all_data, footer)

        return ArchiveIndex(footer=footer, chunks=chunks, toc=toc)

    def _parse_footer(self, data: bytes) -> ArchiveIndexFooter:
        """Parse archive index footer from end of file."""
        if len(data) < self.FOOTER_SIZE:
            raise ValueError(f"Data too short for footer: {len(data)} < {self.FOOTER_SIZE}")

        # Footer is exactly 28 bytes at the end
        footer_data = data[-self.FOOTER_SIZE:]

        # Parse footer structure (big-endian except element_count)
        toc_hash = footer_data[0:8]  # First 8 bytes of MD5 hash of TOC
        version = footer_data[8]     # Index format version (always 1)
        reserved = footer_data[9:11] # Reserved bytes (must be [0, 0])
        page_size_kb = footer_data[11]   # Page size in KB (always 4)
        offset_bytes = footer_data[12]   # Archive offset field size (4 for archives)
        size_bytes = footer_data[13]     # Compressed size field size (always 4)
        ekey_length = footer_data[14]    # EKey length in bytes (always 16 for full MD5)
        footer_hash_bytes = footer_data[15]  # Footer hash length (always 8)

        # Element count is little-endian (special case!)
        element_count = struct.unpack('<I', footer_data[16:20])[0]

        # Footer hash is last 8 bytes
        footer_hash = footer_data[20:28]

        return ArchiveIndexFooter(
            toc_hash=toc_hash,
            version=version,
            reserved=reserved,
            page_size_kb=page_size_kb,
            offset_bytes=offset_bytes,
            size_bytes=size_bytes,
            ekey_length=ekey_length,
            footer_hash_bytes=footer_hash_bytes,
            element_count=element_count,
            footer_hash=footer_hash
        )

    def _parse_chunks_and_toc(self, data: bytes, footer: ArchiveIndexFooter) -> tuple[list[ArchiveIndexChunk], list[bytes]]:
        """Parse chunks and table of contents."""
        chunk_count = footer.element_count
        file_size = len(data)
        non_footer_size = file_size - self.FOOTER_SIZE

        # Calculate structure sizes
        toc_size = chunk_count * self.TRUNCATED_KEY_SIZE
        data_size = non_footer_size - toc_size

        # Validate structure
        if data_size % self.CHUNK_SIZE != 0:
            raise ValueError("Invalid archive index block structure")

        # Read table of contents (TOC) - last key of each chunk
        toc_offset = data_size
        toc_data = data[toc_offset:toc_offset + toc_size]

        toc: list[bytes] = []
        for i in range(chunk_count):
            key_offset = i * self.TRUNCATED_KEY_SIZE
            key = toc_data[key_offset:key_offset + self.TRUNCATED_KEY_SIZE]
            toc.append(key)

        # Parse data chunks
        chunks: list[ArchiveIndexChunk] = []
        for chunk_index in range(data_size // self.CHUNK_SIZE):
            chunk_offset = chunk_index * self.CHUNK_SIZE
            chunk_data = data[chunk_offset:chunk_offset + self.CHUNK_SIZE]

            chunk = self._parse_chunk(chunk_index, chunk_data)
            chunks.append(chunk)

        return chunks, toc

    def _parse_chunk(self, chunk_index: int, chunk_data: bytes) -> ArchiveIndexChunk:
        """Parse a single chunk."""
        if len(chunk_data) != self.CHUNK_SIZE:
            raise ValueError(f"Invalid chunk size: expected {self.CHUNK_SIZE}, got {len(chunk_data)}")

        entries: list[ArchiveIndexEntry] = []
        last_key = b''

        # Parse entries (24 bytes each)
        for entry_index in range(self.MAX_ENTRIES_PER_CHUNK):
            entry_offset = entry_index * self.ENTRY_SIZE
            if entry_offset + self.ENTRY_SIZE > len(chunk_data):
                break

            entry_data = chunk_data[entry_offset:entry_offset + self.ENTRY_SIZE]

            # Entry structure: 9 bytes ekey + 4 bytes offset + 4 bytes size + 7 bytes reserved
            ekey = entry_data[0:9]
            offset_bytes = entry_data[9:13]
            size_bytes = entry_data[13:17]
            # Reserved: entry_data[17:24]

            # Check for zero entry (end of chunk)
            if ekey == b'\x00' * 9:
                break

            offset = struct.unpack('>I', offset_bytes)[0]  # Big-endian
            size = struct.unpack('>I', size_bytes)[0]      # Big-endian

            entry = ArchiveIndexEntry(
                ekey=ekey,
                offset=offset,
                size=size
            )
            entries.append(entry)

            last_key = ekey

        return ArchiveIndexChunk(
            chunk_index=chunk_index,
            entries=entries,
            last_key=last_key
        )

    def find_entry(self, obj: ArchiveIndex, ekey: bytes) -> ArchiveIndexEntry | None:
        """Find entry by encoding key.

        Args:
            obj: Parsed archive index
            ekey: Encoding key to find (full 16 bytes or truncated 9 bytes)

        Returns:
            Found entry or None
        """
        # Truncate key to 9 bytes for comparison
        search_key = ekey[:9]

        # Linear search through all chunks
        for chunk in obj.chunks:
            for entry in chunk.entries:
                if entry.ekey == search_key:
                    return entry

        return None

    def find_entries_in_range(self, obj: ArchiveIndex,
                              start_offset: int, end_offset: int) -> list[ArchiveIndexEntry]:
        """Find entries within offset range.

        Args:
            obj: Parsed archive index
            start_offset: Start offset (inclusive)
            end_offset: End offset (exclusive)

        Returns:
            List of entries in range
        """
        matches: list[ArchiveIndexEntry] = []

        for chunk in obj.chunks:
            for entry in chunk.entries:
                if start_offset <= entry.offset < end_offset:
                    matches.append(entry)

        return matches

    def validate_toc_hash(self, obj: ArchiveIndex) -> bool:
        """Validate table of contents hash.

        Args:
            obj: Parsed archive index

        Returns:
            True if TOC hash is valid
        """
        # Concatenate all TOC keys
        toc_data = b''.join(obj.toc)

        # Calculate MD5 hash
        md5_hash = hashlib.md5(toc_data).digest()

        # Compare upper 8 bytes with footer TOC hash
        calculated_hash = md5_hash[8:16]
        return calculated_hash == obj.footer.toc_hash

    def validate_footer_hash(self, obj: ArchiveIndex) -> bool:
        """Validate footer hash.

        Args:
            obj: Parsed archive index

        Returns:
            True if footer hash is valid
        """
        footer = obj.footer

        # Build data to hash from footer fields
        data = bytearray(20)  # Pad to 20 bytes
        data[0] = footer.version
        data[1:3] = footer.reserved
        data[3] = footer.page_size_kb
        data[4] = footer.offset_bytes
        data[5] = footer.size_bytes
        data[6] = footer.ekey_length
        data[7] = footer.footer_hash_bytes

        # Element count is little-endian
        element_count_bytes = struct.pack('<I', footer.element_count)
        data[8:12] = element_count_bytes

        # Calculate MD5 hash
        md5_hash = hashlib.md5(data).digest()

        # Compare lower 8 bytes with footer hash
        calculated_hash = md5_hash[:8]
        return calculated_hash == footer.footer_hash

    def get_statistics(self, obj: ArchiveIndex) -> dict[str, Any]:
        """Get statistics about the archive index.

        Args:
            obj: Parsed archive index

        Returns:
            Statistics dictionary
        """
        total_entries = sum(len(chunk.entries) for chunk in obj.chunks)
        non_empty_chunks = sum(1 for chunk in obj.chunks if chunk.entries)

        # Calculate size statistics
        if total_entries > 0:
            sizes: list[int] = [entry.size for chunk in obj.chunks for entry in chunk.entries]
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
        else:
            min_size = max_size = avg_size = 0

        return {
            'total_chunks': len(obj.chunks),
            'non_empty_chunks': non_empty_chunks,
            'total_entries': total_entries,
            'entries_per_chunk': total_entries / len(obj.chunks) if obj.chunks else 0,
            'min_entry_size': min_size,
            'max_entry_size': max_size,
            'avg_entry_size': avg_size,
            'toc_hash_valid': self.validate_toc_hash(obj),
            'footer_hash_valid': self.validate_footer_hash(obj)
        }

    def build(self, obj: ArchiveIndex) -> bytes:
        """Build archive index binary data from structure.

        Args:
            obj: Archive index structure

        Returns:
            Binary archive index data
        """
        result = BytesIO()

        # Write chunks
        for chunk in obj.chunks:
            chunk_data = bytearray(self.CHUNK_SIZE)

            for i, entry in enumerate(chunk.entries):
                if i >= self.MAX_ENTRIES_PER_CHUNK:
                    break

                entry_offset = i * self.ENTRY_SIZE

                # Write entry: 9 bytes ekey + 4 bytes offset + 4 bytes size + 7 bytes reserved
                chunk_data[entry_offset:entry_offset + 9] = entry.ekey
                chunk_data[entry_offset + 9:entry_offset + 13] = struct.pack('>I', entry.offset)
                chunk_data[entry_offset + 13:entry_offset + 17] = struct.pack('>I', entry.size)
                # Reserved bytes are already zero from bytearray initialization

            result.write(chunk_data)

        # Write table of contents
        for key in obj.toc:
            result.write(key)

        # Write footer
        footer = obj.footer
        result.write(footer.toc_hash)
        result.write(struct.pack('B', footer.version))
        result.write(footer.reserved)
        result.write(struct.pack('B', footer.page_size_kb))
        result.write(struct.pack('B', footer.offset_bytes))
        result.write(struct.pack('B', footer.size_bytes))
        result.write(struct.pack('B', footer.ekey_length))
        result.write(struct.pack('B', footer.footer_hash_bytes))
        result.write(struct.pack('<I', footer.element_count))  # Little-endian
        result.write(footer.footer_hash)

        return result.getvalue()


class ArchiveBuilder:
    """Builder for archive index files."""

    def __init__(self) -> None:
        """Initialize archive builder."""
        pass

    def build(self, obj: ArchiveIndex) -> bytes:
        """Build archive index file from object.

        Args:
            obj: Archive index object to build

        Returns:
            Binary archive index data
        """
        parser = ArchiveIndexParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls) -> ArchiveIndex:
        """Create an empty archive index.

        Returns:
            Empty archive index object
        """
        footer = ArchiveIndexFooter(
            toc_hash=b'\x00' * 16,
            version=1,
            reserved=b'\x00' * 2,
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=0,
            footer_hash=b'\x00' * 8
        )

        return ArchiveIndex(
            footer=footer,
            chunks=[],
            toc=[]
        )

    @classmethod
    def create_with_entries(cls, entries: list[ArchiveIndexEntry]) -> ArchiveIndex:
        """Create archive index with given entries.

        Args:
            entries: List of archive entries

        Returns:
            Archive index object
        """
        # Group entries into chunks
        chunks: list[ArchiveIndexChunk] = []
        chunk_size = 4096 // 24  # 170 entries per chunk

        for i in range(0, len(entries), chunk_size):
            chunk_entries = entries[i:i + chunk_size]
            last_key = chunk_entries[-1].ekey if chunk_entries else b'\x00' * 9

            chunk = ArchiveIndexChunk(
                chunk_index=len(chunks),
                entries=chunk_entries,
                last_key=last_key
            )
            chunks.append(chunk)

        # Create TOC from last keys
        toc: list[bytes] = [chunk.last_key + b'\x00' * 7 for chunk in chunks]  # Pad to 16 bytes

        # Calculate TOC hash
        toc_data = b''.join(toc)
        toc_hash = hashlib.md5(toc_data).digest()

        footer = ArchiveIndexFooter(
            toc_hash=toc_hash,
            version=1,
            reserved=b'\x00' * 2,
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=len(entries),
            footer_hash=b'\x00' * 8  # Would need to calculate actual hash
        )

        return ArchiveIndex(
            footer=footer,
            chunks=chunks,
            toc=toc
        )


def is_obj(data: bytes) -> bool:
    """Check if data appears to be an archive index file.

    Args:
        data: Data to check

    Returns:
        True if data appears to be an archive index
    """
    if len(data) < 28:  # Minimum size for footer
        return False

    # Check footer structure for reasonable values
    try:
        footer_data = data[-28:]
        version = footer_data[8]
        page_size_kb = footer_data[11]
        offset_bytes = footer_data[12]
        size_bytes = footer_data[13]
        ekey_length = footer_data[14]
        footer_hash_bytes = footer_data[15]

        # Validate expected values
        return (version == 1 and
                page_size_kb == 4 and
                offset_bytes == 4 and
                size_bytes == 4 and
                ekey_length == 16 and
                footer_hash_bytes == 8)
    except Exception:
        return False
