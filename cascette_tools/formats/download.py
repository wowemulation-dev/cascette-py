"""Download format parser for NGDP/CASC."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class DownloadTag(BaseModel):
    """Download manifest tag with file association bitmask."""

    name: str = Field(description="Tag name")
    tag_type: int = Field(description="Tag type identifier")
    file_mask: bytes = Field(description="Bitmask indicating which files have this tag")

    def has_file(self, file_index: int) -> bool:
        """Check if file at given index has this tag.

        Uses little-endian bit ordering within each byte:
        - Bit 0 (LSB) corresponds to file index byte_index * 8 + 0
        - Bit 7 (MSB) corresponds to file index byte_index * 8 + 7

        Args:
            file_index: Index of file to check

        Returns:
            True if file has this tag
        """
        byte_index = file_index // 8
        bit_offset = file_index % 8

        if byte_index >= len(self.file_mask):
            return False

        return (self.file_mask[byte_index] & (1 << bit_offset)) != 0


class DownloadEntry(BaseModel):
    """Download manifest file entry."""

    ekey: bytes = Field(description="Encoding key")
    size: int = Field(description="File size in bytes")
    priority: int = Field(description="Download priority (0-255, lower = higher priority)")
    checksum: bytes | None = Field(default=None, description="MD5 checksum (if available)")
    tags: list[str] = Field(default_factory=list, description="List of tag names")


class DownloadHeader(BaseModel):
    """Download manifest header."""

    version: int = Field(description="Format version")
    ekey_size: int = Field(description="Encoding key size in bytes")
    has_checksum: bool = Field(description="Whether entries have checksums")
    entry_count: int = Field(description="Number of file entries")
    tag_count: int = Field(description="Number of tags")


class DownloadFile(BaseModel):
    """Complete download manifest structure."""

    header: DownloadHeader = Field(description="Manifest header")
    tags: list[DownloadTag] = Field(description="Tag definitions")
    entries: list[DownloadEntry] = Field(description="File entries")

    def get_high_priority_entries(self, max_priority: int = 50) -> list[DownloadEntry]:
        """Get entries with high priority (low priority value).

        Args:
            max_priority: Maximum priority value to include

        Returns:
            List of high priority entries
        """
        return [entry for entry in self.entries if entry.priority <= max_priority]

    def get_entries_with_tag(self, tag_name: str) -> list[DownloadEntry]:
        """Get entries that have a specific tag.

        Args:
            tag_name: Name of tag to filter by

        Returns:
            List of entries with the tag
        """
        return [entry for entry in self.entries if tag_name in entry.tags]

    def get_sorted_by_priority(self) -> list[DownloadEntry]:
        """Get entries sorted by priority (ascending).

        Returns:
            List of entries sorted by priority (highest priority first)
        """
        return sorted(self.entries, key=lambda x: x.priority)


class DownloadParser(FormatParser[DownloadFile]):
    """Parser for download format."""

    def parse(self, data: bytes | BinaryIO) -> DownloadFile:
        """Parse download manifest.

        Args:
            data: Binary data or stream

        Returns:
            Parsed download manifest
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header_data = stream.read(11)  # DL(2) + version(1) + ekey_size(1) + has_checksum(1) + entry_count(4) + tag_count(2)
        if len(header_data) < 11:
            raise ValueError("Insufficient data for header")

        magic = header_data[0:2]
        if magic != b'DL':
            raise ValueError(f"Invalid magic: {magic.hex()}, expected 444C (DL)")

        version = header_data[2]
        ekey_size = header_data[3]
        has_checksum = header_data[4] != 0
        entry_count = struct.unpack('>I', header_data[5:9])[0]  # big-endian
        tag_count = struct.unpack('>H', header_data[9:11])[0]  # big-endian

        # Skip reserved byte (1 byte)
        reserved = stream.read(1)
        if len(reserved) < 1:
            raise ValueError("Insufficient data for reserved byte")

        logger.debug("Parsed download header",
                    version=version, ekey_size=ekey_size, has_checksum=has_checksum,
                    entry_count=entry_count, tag_count=tag_count)

        header = DownloadHeader(
            version=version,
            ekey_size=ekey_size,
            has_checksum=has_checksum,
            entry_count=entry_count,
            tag_count=tag_count
        )

        # Calculate priority mask size
        priority_mask_size = (entry_count + 7) // 8

        # Parse tags
        tags = []
        for _ in range(tag_count):
            # Read tag name (null-terminated)
            name_bytes = bytearray()
            while True:
                byte = stream.read(1)
                if not byte or byte == b'\x00':
                    break
                name_bytes.extend(byte)

            tag_name = name_bytes.decode('utf-8', errors='replace')

            # Read tag type (2 bytes big-endian)
            tag_type_data = stream.read(2)
            if len(tag_type_data) < 2:
                raise ValueError(f"Insufficient data for tag type: {tag_name}")
            tag_type = struct.unpack('>H', tag_type_data)[0]

            # Read priority bitmask
            priority_mask_data = stream.read(priority_mask_size)
            if len(priority_mask_data) < priority_mask_size:
                raise ValueError(f"Insufficient data for priority bitmask: {tag_name}")

            tags.append(DownloadTag(
                name=tag_name,
                tag_type=tag_type,
                file_mask=priority_mask_data
            ))

        # Parse file entries
        entries = []
        for i in range(entry_count):
            # Read encoding key
            ekey_data = stream.read(ekey_size)
            if len(ekey_data) < ekey_size:
                raise ValueError(f"Insufficient data for encoding key at entry {i}")

            # Read file size (5 bytes, 40-bit big-endian)
            size_data = stream.read(5)
            if len(size_data) < 5:
                raise ValueError(f"Insufficient data for file size at entry {i}")
            file_size = struct.unpack('>Q', b'\x00\x00\x00' + size_data)[0]  # Pad to 8 bytes

            # Read download priority (1 byte)
            priority_data = stream.read(1)
            if len(priority_data) < 1:
                raise ValueError(f"Insufficient data for priority at entry {i}")
            priority = priority_data[0]

            # Read checksum if present
            checksum = None
            if has_checksum:
                checksum_data = stream.read(4)
                if len(checksum_data) < 4:
                    raise ValueError(f"Insufficient data for checksum at entry {i}")
                checksum = checksum_data

            # Determine tags for this file
            file_tags = []
            for tag in tags:
                if tag.has_file(i):
                    file_tags.append(tag.name)

            entries.append(DownloadEntry(
                ekey=ekey_data,
                size=file_size,
                priority=priority,
                checksum=checksum,
                tags=file_tags
            ))

        return DownloadFile(
            header=header,
            tags=tags,
            entries=entries
        )

    def build(self, obj: DownloadFile) -> bytes:
        """Build download manifest binary data.

        Args:
            obj: Download manifest structure

        Returns:
            Binary download data
        """
        result = BytesIO()

        # Write header
        result.write(b'DL')  # Magic
        result.write(struct.pack('B', obj.header.version))  # Version
        result.write(struct.pack('B', obj.header.ekey_size))  # EKey size
        result.write(struct.pack('B', 1 if obj.header.has_checksum else 0))  # Has checksum
        result.write(struct.pack('>I', len(obj.entries)))  # Entry count (big-endian)
        result.write(struct.pack('>H', len(obj.tags)))  # Tag count (big-endian)
        result.write(b'\x00')  # Reserved byte

        # Calculate priority mask size
        priority_mask_size = (len(obj.entries) + 7) // 8

        # Rebuild tag priority masks from entry tags
        tag_masks = {}
        for tag in obj.tags:
            mask = bytearray(priority_mask_size)
            for i, entry in enumerate(obj.entries):
                if tag.name in entry.tags:
                    byte_index = i // 8
                    bit_offset = i % 8
                    mask[byte_index] |= (1 << bit_offset)
            tag_masks[tag.name] = bytes(mask)

        # Write tags
        for tag in obj.tags:
            # Write tag name (null-terminated)
            result.write(tag.name.encode('utf-8'))
            result.write(b'\x00')

            # Write tag type (2 bytes big-endian)
            result.write(struct.pack('>H', tag.tag_type))

            # Write priority bitmask (use rebuilt mask to ensure consistency)
            result.write(tag_masks[tag.name])

        # Write file entries
        for entry in obj.entries:
            # Write encoding key
            if len(entry.ekey) != obj.header.ekey_size:
                raise ValueError(f"Encoding key size mismatch: expected {obj.header.ekey_size}, got {len(entry.ekey)}")
            result.write(entry.ekey)

            # Write file size (5 bytes, 40-bit big-endian)
            if entry.size >= (1 << 40):
                raise ValueError(f"File size too large: {entry.size}")
            size_bytes = struct.pack('>Q', entry.size)[3:]  # Take last 5 bytes
            result.write(size_bytes)

            # Write download priority (1 byte)
            if entry.priority > 255:
                raise ValueError(f"Priority too large: {entry.priority}")
            result.write(struct.pack('B', entry.priority))

            # Write checksum if enabled
            if obj.header.has_checksum:
                if entry.checksum is None:
                    raise ValueError("Checksum required but not provided for entry")
                if len(entry.checksum) != 4:
                    raise ValueError(f"Checksum must be 4 bytes, got {len(entry.checksum)}")
                result.write(entry.checksum)
            elif entry.checksum is not None:
                raise ValueError("Checksum provided but not expected")

        return result.getvalue()


class DownloadBuilder:
    """Builder for download manifest files."""

    def __init__(self):
        """Initialize download builder."""
        pass

    def build(self, obj: DownloadFile) -> bytes:
        """Build download file from object.

        Args:
            obj: Download file object to build

        Returns:
            Binary download data
        """
        parser = DownloadParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls) -> DownloadFile:
        """Create an empty download file.

        Returns:
            Empty download file object
        """
        header = DownloadHeader(
            version=3,
            ekey_size=16,
            has_checksum=False,
            tag_count=0,
            entry_count=0
        )

        return DownloadFile(
            header=header,
            tags=[],
            entries=[]
        )

    @classmethod
    def create_with_entries(cls, entries: list[DownloadEntry], tags: list[DownloadTag] | None = None) -> DownloadFile:
        """Create download file with given entries.

        Args:
            entries: List of download entries
            tags: Optional list of tags

        Returns:
            Download file object
        """
        tags = tags or []

        header = DownloadHeader(
            version=3,
            ekey_size=16,
            has_checksum=any(e.checksum is not None for e in entries),
            tag_count=len(tags),
            entry_count=len(entries)
        )

        return DownloadFile(
            header=header,
            tags=tags,
            entries=entries
        )


def is_download(data: bytes) -> bool:
    """Check if data appears to be a download manifest.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a download manifest
    """
    if len(data) < 2:
        return False

    # Check for DL magic
    return data[:2] == b'DL'
