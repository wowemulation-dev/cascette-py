"""Install format parser for NGDP/CASC."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class InstallTag(BaseModel):
    """Install manifest tag with bitmask for file association."""

    name: str = Field(description="Tag name (e.g., Windows, enUS)")
    tag_type: int = Field(description="Tag type identifier")
    bit_mask: bytes = Field(description="Bitmask indicating which files have this tag")

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

        if byte_index >= len(self.bit_mask):
            return False

        return (self.bit_mask[byte_index] & (1 << bit_offset)) != 0


class InstallEntry(BaseModel):
    """Install manifest file entry."""

    filename: str = Field(description="File path")
    md5_hash: bytes = Field(description="MD5 content key (16 bytes)")
    size: int = Field(description="File size in bytes")
    file_type: int | None = Field(default=None, description="File type byte (V2 only)")
    tags: list[str] = Field(default_factory=list, description="List of tag names")


class InstallFile(BaseModel):
    """Complete install manifest structure."""

    version: int = Field(description="Format version")
    hash_size: int = Field(description="Hash size in bytes")
    entries: list[InstallEntry] = Field(description="File entries")
    tags: list[InstallTag] = Field(description="Tag definitions")


class InstallParser(FormatParser[InstallFile]):
    """Parser for install format."""

    def parse(self, data: bytes | BinaryIO) -> InstallFile:
        """Parse install manifest.

        Args:
            data: Binary data or stream

        Returns:
            Parsed install manifest
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header_data = stream.read(10)  # IN(2) + version(1) + hash_size(1) + tag_count(2) + entry_count(4)
        if len(header_data) < 10:
            raise ValueError("Insufficient data for header")

        magic = header_data[0:2]
        if magic != b'IN':
            raise ValueError(f"Invalid magic: {magic.hex()}, expected 494E (IN)")

        version = header_data[2]
        hash_size = header_data[3]
        tag_count = struct.unpack('>H', header_data[4:6])[0]  # big-endian
        entry_count = struct.unpack('>I', header_data[6:10])[0]  # big-endian

        # Validate version (accept V1 and V2, matching Agent.exe)
        if version == 0 or version > 2:
            raise ValueError(f"Unsupported install version: {version}")

        logger.debug("Parsed install header",
                    version=version, hash_size=hash_size,
                    tag_count=tag_count, entry_count=entry_count)

        # Calculate tag mask size
        mask_size = (entry_count + 7) // 8

        # Parse tags
        tags: list[InstallTag] = []
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

            # Read bit mask
            bit_mask_data = stream.read(mask_size)
            if len(bit_mask_data) < mask_size:
                raise ValueError(f"Insufficient data for bit mask: {tag_name}")

            tags.append(InstallTag(
                name=tag_name,
                tag_type=tag_type,
                bit_mask=bit_mask_data
            ))

        # Parse file entries
        entries: list[InstallEntry] = []
        for i in range(entry_count):
            # Read filename (null-terminated)
            filename_bytes = bytearray()
            while True:
                byte = stream.read(1)
                if not byte or byte == b'\x00':
                    break
                filename_bytes.extend(byte)

            filename = filename_bytes.decode('utf-8', errors='replace')

            # Read MD5 hash
            md5_data = stream.read(hash_size)
            if len(md5_data) < hash_size:
                raise ValueError(f"Insufficient data for MD5 hash: {filename}")

            # Read file size (4 bytes big-endian)
            size_data = stream.read(4)
            if len(size_data) < 4:
                raise ValueError(f"Insufficient data for file size: {filename}")
            file_size = struct.unpack('>I', size_data)[0]

            # Read file type for V2 (1 byte after file_size)
            file_type = None
            if version >= 2:
                ft_data = stream.read(1)
                if len(ft_data) < 1:
                    raise ValueError(f"Insufficient data for file_type: {filename}")
                file_type = ft_data[0]

            # Determine tags for this file
            file_tags: list[str] = []
            for tag in tags:
                if tag.has_file(i):
                    file_tags.append(tag.name)

            entries.append(InstallEntry(
                filename=filename,
                md5_hash=md5_data,
                size=file_size,
                file_type=file_type,
                tags=file_tags
            ))

        return InstallFile(
            version=version,
            hash_size=hash_size,
            entries=entries,
            tags=tags
        )

    def build(self, obj: InstallFile) -> bytes:
        """Build install manifest binary data.

        Args:
            obj: Install manifest structure

        Returns:
            Binary install data
        """
        result = BytesIO()

        # Write header
        result.write(b'IN')  # Magic
        result.write(struct.pack('B', obj.version))  # Version
        result.write(struct.pack('B', obj.hash_size))  # Hash size
        result.write(struct.pack('>H', len(obj.tags)))  # Tag count (big-endian)
        result.write(struct.pack('>I', len(obj.entries)))  # Entry count (big-endian)

        # Calculate mask size
        mask_size = (len(obj.entries) + 7) // 8

        # Rebuild tag bitmasks from entry tags
        tag_masks: dict[str, bytes] = {}
        for tag in obj.tags:
            mask = bytearray(mask_size)
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

            # Write bit mask (use rebuilt mask to ensure consistency)
            result.write(tag_masks[tag.name])

        # Write file entries
        for entry in obj.entries:
            # Write filename (null-terminated)
            result.write(entry.filename.encode('utf-8'))
            result.write(b'\x00')

            # Write MD5 hash
            result.write(entry.md5_hash)

            # Write file size (4 bytes big-endian)
            result.write(struct.pack('>I', entry.size))

            # Write file type for V2
            if entry.file_type is not None:
                result.write(struct.pack('B', entry.file_type))

        return result.getvalue()


class InstallBuilder:
    """Builder for install manifest files."""

    def __init__(self):
        """Initialize install builder."""
        pass

    def build(self, obj: InstallFile) -> bytes:
        """Build install file from object.

        Args:
            obj: Install file object to build

        Returns:
            Binary install data
        """
        parser = InstallParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls) -> InstallFile:
        """Create an empty install file.

        Returns:
            Empty install file object
        """
        return InstallFile(
            version=1,
            hash_size=16,
            tags=[],
            entries=[]
        )

    @classmethod
    def create_with_entries(cls, entries: list[InstallEntry], tags: list[InstallTag] | None = None) -> InstallFile:
        """Create install file with given entries.

        Args:
            entries: List of install entries
            tags: Optional list of tags

        Returns:
            Install file object
        """
        return InstallFile(
            version=1,
            hash_size=16,
            tags=tags or [],
            entries=entries
        )


def is_install(data: bytes) -> bool:
    """Check if data appears to be an install manifest.

    Args:
        data: Data to check

    Returns:
        True if data appears to be an install manifest
    """
    if len(data) < 2:
        return False

    # Check for IN magic
    return data[:2] == b'IN'
