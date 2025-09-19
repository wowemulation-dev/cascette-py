"""Patch Archive (PA) format parser for NGDP/CASC.

The Patch Archive format is used by NGDP/TACT to describe differential patches
between different versions of content. PA files contain manifest files that map
old content keys to new content keys and patch data, enabling incremental
updates through differential patches.

Format Structure:
- Magic: 'PA' (2 bytes)
- Version: 1 byte (typically 2)
- File key size: 1 byte (16 for MD5)
- Old key size: 1 byte (16 for MD5)
- Patch key size: 1 byte (16 for MD5)
- Block size bits: 1 byte (16 for 64KB blocks)
- Block count: 2 bytes (big-endian)
- Flags: 1 byte
- For each entry:
  - Old content key: old_key_size bytes
  - New content key: file_key_size bytes
  - Patch encoding key: patch_key_size bytes
  - Compression info: null-terminated string

Key Features:
- MD5-based content addressing (16-byte keys)
- Variable-length compression specifications
- Support for patch chains and complex update scenarios
- Big-endian header format
"""

from __future__ import annotations

import struct
from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, ConfigDict, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()

# PA format constants
PA_MAGIC = b'PA'
PA_HEADER_SIZE = 10
DEFAULT_KEY_SIZE = 16  # MD5 hash size


class PatchArchiveHeader(BaseModel):
    """PA format header (10 bytes, big-endian)."""

    magic: bytes = Field(description="Magic bytes 'PA'")
    version: int = Field(description="Version (typically 2)")
    file_key_size: int = Field(description="File key size (16 for MD5)")
    old_key_size: int = Field(description="Old key size (16 for MD5)")
    patch_key_size: int = Field(description="Patch key size (16 for MD5)")
    block_size_bits: int = Field(description="Block size bits (16 for 64KB blocks)")
    block_count: int = Field(description="Block count")
    flags: int = Field(description="Flags")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PatchEntry(BaseModel):
    """Single patch entry from PA file."""

    old_content_key: bytes = Field(description="MD5 hash of old content")
    new_content_key: bytes = Field(description="MD5 hash of new content")
    patch_encoding_key: bytes = Field(description="MD5 hash of patch data")
    compression_info: str = Field(description="Compression specification")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PatchArchiveFile(BaseModel):
    """Complete patch archive file representation."""

    header: PatchArchiveHeader = Field(description="PA file header")
    entries: list[PatchEntry] = Field(description="Patch entries")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class CompressionSpec:
    """Compression specification parser and utilities."""

    @staticmethod
    def parse(spec_string: str) -> dict[str, Any]:
        """Parse compression specification string.

        Args:
            spec_string: The compression specification string to parse

        Returns:
            Dictionary containing parsed compression information
        """
        spec = {
            'original': spec_string,
            'compression': 'none',
            'options': {}
        }

        if not spec_string:
            return spec

        # Handle common compression specs
        if spec_string == '{*=z}':
            spec['compression'] = 'zlib'
        elif spec_string == '{*=l}':
            spec['compression'] = 'lz4'
        elif spec_string.startswith('{') and spec_string.endswith('}'):
            # Complex spec - parse key=value pairs
            inner = spec_string[1:-1]
            for part in inner.split(','):
                if '=' in part:
                    key, value = part.split('=', 1)
                    spec['options'][key.strip()] = value.strip()

        return spec

    @staticmethod
    def build(spec_dict: dict[str, Any]) -> str:
        """Build compression specification string from parsed data.

        Args:
            spec_dict: Dictionary containing compression information

        Returns:
            Compression specification string
        """
        if 'original' in spec_dict:
            return spec_dict['original']

        compression = spec_dict.get('compression', 'none')
        if compression == 'zlib':
            return '{*=z}'
        elif compression == 'lz4':
            return '{*=l}'
        elif compression == 'none' or not compression:
            return ''

        # Build complex spec from options
        options = spec_dict.get('options', {})
        if options:
            option_parts = []
            for key, value in options.items():
                option_parts.append(f"{key}={value}")
            return '{' + ','.join(option_parts) + '}'

        return ''


class PatchArchiveParser(FormatParser[PatchArchiveFile]):
    """Parser for Patch Archive (PA) files."""

    def parse(self, data: bytes | BinaryIO) -> PatchArchiveFile:
        """Parse patch archive data.

        Args:
            data: Binary data or stream

        Returns:
            Parsed patch archive file

        Raises:
            ValueError: If data is invalid or cannot be parsed
        """
        if isinstance(data, (bytes, bytearray)):
            raw_data = bytes(data)
        else:
            raw_data = data.read()

        if len(raw_data) < PA_HEADER_SIZE:
            raise ValueError(f"Data too short for PA header: {len(raw_data)} < {PA_HEADER_SIZE}")

        # Parse header
        header = self._parse_header(raw_data)

        # Parse entries
        entries = self._parse_entries(raw_data, header)

        return PatchArchiveFile(header=header, entries=entries)

    def _parse_header(self, data: bytes) -> PatchArchiveHeader:
        """Parse PA format header.

        Args:
            data: Raw binary data

        Returns:
            Parsed header

        Raises:
            ValueError: If header is invalid
        """
        header_data = data[:PA_HEADER_SIZE]

        # Parse header fields (all big-endian)
        magic = header_data[0:2]
        if magic != PA_MAGIC:
            raise ValueError(f"Invalid PA magic: {magic!r}, expected {PA_MAGIC!r}")

        version = header_data[2]
        file_key_size = header_data[3]
        old_key_size = header_data[4]
        patch_key_size = header_data[5]
        block_size_bits = header_data[6]
        block_count = struct.unpack('>H', header_data[7:9])[0]  # Big-endian 16-bit
        flags = header_data[9]

        # Validate common values
        if version not in [1, 2]:
            logger.warning("Unexpected PA version", version=version)
        if file_key_size != DEFAULT_KEY_SIZE:
            logger.warning("Unexpected file key size", size=file_key_size)
        if old_key_size != DEFAULT_KEY_SIZE:
            logger.warning("Unexpected old key size", size=old_key_size)
        if patch_key_size != DEFAULT_KEY_SIZE:
            logger.warning("Unexpected patch key size", size=patch_key_size)

        return PatchArchiveHeader(
            magic=magic,
            version=version,
            file_key_size=file_key_size,
            old_key_size=old_key_size,
            patch_key_size=patch_key_size,
            block_size_bits=block_size_bits,
            block_count=block_count,
            flags=flags
        )

    def _parse_entries(self, data: bytes, header: PatchArchiveHeader, max_entries: int = 1000) -> list[PatchEntry]:
        """Parse patch entries from PA data.

        Args:
            data: Raw binary data
            header: Parsed header
            max_entries: Maximum number of entries to parse (for safety)

        Returns:
            List of parsed patch entries

        Raises:
            ValueError: If entry data is invalid
        """
        entries = []
        offset = PA_HEADER_SIZE
        entry_index = 0

        while offset < len(data) and entry_index < max_entries:
            # Check if we have enough data for minimum entry
            min_entry_size = header.old_key_size + header.file_key_size + header.patch_key_size + 1  # +1 for null terminator
            if offset + min_entry_size > len(data):
                break

            try:
                # Read old content key
                old_key_end = offset + header.old_key_size
                old_content_key = data[offset:old_key_end]
                offset = old_key_end

                # Read new content key
                new_key_end = offset + header.file_key_size
                new_content_key = data[offset:new_key_end]
                offset = new_key_end

                # Read patch encoding key
                patch_key_end = offset + header.patch_key_size
                patch_encoding_key = data[offset:patch_key_end]
                offset = patch_key_end

                # Read compression info (null-terminated string)
                compression_start = offset
                null_pos = data.find(0, offset)
                if null_pos == -1:
                    # No null terminator found, take rest of data or reasonable limit
                    compression_end = min(offset + 256, len(data))  # Reasonable limit
                    compression_info = data[compression_start:compression_end].decode('utf-8', errors='replace')
                    offset = compression_end
                else:
                    compression_info = data[compression_start:null_pos].decode('utf-8', errors='replace')
                    offset = null_pos + 1  # Skip null terminator

                entry = PatchEntry(
                    old_content_key=old_content_key,
                    new_content_key=new_content_key,
                    patch_encoding_key=patch_encoding_key,
                    compression_info=compression_info
                )

                entries.append(entry)
                entry_index += 1

            except (struct.error, UnicodeDecodeError, IndexError) as e:
                logger.warning("Error parsing entry", index=entry_index, offset=offset, error=str(e))
                break

        logger.debug("Parsed patch entries", count=len(entries))
        return entries

    def build(self, obj: PatchArchiveFile) -> bytes:
        """Build binary data from patch archive object.

        Args:
            obj: Patch archive file object

        Returns:
            Binary data representing the patch archive

        Raises:
            ValueError: If object data is invalid
        """
        result = bytearray()

        # Build header
        header = obj.header

        # Validate header values
        if header.magic != PA_MAGIC:
            raise ValueError(f"Invalid magic: {header.magic!r}")
        if header.file_key_size <= 0 or header.old_key_size <= 0 or header.patch_key_size <= 0:
            raise ValueError("Key sizes must be positive")

        # Pack header (big-endian)
        result.extend(header.magic)  # 2 bytes
        result.append(header.version)  # 1 byte
        result.append(header.file_key_size)  # 1 byte
        result.append(header.old_key_size)  # 1 byte
        result.append(header.patch_key_size)  # 1 byte
        result.append(header.block_size_bits)  # 1 byte
        result.extend(struct.pack('>H', header.block_count))  # 2 bytes, big-endian
        result.append(header.flags)  # 1 byte

        # Build entries
        for entry in obj.entries:
            # Validate key sizes
            if len(entry.old_content_key) != header.old_key_size:
                raise ValueError(f"Old key size mismatch: {len(entry.old_content_key)} != {header.old_key_size}")
            if len(entry.new_content_key) != header.file_key_size:
                raise ValueError(f"New key size mismatch: {len(entry.new_content_key)} != {header.file_key_size}")
            if len(entry.patch_encoding_key) != header.patch_key_size:
                raise ValueError(f"Patch key size mismatch: {len(entry.patch_encoding_key)} != {header.patch_key_size}")

            # Add keys
            result.extend(entry.old_content_key)
            result.extend(entry.new_content_key)
            result.extend(entry.patch_encoding_key)

            # Add compression info with null terminator
            compression_bytes = entry.compression_info.encode('utf-8')
            result.extend(compression_bytes)
            result.append(0)  # Null terminator

        return bytes(result)


def is_patch_archive(data: bytes) -> bool:
    """Check if data represents a patch archive file.

    Args:
        data: Binary data to check

    Returns:
        True if data appears to be a PA file
    """
    if len(data) < PA_HEADER_SIZE:
        return False

    return data[:2] == PA_MAGIC


class PatchArchiveBuilder:
    """Builder for patch archive files."""

    def __init__(self):
        """Initialize patch archive builder."""
        pass

    def build(self, obj: PatchArchiveFile) -> bytes:
        """Build patch archive file from object.

        Args:
            obj: Patch archive file object to build

        Returns:
            Binary patch archive data
        """
        parser = PatchArchiveParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls, version: int = 2, key_size: int = 16) -> PatchArchiveFile:
        """Create an empty patch archive file.

        Args:
            version: PA format version
            key_size: Size of content keys

        Returns:
            Empty patch archive file
        """
        return create_empty_patch_archive(version, key_size)

    @classmethod
    def create_with_entries(cls, entries: list[PatchEntry], version: int = 2) -> PatchArchiveFile:
        """Create patch archive with given entries.

        Args:
            entries: List of patch entries
            version: PA format version

        Returns:
            Patch archive file object
        """
        header = PatchArchiveHeader(
            magic=b'PA',
            version=version,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,  # 64KB blocks
            block_count=len(entries),
            flags=0
        )

        return PatchArchiveFile(header=header, entries=entries)


def create_empty_patch_archive(version: int = 2, key_size: int = DEFAULT_KEY_SIZE) -> PatchArchiveFile:
    """Create an empty patch archive file.

    Args:
        version: PA format version
        key_size: Size of content keys

    Returns:
        Empty patch archive file
    """
    header = PatchArchiveHeader(
        magic=PA_MAGIC,
        version=version,
        file_key_size=key_size,
        old_key_size=key_size,
        patch_key_size=key_size,
        block_size_bits=16,  # 64KB blocks
        block_count=0,
        flags=0
    )

    return PatchArchiveFile(header=header, entries=[])
