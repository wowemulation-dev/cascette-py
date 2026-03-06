"""Patch Archive (PA) format parser for NGDP/CASC.

The Patch Archive format is used by NGDP/TACT to describe differential patches
between different versions of content. PA files contain patch manifests that map
old content keys to new content keys via patch data, enabling incremental
updates through ZBSDIFF1 patches.

Format Structure (verified against BuildBackup and Agent.exe):
- Header (10 bytes, big-endian):
  - Magic: 'PA' (2 bytes)
  - Version: 1 byte (1 or 2)
  - File key size: 1 byte (16 for MD5)
  - Old key size: 1 byte (16 for MD5)
  - Patch key size: 1 byte (16 for MD5)
  - Block size bits: 1 byte (block_size = 1 << bits)
  - Block count: 2 bytes (big-endian)
  - Flags: 1 byte (bit 0: plain data, bit 1: encoding info present)
- Encoding info (when flags bit 1 set):
  - Encoding CKey: file_key_size bytes
  - Encoding EKey: file_key_size bytes
  - Decoded size: 4 bytes (big-endian)
  - Encoded size: 4 bytes (big-endian)
  - ESpec length: 1 byte
  - ESpec string: espec_length bytes (length-prefixed, NOT null-terminated)
- Block table (block_count entries):
  - Last file CKey: file_key_size bytes
  - Block MD5: 16 bytes
  - Block offset: 4 bytes (big-endian, absolute offset in file)
- File entries per block (at block_offset):
  - num_patches: 1 byte (0 = end of block)
  - Target file CKey: file_key_size bytes
  - Decoded size: 5 bytes (uint40, big-endian)
  - Per source patch (num_patches times):
    - Source file EKey: old_key_size bytes
    - Decoded size: 5 bytes (uint40, big-endian)
    - Patch EKey: patch_key_size bytes
    - Patch size: 4 bytes (big-endian)
    - Patch index: 1 byte
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
    version: int = Field(description="Version (1 or 2)")
    file_key_size: int = Field(description="File key size (16 for MD5)")
    old_key_size: int = Field(description="Old key size (16 for MD5)")
    patch_key_size: int = Field(description="Patch key size (16 for MD5)")
    block_size_bits: int = Field(description="Block size bits (block_size = 1 << bits)")
    block_count: int = Field(description="Block count")
    flags: int = Field(description="Flags")

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def is_plain_data(self) -> bool:
        """Check if flag bit 0 (plain data) is set."""
        return (self.flags & 0x01) != 0

    def has_extended_header(self) -> bool:
        """Check if flag bit 1 (encoding info) is set."""
        return (self.flags & 0x02) != 0


class PatchEncodingInfo(BaseModel):
    """Encoding file information from extended header."""

    encoding_ckey: bytes = Field(description="Encoding file content key")
    encoding_ekey: bytes = Field(description="Encoding file encoding key")
    decoded_size: int = Field(description="Encoding file decoded size")
    encoded_size: int = Field(description="Encoding file encoded size")
    encoding_spec: str = Field(description="Encoding format specification")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class FilePatch(BaseModel):
    """A single source patch within a file entry."""

    source_ekey: bytes = Field(description="Source file encoding key")
    source_decoded_size: int = Field(description="Source file decoded size")
    patch_ekey: bytes = Field(description="Patch encoding key")
    patch_size: int = Field(description="Patch data size in bytes")
    patch_index: int = Field(description="Patch application order index")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class FileEntry(BaseModel):
    """A file entry within a block, containing one or more patches."""

    target_ckey: bytes = Field(description="Target file content key")
    decoded_size: int = Field(description="Target file decoded size")
    patches: list[FilePatch] = Field(description="Source patches for this file")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class BlockEntry(BaseModel):
    """A block table entry."""

    last_file_ckey: bytes = Field(description="Last file content key in this block")
    block_md5: bytes = Field(description="MD5 hash of block data")
    block_offset: int = Field(description="Absolute byte offset of block data")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PatchEntry(BaseModel):
    """Flattened patch entry for backward compatibility.

    Each PatchEntry maps one source file to its patch. A FileEntry
    with multiple patches produces multiple PatchEntry objects.
    """

    old_content_key: bytes = Field(description="Source file encoding key")
    new_content_key: bytes = Field(description="Target file content key")
    patch_encoding_key: bytes = Field(description="Patch encoding key")
    compression_info: str = Field(default="", description="Compression specification (unused in block format)")

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PatchArchiveFile(BaseModel):
    """Complete patch archive file representation."""

    header: PatchArchiveHeader = Field(description="PA file header")
    entries: list[PatchEntry] = Field(description="Flattened patch entries")
    encoding_info: PatchEncodingInfo | None = Field(default=None, description="Encoding file info (from extended header)")
    blocks: list[BlockEntry] = Field(default_factory=list, description="Block table entries")
    file_entries: list[FileEntry] = Field(default_factory=list, description="Structured file entries")

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
        spec: dict[str, Any] = {
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
            return str(spec_dict['original'])

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
            option_parts: list[str] = []
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
        header, offset = self._parse_header(raw_data)

        # Parse encoding info if extended header flag is set
        encoding_info = None
        if header.has_extended_header():
            encoding_info, offset = self._parse_encoding_info(raw_data, offset, header)

        # Parse block table
        blocks, offset = self._parse_block_table(raw_data, offset, header)

        # Parse file entries from blocks
        file_entries = self._parse_file_entries(raw_data, blocks, header)

        # Flatten file entries into PatchEntry objects for backward compatibility
        entries = self._flatten_entries(file_entries)

        logger.debug("Parsed patch archive",
                     blocks=len(blocks),
                     file_entries=len(file_entries),
                     total_patches=len(entries))

        return PatchArchiveFile(
            header=header,
            entries=entries,
            encoding_info=encoding_info,
            blocks=blocks,
            file_entries=file_entries,
        )

    def _parse_header(self, data: bytes) -> tuple[PatchArchiveHeader, int]:
        """Parse PA format header.

        Returns:
            Tuple of (header, offset after header)
        """
        header_data = data[:PA_HEADER_SIZE]

        magic = header_data[0:2]
        if magic != PA_MAGIC:
            raise ValueError(f"Invalid PA magic: {magic!r}, expected {PA_MAGIC!r}")

        version = header_data[2]
        file_key_size = header_data[3]
        old_key_size = header_data[4]
        patch_key_size = header_data[5]
        block_size_bits = header_data[6]
        block_count = struct.unpack('>H', header_data[7:9])[0]
        flags = header_data[9]

        if version not in [1, 2]:
            logger.warning("Unexpected PA version", version=version)

        if not (12 <= block_size_bits <= 24):
            raise ValueError(
                f"Invalid block_size_bits {block_size_bits}: must be 12-24 "
                f"(block size = 1 << block_size_bits)"
            )

        header = PatchArchiveHeader(
            magic=magic,
            version=version,
            file_key_size=file_key_size,
            old_key_size=old_key_size,
            patch_key_size=patch_key_size,
            block_size_bits=block_size_bits,
            block_count=block_count,
            flags=flags
        )

        return header, PA_HEADER_SIZE

    def _parse_encoding_info(
        self, data: bytes, offset: int, header: PatchArchiveHeader
    ) -> tuple[PatchEncodingInfo, int]:
        """Parse encoding info from extended header."""
        fks = header.file_key_size

        enc_ckey = data[offset:offset + fks]
        offset += fks
        enc_ekey = data[offset:offset + fks]
        offset += fks

        decoded_size = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        encoded_size = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4

        espec_len = data[offset]
        offset += 1
        espec = data[offset:offset + espec_len].decode('utf-8')
        offset += espec_len

        info = PatchEncodingInfo(
            encoding_ckey=enc_ckey,
            encoding_ekey=enc_ekey,
            decoded_size=decoded_size,
            encoded_size=encoded_size,
            encoding_spec=espec,
        )

        logger.debug("Parsed encoding info",
                     decoded_size=decoded_size,
                     encoded_size=encoded_size,
                     espec_len=espec_len)

        return info, offset

    def _parse_block_table(
        self, data: bytes, offset: int, header: PatchArchiveHeader
    ) -> tuple[list[BlockEntry], int]:
        """Parse block table entries."""
        blocks: list[BlockEntry] = []
        fks = header.file_key_size

        for _ in range(header.block_count):
            last_ckey = data[offset:offset + fks]
            offset += fks
            block_md5 = data[offset:offset + 16]
            offset += 16
            block_offset = struct.unpack('>I', data[offset:offset + 4])[0]
            offset += 4

            blocks.append(BlockEntry(
                last_file_ckey=last_ckey,
                block_md5=block_md5,
                block_offset=block_offset,
            ))

        return blocks, offset

    def _parse_file_entries(
        self, data: bytes, blocks: list[BlockEntry], header: PatchArchiveHeader
    ) -> list[FileEntry]:
        """Parse file entries from block data."""
        file_entries: list[FileEntry] = []
        fks = header.file_key_size
        oks = header.old_key_size
        pks = header.patch_key_size

        for block in blocks:
            pos = block.block_offset

            while pos < len(data):
                if pos >= len(data):
                    break

                num_patches = data[pos]
                pos += 1

                if num_patches == 0:
                    break

                # Target file CKey
                target_ckey = data[pos:pos + fks]
                pos += fks

                # Decoded size (uint40 big-endian)
                decoded_size = int.from_bytes(data[pos:pos + 5], 'big')
                pos += 5

                patches: list[FilePatch] = []
                for _ in range(num_patches):
                    src_ekey = data[pos:pos + oks]
                    pos += oks
                    src_dec_size = int.from_bytes(data[pos:pos + 5], 'big')
                    pos += 5
                    patch_ekey = data[pos:pos + pks]
                    pos += pks
                    patch_size = struct.unpack('>I', data[pos:pos + 4])[0]
                    pos += 4
                    patch_idx = data[pos]
                    pos += 1

                    patches.append(FilePatch(
                        source_ekey=src_ekey,
                        source_decoded_size=src_dec_size,
                        patch_ekey=patch_ekey,
                        patch_size=patch_size,
                        patch_index=patch_idx,
                    ))

                file_entries.append(FileEntry(
                    target_ckey=target_ckey,
                    decoded_size=decoded_size,
                    patches=patches,
                ))

        return file_entries

    def _flatten_entries(self, file_entries: list[FileEntry]) -> list[PatchEntry]:
        """Flatten structured file entries into PatchEntry objects.

        Each FileEntry with N patches produces N PatchEntry objects.
        """
        entries: list[PatchEntry] = []
        for fe in file_entries:
            for patch in fe.patches:
                entries.append(PatchEntry(
                    old_content_key=patch.source_ekey,
                    new_content_key=fe.target_ckey,
                    patch_encoding_key=patch.patch_ekey,
                ))
        return entries

    def build(self, obj: PatchArchiveFile) -> bytes:
        """Build binary data from patch archive object.

        Builds a simplified PA file without encoding info or block structure.
        For creating test data only.
        """
        result = bytearray()

        header = obj.header

        if header.magic != PA_MAGIC:
            raise ValueError(f"Invalid magic: {header.magic!r}")
        if header.file_key_size <= 0 or header.old_key_size <= 0 or header.patch_key_size <= 0:
            raise ValueError("Key sizes must be positive")

        # Pack header
        result.extend(header.magic)
        result.append(header.version)
        result.append(header.file_key_size)
        result.append(header.old_key_size)
        result.append(header.patch_key_size)
        result.append(header.block_size_bits)
        result.extend(struct.pack('>H', header.block_count))
        result.append(header.flags)

        # Build flattened entries (simplified format for tests)
        for entry in obj.entries:
            if len(entry.old_content_key) != header.old_key_size:
                raise ValueError(f"Old key size mismatch: {len(entry.old_content_key)} != {header.old_key_size}")
            if len(entry.new_content_key) != header.file_key_size:
                raise ValueError(f"New key size mismatch: {len(entry.new_content_key)} != {header.file_key_size}")
            if len(entry.patch_encoding_key) != header.patch_key_size:
                raise ValueError(f"Patch key size mismatch: {len(entry.patch_encoding_key)} != {header.patch_key_size}")

            result.extend(entry.old_content_key)
            result.extend(entry.new_content_key)
            result.extend(entry.patch_encoding_key)

            compression_bytes = entry.compression_info.encode('utf-8')
            result.extend(compression_bytes)
            result.append(0)

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
        """Build patch archive file from object."""
        parser = PatchArchiveParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls, version: int = 2, key_size: int = 16) -> PatchArchiveFile:
        """Create an empty patch archive file."""
        return create_empty_patch_archive(version, key_size)

    @classmethod
    def create_with_entries(cls, entries: list[PatchEntry], version: int = 2) -> PatchArchiveFile:
        """Create patch archive with given entries."""
        header = PatchArchiveHeader(
            magic=b'PA',
            version=version,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=len(entries),
            flags=0
        )

        return PatchArchiveFile(header=header, entries=entries)


def create_empty_patch_archive(version: int = 2, key_size: int = DEFAULT_KEY_SIZE) -> PatchArchiveFile:
    """Create an empty patch archive file."""
    header = PatchArchiveHeader(
        magic=PA_MAGIC,
        version=version,
        file_key_size=key_size,
        old_key_size=key_size,
        patch_key_size=key_size,
        block_size_bits=16,
        block_count=0,
        flags=0
    )

    return PatchArchiveFile(header=header, entries=[])
