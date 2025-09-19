"""Root format parser for NGDP/CASC."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class RootRecord(BaseModel):
    """Root file record."""

    file_id: int = Field(description="File Data ID")
    content_key: bytes = Field(description="Content key (16 bytes)")
    name_hash: int = Field(description="Name hash (64-bit)")


class RootBlock(BaseModel):
    """Root file block."""

    num_records: int = Field(description="Number of records in block")
    content_flags: int = Field(description="Content flags")
    locale_flags: int = Field(description="Locale flags")
    records: list[RootRecord] = Field(description="File records")


class RootHeader(BaseModel):
    """Root file header."""

    version: int = Field(description="Root format version")
    magic: bytes | None = Field(default=None, description="Magic bytes (MFST)")
    header_size: int | None = Field(default=None, description="Header size (v3+)")
    version_field: int | None = Field(default=None, description="Version field (v3+)")
    total_files: int | None = Field(default=None, description="Total file count")
    named_files: int | None = Field(default=None, description="Named file count")
    padding: int | None = Field(default=None, description="Padding field (v3+)")


class RootFile(BaseModel):
    """Complete root file structure."""

    header: RootHeader = Field(description="File header")
    blocks: list[RootBlock] = Field(description="Data blocks")


class RootParser(FormatParser[RootFile]):
    """Parser for root format."""

    def parse(self, data: bytes | BinaryIO) -> RootFile:
        """Parse root file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed root file
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header = self._parse_header(stream)

        # Parse blocks
        blocks = self._parse_blocks(stream)

        return RootFile(header=header, blocks=blocks)

    def _detect_version(self, data: bytes) -> int:
        """Detect root file version from data."""
        if len(data) < 4:
            return 1

        # Check for MFST magic (or TSFM which is little-endian MFST)
        magic = data[0:4]
        if magic not in (b'MFST', b'TSFM'):
            return 1  # Pre-30080, no magic

        if len(data) < 12:
            return 2

        # Read potential counts/header size
        value1 = struct.unpack('<I', data[4:8])[0]

        # Heuristic: if first value < 1000, likely v3+ with header_size
        if value1 < 1000:
            return 3  # Build 50893+
        else:
            return 2  # Build 30080+

    def _parse_header(self, stream: BinaryIO) -> RootHeader:
        """Parse root file header based on detected version."""
        # Read all data to detect version
        current_pos = stream.tell()
        all_data = stream.read()
        stream.seek(current_pos)

        version = self._detect_version(all_data)

        if version == 1:
            # No header, raw blocks
            return RootHeader(version=1)

        # Read MFST magic
        magic_bytes = stream.read(4)
        if len(magic_bytes) != 4:
            raise ValueError("Incomplete magic bytes")

        if version == 2:
            # Version 2: Build 30080+
            total_files_bytes = stream.read(4)
            named_files_bytes = stream.read(4)

            if len(total_files_bytes) != 4 or len(named_files_bytes) != 4:
                raise ValueError("Incomplete header for version 2")

            total_files = struct.unpack('<I', total_files_bytes)[0]
            named_files = struct.unpack('<I', named_files_bytes)[0]

            return RootHeader(
                version=2,
                magic=magic_bytes,
                total_files=total_files,
                named_files=named_files
            )

        elif version == 3:
            # Version 3: Build 50893+
            header_size_bytes = stream.read(4)
            version_field_bytes = stream.read(4)
            total_files_bytes = stream.read(4)
            named_files_bytes = stream.read(4)
            padding_bytes = stream.read(4)

            if (len(header_size_bytes) != 4 or len(version_field_bytes) != 4 or
                len(total_files_bytes) != 4 or len(named_files_bytes) != 4 or
                len(padding_bytes) != 4):
                raise ValueError("Incomplete header for version 3")

            header_size = struct.unpack('<I', header_size_bytes)[0]
            version_field = struct.unpack('<I', version_field_bytes)[0]
            total_files = struct.unpack('<I', total_files_bytes)[0]
            named_files = struct.unpack('<I', named_files_bytes)[0]
            padding = struct.unpack('<I', padding_bytes)[0]

            return RootHeader(
                version=3,
                magic=magic_bytes,
                header_size=header_size,
                version_field=version_field,
                total_files=total_files,
                named_files=named_files,
                padding=padding
            )

        raise ValueError(f"Unsupported root version: {version}")

    def _parse_blocks(self, stream: BinaryIO) -> list[RootBlock]:
        """Parse all blocks in the root file."""
        blocks = []

        while True:
            block = self._parse_block(stream)
            if block is None:
                break
            blocks.append(block)

        return blocks

    def _parse_block(self, stream: BinaryIO) -> RootBlock | None:
        """Parse a single root block."""
        # Read block header
        num_records_bytes = stream.read(4)
        if len(num_records_bytes) != 4:
            return None

        num_records = struct.unpack('<I', num_records_bytes)[0]
        if num_records == 0 or num_records > 1000000:  # Sanity check
            return None

        content_flags_bytes = stream.read(4)
        locale_flags_bytes = stream.read(4)

        if len(content_flags_bytes) != 4 or len(locale_flags_bytes) != 4:
            return None

        content_flags = struct.unpack('<I', content_flags_bytes)[0]
        locale_flags = struct.unpack('<I', locale_flags_bytes)[0]

        # Read FileDataID deltas
        deltas = []
        for _ in range(num_records):
            delta_bytes = stream.read(4)
            if len(delta_bytes) != 4:
                return None
            delta = struct.unpack('<i', delta_bytes)[0]  # Signed int32
            deltas.append(delta)

        # Decode FileDataIDs from deltas
        file_ids = []
        current_id = 0
        for i, delta in enumerate(deltas):
            if i == 0:
                current_id = delta
            else:
                current_id = current_id + delta
            file_ids.append(current_id)
            current_id += 1  # Increment for next iteration

        # Read records (content keys and name hashes)
        records = []
        for i in range(num_records):
            content_key_bytes = stream.read(16)
            name_hash_bytes = stream.read(8)

            if len(content_key_bytes) != 16 or len(name_hash_bytes) != 8:
                return None

            name_hash = struct.unpack('<Q', name_hash_bytes)[0]  # 64-bit name hash

            records.append(RootRecord(
                file_id=file_ids[i],
                content_key=content_key_bytes,
                name_hash=name_hash
            ))

        return RootBlock(
            num_records=num_records,
            content_flags=content_flags,
            locale_flags=locale_flags,
            records=records
        )

    def find_file_by_id(self, root_file: RootFile, file_id: int) -> RootRecord | None:
        """Find a file entry by FileDataID.

        Args:
            root_file: Parsed root file
            file_id: File Data ID to find

        Returns:
            Found record or None
        """
        for block in root_file.blocks:
            for record in block.records:
                if record.file_id == file_id:
                    return record
        return None

    def find_files_by_content_key(self, root_file: RootFile, content_key: bytes) -> list[RootRecord]:
        """Find file entries by content key.

        Args:
            root_file: Parsed root file
            content_key: Content key to find

        Returns:
            List of matching records
        """
        matches = []
        for block in root_file.blocks:
            for record in block.records:
                if record.content_key == content_key:
                    matches.append(record)
        return matches

    def get_statistics(self, root_file: RootFile) -> dict:
        """Get statistics about the root file.

        Args:
            root_file: Parsed root file

        Returns:
            Statistics dictionary
        """
        total_files = sum(block.num_records for block in root_file.blocks)
        unique_flags = set()
        locale_counts = {}

        for block in root_file.blocks:
            flag_combo = (block.content_flags, block.locale_flags)
            unique_flags.add(flag_combo)
            locale_counts[block.locale_flags] = locale_counts.get(block.locale_flags, 0) + block.num_records

        return {
            'total_files': total_files,
            'total_blocks': len(root_file.blocks),
            'unique_flag_combinations': len(unique_flags),
            'files_per_locale': locale_counts
        }

    def build(self, obj: RootFile) -> bytes:
        """Build root binary data from file structure.

        Args:
            obj: Root file structure

        Returns:
            Binary root data
        """
        result = BytesIO()

        # Write header based on version
        header = obj.header

        if header.version >= 2:
            # Write magic
            if header.magic:
                result.write(header.magic)
            else:
                result.write(b'MFST')

            if header.version == 2:
                # Version 2 header
                result.write(struct.pack('<I', header.total_files or 0))
                result.write(struct.pack('<I', header.named_files or 0))

            elif header.version == 3:
                # Version 3 header
                result.write(struct.pack('<I', header.header_size or 24))
                result.write(struct.pack('<I', header.version_field or 3))
                result.write(struct.pack('<I', header.total_files or 0))
                result.write(struct.pack('<I', header.named_files or 0))
                result.write(struct.pack('<I', header.padding or 0))

        # Write blocks
        for block in obj.blocks:
            # Write block header
            result.write(struct.pack('<I', block.num_records))
            result.write(struct.pack('<I', block.content_flags))
            result.write(struct.pack('<I', block.locale_flags))

            # Write FileDataID deltas
            current_id = 0
            for i, record in enumerate(block.records):
                if i == 0:
                    delta = record.file_id
                else:
                    delta = record.file_id - current_id - 1
                current_id = record.file_id
                result.write(struct.pack('<i', delta))

            # Write records
            for record in block.records:
                result.write(record.content_key)
                result.write(struct.pack('<Q', record.name_hash))

        return result.getvalue()


class RootBuilder:
    """Builder for root manifest files."""

    def __init__(self):
        """Initialize root builder."""
        pass

    def build(self, obj: RootFile) -> bytes:
        """Build root file from object.

        Args:
            obj: Root file object to build

        Returns:
            Binary root data
        """
        parser = RootParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls, version: int = 1) -> RootFile:
        """Create an empty root file.

        Args:
            version: Root format version

        Returns:
            Empty root file object
        """
        if version == 1:
            header = RootHeader(magic=None, version=1, total_files=0, named_files=0)
        else:
            header = RootHeader(magic=b'TSFM', version=version, total_files=0, named_files=0)

        return RootFile(header=header, blocks=[])

    @classmethod
    def create_with_records(cls, records: list[RootRecord], version: int = 1) -> RootFile:
        """Create root file with given records.

        Args:
            records: List of root records
            version: Root format version

        Returns:
            Root file object
        """
        # Group records into blocks (simplified)
        block = RootBlock(
            num_records=len(records),
            content_flags=0,
            locale_flags=0,
            records=records
        )

        if version == 1:
            header = RootHeader(
                magic=None,
                version=1,
                total_files=len(records),
                named_files=len([r for r in records if r.name_hash != 0])
            )
        else:
            header = RootHeader(
                magic=b'TSFM',
                version=version,
                total_files=len(records),
                named_files=len([r for r in records if r.name_hash != 0])
            )

        return RootFile(header=header, blocks=[block])


def format_content_flags(flags: int) -> str:
    """Format content flags as human-readable string."""
    flag_names = []

    if flags & 0x00000001:
        flag_names.append("LoadOnWindows")
    if flags & 0x00000002:
        flag_names.append("LoadOnMacOS")
    if flags & 0x00000008:
        flag_names.append("LowViolence")
    if flags & 0x00000200:
        flag_names.append("DoNotLoad")
    if flags & 0x00000400:
        flag_names.append("UpdatePlugin")
    if flags & 0x00000800:
        flag_names.append("ARM64")
    if flags & 0x00001000:
        flag_names.append("Encrypted")
    if flags & 0x00002000:
        flag_names.append("NoNameHash")
    if flags & 0x00010000:
        flag_names.append("NoCompression")

    if not flag_names:
        return "None (0x00000000)"

    return f"{', '.join(flag_names)} (0x{flags:08x})"


def format_locale_flags(flags: int) -> str:
    """Format locale flags as human-readable string."""
    locales = {
        0x00000002: "enUS",
        0x00000004: "koKR",
        0x00000010: "frFR",
        0x00000020: "deDE",
        0x00000040: "zhCN",
        0x00000080: "zhTW",
        0x00000100: "esES",
        0x00000200: "esMX",
        0x00000400: "ruRU",
        0x00000800: "ptBR",
        0x00001000: "itIT",
        0x00002000: "ptPT"
    }

    active_locales = []
    for flag, locale in locales.items():
        if flags & flag:
            active_locales.append(locale)

    if not active_locales:
        return f"None (0x{flags:08x})"

    return f"{', '.join(active_locales)} (0x{flags:08x})"


def is_root(data: bytes) -> bool:
    """Check if data appears to be a root file.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a root file
    """
    if len(data) < 4:
        return False

    # Check for MFST magic (or TSFM which is little-endian MFST)
    magic = data[:4]
    if magic in (b'MFST', b'TSFM'):
        return True

    # For version 1 files without magic, we can't reliably detect
    # without parsing, so assume it might be a root file
    return True
