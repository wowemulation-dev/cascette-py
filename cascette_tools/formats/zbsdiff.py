"""ZBSDIFF1 (Zlib-compressed Binary Differential) format parser.

The ZBSDIFF1 format is a zlib-compressed binary differential patch format
used by NGDP/TACT for efficient file updates. Based on the bsdiff algorithm
by Colin Percival, with zlib compression applied to all data blocks.

Format Structure:
- 32-byte header (big-endian) with format signature and block sizes
- Control block (zlib-compressed): patch instructions
- Diff block (zlib-compressed): data differences
- Extra block (zlib-compressed): new data insertions

Key Features:
- Memory-efficient streaming application without loading entire files
- Zlib compression on all data blocks for minimal patch size
- Big-endian header format, little-endian control entries
- Size validation (1GB limit for safety)
"""

from __future__ import annotations

import struct
import zlib
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field, field_validator

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()

# Safety limits
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
MAX_CONTROL_ENTRIES = 100000  # Reasonable limit for control entries


class ZbsdiffHeader(BaseModel):
    """ZBSDIFF1 format header (32 bytes, big-endian)."""

    magic: bytes = Field(description="Magic bytes (ZBSDIFF1)")
    control_length: int = Field(description="Control block compressed size (8 bytes)")
    diff_length: int = Field(description="Diff block compressed size (8 bytes)")
    new_size: int = Field(description="Target file size after patching (8 bytes)")

    @field_validator("magic")
    @classmethod
    def validate_magic(cls, v: bytes) -> bytes:
        """Validate magic bytes."""
        if v != b"ZBSDIFF1":
            raise ValueError(f"Invalid ZBSDIFF1 magic: {v!r}")
        return v

    @field_validator("control_length", "diff_length", "new_size")
    @classmethod
    def validate_sizes(cls, v: int) -> int:
        """Validate size fields are reasonable."""
        if v < 0:
            raise ValueError(f"Size cannot be negative: {v}")
        if v > MAX_FILE_SIZE:
            raise ValueError(f"Size too large: {v} > {MAX_FILE_SIZE}")
        return v


class ZbsdiffControlEntry(BaseModel):
    """Single control entry from control block (24 bytes total)."""

    add_length: int = Field(description="Bytes to copy from diff block")
    copy_length: int = Field(description="Bytes to copy from old file")
    offset: int = Field(description="Relative seek in old file (can be negative)")

    @field_validator("add_length", "copy_length")
    @classmethod
    def validate_lengths(cls, v: int) -> int:
        """Validate length fields are non-negative."""
        if v < 0:
            raise ValueError(f"Length cannot be negative: {v}")
        return v


class ZbsdiffFile(BaseModel):
    """Complete ZBSDIFF1 file structure."""

    header: ZbsdiffHeader = Field(description="File header")
    control_entries: list[ZbsdiffControlEntry] = Field(description="Control block entries")
    diff_data: bytes = Field(description="Diff block data (decompressed)")
    extra_data: bytes = Field(description="Extra block data (decompressed)")

    @field_validator("control_entries")
    @classmethod
    def validate_control_entries(cls, v: list[ZbsdiffControlEntry]) -> list[ZbsdiffControlEntry]:
        """Validate control entries count."""
        if len(v) > MAX_CONTROL_ENTRIES:
            raise ValueError(f"Too many control entries: {len(v)} > {MAX_CONTROL_ENTRIES}")
        return v


class ZbsdiffParser(FormatParser[ZbsdiffFile]):
    """Parser for ZBSDIFF1 binary differential patch files."""

    MAGIC = b"ZBSDIFF1"
    HEADER_SIZE = 32

    def parse(self, data: bytes | BinaryIO) -> ZbsdiffFile:
        """Parse ZBSDIFF1 data.

        Args:
            data: Binary data or stream

        Returns:
            Parsed ZBSDIFF1 file

        Raises:
            ValueError: If data is invalid or corrupted
        """
        if isinstance(data, (bytes, bytearray)):
            stream = BytesIO(data)
        else:
            stream = data

        try:
            # Parse header
            header = self._parse_header(stream)
            logger.debug("Parsed header",
                        control_length=header.control_length,
                        diff_length=header.diff_length,
                        new_size=header.new_size)

            # Extract compressed blocks
            control_compressed = stream.read(header.control_length)
            if len(control_compressed) != header.control_length:
                raise ValueError(f"Control block too short: {len(control_compressed)} < {header.control_length}")

            diff_compressed = stream.read(header.diff_length)
            if len(diff_compressed) != header.diff_length:
                raise ValueError(f"Diff block too short: {len(diff_compressed)} < {header.diff_length}")

            extra_compressed = stream.read()  # Read remaining data

            # Decompress blocks
            try:
                control_data = zlib.decompress(control_compressed)
            except zlib.error as e:
                raise ValueError(f"Failed to decompress control block: {e}") from e

            try:
                diff_data = zlib.decompress(diff_compressed)
            except zlib.error as e:
                raise ValueError(f"Failed to decompress diff block: {e}") from e

            try:
                extra_data = zlib.decompress(extra_compressed) if extra_compressed else b""
            except zlib.error as e:
                raise ValueError(f"Failed to decompress extra block: {e}") from e

            # Parse control entries
            control_entries = self._parse_control_entries(control_data)

            logger.debug("Parsed ZBSDIFF1 file",
                        control_entries=len(control_entries),
                        diff_size=len(diff_data),
                        extra_size=len(extra_data))

            return ZbsdiffFile(
                header=header,
                control_entries=control_entries,
                diff_data=diff_data,
                extra_data=extra_data
            )

        except struct.error as e:
            raise ValueError(f"Failed to parse ZBSDIFF1 data: {e}") from e

    def build(self, obj: ZbsdiffFile) -> bytes:
        """Build binary data from ZBSDIFF1 object.

        Args:
            obj: ZBSDIFF1 file object

        Returns:
            Binary data
        """
        # Build control block
        control_data = self._build_control_entries(obj.control_entries)

        # Compress blocks
        control_compressed = zlib.compress(control_data)
        diff_compressed = zlib.compress(obj.diff_data)
        extra_compressed = zlib.compress(obj.extra_data) if obj.extra_data else b""

        # Update header with actual compressed sizes
        header = ZbsdiffHeader(
            magic=self.MAGIC,
            control_length=len(control_compressed),
            diff_length=len(diff_compressed),
            new_size=obj.header.new_size
        )

        # Build header
        header_data = self._build_header(header)

        return header_data + control_compressed + diff_compressed + extra_compressed

    def apply_patch(self, old_data: bytes, patch: ZbsdiffFile) -> bytes:
        """Apply ZBSDIFF1 patch to old data.

        Args:
            old_data: Original data to patch
            patch: ZBSDIFF1 patch to apply

        Returns:
            Patched data

        Raises:
            ValueError: If patch application fails
        """
        if len(old_data) > MAX_FILE_SIZE:
            raise ValueError(f"Old file too large: {len(old_data)} > {MAX_FILE_SIZE}")

        new_data = bytearray(patch.header.new_size)
        old_pos = 0
        new_pos = 0
        diff_pos = 0
        extra_pos = 0

        try:
            for i, entry in enumerate(patch.control_entries):
                # Add from diff block
                if entry.add_length > 0:
                    if diff_pos + entry.add_length > len(patch.diff_data):
                        raise ValueError(f"Diff block overflow at entry {i}")
                    if new_pos + entry.add_length > len(new_data):
                        raise ValueError(f"New data overflow at entry {i}")

                    # Add diff data to old data
                    for j in range(entry.add_length):
                        if old_pos + j < len(old_data):
                            new_data[new_pos + j] = (old_data[old_pos + j] + patch.diff_data[diff_pos + j]) & 0xFF
                        else:
                            new_data[new_pos + j] = patch.diff_data[diff_pos + j]

                    old_pos += entry.add_length
                    new_pos += entry.add_length
                    diff_pos += entry.add_length

                # Copy from extra block
                if entry.copy_length > 0:
                    if extra_pos + entry.copy_length > len(patch.extra_data):
                        raise ValueError(f"Extra block overflow at entry {i}")
                    if new_pos + entry.copy_length > len(new_data):
                        raise ValueError(f"New data overflow at entry {i}")

                    new_data[new_pos:new_pos + entry.copy_length] = patch.extra_data[extra_pos:extra_pos + entry.copy_length]

                    new_pos += entry.copy_length
                    extra_pos += entry.copy_length

                # Seek in old file (affects next entry's starting position)
                old_pos += entry.offset
                if old_pos < 0:
                    raise ValueError(f"Negative old position at entry {i}")

        except (IndexError, OverflowError) as e:
            raise ValueError(f"Patch application failed: {e}") from e

        return bytes(new_data)

    def _parse_header(self, stream: BinaryIO) -> ZbsdiffHeader:
        """Parse ZBSDIFF1 header."""
        header_data = stream.read(self.HEADER_SIZE)
        if len(header_data) != self.HEADER_SIZE:
            raise ValueError(f"Header too short: {len(header_data)} < {self.HEADER_SIZE}")

        # Parse header fields (all big-endian)
        magic = header_data[0:8]
        control_length = struct.unpack(">Q", header_data[8:16])[0]
        diff_length = struct.unpack(">Q", header_data[16:24])[0]
        new_size = struct.unpack(">Q", header_data[24:32])[0]

        return ZbsdiffHeader(
            magic=magic,
            control_length=control_length,
            diff_length=diff_length,
            new_size=new_size
        )

    def _build_header(self, header: ZbsdiffHeader) -> bytes:
        """Build ZBSDIFF1 header."""
        return (
            header.magic +
            struct.pack(">Q", header.control_length) +
            struct.pack(">Q", header.diff_length) +
            struct.pack(">Q", header.new_size)
        )

    def _parse_control_entries(self, control_data: bytes) -> list[ZbsdiffControlEntry]:
        """Parse control block into entries."""
        entries = []
        offset = 0
        entry_size = 24  # 3 signed 64-bit integers

        while offset + entry_size <= len(control_data):
            # Read three signed 64-bit little-endian integers
            add_length = struct.unpack("<q", control_data[offset:offset+8])[0]
            copy_length = struct.unpack("<q", control_data[offset+8:offset+16])[0]
            seek_offset = struct.unpack("<q", control_data[offset+16:offset+24])[0]

            # Convert to unsigned lengths, keep signed offset
            if add_length < 0:
                add_length = 0
            if copy_length < 0:
                copy_length = 0

            entry = ZbsdiffControlEntry(
                add_length=add_length,
                copy_length=copy_length,
                offset=seek_offset
            )
            entries.append(entry)

            offset += entry_size

            # Safety check
            if len(entries) > MAX_CONTROL_ENTRIES:
                raise ValueError(f"Too many control entries: {len(entries)}")

        return entries

    def _build_control_entries(self, entries: list[ZbsdiffControlEntry]) -> bytes:
        """Build control block from entries."""
        data = bytearray()

        for entry in entries:
            # Write three signed 64-bit little-endian integers
            data.extend(struct.pack("<q", entry.add_length))
            data.extend(struct.pack("<q", entry.copy_length))
            data.extend(struct.pack("<q", entry.offset))

        return bytes(data)


class ZbsdiffBuilder:
    """Builder for ZBSDIFF patch files."""

    def __init__(self):
        """Initialize ZBSDIFF builder."""
        pass

    def build(self, obj: ZbsdiffFile) -> bytes:
        """Build ZBSDIFF file from object.

        Args:
            obj: ZBSDIFF file object to build

        Returns:
            Binary ZBSDIFF data
        """
        parser = ZbsdiffParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls, new_size: int = 0) -> ZbsdiffFile:
        """Create an empty ZBSDIFF file.

        Args:
            new_size: Size of the new file

        Returns:
            Empty ZBSDIFF file object
        """
        header = ZbsdiffHeader(
            magic=b'ZBSDIFF1',
            control_length=0,
            diff_length=0,
            new_size=new_size
        )

        return ZbsdiffFile(
            header=header,
            control_entries=[],
            diff_data=b'',
            extra_data=b''
        )

    @classmethod
    def create_with_data(
        cls,
        control_entries: list[ZbsdiffControlEntry],
        diff_data: bytes,
        extra_data: bytes,
        new_size: int
    ) -> ZbsdiffFile:
        """Create ZBSDIFF file with given data.

        Args:
            control_entries: List of control entries
            diff_data: Diff data block
            extra_data: Extra data block
            new_size: Size of the new file

        Returns:
            ZBSDIFF file object
        """
        header = ZbsdiffHeader(
            magic=b'ZBSDIFF1',
            control_length=len(control_entries) * 24,  # 3 * 8 bytes per entry
            diff_length=len(diff_data),
            new_size=new_size
        )

        return ZbsdiffFile(
            header=header,
            control_entries=control_entries,
            diff_data=diff_data,
            extra_data=extra_data
        )
