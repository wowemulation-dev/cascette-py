"""TVFS (TACT Virtual File System) format parser."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class TVFSEntry(BaseModel):
    """TVFS file entry."""

    ckey: bytes = Field(description="Content key (16 bytes MD5 hash)")
    path_hash: int = Field(description="Path hash (8 bytes Jenkins96, little-endian)")
    file_data_id: int = Field(description="File Data ID (4 bytes, little-endian)")
    flags: int = Field(default=0, description="Entry flags")

    def __str__(self) -> str:
        """String representation of entry."""
        return f"FileDataID:{self.file_data_id} CKey:{self.ckey.hex()[:16]} PathHash:{self.path_hash:016x}"


class TVFSHeader(BaseModel):
    """TVFS header structure."""

    magic: bytes = Field(description="Magic bytes 'TVFS'")
    version: int = Field(description="Format version")
    flags: int = Field(description="Header flags")
    data_version: int = Field(description="Data version")
    reserved: int = Field(default=0, description="Reserved field")
    block_count: int = Field(description="Block count")
    entry_count: int = Field(description="Entry count")
    max_file_data_id: int = Field(description="Maximum file data ID")

    def __str__(self) -> str:
        """String representation of header."""
        return f"TVFS v{self.version} - {self.entry_count} entries, max FileDataID: {self.max_file_data_id}"


class TVFSFile(BaseModel):
    """Complete TVFS file structure."""

    header: TVFSHeader = Field(description="File header")
    entries: list[TVFSEntry] = Field(description="File entries")

    def get_entry_by_file_data_id(self, file_data_id: int) -> TVFSEntry | None:
        """Get entry by file data ID.

        Args:
            file_data_id: File data ID to search for

        Returns:
            Matching entry or None if not found
        """
        for entry in self.entries:
            if entry.file_data_id == file_data_id:
                return entry
        return None

    def get_entries_by_path_hash(self, path_hash: int) -> list[TVFSEntry]:
        """Get entries by path hash.

        Args:
            path_hash: Path hash to search for

        Returns:
            List of matching entries
        """
        return [entry for entry in self.entries if entry.path_hash == path_hash]

    def get_entry_by_content_key(self, ckey: bytes) -> TVFSEntry | None:
        """Get entry by content key.

        Args:
            ckey: Content key to search for

        Returns:
            Matching entry or None if not found
        """
        for entry in self.entries:
            if entry.ckey == ckey:
                return entry
        return None

    def __str__(self) -> str:
        """String representation of file."""
        return f"TVFS: {self.header} ({len(self.entries)} entries)"


class TVFSParser(FormatParser[TVFSFile]):
    """Parser for TVFS format."""

    def parse(self, data: bytes | BinaryIO) -> TVFSFile:
        """Parse TVFS file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed TVFS file

        Raises:
            ValueError: If data is invalid or corrupted
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header = self._parse_header(stream)

        # Parse entries
        entries = self._parse_entries(stream, header.entry_count)

        return TVFSFile(header=header, entries=entries)

    def _parse_header(self, stream: BinaryIO) -> TVFSHeader:
        """Parse TVFS header.

        Args:
            stream: Binary stream

        Returns:
            Parsed header

        Raises:
            ValueError: If header is invalid
        """
        # Read header data (20 bytes total)
        header_data = stream.read(20)
        if len(header_data) != 20:
            raise ValueError(f"Invalid header size: {len(header_data)}, expected 20")

        # Unpack header fields
        try:
            (
                magic,
                version,
                flags,
                data_version,
                reserved,
                block_count,
                entry_count,
                max_file_data_id,
            ) = struct.unpack(">4sBBBBIII", header_data)
        except struct.error as e:
            raise ValueError(f"Failed to unpack header: {e}") from e

        # Validate magic
        if magic != b"TVFS":
            raise ValueError(f"Invalid magic: {magic!r}, expected b'TVFS'")

        # Log parsed header
        logger.debug(
            "Parsed TVFS header",
            version=version,
            flags=flags,
            data_version=data_version,
            block_count=block_count,
            entry_count=entry_count,
            max_file_data_id=max_file_data_id,
        )

        return TVFSHeader(
            magic=magic,
            version=version,
            flags=flags,
            data_version=data_version,
            reserved=reserved,
            block_count=block_count,
            entry_count=entry_count,
            max_file_data_id=max_file_data_id,
        )

    def _parse_entries(self, stream: BinaryIO, entry_count: int) -> list[TVFSEntry]:
        """Parse TVFS entries.

        Args:
            stream: Binary stream
            entry_count: Number of entries to parse

        Returns:
            List of parsed entries

        Raises:
            ValueError: If entries are invalid
        """
        entries = []

        for i in range(entry_count):
            # Read entry data (28 bytes: 16 + 8 + 4)
            entry_data = stream.read(28)
            if len(entry_data) != 28:
                raise ValueError(f"Invalid entry {i} size: {len(entry_data)}, expected 28")

            try:
                # Unpack: content key (16), path hash (8, little-endian), file data id (4, little-endian)
                ckey = entry_data[:16]
                path_hash = struct.unpack("<Q", entry_data[16:24])[0]
                file_data_id = struct.unpack("<I", entry_data[24:28])[0]
            except struct.error as e:
                raise ValueError(f"Failed to unpack entry {i}: {e}") from e

            entry = TVFSEntry(
                ckey=ckey,
                path_hash=path_hash,
                file_data_id=file_data_id,
                flags=0,  # No flags in this simplified format
            )
            entries.append(entry)

        logger.debug("Parsed TVFS entries", count=len(entries))
        return entries

    def build(self, obj: TVFSFile) -> bytes:
        """Build TVFS binary data from object.

        Args:
            obj: TVFS file object

        Returns:
            Binary data

        Raises:
            ValueError: If object is invalid
        """
        output = BytesIO()

        # Build header
        try:
            header_data = struct.pack(
                ">4sBBBBIII",
                obj.header.magic,
                obj.header.version,
                obj.header.flags,
                obj.header.data_version,
                obj.header.reserved,
                obj.header.block_count,
                obj.header.entry_count,
                obj.header.max_file_data_id,
            )
            output.write(header_data)
        except struct.error as e:
            raise ValueError(f"Failed to pack header: {e}") from e

        # Build entries
        for i, entry in enumerate(obj.entries):
            try:
                # Content key (16 bytes)
                if len(entry.ckey) != 16:
                    raise ValueError(f"Entry {i} content key must be 16 bytes, got {len(entry.ckey)}")
                output.write(entry.ckey)

                # Path hash (8 bytes, little-endian)
                path_hash_data = struct.pack("<Q", entry.path_hash)
                output.write(path_hash_data)

                # File data ID (4 bytes, little-endian)
                file_data_id_data = struct.pack("<I", entry.file_data_id)
                output.write(file_data_id_data)

            except struct.error as e:
                raise ValueError(f"Failed to pack entry {i}: {e}") from e

        result = output.getvalue()
        logger.debug("Built TVFS data", size=len(result))
        return result

    def calculate_path_hash(self, path: str) -> int:
        """Calculate Jenkins96 path hash for a file path.

        This is a simplified placeholder implementation.
        The actual Jenkins96 hash requires proper implementation.

        Args:
            path: File path

        Returns:
            Path hash (placeholder implementation)
        """
        # Simple hash placeholder - in real implementation this should be Jenkins96
        path_bytes = path.lower().encode("utf-8")
        hash_value = 0
        for byte in path_bytes:
            hash_value = ((hash_value << 5) + hash_value + byte) & 0xFFFFFFFFFFFFFFFF
        return hash_value

    def find_entries_by_path_hash(self, obj: TVFSFile, path_hash: int) -> list[TVFSEntry]:
        """Find entries by path hash.

        Args:
            obj: TVFS file object
            path_hash: Path hash to search for

        Returns:
            List of matching entries
        """
        return obj.get_entries_by_path_hash(path_hash)

    def find_entry_by_file_data_id(self, obj: TVFSFile, file_data_id: int) -> TVFSEntry | None:
        """Find entry by file data ID.

        Args:
            obj: TVFS file object
            file_data_id: File data ID to search for

        Returns:
            Matching entry or None if not found
        """
        return obj.get_entry_by_file_data_id(file_data_id)


class TVFSBuilder:
    """Builder for TVFS files."""

    def __init__(self):
        """Initialize TVFS builder."""
        pass

    def build(self, obj: TVFSFile) -> bytes:
        """Build TVFS file from object.

        Args:
            obj: TVFS file object to build

        Returns:
            Binary TVFS data
        """
        parser = TVFSParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls) -> TVFSFile:
        """Create an empty TVFS file.

        Returns:
            Empty TVFS file object
        """
        header = TVFSHeader(
            magic=b'TVFS',
            version=1,
            flags=0,
            data_version=1,
            block_count=0,
            entry_count=0,
            max_file_data_id=0
        )

        return TVFSFile(header=header, entries=[])

    @classmethod
    def create_with_entries(cls, entries: list[TVFSEntry]) -> TVFSFile:
        """Create TVFS file with given entries.

        Args:
            entries: List of TVFS entries

        Returns:
            TVFS file object
        """
        header = TVFSHeader(
            magic=b'TVFS',
            version=1,
            flags=0,
            data_version=1,
            block_count=1,
            entry_count=len(entries),
            max_file_data_id=max(e.file_data_id for e in entries) if entries else 0
        )

        return TVFSFile(header=header, entries=entries)
