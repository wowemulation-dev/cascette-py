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

        # Validate version (only version 1 is known)
        if version != 1:
            raise ValueError(f"Unsupported TVFS version: {version}")

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
        entries: list[TVFSEntry] = []

        for i in range(entry_count):
            # Read entry data (28 bytes: 16 + 8 + 4)
            entry_data = stream.read(28)
            if len(entry_data) != 28:
                raise ValueError(
                    f"Invalid entry {i} size: {len(entry_data)}, expected 28"
                )

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
                    raise ValueError(
                        f"Entry {i} content key must be 16 bytes, got {len(entry.ckey)}"
                    )
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

    def find_entries_by_path_hash(
        self, obj: TVFSFile, path_hash: int
    ) -> list[TVFSEntry]:
        """Find entries by path hash.

        Args:
            obj: TVFS file object
            path_hash: Path hash to search for

        Returns:
            List of matching entries
        """
        return obj.get_entries_by_path_hash(path_hash)

    def find_entry_by_file_data_id(
        self, obj: TVFSFile, file_data_id: int
    ) -> TVFSEntry | None:
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
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=1,
            block_count=0,
            entry_count=0,
            max_file_data_id=0,
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
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=1,
            block_count=1,
            entry_count=len(entries),
            max_file_data_id=max(e.file_data_id for e in entries) if entries else 0,
        )

        return TVFSFile(header=header, entries=entries)


# ---------------------------------------------------------------------------
# TVFS v3 (CASC v3 / WoW 8.2+) support
#
# The v3 layout replaces the legacy flat entry list with four tables:
#   - Path table: prefix-tree encoding of file paths (leaf = VFS byte offset)
#   - VFS table: span-based file entries (span_count + N spans)
#   - Container file table (CFT): fixed-stride EKey/encoded-size entries
#     addressed by byte offset from VFS spans
#   - Encoding spec table (EST): null-terminated encoding specs, present
#     when flag 0x02 is set
#
# Header is 38 bytes, or 46 with the EST fields. All integers big-endian.
# Flags: 0x01 include ckey, 0x02 encoding spec, 0x04 patch support.
# ---------------------------------------------------------------------------


class TVFSV3Header(BaseModel):
    """TVFS v3 header (38 bytes, 46 with encoding spec table)."""

    magic: bytes = Field(description="Magic bytes 'TVFS'")
    format_version: int = Field(description="Format version (1)")
    header_size: int = Field(description="Header size (38 or 46)")
    ekey_size: int = Field(description="EKey size (9)")
    pkey_size: int = Field(description="PKey size (9)")
    flags: int = Field(description="Format flags")
    path_table_offset: int = Field(description="Path table offset")
    path_table_size: int = Field(description="Path table size")
    vfs_table_offset: int = Field(description="VFS table offset")
    vfs_table_size: int = Field(description="VFS table size")
    cft_table_offset: int = Field(description="Container file table offset")
    cft_table_size: int = Field(description="Container file table size")
    max_depth: int = Field(description="Maximum path depth")
    est_table_offset: int | None = Field(default=None, description="EST offset")
    est_table_size: int | None = Field(default=None, description="EST size")

    def includes_content_keys(self) -> bool:
        """Whether the CFT carries content keys."""
        return (self.flags & 0x01) != 0

    def has_encoding_spec(self) -> bool:
        """Whether the header carries the EST fields."""
        return (self.flags & 0x02) != 0

    def has_patch_support(self) -> bool:
        """Whether the CFT carries patch offsets."""
        return (self.flags & 0x04) != 0

    def cft_offs_size(self) -> int:
        """Byte width of CFT offsets in VFS spans (CascLib GetOffsetFieldSize)."""
        return _offset_field_size(self.cft_table_size)

    def est_offs_size(self) -> int:
        """Byte width of EST offsets in CFT entries."""
        return _offset_field_size(self.est_table_size or 0)

    def cft_entry_size(self) -> int:
        """Byte size of one CFT entry."""
        size = self.ekey_size + 4  # EKey + encoded size
        if self.includes_content_keys():
            size += self.pkey_size
        if self.has_encoding_spec():
            size += self.est_offs_size()
        if self.has_patch_support():
            size += self.cft_offs_size()
        return size


def _offset_field_size(size: int) -> int:
    """Minimum bytes to address any offset in a table of `size` bytes."""
    if size > 0x00FF_FFFF:
        return 4
    if size > 0x0000_FFFF:
        return 3
    if size > 0x0000_00FF:
        return 2
    return 1


class TVFSV3PathFile(BaseModel):
    """A resolved file path entry from the path table."""

    path: str = Field(description="Full path (components joined by /)")
    vfs_offset: int = Field(description="Byte offset into the VFS table")


class TVFSV3VfsSpan(BaseModel):
    """A single span within a VFS entry."""

    file_offset: int = Field(description="Offset within the referenced content")
    span_length: int = Field(description="Content size of this span")
    cft_offset: int = Field(description="Byte offset into the container file table")


class TVFSV3VfsEntry(BaseModel):
    """A VFS entry with one or more spans."""

    offset: int = Field(description="Byte offset within the VFS table")
    spans: list[TVFSV3VfsSpan] = Field(description="Spans making up this file")


class TVFSV3ContainerEntry(BaseModel):
    """A container file table entry."""

    offset: int = Field(description="Byte offset within the CFT")
    ekey: bytes = Field(description="Encoding key (truncated)")
    encoded_size: int = Field(description="Encoded (compressed) size")
    content_key: bytes | None = Field(default=None, description="Content key")
    est_index: int | None = Field(default=None, description="Encoding spec index")
    patch_offset: int | None = Field(default=None, description="Patch CFT offset")


class TVFSV3File(BaseModel):
    """Complete TVFS v3 file structure."""

    header: TVFSV3Header = Field(description="File header")
    path_files: list[TVFSV3PathFile] = Field(
        default_factory=list, description="Resolved file paths"
    )
    vfs_entries: list[TVFSV3VfsEntry] = Field(
        default_factory=list, description="VFS span entries"
    )
    container_entries: list[TVFSV3ContainerEntry] = Field(
        default_factory=list, description="Container file table entries"
    )
    est_specs: list[str] = Field(default_factory=list, description="Encoding specs")

    def cft_ekey_set(self) -> set[bytes]:
        """All distinct ekeys referenced by the container file table."""
        return {e.ekey for e in self.container_entries}

    def path_to_ekey(self) -> dict[str, bytes]:
        """Map file path -> ekey via path table -> VFS span -> CFT lookup."""
        by_offset = {e.offset: e for e in self.vfs_entries}
        cft_by_offset = {e.offset: e for e in self.container_entries}
        result: dict[str, bytes] = {}
        for pf in self.path_files:
            vfs = by_offset.get(pf.vfs_offset)
            if not vfs or not vfs.spans:
                continue
            cft = cft_by_offset.get(vfs.spans[0].cft_offset)
            if cft:
                result[pf.path] = cft.ekey
        return result

    def __str__(self) -> str:
        """String representation."""
        return (
            f"TVFS v3: {len(self.path_files)} paths, "
            f"{len(self.vfs_entries)} vfs entries, "
            f"{len(self.container_entries)} cft entries"
        )


class TVFSV3Parser(FormatParser[TVFSV3File]):
    """Parser for the TVFS v3 (CASC v3) format."""

    def parse(self, data: bytes | BinaryIO) -> TVFSV3File:
        """Parse a TVFS v3 file from decompressed bytes.

        Args:
            data: Decompressed TVFS binary data

        Returns:
            Parsed TVFS v3 file

        Raises:
            ValueError: If data is invalid
        """
        if isinstance(data, bytes):
            raw = data
        else:
            raw = data.read()
        if len(raw) < 38:
            raise ValueError(f"TVFS v3 data too short: {len(raw)} bytes")

        header = self._parse_header(raw)
        path_files = self._parse_path_table(
            raw, header.path_table_offset, header.path_table_size
        )
        vfs_entries = self._parse_vfs_table(
            raw, header.vfs_table_offset, header.vfs_table_size, header
        )
        container_entries = self._parse_cft(
            raw, header.cft_table_offset, header.cft_table_size, header
        )
        est_specs: list[str] = []
        if header.has_encoding_spec() and header.est_table_offset is not None:
            est_specs = self._parse_est(
                raw, header.est_table_offset, header.est_table_size or 0
            )

        return TVFSV3File(
            header=header,
            path_files=path_files,
            vfs_entries=vfs_entries,
            container_entries=container_entries,
            est_specs=est_specs,
        )

    def build(self, obj: TVFSV3File) -> bytes:
        """Build a TVFS v3 file from the parsed model.

        Rebuilds the table blobs in place using the header offsets.
        """
        raise NotImplementedError("TVFS v3 build is not implemented")

    def _parse_header(self, raw: bytes) -> TVFSV3Header:
        magic = raw[0:4]
        if magic != b"TVFS":
            raise ValueError(f"Invalid TVFS magic: {magic!r}")
        format_version = raw[4]
        if format_version != 1:
            raise ValueError(f"Unsupported TVFS v3 version: {format_version}")
        header_size = raw[5]
        ekey_size = raw[6]
        pkey_size = raw[7]
        flags = int.from_bytes(raw[8:12], "big")
        path_off = int.from_bytes(raw[12:16], "big")
        path_sz = int.from_bytes(raw[16:20], "big")
        vfs_off = int.from_bytes(raw[20:24], "big")
        vfs_sz = int.from_bytes(raw[24:28], "big")
        cft_off = int.from_bytes(raw[28:32], "big")
        cft_sz = int.from_bytes(raw[32:36], "big")
        max_depth = int.from_bytes(raw[36:38], "big")
        est_off = est_sz = None
        if flags & 0x02:
            if len(raw) < 46:
                raise ValueError("TVFS v3 header truncated (missing EST fields)")
            est_off = int.from_bytes(raw[38:42], "big")
            est_sz = int.from_bytes(raw[42:46], "big")
        return TVFSV3Header(
            magic=magic,
            format_version=format_version,
            header_size=header_size,
            ekey_size=ekey_size,
            pkey_size=pkey_size,
            flags=flags,
            path_table_offset=path_off,
            path_table_size=path_sz,
            vfs_table_offset=vfs_off,
            vfs_table_size=vfs_sz,
            cft_table_offset=cft_off,
            cft_table_size=cft_sz,
            max_depth=max_depth,
            est_table_offset=est_off,
            est_table_size=est_sz,
        )

    def _parse_path_table(
        self, raw: bytes, offset: int, size: int
    ) -> list[TVFSV3PathFile]:
        """Parse the prefix-tree path table, resolving file leaves.

        Matches CascLib's CapturePathEntry / ParsePathFileTable:
        - 0x00 byte = path separator (optional, before a name fragment)
        - name fragments are length-prefixed: length byte + name bytes;
          consecutive fragments within one entry are concatenated (trie
          sharing), with an optional 0x00 separator between them
        - 0xFF + 4-byte BE NodeValue terminates a leaf
          - bit 31 set: folder node, lower 31 bits = folder data length
            (includes the 4-byte NodeValue itself)
          - bit 31 clear: file node, value = byte offset into the VFS table
        """
        if offset + size > len(raw):
            raise ValueError("TVFS v3 path table out of bounds")
        data = raw[offset : offset + size]
        files: list[TVFSV3PathFile] = []

        def walk(start: int, end: int, prefix: list[str]) -> None:
            pos = start
            while pos < end:
                # optional leading path separator
                if data[pos] == 0x00:
                    pos += 1
                # name fragments until 0xFF node value marker
                fragments: list[bytes] = []
                while pos < end and data[pos] != 0xFF:
                    name_len = data[pos]
                    pos += 1
                    if pos + name_len > end:
                        return
                    fragments.append(data[pos : pos + name_len])
                    pos += name_len
                    # optional separator before next fragment / marker
                    if pos < end and data[pos] == 0x00:
                        pos += 1
                if pos >= end or data[pos] != 0xFF:
                    return
                pos += 1  # skip 0xFF
                if pos + 4 > end:
                    return
                node_value = int.from_bytes(data[pos : pos + 4], "big")
                pos += 4
                name = b"".join(fragments).decode("utf-8", errors="replace")
                if node_value & 0x8000_0000:
                    # folder: children are inline; length includes the 4-byte NodeValue
                    children_len = (node_value & 0x7FFF_FFFF) - 4
                    children_start = pos
                    children_end = min(children_start + children_len, end)
                    walk(children_start, children_end, prefix + [name])
                    pos = children_end
                else:
                    files.append(
                        TVFSV3PathFile(
                            path="/".join(prefix + [name]), vfs_offset=node_value
                        )
                    )

        walk(0, len(data), [])
        return files

    def _parse_vfs_table(
        self, raw: bytes, offset: int, size: int, header: TVFSV3Header
    ) -> list[TVFSV3VfsEntry]:
        """Parse the VFS table: span_count(1) + N × (file_offset(4) + span_length(4) + cft_offset(cft_offs_size))."""
        if offset + size > len(raw):
            raise ValueError("TVFS v3 VFS table out of bounds")
        data = raw[offset : offset + size]
        cft_offs_size = header.cft_offs_size()
        entries: list[TVFSV3VfsEntry] = []
        pos = 0
        while pos < len(data):
            entry_offset = pos
            span_count = data[pos]
            pos += 1
            spans: list[TVFSV3VfsSpan] = []
            for _ in range(span_count):
                if pos + 8 + cft_offs_size > len(data):
                    break
                file_off = int.from_bytes(data[pos : pos + 4], "big")
                span_len = int.from_bytes(data[pos + 4 : pos + 8], "big")
                cft_off = int.from_bytes(data[pos + 8 : pos + 8 + cft_offs_size], "big")
                pos += 8 + cft_offs_size
                spans.append(
                    TVFSV3VfsSpan(
                        file_offset=file_off,
                        span_length=span_len,
                        cft_offset=cft_off,
                    )
                )
            if span_count == 255:
                continue  # deleted entry
            entries.append(TVFSV3VfsEntry(offset=entry_offset, spans=spans))
        return entries

    def _parse_cft(
        self, raw: bytes, offset: int, size: int, header: TVFSV3Header
    ) -> list[TVFSV3ContainerEntry]:
        """Parse the container file table (fixed-stride entries)."""
        if offset + size > len(raw):
            raise ValueError("TVFS v3 CFT out of bounds")
        data = raw[offset : offset + size]
        entry_size = header.cft_entry_size()
        entries: list[TVFSV3ContainerEntry] = []
        pos = 0
        while pos + entry_size <= len(data):
            e = self._read_cft_entry(data, pos, header)
            entries.append(e)
            pos += entry_size
        return entries

    def _read_cft_entry(
        self, data: bytes, offset: int, header: TVFSV3Header
    ) -> TVFSV3ContainerEntry:
        ekey_size = header.ekey_size
        pos = offset
        ekey = data[pos : pos + ekey_size]
        pos += ekey_size
        encoded_size = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        content_key: bytes | None = None
        if header.includes_content_keys():
            content_key = data[pos : pos + header.pkey_size]
            pos += header.pkey_size
        est_index: int | None = None
        if header.has_encoding_spec():
            sz = header.est_offs_size()
            est_index = int.from_bytes(data[pos : pos + sz], "big")
            pos += sz
        patch_offset: int | None = None
        if header.has_patch_support():
            sz = header.cft_offs_size()
            patch_offset = int.from_bytes(data[pos : pos + sz], "big")
            pos += sz
        return TVFSV3ContainerEntry(
            offset=offset,
            ekey=ekey,
            encoded_size=encoded_size,
            content_key=content_key,
            est_index=est_index,
            patch_offset=patch_offset,
        )

    def _parse_est(self, raw: bytes, offset: int, size: int) -> list[str]:
        """Parse null-terminated encoding spec strings."""
        if offset + size > len(raw):
            raise ValueError("TVFS v3 EST out of bounds")
        data = raw[offset : offset + size]
        specs: list[str] = []
        start = 0
        for i, byte in enumerate(data):
            if byte == 0:
                if i > start:
                    specs.append(data[start:i].decode("utf-8", errors="replace"))
                start = i + 1
        return specs
