"""Size manifest format parser for NGDP/CASC.

The size manifest (``DS`` magic) maps partial encoding keys to estimated
file sizes (eSize). It is used for pre-download space allocation and
progress reporting.

Binary layout (per CascLib / cascette-rs / wowdev.wiki, verified against
real builds):

    [Header: 15 bytes]
      magic[2]        "DS"
      version[1]      Format version (1; the only version seen in the wild)
      ekey_size[1]    EKey length per entry in bytes (typically 9)
      num_files[4]    Number of file entries (big-endian u32)
      num_tags[2]     Number of tags between header and file entries (BE u16)
      total_size[5]   40-bit big-endian sum of all entry esizes
    [Tags: variable]
      num_tags × (null-terminated name + u16 BE type + bitmap of
      ceil(num_files/8) bytes)
    [Entries: fixed stride]
      num_files × (ekey[ekey_size] + esize[4] BE), sorted by esize desc

Earlier versions of this parser assumed a legacy layout (10-byte header,
null-terminated string keys, key hashes) that does not match the real
format; that caused ``Invalid eSize byte count`` errors when parsing
real manifests.
"""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class SizeTag(BaseModel):
    """Size manifest tag with file indices and bitmap support."""

    name: str = Field(description="Tag name")
    tag_id: int = Field(description="Tag identifier (16-bit)")
    tag_type: int = Field(
        description="Tag type (Platform=0x0001, Architecture=0x0002, etc.)"
    )
    file_indices: list[int] = Field(description="List of file indices with this tag")
    bit_mask: bytes = Field(
        default_factory=bytes,
        description="Bitmap of files with this tag (one bit per file)",
    )

    def has_file(self, file_index: int) -> bool:
        """Check if file at given index has this tag.

        Uses bitmap if available, otherwise checks indices list.
        Bitmap uses MSB bit ordering (bit 7 is LSB, bit 0 is MSB).
        """
        if self.bit_mask:
            byte_index = file_index >> 3  # Divide by 8
            bit_position = file_index & 7  # Modulo 8
            bit_mask = 0x80 >> bit_position
            return (self.bit_mask[byte_index] & bit_mask) != 0
        return file_index in self.file_indices


class SizeEntry(BaseModel):
    """Size manifest file entry.

    A partial encoding key (``ekey_size`` bytes) mapped to an estimated
    file size. On disk each entry is ``ekey_size + 4`` bytes, fixed
    stride, sorted descending by esize.
    """

    key: bytes = Field(description="Partial encoding key (ekey_size bytes)")
    esize: int = Field(description="Estimated file size")

    def __str__(self) -> str:
        """String representation."""
        return f"SizeEntry(key={self.key.hex()[:16]}…, esize={self.esize})"


class SizeHeader(BaseModel):
    """Size manifest header (15 bytes)."""

    version: int = Field(description="Format version (1 or 2)")
    ekey_size: int = Field(default=9, description="EKey length per entry in bytes")
    entry_count: int = Field(description="Number of file entries")
    tag_count: int = Field(default=0, description="Number of tag entries")
    total_size: int | None = Field(
        default=None, description="Total size across all entries (40-bit)"
    )


class SizeFile(BaseModel):
    """Complete size manifest structure."""

    header: SizeHeader = Field(description="Manifest header")
    entries: list[SizeEntry] = Field(description="File entries")
    tags: list[SizeTag] = Field(
        default_factory=lambda: list[SizeTag](), description="Tag definitions"
    )


class SizeParser(FormatParser[SizeFile]):
    """Parser for the size manifest (DS) format."""

    HEADER_SIZE = 15

    def parse(self, data: bytes | BinaryIO) -> SizeFile:
        """Parse a size manifest.

        Args:
            data: Binary data or stream (decompressed)

        Returns:
            Parsed size manifest

        Raises:
            ValueError: If data is invalid or corrupted
        """
        if isinstance(data, bytes):
            raw = data
        else:
            raw = data.read()

        if len(raw) < self.HEADER_SIZE:
            raise ValueError(
                f"Insufficient data for header: {len(raw)} bytes, "
                f"expected {self.HEADER_SIZE}"
            )
        if raw[:2] != b"DS":
            raise ValueError(f"Invalid magic: {raw[:2].hex()}, expected 4453 (DS)")

        version = raw[2]
        ekey_size = raw[3]
        entry_count = struct.unpack(">I", raw[4:8])[0]
        tag_count = struct.unpack(">H", raw[8:10])[0]
        total_size = int.from_bytes(raw[10:15], "big")

        if version == 0 or version > 2:
            raise ValueError(f"Unsupported size manifest version: {version}")
        if ekey_size == 0 or ekey_size > 16:
            raise ValueError(f"Invalid eKey byte count: {ekey_size}")

        header = SizeHeader(
            version=version,
            ekey_size=ekey_size,
            entry_count=entry_count,
            tag_count=tag_count,
            total_size=total_size,
        )

        pos = self.HEADER_SIZE
        bitfield_len = (entry_count + 7) // 8

        # Tags between header and entries
        tags: list[SizeTag] = []
        for tag_idx in range(tag_count):
            if pos >= len(raw):
                raise ValueError(f"Insufficient data for tag {tag_idx}")
            end = raw.index(0, pos) if 0 in raw[pos:] else len(raw)
            name = raw[pos:end].decode("utf-8", errors="replace")
            pos = end + 1
            if pos + 2 > len(raw):
                raise ValueError(f"Insufficient data for tag type at tag {tag_idx}")
            tag_type = struct.unpack(">H", raw[pos : pos + 2])[0]
            pos += 2
            if tag_type == 0 or tag_type == 0xFFFF:
                break  # end marker
            if pos + bitfield_len > len(raw):
                raise ValueError(f"Insufficient data for tag bitmap at tag {tag_idx}")
            bitmap = raw[pos : pos + bitfield_len]
            pos += bitfield_len

            file_indices: list[int] = []
            for byte_idx, byte_val in enumerate(bitmap):
                if byte_val == 0:
                    continue
                for bit_idx in range(8):
                    if byte_val & (0x80 >> bit_idx):
                        file_indices.append(byte_idx * 8 + bit_idx)

            tags.append(
                SizeTag(
                    name=name,
                    tag_id=tag_idx,
                    tag_type=tag_type,
                    file_indices=file_indices,
                    bit_mask=bitmap,
                )
            )

        # Fixed-stride entries
        stride = ekey_size + 4
        needed = pos + stride * entry_count
        if len(raw) < needed:
            raise ValueError(
                f"Insufficient data for entries: need {needed}, have {len(raw)}"
            )

        entries: list[SizeEntry] = []
        for _ in range(entry_count):
            key = raw[pos : pos + ekey_size]
            pos += ekey_size
            esize = struct.unpack(">I", raw[pos : pos + 4])[0]
            pos += 4
            entries.append(SizeEntry(key=key, esize=esize))

        logger.debug(
            "Parsed size manifest",
            version=version,
            ekey_size=ekey_size,
            entry_count=entry_count,
            tag_count=len(tags),
            total_size=total_size,
        )
        return SizeFile(header=header, entries=entries, tags=tags)

    def parse_tag_entries(
        self, data: bytes | BinaryIO, tag_count: int, entry_count: int
    ) -> list[SizeTag]:
        """Parse tag entries from a size manifest tag blob.

        Tag Entry Structure (variable length, inline):
            - Null-terminated tag name string
            - 2-byte BE tag type
            - Bitmap data: (entry_count + 7) >> 3 bytes

        End markers 0x0000 or 0xFFFF stop parsing.

        Args:
            data: Binary tag blob data
            tag_count: Number of tag entries to parse
            entry_count: Total number of file entries (determines bitmap size)

        Returns:
            List of parsed SizeTag objects
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        tags: list[SizeTag] = []
        ptr = 0
        entry_index = 0
        bitmap_size = (entry_count + 7) >> 3

        while entry_index < tag_count:
            stream.seek(ptr)
            name_bytes = b""
            while True:
                byte = stream.read(1)
                if not byte or byte == b"\x00":
                    break
                name_bytes += byte
            tag_name = name_bytes.decode("utf-8", errors="replace")
            null_offset = stream.tell() - 1

            tag_type_offset = null_offset + 1
            stream.seek(tag_type_offset)
            tag_type_data = stream.read(2)
            if len(tag_type_data) < 2:
                logger.warning("Incomplete tag entry header at index %d", entry_index)
                break
            tag_type = struct.unpack(">H", tag_type_data)[0]

            if tag_type == 0 or tag_type == 0xFFFF:
                logger.debug(
                    "End of tag entries at index %d (marker: 0x%04x)",
                    entry_index,
                    tag_type,
                )
                break

            bitmap_offset = null_offset + 3
            stream.seek(bitmap_offset)
            bitmap = stream.read(bitmap_size)

            file_indices: list[int] = []
            for byte_idx, byte_val in enumerate(bitmap):
                if byte_val == 0:
                    continue
                for bit_idx in range(8):
                    if byte_val & (0x80 >> bit_idx):
                        file_indices.append(byte_idx * 8 + bit_idx)

            tags.append(
                SizeTag(
                    name=tag_name,
                    tag_id=entry_index,
                    tag_type=tag_type,
                    file_indices=file_indices,
                    bit_mask=bitmap,
                )
            )
            ptr = bitmap_offset + bitmap_size
            entry_index += 1

        logger.debug("Parsed %d tag entries", len(tags))
        return tags

    def build(self, obj: SizeFile) -> bytes:
        """Build size manifest binary data.

        Args:
            obj: Size manifest structure

        Returns:
            Binary size data
        """
        result = BytesIO()
        ekey_size = obj.header.ekey_size or 9
        entry_count = len(obj.entries)
        total_size = obj.header.total_size or 0

        # Header
        result.write(b"DS")
        result.write(struct.pack("B", obj.header.version))
        result.write(struct.pack("B", ekey_size))
        result.write(struct.pack(">I", entry_count))
        result.write(struct.pack(">H", len(obj.tags)))
        if total_size >= (1 << 40):
            raise ValueError(f"Total size too large: {total_size}")
        result.write(total_size.to_bytes(5, "big"))

        # Tags (null-terminated name + u16 BE type + bitmap)
        bitfield_len = (entry_count + 7) // 8
        for tag in obj.tags:
            result.write(tag.name.encode("utf-8"))
            result.write(b"\x00")
            result.write(struct.pack(">H", tag.tag_type))
            mask = tag.bit_mask
            if len(mask) < bitfield_len:
                mask = mask + b"\x00" * (bitfield_len - len(mask))
            result.write(mask[:bitfield_len])

        # Entries (ekey + 4-byte esize, fixed stride)
        for entry in obj.entries:
            key = entry.key
            if len(key) != ekey_size:
                raise ValueError(
                    f"Entry key length {len(key)} != header ekey_size {ekey_size}"
                )
            result.write(key)
            result.write(struct.pack(">I", entry.esize))

        return result.getvalue()


class SizeBuilder:
    """Builder for size manifest files."""

    def __init__(self) -> None:
        """Initialize size builder."""
        pass

    def build(self, obj: SizeFile) -> bytes:
        """Build size file from object.

        Args:
            obj: Size file object to build

        Returns:
            Binary size data
        """
        parser = SizeParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls, version: int = 1) -> SizeFile:
        """Create an empty size file.

        Args:
            version: Size manifest version (1 or 2)

        Returns:
            Empty size file object
        """
        header = SizeHeader(
            version=version,
            ekey_size=9,
            entry_count=0,
            tag_count=0,
            total_size=0,
        )
        return SizeFile(header=header, entries=[], tags=[])

    @classmethod
    def create_with_entries(
        cls,
        entries: list[SizeEntry],
        version: int = 1,
        ekey_size: int = 9,
    ) -> SizeFile:
        """Create size file with given entries.

        Args:
            entries: List of size entries
            version: Size manifest version (1 or 2)
            ekey_size: EKey length per entry in bytes (default 9)

        Returns:
            Size file object
        """
        total_size = sum(entry.esize for entry in entries)
        header = SizeHeader(
            version=version,
            ekey_size=ekey_size,
            entry_count=len(entries),
            tag_count=0,
            total_size=total_size,
        )
        return SizeFile(header=header, entries=entries, tags=[])


def is_size(data: bytes) -> bool:
    """Check if data appears to be a size manifest.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a size manifest
    """
    if len(data) < 2:
        return False
    return data[:2] == b"DS"


def parse_tag_query(query: str) -> list[tuple[str, bool]]:
    """Parse tag query string into list of (tag_name, is_subtractive) tuples.

    Tag query syntax supports:
    - Additive tags: "enUS,frFR" - selects files with any of these tags
    - Subtractive tags: "enUS,!beta" - selects enUS files excluding beta files
    - Mixed queries: "enUS,!beta,debug" - combines additive and subtractive
    - Delimiters: comma (','), question mark ('?'), colon (':')

    Args:
        query: Tag query string

    Returns:
        List of (tag_name, is_subtractive) tuples
    """
    if not query:
        return []

    # Split on delimiters: ',', '?', ':'
    tokens: list[str] = []
    current: list[str] = []

    for char in query:
        if char in (",", "?", ":"):
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        tokens.append("".join(current))

    # Parse each token
    result: list[tuple[str, bool]] = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue

        is_subtractive = token.startswith("!")
        tag_name = token[1:] if is_subtractive else token

        if tag_name:
            result.append((tag_name, is_subtractive))

    logger.debug("Parsed tag query '%s' into %d tokens", query, len(result))
    return result


def apply_tag_query(tags: list[SizeTag], query: str, file_count: int) -> bytes:
    """Apply tag query and generate selection bitmap matching Agent.exe behavior.

    Tag query logic (from Agent.exe ApplyTagQuery / cascette-rs
    get_files_for_tag_query):
    1. Requested tags are grouped by TagType (Platform, Architecture,
       Locale, etc.)
    2. Within each group, the tag bitmasks are OR'd — a file matches the
       group if ANY tag in the group matches (multi-locale installs).
    3. Between groups, the group masks are AND'd — a file must match ALL
       groups.
    4. Subtractive tags (prefixed with `!`) clear bits after the groups
       have been combined.

    Args:
        tags: List of SizeTag objects
        query: Tag query string (e.g., "enUS,!beta,debug" or
            "Windows,x86_64,enUS")
        file_count: Total number of files in manifest

    Returns:
        Bitmap of selected files (one bit per file)
    """
    # Calculate bitmap size
    bitmap_size = (file_count + 7) // 8

    # Parse query
    parsed_query = parse_tag_query(query)

    # If no tags or empty query, return all selected
    if not tags or not query or not parsed_query:
        logger.debug("No tags or empty query, returning all files selected")
        return bytes([0xFF] * bitmap_size)

    # Create tag lookup for quick access
    tag_map: dict[str, SizeTag] = {tag.name: tag for tag in tags}

    # Resolve query tokens to tags, split subtractive from additive
    additive: list[SizeTag] = []
    subtractive: list[SizeTag] = []
    for tag_name, is_subtractive in parsed_query:
        tag = tag_map.get(tag_name)
        if tag is None:
            logger.warning("Unknown tag '%s' found in query, ignoring", tag_name)
            continue
        (subtractive if is_subtractive else additive).append(tag)

    # No recognized tags: keep the legacy fallback (all selected).
    if not additive and not subtractive:
        logger.debug("No recognized tags in query, returning all files selected")
        return bytes([0xFF] * bitmap_size)

    # AND identity: start with all bits set.
    result_mask = bytearray([0xFF] * bitmap_size)

    # OR within tag-type group, AND between groups.
    if additive:
        groups: dict[int, list[SizeTag]] = {}
        for tag in additive:
            groups.setdefault(tag.tag_type, []).append(tag)

        for group_tags in groups.values():
            # OR identity: start with all bits clear.
            group_mask = bytearray(bitmap_size)
            for tag in group_tags:
                for i in range(min(len(tag.bit_mask), bitmap_size)):
                    group_mask[i] |= tag.bit_mask[i]
            # AND between groups.
            for i in range(bitmap_size):
                result_mask[i] &= group_mask[i]

    # Subtractive tags clear bits.
    for tag in subtractive:
        for i in range(min(len(tag.bit_mask), bitmap_size)):
            result_mask[i] &= ~tag.bit_mask[i]

    logger.debug("Applied tag query, bitmap size: %d bytes", len(result_mask))
    return bytes(result_mask)


def is_file_selected(bitmap: bytes, file_index: int) -> bool:
    """Check if file at given index is selected in bitmap.

    Implements IsFileSelected from Agent.exe:
    - byteOffset = fileIndex >> 3 (divide by 8)
    - bitPosition = fileIndex & 7 (modulo 8)
    - bitMask = 0x80 >> bitPosition

    Args:
        bitmap: File selection bitmap
        file_index: Index of file to check

    Returns:
        True if file is selected
    """
    byte_offset = file_index >> 3
    bit_position = file_index & 7
    bit_mask = 0x80 >> bit_position

    if byte_offset >= len(bitmap):
        return False

    return (bitmap[byte_offset] & bit_mask) != 0
