"""Size manifest format parser for NGDP/CASC."""

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
    tag_type: int = Field(description="Tag type (Platform=0x0001, Architecture=0x0002, etc.)")
    file_indices: list[int] = Field(description="List of file indices with this tag")
    bit_mask: bytes = Field(default_factory=bytes, description="Bitmap of files with this tag (one bit per file)")

    def has_file(self, file_index: int) -> bool:
        """Check if file at given index has this tag.

        Uses bitmap if available, otherwise checks indices list.
        Bitmap uses MSB bit ordering (bit 7 is LSB, bit 0 is MSB).

        Args:
            file_index: Index of file to check

        Returns:
            True if file has this tag
        """
        if self.bit_mask:
            byte_index = file_index >> 3  # Divide by 8
            bit_position = file_index & 7  # Modulo 8
            bit_mask = 0x80 >> bit_position
            return (self.bit_mask[byte_index] & bit_mask) != 0
        return file_index in self.file_indices


class SizeEntry(BaseModel):
    """Size manifest file entry."""

    key: str = Field(description="Content key (null-terminated string)")
    key_hash: int = Field(description="16-bit hash/identifier")
    esize: int = Field(description="Estimated file size")


class SizeHeader(BaseModel):
    """Size manifest header."""

    version: int = Field(description="Format version (1 or 2)")
    flags: int = Field(description="Flags byte")
    entry_count: int = Field(description="Number of entries")
    key_size_bits: int = Field(description="Key size in bits")
    total_size: int | None = Field(default=None, description="Total size across all entries")
    esize_bytes: int | None = Field(default=None, description="Byte width of eSize (V1 only)")
    tag_count: int = Field(default=0, description="Number of tag entries")


class SizeFile(BaseModel):
    """Complete size manifest structure."""

    header: SizeHeader = Field(description="Manifest header")
    entries: list[SizeEntry] = Field(description="File entries")
    tags: list[SizeTag] = Field(default_factory=list, description="Tag definitions")


class SizeParser(FormatParser[SizeFile]):
    """Parser for size format."""

    def parse(self, data: bytes | BinaryIO) -> SizeFile:
        """Parse size manifest.

        Args:
            data: Binary data or stream

        Returns:
            Parsed size manifest
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse common header (10 bytes minimum)
        # magic(2) + version(1) + flags(1) + entry_count(4) + key_size_bits(2) = 10
        header_data = stream.read(10)
        if len(header_data) < 10:
            raise ValueError("Insufficient data for header")

        magic = header_data[0:2]
        if magic != b'DS':
            raise ValueError(f"Invalid magic: {magic.hex()}, expected 4453 (DS)")

        version = header_data[2]
        flags = header_data[3]
        entry_count = struct.unpack('>I', header_data[4:8])[0]  # big-endian
        key_size_bits = struct.unpack('>H', header_data[8:10])[0]  # big-endian

        # Validate version
        if version == 0 or version > 2:
            raise ValueError(f"Unsupported size manifest version: {version}")

        logger.debug("Parsed size header",
                    version=version, flags=flags,
                    entry_count=entry_count, key_size_bits=key_size_bits)

        # Parse version-specific header fields
        total_size = None
        esize_bytes = None

        if version == 1:
            # V1: total_size (8 bytes) + esize_bytes (1 byte)
            v1_extra = stream.read(9)
            if len(v1_extra) < 9:
                raise ValueError("Insufficient data for V1 header fields")
            total_size = struct.unpack('>Q', v1_extra[0:8])[0]  # big-endian
            esize_bytes = v1_extra[8]

            if esize_bytes < 1 or esize_bytes > 8:
                raise ValueError(f"Invalid eSize byte count: {esize_bytes}")

        elif version == 2:
            # V2: total_size (5 bytes)
            v2_extra = stream.read(5)
            if len(v2_extra) < 5:
                raise ValueError("Insufficient data for V2 header fields")
            # Pad to 8 bytes for unpacking
            total_size = struct.unpack('>Q', b'\x00\x00\x00' + v2_extra)[0]
            esize_bytes = 4  # Fixed at 4 bytes for V2

        header = SizeHeader(
            version=version,
            flags=flags,
            entry_count=entry_count,
            key_size_bits=key_size_bits,
            total_size=total_size,
            esize_bytes=esize_bytes
        )

        # Calculate key size in bytes
        key_size_bytes = (key_size_bits + 7) >> 3

        # Parse entries
        entries: list[SizeEntry] = []
        for i in range(entry_count):
            # Read null-terminated key
            key_bytes = bytearray()
            while True:
                byte = stream.read(1)
                if not byte or byte == b'\x00':
                    break
                key_bytes.extend(byte)

            key = key_bytes.decode('utf-8', errors='replace')

            # Read key hash (2 bytes big-endian)
            key_hash_data = stream.read(2)
            if len(key_hash_data) < 2:
                raise ValueError(f"Insufficient data for key hash at entry {i}")
            key_hash = struct.unpack('>H', key_hash_data)[0]

            # Validate key hash (cannot be 0x0000 or 0xFFFF)
            if key_hash == 0x0000 or key_hash == 0xFFFF:
                raise ValueError(f"Invalid key hash 0x{key_hash:04X} at entry {i}")

            # Read eSize data
            esize_data = stream.read(esize_bytes)
            if len(esize_data) < esize_bytes:
                raise ValueError(f"Insufficient data for eSize at entry {i}")

            # Parse eSize based on byte width
            if esize_bytes == 1:
                esize = esize_data[0]
            elif esize_bytes == 2:
                esize = struct.unpack('>H', esize_data)[0]
            elif esize_bytes == 4:
                esize = struct.unpack('>I', esize_data)[0]
            elif esize_bytes == 8:
                esize = struct.unpack('>Q', esize_data)[0]
            else:
                esize = int.from_bytes(esize_data, byteorder='big')

            entries.append(SizeEntry(
                key=key,
                key_hash=key_hash,
                esize=esize
            ))

        return SizeFile(
            header=header,
            entries=entries,
            tags=[]  # Tags are parsed separately with parse_tag_entries()
        )

    def parse_tag_entries(self, data: bytes | BinaryIO, tag_count: int, entry_count: int) -> list[SizeTag]:
        """Parse tag entries from size manifest tag blob.

        Tag Entry Structure (variable length, inline):
            - Null-terminated tag name string
            - 2-byte BE tag type (determines tag category)
            - Bitmap data: (entry_count + 7) >> 3 bytes

        The 2-byte BE tag type indicates:
            - Tag category (Platform=0x0001, Architecture=0x0002, etc.)
            - End markers: 0x0000 or 0xFFFF stops parsing

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

        while entry_index < tag_count:
            # 1. Read null-terminated string starting at ptr
            stream.seek(ptr)
            name_bytes = b''
            while True:
                byte = stream.read(1)
                if not byte or byte == b'\x00':
                    break
                name_bytes += byte

            tag_name = name_bytes.decode('utf-8', errors='replace')
            null_offset = stream.tell() - 1  # Position of null terminator (current pos - 1 for the byte we just read)

            # 2. Read 2-byte BE tag type at null + 1
            tag_type_offset = null_offset + 1
            stream.seek(tag_type_offset)
            tag_type_data = stream.read(2)
            if len(tag_type_data) < 2:
                logger.warning("Incomplete tag entry header at index %d", entry_index)
                break

            tag_type = struct.unpack('>H', tag_type_data)[0]

            # 3. Check for end markers (0x0000 or 0xFFFF)
            if tag_type == 0 or tag_type == 0xFFFF:
                logger.debug(
                    "End of tag entries at index %d (marker: 0x%04x)",
                    entry_index, tag_type
                )
                break

            # 4. Bitmap starts at null + 3 (after null and tag type)
            bitmap_size = (entry_count + 7) >> 3
            bitmap_offset = null_offset + 3
            stream.seek(bitmap_offset)
            bitmap = stream.read(bitmap_size)

            # 5. Decode file indices from bitmap (MSB bit ordering)
            file_indices = []
            for byte_idx, byte_val in enumerate(bitmap):
                if byte_val == 0:
                    continue
                for bit_idx in range(8):
                    if byte_val & (0x80 >> bit_idx):
                        file_indices.append(byte_idx * 8 + bit_idx)

            tag_id = entry_index

            tags.append(SizeTag(
                name=tag_name,
                tag_id=tag_id,
                tag_type=tag_type,
                file_indices=file_indices,
                bit_mask=bitmap
            ))

            # 6. Advance to next entry
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

        # Write common header
        result.write(b'DS')  # Magic
        result.write(struct.pack('B', obj.header.version))  # Version
        result.write(struct.pack('B', obj.header.flags))  # Flags
        result.write(struct.pack('>I', len(obj.entries)))  # Entry count (big-endian)
        result.write(struct.pack('>H', obj.header.key_size_bits))  # Key size bits (big-endian)

        # Write version-specific fields
        if obj.header.version == 1:
            result.write(struct.pack('>Q', obj.header.total_size or 0))  # Total size
            result.write(struct.pack('B', obj.header.esize_bytes or 4))  # eSize byte width
        elif obj.header.version == 2:
            total_size = obj.header.total_size or 0
            if total_size >= (1 << 40):
                raise ValueError(f"Total size too large: {total_size}")
            size_bytes = struct.pack('>Q', total_size)[3:]  # Take last 5 bytes
            result.write(size_bytes)

        # Calculate key size in bytes
        key_size_bytes = (obj.header.key_size_bits + 7) >> 3

        # Write entries
        for entry in obj.entries:
            # Write null-terminated key
            result.write(entry.key.encode('utf-8'))
            result.write(b'\x00')

            # Write key hash (2 bytes big-endian)
            result.write(struct.pack('>H', entry.key_hash))

            # Write eSize data
            esize_bytes = obj.header.esize_bytes or 4
            if esize_bytes == 1:
                result.write(struct.pack('B', entry.esize))
            elif esize_bytes == 2:
                result.write(struct.pack('>H', entry.esize))
            elif esize_bytes == 4:
                result.write(struct.pack('>I', entry.esize))
            elif esize_bytes == 8:
                result.write(struct.pack('>Q', entry.esize))
            else:
                result.write(entry.esize.to_bytes(esize_bytes, byteorder='big'))

        return result.getvalue()


class SizeBuilder:
    """Builder for size manifest files."""

    def __init__(self):
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
    def create_empty(cls, version: int = 2) -> SizeFile:
        """Create an empty size file.

        Args:
            version: Size manifest version (1 or 2)

        Returns:
            Empty size file object
        """
        header = SizeHeader(
            version=version,
            flags=0,
            entry_count=0,
            key_size_bits=128,  # 16 bytes = 128 bits (MD5)
            total_size=0,
            esize_bytes=4 if version == 2 else 4
        )

        return SizeFile(
            header=header,
            entries=[],
            tags=[]
        )

    @classmethod
    def create_with_entries(cls, entries: list[SizeEntry], version: int = 2) -> SizeFile:
        """Create size file with given entries.

        Args:
            entries: List of size entries
            version: Size manifest version (1 or 2)

        Returns:
            Size file object
        """
        total_size = sum(entry.esize for entry in entries)
        key_size_bits = 128  # Default to MD5 (16 bytes = 128 bits)

        header = SizeHeader(
            version=version,
            flags=0,
            entry_count=len(entries),
            key_size_bits=key_size_bits,
            total_size=total_size,
            esize_bytes=4 if version == 2 else 4
        )

        return SizeFile(
            header=header,
            entries=entries,
            tags=[]
        )


def is_size(data: bytes) -> bool:
    """Check if data appears to be a size manifest.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a size manifest
    """
    if len(data) < 2:
        return False

    # Check for DS magic
    return data[:2] == b'DS'


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
    tokens = []
    current = []

    for char in query:
        if char in (',', '?', ':'):
            if current:
                tokens.append(''.join(current))
                current = []
        else:
            current.append(char)

    if current:
        tokens.append(''.join(current))

    # Parse each token
    result = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue

        is_subtractive = token.startswith('!')
        tag_name = token[1:] if is_subtractive else token

        if tag_name:
            result.append((tag_name, is_subtractive))

    logger.debug("Parsed tag query '%s' into %d tokens", query, len(result))
    return result


def apply_tag_query(
    tags: list[SizeTag],
    query: str,
    file_count: int
) -> bytes:
    """Apply tag query and generate selection bitmap matching Agent.exe behavior.

    Implements ApplyTagQuery algorithm from Agent.exe:
    1. Parse query to find matching tags
    2. If any subtractive tags, initialize bitmap to 0xFF (all selected)
       Otherwise, initialize to 0x00 (none selected)
    3. Apply tag filters:
       - Subtractive tags: clear bits to exclude files
       - Additive tags: set bits to include files

    Args:
        tags: List of SizeTag objects
        query: Tag query string (e.g., "enUS,!beta,debug")
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

    # Determine if any subtractive tags in query
    has_subtractive = any(is_subtractive for _, is_subtractive in parsed_query)

    # Initialize bitmap based on tag type
    if has_subtractive:
        # Start with all selected, then clear subtractive tags
        bitmap = bytearray([0xFF] * bitmap_size)
    else:
        # Start with none selected, then set additive tags
        bitmap = bytearray([0x00] * bitmap_size)

    # Create tag lookup for quick access
    tag_map: dict[str, SizeTag] = {tag.name: tag for tag in tags}

    # Apply each tag filter
    for tag_name, is_subtractive in parsed_query:
        tag = tag_map.get(tag_name)

        if tag is None:
            logger.warning("Unknown tag '%s' found in query, ignoring", tag_name)
            continue

        # Apply tag bitmap to selection
        for i in range(len(tag.bit_mask)):
            if i >= bitmap_size:
                break

            if is_subtractive:
                # Clear bits for subtractive tags
                bitmap[i] &= ~tag.bit_mask[i]
            else:
                # Set bits for additive tags
                bitmap[i] |= tag.bit_mask[i]

    logger.debug("Applied tag query, bitmap size: %d bytes", len(bitmap))
    return bytes(bitmap)


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
