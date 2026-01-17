"""Encoding format parser for NGDP/CASC."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class EncodingHeader(BaseModel):
    """Encoding file header."""

    magic: bytes = Field(description="Magic bytes (EN)")
    version: int = Field(description="Format version")
    ckey_size: int = Field(description="Content key size in bytes")
    ekey_size: int = Field(description="Encoding key size in bytes")
    ckey_page_size_kb: int = Field(description="CKey page size in KB")
    ekey_page_size_kb: int = Field(description="EKey page size in KB")
    ckey_page_count: int = Field(description="Number of CKey pages")
    ekey_page_count: int = Field(description="Number of EKey pages")
    unknown: int = Field(description="Unknown field")
    espec_size: int = Field(description="ESpec table size in bytes")


class CKeyPageEntry(BaseModel):
    """CKey page entry mapping content to encoding keys."""

    content_key: bytes = Field(description="Content key (MD5 hash)")
    encoding_keys: list[bytes] = Field(description="List of encoding keys")
    file_size: int = Field(description="Decompressed file size")


class EKeyPageEntry(BaseModel):
    """EKey page entry with encoding metadata."""

    encoding_key: bytes = Field(description="Encoding key (MD5 hash)")
    content_keys: list[bytes] = Field(description="Content keys")
    espec_index: int = Field(description="Index into ESpec table")
    file_size: int = Field(description="Encoded file size")


class CKeyPage(BaseModel):
    """Complete CKey page with entries."""

    page_index: int = Field(description="Page index")
    entries: list[CKeyPageEntry] = Field(description="Page entries")


class EKeyPage(BaseModel):
    """Complete EKey page with entries."""

    page_index: int = Field(description="Page index")
    entries: list[EKeyPageEntry] = Field(description="Page entries")


class EncodingFile(BaseModel):
    """Complete encoding file structure."""

    header: EncodingHeader = Field(description="File header")
    espec_table: list[str] = Field(description="ESpec string table")
    ckey_index: list[tuple[bytes, bytes]] = Field(description="CKey page index (first_key, checksum)")
    ekey_index: list[tuple[bytes, bytes]] = Field(description="EKey page index (first_key, checksum)")
    pages_start_offset: int = Field(default=0, description="Offset where pages begin (for sequential reading)")


class EncodingParser(FormatParser[EncodingFile]):
    """Parser for encoding format."""

    ENCODING_MAGIC = b'EN'
    HEADER_SIZE = 22

    def parse(self, data: bytes | BinaryIO) -> EncodingFile:
        """Parse encoding file matching exact CASC structure order.

        The correct order is:
        1. Header
        2. ESpec table
        3. CKey index
        4. CKey pages (immediately after CKey index)
        5. EKey index
        6. EKey pages

        Args:
            data: Binary data or stream

        Returns:
            Parsed encoding file
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header = self._parse_header(stream)

        # Parse ESpec table
        espec_table = self._parse_espec_table(stream, header)

        # Parse CKey index
        ckey_index = self._parse_ckey_index_sequential(stream, header)

        # CKey pages start immediately after CKey index
        pages_start_offset = stream.tell()

        # Skip CKey pages to read EKey index
        ckey_pages_size = header.ckey_page_count * header.ckey_page_size_kb * 1024
        stream.seek(pages_start_offset + ckey_pages_size)

        # Parse EKey index (after CKey pages)
        ekey_index = self._parse_ekey_index_sequential(stream, header)

        return EncodingFile(
            header=header,
            espec_table=espec_table,
            ckey_index=ckey_index,
            ekey_index=ekey_index,
            pages_start_offset=pages_start_offset
        )

    def _parse_header(self, stream: BinaryIO) -> EncodingHeader:
        """Parse encoding file header."""
        header_data = stream.read(self.HEADER_SIZE)
        if len(header_data) != self.HEADER_SIZE:
            raise ValueError(f"Incomplete header: expected {self.HEADER_SIZE}, got {len(header_data)}")

        # Parse header fields (big-endian)
        magic = header_data[0:2]
        if magic != self.ENCODING_MAGIC:
            raise ValueError(f"Invalid encoding magic: {magic}")

        version = header_data[2]
        ckey_size = header_data[3]
        ekey_size = header_data[4]
        ckey_page_size_kb = struct.unpack('>H', header_data[5:7])[0]
        ekey_page_size_kb = struct.unpack('>H', header_data[7:9])[0]
        ckey_page_count = struct.unpack('>I', header_data[9:13])[0]
        ekey_page_count = struct.unpack('>I', header_data[13:17])[0]
        unknown = header_data[17]
        espec_size = struct.unpack('>I', header_data[18:22])[0]

        return EncodingHeader(
            magic=magic,
            version=version,
            ckey_size=ckey_size,
            ekey_size=ekey_size,
            ckey_page_size_kb=ckey_page_size_kb,
            ekey_page_size_kb=ekey_page_size_kb,
            ckey_page_count=ckey_page_count,
            ekey_page_count=ekey_page_count,
            unknown=unknown,
            espec_size=espec_size
        )

    def _parse_espec_table(self, stream: BinaryIO, header: EncodingHeader) -> list[str]:
        """Parse ESpec string table."""
        if header.espec_size == 0:
            return []

        espec_data = stream.read(header.espec_size)
        if len(espec_data) != header.espec_size:
            raise ValueError(f"Incomplete ESpec table: expected {header.espec_size}, got {len(espec_data)}")

        # Split on null bytes to get individual ESpec strings
        especs = espec_data.split(b'\x00')
        return [spec.decode('ascii', errors='replace') for spec in especs if spec]

    def _parse_ckey_index(self, stream: BinaryIO, header: EncodingHeader) -> list[tuple[bytes, bytes]]:
        """Parse CKey page index."""
        # Each index entry is exactly 32 bytes: 16 bytes first_key + 16 bytes checksum
        entry_size = 32
        index_size = header.ckey_page_count * entry_size
        if index_size == 0:
            return []

        index_data = stream.read(index_size)
        if len(index_data) != index_size:
            raise ValueError(f"Incomplete CKey index: expected {index_size}, got {len(index_data)}")

        # Parse index entries
        index: list[tuple[bytes, bytes]] = []
        offset = 0

        for _ in range(header.ckey_page_count):
            if offset + entry_size > len(index_data):
                raise ValueError("CKey index truncated")
            first_key = index_data[offset:offset + 16]
            checksum = index_data[offset + 16:offset + 32]
            index.append((first_key, checksum))
            offset += entry_size

        return index

    def _parse_ekey_index(self, stream: BinaryIO, header: EncodingHeader) -> list[tuple[bytes, bytes]]:
        """Parse EKey page index."""
        # Each index entry is exactly 32 bytes: 16 bytes first_key + 16 bytes checksum
        entry_size = 32
        index_size = header.ekey_page_count * entry_size
        if index_size == 0:
            return []

        index_data = stream.read(index_size)
        if len(index_data) != index_size:
            raise ValueError(f"Incomplete EKey index: expected {index_size}, got {len(index_data)}")

        # Parse index entries
        index: list[tuple[bytes, bytes]] = []
        offset = 0

        for _ in range(header.ekey_page_count):
            if offset + entry_size > len(index_data):
                raise ValueError("EKey index truncated")
            first_key = index_data[offset:offset + 16]
            checksum = index_data[offset + 16:offset + 32]
            index.append((first_key, checksum))
            offset += entry_size

        return index

    def _parse_ckey_index_sequential(self, stream: BinaryIO, header: EncodingHeader) -> list[tuple[bytes, bytes]]:
        """Parse CKey page index sequentially like Rust."""
        index: list[tuple[bytes, bytes]] = []

        for _ in range(header.ckey_page_count):
            # Read each index entry sequentially (16 + 16 bytes)
            first_key = stream.read(16)
            checksum = stream.read(16)

            if len(first_key) != 16 or len(checksum) != 16:
                raise ValueError("Incomplete CKey index entry")

            index.append((first_key, checksum))

        return index

    def _parse_ekey_index_sequential(self, stream: BinaryIO, header: EncodingHeader) -> list[tuple[bytes, bytes]]:
        """Parse EKey page index sequentially like Rust."""
        index: list[tuple[bytes, bytes]] = []

        for _ in range(header.ekey_page_count):
            # Read each index entry sequentially (16 + 16 bytes)
            first_key = stream.read(16)
            checksum = stream.read(16)

            if len(first_key) != 16 or len(checksum) != 16:
                raise ValueError("Incomplete EKey index entry")

            index.append((first_key, checksum))

        return index

    def load_ckey_page_sequential(self, encoding_data: bytes, encoding_file: EncodingFile, page_index: int,
                                  max_entries: int = 1000) -> CKeyPage:
        """Load and parse a CKey page using sequential reading like Rust.

        Matches Rust CKeyPageEntry structure from entry_v2.rs:
        1. key_count (1 byte) - number of encoding keys
        2. file_size (40-bit: 1 byte high + 4 bytes low, big-endian)
        3. content_key (16 bytes)
        4. encoding_keys (16 bytes each, key_count times)

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            page_index: Index of page to load
            max_entries: Maximum entries to parse per page

        Returns:
            Parsed CKey page
        """
        header = encoding_file.header

        if page_index >= header.ckey_page_count:
            raise ValueError(f"Page index {page_index} >= page count {header.ckey_page_count}")

        # Calculate sequential offset from pages start, like Rust does
        page_size = header.ckey_page_size_kb * 1024
        sequential_offset = encoding_file.pages_start_offset + (page_index * page_size)

        if sequential_offset + page_size > len(encoding_data):
            raise ValueError(f"CKey page {page_index} extends beyond file")

        # Read page data sequentially
        page_data = encoding_data[sequential_offset:sequential_offset + page_size]

        # Parse page entries exactly like Rust entry_v2
        entries: list[CKeyPageEntry] = []
        offset = 0
        entry_count = 0

        while offset < len(page_data) and entry_count < max_entries:
            # Minimum size check: key_count(1) + file_size(5) + content_key(16)
            if offset + 22 > len(page_data):
                break

            # Read key count
            key_count = page_data[offset]

            # Check for padding (zero key_count indicates padding)
            if key_count == 0:
                break  # Hit padding
            offset += 1

            # Read file size (40-bit: 1 byte high + 4 bytes low, big-endian)
            if offset + 5 > len(page_data):
                break
            file_size_high = page_data[offset]
            offset += 1
            file_size_low = struct.unpack('>I', page_data[offset:offset + 4])[0]
            offset += 4
            file_size = (file_size_high << 32) | file_size_low

            # Read content key (always 16 bytes)
            if offset + 16 > len(page_data):
                break
            content_key = page_data[offset:offset + 16]
            offset += 16

            # Read encoding keys - match Rust behavior for corrupted entries
            encoding_keys: list[bytes] = []

            # Check if we have enough space for ALL encoding keys
            remaining_bytes = len(page_data) - offset
            bytes_needed = key_count * 16

            if bytes_needed > remaining_bytes:
                # Entry extends beyond page boundary - this matches the Rust failure case
                # The Rust implementation would fail with an I/O error here and stop parsing
                logger.debug(
                    "Entry extends beyond page boundary, stopping page parse",
                    page_index=page_index,
                    offset=offset - 22,  # Start of entry
                    key_count=key_count,
                    bytes_needed=bytes_needed,
                    bytes_available=remaining_bytes
                )
                break  # Stop parsing this page, like Rust does

            # Read all encoding keys
            for _ in range(key_count):
                if offset + 16 > len(page_data):
                    break
                encoding_key = page_data[offset:offset + 16]
                encoding_keys.append(encoding_key)
                offset += 16

            # Only add entry if we read all expected encoding keys
            if len(encoding_keys) == key_count:
                entry = CKeyPageEntry(
                    file_size=file_size,
                    content_key=content_key,
                    encoding_keys=encoding_keys
                )
                entries.append(entry)
                entry_count += 1
            else:
                # Incomplete entry - stop parsing like Rust
                break

        return CKeyPage(page_index=page_index, entries=entries)

    def find_content_key_sequential(self, encoding_data: bytes, encoding_file: EncodingFile,
                                   content_key: bytes) -> list[bytes] | None:
        """Find encoding keys for a content key using sequential reading like Rust.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            content_key: Content key to search for

        Returns:
            List of encoding keys if found, None otherwise
        """
        logger.debug(
            "Starting sequential content key search",
            content_key=content_key.hex(),
            total_pages=encoding_file.header.ckey_page_count
        )

        for page_idx in range(encoding_file.header.ckey_page_count):
            try:
                page = self.load_ckey_page_sequential(encoding_data, encoding_file, page_idx, max_entries=10000)
                for entry in page.entries:
                    if entry.content_key == content_key:
                        logger.debug(
                            "Found content key using sequential reading",
                            page_index=page_idx,
                            content_key=content_key.hex(),
                            encoding_keys=[k.hex() for k in entry.encoding_keys]
                        )
                        return entry.encoding_keys
            except Exception as e:
                logger.warning(
                    "Failed to load page during sequential content key search",
                    page_index=page_idx,
                    error=str(e)
                )
                continue

        logger.debug("Content key not found in sequential search", content_key=content_key.hex())
        return None

    def load_ckey_page(self, encoding_data: bytes, encoding_file: EncodingFile, page_index: int,
                       max_entries: int = 1000) -> CKeyPage:
        """Load and parse a specific CKey page.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            page_index: Index of page to load
            max_entries: Maximum entries to parse per page

        Returns:
            Parsed CKey page
        """
        header = encoding_file.header

        if page_index >= header.ckey_page_count:
            raise ValueError(f"Page index {page_index} >= page count {header.ckey_page_count}")

        # Calculate page offset
        page_offset = self._get_ckey_page_offset(encoding_file, page_index)
        page_size = header.ckey_page_size_kb * 1024

        if page_offset + page_size > len(encoding_data):
            raise ValueError(f"CKey page {page_index} extends beyond file")

        page_data = encoding_data[page_offset:page_offset + page_size]

        # Parse page entries
        entries: list[CKeyPageEntry] = []
        offset = 0
        entry_count = 0

        while offset < len(page_data) and entry_count < max_entries:
            # Minimum size check: key_count(1) + file_size(5) + content_key(16)
            if offset + 22 > len(page_data):
                break

            # Read key count
            key_count = page_data[offset]

            # Check for padding (zero key_count indicates padding)
            if key_count == 0:
                break  # Hit padding

            offset += 1

            # Read file size (40-bit: 1 byte high + 4 bytes low, big-endian)
            if offset + 5 > len(page_data):
                break
            file_size_high = page_data[offset]
            offset += 1
            file_size_low = struct.unpack('>I', page_data[offset:offset + 4])[0]
            offset += 4
            file_size = (file_size_high << 32) | file_size_low

            # Read content key (always 16 bytes)
            if offset + 16 > len(page_data):
                break
            content_key = page_data[offset:offset + 16]
            offset += 16

            # Read encoding keys - match Rust behavior for corrupted entries
            encoding_keys: list[bytes] = []

            # Check if we have enough space for ALL encoding keys
            remaining_bytes = len(page_data) - offset
            bytes_needed = key_count * 16

            if bytes_needed > remaining_bytes:
                # Entry extends beyond page boundary - this matches the Rust failure case
                # The Rust implementation would fail with an I/O error here and stop parsing
                logger.debug(
                    "Entry extends beyond page boundary, stopping page parse",
                    page_index=page_index,
                    offset=offset - 21,  # Start of entry
                    key_count=key_count,
                    bytes_needed=bytes_needed,
                    bytes_available=remaining_bytes
                )
                break  # Stop parsing this page, like Rust does

            # We have enough space for all keys, read them all
            for _ in range(key_count):
                ekey = page_data[offset:offset + 16]
                offset += 16
                encoding_keys.append(ekey)

            entries.append(CKeyPageEntry(
                content_key=content_key,
                encoding_keys=encoding_keys,
                file_size=file_size
            ))

            entry_count += 1

        return CKeyPage(page_index=page_index, entries=entries)

    def find_content_key(self, encoding_data: bytes, encoding_file: EncodingFile,
                        content_key: bytes) -> list[bytes] | None:
        """Find encoding keys for a content key using index-based lookup.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            content_key: Content key to search for

        Returns:
            List of encoding keys if found, None otherwise
        """
        # Use binary search on the index to find the correct page
        target_page = None

        # Find which page should contain this key based on the index
        for i in range(len(encoding_file.ckey_index) - 1):
            current_first_key = encoding_file.ckey_index[i][0]
            next_first_key = encoding_file.ckey_index[i + 1][0]

            # The key belongs in page i if it's >= current and < next
            if current_first_key <= content_key < next_first_key:
                target_page = i
                break

        # Check if it might be in the last page
        if target_page is None and encoding_file.ckey_index:
            if content_key >= encoding_file.ckey_index[-1][0]:
                target_page = len(encoding_file.ckey_index) - 1

        if target_page is not None:
            try:
                # Only load and search the target page
                page = self.load_ckey_page(encoding_data, encoding_file, target_page)
                for entry in page.entries:
                    if entry.content_key == content_key:
                        logger.debug(
                            "Found content key using index lookup",
                            target_page=target_page,
                            content_key=content_key.hex(),
                            encoding_keys=[k.hex() for k in entry.encoding_keys]
                        )
                        return entry.encoding_keys
            except Exception as e:
                logger.warning(f"Failed to load target CKey page {target_page}: {e}")

        return None

    def load_ekey_page(self, encoding_data: bytes, encoding_file: EncodingFile, page_index: int,
                       max_entries: int = 1000) -> EKeyPage:
        """Load and parse a specific EKey page.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            page_index: Index of page to load
            max_entries: Maximum entries to parse per page

        Returns:
            Parsed EKey page
        """
        header = encoding_file.header

        if page_index >= header.ekey_page_count:
            raise ValueError(f"Page index {page_index} >= page count {header.ekey_page_count}")

        # Calculate page offset
        page_offset = self._get_ekey_page_offset(encoding_file, page_index)
        page_size = header.ekey_page_size_kb * 1024

        if page_offset + page_size > len(encoding_data):
            raise ValueError(f"EKey page {page_index} extends beyond file")

        page_data = encoding_data[page_offset:page_offset + page_size]

        # Parse page entries
        entries: list[EKeyPageEntry] = []
        offset = 0
        entry_count = 0

        while offset + header.ekey_size + 9 <= len(page_data) and entry_count < max_entries:
            # Read encoding key (16 bytes)
            encoding_key = page_data[offset:offset + header.ekey_size]
            offset += header.ekey_size

            # Check for padding - all zero bytes indicate padding
            if encoding_key == b'\x00' * header.ekey_size:
                break

            # Read ESpec index (4 bytes, big-endian matching Rust)
            if offset + 4 > len(page_data):
                break
            espec_index = struct.unpack('>I', page_data[offset:offset + 4])[0]
            offset += 4

            # Read file size (40-bit: 1 byte high + 4 bytes low, big-endian)
            if offset + 5 > len(page_data):
                break
            file_size_high = page_data[offset]
            offset += 1
            file_size_low = struct.unpack('>I', page_data[offset:offset + 4])[0]
            offset += 4
            file_size = (file_size_high << 32) | file_size_low

            # For simplicity, assume 1 content key per encoding key
            # Real implementation would parse the actual structure
            content_keys: list[bytes] = []
            if offset + header.ckey_size <= len(page_data):
                ckey = page_data[offset:offset + header.ckey_size]
                if ckey != b'\x00' * header.ckey_size:
                    content_keys.append(ckey)
                offset += header.ckey_size

            entries.append(EKeyPageEntry(
                encoding_key=encoding_key,
                content_keys=content_keys,
                espec_index=espec_index,
                file_size=file_size
            ))

            entry_count += 1

        return EKeyPage(page_index=page_index, entries=entries)

    def _get_ckey_page_offset(self, encoding_file: EncodingFile, page_index: int) -> int:
        """Calculate offset of CKey page data.

        CKey pages come immediately after CKey index, not after both indices.
        """
        # CKey pages are stored at pages_start_offset which is right after CKey index
        page_size_bytes = encoding_file.header.ckey_page_size_kb * 1024
        return encoding_file.pages_start_offset + (page_index * page_size_bytes)

    def _get_ekey_page_offset(self, encoding_file: EncodingFile, page_index: int) -> int:
        """Calculate offset of EKey page data.

        EKey pages come after CKey pages and EKey index.
        """
        header = encoding_file.header

        # EKey pages start after: CKey pages + EKey index
        ckey_pages_size = header.ckey_page_count * header.ckey_page_size_kb * 1024
        ekey_index_size = header.ekey_page_count * 32  # 32 bytes per index entry

        ekey_pages_start = encoding_file.pages_start_offset + ckey_pages_size + ekey_index_size
        page_size_bytes = header.ekey_page_size_kb * 1024

        return ekey_pages_start + (page_index * page_size_bytes)

    def find_content_key_entry(self, encoding_data: bytes, encoding_file: EncodingFile,
                                content_key: bytes) -> CKeyPageEntry | None:
        """Find entry for a specific content key using index-based lookup.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            content_key: Content key to find

        Returns:
            Found entry or None
        """
        # Use binary search on the index to find the correct page
        target_page = None

        # Find which page should contain this key based on the index
        for i in range(len(encoding_file.ckey_index) - 1):
            current_first_key = encoding_file.ckey_index[i][0]
            next_first_key = encoding_file.ckey_index[i + 1][0]

            # The key belongs in page i if it's >= current and < next
            if current_first_key <= content_key < next_first_key:
                target_page = i
                break

        # Check if it might be in the last page
        if target_page is None and encoding_file.ckey_index:
            if content_key >= encoding_file.ckey_index[-1][0]:
                target_page = len(encoding_file.ckey_index) - 1

        if target_page is not None:
            try:
                # Only load and search the target page
                page = self.load_ckey_page(encoding_data, encoding_file, target_page, max_entries=10000)
                for entry in page.entries:
                    if entry.content_key == content_key:
                        logger.debug(
                            "Found content key using index lookup",
                            target_page=target_page,
                            content_key=content_key.hex()
                        )
                        return entry
            except Exception as e:
                logger.warning(f"Failed to load target CKey page {target_page}: {e}")

        return None

    def find_encoding_key(self, encoding_data: bytes, encoding_file: EncodingFile,
                          encoding_key: bytes) -> EKeyPageEntry | None:
        """Find entry for a specific encoding key.

        Args:
            encoding_data: Complete encoding file data
            encoding_file: Parsed encoding file structure
            encoding_key: Encoding key to find

        Returns:
            Found entry or None
        """
        # Simple linear search through pages
        for page_index in range(encoding_file.header.ekey_page_count):
            try:
                page = self.load_ekey_page(encoding_data, encoding_file, page_index)
                for entry in page.entries:
                    if entry.encoding_key == encoding_key:
                        return entry
            except Exception as e:
                logger.warning(f"Failed to load EKey page {page_index}: {e}")
                continue

        return None

    def build(self, obj: EncodingFile) -> bytes:
        """Build encoding binary data from file structure.

        Args:
            obj: Encoding file structure

        Returns:
            Binary encoding data
        """
        result = BytesIO()

        # Write header
        header = obj.header
        result.write(header.magic)
        result.write(struct.pack('B', header.version))
        result.write(struct.pack('B', header.ckey_size))
        result.write(struct.pack('B', header.ekey_size))
        result.write(struct.pack('>H', header.ckey_page_size_kb))
        result.write(struct.pack('>H', header.ekey_page_size_kb))
        result.write(struct.pack('>I', header.ckey_page_count))
        result.write(struct.pack('>I', header.ekey_page_count))
        result.write(struct.pack('B', header.unknown))
        result.write(struct.pack('>I', header.espec_size))

        # Write ESpec table
        if obj.espec_table:
            espec_data = b'\x00'.join(spec.encode('ascii') for spec in obj.espec_table)
            espec_data += b'\x00'  # Null terminator
            result.write(espec_data)

        # Write indices
        for first_key, checksum in obj.ckey_index:
            result.write(first_key)
            result.write(checksum)

        for first_key, checksum in obj.ekey_index:
            result.write(first_key)
            result.write(checksum)

        # Note: Page data would need to be rebuilt from actual page structures
        # This is a simplified implementation

        return result.getvalue()


class EncodingBuilder:
    """Builder for encoding format files."""

    def __init__(self):
        """Initialize encoding builder."""
        pass

    def build(self, obj: EncodingFile) -> bytes:
        """Build encoding file from object.

        Args:
            obj: Encoding file object to build

        Returns:
            Binary encoding data
        """
        # Use the existing build logic from EncodingParser
        parser = EncodingParser()
        return parser.build(obj)

    @classmethod
    def create_empty(cls) -> EncodingFile:
        """Create an empty encoding file.

        Returns:
            Empty encoding file object
        """
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,  # Standard MD5 size
            ekey_size=16,  # Standard MD5 size
            ckey_page_size_kb=4,
            ekey_page_size_kb=4,
            ckey_page_count=0,
            ekey_page_count=0,
            unknown=0,
            espec_size=0
        )

        return EncodingFile(
            header=header,
            espec_table=[],
            ckey_index=[],
            ekey_index=[]
        )

    @classmethod
    def create_with_entries(
        cls,
        ckey_entries: list[CKeyPageEntry],
        ekey_entries: list[EKeyPageEntry],
        espec_table: list[str] | None = None
    ) -> EncodingFile:
        """Create encoding file with given entries.

        Args:
            ckey_entries: Content key entries
            ekey_entries: Encoding key entries
            espec_table: Optional ESpec table

        Returns:
            Encoding file object
        """
        espec_table = espec_table or []
        espec_size = len(b'\x00'.join(spec.encode('ascii') for spec in espec_table) + b'\x00') if espec_table else 0

        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,  # Standard MD5 size
            ekey_size=16,  # Standard MD5 size
            ckey_page_size_kb=4,
            ekey_page_size_kb=4,
            ckey_page_count=1 if ckey_entries else 0,
            ekey_page_count=1 if ekey_entries else 0,
            unknown=0,
            espec_size=espec_size
        )

        return EncodingFile(
            header=header,
            espec_table=espec_table,
            ckey_index=[(b'\x00' * 16, b'\x00' * 16)],  # Simplified index (first_key, checksum)
            ekey_index=[(b'\x00' * 16, b'\x00' * 16)]   # Simplified index (first_key, checksum)
        )


def is_encoding(data: bytes) -> bool:
    """Check if data appears to be an encoding file.

    Args:
        data: Data to check

    Returns:
        True if data starts with encoding magic
    """
    return len(data) >= 2 and data[:2] == b'EN'
