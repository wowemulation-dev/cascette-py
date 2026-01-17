"""Tests for encoding format parser."""

import struct
from io import BytesIO

import pytest

from cascette_tools.formats.encoding import (
    CKeyPage,
    CKeyPageEntry,
    EKeyPage,
    EKeyPageEntry,
    EncodingFile,
    EncodingHeader,
    EncodingParser,
    is_encoding,
)


class TestEncodingParser:
    """Test encoding format parser."""

    def test_is_encoding_function(self):
        """Test is_encoding detection function."""
        # Valid encoding data
        assert is_encoding(b'EN\x01\x10\x10')

        # Invalid data
        assert not is_encoding(b'BL')
        assert not is_encoding(b'E')
        assert not is_encoding(b'')

    def test_parse_header_basic(self):
        """Test parsing basic encoding header."""
        # Create test header
        header_data = BytesIO()
        header_data.write(b'EN')  # magic
        header_data.write(struct.pack('B', 1))  # version
        header_data.write(struct.pack('B', 16))  # ckey_size
        header_data.write(struct.pack('B', 16))  # ekey_size
        header_data.write(struct.pack('>H', 4))  # ckey_page_size_kb
        header_data.write(struct.pack('>H', 4))  # ekey_page_size_kb
        header_data.write(struct.pack('>I', 2))  # ckey_page_count
        header_data.write(struct.pack('>I', 3))  # ekey_page_count
        header_data.write(struct.pack('B', 0))  # unknown
        header_data.write(struct.pack('>I', 100))  # espec_size

        # Add minimal data to satisfy parsing
        header_data.write(b'\x00' * 100)  # espec_data
        header_data.write(b'\x00' * (2 * (16 + 16)))  # ckey_index (2 entries)

        # Add CKey pages data (4KB per page * 2 pages)
        ckey_pages_size = 4 * 1024 * 2
        header_data.write(b'\x00' * ckey_pages_size)

        header_data.write(b'\x00' * (3 * (16 + 16)))  # ekey_index (3 entries)

        parser = EncodingParser()
        encoding_file = parser.parse(header_data.getvalue())

        # Verify header
        header = encoding_file.header
        assert header.magic == b'EN'
        assert header.version == 1
        assert header.ckey_size == 16
        assert header.ekey_size == 16
        assert header.ckey_page_size_kb == 4
        assert header.ekey_page_size_kb == 4
        assert header.ckey_page_count == 2
        assert header.ekey_page_count == 3
        assert header.unknown == 0
        assert header.espec_size == 100

    def test_parse_espec_table(self):
        """Test parsing ESpec table."""
        # Create test data with ESpec strings
        espec_strings = ["z", "zn", "ze"]
        espec_data = b'\x00'.join(s.encode('ascii') for s in espec_strings) + b'\x00'

        # Create complete encoding data
        encoding_data = BytesIO()
        # Header
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))  # version
        encoding_data.write(struct.pack('B', 16))  # ckey_size
        encoding_data.write(struct.pack('B', 16))  # ekey_size
        encoding_data.write(struct.pack('>H', 1))  # ckey_page_size_kb
        encoding_data.write(struct.pack('>H', 1))  # ekey_page_size_kb
        encoding_data.write(struct.pack('>I', 0))  # ckey_page_count
        encoding_data.write(struct.pack('>I', 0))  # ekey_page_count
        encoding_data.write(struct.pack('B', 0))  # unknown
        encoding_data.write(struct.pack('>I', len(espec_data)))  # espec_size

        # ESpec table
        encoding_data.write(espec_data)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data.getvalue())

        # Verify ESpec table
        assert len(encoding_file.espec_table) == len(espec_strings)
        for i, expected in enumerate(espec_strings):
            assert encoding_file.espec_table[i] == expected

    def test_parse_empty_espec_table(self):
        """Test parsing with empty ESpec table."""
        # Create encoding data with no ESpec table
        encoding_data = BytesIO()
        # Header
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 0))  # espec_size = 0

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data.getvalue())

        assert len(encoding_file.espec_table) == 0

    def test_parse_indices(self):
        """Test parsing CKey and EKey indices."""
        ckey_page_count = 2
        ekey_page_count = 1
        key_size = 16

        # Create test indices (each entry is first_key + checksum = 32 bytes)
        ckey_index_data = b'\x01' * 16 + b'\x02' * 16 + b'\x03' * 16 + b'\x04' * 16  # 2 entries = 64 bytes
        ekey_index_data = b'\x05' * 16 + b'\x06' * 16  # 1 entry = 32 bytes

        # Create encoding data
        encoding_data = BytesIO()
        # Header
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', key_size))
        encoding_data.write(struct.pack('B', key_size))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', ckey_page_count))
        encoding_data.write(struct.pack('>I', ekey_page_count))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 0))  # espec_size = 0

        # Indices and pages layout: CKey index -> CKey pages -> EKey index -> EKey pages
        encoding_data.write(ckey_index_data)

        # Add CKey pages data (page_size_kb * 1024 * page_count)
        ckey_pages_size = 1 * 1024 * ckey_page_count  # 1KB per page * 2 pages
        encoding_data.write(b'\x00' * ckey_pages_size)

        # Now write EKey index
        encoding_data.write(ekey_index_data)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data.getvalue())

        # Verify indices
        assert len(encoding_file.ckey_index) == ckey_page_count
        assert len(encoding_file.ekey_index) == ekey_page_count

        # Check specific entries (now tuples of (first_key, checksum))
        assert encoding_file.ckey_index[0] == (b'\x01' * 16, b'\x02' * 16)
        assert encoding_file.ckey_index[1] == (b'\x03' * 16, b'\x04' * 16)
        assert encoding_file.ekey_index[0] == (b'\x05' * 16, b'\x06' * 16)

    def test_load_ckey_page(self):
        """Test loading and parsing CKey page."""
        # Create minimal encoding file for page loading
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=1,
            ekey_page_size_kb=1,
            ckey_page_count=1,
            ekey_page_count=0,
            unknown=0,
            espec_size=0
        )

        encoding_file = EncodingFile(
            header=header,
            espec_table=[],
            ckey_index=[(b'\x00' * 16, b'\x00' * 16)],  # Dummy index entry (first_key, checksum)
            ekey_index=[],
            pages_start_offset=22 + 0 + 32  # header(22) + espec(0) + ckey_index(32)
        )

        # Create page data with test entry (following Rust CKeyPageEntry format)
        # Format: key_count (1 byte) + file_size (40-bit: 1 byte high + 4 bytes low, big-endian) + content_key (16 bytes) + encoding_keys (16 bytes each)
        page_data = BytesIO()
        page_data.write(struct.pack('B', 1))  # key_count (ekey_count)
        # file_size as 40-bit big-endian (1 byte high + 4 bytes low)
        file_size = 1024
        page_data.write(struct.pack('B', (file_size >> 32) & 0xFF))  # high byte
        page_data.write(struct.pack('>I', file_size & 0xFFFFFFFF))   # low 4 bytes
        page_data.write(b'\x01' * 16)  # content_key
        page_data.write(b'\x02' * 16)  # encoding_key
        page_data.write(b'\x00' * (1024 - page_data.tell()))  # pad to page size

        # Create complete encoding data
        encoding_data = BytesIO()
        # Header (22 bytes)
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', 1))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 0))

        # No ESpec (espec_size = 0)
        # CKey index (32 bytes)
        encoding_data.write(b'\x00' * 32)
        # No EKey index
        # Page data
        encoding_data.write(page_data.getvalue())

        parser = EncodingParser()
        page = parser.load_ckey_page(encoding_data.getvalue(), encoding_file, 0)

        # Verify page
        assert page.page_index == 0
        assert len(page.entries) == 1

        entry = page.entries[0]
        assert entry.content_key == b'\x01' * 16
        assert len(entry.encoding_keys) == 1
        assert entry.encoding_keys[0] == b'\x02' * 16
        assert entry.file_size == 1024

    def test_load_ekey_page(self):
        """Test loading and parsing EKey page."""
        # Create minimal encoding file for page loading
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=1,
            ekey_page_size_kb=1,
            ckey_page_count=0,
            ekey_page_count=1,
            unknown=0,
            espec_size=0
        )

        encoding_file = EncodingFile(
            header=header,
            espec_table=[],
            ckey_index=[],
            ekey_index=[(b'\x00' * 16, b'\x00' * 16)],  # Dummy index entry (first_key, checksum)
            pages_start_offset=22 + 0 + 0  # header(22) + espec(0) + ckey_index(0 pages)
        )

        # Create page data with test entry (matching Rust format)
        page_data = BytesIO()
        page_data.write(b'\x03' * 16)  # encoding_key (16 bytes)
        page_data.write(struct.pack('>I', 1))  # espec_index (4 bytes, big-endian)
        # file_size (40-bit: 1 byte high + 4 bytes low, big-endian)
        page_data.write(struct.pack('B', 0))  # file_size_high (for 2048, this is 0)
        page_data.write(struct.pack('>I', 2048))  # file_size_low
        page_data.write(b'\x04' * 16)  # content_key (16 bytes)
        page_data.write(b'\x00' * (1024 - page_data.tell()))  # pad to page size

        # Create complete encoding data
        encoding_data = BytesIO()
        # Header (22 bytes)
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('>I', 1))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 0))

        # No ESpec (espec_size = 0)
        # No CKey index
        # EKey index (32 bytes)
        encoding_data.write(b'\x00' * 32)
        # Page data
        encoding_data.write(page_data.getvalue())

        parser = EncodingParser()
        page = parser.load_ekey_page(encoding_data.getvalue(), encoding_file, 0)

        # Verify page
        assert page.page_index == 0
        assert len(page.entries) == 1

        entry = page.entries[0]
        assert entry.encoding_key == b'\x03' * 16
        assert entry.espec_index == 1
        assert entry.file_size == 2048
        assert len(entry.content_keys) == 1
        assert entry.content_keys[0] == b'\x04' * 16

    def test_invalid_magic(self):
        """Test error handling for invalid magic."""
        invalid_data = b'BL' + b'\x00' * 20

        parser = EncodingParser()
        with pytest.raises(ValueError, match="Invalid encoding magic"):
            parser.parse(invalid_data)

    def test_incomplete_header(self):
        """Test error handling for incomplete header."""
        incomplete_data = b'EN\x01\x10'  # Too short

        parser = EncodingParser()
        with pytest.raises(ValueError, match="Incomplete header"):
            parser.parse(incomplete_data)

    def test_incomplete_espec_table(self):
        """Test error handling for incomplete ESpec table."""
        # Header claiming large ESpec but short data
        encoding_data = BytesIO()
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 1000))  # Large ESpec size

        encoding_data.write(b'\x00' * 10)  # But only 10 bytes

        parser = EncodingParser()
        with pytest.raises(ValueError, match="Incomplete ESpec table"):
            parser.parse(encoding_data.getvalue())

    def test_page_index_out_of_range(self):
        """Test error handling for page index out of range."""
        # Create minimal encoding file
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=1,
            ekey_page_size_kb=1,
            ckey_page_count=1,
            ekey_page_count=1,
            unknown=0,
            espec_size=0
        )

        encoding_file = EncodingFile(
            header=header,
            espec_table=[],
            ckey_index=[(b'\x00' * 16, b'\x00' * 16)],
            ekey_index=[(b'\x00' * 16, b'\x00' * 16)]
        )

        parser = EncodingParser()

        # Test CKey page out of range
        with pytest.raises(ValueError, match="Page index 5 >= page count 1"):
            parser.load_ckey_page(b'', encoding_file, 5)

        # Test EKey page out of range
        with pytest.raises(ValueError, match="Page index 5 >= page count 1"):
            parser.load_ekey_page(b'', encoding_file, 5)

    def test_round_trip_header(self):
        """Test round-trip parsing and building for header."""
        # Create encoding file structure
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=4,
            ekey_page_size_kb=4,
            ckey_page_count=0,  # Set to 0 to avoid page data requirements
            ekey_page_count=0,  # Set to 0 to avoid page data requirements
            unknown=42,
            espec_size=0
        )

        # Create empty indices to match header counts
        ckey_index = []
        ekey_index = []

        encoding_file = EncodingFile(
            header=header,
            espec_table=[],
            ckey_index=ckey_index,
            ekey_index=ekey_index
        )

        # Build and parse back
        parser = EncodingParser()
        binary_data = parser.build(encoding_file)
        parsed_file = parser.parse(binary_data)

        # Verify round trip
        assert parsed_file.header.magic == header.magic
        assert parsed_file.header.version == header.version
        assert parsed_file.header.ckey_size == header.ckey_size
        assert parsed_file.header.ekey_size == header.ekey_size
        assert parsed_file.header.ckey_page_size_kb == header.ckey_page_size_kb
        assert parsed_file.header.ekey_page_size_kb == header.ekey_page_size_kb
        assert parsed_file.header.ckey_page_count == header.ckey_page_count  # 0
        assert parsed_file.header.ekey_page_count == header.ekey_page_count  # 0
        assert parsed_file.header.unknown == header.unknown

    def test_round_trip_with_espec(self):
        """Test round-trip with ESpec table."""
        # Create encoding file with ESpec table
        espec_strings = ["z", "zn", "ze"]
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=1,
            ekey_page_size_kb=1,
            ckey_page_count=0,
            ekey_page_count=0,
            unknown=0,
            espec_size=8  # Will be recalculated
        )

        encoding_file = EncodingFile(
            header=header,
            espec_table=espec_strings,
            ckey_index=[],
            ekey_index=[]
        )

        # Build and parse back
        parser = EncodingParser()
        binary_data = parser.build(encoding_file)
        parsed_file = parser.parse(binary_data)

        # Verify ESpec table
        assert len(parsed_file.espec_table) == len(espec_strings)
        for i, expected in enumerate(espec_strings):
            assert parsed_file.espec_table[i] == expected

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        # Create test encoding file
        encoding_data = BytesIO()
        encoding_data.write(b'EN')
        encoding_data.write(struct.pack('B', 1))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('B', 16))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>H', 1))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('>I', 0))
        encoding_data.write(struct.pack('B', 0))
        encoding_data.write(struct.pack('>I', 0))

        test_file = tmp_path / "test.encoding"
        test_file.write_bytes(encoding_data.getvalue())

        # Parse from file
        parser = EncodingParser()
        encoding_file = parser.parse_file(str(test_file))

        assert encoding_file.header.magic == b'EN'
        assert encoding_file.header.version == 1


class TestEncodingModels:
    """Test encoding Pydantic models."""

    def test_encoding_header_model(self):
        """Test EncodingHeader model."""
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=4,
            ekey_page_size_kb=4,
            ckey_page_count=10,
            ekey_page_count=5,
            unknown=0,
            espec_size=100
        )

        assert header.magic == b'EN'
        assert header.version == 1
        assert header.ckey_size == 16
        assert header.ekey_size == 16
        assert header.ckey_page_size_kb == 4
        assert header.ekey_page_size_kb == 4
        assert header.ckey_page_count == 10
        assert header.ekey_page_count == 5
        assert header.unknown == 0
        assert header.espec_size == 100

    def test_ckey_page_entry_model(self):
        """Test CKeyPageEntry model."""
        entry = CKeyPageEntry(
            content_key=b'\x01' * 16,
            encoding_keys=[b'\x02' * 16, b'\x03' * 16],
            file_size=1024
        )

        assert entry.content_key == b'\x01' * 16
        assert len(entry.encoding_keys) == 2
        assert entry.encoding_keys[0] == b'\x02' * 16
        assert entry.encoding_keys[1] == b'\x03' * 16
        assert entry.file_size == 1024

    def test_ekey_page_entry_model(self):
        """Test EKeyPageEntry model."""
        entry = EKeyPageEntry(
            encoding_key=b'\x04' * 16,
            content_keys=[b'\x05' * 16],
            espec_index=2,
            file_size=2048
        )

        assert entry.encoding_key == b'\x04' * 16
        assert len(entry.content_keys) == 1
        assert entry.content_keys[0] == b'\x05' * 16
        assert entry.espec_index == 2
        assert entry.file_size == 2048

    def test_ckey_page_model(self):
        """Test CKeyPage model."""
        entries = [
            CKeyPageEntry(
                content_key=b'\x01' * 16,
                encoding_keys=[b'\x02' * 16],
                file_size=1024
            )
        ]

        page = CKeyPage(page_index=0, entries=entries)

        assert page.page_index == 0
        assert len(page.entries) == 1
        assert page.entries[0].content_key == b'\x01' * 16

    def test_ekey_page_model(self):
        """Test EKeyPage model."""
        entries = [
            EKeyPageEntry(
                encoding_key=b'\x03' * 16,
                content_keys=[b'\x04' * 16],
                espec_index=1,
                file_size=2048
            )
        ]

        page = EKeyPage(page_index=1, entries=entries)

        assert page.page_index == 1
        assert len(page.entries) == 1
        assert page.entries[0].encoding_key == b'\x03' * 16

    def test_encoding_file_model(self):
        """Test complete EncodingFile model."""
        header = EncodingHeader(
            magic=b'EN',
            version=1,
            ckey_size=16,
            ekey_size=16,
            ckey_page_size_kb=1,
            ekey_page_size_kb=1,
            ckey_page_count=1,
            ekey_page_count=1,
            unknown=0,
            espec_size=10
        )

        encoding_file = EncodingFile(
            header=header,
            espec_table=["z", "zn"],
            ckey_index=[(b'\x01' * 16, b'\x01' * 16)],
            ekey_index=[(b'\x02' * 16, b'\x02' * 16)]
        )

        assert encoding_file.header == header
        assert len(encoding_file.espec_table) == 2
        assert encoding_file.espec_table[0] == "z"
        assert encoding_file.espec_table[1] == "zn"
        assert len(encoding_file.ckey_index) == 1
        assert len(encoding_file.ekey_index) == 1
        assert encoding_file.ckey_index[0] == (b'\x01' * 16, b'\x01' * 16)
        assert encoding_file.ekey_index[0] == (b'\x02' * 16, b'\x02' * 16)
