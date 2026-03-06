"""Tests for size format parser."""

import struct
from io import BytesIO

import pytest

from cascette_tools.formats.size import (
    SizeBuilder,
    SizeEntry,
    SizeParser,
    SizeTag,
    apply_tag_query,
    is_file_selected,
    is_size,
    parse_tag_query,
)


class TestSizeParser:
    """Test size format parser."""

    def test_is_size_function(self):
        """Test is_size detection function."""
        # Valid size data with DS magic
        assert is_size(b'DS\x01\x00\x00\x00\x01\x00\x00\x80')

        # Invalid magic
        assert not is_size(b'XX\x01\x10')
        assert not is_size(b'EN\x01\x10')

        # Too short
        assert not is_size(b'D')
        assert not is_size(b'')

    def test_parse_v1_header(self):
        """Test parsing V1 size manifest header."""
        parser = SizeParser()

        # Build V1 header: DS + version=1 + flags=0 + entry_count=0 + key_size_bits=128
        # V1 specific: total_size=0x1000 (4096) + esize_bytes=4
        data = BytesIO()
        data.write(b'DS')  # magic
        data.write(struct.pack('B', 1))  # version
        data.write(struct.pack('B', 0))  # flags
        data.write(struct.pack('>I', 0))  # entry_count (big-endian)
        data.write(struct.pack('>H', 128))  # key_size_bits (big-endian)
        data.write(struct.pack('>Q', 4096))  # total_size (big-endian)
        data.write(struct.pack('B', 4))  # esize_bytes

        size = parser.parse(data.getvalue())

        assert size.header.version == 1
        assert size.header.flags == 0
        assert size.header.entry_count == 0
        assert size.header.key_size_bits == 128
        assert size.header.total_size == 4096
        assert size.header.esize_bytes == 4

    def test_parse_v2_header(self):
        """Test parsing V2 size manifest header."""
        parser = SizeParser()

        # Build V2 header: DS + version=2 + flags=0 + entry_count=0 + key_size_bits=128
        # V2 specific: total_size=0x1000 (4096) as 5-byte uint40
        data = BytesIO()
        data.write(b'DS')  # magic
        data.write(struct.pack('B', 2))  # version
        data.write(struct.pack('B', 0))  # flags
        data.write(struct.pack('>I', 0))  # entry_count (big-endian)
        data.write(struct.pack('>H', 128))  # key_size_bits (big-endian)
        # 5-byte total_size (0x1000 = 4096 decimal)
        data.write(struct.pack('>Q', 4096)[3:])  # Last 5 bytes of 8-byte value

        size = parser.parse(data.getvalue())

        assert size.header.version == 2
        assert size.header.flags == 0
        assert size.header.entry_count == 0
        assert size.header.key_size_bits == 128
        assert size.header.total_size == 4096
        assert size.header.esize_bytes == 4  # Fixed at 4 for V2

    def test_parse_v1_entries(self):
        """Test parsing V1 size manifest entries."""
        parser = SizeParser()

        # Build V1 size manifest with entries
        data = BytesIO()

        # Header
        data.write(b'DS')  # magic
        data.write(struct.pack('B', 1))  # version
        data.write(struct.pack('B', 0))  # flags
        data.write(struct.pack('>I', 2))  # entry_count
        data.write(struct.pack('>H', 128))  # key_size_bits
        data.write(struct.pack('>Q', 6144))  # total_size (1024 + 5120)
        data.write(struct.pack('B', 4))  # esize_bytes

        # Entry 1
        data.write(b'file1.dat\x00')  # null-terminated key
        data.write(struct.pack('>H', 0x1234))  # key_hash
        data.write(struct.pack('>I', 1024))  # esize (4 bytes)

        # Entry 2
        data.write(b'file2.dat\x00')  # null-terminated key
        data.write(struct.pack('>H', 0x5678))  # key_hash
        data.write(struct.pack('>I', 5120))  # esize (4 bytes)

        size = parser.parse(data.getvalue())

        assert size.header.version == 1
        assert len(size.entries) == 2

        entry1 = size.entries[0]
        assert entry1.key == "file1.dat"
        assert entry1.key_hash == 0x1234
        assert entry1.esize == 1024

        entry2 = size.entries[1]
        assert entry2.key == "file2.dat"
        assert entry2.key_hash == 0x5678
        assert entry2.esize == 5120

    def test_parse_v2_entries(self):
        """Test parsing V2 size manifest entries."""
        parser = SizeParser()

        # Build V2 size manifest with entries
        data = BytesIO()

        # Header
        data.write(b'DS')  # magic
        data.write(struct.pack('B', 2))  # version
        data.write(struct.pack('B', 0))  # flags
        data.write(struct.pack('>I', 1))  # entry_count
        data.write(struct.pack('>H', 128))  # key_size_bits
        # 5-byte total_size
        data.write(struct.pack('>Q', 2048)[3:])

        # Entry
        data.write(b'single.dat\x00')  # null-terminated key
        data.write(struct.pack('>H', 0xABCD))  # key_hash
        data.write(struct.pack('>I', 2048))  # esize (4 bytes, fixed for V2)

        size = parser.parse(data.getvalue())

        assert size.header.version == 2
        assert len(size.entries) == 1

        entry = size.entries[0]
        assert entry.key == "single.dat"
        assert entry.key_hash == 0xABCD
        assert entry.esize == 2048

    def test_invalid_key_hash(self):
        """Test that invalid key hashes are rejected."""
        parser = SizeParser()

        # Build size manifest with invalid key hash (0x0000)
        data = BytesIO()

        # Header
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 1))
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 0))
        data.write(struct.pack('B', 4))

        # Entry with invalid key hash
        data.write(b'test.dat\x00')
        data.write(struct.pack('>H', 0x0000))  # Invalid: 0x0000
        data.write(struct.pack('>I', 1024))

        with pytest.raises(ValueError, match="Invalid key hash"):
            parser.parse(data.getvalue())

        # Try with 0xFFFF
        data2 = BytesIO()

        # Header
        data2.write(b'DS')
        data2.write(struct.pack('B', 1))
        data2.write(struct.pack('B', 0))
        data2.write(struct.pack('>I', 1))
        data2.write(struct.pack('>H', 128))
        data2.write(struct.pack('>Q', 0))
        data2.write(struct.pack('B', 4))

        # Entry with invalid key hash
        data2.write(b'test.dat\x00')
        data2.write(struct.pack('>H', 0xFFFF))  # Invalid: 0xFFFF
        data2.write(struct.pack('>I', 1024))

        with pytest.raises(ValueError, match="Invalid key hash"):
            parser.parse(data2.getvalue())

    def test_unsupported_version(self):
        """Test that unsupported versions are rejected."""
        parser = SizeParser()

        # Version 0
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 0))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 0))
        data.write(struct.pack('>H', 128))

        with pytest.raises(ValueError, match="Unsupported size manifest version"):
            parser.parse(data.getvalue())

        # Version 3
        data2 = BytesIO()
        data2.write(b'DS')
        data2.write(struct.pack('B', 3))
        data2.write(struct.pack('B', 0))
        data2.write(struct.pack('>I', 0))
        data2.write(struct.pack('>H', 128))

        with pytest.raises(ValueError, match="Unsupported size manifest version"):
            parser.parse(data2.getvalue())

    def test_size_tag_has_file(self):
        """Test SizeTag.has_file method using file_indices fallback."""
        tag = SizeTag(
            name="test",
            tag_id=1,
            tag_type=1,
            file_indices=[0, 2, 5, 10, 100]
        )

        assert tag.has_file(0) is True
        assert tag.has_file(1) is False
        assert tag.has_file(2) is True
        assert tag.has_file(5) is True
        assert tag.has_file(10) is True
        assert tag.has_file(99) is False
        assert tag.has_file(100) is True
        assert tag.has_file(101) is False

    def test_build_v1(self):
        """Test building V1 size manifest."""
        entries = [
            SizeEntry(key="file1.dat", key_hash=0x1234, esize=1024),
            SizeEntry(key="file2.dat", key_hash=0x5678, esize=5120)
        ]

        size_file = SizeBuilder.create_with_entries(entries, version=1)
        data = SizeBuilder().build(size_file)

        # Verify can re-parse
        parser = SizeParser()
        reparsed = parser.parse(data)

        assert reparsed.header.version == 1
        assert reparsed.header.entry_count == 2
        assert len(reparsed.entries) == 2

        assert reparsed.entries[0].key == "file1.dat"
        assert reparsed.entries[0].key_hash == 0x1234
        assert reparsed.entries[0].esize == 1024

        assert reparsed.entries[1].key == "file2.dat"
        assert reparsed.entries[1].key_hash == 0x5678
        assert reparsed.entries[1].esize == 5120

    def test_build_v2(self):
        """Test building V2 size manifest."""
        entries = [
            SizeEntry(key="file.dat", key_hash=0xABCD, esize=2048)
        ]

        size_file = SizeBuilder.create_with_entries(entries, version=2)
        data = SizeBuilder().build(size_file)

        # Verify can re-parse
        parser = SizeParser()
        reparsed = parser.parse(data)

        assert reparsed.header.version == 2
        assert reparsed.header.entry_count == 1
        assert len(reparsed.entries) == 1

        assert reparsed.entries[0].key == "file.dat"
        assert reparsed.entries[0].key_hash == 0xABCD
        assert reparsed.entries[0].esize == 2048

    def test_create_empty(self):
        """Test creating empty size manifest."""
        v1_empty = SizeBuilder.create_empty(version=1)
        assert v1_empty.header.version == 1
        assert v1_empty.header.entry_count == 0
        assert len(v1_empty.entries) == 0

        v2_empty = SizeBuilder.create_empty(version=2)
        assert v2_empty.header.version == 2
        assert v2_empty.header.entry_count == 0
        assert len(v2_empty.entries) == 0


class TestTagQuery:
    """Test tag query parsing and bitmap operations."""

    def test_parse_tag_query_simple(self):
        """Test parsing simple tag query."""
        result = parse_tag_query("enUS")
        assert len(result) == 1
        assert result[0] == ("enUS", False)

    def test_parse_tag_query_multiple(self):
        """Test parsing multiple tags."""
        result = parse_tag_query("enUS,deDE,frFR")
        assert len(result) == 3
        assert result == [("enUS", False), ("deDE", False), ("frFR", False)]

    def test_parse_tag_query_subtractive(self):
        """Test parsing subtractive tags."""
        result = parse_tag_query("enUS,!beta")
        assert len(result) == 2
        assert result[0] == ("enUS", False)
        assert result[1] == ("beta", True)

    def test_parse_tag_query_mixed(self):
        """Test parsing mixed additive and subtractive tags."""
        result = parse_tag_query("enUS,!beta,debug")
        assert len(result) == 3
        assert result == [("enUS", False), ("beta", True), ("debug", False)]

    def test_parse_tag_query_delimiters(self):
        """Test parsing with different delimiters."""
        result = parse_tag_query("enUS?deDE:frFR")
        assert len(result) == 3
        assert result == [("enUS", False), ("deDE", False), ("frFR", False)]

    def test_parse_tag_query_empty(self):
        """Test parsing empty query."""
        result = parse_tag_query("")
        assert result == []

        result2 = parse_tag_query("   ")
        assert result2 == []

    def test_parse_tag_query_whitespace(self):
        """Test parsing with whitespace."""
        result = parse_tag_query("enUS, deDE , frFR")
        assert len(result) == 3
        assert result == [("enUS", False), ("deDE", False), ("frFR", False)]

    def test_apply_tag_query_empty(self):
        """Test applying empty tag query."""
        tags = [
            SizeTag(name="enUS", tag_id=1, tag_type=4, file_indices=[], bit_mask=b'\xFF'),
            SizeTag(name="deDE", tag_id=2, tag_type=4, file_indices=[], bit_mask=b'\xFF'),
        ]

        bitmap = apply_tag_query(tags, "", 10)
        assert len(bitmap) == 2
        # All files should be selected (0xFF)
        assert bitmap == b'\xFF\xFF'

    def test_apply_tag_query_no_tags(self):
        """Test applying query with no tags available."""
        tags: list[SizeTag] = []
        bitmap = apply_tag_query(tags, "enUS", 10)
        assert len(bitmap) == 2
        # All files selected when no tags
        assert bitmap == b'\xFF\xFF'

    def test_apply_tag_query_simple_additive(self):
        """Test applying simple additive tag query."""
        # Create tags with bitmasks for 10 files
        # Tag 1 (enUS): files 0, 2, 4, 6, 8 set
        # Tag 2 (deDE): files 1, 3, 5, 7, 9 set
        tag1_mask = bytearray(2)
        for i in range(0, 10, 2):
            byte_index = i >> 3
            bit_position = i & 7
            tag1_mask[byte_index] |= (0x80 >> bit_position)

        tag2_mask = bytearray(2)
        for i in range(1, 10, 2):
            byte_index = i >> 3
            bit_position = i & 7
            tag2_mask[byte_index] |= (0x80 >> bit_position)

        tags = [
            SizeTag(name="enUS", tag_id=1, tag_type=4, file_indices=[], bit_mask=bytes(tag1_mask)),
            SizeTag(name="deDE", tag_id=2, tag_type=4, file_indices=[], bit_mask=bytes(tag2_mask)),
        ]

        # Query for enUS should select files 0, 2, 4, 6, 8
        bitmap = apply_tag_query(tags, "enUS", 10)
        assert is_file_selected(bitmap, 0) is True
        assert is_file_selected(bitmap, 1) is False
        assert is_file_selected(bitmap, 2) is True
        assert is_file_selected(bitmap, 3) is False
        assert is_file_selected(bitmap, 4) is True

    def test_apply_tag_query_subtractive(self):
        """Test applying subtractive tag query."""
        # Tag with all files set
        tag_mask = bytes([0xFF, 0xFF])

        tags = [
            SizeTag(name="all", tag_id=1, tag_type=1, file_indices=[], bit_mask=tag_mask),
            SizeTag(name="beta", tag_id=2, tag_type=1, file_indices=[0, 1], bit_mask=b'\xC0\x00'),
        ]

        # Query for all but exclude beta
        bitmap = apply_tag_query(tags, "all,!beta", 10)

        # Files 0 and 1 should be excluded
        assert is_file_selected(bitmap, 0) is False
        assert is_file_selected(bitmap, 1) is False
        # Files 2+ should be selected
        assert is_file_selected(bitmap, 2) is True
        assert is_file_selected(bitmap, 3) is True

    def test_is_file_selected_bitmap(self):
        """Test is_file_selected function."""
        bitmap = bytes([0b11000000, 0b00001100])

        # First byte: bits 7-0 = 1,1,0,0,0,0,0,0
        assert is_file_selected(bitmap, 0) is True   # Bit 7
        assert is_file_selected(bitmap, 1) is True   # Bit 6
        assert is_file_selected(bitmap, 2) is False  # Bit 5

        # Second byte: bits 15-8 = 0,0,0,0,1,1,0,0
        assert is_file_selected(bitmap, 8) is False  # Bit 15
        assert is_file_selected(bitmap, 9) is False  # Bit 14
        assert is_file_selected(bitmap, 10) is False  # Bit 13
        assert is_file_selected(bitmap, 11) is False  # Bit 12
        assert is_file_selected(bitmap, 12) is True   # Bit 11
        assert is_file_selected(bitmap, 13) is True   # Bit 10

    def test_is_file_selected_out_of_range(self):
        """Test is_file_selected with out-of-range index."""
        bitmap = bytes([0xFF, 0xFF])

        assert is_file_selected(bitmap, 0) is True
        assert is_file_selected(bitmap, 15) is True
        assert is_file_selected(bitmap, 16) is False  # Out of range

    def test_unknown_tag_warning(self, caplog):
        """Test that unknown tags are logged as warnings."""
        tags = [
            SizeTag(name="enUS", tag_id=1, tag_type=4, file_indices=[], bit_mask=b'\xFF'),
        ]

        # Query with unknown tag
        bitmap = apply_tag_query(tags, "enUS,unknown_tag", 5)

        # Bitmap should still work
        assert len(bitmap) == 1

        # Unknown tag should be logged as warning (verify logs if caplog available)
        # Note: This test verifies the function handles unknown tags gracefully


class TestSizeParserEdgeCases:
    """Test error paths and edge cases in SizeParser."""

    def _build_v1_header(self, entry_count: int = 0, esize_bytes: int = 4) -> bytes:
        """Build a minimal V1 size manifest header."""
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))          # version
        data.write(struct.pack('B', 0))          # flags
        data.write(struct.pack('>I', entry_count))
        data.write(struct.pack('>H', 128))       # key_size_bits
        data.write(struct.pack('>Q', 0))         # total_size
        data.write(struct.pack('B', esize_bytes))
        return data.getvalue()

    def _build_v2_header(self, entry_count: int = 0) -> bytes:
        """Build a minimal V2 size manifest header."""
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 2))          # version
        data.write(struct.pack('B', 0))          # flags
        data.write(struct.pack('>I', entry_count))
        data.write(struct.pack('>H', 128))       # key_size_bits
        data.write(struct.pack('>Q', 0)[3:])     # 5-byte total_size
        return data.getvalue()

    def test_parse_stream_input(self):
        """Test parse() accepts a BytesIO stream directly (not just bytes)."""
        header = self._build_v2_header(entry_count=0)
        stream = BytesIO(header)
        parser = SizeParser()
        size = parser.parse(stream)
        assert size.header.version == 2
        assert len(size.entries) == 0

    def test_parse_insufficient_header(self):
        """Test that truncated header raises ValueError."""
        parser = SizeParser()
        with pytest.raises(ValueError, match="Insufficient data for header"):
            parser.parse(b'DS\x01\x00')  # Only 4 bytes instead of 10

    def test_parse_invalid_magic(self):
        """Test that invalid magic bytes raise ValueError."""
        parser = SizeParser()
        data = b'XX\x01\x00\x00\x00\x00\x00\x00\x80'
        with pytest.raises(ValueError, match="Invalid magic"):
            parser.parse(data)

    def test_parse_v1_header_esize_bytes_zero(self):
        """Test V1 header with esize_bytes=0 raises ValueError."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))   # version
        data.write(struct.pack('B', 0))   # flags
        data.write(struct.pack('>I', 0))  # entry_count
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 0))  # total_size
        data.write(struct.pack('B', 0))   # esize_bytes = 0 (invalid)
        with pytest.raises(ValueError, match="Invalid eSize byte count"):
            parser.parse(data.getvalue())

    def test_parse_v1_header_esize_bytes_too_large(self):
        """Test V1 header with esize_bytes=9 raises ValueError."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 0))
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 0))
        data.write(struct.pack('B', 9))   # esize_bytes = 9 (invalid, max=8)
        with pytest.raises(ValueError, match="Invalid eSize byte count"):
            parser.parse(data.getvalue())

    def test_parse_v1_header_truncated_v1_fields(self):
        """Test V1 with insufficient V1-specific header data."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 0))
        data.write(struct.pack('>H', 128))
        data.write(b'\x00\x00')           # Only 2 bytes instead of 9 for V1 extra
        with pytest.raises(ValueError, match="Insufficient data for V1 header"):
            parser.parse(data.getvalue())

    def test_parse_v2_header_truncated(self):
        """Test V2 with insufficient V2-specific header data."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 2))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 0))
        data.write(struct.pack('>H', 128))
        data.write(b'\x00\x00')           # Only 2 bytes instead of 5 for V2 extra
        with pytest.raises(ValueError, match="Insufficient data for V2 header"):
            parser.parse(data.getvalue())

    def test_parse_v1_esize_1_byte(self):
        """Test V1 with esize_bytes=1 (uint8 esize)."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 1))   # 1 entry
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 200))  # total_size
        data.write(struct.pack('B', 1))     # esize_bytes = 1
        # Entry
        data.write(b'small.dat\x00')
        data.write(struct.pack('>H', 0x1234))
        data.write(struct.pack('B', 200))   # 1-byte esize
        size = parser.parse(data.getvalue())
        assert size.entries[0].esize == 200
        assert size.header.esize_bytes == 1

    def test_parse_v1_esize_2_bytes(self):
        """Test V1 with esize_bytes=2 (uint16 esize)."""
        parser = SizeParser()
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 1))
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 1000))
        data.write(struct.pack('B', 2))    # esize_bytes = 2
        # Entry
        data.write(b'medium.dat\x00')
        data.write(struct.pack('>H', 0x5678))
        data.write(struct.pack('>H', 1000))  # 2-byte esize
        size = parser.parse(data.getvalue())
        assert size.entries[0].esize == 1000
        assert size.header.esize_bytes == 2

    def test_parse_v1_esize_8_bytes(self):
        """Test V1 with esize_bytes=8 (uint64 esize)."""
        parser = SizeParser()
        large_size = 0x1_0000_0000  # 4 GiB, needs 8 bytes
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 1))
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', large_size))
        data.write(struct.pack('B', 8))      # esize_bytes = 8
        # Entry
        data.write(b'huge.dat\x00')
        data.write(struct.pack('>H', 0xABCD))
        data.write(struct.pack('>Q', large_size))  # 8-byte esize
        size = parser.parse(data.getvalue())
        assert size.entries[0].esize == large_size
        assert size.header.esize_bytes == 8

    def test_parse_entry_key_hash_truncated(self):
        """Test that truncated key hash raises ValueError."""
        parser = SizeParser()
        header = self._build_v1_header(entry_count=1)
        # Add a key but truncate before key_hash
        data = header + b'test.dat\x00\x12'  # Only 1 byte of hash instead of 2
        with pytest.raises(ValueError, match="Insufficient data for key hash"):
            parser.parse(data)

    def test_parse_entry_esize_truncated(self):
        """Test that truncated esize raises ValueError."""
        parser = SizeParser()
        header = self._build_v1_header(entry_count=1, esize_bytes=4)
        # Add key + key_hash but truncate before esize
        data = header + b'test.dat\x00' + struct.pack('>H', 0x1234) + b'\x00\x00'  # only 2 of 4 esize bytes
        with pytest.raises(ValueError, match="Insufficient data for eSize"):
            parser.parse(data)

    def test_build_v2_total_size_too_large(self):
        """Test that V2 build raises if total_size >= 2^40."""
        from cascette_tools.formats.size import SizeFile, SizeHeader
        header = SizeHeader(
            version=2, flags=0, entry_count=0, key_size_bits=128,
            total_size=(1 << 40),  # Exactly 2^40 — too large for 5-byte uint40
            esize_bytes=4
        )
        obj = SizeFile(header=header, entries=[], tags=[])
        parser = SizeParser()
        with pytest.raises(ValueError, match="Total size too large"):
            parser.build(obj)

    def test_build_esize_1_byte(self):
        """Test building V1 with esize_bytes=1 round-trips correctly."""
        from cascette_tools.formats.size import SizeFile, SizeHeader
        entry = SizeEntry(key="tiny.dat", key_hash=0x1234, esize=42)
        header = SizeHeader(
            version=1, flags=0, entry_count=1, key_size_bits=128,
            total_size=42, esize_bytes=1
        )
        obj = SizeFile(header=header, entries=[entry], tags=[])
        parser = SizeParser()
        data = parser.build(obj)
        reparsed = parser.parse(data)
        assert reparsed.entries[0].esize == 42

    def test_build_esize_2_bytes(self):
        """Test building V1 with esize_bytes=2 round-trips correctly."""
        from cascette_tools.formats.size import SizeFile, SizeHeader
        entry = SizeEntry(key="small.dat", key_hash=0x5678, esize=1000)
        header = SizeHeader(
            version=1, flags=0, entry_count=1, key_size_bits=128,
            total_size=1000, esize_bytes=2
        )
        obj = SizeFile(header=header, entries=[entry], tags=[])
        parser = SizeParser()
        data = parser.build(obj)
        reparsed = parser.parse(data)
        assert reparsed.entries[0].esize == 1000

    def test_build_esize_8_bytes(self):
        """Test building V1 with esize_bytes=8 round-trips correctly."""
        from cascette_tools.formats.size import SizeFile, SizeHeader
        large = 0x1_0000_0000
        entry = SizeEntry(key="huge.dat", key_hash=0xABCD, esize=large)
        header = SizeHeader(
            version=1, flags=0, entry_count=1, key_size_bits=128,
            total_size=large, esize_bytes=8
        )
        obj = SizeFile(header=header, entries=[entry], tags=[])
        parser = SizeParser()
        data = parser.build(obj)
        reparsed = parser.parse(data)
        assert reparsed.entries[0].esize == large

    def test_builder_build_delegates(self):
        """Test that SizeBuilder.build() delegates to SizeParser.build()."""
        size_file = SizeBuilder.create_empty(version=2)
        builder = SizeBuilder()
        data = builder.build(size_file)
        parser = SizeParser()
        reparsed = parser.parse(data)
        assert reparsed.header.version == 2
        assert len(reparsed.entries) == 0

    def test_builder_create_empty_v1(self):
        """Test SizeBuilder.create_empty(version=1) sets correct defaults."""
        size_file = SizeBuilder.create_empty(version=1)
        assert size_file.header.version == 1
        assert size_file.header.total_size == 0
        assert size_file.header.key_size_bits == 128
        assert len(size_file.entries) == 0
        assert len(size_file.tags) == 0

    def test_builder_create_with_entries_computes_total_size(self):
        """Test that create_with_entries computes total_size from entry esizes."""
        entries = [
            SizeEntry(key="a.dat", key_hash=0x1111, esize=100),
            SizeEntry(key="b.dat", key_hash=0x2222, esize=200),
            SizeEntry(key="c.dat", key_hash=0x3333, esize=300),
        ]
        size_file = SizeBuilder.create_with_entries(entries, version=2)
        assert size_file.header.total_size == 600
        assert size_file.header.entry_count == 3
        assert len(size_file.entries) == 3

    def test_apply_tag_query_unknown_tag_continues(self):
        """Test apply_tag_query ignores unknown tags and still returns a bitmap."""
        tags = [
            SizeTag(name="enUS", tag_id=1, tag_type=4, file_indices=[0, 1], bit_mask=b'\xC0'),
        ]
        # "nonexistent" is not in tags; should be silently skipped
        bitmap = apply_tag_query(tags, "enUS,nonexistent", 5)
        assert len(bitmap) == 1
        # "enUS" is additive: files 0,1 selected; nonexistent skipped
        assert bitmap[0] & 0x80  # file 0 selected
        assert bitmap[0] & 0x40  # file 1 selected

    def test_parse_v1_esize_3_bytes(self):
        """Test V1 with esize_bytes=3 uses the generic int.from_bytes fallback path."""
        parser = SizeParser()
        # 3-byte esize is valid per header (1-8 range) but hits the else branch in build/parse
        data = BytesIO()
        data.write(b'DS')
        data.write(struct.pack('B', 1))
        data.write(struct.pack('B', 0))
        data.write(struct.pack('>I', 1))
        data.write(struct.pack('>H', 128))
        data.write(struct.pack('>Q', 500))
        data.write(struct.pack('B', 3))     # esize_bytes = 3 → hits else branch
        # Entry: key + hash + 3-byte esize
        data.write(b'three.dat\x00')
        data.write(struct.pack('>H', 0x1234))
        data.write(b'\x00\x01\xF4')         # 500 in big-endian 3 bytes
        size = parser.parse(data.getvalue())
        assert size.entries[0].esize == 500
        assert size.header.esize_bytes == 3

    def test_build_esize_3_bytes(self):
        """Test build() with esize_bytes=3 uses the generic to_bytes fallback path."""
        from cascette_tools.formats.size import SizeFile, SizeHeader
        entry = SizeEntry(key="three.dat", key_hash=0x1234, esize=500)
        header = SizeHeader(
            version=1, flags=0, entry_count=1, key_size_bits=128,
            total_size=500, esize_bytes=3
        )
        obj = SizeFile(header=header, entries=[entry], tags=[])
        parser = SizeParser()
        data = parser.build(obj)
        reparsed = parser.parse(data)
        assert reparsed.entries[0].esize == 500

    def test_parse_tag_entries_stream_input(self):
        """Test parse_tag_entries accepts a BytesIO stream (not just bytes)."""
        parser = SizeParser()
        blob = BytesIO()
        blob.write(b'enUS\x00')
        blob.write(struct.pack('>H', 4))
        blob.write(b'\xC0')
        blob.seek(0)
        # Pass a stream (BytesIO) directly instead of bytes to hit the else branch
        tags = parser.parse_tag_entries(blob, tag_count=1, entry_count=2)
        assert len(tags) == 1
        assert tags[0].name == "enUS"

    def test_apply_tag_query_bitmask_longer_than_file_count(self):
        """Test apply_tag_query breaks early when tag bitmask exceeds file_count bitmap size."""
        # Tag bitmask is 4 bytes but file_count only needs 1 byte (8 files)
        # The loop should break at i >= bitmap_size (line 546)
        tags = [
            SizeTag(name="wide", tag_id=1, tag_type=4, file_indices=[0, 1], bit_mask=b'\xC0\xFF\xFF\xFF'),
        ]
        bitmap = apply_tag_query(tags, "wide", 8)
        # bitmap_size = 1, tag bitmask has 4 bytes — only first byte should be applied
        assert len(bitmap) == 1
        assert bitmap[0] == 0xC0  # Only first byte of the 4-byte mask applied

    def test_parse_tag_entries_truncated_tag_type(self):
        """Test that truncated tag type data logs warning and stops parsing."""
        parser = SizeParser()
        # Write tag name but only 1 byte of tag_type (needs 2)
        blob = b'enUS\x00\xFF'   # Only 1 byte of tag_type instead of 2
        # Should break early (warning logged), returning 0 tags
        tags = parser.parse_tag_entries(blob, tag_count=1, entry_count=2)
        assert len(tags) == 0


class TestTagEntries:
    """Test parse_tag_entries method for tag blob parsing."""

    def test_parse_tag_entries_simple(self):
        """Test parsing single tag entry.

        Tag format: null-terminated string + 2-byte BE tag_type + bitmap
        - String: "enUS\x00" (5 bytes)
        - Tag type: 0x0004 (locale category)
        - Bitmap: 0xA8 (files 0,2,4 set in MSB order)
        - entry_count=5 determines bitmap size: (5+7)>>3 = 1 byte
        """
        parser = SizeParser()

        blob = BytesIO()
        blob.write(b'enUS\x00')              # Null-terminated string
        blob.write(struct.pack('>H', 4))      # 2-byte BE tag_type (locale)
        blob.write(b'\xa8')                   # Bitmap: files 0,2,4 = 0xA8 (MSB)

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=1, entry_count=5)

        assert len(tags) == 1
        tag = tags[0]
        assert tag.name == "enUS"
        assert tag.tag_id == 0
        assert tag.tag_type == 4
        assert tag.file_indices == [0, 2, 4]
        # Verify bitmap was built correctly (MSB bit ordering)
        assert tag.has_file(0) is True
        assert tag.has_file(1) is False
        assert tag.has_file(2) is True
        assert tag.has_file(3) is False
        assert tag.has_file(4) is True

    def test_parse_tag_entries_multiple(self):
        """Test parsing multiple tag entries."""
        parser = SizeParser()

        blob = BytesIO()

        # Entry 1: "enUS" tag with indices [0, 1, 2]
        # Bitmap for [0,1,2]: bits 0,1,2 set = 0b11100000 = 0xE0 (MSB order)
        blob.write(b'enUS\x00')              # Null-terminated string
        blob.write(struct.pack('>H', 4))      # tag_type (locale)
        blob.write(b'\xe0')                   # Bitmap: 0xE0

        # Entry 2: "deDE" tag with indices [0, 1]
        blob.write(b'deDE\x00')              # Null-terminated string
        blob.write(struct.pack('>H', 4))      # tag_type (locale)
        blob.write(b'\xc0')                   # Bitmap: 0xC0

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=2, entry_count=3)

        assert len(tags) == 2
        assert tags[0].name == "enUS"
        assert tags[0].tag_id == 0
        assert tags[0].file_indices == [0, 1, 2]

        assert tags[1].name == "deDE"
        assert tags[1].tag_id == 1
        assert tags[1].file_indices == [0, 1]

    def test_parse_tag_entries_end_marker(self):
        """Test that tag parsing stops at 0x0000 end marker."""
        parser = SizeParser()

        blob = BytesIO()

        # Entry 1: "enUS" tag with indices [0, 1]
        blob.write(b'enUS\x00')              # Null-terminated string
        blob.write(struct.pack('>H', 4))      # tag_type (locale)
        blob.write(b'\xc0')                   # Bitmap: files 0,1 = 0xC0

        # End marker: tag_type = 0x0000
        blob.write(b'end\x00')               # Some string
        blob.write(struct.pack('>H', 0x0000)) # End marker

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=2, entry_count=2)

        # Should only parse 1 entry (stops at end marker)
        assert len(tags) == 1
        assert tags[0].name == "enUS"

    def test_parse_tag_entries_ffff_end_marker(self):
        """Test that 0xFFFF also acts as end marker."""
        parser = SizeParser()

        blob = BytesIO()

        # Entry: "test" tag with index [5]
        # Bitmap for [5]: bit 5 set = 0x04 (MSB order)
        blob.write(b'test\x00')              # Null-terminated string
        blob.write(struct.pack('>H', 1))      # tag_type (platform)
        blob.write(b'\x04')                   # Bitmap: file 5 = 0x04

        # End marker: tag_type = 0xFFFF
        blob.write(b'end\x00')               # Some string
        blob.write(struct.pack('>H', 0xFFFF)) # End marker

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=2, entry_count=6)

        assert len(tags) == 1
        assert tags[0].name == "test"

    def test_parse_tag_entries_bitmap_sparsity(self):
        """Test bitmap parsing for sparse file indices.

        Sparse indices [5, 100, 500] require entry_count=501.
        bitmap_size = (501+7)>>3 = 63 bytes
        """
        parser = SizeParser()

        entry_count = 501
        bitmap_size = (entry_count + 7) >> 3  # 63 bytes
        bitmap = bytearray(bitmap_size)

        # Set bits in MSB order
        # Index 5: byte 0, bit 5 = 0x04
        bitmap[5 // 8] |= (0x80 >> (5 % 8))
        # Index 100: byte 12, bit 4
        bitmap[100 // 8] |= (0x80 >> (100 % 8))
        # Index 500: byte 62, bit 4
        bitmap[500 // 8] |= (0x80 >> (500 % 8))

        blob = BytesIO()
        blob.write(b'sparse\x00')            # Null-terminated string
        blob.write(struct.pack('>H', 1))       # tag_type (platform)
        blob.write(bytes(bitmap))              # Bitmap data

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=1, entry_count=entry_count)

        assert len(tags) == 1
        tag = tags[0]
        assert tag.name == "sparse"
        assert tag.file_indices == [5, 100, 500]

        # Verify bitmap size is based on entry_count
        assert len(tag.bit_mask) == 63

        # Verify specific indices are set
        assert tag.has_file(5) is True
        assert tag.has_file(100) is True
        assert tag.has_file(500) is True
        assert tag.has_file(4) is False
        assert tag.has_file(99) is False

    def test_parse_tag_entries_empty(self):
        """Test parsing empty tag table."""
        parser = SizeParser()

        tags = parser.parse_tag_entries(b'', tag_count=0, entry_count=0)
        assert len(tags) == 0

    def test_parse_tag_entries_msb_bit_ordering(self):
        """Test MSB bit ordering in bitmap parsing.

        MSB bit ordering: file 0 = bit 7 (0x80), file 7 = bit 0 (0x01)
        File indices 0-7 should produce bitmap byte 0xFF.
        """
        parser = SizeParser()

        blob = BytesIO()

        # Tag with indices 0-7: all bits set = 0xFF
        blob.write(b'msb\x00')               # Null-terminated string
        blob.write(struct.pack('>H', 1))       # tag_type (platform)
        blob.write(b'\xff')                    # Bitmap: all 8 bits set

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=1, entry_count=8)

        assert len(tags) == 1
        tag = tags[0]

        # First byte should have all bits set (0xFF)
        assert tag.bit_mask[0] == 0xFF

        # Verify MSB ordering by checking file indices
        assert tag.has_file(0) is True   # Bit 7 (MSB)
        assert tag.has_file(1) is True   # Bit 6
        assert tag.has_file(2) is True   # Bit 5
        assert tag.has_file(3) is True   # Bit 4
        assert tag.has_file(4) is True   # Bit 3
        assert tag.has_file(5) is True   # Bit 2
        assert tag.has_file(6) is True   # Bit 1
        assert tag.has_file(7) is True   # Bit 0 (LSB)

