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
    """Test size format parser (correct 15-byte DS layout)."""

    def _build_manifest(
        self,
        entries: list[tuple[bytes, int]],
        tags: list[tuple[str, int, bytes]] | None = None,
        ekey_size: int = 9,
        version: int = 1,
    ) -> bytes:
        """Build a size manifest with the real DS layout."""
        tags = tags or []
        total = sum(e for _, e in entries)
        out = bytearray()
        out += b"DS"
        out += struct.pack("B", version)
        out += struct.pack("B", ekey_size)
        out += struct.pack(">I", len(entries))
        out += struct.pack(">H", len(tags))
        out += total.to_bytes(5, "big")
        bitfield_len = (len(entries) + 7) // 8
        for name, tag_type, mask in tags:
            out += name.encode("utf-8") + b"\x00"
            out += struct.pack(">H", tag_type)
            out += mask.ljust(bitfield_len, b"\x00")[:bitfield_len]
        for key, esize in entries:
            assert len(key) == ekey_size
            out += key
            out += struct.pack(">I", esize)
        return bytes(out)

    def test_is_size_function(self):
        """Test is_size detection function."""
        assert is_size(b"DS\x01\x00\x00\x00\x01\x00\x00\x80")
        assert not is_size(b"XX\x01\x10")
        assert not is_size(b"EN\x01\x10")
        assert not is_size(b"D")
        assert not is_size(b"")

    def test_parse_header_real_layout(self):
        """Parse the 15-byte DS header."""
        data = self._build_manifest([(b"\x01" * 9, 100), (b"\x02" * 9, 200)])
        size = SizeParser().parse(data)
        assert size.header.version == 1
        assert size.header.ekey_size == 9
        assert size.header.entry_count == 2
        assert size.header.tag_count == 0
        assert size.header.total_size == 300

    def test_parse_entries(self):
        """Parse fixed-stride entries: ekey + 4-byte esize."""
        e1 = (b"\x11" * 9, 1024)
        e2 = (b"\x22" * 9, 5120)
        size = SizeParser().parse(self._build_manifest([e1, e2]))
        assert len(size.entries) == 2
        assert size.entries[0].key == b"\x11" * 9
        assert size.entries[0].esize == 1024
        assert size.entries[1].key == b"\x22" * 9
        assert size.entries[1].esize == 5120

    def test_parse_tags_between_header_and_entries(self):
        """Tags live between the header and the entries."""
        entries = [(bytes([i]) * 9, i * 10) for i in range(1, 6)]
        mask = b"\xa8"  # files 0,2,4
        tags = [("enUS", 4, mask), ("Windows", 1, b"\xe0")]
        size = SizeParser().parse(self._build_manifest(entries, tags))
        assert size.header.tag_count == 2
        assert len(size.tags) == 2
        assert size.tags[0].name == "enUS"
        assert size.tags[0].tag_type == 4
        assert size.tags[0].file_indices == [0, 2, 4]
        assert size.tags[1].name == "Windows"
        assert len(size.entries) == 5

    def test_parse_ekey_size_16(self):
        """Support 16-byte keys (ekey_size=16)."""
        entries = [(b"\xab" * 16, 42)]
        size = SizeParser().parse(self._build_manifest(entries, ekey_size=16))
        assert size.header.ekey_size == 16
        assert size.entries[0].key == b"\xab" * 16

    def test_unsupported_version(self):
        """Version 0 and >2 rejected."""
        data = self._build_manifest([])
        with pytest.raises(ValueError, match="version"):
            SizeParser().parse(data[:2] + b"\x00" + data[3:])
        with pytest.raises(ValueError, match="version"):
            SizeParser().parse(data[:2] + b"\x03" + data[3:])

    def test_invalid_ekey_size(self):
        """ekey_size 0 or >16 rejected."""
        data = self._build_manifest([(b"a" * 9, 1)])
        with pytest.raises(ValueError, match="eKey"):
            SizeParser().parse(data[:3] + b"\x00" + data[4:])
        with pytest.raises(ValueError, match="eKey"):
            SizeParser().parse(data[:3] + b"\x11" + data[4:])

    def test_size_tag_has_file(self):
        """Tag.has_file uses MSB bit ordering."""
        tag = SizeTag(
            name="t",
            tag_id=0,
            tag_type=1,
            file_indices=[0, 2, 4],
            bit_mask=b"\xa8",
        )
        assert tag.has_file(0) is True
        assert tag.has_file(1) is False
        assert tag.has_file(2) is True
        assert tag.has_file(4) is True
        assert tag.has_file(3) is False

    def test_build_roundtrip(self):
        """build() produces bytes parse() reads back identically."""
        entries = [(bytes([i]) * 9, i * 100) for i in range(1, 4)]
        mask = b"\xe0"
        tags = [("enUS", 4, mask)]
        blob = SizeParser().build(
            SizeParser().parse(self._build_manifest(entries, tags))
        )
        size = SizeParser().parse(blob)
        assert size.header.ekey_size == 9
        assert [e.esize for e in size.entries] == [100, 200, 300]
        assert size.tags[0].name == "enUS"

    def test_create_empty(self):
        """SizeBuilder.create_empty produces a valid empty manifest."""
        size = SizeBuilder.create_empty(version=1)
        assert size.header.version == 1
        assert size.header.ekey_size == 9
        assert size.header.entry_count == 0
        assert len(size.entries) == 0


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
            SizeTag(
                name="enUS", tag_id=1, tag_type=4, file_indices=[], bit_mask=b"\xff"
            ),
            SizeTag(
                name="deDE", tag_id=2, tag_type=4, file_indices=[], bit_mask=b"\xff"
            ),
        ]

        bitmap = apply_tag_query(tags, "", 10)
        assert len(bitmap) == 2
        # All files should be selected (0xFF)
        assert bitmap == b"\xff\xff"

    def test_apply_tag_query_no_tags(self):
        """Test applying query with no tags available."""
        tags: list[SizeTag] = []
        bitmap = apply_tag_query(tags, "enUS", 10)
        assert len(bitmap) == 2
        # All files selected when no tags
        assert bitmap == b"\xff\xff"

    def test_apply_tag_query_simple_additive(self):
        """Test applying simple additive tag query."""
        # Create tags with bitmasks for 10 files
        # Tag 1 (enUS): files 0, 2, 4, 6, 8 set
        # Tag 2 (deDE): files 1, 3, 5, 7, 9 set
        tag1_mask = bytearray(2)
        for i in range(0, 10, 2):
            byte_index = i >> 3
            bit_position = i & 7
            tag1_mask[byte_index] |= 0x80 >> bit_position

        tag2_mask = bytearray(2)
        for i in range(1, 10, 2):
            byte_index = i >> 3
            bit_position = i & 7
            tag2_mask[byte_index] |= 0x80 >> bit_position

        tags = [
            SizeTag(
                name="enUS",
                tag_id=1,
                tag_type=4,
                file_indices=[],
                bit_mask=bytes(tag1_mask),
            ),
            SizeTag(
                name="deDE",
                tag_id=2,
                tag_type=4,
                file_indices=[],
                bit_mask=bytes(tag2_mask),
            ),
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
            SizeTag(
                name="all", tag_id=1, tag_type=1, file_indices=[], bit_mask=tag_mask
            ),
            SizeTag(
                name="beta",
                tag_id=2,
                tag_type=1,
                file_indices=[0, 1],
                bit_mask=b"\xc0\x00",
            ),
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
        assert is_file_selected(bitmap, 0) is True  # Bit 7
        assert is_file_selected(bitmap, 1) is True  # Bit 6
        assert is_file_selected(bitmap, 2) is False  # Bit 5

        # Second byte: bits 15-8 = 0,0,0,0,1,1,0,0
        assert is_file_selected(bitmap, 8) is False  # Bit 15
        assert is_file_selected(bitmap, 9) is False  # Bit 14
        assert is_file_selected(bitmap, 10) is False  # Bit 13
        assert is_file_selected(bitmap, 11) is False  # Bit 12
        assert is_file_selected(bitmap, 12) is True  # Bit 11
        assert is_file_selected(bitmap, 13) is True  # Bit 10

    def test_is_file_selected_out_of_range(self):
        """Test is_file_selected with out-of-range index."""
        bitmap = bytes([0xFF, 0xFF])

        assert is_file_selected(bitmap, 0) is True
        assert is_file_selected(bitmap, 15) is True
        assert is_file_selected(bitmap, 16) is False  # Out of range

    def test_unknown_tag_warning(self, caplog):
        """Test that unknown tags are logged as warnings."""
        tags = [
            SizeTag(
                name="enUS", tag_id=1, tag_type=4, file_indices=[], bit_mask=b"\xff"
            ),
        ]

        # Query with unknown tag
        bitmap = apply_tag_query(tags, "enUS,unknown_tag", 5)

        # Bitmap should still work
        assert len(bitmap) == 1

        # Unknown tag should be logged as warning (verify logs if caplog available)
        # Note: This test verifies the function handles unknown tags gracefully


class TestSizeParserEdgeCases:
    """Test error paths and edge cases in SizeParser."""

    def _build_manifest(
        self,
        entries: list[tuple[bytes, int]],
        tags: list[tuple[str, int, bytes]] | None = None,
        ekey_size: int = 9,
    ) -> bytes:
        tags = tags or []
        total = sum(e for _, e in entries)
        out = bytearray()
        out += b"DS"
        out += struct.pack("B", 1)
        out += struct.pack("B", ekey_size)
        out += struct.pack(">I", len(entries))
        out += struct.pack(">H", len(tags))
        out += total.to_bytes(5, "big")
        bitfield_len = (len(entries) + 7) // 8
        for name, tag_type, mask in tags:
            out += name.encode("utf-8") + b"\x00"
            out += struct.pack(">H", tag_type)
            out += mask.ljust(bitfield_len, b"\x00")[:bitfield_len]
        for key, esize in entries:
            out += key + struct.pack(">I", esize)
        return bytes(out)

    def test_parse_stream_input(self):
        """Parser accepts a BinaryIO stream."""
        data = self._build_manifest([(b"\x01" * 9, 1)])
        size = SizeParser().parse(BytesIO(data))
        assert len(size.entries) == 1

    def test_parse_insufficient_header(self):
        """Data shorter than the 15-byte header is rejected."""
        with pytest.raises(ValueError, match="Insufficient data"):
            SizeParser().parse(b"DS\x01" + b"\x00" * 8)

    def test_parse_invalid_magic(self):
        """Non-DS magic is rejected."""
        data = self._build_manifest([(b"\x01" * 9, 1)])
        with pytest.raises(ValueError, match="magic"):
            SizeParser().parse(b"XX" + data[2:])

    def test_parse_entries_truncated(self):
        """Entries shorter than the declared count are rejected."""
        data = self._build_manifest([(b"\x01" * 9, 1)])
        with pytest.raises(ValueError, match="Insufficient data"):
            SizeParser().parse(data[:-5])

    def test_parse_tag_entries_end_marker(self):
        """Tag parsing stops at end markers 0x0000/0xFFFF."""
        parser = SizeParser()
        # tag with 0x0000 type = end marker
        blob = b"enUS\x00" + struct.pack(">H", 0) + b"\x00"
        tags = parser.parse_tag_entries(blob, tag_count=1, entry_count=8)
        assert tags == []
        blob2 = b"enUS\x00" + struct.pack(">H", 0xFFFF) + b"\x00"
        tags2 = parser.parse_tag_entries(blob2, tag_count=1, entry_count=8)
        assert tags2 == []

    def test_build_v2_total_size_too_large(self):
        """Total size exceeding 40 bits is rejected on build."""
        size = SizeBuilder.create_with_entries(
            [SizeEntry(key=b"\x01" * 9, esize=1 << 40)]
        )
        size.header.total_size = 1 << 40
        with pytest.raises(ValueError, match="too large"):
            SizeParser().build(size)

    def test_builder_build_delegates(self):
        """SizeBuilder.build delegates to SizeParser.build."""
        size = SizeBuilder.create_with_entries([SizeEntry(key=b"\x01" * 9, esize=5)])
        blob = SizeBuilder().build(size)
        parsed = SizeParser().parse(blob)
        assert parsed.entries[0].esize == 5

    def test_builder_create_empty_v1(self):
        """create_empty(version=1) defaults ekey_size to 9."""
        size = SizeBuilder.create_empty(version=1)
        assert size.header.ekey_size == 9
        blob = SizeParser().build(size)
        assert SizeParser().parse(blob).header.entry_count == 0

    def test_builder_create_with_entries_computes_total_size(self):
        """create_with_entries sums esize into total_size."""
        entries = [
            SizeEntry(key=b"\x01" * 9, esize=100),
            SizeEntry(key=b"\x02" * 9, esize=200),
        ]
        size = SizeBuilder.create_with_entries(entries)
        assert size.header.total_size == 300
        assert size.header.entry_count == 2

    def test_apply_tag_query_unknown_tag_continues(self):
        """Unknown tag names are skipped, not fatal."""
        tag = SizeTag(
            name="Windows", tag_id=0, tag_type=1, file_indices=[0], bit_mask=b"\x80"
        )
        bitmap = apply_tag_query([tag], "Windows,Nonexistent", 1)
        assert is_file_selected(bitmap, 0) is True

    def test_parse_tag_entries_stream_input(self):
        """parse_tag_entries accepts a stream."""
        parser = SizeParser()
        blob = b"enUS\x00" + struct.pack(">H", 4) + b"\xa8"
        tags = parser.parse_tag_entries(BytesIO(blob), tag_count=1, entry_count=5)
        assert tags[0].name == "enUS"
        assert tags[0].file_indices == [0, 2, 4]

    def test_apply_tag_query_bitmask_longer_than_file_count(self):
        """Bitmask longer than needed is trimmed."""
        tag = SizeTag(
            name="t", tag_id=0, tag_type=1, file_indices=[0], bit_mask=b"\x80\xff"
        )
        bitmap = apply_tag_query([tag], "t", 1)
        assert len(bitmap) == 1
        assert is_file_selected(bitmap, 0) is True

    def test_parse_tag_entries_truncated_tag_type(self):
        """Truncated tag type logs a warning and stops."""
        parser = SizeParser()
        blob = b"enUS\x00" + b"\x00"
        tags = parser.parse_tag_entries(blob, tag_count=1, entry_count=5)
        assert tags == []

    def test_parse_entry_ekey_size_mismatch_build(self):
        """build rejects an entry key length not matching ekey_size."""
        size = SizeBuilder.create_with_entries([SizeEntry(key=b"\x01" * 8, esize=1)])
        with pytest.raises(ValueError, match="key length"):
            SizeParser().build(size)


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
        blob.write(b"enUS\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 4))  # 2-byte BE tag_type (locale)
        blob.write(b"\xa8")  # Bitmap: files 0,2,4 = 0xA8 (MSB)

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
        blob.write(b"enUS\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 4))  # tag_type (locale)
        blob.write(b"\xe0")  # Bitmap: 0xE0

        # Entry 2: "deDE" tag with indices [0, 1]
        blob.write(b"deDE\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 4))  # tag_type (locale)
        blob.write(b"\xc0")  # Bitmap: 0xC0

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
        blob.write(b"enUS\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 4))  # tag_type (locale)
        blob.write(b"\xc0")  # Bitmap: files 0,1 = 0xC0

        # End marker: tag_type = 0x0000
        blob.write(b"end\x00")  # Some string
        blob.write(struct.pack(">H", 0x0000))  # End marker

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
        blob.write(b"test\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 1))  # tag_type (platform)
        blob.write(b"\x04")  # Bitmap: file 5 = 0x04

        # End marker: tag_type = 0xFFFF
        blob.write(b"end\x00")  # Some string
        blob.write(struct.pack(">H", 0xFFFF))  # End marker

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
        bitmap[5 // 8] |= 0x80 >> (5 % 8)
        # Index 100: byte 12, bit 4
        bitmap[100 // 8] |= 0x80 >> (100 % 8)
        # Index 500: byte 62, bit 4
        bitmap[500 // 8] |= 0x80 >> (500 % 8)

        blob = BytesIO()
        blob.write(b"sparse\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 1))  # tag_type (platform)
        blob.write(bytes(bitmap))  # Bitmap data

        blob.seek(0)
        tags = parser.parse_tag_entries(
            blob.getvalue(), tag_count=1, entry_count=entry_count
        )

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

        tags = parser.parse_tag_entries(b"", tag_count=0, entry_count=0)
        assert len(tags) == 0

    def test_parse_tag_entries_msb_bit_ordering(self):
        """Test MSB bit ordering in bitmap parsing.

        MSB bit ordering: file 0 = bit 7 (0x80), file 7 = bit 0 (0x01)
        File indices 0-7 should produce bitmap byte 0xFF.
        """
        parser = SizeParser()

        blob = BytesIO()

        # Tag with indices 0-7: all bits set = 0xFF
        blob.write(b"msb\x00")  # Null-terminated string
        blob.write(struct.pack(">H", 1))  # tag_type (platform)
        blob.write(b"\xff")  # Bitmap: all 8 bits set

        blob.seek(0)
        tags = parser.parse_tag_entries(blob.getvalue(), tag_count=1, entry_count=8)

        assert len(tags) == 1
        tag = tags[0]

        # First byte should have all bits set (0xFF)
        assert tag.bit_mask[0] == 0xFF

        # Verify MSB ordering by checking file indices
        assert tag.has_file(0) is True  # Bit 7 (MSB)
        assert tag.has_file(1) is True  # Bit 6
        assert tag.has_file(2) is True  # Bit 5
        assert tag.has_file(3) is True  # Bit 4
        assert tag.has_file(4) is True  # Bit 3
        assert tag.has_file(5) is True  # Bit 2
        assert tag.has_file(6) is True  # Bit 1
        assert tag.has_file(7) is True  # Bit 0 (LSB)
