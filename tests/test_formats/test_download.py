"""Tests for download format parser."""

import struct
from io import BytesIO

import pytest

from cascette_tools.formats.download import (
    DownloadEntry,
    DownloadFile,
    DownloadHeader,
    DownloadParser,
    DownloadTag,
    is_download,
)


class TestDownloadParser:
    """Test download format parser."""

    def test_is_download_function(self):
        """Test is_download detection function."""
        # Valid download data with DL magic
        assert is_download(b'DL\x01\x09\x00\x00\x00\x00\x01\x00\x01\x00')

        # Invalid magic
        assert not is_download(b'XX\x01\x09')
        assert not is_download(b'IN\x01\x09')

        # Too short
        assert not is_download(b'D')
        assert not is_download(b'')

    def test_download_tag_has_file(self):
        """Test DownloadTag.has_file method."""
        # Create tag with bitmask: files 0, 2, 5 have the tag
        # Byte 0: bits 0, 2, 5 set = 0b00100101 = 0x25
        bitmask = bytearray(1)
        bitmask[0] = 0b00100101  # bits 0, 2, 5 set

        tag = DownloadTag(name="test", tag_type=1, file_mask=bytes(bitmask))

        assert tag.has_file(0) is True   # bit 0
        assert tag.has_file(1) is False  # bit 1
        assert tag.has_file(2) is True   # bit 2
        assert tag.has_file(3) is False  # bit 3
        assert tag.has_file(4) is False  # bit 4
        assert tag.has_file(5) is True   # bit 5
        assert tag.has_file(6) is False  # bit 6
        assert tag.has_file(7) is False  # bit 7
        assert tag.has_file(8) is False  # out of range

        # Test with multiple bytes
        bitmask_multi = bytearray(2)
        bitmask_multi[0] = 0b00000001  # bit 0 set
        bitmask_multi[1] = 0b00000001  # bit 8 set (first bit of second byte)

        tag_multi = DownloadTag(name="test2", tag_type=2, file_mask=bytes(bitmask_multi))

        assert tag_multi.has_file(0) is True   # bit 0 in byte 0
        assert tag_multi.has_file(7) is False  # bit 7 in byte 0
        assert tag_multi.has_file(8) is True   # bit 0 in byte 1
        assert tag_multi.has_file(15) is False  # bit 7 in byte 1
        assert tag_multi.has_file(16) is False  # out of range

    def test_parse_empty_download(self):
        """Test parsing empty download manifest."""
        data = BytesIO()
        # DL magic
        data.write(b'DL')
        # Version 1
        data.write(struct.pack('B', 1))
        # EKey size 9
        data.write(struct.pack('B', 9))
        # Has checksum: no
        data.write(struct.pack('B', 0))
        # Entry count: 0
        data.write(struct.pack('>I', 0))
        # Tag count: 0
        data.write(struct.pack('>H', 0))
        # Reserved byte
        data.write(b'\x00')

        parser = DownloadParser()
        result = parser.parse(data.getvalue())

        assert result.header.version == 1
        assert result.header.ekey_size == 9
        assert result.header.has_checksum is False
        assert result.header.entry_count == 0
        assert result.header.tag_count == 0
        assert len(result.entries) == 0
        assert len(result.tags) == 0

    def test_parse_simple_download_no_checksum(self):
        """Test parsing simple download manifest without checksums."""
        data = BytesIO()

        # Header
        data.write(b'DL')  # Magic
        data.write(struct.pack('B', 1))  # Version
        data.write(struct.pack('B', 9))  # EKey size
        data.write(struct.pack('B', 0))  # Has checksum: no
        data.write(struct.pack('>I', 2))  # Entry count: 2
        data.write(struct.pack('>H', 1))  # Tag count: 1
        # No reserved byte for version 1

        # Entry 0: ekey, size 1000, priority 10
        data.write(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')  # EKey
        data.write(struct.pack('>Q', 1000)[3:])  # Size (5 bytes)
        data.write(struct.pack('B', 10))  # Priority

        # Entry 1: ekey, size 2000, priority 20
        data.write(b'\x11\x12\x13\x14\x15\x16\x17\x18\x19')  # EKey
        data.write(struct.pack('>Q', 2000)[3:])  # Size (5 bytes)
        data.write(struct.pack('B', 20))  # Priority

        # Tag: "Windows" type 1, affects files 0 and 1 (version 1: tags come AFTER entries)
        data.write(b'Windows\x00')  # Tag name
        data.write(struct.pack('>H', 1))  # Tag type
        data.write(b'\x03')  # Bitmask: 0b00000011 (files 0 and 1)

        parser = DownloadParser()
        result = parser.parse(data.getvalue())

        assert result.header.version == 1
        assert result.header.ekey_size == 9
        assert result.header.has_checksum is False
        assert result.header.entry_count == 2
        assert result.header.tag_count == 1

        assert len(result.tags) == 1
        assert result.tags[0].name == "Windows"
        assert result.tags[0].tag_type == 1

        assert len(result.entries) == 2

        # Check first entry
        assert result.entries[0].ekey == b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'
        assert result.entries[0].size == 1000
        assert result.entries[0].priority == 10
        assert result.entries[0].checksum is None
        assert "Windows" in result.entries[0].tags

        # Check second entry
        assert result.entries[1].ekey == b'\x11\x12\x13\x14\x15\x16\x17\x18\x19'
        assert result.entries[1].size == 2000
        assert result.entries[1].priority == 20
        assert result.entries[1].checksum is None
        assert "Windows" in result.entries[1].tags

    def test_parse_download_with_checksum(self):
        """Test parsing download manifest with checksums."""
        data = BytesIO()

        # Header
        data.write(b'DL')  # Magic
        data.write(struct.pack('B', 1))  # Version
        data.write(struct.pack('B', 16))  # EKey size (full MD5)
        data.write(struct.pack('B', 1))  # Has checksum: yes
        data.write(struct.pack('>I', 1))  # Entry count: 1
        data.write(struct.pack('>H', 0))  # Tag count: 0
        # No reserved byte for version 1

        # Entry 0: ekey, size 500, priority 5, checksum
        data.write(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')  # EKey (16 bytes)
        data.write(struct.pack('>Q', 500)[3:])  # Size (5 bytes)
        data.write(struct.pack('B', 5))  # Priority
        data.write(b'\xa1\xa2\xa3\xa4')  # Checksum

        parser = DownloadParser()
        result = parser.parse(data.getvalue())

        assert result.header.version == 1
        assert result.header.ekey_size == 16
        assert result.header.has_checksum is True
        assert result.header.entry_count == 1
        assert result.header.tag_count == 0

        assert len(result.entries) == 1
        assert result.entries[0].ekey == b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        assert result.entries[0].size == 500
        assert result.entries[0].priority == 5
        assert result.entries[0].checksum == b'\xa1\xa2\xa3\xa4'
        assert len(result.entries[0].tags) == 0

    def test_parse_large_file_size(self):
        """Test parsing entry with large file size (using 40-bit size)."""
        data = BytesIO()

        # Header for one entry
        data.write(b'DL')  # Magic
        data.write(struct.pack('B', 1))  # Version
        data.write(struct.pack('B', 9))  # EKey size
        data.write(struct.pack('B', 0))  # Has checksum: no
        data.write(struct.pack('>I', 1))  # Entry count: 1
        data.write(struct.pack('>H', 0))  # Tag count: 0
        # No reserved byte for version 1

        # Entry with large size (1TB = 2^40 bytes)
        large_size = (1 << 40) - 1  # Maximum 40-bit value
        data.write(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')  # EKey
        data.write(struct.pack('>Q', large_size)[3:])  # Size (5 bytes)
        data.write(struct.pack('B', 255))  # Priority (max value)

        parser = DownloadParser()
        result = parser.parse(data.getvalue())

        assert len(result.entries) == 1
        assert result.entries[0].size == large_size
        # 255 as unsigned byte is -1 as signed byte (priority is signed per Rust spec)
        assert result.entries[0].priority == -1

    def test_build_empty_download(self):
        """Test building empty download manifest."""
        header = DownloadHeader(
            version=1,
            ekey_size=9,
            has_checksum=False,
            entry_count=0,
            tag_count=0
        )

        download_file = DownloadFile(
            header=header,
            tags=[],
            entries=[]
        )

        parser = DownloadParser()
        data = parser.build(download_file)

        # Verify the built data
        expected = (
            b'DL'  # Magic
            b'\x01'  # Version
            b'\x09'  # EKey size
            b'\x00'  # Has checksum: no
            b'\x00\x00\x00\x00'  # Entry count: 0 (big-endian)
            b'\x00\x00'  # Tag count: 0 (big-endian)
            # No reserved byte for version 1
        )

        assert data == expected

    def test_build_simple_download(self):
        """Test building simple download manifest."""
        header = DownloadHeader(
            version=1,
            ekey_size=9,
            has_checksum=False,
            entry_count=1,
            tag_count=1
        )

        tag = DownloadTag(
            name="Test",
            tag_type=42,
            file_mask=b'\x01'  # File 0 has this tag
        )

        entry = DownloadEntry(
            ekey=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09',
            size=12345,
            priority=100,
            checksum=None,
            tags=["Test"]
        )

        download_file = DownloadFile(
            header=header,
            tags=[tag],
            entries=[entry]
        )

        parser = DownloadParser()
        data = parser.build(download_file)

        # Parse it back to verify correctness
        rebuilt = parser.parse(data)

        assert rebuilt.header.version == 1
        assert rebuilt.header.ekey_size == 9
        assert rebuilt.header.has_checksum is False
        assert len(rebuilt.entries) == 1
        assert len(rebuilt.tags) == 1

        assert rebuilt.entries[0].ekey == b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'
        assert rebuilt.entries[0].size == 12345
        assert rebuilt.entries[0].priority == 100
        assert "Test" in rebuilt.entries[0].tags

    def test_build_with_checksum(self):
        """Test building download manifest with checksums."""
        header = DownloadHeader(
            version=1,
            ekey_size=16,
            has_checksum=True,
            entry_count=1,
            tag_count=0
        )

        entry = DownloadEntry(
            ekey=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10',
            size=9999,
            priority=50,
            checksum=b'\xde\xad\xbe\xef',
            tags=[]
        )

        download_file = DownloadFile(
            header=header,
            tags=[],
            entries=[entry]
        )

        parser = DownloadParser()
        data = parser.build(download_file)

        # Parse it back to verify correctness
        rebuilt = parser.parse(data)

        assert rebuilt.header.has_checksum is True
        assert len(rebuilt.entries) == 1
        assert rebuilt.entries[0].checksum == b'\xde\xad\xbe\xef'

    def test_round_trip_complex(self):
        """Test round-trip parsing with complex download manifest."""
        header = DownloadHeader(
            version=1,
            ekey_size=9,
            has_checksum=True,
            entry_count=3,
            tag_count=2
        )

        tag1 = DownloadTag(name="Windows", tag_type=1, file_mask=b'\x05')  # Files 0 and 2
        tag2 = DownloadTag(name="enUS", tag_type=2, file_mask=b'\x03')  # Files 0 and 1

        entry1 = DownloadEntry(
            ekey=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09',
            size=1000,
            priority=10,
            checksum=b'\xa1\xa2\xa3\xa4',
            tags=["Windows", "enUS"]
        )
        entry2 = DownloadEntry(
            ekey=b'\x11\x12\x13\x14\x15\x16\x17\x18\x19',
            size=2000,
            priority=20,
            checksum=b'\xb1\xb2\xb3\xb4',
            tags=["enUS"]
        )
        entry3 = DownloadEntry(
            ekey=b'\x21\x22\x23\x24\x25\x26\x27\x28\x29',
            size=3000,
            priority=30,
            checksum=b'\xc1\xc2\xc3\xc4',
            tags=["Windows"]
        )

        original = DownloadFile(
            header=header,
            tags=[tag1, tag2],
            entries=[entry1, entry2, entry3]
        )

        parser = DownloadParser()

        # Build and parse back
        data = parser.build(original)
        rebuilt = parser.parse(data)

        # Verify header
        assert rebuilt.header.version == original.header.version
        assert rebuilt.header.ekey_size == original.header.ekey_size
        assert rebuilt.header.has_checksum == original.header.has_checksum
        assert len(rebuilt.entries) == len(original.entries)
        assert len(rebuilt.tags) == len(original.tags)

        # Verify entries
        for _i, (orig_entry, rebuilt_entry) in enumerate(zip(original.entries, rebuilt.entries, strict=True)):
            assert rebuilt_entry.ekey == orig_entry.ekey
            assert rebuilt_entry.size == orig_entry.size
            assert rebuilt_entry.priority == orig_entry.priority
            assert rebuilt_entry.checksum == orig_entry.checksum
            assert set(rebuilt_entry.tags) == set(orig_entry.tags)

    def test_get_high_priority_entries(self):
        """Test filtering high priority entries."""
        entries = [
            DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, tags=[]),
            DownloadEntry(ekey=b'\x02' * 9, size=2000, priority=50, tags=[]),
            DownloadEntry(ekey=b'\x03' * 9, size=3000, priority=100, tags=[]),
            DownloadEntry(ekey=b'\x04' * 9, size=4000, priority=5, tags=[]),
        ]

        download_file = DownloadFile(
            header=DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=4, tag_count=0),
            tags=[],
            entries=entries
        )

        high_priority = download_file.get_high_priority_entries(max_priority=50)
        assert len(high_priority) == 3  # priorities 10, 50, 5
        priorities = [entry.priority for entry in high_priority]
        assert 10 in priorities
        assert 50 in priorities
        assert 5 in priorities
        assert 100 not in priorities

    def test_get_entries_with_tag(self):
        """Test filtering entries by tag."""
        entries = [
            DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, tags=["Windows"]),
            DownloadEntry(ekey=b'\x02' * 9, size=2000, priority=20, tags=["Linux"]),
            DownloadEntry(ekey=b'\x03' * 9, size=3000, priority=30, tags=["Windows", "Linux"]),
            DownloadEntry(ekey=b'\x04' * 9, size=4000, priority=40, tags=[]),
        ]

        download_file = DownloadFile(
            header=DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=4, tag_count=0),
            tags=[],
            entries=entries
        )

        windows_entries = download_file.get_entries_with_tag("Windows")
        assert len(windows_entries) == 2  # entries 0 and 2

        linux_entries = download_file.get_entries_with_tag("Linux")
        assert len(linux_entries) == 2  # entries 1 and 2

        nonexistent_entries = download_file.get_entries_with_tag("macOS")
        assert len(nonexistent_entries) == 0

    def test_get_sorted_by_priority(self):
        """Test sorting entries by priority."""
        entries = [
            DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=100, tags=[]),
            DownloadEntry(ekey=b'\x02' * 9, size=2000, priority=10, tags=[]),
            DownloadEntry(ekey=b'\x03' * 9, size=3000, priority=50, tags=[]),
            DownloadEntry(ekey=b'\x04' * 9, size=4000, priority=5, tags=[]),
        ]

        download_file = DownloadFile(
            header=DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=4, tag_count=0),
            tags=[],
            entries=entries
        )

        sorted_entries = download_file.get_sorted_by_priority()
        priorities = [entry.priority for entry in sorted_entries]
        assert priorities == [5, 10, 50, 100]  # Ascending order (lower priority value = higher priority)

    def test_validation_errors(self):
        """Test various validation errors."""
        parser = DownloadParser()

        # Invalid magic
        with pytest.raises(ValueError, match="Invalid magic"):
            parser.parse(b'XX\x01\x09\x00\x00\x00\x00\x01\x00\x01\x00')

        # Insufficient data for header
        with pytest.raises(ValueError, match="Insufficient data for header"):
            parser.parse(b'DL\x01\x09\x00')

        # Missing entry data (version 1 has no reserved byte, goes straight to entries)
        with pytest.raises(ValueError, match="Insufficient data for encoding key at entry 0"):
            parser.parse(b'DL\x01\x09\x00\x00\x00\x00\x01\x00\x01')

    def test_build_validation_errors(self):
        """Test build validation errors."""
        parser = DownloadParser()

        # Wrong ekey size
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 16, size=1000, priority=10)  # Wrong size
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="Encoding key size mismatch"):
            parser.build(download_file)

        # File size too large
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=(1 << 40), priority=10)  # Too large
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="File size too large"):
            parser.build(download_file)

        # Priority out of range (signed byte range is -128 to 127)
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=256)  # Out of range
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="Priority out of range"):
            parser.build(download_file)

        # Missing checksum when required
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=True, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, checksum=None)
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="Checksum required but not provided"):
            parser.build(download_file)

        # Wrong checksum size
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=True, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, checksum=b'\x01\x02')  # Wrong size
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="Checksum must be 4 bytes"):
            parser.build(download_file)

        # Unexpected checksum
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, checksum=b'\x01\x02\x03\x04')
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        with pytest.raises(ValueError, match="Checksum provided but not expected"):
            parser.build(download_file)

    def test_edge_cases(self):
        """Test edge cases."""
        parser = DownloadParser()

        # Empty manifest with tags (but no files to tag)
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=0, tag_count=1)
        tag = DownloadTag(name="Test", tag_type=1, file_mask=b'')  # Empty mask
        download_file = DownloadFile(header=header, tags=[tag], entries=[])

        data = parser.build(download_file)
        rebuilt = parser.parse(data)

        assert len(rebuilt.tags) == 1
        assert len(rebuilt.entries) == 0
        assert rebuilt.tags[0].name == "Test"

        # Files with no tags
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, tags=[])
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        data = parser.build(download_file)
        rebuilt = parser.parse(data)

        assert len(rebuilt.tags) == 0
        assert len(rebuilt.entries) == 1
        assert len(rebuilt.entries[0].tags) == 0

    def test_validation_function(self):
        """Test the validation function."""
        parser = DownloadParser()

        # Create valid download manifest
        header = DownloadHeader(version=1, ekey_size=9, has_checksum=False, entry_count=1, tag_count=0)
        entry = DownloadEntry(ekey=b'\x01' * 9, size=1000, priority=10, tags=[])
        download_file = DownloadFile(header=header, tags=[], entries=[entry])

        valid_data = parser.build(download_file)
        is_valid, message = parser.validate(valid_data)
        assert is_valid
        assert message == "Valid"

        # Test with invalid data (sufficient length but wrong magic)
        invalid_data = b'XX\x01\x09\x00\x00\x00\x00\x01\x00\x01\x00'
        is_valid, message = parser.validate(invalid_data)
        assert not is_valid
        assert "Invalid magic" in message
