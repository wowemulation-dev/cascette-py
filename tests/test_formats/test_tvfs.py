"""Tests for TVFS format parser."""

import struct
from io import BytesIO

import pytest

from cascette_tools.formats.tvfs import (
    TVFSEntry,
    TVFSFile,
    TVFSHeader,
    TVFSParser,
)


class TestTVFSEntry:
    """Test TVFS entry model."""

    def test_create_entry(self):
        """Test creating a TVFS entry."""
        ckey = b"1234567890123456"  # 16 bytes
        path_hash = 0x1234567890ABCDEF
        file_data_id = 12345

        entry = TVFSEntry(
            ckey=ckey,
            path_hash=path_hash,
            file_data_id=file_data_id,
        )

        assert entry.ckey == ckey
        assert entry.path_hash == path_hash
        assert entry.file_data_id == file_data_id
        assert entry.flags == 0

    def test_entry_string_representation(self):
        """Test entry string representation."""
        ckey = b"1234567890123456"
        entry = TVFSEntry(
            ckey=ckey,
            path_hash=0x1234567890ABCDEF,
            file_data_id=12345,
        )

        str_repr = str(entry)
        assert "FileDataID:12345" in str_repr
        assert "3132333435363738" in str_repr  # hex of first 8 bytes of ckey
        assert "1234567890abcdef" in str_repr


class TestTVFSHeader:
    """Test TVFS header model."""

    def test_create_header(self):
        """Test creating a TVFS header."""
        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=10,
            entry_count=100,
            max_file_data_id=99999,
        )

        assert header.magic == b"TVFS"
        assert header.version == 1
        assert header.flags == 0x07
        assert header.data_version == 2
        assert header.block_count == 10
        assert header.entry_count == 100
        assert header.max_file_data_id == 99999

    def test_header_string_representation(self):
        """Test header string representation."""
        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=10,
            entry_count=100,
            max_file_data_id=99999,
        )

        str_repr = str(header)
        assert "TVFS v1" in str_repr
        assert "100 entries" in str_repr
        assert "max FileDataID: 99999" in str_repr


class TestTVFSFile:
    """Test TVFS file model."""

    def test_create_file(self):
        """Test creating a TVFS file."""
        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=2,
            max_file_data_id=20000,
        )

        entries = [
            TVFSEntry(
                ckey=b"1234567890123456",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"6543210987654321",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
        ]

        tvfs_file = TVFSFile(header=header, entries=entries)

        assert tvfs_file.header == header
        assert len(tvfs_file.entries) == 2
        assert tvfs_file.entries == entries

    def test_get_entry_by_file_data_id(self):
        """Test getting entry by file data ID."""
        entries = [
            TVFSEntry(
                ckey=b"1234567890123456",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"6543210987654321",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
        ]

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=0,
            block_count=1,
            entry_count=2,
            max_file_data_id=20000,
        )

        tvfs_file = TVFSFile(header=header, entries=entries)

        # Test finding existing entries
        entry = tvfs_file.get_entry_by_file_data_id(10000)
        assert entry is not None
        assert entry.file_data_id == 10000
        assert entry.ckey == b"1234567890123456"

        # Test not finding entries
        entry = tvfs_file.get_entry_by_file_data_id(99999)
        assert entry is None

    def test_get_entries_by_path_hash(self):
        """Test getting entries by path hash."""
        entries = [
            TVFSEntry(
                ckey=b"1234567890123456",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"6543210987654321",
                path_hash=0x1111111111111111,  # Same path hash
                file_data_id=20000,
            ),
            TVFSEntry(
                ckey=b"abcdefghijklmnop",
                path_hash=0x2222222222222222,  # Different path hash
                file_data_id=30000,
            ),
        ]

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=0,
            block_count=1,
            entry_count=3,
            max_file_data_id=30000,
        )

        tvfs_file = TVFSFile(header=header, entries=entries)

        # Test finding entries with same path hash
        matching_entries = tvfs_file.get_entries_by_path_hash(0x1111111111111111)
        assert len(matching_entries) == 2
        assert all(e.path_hash == 0x1111111111111111 for e in matching_entries)

        # Test finding single entry
        matching_entries = tvfs_file.get_entries_by_path_hash(0x2222222222222222)
        assert len(matching_entries) == 1
        assert matching_entries[0].file_data_id == 30000

        # Test finding no entries
        matching_entries = tvfs_file.get_entries_by_path_hash(0x9999999999999999)
        assert len(matching_entries) == 0

    def test_get_entry_by_content_key(self):
        """Test getting entry by content key."""
        entries = [
            TVFSEntry(
                ckey=b"1234567890123456",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"6543210987654321",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
        ]

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=0,
            block_count=1,
            entry_count=2,
            max_file_data_id=20000,
        )

        tvfs_file = TVFSFile(header=header, entries=entries)

        # Test finding existing entry
        entry = tvfs_file.get_entry_by_content_key(b"1234567890123456")
        assert entry is not None
        assert entry.file_data_id == 10000

        # Test not finding entry
        entry = tvfs_file.get_entry_by_content_key(b"nonexistentckey!")
        assert entry is None


class TestTVFSParser:
    """Test TVFS parser."""

    def test_parse_empty_file(self):
        """Test parsing empty TVFS file."""
        parser = TVFSParser()

        # Create minimal valid TVFS data with 0 entries
        data = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 0, 0)

        tvfs_file = parser.parse(data)

        assert tvfs_file.header.magic == b"TVFS"
        assert tvfs_file.header.version == 1
        assert tvfs_file.header.entry_count == 0
        assert len(tvfs_file.entries) == 0

    def test_parse_single_entry(self):
        """Test parsing TVFS file with single entry."""
        parser = TVFSParser()

        # Create header
        header_data = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 1, 12345)

        # Create single entry
        ckey = b"1234567890123456"  # 16 bytes
        path_hash = 0x1111111111111111
        file_data_id = 12345

        entry_data = ckey + struct.pack("<Q", path_hash) + struct.pack("<I", file_data_id)

        data = header_data + entry_data

        tvfs_file = parser.parse(data)

        assert tvfs_file.header.entry_count == 1
        assert tvfs_file.header.max_file_data_id == 12345
        assert len(tvfs_file.entries) == 1

        entry = tvfs_file.entries[0]
        assert entry.ckey == ckey
        assert entry.path_hash == path_hash
        assert entry.file_data_id == file_data_id

    def test_parse_multiple_entries(self):
        """Test parsing TVFS file with multiple entries."""
        parser = TVFSParser()

        # Create header for 3 entries
        header_data = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 3, 30000)

        # Create three entries
        entries_data = b""

        test_entries = [
            (b"1111111111111111", 0x1111111111111111, 10000),
            (b"2222222222222222", 0x2222222222222222, 20000),
            (b"3333333333333333", 0x3333333333333333, 30000),
        ]

        for ckey, path_hash, file_data_id in test_entries:
            entry_data = ckey + struct.pack("<Q", path_hash) + struct.pack("<I", file_data_id)
            entries_data += entry_data

        data = header_data + entries_data

        tvfs_file = parser.parse(data)

        assert tvfs_file.header.entry_count == 3
        assert len(tvfs_file.entries) == 3

        for i, (expected_ckey, expected_hash, expected_id) in enumerate(test_entries):
            entry = tvfs_file.entries[i]
            assert entry.ckey == expected_ckey
            assert entry.path_hash == expected_hash
            assert entry.file_data_id == expected_id

    def test_parse_from_stream(self):
        """Test parsing TVFS file from stream."""
        parser = TVFSParser()

        # Create test data
        header_data = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 1, 12345)
        ckey = b"1234567890123456"
        entry_data = ckey + struct.pack("<Q", 0x1111111111111111) + struct.pack("<I", 12345)
        data = header_data + entry_data

        stream = BytesIO(data)
        tvfs_file = parser.parse(stream)

        assert len(tvfs_file.entries) == 1
        assert tvfs_file.entries[0].ckey == ckey

    def test_parse_invalid_magic(self):
        """Test parsing with invalid magic."""
        parser = TVFSParser()

        # Create data with invalid magic
        data = struct.pack(">4sBBBBIII", b"INVALID", 1, 0x07, 2, 0, 1, 0, 0)

        with pytest.raises(ValueError, match="Invalid magic"):
            parser.parse(data)

    def test_parse_truncated_header(self):
        """Test parsing with truncated header."""
        parser = TVFSParser()

        # Create truncated data (only 10 bytes instead of 20)
        data = b"TVFS123456"

        with pytest.raises(ValueError, match="Invalid header size"):
            parser.parse(data)

    def test_parse_truncated_entry(self):
        """Test parsing with truncated entry."""
        parser = TVFSParser()

        # Create header saying there's 1 entry
        header_data = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 1, 12345)

        # But only provide partial entry data (10 bytes instead of 28)
        partial_entry = b"1234567890"
        data = header_data + partial_entry

        with pytest.raises(ValueError, match="Invalid entry 0 size"):
            parser.parse(data)

    def test_build_empty_file(self):
        """Test building empty TVFS file."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=0,
            max_file_data_id=0,
        )

        tvfs_file = TVFSFile(header=header, entries=[])
        data = parser.build(tvfs_file)

        # Should be exactly 20 bytes (header only)
        assert len(data) == 20

        # Verify header is correct
        expected_header = struct.pack(">4sBBBBIII", b"TVFS", 1, 0x07, 2, 0, 1, 0, 0)
        assert data == expected_header

    def test_build_single_entry(self):
        """Test building TVFS file with single entry."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=1,
            max_file_data_id=12345,
        )

        ckey = b"1234567890123456"
        entry = TVFSEntry(
            ckey=ckey,
            path_hash=0x1111111111111111,
            file_data_id=12345,
        )

        tvfs_file = TVFSFile(header=header, entries=[entry])
        data = parser.build(tvfs_file)

        # Should be 48 bytes (20 header + 28 entry)
        assert len(data) == 48

        # Verify we can parse it back
        parsed = parser.parse(data)
        assert len(parsed.entries) == 1
        assert parsed.entries[0].ckey == ckey

    def test_build_multiple_entries(self):
        """Test building TVFS file with multiple entries."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=2,
            max_file_data_id=20000,
        )

        entries = [
            TVFSEntry(
                ckey=b"1111111111111111",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"2222222222222222",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
        ]

        tvfs_file = TVFSFile(header=header, entries=entries)
        data = parser.build(tvfs_file)

        # Should be 76 bytes (20 header + 2 * 28 entries)
        assert len(data) == 76

        # Verify we can parse it back
        parsed = parser.parse(data)
        assert len(parsed.entries) == 2
        assert parsed.entries[0].file_data_id == 10000
        assert parsed.entries[1].file_data_id == 20000

    def test_build_invalid_content_key(self):
        """Test building with invalid content key length."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=1,
            max_file_data_id=12345,
        )

        # Create entry with invalid content key (only 10 bytes instead of 16)
        entry = TVFSEntry(
            ckey=b"1234567890",  # Too short
            path_hash=0x1111111111111111,
            file_data_id=12345,
        )

        tvfs_file = TVFSFile(header=header, entries=[entry])

        with pytest.raises(ValueError, match="content key must be 16 bytes"):
            parser.build(tvfs_file)

    def test_round_trip_parsing(self):
        """Test round-trip parsing: parse → build → parse."""
        parser = TVFSParser()

        # Create original data
        original_entries = [
            TVFSEntry(
                ckey=b"1111111111111111",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"2222222222222222",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
            TVFSEntry(
                ckey=b"3333333333333333",
                path_hash=0x3333333333333333,
                file_data_id=30000,
            ),
        ]

        original_header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=3,
            max_file_data_id=30000,
        )

        original_file = TVFSFile(header=original_header, entries=original_entries)

        # Build → Parse → Build
        data1 = parser.build(original_file)
        parsed_file = parser.parse(data1)
        data2 = parser.build(parsed_file)

        # Data should be identical
        assert data1 == data2

        # Parsed file should match original
        assert parsed_file.header.magic == original_header.magic
        assert parsed_file.header.version == original_header.version
        assert parsed_file.header.entry_count == original_header.entry_count
        assert len(parsed_file.entries) == len(original_entries)

        for original, parsed in zip(original_entries, parsed_file.entries, strict=True):
            assert original.ckey == parsed.ckey
            assert original.path_hash == parsed.path_hash
            assert original.file_data_id == parsed.file_data_id

    def test_validate_good_data(self):
        """Test validating good TVFS data."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=1,
            max_file_data_id=12345,
        )

        entry = TVFSEntry(
            ckey=b"1234567890123456",
            path_hash=0x1111111111111111,
            file_data_id=12345,
        )

        tvfs_file = TVFSFile(header=header, entries=[entry])
        data = parser.build(tvfs_file)

        is_valid, message = parser.validate(data)
        assert is_valid
        assert message == "Valid"

    def test_validate_bad_data(self):
        """Test validating bad TVFS data."""
        parser = TVFSParser()

        # Create invalid data (wrong magic, but correct length)
        data = struct.pack(">4sBBBBIII", b"INVD", 1, 0x07, 2, 0, 1, 0, 0)

        is_valid, message = parser.validate(data)
        assert not is_valid
        assert "Invalid magic" in message

    def test_calculate_path_hash(self):
        """Test path hash calculation (placeholder implementation)."""
        parser = TVFSParser()

        # Test basic functionality
        hash1 = parser.calculate_path_hash("test/path")
        hash2 = parser.calculate_path_hash("test/path")
        hash3 = parser.calculate_path_hash("different/path")

        # Same path should give same hash
        assert hash1 == hash2

        # Different paths should give different hashes (with high probability)
        assert hash1 != hash3

        # Should return 64-bit integers
        assert isinstance(hash1, int)
        assert 0 <= hash1 <= 0xFFFFFFFFFFFFFFFF

    def test_find_entries_by_path_hash(self):
        """Test finding entries by path hash helper method."""
        parser = TVFSParser()

        entries = [
            TVFSEntry(
                ckey=b"1111111111111111",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"2222222222222222",
                path_hash=0x1111111111111111,  # Same hash
                file_data_id=20000,
            ),
            TVFSEntry(
                ckey=b"3333333333333333",
                path_hash=0x2222222222222222,  # Different hash
                file_data_id=30000,
            ),
        ]

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=0,
            block_count=1,
            entry_count=3,
            max_file_data_id=30000,
        )

        tvfs_file = TVFSFile(header=header, entries=entries)

        # Test finding multiple entries with same hash
        matching = parser.find_entries_by_path_hash(tvfs_file, 0x1111111111111111)
        assert len(matching) == 2
        assert all(e.path_hash == 0x1111111111111111 for e in matching)

    def test_find_entry_by_file_data_id(self):
        """Test finding entry by file data ID helper method."""
        parser = TVFSParser()

        entries = [
            TVFSEntry(
                ckey=b"1111111111111111",
                path_hash=0x1111111111111111,
                file_data_id=10000,
            ),
            TVFSEntry(
                ckey=b"2222222222222222",
                path_hash=0x2222222222222222,
                file_data_id=20000,
            ),
        ]

        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0,
            data_version=0,
            block_count=1,
            entry_count=2,
            max_file_data_id=20000,
        )

        tvfs_file = TVFSFile(header=header, entries=entries)

        # Test finding existing entry
        entry = parser.find_entry_by_file_data_id(tvfs_file, 10000)
        assert entry is not None
        assert entry.file_data_id == 10000
        assert entry.ckey == b"1111111111111111"

        # Test not finding entry
        entry = parser.find_entry_by_file_data_id(tvfs_file, 99999)
        assert entry is None


class TestTVFSEdgeCases:
    """Test edge cases and error conditions."""

    def test_large_entries(self):
        """Test handling large number of entries."""
        parser = TVFSParser()

        # Create file with 1000 entries
        num_entries = 1000
        header = TVFSHeader(
            magic=b"TVFS",
            version=1,
            flags=0x07,
            data_version=2,
            reserved=0,
            block_count=1,
            entry_count=num_entries,
            max_file_data_id=num_entries - 1,
        )

        entries = []
        for i in range(num_entries):
            # Create proper 16-byte content key
            ckey = f"{i:016d}".encode()[:16].ljust(16, b'\x00')
            entries.append(
                TVFSEntry(
                    ckey=ckey,
                    path_hash=(i * 0x1111111111111111) & 0xFFFFFFFFFFFFFFFF,
                    file_data_id=i,
                )
            )

        tvfs_file = TVFSFile(header=header, entries=entries)
        data = parser.build(tvfs_file)

        # Should be able to parse it back
        parsed = parser.parse(data)
        assert len(parsed.entries) == num_entries
        assert parsed.entries[500].file_data_id == 500

    def test_max_values(self):
        """Test with maximum values."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=255,  # Max uint8
            flags=255,  # Max uint8 (not uint32)
            data_version=255,  # Max uint8
            reserved=255,  # Max uint8
            block_count=0xFFFFFFFF,  # Max uint32
            entry_count=1,
            max_file_data_id=0xFFFFFFFF,  # Max uint32
        )

        entry = TVFSEntry(
            ckey=b"\xFF" * 16,  # All 0xFF bytes
            path_hash=0xFFFFFFFFFFFFFFFF,  # Max uint64
            file_data_id=0xFFFFFFFF,  # Max uint32
        )

        tvfs_file = TVFSFile(header=header, entries=[entry])
        data = parser.build(tvfs_file)

        # Should be able to parse it back
        parsed = parser.parse(data)
        assert parsed.header.version == 255
        assert parsed.entries[0].path_hash == 0xFFFFFFFFFFFFFFFF

    def test_zero_values(self):
        """Test with zero values."""
        parser = TVFSParser()

        header = TVFSHeader(
            magic=b"TVFS",
            version=0,
            flags=0,
            data_version=0,
            reserved=0,
            block_count=0,
            entry_count=1,
            max_file_data_id=0,
        )

        entry = TVFSEntry(
            ckey=b"\x00" * 16,  # All zero bytes
            path_hash=0,
            file_data_id=0,
        )

        tvfs_file = TVFSFile(header=header, entries=[entry])
        data = parser.build(tvfs_file)

        # Should be able to parse it back
        parsed = parser.parse(data)
        assert parsed.header.version == 0
        assert parsed.entries[0].path_hash == 0
        assert parsed.entries[0].ckey == b"\x00" * 16
