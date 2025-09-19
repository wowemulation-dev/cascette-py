"""Tests for root format parser."""

import struct
from io import BytesIO

from cascette_tools.formats.root import (
    RootBlock,
    RootFile,
    RootHeader,
    RootParser,
    RootRecord,
    format_content_flags,
    format_locale_flags,
    is_root,
)


class TestRootParser:
    """Test root format parser."""

    def test_is_root_function(self):
        """Test is_root detection function."""
        # Valid root data with MFST magic
        assert is_root(b'MFST\x00\x00\x00\x00')
        assert is_root(b'TSFM\x00\x00\x00\x00')

        # Data without magic (might be v1)
        assert is_root(b'\x01\x00\x00\x00\x02\x00\x00\x00')

        # Too short
        assert not is_root(b'MF')
        assert not is_root(b'')

    def test_detect_version_v1(self):
        """Test version detection for v1 (no magic)."""
        data = b'\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'  # No MFST magic

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 1

    def test_detect_version_v2(self):
        """Test version detection for v2."""
        # MFST + large value (>= 1000)
        data = b'MFST' + struct.pack('<I', 5000) + struct.pack('<I', 2000)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 2

    def test_detect_version_v3(self):
        """Test version detection for v3."""
        # MFST + small value (< 1000, likely header_size)
        data = b'MFST' + struct.pack('<I', 24) + struct.pack('<I', 3)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 3

    def test_parse_header_v1(self):
        """Test parsing v1 header (no header)."""
        # Create v1 data (no magic)
        root_data = BytesIO()
        root_data.write(struct.pack('<I', 2))  # num_records
        root_data.write(struct.pack('<I', 0x01))  # content_flags
        root_data.write(struct.pack('<I', 0x02))  # locale_flags

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert root_file.header.version == 1
        assert root_file.header.magic is None
        assert root_file.header.total_files is None
        assert root_file.header.named_files is None

    def test_parse_header_v2(self):
        """Test parsing v2 header."""
        # Create v2 data
        root_data = BytesIO()
        root_data.write(b'MFST')  # magic
        root_data.write(struct.pack('<I', 5000))  # total_files (large value for v2)
        root_data.write(struct.pack('<I', 3000))  # named_files

        # Add minimal block to complete parsing
        root_data.write(struct.pack('<I', 0))  # Empty block to terminate

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert root_file.header.version == 2
        assert root_file.header.magic == b'MFST'
        assert root_file.header.total_files == 5000
        assert root_file.header.named_files == 3000
        assert root_file.header.header_size is None
        assert root_file.header.version_field is None

    def test_parse_header_v3(self):
        """Test parsing v3 header."""
        # Create v3 data
        root_data = BytesIO()
        root_data.write(b'MFST')  # magic
        root_data.write(struct.pack('<I', 24))  # header_size (small value for v3)
        root_data.write(struct.pack('<I', 3))   # version_field
        root_data.write(struct.pack('<I', 8000))  # total_files
        root_data.write(struct.pack('<I', 6000))  # named_files
        root_data.write(struct.pack('<I', 0))   # padding

        # Add minimal block to complete parsing
        root_data.write(struct.pack('<I', 0))  # Empty block to terminate

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert root_file.header.version == 3
        assert root_file.header.magic == b'MFST'
        assert root_file.header.header_size == 24
        assert root_file.header.version_field == 3
        assert root_file.header.total_files == 8000
        assert root_file.header.named_files == 6000
        assert root_file.header.padding == 0

    def test_parse_single_block(self):
        """Test parsing a single root block."""
        # Create test data with one block containing two records
        file_ids = [100, 102]  # FileDataIDs
        content_keys = [b'\x01' * 16, b'\x02' * 16]
        name_hashes = [0x1234567890abcdef, 0xfedcba0987654321]

        # Calculate deltas
        deltas = [file_ids[0], file_ids[1] - file_ids[0] - 1]

        root_data = BytesIO()
        # No header (v1)

        # Block header
        root_data.write(struct.pack('<I', 2))    # num_records
        root_data.write(struct.pack('<I', 0x01)) # content_flags
        root_data.write(struct.pack('<I', 0x02)) # locale_flags

        # FileDataID deltas
        for delta in deltas:
            root_data.write(struct.pack('<i', delta))

        # Records
        for i in range(2):
            root_data.write(content_keys[i])     # content_key
            root_data.write(struct.pack('<Q', name_hashes[i]))  # name_hash

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        # Verify parsing
        assert len(root_file.blocks) == 1
        block = root_file.blocks[0]

        assert block.num_records == 2
        assert block.content_flags == 0x01
        assert block.locale_flags == 0x02
        assert len(block.records) == 2

        # Verify records
        for i, record in enumerate(block.records):
            assert record.file_id == file_ids[i]
            assert record.content_key == content_keys[i]
            assert record.name_hash == name_hashes[i]

    def test_parse_multiple_blocks(self):
        """Test parsing multiple root blocks."""
        root_data = BytesIO()
        # No header (v1)

        # First block
        root_data.write(struct.pack('<I', 1))    # num_records
        root_data.write(struct.pack('<I', 0x01)) # content_flags
        root_data.write(struct.pack('<I', 0x02)) # locale_flags
        root_data.write(struct.pack('<i', 200))  # file_id delta
        root_data.write(b'\x03' * 16)            # content_key
        root_data.write(struct.pack('<Q', 0x1111111111111111))  # name_hash

        # Second block
        root_data.write(struct.pack('<I', 1))    # num_records
        root_data.write(struct.pack('<I', 0x04)) # content_flags
        root_data.write(struct.pack('<I', 0x08)) # locale_flags
        root_data.write(struct.pack('<i', 300))  # file_id delta
        root_data.write(b'\x06' * 16)            # content_key
        root_data.write(struct.pack('<Q', 0x2222222222222222))  # name_hash

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        # Verify parsing
        assert len(root_file.blocks) == 2

        # First block
        block1 = root_file.blocks[0]
        assert block1.num_records == 1
        assert block1.content_flags == 0x01
        assert block1.locale_flags == 0x02
        assert len(block1.records) == 1
        assert block1.records[0].file_id == 200
        assert block1.records[0].content_key == b'\x03' * 16

        # Second block
        block2 = root_file.blocks[1]
        assert block2.num_records == 1
        assert block2.content_flags == 0x04
        assert block2.locale_flags == 0x08
        assert len(block2.records) == 1
        assert block2.records[0].file_id == 300
        assert block2.records[0].content_key == b'\x06' * 16

    def test_find_file_by_id(self):
        """Test finding file by FileDataID."""
        # Create root file with test data
        record1 = RootRecord(file_id=100, content_key=b'\x01' * 16, name_hash=0x1111)
        record2 = RootRecord(file_id=200, content_key=b'\x02' * 16, name_hash=0x2222)

        block = RootBlock(
            num_records=2,
            content_flags=0x01,
            locale_flags=0x02,
            records=[record1, record2]
        )

        root_file = RootFile(
            header=RootHeader(version=1),
            blocks=[block]
        )

        parser = RootParser()

        # Find existing file
        found = parser.find_file_by_id(root_file, 100)
        assert found is not None
        assert found.file_id == 100
        assert found.content_key == b'\x01' * 16

        # Find non-existent file
        not_found = parser.find_file_by_id(root_file, 999)
        assert not_found is None

    def test_find_files_by_content_key(self):
        """Test finding files by content key."""
        # Create root file with duplicate content key
        record1 = RootRecord(file_id=100, content_key=b'\x01' * 16, name_hash=0x1111)
        record2 = RootRecord(file_id=200, content_key=b'\x01' * 16, name_hash=0x2222)  # Same content key
        record3 = RootRecord(file_id=300, content_key=b'\x02' * 16, name_hash=0x3333)

        block = RootBlock(
            num_records=3,
            content_flags=0x01,
            locale_flags=0x02,
            records=[record1, record2, record3]
        )

        root_file = RootFile(
            header=RootHeader(version=1),
            blocks=[block]
        )

        parser = RootParser()

        # Find files with duplicate content key
        found = parser.find_files_by_content_key(root_file, b'\x01' * 16)
        assert len(found) == 2
        assert found[0].file_id == 100
        assert found[1].file_id == 200

        # Find unique content key
        found_unique = parser.find_files_by_content_key(root_file, b'\x02' * 16)
        assert len(found_unique) == 1
        assert found_unique[0].file_id == 300

        # Find non-existent content key
        not_found = parser.find_files_by_content_key(root_file, b'\x99' * 16)
        assert len(not_found) == 0

    def test_get_statistics(self):
        """Test getting root file statistics."""
        # Create root file with multiple blocks
        block1 = RootBlock(
            num_records=2,
            content_flags=0x01,
            locale_flags=0x02,
            records=[
                RootRecord(file_id=100, content_key=b'\x01' * 16, name_hash=0x1111),
                RootRecord(file_id=200, content_key=b'\x02' * 16, name_hash=0x2222)
            ]
        )

        block2 = RootBlock(
            num_records=1,
            content_flags=0x04,
            locale_flags=0x02,  # Same locale as block1
            records=[
                RootRecord(file_id=300, content_key=b'\x03' * 16, name_hash=0x3333)
            ]
        )

        root_file = RootFile(
            header=RootHeader(version=1),
            blocks=[block1, block2]
        )

        parser = RootParser()
        stats = parser.get_statistics(root_file)

        assert stats['total_files'] == 3
        assert stats['total_blocks'] == 2
        assert stats['unique_flag_combinations'] == 2  # (0x01, 0x02) and (0x04, 0x02)
        assert stats['files_per_locale'][0x02] == 3  # All files have locale 0x02

    def test_round_trip_v1(self):
        """Test round-trip parsing and building for v1."""
        # Create original data
        record = RootRecord(file_id=123, content_key=b'\x05' * 16, name_hash=0xabcdef)
        block = RootBlock(
            num_records=1,
            content_flags=0x01,
            locale_flags=0x02,
            records=[record]
        )
        root_file = RootFile(
            header=RootHeader(version=1),
            blocks=[block]
        )

        # Build and parse back
        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed_file = parser.parse(binary_data)

        # Verify round trip
        assert parsed_file.header.version == root_file.header.version
        assert len(parsed_file.blocks) == 1

        parsed_block = parsed_file.blocks[0]
        original_block = root_file.blocks[0]

        assert parsed_block.num_records == original_block.num_records
        assert parsed_block.content_flags == original_block.content_flags
        assert parsed_block.locale_flags == original_block.locale_flags
        assert len(parsed_block.records) == 1

        parsed_record = parsed_block.records[0]
        original_record = original_block.records[0]

        assert parsed_record.file_id == original_record.file_id
        assert parsed_record.content_key == original_record.content_key
        assert parsed_record.name_hash == original_record.name_hash

    def test_round_trip_v2(self):
        """Test round-trip parsing and building for v2."""
        # Create v2 root file
        header = RootHeader(
            version=2,
            magic=b'MFST',
            total_files=1000,
            named_files=800
        )

        record = RootRecord(file_id=456, content_key=b'\x07' * 16, name_hash=0x123456)
        block = RootBlock(
            num_records=1,
            content_flags=0x08,
            locale_flags=0x10,
            records=[record]
        )

        root_file = RootFile(header=header, blocks=[block])

        # Build and parse back
        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed_file = parser.parse(binary_data)

        # Verify round trip
        assert parsed_file.header.version == 2
        assert parsed_file.header.magic == b'MFST'
        assert parsed_file.header.total_files == 1000
        assert parsed_file.header.named_files == 800

    def test_invalid_block_num_records(self):
        """Test error handling for invalid num_records."""
        # Create data with excessive num_records
        root_data = BytesIO()
        root_data.write(struct.pack('<I', 2000000))  # Too many records
        root_data.write(struct.pack('<I', 0x01))     # content_flags
        root_data.write(struct.pack('<I', 0x02))     # locale_flags

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        # Should have no blocks due to sanity check
        assert len(root_file.blocks) == 0

    def test_incomplete_block_data(self):
        """Test handling of incomplete block data."""
        # Create data with incomplete block
        root_data = BytesIO()
        root_data.write(struct.pack('<I', 1))    # num_records
        root_data.write(struct.pack('<I', 0x01)) # content_flags
        # Missing locale_flags and rest of data

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        # Should have no blocks due to incomplete data
        assert len(root_file.blocks) == 0

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        # Create test root file
        root_data = BytesIO()
        root_data.write(struct.pack('<I', 1))    # num_records
        root_data.write(struct.pack('<I', 0x01)) # content_flags
        root_data.write(struct.pack('<I', 0x02)) # locale_flags
        root_data.write(struct.pack('<i', 789))  # file_id delta
        root_data.write(b'\x09' * 16)            # content_key
        root_data.write(struct.pack('<Q', 0x987654321))  # name_hash

        test_file = tmp_path / "test.root"
        test_file.write_bytes(root_data.getvalue())

        # Parse from file
        parser = RootParser()
        root_file = parser.parse_file(str(test_file))

        assert root_file.header.version == 1
        assert len(root_file.blocks) == 1
        assert root_file.blocks[0].records[0].file_id == 789


class TestRootFormatting:
    """Test root format utility functions."""

    def test_format_content_flags(self):
        """Test content flags formatting."""
        # No flags
        assert format_content_flags(0) == "None (0x00000000)"

        # Single flag
        assert "LoadOnWindows" in format_content_flags(0x00000001)
        assert "0x00000001" in format_content_flags(0x00000001)

        # Multiple flags
        flags = 0x00000001 | 0x00000002  # LoadOnWindows | LoadOnMacOS
        formatted = format_content_flags(flags)
        assert "LoadOnWindows" in formatted
        assert "LoadOnMacOS" in formatted
        assert "0x00000003" in formatted

        # Encrypted flag
        assert "Encrypted" in format_content_flags(0x00001000)

    def test_format_locale_flags(self):
        """Test locale flags formatting."""
        # No flags
        assert format_locale_flags(0) == "None (0x00000000)"

        # Single locale
        assert "enUS" in format_locale_flags(0x00000002)
        assert "0x00000002" in format_locale_flags(0x00000002)

        # Multiple locales
        flags = 0x00000002 | 0x00000020  # enUS | deDE
        formatted = format_locale_flags(flags)
        assert "enUS" in formatted
        assert "deDE" in formatted
        assert "0x00000022" in formatted

        # Korean locale
        assert "koKR" in format_locale_flags(0x00000004)


class TestRootModels:
    """Test root Pydantic models."""

    def test_root_record_model(self):
        """Test RootRecord model."""
        record = RootRecord(
            file_id=12345,
            content_key=b'\xaa' * 16,
            name_hash=0x1234567890abcdef
        )

        assert record.file_id == 12345
        assert record.content_key == b'\xaa' * 16
        assert record.name_hash == 0x1234567890abcdef

    def test_root_block_model(self):
        """Test RootBlock model."""
        records = [
            RootRecord(file_id=100, content_key=b'\x01' * 16, name_hash=0x1111),
            RootRecord(file_id=200, content_key=b'\x02' * 16, name_hash=0x2222)
        ]

        block = RootBlock(
            num_records=2,
            content_flags=0x01,
            locale_flags=0x02,
            records=records
        )

        assert block.num_records == 2
        assert block.content_flags == 0x01
        assert block.locale_flags == 0x02
        assert len(block.records) == 2
        assert block.records[0].file_id == 100

    def test_root_header_model(self):
        """Test RootHeader model."""
        # Version 1 header
        header_v1 = RootHeader(version=1)
        assert header_v1.version == 1
        assert header_v1.magic is None

        # Version 3 header
        header_v3 = RootHeader(
            version=3,
            magic=b'MFST',
            header_size=24,
            version_field=3,
            total_files=5000,
            named_files=4000,
            padding=0
        )

        assert header_v3.version == 3
        assert header_v3.magic == b'MFST'
        assert header_v3.header_size == 24
        assert header_v3.total_files == 5000

    def test_root_file_model(self):
        """Test complete RootFile model."""
        header = RootHeader(version=1)
        block = RootBlock(
            num_records=1,
            content_flags=0x01,
            locale_flags=0x02,
            records=[RootRecord(file_id=123, content_key=b'\x01' * 16, name_hash=0x1234)]
        )

        root_file = RootFile(header=header, blocks=[block])

        assert root_file.header.version == 1
        assert len(root_file.blocks) == 1
        assert root_file.blocks[0].num_records == 1
