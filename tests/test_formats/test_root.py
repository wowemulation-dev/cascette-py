"""Tests for root format parser."""

import struct
from io import BytesIO

from cascette_tools.formats.root import (
    RootBlock,
    RootBuilder,
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
        # MFST + large value (>= 1000) - MFST uses big-endian header fields
        data = b'MFST' + struct.pack('>I', 5000) + struct.pack('>I', 2000)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 2

    def test_detect_version_v3(self):
        """Test version detection for v3."""
        # MFST + small header_size + version=3 - MFST uses big-endian
        data = b'MFST' + struct.pack('>I', 24) + struct.pack('>I', 3)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 3

    def test_detect_version_v4(self):
        """Test version detection for v4."""
        # MFST + small header_size + version=4 - MFST uses big-endian
        data = b'MFST' + struct.pack('>I', 24) + struct.pack('>I', 4)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 4

    def test_detect_version_small_v2_not_misidentified(self):
        """Test that a v2 file with small total_files is not misidentified as v3+.

        Regression test: the old heuristic (value1 < 1000) would classify
        a v2 file with fewer than 1000 total files as v3.
        """
        # MFST + total_files=42, named_files=5 - MFST uses big-endian
        # value2=5 is NOT in (2,3,4) so this stays v2
        data = b'MFST' + struct.pack('>I', 42) + struct.pack('>I', 5)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 2

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
        # Create v2 data - MFST uses big-endian header fields
        root_data = BytesIO()
        root_data.write(b'MFST')  # magic
        root_data.write(struct.pack('>I', 5000))  # total_files (large value for v2)
        root_data.write(struct.pack('>I', 3000))  # named_files

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
        # Create v3 data - MFST uses big-endian header fields
        root_data = BytesIO()
        root_data.write(b'MFST')  # magic
        root_data.write(struct.pack('>I', 24))  # header_size (small value for v3)
        root_data.write(struct.pack('>I', 3))   # version_field
        root_data.write(struct.pack('>I', 8000))  # total_files
        root_data.write(struct.pack('>I', 6000))  # named_files
        root_data.write(struct.pack('>I', 0))   # padding

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

    def test_parse_header_v4(self):
        """Test parsing v4 header."""
        # MFST uses big-endian header fields; block data remains little-endian
        root_data = BytesIO()
        root_data.write(b'MFST')  # magic
        root_data.write(struct.pack('>I', 24))   # header_size
        root_data.write(struct.pack('>I', 4))    # version_field
        root_data.write(struct.pack('>I', 10000))  # total_files
        root_data.write(struct.pack('>I', 8000))  # named_files
        root_data.write(struct.pack('>I', 0))    # padding

        # Add a block with 5-byte content flags (V4) - block data is always LE
        root_data.write(struct.pack('<I', 1))    # num_records
        # 5-byte content flags (40-bit little-endian)
        root_data.write(b'\x01\x00\x00\x00\x01')  # flags = 0x0100000001
        root_data.write(struct.pack('<I', 0x02))  # locale_flags
        root_data.write(struct.pack('<i', 500))  # file_id delta
        root_data.write(b'\xAA' * 16)            # content_key
        root_data.write(struct.pack('<Q', 0x1234567890abcdef))  # name_hash

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert root_file.header.version == 4
        assert root_file.header.magic == b'MFST'
        assert root_file.header.header_size == 24
        assert root_file.header.version_field == 4
        assert root_file.header.total_files == 10000
        assert root_file.header.named_files == 8000

        assert len(root_file.blocks) == 1
        assert root_file.blocks[0].content_flags == 0x0100000001
        assert root_file.blocks[0].records[0].file_id == 500

    def test_round_trip_v4(self):
        """Test round-trip parsing and building for v4 with 5-byte content flags."""
        header = RootHeader(
            version=4,
            magic=b'MFST',
            header_size=24,
            version_field=4,
            total_files=1,
            named_files=1,
            padding=0
        )

        record = RootRecord(file_id=100, content_key=b'\xBB' * 16, name_hash=0xDEAD)
        block = RootBlock(
            num_records=1,
            content_flags=0x0100000001,  # 40-bit flag
            locale_flags=0x02,
            records=[record]
        )
        root_file = RootFile(header=header, blocks=[block])

        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed_file = parser.parse(binary_data)

        assert parsed_file.header.version == 4
        assert len(parsed_file.blocks) == 1
        assert parsed_file.blocks[0].content_flags == 0x0100000001
        assert parsed_file.blocks[0].records[0].file_id == 100

    def test_format_content_flags_v4_wide(self):
        """Test formatting of 40-bit content flags."""
        # Flags exceeding 32 bits should use wider hex format
        formatted = format_content_flags(0x0100000001)
        assert "LoadOnWindows" in formatted
        assert "0x0100000001" in formatted

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


class TestRootEmptyBlocks:
    """Test empty block handling (backported from cascette-rs dda8ead)."""

    def test_empty_block_skipped_v1(self):
        """Test that empty blocks (num_records=0) are skipped, not treated as EOF."""
        root_data = BytesIO()

        # First block: empty (should be skipped)
        root_data.write(struct.pack('<I', 0))    # num_records = 0
        root_data.write(struct.pack('<I', 0x00)) # content_flags
        root_data.write(struct.pack('<I', 0x00)) # locale_flags

        # Second block: has data (should be parsed)
        root_data.write(struct.pack('<I', 1))    # num_records
        root_data.write(struct.pack('<I', 0x01)) # content_flags
        root_data.write(struct.pack('<I', 0x02)) # locale_flags
        root_data.write(struct.pack('<i', 42))   # file_id delta
        root_data.write(b'\xAB' * 16)            # content_key
        root_data.write(struct.pack('<Q', 0xDEAD))  # name_hash

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert len(root_file.blocks) == 1
        assert root_file.blocks[0].records[0].file_id == 42

    def test_multiple_empty_blocks_skipped(self):
        """Test that multiple consecutive empty blocks are all skipped."""
        root_data = BytesIO()

        # Two empty blocks
        for _ in range(2):
            root_data.write(struct.pack('<I', 0))    # num_records = 0
            root_data.write(struct.pack('<I', 0x00)) # content_flags
            root_data.write(struct.pack('<I', 0x00)) # locale_flags

        # Real block
        root_data.write(struct.pack('<I', 1))
        root_data.write(struct.pack('<I', 0x01))
        root_data.write(struct.pack('<I', 0x02))
        root_data.write(struct.pack('<i', 99))
        root_data.write(b'\xCC' * 16)
        root_data.write(struct.pack('<Q', 0xBEEF))

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert len(root_file.blocks) == 1
        assert root_file.blocks[0].records[0].file_id == 99

    def test_empty_block_between_real_blocks(self):
        """Test that an empty block between two real blocks is skipped."""
        root_data = BytesIO()

        # First real block
        root_data.write(struct.pack('<I', 1))
        root_data.write(struct.pack('<I', 0x01))
        root_data.write(struct.pack('<I', 0x02))
        root_data.write(struct.pack('<i', 10))
        root_data.write(b'\x11' * 16)
        root_data.write(struct.pack('<Q', 0x1111))

        # Empty block (should be skipped)
        root_data.write(struct.pack('<I', 0))
        root_data.write(struct.pack('<I', 0x00))
        root_data.write(struct.pack('<I', 0x00))

        # Second real block
        root_data.write(struct.pack('<I', 1))
        root_data.write(struct.pack('<I', 0x04))
        root_data.write(struct.pack('<I', 0x08))
        root_data.write(struct.pack('<i', 20))
        root_data.write(b'\x22' * 16)
        root_data.write(struct.pack('<Q', 0x2222))

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert len(root_file.blocks) == 2
        assert root_file.blocks[0].records[0].file_id == 10
        assert root_file.blocks[1].records[0].file_id == 20


class TestRootEndianness:
    """Test endianness-aware header I/O (backported from cascette-rs dda8ead).

    MFST magic = big-endian header fields.
    TSFM magic = little-endian header fields.
    Block data always uses little-endian regardless of header magic.
    """

    def test_mfst_v2_round_trip(self):
        """Test MFST (big-endian) v2 header round-trip."""
        header = RootHeader(version=2, magic=b'MFST', total_files=1000, named_files=800)
        record = RootRecord(file_id=456, content_key=b'\x07' * 16, name_hash=0x123456)
        block = RootBlock(num_records=1, content_flags=0x08, locale_flags=0x10, records=[record])
        root_file = RootFile(header=header, blocks=[block])

        parser = RootParser()
        binary_data = parser.build(root_file)

        # Verify MFST magic at start
        assert binary_data[:4] == b'MFST'
        # Verify big-endian header fields
        assert struct.unpack('>I', binary_data[4:8])[0] == 1000
        assert struct.unpack('>I', binary_data[8:12])[0] == 800

        # Parse back and verify
        parsed = parser.parse(binary_data)
        assert parsed.header.version == 2
        assert parsed.header.magic == b'MFST'
        assert parsed.header.total_files == 1000
        assert parsed.header.named_files == 800
        assert len(parsed.blocks) == 1
        assert parsed.blocks[0].records[0].file_id == 456

    def test_tsfm_v2_round_trip(self):
        """Test TSFM (little-endian) v2 header round-trip."""
        header = RootHeader(version=2, magic=b'TSFM', total_files=1000, named_files=800)
        record = RootRecord(file_id=456, content_key=b'\x07' * 16, name_hash=0x123456)
        block = RootBlock(num_records=1, content_flags=0x08, locale_flags=0x10, records=[record])
        root_file = RootFile(header=header, blocks=[block])

        parser = RootParser()
        binary_data = parser.build(root_file)

        # Verify TSFM magic at start
        assert binary_data[:4] == b'TSFM'
        # Verify little-endian header fields
        assert struct.unpack('<I', binary_data[4:8])[0] == 1000
        assert struct.unpack('<I', binary_data[8:12])[0] == 800

        # Parse back and verify
        parsed = parser.parse(binary_data)
        assert parsed.header.version == 2
        assert parsed.header.magic == b'TSFM'
        assert parsed.header.total_files == 1000
        assert parsed.header.named_files == 800

    def test_mfst_v3_round_trip(self):
        """Test MFST (big-endian) v3 header round-trip."""
        header = RootHeader(
            version=3, magic=b'MFST', header_size=24,
            version_field=3, total_files=5000, named_files=4000, padding=0
        )
        record = RootRecord(file_id=100, content_key=b'\xAA' * 16, name_hash=0xDEAD)
        block = RootBlock(num_records=1, content_flags=0x01, locale_flags=0x02, records=[record])
        root_file = RootFile(header=header, blocks=[block])

        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed = parser.parse(binary_data)

        assert parsed.header.version == 3
        assert parsed.header.magic == b'MFST'
        assert parsed.header.header_size == 24
        assert parsed.header.total_files == 5000
        assert parsed.header.named_files == 4000

    def test_tsfm_v3_round_trip(self):
        """Test TSFM (little-endian) v3 header round-trip."""
        header = RootHeader(
            version=3, magic=b'TSFM', header_size=24,
            version_field=3, total_files=5000, named_files=4000, padding=0
        )
        record = RootRecord(file_id=100, content_key=b'\xBB' * 16, name_hash=0xBEEF)
        block = RootBlock(num_records=1, content_flags=0x01, locale_flags=0x02, records=[record])
        root_file = RootFile(header=header, blocks=[block])

        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed = parser.parse(binary_data)

        assert parsed.header.version == 3
        assert parsed.header.magic == b'TSFM'
        assert parsed.header.total_files == 5000

    def test_detect_version_tsfm_v3(self):
        """Test version detection with TSFM (little-endian) magic."""
        data = b'TSFM' + struct.pack('<I', 24) + struct.pack('<I', 3)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 3

    def test_detect_version_tsfm_v2(self):
        """Test version detection with TSFM (little-endian) v2."""
        data = b'TSFM' + struct.pack('<I', 5000) + struct.pack('<I', 2000)

        parser = RootParser()
        version = parser._detect_version(data)
        assert version == 2

    def test_parse_tsfm_v2_manual(self):
        """Test parsing manually constructed TSFM v2 data."""
        root_data = BytesIO()
        root_data.write(b'TSFM')
        root_data.write(struct.pack('<I', 3000))  # total_files (LE for TSFM)
        root_data.write(struct.pack('<I', 2000))  # named_files (LE for TSFM)

        # Block data (always LE)
        root_data.write(struct.pack('<I', 1))
        root_data.write(struct.pack('<I', 0x01))
        root_data.write(struct.pack('<I', 0x02))
        root_data.write(struct.pack('<i', 77))
        root_data.write(b'\xDD' * 16)
        root_data.write(struct.pack('<Q', 0xCAFE))

        parser = RootParser()
        root_file = parser.parse(root_data.getvalue())

        assert root_file.header.magic == b'TSFM'
        assert root_file.header.total_files == 3000
        assert root_file.header.named_files == 2000
        assert root_file.blocks[0].records[0].file_id == 77


class TestRootBuilderDefaults:
    """Test RootBuilder default magic (backported from cascette-rs dda8ead)."""

    def test_create_empty_v2_defaults_to_mfst(self):
        """Test that create_empty v2 defaults to MFST magic."""
        root_file = RootBuilder.create_empty(version=2)
        assert root_file.header.magic == b'MFST'

    def test_create_empty_v3_defaults_to_mfst(self):
        """Test that create_empty v3 defaults to MFST magic."""
        root_file = RootBuilder.create_empty(version=3)
        assert root_file.header.magic == b'MFST'

    def test_create_empty_v4_defaults_to_mfst(self):
        """Test that create_empty v4 defaults to MFST magic."""
        root_file = RootBuilder.create_empty(version=4)
        assert root_file.header.magic == b'MFST'

    def test_create_with_records_v2_defaults_to_mfst(self):
        """Test that create_with_records v2 defaults to MFST magic."""
        records = [RootRecord(file_id=1, content_key=b'\x01' * 16, name_hash=0x1234)]
        root_file = RootBuilder.create_with_records(records, version=2)
        assert root_file.header.magic == b'MFST'

    def test_create_with_records_v3_defaults_to_mfst(self):
        """Test that create_with_records v3 defaults to MFST magic."""
        records = [RootRecord(file_id=1, content_key=b'\x01' * 16, name_hash=0x1234)]
        root_file = RootBuilder.create_with_records(records, version=3)
        assert root_file.header.magic == b'MFST'

    def test_builder_round_trip_mfst(self):
        """Test that builder-created MFST files round-trip correctly."""
        records = [
            RootRecord(file_id=100, content_key=b'\xAA' * 16, name_hash=0xDEAD),
            RootRecord(file_id=200, content_key=b'\xBB' * 16, name_hash=0xBEEF),
        ]
        root_file = RootBuilder.create_with_records(records, version=2)

        parser = RootParser()
        binary_data = parser.build(root_file)
        parsed = parser.parse(binary_data)

        assert parsed.header.magic == b'MFST'
        assert parsed.header.total_files == 2
        assert len(parsed.blocks) == 1
        assert parsed.blocks[0].records[0].file_id == 100
        assert parsed.blocks[0].records[1].file_id == 200
