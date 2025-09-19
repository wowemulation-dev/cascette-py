"""Tests for ZBSDIFF1 format parser."""

import struct
import zlib
from io import BytesIO

import pytest

from cascette_tools.formats.zbsdiff import (
    MAX_CONTROL_ENTRIES,
    MAX_FILE_SIZE,
    ZbsdiffControlEntry,
    ZbsdiffFile,
    ZbsdiffHeader,
    ZbsdiffParser,
)


class TestZbsdiffHeader:
    """Test ZBSDIFF1 header model."""

    def test_valid_header(self):
        """Test valid header creation."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=100,
            diff_length=200,
            new_size=1000
        )
        assert header.magic == b"ZBSDIFF1"
        assert header.control_length == 100
        assert header.diff_length == 200
        assert header.new_size == 1000

    def test_invalid_magic(self):
        """Test invalid magic bytes."""
        with pytest.raises(ValueError, match="Invalid ZBSDIFF1 magic"):
            ZbsdiffHeader(
                magic=b"INVALID1",
                control_length=100,
                diff_length=200,
                new_size=1000
            )

    def test_negative_sizes(self):
        """Test negative size validation."""
        with pytest.raises(ValueError, match="Size cannot be negative"):
            ZbsdiffHeader(
                magic=b"ZBSDIFF1",
                control_length=-1,
                diff_length=200,
                new_size=1000
            )

    def test_too_large_sizes(self):
        """Test size too large validation."""
        with pytest.raises(ValueError, match="Size too large"):
            ZbsdiffHeader(
                magic=b"ZBSDIFF1",
                control_length=100,
                diff_length=200,
                new_size=MAX_FILE_SIZE + 1
            )


class TestZbsdiffControlEntry:
    """Test ZBSDIFF1 control entry model."""

    def test_valid_entry(self):
        """Test valid control entry."""
        entry = ZbsdiffControlEntry(
            add_length=10,
            copy_length=20,
            offset=5
        )
        assert entry.add_length == 10
        assert entry.copy_length == 20
        assert entry.offset == 5

    def test_negative_lengths(self):
        """Test negative length validation."""
        with pytest.raises(ValueError, match="Length cannot be negative"):
            ZbsdiffControlEntry(
                add_length=-1,
                copy_length=20,
                offset=5
            )

    def test_negative_offset_allowed(self):
        """Test negative offset is allowed."""
        entry = ZbsdiffControlEntry(
            add_length=10,
            copy_length=20,
            offset=-5
        )
        assert entry.offset == -5


class TestZbsdiffFile:
    """Test ZBSDIFF1 file model."""

    def test_valid_file(self):
        """Test valid file creation."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=100,
            diff_length=200,
            new_size=1000
        )
        entries = [
            ZbsdiffControlEntry(add_length=10, copy_length=20, offset=0),
            ZbsdiffControlEntry(add_length=15, copy_length=25, offset=5)
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"diff data",
            extra_data=b"extra data"
        )

        assert zbsdiff_file.header == header
        assert len(zbsdiff_file.control_entries) == 2
        assert zbsdiff_file.diff_data == b"diff data"
        assert zbsdiff_file.extra_data == b"extra data"

    def test_too_many_control_entries(self):
        """Test validation of too many control entries."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=100,
            diff_length=200,
            new_size=1000
        )

        # Create too many entries
        entries = [
            ZbsdiffControlEntry(add_length=1, copy_length=1, offset=0)
            for _ in range(MAX_CONTROL_ENTRIES + 1)
        ]

        with pytest.raises(ValueError, match="Too many control entries"):
            ZbsdiffFile(
                header=header,
                control_entries=entries,
                diff_data=b"diff",
                extra_data=b"extra"
            )


class TestZbsdiffParser:
    """Test ZBSDIFF1 parser."""

    def create_sample_patch(self) -> bytes:
        """Create a valid sample ZBSDIFF1 patch for testing."""
        # Create control entries
        entries = [
            ZbsdiffControlEntry(add_length=5, copy_length=3, offset=0),
            ZbsdiffControlEntry(add_length=2, copy_length=4, offset=1)
        ]

        # Build control block
        control_data = bytearray()
        for entry in entries:
            control_data.extend(struct.pack("<q", entry.add_length))
            control_data.extend(struct.pack("<q", entry.copy_length))
            control_data.extend(struct.pack("<q", entry.offset))

        # Create diff and extra data
        diff_data = b"diffs"
        extra_data = b"exthello"

        # Compress blocks
        control_compressed = zlib.compress(control_data)
        diff_compressed = zlib.compress(diff_data)
        extra_compressed = zlib.compress(extra_data)

        # Build header
        header_data = (
            b"ZBSDIFF1" +
            struct.pack(">Q", len(control_compressed)) +
            struct.pack(">Q", len(diff_compressed)) +
            struct.pack(">Q", 15)  # new_size
        )

        return header_data + control_compressed + diff_compressed + extra_compressed

    def test_parse_valid_patch(self):
        """Test parsing valid ZBSDIFF1 patch."""
        patch_data = self.create_sample_patch()
        parser = ZbsdiffParser()

        zbsdiff_file = parser.parse(patch_data)

        # Verify header
        assert zbsdiff_file.header.magic == b"ZBSDIFF1"
        assert zbsdiff_file.header.new_size == 15

        # Verify control entries
        assert len(zbsdiff_file.control_entries) == 2
        assert zbsdiff_file.control_entries[0].add_length == 5
        assert zbsdiff_file.control_entries[0].copy_length == 3
        assert zbsdiff_file.control_entries[0].offset == 0

        # Verify data blocks
        assert zbsdiff_file.diff_data == b"diffs"
        assert zbsdiff_file.extra_data == b"exthello"

    def test_parse_from_stream(self):
        """Test parsing from BytesIO stream."""
        patch_data = self.create_sample_patch()
        stream = BytesIO(patch_data)
        parser = ZbsdiffParser()

        zbsdiff_file = parser.parse(stream)
        assert zbsdiff_file.header.magic == b"ZBSDIFF1"

    def test_parse_invalid_magic(self):
        """Test parsing with invalid magic."""
        invalid_data = b"INVALID1" + b"\x00" * 24 + b"dummy"
        parser = ZbsdiffParser()

        with pytest.raises(ValueError, match="Invalid ZBSDIFF1 magic"):
            parser.parse(invalid_data)

    def test_parse_truncated_header(self):
        """Test parsing truncated header."""
        truncated_data = b"ZBSDIFF1" + b"\x00" * 10  # Too short
        parser = ZbsdiffParser()

        with pytest.raises(ValueError, match="Header too short"):
            parser.parse(truncated_data)

    def test_parse_truncated_blocks(self):
        """Test parsing with truncated compressed blocks."""
        # Create header claiming large control block but provide small data
        header_data = (
            b"ZBSDIFF1" +
            struct.pack(">Q", 1000) +  # Claim 1000 bytes
            struct.pack(">Q", 100) +
            struct.pack(">Q", 1000)
        )
        incomplete_data = header_data + b"small"
        parser = ZbsdiffParser()

        with pytest.raises(ValueError, match="Control block too short"):
            parser.parse(incomplete_data)

    def test_parse_invalid_compression(self):
        """Test parsing with invalid zlib compression."""
        # Create header
        header_data = (
            b"ZBSDIFF1" +
            struct.pack(">Q", 5) +
            struct.pack(">Q", 5) +
            struct.pack(">Q", 100)
        )
        # Invalid compressed data
        invalid_data = header_data + b"notok" + b"notok" + b"extra"
        parser = ZbsdiffParser()

        with pytest.raises(ValueError, match="Failed to decompress control block"):
            parser.parse(invalid_data)

    def test_build_valid_patch(self):
        """Test building valid ZBSDIFF1 patch."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,  # Will be updated by build
            diff_length=0,     # Will be updated by build
            new_size=100
        )

        entries = [
            ZbsdiffControlEntry(add_length=10, copy_length=5, offset=2)
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"diff_data",
            extra_data=b"extra_data"
        )

        parser = ZbsdiffParser()
        built_data = parser.build(zbsdiff_file)

        # Verify it starts with magic
        assert built_data.startswith(b"ZBSDIFF1")

        # Parse it back to verify correctness
        reparsed = parser.parse(built_data)
        assert reparsed.header.magic == b"ZBSDIFF1"
        assert reparsed.header.new_size == 100
        assert len(reparsed.control_entries) == 1
        assert reparsed.diff_data == b"diff_data"
        assert reparsed.extra_data == b"extra_data"

    def test_round_trip(self):
        """Test parse -> build -> parse round trip."""
        original_data = self.create_sample_patch()
        parser = ZbsdiffParser()

        # Parse
        zbsdiff_file = parser.parse(original_data)

        # Build
        rebuilt_data = parser.build(zbsdiff_file)

        # Parse again
        reparsed = parser.parse(rebuilt_data)

        # Verify equivalence
        assert reparsed.header.magic == zbsdiff_file.header.magic
        assert reparsed.header.new_size == zbsdiff_file.header.new_size
        assert len(reparsed.control_entries) == len(zbsdiff_file.control_entries)
        assert reparsed.diff_data == zbsdiff_file.diff_data
        assert reparsed.extra_data == zbsdiff_file.extra_data

    def test_apply_patch_simple(self):
        """Test applying a simple patch."""
        # Create a simple patch that adds data
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,
            diff_length=0,
            new_size=8
        )

        # Add 3 bytes from diff, copy 5 bytes from extra
        entries = [
            ZbsdiffControlEntry(add_length=3, copy_length=5, offset=0)
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"\x01\x02\x03",  # Add these to old data
            extra_data=b"hello"          # Copy these to new data
        )

        old_data = b"abc"  # Original data
        parser = ZbsdiffParser()

        new_data = parser.apply_patch(old_data, zbsdiff_file)

        # Expected: (a+1, b+2, c+3) + "hello" = "bddhello"
        expected = bytes([ord('a') + 1, ord('b') + 2, ord('c') + 3]) + b"hello"
        assert new_data == expected

    def test_apply_patch_with_seek(self):
        """Test applying patch with seek offset."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,
            diff_length=0,
            new_size=3
        )

        # Add 2 bytes, then seek forward and add 1 more
        entries = [
            ZbsdiffControlEntry(add_length=2, copy_length=0, offset=0),
            ZbsdiffControlEntry(add_length=1, copy_length=0, offset=1)  # Skip 1 byte
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"\x01\x02\x03",
            extra_data=b""
        )

        old_data = b"abcde"
        parser = ZbsdiffParser()

        new_data = parser.apply_patch(old_data, zbsdiff_file)

        # Expected: (a+1, b+2, c+3) - offset affects position for future operations
        expected = bytes([ord('a') + 1, ord('b') + 2, ord('c') + 3])
        assert new_data == expected

    def test_apply_patch_overflow_protection(self):
        """Test patch application with overflow protection."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,
            diff_length=0,
            new_size=5
        )

        entries = [
            ZbsdiffControlEntry(add_length=10, copy_length=0, offset=0)  # Too much
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"0123456789",
            extra_data=b""
        )

        old_data = b"abc"
        parser = ZbsdiffParser()

        with pytest.raises(ValueError, match="New data overflow"):
            parser.apply_patch(old_data, zbsdiff_file)

    def test_apply_patch_large_file_protection(self):
        """Test patch application rejects overly large files."""
        parser = ZbsdiffParser()

        # Create minimal patch
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,
            diff_length=0,
            new_size=1
        )

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=[],
            diff_data=b"",
            extra_data=b""
        )

        # Try to patch file that's too large
        large_data = b"x" * (MAX_FILE_SIZE + 1)

        with pytest.raises(ValueError, match="Old file too large"):
            parser.apply_patch(large_data, zbsdiff_file)

    def test_validate_method(self):
        """Test validate method."""
        parser = ZbsdiffParser()

        # Valid data
        valid_data = self.create_sample_patch()
        is_valid, message = parser.validate(valid_data)
        assert is_valid
        assert message == "Valid"

        # Invalid data
        invalid_data = b"invalid"
        is_valid, message = parser.validate(invalid_data)
        assert not is_valid
        assert "Header too short" in message

    def test_empty_patch(self):
        """Test parsing patch with no operations."""
        # Create header with no operations
        header_data = (
            b"ZBSDIFF1" +
            struct.pack(">Q", len(zlib.compress(b""))) +  # Empty control
            struct.pack(">Q", len(zlib.compress(b""))) +  # Empty diff
            struct.pack(">Q", 0)  # Empty new size
        )

        patch_data = (
            header_data +
            zlib.compress(b"") +  # Empty control
            zlib.compress(b"") +  # Empty diff
            zlib.compress(b"")    # Empty extra
        )

        parser = ZbsdiffParser()
        zbsdiff_file = parser.parse(patch_data)

        assert zbsdiff_file.header.new_size == 0
        assert len(zbsdiff_file.control_entries) == 0
        assert zbsdiff_file.diff_data == b""
        assert zbsdiff_file.extra_data == b""

    def test_build_empty_extra_block(self):
        """Test building patch with empty extra block."""
        header = ZbsdiffHeader(
            magic=b"ZBSDIFF1",
            control_length=0,
            diff_length=0,
            new_size=5
        )

        entries = [
            ZbsdiffControlEntry(add_length=5, copy_length=0, offset=0)
        ]

        zbsdiff_file = ZbsdiffFile(
            header=header,
            control_entries=entries,
            diff_data=b"12345",
            extra_data=b""  # Empty extra block
        )

        parser = ZbsdiffParser()
        built_data = parser.build(zbsdiff_file)

        # Should build successfully
        reparsed = parser.parse(built_data)
        assert reparsed.extra_data == b""

    def test_parse_control_entries_edge_cases(self):
        """Test parsing control entries with edge cases."""
        parser = ZbsdiffParser()

        # Test with partial entry (should stop parsing)
        partial_data = struct.pack("<q", 5) + struct.pack("<q", 10)  # Missing third field
        entries = parser._parse_control_entries(partial_data)
        assert len(entries) == 0  # Incomplete entry should be ignored

        # Test with exact size
        complete_data = (
            struct.pack("<q", 5) + struct.pack("<q", 10) + struct.pack("<q", -2)
        )
        entries = parser._parse_control_entries(complete_data)
        assert len(entries) == 1
        assert entries[0].add_length == 5
        assert entries[0].copy_length == 10
        assert entries[0].offset == -2
