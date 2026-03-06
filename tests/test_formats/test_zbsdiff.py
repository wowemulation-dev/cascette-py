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
            struct.pack("<q", len(control_compressed)) +
            struct.pack("<q", len(diff_compressed)) +
            struct.pack("<q", 15)  # new_size
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
            struct.pack("<q", 1000) +  # Claim 1000 bytes
            struct.pack("<q", 100) +
            struct.pack("<q", 1000)
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
            struct.pack("<q", 5) +
            struct.pack("<q", 5) +
            struct.pack("<q", 100)
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
            struct.pack("<q", len(zlib.compress(b""))) +  # Empty control
            struct.pack("<q", len(zlib.compress(b""))) +  # Empty diff
            struct.pack("<q", 0)  # Empty new size
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
        # Use sign-magnitude encoding (offtout) for bsdiff values
        partial_data = ZbsdiffParser._offtout(5) + ZbsdiffParser._offtout(10)  # Missing third field
        entries = parser._parse_control_entries(partial_data)
        assert len(entries) == 0  # Incomplete entry should be ignored

        # Test with exact size (negative offset uses sign-magnitude, not two's complement)
        complete_data = (
            ZbsdiffParser._offtout(5) + ZbsdiffParser._offtout(10) + ZbsdiffParser._offtout(-2)
        )
        entries = parser._parse_control_entries(complete_data)
        assert len(entries) == 1
        assert entries[0].add_length == 5
        assert entries[0].copy_length == 10
        assert entries[0].offset == -2


class TestZbsdiffBuilder:
    """Test ZbsdiffBuilder class methods."""

    def test_builder_build(self):
        """ZbsdiffBuilder.build() delegates to ZbsdiffParser.build()."""
        from cascette_tools.formats.zbsdiff import (
            ZbsdiffBuilder,
            ZbsdiffParser,
        )
        empty = ZbsdiffBuilder.create_empty(new_size=0)
        builder = ZbsdiffBuilder()
        result = builder.build(empty)
        parser = ZbsdiffParser()
        parsed = parser.parse(result)
        assert parsed.header.new_size == 0

    def test_create_empty(self):
        """ZbsdiffBuilder.create_empty() returns a valid empty ZbsdiffFile."""
        from cascette_tools.formats.zbsdiff import ZbsdiffBuilder
        z = ZbsdiffBuilder.create_empty(new_size=1024)
        assert z.header.new_size == 1024
        assert z.header.control_length == 0
        assert len(z.control_entries) == 0

    def test_create_with_data(self):
        """ZbsdiffBuilder.create_with_data() sets header fields correctly."""

        from cascette_tools.formats.zbsdiff import (
            ZbsdiffBuilder,
            ZbsdiffControlEntry,
        )
        control_entry = ZbsdiffControlEntry(add_length=4, copy_length=0, offset=0)
        diff_data = b'test'
        z = ZbsdiffBuilder.create_with_data(
            control_entries=[control_entry],
            diff_data=diff_data,
            extra_data=b'',
            new_size=4
        )
        assert z.header.new_size == 4
        assert z.header.diff_length == len(diff_data)
        assert len(z.control_entries) == 1


class TestZbsdiffEdgeCases:
    """Test zbsdiff error paths not covered by existing tests."""

    def test_control_decompression_failure(self):
        """Corrupt zlib control block raises ValueError."""
        import struct
        import zlib

        from cascette_tools.formats.zbsdiff import ZbsdiffParser
        # Build a header pointing to corrupt zlib data
        corrupt = b'\xFF\xFF\xFF\xFF'  # invalid zlib
        diff = zlib.compress(b'')
        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<Q', len(corrupt))   # control_length
        buf += struct.pack('<Q', len(diff))      # diff_length
        buf += struct.pack('<Q', 0)              # new_size
        buf += corrupt
        buf += diff
        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="decompress control"):
            parser.parse(bytes(buf))

    def test_diff_decompression_failure(self):
        """Corrupt zlib diff block raises ValueError."""
        import struct
        import zlib

        from cascette_tools.formats.zbsdiff import ZbsdiffParser
        control = zlib.compress(b'')   # valid empty control
        corrupt = b'\xFF\xFF\xFF'
        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<Q', len(control))
        buf += struct.pack('<Q', len(corrupt))
        buf += struct.pack('<Q', 0)
        buf += control
        buf += corrupt
        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="decompress diff"):
            parser.parse(bytes(buf))

    def test_negative_old_position_raises(self):
        """Control entry with large negative offset causes ValueError."""
        import struct
        import zlib

        from cascette_tools.formats.zbsdiff import ZbsdiffParser

        # Build a control entry with seek_offset = very large negative → wraps old_pos below 0
        def _offout(val: int) -> bytes:
            if val < 0:
                return struct.pack('<Q', ((-val) | (1 << 63)))
            return struct.pack('<Q', val)

        # old_data is empty, so old_pos starts at 0; add_length=0, copy_length=0, offset=-1
        # After the entry: old_pos = 0 + (-1) = -1 → should raise
        control_entries = _offout(0) + _offout(0) + _offout(-1)  # add=0, copy=0, seek=-1
        control_compressed = zlib.compress(control_entries)
        diff_compressed = zlib.compress(b'')
        extra_compressed = zlib.compress(b'')

        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<Q', len(control_compressed))
        buf += struct.pack('<Q', len(diff_compressed))
        buf += struct.pack('<Q', 0)              # new_size
        buf += control_compressed
        buf += diff_compressed
        buf += extra_compressed

        parser = ZbsdiffParser()
        z = parser.parse(bytes(buf))
        with pytest.raises(ValueError, match="Negative old position"):
            parser.apply_patch(b'', z)


class TestZbsdiffParserEdgeCases:
    """Test edge cases not covered by existing tests."""

    def _make_patch(
        self,
        control_entries_bytes: bytes,
        diff_data: bytes = b'',
        extra_data: bytes = b'',
        new_size: int = 0,
    ) -> bytes:
        """Build a minimal valid ZBSDIFF1 patch blob."""
        control_compressed = zlib.compress(control_entries_bytes)
        diff_compressed = zlib.compress(diff_data)
        extra_compressed = zlib.compress(extra_data) if extra_data else b''

        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<q', len(control_compressed))
        buf += struct.pack('<q', len(diff_compressed))
        buf += struct.pack('<q', new_size)
        buf += control_compressed
        buf += diff_compressed
        buf += extra_compressed
        return bytes(buf)

    @staticmethod
    def _offtout(val: int) -> bytes:
        """Encode sign-magnitude 64-bit integer."""
        if val < 0:
            return struct.pack('<Q', ((-val) | (1 << 63)))
        return struct.pack('<Q', val)

    def test_diff_block_too_short(self):
        """Truncated diff block raises ValueError (line 137)."""
        control = zlib.compress(b'')
        # Claim diff_length=50 but write only 3 bytes
        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<q', len(control))
        buf += struct.pack('<q', 50)         # diff_length = 50 (too large)
        buf += struct.pack('<q', 0)
        buf += control
        buf += b'\xFF\xFF\xFF'               # only 3 bytes

        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="Diff block too short"):
            parser.parse(bytes(buf))

    def test_extra_block_decompression_failure(self):
        """Corrupt extra block raises ValueError (lines 154-155)."""
        # Control = empty, diff = empty zlib, extra = corrupt
        control = zlib.compress(b'')
        diff = zlib.compress(b'')
        corrupt_extra = b'\xFF\xFF\xFF'

        buf = bytearray()
        buf += b'ZBSDIFF1'
        buf += struct.pack('<q', len(control))
        buf += struct.pack('<q', len(diff))
        buf += struct.pack('<q', 0)
        buf += control
        buf += diff
        buf += corrupt_extra

        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="decompress extra"):
            parser.parse(bytes(buf))

    def test_struct_error_propagates(self):
        """struct.error during header parse raises ValueError (line 173)."""
        # Provide only 4 bytes — header needs 32 bytes
        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="(Header too short|Failed to parse)"):
            parser.parse(b'ZBSDIF\x00\x00')

    def test_diff_block_overflow(self):
        """Control entry requiring more diff bytes than available raises ValueError (line 232)."""
        # one entry: add_length=10, diff_data has only 5 bytes, new_size=10
        entry = self._offtout(10) + self._offtout(0) + self._offtout(0)
        # diff_data = 5 bytes, but add_length=10 requires 10
        blob = self._make_patch(entry, diff_data=b'\x01' * 5, new_size=10)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)
        with pytest.raises(ValueError, match="Diff block overflow"):
            parser.apply_patch(b'\x00' * 10, patch)

    def test_apply_patch_beyond_old_data_boundary(self):
        """add_length extending past old_data uses diff byte directly (line 241)."""
        # old_data = b'\x10', add_length=2 → index 0 within old, index 1 beyond old
        # diff_data must have 2 bytes
        old_data = b'\x10'
        diff_data = b'\x01\x02'  # 2 bytes
        entry = self._offtout(2) + self._offtout(0) + self._offtout(0)
        blob = self._make_patch(entry, diff_data=diff_data, new_size=2)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)
        result = parser.apply_patch(old_data, patch)

        # byte 0: old[0] + diff[0] = 0x10 + 0x01 = 0x11
        # byte 1: old[1] out of range → just diff[1] = 0x02
        assert result == bytes([0x11, 0x02])

    def test_extra_block_overflow(self):
        """Control entry requiring more extra bytes than available raises ValueError (line 250)."""
        # add_length=0, copy_length=10, extra_data has only 5 bytes
        entry = self._offtout(0) + self._offtout(10) + self._offtout(0)
        blob = self._make_patch(entry, extra_data=b'\xAA' * 5, new_size=10)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)
        with pytest.raises(ValueError, match="Extra block overflow"):
            parser.apply_patch(b'', patch)

    def test_new_data_overflow_from_copy(self):
        """Control entry copy_length overflowing new_data raises ValueError (line 252)."""
        # new_size=2 but copy_length=10 → overflow new_data
        entry = self._offtout(0) + self._offtout(10) + self._offtout(0)
        blob = self._make_patch(entry, extra_data=b'\xAA' * 10, new_size=2)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)
        with pytest.raises(ValueError, match="(Extra block overflow|New data overflow)"):
            parser.apply_patch(b'', patch)

    def test_negative_add_length_clamped_to_zero(self):
        """Negative add_length in control entry is clamped to 0 (line 326)."""
        # Sign-magnitude encode: bit 63 set = negative, lower bits = magnitude
        # Encodes -5: magnitude=5, set bit 63
        magnitude = 5
        buf = bytearray(struct.pack('<Q', magnitude))
        buf[7] |= 0x80  # set sign bit
        entry = bytes(buf) + struct.pack('<Q', 0) + struct.pack('<Q', 0)
        blob = self._make_patch(entry, new_size=0)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)

        # With add_length clamped to 0 and copy_length=0, applying to empty produces empty
        result = parser.apply_patch(b'', patch)
        assert result == b''

    def test_negative_copy_length_clamped_to_zero(self):
        """Negative copy_length in control entry is clamped to 0 (line 328)."""
        # Encode copy_length = -3 via sign-magnitude
        magnitude = 3
        buf = bytearray(struct.pack('<Q', magnitude))
        buf[7] |= 0x80
        entry = struct.pack('<Q', 0) + bytes(buf) + struct.pack('<Q', 0)
        blob = self._make_patch(entry, new_size=0)

        parser = ZbsdiffParser()
        patch = parser.parse(blob)
        result = parser.apply_patch(b'', patch)
        assert result == b''

    def test_too_many_control_entries_raises(self):
        """More than MAX_CONTROL_ENTRIES raises ValueError (line 341)."""
        # Build MAX_CONTROL_ENTRIES + 1 entries of all zeros
        entry = struct.pack('<Q', 0) * 3  # add=0, copy=0, seek=0
        too_many = entry * (MAX_CONTROL_ENTRIES + 1)
        blob = self._make_patch(too_many, new_size=0)

        parser = ZbsdiffParser()
        with pytest.raises(ValueError, match="Too many control entries"):
            parser.parse(blob)
