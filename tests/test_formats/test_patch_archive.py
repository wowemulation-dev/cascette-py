"""Tests for patch archive format parser."""

import struct
from io import BytesIO

import pytest

from cascette_tools.formats.patch_archive import (
    PA_HEADER_SIZE,
    PA_MAGIC,
    CompressionSpec,
    PatchArchiveFile,
    PatchArchiveHeader,
    PatchArchiveParser,
    PatchEntry,
    create_empty_patch_archive,
    is_patch_archive,
)


class TestPatchArchiveHeader:
    """Test patch archive header model."""

    def test_header_creation(self):
        """Test creating patch archive header."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=100,
            flags=1
        )

        assert header.magic == PA_MAGIC
        assert header.version == 2
        assert header.file_key_size == 16
        assert header.old_key_size == 16
        assert header.patch_key_size == 16
        assert header.block_size_bits == 16
        assert header.block_count == 100
        assert header.flags == 1


class TestPatchEntry:
    """Test patch entry model."""

    def test_entry_creation(self):
        """Test creating patch entry."""
        old_key = b'0123456789abcdef'
        new_key = b'fedcba9876543210'
        patch_key = b'abcdef0123456789'
        compression = '{*=z}'

        entry = PatchEntry(
            old_content_key=old_key,
            new_content_key=new_key,
            patch_encoding_key=patch_key,
            compression_info=compression
        )

        assert entry.old_content_key == old_key
        assert entry.new_content_key == new_key
        assert entry.patch_encoding_key == patch_key
        assert entry.compression_info == compression


class TestCompressionSpec:
    """Test compression specification utilities."""

    def test_parse_empty_spec(self):
        """Test parsing empty compression spec."""
        spec = CompressionSpec.parse('')

        assert spec['original'] == ''
        assert spec['compression'] == 'none'
        assert spec['options'] == {}

    def test_parse_zlib_spec(self):
        """Test parsing zlib compression spec."""
        spec = CompressionSpec.parse('{*=z}')

        assert spec['original'] == '{*=z}'
        assert spec['compression'] == 'zlib'
        assert spec['options'] == {}

    def test_parse_lz4_spec(self):
        """Test parsing LZ4 compression spec."""
        spec = CompressionSpec.parse('{*=l}')

        assert spec['original'] == '{*=l}'
        assert spec['compression'] == 'lz4'
        assert spec['options'] == {}

    def test_parse_complex_spec(self):
        """Test parsing complex compression spec."""
        spec = CompressionSpec.parse('{method=zstd,level=3}')

        assert spec['original'] == '{method=zstd,level=3}'
        assert spec['compression'] == 'none'  # Unknown compression
        assert spec['options'] == {'method': 'zstd', 'level': '3'}

    def test_build_empty_spec(self):
        """Test building empty compression spec."""
        spec_dict = {'compression': 'none'}
        result = CompressionSpec.build(spec_dict)

        assert result == ''

    def test_build_zlib_spec(self):
        """Test building zlib compression spec."""
        spec_dict = {'compression': 'zlib'}
        result = CompressionSpec.build(spec_dict)

        assert result == '{*=z}'

    def test_build_lz4_spec(self):
        """Test building LZ4 compression spec."""
        spec_dict = {'compression': 'lz4'}
        result = CompressionSpec.build(spec_dict)

        assert result == '{*=l}'

    def test_build_from_original(self):
        """Test building from original string."""
        spec_dict = {'original': '{custom=spec}'}
        result = CompressionSpec.build(spec_dict)

        assert result == '{custom=spec}'

    def test_build_complex_spec(self):
        """Test building complex compression spec."""
        spec_dict = {
            'compression': 'unknown',
            'options': {'method': 'zstd', 'level': '3'}
        }
        result = CompressionSpec.build(spec_dict)

        assert result in ['{method=zstd,level=3}', '{level=3,method=zstd}']  # Order may vary


class TestPatchArchiveParser:
    """Test patch archive parser."""

    def test_parse_empty_archive(self):
        """Test parsing empty patch archive."""
        # Create minimal valid PA header with no entries
        header_data = bytearray()
        header_data.extend(PA_MAGIC)  # Magic: 'PA'
        header_data.append(2)  # Version
        header_data.append(16)  # File key size
        header_data.append(16)  # Old key size
        header_data.append(16)  # Patch key size
        header_data.append(16)  # Block size bits
        header_data.extend(struct.pack('>H', 0))  # Block count (big-endian)
        header_data.append(0)  # Flags

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(header_data))

        assert patch_archive.header.magic == PA_MAGIC
        assert patch_archive.header.version == 2
        assert patch_archive.header.file_key_size == 16
        assert patch_archive.header.old_key_size == 16
        assert patch_archive.header.patch_key_size == 16
        assert patch_archive.header.block_size_bits == 16
        assert patch_archive.header.block_count == 0
        assert patch_archive.header.flags == 0
        assert len(patch_archive.entries) == 0

    def test_parse_single_entry(self):
        """Test parsing patch archive with single entry."""
        # Create header
        header_data = bytearray()
        header_data.extend(PA_MAGIC)  # Magic: 'PA'
        header_data.append(2)  # Version
        header_data.append(16)  # File key size
        header_data.append(16)  # Old key size
        header_data.append(16)  # Patch key size
        header_data.append(16)  # Block size bits
        header_data.extend(struct.pack('>H', 1))  # Block count (big-endian)
        header_data.append(0)  # Flags

        # Create single entry
        old_key = b'0123456789abcdef'
        new_key = b'fedcba9876543210'
        patch_key = b'abcdef0123456789'
        compression = '{*=z}'

        entry_data = bytearray()
        entry_data.extend(old_key)  # Old content key
        entry_data.extend(new_key)  # New content key
        entry_data.extend(patch_key)  # Patch encoding key
        entry_data.extend(compression.encode('utf-8'))  # Compression info
        entry_data.append(0)  # Null terminator

        full_data = header_data + entry_data

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(full_data))

        assert len(patch_archive.entries) == 1
        entry = patch_archive.entries[0]
        assert entry.old_content_key == old_key
        assert entry.new_content_key == new_key
        assert entry.patch_encoding_key == patch_key
        assert entry.compression_info == compression

    def test_parse_multiple_entries(self):
        """Test parsing patch archive with multiple entries."""
        # Create header
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 2))
        header_data.append(0)

        # Create entries
        entries_data = bytearray()

        # Entry 1
        entries_data.extend(b'0123456789abcdef')  # Old key
        entries_data.extend(b'fedcba9876543210')  # New key
        entries_data.extend(b'abcdef0123456789')  # Patch key
        entries_data.extend(b'{*=z}')  # Compression
        entries_data.append(0)  # Null terminator

        # Entry 2
        entries_data.extend(b'1111222233334444')  # Old key
        entries_data.extend(b'5555666677778888')  # New key
        entries_data.extend(b'9999aaaabbbbcccc')  # Patch key
        entries_data.extend(b'{*=l}')  # Compression
        entries_data.append(0)  # Null terminator

        full_data = header_data + entries_data

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(full_data))

        assert len(patch_archive.entries) == 2

        # Check first entry
        entry1 = patch_archive.entries[0]
        assert entry1.old_content_key == b'0123456789abcdef'
        assert entry1.new_content_key == b'fedcba9876543210'
        assert entry1.patch_encoding_key == b'abcdef0123456789'
        assert entry1.compression_info == '{*=z}'

        # Check second entry
        entry2 = patch_archive.entries[1]
        assert entry2.old_content_key == b'1111222233334444'
        assert entry2.new_content_key == b'5555666677778888'
        assert entry2.patch_encoding_key == b'9999aaaabbbbcccc'
        assert entry2.compression_info == '{*=l}'

    def test_parse_from_stream(self):
        """Test parsing from stream."""
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 0))
        header_data.append(0)

        stream = BytesIO(bytes(header_data))

        parser = PatchArchiveParser()
        patch_archive = parser.parse(stream)

        assert patch_archive.header.magic == PA_MAGIC
        assert patch_archive.header.version == 2

    def test_parse_invalid_magic(self):
        """Test parsing data with invalid magic."""
        data = b'XX' + b'\x00' * 8  # Invalid magic

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Invalid PA magic"):
            parser.parse(data)

    def test_parse_too_short(self):
        """Test parsing data that's too short."""
        data = b'PA\x02'  # Only 3 bytes

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Data too short"):
            parser.parse(data)

    def test_build_empty_archive(self):
        """Test building empty patch archive."""
        patch_archive = create_empty_patch_archive()

        parser = PatchArchiveParser()
        binary_data = parser.build(patch_archive)

        assert len(binary_data) == PA_HEADER_SIZE
        assert binary_data[:2] == PA_MAGIC

    def test_build_single_entry(self):
        """Test building patch archive with single entry."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=1,
            flags=0
        )

        entry = PatchEntry(
            old_content_key=b'0123456789abcdef',
            new_content_key=b'fedcba9876543210',
            patch_encoding_key=b'abcdef0123456789',
            compression_info='{*=z}'
        )

        patch_archive = PatchArchiveFile(header=header, entries=[entry])

        parser = PatchArchiveParser()
        binary_data = parser.build(patch_archive)

        # Should contain header + entry data
        expected_size = PA_HEADER_SIZE + 16 + 16 + 16 + len('{*=z}') + 1  # +1 for null terminator
        assert len(binary_data) == expected_size

    def test_build_invalid_magic(self):
        """Test building archive with invalid magic."""
        header = PatchArchiveHeader(
            magic=b'XX',  # Invalid magic
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=0,
            flags=0
        )

        patch_archive = PatchArchiveFile(header=header, entries=[])

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Invalid magic"):
            parser.build(patch_archive)

    def test_build_invalid_key_size(self):
        """Test building archive with invalid key size."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=1,
            flags=0
        )

        entry = PatchEntry(
            old_content_key=b'short',  # Wrong size
            new_content_key=b'fedcba9876543210',
            patch_encoding_key=b'abcdef0123456789',
            compression_info=''
        )

        patch_archive = PatchArchiveFile(header=header, entries=[entry])

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Old key size mismatch"):
            parser.build(patch_archive)

    def test_round_trip_empty(self):
        """Test round-trip parsing and building empty archive."""
        original = create_empty_patch_archive()

        parser = PatchArchiveParser()
        binary_data = parser.build(original)
        parsed = parser.parse(binary_data)

        assert parsed.header.magic == original.header.magic
        assert parsed.header.version == original.header.version
        assert parsed.header.file_key_size == original.header.file_key_size
        assert parsed.header.old_key_size == original.header.old_key_size
        assert parsed.header.patch_key_size == original.header.patch_key_size
        assert parsed.header.block_size_bits == original.header.block_size_bits
        assert parsed.header.block_count == original.header.block_count
        assert parsed.header.flags == original.header.flags
        assert len(parsed.entries) == len(original.entries)

    def test_round_trip_with_entries(self):
        """Test round-trip parsing and building with entries."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=2,
            flags=1
        )

        entries = [
            PatchEntry(
                old_content_key=b'0123456789abcdef',
                new_content_key=b'fedcba9876543210',
                patch_encoding_key=b'abcdef0123456789',
                compression_info='{*=z}'
            ),
            PatchEntry(
                old_content_key=b'1111222233334444',
                new_content_key=b'5555666677778888',
                patch_encoding_key=b'9999aaaabbbbcccc',
                compression_info=''  # Empty compression
            )
        ]

        original = PatchArchiveFile(header=header, entries=entries)

        parser = PatchArchiveParser()
        binary_data = parser.build(original)
        parsed = parser.parse(binary_data)

        # Check header
        assert parsed.header.magic == original.header.magic
        assert parsed.header.version == original.header.version
        assert parsed.header.flags == original.header.flags

        # Check entries
        assert len(parsed.entries) == len(original.entries)
        for _i, (parsed_entry, original_entry) in enumerate(zip(parsed.entries, original.entries, strict=False)):
            assert parsed_entry.old_content_key == original_entry.old_content_key
            assert parsed_entry.new_content_key == original_entry.new_content_key
            assert parsed_entry.patch_encoding_key == original_entry.patch_encoding_key
            assert parsed_entry.compression_info == original_entry.compression_info

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        patch_archive = create_empty_patch_archive()

        parser = PatchArchiveParser()
        binary_data = parser.build(patch_archive)

        # Write to file
        test_file = tmp_path / "test.pa"
        test_file.write_bytes(binary_data)

        # Parse from file
        parsed = parser.parse_file(str(test_file))

        assert parsed.header.magic == PA_MAGIC
        assert parsed.header.version == 2

    def test_validation_success(self):
        """Test successful validation."""
        patch_archive = create_empty_patch_archive()

        parser = PatchArchiveParser()
        binary_data = parser.build(patch_archive)

        is_valid, message = parser.validate(binary_data)

        assert is_valid
        assert message == "Valid"

    def test_validation_failure(self):
        """Test validation failure."""
        invalid_data = b'invalid patch archive data'

        parser = PatchArchiveParser()
        is_valid, message = parser.validate(invalid_data)

        assert not is_valid
        assert "Invalid PA magic" in message


class TestUtilityFunctions:
    """Test utility functions."""

    def test_is_patch_archive_valid(self):
        """Test is_patch_archive with valid data."""
        data = PA_MAGIC + b'\x00' * 8

        assert is_patch_archive(data)

    def test_is_patch_archive_invalid_magic(self):
        """Test is_patch_archive with invalid magic."""
        data = b'XX' + b'\x00' * 8

        assert not is_patch_archive(data)

    def test_is_patch_archive_too_short(self):
        """Test is_patch_archive with too short data."""
        data = b'PA'

        assert not is_patch_archive(data)

    def test_create_empty_patch_archive_default(self):
        """Test creating empty patch archive with defaults."""
        patch_archive = create_empty_patch_archive()

        assert patch_archive.header.magic == PA_MAGIC
        assert patch_archive.header.version == 2
        assert patch_archive.header.file_key_size == 16
        assert patch_archive.header.old_key_size == 16
        assert patch_archive.header.patch_key_size == 16
        assert patch_archive.header.block_size_bits == 16
        assert patch_archive.header.block_count == 0
        assert patch_archive.header.flags == 0
        assert len(patch_archive.entries) == 0

    def test_create_empty_patch_archive_custom(self):
        """Test creating empty patch archive with custom parameters."""
        patch_archive = create_empty_patch_archive(version=1, key_size=20)

        assert patch_archive.header.version == 1
        assert patch_archive.header.file_key_size == 20
        assert patch_archive.header.old_key_size == 20
        assert patch_archive.header.patch_key_size == 20


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_parse_no_null_terminator(self):
        """Test parsing entry without null terminator."""
        # Create header
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 1))
        header_data.append(0)

        # Create entry without null terminator
        entry_data = bytearray()
        entry_data.extend(b'0123456789abcdef')  # Old key
        entry_data.extend(b'fedcba9876543210')  # New key
        entry_data.extend(b'abcdef0123456789')  # Patch key
        entry_data.extend(b'{*=z}')  # Compression (no null terminator)

        full_data = header_data + entry_data

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(full_data))

        # Should still parse, taking the rest as compression info
        assert len(patch_archive.entries) == 1
        assert patch_archive.entries[0].compression_info == '{*=z}'

    def test_parse_empty_compression(self):
        """Test parsing entry with empty compression info."""
        # Create header
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 1))
        header_data.append(0)

        # Create entry with empty compression
        entry_data = bytearray()
        entry_data.extend(b'0123456789abcdef')  # Old key
        entry_data.extend(b'fedcba9876543210')  # New key
        entry_data.extend(b'abcdef0123456789')  # Patch key
        entry_data.append(0)  # Just null terminator

        full_data = header_data + entry_data

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(full_data))

        assert len(patch_archive.entries) == 1
        assert patch_archive.entries[0].compression_info == ''

    def test_parse_unusual_version(self):
        """Test parsing with unusual but valid version."""
        # Create header with version 1
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(1)  # Version 1
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 0))
        header_data.append(0)

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(header_data))

        assert patch_archive.header.version == 1

    def test_parse_unusual_key_sizes(self):
        """Test parsing with unusual key sizes."""
        # Create header with different key sizes
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(20)  # File key size
        header_data.append(16)  # Old key size
        header_data.append(24)  # Patch key size
        header_data.append(16)
        header_data.extend(struct.pack('>H', 0))
        header_data.append(0)

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(header_data))

        assert patch_archive.header.file_key_size == 20
        assert patch_archive.header.old_key_size == 16
        assert patch_archive.header.patch_key_size == 24
