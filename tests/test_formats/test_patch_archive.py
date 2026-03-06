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


def _build_block_format_pa(
    entries: list[tuple[bytes, int, list[tuple[bytes, int, bytes, int, int]]]],
    flags: int = 0x02,
    encoding_info: tuple[bytes, bytes, int, int, str] | None = None,
) -> bytes:
    """Build a PA file in the real block-based format.

    Args:
        entries: List of (target_ckey, decoded_size, patches) where
            patches is [(src_ekey, src_size, patch_ekey, patch_size, patch_idx), ...]
        flags: Header flags (default 0x02 for encoding info)
        encoding_info: Optional (enc_ckey, enc_ekey, dec_size, enc_size, espec)
    """
    file_key_size = 16
    old_key_size = 16
    patch_key_size = 16

    # Header
    header = bytearray()
    header.extend(PA_MAGIC)
    header.append(2)  # version
    header.append(file_key_size)
    header.append(old_key_size)
    header.append(patch_key_size)
    header.append(16)  # block_size_bits
    header.extend(struct.pack('>H', 1))  # 1 block
    header.append(flags)

    # Encoding info (if flags bit 1 set)
    enc_section = bytearray()
    if flags & 0x02:
        if encoding_info is None:
            encoding_info = (b'\x00' * 16, b'\x00' * 16, 0, 0, '')
        enc_ckey, enc_ekey, dec_size, enc_size, espec = encoding_info
        enc_section.extend(enc_ckey)
        enc_section.extend(enc_ekey)
        enc_section.extend(struct.pack('>I', dec_size))
        enc_section.extend(struct.pack('>I', enc_size))
        enc_section.append(len(espec))
        enc_section.extend(espec.encode('utf-8'))

    # Block table: 1 block entry
    # We need to compute the block_offset (where file entries start)
    block_table = bytearray()
    last_ckey = entries[-1][0] if entries else b'\xff' * 16
    block_md5 = b'\x00' * 16  # placeholder
    block_offset = len(header) + len(enc_section) + file_key_size + 16 + 4
    block_table.extend(last_ckey)
    block_table.extend(block_md5)
    block_table.extend(struct.pack('>I', block_offset))

    # File entries
    file_data = bytearray()
    for target_ckey, decoded_size, patches in entries:
        file_data.append(len(patches))  # num_patches
        file_data.extend(target_ckey)
        file_data.extend(decoded_size.to_bytes(5, 'big'))  # uint40
        for src_ekey, src_size, patch_ekey, patch_size, patch_idx in patches:
            file_data.extend(src_ekey)
            file_data.extend(src_size.to_bytes(5, 'big'))
            file_data.extend(patch_ekey)
            file_data.extend(struct.pack('>I', patch_size))
            file_data.append(patch_idx)
    file_data.append(0)  # End of block marker

    return bytes(header + enc_section + block_table + file_data)


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
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)   # Version
        header_data.append(16)  # File key size
        header_data.append(16)  # Old key size
        header_data.append(16)  # Patch key size
        header_data.append(16)  # Block size bits
        header_data.extend(struct.pack('>H', 0))  # Block count = 0
        header_data.append(0)   # Flags

        parser = PatchArchiveParser()
        patch_archive = parser.parse(bytes(header_data))

        assert patch_archive.header.magic == PA_MAGIC
        assert patch_archive.header.version == 2
        assert patch_archive.header.block_count == 0
        assert len(patch_archive.entries) == 0

    def test_parse_single_entry_block_format(self):
        """Test parsing patch archive with single entry in block format."""
        old_key = b'0123456789abcdef'
        new_key = b'fedcba9876543210'
        patch_key = b'abcdef0123456789'

        data = _build_block_format_pa([
            (new_key, 1000, [(old_key, 900, patch_key, 200, 0)]),
        ])

        parser = PatchArchiveParser()
        patch_archive = parser.parse(data)

        assert len(patch_archive.entries) == 1
        entry = patch_archive.entries[0]
        assert entry.old_content_key == old_key
        assert entry.new_content_key == new_key
        assert entry.patch_encoding_key == patch_key

    def test_parse_multiple_entries_block_format(self):
        """Test parsing patch archive with multiple entries in block format."""
        data = _build_block_format_pa([
            (b'fedcba9876543210', 1000, [
                (b'0123456789abcdef', 900, b'abcdef0123456789', 200, 0),
            ]),
            (b'5555666677778888', 2000, [
                (b'1111222233334444', 1800, b'9999aaaabbbbcccc', 300, 0),
            ]),
        ])

        parser = PatchArchiveParser()
        patch_archive = parser.parse(data)

        assert len(patch_archive.entries) == 2

        entry1 = patch_archive.entries[0]
        assert entry1.old_content_key == b'0123456789abcdef'
        assert entry1.new_content_key == b'fedcba9876543210'
        assert entry1.patch_encoding_key == b'abcdef0123456789'

        entry2 = patch_archive.entries[1]
        assert entry2.old_content_key == b'1111222233334444'
        assert entry2.new_content_key == b'5555666677778888'
        assert entry2.patch_encoding_key == b'9999aaaabbbbcccc'

    def test_parse_multi_patch_entry(self):
        """Test parsing file entry with multiple source patches."""
        target = b'fedcba9876543210'
        src1 = b'0123456789abcdef'
        src2 = b'1111222233334444'
        patch1 = b'abcdef0123456789'
        patch2 = b'9999aaaabbbbcccc'

        data = _build_block_format_pa([
            (target, 1000, [
                (src1, 900, patch1, 200, 0),
                (src2, 950, patch2, 150, 1),
            ]),
        ])

        parser = PatchArchiveParser()
        pa = parser.parse(data)

        # Multi-patch entries get flattened
        assert len(pa.entries) == 2
        assert pa.entries[0].old_content_key == src1
        assert pa.entries[0].new_content_key == target
        assert pa.entries[0].patch_encoding_key == patch1
        assert pa.entries[1].old_content_key == src2
        assert pa.entries[1].new_content_key == target
        assert pa.entries[1].patch_encoding_key == patch2

        # Also check structured file_entries
        assert len(pa.file_entries) == 1
        assert len(pa.file_entries[0].patches) == 2

    def test_parse_encoding_info(self):
        """Test parsing with encoding info (extended header)."""
        enc_ckey = b'encodingckey1234'
        enc_ekey = b'encodingekey5678'

        data = _build_block_format_pa(
            entries=[],
            flags=0x02,
            encoding_info=(enc_ckey, enc_ekey, 50_000_000, 49_500_000, 'b:{*=z}'),
        )

        parser = PatchArchiveParser()
        pa = parser.parse(data)

        assert pa.encoding_info is not None
        assert pa.encoding_info.encoding_ckey == enc_ckey
        assert pa.encoding_info.encoding_ekey == enc_ekey
        assert pa.encoding_info.decoded_size == 50_000_000
        assert pa.encoding_info.encoded_size == 49_500_000
        assert pa.encoding_info.encoding_spec == 'b:{*=z}'

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
        data = b'XX' + b'\x00' * 8

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Invalid PA magic"):
            parser.parse(data)

    def test_parse_too_short(self):
        """Test parsing data that's too short."""
        data = b'PA\x02'

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

        expected_size = PA_HEADER_SIZE + 16 + 16 + 16 + len('{*=z}') + 1
        assert len(binary_data) == expected_size

    def test_build_invalid_magic(self):
        """Test building archive with invalid magic."""
        header = PatchArchiveHeader(
            magic=b'XX',
            version=2, file_key_size=16, old_key_size=16,
            patch_key_size=16, block_size_bits=16, block_count=0, flags=0
        )

        patch_archive = PatchArchiveFile(header=header, entries=[])

        parser = PatchArchiveParser()

        with pytest.raises(ValueError, match="Invalid magic"):
            parser.build(patch_archive)

    def test_build_invalid_key_size(self):
        """Test building archive with invalid key size."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2, file_key_size=16, old_key_size=16,
            patch_key_size=16, block_size_bits=16, block_count=1, flags=0
        )

        entry = PatchEntry(
            old_content_key=b'short',
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
        assert parsed.header.block_count == original.header.block_count
        assert len(parsed.entries) == len(original.entries)

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        patch_archive = create_empty_patch_archive()

        parser = PatchArchiveParser()
        binary_data = parser.build(patch_archive)

        test_file = tmp_path / "test.pa"
        test_file.write_bytes(binary_data)

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


class TestPatchArchiveFlags:
    """Test patch archive flag methods."""

    def test_is_plain_data(self):
        """Test is_plain_data flag method."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC, version=2, file_key_size=16, old_key_size=16,
            patch_key_size=16, block_size_bits=16, block_count=0, flags=0x01
        )
        assert header.is_plain_data() is True
        assert header.has_extended_header() is False

    def test_has_extended_header(self):
        """Test has_extended_header flag method."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC, version=2, file_key_size=16, old_key_size=16,
            patch_key_size=16, block_size_bits=16, block_count=0, flags=0x02
        )
        assert header.is_plain_data() is False
        assert header.has_extended_header() is True

    def test_both_flags(self):
        """Test both flags set."""
        header = PatchArchiveHeader(
            magic=PA_MAGIC, version=2, file_key_size=16, old_key_size=16,
            patch_key_size=16, block_size_bits=16, block_count=0, flags=0x03
        )
        assert header.is_plain_data() is True
        assert header.has_extended_header() is True

    def test_extended_header_parsed_correctly(self):
        """Test that extended header flag triggers encoding info parsing."""
        data = _build_block_format_pa(
            entries=[],
            flags=0x02,
            encoding_info=(b'\xaa' * 16, b'\xbb' * 16, 100, 90, '{*=z}'),
        )

        parser = PatchArchiveParser()
        pa = parser.parse(data)

        assert pa.header.flags == 0x02
        assert pa.encoding_info is not None
        assert pa.encoding_info.encoding_spec == '{*=z}'

    def test_plain_data_flag_accepted(self):
        """Test that plain data flag (bit 0) is accepted."""
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(2)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.append(16)
        header_data.extend(struct.pack('>H', 0))
        header_data.append(0x01)

        parser = PatchArchiveParser()
        pa = parser.parse(bytes(header_data))
        assert pa.header.flags == 0x01
        assert pa.header.is_plain_data() is True


class TestEdgeCases:
    """Test edge cases."""

    def test_parse_unusual_version(self):
        """Test parsing with unusual but valid version."""
        header_data = bytearray()
        header_data.extend(PA_MAGIC)
        header_data.append(1)
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

    def test_parse_block_size_bits_boundary_values(self):
        """Test block_size_bits is validated to 12-24 per Agent.exe ParseHeader."""
        def make_header(block_size_bits: int) -> bytes:
            data = bytearray()
            data.extend(PA_MAGIC)
            data.append(2)   # version
            data.append(16)  # file_key_size
            data.append(16)  # old_key_size
            data.append(16)  # patch_key_size
            data.append(block_size_bits)
            data.extend(struct.pack('>H', 0))  # block_count
            data.append(0)   # flags
            return bytes(data)

        parser = PatchArchiveParser()

        # Valid boundary values
        for bits in [12, 16, 24]:
            result = parser.parse(make_header(bits))
            assert result.header.block_size_bits == bits

        # Invalid values
        with pytest.raises(ValueError, match="block_size_bits"):
            parser.parse(make_header(11))

        with pytest.raises(ValueError, match="block_size_bits"):
            parser.parse(make_header(25))


class TestPatchArchiveBuilderMethods:
    """Test PatchArchiveBuilder class methods and uncovered build() paths."""

    def test_builder_build(self):
        """PatchArchiveBuilder.build() delegates to parser (lines 519-520)."""
        from cascette_tools.formats.patch_archive import PatchArchiveBuilder
        archive = PatchArchiveBuilder.create_empty()

        builder = PatchArchiveBuilder()
        binary = builder.build(archive)
        assert binary[:2] == b'PA'

    def test_builder_create_empty(self):
        """PatchArchiveBuilder.create_empty() returns empty archive (line 525)."""
        from cascette_tools.formats.patch_archive import PatchArchiveBuilder
        archive = PatchArchiveBuilder.create_empty()
        assert archive.header.block_count == 0
        assert archive.entries == []

    def test_builder_create_with_entries(self):
        """PatchArchiveBuilder.create_with_entries() builds header (lines 530-541)."""
        from cascette_tools.formats.patch_archive import PatchArchiveBuilder, PatchEntry
        entries = [
            PatchEntry(
                old_content_key=b'\x01' * 16,
                new_content_key=b'\x02' * 16,
                patch_encoding_key=b'\x03' * 16,
                compression_info='',
            ),
        ]
        archive = PatchArchiveBuilder.create_with_entries(entries)
        assert archive.header.block_count == 1
        assert archive.header.version == 2
        assert len(archive.entries) == 1

    def test_unexpected_version_warns(self):
        """Version not in [1, 2] logs a warning but parses successfully (line 296)."""
        from cascette_tools.formats.patch_archive import PA_MAGIC, PatchArchiveParser
        data = bytearray()
        data.extend(PA_MAGIC)
        data.append(3)   # version = 3 (unexpected)
        data.append(16)  # file_key_size
        data.append(16)  # old_key_size
        data.append(16)  # patch_key_size
        data.append(16)  # block_size_bits
        data.extend(b'\x00\x00')  # block_count = 0
        data.append(0)            # flags

        parser = PatchArchiveParser()
        archive = parser.parse(bytes(data))
        assert archive.header.version == 3  # parsed despite unexpected version

    def test_build_zero_key_size_raises(self):
        """build() raises when key sizes are zero (line 463)."""
        from cascette_tools.formats.patch_archive import (
            PA_MAGIC,
            PatchArchiveFile,
            PatchArchiveHeader,
            PatchArchiveParser,
        )
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=0,   # invalid!
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=0,
            flags=0,
        )
        archive = PatchArchiveFile(header=header, entries=[])
        parser = PatchArchiveParser()
        with pytest.raises(ValueError, match="Key sizes must be positive"):
            parser.build(archive)

    def test_build_new_key_mismatch_raises(self):
        """build() raises when new_content_key doesn't match file_key_size (line 480)."""
        from cascette_tools.formats.patch_archive import (
            PA_MAGIC,
            PatchArchiveFile,
            PatchArchiveHeader,
            PatchArchiveParser,
            PatchEntry,
        )
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=1,
            flags=0,
        )
        entry = PatchEntry(
            old_content_key=b'\x01' * 16,
            new_content_key=b'\x02' * 8,  # 8 bytes, but file_key_size=16
            patch_encoding_key=b'\x03' * 16,
            compression_info='',
        )
        archive = PatchArchiveFile(header=header, entries=[entry])
        parser = PatchArchiveParser()
        with pytest.raises(ValueError, match="New key size mismatch"):
            parser.build(archive)

    def test_build_patch_key_mismatch_raises(self):
        """build() raises when patch_encoding_key doesn't match patch_key_size (line 482)."""
        from cascette_tools.formats.patch_archive import (
            PA_MAGIC,
            PatchArchiveFile,
            PatchArchiveHeader,
            PatchArchiveParser,
            PatchEntry,
        )
        header = PatchArchiveHeader(
            magic=PA_MAGIC,
            version=2,
            file_key_size=16,
            old_key_size=16,
            patch_key_size=16,
            block_size_bits=16,
            block_count=1,
            flags=0,
        )
        entry = PatchEntry(
            old_content_key=b'\x01' * 16,
            new_content_key=b'\x02' * 16,
            patch_encoding_key=b'\x03' * 4,  # 4 bytes, but patch_key_size=16
            compression_info='',
        )
        archive = PatchArchiveFile(header=header, entries=[entry])
        parser = PatchArchiveParser()
        with pytest.raises(ValueError, match="Patch key size mismatch"):
            parser.build(archive)
