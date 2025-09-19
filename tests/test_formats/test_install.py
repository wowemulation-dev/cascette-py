"""Tests for install format parser."""

import struct
from io import BytesIO

from cascette_tools.formats.install import (
    InstallEntry,
    InstallFile,
    InstallParser,
    InstallTag,
    is_install,
)


class TestInstallParser:
    """Test install format parser."""

    def test_is_install_function(self):
        """Test is_install detection function."""
        # Valid install data with IN magic
        assert is_install(b'IN\x01\x10\x00\x01\x00\x00\x00\x01')

        # Invalid magic
        assert not is_install(b'XX\x01\x10')
        assert not is_install(b'EN\x01\x10')

        # Too short
        assert not is_install(b'I')
        assert not is_install(b'')

    def test_install_tag_has_file(self):
        """Test InstallTag.has_file method."""
        # Create tag with bitmask: files 0, 2, 5 have the tag
        # Byte 0: bits 0 and 2 set = 0b00000101 = 0x05
        # Byte 1: bit 5 set (bit 5 - 8 = -3, so bit 5 in second byte is bit 5-8 = bit 5 in byte 0)
        # Actually bit 5 is in byte 0, bit position 5
        bitmask = bytearray(1)
        bitmask[0] = 0b00100101  # bits 0, 2, 5 set

        tag = InstallTag(name="test", tag_type=1, bit_mask=bytes(bitmask))

        assert tag.has_file(0) is True   # bit 0
        assert tag.has_file(1) is False  # bit 1
        assert tag.has_file(2) is True   # bit 2
        assert tag.has_file(3) is False  # bit 3
        assert tag.has_file(4) is False  # bit 4
        assert tag.has_file(5) is True   # bit 5
        assert tag.has_file(6) is False  # bit 6
        assert tag.has_file(7) is False  # bit 7
        assert tag.has_file(8) is False  # out of range

    def test_parse_minimal_install(self):
        """Test parsing minimal install manifest."""
        parser = InstallParser()

        # Build minimal install data
        data = BytesIO()

        # Header: IN + version=1 + hash_size=16 + tag_count=0 + entry_count=1
        data.write(b'IN')  # magic
        data.write(struct.pack('B', 1))  # version
        data.write(struct.pack('B', 16))  # hash_size
        data.write(struct.pack('>H', 0))  # tag_count (big-endian)
        data.write(struct.pack('>I', 1))  # entry_count (big-endian)

        # No tags (tag_count = 0)

        # One file entry
        data.write(b'test.txt\x00')  # filename
        data.write(b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef')  # MD5 hash
        data.write(struct.pack('>I', 1024))  # file size (big-endian)

        install = parser.parse(data.getvalue())

        assert install.version == 1
        assert install.hash_size == 16
        assert len(install.tags) == 0
        assert len(install.entries) == 1

        entry = install.entries[0]
        assert entry.filename == "test.txt"
        assert entry.md5_hash == b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'
        assert entry.size == 1024
        assert entry.tags == []

    def test_parse_install_with_tags(self):
        """Test parsing install manifest with tags."""
        parser = InstallParser()

        # Build install data with tags
        data = BytesIO()

        # Header: IN + version=1 + hash_size=16 + tag_count=2 + entry_count=3
        data.write(b'IN')  # magic
        data.write(struct.pack('B', 1))  # version
        data.write(struct.pack('B', 16))  # hash_size
        data.write(struct.pack('>H', 2))  # tag_count (big-endian)
        data.write(struct.pack('>I', 3))  # entry_count (big-endian)

        # Tag 1: "Windows" type=1, applies to files 0,2
        data.write(b'Windows\x00')  # tag name
        data.write(struct.pack('>H', 1))  # tag type (big-endian)
        # Bitmask for 3 files = 1 byte: bits 0,2 set = 0b00000101
        data.write(b'\x05')

        # Tag 2: "enUS" type=4, applies to files 1,2
        data.write(b'enUS\x00')  # tag name
        data.write(struct.pack('>H', 4))  # tag type (big-endian)
        # Bitmask for 3 files = 1 byte: bits 1,2 set = 0b00000110
        data.write(b'\x06')

        # File entries
        for i, name in enumerate(['file1.exe', 'file2.txt', 'file3.dll']):
            data.write(name.encode('utf-8') + b'\x00')  # filename
            data.write(bytes(range(16)))  # MD5 hash (dummy)
            data.write(struct.pack('>I', 1000 + i))  # file size

        install = parser.parse(data.getvalue())

        assert install.version == 1
        assert install.hash_size == 16
        assert len(install.tags) == 2
        assert len(install.entries) == 3

        # Check tags
        assert install.tags[0].name == "Windows"
        assert install.tags[0].tag_type == 1
        assert install.tags[1].name == "enUS"
        assert install.tags[1].tag_type == 4

        # Check file tag assignments
        assert install.entries[0].tags == ["Windows"]  # file 0: only Windows
        assert install.entries[1].tags == ["enUS"]     # file 1: only enUS
        assert install.entries[2].tags == ["Windows", "enUS"]  # file 2: both tags

    def test_round_trip_minimal(self):
        """Test parsing then building gives same data."""
        parser = InstallParser()

        # Create original data
        original_data = BytesIO()
        original_data.write(b'IN')  # magic
        original_data.write(struct.pack('B', 1))  # version
        original_data.write(struct.pack('B', 16))  # hash_size
        original_data.write(struct.pack('>H', 0))  # tag_count
        original_data.write(struct.pack('>I', 1))  # entry_count
        original_data.write(b'test.txt\x00')  # filename
        original_data.write(bytes(range(16)))  # MD5
        original_data.write(struct.pack('>I', 512))  # size

        original_bytes = original_data.getvalue()

        # Parse then build
        install = parser.parse(original_bytes)
        rebuilt_bytes = parser.build(install)

        assert rebuilt_bytes == original_bytes

    def test_round_trip_with_tags(self):
        """Test round-trip with tags."""
        parser = InstallParser()

        # Create install with tags
        install = InstallFile(
            version=1,
            hash_size=16,
            tags=[
                InstallTag(name="Windows", tag_type=1, bit_mask=b'\x05'),  # files 0,2
                InstallTag(name="x64", tag_type=2, bit_mask=b'\x03'),      # files 0,1
            ],
            entries=[
                InstallEntry(
                    filename="file1.exe",
                    md5_hash=bytes(range(16)),
                    size=1000,
                    tags=["Windows", "x64"]
                ),
                InstallEntry(
                    filename="file2.txt",
                    md5_hash=bytes(range(1, 17)),
                    size=2000,
                    tags=["x64"]
                ),
                InstallEntry(
                    filename="file3.dll",
                    md5_hash=bytes(range(2, 18)),
                    size=3000,
                    tags=["Windows"]
                ),
            ]
        )

        # Build then parse
        built_bytes = parser.build(install)
        parsed_install = parser.parse(built_bytes)

        # Verify structure
        assert parsed_install.version == install.version
        assert parsed_install.hash_size == install.hash_size
        assert len(parsed_install.tags) == len(install.tags)
        assert len(parsed_install.entries) == len(install.entries)

        # Verify tags
        for i, tag in enumerate(parsed_install.tags):
            original_tag = install.tags[i]
            assert tag.name == original_tag.name
            assert tag.tag_type == original_tag.tag_type

        # Verify entries
        for i, entry in enumerate(parsed_install.entries):
            original_entry = install.entries[i]
            assert entry.filename == original_entry.filename
            assert entry.md5_hash == original_entry.md5_hash
            assert entry.size == original_entry.size
            assert set(entry.tags) == set(original_entry.tags)

    def test_empty_install(self):
        """Test parsing install with no files."""
        parser = InstallParser()

        # Header only - no tags, no files
        data = BytesIO()
        data.write(b'IN\x01\x10\x00\x00\x00\x00\x00\x00')  # header with counts = 0

        install = parser.parse(data.getvalue())

        assert install.version == 1
        assert install.hash_size == 16
        assert len(install.tags) == 0
        assert len(install.entries) == 0

    def test_files_with_no_tags(self):
        """Test files that don't have any tags."""
        parser = InstallParser()

        # Create install with 1 tag but file doesn't have it
        data = BytesIO()
        data.write(b'IN\x01\x10\x00\x01\x00\x00\x00\x01')  # header

        # Tag that doesn't apply to the file
        data.write(b'Optional\x00')  # tag name
        data.write(struct.pack('>H', 1))  # tag type
        data.write(b'\x00')  # bitmask: no files have this tag

        # One file
        data.write(b'core.exe\x00')
        data.write(bytes(range(16)))
        data.write(struct.pack('>I', 2048))

        install = parser.parse(data.getvalue())

        assert len(install.entries) == 1
        assert install.entries[0].tags == []  # No tags

    def test_files_with_many_tags(self):
        """Test files with multiple tags."""
        parser = InstallParser()

        # Create several tags that all apply to one file
        data = BytesIO()
        data.write(b'IN\x01\x10\x00\x04\x00\x00\x00\x01')  # header: 4 tags, 1 file

        tag_names = ['Windows', 'x64', 'enUS', 'Base']
        for name in tag_names:
            data.write(name.encode('utf-8') + b'\x00')
            data.write(struct.pack('>H', 1))  # tag type
            data.write(b'\x01')  # bitmask: file 0 has this tag

        # One file
        data.write(b'game.exe\x00')
        data.write(bytes(range(16)))
        data.write(struct.pack('>I', 5000))

        install = parser.parse(data.getvalue())

        assert len(install.entries) == 1
        assert set(install.entries[0].tags) == set(tag_names)

    def test_invalid_magic(self):
        """Test parsing with invalid magic."""
        parser = InstallParser()

        data = b'XX\x01\x10\x00\x00\x00\x00\x00\x00'

        try:
            parser.parse(data)
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            assert "Invalid magic" in str(e)

    def test_truncated_header(self):
        """Test parsing with truncated header."""
        parser = InstallParser()

        # Only magic bytes
        data = b'IN'

        try:
            parser.parse(data)
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            assert "Insufficient data for header" in str(e)

    def test_truncated_tag_data(self):
        """Test parsing with truncated tag data."""
        parser = InstallParser()

        # Valid header with 1 tag but no tag data
        data = b'IN\x01\x10\x00\x01\x00\x00\x00\x01'

        try:
            parser.parse(data)
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            assert "Insufficient data" in str(e)

    def test_build_empty_install(self):
        """Test building empty install manifest."""
        parser = InstallParser()

        install = InstallFile(
            version=1,
            hash_size=16,
            tags=[],
            entries=[]
        )

        data = parser.build(install)

        # Should be just header
        expected = b'IN\x01\x10\x00\x00\x00\x00\x00\x00'
        assert data == expected

    def test_validate_method(self):
        """Test the validate method."""
        parser = InstallParser()

        # Build valid data
        install = InstallFile(
            version=1,
            hash_size=16,
            tags=[],
            entries=[
                InstallEntry(
                    filename="test.exe",
                    md5_hash=bytes(range(16)),
                    size=1024,
                    tags=[]
                )
            ]
        )

        data = parser.build(install)

        # Should validate successfully
        is_valid, message = parser.validate(data)
        assert is_valid is True
        assert message == "Valid"

        # Test with corrupted data
        corrupted_data = data[:-1]  # Remove last byte
        is_valid, message = parser.validate(corrupted_data)
        assert is_valid is False
        assert "Insufficient data" in message

    def test_utf8_filenames(self):
        """Test handling of UTF-8 filenames."""
        parser = InstallParser()

        install = InstallFile(
            version=1,
            hash_size=16,
            tags=[],
            entries=[
                InstallEntry(
                    filename="测试文件.txt",  # Chinese characters
                    md5_hash=bytes(range(16)),
                    size=512,
                    tags=[]
                )
            ]
        )

        # Build and parse back
        data = parser.build(install)
        parsed = parser.parse(data)

        assert parsed.entries[0].filename == "测试文件.txt"

    def test_large_bitmasks(self):
        """Test handling of larger bitmasks for many files."""
        parser = InstallParser()

        # Create install with 20 files (3 bytes for bitmask)
        entries = []
        for i in range(20):
            entries.append(InstallEntry(
                filename=f"file{i:02d}.dat",
                md5_hash=bytes(range(16)),
                size=100 + i,
                tags=["Base"] if i % 2 == 0 else []  # Every other file has Base tag
            ))

        # Create bitmask: every even-indexed file has the tag
        mask = bytearray(3)  # (20 + 7) // 8 = 3 bytes
        for i in range(0, 20, 2):  # 0, 2, 4, 6, 8, 10, 12, 14, 16, 18
            byte_index = i // 8
            bit_offset = i % 8
            mask[byte_index] |= (1 << bit_offset)

        install = InstallFile(
            version=1,
            hash_size=16,
            tags=[InstallTag(name="Base", tag_type=1, bit_mask=bytes(mask))],
            entries=entries
        )

        # Build and parse
        data = parser.build(install)
        parsed = parser.parse(data)

        assert len(parsed.entries) == 20

        # Check tag assignments
        for i, entry in enumerate(parsed.entries):
            if i % 2 == 0:
                assert "Base" in entry.tags
            else:
                assert "Base" not in entry.tags
