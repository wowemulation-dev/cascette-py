"""Tests for archive index format parser."""

import hashlib
import struct

import pytest

from cascette_tools.formats.archive import (
    ArchiveIndex,
    ArchiveIndexChunk,
    ArchiveIndexEntry,
    ArchiveIndexFooter,
    ArchiveIndexParser,
    is_obj,
)


class TestArchiveIndexParser:
    """Test archive index format parser."""

    def test_is_obj_function(self):
        """Test is_obj detection function."""
        # Create valid footer
        footer_data = bytearray(28)
        footer_data[8] = 1    # version
        footer_data[11] = 4   # page_size_kb
        footer_data[12] = 4   # offset_bytes
        footer_data[13] = 4   # size_bytes
        footer_data[14] = 16  # ekey_length
        footer_data[15] = 8   # footer_hash_bytes

        # Valid archive index
        assert is_obj(bytes(footer_data))

        # Invalid data
        assert not is_obj(b'invalid')
        assert not is_obj(b'')
        assert not is_obj(b'\x00' * 20)  # Too short

        # Invalid footer values
        invalid_footer = footer_data.copy()
        invalid_footer[8] = 2  # Wrong version
        assert not is_obj(bytes(invalid_footer))

    def test_parse_footer_basic(self):
        """Test parsing basic archive index footer."""
        # Create test footer
        footer_data = bytearray(28)
        footer_data[0:8] = b'\x01' * 8      # toc_hash
        footer_data[8] = 1                  # version
        footer_data[9:11] = b'\x00\x00'     # reserved
        footer_data[11] = 4                 # page_size_kb
        footer_data[12] = 4                 # offset_bytes
        footer_data[13] = 4                 # size_bytes
        footer_data[14] = 16                # ekey_length
        footer_data[15] = 8                 # footer_hash_bytes
        footer_data[16:20] = struct.pack('<I', 2)  # element_count (little-endian)
        footer_data[20:28] = b'\x02' * 8    # footer_hash

        # Create complete archive index data (chunks + toc + footer)
        chunk_data = b'\x00' * (4096 * 2)  # Two empty chunks
        toc_data = b'\x00' * (9 * 2)       # Two TOC entries
        archive_data = chunk_data + toc_data + footer_data

        parser = ArchiveIndexParser()
        archive_index = parser.parse(bytes(archive_data))

        # Verify footer
        footer = archive_index.footer
        assert footer.toc_hash == b'\x01' * 8
        assert footer.version == 1
        assert footer.reserved == b'\x00\x00'
        assert footer.page_size_kb == 4
        assert footer.offset_bytes == 4
        assert footer.size_bytes == 4
        assert footer.ekey_length == 16
        assert footer.footer_hash_bytes == 8
        assert footer.element_count == 2
        assert footer.footer_hash == b'\x02' * 8

    def test_parse_single_chunk_with_entries(self):
        """Test parsing single chunk with entries."""
        # Create test entries
        entry1_ekey = b'\x01' * 9
        entry1_offset = 1000
        entry1_size = 2000

        entry2_ekey = b'\x02' * 9
        entry2_offset = 3000
        entry2_size = 4000

        # Build chunk data
        chunk_data = bytearray(4096)

        # Entry 1
        chunk_data[0:9] = entry1_ekey
        chunk_data[9:13] = struct.pack('>I', entry1_offset)
        chunk_data[13:17] = struct.pack('>I', entry1_size)
        # 7 bytes reserved (already zero)

        # Entry 2
        chunk_data[24:33] = entry2_ekey
        chunk_data[33:37] = struct.pack('>I', entry2_offset)
        chunk_data[37:41] = struct.pack('>I', entry2_size)

        # Create TOC (last key of each chunk)
        toc_data = entry2_ekey  # Only one chunk

        # Create footer
        footer_data = bytearray(28)
        footer_data[8] = 1                  # version
        footer_data[11] = 4                 # page_size_kb
        footer_data[12] = 4                 # offset_bytes
        footer_data[13] = 4                 # size_bytes
        footer_data[14] = 16                # ekey_length
        footer_data[15] = 8                 # footer_hash_bytes
        footer_data[16:20] = struct.pack('<I', 1)  # element_count

        # Build complete archive index
        archive_data = chunk_data + toc_data + footer_data

        parser = ArchiveIndexParser()
        archive_index = parser.parse(bytes(archive_data))

        # Verify parsing
        assert len(archive_index.chunks) == 1
        chunk = archive_index.chunks[0]

        assert chunk.chunk_index == 0
        assert len(chunk.entries) == 2
        assert chunk.last_key == entry2_ekey

        # Verify entries
        assert chunk.entries[0].ekey == entry1_ekey
        assert chunk.entries[0].offset == entry1_offset
        assert chunk.entries[0].size == entry1_size

        assert chunk.entries[1].ekey == entry2_ekey
        assert chunk.entries[1].offset == entry2_offset
        assert chunk.entries[1].size == entry2_size

        # Verify TOC
        assert len(archive_index.toc) == 1
        assert archive_index.toc[0] == entry2_ekey

    def test_parse_multiple_chunks(self):
        """Test parsing multiple chunks."""
        # Create two chunks with one entry each
        chunk1_data = bytearray(4096)
        chunk1_ekey = b'\x11' * 9
        chunk1_data[0:9] = chunk1_ekey
        chunk1_data[9:13] = struct.pack('>I', 1000)
        chunk1_data[13:17] = struct.pack('>I', 2000)

        chunk2_data = bytearray(4096)
        chunk2_ekey = b'\x22' * 9
        chunk2_data[0:9] = chunk2_ekey
        chunk2_data[9:13] = struct.pack('>I', 3000)
        chunk2_data[13:17] = struct.pack('>I', 4000)

        # Create TOC
        toc_data = chunk1_ekey + chunk2_ekey

        # Create footer
        footer_data = bytearray(28)
        footer_data[8] = 1                  # version
        footer_data[11] = 4                 # page_size_kb
        footer_data[12] = 4                 # offset_bytes
        footer_data[13] = 4                 # size_bytes
        footer_data[14] = 16                # ekey_length
        footer_data[15] = 8                 # footer_hash_bytes
        footer_data[16:20] = struct.pack('<I', 2)  # element_count

        # Build complete archive index
        archive_data = chunk1_data + chunk2_data + toc_data + footer_data

        parser = ArchiveIndexParser()
        archive_index = parser.parse(bytes(archive_data))

        # Verify parsing
        assert len(archive_index.chunks) == 2

        # Chunk 1
        chunk1 = archive_index.chunks[0]
        assert chunk1.chunk_index == 0
        assert len(chunk1.entries) == 1
        assert chunk1.entries[0].ekey == chunk1_ekey
        assert chunk1.last_key == chunk1_ekey

        # Chunk 2
        chunk2 = archive_index.chunks[1]
        assert chunk2.chunk_index == 1
        assert len(chunk2.entries) == 1
        assert chunk2.entries[0].ekey == chunk2_ekey
        assert chunk2.last_key == chunk2_ekey

        # Verify TOC
        assert len(archive_index.toc) == 2
        assert archive_index.toc[0] == chunk1_ekey
        assert archive_index.toc[1] == chunk2_ekey

    def test_find_entry(self):
        """Test finding entry by encoding key."""
        # Create archive index with test data
        entry1 = ArchiveIndexEntry(ekey=b'\x01' * 9, offset=1000, size=2000)
        entry2 = ArchiveIndexEntry(ekey=b'\x02' * 9, offset=3000, size=4000)

        chunk = ArchiveIndexChunk(
            chunk_index=0,
            entries=[entry1, entry2],
            last_key=b'\x02' * 9
        )

        footer = ArchiveIndexFooter(
            toc_hash=b'\x00' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=1,
            footer_hash=b'\x00' * 8
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[chunk],
            toc=[b'\x02' * 9]
        )

        parser = ArchiveIndexParser()

        # Find existing entry with truncated key
        found = parser.find_entry(archive_index, b'\x01' * 9)
        assert found is not None
        assert found.ekey == b'\x01' * 9
        assert found.offset == 1000

        # Find existing entry with full key (should truncate)
        found_full = parser.find_entry(archive_index, b'\x01' * 16)
        assert found_full is not None
        assert found_full.ekey == b'\x01' * 9

        # Find non-existent entry
        not_found = parser.find_entry(archive_index, b'\x99' * 9)
        assert not_found is None

    def test_find_entries_in_range(self):
        """Test finding entries within offset range."""
        # Create archive index with test data
        entry1 = ArchiveIndexEntry(ekey=b'\x01' * 9, offset=1000, size=500)
        entry2 = ArchiveIndexEntry(ekey=b'\x02' * 9, offset=2000, size=1000)
        entry3 = ArchiveIndexEntry(ekey=b'\x03' * 9, offset=5000, size=2000)

        chunk = ArchiveIndexChunk(
            chunk_index=0,
            entries=[entry1, entry2, entry3],
            last_key=b'\x03' * 9
        )

        footer = ArchiveIndexFooter(
            toc_hash=b'\x00' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=1,
            footer_hash=b'\x00' * 8
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[chunk],
            toc=[b'\x03' * 9]
        )

        parser = ArchiveIndexParser()

        # Find entries in range
        entries_in_range = parser.find_entries_in_range(archive_index, 1500, 3000)
        assert len(entries_in_range) == 1
        assert entries_in_range[0].offset == 2000

        # Find entries in wider range
        entries_wide = parser.find_entries_in_range(archive_index, 0, 10000)
        assert len(entries_wide) == 3

        # Find entries in empty range
        entries_empty = parser.find_entries_in_range(archive_index, 10000, 20000)
        assert len(entries_empty) == 0

    def test_validate_toc_hash(self):
        """Test TOC hash validation."""
        # Create test TOC
        toc_keys = [b'\x01' * 9, b'\x02' * 9]
        toc_data = b''.join(toc_keys)

        # Calculate actual hash
        md5_hash = hashlib.md5(toc_data).digest()
        expected_toc_hash = md5_hash[8:16]  # Upper 8 bytes

        # Create archive index
        footer = ArchiveIndexFooter(
            toc_hash=expected_toc_hash,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=2,
            footer_hash=b'\x00' * 8
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[],
            toc=toc_keys
        )

        parser = ArchiveIndexParser()

        # Valid hash should pass
        assert parser.validate_toc_hash(archive_index)

        # Invalid hash should fail
        archive_index.footer.toc_hash = b'\x99' * 8
        assert not parser.validate_toc_hash(archive_index)

    def test_validate_footer_hash(self):
        """Test footer hash validation."""
        # Create footer with known values
        footer = ArchiveIndexFooter(
            toc_hash=b'\x00' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=2,
            footer_hash=b'\x00' * 8  # Will be calculated
        )

        # Calculate expected footer hash
        data = bytearray(20)
        data[0] = 1              # version
        data[1:3] = b'\x00\x00'  # reserved
        data[3] = 4              # page_size_kb
        data[4] = 4              # offset_bytes
        data[5] = 4              # size_bytes
        data[6] = 16             # ekey_length
        data[7] = 8              # footer_hash_bytes
        data[8:12] = struct.pack('<I', 2)  # element_count

        md5_hash = hashlib.md5(data).digest()
        expected_footer_hash = md5_hash[:8]  # Lower 8 bytes

        footer.footer_hash = expected_footer_hash

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[],
            toc=[]
        )

        parser = ArchiveIndexParser()

        # Valid hash should pass
        assert parser.validate_footer_hash(archive_index)

        # Invalid hash should fail
        archive_index.footer.footer_hash = b'\x99' * 8
        assert not parser.validate_footer_hash(archive_index)

    def test_get_statistics(self):
        """Test getting archive index statistics."""
        # Create archive index with test data
        entry1 = ArchiveIndexEntry(ekey=b'\x01' * 9, offset=1000, size=500)
        entry2 = ArchiveIndexEntry(ekey=b'\x02' * 9, offset=2000, size=1000)

        chunk1 = ArchiveIndexChunk(
            chunk_index=0,
            entries=[entry1, entry2],
            last_key=b'\x02' * 9
        )

        chunk2 = ArchiveIndexChunk(
            chunk_index=1,
            entries=[],  # Empty chunk
            last_key=b''
        )

        footer = ArchiveIndexFooter(
            toc_hash=b'\x00' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=2,
            footer_hash=b'\x00' * 8
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[chunk1, chunk2],
            toc=[b'\x02' * 9, b'']
        )

        parser = ArchiveIndexParser()
        stats = parser.get_statistics(archive_index)

        assert stats['total_chunks'] == 2
        assert stats['non_empty_chunks'] == 1
        assert stats['total_entries'] == 2
        assert stats['entries_per_chunk'] == 1.0
        assert stats['min_entry_size'] == 500
        assert stats['max_entry_size'] == 1000
        assert stats['avg_entry_size'] == 750.0

    def test_round_trip(self):
        """Test round-trip parsing and building."""
        # Create test data
        entry = ArchiveIndexEntry(ekey=b'\x05' * 9, offset=12345, size=67890)

        chunk = ArchiveIndexChunk(
            chunk_index=0,
            entries=[entry],
            last_key=b'\x05' * 9
        )

        footer = ArchiveIndexFooter(
            toc_hash=b'\x11' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=1,
            footer_hash=b'\x22' * 8
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[chunk],
            toc=[b'\x05' * 9]
        )

        # Build and parse back
        parser = ArchiveIndexParser()
        binary_data = parser.build(archive_index)
        parsed_index = parser.parse(binary_data)

        # Verify round trip
        assert parsed_index.footer.version == archive_index.footer.version
        assert parsed_index.footer.element_count == archive_index.footer.element_count

        assert len(parsed_index.chunks) == 1
        parsed_chunk = parsed_index.chunks[0]
        original_chunk = archive_index.chunks[0]

        assert len(parsed_chunk.entries) == 1
        parsed_entry = parsed_chunk.entries[0]
        original_entry = original_chunk.entries[0]

        assert parsed_entry.ekey == original_entry.ekey
        assert parsed_entry.offset == original_entry.offset
        assert parsed_entry.size == original_entry.size

    def test_invalid_data_size(self):
        """Test error handling for invalid data size."""
        # Too short for footer
        short_data = b'\x00' * 20

        parser = ArchiveIndexParser()
        with pytest.raises(ValueError, match="Data too short for footer"):
            parser.parse(short_data)

    def test_invalid_chunk_structure(self):
        """Test error handling for invalid chunk structure."""
        # Create data with invalid chunk structure
        invalid_chunk_data = b'\x00' * 1000  # Not multiple of 4096

        # Create footer
        footer_data = bytearray(28)
        footer_data[8] = 1                  # version
        footer_data[11] = 4                 # page_size_kb
        footer_data[12] = 4                 # offset_bytes
        footer_data[13] = 4                 # size_bytes
        footer_data[14] = 16                # ekey_length
        footer_data[15] = 8                 # footer_hash_bytes
        footer_data[16:20] = struct.pack('<I', 1)  # element_count

        # No TOC data
        archive_data = invalid_chunk_data + footer_data

        parser = ArchiveIndexParser()
        with pytest.raises(ValueError, match="Invalid archive index block structure"):
            parser.parse(archive_data)

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        # Create test archive index file
        chunk_data = b'\x00' * 4096  # Empty chunk
        toc_data = b'\x00' * 9       # Empty TOC entry

        footer_data = bytearray(28)
        footer_data[8] = 1           # version
        footer_data[11] = 4          # page_size_kb
        footer_data[12] = 4          # offset_bytes
        footer_data[13] = 4          # size_bytes
        footer_data[14] = 16         # ekey_length
        footer_data[15] = 8          # footer_hash_bytes
        footer_data[16:20] = struct.pack('<I', 1)  # element_count

        archive_data = chunk_data + toc_data + footer_data

        test_file = tmp_path / "test.index"
        test_file.write_bytes(archive_data)

        # Parse from file
        parser = ArchiveIndexParser()
        archive_index = parser.parse_file(str(test_file))

        assert archive_index.footer.version == 1
        assert len(archive_index.chunks) == 1


class TestArchiveIndexModels:
    """Test archive index Pydantic models."""

    def test_archive_index_entry_model(self):
        """Test ArchiveIndexEntry model."""
        entry = ArchiveIndexEntry(
            ekey=b'\xaa' * 9,
            offset=12345,
            size=67890
        )

        assert entry.ekey == b'\xaa' * 9
        assert entry.offset == 12345
        assert entry.size == 67890

    def test_archive_index_footer_model(self):
        """Test ArchiveIndexFooter model."""
        footer = ArchiveIndexFooter(
            toc_hash=b'\x11' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=5,
            footer_hash=b'\x22' * 8
        )

        assert footer.toc_hash == b'\x11' * 8
        assert footer.version == 1
        assert footer.reserved == b'\x00\x00'
        assert footer.page_size_kb == 4
        assert footer.element_count == 5
        assert footer.footer_hash == b'\x22' * 8

    def test_archive_index_chunk_model(self):
        """Test ArchiveIndexChunk model."""
        entries = [
            ArchiveIndexEntry(ekey=b'\x01' * 9, offset=1000, size=500),
            ArchiveIndexEntry(ekey=b'\x02' * 9, offset=2000, size=1000)
        ]

        chunk = ArchiveIndexChunk(
            chunk_index=3,
            entries=entries,
            last_key=b'\x02' * 9
        )

        assert chunk.chunk_index == 3
        assert len(chunk.entries) == 2
        assert chunk.last_key == b'\x02' * 9
        assert chunk.entries[0].offset == 1000
        assert chunk.entries[1].size == 1000

    def test_archive_index_model(self):
        """Test complete ArchiveIndex model."""
        footer = ArchiveIndexFooter(
            toc_hash=b'\x11' * 8,
            version=1,
            reserved=b'\x00\x00',
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            ekey_length=16,
            footer_hash_bytes=8,
            element_count=1,
            footer_hash=b'\x22' * 8
        )

        chunk = ArchiveIndexChunk(
            chunk_index=0,
            entries=[ArchiveIndexEntry(ekey=b'\x05' * 9, offset=1000, size=500)],
            last_key=b'\x05' * 9
        )

        archive_index = ArchiveIndex(
            footer=footer,
            chunks=[chunk],
            toc=[b'\x05' * 9]
        )

        assert archive_index.footer.version == 1
        assert len(archive_index.chunks) == 1
        assert len(archive_index.toc) == 1
        assert archive_index.chunks[0].chunk_index == 0
        assert archive_index.toc[0] == b'\x05' * 9
