"""Tests for BLTE format parser."""

import struct
import zlib
from io import BytesIO

import pytest

from cascette_tools.core.types import CompressionMode, EncryptionType
from cascette_tools.formats.blte import (
    BLTEChunk,
    BLTEFile,
    BLTEHeader,
    BLTEParser,
    TACTKeyStore,
    decompress_blte,
    is_blte,
)


class TestBLTEParser:
    """Test BLTE format parser."""

    def test_is_blte_function(self):
        """Test is_blte detection function."""
        # Valid BLTE data
        assert is_blte(b'BLTE\x00\x00\x00\x00')

        # Invalid data
        assert not is_blte(b'TEST')
        assert not is_blte(b'BLT')
        assert not is_blte(b'')

    def test_single_chunk_no_compression(self):
        """Test parsing single chunk with no compression."""
        # Create test data: BLTE magic + header size 0 + compression mode 'N' + data
        test_data = b'Hello, World!'
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'N' + test_data

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)

        # Verify header
        assert blte_file.header.magic == b'BLTE'
        assert blte_file.header.header_size == 0
        assert blte_file.header.is_single_chunk()
        assert blte_file.header.flags is None
        assert blte_file.header.chunk_count is None

        # Verify chunks
        assert len(blte_file.chunks) == 1
        chunk = blte_file.chunks[0]
        assert chunk.compression_mode == CompressionMode.NONE
        assert chunk.data == test_data

        # Test decompression
        decompressed = parser.decompress(blte_file)
        assert decompressed == test_data

    def test_single_chunk_zlib_compression(self):
        """Test parsing single chunk with zlib compression."""
        # Create test data
        original_data = b'Hello, World! This is a longer message for compression.'
        compressed_data = zlib.compress(original_data)
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'Z' + compressed_data

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)

        # Verify parsing
        assert blte_file.header.is_single_chunk()
        assert len(blte_file.chunks) == 1
        chunk = blte_file.chunks[0]
        assert chunk.compression_mode == CompressionMode.ZLIB
        assert chunk.data == compressed_data

        # Test decompression
        decompressed = parser.decompress(blte_file)
        assert decompressed == original_data

    def test_multi_chunk_file(self):
        """Test parsing multi-chunk file."""
        # Create test chunks
        chunk1_data = b'First chunk data'
        chunk2_data = b'Second chunk data'

        # Build BLTE file manually
        # Header: magic + header_size + flags + chunk_count + chunk_info_table
        chunk_count = 2
        flags = 0x0F

        # Calculate header size: 1 (flags) + 3 (chunk_count) + 2 * (4+4+16) (chunk_info)
        header_size = 1 + 3 + 2 * (4 + 4 + 16)

        # Chunk info
        chunk1_compressed_size = 1 + len(chunk1_data)  # +1 for compression mode
        chunk1_decompressed_size = len(chunk1_data)
        chunk1_checksum = b'\x01' * 16  # Dummy checksum

        chunk2_compressed_size = 1 + len(chunk2_data)
        chunk2_decompressed_size = len(chunk2_data)
        chunk2_checksum = b'\x02' * 16

        # Build BLTE data
        blte_data = BytesIO()
        blte_data.write(b'BLTE')
        blte_data.write(struct.pack('>I', header_size))
        blte_data.write(struct.pack('B', flags))
        blte_data.write(struct.pack('>I', chunk_count)[1:])  # 24-bit

        # Chunk info table
        blte_data.write(struct.pack('>I', chunk1_compressed_size))
        blte_data.write(struct.pack('>I', chunk1_decompressed_size))
        blte_data.write(chunk1_checksum)

        blte_data.write(struct.pack('>I', chunk2_compressed_size))
        blte_data.write(struct.pack('>I', chunk2_decompressed_size))
        blte_data.write(chunk2_checksum)

        # Chunk data
        blte_data.write(b'N' + chunk1_data)
        blte_data.write(b'N' + chunk2_data)

        # Parse
        parser = BLTEParser()
        blte_file = parser.parse(blte_data.getvalue())

        # Verify header
        assert not blte_file.header.is_single_chunk()
        assert blte_file.header.header_size == header_size
        assert blte_file.header.flags == flags
        assert blte_file.header.chunk_count == chunk_count

        # Verify chunks
        assert len(blte_file.chunks) == 2

        chunk1 = blte_file.chunks[0]
        assert chunk1.compression_mode == CompressionMode.NONE
        assert chunk1.data == chunk1_data
        assert chunk1.compressed_size == chunk1_compressed_size
        assert chunk1.decompressed_size == chunk1_decompressed_size
        assert chunk1.checksum == chunk1_checksum

        chunk2 = blte_file.chunks[1]
        assert chunk2.compression_mode == CompressionMode.NONE
        assert chunk2.data == chunk2_data
        assert chunk2.compressed_size == chunk2_compressed_size
        assert chunk2.decompressed_size == chunk2_decompressed_size
        assert chunk2.checksum == chunk2_checksum

        # Test decompression
        decompressed = parser.decompress(blte_file)
        assert decompressed == chunk1_data + chunk2_data

    def test_encrypted_chunk_without_crypto(self):
        """Test encrypted chunk handling without crypto library."""
        # Create encrypted chunk data
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + struct.pack('B', EncryptionType.SALSA20.value) + b'\x01' * 8 + b'encrypted_data'

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)

        # Verify parsing
        assert len(blte_file.chunks) == 1
        chunk = blte_file.chunks[0]
        assert chunk.compression_mode == CompressionMode.ENCRYPTED
        assert chunk.encryption_type == EncryptionType.SALSA20
        assert chunk.encryption_key_name == b'\x01' * 8
        assert chunk.data == b'encrypted_data'

        # Test decompression should fail without crypto library
        with pytest.raises(ValueError, match="Encryption support not available"):
            parser.decompress(blte_file)

    def test_round_trip_single_chunk(self):
        """Test round-trip parsing and building for single chunk."""
        original_data = b'Test data for round trip'

        # Create BLTE file structure
        header = BLTEHeader(magic=b'BLTE', header_size=0)
        chunk = BLTEChunk(
            compressed_size=len(original_data) + 1,
            decompressed_size=len(original_data),
            checksum=b'',
            compression_mode=CompressionMode.NONE,
            data=original_data
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])

        # Build binary data
        parser = BLTEParser()
        binary_data = parser.build(blte_file)

        # Parse back
        parsed_file = parser.parse(binary_data)

        # Verify round trip
        assert parsed_file.header.magic == blte_file.header.magic
        assert parsed_file.header.header_size == blte_file.header.header_size
        assert len(parsed_file.chunks) == len(blte_file.chunks)
        assert parsed_file.chunks[0].compression_mode == blte_file.chunks[0].compression_mode
        assert parsed_file.chunks[0].data == blte_file.chunks[0].data

    def test_round_trip_multi_chunk(self):
        """Test round-trip parsing and building for multi-chunk."""
        chunk1_data = b'First chunk'
        chunk2_data = b'Second chunk'

        # Create BLTE file structure
        header = BLTEHeader(
            magic=b'BLTE',
            header_size=1 + 3 + 2 * (4 + 4 + 16),  # flags + chunk_count + 2 chunk_infos
            flags=0x0F,
            chunk_count=2
        )

        chunk1 = BLTEChunk(
            compressed_size=len(chunk1_data) + 1,
            decompressed_size=len(chunk1_data),
            checksum=b'\x01' * 16,
            compression_mode=CompressionMode.NONE,
            data=chunk1_data
        )

        chunk2 = BLTEChunk(
            compressed_size=len(chunk2_data) + 1,
            decompressed_size=len(chunk2_data),
            checksum=b'\x02' * 16,
            compression_mode=CompressionMode.NONE,
            data=chunk2_data
        )

        blte_file = BLTEFile(header=header, chunks=[chunk1, chunk2])

        # Build and parse back
        parser = BLTEParser()
        binary_data = parser.build(blte_file)
        parsed_file = parser.parse(binary_data)

        # Verify round trip
        assert parsed_file.header.header_size == blte_file.header.header_size
        assert parsed_file.header.flags == blte_file.header.flags
        assert parsed_file.header.chunk_count == blte_file.header.chunk_count
        assert len(parsed_file.chunks) == 2

        for _i, (original, parsed) in enumerate(zip(blte_file.chunks, parsed_file.chunks, strict=False)):
            assert parsed.compression_mode == original.compression_mode
            assert parsed.data == original.data
            assert parsed.compressed_size == original.compressed_size
            assert parsed.decompressed_size == original.decompressed_size
            assert parsed.checksum == original.checksum

    def test_invalid_magic(self):
        """Test error handling for invalid magic."""
        invalid_data = b'TEST\x00\x00\x00\x00'

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Invalid BLTE magic"):
            parser.parse(invalid_data)

    def test_incomplete_header(self):
        """Test error handling for incomplete header."""
        incomplete_data = b'BLTE\x00\x00'  # Missing header size bytes

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete header size"):
            parser.parse(incomplete_data)

    def test_incomplete_chunk_info(self):
        """Test error handling for incomplete chunk info."""
        # Multi-chunk with incomplete chunk info
        blte_data = b'BLTE' + struct.pack('>I', 28) + struct.pack('B', 0x0F) + struct.pack('>I', 1)[1:] + b'\x00\x00'  # Incomplete chunk info

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete chunk info"):
            parser.parse(blte_data)

    def test_unknown_compression_mode(self):
        """Test error handling for unknown compression mode."""
        # Single chunk with unknown compression mode
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'X' + b'test_data'

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Unknown compression mode"):
            parser.parse(blte_data)

    def test_convenience_function(self):
        """Test convenience decompress_blte function."""
        original_data = b'Test data'
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'N' + original_data

        decompressed = decompress_blte(blte_data)
        assert decompressed == original_data

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        # Create test BLTE file
        original_data = b'Test file data'
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'N' + original_data

        test_file = tmp_path / "test.blte"
        test_file.write_bytes(blte_data)

        # Parse from file
        parser = BLTEParser()
        blte_file = parser.parse_file(str(test_file))

        assert blte_file.header.is_single_chunk()
        assert len(blte_file.chunks) == 1
        assert blte_file.chunks[0].data == original_data

        # Test decompression
        decompressed = parser.decompress(blte_file)
        assert decompressed == original_data

    def test_write_file(self, tmp_path):
        """Test writing to file."""
        # Create BLTE file structure
        original_data = b'Test write data'
        header = BLTEHeader(magic=b'BLTE', header_size=0)
        chunk = BLTEChunk(
            compressed_size=len(original_data) + 1,
            decompressed_size=len(original_data),
            checksum=b'',
            compression_mode=CompressionMode.NONE,
            data=original_data
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])

        # Write to file
        parser = BLTEParser()
        test_file = tmp_path / "output.blte"
        parser.build_file(blte_file, str(test_file))

        # Verify file contents
        written_data = test_file.read_bytes()
        expected_data = b'BLTE' + struct.pack('>I', 0) + b'N' + original_data
        assert written_data == expected_data


class TestTACTKeyStore:
    """Test TACT key store."""

    def test_add_and_get_key(self):
        """Test adding and retrieving keys."""
        store = TACTKeyStore()
        key_name = b'testkey1'
        key_value = b'0123456789abcdef'

        # Add key
        store.add_key(key_name, key_value)

        # Retrieve key
        retrieved = store.get_key(key_name)
        assert retrieved == key_value

        # Non-existent key
        assert store.get_key(b'notfound') is None

    def test_multiple_keys(self):
        """Test managing multiple keys."""
        store = TACTKeyStore()

        keys = {
            b'key1': b'value1',
            b'key2': b'value2',
            b'key3': b'value3',
        }

        # Add all keys
        for name, value in keys.items():
            store.add_key(name, value)

        # Verify all keys
        for name, expected_value in keys.items():
            assert store.get_key(name) == expected_value


class TestBLTEModels:
    """Test BLTE Pydantic models."""

    def test_blte_header_single_chunk(self):
        """Test BLTEHeader model for single chunk."""
        header = BLTEHeader(magic=b'BLTE', header_size=0)
        assert header.is_single_chunk()
        assert header.flags is None
        assert header.chunk_count is None

    def test_blte_header_multi_chunk(self):
        """Test BLTEHeader model for multi-chunk."""
        header = BLTEHeader(
            magic=b'BLTE',
            header_size=28,
            flags=0x0F,
            chunk_count=2
        )
        assert not header.is_single_chunk()
        assert header.flags == 0x0F
        assert header.chunk_count == 2

    def test_blte_chunk_basic(self):
        """Test BLTEChunk model."""
        chunk = BLTEChunk(
            compressed_size=100,
            decompressed_size=200,
            checksum=b'\x01' * 16,
            compression_mode=CompressionMode.ZLIB,
            data=b'test data'
        )

        assert chunk.compressed_size == 100
        assert chunk.decompressed_size == 200
        assert chunk.checksum == b'\x01' * 16
        assert chunk.compression_mode == CompressionMode.ZLIB
        assert chunk.data == b'test data'
        assert chunk.encryption_type is None
        assert chunk.encryption_key_name is None

    def test_blte_chunk_encrypted(self):
        """Test BLTEChunk model with encryption."""
        chunk = BLTEChunk(
            compressed_size=100,
            decompressed_size=200,
            checksum=b'\x01' * 16,
            compression_mode=CompressionMode.ENCRYPTED,
            data=b'encrypted data',
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=b'testkey1'
        )

        assert chunk.compression_mode == CompressionMode.ENCRYPTED
        assert chunk.encryption_type == EncryptionType.SALSA20
        assert chunk.encryption_key_name == b'testkey1'

    def test_blte_file_complete(self):
        """Test complete BLTEFile model."""
        header = BLTEHeader(magic=b'BLTE', header_size=0)
        chunk = BLTEChunk(
            compressed_size=10,
            decompressed_size=10,
            checksum=b'',
            compression_mode=CompressionMode.NONE,
            data=b'test data'
        )

        blte_file = BLTEFile(header=header, chunks=[chunk])
        assert blte_file.header == header
        assert len(blte_file.chunks) == 1
        assert blte_file.chunks[0] == chunk
