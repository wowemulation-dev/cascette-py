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

        # Calculate header size (on-disk includes preamble):
        # 8 (magic + header_size) + 1 (flags) + 3 (chunk_count) + 2 * (4+4+16) (chunk_info)
        header_size = 8 + 1 + 3 + 2 * (4 + 4 + 16)

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

    def test_encrypted_chunk_without_key(self):
        """Test encrypted chunk handling without matching TACT key.

        Wire format after 'E' mode byte:
          key_name_length(1=8) + key_name(8) + iv_length(1) + iv(iv_length) + algorithm(1) + payload
        """
        key_name = b'\x01' * 8
        iv = b'\x02' * 8
        # key_name_length=8, key_name, iv_length=8, iv, algorithm='S', payload
        enc_header = (
            struct.pack('B', 8) +         # key_name_length
            key_name +                     # key_name (8 bytes)
            struct.pack('B', 8) +          # iv_length
            iv +                           # iv (8 bytes)
            struct.pack('B', EncryptionType.SALSA20.value)  # algorithm = 'S'
        )
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + enc_header + b'encrypted_data'

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)

        # Verify parsing
        assert len(blte_file.chunks) == 1
        chunk = blte_file.chunks[0]
        assert chunk.compression_mode == CompressionMode.ENCRYPTED
        assert chunk.encryption_type == EncryptionType.SALSA20
        assert chunk.encryption_key_name == key_name
        assert chunk.encryption_iv == iv
        assert chunk.data == b'encrypted_data'

        # Decompression should fail when key is not in the key store
        with pytest.raises(ValueError, match="Encryption key not found"):
            parser.decompress(blte_file)

    def test_encrypted_chunk_invalid_key_name_length(self):
        """key_name_length must be exactly 8 per Agent.exe DecodeEncryption."""
        # key_name_length = 4 (wrong), key_name(8), iv_length(0), algorithm('S')
        bad_header = (
            struct.pack('B', 4) +         # key_name_length = 4 (not 8)
            b'\x01' * 8 +                  # key_name
            struct.pack('B', 0) +          # iv_length = 0
            struct.pack('B', EncryptionType.SALSA20.value)
        )
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + bad_header + b'data'

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Invalid key_name_length"):
            parser.parse(blte_data)

    def test_encrypted_chunk_invalid_iv_length(self):
        """iv_length must not exceed 8 per Agent.exe."""
        bad_header = (
            struct.pack('B', 8) +         # key_name_length = 8 (correct)
            b'\x01' * 8 +                  # key_name
            struct.pack('B', 9) +          # iv_length = 9 (too large)
            b'\x00' * 9 +                  # iv bytes
            struct.pack('B', EncryptionType.SALSA20.value)
        )
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + bad_header + b'data'

        parser = BLTEParser()
        with pytest.raises(ValueError, match="iv_length.*maximum"):
            parser.parse(blte_data)

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
            header_size=8 + 1 + 3 + 2 * (4 + 4 + 16),  # preamble + flags + chunk_count + 2 chunk_infos
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
            header_size=36,  # 8 (preamble) + 4 (flags+count) + 1 * 24 (chunk_info)
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


class TestBLTEParserErrorPaths:
    """Test BLTE parser truncated/error paths not covered by the main test class."""

    def _make_multi_chunk_prefix(self, flags: int, chunk_count: int) -> bytes:
        """Build a BLTE multi-chunk prefix up to (but not including) the chunk-info table."""
        header_size = 8 + 1 + 3 + chunk_count * 24
        return (
            b'BLTE'
            + struct.pack('>I', header_size)
            + struct.pack('B', flags)
            + struct.pack('>I', chunk_count)[1:]   # 24-bit chunk count
        )

    def test_truncated_flags_byte(self):
        """Parse error when flags byte is missing in multi-chunk header (line 151)."""
        # header_size > 0 but nothing follows the 8-byte preamble
        blte_data = b'BLTE' + struct.pack('>I', 12)  # header_size=12 (multi-chunk)
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete flags"):
            parser.parse(blte_data)

    def test_truncated_chunk_count(self):
        """Parse error when chunk-count bytes are missing in multi-chunk header (line 157)."""
        # header_size > 0, flags byte present, chunk-count bytes missing
        blte_data = b'BLTE' + struct.pack('>I', 12) + struct.pack('B', 0x0F)
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete chunk count"):
            parser.parse(blte_data)

    def test_incomplete_chunk_data(self):
        """Parse error when actual chunk payload is shorter than declared (line 209)."""
        prefix = self._make_multi_chunk_prefix(0x0F, 1)
        # Declare chunk compressed_size=100, but only write 5 payload bytes
        chunk_info = (
            struct.pack('>I', 100)  # compressed_size
            + struct.pack('>I', 50)  # decompressed_size
            + b'\x00' * 16           # checksum
        )
        blte_data = prefix + chunk_info + b'N' + b'x' * 4  # 5 bytes instead of 100
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete chunk data"):
            parser.parse(blte_data)

    def test_empty_single_chunk_data(self):
        """Parse error for single chunk with no bytes after compression byte (line 221)."""
        # header_size=0 + 'N' only — chunk_data after the mode byte is empty
        # (the check is if not data at the top of _parse_single_chunk, which requires zero bytes)
        # Pass a BLTE file with zero bytes after the magic+header_size
        blte_data = b'BLTE' + struct.pack('>I', 0)  # no mode byte at all → data=""
        parser = BLTEParser()
        # _parse_single_chunk gets called with b'' (the whole rest of stream after header)
        with pytest.raises(ValueError, match="Empty chunk data"):
            parser.parse(blte_data)

    def test_empty_multi_chunk_payload(self):
        """Parse error for multi-chunk chunk with zero declared compressed_size (line 247)."""
        prefix = self._make_multi_chunk_prefix(0x0F, 1)
        chunk_info = (
            struct.pack('>I', 0)    # compressed_size = 0 → empty data → _parse_chunk raises
            + struct.pack('>I', 0)  # decompressed_size
            + b'\x00' * 16          # checksum
        )
        blte_data = prefix + chunk_info  # no payload at all
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Empty chunk data"):
            parser.parse(blte_data)

    def test_unknown_compression_in_multi_chunk(self):
        """Parse error for unknown compression mode inside a multi-chunk chunk (line 259-260)."""
        prefix = self._make_multi_chunk_prefix(0x0F, 1)
        payload = b'X' + b'data'  # 'X' is not a valid CompressionMode
        chunk_info = (
            struct.pack('>I', len(payload))
            + struct.pack('>I', 4)
            + b'\x00' * 16
        )
        blte_data = prefix + chunk_info + payload
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Unknown compression mode"):
            parser.parse(blte_data)

    def test_extended_format_with_decompressed_checksums(self):
        """Extended format (flags=0x10) stores MD5 for both compressed and decompressed data."""
        import hashlib
        data1 = b'hello world'
        data2 = b'second chunk'
        chunk_count = 2
        # Extended format has 40 bytes per chunk-info (vs 24 for standard)
        header_size = 8 + 1 + 3 + chunk_count * 40

        blte_data = BytesIO()
        blte_data.write(b'BLTE')
        blte_data.write(struct.pack('>I', header_size))
        blte_data.write(struct.pack('B', 0x10))          # extended flags
        blte_data.write(struct.pack('>I', chunk_count)[1:])

        for raw in (data1, data2):
            payload = b'N' + raw
            blte_data.write(struct.pack('>I', len(payload)))
            blte_data.write(struct.pack('>I', len(raw)))
            blte_data.write(hashlib.md5(payload).digest())      # compressed checksum
            blte_data.write(hashlib.md5(raw).digest())          # decompressed checksum

        blte_data.write(b'N' + data1)
        blte_data.write(b'N' + data2)

        parser = BLTEParser()
        blte_file = parser.parse(blte_data.getvalue())

        assert blte_file.header.flags == 0x10
        assert len(blte_file.chunks) == 2
        assert blte_file.chunks[0].decompressed_checksum is not None
        assert blte_file.chunks[1].decompressed_checksum is not None

        decompressed = parser.decompress(blte_file)
        assert decompressed == data1 + data2

    def test_zlib_decompression_failure(self):
        """Corrupt zlib data inside a BLTE chunk raises ValueError."""
        bad_zlib = b'Z' + b'\xFF' * 20  # 'Z' mode + corrupt zlib stream
        blte_data = b'BLTE' + struct.pack('>I', 0) + bad_zlib
        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        with pytest.raises(ValueError, match="(ZLIB|Failed to decompress)"):
            parser.decompress(blte_file)

    def test_encrypted_chunk_header_too_small(self):
        """Encrypted chunk with fewer than 11 header bytes raises ValueError."""
        # Only 5 bytes after 'E' — well below the 11-byte minimum
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + b'\x08\x01\x02\x03\x04'
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Encrypted chunk header too small"):
            parser.parse(blte_data)

    def test_encrypted_chunk_missing_algorithm_byte(self):
        """Encrypted chunk truncated before algorithm byte raises ValueError."""
        # key_name_length=8, key_name=8 bytes, iv_length=8, iv=8 bytes, but NO algorithm byte
        bad_header = (
            struct.pack('B', 8)     # key_name_length
            + b'\x01' * 8           # key_name
            + struct.pack('B', 8)   # iv_length
            + b'\x02' * 8           # iv (8 bytes, no algorithm byte follows)
        )
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + bad_header
        parser = BLTEParser()
        with pytest.raises(ValueError, match="truncated"):
            parser.parse(blte_data)


class TestBLTEBuilder:
    """Test BLTEBuilder class methods."""

    def test_create_single_chunk_no_compression(self):
        """BLTEBuilder.create_single_chunk produces a parseable single-chunk file."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'hello builder'
        blte_file = BLTEBuilder.create_single_chunk(data, CompressionMode.NONE)

        assert blte_file.header.is_single_chunk()
        assert len(blte_file.chunks) == 1
        assert blte_file.chunks[0].data == data

        # Round-trip via parser
        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_create_single_chunk_zlib(self):
        """BLTEBuilder.create_single_chunk with ZLIB compression round-trips."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'compress me ' * 20
        blte_file = BLTEBuilder.create_single_chunk(data, CompressionMode.ZLIB)

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_create_multi_chunk(self):
        """BLTEBuilder.create_multi_chunk produces a parseable multi-chunk file."""
        from cascette_tools.formats.blte import BLTEBuilder
        chunks_in = [
            (b'first chunk data', CompressionMode.NONE),
            (b'second chunk data', CompressionMode.NONE),
        ]
        blte_file = BLTEBuilder.create_multi_chunk(chunks_in)

        assert not blte_file.header.is_single_chunk()
        assert blte_file.header.chunk_count == 2
        assert blte_file.header.flags == 0x0F

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        result = parser.decompress(parsed)
        assert result == b'first chunk datasecond chunk data'

    def test_create_multi_chunk_zlib(self):
        """BLTEBuilder.create_multi_chunk with ZLIB compression round-trips."""
        from cascette_tools.formats.blte import BLTEBuilder
        raw = b'data to compress ' * 10
        chunks_in = [
            (raw, CompressionMode.ZLIB),
        ]
        blte_file = BLTEBuilder.create_multi_chunk(chunks_in)

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == raw

    def test_create_multi_chunk_extended(self):
        """BLTEBuilder.create_multi_chunk_extended uses flags=0x10 and stores dual checksums."""
        from cascette_tools.formats.blte import BLTEBuilder
        chunks_in = [
            (b'chunk one', CompressionMode.NONE),
            (b'chunk two', CompressionMode.NONE),
        ]
        blte_file = BLTEBuilder.create_multi_chunk_extended(chunks_in)

        assert blte_file.header.flags == 0x10
        assert blte_file.header.chunk_count == 2
        for chunk in blte_file.chunks:
            assert chunk.decompressed_checksum is not None

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        result = parser.decompress(parsed)
        assert result == b'chunk onechunk two'

    def test_builder_build_delegates_to_parser(self):
        """BLTEBuilder.build() produces same output as BLTEParser.build()."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'builder test'
        blte_file = BLTEBuilder.create_single_chunk(data)

        builder = BLTEBuilder()
        binary_builder = builder.build(blte_file)

        parser = BLTEParser()
        binary_parser = parser.build(blte_file)

        assert binary_builder == binary_parser

    def test_multi_chunk_missing_flags_raises(self):
        """build() raises ValueError when multi-chunk header is missing flags."""
        header = BLTEHeader(magic=b'BLTE', header_size=36, flags=None, chunk_count=1)
        chunk = BLTEChunk(
            compressed_size=5,
            decompressed_size=4,
            checksum=b'\x00' * 16,
            compression_mode=CompressionMode.NONE,
            data=b'test'
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])
        parser = BLTEParser()
        with pytest.raises(ValueError, match="missing flags or chunk count"):
            parser.build(blte_file)


class TestBLTEParserUncoveredPaths:
    """Test BLTE paths that need additional coverage."""

    def _make_multi_chunk_prefix(self, flags: int, chunk_count: int) -> bytes:
        header_size = 8 + 1 + 3 + chunk_count * 24
        return (
            b'BLTE'
            + struct.pack('>I', header_size)
            + struct.pack('B', flags)
            + struct.pack('>I', chunk_count)[1:]
        )

    def test_parse_chunks_null_chunk_count_raises(self):
        """_parse_chunks raises ValueError when multi-chunk header has no chunk_count."""
        parser = BLTEParser()
        # Call _parse_chunks directly with a crafted header that has no flags/chunk_count
        from io import BytesIO as _BytesIO
        bad_header = BLTEHeader(magic=b'BLTE', header_size=12, flags=None, chunk_count=None)
        stream = _BytesIO(b'')
        with pytest.raises(ValueError, match="Chunk count or flags not available"):
            parser._parse_chunks(stream, bad_header)

    def test_extended_format_incomplete_decomp_checksum(self):
        """Truncated decompressed checksum in extended format raises ValueError (line 200)."""
        # Build an extended-format (0x10) BLTE with a truncated decompressed checksum
        chunk_count = 1
        header_size = 8 + 1 + 3 + chunk_count * 40

        blte_data = BytesIO()
        blte_data.write(b'BLTE')
        blte_data.write(struct.pack('>I', header_size))
        blte_data.write(struct.pack('B', 0x10))          # extended flags
        blte_data.write(struct.pack('>I', chunk_count)[1:])

        # Write chunk info: comp_size(4) + decomp_size(4) + checksum(16) + TRUNCATED decomp_checksum
        blte_data.write(struct.pack('>I', 5))   # compressed_size
        blte_data.write(struct.pack('>I', 4))   # decompressed_size
        blte_data.write(b'\x00' * 16)           # checksum
        blte_data.write(b'\x00' * 8)            # only 8 bytes instead of 16 → truncated

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Incomplete decompressed checksum"):
            parser.parse(blte_data.getvalue())

    def test_encrypted_chunk_in_multi_chunk(self):
        """Encrypted chunk parsed correctly inside a multi-chunk file (line 254)."""
        key_name = b'\xAB' * 8
        iv = b'\xCD' * 8
        enc_header = (
            struct.pack('B', 8) + key_name
            + struct.pack('B', 8) + iv
            + struct.pack('B', EncryptionType.SALSA20.value)
        )
        encrypted_payload = b'fake_ciphertext'
        chunk_payload = b'E' + enc_header + encrypted_payload

        prefix = self._make_multi_chunk_prefix(0x0F, 1)
        chunk_info = (
            struct.pack('>I', len(chunk_payload))
            + struct.pack('>I', len(encrypted_payload))
            + b'\x00' * 16
        )
        blte_data = prefix + chunk_info + chunk_payload

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)

        assert len(blte_file.chunks) == 1
        chunk = blte_file.chunks[0]
        assert chunk.compression_mode == CompressionMode.ENCRYPTED
        assert chunk.encryption_key_name == key_name
        assert chunk.data == encrypted_payload

    def test_unknown_encryption_algorithm_raises(self):
        """Unknown encryption algorithm byte raises ValueError (lines 307-308)."""
        # Wire format: key_name_length(8) + key_name(8) + iv_length(0) + algorithm(0xFF = invalid)
        bad_enc = (
            struct.pack('B', 8) + b'\x01' * 8  # key_name
            + struct.pack('B', 0)              # iv_length = 0
            + struct.pack('B', 0xFF)           # algorithm = 0xFF (unknown)
        )
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + bad_enc + b'payload'

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Unknown encryption algorithm"):
            parser.parse(blte_data)

    def test_lz4_decompression(self):
        """LZ4 decompression in _decompress_block_data (lines 428-435)."""
        import lz4.block
        raw = b'lz4 test data ' * 10
        compressed = lz4.block.compress(raw)

        blte_data = b'BLTE' + struct.pack('>I', 0) + b'L' + compressed

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        assert blte_file.chunks[0].compression_mode == CompressionMode.LZ4

        decompressed = parser.decompress(blte_file)
        assert decompressed == raw

    def test_unsupported_decompression_mode_raises(self):
        """_decompress_block_data with ENCRYPTED mode raises ValueError (line 438-439)."""
        # Calling _decompress_block_data with ENCRYPTED mode directly raises
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Unsupported compression mode"):
            parser._decompress_block_data(CompressionMode.ENCRYPTED, b'test')

    def test_frame_decompression(self):
        """_decompress_frame correctly decodes nested frames (lines 443-473)."""
        # Frame format: frame_size(3 LE) + comp_type(1) + frame_data(frame_size-1)
        # Use NONE compression for simplicity
        frame_data = b'frame content'
        frame_size = 1 + len(frame_data)  # comp_type byte + data
        frame = (
            frame_size.to_bytes(3, 'little')   # 3-byte LE frame size
            + b'N'                              # CompressionMode.NONE
            + frame_data
        )

        blte_data = b'BLTE' + struct.pack('>I', 0) + b'F' + frame

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        assert blte_file.chunks[0].compression_mode == CompressionMode.FRAME

        decompressed = parser.decompress(blte_file)
        assert decompressed == frame_data

    def test_frame_decompression_multi_frame(self):
        """_decompress_frame handles multiple frames concatenated."""
        frame1_data = b'first frame'
        frame2_data = b'second frame'

        def make_frame(data: bytes) -> bytes:
            frame_size = 1 + len(data)
            return frame_size.to_bytes(3, 'little') + b'N' + data

        frame_blob = make_frame(frame1_data) + make_frame(frame2_data)
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'F' + frame_blob

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        decompressed = parser.decompress(blte_file)
        assert decompressed == frame1_data + frame2_data

    def test_frame_decompression_unknown_type_raises(self):
        """Unknown compression type inside a frame raises ValueError."""
        frame_size = 1 + 4  # comp_type + 4 data bytes
        frame = frame_size.to_bytes(3, 'little') + b'X' + b'data'
        blte_data = b'BLTE' + struct.pack('>I', 0) + b'F' + frame

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        with pytest.raises(ValueError, match="Unknown frame compression type"):
            parser.decompress(blte_file)

    def test_build_extended_null_checksum_written_as_zeros(self):
        """build() writes 16 zero bytes when decompressed_checksum is None in extended format (line 513)."""
        header = BLTEHeader(magic=b'BLTE', header_size=12 + 40, flags=0x10, chunk_count=1)
        chunk = BLTEChunk(
            compressed_size=5, decompressed_size=4,
            checksum=b'\x01' * 16,
            compression_mode=CompressionMode.NONE,
            data=b'test',
            decompressed_checksum=None,  # → should write 16 zeros
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])

        parser = BLTEParser()
        binary = parser.build(blte_file)

        # Re-parse to verify the extended format with null checksum
        parsed = parser.parse(binary)
        # decompressed_checksum was None → stored as b'\x00'*16
        assert parsed.chunks[0].decompressed_checksum == b'\x00' * 16

    def test_build_encrypted_chunk(self):
        """build() writes encryption header for encrypted chunks (lines 522-531)."""
        key_name = b'\x11' * 8
        iv = b'\x22' * 8
        payload = b'ciphertext'

        header = BLTEHeader(magic=b'BLTE', header_size=0)
        chunk = BLTEChunk(
            compressed_size=len(payload) + 1 + 8 + 8 + 1 + 1 + 1,
            decompressed_size=len(payload),
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=payload,
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=key_name,
            encryption_iv=iv,
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])

        parser = BLTEParser()
        binary = parser.build(blte_file)

        # Should re-parse without error
        parsed = parser.parse(binary)
        assert parsed.chunks[0].compression_mode == CompressionMode.ENCRYPTED
        assert parsed.chunks[0].encryption_key_name == key_name

    def test_build_encrypted_chunk_missing_type_raises(self):
        """build() raises ValueError when encrypted chunk has no encryption_type."""
        header = BLTEHeader(magic=b'BLTE', header_size=0)
        chunk = BLTEChunk(
            compressed_size=10, decompressed_size=4,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=b'test',
            encryption_type=None,  # Missing!
            encryption_key_name=b'\x00' * 8,
        )
        blte_file = BLTEFile(header=header, chunks=[chunk])

        parser = BLTEParser()
        with pytest.raises(ValueError, match="Encrypted chunk missing encryption info"):
            parser.build(blte_file)

    def test_decrypt_chunk_no_crypto_raises(self):
        """_decrypt_chunk raises ValueError when pycryptodome is not available."""
        import cascette_tools.formats.blte as blte_mod
        original = blte_mod.has_crypto

        blte_mod.has_crypto = False
        try:
            parser = BLTEParser()
            chunk = BLTEChunk(
                compressed_size=20, decompressed_size=10,
                checksum=b'',
                compression_mode=CompressionMode.ENCRYPTED,
                data=b'payload',
                encryption_type=EncryptionType.SALSA20,
                encryption_key_name=b'\x01' * 8,
                encryption_iv=b'\x02' * 8,
            )
            with pytest.raises(ValueError, match="Encryption support not available"):
                parser._decrypt_chunk(chunk)
        finally:
            blte_mod.has_crypto = original

    def test_decrypt_chunk_no_key_name_raises(self):
        """_decrypt_chunk raises ValueError when encryption_key_name is missing (line 373)."""
        parser = BLTEParser()
        chunk = BLTEChunk(
            compressed_size=20, decompressed_size=10,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=b'payload',
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=None,  # Missing!
        )
        with pytest.raises(ValueError, match="No encryption key name"):
            parser._decrypt_chunk(chunk)

    def test_decrypt_chunk_salsa20(self):
        """Full Salsa20 decrypt round-trip via _decrypt_chunk (lines 383-409)."""
        from Crypto.Cipher import Salsa20  # type: ignore[import-untyped]

        key_name = b'\x01' * 8
        key_value = b'\xAA' * 16    # 16-byte TACT key
        iv = b'\x02' * 8
        nonce = iv[:8]
        full_key = key_value * 2    # doubled to 32 bytes per agent behaviour

        plaintext = b'N' + b'hello salsa20 world'  # 'N' = inner NONE compression
        cipher = Salsa20.new(key=full_key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        store = TACTKeyStore()
        store.add_key(key_name, key_value)

        chunk = BLTEChunk(
            compressed_size=len(ciphertext), decompressed_size=len(plaintext) - 1,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=ciphertext,
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=key_name,
            encryption_iv=iv,
        )

        parser = BLTEParser(key_store=store)
        decrypted = parser._decrypt_chunk(chunk)
        assert decrypted == plaintext

    def test_decrypt_chunk_arc4(self):
        """Full ARC4 decrypt round-trip via _decrypt_chunk (lines 385-386, 413-417)."""
        from Crypto.Cipher import ARC4  # type: ignore[import-untyped]

        key_name = b'\x02' * 8
        key_value = b'\xBB' * 16
        plaintext = b'N' + b'hello arc4 world'

        cipher = ARC4.new(key_value)
        ciphertext = cipher.encrypt(plaintext)

        store = TACTKeyStore()
        store.add_key(key_name, key_value)

        chunk = BLTEChunk(
            compressed_size=len(ciphertext), decompressed_size=len(plaintext) - 1,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=ciphertext,
            encryption_type=EncryptionType.ARC4,
            encryption_key_name=key_name,
            encryption_iv=None,
        )

        parser = BLTEParser(key_store=store)
        decrypted = parser._decrypt_chunk(chunk)
        assert decrypted == plaintext

    def test_decrypt_chunk_unsupported_type_raises(self):
        """_decrypt_chunk raises ValueError for unsupported encryption type (lines 387-388)."""
        store = TACTKeyStore()
        store.add_key(b'\x01' * 8, b'\xAA' * 16)

        chunk = BLTEChunk(
            compressed_size=10, decompressed_size=5,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=b'payload',
            encryption_type=None,      # triggers the else branch
            encryption_key_name=b'\x01' * 8,
        )
        # Patch the encryption_type to a non-None invalid value by bypassing validation
        object.__setattr__(chunk, 'encryption_type', object())  # type: ignore[arg-type]

        parser = BLTEParser(key_store=store)
        with pytest.raises((ValueError, AttributeError)):
            parser._decrypt_chunk(chunk)

    def test_decompress_encrypted_chunk_full_flow(self):
        """Full encrypted→decompress flow via decompress() (lines 348-365)."""
        from Crypto.Cipher import Salsa20  # type: ignore[import-untyped]

        key_name = b'\x03' * 8
        key_value = b'\xCC' * 16
        iv = b'\x04' * 8
        nonce = iv[:8]
        full_key = key_value * 2

        raw_data = b'decompressed content'
        plaintext = b'N' + raw_data  # inner NONE compression

        cipher = Salsa20.new(key=full_key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        enc_header = (
            struct.pack('B', 8) + key_name
            + struct.pack('B', 8) + iv
            + struct.pack('B', EncryptionType.SALSA20.value)
        )

        blte_data = b'BLTE' + struct.pack('>I', 0) + b'E' + enc_header + ciphertext

        store = TACTKeyStore()
        store.add_key(key_name, key_value)

        parser = BLTEParser(key_store=store)
        blte_file = parser.parse(blte_data)
        decompressed = parser.decompress(blte_file)
        assert decompressed == raw_data

    def test_create_single_chunk_lz4(self):
        """BLTEBuilder.create_single_chunk with LZ4 compression (line 577)."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'lz4 builder test ' * 15

        blte_file = BLTEBuilder.create_single_chunk(data, CompressionMode.LZ4)
        assert blte_file.chunks[0].compression_mode == CompressionMode.LZ4

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_create_multi_chunk_lz4(self):
        """BLTEBuilder.create_multi_chunk with LZ4 compression (line 618)."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'multi lz4 chunk ' * 15
        chunks_in = [(data, CompressionMode.LZ4)]

        blte_file = BLTEBuilder.create_multi_chunk(chunks_in)
        assert blte_file.chunks[0].compression_mode == CompressionMode.LZ4

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_create_multi_chunk_extended_lz4(self):
        """BLTEBuilder.create_multi_chunk_extended with LZ4 (lines 665, 667)."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'extended lz4 chunk ' * 15
        chunks_in = [(data, CompressionMode.LZ4)]

        blte_file = BLTEBuilder.create_multi_chunk_extended(chunks_in)
        assert blte_file.header.flags == 0x10
        assert blte_file.chunks[0].compression_mode == CompressionMode.LZ4

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_create_multi_chunk_extended_zlib(self):
        """BLTEBuilder.create_multi_chunk_extended with ZLIB (line 664)."""
        from cascette_tools.formats.blte import BLTEBuilder
        data = b'extended zlib chunk ' * 20
        chunks_in = [(data, CompressionMode.ZLIB)]

        blte_file = BLTEBuilder.create_multi_chunk_extended(chunks_in)
        assert blte_file.header.flags == 0x10
        assert blte_file.chunks[0].compression_mode == CompressionMode.ZLIB

        parser = BLTEParser()
        binary = parser.build(blte_file)
        parsed = parser.parse(binary)
        assert parser.decompress(parsed) == data

    def test_decrypt_salsa20_wrong_key_length_raises(self):
        """_decrypt_salsa20 with non-16-byte key raises ValueError (line 400)."""
        parser = BLTEParser()
        with pytest.raises(ValueError, match="Salsa20 key must be 16 bytes"):
            parser._decrypt_salsa20(b'data', b'\xAA' * 32, b'\x00' * 8)  # 32-byte key (wrong)

    def test_lz4_decompression_failure(self):
        """Corrupt LZ4 data raises ValueError wrapping lz4 error (lines 434-435)."""
        corrupt_lz4 = b'L' + b'\xFF' * 20  # 'L' mode + corrupt lz4 stream
        blte_data = b'BLTE' + struct.pack('>I', 0) + corrupt_lz4

        parser = BLTEParser()
        blte_file = parser.parse(blte_data)
        with pytest.raises(ValueError, match="(LZ4 decompression failed|Failed to decompress)"):
            parser.decompress(blte_file)

    def test_decrypt_empty_result_returns_empty(self):
        """If decryption produces empty bytes, _decompress_chunk returns b'' (line 352)."""
        from Crypto.Cipher import Salsa20  # type: ignore[import-untyped]

        key_name = b'\x05' * 8
        key_value = b'\xEE' * 16
        iv = b'\x06' * 8
        nonce = iv[:8]
        full_key = key_value * 2

        # Encrypt empty bytes — cipher produces empty output
        cipher = Salsa20.new(key=full_key, nonce=nonce)
        ciphertext = cipher.encrypt(b'')  # empty plaintext

        store = TACTKeyStore()
        store.add_key(key_name, key_value)

        chunk = BLTEChunk(
            compressed_size=0, decompressed_size=0,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=ciphertext,
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=key_name,
            encryption_iv=iv,
        )

        parser = BLTEParser(key_store=store)
        result = parser._decompress_chunk(chunk)
        assert result == b''

    def test_decrypt_unknown_inner_mode_raises(self):
        """Unknown inner compression mode after decryption raises ValueError (lines 357-358)."""
        from Crypto.Cipher import Salsa20  # type: ignore[import-untyped]

        key_name = b'\x07' * 8
        key_value = b'\xFF' * 16
        iv = b'\x08' * 8
        nonce = iv[:8]
        full_key = key_value * 2

        # Encrypt 'X' + payload — 'X' is not a valid CompressionMode
        plaintext = b'X' + b'payload data'
        cipher = Salsa20.new(key=full_key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        store = TACTKeyStore()
        store.add_key(key_name, key_value)

        chunk = BLTEChunk(
            compressed_size=len(ciphertext), decompressed_size=len(plaintext) - 1,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=ciphertext,
            encryption_type=EncryptionType.SALSA20,
            encryption_key_name=key_name,
            encryption_iv=iv,
        )

        parser = BLTEParser(key_store=store)
        with pytest.raises(ValueError, match="Unknown inner compression mode"):
            parser._decompress_chunk(chunk)
