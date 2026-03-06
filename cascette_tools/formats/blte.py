"""BLTE (Block Table Encoded) format parser."""

from __future__ import annotations

import struct
import zlib
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.types import CompressionMode, EncryptionType
from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()

try:
    import lz4.block
    has_lz4 = True
except ImportError:
    lz4 = None  # type: ignore[assignment]
    has_lz4 = False

try:
    from Crypto.Cipher import ARC4, Salsa20  # type: ignore[import-untyped]
    has_crypto = True
    if TYPE_CHECKING:
        # Type stubs for crypto modules when type checking
        from typing import Protocol

        class CipherProtocol(Protocol):
            """Protocol for cipher objects."""
            def decrypt(self, data: bytes) -> bytes: ...

        class Salsa20Module(Protocol):
            """Protocol for Salsa20 module."""
            @staticmethod
            def new(key: bytes, nonce: bytes) -> CipherProtocol: ...

        class ARC4Module(Protocol):
            """Protocol for ARC4 module."""
            @staticmethod
            def new(key: bytes) -> CipherProtocol: ...
except ImportError:
    ARC4 = None  # type: ignore[assignment]
    Salsa20 = None  # type: ignore[assignment]
    has_crypto = False


class BLTEChunk(BaseModel):
    """BLTE chunk information."""

    compressed_size: int = Field(description="Compressed size")
    decompressed_size: int = Field(description="Decompressed size")
    checksum: bytes = Field(description="MD5 checksum of compressed data")
    decompressed_checksum: bytes | None = Field(default=None, description="MD5 checksum of decompressed data (extended format only)")
    compression_mode: CompressionMode = Field(description="Compression mode")
    data: bytes = Field(description="Chunk data")
    encryption_type: EncryptionType | None = Field(default=None, description="Encryption type")
    encryption_key_name: bytes | None = Field(default=None, description="Encryption key name (8 bytes)")
    encryption_iv: bytes | None = Field(default=None, description="Encryption IV (up to 8 bytes)")


class BLTEHeader(BaseModel):
    """BLTE file header."""

    magic: bytes = Field(description="Magic bytes (BLTE)")
    header_size: int = Field(description="Header size")
    flags: int | None = Field(default=None, description="Flags")
    chunk_count: int | None = Field(default=None, description="Number of chunks")

    def is_single_chunk(self) -> bool:
        """Check if this is a single chunk file."""
        return self.header_size == 0


class BLTEFile(BaseModel):
    """Complete BLTE file structure."""

    header: BLTEHeader = Field(description="File header")
    chunks: list[BLTEChunk] = Field(description="Data chunks")


class TACTKeyStore:
    """Simple TACT key store for encryption."""

    def __init__(self):
        self.keys: dict[bytes, bytes] = {}

    def add_key(self, key_name: bytes, key_value: bytes) -> None:
        """Add a TACT key to the store."""
        self.keys[key_name] = key_value

    def get_key(self, key_name: bytes) -> bytes | None:
        """Get a TACT key by name."""
        return self.keys.get(key_name)


class BLTEParser(FormatParser[BLTEFile]):
    """Parser for BLTE format."""

    BLTE_MAGIC = b'BLTE'
    ENCRYPTION_KEY_NAME_SIZE = 8

    def __init__(self, key_store: TACTKeyStore | None = None):
        """Initialize parser with optional key store."""
        self.key_store = key_store or TACTKeyStore()

    def parse(self, data: bytes | BinaryIO) -> BLTEFile:
        """Parse BLTE file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed BLTE file
        """
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Parse header
        header = self._parse_header(stream)

        # Parse chunks
        chunks = self._parse_chunks(stream, header)

        return BLTEFile(header=header, chunks=chunks)

    def _parse_header(self, stream: BinaryIO) -> BLTEHeader:
        """Parse BLTE header."""
        # Check BLTE magic
        magic = stream.read(4)
        if magic != self.BLTE_MAGIC:
            raise ValueError(f"Invalid BLTE magic: {magic}")

        # Read header size
        header_size_bytes = stream.read(4)
        if len(header_size_bytes) != 4:
            raise ValueError("Incomplete header size")
        header_size = struct.unpack('>I', header_size_bytes)[0]

        header = BLTEHeader(magic=magic, header_size=header_size)

        if header_size > 0:
            # Multi-chunk file with extended header
            flags_bytes = stream.read(1)
            if len(flags_bytes) != 1:
                raise ValueError("Incomplete flags")
            flags = flags_bytes[0]

            # Read chunk count (24-bit big-endian)
            chunk_count_bytes = stream.read(3)
            if len(chunk_count_bytes) != 3:
                raise ValueError("Incomplete chunk count")
            chunk_count = struct.unpack('>I', b'\x00' + chunk_count_bytes)[0]

            header.flags = flags
            header.chunk_count = chunk_count

        return header

    def _parse_chunks(self, stream: BinaryIO, header: BLTEHeader) -> list[BLTEChunk]:
        """Parse chunks from BLTE data."""
        chunks: list[BLTEChunk] = []

        if header.is_single_chunk():
            # Single chunk - read rest of stream
            chunk_data = stream.read()
            chunk = self._parse_single_chunk(chunk_data)
            chunks.append(chunk)
        else:
            # Multi-chunk file - read chunk info table first
            if header.chunk_count is None or header.flags is None:
                raise ValueError("Chunk count or flags not available")

            # Check if this is extended format (0x10) or standard format (0x0F)
            is_extended = header.flags == 0x10

            chunk_infos: list[tuple[int, int, bytes, bytes | None]] = []
            for _ in range(header.chunk_count):
                comp_size_bytes = stream.read(4)
                decomp_size_bytes = stream.read(4)
                checksum_bytes = stream.read(16)

                if len(comp_size_bytes) != 4 or len(decomp_size_bytes) != 4 or len(checksum_bytes) != 16:
                    raise ValueError("Incomplete chunk info")

                comp_size = struct.unpack('>I', comp_size_bytes)[0]
                decomp_size = struct.unpack('>I', decomp_size_bytes)[0]
                checksum = checksum_bytes

                # Read decompressed checksum if extended format
                decomp_checksum = None
                if is_extended:
                    decomp_checksum_bytes = stream.read(16)
                    if len(decomp_checksum_bytes) != 16:
                        raise ValueError("Incomplete decompressed checksum in extended format")
                    decomp_checksum = decomp_checksum_bytes

                chunk_infos.append((comp_size, decomp_size, checksum, decomp_checksum))

            # Read and parse chunks
            for comp_size, decomp_size, checksum, decomp_checksum in chunk_infos:
                chunk_data = stream.read(comp_size)
                if len(chunk_data) != comp_size:
                    raise ValueError(f"Incomplete chunk data: expected {comp_size}, got {len(chunk_data)}")

                chunk = self._parse_chunk(chunk_data, comp_size, decomp_size)
                chunk.checksum = checksum
                chunk.decompressed_checksum = decomp_checksum
                chunks.append(chunk)

        return chunks

    def _parse_single_chunk(self, data: bytes) -> BLTEChunk:
        """Parse single chunk without size info."""
        if not data:
            raise ValueError("Empty chunk data")

        mode_byte = data[0:1]
        chunk_data = data[1:]

        # Check if encrypted
        if mode_byte == CompressionMode.ENCRYPTED.encode():
            return self._parse_encrypted_chunk(chunk_data, len(data), 0)

        # Regular compression
        try:
            compression_mode = CompressionMode(mode_byte.decode())
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"Unknown compression mode: {mode_byte}") from e

        return BLTEChunk(
            compressed_size=len(data),
            decompressed_size=0,  # Unknown for single chunk
            checksum=b'',
            compression_mode=compression_mode,
            data=chunk_data
        )

    def _parse_chunk(self, data: bytes, comp_size: int, decomp_size: int) -> BLTEChunk:
        """Parse chunk with known sizes."""
        if not data:
            raise ValueError("Empty chunk data")

        mode_byte = data[0:1]
        chunk_data = data[1:]

        # Check if encrypted
        if mode_byte == CompressionMode.ENCRYPTED.encode():
            return self._parse_encrypted_chunk(chunk_data, comp_size, decomp_size)

        # Regular compression
        try:
            compression_mode = CompressionMode(mode_byte.decode())
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"Unknown compression mode: {mode_byte}") from e

        return BLTEChunk(
            compressed_size=comp_size,
            decompressed_size=decomp_size,
            checksum=b'',
            compression_mode=compression_mode,
            data=chunk_data
        )

    def _parse_encrypted_chunk(self, data: bytes, comp_size: int, decomp_size: int) -> BLTEChunk:
        """Parse encrypted chunk.

        Wire format after the leading 'E' mode byte (already consumed):
          [0]      key_name_length  (must be 8)
          [1..8]   key_name         (8 bytes)
          [9]      iv_length        (max 8)
          [10..]   iv               (iv_length bytes)
          [10+iv_length]  algorithm ('S' = Salsa20)
          [11+iv_length..] encrypted payload
        """
        # Minimum: key_name_length(1) + key_name(8) + iv_length(1) + algorithm(1) = 11
        if len(data) < 11:
            raise ValueError("Encrypted chunk header too small")

        key_name_length = data[0]
        if key_name_length != self.ENCRYPTION_KEY_NAME_SIZE:
            raise ValueError(
                f"Invalid key_name_length {key_name_length}: must be {self.ENCRYPTION_KEY_NAME_SIZE}"
            )

        key_name = data[1:1 + self.ENCRYPTION_KEY_NAME_SIZE]
        iv_length = data[1 + self.ENCRYPTION_KEY_NAME_SIZE]
        if iv_length > 8:
            raise ValueError(f"iv_length {iv_length} exceeds maximum of 8")

        header_end = 1 + self.ENCRYPTION_KEY_NAME_SIZE + 1 + iv_length
        if len(data) < header_end + 1:
            raise ValueError("Encrypted chunk header truncated (missing algorithm byte)")

        iv = data[1 + self.ENCRYPTION_KEY_NAME_SIZE + 1:header_end]
        # Zero-pad IV to 8 bytes (agent behaviour: read into zero-initialised buffer)
        iv = iv.ljust(8, b'\x00')

        algorithm_byte = data[header_end]
        try:
            encryption_type = EncryptionType(algorithm_byte)
        except ValueError as e:
            raise ValueError(f"Unknown encryption algorithm: {algorithm_byte:02x}") from e

        encrypted_data = data[header_end + 1:]

        return BLTEChunk(
            compressed_size=comp_size,
            decompressed_size=decomp_size,
            checksum=b'',
            compression_mode=CompressionMode.ENCRYPTED,
            data=encrypted_data,
            encryption_type=encryption_type,
            encryption_key_name=key_name,
            encryption_iv=iv,
        )

    def decompress(self, obj: BLTEFile) -> bytes:
        """Decompress BLTE file.

        Args:
            obj: Parsed BLTE file

        Returns:
            Decompressed data
        """
        result = BytesIO()

        for i, chunk in enumerate(obj.chunks):
            try:
                decompressed = self._decompress_chunk(chunk)
                result.write(decompressed)
            except Exception as e:
                raise ValueError(f"Failed to decompress chunk {i}: {e}") from e

        return result.getvalue()

    def _decompress_chunk(self, chunk: BLTEChunk) -> bytes:
        """Decompress individual chunk."""
        data = chunk.data

        # Handle encryption first
        if chunk.compression_mode == CompressionMode.ENCRYPTED:
            data = self._decrypt_chunk(chunk)
            # After decryption, parse inner compression type
            if len(data) == 0:
                return b''

            inner_mode_byte = data[0:1]
            try:
                compression_mode = CompressionMode(inner_mode_byte.decode())
            except (ValueError, UnicodeDecodeError) as e:
                raise ValueError(f"Unknown inner compression mode: {inner_mode_byte}") from e

            data = data[1:]  # Skip compression type byte
        else:
            compression_mode = chunk.compression_mode

        # Decompress based on compression mode
        return self._decompress_block_data(compression_mode, data)

    def _decrypt_chunk(self, chunk: BLTEChunk) -> bytes:
        """Decrypt an encrypted chunk using TACT keys."""
        if not has_crypto:
            raise ValueError("Encryption support not available - install pycryptodome")

        if not chunk.encryption_key_name:
            raise ValueError("No encryption key name provided")

        # Get encryption key from key store
        key = self.key_store.get_key(chunk.encryption_key_name)
        if not key:
            raise ValueError(f"Encryption key not found: {chunk.encryption_key_name.hex()}")

        iv = chunk.encryption_iv or b'\x00' * 8

        # Decrypt based on encryption type
        if chunk.encryption_type == EncryptionType.SALSA20:
            return self._decrypt_salsa20(chunk.data, key, iv)
        elif chunk.encryption_type == EncryptionType.ARC4:
            return self._decrypt_arc4(chunk.data, key)
        else:
            raise ValueError(f"Unsupported encryption type: {chunk.encryption_type}")

    def _decrypt_salsa20(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using Salsa20 stream cipher.

        The IV comes from the 'E' block header (not prepended to the ciphertext).
        Key is 16 bytes, doubled to 32 bytes for Salsa20's 256-bit key schedule
        (Tau constant: "expand 16-byte k").
        """
        if not has_crypto or Salsa20 is None:
            raise ValueError("Crypto support not available - install pycryptodome")
        if len(key) != 16:
            raise ValueError("Salsa20 key must be 16 bytes")

        nonce = iv[:8].ljust(8, b'\x00')

        # Expand 16-byte key to 32 bytes (matches agent's key doubling)
        full_key = key * 2

        # Type ignore for optional crypto dependency - cipher type is dynamic
        cipher = Salsa20.new(key=full_key, nonce=nonce)  # type: ignore[attr-defined]
        return cipher.decrypt(data)  # type: ignore[no-any-return]

    def _decrypt_arc4(self, data: bytes, key: bytes) -> bytes:
        """Decrypt using ARC4 stream cipher."""
        if not has_crypto or ARC4 is None:
            raise ValueError("Crypto support not available - install pycryptodome")
        # Type ignore for optional crypto dependency - cipher type is dynamic
        cipher = ARC4.new(key)  # type: ignore[attr-defined]
        return cipher.decrypt(data)  # type: ignore[no-any-return]

    def _decompress_block_data(self, compression_mode: CompressionMode, data: bytes) -> bytes:
        """Decompress a single block based on compression type."""
        if compression_mode == CompressionMode.NONE:
            return data
        elif compression_mode == CompressionMode.ZLIB:
            try:
                return zlib.decompress(data)
            except zlib.error as e:
                raise ValueError(f"ZLIB decompression failed: {e}") from e
        elif compression_mode == CompressionMode.LZ4:
            if not has_lz4 or lz4 is None:
                raise ValueError("LZ4 support not available - install lz4")
            try:
                # Type ignore for optional lz4 dependency - decompress returns bytes
                return lz4.block.decompress(data)  # type: ignore[attr-defined,no-any-return]
            except Exception as e:
                raise ValueError(f"LZ4 decompression failed: {e}") from e
        elif compression_mode == CompressionMode.FRAME:
            return self._decompress_frame(data)
        else:
            raise ValueError(f"Unsupported compression mode: {compression_mode}")

    def _decompress_frame(self, data: bytes) -> bytes:
        """Decompress frame-compressed data (recursive compression)."""
        offset = 0
        result = bytearray()

        while offset < len(data):
            # Read frame header (3 bytes for size, 1 for type)
            if offset + 4 > len(data):
                break

            # Frame size (24-bit little-endian)
            frame_size = int.from_bytes(data[offset:offset+3], 'little')
            offset += 3

            # Frame compression type
            frame_comp_type = data[offset:offset+1]
            offset += 1

            # Frame data
            frame_data = data[offset:offset+frame_size-1]  # -1 for comp type
            offset += frame_size - 1

            # Convert to compression mode
            try:
                frame_compression_mode = CompressionMode(frame_comp_type.decode())
            except (ValueError, UnicodeDecodeError) as e:
                raise ValueError(f"Unknown frame compression type: {frame_comp_type}") from e

            # Decompress frame recursively
            decompressed = self._decompress_block_data(frame_compression_mode, frame_data)
            result.extend(decompressed)

        return bytes(result)

    def build(self, obj: BLTEFile) -> bytes:
        """Build BLTE binary data from file structure.

        Args:
            obj: BLTE file structure

        Returns:
            Binary BLTE data
        """
        result = BytesIO()

        # Write magic
        result.write(self.BLTE_MAGIC)

        # Write header size
        result.write(struct.pack('>I', obj.header.header_size))

        # Write extended header if multi-chunk
        if not obj.header.is_single_chunk():
            if obj.header.flags is None or obj.header.chunk_count is None:
                raise ValueError("Multi-chunk file missing flags or chunk count")

            result.write(struct.pack('B', obj.header.flags))
            result.write(struct.pack('>I', obj.header.chunk_count)[1:])  # 24-bit

            # Check if this is extended format
            is_extended = obj.header.flags == 0x10

            # Write chunk info table
            for chunk in obj.chunks:
                result.write(struct.pack('>I', chunk.compressed_size))
                result.write(struct.pack('>I', chunk.decompressed_size))
                result.write(chunk.checksum)

                # Write decompressed checksum if extended format
                if is_extended:
                    if chunk.decompressed_checksum is None:
                        # If no decompressed checksum provided, write zeros
                        result.write(b'\x00' * 16)
                    else:
                        result.write(chunk.decompressed_checksum)

        # Write chunk data
        for chunk in obj.chunks:
            result.write(chunk.compression_mode.encode())

            if chunk.compression_mode == CompressionMode.ENCRYPTED:
                if chunk.encryption_type is None or chunk.encryption_key_name is None:
                    raise ValueError("Encrypted chunk missing encryption info")
                # Wire format: key_name_length(1) + key_name(8) + iv_length(1) + iv + algorithm(1)
                iv = chunk.encryption_iv or b'\x00' * 8
                iv_trimmed = iv.rstrip(b'\x00') or b'\x00'  # keep at least 1 byte if all zero
                result.write(struct.pack('B', self.ENCRYPTION_KEY_NAME_SIZE))  # key_name_length = 8
                result.write(chunk.encryption_key_name)
                result.write(struct.pack('B', len(iv_trimmed)))               # iv_length
                result.write(iv_trimmed)
                result.write(struct.pack('B', chunk.encryption_type.value))   # algorithm

            result.write(chunk.data)

        return result.getvalue()


class BLTEBuilder:
    """Builder for BLTE format files."""

    def __init__(self):
        """Initialize BLTE builder."""
        pass

    def build(self, obj: BLTEFile) -> bytes:
        """Build BLTE file from object.

        Args:
            obj: BLTE file object to build

        Returns:
            Binary BLTE data
        """
        # Use the existing build logic from BLTEParser
        parser = BLTEParser()
        return parser.build(obj)

    @classmethod
    def create_single_chunk(cls, data: bytes, compression: CompressionMode = CompressionMode.NONE) -> BLTEFile:
        """Create a single chunk BLTE file.

        Args:
            data: Raw data to encode
            compression: Compression mode to use

        Returns:
            BLTE file object
        """
        import hashlib

        # Compress data based on mode
        compressed_data: bytes = data
        if compression == CompressionMode.ZLIB:
            compressed_data = zlib.compress(data)
        elif compression == CompressionMode.LZ4 and has_lz4:
            # Type ignore for optional lz4 dependency
            compressed_data = bytes(lz4.block.compress(data))  # type: ignore[attr-defined]

        # Create chunk
        chunk = BLTEChunk(
            compressed_size=len(compressed_data),
            decompressed_size=len(data),
            checksum=hashlib.md5(compressed_data).digest(),
            compression_mode=compression,
            data=compressed_data
        )

        # Create header for single chunk
        header = BLTEHeader(
            magic=b'BLTE',
            header_size=0,  # Single chunk indicator
            flags=None,
            chunk_count=None
        )

        return BLTEFile(header=header, chunks=[chunk])

    @classmethod
    def create_multi_chunk(cls, chunks: list[tuple[bytes, CompressionMode]]) -> BLTEFile:
        """Create a multi-chunk BLTE file.

        Args:
            chunks: List of (data, compression_mode) tuples

        Returns:
            BLTE file object
        """
        import hashlib

        blte_chunks: list[BLTEChunk] = []
        for data, compression in chunks:
            # Compress data based on mode
            compressed_data: bytes = data
            if compression == CompressionMode.ZLIB:
                compressed_data = zlib.compress(data)
            elif compression == CompressionMode.LZ4 and has_lz4:
                # Type ignore for optional lz4 dependency
                compressed_data = bytes(lz4.block.compress(data))  # type: ignore[attr-defined]

            # Create chunk
            # compressed_size includes the 1-byte mode prefix written by build()
            chunk = BLTEChunk(
                compressed_size=len(compressed_data) + 1,
                decompressed_size=len(data),
                checksum=hashlib.md5(compression.encode() + compressed_data).digest(),
                compression_mode=compression,
                data=compressed_data
            )
            blte_chunks.append(chunk)

        # Calculate header size: 8 (magic + header_size) + 4 (flags + chunk_count) + (24 bytes per chunk)
        # The on-disk header_size includes the 8-byte BLTE preamble
        header_size = 12 + len(chunks) * 24

        # Create header for multi-chunk
        header = BLTEHeader(
            magic=b'BLTE',
            header_size=header_size,
            flags=0x0F,  # Standard flags for multi-chunk
            chunk_count=len(chunks)
        )

        return BLTEFile(header=header, chunks=blte_chunks)

    @classmethod
    def create_multi_chunk_extended(cls, chunks: list[tuple[bytes, CompressionMode]]) -> BLTEFile:
        """Create a multi-chunk BLTE file with extended format (0x10).

        Extended format includes MD5 checksums for both compressed and decompressed data.

        Args:
            chunks: List of (data, compression_mode) tuples

        Returns:
            BLTE file object with extended format
        """
        import hashlib

        blte_chunks: list[BLTEChunk] = []
        for data, compression in chunks:
            # Compress data based on mode
            compressed_data: bytes = data
            if compression == CompressionMode.ZLIB:
                compressed_data = zlib.compress(data)
            elif compression == CompressionMode.LZ4 and has_lz4:
                # Type ignore for optional lz4 dependency
                compressed_data = bytes(lz4.block.compress(data))  # type: ignore[attr-defined]

            # Create chunk with both checksums
            # compressed_size includes the 1-byte mode prefix written by build()
            chunk = BLTEChunk(
                compressed_size=len(compressed_data) + 1,
                decompressed_size=len(data),
                checksum=hashlib.md5(compression.encode() + compressed_data).digest(),
                decompressed_checksum=hashlib.md5(data).digest(),
                compression_mode=compression,
                data=compressed_data
            )
            blte_chunks.append(chunk)

        # Calculate header size: 8 (magic + header_size) + 4 (flags + chunk_count) + (40 bytes per chunk)
        # The on-disk header_size includes the 8-byte BLTE preamble
        header_size = 12 + len(chunks) * 40

        # Create header for multi-chunk extended format
        header = BLTEHeader(
            magic=b'BLTE',
            header_size=header_size,
            flags=0x10,  # Extended flags for multi-chunk
            chunk_count=len(chunks)
        )

        return BLTEFile(header=header, chunks=blte_chunks)


def decompress_blte(data: bytes, key_store: TACTKeyStore | None = None) -> bytes:
    """Convenience function to decompress BLTE data.

    Args:
        data: BLTE-encoded data
        key_store: Optional TACT key store for encrypted chunks

    Returns:
        Decompressed data
    """
    parser = BLTEParser(key_store)
    obj = parser.parse(data)
    return parser.decompress(obj)


def is_blte(data: bytes) -> bool:
    """Check if data appears to be BLTE-encoded.

    Args:
        data: Data to check

    Returns:
        True if data starts with BLTE magic
    """
    return len(data) >= 4 and data[:4] == b'BLTE'
