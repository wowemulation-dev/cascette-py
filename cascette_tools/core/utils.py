"""Shared utilities for cascette-tools."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import BinaryIO


def hexlify(data: bytes, upper: bool = False) -> str:
    """Convert bytes to hex string.

    Args:
        data: Binary data to convert
        upper: Use uppercase hex if True, lowercase if False

    Returns:
        Hex string representation of the data

    Example:
        >>> hexlify(b"hello")
        '68656c6c6f'
        >>> hexlify(b"hello", upper=True)
        '68656C6C6F'
    """
    result = data.hex()
    return result.upper() if upper else result


def unhexlify(hex_str: str) -> bytes:
    """Convert hex string to bytes.

    Args:
        hex_str: Hex string to convert

    Returns:
        Binary data

    Raises:
        ValueError: If hex_str contains invalid hex characters

    Example:
        >>> unhexlify('68656c6c6f')
        b'hello'
    """
    return bytes.fromhex(hex_str)


def compute_md5(data: bytes) -> bytes:
    """Compute MD5 hash.

    Args:
        data: Input data to hash

    Returns:
        16-byte MD5 hash digest

    Example:
        >>> compute_md5(b"hello").hex()
        '5d41402abc4b2a76b9719d911017c592'
    """
    return hashlib.md5(data).digest()


def compute_jenkins96(path: str) -> int:
    """Compute Jenkins96 hash for a path.

    This is used for CASC file path hashing in World of Warcraft's
    content distribution system.

    Args:
        path: File path string to hash

    Returns:
        Jenkins96 hash value as 64-bit integer

    Example:
        >>> compute_jenkins96("World\\Map\\Azeroth\\Azeroth.wdt")
        12345678901234567890
    """
    path_upper = path.upper().replace("/", "\\")
    hash1 = 0x7FED7FED
    hash2 = 0xEEEEEEEE

    for char in path_upper:
        hash1 = ((hash1 + ord(char)) * 0x193) & 0xFFFFFFFF
        hash2 = ((hash2 + (hash1 ^ ord(char))) * 0x1B3) & 0xFFFFFFFF

    return ((hash1 * hash2) & 0xFFFFFFFFFFFFFFFF)


def read_cstring(stream: BinaryIO, encoding: str = "utf-8") -> str:
    """Read null-terminated string from stream.

    Args:
        stream: Binary stream to read from
        encoding: String encoding to use for decoding

    Returns:
        Decoded string without null terminator

    Raises:
        UnicodeDecodeError: If bytes cannot be decoded with specified encoding

    Example:
        >>> import io
        >>> stream = io.BytesIO(b"hello\\x00world")
        >>> read_cstring(stream)
        'hello'
    """
    chars = []
    while True:
        char = stream.read(1)
        if not char or char == b'\x00':
            break
        chars.append(char)
    return b''.join(chars).decode(encoding)


def chunked_read(
    stream: BinaryIO,
    chunk_size: int = 8192
) -> Iterator[bytes]:
    """Read stream in chunks.

    Args:
        stream: Binary stream to read from
        chunk_size: Size of each chunk in bytes

    Yields:
        Data chunks as bytes

    Raises:
        ValueError: If chunk_size is not positive

    Example:
        >>> import io
        >>> stream = io.BytesIO(b"hello world")
        >>> chunks = list(chunked_read(stream, chunk_size=5))
        >>> chunks
        [b'hello', b' worl', b'd']
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        yield chunk


def format_size(size: int) -> str:
    """Format byte size as human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string with appropriate unit (e.g., "1.5 MB")

    Example:
        >>> format_size(1024)
        '1.0 KB'
        >>> format_size(1536)
        '1.5 KB'
        >>> format_size(1048576)
        '1.0 MB'
    """
    if size < 0:
        return "0 B"

    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_float < 1024.0:
            if unit == "B":
                return f"{int(size_float)} {unit}"
            return f"{size_float:.1f} {unit}"
        size_float /= 1024.0
    return f"{size_float:.1f} PB"


def validate_hash_string(hash_str: str) -> bool:
    """Validate hex hash string.

    Args:
        hash_str: Hash string to validate

    Returns:
        True if valid hex string, False otherwise

    Example:
        >>> validate_hash_string("deadbeef")
        True
        >>> validate_hash_string("invalid")
        False
        >>> validate_hash_string("")
        False
    """
    if not hash_str or hash_str != hash_str.strip() or ' ' in hash_str or '\t' in hash_str:
        return False
    try:
        bytes.fromhex(hash_str)
        return True
    except ValueError:
        return False
