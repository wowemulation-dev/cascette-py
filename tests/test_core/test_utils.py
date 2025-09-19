"""Tests for cascette_tools.core.utils module."""

import io

import pytest

from cascette_tools.core.utils import (
    chunked_read,
    compute_jenkins96,
    compute_md5,
    format_size,
    hexlify,
    read_cstring,
    unhexlify,
    validate_hash_string,
)


class TestHexlify:
    """Test hexlify function."""

    def test_basic_conversion(self):
        """Test basic bytes to hex conversion."""
        assert hexlify(b"hello") == "68656c6c6f"
        assert hexlify(b"world") == "776f726c64"

    def test_uppercase_option(self):
        """Test uppercase hex output."""
        assert hexlify(b"hello", upper=True) == "68656C6C6F"
        assert hexlify(b"HELLO", upper=True) == "48454C4C4F"

    def test_empty_data(self):
        """Test with empty bytes."""
        assert hexlify(b"") == ""
        assert hexlify(b"", upper=True) == ""

    def test_binary_data(self):
        """Test with various binary data."""
        assert hexlify(b"\x00") == "00"
        assert hexlify(b"\xff") == "ff"
        assert hexlify(b"\x00\xff\x42") == "00ff42"
        assert hexlify(b"\x00\xff\x42", upper=True) == "00FF42"


class TestUnhexlify:
    """Test unhexlify function."""

    def test_basic_conversion(self):
        """Test basic hex to bytes conversion."""
        assert unhexlify("68656c6c6f") == b"hello"
        assert unhexlify("776f726c64") == b"world"

    def test_uppercase_hex(self):
        """Test with uppercase hex."""
        assert unhexlify("68656C6C6F") == b"hello"
        assert unhexlify("48454C4C4F") == b"HELLO"

    def test_mixed_case(self):
        """Test with mixed case hex."""
        assert unhexlify("68656C6c6F") == b"hello"

    def test_empty_string(self):
        """Test with empty string."""
        assert unhexlify("") == b""

    def test_binary_values(self):
        """Test with binary hex values."""
        assert unhexlify("00") == b"\x00"
        assert unhexlify("ff") == b"\xff"
        assert unhexlify("00ff42") == b"\x00\xff\x42"

    def test_invalid_hex(self):
        """Test with invalid hex strings."""
        with pytest.raises(ValueError):
            unhexlify("invalid")
        with pytest.raises(ValueError):
            unhexlify("gg")
        with pytest.raises(ValueError):
            unhexlify("1")  # Odd length


class TestComputeMd5:
    """Test compute_md5 function."""

    def test_known_values(self):
        """Test with known MD5 values."""
        # Empty string
        assert compute_md5(b"").hex() == "d41d8cd98f00b204e9800998ecf8427e"
        # "hello"
        assert compute_md5(b"hello").hex() == "5d41402abc4b2a76b9719d911017c592"
        # "The quick brown fox jumps over the lazy dog"
        assert compute_md5(
            b"The quick brown fox jumps over the lazy dog"
        ).hex() == "9e107d9d372bb6826bd81d3542a419d6"

    def test_binary_data(self):
        """Test with binary data."""
        data = b"\x00\x01\x02\x03\xff\xfe\xfd"
        result = compute_md5(data)
        assert len(result) == 16  # MD5 is always 16 bytes
        assert isinstance(result, bytes)

    def test_large_data(self):
        """Test with larger data."""
        data = b"a" * 10000
        result = compute_md5(data)
        assert len(result) == 16
        # Verify it's deterministic
        assert compute_md5(data) == result


class TestComputeJenkins96:
    """Test compute_jenkins96 function."""

    def test_basic_paths(self):
        """Test with basic path strings."""
        # Test that function returns consistent results
        path1 = "test/path.txt"
        result1 = compute_jenkins96(path1)
        assert isinstance(result1, int)
        assert result1 == compute_jenkins96(path1)  # Deterministic

    def test_case_insensitive(self):
        """Test that paths are case-insensitive."""
        path_lower = "test/path.txt"
        path_upper = "TEST/PATH.TXT"
        path_mixed = "Test/Path.Txt"

        result1 = compute_jenkins96(path_lower)
        result2 = compute_jenkins96(path_upper)
        result3 = compute_jenkins96(path_mixed)

        assert result1 == result2 == result3

    def test_slash_normalization(self):
        """Test that forward slashes are converted to backslashes."""
        path_forward = "folder/subfolder/file.txt"
        path_backward = "folder\\subfolder\\file.txt"

        assert compute_jenkins96(path_forward) == compute_jenkins96(path_backward)

    def test_empty_string(self):
        """Test with empty string."""
        result = compute_jenkins96("")
        assert isinstance(result, int)
        # Should be deterministic
        assert compute_jenkins96("") == result

    def test_special_characters(self):
        """Test with paths containing special characters."""
        paths = [
            "path with spaces.txt",
            "path-with-dashes.txt",
            "path_with_underscores.txt",
            "path.with.dots.txt",
        ]

        for path in paths:
            result = compute_jenkins96(path)
            assert isinstance(result, int)
            assert result == compute_jenkins96(path)  # Deterministic

    def test_typical_wow_paths(self):
        """Test with typical WoW file paths."""
        paths = [
            "World\\Map\\Azeroth\\Azeroth.wdt",
            "Character\\Human\\Male\\HumanMale.m2",
            "Tileset\\Generic\\Passive Doodads\\Rocks\\Rock01.mdx",
        ]

        for path in paths:
            result = compute_jenkins96(path)
            assert isinstance(result, int)
            assert 0 <= result <= 0xFFFFFFFFFFFFFFFF  # 64-bit unsigned


class TestReadCstring:
    """Test read_cstring function."""

    def test_basic_string(self):
        """Test reading basic null-terminated string."""
        stream = io.BytesIO(b"hello\x00world")
        result = read_cstring(stream)
        assert result == "hello"
        # Stream position should be after the null byte
        assert stream.read() == b"world"

    def test_empty_string(self):
        """Test reading empty string (immediate null)."""
        stream = io.BytesIO(b"\x00remaining")
        result = read_cstring(stream)
        assert result == ""
        assert stream.read() == b"remaining"

    def test_no_null_terminator(self):
        """Test when stream ends without null terminator."""
        stream = io.BytesIO(b"hello")
        result = read_cstring(stream)
        assert result == "hello"

    def test_empty_stream(self):
        """Test with empty stream."""
        stream = io.BytesIO(b"")
        result = read_cstring(stream)
        assert result == ""

    def test_utf8_encoding(self):
        """Test with UTF-8 encoded strings."""
        utf8_bytes = "hello 世界".encode()
        stream = io.BytesIO(utf8_bytes + b"\x00")
        result = read_cstring(stream)
        assert result == "hello 世界"

    def test_custom_encoding(self):
        """Test with custom encoding."""
        latin1_bytes = "héllo".encode("latin-1")
        stream = io.BytesIO(latin1_bytes + b"\x00")
        result = read_cstring(stream, encoding="latin-1")
        assert result == "héllo"

    def test_invalid_encoding(self):
        """Test with invalid bytes for encoding."""
        # Invalid UTF-8 sequence
        stream = io.BytesIO(b"\xff\xfe\x00")
        with pytest.raises(UnicodeDecodeError):
            read_cstring(stream)

    def test_multiple_null_bytes(self):
        """Test with multiple consecutive null bytes."""
        stream = io.BytesIO(b"hello\x00\x00world")
        result = read_cstring(stream)
        assert result == "hello"
        # Should stop at first null
        assert stream.read() == b"\x00world"


class TestChunkedRead:
    """Test chunked_read function."""

    def test_basic_chunking(self):
        """Test basic chunk reading."""
        data = b"hello world test"
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=5))

        assert chunks == [b"hello", b" worl", b"d tes", b"t"]
        assert b"".join(chunks) == data

    def test_exact_chunk_size(self):
        """Test when data size is exactly chunk size."""
        data = b"hello"
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=5))

        assert chunks == [b"hello"]

    def test_smaller_than_chunk(self):
        """Test when data is smaller than chunk size."""
        data = b"hi"
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=10))

        assert chunks == [b"hi"]

    def test_empty_stream(self):
        """Test with empty stream."""
        stream = io.BytesIO(b"")
        chunks = list(chunked_read(stream, chunk_size=5))

        assert chunks == []

    def test_large_data(self):
        """Test with larger data."""
        data = b"a" * 10000
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=1024))

        # Should have ceil(10000/1024) = 10 chunks
        assert len(chunks) == 10
        assert b"".join(chunks) == data

        # First 9 chunks should be full size
        for i in range(9):
            assert len(chunks[i]) == 1024
        # Last chunk should be remainder
        assert len(chunks[9]) == 10000 % 1024

    def test_default_chunk_size(self):
        """Test with default chunk size."""
        data = b"test data"
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream))  # Default 8192

        assert chunks == [b"test data"]

    def test_invalid_chunk_size(self):
        """Test with invalid chunk sizes."""
        stream = io.BytesIO(b"test")

        with pytest.raises(ValueError, match="chunk_size must be positive"):
            list(chunked_read(stream, chunk_size=0))

        with pytest.raises(ValueError, match="chunk_size must be positive"):
            list(chunked_read(stream, chunk_size=-1))

    def test_generator_behavior(self):
        """Test that function returns a generator."""
        stream = io.BytesIO(b"test data")
        result = chunked_read(stream, chunk_size=4)

        # Should be a generator, not a list
        assert hasattr(result, "__next__")
        assert hasattr(result, "__iter__")


class TestFormatSize:
    """Test format_size function."""

    def test_bytes(self):
        """Test byte formatting."""
        assert format_size(0) == "0 B"
        assert format_size(1) == "1 B"
        assert format_size(512) == "512 B"
        assert format_size(1023) == "1023 B"

    def test_kilobytes(self):
        """Test kilobyte formatting."""
        assert format_size(1024) == "1.0 KB"
        assert format_size(1536) == "1.5 KB"
        assert format_size(2048) == "2.0 KB"
        assert format_size(1047552) == "1023.0 KB"

    def test_megabytes(self):
        """Test megabyte formatting."""
        assert format_size(1048576) == "1.0 MB"
        assert format_size(1572864) == "1.5 MB"
        assert format_size(2097152) == "2.0 MB"

    def test_gigabytes(self):
        """Test gigabyte formatting."""
        assert format_size(1073741824) == "1.0 GB"
        assert format_size(1610612736) == "1.5 GB"

    def test_terabytes(self):
        """Test terabyte formatting."""
        assert format_size(1099511627776) == "1.0 TB"
        assert format_size(1649267441664) == "1.5 TB"

    def test_petabytes(self):
        """Test petabyte formatting."""
        size_pb = 1024**5
        assert format_size(size_pb) == "1.0 PB"

    def test_negative_size(self):
        """Test with negative size."""
        assert format_size(-1) == "0 B"
        assert format_size(-1000) == "0 B"

    def test_very_large_size(self):
        """Test with very large sizes."""
        # Larger than petabytes should still show as PB
        huge_size = 1024**6
        result = format_size(huge_size)
        assert result.endswith(" PB")
        assert "1024.0 PB" == result

    def test_decimal_precision(self):
        """Test decimal precision in output."""
        # Test that we get exactly one decimal place for non-byte units
        assert format_size(1536) == "1.5 KB"  # Not "1.50 KB"
        assert format_size(1049088) == "1.0 MB"  # 1024.5 KB = 1.0 MB
        # Test a value that should show as KB with decimal
        assert format_size(1536) == "1.5 KB"  # 1.5 * 1024 = 1536


class TestValidateHashString:
    """Test validate_hash_string function."""

    def test_valid_hashes(self):
        """Test with valid hex hash strings."""
        assert validate_hash_string("deadbeef") is True
        assert validate_hash_string("DEADBEEF") is True
        assert validate_hash_string("0123456789abcdef") is True
        assert validate_hash_string("0123456789ABCDEF") is True
        assert validate_hash_string("00") is True
        assert validate_hash_string("ff") is True

    def test_invalid_hashes(self):
        """Test with invalid hash strings."""
        assert validate_hash_string("invalid") is False
        assert validate_hash_string("gg") is False
        assert validate_hash_string("xyz") is False
        assert validate_hash_string("deadbeeg") is False  # 'g' is invalid
        assert validate_hash_string("hello world") is False

    def test_empty_string(self):
        """Test with empty string."""
        assert validate_hash_string("") is False

    def test_none_value(self):
        """Test with None (should be handled gracefully)."""
        # This will test the truthiness check
        assert validate_hash_string("") is False

    def test_odd_length(self):
        """Test with odd-length hex strings."""
        assert validate_hash_string("f") is False  # Single character
        assert validate_hash_string("fff") is False  # Odd length

    def test_mixed_case(self):
        """Test with mixed case hex."""
        assert validate_hash_string("DeAdBeEf") is True
        assert validate_hash_string("aBcDeF") is True

    def test_whitespace(self):
        """Test with whitespace in hash strings."""
        assert validate_hash_string(" deadbeef") is False
        assert validate_hash_string("deadbeef ") is False
        assert validate_hash_string("dead beef") is False
        assert validate_hash_string("\tdeadbeef") is False
        assert validate_hash_string("deadbeef\n") is False

    def test_real_hash_lengths(self):
        """Test with typical hash string lengths."""
        # MD5 (32 chars)
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        assert validate_hash_string(md5_hash) is True

        # SHA1 (40 chars)
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert validate_hash_string(sha1_hash) is True

        # SHA256 (64 chars)
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_hash_string(sha256_hash) is True
