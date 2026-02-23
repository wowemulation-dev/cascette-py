"""Tests for cascette_tools.core.integrity module."""

import hashlib

import pytest

from cascette_tools.core.integrity import (
    IntegrityError,
    verify_content_key,
    verify_ekey_size,
)


class TestIntegrityError:
    """Test IntegrityError exception."""

    def test_basic_message(self):
        """Test basic error with message only."""
        err = IntegrityError("test error")
        assert str(err) == "test error"
        assert err.expected is None
        assert err.actual is None
        assert err.key_hex is None

    def test_with_all_fields(self):
        """Test error with all optional fields."""
        err = IntegrityError(
            "mismatch",
            expected="aabbccdd",
            actual="11223344",
            key_hex="deadbeef",
        )
        assert str(err) == "mismatch"
        assert err.expected == "aabbccdd"
        assert err.actual == "11223344"
        assert err.key_hex == "deadbeef"

    def test_with_int_fields(self):
        """Test error with integer expected/actual (for size checks)."""
        err = IntegrityError(
            "size mismatch",
            expected=1024,
            actual=512,
        )
        assert err.expected == 1024
        assert err.actual == 512

    def test_is_exception(self):
        """Test that IntegrityError is a proper exception."""
        assert issubclass(IntegrityError, Exception)
        with pytest.raises(IntegrityError):
            raise IntegrityError("test")


class TestVerifyContentKey:
    """Test verify_content_key function."""

    def test_matching_hash(self):
        """Test verification with correct content key."""
        data = b"hello world"
        ckey = hashlib.md5(data).digest()
        assert verify_content_key(data, ckey) is True

    def test_empty_data(self):
        """Test verification with empty data."""
        data = b""
        ckey = hashlib.md5(data).digest()
        assert verify_content_key(data, ckey) is True

    def test_large_data(self):
        """Test verification with larger data."""
        data = b"A" * 1_000_000
        ckey = hashlib.md5(data).digest()
        assert verify_content_key(data, ckey) is True

    def test_binary_data(self):
        """Test verification with binary data."""
        data = bytes(range(256)) * 100
        ckey = hashlib.md5(data).digest()
        assert verify_content_key(data, ckey) is True

    def test_mismatched_hash(self):
        """Test that mismatched hash raises IntegrityError."""
        data = b"hello world"
        wrong_ckey = b"\x00" * 16

        with pytest.raises(IntegrityError) as exc_info:
            verify_content_key(data, wrong_ckey)

        err = exc_info.value
        assert err.expected == wrong_ckey.hex()
        actual_hex = hashlib.md5(data).hexdigest()
        assert err.actual == actual_hex
        assert "Content key mismatch" in str(err)

    def test_single_bit_difference(self):
        """Test that a single bit difference is detected."""
        data = b"hello world"
        ckey = bytearray(hashlib.md5(data).digest())
        # Flip one bit
        ckey[0] ^= 0x01
        ckey = bytes(ckey)

        with pytest.raises(IntegrityError):
            verify_content_key(data, ckey)

    def test_tampered_data(self):
        """Test that tampered data is detected."""
        original = b"hello world"
        ckey = hashlib.md5(original).digest()
        tampered = b"hello world!"

        with pytest.raises(IntegrityError):
            verify_content_key(tampered, ckey)


class TestVerifyEkeySize:
    """Test verify_ekey_size function."""

    def test_matching_size(self):
        """Test verification with correct size."""
        data = b"hello world"
        assert verify_ekey_size(data, 11) is True

    def test_empty_data(self):
        """Test verification with empty data and size 0."""
        assert verify_ekey_size(b"", 0) is True

    def test_size_too_small(self):
        """Test that smaller-than-expected data raises error."""
        data = b"hello"

        with pytest.raises(IntegrityError) as exc_info:
            verify_ekey_size(data, 100)

        err = exc_info.value
        assert err.expected == 100
        assert err.actual == 5
        assert "Encoded size mismatch" in str(err)

    def test_size_too_large(self):
        """Test that larger-than-expected data raises error."""
        data = b"hello world extra"

        with pytest.raises(IntegrityError) as exc_info:
            verify_ekey_size(data, 5)

        err = exc_info.value
        assert err.expected == 5
        assert err.actual == len(data)

    def test_off_by_one(self):
        """Test that off-by-one size is detected."""
        data = b"hello"

        with pytest.raises(IntegrityError):
            verify_ekey_size(data, 4)

        with pytest.raises(IntegrityError):
            verify_ekey_size(data, 6)
