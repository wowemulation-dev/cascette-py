"""Tests for cascette_tools.formats.base module."""

from __future__ import annotations

import tempfile
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import pytest
from pydantic import BaseModel

from cascette_tools.formats.base import FormatParser


class SimpleModel(BaseModel):
    """Test model for testing format parser."""

    value: int
    text: str


class TestFormatParser(FormatParser[SimpleModel]):
    """Concrete implementation of FormatParser for testing."""

    def parse(self, data: bytes | BinaryIO) -> SimpleModel:
        """Parse test data format."""
        if isinstance(data, bytes):
            stream = BytesIO(data)
        else:
            stream = data

        # Simple format: 4 bytes for int + length byte + string
        value_bytes = stream.read(4)
        if len(value_bytes) < 4:
            raise ValueError("Insufficient data for value")

        value = int.from_bytes(value_bytes, byteorder="big")

        text_length_bytes = stream.read(1)
        if len(text_length_bytes) < 1:
            raise ValueError("Insufficient data for text length")

        text_length = text_length_bytes[0]
        text_bytes = stream.read(text_length)
        if len(text_bytes) < text_length:
            raise ValueError("Insufficient data for text")

        text = text_bytes.decode("utf-8")

        return SimpleModel(value=value, text=text)

    def build(self, obj: SimpleModel) -> bytes:
        """Build test data format."""
        text_bytes = obj.text.encode("utf-8")
        if len(text_bytes) > 255:
            raise ValueError("Text too long (max 255 bytes)")

        result = bytearray()
        result.extend(obj.value.to_bytes(4, byteorder="big"))
        result.extend([len(text_bytes)])
        result.extend(text_bytes)

        return bytes(result)


class BrokenParser(FormatParser[SimpleModel]):
    """Parser that breaks round-trip validation."""

    def parse(self, data: bytes | BinaryIO) -> SimpleModel:
        """Always returns the same model regardless of input."""
        return SimpleModel(value=42, text="broken")

    def build(self, obj: SimpleModel) -> bytes:
        """Always returns the same bytes regardless of input."""
        return b"\x00\x00\x00\x2a\x06broken"


class TestFormatParserBase:
    """Tests for base FormatParser functionality."""

    def test_abstract_instantiation(self) -> None:
        """Test that FormatParser cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            FormatParser()  # type: ignore

    def test_concrete_implementation(self) -> None:
        """Test concrete implementation works."""
        parser = TestFormatParser()

        # Test data
        test_data = SimpleModel(value=123, text="hello")
        binary_data = parser.build(test_data)

        # Parse back
        parsed = parser.parse(binary_data)

        assert parsed.value == 123
        assert parsed.text == "hello"

    def test_parse_with_bytes(self) -> None:
        """Test parsing with bytes input."""
        parser = TestFormatParser()

        # Create test data: value=42, text="test"
        data = b"\x00\x00\x00\x2a\x04test"

        result = parser.parse(data)

        assert result.value == 42
        assert result.text == "test"

    def test_parse_with_bytesio(self) -> None:
        """Test parsing with BytesIO input."""
        parser = TestFormatParser()

        # Create test data: value=42, text="test"
        data = BytesIO(b"\x00\x00\x00\x2a\x04test")

        result = parser.parse(data)

        assert result.value == 42
        assert result.text == "test"

    def test_build_round_trip(self) -> None:
        """Test build and parse round trip."""
        parser = TestFormatParser()

        original = SimpleModel(value=999, text="round-trip")

        # Build to bytes
        binary_data = parser.build(original)

        # Parse back
        parsed = parser.parse(binary_data)

        assert parsed == original

    def test_validate_success(self) -> None:
        """Test successful validation."""
        parser = TestFormatParser()

        # Create valid data
        test_data = SimpleModel(value=100, text="valid")
        binary_data = parser.build(test_data)

        is_valid, message = parser.validate(binary_data)

        assert is_valid is True
        assert message == "Valid"

    def test_validate_round_trip_failure(self) -> None:
        """Test validation with round-trip failure."""
        parser = BrokenParser()

        # Any data will fail round-trip
        data = b"\x00\x00\x00\x01\x01x"

        is_valid, message = parser.validate(data)

        assert is_valid is False
        assert "Round-trip validation failed" in message

    def test_validate_parse_error(self) -> None:
        """Test validation with parse error."""
        parser = TestFormatParser()

        # Invalid data (too short)
        data = b"\x00\x00"

        is_valid, message = parser.validate(data)

        assert is_valid is False
        assert "Insufficient data" in message

    def test_parse_file_success(self) -> None:
        """Test parsing from file."""
        parser = TestFormatParser()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write test data: value=777, text="file"
            f.write(b"\x00\x00\x03\x09\x04file")
            temp_path = f.name

        try:
            result = parser.parse_file(temp_path)

            assert result.value == 777
            assert result.text == "file"
        finally:
            Path(temp_path).unlink()

    def test_parse_file_not_found(self) -> None:
        """Test parsing from non-existent file."""
        parser = TestFormatParser()

        with pytest.raises(ValueError, match="Cannot read file"):
            parser.parse_file("/non/existent/file")

    def test_build_file_success(self) -> None:
        """Test building to file."""
        parser = TestFormatParser()
        test_data = SimpleModel(value=555, text="output")

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            parser.build_file(test_data, temp_path)

            # Read back and verify
            with open(temp_path, "rb") as f:
                written_data = f.read()

            # Parse to verify
            parsed = parser.parse(written_data)
            assert parsed == test_data
        finally:
            Path(temp_path).unlink()

    def test_build_file_permission_error(self) -> None:
        """Test building to file with permission error."""
        parser = TestFormatParser()
        test_data = SimpleModel(value=123, text="test")

        # Try to write to root directory (should fail)
        with pytest.raises(ValueError, match="Cannot write file"):
            parser.build_file(test_data, "/root/forbidden.dat")

    def test_edge_cases(self) -> None:
        """Test edge cases and error conditions."""
        parser = TestFormatParser()

        # Empty string
        empty_text = SimpleModel(value=0, text="")
        data = parser.build(empty_text)
        parsed = parser.parse(data)
        assert parsed == empty_text

        # Maximum length text (255 bytes)
        max_text = SimpleModel(value=999, text="x" * 255)
        data = parser.build(max_text)
        parsed = parser.parse(data)
        assert parsed == max_text

        # Text too long should raise error
        with pytest.raises(ValueError, match="Text too long"):
            parser.build(SimpleModel(value=1, text="x" * 256))
