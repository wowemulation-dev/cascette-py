"""Base classes for format parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import BinaryIO, Generic, TypeVar

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()

T = TypeVar("T", bound=BaseModel)


class FormatParser(ABC, Generic[T]):
    """Base class for format parsers."""

    @abstractmethod
    def parse(self, data: bytes | BinaryIO) -> T:
        """Parse binary data.

        Args:
            data: Binary data or stream

        Returns:
            Parsed format object
        """
        ...

    def parse_file(self, path: str) -> T:
        """Parse format from file.

        Args:
            path: File path

        Returns:
            Parsed format object
        """
        try:
            with open(path, "rb") as f:
                return self.parse(f)
        except OSError as e:
            logger.error("Failed to read file", path=path, error=str(e))
            raise ValueError(f"Cannot read file {path}: {e}") from e

    @abstractmethod
    def build(self, obj: T) -> bytes:
        """Build binary data from object.

        Args:
            obj: Format object

        Returns:
            Binary data
        """
        ...

    def validate(self, data: bytes) -> tuple[bool, str]:
        """Validate format data.

        Args:
            data: Binary data to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            obj = self.parse(data)
            rebuilt = self.build(obj)
            if data != rebuilt:
                return False, "Round-trip validation failed"
            return True, "Valid"
        except Exception as e:
            return False, str(e)

    def build_file(self, obj: T, path: str) -> None:
        """Build format to file.

        Args:
            obj: Format object
            path: Output file path
        """
        try:
            data = self.build(obj)
            with open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            logger.error("Failed to write file", path=path, error=str(e))
            raise ValueError(f"Cannot write file {path}: {e}") from e
