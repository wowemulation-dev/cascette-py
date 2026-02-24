"""Containerless storage backend for loose file installations.

Parallel to local_storage.py (CASC archives). Writes decoded content
directly to filesystem paths derived from the file database.
Callers decompress BLTE before calling write_content.

Key differences from LocalStorage:
- No CASC archives or bucket-based indices
- Files stored at their final filesystem paths
- File database provides the ekey→path mapping
- No shmem or index file management
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import structlog

from cascette_tools.core.integrity import IntegrityError
from cascette_tools.formats.file_db import FileDatabase, FileDbEntry

logger = structlog.get_logger()


class ContainerlessStorage:
    """Manages loose file storage for containerless installations."""

    def __init__(self, base_path: Path):
        """Initialize containerless storage.

        Args:
            base_path: Base installation directory
        """
        self.base_path = base_path
        self._path_index: dict[bytes, str] = {}   # ekey → relative_path
        self._ckey_index: dict[bytes, str] = {}    # ckey → relative_path
        self._entry_index: dict[bytes, FileDbEntry] = {}  # ekey → entry
        self._written_keys: set[bytes] = set()

    def set_file_database(self, file_db: FileDatabase) -> None:
        """Build ekey→path and ckey→path indices from file database.

        Args:
            file_db: Parsed file database
        """
        self._path_index.clear()
        self._ckey_index.clear()
        self._entry_index.clear()

        for entry in file_db.entries:
            normalized_path = entry.relative_path.replace('\\', '/')
            self._path_index[entry.ekey] = normalized_path
            self._ckey_index[entry.ckey] = normalized_path
            self._entry_index[entry.ekey] = entry

        logger.debug(
            "File database loaded",
            ekey_entries=len(self._path_index),
            ckey_entries=len(self._ckey_index),
        )

    def initialize(self) -> None:
        """Create base directory."""
        self.base_path.mkdir(parents=True, exist_ok=True)
        logger.info("Initialized containerless storage", path=str(self.base_path))

    def write_content(
        self,
        encoding_key: bytes,
        data: bytes,
        *,
        expected_ckey: bytes | None = None,
    ) -> Path:
        """Write decoded content to filesystem path.

        Args:
            encoding_key: Encoding key (16 bytes)
            data: Decoded (decompressed) content
            expected_ckey: If provided, verify MD5 matches

        Returns:
            Full filesystem path of written file

        Raises:
            IntegrityError: If expected_ckey is provided and MD5 does not match
            KeyError: If encoding_key is not in the file database
        """
        # Deduplication
        if encoding_key in self._written_keys:
            rel_path = self._path_index.get(encoding_key)
            if rel_path:
                return self.base_path / rel_path
            return self.base_path / encoding_key.hex()

        # Verify content key if provided
        if expected_ckey is not None:
            actual_md5 = hashlib.md5(data).digest()
            if actual_md5 != expected_ckey:
                raise IntegrityError(
                    f"Content key mismatch for ekey {encoding_key.hex()}: "
                    f"expected {expected_ckey.hex()}, got {actual_md5.hex()}",
                    expected=expected_ckey.hex(),
                    actual=actual_md5.hex(),
                    key_hex=encoding_key.hex(),
                )

        # Look up relative path
        rel_path = self._path_index.get(encoding_key)
        if rel_path is None:
            raise KeyError(
                f"Encoding key {encoding_key.hex()} not found in file database"
            )

        # Write file
        full_path = self.base_path / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(data)

        self._written_keys.add(encoding_key)
        return full_path

    def file_exists(self, encoding_key: bytes) -> bool:
        """Check if file exists on disk at expected path.

        Args:
            encoding_key: Encoding key to check

        Returns:
            True if file exists at the expected path
        """
        rel_path = self._path_index.get(encoding_key)
        if rel_path is None:
            return False
        return (self.base_path / rel_path).exists()

    def get_file_path(self, encoding_key: bytes) -> Path | None:
        """Resolve encoding key to full filesystem path.

        Args:
            encoding_key: Encoding key to look up

        Returns:
            Full path, or None if key not in database
        """
        rel_path = self._path_index.get(encoding_key)
        if rel_path is None:
            return None
        return self.base_path / rel_path

    def identify_file(self, entry: FileDbEntry) -> tuple[bytes, bool]:
        """Hash on-disk file and compare against expected content key.

        Args:
            entry: File database entry to check

        Returns:
            (actual_md5, matches_ckey) tuple
        """
        rel_path = entry.relative_path.replace('\\', '/')
        full_path = self.base_path / rel_path

        if not full_path.exists():
            return b'', False

        actual_md5 = hashlib.md5(full_path.read_bytes()).digest()
        return actual_md5, actual_md5 == entry.ckey

    def get_entry(self, encoding_key: bytes) -> FileDbEntry | None:
        """Look up file database entry by encoding key.

        Args:
            encoding_key: Encoding key

        Returns:
            FileDbEntry or None
        """
        return self._entry_index.get(encoding_key)
