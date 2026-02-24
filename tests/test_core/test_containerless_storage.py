"""Tests for containerless storage backend."""

import hashlib
from pathlib import Path

import pytest

from cascette_tools.core.containerless_storage import ContainerlessStorage
from cascette_tools.core.integrity import IntegrityError
from cascette_tools.formats.file_db import (
    FileDatabase,
    FileDbEntry,
    FileDbMeta,
)


def _make_entry(
    index: int,
    ekey: bytes,
    ckey: bytes,
    path: str,
) -> FileDbEntry:
    """Create a test FileDbEntry."""
    return FileDbEntry(
        file_index=index,
        ekey=ekey,
        ckey=ckey,
        encoded_size=100,
        decoded_size=200,
        flags=0,
        relative_path=path,
    )


def _make_file_db(entries: list[FileDbEntry]) -> FileDatabase:
    """Create a test FileDatabase."""
    return FileDatabase(
        meta=FileDbMeta(id=1, entry_count=len(entries)),
        tags=[],
        entries=entries,
    )


class TestContainerlessStorage:
    """Test containerless storage operations."""

    def test_initialize(self, tmp_path: Path):
        """Initialize creates the base directory."""
        base = tmp_path / "game"
        storage = ContainerlessStorage(base)
        storage.initialize()

        assert base.exists()
        assert base.is_dir()

    def test_write_content(self, tmp_path: Path):
        """Write content creates file at expected path."""
        ekey = b'\x01' * 16
        ckey = b'\x02' * 16
        content = b"Hello, World!"

        entries = [_make_entry(0, ekey, ckey, "Data/file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        result_path = storage.write_content(ekey, content)

        assert result_path == tmp_path / "Data" / "file.txt"
        assert result_path.exists()
        assert result_path.read_bytes() == content

    def test_write_content_with_backslash_path(self, tmp_path: Path):
        """Windows-style backslash paths are normalized."""
        ekey = b'\x01' * 16
        ckey = b'\x02' * 16
        content = b"test data"

        entries = [_make_entry(0, ekey, ckey, r"Data\sub\file.dat")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        result_path = storage.write_content(ekey, content)

        assert result_path == tmp_path / "Data" / "sub" / "file.dat"
        assert result_path.exists()

    def test_write_content_dedup(self, tmp_path: Path):
        """Duplicate writes are skipped."""
        ekey = b'\x01' * 16
        ckey = b'\x02' * 16
        content = b"data"

        entries = [_make_entry(0, ekey, ckey, "file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        path1 = storage.write_content(ekey, content)
        path2 = storage.write_content(ekey, content)

        assert path1 == path2

    def test_write_content_ckey_verification_pass(self, tmp_path: Path):
        """Content key verification passes when MD5 matches."""
        content = b"verified content"
        ckey = hashlib.md5(content).digest()
        ekey = b'\x01' * 16

        entries = [_make_entry(0, ekey, ckey, "file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        # Should not raise
        storage.write_content(ekey, content, expected_ckey=ckey)

    def test_write_content_ckey_verification_fail(self, tmp_path: Path):
        """Content key verification fails when MD5 does not match."""
        content = b"wrong content"
        expected_ckey = b'\xff' * 16
        ekey = b'\x01' * 16

        entries = [_make_entry(0, ekey, expected_ckey, "file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        with pytest.raises(IntegrityError):
            storage.write_content(ekey, content, expected_ckey=expected_ckey)

    def test_write_content_unknown_ekey(self, tmp_path: Path):
        """Writing with unknown encoding key raises KeyError."""
        entries = [_make_entry(0, b'\x01' * 16, b'\x02' * 16, "file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        unknown_ekey = b'\xff' * 16
        with pytest.raises(KeyError):
            storage.write_content(unknown_ekey, b"data")

    def test_file_exists(self, tmp_path: Path):
        """file_exists returns True when file is on disk."""
        ekey = b'\x01' * 16
        entries = [_make_entry(0, ekey, b'\x02' * 16, "file.txt")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        assert storage.file_exists(ekey) is False

        storage.write_content(ekey, b"data")

        assert storage.file_exists(ekey) is True

    def test_get_file_path(self, tmp_path: Path):
        """get_file_path resolves ekey to full path."""
        ekey = b'\x01' * 16
        entries = [_make_entry(0, ekey, b'\x02' * 16, "game/model.m2")]
        db = _make_file_db(entries)

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)

        path = storage.get_file_path(ekey)
        assert path == tmp_path / "game" / "model.m2"

        # Unknown key returns None
        assert storage.get_file_path(b'\xff' * 16) is None

    def test_identify_file_matching(self, tmp_path: Path):
        """identify_file detects matching content."""
        content = b"test content for hashing"
        ckey = hashlib.md5(content).digest()
        ekey = b'\x01' * 16

        entry = _make_entry(0, ekey, ckey, "file.txt")
        db = _make_file_db([entry])

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        # Write the file
        (tmp_path / "file.txt").write_bytes(content)

        actual_md5, matches = storage.identify_file(entry)
        assert matches is True
        assert actual_md5 == ckey

    def test_identify_file_not_matching(self, tmp_path: Path):
        """identify_file detects non-matching content."""
        ekey = b'\x01' * 16
        ckey = b'\xaa' * 16  # Won't match actual content

        entry = _make_entry(0, ekey, ckey, "file.txt")
        db = _make_file_db([entry])

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)
        storage.initialize()

        (tmp_path / "file.txt").write_bytes(b"different content")

        actual_md5, matches = storage.identify_file(entry)
        assert matches is False

    def test_identify_file_missing(self, tmp_path: Path):
        """identify_file handles missing files."""
        ekey = b'\x01' * 16
        entry = _make_entry(0, ekey, b'\x02' * 16, "missing.txt")
        db = _make_file_db([entry])

        storage = ContainerlessStorage(tmp_path)
        storage.set_file_database(db)

        actual_md5, matches = storage.identify_file(entry)
        assert matches is False
        assert actual_md5 == b''
