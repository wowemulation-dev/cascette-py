"""Tests for containerless update delta logic."""

import hashlib
from pathlib import Path

from cascette_tools.core.containerless_update import (
    ContainerlessClassification,
    classify_containerless_files,
    identify_existing_files,
)
from cascette_tools.formats.file_db import (
    FileDatabase,
    FileDbEntry,
    FileDbMeta,
)


def _make_entry(
    index: int,
    ekey: bytes,
    content: bytes,
    path: str,
) -> FileDbEntry:
    """Create a FileDbEntry with ckey = MD5(content)."""
    return FileDbEntry(
        file_index=index,
        ekey=ekey,
        ckey=hashlib.md5(content).digest(),
        encoded_size=len(content),
        decoded_size=len(content),
        flags=0,
        relative_path=path,
    )


def _make_entry_raw(
    index: int,
    ekey: bytes,
    ckey: bytes,
    path: str,
) -> FileDbEntry:
    """Create a FileDbEntry with explicit ckey."""
    return FileDbEntry(
        file_index=index,
        ekey=ekey,
        ckey=ckey,
        encoded_size=100,
        decoded_size=200,
        flags=0,
        relative_path=path,
    )


def _make_db(entries: list[FileDbEntry]) -> FileDatabase:
    return FileDatabase(
        meta=FileDbMeta(id=1, entry_count=len(entries)),
        tags=[],
        entries=entries,
    )


class TestIdentifyExistingFiles:
    """Test file identification (hashing)."""

    def test_identify_existing(self, tmp_path: Path):
        """Existing files are hashed correctly."""
        content = b"test file content"
        (tmp_path / "file.txt").write_bytes(content)

        entry = _make_entry(0, b'\x01' * 16, content, "file.txt")
        db = _make_db([entry])

        hashes = identify_existing_files(tmp_path, db)

        assert 0 in hashes
        assert hashes[0] == hashlib.md5(content).digest()

    def test_identify_missing(self, tmp_path: Path):
        """Missing files are omitted from results."""
        entry = _make_entry(0, b'\x01' * 16, b"data", "missing.txt")
        db = _make_db([entry])

        hashes = identify_existing_files(tmp_path, db)

        assert 0 not in hashes

    def test_identify_mixed(self, tmp_path: Path):
        """Mix of existing and missing files."""
        content_a = b"file A"
        content_b = b"file B"
        (tmp_path / "a.txt").write_bytes(content_a)
        # b.txt does not exist

        entries = [
            _make_entry(0, b'\x01' * 16, content_a, "a.txt"),
            _make_entry(1, b'\x02' * 16, content_b, "b.txt"),
        ]
        db = _make_db(entries)

        hashes = identify_existing_files(tmp_path, db)

        assert 0 in hashes
        assert 1 not in hashes


class TestClassifyContainerlessFiles:
    """Test file classification for containerless updates."""

    def test_fresh_install(self, tmp_path: Path):
        """Fresh install: all files need download."""
        entries = [
            _make_entry_raw(0, b'\x01' * 16, b'\xaa' * 16, "file1.txt"),
            _make_entry_raw(1, b'\x02' * 16, b'\xbb' * 16, "file2.txt"),
        ]
        db = _make_db(entries)

        delta = classify_containerless_files(tmp_path, None, db)

        assert delta.unchanged_count == 0
        assert delta.download_count == 2
        assert delta.obsolete_count == 0
        assert len(delta.download_entries) == 2

    def test_all_unchanged(self, tmp_path: Path):
        """All files exist and match."""
        content_a = b"content A"
        content_b = b"content B"

        (tmp_path / "a.txt").write_bytes(content_a)
        (tmp_path / "b.txt").write_bytes(content_b)

        entries = [
            _make_entry(0, b'\x01' * 16, content_a, "a.txt"),
            _make_entry(1, b'\x02' * 16, content_b, "b.txt"),
        ]
        db = _make_db(entries)

        delta = classify_containerless_files(tmp_path, None, db)

        assert delta.unchanged_count == 2
        assert delta.download_count == 0
        assert delta.obsolete_count == 0

    def test_mixed_classification(self, tmp_path: Path):
        """Mix of unchanged, needs download, and obsolete files."""
        content_unchanged = b"same content"
        content_changed = b"old content"

        (tmp_path / "unchanged.txt").write_bytes(content_unchanged)
        (tmp_path / "changed.txt").write_bytes(content_changed)

        # Old DB has an extra file that's not in the new DB
        old_entries = [
            _make_entry(0, b'\x01' * 16, content_unchanged, "unchanged.txt"),
            _make_entry(1, b'\x02' * 16, content_changed, "changed.txt"),
            _make_entry_raw(2, b'\x03' * 16, b'\xcc' * 16, "obsolete.txt"),
        ]
        old_db = _make_db(old_entries)

        # New DB: unchanged stays, changed has new ckey, obsolete is gone
        new_content_changed = b"new content"
        new_entries = [
            _make_entry(0, b'\x01' * 16, content_unchanged, "unchanged.txt"),
            _make_entry(1, b'\x04' * 16, new_content_changed, "changed.txt"),
        ]
        new_db = _make_db(new_entries)

        delta = classify_containerless_files(tmp_path, old_db, new_db)

        assert delta.unchanged_count == 1
        assert delta.download_count == 1
        assert delta.obsolete_count == 1
        assert len(delta.download_entries) == 1
        assert delta.download_entries[0].relative_path == "changed.txt"
        assert "obsolete.txt" in delta.obsolete_paths

    def test_obsolete_with_backslash_paths(self, tmp_path: Path):
        """Backslash paths are normalized for obsolete detection."""
        old_entries = [
            _make_entry_raw(0, b'\x01' * 16, b'\xaa' * 16, r"Data\old.txt"),
        ]
        old_db = _make_db(old_entries)

        new_entries = [
            _make_entry_raw(0, b'\x02' * 16, b'\xbb' * 16, r"Data\new.txt"),
        ]
        new_db = _make_db(new_entries)

        delta = classify_containerless_files(tmp_path, old_db, new_db)

        assert delta.obsolete_count == 1
        assert "Data/old.txt" in delta.obsolete_paths

    def test_no_obsolete_without_old_db(self, tmp_path: Path):
        """Without old DB, no files are marked obsolete."""
        entries = [
            _make_entry_raw(0, b'\x01' * 16, b'\xaa' * 16, "file.txt"),
        ]
        db = _make_db(entries)

        delta = classify_containerless_files(tmp_path, None, db)

        assert delta.obsolete_count == 0
        assert delta.obsolete_paths == []


class TestContainerlessClassification:
    """Test the classification enum values."""

    def test_values_match_agent(self):
        """Classification values match Agent.exe constants."""
        assert ContainerlessClassification.unchanged.value == 0
        assert ContainerlessClassification.needs_download.value == 1
        assert ContainerlessClassification.obsolete.value == 6
