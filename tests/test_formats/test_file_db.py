"""Tests for file database parser."""

import sqlite3

import pytest

from cascette_tools.formats.file_db import (
    FileDatabaseParser,
    FileDbTag,
    _build_tags_blob,
    _parse_tags_blob,
    is_file_db,
)


def _make_test_db(
    entries: list[tuple[int, bytes, bytes, int, int, int, str]],
    tags_blob: bytes | None = None,
    entry_count: int | None = None,
) -> bytes:
    """Create a synthetic SQLite file database blob for testing."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY, entry_count INTEGER)")
    conn.execute("CREATE TABLE tags (id INTEGER PRIMARY KEY, data BLOB)")
    conn.execute(
        "CREATE TABLE files ("
        "file_index INTEGER PRIMARY KEY, ekey BLOB, ckey BLOB, "
        "encoded_size INTEGER, decoded_size INTEGER, "
        "flags INTEGER, relative_path TEXT)"
    )

    count = entry_count if entry_count is not None else len(entries)
    conn.execute("INSERT INTO meta (id, entry_count) VALUES (1, ?)", (count,))

    if tags_blob is not None:
        conn.execute("INSERT INTO tags (id, data) VALUES (1, ?)", (tags_blob,))

    for idx, ekey, ckey, enc_sz, dec_sz, flags, path in entries:
        conn.execute(
            "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
            (idx, ekey, ckey, enc_sz, dec_sz, flags, path),
        )

    conn.commit()
    result = conn.serialize()
    conn.close()
    return bytes(result) if result is not None else b""


class TestFileDatabaseParser:
    """Test file database parser."""

    def test_parse_empty_db(self):
        """Parse a file database with no entries."""
        blob = _make_test_db([], entry_count=0)
        parser = FileDatabaseParser()
        db = parser.parse(blob)

        assert db.meta.id == 1
        assert db.meta.entry_count == 0
        assert db.entries == []
        assert db.tags == []

    def test_parse_with_entries(self):
        """Parse a file database with file entries."""
        ekey = b'\x01' * 16
        ckey = b'\x02' * 16
        entries = [(0, ekey, ckey, 1000, 2000, 0, r"Data\file.dat")]

        blob = _make_test_db(entries)
        parser = FileDatabaseParser()
        db = parser.parse(blob)

        assert db.meta.entry_count == 1
        assert len(db.entries) == 1
        assert db.entries[0].file_index == 0
        assert db.entries[0].ekey == ekey
        assert db.entries[0].ckey == ckey
        assert db.entries[0].encoded_size == 1000
        assert db.entries[0].decoded_size == 2000
        assert db.entries[0].flags == 0
        assert db.entries[0].relative_path == r"Data\file.dat"

    def test_parse_multiple_entries(self):
        """Parse a file database with multiple entries."""
        entries = [
            (0, b'\x01' * 16, b'\x02' * 16, 100, 200, 0, "file1.dat"),
            (1, b'\x03' * 16, b'\x04' * 16, 300, 400, 1, "sub/file2.dat"),
            (2, b'\x05' * 16, b'\x06' * 16, 500, 600, 0, r"Data\sub\file3.dat"),
        ]

        blob = _make_test_db(entries, entry_count=3)
        parser = FileDatabaseParser()
        db = parser.parse(blob)

        assert db.meta.entry_count == 3
        assert len(db.entries) == 3
        assert db.entries[0].relative_path == "file1.dat"
        assert db.entries[1].relative_path == "sub/file2.dat"
        assert db.entries[2].relative_path == r"Data\sub\file3.dat"

    def test_roundtrip_parse_build(self):
        """Round-trip: parse → build → parse produces identical results."""
        ekey = b'\xaa' * 16
        ckey = b'\xbb' * 16
        entries = [
            (0, ekey, ckey, 1234, 5678, 42, "game/data/model.m2"),
            (1, b'\xcc' * 16, b'\xdd' * 16, 999, 1999, 0, "game/data/tex.blp"),
        ]

        blob = _make_test_db(entries, entry_count=2)
        parser = FileDatabaseParser()

        db1 = parser.parse(blob)
        rebuilt = parser.build(db1)
        db2 = parser.parse(rebuilt)

        assert db2.meta.entry_count == db1.meta.entry_count
        assert len(db2.entries) == len(db1.entries)
        for e1, e2 in zip(db1.entries, db2.entries, strict=True):
            assert e1.file_index == e2.file_index
            assert e1.ekey == e2.ekey
            assert e1.ckey == e2.ckey
            assert e1.encoded_size == e2.encoded_size
            assert e1.decoded_size == e2.decoded_size
            assert e1.flags == e2.flags
            assert e1.relative_path == e2.relative_path

    def test_salsa20_encrypted_detection(self):
        """Encrypted file database raises ValueError."""
        data = b'\x45' + b'\x00' * 100
        parser = FileDatabaseParser()

        with pytest.raises(ValueError, match="Salsa20-encrypted"):
            parser.parse(data)

    def test_empty_blob_raises(self):
        """Empty blob raises ValueError."""
        parser = FileDatabaseParser()
        with pytest.raises(ValueError, match="Empty"):
            parser.parse(b"")


class TestFileDbTags:
    """Test tag parsing and bitmask operations."""

    def test_parse_tags_blob(self):
        """Parse a binary tags blob."""
        import struct

        # Build a tags blob with one tag: "Windows", type=1, bitmask=[0x80]
        name = b"Windows"
        blob = struct.pack('<H', len(name)) + name + struct.pack('<H', 1) + b'\x80'

        tags = _parse_tags_blob(blob, entry_count=1)
        assert len(tags) == 1
        assert tags[0].name == "Windows"
        assert tags[0].tag_type == 1
        assert tags[0].bit_mask == b'\x80'

    def test_build_tags_blob_roundtrip(self):
        """Tags blob roundtrip: build → parse produces identical tags."""
        tags = [
            FileDbTag(name="Windows", tag_type=1, bit_mask=b'\xa4'),
            FileDbTag(name="enUS", tag_type=2, bit_mask=b'\xc0'),
        ]
        blob = _build_tags_blob(tags)
        parsed = _parse_tags_blob(blob, entry_count=8)

        assert len(parsed) == 2
        assert parsed[0].name == "Windows"
        assert parsed[0].tag_type == 1
        assert parsed[0].bit_mask == b'\xa4'
        assert parsed[1].name == "enUS"
        assert parsed[1].tag_type == 2
        assert parsed[1].bit_mask == b'\xc0'

    def test_tag_has_file_msb_ordering(self):
        """Test MSB bit ordering matches InstallTag behavior."""
        # Files 0, 2, 5 = 0x80 | 0x20 | 0x04 = 0xA4
        tag = FileDbTag(name="test", tag_type=1, bit_mask=bytes([0xA4]))

        assert tag.has_file(0) is True   # 0x80
        assert tag.has_file(1) is False
        assert tag.has_file(2) is True   # 0x20
        assert tag.has_file(3) is False
        assert tag.has_file(4) is False
        assert tag.has_file(5) is True   # 0x04
        assert tag.has_file(6) is False
        assert tag.has_file(7) is False
        assert tag.has_file(8) is False  # out of range

    def test_parse_db_with_tags(self):
        """Parse a file database including tags."""
        import struct

        name = b"Windows"
        tags_blob = struct.pack('<H', len(name)) + name + struct.pack('<H', 1) + b'\x80'

        entries = [(0, b'\x01' * 16, b'\x02' * 16, 100, 200, 0, "file.dat")]
        blob = _make_test_db(entries, tags_blob=tags_blob, entry_count=1)

        parser = FileDatabaseParser()
        db = parser.parse(blob)

        assert len(db.tags) == 1
        assert db.tags[0].name == "Windows"
        assert db.tags[0].has_file(0) is True

    def test_filter_by_tags(self):
        """Test FileDatabase.filter_by_tags()."""
        import struct

        # Two tags: "Windows" covers file 0, "enUS" covers files 0 and 1
        win_name = b"Windows"
        enus_name = b"enUS"
        tags_blob = (
            struct.pack('<H', len(win_name)) + win_name + struct.pack('<H', 1) + b'\x80'
            + struct.pack('<H', len(enus_name)) + enus_name + struct.pack('<H', 2) + b'\xc0'
        )

        entries = [
            (0, b'\x01' * 16, b'\x02' * 16, 100, 200, 0, "file0.dat"),
            (1, b'\x03' * 16, b'\x04' * 16, 100, 200, 0, "file1.dat"),
        ]
        blob = _make_test_db(entries, tags_blob=tags_blob, entry_count=2)

        db = FileDatabaseParser().parse(blob)

        # Filter by Windows only → file 0
        filtered = db.filter_by_tags(platform="Windows")
        assert len(filtered) == 1
        assert filtered[0].file_index == 0

        # Filter by enUS only → files 0 and 1
        filtered = db.filter_by_tags(locale="enUS")
        assert len(filtered) == 2

        # Filter by Windows AND enUS → only file 0 (intersection)
        filtered = db.filter_by_tags(platform="Windows", locale="enUS")
        assert len(filtered) == 1
        assert filtered[0].file_index == 0

        # No filters → all entries
        filtered = db.filter_by_tags()
        assert len(filtered) == 2


class TestIsFileDb:
    """Test is_file_db detection function."""

    def test_sqlite_magic(self):
        """SQLite files are detected."""
        assert is_file_db(b'SQLite format 3\x00' + b'\x00' * 100)

    def test_encrypted_marker(self):
        """Salsa20 encrypted marker is detected."""
        assert is_file_db(b'\x45' + b'\x00' * 100)

    def test_unknown_format(self):
        """Unknown formats are not detected."""
        assert not is_file_db(b'\x00\x00\x00\x00')
        assert not is_file_db(b'BLTE')
        assert not is_file_db(b'')
        assert not is_file_db(b'\x01')
