"""Tests for cascette_tools.core.build_update."""

from __future__ import annotations

import hashlib
import struct

from cascette_tools.core.build_update import (
    FileClassification,
    classify_files,
    compare_configs,
)
from cascette_tools.core.encoding_cache import EncodingCache
from cascette_tools.formats.config import BuildConfig
from cascette_tools.formats.encoding import EncodingParser


def _make_key(seed: int) -> bytes:
    """Generate a deterministic 16-byte key from an integer seed."""
    return hashlib.md5(seed.to_bytes(4, "little")).digest()


def _build_encoding_data(ckey_ekey_pairs: list[tuple[bytes, bytes]]) -> bytes:
    """Build minimal encoding file binary data from CKey→EKey pairs.

    Format:
    - 2-byte magic "EN"
    - 20-byte header (version=1, key sizes=16, page sizes=4KB, counts, espec_size)
    - ESpec table ("n\\x00")
    - CKey index (one 32-byte entry per page: first_key + md5 checksum)
    - CKey pages (entries padded to 4KB)
    - EKey index (one 32-byte entry, dummy)
    - EKey pages (empty, 4KB)
    """
    page_size_kb = 4
    page_size = page_size_kb * 1024

    # Build CKey page entries
    page_entries = bytearray()
    for ckey, ekey in ckey_ekey_pairs:
        # key_count (1 byte)
        page_entries.append(1)
        # file_size: 40-bit BE (1 byte high + 4 bytes low) = 1024 bytes
        page_entries.append(0)
        page_entries.extend(struct.pack(">I", 1024))
        # content_key (16 bytes)
        page_entries.extend(ckey[:16])
        # encoding_key (16 bytes)
        page_entries.extend(ekey[:16])

    # Determine how many pages we need
    # Each entry is 1 + 5 + 16 + 16 = 38 bytes
    entries_per_page = page_size // 38
    ckey_page_count = max(1, (len(ckey_ekey_pairs) + entries_per_page - 1) // entries_per_page)

    # Pad page data to full page boundaries
    total_page_bytes = ckey_page_count * page_size
    page_data = bytes(page_entries).ljust(total_page_bytes, b"\x00")

    # ESpec table
    espec_data = b"n\x00"
    espec_size = len(espec_data)

    # Header
    header = bytearray()
    header.extend(b"EN")
    header.append(1)  # version
    header.append(16)  # ckey_size
    header.append(16)  # ekey_size
    header.extend(struct.pack(">H", page_size_kb))  # ckey_page_size_kb
    header.extend(struct.pack(">H", page_size_kb))  # ekey_page_size_kb
    header.extend(struct.pack(">I", ckey_page_count))  # ckey_page_count
    header.extend(struct.pack(">I", 1))  # ekey_page_count
    header.append(0)  # unknown
    header.extend(struct.pack(">I", espec_size))  # espec_size

    # CKey index entries (32 bytes each: first_key + checksum)
    # For simplicity, use the first CKey of each page as first_key
    ckey_index = bytearray()
    for i in range(ckey_page_count):
        start = i * entries_per_page
        if start < len(ckey_ekey_pairs):
            first_key = ckey_ekey_pairs[start][0][:16]
        else:
            first_key = b"\x00" * 16
        checksum = hashlib.md5(page_data[i * page_size : (i + 1) * page_size]).digest()
        ckey_index.extend(first_key)
        ckey_index.extend(checksum)

    # EKey index (dummy, 1 page)
    ekey_index = b"\x00" * 16 + hashlib.md5(b"\x00" * page_size).digest()

    # EKey page data (empty, 1 page)
    ekey_page_data = b"\x00" * page_size

    # Assemble
    result = bytearray()
    result.extend(header)
    result.extend(espec_data)
    result.extend(ckey_index)
    result.extend(page_data)
    result.extend(ekey_index)
    result.extend(ekey_page_data)

    return bytes(result)


def _make_ecache(entries: list[tuple[bytes, bytes]], tmp_path: object) -> EncodingCache:
    """Create an EncodingCache with the given CKey→EKey entries.

    Args:
        entries: List of (ckey, ekey) pairs
        tmp_path: pytest tmp_path fixture value

    Returns:
        Populated and flushed EncodingCache
    """
    from pathlib import Path

    ecache_path = Path(str(tmp_path)) / "ecache"
    ecache = EncodingCache(base_path=ecache_path)
    ecache.initialize()

    for ckey, ekey in entries:
        ecache.write_entry(ckey, ekey, 0)

    ecache.flush()

    # Reload to get sorted buckets for binary search
    loaded = EncodingCache.load(ecache_path)
    assert loaded is not None
    return loaded


class TestCompareConfigs:
    """Tests for compare_configs()."""

    def test_no_change(self) -> None:
        """Identical configs produce empty diff."""
        config = BuildConfig(
            encoding="aabb",
            root="ccdd",
            install="eeff",
            download="1122",
            size="3344",
        )
        diff = compare_configs(config, config)
        assert diff == {}

    def test_encoding_changed(self) -> None:
        """Encoding field change appears in diff."""
        old = BuildConfig(encoding="aabb", root="ccdd")
        new = BuildConfig(encoding="xxyy", root="ccdd")
        diff = compare_configs(old, new)
        assert "encoding" in diff
        assert diff["encoding"] == ("aabb", "xxyy")
        assert "root" not in diff

    def test_multiple_changes(self) -> None:
        """Multiple field changes all appear."""
        old = BuildConfig(encoding="aa", root="bb", download="cc")
        new = BuildConfig(encoding="xx", root="yy", download="cc")
        diff = compare_configs(old, new)
        assert len(diff) == 2
        assert "encoding" in diff
        assert "root" in diff
        assert "download" not in diff


class TestClassifyFiles:
    """Tests for classify_files()."""

    def test_all_unchanged(self, tmp_path: object) -> None:
        """When old ecache matches new encoding exactly, all are unchanged."""
        pairs = [(_make_key(i), _make_key(i + 100)) for i in range(5)]

        ecache = _make_ecache(pairs, tmp_path)
        encoding_data = _build_encoding_data(pairs)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert delta.unchanged_count == 5
        assert delta.download_count == 0
        assert delta.obsolete_count == 0
        assert len(delta.new_ekeys) == 0

    def test_new_file(self, tmp_path: object) -> None:
        """CKey in new encoding but not in old ecache → needs_download."""
        old_pairs = [(_make_key(1), _make_key(101))]
        new_pairs = [(_make_key(1), _make_key(101)), (_make_key(2), _make_key(102))]

        ecache = _make_ecache(old_pairs, tmp_path)
        encoding_data = _build_encoding_data(new_pairs)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert delta.unchanged_count == 1
        assert delta.download_count == 1
        new_ckey = _make_key(2)
        assert delta.classifications[new_ckey] == FileClassification.needs_download
        assert new_ckey in delta.new_ekeys
        assert delta.new_ekeys[new_ckey] == _make_key(102)

    def test_changed_ekey(self, tmp_path: object) -> None:
        """Same CKey but different EKey → needs_download."""
        ckey = _make_key(1)
        old_ekey = _make_key(101)
        new_ekey = _make_key(201)

        ecache = _make_ecache([(ckey, old_ekey)], tmp_path)
        encoding_data = _build_encoding_data([(ckey, new_ekey)])

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert delta.unchanged_count == 0
        assert delta.download_count == 1
        assert delta.classifications[ckey] == FileClassification.needs_download
        assert delta.new_ekeys[ckey] == new_ekey

    def test_obsolete(self, tmp_path: object) -> None:
        """CKey in old ecache but not in new encoding → obsolete."""
        old_pairs = [(_make_key(1), _make_key(101)), (_make_key(2), _make_key(102))]
        new_pairs = [(_make_key(1), _make_key(101))]

        ecache = _make_ecache(old_pairs, tmp_path)
        encoding_data = _build_encoding_data(new_pairs)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert delta.unchanged_count == 1
        assert delta.download_count == 0
        assert delta.obsolete_count == 1
        obsolete_ckey = _make_key(2)
        assert delta.classifications[obsolete_ckey] == FileClassification.obsolete
        assert len(delta.obsolete_ekeys) == 1
        assert delta.obsolete_ekeys[0] == (obsolete_ckey, _make_key(102))

    def test_mixed(self, tmp_path: object) -> None:
        """Combination of unchanged, needs_download, and obsolete."""
        ckey_unchanged = _make_key(1)
        ekey_unchanged = _make_key(101)

        ckey_changed = _make_key(2)
        old_ekey_changed = _make_key(102)
        new_ekey_changed = _make_key(202)

        ckey_new = _make_key(3)
        ekey_new = _make_key(103)

        ckey_obsolete = _make_key(4)
        ekey_obsolete = _make_key(104)

        old_pairs = [
            (ckey_unchanged, ekey_unchanged),
            (ckey_changed, old_ekey_changed),
            (ckey_obsolete, ekey_obsolete),
        ]
        new_pairs = [
            (ckey_unchanged, ekey_unchanged),
            (ckey_changed, new_ekey_changed),
            (ckey_new, ekey_new),
        ]

        ecache = _make_ecache(old_pairs, tmp_path)
        encoding_data = _build_encoding_data(new_pairs)

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert delta.unchanged_count == 1
        assert delta.download_count == 2  # changed + new
        assert delta.obsolete_count == 1

        assert delta.classifications[ckey_unchanged] == FileClassification.unchanged
        assert delta.classifications[ckey_changed] == FileClassification.needs_download
        assert delta.classifications[ckey_new] == FileClassification.needs_download
        assert delta.classifications[ckey_obsolete] == FileClassification.obsolete

    def test_get_download_ekeys(self, tmp_path: object) -> None:
        """new_ekeys contains correct EKeys for needs_download files."""
        ckey1 = _make_key(1)
        ekey1 = _make_key(101)
        ckey2 = _make_key(2)
        ekey2 = _make_key(102)

        # Only ckey2 is new (not in old ecache)
        ecache = _make_ecache([(ckey1, ekey1)], tmp_path)
        encoding_data = _build_encoding_data([(ckey1, ekey1), (ckey2, ekey2)])

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert ckey2 in delta.new_ekeys
        assert delta.new_ekeys[ckey2] == ekey2
        assert ckey1 not in delta.new_ekeys

    def test_get_obsolete_ekeys(self, tmp_path: object) -> None:
        """obsolete_ekeys contains correct (CKey, EKey) pairs."""
        ckey1 = _make_key(1)
        ekey1 = _make_key(101)
        ckey2 = _make_key(2)
        ekey2 = _make_key(102)

        ecache = _make_ecache([(ckey1, ekey1), (ckey2, ekey2)], tmp_path)
        # Only ckey1 in new encoding
        encoding_data = _build_encoding_data([(ckey1, ekey1)])

        parser = EncodingParser()
        encoding_file = parser.parse(encoding_data)

        delta = classify_files(ecache, encoding_data, encoding_file, parser)

        assert len(delta.obsolete_ekeys) == 1
        assert delta.obsolete_ekeys[0] == (ckey2, ekey2)


class TestObsoleteEntryStatus:
    """Test that obsolete entries use the correct non-resident status."""

    def test_obsolete_entry_status(self, tmp_path: object) -> None:
        """Verify that insert_entry with status=7 writes data-nonres entries."""
        from pathlib import Path

        from cascette_tools.core.local_storage import (
            LocalIndexEntry,
            LocalStorage,
            compute_bucket,
            format_idx_filename,
        )

        install_path = Path(str(tmp_path)) / "install"
        storage = LocalStorage(install_path)
        storage.initialize()

        # Write some content first so index files exist
        ekey = _make_key(50)
        storage.write_content(ekey, b"test data " * 10)
        storage.flush_indices()

        # Use the same bucket as the existing entry so the index file exists
        existing_bucket = compute_bucket(ekey)
        generation = storage.bucket_generations[existing_bucket]
        idx_path = storage.data_path / format_idx_filename(existing_bucket, generation)
        assert idx_path.exists()

        # Read update section before insert (should be all zeros at 0x10000)
        data_before = idx_path.read_bytes()
        update_offset = 0x10000
        assert data_before[update_offset : update_offset + 24] == b"\x00" * 24

        # Mark an entry as non-resident in the same bucket
        obsolete_ekey = _make_key(99)
        entry = LocalIndexEntry(
            key=obsolete_ekey[:9], archive_id=0, archive_offset=0, size=0
        )
        storage.insert_entry(existing_bucket, entry, status=7)

        # Verify the update section now has non-zero data (24-byte UpdateEntry)
        data_after = idx_path.read_bytes()
        assert data_after[update_offset : update_offset + 24] != b"\x00" * 24
