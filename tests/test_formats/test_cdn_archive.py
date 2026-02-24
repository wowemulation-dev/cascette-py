"""Tests for CDN archive index format parser."""

from __future__ import annotations

import hashlib
import struct
from io import BytesIO

import pytest

from cascette_tools.formats.cdn_archive import (
    CdnArchiveFooter,
    CdnArchiveParser,
    is_archive_group,
    is_cdn_archive_index,
)


def _build_footer(
    *,
    version: int = 1,
    page_size_kb: int = 4,
    offset_bytes: int = 4,
    size_bytes: int = 4,
    key_bytes: int = 16,
    footer_hash_bytes: int = 8,
    entry_count: int = 0,
) -> bytes:
    """Build a 28-byte footer for testing."""
    toc_hash = b"\x00" * 8
    reserved = b"\x00\x00"
    footer_hash = b"\x00" * 8

    footer = bytearray()
    footer.extend(toc_hash)
    footer.append(version)
    footer.extend(reserved)
    footer.append(page_size_kb)
    footer.append(offset_bytes)
    footer.append(size_bytes)
    footer.append(key_bytes)
    footer.append(footer_hash_bytes)
    footer.extend(struct.pack("<I", entry_count))
    footer.extend(footer_hash)
    assert len(footer) == 28
    return bytes(footer)


def _build_entry(
    key: bytes,
    offset: int,
    size: int,
    *,
    archive_index: int | None = None,
    key_bytes: int = 16,
) -> bytes:
    """Build a single archive index entry.

    Binary layout: [key][size][offset] (size comes before offset).
    For archive-groups: [key][size][archive_index(2) + offset(4)].
    """
    entry = bytearray()
    # Pad or truncate key
    if len(key) < key_bytes:
        entry.extend(key + b"\x00" * (key_bytes - len(key)))
    else:
        entry.extend(key[:key_bytes])

    # Size comes before offset in the binary format
    entry.extend(struct.pack(">I", size))

    if archive_index is not None:
        entry.extend(struct.pack(">H", archive_index))
    entry.extend(struct.pack(">I", offset))
    return bytes(entry)


def _build_archive_index(
    entries: list[tuple[bytes, int, int]],
    *,
    key_bytes: int = 16,
    offset_bytes: int = 4,
    page_size_kb: int = 4,
    footer_hash_bytes: int = 8,
) -> bytes:
    """Build a complete archive index with correct paged layout.

    Layout: [Pages][TOC keys][TOC hashes][Footer]
    Pages start at byte 0. TOC follows after all pages.
    """
    page_size = page_size_kb * 1024
    entry_size = key_bytes + offset_bytes + 4  # 4 = size_bytes
    entries_per_page = page_size // entry_size

    pages = bytearray()
    toc_keys = bytearray()
    toc_hashes = bytearray()
    for page_start in range(0, max(len(entries), 1), entries_per_page):
        page_entries = entries[page_start:page_start + entries_per_page]
        page_data = bytearray()
        last_key = b'\x00' * key_bytes
        for key, offset, size in page_entries:
            padded_key = (key + b'\x00' * key_bytes)[:key_bytes]
            last_key = padded_key
            page_data.extend(_build_entry(key, offset, size, key_bytes=key_bytes))
        page_data.extend(b'\x00' * (page_size - len(page_data)))
        pages.extend(page_data)
        toc_keys.extend(last_key)
        toc_hashes.extend(hashlib.md5(bytes(page_data)).digest()[:footer_hash_bytes])

    data = bytearray()
    data.extend(pages)
    data.extend(toc_keys)
    data.extend(toc_hashes)
    data.extend(_build_footer(
        entry_count=len(entries),
        key_bytes=key_bytes,
        offset_bytes=offset_bytes,
        page_size_kb=page_size_kb,
        footer_hash_bytes=footer_hash_bytes,
    ))
    return bytes(data)


def _build_archive_group(
    entries: list[tuple[bytes, int, int, int]],
    *,
    key_bytes: int = 16,
    page_size_kb: int = 4,
    footer_hash_bytes: int = 8,
) -> bytes:
    """Build archive-group with correct paged layout."""
    page_size = page_size_kb * 1024
    entry_size = key_bytes + 6 + 4  # 6 = offset_bytes, 4 = size_bytes
    entries_per_page = page_size // entry_size

    pages = bytearray()
    toc_keys = bytearray()
    toc_hashes = bytearray()
    for page_start in range(0, max(len(entries), 1), entries_per_page):
        page_entries = entries[page_start:page_start + entries_per_page]
        page_data = bytearray()
        last_key = b'\x00' * key_bytes
        for key, archive_idx, offset, size in page_entries:
            padded_key = (key + b'\x00' * key_bytes)[:key_bytes]
            last_key = padded_key
            page_data.extend(
                _build_entry(key, offset, size, archive_index=archive_idx, key_bytes=key_bytes)
            )
        page_data.extend(b'\x00' * (page_size - len(page_data)))
        pages.extend(page_data)
        toc_keys.extend(last_key)
        toc_hashes.extend(hashlib.md5(bytes(page_data)).digest()[:footer_hash_bytes])

    data = bytearray()
    data.extend(pages)
    data.extend(toc_keys)
    data.extend(toc_hashes)
    data.extend(_build_footer(
        entry_count=len(entries),
        key_bytes=key_bytes,
        offset_bytes=6,
        page_size_kb=page_size_kb,
        footer_hash_bytes=footer_hash_bytes,
    ))
    return bytes(data)


class TestCdnArchiveFooter:
    """Tests for footer model."""

    def test_is_archive_group_true(self) -> None:
        footer = CdnArchiveFooter(
            toc_hash=b"\x00" * 8,
            version=1,
            reserved=b"\x00\x00",
            page_size_kb=4,
            offset_bytes=6,
            size_bytes=4,
            key_bytes=16,
            footer_hash_bytes=8,
            entry_count=0,
            footer_hash=b"\x00" * 8,
        )
        assert footer.is_archive_group is True

    def test_is_archive_group_false(self) -> None:
        footer = CdnArchiveFooter(
            toc_hash=b"\x00" * 8,
            version=1,
            reserved=b"\x00\x00",
            page_size_kb=4,
            offset_bytes=4,
            size_bytes=4,
            key_bytes=16,
            footer_hash_bytes=8,
            entry_count=0,
            footer_hash=b"\x00" * 8,
        )
        assert footer.is_archive_group is False


class TestCdnArchiveParser:
    """Tests for the CDN archive parser."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_parse_empty_archive(self) -> None:
        data = _build_archive_index([])
        result = self.parser.parse(data)
        assert len(result.entries) == 0
        assert result.footer.entry_count == 0

    def test_parse_single_entry(self) -> None:
        key = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        data = _build_archive_index([(key, 1000, 500)])
        result = self.parser.parse(data)
        assert len(result.entries) == 1
        assert result.entries[0].encoding_key == key
        assert result.entries[0].offset == 1000
        assert result.entries[0].size == 500
        assert result.entries[0].archive_index is None

    def test_parse_multiple_entries(self) -> None:
        entries = [
            (bytes([i] * 16), i * 100, i * 50)
            for i in range(1, 4)
        ]
        data = _build_archive_index(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 3

    def test_parse_skips_zero_entries(self) -> None:
        entries = [
            (b"\x00" * 16, 0, 0),  # Zero key - should be skipped
            (b"\x01" * 16, 100, 50),
        ]
        data = _build_archive_index(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 1

    def test_parse_archive_group(self) -> None:
        entries = [
            (b"\x01" * 16, 5, 1000, 500),
            (b"\x02" * 16, 10, 2000, 600),
        ]
        data = _build_archive_group(entries)
        result = self.parser.parse(data)
        assert result.footer.is_archive_group
        assert len(result.entries) == 2
        assert result.entries[0].archive_index == 5
        assert result.entries[0].offset == 1000
        assert result.entries[1].archive_index == 10

    def test_parse_footer_version(self) -> None:
        data = _build_archive_index([])
        result = self.parser.parse(data)
        assert result.footer.version == 1

    def test_parse_footer_key_bytes(self) -> None:
        data = _build_archive_index([], key_bytes=9)
        result = self.parser.parse(data)
        assert result.footer.key_bytes == 9

    def test_parse_from_stream(self) -> None:
        raw = _build_archive_index([(b"\xAB" * 16, 100, 50)])
        stream = BytesIO(raw)
        result = self.parser.parse(stream)
        assert len(result.entries) == 1

    def test_parse_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            self.parser.parse(b"\x00" * 10)

    def test_parse_9_byte_keys(self) -> None:
        key = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        data = _build_archive_index([(key, 100, 50)], key_bytes=9)
        result = self.parser.parse(data)
        assert len(result.entries) == 1
        assert result.entries[0].encoding_key == key


class TestCdnArchiveParserFindEntry:
    """Tests for entry lookup."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_find_existing_entry(self) -> None:
        key = b"\x01" * 16
        data = _build_archive_index([(key, 100, 50)])
        index = self.parser.parse(data)
        entry = self.parser.find_entry(index, key)
        assert entry is not None
        assert entry.offset == 100

    def test_find_nonexistent_entry(self) -> None:
        data = _build_archive_index([(b"\x01" * 16, 100, 50)])
        index = self.parser.parse(data)
        entry = self.parser.find_entry(index, b"\xFF" * 16)
        assert entry is None

    def test_find_with_longer_key(self) -> None:
        """Search key longer than stored key_bytes gets truncated."""
        key = b"\x01" * 16
        data = _build_archive_index([(key, 100, 50)])
        index = self.parser.parse(data)
        # 20-byte search key truncated to 16
        long_key = b"\x01" * 20
        entry = self.parser.find_entry(index, long_key)
        assert entry is not None

    def test_find_with_shorter_key(self) -> None:
        """Search key shorter than stored key_bytes gets padded."""
        key = b"\x01" * 16
        data = _build_archive_index([(key, 100, 50)])
        index = self.parser.parse(data)
        # 8-byte search key padded with zeros - won't match \x01 * 16
        short_key = b"\x01" * 8
        entry = self.parser.find_entry(index, short_key)
        assert entry is None


class TestCdnArchiveParserArchiveIndices:
    """Tests for archive index distribution."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_regular_archive_returns_empty(self) -> None:
        data = _build_archive_index([(b"\x01" * 16, 100, 50)])
        index = self.parser.parse(data)
        assert self.parser.get_archive_indices(index) == {}

    def test_archive_group_distribution(self) -> None:
        entries = [
            (b"\x01" * 16, 5, 100, 50),
            (b"\x02" * 16, 5, 200, 60),
            (b"\x03" * 16, 10, 300, 70),
        ]
        data = _build_archive_group(entries)
        index = self.parser.parse(data)
        dist = self.parser.get_archive_indices(index)
        assert dist[5] == 2
        assert dist[10] == 1


class TestCdnArchiveParserStatistics:
    """Tests for statistics generation."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_empty_archive_stats(self) -> None:
        data = _build_archive_index([])
        index = self.parser.parse(data)
        stats = self.parser.get_statistics(index)
        assert stats["format"] == "archive-index"
        assert stats["total_entries"] == 0

    def test_archive_stats_with_entries(self) -> None:
        entries = [
            (b"\x01" * 16, 0, 100),
            (b"\x02" * 16, 100, 200),
            (b"\x03" * 16, 300, 50),
        ]
        data = _build_archive_index(entries)
        index = self.parser.parse(data)
        stats = self.parser.get_statistics(index)
        assert stats["total_entries"] == 3
        assert stats["min_size"] == 50
        assert stats["max_size"] == 200
        assert stats["total_size"] == 350

    def test_archive_group_stats(self) -> None:
        entries = [
            (b"\x01" * 16, 0, 100, 50),
            (b"\x02" * 16, 1, 200, 60),
        ]
        data = _build_archive_group(entries)
        index = self.parser.parse(data)
        stats = self.parser.get_statistics(index)
        assert stats["format"] == "archive-group"
        assert stats["unique_archive_indices"] == 2


class TestCdnArchiveParserBuild:
    """Tests for building archive index binary data."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_roundtrip_empty(self) -> None:
        original = _build_archive_index([])
        index = self.parser.parse(original)
        rebuilt = self.parser.build(index)
        reparsed = self.parser.parse(rebuilt)
        assert reparsed.footer.entry_count == 0

    def test_roundtrip_single_entry(self) -> None:
        key = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        original = _build_archive_index([(key, 1000, 500)])
        index = self.parser.parse(original)
        rebuilt = self.parser.build(index)
        reparsed = self.parser.parse(rebuilt)
        assert len(reparsed.entries) == 1
        assert reparsed.entries[0].encoding_key == key
        assert reparsed.entries[0].offset == 1000
        assert reparsed.entries[0].size == 500

    def test_roundtrip_archive_group(self) -> None:
        entries = [
            (b"\x01" * 16, 5, 1000, 500),
            (b"\x02" * 16, 10, 2000, 600),
        ]
        original = _build_archive_group(entries)
        index = self.parser.parse(original)
        rebuilt = self.parser.build(index)
        reparsed = self.parser.parse(rebuilt)
        assert reparsed.footer.is_archive_group
        assert len(reparsed.entries) == 2
        assert reparsed.entries[0].archive_index == 5

    def test_build_preserves_footer_fields(self) -> None:
        original = _build_archive_index([], key_bytes=9)
        index = self.parser.parse(original)
        rebuilt = self.parser.build(index)
        reparsed = self.parser.parse(rebuilt)
        assert reparsed.footer.key_bytes == 9
        assert reparsed.footer.version == 1


class TestIsCdnArchiveIndex:
    """Tests for format detection functions."""

    def test_valid_archive_index(self) -> None:
        data = _build_archive_index([])
        assert is_cdn_archive_index(data) is True

    def test_valid_archive_group(self) -> None:
        data = _build_archive_group([])
        assert is_cdn_archive_index(data) is True

    def test_too_short(self) -> None:
        assert is_cdn_archive_index(b"\x00" * 10) is False

    def test_wrong_version(self) -> None:
        data = bytearray(_build_archive_index([]))
        data[-20] = 99  # Corrupt version byte
        assert is_cdn_archive_index(bytes(data)) is False

    def test_wrong_size_bytes(self) -> None:
        data = bytearray(_build_archive_index([]))
        data[-15] = 8  # Invalid size_bytes (should be 4)
        assert is_cdn_archive_index(bytes(data)) is False


class TestIsArchiveGroup:
    """Tests for archive-group detection."""

    def test_archive_group_detected(self) -> None:
        data = _build_archive_group([])
        assert is_archive_group(data) is True

    def test_regular_archive_not_detected(self) -> None:
        data = _build_archive_index([])
        assert is_archive_group(data) is False

    def test_too_short(self) -> None:
        assert is_archive_group(b"\x00" * 10) is False


class TestCdnArchivePageBoundaries:
    """Tests for page boundary handling in CDN archive indices."""

    def setup_method(self) -> None:
        self.parser = CdnArchiveParser()

    def test_single_page_entries_not_corrupted_by_checksum(self) -> None:
        """Entries that don't fill a page must not leak checksum bytes."""
        # 3 entries at 24 bytes each = 72 bytes in a 4KB page.
        # Old parser would read through 4024 bytes of padding + checksum.
        entries = [
            (bytes([i] * 16), i * 1000, i * 100)
            for i in range(1, 4)
        ]
        data = _build_archive_index(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 3
        for i, entry in enumerate(result.entries, start=1):
            assert entry.offset == i * 1000
            assert entry.size == i * 100

    def test_multi_page_parsing(self) -> None:
        """Entries spanning multiple pages are all parsed correctly."""
        # With 16-byte keys, 4-byte offset, 4-byte size: entry_size = 24
        # 4KB page fits 4096 // 24 = 170 entries per page
        # 200 entries requires 2 pages
        entries = [
            (bytes([(i >> 8) & 0xFF, i & 0xFF] + [0] * 14), i * 10, i * 5)
            for i in range(1, 201)
        ]
        data = _build_archive_index(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 200
        # Check first entry
        assert result.entries[0].offset == 10
        assert result.entries[0].size == 5
        # Check last entry (on second page)
        assert result.entries[-1].offset == 2000
        assert result.entries[-1].size == 1000

    def test_exact_page_boundary(self) -> None:
        """Entries filling a page exactly still parse correctly."""
        # entry_size = 24, page = 4096, entries_per_page = 170
        # Exactly 170 entries fills one page with 170*24 = 4080 bytes
        # (16 bytes of zero padding remain, but no overflow)
        entries = [
            (bytes([(i >> 8) & 0xFF, i & 0xFF] + [0xAA] * 14), i, i * 2)
            for i in range(1, 171)
        ]
        data = _build_archive_index(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 170
        assert result.entries[0].offset == 1
        assert result.entries[-1].offset == 170

    def test_multi_page_roundtrip(self) -> None:
        """Build -> parse -> build -> parse roundtrip across page boundaries."""
        entries = [
            (bytes([(i >> 8) & 0xFF, i & 0xFF] + [0xBB] * 14), i * 100, i * 50)
            for i in range(1, 201)
        ]
        data = _build_archive_index(entries)
        index = self.parser.parse(data)
        rebuilt = self.parser.build(index)
        reparsed = self.parser.parse(rebuilt)
        assert len(reparsed.entries) == 200
        for orig, rebuilt_entry in zip(index.entries, reparsed.entries, strict=True):
            assert orig.encoding_key == rebuilt_entry.encoding_key
            assert orig.offset == rebuilt_entry.offset
            assert orig.size == rebuilt_entry.size

    def test_archive_group_multi_page(self) -> None:
        """Archive-group entries spanning pages parse correctly."""
        # entry_size = 16 + 6 + 4 = 26, entries_per_page = 4096 // 26 = 157
        entries = [
            (bytes([(i >> 8) & 0xFF, i & 0xFF] + [0xCC] * 14), i % 256, i * 10, i * 5)
            for i in range(1, 200)
        ]
        data = _build_archive_group(entries)
        result = self.parser.parse(data)
        assert len(result.entries) == 199
        assert result.footer.is_archive_group
        # Verify last entry (on second page)
        assert result.entries[-1].archive_index == 199 % 256
        assert result.entries[-1].offset == 1990
        assert result.entries[-1].size == 995
