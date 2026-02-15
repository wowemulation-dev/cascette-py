"""Tests for CDN archive index format parser."""

from __future__ import annotations

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
    """Build a single archive index entry."""
    entry = bytearray()
    # Pad or truncate key
    if len(key) < key_bytes:
        entry.extend(key + b"\x00" * (key_bytes - len(key)))
    else:
        entry.extend(key[:key_bytes])

    if archive_index is not None:
        entry.extend(struct.pack(">H", archive_index))
    entry.extend(struct.pack(">I", offset))
    entry.extend(struct.pack(">I", size))
    return bytes(entry)


def _build_archive_index(
    entries: list[tuple[bytes, int, int]],
    *,
    key_bytes: int = 16,
    offset_bytes: int = 4,
) -> bytes:
    """Build a complete archive index with entries and footer."""
    data = bytearray()
    for key, offset, size in entries:
        data.extend(_build_entry(key, offset, size, key_bytes=key_bytes))

    footer = _build_footer(
        entry_count=len(entries),
        key_bytes=key_bytes,
        offset_bytes=offset_bytes,
    )
    data.extend(footer)
    return bytes(data)


def _build_archive_group(
    entries: list[tuple[bytes, int, int, int]],
    *,
    key_bytes: int = 16,
) -> bytes:
    """Build archive-group with (key, archive_index, offset, size) entries."""
    data = bytearray()
    for key, archive_idx, offset, size in entries:
        data.extend(
            _build_entry(key, offset, size, archive_index=archive_idx, key_bytes=key_bytes)
        )

    footer = _build_footer(
        entry_count=len(entries),
        key_bytes=key_bytes,
        offset_bytes=6,  # archive-group uses 6-byte offsets
    )
    data.extend(footer)
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
        entries_data = bytearray()
        entries_data.extend(key)
        entries_data.extend(struct.pack(">I", 100))
        entries_data.extend(struct.pack(">I", 50))
        entries_data.extend(
            _build_footer(entry_count=1, key_bytes=9, offset_bytes=4)
        )
        result = self.parser.parse(bytes(entries_data))
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
