"""Tests for install.py utility functions."""

import pytest

from cascette_tools.commands.install import (
    _fmt_size,
    filter_entries_by_tags,
    get_product_enum,
)
from cascette_tools.core.types import Product
from cascette_tools.formats.download import DownloadEntry, DownloadTag
from cascette_tools.formats.size import SizeTag


class TestFmtSize:
    """Tests for _fmt_size function."""

    def test_bytes(self) -> None:
        assert _fmt_size(0) == "0 B"
        assert _fmt_size(100) == "100 B"
        assert _fmt_size(1023) == "1023 B"

    def test_kilobytes(self) -> None:
        assert _fmt_size(1024) == "1.0 KB"
        assert _fmt_size(1536) == "1.5 KB"
        assert _fmt_size(1048575) == "1024.0 KB"

    def test_megabytes(self) -> None:
        assert _fmt_size(1048576) == "1.0 MB"
        assert _fmt_size(1572864) == "1.5 MB"
        assert _fmt_size(1073741823) == "1024.0 MB"

    def test_gigabytes(self) -> None:
        assert _fmt_size(1073741824) == "1.0 GB"
        assert _fmt_size(1610612736) == "1.5 GB"
        assert _fmt_size(10737418240) == "10.0 GB"

    def test_large_values(self) -> None:
        assert _fmt_size(1099511627776) == "1024.0 GB"
        assert _fmt_size(2**40) == "1024.0 GB"


class TestGetProductEnum:
    """Tests for get_product_enum function."""

    def test_valid_product_wow(self) -> None:
        result = get_product_enum("wow")
        assert result == Product.WOW
        assert result.value == "wow"

    def test_valid_product_wow_classic(self) -> None:
        result = get_product_enum("wow_classic")
        assert result == Product.WOW_CLASSIC
        assert result.value == "wow_classic"

    def test_valid_product_wow_classic_era(self) -> None:
        result = get_product_enum("wow_classic_era")
        assert result == Product.WOW_CLASSIC_ERA
        assert result.value == "wow_classic_era"

    def test_valid_product_agent(self) -> None:
        result = get_product_enum("agent")
        assert result == Product.AGENT

    def test_valid_product_bna(self) -> None:
        result = get_product_enum("bna")
        assert result == Product.BNA

    def test_invalid_product_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown product code"):
            get_product_enum("invalid_product")

    def test_invalid_product_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Unknown product code"):
            get_product_enum("")

    def test_all_products_valid(self) -> None:
        expected_products = [
            "wow",
            "wow_classic",
            "wow_classic_era",
            "wow_classic_titan",
            "wow_anniversary",
            "wowt",
            "wowxptr",
            "fenris",
            "pro",
            "hsb",
            "hero",
            "s2",
            "s1",
            "w3",
            "osi",
            "wlby",
            "agent",
            "bna",
            "bts",
        ]
        for product_code in expected_products:
            result = get_product_enum(product_code)
            assert result.value == product_code


class TestFilterEntriesByTags:
    """Tests for filter_entries_by_tags function."""

    @pytest.fixture
    def sample_entries(self) -> list[DownloadEntry]:
        return [
            DownloadEntry(
                ekey=b"\x01" * 16,
                size=1000,
                priority=0,
            ),
            DownloadEntry(
                ekey=b"\x02" * 16,
                size=2000,
                priority=1,
            ),
            DownloadEntry(
                ekey=b"\x03" * 16,
                size=3000,
                priority=2,
            ),
        ]

    @pytest.fixture
    def sample_tags(self) -> list[DownloadTag]:
        return [
            DownloadTag(
                name="Windows",
                tag_type=1,
                file_mask=b"\x80",
            ),
            DownloadTag(
                name="enUS",
                tag_type=2,
                file_mask=b"\xc0",
            ),
        ]

    @pytest.fixture
    def sample_size_tags(self) -> list[SizeTag]:
        return [
            SizeTag(
                name="Windows",
                tag_id=1,
                tag_type=1,
                file_indices=[0],
                bit_mask=b"\x80",
            ),
            SizeTag(
                name="enUS",
                tag_id=2,
                tag_type=2,
                file_indices=[0, 1],
                bit_mask=b"\xc0",
            ),
        ]

    def test_no_filters_returns_all(
        self, sample_entries: list[DownloadEntry], sample_tags: list[DownloadTag]
    ) -> None:
        result = filter_entries_by_tags(sample_entries, sample_tags)
        assert result == sample_entries

    def test_empty_entries_returns_empty(self, sample_tags: list[DownloadTag]) -> None:
        result = filter_entries_by_tags([], sample_tags, platform="Windows")
        assert result == []

    def test_empty_tags_with_filter_returns_all(
        self, sample_entries: list[DownloadEntry]
    ) -> None:
        result = filter_entries_by_tags(sample_entries, [], platform="Windows")
        assert result == sample_entries

    def test_filter_with_size_tags(
        self,
        sample_entries: list[DownloadEntry],
        sample_size_tags: list[SizeTag],
    ) -> None:
        result = filter_entries_by_tags(
            sample_entries,
            [],
            platform="Windows",
            size_tags=sample_size_tags,
        )
        assert len(result) == 1
        assert result[0].ekey == b"\x01" * 16

    def test_filter_multiple_criteria(
        self,
        sample_entries: list[DownloadEntry],
        sample_size_tags: list[SizeTag],
    ) -> None:
        result = filter_entries_by_tags(
            sample_entries,
            [],
            platform="Windows",
            locale="enUS",
            size_tags=sample_size_tags,
        )
        assert len(result) >= 1

    def test_platform_filter_with_download_tags(
        self,
        sample_entries: list[DownloadEntry],
        sample_tags: list[DownloadTag],
    ) -> None:
        result = filter_entries_by_tags(
            sample_entries,
            sample_tags,
            platform="Windows",
        )
        assert len(result) == 1

    def test_locale_filter_with_download_tags(
        self,
        sample_entries: list[DownloadEntry],
        sample_tags: list[DownloadTag],
    ) -> None:
        result = filter_entries_by_tags(
            sample_entries,
            sample_tags,
            locale="enUS",
        )
        assert len(result) == 2

    def test_all_filter_parameters(
        self,
        sample_entries: list[DownloadEntry],
        sample_tags: list[DownloadTag],
    ) -> None:
        result = filter_entries_by_tags(
            sample_entries,
            sample_tags,
            platform="Windows",
            arch="x86_64",
            locale="enUS",
        )
        assert isinstance(result, list)

    def test_preserves_entry_order(self, sample_tags: list[DownloadTag]) -> None:
        entries = [
            DownloadEntry(ekey=b"\x01" * 16, size=100, priority=0),
            DownloadEntry(ekey=b"\x02" * 16, size=200, priority=1),
            DownloadEntry(ekey=b"\x03" * 16, size=300, priority=2),
        ]
        result = filter_entries_by_tags(entries, sample_tags, locale="enUS")
        assert [e.priority for e in result] == [0, 1]
