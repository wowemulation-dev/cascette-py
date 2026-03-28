"""Tests for cascette_tools.core.cdn_archive_fetcher module."""

from unittest.mock import Mock, patch

import pytest

from cascette_tools.core.cdn_archive_fetcher import (
    ArchiveLocation,
    CdnArchiveFetcher,
    IndexMap,
    create_patch_archive_fetcher,
    get_cached_index_path,
    parse_cdn_config_archives,
)
from cascette_tools.formats.cdn_archive import CdnArchiveEntry


def make_mock_entry(key: bytes, offset: int, size: int) -> CdnArchiveEntry:
    return CdnArchiveEntry(encoding_key=key, offset=offset, size=size)


class TestGetCachedIndexPath:
    """Test get_cached_index_path function."""

    def test_returns_correct_path(self, tmp_path):
        result = get_cached_index_path(tmp_path, "ABC123DEF456")
        expected = tmp_path / "abc123def456.index"
        assert result == expected

    def test_lowercases_hash(self, tmp_path):
        result = get_cached_index_path(tmp_path, "ABC123")
        assert "abc123" in str(result)

    def test_appends_index_suffix(self, tmp_path):
        result = get_cached_index_path(tmp_path, "abc123")
        assert result.suffix == ".index"


class TestArchiveLocation:
    """Test ArchiveLocation dataclass."""

    def test_basic_location(self):
        loc = ArchiveLocation(archive_hash="abc123", offset=100, size=500)
        assert loc.archive_hash == "abc123"
        assert loc.offset == 100
        assert loc.size == 500


class TestIndexMap:
    """Test IndexMap class."""

    def test_empty_map(self):
        index_map = IndexMap()
        assert len(index_map.entries) == 0
        assert index_map.archive_count == 0
        assert index_map.total_entries == 0

    def test_add_archive(self):
        index_map = IndexMap()

        entries = [
            make_mock_entry(b"\x11" * 16, 0, 100),
            make_mock_entry(b"\x22" * 16, 100, 200),
        ]

        index_map.add_archive("abc123", entries)

        assert index_map.archive_count == 1
        assert index_map.total_entries == 2
        assert len(index_map.entries) == 2

    def test_find_existing_key(self):
        index_map = IndexMap()
        key = b"\x12" * 16

        entries = [make_mock_entry(key, 100, 500)]
        index_map.add_archive("abc123", entries)

        result = index_map.find(key)

        assert result is not None
        assert result.archive_hash == "abc123"
        assert result.offset == 100
        assert result.size == 500

    def test_find_nonexistent_key(self):
        index_map = IndexMap()

        result = index_map.find(b"\xff" * 16)

        assert result is None

    def test_find_truncated_key(self):
        index_map = IndexMap()
        key = b"\x12" * 16

        entries = [make_mock_entry(key, 100, 500)]
        index_map.add_archive("abc123", entries)

        result = index_map.find(key)

        assert result is not None


class TestCdnArchiveFetcher:
    """Test CdnArchiveFetcher class."""

    def test_init_default_values(self):
        fetcher = CdnArchiveFetcher()
        assert fetcher.cdn_base == "http://us.cdn.blizzard.com"
        assert fetcher.cdn_path == "tpr/wow"
        assert fetcher.timeout == 30.0
        assert fetcher.max_concurrent == 10
        assert fetcher.content_type == "data"

    def test_init_custom_values(self):
        fetcher = CdnArchiveFetcher(
            cdn_base="https://custom.cdn.com",
            cdn_path="custom/path",
            timeout=60.0,
            max_concurrent=5,
        )
        assert fetcher.cdn_base == "https://custom.cdn.com"
        assert fetcher.cdn_path == "custom/path"
        assert fetcher.timeout == 60.0
        assert fetcher.max_concurrent == 5

    def test_init_patch_content_type(self):
        fetcher = CdnArchiveFetcher(content_type="patch")
        assert fetcher.content_type == "patch"

    def test_init_invalid_content_type(self):
        with pytest.raises(ValueError, match="content_type must be 'data' or 'patch'"):
            CdnArchiveFetcher(content_type="invalid")

    def test_make_index_url(self):
        fetcher = CdnArchiveFetcher(
            cdn_base="https://cdn.example.com", cdn_path="tpr/wow"
        )
        url = fetcher._make_index_url("ABC123DEF456")
        assert url == "https://cdn.example.com/tpr/wow/data/ab/c1/abc123def456.index"

    def test_make_data_url(self):
        fetcher = CdnArchiveFetcher(
            cdn_base="https://cdn.example.com", cdn_path="tpr/wow"
        )
        url = fetcher._make_data_url("ABC123DEF456")
        assert url == "https://cdn.example.com/tpr/wow/data/ab/c1/abc123def456"

    def test_make_url_patch_content_type(self):
        fetcher = CdnArchiveFetcher(
            cdn_base="https://cdn.example.com", cdn_path="tpr/wow", content_type="patch"
        )
        url = fetcher._make_data_url("ABC123DEF456")
        assert "/patch/" in url

    def test_load_index_from_bytes_success(self):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        result = fetcher.load_index_from_bytes("abc123", b"index data")

        assert result is True
        assert fetcher.index_map.total_entries == 1

    def test_load_index_from_bytes_parse_error(self):
        fetcher = CdnArchiveFetcher()
        fetcher._parser = Mock()
        fetcher._parser.parse.side_effect = Exception("Parse error")

        result = fetcher.load_index_from_bytes("abc123", b"invalid data")

        assert result is False

    def test_load_index_from_file_success(self, tmp_path):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        index_file = tmp_path / "abc123.index"
        index_file.write_bytes(b"index data")

        result = fetcher.load_index_from_file("abc123", index_file)

        assert result is True

    def test_load_index_from_file_not_exists(self, tmp_path):
        fetcher = CdnArchiveFetcher()

        result = fetcher.load_index_from_file("abc123", tmp_path / "nonexistent.index")

        assert result is False

    def test_download_index_success(self):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"index data"

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.download_index(mock_client, "abc123")

        assert result is True
        assert fetcher.index_map.total_entries == 1

    def test_download_index_http_error(self):
        fetcher = CdnArchiveFetcher()

        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.download_index(mock_client, "abc123")

        assert result is False

    def test_download_index_with_cache_hit(self, tmp_path):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        cache_dir = tmp_path / "indices"
        cache_dir.mkdir()

        cached_index = cache_dir / "abc123.index"
        cached_index.write_bytes(b"cached index data")

        mock_client = Mock()

        success, data = fetcher.download_index_with_cache(
            mock_client, "abc123", cache_dir
        )

        assert success is True
        assert data == b"cached index data"

    def test_download_index_with_cache_miss(self, tmp_path):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"downloaded index data"

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        cache_dir = tmp_path / "indices"
        cache_dir.mkdir()

        success, data = fetcher.download_index_with_cache(
            mock_client, "abc123", cache_dir
        )

        assert success is True
        assert data == b"downloaded index data"
        assert (cache_dir / "abc123.index").exists()

    def test_download_indices(self):
        fetcher = CdnArchiveFetcher()

        mock_parser = Mock()
        mock_index = Mock()
        mock_index.entries = [make_mock_entry(b"\x12" * 16, 100, 500)]
        mock_parser.parse.return_value = mock_index
        fetcher._parser = mock_parser

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"index data"

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            progress_calls = []

            def progress_callback(completed: int, total: int) -> None:
                progress_calls.append((completed, total))

            result = fetcher.download_indices(
                ["abc123", "def456"], progress_callback=progress_callback
            )

            assert result == 2
            assert len(progress_calls) == 2

    def test_fetch_file_success(self):
        fetcher = CdnArchiveFetcher()

        key = b"\x12" * 16
        entries = [make_mock_entry(key, 100, 13)]
        fetcher.index_map.add_archive("abc123", entries)

        mock_response = Mock()
        mock_response.status_code = 206
        mock_response.content = b"Hello, World!"

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.fetch_file(mock_client, key, decompress=False, verify=False)

        assert result == b"Hello, World!"

    def test_fetch_file_not_found(self):
        fetcher = CdnArchiveFetcher()

        mock_client = Mock()

        result = fetcher.fetch_file(mock_client, b"\xff" * 16)

        assert result is None

    def test_fetch_file_http_error(self):
        fetcher = CdnArchiveFetcher()

        key = b"\x12" * 16
        entries = [make_mock_entry(key, 100, 500)]
        fetcher.index_map.add_archive("abc123", entries)

        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.fetch_file(mock_client, key)

        assert result is None

    def test_fetch_file_raw_success(self):
        fetcher = CdnArchiveFetcher()

        mock_response = Mock()
        mock_response.status_code = 206
        mock_response.content = b"raw data"

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.fetch_file_raw(mock_client, "abc123", 100, 500)

        assert result == b"raw data"

    def test_fetch_file_raw_error(self):
        fetcher = CdnArchiveFetcher()

        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = Mock()
        mock_client.get.return_value = mock_response

        result = fetcher.fetch_file_raw(mock_client, "abc123", 100, 500)

        assert result is None

    def test_fetch_file_via_cdn_success(self):
        mock_cdn_client = Mock()
        mock_cdn_client.ensure_initialized = Mock()
        mock_cdn_client.cdn_servers = ["http://cdn1.example.com"]
        mock_cdn_client.cdn_path = "tpr/wow"
        mock_cdn_client.config.fallback_mirrors = []
        mock_cdn_client.client = Mock()

        fetcher = CdnArchiveFetcher(cdn_client=mock_cdn_client)

        key = b"\x12" * 16
        entries = [make_mock_entry(key, 100, 13)]
        fetcher.index_map.add_archive("abc123", entries)

        mock_response = Mock()
        mock_response.status_code = 206
        mock_response.content = b"Hello, World!"

        mock_cdn_client.client.get.return_value = mock_response

        result = fetcher.fetch_file_via_cdn(
            mock_cdn_client, key, decompress=False, verify=False
        )

        assert result == b"Hello, World!"

    def test_fetch_file_via_cdn_not_found(self):
        mock_cdn_client = Mock()
        mock_cdn_client.ensure_initialized = Mock()
        mock_cdn_client.cdn_servers = []
        mock_cdn_client.config.fallback_mirrors = []

        fetcher = CdnArchiveFetcher(cdn_client=mock_cdn_client)

        result = fetcher.fetch_file_via_cdn(mock_cdn_client, b"\xff" * 16)

        assert result is None


class TestCreatePatchArchiveFetcher:
    """Test create_patch_archive_fetcher factory function."""

    def test_creates_patch_fetcher(self):
        fetcher = create_patch_archive_fetcher()
        assert fetcher.content_type == "patch"

    def test_passes_parameters(self):
        fetcher = create_patch_archive_fetcher(
            cdn_base="https://custom.cdn.com", cdn_path="custom/path", timeout=60.0
        )
        assert fetcher.cdn_base == "https://custom.cdn.com"
        assert fetcher.cdn_path == "custom/path"
        assert fetcher.timeout == 60.0
        assert fetcher.content_type == "patch"


class TestParseCdnConfigArchives:
    """Test parse_cdn_config_archives function."""

    def test_parses_archives_line(self):
        content = """
# Comment
archives = abc123 def456 ghi789
other = value
"""
        result = parse_cdn_config_archives(content)
        assert result == ["abc123", "def456", "ghi789"]

    def test_empty_archives(self):
        content = "# No archives"
        result = parse_cdn_config_archives(content)
        assert result == []

    def test_no_archives_line(self):
        content = "other = value"
        result = parse_cdn_config_archives(content)
        assert result == []
