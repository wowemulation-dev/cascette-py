"""Tests for tact.py module."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.config import TACTConfig
from cascette_tools.core.tact import BPSVParser, TACTClient
from cascette_tools.core.types import Product


class TestBPSVParser:
    """Test BPSVParser class."""

    def test_parse_simple_manifest(self):
        """Test parsing simple BPSV manifest."""
        parser = BPSVParser()

        # BPSV format: key=value pairs separated by pipes
        manifest = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\nus|abc123def456|def456abc123\neu|789abc123def|123def789abc"

        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0] == {
            "Region": "us",
            "BuildConfig": "abc123def456",
            "CDNConfig": "def456abc123"
        }
        assert result[1] == {
            "Region": "eu",
            "BuildConfig": "789abc123def",
            "CDNConfig": "123def789abc"
        }

    def test_parse_empty_manifest(self):
        """Test parsing empty manifest."""
        parser = BPSVParser()
        result = parser.parse("")
        assert result == []

    def test_parse_header_only(self):
        """Test parsing manifest with only header."""
        parser = BPSVParser()
        manifest = "Region!STRING:0|BuildConfig!HEX:16"
        result = parser.parse(manifest)
        assert result == []

    def test_parse_with_empty_lines(self):
        """Test parsing manifest with empty lines."""
        parser = BPSVParser()
        manifest = "Region!STRING:0|Value!STRING:0\n\nus|test\n\neu|test2\n"
        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_parse_with_special_characters(self):
        """Test parsing with special characters in values."""
        parser = BPSVParser()
        manifest = "Name!STRING:0|Path!STRING:0\nWoW Classic|wow_classic\nWoW Beta|wowt"
        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0]["Name"] == "WoW Classic"
        assert result[0]["Path"] == "wow_classic"

    def test_parse_malformed_header(self):
        """Test parsing with malformed header."""
        parser = BPSVParser()
        # Missing type information
        manifest = "Region|BuildConfig\nus|abc123"

        # Should still work by treating everything as strings
        result = parser.parse(manifest)
        assert len(result) == 1
        assert result[0]["Region"] == "us"

    def test_parse_mismatched_columns(self):
        """Test parsing with mismatched columns."""
        parser = BPSVParser()
        manifest = "A!STRING:0|B!STRING:0|C!STRING:0\nval1|val2\nval3|val4|val5|val6"

        result = parser.parse(manifest)
        assert len(result) == 2
        # First row has missing column
        assert result[0] == {"A": "val1", "B": "val2", "C": ""}
        # Second row has extra column (should be ignored)
        assert result[1] == {"A": "val3", "B": "val4", "C": "val5"}


class TestTACTClient:
    """Test TACTClient class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        client = TACTClient()

        assert client.region == "us"
        assert isinstance(client.config, TACTConfig)
        assert isinstance(client.cache, DiskCache)
        assert client._base_url == "https://us.version.battle.net"
        assert client.session is None

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        config = TACTConfig(timeout=60.0)
        client = TACTClient(region="eu", config=config)

        assert client.region == "eu"
        assert client.config == config
        assert client._base_url == "https://eu.version.battle.net"

    def test_init_invalid_region(self):
        """Test initialization with invalid region."""
        # Region validation is done by TACTConfig, not TACTClient
        client = TACTClient(region="invalid")
        assert client.region == "invalid"

    def test_build_url_versions(self):
        """Test building URL for versions endpoint."""
        client = TACTClient(region="us")
        url = client._build_url("versions", Product.WOW)
        assert url == "https://us.version.battle.net/wow/versions"

    def test_build_url_cdns(self):
        """Test building URL for CDNs endpoint."""
        client = TACTClient(region="eu")
        url = client._build_url("cdns", Product.WOW_CLASSIC)
        assert url == "https://eu.version.battle.net/wow_classic/cdns"

    def test_build_url_bgdl(self):
        """Test building URL for BGDL endpoint."""
        client = TACTClient(region="kr")
        url = client._build_url("bgdl", Product.WOW_CLASSIC_ERA)
        assert url == "https://kr.version.battle.net/wow_classic_era/bgdl"

    @patch("httpx.Client.get")
    def test_fetch_with_retry_success(self, mock_get):
        """Test successful fetch with retry."""
        mock_response = MagicMock()
        mock_response.text = "test response"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        client = TACTClient()
        result = client._fetch_with_retry("https://test.url")

        assert result == "test response"
        mock_get.assert_called_once()

    @patch("httpx.Client.get")
    def test_fetch_with_retry_failure_then_success(self, mock_get):
        """Test fetch with initial failure then success."""
        # First call fails, second succeeds
        failed_response = MagicMock()
        failed_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )

        success_response = MagicMock()
        success_response.text = "success response"
        success_response.raise_for_status.return_value = None

        mock_get.side_effect = [failed_response, success_response]

        client = TACTClient()
        result = client._fetch_with_retry("https://test.url")

        assert result == "success response"
        assert mock_get.call_count == 2

    @patch("httpx.Client.get")
    def test_fetch_with_retry_all_failures(self, mock_get):
        """Test fetch with all retries failing."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )
        mock_get.return_value = mock_response

        client = TACTClient()

        with pytest.raises(httpx.HTTPStatusError):
            client._fetch_with_retry("https://test.url")

        # Should retry max_retries + 1 times (3 + 1 = 4)
        assert mock_get.call_count == 4

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_versions_cache_hit(self, mock_fetch):
        """Test fetch_versions with cache hit."""
        client = TACTClient()

        # Mock cache hit
        with patch.object(client.cache, "get_api", return_value="cached response"):
            result = client.fetch_versions(Product.WOW)

            assert result == "cached response"
            mock_fetch.assert_not_called()

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_versions_cache_miss(self, mock_fetch):
        """Test fetch_versions with cache miss."""
        mock_fetch.return_value = "fresh response"

        client = TACTClient()

        # Mock cache miss
        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_versions(Product.WOW)

            assert result == "fresh response"
            mock_fetch.assert_called_once()
            mock_put.assert_called_once_with("tact:us:wow:versions", "fresh response")

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_cdns_cache_miss(self, mock_fetch):
        """Test fetch_cdns with cache miss."""
        mock_fetch.return_value = "cdns response"

        client = TACTClient(region="eu")

        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_cdns(Product.WOW_CLASSIC)

            assert result == "cdns response"
            mock_put.assert_called_once_with("tact:eu:wow_classic:cdns", "cdns response")

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_bgdl_cache_miss(self, mock_fetch):
        """Test fetch_bgdl with cache miss."""
        mock_fetch.return_value = "bgdl response"

        client = TACTClient(region="kr")

        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_bgdl(Product.WOW_CLASSIC_ERA)

            assert result == "bgdl response"
            mock_put.assert_called_once_with("tact:kr:wow_classic_era:bgdl", "bgdl response")

    def test_parse_versions(self):
        """Test parsing versions manifest."""
        client = TACTClient()

        manifest = "Region!STRING:0|BuildConfig!HEX:16\nus|abc123def456\neu|def456abc123"
        result = client.parse_versions(manifest)

        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_parse_cdns(self):
        """Test parsing CDNs manifest."""
        client = TACTClient()

        manifest = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\nus|tpr/wow|cdn1.example.com cdn2.example.com"
        result = client.parse_cdns(manifest)

        assert len(result) == 1
        assert result[0]["Name"] == "us"
        assert result[0]["Path"] == "tpr/wow"

    def test_parse_bgdl(self):
        """Test parsing BGDL manifest."""
        client = TACTClient()

        manifest = "Product!STRING:0|Priority!DEC:1\nwow|1"
        result = client.parse_bgdl(manifest)

        assert len(result) == 1
        assert result[0]["Product"] == "wow"

    @patch.object(TACTClient, "fetch_versions")
    @patch.object(TACTClient, "parse_versions")
    def test_get_latest_build_found(self, mock_parse, mock_fetch):
        """Test get_latest_build when build is found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Region": "eu", "BuildConfig": "abc123"},
            {"Region": "us", "BuildConfig": "def456"},
        ]

        client = TACTClient(region="us")
        result = client.get_latest_build(Product.WOW)

        assert result == {"Region": "us", "BuildConfig": "def456"}
        mock_fetch.assert_called_once_with(Product.WOW)

    @patch.object(TACTClient, "fetch_versions")
    @patch.object(TACTClient, "parse_versions")
    def test_get_latest_build_not_found(self, mock_parse, mock_fetch):
        """Test get_latest_build when build is not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Region": "eu", "BuildConfig": "abc123"},
        ]

        client = TACTClient(region="us")
        result = client.get_latest_build(Product.WOW)

        assert result is None

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_servers_found(self, mock_parse, mock_fetch):
        """Test get_cdn_servers when servers are found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "us", "Hosts": "cdn1.example.com cdn2.example.com"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_servers(Product.WOW)

        assert result == ["http://cdn1.example.com", "http://cdn2.example.com"]

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_servers_not_found(self, mock_parse, mock_fetch):
        """Test get_cdn_servers when region not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "eu", "Hosts": "cdn1.example.com"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_servers(Product.WOW)

        assert result == []

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_path_found(self, mock_parse, mock_fetch):
        """Test get_cdn_path when path is found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "us", "Path": "tpr/wow"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_path(Product.WOW)

        assert result == "tpr/wow"

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_path_not_found(self, mock_parse, mock_fetch):
        """Test get_cdn_path when region not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "eu", "Path": "tpr/wow"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_path(Product.WOW)

        assert result is None

    def test_clear_cache(self):
        """Test clearing cache."""
        client = TACTClient()

        with patch.object(client.cache, "clear_expired", return_value=5) as mock_clear:
            result = client.clear_cache()

            assert result == 5
            mock_clear.assert_called_once()

    def test_clear_cache_for_product(self):
        """Test clearing cache for specific product."""
        client = TACTClient()

        # Test implementation would need to clear specific product entries
        # For now, just verify the method exists and can be called
        with patch.object(client.cache, "clear_expired", return_value=2):
            result = client.clear_cache(Product.WOW)
            assert result == 2
