"""Tests for cdn.py module."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.config import CDNConfig
from cascette_tools.core.tact import TACTClient
from cascette_tools.core.types import Product


class TestCDNClient:
    """Test CDNClient class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        client = CDNClient(Product.WOW)

        assert client.product == Product.WOW
        assert client.region == "us"
        assert isinstance(client.config, CDNConfig)
        assert isinstance(client.cache, DiskCache)
        assert isinstance(client.tact_client, TACTClient)
        assert client.cdn_path is None
        assert client.cdn_servers == []
        assert client._initialized is False
        # No _session attribute in this implementation

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        config = CDNConfig(timeout=60.0)
        client = CDNClient(Product.WOW_CLASSIC, region="eu", config=config)

        assert client.product == Product.WOW_CLASSIC
        assert client.region == "eu"
        assert client.config == config

    def test_build_url_config(self):
        """Test URL building for config files."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("abc123def456", "config", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/config/ab/c1/abc123def456"

    def test_build_url_data(self):
        """Test URL building for data files."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("abc123def456", "data", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/data/ab/c1/abc123def456"

    def test_build_url_index(self):
        """Test URL building for index files."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("abc123def456", "index", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/data/ab/c1/abc123def456.index"

    def test_build_url_patch(self):
        """Test URL building for patch files."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("abc123def456", "patch", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/patch/ab/c1/abc123def456"

    def test_build_url_patch_index(self):
        """Test URL building for patch index files."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("abc123def456", "patch_index", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/patch/ab/c1/abc123def456.index"

    def test_build_url_uppercase_hash(self):
        """Test URL building with uppercase hash."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        url = client._build_url("ABC123DEF456", "config", "https://cdn.example.com")
        assert url == "https://cdn.example.com/tpr/wow/config/ab/c1/abc123def456"

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_ensure_initialized_success(self, mock_parse, mock_fetch):
        """Test successful initialization."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {
                "Name": "us",
                "Path": "tpr/wow",
                "Hosts": "cdn1.example.com cdn2.example.com"
            }
        ]

        client = CDNClient(Product.WOW, region="us")
        client._ensure_initialized()

        assert client._initialized is True
        assert client.cdn_path == "tpr/wow"
        assert client.cdn_servers == ["http://cdn1.example.com", "http://cdn2.example.com"]

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_ensure_initialized_region_not_found(self, mock_parse, mock_fetch):
        """Test initialization when region not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {
                "Name": "eu",
                "Path": "tpr/wow",
                "Hosts": "cdn1.example.com"
            }
        ]

        client = CDNClient(Product.WOW, region="us")

        with pytest.raises(ValueError, match="CDN configuration not found for region"):
            client._ensure_initialized()

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_ensure_initialized_already_initialized(self, mock_parse, mock_fetch):
        """Test that initialization is skipped if already done."""
        client = CDNClient(Product.WOW)
        client._initialized = True

        client._ensure_initialized()

        mock_fetch.assert_not_called()
        mock_parse.assert_not_called()

    @patch("httpx.Client.get")
    def test_fetch_from_cdn_success_first_mirror(self, mock_get):
        """Test successful fetch from first mirror."""
        mock_response = MagicMock()
        mock_response.content = b"test data"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        result = client._fetch_from_cdn("abc123def456", "config")

        assert result == b"test data"
        mock_get.assert_called_once()

    @patch("httpx.Client.get")
    def test_fetch_from_cdn_fallback_to_second_mirror(self, mock_get):
        """Test fallback to second mirror when first fails."""
        # First call fails, second succeeds
        failed_response = MagicMock()
        failed_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )

        success_response = MagicMock()
        success_response.content = b"success data"
        success_response.raise_for_status.return_value = None

        mock_get.side_effect = [failed_response, success_response]

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        result = client._fetch_from_cdn("abc123def456", "config")

        assert result == b"success data"
        assert mock_get.call_count == 2

    @patch("httpx.Client.get")
    def test_fetch_from_cdn_all_mirrors_fail(self, mock_get):
        """Test when all mirrors fail."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )
        mock_get.return_value = mock_response

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with pytest.raises(httpx.HTTPStatusError):
            client._fetch_from_cdn("abc123def456", "config")

        # Should try all 3 mirrors with 3 retries each = 9 total calls
        assert mock_get.call_count == 9

    @patch.object(CDNClient, "_ensure_initialized")
    def test_fetch_config_cache_hit(self, mock_init):
        """Test fetch_config with cache hit."""
        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=b"cached data"):
            result = client.fetch_config("abc123def456")

            assert result == b"cached data"

    @patch.object(CDNClient, "_ensure_initialized")
    @patch.object(CDNClient, "_fetch_from_cdn")
    def test_fetch_config_cache_miss(self, mock_fetch, mock_init):
        """Test fetch_config with cache miss."""
        mock_fetch.return_value = b"fresh data"

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=None), \
             patch.object(client.cache, "put_cdn") as mock_put:

            result = client.fetch_config("abc123def456")

            assert result == b"fresh data"
            mock_fetch.assert_called_once_with("abc123def456", "config")
            mock_put.assert_called_once_with("abc123def456", b"fresh data", "config", "tpr/wow")

    @patch.object(CDNClient, "_ensure_initialized")
    @patch.object(CDNClient, "_fetch_from_cdn")
    def test_fetch_data_cache_miss(self, mock_fetch, mock_init):
        """Test fetch_data with cache miss."""
        mock_fetch.return_value = b"data content"

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=None), \
             patch.object(client.cache, "put_cdn") as mock_put:

            result = client.fetch_data("def456abc123")

            assert result == b"data content"
            mock_fetch.assert_called_once_with("def456abc123", "data")
            mock_put.assert_called_once_with("def456abc123", b"data content", "data", "tpr/wow")

    @patch.object(CDNClient, "_ensure_initialized")
    @patch.object(CDNClient, "_fetch_from_cdn")
    def test_fetch_data_index_cache_miss(self, mock_fetch, mock_init):
        """Test fetch_data for index files with cache miss."""
        mock_fetch.return_value = b"index content"

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=None), \
             patch.object(client.cache, "put_cdn") as mock_put:

            result = client.fetch_data("def456abc123", is_index=True)

            assert result == b"index content"
            mock_fetch.assert_called_once_with("def456abc123", "index")
            mock_put.assert_called_once_with("def456abc123", b"index content", "index", "tpr/wow")

    @patch.object(CDNClient, "_ensure_initialized")
    @patch.object(CDNClient, "_fetch_from_cdn")
    def test_fetch_patch_cache_miss(self, mock_fetch, mock_init):
        """Test fetch_patch with cache miss."""
        mock_fetch.return_value = b"patch content"

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=None), \
             patch.object(client.cache, "put_cdn") as mock_put:

            result = client.fetch_patch("789abc123def")

            assert result == b"patch content"
            mock_fetch.assert_called_once_with("789abc123def", "patch")
            mock_put.assert_called_once_with("789abc123def", b"patch content", "patch", "tpr/wow")

    @patch.object(CDNClient, "_ensure_initialized")
    @patch.object(CDNClient, "_fetch_from_cdn")
    def test_fetch_patch_index_cache_miss(self, mock_fetch, mock_init):
        """Test fetch_patch for index files with cache miss."""
        mock_fetch.return_value = b"patch index content"

        client = CDNClient(Product.WOW)
        client.cdn_path = "tpr/wow"

        with patch.object(client.cache, "get_cdn", return_value=None), \
             patch.object(client.cache, "put_cdn") as mock_put:

            result = client.fetch_patch("789abc123def", is_index=True)

            assert result == b"patch index content"
            mock_fetch.assert_called_once_with("789abc123def", "patch_index")
            mock_put.assert_called_once_with("789abc123def", b"patch index content", "patch_index", "tpr/wow")

    def test_context_manager(self):
        """Test context manager functionality."""
        with CDNClient(Product.WOW) as client:
            assert isinstance(client, CDNClient)

    def test_close_clients(self):
        """Test closing HTTP clients."""
        client = CDNClient(Product.WOW)

        # Create clients
        _ = client.client
        _ = client.async_client

        # Mock close methods
        with patch.object(client._client, "close") as mock_sync_close:
            client.close()
            mock_sync_close.assert_called_once()

    def test_client_properties(self):
        """Test HTTP client properties."""
        client = CDNClient(Product.WOW)

        # Test sync client
        sync_client = client.client
        assert isinstance(sync_client, httpx.Client)
        assert sync_client is client.client  # Should reuse same instance

        # Test async client
        async_client = client.async_client
        assert isinstance(async_client, httpx.AsyncClient)
        assert async_client is client.async_client  # Should reuse same instance

    def test_client_configuration(self):
        """Test HTTP client configuration."""
        config = CDNConfig(timeout=60.0, verify_ssl=False)
        client = CDNClient(Product.WOW, config=config)

        sync_client = client.client
        # Check timeout - httpx uses Timeout object
        assert sync_client.timeout.read == 60.0
        # SSL verification is internal to httpx transport

        async_client = client.async_client
        assert async_client.timeout.read == 60.0
        # SSL verification is internal to httpx transport

    def test_product_integration(self):
        """Test integration with different products."""
        # Test with different products
        client_wow = CDNClient(Product.WOW)
        client_classic = CDNClient(Product.WOW_CLASSIC)
        client_era = CDNClient(Product.WOW_CLASSIC_ERA)

        assert client_wow.product == Product.WOW
        assert client_classic.product == Product.WOW_CLASSIC
        assert client_era.product == Product.WOW_CLASSIC_ERA

        # Verify TACT clients use correct product
        assert client_wow.tact_client.region == "us"
        assert client_classic.tact_client.region == "us"

    def test_region_integration(self):
        """Test integration with different regions."""
        client_us = CDNClient(Product.WOW, region="us")
        client_eu = CDNClient(Product.WOW, region="eu")

        assert client_us.region == "us"
        assert client_eu.region == "eu"

        # Verify TACT clients use correct region
        assert client_us.tact_client.region == "us"
        assert client_eu.tact_client.region == "eu"

    @patch.object(CDNClient, "_ensure_initialized")
    def test_lazy_initialization(self, mock_init):
        """Test that initialization is lazy."""
        client = CDNClient(Product.WOW)

        # Should not be initialized yet
        mock_init.assert_not_called()

        # Set up the client state as if it were initialized
        def setup_client():
            client._initialized = True
            client.cdn_path = "tpr/wow"

        mock_init.side_effect = setup_client

        # Should initialize on first fetch
        with patch.object(client.cache, "get_cdn", return_value=b"cached"):
            client.fetch_config("abc123")
            mock_init.assert_called_once()
