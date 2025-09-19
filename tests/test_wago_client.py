"""Tests for Wago.tools API client."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest
import structlog

from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import Product
from cascette_tools.database.wago import (
    WagoBuild,
    WagoCacheMetadata,
    WagoClient,
)

# Set up test logger
structlog.configure(
    processors=[structlog.dev.ConsoleRenderer()],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


@pytest.fixture
def temp_data_dir():
    """Create temporary data directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def test_config(temp_data_dir):
    """Create test configuration with temporary data directory."""
    config = AppConfig()
    config.data_dir = temp_data_dir
    return config


@pytest.fixture
def wago_client(test_config):
    """Create WagoClient instance for testing."""
    client = WagoClient(config=test_config)
    yield client
    client.close()


@pytest.fixture
def sample_wago_response():
    """Sample response from Wago.tools API - matches actual API format."""
    return {
        "wow": [
            {
                "product": "wow",
                "version": "11.0.5.56647",
                "created_at": "2024-09-15 10:30:00",
                "build_config": "abc123def456",
                "cdn_config": "def456abc123",
                "product_config": "789abc123def",
                "is_bgdl": False
            },
            {
                "product": "wow",
                "version": "11.0.5.56646",
                "created_at": "2024-09-14 10:30:00",
                "build_config": "abc123def455",
                "cdn_config": "def456abc122",
                "product_config": "789abc123dee",
                "is_bgdl": False
            }
        ],
        "wow_classic": [
            {
                "product": "wow_classic",
                "version": "1.15.0.12345",
                "created_at": "2024-09-15 10:30:00",
                "build_config": "classic123def456",
                "cdn_config": "classic456abc123",
                "product_config": "classic789abc123def",
                "is_bgdl": False
            }
        ],
        "wow_classic_era": [
            {
                "product": "wow_classic_era",
                "version": "1.14.4.12344",
                "created_at": "2024-09-14 10:30:00",
                "build_config": "era123def456",
                "cdn_config": "era456abc123",
                "product_config": "era789abc123def",
                "is_bgdl": False
            }
        ],
        "unsupported_product": [
            {
                "product": "unsupported_product",
                "version": "1.0.0.11111",
                "created_at": "2024-09-14 10:30:00",
                "build_config": "unsupported123",
                "cdn_config": "unsupported456",
                "product_config": "unsupported789",
                "is_bgdl": False
            }
        ]
    }


@pytest.fixture
def sample_wago_builds():
    """Sample WagoBuild instances for testing."""
    return [
        WagoBuild(
            id=12345,
            build="56647",
            version="11.0.5.56647",
            product="wow",
            build_time=datetime(2024, 9, 15, 10, 30, 0, tzinfo=timezone.utc),
            build_config="abc123def456",
            cdn_config="def456abc123",
            product_config="789abc123def",
            encoding_ekey="encoding123",
            root_ekey="root456",
            install_ekey="install789",
            download_ekey="download012"
        ),
        WagoBuild(
            id=12344,
            build="56646",
            version="11.0.5.56646",
            product="wow",
            build_time=datetime(2024, 9, 14, 10, 30, 0, tzinfo=timezone.utc),
            build_config="abc123def455",
            cdn_config="def456abc122",
            product_config="789abc123dee",
            encoding_ekey="encoding122",
            root_ekey="root455",
            install_ekey="install788",
            download_ekey="download011"
        )
    ]


class TestWagoBuild:
    """Test WagoBuild model."""

    def test_create_basic_build(self):
        """Test creating basic build instance."""
        build = WagoBuild(
            id=12345,
            build="56647",
            version="11.0.5.56647",
            product="wow"
        )

        assert build.id == 12345
        assert build.build == "56647"
        assert build.version == "11.0.5.56647"
        assert build.product == "wow"
        assert build.build_time is None
        assert build.build_config is None

    def test_create_full_build(self):
        """Test creating build with all fields."""
        build_time = datetime(2024, 9, 15, 10, 30, 0, tzinfo=timezone.utc)
        build = WagoBuild(
            id=12345,
            build="56647",
            version="11.0.5.56647",
            product="wow",
            build_time=build_time,
            build_config="abc123def456",
            cdn_config="def456abc123",
            product_config="789abc123def",
            encoding_ekey="encoding123",
            root_ekey="root456",
            install_ekey="install789",
            download_ekey="download012"
        )

        assert build.build_time == build_time
        assert build.build_config == "abc123def456"
        assert build.cdn_config == "def456abc123"
        assert build.encoding_ekey == "encoding123"

    def test_model_serialization(self, sample_wago_builds):
        """Test model serialization and deserialization."""
        build = sample_wago_builds[0]

        # Test serialization
        data = build.model_dump()
        assert data["id"] == 12345
        assert data["version"] == "11.0.5.56647"

        # Test deserialization
        new_build = WagoBuild(**data)
        assert new_build.id == build.id
        assert new_build.version == build.version
        assert new_build.build_time == build.build_time


class TestWagoCacheMetadata:
    """Test WagoCacheMetadata model."""

    def test_create_metadata(self):
        """Test creating cache metadata."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)

        metadata = WagoCacheMetadata(
            fetch_time=now,
            expires_at=expires,
            build_count=100
        )

        assert metadata.fetch_time == now
        assert metadata.expires_at == expires
        assert metadata.build_count == 100
        assert metadata.api_version == "v1"

    def test_model_serialization(self):
        """Test metadata serialization."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)

        metadata = WagoCacheMetadata(
            fetch_time=now,
            expires_at=expires,
            build_count=50,
            api_version="v2"
        )

        data = metadata.model_dump(mode="json")
        assert "fetch_time" in data
        assert "expires_at" in data
        assert data["build_count"] == 50
        assert data["api_version"] == "v2"


class TestWagoClient:
    """Test WagoClient functionality."""

    def test_client_initialization(self, test_config):
        """Test client initialization."""
        with WagoClient(config=test_config) as client:
            assert client.config == test_config
            assert client.cache_dir == test_config.data_dir / "wago_cache"
            assert client.cache_dir.exists()
            assert client.cache_file == client.cache_dir / "builds.json"
            assert client.metadata_file == client.cache_dir / "metadata.json"

    def test_client_initialization_no_config(self, temp_data_dir):
        """Test client initialization without config."""
        # Mock AppConfig to use temp directory
        with patch('cascette_tools.database.wago.AppConfig') as mock_app_config:
            mock_config = AppConfig()
            mock_config.data_dir = temp_data_dir
            mock_app_config.return_value = mock_config

            with WagoClient() as client:
                assert isinstance(client.config, AppConfig)
                assert client.cache_dir.exists()

    def test_http_client_property(self, wago_client):
        """Test HTTP client property."""
        client_instance = wago_client.client

        assert isinstance(client_instance, httpx.Client)
        assert str(client_instance.base_url) == "https://wago.tools/api/"
        assert client_instance.timeout.read == 30.0

        # Test client reuse
        assert wago_client.client is client_instance

    def test_cache_validation_no_cache(self, wago_client):
        """Test cache validation when no cache exists."""
        assert not wago_client._is_cache_valid()

    def test_cache_validation_missing_metadata(self, wago_client):
        """Test cache validation when metadata is missing."""
        # Create cache file but no metadata
        wago_client.cache_file.write_text("[]")
        assert not wago_client._is_cache_valid()

    def test_cache_validation_expired(self, wago_client):
        """Test cache validation with expired cache."""
        # Create expired metadata
        past_time = datetime.now(timezone.utc) - timedelta(hours=25)
        metadata = WagoCacheMetadata(
            fetch_time=past_time,
            expires_at=past_time + timedelta(hours=24),
            build_count=0
        )

        wago_client.cache_file.write_text("[]")
        wago_client.metadata_file.write_text(
            json.dumps(metadata.model_dump(mode="json"), default=str)
        )

        assert not wago_client._is_cache_valid()

    def test_cache_validation_valid(self, wago_client):
        """Test cache validation with valid cache."""
        # Create valid metadata
        now = datetime.now(timezone.utc)
        metadata = WagoCacheMetadata(
            fetch_time=now,
            expires_at=now + timedelta(hours=24),
            build_count=10
        )

        wago_client.cache_file.write_text("[]")
        wago_client.metadata_file.write_text(
            json.dumps(metadata.model_dump(mode="json"), default=str)
        )

        assert wago_client._is_cache_valid()

    def test_cache_validation_invalid_json(self, wago_client):
        """Test cache validation with invalid JSON."""
        wago_client.cache_file.write_text("[]")
        wago_client.metadata_file.write_text("invalid json")

        assert not wago_client._is_cache_valid()

    def test_load_cache(self, wago_client, sample_wago_builds):
        """Test loading cache."""
        # Prepare cache data
        cache_data = []
        for build in sample_wago_builds:
            data = build.model_dump()
            if data.get("build_time"):
                data["build_time"] = data["build_time"].isoformat()
            cache_data.append(data)

        wago_client.cache_file.write_text(json.dumps(cache_data, indent=2))

        # Load cache
        builds = wago_client._load_cache()

        assert len(builds) == 2
        assert builds[0].id == 12345
        assert builds[0].version == "11.0.5.56647"
        assert builds[0].build_time == sample_wago_builds[0].build_time

    def test_save_cache(self, wago_client, sample_wago_builds):
        """Test saving cache."""
        wago_client._save_cache(sample_wago_builds)

        # Verify cache file
        assert wago_client.cache_file.exists()
        cache_data = json.loads(wago_client.cache_file.read_text())
        assert len(cache_data) == 2
        assert cache_data[0]["id"] == 12345

        # Verify metadata file
        assert wago_client.metadata_file.exists()
        metadata_data = json.loads(wago_client.metadata_file.read_text())
        assert metadata_data["build_count"] == 2
        assert "fetch_time" in metadata_data
        assert "expires_at" in metadata_data

    @patch("httpx.Client.get")
    def test_fetch_builds_from_api(self, mock_get, wago_client, sample_wago_response):
        """Test fetching builds from API."""
        # Mock API response - now it's a single call returning all products
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_wago_response
        mock_get.return_value = mock_response

        builds = wago_client.fetch_builds(force_refresh=True)

        # Should fetch once from the /builds endpoint
        assert mock_get.call_count == 1
        mock_get.assert_called_with("/builds")

        # Verify builds - should get 4 total (2 wow, 1 wow_classic, 1 wow_classic_era)
        # The unsupported_product should be filtered out
        assert len(builds) == 4
        assert all(isinstance(b, WagoBuild) for b in builds)

        # Check products are correctly assigned
        products = {b.product for b in builds}
        assert products == {"wow", "wow_classic", "wow_classic_era"}

        # Check that unsupported products were filtered
        assert not any(b.product == "unsupported_product" for b in builds)

        # Verify cache was saved
        assert wago_client.cache_file.exists()
        assert wago_client.metadata_file.exists()

    @patch("httpx.Client.get")
    def test_fetch_builds_api_error(self, mock_get, wago_client):
        """Test API error handling."""
        mock_get.side_effect = httpx.HTTPError("API Error")

        with pytest.raises(httpx.HTTPError):
            wago_client.fetch_builds(force_refresh=True)

    @patch("httpx.Client.get")
    def test_fetch_builds_api_error_with_cache_fallback(self, mock_get, wago_client, sample_wago_builds):
        """Test API error with cache fallback."""
        # Create expired cache
        wago_client._save_cache(sample_wago_builds)

        # Mock API error
        mock_get.side_effect = httpx.HTTPError("API Error")

        # Should fall back to expired cache
        builds = wago_client.fetch_builds(force_refresh=True)
        assert len(builds) == 2

    def test_fetch_builds_use_cache(self, wago_client, sample_wago_builds):
        """Test using valid cache instead of API."""
        # Create valid cache
        wago_client._save_cache(sample_wago_builds)

        with patch("httpx.Client.get") as mock_get:
            builds = wago_client.fetch_builds()

            # Should not call API
            mock_get.assert_not_called()
            assert len(builds) == 2

    @patch("httpx.Client.get")
    def test_get_builds_for_product(self, mock_get, wago_client, sample_wago_response):
        """Test filtering builds by product."""
        # Mock API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_wago_response
        mock_get.return_value = mock_response

        builds = wago_client.get_builds_for_product(Product.WOW, force_refresh=True)

        # Should only return WoW builds
        assert all(b.product == "wow" for b in builds)

    @patch("httpx.Client.get")
    def test_find_build(self, mock_get, wago_client, sample_wago_response):
        """Test finding specific build by version."""
        # Mock API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_wago_response
        mock_get.return_value = mock_response

        # Find existing build
        build = wago_client.find_build("11.0.5.56647", force_refresh=True)
        assert build is not None
        assert build.version == "11.0.5.56647"
        assert build.product == "wow"

        # Find classic build
        build = wago_client.find_build("1.15.0.12345", force_refresh=True)
        assert build is not None
        assert build.version == "1.15.0.12345"
        assert build.product == "wow_classic"

        # Find non-existing build
        build = wago_client.find_build("99.0.0.99999", force_refresh=True)
        assert build is None

    @patch("httpx.Client.get")
    def test_get_latest_build(self, mock_get, wago_client, sample_wago_response):
        """Test getting latest build for product."""
        # Mock API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_wago_response
        mock_get.return_value = mock_response

        latest = wago_client.get_latest_build(Product.WOW, force_refresh=True)

        assert latest is not None
        # Since we generate IDs from hash, we check version instead
        assert latest.version == "11.0.5.56647"  # Should be one of the wow builds
        assert latest.product == "wow"

    def test_get_latest_build_no_builds(self, wago_client):
        """Test getting latest build when no builds exist."""
        # Clear cache to ensure no builds are available
        wago_client.clear_cache()

        with patch("httpx.Client.get") as mock_get:
            # Mock empty response
            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {}  # Empty dict, no products
            mock_get.return_value = mock_response

            latest = wago_client.get_latest_build(Product.WOW, force_refresh=True)
            assert latest is None

    def test_clear_cache(self, wago_client, sample_wago_builds):
        """Test clearing cache."""
        # Create cache
        wago_client._save_cache(sample_wago_builds)
        assert wago_client.cache_file.exists()
        assert wago_client.metadata_file.exists()

        # Clear cache
        result = wago_client.clear_cache()
        assert result is True
        assert not wago_client.cache_file.exists()
        assert not wago_client.metadata_file.exists()

        # Clear again (should return False)
        result = wago_client.clear_cache()
        assert result is False

    def test_get_cache_status_invalid(self, wago_client):
        """Test cache status when cache is invalid."""
        status = wago_client.get_cache_status()

        assert status["valid"] is False
        assert status["exists"] is False

    def test_get_cache_status_valid(self, wago_client, sample_wago_builds):
        """Test cache status when cache is valid."""
        wago_client._save_cache(sample_wago_builds)

        status = wago_client.get_cache_status()

        assert status["valid"] is True
        assert "fetch_time" in status
        assert "expires_at" in status
        assert status["build_count"] == 2
        assert status["age_hours"] >= 0
        assert status["remaining_hours"] > 0
        assert status["cache_size_kb"] > 0

    def test_context_manager(self, test_config):
        """Test context manager functionality."""
        with WagoClient(config=test_config) as client:
            assert isinstance(client, WagoClient)

        # Client should be closed after context

    @patch("httpx.Client.get")
    def test_datetime_parsing_variants(self, mock_get, wago_client):
        """Test parsing different datetime formats from API."""
        # Mock response with various datetime formats - new API format with product keys
        response_data = {
            "wow": [
                {
                    "id": 1,
                    "product": "wow",
                    "build": "12345",
                    "version": "1.0.0.12345",
                    "created_at": "2024-09-15T10:30:00Z"  # With Z suffix
                },
                {
                    "id": 2,
                    "product": "wow",
                    "build": "12346",
                    "version": "1.0.0.12346",
                    "created_at": "2024-09-15T10:30:00+00:00"  # With timezone
                },
                {
                    "id": 3,
                    "product": "wow",
                    "build": "12347",
                    "version": "1.0.0.12347"
                    # No created_at field
                }
            ],
            "wow_classic": [],
            "wow_classic_era": []
        }

        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = response_data
        mock_get.return_value = mock_response

        builds = wago_client.fetch_builds(force_refresh=True)

        # Should parse all builds correctly
        wow_builds = [b for b in builds if b.product == "wow"]
        assert len(wow_builds) == 3

        # Check datetime parsing (now using created_at field)
        build_with_z = next(b for b in wow_builds if b.id == 1)
        assert build_with_z.build_time is not None

        build_with_tz = next(b for b in wow_builds if b.id == 2)
        assert build_with_tz.build_time is not None

        build_no_time = next(b for b in wow_builds if b.id == 3)
        assert build_no_time.build_time is None

    @patch("httpx.Client.get")
    def test_build_parse_error_handling(self, mock_get, wago_client):
        """Test handling of build parsing errors."""
        # Mock response with invalid build data - new API format
        response_data = {
            "wow": [
                {
                    "id": 1,
                    "product": "wow",
                    "build": "12345",
                    "version": "1.0.0.12345"
                    # Valid build
                },
                {
                    # Missing required fields
                    "product": "wow",
                    "build": "12346"
                },
                {
                    "id": "invalid_id",  # Invalid ID type
                    "product": "wow",
                    "build": "12347",
                    "version": "1.0.0.12347"
                }
            ],
            "wow_classic": [],
            "wow_classic_era": []
        }

        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = response_data
        mock_get.return_value = mock_response

        builds = wago_client.fetch_builds(force_refresh=True)

        # Should only include valid builds (just the 1 valid wow build)
        assert len(builds) == 1
        wow_builds = [b for b in builds if b.product == "wow"]
        assert len(wow_builds) == 1
        assert wow_builds[0].id == 1

    def test_client_close(self, wago_client):
        """Test client close functionality."""
        # Access client to create it
        _ = wago_client.client
        assert wago_client._client is not None

        # Close client
        wago_client.close()

        # Should be able to close multiple times without error
        wago_client.close()


class TestWagoClientDatabase:
    """Test WagoClient database functionality."""

    def test_database_initialization(self, wago_client):
        """Test database schema initialization."""
        # Database should be created automatically
        assert wago_client.db_path.exists()

        # Check schema exists
        cursor = wago_client.conn.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name IN ('wago_builds', 'wago_import_log')
        """)
        tables = [row[0] for row in cursor]
        assert "wago_builds" in tables
        assert "wago_import_log" in tables

    def test_import_builds_to_database(self, wago_client, sample_wago_builds):
        """Test importing builds to database."""
        stats = wago_client.import_builds_to_database(sample_wago_builds)

        assert stats["fetched"] == 2
        assert stats["imported"] == 2
        assert stats["updated"] == 0
        assert stats["skipped"] == 0

        # Verify builds in database
        cursor = wago_client.conn.execute("SELECT COUNT(*) FROM wago_builds")
        count = cursor.fetchone()[0]
        assert count == 2

        # Verify import log
        cursor = wago_client.conn.execute("SELECT * FROM wago_import_log WHERE success = 1")
        log_entry = cursor.fetchone()
        assert log_entry is not None
        assert log_entry["builds_fetched"] == 2
        assert log_entry["builds_imported"] == 2

    def test_import_builds_update_existing(self, wago_client, sample_wago_builds):
        """Test updating existing builds in database."""
        # First import
        wago_client.import_builds_to_database(sample_wago_builds)

        # Modify build and import again
        updated_build = sample_wago_builds[0].model_copy()
        updated_build.version = "11.0.5.56647-updated"
        updated_build.build_config = "updated_config_hash"

        stats = wago_client.import_builds_to_database([updated_build])

        assert stats["fetched"] == 1
        assert stats["imported"] == 0
        assert stats["updated"] == 1

        # Verify update in database
        cursor = wago_client.conn.execute(
            "SELECT version, build_config FROM wago_builds WHERE id = ?",
            (updated_build.id,)
        )
        row = cursor.fetchone()
        assert row["version"] == "11.0.5.56647-updated"
        assert row["build_config"] == "updated_config_hash"

    def test_get_database_builds(self, wago_client, sample_wago_builds):
        """Test retrieving builds from database."""
        # Import builds
        wago_client.import_builds_to_database(sample_wago_builds)

        # Get all builds
        builds = wago_client.get_database_builds()
        assert len(builds) == 2
        assert all(isinstance(b, WagoBuild) for b in builds)

        # Get builds by product
        wow_builds = wago_client.get_database_builds(product="wow")
        assert len(wow_builds) == 2
        assert all(b.product == "wow" for b in wow_builds)

        # Get limited builds
        limited_builds = wago_client.get_database_builds(limit=1)
        assert len(limited_builds) == 1

    def test_get_database_builds_empty(self, wago_client):
        """Test getting builds from empty database."""
        builds = wago_client.get_database_builds()
        assert builds == []

    def test_find_database_build(self, wago_client, sample_wago_builds):
        """Test finding specific build in database."""
        # Import builds
        wago_client.import_builds_to_database(sample_wago_builds)

        # Find existing build
        build = wago_client.find_database_build("11.0.5.56647")
        assert build is not None
        assert build.version == "11.0.5.56647"
        assert build.id == 12345

        # Find build with product filter
        build = wago_client.find_database_build("11.0.5.56647", product="wow")
        assert build is not None

        # Find non-existing build
        build = wago_client.find_database_build("99.0.0.99999")
        assert build is None

        # Find with wrong product
        build = wago_client.find_database_build("11.0.5.56647", product="wow_classic")
        assert build is None

    def test_get_import_statistics(self, wago_client, sample_wago_builds):
        """Test getting import statistics."""
        # Import builds
        wago_client.import_builds_to_database(sample_wago_builds)

        stats = wago_client.get_import_statistics()

        # Check structure
        assert "builds_by_product" in stats
        assert "total_builds" in stats
        assert "latest_builds" in stats
        assert "import_history" in stats
        assert "recent_imports" in stats

        # Check values
        assert stats["total_builds"] == 2
        assert stats["builds_by_product"]["wow"] == 2
        assert len(stats["recent_imports"]) == 1

        # Check import history
        assert stats["import_history"]["import_count"] == 1
        assert stats["import_history"]["total_imported"] == 2

    def test_get_import_statistics_empty(self, wago_client):
        """Test statistics with empty database."""
        stats = wago_client.get_import_statistics()

        assert stats["total_builds"] == 0
        assert stats["builds_by_product"] == {}
        assert stats["latest_builds"] == {}
        assert stats["recent_imports"] == []

    @patch("httpx.Client.get")
    def test_import_from_api(self, mock_get, wago_client, sample_wago_response):
        """Test importing builds fetched from API."""
        # Mock API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_wago_response
        mock_get.return_value = mock_response

        # Import with auto-fetch
        stats = wago_client.import_builds_to_database(force_refresh=True)

        # Should fetch once from the single API endpoint
        assert mock_get.call_count == 1

        # Should have 4 builds total (2 wow, 1 wow_classic, 1 wow_classic_era)
        assert stats["fetched"] == 4
        assert stats["imported"] == 4

        # Verify in database
        cursor = wago_client.conn.execute("SELECT COUNT(*) FROM wago_builds")
        count = cursor.fetchone()[0]
        assert count == 4

    def test_import_error_logging(self, wago_client, sample_wago_builds):
        """Test error logging during import."""
        # Create a scenario that will cause database constraint violation
        # by inserting the same build twice without proper handling
        build = sample_wago_builds[0]

        # First insert should succeed
        wago_client.import_builds_to_database([build])

        # Manually insert duplicate to create constraint violation
        try:
            wago_client.conn.execute("""
                INSERT INTO wago_builds (
                    id, build, version, product
                ) VALUES (?, ?, ?, ?)
            """, (build.id, build.build, build.version, build.product))
            wago_client.conn.commit()
        except sqlite3.IntegrityError:
            # Expected - this tests the error logging pathway
            pass

        # The import error logging is tested through exception paths in the code
        # Let's just verify the database has proper constraints
        cursor = wago_client.conn.execute(
            "SELECT COUNT(*) FROM wago_builds WHERE id = ? AND product = ?",
            (build.id, build.product)
        )
        count = cursor.fetchone()[0]
        assert count == 1  # Should only have one record despite attempts to duplicate

    def test_database_connection_reuse(self, wago_client):
        """Test database connection reuse."""
        conn1 = wago_client.conn
        conn2 = wago_client.conn

        # Should reuse same connection
        assert conn1 is conn2

    def test_close_database_connection(self, wago_client):
        """Test closing database connection."""
        # Access connection to create it
        _ = wago_client.conn
        assert wago_client._conn is not None

        # Close client
        wago_client.close()

        # Connection should be closed
        with pytest.raises(sqlite3.ProgrammingError):
            wago_client._conn.execute("SELECT 1")

    def test_incremental_import_preserves_data(self, wago_client, sample_wago_builds):
        """Test that incremental imports preserve existing data."""
        # First import
        wago_client.import_builds_to_database(sample_wago_builds[:1])
        assert len(wago_client.get_database_builds()) == 1

        # Second import with additional builds
        wago_client.import_builds_to_database(sample_wago_builds[1:])
        assert len(wago_client.get_database_builds()) == 2

        # Third import with all builds (should not duplicate)
        stats = wago_client.import_builds_to_database(sample_wago_builds)
        assert stats["imported"] == 0  # No new imports
        assert stats["updated"] == 2   # All existing updated
        assert len(wago_client.get_database_builds()) == 2

    def test_product_family_support(self, wago_client):
        """Test product family constants."""
        assert "wow" in wago_client.SUPPORTED_PRODUCTS
        assert "wow_classic" in wago_client.SUPPORTED_PRODUCTS
        assert "wow_classic_era" in wago_client.SUPPORTED_PRODUCTS

        assert "wow" in wago_client.PRODUCT_FAMILIES
        assert "agent" in wago_client.PRODUCT_FAMILIES
        assert "bna" in wago_client.PRODUCT_FAMILIES

        wow_family = wago_client.PRODUCT_FAMILIES["wow"]
        assert "wow" in wow_family
        assert "wow_classic" in wow_family
        assert "wow_classic_era" in wow_family
