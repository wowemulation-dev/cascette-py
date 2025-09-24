"""Comprehensive tests for cascette_tools.database.wago module."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest

from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import Product
from cascette_tools.database.wago import WagoBuild, WagoCacheMetadata, WagoClient


class TestWagoBuild:
    """Test WagoBuild model."""

    def test_wagobuild_basic_fields(self):
        """Test WagoBuild with basic required fields."""
        build = WagoBuild(
            id=12345,
            build="10.2.5.52902",
            version="10.2.5.52902",
            product="wow"
        )
        assert build.id == 12345
        assert build.build == "10.2.5.52902"
        assert build.version == "10.2.5.52902"
        assert build.product == "wow"
        assert build.build_time is None
        assert build.build_config is None

    def test_wagobuild_full_fields(self):
        """Test WagoBuild with all fields populated."""
        build_time = datetime.now(UTC)
        build = WagoBuild(
            id=12345,
            build="10.2.5.52902",
            version="10.2.5.52902",
            product="wow",
            build_time=build_time,
            build_config="abc123def456",
            cdn_config="fed456cba789",
            product_config="123fed456abc",
            encoding_ekey="encoding123",
            root_ekey="root456",
            install_ekey="install789",
            download_ekey="download012"
        )
        assert build.build_time == build_time
        assert build.build_config == "abc123def456"
        assert build.cdn_config == "fed456cba789"
        assert build.product_config == "123fed456abc"
        assert build.encoding_ekey == "encoding123"
        assert build.root_ekey == "root456"
        assert build.install_ekey == "install789"
        assert build.download_ekey == "download012"


class TestWagoCacheMetadata:
    """Test WagoCacheMetadata model."""

    def test_cache_metadata_required_fields(self):
        """Test WagoCacheMetadata with required fields."""
        fetch_time = datetime.now(UTC)
        expires_at = fetch_time + timedelta(hours=24)

        metadata = WagoCacheMetadata(
            fetch_time=fetch_time,
            expires_at=expires_at,
            build_count=100
        )
        assert metadata.fetch_time == fetch_time
        assert metadata.expires_at == expires_at
        assert metadata.build_count == 100
        assert metadata.api_version == "v1"  # Default value

    def test_cache_metadata_custom_api_version(self):
        """Test WagoCacheMetadata with custom API version."""
        metadata = WagoCacheMetadata(
            fetch_time=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=24),
            build_count=50,
            api_version="v2"
        )
        assert metadata.api_version == "v2"


class TestWagoClient:
    """Test WagoClient functionality."""

    @pytest.fixture
    def temp_config(self, tmp_path):
        """Create a temporary config for testing."""
        config = AppConfig()
        config.data_dir = tmp_path / "test_data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        return config

    @pytest.fixture
    def mock_builds_response(self):
        """Mock API response with sample builds - new format with product keys."""
        return {
            "wow": [
                {
                    "id": 12345,
                    "product": "wow",
                    "build": "10.2.5.52902",
                    "version": "10.2.5.52902",
                    "created_at": "2024-01-15T10:30:00Z",
                    "build_config": "abc123def456",
                    "cdn_config": "fed456cba789",
                    "product_config": "123fed456abc",
                    "encoding_ekey": "encoding123",
                    "root_ekey": "root456",
                    "install_ekey": "install789",
                    "download_ekey": "download012"
                },
                {
                    "id": 12346,
                    "product": "wow",
                    "build": "10.2.6.52902",
                    "version": "10.2.6.52902",
                    "created_at": "2024-01-16T11:30:00Z",
                    "build_config": "def456abc789",
                    "cdn_config": "789fed456abc",
                    "product_config": "456abc789def"
                }
            ],
            "wow_classic": [],
            "wow_classic_era": []
        }

    @pytest.fixture
    def wago_client(self, temp_config):
        """Create a WagoClient instance with temporary config."""
        client = WagoClient(temp_config)
        yield client
        client.close()

    def test_init_default_config(self, tmp_path):
        """Test WagoClient initialization with default config."""
        with patch('cascette_tools.database.wago.AppConfig') as mock_config:
            mock_config.return_value.data_dir = tmp_path
            with WagoClient() as client:
                assert client.config is not None
                assert client.cache_dir == tmp_path / "wago_cache"
                assert client.db_path == tmp_path / "wago_builds.db"

    def test_init_custom_config(self, temp_config):
        """Test WagoClient initialization with custom config."""
        with WagoClient(temp_config) as client:
            assert client.config == temp_config
            assert client.cache_dir == temp_config.data_dir / "wago_cache"
            assert client.db_path == temp_config.data_dir / "wago_builds.db"

    def test_database_initialization(self, wago_client):
        """Test that database schema is properly initialized."""
        # Database should be initialized on creation
        conn = wago_client.conn

        # Check that tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [row[0] for row in tables]

        assert "wago_builds" in table_names
        assert "wago_import_log" in table_names

        # Check indexes exist
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        index_names = [row[0] for row in indexes]

        assert "idx_wago_product" in index_names
        assert "idx_wago_version" in index_names
        assert "idx_wago_build_time" in index_names

    def test_is_cache_valid_no_cache(self, wago_client):
        """Test cache validation when no cache files exist."""
        assert not wago_client._is_cache_valid()

    def test_is_cache_valid_missing_metadata(self, wago_client):
        """Test cache validation when metadata file is missing."""
        # Create cache file but no metadata
        wago_client.cache_file.parent.mkdir(parents=True, exist_ok=True)
        wago_client.cache_file.write_text("[]")

        assert not wago_client._is_cache_valid()

    def test_is_cache_valid_fresh_cache(self, wago_client):
        """Test cache validation with fresh cache."""
        # Create valid cache and metadata
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache data
        cache_data = [{"id": 1, "build": "test", "version": "test", "product": "wow"}]
        with open(wago_client.cache_file, "w") as f:
            json.dump(cache_data, f)

        # Fresh metadata
        now = datetime.now(UTC)
        metadata = WagoCacheMetadata(
            fetch_time=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=23),
            build_count=1
        )
        with open(wago_client.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, default=str)

        assert wago_client._is_cache_valid()

    def test_is_cache_valid_expired_cache(self, wago_client):
        """Test cache validation with expired cache."""
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache data
        cache_data = [{"id": 1, "build": "test", "version": "test", "product": "wow"}]
        with open(wago_client.cache_file, "w") as f:
            json.dump(cache_data, f)

        # Expired metadata
        now = datetime.now(UTC)
        metadata = WagoCacheMetadata(
            fetch_time=now - timedelta(hours=25),
            expires_at=now - timedelta(hours=1),
            build_count=1
        )
        with open(wago_client.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, default=str)

        assert not wago_client._is_cache_valid()

    def test_load_cache(self, wago_client):
        """Test loading builds from cache."""
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create cache data with datetime
        build_time = datetime.now(UTC)
        cache_data = [{
            "id": 12345,
            "build": "10.2.5.52902",
            "version": "10.2.5.52902",
            "product": "wow",
            "build_time": build_time.isoformat(),
            "build_config": "abc123"
        }]

        with open(wago_client.cache_file, "w") as f:
            json.dump(cache_data, f)

        builds = wago_client._load_cache()
        assert len(builds) == 1
        assert builds[0].id == 12345
        assert builds[0].build == "10.2.5.52902"
        assert builds[0].build_config == "abc123"
        assert isinstance(builds[0].build_time, datetime)

    def test_save_cache(self, wago_client):
        """Test saving builds to cache."""
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create builds to save
        build_time = datetime.now(UTC)
        builds = [WagoBuild(
            id=12345,
            build="10.2.5.52902",
            version="10.2.5.52902",
            product="wow",
            build_time=build_time,
            build_config="abc123"
        )]

        wago_client._save_cache(builds)

        # Verify cache file was created
        assert wago_client.cache_file.exists()
        assert wago_client.metadata_file.exists()

        # Verify cache content
        with open(wago_client.cache_file) as f:
            cache_data = json.load(f)
        assert len(cache_data) == 1
        assert cache_data[0]["id"] == 12345
        assert cache_data[0]["build_time"] == build_time.isoformat()

        # Verify metadata
        with open(wago_client.metadata_file) as f:
            metadata_data = json.load(f)
        assert metadata_data["build_count"] == 1
        assert "fetch_time" in metadata_data
        assert "expires_at" in metadata_data

    @patch('cascette_tools.database.wago.httpx.Client')
    def test_fetch_builds_from_api(self, mock_client_class, wago_client, mock_builds_response):
        """Test fetching builds from API."""
        # Setup mock client
        mock_client = Mock()
        mock_response = Mock()
        mock_response.json.return_value = mock_builds_response
        mock_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        builds = wago_client.fetch_builds(force_refresh=True)

        # Verify API was called once (single endpoint)
        assert mock_client.get.call_count == 1

        # Verify builds were parsed correctly
        assert len(builds) == 2  # 2 wow builds (empty classic and era)
        wow_builds = [b for b in builds if b.product == "wow"]
        assert len(wow_builds) == 2
        assert wow_builds[0].id == 12345
        assert wow_builds[0].build == "10.2.5.52902"
        assert isinstance(wow_builds[0].build_time, datetime)

    @patch('cascette_tools.database.wago.httpx.Client')
    def test_fetch_builds_http_error_with_cache_fallback(self, mock_client_class, wago_client):
        """Test fetch_builds falls back to cache on HTTP error."""
        # Setup mock client to raise HTTP error
        mock_client = Mock()
        mock_client.get.side_effect = httpx.HTTPError("Network error")
        mock_client_class.return_value = mock_client

        # Create cache file
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)
        cache_data = [{"id": 1, "build": "test", "version": "test", "product": "wow"}]
        with open(wago_client.cache_file, "w") as f:
            json.dump(cache_data, f)

        # Should fall back to cache
        builds = wago_client.fetch_builds(force_refresh=True)
        assert len(builds) == 1
        assert builds[0].id == 1

    @patch('cascette_tools.database.wago.httpx.Client')
    def test_fetch_builds_http_error_no_cache(self, mock_client_class, wago_client):
        """Test fetch_builds raises error when no cache available."""
        # Setup mock client to raise HTTP error
        mock_client = Mock()
        mock_client.get.side_effect = httpx.HTTPError("Network error")
        mock_client_class.return_value = mock_client

        # Should raise the HTTP error
        with pytest.raises(httpx.HTTPError):
            wago_client.fetch_builds(force_refresh=True)

    def test_fetch_builds_uses_cache(self, wago_client):
        """Test fetch_builds uses valid cache instead of API."""
        # Create valid cache
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        cache_data = [{"id": 1, "build": "cached", "version": "cached", "product": "wow"}]
        with open(wago_client.cache_file, "w") as f:
            json.dump(cache_data, f)

        # Fresh metadata
        now = datetime.now(UTC)
        metadata = WagoCacheMetadata(
            fetch_time=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=23),
            build_count=1
        )
        with open(wago_client.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, default=str)

        # Should use cache without making API call
        with patch('cascette_tools.database.wago.httpx.Client') as mock_client_class:
            builds = wago_client.fetch_builds()
            # Client should not be instantiated since cache is used
            mock_client_class.assert_not_called()
            assert len(builds) == 1
            assert builds[0].build == "cached"

    def test_get_builds_for_product(self, wago_client):
        """Test filtering builds by product."""
        # Mock fetch_builds to return mixed products
        builds = [
            WagoBuild(id=1, build="1", version="1", product="wow"),
            WagoBuild(id=2, build="2", version="2", product="wow_classic"),
            WagoBuild(id=3, build="3", version="3", product="wow"),
        ]

        with patch.object(wago_client, 'fetch_builds', return_value=builds):
            # Test with string
            wow_builds = wago_client.get_builds_for_product("wow")
            assert len(wow_builds) == 2
            assert all(b.product == "wow" for b in wow_builds)

            # Test with Product enum
            classic_builds = wago_client.get_builds_for_product(Product.WOW_CLASSIC)
            assert len(classic_builds) == 1
            assert classic_builds[0].product == "wow_classic"

    def test_find_build(self, wago_client):
        """Test finding specific build by version."""
        builds = [
            WagoBuild(id=1, build="1.0.0", version="1.0.0", product="wow"),
            WagoBuild(id=2, build="2.0.0", version="2.0.0", product="wow_classic"),
        ]

        with patch.object(wago_client, 'fetch_builds', return_value=builds):
            # Find without product filter
            build = wago_client.find_build("1.0.0")
            assert build is not None
            assert build.id == 1

            # Find with product filter (string)
            build = wago_client.find_build("2.0.0", "wow_classic")
            assert build is not None
            assert build.id == 2

            # Find with product filter (enum)
            build = wago_client.find_build("2.0.0", Product.WOW_CLASSIC)
            assert build is not None
            assert build.id == 2

            # Find non-existent
            build = wago_client.find_build("3.0.0")
            assert build is None

            # Find wrong product
            build = wago_client.find_build("1.0.0", "wow_classic")
            assert build is None

    def test_get_latest_build(self, wago_client):
        """Test getting latest build by highest ID."""
        builds = [
            WagoBuild(id=1, build="1.0.0", version="1.0.0", product="wow"),
            WagoBuild(id=3, build="3.0.0", version="3.0.0", product="wow"),
            WagoBuild(id=2, build="2.0.0", version="2.0.0", product="wow"),
        ]

        with patch.object(wago_client, 'get_builds_for_product', return_value=builds):
            latest = wago_client.get_latest_build("wow")
            assert latest is not None
            assert latest.id == 3  # Highest ID
            assert latest.version == "3.0.0"

    def test_get_latest_build_no_builds(self, wago_client):
        """Test getting latest build when no builds exist."""
        with patch.object(wago_client, 'get_builds_for_product', return_value=[]):
            latest = wago_client.get_latest_build("wow")
            assert latest is None

    def test_clear_cache(self, wago_client):
        """Test clearing cache files."""
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create cache files
        wago_client.cache_file.write_text("[]")
        wago_client.metadata_file.write_text("{}")

        assert wago_client.cache_file.exists()
        assert wago_client.metadata_file.exists()

        # Clear cache
        result = wago_client.clear_cache()
        assert result is True
        assert not wago_client.cache_file.exists()
        assert not wago_client.metadata_file.exists()

    def test_clear_cache_no_files(self, wago_client):
        """Test clearing cache when no files exist."""
        result = wago_client.clear_cache()
        assert result is False

    def test_get_cache_status_invalid(self, wago_client):
        """Test cache status when cache is invalid."""
        status = wago_client.get_cache_status()
        assert status["valid"] is False
        assert status["exists"] is False

    def test_get_cache_status_valid(self, wago_client):
        """Test cache status with valid cache."""
        wago_client.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create cache files
        wago_client.cache_file.write_text("[]")

        now = datetime.now(UTC)
        metadata = WagoCacheMetadata(
            fetch_time=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=23),
            build_count=5
        )
        with open(wago_client.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, default=str)

        status = wago_client.get_cache_status()
        assert status["valid"] is True
        assert status["build_count"] == 5
        assert "age_hours" in status
        assert "remaining_hours" in status
        assert "cache_size_kb" in status

    def test_import_builds_to_database(self, wago_client):
        """Test importing builds to database."""
        builds = [
            WagoBuild(
                id=1, build="1.0.0", version="1.0.0", product="wow",
                build_config="abc123", cdn_config="def456"
            ),
            WagoBuild(
                id=2, build="2.0.0", version="2.0.0", product="wow_classic",
                encoding_ekey="enc789"
            )
        ]

        stats = wago_client.import_builds_to_database(builds)

        assert stats["fetched"] == 2
        assert stats["imported"] == 2
        assert stats["updated"] == 0
        assert stats["skipped"] == 0

        # Verify builds were inserted
        rows = wago_client.conn.execute("SELECT * FROM wago_builds").fetchall()
        assert len(rows) == 2

        # Verify import log
        log_rows = wago_client.conn.execute("SELECT * FROM wago_import_log").fetchall()
        assert len(log_rows) == 1
        assert log_rows[0]["success"] == 1

    def test_import_builds_update_existing(self, wago_client):
        """Test updating existing builds during import."""
        # Insert initial build
        initial_build = WagoBuild(
            id=1, build="1.0.0", version="1.0.0", product="wow",
            build_config="old_config"
        )
        wago_client.import_builds_to_database([initial_build])

        # Import updated build
        updated_build = WagoBuild(
            id=1, build="1.0.1", version="1.0.1", product="wow",
            build_config="new_config"
        )
        stats = wago_client.import_builds_to_database([updated_build])

        assert stats["imported"] == 0
        assert stats["updated"] == 1

        # Verify update
        row = wago_client.conn.execute(
            "SELECT build_config FROM wago_builds WHERE id = 1"
        ).fetchone()
        assert row["build_config"] == "new_config"

    def test_get_database_builds(self, wago_client):
        """Test retrieving builds from database."""
        builds = [
            WagoBuild(id=1, build="1.0.0", version="1.0.0", product="wow"),
            WagoBuild(id=2, build="2.0.0", version="2.0.0", product="wow_classic"),
        ]
        wago_client.import_builds_to_database(builds)

        # Get all builds
        db_builds = wago_client.get_database_builds()
        assert len(db_builds) == 2

        # Get builds for specific product
        wow_builds = wago_client.get_database_builds(product="wow")
        assert len(wow_builds) == 1
        assert wow_builds[0].product == "wow"

        # Get builds with limit
        limited_builds = wago_client.get_database_builds(limit=1)
        assert len(limited_builds) == 1

    def test_find_database_build(self, wago_client):
        """Test finding builds in database."""
        builds = [
            WagoBuild(id=1, build="1.0.0", version="1.0.0", product="wow"),
            WagoBuild(id=2, build="2.0.0", version="2.0.0", product="wow_classic"),
        ]
        wago_client.import_builds_to_database(builds)

        # Find build by version only
        build = wago_client.find_database_build("1.0.0")
        assert build is not None
        assert build.id == 1

        # Find build by version and product
        build = wago_client.find_database_build("2.0.0", "wow_classic")
        assert build is not None
        assert build.id == 2

        # Find non-existent
        build = wago_client.find_database_build("3.0.0")
        assert build is None

    def test_get_import_statistics(self, wago_client):
        """Test getting import statistics."""
        builds = [
            WagoBuild(
                id=1, build="1.0.0", version="1.0.0", product="wow",
                build_time=datetime.now(UTC)
            ),
            WagoBuild(
                id=2, build="2.0.0", version="2.0.0", product="wow_classic",
                build_time=datetime.now(UTC)
            ),
        ]
        wago_client.import_builds_to_database(builds)

        stats = wago_client.get_import_statistics()

        assert stats["total_builds"] == 2
        assert "wow" in stats["builds_by_product"]
        assert "wow_classic" in stats["builds_by_product"]
        assert stats["builds_by_product"]["wow"] == 1
        assert stats["builds_by_product"]["wow_classic"] == 1
        assert "latest_builds" in stats
        assert "import_history" in stats
        assert "recent_imports" in stats

    def test_context_manager(self, temp_config):
        """Test WagoClient as context manager."""
        with WagoClient(temp_config) as client:
            assert client is not None
            assert hasattr(client, 'conn')

        # Client should be closed after context exit
        # Note: We can't easily test the closed state without accessing private attributes

    def test_close(self, wago_client):
        """Test closing client connections."""
        # Access client and connection to ensure they're created
        _ = wago_client.client
        _ = wago_client.conn

        # Close should not raise errors
        wago_client.close()

    def test_supported_products_constant(self):
        """Test that supported products constant is correct."""
        assert WagoClient.SUPPORTED_PRODUCTS == ["wow", "wow_classic", "wow_classic_era"]

    def test_product_families_constant(self):
        """Test that product families mapping is correct."""
        families = WagoClient.PRODUCT_FAMILIES
        assert "wow" in families
        assert "agent" in families
        assert "bna" in families
        assert families["wow"] == ["wow", "wow_classic", "wow_classic_era"]

    def test_cache_lifetime_constant(self):
        """Test that cache lifetime is 24 hours."""
        assert WagoClient.CACHE_LIFETIME == timedelta(hours=24)

    def test_api_base_constant(self):
        """Test that API base URL is correct."""
        assert WagoClient.API_BASE == "https://wago.tools/api"
