"""Comprehensive tests for cascette_tools.database.tact_keys module."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest

from cascette_tools.core.config import AppConfig
from cascette_tools.database.tact_keys import (
    TACTKey,
    TACTKeyManager,
    create_blte_key_store,
)


class TestTACTKey:
    """Test TACTKey model."""

    def test_tact_key_basic_fields(self):
        """Test TACTKey with basic required fields."""
        key = TACTKey(
            key_name="ABCD1234EFGH5678",
            key_value="1234567890ABCDEF1234567890ABCDEF"
        )
        assert key.key_name == "ABCD1234EFGH5678"
        assert key.key_value == "1234567890ABCDEF1234567890ABCDEF"
        assert key.description is None
        assert key.product_family == "wow"  # Default
        assert key.verified is False  # Default

    def test_tact_key_all_fields(self):
        """Test TACTKey with all fields populated."""
        key = TACTKey(
            key_name="ABCD1234EFGH5678",
            key_value="1234567890ABCDEF1234567890ABCDEF",
            description="Test encryption key",
            product_family="battlenet",
            verified=True
        )
        assert key.description == "Test encryption key"
        assert key.product_family == "battlenet"
        assert key.verified is True


class TestTACTKeyManager:
    """Test TACTKeyManager functionality."""

    @pytest.fixture
    def temp_config(self, tmp_path):
        """Create a temporary config for testing."""
        config = AppConfig()
        config.data_dir = tmp_path / "test_data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        return config

    @pytest.fixture
    def key_manager(self, temp_config):
        """Create a TACTKeyManager instance with temporary config."""
        manager = TACTKeyManager(temp_config)
        yield manager
        manager.close()

    @pytest.fixture
    def sample_wowdev_response(self):
        """Mock response from wowdev/TACTKeys GitHub repository."""
        return """# World of Warcraft TACT Keys
# Format: keyname;keyvalue;description
# Comments start with #

ABCD1234EFGH5678;1234567890ABCDEF1234567890ABCDEF;Test Key 1
FEDC9876BA54321;FEDCBA0987654321FEDCBA0987654321;Test Key 2
1111222233334444;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;Key with A's
# This is a comment line and should be ignored

# Empty lines above should also be ignored
5555666677778888;BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;Another test key
"""

    def test_init_default_config(self, tmp_path):
        """Test TACTKeyManager initialization with default config."""
        with patch('cascette_tools.database.tact_keys.AppConfig') as mock_config:
            mock_config.return_value.data_dir = tmp_path
            with TACTKeyManager() as manager:
                assert manager.config is not None
                assert manager.db_path == tmp_path / "tact_keys.db"
                assert manager.cache_dir == tmp_path / "tact_cache"

    def test_init_custom_config(self, temp_config):
        """Test TACTKeyManager initialization with custom config."""
        with TACTKeyManager(temp_config) as manager:
            assert manager.config == temp_config
            assert manager.db_path == temp_config.data_dir / "tact_keys.db"
            assert manager.cache_dir == temp_config.data_dir / "tact_cache"

    def test_database_initialization(self, key_manager):
        """Test that database schema is properly initialized."""
        # Database should be initialized on creation
        conn = key_manager.conn

        # Check that table exists
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [row[0] for row in tables]

        assert "tact_keys" in table_names

        # Check indexes exist
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        index_names = [row[0] for row in indexes]

        assert "idx_key_name" in index_names
        assert "idx_product_family" in index_names

    def test_get_key_not_found(self, key_manager):
        """Test getting a key that doesn't exist."""
        key = key_manager.get_key("NONEXISTENT123")
        assert key is None

    def test_add_and_get_key_string(self, key_manager):
        """Test adding and retrieving a key with string key name."""
        tact_key = TACTKey(
            key_name="ABCD1234EFGH5678",
            key_value="1234567890ABCDEF1234567890ABCDEF",
            description="Test key",
            verified=True
        )

        # Add key
        result = key_manager.add_key(tact_key)
        assert result is True

        # Retrieve key
        retrieved = key_manager.get_key("ABCD1234EFGH5678")
        assert retrieved is not None
        assert retrieved.key_name == "ABCD1234EFGH5678"
        assert retrieved.key_value == "1234567890ABCDEF1234567890ABCDEF"
        assert retrieved.description == "Test key"
        assert retrieved.verified is True

    def test_add_and_get_key_bytes(self, key_manager):
        """Test adding and retrieving a key with bytes key name."""
        tact_key = TACTKey(
            key_name="ABCD1234EF125678",  # Valid hex
            key_value="1234567890ABCDEF1234567890ABCDEF"
        )

        key_manager.add_key(tact_key)

        # Retrieve using bytes
        key_bytes = bytes.fromhex("ABCD1234EF125678")
        retrieved = key_manager.get_key(key_bytes)
        assert retrieved is not None
        assert retrieved.key_name == "ABCD1234EF125678"

    def test_get_key_case_insensitive(self, key_manager):
        """Test that key retrieval is case insensitive."""
        tact_key = TACTKey(
            key_name="abcd1234ef125678",  # Valid hex
            key_value="1234567890ABCDEF1234567890ABCDEF"
        )

        key_manager.add_key(tact_key)

        # Should find key regardless of case
        retrieved_upper = key_manager.get_key("ABCD1234EF125678")
        retrieved_lower = key_manager.get_key("abcd1234ef125678")
        retrieved_mixed = key_manager.get_key("AbCd1234Ef125678")

        assert retrieved_upper is not None
        assert retrieved_lower is not None
        assert retrieved_mixed is not None
        assert retrieved_upper.key_name == "ABCD1234EF125678"  # Stored as uppercase

    def test_add_key_update_existing(self, key_manager):
        """Test updating an existing key."""
        # Add initial key
        initial_key = TACTKey(
            key_name="ABCD1234EF125678",  # Valid hex
            key_value="1111111111111111111111111111111",
            description="Initial description"
        )
        key_manager.add_key(initial_key)

        # Update key
        updated_key = TACTKey(
            key_name="ABCD1234EF125678",
            key_value="2222222222222222222222222222222",
            description="Updated description",
            verified=True
        )
        result = key_manager.add_key(updated_key)
        assert result is True

        # Verify update
        retrieved = key_manager.get_key("ABCD1234EF125678")
        assert retrieved.key_value == "2222222222222222222222222222222"
        assert retrieved.description == "Updated description"
        assert retrieved.verified is True

    def test_get_all_keys_empty(self, key_manager):
        """Test getting all keys when database is empty."""
        keys = key_manager.get_all_keys()
        assert keys == []

    def test_get_all_keys(self, key_manager):
        """Test getting all keys from database."""
        # Add multiple keys
        keys_to_add = [
            TACTKey(key_name="KEY1", key_value="VALUE1", product_family="wow"),
            TACTKey(key_name="KEY2", key_value="VALUE2", product_family="battlenet"),
            TACTKey(key_name="KEY3", key_value="VALUE3", product_family="wow", verified=True)
        ]

        for key in keys_to_add:
            key_manager.add_key(key)

        # Retrieve all keys
        all_keys = key_manager.get_all_keys()
        assert len(all_keys) == 3

        # Verify keys are present
        key_names = {key.key_name for key in all_keys}
        assert key_names == {"KEY1", "KEY2", "KEY3"}

    def test_get_keys_by_family(self, key_manager):
        """Test getting keys filtered by product family."""
        # Add keys for different families
        keys_to_add = [
            TACTKey(key_name="WOW1", key_value="VALUE1", product_family="wow"),
            TACTKey(key_name="WOW2", key_value="VALUE2", product_family="wow"),
            TACTKey(key_name="BN1", key_value="VALUE3", product_family="battlenet"),
        ]

        for key in keys_to_add:
            key_manager.add_key(key)

        # Get WoW keys
        wow_keys = key_manager.get_keys_by_family("wow")
        assert len(wow_keys) == 2
        assert all(key.product_family == "wow" for key in wow_keys)

        # Get Battle.net keys
        bn_keys = key_manager.get_keys_by_family("battlenet")
        assert len(bn_keys) == 1
        assert bn_keys[0].product_family == "battlenet"

        # Get non-existent family
        empty_keys = key_manager.get_keys_by_family("nonexistent")
        assert empty_keys == []

    @patch('cascette_tools.database.tact_keys.httpx.Client')
    def test_fetch_wowdev_keys_success(self, mock_client_class, key_manager, sample_wowdev_response):
        """Test successful fetching of keys from wowdev repository."""
        # Setup mock client
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = sample_wowdev_response
        mock_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        keys = key_manager.fetch_wowdev_keys(force_refresh=True)

        # Should parse 4 valid keys (ignoring comments and empty lines)
        assert len(keys) == 4

        # Verify first key
        assert keys[0].key_name == "ABCD1234EFGH5678"
        assert keys[0].key_value == "1234567890ABCDEF1234567890ABCDEF"
        assert keys[0].description == "Test Key 1"
        assert keys[0].product_family == "wow"
        assert keys[0].verified is True  # wowdev keys are verified

        # Verify cache files were created
        cache_file = key_manager.cache_dir / "wowdev_keys.json"
        metadata_file = key_manager.cache_dir / "wowdev_metadata.json"
        assert cache_file.exists()
        assert metadata_file.exists()

    @patch('cascette_tools.database.tact_keys.httpx.Client')
    def test_fetch_wowdev_keys_uses_cache(self, mock_client_class, key_manager):
        """Test that fetch_wowdev_keys uses valid cache."""
        # Create valid cache
        key_manager.cache_dir.mkdir(parents=True, exist_ok=True)

        cached_keys = [
            {
                "key_name": "CACHED1234",
                "key_value": "CACHEDVALUE123",
                "description": "Cached key",
                "product_family": "wow",
                "verified": True
            }
        ]

        cache_file = key_manager.cache_dir / "wowdev_keys.json"
        metadata_file = key_manager.cache_dir / "wowdev_metadata.json"

        with open(cache_file, "w") as f:
            json.dump(cached_keys, f)

        # Create fresh metadata
        metadata = {
            "fetch_time": datetime.now(UTC).isoformat(),
            "key_count": 1,
            "source": "wowdev/TACTKeys"
        }
        with open(metadata_file, "w") as f:
            json.dump(metadata, f)

        # Should use cache without making HTTP request
        keys = key_manager.fetch_wowdev_keys()

        # Verify no HTTP request was made
        mock_client_class.assert_not_called()

        # Verify cached keys were returned
        assert len(keys) == 1
        assert keys[0].key_name == "CACHED1234"

    @patch('cascette_tools.database.tact_keys.httpx.Client')
    def test_fetch_wowdev_keys_expired_cache(self, mock_client_class, key_manager, sample_wowdev_response):
        """Test fetching when cache is expired."""
        # Create expired cache
        key_manager.cache_dir.mkdir(parents=True, exist_ok=True)

        cache_file = key_manager.cache_dir / "wowdev_keys.json"
        metadata_file = key_manager.cache_dir / "wowdev_metadata.json"

        # Old cached keys
        cached_keys = [{"key_name": "OLD", "key_value": "OLD", "product_family": "wow", "verified": True}]
        with open(cache_file, "w") as f:
            json.dump(cached_keys, f)

        # Expired metadata (25 hours ago)
        old_time = datetime.now(UTC) - timedelta(hours=25)
        metadata = {
            "fetch_time": old_time.isoformat(),
            "key_count": 1,
            "source": "wowdev/TACTKeys"
        }
        with open(metadata_file, "w") as f:
            json.dump(metadata, f)

        # Setup mock for fresh fetch
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = sample_wowdev_response
        mock_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        keys = key_manager.fetch_wowdev_keys()

        # Should make HTTP request due to expired cache
        mock_client.get.assert_called_once()

        # Should return fresh keys, not cached ones
        assert len(keys) == 4  # From sample_wowdev_response
        assert not any(key.key_name == "OLD" for key in keys)

    @patch('cascette_tools.database.tact_keys.httpx.Client')
    def test_fetch_wowdev_keys_http_error_with_stale_cache(self, mock_client_class, key_manager):
        """Test falling back to stale cache on HTTP error."""
        # Create stale cache
        key_manager.cache_dir.mkdir(parents=True, exist_ok=True)

        cached_keys = [{"key_name": "STALE", "key_value": "STALE", "product_family": "wow", "verified": True}]
        cache_file = key_manager.cache_dir / "wowdev_keys.json"
        with open(cache_file, "w") as f:
            json.dump(cached_keys, f)

        # Setup mock to raise HTTP error
        mock_client = Mock()
        mock_client.get.side_effect = httpx.HTTPError("Network error")
        mock_client_class.return_value = mock_client

        keys = key_manager.fetch_wowdev_keys(force_refresh=True)

        # Should return stale cached keys
        assert len(keys) == 1
        assert keys[0].key_name == "STALE"

    @patch('cascette_tools.database.tact_keys.httpx.Client')
    def test_fetch_wowdev_keys_http_error_no_cache(self, mock_client_class, key_manager):
        """Test HTTP error with no cache available."""
        # Setup mock to raise HTTP error
        mock_client = Mock()
        mock_client.get.side_effect = httpx.HTTPError("Network error")
        mock_client_class.return_value = mock_client

        keys = key_manager.fetch_wowdev_keys(force_refresh=True)

        # Should return empty list when no cache is available
        assert keys == []

    def test_import_keys(self, key_manager):
        """Test importing a list of keys."""
        keys = [
            TACTKey(key_name="KEY1", key_value="VALUE1"),
            TACTKey(key_name="KEY2", key_value="VALUE2"),
            TACTKey(key_name="KEY3", key_value="VALUE3")
        ]

        imported_count = key_manager.import_keys(keys)
        assert imported_count == 3

        # Verify keys were imported
        all_keys = key_manager.get_all_keys()
        assert len(all_keys) == 3

    def test_import_keys_with_failures(self, key_manager):
        """Test importing keys with some failures."""
        # Add a key first to create potential conflict
        existing_key = TACTKey(key_name="EXISTING", key_value="VALUE")
        key_manager.add_key(existing_key)

        # Mock add_key to fail for some keys
        original_add_key = key_manager.add_key
        call_count = 0

        def mock_add_key(key):
            nonlocal call_count
            call_count += 1
            if key.key_name == "FAIL":
                return False  # Simulate failure
            return original_add_key(key)

        with patch.object(key_manager, 'add_key', side_effect=mock_add_key):
            keys = [
                TACTKey(key_name="SUCCESS1", key_value="VALUE1"),
                TACTKey(key_name="FAIL", key_value="VALUE2"),
                TACTKey(key_name="SUCCESS2", key_value="VALUE3")
            ]

            imported_count = key_manager.import_keys(keys)
            assert imported_count == 2  # Only successful imports counted

    @patch.object(TACTKeyManager, 'fetch_wowdev_keys')
    @patch.object(TACTKeyManager, 'import_keys')
    def test_sync_with_wowdev(self, mock_import, mock_fetch, key_manager):
        """Test syncing with wowdev repository."""
        # Setup mocks
        mock_keys = [TACTKey(key_name="TEST", key_value="VALUE")]
        mock_fetch.return_value = mock_keys
        mock_import.return_value = 1

        result = key_manager.sync_with_wowdev()

        # Verify calls
        mock_fetch.assert_called_once_with(force_refresh=True)
        mock_import.assert_called_once_with(mock_keys)
        assert result == 1

    def test_get_statistics_empty_database(self, key_manager):
        """Test getting statistics from empty database."""
        stats = key_manager.get_statistics()

        assert stats["total_keys"] == 0
        assert stats["verified"] == 0
        assert stats["unverified"] == 0
        assert stats["by_family"] == {}

    def test_get_statistics(self, key_manager):
        """Test getting statistics from populated database."""
        # Add keys with different properties
        keys = [
            TACTKey(key_name="WOW1", key_value="V1", product_family="wow", verified=True),
            TACTKey(key_name="WOW2", key_value="V2", product_family="wow", verified=False),
            TACTKey(key_name="BN1", key_value="V3", product_family="battlenet", verified=True),
            TACTKey(key_name="BN2", key_value="V4", product_family="battlenet", verified=True)
        ]

        for key in keys:
            key_manager.add_key(key)

        stats = key_manager.get_statistics()

        assert stats["total_keys"] == 4
        assert stats["verified"] == 3
        assert stats["unverified"] == 1
        assert stats["by_family"]["wow"] == 2
        assert stats["by_family"]["battlenet"] == 2

    def test_context_manager(self, temp_config):
        """Test TACTKeyManager as context manager."""
        with TACTKeyManager(temp_config) as manager:
            assert manager is not None
            # Add a key to test functionality
            key = TACTKey(key_name="TEST", key_value="VALUE")
            result = manager.add_key(key)
            assert result is True

        # Manager should be closed after context exit

    def test_close(self, key_manager):
        """Test closing manager connections."""
        # Access client and connection to ensure they're created
        _ = key_manager.client
        _ = key_manager.conn

        # Close should not raise errors
        key_manager.close()

        # After close, _conn and _client should be None
        assert key_manager._conn is None
        assert key_manager._client is None

    def test_github_raw_url_constant(self):
        """Test that GitHub raw URL is correct."""
        expected_url = "https://raw.githubusercontent.com/wowdev/TACTKeys/master"
        assert TACTKeyManager.GITHUB_RAW_URL == expected_url

    def test_cache_lifetime_constant(self):
        """Test that cache lifetime is 24 hours."""
        assert TACTKeyManager.CACHE_LIFETIME == timedelta(hours=24)


class TestCreateBlteKeyStore:
    """Test create_blte_key_store helper function."""

    @pytest.fixture
    def key_manager(self, tmp_path):
        """Create a TACTKeyManager with sample keys."""
        config = AppConfig()
        config.data_dir = tmp_path / "test_data"
        config.data_dir.mkdir(parents=True, exist_ok=True)

        manager = TACTKeyManager(config)

        # Add sample keys (8-byte hex strings)
        keys = [
            TACTKey(key_name="ABCD1234", key_value="1111222233334444", product_family="wow"),
            TACTKey(key_name="EF125678", key_value="5555666677778888", product_family="wow"),  # Valid hex
            TACTKey(key_name="1234ABCD", key_value="9999AAAABBBBCCCC", product_family="battlenet")
        ]

        for key in keys:
            manager.add_key(key)

        yield manager
        manager.close()

    def test_create_blte_key_store_wow(self, key_manager):
        """Test creating BLTE key store for WoW product family."""
        key_store = create_blte_key_store(key_manager, "wow")

        # Should have 2 WoW keys
        assert len(key_store) == 2

        # Verify keys are converted to bytes
        expected_keys = {
            bytes.fromhex("ABCD1234"): bytes.fromhex("1111222233334444"),
            bytes.fromhex("EF125678"): bytes.fromhex("5555666677778888")
        }

        assert key_store == expected_keys

    def test_create_blte_key_store_battlenet(self, key_manager):
        """Test creating BLTE key store for battlenet product family."""
        key_store = create_blte_key_store(key_manager, "battlenet")

        # Should have 1 battlenet key
        assert len(key_store) == 1

        expected_key = bytes.fromhex("1234ABCD")
        expected_value = bytes.fromhex("9999AAAABBBBCCCC")

        assert expected_key in key_store
        assert key_store[expected_key] == expected_value

    def test_create_blte_key_store_empty_family(self, key_manager):
        """Test creating BLTE key store for non-existent product family."""
        key_store = create_blte_key_store(key_manager, "nonexistent")
        assert key_store == {}

    def test_create_blte_key_store_invalid_hex(self, tmp_path):
        """Test handling of invalid hex strings in keys."""
        config = AppConfig()
        config.data_dir = tmp_path / "test_data"
        config.data_dir.mkdir(parents=True, exist_ok=True)

        with TACTKeyManager(config) as manager:
            # Manually insert invalid hex key into database
            with manager.conn:
                manager.conn.execute("""
                    INSERT INTO tact_keys (key_name, key_value, product_family, verified)
                    VALUES (?, ?, ?, ?)
                """, ("INVALIDHEX", "ALSOINVALID", "wow", 1))

            # Should handle invalid hex gracefully
            key_store = create_blte_key_store(manager, "wow")

            # Should be empty due to invalid hex
            assert key_store == {}
