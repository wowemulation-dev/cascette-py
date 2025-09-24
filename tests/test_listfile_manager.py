"""Tests for ListfileManager functionality."""

import csv
import gzip
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest
import structlog

from cascette_tools.core.config import AppConfig
from cascette_tools.database.listfile import (
    FileDataEntry,
    ListfileCacheMetadata,
    ListfileManager,
)

# Disable logging for tests
structlog.configure(processors=[])

@pytest.fixture
def temp_config(tmp_path):
    """Create a temporary config for testing."""
    config = AppConfig()
    config.data_dir = tmp_path / "data"
    config.data_dir.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture
def sample_listfile_csv():
    """Sample CSV data from wowdev/wow-listfile."""
    return r"""fdid;filename
123456;Interface\AddOns\Blizzard_AuctionHouseUI\Blizzard_AuctionHouseUI.lua
789012;Sound\Music\GlueScreenMusic\wow_main_theme.mp3
345678;World\Textures\environment\grass_01.blp
901234;Creature\Dragon\Dragon_Red.m2"""


@pytest.fixture
def sample_listfile_entries():
    """Sample file entries for testing."""
    return [
        FileDataEntry(fdid=123456, path="Interface\\AddOns\\Blizzard_AuctionHouseUI\\Blizzard_AuctionHouseUI.lua", verified=True),
        FileDataEntry(fdid=789012, path="Sound\\Music\\GlueScreenMusic\\wow_main_theme.mp3", verified=True),
        FileDataEntry(fdid=345678, path="World\\Textures\\environment\\grass_01.blp", verified=True),
        FileDataEntry(fdid=901234, path="Creature\\Dragon\\Dragon_Red.m2", verified=True),
    ]


class TestFileDataEntry:
    """Test FileDataEntry model."""

    def test_create_file_entry(self):
        """Test creating a basic file entry."""
        entry = FileDataEntry(
            fdid=12345,
            path="Interface/AddOns/test.lua"
        )
        assert entry.fdid == 12345
        assert entry.path == "Interface/AddOns/test.lua"
        assert entry.verified is False
        assert entry.lookup_hash is None
        assert entry.added_date is None
        assert entry.product is None

    def test_create_full_file_entry(self):
        """Test creating a complete file entry."""
        added_date = datetime.now(UTC)
        entry = FileDataEntry(
            fdid=67890,
            path="Sound/Music/theme.mp3",
            verified=True,
            lookup_hash=0x12345678,
            added_date=added_date,
            product="wow"
        )
        assert entry.fdid == 67890
        assert entry.path == "Sound/Music/theme.mp3"
        assert entry.verified is True
        assert entry.lookup_hash == 0x12345678
        assert entry.added_date == added_date
        assert entry.product == "wow"

    def test_file_entry_validation(self):
        """Test file entry validation."""
        # Valid entry
        entry = FileDataEntry(fdid=123, path="test.txt")
        assert entry.fdid == 123

        # Invalid FDID
        with pytest.raises((ValueError, TypeError)):
            FileDataEntry(fdid="not_a_number", path="test.txt")  # type: ignore[arg-type]

        # Invalid path
        with pytest.raises((ValueError, TypeError)):
            FileDataEntry(fdid=123, path=None)  # type: ignore[arg-type]


class TestListfileCacheMetadata:
    """Test ListfileCacheMetadata model."""

    def test_create_cache_metadata(self):
        """Test creating cache metadata."""
        fetch_time = datetime.now(UTC)
        metadata = ListfileCacheMetadata(
            fetch_time=fetch_time,
            entry_count=1000,
            file_size=50000,
            source="wowdev/wow-listfile"
        )
        assert metadata.fetch_time == fetch_time
        assert metadata.entry_count == 1000
        assert metadata.file_size == 50000
        assert metadata.source == "wowdev/wow-listfile"
        assert metadata.cache_version == "1.0"

    def test_cache_metadata_serialization(self):
        """Test cache metadata JSON serialization."""
        fetch_time = datetime(2023, 1, 15, 12, 30, 45, tzinfo=UTC)
        metadata = ListfileCacheMetadata(
            fetch_time=fetch_time,
            entry_count=500,
            file_size=25000,
            source="test"
        )

        # Serialize to dict
        data = metadata.model_dump(mode='json')
        assert isinstance(data["fetch_time"], str)

        # Deserialize back
        restored = ListfileCacheMetadata.model_validate(data)
        assert restored.fetch_time == fetch_time
        assert restored.entry_count == 500


class TestListfileManager:
    """Test ListfileManager functionality."""

    def test_init_listfile_manager(self, temp_config):
        """Test initializing ListfileManager."""
        with ListfileManager(temp_config) as manager:
            assert manager.config == temp_config
            assert manager.db_path == temp_config.data_dir / "listfile.db"
            assert manager.cache_dir == temp_config.data_dir / "listfile_cache"
            assert manager.cache_dir.exists()

    def test_init_default_config(self):
        """Test initialization with default config."""
        with patch('cascette_tools.database.listfile.AppConfig') as mock_config:
            mock_instance = Mock()
            mock_instance.data_dir = Path("/tmp/test")
            mock_config.return_value = mock_instance

            with ListfileManager() as manager:
                assert manager.config == mock_instance

    def test_database_initialization(self, temp_config):
        """Test database schema initialization."""
        with ListfileManager(temp_config) as manager:
            # Check that tables exist
            cursor = manager.conn.cursor()
            tables = cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """).fetchall()

            table_names = [table[0] for table in tables]
            expected_tables = ['file_entries', 'listfile_sources', 'listfile_updates', 'file_search']

            for table in expected_tables:
                assert table in table_names

    def test_database_indexes(self, temp_config):
        """Test that database indexes are created."""
        with ListfileManager(temp_config) as manager:
            cursor = manager.conn.cursor()
            indexes = cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
            """).fetchall()

            index_names = [index[0] for index in indexes]
            expected_indexes = ['idx_fdid', 'idx_path_lower', 'idx_lookup_hash',
                               'idx_product_family', 'idx_product']

            for index in expected_indexes:
                assert index in index_names

    @patch('httpx.Client.get')
    def test_fetch_listfile_success(self, mock_get, temp_config, sample_listfile_csv):
        """Test successful listfile fetch from GitHub."""
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = sample_listfile_csv
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with ListfileManager(temp_config) as manager:
            entries = manager.fetch_listfile()

            # Check that entries were parsed correctly
            assert len(entries) == 4
            assert all(isinstance(entry, FileDataEntry) for entry in entries)
            assert entries[0].fdid == 123456
            assert entries[0].path == "Interface\\AddOns\\Blizzard_AuctionHouseUI\\Blizzard_AuctionHouseUI.lua"
            assert entries[0].verified is True

            # Check that cache files were created
            cache_file = temp_config.data_dir / "listfile_cache" / "listfile.csv.gz"
            metadata_file = temp_config.data_dir / "listfile_cache" / "listfile_metadata.json"
            assert cache_file.exists()
            assert metadata_file.exists()

    @patch('httpx.Client.get')
    def test_fetch_listfile_http_error(self, mock_get, temp_config):
        """Test listfile fetch with HTTP error."""
        # Mock HTTP error
        mock_get.side_effect = httpx.HTTPError("Network error")

        with ListfileManager(temp_config) as manager:
            with pytest.raises(httpx.HTTPError):
                manager.fetch_listfile()

    def test_fetch_listfile_use_cache(self, temp_config, sample_listfile_entries):
        """Test using cached listfile when available and fresh."""
        # Create valid cache first
        cache_file = temp_config.data_dir / "listfile_cache" / "listfile.csv.gz"
        metadata_file = temp_config.data_dir / "listfile_cache" / "listfile_metadata.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        # Write cache file
        with gzip.open(cache_file, "wt", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["fdid", "path"])
            for entry in sample_listfile_entries:
                writer.writerow([entry.fdid, entry.path])

        # Write metadata file
        metadata = ListfileCacheMetadata(
            fetch_time=datetime.now(UTC),
            entry_count=len(sample_listfile_entries),
            file_size=cache_file.stat().st_size,
            source="test"
        )
        with open(metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode='json'), f, default=str)

        with ListfileManager(temp_config) as manager:
            # Should use cache without network call
            with patch('httpx.Client.get') as mock_get:
                entries = manager.fetch_listfile()
                mock_get.assert_not_called()

            assert len(entries) == 4
            assert entries[0].fdid == 123456

    def test_fetch_listfile_expired_cache(self, temp_config, sample_listfile_entries):
        """Test fetching when cache is expired."""
        # Create expired cache first
        cache_file = temp_config.data_dir / "listfile_cache" / "listfile.csv.gz"
        metadata_file = temp_config.data_dir / "listfile_cache" / "listfile_metadata.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        with gzip.open(cache_file, "wt", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["fdid", "path"])
            writer.writerow([12345, "test.txt"])

        # Create expired metadata
        expired_time = datetime.now(UTC) - timedelta(hours=25)
        metadata = ListfileCacheMetadata(
            fetch_time=expired_time,
            entry_count=1,
            file_size=100,
            source="test"
        )
        with open(metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode='json'), f, default=str)

        with ListfileManager(temp_config) as manager:
            # Mock new fetch
            with patch('httpx.Client.get') as mock_get:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.text = "fdid;filename\n67890;new_file.txt"
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response

                entries = manager.fetch_listfile()
                mock_get.assert_called_once()

            assert len(entries) == 1
            assert entries[0].fdid == 67890

    def test_import_entries(self, temp_config, sample_listfile_entries):
        """Test importing entries into database."""
        with ListfileManager(temp_config) as manager:
            count = manager.import_entries(sample_listfile_entries, "test")
            assert count == 4

            # Verify entries in database
            cursor = manager.conn.cursor()
            rows = cursor.execute("SELECT fdid, path FROM file_entries ORDER BY fdid").fetchall()
            assert len(rows) == 4
            assert rows[0]["fdid"] == 123456

    def test_import_entries_update(self, temp_config, sample_listfile_entries):
        """Test updating existing entries."""
        with ListfileManager(temp_config) as manager:
            # Import initial entries
            manager.import_entries(sample_listfile_entries, "test")

            # Create updated entry
            updated_entry = FileDataEntry(
                fdid=123456,
                path="Interface\\AddOns\\UpdatedPath.lua",
                verified=True
            )

            count = manager.import_entries([updated_entry], "test_update")
            assert count == 1

            # Verify update
            path = manager.get_path(123456)
            assert path == "Interface\\AddOns\\UpdatedPath.lua"

            # Verify update was logged
            cursor = manager.conn.cursor()
            updates = cursor.execute("SELECT * FROM listfile_updates").fetchall()
            assert len(updates) == 1
            assert updates[0]["fdid"] == 123456

    def test_get_path(self, temp_config, sample_listfile_entries):
        """Test getting path by FDID."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            path = manager.get_path(123456)
            assert path == "Interface\\AddOns\\Blizzard_AuctionHouseUI\\Blizzard_AuctionHouseUI.lua"

            # Test non-existent FDID
            path = manager.get_path(999999)
            assert path is None

    def test_get_fdid(self, temp_config, sample_listfile_entries):
        """Test getting FDID by path."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            # Test exact match
            fdid = manager.get_fdid("Interface\\AddOns\\Blizzard_AuctionHouseUI\\Blizzard_AuctionHouseUI.lua")
            assert fdid == 123456

            # Test case-insensitive match
            fdid = manager.get_fdid("interface\\addons\\blizzard_auctionhouseui\\blizzard_auctionhouseui.lua")
            assert fdid == 123456

            # Test non-existent path
            fdid = manager.get_fdid("nonexistent/path.txt")
            assert fdid is None

    def test_search_paths(self, temp_config, sample_listfile_entries):
        """Test searching paths using FTS."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            # Search for "Blizzard"
            results = manager.search_paths("Blizzard")
            assert len(results) == 1
            assert results[0].fdid == 123456

            # Search for file extension using FTS5 syntax
            results = manager.search_paths("m2")
            # Should find the Dragon file
            assert len(results) == 1
            assert results[0].fdid == 901234

            # Search for non-existent term
            results = manager.search_paths("nonexistent")
            assert len(results) == 0

    def test_get_statistics(self, temp_config, sample_listfile_entries):
        """Test getting listfile statistics."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            stats = manager.get_statistics()

            assert stats["total_entries"] == 4
            assert stats["verified"] == 4
            assert stats["unverified"] == 0
            assert "by_product_family" in stats
            assert "top_extensions" in stats
            assert "last_update" in stats

    def test_sync_with_wowdev(self, temp_config):
        """Test syncing with wowdev repository."""
        with patch.object(ListfileManager, 'fetch_listfile') as mock_fetch, \
             patch.object(ListfileManager, 'import_entries') as mock_import:

            mock_entries = [FileDataEntry(fdid=123, path="test.txt")]
            mock_fetch.return_value = mock_entries
            mock_import.return_value = 1

            with ListfileManager(temp_config) as manager:
                count = manager.sync_with_wowdev()

                mock_fetch.assert_called_once_with(force_refresh=True)
                mock_import.assert_called_once_with(mock_entries)
                assert count == 1

    def test_export_listfile_csv(self, temp_config, sample_listfile_entries):
        """Test exporting listfile to CSV."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            output_file = temp_config.data_dir / "export.csv"
            manager.export_listfile(output_file, "csv")

            assert output_file.exists()

            # Verify CSV content
            with open(output_file, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 4
                assert int(rows[0]["fdid"]) == 123456

    def test_export_listfile_json(self, temp_config, sample_listfile_entries):
        """Test exporting listfile to JSON."""
        with ListfileManager(temp_config) as manager:
            manager.import_entries(sample_listfile_entries, "test")

            output_file = temp_config.data_dir / "export.json"
            manager.export_listfile(output_file, "json")

            assert output_file.exists()

            # Verify JSON content
            with open(output_file, encoding="utf-8") as f:
                data = json.load(f)
                assert len(data) == 4
                assert data[0]["fdid"] == 123456

    def test_context_manager(self, temp_config):
        """Test using ListfileManager as context manager."""
        with ListfileManager(temp_config) as manager:
            assert manager._conn is not None

        # Connections should be closed after context exit
        # Note: We can't directly test this without accessing private attributes

    def test_close(self, temp_config):
        """Test closing connections."""
        manager = ListfileManager(temp_config)
        try:
            # Access properties to create connections
            _ = manager.conn
            _ = manager.client

            # Close should not raise errors
            manager.close()

            # Multiple closes should be safe
            manager.close()
        finally:
            # Ensure cleanup even if test fails
            manager.close()

    def test_parse_csv_semicolon_format(self, temp_config):
        """Test parsing semicolon-separated CSV format."""
        csv_text = """fdid;filename
123;test1.txt
456;test2.txt"""

        with ListfileManager(temp_config) as manager:
            entries = manager._parse_csv_listfile(csv_text)

            assert len(entries) == 2
            assert entries[0].fdid == 123
            assert entries[0].path == "test1.txt"

    def test_parse_csv_comma_format(self, temp_config):
        """Test parsing comma-separated CSV format."""
        csv_text = """fdid,path
789,"test3.txt"
101112,"test4.txt" """

        with ListfileManager(temp_config) as manager:
            entries = manager._parse_csv_listfile(csv_text)

            assert len(entries) == 2
            assert entries[0].fdid == 789
            assert entries[0].path == "test3.txt"

    def test_parse_csv_invalid_rows(self, temp_config):
        """Test parsing CSV with invalid rows."""
        csv_text = """fdid;filename
123;test1.txt
invalid;row
456;test2.txt
;missing_fdid
789;"""

        with ListfileManager(temp_config) as manager:
            entries = manager._parse_csv_listfile(csv_text)

            # Should skip invalid rows and only parse valid ones
            assert len(entries) == 2
            assert entries[0].fdid == 123
            assert entries[1].fdid == 456

    def test_http_client_properties(self, temp_config):
        """Test HTTP client configuration."""
        with ListfileManager(temp_config) as manager:
            client = manager.client

            assert isinstance(client, httpx.Client)
            assert client.timeout.read == 60.0
            assert client.headers["User-Agent"] == "cascette-tools/0.1.0"

    def test_database_connection_properties(self, temp_config):
        """Test database connection properties."""
        with ListfileManager(temp_config) as manager:
            conn = manager.conn

            assert isinstance(conn, sqlite3.Connection)
            assert conn.row_factory == sqlite3.Row

            # Test WAL mode was set
            result = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert result.lower() == "wal"
