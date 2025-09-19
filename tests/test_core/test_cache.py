"""Tests for cache.py module."""

import os
import time
from unittest.mock import patch

from cascette_tools.core.cache import DiskCache


class TestDiskCache:
    """Test DiskCache class."""

    def test_init_default_base_dir(self, tmp_path):
        """Test initialization with default base directory."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            cache = DiskCache()
            expected_dir = tmp_path / ".cache" / "cascette"
            assert cache.base_dir == expected_dir
            assert cache.cdn_dir == expected_dir / "cdn"
            assert cache.api_dir == expected_dir / "api"
            assert cache.metadata_file == expected_dir / "metadata.json"

    def test_init_custom_base_dir(self, tmp_path):
        """Test initialization with custom base directory."""
        custom_dir = tmp_path / "custom_cache"
        cache = DiskCache(base_dir=custom_dir)
        assert cache.base_dir == custom_dir
        assert cache.cdn_dir == custom_dir / "cdn"
        assert cache.api_dir == custom_dir / "api"
        assert cache.metadata_file == custom_dir / "metadata.json"

    def test_directories_created(self, tmp_path):
        """Test that cache directories are created on initialization."""
        cache_dir = tmp_path / "cache"
        cache = DiskCache(base_dir=cache_dir)

        assert cache.cdn_dir.exists()
        assert cache.api_dir.exists()

    def test_get_cdn_cache_path_config(self, tmp_path):
        """Test CDN cache path generation for config files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        path = cache._get_cdn_cache_path(hash_str, "config", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "config" / "ab" / "cd" / "abcdef1234567890"
        assert path == expected

    def test_get_cdn_cache_path_data(self, tmp_path):
        """Test CDN cache path generation for data files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "1234abcd5678ef90"
        path = cache._get_cdn_cache_path(hash_str, "data", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "data" / "12" / "34" / "1234abcd5678ef90"
        assert path == expected

    def test_get_cdn_cache_path_index(self, tmp_path):
        """Test CDN cache path generation for index files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "fedcba0987654321"
        path = cache._get_cdn_cache_path(hash_str, "index", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "data" / "fe" / "dc" / "fedcba0987654321.index"
        assert path == expected

    def test_get_cdn_cache_path_patch(self, tmp_path):
        """Test CDN cache path generation for patch files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcd1234ef567890"
        path = cache._get_cdn_cache_path(hash_str, "patch", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "patch" / "ab" / "cd" / "abcd1234ef567890"
        assert path == expected

    def test_get_cdn_cache_path_patch_index(self, tmp_path):
        """Test CDN cache path generation for patch index files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "9876543210fedcba"
        path = cache._get_cdn_cache_path(hash_str, "patch_index", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "patch" / "98" / "76" / "9876543210fedcba.index"
        assert path == expected

    def test_get_cdn_cache_path_uppercase_hash(self, tmp_path):
        """Test CDN cache path generation converts uppercase hash to lowercase."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "ABCDEF1234567890"
        path = cache._get_cdn_cache_path(hash_str, "config", "tpr/wow")

        expected = tmp_path / "cdn" / "tpr" / "wow" / "config" / "ab" / "cd" / "abcdef1234567890"
        assert path == expected

    def test_get_api_cache_path(self, tmp_path):
        """Test API cache path generation."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        path = cache._get_api_cache_path(key)

        expected = tmp_path / "api" / "tact_us_wow_versions.cache"
        assert path == expected

    def test_get_api_cache_path_special_chars(self, tmp_path):
        """Test API cache path generation with special characters."""
        cache = DiskCache(base_dir=tmp_path)

        key = "complex/key:with:slashes"
        path = cache._get_api_cache_path(key)

        expected = tmp_path / "api" / "complex_key_with_slashes.cache"
        assert path == expected

    def test_put_cdn_and_get_cdn(self, tmp_path):
        """Test storing and retrieving CDN data."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data = b"test data content"
        file_type = "config"
        cdn_path = "tpr/wow"

        # Store data
        cache.put_cdn(hash_str, data, file_type, cdn_path)

        # Verify cache path exists
        cache_path = cache._get_cdn_cache_path(hash_str, file_type, cdn_path)
        assert cache_path.exists()

        # Retrieve data
        retrieved = cache.get_cdn(hash_str, file_type, cdn_path)
        assert retrieved == data

    def test_put_cdn_atomic_write(self, tmp_path):
        """Test that CDN writes are atomic using temporary files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data = b"test data content"
        file_type = "data"
        cdn_path = "tpr/wow"

        cache_path = cache._get_cdn_cache_path(hash_str, file_type, cdn_path)
        temp_path = cache_path.with_suffix(".tmp")

        # Before writing, neither file should exist
        assert not cache_path.exists()
        assert not temp_path.exists()

        cache.put_cdn(hash_str, data, file_type, cdn_path)

        # After writing, only final file should exist
        assert cache_path.exists()
        assert not temp_path.exists()

    def test_has_cdn_file_exists(self, tmp_path):
        """Test has_cdn returns True for existing valid files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data = b"test data"
        file_type = "config"
        cdn_path = "tpr/wow"

        cache.put_cdn(hash_str, data, file_type, cdn_path)
        assert cache.has_cdn(hash_str, file_type, cdn_path) is True

    def test_has_cdn_file_not_exists(self, tmp_path):
        """Test has_cdn returns False for non-existent files."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "nonexistent123"
        file_type = "config"
        cdn_path = "tpr/wow"

        assert cache.has_cdn(hash_str, file_type, cdn_path) is False

    def test_has_cdn_file_expired(self, tmp_path):
        """Test has_cdn returns True even for old CDN files (CDN content never expires)."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data = b"test data"
        file_type = "config"
        cdn_path = "tpr/wow"

        # Store file
        cache.put_cdn(hash_str, data, file_type, cdn_path)

        # Modify file timestamp to make it older than 24 hours
        cache_path = cache._get_cdn_cache_path(hash_str, file_type, cdn_path)
        old_time = time.time() - (25 * 60 * 60)  # 25 hours ago
        os.utime(cache_path, (old_time, old_time))

        # CDN content never expires, so this should still be True
        assert cache.has_cdn(hash_str, file_type, cdn_path) is True

    def test_get_cdn_expired_file(self, tmp_path):
        """Test get_cdn still returns data for old CDN files (CDN content never expires)."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data = b"test data"
        file_type = "config"
        cdn_path = "tpr/wow"

        cache.put_cdn(hash_str, data, file_type, cdn_path)

        # Make file old (older than 24 hours)
        cache_path = cache._get_cdn_cache_path(hash_str, file_type, cdn_path)
        old_time = time.time() - (25 * 60 * 60)
        os.utime(cache_path, (old_time, old_time))

        # CDN content never expires, so data should still be returned
        assert cache.get_cdn(hash_str, file_type, cdn_path) == data

    def test_put_api_and_get_api(self, tmp_path):
        """Test storing and retrieving API data."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        data = "test api response content"

        # Store data
        cache.put_api(key, data)

        # Verify cache path exists
        cache_path = cache._get_api_cache_path(key)
        assert cache_path.exists()

        # Retrieve data
        retrieved = cache.get_api(key)
        assert retrieved == data

    def test_put_api_atomic_write(self, tmp_path):
        """Test that API writes are atomic using temporary files."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        data = "test api response"

        cache_path = cache._get_api_cache_path(key)
        temp_path = cache_path.with_suffix(".tmp")

        # Before writing, neither file should exist
        assert not cache_path.exists()
        assert not temp_path.exists()

        cache.put_api(key, data)

        # After writing, only final file should exist
        assert cache_path.exists()
        assert not temp_path.exists()

    def test_has_api_file_exists(self, tmp_path):
        """Test has_api returns True for existing valid files."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        data = "test api response"

        cache.put_api(key, data)
        assert cache.has_api(key) is True

    def test_has_api_file_not_exists(self, tmp_path):
        """Test has_api returns False for non-existent files."""
        cache = DiskCache(base_dir=tmp_path)

        key = "nonexistent:key"
        assert cache.has_api(key) is False

    def test_has_api_file_expired(self, tmp_path):
        """Test has_api returns False for expired files."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        data = "test api response"

        # Store file
        cache.put_api(key, data)

        # Modify file timestamp to make it older than 24 hours
        cache_path = cache._get_api_cache_path(key)
        old_time = time.time() - (25 * 60 * 60)  # 25 hours ago
        os.utime(cache_path, (old_time, old_time))

        assert cache.has_api(key) is False

    def test_get_api_expired_file(self, tmp_path):
        """Test get_api returns None for expired files."""
        cache = DiskCache(base_dir=tmp_path)

        key = "tact:us:wow:versions"
        data = "test api response"

        cache.put_api(key, data)

        # Make file expired
        cache_path = cache._get_api_cache_path(key)
        old_time = time.time() - (25 * 60 * 60)
        os.utime(cache_path, (old_time, old_time))

        assert cache.get_api(key) is None

    def test_clear_expired_removes_old_files(self, tmp_path):
        """Test clear_expired only removes old API files, not CDN files."""
        cache = DiskCache(base_dir=tmp_path)

        # Store some files
        cache.put_cdn("hash1", b"data1", "config", "tpr/wow")
        cache.put_cdn("hash2", b"data2", "data", "tpr/wow")
        cache.put_api("key1", "response1")
        cache.put_api("key2", "response2")

        # Make some files old
        old_time = time.time() - (25 * 60 * 60)

        path1 = cache._get_cdn_cache_path("hash1", "config", "tpr/wow")
        os.utime(path1, (old_time, old_time))

        path3 = cache._get_api_cache_path("key1")
        os.utime(path3, (old_time, old_time))

        # Clear expired
        removed = cache.clear_expired()

        # Should only remove 1 file (the expired API file)
        assert removed == 1

        # Verify only the old API file was removed
        assert path1.exists()  # CDN file should still exist (never expires)
        assert not path3.exists()  # Old API file should be removed

        # Verify other files still exist
        path2 = cache._get_cdn_cache_path("hash2", "data", "tpr/wow")
        path4 = cache._get_api_cache_path("key2")
        assert path2.exists()
        assert path4.exists()

    def test_clear_expired_no_files(self, tmp_path):
        """Test clear_expired returns 0 when no files to remove."""
        cache = DiskCache(base_dir=tmp_path)
        removed = cache.clear_expired()
        assert removed == 0

    def test_ttl_exactly_24_hours(self, tmp_path):
        """Test that API files expire at exactly 24 hours, but CDN files never expire."""
        cache = DiskCache(base_dir=tmp_path)

        # Test API cache with 24-hour TTL
        api_key = "test:api:key"
        api_data = "test api response"

        cache.put_api(api_key, api_data)

        # Set API file time to exactly 24 hours ago (minus 1 second to be safe)
        api_path = cache._get_api_cache_path(api_key)
        exactly_24h = time.time() - (24 * 60 * 60) + 1  # 1 second less than 24 hours
        os.utime(api_path, (exactly_24h, exactly_24h))

        # Should still be valid at almost 24 hours
        assert cache.has_api(api_key) is True

        # Set file time to exactly 24 hours + 1 second ago
        over_24h = time.time() - (24 * 60 * 60) - 1  # 1 second more than 24 hours
        os.utime(api_path, (over_24h, over_24h))

        # Should be expired
        assert cache.has_api(api_key) is False

        # Test CDN cache never expires
        hash_str = "abcdef1234567890"
        cdn_data = b"test cdn data"
        cache.put_cdn(hash_str, cdn_data, "config", "tpr/wow")

        # Set CDN file to very old time
        cdn_path = cache._get_cdn_cache_path(hash_str, "config", "tpr/wow")
        very_old = time.time() - (365 * 24 * 60 * 60)  # 1 year ago
        os.utime(cdn_path, (very_old, very_old))

        # CDN content never expires
        assert cache.has_cdn(hash_str, "config", "tpr/wow") is True

    def test_different_cdn_paths_separate_caches(self, tmp_path):
        """Test that different CDN paths create separate cache entries."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        data1 = b"data for path1"
        data2 = b"data for path2"
        file_type = "config"

        # Store same hash under different CDN paths
        cache.put_cdn(hash_str, data1, file_type, "tpr/wow")
        cache.put_cdn(hash_str, data2, file_type, "tpr/wow_classic")

        # Verify both exist and return correct data
        assert cache.get_cdn(hash_str, file_type, "tpr/wow") == data1
        assert cache.get_cdn(hash_str, file_type, "tpr/wow_classic") == data2

    def test_metadata_file_creation(self, tmp_path):
        """Test that metadata file is created and updated."""
        cache = DiskCache(base_dir=tmp_path)

        # Initially should exist (created on init)
        assert cache.metadata_file.exists()

        # Store some data
        cache.put_cdn("hash1", b"data1", "config", "tpr/wow")
        cache.put_api("key1", "response1")

        # Metadata should still exist and be valid JSON
        assert cache.metadata_file.exists()

        # Should be able to read metadata
        import json
        with open(cache.metadata_file) as f:
            metadata = json.load(f)

        assert isinstance(metadata, dict)
        assert "last_updated" in metadata
        assert "statistics" in metadata

    def test_concurrent_access_safety(self, tmp_path):
        """Test that cache is safe for concurrent access via atomic writes."""
        cache = DiskCache(base_dir=tmp_path)

        hash_str = "abcdef1234567890"
        file_type = "config"
        cdn_path = "tpr/wow"

        # First write
        cache.put_cdn(hash_str, b"first data", file_type, cdn_path)
        assert cache.get_cdn(hash_str, file_type, cdn_path) == b"first data"

        # Second write (overwrite)
        cache.put_cdn(hash_str, b"second data", file_type, cdn_path)
        assert cache.get_cdn(hash_str, file_type, cdn_path) == b"second data"

        # Should never have partial data or corruption
        cache_path = cache._get_cdn_cache_path(hash_str, file_type, cdn_path)
        with open(cache_path, "rb") as f:
            content = f.read()
        assert content == b"second data"
