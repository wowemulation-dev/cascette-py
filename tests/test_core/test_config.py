"""Tests for config.py module."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cascette_tools.core.config import AppConfig, CacheConfig, CDNConfig, TACTConfig


class TestCacheConfig:
    """Test CacheConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CacheConfig()

        expected_dir = Path.home() / ".cache" / "cascette"
        assert config.cache_dir == expected_dir
        assert config.ttl == 86400  # 24 hours
        assert config.max_size == 10 * 1024 * 1024 * 1024  # 10GB
        assert config.enabled is True

    def test_custom_values(self):
        """Test custom configuration values."""
        custom_dir = Path("/tmp/custom_cache")
        config = CacheConfig(
            cache_dir=custom_dir,
            ttl=3600,  # 1 hour
            max_size=1024 * 1024,  # 1MB
            enabled=False
        )

        assert config.cache_dir == custom_dir
        assert config.ttl == 3600
        assert config.max_size == 1024 * 1024
        assert config.enabled is False

    def test_ttl_validation(self):
        """Test TTL validation."""
        # Valid TTL values
        CacheConfig(ttl=0)  # No TTL (should work)
        CacheConfig(ttl=3600)  # 1 hour
        CacheConfig(ttl=86400 * 7)  # 1 week

        # Invalid TTL values
        with pytest.raises(ValueError):
            CacheConfig(ttl=-1)

    def test_max_size_validation(self):
        """Test max size validation."""
        # Valid sizes
        CacheConfig(max_size=0)  # No limit
        CacheConfig(max_size=1024)  # 1KB

        # Invalid sizes
        with pytest.raises(ValueError):
            CacheConfig(max_size=-1)


class TestCDNConfig:
    """Test CDNConfig class."""

    def test_default_mirrors(self):
        """Test default mirror configuration."""
        config = CDNConfig()

        expected_mirrors = [
            "https://cdn.arctium.tools",
            "https://casc.wago.tools",
            "https://archive.wow.tools",
        ]
        assert config.mirrors == expected_mirrors
        assert config.timeout == 30.0
        assert config.max_retries == 3
        assert config.verify_ssl is True

    def test_custom_mirrors(self):
        """Test custom mirror configuration."""
        custom_mirrors = ["https://custom.mirror.com", "https://backup.mirror.com"]
        config = CDNConfig(
            mirrors=custom_mirrors,
            timeout=60.0,
            max_retries=5,
            verify_ssl=False
        )

        assert config.mirrors == custom_mirrors
        assert config.timeout == 60.0
        assert config.max_retries == 5
        assert config.verify_ssl is False

    def test_base_url_property(self):
        """Test base_url property returns primary mirror."""
        config = CDNConfig()
        assert config.base_url == "https://cdn.arctium.tools/tpr/wow/"

        # Test with custom mirrors
        custom_mirrors = ["https://custom.mirror.com"]
        config = CDNConfig(mirrors=custom_mirrors)
        assert config.base_url == "https://custom.mirror.com/tpr/wow/"

    def test_timeout_validation(self):
        """Test timeout validation."""
        # Valid timeouts
        CDNConfig(timeout=1.0)
        CDNConfig(timeout=30.0)
        CDNConfig(timeout=300.0)

        # Invalid timeouts
        with pytest.raises(ValueError):
            CDNConfig(timeout=0)
        with pytest.raises(ValueError):
            CDNConfig(timeout=-1.0)

    def test_max_retries_validation(self):
        """Test max retries validation."""
        # Valid retry counts
        CDNConfig(max_retries=0)  # No retries
        CDNConfig(max_retries=1)
        CDNConfig(max_retries=10)

        # Invalid retry counts
        with pytest.raises(ValueError):
            CDNConfig(max_retries=-1)

    def test_empty_mirrors_validation(self):
        """Test that empty mirrors list is invalid."""
        with pytest.raises(ValueError):
            CDNConfig(mirrors=[])


class TestTACTConfig:
    """Test TACTConfig class."""

    def test_default_values(self):
        """Test default TACT configuration."""
        config = TACTConfig()

        assert config.timeout == 30.0
        assert config.max_retries == 3
        assert config.verify_ssl is True
        assert config.regions == ["us", "eu", "kr", "tw", "cn", "sg"]

    def test_custom_values(self):
        """Test custom TACT configuration."""
        config = TACTConfig(
            timeout=60.0,
            max_retries=5,
            verify_ssl=False,
            regions=["us", "eu"]
        )

        assert config.timeout == 60.0
        assert config.max_retries == 5
        assert config.verify_ssl is False
        assert config.regions == ["us", "eu"]

    def test_get_base_url(self):
        """Test base URL generation for regions."""
        config = TACTConfig()

        assert config.get_base_url("us") == "https://us.version.battle.net"
        assert config.get_base_url("eu") == "https://eu.version.battle.net"
        assert config.get_base_url("kr") == "https://kr.version.battle.net"

    def test_timeout_validation(self):
        """Test timeout validation."""
        # Valid timeouts
        TACTConfig(timeout=1.0)
        TACTConfig(timeout=30.0)

        # Invalid timeouts
        with pytest.raises(ValueError):
            TACTConfig(timeout=0)
        with pytest.raises(ValueError):
            TACTConfig(timeout=-1.0)

    def test_regions_validation(self):
        """Test regions validation."""
        # Valid regions
        TACTConfig(regions=["us"])
        TACTConfig(regions=["us", "eu", "kr"])

        # Invalid regions
        with pytest.raises(ValueError):
            TACTConfig(regions=[])
        with pytest.raises(ValueError):
            TACTConfig(regions=["invalid"])


class TestAppConfig:
    """Test AppConfig class."""

    def test_default_values(self):
        """Test default application configuration."""
        config = AppConfig()

        expected_config_dir = Path.home() / ".config" / "cascette-tools"
        expected_data_dir = Path.home() / ".local" / "share" / "cascette-tools"

        assert config.config_dir == expected_config_dir
        assert config.data_dir == expected_data_dir
        assert config.cdn_base_url == "https://cdn.arctium.tools/tpr/wow/"
        assert config.cdn_timeout == 30.0
        assert config.cdn_max_retries == 3
        assert config.cache_enabled is True
        assert config.cache_max_size == 10 * 1024 * 1024 * 1024  # 10GB
        assert config.cache_ttl == 86400 * 7  # 1 week
        assert config.output_format == "rich"
        assert config.log_level == "INFO"

    def test_custom_values(self):
        """Test custom application configuration."""
        custom_config_dir = Path("/tmp/config")
        custom_data_dir = Path("/tmp/data")

        config = AppConfig(
            config_dir=custom_config_dir,
            data_dir=custom_data_dir,
            cdn_base_url="https://custom.cdn.com/",
            cdn_timeout=60.0,
            cdn_max_retries=5,
            cache_enabled=False,
            cache_max_size=1024 * 1024,  # 1MB
            cache_ttl=3600,  # 1 hour
            output_format="json",
            log_level="DEBUG"
        )

        assert config.config_dir == custom_config_dir
        assert config.data_dir == custom_data_dir
        assert config.cdn_base_url == "https://custom.cdn.com/"
        assert config.cdn_timeout == 60.0
        assert config.cdn_max_retries == 5
        assert config.cache_enabled is False
        assert config.cache_max_size == 1024 * 1024
        assert config.cache_ttl == 3600
        assert config.output_format == "json"
        assert config.log_level == "DEBUG"

    @patch("pathlib.Path.mkdir")
    def test_directories_created_on_init(self, mock_mkdir):
        """Test that directories are created during initialization."""
        _ = AppConfig()

        # Should be called twice - once for config_dir, once for data_dir
        assert mock_mkdir.call_count == 2

        # Verify mkdir was called with the right arguments
        calls = mock_mkdir.call_args_list
        assert all(call.kwargs == {"parents": True, "exist_ok": True} for call in calls)

    def test_load_config_file_exists(self, tmp_path):
        """Test loading configuration from existing file."""
        config_file = tmp_path / "config.json"
        config_data = {
            "cdn_timeout": 60.0,
            "cache_enabled": False,
            "log_level": "DEBUG"
        }

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        config = AppConfig.load(config_file)

        assert config.cdn_timeout == 60.0
        assert config.cache_enabled is False
        assert config.log_level == "DEBUG"
        # Other fields should have defaults
        assert config.cdn_max_retries == 3

    def test_load_config_file_not_exists(self, tmp_path):
        """Test loading configuration when file doesn't exist."""
        config_file = tmp_path / "nonexistent.json"

        config = AppConfig.load(config_file)

        # Should return defaults
        assert config.cdn_timeout == 30.0
        assert config.cache_enabled is True
        assert config.log_level == "INFO"

    def test_load_config_no_file_specified(self):
        """Test loading configuration with no file specified."""
        with patch("pathlib.Path.exists", return_value=False):
            config = AppConfig.load()

            # Should return defaults
            assert config.cdn_timeout == 30.0
            assert config.cache_enabled is True

    def test_load_config_invalid_json(self, tmp_path):
        """Test loading configuration with invalid JSON."""
        config_file = tmp_path / "invalid.json"

        with open(config_file, "w") as f:
            f.write("invalid json content")

        with pytest.raises(json.JSONDecodeError):
            AppConfig.load(config_file)

    def test_save_config(self, tmp_path):
        """Test saving configuration to file."""
        config = AppConfig(
            cdn_timeout=60.0,
            cache_enabled=False,
            log_level="DEBUG"
        )

        config_file = tmp_path / "config.json"
        config.save(config_file)

        assert config_file.exists()

        # Verify saved content
        with open(config_file) as f:
            saved_data = json.load(f)

        assert saved_data["cdn_timeout"] == 60.0
        assert saved_data["cache_enabled"] is False
        assert saved_data["log_level"] == "DEBUG"

    def test_save_config_no_file_specified(self, tmp_path):
        """Test saving configuration with no file specified."""
        config_dir = tmp_path / "config"
        config = AppConfig(config_dir=config_dir)

        config.save()

        expected_file = config_dir / "config.json"
        assert expected_file.exists()

    def test_save_config_creates_directory(self, tmp_path):
        """Test that save creates parent directory if it doesn't exist."""
        config = AppConfig()
        config_file = tmp_path / "nested" / "config.json"

        config.save(config_file)

        assert config_file.exists()
        assert config_file.parent.exists()

    def test_output_format_validation(self):
        """Test output format validation."""
        # Valid formats
        AppConfig(output_format="rich")
        AppConfig(output_format="json")
        AppConfig(output_format="yaml")
        AppConfig(output_format="table")

        # Invalid format
        with pytest.raises(ValueError):
            AppConfig(output_format="invalid")

    def test_log_level_validation(self):
        """Test log level validation."""
        # Valid levels
        AppConfig(log_level="DEBUG")
        AppConfig(log_level="INFO")
        AppConfig(log_level="WARNING")
        AppConfig(log_level="ERROR")
        AppConfig(log_level="CRITICAL")

        # Invalid level
        with pytest.raises(ValueError):
            AppConfig(log_level="INVALID")

    def test_cdn_timeout_validation(self):
        """Test CDN timeout validation."""
        # Valid timeouts
        AppConfig(cdn_timeout=1.0)
        AppConfig(cdn_timeout=30.0)

        # Invalid timeouts
        with pytest.raises(ValueError):
            AppConfig(cdn_timeout=0)
        with pytest.raises(ValueError):
            AppConfig(cdn_timeout=-1.0)

    def test_cache_ttl_validation(self):
        """Test cache TTL validation."""
        # Valid TTL values
        AppConfig(cache_ttl=0)  # No TTL
        AppConfig(cache_ttl=3600)  # 1 hour

        # Invalid TTL
        with pytest.raises(ValueError):
            AppConfig(cache_ttl=-1)

    def test_cache_max_size_validation(self):
        """Test cache max size validation."""
        # Valid sizes
        AppConfig(cache_max_size=0)  # No limit
        AppConfig(cache_max_size=1024)  # 1KB

        # Invalid size
        with pytest.raises(ValueError):
            AppConfig(cache_max_size=-1)
