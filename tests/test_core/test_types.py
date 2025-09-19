"""Tests for cascette_tools.core.types module."""

import pytest
from pydantic import ValidationError

from cascette_tools.core.types import (
    BuildInfo,
    CDNConfig,
    CompressionMode,
    EncryptionType,
    FileDataId,
    Product,
    TACTKey,
)


class TestCompressionMode:
    """Tests for CompressionMode enum."""

    def test_compression_mode_values(self) -> None:
        """Test CompressionMode enum values."""
        assert CompressionMode.NONE == "N"
        assert CompressionMode.ZLIB == "Z"
        assert CompressionMode.LZ4 == "L"


class TestEncryptionType:
    """Tests for EncryptionType enum."""

    def test_encryption_mode_values(self) -> None:
        """Test EncryptionType enum values."""
        assert EncryptionType.SALSA20.value == 0x53
        assert EncryptionType.ARC4.value == 0x41


class TestProduct:
    """Tests for Product enum."""

    def test_product_values(self) -> None:
        """Test Product enum contains expected values."""
        assert Product.WOW == "wow"
        assert Product.WOW_CLASSIC == "wow_classic"
        assert Product.WOW_CLASSIC_ERA == "wow_classic_era"
        assert Product.DIABLO_4 == "fenris"
        assert Product.OVERWATCH_2 == "pro"


class TestBuildInfo:
    """Tests for BuildInfo model."""

    def test_build_info_creation(self, sample_build_info: BuildInfo) -> None:
        """Test BuildInfo creation with valid data."""
        assert sample_build_info.build_config == "1234567890abcdef1234567890abcdef12345678"
        assert sample_build_info.cdn_config == "abcdef1234567890abcdef1234567890abcdef12"
        assert sample_build_info.build_id == 12345
        assert sample_build_info.version_name == "1.15.0.54630"

    def test_build_info_required_fields(self) -> None:
        """Test BuildInfo validation with missing required fields."""
        with pytest.raises(ValidationError):
            BuildInfo()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            BuildInfo(build_config="abc123")  # type: ignore[call-arg]  # Missing cdn_config

    def test_build_info_optional_fields(self) -> None:
        """Test BuildInfo with only required fields."""
        build_info = BuildInfo(
            build_config="1234567890abcdef1234567890abcdef12345678",
            cdn_config="abcdef1234567890abcdef1234567890abcdef12"
        )  # type: ignore[call-arg]
        assert build_info.keyring is None
        assert build_info.build_id is None
        assert build_info.version_name is None


class TestFileDataId:
    """Tests for FileDataId model."""

    def test_file_data_id_creation(self) -> None:
        """Test FileDataId creation."""
        fdid = FileDataId(id=123456, filename="Interface\\AddOns\\Blizzard_UIParent\\UIParent.lua")  # type: ignore[call-arg]
        assert fdid.id == 123456
        assert fdid.filename == "Interface\\AddOns\\Blizzard_UIParent\\UIParent.lua"
        assert fdid.content_key is None

    def test_file_data_id_required_id(self) -> None:
        """Test FileDataId requires ID."""
        with pytest.raises(ValidationError):
            FileDataId()  # type: ignore[call-arg]


class TestCDNConfig:
    """Tests for CDNConfig model."""

    def test_cdn_config_creation(self) -> None:
        """Test CDNConfig creation."""
        config = CDNConfig(
            archives=["abc123", "def456"],
            archive_group="group1",
            builds=["build1", "build2"]
        )  # type: ignore[call-arg]
        assert config.archives == ["abc123", "def456"]
        assert config.archive_group == "group1"
        assert config.builds == ["build1", "build2"]

    def test_cdn_config_defaults(self) -> None:
        """Test CDNConfig with default values."""
        config = CDNConfig()  # type: ignore[call-arg]
        assert config.archives == []
        assert config.archive_group is None
        assert config.patch_archives == []


class TestTACTKey:
    """Tests for TACTKey model."""

    def test_tact_key_creation(self) -> None:
        """Test TACTKey creation."""
        key = TACTKey(
            key_name="0x123456",
            key_value="abcdef1234567890abcdef1234567890abcdef12",
            lookup="lookup_value"
        )  # type: ignore[call-arg]
        assert key.key_name == "0x123456"
        assert key.key_value == "abcdef1234567890abcdef1234567890abcdef12"
        assert key.lookup == "lookup_value"

    def test_tact_key_required_fields(self) -> None:
        """Test TACTKey validation with missing fields."""
        with pytest.raises(ValidationError):
            TACTKey()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            TACTKey(key_name="test")  # type: ignore[call-arg]  # Missing key_value and lookup
