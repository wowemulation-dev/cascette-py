"""Tests for wago.py pure utility functions."""

from datetime import UTC, datetime

import pytest

from cascette_tools.database.wago import (
    WagoBuild,
    WagoCacheMetadata,
    adapt_datetime_iso,
    convert_datetime_iso,
)


class TestAdaptDatetimeIso:
    """Tests for adapt_datetime_iso function."""

    def test_naive_datetime_assumes_utc(self) -> None:
        dt = datetime(2024, 1, 1, 0)
        result = adapt_datetime_iso(dt)
        assert "2024-01-01" in result
        assert "+00:00" in result

    def test_timezone_aware_datetime_preserves_utc(self) -> None:
        dt = datetime(2024, 1, 1, 12, 30, 45, tzinfo=UTC)
        result = adapt_datetime_iso(dt)
        assert "2024-01-01" in result
        assert "12:30:45" in result

    def test_returns_string(self) -> None:
        dt = datetime(2024, 6, 15, 10, 20, 30)
        result = adapt_datetime_iso(dt)
        assert isinstance(result, str)


class TestConvertDatetimeIso:
    """Tests for convert_datetime_iso function."""

    def test_valid_iso_string(self) -> None:
        result = convert_datetime_iso(b"2024-01-01T00:00:00+00:00")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1
        assert result.tzinfo == UTC

    def test_z_suffix(self) -> None:
        result = convert_datetime_iso(b"2024-01-01T12:00:00Z")
        assert result.hour == 12
        assert result.tzinfo == UTC

    def test_naive_string_gets_utc(self) -> None:
        result = convert_datetime_iso(b"2024-06-15T10:30:00")
        assert result.month == 6
        assert result.tzinfo == UTC

    def test_malformed_string_raises(self) -> None:
        with pytest.raises(ValueError):
            convert_datetime_iso(b"not a valid ISO string")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            convert_datetime_iso(b"")


class TestWagoBuild:
    """Tests for WagoBuild model."""

    def test_model_creation_minimal(self) -> None:
        build = WagoBuild(
            id=1,
            build="12345",
            version="1.2.3.45678",
            product="wow",
        )
        assert build.id == 1
        assert build.build == "12345"
        assert build.version == "1.2.3.45678"
        assert build.product == "wow"
        assert build.build_config is None
        assert build.cdn_config is None
        assert build.build_time is None

    def test_model_creation_full(self) -> None:
        now = datetime(2024, 1, 1, 0, tzinfo=UTC)
        build = WagoBuild(
            id=2,
            build="54321",
            version="2.0.0.45678",
            product="wow_classic",
            build_config="abc123def",
            cdn_config="def789ghi",
            product_config="prod123",
            build_time=now,
            encoding_ekey="enc123",
            root_ekey="root456",
            install_ekey="inst789",
            download_ekey="down012",
        )
        assert build.id == 2
        assert build.product == "wow_classic"
        assert build.build_config == "abc123def"
        assert build.cdn_config == "def789ghi"
        assert build.product_config == "prod123"
        assert build.build_time == now
        assert build.encoding_ekey == "enc123"
        assert build.root_ekey == "root456"
        assert build.install_ekey == "inst789"
        assert build.download_ekey == "down012"


class TestWagoCacheMetadata:
    """Tests for WagoCacheMetadata model."""

    def test_model_creation(self) -> None:
        now = datetime(2024, 1, 1, 0, tzinfo=UTC)
        later = datetime(2024, 1, 2, 0, tzinfo=UTC)
        meta = WagoCacheMetadata(
            fetch_time=now,
            expires_at=later,
            build_count=100,
        )
        assert meta.fetch_time == now
        assert meta.expires_at == later
        assert meta.build_count == 100
        assert meta.api_version == "v1"

    def test_model_with_custom_api_version(self) -> None:
        now = datetime(2024, 1, 1, 0, tzinfo=UTC)
        later = datetime(2024, 1, 2, 0, tzinfo=UTC)
        meta = WagoCacheMetadata(
            fetch_time=now,
            expires_at=later,
            build_count=50,
            api_version="v2",
        )
        assert meta.api_version == "v2"
