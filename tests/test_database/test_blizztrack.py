"""Tests for cascette_tools.database.blizztrack module."""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from cascette_tools.core.config import AppConfig
from cascette_tools.database.blizztrack import (
    BLIZZTRACK_PRODUCTS,
    BlizzTrackClient,
    _stable_id,
)


class TestStableId:
    """Test _stable_id function."""

    def test_stable_id_deterministic(self):
        result1 = _stable_id("abc123", "wow")
        result2 = _stable_id("abc123", "wow")
        assert result1 == result2

    def test_stable_id_different_config(self):
        result1 = _stable_id("abc123", "wow")
        result2 = _stable_id("def456", "wow")
        assert result1 != result2

    def test_stable_id_different_product(self):
        result1 = _stable_id("abc123", "wow")
        result2 = _stable_id("abc123", "wow_classic")
        assert result1 != result2

    def test_stable_id_returns_int(self):
        result = _stable_id("abc123", "wow")
        assert isinstance(result, int)


class TestBlizzTrackProducts:
    """Test BLIZZTRACK_PRODUCTS constant."""

    def test_contains_expected_products(self):
        assert "agent" in BLIZZTRACK_PRODUCTS
        assert "bna" in BLIZZTRACK_PRODUCTS
        assert "wow" in BLIZZTRACK_PRODUCTS
        assert "wow_classic" in BLIZZTRACK_PRODUCTS
        assert "wow_classic_era" in BLIZZTRACK_PRODUCTS

    def test_excludes_bts(self):
        assert "bts" not in BLIZZTRACK_PRODUCTS


class TestBlizzTrackClient:
    """Test BlizzTrackClient class."""

    @pytest.fixture
    def temp_config(self, tmp_path):
        config = AppConfig()
        config.data_dir = tmp_path / "test_data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        return config

    @pytest.fixture
    def mock_versions_response(self):
        return {
            "success": True,
            "result": {
                "seqn": 1234567,
                "tact": "wow",
                "type": "versions",
                "created_at": "2024-01-15T10:30:00Z",
                "data": [
                    {
                        "name": "Americas",
                        "build_config": "abc123def456789",
                        "build_id": 12345,
                        "cdn_config": "fed456cba789012",
                        "region": "us",
                        "version_name": "10.2.5.52902",
                        "product_config": "123fed456abc789",
                    },
                    {
                        "name": "Europe",
                        "build_config": "abc123def456789",
                        "build_id": 12345,
                        "cdn_config": "fed456cba789012",
                        "region": "eu",
                        "version_name": "10.2.5.52902",
                        "product_config": "123fed456abc789",
                    },
                ],
            },
        }

    @pytest.fixture
    def mock_seqn_history_response(self):
        return {
            "success": True,
            "result": {
                "total": 2,
                "total_pages": 1,
                "results": [
                    {"seqn": 1234567, "created_at": "2024-01-15T10:30:00Z"},
                    {"seqn": 1234566, "created_at": "2024-01-14T10:30:00Z"},
                ],
            },
        }

    def test_init_default_config(self):
        with BlizzTrackClient() as client:
            assert client.config is not None

    def test_init_custom_config(self, temp_config):
        with BlizzTrackClient(temp_config) as client:
            assert client.config == temp_config

    def test_client_lazy_initialization(self, temp_config):
        client = BlizzTrackClient(temp_config)
        assert client._client is None

        http_client = client.client
        assert http_client is not None
        assert client._client is http_client

    def test_client_reuse(self, temp_config):
        with BlizzTrackClient(temp_config) as client:
            client1 = client.client
            client2 = client.client
            assert client1 is client2

    @patch("httpx.Client.get")
    def test_get_versions_success(self, mock_get, temp_config, mock_versions_response):
        mock_response = Mock()
        mock_response.json.return_value = mock_versions_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with BlizzTrackClient(temp_config) as client:
            entries = client._get_versions("wow")

        assert len(entries) == 2
        assert entries[0]["build_config"] == "abc123def456789"

    @patch("httpx.Client.get")
    def test_get_versions_api_error(self, mock_get, temp_config):
        mock_response = Mock()
        mock_response.json.return_value = {
            "success": False,
            "result": {"code": 404, "message": "Not found"},
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with BlizzTrackClient(temp_config) as client:
            with pytest.raises(ValueError, match="BlizzTrack API error"):
                client._get_versions("invalid_product")

    @patch("httpx.Client.get")
    def test_get_seqn_history_success(
        self, mock_get, temp_config, mock_seqn_history_response
    ):
        mock_response = Mock()
        mock_response.json.return_value = mock_seqn_history_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with BlizzTrackClient(temp_config) as client:
            result = client._get_seqn_history("wow", file="versions", page=1)

        assert result["total"] == 2
        assert len(result["results"]) == 2

    @patch("httpx.Client.get")
    def test_get_versions_at_seqn_success(
        self, mock_get, temp_config, mock_versions_response
    ):
        mock_response = Mock()
        mock_response.json.return_value = mock_versions_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with BlizzTrackClient(temp_config) as client:
            entries = client._get_versions_at_seqn("wow", 1234567)

        assert len(entries) == 2

    @patch("httpx.Client.get")
    def test_get_versions_at_seqn_failure(self, mock_get, temp_config):
        mock_response = Mock()
        mock_response.json.return_value = {"success": False}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with BlizzTrackClient(temp_config) as client:
            entries = client._get_versions_at_seqn("wow", 1234567)

        assert entries == []

    def test_entries_to_builds_deduplication(self, temp_config):
        entries = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "cdn_config": "def456",
                "version_name": "10.2.5.52902",
                "product_config": "ghi789",
            },
            {
                "build_config": "abc123",
                "build_id": 12345,
                "cdn_config": "def456",
                "version_name": "10.2.5.52902",
                "product_config": "ghi789",
            },
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client._entries_to_builds(entries, "wow")

        assert len(builds) == 1
        assert builds[0].build_config == "abc123"

    def test_entries_to_builds_empty_config_skipped(self, temp_config):
        entries = [
            {
                "build_config": "",
                "build_id": 12345,
                "version_name": "10.2.5.52902",
            },
            {
                "build_config": "abc123",
                "build_id": 12346,
                "version_name": "10.2.5.52903",
            },
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client._entries_to_builds(entries, "wow")

        assert len(builds) == 1
        assert builds[0].build_config == "abc123"

    def test_entries_to_builds_extract_build_num(self, temp_config):
        entries = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "version_name": "10.2.5.52902",
            }
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client._entries_to_builds(entries, "wow")

        assert len(builds) == 1
        assert builds[0].build == "52902"

    def test_entries_to_builds_no_version_name(self, temp_config):
        entries = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "version_name": "",
            }
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client._entries_to_builds(entries, "wow")

        assert len(builds) == 1
        assert builds[0].build == "12345"

    def test_entries_to_builds_with_recorded_at(self, temp_config):
        entries = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "version_name": "10.2.5.52902",
            }
        ]
        recorded_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

        with BlizzTrackClient(temp_config) as client:
            builds = client._entries_to_builds(entries, "wow", recorded_at=recorded_at)

        assert builds[0].build_time == recorded_at

    @patch.object(BlizzTrackClient, "_get_versions")
    def test_fetch_current_success(self, mock_get_versions, temp_config):
        mock_get_versions.return_value = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "cdn_config": "def456",
                "version_name": "10.2.5.52902",
                "product_config": "ghi789",
            }
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client.fetch_current(products=["wow"])

        assert len(builds) >= 1
        assert any(b.product == "wow" for b in builds)

    @patch.object(BlizzTrackClient, "_get_versions")
    def test_fetch_current_handles_errors(self, mock_get_versions, temp_config):
        mock_get_versions.side_effect = Exception("Network error")

        with BlizzTrackClient(temp_config) as client:
            builds = client.fetch_current(products=["wow"])

        assert builds == []

    @patch.object(BlizzTrackClient, "_get_seqn_history")
    @patch.object(BlizzTrackClient, "_get_versions_at_seqn")
    def test_fetch_history_success(
        self,
        mock_get_at_seqn,
        mock_get_history,
        temp_config,
        mock_seqn_history_response,
    ):
        mock_get_history.return_value = mock_seqn_history_response["result"]
        mock_get_at_seqn.return_value = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "cdn_config": "def456",
                "version_name": "10.2.5.52902",
                "product_config": "ghi789",
            }
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client.fetch_history(products=["wow"], max_pages=1, max_workers=1)

        assert len(builds) >= 1

    @patch.object(BlizzTrackClient, "_get_seqn_history")
    def test_fetch_history_handles_errors(self, mock_get_history, temp_config):
        mock_get_history.side_effect = Exception("Network error")

        with BlizzTrackClient(temp_config) as client:
            builds = client.fetch_history(products=["wow"], max_pages=1)

        assert builds == []

    def test_context_manager(self, temp_config):
        with BlizzTrackClient(temp_config) as client:
            assert client is not None
            _ = client.client

    def test_close(self, temp_config):
        client = BlizzTrackClient(temp_config)
        _ = client.client
        client.close()

    def test_close_without_client(self, temp_config):
        client = BlizzTrackClient(temp_config)
        client.close()

    @patch.object(BlizzTrackClient, "_get_versions")
    def test_fetch_current_multiple_products(self, mock_get_versions, temp_config):
        mock_get_versions.return_value = [
            {
                "build_config": "abc123",
                "build_id": 12345,
                "cdn_config": "def456",
                "version_name": "10.2.5.52902",
            }
        ]

        with BlizzTrackClient(temp_config) as client:
            builds = client.fetch_current(products=["wow", "wow_classic"])

        products_found = {b.product for b in builds}
        assert "wow" in products_found
        assert "wow_classic" in products_found

    def test_api_base_constant(self):
        assert BlizzTrackClient.API_BASE == "https://blizztrack.com/api"
