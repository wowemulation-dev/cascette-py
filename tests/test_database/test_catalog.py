"""Tests for cascette_tools.database.catalog."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import Mock

import pytest

from cascette_tools.core.config import AppConfig
from cascette_tools.database.catalog import (
    CACHE_LIFETIME,
    CatalogCacheMetadata,
    CatalogClient,
    parse_build_config_root,
)
from cascette_tools.formats.catalog import CatalogParser

ROOT_FRAGMENT = {
    "categories": {
        "definitions": [
            {"id": "cat_live", "name": "default#CATEGORIES_LIVE_NAME", "rank": 100}
        ]
    },
    "fragment_id": "default",
    "fragments": [
        {"hash": "f553e93cd67f24d1b8158a68d5406edc", "name": "world_of_warcraft"}
    ],
    "version": 30,
}

WOW_FRAGMENT = {
    "fragment_id": "world_of_warcraft",
    "installs": {
        "wow_classic": {"tact_product": "wow_classic", "run_64_bit_only": True},
        "wow": {"tact_product": "wow"},
    },
    "products": [
        {
            "base": {
                "default_product_type": "retail",
                "name": "world_of_warcraft#PRODUCTS_WOW_NAME",
                "program_id": "WoW",
            },
            "id": "WoW",
        }
    ],
    "program_configuration": {
        "WoW": {
            "is_game_account_level": True,
            "run_each_rule": [
                {
                    "actions": [
                        {
                            "add_product": {
                                "product_id": {"id": "WoW", "type": "wow_classic"}
                            }
                        }
                    ],
                    "match": {
                        "game_account": {"program_id": "WoW", "region": ["US", "EU"]}
                    },
                },
                {
                    "actions": [
                        {
                            "add_product": {
                                "product_id": {"id": "WoWX12", "type": "retail"}
                            }
                        }
                    ],
                    "match": {"license_id": [1106089]},
                },
                {
                    "actions": [{"add_tag": {"name": "disable_upgrade"}}],
                    "match": {
                        "all_of": [{"license_id": 179712}, {"license_id": [813186]}]
                    },
                },
            ],
        }
    },
    "version": 30,
}


def _dumps(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@pytest.fixture
def client(tmp_path) -> CatalogClient:
    config = AppConfig()
    config.data_dir = tmp_path / "data"
    config.config_dir = tmp_path / "config"
    config.data_dir.mkdir(parents=True, exist_ok=True)
    return CatalogClient(config)


class TestParseBuildConfigRoot:
    def test_extracts_root(self):
        raw = b"# Build Configuration\n\nroot = c74e2127e1f9b5c0cc2743219434730c\nbuild-version = 30\n"
        assert parse_build_config_root(raw) == "c74e2127e1f9b5c0cc2743219434730c"

    def test_missing_root(self):
        assert (
            parse_build_config_root(b"# Build Configuration\nbuild-version = 30\n")
            is None
        )

    def test_empty(self):
        assert parse_build_config_root(b"") is None


class TestDatabaseImport:
    def test_schema_created(self, client: CatalogClient):
        tables = {
            row[0]
            for row in client.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for expected in (
            "catalog_builds",
            "catalog_fragments",
            "catalog_products",
            "catalog_categories",
            "catalog_types",
            "catalog_programs",
            "catalog_rules",
            "catalog_licenses",
            "catalog_installs",
            "catalog_import_log",
        ):
            assert expected in tables

    def test_import_root_fragment(self, client: CatalogClient):
        parser = CatalogParser()
        fragment = parser.parse(_dumps(ROOT_FRAGMENT))
        client.import_fragment(
            fragment, "c74e2127e1f9b5c0cc2743219434730c", is_root=True
        )

        rows = client.list_fragments()
        assert len(rows) == 1
        assert rows[0]["is_root"] == 1
        assert rows[0]["version"] == 30
        assert rows[0]["fragment_id"] == "default"

        categories = client.conn.execute(
            "SELECT * FROM catalog_categories WHERE fragment_hash = ?",
            ("c74e2127e1f9b5c0cc2743219434730c",),
        ).fetchall()
        assert len(categories) == 1
        assert categories[0]["category_id"] == "cat_live"

    def test_import_product_fragment(self, client: CatalogClient):
        parser = CatalogParser()
        fragment = parser.parse(_dumps(WOW_FRAGMENT))
        client.import_fragment(fragment, "f553e93cd67f24d1b8158a68d5406edc")

        products = client.list_products()
        assert len(products) == 1
        assert products[0]["program_id"] == "WoW"
        assert products[0]["product_id"] == "WoW"

        program = client.get_program("WoW")
        assert program is not None
        assert program["is_game_account_level"] == 1

        rules = client.list_rules("WoW")
        assert len(rules) == 3
        assert rules[0]["rule_seq"] == 0
        match = json.loads(rules[0]["match_json"])
        assert match["game_account"]["region"] == ["US", "EU"]

        licenses = client.list_licenses()
        by_id = {row["license_id"]: row["programs"] for row in licenses}
        assert by_id[1106089] == 1
        assert by_id[179712] == 1

        # license filtered query
        filtered = client.list_licenses(license_id=1106089)
        assert len(filtered) == 1
        assert filtered[0]["program_id"] == "WoW"

        installs = client.list_installs()
        assert len(installs) == 2
        classic = client.list_installs(tact_product="wow_classic")
        assert len(classic) == 1
        assert classic[0]["install_type"] == "wow_classic"

    def test_import_is_idempotent(self, client: CatalogClient):
        parser = CatalogParser()
        fragment = parser.parse(_dumps(WOW_FRAGMENT))
        client.import_fragment(fragment, "f553e93cd67f24d1b8158a68d5406edc")
        client.import_fragment(fragment, "f553e93cd67f24d1b8158a68d5406edc")

        assert len(client.list_products()) == 1
        assert len(client.list_rules("WoW")) == 3
        assert len(client.list_licenses()) == 3

    def test_stats(self, client: CatalogClient):
        parser = CatalogParser()
        client.import_fragment(
            parser.parse(_dumps(ROOT_FRAGMENT)), "root-hash", is_root=True
        )
        client.import_fragment(parser.parse(_dumps(WOW_FRAGMENT)), "wow-hash")

        stats = client.get_stats()
        assert stats["fragments"] == 2
        assert stats["products"] == 1
        assert stats["programs"] == 1
        assert stats["rules"] == 3
        assert stats["licenses"] == 3
        assert stats["installs"] == 2


class TestCache:
    def test_cache_save_and_load(self, client: CatalogClient):
        fragments = {
            "aaa": _dumps(ROOT_FRAGMENT),
            "bbb": _dumps(WOW_FRAGMENT),
        }
        client._save_cache(fragments, build_version=30, build_config="bc123")

        assert client._cache_valid() is True
        metadata, loaded = client._load_cache()
        assert metadata.build_version == 30
        assert metadata.fragment_count == 2
        assert set(loaded) == {"aaa", "bbb"}
        assert loaded["aaa"] == fragments["aaa"]

    def test_cache_expires(self, client: CatalogClient):
        client._save_cache({"aaa": b"{}"}, build_version=30, build_config="bc123")
        metadata_path = client.metadata_file
        with open(metadata_path) as f:
            metadata = CatalogCacheMetadata.model_validate(json.load(f))
        metadata.expires_at = datetime.now(UTC) - timedelta(hours=1)
        with open(metadata_path, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, indent=2, default=str)

        assert client._cache_valid() is False

    def test_no_cache_initially(self, client: CatalogClient):
        assert client._cache_valid() is False

    def test_metadata_expiry_equals_lifetime(self):
        now = datetime.now(UTC)
        metadata = CatalogCacheMetadata(fetch_time=now, expires_at=now + CACHE_LIFETIME)
        assert metadata.expires_at - metadata.fetch_time == CACHE_LIFETIME


class TestSync:
    def _make_tact_client(self):
        tact = Mock()
        tact.fetch_versions.return_value = "## seqn = 1\nRegion|BuildConfig|CDNConfig|BuildId|VersionsName\nPUB-30|bc30|cc30|32|4929\nPUB-23|bc23|cc23|28|928\n"
        tact.parse_versions.side_effect = lambda manifest: [
            {
                "Region": "PUB-30",
                "BuildConfig": "bc30",
                "CDNConfig": "cc30",
                "BuildId": "32",
                "VersionsName": "4929",
            },
            {
                "Region": "PUB-23",
                "BuildConfig": "bc23",
                "CDNConfig": "cc23",
                "BuildId": "28",
                "VersionsName": "928",
            },
        ]
        return tact

    def _make_cdn_client(self):
        cdn = Mock()
        cdn.fetch_config.return_value = (
            b"# Build Configuration\n\nroot = root-hash-1234\n"
        )
        cdn.fetch_data.side_effect = lambda h, **kw: {
            "root-hash-1234": _dumps(ROOT_FRAGMENT),
            "f553e93cd67f24d1b8158a68d5406edc": _dumps(WOW_FRAGMENT),
        }[h]
        return cdn

    def test_sync_fetches_and_imports(self, client: CatalogClient):
        stats = client.sync(
            region="us",
            force=True,
            tact_client=self._make_tact_client(),
            cdn_client=self._make_cdn_client(),
        )
        assert stats["cache"] is False
        assert stats["build_version"] == 30
        assert stats["fragments"] == 2
        assert stats["imported"] == 2

        fragments = client.list_fragments()
        assert len(fragments) == 2
        root = [f for f in fragments if f["is_root"]][0]
        assert root["hash"] == "root-hash-1234"
        assert root["fragment_id"] == "default"

        assert len(client.list_products()) == 1
        assert len(client.list_rules("WoW")) == 3
        assert len(client.list_licenses()) == 3

        build = client.get_stats()["latest_build"]
        assert build["build_version"] == 30
        assert build["build_config"] == "bc30"
        assert build["root_hash"] == "root-hash-1234"

    def test_sync_picks_build_version(self, client: CatalogClient):
        stats = client.sync(
            region="us",
            build_version=23,
            force=True,
            tact_client=self._make_tact_client(),
            cdn_client=self._make_cdn_client(),
        )
        # Build config content is mocked; only the selection path matters.
        assert stats["build_version"] == 30  # from mocked root fragment
        tact = self._make_tact_client()
        # The selected entry must be PUB-23: verified via fetch_config arg.
        cdn = Mock()
        cdn.fetch_config.return_value = b"root = root-hash-1234\n"
        cdn.fetch_data.side_effect = lambda h, **kw: {
            "root-hash-1234": _dumps(ROOT_FRAGMENT),
            "f553e93cd67f24d1b8158a68d5406edc": _dumps(WOW_FRAGMENT),
        }[h]
        client.sync(
            region="us",
            build_version=23,
            force=True,
            tact_client=tact,
            cdn_client=cdn,
        )
        called_with = cdn.fetch_config.call_args[0][0]
        assert called_with == "bc23"

    def test_sync_uses_cache_on_second_call(self, client: CatalogClient):
        first = client.sync(
            region="us",
            force=True,
            tact_client=self._make_tact_client(),
            cdn_client=self._make_cdn_client(),
        )
        assert first["cache"] is False

        # Second call without force: no network, uses cache.
        tact = Mock()
        cdn = Mock()
        second = client.sync(region="us", tact_client=tact, cdn_client=cdn)
        assert second["cache"] is True
        tact.fetch_versions.assert_not_called()
        cdn.fetch_config.assert_not_called()
        assert second["imported"] == 2

    def test_sync_force_bypasses_cache(self, client: CatalogClient):
        client.sync(
            region="us",
            force=True,
            tact_client=self._make_tact_client(),
            cdn_client=self._make_cdn_client(),
        )
        tact = self._make_tact_client()
        cdn = self._make_cdn_client()
        stats = client.sync(region="us", force=True, tact_client=tact, cdn_client=cdn)
        assert stats["cache"] is False
        tact.fetch_versions.assert_called_once()

    def test_sync_no_build_entries(self, client: CatalogClient):
        tact = Mock()
        tact.fetch_versions.return_value = "empty"
        tact.parse_versions.return_value = []
        with pytest.raises(ValueError, match="No catalog build entries"):
            client.sync(region="us", force=True, tact_client=tact, cdn_client=Mock())

    def test_sync_missing_build_config(self, client: CatalogClient):
        tact = Mock()
        tact.fetch_versions.return_value = "x"
        tact.parse_versions.return_value = [
            {"Region": "PUB-30", "BuildConfig": "", "BuildId": "32"}
        ]
        with pytest.raises(ValueError, match="missing BuildConfig"):
            client.sync(region="us", force=True, tact_client=tact, cdn_client=Mock())

    def test_sync_picks_latest_by_build_num_not_build_id(self, client: CatalogClient):
        """BuildId is not monotonic across catalog versions (PUB-29 had a
        higher BuildId than PUB-30). Ordering must use the build number.
        """
        tact = Mock()
        tact.fetch_versions.return_value = "## seqn = 1\nRegion|BuildConfig|CDNConfig|BuildId|VersionsName\nPUB-29|bc29|cc29|422|2547\nPUB-30|bc30|cc30|333|4929\n"
        tact.parse_versions.side_effect = lambda manifest: [
            {
                "Region": "PUB-29",
                "BuildConfig": "bc29",
                "CDNConfig": "cc29",
                "BuildId": "422",
                "VersionsName": "2547",
            },
            {
                "Region": "PUB-30",
                "BuildConfig": "bc30",
                "CDNConfig": "cc30",
                "BuildId": "333",
                "VersionsName": "4929",
            },
        ]
        cdn = Mock()
        cdn.fetch_config.return_value = b"root = root-hash-1234\n"
        cdn.fetch_data.side_effect = lambda h, **kw: {
            "root-hash-1234": _dumps(ROOT_FRAGMENT),
            "f553e93cd67f24d1b8158a68d5406edc": _dumps(WOW_FRAGMENT),
        }[h]
        client.sync(region="us", force=True, tact_client=tact, cdn_client=cdn)
        # PUB-30 must win despite its lower BuildId.
        assert cdn.fetch_config.call_args[0][0] == "bc30"

    def test_sync_skips_encrypted_fragments(self, client: CatalogClient):
        """Encrypted fragments are recorded without a CDN download."""
        root = dict(ROOT_FRAGMENT)
        root["fragments"] = [
            {
                "decryption_key_id": "catalog-decryption-key-moon2",
                "encrypted_hash": "3d27dc812c5c14aa64212057a06582a6",
                "hash": "2ad29587ffd83b33cb43a169b0bcc37c",
                "name": "moon",
            },
        ]
        tact = self._make_tact_client()
        cdn = self._make_cdn_client()
        cdn.fetch_config.return_value = b"root = root-hash-1234\n"
        cdn.fetch_data.side_effect = lambda h, **kw: {
            "root-hash-1234": _dumps(root),
        }[h]

        stats = client.sync(region="us", force=True, tact_client=tact, cdn_client=cdn)
        assert stats["encrypted"] == 1
        assert stats["fragments"] == 1  # root only; moon not fetched
        cdn.fetch_data.assert_called_once()

        rows = client.list_fragments()
        encrypted = [r for r in rows if r["name"] == "moon"]
        assert len(encrypted) == 1
        assert encrypted[0]["decryption_key_id"] == "catalog-decryption-key-moon2"
        assert encrypted[0]["encrypted_hash"] == "3d27dc812c5c14aa64212057a06582a6"

    def test_cache_schema_mismatch_invalidates(self, client: CatalogClient):
        client._save_cache({"aaa": b"{}"}, build_version=30, build_config="bc30")
        with open(client.metadata_file) as f:
            metadata = CatalogCacheMetadata.model_validate(json.load(f))
        metadata.schema_version = 1
        with open(client.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, indent=2, default=str)
        assert client._cache_valid() is False

    def test_sync_import_log(self, client: CatalogClient):
        client.sync(
            region="us",
            force=True,
            tact_client=self._make_tact_client(),
            cdn_client=self._make_cdn_client(),
        )
        rows = client.conn.execute(
            "SELECT * FROM catalog_import_log WHERE success = 1"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["fragments_imported"] == 2
