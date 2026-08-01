"""Tests for cascette_tools.commands.catalog."""

import json
from collections.abc import Iterator, Mapping
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.catalog import catalog_group
from cascette_tools.core.config import AppConfig
from cascette_tools.database.catalog import CatalogClient
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
        "wow_classic": {"tact_product": "wow_classic", "run_64_bit_only": True}
    },
    "products": [
        {
            "base": {
                "program_id": "WoW",
                "name": "world_of_warcraft#PRODUCTS_WOW_NAME",
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
                    "actions": [
                        {
                            "run_first_rule": [
                                {
                                    "actions": [
                                        {
                                            "add_product": {
                                                "product_id": {
                                                    "id": "WoWX9",
                                                    "type": "retail",
                                                }
                                            }
                                        }
                                    ],
                                    "match": {"license_id": [179712]},
                                }
                            ]
                        }
                    ],
                    "match": {"license_id": [813186]},
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
def cli_runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def temp_config(tmp_path) -> AppConfig:
    config = AppConfig()
    config.data_dir = tmp_path / "test_data"
    config.config_dir = tmp_path / "test_config"
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.config_dir.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture
def seeded_client(temp_config: AppConfig) -> Iterator[CatalogClient]:
    """A CatalogClient with a root and a WoW fragment imported."""
    client = CatalogClient(temp_config)
    parser = CatalogParser()
    client.import_fragment(
        parser.parse(_dumps(ROOT_FRAGMENT)), "root-hash", is_root=True
    )
    client.import_fragment(parser.parse(_dumps(WOW_FRAGMENT)), "wow-hash")
    yield client
    client.close()


def _invoke(runner: CliRunner, config: AppConfig, args: list[str]):
    """Invoke the catalog command group with a config/console context."""
    from rich.console import Console

    return runner.invoke(
        catalog_group,
        args,
        obj={
            "config": config,
            "console": Console(),
            "verbose": False,
            "debug": False,
        },
    )


class TestSyncCommand:
    def test_sync_success(self, cli_runner: CliRunner, temp_config: AppConfig):
        stats = {
            "cache": False,
            "build_version": 30,
            "build_config": "bc30",
            "fragments": 2,
            "imported": 2,
        }
        with patch(
            "cascette_tools.database.catalog.CatalogClient.sync", return_value=stats
        ) as mock_sync:
            result = _invoke(cli_runner, temp_config, ["sync"])
        assert result.exit_code == 0
        mock_sync.assert_called_once()
        kwargs = mock_sync.call_args.kwargs
        assert kwargs["force"] is False
        assert "Catalog synced" in result.output

    def test_sync_cache_hit(self, cli_runner: CliRunner, temp_config: AppConfig):
        stats = {
            "cache": True,
            "build_version": 30,
            "fragments": 2,
            "imported": 2,
        }
        with patch(
            "cascette_tools.database.catalog.CatalogClient.sync", return_value=stats
        ):
            result = _invoke(cli_runner, temp_config, ["sync"])
        assert result.exit_code == 0
        assert "cached" in result.output

    def test_sync_build_version_option(
        self, cli_runner: CliRunner, temp_config: AppConfig
    ):
        with patch(
            "cascette_tools.database.catalog.CatalogClient.sync",
            return_value={"cache": True, "fragments": 1, "imported": 1},
        ) as mock_sync:
            result = _invoke(cli_runner, temp_config, ["sync", "--build-version", "23"])
        assert result.exit_code == 0
        assert mock_sync.call_args.kwargs["build_version"] == 23

    def test_sync_error(self, cli_runner: CliRunner, temp_config: AppConfig):
        with patch(
            "cascette_tools.database.catalog.CatalogClient.sync",
            side_effect=RuntimeError("boom"),
        ):
            result = _invoke(cli_runner, temp_config, ["sync"])
        assert result.exit_code != 0
        assert "boom" in result.output


class TestListCommand:
    def test_list_fragments(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["list"])
        assert result.exit_code == 0
        assert "default" in result.output
        assert "world_of_warcraft" in result.output

    def test_list_empty(self, cli_runner: CliRunner, temp_config: AppConfig):
        result = _invoke(cli_runner, temp_config, ["list"])
        assert result.exit_code == 0
        assert "No catalog data" in result.output


class TestShowCommand:
    def test_show_program(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["show", "WoW"])
        assert result.exit_code == 0
        assert "Program: WoW" in result.output
        assert "Game account level: yes" in result.output
        assert "1106089" in result.output
        assert "add_product WoW/wow_classic" in result.output

    def test_show_recurses_into_nested_rules(
        self, cli_runner: CliRunner, seeded_client: CatalogClient
    ):
        """Nested run_first_rule actions render their inner rules."""
        result = _invoke(cli_runner, seeded_client.config, ["show", "WoW"])
        assert result.exit_code == 0
        assert "run_first_rule" in result.output
        assert "add_product WoWX12/retail" in result.output

    def test_show_unknown_program(
        self, cli_runner: CliRunner, seeded_client: CatalogClient
    ):
        result = _invoke(cli_runner, seeded_client.config, ["show", "Diablo"])
        assert result.exit_code == 0
        assert "No program 'Diablo'" in result.output
        assert "catalog programs" in result.output


class TestProgramsCommand:
    def test_programs_lists_all(
        self, cli_runner: CliRunner, seeded_client: CatalogClient
    ):
        result = _invoke(cli_runner, seeded_client.config, ["programs"])
        assert result.exit_code == 0
        assert "WoW" in result.output
        assert "Total: 1 programs" in result.output

    def test_programs_fragment_filter(
        self, cli_runner: CliRunner, seeded_client: CatalogClient
    ):
        result = _invoke(
            cli_runner,
            seeded_client.config,
            ["programs", "--fragment", "world_of_warcraft"],
        )
        assert result.exit_code == 0
        assert "WoW" in result.output

    def test_programs_fragment_missing(
        self, cli_runner: CliRunner, seeded_client: CatalogClient
    ):
        result = _invoke(
            cli_runner, seeded_client.config, ["programs", "--fragment", "nope"]
        )
        assert result.exit_code == 0
        assert "No fragment 'nope'" in result.output


class TestLicensesCommand:
    def test_list_licenses(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["licenses"])
        assert result.exit_code == 0
        assert "1106089" in result.output
        assert "Total: 3" in result.output

    def test_license_filter(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(
            cli_runner, seeded_client.config, ["licenses", "--license-id", "1106089"]
        )
        assert result.exit_code == 0
        assert "WoW" in result.output

    def test_licenses_empty(self, cli_runner: CliRunner, temp_config: AppConfig):
        result = _invoke(cli_runner, temp_config, ["licenses"])
        assert result.exit_code == 0
        assert "No licenses" in result.output


class TestInstallsCommand:
    def test_list_installs(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["installs"])
        assert result.exit_code == 0
        assert "wow_classic" in result.output
        assert "Total: 1" in result.output

    def test_installs_filter(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(
            cli_runner,
            seeded_client.config,
            ["installs", "--tact-product", "wow_classic"],
        )
        assert result.exit_code == 0
        assert "wow_classic" in result.output


class TestStatsCommand:
    def test_stats(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["stats"])
        assert result.exit_code == 0
        assert "Fragments: 2" in result.output
        assert "Products: 1" in result.output
        assert "Programs: 1" in result.output
        assert "Rules: 3" in result.output
        assert "Licenses: 3" in result.output
        assert "Install configs: 1" in result.output

    def test_stats_no_build(self, cli_runner: CliRunner, seeded_client: CatalogClient):
        result = _invoke(cli_runner, seeded_client.config, ["stats"])
        assert "No build synced yet" in result.output
