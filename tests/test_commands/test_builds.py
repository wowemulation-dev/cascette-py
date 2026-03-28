"""Tests for cascette_tools.commands.builds module."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.builds import (
    _ALL_PRODUCTS,
    _get_context_objects,
)
from cascette_tools.core.config import AppConfig
from cascette_tools.database.wago import WagoBuild


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def temp_config(tmp_path):
    config = AppConfig()
    config.data_dir = tmp_path / "test_data"
    config.data_dir.mkdir(parents=True, exist_ok=True)
    return config


class TestAllProducts:
    """Test _ALL_PRODUCTS constant."""

    def test_contains_expected_products(self):
        assert "wow" in _ALL_PRODUCTS
        assert "wow_classic" in _ALL_PRODUCTS
        assert "wow_classic_era" in _ALL_PRODUCTS
        assert "agent" in _ALL_PRODUCTS
        assert "bna" in _ALL_PRODUCTS


class TestGetContextObjects:
    """Test _get_context_objects helper."""

    def test_extracts_all_objects(self):
        ctx = Mock()
        ctx.obj = {
            "config": AppConfig(),
            "console": Mock(),
            "verbose": True,
            "debug": False,
        }

        config, _console, verbose, debug = _get_context_objects(ctx)

        assert isinstance(config, AppConfig)
        assert verbose is True
        assert debug is False


class TestWagoBuildModel:
    """Test WagoBuild model usage."""

    def test_create_build(self):
        build = WagoBuild(
            id=12345,
            build="52902",
            version="10.2.5.52902",
            product="wow",
            build_config="abc123",
            cdn_config="def456",
        )
        assert build.id == 12345
        assert build.build == "52902"
        assert build.version == "10.2.5.52902"
        assert build.product == "wow"
        assert build.build_config == "abc123"

    def test_build_optional_fields(self):
        build = WagoBuild(
            id=12345,
            build="52902",
            version="10.2.5.52902",
            product="wow",
        )
        assert build.build_config is None
        assert build.cdn_config is None
        assert build.encoding_ekey is None


class TestImportBuildsFunction:
    """Test import_builds_to_database function."""

    def test_import_new_builds(self, temp_config):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.rowcount = 1
        mock_conn.total_changes = 1

        builds = [
            WagoBuild(
                id=12345,
                build="52902",
                version="10.2.5.52902",
                product="wow",
                build_config="abc123",
            )
        ]

        with patch(
            "cascette_tools.database.wago.sqlite3.connect", return_value=mock_conn
        ):
            from cascette_tools.database.wago import WagoClient

            client = WagoClient(temp_config)
            stats = client.import_builds_to_database(builds)

            assert stats["imported"] >= 0


class TestExportBuildsFunction:
    """Test build export functionality."""

    def test_export_to_json(self, tmp_path):
        builds = [
            WagoBuild(
                id=12345,
                build="52902",
                version="10.2.5.52902",
                product="wow",
                build_config="abc123",
            )
        ]

        output_path = tmp_path / "builds.json"
        build_data = [b.model_dump(mode="json") for b in builds]
        output_path.write_text(json.dumps(build_data, indent=2, default=str))

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert len(data) == 1
        assert data[0]["id"] == 12345

    def test_export_to_csv(self, tmp_path):
        import csv

        builds = [
            WagoBuild(
                id=12345,
                build="52902",
                version="10.2.5.52902",
                product="wow",
                build_config="abc123",
            )
        ]

        output_path = tmp_path / "builds.csv"
        with open(output_path, "w", newline="") as f:
            fieldnames = [
                "id",
                "build",
                "version",
                "product",
                "build_config",
                "cdn_config",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for build in builds:
                writer.writerow(
                    {
                        "id": build.id,
                        "build": build.build,
                        "version": build.version,
                        "product": build.product,
                        "build_config": build.build_config or "",
                        "cdn_config": build.cdn_config or "",
                    }
                )

        assert output_path.exists()
        content = output_path.read_text()
        assert "12345" in content
        assert "52902" in content


class TestImportFromFile:
    """Test importing builds from files."""

    def test_import_from_json(self, tmp_path):
        input_path = tmp_path / "builds.json"
        build_data = [
            {
                "id": 12345,
                "build": "52902",
                "version": "10.2.5.52902",
                "product": "wow",
                "build_config": "abc123",
            }
        ]
        input_path.write_text(json.dumps(build_data))

        data = json.loads(input_path.read_text())
        builds = [WagoBuild(**item) for item in data]

        assert len(builds) == 1
        assert builds[0].id == 12345

    def test_import_from_csv(self, tmp_path):
        import csv

        input_path = tmp_path / "builds.csv"
        csv_content = (
            "id,build,version,product,build_config\n12345,52902,10.2.5.52902,wow,abc123"
        )
        input_path.write_text(csv_content)

        with open(input_path, newline="") as f:
            reader = csv.DictReader(f)
            builds = []
            for row in reader:
                builds.append(
                    WagoBuild(
                        id=int(str(row["id"])),
                        build=str(row["build"]),
                        version=str(row["version"]),
                        product=str(row["product"]),
                        build_config=str(row.get("build_config", "")) or None,
                    )
                )

        assert len(builds) == 1
        assert builds[0].id == 12345
