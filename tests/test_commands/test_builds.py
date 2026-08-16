"""Tests for cascette_tools.commands.builds module."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner, Result

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


class TestRegionsForEntry:
    """Test regions_for_entry helper."""

    def test_collects_regions_for_build_config(self):
        from cascette_tools.commands.builds import regions_for_entry

        entries = [
            {"Region": "us", "BuildConfig": "abc"},
            {"Region": "eu", "BuildConfig": "abc"},
            {"Region": "kr", "BuildConfig": "def"},
        ]
        assert regions_for_entry(entries, "abc") == "us,eu"
        assert regions_for_entry(entries, "def") == "kr"
        assert regions_for_entry(entries, "zzz") is None

    def test_deduplicates_regions(self):
        from cascette_tools.commands.builds import regions_for_entry

        entries = [
            {"Region": "us", "BuildConfig": "abc"},
            {"Region": "us", "BuildConfig": "abc"},
            {"Region": "eu", "BuildConfig": "abc"},
        ]
        assert regions_for_entry(entries, "abc") == "us,eu"

    def test_returns_none_without_region_column(self):
        from cascette_tools.commands.builds import regions_for_entry

        entries = [{"BuildConfig": "abc"}]
        assert regions_for_entry(entries, "abc") is None


class TestRibbitFilesCommand:
    """Test the ribbit-files command."""

    def _invoke(self, *args: str, config: AppConfig) -> Result:
        from cascette_tools.__main__ import main

        runner = CliRunner()
        with patch.object(AppConfig, "load", return_value=config):
            return runner.invoke(main, ["builds", "ribbit-files", *args])

    @patch("cascette_tools.database.wago.WagoClient")
    def test_writes_versions_and_cdns(self, mock_wago, tmp_path):

        mock_client = Mock()
        mock_wago.return_value.__enter__.return_value = mock_client
        mock_client.list_builds.return_value = [
            WagoBuild(
                id=31650,
                build="31650",
                version="1.13.2.31650",
                product="wow_classic",
                build_config="2c915a9a226a3f35af6c65fcc7b6ca4a",
                cdn_config="c54b41b3195b9482ce0d3c6bf0b86cdb",
                regions="us,eu",
                seqn=12345,
            )
        ]

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        out_dir = tmp_path / "mirror" / "tpr" / "wow"
        result = self._invoke(
            "wow_classic",
            "31650",
            "--host",
            "localhost:8000",
            "--out-dir",
            str(out_dir),
            config=config,
        )
        assert result.exit_code == 0, result.output

        versions = (out_dir / "versions").read_text()
        cdns = (out_dir / "cdns").read_text()

        # versions BPSV: header, seqn, rows per region
        lines = versions.strip().split("\n")
        assert lines[0].startswith("Region!STRING:0|BuildConfig!HEX:16")
        assert "## seqn = 12345" in versions
        assert (
            "us|2c915a9a226a3f35af6c65fcc7b6ca4a|c54b41b3195b9482ce0d3c6bf0b86cdb"
            in versions
        )
        assert "eu|2c915a9a226a3f35af6c65fcc7b6ca4a" in versions
        assert "31650|1.13.2.31650" in versions

        # cdns BPSV: hosts rewritten to the mirror host
        assert "## seqn = 12345" in cdns
        assert (
            "us|tpr/wow|localhost:8000|http://localhost:8000|tpr/configs/data" in cdns
        )

    @patch("cascette_tools.database.wago.WagoClient")
    def test_default_host_and_regions(self, mock_wago, tmp_path):
        mock_client = Mock()
        mock_wago.return_value.__enter__.return_value = mock_client
        mock_client.list_builds.return_value = [
            WagoBuild(
                id=31650,
                build="31650",
                version="1.13.2.31650",
                product="wow_classic",
                build_config="bc",
                cdn_config="cc",
            )
        ]

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        out_dir = tmp_path / "out"
        result = self._invoke(
            "wow_classic", "31650", "--out-dir", str(out_dir), config=config
        )
        assert result.exit_code == 0, result.output

        versions = (out_dir / "versions").read_text()
        # Default regions us,eu,kr,tw,cn; seqn falls back to 9999999
        assert "## seqn = 9999999" in versions
        assert versions.count("|bc|cc|") == 5

    @patch("cascette_tools.database.wago.WagoClient")
    def test_build_not_found(self, mock_wago, tmp_path):
        mock_client = Mock()
        mock_wago.return_value.__enter__.return_value = mock_client
        mock_client.list_builds.return_value = []

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            "wow_classic", "99999", "--out-dir", str(tmp_path), config=config
        )
        assert result.exit_code != 0
        assert "No builds found" in result.output


class TestExportRibbit:
    """Tests for the builds export-ribbit command."""

    def _invoke(self, *args: str, config: AppConfig) -> Result:
        from cascette_tools.__main__ import main

        runner = CliRunner()
        with patch.object(AppConfig, "load", return_value=config):
            return runner.invoke(main, ["builds", "export-ribbit", *args])

    @patch("cascette_tools.database.wago.WagoClient")
    def test_writes_all_builds_versions_and_cdns(self, mock_wago, tmp_path):
        mock_client = Mock()
        mock_wago.return_value.__enter__.return_value = mock_client
        mock_client.get_database_builds.return_value = [
            WagoBuild(
                id=31650,
                build="31650",
                version="1.13.2.31650",
                product="wow_classic",
                build_config="2c9159a226a3f35af6c65fcc7b6ca4a",
                cdn_config="c54b41b3195b9482ce0d3c6bf0b86cdb",
            ),
            WagoBuild(
                id=38704,
                build="38704",
                version="1.13.7.38704",
                product="wow_classic_era",
                build_config="30daec22777cbe6ab7a0aa31ce621f1b",
                cdn_config="572649a9eda7c06a42b37858d27fbc0f",
            ),
        ]

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        mirror = tmp_path / "mirror"
        result = self._invoke("--mirror-root", str(mirror), config=config)
        assert result.exit_code == 0, result.output

        versions = (mirror / "tpr" / "wow" / "versions").read_text()
        cdns = (mirror / "tpr" / "wow" / "cdns").read_text()

        # Newest build first (agent takes first us row as current)
        assert versions.splitlines()[2].startswith(
            "us|30daec22777cbe6ab7a0aa31ce621f1b"
        )
        # Both builds present, 5 regions each
        assert versions.count("|31650|1.13.2.31650|") == 5
        assert versions.count("|38704|1.13.7.38704|") == 5
        assert "Region!STRING:0|BuildConfig!HEX:16" in versions
        # cdns rewritten to localhost
        assert (
            "us|tpr/wow|localhost:8000|http://localhost:8000|tpr/configs/data" in cdns
        )

    @patch("cascette_tools.database.wago.WagoClient")
    def test_skips_builds_without_config_hashes(self, mock_wago, tmp_path):
        mock_client = Mock()
        mock_wago.return_value.__enter__.return_value = mock_client
        mock_client.get_database_builds.return_value = [
            WagoBuild(
                id=31650,
                build="31650",
                version="1.13.2.31650",
                product="wow_classic",
                build_config=None,
                cdn_config=None,
            ),
        ]

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        mirror = tmp_path / "mirror"
        result = self._invoke("--mirror-root", str(mirror), config=config)
        assert result.exit_code == 0, result.output

        versions = (mirror / "tpr" / "wow" / "versions").read_text()
        assert "31650" not in versions
        assert versions.count("\n") == 2  # header + seqn only


class TestArchivePristine:
    """Tests for the builds archive-pristine command."""

    def _make_install(self, tmp_path):
        """Create a minimal install dir with .build.info + a fake exe."""
        install = tmp_path / "install"
        (install / "_classic_").mkdir(parents=True)
        (install / ".build.info").write_text(
            "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
            "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
            "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|"
            "Last Activated!STRING:0|Version!STRING:0|Product!STRING:0\n"
            "us|1|2c9159a226a3f35af6c65fcc7b6ca4a|"
            "c54b41b3195b9482ce0d3c6bf0b86cdb|||tpr/wow|localhost:8000|||"
            "||1.13.2.31650|wow_classic\n"
        )
        (install / "_classic_" / "Wow.exe").write_bytes(b"\x00" * 64)
        return install

    def _invoke(self, *args: str, config: AppConfig) -> Result:
        from cascette_tools.__main__ import main

        runner = CliRunner()
        with patch.object(AppConfig, "load", return_value=config):
            return runner.invoke(main, ["builds", "archive-pristine", *args])

    @patch("subprocess.run")
    def test_archives_windows_install(self, mock_run, tmp_path):
        """Detects windows-win64 and moves to the archive path."""
        mock_run.return_value = Mock(
            stdout="Wow.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64\n"
        )
        install = self._make_install(tmp_path)
        archive = tmp_path / "archive"

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code == 0, result.output
        target = archive / "1.13.2.31650.windows-win64"
        assert target.exists()
        assert (target / "_classic_" / "Wow.exe").exists()
        assert not install.exists()  # moved

    @patch("subprocess.run")
    def test_detects_macos_x86_64(self, mock_run, tmp_path):
        """Mach-O x86_64 -> macos-x86_64 naming."""
        mock_run.return_value = Mock(
            stdout="Wow.exe: Mach-O 64-bit executable x86_64\n"
        )
        install = self._make_install(tmp_path)
        archive = tmp_path / "archive"

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code == 0, result.output
        assert (archive / "1.13.2.31650.macos-x86_64").exists()

    @patch("subprocess.run")
    def test_detects_macos_arm64(self, mock_run, tmp_path):
        """Mach-O arm64 -> macos-arm64 naming."""
        mock_run.return_value = Mock(stdout="Wow.exe: Mach-O 64-bit executable arm64\n")
        install = self._make_install(tmp_path)
        archive = tmp_path / "archive"

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code == 0, result.output
        assert (archive / "1.13.2.31650.macos-arm64").exists()

    @patch("subprocess.run")
    def test_archives_wowclassic_exe(self, mock_run, tmp_path):
        """1.13.3+ installs ship WowClassic.exe instead of Wow.exe."""
        mock_run.return_value = Mock(
            stdout="WowClassic.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64\n"
        )
        install = tmp_path / "install"
        (install / "_classic_").mkdir(parents=True)
        (install / ".build.info").write_text(
            "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
            "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
            "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|"
            "Last Activated!STRING:0|Version!STRING:0|Product!STRING:0\n"
            "us|1|eabc7dd92330e4907bc234899dd0cd4b|"
            "efc95c64488ab6dda10a7f57eca91f19|||tpr/wow|localhost:8000|||"
            "||1.13.3.32790|wow_classic\n"
        )
        (install / "_classic_" / "WowClassic.exe").write_bytes(b"\x00" * 64)
        archive = tmp_path / "archive"

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code == 0, result.output
        target = archive / "1.13.3.32790.windows-win64"
        assert target.exists()
        assert (target / "_classic_" / "WowClassic.exe").exists()
        assert not install.exists()  # moved

    @patch("subprocess.run")
    def test_rejects_existing_target(self, mock_run, tmp_path):
        """Existing archived version is an error without --force."""
        mock_run.return_value = Mock(
            stdout="Wow.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64\n"
        )
        install = self._make_install(tmp_path)
        archive = tmp_path / "archive"
        (archive / "1.13.2.31650.windows-win64").mkdir(parents=True)

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code != 0
        assert "already" in result.output and "exists" in result.output
        assert install.exists()  # not moved on conflict

    @patch("subprocess.run")
    def test_unrecognized_binary_aborts(self, mock_run, tmp_path):
        """Non-PE/Mach-O binary aborts with a clear message."""
        mock_run.return_value = Mock(stdout="Wow.exe: data\n")
        install = self._make_install(tmp_path)
        archive = tmp_path / "archive"

        config = AppConfig()
        config.data_dir = tmp_path / "data"
        config.data_dir.mkdir(parents=True, exist_ok=True)
        result = self._invoke(
            str(install),
            "--archive-root",
            str(archive),
            "--skip-verify",
            config=config,
        )
        assert result.exit_code != 0
        assert "Unrecognized binary" in result.output
        assert install.exists()
