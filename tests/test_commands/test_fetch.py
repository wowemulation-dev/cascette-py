"""Tests for fetch command module."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from cascette_tools.commands.fetch import (
    _get_context_objects,
    _save_file,
    _show_config_metadata,
    fetch,
)
from cascette_tools.core.config import AppConfig


class TestFetchCommands:
    """Test fetch command functionality."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    # Use standardized fixtures from conftest.py
    # mock_config, mock_console, and mock_cli_context are available

    @pytest.fixture
    def mock_context_objects(self, mock_config, mock_console):
        """Create mock context objects for legacy compatibility."""
        return mock_config, mock_console, False, False

    @pytest.fixture
    def sample_config_data(self):
        """Create sample config file data."""
        return b"# Build Configuration\nroot = abcdef1234567890abcdef1234567890\ninstall = 1234567890abcdef1234567890abcdef\n"

    @pytest.fixture
    def sample_data_file(self):
        """Create sample data file content."""
        return b"BLTE" + b"\x00" * 8 + b"sample game data content"

    @pytest.fixture
    def sample_encoding_data(self):
        """Create sample encoding file data."""
        return b"EN" + b"\x02\x00" + b"\x00" * 100  # Simple encoding header

    @pytest.fixture
    def mock_cdn_client(self):
        """Create mock CDN client."""
        client = Mock()
        client.fetch_config.return_value = b"config data"
        client.fetch_data.return_value = b"data content"
        client.fetch_encoding.return_value = b"encoding data"
        return client

    def test_fetch_group_help(self, runner):
        """Test fetch group shows help when invoked without subcommand."""
        result = runner.invoke(fetch, [])

        assert result.exit_code == 0
        assert "Fetch data from CDN sources" in result.output
        assert "config" in result.output
        assert "data" in result.output
        assert "build" in result.output
        assert "encoding" in result.output
        assert "batch" in result.output
        assert "patch" in result.output
        assert "manifests" in result.output

    def test_fetch_group_help_flag(self, runner):
        """Test fetch group shows help when invoked with --help."""
        result = runner.invoke(fetch, ["--help"])

        assert result.exit_code == 0
        assert "Fetch data from CDN sources" in result.output

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_config_fetch_build_config(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client,
        sample_config_data,
        tmp_path
    ):
        """Test config command fetching build config."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_config.return_value = sample_config_data

        output_file = tmp_path / "test_config.build"

        result = runner.invoke(fetch, [
            "config",
            "abcdef1234567890abcdef1234567890",
            "--type", "build",
            "--output", str(output_file)
        ])

        if result.exit_code != 0:
            print(f"Command output: {result.output}")
            print(f"Exception: {result.exception}")
        assert result.exit_code == 0
        assert output_file.exists()
        assert output_file.read_bytes() == sample_config_data
        mock_cdn_client.fetch_config.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_config_fetch_without_output(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client,
        sample_config_data
    ):
        """Test config command without specifying output file."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_config.return_value = sample_config_data

        with patch("cascette_tools.commands.fetch._save_file") as mock_save:
            result = runner.invoke(fetch, [
                "config",
                "abcdef1234567890abcdef1234567890",
                "--type", "build"
            ])

            assert result.exit_code == 0
            mock_save.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_config_with_metadata(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client,
        sample_config_data
    ):
        """Test config command with metadata display."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_config.return_value = sample_config_data

        with patch("cascette_tools.commands.fetch._show_config_metadata") as mock_metadata:
            result = runner.invoke(fetch, [
                "config",
                "abcdef1234567890abcdef1234567890",
                "--show-metadata"
            ])

            assert result.exit_code == 0
            mock_metadata.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_data_fetch(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client,
        sample_data_file,
        tmp_path
    ):
        """Test data command fetching from CDN."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_data.return_value = sample_data_file

        output_file = tmp_path / "test_data.bin"

        result = runner.invoke(fetch, [
            "data",
            "abcdef1234567890abcdef1234567890",
            "--output", str(output_file)
        ])

        assert result.exit_code == 0
        assert output_file.exists()
        assert output_file.read_bytes() == sample_data_file

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_data_with_range(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client
    ):
        """Test data command with range request."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_data.return_value = b"partial data"

        # Note: data command doesn't actually have --range option in current implementation
        # This test is based on incorrect assumption, so it should be removed or modified
        # For now, test basic data fetch without range
        with patch("cascette_tools.commands.fetch._save_file"):
            result = runner.invoke(fetch, [
                "data",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code == 0
            mock_cdn_client.fetch_data.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.TACTClient")
    def test_build_fetch_latest(
        self,
        mock_tact_class,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test build command fetching build by version string."""
        # Add cdn_timeout and cdn_max_retries to the mock config object
        config_obj, cache_obj, _, _ = mock_context_objects
        config_obj.cdn_timeout = 30.0
        config_obj.cdn_max_retries = 3
        mock_get_context.return_value = mock_context_objects
        mock_tact = Mock()
        mock_tact_class.return_value = mock_tact

        # Mock versions response
        versions = [{"VersionsName": "11.0.2.56461", "BuildConfig": "build_hash"}]
        mock_tact.fetch_versions.return_value = b"versions data"
        mock_tact.parse_versions.return_value = versions

        with patch("cascette_tools.commands.fetch.CDNClient") as mock_cdn_class:
            with patch("cascette_tools.commands.fetch.BuildConfigParser") as mock_parser_class:
                with patch("cascette_tools.commands.fetch.Progress") as mock_progress_class:
                    with patch("cascette_tools.commands.fetch._save_file"):
                        with patch("pathlib.Path.mkdir"):
                          with patch("cascette_tools.database.wago.WagoClient") as mock_wago_class:
                              # Setup WagoClient context manager
                              mock_wago = Mock()
                              mock_wago.get_builds.return_value = []  # Return empty builds
                              # Create a mock build that matches what the command expects
                              mock_build = Mock()
                              mock_build.product = "wow"
                              mock_build.build_config = "build_hash"
                              mock_build.cdn_config = "cdn_hash"
                              mock_build.version = "11.0.2.56461"
                              mock_wago.search_builds.return_value = [mock_build]  # Return the mock build
                              mock_wago_instance = Mock()
                              mock_wago_instance.__enter__ = Mock(return_value=mock_wago)
                              mock_wago_instance.__exit__ = Mock(return_value=None)
                              mock_wago_class.return_value = mock_wago_instance

                              mock_cdn = Mock()
                              mock_cdn.fetch_config.return_value = b"build config data"

                              # Setup context manager properly
                              mock_cdn_instance = Mock()
                              mock_cdn_instance.__enter__ = Mock(return_value=mock_cdn)
                              mock_cdn_instance.__exit__ = Mock(return_value=None)
                              mock_cdn_class.return_value = mock_cdn_instance

                              # Setup context manager properly for Progress
                              mock_progress = Mock()
                              mock_progress_instance = Mock()
                              mock_progress_instance.__enter__ = Mock(return_value=mock_progress)
                              mock_progress_instance.__exit__ = Mock(return_value=None)
                              mock_progress_class.return_value = mock_progress_instance
                              mock_progress.add_task = Mock(return_value=1)
                              mock_progress.update = Mock()

                              mock_parser = Mock()
                              mock_parser_class.return_value = mock_parser
                              mock_build_config = Mock()
                              mock_build_config.extra_fields = {}
                              mock_parser.parse.return_value = mock_build_config

                              result = runner.invoke(fetch, ["build", "11.0.2.56461", "--output-dir", "/tmp"])

                              # Debug output on failure
                              if result.exit_code != 0:
                                  print(f"Exit code: {result.exit_code}")
                                  print(f"Output: {result.output}")
                                  if result.exception:
                                      import traceback
                                      traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
                              assert result.exit_code == 0
                              # When searching Wago succeeds, TACT isn't used
                              mock_wago.search_builds.assert_called_once_with("11.0.2.56461", field="build")

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_encoding_fetch(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client,
        sample_encoding_data
    ):
        """Test encoding command."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_data.return_value = sample_encoding_data

        with patch("cascette_tools.commands.fetch._save_file"):
            result = runner.invoke(fetch, [
                "encoding",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code == 0
            mock_cdn_client.fetch_data.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    def test_batch_fetch(
        self,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with hash list."""
        mock_get_context.return_value = mock_context_objects

        # Create hash list file
        hash_list = tmp_path / "hashes.txt"
        hash_list.write_text("abcdef1234567890abcdef1234567890\n1234567890abcdef1234567890abcdef\n")

        output_dir = tmp_path / "output"

        with patch("cascette_tools.commands.fetch.CDNClient") as mock_cdn_class:
            with patch("cascette_tools.commands.fetch.ThreadPoolExecutor") as mock_executor_class:
                with patch("cascette_tools.commands.fetch.Progress") as mock_progress_class:
                    mock_cdn = Mock()
                    # Setup context manager properly for CDN client
                    mock_cdn_instance = Mock()
                    mock_cdn_instance.__enter__ = Mock(return_value=mock_cdn)
                    mock_cdn_instance.__exit__ = Mock(return_value=None)
                    mock_cdn_class.return_value = mock_cdn_instance
                    mock_cdn.fetch_data.return_value = b"file content"

                    # Setup context manager properly for ThreadPoolExecutor
                    mock_executor = Mock()
                    mock_executor_instance = Mock()
                    mock_executor_instance.__enter__ = Mock(return_value=mock_executor)
                    mock_executor_instance.__exit__ = Mock(return_value=None)
                    mock_executor_class.return_value = mock_executor_instance

                    # Setup context manager properly for Progress
                    mock_progress = Mock()
                    mock_progress_instance = Mock()
                    mock_progress_instance.__enter__ = Mock(return_value=mock_progress)
                    mock_progress_instance.__exit__ = Mock(return_value=None)
                    mock_progress_class.return_value = mock_progress_instance
                    mock_progress.add_task = Mock(return_value=1)
                    mock_progress.update = Mock()

                    # Mock futures
                    future1 = Mock()
                    future2 = Mock()
                    future1.result.return_value = ("hash1", True, "Success")
                    future2.result.return_value = ("hash2", True, "Success")
                    mock_executor.submit.side_effect = [future1, future2]

                    with patch("cascette_tools.commands.fetch.as_completed") as mock_as_completed:
                        mock_as_completed.return_value = [future1, future2]

                        result = runner.invoke(fetch, [
                            "batch",
                            str(hash_list),
                            "--output-dir", str(output_dir)
                        ])

                        assert result.exit_code == 0
                        # Should submit 2 tasks
                        assert mock_executor.submit.call_count == 2

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.CDNClient")
    def test_patch_fetch(
        self,
        mock_cdn_class,
        mock_get_context,
        runner,
        mock_context_objects,
        mock_cdn_client
    ):
        """Test patch command."""
        mock_get_context.return_value = mock_context_objects
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn_client
        mock_cdn_client.fetch_patch.return_value = b"patch data"

        with patch("cascette_tools.commands.fetch._save_file"):
            result = runner.invoke(fetch, [
                "patch",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code == 0
            mock_cdn_client.fetch_patch.assert_called_once()

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.TACTClient")
    def test_manifests_fetch(
        self,
        mock_tact_class,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test manifests command."""
        mock_get_context.return_value = mock_context_objects
        mock_tact = Mock()
        mock_tact_class.return_value = mock_tact

        mock_tact.fetch_versions.return_value = "versions data"
        mock_tact.fetch_cdns.return_value = "cdns data"
        mock_tact.parse_versions.return_value = []
        mock_tact.parse_cdns.return_value = []

        with patch("cascette_tools.commands.fetch._save_file"):
            with patch("cascette_tools.commands.fetch.Progress") as mock_progress_class:
                # Setup context manager properly for Progress
                mock_progress = Mock()
                mock_progress_instance = Mock()
                mock_progress_instance.__enter__ = Mock(return_value=mock_progress)
                mock_progress_instance.__exit__ = Mock(return_value=None)
                mock_progress_class.return_value = mock_progress_instance
                mock_progress.add_task = Mock(return_value=1)
                mock_progress.update = Mock()
                mock_progress.advance = Mock()

                result = runner.invoke(fetch, ["manifests"])

                assert result.exit_code == 0
                mock_tact.fetch_versions.assert_called_once()
                mock_tact.fetch_cdns.assert_called_once()

    def test_config_invalid_hash(self, enhanced_cli_test_setup):
        """Test config command with invalid hash."""
        setup = enhanced_cli_test_setup
        runner = setup['runner']
        console = setup['console']

        # Mock hash validation to return False for invalid hash
        with patch('cascette_tools.commands.fetch.validate_hash_string', return_value=False):
            result = runner.invoke(fetch, ["config", "invalid_hash"])

            assert result.exit_code != 0
            # Check if error message was printed to console
            printed_text = ' '.join(console.printed_lines)
            assert "Invalid hash format" in printed_text or "Invalid hash format" in result.output

    def test_data_invalid_hash(self, enhanced_cli_test_setup):
        """Test data command with invalid hash."""
        setup = enhanced_cli_test_setup
        runner = setup['runner']
        console = setup['console']

        # Mock hash validation to return False for invalid hash
        with patch('cascette_tools.commands.fetch.validate_hash_string', return_value=False):
            result = runner.invoke(fetch, ["data", "invalid_hash"])

            assert result.exit_code != 0
            # Check if error message was printed to console
            printed_text = ' '.join(console.printed_lines)
            assert "Invalid hash format" in printed_text or "Invalid hash format" in result.output

    def test_config_fetch_error(self, enhanced_cli_test_setup):
        """Test config command with CDN fetch error."""
        setup = enhanced_cli_test_setup
        runner = setup['runner']
        cdn_client = setup['cdn_client']

        # Mock hash validation to return True, but CDN fetch to fail
        with patch('cascette_tools.commands.fetch.validate_hash_string', return_value=True):
            cdn_client.fetch_config.side_effect = Exception("Network error")

            result = runner.invoke(fetch, [
                "config",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code != 0
            assert "Error" in result.output

    def test_data_fetch_error(self, enhanced_cli_test_setup):
        """Test data command with CDN fetch error."""
        setup = enhanced_cli_test_setup
        runner = setup['runner']
        cdn_client = setup['cdn_client']

        # Mock hash validation to return True, but CDN fetch to fail
        with patch('cascette_tools.commands.fetch.validate_hash_string', return_value=True):
            cdn_client.fetch_data.side_effect = Exception("Network error")

            result = runner.invoke(fetch, [
                "data",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code != 0
            assert "Error" in result.output

    def test_batch_nonexistent_file(self, runner):
        """Test batch command with nonexistent hash file."""
        result = runner.invoke(fetch, [
            "batch",
            "nonexistent_file.txt"
        ])

        assert result.exit_code != 0

    def test_config_help(self, runner):
        """Test config subcommand shows help."""
        result = runner.invoke(fetch, ["config", "--help"])

        assert result.exit_code == 0
        assert "Fetch configuration files from CDN" in result.output

    def test_data_help(self, runner):
        """Test data subcommand shows help."""
        result = runner.invoke(fetch, ["data", "--help"])

        assert result.exit_code == 0
        assert "Fetch data archives from CDN" in result.output

    def test_build_help(self, runner):
        """Test build subcommand shows help."""
        result = runner.invoke(fetch, ["build", "--help"])

        assert result.exit_code == 0
        assert "Fetch complete build information" in result.output

    def test_encoding_help(self, runner):
        """Test encoding subcommand shows help."""
        result = runner.invoke(fetch, ["encoding", "--help"])

        assert result.exit_code == 0
        assert "Fetch encoding file" in result.output

    def test_batch_help(self, runner):
        """Test batch subcommand shows help."""
        result = runner.invoke(fetch, ["batch", "--help"])

        assert result.exit_code == 0
        assert "Batch fetch from a list of hashes" in result.output

    def test_patch_help(self, runner):
        """Test patch subcommand shows help."""
        result = runner.invoke(fetch, ["patch", "--help"])

        assert result.exit_code == 0
        assert "Fetch patch file" in result.output

    def test_manifests_help(self, runner):
        """Test manifests subcommand shows help."""
        result = runner.invoke(fetch, ["manifests", "--help"])

        assert result.exit_code == 0
        assert "Fetch TACT manifests" in result.output

    def test_data_invalid_hash_additional(self, enhanced_cli_test_setup):
        """Test data command with invalid hash - additional case."""
        setup = enhanced_cli_test_setup
        runner = setup['runner']
        console = setup['console']

        # Mock hash validation to return False for invalid hash
        with patch('cascette_tools.commands.fetch.validate_hash_string', return_value=False):
            result = runner.invoke(fetch, ["data", "toolong1234567890abcdef1234567890abcdef"])

            assert result.exit_code != 0
            # Check if error message was printed to console
            printed_text = ' '.join(console.printed_lines)
            assert "Invalid hash format" in printed_text or "Invalid hash format" in result.output

    @patch("cascette_tools.commands.fetch._get_context_objects")
    @patch("cascette_tools.commands.fetch.TACTClient")
    def test_build_network_error(
        self,
        mock_tact_class,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test build command with network error."""
        mock_get_context.return_value = mock_context_objects
        mock_tact = Mock()
        mock_tact_class.return_value = mock_tact
        mock_tact.fetch_versions.side_effect = Exception("Network error")

        result = runner.invoke(fetch, ["build", "invalidversion"])

        assert result.exit_code != 0
        assert "Error" in result.output

    @patch("cascette_tools.commands.fetch._get_context_objects")
    def test_batch_empty_hash_file(
        self,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with empty hash file."""
        mock_get_context.return_value = mock_context_objects

        # Create empty hash list file
        hash_list = tmp_path / "empty.txt"
        hash_list.write_text("")

        result = runner.invoke(fetch, ["batch", str(hash_list)])

        # Should handle empty file by showing error
        assert result.exit_code != 0
        assert "No valid hashes found" in result.output

    @patch("cascette_tools.commands.fetch._get_context_objects")
    def test_batch_invalid_hashes(
        self,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with invalid hashes in file."""
        mock_get_context.return_value = mock_context_objects

        # Create hash list with invalid entries
        hash_list = tmp_path / "invalid.txt"
        hash_list.write_text("invalid_hash\nshort\n")

        result = runner.invoke(fetch, ["batch", str(hash_list)])

        # Should skip invalid hashes and show error if no valid hashes
        assert result.exit_code != 0
        assert "No valid hashes found" in result.output


class TestFetchUtilityFunctions:
    """Test utility functions used by fetch commands."""

    def test_get_context_objects(self):
        """Test _get_context_objects extracts context properly."""
        mock_config = Mock(spec=AppConfig)
        mock_console = Mock(spec=Console)

        ctx = Mock()
        ctx.obj = {
            "config": mock_config,
            "console": mock_console,
            "verbose": True,
            "debug": False
        }

        config, console, verbose, debug = _get_context_objects(ctx)

        assert config is mock_config
        assert console is mock_console
        assert verbose is True
        assert debug is False

    # test_output_json removed: _output_json function no longer exists in fetch module

    def test_save_file(self, tmp_path):
        """Test _save_file saves data and creates directories."""
        mock_console = Mock(spec=Console)
        data = b"test file content"
        output_path = tmp_path / "subdir" / "test.txt"

        _save_file(data, output_path, mock_console, verbose=True)

        assert output_path.exists()
        assert output_path.read_bytes() == data
        assert output_path.parent.exists()
        mock_console.print.assert_called_once()

    def test_save_file_no_verbose(self, tmp_path):
        """Test _save_file without verbose output."""
        mock_console = Mock(spec=Console)
        data = b"test content"
        output_path = tmp_path / "test.txt"

        _save_file(data, output_path, mock_console, verbose=False)

        assert output_path.exists()
        assert output_path.read_bytes() == data
        mock_console.print.assert_not_called()

    @patch("cascette_tools.commands.fetch.BuildConfigParser")
    def test_show_config_metadata_build(self, mock_parser_class):
        """Test _show_config_metadata for build config."""
        mock_console = Mock(spec=Console)
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser

        mock_config = Mock()
        mock_config.root = "test_root_hash"
        mock_config.encoding = "test_encoding_hash"
        mock_config.install = "test_install_hash"
        mock_config.download = "test_download_hash"
        mock_parser.parse.return_value = mock_config

        data = b"# Build Config\nroot = test_root_hash\n"

        _show_config_metadata(data, "build", mock_console)

        mock_console.print.assert_called()
        mock_parser.parse.assert_called_once()

    @patch("cascette_tools.commands.fetch.CDNConfigParser")
    def test_show_config_metadata_cdn(self, mock_parser_class):
        """Test _show_config_metadata for CDN config."""
        mock_console = Mock(spec=Console)
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser

        mock_config = Mock()
        mock_config.archives = ["archive1", "archive2"]
        mock_config.patch_archives = ["patch1"]
        mock_parser.parse.return_value = mock_config

        data = b"# CDN Config\narchives = archive1 archive2\n"

        _show_config_metadata(data, "cdn", mock_console)

        mock_console.print.assert_called()
        mock_parser.parse.assert_called_once()

    @patch("cascette_tools.commands.fetch.ProductConfigParser")
    def test_show_config_metadata_product(self, mock_parser_class):
        """Test _show_config_metadata for product config."""
        mock_console = Mock(spec=Console)
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser

        mock_config = Mock()
        mock_config.product = "wow"
        mock_config.uid = "test_uid"
        mock_parser.parse.return_value = mock_config

        data = b"# Product Config\nproduct = wow\n"

        _show_config_metadata(data, "product", mock_console)

        mock_console.print.assert_called()
        mock_parser.parse.assert_called_once()

    def test_show_config_metadata_unknown_type(self):
        """Test _show_config_metadata with unknown config type."""
        mock_console = Mock(spec=Console)
        data = b"# Unknown Config\ntest = value\n"

        _show_config_metadata(data, "unknown", mock_console)

        mock_console.print.assert_called()

    def test_show_config_metadata_parse_error(self):
        """Test _show_config_metadata handles parsing errors gracefully."""
        mock_console = Mock(spec=Console)
        data = b"invalid utf-8 \xff\xfe"

        _show_config_metadata(data, None, mock_console)

        mock_console.print.assert_called()


