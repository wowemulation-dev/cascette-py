"""Tests for analyze command module."""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.table import Table

from cascette_tools.commands.analyze import (
    _analyze_archive_stats,
    _analyze_blte_compression,
    _analyze_blte_stats,
    _analyze_config_stats,
    _analyze_download_stats,
    _analyze_encoding_stats,
    _analyze_install_stats,
    _analyze_root_stats,
    _detect_format_type,
    _display_stats_table,
    _fetch_from_cdn_or_path,
    _get_context_objects,
    _output_json,
    _output_table,
    analyze,
)
from cascette_tools.core.config import AppConfig


class TestAnalyzeCommands:
    """Test analyze command functionality."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def mock_config(self):
        """Create mock app config."""
        config = Mock(spec=AppConfig)
        config.output_format = "rich"
        config.cache = Mock()
        config.cdn = Mock()
        config.cdn_timeout = 30
        config.cdn_max_retries = 3
        return config

    @pytest.fixture
    def mock_console(self):
        """Create mock Rich console."""
        return Mock(spec=Console)

    @pytest.fixture
    def mock_context_objects(self, mock_config, mock_console):
        """Create mock context objects."""
        return mock_config, mock_console, False, False

    @pytest.fixture
    def mock_verbose_context_objects(self, mock_config, mock_console):
        """Create mock context objects with verbose enabled."""
        return mock_config, mock_console, True, False

    @pytest.fixture
    def sample_blte_data(self):
        """Create sample BLTE file data."""
        return b"BLTE" + b"\x00" * 8 + b"test data content"

    @pytest.fixture
    def sample_encoding_data(self):
        """Create sample encoding file data."""
        return b"EN" + b"\x02\x00" + b"\x00" * 100

    @pytest.fixture
    def sample_archive_data(self):
        """Create sample archive index data."""
        data = b"test archive data" + b"\x00" * 100
        footer_data = b"\x10" * 16 + b"\x08\x00\x00\x00" + b"\x10\x00\x00\x00"
        return data + footer_data

    @pytest.fixture
    def sample_config_data(self):
        """Create sample config file data."""
        return b"# Build Configuration\nroot = abcdef1234567890abcdef1234567890\ninstall = 1234567890abcdef1234567890abcdef\n"

    @pytest.fixture
    def sample_root_data(self):
        """Create sample root file data."""
        return b"TSFM" + b"\x00" * 12 + b"root file content"

    @pytest.fixture
    def sample_install_data(self):
        """Create sample install file data."""
        return b"IN" + b"\x00" * 20 + b"install manifest content"

    @pytest.fixture
    def sample_download_data(self):
        """Create sample download file data."""
        return b"DL" + b"\x00" * 20 + b"download manifest content"

    def test_analyze_group_help(self, runner):
        """Test analyze group shows help when invoked without subcommand."""
        result = runner.invoke(analyze, [])

        assert result.exit_code == 0
        assert "Analyze NGDP/CASC format files and data" in result.output
        assert "stats" in result.output
        assert "dependencies" in result.output
        assert "coverage" in result.output
        assert "compression" in result.output

    def test_analyze_group_help_flag(self, runner):
        """Test analyze group shows help when invoked with --help."""
        result = runner.invoke(analyze, ["--help"])

        assert result.exit_code == 0
        assert "Analyze NGDP/CASC format files and data" in result.output

    # Stats Command Tests
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._detect_format_type")
    @patch("cascette_tools.commands.analyze._analyze_blte_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_blte_file_auto_detect(
        self,
        mock_display_table,
        mock_analyze_blte,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test stats command with BLTE file using auto-detection."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_detect_format.return_value = "blte"
        mock_analyze_blte.return_value = {
            "chunk_count": 2,
            "total_compressed_size": 100,
            "total_decompressed_size": 200,
            "compression_ratio": 0.5
        }

        result = runner.invoke(analyze, ["stats", "test.blte"])

        assert result.exit_code == 0
        mock_fetch.assert_called_once()
        mock_detect_format.assert_called_once_with(sample_blte_data)
        mock_analyze_blte.assert_called_once_with(sample_blte_data)
        mock_display_table.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._analyze_encoding_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_encoding_file_explicit_type(
        self,
        mock_display_table,
        mock_analyze_encoding,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test stats command with encoding file and explicit format type."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data
        mock_analyze_encoding.return_value = {
            "version": 1,
            "ckey_size": 16,
            "ekey_size": 16,
            "ckey_page_count": 5,
            "ekey_page_count": 3
        }

        result = runner.invoke(analyze, ["stats", "test.encoding", "--format-type", "encoding"])

        assert result.exit_code == 0
        mock_fetch.assert_called_once()
        mock_analyze_encoding.assert_called_once_with(sample_encoding_data)
        mock_display_table.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._detect_format_type")
    @patch("cascette_tools.commands.analyze._analyze_config_stats")
    @patch("cascette_tools.commands.analyze._output_json")
    def test_stats_config_file_json_output(
        self,
        mock_output_json,
        mock_analyze_config,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        sample_config_data
    ):
        """Test stats command with config file using JSON output."""
        config, console, verbose, debug = Mock(), Mock(), False, False
        config.output_format = "json"
        mock_get_context.return_value = config, console, verbose, debug
        mock_fetch.return_value = sample_config_data
        mock_detect_format.return_value = "build"
        mock_analyze_config.return_value = {
            "config_type": "build",
            "entry_count": 2,
            "entries": {"root": "abc123", "install": "def456"}
        }

        result = runner.invoke(analyze, ["stats", "test.config"])

        assert result.exit_code == 0
        mock_fetch.assert_called_once()
        mock_detect_format.assert_called_once_with(sample_config_data)
        mock_analyze_config.assert_called_once_with(sample_config_data, "build")
        mock_output_json.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._detect_format_type")
    def test_stats_auto_detect_unknown_format(
        self,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command when auto-detection returns unknown format."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"unknown data"
        mock_detect_format.return_value = "unknown"

        result = runner.invoke(analyze, ["stats", "test.unknown"])

        assert result.exit_code != 0
        assert "Could not auto-detect format type" in result.output

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_unsupported_format_type(
        self,
        mock_display_table,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test stats command with format type that has no analysis implementation."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data

        result = runner.invoke(analyze, ["stats", "test.blte", "--format-type", "config"])

        assert result.exit_code == 0
        # Should handle gracefully and show error in stats data
        mock_display_table.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_stats_fetch_error(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command with fetch error."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.side_effect = Exception("Network error")

        result = runner.invoke(analyze, ["stats", "test_hash"])

        assert result.exit_code != 0
        assert "Failed to analyze file" in result.output

    # Dependencies Command Tests
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_dependencies_valid_content_key(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test dependencies command with valid content key."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data

        with patch("cascette_tools.formats.EncodingParser") as mock_parser:
            mock_encoding = Mock()
            mock_encoding.header = Mock()
            mock_encoding.header.ckey_size = 16
            mock_encoding.header.ekey_size = 16
            mock_encoding.header.ckey_page_count = 5
            mock_encoding.header.ekey_page_count = 3
            mock_parser.return_value.parse.return_value = mock_encoding

            result = runner.invoke(analyze, [
                "dependencies",
                "test.encoding",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code == 0

    @patch("cascette_tools.commands.analyze._get_context_objects")
    def test_dependencies_invalid_content_key(
        self,
        mock_get_context,
        runner
    ):
        """Test dependencies command with invalid content key hex string."""
        mock_get_context.return_value = Mock(), Mock(), False, False

        result = runner.invoke(analyze, [
            "dependencies",
            "test.encoding",
            "invalid_hex_string"
        ])

        assert result.exit_code != 0
        # Check that the command failed due to hex validation
        assert "Invalid content key hex string" in result.output or result.exception is not None

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_dependencies_with_archive_details(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test dependencies command with archive details flag."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data

        with patch("cascette_tools.formats.EncodingParser") as mock_parser:
            mock_encoding = Mock()
            mock_encoding.header = Mock()
            mock_encoding.header.ckey_size = 16
            mock_encoding.header.ekey_size = 16
            mock_encoding.header.ckey_page_count = 5
            mock_encoding.header.ekey_page_count = 3
            mock_parser.return_value.parse.return_value = mock_encoding

            result = runner.invoke(analyze, [
                "dependencies",
                "test.encoding",
                "abcdef1234567890abcdef1234567890",
                "--show-archive-details"
            ])

            assert result.exit_code == 0

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_dependencies_parser_error(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test dependencies command with parser error."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"invalid data"

        with patch("cascette_tools.formats.EncodingParser") as mock_parser:
            mock_parser.return_value.parse.side_effect = Exception("Parse error")

            result = runner.invoke(analyze, [
                "dependencies",
                "test.encoding",
                "abcdef1234567890abcdef1234567890"
            ])

            assert result.exit_code != 0
            assert "Failed to analyze dependencies" in result.output

    # Coverage Command Tests
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_coverage_encoding_only(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test coverage command with encoding file only."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data

        with patch("cascette_tools.formats.EncodingParser") as mock_parser:
            mock_encoding = Mock()
            mock_encoding.header = Mock()
            mock_encoding.header.ckey_page_count = 5
            mock_encoding.header.ekey_page_count = 3
            mock_parser.return_value.parse.return_value = mock_encoding

            result = runner.invoke(analyze, ["coverage", "test.encoding"])

            assert result.exit_code == 0

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    def test_coverage_encoding_with_root_and_install(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test coverage command with encoding, root, and install files."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.side_effect = [b"encoding data", b"root data", b"install data"]

        with patch("cascette_tools.commands.analyze.EncodingParser") as mock_encoding_parser:
            with patch("cascette_tools.commands.analyze.RootParser") as mock_root_parser:
                with patch("cascette_tools.commands.analyze.InstallParser") as mock_install_parser:
                    # Mock encoding
                    mock_encoding = Mock()
                    mock_encoding.header = Mock()
                    mock_encoding.header.ckey_page_count = 5
                    mock_encoding.header.ekey_page_count = 3
                    mock_encoding_parser.return_value.parse.return_value = mock_encoding

                    # Mock root
                    mock_root = Mock()
                    mock_root.header = Mock()
                    mock_root.header.version = 1
                    mock_block = Mock()
                    mock_block.records = [Mock(), Mock()]
                    mock_root.blocks = [mock_block]
                    mock_root_parser.return_value.parse.return_value = mock_root

                    # Mock install
                    mock_install = Mock()
                    mock_install.entries = [Mock(), Mock(), Mock()]
                    mock_install.tags = [Mock()]
                    mock_install_parser.return_value.parse.return_value = mock_install

                    result = runner.invoke(analyze, [
                        "coverage",
                        "test.encoding",
                        "test.root",
                        "test.install"
                    ])

                    # Debug output if test fails
                    if result.exit_code != 0:
                        print(f"Exit code: {result.exit_code}")
                        print(f"Output: {result.output}")
                        print(f"Exception: {result.exception}")
                        import traceback
                        if result.exc_info:
                            traceback.print_exception(*result.exc_info)

                    assert result.exit_code == 0

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._output_json")
    def test_coverage_json_output(
        self,
        mock_output_json,
        mock_fetch,
        mock_get_context,
        runner,
        sample_encoding_data
    ):
        """Test coverage command with JSON output."""
        config, console, verbose, debug = Mock(), Mock(), False, False
        config.output_format = "json"
        mock_get_context.return_value = config, console, verbose, debug
        mock_fetch.return_value = sample_encoding_data

        with patch("cascette_tools.formats.EncodingParser") as mock_parser:
            mock_encoding = Mock()
            mock_encoding.header = Mock()
            mock_encoding.header.ckey_page_count = 5
            mock_encoding.header.ekey_page_count = 3
            mock_parser.return_value.parse.return_value = mock_encoding

            result = runner.invoke(analyze, ["coverage", "test.encoding"])

            assert result.exit_code == 0
            mock_output_json.assert_called_once()

    # Compression Command Tests
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze.is_blte")
    @patch("cascette_tools.commands.analyze._analyze_blte_compression")
    def test_compression_blte_file(
        self,
        mock_analyze_compression,
        mock_is_blte,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test compression command with BLTE file."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_is_blte.return_value = True
        mock_analyze_compression.return_value = {
            "total_compressed_size": 100,
            "total_decompressed_size": 200,
            "overall_compression_ratio": 0.5,
            "chunk_count": 3,
            "compression_modes": {"zlib": 2, "none": 1},
            "chunk_details": [
                {"compressed_size": 50, "decompressed_size": 100, "compression_mode": "zlib", "ratio": 0.5},
                {"compressed_size": 30, "decompressed_size": 60, "compression_mode": "zlib", "ratio": 0.5},
                {"compressed_size": 20, "decompressed_size": 40, "compression_mode": "none", "ratio": 0.5}
            ]
        }

        result = runner.invoke(analyze, ["compression", "test.blte"])

        assert result.exit_code == 0
        mock_analyze_compression.assert_called_once_with(sample_blte_data)

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze.is_blte")
    @patch("cascette_tools.commands.analyze._analyze_blte_compression")
    def test_compression_with_verbose_and_poorly_compressed_chunks(
        self,
        mock_analyze_compression,
        mock_is_blte,
        mock_fetch,
        mock_get_context,
        runner,
        mock_verbose_context_objects,
        sample_blte_data
    ):
        """Test compression command with verbose mode and poorly compressed chunks."""
        mock_get_context.return_value = mock_verbose_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_is_blte.return_value = True
        mock_analyze_compression.return_value = {
            "total_compressed_size": 180,
            "total_decompressed_size": 200,
            "overall_compression_ratio": 0.9,
            "chunk_count": 2,
            "compression_modes": {"zlib": 1, "none": 1},
            "chunk_details": [
                {"compressed_size": 80, "decompressed_size": 100, "compression_mode": "zlib", "ratio": 0.8},
                {"compressed_size": 100, "decompressed_size": 100, "compression_mode": "none", "ratio": 1.0}
            ]
        }

        result = runner.invoke(analyze, ["compression", "test.blte", "--threshold", "0.9", "--limit", "5"])

        assert result.exit_code == 0

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze.is_blte")
    def test_compression_non_blte_file(
        self,
        mock_is_blte,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test compression command with non-BLTE file."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"not blte data"
        mock_is_blte.return_value = False

        result = runner.invoke(analyze, ["compression", "test.dat"])

        assert result.exit_code != 0
        assert "Input file is not a BLTE file" in result.output

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze.is_blte")
    @patch("cascette_tools.commands.analyze._analyze_blte_compression")
    def test_compression_analysis_error(
        self,
        mock_analyze_compression,
        mock_is_blte,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test compression command when analysis returns error."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_is_blte.return_value = True
        mock_analyze_compression.return_value = {"error": "Failed to parse BLTE"}

        result = runner.invoke(analyze, ["compression", "test.blte"])

        assert result.exit_code != 0
        assert "Failed to parse BLTE" in result.output

    # Help Tests
    def test_stats_help(self, runner):
        """Test stats subcommand shows help."""
        result = runner.invoke(analyze, ["stats", "--help"])

        assert result.exit_code == 0
        assert "Analyze format files and show statistics" in result.output
        assert "INPUT can be either a file path or CDN hash" in result.output

    def test_dependencies_help(self, runner):
        """Test dependencies subcommand shows help."""
        result = runner.invoke(analyze, ["dependencies", "--help"])

        assert result.exit_code == 0
        assert "Analyze file dependencies by tracing content key" in result.output

    def test_coverage_help(self, runner):
        """Test coverage subcommand shows help."""
        result = runner.invoke(analyze, ["coverage", "--help"])

        assert result.exit_code == 0
        assert "Analyze content coverage between encoding, root, and install manifests" in result.output

    def test_compression_help(self, runner):
        """Test compression subcommand shows help."""
        result = runner.invoke(analyze, ["compression", "--help"])

        assert result.exit_code == 0
        assert "Analyze BLTE compression effectiveness" in result.output


class TestAnalyzeHelperFunctions:
    """Test helper functions in analyze module."""

    @pytest.fixture
    def mock_config(self):
        """Create mock app config."""
        config = Mock(spec=AppConfig)
        config.output_format = "rich"
        config.cache = Mock()
        config.cdn = Mock()
        config.cdn_timeout = 30
        config.cdn_max_retries = 3
        return config

    @pytest.fixture
    def mock_console(self):
        """Create mock Rich console."""
        return Mock(spec=Console)

    @pytest.fixture
    def mock_context(self, mock_config, mock_console):
        """Create mock click context."""
        ctx = Mock()
        ctx.obj = {
            "config": mock_config,
            "console": mock_console,
            "verbose": True,
            "debug": False
        }
        return ctx

    def test_get_context_objects(self, mock_context, mock_config, mock_console):
        """Test _get_context_objects helper function."""
        config, console, verbose, debug = _get_context_objects(mock_context)

        assert config == mock_config
        assert console == mock_console
        assert verbose is True
        assert debug is False

    def test_output_json(self, mock_console, capsys):
        """Test _output_json helper function."""
        test_data = {"key": "value", "number": 42, "nested": {"sub": "data"}}

        _output_json(test_data, mock_console)

        captured = capsys.readouterr()
        assert json.loads(captured.out) == test_data

    def test_output_table(self, mock_console):
        """Test _output_table helper function."""
        table = Table(title="Test Table")
        table.add_column("Column 1")
        table.add_row("Value 1")

        _output_table(table, mock_console)

        mock_console.print.assert_called_once_with(table)

    def test_fetch_from_cdn_or_path_file_exists(self, mock_config, mock_console, tmp_path):
        """Test _fetch_from_cdn_or_path with existing file."""
        test_data = b"test file content"
        test_file = tmp_path / "test.dat"
        test_file.write_bytes(test_data)

        result = _fetch_from_cdn_or_path(str(test_file), mock_console, mock_config)

        assert result == test_data

    def test_fetch_from_cdn_or_path_file_read_error(self, mock_config, mock_console):
        """Test _fetch_from_cdn_or_path with file read error."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_bytes", side_effect=OSError("Permission denied")):
                with pytest.raises(Exception, match="Failed to read file"):
                    _fetch_from_cdn_or_path("/test/file.dat", mock_console, mock_config)

    @patch("cascette_tools.commands.analyze.Progress")
    @patch("cascette_tools.commands.analyze.validate_hash_string")
    @patch("cascette_tools.commands.analyze.CDNConfig")
    @patch("cascette_tools.commands.analyze.CDNClient")
    def test_fetch_from_cdn_or_path_valid_hash(
        self, mock_cdn_class, mock_cdn_config_class, mock_validate_hash, mock_progress_class, mock_config, mock_console
    ):
        """Test _fetch_from_cdn_or_path with valid hash."""
        mock_validate_hash.return_value = True
        mock_cdn_config = Mock()
        mock_cdn_config_class.return_value = mock_cdn_config
        mock_cdn = Mock()
        mock_cdn.fetch_data.return_value = b"cdn data"
        mock_cdn_class.return_value = mock_cdn

        # Mock Progress as a context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock()
        mock_progress_class.return_value = mock_progress

        result = _fetch_from_cdn_or_path("abc123def456", mock_console, mock_config)

        assert result == b"cdn data"
        mock_cdn.fetch_data.assert_called_once_with("abc123def456")

    @patch("cascette_tools.commands.analyze.validate_hash_string")
    def test_fetch_from_cdn_or_path_invalid_hash(self, mock_validate_hash, mock_config, mock_console):
        """Test _fetch_from_cdn_or_path with invalid hash."""
        mock_validate_hash.return_value = False

        with pytest.raises(Exception, match="Invalid input: not a valid file path or hash"):
            _fetch_from_cdn_or_path("invalid_hash", mock_console, mock_config)

    @patch("cascette_tools.commands.analyze.Progress")
    @patch("cascette_tools.commands.analyze.validate_hash_string")
    @patch("cascette_tools.commands.analyze.CDNConfig")
    @patch("cascette_tools.commands.analyze.CDNClient")
    def test_fetch_from_cdn_or_path_cdn_error(
        self, mock_cdn_class, mock_cdn_config_class, mock_validate_hash, mock_progress_class, mock_config, mock_console
    ):
        """Test _fetch_from_cdn_or_path with CDN fetch error."""
        mock_validate_hash.return_value = True
        mock_cdn_config = Mock()
        mock_cdn_config_class.return_value = mock_cdn_config
        mock_cdn = Mock()
        mock_cdn.fetch_data.side_effect = Exception("CDN error")
        mock_cdn_class.return_value = mock_cdn

        # Mock Progress as a context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock()
        mock_progress_class.return_value = mock_progress

        with pytest.raises(Exception, match="Failed to fetch from CDN"):
            _fetch_from_cdn_or_path("abc123def456", mock_console, mock_config)

    def test_detect_format_type_blte(self):
        """Test _detect_format_type with BLTE data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=True):
            result = _detect_format_type(b"BLTE data")
            assert result == "blte"

    def test_detect_format_type_encoding(self):
        """Test _detect_format_type with encoding data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=True):
                result = _detect_format_type(b"encoding data")
                assert result == "encoding"

    def test_detect_format_type_config(self):
        """Test _detect_format_type with config data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=True):
                    with patch("cascette_tools.commands.analyze.detect_config_type", return_value="build"):
                        result = _detect_format_type(b"config data")
                        assert result == "build"

    def test_detect_format_type_config_unknown_type(self):
        """Test _detect_format_type with config data of unknown type."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=True):
                    with patch("cascette_tools.commands.analyze.detect_config_type", return_value=None):
                        result = _detect_format_type(b"config data")
                        assert result == "unknown"

    def test_detect_format_type_root(self):
        """Test _detect_format_type with root data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=False):
                    with patch("cascette_tools.commands.analyze.is_root", return_value=True):
                        result = _detect_format_type(b"root data")
                        assert result == "root"

    def test_detect_format_type_install(self):
        """Test _detect_format_type with install data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=False):
                    with patch("cascette_tools.commands.analyze.is_root", return_value=False):
                        with patch("cascette_tools.commands.analyze.is_install", return_value=True):
                            result = _detect_format_type(b"install data")
                            assert result == "install"

    def test_detect_format_type_download(self):
        """Test _detect_format_type with download data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=False):
                    with patch("cascette_tools.commands.analyze.is_root", return_value=False):
                        with patch("cascette_tools.commands.analyze.is_install", return_value=False):
                            with patch("cascette_tools.commands.analyze.is_download", return_value=True):
                                result = _detect_format_type(b"download data")
                                assert result == "download"

    def test_detect_format_type_archive_by_padding(self):
        """Test _detect_format_type with archive data detected by padding."""
        archive_data = b"test data" + b"\x00" * 12  # Ends with null padding
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=False):
                    with patch("cascette_tools.commands.analyze.is_root", return_value=False):
                        with patch("cascette_tools.commands.analyze.is_install", return_value=False):
                            with patch("cascette_tools.commands.analyze.is_download", return_value=False):
                                result = _detect_format_type(archive_data)
                                assert result == "archive"

    def test_detect_format_type_unknown(self):
        """Test _detect_format_type with unknown data."""
        with patch("cascette_tools.commands.analyze.is_blte", return_value=False):
            with patch("cascette_tools.commands.analyze.is_encoding", return_value=False):
                with patch("cascette_tools.commands.analyze.is_config_file", return_value=False):
                    with patch("cascette_tools.commands.analyze.is_root", return_value=False):
                        with patch("cascette_tools.commands.analyze.is_install", return_value=False):
                            with patch("cascette_tools.commands.analyze.is_download", return_value=False):
                                result = _detect_format_type(b"unknown")
                                assert result == "unknown"


class TestAnalyzeCompressionAnalysis:
    """Test _analyze_blte_compression function."""

    @patch("cascette_tools.commands.analyze.BLTEParser")
    def test_analyze_blte_compression_success(self, mock_parser):
        """Test BLTE compression analysis success case."""
        mock_blte = Mock()

        # Create mock chunks with different compression modes
        mock_chunk1 = Mock()
        mock_chunk1.compressed_size = 100
        mock_chunk1.decompressed_size = 200
        mock_chunk1.compression_mode = Mock()
        mock_chunk1.compression_mode.name = "zlib"

        mock_chunk2 = Mock()
        mock_chunk2.compressed_size = 50
        mock_chunk2.decompressed_size = 50
        mock_chunk2.compression_mode = Mock()
        mock_chunk2.compression_mode.name = "none"

        mock_blte.chunks = [mock_chunk1, mock_chunk2]
        mock_parser.return_value.parse.return_value = mock_blte

        result = _analyze_blte_compression(b"blte data")

        assert result["total_compressed_size"] == 150
        assert result["total_decompressed_size"] == 250
        assert result["overall_compression_ratio"] == 0.6
        assert result["chunk_count"] == 2
        assert result["compression_modes"] == {"zlib": 1, "none": 1}
        assert len(result["chunk_details"]) == 2

    @patch("cascette_tools.commands.analyze.BLTEParser")
    def test_analyze_blte_compression_zero_decompressed(self, mock_parser):
        """Test BLTE compression analysis with zero decompressed size."""
        mock_blte = Mock()

        mock_chunk = Mock()
        mock_chunk.compressed_size = 100
        mock_chunk.decompressed_size = 0
        mock_chunk.compression_mode = Mock()
        mock_chunk.compression_mode.name = "zlib"

        mock_blte.chunks = [mock_chunk]
        mock_parser.return_value.parse.return_value = mock_blte

        result = _analyze_blte_compression(b"blte data")

        assert result["overall_compression_ratio"] == 0
        assert result["chunk_details"][0]["ratio"] == 0

    @patch("cascette_tools.commands.analyze.BLTEParser")
    def test_analyze_blte_compression_parser_error(self, mock_parser):
        """Test BLTE compression analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_blte_compression(b"invalid blte")

        assert "error" in result
        assert "Failed to analyze BLTE" in result["error"]


class TestAnalyzeStatsHelpers:
    """Test format-specific stats analysis helper functions."""

    @patch("cascette_tools.commands.analyze.BLTEParser")
    def test_analyze_blte_stats_success(self, mock_parser):
        """Test BLTE stats analysis success case."""
        mock_blte = Mock()
        mock_blte.header = Mock()
        mock_blte.header.header_size = 12
        mock_blte.header.flags = 0x01

        mock_chunk1 = Mock()
        mock_chunk1.compressed_size = 100
        mock_chunk1.decompressed_size = 200

        mock_chunk2 = Mock()
        mock_chunk2.compressed_size = 50
        mock_chunk2.decompressed_size = 100

        mock_blte.chunks = [mock_chunk1, mock_chunk2]
        mock_parser.return_value.parse.return_value = mock_blte

        result = _analyze_blte_stats(b"blte data")

        assert result["chunk_count"] == 2
        assert result["total_compressed_size"] == 150
        assert result["total_decompressed_size"] == 300
        assert result["compression_ratio"] == 0.5
        assert result["header_size"] == 12
        assert result["flags"] == 0x01

    @patch("cascette_tools.commands.analyze.BLTEParser")
    def test_analyze_blte_stats_parser_error(self, mock_parser):
        """Test BLTE stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_blte_stats(b"invalid blte")

        assert "error" in result
        assert "Failed to parse BLTE" in result["error"]

    @patch("cascette_tools.commands.analyze.EncodingParser")
    def test_analyze_encoding_stats_success(self, mock_parser):
        """Test encoding stats analysis success case."""
        mock_encoding = Mock()
        mock_encoding.header = Mock()
        mock_encoding.header.version = 1
        mock_encoding.header.ckey_size = 16
        mock_encoding.header.ekey_size = 16
        mock_encoding.header.ckey_page_count = 5
        mock_encoding.header.ekey_page_count = 3
        mock_encoding.header.ckey_page_size_kb = 4
        mock_encoding.header.ekey_page_size_kb = 4
        mock_encoding.header.espec_size = 100
        mock_parser.return_value.parse.return_value = mock_encoding

        result = _analyze_encoding_stats(b"encoding data")

        assert result["version"] == 1
        assert result["ckey_size"] == 16
        assert result["ekey_size"] == 16
        assert result["ckey_page_count"] == 5
        assert result["ekey_page_count"] == 3
        assert result["ckey_page_size_kb"] == 4
        assert result["ekey_page_size_kb"] == 4
        assert result["espec_size"] == 100

    @patch("cascette_tools.commands.analyze.EncodingParser")
    def test_analyze_encoding_stats_parser_error(self, mock_parser):
        """Test encoding stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_encoding_stats(b"invalid encoding")

        assert "error" in result
        assert "Failed to parse encoding" in result["error"]

    @patch("cascette_tools.commands.analyze.BuildConfigParser")
    def test_analyze_config_stats_build_success(self, mock_parser):
        """Test build config stats analysis success case."""
        mock_config = Mock()
        mock_config.model_dump.return_value = {
            "root": "abc123",
            "install": ["def456"],
            "encoding": ["ghi789"]
        }
        mock_parser.return_value.parse.return_value = mock_config

        result = _analyze_config_stats(b"config data", "build")

        assert result["config_type"] == "build"
        assert result["entry_count"] == 3
        assert "entries" in result

    @patch("cascette_tools.commands.analyze.CDNConfigParser")
    def test_analyze_config_stats_cdn_success(self, mock_parser):
        """Test CDN config stats analysis success case."""
        mock_config = Mock()
        mock_config.model_dump.return_value = {
            "archives": ["archive1", "archive2"],
            "patch_archives": ["patch1"]
        }
        mock_parser.return_value.parse.return_value = mock_config

        result = _analyze_config_stats(b"config data", "cdn")

        assert result["config_type"] == "cdn"
        assert result["entry_count"] == 2

    @patch("cascette_tools.commands.analyze.PatchConfigParser")
    def test_analyze_config_stats_patch_success(self, mock_parser):
        """Test patch config stats analysis success case."""
        # Create a simple object that doesn't have model_dump method
        class MockPatchConfig:
            def __init__(self):
                self.patch_entry = "entry1"
                self.base_build = "build1"

        mock_config = MockPatchConfig()
        mock_parser.return_value.parse.return_value = mock_config

        result = _analyze_config_stats(b"config data", "patch")

        assert result["config_type"] == "patch"
        assert result["entry_count"] == 2

    @patch("cascette_tools.commands.analyze.ProductConfigParser")
    def test_analyze_config_stats_product_success(self, mock_parser):
        """Test product config stats analysis success case."""
        # Create a simple object that doesn't have model_dump method
        class MockProductConfig:
            def __init__(self):
                self.all_build_configs = ["config1", "config2"]
                self.active_build_config = "active_config"

        mock_config = MockProductConfig()
        mock_parser.return_value.parse.return_value = mock_config

        result = _analyze_config_stats(b"config data", "product")

        assert result["config_type"] == "product"
        assert result["entry_count"] == 2

    def test_analyze_config_stats_unknown_type(self):
        """Test config stats analysis with unknown config type."""
        result = _analyze_config_stats(b"config data", "unknown")

        assert "error" in result
        assert "Unknown config type" in result["error"]

    @patch("cascette_tools.commands.analyze.BuildConfigParser")
    def test_analyze_config_stats_parser_error(self, mock_parser):
        """Test config stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_config_stats(b"invalid config", "build")

        assert "error" in result
        assert "Failed to parse config" in result["error"]

    @patch("cascette_tools.commands.analyze.ArchiveIndexParser")
    def test_analyze_archive_stats_success(self, mock_parser):
        """Test archive stats analysis success case."""
        mock_archive = Mock()
        mock_archive.footer = Mock()
        mock_archive.footer.ekey_length = 16
        mock_archive.footer.version = 2
        mock_archive.footer.page_size_kb = 4

        # Create mock chunks with entries
        mock_chunk1 = Mock()
        mock_entry1 = Mock()
        mock_entry1.size = 100
        mock_entry2 = Mock()
        mock_entry2.size = 200
        mock_chunk1.entries = [mock_entry1, mock_entry2]

        mock_chunk2 = Mock()
        mock_entry3 = Mock()
        mock_entry3.size = 150
        mock_chunk2.entries = [mock_entry3]

        mock_archive.chunks = [mock_chunk1, mock_chunk2]
        mock_parser.return_value.parse.return_value = mock_archive

        result = _analyze_archive_stats(b"archive data")

        assert result["chunk_count"] == 2
        assert result["total_entries"] == 3
        assert result["total_content_size"] == 450
        assert result["ekey_length"] == 16
        assert result["version"] == 2
        assert result["page_size_kb"] == 4

    @patch("cascette_tools.commands.analyze.ArchiveIndexParser")
    def test_analyze_archive_stats_parser_error(self, mock_parser):
        """Test archive stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_archive_stats(b"invalid archive")

        assert "error" in result
        assert "Failed to parse archive" in result["error"]

    @patch("cascette_tools.commands.analyze.RootParser")
    def test_analyze_root_stats_success(self, mock_parser):
        """Test root stats analysis success case."""
        mock_root = Mock()
        mock_root.header = Mock()
        mock_root.header.version = 1
        mock_root.header.total_files = 1000
        mock_root.header.named_files = 800

        # Create mock blocks with records
        mock_block1 = Mock()
        mock_block1.records = [Mock(), Mock()]
        mock_block2 = Mock()
        mock_block2.records = [Mock()]
        mock_root.blocks = [mock_block1, mock_block2]

        mock_parser.return_value.parse.return_value = mock_root

        result = _analyze_root_stats(b"root data")

        assert result["version"] == 1
        assert result["block_count"] == 2
        assert result["total_records"] == 3
        assert result["total_files"] == 1000
        assert result["named_files"] == 800

    @patch("cascette_tools.commands.analyze.RootParser")
    def test_analyze_root_stats_parser_error(self, mock_parser):
        """Test root stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_root_stats(b"invalid root")

        assert "error" in result
        assert "Failed to parse root" in result["error"]

    @patch("cascette_tools.commands.analyze.InstallParser")
    def test_analyze_install_stats_success(self, mock_parser):
        """Test install stats analysis success case."""
        mock_install = Mock()

        mock_entry1 = Mock()
        mock_entry1.size = 100
        mock_entry2 = Mock()
        mock_entry2.size = 200
        mock_install.entries = [mock_entry1, mock_entry2]

        mock_install.tags = [Mock(), Mock(), Mock()]

        mock_parser.return_value.parse.return_value = mock_install

        result = _analyze_install_stats(b"install data")

        assert result["entry_count"] == 2
        assert result["tag_count"] == 3
        assert result["total_size"] == 300

    @patch("cascette_tools.commands.analyze.InstallParser")
    def test_analyze_install_stats_parser_error(self, mock_parser):
        """Test install stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_install_stats(b"invalid install")

        assert "error" in result
        assert "Failed to parse install" in result["error"]

    @patch("cascette_tools.commands.analyze.DownloadParser")
    def test_analyze_download_stats_success(self, mock_parser):
        """Test download stats analysis success case."""
        mock_download = Mock()

        mock_entry1 = Mock()
        mock_entry1.size = 150
        mock_entry1.priority = 1
        mock_entry2 = Mock()
        mock_entry2.size = 250
        mock_entry2.priority = 2
        mock_entry3 = Mock()
        mock_entry3.size = 100
        mock_entry3.priority = 1
        mock_download.entries = [mock_entry1, mock_entry2, mock_entry3]

        mock_download.tags = [Mock(), Mock()]

        mock_parser.return_value.parse.return_value = mock_download

        result = _analyze_download_stats(b"download data")

        assert result["entry_count"] == 3
        assert result["tag_count"] == 2
        assert result["total_size"] == 500
        assert result["priority_levels"] == 2  # Unique priority levels: 1, 2

    @patch("cascette_tools.commands.analyze.DownloadParser")
    def test_analyze_download_stats_parser_error(self, mock_parser):
        """Test download stats analysis with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse failed")

        result = _analyze_download_stats(b"invalid download")

        assert "error" in result
        assert "Failed to parse download" in result["error"]


class TestDisplayStatsTable:
    """Test _display_stats_table function."""

    @pytest.fixture
    def mock_console(self):
        """Create mock Rich console."""
        return Mock(spec=Console)

    def test_display_stats_table_basic(self, mock_console):
        """Test displaying basic stats table."""
        stats_data = {
            "format_type": "blte",
            "file_size": 1024,
            "md5": "abcdef123456789",
            "chunk_count": 3,
            "compression_ratio": 0.75
        }

        with patch("cascette_tools.commands.analyze.format_size") as mock_format_size:
            with patch("cascette_tools.commands.analyze._output_table") as mock_output_table:
                mock_format_size.side_effect = lambda x: f"{x}B"

                _display_stats_table(stats_data, mock_console, False)

                mock_output_table.assert_called_once()
                # Get the table that was passed to _output_table
                table_call = mock_output_table.call_args[0][0]
                assert table_call.title == "Blte File Statistics"

    def test_display_stats_table_with_size_formatting(self, mock_console):
        """Test stats table with size field formatting."""
        stats_data = {
            "format_type": "encoding",
            "file_size": 2048,
            "md5": "123abc",
            "total_compressed_size": 1024,
            "total_decompressed_size": 2048
        }

        with patch("cascette_tools.commands.analyze.format_size") as mock_format_size:
            with patch("cascette_tools.commands.analyze._output_table"):
                mock_format_size.side_effect = lambda x: f"{x//1024}KB"

                _display_stats_table(stats_data, mock_console, False)

                # Verify format_size was called for size fields
                assert mock_format_size.call_count >= 3  # file_size + 2 other size fields

    def test_display_stats_table_with_ratio_formatting(self, mock_console):
        """Test stats table with ratio field formatting."""
        stats_data = {
            "format_type": "blte",
            "file_size": 1024,
            "md5": "123abc",
            "compression_ratio": 0.666666
        }

        with patch("cascette_tools.commands.analyze.format_size") as mock_format_size:
            with patch("cascette_tools.commands.analyze._output_table") as mock_output_table:
                mock_format_size.return_value = "1KB"

                _display_stats_table(stats_data, mock_console, False)

                mock_output_table.assert_called_once()

    def test_display_stats_table_with_error(self, mock_console):
        """Test stats table display with error present."""
        stats_data = {
            "format_type": "blte",
            "file_size": 1024,
            "md5": "123abc",
            "error": "Parse failed"
        }

        with patch("cascette_tools.commands.analyze.format_size") as mock_format_size:
            with patch("cascette_tools.commands.analyze._output_table") as mock_output_table:
                mock_format_size.return_value = "1KB"

                _display_stats_table(stats_data, mock_console, False)

                mock_output_table.assert_called_once()

    def test_display_stats_table_excludes_internal_fields(self, mock_console):
        """Test that internal fields are excluded from display."""
        stats_data = {
            "input": "test.blte",  # Should be excluded
            "format_type": "blte",  # Should be excluded from data rows
            "file_size": 1024,  # Should be excluded from data rows
            "md5": "123abc",  # Should be excluded from data rows
            "chunk_count": 3,
            "compression_ratio": 0.5
        }

        with patch("cascette_tools.commands.analyze.format_size") as mock_format_size:
            with patch("cascette_tools.commands.analyze._output_table") as mock_output_table:
                mock_format_size.return_value = "1KB"

                _display_stats_table(stats_data, mock_console, False)

                mock_output_table.assert_called_once()


class TestComprehensiveCommandScenarios:
    """Test comprehensive command scenarios and edge cases."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def mock_context_objects(self):
        """Create mock context objects."""
        config = Mock(spec=AppConfig)
        config.output_format = "rich"
        config.cdn_timeout = 30
        config.cdn_max_retries = 3
        console = Mock(spec=Console)
        return config, console, False, False

    # Error handling edge cases
    def test_stats_command_exception_handling(self, runner):
        """Test stats command exception handling during analysis."""
        with patch("cascette_tools.commands.analyze._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path") as mock_fetch:
                mock_get_context.return_value = Mock(), Mock(), False, False
                mock_fetch.side_effect = Exception("Unexpected error")

                result = runner.invoke(analyze, ["stats", "test_hash"])

                assert result.exit_code != 0
                assert "Failed to analyze file" in result.output

    def test_dependencies_command_exception_handling(self, runner):
        """Test dependencies command exception handling."""
        with patch("cascette_tools.commands.analyze._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path") as mock_fetch:
                mock_get_context.return_value = Mock(), Mock(), False, False
                mock_fetch.side_effect = Exception("Unexpected error")

                result = runner.invoke(analyze, [
                    "dependencies",
                    "test.encoding",
                    "abcdef1234567890abcdef1234567890"
                ])

                assert result.exit_code != 0
                assert "Failed to analyze dependencies" in result.output

    def test_coverage_command_exception_handling(self, runner):
        """Test coverage command exception handling."""
        with patch("cascette_tools.commands.analyze._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path") as mock_fetch:
                mock_get_context.return_value = Mock(), Mock(), False, False
                mock_fetch.side_effect = Exception("Unexpected error")

                result = runner.invoke(analyze, ["coverage", "test.encoding"])

                assert result.exit_code != 0
                assert "Failed to analyze coverage" in result.output

    def test_compression_command_exception_handling(self, runner):
        """Test compression command exception handling."""
        with patch("cascette_tools.commands.analyze._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path") as mock_fetch:
                mock_get_context.return_value = Mock(), Mock(), False, False
                mock_fetch.side_effect = Exception("Unexpected error")

                result = runner.invoke(analyze, ["compression", "test.blte"])

                assert result.exit_code != 0
                assert "Failed to analyze compression" in result.output

    # All format types coverage for stats command
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._analyze_root_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_root_format(
        self,
        mock_display_table,
        mock_analyze_root,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command with root format."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"root data"
        mock_analyze_root.return_value = {
            "version": 1,
            "block_count": 5,
            "total_records": 100
        }

        result = runner.invoke(analyze, ["stats", "test.root", "--format-type", "root"])

        assert result.exit_code == 0
        mock_analyze_root.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._analyze_install_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_install_format(
        self,
        mock_display_table,
        mock_analyze_install,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command with install format."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"install data"
        mock_analyze_install.return_value = {
            "entry_count": 50,
            "tag_count": 10,
            "total_size": 1024000
        }

        result = runner.invoke(analyze, ["stats", "test.install", "--format-type", "install"])

        assert result.exit_code == 0
        mock_analyze_install.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._analyze_download_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_download_format(
        self,
        mock_display_table,
        mock_analyze_download,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command with download format."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"download data"
        mock_analyze_download.return_value = {
            "entry_count": 75,
            "tag_count": 5,
            "total_size": 2048000,
            "priority_levels": 3
        }

        result = runner.invoke(analyze, ["stats", "test.download", "--format-type", "download"])

        assert result.exit_code == 0
        mock_analyze_download.assert_called_once()

    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._analyze_archive_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_archive_format(
        self,
        mock_display_table,
        mock_analyze_archive,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test stats command with archive format."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"archive data"
        mock_analyze_archive.return_value = {
            "chunk_count": 10,
            "total_entries": 500,
            "total_content_size": 10240000,
            "ekey_length": 16,
            "version": 2
        }

        result = runner.invoke(analyze, ["stats", "test.index", "--format-type", "archive"])

        assert result.exit_code == 0
        mock_analyze_archive.assert_called_once()

    # Test all config subtypes
    @pytest.mark.parametrize("config_type", ["build", "cdn", "patch", "product"])
    @patch("cascette_tools.commands.analyze._get_context_objects")
    @patch("cascette_tools.commands.analyze._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.analyze._detect_format_type")
    @patch("cascette_tools.commands.analyze._analyze_config_stats")
    @patch("cascette_tools.commands.analyze._display_stats_table")
    def test_stats_all_config_types(
        self,
        mock_display_table,
        mock_analyze_config,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        config_type
    ):
        """Test stats command with all config format types."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"config data"
        mock_detect_format.return_value = config_type
        mock_analyze_config.return_value = {
            "config_type": config_type,
            "entry_count": 5,
            "entries": {"key1": "value1", "key2": "value2"}
        }

        result = runner.invoke(analyze, ["stats", f"test.{config_type}"])

        assert result.exit_code == 0
        mock_detect_format.assert_called_once_with(b"config data")
        mock_analyze_config.assert_called_once_with(b"config data", config_type)
