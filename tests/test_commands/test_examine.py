"""Tests for examine command module."""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.examine import examine
from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import CompressionMode
from cascette_tools.formats import (
    ArchiveIndex,
    ArchiveIndexChunk,
    ArchiveIndexEntry,
    ArchiveIndexFooter,
    BLTEChunk,
    BLTEFile,
    BLTEHeader,
    BuildConfig,
    EncodingFile,
    EncodingHeader,
)


class TestExamineCommands:
    """Test examine command functionality."""

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
    def sample_blte_data(self):
        """Create sample BLTE file data."""
        return (
            b"BLTE"  # Magic
            b"\x00\x00\x00\x00"  # Header size (0 = single chunk)
            b"N"  # Compression mode (no compression)
            b"Hello BLTE!"  # Data
        )

    @pytest.fixture
    def sample_blte_file(self):
        """Create sample BLTE file structure."""
        return BLTEFile(
            header=BLTEHeader(
                magic=b"BLTE",
                header_size=0,
                flags=None,
                chunk_count=None
            ),
            chunks=[
                BLTEChunk(
                    compressed_size=13,
                    decompressed_size=12,
                    checksum=b"\x00" * 16,
                    compression_mode=CompressionMode.NONE,
                    data=b"Hello BLTE!",
                    encryption_type=None,
                    encryption_key_name=None
                )
            ]
        )

    @pytest.fixture
    def sample_encoding_file(self):
        """Create sample encoding file structure."""
        return EncodingFile(
            header=EncodingHeader(
                magic=b"EN",
                version=1,
                ckey_size=16,
                ekey_size=16,
                ckey_page_size_kb=4,
                ekey_page_size_kb=4,
                ckey_page_count=1,
                ekey_page_count=1,
                unknown=0,
                espec_size=0
            ),
            espec_table=[],
            ckey_index=[(b"\x12\x34\x56\x78" + b"\x00" * 12, b"\x00" * 16)],  # Sample index entry (first_key, checksum)
            ekey_index=[(b"\xab\xcd\xef\x00" + b"\x00" * 12, b"\x00" * 16)]   # Sample index entry (first_key, checksum)
        )

    @pytest.fixture
    def sample_archive_index(self):
        """Create sample archive index structure."""
        return ArchiveIndex(
            footer=ArchiveIndexFooter(
                toc_hash=b"\x00" * 16,
                version=1,
                reserved=b"\x00" * 8,
                page_size_kb=4,
                offset_bytes=4,
                size_bytes=4,
                ekey_length=9,
                footer_hash_bytes=8,
                element_count=1,
                footer_hash=b"\x00" * 8
            ),
            chunks=[
                ArchiveIndexChunk(
                    chunk_index=0,
                    entries=[
                        ArchiveIndexEntry(
                            ekey=b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11",
                            size=1024,
                            offset=0
                        )
                    ],
                    last_key=b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11"
                )
            ],
            toc=[b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11"]  # Table of contents
        )

    def test_examine_blte_from_file(self, runner, tmp_path, sample_blte_data, sample_blte_file):
        """Test examine blte command with file input."""
        # Create test file
        test_file = tmp_path / "test.blte"
        test_file.write_bytes(sample_blte_data)

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.BLTEParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_blte_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["blte", str(test_file)])
                assert result.exit_code == 0
                mock_parser.parse.assert_called_once()

    def test_examine_blte_with_decompression(self, runner, tmp_path, sample_blte_data, sample_blte_file):
        """Test examine blte command with decompression."""
        test_file = tmp_path / "test.blte"
        test_file.write_bytes(sample_blte_data)

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_config.cdn_timeout = 30
            mock_config.cdn_max_retries = 3
            mock_console = Mock()
            mock_console.__enter__ = Mock(return_value=mock_console)
            mock_console.__exit__ = Mock(return_value=None)
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.decompress_blte") as mock_decompress:
                mock_decompress.return_value = b"Hello BLTE!"

                with patch("cascette_tools.commands.examine.BLTEParser") as mock_parser_class:
                    mock_parser = Mock()
                    mock_parser.parse.return_value = sample_blte_file
                    mock_parser_class.return_value = mock_parser

                    with patch("cascette_tools.commands.examine.Progress") as mock_progress_class:
                        mock_progress = Mock()
                        mock_progress.__enter__ = Mock(return_value=mock_progress)
                        mock_progress.__exit__ = Mock(return_value=None)
                        mock_progress_class.return_value = mock_progress

                        result = runner.invoke(examine, ["blte", str(test_file), "--decompress"])
                        assert result.exit_code == 0
                        mock_decompress.assert_called_once()

    def test_examine_blte_json_output(self, runner, tmp_path, sample_blte_data, sample_blte_file):
        """Test examine blte command with JSON output."""
        test_file = tmp_path / "test.blte"
        test_file.write_bytes(sample_blte_data)

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "json"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.BLTEParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_blte_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["blte", str(test_file)])
                assert result.exit_code == 0

                # Check that output is valid JSON
                output_lines = result.output.strip().split('\n')
                json_str = '\n'.join(output_lines)
                parsed_json = json.loads(json_str)
                assert "magic" in parsed_json
                assert "chunk_count" in parsed_json

    def test_examine_blte_output_file(self, runner, tmp_path, sample_blte_data, sample_blte_file):
        """Test examine blte command with output file."""
        test_file = tmp_path / "test.blte"
        output_file = tmp_path / "output.dat"
        test_file.write_bytes(sample_blte_data)

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_config.cdn_timeout = 30
            mock_config.cdn_max_retries = 3
            mock_console = Mock()
            mock_console.__enter__ = Mock(return_value=mock_console)
            mock_console.__exit__ = Mock(return_value=None)
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.decompress_blte") as mock_decompress:
                mock_decompress.return_value = b"Hello BLTE!"

                with patch("cascette_tools.commands.examine.BLTEParser") as mock_parser_class:
                    mock_parser = Mock()
                    mock_parser.parse.return_value = sample_blte_file
                    mock_parser_class.return_value = mock_parser

                    with patch("cascette_tools.commands.examine.Progress") as mock_progress_class:
                        mock_progress = Mock()
                        mock_progress.__enter__ = Mock(return_value=mock_progress)
                        mock_progress.__exit__ = Mock(return_value=None)
                        mock_progress_class.return_value = mock_progress

                        result = runner.invoke(examine, ["blte", str(test_file), "-o", str(output_file)])
                        assert result.exit_code == 0
                        assert output_file.exists()
                        assert output_file.read_bytes() == b"Hello BLTE!"

    def test_examine_encoding_from_file(self, runner, tmp_path, sample_encoding_file):
        """Test examine encoding command with file input."""
        test_file = tmp_path / "test.encoding"
        test_file.write_bytes(b"dummy encoding data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.EncodingParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_encoding_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["encoding", str(test_file)])
                assert result.exit_code == 0
                mock_parser.parse.assert_called_once()

    def test_examine_encoding_with_search(self, runner, tmp_path, sample_encoding_file):
        """Test examine encoding command with content key search."""
        test_file = tmp_path / "test.encoding"
        test_file.write_bytes(b"dummy encoding data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.EncodingParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_encoding_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["encoding", str(test_file), "--search", "12345678"])
                assert result.exit_code == 0

    def test_examine_encoding_json_output(self, runner, tmp_path, sample_encoding_file):
        """Test examine encoding command with JSON output."""
        test_file = tmp_path / "test.encoding"
        test_file.write_bytes(b"dummy encoding data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "json"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.EncodingParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_encoding_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["encoding", str(test_file)])
                assert result.exit_code == 0

                # Check that output is valid JSON
                parsed_json = json.loads(result.output)
                assert "magic" in parsed_json
                assert "ckey_page_count" in parsed_json

    def test_examine_config_build_type(self, runner, tmp_path):
        """Test examine config command with build config."""
        test_file = tmp_path / "test.config"
        config_data = b"## Build Config\nbuild-name = test\nversion = 1.0"
        test_file.write_bytes(config_data)

        mock_build_config = BuildConfig(build_name="test", extra_fields={"version": "1.0"})

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.is_config_file", return_value=True):
                with patch("cascette_tools.commands.examine.detect_config_type", return_value="build"):
                    with patch("cascette_tools.commands.examine.BuildConfigParser") as mock_parser_class:
                        mock_parser = Mock()
                        mock_parser.parse.return_value = mock_build_config
                        mock_parser_class.return_value = mock_parser

                        result = runner.invoke(examine, ["config", str(test_file)])
                        assert result.exit_code == 0

    def test_examine_archive_from_file(self, runner, tmp_path, sample_archive_index):
        """Test examine archive command with file input."""
        test_file = tmp_path / "test.index"
        test_file.write_bytes(b"dummy archive data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.ArchiveIndexParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_archive_index
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["archive", str(test_file)])
                assert result.exit_code == 0
                mock_parser.parse.assert_called_once()

    def test_examine_archive_json_output(self, runner, tmp_path, sample_archive_index):
        """Test examine archive command with JSON output."""
        test_file = tmp_path / "test.index"
        test_file.write_bytes(b"dummy archive data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "json"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.ArchiveIndexParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_archive_index
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["archive", str(test_file)])
                assert result.exit_code == 0

                # Check that output is valid JSON
                parsed_json = json.loads(result.output)
                assert "footer" in parsed_json
                assert "chunks" in parsed_json

    def test_fetch_from_cdn_or_path_file(self, tmp_path):
        """Test _fetch_from_cdn_or_path with local file."""
        from cascette_tools.commands.examine import _fetch_from_cdn_or_path

        test_file = tmp_path / "test.dat"
        test_data = b"test data"
        test_file.write_bytes(test_data)

        mock_console = Mock()
        mock_config = Mock()

        result = _fetch_from_cdn_or_path(str(test_file), mock_console, mock_config)
        assert result == test_data

    def test_fetch_from_cdn_or_path_hash(self, tmp_path):
        """Test _fetch_from_cdn_or_path with CDN hash."""
        from cascette_tools.commands.examine import _fetch_from_cdn_or_path

        test_hash = "1234567890abcdef1234567890abcdef"
        test_data = b"cdn data"

        mock_console = Mock()
        mock_config = Mock()
        mock_config.cdn = Mock()
        mock_config.cdn_timeout = 30
        mock_config.cdn_max_retries = 3

        with patch("cascette_tools.commands.examine.validate_hash_string", return_value=True):
            with patch("cascette_tools.commands.examine.CDNClient") as mock_cdn_class:
                mock_cdn = Mock()
                mock_cdn.fetch_data.return_value = test_data
                mock_cdn_class.return_value = mock_cdn

                with patch("cascette_tools.commands.examine.CDNConfig") as mock_cdn_config_class:
                    with patch("cascette_tools.commands.examine.Product"):
                        with patch("cascette_tools.commands.examine.Progress") as mock_progress_class:
                            mock_cdn_config = Mock()
                            mock_cdn_config_class.return_value = mock_cdn_config

                            mock_progress = Mock()
                            mock_progress.__enter__ = Mock(return_value=mock_progress)
                            mock_progress.__exit__ = Mock(return_value=None)
                            mock_progress_class.return_value = mock_progress

                            result = _fetch_from_cdn_or_path(test_hash, mock_console, mock_config)
                            assert result == test_data
                            mock_cdn.fetch_data.assert_called_once_with(test_hash)
                            mock_cdn_config_class.assert_called_once_with(
                                timeout=mock_config.cdn_timeout,
                                max_retries=mock_config.cdn_max_retries
                            )

    def test_fetch_from_cdn_or_path_invalid_input(self, tmp_path):
        """Test _fetch_from_cdn_or_path with invalid input."""
        import click

        from cascette_tools.commands.examine import _fetch_from_cdn_or_path

        mock_console = Mock()
        mock_config = Mock()

        with patch("cascette_tools.commands.examine.validate_hash_string", return_value=False):
            with pytest.raises(click.ClickException, match="Invalid input"):
                _fetch_from_cdn_or_path("invalid", mock_console, mock_config)

    def test_fetch_from_cdn_or_path_file_not_found(self, tmp_path):
        """Test _fetch_from_cdn_or_path with missing file."""
        import click

        from cascette_tools.commands.examine import _fetch_from_cdn_or_path

        missing_file = tmp_path / "missing.dat"
        mock_console = Mock()
        mock_config = Mock()
        mock_config.cdn_timeout = 30
        mock_config.cdn_max_retries = 3

        with pytest.raises(click.ClickException, match="Invalid input"):
            _fetch_from_cdn_or_path(str(missing_file), mock_console, mock_config)

    def test_fetch_from_cdn_or_path_cdn_error(self, tmp_path):
        """Test _fetch_from_cdn_or_path with CDN error."""
        import click

        from cascette_tools.commands.examine import _fetch_from_cdn_or_path

        test_hash = "1234567890abcdef1234567890abcdef"
        mock_console = Mock()
        mock_config = Mock()
        mock_config.cdn_timeout = 30
        mock_config.cdn_max_retries = 3

        with patch("cascette_tools.commands.examine.validate_hash_string", return_value=True):
            with patch("cascette_tools.commands.examine.CDNClient") as mock_cdn_class:
                mock_cdn = Mock()
                mock_cdn.fetch_data.side_effect = Exception("CDN error")
                mock_cdn_class.return_value = mock_cdn

                with patch("cascette_tools.commands.examine.CDNConfig") as mock_cdn_config_class:
                    with patch("cascette_tools.commands.examine.Product"):
                        with patch("cascette_tools.commands.examine.Progress") as mock_progress_class:
                            mock_cdn_config = Mock()
                            mock_cdn_config_class.return_value = mock_cdn_config

                            mock_progress = Mock()
                            mock_progress.__enter__ = Mock(return_value=mock_progress)
                            mock_progress.__exit__ = Mock(return_value=None)
                            mock_progress_class.return_value = mock_progress

                            with pytest.raises(click.ClickException, match="Failed to fetch from CDN"):
                                _fetch_from_cdn_or_path(test_hash, mock_console, mock_config)

    def test_output_json(self):
        """Test _output_json function."""
        from cascette_tools.commands.examine import _output_json

        test_data = {"key": "value", "number": 42}
        mock_console = Mock()

        # Capture stdout
        import sys
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            _output_json(test_data, mock_console)
            output = captured_output.getvalue()

            # Verify it's valid JSON
            parsed = json.loads(output)
            assert parsed == test_data
        finally:
            sys.stdout = sys.__stdout__

    def test_output_table(self):
        """Test _output_table function."""
        from rich.table import Table

        from cascette_tools.commands.examine import _output_table

        mock_console = Mock()
        test_table = Table(title="Test Table")
        test_table.add_column("Column 1")
        test_table.add_row("Value 1")

        _output_table(test_table, mock_console)
        mock_console.print.assert_called_once_with(test_table)

    def test_get_context_objects(self):
        """Test _get_context_objects function."""
        import click

        from cascette_tools.commands.examine import _get_context_objects

        mock_config = Mock()
        mock_console = Mock()

        ctx = click.Context(click.Command("test"))
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

    def test_examine_blte_invalid_file(self, runner, tmp_path):
        """Test examine blte command with invalid BLTE file."""
        test_file = tmp_path / "invalid.blte"
        test_file.write_bytes(b"not a blte file")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.BLTEParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.side_effect = ValueError("Invalid BLTE format")
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["blte", str(test_file)])
                assert result.exit_code == 1
                assert "Failed to examine BLTE file" in result.output

    def test_examine_encoding_with_limit(self, runner, tmp_path, sample_encoding_file):
        """Test examine encoding command with entry limit."""
        test_file = tmp_path / "test.encoding"
        test_file.write_bytes(b"dummy encoding data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.EncodingParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_encoding_file
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["encoding", str(test_file), "--limit", "5"])
                assert result.exit_code == 0

    def test_examine_config_unknown_type(self, runner, tmp_path):
        """Test examine config command with unknown config type."""
        test_file = tmp_path / "unknown.config"
        test_file.write_bytes(b"unknown config")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.is_config_file", return_value=True):
                with patch("cascette_tools.commands.examine.detect_config_type", return_value="unknown"):
                    result = runner.invoke(examine, ["config", str(test_file)])
                    assert result.exit_code == 1
                    assert "Unknown config type" in result.output

    def test_examine_config_invalid_file(self, runner, tmp_path):
        """Test examine config command with non-config file."""
        test_file = tmp_path / "notconfig.dat"
        test_file.write_bytes(b"not a config file")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, False, False)

            with patch("cascette_tools.commands.examine.is_config_file", return_value=False):
                result = runner.invoke(examine, ["config", str(test_file)])
                assert result.exit_code == 1
                assert "not a valid config file" in result.output

    def test_examine_archive_verbose_mode(self, runner, tmp_path, sample_archive_index):
        """Test examine archive command in verbose mode."""
        test_file = tmp_path / "test.index"
        test_file.write_bytes(b"dummy archive data")

        with patch("cascette_tools.commands.examine._get_context_objects") as mock_context:
            mock_config = Mock()
            mock_config.output_format = "rich"
            mock_console = Mock()
            mock_context.return_value = (mock_config, mock_console, True, False)  # verbose=True

            with patch("cascette_tools.commands.examine.ArchiveIndexParser") as mock_parser_class:
                mock_parser = Mock()
                mock_parser.parse.return_value = sample_archive_index
                mock_parser_class.return_value = mock_parser

                result = runner.invoke(examine, ["archive", str(test_file)])
                assert result.exit_code == 0

    def test_examine_commands_help(self, runner):
        """Test examine command help output."""
        result = runner.invoke(examine, ["--help"])
        assert result.exit_code == 0
        assert "Examine NGDP/CASC format files" in result.output

        # Test subcommand help
        for cmd in ["blte", "encoding", "config", "archive"]:
            result = runner.invoke(examine, [cmd, "--help"])
            assert result.exit_code == 0
