"""Tests for validate command module."""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import click
import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.table import Table

from cascette_tools.commands.validate import (
    _detect_format_type,
    _fetch_from_cdn_or_path,
    _get_context_objects,
    _output_json,
    _output_table,
    _validate_checksums,
    _validate_format_structure,
    validate,
)
from cascette_tools.core.config import AppConfig


class TestValidateCommands:
    """Test validate command functionality."""

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
        # Simple archive with footer
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
        # Simple root file structure
        return b"TSFM" + b"\x00" * 12 + b"root file content"

    def test_validate_group_help(self, runner):
        """Test validate group shows help when invoked without subcommand."""
        result = runner.invoke(validate, [])

        assert result.exit_code == 0
        assert "Validate NGDP/CASC format files and integrity" in result.output
        assert "format" in result.output
        assert "integrity" in result.output
        assert "roundtrip" in result.output
        assert "relationships" in result.output
        assert "batch" in result.output

    def test_validate_group_help_flag(self, runner):
        """Test validate group shows help when invoked with --help."""
        result = runner.invoke(validate, ["--help"])

        assert result.exit_code == 0
        assert "Validate NGDP/CASC format files and integrity" in result.output

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    @patch("cascette_tools.commands.validate._validate_format_structure")
    @patch("cascette_tools.commands.validate._validate_checksums")
    def test_format_validate_blte(
        self,
        mock_validate_checksums,
        mock_validate_structure,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test format command with BLTE file."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_detect_format.return_value = "blte"
        mock_validate_structure.return_value = (True, "Valid structure", {"chunks": 1})
        mock_validate_checksums.return_value = (True, "Valid checksums", {"verified": True})

        result = runner.invoke(validate, ["format", "test.blte"])

        assert result.exit_code == 0
        mock_fetch.assert_called_once()
        mock_detect_format.assert_called_once_with(sample_blte_data)
        mock_validate_structure.assert_called_once_with(sample_blte_data, "blte")
        mock_validate_checksums.assert_called_once_with(sample_blte_data, "blte")

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._validate_format_structure")
    @patch("cascette_tools.commands.validate._validate_checksums")
    def test_format_validate_encoding_with_type(
        self,
        mock_validate_checksums,
        mock_validate_structure,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test format command with encoding file and explicit type."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data
        mock_validate_structure.return_value = (True, "Valid structure", {"entries": 100})
        mock_validate_checksums.return_value = (True, "Valid checksums", {"verified": True})

        result = runner.invoke(validate, [
            "format",
            "test.encoding",
            "--format-type", "encoding"
        ])

        assert result.exit_code == 0
        mock_validate_structure.assert_called_once_with(sample_encoding_data, "encoding")
        mock_validate_checksums.assert_called_once_with(sample_encoding_data, "encoding")

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._validate_format_structure")
    def test_format_validate_strict_mode_failure(
        self,
        mock_validate_structure,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test format command in strict mode with validation failure."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_validate_structure.return_value = (False, "Invalid structure", {"error": "Parse failed"})

        result = runner.invoke(validate, [
            "format",
            "test.blte",
            "--format-type", "blte",
            "--strict"
        ])

        assert result.exit_code != 0

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    def test_format_validate_undetected_format(
        self,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test format command when format type cannot be detected."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"unknown data"
        mock_detect_format.return_value = None

        result = runner.invoke(validate, ["format", "test.unknown"])

        assert result.exit_code != 0
        assert "Could not detect format type" in result.output

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate.compute_md5")
    def test_integrity_validate_with_manifest(
        self,
        mock_compute_md5,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test integrity command with manifest files."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data
        mock_hash_obj = Mock()
        mock_hash_obj.hex.return_value = "abcdef1234567890abcdef1234567890"
        mock_compute_md5.return_value = mock_hash_obj

        result = runner.invoke(validate, [
            "integrity",
            "abcdef1234567890abcdef1234567890",
            "--check-md5"
        ])

        assert result.exit_code == 0
        mock_fetch.assert_called_once()
        mock_compute_md5.assert_called_with(sample_encoding_data)

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate.compute_md5")
    @patch("cascette_tools.commands.validate.is_blte")
    def test_integrity_validate_sample_files(
        self,
        mock_is_blte,
        mock_compute_md5,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test integrity command with BLTE file validation."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_is_blte.return_value = True
        mock_hash_obj = Mock()
        mock_hash_obj.hex.return_value = "abcdef1234567890abcdef1234567890"
        mock_compute_md5.return_value = mock_hash_obj

        with patch("cascette_tools.commands.validate.decompress_blte") as mock_decompress:
            mock_decompress.return_value = b"decompressed data"

            result = runner.invoke(validate, [
                "integrity",
                "test.blte",
                "--check-blte"
            ])

            assert result.exit_code == 0
            mock_fetch.assert_called_once()
            mock_is_blte.assert_called_with(sample_blte_data)

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    @patch("cascette_tools.commands.validate.Progress")
    def test_roundtrip_validate_blte(
        self,
        mock_progress_class,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test roundtrip command with BLTE file."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_detect_format.return_value = "blte"

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        with patch("cascette_tools.commands.validate.BLTEParser") as mock_parser:
            with patch("cascette_tools.commands.validate.BLTEBuilder") as mock_builder:
                mock_blte = Mock()
                mock_parser.return_value.parse.return_value = mock_blte
                mock_builder.return_value.build.return_value = sample_blte_data

                result = runner.invoke(validate, [
                    "roundtrip",
                    "test.blte",
                    "--format-type", "blte"
                ])

                assert result.exit_code == 0
                mock_parser.return_value.parse.assert_called_once()
                mock_builder.return_value.build.assert_called_once()

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    @patch("cascette_tools.commands.validate.Progress")
    def test_roundtrip_validate_encoding(
        self,
        mock_progress_class,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_encoding_data
    ):
        """Test roundtrip command with encoding file."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_encoding_data
        mock_detect_format.return_value = "encoding"

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        with patch("cascette_tools.commands.validate.EncodingParser") as mock_parser:
            with patch("cascette_tools.commands.validate.EncodingBuilder") as mock_builder:
                mock_encoding = Mock()
                mock_parser.return_value.parse.return_value = mock_encoding
                mock_builder.return_value.build.return_value = sample_encoding_data

                result = runner.invoke(validate, [
                    "roundtrip",
                    "test.encoding",
                    "--format-type", "encoding"
                ])

                assert result.exit_code == 0

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    @patch("cascette_tools.commands.validate.Progress")
    def test_roundtrip_mismatch_failure(
        self,
        mock_progress_class,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_blte_data
    ):
        """Test roundtrip command when data doesn't match after roundtrip."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = sample_blte_data
        mock_detect_format.return_value = "blte"

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        with patch("cascette_tools.commands.validate.BLTEParser") as mock_parser:
            with patch("cascette_tools.commands.validate.BLTEBuilder") as mock_builder:
                mock_blte = Mock()
                mock_parser.return_value.parse.return_value = mock_blte
                # Return different data to simulate mismatch
                mock_builder.return_value.build.return_value = b"different data"

                result = runner.invoke(validate, [
                    "roundtrip",
                    "test.blte",
                    "--format-type", "blte"
                ])

                assert result.exit_code == 1  # Should fail due to mismatch

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate.Progress")
    def test_relationships_validate_build_refs(
        self,
        mock_progress_class,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects,
        sample_root_data,
        sample_encoding_data
    ):
        """Test relationships command with root and encoding files."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.side_effect = [sample_root_data, sample_encoding_data]

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        with patch("cascette_tools.commands.validate.RootParser") as mock_root_parser:
            with patch("cascette_tools.commands.validate.EncodingParser") as mock_encoding_parser:
                # Mock root object
                mock_root = Mock()
                mock_block = Mock()
                mock_record = Mock()
                mock_record.content_key = b"shared_key"
                mock_block.records = [mock_record]
                mock_root.blocks = [mock_block]
                mock_root_parser.return_value.parse.return_value = mock_root

                # Mock encoding object
                mock_encoding = Mock()
                mock_encoding.ckey_index = {b"shared_key": Mock()}
                mock_encoding_parser.return_value.parse.return_value = mock_encoding

                result = runner.invoke(validate, [
                    "relationships",
                    "root_hash",
                    "encoding_hash"
                ])

                assert result.exit_code == 0
                assert mock_fetch.call_count == 2

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate.track")
    def test_batch_validate_multiple_files(
        self,
        mock_track,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with multiple files in a directory."""
        mock_get_context.return_value = mock_context_objects
        # Mock track to return the files list without progress tracking
        mock_track.side_effect = lambda files, **kwargs: files

        # Create test files in the directory
        test_file1 = tmp_path / "test1.blte"
        test_file1.write_bytes(b"BLTE test data")
        test_file2 = tmp_path / "test2.encoding"
        test_file2.write_bytes(b"EN encoding data")

        with patch("cascette_tools.commands.validate._detect_format_type") as mock_detect:
            with patch("cascette_tools.commands.validate._validate_format_structure") as mock_validate_structure:
                with patch("cascette_tools.commands.validate._validate_checksums") as mock_validate_checksums:
                    with patch("cascette_tools.commands.validate.compute_md5") as mock_compute_md5:
                        mock_detect.side_effect = ["blte", "encoding"]
                        mock_validate_structure.return_value = (True, "Valid structure", {})
                        mock_validate_checksums.return_value = (True, "Valid checksums", {})
                        mock_hash = Mock()
                        mock_hash.hex.return_value = "abc123"
                        mock_compute_md5.return_value = mock_hash

                        result = runner.invoke(validate, [
                            "batch",
                            str(tmp_path)
                        ])

                        assert result.exit_code == 0
                        # Should validate both files in the directory
                        assert mock_detect.call_count >= 1

    def test_format_invalid_hash(self, runner):
        """Test format command with invalid hash."""
        result = runner.invoke(validate, ["format", "invalid_hash"])

        assert result.exit_code != 0

    def test_integrity_missing_arguments(self, runner):
        """Test integrity command with missing arguments."""
        result = runner.invoke(validate, ["integrity"])

        assert result.exit_code != 0

    def test_roundtrip_unsupported_format(self, runner):
        """Test roundtrip command with unsupported format."""
        result = runner.invoke(validate, [
            "roundtrip",
            "test.unknown",
            "--format-type", "unknown"
        ])

        assert result.exit_code != 0
        assert "is not one of" in result.output

    def test_relationships_unsupported_type(self, runner):
        """Test relationships command with unsupported type."""
        with patch("cascette_tools.commands.validate._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.validate._fetch_from_cdn_or_path") as mock_fetch:
                mock_get_context.return_value = Mock(), Mock(), False, False
                mock_fetch.return_value = b"test data"

                result = runner.invoke(validate, [
                    "relationships",
                    "test_hash",
                    "--type", "unsupported"
                ])

                assert result.exit_code != 0

    def test_batch_nonexistent_file(self, runner):
        """Test batch command with nonexistent file list."""
        result = runner.invoke(validate, [
            "batch",
            "nonexistent_list.txt"
        ])

        assert result.exit_code != 0

    def test_format_help(self, runner):
        """Test format subcommand shows help."""
        result = runner.invoke(validate, ["format", "--help"])

        assert result.exit_code == 0
        assert "Validate individual format files" in result.output

    def test_integrity_help(self, runner):
        """Test integrity subcommand shows help."""
        result = runner.invoke(validate, ["integrity", "--help"])

        assert result.exit_code == 0
        assert "Check file integrity and checksums" in result.output

    def test_roundtrip_help(self, runner):
        """Test roundtrip subcommand shows help."""
        result = runner.invoke(validate, ["roundtrip", "--help"])

        assert result.exit_code == 0
        assert "Test parse/build roundtrip validation" in result.output

    def test_relationships_help(self, runner):
        """Test relationships subcommand shows help."""
        result = runner.invoke(validate, ["relationships", "--help"])

        assert result.exit_code == 0
        assert "Validate cross-format relationships" in result.output

    def test_batch_help(self, runner):
        """Test batch subcommand shows help."""
        result = runner.invoke(validate, ["batch", "--help"])

        assert result.exit_code == 0
        assert "Batch validate multiple files in a directory" in result.output

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    def test_format_fetch_error(
        self,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test format command with fetch error."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.side_effect = Exception("Network error")

        result = runner.invoke(validate, ["format", "test_hash"])

        assert result.exit_code != 0
        assert "Failed to validate" in result.output

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._output_json")
    def test_format_json_output(
        self,
        mock_output_json,
        mock_get_context,
        runner,
        sample_blte_data
    ):
        """Test format command with JSON output."""
        config, console, verbose, debug = Mock(), Mock(), False, False
        config.output_format = "json"
        mock_get_context.return_value = config, console, verbose, debug

        with patch("cascette_tools.commands.validate._fetch_from_cdn_or_path") as mock_fetch:
            with patch("cascette_tools.commands.validate._detect_format_type") as mock_detect:
                with patch("cascette_tools.commands.validate._validate_format_structure") as mock_structure:
                    with patch("cascette_tools.commands.validate._validate_checksums") as mock_checksum:
                        mock_fetch.return_value = sample_blte_data
                        mock_detect.return_value = "blte"
                        mock_structure.return_value = (True, "Valid", {})
                        mock_checksum.return_value = (True, "Valid", {})

                        result = runner.invoke(validate, ["format", "test.blte"])

                        assert result.exit_code == 0
                        mock_output_json.assert_called_once()

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate.track")
    def test_batch_invalid_line_format(
        self,
        mock_track,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with directory containing invalid files."""
        mock_get_context.return_value = mock_context_objects
        # Mock track to return the files list without progress tracking
        mock_track.side_effect = lambda files, **kwargs: files

        # Create files that cannot be detected
        invalid_file = tmp_path / "invalid.txt"
        invalid_file.write_bytes(b"invalid data that cannot be detected")

        with patch("cascette_tools.commands.validate._detect_format_type") as mock_detect_format:
            with patch("cascette_tools.commands.validate.compute_md5") as mock_compute_md5:
                mock_detect_format.return_value = None  # Cannot detect format
                mock_hash = Mock()
                mock_hash.hex.return_value = "abc123"
                mock_compute_md5.return_value = mock_hash

                result = runner.invoke(validate, ["batch", str(tmp_path)])

                # Should handle invalid files gracefully
                assert result.exit_code == 0

    @patch("cascette_tools.commands.validate._get_context_objects")
    def test_batch_empty_file_list(
        self,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with empty directory."""
        mock_get_context.return_value = mock_context_objects

        # Create empty directory
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()

        result = runner.invoke(validate, ["batch", str(empty_dir)])

        # Should handle empty directory gracefully
        assert result.exit_code == 0


class TestValidateHelperFunctions:
    """Test helper functions in validate module."""

    # Use the standardized mock_config from conftest.py instead of creating a duplicate

    # Use the standardized mock_console from conftest.py instead of creating a duplicate

    # Use the standardized mock_cli_context from conftest.py instead of creating a duplicate

    def test_get_context_objects(self, mock_cli_context, mock_config, mock_console):
        """Test _get_context_objects helper function."""
        config, console, verbose, debug = _get_context_objects(mock_cli_context)

        assert config == mock_config
        assert console == mock_console
        assert verbose is False  # Updated to match conftest.py defaults
        assert debug is False

    def test_output_json(self, mock_console, capsys):
        """Test _output_json helper function."""
        test_data = {"key": "value", "number": 42}

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

    def test_fetch_from_cdn_or_path_file_not_found(self, mock_config, mock_console):
        """Test _fetch_from_cdn_or_path with non-existent file."""
        non_existent_file = "/path/that/does/not/exist.dat"

        with pytest.raises(click.ClickException):
            _fetch_from_cdn_or_path(non_existent_file, mock_console, mock_config)

    def test_fetch_from_cdn_or_path_file_read_error(self, mock_config, mock_console):
        """Test _fetch_from_cdn_or_path with file read error."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_bytes", side_effect=OSError("Permission denied")):
                with pytest.raises(Exception, match="Failed to read file"):
                    _fetch_from_cdn_or_path("/test/file.dat", mock_console, mock_config)

    @patch("cascette_tools.commands.validate.validate_hash_string")
    @patch("cascette_tools.commands.validate.CDNClient")
    @patch("cascette_tools.commands.validate.Progress")
    def test_fetch_from_cdn_or_path_valid_hash(
        self, mock_progress_class, mock_cdn_class, mock_validate_hash, mock_config, mock_console
    ):
        """Test _fetch_from_cdn_or_path with valid hash."""
        mock_validate_hash.return_value = True
        mock_cdn = Mock()
        mock_cdn.fetch_data.return_value = b"cdn data"
        mock_cdn.__enter__ = Mock(return_value=mock_cdn)
        mock_cdn.__exit__ = Mock(return_value=None)
        mock_cdn_class.return_value = mock_cdn

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        result = _fetch_from_cdn_or_path("abc123", mock_console, mock_config)

        assert result == b"cdn data"
        mock_cdn.fetch_data.assert_called_once_with("abc123")

    @patch("cascette_tools.commands.validate.validate_hash_string")
    def test_fetch_from_cdn_or_path_invalid_hash(self, mock_validate_hash, mock_config, mock_console):
        """Test _fetch_from_cdn_or_path with invalid hash."""
        mock_validate_hash.return_value = False

        with pytest.raises(Exception, match="Invalid input: not a valid file path or hash"):
            _fetch_from_cdn_or_path("invalid_hash", mock_console, mock_config)

    @patch("cascette_tools.commands.validate.validate_hash_string")
    @patch("cascette_tools.commands.validate.CDNClient")
    @patch("cascette_tools.commands.validate.Progress")
    def test_fetch_from_cdn_or_path_cdn_error(
        self, mock_progress_class, mock_cdn_class, mock_validate_hash, mock_config, mock_console
    ):
        """Test _fetch_from_cdn_or_path with CDN fetch error."""
        mock_validate_hash.return_value = True
        mock_cdn = Mock()
        mock_cdn.fetch_data.side_effect = Exception("CDN error")
        mock_cdn.__enter__ = Mock(return_value=mock_cdn)
        mock_cdn.__exit__ = Mock(return_value=None)
        mock_cdn_class.return_value = mock_cdn

        # Mock Progress context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock(return_value=1)
        mock_progress_class.return_value = mock_progress

        with pytest.raises(Exception, match="Failed to fetch from CDN"):
            _fetch_from_cdn_or_path("abc123", mock_console, mock_config)

    def test_detect_format_type_blte(self):
        """Test _detect_format_type with BLTE data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=True):
            result = _detect_format_type(b"BLTE data")
            assert result == "blte"

    def test_detect_format_type_encoding(self):
        """Test _detect_format_type with encoding data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=True):
                result = _detect_format_type(b"encoding data")
                assert result == "encoding"

    def test_detect_format_type_root(self):
        """Test _detect_format_type with root data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=True):
                    result = _detect_format_type(b"root data")
                    assert result == "root"

    def test_detect_format_type_install(self):
        """Test _detect_format_type with install data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=True):
                        result = _detect_format_type(b"install data")
                        assert result == "install"

    def test_detect_format_type_download(self):
        """Test _detect_format_type with download data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=True):
                            result = _detect_format_type(b"download data")
                            assert result == "download"

    def test_detect_format_type_patch_archive(self):
        """Test _detect_format_type with patch archive data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=True):
                                result = _detect_format_type(b"patch archive data")
                                assert result == "patch_archive"

    def test_detect_format_type_config(self):
        """Test _detect_format_type with config data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=False):
                                with patch("cascette_tools.commands.validate.is_config_file", return_value=True):
                                    with patch("cascette_tools.commands.validate.detect_config_type", return_value="build"):
                                        result = _detect_format_type(b"config data")
                                        assert result == "build"

    def test_detect_format_type_tvfs(self):
        """Test _detect_format_type with TVFS data."""
        tvfs_data = b"TVFS" + b"\x00" * 20
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=False):
                                with patch("cascette_tools.commands.validate.is_config_file", return_value=False):
                                    result = _detect_format_type(tvfs_data)
                                    assert result == "tvfs"

    def test_detect_format_type_zbsdiff(self):
        """Test _detect_format_type with ZBSDIFF data."""
        zbsdiff_data = b"ZBSDIFF1" + b"\x00" * 20
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=False):
                                with patch("cascette_tools.commands.validate.is_config_file", return_value=False):
                                    result = _detect_format_type(zbsdiff_data)
                                    assert result == "zbsdiff"

    def test_detect_format_type_archive(self):
        """Test _detect_format_type with archive data."""
        archive_data = b"test data" + b"\x00\x00\x00\x01"
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=False):
                                with patch("cascette_tools.commands.validate.is_config_file", return_value=False):
                                    result = _detect_format_type(archive_data)
                                    assert result == "archive"

    def test_detect_format_type_unknown(self):
        """Test _detect_format_type with unknown data."""
        with patch("cascette_tools.commands.validate.is_blte", return_value=False):
            with patch("cascette_tools.commands.validate.is_encoding", return_value=False):
                with patch("cascette_tools.commands.validate.is_root", return_value=False):
                    with patch("cascette_tools.commands.validate.is_install", return_value=False):
                        with patch("cascette_tools.commands.validate.is_download", return_value=False):
                            with patch("cascette_tools.commands.validate.is_patch_archive", return_value=False):
                                with patch("cascette_tools.commands.validate.is_config_file", return_value=False):
                                    result = _detect_format_type(b"unknown")
                                    assert result is None


class TestValidateFormatStructure:
    """Test _validate_format_structure function."""

    @patch("cascette_tools.commands.validate.BLTEParser")
    def test_validate_blte_structure_valid(self, mock_parser):
        """Test BLTE structure validation success."""
        mock_blte = Mock()
        mock_blte.chunks = [Mock(compressed_size=100, decompressed_size=200)]
        mock_parser.return_value.parse.return_value = mock_blte

        valid, msg, info = _validate_format_structure(b"blte data", "blte")

        assert valid is True
        assert "Valid structure" in msg
        assert info["chunk_count"] == 1
        assert info["total_compressed"] == 100
        assert info["total_decompressed"] == 200

    @patch("cascette_tools.commands.validate.BLTEParser")
    def test_validate_blte_structure_error(self, mock_parser):
        """Test BLTE structure validation failure."""
        mock_parser.return_value.parse.side_effect = Exception("Parse error")

        valid, msg, info = _validate_format_structure(b"invalid blte", "blte")

        assert valid is False
        assert "Structure validation failed" in msg
        assert "Parse error" in msg

    @patch("cascette_tools.commands.validate.EncodingParser")
    def test_validate_encoding_structure_valid(self, mock_parser):
        """Test encoding structure validation success."""
        mock_encoding = Mock()
        mock_encoding.header = Mock(version=1, ckey_page_count=5, ekey_page_count=3)
        mock_parser.return_value.parse.return_value = mock_encoding

        valid, msg, info = _validate_format_structure(b"encoding data", "encoding")

        assert valid is True
        assert "Valid structure" in msg
        assert info["version"] == 1
        assert info["ckey_page_count"] == 5
        assert info["ekey_page_count"] == 3

    @patch("cascette_tools.commands.validate.RootParser")
    def test_validate_root_structure_valid(self, mock_parser):
        """Test root structure validation success."""
        mock_root = Mock()
        mock_root.header = Mock(version=1)
        mock_block1 = Mock()
        mock_block1.records = [Mock(), Mock()]
        mock_block2 = Mock()
        mock_block2.records = [Mock()]
        mock_root.blocks = [mock_block1, mock_block2]
        mock_parser.return_value.parse.return_value = mock_root

        valid, msg, info = _validate_format_structure(b"root data", "root")

        assert valid is True
        assert "Valid structure" in msg
        assert info["version"] == 1
        assert info["block_count"] == 2
        assert info["total_records"] == 3

    @patch("cascette_tools.commands.validate.InstallParser")
    def test_validate_install_structure_valid(self, mock_parser):
        """Test install structure validation success."""
        mock_install = Mock()
        mock_install.tags = [Mock(), Mock()]
        mock_install.entries = [Mock(), Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_install

        valid, msg, info = _validate_format_structure(b"install data", "install")

        assert valid is True
        assert "Valid structure" in msg
        assert info["tag_count"] == 2
        assert info["entry_count"] == 3

    @patch("cascette_tools.commands.validate.DownloadParser")
    def test_validate_download_structure_valid(self, mock_parser):
        """Test download structure validation success."""
        mock_download = Mock()
        mock_download.tags = [Mock()]
        mock_download.entries = [Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_download

        valid, msg, info = _validate_format_structure(b"download data", "download")

        assert valid is True
        assert "Valid structure" in msg
        assert info["tag_count"] == 1
        assert info["entry_count"] == 2

    @patch("cascette_tools.commands.validate.ArchiveIndexParser")
    def test_validate_archive_structure_valid(self, mock_parser):
        """Test archive structure validation success."""
        mock_archive = Mock()
        mock_archive.footer = Mock(version=2, element_count=10)
        mock_archive.chunks = [Mock(), Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_archive

        valid, msg, info = _validate_format_structure(b"archive data", "archive")

        assert valid is True
        assert "Valid structure" in msg
        assert info["version"] == 2
        assert info["element_count"] == 10
        assert info["chunk_count"] == 3

    @patch("cascette_tools.commands.validate.PatchArchiveParser")
    def test_validate_patch_archive_structure_valid(self, mock_parser):
        """Test patch archive structure validation success."""
        mock_patch_archive = Mock()
        mock_patch_archive.header = Mock(version=1)
        mock_patch_archive.entries = [Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_patch_archive

        valid, msg, info = _validate_format_structure(b"patch archive data", "patch_archive")

        assert valid is True
        assert "Valid structure" in msg
        assert info["version"] == 1
        assert info["entry_count"] == 2

    @patch("cascette_tools.commands.validate.TVFSParser")
    def test_validate_tvfs_structure_valid(self, mock_parser):
        """Test TVFS structure validation success."""
        mock_tvfs = Mock()
        mock_tvfs.header = Mock(version=1)
        mock_tvfs.entries = [Mock(), Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_tvfs

        valid, msg, info = _validate_format_structure(b"tvfs data", "tvfs")

        assert valid is True
        assert "Valid structure" in msg
        assert info["version"] == 1
        assert info["entry_count"] == 3

    @patch("cascette_tools.commands.validate.ZbsdiffParser")
    def test_validate_zbsdiff_structure_valid(self, mock_parser):
        """Test ZBSDIFF structure validation success."""
        mock_zbsdiff = Mock()
        mock_zbsdiff.header = Mock(new_size=1024)
        mock_zbsdiff.control_entries = [Mock(), Mock()]
        mock_parser.return_value.parse.return_value = mock_zbsdiff

        valid, msg, info = _validate_format_structure(b"zbsdiff data", "zbsdiff")

        assert valid is True
        assert "Valid structure" in msg
        assert info["new_size"] == 1024
        assert info["control_entries"] == 2

    @patch("cascette_tools.commands.validate.BuildConfigParser")
    def test_validate_build_config_structure_valid(self, mock_parser):
        """Test build config structure validation success."""
        mock_config = Mock()
        mock_config.model_dump.return_value = {"root": "abc123", "install": "def456"}
        mock_parser.return_value.parse.return_value = mock_config

        valid, msg, info = _validate_format_structure(b"build config", "build")

        assert valid is True
        assert "Valid structure" in msg
        assert info["field_count"] == 2

    @patch("cascette_tools.commands.validate.CDNConfigParser")
    def test_validate_cdn_config_structure_valid(self, mock_parser):
        """Test CDN config structure validation success."""
        mock_config = Mock()
        mock_config.model_dump.return_value = {"archives": ["arch1", "arch2"], "patch_archives": ["patch1"]}
        mock_parser.return_value.parse.return_value = mock_config

        valid, msg, info = _validate_format_structure(b"cdn config", "cdn")

        assert valid is True
        assert "Valid structure" in msg
        assert info["field_count"] == 2

    @patch("cascette_tools.commands.validate.PatchConfigParser")
    def test_validate_patch_config_structure_valid(self, mock_parser):
        """Test patch config structure validation success."""
        # Create a simple class with just the fields we want
        class MockPatchConfig:
            def __init__(self):
                self.patch_entry = "entry1"
                self.base_build = "build1"

        mock_config = MockPatchConfig()
        mock_parser.return_value.parse.return_value = mock_config

        valid, msg, info = _validate_format_structure(b"patch config", "patch")

        assert valid is True
        assert "Valid structure" in msg
        assert info["field_count"] == 2

    @patch("cascette_tools.commands.validate.ProductConfigParser")
    def test_validate_product_config_structure_valid(self, mock_parser):
        """Test product config structure validation success."""
        # Create a simple class with just the fields we want
        class MockProductConfig:
            def __init__(self):
                self.all_build_configs = ["config1"]
                self.active_build_config = "active_config"

        mock_config = MockProductConfig()
        mock_parser.return_value.parse.return_value = mock_config

        valid, msg, info = _validate_format_structure(b"product config", "product")

        assert valid is True
        assert "Valid structure" in msg
        assert info["field_count"] == 2


class TestValidateChecksums:
    """Test _validate_checksums function."""

    @patch("cascette_tools.commands.validate.BLTEParser")
    def test_validate_blte_checksums_valid(self, mock_parser):
        """Test BLTE checksum validation success."""
        mock_blte = Mock()
        mock_chunk1 = Mock()
        mock_chunk2 = Mock()
        mock_blte.chunks = [mock_chunk1, mock_chunk2]
        mock_parser.return_value.parse.return_value = mock_blte

        valid, msg, info = _validate_checksums(b"blte data", "blte")

        assert valid is True
        assert "Checksums valid" in msg
        assert info["valid_chunks"] == 2
        assert info["invalid_chunks"] == 0
        assert info["total_chunks"] == 2

    @patch("cascette_tools.commands.validate.BLTEParser")
    def test_validate_blte_checksums_error(self, mock_parser):
        """Test BLTE checksum validation with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse error")

        valid, msg, info = _validate_checksums(b"invalid blte", "blte")

        assert valid is False
        assert "Checksum validation failed" in msg
        assert "Parse error" in msg

    @patch("cascette_tools.commands.validate.ArchiveIndexParser")
    def test_validate_archive_checksums_valid(self, mock_parser):
        """Test archive checksum validation success."""
        mock_archive = Mock()
        mock_archive.footer = Mock()
        mock_archive.footer.toc_hash = b"\x12\x34\x56\x78" * 4
        mock_archive.footer.element_count = 5

        # Create mock chunks with entries
        mock_chunk1 = Mock()
        mock_chunk1.entries = [Mock(), Mock()]
        mock_chunk2 = Mock()
        mock_chunk2.entries = [Mock(), Mock(), Mock()]
        mock_archive.chunks = [mock_chunk1, mock_chunk2]

        mock_parser.return_value.parse.return_value = mock_archive

        valid, msg, info = _validate_checksums(b"archive data", "archive")

        assert valid is True
        assert "Checksums valid" in msg
        assert info["toc_hash"] == "12345678123456781234567812345678"
        assert info["element_count"] == 5
        assert info["actual_entries"] == 5

    @patch("cascette_tools.commands.validate.ArchiveIndexParser")
    def test_validate_archive_checksums_mismatch(self, mock_parser):
        """Test archive checksum validation with element count mismatch."""
        mock_archive = Mock()
        mock_archive.footer = Mock()
        mock_archive.footer.toc_hash = b"\x12\x34\x56\x78" * 4
        mock_archive.footer.element_count = 10  # Mismatch!

        # Create mock chunks with fewer entries than expected
        mock_chunk1 = Mock()
        mock_chunk1.entries = [Mock(), Mock()]
        mock_chunk2 = Mock()
        mock_chunk2.entries = [Mock()]
        mock_archive.chunks = [mock_chunk1, mock_chunk2]

        mock_parser.return_value.parse.return_value = mock_archive

        valid, msg, info = _validate_checksums(b"archive data", "archive")

        assert valid is False
        assert "Element count mismatch" in msg
        assert info["element_count"] == 10
        assert info["actual_entries"] == 3

    def test_validate_checksums_unsupported_format(self):
        """Test checksum validation for unsupported format."""
        valid, msg, info = _validate_checksums(b"unknown data", "unknown")

        assert valid is True
        assert "Checksums valid" in msg
        assert info == {}

    @patch("cascette_tools.commands.validate.ArchiveIndexParser")
    def test_validate_archive_checksums_error(self, mock_parser):
        """Test archive checksum validation with parser error."""
        mock_parser.return_value.parse.side_effect = Exception("Parse error")

        valid, msg, info = _validate_checksums(b"invalid archive", "archive")

        assert valid is False
        assert "Checksum validation failed" in msg
        assert "Parse error" in msg


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

    # Additional integration tests
    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate.validate_hash_string")
    @patch("cascette_tools.commands.validate.is_blte")
    @patch("cascette_tools.commands.validate.decompress_blte")
    def test_integrity_command_md5_mismatch(
        self,
        mock_decompress_blte,
        mock_is_blte,
        mock_validate_hash,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test integrity command with MD5 mismatch."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"test data"
        mock_validate_hash.return_value = True
        mock_is_blte.return_value = False

        with patch("cascette_tools.commands.validate.compute_md5") as mock_compute_md5:
            mock_hash_obj = Mock()
            mock_hash_obj.hex.return_value = "different_hash"
            mock_compute_md5.return_value = mock_hash_obj

            result = runner.invoke(validate, ["integrity", "expected_hash", "--check-md5"])

            assert result.exit_code == 1  # Should fail due to hash mismatch

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate._detect_format_type")
    def test_roundtrip_command_parser_exception(
        self,
        mock_detect_format,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test roundtrip command with parser exception."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.return_value = b"invalid data"
        mock_detect_format.return_value = "root"

        with patch("cascette_tools.commands.validate.RootParser") as mock_parser:
            mock_parser.return_value.parse.side_effect = Exception("Parse failed")

            result = runner.invoke(validate, ["roundtrip", "test_hash"])

            assert result.exit_code == 1

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate._fetch_from_cdn_or_path")
    @patch("cascette_tools.commands.validate.Progress")
    def test_relationships_command_with_install_file(
        self,
        mock_progress_class,
        mock_fetch,
        mock_get_context,
        runner,
        mock_context_objects
    ):
        """Test relationships command with install file validation."""
        mock_get_context.return_value = mock_context_objects
        mock_fetch.side_effect = [b"root data", b"encoding data", b"install data"]

        # Mock Progress as a context manager
        mock_progress = Mock()
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=None)
        mock_progress.add_task = Mock()
        mock_progress_class.return_value = mock_progress

        with patch("cascette_tools.commands.validate.RootParser") as mock_root_parser:
            with patch("cascette_tools.commands.validate.EncodingParser") as mock_encoding_parser:
                with patch("cascette_tools.commands.validate.InstallParser") as mock_install_parser:
                    # Mock root object
                    mock_root = Mock()
                    mock_block = Mock()
                    mock_record = Mock()
                    mock_record.content_key = b"shared_key"
                    mock_block.records = [mock_record]
                    mock_root.blocks = [mock_block]
                    mock_root_parser.return_value.parse.return_value = mock_root

                    # Mock encoding object
                    mock_encoding = Mock()
                    mock_encoding.ckey_index = {b"shared_key": Mock()}
                    mock_encoding_parser.return_value.parse.return_value = mock_encoding

                    # Mock install object
                    mock_install = Mock()
                    mock_install_entry = Mock()
                    mock_install_entry.md5_hash = b"shared_key"
                    mock_install.entries = [mock_install_entry]
                    mock_install_parser.return_value.parse.return_value = mock_install

                    result = runner.invoke(validate, [
                        "relationships", "root_hash", "encoding_hash",
                        "--install-file", "install_hash"
                    ])

                    assert result.exit_code == 0
                    assert mock_fetch.call_count == 3

    @patch("cascette_tools.commands.validate._get_context_objects")
    @patch("cascette_tools.commands.validate.track")
    def test_batch_command_format_type_filter(
        self,
        mock_track,
        mock_get_context,
        runner,
        mock_context_objects,
        tmp_path
    ):
        """Test batch command with format type filtering."""
        mock_get_context.return_value = mock_context_objects
        # Mock track to return the files list without progress tracking
        mock_track.side_effect = lambda files, **kwargs: files

        # Create test files
        file1 = tmp_path / "test1.blte"
        file1.write_bytes(b"BLTE" + b"\x00" * 8 + b"blte data")
        file2 = tmp_path / "test2.encoding"
        file2.write_bytes(b"EN" + b"\x00" * 20 + b"encoding data")

        with patch("cascette_tools.commands.validate._detect_format_type") as mock_detect_format:
            with patch("cascette_tools.commands.validate._validate_format_structure") as mock_validate_structure:
                with patch("cascette_tools.commands.validate._validate_checksums") as mock_validate_checksums:
                    with patch("cascette_tools.commands.validate.compute_md5") as mock_compute_md5:
                        # Only detect BLTE format to trigger filtering
                        mock_detect_format.side_effect = ["blte", "encoding"]
                        mock_validate_structure.return_value = (True, "Valid structure", {})
                        mock_validate_checksums.return_value = (True, "Valid checksums", {})
                        mock_hash = Mock()
                        mock_hash.hex.return_value = "abc123"
                        mock_compute_md5.return_value = mock_hash

                        # Filter for only BLTE files
                        result = runner.invoke(validate, ["batch", str(tmp_path), "--format-type", "blte"])

                        assert result.exit_code == 0
                        # Should process both files but only validate the BLTE one
                        assert mock_detect_format.call_count >= 1

    def test_format_command_no_parser_available(self, runner):
        """Test format command with no parser available."""
        result = runner.invoke(validate, ["format", "test.unknown", "--format-type", "unsupported"])

        # Should handle gracefully or return appropriate error
        assert result.exit_code != 0

    # Error handling edge cases
    def test_exception_handling_during_fetch(self, runner):
        """Test exception handling during file fetch."""
        with patch("cascette_tools.commands.validate._get_context_objects") as mock_get_context:
            with patch("cascette_tools.commands.validate._fetch_from_cdn_or_path", side_effect=Exception("Network timeout")):
                mock_get_context.return_value = Mock(), Mock(), False, False
                result = runner.invoke(validate, ["format", "test_hash"])

                assert result.exit_code != 0
                assert "Failed to validate format" in result.output
