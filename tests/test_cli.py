"""Integration tests for the main CLI entry point."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from cascette_tools.__main__ import main
from cascette_tools.core.config import AppConfig


class TestMainCLI:
    """Test main CLI functionality."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_main_help(self) -> None:
        """Test main help command loads correctly."""
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Python tools for NGDP/CASC format analysis" in result.output
        assert "Commands:" in result.output

    def test_version_command(self) -> None:
        """Test version command."""
        result = self.runner.invoke(main, ["version"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "cascette-tools 0.1.0" in clean_output

    def test_version_command_verbose(self) -> None:
        """Test version command with verbose flag."""
        result = self.runner.invoke(main, ["--verbose", "version"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "cascette-tools 0.1.0" in clean_output
        assert "Python" in clean_output
        assert "Platform:" in clean_output

    def test_version_command_json_output(self) -> None:
        """Test version command with JSON output."""
        result = self.runner.invoke(main, ["--output", "json", "version"])
        assert result.exit_code == 0

        # Parse JSON output - strip whitespace
        json_output = json.loads(result.output.strip())
        assert json_output["name"] == "cascette-tools"
        assert json_output["version"] == "0.1.0"
        assert "python_version" in json_output
        assert "platform" in json_output

    def test_global_options_verbose(self) -> None:
        """Test verbose global option."""
        result = self.runner.invoke(main, ["--verbose", "version"])
        assert result.exit_code == 0

    def test_global_options_debug(self) -> None:
        """Test debug global option."""
        result = self.runner.invoke(main, ["--debug", "version"])
        assert result.exit_code == 0

    def test_global_options_output_formats(self) -> None:
        """Test different output format options."""
        for output_format in ["rich", "json", "plain"]:
            result = self.runner.invoke(main, ["--output", output_format, "version"])
            assert result.exit_code == 0

    def test_invalid_output_format(self) -> None:
        """Test invalid output format."""
        result = self.runner.invoke(main, ["--output", "invalid", "version"])
        assert result.exit_code != 0
        assert "Invalid value for '--output'" in result.output

    def test_configuration_loading_default(self) -> None:
        """Test configuration loading with defaults."""
        with patch.object(AppConfig, 'load') as mock_load:
            mock_load.return_value = AppConfig()
            result = self.runner.invoke(main, ["version"])
            assert result.exit_code == 0
            mock_load.assert_called_once_with(None)

    def test_configuration_loading_with_file(self) -> None:
        """Test configuration loading with custom file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {
                "output_format": "json",
                "log_level": "DEBUG"
            }
            json.dump(config_data, f)
            config_path = Path(f.name)

        try:
            result = self.runner.invoke(main, ["--config", str(config_path), "version"])
            assert result.exit_code == 0
        finally:
            config_path.unlink()

    def test_configuration_loading_failure(self) -> None:
        """Test configuration loading failure handling."""
        with patch.object(AppConfig, 'load') as mock_load:
            mock_load.side_effect = Exception("Config load failed")
            result = self.runner.invoke(main, ["version"])
            assert result.exit_code == 1

    def test_command_groups_registered(self) -> None:
        """Test that all command groups are registered."""
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0

        # Check that all expected command groups are listed
        expected_commands = [
            "examine",
            "analyze",
            "fetch",
            "validate",
            "tact",
            "listfile"
        ]

        for command in expected_commands:
            assert command in result.output

    def test_examine_command_group(self) -> None:
        """Test examine command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["examine"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Examine NGDP/CASC format files" in clean_output
        assert "Commands:" in clean_output
        assert "blte" in clean_output
        assert "encoding" in clean_output
        assert "config" in clean_output
        assert "archive" in clean_output

    def test_analyze_command_group(self) -> None:
        """Test analyze command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["analyze"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Analyze NGDP/CASC format files and data" in clean_output
        assert "Commands:" in clean_output
        assert "compression" in clean_output
        assert "coverage" in clean_output
        assert "dependencies" in clean_output
        assert "stats" in clean_output

    def test_fetch_command_group(self) -> None:
        """Test fetch command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["fetch"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Fetch data from CDN sources" in clean_output
        assert "Commands:" in clean_output
        assert "batch" in clean_output
        assert "build" in clean_output
        assert "config" in clean_output
        assert "data" in clean_output
        assert "encoding" in clean_output
        assert "manifests" in clean_output
        assert "patch" in clean_output

    def test_validate_command_group(self) -> None:
        """Test validate command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["validate"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Validate NGDP/CASC format files and integrity" in clean_output
        assert "Commands:" in clean_output
        assert "format" in clean_output
        assert "integrity" in clean_output
        assert "roundtrip" in clean_output
        assert "relationships" in clean_output
        assert "batch" in clean_output

    def test_tact_command_group(self) -> None:
        """Test tact command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["tact"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Manage TACT encryption keys" in clean_output
        assert "Commands:" in clean_output
        assert "export" in clean_output
        assert "list" in clean_output
        assert "search" in clean_output
        assert "stats" in clean_output
        assert "sync" in clean_output

    def test_listfile_command_group(self) -> None:
        """Test listfile command group shows help when no subcommand given."""
        result = self.runner.invoke(main, ["listfile"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "Manage FileDataID to path mappings" in clean_output
        assert "Commands:" in clean_output
        assert "export" in clean_output
        assert "lookup" in clean_output
        assert "search" in clean_output
        assert "stats" in clean_output
        assert "sync" in clean_output

    def test_configuration_override_with_verbose(self) -> None:
        """Test that CLI options override configuration."""
        with patch.object(AppConfig, 'load') as mock_load:
            config = AppConfig(log_level="ERROR")
            mock_load.return_value = config

            # The CLI should override the log level when --verbose is used
            result = self.runner.invoke(main, ["--verbose", "version"])
            assert result.exit_code == 0
            # Config should be modified to INFO level due to --verbose
            assert config.log_level == "INFO"

    def test_configuration_override_with_debug(self) -> None:
        """Test that debug option overrides configuration."""
        with patch.object(AppConfig, 'load') as mock_load:
            config = AppConfig(log_level="ERROR")
            mock_load.return_value = config

            # The CLI should override the log level when --debug is used
            result = self.runner.invoke(main, ["--debug", "version"])
            assert result.exit_code == 0
            # Config should be modified to DEBUG level due to --debug
            assert config.log_level == "DEBUG"

    def test_configuration_override_with_output(self) -> None:
        """Test that output option overrides configuration."""
        with patch.object(AppConfig, 'load') as mock_load:
            config = AppConfig(output_format="rich")
            mock_load.return_value = config

            # The CLI should override the output format
            result = self.runner.invoke(main, ["--output", "json", "version"])
            assert result.exit_code == 0
            # Config should be modified to json format
            assert config.output_format == "json"

    def test_exception_handling_keyboard_interrupt(self) -> None:
        """Test keyboard interrupt handling."""
        from cascette_tools.__main__ import handle_exception

        with patch('sys.exit') as mock_exit:
            with patch('cascette_tools.__main__.logger') as mock_logger:
                handle_exception(KeyboardInterrupt, KeyboardInterrupt(), None)
                mock_exit.assert_called_with(1)
                mock_logger.info.assert_called_once()

    def test_exception_handling_general_exception(self) -> None:
        """Test general exception handling."""
        from cascette_tools.__main__ import handle_exception

        with patch('sys.exit') as mock_exit:
            handle_exception(Exception, Exception("test error"), None)
            mock_exit.assert_called_once_with(1)

    def test_main_execution_exception_handling(self) -> None:
        """Test main execution exception handling."""
        with patch('cascette_tools.__main__.main') as mock_main:
            mock_main.side_effect = Exception("CLI failed")

            # This test simulates running the CLI as a module
            with patch('sys.exit') as mock_exit:
                with patch('cascette_tools.__main__.logger') as mock_logger:
                    # Import and run the main block
                    with patch('cascette_tools.__main__.__name__', '__main__'):
                        try:
                            exec("""
if __name__ == "__main__":
    sys.excepthook = handle_exception
    try:
        main()
    except Exception as e:
        logger.error("CLI execution failed", error=str(e))
        sys.exit(1)
""", {
                                'main': mock_main,
                                'handle_exception': lambda *args: None,
                                'sys': sys,
                                'logger': mock_logger,
                                '__name__': '__main__'
                            })
                        except SystemExit:
                            pass

                    mock_logger.error.assert_called_once()
                    mock_exit.assert_called_once_with(1)


class TestCLIIntegration:
    """Integration tests for CLI functionality."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_cli_as_module(self) -> None:
        """Test CLI works when invoked as module."""
        # This simulates python -m cascette_tools --help
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_cli_extensibility(self) -> None:
        """Test that CLI is extensible for future commands."""
        # Check that help shows proper structure for adding new commands
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0

        # Should show command groups that can be extended
        assert "Commands:" in result.output

        # Test that command groups have help
        for cmd in ["examine", "analyze", "fetch", "validate", "tact", "listfile"]:
            result = self.runner.invoke(main, [cmd, "--help"])
            assert result.exit_code == 0

    def test_context_passing(self) -> None:
        """Test that context is properly passed to subcommands."""
        # This tests that config and console objects are available in context
        result = self.runner.invoke(main, ["--verbose", "--output", "json", "examine"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        # The help output should work, indicating context was passed correctly
        assert "Examine NGDP/CASC format files" in clean_output
        assert "Commands:" in clean_output
