"""Tests for cascette_tools.__main__ module."""

from click.testing import CliRunner

from cascette_tools.__main__ import main


class TestMainCLI:
    """Tests for main CLI functionality."""

    def test_main_help(self) -> None:
        """Test main command help output."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Python tools for NGDP/CASC format analysis" in result.output

    def test_version_command(self) -> None:
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        # Remove ANSI color codes for testing
        import re
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
        assert "cascette-tools 0.1.0" in clean_output

    def test_version_option(self) -> None:
        """Test --version option."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_verbose_flag(self) -> None:
        """Test verbose flag is accepted."""
        runner = CliRunner()
        result = runner.invoke(main, ["--verbose", "version"])
        assert result.exit_code == 0

    def test_debug_flag(self) -> None:
        """Test debug flag is accepted."""
        runner = CliRunner()
        result = runner.invoke(main, ["--debug", "version"])
        assert result.exit_code == 0
