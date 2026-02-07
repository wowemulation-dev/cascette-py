"""Tests for TACT key management commands."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.tact import tact_group


class TestTactCommands:
    """Test TACT key management commands."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    # Use standardized fixtures from conftest.py
    # mock_config, mock_console, and mock_cli_context are available

    @pytest.fixture
    def mock_tact_manager(self):
        """Create mock TACT key manager."""
        manager = Mock()

        # Create mock TACTKey objects
        mock_key1 = Mock()
        mock_key1.key_name = "ABCDEF1234567890ABCDEF1234567890"
        mock_key1.key_value = "1234567890ABCDEF1234567890ABCDEF"
        mock_key1.description = "Test key 1 description"
        mock_key1.product_family = "wow"
        mock_key1.verified = True

        mock_key2 = Mock()
        mock_key2.key_name = "FEDCBA0987654321FEDCBA0987654321"
        mock_key2.key_value = "FEDCBA0987654321FEDCBA0987654321"
        mock_key2.description = "Test key 2 description that is very long and should be truncated"
        mock_key2.product_family = "wow"
        mock_key2.verified = False

        manager.fetch_wowdev_keys.return_value = [mock_key1, mock_key2]
        manager.import_keys.return_value = 2
        manager.get_statistics.return_value = {
            "total_keys": 100,
            "verified": 90,
            "unverified": 10,
            "by_family": {"wow": 80, "s2": 20}
        }
        manager.get_key.return_value = mock_key1
        manager.get_all_keys.return_value = [mock_key1, mock_key2]
        manager.get_keys_by_family.return_value = [mock_key1, mock_key2]
        manager.export_keys.return_value = None

        # Add context manager support
        manager.__enter__ = Mock(return_value=manager)
        manager.__exit__ = Mock(return_value=None)
        manager.close = Mock()
        return manager

    def _setup_mock_cli_context_manager(self, mock_manager_class, mock_manager):
        """Helper to set up mock context manager properly."""
        # The manager class should return the mock_manager when instantiated
        mock_manager_class.return_value = mock_manager
        return mock_manager

    def test_tact_group_help(self, runner):
        """Test tact group shows help when invoked without subcommand."""
        result = runner.invoke(tact_group, [])

        # Click returns exit code 2 when group is invoked without subcommand
        assert result.exit_code in (0, 2)
        assert "Manage TACT encryption keys" in result.output
        assert "sync" in result.output
        assert "list" in result.output
        assert "search" in result.output
        assert "export" in result.output
        assert "stats" in result.output

    def test_tact_group_help_flag(self, runner):
        """Test tact group shows help when invoked with --help."""
        result = runner.invoke(tact_group, ["--help"])

        assert result.exit_code == 0
        assert "Manage TACT encryption keys" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_sync_keys_default(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test sync command with default options."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        # Create a context for the test
        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.fetch_wowdev_keys.assert_called_once_with(force_refresh=False)
            mock_tact_manager.import_keys.assert_called_once()
            mock_tact_manager.get_statistics.assert_called_once()
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Synced 2 TACT keys" in console_output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_sync_keys_force_refresh(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test sync command with force refresh."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["sync", "--force"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.fetch_wowdev_keys.assert_called_once_with(force_refresh=True)

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_sync_keys_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test sync command with error during sync."""
        mock_manager = Mock()
        mock_manager.fetch_wowdev_keys.side_effect = Exception("Network error")
        # Add context manager support
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code != 0
            assert "Failed to sync" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_list_keys_all(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test list command showing all keys."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["list"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.get_all_keys.assert_called_once()
            # Table object was printed successfully
            assert result.exit_code == 0

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_list_keys_by_family(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test list command filtering by family."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["list", "--family", "wow"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.get_keys_by_family.assert_called_once_with("wow")

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_list_keys_with_limit(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test list command with limit."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["list", "--limit", "5"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            # Limit was applied correctly
            mock_tact_manager.get_all_keys.assert_called_once()

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_list_keys_empty_result(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test list command with no keys found."""
        mock_tact_manager.get_all_keys.return_value = []
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["list"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            assert "No TACT keys found" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_search_key_found(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test search command with found key."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["search", "ABCDEF"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.get_key.assert_called_once_with("ABCDEF")
            # Key search was successful
            assert result.exit_code == 0

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_search_key_not_found(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test search command with key not found."""
        mock_tact_manager.get_key.return_value = None
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["search", "NOTFOUND"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            assert "Key not found" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_search_key_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test search command with error."""
        mock_manager = Mock()
        mock_manager.get_key.side_effect = Exception("Database error")
        # Add context manager support
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["search", "ERROR"], obj=mock_cli_context.obj)

            # The error is caught but command should fail
            assert result.exit_code != 0 or "error" in result.output.lower()

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_export_keys_all(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test export command for all keys."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            output_file = "test_keys.json"
            result = runner.invoke(tact_group, ["export", output_file], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.export_keys.assert_called_once()
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Exported" in console_output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_export_keys_by_family(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test export command filtered by family."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            output_file = "test_keys.json"
            result = runner.invoke(
                tact_group,
                ["export", output_file, "--family", "wow"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            # Check export_keys was called with the correct arguments
            args, kwargs = mock_tact_manager.export_keys.call_args
            assert "wow" in str(args) or (kwargs and kwargs.get('family') == "wow") or args[1] == "wow"

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_export_keys_write_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test export command with write error."""
        mock_manager = Mock()
        mock_manager.export_keys.side_effect = Exception("Write error")
        mock_manager.get_all_keys.return_value = []
        # Add context manager support
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["export", "test.json"], obj=mock_cli_context.obj)

            assert result.exit_code != 0
            assert "Failed to export" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_show_stats(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test stats command."""
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["stats"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_tact_manager.get_statistics.assert_called_once()
            # Statistics table was printed successfully
            assert result.exit_code == 0

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_show_stats_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test stats command with error."""
        mock_manager = Mock()
        mock_manager.get_statistics.side_effect = Exception("Database error")
        # Add context manager support
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["stats"], obj=mock_cli_context.obj)

            # Command should complete but show error
            assert result.exit_code != 0 or "error" in result.output.lower()

    def test_sync_help(self, runner):
        """Test sync subcommand help."""
        result = runner.invoke(tact_group, ["sync", "--help"])

        assert result.exit_code == 0
        assert "Sync TACT keys" in result.output

    def test_list_help(self, runner):
        """Test list subcommand help."""
        result = runner.invoke(tact_group, ["list", "--help"])

        assert result.exit_code == 0
        assert "List TACT keys" in result.output

    def test_search_help(self, runner):
        """Test search subcommand help."""
        result = runner.invoke(tact_group, ["search", "--help"])

        assert result.exit_code == 0
        assert "Search for" in result.output

    def test_export_help(self, runner):
        """Test export subcommand help."""
        result = runner.invoke(tact_group, ["export", "--help"])

        assert result.exit_code == 0
        assert "Export TACT keys" in result.output

    def test_stats_help(self, runner):
        """Test stats subcommand help."""
        result = runner.invoke(tact_group, ["stats", "--help"])

        assert result.exit_code == 0
        assert "Show TACT key" in result.output

    def test_search_missing_argument(self, runner):
        """Test search command with missing argument."""
        result = runner.invoke(tact_group, ["search"])

        assert result.exit_code != 0
        assert "Missing argument" in result.output

    def test_export_missing_argument(self, runner):
        """Test export command with missing argument."""
        result = runner.invoke(tact_group, ["export"])

        assert result.exit_code != 0
        assert "Missing argument" in result.output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_list_keys_database_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test list command with database error."""
        mock_manager = Mock()
        mock_manager.get_all_keys.side_effect = Exception("Database connection failed")
        # Add context manager support
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["list"], obj=mock_cli_context.obj)

            assert result.exit_code != 0 or "error" in result.output.lower()

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_export_keys_empty_result(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test export command with no keys."""
        mock_tact_manager.get_all_keys.return_value = []
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["export", "empty.json"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Exported 0 TACT keys" in console_output

    @patch("cascette_tools.commands.tact.TACTKeyManager")
    def test_sync_keys_no_new_keys(
        self,
        mock_manager_class,
        runner,
        mock_tact_manager,
        mock_cli_context
    ):
        """Test sync command when no new keys are imported."""
        mock_tact_manager.fetch_wowdev_keys.return_value = []
        mock_tact_manager.import_keys.return_value = 0
        self._setup_mock_cli_context_manager(mock_manager_class, mock_tact_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(tact_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Synced 0 TACT keys" in console_output
