"""Tests for listfile command module."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.listfile import listfile_group


class TestListfileCommands:
    """Test listfile command functionality."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    # Use standardized fixtures from conftest.py
    # mock_config, mock_console, and mock_cli_context are available

    @pytest.fixture
    def mock_listfile_manager(self):
        """Create mock listfile manager."""
        manager = Mock()
        manager.fetch_listfile.return_value = [
            {"file_data_id": 123456, "path": "Interface/Icons/Spell_Shadow_SoulBurn.blp"},
            {"file_data_id": 789012, "path": "World/Maps/Azeroth/Azeroth_1_1.adt"}
        ]
        manager.import_entries.return_value = 2
        manager.get_statistics.return_value = {
            "total_entries": 1000000,
            "verified": 950000,
            "unverified": 50000
        }
        # Create mock FileDataEntry objects for search_paths
        from cascette_tools.database.listfile import FileDataEntry
        mock_entries = [
            FileDataEntry(fdid=123456, path="Interface/Icons/Spell_Shadow_SoulBurn.blp", verified=True),
            FileDataEntry(fdid=123457, path="Interface/Icons/Spell_Shadow_SoulBurn2.blp", verified=False)
        ]
        manager.search_paths.return_value = mock_entries
        manager.search_by_pattern.return_value = [
            {
                "file_data_id": 123456,
                "path": "Interface/Icons/Spell_Shadow_SoulBurn.blp",
                "verified": True
            },
            {
                "file_data_id": 123457,
                "path": "Interface/Icons/Spell_Shadow_SoulBurn2.blp",
                "verified": False
            }
        ]
        # Set up proper return values for get_path and get_fdid methods
        manager.get_path.return_value = "Interface/Icons/Spell_Shadow_SoulBurn.blp"
        manager.get_fdid.return_value = 123456
        # Set up export_listfile method
        manager.export_listfile.return_value = None  # export methods usually return None
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

    def _add_context_manager_support(self, mock_manager):
        """Helper to add context manager support to a mock."""
        mock_manager.__enter__ = Mock(return_value=mock_manager)
        mock_manager.__exit__ = Mock(return_value=None)
        mock_manager.close = Mock()
        return mock_manager

    def test_listfile_group_help(self, runner):
        """Test listfile group shows help when invoked without subcommand."""
        result = runner.invoke(listfile_group, [])

        assert result.exit_code == 0
        assert "Manage FileDataID to path mappings" in result.output
        assert "sync" in result.output
        assert "search" in result.output
        assert "lookup" in result.output
        assert "export" in result.output
        assert "stats" in result.output

    def test_listfile_group_help_flag(self, runner):
        """Test listfile group shows help when invoked with --help."""
        result = runner.invoke(listfile_group, ["--help"])

        assert result.exit_code == 0
        assert "Manage FileDataID to path mappings" in result.output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_sync_listfile_default(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test sync command with default options."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_listfile_manager.fetch_listfile.assert_called_once_with(force_refresh=False)
            mock_listfile_manager.import_entries.assert_called_once()
            mock_listfile_manager.get_statistics.assert_called_once()
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Synced 2 file entries" in console_output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_sync_listfile_force_refresh(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test sync command with force refresh."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["sync", "--force"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_listfile_manager.fetch_listfile.assert_called_once_with(force_refresh=True)

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_sync_listfile_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test sync command with error during sync."""
        mock_manager = Mock()
        mock_manager.fetch_listfile.side_effect = Exception("Network error")
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code != 0
            assert "Failed to sync" in result.output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_search_paths_pattern_match(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test search command with pattern matching."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["search", "Interface/Icons/*.blp"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            mock_listfile_manager.search_paths.assert_called_once_with("Interface/Icons/*.blp", 20)
            mock_listfile_manager.close.assert_called_once()

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_search_paths_with_limit(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test search command with result limit."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["search", "Interface/*", "--limit", "50"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_search_paths_no_results(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test search command with no results."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.search_paths.return_value = []  # Return empty list
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["search", "nonexistent/*"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "No files matching" in console_output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_search_paths_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test search command with database error."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.search_paths.side_effect = Exception("Database error")
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["search", "test/*"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code != 0
            # Exception should be raised
            assert result.exception is not None

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_lookup_file_by_id(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test lookup command by FileDataID."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["lookup", "123456"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            mock_listfile_manager.get_path.assert_called_once_with(123456)

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_lookup_file_by_path(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test lookup command by file path."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["lookup", "Interface/Icons/Spell_Shadow_SoulBurn.blp"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            mock_listfile_manager.get_fdid.assert_called_once_with(
                "Interface/Icons/Spell_Shadow_SoulBurn.blp"
            )

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_lookup_file_not_found(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test lookup command with file not found."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.get_path.return_value = None
        mock_manager.get_fdid.return_value = None
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["lookup", "999999"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            # Check console output properly - actual output is "Not found: {identifier}"
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Not found: 999999" in console_output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_lookup_file_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test lookup command with database error."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.get_path.side_effect = Exception("Database error")
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["lookup", "123456"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code != 0
            # Check that error was handled
            assert result.exception is not None

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_export_listfile_csv(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context,
        tmp_path
    ):
        """Test export command in CSV format."""
        mock_manager_class.return_value = mock_listfile_manager
        output_file = tmp_path / "listfile.csv"

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["export", str(output_file), "--format", "csv"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            mock_listfile_manager.export_listfile.assert_called_once()

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_export_listfile_json(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context,
        tmp_path
    ):
        """Test export command in JSON format."""
        mock_manager_class.return_value = mock_listfile_manager
        output_file = tmp_path / "listfile.json"

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["export", str(output_file), "--format", "json"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_export_listfile_write_error(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test export command with file write error."""
        mock_manager_class.return_value = mock_listfile_manager

        # Set up export to raise an exception
        mock_listfile_manager.export_listfile.side_effect = OSError("Permission denied")

        with runner.isolated_filesystem():
            # Try to export with mock error
            result = runner.invoke(
                listfile_group,
                ["export", "test.csv"],
                obj=mock_cli_context.obj
            )

            assert result.exit_code != 0
            # Exception should be raised
            assert result.exception is not None

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_show_stats(
        self,
        mock_manager_class,
        runner,
        mock_listfile_manager,
        mock_cli_context
    ):
        """Test stats command."""
        mock_manager_class.return_value = mock_listfile_manager

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["stats"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            mock_listfile_manager.get_statistics.assert_called_once()

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_show_stats_error(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test stats command with database error."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.get_statistics.side_effect = Exception("Database error")
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["stats"], obj=mock_cli_context.obj)

            assert result.exit_code != 0
            # Exception should be raised
            assert result.exception is not None

    def test_sync_help(self, runner):
        """Test sync subcommand shows help."""
        result = runner.invoke(listfile_group, ["sync", "--help"])

        assert result.exit_code == 0
        assert "Sync listfile" in result.output

    def test_search_help(self, runner):
        """Test search subcommand shows help."""
        result = runner.invoke(listfile_group, ["search", "--help"])

        assert result.exit_code == 0
        assert "Search for file paths matching pattern" in result.output

    def test_lookup_help(self, runner):
        """Test lookup subcommand shows help."""
        result = runner.invoke(listfile_group, ["lookup", "--help"])

        assert result.exit_code == 0
        assert "Lookup file by FDID or path" in result.output

    def test_export_help(self, runner):
        """Test export subcommand shows help."""
        result = runner.invoke(listfile_group, ["export", "--help"])

        assert result.exit_code == 0
        assert "Export listfile" in result.output

    def test_stats_help(self, runner):
        """Test stats subcommand shows help."""
        result = runner.invoke(listfile_group, ["stats", "--help"])

        assert result.exit_code == 0
        assert "Show listfile database statistics" in result.output

    def test_search_missing_argument(self, runner):
        """Test search command with missing argument."""
        result = runner.invoke(listfile_group, ["search"])

        assert result.exit_code != 0

    def test_lookup_missing_argument(self, runner):
        """Test lookup command with missing argument."""
        result = runner.invoke(listfile_group, ["lookup"])

        assert result.exit_code != 0

    def test_export_missing_argument(self, runner):
        """Test export command with missing argument."""
        result = runner.invoke(listfile_group, ["export"])

        assert result.exit_code != 0

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_sync_listfile_no_new_entries(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test sync command when no new entries are imported."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.fetch_listfile.return_value = []
        mock_manager.import_entries.return_value = 0
        mock_manager.get_statistics.return_value = {
            "total_entries": 1000000,
            "verified": 950000,
            "unverified": 50000
        }
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(listfile_group, ["sync"], obj=mock_cli_context.obj)

            assert result.exit_code == 0
            # Check console output
            console_output = ' '.join(mock_cli_context.obj['console'].printed_lines)
            assert "Synced 0 file entries" in console_output

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_export_listfile_empty_result(
        self,
        mock_manager_class,
        runner,
        mock_cli_context,
        tmp_path
    ):
        """Test export command with no entries to export."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        mock_manager.export_listfile.return_value = None
        mock_manager.get_statistics.return_value = {
            "total_entries": 0,
            "verified": 0,
            "unverified": 0
        }
        mock_manager.close = Mock()
        output_file = tmp_path / "empty_listfile.csv"

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["export", str(output_file)],
                obj=mock_cli_context.obj
            )

            assert result.exit_code == 0
            # Check that export was attempted
            mock_manager.export_listfile.assert_called_once()

    @patch("cascette_tools.commands.listfile.ListfileManager")
    def test_lookup_file_invalid_id(
        self,
        mock_manager_class,
        runner,
        mock_cli_context
    ):
        """Test lookup command with invalid FileDataID."""
        mock_manager = Mock()
        self._add_context_manager_support(mock_manager)
        self._setup_mock_cli_context_manager(mock_manager_class, mock_manager)
        # lookup_by_id should be called with -1 for invalid input
        mock_manager.lookup_by_id.return_value = None
        mock_manager.close = Mock()

        with runner.isolated_filesystem():
            result = runner.invoke(
                listfile_group,
                ["lookup", "invalid_id"],
                obj=mock_cli_context.obj
            )

            # Should try lookup_by_path since ID parsing failed
            assert result.exit_code == 0

