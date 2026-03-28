"""Tests for cascette_tools.commands.archive module."""

import struct
from io import BytesIO
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from cascette_tools.commands.archive import (
    ArchiveIndexResult,
    _get_context_objects,
    parse_archive_index_footer,
    parse_cdn_config_archives,
    search_archive_index,
)
from cascette_tools.core.config import AppConfig


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def temp_config(tmp_path):
    config = AppConfig()
    config.data_dir = tmp_path / "test_data"
    config.data_dir.mkdir(parents=True, exist_ok=True)
    return config


def make_valid_index_footer(
    entry_count: int = 1,
    key_bytes: int = 16,
    offset_bytes: int = 4,
    size_bytes: int = 4,
    version: int = 1,
) -> bytes:
    footer = BytesIO()
    footer.write(b"\x00" * 8)
    footer.write(struct.pack("<B", version))
    footer.write(b"\x00" * 2)
    footer.write(struct.pack("<B", 4))
    footer.write(struct.pack("<B", offset_bytes))
    footer.write(struct.pack("<B", size_bytes))
    footer.write(struct.pack("<B", key_bytes))
    footer.write(struct.pack("<B", 16))
    footer.write(struct.pack("<I", entry_count))
    footer.write(b"\x00" * 8)
    return footer.getvalue()


def make_valid_index_data(
    entries: list[tuple[bytes, int, int]] | None = None,
    is_archive_group: bool = False,
) -> bytes:
    data = BytesIO()

    if entries is None:
        entries = [(b"\x12" * 16, 0, 100)]

    for key, offset, size in entries:
        data.write(key)
        if is_archive_group:
            data.write(struct.pack(">HI", 0, offset))
        else:
            data.write(struct.pack(">I", offset))
        data.write(struct.pack(">I", size))

    footer = make_valid_index_footer(
        entry_count=len(entries), offset_bytes=6 if is_archive_group else 4
    )
    data.write(footer)

    return data.getvalue()


class TestArchiveIndexResult:
    """Test ArchiveIndexResult dataclass."""

    def test_basic_result(self):
        result = ArchiveIndexResult(offset=100, size=500)
        assert result.offset == 100
        assert result.size == 500
        assert result.archive_index is None

    def test_archive_group_result(self):
        result = ArchiveIndexResult(offset=100, size=500, archive_index=3)
        assert result.archive_index == 3


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


class TestParseCdnConfigArchives:
    """Test parse_cdn_config_archives function."""

    def test_parses_archives_line(self, tmp_path):
        config_content = """
# Comment
archives = abc123 def456 ghi789
other = value
"""
        config_path = tmp_path / "cdn_config"
        config_path.write_text(config_content)

        result = parse_cdn_config_archives(config_path)

        assert result == ["abc123", "def456", "ghi789"]

    def test_empty_archives(self, tmp_path):
        config_content = "# No archives"
        config_path = tmp_path / "cdn_config"
        config_path.write_text(config_content)

        result = parse_cdn_config_archives(config_path)

        assert result == []


class TestParseArchiveIndexFooter:
    """Test parse_archive_index_footer function."""

    def test_valid_footer(self):
        footer_data = make_valid_index_footer(entry_count=10)
        result = parse_archive_index_footer(footer_data)

        assert result is not None
        assert result["version"] == 1
        assert result["entry_count"] == 10
        assert result["key_bytes"] == 16
        assert result["offset_bytes"] == 4
        assert result["size_bytes"] == 4

    def test_too_short_data(self):
        result = parse_archive_index_footer(b"\x00" * 20)
        assert result is None

    def test_exactly_28_bytes(self):
        footer_data = make_valid_index_footer()
        result = parse_archive_index_footer(footer_data)
        assert result is not None


class TestSearchArchiveIndex:
    """Test search_archive_index function."""

    def test_find_entry(self):
        target_key = b"\x12" * 16
        index_data = make_valid_index_data(entries=[(target_key, 100, 500)])

        result = search_archive_index(index_data, target_key)

        assert result is not None
        assert result.offset == 100
        assert result.size == 500

    def test_entry_not_found(self):
        target_key = b"\xff" * 16
        other_key = b"\x12" * 16
        index_data = make_valid_index_data(entries=[(other_key, 100, 500)])

        result = search_archive_index(index_data, target_key)

        assert result is None

    def test_archive_group_entry(self):
        target_key = b"\x12" * 16
        index_data = make_valid_index_data(
            entries=[(target_key, 100, 500)], is_archive_group=True
        )

        result = search_archive_index(index_data, target_key)

        assert result is not None
        assert result.archive_index == 0

    def test_multiple_entries(self):
        key1 = b"\x11" * 16
        key2 = b"\x22" * 16
        key3 = b"\x33" * 16
        index_data = make_valid_index_data(
            entries=[
                (key1, 100, 500),
                (key2, 200, 600),
                (key3, 300, 700),
            ]
        )

        result = search_archive_index(index_data, key2)

        assert result is not None
        assert result.offset == 200
        assert result.size == 600

    def test_invalid_version(self):
        footer = make_valid_index_footer(version=2)
        data = b"\x00" * 100 + footer

        result = search_archive_index(data, b"\x12" * 16)

        assert result is None


class TestExamineCommand:
    """Test 'archive examine' command."""

    @patch("cascette_tools.commands.archive.is_cdn_archive_index")
    @patch("cascette_tools.commands.archive.CdnArchiveParser")
    def test_examine_valid_file(
        self, mock_parser_class, mock_is_index, cli_runner, tmp_path, temp_config
    ):
        mock_is_index.return_value = True

        mock_index = Mock()
        mock_index.footer = Mock(
            version=1,
            key_bytes=16,
            offset_bytes=4,
            size_bytes=4,
            entry_count=1,
            toc_hash=b"\x00" * 8,
        )
        mock_index.entries = []

        mock_parser = Mock()
        mock_parser.parse.return_value = mock_index
        mock_parser.get_statistics.return_value = {"total_entries": 1}
        mock_parser_class.return_value = mock_parser

        index_file = tmp_path / "test.index"
        index_file.write_bytes(make_valid_index_data())

        context_obj = {
            "config": temp_config,
            "console": Mock(),
            "verbose": False,
            "debug": False,
        }

        from cascette_tools.commands.archive import archive

        result = cli_runner.invoke(
            archive, ["examine", str(index_file)], obj=context_obj
        )

        assert result.exit_code == 0

    @patch("cascette_tools.commands.archive.is_cdn_archive_index")
    def test_examine_invalid_file(
        self, mock_is_index, cli_runner, tmp_path, temp_config
    ):
        mock_is_index.return_value = False

        index_file = tmp_path / "test.index"
        index_file.write_bytes(b"not an index")

        context_obj = {
            "config": temp_config,
            "console": Mock(),
            "verbose": False,
            "debug": False,
        }

        from cascette_tools.commands.archive import archive

        result = cli_runner.invoke(
            archive, ["examine", str(index_file)], obj=context_obj
        )

        assert result.exit_code == 0


class TestScanCommand:
    """Test 'archive scan' command."""

    @patch("cascette_tools.commands.archive.is_cdn_archive_index")
    @patch("cascette_tools.commands.archive.is_archive_group")
    def test_scan_directory(
        self, mock_is_ag, mock_is_index, cli_runner, tmp_path, temp_config
    ):
        mock_is_index.return_value = True
        mock_is_ag.return_value = True

        index_file = tmp_path / "test.index"
        index_file.write_bytes(b"\x00" * 1024 * 1024)

        context_obj = {
            "config": temp_config,
            "console": Mock(),
            "verbose": False,
            "debug": False,
        }

        from cascette_tools.commands.archive import archive

        result = cli_runner.invoke(archive, ["scan", str(tmp_path)], obj=context_obj)

        assert result.exit_code == 0


class TestFindCommand:
    """Test 'archive find' command."""

    @patch("cascette_tools.commands.archive.is_cdn_archive_index")
    @patch("cascette_tools.commands.archive.CdnArchiveParser")
    def test_find_entry(
        self, mock_parser_class, mock_is_index, cli_runner, tmp_path, temp_config
    ):
        mock_is_index.return_value = True

        target_key = b"\x12" * 16
        mock_entry = Mock()
        mock_entry.encoding_key = target_key
        mock_entry.offset = 100
        mock_entry.size = 500
        mock_entry.archive_index = None

        mock_index = Mock()
        mock_index.entries = [mock_entry]
        mock_index.footer = Mock(
            version=1,
            key_bytes=16,
            offset_bytes=4,
            size_bytes=4,
            entry_count=1,
            toc_hash=b"\x00" * 8,
        )

        mock_parser = Mock()
        mock_parser.parse.return_value = mock_index
        mock_parser.find_entry.return_value = mock_entry
        mock_parser_class.return_value = mock_parser

        index_file = tmp_path / "test.index"
        index_file.write_bytes(make_valid_index_data())

        context_obj = {
            "config": temp_config,
            "console": Mock(),
            "verbose": False,
            "debug": False,
        }

        from cascette_tools.commands.archive import archive

        result = cli_runner.invoke(
            archive, ["find", str(index_file), target_key.hex()], obj=context_obj
        )

        assert result.exit_code == 0

    def test_find_invalid_key(self, cli_runner, tmp_path, temp_config):
        index_file = tmp_path / "test.index"
        index_file.write_bytes(b"\x00" * 100)

        context_obj = {
            "config": temp_config,
            "console": Mock(),
            "verbose": False,
            "debug": False,
        }

        from cascette_tools.commands.archive import archive

        result = cli_runner.invoke(
            archive, ["find", str(index_file), "not-valid-hex"], obj=context_obj
        )

        assert result.exit_code == 0
