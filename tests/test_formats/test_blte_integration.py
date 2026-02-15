"""Tests for BLTE integration with TACT key database."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cascette_tools.core.types import TACTKey
from cascette_tools.formats.blte import TACTKeyStore
from cascette_tools.formats.blte_integration import (
    DatabaseTACTKeyStore,
    IntegratedBLTEParser,
    create_integrated_parser,
)


@pytest.fixture
def mock_tact_manager() -> MagicMock:
    manager = MagicMock()
    manager.get_all_keys.return_value = []
    return manager


@pytest.fixture
def mock_key_store_data() -> dict[bytes, bytes]:
    """Sample TACT keys for testing."""
    return {
        bytes.fromhex("0123456789abcdef"): bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("fedcba9876543210"): bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    }


class TestDatabaseTACTKeyStore:
    """Tests for database-backed TACT key store."""

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_init_loads_keys(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        mock_create.return_value = {b"\x01" * 8: b"\x02" * 16}
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        mock_create.assert_called_once_with(mock_tact_manager, "wow")
        assert store.keys == {b"\x01" * 8: b"\x02" * 16}

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_get_key_from_memory(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        key_name = b"\x01" * 8
        key_value = b"\x02" * 16
        mock_create.return_value = {key_name: key_value}
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        assert store.get_key(key_name) == key_value

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_get_key_from_database(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        mock_create.return_value = {}
        key_name = b"\x01" * 8
        key_hex = "00112233445566778899aabbccddeeff"

        mock_tact_manager.get_key.return_value = TACTKey(
            key_name=key_name.hex(),
            key_value=key_hex,
            lookup="0",
        )
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        result = store.get_key(key_name)
        assert result == bytes.fromhex(key_hex)

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_get_key_not_found(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        mock_create.return_value = {}
        mock_tact_manager.get_key.return_value = None
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        result = store.get_key(b"\xFF" * 8)
        assert result is None

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_get_key_invalid_hex_in_db(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        mock_create.return_value = {}
        mock_tact_manager.get_key.return_value = TACTKey(
            key_name="0123456789abcdef",
            key_value="not_valid_hex",
            lookup="0",
        )
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        result = store.get_key(b"\x01\x23\x45\x67\x89\xab\xcd\xef")
        assert result is None

    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_refresh_reloads_keys(self, mock_create: MagicMock, mock_tact_manager: MagicMock) -> None:
        mock_create.return_value = {}
        store = DatabaseTACTKeyStore(mock_tact_manager, "wow")
        assert mock_create.call_count == 1

        mock_create.return_value = {b"\x01" * 8: b"\x02" * 16}
        store.refresh()
        assert mock_create.call_count == 2
        assert len(store.keys) == 1


class TestIntegratedBLTEParser:
    """Tests for integrated BLTE parser."""

    @patch("cascette_tools.formats.blte_integration.TACTKeyManager")
    @patch("cascette_tools.formats.blte_integration.DatabaseTACTKeyStore")
    def test_init(self, mock_store_cls: MagicMock, mock_mgr_cls: MagicMock) -> None:
        mock_store = MagicMock(spec=TACTKeyStore)
        mock_store_cls.return_value = mock_store

        _parser = IntegratedBLTEParser(product_family="wow")
        mock_mgr_cls.assert_called_once()
        mock_store_cls.assert_called_once()

    @patch("cascette_tools.formats.blte_integration.TACTKeyManager")
    @patch("cascette_tools.formats.blte_integration.DatabaseTACTKeyStore")
    def test_close(self, mock_store_cls: MagicMock, mock_mgr_cls: MagicMock) -> None:
        mock_mgr = MagicMock()
        mock_mgr_cls.return_value = mock_mgr
        mock_store_cls.return_value = MagicMock(spec=TACTKeyStore)

        parser = IntegratedBLTEParser()
        parser.close()
        mock_mgr.close.assert_called_once()

    @patch("cascette_tools.formats.blte_integration.TACTKeyManager")
    @patch("cascette_tools.formats.blte_integration.DatabaseTACTKeyStore")
    def test_context_manager(self, mock_store_cls: MagicMock, mock_mgr_cls: MagicMock) -> None:
        mock_mgr = MagicMock()
        mock_mgr_cls.return_value = mock_mgr
        mock_store_cls.return_value = MagicMock(spec=TACTKeyStore)

        with IntegratedBLTEParser() as parser:
            assert parser is not None
        mock_mgr.close.assert_called_once()

    @patch("cascette_tools.formats.blte_integration.TACTKeyManager")
    @patch("cascette_tools.formats.blte_integration.DatabaseTACTKeyStore")
    def test_ensure_keys_synced_with_keys(
        self, mock_store_cls: MagicMock, mock_mgr_cls: MagicMock
    ) -> None:
        mock_mgr = MagicMock()
        mock_mgr.get_all_keys.return_value = [TACTKey(key_name="abc", key_value="def", lookup="0")]
        mock_mgr_cls.return_value = mock_mgr
        mock_store_cls.return_value = MagicMock(spec=TACTKeyStore)

        parser = IntegratedBLTEParser()
        parser.ensure_keys_synced()
        mock_mgr.sync_with_wowdev.assert_not_called()

    @patch("cascette_tools.formats.blte_integration.TACTKeyManager")
    @patch("cascette_tools.formats.blte_integration.create_blte_key_store")
    def test_ensure_keys_synced_without_keys(
        self, mock_create: MagicMock, mock_mgr_cls: MagicMock
    ) -> None:
        mock_mgr = MagicMock()
        mock_mgr.get_all_keys.return_value = []
        mock_mgr_cls.return_value = mock_mgr
        mock_create.return_value = {}

        parser = IntegratedBLTEParser()
        parser.ensure_keys_synced()
        mock_mgr.sync_with_wowdev.assert_called_once()
        # key_store is a real DatabaseTACTKeyStore, so isinstance check passes
        # and refresh() calls _load_keys() which calls create_blte_key_store
        assert mock_create.call_count == 2  # init + refresh


class TestCreateIntegratedParser:
    """Tests for the factory function."""

    @patch("cascette_tools.formats.blte_integration.IntegratedBLTEParser")
    def test_creates_parser(self, mock_parser_cls: MagicMock) -> None:
        mock_parser = MagicMock()
        mock_parser_cls.return_value = mock_parser

        result = create_integrated_parser(sync_keys=False)
        mock_parser_cls.assert_called_once()
        assert result == mock_parser

    @patch("cascette_tools.formats.blte_integration.IntegratedBLTEParser")
    def test_syncs_keys_by_default(self, mock_parser_cls: MagicMock) -> None:
        mock_parser = MagicMock()
        mock_parser_cls.return_value = mock_parser

        create_integrated_parser(sync_keys=True)
        mock_parser.ensure_keys_synced.assert_called_once()

    @patch("cascette_tools.formats.blte_integration.IntegratedBLTEParser")
    def test_skip_sync(self, mock_parser_cls: MagicMock) -> None:
        mock_parser = MagicMock()
        mock_parser_cls.return_value = mock_parser

        create_integrated_parser(sync_keys=False)
        mock_parser.ensure_keys_synced.assert_not_called()
