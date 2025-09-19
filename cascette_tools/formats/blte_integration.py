"""Integration between BLTE parser and TACT key database."""

from __future__ import annotations

import structlog

from cascette_tools.core.config import AppConfig
from cascette_tools.database.tact_keys import TACTKeyManager, create_blte_key_store
from cascette_tools.formats.blte import BLTEParser, TACTKeyStore

logger = structlog.get_logger()


class DatabaseTACTKeyStore(TACTKeyStore):
    """TACT key store backed by database."""

    def __init__(self, manager: TACTKeyManager, product_family: str = "wow"):
        """Initialize with database manager.

        Args:
            manager: TACT key manager
            product_family: Product family to load keys for
        """
        super().__init__()
        self.manager = manager
        self.product_family = product_family
        self._load_keys()

    def _load_keys(self) -> None:
        """Load keys from database."""
        key_dict = create_blte_key_store(self.manager, self.product_family)
        self.keys = key_dict
        logger.info("tact_keys_loaded", count=len(self.keys), family=self.product_family)

    def get_key(self, key_name: bytes) -> bytes | None:
        """Get a TACT key by name, checking database if not in memory.

        Args:
            key_name: Key name (8 bytes)

        Returns:
            Key value (16 bytes) or None if not found
        """
        # Check memory first
        key_value = super().get_key(key_name)
        if key_value:
            return key_value

        # Check database
        db_key = self.manager.get_key(key_name)
        if db_key:
            try:
                key_value = bytes.fromhex(db_key.key_value)
                # Cache in memory for next time
                self.add_key(key_name, key_value)
                logger.debug("tact_key_loaded_from_db", key_name=key_name.hex())
                return key_value
            except ValueError as e:
                logger.warning("invalid_tact_key_value",
                             key_name=key_name.hex(),
                             error=str(e))

        logger.warning("tact_key_not_found", key_name=key_name.hex())
        return None

    def refresh(self) -> None:
        """Refresh keys from database."""
        self._load_keys()


class IntegratedBLTEParser(BLTEParser):
    """BLTE parser with integrated TACT key database support."""

    def __init__(self, config: AppConfig | None = None, product_family: str = "wow"):
        """Initialize with database integration.

        Args:
            config: Application configuration
            product_family: Product family for key lookup
        """
        self.config = config or AppConfig()
        self.tact_manager = TACTKeyManager(self.config)
        key_store = DatabaseTACTKeyStore(self.tact_manager, product_family)
        super().__init__(key_store)

    def ensure_keys_synced(self) -> None:
        """Ensure TACT keys are synced from wowdev repository."""
        if not self.tact_manager.get_all_keys():
            logger.info("syncing_tact_keys_from_wowdev")
            self.tact_manager.sync_with_wowdev()
            if isinstance(self.key_store, DatabaseTACTKeyStore):
                self.key_store.refresh()

    def close(self) -> None:
        """Close database connections."""
        self.tact_manager.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def decompress_blte_with_db(data: bytes,
                            config: AppConfig | None = None,
                            product_family: str = "wow") -> bytes:
    """Convenience function to decompress BLTE data with database key lookup.

    Args:
        data: BLTE-encoded data
        config: Application configuration
        product_family: Product family for key lookup

    Returns:
        Decompressed data

    Raises:
        ValueError: If decompression fails
    """
    with IntegratedBLTEParser(config, product_family) as parser:
        parser.ensure_keys_synced()
        blte_file = parser.parse(data)
        return parser.decompress(blte_file)


def create_integrated_parser(config: AppConfig | None = None,
                            product_family: str = "wow",
                            sync_keys: bool = True) -> IntegratedBLTEParser:
    """Create an integrated BLTE parser with TACT key database.

    Args:
        config: Application configuration
        product_family: Product family for key lookup
        sync_keys: Whether to sync keys from wowdev if database is empty

    Returns:
        Integrated BLTE parser ready for use
    """
    parser = IntegratedBLTEParser(config, product_family)

    if sync_keys:
        parser.ensure_keys_synced()

    return parser
