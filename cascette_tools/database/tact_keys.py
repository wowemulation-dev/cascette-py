"""TACT encryption key database management."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.config import AppConfig

logger = structlog.get_logger()


class TACTKey(BaseModel):
    """TACT encryption key entry."""

    key_name: str = Field(description="Key name (8 bytes hex)")
    key_value: str = Field(description="Key value (16 bytes hex)")
    description: str | None = Field(default=None, description="Key description")
    product_family: str = Field(default="wow", description="Product family")
    verified: bool = Field(default=False, description="Community verified")


class TACTKeyManager:
    """Manages TACT encryption keys from wowdev/TACTKeys."""

    GITHUB_RAW_URL = "https://raw.githubusercontent.com/wowdev/TACTKeys/master"
    CACHE_LIFETIME = timedelta(hours=24)

    def __init__(self, config: AppConfig | None = None) -> None:
        """Initialize TACT key manager.

        Args:
            config: Application configuration
        """
        self.config = config or AppConfig()
        self.db_path = self.config.data_dir / "tact_keys.db"
        self.cache_dir = self.config.data_dir / "tact_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._conn: sqlite3.Connection | None = None
        self._client: httpx.Client | None = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=30.0,
                headers={"User-Agent": "cascette-tools/0.1.0"}
            )
        return self._client

    def _init_db(self) -> None:
        """Initialize database schema for TACT keys."""
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS tact_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_name TEXT NOT NULL UNIQUE,
                    key_value TEXT NOT NULL,
                    description TEXT,
                    product_family TEXT DEFAULT 'wow',
                    verified INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_key_name ON tact_keys(key_name);
                CREATE INDEX IF NOT EXISTS idx_product_family ON tact_keys(product_family);
            """)

        logger.info("tact_keys_db_initialized", path=str(self.db_path))

    def get_key(self, key_name: str | bytes) -> TACTKey | None:
        """Get a TACT key by name.

        Args:
            key_name: Key name (hex string or bytes)

        Returns:
            TACT key if found, None otherwise
        """
        # Convert bytes to hex string if needed
        if isinstance(key_name, bytes):
            key_name = key_name.hex().upper()
        else:
            key_name = key_name.upper()

        row = self.conn.execute(
            "SELECT * FROM tact_keys WHERE key_name = ?",
            (key_name,)
        ).fetchone()

        if row:
            return TACTKey(
                key_name=row["key_name"],
                key_value=row["key_value"],
                description=row["description"],
                product_family=row["product_family"],
                verified=bool(row["verified"])
            )

        return None

    def add_key(self, key: TACTKey) -> bool:
        """Add or update a TACT key.

        Args:
            key: TACT key to add

        Returns:
            True if added/updated, False on error
        """
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT OR REPLACE INTO tact_keys
                    (key_name, key_value, description, product_family, verified, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    key.key_name.upper(),
                    key.key_value.upper(),
                    key.description,
                    key.product_family,
                    key.verified
                ))
            return True
        except sqlite3.Error as e:
            logger.error("tact_key_add_failed", error=str(e))
            return False

    def get_all_keys(self) -> list[TACTKey]:
        """Get all TACT keys from database.

        Returns:
            List of all TACT keys
        """
        rows = self.conn.execute("SELECT * FROM tact_keys").fetchall()

        keys = []
        for row in rows:
            keys.append(TACTKey(
                key_name=row["key_name"],
                key_value=row["key_value"],
                description=row["description"],
                product_family=row["product_family"],
                verified=bool(row["verified"])
            ))

        return keys

    def get_keys_by_family(self, family: str) -> list[TACTKey]:
        """Get TACT keys for a product family.

        Args:
            family: Product family (e.g., 'wow', 'battlenet')

        Returns:
            List of TACT keys for the family
        """
        rows = self.conn.execute(
            "SELECT * FROM tact_keys WHERE product_family = ?",
            (family,)
        ).fetchall()

        keys = []
        for row in rows:
            keys.append(TACTKey(
                key_name=row["key_name"],
                key_value=row["key_value"],
                description=row["description"],
                product_family=row["product_family"],
                verified=bool(row["verified"])
            ))

        return keys

    def fetch_wowdev_keys(self, force_refresh: bool = False) -> list[TACTKey]:
        """Fetch TACT keys from wowdev/TACTKeys repository.

        Args:
            force_refresh: Force fetch even if cache is valid

        Returns:
            List of TACT keys
        """
        cache_file = self.cache_dir / "wowdev_keys.json"
        metadata_file = self.cache_dir / "wowdev_metadata.json"

        # Check cache validity
        if not force_refresh and cache_file.exists() and metadata_file.exists():
            try:
                with open(metadata_file) as f:
                    metadata = json.load(f)

                fetch_time = datetime.fromisoformat(metadata["fetch_time"])
                if datetime.now(timezone.utc) - fetch_time < self.CACHE_LIFETIME:
                    # Cache is valid, load from cache
                    with open(cache_file) as f:
                        data = json.load(f)

                    keys = [TACTKey(**k) for k in data]
                    logger.info("tact_keys_from_cache", count=len(keys))
                    return keys
            except Exception as e:
                logger.warning("tact_cache_load_failed", error=str(e))

        # Fetch from GitHub
        logger.info("fetching_tact_keys_from_github")

        try:
            # Fetch WoW keys CSV
            response = self.client.get(f"{self.GITHUB_RAW_URL}/WoW.txt")
            response.raise_for_status()

            keys = []
            for line in response.text.strip().split('\n'):
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse semicolon-separated format: keyname;keyvalue;description
                parts = line.split(';')
                if len(parts) < 2:
                    continue

                # Extract key components
                key_name = parts[0].strip().upper()
                key_value = parts[1].strip().upper()
                description = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None

                key = TACTKey(
                    key_name=key_name,
                    key_value=key_value,
                    description=description,
                    product_family="wow",
                    verified=True  # wowdev keys are community verified
                )
                keys.append(key)

            # Cache the results
            with open(cache_file, 'w') as f:
                json.dump([k.model_dump() for k in keys], f, indent=2)

            with open(metadata_file, 'w') as f:
                json.dump({
                    "fetch_time": datetime.now(timezone.utc).isoformat(),
                    "key_count": len(keys),
                    "source": "wowdev/TACTKeys"
                }, f, indent=2)

            logger.info("tact_keys_fetched", count=len(keys))
            return keys

        except httpx.HTTPError as e:
            logger.error("tact_keys_fetch_failed", error=str(e))
            # Try to return cached data if available
            if cache_file.exists():
                with open(cache_file) as f:
                    data = json.load(f)
                keys = [TACTKey(**k) for k in data]
                logger.warning("using_stale_tact_cache", count=len(keys))
                return keys
            return []

    def import_keys(self, keys: list[TACTKey]) -> int:
        """Import TACT keys into database.

        Args:
            keys: List of TACT keys to import

        Returns:
            Number of keys imported/updated
        """
        imported = 0

        for key in keys:
            if self.add_key(key):
                imported += 1

        logger.info("tact_keys_imported", count=imported)
        return imported

    def sync_with_wowdev(self) -> int:
        """Sync database with latest wowdev/TACTKeys.

        Returns:
            Number of keys imported/updated
        """
        keys = self.fetch_wowdev_keys(force_refresh=True)
        return self.import_keys(keys)

    def get_statistics(self) -> dict:
        """Get database statistics.

        Returns:
            Dictionary with statistics
        """
        stats = {
            "total_keys": 0,
            "verified": 0,
            "unverified": 0,
            "by_family": {}
        }

        # Total keys
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM tact_keys").fetchone()
        stats["total_keys"] = row["cnt"]

        # Verified/unverified
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM tact_keys WHERE verified = 1").fetchone()
        stats["verified"] = row["cnt"]
        stats["unverified"] = stats["total_keys"] - stats["verified"]

        # By product family
        rows = self.conn.execute("""
            SELECT product_family, COUNT(*) as cnt
            FROM tact_keys
            GROUP BY product_family
        """).fetchall()

        for row in rows:
            stats["by_family"][row["product_family"]] = row["cnt"]

        return stats

    def export_keys(self, output_path: Path, product_family: str | None = None) -> None:
        """Export TACT keys to JSON file.

        Args:
            output_path: Path to save JSON file
            product_family: Optional family filter
        """
        if product_family:
            keys = self.get_keys_by_family(product_family)
        else:
            keys = self.get_all_keys()

        export_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_keys": len(keys),
            "product_family_filter": product_family,
            "keys": [key.model_dump() for key in keys]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info("tact_keys_exported", path=str(output_path), count=len(keys))

    def close(self) -> None:
        """Close database connection and HTTP client."""
        if self._conn:
            self._conn.close()
            self._conn = None
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def create_blte_key_store(manager: TACTKeyManager, product_family: str = "wow") -> dict[bytes, bytes]:
    """Create a BLTE-compatible key store from database.

    Args:
        manager: TACT key manager
        product_family: Product family to load keys for

    Returns:
        Dictionary mapping key names (bytes) to key values (bytes)
    """
    keys = manager.get_keys_by_family(product_family)

    key_store = {}
    for key in keys:
        try:
            # Convert hex strings to bytes
            key_name_bytes = bytes.fromhex(key.key_name)
            key_value_bytes = bytes.fromhex(key.key_value)
            key_store[key_name_bytes] = key_value_bytes
        except ValueError as e:
            logger.warning("invalid_tact_key", key_name=key.key_name, error=str(e))

    return key_store
