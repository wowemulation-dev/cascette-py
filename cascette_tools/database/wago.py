"""Wago.tools API client with local caching (24-hour lifetime)."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import Product

logger = structlog.get_logger()


class WagoBuild(BaseModel):
    """Build information from Wago.tools."""

    id: int = Field(description="Build ID")
    build: str = Field(description="Build number")
    version: str = Field(description="Version string")
    product: str = Field(description="Product code")
    build_time: datetime | None = Field(default=None, description="Build timestamp")
    build_config: str | None = Field(default=None, description="Build config hash")
    cdn_config: str | None = Field(default=None, description="CDN config hash")
    product_config: str | None = Field(default=None, description="Product config hash")
    encoding_ekey: str | None = Field(default=None, description="Encoding key")
    root_ekey: str | None = Field(default=None, description="Root key")
    install_ekey: str | None = Field(default=None, description="Install key")
    download_ekey: str | None = Field(default=None, description="Download key")


class WagoCacheMetadata(BaseModel):
    """Cache metadata for Wago.tools data."""

    fetch_time: datetime = Field(description="When data was fetched")
    expires_at: datetime = Field(description="When cache expires")
    build_count: int = Field(description="Number of builds cached")
    api_version: str = Field(default="v1", description="API version used")


def adapt_datetime_iso(val: datetime) -> str:
    """Adapt datetime to ISO format string for SQLite storage.

    This replaces the deprecated default datetime adapter in Python 3.12+.
    Stores datetime objects as ISO format strings in UTC timezone.

    Args:
        val: datetime object to adapt

    Returns:
        ISO format string representation
    """
    if val.tzinfo is None:
        # Assume naive datetimes are UTC
        val = val.replace(tzinfo=UTC)
    elif val.tzinfo != UTC:
        # Convert to UTC for consistent storage
        val = val.astimezone(UTC)

    return val.isoformat()


def convert_datetime_iso(val: bytes) -> datetime:
    """Convert ISO format string from SQLite to datetime object.

    This replaces the deprecated default datetime converter in Python 3.12+.
    Converts stored ISO format strings back to timezone-aware datetime objects in UTC.

    Args:
        val: ISO format string as bytes from SQLite

    Returns:
        timezone-aware datetime object in UTC
    """
    datestr = val.decode('utf-8')
    # Parse ISO format string and ensure UTC timezone
    dt = datetime.fromisoformat(datestr)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    elif dt.tzinfo != UTC:
        dt = dt.astimezone(UTC)

    return dt


class WagoClient:
    """Client for Wago.tools API with 24-hour local caching and SQLite storage."""

    API_BASE = "https://wago.tools/api"
    CACHE_LIFETIME = timedelta(hours=24)

    # Product families supported by Wago.tools
    SUPPORTED_PRODUCTS = ["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]
    PRODUCT_FAMILIES = {
        "wow": ["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"],
        "agent": ["agent"],
        "bna": ["bna"]
    }

    def __init__(self, config: AppConfig | None = None) -> None:
        """Initialize Wago client.

        Args:
            config: Application configuration
        """
        self.config = config or AppConfig()
        self.cache_dir = self.config.data_dir / "wago_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.cache_file = self.cache_dir / "builds.json"
        self.metadata_file = self.cache_dir / "metadata.json"
        self.db_path = self.config.data_dir / "wago_builds.db"

        self._client: httpx.Client | None = None
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        """Get or create database connection with proper datetime handling."""
        if self._conn is None:
            # Register explicit datetime adapters and converters to avoid deprecation warnings
            # This replaces the deprecated default adapters in Python 3.12+
            sqlite3.register_adapter(datetime, adapt_datetime_iso)
            sqlite3.register_converter("TIMESTAMP", convert_datetime_iso)

            # Connect with parse_decltypes to enable type converters
            self._conn = sqlite3.connect(str(self.db_path), detect_types=sqlite3.PARSE_DECLTYPES)
            self._conn.row_factory = sqlite3.Row

        return self._conn

    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.API_BASE,
                timeout=30.0,
                headers={
                    "User-Agent": "cascette-tools/0.1.0",
                    "Accept": "application/json",
                }
            )
        return self._client

    def _init_db(self) -> None:
        """Initialize database schema for Wago builds."""
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS builds (
                    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    id INTEGER NOT NULL,
                    build TEXT NOT NULL,
                    version TEXT NOT NULL,
                    product TEXT NOT NULL,
                    build_time TIMESTAMP,
                    build_config TEXT,
                    cdn_config TEXT,
                    product_config TEXT,
                    encoding_ekey TEXT,
                    root_ekey TEXT,
                    install_ekey TEXT,
                    download_ekey TEXT,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(id, product)
                );

                CREATE INDEX IF NOT EXISTS idx_builds_product ON builds(product);
                CREATE INDEX IF NOT EXISTS idx_builds_version ON builds(version);
                CREATE INDEX IF NOT EXISTS idx_builds_build_time ON builds(build_time);

                CREATE TABLE IF NOT EXISTS wago_import_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    import_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT DEFAULT 'wago_api',
                    builds_fetched INTEGER DEFAULT 0,
                    builds_imported INTEGER DEFAULT 0,
                    builds_updated INTEGER DEFAULT 0,
                    products TEXT,  -- JSON array of products imported
                    success INTEGER DEFAULT 1,
                    error_message TEXT
                );
            """)

    def _is_cache_valid(self) -> bool:
        """Check if cached data is still valid.

        Returns:
            True if cache exists and is less than 24 hours old
        """
        if not self.cache_file.exists() or not self.metadata_file.exists():
            return False

        try:
            with open(self.metadata_file) as f:
                metadata = WagoCacheMetadata(**json.load(f))

            now = datetime.now(UTC)
            if now < metadata.expires_at:
                age = now - metadata.fetch_time
                logger.info(
                    "cache_valid",
                    age_hours=age.total_seconds() / 3600,
                    expires_in_hours=(metadata.expires_at - now).total_seconds() / 3600,
                    build_count=metadata.build_count,
                )
                return True

            logger.info("cache_expired", expired_since=now - metadata.expires_at)
            return False

        except Exception as e:
            logger.warning("cache_invalid", error=str(e))
            return False

    def _load_cache(self) -> list[WagoBuild]:
        """Load builds from cache.

        Returns:
            List of cached builds
        """
        with open(self.cache_file) as f:
            data: list[dict[str, Any]] = json.load(f)

        builds: list[WagoBuild] = []
        for item in data:
            # Handle datetime fields
            if item.get("build_time"):
                item["build_time"] = datetime.fromisoformat(item["build_time"])
            builds.append(WagoBuild(**item))

        logger.info("cache_loaded", build_count=len(builds))
        return builds

    def _save_cache(self, builds: list[WagoBuild]) -> None:
        """Save builds to cache with metadata.

        Args:
            builds: List of builds to cache
        """
        # Prepare data for JSON serialization
        data: list[dict[str, Any]] = []
        for build in builds:
            item = build.model_dump()
            # Convert datetime to ISO format
            if item.get("build_time"):
                build_time = item["build_time"]
                if isinstance(build_time, datetime):
                    item["build_time"] = build_time.isoformat()
            data.append(item)

        # Save builds
        with open(self.cache_file, "w") as f:
            json.dump(data, f, indent=2)

        # Save metadata
        now = datetime.now(UTC)
        metadata = WagoCacheMetadata(
            fetch_time=now,
            expires_at=now + self.CACHE_LIFETIME,
            build_count=len(builds),
        )

        with open(self.metadata_file, "w") as f:
            json.dump(metadata.model_dump(mode="json"), f, indent=2, default=str)

        logger.info(
            "cache_saved",
            build_count=len(builds),
            expires_at=metadata.expires_at.isoformat(),
        )

    def fetch_builds(self, force_refresh: bool = False) -> list[WagoBuild]:
        """Fetch build data from Wago.tools or cache.

        Args:
            force_refresh: Force API fetch even if cache is valid

        Returns:
            List of builds

        Raises:
            httpx.HTTPError: On API communication errors
        """
        # Check cache unless forced refresh
        if not force_refresh and self._is_cache_valid():
            return self._load_cache()

        # Fetch from API
        logger.info("fetching_from_api", reason="cache_invalid" if not force_refresh else "forced")

        try:
            # Fetch all builds from the single API endpoint
            response = self.client.get("/builds")
            response.raise_for_status()

            data: dict[str, list[dict[str, Any]]] = response.json()
            all_builds: list[WagoBuild] = []
            products_found: set[str] = set()

            # The API returns a dict with product codes as keys
            # e.g., {"wowt": [...], "wow": [...], "wow_classic": [...]}
            for product_code, builds_list in data.items():
                # Skip if product is not in our supported list
                if product_code not in self.SUPPORTED_PRODUCTS:
                    logger.debug("skipping_unsupported_product", product=product_code)
                    continue

                products_found.add(product_code)

                # Parse builds for this product
                for item in builds_list:
                    try:
                        # Make a copy to avoid modifying the original data
                        build_data: dict[str, Any] = item.copy()

                        # The product field should already be in the data,
                        # but ensure it matches the key we're processing
                        build_data["product"] = product_code

                        # Map 'created_at' to 'build_time' if present
                        if build_data.get("created_at"):
                            created_at = build_data.pop("created_at")
                            # Handle datetime string format from API
                            if isinstance(created_at, str):
                                # Parse the format "2025-09-11 02:10:05"
                                try:
                                    build_data["build_time"] = datetime.strptime(
                                        created_at, "%Y-%m-%d %H:%M:%S"
                                    ).replace(tzinfo=UTC)
                                except ValueError:
                                    # Try ISO format as fallback
                                    build_data["build_time"] = datetime.fromisoformat(
                                        created_at.replace("Z", "+00:00")
                                    )

                        # Extract build number from version if build field is missing
                        # Version format: "11.0.2.56196" -> build should be "56196"
                        if not build_data.get("build") and build_data.get("version"):
                            version = build_data["version"]
                            if isinstance(version, str) and "." in version:
                                # Extract the last component as the build number
                                build_data["build"] = version.split(".")[-1]
                            else:
                                # Fallback if no dots (shouldn't happen with WoW versions)
                                build_data["build"] = str(version)

                        # Generate an ID if missing (use hash of version+product)
                        if not build_data.get("id"):
                            import hashlib
                            id_str = f"{build_data.get('version', '')}_{product_code}"
                            build_data["id"] = int(hashlib.md5(id_str.encode()).hexdigest()[:8], 16)

                        build = WagoBuild(**build_data)
                        all_builds.append(build)

                    except Exception as e:
                        logger.warning(
                            "build_parse_error",
                            product=product_code,
                            build_version=item.get("version"),
                            error=str(e),
                        )

            logger.info(
                "api_fetch_complete",
                total_builds=len(all_builds),
                products_found=sorted(products_found),
                products_filtered=sorted(set(self.SUPPORTED_PRODUCTS) - products_found),
            )

            # Save to cache
            self._save_cache(all_builds)

            return all_builds

        except httpx.HTTPError as e:
            logger.error("api_fetch_failed", error=str(e))

            # Try to use expired cache as fallback
            if self.cache_file.exists():
                logger.warning("using_expired_cache")
                return self._load_cache()

            raise

    def get_builds_for_product(
        self,
        product: Product | str,
        force_refresh: bool = False
    ) -> list[WagoBuild]:
        """Get builds for a specific product.

        Args:
            product: Product to filter by
            force_refresh: Force API refresh

        Returns:
            Filtered list of builds
        """
        all_builds = self.fetch_builds(force_refresh)

        # Convert Product enum to string value
        if isinstance(product, Product):
            product_str = product.value
        else:
            product_str = str(product)
        filtered = [b for b in all_builds if b.product == product_str]

        logger.info(
            "product_filtered",
            product=product_str,
            build_count=len(filtered),
        )

        return filtered

    def find_build(
        self,
        version: str,
        product: Product | str | None = None,
        force_refresh: bool = False
    ) -> WagoBuild | None:
        """Find a specific build by version.

        Args:
            version: Version string to find
            product: Optional product filter
            force_refresh: Force API refresh

        Returns:
            Build if found, None otherwise
        """
        builds = self.fetch_builds(force_refresh)

        for build in builds:
            if build.version == version:
                if product is None:
                    logger.info("build_found", version=version, product=build.product)
                    return build
                # Convert Product enum to string value
                if isinstance(product, Product):
                    product_str = product.value
                else:
                    product_str = str(product)
                if build.product == product_str:
                    logger.info("build_found", version=version, product=build.product)
                    return build

        logger.warning("build_not_found", version=version, product=product)
        return None

    def get_latest_build(
        self,
        product: Product | str,
        force_refresh: bool = False
    ) -> WagoBuild | None:
        """Get the latest build for a product.

        Args:
            product: Product to get latest for
            force_refresh: Force API refresh

        Returns:
            Latest build if found
        """
        builds = self.get_builds_for_product(product, force_refresh)

        if not builds:
            return None

        # Sort by build_time if available, fallback to ID
        # Filter out builds without build_time first
        builds_with_time = [b for b in builds if b.build_time is not None]
        if builds_with_time:
            latest = max(builds_with_time, key=lambda b: b.build_time if b.build_time is not None else datetime.min.replace(tzinfo=UTC))
        else:
            # Fallback to ID if no builds have timestamps
            latest = max(builds, key=lambda b: b.id)

        logger.info(
            "latest_build",
            product=str(product),
            version=latest.version,
            build_id=latest.id,
        )

        return latest

    def clear_cache(self) -> bool:
        """Clear the local cache.

        Returns:
            True if cache was cleared
        """
        removed = False

        for file in [self.cache_file, self.metadata_file]:
            if file.exists():
                file.unlink()
                removed = True

        if removed:
            logger.info("cache_cleared")

        return removed

    def get_cache_status(self) -> dict[str, Any]:
        """Get cache status information.

        Returns:
            Dictionary with cache status
        """
        if not self._is_cache_valid():
            return {
                "valid": False,
                "exists": self.cache_file.exists(),
            }

        with open(self.metadata_file) as f:
            metadata = WagoCacheMetadata(**json.load(f))

        now = datetime.now(UTC)
        age = now - metadata.fetch_time
        remaining = metadata.expires_at - now

        return {
            "valid": True,
            "fetch_time": metadata.fetch_time.isoformat(),
            "expires_at": metadata.expires_at.isoformat(),
            "age_hours": round(age.total_seconds() / 3600, 1),
            "remaining_hours": round(remaining.total_seconds() / 3600, 1),
            "build_count": metadata.build_count,
            "cache_size_kb": round(self.cache_file.stat().st_size / 1024, 1),
        }

    def update_build_ekeys(
        self,
        build_id: int,
        product: str,
        encoding_ekey: str | None = None,
        root_ekey: str | None = None,
        install_ekey: str | None = None,
        download_ekey: str | None = None
    ) -> bool:
        """Update EKEY fields for a specific build.

        Args:
            build_id: Build ID to update
            product: Product code for the build
            encoding_ekey: Encoding EKEY hash
            root_ekey: Root manifest EKEY hash
            install_ekey: Install manifest EKEY hash
            download_ekey: Download manifest EKEY hash

        Returns:
            True if update was successful, False otherwise
        """
        try:
            # Build update query dynamically based on provided EKEYs
            updates: list[str] = []
            params: list[Any] = []

            if encoding_ekey is not None:
                updates.append("encoding_ekey = ?")
                params.append(encoding_ekey)

            if root_ekey is not None:
                updates.append("root_ekey = ?")
                params.append(root_ekey)

            if install_ekey is not None:
                updates.append("install_ekey = ?")
                params.append(install_ekey)

            if download_ekey is not None:
                updates.append("download_ekey = ?")
                params.append(download_ekey)

            # Only proceed if there are fields to update
            if not updates:
                return True  # Nothing to update

            # Add updated_at timestamp
            updates.append("updated_at = CURRENT_TIMESTAMP")

            # Add WHERE clause parameters
            params.extend([build_id, product])

            # Execute update
            with self.conn:
                cursor = self.conn.execute(
                    f"""
                    UPDATE builds
                    SET {', '.join(updates)}
                    WHERE id = ? AND product = ?
                    """,
                    params
                )

                # Check if any rows were updated
                if cursor.rowcount > 0:
                    logger.info(
                        "build_ekeys_updated",
                        build_id=build_id,
                        product=product,
                        rows_updated=cursor.rowcount
                    )
                    return True
                else:
                    logger.warning(
                        "build_ekeys_update_no_match",
                        build_id=build_id,
                        product=product
                    )
                    return False

        except Exception as e:
            logger.error(
                "build_ekeys_update_failed",
                build_id=build_id,
                product=product,
                error=str(e)
            )
            return False

    def __enter__(self) -> WagoClient:
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()

    def import_builds_to_database(
        self,
        builds: list[WagoBuild] | None = None,
        force_refresh: bool = False
    ) -> dict[str, int]:
        """Import builds into SQLite database.

        Args:
            builds: Builds to import, fetch from API if None
            force_refresh: Force API refresh before import

        Returns:
            Dictionary with import statistics
        """
        if builds is None:
            builds = self.fetch_builds(force_refresh)

        stats: dict[str, int] = {
            "fetched": len(builds),
            "imported": 0,
            "updated": 0,
            "skipped": 0
        }

        products_imported: set[str] = set()

        try:
            with self.conn:
                for build in builds:
                    products_imported.add(build.product)

                    # Check if build already exists
                    existing = self.conn.execute(
                        "SELECT id, updated_at FROM builds WHERE id = ? AND product = ?",
                        (build.id, build.product)
                    ).fetchone()

                    if existing:
                        # Update existing build
                        self.conn.execute("""
                            UPDATE builds SET
                                build = ?, version = ?, build_time = ?,
                                build_config = ?, cdn_config = ?, product_config = ?,
                                encoding_ekey = ?, root_ekey = ?, install_ekey = ?,
                                download_ekey = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE id = ? AND product = ?
                        """, (
                            build.build, build.version, build.build_time,
                            build.build_config, build.cdn_config, build.product_config,
                            build.encoding_ekey, build.root_ekey, build.install_ekey,
                            build.download_ekey, build.id, build.product
                        ))
                        stats["updated"] += 1
                    else:
                        # Insert new build
                        self.conn.execute("""
                            INSERT INTO builds (
                                id, build, version, product, build_time,
                                build_config, cdn_config, product_config,
                                encoding_ekey, root_ekey, install_ekey, download_ekey
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            build.id, build.build, build.version, build.product,
                            build.build_time, build.build_config, build.cdn_config,
                            build.product_config, build.encoding_ekey, build.root_ekey,
                            build.install_ekey, build.download_ekey
                        ))
                        stats["imported"] += 1

                # Log import operation
                self.conn.execute("""
                    INSERT INTO wago_import_log (
                        builds_fetched, builds_imported, builds_updated,
                        products, success
                    ) VALUES (?, ?, ?, ?, 1)
                """, (
                    stats["fetched"], stats["imported"], stats["updated"],
                    json.dumps(sorted(products_imported))
                ))

            logger.info(
                "builds_imported",
                **stats,
                products=sorted(products_imported)
            )

        except Exception as e:
            logger.error("import_failed", error=str(e), **stats)

            # Log failed import
            try:
                with self.conn:
                    self.conn.execute("""
                        INSERT INTO wago_import_log (
                            builds_fetched, builds_imported, builds_updated,
                            products, success, error_message
                        ) VALUES (?, ?, ?, ?, 0, ?)
                    """, (
                        stats["fetched"], stats["imported"], stats["updated"],
                        json.dumps(sorted(products_imported)), str(e)
                    ))
            except Exception:
                pass  # Don't fail on logging errors

            raise

        return stats

    def get_database_builds(
        self,
        product: Product | str | None = None,
        limit: int | None = None
    ) -> list[WagoBuild]:
        """Get builds from database.

        Args:
            product: Product filter
            limit: Maximum number of builds to return

        Returns:
            List of builds from database
        """
        query = "SELECT * FROM builds"
        params: list[Any] = []

        if product:
            query += " WHERE product = ?"
            # Convert Product enum to string value
            if isinstance(product, Product):
                product_str = product.value
            else:
                product_str = str(product)
            params.append(product_str)

        query += " ORDER BY build_time DESC, id DESC"

        if limit:
            query += " LIMIT ?"
            params.append(limit)

        cursor = self.conn.execute(query, params)
        builds: list[WagoBuild] = []

        for row in cursor:
            # Convert row to dict and create WagoBuild
            data = dict(row)
            # Remove database-specific fields
            data.pop("row_id", None)
            data.pop("imported_at", None)
            data.pop("updated_at", None)
            builds.append(WagoBuild(**data))

        return builds

    def get_import_statistics(self) -> dict[str, Any]:
        """Get statistics about imported builds.

        Returns:
            Dictionary with import statistics
        """
        stats: dict[str, Any] = {}

        # Total builds by product
        cursor = self.conn.execute("""
            SELECT product, COUNT(*) as count
            FROM builds
            GROUP BY product
            ORDER BY product
        """)
        stats["builds_by_product"] = {str(row[0]): int(row[1]) for row in cursor.fetchall()}

        # Total builds
        total = sum(stats["builds_by_product"].values())
        stats["total_builds"] = total

        # Latest build per product
        cursor = self.conn.execute("""
            SELECT product, MAX(build_time) as latest_build_time,
                   version, build
            FROM builds
            WHERE build_time IS NOT NULL
            GROUP BY product
            ORDER BY product
        """)
        stats["latest_builds"] = {
            str(row["product"]): {
                "build_time": row["latest_build_time"],
                "version": str(row["version"]),
                "build": str(row["build"])
            }
            for row in cursor
        }

        # Import history
        cursor = self.conn.execute("""
            SELECT COUNT(*) as import_count,
                   MAX(import_time) as last_import,
                   SUM(builds_imported) as total_imported,
                   SUM(builds_updated) as total_updated
            FROM wago_import_log
            WHERE success = 1
        """)
        import_info = cursor.fetchone()
        stats["import_history"] = dict(import_info) if import_info else {}

        # Recent imports
        cursor = self.conn.execute("""
            SELECT import_time, builds_fetched, builds_imported,
                   builds_updated, products
            FROM wago_import_log
            WHERE success = 1
            ORDER BY import_time DESC
            LIMIT 5
        """)
        stats["recent_imports"] = [
            {
                "import_time": row["import_time"],
                "builds_fetched": int(row["builds_fetched"]) if row["builds_fetched"] is not None else 0,
                "builds_imported": int(row["builds_imported"]) if row["builds_imported"] is not None else 0,
                "builds_updated": int(row["builds_updated"]) if row["builds_updated"] is not None else 0,
                "products": json.loads(row["products"]) if row["products"] else []
            }
            for row in cursor
        ]

        return stats

    def find_database_build(
        self,
        version: str,
        product: Product | str | None = None
    ) -> WagoBuild | None:
        """Find a build in the database by version.

        Args:
            version: Version string to find
            product: Optional product filter

        Returns:
            Build if found, None otherwise
        """
        query = "SELECT * FROM builds WHERE version = ?"
        params: list[Any] = [version]

        if product:
            query += " AND product = ?"
            # Convert Product enum to string value
            if isinstance(product, Product):
                product_str = product.value
            else:
                product_str = str(product)
            params.append(product_str)

        query += " LIMIT 1"

        cursor = self.conn.execute(query, params)
        row = cursor.fetchone()

        if row:
            data = dict(row)
            data.pop("row_id", None)
            data.pop("imported_at", None)
            data.pop("updated_at", None)
            return WagoBuild(**data)

        return None

    def list_builds(
        self,
        product: str | None = None,
        version: str | None = None,
        limit: int | None = None
    ) -> list[WagoBuild]:
        """List builds from database with optional filtering.

        Args:
            product: Filter by product (e.g., 'wow', 'wow_classic')
            version: Filter by version (supports SQL wildcards, e.g., '11.0.%')
            limit: Maximum number of results to return

        Returns:
            List of WagoBuild objects matching the criteria
        """
        cursor = self.conn.cursor()

        # Check if table exists
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='builds'
        """)
        count_row = cursor.fetchone()
        if count_row is None or count_row[0] == 0:
            return []  # Table doesn't exist yet

        query = "SELECT * FROM builds WHERE 1=1"
        params: list[Any] = []

        if product:
            query += " AND product = ?"
            params.append(product)

        if version:
            # Support wildcards by replacing * with %
            version_pattern = version.replace('*', '%')
            query += " AND version LIKE ?"
            params.append(version_pattern)

        # Order by ID descending (newest first)
        query += " ORDER BY id DESC"

        if limit:
            query += " LIMIT ?"
            params.append(limit)

        cursor.execute(query, params)

        builds: list[WagoBuild] = []
        for row in cursor.fetchall():
            data = dict(row)
            # Remove database-specific fields
            data.pop("row_id", None)
            data.pop("imported_at", None)
            data.pop("updated_at", None)
            builds.append(WagoBuild(**data))

        return builds

    def search_builds(
        self,
        query: str,
        field: str = "all"
    ) -> list[WagoBuild]:
        """Search for builds matching a query.

        Args:
            query: Search query string
            field: Field to search in ('version', 'build', 'config', 'all')

        Returns:
            List of WagoBuild objects matching the search
        """
        cursor = self.conn.cursor()

        # Check if table exists
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='builds'
        """)
        count_row = cursor.fetchone()
        if count_row is None or count_row[0] == 0:
            return []  # Table doesn't exist yet

        params: list[Any] = []

        if field == "version":
            sql_query = "SELECT * FROM builds WHERE version LIKE ? ORDER BY id DESC"
            params = [f"%{query}%"]
        elif field == "build":
            sql_query = "SELECT * FROM builds WHERE build LIKE ? ORDER BY id DESC"
            params = [f"%{query}%"]
        elif field == "config":
            sql_query = """
                SELECT * FROM builds
                WHERE build_config LIKE ?
                   OR cdn_config LIKE ?
                   OR product_config LIKE ?
                ORDER BY id DESC
            """
            params = [f"%{query}%", f"%{query}%", f"%{query}%"]
        else:  # all
            sql_query = """
                SELECT * FROM builds
                WHERE version LIKE ?
                   OR build LIKE ?
                   OR build_config LIKE ?
                   OR cdn_config LIKE ?
                   OR product_config LIKE ?
                   OR product LIKE ?
                ORDER BY id DESC
            """
            params = [f"%{query}%"] * 6

        cursor.execute(sql_query, params)

        builds: list[WagoBuild] = []
        for row in cursor.fetchall():
            data = dict(row)
            data.pop("row_id", None)
            data.pop("imported_at", None)
            data.pop("updated_at", None)
            builds.append(WagoBuild(**data))

        return builds

    def get_build_stats(self) -> dict[str, Any]:
        """Get statistics about the build database.

        Returns:
            Dictionary with statistics including total builds, products,
            versions, date range, and breakdowns by product/version
        """
        cursor = self.conn.cursor()

        # Check if table exists and has data
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='builds'
        """)
        count_row = cursor.fetchone()
        if count_row is None or count_row[0] == 0:
            # Table doesn't exist yet - return empty stats
            return {
                "total_builds": 0,
                "product_count": 0,
                "version_count": 0,
                "date_range": "N/A",
                "by_product": {},
                "by_major_version": {},
            }

        # Total builds
        cursor.execute("SELECT COUNT(*) FROM builds")
        total_row = cursor.fetchone()
        total_builds = int(total_row[0]) if total_row else 0

        if total_builds == 0:
            # Table exists but is empty
            return {
                "total_builds": 0,
                "product_count": 0,
                "version_count": 0,
                "date_range": "N/A",
                "by_product": {},
                "by_major_version": {},
            }

        # Product count
        cursor.execute("SELECT COUNT(DISTINCT product) FROM builds")
        product_row = cursor.fetchone()
        product_count = int(product_row[0]) if product_row else 0

        # Version count
        cursor.execute("SELECT COUNT(DISTINCT version) FROM builds WHERE version IS NOT NULL")
        version_row = cursor.fetchone()
        version_count = int(version_row[0]) if version_row else 0

        # Date range
        cursor.execute("""
            SELECT
                MIN(build_time) as earliest,
                MAX(build_time) as latest
            FROM builds
            WHERE build_time IS NOT NULL
        """)
        row = cursor.fetchone()
        if row and row[0] and row[1]:
            earliest = str(row[0])
            latest = str(row[1])
            date_range = f"{earliest[:10]} to {latest[:10]}"
        else:
            date_range = "N/A"

        # Builds by product
        cursor.execute("""
            SELECT product, COUNT(*) as count
            FROM builds
            GROUP BY product
            ORDER BY count DESC
        """)
        by_product: dict[str, int] = {str(row[0]): int(row[1]) for row in cursor.fetchall()}

        # Builds by major version
        cursor.execute("""
            SELECT
                SUBSTR(version, 1, INSTR(version || '.', '.') - 1) as major_version,
                COUNT(*) as count
            FROM builds
            WHERE version IS NOT NULL
            GROUP BY major_version
            ORDER BY CAST(major_version AS INTEGER) DESC
        """)
        by_major_version: dict[str, int] = {str(row[0]): int(row[1]) for row in cursor.fetchall()}

        return {
            "total_builds": total_builds,
            "product_count": product_count,
            "version_count": version_count,
            "date_range": date_range,
            "by_product": by_product,
            "by_major_version": by_major_version,
        }

    def close(self) -> None:
        """Close HTTP client and database connection."""
        if self._client:
            self._client.close()
        if self._conn:
            self._conn.close()
