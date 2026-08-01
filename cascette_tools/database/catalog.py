"""Product catalog client: Ribbit/CDN sync, SQLite import, and 24h local cache.

The ``catalogs`` Ribbit product serves the TPR product catalog: a root JSON
fragment referencing per-product sub-fragments by hash. This client:

1. Fetches the latest catalog build from Ribbit (``tpr/catalogs``).
2. Resolves the root fragment via the build config's ``root`` key.
3. Follows sub-fragment hashes on the CDN.
4. Imports everything into ``catalog.db`` (fragments, products, programs,
   entitlement rules, licenses, install configs).
5. Caches the raw fragments locally for 24 hours (same pattern as
   :class:`cascette_tools.database.wago.WagoClient`).

Entitlement rules are stored per program; license IDs referenced by rules
are extracted into a dedicated table so consumers can answer "which
license gates which product" without re-walking rule JSON.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import Product
from cascette_tools.formats.catalog import (
    CatalogFragment,
    CatalogParser,
    EntitlementRule,
    rule_license_ids,
)

logger = structlog.get_logger()

CACHE_LIFETIME = timedelta(hours=24)
CACHE_SCHEMA_VERSION = 2


class CatalogCacheMetadata(BaseModel):
    """Metadata for the local catalog fragment cache."""

    fetch_time: datetime = Field(description="When data was fetched")
    expires_at: datetime = Field(description="When cache expires")
    build_version: int | None = Field(default=None, description="Catalog build version")
    build_config: str | None = Field(default=None, description="Build config hash")
    fragment_count: int = Field(default=0, description="Number of cached fragments")
    schema_version: int = Field(
        default=2, description="Cache format version (bumped on format changes)"
    )
    encrypted_fragments: list[dict[str, str]] = Field(
        default_factory=list,
        description="Metadata for fragments served encrypted on the CDN",
    )


def adapt_datetime_iso(val: datetime) -> str:
    """Adapt datetime to ISO format string for SQLite storage (UTC)."""
    if val.tzinfo is None:
        val = val.replace(tzinfo=UTC)
    elif val.tzinfo != UTC:
        val = val.astimezone(UTC)
    return val.isoformat()


def convert_datetime_iso(val: bytes) -> datetime:
    """Convert ISO format string from SQLite to UTC datetime."""
    dt = datetime.fromisoformat(val.decode("utf-8"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    elif dt.tzinfo != UTC:
        dt = dt.astimezone(UTC)
    return dt


def parse_build_config_root(raw: bytes) -> str | None:
    """Extract the ``root = <hash>`` line from a build config text file.

    Args:
        raw: Build config bytes.

    Returns:
        Root hash, or None if the line is missing.
    """
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("root"):
            _, sep, value = stripped.partition("=")
            if sep:
                return value.strip()
    return None


class CatalogClient:
    """SQLite storage and sync for the TPR product catalog."""

    def __init__(self, config: AppConfig | None = None) -> None:
        """Initialize the catalog client.

        Args:
            config: Application configuration.
        """
        self.config = config or AppConfig()
        self.cache_dir = self.config.data_dir / "catalog_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "catalog.json"
        self.metadata_file = self.cache_dir / "metadata.json"
        self.db_path = self.config.data_dir / "catalog.db"
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        """Get or create the database connection with datetime handling."""
        if self._conn is None:
            sqlite3.register_adapter(datetime, adapt_datetime_iso)
            sqlite3.register_converter("TIMESTAMP", convert_datetime_iso)
            self._conn = sqlite3.connect(
                str(self.db_path), detect_types=sqlite3.PARSE_DECLTYPES
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        """Create the catalog schema if it does not exist."""
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS catalog_builds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    build_version INTEGER,
                    build_num TEXT,
                    build_config TEXT,
                    cdn_config TEXT,
                    build_branch TEXT,
                    root_hash TEXT,
                    region TEXT,
                    seqn INTEGER,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(build_config, region)
                );

                CREATE TABLE IF NOT EXISTS catalog_fragments (
                    hash TEXT PRIMARY KEY,
                    name TEXT,
                    platform TEXT,
                    requires_json TEXT,
                    encrypted_hash TEXT,
                    decryption_key_id TEXT,
                    fragment_id TEXT,
                    version INTEGER,
                    is_root INTEGER DEFAULT 0,
                    raw_json TEXT NOT NULL,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS catalog_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    program_id TEXT,
                    product_id TEXT,
                    name TEXT,
                    base_json TEXT,
                    UNIQUE(fragment_hash, product_id)
                );

                CREATE TABLE IF NOT EXISTS catalog_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    category_id TEXT NOT NULL,
                    name TEXT,
                    rank INTEGER,
                    UNIQUE(fragment_hash, category_id)
                );

                CREATE TABLE IF NOT EXISTS catalog_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    type_id TEXT NOT NULL,
                    category TEXT,
                    product_defaults_json TEXT,
                    UNIQUE(fragment_hash, type_id)
                );

                CREATE TABLE IF NOT EXISTS catalog_programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    program_id TEXT NOT NULL,
                    is_game_account_level INTEGER,
                    config_json TEXT NOT NULL,
                    UNIQUE(fragment_hash, program_id)
                );

                CREATE TABLE IF NOT EXISTS catalog_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    program_id TEXT NOT NULL,
                    rule_seq INTEGER NOT NULL,
                    level TEXT,
                    match_json TEXT,
                    actions_json TEXT,
                    UNIQUE(fragment_hash, program_id, rule_seq)
                );

                CREATE TABLE IF NOT EXISTS catalog_licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_id INTEGER NOT NULL,
                    fragment_hash TEXT NOT NULL,
                    program_id TEXT NOT NULL,
                    rule_seq INTEGER NOT NULL,
                    UNIQUE(license_id, fragment_hash, program_id, rule_seq)
                );

                CREATE TABLE IF NOT EXISTS catalog_installs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash TEXT NOT NULL,
                    install_type TEXT NOT NULL,
                    tact_product TEXT,
                    config_json TEXT,
                    UNIQUE(fragment_hash, install_type)
                );

                CREATE TABLE IF NOT EXISTS catalog_import_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    import_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT DEFAULT 'ribbit',
                    build_version INTEGER,
                    fragments_fetched INTEGER DEFAULT 0,
                    fragments_imported INTEGER DEFAULT 0,
                    success INTEGER DEFAULT 1,
                    error_message TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rules_program ON catalog_rules(program_id);
                CREATE INDEX IF NOT EXISTS idx_licenses_id ON catalog_licenses(license_id);
                CREATE INDEX IF NOT EXISTS idx_installs_tact ON catalog_installs(tact_product);
                """
            )
        self._migrate_db()

    def _migrate_db(self) -> None:
        """Add columns introduced after the initial schema (idempotent)."""
        columns = {
            row[1]
            for row in self.conn.execute(
                "PRAGMA table_info(catalog_fragments)"
            ).fetchall()
        }
        for column, ddl in (
            (
                "encrypted_hash",
                "ALTER TABLE catalog_fragments ADD COLUMN encrypted_hash TEXT",
            ),
            (
                "decryption_key_id",
                "ALTER TABLE catalog_fragments ADD COLUMN decryption_key_id TEXT",
            ),
        ):
            if column not in columns:
                with self.conn:
                    self.conn.execute(ddl)

    # ------------------------------------------------------------------ cache

    def _cache_valid(self) -> bool:
        """Check whether the local fragment cache is fresh and compatible."""
        if not self.cache_file.exists() or not self.metadata_file.exists():
            return False
        try:
            with open(self.metadata_file) as f:
                metadata = CatalogCacheMetadata.model_validate(json.load(f))
            if metadata.schema_version != CACHE_SCHEMA_VERSION:
                logger.warning(
                    "catalog_cache_schema_mismatch",
                    expected=CACHE_SCHEMA_VERSION,
                    found=metadata.schema_version,
                )
                return False
            return datetime.now(UTC) < metadata.expires_at
        except Exception as e:
            logger.warning("catalog_cache_invalid", error=str(e))
            return False

    def _load_cache(self) -> tuple[CatalogCacheMetadata, dict[str, bytes]]:
        """Load cached fragments keyed by hash."""
        try:
            with open(self.metadata_file) as f:
                metadata = CatalogCacheMetadata.model_validate(json.load(f))
            with open(self.cache_file) as f:
                raw: dict[str, str] = json.load(f)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            logger.warning("catalog_cache_load_failed", error=str(e))
            return CatalogCacheMetadata(
                fetch_time=datetime.min.replace(tzinfo=UTC),
                expires_at=datetime.min.replace(tzinfo=UTC),
            ), {}
        fragments = {h: v.encode("utf-8") for h, v in raw.items()}
        return metadata, fragments

    def _save_cache(
        self,
        fragments: dict[str, bytes],
        build_version: int | None,
        build_config: str | None,
        encrypted_fragments: list[dict[str, str]] | None = None,
    ) -> None:
        """Persist fragments and metadata with a 24-hour expiry."""
        now = datetime.now(UTC)
        metadata = CatalogCacheMetadata(
            fetch_time=now,
            expires_at=now + CACHE_LIFETIME,
            build_version=build_version,
            build_config=build_config,
            fragment_count=len(fragments),
            encrypted_fragments=encrypted_fragments or [],
        )
        raw = {h: v.decode("utf-8") for h, v in fragments.items()}
        try:
            with open(self.cache_file, "w") as f:
                json.dump(raw, f, indent=2)
            with open(self.metadata_file, "w") as f:
                json.dump(metadata.model_dump(mode="json"), f, indent=2, default=str)
        except OSError as e:
            logger.warning("catalog_cache_save_failed", error=str(e))
            return
        logger.info(
            "catalog_cache_saved",
            fragment_count=len(fragments),
            expires_at=metadata.expires_at.isoformat(),
        )

    # ------------------------------------------------------------------ sync

    def sync(
        self,
        region: str = "us",
        build_version: int | None = None,
        force: bool = False,
        tact_client: Any | None = None,
        cdn_client: Any | None = None,
    ) -> dict[str, Any]:
        """Fetch the catalog from Ribbit/CDN and import it into the database.

        Uses the 24-hour local cache unless ``force`` is set or no valid
        cache exists.

        Args:
            region: Ribbit region (defaults to ``us``).
            build_version: Optional catalog build version (e.g. ``30``);
                defaults to the newest build.
            force: Bypass the local cache.
            tact_client: Optional TACT client (for tests).
            cdn_client: Optional CDN client (for tests).

        Returns:
            Import statistics.
        """
        if not force and self._cache_valid():
            metadata, cached = self._load_cache()
            imported = self._import_cached_fragments(
                cached, encrypted_fragments=metadata.encrypted_fragments
            )
            logger.info(
                "catalog_cache_hit",
                build_version=metadata.build_version,
                fragment_count=metadata.fragment_count,
            )
            return {
                "cache": True,
                "build_version": metadata.build_version,
                "fragments": len(cached),
                "imported": imported,
            }
        from cascette_tools.core.cdn import CDNClient
        from cascette_tools.core.tact import TACTClient

        tact = tact_client or TACTClient(region=region)
        cdn = cdn_client or CDNClient(
            Product.CATALOGS,
            region,
            config=self.config.create_cdn_config(Product.CATALOGS),
        )

        try:
            entry = self._select_build(tact, build_version)
            build_config = str(entry.get("BuildConfig") or "")
            if not build_config:
                raise ValueError("Catalog build entry missing BuildConfig")
            build_config_bytes = cdn.fetch_config(build_config)
            root_hash = parse_build_config_root(build_config_bytes)
            if not root_hash:
                raise ValueError(f"Build config {build_config} missing root key")

            root_bytes = cdn.fetch_data(root_hash)
            parser = CatalogParser()
            root = parser.parse(root_bytes)

            fragments: dict[str, bytes] = {root_hash: root_bytes}
            encrypted: list[dict[str, str]] = []
            for ref in root.fragments:
                if ref.is_encrypted:
                    # The CDN only serves the encrypted form under
                    # encrypted_hash; the plain hash 404s. Record the
                    # metadata and skip the download.
                    encrypted.append(
                        {
                            "hash": ref.hash,
                            "name": ref.name,
                            "encrypted_hash": ref.encrypted_hash or "",
                            "decryption_key_id": ref.decryption_key_id or "",
                        }
                    )
                    continue
                try:
                    fragments[ref.hash] = cdn.fetch_data(ref.hash, quiet=True)
                except Exception as e:
                    logger.warning(
                        "catalog_fragment_fetch_failed",
                        fragment=ref.name,
                        hash=ref.hash,
                        error=str(e),
                    )

            build_version_num = root.version
            self._save_cache(
                fragments,
                build_version_num,
                build_config,
                encrypted_fragments=encrypted,
            )
            self._record_build(
                build_version_num,
                entry,
                root_hash=root_hash,
                region=region,
            )
            imported = self._import_cached_fragments(
                fragments, encrypted_fragments=encrypted
            )
            return {
                "cache": False,
                "build_version": build_version_num,
                "build_config": build_config,
                "fragments": len(fragments),
                "encrypted": len(encrypted),
                "imported": imported,
            }
        except Exception as e:
            logger.error("catalog_sync_failed", error=str(e))
            self._log_import(success=False, error_message=str(e))
            raise

    def _select_build(self, tact: Any, build_version: int | None) -> dict[str, str]:
        """Pick a catalog build entry from the Ribbit versions manifest.

        Prefers a region named ``PUB-<build_version>`` when a version is
        requested; otherwise the entry with the highest build number
        (VersionsName). BuildId is not monotonic across catalog versions,
        so it cannot be used for ordering.
        """
        manifest = tact.fetch_versions(Product.CATALOGS)
        entries = tact.parse_versions(manifest)
        if not entries:
            raise ValueError("No catalog build entries from Ribbit")

        if build_version is not None:
            wanted = f"pub-{build_version}"
            for entry in entries:
                if str(entry.get("Region", "")).lower() == wanted:
                    return entry

        def _build_num(entry: dict[str, str]) -> int:
            value = str(entry.get("VersionsName") or "0")
            try:
                return int(value)
            except ValueError:
                return 0

        return max(entries, key=_build_num)

    def _record_build(
        self,
        build_version: int | None,
        entry: dict[str, str],
        root_hash: str,
        region: str,
    ) -> None:
        """Insert or update the catalog_builds row."""
        seqn = None
        try:
            seqn = int(str(entry.get("seqn") or "")) or None
        except ValueError:
            seqn = None
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO catalog_builds (
                    build_version, build_num, build_config, cdn_config,
                    root_hash, region, seqn
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(build_config, region) DO UPDATE SET
                    build_version = excluded.build_version,
                    build_num = excluded.build_num,
                    cdn_config = excluded.cdn_config,
                    root_hash = excluded.root_hash,
                    seqn = excluded.seqn,
                    fetched_at = CURRENT_TIMESTAMP
                """,
                (
                    build_version,
                    entry.get("VersionsName"),
                    entry.get("BuildConfig"),
                    entry.get("CDNConfig"),
                    root_hash,
                    region,
                    seqn,
                ),
            )

    # ------------------------------------------------------------------ import

    def _import_cached_fragments(
        self,
        fragments: dict[str, bytes],
        encrypted_fragments: list[dict[str, str]] | None = None,
    ) -> int:
        """Import every cached fragment into the database.

        Args:
            fragments: Fragment hash to raw JSON bytes.
            encrypted_fragments: Metadata for fragments served encrypted
                on the CDN (recorded without content).

        Returns:
            Number of fragments imported.
        """
        parser = CatalogParser()
        imported = 0
        # Derive fragment names from the root fragment's reference list.
        names: dict[str, str] = {}
        for _fragment_hash, raw in fragments.items():
            try:
                fragment = parser.parse(raw)
            except ValueError:
                continue
            if fragment.is_root:
                names = {ref.hash: ref.name for ref in fragment.fragments}
        for fragment_hash, raw in fragments.items():
            try:
                fragment = parser.parse(raw)
            except ValueError:
                continue
            self.import_fragment(
                fragment,
                fragment_hash,
                raw,
                is_root=fragment.is_root,
                name=names.get(fragment_hash),
            )
            imported += 1
        for meta in encrypted_fragments or []:
            meta = dict(meta)
            if "name" not in meta:
                resolved = names.get(meta.get("hash", ""))
                if resolved is not None:
                    meta["name"] = resolved
            self._record_encrypted_fragment(meta)
        self._log_import(success=True, fragments_imported=imported)
        logger.info(
            "catalog_import_complete",
            fragments=imported,
            encrypted=len(encrypted_fragments or []),
        )
        return imported

    def _record_encrypted_fragment(self, meta: dict[str, str]) -> None:
        """Record an encrypted fragment's metadata without its content."""
        placeholder = json.dumps(
            {
                "encrypted": True,
                "encrypted_hash": meta.get("encrypted_hash", ""),
                "decryption_key_id": meta.get("decryption_key_id", ""),
            }
        )
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO catalog_fragments (
                    hash, name, encrypted_hash, decryption_key_id,
                    is_root, raw_json
                ) VALUES (?, ?, ?, ?, 0, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    name = excluded.name,
                    encrypted_hash = excluded.encrypted_hash,
                    decryption_key_id = excluded.decryption_key_id,
                    is_root = 0,
                    raw_json = excluded.raw_json,
                    fetched_at = CURRENT_TIMESTAMP
                """,
                (
                    meta.get("hash", ""),
                    meta.get("name"),
                    meta.get("encrypted_hash"),
                    meta.get("decryption_key_id"),
                    placeholder,
                ),
            )

    def import_fragment(
        self,
        fragment: CatalogFragment,
        fragment_hash: str,
        raw: bytes | None = None,
        is_root: bool = False,
        name: str | None = None,
    ) -> None:
        """Import a single parsed fragment (insert/update semantics).

        Args:
            fragment: Parsed catalog fragment.
            fragment_hash: CDN hash of the fragment.
            raw: Raw fragment bytes (stored verbatim).
            is_root: Whether this is the root fragment.
            name: Fragment name from the root's reference list.
        """
        raw_json = raw.decode("utf-8") if raw is not None else json.dumps(fragment.data)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO catalog_fragments (
                    hash, name, platform, requires_json, fragment_id,
                    version, is_root, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    name = excluded.name,
                    platform = excluded.platform,
                    requires_json = excluded.requires_json,
                    fragment_id = excluded.fragment_id,
                    version = excluded.version,
                    is_root = excluded.is_root,
                    raw_json = excluded.raw_json,
                    fetched_at = CURRENT_TIMESTAMP
                """,
                (
                    fragment_hash,
                    name,
                    None,
                    None,
                    fragment.fragment_id,
                    fragment.version,
                    1 if is_root else 0,
                    raw_json,
                ),
            )

            for category in fragment.categories:
                self.conn.execute(
                    """
                    INSERT INTO catalog_categories (
                        fragment_hash, category_id, name, rank
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(fragment_hash, category_id) DO UPDATE SET
                        name = excluded.name, rank = excluded.rank
                    """,
                    (fragment_hash, category.id, category.name, category.rank),
                )

            for type_def in fragment.types:
                category = type_def.category or type_def.category_id
                self.conn.execute(
                    """
                    INSERT INTO catalog_types (
                        fragment_hash, type_id, category, product_defaults_json
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(fragment_hash, type_id) DO UPDATE SET
                        category = excluded.category,
                        product_defaults_json = excluded.product_defaults_json
                    """,
                    (
                        fragment_hash,
                        type_def.id,
                        category,
                        json.dumps(type_def.product_defaults or {}),
                    ),
                )

            for product in fragment.products:
                base = product.base
                program_id = base.program_id if base else None
                product_id = product.id or (base.real_product_id if base else None)
                if not product_id:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO catalog_products (
                        fragment_hash, program_id, product_id, name, base_json
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(fragment_hash, product_id) DO UPDATE SET
                        program_id = excluded.program_id,
                        name = excluded.name,
                        base_json = excluded.base_json
                    """,
                    (
                        fragment_hash,
                        program_id,
                        product_id,
                        base.name if base else None,
                        json.dumps(base.model_dump(mode="json", exclude_none=True))
                        if base
                        else None,
                    ),
                )

            for program_id, program_config in fragment.program_configuration.items():
                self.conn.execute(
                    """
                    INSERT INTO catalog_programs (
                        fragment_hash, program_id, is_game_account_level, config_json
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(fragment_hash, program_id) DO UPDATE SET
                        is_game_account_level = excluded.is_game_account_level,
                        config_json = excluded.config_json
                    """,
                    (
                        fragment_hash,
                        program_id,
                        1 if program_config.is_game_account_level else 0,
                        json.dumps(
                            program_config.model_dump(mode="json", exclude_none=True)
                        ),
                    ),
                )

                rules = (
                    program_config.run_each_rule or program_config.run_first_rule or []
                )
                for rule_seq, rule in enumerate(rules):
                    self._import_rule(fragment_hash, program_id, rule_seq, rule)

            for install_type, install in fragment.installs.items():
                self.conn.execute(
                    """
                    INSERT INTO catalog_installs (
                        fragment_hash, install_type, tact_product, config_json
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(fragment_hash, install_type) DO UPDATE SET
                        tact_product = excluded.tact_product,
                        config_json = excluded.config_json
                    """,
                    (
                        fragment_hash,
                        install_type,
                        install.tact_product,
                        json.dumps(install.model_dump(mode="json", exclude_none=True)),
                    ),
                )

    def _import_rule(
        self,
        fragment_hash: str,
        program_id: str,
        rule_seq: int,
        rule: EntitlementRule,
    ) -> None:
        """Import one top-level rule and its referenced license IDs."""
        match_json = (
            json.dumps(
                rule.match.model_dump(mode="json", exclude_none=True, by_alias=True)
            )
            if rule.match is not None
            else None
        )
        actions_json = (
            json.dumps(
                [
                    a.model_dump(mode="json", exclude_none=True)
                    for a in rule.actions or []
                ]
            )
            if rule.actions
            else None
        )
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO catalog_rules (
                    fragment_hash, program_id, rule_seq, level, match_json, actions_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(fragment_hash, program_id, rule_seq) DO UPDATE SET
                    level = excluded.level,
                    match_json = excluded.match_json,
                    actions_json = excluded.actions_json
                """,
                (
                    fragment_hash,
                    program_id,
                    rule_seq,
                    rule.level,
                    match_json,
                    actions_json,
                ),
            )
            for license_id in rule_license_ids(rule):
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO catalog_licenses (
                        license_id, fragment_hash, program_id, rule_seq
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (license_id, fragment_hash, program_id, rule_seq),
                )

    def _log_import(
        self,
        success: bool,
        fragments_imported: int = 0,
        error_message: str | None = None,
    ) -> None:
        """Append a row to the import log."""
        try:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO catalog_import_log (
                        fragments_imported, success, error_message
                    ) VALUES (?, ?, ?)
                    """,
                    (fragments_imported, 1 if success else 0, error_message),
                )
        except Exception:
            pass  # Never fail on logging errors

    # ------------------------------------------------------------------ queries

    def list_fragments(self, product: str | None = None) -> list[sqlite3.Row]:
        """List imported fragments, optionally filtered by product name."""
        if product:
            return self.conn.execute(
                """
                SELECT * FROM catalog_fragments
                WHERE name = ? OR fragment_id = ?
                ORDER BY is_root DESC, name
                """,
                (product, product),
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM catalog_fragments ORDER BY is_root DESC, name"
        ).fetchall()

    def list_products(self, program: str | None = None) -> list[sqlite3.Row]:
        """List products, optionally filtered by program id."""
        if program:
            return self.conn.execute(
                "SELECT * FROM catalog_products WHERE program_id = ? ORDER BY product_id",
                (program,),
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM catalog_products ORDER BY program_id, product_id"
        ).fetchall()

    def get_program(self, program_id: str) -> sqlite3.Row | None:
        """Get the most recent program configuration row."""
        return self.conn.execute(
            """
            SELECT * FROM catalog_programs
            WHERE program_id = ?
            ORDER BY id DESC LIMIT 1
            """,
            (program_id,),
        ).fetchone()

    def list_programs(self) -> list[sqlite3.Row]:
        """List distinct programs (most recent fragment per program)."""
        return self.conn.execute(
            """
            SELECT fragment_hash, program_id, is_game_account_level, config_json
            FROM catalog_programs
            WHERE id IN (
                SELECT MAX(id) FROM catalog_programs GROUP BY program_id
            )
            ORDER BY program_id
            """
        ).fetchall()

    def list_rules(self, program_id: str) -> list[sqlite3.Row]:
        """List rules for a program (most recent fragment first)."""
        return self.conn.execute(
            """
            SELECT r.* FROM catalog_rules r
            JOIN catalog_programs p
              ON p.program_id = r.program_id AND p.fragment_hash = r.fragment_hash
            WHERE r.program_id = ?
            ORDER BY p.id DESC, r.rule_seq
            """,
            (program_id,),
        ).fetchall()

    def list_licenses(self, license_id: int | None = None) -> list[sqlite3.Row]:
        """List license-to-program mappings, optionally filtered by id."""
        if license_id is not None:
            return self.conn.execute(
                """
                SELECT l.license_id, l.program_id, l.rule_seq, l.fragment_hash
                FROM catalog_licenses l
                WHERE l.license_id = ?
                ORDER BY l.program_id
                """,
                (license_id,),
            ).fetchall()
        return self.conn.execute(
            """
            SELECT license_id, COUNT(DISTINCT program_id) AS programs
            FROM catalog_licenses
            GROUP BY license_id
            ORDER BY license_id
            """
        ).fetchall()

    def list_installs(self, tact_product: str | None = None) -> list[sqlite3.Row]:
        """List install configurations, optionally filtered by tact_product."""
        if tact_product:
            return self.conn.execute(
                """
                SELECT * FROM catalog_installs
                WHERE tact_product = ?
                ORDER BY install_type
                """,
                (tact_product,),
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM catalog_installs ORDER BY tact_product, install_type"
        ).fetchall()

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics about the imported catalog."""
        stats: dict[str, Any] = {}
        for table, column in (
            ("catalog_fragments", "fragments"),
            ("catalog_products", "products"),
            ("catalog_programs", "programs"),
            ("catalog_rules", "rules"),
            ("catalog_licenses", "licenses"),
            ("catalog_installs", "installs"),
        ):
            stats[column] = self.conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        latest = self.conn.execute(
            "SELECT * FROM catalog_builds ORDER BY id DESC LIMIT 1"
        ).fetchone()
        stats["latest_build"] = dict(latest) if latest else None
        return stats

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> CatalogClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
