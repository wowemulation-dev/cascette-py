"""FileDataID (FDID) management with wowdev/wow-listfile integration."""

from __future__ import annotations

import csv
import gzip
import io
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.config import AppConfig

_base_logger = structlog.get_logger()

class SafeLogger:
    """Logger wrapper that gracefully handles configuration issues."""

    def __init__(self, base_logger):
        self._logger = base_logger

    def _safe_log(self, method_name, msg, **kwargs):
        try:
            getattr(self._logger, method_name)(msg, **kwargs)
        except Exception:
            # Silently ignore logging errors during testing
            pass

    def info(self, msg, **kwargs):
        self._safe_log('info', msg, **kwargs)

    def debug(self, msg, **kwargs):
        self._safe_log('debug', msg, **kwargs)

    def warning(self, msg, **kwargs):
        self._safe_log('warning', msg, **kwargs)

    def error(self, msg, **kwargs):
        self._safe_log('error', msg, **kwargs)

logger = SafeLogger(_base_logger)


class FileDataEntry(BaseModel):
    """File entry from listfile."""

    fdid: int = Field(description="FileDataID")
    path: str = Field(description="File path")
    verified: bool = Field(default=False, description="Verification status")
    lookup_hash: int | None = Field(default=None, description="Jenkins96 lookup hash")
    added_date: datetime | None = Field(default=None, description="When entry was added")
    product: str | None = Field(default=None, description="Product this file belongs to")


class ListfileCacheMetadata(BaseModel):
    """Metadata for cached listfile data."""

    fetch_time: datetime = Field(description="When the listfile was fetched")
    entry_count: int = Field(description="Number of entries in the listfile")
    file_size: int = Field(description="Size of the cached file in bytes")
    source: str = Field(description="Source of the listfile data")
    cache_version: str = Field(default="1.0", description="Cache format version")


class ListfileManager:
    """Manages FileDataID to path mappings from wowdev/wow-listfile."""

    GITHUB_RAW_URL = "https://github.com/wowdev/wow-listfile/raw/master"
    CACHE_LIFETIME = timedelta(hours=24)  # Same as other caches

    def __init__(self, config: AppConfig | None = None) -> None:
        """Initialize listfile manager.

        Args:
            config: Application configuration
        """
        self.config = config or AppConfig()
        self.db_path = self.config.data_dir / "listfile.db"
        self.cache_dir = self.config.data_dir / "listfile_cache"
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
            # Enable optimizations for bulk inserts
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=60.0,  # Longer timeout for large files
                follow_redirects=True,
                headers={"User-Agent": "cascette-tools/0.1.0"}
            )
        return self._client

    def _init_db(self) -> None:
        """Initialize database schema for listfile."""
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS file_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fdid INTEGER NOT NULL UNIQUE,
                    path TEXT NOT NULL,
                    path_lower TEXT NOT NULL,  -- For case-insensitive search
                    verified INTEGER DEFAULT 0,
                    lookup_hash INTEGER,
                    added_date TIMESTAMP,
                    product TEXT,  -- Deprecated, use product_family
                    product_family TEXT DEFAULT 'wow',  -- Product family this entry belongs to
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_fdid ON file_entries(fdid);
                CREATE INDEX IF NOT EXISTS idx_path_lower ON file_entries(path_lower);
                CREATE INDEX IF NOT EXISTS idx_lookup_hash ON file_entries(lookup_hash);
                CREATE INDEX IF NOT EXISTS idx_product_family ON file_entries(product_family);
                CREATE INDEX IF NOT EXISTS idx_product ON file_entries(product);

                CREATE TABLE IF NOT EXISTS listfile_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,  -- 'wowdev', 'community', 'extracted'
                    fetch_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    entry_count INTEGER,
                    file_size INTEGER,
                    metadata TEXT  -- JSON with additional info
                );

                CREATE TABLE IF NOT EXISTS listfile_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fdid INTEGER NOT NULL,
                    old_path TEXT,
                    new_path TEXT,
                    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    FOREIGN KEY (fdid) REFERENCES file_entries(fdid)
                );

                -- Full-text search for file paths
                CREATE VIRTUAL TABLE IF NOT EXISTS file_search
                USING fts5(fdid UNINDEXED, path, content=file_entries);

                -- Trigger to keep FTS index updated
                CREATE TRIGGER IF NOT EXISTS file_entries_ai AFTER INSERT ON file_entries
                BEGIN
                    INSERT INTO file_search(fdid, path) VALUES (new.fdid, new.path);
                END;

                CREATE TRIGGER IF NOT EXISTS file_entries_ad AFTER DELETE ON file_entries
                BEGIN
                    DELETE FROM file_search WHERE fdid = old.fdid;
                END;

                CREATE TRIGGER IF NOT EXISTS file_entries_au AFTER UPDATE ON file_entries
                BEGIN
                    UPDATE file_search SET path = new.path WHERE fdid = new.fdid;
                END;
            """)

        logger.info("listfile_db_initialized", db_path=str(self.db_path))

    def fetch_listfile(self, force_refresh: bool = False) -> list[FileDataEntry]:
        """Fetch listfile from wowdev/wow-listfile repository.

        Args:
            force_refresh: Force fetch even if cache is valid

        Returns:
            List of file entries

        Raises:
            httpx.HTTPError: On fetch errors
        """
        cache_file = self.cache_dir / "listfile.csv.gz"
        metadata_file = self.cache_dir / "listfile_metadata.json"

        # Check cache validity
        if not force_refresh and cache_file.exists() and metadata_file.exists():
            with open(metadata_file) as f:
                metadata_dict = json.load(f)

            try:
                metadata = ListfileCacheMetadata.model_validate(metadata_dict)
                if datetime.now(UTC) - metadata.fetch_time < self.CACHE_LIFETIME:
                    logger.info("using_cached_listfile")
                    return self._load_cached_listfile(cache_file)
            except Exception as e:
                logger.warning("invalid_listfile_metadata", error=str(e))

        logger.info("fetching_listfile_from_github")

        try:
            # Fetch CSV listfile (it's typically provided as CSV)
            response = self.client.get(f"{self.GITHUB_RAW_URL}/community-listfile.csv")
            response.raise_for_status()

            entries = self._parse_csv_listfile(response.text)

            logger.info("fetched_listfile", count=len(entries))

            # Cache the listfile (compressed)
            with gzip.open(cache_file, "wt", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["fdid", "path"])
                for entry in entries:
                    writer.writerow([entry.fdid, entry.path])

            metadata = ListfileCacheMetadata(
                fetch_time=datetime.now(UTC),
                entry_count=len(entries),
                file_size=cache_file.stat().st_size,
                source="wowdev/wow-listfile"
            )
            with open(metadata_file, "w") as f:
                json.dump(metadata.model_dump(mode='json'), f, indent=2, default=str)

            return entries

        except httpx.HTTPError as e:
            logger.error("failed_to_fetch_listfile", error=str(e))

            # Try to use cached data as fallback
            if cache_file.exists():
                logger.warning("using_expired_listfile_cache")
                return self._load_cached_listfile(cache_file)

            raise

    def _load_cached_listfile(self, cache_file: Path) -> list[FileDataEntry]:
        """Load listfile from cache.

        Args:
            cache_file: Path to cached file

        Returns:
            List of file entries
        """
        entries = []

        with gzip.open(cache_file, "rt", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = FileDataEntry(
                        fdid=int(row["fdid"]),
                        path=row["path"],
                        verified=True  # Community listfile entries are verified
                    )
                    entries.append(entry)
                except (ValueError, KeyError) as e:
                    logger.debug("skip_invalid_entry", row=row, error=str(e))

        logger.info("loaded_cached_listfile", count=len(entries))
        return entries

    def _parse_csv_listfile(self, csv_text: str) -> list[FileDataEntry]:
        """Parse CSV format listfile.

        Args:
            csv_text: CSV text from GitHub

        Returns:
            List of parsed file entries
        """
        entries = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            try:
                # Handle both semicolon and comma separated formats
                if ";" in str(row):
                    parts = list(row.values())[0].split(";")
                    if len(parts) >= 2:
                        fdid = int(parts[0])
                        path = parts[1]
                    else:
                        continue
                else:
                    fdid = int(row.get("fdid", row.get("id", 0)))
                    path = row.get("path", row.get("filename", ""))

                if fdid and path:
                    entry = FileDataEntry(
                        fdid=fdid,
                        path=path.strip(),
                        verified=True
                    )
                    entries.append(entry)

            except (ValueError, KeyError) as e:
                logger.debug("skip_invalid_listfile_entry", row=row, error=str(e))

        return entries

    def import_entries(self, entries: list[FileDataEntry], source: str = "wowdev") -> int:
        """Import file entries into database.

        Args:
            entries: List of file entries to import
            source: Source of the entries

        Returns:
            Number of entries imported/updated
        """
        imported = 0

        # Use transaction for bulk insert
        with self.conn:
            # Prepare bulk insert
            self.conn.execute("BEGIN TRANSACTION")

            for entry in entries:
                try:
                    # Check if entry exists
                    existing = self.conn.execute(
                        "SELECT fdid, path FROM file_entries WHERE fdid = ?",
                        (entry.fdid,)
                    ).fetchone()

                    if existing:
                        # Update if path changed
                        if existing["path"] != entry.path:
                            self.conn.execute("""
                                INSERT INTO listfile_updates
                                (fdid, old_path, new_path, source)
                                VALUES (?, ?, ?, ?)
                            """, (entry.fdid, existing["path"], entry.path, source))

                            self.conn.execute("""
                                UPDATE file_entries
                                SET path = ?, path_lower = ?, verified = ?,
                                    product_family = 'wow',
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE fdid = ?
                            """, (entry.path, entry.path.lower(),
                                  int(entry.verified), entry.fdid))

                            logger.debug("updated_file_entry", fdid=entry.fdid)
                            imported += 1
                    else:
                        # Insert new entry with WoW family (FileDataIDs are shared)
                        self.conn.execute("""
                            INSERT INTO file_entries
                            (fdid, path, path_lower, verified, lookup_hash,
                             added_date, product, product_family)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'wow')
                        """, (entry.fdid, entry.path, entry.path.lower(),
                              int(entry.verified), entry.lookup_hash,
                              entry.added_date, entry.product))

                        imported += 1

                except sqlite3.IntegrityError as e:
                    logger.debug("duplicate_entry", fdid=entry.fdid, error=str(e))

            self.conn.execute("COMMIT")

            # Record import
            self.conn.execute("""
                INSERT INTO listfile_sources (source, entry_count, metadata)
                VALUES (?, ?, ?)
            """, (source, imported, json.dumps({"timestamp": datetime.now().isoformat()})))

        logger.info("listfile_imported", count=imported, source=source)
        return imported

    def get_path(self, fdid: int) -> str | None:
        """Get file path for a FileDataID.

        Args:
            fdid: FileDataID

        Returns:
            File path if found
        """
        row = self.conn.execute(
            "SELECT path FROM file_entries WHERE fdid = ?",
            (fdid,)
        ).fetchone()

        return row["path"] if row else None

    def get_fdid(self, path: str) -> int | None:
        """Get FileDataID for a path.

        Args:
            path: File path

        Returns:
            FileDataID if found
        """
        # Try exact match first
        row = self.conn.execute(
            "SELECT fdid FROM file_entries WHERE path = ? OR path_lower = ?",
            (path, path.lower())
        ).fetchone()

        return row["fdid"] if row else None

    def search_paths(self, pattern: str, limit: int = 100) -> list[FileDataEntry]:
        """Search for file paths matching pattern.

        Args:
            pattern: Search pattern (supports FTS5 syntax)
            limit: Maximum results

        Returns:
            List of matching entries
        """
        # Use FTS for efficient search
        rows = self.conn.execute("""
            SELECT e.fdid, e.path, e.verified, e.product
            FROM file_search s
            JOIN file_entries e ON s.fdid = e.fdid
            WHERE s.path MATCH ?
            ORDER BY rank
            LIMIT ?
        """, (pattern, limit)).fetchall()

        entries = []
        for row in rows:
            entries.append(FileDataEntry(
                fdid=row["fdid"],
                path=row["path"],
                verified=bool(row["verified"]),
                product=row["product"]
            ))

        return entries

    def get_statistics(self) -> dict[str, Any]:
        """Get listfile statistics.

        Returns:
            Statistics dictionary
        """
        stats = {}

        # Total entries
        stats["total_entries"] = self.conn.execute(
            "SELECT COUNT(*) FROM file_entries"
        ).fetchone()[0]

        # Verified vs unverified
        stats["verified"] = self.conn.execute(
            "SELECT COUNT(*) FROM file_entries WHERE verified = 1"
        ).fetchone()[0]

        stats["unverified"] = stats["total_entries"] - stats["verified"]

        # By product family
        product_families = self.conn.execute("""
            SELECT product_family, COUNT(*) as count
            FROM file_entries
            WHERE product_family IS NOT NULL
            GROUP BY product_family
        """).fetchall()

        if product_families:
            stats["by_product_family"] = {row["product_family"]: row["count"] for row in product_families}

        # By legacy product
        products = self.conn.execute("""
            SELECT product, COUNT(*) as count
            FROM file_entries
            WHERE product IS NOT NULL
            GROUP BY product
        """).fetchall()

        if products:
            stats["by_product"] = {row["product"]: row["count"] for row in products}

        # File extensions
        extensions = self.conn.execute("""
            SELECT
                LOWER(SUBSTR(path, -4)) as ext,
                COUNT(*) as count
            FROM file_entries
            WHERE path LIKE '%.___'
            GROUP BY ext
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()

        stats["top_extensions"] = {row["ext"]: row["count"] for row in extensions}

        # Last update
        last_source = self.conn.execute("""
            SELECT fetch_time, entry_count, source
            FROM listfile_sources
            ORDER BY id DESC LIMIT 1
        """).fetchone()

        if last_source:
            stats["last_update"] = {
                "time": last_source["fetch_time"],
                "count": last_source["entry_count"],
                "source": last_source["source"]
            }

        return stats

    def sync_with_wowdev(self) -> int:
        """Sync database with latest wow-listfile.

        Returns:
            Number of entries imported/updated
        """
        entries = self.fetch_listfile(force_refresh=True)
        return self.import_entries(entries)

    def export_listfile(self, output_file: Path, format: str = "csv") -> None:
        """Export listfile to file.

        Args:
            output_file: Output file path
            format: Export format (csv or json)
        """
        rows = self.conn.execute("""
            SELECT fdid, path, verified, product
            FROM file_entries
            ORDER BY fdid
        """).fetchall()

        if format == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["fdid", "path", "verified", "product"])
                for row in rows:
                    writer.writerow([row["fdid"], row["path"],
                                     row["verified"], row["product"]])
        else:  # json
            entries = []
            for row in rows:
                entries.append({
                    "fdid": row["fdid"],
                    "path": row["path"],
                    "verified": bool(row["verified"]),
                    "product": row["product"]
                })

            with open(output_file, "w") as f:
                json.dump(entries, f, indent=2)

        logger.info("exported_listfile", count=len(rows), path=str(output_file))

    def close(self) -> None:
        """Close connections."""
        if self._conn:
            self._conn.close()
        if self._client:
            self._client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
