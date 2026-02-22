"""Unified cache management for CASC data."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import structlog

logger = structlog.get_logger()


class DiskCache:
    """Disk cache matching Rust cascette cache structure.

    Cache layout:
    ~/.cache/cascette/
    ├── cdn/                      # CDN content cache
    │   └── {path}/               # Path from TACT cdns endpoint (e.g., tpr/wow)
    │       ├── config/           # Build, CDN, and Patch configuration files
    │       │   └── {hash[:2]}/{hash[2:4]}/{hash}
    │       ├── data/             # Archives, indices, and standalone files
    │       │   ├── {hash[:2]}/{hash[2:4]}/{hash}        # Archive/standalone file
    │       │   └── {hash[:2]}/{hash[2:4]}/{hash}.index  # Archive index
    │       └── patch/            # Patch manifests, files, archives, and indices
    │           ├── {hash[:2]}/{hash[2:4]}/{hash}        # Patch manifest/archive
    │           └── {hash[:2]}/{hash[2:4]}/{hash}.index  # Patch archive index
    └── api/                      # TACT HTTPS API responses
        └── {safe_filename}.cache
    """

    def __init__(self, base_dir: Path | None = None):
        """Initialize disk cache.

        Args:
            base_dir: Base cache directory, defaults to ~/.cache/cascette
        """
        self.base_dir = base_dir or (Path.home() / ".cache" / "cascette")
        self.cdn_dir = self.base_dir / "cdn"
        self.api_dir = self.base_dir / "api"
        self.metadata_file = self.base_dir / "metadata.json"
        self.metadata: dict[str, Any] = {}

        # Ensure directories exist
        self.cdn_dir.mkdir(parents=True, exist_ok=True)
        self.api_dir.mkdir(parents=True, exist_ok=True)

        # Load or create metadata
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load cache metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, encoding="utf-8") as f:
                    loaded_data: Any = json.load(f)
                    if isinstance(loaded_data, dict):
                        self.metadata = loaded_data
                    else:
                        logger.warning("metadata_invalid_format", type=type(loaded_data).__name__)
                        self.metadata = {}
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("metadata_load_failed", error=str(e))
                self.metadata = {}
        else:
            self.metadata = {}

        # Ensure required structure
        if "last_updated" not in self.metadata:
            self.metadata["last_updated"] = time.time()
        if "statistics" not in self.metadata:
            self.metadata["statistics"] = {}

        self._save_metadata()

    def _save_metadata(self) -> None:
        """Save cache metadata to disk."""
        try:
            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, indent=2)
        except OSError as e:
            logger.warning("metadata_save_failed", error=str(e))

    def _update_metadata(self, identifier: str, file_type: str, size: int) -> None:
        """Update metadata for a cache entry.

        Args:
            identifier: Hash or key identifier
            file_type: Type of file being cached
            size: Size of the cached data
        """
        self.metadata["last_updated"] = time.time()

        stats = cast(dict[str, dict[str, int]], self.metadata.get("statistics", {}))
        if not isinstance(self.metadata.get("statistics"), dict):
            stats = {}
            self.metadata["statistics"] = stats

        if file_type not in stats:
            stats[file_type] = {"count": 0, "total_size": 0}

        type_stats = stats[file_type]
        type_stats["count"] = type_stats.get("count", 0) + 1
        type_stats["total_size"] = type_stats.get("total_size", 0) + size

        self._save_metadata()

    def _get_cdn_cache_path(self, hash_str: str, file_type: str, cdn_path: str) -> Path:
        """Get CDN cache path for a hash, matching Rust structure.

        Args:
            hash_str: Hex hash string
            file_type: Type of file (config, data, index, patch, patch_index)
            cdn_path: Path from TACT cdns endpoint (e.g., "tpr/wow")

        Returns:
            Full cache path in cdn/{path}/ subdirectory

        Raises:
            ValueError: If hash_str is empty or invalid
        """
        if not hash_str:
            raise ValueError("Hash string cannot be empty")

        hash_lower = hash_str.lower()
        subdir1 = hash_lower[:2]
        subdir2 = hash_lower[2:4]

        # Determine the correct directory based on file type
        if file_type == "index":
            # Archive indices go in data/ directory
            content_type = "data"
            filename = f"{hash_lower}.index"
        elif file_type == "patch_index":
            # Patch archive indices go in patch/ directory
            content_type = "patch"
            filename = f"{hash_lower}.index"
        elif file_type == "patch":
            # Patch files go in patch/ directory
            content_type = "patch"
            filename = hash_lower
        else:
            # config, data files go in their respective directories
            content_type = file_type
            filename = hash_lower

        return self.cdn_dir / cdn_path / content_type / subdir1 / subdir2 / filename

    def _get_api_cache_path(self, key: str) -> Path:
        """Get API cache path for a key.

        Args:
            key: API cache key (e.g., "tact:us:wow:versions")

        Returns:
            Full cache path in api/ directory
        """
        # Create a safe filename from the key
        safe_key = key.replace("/", "_").replace(":", "_")
        return self.api_dir / f"{safe_key}.cache"

    def has_cdn(self, hash_str: str, file_type: str, cdn_path: str) -> bool:
        """Check if CDN file exists in cache.

        Args:
            hash_str: Hex hash string
            file_type: Type of file (config, data, index, patch, patch_index)
            cdn_path: Path from TACT cdns endpoint (e.g., "tpr/wow")

        Returns:
            True if cached (CDN content never expires once cached)
        """
        cache_path = self._get_cdn_cache_path(hash_str, file_type, cdn_path)
        # CDN content is immutable - if it exists, it's valid forever
        return cache_path.exists()

    def get_cdn(self, hash_str: str, file_type: str, cdn_path: str) -> bytes | None:
        """Get CDN file from cache.

        Args:
            hash_str: Hex hash string
            file_type: Type of file (config, data, index, patch, patch_index)
            cdn_path: Path from TACT cdns endpoint (e.g., "tpr/wow")

        Returns:
            Cached data or None if not found
        """
        cache_path = self._get_cdn_cache_path(hash_str, file_type, cdn_path)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "rb") as f:
                return f.read()
        except OSError as e:
            logger.warning("cdn_cache_read_failed", hash=hash_str, error=str(e))
            return None

    def put_cdn(self, hash_str: str, data: bytes, file_type: str, cdn_path: str) -> None:
        """Store CDN file in cache.

        Args:
            hash_str: Hex hash string
            data: File data
            file_type: Type of file (config, data, index, patch, patch_index)
            cdn_path: Path from TACT cdns endpoint (e.g., "tpr/wow")
        """
        cache_path = self._get_cdn_cache_path(hash_str, file_type, cdn_path)

        # Ensure parent directory exists
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically with temp file
        temp_path = cache_path.with_suffix(".tmp")
        try:
            with open(temp_path, "wb") as f:
                f.write(data)
            temp_path.replace(cache_path)
        except OSError as e:
            logger.warning("cdn_cache_write_failed", hash=hash_str, error=str(e))
            if temp_path.exists():
                temp_path.unlink()
            return

        # Update metadata
        self._update_metadata(hash_str, file_type, len(data))
        logger.debug("cdn_cache_stored", hash=hash_str, type=file_type, size=len(data))

    def has_api(self, key: str) -> bool:
        """Check if API response exists in cache.

        Args:
            key: API cache key (e.g., "tact:us:wow:versions")

        Returns:
            True if cached and valid
        """
        cache_path = self._get_api_cache_path(key)
        if not cache_path.exists():
            return False

        # Check if cache is still valid (24-hour lifetime)
        stat = cache_path.stat()
        age = time.time() - stat.st_mtime
        return age <= (24 * 60 * 60)

    def get_api(self, key: str) -> str | None:
        """Get API response from cache.

        Args:
            key: API cache key

        Returns:
            Cached response or None if not found/expired
        """
        if not self.has_api(key):
            return None

        cache_path = self._get_api_cache_path(key)
        try:
            with open(cache_path, encoding="utf-8") as f:
                return f.read()
        except OSError as e:
            logger.warning("api_cache_read_failed", key=key, error=str(e))
            return None

    def put_api(self, key: str, data: str) -> None:
        """Store API response in cache.

        Args:
            key: API cache key
            data: Response data
        """
        cache_path = self._get_api_cache_path(key)

        # Write atomically with temp file
        temp_path = cache_path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(data)
            temp_path.replace(cache_path)
        except OSError as e:
            logger.warning("api_cache_write_failed", key=key, error=str(e))
            if temp_path.exists():
                temp_path.unlink()
            return

        # Update metadata
        self._update_metadata(key, "api", len(data))
        logger.debug("api_cache_stored", key=key, size=len(data))

    def clear_expired(self) -> int:
        """Remove expired cache entries (API responses only).

        CDN content is never removed as it's immutable.

        Returns:
            Number of files removed
        """
        removed = 0
        now = time.time()
        max_age = 24 * 60 * 60  # 24 hours

        # Only check API cache - CDN content never expires
        for path in self.api_dir.rglob("*.cache"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age > max_age:
                    try:
                        path.unlink()
                        removed += 1
                    except OSError as e:
                        logger.warning("cache_cleanup_failed", path=str(path), error=str(e))

        if removed > 0:
            logger.info("cache_cleanup", removed=removed)

        return removed
