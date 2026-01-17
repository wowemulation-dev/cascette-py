"""CDN archive fetcher for downloading files from CDN archives.

This module provides functionality to:
1. Download archive indices from CDN
2. Build an in-memory index map (encoding key → archive, offset, size)
3. Fetch files using HTTP range requests
4. Decompress BLTE-encoded data

The typical workflow is:
1. Fetch CDN config to get list of archives
2. Download archive indices (in parallel for speed)
3. Build index map for fast lookups
4. Extract files by encoding key using range requests
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx
import structlog

from cascette_tools.formats.blte import decompress_blte, is_blte
from cascette_tools.formats.cdn_archive import CdnArchiveParser, CdnArchiveEntry

logger = structlog.get_logger()


def get_cached_index_path(indices_dir: Path, archive_hash: str) -> Path:
    """Get the path where a cached index should be stored.

    Args:
        indices_dir: Base indices directory (e.g., Data/indices/)
        archive_hash: Archive hash

    Returns:
        Path to the cached index file
    """
    return indices_dir / f"{archive_hash.lower()}.index"


@dataclass
class ArchiveLocation:
    """Location of a file within a CDN archive."""
    archive_hash: str
    offset: int
    size: int


@dataclass
class IndexMap:
    """In-memory index map for fast encoding key lookups."""
    entries: dict[bytes, ArchiveLocation] = field(default_factory=dict)
    archive_count: int = 0
    total_entries: int = 0

    def add_archive(self, archive_hash: str, entries: list[CdnArchiveEntry]) -> None:
        """Add entries from an archive index to the map.

        Args:
            archive_hash: Archive hash
            entries: List of archive index entries
        """
        for entry in entries:
            # Use truncated key (first 9 bytes) for memory efficiency
            # This matches how most lookups work
            key = entry.encoding_key[:16]  # Full 16-byte key for accuracy
            self.entries[key] = ArchiveLocation(
                archive_hash=archive_hash,
                offset=entry.offset,
                size=entry.size
            )
            self.total_entries += 1
        self.archive_count += 1

    def find(self, encoding_key: bytes) -> ArchiveLocation | None:
        """Find location for an encoding key.

        Args:
            encoding_key: Encoding key to find (16 bytes)

        Returns:
            Archive location or None if not found
        """
        # Try full key first
        if encoding_key in self.entries:
            return self.entries[encoding_key]

        # Try truncated key
        truncated = encoding_key[:16]
        return self.entries.get(truncated)


class CdnArchiveFetcher:
    """Fetches files from CDN archives using indices."""

    def __init__(
        self,
        cdn_base: str = "http://us.cdn.blizzard.com",
        cdn_path: str = "tpr/wow",
        timeout: float = 30.0,
        max_concurrent: int = 10
    ):
        """Initialize fetcher.

        Args:
            cdn_base: CDN base URL
            cdn_path: CDN product path
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.cdn_base = cdn_base
        self.cdn_path = cdn_path
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.index_map = IndexMap()
        self._parser = CdnArchiveParser()

    def _make_index_url(self, archive_hash: str) -> str:
        """Make URL for archive index file."""
        h = archive_hash.lower()
        return f"{self.cdn_base}/{self.cdn_path}/data/{h[:2]}/{h[2:4]}/{h}.index"

    def _make_data_url(self, archive_hash: str) -> str:
        """Make URL for archive data file."""
        h = archive_hash.lower()
        return f"{self.cdn_base}/{self.cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"

    def load_index_from_bytes(self, archive_hash: str, data: bytes) -> bool:
        """Load an index from raw bytes and add to index map.

        Args:
            archive_hash: Archive hash
            data: Raw index file data

        Returns:
            True if successful, False otherwise
        """
        try:
            index = self._parser.parse(data)
            self.index_map.add_archive(archive_hash, index.entries)
            logger.debug(f"Loaded index {archive_hash}: {len(index.entries)} entries")
            return True
        except Exception as e:
            logger.warning(f"Error parsing index {archive_hash}: {e}")
            return False

    def load_index_from_file(self, archive_hash: str, path: Path) -> bool:
        """Load an index from a cached file.

        Args:
            archive_hash: Archive hash
            path: Path to the cached index file

        Returns:
            True if successful, False otherwise
        """
        try:
            if not path.exists():
                return False
            data = path.read_bytes()
            return self.load_index_from_bytes(archive_hash, data)
        except Exception as e:
            logger.warning(f"Error loading cached index {archive_hash}: {e}")
            return False

    def download_index(self, client: httpx.Client, archive_hash: str) -> bool:
        """Download and parse a single archive index.

        Args:
            client: HTTP client
            archive_hash: Archive hash

        Returns:
            True if successful, False otherwise
        """
        url = self._make_index_url(archive_hash)
        try:
            response = client.get(url)
            if response.status_code != 200:
                logger.warning(f"Failed to fetch index {archive_hash}: HTTP {response.status_code}")
                return False

            # Parse the index
            index = self._parser.parse(response.content)

            # Add to index map
            self.index_map.add_archive(archive_hash, index.entries)

            logger.debug(f"Loaded index {archive_hash}: {len(index.entries)} entries")
            return True

        except Exception as e:
            logger.warning(f"Error loading index {archive_hash}: {e}")
            return False

    def download_index_with_cache(
        self,
        client: httpx.Client,
        archive_hash: str,
        cache_dir: Path | None = None
    ) -> tuple[bool, bytes | None]:
        """Download an index, optionally caching to disk.

        Args:
            client: HTTP client
            archive_hash: Archive hash
            cache_dir: Directory to cache indices (e.g., Data/indices/)

        Returns:
            Tuple of (success, raw_data or None)
        """
        # Check cache first
        if cache_dir:
            cache_path = get_cached_index_path(cache_dir, archive_hash)
            if cache_path.exists():
                data = cache_path.read_bytes()
                if self.load_index_from_bytes(archive_hash, data):
                    return True, data

        # Download from CDN
        url = self._make_index_url(archive_hash)
        try:
            response = client.get(url)
            if response.status_code != 200:
                return False, None

            data = response.content

            # Parse and add to index map
            index = self._parser.parse(data)
            self.index_map.add_archive(archive_hash, index.entries)

            # Cache to disk
            if cache_dir:
                cache_path = get_cached_index_path(cache_dir, archive_hash)
                cache_path.write_bytes(data)

            return True, data

        except Exception as e:
            logger.warning(f"Error loading index {archive_hash}: {e}")
            return False, None

    def download_indices(
        self,
        archive_hashes: list[str],
        progress_callback: Callable[[int, int], None] | None = None
    ) -> int:
        """Download multiple archive indices.

        Args:
            archive_hashes: List of archive hashes
            progress_callback: Optional callback(completed, total)

        Returns:
            Number of successfully downloaded indices
        """
        successful = 0
        total = len(archive_hashes)

        with httpx.Client(timeout=self.timeout) as client:
            for i, archive_hash in enumerate(archive_hashes):
                if self.download_index(client, archive_hash):
                    successful += 1

                if progress_callback:
                    progress_callback(i + 1, total)

        logger.info(
            f"Downloaded {successful}/{total} archive indices",
            total_entries=self.index_map.total_entries
        )
        return successful

    async def download_indices_async(
        self,
        archive_hashes: list[str],
        progress_callback: Callable[[int, int], None] | None = None
    ) -> int:
        """Download multiple archive indices asynchronously.

        Args:
            archive_hashes: List of archive hashes
            progress_callback: Optional callback(completed, total)

        Returns:
            Number of successfully downloaded indices
        """
        successful = 0
        total = len(archive_hashes)
        completed = 0
        lock = asyncio.Lock()

        async def download_one(client: httpx.AsyncClient, archive_hash: str) -> bool:
            nonlocal successful, completed
            url = self._make_index_url(archive_hash)
            try:
                response = await client.get(url)
                if response.status_code != 200:
                    return False

                # Parse the index
                index = self._parser.parse(response.content)

                # Add to index map (thread-safe)
                async with lock:
                    self.index_map.add_archive(archive_hash, index.entries)
                    successful += 1
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)

                return True

            except Exception as e:
                async with lock:
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)
                logger.debug(f"Error loading index {archive_hash}: {e}")
                return False

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Process in batches to limit concurrency
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def download_with_semaphore(archive_hash: str) -> bool:
                async with semaphore:
                    return await download_one(client, archive_hash)

            tasks = [download_with_semaphore(h) for h in archive_hashes]
            await asyncio.gather(*tasks)

        logger.info(
            f"Downloaded {successful}/{total} archive indices",
            total_entries=self.index_map.total_entries
        )
        return successful

    def fetch_file(
        self,
        client: httpx.Client,
        encoding_key: bytes,
        decompress: bool = True
    ) -> bytes | None:
        """Fetch a file from CDN archives by encoding key.

        Args:
            client: HTTP client
            encoding_key: Encoding key (16 bytes)
            decompress: Whether to decompress BLTE data

        Returns:
            File data or None if not found
        """
        # Find location in index map
        location = self.index_map.find(encoding_key)
        if not location:
            logger.warning(f"Encoding key not found in index map: {encoding_key.hex()}")
            return None

        # Fetch using range request
        url = self._make_data_url(location.archive_hash)
        headers = {
            "Range": f"bytes={location.offset}-{location.offset + location.size - 1}"
        }

        try:
            response = client.get(url, headers=headers)
            if response.status_code not in [200, 206]:
                logger.warning(
                    f"Failed to fetch data: HTTP {response.status_code}",
                    archive=location.archive_hash,
                    offset=location.offset,
                    size=location.size
                )
                return None

            data = response.content

            # Decompress BLTE if requested
            if decompress and is_blte(data):
                try:
                    data = decompress_blte(data)
                except Exception as e:
                    logger.warning(f"BLTE decompression failed: {e}")
                    return None

            return data

        except Exception as e:
            logger.warning(f"Error fetching file: {e}")
            return None

    def fetch_file_raw(
        self,
        client: httpx.Client,
        archive_hash: str,
        offset: int,
        size: int
    ) -> bytes | None:
        """Fetch raw data from a specific archive location.

        Args:
            client: HTTP client
            archive_hash: Archive hash
            offset: Byte offset
            size: Byte count

        Returns:
            Raw data or None on error
        """
        url = self._make_data_url(archive_hash)
        headers = {
            "Range": f"bytes={offset}-{offset + size - 1}"
        }

        try:
            response = client.get(url, headers=headers)
            if response.status_code not in [200, 206]:
                return None
            return response.content
        except Exception as e:
            logger.warning(f"Error fetching raw data: {e}")
            return None


def parse_cdn_config_archives(content: str) -> list[str]:
    """Parse archive list from CDN config content.

    Args:
        content: CDN config text content

    Returns:
        List of archive hashes
    """
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('archives = '):
            hashes = line[len('archives = '):].split()
            return hashes
    return []
