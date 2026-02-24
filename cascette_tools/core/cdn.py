"""CDN client with disk caching and TACT integration."""

from __future__ import annotations

import asyncio

import httpx
import structlog

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.config import CDNConfig
from cascette_tools.core.tact import TACTClient
from cascette_tools.core.types import Product

logger = structlog.get_logger()


class CDNClient:
    """CDN client with disk caching and TACT integration.

    The CDN client requires the Path value from TACT cdns endpoint
    to properly construct URLs and cache paths.
    """

    def __init__(
        self,
        product: Product,
        region: str = "us",
        config: CDNConfig | None = None
    ):
        """Initialize CDN client.

        Args:
            product: Product code (e.g., Product.WOW)
            region: Region code (default: "us")
            config: Optional CDN configuration
        """
        self.product = product
        self.region = region
        self.config = config or CDNConfig()
        self.cache = DiskCache()
        self.tact_client = TACTClient(region=region)
        self._client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

        # These will be populated from TACT cdns endpoint
        self.cdn_path: str | None = None  # e.g., "tpr/wow"
        self.cdn_servers: list[str] = []  # List of CDN server URLs
        self._initialized = False

    @property
    def client(self) -> httpx.Client:
        """Get or create sync HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                follow_redirects=True,
            )
        return self._client

    @property
    def async_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                follow_redirects=True,
            )
        return self._async_client

    def ensure_initialized(self) -> None:
        """Ensure CDN client is initialized with TACT data."""
        if self._initialized:
            return

        # Fetch CDN configuration from TACT
        cdns_manifest = self.tact_client.fetch_cdns(self.product)
        cdns = self.tact_client.parse_cdns(cdns_manifest)

        # Find our region's CDN configuration
        for entry in cdns:
            if entry.get("Name") == self.region:
                # Extract the Path value - CRITICAL!
                self.cdn_path = entry.get("Path", "")

                # Extract CDN servers
                hosts = entry.get("Hosts", "").split()
                self.cdn_servers = [f"http://{host}" for host in hosts]

                logger.info(
                    "cdn_initialized",
                    product=self.product.value,
                    path=self.cdn_path,
                    servers=len(self.cdn_servers)
                )
                self._initialized = True
                return

        # Region not found
        raise ValueError(f"CDN configuration not found for region: {self.region}")

    def _build_url(self, hash_str: str, file_type: str, mirror: str) -> str:
        """Build CDN URL for a given hash.

        Args:
            hash_str: Hex hash string
            file_type: Type of file (config, data, index, patch, patch_index)
            mirror: Mirror base URL

        Returns:
            Complete URL for the file
        """
        hash_lower = hash_str.lower()
        subdir1 = hash_lower[:2]
        subdir2 = hash_lower[2:4]

        # Determine content type and file name
        if file_type == "config":
            content_type = "config"
            file_name = hash_lower
        elif file_type == "data":
            content_type = "data"
            file_name = hash_lower
        elif file_type == "index":
            content_type = "data"
            file_name = f"{hash_lower}.index"
        elif file_type == "patch":
            content_type = "patch"
            file_name = hash_lower
        elif file_type == "patch_index":
            content_type = "patch"
            file_name = f"{hash_lower}.index"
        else:
            raise ValueError(f"Unknown file type: {file_type}")

        url = f"{mirror}/{self.cdn_path}/{content_type}/{subdir1}/{subdir2}/{file_name}"
        logger.debug(
            "cdn_url_built",
            url=url,
            mirror=mirror,
            cdn_path=self.cdn_path,
            content_type=content_type,
            hash=hash_str
        )
        return url

    def _fetch_from_cdn(
        self, hash_str: str, file_type: str, quiet: bool = False
    ) -> bytes:
        """Fetch file from CDN servers with mirror fallback.

        Uses Ribbit-provided CDN servers first, then falls back to community mirrors.

        Args:
            hash_str: File hash
            file_type: Type of file (config, data, index, patch, patch_index)
            quiet: If True, log at debug level instead of error when all mirrors fail

        Returns:
            File data

        Raises:
            httpx.HTTPStatusError: If all mirrors fail
        """
        last_error = None

        # Build mirror list: Ribbit servers first, then community fallback mirrors
        mirrors = self.cdn_servers + self.config.fallback_mirrors
        logger.info(
            "cdn_mirror_list",
            mirrors=mirrors,
            cdn_servers=self.cdn_servers,
            fallbacks=self.config.fallback_mirrors,
            cdn_path=self.cdn_path
        )

        if not mirrors:
            raise ValueError("No CDN mirrors available (Ribbit servers and fallback mirrors empty)")

        # Try each mirror in order
        for mirror_idx, mirror in enumerate(mirrors):
            url = self._build_url(hash_str, file_type, mirror)
            logger.info(
                "cdn_url_built",
                url=url,
                cdn_path=self.cdn_path,
                mirror=mirror
            )

            for attempt in range(self.config.max_retries):
                try:
                    response = self.client.get(url)
                    response.raise_for_status()

                    logger.debug(
                        "cdn_fetch_success",
                        hash=hash_str,
                        type=file_type,
                        mirror=mirror,
                        mirror_idx=mirror_idx,
                        attempt=attempt + 1
                    )
                    return response.content

                except httpx.HTTPError as e:
                    last_error = e
                    logger.debug(
                        "cdn_fetch_retry",
                        hash=hash_str,
                        type=file_type,
                        mirror=mirror,
                        attempt=attempt + 1,
                        error=str(e)
                    )
                    continue  # Try next attempt

            # All attempts failed for this mirror, try next mirror
            # Log at debug level since mirror failures are expected for old builds
            # (official CDNs don't serve all historic content)
            logger.debug(
                "cdn_mirror_failed",
                hash=hash_str,
                type=file_type,
                mirror=mirror,
                mirror_idx=mirror_idx
            )

        # All mirrors failed
        if quiet:
            logger.debug("cdn_all_mirrors_failed", hash=hash_str, type=file_type)
        else:
            logger.error("cdn_all_mirrors_failed", hash=hash_str, type=file_type)
        if last_error:
            raise last_error
        raise httpx.HTTPError(f"Failed to fetch {hash_str} from all mirrors")

    def fetch_config(self, hash_str: str, config_type: str = "config") -> bytes:
        """Fetch configuration file (build, cdn, or patch config).

        Args:
            hash_str: Configuration file hash
            config_type: Type hint for logging (build/cdn/patch)

        Returns:
            Configuration data
        """
        self.ensure_initialized()
        assert self.cdn_path is not None, "CDN path should be set after initialization"

        # Check cache first
        cached = self.cache.get_cdn(hash_str, "config", self.cdn_path)
        if cached:
            logger.debug(
                "cache_hit",
                hash=hash_str,
                type="config",
                config_type=config_type,
                path=self.cdn_path
            )
            return cached

        # Fetch from CDN with mirror fallback
        data = self._fetch_from_cdn(hash_str, "config")

        # Store in cache
        self.cache.put_cdn(hash_str, data, "config", self.cdn_path)
        logger.debug(
            "cache_store",
            hash=hash_str,
            type="config",
            config_type=config_type,
            size=len(data)
        )

        return data

    def fetch_data(
        self, hash_str: str, is_index: bool = False, quiet: bool = False
    ) -> bytes:
        """Fetch data file (archive, index, or standalone file).

        Args:
            hash_str: Data file hash
            is_index: True if fetching an archive index
            quiet: If True, log at debug level when all mirrors fail

        Returns:
            File data
        """
        self.ensure_initialized()
        assert self.cdn_path is not None, "CDN path should be set after initialization"

        file_type = "index" if is_index else "data"

        # Check cache first
        cached = self.cache.get_cdn(hash_str, file_type, self.cdn_path)
        if cached:
            logger.debug(
                "cache_hit",
                hash=hash_str,
                type=file_type,
                path=self.cdn_path
            )
            return cached

        # Fetch from CDN with mirror fallback
        data = self._fetch_from_cdn(hash_str, file_type, quiet=quiet)

        # Store in cache
        self.cache.put_cdn(hash_str, data, file_type, self.cdn_path)
        logger.debug(
            "cache_store",
            hash=hash_str,
            type=file_type,
            size=len(data)
        )

        return data

    async def _fetch_from_cdn_async(
        self, hash_str: str, file_type: str, quiet: bool = False
    ) -> bytes:
        """Fetch file from CDN servers with mirror fallback (async).

        Same mirror-fallback logic as _fetch_from_cdn but uses the async client.

        Args:
            hash_str: File hash
            file_type: Type of file (config, data, index, patch, patch_index)
            quiet: If True, log at debug level instead of error when all mirrors fail

        Returns:
            File data

        Raises:
            httpx.HTTPError: If all mirrors fail
        """
        last_error = None

        mirrors = self.cdn_servers + self.config.fallback_mirrors

        if not mirrors:
            raise ValueError("No CDN mirrors available (Ribbit servers and fallback mirrors empty)")

        for mirror_idx, mirror in enumerate(mirrors):
            url = self._build_url(hash_str, file_type, mirror)

            for attempt in range(self.config.max_retries):
                try:
                    response = await self.async_client.get(url)
                    response.raise_for_status()

                    logger.debug(
                        "cdn_fetch_async_success",
                        hash=hash_str,
                        type=file_type,
                        mirror=mirror,
                        mirror_idx=mirror_idx,
                        attempt=attempt + 1
                    )
                    return response.content

                except httpx.HTTPError as e:
                    last_error = e
                    logger.debug(
                        "cdn_fetch_async_retry",
                        hash=hash_str,
                        type=file_type,
                        mirror=mirror,
                        attempt=attempt + 1,
                        error=str(e)
                    )
                    continue

            logger.debug(
                "cdn_mirror_failed",
                hash=hash_str,
                type=file_type,
                mirror=mirror,
                mirror_idx=mirror_idx
            )

        if quiet:
            logger.debug("cdn_all_mirrors_failed", hash=hash_str, type=file_type)
        else:
            logger.error("cdn_all_mirrors_failed", hash=hash_str, type=file_type)
        if last_error:
            raise last_error
        raise httpx.HTTPError(f"Failed to fetch {hash_str} from all mirrors")

    async def fetch_data_async(
        self, hash_str: str, is_index: bool = False, quiet: bool = False
    ) -> bytes:
        """Fetch data file asynchronously with caching.

        Checks the local disk cache first (synchronously, since disk I/O
        is fast), then fetches from CDN using the async client.

        Args:
            hash_str: Data file hash
            is_index: True if fetching an archive index
            quiet: If True, log at debug level when all mirrors fail

        Returns:
            File data
        """
        self.ensure_initialized()
        assert self.cdn_path is not None, "CDN path should be set after initialization"

        file_type = "index" if is_index else "data"

        # Check cache first (sync - local disk)
        cached = self.cache.get_cdn(hash_str, file_type, self.cdn_path)
        if cached:
            logger.debug(
                "cache_hit",
                hash=hash_str,
                type=file_type,
                path=self.cdn_path
            )
            return cached

        # Fetch from CDN with mirror fallback (async)
        data = await self._fetch_from_cdn_async(hash_str, file_type, quiet=quiet)

        # Store in cache (sync - local disk)
        self.cache.put_cdn(hash_str, data, file_type, self.cdn_path)
        logger.debug(
            "cache_store",
            hash=hash_str,
            type=file_type,
            size=len(data)
        )

        return data

    async def fetch_patch_async(
        self, hash_str: str, is_index: bool = False, quiet: bool = False,
    ) -> bytes:
        """Fetch patch file asynchronously with caching.

        Checks the local disk cache first (synchronously, since disk I/O
        is fast), then fetches from CDN using the async client.

        Args:
            hash_str: Patch file hash
            is_index: True if fetching a patch archive index
            quiet: If True, log at debug level when all mirrors fail

        Returns:
            Patch data
        """
        self.ensure_initialized()
        assert self.cdn_path is not None, "CDN path should be set after initialization"

        file_type = "patch_index" if is_index else "patch"

        # Check cache first (sync - local disk)
        cached = self.cache.get_cdn(hash_str, file_type, self.cdn_path)
        if cached is not None:
            logger.debug(
                "cache_hit",
                hash=hash_str,
                type=file_type,
                path=self.cdn_path,
            )
            return cached

        # Fetch from CDN with mirror fallback (async)
        data = await self._fetch_from_cdn_async(hash_str, file_type, quiet=quiet)

        # Store in cache (sync - local disk)
        self.cache.put_cdn(hash_str, data, file_type, self.cdn_path)
        logger.debug(
            "cache_store",
            hash=hash_str,
            type=file_type,
            size=len(data),
        )

        return data

    def fetch_patch(self, hash_str: str, is_index: bool = False) -> bytes:
        """Fetch patch file (manifest, archive, or index).

        Args:
            hash_str: Patch file hash
            is_index: True if fetching a patch archive index

        Returns:
            Patch data
        """
        self.ensure_initialized()
        assert self.cdn_path is not None, "CDN path should be set after initialization"

        file_type = "patch_index" if is_index else "patch"

        # Check cache first
        cached = self.cache.get_cdn(hash_str, file_type, self.cdn_path)
        if cached:
            logger.debug(
                "cache_hit",
                hash=hash_str,
                type=file_type,
                path=self.cdn_path
            )
            return cached

        # Fetch from CDN with mirror fallback
        data = self._fetch_from_cdn(hash_str, file_type)

        # Store in cache
        self.cache.put_cdn(hash_str, data, file_type, self.cdn_path)
        logger.debug(
            "cache_store",
            hash=hash_str,
            type=file_type,
            size=len(data)
        )

        return data

    def close(self) -> None:
        """Close sync HTTP client.

        For async client cleanup, use aclose() in an async context.
        """
        if self._client:
            self._client.close()
        if self._async_client:
            # Best-effort sync close: schedule in running loop if available
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_client.aclose())
            except RuntimeError:
                # No running loop - just drop the reference
                pass
            self._async_client = None

    async def aclose(self) -> None:
        """Close both sync and async HTTP clients."""
        if self._client:
            self._client.close()
            self._client = None
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> CDNClient:
        """Context manager entry."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.close()

    async def __aenter__(self) -> CDNClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Async context manager exit."""
        await self.aclose()
