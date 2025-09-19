"""TACT HTTPS client with API response caching."""

from __future__ import annotations

import time

import httpx
import structlog

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.config import TACTConfig
from cascette_tools.core.types import Product

logger = structlog.get_logger()


class BPSVParser:
    """Parser for Blizzard Pipe-Separated Values format."""

    def parse(self, manifest: str) -> list[dict[str, str]]:
        """Parse BPSV manifest into list of dictionaries.

        Args:
            manifest: BPSV manifest text

        Returns:
            List of parsed entries
        """
        if not manifest.strip():
            return []

        lines = [line.strip() for line in manifest.strip().split('\n') if line.strip()]
        if not lines:
            return []

        # First line is header with column definitions
        header_line = lines[0]
        if not header_line:
            return []

        # Parse header to get column names
        # Format: ColumnName!TYPE:SIZE|ColumnName2!TYPE:SIZE
        columns = []
        for column_def in header_line.split('|'):
            if '!' in column_def:
                column_name = column_def.split('!')[0]
            else:
                column_name = column_def
            columns.append(column_name)

        # Parse data lines
        results = []
        for line in lines[1:]:
            if not line:
                continue

            values = line.split('|')
            entry = {}

            # Map values to columns, handling mismatched counts
            for i, column in enumerate(columns):
                if i < len(values):
                    entry[column] = values[i]
                else:
                    entry[column] = ""  # Missing value

            results.append(entry)

        return results


class TACTClient:
    """TACT HTTPS client with API response caching.

    Handles queries to TACT endpoints (versions, cdns, bgdl)
    with automatic caching of responses in ~/.cache/cascette/api/.
    """

    def __init__(self, region: str = "us", config: TACTConfig | None = None):
        """Initialize TACT client.

        Args:
            region: Region code (us, eu, kr, tw, cn, sg)
            config: Optional TACT configuration
        """
        self.region = region
        self.config = config or TACTConfig()
        self.cache = DiskCache()  # Uses same structure as Rust
        self.session = None
        self._base_url = f"https://{region}.version.battle.net"

    def _build_url(self, endpoint: str, product: Product) -> str:
        """Build URL for TACT endpoint.

        Args:
            endpoint: API endpoint (versions, cdns, bgdl)
            product: Product code

        Returns:
            Full URL for the endpoint
        """
        # HTTPS TACT v2 uses pattern: /{product}/{endpoint}
        return f"{self._base_url}/{product.value}/{endpoint}"

    def _fetch_with_retry(self, url: str) -> str:
        """Fetch URL with retry logic.

        Args:
            url: URL to fetch

        Returns:
            Response text

        Raises:
            httpx.HTTPStatusError: If all retries fail
        """
        last_error = None

        for attempt in range(self.config.max_retries + 1):
            try:
                with httpx.Client(
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl
                ) as client:
                    response = client.get(url)
                    response.raise_for_status()
                    return response.text

            except httpx.HTTPError as e:
                last_error = e
                if attempt < self.config.max_retries:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.debug(
                        "tact_retry",
                        url=url,
                        attempt=attempt + 1,
                        wait=wait_time,
                        error=str(e)
                    )
                    time.sleep(wait_time)
                    continue
                break

        # All retries failed
        logger.error("tact_fetch_failed", url=url, error=str(last_error))
        if last_error:
            raise last_error
        raise httpx.HTTPError(f"Failed to fetch {url}")

    def fetch_versions(self, product: Product) -> str:
        """Fetch product versions with caching.

        Args:
            product: Product code

        Returns:
            Version manifest as string
        """
        cache_key = f"tact:{self.region}:{product.value}:versions"

        # Check cache first
        cached = self.cache.get_api(cache_key)
        if cached:
            logger.debug("cache_hit", key=cache_key, type="api")
            return cached

        # Fetch from TACT endpoint
        url = self._build_url("versions", product)
        response = self._fetch_with_retry(url)

        # Store in cache
        self.cache.put_api(cache_key, response)
        logger.debug("tact_fetched", endpoint="versions", product=product.value)

        return response

    def fetch_cdns(self, product: Product) -> str:
        """Fetch CDN configuration with caching.

        Args:
            product: Product code

        Returns:
            CDN manifest as string
        """
        cache_key = f"tact:{self.region}:{product.value}:cdns"

        # Check cache first
        cached = self.cache.get_api(cache_key)
        if cached:
            logger.debug("cache_hit", key=cache_key, type="api")
            return cached

        # Fetch from TACT endpoint
        url = self._build_url("cdns", product)
        response = self._fetch_with_retry(url)

        # Store in cache
        self.cache.put_api(cache_key, response)
        logger.debug("tact_fetched", endpoint="cdns", product=product.value)

        return response

    def fetch_bgdl(self, product: Product) -> str:
        """Fetch background download configuration with caching.

        Args:
            product: Product code

        Returns:
            BGDL manifest as string
        """
        cache_key = f"tact:{self.region}:{product.value}:bgdl"

        # Check cache first
        cached = self.cache.get_api(cache_key)
        if cached:
            logger.debug("cache_hit", key=cache_key, type="api")
            return cached

        # Fetch from TACT endpoint
        url = self._build_url("bgdl", product)
        response = self._fetch_with_retry(url)

        # Store in cache
        self.cache.put_api(cache_key, response)
        logger.debug("tact_fetched", endpoint="bgdl", product=product.value)

        return response

    def parse_versions(self, manifest: str) -> list[dict[str, str]]:
        """Parse versions manifest.

        Args:
            manifest: BPSV manifest text

        Returns:
            List of version entries
        """
        parser = BPSVParser()
        return parser.parse(manifest)

    def parse_cdns(self, manifest: str) -> list[dict[str, str]]:
        """Parse CDN manifest.

        Args:
            manifest: BPSV manifest text

        Returns:
            List of CDN entries
        """
        parser = BPSVParser()
        return parser.parse(manifest)

    def parse_bgdl(self, manifest: str) -> list[dict[str, str]]:
        """Parse BGDL manifest.

        Args:
            manifest: BPSV manifest text

        Returns:
            List of BGDL entries
        """
        parser = BPSVParser()
        return parser.parse(manifest)

    def get_latest_build(self, product: Product) -> dict[str, str] | None:
        """Get latest build information for a product.

        Args:
            product: Product code

        Returns:
            Latest build info or None if not found
        """
        manifest = self.fetch_versions(product)
        versions = self.parse_versions(manifest)

        # Filter by region and get first (latest)
        for entry in versions:
            if entry.get("Region") == self.region:
                return entry
        return None

    def get_cdn_servers(self, product: Product) -> list[str]:
        """Get CDN server list for a product.

        Args:
            product: Product code

        Returns:
            List of CDN server URLs
        """
        manifest = self.fetch_cdns(product)
        cdns = self.parse_cdns(manifest)

        # Filter by region and extract servers
        for entry in cdns:
            if entry.get("Name") == self.region:
                hosts = entry.get("Hosts", "").split()
                return [f"http://{host}" for host in hosts]
        return []

    def get_cdn_path(self, product: Product) -> str | None:
        """Get CDN path for a product.

        Args:
            product: Product code

        Returns:
            CDN path or None if not found
        """
        manifest = self.fetch_cdns(product)
        cdns = self.parse_cdns(manifest)

        # Filter by region and extract path
        for entry in cdns:
            if entry.get("Name") == self.region:
                return entry.get("Path")
        return None

    def clear_cache(self, product: Product | None = None) -> int:
        """Clear cached API responses.

        Args:
            product: Optional product to clear (all if None)

        Returns:
            Number of entries cleared
        """
        # For now, just clear expired entries
        # TODO: Implement product-specific clearing
        return self.cache.clear_expired()
