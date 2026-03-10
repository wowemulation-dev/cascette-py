"""BlizzTrack API client for archived NGDP manifest history."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from cascette_tools.core.config import AppConfig
from cascette_tools.database.wago import WagoBuild

logger = structlog.get_logger()

# Products supported for BlizzTrack sync.
# These are the TACT product codes used in NGDP manifests.
#
# Note: "bts" (Battle.net Setup) is intentionally excluded. Unlike other
# products, bts uses the target product code (e.g. "wow", "d3", "hero") as
# its region field instead of geographic regions. Each entry represents the
# installer configuration for a different game, so bts builds don't fit the
# standard per-product model. If bts support is added, its entries should
# either be attached to the corresponding product or stored separately.
BLIZZTRACK_PRODUCTS = [
    "agent",
    "bna",
    "wow",
    "wow_classic",
    "wow_classic_era",
    "wow_classic_titan",
    "wow_anniversary",
]


def _stable_id(build_config: str, product: str) -> int:
    """Derive a stable integer ID from build_config + product.

    Uses the first 8 hex digits of the MD5 hash, matching the approach
    used in WagoClient.fetch_builds for builds with missing IDs.
    """
    key = f"{build_config}_{product}"
    return int(hashlib.md5(key.encode()).hexdigest()[:8], 16)


class BlizzTrackClient:
    """Client for the BlizzTrack API.

    Fetches current and historical NGDP manifest data (versions, CDNs) for
    Blizzard products. Converts the per-region snapshot format into WagoBuild
    records compatible with the existing SQLite schema.

    BlizzTrack returns one entry per region per seqn snapshot. All regions
    within a snapshot share the same build_config / cdn_config hashes. We
    deduplicate on (build_config, product) before returning results.
    """

    API_BASE = "https://blizztrack.com/api"

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or AppConfig()
        self._client: httpx.Client | None = None

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
                },
            )
        return self._client

    def _get_versions(self, product: str) -> list[dict[str, Any]]:
        """Fetch current versions manifest for a product.

        Returns:
            List of per-region version entries from BlizzTrack.

        Raises:
            httpx.HTTPError: On network or API errors.
            ValueError: If the API reports failure.
        """
        response = self.client.get(f"/manifest/{product}/versions")
        response.raise_for_status()
        data: dict[str, Any] = response.json()

        if not data.get("success"):
            result = data.get("result", {})
            raise ValueError(
                f"BlizzTrack API error for {product}: "
                f"{result.get('code')} {result.get('message')}"
            )

        return list(data["result"].get("data", []))

    def _get_seqn_history(
        self, product: str, file: str = "versions", page: int = 1, limit: int = 100
    ) -> dict[str, Any]:
        """Fetch paginated seqn history for a product+file combination.

        Returns:
            The full result dict including 'results', 'total', 'total_pages'.
        """
        response = self.client.get(
            f"/manifest/{product}/seqn",
            params={"file": file, "page": page, "limit": limit},
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()

        if not data.get("success"):
            result = data.get("result", {})
            raise ValueError(
                f"BlizzTrack seqn history error for {product}/{file}: "
                f"{result.get('code')} {result.get('message')}"
            )

        return dict(data["result"])

    def _get_versions_at_seqn(self, product: str, seqn: int) -> list[dict[str, Any]]:
        """Fetch a historical versions snapshot by seqn number.

        Returns:
            List of per-region version entries.
        """
        response = self.client.get(
            f"/manifest/{product}/versions", params={"seqn": seqn}
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()

        if not data.get("success"):
            return []

        return list(data["result"].get("data", []))

    def _entries_to_builds(
        self,
        entries: list[dict[str, Any]],
        product: str,
        recorded_at: datetime | None = None,
    ) -> list[WagoBuild]:
        """Convert BlizzTrack per-region entries to deduplicated WagoBuild records.

        Multiple regions share identical config hashes within a snapshot.
        We take the first occurrence per build_config and discard duplicates.
        """
        seen_configs: set[str] = set()
        builds: list[WagoBuild] = []

        for entry in entries:
            build_config = entry.get("build_config", "")
            if not build_config or build_config in seen_configs:
                continue
            seen_configs.add(build_config)

            version_name: str = entry.get("version_name", "")
            build_id_raw: int | None = entry.get("build_id")

            # Derive a stable integer ID: prefer build_id if present and
            # non-zero, otherwise hash build_config+product.
            if build_id_raw:
                synthetic_id = _stable_id(build_config, product)
                # Use the hash rather than the raw build_id to avoid collisions
                # across different products that share the same numeric build_id.
                build_id = synthetic_id
            else:
                build_id = _stable_id(build_config, product)

            # Extract build number from version_name (last dotted component).
            build_num = ""
            if version_name and "." in version_name:
                build_num = version_name.split(".")[-1]
            elif build_id_raw:
                build_num = str(build_id_raw)

            builds.append(
                WagoBuild(
                    id=build_id,
                    build=build_num,
                    version=version_name,
                    product=product,
                    build_time=recorded_at,
                    build_config=build_config,
                    cdn_config=entry.get("cdn_config"),
                    product_config=entry.get("product_config"),
                )
            )

        return builds

    def fetch_current(self, products: list[str] | None = None) -> list[WagoBuild]:
        """Fetch the current versions manifest for each product.

        Args:
            products: Product codes to fetch. Defaults to BLIZZTRACK_PRODUCTS.

        Returns:
            Deduplicated list of WagoBuild records (one per build_config).
        """
        targets = products or BLIZZTRACK_PRODUCTS
        all_builds: list[WagoBuild] = []
        now = datetime.now(UTC)

        for product in targets:
            try:
                entries = self._get_versions(product)
                builds = self._entries_to_builds(entries, product, recorded_at=now)
                logger.info(
                    "blizztrack_current_fetched",
                    product=product,
                    builds=len(builds),
                )
                all_builds.extend(builds)
            except Exception as e:
                logger.warning(
                    "blizztrack_current_failed", product=product, error=str(e)
                )

        return all_builds

    def _resolve_snapshot(
        self,
        product: str,
        seqn: int,
        recorded_at: datetime | None,
    ) -> list[WagoBuild]:
        """Fetch and convert a single seqn snapshot. Called from worker threads."""
        try:
            entries = self._get_versions_at_seqn(product, seqn)
            return self._entries_to_builds(entries, product, recorded_at=recorded_at)
        except Exception as e:
            logger.debug(
                "blizztrack_seqn_fetch_failed",
                product=product,
                seqn=seqn,
                error=str(e),
            )
            return []

    def fetch_history(
        self,
        products: list[str] | None = None,
        max_pages: int = 10,
        max_workers: int = 5,
    ) -> list[WagoBuild]:
        """Fetch the full seqn history for each product and resolve each snapshot.

        Walks the paginated seqn history (one request per page) to collect all
        snapshot references, then fetches every snapshot concurrently.

        Args:
            products: Product codes to fetch. Defaults to BLIZZTRACK_PRODUCTS.
            max_pages: Maximum seqn history pages to walk per product (100 seqns
                       per page). Use 0 for unlimited.
            max_workers: Thread pool size for concurrent snapshot fetching.
                         Keep low (≤5) to avoid hitting BlizzTrack rate limits.

        Returns:
            Deduplicated list of WagoBuild records across all snapshots.
        """
        targets = products or BLIZZTRACK_PRODUCTS
        # Outer dedup: (build_config, product) across all snapshots.
        seen: set[tuple[str, str]] = set()
        all_builds: list[WagoBuild] = []

        for product in targets:
            try:
                # Phase 1: collect all (seqn, recorded_at) refs via pagination.
                snapshot_refs: list[tuple[int, datetime | None]] = []
                page = 1
                while True:
                    history = self._get_seqn_history(
                        product, file="versions", page=page, limit=100
                    )
                    snapshots: list[dict[str, Any]] = history.get("results", [])
                    total_pages: int = int(history.get("total_pages", 1))

                    for snapshot in snapshots:
                        seqn: int = snapshot["seqn"]
                        recorded_at_str: str = snapshot.get("created_at", "")
                        recorded_at: datetime | None = None
                        if recorded_at_str:
                            try:
                                recorded_at = datetime.fromisoformat(
                                    recorded_at_str.replace("Z", "+00:00")
                                )
                            except ValueError:
                                pass
                        snapshot_refs.append((seqn, recorded_at))

                    if page >= total_pages or (max_pages and page >= max_pages):
                        break
                    page += 1

                # Phase 2: resolve all snapshots concurrently.
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {
                        pool.submit(self._resolve_snapshot, product, seqn, recorded_at): seqn
                        for seqn, recorded_at in snapshot_refs
                    }
                    for future in as_completed(futures):
                        builds = future.result()
                        for build in builds:
                            key = (build.build_config or "", product)
                            if key in seen:
                                continue
                            seen.add(key)
                            all_builds.append(build)

                logger.info(
                    "blizztrack_history_fetched",
                    product=product,
                    builds=sum(1 for b in all_builds if b.product == product),
                )

            except Exception as e:
                logger.warning(
                    "blizztrack_history_failed", product=product, error=str(e)
                )

        return all_builds

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()

    def __enter__(self) -> BlizzTrackClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
