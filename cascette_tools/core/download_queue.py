"""Concurrent download queue with per-host rate limiting.

Implements a priority-based download queue modeled after Agent.exe's
download engine: 12 concurrent connections globally, 3 per host,
with exponential backoff retry and mirror rotation on failure.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


@dataclass
class DownloadResult:
    """Result of a single download operation.

    Attributes:
        ekey: Encoding key identifying the content
        data: Fetched data bytes, or None on failure
        error: Error description if the download failed
        source: Archive hash or "loose" indicating fetch origin
        attempts: Number of attempts made before success or final failure
    """

    ekey: bytes
    data: bytes | None
    error: str | None = None
    source: str = ""
    attempts: int = 1


@dataclass(order=True)
class _QueueItem:
    """Internal priority queue entry. Lower priority values process first."""

    priority: int
    ekey: bytes = field(compare=False)
    coro_factory: Callable[[], Coroutine[Any, Any, DownloadResult]] = field(
        compare=False
    )


class DownloadQueue:
    """Priority-based concurrent download queue.

    Manages download concurrency with:
    - A global semaphore limiting total concurrent downloads
    - Per-host semaphores limiting connections to each CDN server
    - Priority ordering (lower values first)
    - Exponential backoff retry with mirror rotation

    Args:
        max_concurrency: Maximum total concurrent downloads
        max_per_host: Maximum concurrent downloads per CDN host
        max_retries: Maximum retry attempts per download
        base_backoff: Base delay in seconds for exponential backoff
    """

    def __init__(
        self,
        max_concurrency: int = 12,
        max_per_host: int = 3,
        max_retries: int = 3,
        base_backoff: float = 0.5,
    ):
        self.max_concurrency = max_concurrency
        self.max_per_host = max_per_host
        self.max_retries = max_retries
        self.base_backoff = base_backoff

        self._queue: asyncio.PriorityQueue[_QueueItem] = asyncio.PriorityQueue()
        self._global_semaphore = asyncio.Semaphore(max_concurrency)
        self._host_semaphores: dict[str, asyncio.Semaphore] = {}
        self._progress_callback: Callable[[int, int, int], None] | None = None
        self._completed = 0
        self._total_bytes = 0

    @property
    def progress_callback(self) -> Callable[[int, int, int], None] | None:
        """Get progress callback."""
        return self._progress_callback

    @progress_callback.setter
    def progress_callback(self, callback: Callable[[int, int, int], None] | None) -> None:
        """Set progress callback: (completed, total, bytes_downloaded)."""
        self._progress_callback = callback

    def get_host_semaphore(self, url: str) -> asyncio.Semaphore:
        """Get or create a per-host semaphore for the given URL.

        Args:
            url: Full URL to extract hostname from

        Returns:
            Semaphore for the URL's host
        """
        host = urlparse(url).hostname or "unknown"
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(self.max_per_host)
        return self._host_semaphores[host]

    async def submit(
        self,
        priority: int,
        ekey: bytes,
        coro_factory: Callable[[], Coroutine[Any, Any, DownloadResult]],
    ) -> None:
        """Enqueue a download task.

        Args:
            priority: Download priority (lower = higher priority)
            ekey: Encoding key for the content
            coro_factory: Callable that creates the download coroutine.
                          Called fresh on each retry attempt.
        """
        await self._queue.put(_QueueItem(priority=priority, ekey=ekey, coro_factory=coro_factory))

    async def run(self, total: int) -> AsyncIterator[DownloadResult]:
        """Process queued downloads concurrently, yielding results.

        Creates up to max_concurrency worker tasks that pull from the
        priority queue. Results are yielded as they complete.

        Args:
            total: Total number of items for progress tracking

        Yields:
            DownloadResult for each completed download
        """
        result_queue: asyncio.Queue[DownloadResult | None] = asyncio.Queue()
        self._completed = 0
        self._total_bytes = 0
        workers_done = 0
        num_workers = min(self.max_concurrency, total)

        async def worker() -> None:
            while True:
                try:
                    item = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                result = await self._execute_with_retry(item)
                self._completed += 1
                if result.data is not None:
                    self._total_bytes += len(result.data)

                if self._progress_callback:
                    self._progress_callback(self._completed, total, self._total_bytes)

                await result_queue.put(result)

            await result_queue.put(None)  # Signal worker done

        # Start workers
        for _ in range(num_workers):
            asyncio.ensure_future(worker())

        # Yield results as they arrive
        yielded = 0
        while workers_done < num_workers:
            result = await result_queue.get()
            if result is None:
                workers_done += 1
                continue
            yielded += 1
            yield result

    async def _execute_with_retry(self, item: _QueueItem) -> DownloadResult:
        """Execute a download with retry and backoff.

        Args:
            item: Queue item containing the download task

        Returns:
            DownloadResult with data on success or error on failure
        """
        last_error: str | None = None

        for attempt in range(1, self.max_retries + 1):
            async with self._global_semaphore:
                try:
                    result = await item.coro_factory()
                    if result.data is not None:
                        result.attempts = attempt
                        return result
                    last_error = result.error or "No data returned"
                except Exception as e:
                    last_error = str(e)
                    logger.debug(
                        "download_retry",
                        ekey=item.ekey.hex(),
                        attempt=attempt,
                        error=last_error,
                    )

            if attempt < self.max_retries:
                backoff = self.base_backoff * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)

        return DownloadResult(
            ekey=item.ekey,
            data=None,
            error=last_error,
            attempts=self.max_retries,
        )
