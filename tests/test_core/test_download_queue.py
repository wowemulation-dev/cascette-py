"""Tests for cascette_tools.core.download_queue module."""

import asyncio
import time

from cascette_tools.core.download_queue import DownloadQueue, DownloadResult


class TestDownloadResult:
    """Test DownloadResult dataclass."""

    def test_success_result(self):
        """Test result with data."""
        result = DownloadResult(
            ekey=b"\x01" * 16,
            data=b"file content",
            source="abc123",
            attempts=1,
        )
        assert result.data == b"file content"
        assert result.error is None
        assert result.source == "abc123"
        assert result.attempts == 1

    def test_failure_result(self):
        """Test result without data."""
        result = DownloadResult(
            ekey=b"\x02" * 16,
            data=None,
            error="HTTP 404",
            source="loose",
            attempts=3,
        )
        assert result.data is None
        assert result.error == "HTTP 404"
        assert result.attempts == 3

    def test_defaults(self):
        """Test default field values."""
        result = DownloadResult(ekey=b"\x03" * 16, data=b"x")
        assert result.error is None
        assert result.source == ""
        assert result.attempts == 1


async def _make_ok_result(ekey: bytes, data: bytes) -> DownloadResult:
    """Helper to create a successful DownloadResult."""
    return DownloadResult(ekey=ekey, data=data)


class TestDownloadQueue:
    """Test DownloadQueue class."""

    def test_constructor_defaults(self):
        """Test default constructor values."""
        queue = DownloadQueue()
        assert queue.max_concurrency == 12
        assert queue.max_per_host == 3
        assert queue.max_retries == 3
        assert queue.base_backoff == 0.5

    def test_constructor_custom(self):
        """Test custom constructor values."""
        queue = DownloadQueue(
            max_concurrency=8,
            max_per_host=2,
            max_retries=5,
            base_backoff=1.0,
        )
        assert queue.max_concurrency == 8
        assert queue.max_per_host == 2
        assert queue.max_retries == 5
        assert queue.base_backoff == 1.0

    def test_get_host_semaphore_creates_lazily(self):
        """Test per-host semaphores are created on first access."""
        queue = DownloadQueue(max_per_host=3)
        sem = queue.get_host_semaphore("http://cdn.example.com/data/ab/cd/abcd.index")
        assert isinstance(sem, asyncio.Semaphore)
        # Same host returns same semaphore
        sem2 = queue.get_host_semaphore("http://cdn.example.com/other/path")
        assert sem is sem2

    def test_get_host_semaphore_different_hosts(self):
        """Test different hosts get different semaphores."""
        queue = DownloadQueue(max_per_host=3)
        sem1 = queue.get_host_semaphore("http://cdn1.example.com/path")
        sem2 = queue.get_host_semaphore("http://cdn2.example.com/path")
        assert sem1 is not sem2

    def test_priority_ordering(self):
        """Test that lower priority values are processed first."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=1, max_retries=1)
            results_order: list[int] = []

            async def make_result(pri: int) -> DownloadResult:
                results_order.append(pri)
                return DownloadResult(
                    ekey=bytes([pri]) * 16,
                    data=b"ok",
                    source="test",
                )

            # Submit in reverse priority order
            for pri in [30, 10, 20]:
                await queue.submit(
                    priority=pri,
                    ekey=bytes([pri]) * 16,
                    coro_factory=lambda p=pri: make_result(p),
                )

            results = []
            async for result in queue.run(total=3):
                results.append(result)

            assert len(results) == 3
            # With concurrency=1, priority order is guaranteed
            assert results_order == [10, 20, 30]

        asyncio.run(_run())

    def test_concurrency_limit(self):
        """Test that no more than max_concurrency tasks run at once."""
        async def _run() -> None:
            max_concurrent = 3
            queue = DownloadQueue(max_concurrency=max_concurrent, max_retries=1)
            active = 0
            max_active = 0
            lock = asyncio.Lock()

            async def make_result(idx: int) -> DownloadResult:
                nonlocal active, max_active
                async with lock:
                    active += 1
                    max_active = max(max_active, active)
                await asyncio.sleep(0.01)
                async with lock:
                    active -= 1
                return DownloadResult(ekey=bytes([idx]) * 16, data=b"ok")

            for i in range(10):
                await queue.submit(
                    priority=0,
                    ekey=bytes([i]) * 16,
                    coro_factory=lambda idx=i: make_result(idx),
                )

            results = []
            async for result in queue.run(total=10):
                results.append(result)

            assert len(results) == 10
            assert max_active <= max_concurrent

        asyncio.run(_run())

    def test_retry_on_failure(self):
        """Test retry with eventual success."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=1, max_retries=3, base_backoff=0.01)
            call_count = 0

            async def make_result() -> DownloadResult:
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    return DownloadResult(
                        ekey=b"\x01" * 16,
                        data=None,
                        error="transient error",
                    )
                return DownloadResult(ekey=b"\x01" * 16, data=b"success")

            await queue.submit(priority=0, ekey=b"\x01" * 16, coro_factory=make_result)

            results = []
            async for result in queue.run(total=1):
                results.append(result)

            assert len(results) == 1
            assert results[0].data == b"success"
            assert results[0].attempts == 3

        asyncio.run(_run())

    def test_retry_exhaustion(self):
        """Test that all retries exhausted returns failure."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=1, max_retries=2, base_backoff=0.01)

            async def always_fail() -> DownloadResult:
                return DownloadResult(
                    ekey=b"\x01" * 16,
                    data=None,
                    error="permanent error",
                )

            await queue.submit(priority=0, ekey=b"\x01" * 16, coro_factory=always_fail)

            results = []
            async for result in queue.run(total=1):
                results.append(result)

            assert len(results) == 1
            assert results[0].data is None
            assert results[0].error == "permanent error"
            assert results[0].attempts == 2

        asyncio.run(_run())

    def test_retry_exception_handling(self):
        """Test that exceptions during download are caught and retried."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=1, max_retries=3, base_backoff=0.01)
            call_count = 0

            async def raise_then_succeed() -> DownloadResult:
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise ConnectionError("connection reset")
                return DownloadResult(ekey=b"\x01" * 16, data=b"ok")

            await queue.submit(
                priority=0, ekey=b"\x01" * 16, coro_factory=raise_then_succeed
            )

            results = []
            async for result in queue.run(total=1):
                results.append(result)

            assert len(results) == 1
            assert results[0].data == b"ok"
            assert results[0].attempts == 3

        asyncio.run(_run())

    def test_progress_callback(self):
        """Test that progress callback is invoked for each completion."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=4, max_retries=1)
            callback_calls: list[tuple[int, int, int]] = []

            def on_progress(completed: int, total: int, bytes_downloaded: int) -> None:
                callback_calls.append((completed, total, bytes_downloaded))

            queue.progress_callback = on_progress

            for i in range(5):
                await queue.submit(
                    priority=0,
                    ekey=bytes([i]) * 16,
                    coro_factory=lambda: _make_ok_result(b"\x00" * 16, b"data"),
                )

            results = []
            async for result in queue.run(total=5):
                results.append(result)

            assert len(callback_calls) == 5
            # Last callback should have completed == 5, total == 5
            assert callback_calls[-1][0] == 5
            assert callback_calls[-1][1] == 5

        asyncio.run(_run())

    def test_exponential_backoff_timing(self):
        """Test that retry backoff increases exponentially."""
        async def _run() -> None:
            queue = DownloadQueue(
                max_concurrency=1, max_retries=3, base_backoff=0.05
            )
            timestamps: list[float] = []

            async def track_time() -> DownloadResult:
                timestamps.append(time.monotonic())
                return DownloadResult(ekey=b"\x01" * 16, data=None, error="fail")

            await queue.submit(priority=0, ekey=b"\x01" * 16, coro_factory=track_time)

            async for _ in queue.run(total=1):
                pass

            assert len(timestamps) == 3
            # First retry after ~0.05s, second after ~0.1s
            gap1 = timestamps[1] - timestamps[0]
            gap2 = timestamps[2] - timestamps[1]
            assert gap1 >= 0.04  # base_backoff * 2^0 = 0.05
            assert gap2 >= 0.08  # base_backoff * 2^1 = 0.10

        asyncio.run(_run())

    def test_empty_queue(self):
        """Test running with no items submitted."""
        async def _run() -> None:
            queue = DownloadQueue(max_concurrency=4)
            results = []
            async for result in queue.run(total=0):
                results.append(result)
            assert results == []

        asyncio.run(_run())
