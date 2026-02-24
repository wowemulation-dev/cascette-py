"""Persistent installation state for download resume.

Tracks which files have been downloaded so that interrupted installations
can resume without re-downloading completed files. State is persisted as
JSON using atomic writes (temp file + os.replace) to prevent corruption.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cascette_tools.formats.download import DownloadEntry


class FileStatus(Enum):
    """Status of an individual file in the install process."""

    pending = "pending"
    downloaded = "downloaded"
    failed = "failed"


@dataclass
class PriorityStats:
    """Per-priority download statistics."""

    total: int = 0
    completed: int = 0
    failed: int = 0
    bytes_total: int = 0
    bytes_done: int = 0


class InstallState:
    """Persistent download state for resumable installations.

    Stores which encoding keys have been downloaded or failed,
    along with per-priority statistics. State is saved to a JSON file
    using atomic writes to prevent corruption on interruption.

    Args:
        install_path: Root installation directory
        build_config_hash: Hash identifying the build configuration
    """

    STATE_FILENAME = ".install_state.json"
    SAVE_INTERVAL_COUNT = 100
    SAVE_INTERVAL_SECONDS = 30.0

    def __init__(self, install_path: Path, build_config_hash: str = "") -> None:
        self.install_path = install_path
        self.build_config_hash = build_config_hash
        self.downloaded: set[str] = set()
        self.failed: set[str] = set()
        self.priority_stats: dict[int, PriorityStats] = {}
        self.total_bytes_written: int = 0

        self._unsaved_count: int = 0
        self._last_save_time: float = time.monotonic()

    @property
    def state_file_path(self) -> Path:
        """Path to the state file."""
        return self.install_path / "Data" / self.STATE_FILENAME

    def init_priority_stats(self, entries: list[DownloadEntry]) -> None:
        """Initialize per-priority counters from the full entry list.

        Args:
            entries: All download entries (before filtering)
        """
        self.priority_stats.clear()
        for entry in entries:
            if entry.priority not in self.priority_stats:
                self.priority_stats[entry.priority] = PriorityStats()
            stats = self.priority_stats[entry.priority]
            stats.total += 1
            stats.bytes_total += entry.size

    def mark_downloaded(self, ekey: bytes, size: int, priority: int) -> None:
        """Record a file as downloaded.

        Args:
            ekey: Encoding key of the downloaded file
            size: Size of the downloaded data in bytes
            priority: Download priority of the entry
        """
        hex_key = ekey.hex()
        self.downloaded.add(hex_key)
        self.failed.discard(hex_key)
        self.total_bytes_written += size

        if priority in self.priority_stats:
            self.priority_stats[priority].completed += 1
            self.priority_stats[priority].bytes_done += size

        self._unsaved_count += 1

    def mark_failed(self, ekey: bytes, priority: int) -> None:
        """Record a file as permanently failed.

        Args:
            ekey: Encoding key of the failed file
            priority: Download priority of the entry
        """
        hex_key = ekey.hex()
        self.failed.add(hex_key)

        if priority in self.priority_stats:
            self.priority_stats[priority].failed += 1

        self._unsaved_count += 1

    def is_downloaded(self, ekey: bytes) -> bool:
        """Check if a file has already been downloaded.

        Args:
            ekey: Encoding key to check

        Returns:
            True if the file was previously downloaded
        """
        return ekey.hex() in self.downloaded

    def get_pending_entries(
        self, entries: list[DownloadEntry]
    ) -> list[DownloadEntry]:
        """Filter out already-downloaded entries.

        Args:
            entries: List of download entries to filter

        Returns:
            Entries that have not been downloaded yet
        """
        return [e for e in entries if e.ekey.hex() not in self.downloaded]

    def get_priority_summary(self) -> dict[int, PriorityStats]:
        """Get per-priority statistics.

        Returns:
            Dict mapping priority level to its stats
        """
        return dict(self.priority_stats)

    def should_save(self) -> bool:
        """Check if state should be persisted based on count/time thresholds."""
        if self._unsaved_count >= self.SAVE_INTERVAL_COUNT:
            return True
        elapsed = time.monotonic() - self._last_save_time
        return elapsed >= self.SAVE_INTERVAL_SECONDS

    def save(self) -> None:
        """Persist state to disk using atomic write.

        Writes to a temporary file first, then atomically replaces
        the target file. This prevents corruption if the process is
        killed during the write.
        """
        state_path = self.state_file_path
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = state_path.with_suffix(".json.tmp")

        data = {
            "build_config_hash": self.build_config_hash,
            "downloaded": sorted(self.downloaded),
            "failed": sorted(self.failed),
            "priority_stats": {
                str(k): {
                    "total": v.total,
                    "completed": v.completed,
                    "failed": v.failed,
                    "bytes_total": v.bytes_total,
                    "bytes_done": v.bytes_done,
                }
                for k, v in self.priority_stats.items()
            },
            "total_bytes_written": self.total_bytes_written,
        }

        tmp_path.write_text(json.dumps(data, separators=(",", ":")))
        os.replace(tmp_path, state_path)

        self._unsaved_count = 0
        self._last_save_time = time.monotonic()

    @classmethod
    def load(
        cls, install_path: Path, expected_build_config_hash: str = ""
    ) -> InstallState | None:
        """Load state from disk.

        Args:
            install_path: Root installation directory
            expected_build_config_hash: If non-empty, the loaded state must
                match this hash. Returns None on mismatch.

        Returns:
            Loaded InstallState, or None if no state file exists or
            the build config hash does not match.
        """
        state_path = install_path / "Data" / cls.STATE_FILENAME

        if not state_path.exists():
            return None

        try:
            raw = json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

        stored_hash = raw.get("build_config_hash", "")

        if expected_build_config_hash and stored_hash != expected_build_config_hash:
            return None

        state = cls(install_path, build_config_hash=stored_hash)
        state.downloaded = set(raw.get("downloaded", []))
        state.failed = set(raw.get("failed", []))
        state.total_bytes_written = raw.get("total_bytes_written", 0)

        for k, v in raw.get("priority_stats", {}).items():
            state.priority_stats[int(k)] = PriorityStats(
                total=v.get("total", 0),
                completed=v.get("completed", 0),
                failed=v.get("failed", 0),
                bytes_total=v.get("bytes_total", 0),
                bytes_done=v.get("bytes_done", 0),
            )

        return state

    def cleanup(self) -> None:
        """Remove the state file after a completed installation."""
        state_path = self.state_file_path
        if state_path.exists():
            state_path.unlink()
