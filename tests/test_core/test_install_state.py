"""Tests for cascette_tools.core.install_state module."""

from pathlib import Path

from cascette_tools.core.install_state import (
    FileStatus,
    InstallState,
    PriorityStats,
)
from cascette_tools.formats.download import DownloadEntry


def _make_entry(ekey_byte: int, size: int = 100, priority: int = 0) -> DownloadEntry:
    """Create a DownloadEntry with a given ekey byte pattern."""
    return DownloadEntry(
        ekey=bytes([ekey_byte]) * 16,
        size=size,
        priority=priority,
    )


class TestFileStatus:
    """Test FileStatus enum values."""

    def test_values(self):
        assert FileStatus.pending.value == "pending"
        assert FileStatus.downloaded.value == "downloaded"
        assert FileStatus.failed.value == "failed"


class TestPriorityStats:
    """Test PriorityStats dataclass."""

    def test_defaults(self):
        stats = PriorityStats()
        assert stats.total == 0
        assert stats.completed == 0
        assert stats.failed == 0
        assert stats.bytes_total == 0
        assert stats.bytes_done == 0


class TestInstallState:
    """Test InstallState class."""

    def test_mark_downloaded(self, tmp_path: Path):
        """mark_downloaded records ekey and is_downloaded returns True."""
        state = InstallState(tmp_path, "abc123")
        ekey = b"\x01" * 16

        assert not state.is_downloaded(ekey)
        state.mark_downloaded(ekey, 500, priority=0)
        assert state.is_downloaded(ekey)

    def test_mark_failed(self, tmp_path: Path):
        """mark_failed records ekey in the failed set."""
        state = InstallState(tmp_path, "abc123")
        ekey = b"\x02" * 16

        state.mark_failed(ekey, priority=1)
        assert ekey.hex() in state.failed

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        """State survives a save/load cycle."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "hash123")
        state.priority_stats[0] = PriorityStats(total=10, bytes_total=5000)
        state.mark_downloaded(b"\x01" * 16, 100, priority=0)
        state.mark_downloaded(b"\x02" * 16, 200, priority=0)
        state.mark_failed(b"\x03" * 16, priority=0)
        state.save()

        loaded = InstallState.load(tmp_path, "hash123")
        assert loaded is not None
        assert loaded.build_config_hash == "hash123"
        assert loaded.is_downloaded(b"\x01" * 16)
        assert loaded.is_downloaded(b"\x02" * 16)
        assert (b"\x03" * 16).hex() in loaded.failed
        assert loaded.total_bytes_written == 300
        assert loaded.priority_stats[0].completed == 2
        assert loaded.priority_stats[0].failed == 1

    def test_atomic_write(self, tmp_path: Path):
        """After save, state file exists and no .tmp file remains."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "abc")
        state.save()

        assert state.state_file_path.exists()
        assert not state.state_file_path.with_suffix(".json.tmp").exists()

    def test_get_pending_entries(self, tmp_path: Path):
        """get_pending_entries filters out downloaded entries."""
        state = InstallState(tmp_path, "abc")
        entries = [
            _make_entry(0x01, size=100, priority=0),
            _make_entry(0x02, size=200, priority=0),
            _make_entry(0x03, size=300, priority=1),
        ]

        state.mark_downloaded(b"\x01" * 16, 100, priority=0)
        pending = state.get_pending_entries(entries)

        assert len(pending) == 2
        ekeys = [e.ekey for e in pending]
        assert b"\x01" * 16 not in ekeys
        assert b"\x02" * 16 in ekeys
        assert b"\x03" * 16 in ekeys

    def test_resume_with_matching_config(self, tmp_path: Path):
        """load succeeds when build_config_hash matches."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "match_hash")
        state.mark_downloaded(b"\xaa" * 16, 50, priority=0)
        state.save()

        loaded = InstallState.load(tmp_path, "match_hash")
        assert loaded is not None
        assert loaded.is_downloaded(b"\xaa" * 16)

    def test_resume_with_mismatched_config(self, tmp_path: Path):
        """load returns None when build_config_hash differs."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "old_hash")
        state.save()

        loaded = InstallState.load(tmp_path, "new_hash")
        assert loaded is None

    def test_priority_stats_tracking(self, tmp_path: Path):
        """Per-priority counters update on mark_downloaded/mark_failed."""
        state = InstallState(tmp_path, "abc")
        entries = [
            _make_entry(0x01, size=100, priority=0),
            _make_entry(0x02, size=200, priority=0),
            _make_entry(0x03, size=300, priority=1),
        ]
        state.init_priority_stats(entries)

        state.mark_downloaded(b"\x01" * 16, 100, priority=0)
        state.mark_failed(b"\x02" * 16, priority=0)
        state.mark_downloaded(b"\x03" * 16, 300, priority=1)

        summary = state.get_priority_summary()
        assert summary[0].total == 2
        assert summary[0].completed == 1
        assert summary[0].failed == 1
        assert summary[0].bytes_done == 100
        assert summary[1].total == 1
        assert summary[1].completed == 1
        assert summary[1].bytes_done == 300

    def test_load_nonexistent(self, tmp_path: Path):
        """load returns None when no state file exists."""
        loaded = InstallState.load(tmp_path)
        assert loaded is None

    def test_empty_state(self, tmp_path: Path):
        """A fresh state has no downloaded entries; all are pending."""
        state = InstallState(tmp_path, "abc")
        entries = [
            _make_entry(0x01),
            _make_entry(0x02),
        ]
        pending = state.get_pending_entries(entries)
        assert len(pending) == 2

    def test_cleanup_removes_state_file(self, tmp_path: Path):
        """cleanup removes the state file from disk."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "abc")
        state.save()
        assert state.state_file_path.exists()

        state.cleanup()
        assert not state.state_file_path.exists()

    def test_should_save_count_threshold(self, tmp_path: Path):
        """should_save returns True after SAVE_INTERVAL_COUNT marks."""
        state = InstallState(tmp_path, "abc")
        state.priority_stats[0] = PriorityStats(total=200, bytes_total=10000)

        for i in range(InstallState.SAVE_INTERVAL_COUNT - 1):
            state.mark_downloaded(bytes([i % 256]) * 16, 1, priority=0)
        # Not yet at threshold (monotonic time hasn't elapsed either)
        state._last_save_time = float("inf")  # Disable time-based trigger
        assert not state.should_save()

        state.mark_downloaded(b"\xff" * 16, 1, priority=0)
        assert state.should_save()

    def test_load_without_expected_hash(self, tmp_path: Path):
        """load with empty expected hash accepts any stored hash."""
        (tmp_path / "Data").mkdir(parents=True)
        state = InstallState(tmp_path, "any_hash")
        state.save()

        loaded = InstallState.load(tmp_path, "")
        assert loaded is not None
        assert loaded.build_config_hash == "any_hash"

    def test_mark_downloaded_clears_failed(self, tmp_path: Path):
        """If a previously-failed ekey succeeds, it moves from failed to downloaded."""
        state = InstallState(tmp_path, "abc")
        state.priority_stats[0] = PriorityStats(total=1, bytes_total=100)
        ekey = b"\x05" * 16

        state.mark_failed(ekey, priority=0)
        assert ekey.hex() in state.failed

        state.mark_downloaded(ekey, 100, priority=0)
        assert state.is_downloaded(ekey)
        assert ekey.hex() not in state.failed
