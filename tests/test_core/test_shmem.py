"""Tests for shmem control protocol V4 and V5."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from cascette_tools.core.shmem import (
    FREE_SPACE_TABLE_FORMAT,
    OFF_DATA_SIZE,
    OFF_EXCLUSIVE_FLAG,
    OFF_FREE_SPACE_FORMAT,
    OFF_GENERATIONS,
    OFF_INIT_FLAG,
    OFF_PID_TRACKING,
    OFF_VERSION,
    PID_TRACKING_SIZE,
    V4_TOTAL_SIZE,
    PidTracking,
    ShmemControl,
    ShmemLock,
)


class TestShmemV4WriteRead:
    """Tests for V4 protocol write/read roundtrip."""

    def test_v4_total_size(self) -> None:
        shmem = ShmemControl(version=4)
        assert shmem.total_size() == V4_TOTAL_SIZE

    def test_v4_roundtrip(self) -> None:
        shmem = ShmemControl(
            version=4,
            initialized=True,
            path_string="Global\\C:\\Games\\WoW\\Data\\data",
            data_size=0x2000,
            generations=[i + 1 for i in range(16)],
        )
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)

        assert parsed.version == 4
        assert parsed.initialized is True
        assert parsed.path_string == "Global\\C:\\Games\\WoW\\Data\\data"
        assert parsed.data_size == 0x2000
        assert parsed.generations == [i + 1 for i in range(16)]

    def test_v4_version_byte(self) -> None:
        shmem = ShmemControl(version=4)
        data = shmem.to_bytes()
        assert data[OFF_VERSION] == 4

    def test_v4_init_flag(self) -> None:
        shmem = ShmemControl(version=4, initialized=True)
        data = shmem.to_bytes()
        assert data[OFF_INIT_FLAG] != 0

    def test_v4_free_space_format(self) -> None:
        shmem = ShmemControl(version=4)
        data = shmem.to_bytes()
        fmt = struct.unpack_from('<I', data, OFF_FREE_SPACE_FORMAT)[0]
        assert fmt == FREE_SPACE_TABLE_FORMAT

    def test_v4_data_size_nonzero(self) -> None:
        shmem = ShmemControl(version=4, data_size=0)
        data = shmem.to_bytes()
        ds = struct.unpack_from('<I', data, OFF_DATA_SIZE)[0]
        assert ds > 0  # Forced to 0x1000 when 0

    def test_v4_generation_numbers(self) -> None:
        gens = [10, 20, 30, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5]
        shmem = ShmemControl(version=4, generations=gens)
        data = shmem.to_bytes()

        for i in range(16):
            val = struct.unpack_from('<I', data, OFF_GENERATIONS + i * 4)[0]
            assert val == gens[i]

    def test_v4_no_exclusive_flag(self) -> None:
        """V4 should not have exclusive flag at offset 0x150."""
        shmem = ShmemControl(version=4)
        data = shmem.to_bytes()
        # In V4, offset 0x150 is the start of the free space table (should be zeros)
        val = struct.unpack_from('<I', data, OFF_EXCLUSIVE_FLAG)[0]
        assert val == 0


class TestShmemV5WriteRead:
    """Tests for V5 protocol write/read roundtrip."""

    def test_v5_roundtrip(self) -> None:
        shmem = ShmemControl(
            version=5,
            initialized=True,
            path_string="Global\\D:\\WoW\\Data\\data",
            data_size=0x5000,
            generations=[3] * 16,
            exclusive_flag=0,
        )
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)

        assert parsed.version == 5
        assert parsed.data_size == 0x5000
        assert parsed.generations == [3] * 16
        assert parsed.exclusive_flag == 0

    def test_v5_version_byte(self) -> None:
        shmem = ShmemControl(version=5)
        data = shmem.to_bytes()
        assert data[OFF_VERSION] == 5

    def test_v5_exclusive_flag(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x01)
        data = shmem.to_bytes()
        flag = struct.unpack_from('<I', data, OFF_EXCLUSIVE_FLAG)[0]
        assert flag == 0x01
        assert shmem.is_exclusive

    def test_v5_not_exclusive(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x00)
        assert not shmem.is_exclusive

    def test_v5_total_size_no_pid(self) -> None:
        """V5 without PID tracking uses page-aligned size."""
        shmem = ShmemControl(version=5, exclusive_flag=0x00)
        size = shmem.total_size()
        assert size % 4096 == 0
        assert size > V4_TOTAL_SIZE

    def test_v5_total_size_with_pid(self) -> None:
        """V5 with PID tracking is larger."""
        shmem_no_pid = ShmemControl(version=5, exclusive_flag=0x00)
        shmem_pid = ShmemControl(version=5, exclusive_flag=0x02)
        assert shmem_pid.total_size() >= shmem_no_pid.total_size()

    def test_v5_generation_numbers(self) -> None:
        """V5 preserves generation numbers same as V4."""
        gens = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
        shmem = ShmemControl(version=5, generations=gens)
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)
        assert parsed.generations == gens


class TestVersionAutoDetection:
    """Tests for protocol version auto-detection."""

    def test_detect_v4(self) -> None:
        shmem = ShmemControl(version=4)
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)
        assert parsed.version == 4

    def test_detect_v5(self) -> None:
        shmem = ShmemControl(version=5)
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)
        assert parsed.version == 5

    def test_reject_v3(self) -> None:
        data = bytearray(V4_TOTAL_SIZE)
        data[OFF_VERSION] = 3
        with pytest.raises(ValueError, match="Unsupported shmem protocol version"):
            ShmemControl.from_bytes(bytes(data))

    def test_reject_v6(self) -> None:
        data = bytearray(V4_TOTAL_SIZE)
        data[OFF_VERSION] = 6
        with pytest.raises(ValueError, match="Unsupported shmem protocol version"):
            ShmemControl.from_bytes(bytes(data))

    def test_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            ShmemControl.from_bytes(b"\x04" * 10)


class TestPidTracking:
    """Tests for V5 PID tracking."""

    def test_add_process(self) -> None:
        tracking = PidTracking()
        slot = tracking.add_process(1234, mode=1)
        assert slot >= 0
        assert tracking.total_count == 1
        assert tracking.writer_count == 1
        assert tracking.slots[slot].pid == 1234
        assert tracking.slots[slot].mode == 1

    def test_add_readonly(self) -> None:
        tracking = PidTracking()
        tracking.add_process(5678, mode=2)
        assert tracking.total_count == 1
        assert tracking.writer_count == 0  # Read-only doesn't count as writer

    def test_remove_process(self) -> None:
        tracking = PidTracking()
        tracking.add_process(1234, mode=1)
        assert tracking.remove_process(1234)
        assert tracking.total_count == 0
        assert tracking.writer_count == 0

    def test_remove_nonexistent(self) -> None:
        tracking = PidTracking()
        assert not tracking.remove_process(9999)

    def test_multiple_processes(self) -> None:
        tracking = PidTracking()
        tracking.add_process(100, mode=1)
        tracking.add_process(200, mode=2)
        tracking.add_process(300, mode=1)
        assert tracking.total_count == 3
        assert tracking.writer_count == 2

    def test_generation_increments(self) -> None:
        tracking = PidTracking()
        tracking.add_process(100, mode=1)
        assert tracking.generation == 1
        tracking.add_process(200, mode=1)
        assert tracking.generation == 2

    def test_recount(self) -> None:
        tracking = PidTracking()
        tracking.add_process(100, mode=1)
        tracking.add_process(200, mode=2)
        # Corrupt counts
        tracking.writer_count = 99
        tracking.total_count = 99
        tracking.recount()
        assert tracking.total_count == 2
        assert tracking.writer_count == 1

    def test_pid_tracking_roundtrip(self) -> None:
        tracking = PidTracking()
        tracking.add_process(1234, mode=1)
        tracking.add_process(5678, mode=2)
        data = tracking.to_bytes()
        assert len(data) == PID_TRACKING_SIZE

        parsed = PidTracking.from_bytes(data)
        assert parsed.total_count == 2
        assert parsed.writer_count == 1
        assert parsed.generation == 2
        # Find the PIDs in slots
        pids = [s.pid for s in parsed.slots if s.pid != 0]
        assert 1234 in pids
        assert 5678 in pids

    def test_v4_has_no_pid_tracking(self) -> None:
        shmem = ShmemControl(version=4)
        assert not shmem.has_pid_tracking
        assert shmem.pid_tracking is None

    def test_v5_with_pid_flag(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x02)
        assert shmem.has_pid_tracking
        assert shmem.pid_tracking is not None

    def test_v5_pid_tracking_roundtrip(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x02)
        assert shmem.pid_tracking is not None
        shmem.pid_tracking.add_process(42, mode=1)

        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)

        assert parsed.has_pid_tracking
        assert parsed.pid_tracking is not None
        assert parsed.pid_tracking.total_count == 1
        pids = [s.pid for s in parsed.pid_tracking.slots if s.pid != 0]
        assert 42 in pids

    def test_crash_recovery_recount(self) -> None:
        """State=2 on read triggers automatic recount."""
        tracking = PidTracking()
        tracking.add_process(100, mode=1)
        tracking.state = 2  # Simulate crash during modification

        data = tracking.to_bytes()
        parsed = PidTracking.from_bytes(data)

        # After crash recovery, state should be back to idle
        assert parsed.state == 1
        assert parsed.total_count == 1
        assert parsed.writer_count == 1
        assert parsed.last_modified_slot == 0  # Cleared by recount


class TestShmemFileIO:
    """Tests for file read/write operations."""

    def test_write_and_read(self, tmp_path: Path) -> None:
        shmem_path = tmp_path / "shmem"
        shmem = ShmemControl(
            version=5,
            path_string="Global\\test",
            data_size=0x3000,
            generations=[2] * 16,
        )
        shmem.write(shmem_path)

        parsed = ShmemControl.read(shmem_path)
        assert parsed.version == 5
        assert parsed.data_size == 0x3000
        assert parsed.generations == [2] * 16

    def test_read_nonexistent(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ShmemControl.read(tmp_path / "nonexistent")


class TestShmemLock:
    """Tests for lock file protocol."""

    def test_acquire_and_release(self, tmp_path: Path) -> None:
        shmem_path = tmp_path / "shmem"
        lock = ShmemLock(shmem_path)

        assert lock.acquire()
        assert lock.lock_path.exists()
        lock.release()
        assert not lock.lock_path.exists()

    def test_context_manager(self, tmp_path: Path) -> None:
        shmem_path = tmp_path / "shmem"
        with ShmemLock(shmem_path) as lock:
            assert lock.lock_path.exists()
        assert not lock.lock_path.exists()

    def test_double_acquire_fails(self, tmp_path: Path) -> None:
        shmem_path = tmp_path / "shmem"
        lock1 = ShmemLock(shmem_path)
        assert lock1.acquire()

        # Second acquire should fail (lock file exists)
        lock2 = ShmemLock(shmem_path)
        assert not lock2.acquire(timeout_s=0.1)  # Short timeout

        lock1.release()

    def test_lock_after_release(self, tmp_path: Path) -> None:
        shmem_path = tmp_path / "shmem"
        lock1 = ShmemLock(shmem_path)
        lock1.acquire()
        lock1.release()

        lock2 = ShmemLock(shmem_path)
        assert lock2.acquire()
        lock2.release()


class TestExclusiveAccess:
    """Tests for V5 exclusive access flag behavior."""

    def test_exclusive_flag_roundtrip(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x01)
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)
        assert parsed.is_exclusive
        assert parsed.exclusive_flag == 0x01

    def test_pid_tracking_flag(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x02)
        data = shmem.to_bytes()
        parsed = ShmemControl.from_bytes(data)
        assert parsed.has_pid_tracking
        assert not parsed.is_exclusive

    def test_both_flags(self) -> None:
        shmem = ShmemControl(version=5, exclusive_flag=0x03)
        assert shmem.is_exclusive
        assert shmem.has_pid_tracking

    def test_v4_no_exclusive(self) -> None:
        shmem = ShmemControl(version=4)
        assert not shmem.is_exclusive
        assert not shmem.has_pid_tracking

    def test_v5_pid_region_offset(self) -> None:
        """PID tracking data is written at offset 0x154 in V5."""
        shmem = ShmemControl(version=5, exclusive_flag=0x02)
        assert shmem.pid_tracking is not None
        shmem.pid_tracking.add_process(9999, mode=1)

        data = shmem.to_bytes()
        # State should be at OFF_PID_TRACKING (0x154)
        state = struct.unpack_from('<I', data, OFF_PID_TRACKING)[0]
        assert state == 1  # idle
