"""Shared memory control protocol for CASC multi-process coordination.

Implements the shmem control file (Data/data/shmem) used by Agent.exe to
coordinate multiple processes accessing the same CASC storage. Supports
protocol versions 4 (base) and 5 (exclusive access + PID tracking).

Reference: Agent.exe shmem_control_block.cpp, shmem_control.win32.cpp,
pid_tracking.cpp.

Layout uses DWORD-indexed fields (multiply index by 4 for byte offset):
  DWORD[0x42] (0x108): free space table format, must be 0x2AB8
  DWORD[0x43] (0x10C): data size, must be non-zero
  DWORD[0x44]-[0x53] (0x110-0x14F): 16 bucket generation numbers
  DWORD[0x54] (0x150): V5 exclusive access flags (bit 0=exclusive, bit 1=PID tracking)
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Shmem protocol constants
FREE_SPACE_TABLE_FORMAT = 0x2AB8
FREE_SPACE_TABLE_SIZE = 0x2AB8

# V4 layout sizes
V4_HEADER_SIZE = 0x150  # Up to (but not including) free space table
V4_TOTAL_SIZE = 0x2C10  # align16(0x150 + 0x2AB8) = 0x2C10

# V5 layout sizes
V5_BASE_HEADER_SIZE = 0x154  # V4 header + 4-byte exclusive flag
PID_TRACKING_SIZE = 0x228  # PID tracking region size
PID_TRACKING_MAX_SLOTS = 64  # Maximum tracked processes

# Offsets (byte)
OFF_VERSION = 0x00
OFF_INIT_FLAG = 0x02
OFF_PATH_LEN = 0x04
OFF_PATH_STR = 0x08
OFF_FREE_SPACE_FORMAT = 0x108
OFF_DATA_SIZE = 0x10C
OFF_GENERATIONS = 0x110  # 16 x uint32 LE (64 bytes)
OFF_EXCLUSIVE_FLAG = 0x150  # V5 only
OFF_PID_TRACKING = 0x154  # V5 with PID tracking only

# Lock file constants
LOCK_RETRY_COUNT = 10
LOCK_RETRY_DELAY_S = 1.0  # 10 seconds total (10 x 1s)


@dataclass
class PidSlot:
    """A single PID tracking slot."""

    pid: int = 0  # Process ID (0 = empty)
    mode: int = 0  # 1 = read-write, 2 = read-only


@dataclass
class PidTracking:
    """V5 PID tracking region (0x228 bytes).

    Tracks which processes have the CASC storage bound and in what mode.
    State machine: 1=idle, 2=modifying.
    """

    state: int = 1  # 1=idle, 2=modifying
    writer_count: int = 0
    total_count: int = 0
    last_modified_slot: int = 0
    generation: int = 0  # uint64, incremented on each add
    max_slots: int = PID_TRACKING_MAX_SLOTS
    slots: list[PidSlot] = field(default_factory=lambda: [PidSlot() for _ in range(PID_TRACKING_MAX_SLOTS)])

    def add_process(self, pid: int, mode: int = 1) -> int:
        """Register a process in the slot array.

        Args:
            pid: Process ID to register
            mode: Access mode (1=read-write, 2=read-only)

        Returns:
            Slot index, or -1 if no free slot
        """
        for i, slot in enumerate(self.slots):
            if slot.pid == 0:
                self.state = 2  # modifying
                slot.pid = pid
                slot.mode = mode
                self.last_modified_slot = i
                self.generation += 1
                self.total_count += 1
                if mode == 1:
                    self.writer_count += 1
                self.state = 1  # idle
                return i
        return -1

    def remove_process(self, pid: int) -> bool:
        """Remove a process from the slot array.

        Args:
            pid: Process ID to remove

        Returns:
            True if found and removed
        """
        for slot in self.slots:
            if slot.pid == pid:
                self.state = 2
                mode = slot.mode
                slot.pid = 0
                slot.mode = 0
                self.total_count = max(0, self.total_count - 1)
                if mode == 1:
                    self.writer_count = max(0, self.writer_count - 1)
                self.state = 1
                return True
        return False

    def recount(self) -> None:
        """Recount occupied slots. Called on startup if state==2 (crash recovery)."""
        self.state = 1  # Back to idle
        self.last_modified_slot = 0
        self.writer_count = 0
        self.total_count = 0
        for slot in self.slots:
            if slot.pid != 0:
                self.total_count += 1
                if slot.mode == 1:
                    self.writer_count += 1

    def to_bytes(self) -> bytes:
        """Serialize PID tracking region to 0x228 bytes."""
        buf = bytearray(PID_TRACKING_SIZE)
        struct.pack_into('<I', buf, 0x00, self.state)
        struct.pack_into('<I', buf, 0x04, self.writer_count)
        struct.pack_into('<I', buf, 0x08, self.total_count)
        struct.pack_into('<I', buf, 0x0C, self.last_modified_slot)
        struct.pack_into('<Q', buf, 0x10, self.generation)
        struct.pack_into('<I', buf, 0x18, self.max_slots)

        # PID array at +0x1C
        for i in range(self.max_slots):
            struct.pack_into('<I', buf, 0x1C + i * 4, self.slots[i].pid)

        # Mode array after PIDs
        modes_offset = 0x1C + self.max_slots * 4
        for i in range(self.max_slots):
            struct.pack_into('<I', buf, modes_offset + i * 4, self.slots[i].mode)

        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> PidTracking:
        """Parse PID tracking region from bytes."""
        if len(data) < 0x1C:
            raise ValueError(f"PID tracking data too short: {len(data)}")

        state = struct.unpack_from('<I', data, 0x00)[0]
        writer_count = struct.unpack_from('<I', data, 0x04)[0]
        total_count = struct.unpack_from('<I', data, 0x08)[0]
        last_modified_slot = struct.unpack_from('<I', data, 0x0C)[0]
        generation = struct.unpack_from('<Q', data, 0x10)[0]
        max_slots = struct.unpack_from('<I', data, 0x18)[0]

        slots: list[PidSlot] = []
        for i in range(min(max_slots, PID_TRACKING_MAX_SLOTS)):
            pid_off = 0x1C + i * 4
            mode_off = 0x1C + max_slots * 4 + i * 4
            pid = struct.unpack_from('<I', data, pid_off)[0] if pid_off + 4 <= len(data) else 0
            mode = struct.unpack_from('<I', data, mode_off)[0] if mode_off + 4 <= len(data) else 0
            slots.append(PidSlot(pid=pid, mode=mode))

        # Pad to max_slots
        while len(slots) < PID_TRACKING_MAX_SLOTS:
            slots.append(PidSlot())

        tracking = cls(
            state=state,
            writer_count=writer_count,
            total_count=total_count,
            last_modified_slot=last_modified_slot,
            generation=generation,
            max_slots=max_slots,
            slots=slots,
        )

        # Crash recovery: recount if state was 2 (modifying) at time of read
        if state == 2:
            logger.warning("PID tracking state=2 on read, running crash recovery recount")
            tracking.recount()

        return tracking


def _page_align(size: int, page_size: int = 4096) -> int:
    """Round up to next page boundary."""
    return (size + page_size - 1) & ~(page_size - 1)



@dataclass
class ShmemControl:
    """Shared memory control file for CASC multi-process coordination.

    Supports protocol versions 4 and 5.
    """

    version: int = 5
    initialized: bool = True
    path_string: str = ""
    data_size: int = 0x1000  # Must be non-zero
    generations: list[int] = field(default_factory=lambda: [1] * 16)
    exclusive_flag: int = 0  # V5 only: bit 0=exclusive, bit 1=PID tracking
    pid_tracking: PidTracking | None = None  # V5 only, when bit 1 set

    def __post_init__(self) -> None:
        if self.version == 5 and self.exclusive_flag & 0x02 and self.pid_tracking is None:
            self.pid_tracking = PidTracking()

    @property
    def has_pid_tracking(self) -> bool:
        """True if V5 with PID tracking enabled."""
        return self.version >= 5 and bool(self.exclusive_flag & 0x02)

    @property
    def is_exclusive(self) -> bool:
        """True if V5 with exclusive access flag set."""
        return self.version >= 5 and bool(self.exclusive_flag & 0x01)

    def total_size(self) -> int:
        """Compute total shmem file size for the current configuration."""
        if self.version <= 4:
            return V4_TOTAL_SIZE

        # V5: header + free space table, page-aligned
        header_size = V5_BASE_HEADER_SIZE
        if self.has_pid_tracking:
            header_size += PID_TRACKING_SIZE

        return _page_align(header_size + FREE_SPACE_TABLE_SIZE)

    def to_bytes(self) -> bytes:
        """Serialize shmem control block to bytes."""
        size = self.total_size()
        buf = bytearray(size)

        # Version (byte 0x00)
        buf[OFF_VERSION] = self.version & 0xFF

        # Initialization flag (byte 0x02, must be non-zero)
        buf[OFF_INIT_FLAG] = 1 if self.initialized else 0

        # Path string
        path_bytes = self.path_string.encode('utf-8')
        if path_bytes:
            struct.pack_into('<I', buf, OFF_PATH_LEN, len(path_bytes) + 1)
            end = min(OFF_PATH_STR + len(path_bytes), OFF_FREE_SPACE_FORMAT)
            buf[OFF_PATH_STR:end] = path_bytes[:end - OFF_PATH_STR]

        # Free space table format (DWORD[0x42])
        struct.pack_into('<I', buf, OFF_FREE_SPACE_FORMAT, FREE_SPACE_TABLE_FORMAT)

        # Data size (DWORD[0x43], must be non-zero)
        struct.pack_into('<I', buf, OFF_DATA_SIZE, self.data_size if self.data_size > 0 else 0x1000)

        # Generation numbers (DWORD[0x44]-[0x53])
        for i in range(16):
            struct.pack_into('<I', buf, OFF_GENERATIONS + i * 4, self.generations[i])

        # V5 exclusive access flag (DWORD[0x54])
        if self.version >= 5:
            struct.pack_into('<I', buf, OFF_EXCLUSIVE_FLAG, self.exclusive_flag)

            # PID tracking region
            if self.has_pid_tracking and self.pid_tracking is not None:
                pid_data = self.pid_tracking.to_bytes()
                buf[OFF_PID_TRACKING:OFF_PID_TRACKING + len(pid_data)] = pid_data

        # Free space table (all zeros = empty)
        # Table starts after the header region. Position depends on version.
        # The free space table is initialized as zeros (empty free space).

        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> ShmemControl:
        """Parse an existing shmem file with version auto-detection.

        Args:
            data: Raw shmem file bytes

        Returns:
            Parsed ShmemControl

        Raises:
            ValueError: If data is too short or version is unsupported
        """
        if len(data) < V4_HEADER_SIZE:
            raise ValueError(f"Shmem data too short: {len(data)} < {V4_HEADER_SIZE}")

        version = data[OFF_VERSION]
        if version < 4 or version > 5:
            raise ValueError(f"Unsupported shmem protocol version: {version}")

        initialized = data[OFF_INIT_FLAG] != 0

        # Path string
        path_len = struct.unpack_from('<I', data, OFF_PATH_LEN)[0]
        path_string = ""
        if path_len > 1 and OFF_PATH_STR + path_len - 1 <= len(data):
            path_bytes = data[OFF_PATH_STR:OFF_PATH_STR + path_len - 1]
            path_string = path_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

        # Validate free space format
        free_space_format = struct.unpack_from('<I', data, OFF_FREE_SPACE_FORMAT)[0]
        if free_space_format != FREE_SPACE_TABLE_FORMAT:
            logger.warning(
                "Unexpected free space table format",
                expected=f"{FREE_SPACE_TABLE_FORMAT:#06x}",
                actual=f"{free_space_format:#06x}",
            )

        data_size = struct.unpack_from('<I', data, OFF_DATA_SIZE)[0]

        if not initialized:
            logger.warning("Shmem initialization flag is zero")
        if data_size == 0:
            logger.warning("Shmem data size is zero")

        # Generation numbers
        generations: list[int] = []
        for i in range(16):
            gen = struct.unpack_from('<I', data, OFF_GENERATIONS + i * 4)[0]
            generations.append(gen)

        # V5 exclusive flag
        exclusive_flag = 0
        pid_tracking = None

        if version >= 5 and len(data) > OFF_EXCLUSIVE_FLAG + 4:
            exclusive_flag = struct.unpack_from('<I', data, OFF_EXCLUSIVE_FLAG)[0]

            if exclusive_flag & 0x02 and len(data) > OFF_PID_TRACKING + 0x1C:
                pid_data = data[OFF_PID_TRACKING:OFF_PID_TRACKING + PID_TRACKING_SIZE]
                pid_tracking = PidTracking.from_bytes(pid_data)

        return cls(
            version=version,
            initialized=initialized,
            path_string=path_string,
            data_size=data_size,
            generations=generations,
            exclusive_flag=exclusive_flag,
            pid_tracking=pid_tracking,
        )

    @classmethod
    def read(cls, path: Path) -> ShmemControl:
        """Read and parse a shmem file from disk.

        Args:
            path: Path to the shmem file

        Returns:
            Parsed ShmemControl

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If format is invalid
        """
        data = path.read_bytes()
        return cls.from_bytes(data)

    def write(self, path: Path) -> None:
        """Write shmem control block to disk.

        Args:
            path: Path to write the shmem file
        """
        path.write_bytes(self.to_bytes())
        logger.info(
            "Wrote shmem file",
            path=str(path),
            version=self.version,
            size=self.total_size(),
        )


class ShmemLock:
    """Lock file protocol for shmem mutual exclusion.

    Creates a .lock file adjacent to the shmem file. Uses file-based
    locking with retry and backoff matching Agent.exe behavior
    (10 retries with ~1 second delay).
    """

    def __init__(self, shmem_path: Path):
        self.lock_path = shmem_path.with_suffix('.lock')
        self._fd: int | None = None

    def acquire(self, timeout_s: float = 10.0) -> bool:
        """Acquire the lock file.

        Args:
            timeout_s: Maximum time to wait in seconds

        Returns:
            True if lock acquired, False if timed out
        """
        retries = LOCK_RETRY_COUNT
        delay = timeout_s / retries

        for attempt in range(retries):
            try:
                # O_CREAT | O_EXCL: atomic create-if-not-exists
                self._fd = os.open(
                    str(self.lock_path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o644,
                )
                logger.debug("Acquired shmem lock", path=str(self.lock_path))
                return True
            except FileExistsError:
                if attempt < retries - 1:
                    logger.debug(
                        "Shmem lock held, retrying",
                        attempt=attempt + 1,
                        max_retries=retries,
                    )
                    time.sleep(delay)

        logger.warning("Failed to acquire shmem lock after retries", path=str(self.lock_path))
        return False

    def release(self) -> None:
        """Release the lock file."""
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.lock_path.unlink(missing_ok=True)
            logger.debug("Released shmem lock", path=str(self.lock_path))
        except OSError as e:
            logger.warning("Failed to remove lock file", path=str(self.lock_path), error=str(e))

    def __enter__(self) -> ShmemLock:
        if not self.acquire():
            raise TimeoutError(f"Failed to acquire shmem lock: {self.lock_path}")
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
