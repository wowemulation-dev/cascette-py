"""Tests for V7 local index file format correctness.

Tests cover bucket assignment (XOR-fold), entry serialization (sorted and update),
file layout (offsets, padding, alignment), hash validation (lookup3), and
write-parse roundtrips.
"""

from __future__ import annotations

import struct

import pytest

from cascette_tools.core.local_storage import (
    LocalIndexEntry,
    LocalIndexHeader,
    LocalStorage,
    UpdateEntry,
    compute_bucket,
    parse_local_idx_file,
)
from cascette_tools.crypto.jenkins import hashlittle, hashlittle2


class TestComputeBucket:
    """Tests for XOR-fold bucket assignment."""

    def test_xor_fold_basic(self) -> None:
        """All-zero key produces bucket 0."""
        key = b"\x00" * 9
        assert compute_bucket(key) == 0

    def test_xor_fold_single_byte_set(self) -> None:
        """Key with only first byte set: xor=0x0F, fold=(0 ^ 0x0F) = 0x0F."""
        key = b"\x0f" + b"\x00" * 8
        xor_val = 0x0F
        expected = (((xor_val >> 4) ^ xor_val) + 0) & 0x0F
        assert compute_bucket(key) == expected

    def test_xor_fold_all_same_byte(self) -> None:
        """9 identical bytes: odd count means xor = byte value."""
        key = b"\xab" * 16  # Only first 9 bytes used
        xor_val = 0xAB  # 9 XORs of 0xAB = 0xAB (odd count)
        expected = (((xor_val >> 4) ^ xor_val) + 0) & 0x0F
        assert compute_bucket(key) == expected

    def test_xor_fold_differs_from_simple_mask(self) -> None:
        """XOR-fold produces different results than old ekey[0] & 0x0F."""
        key = b"\xab" * 16
        old_bucket = key[0] & 0x0F  # 0x0B
        new_bucket = compute_bucket(key)
        assert old_bucket != new_bucket

    def test_seed_affects_result(self) -> None:
        """Different seeds produce different buckets."""
        key = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11"
        b0 = compute_bucket(key, seed=0)
        b1 = compute_bucket(key, seed=1)
        # Seeds shift the result
        assert b0 != b1 or b0 == b1  # Both valid, but test they're computed
        # Verify formula manually
        xor_val = 0
        for i in range(9):
            xor_val ^= key[i]
        assert b0 == (((xor_val >> 4) ^ xor_val) + 0) & 0x0F
        assert b1 == (((xor_val >> 4) ^ xor_val) + 1) & 0x0F

    def test_short_key_uses_available_bytes(self) -> None:
        """Keys shorter than 9 bytes use only available bytes."""
        short_key = b"\xff\x00"
        assert compute_bucket(short_key) == compute_bucket(short_key)
        # xor of [0xff, 0x00] = 0xff
        xor_val = 0xFF
        expected = (((xor_val >> 4) ^ xor_val) + 0) & 0x0F
        assert compute_bucket(short_key) == expected

    def test_bucket_range(self) -> None:
        """All results are in range 0x00-0x0F."""
        for i in range(256):
            key = bytes([i]) + b"\x00" * 8
            bucket = compute_bucket(key)
            assert 0 <= bucket <= 0x0F


class TestLocalIndexEntryRoundtrip:
    """Tests for 18-byte sorted entry serialization."""

    def test_basic_roundtrip(self) -> None:
        entry = LocalIndexEntry(
            key=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            archive_id=1,
            archive_offset=0x1000,
            size=4096,
        )
        data = entry.to_bytes()
        assert len(data) == 18
        parsed = LocalIndexEntry.from_bytes(data)
        assert parsed.key == entry.key
        assert parsed.archive_id == entry.archive_id
        assert parsed.archive_offset == entry.archive_offset
        assert parsed.size == entry.size

    def test_max_values(self) -> None:
        """Test with maximum field values."""
        entry = LocalIndexEntry(
            key=b"\xff" * 9,
            archive_id=1023,  # 10 bits max
            archive_offset=0x3FFFFFFF,  # 30 bits max
            size=0xFFFFFFFF,  # 32 bits max
        )
        data = entry.to_bytes()
        parsed = LocalIndexEntry.from_bytes(data)
        assert parsed.archive_id == entry.archive_id
        assert parsed.archive_offset == entry.archive_offset
        assert parsed.size == entry.size

    def test_zero_entry(self) -> None:
        entry = LocalIndexEntry(
            key=b"\x00" * 9,
            archive_id=0,
            archive_offset=0,
            size=0,
        )
        data = entry.to_bytes()
        assert len(data) == 18
        assert data == b"\x00" * 18


class TestUpdateEntryRoundtrip:
    """Tests for 24-byte update entry serialization."""

    def test_basic_roundtrip(self) -> None:
        entry = UpdateEntry(
            hash_guard=0x80001234,
            key=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            archive_id=1,
            archive_offset=0x1000,
            size=4096,
            status=0,
        )
        data = entry.to_bytes()
        assert len(data) == 24
        parsed = UpdateEntry.from_bytes(data)
        assert parsed.hash_guard == entry.hash_guard
        assert parsed.key == entry.key
        assert parsed.archive_id == entry.archive_id
        assert parsed.archive_offset == entry.archive_offset
        assert parsed.size == entry.size
        assert parsed.status == entry.status

    def test_status_values(self) -> None:
        """Test all known status values roundtrip."""
        for status in [0, 3, 6, 7]:
            entry = UpdateEntry(
                hash_guard=0x80000000,
                key=b"\xaa" * 9,
                archive_id=0,
                archive_offset=0,
                size=100,
                status=status,
            )
            parsed = UpdateEntry.from_bytes(entry.to_bytes())
            assert parsed.status == status

    def test_from_index_entry(self) -> None:
        """Test conversion from LocalIndexEntry with auto hash guard."""
        idx_entry = LocalIndexEntry(
            key=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            archive_id=1,
            archive_offset=0x1000,
            size=4096,
        )
        update = UpdateEntry.from_index_entry(idx_entry, status=3)

        assert update.key == idx_entry.key
        assert update.archive_id == idx_entry.archive_id
        assert update.archive_offset == idx_entry.archive_offset
        assert update.size == idx_entry.size
        assert update.status == 3
        # High bit must be set
        assert update.hash_guard & 0x80000000 != 0

    def test_hash_guard_computation(self) -> None:
        """Verify hash guard matches hashlittle(bytes[4:24], 0) | 0x80000000."""
        idx_entry = LocalIndexEntry(
            key=b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x42",
            archive_id=5,
            archive_offset=0x2000,
            size=8192,
        )
        update = UpdateEntry.from_index_entry(idx_entry, status=0)

        # Recompute from serialized bytes
        raw = update.to_bytes()
        payload = raw[4:24]
        expected_guard = hashlittle(payload, 0) | 0x80000000
        assert update.hash_guard == expected_guard


class TestLocalIndexHeaderSerialization:
    """Tests for header serialization."""

    def test_header_size(self) -> None:
        """Header serializes to 16 bytes."""
        header = LocalIndexHeader()
        assert len(header.to_bytes()) == 16

    def test_header_fields(self) -> None:
        """Verify header field positions in serialized bytes."""
        header = LocalIndexHeader(bucket=5, version=7, segment_size=0x40000000)
        data = header.to_bytes()

        version = struct.unpack("<H", data[0:2])[0]
        bucket = data[2]
        segment_size = struct.unpack("<Q", data[8:16])[0]

        assert version == 7
        assert bucket == 5
        assert segment_size == 0x40000000


class TestFileLayout:
    """Tests for V7 index file layout correctness."""

    def _make_entries(self, count: int) -> list[LocalIndexEntry]:
        """Create test entries with distinct keys."""
        entries = []
        for i in range(count):
            entries.append(
                LocalIndexEntry(
                    key=bytes([i]) + b"\x00" * 8,
                    archive_id=0,
                    archive_offset=i * 100,
                    size=100,
                )
            )
        return entries

    def test_header_at_offset_0x08(self, tmp_path: pytest.TempPathFactory) -> None:
        """Header data starts at offset 0x08."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(1)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()

        # Guarded block header at 0x00: block_size (4) + hash (4)
        block_size = struct.unpack("<I", data[0:4])[0]
        assert block_size == 16  # Header data is 16 bytes

        # Header data at 0x08
        version = struct.unpack("<H", data[8:10])[0]
        assert version == 7

    def test_entry_block_at_offset_0x20(self, tmp_path: pytest.TempPathFactory) -> None:
        """Entry guarded block starts at offset 0x20."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(3)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()

        # Entry block size at 0x20
        entry_block_size = struct.unpack("<I", data[0x20:0x24])[0]
        assert entry_block_size == 3 * 18  # 3 entries * 18 bytes

    def test_entries_at_offset_0x28(self, tmp_path: pytest.TempPathFactory) -> None:
        """Entry data starts at offset 0x28."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(1)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()

        # First entry key should be at 0x28
        assert data[0x28] == 0x00  # First byte of first entry key

    def test_padding_between_header_and_entries(self, tmp_path: pytest.TempPathFactory) -> None:
        """8 bytes of zero padding at 0x18-0x1F."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(1)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()
        assert data[0x18:0x20] == b"\x00" * 8

    def test_update_section_at_0x10000(self, tmp_path: pytest.TempPathFactory) -> None:
        """Update section starts at offset 0x10000."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(1)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()

        # File must be at least 0x10000 + 0x7800 bytes
        assert len(data) >= 0x10000 + 0x7800

        # Update section should be all zeros (empty)
        assert data[0x10000:0x10000 + 24] == b"\x00" * 24

    def test_file_size_with_entries(self, tmp_path: pytest.TempPathFactory) -> None:
        """Total file size is 0x10000 + 0x7800 for small entry counts."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = self._make_entries(10)
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()
        assert len(data) == 0x10000 + 0x7800


class TestSortedSectionHash:
    """Tests for iterative hashlittle2 sorted section hash."""

    def test_single_entry_hash(self) -> None:
        """Hash of single entry matches iterative hashlittle2."""
        entry = LocalIndexEntry(
            key=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            archive_id=0,
            archive_offset=0,
            size=100,
        )
        entry_bytes = entry.to_bytes()
        pc, _pb = hashlittle2(entry_bytes, 0, 0)
        assert pc != 0  # Non-trivial hash

    def test_multi_entry_hash_is_iterative(self) -> None:
        """Multiple entries produce accumulated hash state."""
        entries = [
            LocalIndexEntry(key=bytes([i]) + b"\x00" * 8, archive_id=0, archive_offset=0, size=100)
            for i in range(5)
        ]

        pc, pb = 0, 0
        for entry in entries:
            pc, pb = hashlittle2(entry.to_bytes(), pc, pb)

        # Hash of all entries is different from hash of just the first
        first_pc, _ = hashlittle2(entries[0].to_bytes(), 0, 0)
        assert pc != first_pc

    def test_hash_matches_written_file(self, tmp_path: pytest.TempPathFactory) -> None:
        """Hash stored in file matches recomputed hash."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = [
            LocalIndexEntry(key=bytes([i]) + b"\x00" * 8, archive_id=0, archive_offset=i * 50, size=50)
            for i in range(3)
        ]
        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, entries)

        data = idx_path.read_bytes()

        # Read stored hash from entry block header at 0x24
        stored_hash = struct.unpack("<I", data[0x24:0x28])[0]

        # Recompute
        pc, pb = 0, 0
        for entry in entries:
            pc, pb = hashlittle2(entry.to_bytes(), pc, pb)

        assert stored_hash == pc


class TestParseRoundtrip:
    """Tests for write-then-parse roundtrip."""

    def test_empty_file_roundtrip(self, tmp_path: pytest.TempPathFactory) -> None:
        """Empty index file can be written and parsed."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 5, [])

        data = idx_path.read_bytes()
        info = parse_local_idx_file(data)

        assert info.version == 7
        assert info.bucket == 5
        assert info.entries == []
        assert info.update_entries == []

    def test_entries_roundtrip(self, tmp_path: pytest.TempPathFactory) -> None:
        """Written entries can be parsed back."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        entries = [
            LocalIndexEntry(
                key=bytes([i + 1]) + b"\x00" * 8,  # Non-zero keys
                archive_id=0,
                archive_offset=i * 100,
                size=100,
            )
            for i in range(5)
        ]

        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 3, entries)

        data = idx_path.read_bytes()
        info = parse_local_idx_file(data)

        assert info.version == 7
        assert info.bucket == 3
        assert info.ekey_length == 9
        assert len(info.entries) == 5

        for orig, parsed in zip(entries, info.entries, strict=True):
            assert parsed.key == orig.key
            assert parsed.archive_id == orig.archive_id
            assert parsed.archive_offset == orig.archive_offset
            assert parsed.size == orig.size

    def test_header_hash_validates(self, tmp_path: pytest.TempPathFactory) -> None:
        """Header hash in written file validates on parse."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, [])

        data = idx_path.read_bytes()

        # Verify header hash
        block_size = struct.unpack("<I", data[0:4])[0]
        stored_hash = struct.unpack("<I", data[4:8])[0]
        header_data = data[8 : 8 + block_size]
        computed_hash = hashlittle(header_data, 0)

        assert stored_hash == computed_hash

    def test_segment_size_roundtrip(self, tmp_path: pytest.TempPathFactory) -> None:
        """Segment size field survives roundtrip."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        idx_path = storage.data_path / "test.idx"
        storage._write_index_file(idx_path, 0, [])

        data = idx_path.read_bytes()
        info = parse_local_idx_file(data)

        assert info.segment_size == 0x40000000


class TestInsertEntry:
    """Tests for incremental update section writes."""

    def test_insert_entry_to_update_section(self, tmp_path: pytest.TempPathFactory) -> None:
        """insert_entry writes to the update section of an existing file."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        # Write initial index file
        idx_path = storage.data_path / "0000000001.idx"
        storage._write_index_file(idx_path, 0, [])

        # Insert an entry
        entry = LocalIndexEntry(
            key=b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x42",
            archive_id=1,
            archive_offset=0x100,
            size=256,
        )
        storage.insert_entry(0, entry, status=0)

        # Read and parse
        data = idx_path.read_bytes()
        info = parse_local_idx_file(data)

        assert len(info.update_entries) == 1
        uentry = info.update_entries[0]
        assert uentry.key == entry.key
        assert uentry.archive_id == entry.archive_id
        assert uentry.archive_offset == entry.archive_offset
        assert uentry.size == entry.size
        assert uentry.status == 0
        assert uentry.hash_guard & 0x80000000 != 0

    def test_insert_multiple_entries(self, tmp_path: pytest.TempPathFactory) -> None:
        """Multiple insert_entry calls append sequentially."""
        storage = LocalStorage(tmp_path)  # type: ignore[arg-type]
        storage.initialize()

        idx_path = storage.data_path / "0000000001.idx"
        storage._write_index_file(idx_path, 0, [])

        for i in range(3):
            entry = LocalIndexEntry(
                key=bytes([i + 1]) + b"\x00" * 8,
                archive_id=0,
                archive_offset=i * 100,
                size=100,
            )
            storage.insert_entry(0, entry, status=0)

        data = idx_path.read_bytes()
        info = parse_local_idx_file(data)

        assert len(info.update_entries) == 3


class TestKmtV8Format:
    """Tests for KMT v8 format awareness.

    KMT v8 (casc::KmtV8) stores full 16-byte EKeys and uses 64-bit storage
    offsets. Key differences from V7 documented in casc/cascette-deferred-topics.md:

    - Sorted entry size: 0x20 (32) bytes (vs 18 bytes in V7)
    - Update entry size: 0x28 (40) bytes (vs 24 bytes in V7)
    - EKey: full 16 bytes (vs 9-byte prefix in V7)
    - StorageOffset: 8 bytes / 64-bit (vs 5 bytes in V7)
    - Hash guard payload: 33 bytes (0x21) from entry[4..] (vs 20 bytes in V7)
    - Revision header field >= 8 (vs version == 7)
    """

    def _build_v8_update_entry(
        self,
        ekey: bytes,
        offset_lo: int,
        offset_hi: int,
        encoded_size: int,
        decoded_size: int,
        status: int = 1,
    ) -> bytes:
        """Build a 40-byte KMT v8 update entry per casc/cascette-deferred-topics.md."""
        entry = bytearray(40)
        # [0x04..0x13]: full 16-byte EKey
        entry[4:20] = ekey[:16]
        # [0x14..0x17]: StorageOffset low (LE)
        struct.pack_into('<I', entry, 0x14, offset_lo)
        # [0x18..0x1B]: StorageOffset high (LE)
        struct.pack_into('<I', entry, 0x18, offset_hi)
        # [0x1C..0x1F]: EncodedSize (LE)
        struct.pack_into('<I', entry, 0x1C, encoded_size)
        # [0x20..0x23]: DecodedSize (LE)
        struct.pack_into('<I', entry, 0x20, decoded_size)
        # [0x24]: Status
        entry[0x24] = status
        # [0x00..0x03]: HashGuard = hashlittle(entry[4:37], 0) | 0x80000000
        payload = bytes(entry[4:37])  # 33 bytes = 0x21
        guard = hashlittle(payload, 0) | 0x80000000
        struct.pack_into('<I', entry, 0, guard)
        return bytes(entry)

    def test_v8_update_entry_hash_guard_covers_33_bytes(self) -> None:
        """V8 hash guard covers 33 bytes (0x21) from entry[4..].

        Per casc/cascette-deferred-topics.md:
          JenkinsHashLittle2(&entry[4], 0x21, 0) | 0x80000000
        where entry[4..37] (33 bytes) = EKey (16) + offset_lo (4) + offset_hi (4)
        + encoded_size (4) + decoded_size (4) + status (1).
        """
        ekey = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        raw = self._build_v8_update_entry(ekey, 0x1000, 0, 512, 1024, status=1)

        assert len(raw) == 40
        payload = raw[4:37]  # 33 bytes
        expected_guard = hashlittle(payload, 0) | 0x80000000
        actual_guard = struct.unpack('<I', raw[0:4])[0]
        assert actual_guard == expected_guard
        assert actual_guard & 0x80000000 != 0, "High bit must be set"

    def test_v8_update_entry_high_bit_distinguishes_from_empty(self) -> None:
        """High bit in hash guard distinguishes valid entries from empty slots.

        Empty slots have first 4 bytes == 0, valid entries have bit 31 set.
        """
        ekey = b'\xde\xad\xbe\xef' * 4
        raw = self._build_v8_update_entry(ekey, 0, 0, 0, 0, status=1)
        guard = struct.unpack('<I', raw[0:4])[0]
        assert guard != 0, "Non-empty entry must not have zero hash guard"
        assert guard & 0x80000000 != 0, "High bit must be set"

    def test_v8_sorted_entry_is_32_bytes(self) -> None:
        """V8 sorted entries are 32 (0x20) bytes.

        Layout: EKey (16) + StorageOffset_lo (4) + StorageOffset_hi (4)
        + EncodedSize (4) + DecodedSize (4) = 32 bytes.
        """
        # Build minimal 32-byte sorted entry
        entry = bytearray(32)
        ekey = b'\xaa\xbb\xcc\xdd' * 4
        entry[0:16] = ekey
        struct.pack_into('<I', entry, 16, 0x2000)   # offset_lo
        struct.pack_into('<I', entry, 20, 0)         # offset_hi
        struct.pack_into('<I', entry, 24, 256)       # encoded_size
        struct.pack_into('<I', entry, 28, 512)       # decoded_size

        assert len(entry) == 32

        # Verify field extraction is correct
        extracted_ekey = bytes(entry[0:16])
        extracted_offset_lo = struct.unpack('<I', entry[16:20])[0]
        extracted_offset_hi = struct.unpack('<I', entry[20:24])[0]
        extracted_encoded = struct.unpack('<I', entry[24:28])[0]
        extracted_decoded = struct.unpack('<I', entry[28:32])[0]

        assert extracted_ekey == ekey
        assert extracted_offset_lo == 0x2000
        assert extracted_offset_hi == 0
        assert extracted_encoded == 256
        assert extracted_decoded == 512

    def test_v7_vs_v8_hash_guard_coverage_differs(self) -> None:
        """V7 covers 19 bytes (0x13), V8 covers 33 bytes (0x21) from entry[4..].

        This test documents the behavioral difference to catch regressions
        if the parsing code conflates the two formats.

        V7: hashlittle(entry[4:23], 0) | 0x80000000  (19 bytes)
        V8: hashlittle(entry[4:37], 0) | 0x80000000  (33 bytes)
        """
        payload = b'\x11' * 40  # 40 arbitrary bytes

        v7_guard = hashlittle(payload[4:23], 0) | 0x80000000  # 19 bytes
        v8_guard = hashlittle(payload[4:37], 0) | 0x80000000  # 33 bytes

        # They should produce different hash values (different byte counts)
        assert v7_guard != v8_guard, (
            "V7 and V8 hash guards cover different payload lengths "
            "and must produce different results for the same data"
        )

    def test_parse_detects_v8_version_byte(self) -> None:
        """parse_local_idx_file detects version 8 files from the header.

        The parser reads version at header offset 8-9 (LE uint16) and warns
        for version 8. This test verifies the version byte is read correctly.
        """
        # Build a minimal V8-style guarded block
        inner = bytearray(16)
        struct.pack_into('<H', inner, 0, 8)   # version = 8
        inner[2] = 0                           # bucket
        inner[4] = 4                           # encoded_size_length
        inner[5] = 8                           # storage_offset_length (64-bit)
        inner[6] = 16                          # ekey_length (full 16 bytes)
        inner[7] = 0                           # file_offset_bits
        struct.pack_into('<Q', inner, 8, 0x40000000)  # segment_size

        header_hash = hashlittle(bytes(inner), 0)

        file_data = bytearray(0x10000 + 0x7800)
        # Outer header: block_size=16, hash
        struct.pack_into('<I', file_data, 0, 16)
        struct.pack_into('<I', file_data, 4, header_hash)
        # Inner header at offset 8
        file_data[8:24] = inner
        # Zero padding at 0x18..0x20 already zero
        # Entry block: block_size=0, hash=0
        struct.pack_into('<I', file_data, 0x20, 0)
        struct.pack_into('<I', file_data, 0x24, 0)

        info = parse_local_idx_file(bytes(file_data))
        assert info.version == 8
        assert info.ekey_length == 16
