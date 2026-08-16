"""Tests for integrity verification in local_storage module."""

import hashlib
from pathlib import Path

import pytest

from cascette_tools.core.integrity import IntegrityError
from cascette_tools.core.local_storage import (
    LOCAL_HEADER_SIZE,
    LocalStorage,
    compute_bucket,
)


class TestWriteContentDeduplication:
    """Test write_content deduplication behavior."""

    def test_duplicate_write_skipped(self, tmp_path: Path):
        """Test that writing the same key+size twice skips the second write."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data = b"hello world"

        entry1 = storage.write_content(ekey, data)
        entry2 = storage.write_content(ekey, data)

        # Second write should return the same entry
        assert entry1.key == entry2.key
        assert entry1.archive_id == entry2.archive_id
        assert entry1.archive_offset == entry2.archive_offset
        assert entry1.size == entry2.size

        # Only one real entry should exist in bucket (plus 16 segment
        # reconstruction-header entries indexed in the KMT, one per seed-1
        # bucket, added when the first data file is created).
        bucket = compute_bucket(ekey)
        real_entries = [
            e for e in storage.bucket_entries[bucket] if e.size != LOCAL_HEADER_SIZE
        ]
        assert len(real_entries) == 1

        # The reconstruction entries are present in their seed-1 buckets.
        from cascette_tools.core.local_storage import compute_bucket as cb

        recon_total = 0
        for b, entries in storage.bucket_entries.items():
            for e in entries:
                if e.size == LOCAL_HEADER_SIZE:
                    recon_total += 1
                    assert cb(e.key, seed=1) == b, "recon key in wrong bucket"
        assert recon_total == 16

    def test_different_size_not_deduplicated(self, tmp_path: Path):
        """Test that same key with different size writes both."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data1 = b"hello"
        data2 = b"hello world extended"

        storage.write_content(ekey, data1)
        storage.write_content(ekey, data2)

        # Both entries should exist (different sizes); the bucket also holds
        # its segment reconstruction-header entry (size 30).
        bucket = compute_bucket(ekey)
        real_entries = [
            e for e in storage.bucket_entries[bucket] if e.size != LOCAL_HEADER_SIZE
        ]
        assert len(real_entries) == 2

    def test_different_keys_not_deduplicated(self, tmp_path: Path):
        """Test that different keys with same data are both written."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey1 = b"\xab" * 16
        ekey2 = b"\xcd" * 16
        data = b"same data"

        storage.write_content(ekey1, data)
        storage.write_content(ekey2, data)

        # Both should be written (different keys). Total = 16 segment
        # reconstruction entries + 2 real file entries.
        total = sum(len(entries) for entries in storage.bucket_entries.values())
        assert total == 18


class TestWriteContentVerification:
    """Test write_content integrity verification."""

    def test_correct_ckey_passes(self, tmp_path: Path):
        """Test that correct content key passes verification."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data = b"hello world"
        ckey = hashlib.md5(data).digest()

        entry = storage.write_content(ekey, data, expected_ckey=ckey)
        assert entry.size == LOCAL_HEADER_SIZE + len(data)

    def test_wrong_ckey_raises(self, tmp_path: Path):
        """Test that wrong content key raises IntegrityError."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data = b"hello world"
        wrong_ckey = b"\x00" * 16

        with pytest.raises(IntegrityError) as exc_info:
            storage.write_content(ekey, data, expected_ckey=wrong_ckey)

        assert "Content key mismatch" in str(exc_info.value)

    def test_no_ckey_skips_verification(self, tmp_path: Path):
        """Test that omitting expected_ckey skips verification."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data = b"hello world"

        # Should not raise even without verification
        entry = storage.write_content(ekey, data)
        assert entry.size == LOCAL_HEADER_SIZE + len(data)

    def test_failed_verification_does_not_write(self, tmp_path: Path):
        """Test that failed verification prevents data from being written."""
        storage = LocalStorage(tmp_path)
        storage.initialize()

        ekey = b"\xab" * 16
        data = b"hello world"
        wrong_ckey = b"\x00" * 16

        with pytest.raises(IntegrityError):
            storage.write_content(ekey, data, expected_ckey=wrong_ckey)

        # No entries should exist
        bucket = compute_bucket(ekey)
        assert len(storage.bucket_entries[bucket]) == 0

        # Data file should not have been written
        data_file = storage.data_path / "data.000"
        assert not data_file.exists() or data_file.stat().st_size == 0
