"""Integration test exercising the Phase 1 pipeline end-to-end.

Simulates the install_poc.py flow:
1. CdnArchiveFetcher fetches data (mocked HTTP) with size verification
2. LocalStorage writes content with deduplication and CKey verification
3. Verifies the full chain works together
"""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cascette_tools.core.cdn_archive_fetcher import (
    ArchiveLocation,
    CdnArchiveFetcher,
)
from cascette_tools.core.integrity import IntegrityError
from cascette_tools.core.local_storage import LocalStorage


class TestPhase1Pipeline:
    """Test the fetch -> verify -> write -> deduplicate pipeline."""

    def _make_fetcher_with_entry(
        self, ekey: bytes, size: int
    ) -> CdnArchiveFetcher:
        fetcher = CdnArchiveFetcher(cdn_base="http://test.cdn", cdn_path="tpr/test")
        fetcher.index_map.entries[ekey[:16]] = ArchiveLocation(
            archive_hash="aabbccdd",
            offset=0,
            size=size,
        )
        return fetcher

    def _mock_client(self, content: bytes) -> MagicMock:
        response = MagicMock()
        response.status_code = 206
        response.content = content
        client = MagicMock()
        client.get.return_value = response
        return client

    def test_fetch_and_write_with_ckey_verification(self, tmp_path: Path):
        """Fetch data from CDN, verify size, write to storage with CKey check."""
        data = b"Hello, CASC world!"
        ekey = b"\xab" * 16
        ckey = hashlib.md5(data).digest()

        # Step 1: Fetch with size verification
        fetcher = self._make_fetcher_with_entry(ekey, size=len(data))
        client = self._mock_client(data)

        fetched = fetcher.fetch_file(client, ekey, decompress=False, verify=True)
        assert fetched is not None
        assert fetched == data

        # Step 2: Write to local storage with CKey verification
        storage = LocalStorage(tmp_path)
        storage.initialize()

        entry = storage.write_content(ekey, fetched, expected_ckey=ckey)
        assert entry.size == len(data)

        # Step 3: Verify data file was written
        data_file = storage.data_path / "data.000"
        assert data_file.exists()
        assert data_file.read_bytes() == data

    def test_fetch_size_mismatch_prevents_write(self, tmp_path: Path):
        """Size verification failure in fetcher prevents any write to storage."""
        data = b"truncated"
        ekey = b"\xab" * 16

        # Fetcher expects 1000 bytes but gets 9
        fetcher = self._make_fetcher_with_entry(ekey, size=1000)
        client = self._mock_client(data)

        fetched = fetcher.fetch_file(client, ekey, decompress=False, verify=True)
        assert fetched is None  # Rejected by size check

        # Storage never gets called in this case
        storage = LocalStorage(tmp_path)
        storage.initialize()
        assert len(storage.bucket_entries) == 16
        # All buckets empty
        total = sum(len(entries) for entries in storage.bucket_entries.values())
        assert total == 0

    def test_ckey_mismatch_prevents_write(self, tmp_path: Path):
        """CKey verification failure prevents data from being stored."""
        data = b"legitimate data"
        ekey = b"\xab" * 16
        wrong_ckey = b"\x00" * 16  # Does not match MD5 of data

        storage = LocalStorage(tmp_path)
        storage.initialize()

        with pytest.raises(IntegrityError, match="Content key mismatch"):
            storage.write_content(ekey, data, expected_ckey=wrong_ckey)

        # No data file should have been created (verification happens before write)
        data_file = storage.data_path / "data.000"
        assert not data_file.exists() or data_file.stat().st_size == 0

    def test_deduplication_across_multiple_writes(self, tmp_path: Path):
        """Same content written twice is deduplicated."""
        data = b"same content"
        ekey = b"\xab" * 16
        ckey = hashlib.md5(data).digest()

        storage = LocalStorage(tmp_path)
        storage.initialize()

        entry1 = storage.write_content(ekey, data, expected_ckey=ckey)
        entry2 = storage.write_content(ekey, data, expected_ckey=ckey)

        # Both return the same entry
        assert entry1.key == entry2.key
        assert entry1.archive_offset == entry2.archive_offset

        # Data file contains data only once
        data_file = storage.data_path / "data.000"
        assert data_file.stat().st_size == len(data)

    def test_different_content_not_deduplicated(self, tmp_path: Path):
        """Different content with different keys is written separately."""
        data1 = b"first file"
        data2 = b"second file"
        ekey1 = b"\xab" * 16
        ekey2 = b"\xcd" * 16

        storage = LocalStorage(tmp_path)
        storage.initialize()

        entry1 = storage.write_content(ekey1, data1)
        entry2 = storage.write_content(ekey2, data2)

        # Different offsets
        assert entry1.archive_offset != entry2.archive_offset

        # Data file contains both
        data_file = storage.data_path / "data.000"
        assert data_file.stat().st_size == len(data1) + len(data2)
