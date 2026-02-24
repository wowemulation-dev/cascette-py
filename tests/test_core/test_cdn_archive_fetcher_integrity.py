"""Integration tests for integrity verification in CdnArchiveFetcher."""

from unittest.mock import MagicMock

from cascette_tools.core.cdn_archive_fetcher import (
    ArchiveLocation,
    CdnArchiveFetcher,
)


class TestFetchFileVerification:
    """Test fetch_file size verification against index entries."""

    def _make_fetcher_with_entry(
        self, ekey: bytes, archive_hash: str, offset: int, size: int
    ) -> CdnArchiveFetcher:
        """Create a fetcher with a single index entry pre-loaded."""
        fetcher = CdnArchiveFetcher(cdn_base="http://test.cdn", cdn_path="tpr/test")
        fetcher.index_map.entries[ekey[:16]] = ArchiveLocation(
            archive_hash=archive_hash,
            offset=offset,
            size=size,
        )
        return fetcher

    def _mock_client(self, content: bytes, status_code: int = 206) -> MagicMock:
        """Create a mock httpx.Client that returns given content."""
        response = MagicMock()
        response.status_code = status_code
        response.content = content
        client = MagicMock()
        client.get.return_value = response
        return client

    def test_fetch_file_correct_size_returns_data(self):
        """Data whose length matches index entry size is returned."""
        ekey = b"\xab" * 16
        data = b"hello world"  # 11 bytes

        fetcher = self._make_fetcher_with_entry(ekey, "aabb", offset=0, size=11)
        client = self._mock_client(data)

        result = fetcher.fetch_file(client, ekey, decompress=False, verify=True)
        assert result == data

    def test_fetch_file_wrong_size_returns_none(self):
        """Data whose length differs from index entry is rejected."""
        ekey = b"\xab" * 16
        data = b"short"  # 5 bytes, but index says 100

        fetcher = self._make_fetcher_with_entry(ekey, "aabb", offset=0, size=100)
        client = self._mock_client(data)

        result = fetcher.fetch_file(client, ekey, decompress=False, verify=True)
        assert result is None

    def test_fetch_file_verify_disabled_ignores_size(self):
        """With verify=False, size mismatch is ignored."""
        ekey = b"\xab" * 16
        data = b"short"  # 5 bytes, but index says 100

        fetcher = self._make_fetcher_with_entry(ekey, "aabb", offset=0, size=100)
        client = self._mock_client(data)

        result = fetcher.fetch_file(client, ekey, decompress=False, verify=False)
        assert result == data

    def test_fetch_file_unknown_key_returns_none(self):
        """Key not in index map returns None."""
        fetcher = CdnArchiveFetcher(cdn_base="http://test.cdn", cdn_path="tpr/test")
        client = self._mock_client(b"data")

        result = fetcher.fetch_file(client, b"\xff" * 16, decompress=False)
        assert result is None

    def test_fetch_file_http_error_returns_none(self):
        """Non-success HTTP status returns None."""
        ekey = b"\xab" * 16
        fetcher = self._make_fetcher_with_entry(ekey, "aabb", offset=0, size=5)
        client = self._mock_client(b"", status_code=404)

        result = fetcher.fetch_file(client, ekey, decompress=False)
        assert result is None

    def test_fetch_file_range_header_is_correct(self):
        """Verify the Range header matches index entry offset and size."""
        ekey = b"\xab" * 16
        data = b"x" * 50

        fetcher = self._make_fetcher_with_entry(ekey, "aabb", offset=1000, size=50)
        client = self._mock_client(data)

        fetcher.fetch_file(client, ekey, decompress=False, verify=True)

        # Check the Range header sent
        call_args = client.get.call_args
        headers = call_args[1]["headers"]
        assert headers["Range"] == "bytes=1000-1049"
