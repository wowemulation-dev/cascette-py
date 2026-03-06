"""Tests for tact.py module."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.config import TACTConfig
from cascette_tools.core.tact import BPSVParser, TACTClient
from cascette_tools.core.types import Product


class TestBPSVParser:
    """Test BPSVParser class."""

    def test_parse_simple_manifest(self):
        """Test parsing simple BPSV manifest."""
        parser = BPSVParser()

        # BPSV format: key=value pairs separated by pipes
        manifest = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\nus|abc123def456|def456abc123\neu|789abc123def|123def789abc"

        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0] == {
            "Region": "us",
            "BuildConfig": "abc123def456",
            "CDNConfig": "def456abc123"
        }
        assert result[1] == {
            "Region": "eu",
            "BuildConfig": "789abc123def",
            "CDNConfig": "123def789abc"
        }

    def test_parse_empty_manifest(self):
        """Test parsing empty manifest."""
        parser = BPSVParser()
        result = parser.parse("")
        assert result == []

    def test_parse_header_only(self):
        """Test parsing manifest with only header."""
        parser = BPSVParser()
        manifest = "Region!STRING:0|BuildConfig!HEX:16"
        result = parser.parse(manifest)
        assert result == []

    def test_parse_with_empty_lines(self):
        """Test parsing manifest with empty lines."""
        parser = BPSVParser()
        manifest = "Region!STRING:0|Value!STRING:0\n\nus|test\n\neu|test2\n"
        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_parse_with_special_characters(self):
        """Test parsing with special characters in values."""
        parser = BPSVParser()
        manifest = "Name!STRING:0|Path!STRING:0\nWoW Classic|wow_classic\nWoW Beta|wowt"
        result = parser.parse(manifest)

        assert len(result) == 2
        assert result[0]["Name"] == "WoW Classic"
        assert result[0]["Path"] == "wow_classic"

    def test_parse_malformed_header(self):
        """Test parsing with malformed header."""
        parser = BPSVParser()
        # Missing type information
        manifest = "Region|BuildConfig\nus|abc123"

        # Should still work by treating everything as strings
        result = parser.parse(manifest)
        assert len(result) == 1
        assert result[0]["Region"] == "us"

    def test_parse_mismatched_columns(self):
        """Test parsing with mismatched columns."""
        parser = BPSVParser()
        manifest = "A!STRING:0|B!STRING:0|C!STRING:0\nval1|val2\nval3|val4|val5|val6"

        result = parser.parse(manifest)
        assert len(result) == 2
        # First row has missing column
        assert result[0] == {"A": "val1", "B": "val2", "C": ""}
        # Second row has extra column (should be ignored)
        assert result[1] == {"A": "val3", "B": "val4", "C": "val5"}


class TestTACTClient:
    """Test TACTClient class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        client = TACTClient()

        assert client.region == "us"
        assert isinstance(client.config, TACTConfig)
        assert isinstance(client.cache, DiskCache)
        assert client._base_url == "https://us.version.battle.net"
        assert client.session is None

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        config = TACTConfig(timeout=60.0)
        client = TACTClient(region="eu", config=config)

        assert client.region == "eu"
        assert client.config == config
        assert client._base_url == "https://eu.version.battle.net"

    def test_init_invalid_region(self):
        """Test initialization with invalid region."""
        # Region validation is done by TACTConfig, not TACTClient
        client = TACTClient(region="invalid")
        assert client.region == "invalid"

    def test_build_url_versions(self):
        """Test building URL for versions endpoint."""
        client = TACTClient(region="us")
        url = client._build_url("versions", Product.WOW)
        assert url == "https://us.version.battle.net/wow/versions"

    def test_build_url_cdns(self):
        """Test building URL for CDNs endpoint."""
        client = TACTClient(region="eu")
        url = client._build_url("cdns", Product.WOW_CLASSIC)
        assert url == "https://eu.version.battle.net/wow_classic/cdns"

    def test_build_url_bgdl(self):
        """Test building URL for BGDL endpoint."""
        client = TACTClient(region="kr")
        url = client._build_url("bgdl", Product.WOW_CLASSIC_ERA)
        assert url == "https://kr.version.battle.net/wow_classic_era/bgdl"

    @patch("httpx.Client.get")
    def test_fetch_with_retry_success(self, mock_get):
        """Test successful fetch with retry."""
        mock_response = MagicMock()
        mock_response.text = "test response"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        client = TACTClient()
        result = client._fetch_with_retry("https://test.url")

        assert result == "test response"
        mock_get.assert_called_once()

    @patch("httpx.Client.get")
    def test_fetch_with_retry_failure_then_success(self, mock_get):
        """Test fetch with initial failure then success."""
        # First call fails, second succeeds
        failed_response = MagicMock()
        failed_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )

        success_response = MagicMock()
        success_response.text = "success response"
        success_response.raise_for_status.return_value = None

        mock_get.side_effect = [failed_response, success_response]

        client = TACTClient()
        result = client._fetch_with_retry("https://test.url")

        assert result == "success response"
        assert mock_get.call_count == 2

    @patch("httpx.Client.get")
    def test_fetch_with_retry_all_failures(self, mock_get):
        """Test fetch with all retries failing."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock()
        )
        mock_get.return_value = mock_response

        client = TACTClient()

        with pytest.raises(httpx.HTTPStatusError):
            client._fetch_with_retry("https://test.url")

        # Should retry max_retries + 1 times (3 + 1 = 4)
        assert mock_get.call_count == 4

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_versions_cache_hit(self, mock_fetch):
        """Test fetch_versions with cache hit."""
        client = TACTClient()

        # Mock cache hit
        with patch.object(client.cache, "get_api", return_value="cached response"):
            result = client.fetch_versions(Product.WOW)

            assert result == "cached response"
            mock_fetch.assert_not_called()

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_versions_cache_miss(self, mock_fetch):
        """Test fetch_versions with cache miss."""
        mock_fetch.return_value = "fresh response"

        client = TACTClient()

        # Mock cache miss
        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_versions(Product.WOW)

            assert result == "fresh response"
            mock_fetch.assert_called_once()
            mock_put.assert_called_once_with("tact:us:wow:versions", "fresh response")

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_cdns_cache_miss(self, mock_fetch):
        """Test fetch_cdns with cache miss."""
        mock_fetch.return_value = "cdns response"

        client = TACTClient(region="eu")

        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_cdns(Product.WOW_CLASSIC)

            assert result == "cdns response"
            mock_put.assert_called_once_with("tact:eu:wow_classic:cdns", "cdns response")

    @patch.object(TACTClient, "_fetch_with_retry")
    def test_fetch_bgdl_cache_miss(self, mock_fetch):
        """Test fetch_bgdl with cache miss."""
        mock_fetch.return_value = "bgdl response"

        client = TACTClient(region="kr")

        with patch.object(client.cache, "get_api", return_value=None), \
             patch.object(client.cache, "put_api") as mock_put:

            result = client.fetch_bgdl(Product.WOW_CLASSIC_ERA)

            assert result == "bgdl response"
            mock_put.assert_called_once_with("tact:kr:wow_classic_era:bgdl", "bgdl response")

    def test_parse_versions(self):
        """Test parsing versions manifest."""
        client = TACTClient()

        manifest = "Region!STRING:0|BuildConfig!HEX:16\nus|abc123def456\neu|def456abc123"
        result = client.parse_versions(manifest)

        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_parse_cdns(self):
        """Test parsing CDNs manifest."""
        client = TACTClient()

        manifest = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\nus|tpr/wow|cdn1.example.com cdn2.example.com"
        result = client.parse_cdns(manifest)

        assert len(result) == 1
        assert result[0]["Name"] == "us"
        assert result[0]["Path"] == "tpr/wow"

    def test_parse_bgdl(self):
        """Test parsing BGDL manifest."""
        client = TACTClient()

        manifest = "Product!STRING:0|Priority!DEC:1\nwow|1"
        result = client.parse_bgdl(manifest)

        assert len(result) == 1
        assert result[0]["Product"] == "wow"

    @patch.object(TACTClient, "fetch_versions")
    @patch.object(TACTClient, "parse_versions")
    def test_get_latest_build_found(self, mock_parse, mock_fetch):
        """Test get_latest_build when build is found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Region": "eu", "BuildConfig": "abc123"},
            {"Region": "us", "BuildConfig": "def456"},
        ]

        client = TACTClient(region="us")
        result = client.get_latest_build(Product.WOW)

        assert result == {"Region": "us", "BuildConfig": "def456"}
        mock_fetch.assert_called_once_with(Product.WOW)

    @patch.object(TACTClient, "fetch_versions")
    @patch.object(TACTClient, "parse_versions")
    def test_get_latest_build_not_found(self, mock_parse, mock_fetch):
        """Test get_latest_build when build is not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Region": "eu", "BuildConfig": "abc123"},
        ]

        client = TACTClient(region="us")
        result = client.get_latest_build(Product.WOW)

        assert result is None

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_servers_found(self, mock_parse, mock_fetch):
        """Test get_cdn_servers when servers are found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "us", "Hosts": "cdn1.example.com cdn2.example.com"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_servers(Product.WOW)

        assert result == ["http://cdn1.example.com", "http://cdn2.example.com"]

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_servers_not_found(self, mock_parse, mock_fetch):
        """Test get_cdn_servers when region not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "eu", "Hosts": "cdn1.example.com"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_servers(Product.WOW)

        assert result == []

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_path_found(self, mock_parse, mock_fetch):
        """Test get_cdn_path when path is found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "us", "Path": "tpr/wow"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_path(Product.WOW)

        assert result == "tpr/wow"

    @patch.object(TACTClient, "fetch_cdns")
    @patch.object(TACTClient, "parse_cdns")
    def test_get_cdn_path_not_found(self, mock_parse, mock_fetch):
        """Test get_cdn_path when region not found."""
        mock_fetch.return_value = "manifest"
        mock_parse.return_value = [
            {"Name": "eu", "Path": "tpr/wow"},
        ]

        client = TACTClient(region="us")
        result = client.get_cdn_path(Product.WOW)

        assert result is None

    def test_clear_cache(self):
        """Test clearing cache."""
        client = TACTClient()

        with patch.object(client.cache, "clear_expired", return_value=5) as mock_clear:
            result = client.clear_cache()

            assert result == 5
            mock_clear.assert_called_once()

    def test_clear_cache_for_product(self):
        """Test clearing cache for specific product."""
        client = TACTClient()

        # Test implementation would need to clear specific product entries
        # For now, just verify the method exists and can be called
        with patch.object(client.cache, "clear_expired", return_value=2):
            result = client.clear_cache(Product.WOW)
            assert result == 2


class TestBPSVParserCommentHandling:
    """Tests for BPSV comment and metadata line handling.

    Validates behavior of tact::PsvReader::ParseMetadataLine (0x6f1d1c):
    - '## seqn = N' lines are skipped and the seqn value is extractable.
    - '#' prefixed lines are comments and are skipped.
    Both must be excluded from data row parsing.
    """

    def test_double_hash_seqn_line_is_skipped(self):
        """'## seqn = N' lines must not appear as data rows."""
        parser = BPSVParser()
        manifest = (
            "## seqn = 3568387\n"
            "Region!STRING:0|BuildConfig!HEX:16\n"
            "us|abc123def456\n"
            "eu|789abc123def\n"
        )
        result = parser.parse(manifest)
        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_single_hash_comment_line_is_skipped(self):
        """Lines beginning with '#' are comments per ParseMetadataLine and must be skipped."""
        parser = BPSVParser()
        manifest = (
            "## seqn = 42\n"
            "# This is a comment\n"
            "Region!STRING:0|BuildConfig!HEX:16\n"
            "us|abc123def456\n"
        )
        result = parser.parse(manifest)
        assert len(result) == 1
        assert result[0]["Region"] == "us"

    def test_comment_only_document_returns_empty(self):
        """Document with only comment lines and no header returns empty list."""
        parser = BPSVParser()
        manifest = "## seqn = 1\n# just a comment\n"
        result = parser.parse(manifest)
        assert result == []

    def test_comment_between_data_rows_is_skipped(self):
        """Comment lines between data rows are also skipped."""
        parser = BPSVParser()
        manifest = (
            "Region!STRING:0|Value!STRING:0\n"
            "us|val1\n"
            "# mid-document comment\n"
            "eu|val2\n"
        )
        result = parser.parse(manifest)
        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[1]["Region"] == "eu"

    def test_seqn_and_comment_before_header(self):
        """Both ## seqn and # comments can appear before the header line."""
        parser = BPSVParser()
        manifest = (
            "## seqn = 99\n"
            "# optional comment\n"
            "Name!STRING:32|Region!STRING:8\n"
            "US-Server|US\n"
            "EU-Server|EU\n"
        )
        result = parser.parse(manifest)
        assert len(result) == 2
        assert result[0]["Name"] == "US-Server"
        assert result[0]["Region"] == "US"
        assert result[1]["Name"] == "EU-Server"
        assert result[1]["Region"] == "EU"

    def test_real_ribbit_style_versions_manifest(self):
        """Validates parsing of a realistic Ribbit-style BPSV versions manifest.

        Ribbit injects '## seqn = N' at the top of every manifest response.
        This is the format actually returned by Blizzard CDN infrastructure.
        """
        parser = BPSVParser()
        manifest = "\n".join([
            "## seqn = 3568387",
            "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|KeyRing!HEX:16|BuildId!DEC:0|VersionsName!String:0|ProductConfig!HEX:16",
            "us|4e4525fb424e72da28bc1b9ab5f22a84|c4a9ee27e76de9f8d63cd65cf8dce5bf||9370|3.13.3.9370|e3a2ca2b2d1abf6d3dfbaab3a29e8af0",
            "eu|4e4525fb424e72da28bc1b9ab5f22a84|c4a9ee27e76de9f8d63cd65cf8dce5bf||9370|3.13.3.9370|e3a2ca2b2d1abf6d3dfbaab3a29e8af0",
        ])
        result = parser.parse(manifest)
        assert len(result) == 2
        assert result[0]["Region"] == "us"
        assert result[0]["BuildConfig"] == "4e4525fb424e72da28bc1b9ab5f22a84"
        assert result[0]["BuildId"] == "9370"
        assert result[0]["VersionsName"] == "3.13.3.9370"
        # Empty fields produce empty strings, not missing keys
        assert result[0]["KeyRing"] == ""


class TestBPSVParserSequenceNumber:
    """Tests for Ribbit sequence number extraction.

    Agent.exe reads '## seqn = ' (0x8fd00c) + decimal integer for cache validation.
    Implemented in sub_41cafa.
    """

    def test_extract_seqn_from_standard_manifest(self):
        """Extracts seqn from a standard BPSV manifest."""
        parser = BPSVParser()
        manifest = "## seqn = 3568387\nRegion!STRING:0\nus\n"
        seqn = parser.extract_sequence_number(manifest)
        assert seqn == 3568387

    def test_extract_seqn_returns_none_when_absent(self):
        """Returns None when no seqn line is present."""
        parser = BPSVParser()
        manifest = "Region!STRING:0\nus\n"
        seqn = parser.extract_sequence_number(manifest)
        assert seqn is None

    def test_extract_seqn_zero(self):
        """Handles seqn value of zero."""
        parser = BPSVParser()
        manifest = "## seqn = 0\nRegion!STRING:0\nus\n"
        seqn = parser.extract_sequence_number(manifest)
        assert seqn == 0

    def test_extract_seqn_large_value(self):
        """Handles large seqn values."""
        parser = BPSVParser()
        manifest = "## seqn = 9999999\nRegion!STRING:0\nus\n"
        seqn = parser.extract_sequence_number(manifest)
        assert seqn == 9999999

    def test_extract_seqn_empty_manifest(self):
        """Returns None on empty manifest."""
        parser = BPSVParser()
        assert parser.extract_sequence_number("") is None

    def test_extract_seqn_is_independent_of_parse(self):
        """Sequence number extraction does not interfere with data parsing."""
        parser = BPSVParser()
        manifest = (
            "## seqn = 12345\n"
            "Region!STRING:0|BuildConfig!HEX:16\n"
            "us|abc123def456\n"
        )
        seqn = parser.extract_sequence_number(manifest)
        rows = parser.parse(manifest)
        assert seqn == 12345
        assert len(rows) == 1
        assert rows[0]["Region"] == "us"


class TestBPSVParserTypeSystem:
    """Tests for BPSV header type system.

    Agent.exe (TACT 3.13.3) supports three type codes per ParseHeaderLine (0x6f19e6):
    - DEC (0x444543): decimal integer
    - HEX (0x484558): hexadecimal integer
    - STRING (0x535452494E47): UTF-8 string

    Type names are case-insensitive (converted to uppercase before comparison).
    The parser currently returns all values as strings; these tests verify column
    names are correctly extracted regardless of the type annotation case.
    """

    def test_string_type_uppercase(self):
        """STRING type (uppercase) is recognized and column name extracted."""
        parser = BPSVParser()
        manifest = "Region!STRING:0\nus\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "Region" in result[0]

    def test_string_type_lowercase(self):
        """string type (lowercase) is accepted per case-insensitive spec."""
        parser = BPSVParser()
        manifest = "Region!string:0\nus\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "Region" in result[0]

    def test_string_type_mixed_case(self):
        """String type (mixed case) is accepted per case-insensitive spec."""
        parser = BPSVParser()
        manifest = "Region!String:100\nus\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "Region" in result[0]

    def test_dec_type(self):
        """DEC type is recognized and column name extracted."""
        parser = BPSVParser()
        manifest = "BuildId!DEC:0\n9370\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "BuildId" in result[0]
        assert result[0]["BuildId"] == "9370"

    def test_hex_type(self):
        """HEX type is recognized and column name extracted."""
        parser = BPSVParser()
        manifest = "BuildConfig!HEX:16\nabc123def456abc1\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "BuildConfig" in result[0]
        assert result[0]["BuildConfig"] == "abc123def456abc1"

    def test_multiple_types_in_header(self):
        """Header with all three types is correctly parsed."""
        parser = BPSVParser()
        manifest = (
            "Region!STRING:0|BuildId!DEC:0|BuildConfig!HEX:16\n"
            "us|9370|abc123def456abc1def456abc123def4\n"
        )
        result = parser.parse(manifest)
        assert len(result) == 1
        assert result[0]["Region"] == "us"
        assert result[0]["BuildId"] == "9370"
        assert result[0]["BuildConfig"] == "abc123def456abc1def456abc123def4"

    def test_width_value_is_ignored_for_column_name(self):
        """The ':width' suffix does not affect column name extraction."""
        parser = BPSVParser()
        manifest = "Name!STRING:100|Path!STRING:0\nWoW|wow\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert "Name" in result[0]
        assert "Path" in result[0]

    def test_empty_value_is_preserved(self):
        """Empty pipe-separated values produce empty strings (BpsvValue::Empty)."""
        parser = BPSVParser()
        manifest = "A!STRING:0|B!STRING:0|C!STRING:0\nval1||val3\n"
        result = parser.parse(manifest)
        assert len(result) == 1
        assert result[0]["A"] == "val1"
        assert result[0]["B"] == ""
        assert result[0]["C"] == "val3"
