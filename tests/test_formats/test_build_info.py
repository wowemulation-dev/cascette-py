"""Tests for build_info format parser."""


from cascette_tools.core.types import LocaleConfig
from cascette_tools.formats.build_info import (
    STANDARD_HEADER,
    BuildInfoParser,
    FieldType,
    LocalBuildInfo,
    build_tags_string,
    create_build_info,
    parse_header,
    parse_tags,
    update_last_activated,
)


class TestParseHeader:
    """Test header parsing function."""

    def test_parse_standard_header(self):
        """Test parsing the standard .build.info header."""
        fields = parse_header(STANDARD_HEADER)

        assert len(fields) == 15

        # Check first field
        assert fields[0].name == "Branch"
        assert fields[0].field_type == FieldType.STRING
        assert fields[0].size == 0

        # Check a HEX field
        build_key_field = next(f for f in fields if f.name == "Build Key")
        assert build_key_field.field_type == FieldType.HEX
        assert build_key_field.size == 16

        # Check a DEC field
        active_field = next(f for f in fields if f.name == "Active")
        assert active_field.field_type == FieldType.DEC
        assert active_field.size == 1

    def test_parse_empty_header(self):
        """Test parsing empty header."""
        fields = parse_header("")
        assert len(fields) == 0

    def test_parse_single_field(self):
        """Test parsing single field."""
        fields = parse_header("Test!STRING:0")
        assert len(fields) == 1
        assert fields[0].name == "Test"
        assert fields[0].field_type == FieldType.STRING


class TestParseTags:
    """Test tag parsing function."""

    def test_parse_simple_tags(self):
        """Test parsing simple tag string."""
        tags_str = "Windows x86_64 US? enUS speech?:Windows x86_64 US? enUS text?"

        platform, arch, locale_configs, region = parse_tags(tags_str)

        assert platform == "Windows"
        assert arch == "x86_64"
        assert region == "US"
        assert len(locale_configs) == 1
        assert locale_configs[0].code == "enUS"
        assert locale_configs[0].has_speech is True
        assert locale_configs[0].has_text is True

    def test_parse_multiple_locales(self):
        """Test parsing tags with multiple locales."""
        tags_str = "Windows x86_64 EU? enUS speech?:Windows x86_64 EU? deDE speech?"

        platform, arch, locale_configs, region = parse_tags(tags_str)

        assert platform == "Windows"
        assert len(locale_configs) == 2
        assert locale_configs[0].code == "enUS"
        assert locale_configs[1].code == "deDE"

    def test_parse_osx_platform(self):
        """Test parsing OSX platform."""
        tags_str = "OSX arm64 US? enUS speech?"

        platform, arch, locale_configs, region = parse_tags(tags_str)

        assert platform == "OSX"
        assert arch == "arm64"

    def test_parse_empty_tags(self):
        """Test parsing empty tags string."""
        platform, arch, locale_configs, region = parse_tags("")

        assert platform is None
        assert arch is None
        assert region is None
        assert len(locale_configs) == 0


class TestBuildTagsString:
    """Test tag string building function."""

    def test_build_with_speech_and_text(self):
        """Test building tags with both speech and text."""
        result = build_tags_string(
            platform="Windows",
            architecture="x86_64",
            locale="enUS",
            region="us",
            has_speech=True,
            has_text=True,
        )

        assert "Windows" in result
        assert "x86_64" in result
        assert "US?" in result
        assert "enUS" in result
        assert "speech?" in result
        assert "text?" in result
        assert ":" in result  # Should have two groups

    def test_build_speech_only(self):
        """Test building tags with speech only."""
        result = build_tags_string(
            platform="Windows",
            architecture="x86_64",
            locale="enUS",
            region="us",
            has_speech=True,
            has_text=False,
        )

        assert "speech?" in result
        assert "text?" not in result
        assert ":" not in result  # Single group

    def test_build_text_only(self):
        """Test building tags with text only."""
        result = build_tags_string(
            platform="Windows",
            architecture="x86_64",
            locale="enUS",
            region="us",
            has_speech=False,
            has_text=True,
        )

        assert "speech?" not in result
        assert "text?" in result


class TestBuildInfoParser:
    """Test BuildInfoParser class."""

    def test_parse_simple_build_info(self):
        """Test parsing simple .build.info content."""
        content = (
            "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
            "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
            "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|"
            "Version!STRING:0|KeyRing!HEX:16|Product!STRING:0\n"
            "us|1|abc123|def456||0|tpr/wow|host1.example.com|"
            "host1.example.com|Windows x86_64 US? enUS speech?|||1.15.8.65300||wow_classic_era\n"
        )

        parser = BuildInfoParser()
        result = parser.parse(content.encode())

        assert result.branch == "us"
        assert result.active == 1
        assert result.build_key == "abc123"
        assert result.cdn_key == "def456"
        assert result.cdn_path == "tpr/wow"
        assert result.version == "1.15.8.65300"
        assert result.product == "wow_classic_era"
        assert result.platform == "Windows"
        assert result.architecture == "x86_64"
        assert result.region == "US"

    def test_parse_with_empty_fields(self):
        """Test parsing .build.info with empty optional fields."""
        content = (
            "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
            "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
            "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|"
            "Version!STRING:0|KeyRing!HEX:16|Product!STRING:0\n"
            "us|1|abc123|def456||||||||||||wow\n"
        )

        parser = BuildInfoParser()
        result = parser.parse(content.encode())

        assert result.branch == "us"
        assert result.build_key == "abc123"
        assert result.install_key == ""
        assert result.im_size is None

    def test_parse_insufficient_lines(self):
        """Test parsing with insufficient lines returns empty object."""
        content = "Branch!STRING:0|Active!DEC:1\n"

        parser = BuildInfoParser()
        result = parser.parse(content.encode())

        # Should return default/empty values
        assert result.branch == ""

    def test_round_trip(self):
        """Test parse -> build -> parse produces consistent results."""
        original = LocalBuildInfo(
            branch="us",
            active=1,
            build_key="abc123def456789012345678901234567890",
            cdn_key="fedcba098765432109876543210987654321",
            install_key="",
            im_size=None,
            cdn_path="tpr/wow",
            cdn_hosts="host1.example.com host2.example.com",
            cdn_servers="host1.example.com host2.example.com",
            tags="Windows x86_64 US? enUS speech?:Windows x86_64 US? enUS text?",
            armadillo="",
            last_activated="2024-01-15T12:00:00Z",
            version="1.15.8.65300",
            keyring="",
            product="wow_classic_era",
            platform="Windows",
            architecture="x86_64",
            locale_configs=[LocaleConfig(code="enUS", has_speech=True, has_text=True)],
            region="US",
        )

        parser = BuildInfoParser()
        built = parser.build(original)
        parsed = parser.parse(built)

        assert parsed.branch == original.branch
        assert parsed.active == original.active
        assert parsed.build_key == original.build_key
        assert parsed.cdn_key == original.cdn_key
        assert parsed.version == original.version
        assert parsed.product == original.product

    def test_build_produces_valid_format(self):
        """Test that build produces parseable output."""
        info = LocalBuildInfo(
            branch="eu",
            active=1,
            build_key="test_build_key",
            cdn_key="test_cdn_key",
            version="2.0.0.12345",
            product="wow",
        )

        parser = BuildInfoParser()
        built = parser.build(info)

        # Should have header and data line
        lines = built.decode().strip().split("\n")
        assert len(lines) == 2

        # Header should contain expected fields
        assert "Branch!STRING:0" in lines[0]
        assert "Build Key!HEX:16" in lines[0]

        # Data line should contain our values
        assert "eu" in lines[1]
        assert "test_build_key" in lines[1]


class TestCreateBuildInfo:
    """Test create_build_info convenience function."""

    def test_create_with_defaults(self):
        """Test creating build info with minimal parameters."""
        info = create_build_info(
            branch="us",
            build_config_hash="abc123",
            cdn_config_hash="def456",
            cdn_path="tpr/wow",
            cdn_hosts=["host1.example.com", "host2.example.com"],
            version="1.0.0.12345",
            product="wow",
        )

        assert info.branch == "us"
        assert info.build_key == "abc123"
        assert info.cdn_key == "def456"
        assert info.platform == "Windows"
        assert info.architecture == "x86_64"
        assert info.active == 1
        assert len(info.locale_configs) == 1
        assert info.locale_configs[0].code == "enUS"
        assert info.locale_configs[0].has_speech is True
        assert info.locale_configs[0].has_text is True

    def test_create_with_custom_options(self):
        """Test creating build info with custom options."""
        info = create_build_info(
            branch="eu",
            build_config_hash="xyz789",
            cdn_config_hash="uvw012",
            cdn_path="tpr/wow",
            cdn_hosts=["eu.example.com"],
            version="2.0.0.54321",
            product="wow_classic",
            platform="OSX",
            architecture="arm64",
            locale="deDE",
            region="eu",
            has_speech=True,
            has_text=False,
        )

        assert info.platform == "OSX"
        assert info.architecture == "arm64"
        assert info.region == "EU"
        assert len(info.locale_configs) == 1
        assert info.locale_configs[0].code == "deDE"
        assert info.locale_configs[0].has_speech is True
        assert info.locale_configs[0].has_text is False

    def test_cdn_hosts_joined_correctly(self):
        """Test that CDN hosts are joined with spaces."""
        info = create_build_info(
            branch="us",
            build_config_hash="abc",
            cdn_config_hash="def",
            cdn_path="tpr/wow",
            cdn_hosts=["host1.com", "host2.com", "host3.com"],
            version="1.0.0",
            product="wow",
        )

        assert info.cdn_hosts == "host1.com host2.com host3.com"
        assert info.cdn_servers == "host1.com host2.com host3.com"


class TestUpdateLastActivated:
    """Test update_last_activated function."""

    def test_updates_timestamp(self):
        """Test that last_activated is updated."""
        info = LocalBuildInfo(
            branch="us",
            active=1,
            last_activated="",
        )

        updated = update_last_activated(info)

        assert updated.last_activated != ""
        # Should be in ISO format with Z suffix
        assert "T" in updated.last_activated
        assert updated.last_activated.endswith("Z")

    def test_overwrites_existing_timestamp(self):
        """Test that existing timestamp is overwritten."""
        info = LocalBuildInfo(
            branch="us",
            active=1,
            last_activated="2020-01-01T00:00:00Z",
        )

        updated = update_last_activated(info)

        assert updated.last_activated != "2020-01-01T00:00:00Z"
        # New timestamp should be more recent (starts with 202x)
        assert updated.last_activated.startswith("202")


class TestLocaleConfig:
    """Test LocaleConfig display method."""

    def test_display_with_both_flags(self):
        """Test display with speech and text."""
        config = LocaleConfig(code="enUS", has_speech=True, has_text=True)
        assert config.display() == "enUS (speech, text)"

    def test_display_with_speech_only(self):
        """Test display with speech only."""
        config = LocaleConfig(code="deDE", has_speech=True, has_text=False)
        assert config.display() == "deDE (speech)"

    def test_display_with_text_only(self):
        """Test display with text only."""
        config = LocaleConfig(code="frFR", has_speech=False, has_text=True)
        assert config.display() == "frFR (text)"

    def test_display_with_no_flags(self):
        """Test display with no flags."""
        config = LocaleConfig(code="koKR", has_speech=False, has_text=False)
        assert config.display() == "koKR"
