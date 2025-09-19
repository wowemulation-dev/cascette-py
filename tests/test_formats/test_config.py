"""Tests for configuration format parsers."""

from io import BytesIO

from cascette_tools.formats.config import (
    BuildConfig,
    BuildConfigParser,
    CDNConfig,
    CDNConfigParser,
    PatchConfig,
    PatchConfigParser,
    ProductConfig,
    ProductConfigParser,
    detect_config_type,
    is_config_file,
)


class TestBuildConfigParser:
    """Test build configuration parser."""

    def test_parse_basic_build_config(self):
        """Test parsing basic build configuration."""
        config_content = """
root = abc123def456
encoding = content123 encoding456
install = installcontent789 installenc012
download = downloadcontent345 downloadenc678
size = sizecontent901 sizeenc234
build-name = Test Build
build-product = wow
build-uid = test-uid-123
        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(config_content.encode('utf-8'))

        assert build_config.root == "abc123def456"
        assert build_config.encoding == "content123 encoding456"
        assert build_config.install == "installcontent789 installenc012"
        assert build_config.download == "downloadcontent345 downloadenc678"
        assert build_config.size == "sizecontent901 sizeenc234"
        assert build_config.build_name == "Test Build"
        assert build_config.build_product == "wow"
        assert build_config.build_uid == "test-uid-123"

    def test_parse_with_extra_fields(self):
        """Test parsing build config with extra fields."""
        config_content = """
root = abc123
custom-field = custom-value
another-field = another-value
        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(config_content.encode('utf-8'))

        assert build_config.root == "abc123"
        assert len(build_config.extra_fields) == 2
        assert build_config.extra_fields["custom-field"] == "custom-value"
        assert build_config.extra_fields["another-field"] == "another-value"

    def test_parse_with_comments(self):
        """Test parsing config with comments."""
        config_content = """
# This is a comment
root = abc123
# Another comment
encoding = content123 encoding456
        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(config_content.encode('utf-8'))

        assert build_config.root == "abc123"
        assert build_config.encoding == "content123 encoding456"

    def test_parse_empty_config(self):
        """Test parsing empty configuration."""
        config_content = ""

        parser = BuildConfigParser()
        build_config = parser.parse(config_content.encode('utf-8'))

        assert build_config.root is None
        assert build_config.encoding is None
        assert len(build_config.extra_fields) == 0

    def test_round_trip_build_config(self):
        """Test round-trip parsing and building."""
        original_config = BuildConfig(
            root="abc123",
            encoding="content123 encoding456",
            build_name="Test Build",
            extra_fields={"custom": "value"}
        )

        parser = BuildConfigParser()
        binary_data = parser.build(original_config)
        parsed_config = parser.parse(binary_data)

        assert parsed_config.root == original_config.root
        assert parsed_config.encoding == original_config.encoding
        assert parsed_config.build_name == original_config.build_name
        assert parsed_config.extra_fields == original_config.extra_fields

    def test_parse_from_stream(self):
        """Test parsing from stream."""
        config_content = "root = abc123\nencoding = content123 encoding456"
        stream = BytesIO(config_content.encode('utf-8'))

        parser = BuildConfigParser()
        build_config = parser.parse(stream)

        assert build_config.root == "abc123"
        assert build_config.encoding == "content123 encoding456"

    def test_file_parsing(self, tmp_path):
        """Test parsing from file."""
        config_content = "root = abc123\nbuild-name = Test Build"
        test_file = tmp_path / "build_config.txt"
        test_file.write_text(config_content)

        parser = BuildConfigParser()
        build_config = parser.parse_file(str(test_file))

        assert build_config.root == "abc123"
        assert build_config.build_name == "Test Build"


class TestCDNConfigParser:
    """Test CDN configuration parser."""

    def test_parse_basic_cdn_config(self):
        """Test parsing basic CDN configuration."""
        config_content = """
archives = archive1 archive2 archive3
archive-group = group123
patch-archives = patcharc1 patcharc2
patch-archive-group = patchgroup456
builds = build1 build2
file-index = fileindex789
        """.strip()

        parser = CDNConfigParser()
        cdn_config = parser.parse(config_content.encode('utf-8'))

        assert cdn_config.archives == ["archive1", "archive2", "archive3"]
        assert cdn_config.archive_group == "group123"
        assert cdn_config.patch_archives == ["patcharc1", "patcharc2"]
        assert cdn_config.patch_archive_group == "patchgroup456"
        assert cdn_config.builds == ["build1", "build2"]
        assert cdn_config.file_index == "fileindex789"

    def test_parse_empty_lists(self):
        """Test parsing CDN config with empty lists."""
        config_content = """
archives =
builds =
        """.strip()

        parser = CDNConfigParser()
        cdn_config = parser.parse(config_content.encode('utf-8'))

        assert cdn_config.archives == []
        assert cdn_config.builds == []

    def test_parse_single_values(self):
        """Test parsing CDN config with single values."""
        config_content = """
archives = singlearchive
builds = singlebuild
        """.strip()

        parser = CDNConfigParser()
        cdn_config = parser.parse(config_content.encode('utf-8'))

        assert cdn_config.archives == ["singlearchive"]
        assert cdn_config.builds == ["singlebuild"]

    def test_round_trip_cdn_config(self):
        """Test round-trip parsing and building."""
        original_config = CDNConfig(
            archives=["arch1", "arch2"],
            archive_group="group123",
            builds=["build1"],
            extra_fields={"custom": "value"}
        )

        parser = CDNConfigParser()
        binary_data = parser.build(original_config)
        parsed_config = parser.parse(binary_data)

        assert parsed_config.archives == original_config.archives
        assert parsed_config.archive_group == original_config.archive_group
        assert parsed_config.builds == original_config.builds
        assert parsed_config.extra_fields == original_config.extra_fields


class TestPatchConfigParser:
    """Test patch configuration parser."""

    def test_parse_basic_patch_config(self):
        """Test parsing basic patch configuration."""
        config_content = """
patch-archives = patcharc1 patcharc2
patch-archive-group = patchgroup123
builds = build1 build2
        """.strip()

        parser = PatchConfigParser()
        patch_config = parser.parse(config_content.encode('utf-8'))

        assert patch_config.patch_archives == ["patcharc1", "patcharc2"]
        assert patch_config.patch_archive_group == "patchgroup123"
        assert patch_config.builds == ["build1", "build2"]

    def test_round_trip_patch_config(self):
        """Test round-trip parsing and building."""
        original_config = PatchConfig(
            patch_archives=["patch1", "patch2"],
            builds=["build1"],
            extra_fields={"version": "1.0"}
        )

        parser = PatchConfigParser()
        binary_data = parser.build(original_config)
        parsed_config = parser.parse(binary_data)

        assert parsed_config.patch_archives == original_config.patch_archives
        assert parsed_config.builds == original_config.builds
        assert parsed_config.extra_fields == original_config.extra_fields


class TestProductConfigParser:
    """Test product configuration parser."""

    def test_parse_basic_product_config(self):
        """Test parsing basic product configuration."""
        config_content = """
product = wow
uid = product-uid-123
name = World of Warcraft
        """.strip()

        parser = ProductConfigParser()
        product_config = parser.parse(config_content.encode('utf-8'))

        assert product_config.product == "wow"
        assert product_config.uid == "product-uid-123"
        assert product_config.name == "World of Warcraft"

    def test_round_trip_product_config(self):
        """Test round-trip parsing and building."""
        original_config = ProductConfig(
            product="wow",
            uid="uid123",
            name="World of Warcraft",
            extra_fields={"version": "retail"}
        )

        parser = ProductConfigParser()
        binary_data = parser.build(original_config)
        parsed_config = parser.parse(binary_data)

        assert parsed_config.product == original_config.product
        assert parsed_config.uid == original_config.uid
        assert parsed_config.name == original_config.name
        assert parsed_config.extra_fields == original_config.extra_fields


class TestConfigUtilities:
    """Test configuration utility functions."""

    def test_is_config_file(self):
        """Test config file detection."""
        # Valid config data
        valid_config = b"root = abc123\nencoding = def456"
        assert is_config_file(valid_config)

        # Invalid data
        assert not is_config_file(b"invalid data")
        assert not is_config_file(b"")
        assert not is_config_file(b"just some text without equals")

        # Comments only
        comment_only = b"# This is just a comment\n# Another comment"
        assert not is_config_file(comment_only)

    def test_detect_config_type(self):
        """Test config type detection."""
        # Build config
        build_config = b"root = abc123\nencoding = def456\nbuild-name = test"
        assert detect_config_type(build_config) == "build"

        # CDN config
        cdn_config = b"archives = arch1 arch2\narchive-group = group1"
        assert detect_config_type(cdn_config) == "cdn"

        # Patch config
        patch_config = b"patch-archives = patch1 patch2\nbuilds = build1"
        assert detect_config_type(patch_config) == "patch"

        # Product config
        product_config = b"product = wow\nuid = uid123\nname = World of Warcraft"
        assert detect_config_type(product_config) == "product"

        # Unknown config
        unknown_config = b"unknown-field = value\nanother-field = value2"
        assert detect_config_type(unknown_config) == "unknown"

        # Invalid data
        invalid_result = detect_config_type(b"invalid data")
        assert invalid_result is None or invalid_result == "unknown"

    def test_detect_config_type_with_comments(self):
        """Test config type detection with comments."""
        config_with_comments = b"""
# This is a build config
# Contains root and encoding
root = abc123
encoding = def456 ghi789
        """.strip()

        assert detect_config_type(config_with_comments) == "build"


class TestConfigModels:
    """Test configuration Pydantic models."""

    def test_build_config_model(self):
        """Test BuildConfig model."""
        config = BuildConfig(
            root="abc123",
            encoding="content123 encoding456",
            build_name="Test Build",
            extra_fields={"custom": "value"}
        )

        assert config.root == "abc123"
        assert config.encoding == "content123 encoding456"
        assert config.build_name == "Test Build"
        assert config.extra_fields["custom"] == "value"

    def test_cdn_config_model(self):
        """Test CDNConfig model."""
        config = CDNConfig(
            archives=["arch1", "arch2"],
            archive_group="group123",
            builds=["build1", "build2"],
            extra_fields={"version": "1.0"}
        )

        assert config.archives == ["arch1", "arch2"]
        assert config.archive_group == "group123"
        assert config.builds == ["build1", "build2"]
        assert config.extra_fields["version"] == "1.0"

    def test_patch_config_model(self):
        """Test PatchConfig model."""
        config = PatchConfig(
            patch_archives=["patch1", "patch2"],
            patch_archive_group="patchgroup123",
            builds=["build1"],
            extra_fields={"type": "incremental"}
        )

        assert config.patch_archives == ["patch1", "patch2"]
        assert config.patch_archive_group == "patchgroup123"
        assert config.builds == ["build1"]
        assert config.extra_fields["type"] == "incremental"

    def test_product_config_model(self):
        """Test ProductConfig model."""
        config = ProductConfig(
            product="wow",
            uid="uid123",
            name="World of Warcraft",
            extra_fields={"region": "us"}
        )

        assert config.product == "wow"
        assert config.uid == "uid123"
        assert config.name == "World of Warcraft"
        assert config.extra_fields["region"] == "us"

    def test_default_values(self):
        """Test model default values."""
        # BuildConfig with minimal data
        build_config = BuildConfig()
        assert build_config.root is None
        assert build_config.encoding is None
        assert build_config.extra_fields == {}

        # CDNConfig with minimal data
        cdn_config = CDNConfig()
        assert cdn_config.archives == []
        assert cdn_config.archive_group is None
        assert cdn_config.extra_fields == {}

        # PatchConfig with minimal data
        patch_config = PatchConfig()
        assert patch_config.patch_archives == []
        assert patch_config.patch_archive_group is None
        assert patch_config.extra_fields == {}

        # ProductConfig with minimal data
        product_config = ProductConfig()
        assert product_config.product is None
        assert product_config.uid is None
        assert product_config.extra_fields == {}


class TestConfigParsing:
    """Test various configuration parsing scenarios."""

    def test_parse_malformed_config(self):
        """Test parsing malformed configuration."""
        # Missing equals sign - should be ignored
        malformed_config = """
root = abc123
invalid line without equals
encoding = def456
        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(malformed_config.encode('utf-8'))

        assert build_config.root == "abc123"
        assert build_config.encoding == "def456"
        # Invalid line should be ignored

    def test_parse_whitespace_handling(self):
        """Test whitespace handling in configuration."""
        config_with_whitespace = """

   root   =   abc123

   build-name   =   Test Build

        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(config_with_whitespace.encode('utf-8'))

        assert build_config.root == "abc123"
        assert build_config.build_name == "Test Build"

    def test_parse_unicode_content(self):
        """Test parsing configuration with unicode content."""
        unicode_config = """
build-name = Tëst Büild 测试
build-product = wów
        """.strip()

        parser = BuildConfigParser()
        build_config = parser.parse(unicode_config.encode('utf-8'))

        assert build_config.build_name == "Tëst Büild 测试"
        assert build_config.build_product == "wów"

    def test_large_config_file(self):
        """Test parsing large configuration file."""
        # Create config with many extra fields
        lines = ["root = abc123"]
        for i in range(100):
            lines.append(f"extra-field-{i} = value-{i}")

        large_config = '\n'.join(lines)

        parser = BuildConfigParser()
        build_config = parser.parse(large_config.encode('utf-8'))

        assert build_config.root == "abc123"
        assert len(build_config.extra_fields) == 100
        assert build_config.extra_fields["extra-field-50"] == "value-50"
