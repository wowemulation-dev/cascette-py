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


class TestBuildConfigAccessors:
    """Test typed accessor methods on BuildConfig."""

    def _hash(self, n: int) -> str:
        return f"{n:032x}"

    def test_get_size_info(self):
        """Test size accessor returns ConfigFileInfo."""
        config = BuildConfig(
            size=f"{self._hash(1)} {self._hash(2)}",
            size_size="100 200",
        )
        info = config.get_size_info()
        assert info is not None
        assert info.content_key == self._hash(1)
        assert info.encoding_key == self._hash(2)
        assert info.size == 200

    def test_get_size_info_missing(self):
        """Test size accessor returns None when missing."""
        config = BuildConfig()
        assert config.get_size_info() is None

    def test_get_vfs_root_info(self):
        """Test VFS root accessor returns ConfigFileInfo."""
        config = BuildConfig(
            vfs_root=f"{self._hash(3)} {self._hash(4)}",
            vfs_root_size="300 400",
        )
        info = config.get_vfs_root_info()
        assert info is not None
        assert info.content_key == self._hash(3)
        assert info.encoding_key == self._hash(4)
        assert info.size == 400

    def test_get_vfs_root_info_missing(self):
        """Test VFS root accessor returns None when missing."""
        config = BuildConfig()
        assert config.get_vfs_root_info() is None

    def test_get_encoding_info(self):
        """Test encoding accessor returns ConfigFileInfo."""
        config = BuildConfig(
            encoding=f"{self._hash(5)} {self._hash(6)}",
            encoding_size="500 600",
        )
        info = config.get_encoding_info()
        assert info is not None
        assert info.content_key == self._hash(5)
        assert info.encoding_key == self._hash(6)
        assert info.size == 600

    def test_get_encoding_info_content_key_only(self):
        """Test encoding accessor with content key only (no encoding key)."""
        config = BuildConfig(encoding=self._hash(7))
        info = config.get_encoding_info()
        assert info is not None
        assert info.content_key == self._hash(7)
        assert info.encoding_key is None
        assert info.size is None

    def test_build_playtime_url(self):
        """Test build playtime URL field."""
        config = BuildConfig(build_playtime_url="https://example.com/playtime")
        assert config.build_playtime_url == "https://example.com/playtime"

    def test_build_product_espec(self):
        """Test build product espec field."""
        config = BuildConfig(build_product_espec="wow_classic")
        assert config.build_product_espec == "wow_classic"

    def test_get_partial_priorities(self):
        """Test partial priority parsing."""
        config = BuildConfig(
            build_partial_priority="speech:0,world:1,base:2",
        )
        priorities = config.get_partial_priorities()
        assert len(priorities) == 3
        assert priorities[0].key == "speech"
        assert priorities[0].priority == 0
        assert priorities[1].key == "world"
        assert priorities[1].priority == 1
        assert priorities[2].key == "base"
        assert priorities[2].priority == 2

    def test_get_partial_priorities_malformed_skipped(self):
        """Test partial priority parsing skips malformed entries."""
        config = BuildConfig(
            build_partial_priority="speech:0,bad_entry,world:abc,base:2",
        )
        priorities = config.get_partial_priorities()
        assert len(priorities) == 2
        assert priorities[0].key == "speech"
        assert priorities[1].key == "base"

    def test_get_partial_priorities_empty(self):
        """Test partial priority returns empty list when missing."""
        config = BuildConfig()
        assert config.get_partial_priorities() == []

    def test_get_partial_priorities_fallback_to_partial_priority(self):
        """Test partial priority falls back to partial-priority field."""
        config = BuildConfig(partial_priority="a:1,b:2")
        priorities = config.get_partial_priorities()
        assert len(priorities) == 2
        assert priorities[0].key == "a"
        assert priorities[1].key == "b"

    def test_get_vfs_entries(self):
        """Test VFS entries accessor."""
        config = BuildConfig(
            extra_fields={
                "vfs-1": f"{self._hash(10)} {self._hash(11)}",
                "vfs-1-size": "1000 1100",
                "vfs-2": f"{self._hash(20)} {self._hash(21)}",
                "vfs-2-size": "2000 2100",
            }
        )
        entries = config.get_vfs_entries()
        assert len(entries) == 2

        assert entries[0][0] == 1
        assert entries[0][1].content_key == self._hash(10)
        assert entries[0][1].encoding_key == self._hash(11)
        assert entries[0][1].size == 1100

        assert entries[1][0] == 2
        assert entries[1][1].content_key == self._hash(20)

    def test_get_vfs_entries_stops_at_gap(self):
        """Test VFS entries stop at first missing index."""
        config = BuildConfig(
            extra_fields={
                "vfs-1": self._hash(10),
                "vfs-3": self._hash(30),  # gap at 2
            }
        )
        entries = config.get_vfs_entries()
        assert len(entries) == 1
        assert entries[0][0] == 1

    def test_get_vfs_entries_empty(self):
        """Test VFS entries returns empty list when none present."""
        config = BuildConfig()
        assert config.get_vfs_entries() == []


class TestBuildConfigParserNewFields:
    """Test BuildConfigParser with new fields."""

    def _hash(self, n: int) -> str:
        return f"{n:032x}"

    def test_parse_new_fields(self):
        """Test parsing config with new fields."""
        config_content = f"""
root = {self._hash(1)}
encoding = {self._hash(2)} {self._hash(3)}
encoding-size = 100 200
size = {self._hash(4)} {self._hash(5)}
size-size = 300 400
vfs-root = {self._hash(6)} {self._hash(7)}
vfs-root-size = 500 600
build-playtime-url = https://example.com/pt
build-product-espec = wow
build-partial-priority = speech:0,world:1
        """.strip()

        parser = BuildConfigParser()
        config = parser.parse(config_content.encode('utf-8'))

        assert config.encoding_size == "100 200"
        assert config.size == f"{self._hash(4)} {self._hash(5)}"
        assert config.size_size == "300 400"
        assert config.vfs_root == f"{self._hash(6)} {self._hash(7)}"
        assert config.vfs_root_size == "500 600"
        assert config.build_playtime_url == "https://example.com/pt"
        assert config.build_product_espec == "wow"
        assert config.build_partial_priority == "speech:0,world:1"

    def test_parse_vfs_entries_in_extra_fields(self):
        """Test VFS entries are stored in extra_fields."""
        config_content = f"""
root = {self._hash(1)}
vfs-1 = {self._hash(10)} {self._hash(11)}
vfs-1-size = 1000 1100
vfs-2 = {self._hash(20)}
        """.strip()

        parser = BuildConfigParser()
        config = parser.parse(config_content.encode('utf-8'))

        assert "vfs-1" in config.extra_fields
        assert "vfs-1-size" in config.extra_fields
        assert "vfs-2" in config.extra_fields

    def test_round_trip_new_fields(self):
        """Test round-trip with new fields."""
        original = BuildConfig(
            root=self._hash(1),
            encoding=f"{self._hash(2)} {self._hash(3)}",
            encoding_size="100 200",
            size=f"{self._hash(4)} {self._hash(5)}",
            size_size="300 400",
            vfs_root=f"{self._hash(6)} {self._hash(7)}",
            vfs_root_size="500 600",
            build_playtime_url="https://example.com/pt",
            build_product_espec="wow",
            build_partial_priority="speech:0,world:1",
        )

        parser = BuildConfigParser()
        data = parser.build(original)
        reparsed = parser.parse(data)

        assert reparsed.size == original.size
        assert reparsed.size_size == original.size_size
        assert reparsed.vfs_root == original.vfs_root
        assert reparsed.vfs_root_size == original.vfs_root_size
        assert reparsed.build_playtime_url == original.build_playtime_url
        assert reparsed.build_product_espec == original.build_product_espec
        assert reparsed.build_partial_priority == original.build_partial_priority

        # Typed accessors work after round-trip
        size_info = reparsed.get_size_info()
        assert size_info is not None
        assert size_info.content_key == self._hash(4)
        assert size_info.size == 400

        priorities = reparsed.get_partial_priorities()
        assert len(priorities) == 2
        assert priorities[0].key == "speech"

    def test_round_trip_vfs_entries(self):
        """Test round-trip with VFS entries in extra_fields."""
        original = BuildConfig(
            root=self._hash(1),
            extra_fields={
                "vfs-1": f"{self._hash(10)} {self._hash(11)}",
                "vfs-1-size": "1000 1100",
                "vfs-2": f"{self._hash(20)}",
                "custom-field": "custom-value",
            },
        )

        parser = BuildConfigParser()
        data = parser.build(original)
        reparsed = parser.parse(data)

        entries = reparsed.get_vfs_entries()
        assert len(entries) == 2
        assert entries[0][1].content_key == self._hash(10)
        assert reparsed.extra_fields["custom-field"] == "custom-value"

    def test_build_field_order(self):
        """Test builder outputs fields in canonical order."""
        config = BuildConfig(
            root=self._hash(1),
            encoding=self._hash(2),
            build_name="Test",
            vfs_root=self._hash(3),
            size=self._hash(4),
        )

        parser = BuildConfigParser()
        data = parser.build(config).decode('utf-8')
        lines = [line for line in data.strip().split('\n') if line]

        keys = [line.split(' = ', 1)[0] for line in lines]
        assert keys.index('root') < keys.index('size')
        assert keys.index('size') < keys.index('vfs-root')
        assert keys.index('vfs-root') < keys.index('encoding')
        assert keys.index('encoding') < keys.index('build-name')


class TestCDNConfigNewFields:
    """Test CDNConfig with new fields."""

    def test_parse_patch_file_index_fields(self):
        """Test parsing patch file index fields."""
        config_content = """
archives = arch1 arch2
patch-file-index = pfi1 pfi2
patch-file-index-size = 1000 2000
file-index = fi1
file-index-size = 500
        """.strip()

        parser = CDNConfigParser()
        config = parser.parse(config_content.encode('utf-8'))

        assert config.patch_file_index == "pfi1 pfi2"
        assert config.patch_file_index_size == "1000 2000"
        assert config.file_index == "fi1"
        assert config.file_index_size == "500"

    def test_get_patch_file_index_size(self):
        """Test patch file index size accessor."""
        config = CDNConfig(patch_file_index_size="54321")
        assert config.get_patch_file_index_size() == 54321

    def test_get_patch_file_index_size_missing(self):
        """Test patch file index size returns None when missing."""
        config = CDNConfig()
        assert config.get_patch_file_index_size() is None

    def test_get_patch_file_indices(self):
        """Test patch file indices accessor."""
        config = CDNConfig(
            patch_file_index="aabb1122 ccdd3344",
            patch_file_index_size="1000 2000",
        )
        indices = config.get_patch_file_indices()
        assert len(indices) == 2
        assert indices[0].content_key == "aabb1122"
        assert indices[0].index_size == 1000
        assert indices[1].content_key == "ccdd3344"
        assert indices[1].index_size == 2000

    def test_get_patch_file_indices_no_sizes(self):
        """Test patch file indices without size data."""
        config = CDNConfig(patch_file_index="aabb1122")
        indices = config.get_patch_file_indices()
        assert len(indices) == 1
        assert indices[0].content_key == "aabb1122"
        assert indices[0].index_size is None

    def test_get_patch_file_indices_empty(self):
        """Test patch file indices returns empty list when missing."""
        config = CDNConfig()
        assert config.get_patch_file_indices() == []

    def test_get_file_index_size(self):
        """Test file index size accessor."""
        config = CDNConfig(file_index_size="12345")
        assert config.get_file_index_size() == 12345

    def test_round_trip_with_patch_file_index(self):
        """Test round-trip with patch file index fields."""
        original = CDNConfig(
            archives=["arch1"],
            patch_file_index="pfi1 pfi2",
            patch_file_index_size="1000 2000",
            file_index="fi1",
            file_index_size="500",
        )

        parser = CDNConfigParser()
        data = parser.build(original)
        reparsed = parser.parse(data)

        assert reparsed.patch_file_index == original.patch_file_index
        assert reparsed.patch_file_index_size == original.patch_file_index_size
        assert reparsed.file_index == original.file_index
        assert reparsed.file_index_size == original.file_index_size

        indices = reparsed.get_patch_file_indices()
        assert len(indices) == 2
        assert indices[0].index_size == 1000

    def test_round_trip_archives_index_size(self):
        """Test round-trip with archives-index-size field."""
        original = CDNConfig(
            archives=["arch1", "arch2"],
            archives_index_size="100 200",
        )

        parser = CDNConfigParser()
        data = parser.build(original)
        reparsed = parser.parse(data)

        assert reparsed.archives_index_size == "100 200"

    def test_build_field_order(self):
        """Test CDN builder outputs fields in canonical order."""
        config = CDNConfig(
            archives=["arch1"],
            archive_group="group1",
            patch_archives=["parch1"],
            file_index="fi1",
            file_index_size="500",
            patch_file_index="pfi1",
            patch_file_index_size="1000",
        )

        parser = CDNConfigParser()
        data = parser.build(config).decode('utf-8')
        lines = [line for line in data.strip().split('\n') if line]

        keys = [line.split(' = ', 1)[0] for line in lines]
        assert keys.index('archives') < keys.index('archive-group')
        assert keys.index('patch-archives') < keys.index('file-index')
        assert keys.index('file-index') < keys.index('file-index-size')
        assert keys.index('file-index-size') < keys.index('patch-file-index')
        assert keys.index('patch-file-index') < keys.index('patch-file-index-size')
