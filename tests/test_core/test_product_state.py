"""Tests for product state file generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from cascette_tools.core.product_state import (
    ProductInfo,
    encode_varint,
    generate_all_state_files,
    generate_flavor_info,
    generate_launcher_db,
    generate_patch_result,
    generate_product_db,
    get_product_directory_name,
    parse_product_db,
)


@pytest.fixture
def product_info(tmp_path: Path) -> ProductInfo:
    return ProductInfo(
        product_code="wow_classic_era",
        version="1.15.8.65300",
        build_config="e2dc540a98cccb45d764025ab28b703a",
        region="us",
        locale="enUS",
        install_path=tmp_path / "wow_classic_era",
    )


class TestEncodeVarint:
    """Tests for protobuf varint encoding."""

    def test_zero(self) -> None:
        assert encode_varint(0) == b"\x00"

    def test_small_value(self) -> None:
        assert encode_varint(1) == b"\x01"

    def test_max_single_byte(self) -> None:
        assert encode_varint(127) == b"\x7f"

    def test_two_byte_value(self) -> None:
        result = encode_varint(128)
        assert len(result) == 2
        assert result[0] == 0x80
        assert result[1] == 0x01

    def test_larger_value(self) -> None:
        result = encode_varint(300)
        assert len(result) == 2
        # 300 = 0b100101100 -> low 7 bits: 0b0101100 | 0x80, high: 0b10
        assert result[0] == 0xAC
        assert result[1] == 0x02

    def test_large_value(self) -> None:
        result = encode_varint(16384)
        assert len(result) == 3


class TestGetProductDirectoryName:
    """Tests for product directory name mapping."""

    def test_wow_retail(self) -> None:
        assert get_product_directory_name("wow") == "_retail_"

    def test_wow_classic(self) -> None:
        assert get_product_directory_name("wow_classic") == "_classic_"

    def test_wow_classic_era(self) -> None:
        assert get_product_directory_name("wow_classic_era") == "_classic_era_"

    def test_wow_classic_titan(self) -> None:
        assert get_product_directory_name("wow_classic_titan") == "_classic_titan_"

    def test_wow_anniversary(self) -> None:
        assert get_product_directory_name("wow_anniversary") == "_anniversary_"

    def test_wowt(self) -> None:
        assert get_product_directory_name("wowt") == "_ptr_"

    def test_wow_beta(self) -> None:
        assert get_product_directory_name("wow_beta") == "_ptr_"

    def test_agent_returns_none(self) -> None:
        assert get_product_directory_name("agent") is None

    def test_unknown_returns_none(self) -> None:
        assert get_product_directory_name("unknown_product") is None


class TestGenerateProductDb:
    """Tests for .product.db generation."""

    def test_generates_file(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        assert path.exists()
        assert path.name == ".product.db"

    def test_file_not_empty(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        assert path.stat().st_size > 0

    def test_contains_product_code(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        assert b"wow_classic_era" in data

    def test_contains_version(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        assert b"1.15.8.65300" in data

    def test_contains_build_config(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        assert b"e2dc540a98cccb45d764025ab28b703a" in data

    def test_contains_locale(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        assert b"enUS" in data

    def test_contains_region(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        assert b"us" in data

    def test_starts_with_protobuf_tag(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        # Field 1 string tag
        assert data[0] == 0x0A


class TestGenerateLauncherDb:
    """Tests for Launcher.db generation."""

    def test_generates_file(self, tmp_path: Path) -> None:
        path = generate_launcher_db("enUS", tmp_path)
        assert path.exists()
        assert path.name == "Launcher.db"

    def test_contains_locale(self, tmp_path: Path) -> None:
        path = generate_launcher_db("enUS", tmp_path)
        assert path.read_bytes() == b"enUS"

    def test_different_locale(self, tmp_path: Path) -> None:
        path = generate_launcher_db("deDE", tmp_path)
        assert path.read_bytes() == b"deDE"


class TestGeneratePatchResult:
    """Tests for .patch.result generation."""

    def test_generates_file(self, tmp_path: Path) -> None:
        path = generate_patch_result(tmp_path)
        assert path.exists()
        assert path.name == ".patch.result"

    def test_success_byte(self, tmp_path: Path) -> None:
        path = generate_patch_result(tmp_path, success=True)
        assert path.read_bytes() == b"\x01"

    def test_failure_byte(self, tmp_path: Path) -> None:
        path = generate_patch_result(tmp_path, success=False)
        assert path.read_bytes() == b"\x00"


class TestGenerateFlavorInfo:
    """Tests for .flavor.info generation."""

    def test_wow_classic_era(self, tmp_path: Path) -> None:
        path = generate_flavor_info("wow_classic_era", tmp_path)
        assert path is not None
        assert path.exists()
        assert path.name == ".flavor.info"

    def test_creates_product_directory(self, tmp_path: Path) -> None:
        generate_flavor_info("wow_classic_era", tmp_path)
        assert (tmp_path / "_classic_era_").is_dir()

    def test_content_format(self, tmp_path: Path) -> None:
        path = generate_flavor_info("wow_classic_era", tmp_path)
        assert path is not None
        content = path.read_text(encoding="utf-8")
        assert "Product Flavor!STRING:0" in content
        assert "wow_classic_era" in content

    def test_non_wow_product_returns_none(self, tmp_path: Path) -> None:
        result = generate_flavor_info("agent", tmp_path)
        assert result is None

    def test_retail_wow(self, tmp_path: Path) -> None:
        path = generate_flavor_info("wow", tmp_path)
        assert path is not None
        assert (tmp_path / "_retail_").is_dir()


class TestGenerateAllStateFiles:
    """Tests for generating all state files at once."""

    def test_returns_dict(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert isinstance(files, dict)

    def test_contains_product_db(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert ".product.db" in files
        assert files[".product.db"].exists()

    def test_contains_launcher_db(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert "Launcher.db" in files
        assert files["Launcher.db"].exists()

    def test_contains_patch_result(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert ".patch.result" in files
        assert files[".patch.result"].exists()

    def test_contains_flavor_info_for_wow(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert ".flavor.info" in files
        assert files[".flavor.info"].exists()

    def test_no_flavor_info_for_agent(self, tmp_path: Path) -> None:
        info = ProductInfo(
            product_code="agent",
            version="1.0.0",
            build_config="a" * 32,
            region="us",
            locale="enUS",
            install_path=tmp_path,
        )
        files = generate_all_state_files(info, tmp_path)
        assert ".flavor.info" not in files

    def test_file_count_wow(self, product_info: ProductInfo, tmp_path: Path) -> None:
        files = generate_all_state_files(product_info, tmp_path)
        assert len(files) == 4  # product.db, Launcher.db, patch.result, flavor.info


class TestParseProductDb:
    """Tests for .product.db parsing."""

    def test_roundtrip(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        parsed = parse_product_db(data)
        assert parsed["product_code"] == "wow_classic_era"
        assert parsed["product_name"] == "wow_classic_era"

    def test_empty_data(self) -> None:
        result = parse_product_db(b"")
        assert result == {}

    def test_truncated_data(self) -> None:
        # Single byte - not enough for tag + length
        result = parse_product_db(b"\x0a")
        assert result == {}

    def test_install_info_parsed(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        parsed = parse_product_db(data)
        assert "install_info" in parsed

    def test_build_info_parsed(self, product_info: ProductInfo, tmp_path: Path) -> None:
        path = generate_product_db(product_info, tmp_path)
        data = path.read_bytes()
        parsed = parse_product_db(data)
        assert "build_info" in parsed
