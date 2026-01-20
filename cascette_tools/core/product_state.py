"""Product state file generation for Battle.net compatible installations.

This module provides functions to generate the metadata files that Battle.net
creates during installation:
- .product.db: Protobuf database with product info
- Launcher.db: Locale setting (4 bytes)
- .patch.result: Patch operation result (1 byte)
- .flavor.info: Product flavor for WoW games

These files are required for the game client to recognize the installation
as valid and allow launching.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


@dataclass
class ProductInfo:
    """Information needed to generate product state files."""

    product_code: str
    """Product code (e.g., 'wow_classic_era')."""

    version: str
    """Version string (e.g., '1.15.8.65300')."""

    build_config: str
    """Build config hash (32 hex characters)."""

    region: str
    """Region code (e.g., 'us', 'eu')."""

    locale: str
    """Locale code (e.g., 'enUS', 'deDE')."""

    install_path: Path
    """Installation directory path."""


def encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint.

    Args:
        value: Non-negative integer to encode.

    Returns:
        Varint-encoded bytes.
    """
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result) if result else b"\x00"


def _build_install_info_protobuf(
    install_path: Path,
    region: str,
    locale: str,
) -> bytes:
    """Build the install info protobuf structure.

    Args:
        install_path: Installation directory path.
        region: Region code.
        locale: Locale code.

    Returns:
        Serialized protobuf bytes.
    """
    data = bytearray()
    path_str = str(install_path)

    # Field 3: Install path (string) - tag 0x1a
    data.append(0x1A)
    data.append(len(path_str))
    data.extend(path_str.encode("utf-8"))

    # Field 2: Region (string) - tag 0x12
    data.append(0x12)
    data.append(len(region))
    data.extend(region.encode("utf-8"))

    # Field 3: Unknown field (int32) - tag 0x18
    data.append(0x18)
    data.append(0x02)  # Value 2

    # Field 4: Unknown field (int32) - tag 0x20
    data.append(0x20)
    data.append(0x02)  # Value 2

    # Field 5: Unknown field (int32) - tag 0x28
    data.append(0x28)
    data.append(0x03)  # Value 3

    # Field 6: Locale info - tag 0x32
    data.append(0x32)
    data.append(len(locale))
    data.extend(locale.encode("utf-8"))

    # Field 7: Locale info repeated - tag 0x3a
    data.append(0x3A)
    data.append(len(locale))
    data.extend(locale.encode("utf-8"))

    # Field 8: Settings structure - tag 0x42
    settings_len = 2 + len(locale) + 2  # Field 1 + locale + Field 2
    data.append(0x42)
    data.append(settings_len)
    data.append(0x0A)  # Field 1 tag
    data.append(len(locale))
    data.extend(locale.encode("utf-8"))
    data.append(0x10)  # Field 2 tag
    data.append(0x03)  # Value 3

    return bytes(data)


def _build_build_info_protobuf(version: str, build_key: str) -> bytes:
    """Build the build info protobuf structure.

    Args:
        version: Version string.
        build_key: Build config hash.

    Returns:
        Serialized protobuf bytes.
    """
    data = bytearray()

    # Field 1: Some flag (int32) - tag 0x08
    data.extend([0x08, 0x01])  # Value 1

    # Field 2: Some flag (int32) - tag 0x10
    data.extend([0x10, 0x01])  # Value 1

    # Field 3: Some flag (int32) - tag 0x18
    data.extend([0x18, 0x01])  # Value 1

    # Field 4: Some flag (int32) - tag 0x20
    data.extend([0x20, 0x00])  # Value 0

    # Field 5: Some flag (int32) - tag 0x28
    data.extend([0x28, 0x01])  # Value 1

    # Field 7: Version string - tag 0x3a
    data.append(0x3A)
    data.append(len(version))
    data.extend(version.encode("utf-8"))

    # Field 12: Build key (bytes) - tag 0x62
    data.append(0x62)
    data.append(0x20)  # 32 bytes for build key (hex string)
    data.extend(build_key.encode("utf-8"))

    # Field 14: Build key repeated (bytes) - tag 0x72
    data.append(0x72)
    data.append(0x20)  # 32 bytes
    data.extend(build_key.encode("utf-8"))

    # Field 16: Content key (bytes) - tag 0x82 0x01 (varint field number 16)
    # Using a placeholder content key for now
    content_key = "5090256c2742e6652de8aef3641c6eb1"
    data.append(0x82)
    data.append(0x01)  # Varint length prefix continuation
    data.append(0x20)  # 32 bytes
    data.extend(content_key.encode("utf-8"))

    return bytes(data)


def generate_product_db(info: ProductInfo, target_dir: Path) -> Path:
    """Generate .product.db file (Battle.net compatible protobuf).

    The .product.db file contains product metadata in protobuf format:
    - Field 1: Product code
    - Field 2: Product name (same as code)
    - Field 3: Install info structure
    - Field 4: Build info structure

    Args:
        info: Product information.
        target_dir: Target installation directory.

    Returns:
        Path to the generated file.
    """
    logger.info("Generating .product.db", product=info.product_code)

    data = bytearray()
    product_name = info.product_code

    # Field 1: Product code (string) - tag 0x0a
    data.append(0x0A)
    data.append(len(product_name))
    data.extend(product_name.encode("utf-8"))

    # Field 2: Product name (string) - tag 0x12
    data.append(0x12)
    data.append(len(product_name))
    data.extend(product_name.encode("utf-8"))

    # Field 3: Install info structure - tag 0x1a
    install_info = _build_install_info_protobuf(
        info.install_path,
        info.region,
        info.locale,
    )
    data.append(0x1A)
    data.append(len(install_info))
    data.extend(install_info)

    # Field 4: Build info structure - tag 0x22
    build_info = _build_build_info_protobuf(info.version, info.build_config)
    data.append(0x22)
    data.extend(encode_varint(len(build_info)))
    data.extend(build_info)

    product_db_path = target_dir / ".product.db"
    product_db_path.write_bytes(bytes(data))

    logger.info("Generated .product.db", path=str(product_db_path), size=len(data))
    return product_db_path


def generate_launcher_db(locale: str, target_dir: Path) -> Path:
    """Generate Launcher.db file containing locale setting.

    The Launcher.db file contains the locale string as raw bytes.
    Battle.net uses this to track the installation's language setting.

    Args:
        locale: Locale code (e.g., 'enUS').
        target_dir: Target installation directory.

    Returns:
        Path to the generated file.
    """
    logger.info("Generating Launcher.db", locale=locale)

    launcher_db_path = target_dir / "Launcher.db"
    launcher_db_path.write_bytes(locale.encode("utf-8"))

    logger.info("Generated Launcher.db", path=str(launcher_db_path))
    return launcher_db_path


def generate_patch_result(target_dir: Path, success: bool = True) -> Path:
    """Generate .patch.result file indicating patch operation status.

    The .patch.result file contains a single byte indicating the result
    of the last patch operation:
    - 0x01: Success
    - 0x00: Failure

    Args:
        target_dir: Target installation directory.
        success: Whether the patch was successful.

    Returns:
        Path to the generated file.
    """
    logger.info("Generating .patch.result", success=success)

    patch_result_path = target_dir / ".patch.result"
    patch_result_path.write_bytes(b"\x01" if success else b"\x00")

    logger.info("Generated .patch.result", path=str(patch_result_path))
    return patch_result_path


def get_product_directory_name(product_code: str) -> str | None:
    """Get the product-specific directory name for WoW games.

    WoW products use specific subdirectory names for game files:
    - wow -> _retail_
    - wow_classic -> _classic_
    - wow_classic_era -> _classic_era_
    - wowt/wow_beta -> _ptr_

    Other products (agent, bna) don't use subdirectories.

    Args:
        product_code: Product code.

    Returns:
        Directory name or None for non-WoW products.
    """
    mapping = {
        "wow": "_retail_",
        "wow_classic": "_classic_",
        "wow_classic_era": "_classic_era_",
        "wow_classic_ptr": "_classic_ptr_",
        "wowt": "_ptr_",
        "wow_beta": "_ptr_",
    }
    return mapping.get(product_code)


def generate_flavor_info(product_code: str, target_dir: Path) -> Path | None:
    """Generate .flavor.info file for WoW products.

    The .flavor.info file is placed in the product-specific directory
    (e.g., _classic_era_) and contains the product flavor in BPSV format.

    Args:
        product_code: Product code.
        target_dir: Target installation directory.

    Returns:
        Path to the generated file, or None if not a WoW product.
    """
    product_dir_name = get_product_directory_name(product_code)
    if product_dir_name is None:
        logger.debug("Skipping .flavor.info for non-WoW product", product=product_code)
        return None

    logger.info("Generating .flavor.info", product=product_code)

    product_dir = target_dir / product_dir_name
    product_dir.mkdir(parents=True, exist_ok=True)

    flavor_info_path = product_dir / ".flavor.info"
    content = f"Product Flavor!STRING:0\n{product_code}\n"
    flavor_info_path.write_text(content, encoding="utf-8")

    logger.info("Generated .flavor.info", path=str(flavor_info_path))
    return flavor_info_path


def generate_all_state_files(info: ProductInfo, target_dir: Path) -> dict[str, Path]:
    """Generate all product state files for an installation.

    This is a convenience function that generates all required state files:
    - .product.db
    - Launcher.db
    - .patch.result
    - .flavor.info (WoW products only)

    Args:
        info: Product information.
        target_dir: Target installation directory.

    Returns:
        Dictionary mapping file names to their paths.
    """
    logger.info(
        "Generating all product state files",
        product=info.product_code,
        target=str(target_dir),
    )

    files: dict[str, Path] = {}

    files[".product.db"] = generate_product_db(info, target_dir)
    files["Launcher.db"] = generate_launcher_db(info.locale, target_dir)
    files[".patch.result"] = generate_patch_result(target_dir)

    flavor_path = generate_flavor_info(info.product_code, target_dir)
    if flavor_path:
        files[".flavor.info"] = flavor_path

    logger.info("Generated all product state files", count=len(files))
    return files


def parse_product_db(data: bytes) -> dict[str, str | dict[str, int]]:
    """Parse a .product.db file and extract its contents.

    This is useful for analyzing existing Battle.net installations.

    Args:
        data: Raw bytes from .product.db file.

    Returns:
        Dictionary with parsed fields.
    """
    result: dict[str, str | dict[str, int]] = {}
    offset = 0

    while offset < len(data):
        if offset >= len(data):
            break

        # Read field tag
        tag = data[offset]
        offset += 1

        # Read length (simple single-byte for now)
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1

        # Handle varint length for larger fields
        if length & 0x80:
            # Multi-byte varint
            length = length & 0x7F
            shift = 7
            while offset < len(data) and data[offset - 1] & 0x80:
                length |= (data[offset] & 0x7F) << shift
                shift += 7
                offset += 1

        if offset + length > len(data):
            break

        field_data = data[offset : offset + length]
        offset += length

        # Decode based on tag
        if tag == 0x0A:
            result["product_code"] = field_data.decode("utf-8", errors="replace")
        elif tag == 0x12:
            result["product_name"] = field_data.decode("utf-8", errors="replace")
        elif tag == 0x1A:
            result["install_info"] = {"raw_length": len(field_data)}
        elif tag == 0x22:
            result["build_info"] = {"raw_length": len(field_data)}

    return result
