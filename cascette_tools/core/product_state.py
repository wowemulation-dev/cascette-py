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

    game_subfolder: str | None = None
    """Product subfolder (e.g., '_classic_'). Stored in UserSettings field 13."""

    account_country: str | None = None
    """Account country code (e.g., 'BGR'). Stored in UserSettings field 11."""

    geo_ip_country: str | None = None
    """Geo-IP country code (e.g., 'BG'). Stored in UserSettings field 12."""

    install_key: str | None = None
    """Install manifest encoding key. Stored in BaseProductState field 16."""

    tags: str = ""
    """Compound tag string. Stored in BaseProductState field 17."""

    total_downloaded: int = 0
    """Bytes downloaded during install. Stored in UpdateProgress field 4."""


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


def generate_product_db(info: ProductInfo, target_dir: Path) -> Path:
    """Generate .product.db file matching Agent.exe output.

    Serializes a ``proto_database.ProductInstall`` protobuf message, the
    same structure the Battle.net Agent writes to per-install
    ``.product.db`` files. The schema is defined in
    ``proto/proto_database.proto`` (compiled to
    ``cascette_tools/proto/proto_database_pb2.py``), matching
    battle.net-agent's ``proto_database.proto`` and cascette-rs's
    ``layout/product_db.rs``.

    Args:
        info: Product information.
        target_dir: Target installation directory.

    Returns:
        Path to the generated file.
    """
    from cascette_tools.proto import proto_database_pb2 as pd

    logger.info("Generating .product.db", product=info.product_code)

    msg = pd.ProductInstall()
    msg.uid = info.product_code
    msg.productCode = info.product_code

    s = msg.settings
    s.install_path = str(info.install_path)
    s.play_region = info.region
    s.desktop_shortcut = pd.SHORTCUT_ALL_USERS
    s.startmenu_shortcut = pd.SHORTCUT_ALL_USERS
    s.language_settings = pd.LANGSETTING_ADVANCED
    s.selected_text_language = info.locale
    s.selected_speech_language = info.locale
    lang = s.languages.add()
    lang.language = info.locale
    lang.option = pd.LANGOPTION_TEXT_AND_SPEECH
    s.additional_tags = ""
    s.version_branch = ""
    if info.account_country:
        s.account_country = info.account_country
    if info.geo_ip_country:
        s.geo_ip_country = info.geo_ip_country
    if info.game_subfolder:
        s.game_subfolder = info.game_subfolder

    b = msg.cachedProductState.baseProductState
    b.installed = True
    b.playable = True
    b.updateComplete = True
    b.backgroundDownloadAvailable = False
    b.backgroundDownloadComplete = True
    b.currentVersionStr = info.version
    b.decryptionKey = ""
    b.completedBuildKeys.append(info.build_config)
    b.activeBuildKey = info.build_config
    if info.install_key:
        b.activeInstallKey = info.install_key
    b.activeTagString = info.tags

    bp = msg.cachedProductState.backfillProgress
    bp.progress = 0.0
    bp.backgrounddownload = False
    bp.paused = False

    rp = msg.cachedProductState.repairProgress
    rp.progress = 0.0

    up = msg.cachedProductState.updateProgress
    up.lastDiscSetUsed = ""
    up.progress = 1.0
    up.discIgnored = False
    up.totalToDownload = info.total_downloaded
    up.downloadRemaining = 0

    # productFamily: first path component of the product code
    # ("wow_classic" -> "wow"), matching cascette-rs.
    msg.productFamily = (
        info.product_code.split("_")[0]
        if "_" in info.product_code
        else info.product_code
    )
    msg.hidden = False

    data = msg.SerializeToString()
    product_db_path = target_dir / ".product.db"
    product_db_path.write_bytes(data)

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

    The client reads this file at the installation root on startup. Writing
    ASCII "0" signals that no update is pending; a missing or non-zero file
    makes the client contact the live patch server and show an update
    dialog. Matches the reference install ("0\n") and cascette-rs (b"0").

    Args:
        target_dir: Target installation directory.
        success: Whether the patch was successful (kept for API parity;
            a successful install always writes "0").

    Returns:
        Path to the generated file.
    """
    logger.info("Generating .patch.result", success=success)

    patch_result_path = target_dir / ".patch.result"
    patch_result_path.write_bytes(b"0\n")

    logger.info("Generated .patch.result", path=str(patch_result_path))
    return patch_result_path


def get_product_directory_name(product_code: str) -> str | None:
    """Get the product-specific directory name for WoW games.

    WoW products use specific subdirectory names for game files:
    - wow -> _retail_
    - wow_classic -> _classic_
    - wow_classic_era -> _classic_era_
    - wow_classic_titan -> _classic_titan_
    - wow_anniversary -> _anniversary_
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
        "wow_classic_titan": "_classic_titan_",
        "wow_anniversary": "_anniversary_",
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
