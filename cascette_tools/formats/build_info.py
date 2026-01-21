"""Parser and builder for .build.info files.

The .build.info file is used by Battle.net installations to track
the current build configuration and selected installation options.

Format:
- Line 1: Header with column definitions (Name!TYPE:size)
- Line 2+: Data rows with pipe-separated values

Field types:
- STRING:0 - Variable-length string
- HEX:16 - Hex-encoded data (16 bytes = 32 hex chars for hashes)
- DEC:1, DEC:4 - Decimal integer with byte size
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.core.types import LocaleConfig
from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class FieldType(str, Enum):
    """Types for .build.info fields."""

    STRING = "STRING"
    HEX = "HEX"
    DEC = "DEC"


class FieldDefinition(BaseModel):
    """Definition of a .build.info column."""

    name: str = Field(..., description="Column name")
    field_type: FieldType = Field(..., description="Field data type")
    size: int = Field(default=0, description="Size hint (bytes for HEX/DEC)")


class LocalBuildInfo(BaseModel):
    """Complete .build.info file representation.

    This model represents the full contents of a .build.info file,
    including both raw values and parsed tag data.
    """

    # Core configuration fields
    branch: str = Field(default="", description="Branch/region code (e.g., 'us')")
    active: int = Field(default=1, description="Whether this config is active")
    build_key: str = Field(default="", description="Build config hash")
    cdn_key: str = Field(default="", description="CDN config hash")
    install_key: str = Field(default="", description="Install manifest hash")
    im_size: int | None = Field(default=None, description="Install manifest size")
    cdn_path: str = Field(default="", description="CDN path prefix")
    cdn_hosts: str = Field(default="", description="CDN hostnames (space-separated)")
    cdn_servers: str = Field(default="", description="CDN server URLs (space-separated)")
    tags: str = Field(default="", description="Raw tag string")
    armadillo: str = Field(default="", description="Armadillo anti-cheat identifier")
    last_activated: str = Field(default="", description="Last activation timestamp")
    version: str = Field(default="", description="Version string (e.g., '1.15.8.65300')")
    keyring: str = Field(default="", description="Keyring hash")
    product: str = Field(default="", description="Product code (e.g., 'wow_classic_era')")

    # Parsed tag data (computed from 'tags' field)
    platform: str | None = Field(default=None, description="Target platform (e.g., Windows)")
    architecture: str | None = Field(default=None, description="Target architecture (e.g., x86_64)")
    locale_configs: list[LocaleConfig] = Field(  # pyright: ignore[reportUnknownVariableType]
        default_factory=list, description="Installed locale configurations"
    )
    region: str | None = Field(default=None, description="Target region (e.g., EU)")


# Standard header used by Battle.net installations
STANDARD_HEADER = (
    "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
    "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
    "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|"
    "Version!STRING:0|KeyRing!HEX:16|Product!STRING:0"
)

# Field name mapping (header name -> model attribute)
FIELD_NAME_MAP = {
    "Branch": "branch",
    "Active": "active",
    "Build Key": "build_key",
    "CDN Key": "cdn_key",
    "Install Key": "install_key",
    "IM Size": "im_size",
    "CDN Path": "cdn_path",
    "CDN Hosts": "cdn_hosts",
    "CDN Servers": "cdn_servers",
    "Tags": "tags",
    "Armadillo": "armadillo",
    "Last Activated": "last_activated",
    "Version": "version",
    "KeyRing": "keyring",
    "Product": "product",
}

# Reverse mapping for building
ATTR_NAME_MAP = {v: k for k, v in FIELD_NAME_MAP.items()}


def parse_header(header_line: str) -> list[FieldDefinition]:
    """Parse .build.info header line into field definitions.

    Args:
        header_line: Header line (e.g., "Branch!STRING:0|Active!DEC:1|...")

    Returns:
        List of field definitions in order
    """
    fields = []
    for field_spec in header_line.split("|"):
        if not field_spec:
            continue
        # Format: Name!TYPE:size
        match = re.match(r"(.+)!(\w+):(\d+)", field_spec)
        if match:
            name, type_str, size = match.groups()
            try:
                field_type = FieldType(type_str)
            except ValueError:
                field_type = FieldType.STRING
            fields.append(
                FieldDefinition(name=name, field_type=field_type, size=int(size))
            )
        else:
            # Handle fields without proper format
            fields.append(FieldDefinition(name=field_spec, field_type=FieldType.STRING, size=0))
    return fields


def parse_tags(tags_str: str) -> tuple[str | None, str | None, list[LocaleConfig], str | None]:
    """Parse tags string into structured components.

    The tags field has format like:
    "Windows x86_64 EU? enUS speech?:Windows x86_64 EU? enUS text?"

    Args:
        tags_str: Raw tags string

    Returns:
        Tuple of (platform, architecture, locale_configs, region)
    """
    platform: str | None = None
    architecture: str | None = None
    region: str | None = None
    locale_order: list[str] = []
    locale_map: dict[str, LocaleConfig] = {}

    # Extract platform
    platform_match = re.search(r"\b(Windows|OSX|Android|iOS|PS5|Web|XBSX)\b", tags_str)
    if platform_match:
        platform = platform_match.group(1)

    # Extract architecture
    arch_match = re.search(r"\b(x86_64|x86_32|arm64)\b", tags_str)
    if arch_match:
        architecture = arch_match.group(1)

    # Parse locale configurations from colon-separated groups
    locale_pattern = re.compile(r"\b(enUS|deDE|esES|esMX|frFR|koKR|ptBR|ruRU|zhCN|zhTW)\b")
    for group in tags_str.split(":"):
        locale_match = locale_pattern.search(group)
        if locale_match:
            code = locale_match.group(1)
            if code not in locale_map:
                locale_map[code] = LocaleConfig(code=code)
                locale_order.append(code)
            # Check for speech/text flags
            if re.search(r"\bspeech\b", group, re.IGNORECASE):
                locale_map[code].has_speech = True
            if re.search(r"\btext\b", group, re.IGNORECASE):
                locale_map[code].has_text = True

    # Extract region
    region_match = re.search(r"\b(US|EU|KR|TW|CN)\b", tags_str)
    if region_match:
        region = region_match.group(1)

    locale_configs = [locale_map[code] for code in locale_order]
    return platform, architecture, locale_configs, region


def build_tags_string(
    platform: str,
    architecture: str,
    locale: str,
    region: str,
    has_speech: bool = True,
    has_text: bool = True,
) -> str:
    """Build a tags string from components.

    Args:
        platform: Platform name (e.g., "Windows")
        architecture: Architecture (e.g., "x86_64")
        locale: Locale code (e.g., "enUS")
        region: Region code (e.g., "us")
        has_speech: Include speech audio
        has_text: Include text/UI

    Returns:
        Formatted tags string
    """
    region_upper = region.upper()
    groups = []
    if has_speech:
        groups.append(f"{platform} {architecture} {region_upper}? {locale} speech?")
    if has_text:
        groups.append(f"{platform} {architecture} {region_upper}? {locale} text?")
    return ":".join(groups)


class BuildInfoParser(FormatParser[LocalBuildInfo]):
    """Parser for .build.info files."""

    def parse(self, data: bytes | BinaryIO) -> LocalBuildInfo:
        """Parse .build.info data.

        Args:
            data: Binary data or stream

        Returns:
            Parsed LocalBuildInfo
        """
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data.read().decode("utf-8", errors="replace")

        lines = text.strip().split("\n")
        if len(lines) < 2:
            logger.warning("Insufficient lines in .build.info", line_count=len(lines))
            return LocalBuildInfo()

        # Parse header
        fields = parse_header(lines[0])

        # Parse first data line (typically only one data line)
        values = lines[1].split("|")

        # Build kwargs for LocalBuildInfo
        kwargs: dict[str, str | int | None] = {}
        for i, field in enumerate(fields):
            if i >= len(values):
                break

            value = values[i]
            attr_name = FIELD_NAME_MAP.get(field.name)
            if not attr_name:
                continue

            # Convert based on type
            if field.field_type == FieldType.DEC:
                if value:
                    try:
                        kwargs[attr_name] = int(value)
                    except ValueError:
                        kwargs[attr_name] = None
                else:
                    kwargs[attr_name] = None
            else:
                kwargs[attr_name] = value

        # Create base object
        info = LocalBuildInfo(**kwargs)

        # Parse tags into structured data
        if info.tags:
            platform, arch, locale_configs, region = parse_tags(info.tags)
            info.platform = platform
            info.architecture = arch
            info.locale_configs = locale_configs
            info.region = region

        return info

    def build(self, obj: LocalBuildInfo) -> bytes:
        """Build .build.info binary data.

        Args:
            obj: LocalBuildInfo object

        Returns:
            Binary .build.info content
        """
        # Parse header to get field order
        fields = parse_header(STANDARD_HEADER)

        # Build data line
        values: list[str] = []
        for field in fields:
            attr_name = FIELD_NAME_MAP.get(field.name, "")
            if not attr_name:
                values.append("")
                continue

            value = getattr(obj, attr_name, None)
            if value is None:
                values.append("")
            elif isinstance(value, int):
                values.append(str(value))
            else:
                values.append(str(value))

        data_line = "|".join(values)
        content = f"{STANDARD_HEADER}\n{data_line}\n"
        return content.encode("utf-8")

    def parse_file(self, path: str) -> LocalBuildInfo:
        """Parse .build.info from file path.

        Args:
            path: File path

        Returns:
            Parsed LocalBuildInfo
        """
        try:
            with open(path, "rb") as f:
                return self.parse(f)
        except OSError as e:
            logger.error("Failed to read .build.info", path=path, error=str(e))
            raise ValueError(f"Cannot read file {path}: {e}") from e


def create_build_info(
    branch: str,
    build_config_hash: str,
    cdn_config_hash: str,
    cdn_path: str,
    cdn_hosts: list[str],
    version: str,
    product: str,
    platform: str = "Windows",
    architecture: str = "x86_64",
    locale: str = "enUS",
    region: str = "us",
    has_speech: bool = True,
    has_text: bool = True,
    install_key: str = "",
    im_size: int | None = None,
    keyring: str = "",
) -> LocalBuildInfo:
    """Create a new LocalBuildInfo with computed fields.

    This is a convenience function for creating .build.info during installation.

    Args:
        branch: Branch/region code
        build_config_hash: Build config hash
        cdn_config_hash: CDN config hash
        cdn_path: CDN path prefix
        cdn_hosts: List of CDN hostnames
        version: Version string
        product: Product code
        platform: Target platform
        architecture: Target architecture
        locale: Target locale
        region: Target region
        has_speech: Include speech audio
        has_text: Include text/UI
        install_key: Install manifest hash
        im_size: Install manifest size
        keyring: Keyring hash

    Returns:
        Configured LocalBuildInfo
    """
    tags_str = build_tags_string(platform, architecture, locale, region, has_speech, has_text)
    cdn_hosts_str = " ".join(cdn_hosts)

    # Build locale config
    locale_config = LocaleConfig(code=locale, has_speech=has_speech, has_text=has_text)

    return LocalBuildInfo(
        branch=branch,
        active=1,
        build_key=build_config_hash,
        cdn_key=cdn_config_hash,
        install_key=install_key,
        im_size=im_size,
        cdn_path=cdn_path,
        cdn_hosts=cdn_hosts_str,
        cdn_servers=cdn_hosts_str,
        tags=tags_str,
        armadillo="",
        last_activated="",
        version=version,
        keyring=keyring,
        product=product,
        platform=platform,
        architecture=architecture,
        locale_configs=[locale_config],
        region=region.upper(),
    )


def update_last_activated(info: LocalBuildInfo) -> LocalBuildInfo:
    """Update the last_activated timestamp to current time.

    Args:
        info: LocalBuildInfo to update

    Returns:
        Updated LocalBuildInfo with current timestamp
    """
    # Battle.net uses format like "2024-01-15T12:00:00Z"
    now = datetime.now(UTC)
    info.last_activated = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return info
