"""Installation state analyzer for NGDP/CASC installations.

This module provides tools to analyze Battle.net product installations,
calculate progress, and understand what needs to be downloaded for
a full installation.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

import click
import structlog
from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.config import AppConfig, CDNConfig
from cascette_tools.core.local_storage import (
    LocalIndexEntry,
    parse_local_idx_file,
)
from cascette_tools.core.types import Product
from cascette_tools.core.utils import format_size
from cascette_tools.formats.config import BuildConfigParser
from cascette_tools.formats.download import DownloadParser

logger = structlog.get_logger()


class LocaleConfig(BaseModel):
    """Configuration for a single installed locale."""

    code: str = Field(description="Locale code (e.g., enUS)")
    has_speech: bool = Field(default=False, description="Speech audio installed")
    has_text: bool = Field(default=False, description="Text/UI installed")

    def display(self) -> str:
        """Format locale with content flags."""
        flags: list[str] = []
        if self.has_speech:
            flags.append("speech")
        if self.has_text:
            flags.append("text")
        if flags:
            return f"{self.code} ({', '.join(flags)})"
        return self.code


class BuildInfoTags(BaseModel):
    """Tags parsed from .build.info file."""

    platform: str | None = Field(default=None, description="Target platform (e.g., Windows)")
    architecture: str | None = Field(default=None, description="Target architecture (e.g., x86_64)")
    locale_configs: list[LocaleConfig] = Field(default_factory=list, description="Installed locale configurations")  # pyright: ignore[reportUnknownVariableType]
    region: str | None = Field(default=None, description="Target region (e.g., EU)")
    raw_tags: str = Field(default="", description="Raw tag string from .build.info")

    @property
    def locales(self) -> list[str]:
        """List of locale codes for backward compatibility."""
        return [lc.code for lc in self.locale_configs]

    @property
    def locale(self) -> str | None:
        """Primary locale (first in list) for backward compatibility."""
        return self.locale_configs[0].code if self.locale_configs else None

    @property
    def locale_display(self) -> str:
        """Format all locales with content flags for display."""
        if not self.locale_configs:
            return ""
        return ", ".join(lc.display() for lc in self.locale_configs)


def parse_build_info_tags(install_path: Path) -> BuildInfoTags:
    """Parse tags from .build.info file.

    The .build.info file contains a Tags field with format like:
    "Windows x86_64 EU? acct-DEU? geoip-TH? enUS speech?:Windows x86_64 EU? ..."

    Args:
        install_path: Path to installation root

    Returns:
        BuildInfoTags with parsed platform, arch, locale, region
    """
    build_info_path = install_path / ".build.info"
    if not build_info_path.exists():
        return BuildInfoTags()

    try:
        content = build_info_path.read_text()
        lines = content.strip().split('\n')
        if len(lines) < 2:
            return BuildInfoTags()

        # Parse header to find Tags column
        headers = lines[0].split('|')
        tag_col_idx = None
        for i, header in enumerate(headers):
            if header.startswith('Tags'):
                tag_col_idx = i
                break

        if tag_col_idx is None:
            return BuildInfoTags()

        # Parse data line
        data = lines[1].split('|')
        if tag_col_idx >= len(data):
            return BuildInfoTags()

        raw_tags = data[tag_col_idx]
        tags = BuildInfoTags(raw_tags=raw_tags)

        # Extract platform
        platform_match = re.search(r'\b(Windows|OSX|Android|iOS|PS5|Web|XBSX)\b', raw_tags)
        if platform_match:
            tags.platform = platform_match.group(1)

        # Extract architecture
        arch_match = re.search(r'\b(x86_64|x86_32|arm64)\b', raw_tags)
        if arch_match:
            tags.architecture = arch_match.group(1)

        # Parse locale configurations from colon-separated groups
        # Each group format: "Windows x86_64 EU? ... locale speech?" or "... locale text?"
        locale_order: list[str] = []
        locale_map: dict[str, LocaleConfig] = {}
        locale_pattern = re.compile(r'\b(enUS|deDE|esES|esMX|frFR|koKR|ptBR|ruRU|zhCN|zhTW)\b')
        for group in raw_tags.split(':'):
            locale_match = locale_pattern.search(group)
            if locale_match:
                code = locale_match.group(1)
                if code not in locale_map:
                    locale_map[code] = LocaleConfig(code=code)
                    locale_order.append(code)
                # Check for speech/text flags (with or without ?)
                if re.search(r'\bspeech\b', group, re.IGNORECASE):
                    locale_map[code].has_speech = True
                if re.search(r'\btext\b', group, re.IGNORECASE):
                    locale_map[code].has_text = True
        # Build ordered list of locale configs
        tags.locale_configs = [locale_map[code] for code in locale_order]

        # Extract region
        region_match = re.search(r'\b(US|EU|KR|TW|CN)\b', raw_tags)
        if region_match:
            tags.region = region_match.group(1)

        return tags

    except Exception as e:
        logger.warning(f"Failed to parse .build.info tags: {e}")
        return BuildInfoTags()


class InstallationState(BaseModel):
    """Represents the current state of an installation."""

    install_path: Path = Field(description="Installation root path")
    product_code: str = Field(description="Product code (e.g., wow_classic_era)")
    build_config_hash: str | None = Field(default=None, description="Build config hash")
    cdn_config_hash: str | None = Field(default=None, description="CDN config hash")
    local_entries: dict[str, LocalIndexEntry] = Field(default_factory=dict, description="Local idx entries by hex key")
    local_data_size: int = Field(default=0, description="Total size of local .data files")
    local_entry_count: int = Field(default=0, description="Total number of local entries")
    tags: BuildInfoTags = Field(default_factory=BuildInfoTags, description="Tags from .build.info")


class InstallationProgress(BaseModel):
    """Progress information for an installation."""

    total_entries: int = Field(description="Total entries needed")
    downloaded_entries: int = Field(description="Entries already downloaded")
    total_size: int = Field(description="Total size needed in bytes")
    downloaded_size: int = Field(description="Size already downloaded")
    priority_breakdown: dict[int, dict[str, int | float]] = Field(description="Breakdown by priority level")
    missing_entries: list[str] = Field(default_factory=list, description="Missing encoding keys (first 100)")
    tags_used: BuildInfoTags | None = Field(default=None, description="Tags used for filtering")


def scan_local_installation(install_path: Path, product_code: str) -> InstallationState:
    """Scan a local installation and gather state information.

    Args:
        install_path: Path to installation root (e.g., World of Warcraft/)
        product_code: Product sub-folder (e.g., wow_classic_era)

    Returns:
        InstallationState with all local information
    """
    state = InstallationState(
        install_path=install_path,
        product_code=product_code
    )

    # Parse tags from .build.info
    state.tags = parse_build_info_tags(install_path)
    if state.tags.platform:
        logger.info(f"Detected tags: {state.tags.platform} {state.tags.architecture} {state.tags.locale_display}")

    # Find the data directory
    # Structure: install_path/Data/{product_code}/
    data_path = install_path / "Data" / product_code

    if not data_path.exists():
        # Try direct Data folder
        data_path = install_path / "Data"

    logger.info(f"Scanning installation at {data_path}")

    # Read config files to get build/cdn config hashes
    config_path = data_path / "config" if (data_path / "config").exists() else install_path / "Data" / "config"
    if config_path.exists():
        for config_file in config_path.rglob("*"):
            if config_file.is_file() and len(config_file.name) == 32:
                # This is likely a config file (32 char hex name)
                state.build_config_hash = config_file.name
                logger.debug(f"Found config: {config_file.name}")
                break

    # Scan local .idx files using the V7 format parser from local_storage
    # Local idx files are in Data/data/ or Data/{product}/
    idx_locations = [
        data_path,
        data_path / "data",
        install_path / "Data" / "data",
    ]

    for idx_dir in idx_locations:
        if not idx_dir.exists():
            continue

        for idx_file in idx_dir.glob("*.idx"):
            if not idx_file.is_file():
                continue

            try:
                # Extract bucket from filename (e.g., 0000000001.idx -> bucket 0x00)
                name = idx_file.stem
                if len(name) == 10 and name.isalnum():
                    idx_data = idx_file.read_bytes()
                    idx_info = parse_local_idx_file(idx_data)

                    for entry in idx_info.entries:
                        hex_key = entry.key.hex()
                        state.local_entries[hex_key] = entry

                    logger.debug(f"Parsed {idx_file.name}: {len(idx_info.entries)} entries (v{idx_info.version})")

            except Exception as e:
                logger.warning(f"Failed to parse {idx_file}: {e}")

    state.local_entry_count = len(state.local_entries)

    # Calculate total data file sizes
    data_file_dirs = [
        data_path,
        data_path / "data",
        install_path / "Data" / "data",
    ]

    for data_dir in data_file_dirs:
        if not data_dir.exists():
            continue

        for data_file in data_dir.glob("data.*"):
            if data_file.is_file():
                state.local_data_size += data_file.stat().st_size

    logger.info(f"Found {state.local_entry_count} local entries, {format_size(state.local_data_size)} data")

    return state


def filter_entries_by_build_info_tags(
    entries: list[Any],
    manifest_tags: list[Any],
    build_info_tags: BuildInfoTags,
) -> list[Any]:
    """Filter download manifest entries by tags from .build.info.

    Uses the platform, architecture, and locale from the installation's
    .build.info file to filter entries, matching Battle.net's behavior.

    Args:
        entries: Download manifest entries
        manifest_tags: Tag definitions from the download manifest
        build_info_tags: Tags parsed from .build.info

    Returns:
        Filtered list of entries matching the installation's configuration
    """
    # Define tag categories
    platform_tags = {"Windows", "OSX", "Android", "iOS", "PS5", "Web", "XBSX"}
    arch_tags = {"x86_32", "x86_64", "arm64"}
    locale_tags = {"enUS", "deDE", "esES", "esMX", "frFR", "koKR", "ptBR", "ruRU", "zhCN", "zhTW"}

    # Build tag filter from .build.info
    required_tags: list[str] = []
    if build_info_tags.platform:
        required_tags.append(build_info_tags.platform)
    if build_info_tags.architecture:
        required_tags.append(build_info_tags.architecture)
    if build_info_tags.locale:
        required_tags.append(build_info_tags.locale)

    if not required_tags:
        # No tags to filter by, return all entries
        return entries

    filtered: list[Any] = []
    for entry in entries:
        entry_tags = set(entry.tags)

        # Check platform: if entry has platform tags, it must match
        entry_platform_tags = entry_tags & platform_tags
        if entry_platform_tags and build_info_tags.platform:
            if build_info_tags.platform not in entry_platform_tags:
                continue

        # Check architecture: if entry has arch tags, it must match
        entry_arch_tags = entry_tags & arch_tags
        if entry_arch_tags and build_info_tags.architecture:
            if build_info_tags.architecture not in entry_arch_tags:
                continue

        # Check locale: if entry has locale tags, it must match
        entry_locale_tags = entry_tags & locale_tags
        if entry_locale_tags and build_info_tags.locale:
            if build_info_tags.locale not in entry_locale_tags:
                continue

        filtered.append(entry)

    return filtered


def calculate_progress(
    state: InstallationState,
    download_manifest: Any,  # DownloadFile
    tags: list[str] | None = None,
    use_build_info_tags: bool = True,
) -> InstallationProgress:
    """Calculate installation progress by comparing local state to download manifest.

    By default, uses tags from .build.info to filter entries, matching how
    Battle.net calculates progress for the installed configuration.

    Args:
        state: Current local installation state (includes .build.info tags)
        download_manifest: Parsed download manifest
        tags: Optional explicit list of tags to filter by
        use_build_info_tags: If True and no explicit tags, use tags from .build.info

    Returns:
        InstallationProgress with detailed breakdown
    """
    # Determine which tags to use for filtering
    entries = download_manifest.entries
    tags_used = None

    if tags:
        # Explicit tags provided
        entries = [e for e in entries if any(t in e.tags for t in tags)]
        tags_used = BuildInfoTags(raw_tags=", ".join(tags))
    elif use_build_info_tags and state.tags.platform:
        # Use tags from .build.info
        entries = filter_entries_by_build_info_tags(
            entries, download_manifest.tags, state.tags
        )
        tags_used = state.tags

    # Group by priority
    priority_groups: dict[int, list[Any]] = defaultdict(list)
    for entry in entries:
        priority_groups[entry.priority].append(entry)

    # Calculate progress
    total_entries = len(entries)
    total_size = sum(e.size for e in entries)

    downloaded_entries = 0
    downloaded_size = 0
    missing: list[str] = []

    priority_breakdown: dict[int, dict[str, int | float]] = {}

    for priority in sorted(priority_groups.keys()):
        group = priority_groups[priority]
        group_total = len(group)
        group_size = sum(e.size for e in group)
        group_downloaded = 0
        group_downloaded_size = 0

        for entry in group:
            # Truncate encoding key to 9 bytes for comparison
            truncated_key = entry.ekey[:9].hex()

            if truncated_key in state.local_entries:
                group_downloaded += 1
                group_downloaded_size += entry.size
                downloaded_entries += 1
                downloaded_size += entry.size
            else:
                if len(missing) < 100:
                    missing.append(entry.ekey.hex())

        priority_breakdown[priority] = {
            "total_entries": group_total,
            "downloaded_entries": group_downloaded,
            "total_size": group_size,
            "downloaded_size": group_downloaded_size,
            "percent": (group_downloaded / group_total * 100) if group_total > 0 else 0
        }

    return InstallationProgress(
        total_entries=total_entries,
        downloaded_entries=downloaded_entries,
        total_size=total_size,
        downloaded_size=downloaded_size,
        priority_breakdown=priority_breakdown,
        missing_entries=missing,
        tags_used=tags_used,
    )


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


@click.group()
def install_state() -> None:
    """Analyze installation state and progress."""
    pass


@install_state.command()
@click.argument("install_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--product", "-p",
    type=str,
    default="wow_classic_era",
    help="Product code (e.g., wow_classic_era)"
)
@click.pass_context
def scan(ctx: click.Context, install_path: Path, product: str) -> None:
    """Scan a local installation and show current state.

    INSTALL_PATH is the root of the game installation (e.g., /path/to/World of Warcraft).
    """
    _config, console, verbose, _ = _get_context_objects(ctx)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description="Scanning installation...", total=None)
            state = scan_local_installation(install_path, product)

        # Display results
        table = Table(title="Local Installation State")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Install Path", str(state.install_path))
        table.add_row("Product Code", state.product_code)
        table.add_row("Build Config", state.build_config_hash or "Not found")
        table.add_row("Local Entries", f"{state.local_entry_count:,}")
        table.add_row("Local Data Size", format_size(state.local_data_size))

        # Display tags from .build.info
        if state.tags.platform:
            tags_str = f"{state.tags.platform} {state.tags.architecture or ''} {state.tags.locale_display}"
            table.add_row("Installed Config", tags_str.strip())
        else:
            table.add_row("Installed Config", "Not detected (no .build.info)")

        console.print(table)

        if verbose and state.local_entries:
            # Show sample entries
            sample_table = Table(title="Sample Local Entries (first 10)")
            sample_table.add_column("Key (truncated)", style="yellow")
            sample_table.add_column("Archive", style="blue")
            sample_table.add_column("Size", style="green")

            for key, entry in list(state.local_entries.items())[:10]:
                sample_table.add_row(key, f"data.{entry.archive_id:03d}", format_size(entry.size))

            console.print(sample_table)

    except Exception as e:
        logger.error("Failed to scan installation", error=str(e))
        raise click.ClickException(f"Failed to scan installation: {e}") from e


@install_state.command()
@click.argument("install_path", type=click.Path(exists=True, path_type=Path))
@click.argument("download_hash", type=str)
@click.option(
    "--product", "-p",
    type=str,
    default="wow_classic_era",
    help="Product code (e.g., wow_classic_era)"
)
@click.option(
    "--tags", "-t",
    type=str,
    multiple=True,
    help="Tags to filter by (e.g., Windows, enUS)"
)
@click.pass_context
def progress(
    ctx: click.Context,
    install_path: Path,
    download_hash: str,
    product: str,
    tags: tuple[str, ...]
) -> None:
    """Calculate installation progress against download manifest.

    INSTALL_PATH is the game installation root.
    DOWNLOAD_HASH is the download manifest hash from build config.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Scan local installation
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as prog:
            prog.add_task(description="Scanning local installation...", total=None)
            state = scan_local_installation(install_path, product)

        # Fetch download manifest from CDN
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as prog:
            prog.add_task(description="Fetching download manifest...", total=None)

            cdn_config = CDNConfig(
                timeout=config.cdn_timeout,
                max_retries=config.cdn_max_retries
            )
            cdn_client = CDNClient(Product.WOW, config=cdn_config)
            download_data = cdn_client.fetch_data(download_hash)

        # Parse download manifest
        parser = DownloadParser()
        download_manifest = parser.parse(download_data)

        # Calculate progress
        tag_list = list(tags) if tags else None
        prog_result = calculate_progress(state, download_manifest, tag_list)

        # Display results
        overall_pct = (prog_result.downloaded_size / prog_result.total_size * 100) if prog_result.total_size > 0 else 0

        summary_table = Table(title="Installation Progress")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")

        summary_table.add_row("Total Entries", f"{prog_result.total_entries:,}")
        summary_table.add_row("Downloaded Entries", f"{prog_result.downloaded_entries:,}")
        summary_table.add_row("Total Size", format_size(prog_result.total_size))
        summary_table.add_row("Downloaded Size", format_size(prog_result.downloaded_size))
        summary_table.add_row("Overall Progress", f"{overall_pct:.1f}%")

        console.print(summary_table)

        # Priority breakdown
        priority_table = Table(title="Progress by Priority Level")
        priority_table.add_column("Priority", style="cyan")
        priority_table.add_column("Entries", style="white")
        priority_table.add_column("Size", style="green")
        priority_table.add_column("Progress", style="yellow")

        for priority in sorted(prog_result.priority_breakdown.keys()):
            breakdown = prog_result.priority_breakdown[priority]
            priority_table.add_row(
                str(priority),
                f"{breakdown['downloaded_entries']:,}/{breakdown['total_entries']:,}",
                f"{format_size(int(breakdown['downloaded_size']))}/{format_size(int(breakdown['total_size']))}",
                f"{breakdown['percent']:.1f}%"
            )

        console.print(priority_table)

        if verbose and prog_result.missing_entries:
            console.print("\n[yellow]First 10 missing entries:[/yellow]")
            for key in prog_result.missing_entries[:10]:
                console.print(f"  {key}")

    except Exception as e:
        logger.error("Failed to calculate progress", error=str(e))
        raise click.ClickException(f"Failed to calculate progress: {e}") from e


@install_state.command()
@click.argument("build_config_path", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def show_config(ctx: click.Context, build_config_path: Path) -> None:
    """Parse and display a build config file.

    BUILD_CONFIG_PATH is the path to a build config file.
    """
    _config, console, _verbose, _ = _get_context_objects(ctx)

    try:
        data = build_config_path.read_bytes()
        parser = BuildConfigParser()
        build_config = parser.parse(data)

        table = Table(title="Build Configuration")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")

        # Show key fields
        if hasattr(build_config, 'model_dump'):
            for key, value in build_config.model_dump().items():
                if value is not None:
                    if isinstance(value, list):
                        value = " ".join(str(v) for v in cast(list[object], value))
                    table.add_row(key, str(value))
        else:
            for key, value in vars(build_config).items():
                if value is not None:
                    table.add_row(key, str(value))

        console.print(table)

    except Exception as e:
        logger.error("Failed to parse build config", error=str(e))
        raise click.ClickException(f"Failed to parse build config: {e}") from e
