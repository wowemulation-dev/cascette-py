"""Installation state analyzer for NGDP/CASC installations.

This module provides tools to analyze Battle.net product installations,
calculate progress, and understand what needs to be downloaded for
a full installation.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from pathlib import Path
from typing import Any, BinaryIO

import click
import structlog
from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.config import AppConfig, CDNConfig
from cascette_tools.core.types import Product
from cascette_tools.core.utils import format_size
from cascette_tools.formats.config import BuildConfigParser, CDNConfigParser
from cascette_tools.formats.download import DownloadParser

logger = structlog.get_logger()


class LocalIdxEntry(BaseModel):
    """Entry from local .idx file."""

    key: bytes = Field(description="Truncated encoding key (9 bytes)")
    size: int = Field(description="File size")
    offset: int = Field(description="Offset in data file")
    data_file: int = Field(description="Data file number")


class LocalIdxFooter(BaseModel):
    """Footer from local .idx file."""

    toc_hash: bytes = Field(description="Table of contents hash")
    version: int = Field(description="Version")
    bucket: int = Field(description="Bucket number (0x00-0x0f)")
    extra_bytes: int = Field(description="Extra bytes per entry")
    encoder_spec_size: int = Field(description="Encoder spec size")
    segment_size: int = Field(description="Segment size in bytes")
    entry_count: int = Field(description="Number of entries")


class InstallationState(BaseModel):
    """Represents the current state of an installation."""

    install_path: Path = Field(description="Installation root path")
    product_code: str = Field(description="Product code (e.g., wow_classic_era)")
    build_config_hash: str | None = Field(default=None, description="Build config hash")
    cdn_config_hash: str | None = Field(default=None, description="CDN config hash")
    local_entries: dict[str, LocalIdxEntry] = Field(default_factory=dict, description="Local idx entries by hex key")
    local_data_size: int = Field(default=0, description="Total size of local .data files")
    local_entry_count: int = Field(default=0, description="Total number of local entries")


class InstallationProgress(BaseModel):
    """Progress information for an installation."""

    total_entries: int = Field(description="Total entries needed")
    downloaded_entries: int = Field(description="Entries already downloaded")
    total_size: int = Field(description="Total size needed in bytes")
    downloaded_size: int = Field(description="Size already downloaded")
    priority_breakdown: dict[int, dict[str, int]] = Field(description="Breakdown by priority level")
    missing_entries: list[str] = Field(default_factory=list, description="Missing encoding keys (first 100)")


def parse_local_idx(data: bytes, bucket: int) -> tuple[LocalIdxFooter, list[LocalIdxEntry]]:
    """Parse a local .idx file.

    Local .idx files have a different format from CDN indices:
    - 9-byte truncated keys for space optimization
    - 4-byte offsets
    - Footer at end of file (similar structure but different fields)

    Args:
        data: Raw .idx file data
        bucket: Bucket number (extracted from filename, e.g., 0x00 from 0000000001.idx)

    Returns:
        Tuple of (footer, entries)
    """
    if len(data) < 28:
        raise ValueError("Data too short for local idx file")

    # Footer is at the end (28 bytes for basic footer)
    # But we need to detect the actual footer location
    # Local idx files use a fixed 65536-byte block size

    # Parse footer from end
    footer_data = data[-28:]

    # Parse footer structure
    toc_hash = footer_data[0:8]
    version = footer_data[8]
    bucket_byte = footer_data[9]  # Should match bucket from filename
    extra_bytes = footer_data[10]
    encoder_spec_size = footer_data[11]
    segment_size = struct.unpack('<I', footer_data[12:16])[0]  # Little-endian
    entry_count = struct.unpack('<I', footer_data[16:20])[0]  # Little-endian

    footer = LocalIdxFooter(
        toc_hash=toc_hash,
        version=version,
        bucket=bucket_byte,
        extra_bytes=extra_bytes,
        encoder_spec_size=encoder_spec_size,
        segment_size=segment_size,
        entry_count=entry_count,
    )

    # Parse entries
    # Entry size: 9 (key) + 4 (size) + 4 (offset) + extra_bytes
    entry_size = 9 + 4 + 4 + extra_bytes
    entries: list[LocalIdxEntry] = []

    # Data is organized in pages, entries are at the start
    pos = 0
    for _ in range(entry_count):
        if pos + entry_size > len(data) - 28:  # Don't read into footer
            break

        key = data[pos:pos + 9]
        pos += 9

        size = struct.unpack('<I', data[pos:pos + 4])[0]
        pos += 4

        offset = struct.unpack('<I', data[pos:pos + 4])[0]
        pos += 4

        # Skip extra bytes
        pos += extra_bytes

        # Skip empty entries
        if key == b'\x00' * 9:
            continue

        # Extract data file number from offset
        # High bits indicate which .data file
        data_file = 0  # Default, would need to check actual data files

        entries.append(LocalIdxEntry(
            key=key,
            size=size,
            offset=offset,
            data_file=data_file
        ))

    return footer, entries


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

    # Scan local .idx files
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
                    bucket = int(name[:2], 16)

                    idx_data = idx_file.read_bytes()
                    footer, entries = parse_local_idx(idx_data, bucket)

                    for entry in entries:
                        hex_key = entry.key.hex()
                        state.local_entries[hex_key] = entry

                    logger.debug(f"Parsed {idx_file.name}: {len(entries)} entries")

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


def calculate_progress(
    state: InstallationState,
    download_manifest: Any,  # DownloadFile
    tags: list[str] | None = None
) -> InstallationProgress:
    """Calculate installation progress by comparing local state to download manifest.

    Args:
        state: Current local installation state
        download_manifest: Parsed download manifest
        tags: Optional list of tags to filter by (e.g., ['Windows', 'enUS'])

    Returns:
        InstallationProgress with detailed breakdown
    """
    # Filter entries by tags if provided
    entries = download_manifest.entries
    if tags:
        entries = [e for e in entries if any(t in e.tags for t in tags)]

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

    priority_breakdown: dict[int, dict[str, int]] = {}

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
        missing_entries=missing
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
    config, console, verbose, _ = _get_context_objects(ctx)

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

        console.print(table)

        if verbose and state.local_entries:
            # Show sample entries
            sample_table = Table(title="Sample Local Entries (first 10)")
            sample_table.add_column("Key (truncated)", style="yellow")
            sample_table.add_column("Size", style="green")

            for i, (key, entry) in enumerate(list(state.local_entries.items())[:10]):
                sample_table.add_row(key, format_size(entry.size))

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
                f"{format_size(breakdown['downloaded_size'])}/{format_size(breakdown['total_size'])}",
                f"{breakdown['percent']:.1f}%"
            )

        console.print(priority_table)

        if verbose and prog_result.missing_entries:
            console.print(f"\n[yellow]First 10 missing entries:[/yellow]")
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
    config, console, verbose, _ = _get_context_objects(ctx)

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
                        value = " ".join(str(v) for v in value)
                    table.add_row(key, str(value))
        else:
            for key, value in vars(build_config).items():
                if value is not None:
                    table.add_row(key, str(value))

        console.print(table)

    except Exception as e:
        logger.error("Failed to parse build config", error=str(e))
        raise click.ClickException(f"Failed to parse build config: {e}") from e
