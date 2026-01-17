"""Search for encoding keys across CDN archive indices.

This module provides utilities to search for specific encoding keys
across all CDN archive indices, enabling resolution of content that
isn't available as loose files.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import click
import httpx
import structlog
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from cascette_tools.core.config import AppConfig
from cascette_tools.formats.cdn_archive import CdnArchiveParser

logger = structlog.get_logger()


def parse_cdn_config_archives(cdn_config_path: Path) -> list[str]:
    """Parse CDN config to get list of archive hashes.

    Args:
        cdn_config_path: Path to CDN config file

    Returns:
        List of archive hashes
    """
    content = cdn_config_path.read_text()
    archives = []

    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('archives = '):
            # Format: archives = hash1 hash2 hash3 ...
            hashes = line[len('archives = '):].split()
            archives.extend(hashes)

    return archives


@dataclass
class ArchiveIndexResult:
    """Result from searching an archive index."""
    offset: int
    size: int
    archive_index: int | None = None  # Only set for archive-groups


def parse_archive_index_footer(index_data: bytes) -> dict | None:
    """Parse the 28-byte footer of an archive index.

    Args:
        index_data: Raw archive index data

    Returns:
        Dict with footer fields or None if invalid
    """
    if len(index_data) < 28:
        return None

    footer_data = index_data[-28:]

    return {
        'toc_hash': footer_data[0:8],
        'version': footer_data[8],
        'reserved': footer_data[9:11],
        'page_size_kb': footer_data[11],
        'offset_bytes': footer_data[12],
        'size_bytes': footer_data[13],
        'key_bytes': footer_data[14],
        'hash_bytes': footer_data[15],
        'entry_count': struct.unpack('<I', footer_data[16:20])[0],
        'footer_hash': footer_data[20:28],
    }


def search_archive_index(index_data: bytes, target_key: bytes) -> ArchiveIndexResult | None:
    """Search an archive index for a specific encoding key.

    Args:
        index_data: Raw archive index data
        target_key: Encoding key to search for (16 bytes)

    Returns:
        ArchiveIndexResult if found, None otherwise
    """
    footer = parse_archive_index_footer(index_data)
    if not footer:
        return None

    version = footer['version']
    offset_bytes = footer['offset_bytes']
    size_bytes = footer['size_bytes']
    key_bytes = footer['key_bytes']
    entry_count = footer['entry_count']

    # Validate
    if version != 1 or key_bytes != 16 or offset_bytes not in [4, 6] or size_bytes != 4:
        return None

    is_archive_group = offset_bytes == 6

    # Calculate entry size
    entry_size = key_bytes + offset_bytes + size_bytes

    # Search entries
    truncated_target = target_key[:key_bytes]
    pos = 0

    for _ in range(entry_count):
        if pos + entry_size > len(index_data) - 28:
            break

        entry_key = index_data[pos:pos + key_bytes]
        pos += key_bytes

        if is_archive_group:
            # Archive-group: 2-byte archive index + 4-byte offset
            archive_idx = struct.unpack('>H', index_data[pos:pos + 2])[0]
            offset = struct.unpack('>I', index_data[pos + 2:pos + 6])[0]
            pos += 6
        else:
            archive_idx = None
            offset = struct.unpack('>I', index_data[pos:pos + 4])[0]
            pos += 4

        size = struct.unpack('>I', index_data[pos:pos + 4])[0]
        pos += 4

        if entry_key == truncated_target:
            return ArchiveIndexResult(offset=offset, size=size, archive_index=archive_idx)

    return None


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


@click.group()
def archive_search() -> None:
    """Search for keys in CDN archive indices."""
    pass


@archive_search.command()
@click.argument("cdn_config_path", type=click.Path(exists=True, path_type=Path))
@click.argument("encoding_key", type=str)
@click.option(
    "--cdn-base", "-c",
    type=str,
    default="http://us.cdn.blizzard.com",
    help="CDN base URL"
)
@click.option(
    "--cdn-path", "-p",
    type=str,
    default="tpr/wow",
    help="CDN path"
)
@click.option(
    "--max-archives", "-m",
    type=int,
    default=0,
    help="Maximum archives to search (0 = all)"
)
@click.pass_context
def find_key(
    ctx: click.Context,
    cdn_config_path: Path,
    encoding_key: str,
    cdn_base: str,
    cdn_path: str,
    max_archives: int
) -> None:
    """Find which archive contains a specific encoding key.

    CDN_CONFIG_PATH is the path to a CDN config file.
    ENCODING_KEY is the encoding key hash to search for.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Parse target key
        target_key = bytes.fromhex(encoding_key)
        if len(target_key) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        # Get archive list from CDN config
        archives = parse_cdn_config_archives(cdn_config_path)
        console.print(f"Found {len(archives)} archives in CDN config")

        if max_archives > 0:
            archives = archives[:max_archives]
            console.print(f"Limiting search to first {max_archives} archives")

        # Search each archive index
        found_archive = None
        found_offset = None
        found_size = None

        with httpx.Client(timeout=30.0) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Searching archives...", total=len(archives))

                for archive_hash in archives:
                    progress.update(task, advance=1)

                    # Fetch archive index
                    h = archive_hash.lower()
                    url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}.index"

                    try:
                        response = client.get(url)
                        if response.status_code != 200:
                            continue

                        index_data = response.content

                        # Search this index
                        result = search_archive_index(index_data, target_key)
                        if result:
                            found_archive = archive_hash
                            found_offset, found_size = result
                            break

                    except Exception as e:
                        logger.debug(f"Failed to fetch {archive_hash}: {e}")
                        continue

        if found_archive:
            table = Table(title="Key Found!")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Encoding Key", encoding_key)
            table.add_row("Archive", found_archive)
            table.add_row("Offset", str(found_offset))
            table.add_row("Size", f"{found_size:,} bytes")

            # Show how to fetch the data
            h = found_archive.lower()
            archive_url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"
            table.add_row("Archive URL", archive_url)

            console.print(table)

            console.print(f"\n[yellow]To fetch this data:[/yellow]")
            console.print(f"curl -r {found_offset}-{found_offset + found_size - 1} '{archive_url}' -o output.bin")
        else:
            console.print(f"[red]Key {encoding_key} not found in any archive[/red]")

    except Exception as e:
        logger.error("Search failed", error=str(e))
        raise click.ClickException(f"Search failed: {e}") from e


@archive_search.command()
@click.argument("cdn_config_path", type=click.Path(exists=True, path_type=Path))
@click.argument("encoding_key", type=str)
@click.argument("output_path", type=click.Path(path_type=Path))
@click.option(
    "--cdn-base", "-c",
    type=str,
    default="http://us.cdn.blizzard.com",
    help="CDN base URL"
)
@click.option(
    "--cdn-path", "-p",
    type=str,
    default="tpr/wow",
    help="CDN path"
)
@click.pass_context
def extract_key(
    ctx: click.Context,
    cdn_config_path: Path,
    encoding_key: str,
    output_path: Path,
    cdn_base: str,
    cdn_path: str
) -> None:
    """Find and extract data for an encoding key.

    CDN_CONFIG_PATH is the path to a CDN config file.
    ENCODING_KEY is the encoding key hash to extract.
    OUTPUT_PATH is where to save the extracted data.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Parse target key
        target_key = bytes.fromhex(encoding_key)
        if len(target_key) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        # Get archive list from CDN config
        archives = parse_cdn_config_archives(cdn_config_path)
        console.print(f"Searching {len(archives)} archives...")

        # Search each archive index
        found_archive = None
        found_offset = None
        found_size = None

        with httpx.Client(timeout=30.0) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Searching...", total=len(archives))

                for archive_hash in archives:
                    progress.update(task, advance=1)

                    h = archive_hash.lower()
                    url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}.index"

                    try:
                        response = client.get(url)
                        if response.status_code != 200:
                            continue

                        result = search_archive_index(response.content, target_key)
                        if result:
                            found_archive = archive_hash
                            found_offset, found_size = result
                            break

                    except Exception:
                        continue

            if not found_archive:
                raise click.ClickException(f"Key {encoding_key} not found in any archive")

            console.print(f"Found in archive {found_archive} at offset {found_offset}, size {found_size}")

            # Fetch the data using range request
            h = found_archive.lower()
            archive_url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"

            console.print(f"Fetching data from {archive_url}...")

            headers = {"Range": f"bytes={found_offset}-{found_offset + found_size - 1}"}
            response = client.get(archive_url, headers=headers)

            if response.status_code not in [200, 206]:
                raise click.ClickException(f"Failed to fetch data: HTTP {response.status_code}")

            # Save to output
            output_path.write_bytes(response.content)
            console.print(f"[green]Saved {len(response.content)} bytes to {output_path}[/green]")

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Extraction failed", error=str(e))
        raise click.ClickException(f"Extraction failed: {e}") from e
