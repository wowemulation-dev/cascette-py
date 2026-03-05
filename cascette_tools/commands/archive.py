"""Commands for working with CDN archive indices and archive-groups."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict

import click
import httpx
import structlog
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from cascette_tools.core.config import AppConfig
from cascette_tools.formats.cdn_archive import (
    CdnArchiveParser,
    is_archive_group,
    is_cdn_archive_index,
)

logger = structlog.get_logger()


class ArchiveIndexFooter(TypedDict):
    """Type definition for archive index footer fields."""
    toc_hash: bytes
    version: int
    reserved: bytes
    page_size_kb: int
    offset_bytes: int
    size_bytes: int
    key_bytes: int
    hash_bytes: int
    entry_count: int
    footer_hash: bytes


@dataclass
class ArchiveIndexResult:
    """Result from searching an archive index."""
    offset: int
    size: int
    archive_index: int | None = None  # Only set for archive-groups


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


def parse_cdn_config_archives(cdn_config_path: Path) -> list[str]:
    """Parse CDN config to get list of archive hashes."""
    content = cdn_config_path.read_text()
    archives: list[str] = []

    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('archives = '):
            hashes: list[str] = line[len('archives = '):].split()
            archives.extend(hashes)

    return archives


def parse_archive_index_footer(index_data: bytes) -> ArchiveIndexFooter | None:
    """Parse the 28-byte footer of an archive index."""
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
    """Search an archive index for a specific encoding key."""
    footer = parse_archive_index_footer(index_data)
    if not footer:
        return None

    version: int = footer['version']
    offset_bytes: int = footer['offset_bytes']
    size_bytes: int = footer['size_bytes']
    key_bytes: int = footer['key_bytes']
    entry_count: int = footer['entry_count']

    if version != 1 or key_bytes != 16 or offset_bytes not in [4, 6] or size_bytes != 4:
        return None

    is_ag: bool = offset_bytes == 6
    entry_size: int = key_bytes + offset_bytes + size_bytes
    truncated_target = target_key[:key_bytes]
    pos = 0

    for _ in range(entry_count):
        if pos + entry_size > len(index_data) - 28:
            break

        entry_key = index_data[pos:pos + key_bytes]
        pos += key_bytes

        if is_ag:
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


@click.group()
def archive() -> None:
    """Work with CDN archive indices and archive-groups."""
    pass


@archive.command()
@click.argument("index_file", type=click.Path(exists=True, path_type=Path))
@click.option("--show-entries", "-e", default=10, help="Number of entries to display")
@click.option("--show-distribution", "-d", is_flag=True, help="Show archive index distribution (archive-groups only)")
def examine(index_file: Path, show_entries: int, show_distribution: bool):
    """Examine a CDN archive index or archive-group file."""

    # Read file
    data = index_file.read_bytes()

    # Detect format
    if not is_cdn_archive_index(data):
        click.echo(f"Error: {index_file} does not appear to be a CDN archive index", err=True)
        return

    is_ag = is_archive_group(data)
    format_type = "archive-group" if is_ag else "CDN archive index"

    click.echo(f"File: {index_file.name}")
    click.echo(f"Format: {format_type}")
    click.echo(f"Size: {len(data):,} bytes ({len(data) / 1024 / 1024:.2f} MB)")
    click.echo()

    # Parse the file
    parser = CdnArchiveParser()
    try:
        index = parser.parse(data)
    except Exception as e:
        click.echo(f"Error parsing file: {e}", err=True)
        return

    # Display footer info
    footer = index.footer
    click.echo("Footer Information:")
    click.echo(f"  Version: {footer.version}")
    click.echo(f"  Key bytes: {footer.key_bytes}")
    click.echo(f"  Offset bytes: {footer.offset_bytes}")
    click.echo(f"  Size bytes: {footer.size_bytes}")
    click.echo(f"  Entry count: {footer.entry_count:,}")
    click.echo(f"  TOC hash: {footer.toc_hash.hex()}")
    click.echo()

    # Display statistics
    stats: dict[str, Any] = parser.get_statistics(index)
    click.echo("Statistics:")
    click.echo(f"  Total entries: {stats['total_entries']:,}")

    if 'unique_archive_indices' in stats:
        click.echo(f"  Unique archive indices: {stats['unique_archive_indices']:,}")
        if 'min_archive_index' in stats:
            click.echo(f"  Archive index range: {stats['min_archive_index']} - {stats['max_archive_index']}")

    if 'min_size' in stats:
        click.echo(f"  Size range: {stats['min_size']:,} - {stats['max_size']:,} bytes")
        click.echo(f"  Average size: {stats['avg_size']:.0f} bytes")
        click.echo(f"  Total size: {stats['total_size']:,} bytes ({stats['total_size'] / 1024 / 1024:.2f} MB)")
    click.echo()

    # Show sample entries
    if show_entries > 0 and index.entries:
        click.echo(f"First {min(show_entries, len(index.entries))} entries:")
        for i, entry in enumerate(index.entries[:show_entries]):
            key_hex = entry.encoding_key.hex()
            if len(key_hex) > 32:
                key_hex = f"{key_hex[:32]}..."

            if entry.archive_index is not None:
                click.echo(f"  [{i:4d}] Key: {key_hex}, Archive: {entry.archive_index:5d}, "
                          f"Offset: 0x{entry.offset:08x}, Size: {entry.size:,}")
            else:
                click.echo(f"  [{i:4d}] Key: {key_hex}, Offset: 0x{entry.offset:08x}, Size: {entry.size:,}")
        click.echo()

    # Show archive distribution for archive-groups
    if show_distribution and is_ag:
        distribution = parser.get_archive_indices(index)
        if distribution:
            click.echo("Archive Index Distribution (top 20):")
            sorted_dist = sorted(distribution.items(), key=lambda x: x[1], reverse=True)
            for archive_idx, count in sorted_dist[:20]:
                percentage = (count / len(index.entries)) * 100
                click.echo(f"  Archive {archive_idx:5d}: {count:7,} entries ({percentage:.1f}%)")


@archive.command()
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option("--min-size", "-s", default=1024*1024, help="Minimum file size in bytes (default: 1MB)")
def scan(directory: Path, min_size: int):
    """Scan directory for archive-groups and CDN archive indices."""

    click.echo(f"Scanning {directory} for archive indices...")
    click.echo(f"Minimum size filter: {min_size:,} bytes")
    click.echo()

    # Find all .index files
    index_files = list(directory.glob("**/*.index"))

    archive_groups: list[tuple[Path, int]] = []
    cdn_indices: list[tuple[Path, int]] = []

    for index_file in index_files:
        size = index_file.stat().st_size

        # Skip small files
        if size < min_size:
            continue

        # Read first chunk to detect format
        try:
            data = index_file.read_bytes()
            if is_cdn_archive_index(data):
                if is_archive_group(data):
                    archive_groups.append((index_file, size))
                else:
                    cdn_indices.append((index_file, size))
        except Exception:
            continue

    # Display results
    if archive_groups:
        click.echo(f"Found {len(archive_groups)} archive-groups:")
        for path, size in sorted(archive_groups, key=lambda x: x[1], reverse=True):
            click.echo(f"  {path.name}: {size:,} bytes ({size / 1024 / 1024:.1f} MB)")
        click.echo()

    if cdn_indices:
        click.echo(f"Found {len(cdn_indices)} CDN archive indices:")
        for path, size in sorted(cdn_indices, key=lambda x: x[1], reverse=True)[:10]:  # Top 10
            click.echo(f"  {path.name}: {size:,} bytes ({size / 1024:.1f} KB)")
        if len(cdn_indices) > 10:
            click.echo(f"  ... and {len(cdn_indices) - 10} more")
        click.echo()

    if not archive_groups and not cdn_indices:
        click.echo("No archive indices or archive-groups found.")


@archive.command()
@click.argument("index_file", type=click.Path(exists=True, path_type=Path))
@click.argument("encoding_key", type=str)
def find(index_file: Path, encoding_key: str):
    """Find an entry by encoding key in an archive index or archive-group."""

    # Parse encoding key
    try:
        key_bytes = bytes.fromhex(encoding_key)
    except ValueError:
        click.echo(f"Error: Invalid hex encoding key: {encoding_key}", err=True)
        return

    # Read and parse file
    data = index_file.read_bytes()

    if not is_cdn_archive_index(data):
        click.echo(f"Error: {index_file} is not a CDN archive index", err=True)
        return

    parser = CdnArchiveParser()
    try:
        index = parser.parse(data)
    except Exception as e:
        click.echo(f"Error parsing file: {e}", err=True)
        return

    # Find entry
    entry = parser.find_entry(index, key_bytes)

    if entry:
        click.echo(f"Found entry in {index_file.name}:")
        click.echo(f"  Encoding key: {entry.encoding_key.hex()}")
        if entry.archive_index is not None:
            click.echo(f"  Archive index: {entry.archive_index}")
        click.echo(f"  Offset: 0x{entry.offset:08x}")
        click.echo(f"  Size: {entry.size:,} bytes")
    else:
        click.echo(f"Entry not found for key: {encoding_key}")


@archive.command()
@click.argument("archive_group", type=click.Path(exists=True, path_type=Path))
@click.argument("cdn_config", type=click.Path(exists=True, path_type=Path))
def validate_mapping(archive_group: Path, cdn_config: Path):
    """Validate archive index mapping against CDN configuration."""

    # Read archive-group
    ag_data = archive_group.read_bytes()

    if not is_archive_group(ag_data):
        click.echo(f"Error: {archive_group} is not an archive-group", err=True)
        return

    parser = CdnArchiveParser()
    try:
        ag_index = parser.parse(ag_data)
    except Exception as e:
        click.echo(f"Error parsing archive-group: {e}", err=True)
        return

    # Read CDN config to get archive list
    cdn_data = cdn_config.read_text()
    archives = []

    for line in cdn_data.split('\n'):
        if line.startswith('archives = '):
            archives = line.split(' = ')[1].split()
            break

    if not archives:
        click.echo("Error: No archives found in CDN config", err=True)
        return

    click.echo(f"CDN has {len(archives)} archives defined")
    click.echo(f"Archive-group uses {len(parser.get_archive_indices(ag_index))} unique indices")
    click.echo()

    # Check archive index distribution
    distribution = parser.get_archive_indices(ag_index)

    # Validate indices
    valid_indices = 0
    beyond_cdn = 0

    for archive_idx, count in distribution.items():
        if archive_idx < len(archives):
            valid_indices += count
        else:
            beyond_cdn += count

    total = len(ag_index.entries)
    click.echo("Archive Index Validation:")
    click.echo(f"  Within CDN range (0-{len(archives)-1}): {valid_indices:,} entries ({valid_indices/total*100:.1f}%)")
    click.echo(f"  Beyond CDN range: {beyond_cdn:,} entries ({beyond_cdn/total*100:.1f}%)")

    # Show top indices beyond CDN range
    high_indices = [(idx, cnt) for idx, cnt in distribution.items() if idx >= len(archives)]
    if high_indices:
        high_indices.sort(key=lambda x: x[1], reverse=True)
        click.echo()
        click.echo("Top indices beyond CDN range:")
        for idx, cnt in high_indices[:10]:
            click.echo(f"  Index {idx:5d}: {cnt:,} entries")


@archive.command("find-key")
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
    _config, console, _verbose, _ = _get_context_objects(ctx)

    try:
        target_key = bytes.fromhex(encoding_key)
        if len(target_key) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        archives = parse_cdn_config_archives(cdn_config_path)
        console.print(f"Found {len(archives)} archives in CDN config")

        if max_archives > 0:
            archives = archives[:max_archives]
            console.print(f"Limiting search to first {max_archives} archives")

        found_archive: str | None = None
        found_offset: int | None = None
        found_size: int | None = None

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

                    h = archive_hash.lower()
                    url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}.index"

                    try:
                        response = client.get(url)
                        if response.status_code != 200:
                            continue

                        result = search_archive_index(response.content, target_key)
                        if result:
                            found_archive = archive_hash
                            found_offset = result.offset
                            found_size = result.size
                            break

                    except Exception as e:
                        logger.debug(f"Failed to fetch {archive_hash}: {e}")
                        continue

        if found_archive and found_offset is not None and found_size is not None:
            table = Table(title="Key Found!")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Encoding Key", encoding_key)
            table.add_row("Archive", found_archive)
            table.add_row("Offset", str(found_offset))
            table.add_row("Size", f"{found_size:,} bytes")

            h = found_archive.lower()
            archive_url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"
            table.add_row("Archive URL", archive_url)

            console.print(table)

            console.print("\n[yellow]To fetch this data:[/yellow]")
            console.print(f"curl -r {found_offset}-{found_offset + found_size - 1} '{archive_url}' -o output.bin")
        else:
            console.print(f"[red]Key {encoding_key} not found in any archive[/red]")

    except Exception as e:
        logger.error("Search failed", error=str(e))
        raise click.ClickException(f"Search failed: {e}") from e


@archive.command("extract-key")
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
    _config, console, _verbose, _ = _get_context_objects(ctx)

    try:
        target_key = bytes.fromhex(encoding_key)
        if len(target_key) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        archives = parse_cdn_config_archives(cdn_config_path)
        console.print(f"Searching {len(archives)} archives...")

        found_archive: str | None = None
        found_offset: int | None = None
        found_size: int | None = None

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
                            found_offset = result.offset
                            found_size = result.size
                            break

                    except Exception:
                        continue

            if not found_archive or found_offset is None or found_size is None:
                raise click.ClickException(f"Key {encoding_key} not found in any archive")

            console.print(f"Found in archive {found_archive} at offset {found_offset}, size {found_size}")

            h = found_archive.lower()
            archive_url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"

            console.print(f"Fetching data from {archive_url}...")

            headers = {"Range": f"bytes={found_offset}-{found_offset + found_size - 1}"}
            response = client.get(archive_url, headers=headers)

            if response.status_code not in [200, 206]:
                raise click.ClickException(f"Failed to fetch data: HTTP {response.status_code}")

            output_path.write_bytes(response.content)
            console.print(f"[green]Saved {len(response.content)} bytes to {output_path}[/green]")

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Extraction failed", error=str(e))
        raise click.ClickException(f"Extraction failed: {e}") from e
