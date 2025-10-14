"""Commands for examining CDN archive indices and archive-groups."""

from pathlib import Path
from typing import Any

import click
import structlog

from cascette_tools.formats.cdn_archive import (
    CdnArchiveParser,
    is_archive_group,
    is_cdn_archive_index,
)

logger = structlog.get_logger()


@click.group()
def archive():
    """Examine CDN archive indices and archive-groups."""
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
