"""Examine commands for format inspection."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import structlog
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.config import AppConfig, CDNConfig
from cascette_tools.core.types import Product
from cascette_tools.core.utils import compute_md5, format_size, validate_hash_string
from cascette_tools.formats import (
    ArchiveIndexParser,
    BLTEParser,
    EncodingParser,
    decompress_blte,
    detect_config_type,
    is_config_file,
)
from cascette_tools.formats.config import (
    BuildConfigParser,
    CDNConfigParser,
    PatchConfigParser,
    ProductConfigParser,
)

logger = structlog.get_logger()


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


def _output_json(data: dict[str, Any], console: Console) -> None:
    """Output data as JSON."""
    print(json.dumps(data, indent=2, default=str))


def _output_table(table: Table, console: Console) -> None:
    """Output table using Rich formatting."""
    console.print(table)


def _fetch_from_cdn_or_path(
    input_str: str,
    console: Console,
    config: AppConfig,
    progress_text: str = "Fetching from CDN"
) -> bytes:
    """Fetch data from CDN hash or read from file path.

    Args:
        input_str: Hash string or file path
        console: Rich console for output
        config: Application configuration
        progress_text: Text to show during CDN fetch

    Returns:
        File content as bytes

    Raises:
        click.ClickException: If file not found or CDN fetch fails
    """
    path = Path(input_str)

    if path.exists():
        # Read from local file
        try:
            return path.read_bytes()
        except OSError as e:
            raise click.ClickException(f"Failed to read file {path}: {e}") from e

    # Assume it's a hash and try CDN
    if not validate_hash_string(input_str):
        raise click.ClickException(f"Invalid input: not a valid file path or hash: {input_str}")

    # Fetch from CDN
    try:
        # Create CDNConfig from AppConfig
        cdn_config = CDNConfig(
            timeout=config.cdn_timeout,
            max_retries=config.cdn_max_retries
        )
        cdn_client = CDNClient(Product.WOW, config=cdn_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description=progress_text, total=None)

            # Fetch from CDN (caching handled by CDNClient)
            data = cdn_client.fetch_data(input_str)

            return data

    except Exception as e:
        raise click.ClickException(f"Failed to fetch from CDN: {e}") from e


@click.group()
def examine() -> None:
    """Examine NGDP/CASC format files."""
    pass


@examine.command()
@click.argument("input_path", type=str)
@click.option(
    "--decompress", "-d",
    is_flag=True,
    help="Show decompressed data information"
)
@click.option(
    "--output-file", "-o",
    type=click.Path(path_type=Path),
    help="Save decompressed data to file"
)
@click.pass_context
def blte(
    ctx: click.Context,
    input_path: str,
    decompress: bool,
    output_file: Path | None
) -> None:
    """Examine BLTE compressed files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching BLTE file")

        # Parse BLTE file
        parser = BLTEParser()
        blte_file = parser.parse(data)

        if config.output_format == "json":
            # JSON output
            result = {
                "magic": blte_file.header.magic.decode('ascii', errors='ignore'),
                "header_size": blte_file.header.header_size,
                "flags": blte_file.header.flags,
                "chunk_count": len(blte_file.chunks),
                "total_compressed_size": sum(chunk.compressed_size for chunk in blte_file.chunks),
                "total_decompressed_size": sum(chunk.decompressed_size for chunk in blte_file.chunks),
                "chunks": []
            }

            for i, chunk in enumerate(blte_file.chunks):
                chunk_info = {
                    "index": i,
                    "compressed_size": chunk.compressed_size,
                    "decompressed_size": chunk.decompressed_size,
                    "compression_mode": chunk.compression_mode.name,
                    "checksum": chunk.checksum.hex()
                }
                if chunk.encryption_type:
                    chunk_info["encryption_type"] = chunk.encryption_type.name
                if chunk.encryption_key_name:
                    chunk_info["encryption_key_name"] = chunk.encryption_key_name.hex()
                result["chunks"].append(chunk_info)

            if decompress:
                try:
                    decompressed = decompress_blte(data)
                    result["decompressed_size"] = len(decompressed)
                    result["decompressed_md5"] = compute_md5(decompressed).hex()
                except Exception as e:
                    result["decompression_error"] = str(e)

            _output_json(result, console)
        else:
            # Rich table output
            table = Table(title="BLTE File Information")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Magic", blte_file.header.magic.decode('ascii', errors='ignore'))
            table.add_row("Header Size", str(blte_file.header.header_size))
            if blte_file.header.flags is not None:
                table.add_row("Flags", f"0x{blte_file.header.flags:08x}")
            table.add_row("Chunk Count", str(len(blte_file.chunks)))
            table.add_row(
                "Total Compressed",
                format_size(sum(chunk.compressed_size for chunk in blte_file.chunks))
            )
            table.add_row(
                "Total Decompressed",
                format_size(sum(chunk.decompressed_size for chunk in blte_file.chunks))
            )

            _output_table(table, console)

            # Chunk details in verbose mode
            if verbose and blte_file.chunks:
                chunk_table = Table(title="Chunk Details")
                chunk_table.add_column("Index", style="cyan")
                chunk_table.add_column("Compressed", style="yellow")
                chunk_table.add_column("Decompressed", style="green")
                chunk_table.add_column("Mode", style="blue")
                chunk_table.add_column("Checksum", style="magenta")

                for i, chunk in enumerate(blte_file.chunks):
                    chunk_table.add_row(
                        str(i),
                        format_size(chunk.compressed_size),
                        format_size(chunk.decompressed_size),
                        chunk.compression_mode.name,
                        chunk.checksum.hex()[:16] + "..."
                    )

                _output_table(chunk_table, console)

        # Handle decompression and output
        if decompress or output_file:
            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True
                ) as progress:
                    progress.add_task(description="Decompressing BLTE data", total=None)
                    decompressed = decompress_blte(data)

                if output_file:
                    output_file.write_bytes(decompressed)
                    console.print(f"[green]Decompressed data saved to {output_file}[/green]")
                elif decompress and config.output_format != "json":
                    console.print(f"[green]Decompressed size: {format_size(len(decompressed))}[/green]")
                    console.print(f"[green]MD5: {compute_md5(decompressed).hex()}[/green]")

            except Exception as e:
                if config.output_format == "json":
                    _output_json({"error": f"Decompression failed: {e}"}, console)
                else:
                    console.print(f"[red]Decompression failed: {e}[/red]")
                sys.exit(1)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine BLTE file", error=str(e))
        raise click.ClickException(f"Failed to examine BLTE file: {e}") from e


@examine.command()
@click.argument("input_path", type=str)
@click.option(
    "--limit", "-l",
    type=int,
    default=10,
    help="Limit number of entries to display"
)
@click.option(
    "--search", "-s",
    type=str,
    help="Search for specific content key (hex string)"
)
@click.pass_context
def encoding(
    ctx: click.Context,
    input_path: str,
    limit: int,
    search: str | None
) -> None:
    """Examine encoding files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching encoding file")

        # Parse encoding file
        parser = EncodingParser()
        encoding_file = parser.parse(data)

        if config.output_format == "json":
            # JSON output
            result = {
                "magic": encoding_file.header.magic.decode('ascii', errors='ignore'),
                "version": encoding_file.header.version,
                "ckey_size": encoding_file.header.ckey_size,
                "ekey_size": encoding_file.header.ekey_size,
                "ckey_page_size_kb": encoding_file.header.ckey_page_size_kb,
                "ekey_page_size_kb": encoding_file.header.ekey_page_size_kb,
                "ckey_page_count": encoding_file.header.ckey_page_count,
                "ekey_page_count": encoding_file.header.ekey_page_count,
                "espec_size": encoding_file.header.espec_size,
                "sample_entries": []
            }

            # Add index information (simplified for current structure)
            result["ckey_index_count"] = len(encoding_file.ckey_index)
            result["ekey_index_count"] = len(encoding_file.ekey_index)
            result["espec_table_count"] = len(encoding_file.espec_table)

            if search:
                result["note"] = "Search functionality requires page parsing implementation"
            else:
                result["note"] = "Full entry parsing requires page loading implementation"

            _output_json(result, console)
        else:
            # Rich table output
            header_table = Table(title="Encoding File Header")
            header_table.add_column("Property", style="cyan")
            header_table.add_column("Value", style="white")

            header_table.add_row("Magic", encoding_file.header.magic.decode('ascii', errors='ignore'))
            header_table.add_row("Version", str(encoding_file.header.version))
            header_table.add_row("CKey Size", f"{encoding_file.header.ckey_size} bytes")
            header_table.add_row("EKey Size", f"{encoding_file.header.ekey_size} bytes")
            header_table.add_row("CKey Page Size", f"{encoding_file.header.ckey_page_size_kb} KB")
            header_table.add_row("EKey Page Size", f"{encoding_file.header.ekey_page_size_kb} KB")
            header_table.add_row("CKey Page Count", str(encoding_file.header.ckey_page_count))
            header_table.add_row("EKey Page Count", str(encoding_file.header.ekey_page_count))
            header_table.add_row("ESpec Size", format_size(encoding_file.header.espec_size))

            _output_table(header_table, console)

            # Sample entries or search results
            entries_table = Table(title=f"Content Key Entries ({limit} shown)" if not search else f"Search Results for {search}")
            entries_table.add_column("Content Key", style="yellow")
            entries_table.add_column("Encoding Keys", style="green")
            entries_table.add_column("File Size", style="blue")

            entries_shown = 0

            if search:
                # Note: Search functionality requires loading pages individually
                console.print("[yellow]Search functionality requires page parsing implementation[/yellow]")
                console.print("[yellow]Use encoding parser's find_content_key method for specific searches[/yellow]")
            else:
                # Show note about page loading
                console.print("[yellow]Entry details require loading pages individually[/yellow]")
                console.print("[yellow]Use encoding parser's load_ckey_page method to access entries[/yellow]")

            if entries_shown > 0:
                _output_table(entries_table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine encoding file", error=str(e))
        raise click.ClickException(f"Failed to examine encoding file: {e}") from e


@examine.command()
@click.argument("input_path", type=str)
@click.pass_context
def config(ctx: click.Context, input_path: str) -> None:
    """Examine build/CDN/product configuration files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config_obj, "Fetching config file")

        # Detect config type and parse
        if not is_config_file(data):
            raise click.ClickException("Input is not a valid config file")

        config_type = detect_config_type(data)

        if config_type == "build":
            parser = BuildConfigParser()
        elif config_type == "cdn":
            parser = CDNConfigParser()
        elif config_type == "patch":
            parser = PatchConfigParser()
        elif config_type == "product":
            parser = ProductConfigParser()
        else:
            raise click.ClickException(f"Unknown config type: {config_type}")

        config_data = parser.parse(data)

        if config_obj.output_format == "json":
            # JSON output
            result = {
                "type": config_type,
                "entries": {}
            }

            # Convert config to dict
            if hasattr(config_data, 'model_dump'):
                result["entries"] = config_data.model_dump()
            else:
                result["entries"] = vars(config_data)

            _output_json(result, console)
        else:
            # Rich table output
            table = Table(title=f"{config_type.title()} Configuration")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")

            # Add config entries to table
            if hasattr(config_data, 'model_dump'):
                entries = config_data.model_dump()
            else:
                entries = vars(config_data)

            for key, value in entries.items():
                # Format complex values
                if isinstance(value, (list, tuple)):
                    value_str = ", ".join(str(v) for v in value)
                    if len(value_str) > 60:
                        value_str = value_str[:57] + "..."
                elif isinstance(value, dict):
                    value_str = f"{len(value)} entries"
                else:
                    value_str = str(value)

                table.add_row(key, value_str)

            _output_table(table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine config file", error=str(e))
        raise click.ClickException(f"Failed to examine config file: {e}") from e


@examine.command()
@click.argument("input_path", type=str)
@click.pass_context
def archive(ctx: click.Context, input_path: str) -> None:
    """Examine archive index files.

    INPUT can be either a file path or CDN hash with .index extension.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching archive index")

        # Parse archive index
        parser = ArchiveIndexParser()
        archive_index = parser.parse(data)

        if config.output_format == "json":
            # JSON output
            result = {
                "footer": {
                    "toc_hash": archive_index.footer.toc_hash.hex(),
                    "version": archive_index.footer.version,
                    "reserved": archive_index.footer.reserved.hex(),
                    "page_size_kb": archive_index.footer.page_size_kb,
                    "offset_bytes": archive_index.footer.offset_bytes,
                    "size_bytes": archive_index.footer.size_bytes,
                    "ekey_length": archive_index.footer.ekey_length,
                    "element_count": archive_index.footer.element_count
                },
                "chunks": len(archive_index.chunks),
                "total_entries": sum(len(chunk.entries) for chunk in archive_index.chunks),
                "sample_entries": []
            }

            # Add sample entries from first chunk
            if archive_index.chunks and archive_index.chunks[0].entries:
                for entry in archive_index.chunks[0].entries[:10]:
                    result["sample_entries"].append({
                        "encoding_key": entry.ekey.hex(),
                        "size": entry.size,
                        "offset": entry.offset
                    })

            _output_json(result, console)
        else:
            # Rich table output
            footer_table = Table(title="Archive Index Footer")
            footer_table.add_column("Property", style="cyan")
            footer_table.add_column("Value", style="white")

            footer_table.add_row("TOC Hash", archive_index.footer.toc_hash.hex())
            footer_table.add_row("Version", str(archive_index.footer.version))
            footer_table.add_row("Page Size", f"{archive_index.footer.page_size_kb} KB")
            footer_table.add_row("Offset Bytes", str(archive_index.footer.offset_bytes))
            footer_table.add_row("Size Bytes", str(archive_index.footer.size_bytes))
            footer_table.add_row("EKey Length", f"{archive_index.footer.ekey_length} bytes")
            footer_table.add_row("Element Count", str(archive_index.footer.element_count))

            _output_table(footer_table, console)

            # Structure information
            structure_table = Table(title="Index Structure")
            structure_table.add_column("Property", style="cyan")
            structure_table.add_column("Value", style="white")

            structure_table.add_row("Chunk Count", str(len(archive_index.chunks)))
            structure_table.add_row("Total Entries", str(sum(len(chunk.entries) for chunk in archive_index.chunks)))

            if archive_index.chunks:
                avg_entries = sum(len(chunk.entries) for chunk in archive_index.chunks) / len(archive_index.chunks)
                structure_table.add_row("Avg Entries/Chunk", f"{avg_entries:.1f}")

            _output_table(structure_table, console)

            # Sample entries from first chunk
            if verbose and archive_index.chunks and archive_index.chunks[0].entries:
                entries_table = Table(title="Sample Entries (First Chunk)")
                entries_table.add_column("Encoding Key", style="yellow")
                entries_table.add_column("Size", style="green")
                entries_table.add_column("Offset", style="blue")

                for entry in archive_index.chunks[0].entries[:10]:  # Show first 10 entries
                    entries_table.add_row(
                        entry.ekey.hex(),
                        format_size(entry.size),
                        str(entry.offset)
                    )

                _output_table(entries_table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine archive index", error=str(e))
        raise click.ClickException(f"Failed to examine archive index: {e}") from e


