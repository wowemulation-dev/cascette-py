"""Inspect commands for examining and analyzing NGDP/CASC format files."""

from __future__ import annotations

import json
from collections import defaultdict
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
    is_blte,
    is_config_file,
    is_download,
    is_encoding,
    is_install,
    is_root,
)
from cascette_tools.formats.config import (
    BuildConfigParser,
    CDNConfigParser,
    PatchConfigParser,
    ProductConfigParser,
)
from cascette_tools.formats.download import DownloadParser
from cascette_tools.formats.install import InstallParser
from cascette_tools.formats.root import RootParser

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
    progress_text: str = "Fetching from CDN",
    cdn_type: str = "data",
    product: Product = Product.WOW,
) -> bytes:
    """Fetch data from CDN hash or read from file path.

    Args:
        input_str: Hash string or file path
        console: Rich console for output
        config: Application configuration
        progress_text: Text to show during CDN fetch
        cdn_type: CDN content type - "config" for build/CDN/patch configs,
            "data" for archives, encoding, root, install, download files
        product: Product to use for CDN lookup

    Returns:
        File content as bytes

    Raises:
        click.ClickException: If file not found or CDN fetch fails
    """
    path = Path(input_str)

    if path.exists():
        try:
            return path.read_bytes()
        except OSError as e:
            raise click.ClickException(f"Failed to read file {path}: {e}") from e

    if not validate_hash_string(input_str):
        raise click.ClickException(f"Invalid input: not a valid file path or hash: {input_str}")

    try:
        cdn_config = CDNConfig(
            timeout=config.cdn_timeout,
            max_retries=config.cdn_max_retries
        )
        cdn_client = CDNClient(product, config=cdn_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description=progress_text, total=None)

            if cdn_type == "config":
                data = cdn_client.fetch_config(input_str)
            elif cdn_type == "index":
                data = cdn_client.fetch_data(input_str, is_index=True)
            else:
                data = cdn_client.fetch_data(input_str)

            return data

    except Exception as e:
        raise click.ClickException(f"Failed to fetch from CDN: {e}") from e


def _detect_format_type(data: bytes) -> str:
    """Detect the format type of the given data."""
    if is_blte(data):
        return "blte"
    elif is_encoding(data):
        return "encoding"
    elif is_config_file(data):
        config_type = detect_config_type(data)
        return config_type if config_type is not None else "unknown"
    elif is_root(data):
        return "root"
    elif is_install(data):
        return "install"
    elif is_download(data):
        return "download"
    else:
        if data.endswith(b'\x00' * 12):
            return "archive"
        return "unknown"


def _analyze_blte_compression(data: bytes) -> dict[str, Any]:
    """Analyze BLTE compression statistics."""
    try:
        parser = BLTEParser()
        blte_file = parser.parse(data)

        total_compressed = sum(chunk.compressed_size for chunk in blte_file.chunks)
        total_decompressed = sum(chunk.decompressed_size for chunk in blte_file.chunks)

        compression_modes: defaultdict[str, int] = defaultdict(int)
        chunk_details: list[dict[str, Any]] = []

        for chunk in blte_file.chunks:
            mode = chunk.compression_mode.name
            compression_modes[mode] += 1

            ratio = chunk.compressed_size / chunk.decompressed_size if chunk.decompressed_size > 0 else 0
            chunk_details.append({
                "compressed_size": chunk.compressed_size,
                "decompressed_size": chunk.decompressed_size,
                "compression_mode": mode,
                "ratio": ratio
            })

        overall_ratio = total_compressed / total_decompressed if total_decompressed > 0 else 0

        return {
            "total_compressed_size": total_compressed,
            "total_decompressed_size": total_decompressed,
            "overall_compression_ratio": overall_ratio,
            "chunk_count": len(blte_file.chunks),
            "compression_modes": dict(compression_modes),
            "chunk_details": chunk_details
        }
    except Exception as e:
        return {"error": f"Failed to analyze BLTE: {e}"}


def _analyze_blte_stats(data: bytes) -> dict[str, Any]:
    """Analyze BLTE file statistics."""
    try:
        parser = BLTEParser()
        blte_file = parser.parse(data)

        total_compressed = sum(chunk.compressed_size for chunk in blte_file.chunks)
        total_decompressed = sum(chunk.decompressed_size for chunk in blte_file.chunks)

        return {
            "chunk_count": len(blte_file.chunks),
            "total_compressed_size": total_compressed,
            "total_decompressed_size": total_decompressed,
            "compression_ratio": total_compressed / total_decompressed if total_decompressed > 0 else 0,
            "header_size": blte_file.header.header_size,
            "flags": blte_file.header.flags
        }
    except Exception as e:
        return {"error": f"Failed to parse BLTE: {e}"}


def _analyze_encoding_stats(data: bytes) -> dict[str, Any]:
    """Analyze encoding file statistics."""
    try:
        if is_blte(data):
            data = decompress_blte(data)
        parser = EncodingParser()
        encoding = parser.parse(data)

        return {
            "version": encoding.header.version,
            "ckey_size": encoding.header.ckey_size,
            "ekey_size": encoding.header.ekey_size,
            "ckey_page_count": encoding.header.ckey_page_count,
            "ekey_page_count": encoding.header.ekey_page_count,
            "ckey_page_size_kb": encoding.header.ckey_page_size_kb,
            "ekey_page_size_kb": encoding.header.ekey_page_size_kb,
            "espec_size": encoding.header.espec_size
        }
    except Exception as e:
        return {"error": f"Failed to parse encoding: {e}"}


def _analyze_config_stats(data: bytes, config_type: str) -> dict[str, Any]:
    """Analyze configuration file statistics."""
    try:
        if config_type == "build":
            parser: BuildConfigParser | CDNConfigParser | PatchConfigParser | ProductConfigParser = BuildConfigParser()
        elif config_type == "cdn":
            parser = CDNConfigParser()
        elif config_type == "patch":
            parser = PatchConfigParser()
        elif config_type == "product":
            parser = ProductConfigParser()
        else:
            return {"error": f"Unknown config type: {config_type}"}

        config_data = parser.parse(data)

        if hasattr(config_data, 'model_dump'):
            entries = config_data.model_dump()
        else:
            entries = vars(config_data)

        return {
            "config_type": config_type,
            "entry_count": len(entries),
            "entries": entries
        }
    except Exception as e:
        return {"error": f"Failed to parse config: {e}"}


def _analyze_archive_stats(data: bytes) -> dict[str, Any]:
    """Analyze archive index statistics."""
    try:
        parser = ArchiveIndexParser()
        archive = parser.parse(data)

        total_entries = sum(len(chunk.entries) for chunk in archive.chunks)
        total_size = sum(entry.size for chunk in archive.chunks for entry in chunk.entries)

        return {
            "chunk_count": len(archive.chunks),
            "total_entries": total_entries,
            "total_content_size": total_size,
            "ekey_length": archive.footer.ekey_length,
            "version": archive.footer.version,
            "page_size_kb": archive.footer.page_size_kb
        }
    except Exception as e:
        return {"error": f"Failed to parse archive: {e}"}


def _analyze_root_stats(data: bytes) -> dict[str, Any]:
    """Analyze root file statistics."""
    try:
        parser = RootParser()
        root = parser.parse(data)

        total_records = sum(len(block.records) for block in root.blocks)

        return {
            "version": root.header.version,
            "block_count": len(root.blocks),
            "total_records": total_records,
            "total_files": root.header.total_files,
            "named_files": root.header.named_files
        }
    except Exception as e:
        return {"error": f"Failed to parse root: {e}"}


def _analyze_install_stats(data: bytes) -> dict[str, Any]:
    """Analyze install file statistics."""
    try:
        parser = InstallParser()
        install = parser.parse(data)

        return {
            "entry_count": len(install.entries),
            "tag_count": len(install.tags),
            "total_size": sum(entry.size for entry in install.entries)
        }
    except Exception as e:
        return {"error": f"Failed to parse install: {e}"}


def _analyze_download_stats(data: bytes) -> dict[str, Any]:
    """Analyze download file statistics."""
    try:
        parser = DownloadParser()
        download = parser.parse(data)

        return {
            "entry_count": len(download.entries),
            "tag_count": len(download.tags),
            "total_size": sum(entry.size for entry in download.entries),
            "priority_levels": len({entry.priority for entry in download.entries})
        }
    except Exception as e:
        return {"error": f"Failed to parse download: {e}"}


def _display_stats_table(stats_data: dict[str, Any], console: Console, verbose: bool) -> None:
    """Display statistics as Rich table."""
    table = Table(title=f"{stats_data['format_type'].title()} File Statistics")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Format Type", stats_data["format_type"])
    table.add_row("File Size", format_size(stats_data["file_size"]))
    table.add_row("MD5", stats_data["md5"])

    for key, value in stats_data.items():
        if key in ["input", "format_type", "file_size", "md5", "error"]:
            continue

        if isinstance(value, (int, float)):
            if "size" in key.lower():
                value_str = format_size(int(value))
            elif "ratio" in key.lower():
                value_str = f"{value:.3f}"
            else:
                value_str = str(value)
        else:
            value_str = str(value)

        table.add_row(key.replace("_", " ").title(), value_str)

    if "error" in stats_data:
        table.add_row("Error", f"[red]{stats_data['error']}[/red]")

    _output_table(table, console)


@click.group()
def inspect() -> None:
    """Inspect and analyze NGDP/CASC format files."""
    pass


# ---------------------------------------------------------------------------
# Format inspection (from examine.py)
# ---------------------------------------------------------------------------

@inspect.command()
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
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code (used when fetching from CDN by hash)",
)
@click.pass_context
def blte(
    ctx: click.Context,
    input_path: str,
    decompress: bool,
    output_file: Path | None,
    product: str,
) -> None:
    """Examine BLTE compressed files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    import sys
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        product_enum = Product(product)
        data = _fetch_from_cdn_or_path(
            input_path, console, config, "Fetching BLTE file", product=product_enum
        )

        parser = BLTEParser()
        blte_file = parser.parse(data)

        if config.output_format == "json":
            result: dict[str, Any] = {
                "magic": blte_file.header.magic.decode('ascii', errors='ignore'),
                "header_size": blte_file.header.header_size,
                "flags": blte_file.header.flags,
                "chunk_count": len(blte_file.chunks),
                "total_compressed_size": sum(chunk.compressed_size for chunk in blte_file.chunks),
                "total_decompressed_size": sum(chunk.decompressed_size for chunk in blte_file.chunks),
                "chunks": []
            }

            for i, chunk in enumerate(blte_file.chunks):
                chunk_info: dict[str, Any] = {
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


@inspect.command()
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
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code (used when fetching from CDN by hash)",
)
@click.pass_context
def encoding(
    ctx: click.Context,
    input_path: str,
    limit: int,
    search: str | None,
    product: str,
) -> None:
    """Examine encoding files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, _, _ = _get_context_objects(ctx)

    try:
        product_enum = Product(product)
        data = _fetch_from_cdn_or_path(
            input_path, console, config, "Fetching encoding file", product=product_enum
        )

        if is_blte(data):
            data = decompress_blte(data)

        parser = EncodingParser()
        encoding_file = parser.parse(data)

        if config.output_format == "json":
            result: dict[str, Any] = {
                "magic": encoding_file.header.magic.decode('ascii', errors='ignore'),
                "version": encoding_file.header.version,
                "ckey_size": encoding_file.header.ckey_size,
                "ekey_size": encoding_file.header.ekey_size,
                "ckey_page_size_kb": encoding_file.header.ckey_page_size_kb,
                "ekey_page_size_kb": encoding_file.header.ekey_page_size_kb,
                "ckey_page_count": encoding_file.header.ckey_page_count,
                "ekey_page_count": encoding_file.header.ekey_page_count,
                "espec_size": encoding_file.header.espec_size,
                "ckey_index_count": len(encoding_file.ckey_index),
                "ekey_index_count": len(encoding_file.ekey_index),
                "espec_table_count": len(encoding_file.espec_table),
            }

            if search:
                try:
                    ckey_bytes = bytes.fromhex(search)
                    ekeys = parser.find_content_key(data, encoding_file, ckey_bytes)
                    if ekeys:
                        result["search_result"] = {
                            "content_key": search,
                            "encoding_keys": [k.hex() for k in ekeys],
                        }
                    else:
                        result["search_result"] = {"content_key": search, "found": False}
                except ValueError as e:
                    result["search_error"] = str(e)
            else:
                entries: list[dict[str, Any]] = []
                collected = 0
                for page_idx in range(encoding_file.header.ckey_page_count):
                    if collected >= limit:
                        break
                    try:
                        page = parser.load_ckey_page(data, encoding_file, page_idx)
                        for entry in page.entries:
                            if collected >= limit:
                                break
                            entries.append({
                                "content_key": entry.content_key.hex(),
                                "encoding_keys": [k.hex() for k in entry.encoding_keys],
                                "file_size": entry.file_size,
                            })
                            collected += 1
                    except Exception:
                        break
                result["entries"] = entries

            _output_json(result, console)
        else:
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

            if search:
                try:
                    ckey_bytes = bytes.fromhex(search)
                    ekeys = parser.find_content_key(data, encoding_file, ckey_bytes)
                    if ekeys:
                        result_table = Table(title=f"Search Result: {search[:16]}...")
                        result_table.add_column("Content Key", style="cyan")
                        result_table.add_column("Encoding Keys", style="green")
                        ekey_str = "\n".join(k.hex() for k in ekeys)
                        result_table.add_row(search, ekey_str)
                        _output_table(result_table, console)
                    else:
                        console.print(f"[yellow]Content key not found: {search}[/yellow]")
                except ValueError as e:
                    console.print(f"[red]Invalid hex key: {e}[/red]")
            else:
                entries_table = Table(title=f"CKey Entries (first {limit})")
                entries_table.add_column("Content Key", style="cyan", no_wrap=True)
                entries_table.add_column("Encoding Keys", style="green")
                entries_table.add_column("File Size", style="magenta", justify="right")

                collected = 0
                for page_idx in range(encoding_file.header.ckey_page_count):
                    if collected >= limit:
                        break
                    try:
                        page = parser.load_ckey_page(data, encoding_file, page_idx)
                        for entry in page.entries:
                            if collected >= limit:
                                break
                            ekey_str = "\n".join(k.hex() for k in entry.encoding_keys)
                            entries_table.add_row(
                                entry.content_key.hex(),
                                ekey_str,
                                format_size(entry.file_size),
                            )
                            collected += 1
                    except Exception:
                        break

                if collected > 0:
                    _output_table(entries_table, console)
                else:
                    console.print("[yellow]No entries found in CKey pages[/yellow]")

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine encoding file", error=str(e))
        raise click.ClickException(f"Failed to examine encoding file: {e}") from e


@inspect.command()
@click.argument("input_path", type=str)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code (used when fetching from CDN by hash)",
)
@click.pass_context
def config(ctx: click.Context, input_path: str, product: str) -> None:
    """Examine build/CDN/product configuration files.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config_obj, console, _, _ = _get_context_objects(ctx)

    try:
        product_enum = Product(product)
        data = _fetch_from_cdn_or_path(
            input_path, console, config_obj, "Fetching config file",
            cdn_type="config", product=product_enum
        )

        if not is_config_file(data):
            raise click.ClickException("Input is not a valid config file")

        config_type = detect_config_type(data)

        if config_type == "build":
            parser: BuildConfigParser | CDNConfigParser | PatchConfigParser | ProductConfigParser = BuildConfigParser()
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
            result: dict[str, Any] = {
                "type": config_type,
                "entries": {}
            }

            if hasattr(config_data, 'model_dump'):
                result["entries"] = config_data.model_dump()
            else:
                result["entries"] = vars(config_data)

            _output_json(result, console)
        else:
            table = Table(title=f"{config_type.title()} Configuration")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")

            if hasattr(config_data, 'model_dump'):
                entries = config_data.model_dump()
            else:
                entries = vars(config_data)

            for key, value in entries.items():
                if isinstance(value, (list, tuple)):
                    value_str = ", ".join(str(v) for v in value)  # type: ignore
                    if len(value_str) > 60:
                        value_str = value_str[:57] + "..."
                elif isinstance(value, dict):
                    value_str = f"{len(value)} entries"  # type: ignore
                else:
                    value_str = str(value)

                table.add_row(key, value_str)

            _output_table(table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to examine config file", error=str(e))
        raise click.ClickException(f"Failed to examine config file: {e}") from e


@inspect.command()
@click.argument("input_path", type=str)
@click.pass_context
def archive(ctx: click.Context, input_path: str) -> None:
    """Examine archive index files.

    INPUT can be either a file path or CDN hash with .index extension.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching archive index", cdn_type="index")

        parser = ArchiveIndexParser()
        archive_index = parser.parse(data)

        if config.output_format == "json":
            result: dict[str, Any] = {
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

            if archive_index.chunks and archive_index.chunks[0].entries:
                for entry in archive_index.chunks[0].entries[:10]:
                    result["sample_entries"].append({
                        "encoding_key": entry.ekey.hex(),
                        "size": entry.size,
                        "offset": entry.offset
                    })

            _output_json(result, console)
        else:
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

            structure_table = Table(title="Index Structure")
            structure_table.add_column("Property", style="cyan")
            structure_table.add_column("Value", style="white")

            structure_table.add_row("Chunk Count", str(len(archive_index.chunks)))
            structure_table.add_row("Total Entries", str(sum(len(chunk.entries) for chunk in archive_index.chunks)))

            if archive_index.chunks:
                avg_entries = sum(len(chunk.entries) for chunk in archive_index.chunks) / len(archive_index.chunks)
                structure_table.add_row("Avg Entries/Chunk", f"{avg_entries:.1f}")

            _output_table(structure_table, console)

            if verbose and archive_index.chunks and archive_index.chunks[0].entries:
                entries_table = Table(title="Sample Entries (First Chunk)")
                entries_table.add_column("Encoding Key", style="yellow")
                entries_table.add_column("Size", style="green")
                entries_table.add_column("Offset", style="blue")

                for entry in archive_index.chunks[0].entries[:10]:
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


# ---------------------------------------------------------------------------
# Format analysis (from analyze.py)
# ---------------------------------------------------------------------------

@inspect.command()
@click.argument("input_path", type=str)
@click.option(
    "--format-type", "-t",
    type=click.Choice(["auto", "blte", "encoding", "config", "archive", "root", "install", "download"], case_sensitive=False),
    default="auto",
    help="Force specific format type (auto-detect if not specified)"
)
@click.pass_context
def stats(
    ctx: click.Context,
    input_path: str,
    format_type: str
) -> None:
    """Show statistics for a format file.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching file for analysis")

        if format_type == "auto":
            format_type = _detect_format_type(data)
            if format_type == "unknown":
                raise click.ClickException("Could not auto-detect format type. Please specify --format-type")

        stats_data = {
            "input": input_path,
            "format_type": format_type,
            "file_size": len(data),
            "md5": compute_md5(data).hex()
        }

        if format_type == "blte":
            stats_data.update(_analyze_blte_stats(data))
        elif format_type == "encoding":
            stats_data.update(_analyze_encoding_stats(data))
        elif format_type in ["build", "cdn", "patch", "product"]:
            stats_data.update(_analyze_config_stats(data, format_type))
        elif format_type == "archive":
            stats_data.update(_analyze_archive_stats(data))
        elif format_type == "root":
            stats_data.update(_analyze_root_stats(data))
        elif format_type == "install":
            stats_data.update(_analyze_install_stats(data))
        elif format_type == "download":
            stats_data.update(_analyze_download_stats(data))
        else:
            stats_data["error"] = f"Analysis not implemented for format: {format_type}"

        if config.output_format == "json":
            _output_json(stats_data, console)
        else:
            _display_stats_table(stats_data, console, verbose)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to analyze file", error=str(e))
        raise click.ClickException(f"Failed to analyze file: {e}") from e


@inspect.command()
@click.argument("encoding_file", type=str)
@click.argument("content_key", type=str)
@click.option(
    "--show-archive-details", "-a",
    is_flag=True,
    help="Show detailed archive information"
)
@click.pass_context
def dependencies(
    ctx: click.Context,
    encoding_file: str,
    content_key: str,
    show_archive_details: bool
) -> None:
    """Trace content key to encoding key to archive.

    ENCODING_FILE can be either a file path or CDN hash.
    CONTENT_KEY should be a hex string of the content key to trace.
    """
    config, console, _, _ = _get_context_objects(ctx)

    try:
        try:
            bytes.fromhex(content_key)
        except ValueError as e:
            raise click.ClickException(f"Invalid content key hex string: {e}") from e

        encoding_data = _fetch_from_cdn_or_path(encoding_file, console, config, "Fetching encoding file")
        if is_blte(encoding_data):
            encoding_data = decompress_blte(encoding_data)

        parser = EncodingParser()
        encoding = parser.parse(encoding_data)

        deps_data = {
            "content_key": content_key,
            "encoding_file": encoding_file,
            "note": "Full dependency tracing requires encoding page loading implementation",
            "encoding_info": {
                "ckey_size": encoding.header.ckey_size,
                "ekey_size": encoding.header.ekey_size,
                "ckey_page_count": encoding.header.ckey_page_count,
                "ekey_page_count": encoding.header.ekey_page_count
            }
        }

        if config.output_format == "json":
            _output_json(deps_data, console)
        else:
            table = Table(title="Dependency Analysis")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Content Key", content_key)
            table.add_row("Encoding File", encoding_file)
            table.add_row("Status", "[yellow]Requires page loading implementation[/yellow]")

            _output_table(table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to analyze dependencies", error=str(e))
        raise click.ClickException(f"Failed to analyze dependencies: {e}") from e


@inspect.command()
@click.argument("encoding_file", type=str)
@click.argument("root_file", type=str, required=False)
@click.argument("install_file", type=str, required=False)
@click.pass_context
def coverage(
    ctx: click.Context,
    encoding_file: str,
    root_file: str | None,
    install_file: str | None
) -> None:
    """Analyze content coverage between encoding, root, and install manifests.

    ENCODING_FILE is required. ROOT_FILE and INSTALL_FILE are optional.
    All can be either file paths or CDN hashes.
    """
    config, console, _, _ = _get_context_objects(ctx)

    try:
        coverage_data: dict[str, Any] = {
            "encoding_file": encoding_file,
            "root_file": root_file,
            "install_file": install_file
        }

        encoding_data = _fetch_from_cdn_or_path(encoding_file, console, config, "Fetching encoding file")
        if is_blte(encoding_data):
            encoding_data = decompress_blte(encoding_data)
        encoding_parser = EncodingParser()
        encoding = encoding_parser.parse(encoding_data)

        coverage_data["encoding_stats"] = {
            "ckey_page_count": encoding.header.ckey_page_count,
            "ekey_page_count": encoding.header.ekey_page_count,
            "note": "Entry count requires page loading"
        }

        root = None
        install = None

        if root_file:
            root_data = _fetch_from_cdn_or_path(root_file, console, config, "Fetching root file")
            root_parser = RootParser()
            root = root_parser.parse(root_data)

            total_records = sum(len(block.records) for block in root.blocks)
            coverage_data["root_stats"] = {
                "block_count": len(root.blocks),
                "total_records": total_records,
                "version": root.header.version
            }

        if install_file:
            install_data = _fetch_from_cdn_or_path(install_file, console, config, "Fetching install file")
            install_parser = InstallParser()
            install = install_parser.parse(install_data)

            coverage_data["install_stats"] = {
                "entry_count": len(install.entries),
                "tag_count": len(install.tags)
            }

        coverage_data["note"] = "Detailed coverage analysis requires full entry loading implementation"

        if config.output_format == "json":
            _output_json(coverage_data, console)
        else:
            table = Table(title="Content Coverage Analysis")
            table.add_column("Manifest", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("Details", style="yellow")

            table.add_row("Encoding", "Analyzed", f"{encoding.header.ckey_page_count} CKey pages")

            if root_file and root:
                table.add_row("Root", "Analyzed", f"{len(root.blocks)} blocks")
            else:
                table.add_row("Root", "Not provided", "-")

            if install_file and install:
                table.add_row("Install", "Analyzed", f"{len(install.entries)} entries")
            else:
                table.add_row("Install", "Not provided", "-")

            _output_table(table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to analyze coverage", error=str(e))
        raise click.ClickException(f"Failed to analyze coverage: {e}") from e


@inspect.command()
@click.argument("input_path", type=str)
@click.option(
    "--threshold", "-t",
    type=float,
    default=0.8,
    help="Compression ratio threshold for 'poorly compressed' files (default: 0.8)"
)
@click.option(
    "--limit", "-l",
    type=int,
    default=10,
    help="Limit number of poorly compressed files to show"
)
@click.pass_context
def compression(
    ctx: click.Context,
    input_path: str,
    threshold: float,
    limit: int
) -> None:
    """Analyze BLTE compression effectiveness.

    INPUT can be either a file path or CDN hash.
    Shows compression ratios and identifies poorly compressed content.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching BLTE file")

        if not is_blte(data):
            raise click.ClickException("Input file is not a BLTE file")

        compression_data = _analyze_blte_compression(data)

        if "error" in compression_data:
            raise click.ClickException(compression_data["error"])

        poorly_compressed = [
            (i, chunk) for i, chunk in enumerate(compression_data["chunk_details"])
            if chunk["ratio"] > threshold
        ]

        compression_data["poorly_compressed_count"] = len(poorly_compressed)
        compression_data["poorly_compressed_chunks"] = poorly_compressed[:limit]
        compression_data["threshold"] = threshold

        if config.output_format == "json":
            _output_json(compression_data, console)
        else:
            summary_table = Table(title="BLTE Compression Analysis")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Value", style="white")

            summary_table.add_row("Total Chunks", str(compression_data["chunk_count"]))
            summary_table.add_row("Compressed Size", format_size(compression_data["total_compressed_size"]))
            summary_table.add_row("Decompressed Size", format_size(compression_data["total_decompressed_size"]))
            summary_table.add_row("Overall Ratio", f"{compression_data['overall_compression_ratio']:.3f}")
            summary_table.add_row("Poorly Compressed", f"{len(poorly_compressed)} (>{threshold:.1f} ratio)")

            _output_table(summary_table, console)

            if verbose:
                modes_table = Table(title="Compression Modes")
                modes_table.add_column("Mode", style="cyan")
                modes_table.add_column("Count", style="white")

                for mode, count in compression_data["compression_modes"].items():
                    modes_table.add_row(mode, str(count))

                _output_table(modes_table, console)

            if poorly_compressed:
                poor_table = Table(title=f"Poorly Compressed Chunks (showing {min(limit, len(poorly_compressed))})")
                poor_table.add_column("Chunk", style="cyan")
                poor_table.add_column("Compressed", style="yellow")
                poor_table.add_column("Decompressed", style="green")
                poor_table.add_column("Ratio", style="red")
                poor_table.add_column("Mode", style="blue")

                for i, chunk in poorly_compressed[:limit]:
                    poor_table.add_row(
                        str(i),
                        format_size(chunk["compressed_size"]),
                        format_size(chunk["decompressed_size"]),
                        f"{chunk['ratio']:.3f}",
                        chunk["compression_mode"]
                    )

                _output_table(poor_table, console)

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Failed to analyze compression", error=str(e))
        raise click.ClickException(f"Failed to analyze compression: {e}") from e
