"""Analyze commands for NGDP/CASC data analysis."""

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
) -> bytes:
    """Fetch data from CDN hash or read from file path.

    Args:
        input_str: Hash string or file path
        console: Rich console for output
        config: Application configuration
        progress_text: Text to show during CDN fetch
        cdn_type: CDN content type - "config" for build/CDN/patch configs,
            "data" for archives, encoding, root, install, download files

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
            if cdn_type == "config":
                data = cdn_client.fetch_config(input_str)
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
        # Try to detect archive index by file extension or structure
        if data.endswith(b'\x00' * 12):  # Archive indices often end with padding
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


@click.group()
def analyze() -> None:
    """Analyze NGDP/CASC format files and data."""
    pass


@analyze.command()
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
    """Analyze format files and show statistics.

    INPUT can be either a file path or CDN hash.
    If hash is provided, file will be fetched from CDN.
    """
    config, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching file for analysis")

        # Detect format if auto
        if format_type == "auto":
            format_type = _detect_format_type(data)
            if format_type == "unknown":
                raise click.ClickException("Could not auto-detect format type. Please specify --format-type")

        # Analyze based on format type
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


@analyze.command()
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
    """Analyze file dependencies by tracing content key to encoding key to archive.

    ENCODING_FILE can be either a file path or CDN hash.
    CONTENT_KEY should be a hex string of the content key to trace.
    """
    config, console, _, _ = _get_context_objects(ctx)

    try:
        # Validate content key
        try:
            bytes.fromhex(content_key)
        except ValueError as e:
            raise click.ClickException(f"Invalid content key hex string: {e}") from e

        # Fetch encoding file
        encoding_data = _fetch_from_cdn_or_path(encoding_file, console, config, "Fetching encoding file")

        # Parse encoding file
        parser = EncodingParser()
        encoding = parser.parse(encoding_data)

        # Note: Full dependency tracing requires implementing page loading in encoding parser
        # For now, provide structure information
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


@analyze.command()
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

        # Parse encoding file
        encoding_data = _fetch_from_cdn_or_path(encoding_file, console, config, "Fetching encoding file")
        encoding_parser = EncodingParser()
        encoding = encoding_parser.parse(encoding_data)

        coverage_data["encoding_stats"] = {
            "ckey_page_count": encoding.header.ckey_page_count,
            "ekey_page_count": encoding.header.ekey_page_count,
            "note": "Entry count requires page loading"
        }

        # Initialize variables for type checking
        root = None
        install = None

        # Parse root file if provided
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

        # Parse install file if provided
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


@analyze.command()
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
        # Fetch data
        data = _fetch_from_cdn_or_path(input_path, console, config, "Fetching BLTE file")

        # Verify it's BLTE
        if not is_blte(data):
            raise click.ClickException("Input file is not a BLTE file")

        # Analyze compression
        compression_data = _analyze_blte_compression(data)

        if "error" in compression_data:
            raise click.ClickException(compression_data["error"])

        # Find poorly compressed chunks
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
            # Summary table
            summary_table = Table(title="BLTE Compression Analysis")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Value", style="white")

            summary_table.add_row("Total Chunks", str(compression_data["chunk_count"]))
            summary_table.add_row("Compressed Size", format_size(compression_data["total_compressed_size"]))
            summary_table.add_row("Decompressed Size", format_size(compression_data["total_decompressed_size"]))
            summary_table.add_row("Overall Ratio", f"{compression_data['overall_compression_ratio']:.3f}")
            summary_table.add_row("Poorly Compressed", f"{len(poorly_compressed)} (>{threshold:.1f} ratio)")

            _output_table(summary_table, console)

            # Compression modes
            if verbose:
                modes_table = Table(title="Compression Modes")
                modes_table.add_column("Mode", style="cyan")
                modes_table.add_column("Count", style="white")

                for mode, count in compression_data["compression_modes"].items():
                    modes_table.add_row(mode, str(count))

                _output_table(modes_table, console)

            # Poorly compressed chunks
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
            parser = BuildConfigParser()
        elif config_type == "cdn":
            parser = CDNConfigParser()
        elif config_type == "patch":
            parser = PatchConfigParser()
        elif config_type == "product":
            parser = ProductConfigParser()
        else:
            return {"error": f"Unknown config type: {config_type}"}

        config_data = parser.parse(data)

        # Convert to dict for analysis
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

    # Basic info
    table.add_row("Format Type", stats_data["format_type"])
    table.add_row("File Size", format_size(stats_data["file_size"]))
    table.add_row("MD5", stats_data["md5"])

    # Format-specific stats
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

    # Show error if present
    if "error" in stats_data:
        table.add_row("Error", f"[red]{stats_data['error']}[/red]")

    _output_table(table, console)
