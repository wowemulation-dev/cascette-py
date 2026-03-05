"""CDN commands for downloading data from Blizzard's NGDP infrastructure."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.config import AppConfig, CDNConfig
from cascette_tools.core.tact import TACTClient
from cascette_tools.core.types import Product
from cascette_tools.core.utils import format_size, validate_hash_string
from cascette_tools.formats import (
    EncodingParser,
    detect_config_type,
    is_blte,
    is_encoding,
)
from cascette_tools.formats.blte import decompress_blte
from cascette_tools.formats.blte_integration import create_integrated_parser
from cascette_tools.formats.config import (
    BuildConfigParser,
    CDNConfigParser,
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


def _get_cdn_mirrors_for_product(product: str) -> list[str]:
    """Get appropriate CDN mirrors based on product type.

    Args:
        product: Product code string

    Returns:
        List of CDN mirror URLs in priority order
    """
    # WoW products use community mirrors
    wow_products = ["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]

    if product in wow_products:
        return [
            "https://casc.wago.tools",
            "https://cdn.arctium.tools",
            "https://archive.wow.tools",
        ]
    else:
        # Non-WoW products use official Blizzard CDNs
        # These are extracted from the TACT cdns endpoint
        return [
            "http://blzddist1-a.akamaihd.net",
            "http://level3.blizzard.com",
            "http://cdn.blizzard.com"
        ]


def _save_file(data: bytes, output_path: Path, console: Console, verbose: bool) -> None:
    """Save data to file and report success."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

    if verbose:
        console.print(f"[green]Saved {format_size(len(data))} to {output_path}[/green]")


def _show_config_metadata(data: bytes, config_type: str | None, console: Console) -> None:
    """Show metadata about a configuration file."""
    try:
        text_data = data.decode('utf-8', errors='ignore')
        lines = text_data.count('\n')

        table = Table(title=f"{(config_type or 'Unknown').title()} Configuration Metadata")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Size", format_size(len(data)))
        table.add_row("Lines", str(lines))
        table.add_row("Type", config_type or 'Unknown')

        # Try to parse and show basic info
        if config_type == "build":
            try:
                parser = BuildConfigParser()
                config = parser.parse(text_data.encode('utf-8'))
                table.add_row("Root", config.root or "N/A")
                table.add_row("Encoding", config.encoding or "N/A")
                table.add_row("Install", config.install or "N/A")
                table.add_row("Download", config.download or "N/A")
            except Exception:
                pass
        elif config_type == "cdn":
            try:
                parser = CDNConfigParser()
                config = parser.parse(text_data.encode('utf-8'))
                table.add_row("Archives", str(len(config.archives)))
                table.add_row("Patch Archives", str(len(config.patch_archives)))
            except Exception:
                pass
        elif config_type == "product":
            try:
                parser = ProductConfigParser()
                config = parser.parse(text_data.encode('utf-8'))
                table.add_row("Product", config.product or "N/A")
                table.add_row("UID", config.uid or "N/A")
            except Exception:
                pass

        console.print(table)

    except Exception as e:
        console.print(f"[yellow]Warning: Could not parse config metadata: {e}[/yellow]")


@click.group()
@click.pass_context
def cdn(ctx: click.Context) -> None:
    """Download data from Blizzard's NGDP CDN infrastructure."""
    pass


@cdn.command()
@click.argument("hash_str", type=str)
@click.option(
    "--type",
    "config_type",
    type=click.Choice(["build", "cdn", "product", "patch"], case_sensitive=False),
    help="Configuration type (auto-detected if not specified)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: {hash}.{type})",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--show-metadata",
    is_flag=True,
    help="Show configuration metadata",
)
@click.pass_context
def config(
    ctx: click.Context,
    hash_str: str,
    config_type: str | None,
    output: Path | None,
    product: str,
    region: str,
    show_metadata: bool,
) -> None:
    """Fetch configuration files from CDN.

    HASH_STR can be a configuration file hash.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    # Validate hash
    if not validate_hash_string(hash_str):
        console.print(f"[red]Error: Invalid hash format: {hash_str}[/red]")
        sys.exit(1)

    try:
        # Create CDN client
        product_enum = Product(product)
        cdn_config = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            console.print(f"[blue]Fetching configuration {hash_str}...[/blue]")

            # Fetch the config
            data = cdn_client.fetch_config(hash_str)

            # Auto-detect config type if not specified
            if not config_type:
                config_type = detect_config_type(data)
                if verbose:
                    console.print(f"[cyan]Auto-detected type: {config_type}[/cyan]")

            # Determine output path
            if not output:
                output = Path(f"{hash_str}.{config_type}")

            # Save file
            _save_file(data, output, console, verbose)

            # Show metadata if requested
            if show_metadata:
                _show_config_metadata(data, config_type, console)

            console.print(f"[green]Successfully fetched {config_type} configuration[/green]")

    except Exception as e:
        logger.error("config_fetch_failed", hash=hash_str, error=str(e))
        console.print(f"[red]Error fetching configuration: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.argument("hash_str", type=str)
@click.option(
    "--index",
    is_flag=True,
    help="Fetch archive index file instead of data",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: {hash} or {hash}.index)",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--decompress",
    is_flag=True,
    help="Decompress BLTE data if applicable",
)
@click.option(
    "--show-info",
    is_flag=True,
    help="Show file information",
)
@click.pass_context
def data(
    ctx: click.Context,
    hash_str: str,
    index: bool,
    output: Path | None,
    product: str,
    region: str,
    decompress: bool,
    show_info: bool,
) -> None:
    """Fetch data archives from CDN.

    HASH_STR can be an archive hash for data or index files.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    # Validate hash
    if not validate_hash_string(hash_str):
        console.print(f"[red]Error: Invalid hash format: {hash_str}[/red]")
        sys.exit(1)

    try:
        # Create CDN client
        product_enum = Product(product)
        cdn_config = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            file_type_str = "index" if index else "data"
            console.print(f"[blue]Fetching {file_type_str} {hash_str}...[/blue]")

            # Fetch the data
            data = cdn_client.fetch_data(hash_str, is_index=index)

            # Determine output path
            if not output:
                suffix = ".index" if index else ""
                output = Path(f"{hash_str}{suffix}")

            # Handle decompression
            final_data = data
            if decompress and not index and is_blte(data):
                try:
                    # Create integrated parser for BLTE decompression
                    blte_parser = create_integrated_parser(config_obj)
                    blte_file = blte_parser.parse(data)
                    final_data = blte_parser.decompress(blte_file)

                    if verbose:
                        console.print(f"[cyan]Decompressed BLTE: {format_size(len(data))} -> {format_size(len(final_data))}[/cyan]")

                    # Update output path to indicate decompression
                    if output.suffix != ".decompressed":
                        output = output.with_suffix(output.suffix + ".decompressed")

                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to decompress BLTE: {e}[/yellow]")
                    final_data = data

            # Save file
            _save_file(final_data, output, console, verbose)

            # Show file information if requested
            if show_info:
                table = Table(title=f"{file_type_str.title()} File Information")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="magenta")

                table.add_row("Hash", hash_str)
                table.add_row("Type", file_type_str)
                table.add_row("Size", format_size(len(data)))

                if decompress and is_blte(data):
                    table.add_row("BLTE", "Yes")
                    table.add_row("Decompressed Size", format_size(len(final_data)))
                else:
                    table.add_row("BLTE", "No")

                console.print(table)

            console.print(f"[green]Successfully fetched {file_type_str} file[/green]")

    except Exception as e:
        logger.error("data_fetch_failed", hash=hash_str, index=index, error=str(e))
        file_type_desc = "index" if index else "data"
        console.print(f"[red]Error fetching {file_type_desc}: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.argument("build_id", type=str)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory (default: build_{build_id})",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--include-manifests",
    is_flag=True,
    help="Also fetch encoding, root, install, and download manifests",
)
@click.pass_context
def build(
    ctx: click.Context,
    build_id: str,
    output_dir: Path | None,
    product: str,
    region: str,
    include_manifests: bool,
) -> None:
    """Fetch complete build information.

    BUILD_ID can be a build number like '19027' or a build config hash.
    Fetches build config, CDN config, and optionally manifests.

    If BUILD_ID is a number, looks it up in the build database for the specified product.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Create TACT and CDN clients
        product_enum = Product(product)
        # tact_client = TACTClient(region=region)  # Currently unused
        cdn_config = CDNConfig(
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            console.print(f"[blue]Fetching build information for {build_id}...[/blue]")

            # Determine if build_id is a hash or build number
            build_config_hash = None
            cdn_config_hash = None
            version_string = build_id  # Default for directory naming
            build_info = None  # Track for EKEY updates
            discovered_ekeys = {}  # Track discovered EKEYs

            if validate_hash_string(build_id):
                # Direct hash provided
                build_config_hash = build_id
            else:
                # Look up build in database
                from cascette_tools.database.wago import WagoClient

                with WagoClient(config_obj) as wago_client:
                    # Search for builds with this build ID and product
                    builds = wago_client.search_builds(build_id, field="build")

                    # Filter by product
                    matching_builds = [b for b in builds if b.product == product]

                    if not matching_builds:
                        console.print(f"[red]Error: Build {build_id} not found for product {product}[/red]")
                        console.print("[yellow]Hint: Use 'cascette_tools builds search' to find available builds[/yellow]")
                        sys.exit(1)

                    # Use first matching build (they should all have same config hashes)
                    build_info = matching_builds[0]
                    build_config_hash = build_info.build_config
                    cdn_config_hash = build_info.cdn_config
                    version_string = build_info.version or build_id

                    if not build_config_hash:
                        console.print(f"[red]Error: Build {build_id} has no build config hash[/red]")
                        sys.exit(1)

                    if verbose:
                        console.print(f"[dim]Found build: {version_string} (Build {build_info.build})[/dim]")
                        console.print(f"[dim]Build config: {build_config_hash}[/dim]")
                        if cdn_config_hash:
                            console.print(f"[dim]CDN config: {cdn_config_hash}[/dim]")

            # Create output directory
            if not output_dir:
                output_dir = Path(f"build_{version_string.replace('.', '_')}")
            output_dir.mkdir(parents=True, exist_ok=True)

            # Progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:

                # Calculate total tasks
                total_tasks = 2  # build + cdn config
                if include_manifests:
                    total_tasks += 4  # root, encoding, install, download

                task = progress.add_task("Fetching build data...", total=total_tasks)

                # Fetch build config
                progress.update(task, description="Fetching build config...")
                build_data = cdn_client.fetch_config(build_config_hash, "build")
                build_path = output_dir / f"{build_config_hash}.build"
                _save_file(build_data, build_path, console, False)
                progress.advance(task)

                # Parse build config to get CDN config hash (if not already from database)
                parser = BuildConfigParser()
                build_config = parser.parse(build_data)

                # Use CDN config from database if available, otherwise try build config
                if not cdn_config_hash:
                    # Try to get CDN config from extra_fields (TACT format specific)
                    cdn_config_hash = build_config.extra_fields.get('cdn-config')

                if cdn_config_hash:
                    # Fetch CDN config
                    progress.update(task, description="Fetching CDN config...")
                    cdn_data = cdn_client.fetch_config(cdn_config_hash, "cdn")
                    cdn_path = output_dir / f"{cdn_config_hash}.cdn"
                    _save_file(cdn_data, cdn_path, console, False)
                    progress.advance(task)
                else:
                    console.print("[yellow]Warning: No CDN config hash available[/yellow]")
                    progress.advance(task)

                # Fetch manifests if requested
                if include_manifests:
                    # Extract encoding key from the build config encoding field
                    # Format can be either:
                    # - Single hash: the encoding key itself
                    # - Two hashes: "content_key encoding_key" - we need the second one
                    encoding_key = None
                    if build_config.encoding:
                        parts = build_config.encoding.split()
                        if len(parts) == 2:
                            # Two hashes: first is content key, second is encoding key
                            encoding_key = parts[1]
                        else:
                            # Single hash: it's the encoding key
                            encoding_key = parts[0]

                        # Track discovered EKEY
                        if encoding_key:
                            discovered_ekeys['encoding_ekey'] = encoding_key

                    # First, fetch the encoding manifest if we have its key
                    encoding_parser = None
                    encoding_manifest = None
                    encoding_raw_data = None  # Keep raw data for lookups
                    if encoding_key:
                        progress.update(task, description="Fetching encoding manifest...")
                        try:
                            encoding_raw_data = cdn_client.fetch_data(encoding_key)
                            encoding_path = output_dir / f"{encoding_key}.encoding"
                            _save_file(encoding_raw_data, encoding_path, console, False)

                            # Check if data is BLTE compressed and decompress if needed
                            encoding_data = encoding_raw_data
                            if encoding_data.startswith(b'BL'):
                                try:
                                    encoding_data = decompress_blte(encoding_data)
                                except Exception as blte_error:
                                    console.print(f"[yellow]Warning: Failed to decompress BLTE encoding data: {blte_error}[/yellow]")
                                    # Try without decompression as fallback

                            # Parse the encoding manifest to look up content keys
                            encoding_parser = EncodingParser()
                            encoding_manifest = encoding_parser.parse(encoding_data)
                            # Keep the decompressed data for content key lookups
                            encoding_raw_data = encoding_data
                        except Exception as e:
                            console.print(f"[yellow]Warning: Failed to fetch/parse encoding: {e}[/yellow]")
                            encoding_parser = None
                            encoding_manifest = None
                            encoding_raw_data = None
                    progress.advance(task)

                    # Now fetch other manifests
                    # For root, install, download: these can be either:
                    # - Single hash: content key (look up in encoding)
                    # - Two hashes: content key + encoding key (use encoding key directly)
                    manifests = [
                        ("root", build_config.root),
                        ("install", build_config.install),
                        ("download", build_config.download),
                    ]

                    for manifest_type, manifest_value in manifests:
                        if manifest_value:
                            progress.update(task, description=f"Fetching {manifest_type} manifest...")
                            try:
                                # Check if we have two hashes (content key + encoding key)
                                parts = manifest_value.split()

                                if len(parts) == 2:
                                    # Two hashes: first is content key, second is encoding key
                                    content_key_str = parts[0]
                                    encoding_key_for_content = parts[1]
                                    if verbose:
                                        console.print(f"[dim]{manifest_type} has direct encoding key: {encoding_key_for_content}[/dim]")
                                else:
                                    # Single hash: it's a content key, need to look up in encoding
                                    content_key_str = parts[0]
                                    content_key_bytes = bytes.fromhex(content_key_str)

                                    # Look up the encoding key for this content key
                                    encoding_key_for_content = None
                                    if encoding_parser and encoding_manifest and encoding_raw_data:
                                        # Use sequential reading method like Rust to look up content key
                                        encoding_keys = encoding_parser.find_content_key_sequential(
                                            encoding_raw_data,
                                            encoding_manifest,
                                            content_key_bytes
                                        )
                                        if encoding_keys:
                                            # Use the first encoding key
                                            encoding_key_for_content = encoding_keys[0].hex()
                                            if verbose:
                                                console.print(f"[dim]Found encoding key for {manifest_type}: {encoding_key_for_content}[/dim]")

                                    if not encoding_key_for_content:
                                        # Try using the content key directly as a fallback
                                        # (some very early builds might work this way)
                                        encoding_key_for_content = content_key_str
                                        if encoding_parser:
                                            console.print(f"[yellow]Warning: Content key {content_key_str[:8]}... not found in encoding manifest, trying direct fetch[/yellow]")

                                # Track discovered EKEY for this manifest type
                                if encoding_key_for_content:
                                    discovered_ekeys[f'{manifest_type}_ekey'] = encoding_key_for_content

                                # Fetch using the encoding key
                                manifest_data = cdn_client.fetch_data(encoding_key_for_content)
                                # CRITICAL: Save with encoding key name, NOT content key!
                                manifest_path = output_dir / f"{encoding_key_for_content}.{manifest_type}"
                                _save_file(manifest_data, manifest_path, console, False)
                            except Exception as e:
                                console.print(f"[yellow]Warning: Failed to fetch {manifest_type}: {e}[/yellow]")
                        progress.advance(task)

            # Create summary
            table = Table(title="Build Information Summary")
            table.add_column("Component", style="cyan")
            table.add_column("Content Key", style="magenta")
            table.add_column("Encoding Key", style="blue")
            table.add_column("Status", style="green")

            table.add_row("Build Config", build_config_hash, "-", "Downloaded")
            if cdn_config_hash:
                table.add_row("CDN Config", cdn_config_hash, "-", "Downloaded")

            if include_manifests:
                # Track what we downloaded
                for manifest_type, manifest_hash in [
                    ("Root", build_config.root),
                    ("Encoding", build_config.encoding),
                    ("Install", build_config.install),
                    ("Download", build_config.download),
                ]:
                    if manifest_hash:
                        # Parse the hash value which may be "content_key encoding_key" or just "content_key"
                        parts = manifest_hash.split()
                        content_key = parts[0]

                        if len(parts) == 2:
                            # We have both keys
                            encoding_key = parts[1]
                        else:
                            # Need to find encoding key - check what file actually exists
                            # Try to find the file we saved
                            possible_files = list(output_dir.glob(f"*.{manifest_type.lower()}"))
                            if possible_files:
                                # Get the encoding key from the actual filename
                                encoding_key = possible_files[0].stem
                            else:
                                encoding_key = "Not found"

                        # Check if file exists with encoding key name
                        manifest_path = output_dir / f"{encoding_key}.{manifest_type.lower()}"
                        status = "Downloaded" if manifest_path.exists() else "Failed"

                        # Show both keys in the table
                        table.add_row(manifest_type, content_key[:16] + "...", encoding_key[:16] + "...", status)

            console.print(table)
            console.print(f"[green]Build data saved to {output_dir}[/green]")

            # Update database with discovered EKEYs if we have a build_info object
            if build_info and discovered_ekeys:
                from cascette_tools.database.wago import WagoClient

                try:
                    with WagoClient(config_obj) as wago_client:
                        # Update the build with discovered EKEYs
                        success = wago_client.update_build_ekeys(
                            build_id=build_info.id,
                            product=build_info.product,
                            encoding_ekey=discovered_ekeys.get('encoding_ekey'),  # type: ignore
                            root_ekey=discovered_ekeys.get('root_ekey'),  # type: ignore
                            install_ekey=discovered_ekeys.get('install_ekey'),  # type: ignore
                            download_ekey=discovered_ekeys.get('download_ekey')  # type: ignore
                        )

                        if success:
                            if verbose:
                                console.print(f"[dim]Updated database with {len(discovered_ekeys)} discovered EKEYs[/dim]")  # type: ignore
                        else:
                            if verbose:
                                console.print("[yellow]Warning: Failed to update database with discovered EKEYs[/yellow]")

                except Exception as e:
                    # Don't fail the whole operation if database update fails
                    if verbose:
                        console.print(f"[yellow]Warning: Could not update database with EKEYs: {e}[/yellow]")

    except Exception as e:
        logger.error("build_fetch_failed", build_id=build_id, error=str(e))
        console.print(f"[red]Error fetching build: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.argument("hash_str", type=str)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: {hash}.encoding)",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--decompress",
    is_flag=True,
    help="Decompress BLTE data if applicable",
)
@click.option(
    "--show-stats",
    is_flag=True,
    help="Show encoding file statistics",
)
@click.pass_context
def encoding(
    ctx: click.Context,
    hash_str: str,
    output: Path | None,
    product: str,
    region: str,
    decompress: bool,
    show_stats: bool,
) -> None:
    """Fetch encoding file by hash.

    HASH_STR must be an encoding file hash.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    # Validate hash
    if not validate_hash_string(hash_str):
        console.print(f"[red]Error: Invalid hash format: {hash_str}[/red]")
        sys.exit(1)

    try:
        # Create CDN client
        product_enum = Product(product)
        cdn_config = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            console.print(f"[blue]Fetching encoding {hash_str}...[/blue]")

            # Fetch the encoding file
            data = cdn_client.fetch_data(hash_str)

            # Determine output path
            if not output:
                output = Path(f"{hash_str}.encoding")

            # Handle decompression
            final_data = data
            if decompress and is_blte(data):
                try:
                    blte_parser = create_integrated_parser(config_obj)
                    blte_file = blte_parser.parse(data)
                    final_data = blte_parser.decompress(blte_file)

                    if verbose:
                        console.print(f"[cyan]Decompressed BLTE: {format_size(len(data))} -> {format_size(len(final_data))}[/cyan]")

                    # Update output path to indicate decompression
                    if output.suffix != ".decompressed":
                        output = output.with_suffix(output.suffix + ".decompressed")

                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to decompress BLTE: {e}[/yellow]")
                    final_data = data

            # Save file
            _save_file(final_data, output, console, verbose)

            # Show statistics if requested
            if show_stats and is_encoding(final_data):
                try:
                    parser = EncodingParser()
                    encoding_file = parser.parse(final_data)

                    table = Table(title="Encoding File Statistics")
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="magenta")

                    table.add_row("Hash", hash_str)
                    table.add_row("Size", format_size(len(data)))
                    if decompress and len(final_data) != len(data):
                        table.add_row("Decompressed Size", format_size(len(final_data)))
                    table.add_row("CKey Index Size", str(len(encoding_file.ckey_index)))
                    table.add_row("EKey Index Size", str(len(encoding_file.ekey_index)))
                    table.add_row("ESpec Table Size", str(len(encoding_file.espec_table)))

                    console.print(table)

                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to parse encoding statistics: {e}[/yellow]")

            console.print("[green]Successfully fetched encoding file[/green]")

    except Exception as e:
        logger.error("encoding_fetch_failed", hash=hash_str, error=str(e))
        console.print(f"[red]Error fetching encoding: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory (default: batch_fetch)",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--file-type",
    type=click.Choice(["config", "data", "index", "encoding"], case_sensitive=False),
    default="data",
    help="Type of files to fetch",
)
@click.option(
    "--max-workers",
    type=int,
    default=4,
    help="Maximum number of parallel downloads",
)
@click.option(
    "--retry-failed",
    is_flag=True,
    help="Retry failed downloads at the end",
)
@click.pass_context
def batch(
    ctx: click.Context,
    input_file: Path,
    output_dir: Path | None,
    product: str,
    region: str,
    file_type: str,
    max_workers: int,
    retry_failed: bool,
) -> None:
    """Batch fetch from a list of hashes.

    INPUT_FILE should contain one hash per line.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Read hash list
        hashes: list[str] = []
        with input_file.open('r') as f:
            for line_num, line in enumerate(f, 1):
                hash_str = line.strip()
                if not hash_str or hash_str.startswith('#'):
                    continue

                if not validate_hash_string(hash_str):
                    console.print(f"[yellow]Warning: Invalid hash on line {line_num}: {hash_str}[/yellow]")
                    continue

                hashes.append(hash_str)

        if not hashes:
            console.print("[red]Error: No valid hashes found in input file[/red]")
            sys.exit(1)

        # Create output directory
        if not output_dir:
            output_dir = Path("batch_fetch")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create CDN client
        product_enum = Product(product)
        cdn_config = CDNConfig(
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        failed_hashes: list[tuple[str, str]] = []
        successful_downloads = 0

        def fetch_single_hash(hash_str: str) -> tuple[str, bool, str]:
            """Fetch a single hash and return result."""
            try:
                with CDNClient(product_enum, region, cdn_config) as client:
                    if file_type == "config":
                        data = client.fetch_config(hash_str)
                        suffix = ""
                    elif file_type == "index":
                        data = client.fetch_data(hash_str, is_index=True)
                        suffix = ".index"
                    elif file_type == "encoding":
                        data = client.fetch_data(hash_str)
                        suffix = ".encoding"
                    else:  # data
                        data = client.fetch_data(hash_str)
                        suffix = ""

                    # Save file
                    output_path = output_dir / f"{hash_str}{suffix}"
                    output_path.write_bytes(data)

                    return hash_str, True, f"Downloaded {format_size(len(data))}"

            except Exception as e:
                return hash_str, False, str(e)

        # Batch download with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            task = progress.add_task("Downloading files...", total=len(hashes))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all download tasks
                future_to_hash = {
                    executor.submit(fetch_single_hash, hash_str): hash_str
                    for hash_str in hashes
                }

                # Process completed downloads
                for future in as_completed(future_to_hash):
                    hash_str, success, message = future.result()

                    if success:
                        successful_downloads += 1
                        if verbose:
                            progress.console.print(f"[green]✓ {hash_str}: {message}[/green]")
                    else:
                        failed_hashes.append((hash_str, message))
                        if verbose:
                            progress.console.print(f"[red]✗ {hash_str}: {message}[/red]")

                    progress.advance(task)

        # Retry failed downloads if requested
        if retry_failed and failed_hashes:
            console.print(f"[yellow]Retrying {len(failed_hashes)} failed downloads...[/yellow]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold yellow]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:

                retry_task = progress.add_task("Retrying failed downloads...", total=len(failed_hashes))

                for hash_str, _original_error in failed_hashes:
                    try:
                        hash_str, success, message = fetch_single_hash(hash_str)
                        if success:
                            successful_downloads += 1
                            if verbose:
                                progress.console.print(f"[green]✓ {hash_str}: {message} (retry successful)[/green]")
                            # Remove from failed list
                            failed_hashes = [(h, e) for h, e in failed_hashes if h != hash_str]
                    except Exception:
                        pass  # Keep in failed list

                    progress.advance(retry_task)

        # Summary
        table = Table(title="Batch Download Summary")
        table.add_column("Result", style="cyan")
        table.add_column("Count", style="magenta")

        table.add_row("Total Hashes", str(len(hashes)))
        table.add_row("Successful", str(successful_downloads))
        table.add_row("Failed", str(len(failed_hashes)))
        table.add_row("Success Rate", f"{(successful_downloads / len(hashes)) * 100:.1f}%")

        console.print(table)

        if failed_hashes:
            console.print(f"[yellow]Failed downloads ({len(failed_hashes)}):[/yellow]")
            for hash_str, error in failed_hashes[:10]:  # Show first 10 failures
                console.print(f"  {hash_str}: {error}")
            if len(failed_hashes) > 10:
                console.print(f"  ... and {len(failed_hashes) - 10} more")

        console.print(f"[green]Batch download completed. Files saved to {output_dir}[/green]")

    except Exception as e:
        logger.error("batch_fetch_failed", input_file=str(input_file), error=str(e))
        console.print(f"[red]Error in batch fetch: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.argument("hash_str", type=str)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: {hash}.patch)",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--index",
    is_flag=True,
    help="Fetch patch archive index instead of patch file",
)
@click.option(
    "--show-info",
    is_flag=True,
    help="Show patch file information",
)
@click.pass_context
def patch(
    ctx: click.Context,
    hash_str: str,
    output: Path | None,
    product: str,
    region: str,
    index: bool,
    show_info: bool,
) -> None:
    """Fetch patch files from CDN.

    HASH_STR can be a patch manifest or patch archive hash.
    """
    config_obj, console, verbose, _ = _get_context_objects(ctx)

    # Validate hash
    if not validate_hash_string(hash_str):
        console.print(f"[red]Error: Invalid hash format: {hash_str}[/red]")
        sys.exit(1)

    try:
        # Create CDN client
        product_enum = Product(product)
        cdn_config = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            file_type_str = "patch index" if index else "patch"
            console.print(f"[blue]Fetching {file_type_str} {hash_str}...[/blue]")

            # Fetch the patch data
            data = cdn_client.fetch_patch(hash_str, is_index=index)

            # Determine output path
            if not output:
                suffix = ".index" if index else ".patch"
                output = Path(f"{hash_str}{suffix}")

            # Save file
            _save_file(data, output, console, verbose)

            # Show file information if requested
            if show_info:
                table = Table(title=f"{file_type_str.title()} File Information")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="magenta")

                table.add_row("Hash", hash_str)
                table.add_row("Type", file_type_str)
                table.add_row("Size", format_size(len(data)))
                table.add_row("BLTE", "Yes" if is_blte(data) else "No")

                console.print(table)

            console.print(f"[green]Successfully fetched {file_type_str} file[/green]")

    except Exception as e:
        logger.error("patch_fetch_failed", hash=hash_str, index=index, error=str(e))
        console.print(f"[red]Error fetching patch: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory (default: manifests_{product})",
)
@click.option(
    "--latest",
    is_flag=True,
    help="Fetch manifests for the latest version only",
)
@click.pass_context
def manifests(
    ctx: click.Context,
    product: str,
    region: str,
    output_dir: Path | None,
    latest: bool,
) -> None:
    """Fetch TACT manifests (versions and cdns).

    Downloads the core TACT API manifests that list available versions
    and CDN configurations.
    """
    _, console, _, _ = _get_context_objects(ctx)

    try:
        # Create TACT client
        product_enum = Product(product)
        tact_client = TACTClient(region=region)

        # Create output directory
        if not output_dir:
            output_dir = Path(f"manifests_{product}")
        output_dir.mkdir(parents=True, exist_ok=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            task = progress.add_task("Fetching TACT manifests...", total=2)

            # Fetch versions manifest
            progress.update(task, description="Fetching versions manifest...")
            versions_data = tact_client.fetch_versions(product_enum)
            versions_path = output_dir / f"{product}_versions.txt"
            _save_file(versions_data.encode('utf-8'), versions_path, console, False)
            progress.advance(task)

            # Fetch CDNs manifest
            progress.update(task, description="Fetching CDNs manifest...")
            cdns_data = tact_client.fetch_cdns(product_enum)
            cdns_path = output_dir / f"{product}_cdns.txt"
            _save_file(cdns_data.encode('utf-8'), cdns_path, console, False)
            progress.advance(task)

        # Parse and show summary
        versions = tact_client.parse_versions(versions_data)
        cdns = tact_client.parse_cdns(cdns_data)

        table = Table(title="TACT Manifests Summary")
        table.add_column("Manifest", style="cyan")
        table.add_column("Entries", style="magenta")
        table.add_column("File", style="green")

        table.add_row("Versions", str(len(versions)), str(versions_path))
        table.add_row("CDNs", str(len(cdns)), str(cdns_path))

        console.print(table)

        if latest and versions:
            # Show latest version info
            latest_version = versions[0]  # Versions are typically sorted newest first

            version_table = Table(title="Latest Version Information")
            version_table.add_column("Property", style="cyan")
            version_table.add_column("Value", style="magenta")

            for key, value in latest_version.items():
                version_table.add_row(key, str(value))

            console.print(version_table)

        console.print(f"[green]TACT manifests saved to {output_dir}[/green]")

    except Exception as e:
        logger.error("manifests_fetch_failed", product=product, error=str(e))
        console.print(f"[red]Error fetching manifests: {e}[/red]")
        sys.exit(1)


@cdn.command()
@click.option(
    "--product",
    "-p",
    type=click.Choice([p.value for p in Product], case_sensitive=False),
    default="wow",
    help="Product code",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory (default: zbsdiff_{product})",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=5,
    help="Maximum number of patches to download",
)
@click.option(
    "--build-config",
    type=str,
    default=None,
    help="Specific build config hash (from Wago database). If not provided, "
         "uses the current live build from the versions manifest.",
)
@click.pass_context
def zbsdiff(
    ctx: click.Context,
    product: str,
    region: str,
    output_dir: Path | None,
    limit: int,
    build_config: str | None,
) -> None:
    """Download ZBSDIFF patches from CDN for format verification.

    Fetches real ZBSDIFF1 patches from Blizzard's CDN by resolving the
    patch manifest from the build config, parsing the PA (patch archive)
    manifest, downloading patch archive indexes, and extracting individual
    patch entries via HTTP range requests.

    Patches are looked up in patch archive indexes first. If found, they
    are extracted via range request from the patch archive. If not found
    in any archive index, a loose file download from patch/ is attempted.
    """
    from cascette_tools.core.cdn_archive_fetcher import create_patch_archive_fetcher
    from cascette_tools.formats.config import CDNConfigParser
    from cascette_tools.formats.patch_archive import PatchArchiveParser
    from cascette_tools.formats.zbsdiff import ZbsdiffParser

    config_obj, console, verbose, _ = _get_context_objects(ctx)

    if not output_dir:
        output_dir = Path(f"zbsdiff_{product}")
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        product_enum = Product(product)
        cdn_config = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        build_config_hash = build_config
        cdn_config_hash = None

        if not build_config_hash:
            # Step 1: Fetch versions manifest to get build config hash
            console.print(f"[blue]Fetching versions manifest for {product}...[/blue]")
            tact_client = TACTClient(region=region)
            versions_data = tact_client.fetch_versions(product_enum)
            versions = tact_client.parse_versions(versions_data)

            if not versions:
                console.print("[red]Error: No versions found[/red]")
                sys.exit(1)

            # Find the version entry for our region
            version_entry = None
            for v in versions:
                r = v.get("Region", v.get("region", ""))
                if r == region:
                    version_entry = v
                    break
            if version_entry is None:
                for v in versions:
                    bc = v.get("BuildConfig", v.get("buildconfig", ""))
                    if bc:
                        version_entry = v
                        break
            if version_entry is None:
                console.print(f"[red]Error: No version entry found for region {region}[/red]")
                sys.exit(1)

            build_config_hash = version_entry.get("BuildConfig", version_entry.get("buildconfig"))
            cdn_config_hash = version_entry.get("CDNConfig", version_entry.get("cdnconfig"))

        if not build_config_hash:
            console.print("[red]Error: No BuildConfig hash available[/red]")
            sys.exit(1)

        console.print(f"  Build config: {build_config_hash}")

        # Step 2: Fetch and parse the build config + CDN config
        with CDNClient(product_enum, region, cdn_config) as cdn_client:
            console.print("[blue]Fetching build config...[/blue]")
            build_config_data = cdn_client.fetch_config(build_config_hash, "build")
            build_config_parser = BuildConfigParser()
            parsed_build_config = build_config_parser.parse(build_config_data)

            patch_info = parsed_build_config.get_patch_info()
            if patch_info is None:
                console.print("[yellow]No patch field in build config. "
                              "This product may not have patches available.[/yellow]")
                sys.exit(0)

            patch_ekey = patch_info.encoding_key or patch_info.content_key
            console.print(f"  Patch manifest encoding key: {patch_ekey}")

            # Get CDN config hash if not already available
            if not cdn_config_hash:
                cdn_config_hash = parsed_build_config.extra_fields.get('cdn-config')

            # Step 3: Download and decode the patch manifest
            console.print("[blue]Fetching patch manifest...[/blue]")
            patch_manifest_raw = cdn_client.fetch_patch(patch_ekey)

            if is_blte(patch_manifest_raw):
                patch_manifest_data = decompress_blte(patch_manifest_raw)
                console.print(f"  BLTE decoded: {format_size(len(patch_manifest_raw))} -> "
                              f"{format_size(len(patch_manifest_data))}")
            else:
                patch_manifest_data = patch_manifest_raw

            # Step 4: Parse the PA manifest
            pa_parser = PatchArchiveParser()
            pa_file = pa_parser.parse(patch_manifest_data)
            console.print(f"  Patch entries: {len(pa_file.entries)}")

            if not pa_file.entries:
                console.print("[yellow]No patch entries found in manifest.[/yellow]")
                sys.exit(0)

            # Step 5: Download patch archive indexes
            patch_archive_hashes: list[str] = []
            patch_fetcher = create_patch_archive_fetcher(cdn_client=cdn_client)

            if cdn_config_hash:
                console.print("[blue]Fetching CDN config for patch archive list...[/blue]")
                cdn_config_data = cdn_client.fetch_config(cdn_config_hash, "cdn")
                cdn_config_parser = CDNConfigParser()
                parsed_cdn_config = cdn_config_parser.parse(cdn_config_data)
                patch_archive_hashes = parsed_cdn_config.patch_archives

                if patch_archive_hashes:
                    console.print(f"  Found {len(patch_archive_hashes)} patch archives")
                    console.print("[blue]Downloading patch archive indexes...[/blue]")

                    loaded = 0
                    for pa_hash in patch_archive_hashes:
                        try:
                            index_data = cdn_client.fetch_patch(pa_hash, is_index=True)
                            if patch_fetcher.load_index_from_bytes(pa_hash, index_data):
                                loaded += 1
                        except Exception as e:
                            logger.debug("patch_index_load_failed",
                                         hash=pa_hash, error=str(e))

                    console.print(f"  Loaded {loaded}/{len(patch_archive_hashes)} indexes "
                                  f"({patch_fetcher.index_map.total_entries} entries)")
                else:
                    console.print("[yellow]No patch archives in CDN config[/yellow]")
            else:
                console.print("[yellow]No CDN config hash available, "
                              "skipping patch archive index loading[/yellow]")

            # Step 6: Download individual ZBSDIFF patches
            entries_to_fetch = pa_file.entries[:limit]
            console.print(f"[blue]Downloading up to {len(entries_to_fetch)} patches...[/blue]")

            results: list[dict[str, str]] = []
            archive_hits = 0
            loose_hits = 0

            for i, entry in enumerate(entries_to_fetch):
                patch_hash = entry.patch_encoding_key.hex()
                old_ckey = entry.old_content_key.hex()
                new_ckey = entry.new_content_key.hex()

                try:
                    patch_data = None
                    source = "loose"

                    # Try patch archive index first
                    if patch_fetcher.index_map.total_entries > 0:
                        archive_data = patch_fetcher.fetch_file_via_cdn(
                            cdn_client,
                            entry.patch_encoding_key,
                            decompress=True,
                            verify=True,
                        )
                        if archive_data is not None:
                            patch_data = archive_data
                            source = "archive"
                            archive_hits += 1

                    # Fall back to loose file download
                    if patch_data is None:
                        try:
                            raw_patch = cdn_client.fetch_patch(patch_hash)
                            if is_blte(raw_patch):
                                patch_data = decompress_blte(raw_patch)
                            else:
                                patch_data = raw_patch
                            source = "loose"
                            loose_hits += 1
                        except Exception:
                            # Both methods failed
                            raise

                    # Validate it looks like ZBSDIFF
                    if patch_data[:8] == b"ZBSDIFF1":
                        out_path = output_dir / f"{patch_hash}.zbsdiff"
                        out_path.write_bytes(patch_data)

                        try:
                            zbsdiff_parser = ZbsdiffParser()
                            parsed = zbsdiff_parser.parse(patch_data)
                            status = (
                                f"ok [{source}] ({len(parsed.control_entries)} ctrl, "
                                f"new_size={parsed.header.new_size})"
                            )
                        except Exception as parse_err:
                            status = f"saved [{source}] (parse warning: {parse_err})"

                        results.append({
                            "old_ckey": old_ckey[:16] + "...",
                            "new_ckey": new_ckey[:16] + "...",
                            "patch_ekey": patch_hash[:16] + "...",
                            "size": format_size(len(patch_data)),
                            "status": status,
                        })
                        console.print(f"  [{i+1}/{len(entries_to_fetch)}] {patch_hash[:16]}... "
                                      f"({format_size(len(patch_data))}) [{source}]")
                    else:
                        magic = patch_data[:8]
                        results.append({
                            "old_ckey": old_ckey[:16] + "...",
                            "new_ckey": new_ckey[:16] + "...",
                            "patch_ekey": patch_hash[:16] + "...",
                            "size": format_size(len(patch_data)),
                            "status": f"skipped (magic: {magic!r})",
                        })

                except Exception as e:
                    error_msg = str(e)
                    if "404" in error_msg or "Not Found" in error_msg:
                        status = "404 (not in archive or loose)"
                    else:
                        status = f"error: {error_msg[:60]}"
                    results.append({
                        "old_ckey": old_ckey[:16] + "...",
                        "new_ckey": new_ckey[:16] + "...",
                        "patch_ekey": patch_hash[:16] + "...",
                        "size": "-",
                        "status": status,
                    })
                    logger.warning("zbsdiff_fetch_entry_failed",
                                   hash=patch_hash, error=error_msg)

            # Summary table
            table = Table(title="ZBSDIFF Patch Download Summary")
            table.add_column("Old CKey", style="dim")
            table.add_column("New CKey", style="dim")
            table.add_column("Patch EKey", style="cyan")
            table.add_column("Size", style="magenta")
            table.add_column("Status", style="green")

            for r in results:
                table.add_row(
                    r["old_ckey"], r["new_ckey"], r["patch_ekey"],
                    r["size"], r["status"]
                )

            console.print(table)

            saved_count = sum(1 for r in results if r["status"].startswith("ok") or r["status"].startswith("saved"))
            console.print(f"[green]Saved {saved_count} ZBSDIFF patches to {output_dir}[/green]")
            if archive_hits or loose_hits:
                console.print(f"[dim]Sources: {archive_hits} from archives, "
                              f"{loose_hits} from loose files[/dim]")

    except Exception as e:
        logger.error("zbsdiff_fetch_failed", product=product, error=str(e))
        console.print(f"[red]Error fetching ZBSDIFF patches: {e}[/red]")
        sys.exit(1)


@cdn.command(name="verify-pa")
@click.option(
    "--products",
    "-p",
    type=str,
    default="wow_classic",
    help="Comma-separated product codes (e.g., wow,wow_classic)",
)
@click.option(
    "--region",
    "-r",
    type=str,
    default="us",
    help="Region code",
)
@click.option(
    "--version-filter",
    "-f",
    type=str,
    default=None,
    help="Comma-separated version glob patterns (e.g., '6.*,8.*,10.*'). "
         "If not provided, uses the current live build for each product.",
)
@click.option(
    "--use-wago/--no-wago",
    default=True,
    help="Use Wago database for historical builds (requires version-filter)",
)
@click.pass_context
def verify_pa(
    ctx: click.Context,
    products: str,
    region: str,
    version_filter: str | None,
    use_wago: bool,
) -> None:
    """Verify PA parser against real CDN data across product versions.

    Downloads PA (Patch Archive) manifests and validates parsing by
    cross-referencing with patch archive indexes.

    Without --version-filter, verifies only the current live build.
    With --version-filter and --use-wago, samples builds from the
    Wago database matching the given version patterns.
    """
    import fnmatch

    from cascette_tools.core.cdn_archive_fetcher import create_patch_archive_fetcher
    from cascette_tools.formats.config import CDNConfigParser
    from cascette_tools.formats.patch_archive import PatchArchiveParser

    config_obj, console, verbose, _ = _get_context_objects(ctx)

    product_list = [p.strip() for p in products.split(",")]

    # Results for summary table
    all_results: list[dict[str, str | int]] = []

    for product_str in product_list:
        try:
            product_enum = Product(product_str)
        except ValueError:
            console.print(f"[yellow]Unknown product: {product_str}, skipping[/yellow]")
            continue

        cdn_config_obj = CDNConfig(
            fallback_mirrors=_get_cdn_mirrors_for_product(product_str),
            timeout=config_obj.cdn_timeout,
            max_retries=config_obj.cdn_max_retries,
        )

        # Build list of (version, build_config_hash, cdn_config_hash) to verify
        builds_to_verify: list[tuple[str, str, str | None]] = []

        if version_filter and use_wago:
            # Use Wago database for historical builds
            from cascette_tools.database.wago import WagoClient

            console.print(f"[blue]Loading Wago builds for {product_str}...[/blue]")
            with WagoClient(config_obj) as wago_client:
                all_builds = wago_client.fetch_builds()
                product_builds = [
                    b for b in all_builds if b.product == product_str
                ]

            if not product_builds:
                console.print(f"[yellow]No Wago builds for {product_str}[/yellow]")
                continue

            # Filter by version patterns
            patterns = [p.strip() for p in version_filter.split(",")]
            matched_builds = []
            for b in product_builds:
                if any(fnmatch.fnmatch(b.version, pat) for pat in patterns):
                    matched_builds.append(b)

            if not matched_builds:
                console.print(f"[yellow]No builds matching {version_filter} "
                              f"for {product_str}[/yellow]")
                continue

            # Sample one build per major.minor version
            seen_versions: set[str] = set()
            for b in sorted(matched_builds, key=lambda x: x.version, reverse=True):
                parts = b.version.split(".")
                major_minor = ".".join(parts[:2]) if len(parts) >= 2 else b.version
                if major_minor not in seen_versions and b.build_config:
                    seen_versions.add(major_minor)
                    builds_to_verify.append(
                        (b.version, b.build_config, b.cdn_config)
                    )

            console.print(f"  Sampled {len(builds_to_verify)} builds from "
                          f"{len(matched_builds)} matches")
        else:
            # Use current live build from versions manifest
            console.print(f"[blue]Fetching current versions for {product_str}...[/blue]")
            tact_client = TACTClient(region=region)
            versions_data = tact_client.fetch_versions(product_enum)
            versions = tact_client.parse_versions(versions_data)

            if not versions:
                console.print(f"[yellow]No versions for {product_str}[/yellow]")
                continue

            version_entry = None
            for v in versions:
                r = v.get("Region", v.get("region", ""))
                if r == region:
                    version_entry = v
                    break
            if version_entry is None:
                for v in versions:
                    bc = v.get("BuildConfig", v.get("buildconfig", ""))
                    if bc:
                        version_entry = v
                        break

            if version_entry:
                bc = version_entry.get("BuildConfig", version_entry.get("buildconfig", ""))
                cc = version_entry.get("CDNConfig", version_entry.get("cdnconfig"))
                ver = version_entry.get("VersionsName", version_entry.get("versionsname", "live"))
                if bc:
                    builds_to_verify.append((ver, bc, cc))

        if not builds_to_verify:
            console.print(f"[yellow]No builds to verify for {product_str}[/yellow]")
            continue

        # Verify each build
        with CDNClient(product_enum, region, cdn_config_obj) as cdn_client:
            for version_str, bc_hash, cc_hash in builds_to_verify:
                result: dict[str, str | int] = {
                    "product": product_str,
                    "version": version_str,
                    "build_config": bc_hash[:16] + "...",
                    "entries": 0,
                    "blocks": 0,
                    "has_encoding_info": "no",
                    "archive_index_entries": 0,
                    "index_hits": 0,
                    "status": "pending",
                }

                try:
                    # Fetch build config
                    build_data = cdn_client.fetch_config(bc_hash, "build")
                    build_parser = BuildConfigParser()
                    parsed_bc = build_parser.parse(build_data)

                    patch_info = parsed_bc.get_patch_info()
                    if patch_info is None:
                        result["status"] = "no patch field"
                        all_results.append(result)
                        continue

                    patch_ekey = patch_info.encoding_key or patch_info.content_key

                    # Fetch patch manifest
                    patch_raw = cdn_client.fetch_patch(patch_ekey)
                    if is_blte(patch_raw):
                        patch_data = decompress_blte(patch_raw)
                    else:
                        patch_data = patch_raw

                    # Parse PA
                    pa_parser = PatchArchiveParser()
                    pa_file = pa_parser.parse(patch_data)

                    result["entries"] = len(pa_file.entries)
                    result["blocks"] = len(pa_file.blocks)
                    result["has_encoding_info"] = "yes" if pa_file.encoding_info else "no"

                    # Try to load patch archive indexes
                    if not cc_hash:
                        cc_hash = parsed_bc.extra_fields.get('cdn-config')

                    index_hit_count = 0
                    if cc_hash:
                        try:
                            cdn_data = cdn_client.fetch_config(cc_hash, "cdn")
                            cdn_parser = CDNConfigParser()
                            parsed_cc = cdn_parser.parse(cdn_data)

                            if parsed_cc.patch_archives:
                                patch_fetcher = create_patch_archive_fetcher(
                                    cdn_client=cdn_client
                                )
                                for pa_hash in parsed_cc.patch_archives:
                                    try:
                                        idx_data = cdn_client.fetch_patch(
                                            pa_hash, is_index=True
                                        )
                                        patch_fetcher.load_index_from_bytes(
                                            pa_hash, idx_data
                                        )
                                    except Exception:
                                        pass

                                result["archive_index_entries"] = (
                                    patch_fetcher.index_map.total_entries
                                )

                                # Check how many PA entries are in the index
                                for entry in pa_file.entries:
                                    loc = patch_fetcher.index_map.find(
                                        entry.patch_encoding_key
                                    )
                                    if loc is not None:
                                        index_hit_count += 1
                        except Exception as e:
                            logger.debug("cdn_config_load_failed",
                                         hash=cc_hash, error=str(e))

                    result["index_hits"] = index_hit_count

                    entry_count = len(pa_file.entries)
                    if entry_count > 0 and index_hit_count == entry_count:
                        result["status"] = "ok (all in index)"
                    elif entry_count > 0 and index_hit_count > 0:
                        pct = index_hit_count * 100 // entry_count
                        result["status"] = f"ok ({pct}% in index)"
                    elif entry_count > 0:
                        result["status"] = "ok (0 in index)"
                    else:
                        result["status"] = "ok (empty)"

                    console.print(f"  {product_str} {version_str}: "
                                  f"{entry_count} entries, "
                                  f"{index_hit_count}/{entry_count} in index")

                except Exception as e:
                    result["status"] = f"error: {str(e)[:40]}"
                    console.print(f"  [red]{product_str} {version_str}: {e}[/red]")

                all_results.append(result)

    # Summary table
    if all_results:
        table = Table(title="PA Verification Summary")
        table.add_column("Product", style="cyan")
        table.add_column("Version")
        table.add_column("Build Config", style="dim")
        table.add_column("Entries", justify="right")
        table.add_column("Blocks", justify="right")
        table.add_column("Enc Info")
        table.add_column("Index Entries", justify="right")
        table.add_column("Index Hits", justify="right")
        table.add_column("Status", style="green")

        for r in all_results:
            table.add_row(
                str(r["product"]),
                str(r["version"]),
                str(r["build_config"]),
                str(r["entries"]),
                str(r["blocks"]),
                str(r["has_encoding_info"]),
                str(r["archive_index_entries"]),
                str(r["index_hits"]),
                str(r["status"]),
            )

        console.print(table)

        ok_count = sum(1 for r in all_results if str(r["status"]).startswith("ok"))
        console.print(f"[green]{ok_count}/{len(all_results)} builds verified[/green]")
    else:
        console.print("[yellow]No builds were verified[/yellow]")


# Note: wago-builds functionality has been moved to the 'builds' command group
# Use: cascette builds sync
