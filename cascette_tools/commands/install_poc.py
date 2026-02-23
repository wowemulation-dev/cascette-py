"""Full installation POC demonstrating the NGDP/CASC resolution chain.

This module demonstrates the complete flow for resolving and fetching
game content from Blizzard's CDN:

1. Fetch BuildConfig and CDNConfig
2. Download encoding file directly from CDN
3. Parse encoding file to resolve content keys
4. Fetch install/download manifests using resolved encoding keys
5. Display installation statistics

Key insight: The encoding file IS available as a loose CDN file.
Archive-groups are generated LOCALLY by Battle.net client.
"""

from __future__ import annotations

import asyncio
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import click
import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.cdn_archive_fetcher import (
    CdnArchiveFetcher,
    parse_cdn_config_archives,
)
from cascette_tools.core.config import AppConfig
from cascette_tools.core.download_queue import DownloadQueue, DownloadResult
from cascette_tools.core.install_state import InstallState
from cascette_tools.core.integrity import IntegrityError
from cascette_tools.core.local_storage import LocalStorage
from cascette_tools.core.product_state import (
    ProductInfo,
    generate_all_state_files,
)
from cascette_tools.core.types import Product
from cascette_tools.formats.blte import decompress_blte, is_blte
from cascette_tools.formats.build_info import (
    BuildInfoParser,
    LocalBuildInfo,
    create_build_info,
    update_last_activated,
)
from cascette_tools.formats.config import (
    BuildConfigParser,
    CDNConfigParser,
)
from cascette_tools.formats.download import DownloadEntry, DownloadParser, DownloadTag
from cascette_tools.formats.encoding import EncodingParser, is_encoding
from cascette_tools.formats.install import InstallEntry, InstallParser, InstallTag
from cascette_tools.formats.size import (
    SizeFile,
    SizeParser,
    SizeTag,
    apply_tag_query,
    is_file_selected,
)

logger = structlog.get_logger()


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


def get_product_enum(product_code: str) -> Product:
    """Map product code string to Product enum."""
    mapping = {
        "wow": Product.WOW,
        "wow_classic": Product.WOW_CLASSIC,
        "wow_classic_era": Product.WOW_CLASSIC_ERA,
        "wow_classic_titan": Product.WOW_CLASSIC_TITAN,
        "wow_anniversary": Product.WOW_ANNIVERSARY,
    }
    if product_code not in mapping:
        raise ValueError(f"Unknown product code: {product_code}")
    return mapping[product_code]


@click.group()
def install_poc() -> None:
    """POC commands for full installation workflow."""
    pass


@install_poc.command()
@click.argument("build_config_hash", type=str)
@click.option(
    "--product", "-r",
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]),
    default="wow_classic_era",
    help="Product code for Ribbit lookup"
)
@click.option(
    "--region",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="CDN region"
)
@click.pass_context
def resolve_manifests(
    ctx: click.Context,
    build_config_hash: str,
    product: str,
    region: str
) -> None:
    """Resolve all manifests starting from a build config hash.

    BUILD_CONFIG_HASH is the hash from the versions endpoint.

    This demonstrates the complete NGDP resolution chain:
    1. BuildConfig -> encoding key
    2. Encoding file -> install/root content key resolution
    3. Install manifest -> file list and sizes
    """
    _, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Initialize CDN client with Ribbit integration
        product_enum = get_product_enum(product)
        cdn_client = CDNClient(product_enum, region=region)

        # Step 1: Fetch and parse BuildConfig
        console.print("[cyan]Step 1:[/cyan] Fetching BuildConfig...")
        build_config_data = cdn_client.fetch_config(build_config_hash, config_type="build")
        build_config = BuildConfigParser().parse(build_config_data)

        encoding_info = build_config.get_encoding_info()
        install_info = build_config.get_install_info()
        download_info = build_config.get_download_info()

        table = Table(title="BuildConfig")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Build Name", build_config.build_name or "N/A")
        table.add_row("Build UID", build_config.build_uid or "N/A")
        table.add_row("Root Content Key", build_config.root or "N/A")
        table.add_row("Encoding Content Key", encoding_info.content_key if encoding_info else "N/A")
        table.add_row("Encoding Encoding Key", encoding_info.encoding_key if encoding_info else "N/A")
        table.add_row("Encoding Size", f"{encoding_info.size:,}" if encoding_info and encoding_info.size else "N/A")
        table.add_row("Install Content Key", install_info.content_key if install_info else "N/A")
        table.add_row("Install Size", f"{install_info.size:,}" if install_info and install_info.size else "N/A")
        table.add_row("Download Content Key", download_info.content_key if download_info else "N/A")
        table.add_row("Download Size", f"{download_info.size:,}" if download_info and download_info.size else "N/A")
        console.print(table)

        if not encoding_info or not encoding_info.encoding_key:
            raise click.ClickException("No encoding key found in BuildConfig")

        # Step 2: Fetch encoding file directly from CDN
        console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file from CDN...")
        console.print(f"  Using encoding key: {encoding_info.encoding_key}")

        encoding_data = cdn_client.fetch_data(encoding_info.encoding_key)
        console.print(f"  Downloaded: {len(encoding_data):,} bytes")

        # Decompress BLTE if needed
        if is_blte(encoding_data):
            console.print("  Format: BLTE compressed")
            encoding_data = decompress_blte(encoding_data)
            console.print(f"  Decompressed: {len(encoding_data):,} bytes")

        # Parse encoding file
        if not is_encoding(encoding_data):
            raise click.ClickException("Downloaded data is not a valid encoding file")

        console.print("\n[cyan]Step 3:[/cyan] Parsing encoding file...")
        encoding_parser = EncodingParser()
        encoding_file = encoding_parser.parse(encoding_data)

        console.print(f"  Version: {encoding_file.header.version}")
        console.print(f"  CKey pages: {encoding_file.header.ckey_page_count}")
        console.print(f"  EKey pages: {encoding_file.header.ekey_page_count}")
        console.print(f"  ESpec entries: {len(encoding_file.espec_table)}")

        # Step 4: Look up install manifest encoding key
        if install_info:
            console.print("\n[cyan]Step 4:[/cyan] Resolving install manifest...")
            install_ckey = bytes.fromhex(install_info.content_key)

            # Find encoding key for install manifest
            install_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, install_ckey)

            if install_ekeys:
                install_ekey = install_ekeys[0].hex()
                console.print(f"  Found encoding key: {install_ekey}")

                # Fetch install manifest
                console.print("\n[cyan]Step 5:[/cyan] Fetching install manifest...")
                install_data = cdn_client.fetch_data(install_ekey)
                console.print(f"  Downloaded: {len(install_data):,} bytes")

                if is_blte(install_data):
                    install_data = decompress_blte(install_data)
                    console.print(f"  Decompressed: {len(install_data):,} bytes")

                # Parse install manifest
                console.print("\n[cyan]Step 6:[/cyan] Parsing install manifest...")
                install_parser = InstallParser()
                install_manifest = install_parser.parse(install_data)

                # Display statistics
                table = Table(title="Install Manifest Summary")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                table.add_row("Total Entries", f"{len(install_manifest.entries):,}")
                table.add_row("Total Tags", str(len(install_manifest.tags)))

                # Calculate sizes
                total_size = sum(e.size for e in install_manifest.entries)
                table.add_row("Total Size", f"{total_size:,} bytes ({total_size / (1024**3):.2f} GB)")

                # Show tag breakdown
                tag_names = [t.name for t in install_manifest.tags]
                table.add_row("Tags", ", ".join(tag_names[:10]) + ("..." if len(tag_names) > 10 else ""))

                console.print(table)

                # Show sample files
                if verbose and install_manifest.entries:
                    console.print("\n[bold]Sample Files (first 10):[/bold]")
                    for entry in install_manifest.entries[:10]:
                        console.print(f"  {entry.filename} ({entry.size:,} bytes)")
            else:
                console.print("[yellow]  Install manifest content key not found in encoding file[/yellow]")

        # Step 7: Look up and fetch download manifest
        if download_info:
            console.print("\n[cyan]Step 7:[/cyan] Resolving download manifest...")
            download_ckey = bytes.fromhex(download_info.content_key)

            download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)
            if download_ekeys:
                download_ekey = download_ekeys[0].hex()
                console.print(f"  Found encoding key: {download_ekey}")

                # Fetch download manifest
                console.print("\n[cyan]Step 8:[/cyan] Fetching download manifest...")
                download_data = cdn_client.fetch_data(download_ekey)
                console.print(f"  Downloaded: {len(download_data):,} bytes")

                if is_blte(download_data):
                    download_data = decompress_blte(download_data)
                    console.print(f"  Decompressed: {len(download_data):,} bytes")

                # Parse download manifest
                console.print("\n[cyan]Step 9:[/cyan] Parsing download manifest...")
                download_parser = DownloadParser()
                download_manifest = download_parser.parse(download_data)

                # Calculate priority distribution
                priority_buckets: dict[int, tuple[int, int]] = {}  # priority -> (count, total_size)
                for entry in download_manifest.entries:
                    if entry.priority not in priority_buckets:
                        priority_buckets[entry.priority] = (0, 0)
                    count, size = priority_buckets[entry.priority]
                    priority_buckets[entry.priority] = (count + 1, size + entry.size)

                total_entries = len(download_manifest.entries)
                total_size = sum(e.size for e in download_manifest.entries)

                # Display download statistics
                table = Table(title="Download Manifest Summary")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                table.add_row("Total Entries", f"{total_entries:,}")
                table.add_row("Total Tags", str(len(download_manifest.tags)))
                table.add_row("Total Size", f"{total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
                table.add_row("Priority Levels", str(len(priority_buckets)))
                console.print(table)

                # Show priority breakdown
                priority_table = Table(title="Download Priority Distribution")
                priority_table.add_column("Priority", style="cyan", justify="right")
                priority_table.add_column("Files", style="green", justify="right")
                priority_table.add_column("Size", style="yellow", justify="right")
                priority_table.add_column("Description", style="dim")

                for priority in sorted(priority_buckets.keys())[:15]:  # Show top 15 priorities
                    count, size = priority_buckets[priority]
                    desc = ""
                    if priority <= 10:
                        desc = "Critical (executables, shaders)"
                    elif priority <= 50:
                        desc = "High (core game data)"
                    elif priority <= 100:
                        desc = "Normal"
                    else:
                        desc = "Low (optional content)"

                    priority_table.add_row(
                        str(priority),
                        f"{count:,}",
                        f"{size / (1024**2):.1f} MB",
                        desc
                    )

                if len(priority_buckets) > 15:
                    priority_table.add_row("...", "...", "...", f"({len(priority_buckets) - 15} more)")

                console.print(priority_table)

                # Show tags
                tag_names = [t.name for t in download_manifest.tags]
                console.print(f"\n[bold]Available Tags:[/bold] {', '.join(tag_names)}")
            else:
                console.print("[yellow]  Download manifest content key not found in encoding file[/yellow]")

        console.print(Panel.fit(
            "[green]Resolution chain complete![/green]\n\n"
            "This demonstrates that:\n"
            "1. Encoding file is available as loose CDN file (using encoding key from BuildConfig)\n"
            "2. Install/download manifests are resolved via encoding file\n"
            "3. Archive-groups are NOT needed for manifest resolution",
            title="Success"
        ))

        # Close CDN client
        cdn_client.close()

    except Exception as e:
        logger.error("Resolution failed", error=str(e))
        raise click.ClickException(f"Resolution failed: {e}") from e


@install_poc.command()
@click.option(
    "--product", "-p",
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]),
    default="wow_classic_era",
    help="Product code"
)
@click.option(
    "--region", "-r",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="Region"
)
@click.pass_context
def discover_latest(
    ctx: click.Context,
    product: str,
    region: str
) -> None:
    """Discover latest build for a product and resolve its manifests.

    This is a convenience command that queries the TACT versions endpoint
    to get the latest build config hash, then resolves all manifests.
    """
    from cascette_tools.core.tact import TACTClient

    _, console, _, _ = _get_context_objects(ctx)

    try:
        # Use TACTClient for querying versions
        tact_client = TACTClient(region=region)
        product_enum = get_product_enum(product)

        console.print(f"[cyan]Querying versions for:[/cyan] {product}")

        # Get latest build for the requested region
        latest = tact_client.get_latest_build(product_enum)

        if not latest:
            raise click.ClickException(
                f"No version found for product '{product}' in region '{region}'"
            )

        build_config_hash = latest.get("BuildConfig", "")
        cdn_config_hash = latest.get("CDNConfig", "")
        version = latest.get("VersionsName", "")
        build_id = latest.get("BuildId", "")

        table = Table(title=f"Latest {product} Build")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Version", version)
        table.add_row("Build ID", build_id)
        table.add_row("Build Config", build_config_hash)
        table.add_row("CDN Config", cdn_config_hash)
        console.print(table)

        # Validate BuildConfig hash before proceeding
        if not build_config_hash:
            raise click.ClickException(
                "BuildConfig hash is empty or missing in version data. "
                "This may indicate a temporary API issue or no builds are available."
            )

        # Validate hash format (should be 32-character hex string)
        if len(build_config_hash) != 32 or not all(c in "0123456789abcdef" for c in build_config_hash.lower()):
            raise click.ClickException(
                f"Invalid BuildConfig hash format: '{build_config_hash}'. "
                "Expected 32-character hexadecimal string."
            )

        # Now invoke the resolve command with new parameters
        console.print("\n[bold]Resolving manifests...[/bold]\n")
        ctx.invoke(
            resolve_manifests,
            build_config_hash=build_config_hash,
            product=product,
            region=region
        )

    except Exception as e:
        logger.error("Discovery failed", error=str(e))
        raise click.ClickException(f"Discovery failed: {e}") from e


@install_poc.command()
@click.argument("cdn_config_hash", type=str)
@click.argument("encoding_key", type=str)
@click.argument("output_path", type=click.Path(path_type=Path))
@click.option(
    "--product", "-r",
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]),
    default="wow_classic_era",
    help="Product code for Ribbit lookup"
)
@click.option(
    "--region",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="CDN region"
)
@click.option(
    "--max-archives", "-m",
    type=int,
    default=0,
    help="Maximum archives to download (0 = all)"
)
@click.option(
    "--no-decompress",
    is_flag=True,
    help="Don't decompress BLTE data"
)
@click.pass_context
def extract_from_archives(
    ctx: click.Context,
    cdn_config_hash: str,
    encoding_key: str,
    output_path: Path,
    product: str,
    region: str,
    max_archives: int,
    no_decompress: bool
) -> None:
    """Extract a file from CDN archives by encoding key.

    This command downloads archive indices, builds an index map,
    then extracts the specified file using HTTP range requests.

    CDN_CONFIG_HASH is the CDN config hash from versions endpoint.
    ENCODING_KEY is the encoding key (32 hex chars) to extract.
    OUTPUT_PATH is where to save the extracted file.
    """
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )

    _, console, _, _ = _get_context_objects(ctx)

    try:
        # Parse encoding key
        ekey = bytes.fromhex(encoding_key)
        if len(ekey) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        # Initialize CDN client
        product_enum = get_product_enum(product)
        cdn_client = CDNClient(product_enum, region=region)

        # Step 1: Fetch CDN config
        console.print("[cyan]Step 1:[/cyan] Fetching CDN config...")
        cdn_config_data = cdn_client.fetch_config(cdn_config_hash, config_type="cdn")
        archives = parse_cdn_config_archives(cdn_config_data.decode())

        if not archives:
            raise click.ClickException("No archives found in CDN config")

        console.print(f"  Found {len(archives)} archives")

        if max_archives > 0:
            archives = archives[:max_archives]
            console.print(f"  Limiting to first {max_archives} archives")

        # Step 2: Download archive indices via CDNClient
        console.print(f"\n[cyan]Step 2:[/cyan] Downloading {len(archives)} archive indices...")

        fetcher = CdnArchiveFetcher(cdn_client=cdn_client)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Downloading indices...", total=len(archives))

            for archive_hash in archives:
                progress.update(task, advance=1)
                index_data = cdn_client.fetch_data(archive_hash, is_index=True)
                fetcher.load_index_from_bytes(archive_hash, index_data)

        console.print(f"  Loaded {len(archives)} indices")
        console.print(f"  Total entries in index map: {fetcher.index_map.total_entries:,}")

        # Step 3: Find and extract the file
        console.print("\n[cyan]Step 3:[/cyan] Extracting file...")
        console.print(f"  Looking for encoding key: {encoding_key}")

        location = fetcher.index_map.find(ekey)
        if not location:
            raise click.ClickException("Encoding key not found in any downloaded archive index")

        console.print(f"  Found in archive: {location.archive_hash}")
        console.print(f"  Offset: {location.offset}, Size: {location.size:,} bytes")

        # Fetch the file via CDNClient
        console.print("\n[cyan]Step 4:[/cyan] Fetching file from archive...")
        data = fetcher.fetch_file_via_cdn(cdn_client, ekey, decompress=not no_decompress)

        if data is None:
            raise click.ClickException("Failed to fetch file from archive")

        # Save to output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(data)

        console.print(Panel.fit(
            f"[green]File extracted successfully![/green]\n\n"
            f"Archive: {location.archive_hash}\n"
            f"Offset: {location.offset}\n"
            f"Compressed size: {location.size:,} bytes\n"
            f"Output size: {len(data):,} bytes\n"
            f"Saved to: {output_path}",
            title="Success"
        ))

        cdn_client.close()

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Extraction failed", error=str(e))
        raise click.ClickException(f"Extraction failed: {e}") from e


@install_poc.command()
@click.argument("build_config_hash", type=str)
@click.argument("cdn_config_hash", type=str)
@click.argument("output_dir", type=click.Path(path_type=Path))
@click.option(
    "--product", "-r",
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]),
    default="wow_classic_era",
    help="Product code for Ribbit lookup"
)
@click.option(
    "--region",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="CDN region"
)
@click.option(
    "--max-archives", "-m",
    type=int,
    default=100,
    help="Maximum archives to download (0 = all)"
)
@click.option(
    "--max-files", "-f",
    type=int,
    default=10,
    help="Maximum files to extract"
)
@click.option(
    "--priority", "-P",
    type=int,
    default=0,
    help="Only extract files with this priority or lower"
)
@click.pass_context
def extract_priority_files(
    ctx: click.Context,
    build_config_hash: str,
    cdn_config_hash: str,
    output_dir: Path,
    product: str,
    region: str,
    max_archives: int,
    max_files: int,
    priority: int
) -> None:
    """Extract high-priority files from download manifest.

    This demonstrates the full installation workflow:
    1. Resolve download manifest
    2. Filter by priority and tags
    3. Download archive indices
    4. Extract files using range requests

    BUILD_CONFIG_HASH is the build config hash.
    CDN_CONFIG_HASH is the CDN config hash.
    OUTPUT_DIR is where to save extracted files.
    """
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )

    _, console, verbose, _ = _get_context_objects(ctx)

    try:
        # Initialize CDN client
        product_enum = get_product_enum(product)
        cdn_client = CDNClient(product_enum, region=region)

        # Step 1: Fetch and parse BuildConfig
        console.print("[cyan]Step 1:[/cyan] Fetching BuildConfig...")
        build_config_data = cdn_client.fetch_config(build_config_hash, config_type="build")
        build_config = BuildConfigParser().parse(build_config_data)

        encoding_info = build_config.get_encoding_info()
        download_info = build_config.get_download_info()

        if not encoding_info or not encoding_info.encoding_key:
            raise click.ClickException("No encoding key in BuildConfig")

        console.print(f"  Build: {build_config.build_name}")

        # Step 2: Fetch encoding file
        console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file...")
        encoding_data = cdn_client.fetch_data(encoding_info.encoding_key)

        if is_blte(encoding_data):
            encoding_data = decompress_blte(encoding_data)

        encoding_parser = EncodingParser()
        encoding_file = encoding_parser.parse(encoding_data)
        console.print(f"  Loaded {encoding_file.header.ckey_page_count} CKey pages")

        # Step 3: Resolve and fetch download manifest
        if not download_info:
            raise click.ClickException("No download manifest in BuildConfig")

        console.print("\n[cyan]Step 3:[/cyan] Resolving download manifest...")
        download_ckey = bytes.fromhex(download_info.content_key)
        download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)

        if not download_ekeys:
            raise click.ClickException("Download manifest not found in encoding file")

        download_ekey = download_ekeys[0].hex()
        console.print(f"  Encoding key: {download_ekey}")

        download_data = cdn_client.fetch_data(download_ekey)
        if is_blte(download_data):
            download_data = decompress_blte(download_data)

        download_parser = DownloadParser()
        download_manifest = download_parser.parse(download_data)

        # Filter by priority
        entries = [e for e in download_manifest.entries if e.priority <= priority]
        console.print(f"  Found {len(entries)} entries with priority <= {priority}")

        if max_files > 0:
            entries = entries[:max_files]
            console.print(f"  Limiting to first {max_files} files")

        # Step 4: Fetch CDN config and download archive indices
        console.print("\n[cyan]Step 4:[/cyan] Fetching CDN config...")
        cdn_config_data = cdn_client.fetch_config(cdn_config_hash, config_type="cdn")
        archives = parse_cdn_config_archives(cdn_config_data.decode())

        if max_archives > 0:
            archives = archives[:max_archives]

        console.print(f"  Downloading {len(archives)} archive indices...")

        fetcher = CdnArchiveFetcher(cdn_client=cdn_client)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Downloading indices...", total=len(archives))

            for archive_hash in archives:
                progress.update(task, advance=1)
                index_data = cdn_client.fetch_data(archive_hash, is_index=True)
                fetcher.load_index_from_bytes(archive_hash, index_data)

        console.print(f"  Index map: {fetcher.index_map.total_entries:,} entries")

        # Step 5: Extract files
        console.print(f"\n[cyan]Step 5:[/cyan] Extracting {len(entries)} files...")
        output_dir.mkdir(parents=True, exist_ok=True)

        extracted = 0
        failed = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Extracting files...", total=len(entries))

            for entry in entries:
                progress.update(task, advance=1)

                # Extract file via CDNClient
                data = fetcher.fetch_file_via_cdn(cdn_client, entry.ekey, decompress=True)

                if data is None:
                    failed += 1
                    if verbose:
                        console.print(f"  [red]Failed:[/red] {entry.ekey.hex()}")
                    continue

                # Save to output directory
                # Use encoding key as filename since we don't have paths
                output_file = output_dir / f"{entry.ekey.hex()}.bin"
                output_file.write_bytes(data)
                extracted += 1

                if verbose:
                    console.print(f"  [green]Extracted:[/green] {entry.ekey.hex()} ({len(data):,} bytes)")

        # Summary
        table = Table(title="Extraction Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Total files", str(len(entries)))
        table.add_row("Extracted", str(extracted))
        table.add_row("Failed", str(failed))
        table.add_row("Output directory", str(output_dir))
        console.print(table)

        cdn_client.close()

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Extraction failed", error=str(e))
        raise click.ClickException(f"Extraction failed: {e}") from e


def filter_entries_by_tags(
    entries: list[DownloadEntry],
    tags: list[DownloadTag],
    platform: str | None = None,
    arch: str | None = None,
    locale: str | None = None,
    size_tags: list[SizeTag] | None = None,
) -> list[DownloadEntry]:
    """Filter download entries by platform, architecture, and locale tags.

    Uses bitmap-based tag filtering matching Agent.exe behavior:
    - Build tag query from platform, arch, locale parameters
    - Apply tag query using bitmap operations (one bit per file)
    - Supports subtractive tags with '!' prefix

    When size_tags are provided (from the size manifest), they are used
    directly as the canonical tag source. Otherwise, download manifest tags
    are converted to SizeTag format.

    Args:
        entries: List of DownloadEntry objects
        tags: List of DownloadTag objects (with bitmasks)
        platform: Platform filter (e.g., "Windows", "OSX")
        arch: Architecture filter (e.g., "x86_64", "arm64")
        locale: Locale filter (e.g., "enUS", "deDE")
        size_tags: Optional list of SizeTag objects from size manifest

    Returns:
        Filtered list of entries
    """
    # Build tag query from parameters
    query_parts: list[str] = []
    if platform:
        query_parts.append(platform)
    if arch:
        query_parts.append(arch)
    if locale:
        query_parts.append(locale)

    query = ",".join(query_parts) if query_parts else ""

    if not query:
        # No filters, return all entries
        return entries

    # Use size manifest tags directly if provided, otherwise convert from
    # download manifest tags
    if size_tags is not None:
        effective_tags = size_tags
    else:
        effective_tags = [
            SizeTag(
                name=tag.name,
                tag_id=tag.tag_type,
                tag_type=tag.tag_type,
                file_indices=[],
                bit_mask=tag.file_mask,
            )
            for tag in tags
        ]

    # Apply tag query to get selection bitmap
    bitmap = apply_tag_query(effective_tags, query, len(entries))

    # Filter entries based on bitmap
    filtered: list[DownloadEntry] = []
    for i, entry in enumerate(entries):
        if is_file_selected(bitmap, i):
            filtered.append(entry)

    logger.debug("Filtered %d entries to %d using query '%s'",
                 len(entries), len(filtered), query)
    return filtered


def _fmt_size(nbytes: int) -> str:
    """Format byte count as human-readable string."""
    if nbytes >= 1024 ** 3:
        return f"{nbytes / (1024 ** 3):.1f} GB"
    if nbytes >= 1024 ** 2:
        return f"{nbytes / (1024 ** 2):.1f} MB"
    if nbytes >= 1024:
        return f"{nbytes / 1024:.1f} KB"
    return f"{nbytes} B"


def _show_priority_table(
    console: Console,
    entries: list[DownloadEntry],
    state: InstallState,
    title: str = "Download Priority Distribution",
) -> None:
    """Display a Rich table of per-priority file counts and sizes."""
    buckets: dict[int, tuple[int, int]] = {}
    for entry in entries:
        count, size = buckets.get(entry.priority, (0, 0))
        buckets[entry.priority] = (count + 1, size + entry.size)

    tbl = Table(title=title)
    tbl.add_column("Priority", style="cyan", justify="right")
    tbl.add_column("Files", style="green", justify="right")
    tbl.add_column("Size", style="yellow", justify="right")
    tbl.add_column("Status", style="dim")

    for pri in sorted(buckets):
        count, size = buckets[pri]
        ps = state.priority_stats.get(pri)
        if ps and ps.completed >= ps.total:
            status = "done"
        elif ps and ps.completed > 0:
            status = f"{ps.completed}/{ps.total} done"
        else:
            status = "pending"
        tbl.add_row(str(pri), f"{count:,}", _fmt_size(size), status)

    console.print(tbl)


@install_poc.command()
@click.argument("build_config_hash", type=str)
@click.argument("cdn_config_hash", type=str)
@click.argument("install_path", type=click.Path(path_type=Path))
@click.option(
    "--product", "-r",
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_titan", "wow_anniversary"]),
    default="wow_classic_era",
    help="Product code for Ribbit lookup"
)
@click.option(
    "--max-archives", "-m",
    type=int,
    default=0,
    help="Maximum archives to download indices for (0 = all)"
)
@click.option(
    "--max-files", "-f",
    type=int,
    default=0,
    help="Maximum files to install (0 = all)"
)
@click.option(
    "--priority", "-P",
    type=int,
    default=255,
    help="Maximum priority level to install (0 = critical, 255 = all)"
)
@click.option(
    "--platform",
    type=click.Choice(["Windows", "OSX", "Android", "iOS"]),
    default="Windows",
    help="Target platform"
)
@click.option(
    "--arch",
    type=click.Choice(["x86_64", "x86_32", "arm64"]),
    default="x86_64",
    help="Target architecture"
)
@click.option(
    "--locale",
    type=click.Choice(["enUS", "deDE", "esES", "esMX", "frFR", "koKR", "ptBR", "ruRU", "zhCN", "zhTW"]),
    default="enUS",
    help="Target locale"
)
@click.option(
    "--region",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="CDN region"
)
@click.option(
    "--resume/--no-resume",
    default=True,
    help="Resume from existing .build.info (default: True)"
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Override existing .build.info even if config hashes differ"
)
@click.pass_context
def install_to_casc(
    ctx: click.Context,
    build_config_hash: str,
    cdn_config_hash: str,
    install_path: Path,
    product: str,
    max_archives: int,
    max_files: int,
    priority: int,
    platform: str,
    arch: str,
    locale: str,
    region: str,
    resume: bool,
    force: bool,
) -> None:
    """Install files to proper local CASC storage structure.

    This command creates a Battle.net-compatible installation:
    - Data/data/ - CASC archives with bucket-based indices (.idx files)
    - Data/indices/ - Downloaded CDN archive indices
    - Data/config/ - Configuration files

    BUILD_CONFIG_HASH is the build config hash from versions endpoint.
    CDN_CONFIG_HASH is the CDN config hash from versions endpoint.
    INSTALL_PATH is the installation directory (e.g., /path/to/wow).
    """
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )

    _config, console, _verbose, _debug = _get_context_objects(ctx)

    try:
        # Step 0: Resume detection - check for existing .build.info
        build_info_path = install_path / ".build.info"
        existing_info: LocalBuildInfo | None = None

        if build_info_path.exists():
            console.print("[cyan]Step 0:[/cyan] Checking existing installation...")
            try:
                parser = BuildInfoParser()
                existing_info = parser.parse_file(str(build_info_path))
                console.print("  Found existing .build.info")
                console.print(f"  Build key: {existing_info.build_key}")
                console.print(f"  CDN key: {existing_info.cdn_key}")

                # Validate hashes match
                if existing_info.build_key != build_config_hash or existing_info.cdn_key != cdn_config_hash:
                    if not force:
                        console.print("[yellow]  Config hashes differ from existing installation:[/yellow]")
                        console.print(f"    Existing build: {existing_info.build_key}")
                        console.print(f"    Requested build: {build_config_hash}")
                        console.print(f"    Existing CDN: {existing_info.cdn_key}")
                        console.print(f"    Requested CDN: {cdn_config_hash}")
                        raise click.ClickException(
                            "Config hashes differ. Use --force to override or --no-resume to start fresh."
                        )
                    console.print("[yellow]  --force: Overriding existing configuration[/yellow]")
                    existing_info = None  # Force fresh installation
                elif resume:
                    console.print("  [green]Resuming from existing configuration[/green]")
                    # Use existing configuration for platform, arch, locale
                    if existing_info.platform:
                        platform = existing_info.platform
                    if existing_info.architecture:
                        arch = existing_info.architecture
                    if existing_info.locale_configs:
                        locale = existing_info.locale_configs[0].code
                    if existing_info.region:
                        region = existing_info.region.lower()

            except ValueError as e:
                console.print(f"[yellow]  Failed to parse existing .build.info: {e}[/yellow]")
                if not force:
                    raise click.ClickException(
                        "Corrupted .build.info file. Use --force to override."
                    ) from e
                console.print("[yellow]  --force: Starting fresh installation[/yellow]")

        # Display tag configuration table
        tag_table = Table(title="Installation Configuration")
        tag_table.add_column("Category", style="cyan")
        tag_table.add_column("Selected", style="green")
        tag_table.add_row("Platform", platform)
        tag_table.add_row("Architecture", arch)
        tag_table.add_row("Locale", locale)
        tag_table.add_row("Region", region.upper())
        tag_table.add_row("Content", "speech, text")
        console.print(tag_table)

        # Initialize local storage
        console.print(f"\n[cyan]Initializing CASC storage at:[/cyan] {install_path}")
        storage = LocalStorage(install_path)
        storage.initialize()

        console.print("  Created: Data/data/")
        console.print("  Created: Data/indices/")
        console.print("  Created: Data/config/")

        # Initialize CDN client with proper Ribbit integration and fallback support
        product_enum = get_product_enum(product)
        cdn_client = CDNClient(product_enum, region=region)
        console.print(f"  Product: {product}, Region: {region}")

        # CDNClient handles caching internally via DiskCache
        console.print("  CDN client initialized with Ribbit integration")

        # Step 1: Fetch and save configs (CDNClient handles caching)
        console.print("\n[cyan]Step 1:[/cyan] Fetching and saving configs...")

        # Build config
        build_config_data = cdn_client.fetch_config(build_config_hash, config_type="build")
        console.print(f"  BuildConfig: {build_config_hash}")
        # Also save to local CASC config directory
        storage.save_config(build_config_hash, build_config_data)
        build_config = BuildConfigParser().parse(build_config_data)
        console.print(f"  Build: {build_config.build_name}")

        encoding_info = build_config.get_encoding_info()
        install_info = build_config.get_install_info()
        download_info = build_config.get_download_info()
        size_info = build_config.get_size_info()

        # CDN config
        cdn_config_data = cdn_client.fetch_config(cdn_config_hash, config_type="cdn")
        console.print(f"  CDNConfig: {cdn_config_hash}")
        # Also save to local CASC config directory
        storage.save_config(cdn_config_hash, cdn_config_data)
        cdn_config = CDNConfigParser().parse(cdn_config_data)
        console.print(f"  Archives: {len(cdn_config.archives)}")

        if not encoding_info or not encoding_info.encoding_key:
            raise click.ClickException("No encoding key in BuildConfig")

        # Step 1.5: Create .build.info early (locks configuration before downloads)
        # Initialize version_str with a default value
        version_str: str = ""

        if existing_info is None:
            console.print("\n[cyan]Creating .build.info...[/cyan]")

            # Extract version from build name (e.g., "WOW-65300patch1.15.8" -> "1.15.8.65300")
            import re
            if build_config.build_name:
                match = re.search(r'(\d+)patch([\d.]+)', build_config.build_name)
                if match:
                    build_id, version = match.groups()
                    version_str = f"{version}.{build_id}"

            # Create build info with selected configuration
            build_info = create_build_info(
                branch=region,
                build_config_hash=build_config_hash,
                cdn_config_hash=cdn_config_hash,
                cdn_path=cdn_client.cdn_path or "",
                cdn_hosts=cdn_client.cdn_servers or [],
                version=version_str,
                product=build_config.build_product or product,
                platform=platform,
                architecture=arch,
                locale=locale,
                region=region,
                has_speech=True,
                has_text=True,
                install_key="",
                im_size=None,
                keyring="",
            )

            # Write .build.info
            build_info_parser = BuildInfoParser()
            build_info_path.write_bytes(build_info_parser.build(build_info))
            console.print(f"  Created: {build_info_path}")
            console.print("  [dim]Configuration locked before downloads[/dim]")
        else:
            console.print("\n[cyan]Using existing .build.info...[/cyan]")
            build_info = existing_info

        # Step 2: Fetch encoding file (CDNClient handles caching)
        console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file...")
        encoding_ekey = bytes.fromhex(encoding_info.encoding_key)
        encoding_data_raw = cdn_client.fetch_data(encoding_info.encoding_key)
        console.print(f"  Size: {len(encoding_data_raw):,} bytes")

        # Write raw encoding file to local CASC storage
        storage.write_content(encoding_ekey, encoding_data_raw)
        console.print("  Written to local storage")

        # Decompress for parsing
        encoding_data = encoding_data_raw
        if is_blte(encoding_data):
            encoding_data = decompress_blte(encoding_data)

        encoding_parser = EncodingParser()
        encoding_file = encoding_parser.parse(encoding_data)
        console.print(f"  Parsed: {encoding_file.header.ckey_page_count} CKey pages")

        # Step 2b: Fetch and parse size manifest (if present)
        size_file: SizeFile | None = None
        if size_info and size_info.encoding_key:
            console.print("\n[cyan]Step 2b:[/cyan] Resolving size manifest...")
            size_ckey = bytes.fromhex(size_info.content_key)
            size_ekeys = encoding_parser.find_content_key(
                encoding_data, encoding_file, size_ckey
            )

            if size_ekeys:
                size_ekey = size_ekeys[0]
                console.print(f"  Encoding key: {size_ekey.hex()}")

                try:
                    size_data_raw = cdn_client.fetch_data(size_ekey.hex())
                    storage.write_content(size_ekey, size_data_raw)

                    size_data = size_data_raw
                    if is_blte(size_data):
                        size_data = decompress_blte(size_data)

                    size_parser = SizeParser()
                    size_file = size_parser.parse(size_data)
                    console.print(f"  Entries: {len(size_file.entries):,}")

                    if size_file.header.total_size:
                        console.print(
                            f"  Total build size: {_fmt_size(size_file.header.total_size)}"
                        )

                    # Parse tag entries from remaining data after entries
                    # The tag blob starts after the entry data in the stream
                    if size_file.header.tag_count > 0:
                        # Re-parse to get stream position after entries
                        stream = BytesIO(size_data)
                        _ = size_parser.parse(stream)
                        remaining = stream.read()
                        if remaining:
                            size_file.tags = size_parser.parse_tag_entries(
                                remaining,
                                size_file.header.tag_count,
                                len(size_file.entries),
                            )
                            console.print(
                                f"  Tags: {len(size_file.tags)}"
                            )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch/parse size manifest, continuing without it",
                        error=str(e),
                    )
                    size_file = None
            else:
                console.print("  [yellow]Size manifest not found in encoding file[/yellow]")
        elif size_info:
            # Size manifest has content key but no encoding key - try direct CDN fetch
            console.print("\n[cyan]Step 2b:[/cyan] Size manifest has no encoding key, skipping")

        # Step 3: Resolve and fetch download manifest
        if not download_info:
            raise click.ClickException("No download manifest in BuildConfig")

        console.print("\n[cyan]Step 3:[/cyan] Resolving download manifest...")
        download_ckey = bytes.fromhex(download_info.content_key)
        download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)

        if not download_ekeys:
            raise click.ClickException("Download manifest not found in encoding file")

        download_ekey = download_ekeys[0]
        download_ekey_hex = download_ekey.hex()
        console.print(f"  Encoding key: {download_ekey_hex}")

        # Fetch download manifest (CDNClient handles caching)
        download_data_raw = cdn_client.fetch_data(download_ekey_hex)
        console.print(f"  Size: {len(download_data_raw):,} bytes")
        # Write to local CASC storage
        storage.write_content(download_ekey, download_data_raw)
        console.print("  Written download manifest to local storage")

        download_data = download_data_raw
        if is_blte(download_data):
            download_data = decompress_blte(download_data)

        download_parser = DownloadParser()
        download_manifest = download_parser.parse(download_data)
        console.print(f"  Total entries in manifest: {len(download_manifest.entries):,}")

        # Display available tags
        tag_names = [t.name for t in download_manifest.tags]
        console.print(f"  Available tags: {', '.join(sorted(tag_names))}")

        # Step 4: Filter by priority and tags
        console.print("\n[cyan]Step 4:[/cyan] Filtering download manifest...")
        console.print(f"  Platform: {platform}")
        console.print(f"  Architecture: {arch}")
        console.print(f"  Locale: {locale}")
        console.print(f"  Max priority: {priority}")

        # Display total build size from size manifest if available
        if size_file and size_file.header.total_size:
            console.print(
                f"  Total build size (from size manifest): "
                f"{_fmt_size(size_file.header.total_size)}"
            )

        # Filter by priority
        download_entries: list[DownloadEntry] = [
            e for e in download_manifest.entries if e.priority <= priority
        ]
        console.print(f"  After priority filter (<= {priority}): {len(download_entries):,} entries")

        # Filter by tags (platform, arch, locale)
        # Use size manifest tags if available (canonical tag source),
        # fall back to download manifest tags
        if size_file and size_file.tags:
            console.print("  Using size manifest tags for filtering")
            download_entries = filter_entries_by_tags(
                download_entries,
                download_manifest.tags,
                platform=platform,
                arch=arch,
                locale=locale,
                size_tags=size_file.tags,
            )
        else:
            download_entries = filter_entries_by_tags(
                download_entries,
                download_manifest.tags,
                platform=platform,
                arch=arch,
                locale=locale,
            )
        console.print(f"  After tag filtering: {len(download_entries):,} entries")

        # Calculate total size
        total_filtered_size = sum(e.size for e in download_entries)
        console.print(f"  Total filtered size: {_fmt_size(total_filtered_size)}")

        # Load or create install state for resume tracking
        install_state = InstallState.load(install_path, build_config_hash)
        if install_state is not None:
            already_done = len(install_state.downloaded)
            console.print(f"\n  [green]Resuming:[/green] {already_done:,} files already downloaded")
            console.print(f"  Previously written: {_fmt_size(install_state.total_bytes_written)}")
        else:
            install_state = InstallState(install_path, build_config_hash)

        # Initialize priority stats from the full filtered set
        install_state.init_priority_stats(download_entries)

        # Show per-priority overview
        _show_priority_table(console, download_entries, install_state)

        # Filter out already-downloaded entries
        pending_entries = install_state.get_pending_entries(download_entries)
        if len(pending_entries) < len(download_entries):
            skipped = len(download_entries) - len(pending_entries)
            console.print(f"  Skipping {skipped:,} already-downloaded files")

        # Step 5: Download archive indices FIRST (needed for both install and download files)
        # This is critical - most files are in archives, not loose on CDN
        console.print("\n[cyan]Step 5:[/cyan] Loading/downloading archive indices...")
        console.print("  (Required before extracting any files)")

        archives = cdn_config.archives
        if max_archives > 0:
            archives = archives[:max_archives]
            console.print(f"  [yellow]Warning: Limited to {max_archives} archives[/yellow]")

        # CdnArchiveFetcher uses cdn_client for fetching with fallback support
        fetcher = CdnArchiveFetcher(cdn_client=cdn_client)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Loading indices...", total=len(archives))

            async def _download_indices_concurrent() -> int:
                """Download archive indices concurrently (12 at a time)."""
                semaphore = asyncio.Semaphore(12)
                lock = asyncio.Lock()
                successful = 0

                async def fetch_one(archive_hash: str) -> None:
                    nonlocal successful
                    async with semaphore:
                        index_data = await cdn_client.fetch_data_async(
                            archive_hash, is_index=True
                        )

                    # Index parsing and disk write under lock (CPU-bound, fast)
                    async with lock:
                        fetcher.load_index_from_bytes(archive_hash, index_data)
                        local_path = storage.indices_path / f"{archive_hash.lower()}.index"
                        if not local_path.exists():
                            local_path.write_bytes(index_data)
                        successful += 1
                        progress.update(task, advance=1)

                tasks = [fetch_one(h) for h in archives]
                await asyncio.gather(*tasks, return_exceptions=True)
                return successful

            indices_loaded = asyncio.run(_download_indices_concurrent())

        console.print(f"  Index map: {fetcher.index_map.total_entries:,} entries")
        console.print(f"  Archives: {indices_loaded}/{len(archives)} loaded")

        # Step 6: Process install manifest (executables and DLLs)
        # Now we can fetch files using the archive indices
        install_entries_extracted = 0
        if install_info:
            console.print("\n[cyan]Step 6:[/cyan] Processing install manifest (executables)...")
            install_ckey = bytes.fromhex(install_info.content_key)
            install_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, install_ckey)

            if install_ekeys:
                install_ekey = install_ekeys[0]
                console.print(f"  Encoding key: {install_ekey.hex()}")

                # Try to fetch install manifest from archives first, then loose via CDNClient
                install_data_raw = fetcher.fetch_file_via_cdn(cdn_client, install_ekey, decompress=False)
                if install_data_raw is None:
                    # Fallback to loose file via CDNClient
                    install_data_raw = cdn_client.fetch_data(install_ekey.hex())

                storage.write_content(install_ekey, install_data_raw)

                install_data = install_data_raw
                if is_blte(install_data):
                    install_data = decompress_blte(install_data)

                install_parser = InstallParser()
                install_manifest = install_parser.parse(install_data)
                console.print(f"  Total install entries: {len(install_manifest.entries):,}")

                # Filter install entries by tags using bitmap operations
                def filter_install_entries(
                    install_entries: list[InstallEntry],
                    install_tags: list[InstallTag],
                    plat: str | None,
                    ar: str | None,
                    loc: str | None
                ) -> list[InstallEntry]:
                    """Filter install entries by platform, arch, locale.
                    Uses bitmap-based tag filtering matching Agent.exe behavior.
                    """
                    # Build tag query from parameters
                    query_parts: list[str] = []
                    if plat:
                        query_parts.append(plat)
                    if ar:
                        query_parts.append(ar)
                    if loc:
                        query_parts.append(loc)
                    query = ",".join(query_parts) if query_parts else ""

                    if not query:
                        # No filters, return all entries
                        return install_entries

                    # Create SizeTag objects from InstallTag for apply_tag_query
                    from cascette_tools.formats.size import SizeTag

                    size_tags = [
                        SizeTag(
                            name=tag.name,
                            tag_id=tag.tag_type,
                            tag_type=tag.tag_type,
                            file_indices=[],
                            bit_mask=tag.bit_mask
                        )
                        for tag in install_tags
                    ]

                    # Apply tag query to get selection bitmap
                    bitmap = apply_tag_query(size_tags, query, len(install_entries))

                    # Filter entries based on bitmap
                    filtered: list[InstallEntry] = []
                    for i, entry in enumerate(install_entries):
                        if is_file_selected(bitmap, i):
                            filtered.append(entry)
                    return filtered

                install_filtered = filter_install_entries(
                    install_manifest.entries,
                    install_manifest.tags,
                    platform, arch, locale
                )
                console.print(f"  After tag filtering: {len(install_filtered):,} entries")

                # Extract install files to filesystem using archive fetcher
                if install_filtered:
                    console.print(f"  Extracting {len(install_filtered)} files to filesystem...")

                    for inst_entry in install_filtered:
                        # Look up encoding keys for this content key
                        file_ekeys = encoding_parser.find_content_key(
                            encoding_data, encoding_file, inst_entry.md5_hash
                        )
                        if not file_ekeys:
                            console.print(f"    [yellow]Skip:[/yellow] {inst_entry.filename} (not in encoding)")
                            continue

                        # Try each encoding key until one succeeds
                        # (matches Rust behavior - content keys can have multiple
                        # encoding keys for different compression strategies)
                        file_data: bytes | None = None
                        for file_ekey in file_ekeys:
                            try:
                                # Try archive fetch first (range request)
                                file_data = fetcher.fetch_file_via_cdn(
                                    cdn_client, file_ekey, decompress=True
                                )

                                if file_data is None:
                                    # Fallback to loose file via CDNClient
                                    # Use quiet=True since missing files are expected
                                    # for old builds
                                    try:
                                        ekey_hex = file_ekey.hex()
                                        file_data = cdn_client.fetch_data(
                                            ekey_hex, quiet=True
                                        )
                                        if is_blte(file_data):
                                            file_data = decompress_blte(file_data)
                                    except Exception:
                                        file_data = None

                                if file_data is not None:
                                    break  # Success with this encoding key

                            except Exception:
                                continue  # Try next encoding key

                        if file_data is None:
                            console.print(f"    [yellow]Not found:[/yellow] {inst_entry.filename}")
                            continue

                        try:
                            # Write to filesystem (normalize Windows paths)
                            fname = inst_entry.filename.replace('\\', '/')
                            output_file = install_path / fname
                            output_file.parent.mkdir(parents=True, exist_ok=True)
                            output_file.write_bytes(file_data)
                            install_entries_extracted += 1

                        except Exception as e:
                            console.print(f"    [red]Error:[/red] {inst_entry.filename}: {e}")

                    console.print(f"  Extracted {install_entries_extracted} files")
            else:
                console.print("  [yellow]Install manifest not found in encoding file[/yellow]")
        else:
            console.print("\n[cyan]Step 6:[/cyan] No install manifest in BuildConfig")

        # Step 7: Install CASC files from download manifest
        if max_files > 0:
            pending_entries = pending_entries[:max_files]

        console.print(f"\n[cyan]Step 7:[/cyan] Installing {len(pending_entries)} files to local CASC...")
        console.print("  Concurrent connections: 12 global, 3 per host")

        installed = 0
        failed = 0
        integrity_errors = 0
        total_bytes = 0

        from rich.progress import (
            DownloadColumn,
            TransferSpeedColumn,
        )

        pending_total_size = sum(e.size for e in pending_entries)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                "Installing files...",
                total=pending_total_size,
            )

            async def _install_files_concurrent() -> tuple[int, int, int, int]:
                """Download and install CASC files concurrently."""
                _installed = 0
                _failed = 0
                _integrity_errors = 0
                _total_bytes = 0

                queue = DownloadQueue(
                    max_concurrency=12, max_per_host=3, max_retries=3
                )

                # Build a priority lookup for state tracking
                entry_priority: dict[str, int] = {
                    e.ekey.hex(): e.priority for e in pending_entries
                }

                # Sort by priority and submit all entries
                sorted_entries = sorted(pending_entries, key=lambda e: e.priority)

                for dl_entry in sorted_entries:
                    ekey = dl_entry.ekey

                    async def make_factory(ek: bytes = ekey) -> DownloadResult:
                        data = await fetcher.fetch_file_via_cdn_async(
                            cdn_client, ek, decompress=False, verify=True,
                        )
                        source = ""
                        loc = fetcher.index_map.find(ek)
                        if loc:
                            source = loc.archive_hash
                        return DownloadResult(
                            ekey=ek,
                            data=data,
                            error=None if data is not None else "Not found in archives",
                            source=source,
                        )

                    await queue.submit(
                        priority=dl_entry.priority,
                        ekey=dl_entry.ekey,
                        coro_factory=make_factory,
                    )

                async for result in queue.run(total=len(sorted_entries)):
                    ekey_hex = result.ekey.hex()
                    pri = entry_priority.get(ekey_hex, 0)

                    if result.data is None:
                        _failed += 1
                        install_state.mark_failed(result.ekey, pri)
                        if install_state.should_save():
                            install_state.save()
                        continue

                    try:
                        storage.write_content(result.ekey, result.data)
                    except IntegrityError as e:
                        _integrity_errors += 1
                        logger.warning(
                            "Integrity error writing content",
                            ekey=ekey_hex,
                            error=str(e),
                        )
                        install_state.mark_failed(result.ekey, pri)
                        if install_state.should_save():
                            install_state.save()
                        continue

                    _installed += 1
                    _total_bytes += len(result.data)
                    install_state.mark_downloaded(
                        result.ekey, len(result.data), pri
                    )
                    progress.update(task, advance=len(result.data))

                    if install_state.should_save():
                        install_state.save()

                return _installed, _failed, _integrity_errors, _total_bytes

            installed, failed, integrity_errors, total_bytes = asyncio.run(
                _install_files_concurrent()
            )

        # Final state save after all downloads
        install_state.save()

        # Step 8: Update .build.info with last activated timestamp
        console.print("\n[cyan]Step 8:[/cyan] Updating .build.info timestamp...")
        build_info = update_last_activated(build_info)
        build_info_parser = BuildInfoParser()
        build_info_path.write_bytes(build_info_parser.build(build_info))
        console.print(f"  Updated: {build_info_path}")
        console.print(f"  Last Activated: {build_info.last_activated}")

        # Step 9: Flush index files
        console.print("\n[cyan]Step 9:[/cyan] Writing local index files...")
        storage.flush_indices()

        # Show bucket distribution
        # LocalStorage.get_statistics() returns dict without type args
        stats: dict[str, Any] = cast(dict[str, Any], storage.get_statistics())  # type: ignore[reportUnknownMemberType]
        total_entries_count: int = stats.get('total_entries', 0)
        console.print(f"  Total entries: {total_entries_count:,}")

        bucket_table = Table(title="Bucket Distribution")
        bucket_table.add_column("Bucket", style="cyan")
        bucket_table.add_column("Entries", style="green", justify="right")
        bucket_table.add_column("Size", style="yellow", justify="right")

        buckets: dict[str, Any] = stats.get('buckets', {})
        for bucket_id, bucket_stats in sorted(buckets.items()):
            bucket_table.add_row(
                str(bucket_id),
                f"{bucket_stats.get('count', 0):,}",
                f"{bucket_stats.get('total_size', 0) / 1024:.1f} KB"
            )

        console.print(bucket_table)

        # Step 10: Generate product state files
        console.print("\n[cyan]Step 10:[/cyan] Generating product state files...")

        # Determine product code from build config
        product_code = build_config.build_product or product

        product_info = ProductInfo(
            product_code=product_code,
            version=version_str or "1.0.0.00000",
            build_config=build_config_hash,
            region=region,
            locale=locale,
            install_path=install_path,
        )

        state_files = generate_all_state_files(product_info, install_path)
        for file_name, file_path in state_files.items():
            console.print(f"  Created: {file_name} ({file_path})")

        # Per-priority results
        _show_priority_table(
            console, download_entries, install_state,
            title="Per-Priority Results",
        )

        # Summary
        summary_table = Table(title="Installation Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        summary_table.add_row("Install path", str(install_path))
        summary_table.add_row("Build", build_config.build_name or "N/A")
        summary_table.add_row("Platform", platform)
        summary_table.add_row("Architecture", arch)
        summary_table.add_row("Locale", locale)
        summary_table.add_row("Priority filter", f"<= {priority}")
        summary_table.add_row("Install manifest files", f"{install_entries_extracted}")
        summary_table.add_row("CASC files installed", f"{installed:,}")
        summary_table.add_row("CASC files failed", str(failed))
        summary_table.add_row("Integrity errors", str(integrity_errors))
        summary_table.add_row("Total data written", _fmt_size(total_bytes))
        summary_table.add_row("Archive indices", f"{len(archives)}")
        summary_table.add_row("State files created", f"{len(state_files)}")
        console.print(summary_table)

        # Clean up state file on successful completion (no failures)
        if failed == 0 and integrity_errors == 0:
            install_state.cleanup()
            console.print("  [dim]Install state file removed (all files succeeded)[/dim]")

        console.print(Panel.fit(
            f"[green]Installation complete![/green]\n\n"
            f"The CASC storage structure has been created at:\n"
            f"  {install_path}/Data/data/    - Local archives with .idx files\n"
            f"  {install_path}/Data/indices/ - CDN archive indices\n"
            f"  {install_path}/Data/config/  - Configuration files\n"
            f"  {install_path}/.product.db   - Product database\n"
            f"  {install_path}/.build.info   - Build information\n"
            f"  {install_path}/Launcher.db   - Launcher state",
            title="Success"
        ))

        # Close CDN client
        cdn_client.close()

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Installation failed", error=str(e))
        raise click.ClickException(f"Installation failed: {e}") from e
