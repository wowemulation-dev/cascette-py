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

from dataclasses import dataclass
from pathlib import Path

import click
import httpx
import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cascette_tools.core.cache import DiskCache
from cascette_tools.core.cdn_archive_fetcher import (
    CdnArchiveFetcher,
    parse_cdn_config_archives,
)
from cascette_tools.core.config import AppConfig
from cascette_tools.core.local_storage import LocalStorage
from cascette_tools.core.product_state import (
    ProductInfo,
    generate_all_state_files,
)
from cascette_tools.formats.blte import decompress_blte, is_blte
from cascette_tools.formats.download import DownloadParser
from cascette_tools.formats.encoding import EncodingParser, is_encoding
from cascette_tools.formats.install import InstallParser

logger = structlog.get_logger()


@dataclass
class BuildConfigInfo:
    """Parsed build config information."""
    root_content_key: str | None
    encoding_content_key: str | None
    encoding_encoding_key: str | None  # CDN key for encoding file
    encoding_size: int | None
    install_content_key: str | None
    install_size: int | None
    download_content_key: str | None
    download_size: int | None
    patch_content_key: str | None
    build_name: str | None
    build_uid: str | None
    build_product: str | None


@dataclass
class CdnConfigInfo:
    """Parsed CDN config information."""
    archives: list[str]
    archive_group: str | None
    file_index: str | None
    patch_archives: list[str]
    patch_archive_group: str | None


def parse_build_config(content: str) -> BuildConfigInfo:
    """Parse build config text file.

    Args:
        content: Build config text content

    Returns:
        Parsed build config info
    """
    config: dict[str, str] = {}
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            config[key] = value

    def get_first(key: str) -> str | None:
        """Get first value from potentially space-separated list."""
        val = config.get(key)
        return val.split()[0] if val else None

    def get_second(key: str) -> str | None:
        """Get second value from potentially space-separated list (encoding key)."""
        val = config.get(key)
        parts = val.split() if val else []
        return parts[1] if len(parts) > 1 else None

    def get_size(key: str) -> int | None:
        """Get size from install/download size field."""
        val = config.get(f'{key}-size')
        return int(val.split()[0]) if val else None

    return BuildConfigInfo(
        root_content_key=get_first('root'),
        encoding_content_key=get_first('encoding'),
        encoding_encoding_key=get_second('encoding'),
        encoding_size=get_size('encoding'),
        install_content_key=get_first('install'),
        install_size=get_size('install'),
        download_content_key=get_first('download'),
        download_size=get_size('download'),
        patch_content_key=get_first('patch'),
        build_name=config.get('build-name'),
        build_uid=config.get('build-uid'),
        build_product=config.get('build-product'),
    )


def parse_cdn_config(content: str) -> CdnConfigInfo:
    """Parse CDN config text file.

    Args:
        content: CDN config text content

    Returns:
        Parsed CDN config info
    """
    config: dict[str, str] = {}
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            config[key] = value

    archives_str = config.get('archives', '')
    archives = archives_str.split() if archives_str else []

    patch_archives_str = config.get('patch-archives', '')
    patch_archives = patch_archives_str.split() if patch_archives_str else []

    return CdnConfigInfo(
        archives=archives,
        archive_group=config.get('archive-group'),
        file_index=config.get('file-index'),
        patch_archives=patch_archives,
        patch_archive_group=config.get('patch-archive-group'),
    )


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract common context objects."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    verbose: bool = ctx.obj["verbose"]
    debug: bool = ctx.obj["debug"]
    return config, console, verbose, debug


def fetch_config(client: httpx.Client, cdn_base: str, cdn_path: str, hash_str: str) -> str:
    """Fetch a config file from CDN.

    Args:
        client: HTTP client
        cdn_base: CDN base URL
        cdn_path: CDN product path (e.g., tpr/wow)
        hash_str: Config hash

    Returns:
        Config file content as string
    """
    h = hash_str.lower()
    url = f"{cdn_base}/{cdn_path}/config/{h[:2]}/{h[2:4]}/{h}"
    response = client.get(url)
    response.raise_for_status()
    return response.text


def fetch_data(client: httpx.Client, cdn_base: str, cdn_path: str, hash_str: str) -> bytes:
    """Fetch a data file from CDN.

    Args:
        client: HTTP client
        cdn_base: CDN base URL
        cdn_path: CDN product path (e.g., tpr/wow)
        hash_str: Data hash

    Returns:
        Raw file content (may be BLTE compressed)
    """
    h = hash_str.lower()
    url = f"{cdn_base}/{cdn_path}/data/{h[:2]}/{h[2:4]}/{h}"
    response = client.get(url)
    response.raise_for_status()
    return response.content


@click.group()
def install_poc() -> None:
    """POC commands for full installation workflow."""
    pass


@install_poc.command()
@click.argument("build_config_hash", type=str)
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
def resolve_manifests(
    ctx: click.Context,
    build_config_hash: str,
    cdn_base: str,
    cdn_path: str
) -> None:
    """Resolve all manifests starting from a build config hash.

    BUILD_CONFIG_HASH is the hash from the versions endpoint.

    This demonstrates the complete NGDP resolution chain:
    1. BuildConfig -> encoding key
    2. Encoding file -> install/root content key resolution
    3. Install manifest -> file list and sizes
    """
    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        with httpx.Client(timeout=60.0) as client:
            # Step 1: Fetch and parse BuildConfig
            console.print("[cyan]Step 1:[/cyan] Fetching BuildConfig...")
            build_config_text = fetch_config(client, cdn_base, cdn_path, build_config_hash)
            build_config = parse_build_config(build_config_text)

            table = Table(title="BuildConfig")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Build Name", build_config.build_name or "N/A")
            table.add_row("Build UID", build_config.build_uid or "N/A")
            table.add_row("Root Content Key", build_config.root_content_key or "N/A")
            table.add_row("Encoding Content Key", build_config.encoding_content_key or "N/A")
            table.add_row("Encoding Encoding Key", build_config.encoding_encoding_key or "N/A")
            table.add_row("Encoding Size", f"{build_config.encoding_size:,}" if build_config.encoding_size else "N/A")
            table.add_row("Install Content Key", build_config.install_content_key or "N/A")
            table.add_row("Install Size", f"{build_config.install_size:,}" if build_config.install_size else "N/A")
            table.add_row("Download Content Key", build_config.download_content_key or "N/A")
            table.add_row("Download Size", f"{build_config.download_size:,}" if build_config.download_size else "N/A")
            console.print(table)

            if not build_config.encoding_encoding_key:
                raise click.ClickException("No encoding key found in BuildConfig")

            # Step 2: Fetch encoding file directly from CDN
            console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file from CDN...")
            console.print(f"  Using encoding key: {build_config.encoding_encoding_key}")

            encoding_data = fetch_data(client, cdn_base, cdn_path, build_config.encoding_encoding_key)
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
            if build_config.install_content_key:
                console.print("\n[cyan]Step 4:[/cyan] Resolving install manifest...")
                install_ckey = bytes.fromhex(build_config.install_content_key)

                # Find encoding key for install manifest
                install_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, install_ckey)

                if install_ekeys:
                    install_ekey = install_ekeys[0].hex()
                    console.print(f"  Found encoding key: {install_ekey}")

                    # Fetch install manifest
                    console.print("\n[cyan]Step 5:[/cyan] Fetching install manifest...")
                    install_data = fetch_data(client, cdn_base, cdn_path, install_ekey)
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
            if build_config.download_content_key:
                console.print("\n[cyan]Step 7:[/cyan] Resolving download manifest...")
                download_ckey = bytes.fromhex(build_config.download_content_key)

                download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)
                if download_ekeys:
                    download_ekey = download_ekeys[0].hex()
                    console.print(f"  Found encoding key: {download_ekey}")

                    # Fetch download manifest
                    console.print("\n[cyan]Step 8:[/cyan] Fetching download manifest...")
                    download_data = fetch_data(client, cdn_base, cdn_path, download_ekey)
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

    except httpx.HTTPError as e:
        logger.error("HTTP error", error=str(e))
        raise click.ClickException(f"HTTP error: {e}") from e
    except Exception as e:
        logger.error("Resolution failed", error=str(e))
        raise click.ClickException(f"Resolution failed: {e}") from e


@install_poc.command()
@click.option(
    "--product", "-p",
    type=str,
    default="wow_classic_era",
    help="Product code"
)
@click.option(
    "--region", "-r",
    type=str,
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
    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        with httpx.Client(timeout=30.0) as client:
            # Query versions endpoint
            url = f"https://{region}.version.battle.net/{product}/versions"
            console.print(f"[cyan]Querying:[/cyan] {url}")

            response = client.get(url)
            response.raise_for_status()

            # Parse BPSV response
            lines = response.text.strip().split('\n')
            if len(lines) < 2:
                raise click.ClickException("Invalid versions response")

            # Filter out comment lines and find header
            data_lines = []
            header_line = None
            for line in lines:
                if line.startswith('##'):
                    continue  # Skip comment lines
                if header_line is None:
                    header_line = line
                else:
                    data_lines.append(line)

            if not header_line or not data_lines:
                raise click.ClickException("No data in versions response")

            headers = [h.split('!')[0] for h in header_line.split('|')]

            # Find indices
            try:
                build_config_idx = headers.index('BuildConfig')
                cdn_config_idx = headers.index('CDNConfig')
                version_idx = headers.index('VersionsName')
                build_id_idx = headers.index('BuildId')
            except ValueError as e:
                raise click.ClickException(f"Missing required field in versions: {e}") from e

            # Parse first data row (latest)
            data_line = data_lines[0]
            values = data_line.split('|')

            build_config_hash = values[build_config_idx]
            cdn_config_hash = values[cdn_config_idx]
            version = values[version_idx]
            build_id = values[build_id_idx]

            table = Table(title=f"Latest {product} Build")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Version", version)
            table.add_row("Build ID", build_id)
            table.add_row("Build Config", build_config_hash)
            table.add_row("CDN Config", cdn_config_hash)
            console.print(table)

            # Now invoke the resolve command
            console.print("\n[bold]Resolving manifests...[/bold]\n")
            ctx.invoke(
                resolve_manifests,
                build_config_hash=build_config_hash,
                cdn_base="http://us.cdn.blizzard.com",
                cdn_path=f"tpr/{product.replace('_', '')}" if product != "wow_classic_era" else "tpr/wow"
            )

    except httpx.HTTPError as e:
        logger.error("HTTP error", error=str(e))
        raise click.ClickException(f"HTTP error: {e}") from e
    except Exception as e:
        logger.error("Discovery failed", error=str(e))
        raise click.ClickException(f"Discovery failed: {e}") from e


@install_poc.command()
@click.argument("cdn_config_hash", type=str)
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
    cdn_base: str,
    cdn_path: str,
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

    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Parse encoding key
        ekey = bytes.fromhex(encoding_key)
        if len(ekey) != 16:
            raise click.ClickException("Encoding key must be 32 hex characters (16 bytes)")

        with httpx.Client(timeout=60.0) as client:
            # Step 1: Fetch CDN config
            console.print("[cyan]Step 1:[/cyan] Fetching CDN config...")
            cdn_config_text = fetch_config(client, cdn_base, cdn_path, cdn_config_hash)
            archives = parse_cdn_config_archives(cdn_config_text)

            if not archives:
                raise click.ClickException("No archives found in CDN config")

            console.print(f"  Found {len(archives)} archives")

            if max_archives > 0:
                archives = archives[:max_archives]
                console.print(f"  Limiting to first {max_archives} archives")

            # Step 2: Download archive indices
            console.print(f"\n[cyan]Step 2:[/cyan] Downloading {len(archives)} archive indices...")

            fetcher = CdnArchiveFetcher(cdn_base=cdn_base, cdn_path=cdn_path)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Downloading indices...", total=len(archives))

                def update_progress(completed: int, total: int) -> None:
                    progress.update(task, completed=completed)

                successful = fetcher.download_indices(archives, progress_callback=update_progress)

            console.print(f"  Downloaded {successful}/{len(archives)} indices")
            console.print(f"  Total entries in index map: {fetcher.index_map.total_entries:,}")

            # Step 3: Find and extract the file
            console.print("\n[cyan]Step 3:[/cyan] Extracting file...")
            console.print(f"  Looking for encoding key: {encoding_key}")

            location = fetcher.index_map.find(ekey)
            if not location:
                raise click.ClickException("Encoding key not found in any downloaded archive index")

            console.print(f"  Found in archive: {location.archive_hash}")
            console.print(f"  Offset: {location.offset}, Size: {location.size:,} bytes")

            # Fetch the file
            console.print("\n[cyan]Step 4:[/cyan] Fetching file from archive...")
            data = fetcher.fetch_file(client, ekey, decompress=not no_decompress)

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
    cdn_base: str,
    cdn_path: str,
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

    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        with httpx.Client(timeout=60.0) as client:
            # Step 1: Fetch and parse BuildConfig
            console.print("[cyan]Step 1:[/cyan] Fetching BuildConfig...")
            build_config_text = fetch_config(client, cdn_base, cdn_path, build_config_hash)
            build_config = parse_build_config(build_config_text)

            if not build_config.encoding_encoding_key:
                raise click.ClickException("No encoding key in BuildConfig")

            console.print(f"  Build: {build_config.build_name}")

            # Step 2: Fetch encoding file
            console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file...")
            encoding_data = fetch_data(client, cdn_base, cdn_path, build_config.encoding_encoding_key)

            if is_blte(encoding_data):
                encoding_data = decompress_blte(encoding_data)

            encoding_parser = EncodingParser()
            encoding_file = encoding_parser.parse(encoding_data)
            console.print(f"  Loaded {encoding_file.header.ckey_page_count} CKey pages")

            # Step 3: Resolve and fetch download manifest
            if not build_config.download_content_key:
                raise click.ClickException("No download manifest in BuildConfig")

            console.print("\n[cyan]Step 3:[/cyan] Resolving download manifest...")
            download_ckey = bytes.fromhex(build_config.download_content_key)
            download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)

            if not download_ekeys:
                raise click.ClickException("Download manifest not found in encoding file")

            download_ekey = download_ekeys[0].hex()
            console.print(f"  Encoding key: {download_ekey}")

            download_data = fetch_data(client, cdn_base, cdn_path, download_ekey)
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
            cdn_config_text = fetch_config(client, cdn_base, cdn_path, cdn_config_hash)
            archives = parse_cdn_config_archives(cdn_config_text)

            if max_archives > 0:
                archives = archives[:max_archives]

            console.print(f"  Downloading {len(archives)} archive indices...")

            fetcher = CdnArchiveFetcher(cdn_base=cdn_base, cdn_path=cdn_path)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Downloading indices...", total=len(archives))

                def update_progress(completed: int, total: int) -> None:
                    progress.update(task, completed=completed)

                fetcher.download_indices(archives, progress_callback=update_progress)

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

                    # Extract file
                    data = fetcher.fetch_file(client, entry.ekey, decompress=True)

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

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Extraction failed", error=str(e))
        raise click.ClickException(f"Extraction failed: {e}") from e


def filter_entries_by_tags(
    entries: list,
    tags: list,
    platform: str | None = None,
    arch: str | None = None,
    locale: str | None = None,
) -> list:
    """Filter download entries by platform, architecture, and locale tags.

    Battle.net's tag filtering logic:
    - Files can have multiple tags from different categories
    - For a file to be included, it must match at least one tag from each
      specified category (OR within category, AND across categories)
    - Files with no tags in a category are included (wildcard)

    Args:
        entries: List of DownloadEntry objects
        tags: List of DownloadTag objects (for reference)
        platform: Platform filter (e.g., "Windows", "OSX")
        arch: Architecture filter (e.g., "x86_64", "arm64")
        locale: Locale filter (e.g., "enUS", "deDE")

    Returns:
        Filtered list of entries
    """
    # Define tag categories
    platform_tags = {"Windows", "OSX", "Android", "iOS", "PS5", "Web", "XBSX"}
    arch_tags = {"x86_32", "x86_64", "arm64"}
    locale_tags = {"enUS", "deDE", "esES", "esMX", "frFR", "koKR", "ptBR", "ruRU", "zhCN", "zhTW"}

    filtered = []
    for entry in entries:
        entry_tags = set(entry.tags)

        # Check platform filter
        if platform:
            entry_platform_tags = entry_tags & platform_tags
            # If entry has platform tags, must match; if no platform tags, include
            if entry_platform_tags and platform not in entry_platform_tags:
                continue

        # Check architecture filter
        if arch:
            entry_arch_tags = entry_tags & arch_tags
            # If entry has arch tags, must match; if no arch tags, include
            if entry_arch_tags and arch not in entry_arch_tags:
                continue

        # Check locale filter
        if locale:
            entry_locale_tags = entry_tags & locale_tags
            # If entry has locale tags, must match; if no locale tags, include
            if entry_locale_tags and locale not in entry_locale_tags:
                continue

        filtered.append(entry)

    return filtered


@install_poc.command()
@click.argument("build_config_hash", type=str)
@click.argument("cdn_config_hash", type=str)
@click.argument("install_path", type=click.Path(path_type=Path))
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
@click.pass_context
def install_to_casc(
    ctx: click.Context,
    build_config_hash: str,
    cdn_config_hash: str,
    install_path: Path,
    cdn_base: str,
    cdn_path: str,
    max_archives: int,
    max_files: int,
    priority: int,
    platform: str,
    arch: str,
    locale: str,
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

    config, console, verbose, debug = _get_context_objects(ctx)

    try:
        # Initialize local storage
        console.print(f"[cyan]Initializing CASC storage at:[/cyan] {install_path}")
        storage = LocalStorage(install_path)
        storage.initialize()

        console.print("  Created: Data/data/")
        console.print("  Created: Data/indices/")
        console.print("  Created: Data/config/")

        # Initialize XDG-compliant disk cache
        cache = DiskCache()
        console.print(f"  Using XDG cache: {cache.base_dir}")

        with httpx.Client(timeout=60.0) as client:
            # Step 1: Fetch and save configs (check XDG cache first)
            console.print("\n[cyan]Step 1:[/cyan] Fetching and saving configs...")

            # Build config (check XDG cache)
            cached_build = cache.get_cdn(build_config_hash, "config", cdn_path)
            if cached_build:
                build_config_text = cached_build.decode()
                console.print(f"  [green]Cached[/green] BuildConfig: {build_config_hash}")
            else:
                build_config_text = fetch_config(client, cdn_base, cdn_path, build_config_hash)
                cache.put_cdn(build_config_hash, build_config_text.encode(), "config", cdn_path)
                console.print(f"  Downloaded BuildConfig: {build_config_hash}")
            # Also save to local CASC config directory
            storage.save_config(build_config_hash, build_config_text.encode())
            build_config = parse_build_config(build_config_text)
            console.print(f"  Build: {build_config.build_name}")

            # CDN config (check XDG cache)
            cached_cdn = cache.get_cdn(cdn_config_hash, "config", cdn_path)
            if cached_cdn:
                cdn_config_text = cached_cdn.decode()
                console.print(f"  [green]Cached[/green] CDNConfig: {cdn_config_hash}")
            else:
                cdn_config_text = fetch_config(client, cdn_base, cdn_path, cdn_config_hash)
                cache.put_cdn(cdn_config_hash, cdn_config_text.encode(), "config", cdn_path)
                console.print(f"  Downloaded CDNConfig: {cdn_config_hash}")
            # Also save to local CASC config directory
            storage.save_config(cdn_config_hash, cdn_config_text.encode())
            cdn_config = parse_cdn_config(cdn_config_text)
            console.print(f"  Archives: {len(cdn_config.archives)}")

            if not build_config.encoding_encoding_key:
                raise click.ClickException("No encoding key in BuildConfig")

            # Step 2: Fetch encoding file (check XDG cache first)
            console.print("\n[cyan]Step 2:[/cyan] Fetching encoding file...")
            encoding_ekey = bytes.fromhex(build_config.encoding_encoding_key)
            encoding_data_raw = cache.get_cdn(build_config.encoding_encoding_key, "data", cdn_path)
            if encoding_data_raw:
                console.print(f"  [green]Cached[/green]: {len(encoding_data_raw):,} bytes")
            else:
                encoding_data_raw = fetch_data(client, cdn_base, cdn_path, build_config.encoding_encoding_key)
                console.print(f"  Downloaded: {len(encoding_data_raw):,} bytes")
                cache.put_cdn(build_config.encoding_encoding_key, encoding_data_raw, "data", cdn_path)
                console.print("  Cached to XDG")

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

            # Step 3: Resolve and fetch download manifest
            if not build_config.download_content_key:
                raise click.ClickException("No download manifest in BuildConfig")

            console.print("\n[cyan]Step 3:[/cyan] Resolving download manifest...")
            download_ckey = bytes.fromhex(build_config.download_content_key)
            download_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, download_ckey)

            if not download_ekeys:
                raise click.ClickException("Download manifest not found in encoding file")

            download_ekey = download_ekeys[0]
            download_ekey_hex = download_ekey.hex()
            console.print(f"  Encoding key: {download_ekey_hex}")

            # Check XDG cache first
            download_data_raw = cache.get_cdn(download_ekey_hex, "data", cdn_path)
            if download_data_raw:
                console.print(f"  [green]Cached[/green]: {len(download_data_raw):,} bytes")
            else:
                download_data_raw = fetch_data(client, cdn_base, cdn_path, download_ekey_hex)
                console.print(f"  Downloaded: {len(download_data_raw):,} bytes")
                cache.put_cdn(download_ekey_hex, download_data_raw, "data", cdn_path)
                console.print("  Cached to XDG")
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

            # Filter by priority
            entries = [e for e in download_manifest.entries if e.priority <= priority]
            console.print(f"  After priority filter (<= {priority}): {len(entries):,} entries")

            # Filter by tags (platform, arch, locale)
            entries = filter_entries_by_tags(
                entries,
                download_manifest.tags,
                platform=platform,
                arch=arch,
                locale=locale
            )
            console.print(f"  After tag filtering: {len(entries):,} entries")

            # Calculate total size
            total_filtered_size = sum(e.size for e in entries)
            console.print(f"  Total filtered size: {total_filtered_size / (1024**3):.2f} GB")

            # Step 5: Download archive indices FIRST (needed for both install and download files)
            # This is critical - most files are in archives, not loose on CDN
            console.print("\n[cyan]Step 5:[/cyan] Loading/downloading archive indices...")
            console.print("  (Required before extracting any files)")

            archives = cdn_config.archives
            if max_archives > 0:
                archives = archives[:max_archives]
                console.print(f"  [yellow]Warning: Limited to {max_archives} archives[/yellow]")

            fetcher = CdnArchiveFetcher(cdn_base=cdn_base, cdn_path=cdn_path)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Loading indices...", total=len(archives))
                xdg_hits = 0
                local_hits = 0
                downloads = 0

                for archive_hash in archives:
                    progress.update(task, advance=1)

                    # Check XDG cache first
                    xdg_data = cache.get_cdn(archive_hash, "index", cdn_path)
                    if xdg_data:
                        # Found in XDG cache - load into fetcher
                        fetcher.load_index_from_bytes(archive_hash, xdg_data)
                        # Also write to local indices directory
                        local_path = storage.indices_path / f"{archive_hash.lower()}.index"
                        if not local_path.exists():
                            local_path.write_bytes(xdg_data)
                        xdg_hits += 1
                    else:
                        # Not in XDG - use existing method (checks local, downloads if needed)
                        success, data = fetcher.download_index_with_cache(
                            client,
                            archive_hash,
                            cache_dir=storage.indices_path
                        )
                        if success and data:
                            # Cache to XDG for future use
                            cache.put_cdn(archive_hash, data, "index", cdn_path)
                            downloads += 1
                        else:
                            # Check if it was a local hit
                            local_path = storage.indices_path / f"{archive_hash.lower()}.index"
                            if local_path.exists():
                                local_hits += 1

            console.print(f"  Index map: {fetcher.index_map.total_entries:,} entries")
            console.print(f"  Archives: {len(archives)} (XDG: {xdg_hits}, local: {local_hits}, downloaded: {downloads})")

            # Step 6: Process install manifest (executables and DLLs)
            # Now we can fetch files using the archive indices
            install_entries_extracted = 0
            if build_config.install_content_key:
                console.print("\n[cyan]Step 6:[/cyan] Processing install manifest (executables)...")
                install_ckey = bytes.fromhex(build_config.install_content_key)
                install_ekeys = encoding_parser.find_content_key(encoding_data, encoding_file, install_ckey)

                if install_ekeys:
                    install_ekey = install_ekeys[0]
                    console.print(f"  Encoding key: {install_ekey.hex()}")

                    # Try to fetch install manifest from archives first, then loose
                    install_data_raw = fetcher.fetch_file(client, install_ekey, decompress=False)
                    if install_data_raw is None:
                        # Fallback to loose file
                        install_data_raw = fetch_data(client, cdn_base, cdn_path, install_ekey.hex())

                    storage.write_content(install_ekey, install_data_raw)

                    install_data = install_data_raw
                    if is_blte(install_data):
                        install_data = decompress_blte(install_data)

                    install_parser = InstallParser()
                    install_manifest = install_parser.parse(install_data)
                    console.print(f"  Total install entries: {len(install_manifest.entries):,}")

                    # Filter install entries by tags (same logic as download)
                    def filter_install_entries(install_entries, plat, ar, loc):
                        """Filter install entries by platform, arch, locale."""
                        platform_tags = {"Windows", "OSX", "Android", "iOS", "PS5", "Web", "XBSX"}
                        arch_tags = {"x86_32", "x86_64", "arm64"}
                        locale_tags = {"enUS", "deDE", "esES", "esMX", "frFR", "koKR", "ptBR", "ruRU", "zhCN", "zhTW"}

                        filtered = []
                        for entry in install_entries:
                            entry_tags = set(entry.tags)
                            if plat:
                                entry_platform_tags = entry_tags & platform_tags
                                if entry_platform_tags and plat not in entry_platform_tags:
                                    continue
                            if ar:
                                entry_arch_tags = entry_tags & arch_tags
                                if entry_arch_tags and ar not in entry_arch_tags:
                                    continue
                            if loc:
                                entry_locale_tags = entry_tags & locale_tags
                                if entry_locale_tags and loc not in entry_locale_tags:
                                    continue
                            filtered.append(entry)
                        return filtered

                    install_filtered = filter_install_entries(install_manifest.entries, platform, arch, locale)
                    console.print(f"  After tag filtering: {len(install_filtered):,} entries")

                    # Extract install files to filesystem using archive fetcher
                    if install_filtered:
                        console.print(f"  Extracting {len(install_filtered)} files to filesystem...")

                        for inst_entry in install_filtered:
                            # Look up encoding key for this content key
                            file_ekeys = encoding_parser.find_content_key(
                                encoding_data, encoding_file, inst_entry.md5_hash
                            )
                            if not file_ekeys:
                                console.print(f"    [yellow]Skip:[/yellow] {inst_entry.filename} (not in encoding)")
                                continue

                            file_ekey = file_ekeys[0]

                            try:
                                # Try archive fetch first (range request)
                                file_data = fetcher.fetch_file(client, file_ekey, decompress=True)

                                if file_data is None:
                                    # Fallback to loose file download
                                    try:
                                        file_data = fetch_data(client, cdn_base, cdn_path, file_ekey.hex())
                                        if is_blte(file_data):
                                            file_data = decompress_blte(file_data)
                                    except Exception:
                                        console.print(f"    [yellow]Not found:[/yellow] {inst_entry.filename}")
                                        continue

                                # Write to filesystem (normalize Windows paths to Unix)
                                normalized_filename = inst_entry.filename.replace('\\', '/')
                                output_file = install_path / normalized_filename
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
                entries = entries[:max_files]

            console.print(f"\n[cyan]Step 7:[/cyan] Installing {len(entries)} files to local CASC...")

            installed = 0
            failed = 0
            total_bytes = 0

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Installing files...", total=len(entries))

                for entry in entries:
                    progress.update(task, advance=1)

                    # Fetch file from CDN archive (keep BLTE compressed)
                    data = fetcher.fetch_file(client, entry.ekey, decompress=False)

                    if data is None:
                        failed += 1
                        continue

                    # Write to local CASC storage
                    storage.write_content(entry.ekey, data)
                    installed += 1
                    total_bytes += len(data)

            # Step 8: Create .build.info file
            console.print("\n[cyan]Step 8:[/cyan] Creating .build.info file...")

            # Build the .build.info content
            build_info_header = (
                "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|"
                "Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|"
                "CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|"
                "Version!STRING:0|KeyRing!HEX:16|Product!STRING:0"
            )

            # Determine region from CDN base
            region = "us"
            if "eu.cdn" in cdn_base:
                region = "eu"
            elif "kr.cdn" in cdn_base:
                region = "kr"
            elif "cn.cdn" in cdn_base:
                region = "cn"

            # Build tag string for the installed configuration
            tag_string = f"{platform} {arch} {region.upper()}? {locale} speech?:{platform} {arch} {region.upper()}? {locale} text?"

            # Extract version from build name (e.g., "WOW-65300patch1.15.8" -> "1.15.8.65300")
            version_str = ""
            if build_config.build_name:
                import re
                match = re.search(r'(\d+)patch([\d.]+)', build_config.build_name)
                if match:
                    build_id, version = match.groups()
                    version_str = f"{version}.{build_id}"

            # Build the data line
            cdn_hosts = cdn_base.replace("http://", "").replace("https://", "")
            cdn_servers = cdn_base

            # Install key and size (from install manifest if available)
            install_key = ""
            im_size = ""

            build_info_data = (
                f"{region}|1|{build_config_hash}|{cdn_config_hash}|"
                f"{install_key}|{im_size}|{cdn_path}|{cdn_hosts}|"
                f"{cdn_servers}|{tag_string}|||{version_str}||wow_classic_era"
            )

            build_info_content = f"{build_info_header}\n{build_info_data}\n"
            build_info_path = install_path / ".build.info"
            build_info_path.write_text(build_info_content)
            console.print(f"  Created: {build_info_path}")

            # Step 9: Flush index files
            console.print("\n[cyan]Step 9:[/cyan] Writing local index files...")
            storage.flush_indices()

            # Show bucket distribution
            stats = storage.get_statistics()
            console.print(f"  Total entries: {stats['total_entries']:,}")

            bucket_table = Table(title="Bucket Distribution")
            bucket_table.add_column("Bucket", style="cyan")
            bucket_table.add_column("Entries", style="green", justify="right")
            bucket_table.add_column("Size", style="yellow", justify="right")

            for bucket_id, bucket_stats in sorted(stats['buckets'].items()):
                bucket_table.add_row(
                    bucket_id,
                    f"{bucket_stats['count']:,}",
                    f"{bucket_stats['total_size'] / 1024:.1f} KB"
                )

            console.print(bucket_table)

            # Step 10: Generate product state files
            console.print("\n[cyan]Step 10:[/cyan] Generating product state files...")

            # Determine product code from build config
            product_code = build_config.build_product or "wow_classic_era"

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
            summary_table.add_row("Total data written", f"{total_bytes / (1024*1024):.2f} MB")
            summary_table.add_row("Archive indices", f"{len(archives)}")
            summary_table.add_row("State files created", f"{len(state_files)}")
            console.print(summary_table)

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

    except click.ClickException:
        raise
    except Exception as e:
        logger.error("Installation failed", error=str(e))
        raise click.ClickException(f"Installation failed: {e}") from e
