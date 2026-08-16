"""Manage WoW build database from Wago.tools, BlizzTrack, and Ribbit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from cascette_tools.core.config import AppConfig
from cascette_tools.database.wago import WagoBuild

# All products supported across both sync sources.
# See blizztrack.py for why "bts" is excluded.
_ALL_PRODUCTS = [
    "agent",
    "bna",
    "wow",
    "wow_classic",
    "wow_classic_era",
    "wow_classic_titan",
    "wow_anniversary",
]


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract context objects from Click context."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]
    verbose = ctx.obj.get("verbose", False)
    debug = ctx.obj.get("debug", False)
    return config, console, verbose, debug


def regions_for_entry(entries: list[dict[str, Any]], build_config: str) -> str | None:
    """Collect the comma-separated region list for a build config.

    The Ribbit versions manifest has one row per region; all regions
    typically serve the same build config. Returns None when no region
    column is present.

    Args:
        entries: Parsed versions manifest rows.
        build_config: Build config hash to match.

    Returns:
        Comma-separated region codes, or None.
    """
    regions = [
        e.get("Region", "")
        for e in entries
        if e.get("BuildConfig") == build_config and e.get("Region")
    ]
    if not regions:
        return None
    return ",".join(dict.fromkeys(regions))


@click.group("builds", short_help="Manage build database.")
def builds_group() -> None:
    """Manage build database from Wago.tools, BlizzTrack, and Ribbit.

    Syncs build metadata from three sources:

    - Wago.tools: WoW product family (wow, wow_classic, wow_classic_era,
      wow_classic_titan, wow_anniversary) with decoded manifest EKEYs.
    - BlizzTrack: All TACT products including agent and bna. Covers
      current versions and archived seqn history.
    - Ribbit: Current live versions directly from Blizzard's TACT
      endpoints for all supported products.

    All sources write into the same SQLite database; duplicates are
    resolved on import using (product, build, build_config) as the
    unique key.
    """
    pass


_RIBBIT_PRODUCTS = [
    "agent",
    "bna",
    "wow",
    "wow_classic",
    "wow_classic_era",
    "wow_classic_titan",
    "wow_anniversary",
]


def _fetch_ribbit_builds(
    config: AppConfig, console: Console, verbose: bool
) -> list[WagoBuild]:
    """Fetch current live builds from Blizzard's TACT HTTPS v2 endpoints.

    Queries the Ribbit versions endpoint for each product and returns
    one WagoBuild per product (deduplicated across regions, since all
    regions serve the same build).
    """
    from cascette_tools.core.tact import TACTClient
    from cascette_tools.core.types import Product

    region = config.default_region or "us"
    client = TACTClient(region=region)
    builds: list[WagoBuild] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching from Ribbit...", total=len(_RIBBIT_PRODUCTS))

        for product_code in _RIBBIT_PRODUCTS:
            progress.update(task, description=f"Ribbit: {product_code}")
            try:
                product_enum = Product(product_code)
                manifest = client.fetch_versions(product_enum)
                entries = client.parse_versions(manifest)

                # Deduplicate: all regions typically serve the same build.
                # Use the first entry (usually 'us') and skip duplicates
                # by BuildConfig.
                seen_configs: set[str] = set()
                manifest_seqn = client.extract_seqn(manifest)
                for entry in entries:
                    build_config = entry.get("BuildConfig", "")
                    if not build_config or build_config in seen_configs:
                        continue
                    seen_configs.add(build_config)

                    build_id = entry.get("BuildId", "")
                    version = entry.get("VersionsName", "")

                    if not build_id or not version:
                        continue

                    build = WagoBuild(
                        id=int(build_id) if build_id.isdigit() else 0,
                        build=build_id,
                        version=version,
                        product=product_code,
                        build_config=build_config,
                        cdn_config=entry.get("CDNConfig") or None,
                        product_config=entry.get("ProductConfig") or None,
                        keyring=entry.get("KeyRing") or None,
                        regions=regions_for_entry(entries, build_config),
                        seqn=manifest_seqn,
                    )
                    builds.append(build)
                    if verbose:
                        console.print(
                            f"[dim]  {product_code}: {version} "
                            f"(bc={build_config[:12]}...)[/dim]"
                        )

            except Exception as e:
                console.print(
                    f"[yellow]Warning: Failed to fetch {product_code} from Ribbit: {e}[/yellow]"
                )

            progress.advance(task)

        progress.update(task, description=f"Ribbit: {len(builds)} builds fetched")

    return builds


@builds_group.command("sync")
@click.option(
    "--source",
    "-s",
    type=click.Choice(["wago", "blizztrack", "ribbit", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Data source to sync from.",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force refresh even if Wago cache is still valid.",
)
@click.option(
    "--history",
    is_flag=True,
    help="Fetch full snapshot history from BlizzTrack (slow, walks all seqns).",
)
@click.option(
    "--show-stats",
    is_flag=True,
    help="Show per-product import statistics after syncing.",
)
@click.pass_context
def sync_builds(
    ctx: click.Context,
    source: str,
    force: bool,
    history: bool,
    show_stats: bool,
) -> None:
    """Sync build database from Wago.tools, BlizzTrack, and/or Ribbit.

    By default syncs from all three sources and deduplicates on import.

    Wago.tools covers WoW products (wow, wow_classic, wow_classic_era,
    wow_classic_titan, wow_anniversary) with decoded metadata.

    BlizzTrack covers all TACT products including agent and bna. Use
    --history to also walk archived seqn snapshots (makes one HTTP
    request per historical snapshot — can be several hundred requests).

    Ribbit fetches current live versions directly from Blizzard's TACT
    HTTPS v2 endpoints for all supported products. Always returns the
    latest single build per product per region.
    """
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    all_builds: list[WagoBuild] = []

    try:
        # --- Wago.tools ---
        if source in ("wago", "all"):
            from cascette_tools.database.wago import WagoClient

            with WagoClient(config_obj) as wago:
                if not force:
                    status = wago.get_cache_status()
                    if status["valid"]:
                        console.print(
                            f"[yellow]Wago cache valid — fetched {status['fetch_time']}, "
                            f"expires in {status['remaining_hours']:.1f} hours[/yellow]"
                        )

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task("Fetching from Wago.tools...", total=None)
                    wago_builds = wago.fetch_builds(force_refresh=force)
                    progress.update(
                        task,
                        description=f"Wago.tools: {len(wago_builds)} builds fetched",
                    )

                all_builds.extend(wago_builds)

                if verbose:
                    console.print(f"[dim]Wago.tools: {len(wago_builds)} builds[/dim]")

        # --- BlizzTrack ---
        if source in ("blizztrack", "all"):
            from cascette_tools.database.blizztrack import BlizzTrackClient

            with BlizzTrackClient(config_obj) as bt:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    if history:
                        task = progress.add_task(
                            "Fetching history from BlizzTrack (this may take a while)...",
                            total=None,
                        )
                        bt_builds = bt.fetch_history()
                    else:
                        task = progress.add_task(
                            "Fetching current versions from BlizzTrack...", total=None
                        )
                        bt_builds = bt.fetch_current()

                    progress.update(
                        task,
                        description=f"BlizzTrack: {len(bt_builds)} builds fetched",
                    )

                all_builds.extend(bt_builds)

                if verbose:
                    console.print(f"[dim]BlizzTrack: {len(bt_builds)} builds[/dim]")

        # --- Ribbit (TACT HTTPS v2) ---
        if source in ("ribbit", "all"):
            ribbit_builds = _fetch_ribbit_builds(config_obj, console, verbose)
            all_builds.extend(ribbit_builds)

        if not all_builds:
            console.print("[yellow]No builds fetched.[/yellow]")
            return

        # --- Import to database (deduplication happens in import_builds_to_database) ---
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            console.print(
                f"\n[cyan]Importing {len(all_builds)} builds to database...[/cyan]"
            )
            import_stats = wago.import_builds_to_database(all_builds)

        # --- Summary table ---
        by_product: dict[str, list[WagoBuild]] = {}
        for build in all_builds:
            by_product.setdefault(build.product, []).append(build)

        table = Table(title="Sync Summary", show_header=True)
        table.add_column("Product", style="cyan")
        table.add_column("Fetched", justify="right", style="green")
        table.add_column("Version Range", style="yellow")

        for product, product_builds in sorted(by_product.items()):
            versions: list[str] = sorted(
                {b.version for b in product_builds if b.version}
            )
            version_range = (
                f"{versions[0]} – {versions[-1]}"
                if len(versions) > 1
                else (versions[0] if versions else "N/A")
            )
            table.add_row(product, str(len(product_builds)), version_range)

        console.print(table)
        console.print(f"\n[green]Total fetched: {len(all_builds)}[/green]")

        if show_stats or verbose:
            console.print(
                f"[green]  Imported (new): {import_stats['imported']}[/green]"
            )
            console.print(
                f"[yellow]  Updated:        {import_stats['updated']}[/yellow]"
            )
            console.print(f"[dim]  Skipped:        {import_stats['skipped']}[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("list")
@click.option(
    "--product",
    "-p",
    type=click.Choice(_ALL_PRODUCTS, case_sensitive=False),
    help="Filter by product",
)
@click.option(
    "--version",
    "-v",
    help="Filter by version (supports wildcards, e.g., '11.0.*')",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=20,
    help="Maximum number of builds to display",
)
@click.option(
    "--all",
    "-a",
    is_flag=True,
    help="Show all builds (overrides limit)",
)
@click.pass_context
def list_builds(
    ctx: click.Context,
    product: str | None,
    version: str | None,
    limit: int,
    all: bool,
) -> None:
    """List builds in the database."""
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            builds = wago.list_builds(product=product, version=version)

            if not builds:
                console.print("[yellow]No builds found matching criteria[/yellow]")
                return

            total = len(builds)

            # Apply limit unless --all is specified
            if not all and total > limit:
                console.print(
                    f"[dim]Showing {limit} of {total} builds (use --all to see all)[/dim]\n"
                )
                builds = builds[:limit]
            else:
                console.print(
                    f"[dim]Showing {len(builds)} of {total} builds (use --all to see all)[/dim]\n"
                )

            # Create table — keep it narrow by default, show hashes only in verbose mode
            table = Table(title="WoW Builds", show_header=True)
            table.add_column("Product", style="green", min_width=8)
            table.add_column("Version", style="yellow", min_width=14)
            table.add_column("Build", style="magenta", justify="right", min_width=6)
            table.add_column("Created", style="blue", min_width=10)

            if verbose:
                table.add_column("Build Config", style="dim", no_wrap=True)
                table.add_column("CDN Config", style="dim", no_wrap=True)
                table.add_column("Product Config", style="dim", no_wrap=True)

            for build in builds:
                row = [
                    build.product,
                    build.version or "N/A",
                    build.build or "N/A",
                    build.build_time.strftime("%Y-%m-%d")
                    if build.build_time
                    else "N/A",
                ]

                if verbose:
                    row.append(build.build_config or "N/A")
                    row.append(build.cdn_config or "N/A")
                    row.append(build.product_config or "N/A")

                table.add_row(*row)

            console.print(table)
            console.print(f"\n[green]Total: {total} builds[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("search")
@click.argument("query", required=True)
@click.option(
    "--field",
    "-f",
    type=click.Choice(
        ["version", "build", "config", "branch", "all"], case_sensitive=False
    ),
    default="all",
    help="Field to search in",
)
@click.option("--verbose", "-v", is_flag=True, help="Show build/CDN config hashes")
@click.pass_context
def search_builds(
    ctx: click.Context,
    query: str,
    field: str,
    verbose: bool,
) -> None:
    """Search for builds matching a query."""
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            builds = wago.search_builds(query, field=field)

            if not builds:
                console.print(f"[yellow]No builds found matching '{query}'[/yellow]")
                return

            # Create results table
            table = Table(title=f"Search Results for '{query}'", show_header=True)
            table.add_column("Product", style="green", min_width=8)
            table.add_column("Version", style="yellow", min_width=14)
            table.add_column("Build", style="magenta", justify="right", min_width=6)
            table.add_column("Created", style="dim", min_width=10)
            if verbose:
                table.add_column("Build Config", style="dim", no_wrap=True)
                table.add_column("CDN Config", style="dim", no_wrap=True)

            for build in builds:
                created = (
                    build.build_time.strftime("%Y-%m-%d") if build.build_time else "N/A"
                )
                row = [
                    build.product,
                    build.version or "N/A",
                    build.build or "N/A",
                    created,
                ]
                if verbose:
                    row += [
                        build.build_config or "N/A",
                        build.cdn_config or "N/A",
                    ]
                table.add_row(*row)

            console.print(table)
            console.print(f"\n[green]Found {len(builds)} matching builds[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("stats")
@click.pass_context
def builds_stats(ctx: click.Context) -> None:
    """Show build database statistics."""
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            stats = wago.get_build_stats()

            # Overall statistics
            console.print("[bold]Build Database Statistics[/bold]\n")
            console.print(f"Total builds: [green]{stats['total_builds']}[/green]")
            console.print(f"Products: [cyan]{stats['product_count']}[/cyan]")
            console.print(f"Unique versions: [yellow]{stats['version_count']}[/yellow]")
            console.print(f"Date range: [magenta]{stats['date_range']}[/magenta]")

            # Cache status
            cache_status = wago.get_cache_status()
            if cache_status["valid"]:
                console.print("\nCache status: [green]Valid[/green]")
                console.print(f"Last updated: {cache_status['fetch_time']}")
                console.print(
                    f"Expires in: {cache_status['remaining_hours']:.1f} hours"
                )
            else:
                console.print("\nCache status: [yellow]Expired or not present[/yellow]")

            # Product breakdown
            if verbose and stats.get("by_product"):
                console.print("\n[bold]Builds by Product:[/bold]")
                product_table = Table(show_header=True, header_style="bold")
                product_table.add_column("Product")
                product_table.add_column("Count", justify="right")
                product_table.add_column("Percentage", justify="right")

                for product, count in stats["by_product"].items():
                    percentage = (count / stats["total_builds"]) * 100
                    product_table.add_row(product, str(count), f"{percentage:.1f}%")

                console.print(product_table)

            # Version breakdown
            if verbose and stats.get("by_major_version"):
                console.print("\n[bold]Builds by Major Version:[/bold]")
                version_table = Table(show_header=True, header_style="bold")
                version_table.add_column("Version")
                version_table.add_column("Count", justify="right")

                for version, count in sorted(stats["by_major_version"].items()):
                    version_table.add_row(version, str(count))

                console.print(version_table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("export")
@click.argument("output", type=click.Path(path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv"], case_sensitive=False),
    default="json",
    help="Export format",
)
@click.option(
    "--product",
    "-p",
    type=click.Choice(_ALL_PRODUCTS, case_sensitive=False),
    help="Filter by product",
)
@click.pass_context
def export_builds(
    ctx: click.Context,
    output: Path,
    format: str,
    product: str | None,
) -> None:
    """Export build database to file."""
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            builds = wago.list_builds(product=product)

            if not builds:
                console.print("[yellow]No builds found to export[/yellow]")
                return

            if format == "json":
                # Convert builds to dict for JSON serialization
                build_data = [
                    {
                        "id": b.id,
                        "product": b.product,
                        "version": b.version,
                        "build": b.build,
                        "build_config": b.build_config,
                        "cdn_config": b.cdn_config,
                        "product_config": b.product_config,
                        "build_time": b.build_time.isoformat()
                        if b.build_time
                        else None,
                        "encoding_ekey": b.encoding_ekey,
                        "root_ekey": b.root_ekey,
                        "install_ekey": b.install_ekey,
                        "download_ekey": b.download_ekey,
                    }
                    for b in builds
                ]

                with open(output, "w") as f:
                    json.dump(build_data, f, indent=2, default=str)

            elif format == "csv":
                import csv

                with open(output, "w", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=[
                            "id",
                            "product",
                            "version",
                            "build",
                            "build_config",
                            "cdn_config",
                            "product_config",
                            "build_time",
                            "encoding_ekey",
                            "root_ekey",
                        ],
                    )
                    writer.writeheader()

                    for build in builds:
                        writer.writerow(
                            {
                                "id": build.id,
                                "product": build.product,
                                "version": build.version,
                                "build": build.build,
                                "build_config": build.build_config,
                                "cdn_config": build.cdn_config,
                                "product_config": build.product_config,
                                "build_time": build.build_time.isoformat()
                                if build.build_time
                                else None,
                                "encoding_ekey": build.encoding_ekey,
                                "root_ekey": build.root_ekey,
                            }
                        )

            console.print(f"[green]Exported {len(builds)} builds to {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("import")
@click.argument("input", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv"], case_sensitive=False),
    help="Import format (auto-detected if not specified)",
)
@click.pass_context
def import_builds(
    ctx: click.Context,
    input: Path,
    format: str | None,
) -> None:
    """Import builds from file to database."""
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        # Auto-detect format if not specified
        if not format:
            if input.suffix.lower() == ".json":
                format = "json"
            elif input.suffix.lower() == ".csv":
                format = "csv"
            else:
                console.print(
                    "[red]Cannot auto-detect format. Please specify --format[/red]"
                )
                raise click.Abort()

        builds: list[WagoBuild] = []

        if format == "json":
            with open(input) as f:
                data = json.load(f)
                for item in data:
                    builds.append(WagoBuild(**item))

        elif format == "csv":
            import csv

            with open(input) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Create clean data dict with only expected fields
                    build_data: dict[str, Any] = {}

                    # Required fields
                    if "id" in row and row["id"]:
                        build_data["id"] = int(str(row["id"]))
                    if "build" in row:
                        build_data["build"] = str(row["build"])
                    if "version" in row:
                        build_data["version"] = str(row["version"])
                    if "product" in row:
                        build_data["product"] = str(row["product"])

                    # Optional fields
                    if "build_time" in row and row["build_time"]:
                        from datetime import datetime

                        build_data["build_time"] = datetime.fromisoformat(
                            str(row["build_time"])
                        )

                    # Optional config fields
                    for field in [
                        "build_config",
                        "cdn_config",
                        "product_config",
                        "encoding_ekey",
                        "root_ekey",
                        "install_ekey",
                        "download_ekey",
                    ]:
                        if field in row and row[field]:
                            build_data[field] = str(row[field])

                    builds.append(WagoBuild(**build_data))

        if not builds:
            console.print("[yellow]No builds found in file[/yellow]")
            return

        # Import to database
        with WagoClient(config_obj) as wago:
            console.print(f"[cyan]Importing {len(builds)} builds to database...[/cyan]")
            stats = wago.import_builds_to_database(builds)

            console.print(f"[green]Imported {stats['imported']} new builds[/green]")
            console.print(
                f"[yellow]Updated {stats['updated']} existing builds[/yellow]"
            )
            console.print(f"[dim]Skipped {stats['skipped']} unchanged builds[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("add")
@click.option(
    "--product",
    "-p",
    required=True,
    type=click.Choice(_ALL_PRODUCTS, case_sensitive=False),
    help="Product code.",
)
@click.option(
    "--version",
    "-v",
    required=True,
    help="Full version string (e.g. 10.1.5.50793).",
)
@click.option(
    "--build-config",
    default=None,
    help="Build config hash (40 hex chars).",
)
@click.option(
    "--cdn-config",
    default=None,
    help="CDN config hash (40 hex chars).",
)
@click.option(
    "--product-config",
    default=None,
    help="Product config hash (40 hex chars).",
)
@click.option(
    "--encoding-ekey",
    default=None,
    help="Encoding manifest EKey.",
)
@click.option(
    "--root-ekey",
    default=None,
    help="Root manifest EKey.",
)
@click.option(
    "--install-ekey",
    default=None,
    help="Install manifest EKey.",
)
@click.option(
    "--download-ekey",
    default=None,
    help="Download manifest EKey.",
)
@click.option(
    "--build-time",
    default=None,
    help="Build timestamp (ISO 8601, e.g. 2023-07-11T00:00:00Z).",
)
@click.pass_context
def add_build(
    ctx: click.Context,
    product: str,
    version: str,
    build_config: str | None,
    cdn_config: str | None,
    product_config: str | None,
    encoding_ekey: str | None,
    root_ekey: str | None,
    install_ekey: str | None,
    download_ekey: str | None,
    build_time: str | None,
) -> None:
    """Manually add a build entry to the database.

    The build number is extracted from the version string (last component).
    The build ID is auto-generated from build_config + product when a
    build_config is provided, otherwise from a hash of the version string.

    \b
    Examples:
      cascette builds add -p wow -v 10.1.5.50793
      cascette builds add -p wow -v 10.1.5.50793 \\
        --build-config abc123... --cdn-config def456...
      cascette builds add -p wow_classic_era -v 1.14.1.41009 \\
        --build-time 2022-03-15T00:00:00Z
    """
    import hashlib
    from datetime import datetime as dt

    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        # Extract build number from version string
        parts = version.split(".")
        if len(parts) < 2:
            console.print(
                "[red]Version must have at least two components "
                "(e.g. 10.1.5.50793)[/red]"
            )
            raise click.Abort()

        build_number = parts[-1]

        # Auto-generate stable ID (same algorithm as blizztrack.py)
        if build_config:
            key = f"{build_config}_{product}"
        else:
            key = f"{version}_{product}"
        build_id = int(hashlib.md5(key.encode()).hexdigest()[:8], 16)

        # Parse build time if provided
        parsed_time = None
        if build_time:
            parsed_time = dt.fromisoformat(build_time.replace("Z", "+00:00"))

        build = WagoBuild(
            id=build_id,
            build=build_number,
            version=version,
            product=product,
            build_time=parsed_time,
            build_config=build_config,
            cdn_config=cdn_config,
            product_config=product_config,
            encoding_ekey=encoding_ekey,
            root_ekey=root_ekey,
            install_ekey=install_ekey,
            download_ekey=download_ekey,
        )

        with WagoClient(config_obj) as wago:
            stats = wago.import_builds_to_database([build])

            if stats["imported"] > 0:
                console.print(f"[green]Added {version} ({product})[/green]")
            elif stats["updated"] > 0:
                console.print(f"[yellow]Updated {version} ({product})[/yellow]")
            else:
                console.print(
                    f"[dim]Build {version} ({product}) already exists unchanged[/dim]"
                )

            console.print(f"  ID: {build_id}")
            if build_config:
                console.print(f"  Build config: {build_config}")
            if cdn_config:
                console.print(f"  CDN config: {cdn_config}")

    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("ribbit-files")
@click.argument("product", type=click.Choice(_ALL_PRODUCTS, case_sensitive=False))
@click.argument("build", type=str)
@click.option(
    "--version",
    "-v",
    default=None,
    help="Full version string to match (alternative to BUILD for lookup).",
)
@click.option(
    "--regions",
    default="us,eu,kr,tw,cn",
    show_default=True,
    help="Comma-separated regions to emit in the versions/cdns replies.",
)
@click.option(
    "--host",
    default="localhost:8000",
    show_default=True,
    help="Host:port rewritten into the cdns Hosts/Servers fields.",
)
@click.option(
    "--cdn-path",
    default="tpr/wow",
    show_default=True,
    help="CDN path for the product (cdns Path column).",
)
@click.option(
    "--config-path",
    default="tpr/configs/data",
    show_default=True,
    help="Config path (cdns ConfigPath column).",
)
@click.option(
    "--seqn",
    type=int,
    default=None,
    help="Override the seqn value (default: from DB or 9999999 when absent).",
)
@click.option(
    "--out-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Write versions/cdns files into this directory. Without it, prints both to stdout.",
)
@click.pass_context
def ribbit_files(
    ctx: click.Context,
    product: str,
    build: str,
    version: str | None,
    regions: str,
    host: str,
    cdn_path: str,
    config_path: str,
    seqn: int | None,
    out_dir: Path | None,
) -> None:
    """Generate simulated Ribbit versions/cdns replies for a build.

    Builds the BPSV documents the wow client and cascette tooling expect
    from the version/CDN manifest endpoints, using the build database as
    the source of truth. This replaces the Arctium archive fetch used by
    tools/setup_local_ribbit.sh, which does not carry versions files for
    historical builds.

    The cdns reply rewrites every Hosts entry to --host and every Servers
    URL to http://--host, matching setup_local_ribbit.sh.

    \b
    Examples:
      cascette builds ribbit-files wow_classic 31650
      cascette builds ribbit-files wow_classic 31650 \\
        --host localhost:8000 --out-dir ./mirror/tpr/wow
      cascette builds ribbit-files wow_classic 31650 \\
        --host tactic.wowemu.dev --cdn-path tpr/wow
    """
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            builds = wago.list_builds(product=product)
            if not builds:
                console.print(f"[red]No builds found for {product}[/red]")
                raise click.Abort()

            match: WagoBuild | None = None
            for b in builds:
                if b.build == build or (version and b.version == version):
                    match = b
                    break
            if match is None:
                console.print(
                    f"[red]Build {build} not found for {product} "
                    f"(got {len(builds)} builds)[/red]"
                )
                raise click.Abort()

        build_config = match.build_config or ""
        cdn_config = match.cdn_config or ""
        versions_name = match.version or f"{build}.0.0.0"
        build_id = match.build or build
        keyring = match.keyring or ""
        product_config = match.product_config or ""
        seqn_value = seqn or match.seqn or 9999999

        region_list = [r.strip() for r in regions.split(",") if r.strip()]
        if not region_list:
            console.print("[red]No regions provided[/red]")
            raise click.Abort()

        # --- versions BPSV ---
        # Type tags are case-sensitive: STRING / DEC / HEX. "String:0" for
        # VersionsName is a fatal assert in the client's FormatHeader.
        versions_header = (
            "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|"
            "KeyRing!HEX:16|BuildId!DEC:4|VersionsName!STRING:0|"
            "ProductConfig!HEX:16"
        )
        versions_lines = [versions_header, f"## seqn = {seqn_value}"]
        for region in region_list:
            versions_lines.append(
                "|".join(
                    [
                        region,
                        build_config,
                        cdn_config,
                        keyring,
                        build_id,
                        versions_name,
                        product_config,
                    ]
                )
            )
        versions_text = "\n".join(versions_lines) + "\n"

        # --- cdns BPSV ---
        cdns_header = (
            "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0|"
            "ConfigPath!STRING:0"
        )
        cdns_lines = [cdns_header, f"## seqn = {seqn_value}"]
        for region in region_list:
            cdns_lines.append(
                "|".join([region, cdn_path, host, f"http://{host}", config_path])
            )
        cdns_text = "\n".join(cdns_lines) + "\n"

        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            versions_path = out_dir / "versions"
            cdns_path = out_dir / "cdns"
            versions_path.write_text(versions_text)
            cdns_path.write_text(cdns_text)
            console.print(f"[green]Wrote {versions_path}[/green]")
            console.print(f"[green]Wrote {cdns_path}[/green]")
            console.print(f"  Product: {product}, Build: {build}, seqn: {seqn_value}")
            console.print(f"  Regions: {', '.join(region_list)}")
            console.print(f"  CDN host: {host}, path: {cdn_path}")
            console.print("  Verify with:")
            console.print(f"    curl -s http://{host}/{cdn_path}/versions")
            console.print(f"    curl -s http://{host}/{cdn_path}/cdns")
        else:
            console.print(versions_text)
            console.print(cdns_text)

    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("scan-formats")
@click.argument("build_config", type=str)
@click.argument("cdn_config", type=str)
@click.option(
    "--product",
    "-r",
    type=click.Choice(_ALL_PRODUCTS, case_sensitive=False),
    default="wow_classic",
    help="Product code for CDN path (default: wow_classic).",
)
@click.option(
    "--region",
    type=click.Choice(["us", "eu", "kr", "tw", "cn"]),
    default="us",
    help="CDN region (default: us).",
)
@click.option(
    "--build",
    type=str,
    default=None,
    help="Build number to record (default: derived from build config via DB lookup).",
)
@click.option(
    "--install-path",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Local install path to also scan for container-side formats.",
)
@click.pass_context
def scan_formats(
    ctx: click.Context,
    build_config: str,
    cdn_config: str,
    product: str,
    region: str,
    build: str | None,
    install_path: Path | None,
) -> None:
    """Detect and record a build's file-format versions.

    Fetches the build's manifests from CDN (root, install, download, size,
    encoding, archive index) and records their format versions. When
    --install-path is given, also scans the local CAS container (idx,
    local headers, segment headers, shmem).

    Examples:
      cascette builds scan-formats 2c9159a... c54b41b... --product wow_classic
      cascette builds scan-formats 2c9159a... c54b41b... \\
        --install-path ~/Downloads/wow_classic/1.13.2.31650.windows-win64
    """
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.core.types import Product as ProductEnum
        from cascette_tools.database.build_formats import (
            detect_cdn_formats,
            detect_container_formats,
        )
        from cascette_tools.database.wago import WagoClient

        product_enum = ProductEnum(product)

        # Resolve build number if not given: query the DB by build config
        build_number = build
        if build_number is None:
            with WagoClient(config_obj) as wago:
                rows = wago.get_database_builds(product=product, limit=2000)
                match = next((r for r in rows if r.build_config == build_config), None)
                if match is not None:
                    build_number = str(match.build)
                    console.print(
                        f"  Build number from DB: {build_number} "
                        f"(product {match.product})"
                    )
            if build_number is None:
                console.print(
                    "[yellow]No build number given and not found in DB; "
                    "recording with build_config only.[/yellow]"
                )
                build_number = "unknown"

        console.print(f"Scanning CDN formats for build config {build_config}...")
        fmts = detect_cdn_formats(
            build_config, cdn_config, product=product_enum, region=region
        )

        # Container-side scan
        if install_path:
            console.print(f"Scanning container formats at {install_path}...")
            cont = detect_container_formats(str(install_path))
            fmts.idx_version = cont.idx_version
            fmts.local_header_version = cont.local_header_version
            fmts.segment_header_bytes = cont.segment_header_bytes
            fmts.shmem_version = cont.shmem_version
            fmts.warnings.extend(cont.warnings)
            source = "container"
        else:
            source = "cdn"

        # Show what was detected
        table = Table(title=f"Format Versions — build {build_number} ({product})")
        table.add_column("Format", style="cyan")
        table.add_column("Version", style="green")
        for key, label in [
            ("root_version", "Root manifest (TVFS)"),
            ("install_version", "Install manifest"),
            ("download_version", "Download manifest"),
            ("size_version", "Size manifest"),
            ("encoding_version", "Encoding file"),
            ("archive_index_version", "CDN archive index footer"),
            ("blte_magic", "BLTE magic"),
            ("idx_version", "Local KMT idx"),
            ("local_header_version", "Local file header"),
            ("segment_header_bytes", "Segment header"),
            ("shmem_version", "shmem protocol"),
        ]:
            table.add_row(label, str(getattr(fmts, key) or "-"))
        console.print(table)
        for w in fmts.warnings:
            console.print(f"  [yellow]warn: {w}[/yellow]")

        # Persist
        with WagoClient(config_obj) as wago:
            inserted = wago.upsert_build_formats(
                product,
                build_number,
                build_config,
                root_version=fmts.root_version,
                install_version=fmts.install_version,
                download_version=fmts.download_version,
                size_version=fmts.size_version,
                encoding_version=fmts.encoding_version,
                archive_index_version=fmts.archive_index_version,
                blte_magic=fmts.blte_magic,
                idx_version=fmts.idx_version,
                local_header_version=fmts.local_header_version,
                segment_header_bytes=fmts.segment_header_bytes,
                shmem_version=fmts.shmem_version,
                source=source,
            )
            action = "inserted" if inserted else "updated"
            console.print(f"[green]Recorded format versions ({action})[/green]")
    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("formats")
@click.option(
    "--product",
    type=click.Choice(_ALL_PRODUCTS, case_sensitive=False),
    default=None,
    help="Filter by product.",
)
@click.option(
    "--build",
    type=str,
    default=None,
    help="Filter by build number.",
)
@click.pass_context
def list_formats(ctx: click.Context, product: str | None, build: str | None) -> None:
    """List recorded per-build file-format versions.

    Shows the format versions recorded by `scan-formats` for each build,
    making branch drift (1.13 / 1.14 / 1.15) visible.
    """
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            rows = wago.get_build_formats(product=product, build=build)

        if not rows:
            console.print(
                "[dim]No format records found. Run 'builds scan-formats'.[/dim]"
            )
            return

        table = Table(title="Build Format Versions")
        table.add_column("Build", style="cyan")
        table.add_column("Product", style="green")
        table.add_column("Root", justify="right")
        table.add_column("Install", justify="right")
        table.add_column("Dl", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Enc", justify="right")
        table.add_column("Idx", justify="right")
        table.add_column("CDN-idx", justify="right")
        table.add_column("Shmem", justify="right")
        table.add_column("Source", style="dim")
        for r in rows:
            table.add_row(
                r["build"],
                r["product"],
                str(r.get("root_version") or "-"),
                str(r.get("install_version") or "-"),
                str(r.get("download_version") or "-"),
                str(r.get("size_version") or "-"),
                str(r.get("encoding_version") or "-"),
                str(r.get("idx_version") or "-"),
                str(r.get("archive_index_version") or "-"),
                str(r.get("shmem_version") or "-"),
                r.get("source") or "-",
            )
        console.print(table)
    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("export-ribbit")
@click.option(
    "--mirror-root",
    type=click.Path(path_type=Path),
    required=True,
    help="Local mirror root (the tree the range HTTP server serves).",
)
@click.option(
    "--host",
    default="localhost:8000",
    show_default=True,
    help="Host:port to rewrite CDN hosts/servers to.",
)
@click.option(
    "--product-path",
    default="tpr/wow",
    show_default=True,
    help="CDN product path under the mirror root (e.g. tpr/wow).",
)
@click.option(
    "--region",
    multiple=True,
    default=["us", "eu", "kr", "tw", "cn"],
    show_default=True,
    help="Regions to emit rows for (repeatable).",
)
@click.pass_context
def export_ribbit(
    ctx: click.Context,
    mirror_root: Path,
    host: str,
    product_path: str,
    region: tuple[str, ...],
) -> None:
    """Generate local versions/cdns fake endpoints from the builds DB.

    Writes <mirror-root>/<product-path>/versions and .../cdns as Ribbit v2
    BPSV files, listing every build in the builds DB that has both a build
    config and a CDN config. The wow client scans the versions file for its
    own version string, and the agent takes the first 'us' row, so a single
    file covering all builds serves any patched client. The cdns file
    rewrites every Hosts/Servers entry to --host.

    This replaces per-build Arctium fetching (tools/setup_local_ribbit.sh):
    the DB already holds the hashes the mirror needs.
    """
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        products = ["wow_classic", "wow_classic_era"]
        builds: list[tuple[str, str, str, str]] = []  # (build, bcfg, ccfg, version)
        with WagoClient(config_obj) as wago:
            seen: set[tuple[str, str]] = set()
            for product in products:
                for r in wago.get_database_builds(product=product, limit=100000):
                    if not r.build_config or not r.cdn_config:
                        continue
                    key = (r.build, r.build_config)
                    if key in seen:
                        continue
                    seen.add(key)
                    builds.append((r.build, r.build_config, r.cdn_config, r.version))

        builds.sort(key=lambda b: int(b[0]) if b[0].isdigit() else 0, reverse=True)

        target = mirror_root / product_path
        target.mkdir(parents=True, exist_ok=True)

        # versions BPSV
        versions_lines = [
            "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|KeyRing!HEX:16|"
            "BuildId!DEC:4|VersionsName!STRING:0|ProductConfig!HEX:16",
            "## seqn = 9999999",
        ]
        for build, bcfg, ccfg, version in builds:
            for r in region:
                versions_lines.append(f"{r}|{bcfg}|{ccfg}||{build}|{version}|")
        (target / "versions").write_text("\n".join(versions_lines) + "\n")

        # cdns BPSV
        cdns_lines = [
            "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0|"
            "ConfigPath!STRING:0",
            "## seqn = 9999999",
        ]
        for r in region:
            cdns_lines.append(
                f"{r}|{product_path}|{host}|http://{host}|tpr/configs/data"
            )
        (target / "cdns").write_text("\n".join(cdns_lines) + "\n")

        console.print(
            f"[green]Wrote[/green] {len(builds)} builds to {target / 'versions'} "
            f"({len(region)} regions each)"
        )
        console.print(f"[green]Wrote[/green] {target / 'cdns'}")
    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@builds_group.command("archive-pristine")
@click.argument("install_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--archive-root",
    type=click.Path(path_type=Path),
    default=Path.home() / "Downloads" / "battle.net" / "wow_classic",
    show_default=True,
    help="Archive root for pristine installs (version dirs live directly under it).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Replace an existing archived build of the same version.",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Skip the CDN pristine check (exe sha256 vs CDN-extracted).",
)
@click.pass_context
def archive_pristine(
    ctx: click.Context,
    install_path: Path,
    archive_root: Path,
    force: bool,
    skip_verify: bool,
) -> None:
    """Verify a build is pristine and archive it for examination.

    Reads .build.info from the install, verifies the game executable
    (Wow.exe or WowClassic.exe) sha256 against the CDN-extracted
    executable (unless --skip-verify), detects OS/ARCH from
    the binary via `file`, and moves the install to
    <archive-root>/<version>.<os>-<arch>.

    The prefix (patched copy) is NOT archived; only the pristine source
    install. An existing target of the same version is an error unless
    --force.
    """
    config_obj, console, _, debug = _get_context_objects(ctx)

    try:
        import hashlib
        import shutil
        import subprocess

        from cascette_tools.core.cdn import CDNClient
        from cascette_tools.core.types import Product
        from cascette_tools.formats.blte import decompress_blte, is_blte
        from cascette_tools.formats.build_info import BuildInfoParser
        from cascette_tools.formats.config import BuildConfigParser
        from cascette_tools.formats.encoding import EncodingParser
        from cascette_tools.formats.install import InstallParser

        # 1. Read .build.info
        bi_path = install_path / ".build.info"
        if not bi_path.exists():
            console.print(f"[red].build.info not found in {install_path}[/red]")
            raise click.Abort()
        bi = BuildInfoParser().parse_file(str(bi_path))
        version = bi.version
        product = bi.product
        if not version or not product:
            console.print("[red].build.info missing version or product[/red]")
            raise click.Abort()
        console.print(f"  Build: {version} ({product})")

        # 2. Locate the game executable (product subfolder). 1.13.2 ships
        # Wow.exe; 1.13.3+ renamed it to WowClassic.exe. Check both.
        subdir = "_classic_era_" if product == "wow_classic_era" else "_classic_"
        exe = None
        for exe_name in ("Wow.exe", "WowClassic.exe"):
            cand = install_path / subdir / exe_name
            if cand.exists():
                exe = cand
                break
        if exe is None:
            console.print(
                f"[red]Wow.exe / WowClassic.exe not found in {install_path}/{subdir}[/red]"
            )
            raise click.Abort()

        # 3. Pristine check: compare sha256 against CDN-extracted Wow.exe
        if not skip_verify:
            try:
                from cascette_tools.database.wago import WagoClient

                local_sha = hashlib.sha256(exe.read_bytes()).hexdigest()
                product_enum = Product(product)
                cdn = CDNClient(product_enum)
                with WagoClient(config_obj) as wago:
                    rows = wago.get_database_builds(product=product, limit=100000)
                    row = next((r for r in rows if r.version == version), None)
                if row is None or not row.build_config:
                    console.print(
                        "[yellow]Build not in DB with config hashes; "
                        "skipping CDN pristine check.[/yellow]"
                    )
                else:
                    bc_raw = cdn.fetch_config(row.build_config)
                    bc = BuildConfigParser().parse(bc_raw)
                    enc_info = bc.get_encoding_info()
                    inst_info = bc.get_install_info()
                    if (
                        enc_info is None
                        or inst_info is None
                        or not enc_info.encoding_key
                        or not inst_info.encoding_key
                    ):
                        console.print(
                            "[yellow]Build config lacks encoding/install keys; "
                            "skipping CDN pristine check.[/yellow]"
                        )
                    else:
                        enc_raw = cdn.fetch_data(enc_info.encoding_key)
                        enc_data = (
                            decompress_blte(enc_raw) if is_blte(enc_raw) else enc_raw
                        )
                        enc_parser = EncodingParser()
                        enc_parsed = enc_parser.parse(enc_data)
                        inst_raw = cdn.fetch_data(inst_info.encoding_key)
                        inst_data = (
                            decompress_blte(inst_raw) if is_blte(inst_raw) else inst_raw
                        )
                        inst = InstallParser().parse(inst_data)
                        entry = next(
                            (
                                e
                                for e in inst.entries
                                if e.filename
                                and (
                                    "wow.exe" in e.filename.lower()
                                    or "wowclassic.exe" in e.filename.lower()
                                )
                            ),
                            None,
                        )
                        if entry is None:
                            console.print(
                                "[yellow]Game executable not in install manifest; "
                                "skipping CDN pristine check.[/yellow]"
                            )
                        else:
                            ekeys = enc_parser.find_content_key(
                                enc_data, enc_parsed, entry.md5_hash
                            )
                            if not ekeys:
                                console.print(
                                    "[yellow]Wow.exe ckey not in encoding "
                                    "table; skipping CDN pristine check.[/yellow]"
                                )
                            else:
                                raw = cdn.fetch_data(ekeys[0].hex())
                                data = decompress_blte(raw) if is_blte(raw) else raw
                                cdn_sha = hashlib.sha256(data).hexdigest()
                                if local_sha != cdn_sha:
                                    console.print(
                                        "[red]PRISTINE CHECK FAILED: local Wow.exe "
                                        f"sha256 {local_sha} != CDN {cdn_sha}. "
                                        "The executable was patched or corrupted. "
                                        "Aborting; nothing moved.[/red]"
                                    )
                                    raise click.Abort()
                                console.print(
                                    f"[green]Pristine OK[/green] "
                                    f"(sha256 {local_sha[:16]}...)"
                                )
            except click.Abort:
                raise
            except Exception as e:
                console.print(
                    f"[yellow]CDN pristine check failed ({e}); continuing "
                    "without verification.[/yellow]"
                )
                if debug:
                    import traceback

                    console.print(traceback.format_exc())

        # 4. Detect OS/ARCH via `file`
        try:
            file_out = subprocess.run(
                ["file", str(exe)], capture_output=True, text=True, check=True
            ).stdout
        except (subprocess.CalledProcessError, OSError) as e:
            console.print(f"[red]file(1) failed: {e}[/red]")
            raise click.Abort() from e
        if "Mach-O" in file_out:
            os_name = "macos"
            arch = "arm64" if "arm64" in file_out else "x86_64"
        elif "PE32+" in file_out and "x86-64" in file_out:
            os_name = "windows"
            arch = "win64"
        else:
            console.print(f"[red]Unrecognized binary: {file_out.strip()}[/red]")
            raise click.Abort()
        console.print(f"  Detected: {os_name}-{arch} ({file_out.strip()[:60]})")

        # 5. Move to archive
        target = archive_root / f"{version}.{os_name}-{arch}"
        if target.exists():
            if not force:
                console.print(
                    f"[red]{target} already exists; use --force to replace.[/red]"
                )
                raise click.Abort()
            console.print(f"[yellow]Replacing existing {target}[/yellow]")
            shutil.rmtree(target)
        archive_root.mkdir(parents=True, exist_ok=True)
        console.print(f"  Moving {install_path} -> {target}")
        shutil.move(str(install_path), str(target))
        console.print(f"[green]Archived pristine build at {target}[/green]")
    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e
