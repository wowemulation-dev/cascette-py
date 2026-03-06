"""Manage WoW build database from Wago.tools and BlizzTrack."""

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


@click.group("builds", short_help="Manage build database.")
def builds_group() -> None:
    """Manage build database from Wago.tools and BlizzTrack.

    Syncs build metadata from two sources:

    - Wago.tools: WoW product family (wow, wow_classic, wow_classic_era,
      wow_classic_titan, wow_anniversary) with decoded manifest EKEYs.
    - BlizzTrack: All TACT products including agent and bna. Covers
      current versions and archived seqn history.

    Both sources write into the same SQLite database; duplicates are
    resolved on import using (id, product) as the unique key.
    """
    pass


@builds_group.command("sync")
@click.option(
    "--source",
    "-s",
    type=click.Choice(["wago", "blizztrack", "all"], case_sensitive=False),
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
    """Sync build database from Wago.tools and/or BlizzTrack.

    By default syncs from both sources and deduplicates on import.

    Wago.tools covers WoW products (wow, wow_classic, wow_classic_era,
    wow_classic_titan, wow_anniversary) with decoded metadata.

    BlizzTrack covers all TACT products including agent and bna. Use
    --history to also walk archived seqn snapshots (makes one HTTP
    request per historical snapshot — can be several hundred requests).
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

        if not all_builds:
            console.print("[yellow]No builds fetched.[/yellow]")
            return

        # --- Import to database (deduplication happens in import_builds_to_database) ---
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            console.print(f"\n[cyan]Importing {len(all_builds)} builds to database...[/cyan]")
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
            versions: list[str] = sorted({b.version for b in product_builds if b.version})
            version_range = f"{versions[0]} – {versions[-1]}" if len(versions) > 1 else (versions[0] if versions else "N/A")
            table.add_row(product, str(len(product_builds)), version_range)

        console.print(table)
        console.print(f"\n[green]Total fetched: {len(all_builds)}[/green]")

        if show_stats or verbose:
            console.print(f"[green]  Imported (new): {import_stats['imported']}[/green]")
            console.print(f"[yellow]  Updated:        {import_stats['updated']}[/yellow]")
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
                console.print(f"[dim]Showing {limit} of {total} builds (use --all to see all)[/dim]\n")
                builds = builds[:limit]
            else:
                console.print(f"[dim]Showing {len(builds)} of {total} builds (use --all to see all)[/dim]\n")

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
                    build.build_time.strftime('%Y-%m-%d') if build.build_time else "N/A",
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
    type=click.Choice(["version", "build", "config", "branch", "all"], case_sensitive=False),
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
                created = build.build_time.strftime("%Y-%m-%d") if build.build_time else "N/A"
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
                console.print(f"Expires in: {cache_status['remaining_hours']:.1f} hours")
            else:
                console.print("\nCache status: [yellow]Expired or not present[/yellow]")

            # Product breakdown
            if verbose and stats.get('by_product'):
                console.print("\n[bold]Builds by Product:[/bold]")
                product_table = Table(show_header=True, header_style="bold")
                product_table.add_column("Product")
                product_table.add_column("Count", justify="right")
                product_table.add_column("Percentage", justify="right")

                for product, count in stats['by_product'].items():
                    percentage = (count / stats['total_builds']) * 100
                    product_table.add_row(
                        product,
                        str(count),
                        f"{percentage:.1f}%"
                    )

                console.print(product_table)

            # Version breakdown
            if verbose and stats.get('by_major_version'):
                console.print("\n[bold]Builds by Major Version:[/bold]")
                version_table = Table(show_header=True, header_style="bold")
                version_table.add_column("Version")
                version_table.add_column("Count", justify="right")

                for version, count in sorted(stats['by_major_version'].items()):
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
                        "build_time": b.build_time.isoformat() if b.build_time else None,
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
                            "id", "product", "version", "build",
                            "build_config", "cdn_config", "product_config",
                            "build_time", "encoding_ekey", "root_ekey"
                        ]
                    )
                    writer.writeheader()

                    for build in builds:
                        writer.writerow({
                            "id": build.id,
                            "product": build.product,
                            "version": build.version,
                            "build": build.build,
                            "build_config": build.build_config,
                            "cdn_config": build.cdn_config,
                            "product_config": build.product_config,
                            "build_time": build.build_time.isoformat() if build.build_time else None,
                            "encoding_ekey": build.encoding_ekey,
                            "root_ekey": build.root_ekey,
                        })

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
                console.print("[red]Cannot auto-detect format. Please specify --format[/red]")
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
                        build_data["build_time"] = datetime.fromisoformat(str(row["build_time"]))

                    # Optional config fields
                    for field in ["build_config", "cdn_config", "product_config", "encoding_ekey", "root_ekey", "install_ekey", "download_ekey"]:
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
            console.print(f"[yellow]Updated {stats['updated']} existing builds[/yellow]")
            console.print(f"[dim]Skipped {stats['skipped']} unchanged builds[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback
            console.print(traceback.format_exc())
        raise click.Abort() from e
