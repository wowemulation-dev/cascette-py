"""Manage WoW build database from Wago.tools."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from cascette_tools.core.config import AppConfig


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract context objects from Click context."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]
    verbose = ctx.obj.get("verbose", False)
    debug = ctx.obj.get("debug", False)
    return config, console, verbose, debug


@click.group("builds", short_help="Manage WoW build database.")
def builds_group() -> None:
    """Manage WoW build database from Wago.tools.

    This command group provides tools for fetching, importing, searching,
    and managing WoW build metadata from the Wago.tools API. The build
    database contains information about 1,900+ WoW builds across all
    products (retail, classic, classic_era, etc.) from version 6.0.x
    through current versions.
    """
    pass


@builds_group.command("sync")
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force refresh even if cache is valid",
)
@click.option(
    "--import-db",
    is_flag=True,
    default=True,
    help="Import fetched builds to SQLite database",
)
@click.option(
    "--show-stats",
    is_flag=True,
    help="Show import statistics after fetching",
)
@click.pass_context
def sync_builds(
    ctx: click.Context,
    force: bool,
    import_db: bool,
    show_stats: bool,
) -> None:
    """Sync build database with Wago.tools.

    Downloads build metadata from Wago.tools API covering all WoW products
    from 6.0.x through current versions. The data is cached locally for
    24 hours and optionally imported into a SQLite database for offline
    querying and analysis.
    """
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            # Check cache status first
            if not force:
                status = wago.get_cache_status()
                if status["valid"]:
                    console.print(
                        f"[yellow]Using cached data from {status['fetch_time']} "
                        f"(expires in {status['remaining_hours']:.1f} hours)[/yellow]"
                    )
                    if verbose:
                        console.print(f"Cache contains {status['build_count']} builds")

            # Fetch builds
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Fetching builds from Wago.tools...", total=None)
                builds = wago.fetch_builds(force_refresh=force)
                progress.update(task, description=f"Fetched {len(builds)} builds")

            # Group builds by product for summary
            by_product = {}
            for build in builds:
                if build.product not in by_product:
                    by_product[build.product] = []
                by_product[build.product].append(build)

            # Display summary table
            table = Table(title="Build Database Summary", show_header=True)
            table.add_column("Product", style="cyan")
            table.add_column("Builds", justify="right", style="green")
            table.add_column("Version Range", style="yellow")
            table.add_column("Date Range", style="magenta")

            for product, product_builds in sorted(by_product.items()):
                versions = sorted({b.version for b in product_builds if b.version})
                dates = sorted([b.build_time for b in product_builds if b.build_time])

                version_range = f"{versions[0]} - {versions[-1]}" if versions else "N/A"
                date_range = f"{dates[0].strftime('%Y-%m-%d')} - {dates[-1].strftime('%Y-%m-%d')}" if dates else "N/A"

                table.add_row(
                    product,
                    str(len(product_builds)),
                    version_range,
                    date_range,
                )

            console.print(table)
            console.print(f"\n[green]Total builds: {len(builds)}[/green]")

            # Import to database if requested
            if import_db:
                console.print("\n[cyan]Importing builds to database...[/cyan]")
                stats = wago.import_builds_to_database(builds)

                if show_stats or verbose:
                    console.print(f"[green]Imported {stats['imported']} new builds[/green]")
                    console.print(f"[yellow]Updated {stats['updated']} existing builds[/yellow]")
                    console.print(f"[dim]Skipped {stats['skipped']} unchanged builds[/dim]")

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
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_ptr", "wow_beta"], case_sensitive=False),
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

            # Apply limit unless --all is specified
            if not all and len(builds) > limit:
                builds = builds[:limit]
                console.print(f"[dim]Showing {limit} of {len(builds)} builds (use --all to see all)[/dim]\n")

            # Create table
            table = Table(title="WoW Builds", show_header=True)
            table.add_column("Build ID", style="cyan", no_wrap=True)
            table.add_column("Product", style="green")
            table.add_column("Version", style="yellow")
            table.add_column("Build", style="magenta", justify="right")
            table.add_column("Created", style="blue")

            # Always show config hashes for fetch command usage
            table.add_column("Build Config", style="dim", no_wrap=True)
            table.add_column("CDN Config", style="dim", no_wrap=True)

            if verbose:
                table.add_column("Product Config", style="dim", no_wrap=True)

            for build in builds:
                row = [
                    str(build.id),
                    build.product,
                    build.version or "N/A",
                    build.build or "N/A",
                    build.build_time.strftime('%Y-%m-%d') if build.build_time else "N/A",
                    # Always show full config hashes for fetch command
                    build.build_config or "N/A",
                    build.cdn_config or "N/A",
                ]

                if verbose:
                    row.append(build.product_config or "N/A")

                table.add_row(*row)

            console.print(table)
            console.print(f"\n[green]Total: {len(builds)} builds[/green]")

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
@click.pass_context
def search_builds(
    ctx: click.Context,
    query: str,
    field: str,
) -> None:
    """Search for builds matching a query."""
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoClient

        with WagoClient(config_obj) as wago:
            builds = wago.search_builds(query, field=field)

            if not builds:
                console.print(f"[yellow]No builds found matching '{query}'[/yellow]")
                return

            # Create results table
            table = Table(title=f"Search Results for '{query}'", show_header=True)
            table.add_column("Build ID", style="cyan", no_wrap=True)
            table.add_column("Product", style="green")
            table.add_column("Version", style="yellow")
            table.add_column("Build", style="magenta", justify="right")
            table.add_column("Build Config", style="dim", no_wrap=True)
            table.add_column("CDN Config", style="dim", no_wrap=True)

            for build in builds:
                table.add_row(
                    str(build.id),
                    build.product,
                    build.version or "N/A",
                    build.build or "N/A",
                    build.build_config or "N/A",
                    build.cdn_config or "N/A",
                )

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
    type=click.Choice(["wow", "wow_classic", "wow_classic_era", "wow_classic_ptr", "wow_beta"], case_sensitive=False),
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
    config_obj, console, verbose, debug = _get_context_objects(ctx)

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
    config_obj, console, verbose, debug = _get_context_objects(ctx)

    try:
        from cascette_tools.database.wago import WagoBuild, WagoClient

        # Auto-detect format if not specified
        if not format:
            if input.suffix.lower() == ".json":
                format = "json"
            elif input.suffix.lower() == ".csv":
                format = "csv"
            else:
                console.print("[red]Cannot auto-detect format. Please specify --format[/red]")
                raise click.Abort()

        builds = []

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
                    build_data = {}

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
