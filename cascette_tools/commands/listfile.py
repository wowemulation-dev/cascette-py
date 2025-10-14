"""FileDataID listfile management commands."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cascette_tools.core.config import AppConfig
from cascette_tools.database.listfile import ListfileManager


@click.group(name="listfile")
@click.pass_context
def listfile_group(ctx: click.Context) -> None:
    """Manage FileDataID to path mappings."""
    pass


@listfile_group.command(name="sync")
@click.option("--force", "-f", is_flag=True, help="Force refresh from GitHub")
@click.pass_context
def sync_listfile(ctx: click.Context, force: bool) -> None:
    """Sync listfile with wowdev/wow-listfile repository."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with console.status("Syncing listfile..."):
        manager = ListfileManager(config)

        try:
            # Fetch and import entries
            entries = manager.fetch_listfile(force_refresh=force)
            imported = manager.import_entries(entries)

            console.print(f"[green]✓[/green] Synced {imported} file entries")

            # Show statistics
            stats = manager.get_statistics()

            table = Table(title="Listfile Database")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Entries", f"{stats['total_entries']:,}")
            table.add_row("Verified", f"{stats['verified']:,}")
            table.add_row("Unverified", f"{stats['unverified']:,}")

            if stats.get("top_extensions"):
                table.add_row("", "")  # Empty row
                table.add_row("Top Extensions", "")
                for ext, count in list(stats["top_extensions"].items())[:5]:
                    table.add_row(f"  {ext}", f"{count:,}")

            console.print(table)

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.ClickException(f"Failed to sync listfile: {e}") from e

        finally:
            manager.close()


@listfile_group.command(name="search")
@click.argument("pattern")
@click.option("--limit", "-l", type=int, default=20, help="Maximum results")
@click.pass_context
def search_paths(ctx: click.Context, pattern: str, limit: int) -> None:
    """Search for file paths matching pattern."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    manager = ListfileManager(config)

    try:
        entries = manager.search_paths(pattern, limit)

        if not entries:
            console.print(f"No files matching: {pattern}")
            return

        # Display results
        table = Table(title=f"Search Results for '{pattern}' (showing {len(entries)} of max {limit})")
        table.add_column("FDID", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Verified", style="blue")

        for entry in entries:
            table.add_row(
                str(entry.fdid),
                entry.path,
                "✓" if entry.verified else "✗"
            )

        console.print(table)

    finally:
        manager.close()


@listfile_group.command(name="lookup")
@click.argument("identifier")
@click.pass_context
def lookup_file(ctx: click.Context, identifier: str) -> None:
    """Lookup file by FDID or path."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    manager = ListfileManager(config)

    try:
        # Try as FDID first
        result = None
        try:
            fdid = int(identifier)
            path = manager.get_path(fdid)
            if path:
                result = {"fdid": fdid, "path": path}
        except ValueError:
            # Try as path
            fdid = manager.get_fdid(identifier)
            if fdid:
                result = {"fdid": fdid, "path": identifier}

        if not result:
            console.print(f"[yellow]Not found:[/yellow] {identifier}")
            return

        # Display result
        table = Table(title="File Entry")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("FileDataID", str(result["fdid"]))
        table.add_row("Path", str(result["path"]))

        # Get file info
        if "." in result["path"]:
            ext = result["path"].rsplit(".", 1)[1]
            table.add_row("Extension", f".{ext}")

        console.print(table)

    finally:
        manager.close()


@listfile_group.command(name="export")
@click.argument("output", type=click.Path(path_type=Path))
@click.option("--format", "-f", type=click.Choice(["csv", "json"]), default="csv", help="Export format")
@click.pass_context
def export_listfile(ctx: click.Context, output: Path, format: str) -> None:
    """Export listfile to file."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    manager = ListfileManager(config)

    try:
        with console.status(f"Exporting to {output}..."):
            manager.export_listfile(output, format)

        stats = manager.get_statistics()
        console.print(f"[green]✓[/green] Exported {stats['total_entries']:,} entries to {output}")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.ClickException(f"Failed to export listfile: {e}") from e

    finally:
        manager.close()


@listfile_group.command(name="stats")
@click.pass_context
def show_stats(ctx: click.Context) -> None:
    """Show listfile database statistics."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    manager = ListfileManager(config)

    try:
        stats = manager.get_statistics()

        table = Table(title="Listfile Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Entries", f"{stats['total_entries']:,}")
        table.add_row("Verified Entries", f"{stats['verified']:,}")
        table.add_row("Unverified Entries", f"{stats['unverified']:,}")

        if stats.get("by_product"):
            table.add_row("", "")  # Empty row
            table.add_row("By Product", "")
            for product, count in stats["by_product"].items():
                table.add_row(f"  {product}", f"{count:,}")

        if stats.get("top_extensions"):
            table.add_row("", "")  # Empty row
            table.add_row("Top File Extensions", "")
            for ext, count in stats["top_extensions"].items():
                table.add_row(f"  {ext}", f"{count:,}")

        if stats.get("last_update"):
            table.add_row("", "")  # Empty row
            table.add_row("Last Update", "")
            table.add_row("  Time", stats["last_update"]["time"])
            table.add_row("  Source", stats["last_update"]["source"])
            table.add_row("  Entries", f"{stats['last_update']['count']:,}")

        console.print(table)

    finally:
        manager.close()


@listfile_group.command(name="import")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", type=click.Choice(["csv", "txt"], case_sensitive=False), default="csv", help="Input file format")
@click.option("--overwrite", is_flag=True, help="Overwrite existing entries")
@click.pass_context
def import_listfile(ctx: click.Context, input_file: Path, format: str, overwrite: bool) -> None:
    """Import listfile from a file.

    Accepts CSV format with columns: fdid,path,verified
    Or TXT format with lines: fdid;path
    """
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with ListfileManager(config) as manager:
        try:
            import csv

            entries_to_import = []

            if format == "csv":
                with open(input_file, newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        entries_to_import.append({
                            "fdid": int(row.get("fdid", 0)),
                            "path": row.get("path", ""),
                            "verified": row.get("verified", "false").lower() in ("true", "1", "yes")
                        })
            else:  # TXT format (fdid;path per line)
                with open(input_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split(';', 1)
                        if len(parts) == 2:
                            try:
                                entries_to_import.append({
                                    "fdid": int(parts[0]),
                                    "path": parts[1],
                                    "verified": False
                                })
                            except ValueError:
                                continue  # Skip invalid lines

            # Convert dicts to FileDataEntry objects
            from cascette_tools.database.listfile import FileDataEntry

            file_entries = []
            for entry_dict in entries_to_import:
                file_entry = FileDataEntry(
                    fdid=entry_dict["fdid"],
                    path=entry_dict["path"],
                    verified=entry_dict.get("verified", False)
                )
                file_entries.append(file_entry)

            # Import the entries (source is "import" for manually imported files)
            imported = manager.import_entries(file_entries, source="import")

            console.print(f"[green]✓[/green] Imported {imported} listfile entries from {input_file}")

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.ClickException(f"Failed to import listfile: {e}") from e
