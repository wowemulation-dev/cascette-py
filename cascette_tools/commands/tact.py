"""TACT key management commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import click
from rich.console import Console
from rich.table import Table

from cascette_tools.core.config import AppConfig
from cascette_tools.database.tact_keys import TACTKeyManager


@click.group(name="tact")
@click.pass_context
def tact_group(ctx: click.Context) -> None:
    """Manage TACT encryption keys."""
    pass


@tact_group.command(name="sync")
@click.option("--force", "-f", is_flag=True, help="Force refresh from GitHub")
@click.pass_context
def sync_keys(ctx: click.Context, force: bool) -> None:
    """Sync TACT keys with wowdev/TACTKeys repository."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with console.status("Syncing TACT keys..."):
        with TACTKeyManager(config) as manager:
            try:
                # Fetch and import keys
                keys = manager.fetch_wowdev_keys(force_refresh=force)
                imported = manager.import_keys(keys)

                console.print(f"[green]✓[/green] Synced {imported} TACT keys")

                # Show statistics
                stats = manager.get_statistics()

                table = Table(title="TACT Key Database")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")

                table.add_row("Total Keys", str(stats["total_keys"]))
                table.add_row("Verified", str(stats["verified"]))
                table.add_row("Unverified", str(stats["unverified"]))

                if stats.get("by_family"):
                    table.add_row("", "")  # Empty row
                    table.add_row("By Product Family", "")
                    for family, count in stats["by_family"].items():
                        table.add_row(f"  {family}", str(count))

                console.print(table)

            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
                raise click.ClickException(f"Failed to sync TACT keys: {e}") from e


@tact_group.command(name="list")
@click.option("--family", "-f", help="Filter by product family (wow, battlenet, etc.)")
@click.option("--limit", "-l", type=int, default=20, help="Number of keys to show")
@click.pass_context
def list_keys(ctx: click.Context, family: str | None, limit: int) -> None:
    """List TACT keys in database."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with TACTKeyManager(config) as manager:
        if family:
            keys = manager.get_keys_by_family(family)
        else:
            keys = manager.get_all_keys()

        if not keys:
            filter_text = f" for family '{family}'" if family else ""
            console.print(f"No TACT keys found{filter_text}")
            return

        # Display keys
        title = f"TACT Keys (showing {min(limit, len(keys))} of {len(keys)})"
        if family:
            title += f" - {family}"

        table = Table(title=title)
        table.add_column("Key Name", style="cyan")
        table.add_column("Family", style="yellow")
        table.add_column("Description", style="green")
        table.add_column("Verified", style="blue")

        for key in keys[:limit]:
            # Truncate long descriptions
            description = key.description or ""
            if len(description) > 40:
                description = description[:37] + "..."

            table.add_row(
                key.key_name[:16] + "...",
                key.product_family,
                description,
                "✓" if key.verified else "✗"
            )

        console.print(table)


@tact_group.command(name="search")
@click.argument("key_name")
@click.pass_context
def search_key(ctx: click.Context, key_name: str) -> None:
    """Search for a specific TACT key."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with TACTKeyManager(config) as manager:
        key = manager.get_key(key_name)

        if not key:
            console.print(f"[yellow]Key not found:[/yellow] {key_name}")
            return

        # Display key details
        table = Table(title="TACT Key Details")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Key Name", key.key_name)
        table.add_row("Key Value", key.key_value)
        table.add_row("Description", key.description or "N/A")
        table.add_row("Product Family", key.product_family)
        table.add_row("Verified", "Yes" if key.verified else "No")

        console.print(table)


@tact_group.command(name="export")
@click.argument("output", type=click.Path(path_type=Path))
@click.option("--family", "-f", help="Filter by product family")
@click.pass_context
def export_keys(ctx: click.Context, output: Path, family: str | None) -> None:
    """Export TACT keys to JSON file."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with TACTKeyManager(config) as manager:
        try:
            manager.export_keys(output, family)

            # Show what was exported
            if family:
                keys = manager.get_keys_by_family(family)
                filter_text = f" for family '{family}'"
            else:
                keys = manager.get_all_keys()
                filter_text = ""

            console.print(f"[green]✓[/green] Exported {len(keys)} TACT keys{filter_text} to {output}")

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.ClickException(f"Failed to export TACT keys: {e}") from e


@tact_group.command(name="stats")
@click.pass_context
def show_stats(ctx: click.Context) -> None:
    """Show TACT key database statistics."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with TACTKeyManager(config) as manager:
        stats = manager.get_statistics()

        table = Table(title="TACT Key Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Keys", str(stats["total_keys"]))
        table.add_row("Verified Keys", str(stats["verified"]))
        table.add_row("Unverified Keys", str(stats["unverified"]))

        if stats.get("by_family"):
            table.add_row("", "")  # Empty row
            table.add_row("By Product Family", "")
            for family, count in stats["by_family"].items():
                table.add_row(f"  {family}", str(count))

        console.print(table)


@tact_group.command(name="import")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", type=click.Choice(["json", "csv"], case_sensitive=False), default="json", help="Input file format")
@click.option("--overwrite", is_flag=True, help="Overwrite existing keys")
@click.pass_context
def import_keys(ctx: click.Context, input_file: Path, format: str, overwrite: bool) -> None:
    """Import TACT keys from a file.

    Accepts JSON format from export or CSV with columns: key_id,key,description,family
    """
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    with TACTKeyManager(config) as manager:
        try:
            import csv
            import json

            keys_to_import: list[dict[str, Any]] = []

            if format == "json":
                with open(input_file) as f:
                    data: Any = json.load(f)
                    # Handle both list and dict formats
                    if isinstance(data, list):
                        # Cast to typed list and append items
                        data_list = cast(list[dict[str, Any]], data)
                        keys_to_import.extend(data_list)
                    elif isinstance(data, dict):
                        # Flatten dict format {"family": [keys...]}
                        data_dict = cast(dict[str, Any], data)
                        for family_key, family_keys in data_dict.items():
                            if isinstance(family_keys, list):
                                family_keys_list = cast(list[dict[str, Any]], family_keys)
                                for key_item in family_keys_list:
                                    if not key_item.get("family"):
                                        key_item["family"] = family_key
                                    keys_to_import.append(key_item)
            else:  # CSV format
                with open(input_file, newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        keys_to_import.append({
                            "key_id": row.get("key_id", ""),
                            "key": row.get("key", ""),
                            "description": row.get("description", ""),
                            "family": row.get("family", "wow"),
                            "verified": row.get("verified", "true").lower() in ("true", "1", "yes")
                        })

            # Convert dicts to TACTKey objects
            from cascette_tools.database.tact_keys import TACTKey

            tact_keys: list[TACTKey] = []
            for key_dict in keys_to_import:
                # Map field names from import format to TACTKey model
                tact_key = TACTKey(
                    key_name=str(key_dict.get("key_id", key_dict.get("key_name", ""))),
                    key_value=str(key_dict.get("key", key_dict.get("key_value", ""))),
                    description=str(key_dict.get("description")) if key_dict.get("description") else None,
                    product_family=str(key_dict.get("family", key_dict.get("product_family", "wow"))),
                    verified=bool(key_dict.get("verified", False))
                )
                tact_keys.append(tact_key)

            # Import the keys
            imported = manager.import_keys(tact_keys)

            console.print(f"[green]✓[/green] Imported {imported} TACT keys from {input_file}")

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise click.ClickException(f"Failed to import TACT keys: {e}") from e
