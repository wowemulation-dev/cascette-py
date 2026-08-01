"""CLI commands for the TPR product catalog (licenses and entitlement rules)."""

from __future__ import annotations

import json
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from cascette_tools.core.config import AppConfig

__all__ = ["catalog_group"]


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console, bool, bool]:
    """Extract context objects from Click context."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]
    verbose = ctx.obj.get("verbose", False)
    debug = ctx.obj.get("debug", False)
    return config, console, verbose, debug


@click.group(
    "catalog", short_help="Manage the TPR product catalog (licenses and rules)."
)
def catalog_group() -> None:
    """Manage the TPR product catalog.

    The catalog is served by Ribbit under the ``catalogs`` product code and
    describes Blizzard products: their entitlement rules, license
    requirements, and install configurations. Sync it from Blizzard's CDN
    into the local database, then inspect rules, licenses, and installs.
    """
    pass


def _render_match(node: Tree, match: Any) -> None:
    """Render a match criteria dict as a recursive tree."""
    if not isinstance(match, dict) or not match:
        node.add("match: always")
        return
    for key, value in match.items():
        if key in ("all_of", "any_of", "none_of") and isinstance(value, list):
            sub = node.add(key)
            for child in value:
                _render_match(sub, child)
        elif key == "not":
            sub = node.add("not")
            _render_match(sub, value)
        elif key == "license_id":
            ids = value if isinstance(value, list) else [value]
            node.add("license " + "/".join(str(i) for i in ids))
        elif key == "game_account" and isinstance(value, dict):
            region = value.get("region")
            region_str = region if isinstance(region, str) else "/".join(region or [])
            node.add(
                f"game_account(program_id={value.get('program_id')}, region={region_str})"
            )
        elif key == "flag":
            node.add(f"flag={value}")
        elif key == "realm_permissions":
            node.add(f"realm_permissions {value}")
        elif key == "igr":
            node.add(f"igr={value}")
        elif key in ("account_region", "account_country"):
            rendered = value if isinstance(value, str) else "/".join(value)
            node.add(f"{key}={rendered}")
        elif key == "always":
            node.add("always")
        else:
            node.add(f"{key}={value}")


def _render_action(node: Tree, action: dict[str, Any]) -> None:
    """Render an action dict, recursing into nested rule collections."""
    for key, value in action.items():
        if key in ("run_first_rule", "run_each_rule") and isinstance(value, list):
            sub = node.add(key)
            for index, nested in enumerate(value):
                _render_rule(sub, nested, f"Rule {index}")
        elif key in ("add_product", "remove_product") and isinstance(value, dict):
            product_id = value.get("product_id")
            if isinstance(product_id, dict):
                target = product_id.get("id", "?")
                product_type = product_id.get("type")
                label = (
                    f"{key} {target}/{product_type}"
                    if product_type
                    else f"{key} {target}"
                )
            else:
                label = f"{key} ?"
            if value.get("level"):
                label += f" (level={value['level']})"
            node.add(label)
        elif key in ("add_tag", "remove_tag") and isinstance(value, dict):
            node.add(f"{key} {value.get('name', '?')}")
        elif key == "run_rule":
            node.add(f"run_rule {value}")
        else:
            node.add(f"{key}={value}")


def _render_rule(node: Tree, rule: dict[str, Any], label: str) -> None:
    """Render one rule (match subtree + action subtrees) into a tree."""
    match = rule.get("match")
    if match:
        match_node = node.add(f"{label}: match")
        _render_match(match_node, match)
    else:
        node.add(f"{label}: always")
    for action in rule.get("actions") or []:
        _render_action(node, action)


@catalog_group.command("sync")
@click.option(
    "--region",
    default=None,
    help="Ribbit region (defaults to configured default region).",
)
@click.option(
    "--build-version",
    type=int,
    default=None,
    help="Catalog build version (e.g. 30). Defaults to the newest build.",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Bypass the 24-hour local cache.",
)
@click.pass_context
def sync_catalog(
    ctx: click.Context,
    region: str | None,
    build_version: int | None,
    force: bool,
) -> None:
    """Fetch the product catalog from Blizzard's CDN and import it."""
    config, console, verbose, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            console.print("[cyan]Syncing product catalog...[/cyan]")
            stats = client.sync(
                region=region or config.default_region,
                build_version=build_version,
                force=force,
            )

            if stats.get("cache"):
                console.print(
                    "[yellow]Using cached catalog "
                    f"(build v{stats.get('build_version')}, "
                    f"{stats.get('fragments')} fragments, imported "
                    f"{stats.get('imported')})"
                    "[/yellow]"
                )
            else:
                summary = (
                    "[green]Catalog synced:[/green] "
                    f"build v{stats.get('build_version')}, "
                    f"{stats.get('fragments')} fragments, "
                    f"{stats.get('imported')} imported"
                )
                if stats.get("encrypted"):
                    summary += f" ({stats.get('encrypted')} encrypted skipped)"
                console.print(summary)
                if verbose:
                    console.print(f"  Build config: {stats.get('build_config')}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("list")
@click.option(
    "--product",
    "-p",
    default=None,
    help="Filter fragments by product name (e.g. 'world_of_warcraft').",
)
@click.pass_context
def list_catalog(ctx: click.Context, product: str | None) -> None:
    """List catalog fragments in the database."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            fragments = client.list_fragments(product=product)
            if not fragments:
                console.print(
                    "[yellow]No catalog data. Run 'cascette catalog sync' first.[/yellow]"
                )
                return

            table = Table(title="Catalog Fragments", show_header=True)
            table.add_column("Hash", style="dim", no_wrap=True, min_width=32)
            table.add_column("Name", style="green", min_width=54, overflow="fold")
            table.add_column("Version", justify="right", style="yellow")
            table.add_column("Products", justify="right")
            table.add_column("Programs", justify="right")
            table.add_column("Root", justify="center")

            for row in fragments:
                products = client.conn.execute(
                    "SELECT COUNT(*) FROM catalog_products WHERE fragment_hash = ?",
                    (row["hash"],),
                ).fetchone()[0]
                programs = client.conn.execute(
                    "SELECT COUNT(*) FROM catalog_programs WHERE fragment_hash = ?",
                    (row["hash"],),
                ).fetchone()[0]
                table.add_row(
                    row["hash"],
                    row["name"] or row["fragment_id"] or "?",
                    str(row["version"] or "?"),
                    str(products),
                    str(programs),
                    "yes" if row["is_root"] else "",
                )

            console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("show")
@click.argument("program", required=True)
@click.pass_context
def show_program(ctx: click.Context, program: str) -> None:
    """Show entitlement rules for a program (e.g. 'WoW')."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            program_row = client.get_program(program)
            if program_row is None:
                console.print(
                    f"[yellow]No program '{program}' in the catalog.[/yellow]\n",
                    "Run 'cascette catalog programs' to list available programs.",
                )
                return

            is_gal = "yes" if program_row["is_game_account_level"] else "no"
            console.print(f"[bold]Program:[/bold] {program}")
            console.print(f"  Game account level: {is_gal}")

            rules = client.list_rules(program)
            if not rules:
                console.print("  No rules.")
                return

            tree = Tree(f"[bold]{len(rules)} rules[/bold]")
            for rule in rules:
                label = f"Rule {rule['rule_seq']}"
                if rule["level"]:
                    label += f" (level={rule['level']})"
                rule_dict: dict[str, Any] = {}
                if rule["match_json"]:
                    rule_dict["match"] = json.loads(rule["match_json"])
                if rule["actions_json"]:
                    rule_dict["actions"] = json.loads(rule["actions_json"])
                _render_rule(tree, rule_dict, label)
            console.print(tree)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("programs")
@click.option(
    "--fragment",
    "-f",
    default=None,
    help="Filter programs by fragment name (e.g. 'world_of_warcraft').",
)
@click.pass_context
def programs_cmd(ctx: click.Context, fragment: str | None) -> None:
    """List programs with entitlement rules and rule counts."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            if fragment:
                fragment_rows = client.list_fragments(product=fragment)
                if not fragment_rows:
                    console.print(
                        f"[yellow]No fragment '{fragment}' in the catalog.[/yellow]",
                    )
                    return
                fragment_hash = fragment_rows[0]["hash"]
                programs = client.conn.execute(
                    "SELECT * FROM catalog_programs WHERE fragment_hash = ? ORDER BY program_id",
                    (fragment_hash,),
                ).fetchall()
            else:
                programs = client.list_programs()

            if not programs:
                console.print(
                    "[yellow]No programs in the catalog. Run 'cascette catalog sync' first.[/yellow]",
                )
                return

            table = Table(title="Catalog Programs", show_header=True)
            table.add_column("Program", style="green", min_width=8)
            table.add_column("Fragment", style="dim")
            table.add_column("Rules", justify="right", style="yellow")
            table.add_column("Game Account Level", justify="center")

            for row in programs:
                rule_count = client.conn.execute(
                    "SELECT COUNT(*) FROM catalog_rules WHERE fragment_hash = ? AND program_id = ?",
                    (row["fragment_hash"], row["program_id"]),
                ).fetchone()[0]
                fragment_row = client.conn.execute(
                    "SELECT name FROM catalog_fragments WHERE hash = ?",
                    (row["fragment_hash"],),
                ).fetchone()
                fragment_name = fragment_row[0] if fragment_row else "?"
                table.add_row(
                    row["program_id"],
                    fragment_name or "?",
                    str(rule_count),
                    "yes" if row["is_game_account_level"] else "",
                )
            console.print(table)
            console.print(
                f"\n[green]Total: {len(programs)} programs[/green]",
                "Use 'cascette catalog show <program>' to see a program's rules.",
            )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("licenses")
@click.option(
    "--license-id",
    type=int,
    default=None,
    help="Show programs gated by a specific license ID.",
)
@click.pass_context
def licenses_cmd(ctx: click.Context, license_id: int | None) -> None:
    """List license IDs referenced by entitlement rules."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            rows = client.list_licenses(license_id=license_id)
            if not rows:
                console.print(
                    "[yellow]No licenses in the catalog. "
                    "Run 'cascette catalog sync' first.[/yellow]"
                )
                return

            table = Table(title="Catalog Licenses", show_header=True)
            table.add_column("License ID", justify="right", style="yellow")
            if license_id is not None:
                table.add_column("Program", style="green")
                table.add_column("Rule", justify="right")
                for row in rows:
                    table.add_row(
                        str(row["license_id"]), row["program_id"], str(row["rule_seq"])
                    )
            else:
                table.add_column("Programs", justify="right", style="green")
                for row in rows:
                    table.add_row(str(row["license_id"]), str(row["programs"]))
            console.print(table)
            console.print(f"\n[green]Total: {len(rows)}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("installs")
@click.option(
    "--tact-product",
    default=None,
    help="Filter installs by TACT product code (e.g. 'wow_classic').",
)
@click.pass_context
def installs_cmd(ctx: click.Context, tact_product: str | None) -> None:
    """List install configurations and their TACT product mappings."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            rows = client.list_installs(tact_product=tact_product)
            if not rows:
                console.print(
                    "[yellow]No install configs in the catalog. "
                    "Run 'cascette catalog sync' first.[/yellow]"
                )
                return

            table = Table(title="Catalog Install Configs", show_header=True)
            table.add_column("Install Type", style="green")
            table.add_column("TACT Product", style="yellow")
            table.add_column("Fragment", style="dim", no_wrap=True)

            for row in rows:
                table.add_row(
                    row["install_type"],
                    row["tact_product"] or "?",
                    row["fragment_hash"],
                )
            console.print(table)
            console.print(f"\n[green]Total: {len(rows)}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e


@catalog_group.command("stats")
@click.pass_context
def catalog_stats(ctx: click.Context) -> None:
    """Show catalog database statistics."""
    config, console, _, debug = _get_context_objects(ctx)

    from cascette_tools.database.catalog import CatalogClient

    try:
        with CatalogClient(config) as client:
            stats = client.get_stats()
            console.print("[bold]Catalog Database Statistics[/bold]\n")
            for label, key in (
                ("Fragments", "fragments"),
                ("Products", "products"),
                ("Programs", "programs"),
                ("Rules", "rules"),
                ("Licenses", "licenses"),
                ("Install configs", "installs"),
            ):
                console.print(f"{label}: [green]{stats[key]}[/green]")

            latest = stats.get("latest_build")
            if latest:
                console.print("\n[bold]Latest Synced Build:[/bold]")
                console.print(f"  Version: {latest.get('build_version')}")
                console.print(f"  Build num: {latest.get('build_num')}")
                console.print(f"  Build config: {latest.get('build_config')}")
                console.print(f"  Root hash: {latest.get('root_hash')}")
                console.print(f"  Fetched: {latest.get('fetched_at')}")
            else:
                console.print("\n[yellow]No build synced yet.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if debug:
            import traceback

            console.print(traceback.format_exc())
        raise click.Abort() from e
