"""Manage cascette-tools configuration."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from cascette_tools.core.config import (
    DEFAULT_FALLBACK_MIRRORS,
    DEFAULT_FAMILY_MIRRORS,
    AppConfig,
    MirrorConfig,
    MirrorSettings,
    resolve_mirrors_for_product,
)
from cascette_tools.core.types import Product, ProductFamily, get_product_family


def _get_context_objects(ctx: click.Context) -> tuple[AppConfig, Console]:
    """Extract config and console from Click context."""
    config: AppConfig = ctx.obj["config"]
    console: Console = ctx.obj["console"]
    return config, console


def _validate_family(target: str) -> ProductFamily:
    """Validate target as a ProductFamily value."""
    try:
        return ProductFamily(target)
    except ValueError:
        valid = ", ".join(f.value for f in ProductFamily)
        raise click.ClickException(
            f"Unknown product family: {target}. Valid families: {valid}"
        ) from None


def _validate_product_code(target: str) -> Product:
    """Validate target as a Product value."""
    try:
        return Product(target)
    except ValueError:
        raise click.ClickException(
            f"Unknown product code: {target}. "
            f"Use 'cascette config mirror list' to see valid values."
        ) from None


@click.group(name="config")
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """Manage cascette-tools configuration."""
    pass


@config_group.group(name="mirror")
@click.pass_context
def mirror_group(ctx: click.Context) -> None:
    """Manage CDN mirror configuration.

    Mirrors can be configured per product family (e.g., wow, battlenet)
    or per product code (e.g., bna, wow_classic). Product-specific mirrors
    override family-level mirrors.
    """
    pass


@mirror_group.command(name="add")
@click.argument("target", type=str)
@click.argument("urls", nargs=-1, required=True)
@click.option(
    "--product-code",
    "--pc",
    is_flag=True,
    help="Treat TARGET as a product code instead of a product family.",
)
@click.pass_context
def mirror_add(
    ctx: click.Context,
    target: str,
    urls: tuple[str, ...],
    product_code: bool,
) -> None:
    """Add CDN mirror URL(s) for a product family or product code.

    TARGET is a product family name (e.g., wow, battlenet, diablo) by default.
    Use --product-code to treat TARGET as a specific product code (e.g., bna).

    URLs are appended to the mirror list. Duplicates are ignored.

    \b
    Examples:
      cascette config mirror add wow https://cdn.arctium.tools
      cascette config mirror add --product-code bna http://example.com
    """
    config, console = _get_context_objects(ctx)

    # Validate target
    if product_code:
        _validate_product_code(target)
    else:
        _validate_family(target)

    # Validate URLs
    for url in urls:
        if not url.startswith(("http://", "https://")):
            raise click.ClickException(
                f"Mirror URL must start with http:// or https://: {url}"
            )

    # Get or create the mirror config for this target
    if product_code:
        existing = config.mirrors.product_overrides.get(target)
    else:
        existing = config.mirrors.family_mirrors.get(target)

    current_urls = list(existing.urls) if existing else []

    # Append new URLs, skip duplicates
    added = []
    for url in urls:
        if url not in current_urls:
            current_urls.append(url)
            added.append(url)

    new_config = MirrorConfig(urls=current_urls)

    if product_code:
        config.mirrors.product_overrides[target] = new_config
    else:
        config.mirrors.family_mirrors[target] = new_config

    config.save()

    target_type = "product" if product_code else "family"
    if added:
        for url in added:
            console.print(f"Added {url} to {target_type} '{target}'")
    else:
        console.print("[dim]No new URLs added (all already present)[/dim]")


@mirror_group.command(name="remove")
@click.argument("target", type=str)
@click.argument("urls", nargs=-1, required=False)
@click.option(
    "--product-code",
    "--pc",
    is_flag=True,
    help="Treat TARGET as a product code instead of a product family.",
)
@click.pass_context
def mirror_remove(
    ctx: click.Context,
    target: str,
    urls: tuple[str, ...],
    product_code: bool,
) -> None:
    """Remove CDN mirror URL(s) for a product family or product code.

    Without URLs, removes ALL mirrors for the target.
    With URLs, removes only the specified URLs.

    \b
    Examples:
      cascette config mirror remove wow https://cdn.arctium.tools
      cascette config mirror remove wow
      cascette config mirror remove --product-code bna
    """
    config, console = _get_context_objects(ctx)

    if product_code:
        store = config.mirrors.product_overrides
    else:
        store = config.mirrors.family_mirrors

    if target not in store:
        console.print(f"[yellow]No mirrors configured for '{target}'[/yellow]")
        return

    if not urls:
        # Remove all mirrors for this target
        del store[target]
        config.save()
        target_type = "product" if product_code else "family"
        console.print(f"Removed all mirrors for {target_type} '{target}'")
    else:
        existing = store[target]
        remaining = [u for u in existing.urls if u not in urls]
        removed = [u for u in urls if u in existing.urls]
        not_found = [u for u in urls if u not in existing.urls]

        if remaining:
            store[target] = MirrorConfig(urls=remaining)
        else:
            del store[target]

        config.save()

        for url in removed:
            console.print(f"Removed {url} from '{target}'")
        for url in not_found:
            console.print(f"[dim]{url} was not in '{target}'[/dim]")


@mirror_group.command(name="list")
@click.option(
    "--resolve",
    "-r",
    type=str,
    default=None,
    help="Show resolved mirrors for a specific product code.",
)
@click.pass_context
def mirror_list(
    ctx: click.Context,
    resolve: str | None,
) -> None:
    """List configured CDN mirrors.

    Without --resolve, shows the raw user configuration.
    With --resolve <product>, shows the effective mirror list after
    resolution (product override > family config > built-in defaults).

    \b
    Examples:
      cascette config mirror list
      cascette config mirror list --resolve wow_classic
      cascette config mirror list --resolve bna
    """
    config, console = _get_context_objects(ctx)

    if resolve:
        # Validate the product
        _validate_product_code(resolve)

        mirrors = resolve_mirrors_for_product(resolve, config.mirrors)
        family = get_product_family(resolve)

        # Determine source
        if (
            resolve in config.mirrors.product_overrides
            and config.mirrors.product_overrides[resolve].urls
        ):
            source = "product override"
        elif (
            family.value in config.mirrors.family_mirrors
            and config.mirrors.family_mirrors[family.value].urls
        ):
            source = "family config"
        elif family.value in DEFAULT_FAMILY_MIRRORS:
            source = "built-in default"
        else:
            source = "generic fallback"

        table = Table(title=f"Resolved Mirrors for '{resolve}'")
        table.add_column("#", style="dim", justify="right")
        table.add_column("URL", style="cyan")

        for i, url in enumerate(mirrors, 1):
            table.add_row(str(i), url)

        console.print(table)
        console.print(f"[dim]Source: {source} (family: {family.value})[/dim]")
        return

    # Show raw configuration
    has_config = False

    if config.mirrors.family_mirrors:
        has_config = True
        table = Table(title="Family Mirrors")
        table.add_column("Family", style="green")
        table.add_column("URLs", style="cyan")

        for family, mirror_cfg in sorted(config.mirrors.family_mirrors.items()):
            urls_str = (
                "\n".join(mirror_cfg.urls) if mirror_cfg.urls else "[dim]empty[/dim]"
            )
            table.add_row(family, urls_str)

        console.print(table)

    if config.mirrors.product_overrides:
        has_config = True
        if config.mirrors.family_mirrors:
            console.print()

        table = Table(title="Product Overrides")
        table.add_column("Product", style="green")
        table.add_column("URLs", style="cyan")

        for product, mirror_cfg in sorted(config.mirrors.product_overrides.items()):
            urls_str = (
                "\n".join(mirror_cfg.urls) if mirror_cfg.urls else "[dim]empty[/dim]"
            )
            table.add_row(product, urls_str)

        console.print(table)

    if not has_config:
        console.print("[dim]No user-configured mirrors. Using built-in defaults.[/dim]")
        console.print()

        table = Table(title="Built-in Default Mirrors")
        table.add_column("Family", style="green")
        table.add_column("URLs", style="cyan")

        for family, urls in sorted(DEFAULT_FAMILY_MIRRORS.items()):
            table.add_row(family, "\n".join(urls))
        table.add_row("[dim]other[/dim]", "\n".join(DEFAULT_FALLBACK_MIRRORS))

        console.print(table)


@mirror_group.command(name="reset")
@click.argument("target", required=False)
@click.option(
    "--product-code",
    "--pc",
    is_flag=True,
    help="Treat TARGET as a product code instead of a product family.",
)
@click.option(
    "--all",
    "reset_all",
    is_flag=True,
    help="Reset ALL mirror configuration to defaults.",
)
@click.pass_context
def mirror_reset(
    ctx: click.Context,
    target: str | None,
    product_code: bool,
    reset_all: bool,
) -> None:
    """Reset mirror configuration to defaults.

    Without arguments, requires --all to reset everything.
    With TARGET, resets just that family or product.

    \b
    Examples:
      cascette config mirror reset --all
      cascette config mirror reset wow
      cascette config mirror reset --product-code bna
    """
    config, console = _get_context_objects(ctx)

    if not target and not reset_all:
        raise click.ClickException(
            "Specify a target to reset, or use --all to reset all mirror configuration."
        )

    if reset_all:
        config.mirrors = MirrorSettings()
        config.save()
        console.print("Reset all mirror configuration to defaults.")
        return

    assert target is not None

    if product_code:
        if target in config.mirrors.product_overrides:
            del config.mirrors.product_overrides[target]
            config.save()
            console.print(f"Reset product override for '{target}'.")
        else:
            console.print(f"[dim]No product override configured for '{target}'[/dim]")
    else:
        if target in config.mirrors.family_mirrors:
            del config.mirrors.family_mirrors[target]
            config.save()
            console.print(f"Reset family mirrors for '{target}'.")
        else:
            console.print(f"[dim]No family mirrors configured for '{target}'[/dim]")
