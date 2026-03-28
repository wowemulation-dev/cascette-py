#!/usr/bin/env python3
"""Search for and import missing builds from Wago.tools."""

import html
import json
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Add parent directory to path to import cascette_tools
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from cascette_tools.core.config import AppConfig
from cascette_tools.database.wago import WagoBuild, WagoClient

console = Console()

# Product codes that are acceptable when searching for a given target product.
# Wago uses separate product codes for PTR/Beta, and some products changed
# codes over time (e.g., Classic Era builds before 1.14 were under wow_classic).
_ACCEPTABLE_PRODUCTS: dict[str, set[str]] = {
    'wow': {'wow'},
    'wow_classic': {'wow_classic'},
    'wow_classic_era': {'wow_classic_era', 'wow_classic'},  # pre-split 1.13.x
    'wow_classic_titan': {'wow_classic_titan'},
    'wow_anniversary': {'wow_anniversary'},
}

# Additional product codes to accept only when the patch version matches.
# Build numbers can collide across products (e.g. 42869 is both 9.2.0 retail
# and 2.5.4 classic), so version verification is required for these.
_VERSION_VERIFIED_PRODUCTS: dict[str, set[str]] = {
    'wow': {'wowt', 'wow_beta', 'wowlivetest', 'wowxptr'},
    'wow_classic': {'wow_classic_ptr', 'wow_classic_beta'},
    'wow_classic_era': {'wow_classic_era_ptr', 'wow_classic_ptr'},
    'wow_classic_titan': set(),
    'wow_anniversary': set(),
}


def parse_wago_search(search_term: str) -> list[dict[str, str]]:
    """Parse Wago.tools search results from HTML.

    Args:
        search_term: Search term like "11.2.5"

    Returns:
        List of build dictionaries
    """
    url = f"https://wago.tools/builds?search={search_term}"

    try:
        response = httpx.get(url, headers={"User-Agent": "cascette-tools/1.0"}, timeout=30)
        response.raise_for_status()

        # Find the data-page attribute containing JSON data
        match = re.search(r'data-page="([^"]+)"', response.text)

        if not match:
            return []

        # Unescape HTML entities
        escaped_json = match.group(1)
        unescaped_json = html.unescape(escaped_json)

        try:
            data = json.loads(unescaped_json)
        except json.JSONDecodeError:
            return []

        # Extract builds from the data structure
        builds = []
        if 'props' in data and 'builds' in data['props']:
            build_data = data['props']['builds']
            if 'data' in build_data:
                builds = build_data['data']

        return builds

    except Exception as e:
        console.print(f"[yellow]Failed to search Wago for {search_term}: {e}[/yellow]")
        return []


def import_missing_builds(test_mode=False):
    """Search for and import missing builds."""

    # Load missing builds
    missing_file = Path("missing_builds_test.json" if test_mode else "missing_builds.json")
    if not missing_file.exists():
        console.print("[red]No missing_builds.json file found. Run scrape_wiki_builds.py first.[/red]")
        return

    with open(missing_file) as f:
        missing_builds = json.load(f)

    if not missing_builds:
        console.print("[green]No missing builds to import![/green]")
        return

    console.print("[bold]Searching for Missing Builds on Wago.tools[/bold]\n")

    config = AppConfig()
    all_found_builds = {}
    # Builds found on Wago but with mismatched version -- need manual review
    version_mismatches: list[dict[str, str]] = []

    # Search for each missing build ID
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:

        for product_code, build_entries in missing_builds.items():
            # Support both old format (list of IDs) and new format (dict of ID->version)
            if isinstance(build_entries, list):
                build_map: dict[str, str] = {bid: '' for bid in build_entries}
            else:
                build_map = build_entries

            task = progress.add_task(f"Searching {product_code}", total=len(build_map))

            found_for_product = []

            for build_id, expected_patch in build_map.items():
                progress.update(task, description=f"Searching {product_code}: Build {build_id}")

                # Search Wago using build ID
                builds = parse_wago_search(build_id)

                if builds:
                    matching_builds = []
                    acceptable = _ACCEPTABLE_PRODUCTS.get(product_code, {product_code})
                    version_verified = _VERSION_VERIFIED_PRODUCTS.get(product_code, set())

                    for build in builds:
                        version = build.get('version', '')
                        if '.' not in version:
                            continue
                        parts = version.split('.')
                        if parts[-1] != build_id:
                            continue

                        build_product = build.get('product', '')
                        wago_patch = '.'.join(parts[:-1])

                        if build_product in acceptable:
                            # Direct product match -- accept
                            build['product'] = product_code
                            matching_builds.append(build)
                        elif build_product in version_verified:
                            # PTR/Beta product -- accept only if patch version
                            # matches to avoid build number collisions
                            if expected_patch and wago_patch == expected_patch:
                                build['product'] = product_code
                                matching_builds.append(build)
                                console.print(
                                    f"  [cyan]~[/cyan] Build {build_id}: "
                                    f"Matched via {build_product} "
                                    f"(version {version} verified)"
                                )

                    if matching_builds:
                        found_for_product.extend(matching_builds)
                        console.print(f"  [green]✓[/green] Build {build_id}: Found {len(matching_builds)} matching entries")
                    else:
                        # Collect version-mismatched entries for manual review
                        has_mismatch = False
                        for build in builds:
                            version = build.get('version', '')
                            if '.' not in version:
                                continue
                            parts = version.split('.')
                            if parts[-1] != build_id:
                                continue
                            wago_patch = '.'.join(parts[:-1])
                            build_product = build.get('product', '')
                            version_mismatches.append({
                                'target_product': product_code,
                                'build_id': build_id,
                                'expected_version': f"{expected_patch}.{build_id}" if expected_patch else f"?.{build_id}",
                                'wago_version': version,
                                'wago_product': build_product,
                                'build_config': build.get('build_config', ''),
                                'cdn_config': build.get('cdn_config', ''),
                            })
                            has_mismatch = True
                        if has_mismatch:
                            console.print(f"  [yellow]?[/yellow] Build {build_id}: Version mismatch (needs manual review)")
                        else:
                            console.print(f"  [yellow]⚠[/yellow] Build {build_id}: Found entries but none matching product/version")
                else:
                    console.print(f"  [red]✗[/red] Build {build_id}: No results found")

                progress.advance(task)

                # Be nice to the server
                time.sleep(0.5)

            if found_for_product:
                all_found_builds[product_code] = found_for_product

    # Import found builds
    if all_found_builds:
        console.print("\n[cyan]Importing found builds into database...[/cyan]")

        with WagoClient(config) as client:
            # Convert to WagoBuild objects
            builds_to_import = []

            for product_code, builds in all_found_builds.items():
                for build in builds:
                    # Create WagoBuild object
                    try:
                        version = build.get('version', '')
                        # Extract build number from version (e.g., "11.2.5.63092" -> "63092")
                        build_number = version.split('.')[-1] if '.' in version else ''

                        # Use the product directly from the search results
                        # Since we already filtered to only exact matches, we can trust the product field
                        normalized_product = build.get('product', product_code)

                        # Handle build_time conversion
                        build_time = None
                        if build.get('created_at'):
                            try:
                                # Parse the datetime string
                                if isinstance(build['created_at'], str):
                                    # Try parsing the format "2025-09-11 02:10:05"
                                    build_time = datetime.strptime(
                                        build['created_at'], "%Y-%m-%d %H:%M:%S"
                                    ).replace(tzinfo=UTC)
                            except ValueError:
                                # Try ISO format as fallback
                                try:
                                    build_time = datetime.fromisoformat(
                                        build['created_at'].replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass

                        wago_build = WagoBuild(
                            id=build.get('id', 0),
                            build=build_number,
                            version=version,
                            product=normalized_product,
                            build_time=build_time,
                            build_config=build.get('build_config'),
                            cdn_config=build.get('cdn_config'),
                            product_config=build.get('product_config'),
                            encoding_ekey=build.get('config', {}).get('encoding') if isinstance(build.get('config'), dict) else None,
                            root_ekey=build.get('config', {}).get('root') if isinstance(build.get('config'), dict) else None
                        )
                        builds_to_import.append(wago_build)
                        console.print(f"  [green]✓[/green] Prepared: {wago_build.version} ({wago_build.product})")
                    except Exception as e:
                        console.print(f"  [red]✗[/red] Failed to prepare {build.get('version')}: {e}")

            # Import all builds at once
            if builds_to_import:
                stats = client.import_builds_to_database(builds_to_import)
                console.print("\n[bold green]Import Complete[/bold green]")
                console.print(f"  Fetched: {stats['fetched']}")
                console.print(f"  Imported: {stats['imported']}")
                console.print(f"  Updated: {stats['updated']}")
                console.print(f"  Skipped: {stats['skipped']}")

    else:
        console.print("\n[yellow]No builds found to import[/yellow]")

    # Report version-mismatched builds that need manual investigation
    if version_mismatches:
        console.print("\n[bold yellow]Builds Requiring Manual Investigation[/bold yellow]")
        console.print(
            "These builds are on the wiki as live but Wago has them under a "
            "different version or product. Build configs may or may not match "
            "the actual live build. Use 'cascette builds add' to add them "
            "manually after verification.\n"
        )

        from rich.table import Table

        table = Table(title="Version Mismatches")
        table.add_column("Product", style="cyan")
        table.add_column("Build", style="green")
        table.add_column("Expected Version", style="yellow")
        table.add_column("Wago Version", style="red")
        table.add_column("Wago Product")
        table.add_column("Build Config")
        table.add_column("CDN Config")

        for m in version_mismatches:
            table.add_row(
                m['target_product'],
                m['build_id'],
                m['expected_version'],
                m['wago_version'],
                m['wago_product'],
                m['build_config'][:16] + '...' if m['build_config'] else '',
                m['cdn_config'][:16] + '...' if m['cdn_config'] else '',
            )

        console.print(table)

        console.print(
            "\nTo add a build manually after verifying the config hashes:\n"
            "  cascette builds add --product wow --version 10.1.5.50793 "
            "--build-config <hash> --cdn-config <hash>"
        )


def main():
    """Main entry point."""
    import sys
    test_mode = '--test' in sys.argv
    import_missing_builds(test_mode=test_mode)


if __name__ == "__main__":
    main()
