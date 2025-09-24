#!/usr/bin/env python3
"""Search for and import missing builds from Wago.tools."""

import html
import json
import re
import sys
import time
from datetime import datetime, UTC
from pathlib import Path

# Add parent directory to path to import cascette_tools
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from cascette_tools.core.config import AppConfig
from cascette_tools.database.wago import WagoBuild, WagoClient

console = Console()


def parse_wago_search(search_term: str) -> list[dict]:
    """Parse Wago.tools search results from HTML.

    Args:
        search_term: Search term like "11.2.5"

    Returns:
        List of build dictionaries
    """
    url = f"https://wago.tools/builds?search={search_term}"

    try:
        response = requests.get(url, headers={"User-Agent": "cascette-tools/1.0"}, timeout=30)
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

    # Search for each missing build ID
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:

        for product_code, build_ids in missing_builds.items():
            task = progress.add_task(f"Searching {product_code}", total=len(build_ids))

            found_for_product = []

            for build_id in build_ids:
                progress.update(task, description=f"Searching {product_code}: Build {build_id}")

                # Search Wago using build ID
                builds = parse_wago_search(build_id)

                if builds:
                    # Filter by matching build ID and product
                    matching_builds = []
                    for build in builds:
                        # Check if build ID matches
                        version = build.get('version', '')
                        if '.' in version:
                            # Extract build from version string
                            parts = version.split('.')
                            if parts[-1] == build_id:
                                build_product = build.get('product', '')

                                # Only accept builds from the exact product we're searching for
                                # We only support these three canonical products
                                if product_code == 'wow' and build_product == 'wow':
                                    matching_builds.append(build)
                                elif product_code == 'wow_classic' and build_product == 'wow_classic':
                                    matching_builds.append(build)
                                elif product_code == 'wow_classic_era' and build_product == 'wow_classic_era':
                                    matching_builds.append(build)

                    if matching_builds:
                        found_for_product.extend(matching_builds)
                        console.print(f"  [green]✓[/green] Build {build_id}: Found {len(matching_builds)} matching entries")
                    else:
                        console.print(f"  [yellow]⚠[/yellow] Build {build_id}: Found entries but none matching product")
                else:
                    console.print(f"  [red]✗[/red] Build {build_id}: No results found")

                progress.advance(task)

                # Be nice to the server
                time.sleep(0.5)  # Shorter delay since we're searching specific build IDs

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
                                except:
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


def main():
    """Main entry point."""
    import sys
    test_mode = '--test' in sys.argv
    import_missing_builds(test_mode=test_mode)


if __name__ == "__main__":
    main()
