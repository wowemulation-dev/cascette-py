#!/usr/bin/env python3
"""Scrape public client builds from Warcraft Wiki - improved version."""

import json
import re
import sqlite3
import sys
from pathlib import Path

# Add parent directory to path to import cascette_tools if needed
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()


def scrape_wiki_builds():
    """Scrape public client builds from Warcraft Wiki.

    Returns:
        Dict with 'retail', 'classic', and 'classic_era' lists of build IDs
    """
    console.print("[cyan]Fetching Warcraft Wiki Public client builds page...[/cyan]")

    url = "https://warcraft.wiki.gg/wiki/Public_client_builds"
    response = requests.get(url, headers={"User-Agent": "cascette-tools/1.0"})
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')

    builds = {
        'retail': set(),  # Use sets to avoid duplicates
        'classic': set(),
        'classic_era': set()
    }

    # Find all tables with darktable class
    tables = soup.find_all('table', class_='darktable')
    console.print(f"Found {len(tables)} tables on page")

    for _table_num, table in enumerate(tables, 1):
        # Process each row
        rows = table.find_all('tr')  # type: ignore[union-attr]

        for row in rows:
            cells = row.find_all('td')  # type: ignore[union-attr]
            if len(cells) < 2:  # Need at least 2 cells for data
                continue

            # Extract all text from the row to get full context
            row_text = ' '.join(cell.get_text().strip() for cell in cells).lower()

            # Look for build ID and version in individual cells
            build_id = None
            version = None

            for cell in cells:
                cell_text = cell.get_text().strip()

                # Check for standalone build number (e.g., "19027")
                if re.match(r'^\d{4,6}$', cell_text):
                    build_id = cell_text

                # Check for version with build (e.g., "6.0.2.19027")
                version_match = re.match(r'^(\d+\.\d+\.\d+)\.(\d+)$', cell_text)
                if version_match:
                    version = version_match.group(1)
                    if not build_id:  # Extract build from full version if needed
                        build_id = version_match.group(2)

                # Simple version without build (e.g., "6.0.2")
                elif re.match(r'^\d+\.\d+\.\d+$', cell_text):
                    version = cell_text

            # Skip if we don't have a build ID
            if not build_id:
                continue

            # Filter based on NGDP support
            # NGDP was introduced with:
            # - Retail: 6.0+ (Warlords of Draenor)
            # - Classic: 1.13+ (2019 re-release uses NGDP)
            # - Classic Era: 1.13.7+ (also uses NGDP)
            # We skip pre-6.0 retail builds as they use MPQ
            if version:
                try:
                    # Check if this is a Classic version (1.13+)
                    if version.startswith('1.'):
                        # Classic 1.13+ uses NGDP, earlier 1.x versions don't
                        parts = version.split('.')
                        if len(parts) >= 2:
                            minor = int(parts[1])
                            if minor < 13:
                                continue  # Skip pre-1.13 (original vanilla, uses MPQ)
                    else:
                        # For non-Classic versions, skip pre-6.0
                        major_version = int(version.split('.')[0])
                        if major_version >= 2 and major_version < 6:
                            # Skip 2.x through 5.x (TBC through MoP, all use MPQ)
                            continue
                except (ValueError, IndexError):
                    # If we can't parse the version, keep it (conservative approach)
                    pass

            # Categorize based on row content and version
            # Check if this row is for retail/live
            is_retail = any(term in row_text for term in ['retail', 'live', 'release'])
            is_classic_era = 'classic era' in row_text or 'classic-era' in row_text
            is_classic = 'classic' in row_text and not is_classic_era

            # If no explicit category but we have version, categorize by version number
            if version and not (is_retail or is_classic or is_classic_era):
                if version.startswith(('1.13', '1.14', '1.15')):
                    # Classic Era versions (1.13.7+ is Era, earlier 1.13.x was Classic)
                    if version.startswith('1.13.'):
                        parts = version.split('.')
                        if len(parts) >= 3:
                            try:
                                patch = int(parts[2])
                                if patch >= 7:
                                    is_classic_era = True
                                else:
                                    is_classic = True  # 1.13.0-1.13.6 was original Classic
                            except ValueError:
                                is_classic = True  # Default to Classic for 1.13.x
                    else:
                        is_classic_era = True  # 1.14.x and 1.15.x are Era
                elif version.startswith(('2.', '3.', '4.', '5.')):
                    # Classic progression servers (TBC Classic, Wrath Classic, etc.)
                    is_classic = True
                else:
                    # 6.x and higher are retail
                    try:
                        major = int(version.split('.')[0])
                        if major >= 6:
                            is_retail = True
                    except (ValueError, IndexError):
                        pass

            # Add to appropriate categories (a build can be in multiple categories)
            if is_retail:
                builds['retail'].add(build_id)
            if is_classic:
                builds['classic'].add(build_id)
            if is_classic_era:
                builds['classic_era'].add(build_id)

            # If still uncategorized but has "retail" or "live" anywhere in row, add to retail
            if not (is_retail or is_classic or is_classic_era):
                if 'retail' in row_text or 'live' in row_text:
                    builds['retail'].add(build_id)

    # Convert sets to sorted lists
    result = {
        'retail': sorted(builds['retail']),
        'classic': sorted(builds['classic']),
        'classic_era': sorted(builds['classic_era'])
    }

    return result


def get_database_builds(product_code):
    """Get existing build IDs from database.

    Args:
        product_code: Product code (wow, wow_classic, wow_classic_era)

    Returns:
        Set of build IDs
    """
    db_path = Path.home() / ".local" / "share" / "cascette-tools" / "wago_builds.db"

    if not db_path.exists():
        console.print(f"[red]Database not found at {db_path}[/red]")
        return set()

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Get all build IDs for the product
    cursor.execute(
        "SELECT DISTINCT build FROM builds WHERE product = ?",
        (product_code,)
    )

    builds = set()
    for row in cursor.fetchall():
        if row[0]:  # Ensure build ID is not null
            builds.add(str(row[0]))

    conn.close()
    return builds


def find_missing_builds():
    """Find missing builds by comparing wiki with database."""

    # Scrape wiki
    wiki_builds = scrape_wiki_builds()

    console.print("\n[green]Found on Warcraft Wiki:[/green]")
    console.print(f"  Retail: {len(wiki_builds['retail'])} unique build IDs")
    console.print(f"  Classic: {len(wiki_builds['classic'])} unique build IDs")
    console.print(f"  Classic Era: {len(wiki_builds['classic_era'])} unique build IDs")

    # Show some examples including 19027 if present
    if wiki_builds['retail']:
        examples = wiki_builds['retail'][:5]
        if '19027' in wiki_builds['retail']:
            console.print("  [bold green]Build 19027 found in retail list![/bold green]")
            if '19027' not in examples:
                examples = ['19027'] + examples[:4]
        console.print(f"  Retail examples: {', '.join(examples)}")
    if wiki_builds['classic']:
        console.print(f"  Classic examples: {', '.join(wiki_builds['classic'][:5])}")
    if wiki_builds['classic_era']:
        console.print(f"  Classic Era examples: {', '.join(wiki_builds['classic_era'][:5])}")

    # Map product names
    product_map = {
        'retail': 'wow',
        'classic': 'wow_classic',
        'classic_era': 'wow_classic_era'
    }

    missing_builds = {}

    console.print("\n[cyan]Checking database for missing build IDs...[/cyan]")

    for wiki_product, db_product in product_map.items():
        # Get database builds
        db_builds = get_database_builds(db_product)
        console.print(f"  {db_product}: {len(db_builds)} builds in database")

        # Check if 19027 is in database
        if db_product == 'wow' and '19027' in db_builds:
            console.print("    [green]Build 19027 already in database[/green]")

        # Find missing
        wiki_build_ids = set(wiki_builds[wiki_product])
        missing = wiki_build_ids - db_builds

        if missing:
            missing_builds[db_product] = sorted(missing)

    # Display results
    console.print("\n[bold]Missing Builds Analysis[/bold]\n")

    table = Table(title="Missing Builds by Product")
    table.add_column("Product", style="cyan")
    table.add_column("Missing Count", style="yellow")
    table.add_column("Build ID Examples", style="green")

    for product, missing in missing_builds.items():
        if missing:
            examples = missing[:5]
            # Highlight if 19027 is missing
            if '19027' in missing and '19027' not in examples:
                examples = ['19027'] + examples[:4]
            examples_str = ', '.join(examples)
            if len(missing) > 5:
                examples_str += f", ... ({len(missing) - 5} more)"
            table.add_row(product, str(len(missing)), examples_str)

    if missing_builds:
        console.print(table)
    else:
        console.print("[green]No missing builds found! Database is complete.[/green]")

    return missing_builds


def main():
    """Main entry point."""
    missing = find_missing_builds()

    # Save to file for next step
    if missing:
        with open("missing_builds.json", "w") as f:
            json.dump(missing, f, indent=2)

        console.print("\n[cyan]Missing build IDs saved to missing_builds.json[/cyan]")

        # Show totals
        total = sum(len(builds) for builds in missing.values())
        console.print(f"[bold]Total missing builds to search: {total}[/bold]")


if __name__ == "__main__":
    main()
