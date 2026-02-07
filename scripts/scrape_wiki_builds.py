#!/usr/bin/env python3
"""Scrape public client builds from Warcraft Wiki - improved version."""

import json
import re
import sqlite3
import sys
from pathlib import Path

# Add parent directory to path to import cascette_tools if needed
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()


def scrape_wiki_builds():
    """Scrape public client builds from Warcraft Wiki.

    Returns:
        Dict with product category keys mapping to lists of build IDs.
        Categories: retail, classic, classic_era, classic_titan, anniversary
    """
    console.print("[cyan]Fetching Warcraft Wiki Public client builds page...[/cyan]")

    url = "https://warcraft.wiki.gg/wiki/Public_client_builds"
    response = httpx.get(url, headers={"User-Agent": "cascette-tools/1.0"})
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')

    builds = {
        'retail': set(),  # Use sets to avoid duplicates
        'classic': set(),
        'classic_era': set(),
        'classic_titan': set(),
        'anniversary': set()
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
            # We skip pre-6.0 retail builds and builds without versions
            if not version:
                # Skip builds without a parseable version - can't verify NGDP support
                continue

            # Pre-check row text for categorization (needed for 2.x-5.x filtering)
            is_retail_row = any(term in row_text for term in ['retail', 'live'])
            is_classic_era_row = 'classic era' in row_text or 'classic-era' in row_text
            is_anniversary_row = 'anniversary' in row_text
            is_titan_row = 'titan' in row_text
            is_classic_row = 'classic' in row_text and not is_classic_era_row and not is_anniversary_row and not is_titan_row

            try:
                major_version = int(version.split('.')[0])

                # Check if this is a Classic version (1.x)
                if major_version == 1:
                    # Classic 1.13+ uses NGDP, earlier 1.x versions don't
                    parts = version.split('.')
                    if len(parts) >= 2:
                        minor = int(parts[1])
                        if minor < 13:
                            continue  # Skip pre-1.13 (original vanilla, uses MPQ)
                elif major_version >= 2 and major_version < 6:
                    # 2.x through 5.x versions:
                    # - Original retail TBC/Wrath/Cata/MoP: NO NGDP (skip)
                    # - Classic re-releases (TBC Classic, etc.): YES NGDP (keep)
                    # - Classic Titan (3.80.x): YES NGDP (keep)
                    # - Anniversary (2.5.5.x): YES NGDP (keep)
                    # Only keep if explicitly marked as classic/titan/anniversary
                    if not is_classic_row and not is_classic_era_row and not is_titan_row and not is_anniversary_row:
                        continue  # Skip original retail 2.x-5.x (pre-NGDP)
                elif major_version < 6:
                    # Any other version < 6.0 is pre-NGDP retail
                    continue
                # 6.0+ retail uses NGDP - keep these
            except (ValueError, IndexError):
                # If we can't parse the version, skip it (safer approach)
                continue

            # Categorize based on row content and version
            is_retail = is_retail_row
            is_classic_era = is_classic_era_row
            is_classic = is_classic_row
            is_titan = is_titan_row
            is_anniversary = is_anniversary_row

            # If no explicit category but we have version, categorize by version number
            if version and not (is_retail or is_classic or is_classic_era or is_titan or is_anniversary):
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
                elif version.startswith('3.80.'):
                    # Classic Titan uses 3.80.x (distinct from WotLK Classic 3.4.x)
                    is_titan = True
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
            if is_titan:
                builds['classic_titan'].add(build_id)
            if is_anniversary:
                builds['anniversary'].add(build_id)

            # If still uncategorized, use version to determine category
            # Only 6.0+ can be added without explicit category (those are retail NGDP)
            # 2.x-5.x should already be filtered out if not explicitly "classic"
            if not (is_retail or is_classic or is_classic_era or is_titan or is_anniversary):
                if major_version >= 6:
                    builds['retail'].add(build_id)
                # Note: 2.x-5.x without explicit "classic" were already skipped above

    # Convert sets to sorted lists
    result = {
        'retail': sorted(builds['retail']),
        'classic': sorted(builds['classic']),
        'classic_era': sorted(builds['classic_era']),
        'classic_titan': sorted(builds['classic_titan']),
        'anniversary': sorted(builds['anniversary'])
    }

    return result


def get_database_builds(product_code):
    """Get existing build IDs from database.

    Args:
        product_code: Product code (wow, wow_classic, wow_classic_era,
            wow_classic_titan, wow_anniversary)

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
    for category, label in [
        ('retail', 'Retail'),
        ('classic', 'Classic'),
        ('classic_era', 'Classic Era'),
        ('classic_titan', 'Classic Titan'),
        ('anniversary', 'Anniversary'),
    ]:
        count = len(wiki_builds[category])
        if count > 0:
            examples = ', '.join(wiki_builds[category][:5])
            console.print(f"  {label}: {count} unique build IDs (e.g. {examples})")
        else:
            console.print(f"  {label}: 0 unique build IDs")

    # Map product names
    product_map = {
        'retail': 'wow',
        'classic': 'wow_classic',
        'classic_era': 'wow_classic_era',
        'classic_titan': 'wow_classic_titan',
        'anniversary': 'wow_anniversary'
    }

    missing_builds = {}

    console.print("\n[cyan]Checking database for missing build IDs...[/cyan]")

    for wiki_product, db_product in product_map.items():
        # Get database builds
        db_builds = get_database_builds(db_product)
        console.print(f"  {db_product}: {len(db_builds)} builds in database")

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
