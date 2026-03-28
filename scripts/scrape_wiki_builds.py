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


def _is_live_build(server: str, phase: str) -> bool:
    """Check if a build was deployed to a live/production server.

    The Server column is the authoritative source for determining whether a
    build reached production. The Phase column alone is not sufficient because
    the wiki uses Phase="Live" for builds that went live *on PTR* as well.

    A build is considered live if the Server column includes at least one
    production server name (Retail, Classic, Classic Era, Classic Anniversary,
    Classic Titan) that is not qualified by PTR/Test/Beta/Alpha.
    """
    live_server_names = ['retail', 'classic era', 'classic anniversary',
                         'classic titan', 'classic']
    test_indicators = ['ptr', 'test', 'beta', 'alpha', 'dev', 'vendor',
                       'submission', 'demo', 'blizzcon', 'internal',
                       'event 1', 'live test']

    server_lower = server.lower()
    server_parts = [s.strip() for s in server_lower.split(',')]

    for part in server_parts:
        # Skip parts that contain test/ptr indicators
        is_test = any(indicator in part for indicator in test_indicators)
        if is_test:
            continue
        # Check if this part names a live server
        if any(name == part for name in live_server_names):
            return True

    # Fallback: some older tables use "Retail" as the Phase value combined
    # with "Test, Retail" in Server (where we already matched "Retail" above).
    # Also handle Phase="Retail" when Server column is absent or empty.
    if not server.strip():
        phase_lower = phase.lower()
        if phase_lower == 'retail' or 'live' in phase_lower:
            return True

    return False


def _get_product_from_server(server: str) -> str | None:
    """Determine the product code from a Server column value.

    Returns the product key (retail, classic, classic_era, classic_titan,
    anniversary) or None if the server value doesn't map to a known product.
    """
    server_lower = server.lower()
    parts = [s.strip() for s in server_lower.split(',')]

    for part in parts:
        if part == 'classic anniversary':
            return 'anniversary'
        if part == 'classic titan' or part == 'classic titan reforged':
            return 'classic_titan'
        if part == 'classic era':
            return 'classic_era'
        if part == 'retail':
            return 'retail'
        if part == 'classic':
            return 'classic'

    return None


# Section heading to default product mapping.
# The h3 heading determines the product for Classic sub-sections.
# Retail expansion tables (h2-level) all map to 'retail'.
_SECTION_PRODUCT_MAP: dict[str, str] = {
    # h3 headings under "Classic"
    'Mists of Pandaria Classic': 'classic',
    'Cataclysm Classic': 'classic',
    'Titan Reforged': 'classic_titan',
    'Wrath of the Lich King Classic': 'classic',
    'Burning Crusade Classic': '_mixed_tbc',  # needs per-row Server inspection
    'Classic Era': 'classic_era',
}

# h2 headings for retail expansions
_RETAIL_SECTIONS: set[str] = {
    'Midnight', 'The War Within', 'Dragonflight', 'Shadowlands',
    'Battle for Azeroth', 'Legion', 'Warlords of Draenor',
    'Mists of Pandaria', 'Cataclysm', 'Wrath of the Lich King',
    'The Burning Crusade', 'World of Warcraft',
}


def scrape_wiki_builds():
    """Scrape public client builds from Warcraft Wiki.

    Uses section headings (h2/h3) to determine which product each table
    belongs to, and filters out PTR/Beta/Alpha/Test builds by examining
    the Server and Phase columns.

    Returns:
        Dict with product category keys mapping to lists of build IDs.
        Categories: retail, classic, classic_era, classic_titan, anniversary
    """
    console.print("[cyan]Fetching Warcraft Wiki Public client builds page...[/cyan]")

    url = "https://warcraft.wiki.gg/wiki/Public_client_builds"
    response = httpx.get(url, headers={"User-Agent": "cascette-tools/1.0"})
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    content = soup.find('div', class_='mw-parser-output')
    if not content:
        content = soup

    # Maps product -> set of (build_id, patch_version) tuples.
    # patch_version is needed for version-aware matching during import
    # (build numbers can collide across products/versions).
    builds: dict[str, set[tuple[str, str]]] = {
        'retail': set(),
        'classic': set(),
        'classic_era': set(),
        'classic_titan': set(),
        'anniversary': set(),
    }

    # Walk through headings and tables in document order to associate each
    # table with its section heading.
    current_h2 = ''
    current_h3 = ''
    table_num = 0
    skipped_ptr = 0
    skipped_no_version = 0

    for elem in content.find_all(['h2', 'h3', 'table']):  # type: ignore[union-attr]
        tag = elem.name
        if tag == 'h2':
            headline = elem.find('span', class_='mw-headline')
            if headline:
                current_h2 = headline.get_text().strip()
                current_h3 = ''
            continue
        if tag == 'h3':
            headline = elem.find('span', class_='mw-headline')
            if headline:
                current_h3 = headline.get_text().strip()
            continue

        if tag != 'table' or 'darktable' not in (elem.get('class') or []):
            continue

        table_num += 1

        # Skip the summary "Current builds" table (table #1)
        if current_h2 == 'Current builds' and current_h3 == '':
            continue

        # Determine the default product for this table from section headings
        section_product = None
        if current_h3 and current_h3 in _SECTION_PRODUCT_MAP:
            section_product = _SECTION_PRODUCT_MAP[current_h3]
        elif current_h2 in _RETAIL_SECTIONS:
            section_product = 'retail'

        if section_product is None:
            # Unknown section, skip
            continue

        # Find column indices from header row
        headers = [th.get_text().strip().lower() for th in elem.find_all('th')]
        col_map: dict[str, int] = {}
        for i, h in enumerate(headers):
            if h in ('server', 'phase', 'version', 'patch', 'build'):
                col_map[h] = i

        server_idx = col_map.get('server')
        phase_idx = col_map.get('phase')
        version_idx = col_map.get('version')
        patch_idx = col_map.get('patch')

        for row in elem.find_all('tr'):
            cells = row.find_all('td')
            if len(cells) < 2:
                continue

            # Extract Server and Phase values
            server = ''
            phase = ''
            if server_idx is not None and server_idx < len(cells):
                server = cells[server_idx].get_text().strip()
            if phase_idx is not None and phase_idx < len(cells):
                phase = cells[phase_idx].get_text().strip()

            # Filter: only keep builds that reached live servers
            if not _is_live_build(server, phase):
                skipped_ptr += 1
                continue

            # Extract build ID from the Version column (build number)
            build_id = None
            if version_idx is not None and version_idx < len(cells):
                cell_text = cells[version_idx].get_text().strip()
                if re.match(r'^\d{4,6}$', cell_text):
                    build_id = cell_text

            if not build_id:
                # Try extracting from full version strings in any cell
                for cell in cells:
                    cell_text = cell.get_text().strip()
                    version_match = re.match(
                        r'^(\d+\.\d+\.\d+)\.(\d+)$', cell_text
                    )
                    if version_match:
                        build_id = version_match.group(2)
                        break
                    if re.match(r'^\d{4,6}$', cell_text):
                        build_id = cell_text
                        break

            if not build_id:
                skipped_no_version += 1
                continue

            # Extract patch version for NGDP filtering on retail tables.
            # Patch values may have letter suffixes (e.g. "4.0.1a").
            patch_version = None
            if patch_idx is not None and patch_idx < len(cells):
                ptext = cells[patch_idx].get_text().strip()
                pmatch = re.match(r'^(\d+\.\d+\.\d+)', ptext)
                if pmatch:
                    patch_version = pmatch.group(1)

            # For retail tables, skip pre-NGDP builds (before 6.0)
            if section_product == 'retail' and patch_version:
                try:
                    major = int(patch_version.split('.')[0])
                    if major < 6:
                        continue
                except (ValueError, IndexError):
                    pass

            # Use empty string if patch version is unknown
            pv = patch_version or ''

            # Determine the product for this specific row
            if section_product == '_mixed_tbc':
                # TBC Classic table has mixed Anniversary and Classic Era PTR rows.
                # Use the Server column to determine the actual product.
                row_product = _get_product_from_server(server)
                if row_product and row_product in builds:
                    builds[row_product].add((build_id, pv))
            else:
                builds[section_product].add((build_id, pv))

    console.print(f"Processed {table_num} tables")
    console.print(f"Skipped {skipped_ptr} PTR/Beta/Alpha/Test builds")
    console.print(f"Skipped {skipped_no_version} rows without build IDs")

    # Convert sets to sorted dicts: {build_id: patch_version}
    result: dict[str, dict[str, str]] = {}
    for category in ('retail', 'classic', 'classic_era',
                      'classic_titan', 'anniversary'):
        result[category] = {
            bid: pv
            for bid, pv in sorted(builds[category])
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
            example_ids = list(wiki_builds[category].keys())[:5]
            examples = ', '.join(example_ids)
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

    missing_builds: dict[str, dict[str, str]] = {}

    console.print("\n[cyan]Checking database for missing build IDs...[/cyan]")

    for wiki_product, db_product in product_map.items():
        # Get database builds
        db_builds = get_database_builds(db_product)
        console.print(f"  {db_product}: {len(db_builds)} builds in database")

        # Find missing: build IDs on wiki but not in database
        wiki_build_map = wiki_builds[wiki_product]
        missing_ids = set(wiki_build_map.keys()) - db_builds

        if missing_ids:
            # Preserve patch version info for version-aware import
            missing_builds[db_product] = {
                bid: wiki_build_map[bid]
                for bid in sorted(missing_ids)
            }

    # Display results
    console.print("\n[bold]Missing Builds Analysis[/bold]\n")

    table = Table(title="Missing Builds by Product")
    table.add_column("Product", style="cyan")
    table.add_column("Missing Count", style="yellow")
    table.add_column("Build ID Examples", style="green")

    for product, missing in missing_builds.items():
        if missing:
            examples = list(missing.keys())[:5]
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
        total = sum(len(bids) for bids in missing.values())
        console.print(f"[bold]Total missing builds to search: {total}[/bold]")


if __name__ == "__main__":
    main()
