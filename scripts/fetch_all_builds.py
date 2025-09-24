#!/usr/bin/env python3
"""Fetch all builds from database with manifests to populate EKEY fields."""

import csv
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Add parent directory to path to import cascette_tools
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table

console = Console()


def get_builds_by_product(product: str) -> list[tuple[int, str]]:
    """Get all builds for a specific product from database.

    Returns:
        List of (build_id, version) tuples
    """
    db_path = Path.home() / ".local" / "share" / "cascette-tools" / "wago_builds.db"

    if not db_path.exists():
        console.print(f"[red]Database not found at {db_path}[/red]")
        return []

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT DISTINCT build, version
        FROM builds
        WHERE product = ?
        ORDER BY CAST(build AS INTEGER)
        """,
        (product,)
    )

    builds = [(row[0], row[1]) for row in cursor.fetchall() if row[0]]
    conn.close()

    return builds


def check_ekeys_in_database(build_id: str, product: str) -> bool:
    """Check if EKEYs exist in database for a build.

    Args:
        build_id: Build ID to check
        product: Product code

    Returns:
        True if any EKEY is present
    """
    db_path = Path.home() / ".local" / "share" / "cascette-tools" / "wago_builds.db"

    if not db_path.exists():
        return False

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT encoding_ekey, root_ekey, install_ekey, download_ekey
        FROM builds
        WHERE product = ? AND build = ?
        """,
        (product, build_id)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        # Check if any EKEY is not null
        return any(ekey for ekey in result if ekey)
    return False


def fetch_build_with_timeout(build_id: str, product: str, timeout_seconds: int = 600) -> tuple[bool, str]:
    """Fetch a single build with timeout.

    Args:
        build_id: Build ID to fetch
        product: Product code (wow, wow_classic, wow_classic_era)
        timeout_seconds: Timeout in seconds (default 10 minutes)

    Returns:
        Tuple of (success, error_message)
    """
    # Check if EKEYs already exist before fetching
    had_ekeys_before = check_ekeys_in_database(build_id, product)

    cmd = [
        "cascette", "fetch", "build", build_id,
        "--product", product,
        "--include-manifests"
    ]

    try:
        # Run with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )

        # Check if successful
        if result.returncode == 0:
            # Check if EKEYs were populated after the fetch
            has_ekeys_after = check_ekeys_in_database(build_id, product)

            if has_ekeys_after:
                if had_ekeys_before:
                    return True, "EKEYs already existed"
                else:
                    return True, ""  # Successfully populated EKEYs
            else:
                # Check if download was mentioned in output
                if "Downloaded" in result.stdout:
                    return True, "Downloaded but no EKEYs stored"
                else:
                    return True, "No manifests available"
        else:
            # Command failed
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            # Extract key error messages
            if "404" in error_msg:
                return False, "404 - Build not found on CDN"
            elif "timeout" in error_msg.lower():
                return False, "Network timeout"
            elif "connection" in error_msg.lower():
                return False, "Connection error"
            else:
                # Truncate long error messages
                return False, error_msg[:100]

    except subprocess.TimeoutExpired:
        return False, f"Timeout after {timeout_seconds} seconds"
    except Exception as e:
        return False, str(e)[:100]


def fetch_all_builds(product: str, timeout_minutes: int = 10):
    """Fetch all builds for a product with manifests.

    Args:
        product: Product code to fetch
        timeout_minutes: Timeout per build in minutes
    """
    console.print(f"\n[bold cyan]Fetching all {product} builds with manifests[/bold cyan]")
    console.print(f"Timeout: {timeout_minutes} minutes per build\n")

    # Get builds from database
    builds = get_builds_by_product(product)

    if not builds:
        console.print(f"[red]No builds found for product {product}[/red]")
        return

    console.print(f"Found [green]{len(builds)}[/green] builds to fetch\n")

    # Prepare CSV for failures
    csv_path = Path(f"failed_builds_{product}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    csv_file = open(csv_path, 'w', newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['product', 'build_id', 'version', 'error_message', 'timestamp'])

    # Statistics
    successful = 0
    failed = 0
    skipped = 0

    # Process each build
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:

        task = progress.add_task(f"Fetching {product} builds", total=len(builds))

        for build_id, version in builds:
            progress.update(
                task,
                description=f"Fetching build {build_id} ({version})"
            )

            # Fetch the build
            success, error_msg = fetch_build_with_timeout(
                build_id,
                product,
                timeout_minutes * 60
            )

            if success:
                if not error_msg:
                    console.print(f"  [green]✓[/green]  Build {build_id}: Successfully populated EKEYs")
                    successful += 1
                elif "already existed" in error_msg:
                    console.print(f"  [cyan]○[/cyan]  Build {build_id}: {error_msg}")
                    skipped += 1
                else:
                    console.print(f"  [yellow]⚠[/yellow]  Build {build_id}: {error_msg}")
                    skipped += 1
            else:
                console.print(f"  [red]✗[/red]  Build {build_id}: {error_msg}")
                failed += 1

                # Write to CSV
                csv_writer.writerow([
                    product,
                    build_id,
                    version,
                    error_msg,
                    datetime.now().isoformat()
                ])
                csv_file.flush()  # Ensure data is written immediately

            progress.advance(task)

            # Small delay between requests to be nice to the server
            time.sleep(1)

    csv_file.close()

    # Print summary
    console.print("\n" + "=" * 60)
    console.print("[bold]Fetch Summary[/bold]")
    console.print("=" * 60)

    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")

    table.add_row("Total Builds", str(len(builds)))
    table.add_row("Successful", f"[green]{successful}[/green]")
    table.add_row("Failed", f"[red]{failed}[/red]")
    table.add_row("Skipped (no EKEYs)", f"[yellow]{skipped}[/yellow]")

    console.print(table)

    if failed > 0:
        console.print(f"\n[yellow]Failed builds saved to: {csv_path}[/yellow]")
    else:
        # Remove empty CSV if no failures
        csv_path.unlink()
        console.print("\n[green]All builds fetched successfully![/green]")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Fetch all builds with manifests")
    parser.add_argument(
        "--product",
        default="wow_classic_era",
        choices=["wow", "wow_classic", "wow_classic_era", "agent", "bna"],
        help="Product to fetch builds for (default: wow_classic_era)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout per build in minutes (default: 10)"
    )

    args = parser.parse_args()

    fetch_all_builds(args.product, args.timeout)


if __name__ == "__main__":
    main()