"""Delta logic for containerless (loose file) installations.

Parallel to build_update.py which handles CASC-mode updates. Compares
on-disk files against a file database to classify what needs downloading.

Agent.exe's containerless update (Op 39) hashes each on-disk file and
compares against the file database content keys. Files are classified as:
- unchanged: exists on disk with matching MD5
- needs_download: missing or MD5 differs
- obsolete: in old DB but not new DB
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import structlog
from rich.console import Console

from cascette_tools.formats.file_db import FileDatabase, FileDbEntry

logger = structlog.get_logger()


class ContainerlessClassification(enum.Enum):
    """Classification of a file during containerless update comparison."""

    unchanged = 0
    needs_download = 1
    obsolete = 6


def _file_db_entry_list() -> list[FileDbEntry]:
    """Factory for typed empty list of FileDbEntry."""
    return []


def _str_list() -> list[str]:
    """Factory for typed empty list of str."""
    return []


@dataclass
class ContainerlessDelta:
    """Result of comparing on-disk files against a file database."""

    download_entries: list[FileDbEntry] = field(default_factory=_file_db_entry_list)
    obsolete_paths: list[str] = field(default_factory=_str_list)
    unchanged_count: int = 0
    download_count: int = 0
    obsolete_count: int = 0


def identify_existing_files(
    base_path: Path,
    file_db: FileDatabase,
    console: Console | None = None,
) -> dict[int, bytes]:
    """Hash all on-disk files referenced by the file database.

    Args:
        base_path: Installation base directory
        file_db: File database with entries to check
        console: Optional console for progress output

    Returns:
        Dictionary mapping file_index → actual MD5 hash.
        Missing files are omitted from the result.
    """
    result: dict[int, bytes] = {}
    total = len(file_db.entries)
    checked = 0

    for entry in file_db.entries:
        rel_path = entry.relative_path.replace('\\', '/')
        full_path = base_path / rel_path

        if full_path.exists():
            actual_md5 = hashlib.md5(full_path.read_bytes()).digest()
            result[entry.file_index] = actual_md5

        checked += 1
        if console and checked % 1000 == 0:
            console.print(f"  Identified {checked}/{total} files...")

    if console:
        console.print(f"  Identified {len(result)}/{total} files on disk")

    return result


def classify_containerless_files(
    base_path: Path,
    old_file_db: FileDatabase | None,
    new_file_db: FileDatabase,
    console: Console | None = None,
) -> ContainerlessDelta:
    """Classify files as unchanged/needs_download/obsolete.

    Compares on-disk files against the new file database:
    1. Hash existing files
    2. For each entry in new DB:
       - If on-disk MD5 matches ckey → unchanged
       - Otherwise → needs_download
    3. If old DB provided, entries in old DB but not new DB → obsolete

    Args:
        base_path: Installation base directory
        old_file_db: Previous file database (None for fresh install)
        new_file_db: New file database from updated build
        console: Optional console for progress output

    Returns:
        ContainerlessDelta with classified entries
    """
    delta = ContainerlessDelta()

    # Step 1: Hash existing files against new DB
    existing_hashes = identify_existing_files(base_path, new_file_db, console)

    # Step 2: Classify new entries
    for entry in new_file_db.entries:
        actual_md5 = existing_hashes.get(entry.file_index)

        if actual_md5 is not None and actual_md5 == entry.ckey:
            delta.unchanged_count += 1
        else:
            delta.download_entries.append(entry)
            delta.download_count += 1

    # Step 3: Find obsolete entries
    if old_file_db is not None:
        new_paths: set[str] = {
            e.relative_path.replace('\\', '/') for e in new_file_db.entries
        }
        for entry in old_file_db.entries:
            normalized = entry.relative_path.replace('\\', '/')
            if normalized not in new_paths:
                delta.obsolete_paths.append(normalized)
                delta.obsolete_count += 1

    logger.info(
        "Containerless delta computed",
        unchanged=delta.unchanged_count,
        download=delta.download_count,
        obsolete=delta.obsolete_count,
    )
    return delta
