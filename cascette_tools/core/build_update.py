"""Build update delta logic for incremental CASC installations.

Agent.exe's BuildUpdateInitState compares old and new encoding files to
classify each file as unchanged (0), needs_download (1), or obsolete (6).
Instead of loading two full encoding files, we compare the new encoding
file against the ecache from the previous install which stores CKey→EKey
mappings on disk.

Patching (Agent.exe classification value 2) is deferred to Phase 8.
Files that could be patched are classified as needs_download instead.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

import structlog

from cascette_tools.core.encoding_cache import EncodingCache
from cascette_tools.formats.config import BuildConfig
from cascette_tools.formats.encoding import EncodingFile, EncodingParser

logger = structlog.get_logger()


class FileClassification(enum.Enum):
    """Classification of a file during build update comparison.

    Maps to Agent.exe entry+0x4e values:
    - 0 = unchanged (CKey exists in old ecache with same EKey)
    - 1 = needs_download (CKey missing from old ecache or EKey differs)
    - 6 = obsolete (CKey in old ecache but not in new encoding)
    """

    unchanged = 0
    needs_download = 1
    obsolete = 6


@dataclass
class BuildDelta:
    """Result of comparing old ecache against new encoding file."""

    classifications: dict[bytes, FileClassification] = field(
        default_factory=lambda: dict[bytes, FileClassification]()
    )
    new_ekeys: dict[bytes, bytes] = field(
        default_factory=lambda: dict[bytes, bytes]()
    )
    obsolete_ekeys: list[tuple[bytes, bytes]] = field(
        default_factory=lambda: list[tuple[bytes, bytes]]()
    )
    unchanged_count: int = 0
    download_count: int = 0
    obsolete_count: int = 0


def compare_configs(
    old: BuildConfig, new: BuildConfig
) -> dict[str, tuple[str | None, str | None]]:
    """Compare key fields between two build configs.

    Returns field → (old_value, new_value) for fields that differ.
    Informational only — used for logging which manifests changed.
    """
    diff: dict[str, tuple[str | None, str | None]] = {}

    fields = [
        ("encoding", old.encoding, new.encoding),
        ("root", old.root, new.root),
        ("install", old.install, new.install),
        ("download", old.download, new.download),
        ("size", old.size, new.size),
    ]

    for name, old_val, new_val in fields:
        if old_val != new_val:
            diff[name] = (old_val, new_val)

    return diff


def classify_files(
    old_ecache: EncodingCache,
    new_encoding_data: bytes,
    new_encoding_file: EncodingFile,
    encoding_parser: EncodingParser,
) -> BuildDelta:
    """Classify files by comparing old ecache against new encoding file.

    Steps:
    1. Iterate all CKey pages of new encoding → build new_ckeys dict
    2. For each CKey, check old_ecache.lookup():
       - Match with same EKey → unchanged
       - No match or EKey differs → needs_download
    3. Find CKeys in old_ecache not in new encoding → obsolete

    Args:
        old_ecache: Encoding cache from previous install
        new_encoding_data: Raw bytes of new encoding file
        new_encoding_file: Parsed new encoding file structure
        encoding_parser: Parser instance for loading CKey pages

    Returns:
        BuildDelta with all classifications
    """
    delta = BuildDelta()

    # Step 1+2: Iterate new encoding pages, classify against old ecache
    new_ckeys: set[bytes] = set()

    for page_idx in range(new_encoding_file.header.ckey_page_count):
        page = encoding_parser.load_ckey_page_sequential(
            new_encoding_data, new_encoding_file, page_idx, max_entries=10000
        )
        for entry in page.entries:
            ckey = entry.content_key
            new_ckeys.add(ckey)

            if not entry.encoding_keys:
                continue

            new_ekey = entry.encoding_keys[0]
            old_entry = old_ecache.lookup(ckey)

            if old_entry is not None and old_entry.encoding_key == new_ekey:
                delta.classifications[ckey] = FileClassification.unchanged
                delta.unchanged_count += 1
            else:
                delta.classifications[ckey] = FileClassification.needs_download
                delta.new_ekeys[ckey] = new_ekey
                delta.download_count += 1

    # Step 3: Find obsolete entries (in old ecache but not in new encoding)
    for bucket_entries in old_ecache.buckets.values():
        for ecache_entry in bucket_entries:
            if ecache_entry.content_key not in new_ckeys:
                delta.classifications[ecache_entry.content_key] = (
                    FileClassification.obsolete
                )
                delta.obsolete_ekeys.append(
                    (ecache_entry.content_key, ecache_entry.encoding_key)
                )
                delta.obsolete_count += 1

    logger.info(
        "Build delta computed",
        unchanged=delta.unchanged_count,
        download=delta.download_count,
        obsolete=delta.obsolete_count,
    )
    return delta
