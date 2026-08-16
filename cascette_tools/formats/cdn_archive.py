"""CDN archive index format parser.

This parser handles both types of CDN archive indices:
1. Regular CDN archive indices (4-byte offsets)
   - Used for individual archive files
   - Maps encoding keys to offsets within a single archive

2. Archive-groups (6-byte offsets: 2-byte archive index + 4-byte offset)
   - Client-generated mega-indices combining multiple CDN archives
   - Maps encoding keys to (archive_index, offset) pairs
   - Archive indices use hash-based assignment (0-65535)

The format is detected automatically based on the offset_bytes field in the footer.
Note: This is different from the legacy chunked archive format in archive.py.
"""

from __future__ import annotations

import hashlib
import struct
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class CdnArchiveEntry(BaseModel):
    """CDN archive index entry."""

    encoding_key: bytes = Field(description="Encoding key (variable length)")
    archive_index: int | None = Field(
        default=None, description="Archive index (only for archive-groups)"
    )
    offset: int = Field(description="Offset in archive data file")
    size: int = Field(description="Compressed size")


class CdnArchiveFooter(BaseModel):
    """CDN archive index footer."""

    toc_hash: bytes = Field(description="MD5 hash of table of contents (first 8 bytes)")
    version: int = Field(description="Index format version")
    reserved: bytes = Field(description="Reserved bytes")
    page_size_kb: int = Field(description="Page size in KB")
    offset_bytes: int = Field(
        description="Offset field size (4 for archives, 6 for archive-groups)"
    )
    size_bytes: int = Field(description="Compressed size field size")
    key_bytes: int = Field(description="Key length in bytes")
    footer_hash_bytes: int = Field(description="Footer hash length")
    entry_count: int = Field(description="Number of entries")
    footer_hash: bytes = Field(description="Footer hash")

    @property
    def is_archive_group(self) -> bool:
        """Check if this is an archive-group (6-byte offsets)."""
        return self.offset_bytes == 6


class CdnArchiveIndex(BaseModel):
    """Complete CDN archive index structure."""

    footer: CdnArchiveFooter = Field(description="Index footer")
    entries: list[CdnArchiveEntry] = Field(description="Archive entries")


class CdnArchiveParser(FormatParser[CdnArchiveIndex]):
    """Parser for CDN archive index and archive-group formats."""

    FOOTER_SIZE = 28  # Footer is always 28 bytes

    def parse(self, data: bytes | BinaryIO) -> CdnArchiveIndex:
        """Parse CDN archive index or archive-group file.

        Args:
            data: Binary data or stream

        Returns:
            Parsed CDN archive index
        """
        if isinstance(data, (bytes, bytearray)):
            all_data = bytes(data)
        else:
            # It's a stream
            current_pos = data.tell()
            all_data = data.read()
            data.seek(current_pos)

        # Parse footer first to determine format
        footer = self._parse_footer(all_data)

        # Parse entries based on format
        entries = self._parse_entries(all_data, footer)

        return CdnArchiveIndex(footer=footer, entries=entries)

    def _parse_footer(self, data: bytes) -> CdnArchiveFooter:
        """Parse archive index footer from end of file."""
        if len(data) < self.FOOTER_SIZE:
            raise ValueError(
                f"Data too short for footer: {len(data)} < {self.FOOTER_SIZE}"
            )

        # Footer is exactly 28 bytes at the end
        footer_data = data[-self.FOOTER_SIZE :]

        # Parse footer structure
        toc_hash = footer_data[0:8]  # First 8 bytes of MD5 hash
        version = footer_data[8]
        reserved = footer_data[9:11]
        page_size_kb = footer_data[11]
        offset_bytes = footer_data[12]  # 4 for archives, 6 for archive-groups
        size_bytes = footer_data[13]
        key_bytes = footer_data[14]  # Key length (variable: 9, 16, etc.)
        footer_hash_bytes = footer_data[15]

        # Validate version: Agent.exe CdnIndexFooterValidator requires version <= 1
        if version > 1:
            raise ValueError(
                f"Unsupported CDN index footer version {version}: must be 0 or 1"
            )

        # Entry count is little-endian (special case!)
        entry_count = struct.unpack("<I", footer_data[16:20])[0]

        # Footer hash (last 8 bytes)
        footer_hash = footer_data[20:28]

        logger.debug(
            "Parsed footer",
            version=version,
            offset_bytes=offset_bytes,
            key_bytes=key_bytes,
            entry_count=entry_count,
            is_archive_group=(offset_bytes == 6),
        )

        return CdnArchiveFooter(
            toc_hash=toc_hash,
            version=version,
            reserved=reserved,
            page_size_kb=page_size_kb,
            offset_bytes=offset_bytes,
            size_bytes=size_bytes,
            key_bytes=key_bytes,
            footer_hash_bytes=footer_hash_bytes,
            entry_count=entry_count,
            footer_hash=footer_hash,
        )

    def _parse_entries(
        self, data: bytes, footer: CdnArchiveFooter
    ) -> list[CdnArchiveEntry]:
        """Parse all entries from the archive index.

        CDN archive indices use the layout:
        ``[Pages][TOC keys][TOC hashes][Footer]``.
        Entry pages start at byte 0, each exactly ``page_size_kb * 1024``
        bytes with zero-padding. The TOC (last key per page + page hash)
        and footer follow after all pages. Entries must be read page-by-page
        to avoid interpreting padding bytes as entry data.
        """
        entries: list[CdnArchiveEntry] = []

        entry_size = footer.key_bytes + footer.offset_bytes + footer.size_bytes
        page_size = footer.page_size_kb * 1024
        entries_per_page = page_size // entry_size

        remaining = footer.entry_count
        page_idx = 0

        while remaining > 0:
            page_offset = page_idx * page_size
            entries_this_page = min(entries_per_page, remaining)

            for i in range(entries_this_page):
                pos = page_offset + (i * entry_size)

                # Parse encoding key
                encoding_key = data[pos : pos + footer.key_bytes]
                pos += footer.key_bytes

                # Parse size (big-endian, always 4 bytes, comes BEFORE offset)
                size = struct.unpack(">I", data[pos : pos + 4])[0]
                pos += footer.size_bytes

                # Parse offset (big-endian, 4 or 6 bytes)
                if footer.is_archive_group:
                    archive_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    offset = struct.unpack(">I", data[pos + 2 : pos + 6])[0]
                else:
                    archive_index = None
                    offset = struct.unpack(">I", data[pos : pos + 4])[0]
                pos += footer.offset_bytes

                # Skip zero entries
                if encoding_key == b"\x00" * footer.key_bytes:
                    continue

                entries.append(
                    CdnArchiveEntry(
                        encoding_key=encoding_key,
                        archive_index=archive_index,
                        offset=offset,
                        size=size,
                    )
                )

            remaining -= entries_this_page
            page_idx += 1

        logger.info(
            f"Parsed {'archive-group' if footer.is_archive_group else 'archive index'}",
            total_entries=len(entries),
            expected_entries=footer.entry_count,
        )

        return entries

    def find_entry(
        self, obj: CdnArchiveIndex, encoding_key: bytes
    ) -> CdnArchiveEntry | None:
        """Find entry by encoding key.

        Args:
            obj: Parsed archive index
            encoding_key: Encoding key to find

        Returns:
            Found entry or None
        """
        # Truncate or pad key to match stored key length
        key_bytes = obj.footer.key_bytes
        if len(encoding_key) > key_bytes:
            search_key = encoding_key[:key_bytes]
        elif len(encoding_key) < key_bytes:
            search_key = encoding_key + (b"\x00" * (key_bytes - len(encoding_key)))
        else:
            search_key = encoding_key

        for entry in obj.entries:
            if entry.encoding_key == search_key:
                return entry

        return None

    def get_archive_indices(self, obj: CdnArchiveIndex) -> dict[int, int]:
        """Get archive index distribution (for archive-groups only).

        Args:
            obj: Parsed archive-group

        Returns:
            Dictionary of archive_index -> count
        """
        if not obj.footer.is_archive_group:
            return {}

        distribution: dict[int, int] = {}
        for entry in obj.entries:
            if entry.archive_index is not None:
                if entry.archive_index not in distribution:
                    distribution[entry.archive_index] = 0
                distribution[entry.archive_index] += 1

        return distribution

    def get_statistics(self, obj: CdnArchiveIndex) -> dict[str, Any]:
        """Get statistics about the archive index.

        Args:
            obj: Parsed archive index

        Returns:
            Statistics dictionary
        """
        stats: dict[str, Any] = {
            "format": "archive-group"
            if obj.footer.is_archive_group
            else "archive-index",
            "version": obj.footer.version,
            "key_bytes": obj.footer.key_bytes,
            "offset_bytes": obj.footer.offset_bytes,
            "total_entries": len(obj.entries),
            "expected_entries": obj.footer.entry_count,
        }

        if obj.footer.is_archive_group:
            # Add archive-group specific stats
            distribution: dict[int, int] = self.get_archive_indices(obj)
            stats["unique_archive_indices"] = len(distribution)
            stats["archive_distribution"] = dict(
                sorted(distribution.items())[:10]
            )  # Top 10

            if distribution:
                stats["min_archive_index"] = min(distribution.keys())
                stats["max_archive_index"] = max(distribution.keys())

        # Size statistics
        if obj.entries:
            sizes: list[int] = [entry.size for entry in obj.entries]
            stats["min_size"] = min(sizes)
            stats["max_size"] = max(sizes)
            stats["avg_size"] = sum(sizes) / len(sizes)
            stats["total_size"] = sum(sizes)

        return stats

    def build(self, obj: CdnArchiveIndex) -> bytes:
        """Build CDN archive index binary data from structure.

        Produces the layout ``[Pages][TOC keys][TOC hashes][Footer]``.
        Each page is zero-padded to ``page_size`` bytes. The TOC follows
        all pages: first the last key of each page, then a hash per page.

        Args:
            obj: Archive index structure

        Returns:
            Binary archive index data
        """
        footer = obj.footer
        entry_size = footer.key_bytes + footer.offset_bytes + footer.size_bytes
        page_size = footer.page_size_kb * 1024
        entries_per_page = page_size // entry_size

        all_entries = list(obj.entries)

        # Build pages, collect TOC data
        pages: list[bytes] = []
        toc_keys: list[bytes] = []
        toc_hashes: list[bytes] = []
        idx = 0

        while idx < len(all_entries):
            page_entries = all_entries[idx : idx + entries_per_page]
            page_data = BytesIO()

            last_key = b"\x00" * footer.key_bytes
            for entry in page_entries:
                last_key = entry.encoding_key[: footer.key_bytes]
                page_data.write(last_key)

                # Size comes before offset in the binary format
                page_data.write(struct.pack(">I", entry.size))

                if footer.is_archive_group:
                    archive_idx = (
                        entry.archive_index if entry.archive_index is not None else 0
                    )
                    page_data.write(struct.pack(">H", archive_idx))
                    page_data.write(struct.pack(">I", entry.offset))
                else:
                    page_data.write(struct.pack(">I", entry.offset))

            # Zero-pad to page_size
            written = page_data.tell()
            if written < page_size:
                page_data.write(b"\x00" * (page_size - written))

            page_bytes = page_data.getvalue()
            pages.append(page_bytes)
            toc_keys.append(last_key)
            toc_hashes.append(
                hashlib.md5(page_bytes).digest()[: footer.footer_hash_bytes]
            )

            idx += entries_per_page

        # Handle empty index: one empty page
        if not all_entries:
            empty_page = b"\x00" * page_size
            pages.append(empty_page)
            toc_keys.append(b"\x00" * footer.key_bytes)
            toc_hashes.append(
                hashlib.md5(empty_page).digest()[: footer.footer_hash_bytes]
            )

        # Assemble: Pages + TOC keys + TOC hashes + Footer
        result = BytesIO()

        for page in pages:
            result.write(page)

        for key in toc_keys:
            result.write(key)

        for h in toc_hashes:
            result.write(h)

        # Write footer
        result.write(footer.toc_hash)
        result.write(struct.pack("B", footer.version))
        result.write(footer.reserved)
        result.write(struct.pack("B", footer.page_size_kb))
        result.write(struct.pack("B", footer.offset_bytes))
        result.write(struct.pack("B", footer.size_bytes))
        result.write(struct.pack("B", footer.key_bytes))
        result.write(struct.pack("B", footer.footer_hash_bytes))
        result.write(struct.pack("<I", footer.entry_count))  # Little-endian!
        result.write(footer.footer_hash)

        return result.getvalue()


def is_archive_group(data: bytes) -> bool:
    """Check if data is an archive-group (6-byte offsets).

    Args:
        data: Data to check

    Returns:
        True if data is an archive-group
    """
    if len(data) < 28:
        return False

    try:
        offset_bytes = data[-16]  # offset_bytes field in footer
        return offset_bytes == 6
    except Exception:
        return False


def is_cdn_archive_index(data: bytes) -> bool:
    """Check if data is a CDN archive index or archive-group.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a CDN archive index
    """
    if len(data) < 28:
        return False

    try:
        footer_data = data[-28:]
        version = footer_data[8]
        offset_bytes = footer_data[12]
        size_bytes = footer_data[13]

        # Valid if version <= 1, size_bytes is 4, and offset_bytes is 4 or 6
        return version <= 1 and size_bytes == 4 and offset_bytes in [4, 6]
    except Exception:
        return False


def _calculate_block_hash(block_data: bytes, hash_bytes: int) -> bytes:
    """Per-block hash: MD5(block_data)[:hash_bytes].

    Mirrors cascette-rs ``calculate_block_hash``.
    """
    return hashlib.md5(block_data).digest()[:hash_bytes]


def _calculate_toc_hash(
    toc_keys: list[bytes], block_hashes: list[bytes], hash_bytes: int
) -> bytes:
    """TOC hash: MD5(toc_keys || block_hashes)[:hash_bytes].

    Mirrors cascette-rs ``calculate_toc_hash``.
    """
    data = b"".join(toc_keys) + b"".join(block_hashes)
    return hashlib.md5(data).digest()[:hash_bytes]


def _calculate_footer_hash(
    *,
    version: int,
    reserved: bytes,
    page_size_kb: int,
    offset_bytes: int,
    size_bytes: int,
    key_bytes: int,
    footer_hash_bytes: int,
    entry_count: int,
) -> bytes:
    """Footer hash: MD5(12-byte header padded to 20 bytes)[:8].

    Header fields: version(1) reserved(2) page_size_kb(1) offset_bytes(1)
    size_bytes(1) key_bytes(1) footer_hash_bytes(1) entry_count(4, LE),
    then zero-padded to 20 bytes. Mirrors cascette-rs
    ``IndexFooter::calculate_footer_hash`` (verified against client files).
    """
    data = bytearray()
    data.append(version)
    data.extend(reserved)
    data.append(page_size_kb)
    data.append(offset_bytes)
    data.append(size_bytes)
    data.append(key_bytes)
    data.append(footer_hash_bytes)
    data.extend(struct.pack("<I", entry_count))
    data.extend(b"\x00" * (20 - len(data)))
    return hashlib.md5(bytes(data)).digest()[:8]


def build_merged_archive_group(
    archives: list[tuple[int, CdnArchiveIndex]],
    *,
    key_bytes: int = 16,
    page_size_kb: int = 4,
    footer_hash_bytes: int = 8,
) -> bytes:
    """K-way merge of pre-sorted archive indices into an archive-group.

    Archive-groups are locally generated mega-indices (never on CDN). Each
    input ``(archive_index, index)`` pair uses the *positional* archive
    number from the CDN config's archive list (0-based), matching the
    client and cascette-rs ``build_merged``. Duplicate keys across archives
    are deduplicated, keeping the first occurrence (lowest archive index).

    Entry layout (26 bytes): [key (16)][size (4, BE)][archive_index (2, BE)]
    [offset (4, BE)]. Pages are 4KB with MD5 block hashes; the TOC holds the
    last key per page then the block hashes.

    Args:
        archives: List of (positional_archive_index, parsed index)
        key_bytes: Key length in bytes
        page_size_kb: Page size in KB
        footer_hash_bytes: Footer/TOC hash length in bytes

    Returns:
        Serialized archive-group bytes (pages + TOC + footer)
    """
    page_size = page_size_kb * 1024
    bytes_per_entry = key_bytes + 6 + 4  # key + size + 6-byte composite offset
    entries_per_page = page_size // bytes_per_entry
    hash_bytes = footer_hash_bytes

    # Validate inputs are sorted by key (format invariant, matches cascette-rs).
    for _archive_idx, index in archives:
        for prev, cur in zip(index.entries, index.entries[1:], strict=False):
            if prev.encoding_key > cur.encoding_key:
                raise ValueError(
                    "Archive index entries must be sorted by encoding key "
                    "(format invariant)"
                )

    # K-way merge: each archive's entries are already sorted; walk them in
    # key order via a heap, deduplicating identical keys (first archive wins).
    import heapq

    heap: list[tuple[bytes, int, int, int, int]] = []
    # (key, archive_index, offset, size, cursor) per live stream
    cursors: list[int] = [0] * len(archives)

    for stream_idx, (archive_idx, index) in enumerate(archives):
        if index.entries:
            first = index.entries[0]
            heapq.heappush(
                heap,
                (
                    first.encoding_key,
                    archive_idx,
                    first.offset,
                    first.size,
                    stream_idx,
                ),
            )

    out_entries: list[CdnArchiveEntry] = []
    prev_key: bytes | None = None

    while heap:
        key, archive_idx, offset, size, stream_idx = heapq.heappop(heap)

        # Deduplicate: skip if key matches the previously emitted key.
        if prev_key is not None and key == prev_key:
            # still advance the stream so we do not re-emit later
            pass
        else:
            out_entries.append(
                CdnArchiveEntry(
                    encoding_key=key,
                    archive_index=archive_idx,
                    offset=offset,
                    size=size,
                )
            )
            prev_key = key

        # Advance the stream that produced this entry.
        stream_cursor = cursors[stream_idx] + 1
        cursors[stream_idx] = stream_cursor
        stream_entries = archives[stream_idx][1].entries
        if stream_cursor < len(stream_entries):
            nxt = stream_entries[stream_cursor]
            heapq.heappush(
                heap,
                (
                    nxt.encoding_key,
                    archives[stream_idx][0],
                    nxt.offset,
                    nxt.size,
                    stream_idx,
                ),
            )

    # Build pages.
    pages: list[bytes] = []
    toc_keys: list[bytes] = []
    block_hashes: list[bytes] = []
    for start in range(0, len(out_entries), entries_per_page):
        page_entries = out_entries[start : start + entries_per_page]
        page_data = bytearray()
        last_key = b"\x00" * key_bytes
        for entry in page_entries:
            key = (entry.encoding_key + b"\x00" * key_bytes)[:key_bytes]
            last_key = key
            page_data.extend(key)
            page_data.extend(struct.pack(">I", entry.size))
            archive_idx = entry.archive_index if entry.archive_index is not None else 0
            page_data.extend(struct.pack(">H", archive_idx))
            page_data.extend(struct.pack(">I", entry.offset))
        page_data.extend(b"\x00" * (page_size - len(page_data)))
        pages.append(bytes(page_data))
        toc_keys.append(last_key)
        block_hashes.append(_calculate_block_hash(bytes(page_data), hash_bytes))

    if not out_entries:
        # Empty group: one empty page (matches cascette-rs build path).
        empty_page = b"\x00" * page_size
        pages.append(empty_page)
        toc_keys.append(b"\x00" * key_bytes)
        block_hashes.append(_calculate_block_hash(empty_page, hash_bytes))

    toc_hash = _calculate_toc_hash(toc_keys, block_hashes, hash_bytes)

    footer = CdnArchiveFooter(
        toc_hash=toc_hash,
        version=1,
        reserved=b"\x00\x00",
        page_size_kb=page_size_kb,
        offset_bytes=6,
        size_bytes=4,
        key_bytes=key_bytes,
        footer_hash_bytes=footer_hash_bytes,
        entry_count=len(out_entries),
        footer_hash=b"\x00" * 8,  # placeholder, recomputed below
    )
    footer.footer_hash = _calculate_footer_hash(
        version=footer.version,
        reserved=footer.reserved,
        page_size_kb=footer.page_size_kb,
        offset_bytes=footer.offset_bytes,
        size_bytes=footer.size_bytes,
        key_bytes=footer.key_bytes,
        footer_hash_bytes=footer.footer_hash_bytes,
        entry_count=footer.entry_count,
    )

    result = bytearray()
    for page in pages:
        result.extend(page)
    for key in toc_keys:
        result.extend(key)
    for h in block_hashes:
        result.extend(h)
    result.extend(footer.toc_hash)
    result.append(footer.version)
    result.extend(footer.reserved)
    result.append(footer.page_size_kb)
    result.append(footer.offset_bytes)
    result.append(footer.size_bytes)
    result.append(footer.key_bytes)
    result.append(footer.footer_hash_bytes)
    result.extend(struct.pack("<I", footer.entry_count))
    result.extend(footer.footer_hash)
    return bytes(result)


def generate_group_index(
    indices_dir: Path,
    archive_keys: list[str],
    group_hash: str,
    is_patch: bool = False,
) -> bool:
    """Generate ``{group_hash}.index`` from individual archive indices.

    Archive-groups are locally generated (the client merges the individual
    CDN archive indices; they are never served from the CDN). Mirrors
    cascette-rs ``generate_group_index``: each archive keeps its positional
    index from the config's archive list (0-based).

    Args:
        indices_dir: Directory containing ``{key}.index`` files
        archive_keys: Archive hashes in CDN config order
        group_hash: Target archive-group hash
        is_patch: Logging label only (data vs patch)

    Returns:
        True if the group was written, False if no indices were available
    """
    from pathlib import Path

    indices_dir = Path(indices_dir)
    group_path = indices_dir / f"{group_hash}.index"
    if group_path.exists():
        return True

    parser = CdnArchiveParser()
    parsed: list[tuple[int, CdnArchiveIndex]] = []
    for i, key in enumerate(archive_keys):
        index_path = indices_dir / f"{key}.index"
        if not index_path.exists():
            logger.debug("individual index missing, skipping for group", key=key)
            continue
        try:
            index = parser.parse(index_path.read_bytes())
            parsed.append((i, index))
        except Exception as e:
            logger.warning(
                "failed to parse index for group merge", key=key, error=str(e)
            )

    if not parsed:
        logger.warning("no indices parsed, skipping group generation")
        return False

    output = build_merged_archive_group(parsed)
    group_path.write_bytes(output)
    logger.info(
        "generated archive group index",
        is_patch=is_patch,
        group_hash=group_hash,
        archives=len(parsed),
        size=len(output),
    )
    return True
