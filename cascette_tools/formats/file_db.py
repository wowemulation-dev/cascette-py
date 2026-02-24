"""File database parser for containerless TACT installations.

The file database is a SQLite blob stored on the CDN as a data file.
Build configs reference it via `build-file-db` (content key + encoding key).
It contains three tables:

- meta: Single row with entry count
- tags: Binary blob encoding per-file tag membership (MSB bit ordering)
- files: File entries mapping encoding keys to filesystem paths

When the first byte is 0x45 ('E'), the blob is Salsa20-encrypted.
Decryption is not yet supported.
"""

from __future__ import annotations

import sqlite3
import struct
from io import BytesIO
from typing import BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class FileDbMeta(BaseModel):
    """Metadata row from the file database meta table."""

    id: int = Field(description="Meta row ID (always 1)")
    entry_count: int = Field(description="Total number of file entries")


class FileDbTag(BaseModel):
    """Tag from the file database tags table.

    Uses the same MSB bit-ordering as InstallTag for bitmask checks.
    """

    name: str = Field(description="Tag name (e.g., Windows, enUS)")
    tag_type: int = Field(description="Tag type identifier")
    bit_mask: bytes = Field(description="Bitmask indicating which files have this tag")

    def has_file(self, file_index: int) -> bool:
        """Check if file at given index has this tag.

        Uses MSB bit ordering within each byte, matching InstallTag.
        """
        byte_index = file_index // 8
        bit_offset = file_index % 8

        if byte_index >= len(self.bit_mask):
            return False

        return (self.bit_mask[byte_index] & (0x80 >> bit_offset)) != 0


class FileDbEntry(BaseModel):
    """File entry from the file database files table."""

    file_index: int = Field(description="Sequential file index")
    ekey: bytes = Field(description="16-byte encoding key")
    ckey: bytes = Field(description="16-byte content key")
    encoded_size: int = Field(description="Encoded (compressed) file size")
    decoded_size: int = Field(description="Decoded (uncompressed) file size")
    flags: int = Field(description="File flags")
    relative_path: str = Field(description="Relative filesystem path")


class FileDatabase(BaseModel):
    """Complete file database structure from a containerless build config."""

    meta: FileDbMeta = Field(description="Database metadata")
    tags: list[FileDbTag] = Field(  # pyright: ignore[reportUnknownVariableType]
        default_factory=list, description="Tag definitions"
    )
    entries: list[FileDbEntry] = Field(  # pyright: ignore[reportUnknownVariableType]
        default_factory=list, description="File entries"
    )

    def filter_by_tags(
        self,
        platform: str | None = None,
        arch: str | None = None,
        locale: str | None = None,
    ) -> list[FileDbEntry]:
        """Filter entries by tag membership.

        Returns entries that match all specified tag criteria.
        Tags are combined with AND: a file must match all specified tags.
        """
        if not platform and not arch and not locale:
            return list(self.entries)

        # Build list of required tag names
        required: list[str] = []
        if platform:
            required.append(platform)
        if arch:
            required.append(arch)
        if locale:
            required.append(locale)

        # Find matching tags
        matching_tags = [t for t in self.tags if t.name in required]
        if not matching_tags:
            return list(self.entries)

        filtered: list[FileDbEntry] = []
        for entry in self.entries:
            if all(tag.has_file(entry.file_index) for tag in matching_tags):
                filtered.append(entry)
        return filtered


def _parse_tags_blob(data: bytes, entry_count: int) -> list[FileDbTag]:
    """Parse the binary tags blob from the tags table.

    Format per tag:
    - 2 bytes: name length (LE)
    - N bytes: tag name (UTF-8)
    - 2 bytes: tag type (LE)
    - ceil(entry_count / 8) bytes: bitmask

    Args:
        data: Raw binary blob from tags.data column
        entry_count: Number of file entries (determines bitmask size)

    Returns:
        List of parsed tags
    """
    mask_size = (entry_count + 7) // 8
    stream = BytesIO(data)
    tags: list[FileDbTag] = []

    while stream.tell() < len(data):
        # Read name length
        name_len_data = stream.read(2)
        if len(name_len_data) < 2:
            break
        name_len = struct.unpack('<H', name_len_data)[0]

        # Read name
        name_data = stream.read(name_len)
        if len(name_data) < name_len:
            break
        name = name_data.decode('utf-8', errors='replace')

        # Read tag type
        type_data = stream.read(2)
        if len(type_data) < 2:
            break
        tag_type = struct.unpack('<H', type_data)[0]

        # Read bitmask
        bit_mask = stream.read(mask_size)
        if len(bit_mask) < mask_size:
            break

        tags.append(FileDbTag(
            name=name,
            tag_type=tag_type,
            bit_mask=bit_mask,
        ))

    return tags


def _build_tags_blob(tags: list[FileDbTag]) -> bytes:
    """Serialize tags to binary blob for the tags table.

    Inverse of _parse_tags_blob.
    """
    result = BytesIO()
    for tag in tags:
        name_bytes = tag.name.encode('utf-8')
        result.write(struct.pack('<H', len(name_bytes)))
        result.write(name_bytes)
        result.write(struct.pack('<H', tag.tag_type))
        result.write(tag.bit_mask)
    return result.getvalue()


class FileDatabaseParser(FormatParser[FileDatabase]):
    """Parser for SQLite-backed file database blobs."""

    def parse(self, data: bytes | BinaryIO) -> FileDatabase:
        """Parse a file database from a SQLite blob.

        Args:
            data: SQLite blob bytes or stream

        Returns:
            Parsed FileDatabase

        Raises:
            ValueError: If data is Salsa20-encrypted or not valid SQLite
        """
        if isinstance(data, (bytes, bytearray)):
            raw = bytes(data)
        else:
            raw = data.read()

        if not raw:
            raise ValueError("Empty file database blob")

        # Check for Salsa20 encryption
        if raw[0] == 0x45:
            raise ValueError(
                "File database is Salsa20-encrypted; decryption not yet supported"
            )

        # Deserialize SQLite blob into in-memory database
        conn = sqlite3.connect(":memory:")
        try:
            conn.deserialize(raw)

            # Query meta table
            cursor = conn.execute("SELECT id, entry_count FROM meta WHERE id = 1")
            meta_row = cursor.fetchone()
            if meta_row is None:
                raise ValueError("No meta row found in file database")
            meta = FileDbMeta(id=meta_row[0], entry_count=meta_row[1])

            # Query tags table
            tags: list[FileDbTag] = []
            cursor = conn.execute("SELECT data FROM tags WHERE id = 1")
            tags_row = cursor.fetchone()
            if tags_row is not None and tags_row[0] is not None:
                tags_data: bytes = bytes(tags_row[0]) if isinstance(tags_row[0], memoryview) else tags_row[0]
                tags = _parse_tags_blob(tags_data, meta.entry_count)

            # Query files table
            entries: list[FileDbEntry] = []
            cursor = conn.execute(
                "SELECT file_index, ekey, ckey, encoded_size, decoded_size, "
                "flags, relative_path FROM files ORDER BY file_index"
            )
            for row in cursor:
                ekey: bytes = bytes(row[1]) if isinstance(row[1], memoryview) else row[1]
                ckey: bytes = bytes(row[2]) if isinstance(row[2], memoryview) else row[2]

                entries.append(FileDbEntry(
                    file_index=row[0],
                    ekey=ekey,
                    ckey=ckey,
                    encoded_size=row[3],
                    decoded_size=row[4],
                    flags=row[5],
                    relative_path=row[6],
                ))

        finally:
            conn.close()

        logger.debug(
            "Parsed file database",
            entry_count=meta.entry_count,
            tags=len(tags),
            files=len(entries),
        )

        return FileDatabase(
            meta=meta,
            tags=tags,
            entries=entries,
        )

    def build(self, obj: FileDatabase) -> bytes:
        """Serialize FileDatabase back to a SQLite blob.

        Args:
            obj: FileDatabase to serialize

        Returns:
            SQLite blob bytes
        """
        conn = sqlite3.connect(":memory:")
        try:
            # Create tables
            conn.execute(
                "CREATE TABLE meta (id INTEGER PRIMARY KEY, entry_count INTEGER)"
            )
            conn.execute(
                "CREATE TABLE tags (id INTEGER PRIMARY KEY, data BLOB)"
            )
            conn.execute(
                "CREATE TABLE files ("
                "file_index INTEGER PRIMARY KEY, "
                "ekey BLOB, ckey BLOB, "
                "encoded_size INTEGER, decoded_size INTEGER, "
                "flags INTEGER, relative_path TEXT)"
            )

            # Insert meta
            conn.execute(
                "INSERT INTO meta (id, entry_count) VALUES (?, ?)",
                (obj.meta.id, obj.meta.entry_count),
            )

            # Insert tags blob
            if obj.tags:
                tags_blob = _build_tags_blob(obj.tags)
                conn.execute(
                    "INSERT INTO tags (id, data) VALUES (1, ?)",
                    (tags_blob,),
                )

            # Insert file entries
            for entry in obj.entries:
                conn.execute(
                    "INSERT INTO files "
                    "(file_index, ekey, ckey, encoded_size, decoded_size, flags, relative_path) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.file_index,
                        entry.ekey,
                        entry.ckey,
                        entry.encoded_size,
                        entry.decoded_size,
                        entry.flags,
                        entry.relative_path,
                    ),
                )

            conn.commit()
            result = conn.serialize()

        finally:
            conn.close()

        return bytes(result)


def is_file_db(data: bytes) -> bool:
    """Check if data appears to be a file database (SQLite or encrypted).

    Args:
        data: Data to check

    Returns:
        True if data starts with SQLite magic or Salsa20 encryption marker
    """
    if len(data) < 4:
        return False
    # SQLite magic: "SQLite format 3\x00"
    if data[:6] == b'SQLite':
        return True
    # Salsa20 encrypted
    if data[0] == 0x45:
        return True
    return False
