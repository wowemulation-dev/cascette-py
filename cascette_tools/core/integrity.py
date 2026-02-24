"""Content integrity verification for CASC downloads.

Verifies downloaded content against expected hashes and sizes.
In CASC, content keys (CKeys) are MD5 hashes of the decompressed
file content. Encoding keys (EKeys) identify the BLTE-compressed
blob on CDN. Verification happens at two levels:

1. BLTE blob size must match the archive index entry size
2. After BLTE decompression, MD5 of content must equal the CKey
"""

from __future__ import annotations

import hashlib

import structlog

logger = structlog.get_logger()


class IntegrityError(Exception):
    """Raised when content verification fails.

    Attributes:
        expected: Expected hash or size as hex string or int
        actual: Actual hash or size as hex string or int
        key_hex: The key being verified (hex string)
    """

    def __init__(
        self,
        message: str,
        *,
        expected: str | int | None = None,
        actual: str | int | None = None,
        key_hex: str | None = None,
    ):
        self.expected = expected
        self.actual = actual
        self.key_hex = key_hex
        super().__init__(message)


def verify_content_key(data: bytes, expected_ckey: bytes) -> bool:
    """Verify decompressed content matches its content key (MD5).

    Args:
        data: Decompressed file content
        expected_ckey: Expected content key (16-byte MD5 hash)

    Returns:
        True if the MD5 of data matches expected_ckey

    Raises:
        IntegrityError: If the hash does not match
    """
    actual_md5 = hashlib.md5(data).digest()
    if actual_md5 != expected_ckey:
        raise IntegrityError(
            f"Content key mismatch: expected {expected_ckey.hex()}, "
            f"got {actual_md5.hex()}",
            expected=expected_ckey.hex(),
            actual=actual_md5.hex(),
            key_hex=expected_ckey.hex(),
        )
    return True


def verify_ekey_size(data: bytes, expected_size: int) -> bool:
    """Verify encoded (BLTE) data matches expected size from index.

    Args:
        data: Raw encoded data (BLTE blob)
        expected_size: Expected size from archive index entry

    Returns:
        True if len(data) matches expected_size

    Raises:
        IntegrityError: If the size does not match
    """
    if len(data) != expected_size:
        raise IntegrityError(
            f"Encoded size mismatch: expected {expected_size}, "
            f"got {len(data)}",
            expected=expected_size,
            actual=len(data),
        )
    return True
