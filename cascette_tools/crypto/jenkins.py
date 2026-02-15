"""Bob Jenkins' lookup3 hash functions.

This module implements the lookup3 hash functions by Bob Jenkins.
These are used for checksum validation in CASC index files.

Reference: http://burtleburtle.net/bob/c/lookup3.c
Public Domain implementation by Bob Jenkins, May 2006.
"""

from __future__ import annotations


def _rot(x: int, k: int) -> int:
    """Rotate x left by k bits (32-bit)."""
    return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF


def _mix(a: int, b: int, c: int) -> tuple[int, int, int]:
    """Mix 3 32-bit values reversibly.

    This is the core mixing function that provides avalanche behavior.
    """
    a = (a - c) & 0xFFFFFFFF
    a = (a ^ _rot(c, 4)) & 0xFFFFFFFF
    c = (c + b) & 0xFFFFFFFF

    b = (b - a) & 0xFFFFFFFF
    b = (b ^ _rot(a, 6)) & 0xFFFFFFFF
    a = (a + c) & 0xFFFFFFFF

    c = (c - b) & 0xFFFFFFFF
    c = (c ^ _rot(b, 8)) & 0xFFFFFFFF
    b = (b + a) & 0xFFFFFFFF

    a = (a - c) & 0xFFFFFFFF
    a = (a ^ _rot(c, 16)) & 0xFFFFFFFF
    c = (c + b) & 0xFFFFFFFF

    b = (b - a) & 0xFFFFFFFF
    b = (b ^ _rot(a, 19)) & 0xFFFFFFFF
    a = (a + c) & 0xFFFFFFFF

    c = (c - b) & 0xFFFFFFFF
    c = (c ^ _rot(b, 4)) & 0xFFFFFFFF
    b = (b + a) & 0xFFFFFFFF

    return a, b, c


def _final(a: int, b: int, c: int) -> tuple[int, int, int]:
    """Final mixing of 3 32-bit values into c.

    Pairs of (a,b,c) values differing in only a few bits will usually
    produce values of c that look totally different.
    """
    c = (c ^ b) & 0xFFFFFFFF
    c = (c - _rot(b, 14)) & 0xFFFFFFFF

    a = (a ^ c) & 0xFFFFFFFF
    a = (a - _rot(c, 11)) & 0xFFFFFFFF

    b = (b ^ a) & 0xFFFFFFFF
    b = (b - _rot(a, 25)) & 0xFFFFFFFF

    c = (c ^ b) & 0xFFFFFFFF
    c = (c - _rot(b, 16)) & 0xFFFFFFFF

    a = (a ^ c) & 0xFFFFFFFF
    a = (a - _rot(c, 4)) & 0xFFFFFFFF

    b = (b ^ a) & 0xFFFFFFFF
    b = (b - _rot(a, 14)) & 0xFFFFFFFF

    c = (c ^ b) & 0xFFFFFFFF
    c = (c - _rot(b, 24)) & 0xFFFFFFFF

    return a, b, c


def hashlittle(data: bytes, initval: int = 0) -> int:
    """Hash a variable-length key into a 32-bit value.

    This is Bob Jenkins' hashlittle() function from lookup3.c.
    Every bit of the key affects every bit of the return value.
    Two keys differing by one or two bits will have totally different hash values.

    Args:
        data: The data to hash
        initval: Initial value (seed) for the hash, defaults to 0

    Returns:
        32-bit hash value

    Example:
        >>> hashlittle(b"hello", 0)
        885767278
    """
    length = len(data)

    # Set up the internal state
    a = b = c = (0xdeadbeef + length + initval) & 0xFFFFFFFF

    # Process data in 12-byte chunks
    offset = 0
    while length > 12:
        # Read 12 bytes (little-endian)
        a = (a + data[offset]) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF

        b = (b + data[offset + 4]) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF

        c = (c + data[offset + 8]) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 11] << 24)) & 0xFFFFFFFF

        a, b, c = _mix(a, b, c)

        length -= 12
        offset += 12

    # Handle the last (probably partial) block
    # All case statements fall through
    if length == 12:
        c = (c + (data[offset + 11] << 24)) & 0xFFFFFFFF
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 11:
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 10:
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 9:
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 8:
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 7:
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 6:
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 5:
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 4:
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 3:
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 2:
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 1:
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 0:
        return c  # Zero length strings require no mixing

    a, b, c = _final(a, b, c)
    return c


def hashlittle2(data: bytes, pc: int = 0, pb: int = 0) -> tuple[int, int]:
    """Return 2 32-bit hash values.

    This is identical to hashlittle(), except it returns two 32-bit hash
    values instead of just one. This is good enough for hash table lookup
    with 2^64 buckets.

    Args:
        data: The data to hash
        pc: Primary seed value, defaults to 0
        pb: Secondary seed value, defaults to 0

    Returns:
        Tuple of (primary_hash, secondary_hash)

    Example:
        >>> hashlittle2(b"hello", 0, 0)
        (885767278, 1543812985)
    """
    length = len(data)

    # Set up the internal state
    a = b = c = (0xdeadbeef + length + pc) & 0xFFFFFFFF
    c = (c + pb) & 0xFFFFFFFF

    # Process data in 12-byte chunks
    offset = 0
    while length > 12:
        # Read 12 bytes (little-endian)
        a = (a + data[offset]) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF

        b = (b + data[offset + 4]) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF

        c = (c + data[offset + 8]) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 11] << 24)) & 0xFFFFFFFF

        a, b, c = _mix(a, b, c)

        length -= 12
        offset += 12

    # Handle the last (probably partial) block
    # All case statements fall through
    if length == 12:
        c = (c + (data[offset + 11] << 24)) & 0xFFFFFFFF
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 11:
        c = (c + (data[offset + 10] << 16)) & 0xFFFFFFFF
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 10:
        c = (c + (data[offset + 9] << 8)) & 0xFFFFFFFF
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 9:
        c = (c + data[offset + 8]) & 0xFFFFFFFF
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 8:
        b = (b + (data[offset + 7] << 24)) & 0xFFFFFFFF
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 7:
        b = (b + (data[offset + 6] << 16)) & 0xFFFFFFFF
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 6:
        b = (b + (data[offset + 5] << 8)) & 0xFFFFFFFF
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 5:
        b = (b + data[offset + 4]) & 0xFFFFFFFF
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 4:
        a = (a + (data[offset + 3] << 24)) & 0xFFFFFFFF
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 3:
        a = (a + (data[offset + 2] << 16)) & 0xFFFFFFFF
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 2:
        a = (a + (data[offset + 1] << 8)) & 0xFFFFFFFF
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 1:
        a = (a + data[offset]) & 0xFFFFFFFF
    elif length == 0:
        return c, b  # Zero length strings require no mixing

    a, b, c = _final(a, b, c)
    return c, b
