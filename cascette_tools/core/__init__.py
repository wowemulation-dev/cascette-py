"""Core functionality for cascette_tools.

This module provides shared functionality used across the entire package:
- Configuration management
- Type definitions
- Utility functions
- CDN client implementations
- Caching mechanisms
"""

from cascette_tools.core.types import (
    BuildInfo,
    CompressionMode,
    EncryptionType,
    Product,
)
from cascette_tools.core.utils import (
    chunked_read,
    compute_jenkins96,
    compute_md5,
    format_size,
    hexlify,
    read_cstring,
    unhexlify,
    validate_hash_string,
)

__all__ = [
    # Types
    "BuildInfo",
    "Product",
    "CompressionMode",
    "EncryptionType",
    # Utils
    "hexlify",
    "unhexlify",
    "compute_md5",
    "compute_jenkins96",
    "read_cstring",
    "chunked_read",
    "format_size",
    "validate_hash_string",
]
