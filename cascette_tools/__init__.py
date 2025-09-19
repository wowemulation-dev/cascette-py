"""Cascette Tools - Python tools for NGDP/CASC format analysis.

This package provides comprehensive tools for analyzing and working with
Blizzard's NGDP (Next Generation Distribution Pipeline) and CASC (Content
Addressable Storage Container) formats.

Key modules:
- core: Shared functionality (config, types, utilities)
- formats: Binary format parsers and builders
- commands: CLI command implementations
- database: Data management and storage
"""

__version__ = "0.1.0"
__author__ = "Cascette Team"

# Re-export commonly used types and functions
from cascette_tools.core.types import (
    BuildInfo,
    CompressionMode,
    EncryptionType,
    Product,
)

__all__ = [
    "__version__",
    "__author__",
    "BuildInfo",
    "Product",
    "CompressionMode",
    "EncryptionType",
]
