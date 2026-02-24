"""Format parsers and builders for NGDP/CASC formats.

This module provides parsers and builders for various binary formats used
in Blizzard's NGDP/CASC system:
- BLTE: Block Table Encoded compression/encryption
- Encoding: Content key to encoding key mappings
- Root: File catalog mappings
- Install: Installation manifests with tag-based filtering
- Download: Download priority manifests for streaming content
- Archive indices: CDN archive organization
- Configuration files: Build, CDN, Patch, and Product configs
- TVFS: TACT Virtual File System (CASC v3)
- ZBSDIFF1: Zlib-compressed binary differential patches
"""

from cascette_tools.formats.archive import (
    ArchiveBuilder,
    ArchiveIndex,
    ArchiveIndexChunk,
    ArchiveIndexEntry,
    ArchiveIndexFooter,
    ArchiveIndexParser,
)
from cascette_tools.formats.base import FormatParser
from cascette_tools.formats.blte import (
    BLTEBuilder,
    BLTEChunk,
    BLTEFile,
    BLTEHeader,
    BLTEParser,
    TACTKeyStore,
    decompress_blte,
    is_blte,
)
from cascette_tools.formats.blte_integration import (
    DatabaseTACTKeyStore,
    IntegratedBLTEParser,
    create_integrated_parser,
    decompress_blte_with_db,
)
from cascette_tools.formats.config import (
    BuildConfig,
    BuildConfigBuilder,
    BuildConfigParser,
    CDNArchiveInfo,
    CDNConfig,
    CDNConfigBuilder,
    CDNConfigParser,
    ConfigFileInfo,
    PartialPriority,
    PatchConfig,
    PatchConfigBuilder,
    PatchConfigParser,
    ProductConfig,
    ProductConfigBuilder,
    ProductConfigParser,
    detect_config_type,
    is_config_file,
)
from cascette_tools.formats.download import (
    DownloadBuilder,
    DownloadEntry,
    DownloadFile,
    DownloadHeader,
    DownloadParser,
    DownloadTag,
    is_download,
)
from cascette_tools.formats.encoding import (
    CKeyPage,
    CKeyPageEntry,
    EKeyPage,
    EKeyPageEntry,
    EncodingBuilder,
    EncodingFile,
    EncodingHeader,
    EncodingParser,
    is_encoding,
)
from cascette_tools.formats.install import (
    InstallBuilder,
    InstallEntry,
    InstallFile,
    InstallParser,
    InstallTag,
    is_install,
)
from cascette_tools.formats.patch_archive import (
    CompressionSpec,
    PatchArchiveBuilder,
    PatchArchiveFile,
    PatchArchiveHeader,
    PatchArchiveParser,
    PatchEntry,
    create_empty_patch_archive,
    is_patch_archive,
)
from cascette_tools.formats.root import (
    RootBlock,
    RootBuilder,
    RootFile,
    RootHeader,
    RootParser,
    RootRecord,
    format_content_flags,
    format_locale_flags,
    is_root,
)
from cascette_tools.formats.size import (
    SizeBuilder,
    SizeEntry,
    SizeFile,
    SizeHeader,
    SizeParser,
    SizeTag,
    is_size,
)
from cascette_tools.formats.tvfs import (
    TVFSBuilder,
    TVFSEntry,
    TVFSFile,
    TVFSHeader,
    TVFSParser,
)
from cascette_tools.formats.zbsdiff import (
    ZbsdiffBuilder,
    ZbsdiffControlEntry,
    ZbsdiffFile,
    ZbsdiffHeader,
    ZbsdiffParser,
)

__all__ = [
    # Base
    "FormatParser",
    # Archive
    "ArchiveBuilder",
    "ArchiveIndex",
    "ArchiveIndexChunk",
    "ArchiveIndexEntry",
    "ArchiveIndexFooter",
    "ArchiveIndexParser",
    # BLTE
    "BLTEBuilder",
    "BLTEChunk",
    "BLTEFile",
    "BLTEHeader",
    "BLTEParser",
    "TACTKeyStore",
    "decompress_blte",
    "is_blte",
    # BLTE with database integration
    "DatabaseTACTKeyStore",
    "IntegratedBLTEParser",
    "create_integrated_parser",
    "decompress_blte_with_db",
    # Config
    "BuildConfig",
    "BuildConfigBuilder",
    "BuildConfigParser",
    "CDNArchiveInfo",
    "CDNConfig",
    "CDNConfigBuilder",
    "CDNConfigParser",
    "ConfigFileInfo",
    "PartialPriority",
    "PatchConfig",
    "PatchConfigBuilder",
    "PatchConfigParser",
    "ProductConfig",
    "ProductConfigBuilder",
    "ProductConfigParser",
    "detect_config_type",
    "is_config_file",
    # Encoding
    "CKeyPage",
    "CKeyPageEntry",
    "EKeyPage",
    "EKeyPageEntry",
    "EncodingBuilder",
    "EncodingFile",
    "EncodingHeader",
    "EncodingParser",
    "is_encoding",
    # Download
    "DownloadBuilder",
    "DownloadEntry",
    "DownloadFile",
    "DownloadHeader",
    "DownloadParser",
    "DownloadTag",
    "is_download",
    # Install
    "InstallBuilder",
    "InstallEntry",
    "InstallFile",
    "InstallParser",
    "InstallTag",
    "is_install",
    # Size
    "SizeBuilder",
    "SizeEntry",
    "SizeFile",
    "SizeHeader",
    "SizeParser",
    "SizeTag",
    "is_size",
    # Root
    "RootBlock",
    "RootBuilder",
    "RootFile",
    "RootHeader",
    "RootParser",
    "RootRecord",
    "format_content_flags",
    "format_locale_flags",
    "is_root",
    # Patch Archive
    "CompressionSpec",
    "PatchArchiveBuilder",
    "PatchArchiveFile",
    "PatchArchiveHeader",
    "PatchArchiveParser",
    "PatchEntry",
    "create_empty_patch_archive",
    "is_patch_archive",
    # TVFS
    "TVFSBuilder",
    "TVFSEntry",
    "TVFSFile",
    "TVFSHeader",
    "TVFSParser",
    # ZBSDIFF1
    "ZbsdiffBuilder",
    "ZbsdiffControlEntry",
    "ZbsdiffFile",
    "ZbsdiffHeader",
    "ZbsdiffParser",
]
