"""Configuration format parsers for NGDP/CASC."""

from __future__ import annotations

import re
from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class ConfigFileInfo(BaseModel):
    """File reference in a config with content key, encoding key, and size."""

    content_key: str
    encoding_key: str | None = None
    size: int | None = None


class PartialPriority(BaseModel):
    """Partial priority entry mapping a content key to a download priority."""

    key: str
    priority: int


class BuildConfig(BaseModel):
    """Build configuration structure."""

    root: str | None = Field(default=None, description="Root content key")
    encoding: str | None = Field(default=None, description="Encoding content and encoding keys")
    encoding_size: str | None = Field(default=None, description="Encoding sizes")
    install: str | None = Field(default=None, description="Install content and encoding keys")
    install_size: str | None = Field(default=None, description="Install sizes")
    download: str | None = Field(default=None, description="Download content and encoding keys")
    download_size: str | None = Field(default=None, description="Download sizes")
    size: str | None = Field(default=None, description="Size content and encoding keys")
    size_size: str | None = Field(default=None, description="Size file sizes")
    patch: str | None = Field(default=None, description="Patch content and encoding keys")
    patch_size: str | None = Field(default=None, description="Patch sizes")
    partial_priority: str | None = Field(default=None, description="Partial priority")
    partial_priority_size: str | None = Field(default=None, description="Partial priority size")
    vfs_root: str | None = Field(default=None, description="VFS root content and encoding keys")
    vfs_root_size: str | None = Field(default=None, description="VFS root sizes")
    build_name: str | None = Field(default=None, description="Build name")
    build_playbuild_installer: str | None = Field(default=None, description="Play build installer")
    build_product: str | None = Field(default=None, description="Build product")
    build_uid: str | None = Field(default=None, description="Build UID")
    build_playtime_url: str | None = Field(default=None, description="Build playtime URL")
    build_product_espec: str | None = Field(default=None, description="Build product ESpec")
    build_partial_priority: str | None = Field(default=None, description="Build partial priority")
    patch_config: str | None = Field(default=None, description="Patch config hash")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")

    def get_size_info(self) -> ConfigFileInfo | None:
        """Get size file information from size and size-size fields."""
        if self.size is None:
            return None
        return _parse_file_info(self.size, self.size_size)

    def get_vfs_root_info(self) -> ConfigFileInfo | None:
        """Get VFS root file information from vfs-root and vfs-root-size fields."""
        if self.vfs_root is None:
            return None
        return _parse_file_info(self.vfs_root, self.vfs_root_size)

    def get_encoding_info(self) -> ConfigFileInfo | None:
        """Get encoding file information from encoding and encoding-size fields."""
        if self.encoding is None:
            return None
        return _parse_file_info(self.encoding, self.encoding_size)

    def get_install_info(self) -> ConfigFileInfo | None:
        """Get install file information from install and install-size fields."""
        if self.install is None:
            return None
        return _parse_file_info(self.install, self.install_size)

    def get_download_info(self) -> ConfigFileInfo | None:
        """Get download file information from download and download-size fields."""
        if self.download is None:
            return None
        return _parse_file_info(self.download, self.download_size)

    def get_patch_info(self) -> ConfigFileInfo | None:
        """Get patch file information from patch and patch-size fields."""
        if self.patch is None:
            return None
        return _parse_file_info(self.patch, self.patch_size)

    def get_partial_priorities(self) -> list[PartialPriority]:
        """Parse partial priority from comma-separated key:priority format.

        Reads from build-partial-priority first, falls back to partial-priority.
        Malformed entries are skipped.
        """
        raw = self.build_partial_priority or self.partial_priority
        if raw is None:
            return []
        return _parse_partial_priority(raw)

    def get_vfs_entries(self) -> list[tuple[int, ConfigFileInfo]]:
        """Get VFS file entries from vfs-1, vfs-1-size, vfs-2, etc.

        Iterates sequentially from 1 and stops at the first missing index.
        """
        result: list[tuple[int, ConfigFileInfo]] = []
        index = 1
        while True:
            key = f"vfs-{index}"
            value = self.extra_fields.get(key)
            if value is None:
                break
            size_key = f"vfs-{index}-size"
            size_value = self.extra_fields.get(size_key)
            result.append((index, _parse_file_info(value, size_value)))
            index += 1
        return result


class CDNArchiveInfo(BaseModel):
    """Archive entry with content key and optional index size."""

    content_key: str
    index_size: int | None = None


class CDNConfig(BaseModel):
    """CDN configuration structure."""

    archives: list[str] = Field(default_factory=list, description="Archive hashes")
    archives_index_size: str | None = Field(default=None, description="Archive index sizes")
    archive_group: str | None = Field(default=None, description="Archive group")
    patch_archives: list[str] = Field(default_factory=list, description="Patch archive hashes")
    patch_archives_index_size: str | None = Field(default=None, description="Patch archive index sizes")
    patch_archive_group: str | None = Field(default=None, description="Patch archive group")
    builds: list[str] = Field(default_factory=list, description="Build config hashes")
    file_index: str | None = Field(default=None, description="File index hash")
    file_index_size: str | None = Field(default=None, description="File index size")
    patch_file_index: str | None = Field(default=None, description="Patch file index hash")
    patch_file_index_size: str | None = Field(default=None, description="Patch file index size")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")

    def get_patch_file_index_size(self) -> int | None:
        """Get patch file index size as integer."""
        if self.patch_file_index_size is None:
            return None
        try:
            return int(self.patch_file_index_size)
        except ValueError:
            return None

    def get_patch_file_indices(self) -> list[CDNArchiveInfo]:
        """Get patch file index entries with sizes."""
        if not self.patch_file_index:
            return []
        indices = self.patch_file_index.split()
        sizes: list[int | None] = []
        if self.patch_file_index_size:
            sizes = [
                _try_parse_int(s) for s in self.patch_file_index_size.split()
            ]
        return [
            CDNArchiveInfo(
                content_key=key,
                index_size=sizes[i] if i < len(sizes) else None,
            )
            for i, key in enumerate(indices)
        ]

    def get_file_index_size(self) -> int | None:
        """Get file index size as integer."""
        if self.file_index_size is None:
            return None
        try:
            return int(self.file_index_size)
        except ValueError:
            return None


class PatchConfig(BaseModel):
    """Patch configuration structure."""

    patch_archives: list[str] = Field(default_factory=list, description="Patch archive hashes")
    patch_archive_group: str | None = Field(default=None, description="Patch archive group")
    builds: list[str] = Field(default_factory=list, description="Build config hashes")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")


class ProductConfig(BaseModel):
    """Product configuration structure."""

    product: str | None = Field(default=None, description="Product code")
    uid: str | None = Field(default=None, description="Product UID")
    name: str | None = Field(default=None, description="Product name")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")


class BuildConfigParser(FormatParser[BuildConfig]):
    """Parser for build configuration files."""

    def parse(self, data: bytes | BinaryIO) -> BuildConfig:
        """Parse build configuration.

        Args:
            data: Binary data or stream

        Returns:
            Parsed build configuration
        """
        if isinstance(data, (bytes, bytearray)):
            content = data.decode('utf-8', errors='replace')
        else:
            content = data.read().decode('utf-8', errors='replace')

        config_dict = self._parse_config_content(content)
        return self._dict_to_build_config(config_dict)

    def _parse_config_content(self, content: str) -> dict[str, str]:
        """Parse configuration file content into dictionary."""
        config: dict[str, str] = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                config[key.strip()] = value.strip()

        return config

    def _dict_to_build_config(self, config_dict: dict[str, str]) -> BuildConfig:
        """Convert dictionary to BuildConfig model."""
        # Known fields
        known_fields: set[str] = {
            'root', 'encoding', 'encoding-size', 'install', 'install-size',
            'download', 'download-size', 'size', 'size-size',
            'patch', 'patch-size',
            'partial-priority', 'partial-priority-size',
            'vfs-root', 'vfs-root-size',
            'build-name', 'build-playbuild-installer', 'build-product', 'build-uid',
            'build-playtime-url', 'build-product-espec', 'build-partial-priority',
            'patch-config',
        }

        # Map dashed keys to underscore for Python field names
        field_mapping: dict[str, str] = {
            'encoding-size': 'encoding_size',
            'install-size': 'install_size',
            'download-size': 'download_size',
            'size-size': 'size_size',
            'patch-size': 'patch_size',
            'partial-priority': 'partial_priority',
            'partial-priority-size': 'partial_priority_size',
            'vfs-root': 'vfs_root',
            'vfs-root-size': 'vfs_root_size',
            'build-name': 'build_name',
            'build-playbuild-installer': 'build_playbuild_installer',
            'build-product': 'build_product',
            'build-uid': 'build_uid',
            'build-playtime-url': 'build_playtime_url',
            'build-product-espec': 'build_product_espec',
            'build-partial-priority': 'build_partial_priority',
            'patch-config': 'patch_config',
        }

        build_config_data: dict[str, Any] = {}
        extra_fields: dict[str, str] = {}

        for key, value in config_dict.items():
            if key in known_fields:
                mapped_key = field_mapping.get(key, key)
                build_config_data[mapped_key] = value
            else:
                extra_fields[key] = value

        build_config_data['extra_fields'] = extra_fields
        return BuildConfig(**build_config_data)

    def build(self, obj: BuildConfig) -> bytes:
        """Build build configuration from structure.

        Args:
            obj: Build configuration structure

        Returns:
            Binary configuration data
        """
        lines: list[str] = []

        # Add known fields in canonical order (matching Agent.exe)
        field_order: list[tuple[str, str]] = [
            ('root', 'root'),
            ('install', 'install'),
            ('install_size', 'install-size'),
            ('download', 'download'),
            ('download_size', 'download-size'),
            ('size', 'size'),
            ('size_size', 'size-size'),
            ('vfs_root', 'vfs-root'),
            ('vfs_root_size', 'vfs-root-size'),
            ('encoding', 'encoding'),
            ('encoding_size', 'encoding-size'),
            ('patch', 'patch'),
            ('patch_size', 'patch-size'),
            ('patch_config', 'patch-config'),
            ('partial_priority', 'partial-priority'),
            ('partial_priority_size', 'partial-priority-size'),
            ('build_name', 'build-name'),
            ('build_uid', 'build-uid'),
            ('build_product', 'build-product'),
            ('build_playbuild_installer', 'build-playbuild-installer'),
            ('build_partial_priority', 'build-partial-priority'),
            ('build_playtime_url', 'build-playtime-url'),
            ('build_product_espec', 'build-product-espec'),
        ]

        for field_name, config_key in field_order:
            value = getattr(obj, field_name)
            if value is not None:
                lines.append(f"{config_key} = {value}")

        # Add VFS entries in sequential order (vfs-1, vfs-1-size, vfs-2, ...)
        vfs_keys = sorted(
            (k for k in obj.extra_fields if _VFS_KEY_PATTERN.match(k)),
            key=_vfs_sort_key,
        )
        non_vfs_extras = {
            k: v for k, v in obj.extra_fields.items()
            if not _VFS_KEY_PATTERN.match(k)
        }

        for key in vfs_keys:
            lines.append(f"{key} = {obj.extra_fields[key]}")

        # Add remaining extra fields
        for key, value in non_vfs_extras.items():
            lines.append(f"{key} = {value}")

        content = '\n'.join(lines) + '\n'
        return content.encode('utf-8')


class CDNConfigParser(FormatParser[CDNConfig]):
    """Parser for CDN configuration files."""

    def parse(self, data: bytes | BinaryIO) -> CDNConfig:
        """Parse CDN configuration.

        Args:
            data: Binary data or stream

        Returns:
            Parsed CDN configuration
        """
        if isinstance(data, (bytes, bytearray)):
            content = data.decode('utf-8', errors='replace')
        else:
            content = data.read().decode('utf-8', errors='replace')

        config_dict = self._parse_config_content(content)
        return self._dict_to_cdn_config(config_dict)

    def _parse_config_content(self, content: str) -> dict[str, str]:
        """Parse configuration file content into dictionary."""
        config: dict[str, str] = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                config[key.strip()] = value.strip()

        return config

    def _dict_to_cdn_config(self, config_dict: dict[str, str]) -> CDNConfig:
        """Convert dictionary to CDNConfig model."""
        # Known fields
        known_fields: set[str] = {
            'archives', 'archives-index-size', 'archive-group',
            'patch-archives', 'patch-archives-index-size', 'patch-archive-group',
            'builds', 'file-index', 'file-index-size',
            'patch-file-index', 'patch-file-index-size',
        }

        cdn_config_data: dict[str, Any] = {}
        extra_fields: dict[str, str] = {}

        for key, value in config_dict.items():
            if key == 'archives':
                cdn_config_data['archives'] = value.split() if value else []
            elif key == 'archives-index-size':
                cdn_config_data['archives_index_size'] = value
            elif key == 'archive-group':
                cdn_config_data['archive_group'] = value
            elif key == 'patch-archives':
                cdn_config_data['patch_archives'] = value.split() if value else []
            elif key == 'patch-archives-index-size':
                cdn_config_data['patch_archives_index_size'] = value
            elif key == 'patch-archive-group':
                cdn_config_data['patch_archive_group'] = value
            elif key == 'builds':
                cdn_config_data['builds'] = value.split() if value else []
            elif key == 'file-index':
                cdn_config_data['file_index'] = value
            elif key == 'file-index-size':
                cdn_config_data['file_index_size'] = value
            elif key == 'patch-file-index':
                cdn_config_data['patch_file_index'] = value
            elif key == 'patch-file-index-size':
                cdn_config_data['patch_file_index_size'] = value
            elif key in known_fields:
                field_name = key.replace('-', '_')
                cdn_config_data[field_name] = value
            else:
                extra_fields[key] = value

        cdn_config_data['extra_fields'] = extra_fields
        return CDNConfig(**cdn_config_data)

    def build(self, obj: CDNConfig) -> bytes:
        """Build CDN configuration from structure.

        Args:
            obj: CDN configuration structure

        Returns:
            Binary configuration data
        """
        lines: list[str] = []

        # Add known fields in canonical order
        if obj.archives:
            lines.append(f"archives = {' '.join(obj.archives)}")
        if obj.archives_index_size:
            lines.append(f"archives-index-size = {obj.archives_index_size}")

        if obj.archive_group:
            lines.append(f"archive-group = {obj.archive_group}")

        if obj.patch_archives:
            lines.append(f"patch-archives = {' '.join(obj.patch_archives)}")
        if obj.patch_archives_index_size:
            lines.append(f"patch-archives-index-size = {obj.patch_archives_index_size}")

        if obj.patch_archive_group:
            lines.append(f"patch-archive-group = {obj.patch_archive_group}")

        if obj.builds:
            lines.append(f"builds = {' '.join(obj.builds)}")

        if obj.file_index:
            lines.append(f"file-index = {obj.file_index}")
        if obj.file_index_size:
            lines.append(f"file-index-size = {obj.file_index_size}")

        if obj.patch_file_index:
            lines.append(f"patch-file-index = {obj.patch_file_index}")
        if obj.patch_file_index_size:
            lines.append(f"patch-file-index-size = {obj.patch_file_index_size}")

        # Add extra fields
        for key, value in obj.extra_fields.items():
            lines.append(f"{key} = {value}")

        content = '\n'.join(lines) + '\n'
        return content.encode('utf-8')


class PatchConfigParser(FormatParser[PatchConfig]):
    """Parser for patch configuration files."""

    def parse(self, data: bytes | BinaryIO) -> PatchConfig:
        """Parse patch configuration.

        Args:
            data: Binary data or stream

        Returns:
            Parsed patch configuration
        """
        if isinstance(data, (bytes, bytearray)):
            content = data.decode('utf-8', errors='replace')
        else:
            content = data.read().decode('utf-8', errors='replace')

        config_dict = self._parse_config_content(content)
        return self._dict_to_patch_config(config_dict)

    def _parse_config_content(self, content: str) -> dict[str, str]:
        """Parse configuration file content into dictionary."""
        config: dict[str, str] = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                config[key.strip()] = value.strip()

        return config

    def _dict_to_patch_config(self, config_dict: dict[str, str]) -> PatchConfig:
        """Convert dictionary to PatchConfig model."""
        patch_config_data: dict[str, Any] = {}
        extra_fields: dict[str, str] = {}

        for key, value in config_dict.items():
            if key == 'patch-archives':
                patch_config_data['patch_archives'] = value.split() if value else []
            elif key == 'patch-archive-group':
                patch_config_data['patch_archive_group'] = value
            elif key == 'builds':
                patch_config_data['builds'] = value.split() if value else []
            else:
                extra_fields[key] = value

        patch_config_data['extra_fields'] = extra_fields
        return PatchConfig(**patch_config_data)

    def build(self, obj: PatchConfig) -> bytes:
        """Build patch configuration from structure.

        Args:
            obj: Patch configuration structure

        Returns:
            Binary configuration data
        """
        lines: list[str] = []

        if obj.patch_archives:
            lines.append(f"patch-archives = {' '.join(obj.patch_archives)}")

        if obj.patch_archive_group:
            lines.append(f"patch-archive-group = {obj.patch_archive_group}")

        if obj.builds:
            lines.append(f"builds = {' '.join(obj.builds)}")

        # Add extra fields
        for key, value in obj.extra_fields.items():
            lines.append(f"{key} = {value}")

        content = '\n'.join(lines) + '\n'
        return content.encode('utf-8')


class ProductConfigParser(FormatParser[ProductConfig]):
    """Parser for product configuration files."""

    def parse(self, data: bytes | BinaryIO) -> ProductConfig:
        """Parse product configuration.

        Args:
            data: Binary data or stream

        Returns:
            Parsed product configuration
        """
        if isinstance(data, (bytes, bytearray)):
            content = data.decode('utf-8', errors='replace')
        else:
            content = data.read().decode('utf-8', errors='replace')

        config_dict = self._parse_config_content(content)
        return self._dict_to_product_config(config_dict)

    def _parse_config_content(self, content: str) -> dict[str, str]:
        """Parse configuration file content into dictionary."""
        config: dict[str, str] = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                config[key.strip()] = value.strip()

        return config

    def _dict_to_product_config(self, config_dict: dict[str, str]) -> ProductConfig:
        """Convert dictionary to ProductConfig model."""
        product_config_data: dict[str, Any] = {}
        extra_fields: dict[str, str] = {}

        for key, value in config_dict.items():
            if key in ['product', 'uid', 'name']:
                product_config_data[key] = value
            else:
                extra_fields[key] = value

        product_config_data['extra_fields'] = extra_fields
        return ProductConfig(**product_config_data)

    def build(self, obj: ProductConfig) -> bytes:
        """Build product configuration from structure.

        Args:
            obj: Product configuration structure

        Returns:
            Binary configuration data
        """
        lines: list[str] = []

        if obj.product:
            lines.append(f"product = {obj.product}")

        if obj.uid:
            lines.append(f"uid = {obj.uid}")

        if obj.name:
            lines.append(f"name = {obj.name}")

        # Add extra fields
        for key, value in obj.extra_fields.items():
            lines.append(f"{key} = {value}")

        content = '\n'.join(lines) + '\n'
        return content.encode('utf-8')


class BuildConfigBuilder:
    """Builder for build configuration files."""

    def __init__(self) -> None:
        """Initialize build config builder."""
        pass

    def build(self, obj: BuildConfig) -> bytes:
        """Build build config file from object.

        Args:
            obj: Build config object to build

        Returns:
            Binary config data
        """
        parser = BuildConfigParser()
        return parser.build(obj)

    @classmethod
    def create_basic(cls, root: str, encoding: str, install: str | None = None) -> BuildConfig:
        """Create basic build config.

        Args:
            root: Root content key
            encoding: Encoding key
            install: Optional install key

        Returns:
            Build config object
        """
        return BuildConfig(
            root=root,
            encoding=encoding,
            install=install
        )


class CDNConfigBuilder:
    """Builder for CDN configuration files."""

    def __init__(self) -> None:
        """Initialize CDN config builder."""
        pass

    def build(self, obj: CDNConfig) -> bytes:
        """Build CDN config file from object.

        Args:
            obj: CDN config object to build

        Returns:
            Binary config data
        """
        parser = CDNConfigParser()
        return parser.build(obj)

    @classmethod
    def create_basic(cls, archives: list[str], builds: list[str]) -> CDNConfig:
        """Create basic CDN config.

        Args:
            archives: List of archive hashes
            builds: List of build hashes

        Returns:
            CDN config object
        """
        return CDNConfig(
            archives=archives,
            builds=builds
        )


class PatchConfigBuilder:
    """Builder for patch configuration files."""

    def __init__(self) -> None:
        """Initialize patch config builder."""
        pass

    def build(self, obj: PatchConfig) -> bytes:
        """Build patch config file from object.

        Args:
            obj: Patch config object to build

        Returns:
            Binary config data
        """
        parser = PatchConfigParser()
        return parser.build(obj)

    @classmethod
    def create_basic(cls, patch_archives: list[str], builds: list[str]) -> PatchConfig:
        """Create basic patch config.

        Args:
            patch_archives: List of patch archive hashes
            builds: List of build hashes

        Returns:
            Patch config object
        """
        return PatchConfig(
            patch_archives=patch_archives,
            builds=builds
        )


class ProductConfigBuilder:
    """Builder for product configuration files."""

    def __init__(self) -> None:
        """Initialize product config builder."""
        pass

    def build(self, obj: ProductConfig) -> bytes:
        """Build product config file from object.

        Args:
            obj: Product config object to build

        Returns:
            Binary config data
        """
        parser = ProductConfigParser()
        return parser.build(obj)

    @classmethod
    def create_basic(cls, product: str, uid: str, name: str | None = None) -> ProductConfig:
        """Create basic product config.

        Args:
            product: Product code
            uid: Product UID
            name: Optional product name

        Returns:
            Product config object
        """
        return ProductConfig(
            product=product,
            uid=uid,
            name=name
        )


def _try_parse_int(s: str) -> int | None:
    """Try to parse a string as an integer, returning None on failure."""
    try:
        return int(s)
    except ValueError:
        return None


def _parse_file_info(keys_value: str, sizes_value: str | None) -> ConfigFileInfo:
    """Parse a dual-hash config value into a ConfigFileInfo.

    Format: content_key [encoding_key] for the keys value,
    content_size [encoding_size] for the sizes value.
    The encoding size (second value in sizes) is used as the file size.
    """
    parts = keys_value.split()
    content_key = parts[0]
    encoding_key = parts[1] if len(parts) > 1 else None

    size: int | None = None
    if sizes_value:
        size_parts = sizes_value.split()
        # Second value is the encoding size (used as file size)
        if len(size_parts) > 1:
            size = _try_parse_int(size_parts[1])

    return ConfigFileInfo(
        content_key=content_key,
        encoding_key=encoding_key,
        size=size,
    )


def _parse_partial_priority(raw: str) -> list[PartialPriority]:
    """Parse comma-separated key:priority values.

    Malformed entries are skipped.
    """
    result: list[PartialPriority] = []
    for entry in raw.split(','):
        entry = entry.strip()
        if ':' not in entry:
            continue
        key, _, priority_str = entry.rpartition(':')
        priority = _try_parse_int(priority_str)
        if priority is not None and key:
            result.append(PartialPriority(key=key, priority=priority))
    return result


# VFS key pattern for matching vfs-N and vfs-N-size
_VFS_KEY_PATTERN = re.compile(r'^vfs-\d+(-size)?$')


def _vfs_sort_key(key: str) -> tuple[int, int]:
    """Sort key for VFS entries: (index, 0 for base / 1 for -size)."""
    match = re.match(r'^vfs-(\d+)(-size)?$', key)
    if match:
        return (int(match.group(1)), 1 if match.group(2) else 0)
    return (0, 0)


def is_config_file(data: bytes) -> bool:
    """Check if data appears to be a configuration file.

    Args:
        data: Data to check

    Returns:
        True if data appears to be a configuration file
    """
    try:
        content = data.decode('utf-8', errors='replace')
        # Look for key = value pattern
        for line in content.strip().split('\n')[:10]:  # Check first 10 lines
            line = line.strip()
            if line and not line.startswith('#') and ' = ' in line:
                return True
        return False
    except Exception:
        return False


def detect_config_type(data: bytes) -> str | None:
    """Detect configuration file type.

    Args:
        data: Configuration data

    Returns:
        Configuration type or None
    """
    try:
        content = data.decode('utf-8', errors='replace')
        lines: list[str] = [line.strip() for line in content.strip().split('\n') if line.strip() and not line.strip().startswith('#')]

        # Check for characteristic fields
        keys: set[str] = set()
        for line in lines:
            if ' = ' in line:
                key = line.split(' = ', 1)[0].strip()
                keys.add(key)

        # Detect based on characteristic keys
        if 'archives' in keys or 'archive-group' in keys:
            return 'cdn'
        elif 'root' in keys or 'encoding' in keys:
            return 'build'
        elif 'patch-archives' in keys and 'archives' not in keys:
            return 'patch'
        elif 'product' in keys or 'uid' in keys:
            return 'product'
        else:
            return 'unknown'

    except Exception:
        return None
