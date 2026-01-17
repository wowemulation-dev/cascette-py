"""Configuration format parsers for NGDP/CASC."""

from __future__ import annotations

from typing import Any, BinaryIO

import structlog
from pydantic import BaseModel, Field

from cascette_tools.formats.base import FormatParser

logger = structlog.get_logger()


class BuildConfig(BaseModel):
    """Build configuration structure."""

    root: str | None = Field(default=None, description="Root content key")
    encoding: str | None = Field(default=None, description="Encoding content and encoding keys")
    install: str | None = Field(default=None, description="Install content and encoding keys")
    download: str | None = Field(default=None, description="Download content and encoding keys")
    size: str | None = Field(default=None, description="Size content and encoding keys")
    patch: str | None = Field(default=None, description="Patch content and encoding keys")
    partial_priority: str | None = Field(default=None, description="Partial priority")
    partial_priority_size: str | None = Field(default=None, description="Partial priority size")
    build_name: str | None = Field(default=None, description="Build name")
    build_playbuild_installer: str | None = Field(default=None, description="Play build installer")
    build_product: str | None = Field(default=None, description="Build product")
    build_uid: str | None = Field(default=None, description="Build UID")
    patch_config: str | None = Field(default=None, description="Patch config hash")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")


class CDNConfig(BaseModel):
    """CDN configuration structure."""

    archives: list[str] = Field(default_factory=list, description="Archive hashes")
    archive_group: str | None = Field(default=None, description="Archive group")
    patch_archives: list[str] = Field(default_factory=list, description="Patch archive hashes")
    patch_archive_group: str | None = Field(default=None, description="Patch archive group")
    builds: list[str] = Field(default_factory=list, description="Build config hashes")
    file_index: str | None = Field(default=None, description="File index hash")
    patch_file_index: str | None = Field(default=None, description="Patch file index hash")
    extra_fields: dict[str, str] = Field(default_factory=dict, description="Additional fields")


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
            'root', 'encoding', 'install', 'download', 'size', 'patch',
            'partial-priority', 'partial-priority-size', 'build-name',
            'build-playbuild-installer', 'build-product', 'build-uid', 'patch-config'
        }

        # Map dashed keys to underscore for Python field names
        field_mapping: dict[str, str] = {
            'partial-priority': 'partial_priority',
            'partial-priority-size': 'partial_priority_size',
            'build-name': 'build_name',
            'build-playbuild-installer': 'build_playbuild_installer',
            'build-product': 'build_product',
            'build-uid': 'build_uid',
            'patch-config': 'patch_config'
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

        # Add known fields in order
        field_order: list[tuple[str, str]] = [
            ('root', 'root'),
            ('encoding', 'encoding'),
            ('install', 'install'),
            ('download', 'download'),
            ('size', 'size'),
            ('patch', 'patch'),
            ('partial_priority', 'partial-priority'),
            ('partial_priority_size', 'partial-priority-size'),
            ('build_name', 'build-name'),
            ('build_playbuild_installer', 'build-playbuild-installer'),
            ('build_product', 'build-product'),
            ('build_uid', 'build-uid'),
            ('patch_config', 'patch-config')
        ]

        for field_name, config_key in field_order:
            value = getattr(obj, field_name)
            if value is not None:
                lines.append(f"{config_key} = {value}")

        # Add extra fields
        for key, value in obj.extra_fields.items():
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
            'archives', 'archive-group', 'patch-archives', 'patch-archive-group',
            'builds', 'file-index', 'patch-file-index'
        }

        cdn_config_data: dict[str, Any] = {}
        extra_fields: dict[str, str] = {}

        for key, value in config_dict.items():
            if key == 'archives':
                cdn_config_data['archives'] = value.split() if value else []
            elif key == 'archive-group':
                cdn_config_data['archive_group'] = value
            elif key == 'patch-archives':
                cdn_config_data['patch_archives'] = value.split() if value else []
            elif key == 'patch-archive-group':
                cdn_config_data['patch_archive_group'] = value
            elif key == 'builds':
                cdn_config_data['builds'] = value.split() if value else []
            elif key == 'file-index':
                cdn_config_data['file_index'] = value
            elif key == 'patch-file-index':
                cdn_config_data['patch_file_index'] = value
            elif key in known_fields:
                # Handle any other known fields
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

        # Add known fields in order
        if obj.archives:
            lines.append(f"archives = {' '.join(obj.archives)}")

        if obj.archive_group:
            lines.append(f"archive-group = {obj.archive_group}")

        if obj.patch_archives:
            lines.append(f"patch-archives = {' '.join(obj.patch_archives)}")

        if obj.patch_archive_group:
            lines.append(f"patch-archive-group = {obj.patch_archive_group}")

        if obj.builds:
            lines.append(f"builds = {' '.join(obj.builds)}")

        if obj.file_index:
            lines.append(f"file-index = {obj.file_index}")

        if obj.patch_file_index:
            lines.append(f"patch-file-index = {obj.patch_file_index}")

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
