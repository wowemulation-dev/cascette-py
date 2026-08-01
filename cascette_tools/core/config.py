"""Configuration management for cascette-tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from cascette_tools.core.types import Product, ProductFamily, get_product_family

logger = structlog.get_logger()


# Built-in default mirrors per product family.
# Used when the user has not configured mirrors for a family.
DEFAULT_FAMILY_MIRRORS: dict[str, list[str]] = {
    ProductFamily.WOW: [
        "https://casc.wago.tools",
        "https://cdn.arctium.tools",
        "https://archive.wow.tools",
    ],
}

# Fallback mirrors for products with no family-specific defaults.
# Official Blizzard CDN servers obtained from TACT/Ribbit are tried first;
# these are used when Ribbit servers are unavailable or fail.
DEFAULT_FALLBACK_MIRRORS: list[str] = [
    "http://blzddist1-a.akamaihd.net",
    "http://level3.blizzard.com",
    "http://cdn.blizzard.com",
]


class MirrorConfig(BaseModel):
    """Mirror configuration for a single product family or product code."""

    urls: list[str] = Field(
        default_factory=list,
        description="Ordered list of mirror URLs (highest priority first)",
    )

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        """Validate that all URLs use http or https."""
        for url in v:
            if not url.startswith(("http://", "https://")):
                raise ValueError(
                    f"Mirror URL must start with http:// or https://: {url}"
                )
        return v


class MirrorSettings(BaseModel):
    """User-configured CDN mirrors.

    Resolution order for a given product:
    1. product_overrides[product_code] (most specific)
    2. family_mirrors[product_family]
    3. Built-in defaults (DEFAULT_FAMILY_MIRRORS / DEFAULT_FALLBACK_MIRRORS)
    """

    family_mirrors: dict[str, MirrorConfig] = Field(
        default_factory=dict, description="Mirrors keyed by product family name"
    )
    product_overrides: dict[str, MirrorConfig] = Field(
        default_factory=dict,
        description="Mirrors keyed by product code, override family config",
    )


def resolve_mirrors_for_product(
    product: Product | str,
    settings: MirrorSettings,
) -> list[str]:
    """Resolve the ordered mirror list for a product.

    Resolution chain (first non-empty wins):
    1. settings.product_overrides[product_code]
    2. settings.family_mirrors[product_family]
    3. DEFAULT_FAMILY_MIRRORS[product_family]
    4. DEFAULT_FALLBACK_MIRRORS

    Args:
        product: Product enum value or string code.
        settings: User's mirror configuration.

    Returns:
        Non-empty list of mirror URLs in priority order.
    """
    product_str = product.value if isinstance(product, Product) else product

    # 1. Product-specific override
    if product_str in settings.product_overrides:
        override = settings.product_overrides[product_str]
        if override.urls:
            return list(override.urls)

    # 2. User-configured family mirrors
    try:
        family = get_product_family(product_str).value
    except (KeyError, ValueError):
        family = None

    if family and family in settings.family_mirrors:
        family_cfg = settings.family_mirrors[family]
        if family_cfg.urls:
            return list(family_cfg.urls)

    # 3. Built-in family defaults
    if family and family in DEFAULT_FAMILY_MIRRORS:
        return list(DEFAULT_FAMILY_MIRRORS[family])

    # 4. Generic fallback
    return list(DEFAULT_FALLBACK_MIRRORS)


class CacheConfig(BaseModel):
    """Cache configuration."""

    cache_dir: Path = Field(
        default=Path.home() / ".cache" / "cascette", description="Cache directory"
    )
    ttl: int = Field(
        default=86400,  # 24 hours
        description="Time to live in seconds",
    )
    max_size: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10GB
        description="Maximum cache size in bytes",
    )
    enabled: bool = Field(default=True, description="Whether caching is enabled")

    @field_validator("ttl")
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        """Validate TTL value."""
        if v < 0:
            raise ValueError("TTL must be non-negative")
        return v

    @field_validator("max_size")
    @classmethod
    def validate_max_size(cls, v: int) -> int:
        """Validate max size value."""
        if v < 0:
            raise ValueError("Max size must be non-negative")
        return v


class CDNConfig(BaseModel):
    """CDN configuration with fallback mirrors.

    Primary CDN servers are obtained dynamically from Blizzard's Ribbit endpoint.
    Fallback mirrors are resolved per-product via resolve_mirrors_for_product()
    and passed in at construction time.
    """

    fallback_mirrors: list[str] = Field(
        default_factory=list,
        description="Fallback CDN mirrors (resolved per-product by AppConfig)",
    )
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts per mirror")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout value."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v

    @field_validator("max_retries")
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        """Validate max retries value."""
        if v < 0:
            raise ValueError("Max retries must be non-negative")
        return v


class TACTConfig(BaseModel):
    """TACT configuration."""

    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    regions: list[str] = Field(
        default=["us", "eu", "kr", "tw", "cn", "sg"], description="Supported regions"
    )

    def get_base_url(self, region: str) -> str:
        """Get base URL for a region."""
        return f"https://{region}.version.battle.net"

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        """Validate timeout value."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v

    @field_validator("max_retries")
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        """Validate max retries value."""
        if v < 0:
            raise ValueError("Max retries must be non-negative")
        return v

    @field_validator("regions")
    @classmethod
    def validate_regions(cls, v: list[str]) -> list[str]:
        """Validate regions list."""
        if not v:
            raise ValueError("Regions list cannot be empty")

        valid_regions = {"us", "eu", "kr", "tw", "cn", "sg"}
        for region in v:
            if region not in valid_regions:
                raise ValueError(
                    f"Invalid region: {region}. Valid regions: {valid_regions}"
                )

        return v


class AppConfig(BaseModel):
    """Application configuration."""

    # Directory settings
    config_dir: Path = Field(
        default=Path.home() / ".config" / "cascette-tools",
        description="Configuration directory",
    )
    data_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "cascette-tools",
        description="Data directory",
    )

    # Region settings
    default_region: str = Field(
        default="kr",
        description="Default CDN region (us, eu, kr, tw, cn). kr provides good coverage for Asia-Pacific.",
    )

    # CDN settings
    cdn_base_url: str = Field(
        default="https://cdn.arctium.tools/tpr/wow/", description="Base CDN URL"
    )
    cdn_timeout: float = Field(default=30.0, description="CDN request timeout")
    cdn_max_retries: int = Field(default=3, description="CDN max retry attempts")

    # Cache settings
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_max_size: int = Field(
        default=10 * 1024 * 1024 * 1024, description="Maximum cache size in bytes"
    )
    cache_ttl: int = Field(
        default=86400 * 7, description="Cache time to live in seconds"
    )

    # Mirror settings
    mirrors: MirrorSettings = Field(
        default_factory=MirrorSettings,
        description="User-configured CDN mirrors per product family or product code",
    )

    # Output settings
    output_format: str = Field(
        default="rich", description="Output format (rich, json, yaml, table)"
    )
    log_level: str = Field(
        default="INFO", description="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )

    def create_cdn_config(self, product: Product | str) -> CDNConfig:
        """Create a CDNConfig with resolved mirrors for the given product.

        Args:
            product: Product enum value or string code.

        Returns:
            CDNConfig with fallback mirrors resolved for the product.
        """
        mirrors = resolve_mirrors_for_product(product, self.mirrors)
        return CDNConfig(
            fallback_mirrors=mirrors,
            timeout=self.cdn_timeout,
            max_retries=self.cdn_max_retries,
        )

    def model_post_init(self, __context: Any) -> None:
        """Ensure directories exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def load(cls, config_file: Path | None = None) -> AppConfig:
        """Load configuration from file.

        Args:
            config_file: Path to config file, uses default if None

        Returns:
            Application configuration
        """
        if config_file is None:
            config_file = Path.home() / ".config" / "cascette-tools" / "config.json"

        if config_file.exists():
            with open(config_file) as f:
                data = json.load(f)
                return cls(**data)

        # Return defaults
        return cls()

    def save(self, config_file: Path | None = None) -> None:
        """Save configuration to file.

        Args:
            config_file: Path to config file, uses default if None
        """
        if config_file is None:
            config_file = self.config_dir / "config.json"

        config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(config_file, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2, default=str)

        logger.info("config_saved", path=str(config_file))

    @field_validator("output_format")
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        """Validate output format."""
        valid_formats = {"rich", "json", "yaml", "table"}
        if v not in valid_formats:
            raise ValueError(
                f"Invalid output format: {v}. Valid formats: {valid_formats}"
            )
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Valid levels: {valid_levels}")
        return v

    @field_validator("cdn_timeout")
    @classmethod
    def validate_cdn_timeout(cls, v: float) -> float:
        """Validate CDN timeout value."""
        if v <= 0:
            raise ValueError("CDN timeout must be positive")
        return v

    @field_validator("cache_ttl")
    @classmethod
    def validate_cache_ttl(cls, v: int) -> int:
        """Validate cache TTL value."""
        if v < 0:
            raise ValueError("Cache TTL must be non-negative")
        return v

    @field_validator("cache_max_size")
    @classmethod
    def validate_cache_max_size(cls, v: int) -> int:
        """Validate cache max size value."""
        if v < 0:
            raise ValueError("Cache max size must be non-negative")
        return v
