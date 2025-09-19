"""Configuration management for cascette-tools."""

from __future__ import annotations

import json
from pathlib import Path

import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger()


class CacheConfig(BaseModel):
    """Cache configuration."""

    cache_dir: Path = Field(
        default=Path.home() / ".cache" / "cascette",
        description="Cache directory"
    )
    ttl: int = Field(
        default=86400,  # 24 hours
        description="Time to live in seconds"
    )
    max_size: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10GB
        description="Maximum cache size in bytes"
    )
    enabled: bool = Field(
        default=True,
        description="Whether caching is enabled"
    )

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
    """CDN configuration with required mirrors."""

    # Fixed mirror order - do not change
    mirrors: list[str] = Field(
        default=[
            "https://cdn.arctium.tools",          # Primary: Complete historical data
            "https://casc.wago.tools",            # Secondary: Community integration
            "https://tact.mirror.reliquaryhq.com"  # Tertiary: Backup mirror
        ],
        description="CDN mirrors in priority order"
    )
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts per mirror")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")

    @property
    def base_url(self) -> str:
        """Get primary mirror URL for backward compatibility."""
        return f"{self.mirrors[0]}/tpr/wow/"

    @field_validator("mirrors")
    @classmethod
    def validate_mirrors(cls, v: list[str]) -> list[str]:
        """Validate mirrors list."""
        if not v:
            raise ValueError("Mirrors list cannot be empty")
        return v

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
        default=["us", "eu", "kr", "tw", "cn", "sg"],
        description="Supported regions"
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
                raise ValueError(f"Invalid region: {region}. Valid regions: {valid_regions}")

        return v


class AppConfig(BaseModel):
    """Application configuration."""

    # Directory settings
    config_dir: Path = Field(
        default=Path.home() / ".config" / "cascette-tools",
        description="Configuration directory"
    )
    data_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "cascette-tools",
        description="Data directory"
    )

    # CDN settings
    cdn_base_url: str = Field(
        default="https://cdn.arctium.tools/tpr/wow/",
        description="Base CDN URL"
    )
    cdn_timeout: float = Field(default=30.0, description="CDN request timeout")
    cdn_max_retries: int = Field(default=3, description="CDN max retry attempts")

    # Cache settings
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_max_size: int = Field(
        default=10 * 1024 * 1024 * 1024,
        description="Maximum cache size in bytes"
    )
    cache_ttl: int = Field(
        default=86400 * 7,
        description="Cache time to live in seconds"
    )

    # Output settings
    output_format: str = Field(
        default="rich",
        description="Output format (rich, json, yaml, table)"
    )
    log_level: str = Field(
        default="INFO",
        description="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )

    def model_post_init(self, __context) -> None:
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
            raise ValueError(f"Invalid output format: {v}. Valid formats: {valid_formats}")
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
