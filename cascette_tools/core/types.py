"""Core type definitions for cascette_tools."""

from enum import Enum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CompressionMode(StrEnum):
    """BLTE compression modes."""
    NONE = "N"
    ZLIB = "Z"
    LZ4 = "L"
    ENCRYPTED = "E"
    FRAME = "F"


class EncryptionType(Enum):
    """BLTE encryption types."""
    SALSA20 = 0x53
    ARC4 = 0x41


class Product(StrEnum):
    """Supported product codes."""
    WOW = "wow"
    WOW_CLASSIC = "wow_classic"
    WOW_CLASSIC_ERA = "wow_classic_era"
    WOW_CLASSIC_TITAN = "wow_classic_titan"
    WOW_ANNIVERSARY = "wow_anniversary"
    WOW_BETA = "wowt"
    WOW_PTR = "wowxptr"
    DIABLO_4 = "fenris"
    OVERWATCH_2 = "pro"
    HEARTHSTONE = "hsb"
    HEROES = "hero"
    STARCRAFT_2 = "s2"
    STARCRAFT_REMASTERED = "s1"
    WARCRAFT_3_REFORGED = "w3"
    DIABLO_2_RESURRECTED = "osi"
    CALL_OF_DUTY_MW2 = "wlby"
    AGENT = "agent"
    BNA = "bna"


class BuildInfo(BaseModel):
    """Build information structure."""
    build_config: str = Field(..., description="Build config hash")
    cdn_config: str = Field(..., description="CDN config hash")
    keyring: str | None = Field(None, description="Keyring hash")
    build_id: int | None = Field(None, description="Build ID")
    version_name: str | None = Field(None, description="Version string")
    product_config: str | None = Field(None, description="Product config hash")

    model_config = ConfigDict(extra="allow")


class FileDataId(BaseModel):
    """File Data ID structure."""
    id: int = Field(..., description="File Data ID")
    filename: str | None = Field(None, description="File name")
    content_key: str | None = Field(None, description="Content key")

    model_config = ConfigDict(extra="allow")


class CDNConfig(BaseModel):
    """CDN configuration structure."""
    archives: list[str] = Field(default_factory=list, description="Archive hashes")
    archive_group: str | None = Field(None, description="Archive group")
    patch_archives: list[str] = Field(default_factory=list, description="Patch archive hashes")
    patch_archive_group: str | None = Field(None, description="Patch archive group")
    builds: list[str] = Field(default_factory=list, description="Build configs")

    model_config = ConfigDict(extra="allow")


class TACTKey(BaseModel):
    """TACT encryption key."""
    key_name: str = Field(..., description="Key name/identifier")
    key_value: str = Field(..., description="Hex-encoded key value")
    lookup: str = Field(..., description="Lookup value")

    model_config = ConfigDict(extra="allow")


class LocaleConfig(BaseModel):
    """Configuration for a single installed locale."""

    code: str = Field(..., description="Locale code (e.g., enUS)")
    has_speech: bool = Field(default=False, description="Speech audio installed")
    has_text: bool = Field(default=False, description="Text/UI installed")

    def display(self) -> str:
        """Format locale with content flags."""
        flags: list[str] = []
        if self.has_speech:
            flags.append("speech")
        if self.has_text:
            flags.append("text")
        if flags:
            return f"{self.code} ({', '.join(flags)})"
        return self.code
