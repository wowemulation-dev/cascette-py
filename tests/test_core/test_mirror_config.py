"""Tests for product family mapping, mirror configuration, and resolution."""

from __future__ import annotations

import pytest

from cascette_tools.core.config import (
    DEFAULT_FALLBACK_MIRRORS,
    DEFAULT_FAMILY_MIRRORS,
    MirrorConfig,
    MirrorSettings,
    resolve_mirrors_for_product,
)
from cascette_tools.core.types import (
    PRODUCT_FAMILY_MAP,
    Product,
    ProductFamily,
    get_product_family,
)


class TestProductFamily:
    """Tests for ProductFamily enum and PRODUCT_FAMILY_MAP."""

    def test_all_products_have_family(self) -> None:
        """Every Product member must have an entry in PRODUCT_FAMILY_MAP."""
        assert set(PRODUCT_FAMILY_MAP.keys()) == set(Product)

    def test_wow_family_members(self) -> None:
        wow_members = [
            Product.WOW,
            Product.WOW_CLASSIC,
            Product.WOW_CLASSIC_ERA,
            Product.WOW_CLASSIC_TITAN,
            Product.WOW_ANNIVERSARY,
            Product.WOW_BETA,
            Product.WOW_PTR,
        ]
        for product in wow_members:
            assert PRODUCT_FAMILY_MAP[product] == ProductFamily.WOW

    def test_battlenet_family_members(self) -> None:
        for product in [Product.AGENT, Product.BNA, Product.BTS]:
            assert PRODUCT_FAMILY_MAP[product] == ProductFamily.BATTLENET

    def test_diablo_family_members(self) -> None:
        for product in [Product.DIABLO_4, Product.DIABLO_2_RESURRECTED]:
            assert PRODUCT_FAMILY_MAP[product] == ProductFamily.DIABLO

    def test_starcraft_family_members(self) -> None:
        for product in [Product.STARCRAFT_2, Product.STARCRAFT_REMASTERED]:
            assert PRODUCT_FAMILY_MAP[product] == ProductFamily.STARCRAFT


class TestGetProductFamily:
    """Tests for get_product_family() helper."""

    def test_by_enum(self) -> None:
        assert get_product_family(Product.WOW) == ProductFamily.WOW

    def test_by_string(self) -> None:
        assert get_product_family("wow") == ProductFamily.WOW
        assert get_product_family("bna") == ProductFamily.BATTLENET

    def test_unknown_string_raises(self) -> None:
        with pytest.raises(ValueError):
            get_product_family("nonexistent_product")

    def test_all_products_resolvable(self) -> None:
        for product in Product:
            family = get_product_family(product)
            assert isinstance(family, ProductFamily)


class TestMirrorConfig:
    """Tests for MirrorConfig model."""

    def test_valid_http_urls(self) -> None:
        cfg = MirrorConfig(urls=["http://example.com", "https://mirror.test"])
        assert len(cfg.urls) == 2

    def test_invalid_url_scheme(self) -> None:
        with pytest.raises(ValueError, match="http:// or https://"):
            MirrorConfig(urls=["ftp://bad.example.com"])

    def test_empty_urls_allowed(self) -> None:
        cfg = MirrorConfig(urls=[])
        assert cfg.urls == []

    def test_default_empty(self) -> None:
        cfg = MirrorConfig()
        assert cfg.urls == []


class TestMirrorSettings:
    """Tests for MirrorSettings model."""

    def test_default_empty(self) -> None:
        settings = MirrorSettings()
        assert settings.family_mirrors == {}
        assert settings.product_overrides == {}

    def test_serialization_roundtrip(self) -> None:
        settings = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://example.com"]),
            },
            product_overrides={
                "bna": MirrorConfig(urls=["http://bna.example.com"]),
            },
        )
        data = settings.model_dump()
        restored = MirrorSettings(**data)
        assert restored.family_mirrors["wow"].urls == ["https://example.com"]
        assert restored.product_overrides["bna"].urls == ["http://bna.example.com"]


class TestResolveMirrorsForProduct:
    """Tests for resolve_mirrors_for_product()."""

    def test_product_override_takes_priority(self) -> None:
        settings = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://family.example.com"]),
            },
            product_overrides={
                "wow_classic": MirrorConfig(urls=["https://override.example.com"]),
            },
        )
        result = resolve_mirrors_for_product("wow_classic", settings)
        assert result == ["https://override.example.com"]

    def test_family_config_used_when_no_override(self) -> None:
        settings = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://family.example.com"]),
            },
        )
        result = resolve_mirrors_for_product("wow_classic", settings)
        assert result == ["https://family.example.com"]

    def test_builtin_defaults_when_no_user_config(self) -> None:
        settings = MirrorSettings()
        result = resolve_mirrors_for_product("wow", settings)
        assert result == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_generic_fallback_for_non_wow_product(self) -> None:
        settings = MirrorSettings()
        result = resolve_mirrors_for_product("bna", settings)
        assert result == DEFAULT_FALLBACK_MIRRORS

    def test_generic_fallback_for_agent(self) -> None:
        settings = MirrorSettings()
        result = resolve_mirrors_for_product("agent", settings)
        assert result == DEFAULT_FALLBACK_MIRRORS

    def test_wow_family_shares_mirrors(self) -> None:
        """All WoW products get the same family mirrors."""
        settings = MirrorSettings()
        wow_products = ["wow", "wow_classic", "wow_classic_era", "wowt"]
        for product in wow_products:
            result = resolve_mirrors_for_product(product, settings)
            assert result == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_returns_list_copy(self) -> None:
        settings = MirrorSettings()
        r1 = resolve_mirrors_for_product("wow", settings)
        r2 = resolve_mirrors_for_product("wow", settings)
        r1.append("https://mutated.example.com")
        assert len(r1) != len(r2)

    def test_accepts_product_enum(self) -> None:
        settings = MirrorSettings()
        result = resolve_mirrors_for_product(Product.WOW, settings)
        assert result == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_empty_override_falls_through(self) -> None:
        """An empty product override should fall through to family config."""
        settings = MirrorSettings(
            product_overrides={
                "wow": MirrorConfig(urls=[]),
            },
        )
        result = resolve_mirrors_for_product("wow", settings)
        assert result == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_empty_family_config_falls_through(self) -> None:
        """An empty family config should fall through to built-in defaults."""
        settings = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=[]),
            },
        )
        result = resolve_mirrors_for_product("wow", settings)
        assert result == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_user_family_config_overrides_builtin(self) -> None:
        custom = ["https://custom1.example.com", "https://custom2.example.com"]
        settings = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=custom),
            },
        )
        result = resolve_mirrors_for_product("wow", settings)
        assert result == custom

    def test_result_always_non_empty(self) -> None:
        """Resolution should return a non-empty list for any valid product."""
        settings = MirrorSettings()
        for product in Product:
            result = resolve_mirrors_for_product(product, settings)
            assert len(result) > 0, f"Empty result for {product}"
