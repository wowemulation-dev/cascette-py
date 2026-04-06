"""Tests for CDN mirror resolution used by cdn.py commands.

These tests verify that resolve_mirrors_for_product() returns the same
mirrors that the old _get_cdn_mirrors_for_product() would have returned,
ensuring backward compatibility after the migration.
"""

from cascette_tools.core.config import (
    DEFAULT_FALLBACK_MIRRORS,
    DEFAULT_FAMILY_MIRRORS,
    MirrorSettings,
    resolve_mirrors_for_product,
)


class TestResolveMirrorsForCdnCommands:
    """Tests for mirror resolution as used by CDN commands."""

    def test_wow_product(self) -> None:
        mirrors = resolve_mirrors_for_product("wow", MirrorSettings())
        assert len(mirrors) == 3
        assert "https://casc.wago.tools" in mirrors
        assert "https://cdn.arctium.tools" in mirrors

    def test_wow_classic_product(self) -> None:
        mirrors = resolve_mirrors_for_product("wow_classic", MirrorSettings())
        assert len(mirrors) == 3
        assert mirrors == DEFAULT_FAMILY_MIRRORS["wow"]

    def test_wow_classic_era_product(self) -> None:
        mirrors = resolve_mirrors_for_product("wow_classic_era", MirrorSettings())
        assert len(mirrors) == 3

    def test_wow_classic_titan_product(self) -> None:
        mirrors = resolve_mirrors_for_product("wow_classic_titan", MirrorSettings())
        assert len(mirrors) == 3

    def test_wow_anniversary_product(self) -> None:
        mirrors = resolve_mirrors_for_product("wow_anniversary", MirrorSettings())
        assert len(mirrors) == 3

    def test_non_wow_product_agent(self) -> None:
        mirrors = resolve_mirrors_for_product("agent", MirrorSettings())
        assert len(mirrors) == 3
        assert "http://blzddist1-a.akamaihd.net" in mirrors
        assert "http://level3.blizzard.com" in mirrors

    def test_non_wow_product_bna(self) -> None:
        mirrors = resolve_mirrors_for_product("bna", MirrorSettings())
        assert "http://blzddist1-a.akamaihd.net" in mirrors

    def test_non_wow_product_diablo4(self) -> None:
        mirrors = resolve_mirrors_for_product("fenris", MirrorSettings())
        assert mirrors[0] == "http://blzddist1-a.akamaihd.net"

    def test_returns_list_copy(self) -> None:
        mirrors1 = resolve_mirrors_for_product("wow", MirrorSettings())
        mirrors2 = resolve_mirrors_for_product("wow", MirrorSettings())
        mirrors1.append("https://example.com")
        assert len(mirrors1) != len(mirrors2)

    def test_wow_mirrors_order(self) -> None:
        mirrors = resolve_mirrors_for_product("wow", MirrorSettings())
        assert mirrors[0] == "https://casc.wago.tools"
        assert mirrors[1] == "https://cdn.arctium.tools"
        assert mirrors[2] == "https://archive.wow.tools"

    def test_non_wow_mirrors_order(self) -> None:
        mirrors = resolve_mirrors_for_product("agent", MirrorSettings())
        assert mirrors == DEFAULT_FALLBACK_MIRRORS
