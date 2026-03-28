"""Tests for cdn.py utility functions."""

from cascette_tools.commands.cdn import _get_cdn_mirrors_for_product


class TestGetCdnMirrorsForProduct:
    """Tests for _get_cdn_mirrors_for_product function."""

    def test_wow_product(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow")
        assert len(mirrors) == 3
        assert "https://casc.wago.tools" in mirrors
        assert "https://cdn.arctium.tools" in mirrors

    def test_wow_classic_product(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow_classic")
        assert len(mirrors) == 3
        assert mirrors[0] == "https://casc.wago.tools"

    def test_wow_classic_era_product(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow_classic_era")
        assert len(mirrors) == 3

    def test_wow_classic_titan_product(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow_classic_titan")
        assert len(mirrors) == 3

    def test_wow_anniversary_product(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow_anniversary")
        assert len(mirrors) == 3

    def test_non_wow_product_agent(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("agent")
        assert len(mirrors) == 3
        assert "http://blzddist1-a.akamaihd.net" in mirrors
        assert "http://level3.blizzard.com" in mirrors

    def test_non_wow_product_bna(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("bna")
        assert "http://blzddist1-a.akamaihd.net" in mirrors

    def test_non_wow_product_diablo4(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("fenris")
        assert mirrors[0] == "http://blzddist1-a.akamaihd.net"

    def test_returns_list_copy(self) -> None:
        mirrors1 = _get_cdn_mirrors_for_product("wow")
        mirrors2 = _get_cdn_mirrors_for_product("wow")
        mirrors1.append("https://example.com")
        assert len(mirrors1) != len(mirrors2)

    def test_wow_mirrors_order(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("wow")
        assert mirrors[0] == "https://casc.wago.tools"
        assert mirrors[1] == "https://cdn.arctium.tools"
        assert mirrors[2] == "https://archive.wow.tools"

    def test_non_wow_mirrors_order(self) -> None:
        mirrors = _get_cdn_mirrors_for_product("agent")
        assert mirrors[0] == "http://blzddist1-a.akamaihd.net"
        assert mirrors[1] == "http://level3.blizzard.com"
        assert mirrors[2] == "http://cdn.blizzard.com"
