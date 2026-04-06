"""Tests for the cascette config mirror CLI commands."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from cascette_tools.__main__ import main
from cascette_tools.core.config import AppConfig, MirrorConfig, MirrorSettings


def _make_config(mirrors: MirrorSettings | None = None) -> AppConfig:
    """Create an AppConfig with optional mirror settings."""
    return AppConfig(mirrors=mirrors or MirrorSettings())


def _invoke(*args: str, config: AppConfig | None = None) -> object:
    """Invoke a CLI command and return the result."""
    runner = CliRunner()
    cfg = config or _make_config()
    with patch.object(AppConfig, "load", return_value=cfg):
        with patch.object(AppConfig, "save"):
            return runner.invoke(main, list(args))


class TestMirrorAdd:
    """Tests for 'cascette config mirror add'."""

    def test_add_family_mirror(self) -> None:
        result = _invoke("config", "mirror", "add", "wow", "https://example.com")
        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "family" in result.output

    def test_add_product_override(self) -> None:
        result = _invoke(
            "config", "mirror", "add", "--product-code", "bna",
            "http://bna.example.com"
        )
        assert result.exit_code == 0
        assert "product" in result.output

    def test_add_multiple_urls(self) -> None:
        result = _invoke(
            "config", "mirror", "add", "wow",
            "https://a.example.com", "https://b.example.com"
        )
        assert result.exit_code == 0
        assert "a.example.com" in result.output
        assert "b.example.com" in result.output

    def test_add_duplicate_ignored(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://existing.example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke(
            "config", "mirror", "add", "wow", "https://existing.example.com",
            config=cfg,
        )
        assert result.exit_code == 0
        assert "No new URLs" in result.output

    def test_add_invalid_url(self) -> None:
        result = _invoke("config", "mirror", "add", "wow", "ftp://bad.example.com")
        assert result.exit_code != 0
        assert "http://" in result.output

    def test_add_invalid_family(self) -> None:
        result = _invoke("config", "mirror", "add", "bogus", "https://example.com")
        assert result.exit_code != 0
        assert "Unknown product family" in result.output

    def test_add_invalid_product_code(self) -> None:
        result = _invoke(
            "config", "mirror", "add", "--product-code", "bogus",
            "https://example.com"
        )
        assert result.exit_code != 0
        assert "Unknown product code" in result.output


class TestMirrorRemove:
    """Tests for 'cascette config mirror remove'."""

    def test_remove_specific_url(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=[
                    "https://a.example.com",
                    "https://b.example.com",
                ]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke(
            "config", "mirror", "remove", "wow", "https://a.example.com",
            config=cfg,
        )
        assert result.exit_code == 0
        assert "Removed" in result.output

    def test_remove_all_for_target(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke("config", "mirror", "remove", "wow", config=cfg)
        assert result.exit_code == 0
        assert "Removed all" in result.output

    def test_remove_nonexistent_target(self) -> None:
        result = _invoke("config", "mirror", "remove", "wow")
        assert result.exit_code == 0
        assert "No mirrors configured" in result.output


class TestMirrorList:
    """Tests for 'cascette config mirror list'."""

    def test_list_empty(self) -> None:
        result = _invoke("config", "mirror", "list")
        assert result.exit_code == 0
        assert "built-in defaults" in result.output.lower() or "Built-in" in result.output

    def test_list_with_family_config(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://custom.example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke("config", "mirror", "list", config=cfg)
        assert result.exit_code == 0
        assert "custom.example.com" in result.output

    def test_list_resolve(self) -> None:
        result = _invoke("config", "mirror", "list", "--resolve", "wow")
        assert result.exit_code == 0
        assert "casc.wago.tools" in result.output
        assert "built-in default" in result.output

    def test_list_resolve_product_override(self) -> None:
        mirrors = MirrorSettings(
            product_overrides={
                "bna": MirrorConfig(urls=["http://custom-bna.example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke(
            "config", "mirror", "list", "--resolve", "bna", config=cfg
        )
        assert result.exit_code == 0
        assert "custom-bna.example.com" in result.output
        assert "product override" in result.output

    def test_list_resolve_invalid_product(self) -> None:
        result = _invoke("config", "mirror", "list", "--resolve", "bogus")
        assert result.exit_code != 0
        assert "Unknown product code" in result.output


class TestMirrorReset:
    """Tests for 'cascette config mirror reset'."""

    def test_reset_all(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke("config", "mirror", "reset", "--all", config=cfg)
        assert result.exit_code == 0
        assert "Reset all" in result.output

    def test_reset_family(self) -> None:
        mirrors = MirrorSettings(
            family_mirrors={
                "wow": MirrorConfig(urls=["https://example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke("config", "mirror", "reset", "wow", config=cfg)
        assert result.exit_code == 0
        assert "Reset family" in result.output

    def test_reset_product(self) -> None:
        mirrors = MirrorSettings(
            product_overrides={
                "bna": MirrorConfig(urls=["http://example.com"]),
            }
        )
        cfg = _make_config(mirrors)
        result = _invoke(
            "config", "mirror", "reset", "--product-code", "bna", config=cfg
        )
        assert result.exit_code == 0
        assert "Reset product" in result.output

    def test_reset_without_target_or_all(self) -> None:
        result = _invoke("config", "mirror", "reset")
        assert result.exit_code != 0
        assert "--all" in result.output

    def test_reset_nonexistent_family(self) -> None:
        result = _invoke("config", "mirror", "reset", "wow")
        assert result.exit_code == 0
        assert "No family mirrors" in result.output
