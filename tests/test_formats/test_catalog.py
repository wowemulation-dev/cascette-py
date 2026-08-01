"""Tests for cascette_tools.formats.catalog."""

import json
from pathlib import Path
from typing import Any

import pytest

from cascette_tools.formats.catalog import (
    CatalogFragment,
    CatalogParser,
    EntitlementAction,
    EntitlementMatchCriteria,
    EntitlementRule,
    extract_license_ids,
    rule_license_ids,
)

# Realistic v23 root fragment (flat categories/types schema, build 928).
V23_ROOT = {
    "categories": {
        "in_development": {"name": "default#CATEGORIES_INDEVELOPMENT_NAME"},
        "live": {"name": "default#CATEGORIES_LIVE_NAME"},
    },
    "fragment_id": "default",
    "fragments": [
        {"hash": "684fe1b51cbaa70a36e2ddf9ca2bc9f9", "name": "world_of_warcraft"},
        {
            "hash": "2f7a42d6f2dfcb3bf3c31a6d50952727",
            "name": "overwatch_mac",
            "platform": "mac",
        },
    ],
    "types": {
        "beta": {"category_id": "in_development"},
        "retail": {"category_id": "live"},
    },
    "vars": {"Client.Profiles.Enabled": "true"},
    "version": 23,
}

# Realistic v30 root fragment (definitions schema, build 4929).
V30_ROOT = {
    "categories": {
        "definitions": [
            {"id": "cat_unknown", "name": "default#CATEGORIES_UNKNOWN_NAME", "rank": 0},
            {"id": "cat_live", "name": "default#CATEGORIES_LIVE_NAME", "rank": 100},
        ]
    },
    "fragment_id": "default",
    "fragments": [
        {"hash": "f553e93cd67f24d1b8158a68d5406edc", "name": "world_of_warcraft"},
        {
            "hash": "70070f0c3c7dc34de83a7788a10c2a56",
            "name": "anbs_cndefault",
            "requires": {"include": "CN", "type": "login_region"},
        },
    ],
    "types": {
        "definitions": [
            {
                "category": "cat_in_development",
                "id": "dev",
                "product_defaults": {"name_style": "type_name_suffix", "rank": 1},
            }
        ]
    },
    "version": 30,
}

# Realistic v30 product fragment with entitlement rules and installs.
V30_WOW = {
    "categories": {
        "definitions": [
            {
                "id": "cat_wow_classic_live",
                "name": "world_of_warcraft#CATEGORIES_WOW_LIVE_CLASSIC_NAME",
                "rank": 99,
            }
        ]
    },
    "fragment_id": "world_of_warcraft",
    "installs": {
        "wow": {
            "tact_product": "wow",
            "run_64_bit_only": True,
            "sso_launch_argument": "-launcherlogin",
        },
        "wow_classic": {
            "tact_product": "wow_classic",
            "auto_update_policy": {"meets_criteria": {"has_game_time": True}},
        },
    },
    "products": [
        {
            "base": {
                "program_id": "WoW",
                "name": "world_of_warcraft#PRODUCTS_WOW_NAME",
                "default_product_type": "retail",
                "tab_order": 1,
            },
            "id": "WoW",
        }
    ],
    "program_configuration": {
        "WoW": {
            "is_game_account_level": True,
            "run_each_rule": [
                {
                    "actions": [
                        {
                            "add_product": {
                                "product_id": {"id": "WoW", "type": "wow_classic"}
                            }
                        },
                        {
                            "run_first_rule": [
                                {
                                    "actions": [
                                        {
                                            "add_product": {
                                                "product_id": {
                                                    "id": "WoWX12",
                                                    "type": "retail",
                                                }
                                            }
                                        }
                                    ],
                                    "match": {"license_id": [1106089]},
                                },
                                {
                                    "actions": [
                                        {
                                            "add_product": {
                                                "product_id": {
                                                    "id": "WoW",
                                                    "type": "retail",
                                                }
                                            }
                                        }
                                    ],
                                },
                            ]
                        },
                    ],
                    "match": {
                        "game_account": {"program_id": "WoW", "region": ["US", "EU"]}
                    },
                },
                {
                    "actions": [{"add_tag": {"name": "disable_upgrade"}}],
                    "match": {
                        "all_of": [
                            {
                                "not": {
                                    "game_account": {
                                        "program_id": "WoW",
                                        "region": "CN",
                                    }
                                }
                            },
                            {"license_id": [1126660, 1106074]},
                        ]
                    },
                },
                {
                    "actions": [
                        {
                            "add_product": {
                                "level": "program",
                                "product_id": {"id": "WoWPTR", "type": "ptr"},
                            }
                        }
                    ],
                    "match": {"license_id": 179712},
                },
            ],
        }
    },
    "types": {
        "definitions": [
            {
                "category": "cat_wow_classic_live",
                "id": "wow_classic",
                "product_defaults": {"rank": -2},
            }
        ]
    },
    "version": 30,
}


def _dumps(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@pytest.fixture
def parser() -> CatalogParser:
    return CatalogParser()


class TestParse:
    """Test parsing catalog fragments."""

    def test_parse_v23_root(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V23_ROOT))
        assert fragment.fragment_id == "default"
        assert fragment.version == 23
        assert fragment.is_root is True
        assert len(fragment.fragments) == 2
        assert fragment.fragments[0].hash == "684fe1b51cbaa70a36e2ddf9ca2bc9f9"
        assert fragment.fragments[0].name == "world_of_warcraft"
        assert fragment.fragments[1].platform == "mac"

    def test_parse_v30_root(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_ROOT))
        assert fragment.version == 30
        assert fragment.is_root is True
        assert len(fragment.fragments) == 2
        assert fragment.fragments[1].requires == {
            "include": "CN",
            "type": "login_region",
        }

    def test_parse_v30_product_fragment(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        assert fragment.fragment_id == "world_of_warcraft"
        assert fragment.is_root is False
        assert len(fragment.products) == 1
        base = fragment.products[0].base
        assert base is not None
        assert base.program_id == "WoW"
        assert fragment.products[0].id == "WoW"
        assert "WoW" in fragment.program_configuration
        assert len(fragment.installs) == 2
        assert fragment.installs["wow_classic"].tact_product == "wow_classic"

    def test_parse_empty_program_configuration(self, parser: CatalogParser):
        """v23 product fragments carry an empty program_configuration list."""
        payload = dict(V30_WOW)
        payload["program_configuration"] = []
        fragment = parser.parse(_dumps(payload))
        assert fragment.program_configuration == {}

    def test_parse_invalid_json(self, parser: CatalogParser):
        with pytest.raises(ValueError, match="Invalid catalog JSON"):
            parser.parse(b"not json at all")

    def test_parse_file(self, parser: CatalogParser, tmp_path: Path):
        path = tmp_path / "fragment.json"
        path.write_bytes(_dumps(V30_WOW))
        fragment = parser.parse_file(str(path))
        assert fragment.fragment_id == "world_of_warcraft"


class TestCategoriesAndTypes:
    """Test schema normalization for categories/types."""

    def test_categories_v23(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V23_ROOT))
        categories = fragment.categories
        assert [c.id for c in categories] == ["in_development", "live"]
        assert categories[0].name == "default#CATEGORIES_INDEVELOPMENT_NAME"

    def test_categories_v30(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_ROOT))
        categories = fragment.categories
        assert [c.id for c in categories] == ["cat_unknown", "cat_live"]
        assert categories[0].rank == 0

    def test_types_v23(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V23_ROOT))
        types = fragment.types
        assert [t.id for t in types] == ["beta", "retail"]
        assert types[0].category_id == "in_development"
        assert types[0].category is None

    def test_types_v30(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_ROOT))
        types = fragment.types
        assert [t.id for t in types] == ["dev"]
        assert types[0].category == "cat_in_development"


class TestRules:
    """Test entitlement rule parsing."""

    def test_rule_structure(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        program = fragment.program_configuration["WoW"]
        assert program.is_game_account_level is True
        rules = program.run_each_rule or []
        assert len(rules) == 3

    def test_nested_run_first_rule(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        program = fragment.program_configuration["WoW"]
        rules = program.run_each_rule or []
        first_rule = rules[0]
        assert first_rule.match is not None
        assert first_rule.match.game_account is not None
        assert first_rule.match.game_account.region == ["US", "EU"]
        assert len(first_rule.actions or []) == 2
        actions = first_rule.actions
        assert actions is not None
        run_first = actions[1].run_first_rule
        assert run_first is not None
        assert len(run_first) == 2

    def test_add_product_with_level(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        rules = fragment.program_configuration["WoW"].run_each_rule or []
        rule_actions = rules[2].actions
        assert rule_actions is not None
        action = rule_actions[0]
        assert action.add_product is not None
        assert action.add_product.level == "program"
        assert action.add_product.product_id.id == "WoWPTR"
        assert action.add_product.product_id.type == "ptr"

    def test_license_id_single_int(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        rules = fragment.program_configuration["WoW"].run_each_rule or []
        match = rules[2].match
        assert match is not None
        assert match.license_id == 179712

    def test_always_match_shorthand(self):
        rule = EntitlementRule.model_validate({"match": "always", "actions": []})
        assert rule.match is not None
        assert rule.match.always is True

    def test_boolean_match_shorthand(self):
        """Real catalog data uses bare booleans as match criteria."""
        always = EntitlementRule.model_validate({"match": True, "actions": []})
        assert always.match is not None
        assert always.match.always is True
        never = EntitlementRule.model_validate({"match": False, "actions": []})
        assert never.match is not None
        assert never.match.always is False

    def test_account_region_list(self):
        """Real catalog data uses a list for account_region/account_country."""
        criteria = EntitlementMatchCriteria.model_validate(
            {"all_of": [{"account_region": ["CN"]}, {"account_country": "US"}]}
        )
        all_of = criteria.all_of
        assert all_of is not None
        child = all_of[0]
        assert child.account_region == ["CN"]
        second = all_of[1]
        assert second.account_country == "US"

    def test_variant_only_product(self, parser: CatalogParser):
        """Some products carry variants instead of a base descriptor."""
        payload = {
            "fragment_id": "world_of_warcraft",
            "products": [{"id": "WoW", "variants": {"retail": {"name": "x"}}}],
            "version": 30,
        }
        fragment = parser.parse(_dumps(payload))
        product = fragment.products[0]
        assert product.id == "WoW"
        assert product.base is None
        assert product.model_extra == {"variants": {"retail": {"name": "x"}}}

    def test_encrypted_fragment_ref(self, parser: CatalogParser):
        """Encrypted fragment references expose decryption metadata."""
        payload = {
            "fragment_id": "default",
            "fragments": [
                {
                    "decryption_key_id": "catalog-decryption-key-moon2",
                    "encrypted_hash": "3d27dc812c5c14aa64212057a06582a6",
                    "hash": "2ad29587ffd83b33cb43a169b0bcc37c",
                    "name": "moon",
                }
            ],
            "version": 30,
        }
        fragment = parser.parse(_dumps(payload))
        ref = fragment.fragments[0]
        assert ref.is_encrypted is True
        assert ref.decryption_key_id == "catalog-decryption-key-moon2"
        assert ref.encrypted_hash == "3d27dc812c5c14aa64212057a06582a6"

    def test_unknown_criteria_tolerated(self):
        criteria = EntitlementMatchCriteria.model_validate(
            {"future_criteria": {"x": 1}, "license_id": [5]}
        )
        assert criteria.license_id == [5]
        assert criteria.model_extra == {"future_criteria": {"x": 1}}

    def test_unknown_action_tolerated(self):
        action = EntitlementAction.model_validate({"future_action": True})
        assert action.model_extra == {"future_action": True}


class TestLicenseExtraction:
    """Test license ID extraction from rules."""

    def test_extract_simple(self):
        criteria = EntitlementMatchCriteria.model_validate({"license_id": [1106089]})
        assert extract_license_ids(criteria) == [1106089]

    def test_extract_single_int(self):
        criteria = EntitlementMatchCriteria.model_validate({"license_id": 179712})
        assert extract_license_ids(criteria) == [179712]

    def test_extract_nested_combinators(self):
        criteria = EntitlementMatchCriteria.model_validate(
            {
                "all_of": [
                    {"not": {"license_id": [5]}},
                    {"any_of": [{"license_id": [6, 7]}, {"license_id": 8}]},
                ]
            }
        )
        assert sorted(extract_license_ids(criteria)) == [5, 6, 7, 8]

    def test_extract_none(self):
        assert extract_license_ids(None) == []

    def test_rule_license_ids_with_nested_rules(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V30_WOW))
        program = fragment.program_configuration["WoW"]
        rules = program.run_each_rule or []
        ids = set()
        for rule in rules:
            ids.update(rule_license_ids(rule))
        assert ids == {1106089, 1126660, 1106074, 179712}


class TestRoundtrip:
    """Test build() round-trips byte-exact."""

    @pytest.mark.parametrize("payload", [V23_ROOT, V30_ROOT, V30_WOW])
    def test_roundtrip_exact(self, parser: CatalogParser, payload: dict[str, Any]):
        raw = _dumps(payload)
        fragment = parser.parse(raw)
        assert parser.build(fragment) == raw

    def test_model_data_preserved(self, parser: CatalogParser):
        fragment = parser.parse(_dumps(V23_ROOT))
        assert isinstance(fragment, CatalogFragment)
        assert fragment.data["version"] == 23
