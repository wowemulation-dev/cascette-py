"""Parser for Blizzard's TPR product catalog.

The catalog is the layer above the NGDP flow. It describes which products
exist, their entitlement requirements, and their install configurations.
The Battle.net client fetches it from ``tpr/catalogs`` (a Ribbit product
code of ``catalogs``) as hash-addressed JSON fragments: a root fragment
references per-product sub-fragments by hash.

Two catalog schemas exist in the wild:

- v23 (build 928): ``categories``/``types`` are flat dicts keyed by id,
  product fragments carry no ``program_configuration``.
- v30 (build 4929): ``categories``/``types`` use a ``definitions`` list,
  product fragments carry entitlement rules in ``program_configuration``
  and install configs in ``installs``.

The parser stores the raw JSON for byte-exact round-trips and exposes
typed views (products, rules, installs, categories, types) through
properties, since ``build()`` re-serializes ``data`` verbatim.
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cascette_tools.formats.base import FormatParser

__all__ = [
    "AddProductAction",
    "AddTagAction",
    "CatalogFragment",
    "CatalogFragmentRef",
    "CatalogInstallConfig",
    "CatalogParser",
    "CatalogProduct",
    "CatalogProductBase",
    "CatalogTypeDef",
    "EntitlementAction",
    "EntitlementMatchCriteria",
    "EntitlementRule",
    "GameAccountCriteria",
    "ProductRef",
    "ProgramConfiguration",
    "RealmPermissions",
    "extract_license_ids",
    "rule_license_ids",
]


class CatalogFragmentRef(BaseModel):
    """Reference to a sub-fragment from the root catalog fragment."""

    model_config = ConfigDict(extra="allow")

    hash: str = Field(..., description="Fragment hash (CDN data file key)")
    name: str = Field(..., description="Fragment name (e.g. 'world_of_warcraft')")
    platform: str | None = Field(
        None, description="Optional platform filter (e.g. 'mac')"
    )
    requires: dict[str, Any] | None = Field(
        None, description="Optional region/country gate (v30+ only)"
    )
    encrypted_hash: str | None = Field(
        None, description="Hash of the encrypted form served by the CDN"
    )
    decryption_key_id: str | None = Field(
        None, description="TACT key id required to decrypt the fragment"
    )

    @property
    def is_encrypted(self) -> bool:
        """True when the fragment is served encrypted on the CDN."""
        return bool(self.encrypted_hash or self.decryption_key_id)


class CatalogCategory(BaseModel):
    """A product display category."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Category id (e.g. 'cat_live')")
    name: str | None = Field(None, description="String-table key for the display name")
    rank: int | None = Field(None, description="Display rank (lower sorts first)")


class CatalogTypeDef(BaseModel):
    """A product type (retail, beta, ptr, ...) and its category."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Type id (e.g. 'wow_classic')")
    category: str | None = Field(None, description="Category id (v30 key 'category')")
    category_id: str | None = Field(
        None, description="Category id (v23 key 'category_id', legacy alias)"
    )
    product_defaults: dict[str, Any] | None = Field(None, description="Type defaults")


class CatalogProductBase(BaseModel):
    """Base product descriptor shared by all types of a product."""

    model_config = ConfigDict(extra="allow")

    program_id: str | None = Field(None, description="Program FourCC (e.g. 'WoW')")
    name: str | None = Field(None, description="String-table key for the product name")
    real_product_id: str | None = Field(None, description="Real product id")
    default_product_type: str | None = Field(None, description="Default type id")
    tab_order: int | None = Field(None, description="Display ordering hint")


class CatalogProduct(BaseModel):
    """A product entry inside a product fragment."""

    model_config = ConfigDict(extra="allow")

    id: str | None = Field(None, description="Product id (v30+; otherwise in base)")
    base: CatalogProductBase | None = Field(
        None, description="Base product descriptor (absent for variant-only products)"
    )
    states: list[dict[str, Any]] | None = Field(None, description="Product states")


class GameAccountCriteria(BaseModel):
    """Game-account match criteria (program id and/or regions)."""

    model_config = ConfigDict(extra="allow")

    program_id: str | None = None
    region: str | list[str] | None = None


class RealmPermissions(BaseModel):
    """Realm permission bitmask criteria."""

    model_config = ConfigDict(extra="allow")

    bits: int | None = None


class EntitlementMatchCriteria(BaseModel):
    """A match criteria node in an entitlement rule.

    The JSON schema is a single-key object; any of the fields below may be
    set (``extra`` tolerates future keys). Combinator fields (``all_of``,
    ``any_of``, ``none_of``, ``not``) recurse. ``license_id`` accepts either
    a single integer or a list of integers.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    license_id: int | list[int] | None = None
    game_account: GameAccountCriteria | None = None
    all_of: list[EntitlementMatchCriteria] | None = None
    any_of: list[EntitlementMatchCriteria] | None = None
    none_of: list[EntitlementMatchCriteria] | None = None
    not_: EntitlementMatchCriteria | None = Field(default=None, alias="not")
    flag: str | None = None
    realm_permissions: RealmPermissions | None = None
    igr: bool | None = None
    account_country: str | list[str] | None = None
    account_region: str | list[str] | None = None
    always: bool | None = None


class ProductRef(BaseModel):
    """Reference to a product/type pair in an add/remove product action."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Product id (e.g. 'WoW', 'WoWX12')")
    type: str | None = Field(None, description="Type id (e.g. 'wow_classic', 'retail')")


class AddProductAction(BaseModel):
    """add_product action payload."""

    model_config = ConfigDict(extra="allow")

    product_id: ProductRef
    level: str | None = Field(None, description="Action level (e.g. 'program')")


class AddTagAction(BaseModel):
    """add_tag action payload."""

    model_config = ConfigDict(extra="allow")

    name: str


class EntitlementAction(BaseModel):
    """An action applied when a rule's criteria match.

    Exactly one action field is set per JSON object. Nested rule collections
    (``run_first_rule``/``run_each_rule``) recurse back into rules.
    """

    model_config = ConfigDict(extra="allow")

    add_product: AddProductAction | None = None
    remove_product: AddProductAction | None = None
    add_tag: AddTagAction | None = None
    remove_tag: AddTagAction | None = None
    run_rule: str | None = None
    run_each_rule: list[EntitlementRule] | None = None
    run_first_rule: list[EntitlementRule] | None = None


class EntitlementRule(BaseModel):
    """A single entitlement rule: optional match criteria plus actions."""

    model_config = ConfigDict(extra="allow")

    match: EntitlementMatchCriteria | None = None
    actions: list[EntitlementAction] | None = None
    level: str | None = None

    @field_validator("match", mode="before")
    @classmethod
    def _normalize_match(cls, v: Any) -> Any:
        """Accept shorthand criteria: the string ``"always"`` and bare booleans.

        ``true`` means an always-true criteria; ``false`` an always-false one.
        """
        if v == "always" or v is True:
            return {"always": True}
        if v is False:
            return {"always": False}
        return v


class ProgramConfiguration(BaseModel):
    """Entitlement rules for one program (e.g. ``WoW``)."""

    model_config = ConfigDict(extra="allow")

    is_game_account_level: bool | None = Field(
        None, description="Rules apply per game account when true"
    )
    run_each_rule: list[EntitlementRule] | None = None
    run_first_rule: list[EntitlementRule] | None = None
    basic_rule: EntitlementRule | None = None


class CatalogInstallConfig(BaseModel):
    """Install configuration for one product type."""

    model_config = ConfigDict(extra="allow")

    tact_product: str | None = Field(
        None, description="TACT product code linking to the NGDP pipeline"
    )
    auto_update_policy: dict[str, Any] | None = None
    run_64_bit_only: bool | None = None
    sso_launch_argument: str | None = None
    locale_specific_uid: bool | None = None


class CatalogFragment(BaseModel):
    """A raw catalog JSON fragment (root or per-product).

    ``data`` holds the original JSON, so ``build()`` round-trips byte-exact
    for any fragment. Typed views are exposed via properties.
    """

    model_config = ConfigDict(extra="allow")

    data: dict[str, Any] = Field(default_factory=dict, description="Raw fragment JSON")

    @property
    def fragment_id(self) -> str:
        """Fragment id (``"default"`` for the root fragment)."""
        return str(self.data.get("fragment_id", "default"))

    @property
    def version(self) -> int | None:
        """Catalog schema version."""
        v = self.data.get("version")
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
        return int(v) if v is not None else None

    @property
    def is_root(self) -> bool:
        """True for the root fragment (contains ``fragments``)."""
        return "fragments" in self.data

    @property
    def fragments(self) -> list[CatalogFragmentRef]:
        """Sub-fragment references (root fragment only)."""
        raw = self.data.get("fragments") or []
        return [CatalogFragmentRef.model_validate(ref) for ref in raw]

    @property
    def categories(self) -> list[CatalogCategory]:
        """Categories, normalized across the v23 and v30 schemas."""
        return _parse_categories(self.data.get("categories"))

    @property
    def types(self) -> list[CatalogTypeDef]:
        """Product types, normalized across the v23 and v30 schemas."""
        return _parse_types(self.data.get("types"))

    @property
    def products(self) -> list[CatalogProduct]:
        """Product entries (product fragments only)."""
        raw = self.data.get("products") or []
        return [CatalogProduct.model_validate(p) for p in raw]

    @property
    def program_configuration(self) -> dict[str, ProgramConfiguration]:
        """Entitlement rules per program (v30 product fragments only)."""
        raw = self.data.get("program_configuration")
        if not raw:
            return {}
        return {
            program: ProgramConfiguration.model_validate(cfg)
            for program, cfg in raw.items()
            if isinstance(cfg, dict)
        }

    @property
    def installs(self) -> dict[str, CatalogInstallConfig]:
        """Install configurations per product type."""
        raw = self.data.get("installs") or {}
        return {
            install_type: CatalogInstallConfig.model_validate(cfg)
            for install_type, cfg in raw.items()
            if isinstance(cfg, dict)
        }


def _parse_categories(raw: Any) -> list[CatalogCategory]:
    """Normalize categories from either schema.

    v23: ``{"in_development": {"name": "..."}}``
    v30: ``{"definitions": [{"id": "...", "name": "...", "rank": 0}]}``
    """
    if not isinstance(raw, dict):
        return []
    definitions = raw.get("definitions")
    if isinstance(definitions, list):
        return [
            CatalogCategory.model_validate(d)
            for d in definitions
            if isinstance(d, dict)
        ]
    # Legacy flat dict keyed by category id.
    result: list[CatalogCategory] = []
    for cat_id, value in raw.items():
        if not isinstance(value, dict):
            continue
        result.append(CatalogCategory.model_validate({**value, "id": cat_id}))
    return result


def _parse_types(raw: Any) -> list[CatalogTypeDef]:
    """Normalize product types from either schema.

    v23: ``{"beta": {"category_id": "in_development"}}``
    v30: ``{"definitions": [{"id": "wow_classic", "category": "..."}]}``
    """
    if not isinstance(raw, dict):
        return []
    definitions = raw.get("definitions")
    if isinstance(definitions, list):
        return [
            CatalogTypeDef.model_validate(d) for d in definitions if isinstance(d, dict)
        ]
    # Legacy flat dict keyed by type id.
    result: list[CatalogTypeDef] = []
    for type_id, value in raw.items():
        if not isinstance(value, dict):
            continue
        result.append(CatalogTypeDef.model_validate({**value, "id": type_id}))
    return result


def extract_license_ids(criteria: EntitlementMatchCriteria | None) -> list[int]:
    """Collect every ``license_id`` value from a criteria tree.

    Args:
        criteria: Criteria node (may be None).

    Returns:
        License IDs in traversal order (deduplication left to callers).
    """
    if criteria is None:
        return []
    ids: list[int] = []
    if criteria.license_id is not None:
        value = criteria.license_id
        ids.extend(value if isinstance(value, list) else [value])
    for combinator in (criteria.all_of, criteria.any_of, criteria.none_of):
        for child in combinator or []:
            ids.extend(extract_license_ids(child))
    ids.extend(extract_license_ids(criteria.not_))
    return ids


def rule_license_ids(rule: EntitlementRule) -> list[int]:
    """Collect license IDs referenced by a rule, including nested rules.

    Nested rules live inside ``run_first_rule``/``run_each_rule`` actions.

    Args:
        rule: Entitlement rule.

    Returns:
        License IDs referenced anywhere in the rule.
    """
    ids = extract_license_ids(rule.match)
    for action in rule.actions or []:
        for nested in (action.run_first_rule or []) + (action.run_each_rule or []):
            ids.extend(rule_license_ids(nested))
    return ids


class CatalogParser(FormatParser[CatalogFragment]):
    """Parse/build catalog JSON fragments."""

    def parse(self, data: bytes | BinaryIO) -> CatalogFragment:
        """Parse a catalog fragment from JSON bytes or a stream.

        Args:
            data: JSON bytes or a binary stream.

        Returns:
            Catalog fragment with raw data preserved.
        """
        if isinstance(data, (bytes, bytearray)):
            text = bytes(data).decode("utf-8")
        else:
            text = data.read().decode("utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid catalog JSON: {e}") from e
        return CatalogFragment(data=payload)

    def build(self, obj: CatalogFragment) -> bytes:
        """Re-serialize a fragment to compact UTF-8 JSON.

        Round-trips byte-exact for fragments fetched from the CDN.
        """
        return json.dumps(obj.data, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )


# Resolve forward references between the recursive rule models.
EntitlementAction.model_rebuild()
EntitlementRule.model_rebuild()
EntitlementMatchCriteria.model_rebuild()
