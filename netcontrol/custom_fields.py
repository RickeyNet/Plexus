"""Custom fields and tags: the constants and value rules, with no I/O.

Values are stored as canonical text (``custom_field_values.value``) so that
equality filters compare like with like whatever the field type:

=========  ==================================  ==============================
Type       Stored form                         Accepted input
=========  ==================================  ==============================
text       as entered, trimmed                 at most ``TEXT_MAX`` characters
number     decimal string, no trailing zeros   any finite number
boolean    ``true`` or ``false``               bool, true/false, yes/no, 1/0
date       ``YYYY-MM-DD``                      a real calendar date
url        as entered, trimmed                 ``http``/``https`` with a host
select     one of the field's choices          a string in ``choices``
=========  ==================================  ==============================

An empty value (``None`` or blank text) canonicalises to ``""``, which the
storage layer treats as "no value" and never stores.

Object types
------------

Every object type that carries custom fields, tags, computed fields and
relationships has one ``ObjectTypeSpec`` in ``_SPECS``: its key, table, id
column and the features that read and change it. Adding a type is one line
in ``_SPECS`` plus the ``purge_trigger_sql`` statements in a migration (so
deleting a row removes its data); the generic API
(``/api/objects/{type}/{id}/...``), the list helpers and the Settings UI pick
it up from here.

Used by the API (``netcontrol.routes.custom_fields``) and by tests directly.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Literal, get_args
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ObjectTypeSpec:
    """One object type that carries custom data.

    ``read_feature``: the feature its REST routes are read with (``None``:
    any signed-in user). ``write_feature``: the feature that changes it
    (``None``: admins only, like IPAM, organization and device model
    writes). ``scope_model``: the ``netcontrol.object_scope.MODELS`` key
    whose rules decide which objects a caller limited to selected inventory
    groups, tenants or sites reads and changes (hosts and groups are checked
    with ``require_host`` / ``require_group``). ``generic``: served by
    ``/api/objects/{type}/{id}/...`` and able to take part in relationships
    (a prefix is keyed by ``subnet|vrf`` and keeps its own endpoints)."""

    key: str
    label: str
    table: str
    read_feature: str | None
    write_feature: str | None
    scope_model: str
    id_column: str = "id"
    generic: bool = True


# The table and column names are fixed here; never user input.
_SPECS: tuple[ObjectTypeSpec, ...] = (
    ObjectTypeSpec("host", "Host", "hosts", "inventory", "inventory", "host"),
    ObjectTypeSpec("group", "Inventory group", "inventory_groups", "inventory", "inventory", "inventory_group"),
    ObjectTypeSpec("prefix", "Prefix", "ipam_prefixes", "ipam", None, "ipam_prefix", generic=False),
    ObjectTypeSpec("vrf", "VRF", "vrfs", "ipam", None, "vrf"),
    ObjectTypeSpec("vlan", "VLAN", "vlans", "ipam", None, "vlan"),
    ObjectTypeSpec("region", "Region", "regions", "organization", None, "region"),
    ObjectTypeSpec("site", "Site", "geo_sites", "organization", None, "site"),
    ObjectTypeSpec("tenant", "Tenant", "tenants", "organization", None, "tenant"),
    ObjectTypeSpec("manufacturer", "Manufacturer", "manufacturers", None, None, "catalog"),
    ObjectTypeSpec("device_type", "Device type", "device_types", None, None, "catalog"),
    ObjectTypeSpec("device_role", "Device role", "device_roles", None, None, "catalog"),
    ObjectTypeSpec(
        "circuit_provider", "Circuit provider", "circuit_providers", "circuits", "circuits.write", "circuit_provider"
    ),
    ObjectTypeSpec("circuit", "Circuit", "circuits", "circuits", "circuits.write", "circuit"),
    ObjectTypeSpec("cluster", "Cluster", "clusters", "virtualization", "virtualization.write", "cluster"),
    ObjectTypeSpec(
        "virtual_machine",
        "Virtual machine",
        "virtual_machines",
        "virtualization",
        "virtualization.write",
        "virtual_machine",
    ),
    ObjectTypeSpec(
        "autonomous_system",
        "Autonomous system",
        "autonomous_systems",
        "routing",
        "routing.write",
        "autonomous_system",
    ),
    # A peering is scoped by its routing instance's host (``host_id`` on the
    # rows ``get_bgp_peering`` / ``list_bgp_peerings`` return).
    ObjectTypeSpec("bgp_peering", "BGP peering", "bgp_peerings", "routing", "routing.write", "routing_instance"),
    ObjectTypeSpec("rack", "Rack", "racks", "dcim", "dcim.write", "rack"),
    ObjectTypeSpec("cable", "Cable", "cables", "dcim", "dcim.write", "cable"),
)
OBJECT_TYPE_SPECS: dict[str, ObjectTypeSpec] = {spec.key: spec for spec in _SPECS}
OBJECT_TYPES: tuple[str, ...] = tuple(OBJECT_TYPE_SPECS)
# The types served by the generic object API; the only ones relationships link.
GENERIC_TYPES: tuple[str, ...] = tuple(s.key for s in _SPECS if s.generic)

# The Literal types are what request bodies validate against; the tuples are
# derived from them so each set is written once. Object types come from the
# registry above and are checked with ``unknown_object_types``.
FieldType = Literal["text", "number", "boolean", "date", "url", "select"]
TagColor = Literal["gray", "red", "orange", "yellow", "green", "teal", "blue", "purple"]
Cardinality = Literal["one-to-one", "one-to-many", "many-to-many"]
FIELD_TYPES: tuple[str, ...] = get_args(FieldType)
TAG_COLORS: tuple[str, ...] = get_args(TagColor)
CARDINALITIES: tuple[str, ...] = get_args(Cardinality)
FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,49}$")
TEXT_MAX = 1000
TAG_NAME_MAX = 50
# Computed fields: the template text and the rendered value are bounded.
COMPUTED_TEMPLATE_MAX = 4000
COMPUTED_OUTPUT_MAX = 1000

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRUE = {"true", "yes", "1"}
_FALSE = {"false", "no", "0"}


class CustomFieldError(ValueError):
    """A value a field does not accept. The message names the field."""


def _label(field: dict) -> str:
    return str(field.get("label") or field.get("key") or "Field")


def _number(raw: object) -> str | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        return None
    try:
        value = Decimal(str(raw).strip())
    except InvalidOperation:
        return None
    if not value.is_finite():
        return None
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def _boolean(raw: object) -> str | None:
    if isinstance(raw, bool):
        return "true" if raw else "false"
    text = str(raw).strip().lower() if isinstance(raw, (int, str)) else ""
    if text in _TRUE:
        return "true"
    if text in _FALSE:
        return "false"
    return None


def _date(text: str) -> bool:
    if not _DATE_RE.fullmatch(text):
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _url(text: str) -> bool:
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme.lower() in ("http", "https") and bool(host)


def canonical_value(field: dict, raw: object) -> str:
    """The stored text for ``raw`` in ``field``; ``""`` for no value.

    ``field`` needs ``field_type`` and, for ``select``, ``choices``; its
    ``label`` (or ``key``) starts every error message.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return ""
    label = _label(field)
    field_type = field.get("field_type")

    if field_type == "number":
        number = _number(raw)
        if number is None:
            raise CustomFieldError(f"{label} must be a number.")
        return number
    if field_type == "boolean":
        flag = _boolean(raw)
        if flag is None:
            raise CustomFieldError(f"{label} must be true or false.")
        return flag

    if not isinstance(raw, str):
        raise CustomFieldError(f"{label} must be text.")
    text = raw.strip()
    if field_type in ("text", "url") and len(text) > TEXT_MAX:
        raise CustomFieldError(f"{label} must be at most {TEXT_MAX} characters.")
    if field_type == "text":
        return text
    if field_type == "date":
        if not _date(text):
            raise CustomFieldError(f"{label} must be a date in the form YYYY-MM-DD.")
        return text
    if field_type == "url":
        if not _url(text):
            raise CustomFieldError(f"{label} must be an http or https URL with a host.")
        return text
    if field_type == "select":
        choices = [str(c) for c in field.get("choices") or []]
        if text not in choices:
            raise CustomFieldError(f"{label} must be one of: {', '.join(choices)}.")
        return text
    raise CustomFieldError(f"{label} has an unknown type '{field_type}'.")


def check_object_values(
    all_fields: list[dict], object_type: str, raw_fields: Mapping[str, object]
) -> tuple[dict[int, str], dict[str, str]]:
    """Check an object's custom field values against the definitions.

    ``all_fields`` is every field definition (``list_custom_fields()``),
    ``raw_fields`` the values by field key. Returns ``(values, errors)``:
    the canonical text by field id of each field that applies to
    ``object_type``, and a message by field key for a key that names no
    field or one that does not apply, a value the field rejects, or a
    required field (with no default) left empty. Shared by the custom data
    API and bulk import.
    """
    applicable = {f["key"]: f for f in all_fields if object_type in f["object_types"]}
    known = {f["key"] for f in all_fields}
    errors: dict[str, str] = {}
    values: dict[int, str] = {}
    for field_key, raw in raw_fields.items():
        field = applicable.get(field_key)
        if field is None:
            errors[field_key] = (
                f"{field_key} does not apply to {object_type}s."
                if field_key in known
                else f"{field_key} is not a custom field (it may have been deleted)."
            )
            continue
        try:
            values[int(field["id"])] = canonical_value(field, raw)
        except CustomFieldError as exc:
            errors[field_key] = str(exc)
    for field in applicable.values():
        if field["required"] and not field["default_value"] and field["key"] not in errors:
            if not values.get(int(field["id"])):
                errors[field["key"]] = f"{field['label']} is required."
    return values, errors


def typed_value(field_type: str, stored: str) -> str | int | float | bool:
    """A stored value as JSON wants it: numbers and booleans typed, the rest
    text. A stored value that no longer parses comes back as text."""
    if field_type == "boolean":
        return stored == "true"
    if field_type == "number":
        try:
            return int(stored) if re.fullmatch(r"-?\d+", stored) else float(stored)
        except ValueError:
            return stored
    return stored


def clean_name(raw: object, label: str, limit: int) -> str:
    """A name trimmed; 1 to ``limit`` characters. ``label`` starts the error
    message (``"Tag name"``)."""
    name = raw.strip() if isinstance(raw, str) else ""
    if not name:
        raise CustomFieldError(f"{label} must not be empty.")
    if len(name) > limit:
        raise CustomFieldError(f"{label} must be at most {limit} characters.")
    return name


def clean_text(raw: object, label: str, limit: int) -> str:
    """Optional text trimmed; at most ``limit`` characters, may be empty (a
    value that is not text counts as empty). ``label`` starts the error
    message (``"Description"``)."""
    text = raw.strip() if isinstance(raw, str) else ""
    if len(text) > limit:
        raise CustomFieldError(f"{label} must be at most {limit} characters.")
    return text


def clean_tag_name(raw: object) -> str:
    """A tag name trimmed; 1 to ``TAG_NAME_MAX`` characters."""
    return clean_name(raw, "Tag name", TAG_NAME_MAX)


def object_type_spec(object_type: str) -> ObjectTypeSpec | None:
    """The registry entry of ``object_type``; ``None`` for an unknown type."""
    return OBJECT_TYPE_SPECS.get(object_type)


def unknown_object_types(object_types: list[str], allowed: tuple[str, ...] = OBJECT_TYPES) -> list[str]:
    """The entries of ``object_types`` that are not in ``allowed``."""
    return [t for t in object_types if t not in allowed]


def purge_trigger_sql(spec: ObjectTypeSpec) -> tuple[str, str]:
    """The statements (drop, then create) that make deleting a row of
    ``spec.table`` remove its tags, custom field values and relationship
    links, through the ``plexus_purge_object_data`` trigger function of
    migration 0109. A migration that registers a new type runs both."""
    name = f"trg_{spec.table}_purge_object_data"
    return (
        f"DROP TRIGGER IF EXISTS {name} ON {spec.table}",
        f"CREATE TRIGGER {name} AFTER DELETE ON {spec.table} FOR EACH ROW "
        f"EXECUTE FUNCTION plexus_purge_object_data('{spec.key}', '{spec.id_column}')",
    )
