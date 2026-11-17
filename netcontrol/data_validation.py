"""Data validation rules: admin-defined checks on the values of inventory and
IPAM objects, enforced on the server.

A rule names an object type (``OBJECT_TYPES``), the field it checks (one of
``OBJECT_FIELDS`` or ``cf.<key>`` for a custom field of a host, group or
prefix), a rule type with its parameters, an error message and an enabled
flag:

=========  =========================  =========================================
Type       Parameters                 A value passes when
=========  =========================  =========================================
regex      ``pattern``                the pattern matches the whole value
length     ``min`` and/or ``max``     its length (characters) is in range
numeric    ``min`` and/or ``max``     it is a number in range
required   (none)                     it is not empty
=========  =========================  =========================================

An empty value passes every rule but ``required``, so a rule on an optional
field only constrains the values that are set. Regex patterns run on RE2
(``routes.user_regex``): linear time, case sensitive, and lookarounds and
backreferences are refused when the rule is saved.

``validate_object`` is the one entry point: the REST create and update
routes, custom field value saves and bulk import call it with the values
they are about to write (and on an update the stored values, ``existing``),
and get back the violations of every enabled rule. Enabled rules are cached
in memory; the admin API calls ``invalidate_rules_cache`` on every write and
the cache also expires after ``CACHE_TTL_SECONDS`` so other worker processes
pick up a change.

Discovery, collectors and external IPAM syncs do not call this module: an
automatic import has nobody to show an error to. ``find_violations`` lists
the stored objects that break enabled rules (the admin "Check existing
data" report).
"""

from __future__ import annotations

import logging
import math
import time
from functools import lru_cache
from typing import Any, NoReturn

import routes.database as db
from fastapi import HTTPException
from routes.user_regex import UserRegex, compile_whole_value_regex

from netcontrol.custom_fields import OBJECT_TYPES as CUSTOM_FIELD_OBJECT_TYPES
from netcontrol.object_scope import ObjectScope

LOGGER = logging.getLogger("plexus.data_validation")

OBJECT_TYPES: tuple[str, ...] = ("host", "group", "prefix", "ip_address", "vlan", "vrf")
# The fields a rule may check on each object type: the names the REST create
# and update bodies use, so a 422 names the form field.
OBJECT_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("hostname", "ip_address", "device_type", "vrf_name", "vlan_id", "aws_instance_id"),
    "group": ("name", "description"),
    "prefix": ("subnet", "vrf", "description", "notes"),
    "ip_address": ("address", "hostname", "description"),
    "vlan": ("vid", "name", "description"),
    "vrf": ("name", "rd", "description"),
}
RULE_TYPES: tuple[str, ...] = ("regex", "length", "numeric", "required")
CUSTOM_FIELD_PREFIX = "cf."

NAME_MAX = 100
MESSAGE_MAX = 300
DESCRIPTION_MAX = 1000
PATTERN_MAX = 500
LENGTH_LIMIT = 100_000
CACHE_TTL_SECONDS = 30.0
# The most objects one "Check existing data" report lists.
VIOLATIONS_LIMIT = 1000


class RuleError(ValueError):
    """An invalid rule definition. ``fields`` maps a rule property
    (``params.pattern``) to its message."""

    def __init__(self, message: str, fields: dict[str, str] | None = None):
        super().__init__(message)
        self.message = message
        self.fields = fields or {}


class ValidationFailed(Exception):
    """Values that break enabled rules. ``violations``: the list
    ``validate_object`` returned (``{"field", "rule", "message"}``)."""

    def __init__(self, violations: list[dict]):
        super().__init__("; ".join(v["message"] for v in violations) or "Validation failed")
        self.violations = violations


# ── Rule definitions ─────────────────────────────────────────────────────────


@lru_cache(maxsize=512)
def _matcher(pattern: str) -> UserRegex:
    return compile_whole_value_regex(pattern)


def custom_field_key(field: str) -> str | None:
    """The custom field key of a ``cf.<key>`` rule field, else ``None``."""
    return field[len(CUSTOM_FIELD_PREFIX) :] if field.startswith(CUSTOM_FIELD_PREFIX) else None


async def rule_fields(object_type: str) -> list[dict]:
    """The fields a rule on ``object_type`` may check: ``{"field", "label",
    "custom"}``, the object's own first, then its custom fields."""
    out = [{"field": f, "label": f.replace("_", " ").capitalize(), "custom": False} for f in OBJECT_FIELDS[object_type]]
    if object_type in CUSTOM_FIELD_OBJECT_TYPES:
        for cf in await db.list_custom_fields(object_type):
            out.append({"field": CUSTOM_FIELD_PREFIX + cf["key"], "label": cf["label"], "custom": True})
    return out


def _bound(raw: Any, name: str, *, integer: bool) -> float | int | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        raise RuleError(f"{name} must be a number.", {f"params.{name}": f"{name} must be a number."})
    try:
        value = float(raw)
    except TypeError, ValueError:
        raise RuleError(f"{name} must be a number.", {f"params.{name}": f"{name} must be a number."}) from None
    if not math.isfinite(value):
        raise RuleError(f"{name} must be a finite number.", {f"params.{name}": f"{name} must be a finite number."})
    if integer:
        if value != int(value) or not 0 <= value <= LENGTH_LIMIT:
            message = f"{name} must be a whole number from 0 to {LENGTH_LIMIT}."
            raise RuleError(message, {f"params.{name}": message})
        return int(value)
    return int(value) if value == int(value) else value


def clean_params(rule_type: str, params: dict[str, Any]) -> dict[str, Any]:
    """The stored parameters of a rule, or ``RuleError``. A regex pattern is
    compiled with RE2 here, so an unsupported one is refused on save."""
    if rule_type == "regex":
        pattern = params.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise RuleError("Enter a pattern.", {"params.pattern": "Enter a pattern."})
        if len(pattern) > PATTERN_MAX:
            message = f"The pattern must be at most {PATTERN_MAX} characters."
            raise RuleError(message, {"params.pattern": message})
        try:
            _matcher(pattern)
        except ValueError as exc:
            message = (
                f"The pattern is not valid: {exc}. Patterns run on RE2, which has no lookarounds or backreferences."
            )
            raise RuleError(message, {"params.pattern": message}) from None
        return {"pattern": pattern}
    if rule_type in ("length", "numeric"):
        integer = rule_type == "length"
        low = _bound(params.get("min"), "min", integer=integer)
        high = _bound(params.get("max"), "max", integer=integer)
        if low is None and high is None:
            raise RuleError("Set a minimum, a maximum or both.", {"params.min": "Set a minimum, a maximum or both."})
        if low is not None and high is not None and low > high:
            raise RuleError(
                "The minimum is above the maximum.", {"params.max": "The maximum must be at least the minimum."}
            )
        return {k: v for k, v in (("min", low), ("max", high)) if v is not None}
    if rule_type == "required":
        return {}
    raise RuleError(f"rule_type must be one of: {', '.join(RULE_TYPES)}.", {"rule_type": "Unknown rule type."})


async def clean_rule(values: dict[str, Any], *, current: dict | None = None) -> dict[str, Any]:
    """A rule's writable properties checked and trimmed (``name``,
    ``object_type``, ``field``, ``rule_type``, ``params``, ``error_message``,
    ``description``, ``enabled``), or ``RuleError`` naming every bad one.
    ``current``: the stored rule on an update; its object type and field
    stay accepted (a rule on a deleted custom field can still be changed or
    turned off)."""
    errors: dict[str, str] = {}
    name = str(values.get("name") or "").strip()
    if not name:
        errors["name"] = "Enter a name."
    elif len(name) > NAME_MAX:
        errors["name"] = f"The name must be at most {NAME_MAX} characters."
    object_type = str(values.get("object_type") or "")
    field = str(values.get("field") or "").strip()
    if object_type not in OBJECT_TYPES:
        errors["object_type"] = f"object_type must be one of: {', '.join(OBJECT_TYPES)}."
    elif not field:
        errors["field"] = "Choose a field."
    elif current and (current["object_type"], current["field"]) == (object_type, field):
        pass
    elif field not in {f["field"] for f in await rule_fields(object_type)}:
        cf = custom_field_key(field)
        errors["field"] = (
            f"No custom field '{cf}' applies to {object_type} objects."
            if cf is not None
            else f"{field} is not a field of {object_type} objects."
        )
    rule_type = str(values.get("rule_type") or "")
    params: dict[str, Any] = {}
    try:
        params = clean_params(rule_type, dict(values.get("params") or {}))
    except RuleError as exc:
        errors.update(exc.fields or {"params": exc.message})
    message = str(values.get("error_message") or "").strip()
    if len(message) > MESSAGE_MAX:
        errors["error_message"] = f"The error message must be at most {MESSAGE_MAX} characters."
    description = str(values.get("description") or "").strip()
    if len(description) > DESCRIPTION_MAX:
        errors["description"] = f"The description must be at most {DESCRIPTION_MAX} characters."
    if errors:
        raise RuleError("Check these fields: " + ", ".join(sorted(errors)) + ".", errors)
    return {
        "name": name,
        "object_type": object_type,
        "field": field,
        "rule_type": rule_type,
        "params": params,
        "error_message": message,
        "description": description,
        "enabled": bool(values.get("enabled", True)),
    }


# ── Checking a value ─────────────────────────────────────────────────────────


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and math.isfinite(value) and value == int(value):
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(v) for v in value)
    return str(value)


def _fmt(number: Any) -> str:
    return str(int(number)) if float(number) == int(number) else str(number)


def _default_message(rule: dict) -> str:
    field = rule["field"]
    params = rule.get("params") or {}
    low, high = params.get("min"), params.get("max")
    kind = rule["rule_type"]
    if kind == "required":
        return f"{field} is required."
    if kind == "regex":
        return f"{field} must match the pattern {params.get('pattern', '')}."
    if low is not None and high is not None:
        bounds = f"from {_fmt(low)} to {_fmt(high)}"
    elif low is not None:
        bounds = f"at least {_fmt(low)}"
    else:
        bounds = f"at most {_fmt(high)}"
    if kind == "length":
        return f"{field} must be {bounds} characters long."
    return f"{field} must be a number {bounds}."


def check_value(rule: dict, value: Any) -> str | None:
    """The message ``value`` gets from ``rule`` (its ``error_message`` or a
    generated one), or ``None`` when it passes. Pure: no database."""
    text = _text(value)
    kind = rule["rule_type"]
    params = rule.get("params") or {}
    message = rule.get("error_message") or _default_message(rule)
    if kind == "required":
        return message if not text.strip() else None
    if not text.strip():
        return None
    if kind == "regex":
        try:
            matcher = _matcher(str(params.get("pattern", "")))
        except ValueError:
            LOGGER.warning("data validation: rule %r has a pattern RE2 refuses; skipped", rule.get("name"))
            return None
        return None if matcher.search(text) else message
    low, high = params.get("min"), params.get("max")
    if kind == "length":
        size = len(text)
        return message if (low is not None and size < low) or (high is not None and size > high) else None
    if kind == "numeric":
        try:
            number = float(text.strip())
        except ValueError:
            return rule.get("error_message") or f"{rule['field']} must be a number."
        if not math.isfinite(number):
            return rule.get("error_message") or f"{rule['field']} must be a number."
        return message if (low is not None and number < low) or (high is not None and number > high) else None
    return None


# ── Cache ────────────────────────────────────────────────────────────────────

_cache: dict[str, list[dict]] | None = None
_cache_at = 0.0


def invalidate_rules_cache() -> None:
    """Drop the cached rules; the next check reads them again."""
    global _cache
    _cache = None


async def enabled_rules(object_type: str) -> list[dict]:
    """The enabled rules of ``object_type`` (cached)."""
    global _cache, _cache_at
    if _cache is None or time.monotonic() - _cache_at > CACHE_TTL_SECONDS:
        by_type: dict[str, list[dict]] = {t: [] for t in OBJECT_TYPES}
        for rule in await db.list_validation_rules(enabled_only=True):
            by_type.setdefault(rule["object_type"], []).append(rule)
        _cache, _cache_at = by_type, time.monotonic()
    return list(_cache.get(object_type, []))


# ── Validating an object ─────────────────────────────────────────────────────


def _merged(values: dict[str, Any], existing: dict | None) -> dict[str, Any]:
    if not existing:
        return dict(values)
    merged = dict(existing)
    for key, value in values.items():
        # On an update ``None`` means "not sent": the stored value stays.
        if value is not None or key not in merged:
            merged[key] = value
    return merged


def violations_of(rules: list[dict], values: dict[str, Any]) -> list[dict]:
    """The violations of ``values`` against ``rules``; a rule whose field is
    not in ``values`` is not checked. Pure: no database."""
    out: list[dict] = []
    for rule in rules:
        if rule["field"] not in values:
            continue
        message = check_value(rule, values[rule["field"]])
        if message is not None:
            out.append({"field": rule["field"], "rule": rule["name"], "message": message})
    return out


async def validate_object(object_type: str, values: dict[str, Any], *, existing: dict | None = None) -> list[dict]:
    """Check ``values`` of an ``object_type`` object against its enabled rules.

    ``values``: the fields being written, named as in ``OBJECT_FIELDS``, and
    custom field values as ``cf.<key>``. ``existing``: the stored values on
    an update; the merged result (``values`` over ``existing``, where a
    ``None`` in ``values`` keeps the stored value) is checked. A rule whose
    field is in neither is not checked, so a caller passes every field it
    writes (an empty string for one being cleared).

    Returns ``[{"field", "rule", "message"}]``, empty when valid.
    """
    if object_type not in OBJECT_TYPES:
        raise ValueError(f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    rules = await enabled_rules(object_type)
    if not rules:
        return []
    return violations_of(rules, _merged(values, existing))


async def require_valid(object_type: str, values: dict[str, Any], *, existing: dict | None = None) -> None:
    """``validate_object``, raising ``ValidationFailed`` on any violation."""
    violations = await validate_object(object_type, values, existing=existing)
    if violations:
        raise ValidationFailed(violations)


def validation_http_error(violations: list[dict], *, field_names: dict[str, str] | None = None) -> HTTPException:
    """The 422 for ``violations``, shaped like the app's other field errors
    (``custom_fields._invalid``): ``{"message", "fields": {field: message},
    "violations": [...]}``. ``field_names`` renames a rule field to the
    request's name for it (a custom field's bare key on a custom data save);
    the first message per field wins."""
    names = field_names or {}
    fields: dict[str, str] = {}
    for v in violations:
        fields.setdefault(names.get(v["field"], v["field"]), v["message"])
    message = " ".join(dict.fromkeys(v["message"] for v in violations)) or "Validation failed."
    return HTTPException(status_code=422, detail={"message": message, "fields": fields, "violations": violations})


def raise_validation_failed(exc: ValidationFailed, *, field_names: dict[str, str] | None = None) -> NoReturn:
    """Raise the HTTP 422 of a ``ValidationFailed``."""
    raise validation_http_error(exc.violations, field_names=field_names) from exc


async def enforce(
    object_type: str,
    values: dict[str, Any],
    *,
    existing: dict | None = None,
    field_names: dict[str, str] | None = None,
) -> None:
    """``validate_object`` for a REST route: HTTP 422 on any violation."""
    violations = await validate_object(object_type, values, existing=existing)
    if violations:
        raise validation_http_error(violations, field_names=field_names)


# ── Stored objects ───────────────────────────────────────────────────────────


def pick(row: dict, object_type: str) -> dict[str, Any]:
    """The rule fields of a stored row of ``object_type`` (``""`` for NULL)."""
    return {f: ("" if row.get(f) is None else row.get(f)) for f in OBJECT_FIELDS[object_type] if f in row}


async def custom_values(object_type: str, keys: list[str]) -> dict[str, dict[str, str]]:
    """``{object_key: {"cf.<key>": text}}`` with every custom field of the
    type (``""`` when unset), for objects whose type has custom fields."""
    if object_type not in CUSTOM_FIELD_OBJECT_TYPES or not keys:
        return {}
    fields = [f["key"] for f in await db.list_custom_fields(object_type)]
    if not fields:
        return {}
    data = await db.get_object_data_bulk(object_type, keys)
    out: dict[str, dict[str, str]] = {}
    for key in keys:
        stored = (data.get(key) or {}).get("fields") or {}
        out[key] = {CUSTOM_FIELD_PREFIX + f: stored.get(f, "") for f in fields}
    return out


def _prefix_key(row: dict) -> str:
    try:
        return db.prefix_key(str(row.get("subnet") or ""), row.get("vrf") or "")
    except ValueError:
        return ""


async def _objects(object_type: str, scope: ObjectScope) -> list[tuple[dict, str, str, dict[str, Any]]]:
    """``(row, key, label, values)`` of every stored ``object_type`` object
    the caller may read."""
    rows: list[dict]
    if object_type == "host":
        rows = scope.filter_hosts(await db.get_all_hosts())
        items = [(r, str(r["id"]), f"{r.get('hostname') or ''} ({r.get('ip_address') or ''})") for r in rows]
    elif object_type == "group":
        rows = scope.filter_groups(await db.get_all_groups())
        items = [(r, str(r["id"]), str(r.get("path") or r.get("name") or "")) for r in rows]
    elif object_type == "prefix":
        rows = [r for r in await db.list_ipam_prefix_records() if r.get("provider") == "plexus"]
        items = [(r, _prefix_key(r), f"{r.get('subnet')}" + (f" ({r['vrf']})" if r.get("vrf") else "")) for r in rows]
    elif object_type == "ip_address":
        rows = [
            {**r, "hostname": r.get("dns_name") or ""}
            for r in await db.list_ipam_allocation_records()
            if r.get("provider") == "plexus"
        ]
        items = [(r, str(r["id"]), str(r.get("address") or "")) for r in rows]
    elif object_type == "vlan":
        rows = await db.list_vlans()
        items = [(r, str(r["id"]), f"VLAN {r.get('vid')}" + (f" {r['name']}" if r.get("name") else "")) for r in rows]
    else:
        rows = await db.list_vrfs()
        items = [(r, str(r["id"]), str(r.get("name") or "")) for r in rows]
    extra = await custom_values(object_type, [k for _, k, _ in items if k])
    return [(r, k, label, {**pick(r, object_type), **extra.get(k, {})}) for r, k, label in items]


async def find_violations(scope: ObjectScope, object_type: str | None = None) -> dict:
    """The stored objects that break enabled rules: ``{"objects": [{
    "object_type", "object_id", "label", "violations"}], "checked",
    "truncated"}``. Hosts and groups are those ``scope`` may read. Only
    Plexus-defined prefixes and addresses are checked, not synced ones."""
    types = [object_type] if object_type else list(OBJECT_TYPES)
    found: list[dict] = []
    checked = 0
    truncated = False
    for kind in types:
        rules = await enabled_rules(kind)
        if not rules:
            continue
        for row, key, label, values in await _objects(kind, scope):
            checked += 1
            violations = violations_of(rules, values)
            if not violations:
                continue
            if len(found) >= VIOLATIONS_LIMIT:
                truncated = True
                break
            found.append(
                {
                    "object_type": kind,
                    "object_id": row.get("id"),
                    "object_key": key,
                    "label": label,
                    "violations": violations,
                }
            )
    return {"objects": found, "checked": checked, "truncated": truncated}
