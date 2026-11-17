"""Dynamic groups: named, saved host filters resolved when they are used.

A filter definition is a dict of criteria. Criteria are AND-combined; the
values of one criterion are alternatives (OR):

* ``groups``: inventory group ids; with ``include_subgroups`` (default
  true) a host in any sub-group matches too.
* ``site_id``, ``role_id``, ``lifecycle_status_id``, ``manufacturer_id``,
  ``device_type_id``, ``tenant_id``, ``region_id`` (a region matches the
  hosts of its sites and of every region under it): ids, ``None`` for "no
  value". The same
  filters as the inventory list (``matching_host_ids`` /
  ``routes.db.find_host_ids_by_device_filters``).
* ``platforms``: the host's driver (``device_type`` column), ignoring case.
* ``statuses``: the host's reachability status (``up``, ``down`` ...).
* ``tag_ids``: tags the host carries: any of them, or all of them with
  ``tag_match: "all"`` (the inventory filter menu's rule).
* ``custom_fields``: field key to accepted values; ``"*"`` accepts any
  value. Values are validated and canonicalised by the field, as in the
  inventory ``cf.<key>=`` filters (``canonical_filter_values``).
* ``search``: ``{"mode": "contains" | "regex", "value": ...}`` matched
  against the hostname or the IP address, ignoring case. Regular
  expressions run on RE2 (``routes.user_regex``), so lookarounds and
  backreferences are refused.
* ``prefixes``: networks (CIDR) that contain the host's IP address.

An empty filter is refused: a dynamic group must narrow something, so a job
never targets every host by accident.

Resolution always starts from the hosts the caller's object scope can read
(``ObjectScope.filter_hosts``): a scoped user never reaches a host outside
their scope through a dynamic group, whoever defined it.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import routes.database as db
from routes.user_regex import compile_user_regex

from netcontrol.device_model import DEVICE_FILTER_KEYS, NONE_FILTER, parse_device_filters
from netcontrol.object_scope import NO_ACCESS, UNRESTRICTED, ObjectScope, scope_for_user
from netcontrol.routes.custom_fields import canonical_filter_values

OBJECT_TYPES: tuple[str, ...] = ("host",)
SEARCH_MODES: tuple[str, ...] = ("contains", "regex")
HAS_VALUE = "*"
LIST_MAX = 200
TEXT_MAX = 100
PATTERN_MAX = 500
NAME_MAX = 100
DESCRIPTION_MAX = 1000

# The criteria keys, in the order the normalised definition lists them.
CRITERIA: tuple[str, ...] = (
    "groups",
    *DEVICE_FILTER_KEYS,
    "platforms",
    "statuses",
    "tag_ids",
    "custom_fields",
    "search",
    "prefixes",
)
TAG_MATCHES: tuple[str, ...] = ("any", "all")
_KNOWN_KEYS = frozenset({*CRITERIA, "include_subgroups", "tag_match"})

# Host columns a member listing returns: no credentials, SNMP or cloud ids.
MEMBER_COLUMNS: tuple[str, ...] = (
    "id",
    "hostname",
    "ip_address",
    "device_type",
    "status",
    "group_id",
    "model",
    "software_version",
)

# Username the server API token acts as (``require_auth``).
API_TOKEN_USER = "api-token"


class DynamicGroupFilterError(ValueError):
    """A filter definition that is not valid: a message and one message per
    criterion key."""

    def __init__(self, message: str, fields: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.fields = fields or {}


# ── Validation ───────────────────────────────────────────────────────────────


def _id_list(raw: object, key: str, errors: dict[str, str]) -> list[int]:
    if not isinstance(raw, list):
        errors[key] = "Must be a list of ids."
        return []
    if len(raw) > LIST_MAX:
        errors[key] = f"At most {LIST_MAX} values."
        return []
    out: list[int] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            errors[key] = "Must be a list of ids."
            return []
        if item not in out:
            out.append(item)
    return out


def _text_list(raw: object, key: str, errors: dict[str, str]) -> list[str]:
    if not isinstance(raw, list):
        errors[key] = "Must be a list of text values."
        return []
    if len(raw) > LIST_MAX:
        errors[key] = f"At most {LIST_MAX} values."
        return []
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item.strip()) > TEXT_MAX:
            errors[key] = f"Each value must be text of 1 to {TEXT_MAX} characters."
            return []
        text = item.strip().lower()
        if text not in out:
            out.append(text)
    return out


def _device_values(raw: object, key: str, errors: dict[str, str]) -> list[int | None]:
    """Device model ids (``None`` or ``"none"`` for no value), checked by the
    inventory list's own parser."""
    if not isinstance(raw, list):
        errors[key] = f"Must be a list of ids or '{NONE_FILTER}'."
        return []
    if len(raw) > LIST_MAX:
        errors[key] = f"At most {LIST_MAX} values."
        return []
    items = [(key, NONE_FILTER if v is None else str(v)) for v in raw if not isinstance(v, bool)]
    if len(items) != len(raw):
        errors[key] = f"{key} must be an id or '{NONE_FILTER}'."
        return []
    parsed, problems = parse_device_filters(items)
    if problems:
        errors.update(problems)
        return []
    return parsed.get(key, [])


def _clean_search(raw: object, errors: dict[str, str]) -> dict | None:
    if not isinstance(raw, dict):
        errors["search"] = "Must be an object with a mode and a value."
        return None
    mode = raw.get("mode", "contains")
    value = raw.get("value")
    if mode not in SEARCH_MODES:
        errors["search"] = "Mode must be 'contains' or 'regex'."
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if len(value) > PATTERN_MAX:
        errors["search"] = f"At most {PATTERN_MAX} characters."
        return None
    if mode == "regex":
        try:
            compile_user_regex(value)
        except ValueError as exc:
            errors["search"] = f"Not a supported regular expression: {exc}"
            return None
    return {"mode": mode, "value": value}


def _clean_prefixes(raw: object, errors: dict[str, str]) -> list[str]:
    if not isinstance(raw, list):
        errors["prefixes"] = "Must be a list of networks."
        return []
    if len(raw) > LIST_MAX:
        errors["prefixes"] = f"At most {LIST_MAX} values."
        return []
    out: list[str] = []
    for item in raw:
        try:
            network = str(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            errors["prefixes"] = f"'{item}' is not a network such as 192.0.2.0/24."
            return []
        if network not in out:
            out.append(network)
    return out


async def _clean_custom_fields(raw: object, errors: dict[str, str]) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        errors["custom_fields"] = "Must map a field key to a list of values."
        return {}
    if len(raw) > LIST_MAX:
        errors["custom_fields"] = f"At most {LIST_MAX} fields."
        return {}
    wanted: list[tuple[str, object]] = []
    out: dict[str, list[str]] = {}
    for key, values in raw.items():
        items = values if isinstance(values, list) else [values]
        if not items or len(items) > LIST_MAX:
            errors[f"custom_fields.{key}"] = f"Give 1 to {LIST_MAX} values."
            continue
        out[str(key)] = []
        for value in items:
            if value == HAS_VALUE:
                out[str(key)].append(HAS_VALUE)
            else:
                wanted.append((str(key), value))
    if out:
        # "Has a value" needs only the field to exist; other values are
        # checked and canonicalised by the field.
        canonical, problems = await canonical_filter_values("host", wanted)
        known = {f["key"] for f in await db.list_custom_fields("host")}
        for key in out:
            if key not in known:
                problems.setdefault(key, f"No custom field '{key}' applies to hosts.")
        for key, message in problems.items():
            errors[f"custom_fields.{key}"] = message
        for field, value in canonical:
            values = out[field["key"]]
            if value not in values:
                values.append(value)
    return {k: v for k, v in out.items() if v and f"custom_fields.{k}" not in errors}


async def validate_filter(raw: object, scope: ObjectScope = UNRESTRICTED) -> dict[str, Any]:
    """The normalised filter definition of ``raw``. Raises
    ``DynamicGroupFilterError`` naming every bad criterion. Inventory groups
    outside ``scope`` count as unknown."""
    if not isinstance(raw, dict):
        raise DynamicGroupFilterError("The filter must be an object of criteria.")
    errors: dict[str, str] = {}
    for key in raw:
        if key not in _KNOWN_KEYS:
            errors[str(key)] = "Unknown criterion."
    out: dict[str, Any] = {}

    groups = _id_list(raw.get("groups", []), "groups", errors)
    if groups:
        existing = {int(g["id"]) for g in await db.get_all_groups() if scope.can_read_group(g["id"])}
        missing = [g for g in groups if g not in existing]
        if missing:
            errors["groups"] = "Unknown inventory group: " + ", ".join(str(m) for m in missing)
        out["groups"] = groups
    include = raw.get("include_subgroups", True)
    if not isinstance(include, bool):
        errors["include_subgroups"] = "Must be true or false."
    out["include_subgroups"] = bool(include)

    for key in DEVICE_FILTER_KEYS:
        if key in raw:
            values = _device_values(raw[key], key, errors)
            if values:
                out[key] = values

    for key in ("platforms", "statuses"):
        if key in raw:
            texts = _text_list(raw[key], key, errors)
            if texts:
                out[key] = texts

    if "tag_ids" in raw:
        tag_ids = _id_list(raw["tag_ids"], "tag_ids", errors)
        if tag_ids:
            known_tags = {int(t["id"]) for t in await db.list_tags()}
            missing = [t for t in tag_ids if t not in known_tags]
            if missing:
                errors["tag_ids"] = "Unknown tag: " + ", ".join(str(m) for m in missing)
            out["tag_ids"] = tag_ids
            tag_match = raw.get("tag_match", "any")
            if tag_match not in TAG_MATCHES:
                errors["tag_match"] = "Must be 'any' or 'all'."
            out["tag_match"] = tag_match

    if "custom_fields" in raw:
        fields = await _clean_custom_fields(raw["custom_fields"], errors)
        if fields:
            out["custom_fields"] = fields

    if raw.get("search") not in (None, ""):
        search = _clean_search(raw["search"], errors)
        if search:
            out["search"] = search

    if "prefixes" in raw:
        prefixes = _clean_prefixes(raw["prefixes"], errors)
        if prefixes:
            out["prefixes"] = prefixes

    if errors:
        raise DynamicGroupFilterError("Filter not valid: " + ", ".join(sorted(errors)), errors)
    if not any(key in out for key in CRITERIA):
        raise DynamicGroupFilterError(
            "Add at least one criterion: a dynamic group with no criteria would match every host.",
            {"filter": "Add at least one criterion."},
        )
    return out


# ── Resolution ───────────────────────────────────────────────────────────────


async def _tagged_keys(tag_ids: list[int], match_all: bool) -> set[str]:
    """Host keys carrying any (or, with ``match_all``, every) tag of
    ``tag_ids``; a deleted tag is carried by nobody."""
    names = {int(t["id"]): t["name"] for t in await db.list_tags()}
    wanted = [names.get(int(t)) for t in tag_ids]
    if match_all:
        if None in wanted:
            return set()
        return await db.find_object_keys("host", [n for n in wanted if n is not None], {})
    keys: set[str] = set()
    for name in wanted:
        if name is not None:
            keys |= await db.find_object_keys("host", [name], {})
    return keys


async def _custom_field_keys(wanted: dict[str, list[str]]) -> set[str] | None:
    """Host keys holding one of the accepted values of every field; a field
    deleted since the filter was saved matches nothing."""
    result: set[str] | None = None
    fields = {f["key"]: f for f in await db.list_custom_fields("host")}
    for key, values in wanted.items():
        field = fields.get(key)
        keys: set[str] = set()
        if field is not None:
            for value in values:
                if value == HAS_VALUE:
                    keys |= await db.find_object_keys_with_field("host", int(field["id"]))
                else:
                    keys |= await db.find_object_keys("host", [], {int(field["id"]): value})
        result = keys if result is None else result & keys
        if not result:
            return set()
    return result


def _search_matcher(search: dict):
    value = str(search.get("value") or "")
    if search.get("mode") == "regex":
        pattern = compile_user_regex(value)
        return lambda text: pattern.search(text) is not None
    needle = value.lower()
    return lambda text: needle in text.lower()


def _in_prefixes(ip_text: object, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        address = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return False
    return any(address.version == n.version and address in n for n in networks)


async def resolve_hosts(filter_def: dict[str, Any], scope: ObjectScope) -> list[dict]:
    """The host rows the (validated) ``filter_def`` matches now, among the
    hosts ``scope`` may read, ordered by hostname and IP. A definition with
    no criteria matches nothing."""
    if not any(key in filter_def for key in CRITERIA):
        return []
    hosts = scope.filter_hosts(await db.get_all_hosts())

    groups = filter_def.get("groups") or []
    if groups and hosts:
        wanted = (
            await db.get_group_subtree_ids(groups)
            if filter_def.get("include_subgroups", True)
            else {int(g) for g in groups}
        )
        hosts = [h for h in hosts if h.get("group_id") is not None and int(h["group_id"]) in wanted]

    device = {k: list(filter_def[k]) for k in DEVICE_FILTER_KEYS if filter_def.get(k)}
    if device and hosts:
        matched = await db.find_host_ids_by_device_filters(device)
        hosts = [h for h in hosts if int(h["id"]) in matched]

    platforms = {str(p).lower() for p in filter_def.get("platforms") or []}
    if platforms:
        hosts = [h for h in hosts if str(h.get("device_type") or "").lower() in platforms]

    statuses = {str(s).lower() for s in filter_def.get("statuses") or []}
    if statuses:
        hosts = [h for h in hosts if str(h.get("status") or "").lower() in statuses]

    if filter_def.get("tag_ids") and hosts:
        keys = await _tagged_keys(list(filter_def["tag_ids"]), filter_def.get("tag_match") == "all")
        hosts = [h for h in hosts if str(h["id"]) in keys]

    if filter_def.get("custom_fields") and hosts:
        field_keys = await _custom_field_keys(dict(filter_def["custom_fields"]))
        hosts = [h for h in hosts if field_keys is not None and str(h["id"]) in field_keys]

    if filter_def.get("search"):
        try:
            matches = _search_matcher(filter_def["search"])
        except ValueError:
            return []
        hosts = [h for h in hosts if matches(str(h.get("hostname") or "")) or matches(str(h.get("ip_address") or ""))]

    if filter_def.get("prefixes"):
        networks = [ipaddress.ip_network(p, strict=False) for p in filter_def["prefixes"]]
        hosts = [h for h in hosts if _in_prefixes(h.get("ip_address"), networks)]

    return sorted(hosts, key=lambda h: (str(h.get("hostname") or "").lower(), str(h.get("ip_address") or "")))


async def resolve_group(group_id: int, scope: ObjectScope) -> list[dict] | None:
    """The hosts dynamic group ``group_id`` matches now within ``scope``;
    ``None`` when the group does not exist."""
    group = await db.get_dynamic_group(int(group_id))
    if group is None:
        return None
    return await resolve_hosts(group["filter"], scope)


async def scope_for_launcher(username: str | None) -> ObjectScope:
    """The object scope of the user a queued job was launched by, for
    resolving a dynamic group when the job starts. The server API token is
    unrestricted; an unknown user sees nothing (fail closed)."""
    if username:
        user = await db.get_user_by_username(username)
        if user:
            return await scope_for_user(user)
        if username == API_TOKEN_USER:
            return UNRESTRICTED
    return NO_ACCESS


async def member_rows(hosts: list[dict]) -> list[dict]:
    """``hosts`` reduced to ``MEMBER_COLUMNS`` plus ``group_name``."""
    names = {int(g["id"]): g["name"] for g in await db.get_all_groups()} if hosts else {}
    rows = []
    for host in hosts:
        row = {c: host.get(c) for c in MEMBER_COLUMNS}
        gid = host.get("group_id")
        row["group_name"] = names.get(int(gid)) if gid is not None else None
        rows.append(row)
    return rows
