"""Typed job input forms and per-job permissions: the rules, with no HTTP.

A playbook declares the inputs its run dialog asks for as a list of fields.
The schema is stored on the playbook (``playbooks.input_schema``) or, for a
Python playbook, declared in code as ``parameters_schema`` on the class; a
stored schema wins over the code one.

==============  ===================================  =========================
Type            Value passed to the run              Accepted input
==============  ===================================  =========================
string          text, trimmed                        at most ``STRING_MAX``
text            multi-line text                      at most ``TEXT_MAX``
integer         ``int``                              a whole number
boolean         ``bool``                             bool, true/false, yes/no
choice          one of ``choices``                   a string in ``choices``
multichoice     list of ``choices``                  a list (or CSV) of them
list            list of strings                      a list or CSV text
ip              IP address text                      IPv4 or IPv6 address
cidr            prefix text                          ``address/length``
host            ``{id, hostname, ip_address, ...}``  an inventory host id
group           ``{id, name}``                       an inventory group id
secret          the decrypted value (run time only)  a secret variable name
==============  ===================================  =========================

``min``/``max`` bound an integer's value, a string's or text's length, and a
multichoice's or list's item count. ``regex`` (string and text) must match
the whole value. The legacy code types ``int``, ``bool`` and ``str`` are
read as ``integer``, ``boolean`` and ``string``.

A secret field stores ``{{secret.NAME}}`` on the job record; the value is
resolved only when the job runs and is scrubbed from the job log, so the
plaintext never reaches the database. A secret reference typed into any
other field is refused.

Permissions (``playbooks.permissions``) name the user roles and access group
ids allowed to ``run`` the job and to ``commit`` (run it live). An empty
rule means "no restriction"; an empty commit rule falls back to the run
rule. Admins and server API token callers are always allowed.

Used by ``netcontrol.routes.playbooks`` and ``netcontrol.routes.jobs``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal, get_args

from routes.secret_resolver import has_secret_references, normalize_secret_name

from netcontrol.custom_fields import CustomFieldError, canonical_value
from netcontrol.routes.host_identity import host_ip_problem

FieldType = Literal[
    "string",
    "text",
    "integer",
    "boolean",
    "choice",
    "multichoice",
    "list",
    "ip",
    "cidr",
    "host",
    "group",
    "secret",
]
FIELD_TYPES: tuple[str, ...] = get_args(FieldType)
TYPE_ALIASES = {"int": "integer", "bool": "boolean", "str": "string"}
ROLES: tuple[str, ...] = ("admin", "user")
ACTIONS: tuple[str, ...] = ("run", "commit")

FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
# The name part of secret_resolver's ``{{secret.NAME}}`` pattern.
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
MAX_FIELDS = 50
STRING_MAX = 1000
TEXT_MAX = 20000
LABEL_MAX = 100
HELP_MAX = 500
REGEX_MAX = 200
CHOICES_MAX = 100
CHOICE_MAX = 200

_BOUNDED = ("integer", "string", "text", "multichoice", "list")
_PATTERNED = ("string", "text")
_CHOICES = ("choice", "multichoice")
_LISTS = ("multichoice", "list")
_OBJECTS = ("host", "group")


class JobInputError(ValueError):
    """Invalid inputs or schema. ``fields`` maps a field (or ``index.attr``
    for a schema definition) to its message."""

    def __init__(self, message: str, fields: dict[str, str] | None = None):
        super().__init__(message)
        self.message = message
        self.fields = fields or {}


class _Invalid(ValueError):
    pass


def _empty(value: object) -> bool:
    return value is None or value == "" or value == [] or (isinstance(value, str) and not value.strip())


# ── Values ───────────────────────────────────────────────────────────────────


def _integer(raw: object, label: str) -> int:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    try:
        text = canonical_value({"field_type": "number", "label": label}, raw)
    except CustomFieldError as exc:
        raise _Invalid(f"{label} must be a whole number.") from exc
    if not re.fullmatch(r"-?\d+", text):
        raise _Invalid(f"{label} must be a whole number.")
    return int(text)


def _items(raw: object, label: str) -> list[str]:
    parts: list[object]
    if isinstance(raw, str):
        parts = list(raw.split(","))
    elif isinstance(raw, list):
        parts = raw
    else:
        raise _Invalid(f"{label} must be a list.")
    items: list[str] = []
    for part in parts:
        if not isinstance(part, (str, int, float)) or isinstance(part, bool):
            raise _Invalid(f"{label} must be a list of text values.")
        text = str(part).strip()
        if text and text not in items:
            items.append(text)
    return items


def _check_bounds(field: dict, size: int, label: str, unit: str) -> None:
    lo, hi = field.get("min"), field.get("max")
    if lo is not None and size < lo:
        raise _Invalid(f"{label} must be at least {lo}{unit}.")
    if hi is not None and size > hi:
        raise _Invalid(f"{label} must be at most {hi}{unit}.")


def _object_id(raw: object, label: str) -> int:
    if isinstance(raw, dict):
        raw = raw.get("id")
    value = _integer(raw, label) if raw is not None else 0
    if value <= 0:
        raise _Invalid(f"{label} must be selected.")
    return value


def coerce_value(field: dict, raw: object) -> Any:
    """``raw`` as the value of ``field`` (a normalized definition).

    Host and group fields come back as the object id and secret fields as
    the secret's name; :func:`resolve_references` checks they exist.
    Raises ``ValueError`` with a message that names the field.
    """
    ftype = field["type"]
    label = field.get("label") or field["name"]

    if ftype == "integer":
        number = _integer(raw, label)
        _check_bounds(field, number, label, "")
        return number
    if ftype == "boolean":
        if isinstance(raw, str) and raw.strip().lower() in ("on", "off"):
            return raw.strip().lower() == "on"
        try:
            return canonical_value({"field_type": "boolean", "label": label}, raw) == "true"
        except CustomFieldError as exc:
            raise _Invalid(str(exc)) from exc
    if ftype in _LISTS:
        items = _items(raw, label)
        if ftype == "multichoice":
            bad = [i for i in items if i not in field.get("choices", [])]
            if bad:
                raise _Invalid(f"{label}: '{bad[0]}' is not one of the choices.")
        _check_bounds(field, len(items), label, " item(s)")
        return items
    if ftype in _OBJECTS:
        return _object_id(raw, label)

    if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
        raise _Invalid(f"{label} must be text.")
    text = str(raw) if ftype == "text" else str(raw).strip()

    if ftype in ("string", "text"):
        limit = STRING_MAX if ftype == "string" else TEXT_MAX
        if len(text) > limit:
            raise _Invalid(f"{label} must be at most {limit} characters.")
        _check_bounds(field, len(text), label, " character(s)")
        pattern = field.get("regex")
        if pattern and not re.fullmatch(pattern, text):
            raise _Invalid(f"{label} does not match the required format.")
        return text
    if ftype == "choice":
        if text not in field.get("choices", []):
            raise _Invalid(f"{label} must be one of: {', '.join(field.get('choices', []))}.")
        return text
    if ftype == "ip":
        if host_ip_problem(text) == "invalid":
            raise _Invalid(f"{label} must be an IP address, for example 192.0.2.10.")
        return str(ipaddress.ip_address(text))
    if ftype == "cidr":
        try:
            if "/" not in text:
                raise ValueError
            ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise _Invalid(f"{label} must be a prefix in CIDR form, for example 192.0.2.0/24.") from exc
        return text
    if ftype == "secret":
        name = normalize_secret_name(text)
        if not SECRET_NAME_RE.fullmatch(name):
            raise _Invalid(f"{label} must name a secret variable.")
        return name
    raise _Invalid(f"{label} has an unknown type '{ftype}'.")


def validate_inputs(schema: list[dict], raw: dict | None) -> dict:
    """Validate and coerce submitted ``raw`` inputs against ``schema``.

    Returns the coerced values (only declared fields; a missing optional
    field with no default is left out). A missing value takes the field's
    default. Raises :class:`JobInputError` with one message per bad field.
    """
    raw = raw if isinstance(raw, dict) else {}
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for field in schema:
        name = field["name"]
        label = field.get("label") or name
        value = raw.get(name)
        if _empty(value):
            value = field.get("default")
        if _empty(value):
            if field.get("required"):
                errors[name] = f"{label} is required."
            continue
        if field["type"] != "secret" and has_secret_references(json.dumps(value)):
            errors[name] = f"{label}: secret references are only allowed in secret fields."
            continue
        try:
            values[name] = coerce_value(field, value)
        except ValueError as exc:
            errors[name] = str(exc)
    if errors:
        raise JobInputError("Some inputs are not valid.", errors)
    return values


async def resolve_references(schema: list[dict], values: dict) -> dict:
    """Check host, group and secret inputs exist and turn them into what the
    job record stores: hosts and groups as small dicts, secrets as
    ``{{secret.NAME}}`` references. Raises :class:`JobInputError`."""
    import routes.database as db

    out = dict(values)
    errors: dict[str, str] = {}
    for field in schema:
        name = field["name"]
        if name not in values:
            continue
        label = field.get("label") or name
        value = values[name]
        if field["type"] == "host":
            hosts = await db.get_hosts_by_ids([value])
            if not hosts:
                errors[name] = f"{label}: host {value} does not exist."
                continue
            host = hosts[0]
            out[name] = {
                "id": host["id"],
                "hostname": host.get("hostname") or "",
                "ip_address": host.get("ip_address") or "",
                "device_type": host.get("device_type") or "",
            }
        elif field["type"] == "group":
            group = await db.get_group(value)
            if not group:
                errors[name] = f"{label}: inventory group {value} does not exist."
                continue
            out[name] = {"id": group["id"], "name": group.get("name") or ""}
        elif field["type"] == "secret":
            if await db.get_secret_variable_by_name(value) is None:
                errors[name] = f"{label}: secret variable '{value}' does not exist."
                continue
            out[name] = "{{secret." + value + "}}"
    if errors:
        raise JobInputError("Some inputs are not valid.", errors)
    return out


async def resolve_secret_inputs(params: dict) -> tuple[dict, set[str]]:
    """Run time: replace ``{{secret.NAME}}`` input values with the decrypted
    secret. Returns the resolved inputs and the values to scrub from the job
    log. Raises ``SecretResolutionError`` for a secret that no longer exists."""
    from routes.secret_resolver import build_redaction_set, resolve_secrets

    resolved = dict(params)
    redact: set[str] = set()
    for key, value in params.items():
        if isinstance(value, str) and has_secret_references(value):
            redact |= await build_redaction_set([value])
            resolved[key] = (await resolve_secrets([value]))[0]
    return resolved, redact


# ── Schema ───────────────────────────────────────────────────────────────────


def _bound(raw: object, where: str, errors: dict[str, str]) -> int | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        errors[where] = "Must be a whole number."
        return None
    try:
        return _integer(raw, "Value")
    except ValueError:
        errors[where] = "Must be a whole number."
        return None


def normalize_field(raw: object, index: int, errors: dict[str, str]) -> dict | None:
    """One field definition in canonical form, or None (errors recorded under
    ``"<index>.<attr>"``)."""
    at = f"{index}"
    if not isinstance(raw, dict):
        errors[at] = "Each field must be an object."
        return None
    name = str(raw.get("name") or "").strip()
    if not FIELD_NAME_RE.fullmatch(name):
        errors[f"{at}.name"] = "Name must start with a letter or _ and use letters, digits and _ (at most 64)."
    ftype = str(raw.get("type") or "string").strip().lower()
    ftype = TYPE_ALIASES.get(ftype, ftype)
    if ftype not in FIELD_TYPES:
        errors[f"{at}.type"] = f"Type must be one of: {', '.join(FIELD_TYPES)}."
    label = str(raw.get("label") or name).strip()
    if len(label) > LABEL_MAX:
        errors[f"{at}.label"] = f"Label must be at most {LABEL_MAX} characters."
    help_text = str(raw.get("help") or "").strip()
    if len(help_text) > HELP_MAX:
        errors[f"{at}.help"] = f"Help must be at most {HELP_MAX} characters."

    field: dict[str, Any] = {
        "name": name,
        "type": ftype,
        "label": label,
        "help": help_text,
        "required": bool(raw.get("required")),
        "default": None,
    }

    if ftype in _CHOICES:
        choices_raw = raw.get("choices")
        if isinstance(choices_raw, str):
            choices_raw = choices_raw.split(",")
        choices: list[str] = []
        if isinstance(choices_raw, list):
            for c in choices_raw:
                text = str(c).strip() if isinstance(c, (str, int, float)) and not isinstance(c, bool) else ""
                if text and text not in choices:
                    choices.append(text)
        if not choices:
            errors[f"{at}.choices"] = "A choice field needs at least one choice."
        elif len(choices) > CHOICES_MAX or any(len(c) > CHOICE_MAX for c in choices):
            errors[f"{at}.choices"] = f"At most {CHOICES_MAX} choices of at most {CHOICE_MAX} characters."
        field["choices"] = choices

    if ftype in _BOUNDED:
        lo = _bound(raw.get("min"), f"{at}.min", errors)
        hi = _bound(raw.get("max"), f"{at}.max", errors)
        if ftype != "integer" and lo is not None and lo < 0:
            errors[f"{at}.min"] = "A length or count minimum cannot be negative."
        if lo is not None and hi is not None and lo > hi:
            errors[f"{at}.max"] = "Max must not be less than min."
        if lo is not None:
            field["min"] = lo
        if hi is not None:
            field["max"] = hi

    if ftype in _PATTERNED:
        pattern = str(raw.get("regex") or "")
        if pattern:
            if len(pattern) > REGEX_MAX:
                errors[f"{at}.regex"] = f"Pattern must be at most {REGEX_MAX} characters."
            else:
                try:
                    re.compile(pattern)
                    field["regex"] = pattern
                except re.error as exc:
                    errors[f"{at}.regex"] = f"Pattern is not a valid regular expression: {exc}."

    default = raw.get("default")
    if not _empty(default) and f"{at}.type" not in errors:
        if ftype in _OBJECTS:
            errors[f"{at}.default"] = "Host and group fields cannot have a default."
        else:
            try:
                field["default"] = coerce_value(field, default)
            except ValueError as exc:
                errors[f"{at}.default"] = f"Default: {exc}"
    return field


def normalize_schema(raw: object) -> list[dict]:
    """A whole input schema in canonical form. Raises :class:`JobInputError`."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise JobInputError("The input schema is not valid JSON.") from exc
    if not isinstance(raw, list):
        raise JobInputError("The input schema must be a list of fields.")
    if len(raw) > MAX_FIELDS:
        raise JobInputError(f"An input schema can have at most {MAX_FIELDS} fields.")
    errors: dict[str, str] = {}
    fields: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        field = normalize_field(item, index, errors)
        if field is None:
            continue
        if field["name"] and field["name"] in seen:
            errors[f"{index}.name"] = f"The name '{field['name']}' is used twice."
        seen.add(field["name"])
        fields.append(field)
    if errors:
        raise JobInputError("The input schema is not valid.", errors)
    return fields


# ── Permissions ──────────────────────────────────────────────────────────────


def _rule(raw: object, action: str, errors: dict[str, str]) -> dict:
    rule: dict[str, list] = {"roles": [], "groups": []}
    if raw is None:
        return rule
    if not isinstance(raw, dict):
        errors[action] = "Must be an object with roles and groups."
        return rule
    for role in raw.get("roles") or []:
        if role not in ROLES:
            errors[f"{action}.roles"] = f"Roles must be among: {', '.join(ROLES)}."
        elif role not in rule["roles"]:
            rule["roles"].append(role)
    for gid in raw.get("groups") or []:
        if isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0:
            errors[f"{action}.groups"] = "Groups must be access group ids."
        elif gid not in rule["groups"]:
            rule["groups"].append(gid)
    return rule


def normalize_permissions(raw: object) -> dict:
    """``{"run": rule, "commit": rule}`` with each rule ``{"roles", "groups"}``.
    Raises :class:`JobInputError`."""
    if raw is None or raw == "":
        raw = {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise JobInputError("Permissions are not valid JSON.") from exc
    if not isinstance(raw, dict):
        raise JobInputError("Permissions must be an object.")
    errors: dict[str, str] = {}
    out = {action: _rule(raw.get(action), action, errors) for action in ACTIONS}
    if errors:
        raise JobInputError("The permissions are not valid.", errors)
    return out


def _is_open(rule: dict) -> bool:
    return not rule.get("roles") and not rule.get("groups")


def effective_rule(permissions: dict, action: str) -> dict:
    """The rule that decides ``action``; an empty commit rule is the run rule."""
    rule = permissions.get(action) or {}
    if action == "commit" and _is_open(rule):
        rule = permissions.get("run") or {}
    return rule


def is_allowed(permissions: dict, action: str, *, role: str, group_ids: list[int]) -> bool:
    """Whether a user with ``role`` in access groups ``group_ids`` may ``action``."""
    if role == "admin":
        return True
    if action == "commit" and not is_allowed(permissions, "run", role=role, group_ids=group_ids):
        return False
    rule = effective_rule(permissions, action)
    if _is_open(rule):
        return True
    return role in rule.get("roles", []) or bool(set(group_ids) & set(rule.get("groups", [])))


async def user_permissions(session: dict | None) -> tuple[str, list[int]]:
    """The caller's role and access group ids. No session is a server API
    token caller, which is admin-equivalent."""
    if session is None:
        return "admin", []
    import routes.database as db

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        return "", []
    return str(user.get("role") or ""), await db.get_user_group_ids(int(user["id"]))
