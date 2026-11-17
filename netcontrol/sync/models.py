"""The sync data model: object types, natural keys, fields, value
normalisation, directions, conflict policies and per-job field mappings.

Every system is read into ``SyncRecord`` objects in one canonical shape per
object type (``OBJECT_SPECS``), so the diff engine compares like with like
whatever the system. A record's natural key is the tuple of its key fields,
normalised (names ignore case), never a database id.

A job's ``mappings`` adjust the remote side per object type::

    {"devices": {"role": "role.name", "serial": false},
     "vrfs": {"_endpoint": "u_cmdb_ci_vrf"}}

A field set to a remote path (dotted, ``site.name``) is synced from and to
that path; ``true`` turns on an optional field at the adapter's default
path; ``false`` / ``null`` / ``""`` leaves the field out of the sync. Keys
starting with ``_`` are adapter options: ``_endpoint`` (the API path or
table), ``_create_defaults`` (values every create sends, such as a status)
and ``_query`` (ServiceNow: an encoded query filtering the records read).
Key fields cannot be turned off; a key field a system does not hold reads
empty there (path ``""``), so only records with that field empty pair up
and can be created on that side.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from netcontrol.sync.transport import canonical_address, canonical_subnet

# ── Vocabulary ───────────────────────────────────────────────────────────────

DIRECTIONS: tuple[str, ...] = ("import", "export", "bidirectional")
CONFLICT_POLICIES: tuple[str, ...] = ("source_wins", "plexus_wins", "skip_conflicts")
CONNECTION_KINDS: tuple[str, ...] = ("netbox", "nautobot", "servicenow")
AUTH_TYPES: dict[str, tuple[str, ...]] = {
    "netbox": ("token",),
    "nautobot": ("token",),
    "servicenow": ("basic", "oauth"),
}
# Entry actions and outcomes.
ACTIONS: tuple[str, ...] = ("create", "update", "delete", "conflict")
OUTCOMES: tuple[str, ...] = ("planned", "applied", "failed", "skipped")
TARGETS: tuple[str, ...] = ("plexus", "remote")

# ── Normalisers ──────────────────────────────────────────────────────────────


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _int(value: Any) -> str:
    text = _text(value)
    try:
        return str(int(float(text))) if text else ""
    except ValueError:
        return text


def _coord(value: Any) -> str:
    text = _text(value)
    try:
        return f"{round(float(text), 6):g}" if text else ""
    except ValueError:
        return text


def _ip(value: Any) -> str:
    try:
        return canonical_address(value)
    except ValueError:
        return _text(value)


def _cidr(value: Any) -> str:
    try:
        return canonical_subnet(value)
    except ValueError:
        return _text(value)


NORMALISERS: dict[str, Callable[[Any], str]] = {
    "text": _text,
    "lower": _lower,
    "int": _int,
    "coord": _coord,
    "ip": _ip,
    "cidr": _cidr,
}


# ── Object types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ObjectSpec:
    """One object type: its key fields, every field it syncs (key first),
    the kind of each field (``NORMALISERS``; ``text`` when not listed) and
    the fields that are off unless a job's mapping turns them on."""

    name: str
    label: str
    key: tuple[str, ...]
    fields: tuple[str, ...]
    kinds: dict[str, str] = field(default_factory=dict)
    optional: frozenset[str] = frozenset()
    # Key fields compared ignoring case.
    folded: frozenset[str] = frozenset()

    def kind(self, name: str) -> str:
        return self.kinds.get(name, "text")


# In dependency order: a run handles them in this order so a device's site,
# device type and VRFs exist before the device.
OBJECT_SPECS: dict[str, ObjectSpec] = {
    spec.name: spec
    for spec in (
        ObjectSpec(
            "sites",
            "site",
            key=("name",),
            fields=("name", "description", "status", "address", "latitude", "longitude"),
            kinds={"status": "lower", "latitude": "coord", "longitude": "coord"},
            folded=frozenset({"name"}),
        ),
        ObjectSpec(
            "manufacturers",
            "manufacturer",
            key=("name",),
            fields=("name", "description"),
            folded=frozenset({"name"}),
        ),
        ObjectSpec(
            "device_types",
            "device type",
            key=("manufacturer", "model"),
            fields=("manufacturer", "model", "part_number", "u_height", "description"),
            kinds={"u_height": "int"},
            folded=frozenset({"manufacturer", "model"}),
        ),
        ObjectSpec(
            "vrfs",
            "VRF",
            key=("name",),
            fields=("name", "rd", "description"),
            folded=frozenset({"name"}),
        ),
        ObjectSpec(
            "vlans",
            "VLAN",
            key=("vid", "site"),
            fields=("vid", "site", "name", "description"),
            kinds={"vid": "int"},
            folded=frozenset({"site"}),
        ),
        ObjectSpec(
            "prefixes",
            "prefix",
            key=("prefix", "vrf"),
            fields=("prefix", "vrf", "description", "site", "vlan"),
            kinds={"prefix": "cidr", "vlan": "int"},
            folded=frozenset({"vrf"}),
        ),
        ObjectSpec(
            "ip_addresses",
            "IP address",
            key=("address",),
            fields=("address", "prefix", "vrf", "dns_name", "description"),
            kinds={"address": "ip", "prefix": "cidr", "dns_name": "lower"},
        ),
        ObjectSpec(
            "devices",
            "device",
            key=("name",),
            fields=("name", "primary_ip", "site", "manufacturer", "device_type", "role", "platform", "serial"),
            kinds={"primary_ip": "ip"},
            optional=frozenset({"role", "platform", "serial"}),
            folded=frozenset({"name"}),
        ),
    )
}
OBJECT_TYPES: tuple[str, ...] = tuple(OBJECT_SPECS)


def spec_for(object_type: str) -> ObjectSpec:
    spec = OBJECT_SPECS.get(object_type)
    if spec is None:
        raise ValueError(f"Unknown object type {object_type!r}; one of: {', '.join(OBJECT_TYPES)}.")
    return spec


def normalise(spec: ObjectSpec, name: str, value: Any) -> str:
    return NORMALISERS[spec.kind(name)](value)


def natural_key(spec: ObjectSpec, values: dict[str, Any]) -> tuple[str, ...]:
    """The normalised key of a record (names folded to lower case)."""
    out = []
    for name in spec.key:
        text = normalise(spec, name, values.get(name))
        out.append(text.lower() if name in spec.folded else text)
    return tuple(out)


def key_text(spec: ObjectSpec, values: dict[str, Any]) -> str:
    """The key as people read it: ``10 @ site-a``, ``192.0.2.0/24 (VRF blue)``."""
    parts = [normalise(spec, name, values.get(name)) for name in spec.key]
    if spec.name == "device_types":
        return " ".join(p for p in parts if p)
    head, rest = parts[0], [p for p in parts[1:] if p]
    if not rest:
        return head
    if spec.name == "prefixes":
        return f"{head} (VRF {rest[0]})"
    return f"{head} @ {rest[0]}"


@dataclass
class SyncRecord:
    """One object as a system holds it: canonical field values (only the
    fields the system reads), the natural key, and ``ref`` - what the
    system needs to update or delete it (a NetBox id, a ServiceNow sys_id,
    a Plexus row id)."""

    object_type: str
    values: dict[str, str]
    ref: Any = None

    @property
    def spec(self) -> ObjectSpec:
        return spec_for(self.object_type)

    @property
    def key(self) -> tuple[str, ...]:
        return natural_key(self.spec, self.values)

    @property
    def label(self) -> str:
        return key_text(self.spec, self.values)


def make_record(
    object_type: str, raw: dict[str, Any], ref: Any = None, fields: Iterable[str] | None = None
) -> SyncRecord:
    """A record from raw values, every value normalised; only ``fields``
    (default every field of the type) are kept."""
    spec = spec_for(object_type)
    wanted = tuple(fields) if fields is not None else spec.fields
    values = {name: normalise(spec, name, raw.get(name)) for name in wanted if name in spec.fields}
    return SyncRecord(object_type, values, ref)


# ── Mappings ─────────────────────────────────────────────────────────────────


class MappingError(ValueError):
    """A job's mapping names an unknown object type or field."""


@dataclass(frozen=True)
class TypeMapping:
    """The resolved mapping of one object type for one adapter: the remote
    path of every field that syncs, and the adapter options."""

    object_type: str
    paths: dict[str, str]
    options: dict[str, Any]

    @property
    def fields(self) -> tuple[str, ...]:
        spec = spec_for(self.object_type)
        return tuple(f for f in spec.fields if f in self.paths)


def resolve_mapping(object_type: str, defaults: dict[str, str], override: dict[str, Any] | None) -> TypeMapping:
    """Merge a job's mapping of one type over an adapter's default paths.
    ``defaults`` maps every field the adapter can sync to its path; optional
    fields of the spec stay off unless ``override`` turns them on."""
    spec = spec_for(object_type)
    override = dict(override or {})
    paths: dict[str, str] = {}
    for name in spec.fields:
        if name in defaults and name not in spec.optional:
            paths[name] = defaults[name]
    options: dict[str, Any] = {}
    for name, value in override.items():
        if name.startswith("_"):
            options[name[1:]] = value
            continue
        if name not in spec.fields:
            raise MappingError(f"{spec.label} has no field {name!r}; fields: {', '.join(spec.fields)}.")
        if value is True:
            if name not in defaults:
                raise MappingError(f"Give the remote path of {spec.label} field {name!r}; it has no default.")
            paths[name] = defaults[name]
        elif value in (False, None, ""):
            if name in spec.key:
                raise MappingError(f"The key field {name!r} of {spec.label}s cannot be turned off.")
            paths.pop(name, None)
        elif isinstance(value, str):
            paths[name] = value.strip()
        else:
            raise MappingError(f"Mapping of {spec.label} field {name!r} must be a path, true or false.")
    # A key field the remote system does not hold (a VRF on a ServiceNow
    # network) reads empty there and is never written: path "".
    for name in spec.key:
        paths.setdefault(name, "")
    return TypeMapping(object_type, paths, options)


def check_mappings(mappings: Any) -> dict[str, dict[str, Any]]:
    """Validate the shape of a job's ``mappings`` (types and fields are
    known); the adapter-specific paths are checked when the job runs."""
    if mappings in (None, ""):
        return {}
    if not isinstance(mappings, dict):
        raise MappingError("Mappings must be an object keyed by object type.")
    out: dict[str, dict[str, Any]] = {}
    for object_type, fields_map in mappings.items():
        spec = OBJECT_SPECS.get(object_type)
        if spec is None:
            raise MappingError(f"Unknown object type {object_type!r} in mappings.")
        if not isinstance(fields_map, dict):
            raise MappingError(f"The mapping of {object_type} must be an object.")
        for name, value in fields_map.items():
            if not isinstance(name, str):
                raise MappingError(f"Mapping keys of {object_type} must be text.")
            if name.startswith("_"):
                continue
            if name not in spec.fields:
                raise MappingError(f"{spec.label} has no field {name!r}; fields: {', '.join(spec.fields)}.")
            if name in spec.key and value in (False, None, ""):
                raise MappingError(f"The key field {name!r} of {spec.label}s cannot be turned off.")
            if not isinstance(value, (str, bool)) and value is not None:
                raise MappingError(f"Mapping of {spec.label} field {name!r} must be a path, true or false.")
        out[object_type] = dict(fields_map)
    return out


def network_of(address: str, prefix: str) -> int | None:
    """The prefix length to write an address with: the prefix's when the
    address lies in it, else ``None``."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return None
    return net.prefixlen if ip_obj.version == net.version and ip_obj in net else None
