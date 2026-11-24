"""Bulk import of inventory and addressing objects from CSV, YAML or JSON.

One module holds the whole pipeline; ``netcontrol.routes.bulk_import`` is a
thin HTTP layer over it:

1. ``parse_records``: the uploaded text as records (one per CSV row or list
   item), keys normalised to snake case (``"IP Address"`` -> ``ip_address``)
   and every value text. A CSV cell that the export guarded against formulas
   (``'=x``) loses its apostrophe here, so export -> edit -> import is
   lossless. YAML is read with ``yaml_safe.safe_load_no_alias`` only (safe
   loader, aliases refused).
2. ``plan_import``: each record checked against the database by the adapter
   of its object type (hosts, groups, prefixes, addresses, VLANs, VRFs):
   references are resolved by name, the record is matched to an existing
   object by the chosen match key, and the row gets an action (``create``,
   ``update``, ``skip`` or ``error``), its field errors and, for an update,
   the field diff. Nothing is written.
3. ``commit_import``: plans again (the client's preview is never trusted)
   and applies the rows through the ``routes.database`` facade helpers, so
   ``@tracks_changes`` emits the object-change events (webhooks, change
   log). By default all or nothing: any row error refuses the whole import,
   and the writes run in one database transaction that a failure rolls back.
   With ``atomic=False`` rows are written one at a time and the import stops
   at the first row that fails, reporting what was written.

Credentials and other secrets are never importable: a column that names one
is ignored. Unknown references are row errors and are never created, except
tags (any inventory user may create a tag through the tag API, so a new tag
name is created on commit and named in the preview).

Columns and rules per object type: ``docs/bulk-import.md``.
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
import ipaddress
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import routes.database as db
import yaml

from netcontrol.csv_cells import CSV_FORMULA_PREFIXES, csv_text_cell
from netcontrol.custom_fields import TEXT_MAX, CustomFieldError, check_object_values, clean_tag_name, typed_value
from netcontrol.data_validation import CUSTOM_FIELD_PREFIX, pick, validate_object
from netcontrol.device_model import LOCATION_DETAIL_MAX
from netcontrol.managed_targets import address_writer_id, caller_confirms_addresses
from netcontrol.network_objects import clean_description, clean_rd, clean_vid, clean_vlan_name, clean_vrf_name
from netcontrol.object_scope import READ_ONLY_DETAIL, ObjectScope
from netcontrol.routes.host_identity import host_ip_problem
from netcontrol.yaml_safe import safe_load_no_alias

# ── Limits ───────────────────────────────────────────────────────────────────

# Largest upload or pasted text, in bytes (the form parser's own cap on a
# pasted field is the same 1 MiB).
MAX_IMPORT_BYTES = 1024 * 1024
# Most records one import takes.
MAX_IMPORT_ROWS = 5000

FORMATS: tuple[str, ...] = ("csv", "yaml", "json")
MODES: tuple[str, ...] = ("create", "update", "upsert")
ACTIONS: tuple[str, ...] = ("create", "update", "skip", "error")

HOSTNAME_MAX = 255
PLATFORM_MAX = 64
GROUP_NAME_MAX = 200
DNS_NAME_MAX = 255

# A column whose name contains one of these words is never imported.
_SECRET_WORDS = ("password", "secret", "credential", "token", "community", "api_key", "private_key", "passphrase")


class BulkImportError(ValueError):
    """The upload as a whole cannot be imported (bad format, too large, no
    rows, an unknown option). The message says why."""


# ── CSV cells ────────────────────────────────────────────────────────────────

# The formula guards (``csv_text_cell``) live in netcontrol.csv_cells and are
# imported above, so exporters outside bulk import can share them.


def csv_field_cell(field_def: dict, value: object) -> str:
    """A custom field value as CSV text: numbers and booleans as written,
    text-like values guarded against formulas."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if field_def["field_type"] == "number":
        return str(value)
    return csv_text_cell(value)


def unguard_cell(text: str) -> str:
    """Undo ``csv_text_cell``: drop the apostrophe it puts before a value
    that starts like a formula. Any other apostrophe is kept."""
    if text.startswith("'") and text[1:].startswith(CSV_FORMULA_PREFIXES):
        return text[1:]
    return text


# ── Host export table (shared by the CSV and YAML exports and the import) ────

# (CSV header, record key). The first seven are written as stored; the rest
# are user text guarded against formulas in CSV.
HOST_EXPORT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Hostname", "hostname"),
    ("IP Address", "ip_address"),
    ("Model", "model"),
    ("Software Version", "software_version"),
    ("Platform", "platform"),
    ("Status", "status"),
    ("Group", "group"),
    ("Manufacturer", "manufacturer"),
    ("Device Type", "device_type"),
    ("Role", "role"),
    ("Lifecycle Status", "lifecycle_status"),
    ("Site", "site"),
    ("Location Detail", "location_detail"),
    ("Tags", "tags"),
)
_HOST_UNGUARDED = 7


def host_export_record(row: dict, group_path: str) -> dict[str, Any]:
    """One host of the export as a record: the ``HOST_EXPORT_COLUMNS`` keys
    (``tags`` a list of names) and ``custom_fields`` (typed values by key).
    ``row`` carries the custom data and device display objects
    (``attach_custom_data``, ``attach_device_data``)."""
    hardware = row.get("hardware") or {}
    return {
        "hostname": row.get("hostname") or "",
        "ip_address": row.get("ip_address") or "",
        "model": row.get("model") or "",
        "software_version": row.get("software_version") or "",
        "platform": row.get("device_type") or "",
        "status": row.get("status") or "",
        "group": group_path,
        "manufacturer": hardware.get("manufacturer") or "",
        "device_type": hardware.get("model") or "",
        "role": (row.get("role") or {}).get("name") or "",
        "lifecycle_status": (row.get("lifecycle_status") or {}).get("name") or "",
        "site": (row.get("site") or {}).get("name") or "",
        "location_detail": row.get("location_detail") or "",
        "tags": [t["name"] for t in row.get("tags") or []],
        "custom_fields": dict(row.get("custom_fields") or {}),
    }


def host_csv_header(fields: list[dict]) -> list[str]:
    """The host CSV header: the standard columns, then one column per host
    custom field (its label), in display order."""
    return [header for header, _ in HOST_EXPORT_COLUMNS] + [f["label"] for f in fields]


def host_csv_row(record: dict[str, Any], fields: list[dict]) -> list[str]:
    """``host_export_record`` as a CSV row under ``host_csv_header``."""
    cells: list[str] = []
    for index, (_, key) in enumerate(HOST_EXPORT_COLUMNS):
        value = "; ".join(record["tags"]) if key == "tags" else record[key]
        cells.append(str(value or "") if index < _HOST_UNGUARDED else csv_text_cell(value))
    values = record["custom_fields"]
    return cells + [csv_field_cell(f, values.get(f["key"])) for f in fields]


async def host_export_records(hosts: list[dict]) -> tuple[list[dict], list[dict[str, Any]]]:
    """The host custom fields and one export record per host of ``hosts``
    (rows of ``get_all_hosts_for_export``, already filtered to the caller's
    scope). Each record's ``group`` is the group's path."""
    from netcontrol.routes.custom_fields import attach_custom_data
    from netcontrol.routes.device_model import attach_device_data

    fields = await db.list_custom_fields("host")
    await attach_custom_data("host", hosts, _id_key)
    await attach_device_data(hosts)
    paths = {int(g["id"]): g["path"] for g in await db.get_all_groups()}
    records = [host_export_record(h, paths.get(int(h["group_id"] or 0), h.get("group_name") or "")) for h in hosts]
    return fields, records


def _id_key(row: dict) -> str:
    return str(row["id"])


# ── Parsing ──────────────────────────────────────────────────────────────────

_NOT_ALNUM = re.compile(r"[^a-z0-9]+")


def column_key(name: object) -> str:
    """A column header or record key in snake case: ``"IP Address"`` and
    ``ip_address`` both give ``ip_address``."""
    return _NOT_ALNUM.sub("_", str(name).strip().lower()).strip("_")


@dataclass
class Record:
    """One row of the upload: its row number (the spreadsheet row of a CSV,
    header being row 1; the item number of a YAML/JSON list) and its values
    by column key. A value is text, except ``tags`` (a list of names) and
    ``custom_fields`` (values by field key or label)."""

    row: int
    values: dict[str, Any]
    problems: list[dict] = field(default_factory=list)


def _scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.isoformat()
    if isinstance(value, (int, float, str)):
        return str(value).strip()
    raise ValueError("must be a single value")


def _record(row: int, raw: dict) -> Record:
    rec = Record(row=row, values={})
    for raw_key, value in raw.items():
        key = column_key(raw_key)
        if not key:
            continue
        if key in rec.values:
            rec.problems.append({"field": key, "message": f"The column {raw_key!s} is given twice."})
            continue
        try:
            if key == "tags" and isinstance(value, list):
                rec.values[key] = [_scalar(v) for v in value]
            elif key == "custom_fields" and isinstance(value, dict):
                rec.values[key] = {str(k): _scalar(v) for k, v in value.items()}
            else:
                rec.values[key] = _scalar(value)
        except ValueError as exc:
            rec.problems.append({"field": key, "message": f"{raw_key!s} {exc}."})
    return rec


def _parse_csv(text: str) -> list[Record]:
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        raise BulkImportError(f"The file is not valid CSV: {exc}.") from exc
    if not rows:
        raise BulkImportError("The file is empty: give a header row and at least one row.")
    header = [unguard_cell(h).strip() for h in rows[0]]
    keys = [column_key(h) for h in header]
    seen: set[str] = set()
    for name, key in zip(header, keys, strict=True):
        if key and key in seen:
            raise BulkImportError(f"The column {name!r} is given twice.")
        seen.add(key)
    records: list[Record] = []
    for index, cells in enumerate(rows[1:], start=2):
        if not any(c.strip() for c in cells):
            continue
        rec = _record(index, {h: unguard_cell(c) for h, c in zip(header, cells, strict=False) if column_key(h)})
        if any(c.strip() for c in cells[len(header) :]):
            rec.problems.append({"field": "", "message": "The row has more cells than the header has columns."})
        records.append(rec)
    return records


def _too_many_rows(count: int) -> str:
    return f"The file has {count} rows; at most {MAX_IMPORT_ROWS} can be imported at once."


def _parse_structured(text: str, fmt: str) -> list[Record]:
    try:
        data = json.loads(text) if fmt == "json" else safe_load_no_alias(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise BulkImportError(f"The file is not valid {fmt.upper()}: {str(exc).splitlines()[0]}") from exc
    if isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), list):
        data = next(iter(data.values()))
    if not isinstance(data, list):
        raise BulkImportError(f"The {fmt.upper()} must be a list of objects.")
    # Before a record is built: each one costs a visit per key.
    if len(data) > MAX_IMPORT_ROWS:
        raise BulkImportError(_too_many_rows(len(data)))
    records: list[Record] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            records.append(Record(row=index, values={}, problems=[{"field": "", "message": "Not an object."}]))
            continue
        records.append(_record(index, item))
    return records


def decode_upload(content: bytes) -> str:
    """Upload bytes as text (UTF-8, a byte order mark dropped)."""
    if len(content) > MAX_IMPORT_BYTES:
        raise BulkImportError(f"The file is larger than {MAX_IMPORT_BYTES // 1024} KiB.")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BulkImportError("The file is not UTF-8 text.") from exc


def parse_records(text: str, fmt: str) -> list[Record]:
    """The records of ``text`` in format ``fmt`` (``csv``, ``yaml`` or
    ``json``). Raises ``BulkImportError`` for a file that cannot be read,
    has no rows or more than ``MAX_IMPORT_ROWS``."""
    if fmt not in FORMATS:
        raise BulkImportError(f"Format must be one of: {', '.join(FORMATS)}.")
    if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise BulkImportError(f"The file is larger than {MAX_IMPORT_BYTES // 1024} KiB.")
    if text.startswith("﻿"):
        text = text[1:]
    records = _parse_csv(text) if fmt == "csv" else _parse_structured(text, fmt)
    if not records:
        raise BulkImportError("The file has no rows to import.")
    if len(records) > MAX_IMPORT_ROWS:
        raise BulkImportError(_too_many_rows(len(records)))
    return records


# ── Validation hook ──────────────────────────────────────────────────────────


async def _extra_row_errors(object_type: str, values: dict[str, Any], existing: dict | None) -> list[dict]:
    """Errors from the data validation rules for one row: ``{field, rule,
    message}`` items. ``object_type`` is the change-event type (``host``,
    ``group``, ``prefix``, ``ip_address``, ``vlan``, ``vrf``), ``values``
    the object as the row would leave it, ``existing`` the stored row of an
    update (``None`` for a create).

    The adapters' keys are mapped onto the rule fields of
    ``data_validation.OBJECT_FIELDS`` (an address's ``dns_name`` is its
    ``hostname``), and every custom field of the type is passed as
    ``cf.<key>`` (``""`` when unset), the way custom data saves are checked."""
    checked = dict(values)
    if object_type == "ip_address" and "dns_name" in checked:
        checked["hostname"] = checked.pop("dns_name")
    custom = checked.pop("custom_fields", None)
    if custom_type := _CUSTOM_TYPES.get(object_type):
        for f in await db.list_custom_fields(custom_type):
            checked[CUSTOM_FIELD_PREFIX + f["key"]] = (custom or {}).get(f["key"], "")
    return await validate_object(object_type, checked, existing=pick(existing, object_type) if existing else None)


# Rule object types whose objects carry custom fields (the adapters'
# ``custom_type``).
_CUSTOM_TYPES: dict[str, str] = {"host": "host", "group": "group", "prefix": "prefix"}


# ── Rows, context, adapters ──────────────────────────────────────────────────


@dataclass(frozen=True)
class Column:
    """An importable column: its CSV header, its key, other keys accepted
    for it, and whether it is exported only (read back but never written)."""

    header: str
    key: str
    aliases: tuple[str, ...] = ()
    readonly: bool = False
    required: bool = False


@dataclass
class RowResult:
    row: int
    key: str = ""
    action: str = "error"
    errors: list[dict] = field(default_factory=list)
    changes: dict[str, dict] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    plan: dict | None = None
    existing: dict | None = None
    new_tags: list[str] = field(default_factory=list)

    def error(self, column: str, message: str) -> None:
        self.errors.append({"field": column, "message": message})

    def as_dict(self) -> dict:
        return {
            "row": self.row,
            "key": self.key,
            "action": self.action,
            "errors": self.errors,
            "changes": self.changes,
            "warnings": self.warnings,
        }


def _text(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return "" if value is None else str(value).strip()


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


@dataclass
class ImportContext:
    """What one import run reads once and shares between its rows."""

    scope: ObjectScope
    user: str
    mode: str
    match_key: str
    data: dict[str, Any] = field(default_factory=dict)
    # Tag names by lower-case name, and the new ones this import creates.
    tags: dict[str, dict] = field(default_factory=dict)
    new_tags: dict[str, str] = field(default_factory=dict)
    all_fields: list[dict] = field(default_factory=list)
    object_data: dict[str, dict] = field(default_factory=dict)
    # Keys seen in this file: key -> first row number.
    seen: dict[Any, int] = field(default_factory=dict)
    # Run after the writes are committed (cache refreshes, IPAM push).
    after_commit: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def tag_ids(self, names: list[str]) -> list[int]:
        """The tag ids of ``names``, creating the new tags on first use."""
        ids: list[int] = []
        for name in names:
            tag = self.tags.get(name.lower())
            if tag is None:
                tag = await db.create_tag(name=name, created_by=self.user)
                self.tags[name.lower()] = tag
            ids.append(int(tag["id"]))
        return ids


class Adapter:
    """How one object type is imported. Subclasses set the class attributes
    and implement ``load``, ``match``, ``build`` and ``apply``."""

    name = ""  # the URL segment: hosts, groups, prefixes ...
    object_type = ""  # the change-event type: host, group, prefix ...
    label = ""  # one object, for messages: "host"
    columns: tuple[Column, ...] = ()
    match_keys: tuple[str, ...] = ()
    custom_type: str | None = None  # custom fields and tags apply

    def template_header(self, fields: list[dict]) -> list[str]:
        return [c.header for c in self.columns] + [f["label"] for f in fields]

    async def load(self, ctx: ImportContext) -> None:
        raise NotImplementedError

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        """The row's key (``None`` when the match column is empty) and the
        existing objects it matches."""
        raise NotImplementedError

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        """Check the row and set ``res.plan`` (and ``res.changes`` for an
        update); errors go to ``res``."""
        raise NotImplementedError

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        """The object as the planned row leaves it (for the validation rules)."""
        raise NotImplementedError

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        raise NotImplementedError

    # ── Custom fields and tags ──

    def custom_columns(self, ctx: ImportContext) -> dict[str, dict]:
        """Custom field definitions by column key (label and field key)."""
        out: dict[str, dict] = {}
        if self.custom_type is None:
            return out
        for f in ctx.all_fields:
            if self.custom_type in f["object_types"]:
                out.setdefault(column_key(f["label"]), f)
                out.setdefault(column_key(f["key"]), f)
        return out

    async def load_custom(self, ctx: ImportContext) -> None:
        if self.custom_type is None:
            return
        ctx.all_fields = await db.list_custom_fields()
        ctx.tags = {t["name"].lower(): t for t in await db.list_tags()}
        ctx.object_data = await db.get_object_data_bulk(self.custom_type)

    def plan_custom(
        self, ctx: ImportContext, values: dict[str, Any], given: set[str], key: str | None, res: RowResult
    ) -> dict | None:
        """The tags and custom values the row leaves on the object (merged
        over the stored ones for an update), or ``None`` when the row gives
        neither. Adds the diff to ``res.changes``."""
        if self.custom_type is None:
            return None
        columns = self.custom_columns(ctx)
        raw_fields: dict[str, Any] = {}
        for column in given:
            if column in columns:
                raw_fields[columns[column]["key"]] = values[column]
        nested = values.get("custom_fields")
        if isinstance(nested, dict):
            for name, value in nested.items():
                f = columns.get(column_key(name))
                if f is None:
                    res.error("custom_fields", f"{name} is not a custom field of {self.label}s.")
                    continue
                raw_fields[f["key"]] = value
        if "tags" not in given and not raw_fields:
            return None
        current = ctx.object_data.get(key or "") or {"tags": [], "fields": {}}
        before_tags = [t["name"] for t in current["tags"]]
        tags = before_tags
        if "tags" in given:
            raw = values["tags"]
            names = raw if isinstance(raw, list) else [n for n in str(raw).split(";")]
            tags = []
            for name in (n.strip() for n in names):
                if not name:
                    continue
                try:
                    name = clean_tag_name(name)
                except CustomFieldError as exc:
                    res.error("tags", str(exc))
                    continue
                known = ctx.tags.get(name.lower())
                if known is not None:
                    name = known["name"]
                else:
                    name = ctx.new_tags.setdefault(name.lower(), name)
                    if name not in res.new_tags:
                        res.new_tags.append(name)
                        res.warnings.append(f"Tag {name!r} does not exist and will be created.")
                if name not in tags:
                    tags.append(name)
        merged = {**current["fields"], **raw_fields}
        canonical, errors = check_object_values(ctx.all_fields, self.custom_type, merged)
        for field_key, message in errors.items():
            res.error(field_key, message)
        if sorted(tags, key=str.lower) != sorted(before_tags, key=str.lower):
            res.changes["Tags"] = {"before": "; ".join(before_tags), "after": "; ".join(tags)}
        by_id = {int(f["id"]): f for f in ctx.all_fields}
        changed = "Tags" in res.changes
        for field_id, text in canonical.items():
            f = by_id[field_id]
            before = current["fields"].get(f["key"], "")
            if before != text:
                res.changes[f["label"]] = {"before": before, "after": text}
                changed = True
        return {"tags": tags, "values": canonical, "changed": changed}

    async def apply_custom(self, ctx: ImportContext, key: str, custom: dict | None) -> None:
        if self.custom_type is None or not custom or not custom["changed"]:
            return
        await db.set_object_data(self.custom_type, key, await ctx.tag_ids(custom["tags"]), custom["values"])

    def custom_values(self, custom: dict | None, key: str | None, ctx: ImportContext) -> dict[str, Any]:
        """The object's custom values (typed, by key) as the row leaves them."""
        if self.custom_type is None:
            return {}
        if custom is None:
            stored = (ctx.object_data.get(key or "") or {}).get("fields", {})
            by_key = {f["key"]: f for f in ctx.all_fields}
            return {k: typed_value(by_key[k]["field_type"], v) for k, v in stored.items() if k in by_key}
        by_id = {int(f["id"]): f for f in ctx.all_fields}
        return {by_id[i]["key"]: typed_value(by_id[i]["field_type"], v) for i, v in custom["values"].items() if v}


def _first(values: dict[str, Any], key: str) -> str:
    return _text(values.get(key))


def _lookup(items: Iterable[dict], key: str = "name") -> dict[str, dict]:
    """Records by lower-case name."""
    return {str(i[key]).lower(): i for i in items}


def _diff(res: RowResult, header: str, before: Any, after: Any) -> None:
    b = "" if before is None else str(before)
    a = "" if after is None else str(after)
    if b != a:
        res.changes[header] = {"before": b, "after": a}


# ── Hosts ────────────────────────────────────────────────────────────────────


class HostAdapter(Adapter):
    name = "hosts"
    object_type = "host"
    label = "host"
    columns = (
        Column("Hostname", "hostname", ("name",), required=True),
        Column("IP Address", "ip_address", ("ip", "address"), required=True),
        Column("Model", "model", readonly=True),
        Column("Software Version", "software_version", readonly=True),
        Column("Platform", "platform", ("driver",)),
        Column("Status", "status", readonly=True),
        Column("Group", "group", ("group_path", "group_name"), required=True),
        Column("Manufacturer", "manufacturer"),
        Column("Device Type", "device_type", ("hardware_model",)),
        Column("Role", "role"),
        Column("Lifecycle Status", "lifecycle_status"),
        Column("Site", "site"),
        Column("Location Detail", "location_detail"),
        Column("Tags", "tags"),
    )
    # Accepted, not exported: the VRF and VLAN of the host's address.
    extra_columns = (Column("VRF", "vrf", ("vrf_name",)), Column("VLAN", "vlan", ("vlan_id",)))
    match_keys = ("hostname", "ip")
    custom_type = "host"

    async def load(self, ctx: ImportContext) -> None:
        await self.load_custom(ctx)
        groups = await db.get_all_groups()
        ctx.data["groups"] = groups
        ctx.data["group_by_path"] = {g["path"]: g for g in groups}
        groups_by_name: dict[str, list[dict]] = {}
        for g in groups:
            groups_by_name.setdefault(g["name"], []).append(g)
        ctx.data["groups_by_name"] = groups_by_name
        ctx.data["path_by_id"] = {int(g["id"]): g["path"] for g in groups}
        hosts = await db.get_all_hosts()
        by_name: dict[str, list[dict]] = {}
        by_ip: dict[str, list[dict]] = {}
        for h in ctx.scope.filter_hosts(hosts):
            by_name.setdefault(str(h.get("hostname") or "").lower(), []).append(h)
            by_ip.setdefault(_canonical_ip(str(h.get("ip_address") or "")), []).append(h)
        ctx.data["hosts_by_name"], ctx.data["hosts_by_ip"] = by_name, by_ip
        # (group id, address) -> host id, over every host: a group holds an address once.
        ctx.data["host_slots"] = {
            (int(h["group_id"] or 0), _canonical_ip(str(h.get("ip_address") or ""))): int(h["id"]) for h in hosts
        }
        ctx.data["device_types"] = await db.list_device_types()
        ctx.data["device_type_by_id"] = {int(d["id"]): d for d in ctx.data["device_types"]}
        roles = await db.list_device_roles()
        statuses = await db.list_lifecycle_statuses()
        sites = await db.list_geo_sites()
        ctx.data["roles"], ctx.data["statuses"], ctx.data["sites"] = _lookup(roles), _lookup(statuses), _lookup(sites)
        ctx.data["names"] = {
            "role_id": {int(r["id"]): r["name"] for r in roles},
            "lifecycle_status_id": {int(s["id"]): s["name"] for s in statuses},
            "site_id": {int(s["id"]): s["name"] for s in sites},
        }
        ctx.data["vrfs"] = _lookup(await db.list_vrfs())
        ctx.data["vlan_vids"] = {int(v["vid"]) for v in await db.list_vlans()}

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        if ctx.match_key == "ip":
            ip = _first(values, "ip_address")
            if not ip:
                return None, []
            wanted = _canonical_ip(ip)
            return wanted, list(ctx.data["hosts_by_ip"].get(wanted, []))
        name = _first(values, "hostname")
        if not name:
            return None, []
        return name, list(ctx.data["hosts_by_name"].get(name.lower(), []))

    def _group(self, ctx: ImportContext, text: str, res: RowResult) -> dict | None:
        group = ctx.data["group_by_path"].get(text)
        if group is None:
            named = ctx.data["groups_by_name"].get(text, [])
            readable = [g for g in named if ctx.scope.can_read_group(g["id"])]
            if len(readable) > 1:
                res.error("group", f"More than one group is named {text!r}: give its path (e.g. Parent / {text}).")
                return None
            group = readable[0] if readable else None
        if group is None or not ctx.scope.can_read_group(group["id"]):
            res.error("group", f"No group {text!r}.")
            return None
        if not ctx.scope.can_write_group(group["id"]):
            res.error("group", READ_ONLY_DETAIL)
            return None
        return group

    def _device_type(self, ctx: ImportContext, values: dict[str, Any], res: RowResult) -> int | None:
        model = _first(values, "device_type")
        maker = _first(values, "manufacturer")
        if not model and not maker:
            return None
        if not model:
            res.error("device_type", "Give the device type with the manufacturer.")
            return None
        found = [
            d
            for d in ctx.data["device_types"]
            if d["model"].lower() == model.lower() and (not maker or d["manufacturer"].lower() == maker.lower())
        ]
        if not found:
            by = f" by {maker}" if maker else ""
            res.error("device_type", f"No device type {model!r}{by}.")
            return None
        if len(found) > 1:
            res.error("device_type", f"More than one manufacturer has a device type {model!r}: give the manufacturer.")
            return None
        return int(found[0]["id"])

    def _ref(self, ctx: ImportContext, kind: str, column: str, text: str, res: RowResult) -> int | None:
        if not text:
            return None
        record = ctx.data[kind].get(text.lower())
        if record is None:
            res.error(column, f"No {column.replace('_', ' ')} {text!r}.")
            return None
        return int(record["id"])

    def _hardware_text(self, ctx: ImportContext, device_type_id: int | None) -> str:
        d = ctx.data["device_type_by_id"].get(int(device_type_id)) if device_type_id is not None else None
        return f"{d['manufacturer']} {d['model']}" if d else ""

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        create = cur is None
        if cur is not None and not ctx.scope.can_write_group(cur.get("group_id")):
            res.error("group", READ_ONLY_DETAIL)
            return

        ip = _first(values, "ip_address") if "ip_address" in given else ""
        if create or "ip_address" in given:
            if not ip:
                res.error("ip_address", "Enter the IP address.")
            elif host_ip_problem(ip) == "invalid":
                res.error("ip_address", f"Invalid IP address: {ip}")
            elif host_ip_problem(ip):
                res.error("ip_address", f"IP address {ip} is in a reserved range and cannot be added to inventory")
        else:
            ip = str(cur.get("ip_address") or "") if cur else ""

        if "hostname" in given:
            hostname = _first(values, "hostname")
            if not hostname and create:
                hostname = ip
            elif not hostname:
                res.error("hostname", "Enter the hostname.")
        else:
            hostname = str(cur["hostname"]) if cur else ip
        if len(hostname) > HOSTNAME_MAX:
            res.error("hostname", f"Hostname must be at most {HOSTNAME_MAX} characters.")

        platform = _first(values, "platform")
        if not platform:
            platform = str(cur.get("device_type") or "cisco_ios") if cur else "cisco_ios"
        if len(platform) > PLATFORM_MAX:
            res.error("platform", f"Platform must be at most {PLATFORM_MAX} characters.")

        group_text = _first(values, "group")
        group: dict | None = None
        if group_text:
            group = self._group(ctx, group_text, res)
        elif create:
            res.error("group", "Give the group (its name or path).")
        group_id = int(group["id"]) if group else (int(cur["group_id"]) if cur else None)

        device: dict[str, Any] = {}
        if "device_type" in given or "manufacturer" in given:
            device["device_type_id"] = self._device_type(ctx, values, res)
        for column, kind, id_field in (
            ("role", "roles", "role_id"),
            ("lifecycle_status", "statuses", "lifecycle_status_id"),
            ("site", "sites", "site_id"),
        ):
            if column in given:
                device[id_field] = self._ref(ctx, kind, column, _first(values, column), res)
        if "location_detail" in given:
            detail = _first(values, "location_detail")
            if len(detail) > LOCATION_DETAIL_MAX:
                res.error("location_detail", f"Location detail must be at most {LOCATION_DETAIL_MAX} characters.")
            device["location_detail"] = detail

        vrf: str | None = None
        if "vrf" in given:
            vrf = _first(values, "vrf")
            if vrf:
                record = ctx.data["vrfs"].get(vrf.lower())
                if record is None:
                    res.error("vrf", f"No VRF {vrf!r}.")
                else:
                    vrf = str(record["name"])
        vlan: str | None = None
        if "vlan" in given:
            vlan = _first(values, "vlan")
            if vlan and (not vlan.isdigit() or int(vlan) not in ctx.data["vlan_vids"]):
                res.error("vlan", f"No VLAN {vlan!r}.")

        if group_id is not None and ip and not res.errors:
            target = (group_id, _canonical_ip(ip))
            holder = ctx.data["host_slots"].get(target)
            if holder is not None and (cur is None or holder != int(cur["id"])):
                res.error("ip_address", "A host with that IP address already exists in this group.")
            if target in ctx.seen:
                res.error("ip_address", f"Row {ctx.seen[target]} adds the same IP address to the same group.")
            else:
                ctx.seen[target] = res.row

        key = str(cur["id"]) if cur else None
        custom = self.plan_custom(ctx, values, given, key, res)
        if create:
            # A host gets the default lifecycle status unless the row names one.
            device = {k: v for k, v in device.items() if v not in (None, "")}
        else:
            assert cur is not None  # nosec B101 - narrowed for mypy
            names = ctx.data["names"]
            _diff(res, "Hostname", cur.get("hostname"), hostname)
            _diff(res, "IP Address", cur.get("ip_address"), ip)
            _diff(res, "Platform", cur.get("device_type"), platform)
            _diff(
                res,
                "Group",
                ctx.data["path_by_id"].get(int(cur["group_id"] or 0)),
                ctx.data["path_by_id"].get(group_id or 0),
            )
            if vrf is not None:
                _diff(res, "VRF", cur.get("vrf_name") or "", vrf)
            if vlan is not None:
                _diff(res, "VLAN", cur.get("vlan_id") or "", vlan)
            for id_field, value in list(device.items()):
                if id_field == "device_type_id":
                    _diff(
                        res, "Device Type", self._hardware_text(ctx, cur.get(id_field)), self._hardware_text(ctx, value)
                    )
                elif id_field == "location_detail":
                    _diff(res, "Location Detail", cur.get("location_detail") or "", value)
                else:
                    header = {"role_id": "Role", "lifecycle_status_id": "Lifecycle Status", "site_id": "Site"}[id_field]
                    before = names[id_field].get(int(cur[id_field])) if cur.get(id_field) is not None else ""
                    after = names[id_field].get(int(value)) if value is not None else ""
                    _diff(res, header, before, after)
                current = cur.get(id_field)
                if (current or None) == (value or None):
                    device.pop(id_field)
        res.plan = {
            "hostname": hostname,
            "ip_address": ip,
            "platform": platform,
            "group_id": group_id,
            "vrf": vrf,
            "vlan": vlan,
            "device": device,
            "custom": custom,
        }

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        plan = res.plan or {}
        cur = res.existing or {}
        out = {
            "hostname": plan.get("hostname"),
            "ip_address": plan.get("ip_address"),
            "device_type": plan.get("platform"),
            "group_id": plan.get("group_id"),
            "vrf_name": plan["vrf"] if plan.get("vrf") is not None else cur.get("vrf_name", ""),
            "vlan_id": plan["vlan"] if plan.get("vlan") is not None else cur.get("vlan_id", ""),
        }
        for k in ("device_type_id", "role_id", "lifecycle_status_id", "site_id", "location_detail"):
            out[k] = (plan.get("device") or {}).get(k, cur.get(k))
        out["custom_fields"] = self.custom_values(plan.get("custom"), str(cur["id"]) if cur else None, ctx)
        return out

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        # An address from the file counts as confirmed only for an admin or
        # the API token (``managed_targets``); a sync job confirms nothing.
        confirmed = await caller_confirms_addresses()
        # Who set the address: the acting user (a scheduled sync job: nobody).
        writer = await address_writer_id()
        if cur is None:
            host_id = await db.add_host(
                plan["group_id"],
                plan["hostname"],
                plan["ip_address"],
                plan["platform"],
                vrf_name=plan["vrf"] or "",
                vlan_id=plan["vlan"] or "",
                address_confirmed=confirmed,
                address_set_by=writer,
            )
            prior_ip = ""
        else:
            host_id = int(cur["id"])
            prior_ip = str(cur.get("ip_address") or "")
            basic = ("Hostname", "IP Address", "Platform", "VRF", "VLAN")
            if any(h in res.changes for h in basic):
                await db.update_host(
                    host_id,
                    plan["hostname"],
                    plan["ip_address"],
                    plan["platform"],
                    vrf_name=plan["vrf"],
                    vlan_id=plan["vlan"],
                    address_confirmed=confirmed,
                    address_set_by=writer,
                )
            if plan["group_id"] != cur.get("group_id"):
                await db.move_hosts([host_id], int(plan["group_id"]))
        if plan["device"]:
            await db.set_host_device_fields(host_id, plan["device"], lock=True)
        await self.apply_custom(ctx, str(host_id), plan["custom"])

        async def follow_up() -> None:
            from netcontrol.routes.inventory import after_host_write

            await after_host_write(
                host_id, plan["hostname"], plan["ip_address"], created=cur is None, prior_ip=prior_ip
            )

        ctx.after_commit.append(follow_up)


# ── Groups ───────────────────────────────────────────────────────────────────

_GROUP_SEPARATOR = " / "


class GroupAdapter(Adapter):
    name = "groups"
    object_type = "group"
    label = "group"
    columns = (
        Column("Name", "name", required=True),
        Column("Parent", "parent", ("parent_path",)),
        Column("Description", "description"),
        Column("Tags", "tags"),
    )
    match_keys = ("path",)
    custom_type = "group"

    async def load(self, ctx: ImportContext) -> None:
        await self.load_custom(ctx)
        groups = await db.get_all_groups()
        ctx.data["group_by_path"] = {g["path"]: g for g in groups}
        ctx.data["planned"] = set()
        ctx.data["group_ids"] = {g["path"]: int(g["id"]) for g in groups}

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        name = _first(values, "name")
        if not name:
            return None, []
        parent = _first(values, "parent")
        path = f"{parent}{_GROUP_SEPARATOR}{name}" if parent else name
        group = ctx.data["group_by_path"].get(path)
        return path, [group] if group is not None and ctx.scope.can_read_group(group["id"]) else []

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        name = _first(values, "name")
        parent = _first(values, "parent")
        if len(name) > GROUP_NAME_MAX:
            res.error("name", f"Name must be at most {GROUP_NAME_MAX} characters.")
        description = _first(values, "description") if "description" in given else None
        if description is not None and len(description) > TEXT_MAX:
            res.error("description", f"Description must be at most {TEXT_MAX} characters.")
        if cur is not None:
            if not ctx.scope.can_write_group(cur["id"]):
                res.error("name", READ_ONLY_DETAIL)
                return
            if description is not None:
                _diff(res, "Description", cur.get("description") or "", description)
        else:
            if _GROUP_SEPARATOR.strip() in name:
                res.error("name", f"A group name cannot contain {_GROUP_SEPARATOR.strip()!r}; use the Parent column.")
            if not parent:
                if ctx.scope.restricted:
                    res.error("parent", "Only accounts with access to all devices can place a group at the top level")
            elif parent not in ctx.data["planned"]:
                group = ctx.data["group_by_path"].get(parent)
                if group is None or not ctx.scope.can_read_group(group["id"]):
                    res.error("parent", f"No group {parent!r} (and no earlier row creates it).")
                elif not ctx.scope.can_write_group(group["id"]):
                    res.error("parent", READ_ONLY_DETAIL)
        custom = self.plan_custom(ctx, values, given, str(cur["id"]) if cur else None, res)
        path = res.key
        if cur is None and not res.errors:
            ctx.data["planned"].add(path)
        res.plan = {"name": name, "parent": parent, "path": path, "description": description, "custom": custom}

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        plan = res.plan or {}
        cur = res.existing or {}
        desc = plan.get("description")
        return {
            "name": plan.get("name"),
            "parent_path": plan.get("parent"),
            "description": desc if desc is not None else cur.get("description", ""),
            "custom_fields": self.custom_values(plan.get("custom"), str(cur["id"]) if cur else None, ctx),
        }

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        if cur is None:
            parent_id = ctx.data["group_ids"][plan["parent"]] if plan["parent"] else None
            group_id = int(await db.create_group(plan["name"], plan["description"] or "", parent_id=parent_id))
            ctx.data["group_ids"][plan["path"]] = group_id
        else:
            group_id = int(cur["id"])
            if "Description" in res.changes:
                await db.update_group(group_id, cur["name"], plan["description"] or "")
        await self.apply_custom(ctx, str(group_id), plan["custom"])


# ── IPAM prefixes ────────────────────────────────────────────────────────────


def _resolve_vrf(ctx: ImportContext, values: dict[str, Any], res: RowResult) -> str:
    vrf = _first(values, "vrf")
    if not vrf:
        return ""
    record = ctx.data["vrfs"].get(vrf.lower())
    if record is None:
        res.error("vrf", f"No VRF {vrf!r}.")
        return vrf
    return str(record["name"])


def _clean(res: RowResult, column: str, fn: Callable[[Any], Any], raw: Any) -> Any:
    try:
        return fn(raw)
    except CustomFieldError as exc:
        res.error(column, str(exc))
        return raw


class PrefixAdapter(Adapter):
    name = "prefixes"
    object_type = "prefix"
    label = "prefix"
    columns = (
        Column("Prefix", "prefix", ("subnet", "cidr", "network"), required=True),
        Column("VRF", "vrf", ("vrf_name",)),
        Column("Description", "description"),
        Column("Site", "site"),
        Column("VLAN", "vlan", ("vlan_id",)),
        Column("Tags", "tags"),
    )
    match_keys = ("prefix",)
    custom_type = "prefix"

    async def load(self, ctx: ImportContext) -> None:
        await self.load_custom(ctx)
        source = await db.get_or_create_builtin_ipam_source()
        ctx.data["source_id"] = int(source["id"])
        records = await db.list_ipam_prefix_records()
        mine = [r for r in records if int(r["source_id"]) == ctx.data["source_id"]]
        ctx.data["prefixes"] = {(r["subnet"], r["vrf"] or ""): r for r in mine}
        ctx.data["subnet_vrf"] = {r["subnet"]: r["vrf"] or "" for r in mine}
        ctx.data["vrfs"] = _lookup(await db.list_vrfs())
        ctx.data["sites"] = _lookup(await db.list_geo_sites())
        ctx.data["vlans"] = await db.list_vlans()

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        text = _first(values, "prefix")
        if not text:
            return None, []
        try:
            subnet = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return text, []
        vrf = _first(values, "vrf")
        record = ctx.data["vrfs"].get(vrf.lower())
        vrf = str(record["name"]) if record else vrf
        found = ctx.data["prefixes"].get((subnet, vrf))
        return f"{subnet} (VRF {vrf})" if vrf else subnet, [found] if found else []

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        text = _first(values, "prefix")
        try:
            subnet = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            res.error("prefix", f"{text!r} is not a network such as 192.0.2.0/24.")
            return
        if subnet != text:
            res.warnings.append(f"Stored as {subnet}.")
        vrf = _resolve_vrf(ctx, values, res)
        if cur is None:
            other = ctx.data["subnet_vrf"].get(subnet)
            if other is not None and other != vrf:
                res.error(
                    "prefix",
                    f"The built-in IPAM source defines {subnet} already (VRF {other or 'global'}); "
                    "a subnet is defined there once.",
                )
        description = _clean(res, "description", clean_description, _first(values, "description"))
        site = ""
        if "site" in given and _first(values, "site"):
            record = ctx.data["sites"].get(_first(values, "site").lower())
            if record is None:
                res.error("site", f"No site {_first(values, 'site')!r}.")
            else:
                site = str(record["name"])
        vlan = ""
        if "vlan" in given and _first(values, "vlan"):
            vlan = _first(values, "vlan")
            at = site.lower()
            ok = vlan.isdigit() and any(
                int(v["vid"]) == int(vlan) and (v["site"] is None or not at or v["site"]["name"].lower() == at)
                for v in ctx.data["vlans"]
            )
            if not ok:
                res.error("vlan", f"No VLAN {vlan!r}{' at ' + site if site else ''}.")
        custom = self.plan_custom(ctx, values, given, db.prefix_key(subnet, vrf), res)
        plan: dict[str, Any] = {"subnet": subnet, "vrf": vrf, "custom": custom, "key": db.prefix_key(subnet, vrf)}
        if cur is None:
            plan.update(description=description, site=site, vlan=vlan)
        else:
            for column, header, value in (
                ("description", "Description", description),
                ("site", "Site", site),
                ("vlan", "VLAN", vlan),
            ):
                if column in given:
                    _diff(res, header, cur.get(column) or "", value)
                    plan[column] = value
                else:
                    plan[column] = None
        res.plan = plan

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        plan = res.plan or {}
        cur = res.existing or {}
        out = {"subnet": plan.get("subnet"), "vrf": plan.get("vrf")}
        for k in ("description", "site", "vlan"):
            out[k] = plan[k] if plan.get(k) is not None else cur.get(k, "")
        out["custom_fields"] = self.custom_values(plan.get("custom"), plan.get("key"), ctx)
        return out

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        if cur is None:
            created = await db.create_ipam_prefix(
                source_id=ctx.data["source_id"], subnet=plan["subnet"], description=plan["description"], vrf=plan["vrf"]
            )
            if not created:
                raise RuntimeError(f"Prefix {plan['subnet']} was not created")
            if plan["site"] or plan["vlan"]:
                await db.update_ipam_prefix(int(created["id"]), site=plan["site"], vlan=plan["vlan"])
        elif any(h in res.changes for h in ("Description", "Site", "VLAN")):
            await db.update_ipam_prefix(
                int(cur["id"]), description=plan["description"], site=plan["site"], vlan=plan["vlan"]
            )
        await self.apply_custom(ctx, plan["key"], plan["custom"])


# ── IP addresses ─────────────────────────────────────────────────────────────


class AddressAdapter(Adapter):
    name = "addresses"
    object_type = "ip_address"
    label = "IP address"
    columns = (
        Column("Address", "address", ("ip_address", "ip"), required=True),
        Column("Prefix", "prefix", ("subnet", "prefix_subnet")),
        Column("VRF", "vrf", ("vrf_name",)),
        Column("DNS Name", "dns_name", ("hostname",)),
        Column("Description", "description"),
    )
    match_keys = ("address",)

    async def load(self, ctx: ImportContext) -> None:
        source = await db.get_or_create_builtin_ipam_source()
        ctx.data["source_id"] = int(source["id"])
        allocations = await db.list_ipam_allocation_records()
        ctx.data["allocations"] = {
            _canonical_ip(str(a["address"])): a for a in allocations if int(a["source_id"]) == ctx.data["source_id"]
        }
        prefixes = []
        for r in await db.list_ipam_prefix_records():
            try:
                prefixes.append((ipaddress.ip_network(r["subnet"], strict=False), r["vrf"] or ""))
            except ValueError:
                continue
        ctx.data["prefixes"] = prefixes
        ctx.data["vrfs"] = _lookup(await db.list_vrfs())

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        text = _first(values, "address")
        if not text:
            return None, []
        found = ctx.data["allocations"].get(_canonical_ip(text))
        return _canonical_ip(text), [found] if found else []

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        text = _first(values, "address")
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            res.error("address", f"{text!r} is not an IP address.")
            return
        vrf = _resolve_vrf(ctx, values, res) if "vrf" in given or cur is None else str(cur.get("vrf_name") or "")
        prefix_text = _first(values, "prefix")
        subnet: str | None = None
        if prefix_text:
            try:
                net = ipaddress.ip_network(prefix_text, strict=False)
            except ValueError:
                res.error("prefix", f"{prefix_text!r} is not a network such as 192.0.2.0/24.")
                net = None
            if net is not None:
                if address.version != net.version or address not in net:
                    res.error("prefix", f"{address} is not in {net}.")
                elif (net, vrf) not in ctx.data["prefixes"]:
                    res.error("prefix", f"No IPAM prefix {net}{' in VRF ' + vrf if vrf else ''}.")
                subnet = str(net)
        elif cur is None or "vrf" in given:
            inside = [n for n, v in ctx.data["prefixes"] if v == vrf and n.version == address.version and address in n]
            if not inside:
                res.error(
                    "prefix", f"No IPAM prefix{' in VRF ' + vrf if vrf else ''} contains {address}: add one first."
                )
            else:
                subnet = str(max(inside, key=lambda n: n.prefixlen))
        dns_name = _first(values, "dns_name")
        if len(dns_name) > DNS_NAME_MAX:
            res.error("dns_name", f"DNS name must be at most {DNS_NAME_MAX} characters.")
        description = _clean(res, "description", clean_description, _first(values, "description"))
        plan: dict[str, Any] = {"address": str(address), "vrf": vrf, "prefix": subnet}
        if cur is None:
            plan.update(dns_name=dns_name, description=description)
        else:
            _diff(
                res,
                "Prefix",
                cur.get("prefix_subnet") or "",
                subnet if subnet is not None else cur.get("prefix_subnet"),
            )
            _diff(res, "VRF", cur.get("vrf_name") or "", vrf)
            for column, header, value in (
                ("dns_name", "DNS Name", dns_name),
                ("description", "Description", description),
            ):
                if column in given:
                    _diff(res, header, cur.get(column) or "", value)
                    plan[column] = value
                else:
                    plan[column] = None
        res.plan = plan

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        plan = res.plan or {}
        cur = res.existing or {}
        return {
            "address": plan.get("address"),
            "prefix_subnet": plan.get("prefix") or cur.get("prefix_subnet", ""),
            "vrf_name": plan.get("vrf"),
            "dns_name": plan["dns_name"] if plan.get("dns_name") is not None else cur.get("dns_name", ""),
            "description": plan["description"] if plan.get("description") is not None else cur.get("description", ""),
        }

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        if cur is None:
            created = await db.create_local_ipam_allocation(
                source_id=ctx.data["source_id"],
                subnet=plan["prefix"],
                address=plan["address"],
                hostname=plan["dns_name"],
                description=plan["description"],
                created_by=ctx.user,
                vrf_name=plan["vrf"],
            )
            if not created:
                raise RuntimeError(f"Address {plan['address']} was not created")
        elif res.changes:
            await db.update_ipam_allocation(
                int(cur["id"]),
                dns_name=plan["dns_name"],
                description=plan["description"],
                prefix_subnet=plan["prefix"],
                vrf_name=plan["vrf"],
            )


# ── VLANs ────────────────────────────────────────────────────────────────────


class VlanAdapter(Adapter):
    name = "vlans"
    object_type = "vlan"
    label = "VLAN"
    columns = (
        Column("VLAN ID", "vid", ("vlan_id", "vlan"), required=True),
        Column("Name", "name"),
        Column("Site", "site"),
        Column("Description", "description"),
    )
    match_keys = ("vid",)

    async def load(self, ctx: ImportContext) -> None:
        ctx.data["vlans"] = {(int(v["vid"]), v["site_id"]): v for v in await db.list_vlans()}
        ctx.data["sites"] = _lookup(await db.list_geo_sites())

    def _site(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[int | None, str]:
        text = _first(values, "site")
        record = ctx.data["sites"].get(text.lower()) if text else None
        return (int(record["id"]) if record else None), text

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        text = _first(values, "vid")
        if not text:
            return None, []
        site_id, site_text = self._site(ctx, values)
        record = ctx.data["sites"].get(site_text.lower()) if site_text else None
        key = f"{text} ({record['name'] if record else site_text})" if site_text else text
        if not text.isdigit():
            return key, []
        found = ctx.data["vlans"].get((int(text), site_id))
        return key, [found] if found and (site_id is not None or not site_text) else []

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        text = _first(values, "vid")
        vid = _clean(res, "vid", clean_vid, int(text) if text.isdigit() else text)
        site_id, site_text = self._site(ctx, values)
        if site_text and site_id is None:
            res.error("site", f"No site {site_text!r}.")
        name = _clean(res, "name", clean_vlan_name, _first(values, "name"))
        description = _clean(res, "description", clean_description, _first(values, "description"))
        plan: dict[str, Any] = {"vid": vid, "site_id": site_id, "name": name, "description": description}
        if cur is not None:
            if "name" in given:
                _diff(res, "Name", cur.get("name") or "", name)
            else:
                plan["name"] = cur.get("name") or ""
            if "description" in given:
                _diff(res, "Description", cur.get("description") or "", description)
            else:
                plan["description"] = cur.get("description") or ""
        res.plan = plan

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        return dict(res.plan or {})

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        if cur is None:
            await db.create_vlan(
                vid=plan["vid"], name=plan["name"], site_id=plan["site_id"], description=plan["description"]
            )
        elif res.changes:
            await db.update_vlan(
                int(cur["id"]), name=plan["name"], site_id=cur["site_id"], description=plan["description"]
            )


# ── VRFs ─────────────────────────────────────────────────────────────────────


class VrfAdapter(Adapter):
    name = "vrfs"
    object_type = "vrf"
    label = "VRF"
    columns = (
        Column("Name", "name", ("vrf", "vrf_name"), required=True),
        Column("RD", "rd", ("route_distinguisher",)),
        Column("Description", "description"),
    )
    match_keys = ("name",)

    async def load(self, ctx: ImportContext) -> None:
        ctx.data["vrfs"] = _lookup(await db.list_vrfs())

    def match(self, ctx: ImportContext, values: dict[str, Any]) -> tuple[Any, list[dict]]:
        name = _first(values, "name")
        if not name:
            return None, []
        found = ctx.data["vrfs"].get(name.lower())
        return name, [found] if found else []

    async def build(self, ctx: ImportContext, values: dict[str, Any], given: set[str], res: RowResult) -> None:
        cur = res.existing
        name = _clean(res, "name", clean_vrf_name, _first(values, "name"))
        rd = _clean(res, "rd", clean_rd, _first(values, "rd"))
        description = _clean(res, "description", clean_description, _first(values, "description"))
        plan = {"name": name, "rd": rd, "description": description}
        if cur is not None:
            for column, header in (("rd", "RD"), ("description", "Description")):
                if column in given:
                    _diff(res, header, cur.get(column) or "", plan[column])
                else:
                    plan[column] = cur.get(column) or ""
        res.plan = plan

    def desired(self, ctx: ImportContext, res: RowResult) -> dict[str, Any]:
        return dict(res.plan or {})

    async def apply(self, ctx: ImportContext, res: RowResult) -> None:
        plan = res.plan
        assert plan is not None  # nosec B101 - only planned rows are applied
        cur = res.existing
        if cur is None:
            await db.create_vrf(name=plan["name"], rd=plan["rd"], description=plan["description"])
        elif res.changes:
            await db.update_vrf(int(cur["id"]), rd=plan["rd"], description=plan["description"])


ADAPTERS: dict[str, Adapter] = {
    a.name: a for a in (HostAdapter(), GroupAdapter(), PrefixAdapter(), AddressAdapter(), VlanAdapter(), VrfAdapter())
}
INVENTORY_TYPES: tuple[str, ...] = ("hosts", "groups")
IPAM_TYPES: tuple[str, ...] = ("prefixes", "addresses", "vlans", "vrfs")


def adapter_for(object_type: str) -> Adapter:
    adapter = ADAPTERS.get(object_type)
    if adapter is None:
        raise BulkImportError(f"Object type must be one of: {', '.join(ADAPTERS)}.")
    return adapter


async def template_header(object_type: str) -> list[str]:
    """The CSV header of an empty import file for ``object_type`` (for hosts,
    the export's header, so an export imports as it is)."""
    adapter = adapter_for(object_type)
    fields = await db.list_custom_fields(adapter.custom_type) if adapter.custom_type else []
    return adapter.template_header(fields)


# ── Planning ─────────────────────────────────────────────────────────────────


@dataclass
class ImportReport:
    object_type: str
    format: str
    mode: str
    match_key: str
    rows: list[RowResult]
    columns: list[str]
    ignored_columns: list[dict]
    new_tags: list[str]
    committed: bool = False
    applied: int = 0
    message: str = ""

    def summary(self) -> dict[str, int]:
        counts = {a: 0 for a in ACTIONS}
        for r in self.rows:
            counts[r.action] += 1
        return {**counts, "total": len(self.rows)}

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.rows if r.action == "error")

    def as_dict(self) -> dict:
        return {
            "object_type": self.object_type,
            "format": self.format,
            "mode": self.mode,
            "match_key": self.match_key,
            "columns": self.columns,
            "ignored_columns": self.ignored_columns,
            "new_tags": self.new_tags,
            "summary": self.summary(),
            "rows": [r.as_dict() for r in self.rows],
            "committed": self.committed,
            "applied": self.applied,
            "message": self.message,
        }


def _column_map(adapter: Adapter, ctx: ImportContext) -> dict[str, tuple[str, str]]:
    """Column key -> (kind, standard key): ``std`` or ``readonly``; custom
    field columns are ``cf``."""
    out: dict[str, tuple[str, str]] = {}
    extra: tuple[Column, ...] = getattr(adapter, "extra_columns", ())
    for col in (*adapter.columns, *extra):
        kind = "readonly" if col.readonly else "std"
        for key in (col.key, column_key(col.header), *col.aliases):
            out.setdefault(key, (kind, col.key))
    for key in adapter.custom_columns(ctx):
        out.setdefault(key, ("cf", key))
    if adapter.custom_type is not None:
        out.setdefault("custom_fields", ("std", "custom_fields"))
    return out


def _normalise(
    adapter: Adapter, ctx: ImportContext, rec: Record, cmap: dict[str, tuple[str, str]], ignored: dict[str, str]
) -> tuple[dict[str, Any], set[str]]:
    values: dict[str, Any] = {}
    for key, value in rec.values.items():
        kind, std = cmap.get(key, ("", ""))
        if any(word in key for word in _SECRET_WORDS) and kind != "cf":
            ignored.setdefault(key, "Secrets cannot be imported.")
            continue
        if not kind:
            ignored.setdefault(key, f"Not a column of {adapter.label}s.")
            continue
        if kind == "readonly":
            ignored.setdefault(key, "Read from the device; not imported.")
            continue
        if std in values:
            rec.problems.append({"field": std, "message": f"The column {std} is given twice."})
            continue
        values[std] = value
    return values, set(values)


async def plan_import(
    object_type: str,
    text: str,
    fmt: str,
    *,
    mode: str,
    match_key: str,
    scope: ObjectScope,
    user: str,
) -> tuple[ImportReport, Adapter, ImportContext]:
    """Parse and check an import without writing anything."""
    adapter = adapter_for(object_type)
    if mode not in MODES:
        raise BulkImportError(f"Mode must be one of: {', '.join(MODES)}.")
    match_key = match_key or adapter.match_keys[0]
    if match_key not in adapter.match_keys:
        raise BulkImportError(f"Match key for {adapter.name} must be one of: {', '.join(adapter.match_keys)}.")
    records = parse_records(text, fmt)
    ctx = ImportContext(scope=scope, user=user, mode=mode, match_key=match_key)
    await adapter.load(ctx)
    cmap = _column_map(adapter, ctx)
    ignored: dict[str, str] = {}
    results: list[RowResult] = []
    for rec in records:
        values, given = _normalise(adapter, ctx, rec, cmap, ignored)
        res = RowResult(row=rec.row)
        results.append(res)
        for problem in rec.problems:
            res.error(problem["field"], problem["message"])
        key, found = adapter.match(ctx, values)
        res.key = str(key) if key is not None else ""
        if key is None:
            res.error(column_key(match_key), f"The {match_key} column is needed to match the row.")
            continue
        dedupe = ("key", key.lower() if isinstance(key, str) else key)
        if dedupe in ctx.seen:
            res.error(column_key(match_key), f"Row {ctx.seen[dedupe]} has the same {match_key}.")
            continue
        ctx.seen[dedupe] = rec.row
        if len(found) > 1:
            res.error(column_key(match_key), f"Matches {len(found)} {adapter.label}s; match on another key.")
            continue
        res.existing = found[0] if found else None
        if res.existing is not None and mode == "create":
            res.action = "skip"
            res.warnings.append(f"The {adapter.label} exists; create mode leaves it alone.")
            continue
        if res.existing is None and mode == "update":
            res.error(column_key(match_key), f"No existing {adapter.label} matches.")
            continue
        if not res.errors:
            await adapter.build(ctx, values, given, res)
        if not res.errors and res.plan is not None:
            desired = adapter.desired(ctx, res)
            for item in await _extra_row_errors(adapter.object_type, desired, res.existing):
                res.error(str(item.get("field", "")), str(item.get("message", "")))
        if res.errors:
            res.action = "error"
        elif res.existing is None:
            res.action = "create"
        elif res.changes:
            res.action = "update"
        else:
            res.action = "skip"
            res.warnings.append("No changes.")
    used = sorted({cmap[k][1] for rec in records for k in rec.values if cmap.get(k, ("", ""))[0] in ("std", "cf")})
    report = ImportReport(
        object_type=adapter.name,
        format=fmt,
        mode=mode,
        match_key=match_key,
        rows=results,
        columns=used,
        ignored_columns=[{"column": k, "reason": v} for k, v in sorted(ignored.items())],
        new_tags=sorted({t for r in results if r.action in ("create", "update") for t in r.new_tags}, key=str.lower),
    )
    return report, adapter, ctx


# ── Commit ───────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _transaction() -> AsyncIterator[None]:
    """One database transaction around every facade write in this task.

    The facade's connection is re-entrant per task: every helper called
    inside reuses the connection held here, and its own ``commit()`` ends a
    savepoint of this transaction rather than the transaction itself
    (asyncpg nests a transaction started inside another as a savepoint). An
    exception rolls all of it back."""
    conn: Any = await db.get_db()
    raw = conn._conn  # the asyncpg connection under the facade's compat layer
    tx = raw.transaction()
    await tx.start()
    try:
        yield
    except BaseException:
        try:
            if conn._tx is not None:
                await conn.rollback()
        finally:
            await tx.rollback()
        raise
    else:
        if conn._tx is not None:
            await conn.commit()
        await tx.commit()
    finally:
        await conn.close()


async def commit_import(
    object_type: str,
    text: str,
    fmt: str,
    *,
    mode: str,
    match_key: str,
    scope: ObjectScope,
    user: str,
    atomic: bool = True,
    stop_at_error: bool = True,
) -> ImportReport:
    """Plan the import again and write it (see the module docstring). With
    ``atomic=False`` and ``stop_at_error=False`` every row is tried: rows
    with errors and failed writes are reported and the rest are written
    (the sync framework's per-object outcomes)."""
    report, adapter, ctx = await plan_import(
        object_type, text, fmt, mode=mode, match_key=match_key, scope=scope, user=user
    )
    todo = [r for r in report.rows if r.action in ("create", "update")]
    current: RowResult | None = None
    if atomic:
        if report.error_count:
            report.message = f"Nothing was imported: {report.error_count} row(s) have errors. Fix them and try again."
            return report
        try:
            async with _transaction():
                for res in todo:
                    current = res
                    await adapter.apply(ctx, res)
        except Exception as exc:
            ctx.after_commit.clear()
            where = "the import"
            if current is not None:
                current.action = "error"
                current.error("", f"The write failed: {type(exc).__name__}: {exc}")
                where = f"row {current.row}"
            report.message = f"Nothing was imported: {where} failed and every write was rolled back."
            return report
        report.applied = len(todo)
    else:
        for res in report.rows:
            if res.action == "error":
                if not stop_at_error:
                    continue
                report.message = (
                    f"Stopped at row {res.row}: it has errors. {report.applied} row(s) before it were imported."
                )
                break
            if res.action not in ("create", "update"):
                continue
            try:
                await adapter.apply(ctx, res)
            except Exception as exc:
                res.action = "error"
                res.error("", f"The write failed: {type(exc).__name__}: {exc}")
                if not stop_at_error:
                    continue
                report.message = (
                    f"Stopped at row {res.row}: the write failed. {report.applied} row(s) before it were imported."
                )
                break
            report.applied += 1
    report.committed = report.applied > 0 or not report.message
    if not report.message:
        report.message = f"Imported {report.applied} row(s)."
    for follow_up in ctx.after_commit:
        try:
            await follow_up()
        except Exception:  # nosec B112 - a follow-up never undoes a committed import
            continue
    return report
