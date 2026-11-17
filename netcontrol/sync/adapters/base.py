"""The adapter interface and the shared base of the REST adapters.

An adapter is one system. ``load`` reads the records of an object type into
canonical ``SyncRecord`` objects; ``apply`` writes the planned entries whose
target it is and sets each entry's outcome. ``fields`` says which fields the
adapter reads for a type and ``writable`` which of them it can write.

``RestAdapter`` holds what NetBox, Nautobot and ServiceNow share: the
resolved field mappings (dotted remote paths), reading a path out of a
remote record, building a request body from canonical values, and the
create / update / delete loop with per-entry outcomes. A subclass gives the
default endpoints and paths and the four HTTP calls.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from netcontrol.sync.engine import Entry
from netcontrol.sync.models import (
    MappingError,
    SyncRecord,
    TypeMapping,
    make_record,
    resolve_mapping,
    spec_for,
)
from netcontrol.sync.transport import HttpJsonClient, SyncError

# Most records read of one type; a bigger set is refused rather than
# silently cut (the diff would read the rest as missing).
MAX_RECORDS_PER_TYPE = 50_000
PAGE_SIZE = 500

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """NetBox-style slug: lower case, runs of other characters to ``-``."""
    return _SLUG_STRIP.sub("-", text.lower()).strip("-")[:100] or "item"


def get_path(raw: dict, path: str) -> Any:
    """The value at a dotted ``path`` of a remote record (``None`` when a
    step is missing or not an object)."""
    current: Any = raw
    for step in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(step)
    return current


def set_path(body: dict, path: str, value: Any) -> None:
    """Write ``value`` at a dotted ``path``: ``site.name`` -> ``{"site":
    {"name": value}}`` (a nested lookup), or ``{"site": None}`` for an empty
    value (clears the reference)."""
    steps = path.split(".")
    if len(steps) == 1:
        body[path] = value
        return
    if value in ("", None):
        body[steps[0]] = None
        return
    current = body
    for step in steps[:-1]:
        nxt = current.get(step)
        if not isinstance(nxt, dict):
            nxt = {}
            current[step] = nxt
        current = nxt
    current[steps[-1]] = value


class SyncAdapter(ABC):
    """One system taking part in a sync."""

    name = ""
    label = ""

    async def __aenter__(self) -> SyncAdapter:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    @abstractmethod
    def supports(self, object_type: str) -> bool: ...

    @abstractmethod
    def fields(self, object_type: str) -> tuple[str, ...]:
        """The fields this adapter reads for the type."""

    @abstractmethod
    def writable(self, object_type: str) -> set[str]:
        """The fields this adapter can write for the type."""

    @abstractmethod
    async def load(self, object_type: str) -> list[SyncRecord]: ...

    @abstractmethod
    async def apply(self, object_type: str, entries: list[Entry]) -> None:
        """Write ``entries`` (all of this type and target) and set each
        one's outcome."""


class RestAdapter(SyncAdapter):
    """Shared base of the REST adapters. Subclasses set ``DEFAULTS``
    (``{object_type: {"endpoint": ..., "paths": {field: path},
    "read_only": {field, ...}, "create_defaults": {...}}}``) and implement
    ``list_raw``, ``create_raw``, ``update_raw``, ``delete_raw`` and
    ``ref_of``."""

    DEFAULTS: dict[str, dict[str, Any]] = {}

    def __init__(self, client: HttpJsonClient, mappings: dict[str, dict[str, Any]] | None = None) -> None:
        self.client = client
        self.mappings = mappings or {}
        self._resolved: dict[str, TypeMapping] = {}

    async def __aenter__(self) -> RestAdapter:
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.client.__aexit__(*exc)

    # ── Mapping ──

    def supports(self, object_type: str) -> bool:
        if object_type in self.DEFAULTS:
            return True
        return bool((self.mappings.get(object_type) or {}).get("_endpoint"))

    def mapping(self, object_type: str) -> TypeMapping:
        if object_type not in self._resolved:
            defaults = self.DEFAULTS.get(object_type, {})
            self._resolved[object_type] = resolve_mapping(
                object_type, dict(defaults.get("paths", {})), self.mappings.get(object_type)
            )
        return self._resolved[object_type]

    def endpoint(self, object_type: str) -> str:
        mapping = self.mapping(object_type)
        endpoint = str(mapping.options.get("endpoint") or self.DEFAULTS.get(object_type, {}).get("endpoint") or "")
        if not endpoint:
            raise MappingError(f"{self.label} has no default endpoint for {object_type}; set _endpoint in the mapping.")
        if "://" in endpoint or ".." in endpoint:
            raise MappingError(f"The {object_type} endpoint must be a path of the connection, not a URL.")
        return endpoint.strip("/")

    def fields(self, object_type: str) -> tuple[str, ...]:
        return self.mapping(object_type).fields

    def writable(self, object_type: str) -> set[str]:
        read_only = set(self.DEFAULTS.get(object_type, {}).get("read_only", ()))
        mapping = self.mapping(object_type)
        defaults = self.DEFAULTS.get(object_type, {}).get("paths", {})
        # A field re-pointed by the job is writable at its new path.
        return {
            f
            for f in mapping.fields
            if mapping.paths[f] and (f not in read_only or mapping.paths[f] != defaults.get(f))
        }

    def create_defaults(self, object_type: str) -> dict[str, Any]:
        mapping = self.mapping(object_type)
        given = mapping.options.get("create_defaults")
        base = dict(self.DEFAULTS.get(object_type, {}).get("create_defaults", {}))
        if isinstance(given, dict):
            base.update(given)
        return base

    # ── Reading ──

    def read_value(self, object_type: str, name: str, raw: dict, path: str) -> Any:
        """The canonical value of field ``name`` out of a remote record
        (a nested object reads its ``name``, ``value`` or ``display``;
        an empty path, a key field the system does not hold, reads "")."""
        if not path:
            return ""
        value = get_path(raw, path)
        if isinstance(value, dict):
            for key in ("name", "value", "display_value", "display"):
                if value.get(key) not in (None, ""):
                    return value[key]
            return ""
        if isinstance(value, list):
            return ""
        return value

    def to_record(self, object_type: str, raw: dict) -> SyncRecord:
        mapping = self.mapping(object_type)
        values = {name: self.read_value(object_type, name, raw, path) for name, path in mapping.paths.items()}
        return make_record(object_type, values, self.ref_of(raw), mapping.fields)

    async def load(self, object_type: str) -> list[SyncRecord]:
        rows = await self.list_raw(object_type)
        return [self.to_record(object_type, raw) for raw in rows]

    # ── Writing ──

    def write_value(self, object_type: str, name: str, value: str, values: dict[str, str]) -> Any:
        """The remote value of a canonical value (hook for subclasses)."""
        return value

    def build_body(self, object_type: str, values: dict[str, str], *, create: bool) -> dict[str, Any]:
        """The request body of a create (every value, the create defaults
        under them) or an update (the changed values; key fields are the
        same on both sides and are not sent)."""
        mapping = self.mapping(object_type)
        key = {k for k in spec_for(object_type).key if mapping.paths.get(k)}
        writable = self.writable(object_type) | key
        body: dict[str, Any] = dict(self.create_defaults(object_type)) if create else {}
        for name, value in values.items():
            if not mapping.paths.get(name) or name not in writable or (not create and name in key):
                continue
            path = self.write_path(mapping.paths[name])
            set_path(body, path, self.write_value(object_type, name, value, values))
        return body

    def write_path(self, path: str) -> str:
        """Where a read path is written (hook: NetBox reads a choice at
        ``status.value`` and writes it at ``status``)."""
        return path

    async def apply(self, object_type: str, entries: list[Entry]) -> None:
        for entry in entries:
            try:
                if entry.action == "create":
                    await self.create_raw(object_type, self.build_body(object_type, entry.values, create=True))
                elif entry.action == "update":
                    await self.update_raw(
                        object_type, entry.ref, self.build_body(object_type, entry.values, create=False)
                    )
                elif entry.action == "delete":
                    await self.delete_raw(object_type, entry.ref)
                else:
                    continue
            except (SyncError, MappingError) as exc:
                entry.failed(str(exc))
                continue
            entry.applied()

    # ── Calls ──

    @abstractmethod
    def ref_of(self, raw: dict) -> Any: ...

    @abstractmethod
    async def list_raw(self, object_type: str) -> list[dict]: ...

    @abstractmethod
    async def create_raw(self, object_type: str, body: dict) -> None: ...

    @abstractmethod
    async def update_raw(self, object_type: str, ref: Any, body: dict) -> None: ...

    @abstractmethod
    async def delete_raw(self, object_type: str, ref: Any) -> None: ...
