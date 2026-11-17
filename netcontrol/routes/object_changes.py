"""The per-object change log: a persistent subscriber of the structured
object-change events (``routes.db.change_events``) and its read API.

Recorder: ``start_recorder`` registers ``on_object_change`` on the change
hook for every tracked type, so each create, update and delete of a host,
inventory group, prefix, IP address, VLAN, VRF, credential, config backup or
job lands in ``object_changes`` with the field-by-field diff, the before and
after snapshots (the event already drops credential secrets, config text and
job parameters; ``redact_value`` masks any other secret-looking key), the
acting user and the request's correlation id. Like every hook it is
fire-and-forget: a failed write is logged and never reaches the caller. A
maintenance loop prunes rows older than the change log retention
(``change_log_retention_days`` in the auth config, Settings > System).

API (``router``, registered behind ``require_auth``; see docs/change-log.md):

* ``GET /api/changes``: the log, newest first, filtered by ``object_type``,
  ``object_id``, ``object_label``, ``user``, ``action``, ``since``/``until``,
  paged with ``limit``/``offset``.
* ``GET /api/changes/{object_type}/{object_id}``: one object's history.

Access follows the REST routes of each type, not one feature: a caller sees
only the types whose feature they hold (hosts and groups: ``inventory``;
prefixes, IP addresses, VLANs and VRFs: ``ipam``; config backups:
``config-backups``; jobs: ``jobs``; clusters, their types and groups,
virtual machines and VM interfaces: ``virtualization``; regions, sites,
tenant groups and tenants: ``organization``; credentials, which belong to their
owners: admins only). A caller limited to selected inventory groups
(``netcontrol.object_scope``) sees only host, group and config backup changes
whose group is readable to them.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from routes.db.change_events import (
    CHANGE_ACTIONS,
    CHANGE_OBJECT_TYPES,
    add_object_change_hook,
    remove_object_change_hook,
)

import netcontrol.routes.state as state
from netcontrol.object_scope import request_scope, scoped
from netcontrol.routes.reporting import _parse_db_datetime_utc
from netcontrol.routes.shared import caller_features
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.object_changes")

router = APIRouter()

PRUNE_INTERVAL = 3600.0
MAX_LIMIT = 500

# The feature whose REST routes read each type. A type missing here
# (credential: per-owner records) is for admins and the API token only.
TYPE_FEATURES: dict[str, str] = {
    "host": "inventory",
    "group": "inventory",
    "prefix": "ipam",
    "ip_address": "ipam",
    "vlan": "ipam",
    "vrf": "ipam",
    "config_backup": "config-backups",
    "job": "jobs",
    "rack": "dcim",
    "rack_reservation": "dcim",
    "front_port": "dcim",
    "rear_port": "dcim",
    "module": "dcim",
    "power_panel": "dcim",
    "power_feed": "dcim",
    "power_port": "dcim",
    "power_outlet": "dcim",
    "cable": "dcim",
    "cluster_type": "virtualization",
    "cluster_group": "virtualization",
    "cluster": "virtualization",
    "virtual_machine": "virtualization",
    "vm_interface": "virtualization",
    "region": "organization",
    "site": "organization",
    "tenant_group": "organization",
    "tenant": "organization",
    "circuit_provider": "circuits",
    "provider_network": "circuits",
    "circuit_type": "circuits",
    "circuit": "circuits",
    "circuit_termination": "circuits",
    "autonomous_system": "routing",
    "routing_instance": "routing",
    "bgp_peer_group": "routing",
    "bgp_peering": "routing",
}
# Types whose rows carry the inventory group they belong to; the only ones a
# caller limited to selected groups may see.
SCOPED_TYPES: frozenset[str] = frozenset({"host", "group", "config_backup"})

# The snapshot field(s) that name an object, first non-empty wins.
_LABEL_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("hostname", "ip_address"),
    "cable": ("label", "id"),
    "module": ("bay",),
    "rack_reservation": ("description", "id"),
    "group": ("name",),
    "prefix": ("subnet",),
    "ip_address": ("address",),
    "vrf": ("name",),
    "credential": ("name",),
    "circuit": ("cid",),
    "circuit_termination": ("term_side",),
    "bgp_peering": ("remote_address",),
}

_prune_task: asyncio.Task | None = None


# ── Recorder ─────────────────────────────────────────────────────────────────


def retention_days() -> int:
    return state._effective_change_log_retention_days()


def _db_time(value: Any) -> str:
    parsed = _parse_db_datetime_utc(str(value or "")) or datetime.now(UTC)
    return parsed.strftime(db.OBJECT_CHANGE_TIME_FORMAT)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except TypeError, ValueError:
        return None


def object_label(object_type: str, snapshot: dict) -> str:
    """The display name of an object from its snapshot."""
    if object_type == "vlan":
        vid, name = snapshot.get("vid"), snapshot.get("name") or ""
        return f"{vid} {name}".strip() if vid is not None else str(name)
    if object_type == "autonomous_system" and snapshot.get("asn") is not None:
        return f"AS{snapshot['asn']}"
    for key in _LABEL_FIELDS.get(object_type, ("name",)):
        value = snapshot.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


async def _context(object_type: str, object_id: str, snapshot: dict) -> tuple[int | None, str]:
    """The inventory group an object belongs to (for object scope) and its label."""
    label = object_label(object_type, snapshot)
    if object_type == "host":
        return _int_or_none(snapshot.get("group_id")), label
    if object_type == "group":
        return _int_or_none(object_id), label
    if object_type == "config_backup":
        host_id = _int_or_none(snapshot.get("host_id"))
        host = await db.get_host(host_id) if host_id is not None else None
        if not host:
            return None, label or (f"host {host_id}" if host_id is not None else "")
        return _int_or_none(host.get("group_id")), str(host.get("hostname") or host.get("ip_address") or "")
    return None, label


async def on_object_change(event: dict) -> None:
    """The object-change hook: store the event as one change log row."""
    object_type = str(event.get("object_type") or "")
    object_id = str(event.get("object_id") or "")
    action = str(event.get("action") or "")
    if object_type not in CHANGE_OBJECT_TYPES or action not in CHANGE_ACTIONS or not object_id:
        return
    before = event.get("before")
    after = event.get("after")
    snapshot = after if isinstance(after, dict) else before if isinstance(before, dict) else {}
    scope_group_id, label = await _context(object_type, object_id, snapshot)
    await db.add_object_change(
        object_type=object_type,
        object_id=object_id,
        action=action,
        changed_at=_db_time(event.get("timestamp")),
        user=str(event.get("user") or ""),
        object_label=label,
        correlation_id=str(event.get("correlation_id") or ""),
        scope_group_id=scope_group_id,
        changes=redact_value(event.get("changes") or {}),
        before=redact_value(before) if isinstance(before, dict) else None,
        after=redact_value(after) if isinstance(after, dict) else None,
    )


async def prune_once() -> int:
    removed = await db.prune_object_changes(retention_days())
    if removed:
        LOGGER.info("change log: pruned %d rows older than %d days", removed, retention_days())
    return removed


async def _prune_loop() -> None:
    last = 0.0
    while True:
        try:
            if time.monotonic() - last >= PRUNE_INTERVAL:
                last = time.monotonic()
                await prune_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("change log: prune failed: %s", type(exc).__name__)
        await asyncio.sleep(60)


async def start_recorder() -> None:
    """Record every tracked change from now on, and prune hourly."""
    global _prune_task
    add_object_change_hook(on_object_change)
    if _prune_task is None or _prune_task.done():
        _prune_task = asyncio.create_task(_prune_loop(), name="object-change-prune")


async def stop_recorder() -> None:
    global _prune_task
    remove_object_change_hook(on_object_change)
    if _prune_task is not None:
        _prune_task.cancel()
        await asyncio.gather(_prune_task, return_exceptions=True)
        _prune_task = None


# ── Access ───────────────────────────────────────────────────────────────────


def readable_types(features: frozenset[str] | None) -> list[str]:
    """The tracked types a caller with ``features`` (``None``: every
    feature) may read the changes of."""
    if features is None:
        return list(CHANGE_OBJECT_TYPES)
    return [t for t in CHANGE_OBJECT_TYPES if TYPE_FEATURES.get(t) in features]


def _bound(value: str | None, name: str, *, end_of_day: bool = False) -> str | None:
    if value is None or not value.strip():
        return None
    parsed = _parse_db_datetime_utc(value)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"{name} must be an ISO 8601 date or date-time")
    if end_of_day and len(value.strip()) == 10:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed.strftime(db.OBJECT_CHANGE_TIME_FORMAT)


async def _list(
    request: Request,
    *,
    object_type: str | None,
    object_id: str | None,
    object_label: str | None,
    user: str | None,
    action: str | None,
    since: str | None,
    until: str | None,
    limit: int,
    offset: int,
) -> dict:
    if object_type is not None and object_type not in CHANGE_OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of {', '.join(CHANGE_OBJECT_TYPES)}")
    if action is not None and action not in CHANGE_ACTIONS:
        raise HTTPException(status_code=400, detail=f"action must be one of {', '.join(CHANGE_ACTIONS)}")
    types = readable_types(await caller_features(request))
    scope = await request_scope(request)
    group_ids = None
    if scope.restricted:
        types = [t for t in types if t in SCOPED_TYPES]
        group_ids = scope.read_groups
    if object_type is not None:
        if object_type not in types:
            raise HTTPException(status_code=403, detail=f"Access denied to {object_type} changes")
        types = [object_type]
    if not types:
        raise HTTPException(status_code=403, detail="Access denied to the change log")
    rows, total = await db.list_object_changes(
        object_types=types,
        object_id=object_id,
        object_label=object_label,
        user=user,
        action=action,
        since=_bound(since, "since"),
        until=_bound(until, "until", end_of_day=True),
        group_ids=group_ids,
        limit=limit,
        offset=offset,
    )
    return {"changes": rows, "total": total, "limit": limit, "offset": offset, "object_types": types}


@router.get("/api/changes")
@scoped("list")
async def list_changes(
    request: Request,
    object_type: str | None = Query(None),
    object_id: str | None = Query(None, max_length=64),
    object_label: str | None = Query(None, max_length=255),
    user: str | None = Query(None, max_length=255),
    action: str | None = Query(None),
    since: str | None = Query(None, max_length=40),
    until: str | None = Query(None, max_length=40),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
):
    return await _list(
        request,
        object_type=object_type,
        object_id=object_id,
        object_label=object_label,
        user=user,
        action=action,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/api/changes/{object_type}/{object_id}")
@scoped("list")
async def object_history(
    request: Request,
    object_type: str,
    object_id: str,
    user: str | None = Query(None, max_length=255),
    action: str | None = Query(None),
    since: str | None = Query(None, max_length=40),
    until: str | None = Query(None, max_length=40),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
):
    return await _list(
        request,
        object_type=object_type,
        object_id=object_id[:64],
        object_label=None,
        user=user,
        action=action,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
