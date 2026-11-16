"""
opnsense_rules.py -- The filter rule views of an OPNsense firewall.

Read from the ``config.xml`` the OPNsense collection stores as the config
backup of the firewall's inventory host; the firewall itself is never
contacted here.

  - ``GET /api/opnsense/hosts/{host_id}/rules``: the rules of the host's
    newest successful backup in evaluation order, with their aliases
    resolved and their flags (any-any, shadowed, disabled, missing alias,
    unused), the aliases and the NAT rules
    (``netcontrol.integrations.opnsense.rules.analyze``). The rule
    counters come from the newest collection of the OPNsense source that
    is this host (``rule_stats`` of its snapshot, see
    ``opnsense_collection.attach_rule_stats``). A host without a backup, or
    whose backup is no ``config.xml``, gets an empty view with
    ``available`` false and a ``message``.
  - ``GET /api/opnsense/hosts/{host_id}/rules/diff?from_backup=&to_backup=``:
    the rules, aliases and NAT that changed between two backups of the host
    (``rules.diff``); without the two ids, between the newest backup and
    the one before it (``available`` false when there are not two).

Registered with Config Backups access (the rules are read from its
backups) and checks the caller's inventory group scope on the host. Only
parsed rules, aliases and NAT are returned: never the backup's text, which
holds password hashes and keys.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request

from netcontrol.integrations.opnsense.rules import analyze, diff
from netcontrol.integrations.pathtrace.opnsense_config import OpnsenseConfig, parse_document
from netcontrol.object_scope import require_host, scoped
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

router = APIRouter()

PROVIDER = "opnsense"
NO_BACKUP = "No configuration backup of this host yet: collect its OPNsense source with configuration backups enabled"
NOT_OPNSENSE = "The backup is not an OPNsense config.xml"
BACKUP_NOT_FOUND = "Backup not found"
TOO_FEW_BACKUPS = "A comparison needs two configuration backups of this host"


def _backup_meta(backup: dict) -> dict[str, Any]:
    return {
        "id": backup["id"],
        "captured_at": backup.get("captured_at"),
        "capture_method": backup.get("capture_method"),
    }


def _parse(backup: dict) -> OpnsenseConfig:
    config = parse_document(str(backup.get("config_text") or ""))
    if config is None:
        raise HTTPException(status_code=422, detail=NOT_OPNSENSE)
    return config


async def _backup_of(host_id: int, backup_id: int) -> dict:
    """A successful backup of ``host_id`` with its text; 404 for another host's."""
    backup = await db.get_config_backup(backup_id)
    if not backup or backup.get("host_id") != host_id or backup.get("status") != "success":
        raise HTTPException(status_code=404, detail=BACKUP_NOT_FOUND)
    return backup


async def rule_stats_for_host(host_id: int) -> dict[str, Any] | None:
    """The newest rule counters an OPNsense source collected for the host:
    ``{"org_ref", "collected_at", "rules": {uuid: counters}}``, or ``None``."""
    sources = {int(o["id"]) for o in await db.list_meraki_orgs() if str(o.get("provider") or "") == PROVIDER}
    found: dict[str, Any] | None = None
    for org_ref, snapshot_id in await db.get_latest_meraki_snapshot_ids():
        if org_ref not in sources:
            continue
        row = await db.get_meraki_snapshot(snapshot_id)
        stats = ((row or {}).get("snapshot") or {}).get("rule_stats")
        if not isinstance(stats, dict) or stats.get("host_id") != host_id:
            continue
        if found is None or str(stats.get("collected_at") or "") > str(found.get("collected_at") or ""):
            found = {"org_ref": org_ref, "collected_at": stats.get("collected_at"), "rules": stats.get("rules") or {}}
    return found


@router.get("/api/opnsense/hosts/{host_id}/rules")
@scoped("host")
async def get_host_rules(host_id: int, request: Request) -> dict[str, Any]:
    host = await require_host(request, host_id)
    answer: dict[str, Any] = {
        "host_id": host_id,
        "host": host.get("hostname") or host.get("ip_address"),
        "available": False,
        "message": "",
        "backup": None,
        "stats_collected_at": None,
    }
    newest = await db.get_config_backups(host_id=host_id, limit=1, status="success")
    config = None
    if newest:
        backup = await _backup_of(host_id, int(newest[0]["id"]))
        answer["backup"] = _backup_meta(backup)
        config = parse_document(str(backup.get("config_text") or ""))
    if config is None:
        # No backup, or one that is not an OPNsense config.xml: an empty view that says why.
        answer["message"] = NOT_OPNSENSE if newest else NO_BACKUP
        return {**answer, **analyze(OpnsenseConfig())}
    try:
        stats = await rule_stats_for_host(host_id)
    except Exception as exc:  # noqa: BLE001 - the rules are shown without counters
        LOGGER.warning("opnsense: rule counters of host %s not read: %s", host_id, type(exc).__name__)
        stats = None
    answer.update(available=True, stats_collected_at=stats["collected_at"] if stats else None)
    return {**answer, **analyze(config, stats["rules"] if stats else None)}


@router.get("/api/opnsense/hosts/{host_id}/rules/diff")
@scoped("host")
async def get_host_rules_diff(
    host_id: int,
    request: Request,
    from_backup: int | None = Query(default=None, ge=1),
    to_backup: int | None = Query(default=None, ge=1),
) -> dict[str, Any]:
    """The changes between two backups of the host; without them, between
    the newest backup and the one before it."""
    await require_host(request, host_id)
    if from_backup is None or to_backup is None:
        recent = await db.get_config_backups(host_id=host_id, limit=2, status="success")
        if len(recent) < 2:
            return {"host_id": host_id, "available": False, "message": TOO_FEW_BACKUPS}
        to_backup = to_backup or int(recent[0]["id"])
        from_backup = from_backup or int(next(b["id"] for b in recent if int(b["id"]) != to_backup))
    before = await _backup_of(host_id, from_backup)
    after = await _backup_of(host_id, to_backup)
    return {
        "host_id": host_id,
        "available": True,
        "message": "",
        "from_backup": _backup_meta(before),
        "to_backup": _backup_meta(after),
        **diff(_parse(before), _parse(after)),
    }
