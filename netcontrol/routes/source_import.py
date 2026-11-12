"""
source_import.py -- Import the devices a topology source found into the inventory.

After a Meraki organization, Cato account, Cisco FMC, Palo Alto Panorama or
Appgate SDP collective has been collected, an administrator can add the
devices of its latest collection to an inventory group in one step, and
with them:

  - assign an existing SNMP profile to the group, which is what turns on
    SNMP polling for its hosts (every inventory host is pinged by the
    monitoring poller; SNMP follows from the group's profile, and polling
    as a whole from the monitoring switch in Settings);
  - create a daily configuration backup policy for the group, with a
    credential the administrator already has, when some of the devices are
    of a platform Config Backups can read.

Nothing is imported automatically, existing hosts are never changed (a
device already in the inventory is skipped and reported), and no
credential or SNMP community is ever created here.

Which devices qualify and what Plexus can do with each is decided by
``netcontrol.integrations.inventory_import`` from the snapshot alone.

Registered admin-only, behind both the ``topology`` and ``inventory``
features.
"""

from __future__ import annotations

import re
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

import netcontrol.routes.state as state
from netcontrol.integrations.inventory_import import PROVIDER_NOTES, importable_devices, provider_key
from netcontrol.routes import meraki_topology
from netcontrol.routes.config_backups import ConfigBackupPolicyCreate, create_backup_policy
from netcontrol.routes.inventory import BULK_ADD_MAX_HOSTS, HostBulkEntry, _bulk_add, assign_group_snmp_profile
from netcontrol.routes.shared import _audit, _corr_id, _get_session, require_credential_access

router = APIRouter()

# The longest inventory group name an import creates (the Topology page's
# "Add to inventory" uses the same limit).
GROUP_NAME_MAX = 120


class ImportDevicesRequest(BaseModel):
    # Node ids (``key``) from GET /api/sources/{org_ref}/importable-devices.
    device_keys: list[str] = Field(min_length=1, max_length=BULK_ADD_MAX_HOSTS)
    # Exactly one of: an existing group, or the name of a new top-level group.
    group_id: int | None = None
    new_group_name: str | None = Field(default=None, max_length=200)
    # An existing SNMP profile to assign to the group; none leaves it as it is.
    snmp_profile_id: str | None = Field(default=None, max_length=100)
    # A credential to create a daily backup policy for the group with; none: no policy.
    backup_credential_id: int | None = None

    model_config = ConfigDict(extra="forbid")


def _group_name(raw: str | None) -> str:
    return re.sub(r"\s+", " ", str(raw or "")).strip()[:GROUP_NAME_MAX].strip()


async def _inventory_hosts() -> list[dict]:
    """Every inventory host, with the name of its group."""
    names = {g["id"]: g.get("path") or g["name"] for g in await db.get_all_groups()}
    return [{**h, "group_name": names.get(h.get("group_id"), "")} for h in await db.get_all_hosts()]


async def _candidates(org_ref: int) -> tuple[dict, dict | None, dict[str, Any]]:
    """The source, the metadata of its latest collection and what of it can be imported."""
    org = await meraki_topology._get_org_or_404(org_ref)
    latest = await meraki_topology.latest_snapshot_of(org_ref)
    meta, snapshot = latest if latest else (None, None)
    found = importable_devices(snapshot, meraki_topology._provider_of(org), await _inventory_hosts())
    return org, meta, found


@router.get("/api/sources/{org_ref}/importable-devices")
async def importable_devices_api(org_ref: int):
    """The devices of the source's latest collection that can be added to
    the inventory, each with the device type it would get, whether it is in
    the inventory already and what Plexus can do with it."""
    org, meta, found = await _candidates(org_ref)
    provider = provider_key(meraki_topology._provider_of(org))
    return {
        "org_ref": org_ref,
        "org_name": org["name"],
        "provider": provider,
        "snapshot_id": meta["id"] if meta else None,
        "collected_at": meta.get("created_at") if meta else None,
        "devices": found["devices"],
        "reason": found["reason"],
        "provider_note": PROVIDER_NOTES.get(provider, ""),
        "suggested_group_name": _group_name(org["name"]),
        "max_devices": BULK_ADD_MAX_HOSTS,
        "monitoring_enabled": bool(state.MONITORING_CONFIG.get("enabled")),
    }


@router.post("/api/sources/{org_ref}/import-devices")
async def import_devices_api(org_ref: int, body: ImportDevicesRequest, request: Request):
    """Add the chosen devices of the source's latest collection to an
    inventory group (created when asked), optionally assign the group an
    SNMP profile and give it a daily backup policy. Devices already in the
    inventory are skipped and reported; existing hosts are never changed."""
    session = _get_session(request)
    org, meta, found = await _candidates(org_ref)
    if meta is None:
        raise HTTPException(409, found["reason"])
    by_key = {d["key"]: d for d in found["devices"]}

    # ── Validate everything before writing anything ──────────────────────
    keys = list(dict.fromkeys(k.strip() for k in body.device_keys if k.strip()))
    if not keys:
        raise HTTPException(400, "Select at least one device")
    unknown = [k for k in keys if k not in by_key]
    if unknown:
        listed = ", ".join(unknown[:5]) + (f" and {len(unknown) - 5} more" if len(unknown) > 5 else "")
        raise HTTPException(400, f"Not devices of the latest collection of this source: {listed}")
    selected = [by_key[k] for k in keys]

    new_name = _group_name(body.new_group_name)
    if (body.group_id is None) == (not new_name):
        raise HTTPException(400, "Give either group_id or new_group_name")
    group: dict | None = None
    if body.group_id is not None:
        group = await db.get_group(body.group_id)
        if not group:
            raise HTTPException(404, "Group not found")
    elif any(g.get("parent_id") is None and g["name"] == new_name for g in await db.get_all_groups()):
        raise HTTPException(409, f"A group named {new_name!r} already exists; choose it as the existing group")

    profile_id = (body.snmp_profile_id or "").strip()
    if profile_id and profile_id not in state.SNMP_PROFILES:
        raise HTTPException(400, "SNMP profile not found")

    if body.backup_credential_id is not None:
        if not any(d["capabilities"]["config_backup"] for d in selected):
            raise HTTPException(400, "None of the selected devices is of a platform Config Backups can read")
        await require_credential_access(body.backup_credential_id, session=session, allow_service=True)

    # ── Group ────────────────────────────────────────────────────────────
    group_created = False
    if group is None:
        level = (await db.get_or_create_group_path([new_name], description=f"Imported from {org['name']}"))[-1]
        group_created = bool(level["created"])
        group = {"id": level["id"], "name": level["name"]}
    group_id = int(group["id"])

    # ── Hosts: never touch one that exists ───────────────────────────────
    already = [
        {
            "key": d["key"],
            "hostname": d["name"],
            "ip_address": d["ip"],
            "reason": "Already in inventory",
            "host_id": d["existing"]["host_id"],
            "group_id": d["existing"]["group_id"],
        }
        for d in selected
        if d["existing"]
    ]
    to_add = [d for d in selected if not d["existing"]]
    result: dict[str, list] = {"added": [], "skipped": [], "errors": []}
    if to_add:
        entries = [HostBulkEntry(hostname=d["name"], ip_address=d["ip"], device_type=d["device_type"]) for d in to_add]
        result = await _bulk_add(entries, group_id, request)

    # ── SNMP profile ─────────────────────────────────────────────────────
    snmp: dict[str, Any] = {"status": "none", "profile_id": "", "profile_name": ""}
    if profile_id:
        current = state.GROUP_SNMP_ASSIGNMENTS.get(group_id, "")
        if current and current != profile_id:
            kept = state.SNMP_PROFILES.get(current) or {}
            snmp = {"status": "kept", "profile_id": current, "profile_name": kept.get("name", "")}
        else:
            assigned = await assign_group_snmp_profile(group_id, profile_id)
            snmp = {"status": "assigned", "profile_id": profile_id, "profile_name": assigned["profile_name"]}

    # ── Backup policy ────────────────────────────────────────────────────
    backup: dict[str, Any] = {"status": "none", "policy_id": None, "name": ""}
    if body.backup_credential_id is not None:
        policies = await db.get_config_backup_policies(group_id)
        if policies:
            policy = policies[0]
            status = "exists"
        else:
            policy = await create_backup_policy(
                ConfigBackupPolicyCreate(
                    name=f"{group['name']} daily backup"[:200],
                    group_id=group_id,
                    credential_id=body.backup_credential_id,
                ),
                request,
            )
            status = "created"
        backup = {
            "status": status,
            "policy_id": policy.get("id"),
            "name": policy.get("name", ""),
            "interval_seconds": policy.get("interval_seconds"),
            "retention_days": policy.get("retention_days"),
        }

    skipped = already + result.get("skipped", [])
    await _audit(
        "meraki_topology",
        "import_devices",
        user=(session or {}).get("user", ""),
        detail=(
            f"org={org['name']} snapshot_id={meta['id']} group_id={group_id} group_created={group_created} "
            f"added={len(result['added'])} skipped={len(skipped)} errors={len(result['errors'])} "
            f"snmp_profile={snmp['status']} backup_policy={backup['status']}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "group": {"id": group_id, "name": group["name"], "created": group_created},
        "added": result["added"],
        "skipped": skipped,
        "errors": result["errors"],
        "counts": {"added": len(result["added"]), "skipped": len(skipped), "errors": len(result["errors"])},
        "snmp_profile": snmp,
        "backup_policy": backup,
        "monitoring_enabled": bool(state.MONITORING_CONFIG.get("enabled")),
    }
