"""VRF and VLAN records, and the addresses device interfaces carry.

Three routers, each registered in ``app.py``:

- ``router`` (signed-in user with the ``ipam`` feature): read the VRF and
  VLAN records with their devices, interfaces and prefixes.
- ``admin_router`` (admin): create, change and delete records, and parse the
  stored configurations again.
- ``host_router`` (gated like ``GET /api/hosts/{host_id}/interface-inventory``):
  a host's interface addresses.

``sync_host_bindings`` is the one place a stored running configuration
becomes interface addresses; ``store_device_config`` calls it on every
capture. Rules live in ``netcontrol.network_objects``, storage in
``routes.db.network_objects``. See ``docs/vrfs-and-vlans.md``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError
from netcontrol.device_model import parse_device_filters
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.network_objects import (
    DESCRIPTION_MAX,
    bindings_from_config,
    clean_description,
    clean_rd,
    clean_vid,
    clean_vlan_name,
    clean_vrf_name,
)
from netcontrol.routes.device_model import check_device_values
from netcontrol.routes.shared import _audit, _corr_id, _session_user

LOGGER = logging.getLogger("plexus.network_objects")

router = APIRouter()
admin_router = APIRouter()
host_router = APIRouter()

PREFIX = "/api/ipam"
# The setting that records the one-off parse of the stored configurations.
BACKFILL_SETTING = "interface_addresses_backfilled"
# Longest text a body accepts before trimming; the real limits are checked
# after trimming.
_RAW_MAX = 200
# Most rows a detail answer lists.
DETAIL_LIMIT = 2000


# ── Request bodies ───────────────────────────────────────────────────────────


class VrfCreate(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    rd: str = Field(default="", max_length=_RAW_MAX)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class VrfUpdate(BaseModel):
    """The name of a VRF never changes: a ``name`` key is refused."""

    model_config = ConfigDict(extra="forbid")

    rd: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class VlanCreate(BaseModel):
    vid: int
    name: str = Field(default="", max_length=_RAW_MAX)
    site_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class VlanUpdate(BaseModel):
    """The VLAN id never changes: a ``vid`` key is refused. ``site_id``
    left out keeps the site; ``null`` moves the VLAN to no site."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    site_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _clean(fn, raw):
    """Run a ``netcontrol.network_objects`` validator; 422 with its message."""
    try:
        return fn(raw)
    except CustomFieldError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit(
        "network_objects", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request)
    )


async def _check_site(site_id: int | None) -> None:
    """400 naming ``site_id`` when it names no site (the device model's
    contract)."""
    if site_id is not None:
        await check_device_values({"site_id": site_id})


def _describe_usage(usage: dict[str, int]) -> str:
    labels = {
        "hosts": "hosts",
        "prefixes": "IPAM prefixes",
        "allocations": "IPAM allocations",
        "interface_addresses": "interface addresses",
        "device_vrfs": "devices",
    }
    return ", ".join(f"{n} {labels[k]}" for k, n in usage.items() if n)


# ── Bindings sync ────────────────────────────────────────────────────────────


async def sync_host_bindings(host_id: int, device_type: str | None, config_text: str) -> int | None:
    """Read a host's running configuration into its interface addresses and
    device VRFs (replacing the stored ones) and create the VRF records it
    names. ``device_type`` ``None``: the host's is looked up.

    Returns the number of addresses stored, or ``None`` when nothing was
    written: the platform's configuration is not read (the stored rows
    stay), the host does not exist, or the parse or write failed (logged;
    never raised, so a capture never fails here)."""
    try:
        if device_type is None:
            host = await db.get_host(int(host_id))
            if host is None:
                return None
            device_type = str(host.get("device_type") or "")
        parse = platform_of(device_type).config
        if parse is None:
            return None
        rows, vrfs = bindings_from_config(parse(config_text or ""))
        if not await db.replace_host_bindings(int(host_id), rows, vrfs):
            return None
        return len(rows)
    except Exception as exc:
        LOGGER.warning("network objects: interface addresses of host %s not stored: %s", host_id, exc)
        return None


async def rebuild_interface_addresses() -> dict[str, int]:
    """Parse the newest stored configuration of every host again.
    ``hosts``: hosts parsed, ``addresses``: addresses stored."""
    hosts = 0
    addresses = 0
    for host in await db.list_binding_hosts():
        newest = await db.get_newest_host_config_backup(host["id"])
        if newest is None:
            continue
        stored = await sync_host_bindings(host["id"], host["device_type"], str(newest.get("config_text") or ""))
        if stored is not None:
            hosts += 1
            addresses += stored
    return {"hosts": hosts, "addresses": addresses}


async def backfill_interface_addresses() -> dict[str, int] | None:
    """The one-off parse after the upgrade to migration 0086: rebuild once,
    then record ``BACKFILL_SETTING`` so it never runs again. ``None`` when
    it had run already."""
    if await db.get_auth_setting(BACKFILL_SETTING):
        return None
    result = await rebuild_interface_addresses()
    await db.set_auth_setting(
        BACKFILL_SETTING, {"done": True, "at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"), **result}
    )
    LOGGER.info(
        "network objects: interface addresses read from %s stored configurations (%s addresses)",
        result["hosts"],
        result["addresses"],
    )
    return result


# ── VRFs ─────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/vrfs")
async def list_vrfs() -> dict:
    return {"vrfs": await db.list_vrfs()}


@router.get(f"{PREFIX}/vrfs/{{vrf_id}}")
async def get_vrf(vrf_id: int) -> dict:
    return _found(await db.get_vrf_detail(vrf_id, DETAIL_LIMIT), "VRF")


@admin_router.post(f"{PREFIX}/vrfs", status_code=201)
async def create_vrf(body: VrfCreate, request: Request) -> dict:
    name = _clean(clean_vrf_name, body.name)
    rd = _clean(clean_rd, body.rd)
    description = _clean(clean_description, body.description)
    try:
        record = await db.create_vrf(name=name, rd=rd, description=description)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "vrf_create", f"id={record['id']} name={name}")
    return record


@admin_router.put(f"{PREFIX}/vrfs/{{vrf_id}}")
async def update_vrf(vrf_id: int, body: VrfUpdate, request: Request) -> dict:
    current = _found(await db.get_vrf(vrf_id), "VRF")
    rd = _clean(clean_rd, body.rd) if body.rd is not None else current["rd"]
    description = (
        _clean(clean_description, body.description) if body.description is not None else current["description"]
    )
    record = _found(await db.update_vrf(vrf_id, rd=rd, description=description), "VRF")
    await _audit_write(request, "vrf_update", f"id={vrf_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/vrfs/{{vrf_id}}")
async def delete_vrf(vrf_id: int, request: Request) -> dict:
    record = _found(await db.get_vrf(vrf_id), "VRF")
    usage = await db.vrf_usage(record["name"])
    affected = sum(usage.values())
    if affected:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"VRF {record['name']} is in use ({_describe_usage(usage)}); it cannot be deleted.",
                "affected": affected,
                "usage": usage,
            },
        )
    await db.delete_vrf(vrf_id)
    await _audit_write(request, "vrf_delete", f"id={vrf_id} name={record['name']}")
    return {"ok": True}


# ── VLANs ────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/vlans")
async def list_vlans(
    site_id: str | None = Query(default=None, max_length=20),
    vid: int | None = Query(default=None, ge=1, le=4094),
) -> dict:
    """``site_id``: a site id, or ``none`` for the VLANs of no site."""
    site: int | None = None
    no_site = False
    if site_id is not None:
        filters, errors = parse_device_filters([("site_id", site_id)])
        if errors:
            raise HTTPException(status_code=400, detail={"message": errors["site_id"], "fields": errors})
        site = filters["site_id"][0]
        no_site = site is None
    return {"vlans": await db.list_vlans(site_id=site, no_site=no_site, vid=vid)}


@router.get(f"{PREFIX}/vlans/{{vlan_id}}")
async def get_vlan(vlan_id: int) -> dict:
    return _found(await db.get_vlan_detail(vlan_id, DETAIL_LIMIT), "VLAN")


@admin_router.post(f"{PREFIX}/vlans", status_code=201)
async def create_vlan(body: VlanCreate, request: Request) -> dict:
    vid = _clean(clean_vid, body.vid)
    name = _clean(clean_vlan_name, body.name)
    description = _clean(clean_description, body.description)
    await _check_site(body.site_id)
    try:
        record = await db.create_vlan(vid=vid, name=name, site_id=body.site_id, description=description)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "vlan_create", f"id={record['id']} vid={vid} site_id={body.site_id or '-'}")
    return record


@admin_router.put(f"{PREFIX}/vlans/{{vlan_id}}")
async def update_vlan(vlan_id: int, body: VlanUpdate, request: Request) -> dict:
    current = _found(await db.get_vlan(vlan_id), "VLAN")
    name = _clean(clean_vlan_name, body.name) if body.name is not None else current["name"]
    description = (
        _clean(clean_description, body.description) if body.description is not None else current["description"]
    )
    site_id = body.site_id if "site_id" in body.model_fields_set else current["site_id"]
    if site_id != current["site_id"]:
        await _check_site(site_id)
    try:
        record = await db.update_vlan(vlan_id, name=name, site_id=site_id, description=description)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record = _found(record, "VLAN")
    await _audit_write(request, "vlan_update", f"id={vlan_id} vid={record['vid']} site_id={site_id or '-'}")
    return record


@admin_router.delete(f"{PREFIX}/vlans/{{vlan_id}}")
async def delete_vlan(vlan_id: int, request: Request) -> dict:
    record = _found(await db.get_vlan(vlan_id), "VLAN")
    await db.delete_vlan(vlan_id)
    await _audit_write(request, "vlan_delete", f"id={vlan_id} vid={record['vid']} site_id={record['site_id'] or '-'}")
    return {"ok": True}


# ── Interface addresses ──────────────────────────────────────────────────────


@admin_router.post(f"{PREFIX}/interface-addresses/rebuild")
async def rebuild(request: Request) -> dict:
    result = await rebuild_interface_addresses()
    await _audit_write(
        request, "interface_addresses_rebuild", f"hosts={result['hosts']} addresses={result['addresses']}"
    )
    return {"ok": True, **result}


@host_router.get("/api/hosts/{host_id}/interface-addresses")
async def host_interface_addresses(host_id: int) -> dict:
    return {"host_id": host_id, **await db.get_interface_addresses_for_host(host_id)}
