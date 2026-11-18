"""VRF and VLAN records, and the addresses device interfaces carry.

Three routers, each registered in ``app.py``:

- ``router`` (signed-in user with the ``ipam`` feature): read the VRF and
  VLAN records with their devices, interfaces and prefixes.
- ``admin_router`` (admin): create, change and delete records, and parse the
  stored configurations again.
- ``host_router`` (gated like ``GET /api/hosts/{host_id}/interface-inventory``):
  a host's interface addresses.

Object scope: a scoped caller reads the VRFs and VLANs of their tenants and
sites and those with no tenant or site (shared), with the devices,
addresses, prefixes and counts of their own hosts and prefixes only; and
the interface addresses of their hosts.

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
from routes.db.organization import TENANT_UNCHANGED, TenantArg

from netcontrol.custom_fields import CustomFieldError
from netcontrol.data_validation import enforce as enforce_validation_rules, pick as rule_values
from netcontrol.device_model import parse_device_filters
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.ipam_model import GLOBAL_NAMESPACE_ID
from netcontrol.network_objects import (
    DESCRIPTION_MAX,
    bindings_from_config,
    clean_description,
    clean_rd,
    clean_vid,
    clean_vlan_name,
    clean_vrf_name,
)
from netcontrol.object_scope import (
    filter_rows,
    readable_host_ids,
    request_scope,
    require_host,
    require_row,
    scoped,
    sql_condition,
)
from netcontrol.routes.custom_fields import custom_list, with_custom_data
from netcontrol.routes.device_model import check_device_values
from netcontrol.routes.ipam_model import check_namespace, check_vlan_group, readable_vrf_route_targets
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
    tenant_id: int | None = None
    namespace_id: int = GLOBAL_NAMESPACE_ID


class VrfUpdate(BaseModel):
    """The name of a VRF never changes: a ``name`` key is refused.
    ``tenant_id`` left out keeps the tenant; ``null`` clears it.
    ``namespace_id`` left out (or null) keeps the namespace."""

    model_config = ConfigDict(extra="forbid")

    rd: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    tenant_id: int | None = None
    namespace_id: int | None = None


class VlanCreate(BaseModel):
    vid: int
    name: str = Field(default="", max_length=_RAW_MAX)
    site_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX)
    tenant_id: int | None = None
    vlan_group_id: int | None = None


class VlanUpdate(BaseModel):
    """The VLAN id never changes: a ``vid`` key is refused. ``site_id``
    left out keeps the site; ``null`` moves the VLAN to no site.
    ``vlan_group_id`` likewise for its VLAN group."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    site_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    tenant_id: int | None = None
    vlan_group_id: int | None = None


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


async def _new_tenant(tenant_id: int | None) -> int | None:
    """``tenant_id`` checked: 400 naming it when it names no tenant."""
    if tenant_id is not None:
        await check_device_values({"tenant_id": tenant_id})
    return tenant_id


async def _changed_tenant(body: VrfUpdate | VlanUpdate, current: dict) -> TenantArg:
    """The tenant an update sets: ``TENANT_UNCHANGED`` when it leaves it out
    or keeps it."""
    if "tenant_id" not in body.model_fields_set or body.tenant_id == current.get("tenant_id"):
        return TENANT_UNCHANGED
    return await _new_tenant(body.tenant_id)


async def _scope_filters(request: Request, *, prefixes: bool = True) -> dict:
    """Keyword arguments of the VRF (``prefixes``) and VLAN readers that keep
    a scoped caller's counts and detail rows to their hosts (and prefixes);
    ``{}`` for an unrestricted caller."""
    host_ids = await readable_host_ids(request)
    if host_ids is None:
        return {}
    if not prefixes:
        return {"host_ids": host_ids}
    return {"host_ids": host_ids, "prefix_scope": await sql_condition("ipam_prefix", request, alias="p")}


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
@scoped("list")
async def list_vrfs(request: Request) -> dict:
    """``tag=`` and ``cf.<key>=`` filter by tag and custom field value."""
    rows = await filter_rows("vrf", await db.list_vrfs(**await _scope_filters(request)), request)
    return {"vrfs": await custom_list("vrf", rows, request)}


@router.get(f"{PREFIX}/vrfs/{{vrf_id}}")
@scoped("object")
async def get_vrf(vrf_id: int, request: Request) -> dict:
    """The VRF with its devices, addresses, prefixes and ``route_targets``
    (``import`` and ``export``)."""
    detail = await require_row(
        request,
        "vrf",
        await db.get_vrf_detail(vrf_id, DETAIL_LIMIT, **await _scope_filters(request)),
        not_found="VRF not found",
    )
    # Only the route targets the caller may read (of their tenants or of none).
    detail["route_targets"] = await readable_vrf_route_targets(vrf_id, request)
    return await with_custom_data("vrf", detail)


@admin_router.post(f"{PREFIX}/vrfs", status_code=201)
async def create_vrf(body: VrfCreate, request: Request) -> dict:
    name = _clean(clean_vrf_name, body.name)
    rd = _clean(clean_rd, body.rd)
    description = _clean(clean_description, body.description)
    tenant_id = await _new_tenant(body.tenant_id)
    await check_namespace(body.namespace_id)
    await enforce_validation_rules("vrf", {"name": name, "rd": rd, "description": description})
    try:
        record = await db.create_vrf(
            name=name, rd=rd, description=description, tenant_id=tenant_id, namespace_id=body.namespace_id
        )
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
    await enforce_validation_rules("vrf", {"rd": rd, "description": description}, existing=rule_values(current, "vrf"))
    tenant_id = await _changed_tenant(body, current)
    if body.namespace_id is not None and body.namespace_id != current["namespace_id"]:
        await check_namespace(body.namespace_id)
    record = _found(
        await db.update_vrf(
            vrf_id, rd=rd, description=description, tenant_id=tenant_id, namespace_id=body.namespace_id
        ),
        "VRF",
    )
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
@scoped("list")
async def list_vlans(
    request: Request,
    site_id: str | None = Query(default=None, max_length=20),
    vid: int | None = Query(default=None, ge=1, le=4094),
    vlan_group_id: int | None = Query(default=None),
) -> dict:
    """``site_id``: a site id, or ``none`` for the VLANs of no site;
    ``vlan_group_id`` one VLAN group's; ``tag=`` and ``cf.<key>=`` filter by
    tag and custom field value."""
    site: int | None = None
    no_site = False
    if site_id is not None:
        filters, errors = parse_device_filters([("site_id", site_id)])
        if errors:
            raise HTTPException(status_code=400, detail={"message": errors["site_id"], "fields": errors})
        site = filters["site_id"][0]
        no_site = site is None
    rows = await db.list_vlans(
        site_id=site,
        no_site=no_site,
        vid=vid,
        vlan_group_id=vlan_group_id,
        **await _scope_filters(request, prefixes=False),
    )
    return {"vlans": await custom_list("vlan", await filter_rows("vlan", rows, request), request)}


@router.get(f"{PREFIX}/vlans/{{vlan_id}}")
@scoped("object")
async def get_vlan(vlan_id: int, request: Request) -> dict:
    detail = await db.get_vlan_detail(vlan_id, DETAIL_LIMIT, **await _scope_filters(request, prefixes=False))
    return await with_custom_data("vlan", await require_row(request, "vlan", detail, not_found="VLAN not found"))


@admin_router.post(f"{PREFIX}/vlans", status_code=201)
async def create_vlan(body: VlanCreate, request: Request) -> dict:
    vid = _clean(clean_vid, body.vid)
    name = _clean(clean_vlan_name, body.name)
    description = _clean(clean_description, body.description)
    await _check_site(body.site_id)
    tenant_id = await _new_tenant(body.tenant_id)
    await check_vlan_group(body.vlan_group_id, vid, body.site_id)
    await enforce_validation_rules("vlan", {"vid": vid, "name": name, "description": description})
    try:
        record = await db.create_vlan(
            vid=vid,
            name=name,
            site_id=body.site_id,
            description=description,
            tenant_id=tenant_id,
            vlan_group_id=body.vlan_group_id,
        )
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
    tenant_id = await _changed_tenant(body, current)
    group_id = body.vlan_group_id if "vlan_group_id" in body.model_fields_set else current["vlan_group_id"]
    if group_id is not None and (group_id != current["vlan_group_id"] or site_id != current["site_id"]):
        await check_vlan_group(group_id, current["vid"], site_id)
    group_arg: TenantArg = group_id if group_id != current["vlan_group_id"] else TENANT_UNCHANGED
    await enforce_validation_rules(
        "vlan", {"name": name, "description": description}, existing=rule_values(current, "vlan")
    )
    try:
        record = await db.update_vlan(
            vlan_id,
            name=name,
            site_id=site_id,
            description=description,
            tenant_id=tenant_id,
            vlan_group_id=group_arg,
        )
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
@scoped("host")
async def host_interface_addresses(host_id: int, request: Request) -> dict:
    if (await request_scope(request)).restricted:
        await require_host(request, host_id)
    return {"host_id": host_id, **await db.get_interface_addresses_for_host(host_id)}
