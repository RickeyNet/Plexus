"""ipam.py -- Lightweight IPAM overview, drilldown, and external sync routes.

Object scope: a scoped caller sees the subnets of the hosts in their
inventory groups and the prefixes and IP addresses of their tenants
(``subnet_scope``); every write here is admin only.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

import netcontrol.routes.state as state
from netcontrol.data_validation import enforce as enforce_validation_rules
from netcontrol.object_scope import (
    filter_rows,
    readable_host_ids,
    request_scope,
    scope_exempt,
    scoped,
    sql_condition,
)
from netcontrol.prefix_index import longest_prefix_match
from netcontrol.routes.custom_fields import attach_custom_data, matching_keys
from netcontrol.routes.device_model import check_device_values
from netcontrol.routes.ipam_adapters import (
    COLLECTION_FED_MESSAGE,
    IpamAdapterError,
    collect_ipam_snapshot,
    get_ipam_provider_catalog,
    is_collection_fed,
    normalize_ipam_provider,
)
from netcontrol.routes.ipam_model import resolve_prefix_namespace
from netcontrol.routes.ipam_push import push_inventory_host_allocation
from netcontrol.routes.ipam_reconciliation import (
    VALID_RESOLUTIONS,
    resolve_diff as reconcile_resolve_diff,
    run_reconciliation,
)
from netcontrol.routes.meraki_topology import ipam_subnets as topology_subnets
from netcontrol.routes.shared import _audit, _corr_id, _get_session, admin_session
from netcontrol.secret_fields import refuse_endpoint_secret_reuse

router = APIRouter()

# Most device interface addresses a subnet drill-down lists.
SUBNET_INTERFACES_LIMIT = 1024


class IpamSyncConfigUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None


class IpamSourceCreate(BaseModel):
    provider: str
    name: str
    base_url: str
    auth_type: str = "token"
    auth_config: dict = Field(default_factory=dict)
    sync_scope: str = ""
    notes: str = ""
    enabled: bool = True
    push_enabled: bool = False
    verify_tls: bool = True


class IpamSourceUpdate(BaseModel):
    provider: str | None = None
    name: str | None = None
    base_url: str | None = None
    auth_type: str | None = None
    auth_config: dict | None = None
    sync_scope: str | None = None
    notes: str | None = None
    enabled: bool | None = None
    push_enabled: bool | None = None
    verify_tls: bool | None = None


class IpamReservationCreate(BaseModel):
    start_ip: str
    end_ip: str | None = None
    reason: str = "Reserved range"


class IpamPrefixCreate(BaseModel):
    subnet: str
    description: str = ""
    vrf: str = ""
    notes: str = ""
    tenant_id: int | None = None
    # The namespace (migration 0110); none: the VRF's, else Global.
    namespace_id: int | None = None


class IpamAllocationCreate(BaseModel):
    address: str
    hostname: str = ""
    description: str = ""
    tenant_id: int | None = None


class IpamTenantSet(BaseModel):
    """The tenant of a prefix or allocation; ``null`` clears it."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: int | None


class IpamReconciliationResolve(BaseModel):
    resolution: str
    note: str = ""


class IpamAllocateRequest(BaseModel):
    subnet: str
    vrf_name: str = ""
    hostname: str = ""
    description: str = ""
    source_id: int | None = None
    push: bool = False
    ttl_seconds: int = 900


def _serialize_source(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "provider": row.get("provider"),
        "name": row.get("name"),
        "base_url": row.get("base_url"),
        "auth_type": row.get("auth_type"),
        "sync_scope": row.get("sync_scope") or "",
        "notes": row.get("notes") or "",
        "enabled": bool(row.get("enabled")),
        "push_enabled": bool(row.get("push_enabled", 0)),
        "verify_tls": bool(row.get("verify_tls", 1)),
        "last_sync_at": row.get("last_sync_at"),
        "last_sync_status": row.get("last_sync_status") or "never",
        "last_sync_message": row.get("last_sync_message") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "prefix_count": int(row.get("prefix_count") or 0),
        "allocation_count": int(row.get("allocation_count") or 0),
        "has_auth_config": bool(row.get("auth_config_enc")),
    }


# ── Object scope ─────────────────────────────────────────────────────────────


async def overview_filters(request: Request) -> dict:
    """Keyword arguments of ``db.get_ipam_overview`` (and, without
    ``prefix_scope``, of ``db.get_ipam_subnet_detail``) for the caller's
    object scope: ``{}`` for an unrestricted caller, else the hosts of the
    readable inventory groups and the prefixes and IP addresses of the
    readable tenants."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return {}
    return {
        "group_ids": scope.read_groups,
        "prefix_scope": await sql_condition("ipam_prefix", request, alias="p"),
        "allocation_scope": await sql_condition("ipam_allocation", request, alias="a"),
    }


class SubnetScope:
    """The subnets (with their VRF) of the IPAM overview a scoped caller
    sees: those of the hosts in their inventory groups and of the prefixes
    in their scope. Cloud and topology subnets are not in it."""

    def __init__(self, subnets: Iterable[dict]) -> None:
        self.pairs: set[tuple[str, str]] = set()
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        for row in subnets:
            try:
                net = ipaddress.ip_network(str(row.get("subnet") or "").strip(), strict=False)
            except ValueError:
                continue
            vrf = str(row.get("vrf_name") or "").strip()
            self.pairs.add((str(net), vrf))
            self.networks.append((net, vrf))
        self.subnets: set[str] = {sn for sn, _ in self.pairs}

    def has_subnet(self, subnet: str, vrf: str | None = None) -> bool:
        """``subnet`` (any VRF when ``vrf`` is ``None``) is in scope."""
        try:
            key = str(ipaddress.ip_network(str(subnet).strip(), strict=False))
        except ValueError:
            return False
        return key in self.subnets if vrf is None else (key, vrf.strip()) in self.pairs

    def has_address(self, address: str, vrf: str | None = None) -> bool:
        """``address`` lies in a subnet in scope (of ``vrf`` when given)."""
        try:
            addr = ipaddress.ip_address(str(address).strip().split("/")[0])
        except ValueError:
            return False
        want = None if vrf is None else vrf.strip()
        return any(
            net.version == addr.version and addr in net and (want is None or v == want) for net, v in self.networks
        )


async def subnet_scope(request: Request) -> SubnetScope | None:
    """The subnets a scoped caller sees (``None``: unrestricted, every
    subnet), read once per request."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return None
    state_obj = getattr(request, "state", None)
    cached = getattr(state_obj, "ipam_subnet_scope", None)
    if isinstance(cached, SubnetScope):
        return cached
    overview = await db.get_ipam_overview(include_cloud=False, include_external=True, **await overview_filters(request))
    view = SubnetScope(overview.get("subnets", []))
    if state_obj is not None:
        state_obj.ipam_subnet_scope = view
    return view


def _subnet_key(row: dict) -> str:
    """The custom-data key of an overview or detail row (no data for a row
    whose subnet does not parse)."""
    try:
        return db.prefix_key(row["subnet"], row.get("vrf_name"))
    except ValueError:
        return ""


@router.get("/api/ipam/overview")
@scoped("list")
async def ipam_overview_api(
    request: Request,
    group_id: int | None = Query(default=None),
    include_cloud: bool = Query(default=True),
    include_external: bool = Query(default=True),
    include_topology: bool = Query(default=True),
):
    """The address space of every source: inventory hosts, cloud resources,
    external and local IPAM prefixes and, with ``include_topology``, the
    subnets of the latest Topology collections (Meraki VLANs and routes, Cato
    and Appgate network ranges, FMC, Panorama and OPNsense connected subnets, routes and VPN pools), with the
    ranges two sites or VPCs both claim listed under ``overlaps``.

    Each subnet carries its ``tags`` and ``custom_fields``; ``tag=`` and
    ``cf.<key>=`` keep only the matching subnets (summary counts unchanged)."""
    if group_id is not None and group_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid inventory group id")
    keys = await matching_keys("prefix", request.query_params)
    filters = await overview_filters(request)
    if filters:
        # Cloud and topology subnets belong to no inventory group or tenant.
        include_cloud = include_topology = False
    overview = await db.get_ipam_overview(
        group_id=group_id,
        include_cloud=include_cloud,
        include_external=include_external,
        topology_subnets=await topology_subnets() if include_topology else None,
        **filters,
    )
    subnets = overview.get("subnets", [])
    if keys is not None:
        subnets = [s for s in subnets if _subnet_key(s) in keys]
        overview["subnets"] = subnets
    await attach_custom_data("prefix", subnets, _subnet_key)
    return overview


@router.get("/api/ipam/address/{ip}")
@scoped("list")
async def ipam_address_context_api(
    ip: str,
    vrf: str | None = Query(default=None),
    request: Request = None,  # type: ignore[assignment]  # ChatOps calls it directly (unrestricted)
):
    """Return the best-matching subnet, utilization, and conflict status for a given IP.

    When `vrf` is provided, prefer subnets in that VRF and only flag a conflict
    when the duplicate exists in the same VRF - overlapping ranges across
    different VRFs are not real conflicts.

    ``interfaces``: the device interfaces that carry the address (of that VRF
    when `vrf` is provided).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    target_vrf = (vrf or "").strip()

    overview = await db.get_ipam_overview(include_cloud=False, include_external=True, **await overview_filters(request))
    subnets = overview.get("subnets", [])

    candidates: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict]] = []
    for s in subnets:
        try:
            candidates.append((ipaddress.ip_network(s["subnet"], strict=False), s))
        except ValueError:
            continue
    # Prefer same-VRF matches; among those (or, without one, among all) the
    # longest prefix.
    best: dict | None = None
    if target_vrf:
        best = longest_prefix_match(
            addr, [(n, s) for n, s in candidates if (s.get("vrf_name") or "").strip() == target_vrf]
        )
    if best is None:
        best = longest_prefix_match(addr, candidates)

    duplicates = overview.get("duplicate_ips", [])
    if target_vrf:
        conflict_entry = next(
            (d for d in duplicates if d.get("ip_address") == ip and (d.get("vrf_name") or "").strip() == target_vrf),
            None,
        )
    else:
        conflict_entry = next((d for d in duplicates if d.get("ip_address") == ip), None)

    return {
        "ip": ip,
        "vrf_name": target_vrf,
        "matched_subnet": best,
        "is_conflict": conflict_entry is not None,
        "conflict_groups": conflict_entry.get("groups", []) if conflict_entry else [],
        "conflict_vrf": (conflict_entry.get("vrf_name") if conflict_entry else None),
        "interfaces": await db.find_interface_addresses(
            ip, target_vrf or None, host_ids=await readable_host_ids(request)
        ),
    }


@router.get("/api/ipam/subnets/{subnet:path}")
@scoped("subnet")
async def ipam_subnet_detail_api(
    request: Request,
    subnet: str,
    group_id: int | None = Query(default=None),
    include_cloud: bool = Query(default=True),
    include_external: bool = Query(default=True),
    vrf: str = Query(default="", max_length=200),
):
    """A subnet's allocations, reservations and free addresses, with the
    ``tags`` and ``custom_fields`` of the prefix (``subnet`` in ``vrf``) and
    the device ``interfaces`` whose address is inside it (of ``vrf`` when it
    is given; at most ``SUBNET_INTERFACES_LIMIT``)."""
    if group_id is not None and group_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid inventory group id")
    # A scoped caller reads a subnet of their scope like anyone else, and any
    # other like one nothing is known of.
    filters = await overview_filters(request)
    filters.pop("prefix_scope", None)
    view = await subnet_scope(request)
    if view is not None and not view.has_subnet(subnet):
        filters.update(group_ids=frozenset(), allocation_scope=("1 = 0", ()), reservations=False)
    try:
        detail = await db.get_ipam_subnet_detail(
            subnet,
            group_id=group_id,
            include_cloud=include_cloud,
            include_external=include_external,
            **filters,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None
    detail["prefixes"] = await filter_rows("ipam_prefix", detail.get("prefixes", []), request)
    await attach_custom_data("prefix", [detail], lambda row: _subnet_key({"subnet": row["subnet"], "vrf_name": vrf}))
    detail["interfaces"] = await db.find_interface_addresses_in_subnet(
        subnet, vrf.strip() or None, SUBNET_INTERFACES_LIMIT, host_ids=await readable_host_ids(request)
    )
    # The aggregate (migration 0110) that holds the subnet, with its usage.
    detail["aggregate"] = await db.aggregate_for_subnet(subnet)
    return detail


@router.get("/api/ipam/providers")
@scope_exempt("the IPAM provider catalogue: no host or inventory group data")
async def ipam_providers_api():
    providers = get_ipam_provider_catalog()
    return {"providers": providers, "count": len(providers)}


@router.get("/api/ipam/sources")
@scope_exempt("IPAM sources are shared, admin-managed integrations: no host or inventory group data")
async def ipam_sources_api(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=False),
):
    try:
        if provider and is_collection_fed(provider):
            normalized_provider: str | None = provider.strip().lower()
        else:
            normalized_provider = normalize_ipam_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported IPAM provider") from None
    rows = await db.list_ipam_sources(provider=normalized_provider, enabled_only=enabled_only)
    return {"sources": [_serialize_source(row) for row in rows], "count": len(rows)}


@router.post("/api/ipam/sources", status_code=201, dependencies=[Depends(admin_session)])
@scoped("admin")
async def create_ipam_source_api(body: IpamSourceCreate, request: Request):
    try:
        provider = normalize_ipam_provider(body.provider)
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported IPAM provider") from None
    session = _get_session(request) or {}
    source = await db.create_ipam_source(
        provider=provider,
        name=body.name.strip(),
        base_url=body.base_url.strip(),
        auth_type=body.auth_type.strip().lower() or "token",
        auth_config=body.auth_config,
        sync_scope=body.sync_scope.strip(),
        notes=body.notes.strip(),
        enabled=body.enabled,
        push_enabled=body.push_enabled,
        verify_tls=body.verify_tls,
        created_by=session.get("user", ""),
    )
    if not source:
        raise HTTPException(status_code=500, detail="Failed to create IPAM source")
    await _audit(
        "ipam",
        "create_source",
        user=session.get("user", ""),
        detail=f"{provider}:{body.name.strip()}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "source": _serialize_source(source)}


@router.put("/api/ipam/sources/{source_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def update_ipam_source_api(source_id: int, body: IpamSourceUpdate, request: Request):
    existing = await db.get_ipam_source(source_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    updates = body.model_dump(exclude_none=True)
    if is_collection_fed(existing.get("provider")):
        # Its collection finds it by provider and address and fills it: only
        # its name, notes and enabled switch are the administrator's; it is
        # never pushed to.
        if str(updates.pop("provider", existing.get("provider")) or "").strip().lower() != existing.get("provider"):
            raise HTTPException(status_code=400, detail="Unsupported IPAM provider")
        fixed = sorted(set(updates) - {"name", "notes", "enabled", "push_enabled"})
        if fixed or updates.get("push_enabled"):
            raise HTTPException(
                status_code=400, detail=f"{COLLECTION_FED_MESSAGE}; only name, notes and enabled change"
            )
    if "provider" in updates:
        try:
            updates["provider"] = normalize_ipam_provider(updates["provider"])
        except ValueError:
            raise HTTPException(status_code=400, detail="Unsupported IPAM provider") from None
    try:
        # The stored API credentials stay with the address they were entered for.
        refuse_endpoint_secret_reuse(
            existing,
            updates,
            has_stored_secret=any((await db.get_ipam_source_auth_config(source_id)).values()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    updated = await db.update_ipam_source(source_id, **updates)
    if not updated:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "update_source",
        user=session.get("user", ""),
        detail=f"source_id={source_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "source": _serialize_source(updated)}


@router.delete("/api/ipam/sources/{source_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def delete_ipam_source_api(source_id: int, request: Request):
    existing = await db.get_ipam_source(source_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    if existing.get("provider") == "plexus":
        raise HTTPException(status_code=400, detail="Cannot delete the built-in Plexus IPAM source")
    deleted = await db.delete_ipam_source(source_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "delete_source",
        user=session.get("user", ""),
        detail=f"source_id={source_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/ipam/sources/{source_id}/validate", dependencies=[Depends(admin_session)])
@scoped("admin")
async def validate_ipam_source_api(source_id: int):
    source = await db.get_ipam_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    if is_collection_fed(source.get("provider")):
        raise HTTPException(status_code=409, detail=COLLECTION_FED_MESSAGE)
    try:
        auth_config = await db.get_ipam_source_auth_config(source_id)
        snapshot = await collect_ipam_snapshot(source, auth_config)
    except IpamAdapterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to validate external IPAM source") from None
    return {"ok": True, "summary": snapshot.get("summary") or {}}


@router.post("/api/ipam/sources/{source_id}/sync", dependencies=[Depends(admin_session)])
@scoped("admin")
async def sync_ipam_source_api(source_id: int, request: Request):
    source = await db.get_ipam_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    if is_collection_fed(source.get("provider")):
        # Never contacted and never marked failed: its collection fills it.
        raise HTTPException(status_code=409, detail=COLLECTION_FED_MESSAGE)
    session = _get_session(request) or {}
    try:
        auth_config = await db.get_ipam_source_auth_config(source_id)
        snapshot = await collect_ipam_snapshot(source, auth_config)
        summary = await db.replace_ipam_source_snapshot(
            source_id,
            prefixes=snapshot.get("prefixes") or [],
            allocations=snapshot.get("allocations") or [],
            sync_status="success",
            sync_message=(
                f"Synced {int(snapshot.get('summary', {}).get('prefix_count', 0))} subnets and "
                f"{int(snapshot.get('summary', {}).get('allocation_count', 0))} allocations"
            ),
        )
    except IpamAdapterError as exc:
        await db.set_ipam_source_sync_status(source_id, status="error", message=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:
        await db.set_ipam_source_sync_status(source_id, status="error", message="External sync failed")
        raise HTTPException(status_code=502, detail="Failed to sync external IPAM source") from None

    await _audit(
        "ipam",
        "sync_source",
        user=session.get("user", ""),
        detail=f"source_id={source_id}",
        correlation_id=_corr_id(request),
    )
    refreshed = await db.get_ipam_source(source_id)
    return {
        "ok": True,
        "source": _serialize_source(refreshed or source),
        "sync": summary,
        "summary": snapshot.get("summary") or {},
    }


@router.get("/api/ipam/subnets/{subnet:path}/reservations")
@scoped("subnet")
async def ipam_reservations_api(request: Request, subnet: str):
    try:
        rows = await db.list_ipam_reservations(subnet)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None
    view = await subnet_scope(request)
    if view is not None and not view.has_subnet(subnet):
        rows = []
    return {"reservations": rows, "count": len(rows)}


@router.post("/api/ipam/subnets/{subnet:path}/reservations", dependencies=[Depends(admin_session)])
@scoped("admin")
async def create_ipam_reservation_api(subnet: str, body: IpamReservationCreate, request: Request):
    session = _get_session(request) or {}
    try:
        reservation = await db.create_ipam_reservation(
            subnet,
            start_ip=body.start_ip,
            end_ip=body.end_ip or body.start_ip,
            reason=body.reason,
            created_by=session.get("user", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if not reservation:
        raise HTTPException(status_code=500, detail="Failed to create reservation")
    await _audit(
        "ipam",
        "create_reservation",
        user=session.get("user", ""),
        detail=f"subnet={subnet}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "reservation": reservation}


@router.delete("/api/ipam/reservations/{reservation_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def delete_ipam_reservation_api(reservation_id: int, request: Request):
    deleted = await db.delete_ipam_reservation(reservation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="IPAM reservation not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "delete_reservation",
        user=session.get("user", ""),
        detail=f"reservation_id={reservation_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.get("/api/ipam/sync-config")
@scope_exempt("the global IPAM sync schedule: no host or inventory group data")
async def get_ipam_sync_config_api():
    return {"config": dict(state.IPAM_SYNC_CONFIG)}


@router.put("/api/ipam/sync-config", dependencies=[Depends(admin_session)])
@scoped("admin")
async def update_ipam_sync_config_api(body: IpamSyncConfigUpdate, request: Request):
    updates = body.model_dump(exclude_none=True)
    cfg = dict(state.IPAM_SYNC_CONFIG)
    if "enabled" in updates:
        cfg["enabled"] = bool(updates["enabled"])
    if "interval_seconds" in updates:
        cfg["interval_seconds"] = max(
            state.IPAM_SYNC_MIN_INTERVAL,
            min(state.IPAM_SYNC_MAX_INTERVAL, int(updates["interval_seconds"])),
        )
    state.IPAM_SYNC_CONFIG = cfg
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "update_sync_config",
        user=session.get("user", ""),
        detail=f"enabled={cfg['enabled']},interval={cfg['interval_seconds']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "config": cfg}


# ─────────────────────────────────────────────────────────────────────────────
# Plexus-native (local) subnet and allocation management
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/api/ipam/prefixes", status_code=201, dependencies=[Depends(admin_session)])
@scoped("admin")
async def create_ipam_prefix_api(body: IpamPrefixCreate, request: Request):
    """Define a subnet in the built-in Plexus IPAM source."""
    try:
        import ipaddress as _ip

        subnet_key = str(_ip.ip_network(body.subnet, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR") from None
    await enforce_validation_rules(
        "prefix", {"subnet": body.subnet, "vrf": body.vrf, "description": body.description, "notes": body.notes}
    )
    await check_device_values({"tenant_id": body.tenant_id})
    namespace_id = await resolve_prefix_namespace(body.namespace_id, body.vrf)

    builtin = await db.get_or_create_builtin_ipam_source()
    # Unique per namespace and VRF (migration 0110).
    if await db.find_namespace_prefix(namespace_id, body.vrf, subnet_key, builtin["id"]) is not None:
        raise HTTPException(status_code=409, detail="Subnet already defined in this namespace and VRF")
    prefix = await db.create_ipam_prefix(
        source_id=builtin["id"],
        subnet=body.subnet,
        description=body.description,
        vrf=body.vrf,
        notes=body.notes,
        tenant_id=body.tenant_id,
        namespace_id=namespace_id,
    )
    if not prefix:
        raise HTTPException(status_code=409, detail="Subnet already defined")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "create_prefix",
        user=session.get("user", ""),
        detail=f"subnet={body.subnet}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "prefix": prefix}


@router.delete("/api/ipam/prefixes/{prefix_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def delete_ipam_prefix_api(prefix_id: int, request: Request):
    """Remove a locally-defined subnet prefix."""
    deleted = await db.delete_ipam_prefix(prefix_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="IPAM prefix not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "delete_prefix",
        user=session.get("user", ""),
        detail=f"prefix_id={prefix_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post(
    "/api/ipam/subnets/{subnet:path}/allocations",
    status_code=201,
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def create_ipam_allocation_api(subnet: str, body: IpamAllocationCreate, request: Request):
    """Manually assign an IP address within a subnet."""
    try:
        import ipaddress as _ip

        net = _ip.ip_network(subnet, strict=False)
        addr = _ip.ip_address(body.address)
        if addr not in net:
            raise HTTPException(status_code=400, detail="Address is not within the specified subnet")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet or IP address") from None
    await enforce_validation_rules(
        "ip_address", {"address": body.address, "hostname": body.hostname, "description": body.description}
    )
    await check_device_values({"tenant_id": body.tenant_id})

    builtin = await db.get_or_create_builtin_ipam_source()
    session = _get_session(request) or {}
    alloc = await db.create_local_ipam_allocation(
        source_id=builtin["id"],
        subnet=subnet,
        address=body.address,
        hostname=body.hostname,
        description=body.description,
        created_by=session.get("user", ""),
        tenant_id=body.tenant_id,
    )
    if not alloc:
        raise HTTPException(status_code=409, detail="IP address already allocated in this source")
    await _audit(
        "ipam",
        "create_allocation",
        user=session.get("user", ""),
        detail=f"subnet={subnet},address={body.address}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "allocation": alloc}


@router.patch("/api/ipam/prefixes/{prefix_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def set_ipam_prefix_tenant_api(prefix_id: int, body: IpamTenantSet, request: Request):
    """Set or clear the tenant of a prefix (of any source)."""
    await check_device_values({"tenant_id": body.tenant_id})
    if not await db.set_prefix_tenant(prefix_id, body.tenant_id):
        raise HTTPException(status_code=404, detail="IPAM prefix not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "set_prefix_tenant",
        user=session.get("user", ""),
        detail=f"prefix_id={prefix_id},tenant_id={body.tenant_id or '-'}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "prefix": await db.get_ipam_prefix(prefix_id)}


@router.patch("/api/ipam/allocations/{allocation_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def set_ipam_allocation_tenant_api(allocation_id: int, body: IpamTenantSet, request: Request):
    """Set or clear the tenant of an IP allocation (of any source)."""
    await check_device_values({"tenant_id": body.tenant_id})
    if not await db.set_allocation_tenant(allocation_id, body.tenant_id):
        raise HTTPException(status_code=404, detail="IPAM allocation not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "set_allocation_tenant",
        user=session.get("user", ""),
        detail=f"allocation_id={allocation_id},tenant_id={body.tenant_id or '-'}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/ipam/allocations/{allocation_id}", dependencies=[Depends(admin_session)])
@scoped("admin")
async def delete_ipam_allocation_api(allocation_id: int, request: Request):
    """Remove a manually-defined IP allocation."""
    deleted = await db.delete_ipam_allocation(allocation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="IPAM allocation not found")
    session = _get_session(request) or {}
    await _audit(
        "ipam",
        "delete_allocation",
        user=session.get("user", ""),
        detail=f"allocation_id={allocation_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# IPAM bi-directional reconciliation (Phase E)
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/api/ipam/sources/{source_id}/reconcile",
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def reconcile_ipam_source_api(source_id: int, request: Request):
    """Run a reconciliation pass for an external IPAM source."""
    session = _get_session(request) or {}
    user = session.get("user", "")
    try:
        summary = await run_reconciliation(source_id, triggered_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=502, detail="Reconciliation failed") from None
    await _audit(
        "ipam",
        "reconcile_source",
        user=user,
        detail=(f"source_id={source_id},run_id={summary.get('run_id')},drifts={summary.get('diff_count')}"),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "summary": summary}


@router.get("/api/ipam/reconciliation/runs")
@scope_exempt("reconciliation runs of the shared IPAM sources: counts only, no host or address data")
async def list_reconciliation_runs_api(
    source_id: int | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    runs = await db.list_reconciliation_runs(source_id=source_id, limit=limit)
    return {"runs": runs, "count": len(runs)}


@router.get("/api/ipam/reconciliation/diffs")
@scoped("list")
async def list_reconciliation_diffs_api(
    request: Request,
    source_id: int | None = Query(default=None),
    run_id: int | None = Query(default=None),
    open_only: bool = Query(default=True),
    limit: int = Query(default=500, ge=1, le=2000),
):
    diffs = await db.list_reconciliation_diffs(
        source_id=source_id,
        run_id=run_id,
        open_only=open_only,
        limit=limit,
    )
    view = await subnet_scope(request)
    if view is not None:
        diffs = [d for d in diffs if view.has_address(str(d.get("address") or ""))]
    return {"diffs": diffs, "count": len(diffs)}


@router.post(
    "/api/ipam/reconciliation/diffs/{diff_id}/resolve",
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def resolve_reconciliation_diff_api(
    diff_id: int,
    body: IpamReconciliationResolve,
    request: Request,
):
    if body.resolution not in VALID_RESOLUTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported resolution; expected one of {sorted(VALID_RESOLUTIONS)}",
        )
    session = _get_session(request) or {}
    user = session.get("user", "")
    try:
        resolved = await reconcile_resolve_diff(
            diff_id,
            resolution=body.resolution,
            resolved_by=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    await _audit(
        "ipam",
        "reconcile_resolve",
        user=user,
        detail=(f"diff_id={diff_id},resolution={body.resolution},address={resolved.get('address')}"),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "diff": resolved}


# ─────────────────────────────────────────────────────────────────────────────
# IPAM-driven provisioning (Phase H) - /api/ipam/allocate
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/api/ipam/allocate",
    status_code=201,
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def allocate_ip_api(body: IpamAllocateRequest, request: Request):
    """Reserve the next available IP in a subnet.

    Creates a pending allocation row that participates in subsequent
    next-IP selection so concurrent calls don't collide. Optionally pushes
    the allocation to enabled external IPAM sources for cross-system visibility
    (push failures do not fail the reservation - call /release to undo).
    """
    try:
        ipaddress.ip_network(body.subnet, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR") from None
    if body.source_id:
        target = await db.get_ipam_source(int(body.source_id))
        if target is not None and is_collection_fed(target.get("provider")):
            # Its next collection would drop the committed allocation.
            raise HTTPException(status_code=400, detail=COLLECTION_FED_MESSAGE)

    session = _get_session(request) or {}
    try:
        pending = await db.allocate_next_ip(
            subnet=body.subnet,
            vrf_name=body.vrf_name,
            hostname=body.hostname,
            description=body.description,
            source_id=body.source_id,
            ttl_seconds=body.ttl_seconds,
            created_by=session.get("user", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None

    push_summary: dict | None = None
    if body.push and pending.get("address"):
        push_summary = await push_inventory_host_allocation(
            hostname=body.hostname,
            ip_address=pending["address"],
            source_hint="allocate",
        )

    await _audit(
        "ipam",
        "allocate_ip",
        user=session.get("user", ""),
        detail=(
            f"subnet={body.subnet},address={pending.get('address')},vrf={body.vrf_name},pending_id={pending.get('id')}"
        ),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "allocation": pending, "push": push_summary}


@router.post(
    "/api/ipam/allocate/{allocation_id}/commit",
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def commit_allocation_api(allocation_id: int, request: Request):
    """Promote a pending allocation into the built-in (or original) IPAM source."""
    pending = await db.get_pending_allocation(allocation_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending allocation not found")
    if pending["state"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Allocation is already {pending['state']}",
        )

    session = _get_session(request) or {}
    target_source_id = pending.get("source_id")
    if not target_source_id:
        builtin = await db.get_or_create_builtin_ipam_source()
        target_source_id = builtin["id"]

    alloc = await db.create_local_ipam_allocation(
        source_id=int(target_source_id),
        subnet=pending["subnet"],
        address=pending["address"],
        hostname=pending.get("hostname", ""),
        description=pending.get("description", ""),
        created_by=session.get("user", ""),
    )
    if not alloc:
        raise HTTPException(
            status_code=409,
            detail="Address already allocated in target IPAM source",
        )

    updated = await db.update_pending_allocation_state(
        allocation_id, state="committed", source_id=int(target_source_id)
    )
    await _audit(
        "ipam",
        "allocate_commit",
        user=session.get("user", ""),
        detail=(f"pending_id={allocation_id},address={pending['address']},source_id={target_source_id}"),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "allocation": updated, "ipam_allocation": alloc}


@router.post(
    "/api/ipam/allocate/{allocation_id}/release",
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def release_allocation_api(allocation_id: int, request: Request):
    """Release a pending allocation (rollback). Idempotent on already-released rows."""
    pending = await db.get_pending_allocation(allocation_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending allocation not found")
    if pending["state"] == "committed":
        raise HTTPException(
            status_code=409,
            detail="Cannot release a committed allocation; delete the underlying IPAM allocation instead",
        )

    session = _get_session(request) or {}
    updated = await db.update_pending_allocation_state(allocation_id, state="released")
    await _audit(
        "ipam",
        "allocate_release",
        user=session.get("user", ""),
        detail=f"pending_id={allocation_id},address={pending.get('address')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "allocation": updated}


@router.get("/api/ipam/allocate/pending")
@scoped("list")
async def list_pending_allocations_api(
    request: Request,
    state: str | None = Query(default=None),
    include_expired: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
):
    view = await subnet_scope(request)
    rows = await db.list_pending_allocations(
        state=state,
        include_expired=include_expired,
        limit=limit,
        **({} if view is None else {"subnets": view.subnets}),
    )
    if view is not None:
        rows = [r for r in rows if view.has_subnet(str(r.get("subnet") or ""), str(r.get("vrf_name") or ""))]
    return {"allocations": rows, "count": len(rows)}


# ─────────────────────────────────────────────────────────────────────────────
# Historical IP allocation tracking (Phase I) - /api/ipam/history & utilization
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/api/ipam/history/{address}")
@scoped("address")
async def get_ip_history_api(
    request: Request,
    address: str,
    vrf: str = Query(default=""),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Return assignment history for an IP, newest first."""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None
    view = await subnet_scope(request)
    rows = (
        []
        if view is not None and not view.has_address(address, vrf)
        else await db.get_ip_history(address, vrf_name=vrf, limit=limit)
    )
    return {"address": address, "vrf": vrf, "history": rows, "count": len(rows)}


@router.get("/api/ipam/history/{address}/at")
@scoped("address")
async def get_ip_owner_at_api(
    request: Request,
    address: str,
    when: str = Query(..., description="ISO-8601 timestamp"),
    vrf: str = Query(default=""),
):
    """Who held this IP at a given timestamp?"""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None
    view = await subnet_scope(request)
    row = (
        None
        if view is not None and not view.has_address(address, vrf)
        else await db.find_ip_owner_at(address, when, vrf_name=vrf)
    )
    return {"address": address, "vrf": vrf, "when": when, "owner": row}


@router.get("/api/ipam/history/host/{hostname}")
@scoped("list")
async def get_history_for_hostname_api(request: Request, hostname: str, limit: int = Query(default=200, ge=1, le=2000)):
    """All IPs ever associated with a hostname."""
    rows = await db.list_ip_history_for_hostname(hostname, limit=limit)
    view = await subnet_scope(request)
    if view is not None:
        rows = [r for r in rows if view.has_address(str(r.get("address") or ""), str(r.get("vrf_name") or ""))]
    return {"hostname": hostname, "history": rows, "count": len(rows)}


@router.get("/api/ipam/utilization")
@scoped("list")
async def list_subnet_utilization_api(
    request: Request,
    subnet: str | None = Query(default=None),
    vrf: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Time-series subnet utilization snapshots, newest first."""
    view = await subnet_scope(request)
    rows = await db.list_subnet_utilization(
        subnet=subnet,
        vrf_name=vrf,
        since=since,
        until=until,
        limit=limit,
        **({} if view is None else {"subnets": view.subnets}),
    )
    if view is not None:
        rows = [r for r in rows if view.has_subnet(str(r.get("subnet") or ""), str(r.get("vrf_name") or ""))]
    return {"snapshots": rows, "count": len(rows)}


@router.post(
    "/api/ipam/utilization/snapshot",
    status_code=201,
    dependencies=[Depends(admin_session)],
)
@scoped("admin")
async def snapshot_utilization_api(
    request: Request,
    subnet: str | None = Query(default=None),
    vrf: str = Query(default=""),
):
    """Capture a utilization snapshot. If `subnet` omitted, snapshots every known subnet."""
    session = _get_session(request) or {}
    if subnet:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid subnet CIDR") from None
        snap = await db.snapshot_subnet_utilization(subnet, vrf_name=vrf)
        if snap is None:
            raise HTTPException(status_code=400, detail="Could not snapshot subnet")
        await _audit(
            "ipam",
            "utilization_snapshot",
            user=session.get("user", ""),
            detail=f"subnet={subnet},vrf={vrf}",
            correlation_id=_corr_id(request),
        )
        return {"ok": True, "snapshot": snap}
    written = await db.snapshot_all_subnet_utilization()
    await _audit(
        "ipam",
        "utilization_snapshot_all",
        user=session.get("user", ""),
        detail=f"snapshots_written={written}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "snapshots_written": written}
