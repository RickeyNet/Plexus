"""dhcp.py -- DHCP scope/lease integration routes (Phase F).

Provides CRUD for DHCP server configs, manual sync, normalized scope/lease
listings, and correlation against discovered inventory.
"""

from __future__ import annotations

import ipaddress

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.routes.dhcp_adapters import (
    DhcpAdapterError,
    collect_dhcp_snapshot,
    get_dhcp_provider_catalog,
    normalize_dhcp_provider,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()
_require_admin = None

# Scope-exhaustion threshold: alert when free/total drops below this.
SCOPE_EXHAUSTION_PCT = 90.0


class DhcpServerCreate(BaseModel):
    provider: str
    name: str
    base_url: str = ""
    auth_type: str = "none"
    auth_config: dict = Field(default_factory=dict)
    notes: str = ""
    enabled: bool = True
    verify_tls: bool = True


class DhcpServerUpdate(BaseModel):
    provider: str | None = None
    name: str | None = None
    base_url: str | None = None
    auth_type: str | None = None
    auth_config: dict | None = None
    notes: str | None = None
    enabled: bool | None = None
    verify_tls: bool | None = None


def init_dhcp(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


def _scope_utilization_pct(scope: dict) -> float:
    total = int(scope.get("total_addresses") or 0)
    used = int(scope.get("used_addresses") or 0)
    if total <= 0:
        return 0.0
    return round((used / total) * 100.0, 2)


def _serialize_scope(row: dict) -> dict:
    pct = _scope_utilization_pct(row)
    return {
        "id": row.get("id"),
        "server_id": row.get("server_id"),
        "external_id": row.get("external_id") or "",
        "subnet": row.get("subnet"),
        "name": row.get("name") or "",
        "range_start": row.get("range_start") or "",
        "range_end": row.get("range_end") or "",
        "total_addresses": int(row.get("total_addresses") or 0),
        "used_addresses": int(row.get("used_addresses") or 0),
        "free_addresses": int(row.get("free_addresses") or 0),
        "utilization_pct": pct,
        "exhausted": pct >= SCOPE_EXHAUSTION_PCT,
        "state": row.get("state") or "",
        "discovered_at": row.get("discovered_at"),
    }


def _serialize_lease(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "server_id": row.get("server_id"),
        "scope_subnet": row.get("scope_subnet") or "",
        "address": row.get("address"),
        "mac_address": row.get("mac_address") or "",
        "hostname": row.get("hostname") or "",
        "client_id": row.get("client_id") or "",
        "state": row.get("state") or "",
        "starts_at": row.get("starts_at"),
        "ends_at": row.get("ends_at"),
        "discovered_at": row.get("discovered_at"),
    }


@router.get("/api/dhcp/providers")
async def list_dhcp_providers_api():
    return {"providers": get_dhcp_provider_catalog()}


@router.get("/api/dhcp/servers")
async def list_dhcp_servers_api():
    rows = await db.list_dhcp_servers()
    return {"servers": rows}


@router.post("/api/dhcp/servers")
async def create_dhcp_server_api(
    body: DhcpServerCreate,
    request: Request,
    _admin=Depends(_require_admin_dep),
):
    session = _get_session(request)
    try:
        provider = normalize_dhcp_provider(body.provider)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_provider")
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name_required")
    row = await db.create_dhcp_server(
        provider=provider,
        name=name,
        base_url=(body.base_url or "").strip(),
        auth_type=(body.auth_type or "none").strip().lower(),
        auth_config=body.auth_config or {},
        notes=body.notes or "",
        enabled=bool(body.enabled),
        verify_tls=bool(body.verify_tls),
        created_by=(session or {}).get("username", ""),
    )
    if not row:
        raise HTTPException(status_code=500, detail="create_failed")
    await _audit(
        "dhcp",
        "server_create",
        user=(session or {}).get("username", ""),
        detail=f"id={row['id']} provider={provider} name={name}",
        correlation_id=_corr_id(request),
    )
    return row


@router.get("/api/dhcp/servers/{server_id}")
async def get_dhcp_server_api(server_id: int):
    row = await db.get_dhcp_server(server_id)
    if not row:
        raise HTTPException(status_code=404, detail="not_found")
    return row


@router.patch("/api/dhcp/servers/{server_id}")
async def update_dhcp_server_api(
    server_id: int,
    body: DhcpServerUpdate,
    request: Request,
    _admin=Depends(_require_admin_dep),
):
    existing = await db.get_dhcp_server(server_id)
    if not existing:
        raise HTTPException(status_code=404, detail="not_found")
    session = _get_session(request)
    update_kwargs = body.model_dump(exclude_unset=True)
    if "provider" in update_kwargs:
        try:
            update_kwargs["provider"] = normalize_dhcp_provider(update_kwargs["provider"])
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid_provider")
    row = await db.update_dhcp_server(server_id, **update_kwargs)
    await _audit(
        "dhcp",
        "server_update",
        user=(session or {}).get("username", ""),
        detail=f"id={server_id} fields={list(update_kwargs.keys())}",
        correlation_id=_corr_id(request),
    )
    return row


@router.delete("/api/dhcp/servers/{server_id}")
async def delete_dhcp_server_api(
    server_id: int,
    request: Request,
    _admin=Depends(_require_admin_dep),
):
    existing = await db.get_dhcp_server(server_id)
    if not existing:
        raise HTTPException(status_code=404, detail="not_found")
    ok = await db.delete_dhcp_server(server_id)
    if not ok:
        raise HTTPException(status_code=500, detail="delete_failed")
    session = _get_session(request)
    await _audit(
        "dhcp",
        "server_delete",
        user=(session or {}).get("username", ""),
        detail=f"id={server_id} provider={existing.get('provider')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


async def sync_dhcp_server(server_id: int, *, triggered_by: str = "manual") -> dict:
    """Pull a fresh scope/lease snapshot for a single server."""
    server = await db.get_dhcp_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="not_found")
    auth_config = await db.get_dhcp_server_auth_config(server_id)
    try:
        snapshot = await collect_dhcp_snapshot(server, auth_config)
    except DhcpAdapterError as exc:
        await db.set_dhcp_server_sync_status(server_id, status="error", message=str(exc))
        raise HTTPException(status_code=502, detail=f"adapter_error: {exc}") from exc
    summary = snapshot.get("summary") or {}
    message = (
        f"{triggered_by}: {int(summary.get('scope_count', 0))} scopes, "
        f"{int(summary.get('lease_count', 0))} leases"
    )
    await db.replace_dhcp_server_snapshot(
        server_id,
        scopes=snapshot.get("scopes") or [],
        leases=snapshot.get("leases") or [],
        sync_status="success",
        sync_message=message,
    )
    return {"summary": summary, "message": message}


@router.post("/api/dhcp/servers/{server_id}/sync")
async def sync_dhcp_server_api(
    server_id: int,
    request: Request,
    _admin=Depends(_require_admin_dep),
):
    session = _get_session(request)
    result = await sync_dhcp_server(server_id, triggered_by="manual")
    await _audit(
        "dhcp",
        "server_sync",
        user=(session or {}).get("username", ""),
        detail=f"id={server_id} {result.get('message', '')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, **result}


@router.get("/api/dhcp/scopes")
async def list_dhcp_scopes_api(
    server_id: int | None = Query(default=None),
    only_exhausted: bool = Query(default=False),
):
    rows = await db.list_dhcp_scopes(server_id=server_id)
    scopes = [_serialize_scope(r) for r in rows]
    if only_exhausted:
        scopes = [s for s in scopes if s["exhausted"]]
    return {"scopes": scopes}


@router.get("/api/dhcp/leases")
async def list_dhcp_leases_api(
    server_id: int | None = Query(default=None),
    scope_subnet: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    rows = await db.list_dhcp_leases(server_id=server_id, scope_subnet=scope_subnet, limit=limit)
    return {"leases": [_serialize_lease(r) for r in rows]}


def _normalize_ip_for_match(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_interface(raw).ip)
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


async def _correlate_leases_to_inventory(leases: list[dict]) -> dict:
    """Classify each lease as known (matches an inventory host IP) or unknown."""
    try:
        hosts = await db.get_all_hosts()
    except Exception:
        hosts = []
    host_ips: set[str] = set()
    host_by_ip: dict[str, str] = {}
    for h in hosts:
        ip = _normalize_ip_for_match(str(h.get("ip") or h.get("ip_address") or ""))
        if not ip:
            continue
        host_ips.add(ip)
        host_by_ip[ip] = str(h.get("hostname") or h.get("name") or "")
    known: list[dict] = []
    unknown: list[dict] = []
    for lease in leases:
        addr = _normalize_ip_for_match(str(lease.get("address") or ""))
        entry = {
            **_serialize_lease(lease),
            "inventory_hostname": host_by_ip.get(addr, ""),
        }
        if addr in host_ips:
            known.append(entry)
        else:
            unknown.append(entry)
    return {"known": known, "unknown": unknown}


@router.get("/api/dhcp/correlation")
async def dhcp_correlation_api(
    server_id: int | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
):
    """Cross-reference DHCP leases against discovered inventory hosts.

    Returns leases split into ``known`` (lease IP appears in inventory) and
    ``unknown`` (lease IP not seen by Plexus discovery — potential rogue
    devices).
    """
    rows = await db.list_dhcp_leases(server_id=server_id, limit=limit)
    classified = await _correlate_leases_to_inventory(rows)
    return {
        "totals": {
            "known": len(classified["known"]),
            "unknown": len(classified["unknown"]),
        },
        **classified,
    }


@router.get("/api/dhcp/exhaustion")
async def dhcp_exhaustion_api():
    """List scopes whose utilization meets or exceeds the exhaustion threshold."""
    rows = await db.list_dhcp_scopes()
    scopes = [_serialize_scope(r) for r in rows]
    exhausted = [s for s in scopes if s["exhausted"]]
    near = [
        s
        for s in scopes
        if not s["exhausted"] and s["utilization_pct"] >= (SCOPE_EXHAUSTION_PCT - 10.0)
    ]
    return {
        "threshold_pct": SCOPE_EXHAUSTION_PCT,
        "exhausted": exhausted,
        "near_exhaustion": near,
    }
