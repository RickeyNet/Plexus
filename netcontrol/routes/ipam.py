"""ipam.py -- Lightweight IPAM overview, drilldown, and external sync routes."""

from __future__ import annotations

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.routes.ipam_adapters import (
    IpamAdapterError,
    collect_ipam_snapshot,
    get_ipam_provider_catalog,
    normalize_ipam_provider,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()
_require_admin = None


class IpamSourceCreate(BaseModel):
    provider: str
    name: str
    base_url: str
    auth_type: str = "token"
    auth_config: dict = Field(default_factory=dict)
    sync_scope: str = ""
    notes: str = ""
    enabled: bool = True
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
    verify_tls: bool | None = None


class IpamReservationCreate(BaseModel):
    start_ip: str
    end_ip: str | None = None
    reason: str = "Reserved range"


def init_ipam(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


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


@router.get("/api/ipam/overview")
async def ipam_overview_api(
    group_id: int | None = Query(default=None),
    include_cloud: bool = Query(default=True),
    include_external: bool = Query(default=True),
):
    if group_id is not None and group_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid inventory group id")
    return await db.get_ipam_overview(
        group_id=group_id,
        include_cloud=include_cloud,
        include_external=include_external,
    )


@router.get("/api/ipam/subnets/{subnet:path}")
async def ipam_subnet_detail_api(
    subnet: str,
    group_id: int | None = Query(default=None),
    include_cloud: bool = Query(default=True),
    include_external: bool = Query(default=True),
):
    if group_id is not None and group_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid inventory group id")
    try:
        return await db.get_ipam_subnet_detail(
            subnet,
            group_id=group_id,
            include_cloud=include_cloud,
            include_external=include_external,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None


@router.get("/api/ipam/providers")
async def ipam_providers_api():
    providers = get_ipam_provider_catalog()
    return {"providers": providers, "count": len(providers)}


@router.get("/api/ipam/sources")
async def ipam_sources_api(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=False),
):
    try:
        normalized_provider = normalize_ipam_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported IPAM provider") from None
    rows = await db.list_ipam_sources(provider=normalized_provider, enabled_only=enabled_only)
    return {"sources": [_serialize_source(row) for row in rows], "count": len(rows)}


@router.post("/api/ipam/sources", status_code=201, dependencies=[Depends(_require_admin_dep)])
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
        enabled=1 if body.enabled else 0,
        verify_tls=1 if body.verify_tls else 0,
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


@router.put("/api/ipam/sources/{source_id}", dependencies=[Depends(_require_admin_dep)])
async def update_ipam_source_api(source_id: int, body: IpamSourceUpdate, request: Request):
    existing = await db.get_ipam_source(source_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    updates = body.model_dump(exclude_none=True)
    if "provider" in updates:
        try:
            updates["provider"] = normalize_ipam_provider(updates["provider"])
        except ValueError:
            raise HTTPException(status_code=400, detail="Unsupported IPAM provider") from None
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


@router.delete("/api/ipam/sources/{source_id}", dependencies=[Depends(_require_admin_dep)])
async def delete_ipam_source_api(source_id: int, request: Request):
    existing = await db.get_ipam_source(source_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IPAM source not found")
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


@router.post("/api/ipam/sources/{source_id}/validate", dependencies=[Depends(_require_admin_dep)])
async def validate_ipam_source_api(source_id: int):
    source = await db.get_ipam_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="IPAM source not found")
    try:
        auth_config = await db.get_ipam_source_auth_config(source_id)
        snapshot = await collect_ipam_snapshot(source, auth_config)
    except IpamAdapterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to validate external IPAM source") from None
    return {"ok": True, "summary": snapshot.get("summary") or {}}


@router.post("/api/ipam/sources/{source_id}/sync", dependencies=[Depends(_require_admin_dep)])
async def sync_ipam_source_api(source_id: int, request: Request):
    source = await db.get_ipam_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="IPAM source not found")
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
async def ipam_reservations_api(subnet: str):
    try:
        rows = await db.list_ipam_reservations(subnet)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None
    return {"reservations": rows, "count": len(rows)}


@router.post("/api/ipam/subnets/{subnet:path}/reservations", dependencies=[Depends(_require_admin_dep)])
async def create_ipam_reservation_api(subnet: str, body: IpamReservationCreate, request: Request):
    session = _get_session(request) or {}
    try:
        reservation = await db.create_ipam_reservation(
            subnet,
            start_ip=body.start_ip,
            end_ip=body.end_ip,
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


@router.delete("/api/ipam/reservations/{reservation_id}", dependencies=[Depends(_require_admin_dep)])
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