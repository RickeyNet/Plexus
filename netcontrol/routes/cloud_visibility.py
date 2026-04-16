"""
cloud_visibility.py -- Cloud network visibility foundation (AWS/Azure/GCP).

Provides:
  - Cloud account CRUD (provider metadata + auth references)
  - Discovery snapshot ingestion (sample mode for initial foundation)
  - Cloud resource + connection + hybrid-link APIs for UI topology rendering
"""

from __future__ import annotations

import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.cloud_visibility")

_require_admin = None

_VALID_PROVIDERS = {"aws", "azure", "gcp"}


def init_cloud_visibility(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


def _normalize_provider(raw: str | None) -> str:
    provider = str(raw or "").strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ValueError("invalid_provider")
    return provider


def _json_loads_safe(raw: str | None, fallback):
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _serialize_account(account: dict) -> dict:
    item = dict(account)
    item["auth_config"] = _json_loads_safe(item.get("auth_config_json"), {})
    return item


def _serialize_resource(resource: dict) -> dict:
    item = dict(resource)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


def _serialize_connection(connection: dict) -> dict:
    item = dict(connection)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


def _serialize_hybrid_link(link: dict) -> dict:
    item = dict(link)
    item["metadata"] = _json_loads_safe(item.get("metadata_json"), {})
    return item


class CloudAccountCreate(BaseModel):
    provider: str
    name: str = Field(min_length=1)
    account_identifier: str = ""
    region_scope: str = ""
    auth_type: str = "manual"
    auth_config: dict = Field(default_factory=dict)
    notes: str = ""
    enabled: bool = True


class CloudAccountUpdate(BaseModel):
    provider: str | None = None
    name: str | None = None
    account_identifier: str | None = None
    region_scope: str | None = None
    auth_type: str | None = None
    auth_config: dict | None = None
    notes: str | None = None
    enabled: bool | None = None


class CloudDiscoveryRequest(BaseModel):
    mode: str = "sample"
    connect_host_ids: list[int] = Field(default_factory=list)
    include_hybrid_links: bool = True


def _sample_snapshot_for_provider(provider: str) -> tuple[list[dict], list[dict]]:
    if provider == "aws":
        resources = [
            {"resource_uid": "aws:vpc:core", "resource_type": "vpc", "name": "prod-core-vpc", "region": "us-east-1", "cidr": "10.200.0.0/16", "status": "active"},
            {"resource_uid": "aws:tgw:global", "resource_type": "transit_gateway", "name": "global-tgw", "region": "us-east-1", "status": "active"},
            {"resource_uid": "aws:dx:primary", "resource_type": "direct_connect", "name": "dx-primary", "region": "us-east-1", "status": "up"},
            {"resource_uid": "aws:sg:app-edge", "resource_type": "security_group", "name": "sg-app-edge", "region": "us-east-1", "status": "active"},
        ]
        connections = [
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:tgw:global", "connection_type": "transit_gateway_attachment", "state": "attached"},
            {"source_resource_uid": "aws:tgw:global", "target_resource_uid": "aws:dx:primary", "connection_type": "direct_connect_gateway", "state": "up"},
            {"source_resource_uid": "aws:vpc:core", "target_resource_uid": "aws:sg:app-edge", "connection_type": "security_boundary", "state": "enforced"},
        ]
        return resources, connections

    if provider == "azure":
        resources = [
            {"resource_uid": "azure:vnet:core", "resource_type": "vnet", "name": "corp-core-vnet", "region": "centralus", "cidr": "10.210.0.0/16", "status": "connected"},
            {"resource_uid": "azure:vnet:shared", "resource_type": "vnet", "name": "shared-services-vnet", "region": "centralus", "cidr": "10.211.0.0/16", "status": "connected"},
            {"resource_uid": "azure:er:primary", "resource_type": "expressroute", "name": "er-primary", "region": "centralus", "status": "provisioned"},
            {"resource_uid": "azure:nsg:edge", "resource_type": "network_security_group", "name": "nsg-edge", "region": "centralus", "status": "active"},
        ]
        connections = [
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:vnet:shared", "connection_type": "vnet_peering", "state": "connected"},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:er:primary", "connection_type": "expressroute_gateway", "state": "up"},
            {"source_resource_uid": "azure:vnet:core", "target_resource_uid": "azure:nsg:edge", "connection_type": "security_boundary", "state": "enforced"},
        ]
        return resources, connections

    resources = [
        {"resource_uid": "gcp:vpc:core", "resource_type": "vpc", "name": "gcp-core-vpc", "region": "us-central1", "cidr": "10.220.0.0/16", "status": "active"},
        {"resource_uid": "gcp:router:core", "resource_type": "cloud_router", "name": "cr-core", "region": "us-central1", "status": "running"},
        {"resource_uid": "gcp:vpn:ha", "resource_type": "ha_vpn_gateway", "name": "ha-vpn-gw", "region": "us-central1", "status": "up"},
        {"resource_uid": "gcp:fw:edge", "resource_type": "firewall_policy", "name": "fw-edge-policy", "region": "global", "status": "active"},
    ]
    connections = [
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:router:core", "connection_type": "router_attachment", "state": "up"},
        {"source_resource_uid": "gcp:router:core", "target_resource_uid": "gcp:vpn:ha", "connection_type": "vpn_tunnel", "state": "up"},
        {"source_resource_uid": "gcp:vpc:core", "target_resource_uid": "gcp:fw:edge", "connection_type": "security_boundary", "state": "enforced"},
    ]
    return resources, connections


async def _build_sample_discovery_snapshot(
    account: dict,
    connect_host_ids: list[int],
    include_hybrid_links: bool,
) -> tuple[list[dict], list[dict], list[dict]]:
    provider = str(account.get("provider") or "").strip().lower()
    resources, connections = _sample_snapshot_for_provider(provider)
    hybrid_links: list[dict] = []
    if not include_hybrid_links:
        return resources, connections, hybrid_links

    hosts = []
    if connect_host_ids:
        hosts = await db.get_hosts_by_ids([int(hid) for hid in connect_host_ids if int(hid) > 0])
    if not hosts:
        hosts = (await db.get_all_hosts())[:2]

    entry_resource_uid = ""
    if provider == "aws":
        entry_resource_uid = "aws:dx:primary"
    elif provider == "azure":
        entry_resource_uid = "azure:er:primary"
    else:
        entry_resource_uid = "gcp:vpn:ha"

    entry_link_type = {"aws": "direct_connect", "azure": "expressroute", "gcp": "vpn"}.get(provider, "vpn")
    for host in hosts:
        hybrid_links.append(
            {
                "host_id": host.get("id"),
                "host_label": host.get("hostname") or host.get("ip_address") or f"host-{host.get('id')}",
                "cloud_resource_uid": entry_resource_uid,
                "connection_type": entry_link_type,
                "state": "up",
                "metadata": {
                    "source": "sample",
                    "host_ip": host.get("ip_address"),
                },
            }
        )

    return resources, connections, hybrid_links


@router.get("/api/cloud/providers")
async def cloud_providers_api():
    providers = [
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "focus_constructs": ["VPC", "Transit Gateway", "Direct Connect", "Security Groups"],
        },
        {
            "id": "azure",
            "name": "Microsoft Azure",
            "focus_constructs": ["VNet", "VNet Peering", "ExpressRoute", "NSG"],
        },
        {
            "id": "gcp",
            "name": "Google Cloud Platform",
            "focus_constructs": ["VPC", "Cloud Router", "HA VPN", "Firewall Policies"],
        },
    ]
    return {"providers": providers, "count": len(providers)}


@router.get("/api/cloud/accounts")
async def cloud_accounts_api(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=False),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    accounts = await db.list_cloud_accounts(provider=normalized_provider, enabled_only=enabled_only)
    return {"accounts": [_serialize_account(a) for a in accounts], "count": len(accounts)}


@router.post("/api/cloud/accounts", status_code=201, dependencies=[Depends(_require_admin_dep)])
async def create_cloud_account_api(body: CloudAccountCreate, request: Request):
    try:
        provider = _normalize_provider(body.provider)
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    session = _get_session(request) or {}
    user = session.get("user", "")
    account = await db.create_cloud_account(
        provider=provider,
        name=body.name.strip(),
        account_identifier=body.account_identifier.strip(),
        region_scope=body.region_scope.strip(),
        auth_type=body.auth_type.strip() or "manual",
        auth_config_json=body.auth_config,
        notes=body.notes.strip(),
        enabled=1 if body.enabled else 0,
        created_by=user,
    )
    if not account:
        raise HTTPException(status_code=500, detail="Failed to create cloud account")

    await _audit(
        "cloud_visibility",
        "create_account",
        user=user,
        detail=f"{provider}:{body.name.strip()}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "account": _serialize_account(account)}


@router.put("/api/cloud/accounts/{account_id}", dependencies=[Depends(_require_admin_dep)])
async def update_cloud_account_api(account_id: int, body: CloudAccountUpdate, request: Request):
    existing = await db.get_cloud_account(account_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    updates = body.model_dump(exclude_none=True)
    if "provider" in updates:
        try:
            updates["provider"] = _normalize_provider(updates.get("provider"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None
    if "auth_config" in updates:
        updates["auth_config_json"] = updates.pop("auth_config")

    updated = await db.update_cloud_account(account_id, **updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "update_account",
        user=session.get("user", ""),
        detail=f"account_id={account_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "account": _serialize_account(updated)}


@router.delete("/api/cloud/accounts/{account_id}", dependencies=[Depends(_require_admin_dep)])
async def delete_cloud_account_api(account_id: int, request: Request):
    existing = await db.get_cloud_account(account_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    deleted = await db.delete_cloud_account(account_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "delete_account",
        user=session.get("user", ""),
        detail=f"account_id={account_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/cloud/accounts/{account_id}/discover", dependencies=[Depends(_require_admin_dep)])
async def discover_cloud_account_api(account_id: int, request: Request, body: CloudDiscoveryRequest | None = None):
    account = await db.get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    payload = body or CloudDiscoveryRequest()
    mode = (payload.mode or "sample").strip().lower()
    if mode != "sample":
        raise HTTPException(status_code=400, detail="Only 'sample' discovery mode is currently supported")

    try:
        resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
            account,
            payload.connect_host_ids,
            payload.include_hybrid_links,
        )
        summary = await db.replace_cloud_discovery_snapshot(
            account_id,
            resources=resources,
            connections=connections,
            hybrid_links=hybrid_links,
            sync_status="success",
            sync_message="Sample discovery snapshot refreshed",
        )
    except Exception:
        LOGGER.error("cloud visibility discovery failed for account_id=%s", account_id, exc_info=True)
        await db.set_cloud_account_sync_status(
            account_id,
            status="error",
            message="Discovery failed. Check server logs for details.",
        )
        raise HTTPException(status_code=500, detail="Cloud discovery failed") from None

    session = _get_session(request) or {}
    await _audit(
        "cloud_visibility",
        "discover_snapshot",
        user=session.get("user", ""),
        detail=f"account_id={account_id} mode={mode}",
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "account_id": account_id,
        "mode": mode,
        "summary": summary,
    }


@router.get("/api/cloud/resources")
async def cloud_resources_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    resources = await db.get_cloud_resources(
        account_id=account_id,
        provider=normalized_provider,
        resource_type=(resource_type.strip() if resource_type else None),
    )
    return {"resources": [_serialize_resource(r) for r in resources], "count": len(resources)}


@router.get("/api/cloud/connections")
async def cloud_connections_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    connections = await db.get_cloud_connections(account_id=account_id, provider=normalized_provider)
    return {"connections": [_serialize_connection(c) for c in connections], "count": len(connections)}


@router.get("/api/cloud/hybrid-links")
async def cloud_hybrid_links_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    links = await db.get_cloud_hybrid_links(account_id=account_id, provider=normalized_provider)
    return {"links": [_serialize_hybrid_link(link) for link in links], "count": len(links)}


@router.get("/api/cloud/topology")
async def cloud_topology_api(
    account_id: int | None = Query(default=None),
    provider: str | None = Query(default=None),
):
    try:
        normalized_provider = _normalize_provider(provider) if provider else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported cloud provider") from None

    snapshot = await db.get_cloud_topology_snapshot(account_id=account_id, provider=normalized_provider)
    return {
        "accounts": [_serialize_account(a) for a in snapshot.get("accounts", []) if a],
        "resources": [_serialize_resource(r) for r in snapshot.get("resources", [])],
        "connections": [_serialize_connection(c) for c in snapshot.get("connections", [])],
        "hybrid_links": [_serialize_hybrid_link(link) for link in snapshot.get("hybrid_links", [])],
        "summary": snapshot.get("summary", {}),
    }
