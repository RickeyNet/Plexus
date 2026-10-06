"""
meraki_topology.py -- Meraki support for the Topology feature.

The newest snapshot of every Meraki organization is merged into the graph
served by ``/api/topology`` (see ``netcontrol.routes.topology``), so Meraki
devices live on the same map as SNMP-discovered ones. This module provides
what feeds and surrounds that merge:

  - Meraki organization CRUD (Dashboard API key is write-only, stored encrypted)
  - Cato Networks accounts, which are stored and collected like an
    organization (``provider`` "cato") and produce the same snapshot format
  - Cisco FMCs for AnyConnect remote access VPN, stored and collected the
    same way (``provider`` "anyconnect")
  - AWS and Azure: the accounts Cloud Visibility discovers are turned into
    one more snapshot per cloud (``provider`` "aws" / "azure") whenever their
    discovery changes
  - On-demand collection builds as background jobs with pollable progress
  - Stored snapshots: list / fetch JSON / delete, and an in-memory cache of
    the latest one per organization
  - Per-node Meraki detail sections and whole-map deep search
  - The list of everything that feeds the map (``/api/topology/sources``):
    neighbor discovery, organizations and accounts, with their last collection
  - Self-contained interactive HTML export of the whole topology

Registered under the ``topology`` feature: reads need ``topology``, builds
and deletes need ``topology.write``, organization (credential) management
needs admin.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from netcontrol.integrations.anyconnect.client import (
    FmcApiError,
    FmcClient,
    validate_base_url as validate_fmc_base_url,
)
from netcontrol.integrations.anyconnect.collector import (
    DEFAULT_OPTIONS as ANYCONNECT_DEFAULT_OPTIONS,
    collect_fmc,
    sanitize_options as sanitize_anyconnect_options,
)
from netcontrol.integrations.anyconnect.normalize import build_snapshot as build_anyconnect_snapshot
from netcontrol.integrations.anyconnect.sample import build_sample_raw as build_anyconnect_sample_raw
from netcontrol.integrations.aws.normalize import build_snapshot as build_aws_snapshot
from netcontrol.integrations.aws.reachability import Reachability
from netcontrol.integrations.aws.sample import build_sample as build_aws_sample
from netcontrol.integrations.azure.normalize import build_snapshot as build_azure_snapshot
from netcontrol.integrations.azure.reachability import Reachability as AzureReachability
from netcontrol.integrations.azure.sample import build_sample as build_azure_sample
from netcontrol.integrations.cato.client import (
    DEFAULT_BASE_URL as CATO_BASE_URL,
    CatoApiError,
    CatoClient,
    validate_base_url as validate_cato_base_url,
)
from netcontrol.integrations.cato.collector import (
    DEFAULT_OPTIONS as CATO_DEFAULT_OPTIONS,
    VALIDATE_QUERY as CATO_VALIDATE_QUERY,
    collect_account,
    sanitize_options as sanitize_cato_options,
)
from netcontrol.integrations.cato.normalize import build_snapshot as build_cato_snapshot
from netcontrol.integrations.cato.sample import build_sample_raw as build_cato_sample_raw
from netcontrol.integrations.meraki.client import (
    DEFAULT_BASE_URL,
    MerakiApiError,
    MerakiClient,
    validate_base_url,
)
from netcontrol.integrations.meraki.clients import client_records
from netcontrol.integrations.meraki.collector import DEFAULT_OPTIONS, collect_organization, sanitize_options
from netcontrol.integrations.meraki.enrich import collected_sections, enrich_snapshot, load_inventory_index
from netcontrol.integrations.meraki.html_export import EXPORT_CSP, export_filename, render_topology_html
from netcontrol.integrations.meraki.normalize import build_snapshot
from netcontrol.integrations.meraki.sample import build_sample_raw
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import (
    build_search_index,
    graph_to_snapshot,
    node_details,
    search_index,
    virtual_appliance_pairs,
)
from netcontrol.integrations.meraki.vpn_reach import VpnCarrier
from netcontrol.routes import background_jobs
from netcontrol.routes.shared import _audit, _corr_id, _get_session, supervise_task
from netcontrol.telemetry import configure_logging, redact_value

router = APIRouter()
LOGGER = configure_logging("plexus.meraki")

_JOB_KIND = "meraki-topology-build"
# Snapshots are multi-megabyte JSON blobs; keep a short history per org.
_SNAPSHOTS_KEPT_PER_ORG = 10
SAMPLE_ORG_NAME = "Sample Organization (demo data)"
SAMPLE_CATO_NAME = "Sample Cato Account (demo data)"
SAMPLE_ANYCONNECT_NAME = "Sample AnyConnect FMC (demo data)"
SAMPLE_AWS_NAME = "Sample AWS Account (demo data)"
SAMPLE_AZURE_NAME = "Sample Azure Subscription (demo data)"
# Marks the demo AWS and Azure accounts, which scheduled discovery leaves alone.
SAMPLE_AWS_AUTH_TYPE = "sample"
# The demo FMC address: a documentation range, never contacted.
SAMPLE_FMC_URL = "https://10.210.2.20"

PROVIDER_MERAKI = "meraki"
PROVIDER_CATO = "cato"
# A Cisco FMC whose FTDs terminate AnyConnect remote access VPN.
PROVIDER_ANYCONNECT = "anyconnect"
PROVIDERS = (PROVIDER_MERAKI, PROVIDER_CATO, PROVIDER_ANYCONNECT)
SAMPLE_ORG_NAMES = (SAMPLE_ORG_NAME, SAMPLE_CATO_NAME, SAMPLE_ANYCONNECT_NAME)
# Not organization providers: AWS and Azure accounts are Cloud Visibility accounts.
PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"

_require_admin = None

# org_ref -> job_id of the build currently running for that organization.
_running_builds: dict[int, str] = {}

# snapshot_id -> {"snapshot": dict, "index": search index | None}. Only the
# latest snapshot of each organization is held: it is parsed once from its
# multi-megabyte JSON row and then reused by every topology build, node-detail
# click and search. Snapshots are immutable, so entries never go stale; they
# are dropped when a newer build replaces them.
_SNAPSHOT_CACHE: dict[int, dict[str, Any]] = {}

# AWS and Azure accounts belong to Cloud Visibility, not to ``meraki_orgs``.
# What the accounts of one cloud discovered is built into one snapshot for all
# of them and referenced by an ``org_ref`` (and cache key) no organization or
# stored snapshot can have.
AWS_ORG_REF = -1
AZURE_ORG_REF = -2
_AWS_ACCOUNT_FIELDS = ("id", "name", "account_identifier", "last_sync_at", "last_sync_status", "last_sync_message")


class _Cloud:
    """How the accounts of one cloud of Cloud Visibility reach the map."""

    def __init__(
        self, provider: str, org_ref: int, label: str, build, reachability, sample, sample_name: str, sample_scope: str
    ):
        self.provider = provider
        self.org_ref = org_ref
        self.label = label
        self.build = build
        self.reachability = reachability
        self.sample = sample
        self.sample_name = sample_name
        self.sample_scope = sample_scope


# Merged in this order, after every organization: their gateways and
# appliances are matched against what the other snapshots already put on the map.
CLOUDS = (
    _Cloud(
        PROVIDER_AWS,
        AWS_ORG_REF,
        "AWS",
        build_aws_snapshot,
        Reachability,
        build_aws_sample,
        SAMPLE_AWS_NAME,
        "us-east-1,us-west-2",
    ),
    _Cloud(
        PROVIDER_AZURE,
        AZURE_ORG_REF,
        "Azure",
        build_azure_snapshot,
        AzureReachability,
        build_azure_sample,
        SAMPLE_AZURE_NAME,
        "",
    ),
)
_CLOUD_BY_PROVIDER = {cloud.provider: cloud for cloud in CLOUDS}
_CLOUD_ORG_REFS = {cloud.org_ref for cloud in CLOUDS}


async def _cloud_entry(cloud: _Cloud) -> dict[str, Any] | None:
    """The snapshot of every enabled account of ``cloud`` that has been
    discovered, rebuilt when a discovery, or the set of accounts, changes."""
    accounts = [
        {key: account.get(key) for key in (*_AWS_ACCOUNT_FIELDS, "resource_count", "connection_count")}
        for account in await db.list_cloud_accounts(provider=cloud.provider, enabled_only=True)
        if account.get("resource_count")
    ]
    if not accounts:
        return None
    signature = tuple(tuple(account.values()) for account in accounts)
    entry = _SNAPSHOT_CACHE.get(cloud.org_ref)
    if entry is None or entry.get("signature") != signature:
        wanted = {account["id"] for account in accounts}
        resources = [r for r in await db.get_cloud_resources(provider=cloud.provider) if r.get("account_id") in wanted]
        connections = [
            c for c in await db.get_cloud_connections(provider=cloud.provider) if c.get("account_id") in wanted
        ]
        inventory = await load_inventory_index()
        # Layout of a large account is CPU-bound; keep it off the event loop.
        snapshot = await asyncio.to_thread(cloud.build, accounts, resources, connections, inventory)
        entry = _SNAPSHOT_CACHE[cloud.org_ref] = {
            "snapshot": snapshot,
            "index": None,
            "signature": signature,
            # Routes and filtering rules, for the Path Mode check.
            "reachability": cloud.reachability(resources, connections),
        }
    return entry


async def _latest_entries() -> list[tuple[int, dict[str, Any]]]:
    latest = await db.get_latest_meraki_snapshot_ids()
    wanted = {snapshot_id for _org_ref, snapshot_id in latest} | _CLOUD_ORG_REFS
    for stale in set(_SNAPSHOT_CACHE) - wanted:
        _SNAPSHOT_CACHE.pop(stale, None)
    entries: list[tuple[int, dict[str, Any]]] = []
    for org_ref, snapshot_id in latest:
        entry = _SNAPSHOT_CACHE.get(snapshot_id)
        if entry is None:
            row = await db.get_meraki_snapshot(snapshot_id)
            if not row:
                continue
            entry = _SNAPSHOT_CACHE[snapshot_id] = {"snapshot": row["snapshot"], "index": None}
        entries.append((org_ref, entry))
    # The clouds go last: their VPN peers and appliances are matched against
    # what the other snapshots already put on the map. Best-effort, like the
    # merge itself: a problem with cloud data must not hide the rest.
    for cloud in CLOUDS:
        try:
            found = await _cloud_entry(cloud)
        except Exception as exc:  # noqa: BLE001
            found = None
            LOGGER.warning("%s: topology snapshot skipped: %s", cloud.provider, type(exc).__name__, exc_info=True)
        if found is None:
            _SNAPSHOT_CACHE.pop(cloud.org_ref, None)
        else:
            entries.append((cloud.org_ref, found))
    return entries


async def latest_snapshots() -> list[tuple[int, dict]]:
    """``(org_ref, snapshot)`` for the newest snapshot of every organization."""
    return [(org_ref, entry["snapshot"]) for org_ref, entry in await _latest_entries()]


async def _subnets_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """The subnet index of a cached snapshot, built once per snapshot."""
    if entry.get("subnets") is None:
        entry["subnets"] = await asyncio.to_thread(subnet_index, entry["snapshot"])
    return entry["subnets"]


async def ipam_subnets() -> list[dict[str, Any]]:
    """The subnets of the latest snapshot of every organization and account,
    for the IPAM overview: the ``subnet_index`` rows (Meraki VLANs, single
    LANs, SVIs and static routes, Cato network ranges, AnyConnect address
    pools) with their organization and provider. AWS and Azure are left
    out: their networks and subnets reach IPAM as Cloud Visibility resources
    already."""
    rows: list[dict[str, Any]] = []
    for org_ref, entry in await _latest_entries():
        if org_ref in _CLOUD_ORG_REFS:
            continue
        snapshot = entry["snapshot"]
        org = snapshot.get("org") or {}
        provider = str(snapshot.get("provider") or PROVIDER_MERAKI)
        org_name = str(org.get("name") or "")
        rows.extend(
            {"org_ref": org_ref, "org_name": org_name, "provider": provider, **subnet}
            for subnet in await _subnets_of(entry)
        )
    return rows


def _topology_changed() -> None:
    """Meraki data feeding the merged graph changed; drop the graph cache."""
    from netcontrol.routes.topology import invalidate_topology_cache

    invalidate_topology_cache()


async def _software_changed() -> None:
    """A collection was stored: bring the software version tracker up to
    date with it. Best-effort; the snapshot is already saved."""
    from netcontrol.routes.software import refresh_after_collection

    await refresh_after_collection()


def init_meraki_topology(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


def _session_user(request: Request) -> str:
    return (_get_session(request) or {}).get("user", "")


class MerakiOrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    # "meraki" (organization), "cato" (account) or "anyconnect" (FMC). Fixed once created.
    provider: str = Field(default=PROVIDER_MERAKI, max_length=20)
    org_id: str = Field(default="", max_length=64)
    base_url: str = Field(default="", max_length=200)
    api_key: str = Field(default="", max_length=400)
    options: dict = Field(default_factory=dict)


class MerakiOrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    org_id: str | None = Field(default=None, max_length=64)
    base_url: str | None = Field(default=None, max_length=200)
    # Write-only: an empty/omitted key means "keep the stored one".
    api_key: str | None = Field(default=None, max_length=400)
    options: dict | None = None


def _provider_of(org: dict) -> str:
    provider = str(org.get("provider") or PROVIDER_MERAKI)
    return provider if provider in PROVIDERS else PROVIDER_MERAKI


def _clean_base_url(raw: str | None, provider: str = PROVIDER_MERAKI) -> str:
    if provider == PROVIDER_ANYCONNECT:
        try:
            return validate_fmc_base_url(raw or "")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="FMC address must be an https URL of the FMC host only (for example https://fmc.example.com)",
            ) from None
    if provider == PROVIDER_CATO:
        try:
            return validate_cato_base_url(raw or CATO_BASE_URL)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"API URL must be an https Cato API URL (for example {CATO_BASE_URL})",
            ) from None
    try:
        return validate_base_url(raw or DEFAULT_BASE_URL)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="API base URL must be an https Meraki Dashboard API URL (for example https://api.meraki.com/api/v1)",
        ) from None


def _options_for(provider: str, raw: object) -> dict[str, Any]:
    if provider == PROVIDER_CATO:
        return sanitize_cato_options(raw)
    if provider == PROVIDER_ANYCONNECT:
        return sanitize_anyconnect_options(raw)
    return sanitize_options(raw)


def _serialize_org(org: dict) -> dict:
    item = dict(org)
    item["provider"] = _provider_of(org)
    item["options"] = _options_for(item["provider"], item.get("options"))
    item["building"] = org["id"] in _running_builds
    return item


async def _get_org_or_404(org_ref: int) -> dict:
    org = await db.get_meraki_org(org_ref)
    if not org:
        raise HTTPException(status_code=404, detail="Meraki organization not found")
    return org


def _cato_error_message(exc: CatoApiError) -> str:
    if exc.status_code in (401, 403):
        return f"Cato rejected the API key (HTTP {exc.status_code})"
    if exc.graphql:
        # ``detail`` is the message the Cato API answered with.
        return f"Cato refused the request: {exc.detail}" if exc.detail else "Cato refused the request"
    if exc.status_code is None:
        return "Could not reach the Cato API"
    return f"Cato API error (HTTP {exc.status_code})"


def _fmc_error_message(exc: FmcApiError) -> str:
    # ``detail`` is the description the FMC answered with.
    detail = f": {exc.detail}" if exc.detail else ""
    if exc.status_code in (401, 403):
        return f"The FMC rejected the credentials (HTTP {exc.status_code}){detail}"
    if exc.status_code is None:
        # Transport failures and client-side checks (unknown domain).
        return f"{exc}{detail}"
    return f"FMC API error (HTTP {exc.status_code}){detail}"


def _api_error_message(exc: MerakiApiError) -> str:
    if exc.status_code == 401:
        return "Meraki rejected the API key (HTTP 401)"
    if exc.status_code in (403, 404):
        return f"The API key has no access to this organization (HTTP {exc.status_code})"
    if exc.status_code is None:
        return "Could not reach the Meraki Dashboard API"
    return f"Meraki Dashboard API error (HTTP {exc.status_code})"


# ── Organizations ────────────────────────────────────────────────────────────


@router.get("/api/meraki/orgs")
async def list_meraki_orgs_api():
    orgs = await db.list_meraki_orgs()
    return {
        "orgs": [_serialize_org(o) for o in orgs],
        "default_options": dict(DEFAULT_OPTIONS),
        "cato_default_options": dict(CATO_DEFAULT_OPTIONS),
        "anyconnect_default_options": dict(ANYCONNECT_DEFAULT_OPTIONS),
    }


@router.post("/api/meraki/orgs", status_code=201, dependencies=[Depends(_require_admin_dep)])
async def create_meraki_org_api(body: MerakiOrgCreate, request: Request):
    user = _session_user(request)
    provider = body.provider.strip().lower() or PROVIDER_MERAKI
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="Provider must be meraki, cato or anyconnect")
    org = await db.create_meraki_org(
        body.name.strip(),
        provider=provider,
        org_id=body.org_id.strip(),
        base_url=_clean_base_url(body.base_url, provider),
        api_key=body.api_key.strip(),
        options=_options_for(provider, body.options),
        created_by=user,
    )
    if not org:
        raise HTTPException(status_code=409, detail="An organization or account with this name already exists")
    await _audit(
        "meraki_topology",
        "create_org",
        user=user,
        detail=f"{org['name']} ({provider})",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "org": _serialize_org(org)}


@router.put("/api/meraki/orgs/{org_ref}", dependencies=[Depends(_require_admin_dep)])
async def update_meraki_org_api(org_ref: int, body: MerakiOrgUpdate, request: Request):
    provider = _provider_of(await _get_org_or_404(org_ref))
    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name.strip()
    if body.org_id is not None:
        updates["org_id"] = body.org_id.strip()
    if body.base_url is not None:
        updates["base_url"] = _clean_base_url(body.base_url, provider)
    if body.api_key and body.api_key.strip():
        updates["api_key"] = body.api_key.strip()
    if body.options is not None:
        updates["options"] = _options_for(provider, body.options)
    org = await db.update_meraki_org(org_ref, **updates)
    if not org:
        raise HTTPException(status_code=409, detail="An organization or account with this name already exists")
    await _audit(
        "meraki_topology",
        "update_org",
        user=_session_user(request),
        detail=f"org_ref={org_ref} fields={','.join(sorted(updates))}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "org": _serialize_org(org)}


@router.delete("/api/meraki/orgs/{org_ref}", dependencies=[Depends(_require_admin_dep)])
async def delete_meraki_org_api(org_ref: int, request: Request):
    org = await _get_org_or_404(org_ref)
    if org_ref in _running_builds:
        raise HTTPException(status_code=409, detail="A topology build is running for this organization")
    await db.delete_meraki_org(org_ref)
    _topology_changed()
    await _audit(
        "meraki_topology",
        "delete_org",
        user=_session_user(request),
        detail=org["name"],
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/meraki/orgs/{org_ref}/validate", dependencies=[Depends(_require_admin_dep)])
async def validate_meraki_org_api(org_ref: int):
    """Check the stored API key and list the organizations it can see."""
    org = await _get_org_or_404(org_ref)
    api_key = await db.get_meraki_org_api_key(org_ref)
    if not api_key:
        return {"ok": False, "message": "No API key is stored for this organization", "organizations": []}
    if _provider_of(org) == PROVIDER_CATO:
        return await _validate_cato(org, api_key)
    if _provider_of(org) == PROVIDER_ANYCONNECT:
        return await _validate_anyconnect(org, api_key)
    try:
        async with MerakiClient(api_key, base_url=org["base_url"] or DEFAULT_BASE_URL, max_retries=1) as client:
            visible = await client.get_all("organizations")
    except MerakiApiError as exc:
        return {"ok": False, "message": _api_error_message(exc), "organizations": []}
    organizations = [
        {"id": str(o.get("id") or ""), "name": str(o.get("name") or "")} for o in visible if isinstance(o, dict)
    ]
    configured = str(org.get("org_id") or "")
    if configured and configured not in {o["id"] for o in organizations}:
        return {
            "ok": False,
            "message": f"The API key is valid but cannot see organization ID {configured}",
            "organizations": organizations,
        }
    if not configured and len(organizations) != 1:
        return {
            "ok": False,
            "message": "The API key can see several organizations; set the Organization ID to pick one",
            "organizations": organizations,
        }
    return {"ok": True, "message": "API key is valid", "organizations": organizations}


async def _validate_cato(org: dict, api_key: str) -> dict:
    account = str(org.get("org_id") or "").strip()
    if not account:
        return {"ok": False, "message": "Set the Cato account ID on this entry", "organizations": []}
    try:
        async with CatoClient(api_key, base_url=org["base_url"] or CATO_BASE_URL, max_retries=1) as client:
            await client.query("plexusValidate", CATO_VALIDATE_QUERY, {"accountID": account})
    except CatoApiError as exc:
        return {"ok": False, "message": _cato_error_message(exc), "organizations": []}
    return {
        "ok": True,
        "message": "API key is valid for this account",
        "organizations": [{"id": account, "name": org["name"]}],
    }


def _fmc_client(org: dict, password: str, options: dict, **kwargs: Any) -> FmcClient:
    """An FMC client for an entry. The username lives in the options, the
    password is the entry's write-only secret."""
    username = str(options.get("username") or "").strip()
    if not username:
        raise ValueError("Set the FMC username on this entry")
    return FmcClient(
        org.get("base_url") or "",
        username,
        password,
        verify_tls=bool(options.get("verify_tls", True)),
        **kwargs,
    )


async def _validate_anyconnect(org: dict, password: str) -> dict:
    options = sanitize_anyconnect_options(org.get("options"))
    try:
        async with _fmc_client(org, password, options, max_retries=1) as client:
            await client.login()
            domain = client.resolve_domain(str(org.get("org_id") or ""))
            domains = [{"id": d["uuid"], "name": d["name"]} for d in client.domains]
    except FmcApiError as exc:
        return {"ok": False, "message": _fmc_error_message(exc), "organizations": []}
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "organizations": []}
    return {
        "ok": True,
        "message": f"Signed in to the FMC; collecting domain {domain['name']}",
        "organizations": domains,
    }


# ── Builds ───────────────────────────────────────────────────────────────────


async def _collect_anyconnect(org: dict, password: str, options: dict, progress) -> dict:
    async with _fmc_client(org, password, options) as client:
        raw = await collect_fmc(client, str(org.get("org_id") or ""), options, progress)
    raw["fmc"]["name"] = org["name"]
    return raw


async def _collect_cato(org: dict, api_key: str, options: dict, progress) -> dict:
    account = str(org.get("org_id") or "").strip()
    if not account:
        raise ValueError("Set the Cato account ID on this entry")
    async with CatoClient(api_key, base_url=org.get("base_url") or CATO_BASE_URL) as client:
        raw = await collect_account(client, account, options, progress)
    raw["account"]["name"] = org["name"]
    return raw


async def _resolve_org_id(client: MerakiClient, org: dict) -> str:
    configured = str(org.get("org_id") or "").strip()
    if configured:
        return configured
    visible = [o for o in await client.get_all("organizations") if isinstance(o, dict) and o.get("id")]
    if len(visible) != 1:
        raise ValueError(
            f"The API key can see {len(visible)} organizations; set the Organization ID on this entry to pick one"
        )
    resolved = str(visible[0]["id"])
    await db.update_meraki_org(org["id"], org_id=resolved)
    return resolved


async def _store_snapshot(org: dict, snapshot: dict, *, user: str, started: float) -> dict:
    duration = round(time.monotonic() - started, 1)
    snapshot_id = await db.create_meraki_snapshot(org["id"], snapshot, built_by=user, duration_seconds=duration)
    await db.prune_meraki_snapshots(org["id"], _SNAPSHOTS_KEPT_PER_ORG)
    warnings = len((snapshot.get("collection") or {}).get("errors") or [])
    await db.update_meraki_org(
        org["id"],
        last_build_at=datetime.now(UTC).isoformat(),
        last_build_status="partial" if warnings else "success",
        last_build_message=f"{warnings} collection warning(s)" if warnings else "",
    )
    _topology_changed()
    await _software_changed()
    return {
        "snapshot_id": snapshot_id,
        "summary": snapshot.get("summary") or {},
        "warning_count": warnings,
        "duration_seconds": duration,
    }


async def _track_clients(org: dict, raw: dict) -> int:
    """Feed the clients of a collection to MAC tracking. Never fails a build."""
    try:
        return await db.upsert_meraki_clients(org["id"], client_records(raw))
    except Exception as exc:  # noqa: BLE001 - the map is already stored
        LOGGER.warning("meraki: could not store clients of org %s: %s", org["name"], type(exc).__name__)
        return 0


_SNAPSHOT_BUILDERS = {
    PROVIDER_MERAKI: build_snapshot,
    PROVIDER_CATO: build_cato_snapshot,
    PROVIDER_ANYCONNECT: build_anyconnect_snapshot,
}


async def _run_build(job_id: str, org: dict, user: str) -> None:
    """Background task: collect -> normalise -> enrich -> store."""
    org_ref = org["id"]
    started = time.monotonic()
    provider = _provider_of(org)
    options = _options_for(provider, org.get("options"))

    def progress(fields: dict) -> None:
        background_jobs.update_progress(job_id, **fields)

    error: str | None = None
    try:
        api_key = await db.get_meraki_org_api_key(org_ref)
        if not api_key:
            raise ValueError("No API key is stored for this organization")
        if provider == PROVIDER_CATO:
            raw = await _collect_cato(org, api_key, options, progress)
        elif provider == PROVIDER_ANYCONNECT:
            raw = await _collect_anyconnect(org, api_key, options, progress)
        else:
            async with MerakiClient(
                api_key,
                base_url=org.get("base_url") or DEFAULT_BASE_URL,
                max_concurrency=options["max_concurrency"],
                requests_per_second=options["requests_per_second"],
            ) as client:
                org_id = await _resolve_org_id(client, org)
                raw = await collect_organization(client, org_id, options, progress)

        progress({"phase": "building map"})
        inventory = await load_inventory_index() if options["inventory_enrich"] else None
        # Layout of a large organization is CPU-bound; keep it off the event loop.
        builder = _SNAPSHOT_BUILDERS.get(provider, build_snapshot)
        snapshot = await asyncio.to_thread(builder, raw, inventory)
        if options["inventory_enrich"]:
            await enrich_snapshot(snapshot, ssh=bool(options.get("ssh_enrich")), progress=progress)

        progress({"phase": "saving"})
        result = await _store_snapshot(org, snapshot, user=user, started=started)
        if provider == PROVIDER_MERAKI:
            result["clients_tracked"] = await _track_clients(org, raw)
        background_jobs.finish_job(job_id, "partial" if result["warning_count"] else "completed", result=result)
        await _audit(
            "meraki_topology",
            "build",
            user=user,
            detail=f"org={org['name']} snapshot_id={result['snapshot_id']} warnings={result['warning_count']}",
        )
        return
    except MerakiApiError as exc:
        error = _api_error_message(exc)
        LOGGER.warning("meraki: build failed for org %s: %s", org["name"], redact_value(str(exc)))
    except CatoApiError as exc:
        error = _cato_error_message(exc)
        LOGGER.warning("cato: build failed for account %s: %s", org["name"], redact_value(f"{exc} {exc.detail}"))
    except FmcApiError as exc:
        error = _fmc_error_message(exc)
        LOGGER.warning("anyconnect: build failed for FMC %s: %s", org["name"], redact_value(f"{exc} {exc.detail}"))
    except ValueError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 - job must always reach a terminal state
        error = "Topology build failed; see the server log for details"
        LOGGER.exception("meraki: build crashed for org %s: %s", org["name"], type(exc).__name__)
    finally:
        _running_builds.pop(org_ref, None)

    await db.update_meraki_org(
        org_ref,
        last_build_at=datetime.now(UTC).isoformat(),
        last_build_status="failed",
        last_build_message=error or "",
    )
    background_jobs.finish_job(job_id, "failed", error=error)


@router.post("/api/meraki/orgs/{org_ref}/build", status_code=202)
async def build_meraki_topology_api(org_ref: int, request: Request):
    """Start a Meraki collection build. Poll ``/api/meraki/builds/{job_id}`` for progress."""
    org = await _get_org_or_404(org_ref)
    if not org.get("has_api_key"):
        raise HTTPException(status_code=400, detail="No API key is stored for this organization")
    # Check-then-set with no await in between: atomic under asyncio.
    if org_ref in _running_builds:
        raise HTTPException(status_code=409, detail="A topology build is already running for this organization")
    job = background_jobs.create_job(_JOB_KIND, {"phase": "starting", "org_ref": org_ref, "org_name": org["name"]})
    _running_builds[org_ref] = job["job_id"]
    supervise_task(asyncio.create_task(_run_build(job["job_id"], org, _session_user(request))), "meraki-topology-build")
    return {"job_id": job["job_id"], "status": "running"}


@router.get("/api/meraki/builds/{job_id}")
async def get_meraki_build_api(job_id: str):
    job = background_jobs.get_job(job_id, kind=_JOB_KIND)
    if job is None:
        raise HTTPException(status_code=404, detail="Build job not found (it may have expired)")
    return job


async def _build_cato_sample(user: str) -> dict:
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_CATO_NAME)
    if not org:
        org = await db.create_meraki_org(
            SAMPLE_CATO_NAME, provider=PROVIDER_CATO, org_id="sample", base_url=CATO_BASE_URL, created_by=user
        )
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample account")
    raw = build_cato_sample_raw()
    raw["account"]["name"] = org["name"]
    result = await _store_snapshot(org, build_cato_snapshot(raw), user=user, started=started)
    return {"ok": True, "org_ref": org["id"], **result}


async def _build_anyconnect_sample(user: str) -> dict:
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_ANYCONNECT_NAME)
    if not org:
        org = await db.create_meraki_org(
            SAMPLE_ANYCONNECT_NAME,
            provider=PROVIDER_ANYCONNECT,
            org_id="Global",
            base_url=SAMPLE_FMC_URL,
            options=sanitize_anyconnect_options({"username": "plexus-readonly"}),
            created_by=user,
        )
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample FMC")
    raw = build_anyconnect_sample_raw()
    raw["fmc"]["name"] = org["name"]
    result = await _store_snapshot(org, build_anyconnect_snapshot(raw), user=user, started=started)
    return {"ok": True, "org_ref": org["id"], **result}


async def _build_cloud_sample(cloud: _Cloud, user: str) -> dict:
    """Discover the demo account of an AWS or Azure cloud. It is a Cloud
    Visibility account like any other (and is deleted there); only its data
    is bundled."""
    started = time.monotonic()
    accounts = await db.list_cloud_accounts(provider=cloud.provider)
    # Only ever the demo account: a real account that happens to share the
    # name keeps its discovery.
    account = next(
        (a for a in accounts if a.get("name") == cloud.sample_name and a.get("auth_type") == SAMPLE_AWS_AUTH_TYPE),
        None,
    )
    if not account:
        account = await db.create_cloud_account(
            provider=cloud.provider,
            name=cloud.sample_name,
            account_identifier="sample",
            region_scope=cloud.sample_scope,
            auth_type=SAMPLE_AWS_AUTH_TYPE,
            notes="Demo data for the Topology map. Delete this account when you are done.",
            created_by=user,
        )
    if not account:
        raise HTTPException(status_code=500, detail="Could not create the sample account")
    resources, connections = cloud.sample()
    await db.replace_cloud_discovery_snapshot(
        account["id"],
        resources=resources,
        connections=connections,
        sync_status="success",
        sync_message="Sample discovery snapshot refreshed",
    )
    _topology_changed()
    entry = await _cloud_entry(cloud)
    return {
        "ok": True,
        "org_ref": cloud.org_ref,
        "snapshot_id": None,
        "summary": (entry["snapshot"].get("summary") if entry else None) or {},
        "warning_count": 0,
        "duration_seconds": round(time.monotonic() - started, 1),
    }


@router.post("/api/meraki/sample", status_code=201)
async def build_sample_topology_api(request: Request, provider: str = Query(default=PROVIDER_MERAKI)):
    """Build a snapshot from bundled demo data (no API key needed).
    ``provider=cato`` builds the demo Cato account instead of the Meraki one,
    ``provider=anyconnect`` the demo FMC with its AnyConnect headends,
    ``provider=aws`` / ``provider=azure`` the demo AWS account / Azure
    subscription in Cloud Visibility."""
    user = _session_user(request)
    if provider == PROVIDER_CATO:
        return await _build_cato_sample(user)
    if provider == PROVIDER_ANYCONNECT:
        return await _build_anyconnect_sample(user)
    if provider in _CLOUD_BY_PROVIDER:
        return await _build_cloud_sample(_CLOUD_BY_PROVIDER[provider], user)
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_ORG_NAME)
    if not org:
        org = await db.create_meraki_org(SAMPLE_ORG_NAME, org_id="sample", base_url=DEFAULT_BASE_URL, created_by=user)
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample organization")
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    result = await _store_snapshot(org, snapshot, user=user, started=started)
    result["clients_tracked"] = await _track_clients(org, raw)
    return {"ok": True, "org_ref": org["id"], **result}


# ── Snapshots ────────────────────────────────────────────────────────────────


@router.get("/api/meraki/snapshots")
async def list_meraki_snapshots_api(
    org_ref: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    return {"snapshots": await db.list_meraki_snapshots(org_ref, limit)}


async def _get_snapshot_or_404(snapshot_id: int, *, include_body: bool) -> dict:
    row = await db.get_meraki_snapshot(snapshot_id, include_body=include_body)
    if not row:
        raise HTTPException(status_code=404, detail="Topology snapshot not found")
    return row


@router.get("/api/meraki/snapshots/{snapshot_id}")
async def get_meraki_snapshot_api(snapshot_id: int):
    return await _get_snapshot_or_404(snapshot_id, include_body=False)


@router.get("/api/meraki/snapshots/{snapshot_id}/data")
async def get_meraki_snapshot_data_api(snapshot_id: int):
    """The full node/edge snapshot as JSON (for scripting / other tools)."""
    return (await _get_snapshot_or_404(snapshot_id, include_body=True))["snapshot"]


@router.delete("/api/meraki/snapshots/{snapshot_id}")
async def delete_meraki_snapshot_api(snapshot_id: int, request: Request):
    await _get_snapshot_or_404(snapshot_id, include_body=False)
    await db.delete_meraki_snapshot(snapshot_id)
    _topology_changed()
    await _audit(
        "meraki_topology",
        "delete_snapshot",
        user=_session_user(request),
        detail=f"snapshot_id={snapshot_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Map sources ──────────────────────────────────────────────────────────────

SOURCE_NEIGHBORS = "neighbors"


def _count_text(count: object, noun: str) -> str:
    number = int(count or 0)
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _utc_iso(stamp: object) -> str | None:
    """A stored timestamp as ISO 8601; the database default has no zone."""
    text = str(stamp or "").strip()
    if not text:
        return None
    if "T" not in text:
        text = text.replace(" ", "T")
    return text if text.endswith("Z") or "+" in text[10:] or "-" in text[10:] else f"{text}+00:00"


def _source(key: str, kind: str, name: str, **fields: Any) -> dict[str, Any]:
    return {
        "key": key,
        "type": kind,
        "id": None,
        "name": name,
        "status": "never",
        "last_collected_at": None,
        "message": "",
        "detail": "",
        "warning_count": 0,
        "collecting": False,
        "can_collect": True,
        "enabled": True,
        "demo": False,
        **fields,
    }


def _neighbor_source(stats: dict) -> dict[str, Any]:
    links, hosts = stats["links"], stats["hosts"]
    return _source(
        SOURCE_NEIGHBORS,
        SOURCE_NEIGHBORS,
        "Inventory devices (CDP / LLDP neighbors)",
        status="success" if links else "never",
        last_collected_at=_utc_iso(stats["last_discovered_at"]),
        detail=(
            f"{_count_text(links, 'link')} from {stats['hosts_with_links']} of {_count_text(hosts, 'device')}"
            if links
            else f"{_count_text(hosts, 'device')} in inventory"
        ),
        can_collect=hosts > 0,
    )


def _org_source(org: dict, newest: dict | None) -> dict[str, Any]:
    provider = _provider_of(org)
    summary = (newest or {}).get("summary") or {}
    return _source(
        f"org:{org['id']}",
        provider,
        org["name"],
        id=org["id"],
        status=str(org.get("last_build_status") or "never"),
        last_collected_at=org.get("last_build_at"),
        message=str(org.get("last_build_message") or ""),
        detail=(
            f"{_count_text(summary.get('sites'), 'site')}, {_count_text(summary.get('devices'), 'device')}"
            if newest
            else ""
        ),
        warning_count=int((newest or {}).get("warning_count") or 0),
        collecting=org["id"] in _running_builds,
        can_collect=bool(org.get("has_api_key")),
        demo=org["name"] in SAMPLE_ORG_NAMES and not org.get("has_api_key"),
    )


def _cloud_source(account: dict) -> dict[str, Any]:
    """A Cloud Visibility account (AWS or Azure) as a source of the map."""
    provider = str(account.get("provider") or PROVIDER_AWS)
    status = str(account.get("last_sync_status") or "never")
    demo = account.get("auth_type") == SAMPLE_AWS_AUTH_TYPE
    resources = int(account.get("resource_count") or 0)
    return _source(
        f"{provider}:{account['id']}",
        provider,
        str(account.get("name") or ""),
        id=account["id"],
        status="failed" if status == "error" else status,
        last_collected_at=_utc_iso(account.get("last_sync_at")),
        message=str(account.get("last_sync_message") or "") if status == "error" else "",
        detail=_count_text(resources, "resource") if resources else "",
        # The demo account has nothing to discover; its data is reloaded as a sample.
        can_collect=not demo,
        enabled=bool(account.get("enabled")),
        demo=demo,
    )


@router.get("/api/topology/sources")
async def list_topology_sources_api():
    """Everything that feeds the topology map, with its last collection:
    neighbor discovery of the inventory, Meraki organizations, Cato accounts,
    AnyConnect FMCs and the AWS and Azure accounts of Cloud Visibility. Credentials are
    never included."""
    newest: dict[int, dict] = {}
    for snapshot in await db.list_meraki_snapshots(limit=500):
        newest.setdefault(snapshot["org_ref"], snapshot)  # newest first
    sources = [_neighbor_source(await db.get_topology_link_stats())]
    sources.extend(_org_source(org, newest.get(org["id"])) for org in await db.list_meraki_orgs())
    for cloud in CLOUDS:
        sources.extend(
            _cloud_source({"provider": cloud.provider, **account})
            for account in await db.list_cloud_accounts(provider=cloud.provider)
        )
    return {"sources": sources}


# ── Node details and whole-map search ────────────────────────────────────────


@router.get("/api/meraki/nodes")
async def get_meraki_node_api(org_ref: int = Query(), node_id: str = Query(min_length=1, max_length=300)):
    """Detail sections for one Meraki node on the topology map."""
    for ref, snapshot in await latest_snapshots():
        if ref == org_ref:
            details = node_details(snapshot, node_id)
            if details:
                return details
    raise HTTPException(status_code=404, detail="Meraki node not found in the latest snapshot")


@router.get("/api/meraki/subnets")
async def list_meraki_subnets_api():
    """Subnets of the latest snapshots with the device that owns each one, for
    picking path endpoints by subnet. ``(org_ref, node_id)`` references are
    resolved to nodes on the merged graph by the Topology page."""
    subnets: list[dict] = []
    for org_ref, entry in await _latest_entries():
        provider = str(entry["snapshot"].get("provider") or PROVIDER_MERAKI)
        subnets.extend({"org_ref": org_ref, "provider": provider, **subnet} for subnet in await _subnets_of(entry))
    return {"subnets": subnets}


async def _cloud_reachability(
    cloud: _Cloud,
    source: str,
    destination: str,
    source_network: str,
    destination_network: str,
    protocol: str,
    port: int | None,
) -> dict:
    entries = dict(await _latest_entries())
    entry = entries.get(cloud.org_ref)
    if entry is None:
        return {
            "applies": False,
            "verdict": "unknown",
            "summary": f"No {cloud.label} account has been discovered.",
            "steps": [],
        }
    # Instances that are an appliance of a Meraki organization on the map.
    carriers: dict[str, VpnCarrier] = {}
    pairs = virtual_appliance_pairs([(ref, item["snapshot"]) for ref, item in entries.items()])
    for (cloud_ref, instance), (org_ref, node_id) in pairs.items():
        device = entries[org_ref]
        if cloud_ref != cloud.org_ref or str(device["snapshot"].get("provider") or PROVIDER_MERAKI) != PROVIDER_MERAKI:
            continue
        if device.get("subnets") is None:
            device["subnets"] = await asyncio.to_thread(subnet_index, device["snapshot"])
        # An AWS instance node is ``i:<instance id>``, an Azure VM ``vm:<id>``.
        key = instance.split(":", 1)[1] if ":" in instance else instance
        carriers[key] = VpnCarrier(device["snapshot"], node_id, device["subnets"])
    try:
        return entry["reachability"].check(
            source,
            destination,
            source_vpc=source_network,
            destination_vpc=destination_network,
            protocol=protocol,
            port=port,
            carriers=carriers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/meraki/aws/reachability")
async def aws_reachability_api(
    source: str = Query(min_length=1, max_length=64),
    destination: str = Query(min_length=1, max_length=64),
    source_vpc: str = Query(default="", max_length=64),
    destination_vpc: str = Query(default="", max_length=64),
    protocol: str = Query(default="", max_length=8),
    port: int | None = Query(default=None, ge=0, le=65535),
):
    """Whether AWS carries and permits traffic from ``source`` to
    ``destination`` (IP addresses or networks) and its replies: VPC and
    transit gateway route tables, VPC peerings, network ACLs and security
    groups of the latest discovery. ``*_vpc`` names the VPC of an address
    whose range exists in several. A route to an instance that is a Meraki
    vMX is followed on through that appliance's VPN."""
    return await _cloud_reachability(
        _CLOUD_BY_PROVIDER[PROVIDER_AWS], source, destination, source_vpc, destination_vpc, protocol, port
    )


@router.get("/api/meraki/azure/reachability")
async def azure_reachability_api(
    source: str = Query(min_length=1, max_length=64),
    destination: str = Query(min_length=1, max_length=64),
    source_vnet: str = Query(default="", max_length=300),
    destination_vnet: str = Query(default="", max_length=300),
    protocol: str = Query(default="", max_length=8),
    port: int | None = Query(default=None, ge=0, le=65535),
):
    """Whether Azure carries and permits traffic from ``source`` to
    ``destination`` (IP addresses or networks) and its replies: the effective
    routes of the subnets (VNet, peerings, gateways, route tables) and the
    network security groups of subnets and network interfaces of the latest
    discovery. ``*_vnet`` names the VNet (``subscription:group:name``) of an
    address whose range exists in several. A route to a virtual machine that
    is a Meraki vMX is followed on through that appliance's VPN."""
    return await _cloud_reachability(
        _CLOUD_BY_PROVIDER[PROVIDER_AZURE], source, destination, source_vnet, destination_vnet, protocol, port
    )


@router.get("/api/topology/search/deep")
async def topology_deep_search_api(
    q: str = Query(min_length=2, max_length=100),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Search everything collected for Meraki nodes - VLANs, subnets, routes,
    VPN peers, firewall rules, ports, neighbors, serials - not just names.

    Hits are returned as ``(org_ref, node_id)`` references, which the
    Topology page resolves to nodes on the merged graph.
    """
    tokens = q.lower().split()[:8]
    results: list[dict] = []
    for org_ref, entry in await _latest_entries():
        if entry["index"] is None:
            entry["index"] = await asyncio.to_thread(build_search_index, entry["snapshot"])
        for hit in search_index(entry["index"], tokens, limit - len(results)):
            results.append({"org_ref": org_ref, **hit})
        if len(results) >= limit:
            break
    return {"results": results, "truncated": len(results) >= limit}


# ── Whole-topology HTML export ───────────────────────────────────────────────


@router.get("/api/topology/export.html")
async def export_topology_html_api(
    request: Request,
    group_id: int | None = Query(default=None),
    download: bool = Query(default=False),
):
    """Self-contained interactive HTML map of the topology.

    Covers what the Topology page shows - inventory devices and their
    discovered links plus (for the all-groups view) every Meraki organization
    - with each device's collected detail embedded. ``download=1`` sends it as
    an attachment; otherwise it renders inline for a new browser tab.
    """
    from netcontrol.routes.topology import get_topology

    graph = await get_topology(group_id)
    snapshots = dict(await latest_snapshots())
    host_sections = {
        node["id"]: await collected_sections(node["id"])
        for node in graph["nodes"]
        if node.get("in_inventory") and isinstance(node["id"], int)
    }
    title = "Plexus"
    if group_id is not None:
        group = next((g for g in await db.get_all_groups() if g["id"] == group_id), None)
        title = f"Plexus - {group['name']}" if group else title
    # Layout of a large topology is CPU-bound; keep it off the event loop.
    snapshot = await asyncio.to_thread(graph_to_snapshot, graph, snapshots, host_sections, title=title)
    html = await asyncio.to_thread(render_topology_html, snapshot)

    # The export has its own CSP (the middleware only fills in a default): the
    # viewer needs an inline script, and ``sandbox`` isolates it from the
    # Plexus origin so it can never use the session it was served under.
    headers = {"Content-Security-Policy": EXPORT_CSP, "Cache-Control": "private, no-store"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{export_filename(snapshot)}"'
        await _audit(
            "topology",
            "export_html",
            user=_session_user(request),
            detail=f"group_id={group_id} nodes={len(snapshot['nodes'])}",
            correlation_id=_corr_id(request),
        )
    return HTMLResponse(html, headers=headers)
