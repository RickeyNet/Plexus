"""
meraki_topology.py -- Meraki support for the Topology feature.

The newest snapshot of every Meraki organization is merged into the graph
served by ``/api/topology`` (see ``netcontrol.routes.topology``), so Meraki
devices live on the same map as SNMP-discovered ones. This module provides
what feeds and surrounds that merge:

  - Meraki organization CRUD (Dashboard API key is write-only, stored encrypted)
  - Cato Networks accounts, which are stored and collected like an
    organization (``provider`` "cato") and produce the same snapshot format
  - Cisco FMCs and the FTDs they manage, stored and collected the same way
    (``provider`` "fmc"; entries stored as "anyconnect" by earlier releases
    are read as "fmc")
  - Palo Alto Panoramas and the firewalls they manage, stored and collected
    the same way (``provider`` "panorama")
  - Appgate SDP collectives (Controllers, Gateways, connected users), stored
    and collected the same way (``provider`` "appgate")
  - AWS, Azure and GCP: the accounts Cloud Visibility discovers are turned
    into one more snapshot per cloud (``provider`` "aws" / "azure" / "gcp")
    whenever their discovery changes
  - On-demand collection builds as background jobs with pollable progress
  - Stored snapshots: list / fetch JSON / delete, and an in-memory cache of
    the latest one per organization
  - Per-node Meraki detail sections and whole-map deep search
  - Path Mode's trace of a flow hop by hop across every device on the map
    (``/api/topology/path``, ``netcontrol.integrations.pathtrace``)
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

from netcontrol.integrations.appgate.client import (
    AppgateApiError,
    AppgateClient,
    validate_base_url as validate_appgate_base_url,
)
from netcontrol.integrations.appgate.collector import (
    DEFAULT_OPTIONS as APPGATE_DEFAULT_OPTIONS,
    collect_appgate,
    sanitize_options as sanitize_appgate_options,
)
from netcontrol.integrations.appgate.normalize import build_snapshot as build_appgate_snapshot
from netcontrol.integrations.appgate.sample import build_sample_raw as build_appgate_sample_raw
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
from netcontrol.integrations.fmc.client import (
    FmcApiError,
    FmcClient,
    validate_base_url as validate_fmc_base_url,
)
from netcontrol.integrations.fmc.collector import (
    DEFAULT_OPTIONS as FMC_DEFAULT_OPTIONS,
    collect_fmc,
    sanitize_options as sanitize_fmc_options,
)
from netcontrol.integrations.fmc.normalize import build_snapshot as build_fmc_snapshot
from netcontrol.integrations.fmc.sample import build_sample_raw as build_fmc_sample_raw
from netcontrol.integrations.gcp.normalize import build_snapshot as build_gcp_snapshot
from netcontrol.integrations.gcp.reachability import Reachability as GcpReachability
from netcontrol.integrations.gcp.sample import build_sample as build_gcp_sample
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
from netcontrol.integrations.panorama.client import (
    PanoramaApiError,
    PanoramaClient,
    validate_base_url as validate_panorama_base_url,
)
from netcontrol.integrations.panorama.collector import (
    COMMAND_DEVICE_GROUPS as PANORAMA_DEVICE_GROUPS,
    COMMAND_SYSTEM_INFO as PANORAMA_SYSTEM_INFO,
    DEFAULT_OPTIONS as PANORAMA_DEFAULT_OPTIONS,
    collect_panorama,
    sanitize_options as sanitize_panorama_options,
)
from netcontrol.integrations.panorama.normalize import build_snapshot as build_panorama_snapshot
from netcontrol.integrations.panorama.sample import build_sample_raw as build_panorama_sample_raw
from netcontrol.integrations.pathtrace.engine import PROTOCOLS as PATH_PROTOCOLS, Tracer
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host
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
SAMPLE_FMC_NAME = "Sample Cisco FMC (demo data)"
# The demo FMC's name before the provider became "fmc": an existing demo
# entry under it is still flagged as demo data (and renamed when rebuilt).
SAMPLE_FMC_LEGACY_NAME = "Sample AnyConnect FMC (demo data)"
SAMPLE_PANORAMA_NAME = "Sample Palo Alto Panorama (demo data)"
SAMPLE_APPGATE_NAME = "Sample Appgate SDP (demo data)"
SAMPLE_AWS_NAME = "Sample AWS Account (demo data)"
SAMPLE_AZURE_NAME = "Sample Azure Subscription (demo data)"
SAMPLE_GCP_NAME = "Sample GCP Project (demo data)"
# Marks the demo AWS, Azure and GCP accounts, which scheduled discovery leaves alone.
SAMPLE_AWS_AUTH_TYPE = "sample"
# The demo FMC address: a documentation range, never contacted.
SAMPLE_FMC_URL = "https://10.210.2.20"
# The demo Panorama address: never contacted.
SAMPLE_PANORAMA_URL = "https://10.210.2.30"
# The demo Appgate Controller's admin address (its own interface): never contacted.
SAMPLE_APPGATE_URL = "https://10.160.1.10:8443"

PROVIDER_MERAKI = "meraki"
PROVIDER_CATO = "cato"
# A Cisco FMC and the FTDs it manages.
PROVIDER_FMC = "fmc"
# A Palo Alto Panorama and the firewalls it manages.
PROVIDER_PANORAMA = "panorama"
# An Appgate SDP collective: its Controllers, Gateways and connected users.
PROVIDER_APPGATE = "appgate"
PROVIDERS = (PROVIDER_MERAKI, PROVIDER_CATO, PROVIDER_FMC, PROVIDER_PANORAMA, PROVIDER_APPGATE)
# Provider keys of earlier releases, read as their current key: an FMC was
# "anyconnect" while it only drew remote access VPN headends.
LEGACY_PROVIDERS = {"anyconnect": PROVIDER_FMC}
SAMPLE_ORG_NAMES = (
    SAMPLE_ORG_NAME,
    SAMPLE_CATO_NAME,
    SAMPLE_FMC_NAME,
    SAMPLE_FMC_LEGACY_NAME,
    SAMPLE_PANORAMA_NAME,
    SAMPLE_APPGATE_NAME,
)
# Not organization providers: AWS, Azure and GCP accounts are Cloud Visibility accounts.
PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

_require_admin = None

# org_ref -> job_id of the build currently running for that organization.
_running_builds: dict[int, str] = {}

# snapshot_id -> {"snapshot": dict, "index": search index | None}. Only the
# latest snapshot of each organization is held: it is parsed once from its
# multi-megabyte JSON row and then reused by every topology build, node-detail
# click and search. Snapshots are immutable, so entries never go stale; they
# are dropped when a newer build replaces them.
_SNAPSHOT_CACHE: dict[int, dict[str, Any]] = {}

# AWS, Azure and GCP accounts belong to Cloud Visibility, not to ``meraki_orgs``.
# What the accounts of one cloud discovered is built into one snapshot for all
# of them and referenced by an ``org_ref`` (and cache key) no organization or
# stored snapshot can have.
AWS_ORG_REF = -1
AZURE_ORG_REF = -2
GCP_ORG_REF = -3
_AWS_ACCOUNT_FIELDS = (
    "id",
    "name",
    "account_identifier",
    "region_scope",
    "last_sync_at",
    "last_sync_status",
    "last_sync_message",
)


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
    _Cloud(
        PROVIDER_GCP,
        GCP_ORG_REF,
        "GCP",
        build_gcp_snapshot,
        GcpReachability,
        build_gcp_sample,
        SAMPLE_GCP_NAME,
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
            snapshot = row["snapshot"]
            # A snapshot stored under a provider key of an earlier release
            # is served under the current key (it is the same format).
            legacy = LEGACY_PROVIDERS.get(str(snapshot.get("provider") or ""))
            if legacy:
                snapshot["provider"] = legacy
            entry = _SNAPSHOT_CACHE[snapshot_id] = {"snapshot": snapshot, "index": None}
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
    LANs, SVIs and static routes, Cato and Appgate network ranges, FMC and
    Panorama connected subnets, static routes and remote access VPN address
    pools)
    with their organization and provider. AWS, Azure and GCP are left out:
    their networks and subnets reach IPAM as Cloud Visibility resources
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
    # "meraki" (organization), "cato" (account), "fmc" (FMC; the legacy
    # "anyconnect" is accepted and stored as "fmc"), "panorama" (Palo Alto
    # Panorama) or "appgate" (Appgate SDP collective). Fixed once created.
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


def _provider_key(raw: str | None) -> str:
    """A provider key as stored now: legacy keys map to their current one."""
    provider = str(raw or "").strip().lower()
    return LEGACY_PROVIDERS.get(provider, provider)


def _provider_of(org: dict) -> str:
    provider = _provider_key(org.get("provider")) or PROVIDER_MERAKI
    return provider if provider in PROVIDERS else PROVIDER_MERAKI


def _clean_base_url(raw: str | None, provider: str = PROVIDER_MERAKI) -> str:
    if provider == PROVIDER_APPGATE:
        try:
            return validate_appgate_base_url(raw or "")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Appgate address must be an https URL of a Controller's admin interface "
                    "(for example https://appgate.example.com:8443)"
                ),
            ) from None
    if provider == PROVIDER_PANORAMA:
        try:
            return validate_panorama_base_url(raw or "")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Panorama address must be an https URL of the Panorama host only "
                    "(for example https://panorama.example.com)"
                ),
            ) from None
    if provider == PROVIDER_FMC:
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
    if provider == PROVIDER_FMC:
        return sanitize_fmc_options(raw)
    if provider == PROVIDER_PANORAMA:
        return sanitize_panorama_options(raw)
    if provider == PROVIDER_APPGATE:
        return sanitize_appgate_options(raw)
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


def _panorama_error_message(exc: PanoramaApiError) -> str:
    # ``detail`` is the message Panorama answered with.
    detail = f": {exc.detail}" if exc.detail else ""
    if exc.status_code in (401, 403):
        return f"Panorama rejected the credentials (HTTP {exc.status_code}){detail}"
    if exc.status_code is None and exc.code:
        return f"Panorama refused the request (error {exc.code}){detail}"
    if exc.status_code is None:
        # Transport failures and client-side checks (unknown device group).
        return f"{exc}{detail}"
    return f"Panorama API error (HTTP {exc.status_code}){detail}"


def _appgate_error_message(exc: AppgateApiError) -> str:
    # ``detail`` is the message the Controller answered with.
    if exc.status_code in (401, 403):
        return f"Appgate rejected the login (HTTP {exc.status_code})"
    if exc.status_code == 406:
        return "Appgate refused the API version"
    if exc.transport:
        return "Could not reach the Appgate controller"
    if exc.status_code is None:
        # Checks Plexus makes itself: an unsupported peer version, an admin
        # user that needs a second factor.
        return str(exc)
    return f"Appgate API error (HTTP {exc.status_code}): {exc.detail or exc}"


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
        "fmc_default_options": dict(FMC_DEFAULT_OPTIONS),
        "panorama_default_options": dict(PANORAMA_DEFAULT_OPTIONS),
        "appgate_default_options": dict(APPGATE_DEFAULT_OPTIONS),
    }


@router.post("/api/meraki/orgs", status_code=201, dependencies=[Depends(_require_admin_dep)])
async def create_meraki_org_api(body: MerakiOrgCreate, request: Request):
    user = _session_user(request)
    provider = _provider_key(body.provider) or PROVIDER_MERAKI
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="Provider must be meraki, cato, fmc, panorama or appgate")
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
    if _provider_of(org) == PROVIDER_FMC:
        return await _validate_fmc(org, api_key)
    if _provider_of(org) == PROVIDER_PANORAMA:
        return await _validate_panorama(org, api_key)
    if _provider_of(org) == PROVIDER_APPGATE:
        return await _validate_appgate(org, api_key)
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


async def _validate_fmc(org: dict, password: str) -> dict:
    options = sanitize_fmc_options(org.get("options"))
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


def _panorama_client(org: dict, secret: str, options: dict, **kwargs: Any) -> PanoramaClient:
    """A Panorama client for an entry. With a username in the options the
    entry's write-only secret is that admin's password (an API key is
    generated for each collection and never stored); without one it is the
    API key itself."""
    username = str(options.get("username") or "").strip()
    credentials = {"username": username, "password": secret} if username else {"api_key": secret}
    return PanoramaClient(
        org.get("base_url") or "",
        verify_tls=bool(options.get("verify_tls", True)),
        **credentials,
        **kwargs,
    )


async def _validate_panorama(org: dict, secret: str) -> dict:
    options = sanitize_panorama_options(org.get("options"))
    wanted = str(org.get("org_id") or "").strip()
    try:
        async with _panorama_client(org, secret, options, max_retries=1) as client:
            info = await client.version()
            system = await client.op(PANORAMA_SYSTEM_INFO)
            groups = await client.op(PANORAMA_DEVICE_GROUPS)
    except PanoramaApiError as exc:
        return {"ok": False, "message": _panorama_error_message(exc), "organizations": []}
    system = system.get("system", system) if isinstance(system, dict) else {}
    hostname = str(system.get("hostname") or "") if isinstance(system, dict) else ""
    names = sorted(
        str(g.get("@name") or "")
        for g in (groups if isinstance(groups, list) else [])
        if isinstance(g, dict) and g.get("@name")
    )
    organizations = [{"id": name, "name": name} for name in names]
    if wanted and wanted.lower() not in {n.lower() for n in names}:
        return {
            "ok": False,
            "message": f"Signed in to Panorama, but it has no device group {wanted}",
            "organizations": organizations,
        }
    version = str(info.get("sw-version") or "")
    where = f"device group {wanted}" if wanted else "every device group"
    name = hostname or str(org.get("base_url") or "")
    return {
        "ok": True,
        "message": f"Signed in to Panorama {name}" + (f" ({version})" if version else "") + f"; collecting {where}",
        "organizations": organizations,
    }


def _appgate_client(org: dict, password: str, options: dict, **kwargs: Any) -> AppgateClient:
    """An Appgate client for an entry. The admin user name lives in the
    options, the identity provider it signs in with in ``org_id``, and its
    password is the entry's write-only secret (the token the login answers
    with is never stored)."""
    username = str(options.get("username") or "").strip()
    if not username:
        raise ValueError("Set the admin user name on this entry")
    return AppgateClient(
        org.get("base_url") or "",
        username,
        password,
        provider_name=str(org.get("org_id") or "").strip() or "local",
        verify_tls=bool(options.get("verify_tls", True)),
        **kwargs,
    )


async def _validate_appgate(org: dict, password: str) -> dict:
    options = sanitize_appgate_options(org.get("options"))
    try:
        async with _appgate_client(org, password, options, max_retries=1) as client:
            await client.login()
            sites = await client.get("/sites", {"range": "0-0"})
            appliances = await client.get("/appliances", {"range": "0-0"})
    except AppgateApiError as exc:
        return {"ok": False, "message": _appgate_error_message(exc), "organizations": []}
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "organizations": []}

    def count(body: Any) -> int:
        if isinstance(body, dict):
            try:
                return int(
                    body.get("totalCount") if body.get("totalCount") is not None else len(body.get("data") or [])
                )
            except TypeError, ValueError:
                return 0
        return len(body) if isinstance(body, list) else 0

    provider = str(org.get("org_id") or "").strip() or "local"
    return {
        "ok": True,
        "message": f"Login OK: Appgate SDP peer v{client.peer_version}, {count(sites)} sites, "
        f"{count(appliances)} appliances",
        "organizations": [{"id": provider, "name": org["name"]}],
    }


# ── Builds ───────────────────────────────────────────────────────────────────


async def _collect_appgate(org: dict, password: str, options: dict, progress) -> dict:
    async with _appgate_client(org, password, options) as client:
        raw = await collect_appgate(client, options, progress)
    # The snapshot is named after the entry; the collective's own name is
    # kept as ``collective_name``.
    raw["collective"]["name"] = org["name"]
    return raw


async def _collect_panorama(org: dict, secret: str, options: dict, progress) -> dict:
    async with _panorama_client(org, secret, options) as client:
        raw = await collect_panorama(client, str(org.get("org_id") or ""), options, progress)
    raw["panorama"]["name"] = org["name"]
    return raw


async def _collect_fmc(org: dict, password: str, options: dict, progress) -> dict:
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
    PROVIDER_FMC: build_fmc_snapshot,
    PROVIDER_PANORAMA: build_panorama_snapshot,
    PROVIDER_APPGATE: build_appgate_snapshot,
    # A capture stored under the legacy key builds the same way.
    "anyconnect": build_fmc_snapshot,
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
        elif provider == PROVIDER_FMC:
            raw = await _collect_fmc(org, api_key, options, progress)
        elif provider == PROVIDER_PANORAMA:
            raw = await _collect_panorama(org, api_key, options, progress)
        elif provider == PROVIDER_APPGATE:
            raw = await _collect_appgate(org, api_key, options, progress)
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
        LOGGER.warning("fmc: build failed for FMC %s: %s", org["name"], redact_value(f"{exc} {exc.detail}"))
    except PanoramaApiError as exc:
        error = _panorama_error_message(exc)
        LOGGER.warning("panorama: build failed for %s: %s", org["name"], redact_value(f"{exc} {exc.detail}"))
    except AppgateApiError as exc:
        error = _appgate_error_message(exc)
        # The message and detail never hold the password or the token.
        LOGGER.warning("appgate: build failed for %s: %s", org["name"], redact_value(f"{exc} {exc.detail}"))
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


async def _build_fmc_sample(user: str) -> dict:
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_FMC_NAME)
    if not org:
        # The demo entry of an earlier release takes the current name
        # rather than leaving two demo FMCs on the map.
        legacy = await db.get_meraki_org_by_name(SAMPLE_FMC_LEGACY_NAME)
        if legacy and not legacy.get("has_api_key"):
            org = await db.update_meraki_org(legacy["id"], name=SAMPLE_FMC_NAME) or legacy
    if not org:
        org = await db.create_meraki_org(
            SAMPLE_FMC_NAME,
            provider=PROVIDER_FMC,
            org_id="Global",
            base_url=SAMPLE_FMC_URL,
            options=sanitize_fmc_options({"username": "plexus-readonly"}),
            created_by=user,
        )
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample FMC")
    raw = build_fmc_sample_raw()
    raw["fmc"]["name"] = org["name"]
    result = await _store_snapshot(org, build_fmc_snapshot(raw), user=user, started=started)
    return {"ok": True, "org_ref": org["id"], **result}


async def _build_panorama_sample(user: str) -> dict:
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_PANORAMA_NAME)
    if not org:
        org = await db.create_meraki_org(
            SAMPLE_PANORAMA_NAME,
            provider=PROVIDER_PANORAMA,
            org_id="",
            base_url=SAMPLE_PANORAMA_URL,
            options=sanitize_panorama_options({"username": "plexus-readonly"}),
            created_by=user,
        )
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample Panorama")
    raw = build_panorama_sample_raw()
    raw["panorama"]["name"] = org["name"]
    result = await _store_snapshot(org, build_panorama_snapshot(raw), user=user, started=started)
    return {"ok": True, "org_ref": org["id"], **result}


async def _build_appgate_sample(user: str) -> dict:
    started = time.monotonic()
    org = await db.get_meraki_org_by_name(SAMPLE_APPGATE_NAME)
    if not org:
        org = await db.create_meraki_org(
            SAMPLE_APPGATE_NAME,
            provider=PROVIDER_APPGATE,
            org_id="local",
            base_url=SAMPLE_APPGATE_URL,
            options=sanitize_appgate_options({"username": "plexus-readonly"}),
            created_by=user,
        )
    if not org:
        raise HTTPException(status_code=500, detail="Could not create the sample Appgate collective")
    raw = build_appgate_sample_raw()
    raw["collective"]["name"] = org["name"]
    result = await _store_snapshot(org, build_appgate_snapshot(raw), user=user, started=started)
    return {"ok": True, "org_ref": org["id"], **result}


async def _build_cloud_sample(cloud: _Cloud, user: str) -> dict:
    """Discover the demo account of an AWS, Azure or GCP cloud. It is a Cloud
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
    ``provider=fmc`` (or the legacy ``anyconnect``) the demo Cisco FMC and
    its FTDs, ``provider=panorama`` the demo Palo Alto Panorama and its
    firewalls, ``provider=appgate`` the demo Appgate SDP collective,
    ``provider=aws`` / ``provider=azure`` / ``provider=gcp`` the demo AWS
    account / Azure subscription / GCP project in Cloud Visibility."""
    user = _session_user(request)
    provider = _provider_key(provider) or PROVIDER_MERAKI
    if provider == PROVIDER_CATO:
        return await _build_cato_sample(user)
    if provider == PROVIDER_FMC:
        return await _build_fmc_sample(user)
    if provider == PROVIDER_PANORAMA:
        return await _build_panorama_sample(user)
    if provider == PROVIDER_APPGATE:
        return await _build_appgate_sample(user)
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


@router.get("/api/meraki/snapshots/{snapshot_id}/warnings")
async def get_meraki_snapshot_warnings_api(snapshot_id: int):
    """The collection warnings of a snapshot (API calls that failed or were
    refused), for the Map Sources dialog."""
    row = await _get_snapshot_or_404(snapshot_id, include_body=True)
    errors = ((row["snapshot"] or {}).get("collection") or {}).get("errors") or []
    return {
        "snapshot_id": snapshot_id,
        "warnings": [
            {
                "scope": str(e.get("scope") or ""),
                "path": str(e.get("path") or ""),
                "status": e.get("status"),
                "message": str(e.get("message") or ""),
            }
            for e in errors
            if isinstance(e, dict)
        ],
    }


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
    """A stored timestamp as ISO 8601 with a full ``+HH:MM`` offset.

    SQLite's default has no zone (``2026-10-09 12:00:00``, UTC); Postgres
    ``NOW()::text`` ends in an hour-only offset (``...12:00:00.123+00``) that
    browsers' ``Date`` does not parse, so both are normalised."""
    text = str(stamp or "").strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).isoformat()


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
        "snapshot_id": None,
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
        # The snapshot on the map, whose warnings the dialog can list.
        snapshot_id=(newest or {}).get("id"),
        collecting=org["id"] in _running_builds,
        can_collect=bool(org.get("has_api_key")),
        demo=org["name"] in SAMPLE_ORG_NAMES and not org.get("has_api_key"),
    )


def _cloud_source(account: dict) -> dict[str, Any]:
    """A Cloud Visibility account (AWS, Azure or GCP) as a source of the map."""
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
    Cisco FMCs, Palo Alto Panoramas, Appgate SDP collectives and the AWS, Azure and GCP accounts of
    Cloud Visibility. Credentials are never included."""
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
        # An AWS or GCP instance node is ``i:<instance id>``, an Azure VM ``vm:<id>``.
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


@router.get("/api/meraki/gcp/reachability")
async def gcp_reachability_api(
    source: str = Query(min_length=1, max_length=64),
    destination: str = Query(min_length=1, max_length=64),
    source_network: str = Query(default="", max_length=300),
    destination_network: str = Query(default="", max_length=300),
    protocol: str = Query(default="", max_length=8),
    port: int | None = Query(default=None, ge=0, le=65535),
):
    """Whether GCP carries and permits traffic from ``source`` to
    ``destination`` (IP addresses or networks) and its replies: the routes
    of the VPC networks (subnet routes, peerings, static routes, the dynamic
    routes Cloud Routers learn) and the VPC firewall rules of the latest
    discovery. ``*_network`` names the VPC network (``project:network``) of
    an address whose range exists in several. A route to an instance that
    is a Meraki vMX is followed on through that appliance's VPN."""
    return await _cloud_reachability(
        _CLOUD_BY_PROVIDER[PROVIDER_GCP], source, destination, source_network, destination_network, protocol, port
    )


# ── Path trace ───────────────────────────────────────────────────────────────

# (host id, route snapshot id) -> forwarding block of an inventory host. A new
# route capture gets a new id, so an entry never goes stale; the dict is
# cleared when it grows past the limit.
_HOST_FORWARDING: dict[tuple[int, int | None], dict[str, Any]] = {}
_HOST_FORWARDING_LIMIT = 5000


async def _inventory_forwarding(nodes: list[dict]) -> dict[int, dict[str, Any]]:
    """The forwarding block of every inventory host on the graph, from its
    interfaces, addresses and latest SSH route capture (bulk queries)."""
    hosts = {n["id"]: n for n in nodes if isinstance(n.get("id"), int) and n.get("in_inventory", True)}
    if not hosts:
        return {}
    captures = await db.get_latest_route_snapshots_for_hosts(list(hosts))
    keys = {host_id: (host_id, (captures.get(host_id) or {}).get("id")) for host_id in hosts}
    missing = [host_id for host_id, key in keys.items() if key not in _HOST_FORWARDING]
    if missing:
        aliases: dict[int, list[str]] = {}
        for row in await db.get_ip_aliases_for_hosts(missing):
            aliases.setdefault(int(row["host_id"]), []).append(str(row.get("ip_address") or ""))
        interfaces = await db.get_interface_inventory_for_hosts(missing)
        if len(_HOST_FORWARDING) + len(missing) > _HOST_FORWARDING_LIMIT:
            _HOST_FORWARDING.clear()
        for host_id in missing:
            node = hosts[host_id]
            host = {"ip_address": node.get("ip") or "", "device_type": node.get("device_type") or ""}
            _HOST_FORWARDING[keys[host_id]] = forwarding_for_host(
                host, aliases.get(host_id, []), captures.get(host_id), interfaces.get(host_id, [])
            )
    return {host_id: _HOST_FORWARDING[key] for host_id, key in keys.items() if key in _HOST_FORWARDING}


def _graph_node_id(raw: str | None) -> Any:
    """A graph node id from the query string: an inventory host's id is an int."""
    if raw is None or not raw.strip():
        return None
    text = raw.strip()
    return int(text) if text.lstrip("-").isdigit() else text


@router.get("/api/topology/path")
async def topology_path_api(
    source: str = Query(min_length=1, max_length=64),
    destination: str = Query(min_length=1, max_length=64),
    source_node: str | None = Query(default=None, max_length=300),
    destination_node: str | None = Query(default=None, max_length=300),
    protocol: str = Query(default="", max_length=8),
    port: int | None = Query(default=None, ge=0, le=65535),
):
    """Trace a flow from ``source`` to ``destination`` (IP addresses or
    networks) hop by hop across every device on the map, and its replies:
    at each device the NAT rules, rule sets, route lookup and link it meets,
    in the order the device applies them, and whether routing is asymmetric.
    ``source_node`` / ``destination_node`` name the graph nodes that own the
    ends when the page knows them. ``protocol`` is ``tcp``, ``udp``, ``icmp``
    or empty (any traffic)."""
    from netcontrol.routes.topology import get_topology

    if protocol.strip().lower() not in ("", "any", "all", *PATH_PROTOCOLS):
        raise HTTPException(status_code=400, detail=f"protocol must be one of {', '.join(PATH_PROTOCOLS)}")
    graph = await get_topology(None)
    entries = await _latest_entries()
    snapshots = {org_ref: entry["snapshot"] for org_ref, entry in entries}
    clouds = {org_ref: entry["reachability"] for org_ref, entry in entries if entry.get("reachability") is not None}
    subnets: list[dict] = []
    for org_ref, entry in entries:
        provider = str(entry["snapshot"].get("provider") or PROVIDER_MERAKI)
        subnets.extend({"org_ref": org_ref, "provider": provider, **subnet} for subnet in await _subnets_of(entry))
    host_forwarding = await _inventory_forwarding(graph.get("nodes") or [])

    def run() -> dict:
        tracer = Tracer(graph, snapshots, clouds, host_forwarding, subnets)
        return tracer.trace(
            source,
            destination,
            source_node=_graph_node_id(source_node),
            destination_node=_graph_node_id(destination_node),
            protocol=protocol,
            port=port,
        )

    try:
        # Building the indexes and walking a large map is CPU-bound.
        return await asyncio.to_thread(run)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
