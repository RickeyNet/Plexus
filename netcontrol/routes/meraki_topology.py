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
  - The reachability sweep: one destination traced from every source
    network the filters keep, as JSON or CSV (``/api/topology/reachability``)
  - The list of everything that feeds the map (``/api/topology/sources``):
    neighbor discovery, the inventory route/configuration collection
    (``netcontrol.routes.inventory_collection``), organizations and accounts,
    with their last collection
  - Self-contained interactive HTML export of the whole topology

Registered under the ``topology`` feature: reads need ``topology``, builds
and deletes need ``topology.write``, organization (credential) management
needs admin.

The routes live under ``/api/sources`` (``/api/sources/{id}/validate``,
``/api/sources/snapshots``...), since an entry can be any of the providers
above; nothing here is named after Meraki.
"""

from __future__ import annotations

import asyncio
import copy
import csv
import io
import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from netcontrol import xlsx
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
from netcontrol.integrations.meraki.forwarding import canonical
from netcontrol.integrations.meraki.html_export import (
    export_csp,
    export_filename,
    pyodide_runtime,
    render_topology_html,
    tracer_payload,
)
from netcontrol.integrations.meraki.normalize import build_snapshot
from netcontrol.integrations.meraki.sample import build_sample_raw
from netcontrol.integrations.meraki.subnets import subnet_index, subnets_containing
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
from netcontrol.integrations.pathtrace import (
    placement as trace_placement,
    summarize as reach_summarize,
    sweep as reach_sweep,
)
from netcontrol.integrations.pathtrace.engine import PROTOCOLS as PATH_PROTOCOLS, Tracer
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, subnets_for_host
from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF
from netcontrol.integrations.pathtrace.offline import (
    dumps as offline_dumps,
    export_ids,
    graph_node_id as _graph_node_id,
    inputs as offline_inputs,
    trace as offline_trace,
)
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


async def _discovered_accounts(cloud: _Cloud) -> list[dict[str, Any]]:
    """The enabled accounts of ``cloud`` that discovery has found resources in."""
    return [
        {key: account.get(key) for key in (*_AWS_ACCOUNT_FIELDS, "resource_count", "connection_count")}
        for account in await db.list_cloud_accounts(provider=cloud.provider, enabled_only=True)
        if account.get("resource_count")
    ]


async def _cloud_rows(cloud: _Cloud, wanted: set[Any]) -> tuple[list[dict], list[dict]]:
    """The discovered resources and connections of the accounts in ``wanted``."""
    resources = [r for r in await db.get_cloud_resources(provider=cloud.provider) if r.get("account_id") in wanted]
    connections = [c for c in await db.get_cloud_connections(provider=cloud.provider) if c.get("account_id") in wanted]
    return resources, connections


async def _cloud_entry(cloud: _Cloud) -> dict[str, Any] | None:
    """The snapshot of every enabled account of ``cloud`` that has been
    discovered, rebuilt when a discovery, or the set of accounts, changes."""
    accounts = await _discovered_accounts(cloud)
    if not accounts:
        return None
    signature = tuple(tuple(account.values()) for account in accounts)
    entry = _SNAPSHOT_CACHE.get(cloud.org_ref)
    if entry is None or entry.get("signature") != signature:
        resources, connections = await _cloud_rows(cloud, {account["id"] for account in accounts})
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
    already. So is the address of each connected remote user (kind
    ``user``): it is there for Path Mode and the search, and is no subnet
    to manage."""
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
            if subnet.get("kind") not in ("user", "host")
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


class SummarizeRequest(BaseModel):
    # One IP address or network per entry, split on newlines, commas, semicolons or spaces.
    addresses: str = Field(min_length=1, max_length=200000)
    # Roll every address up to this prefix length first (none: exact).
    prefix: int | None = None
    # Merge neighbours until at most this many routes of each IP version are left.
    max_routes: int | None = None
    # The sweep's source filters: which collected networks each route is checked against.
    sources: str | None = Field(default=None, max_length=2000)
    providers: str | None = Field(default=None, max_length=200)
    kinds: str | None = Field(default=None, max_length=200)
    vlans: str | None = Field(default=None, max_length=1000)
    name: str | None = Field(default=None, max_length=1000)
    exclude: str | None = Field(default=None, max_length=1000)
    sites: str | None = Field(default=None, max_length=1000)
    within: str | None = Field(default=None, max_length=2000)
    overlaps: str | None = Field(default=None, max_length=2000)
    in_vpn: str | None = Field(default=None, max_length=8)


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
        raise HTTPException(status_code=404, detail="Source not found")
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


@router.get("/api/sources")
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


@router.post("/api/sources", status_code=201, dependencies=[Depends(_require_admin_dep)])
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


@router.put("/api/sources/{org_ref}", dependencies=[Depends(_require_admin_dep)])
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


@router.delete("/api/sources/{org_ref}", dependencies=[Depends(_require_admin_dep)])
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


@router.post("/api/sources/{org_ref}/validate", dependencies=[Depends(_require_admin_dep)])
async def validate_meraki_org_api(org_ref: int):
    """Check the stored credentials of a source: the organizations a Meraki
    key can see, or a sign-in to a Cato, FMC, Panorama or Appgate entry."""
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
    credentials: dict[str, Any] = {"username": username, "password": secret} if username else {"api_key": secret}
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
            total = body.get("totalCount")
            try:
                return int(total if total is not None else len(body.get("data") or []))
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


@router.post("/api/sources/{org_ref}/build", status_code=202)
async def build_meraki_topology_api(org_ref: int, request: Request):
    """Start a collection of the source. Poll ``/api/sources/builds/{job_id}`` for progress."""
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


@router.get("/api/sources/builds/{job_id}")
async def get_meraki_build_api(job_id: str):
    """A collection job: a source's build or the inventory collection."""
    # Imported here: inventory_collection imports this module.
    from netcontrol.routes.inventory_collection import JOB_KIND as INVENTORY_JOB_KIND

    job = background_jobs.get_job(job_id)
    if job is None or job["kind"] not in (_JOB_KIND, INVENTORY_JOB_KIND):
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


@router.post("/api/sources/sample", status_code=201)
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


@router.get("/api/sources/snapshots")
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


@router.get("/api/sources/snapshots/{snapshot_id}")
async def get_meraki_snapshot_api(snapshot_id: int):
    return await _get_snapshot_or_404(snapshot_id, include_body=False)


@router.get("/api/sources/snapshots/{snapshot_id}/data")
async def get_meraki_snapshot_data_api(snapshot_id: int):
    """The full node/edge snapshot as JSON (for scripting / other tools)."""
    return (await _get_snapshot_or_404(snapshot_id, include_body=True))["snapshot"]


@router.get("/api/sources/snapshots/{snapshot_id}/warnings")
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


@router.delete("/api/sources/snapshots/{snapshot_id}")
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


def _count_text(count: int | str | None, noun: str) -> str:
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
    neighbor discovery of the inventory, the SSH collection of its route tables
    and configurations, Meraki organizations, Cato accounts, Cisco FMCs, Palo
    Alto Panoramas, Appgate SDP collectives and the AWS, Azure and GCP accounts
    of Cloud Visibility. Credentials are never included."""
    # Imported here: inventory_collection imports this module.
    from netcontrol.routes.inventory_collection import inventory_source

    newest: dict[int, dict] = {}
    for snapshot in await db.list_meraki_snapshots(limit=500):
        newest.setdefault(snapshot["org_ref"], snapshot)  # newest first
    sources = [_neighbor_source(await db.get_topology_link_stats()), await inventory_source()]
    sources.extend(_org_source(org, newest.get(org["id"])) for org in await db.list_meraki_orgs())
    for cloud in CLOUDS:
        sources.extend(
            _cloud_source({"provider": cloud.provider, **account})
            for account in await db.list_cloud_accounts(provider=cloud.provider)
        )
    return {"sources": sources}


# ── Node details and whole-map search ────────────────────────────────────────


@router.get("/api/sources/nodes")
async def get_meraki_node_api(org_ref: int = Query(), node_id: str = Query(min_length=1, max_length=300)):
    """Detail sections for one Meraki node on the topology map."""
    for ref, snapshot in await latest_snapshots():
        if ref == org_ref:
            details = node_details(snapshot, node_id)
            if details:
                return details
    raise HTTPException(status_code=404, detail="Meraki node not found in the latest snapshot")


@router.get("/api/sources/subnets")
async def list_meraki_subnets_api():
    """Subnets of the latest snapshots with the device that owns each one, for
    picking path endpoints by subnet, then the networks of inventory hosts
    (``org_ref`` ``INVENTORY_ORG_REF``, ``node_id`` the host id).
    ``(org_ref, node_id)`` references are resolved to nodes on the merged
    graph by the Topology page."""
    subnets: list[dict] = []
    for org_ref, entry in await _latest_entries():
        provider = str(entry["snapshot"].get("provider") or PROVIDER_MERAKI)
        subnets.extend({"org_ref": org_ref, "provider": provider, **subnet} for subnet in await _subnets_of(entry))
    subnets.extend(await _inventory_subnets())
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


@router.get("/api/sources/aws/reachability")
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


@router.get("/api/sources/azure/reachability")
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


@router.get("/api/sources/gcp/reachability")
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

# (host id, route snapshot id, config backup id, inventory group) ->
# {"block": forwarding block, "subnets": its subnet index rows} of an
# inventory host. A new route capture or backup gets a new id, so an entry
# never goes stale; the dict is cleared when it grows past the limit.
_HOST_FORWARDING: dict[tuple, dict[str, Any]] = {}
_HOST_FORWARDING_LIMIT = 5000


async def _inventory_forwarding(nodes: list[dict]) -> dict[int, dict[str, Any]]:
    """``host id -> {"block", "subnets"}`` for every inventory host on the
    graph: its forwarding block, from its interfaces, addresses, latest SSH
    route capture and latest successful configuration backup (bulk
    queries), and the subnet index rows of its networks."""
    hosts = {n["id"]: n for n in nodes if isinstance(n.get("id"), int) and n.get("in_inventory", True)}
    if not hosts:
        return {}
    captures = await db.get_latest_route_snapshots_for_hosts(list(hosts))
    backups = await db.get_latest_config_texts_for_hosts(list(hosts))
    keys = {
        host_id: (
            host_id,
            (captures.get(host_id) or {}).get("id"),
            (backups.get(host_id) or {}).get("id"),
            node.get("group_id"),
            str(node.get("group_name") or ""),
        )
        for host_id, node in hosts.items()
    }
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
            block = forwarding_for_host(
                host,
                aliases.get(host_id, []),
                captures.get(host_id),
                interfaces.get(host_id, []),
                config_backup=backups.get(host_id),
            )
            _HOST_FORWARDING[keys[host_id]] = {"block": block, "subnets": subnets_for_host(node, block)}
    return {host_id: _HOST_FORWARDING[key] for host_id, key in keys.items() if key in _HOST_FORWARDING}


async def _inventory_subnets(nodes: list[dict] | None = None) -> list[dict[str, Any]]:
    """The subnet index rows of every inventory host on ``nodes`` (the whole
    map when not given): its VLAN interfaces, connected networks and static
    routes, under ``INVENTORY_ORG_REF``."""
    if nodes is None:
        from netcontrol.routes.topology import get_topology

        nodes = (await get_topology(None)).get("nodes") or []
    return [row for entry in (await _inventory_forwarding(nodes)).values() for row in entry["subnets"]]


async def _trace_sources() -> dict[str, Any]:
    """What a path trace reads over the whole map (every group): the graph,
    the latest snapshot and cloud engine of every source, their subnets and
    the forwarding block of every inventory host."""
    from netcontrol.routes.topology import get_topology

    graph = await get_topology(None)
    entries = await _latest_entries()
    subnets: list[dict] = []
    for org_ref, entry in entries:
        provider = str(entry["snapshot"].get("provider") or PROVIDER_MERAKI)
        subnets.extend({"org_ref": org_ref, "provider": provider, **subnet} for subnet in await _subnets_of(entry))
    hosts = await _inventory_forwarding(graph.get("nodes") or [])
    # The inventory hosts' networks, from the same blocks the tracer reads.
    subnets.extend(row for entry in hosts.values() for row in entry["subnets"])
    snapshots = {org_ref: entry["snapshot"] for org_ref, entry in entries}
    return {
        "graph": graph,
        "snapshots": snapshots,
        "clouds": {
            org_ref: entry["reachability"] for org_ref, entry in entries if entry.get("reachability") is not None
        },
        "host_forwarding": {host_id: entry["block"] for host_id, entry in hosts.items()},
        "subnets": subnets,
        "placements": await _placements(graph, snapshots),
    }


async def _placements(graph: dict, snapshots: dict[int, dict]) -> dict[Any, dict]:
    """Where the Meraki client tables place the devices whose own network
    sits behind a public address a Meraki device answers on
    (``pathtrace.placement``)."""
    networks = trace_placement.networks_to_read(snapshots)
    if not networks:
        return {}
    rows = await db.list_described_meraki_clients(networks)
    return trace_placement.placements(graph, snapshots, rows)


def _tracer_of(sources: dict[str, Any]) -> Callable[[], Tracer]:
    return lambda: Tracer(
        sources["graph"],
        sources["snapshots"],
        sources["clouds"],
        sources["host_forwarding"],
        sources["subnets"],
        placements=sources.get("placements"),
    )


async def _path_tracer() -> Callable[[], Tracer]:
    """Gather what a path trace needs over the whole map (every group) and
    return a builder of the ``Tracer``. Building it indexes the whole map, so
    callers run the builder off the event loop."""
    return _tracer_of(await _trace_sources())


async def _offline_clouds(clouds: dict[int, Any]) -> dict[int, dict[str, Any]]:
    """The discovered rows behind each cloud engine in ``clouds``, which an
    export carries to rebuild the engine (``pathtrace.offline.build``)."""
    rows: dict[int, dict[str, Any]] = {}
    for cloud in CLOUDS:
        if cloud.org_ref not in clouds:
            continue
        wanted = {account["id"] for account in await _discovered_accounts(cloud)}
        resources, connections = await _cloud_rows(cloud, wanted)
        rows[cloud.org_ref] = {"provider": cloud.provider, "resources": resources, "connections": connections}
    return rows


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
    if protocol.strip().lower() not in ("", "any", "all", *PATH_PROTOCOLS):
        raise HTTPException(status_code=400, detail=f"protocol must be one of {', '.join(PATH_PROTOCOLS)}")
    make_tracer = await _path_tracer()

    def run() -> dict:
        tracer = make_tracer()
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


def _reachability_file(report: dict[str, Any], fmt: str, verdict: str | None, source: str = "") -> Response:
    """The rows of a sweep report as a CSV or, for ``xlsx``, a workbook whose
    columns fit their text, with a **Summary** tab of the counts by verdict, a
    tab of every row and one per verdict; the CSV has the same summary after
    its rows, under an empty line. ``verdict`` names the file after the rows
    kept (and makes them one tab); the summary still counts the whole sweep.
    A typed ``source`` names the file ``reachability-from-<source>-to-...``.

    A list of networks (``mode`` ``list``) has the ``LIST_COLUMNS`` only, on
    one **Networks** tab and with no summary, in ``networks-<count>``."""
    listed = report.get("mode") == "list"
    columns = reach_sweep.LIST_COLUMNS if listed else reach_sweep.CSV_COLUMNS
    summary: list[list[Any]] = [] if listed else reach_sweep.summary_rows(report["counts"])
    if fmt == "xlsx":
        sheets: list[xlsx.Sheet] = [] if listed else [xlsx.Sheet("Summary", reach_sweep.SUMMARY_COLUMNS, summary)]
        groups = [("Networks", report["rows"])] if listed else reach_sweep.sheet_groups(report["rows"], verdict)
        sheets.extend(
            xlsx.Sheet(title, columns, [reach_sweep.sheet_row(row, columns) for row in rows]) for title, rows in groups
        )
        payload = xlsx.workbook_of(sheets)
        media_type = xlsx.XLSX_MEDIA_TYPE
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(columns)
        writer.writerows(reach_sweep.csv_row(row, columns) for row in report["rows"])
        if summary:
            writer.writerow([])
            writer.writerow(reach_sweep.SUMMARY_COLUMNS)
            writer.writerows(summary)
        payload = output.getvalue().encode("utf-8")
        media_type = "text/csv; charset=utf-8"
    if listed:
        name = f"networks-{len(report['rows'])}"
    else:
        target = "matrix" if report["destination"] is None else report["destination"]["address"]
        route = f"from-{source}-to-{target}" if source else target
        name = f"reachability-{route}-{report['traffic']}" + (f"-{verdict}" if verdict else "")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{stem}.{fmt}"',
            "Cache-Control": "private, no-store",
        },
    )


def _named_subnets(found: dict[str, Any]) -> list[dict[str, Any]]:
    """The subnet index rows of ``_trace_sources`` with their source's name
    (``org_name``; the inventory's is **Inventory**)."""
    org_names = {
        org_ref: str((snapshot.get("org") or {}).get("name") or "") for org_ref, snapshot in found["snapshots"].items()
    }
    org_names[INVENTORY_ORG_REF] = "Inventory"
    return [{**row, "org_name": org_names.get(row["org_ref"], "")} for row in found["subnets"]]


@router.get("/api/topology/reachability")
async def topology_reachability_api(
    request: Request,
    destination: str = Query(default="", max_length=64),
    destination_node: str | None = Query(default=None, max_length=300),
    destination_org_ref: int | None = Query(default=None),
    destination_node_id: str | None = Query(default=None, max_length=300),
    source: str = Query(default="", max_length=64),
    source_node: str | None = Query(default=None, max_length=300),
    source_org_ref: int | None = Query(default=None),
    source_node_id: str | None = Query(default=None, max_length=300),
    list_only: str = Query(default="", max_length=8, alias="list"),
    protocol: str = Query(default="", max_length=8),
    port: int | None = Query(default=None, ge=0, le=65535),
    sources: str | None = Query(default=None, max_length=2000),
    providers: str | None = Query(default=None, max_length=200),
    kinds: str | None = Query(default=None, max_length=200),
    vlans: str | None = Query(default=None, max_length=1000),
    name: str | None = Query(default=None, max_length=1000),
    exclude: str | None = Query(default=None, max_length=1000),
    sites: str | None = Query(default=None, max_length=1000),
    within: str | None = Query(default=None, max_length=2000),
    overlaps: str | None = Query(default=None, max_length=2000),
    in_vpn: str | None = Query(default=None, max_length=8),
    to_sources: str | None = Query(default=None, max_length=2000),
    to_providers: str | None = Query(default=None, max_length=200),
    to_kinds: str | None = Query(default=None, max_length=200),
    to_vlans: str | None = Query(default=None, max_length=1000),
    to_name: str | None = Query(default=None, max_length=1000),
    to_exclude: str | None = Query(default=None, max_length=1000),
    to_sites: str | None = Query(default=None, max_length=1000),
    to_within: str | None = Query(default=None, max_length=2000),
    to_overlaps: str | None = Query(default=None, max_length=2000),
    to_in_vpn: str | None = Query(default=None, max_length=8),
    format: str = Query(default="json", pattern="^(json|csv|xlsx)$"),
    verdict: str | None = Query(default=None, max_length=16),
):
    """Trace one flow to ``destination`` from every source network of the
    whole map the filters keep (``netcontrol.integrations.pathtrace.sweep``),
    and report each one's verdict and what decided it, as JSON or, with
    ``format=csv`` or ``format=xlsx``, as a CSV or spreadsheet attachment
    (the spreadsheet's columns fit their text). A file download with
    ``verdict`` keeps only the rows of that verdict, as the page shows them.

    ``destination_node`` is the graph node that owns the destination, as for
    ``/api/topology/path``; ``destination_org_ref`` + ``destination_node_id``
    name it by the snapshot node of a picked subnet instead.

    With ``destination`` empty the sweep is a matrix: the ``to_*`` filters
    (the same as the source ones) pick the destination networks from the
    same index, and every source network is traced to every destination
    network of the same IP family that it does not overlap. More than
    ``MAX_ROWS`` traces is refused with their ``count``: narrow the
    filters.

    A typed ``source`` (an IP address or network) replaces the source
    filters: it is traced to ``destination``, or to every destination
    network of a matrix. ``source_node`` / ``source_org_ref`` +
    ``source_node_id`` name its owner, as the destination's do.

    ``list=1`` lists the networks the source filters keep without tracing
    them (``mode`` ``list``): ``source``, its owner, the ``to_*`` filters,
    ``protocol``, ``port`` and ``verdict`` are ignored, and so is the limit."""
    try:
        listing = reach_sweep.parse_flag(list_only, "list") is True
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if listing:
        # Nothing is traced: what picks a source or a destination is ignored.
        source, source_node, source_org_ref, source_node_id, protocol, port, verdict = (
            "",
            None,
            None,
            None,
            "",
            None,
            None,
        )
        destination_node, destination_org_ref, destination_node_id = None, None, None
        to_sources = to_providers = to_kinds = to_vlans = to_name = to_exclude = None
        to_sites = to_within = to_overlaps = to_in_vpn = None
    if protocol.strip().lower() not in ("", "any", "all", *PATH_PROTOCOLS):
        raise HTTPException(status_code=400, detail=f"protocol must be one of {', '.join(PATH_PROTOCOLS)}")
    verdict = (verdict or "").strip().lower() or None
    if verdict is not None and verdict not in reach_sweep.VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {', '.join(reach_sweep.VERDICTS)}")
    destination = destination.strip()
    source = source.strip()
    source_values = {
        "sources": sources,
        "providers": providers,
        "kinds": kinds,
        "vlans": vlans,
        "name": name,
        "exclude": exclude,
        "sites": sites,
        "within": within,
        "overlaps": overlaps,
        "in_vpn": in_vpn,
    }
    if source and any(str(value or "").strip() for value in source_values.values()):
        raise HTTPException(
            status_code=400,
            detail="the source filters pick the source networks; leave source empty to trace one source",
        )
    if not source and (
        str(source_node or "").strip() or source_org_ref is not None or str(source_node_id or "").strip()
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "source_node, source_org_ref and source_node_id name the owner of one source; "
                "leave them empty when the source filters pick the source networks"
            ),
        )
    to_values = {
        "sources": to_sources,
        "providers": to_providers,
        "kinds": to_kinds,
        "vlans": to_vlans,
        "name": to_name,
        "exclude": to_exclude,
        "sites": to_sites,
        "within": to_within,
        "overlaps": to_overlaps,
        "in_vpn": to_in_vpn,
    }
    matrix = not destination and not listing
    if not matrix and any(str(value or "").strip() for value in to_values.values()):
        raise HTTPException(
            status_code=400, detail="to_* filters pick the destination networks; leave destination empty to use them"
        )
    if matrix and (
        str(destination_node or "").strip() or destination_org_ref is not None or str(destination_node_id or "").strip()
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "destination_node, destination_org_ref and destination_node_id name the owner of one destination; "
                "leave them empty when the to_* filters pick the destination networks"
            ),
        )
    try:
        filters = reach_sweep.parse_filters(**source_values)
        to_filters = reach_sweep.parse_filters(**to_values) if matrix else None
        # A typed source, and the destination it is traced to, are addresses or networks.
        typed = reach_sweep.typed_row(source) if source else None
        if typed is not None and not matrix:
            reach_sweep.address_of(destination)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    found = await _trace_sources()
    rows = _named_subnets(found)
    try:
        if typed is not None:
            selected = [typed]
        else:
            selected = reach_sweep.select_rows(rows, filters, None if matrix else destination or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    make_tracer = _tracer_of(found)
    if listing:
        listed = await asyncio.to_thread(lambda: reach_sweep.list_rows(make_tracer(), selected))
        if format in ("csv", "xlsx"):
            await _audit(
                "topology",
                f"export_networks_{format}",
                user=_session_user(request),
                detail=f"rows={len(listed)}",
                correlation_id=_corr_id(request),
            )
            return _reachability_file({"mode": "list", "rows": listed}, format, None)
        return {
            "mode": "list",
            "destination": None,
            "source": None,
            "traffic": "",
            "generated_at": datetime.now(UTC).isoformat(),
            "filters": filters.to_json(),
            "to_filters": None,
            "source_count": len(listed),
            "destination_count": 0,
            "candidates": len(listed),
            "limit": reach_sweep.MAX_ROWS,
            "rows": listed,
            "counts": {each: 0 for each in reach_sweep.VERDICTS},
        }
    targets = reach_sweep.select_rows(rows, to_filters, None) if to_filters is not None else []
    count = len(selected)
    if matrix:
        # Pairing thousands of networks with thousands is CPU-bound too.
        count = await asyncio.to_thread(lambda: sum(1 for _ in reach_sweep.iter_pairs(selected, targets)))
    if count > reach_sweep.MAX_ROWS:
        message = (
            f"{count} source→destination pairs match; at most {reach_sweep.MAX_ROWS} are traced at once. "
            if matrix
            else f"{count} source networks match; at most {reach_sweep.MAX_ROWS} are swept at once. "
        )
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": {"code": "too_many_sources", "message": message + "Narrow the filters."},
                "count": count,
                "limit": reach_sweep.MAX_ROWS,
            },
        )

    def owner(tracer: Tracer, node_text: str | None, org_ref: int | None, node_id: str | None) -> Any:
        """The graph node a page named, or the one of a picked subnet's owner."""
        node = _graph_node_id(node_text)
        if node is None and org_ref is not None and node_id:
            node = tracer.graph_of.get((org_ref, node_id.strip()))
        return node

    def run() -> dict[str, Any]:
        tracer = make_tracer()
        chosen = selected
        if typed is not None:
            graph_node = owner(tracer, source_node, source_org_ref, source_node_id)
            chosen = [reach_sweep.typed_row(source, graph_node=graph_node)]
        if matrix:
            return reach_sweep.run_matrix(tracer, reach_sweep.iter_pairs(chosen, targets), protocol=protocol, port=port)
        node = owner(tracer, destination_node, destination_org_ref, destination_node_id)
        return reach_sweep.run(tracer, chosen, destination, destination_node=node, protocol=protocol, port=port)

    try:
        # Building the indexes and walking the map once per trace is CPU-bound.
        report = await asyncio.to_thread(run)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not matrix:
        report["destination"] = report["destination"] or {"address": destination}
    report["source"] = (report["source"] or {"address": source}) if typed is not None else None
    if format in ("csv", "xlsx"):
        if verdict:
            report["rows"] = [row for row in report["rows"] if row["verdict"] == verdict]
        await _audit(
            "topology",
            f"export_reachability_{format}",
            user=_session_user(request),
            detail=(f"source={source} " if typed is not None else "")
            + f"destination={destination or 'matrix'} traffic={report['traffic']} rows={len(report['rows'])}"
            + (f" verdict={verdict}" if verdict else ""),
            correlation_id=_corr_id(request),
        )
        return _reachability_file(report, format, verdict, source)
    return {
        "mode": "matrix" if matrix else "one",
        "source": report["source"],
        "destination": report["destination"],
        "traffic": report["traffic"],
        "generated_at": datetime.now(UTC).isoformat(),
        "filters": filters.to_json(),
        "to_filters": to_filters.to_json() if to_filters is not None else None,
        "source_count": len(selected),
        "destination_count": len(targets) if matrix else 1,
        "candidates": count,
        "limit": reach_sweep.MAX_ROWS,
        "rows": report["rows"],
        "counts": report["counts"],
    }


@router.post("/api/topology/summarize")
async def topology_summarize_api(body: SummarizeRequest):
    """The fewest routes that cover ``addresses`` (``prefix`` rolls each up
    first, ``max_routes`` caps the routes of each IP version), each with the
    inputs it covers and the collected networks of the whole map it overlaps
    (``netcontrol.integrations.pathtrace.summarize``). The source filters
    (as the reachability sweep's) pick the networks checked; ``kinds``
    defaults to the sweep's. A JSON body, since an address list can be
    long; at most ``MAX_ADDRESSES`` entries."""
    try:
        networks = reach_summarize.parse_addresses(body.addresses)
        if len(networks) > reach_summarize.MAX_ADDRESSES:
            raise ValueError(
                f"{len(networks)} addresses given; at most {reach_summarize.MAX_ADDRESSES} are summarized at once"
            )
        filters = reach_sweep.parse_filters(
            sources=body.sources,
            providers=body.providers,
            kinds=body.kinds,
            vlans=body.vlans,
            name=body.name,
            exclude=body.exclude,
            sites=body.sites,
            within=body.within,
            overlaps=body.overlaps,
            in_vpn=body.in_vpn,
        )
        summary = reach_summarize.summarize(networks, prefix=body.prefix, max_routes=body.max_routes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    found = await _trace_sources()
    selected = reach_sweep.select_rows(_named_subnets(found), filters, None)
    make_tracer = _tracer_of(found)

    def run() -> list[dict[str, Any]]:
        # Only the routes' overlaps need listing: the tracer names their owners.
        hits = reach_summarize.overlapping_rows(summary, selected)
        listed = reach_sweep.list_rows(make_tracer(), hits) if hits else []
        return reach_summarize.routes(networks, summary, listed)

    entries = await asyncio.to_thread(run)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "input_count": len(networks),
        "unique_count": len(set(networks)),
        "prefix": body.prefix,
        "max_routes": body.max_routes,
        "filters": filters.to_json(),
        "route_count": len(entries),
        "routes": entries,
        "text": reach_summarize.routes_text(entries),
        # Every input is covered by construction; kept so the page can rely on it.
        "uncovered": [],
    }


@router.get("/api/topology/search/deep")
async def topology_deep_search_api(
    q: str = Query(min_length=2, max_length=100),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Search everything collected for Meraki nodes - VLANs, subnets, routes,
    VPN peers, firewall rules, ports, neighbors, serials - not just names.

    Hits are returned as ``(org_ref, node_id)`` references, which the
    Topology page resolves to nodes on the merged graph. An IP address or a
    network finds the devices whose collected subnets hold it first, the
    most specific first over every source (an inventory host's VLAN, a cloud
    VM's own address or its subnet, then a site range or a VPN local network
    that covers it, then a firewall's summary route): an address inside a
    subnet is no substring of it.
    """
    tokens = q.lower().split()[:8]
    results: list[dict] = []
    seen: set[tuple[int, str]] = set()
    entries = await _latest_entries()
    # An address or network finds the inventory hosts and the snapshot nodes
    # whose networks hold it: the subnets of every source in one list, so the
    # most specific wins whatever source collected it.
    if canonical(q):
        from netcontrol.routes.topology import get_topology

        nodes = (await get_topology(None)).get("nodes") or []
        labels: dict[int, dict[Any, str]] = {INVENTORY_ORG_REF: {n.get("id"): n.get("label") or "" for n in nodes}}
        tagged = [{**subnet, "org_ref": INVENTORY_ORG_REF} for subnet in await _inventory_subnets(nodes)]
        for org_ref, entry in entries:
            tagged.extend({**subnet, "org_ref": org_ref} for subnet in await _subnets_of(entry))
        for subnet in subnets_containing(tagged, q):
            org_ref = int(subnet["org_ref"])
            if (org_ref, subnet["node_id"]) in seen or len(results) >= limit:
                continue
            seen.add((org_ref, subnet["node_id"]))
            if org_ref not in labels:
                snapshot = next(entry["snapshot"] for ref, entry in entries if ref == org_ref)
                labels[org_ref] = {n.get("id"): n.get("label") or "" for n in snapshot.get("nodes") or []}
            inventory = org_ref == INVENTORY_ORG_REF
            place = subnet["site_name"] or ("Inventory" if inventory else "VPN peer")
            results.append(
                {
                    "org_ref": org_ref,
                    "node_id": subnet["node_id"],
                    "label": labels[org_ref].get(int(subnet["node_id"]) if inventory else subnet["node_id"], ""),
                    "snippet": f"{place} · Subnets: {subnet['cidr']} {subnet['name']}".strip(),
                }
            )
    for org_ref, entry in entries:
        if entry["index"] is None:
            entry["index"] = await asyncio.to_thread(build_search_index, entry["snapshot"])
        for hit in search_index(entry["index"], tokens, limit - len(results)):
            if (org_ref, hit["node_id"]) not in seen:
                seen.add((org_ref, hit["node_id"]))
                results.append({"org_ref": org_ref, **hit})
        if len(results) >= limit:
            break
    return {"results": results, "truncated": len(results) >= limit}


# ── Whole-topology HTML export ───────────────────────────────────────────────

_EXPORT_PATH_MAX_PICKS = 6


def _bad_path(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=f"path: {detail}")


def _parse_export_path(raw: str | None) -> dict[str, Any] | None:
    """The Path Mode state the page sends with an export (``?path=``): the
    traffic asked about and the picks, validated. ``None`` when absent."""
    if raw is None or not raw.strip():
        return None
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise _bad_path("not valid JSON") from exc
    if not isinstance(body, dict):
        raise _bad_path("must be a JSON object")

    traffic = body.get("traffic")
    if traffic is None:
        traffic = {}
    if not isinstance(traffic, dict):
        raise _bad_path("traffic must be an object")
    protocol = traffic.get("protocol")
    if protocol is None:
        protocol = ""
    if not isinstance(protocol, str):
        raise _bad_path("traffic.protocol must be a string")
    protocol = protocol.strip().lower()
    protocol = "" if protocol in ("any", "all") else protocol
    if protocol and protocol not in PATH_PROTOCOLS:
        raise _bad_path(f"traffic.protocol must be one of {', '.join(PATH_PROTOCOLS)}")
    port = traffic.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535):
        raise _bad_path("traffic.port must be an integer from 0 to 65535")
    if protocol not in ("tcp", "udp"):
        port = None  # only a TCP or UDP flow has ports

    picks = body.get("picks")
    if not isinstance(picks, list) or not 1 <= len(picks) <= _EXPORT_PATH_MAX_PICKS:
        raise _bad_path(f"picks must be a list of 1 to {_EXPORT_PATH_MAX_PICKS} entries")
    parsed: list[dict[str, Any]] = []
    for number, pick in enumerate(picks, start=1):
        if not isinstance(pick, dict):
            raise _bad_path(f"pick {number} must be an object")
        node = pick.get("node")
        if isinstance(node, bool) or not (isinstance(node, int) or (isinstance(node, str) and node.strip())):
            raise _bad_path(f"pick {number} has no node")
        label = pick.get("label")
        if not isinstance(label, str) or not label.strip():
            raise _bad_path(f"pick {number} has no label")
        subnet = pick.get("subnet")
        if subnet is not None and (not isinstance(subnet, dict) or not isinstance(subnet.get("cidr"), str)):
            raise _bad_path(f"pick {number} has a subnet without a cidr")
        address = pick.get("address")
        if address is not None and not isinstance(address, str):
            raise _bad_path(f"pick {number} has an address that is not a string")
        parsed.append(
            {
                "node": _graph_node_id(str(node)),
                "label": label.strip(),
                "subnet": subnet if subnet and str(subnet["cidr"]).strip() else None,
                "address": (address or "").strip() or None,
            }
        )
    return {"protocol": protocol, "port": port, "picks": parsed}


def _export_path_picks(path: dict[str, Any], node_ids: set[str]) -> list[dict[str, Any]]:
    """The picks on the exported map, in order, keyed the way the viewer
    keys its own picks; a pick whose key repeats an earlier one is dropped."""
    picks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pick in path["picks"]:
        node = str(pick["node"])
        if node not in node_ids:
            continue
        subnet = pick["subnet"]
        address = pick["address"] if subnet else None
        key = f"s:{address or str(subnet['cidr']).strip()}:{node}" if subnet else f"n:{node}"
        if key in seen:
            continue
        seen.add(key)
        picks.append({**pick, "key": key, "export_node": node, "address": address})
    return picks


def _export_path_data(
    path: dict[str, Any],
    picks: list[dict[str, Any]],
    snapshot: dict[str, Any],
    make_tracer: Callable[[], Tracer] | None,
) -> dict[str, Any]:
    """The ``path`` block the export embeds: traffic, picks and, for every
    pair of picks that are both subnets or addresses, the trace each way."""
    node_ids, edge_ids = export_ids(snapshot)
    legs: list[dict[str, Any]] = []
    tracer = make_tracer() if make_tracer is not None else None
    if tracer is not None:
        for i, first in enumerate(picks):
            for second in picks[i + 1 :]:
                if not first["subnet"] or not second["subnet"]:
                    continue
                directions = [
                    offline_trace(
                        tracer,
                        a["address"] or str(a["subnet"]["cidr"]).strip(),
                        b["address"] or str(b["subnet"]["cidr"]).strip(),
                        source_node=a["node"],
                        destination_node=b["node"],
                        protocol=path["protocol"],
                        port=path["port"],
                        node_ids=node_ids,
                        edge_ids=edge_ids,
                    )
                    for a, b in ((first, second), (second, first))
                ]
                legs.append(
                    {"from": first["key"], "to": second["key"], "forward": directions[0], "backward": directions[1]}
                )

    def subnet_of(pick: dict[str, Any]) -> dict[str, Any] | None:
        subnet = pick["subnet"]
        if not subnet:
            return None
        in_vpn = subnet.get("in_vpn")
        return {
            "cidr": str(subnet["cidr"]).strip(),
            "name": str(subnet.get("name") or ""),
            "kind": str(subnet.get("kind") or ""),
            "site_name": str(subnet.get("site_name") or ""),
            "node_id": pick["export_node"],
            "in_vpn": in_vpn if isinstance(in_vpn, bool) else None,
        }

    return {
        "traffic": {"protocol": path["protocol"], "port": path["port"]},
        "picks": [
            {
                "key": pick["key"],
                "node": pick["export_node"],
                "label": pick["label"],
                "subnet": subnet_of(pick),
                "address": pick["address"],
            }
            for pick in picks
        ],
        "legs": legs,
    }


@router.get("/api/topology/export.html")
async def export_topology_html_api(
    request: Request,
    group_id: int | None = Query(default=None),
    download: bool = Query(default=False),
    path: str | None = Query(default=None, max_length=16000),
    engine: bool = Query(default=True),
):
    """Self-contained interactive HTML map of the topology.

    Covers what the Topology page shows - inventory devices and their
    discovered links plus (for the all-groups view) every Meraki organization
    - with each device's collected detail embedded. ``download=1`` sends it as
    an attachment; otherwise it renders inline for a new browser tab.

    ``path`` is the Path Mode state open on the page (JSON: ``traffic`` and
    ``picks``). The export then carries the picks and, since a file cannot
    ask the server, the trace each way of every leg between two subnets or
    addresses, run over the whole map whatever ``group_id`` is.

    ``engine`` (on by default) also embeds the path tracer when the Pyodide
    runtime is vendored: the runtime, the engine's source and the trace
    inputs of the whole map, so the file traces any two subnets or addresses
    itself, offline. ``engine=0``, or no runtime, gives the smaller file
    without it.
    """
    from netcontrol.routes.topology import get_topology

    asked_path = _parse_export_path(path)
    graph = await get_topology(group_id)
    picks: list[dict[str, Any]] = []
    if asked_path is not None:
        picks = _export_path_picks(asked_path, {str(n["id"]) for n in graph.get("nodes") or []})
    # Packing the runtime the first time reads and compresses megabytes.
    with_engine = engine and await asyncio.to_thread(pyodide_runtime) is not None
    traced_legs = sum(1 for pick in picks if pick["subnet"]) >= 2
    sources = await _trace_sources() if with_engine or traced_legs else None
    make_tracer = _tracer_of(sources) if sources is not None and traced_legs else None
    # The viewer picks the networks of inventory hosts too.
    inventory_subnets = (
        [row for row in sources["subnets"] if row.get("org_ref") == INVENTORY_ORG_REF]
        if sources is not None
        else await _inventory_subnets(graph.get("nodes") or [])
    )
    cloud_rows = await _offline_clouds(sources["clouds"]) if with_engine and sources is not None else {}
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

    def build() -> tuple[dict[str, Any], dict[str, Any] | None, bool, str]:
        snapshot = graph_to_snapshot(graph, snapshots, host_sections, title=title)
        embedded = _export_path_data(asked_path, picks, snapshot, make_tracer) if asked_path and picks else None
        tracer = None
        if with_engine and sources is not None:
            inputs = offline_inputs(
                sources["graph"],
                sources["snapshots"],
                cloud_rows,
                sources["host_forwarding"],
                sources["subnets"],
                snapshot,
                placements=sources.get("placements"),
            )
            tracer = tracer_payload(offline_dumps(inputs))
        page = render_topology_html(snapshot, path=embedded, tracer=tracer, subnets=inventory_subnets)
        return snapshot, embedded, tracer is not None, page

    # Layout of a large topology, the traces and packing the tracer are
    # CPU-bound; keep them off the event loop.
    snapshot, embedded_path, traces_itself, html = await asyncio.to_thread(build)

    # The export has its own CSP (the middleware only fills in a default): the
    # viewer needs an inline script, and ``sandbox`` isolates it from the
    # Plexus origin so it can never use the session it was served under.
    headers = {"Content-Security-Policy": export_csp(traces_itself), "Cache-Control": "private, no-store"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{export_filename(snapshot)}"'
        await _audit(
            "topology",
            "export_html",
            user=_session_user(request),
            detail=f"group_id={group_id} nodes={len(snapshot['nodes'])}"
            + (f" path_legs={len(embedded_path['legs'])}" if embedded_path else "")
            + f" engine={int(traces_itself)}",
            correlation_id=_corr_id(request),
        )
    return HTMLResponse(html, headers=headers)
