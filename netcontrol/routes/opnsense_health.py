"""
opnsense_health.py -- An OPNsense firewall's health in the monitoring poll.

An inventory host that is the firewall of an OPNsense topology source (the
host its collections match, see ``opnsense_collection.matching_host``) needs
no SNMP profile for CPU, memory and the rest: on every monitoring poll of
that host, ``add_to_poll`` reads the light health calls over the source's
API key (``collector.POLL_HEALTH_PARTS``: memory, file systems, temperature,
uptime and load, ``top``'s CPU line, the state table; not the services, which
the collection tracks) and merges them into the poll result before it is
stored and evaluated:

  - CPU, memory and uptime fill the poll's own fields only where SNMP left
    them empty, so a host polled over both keeps one sample per poll and
    its SNMP values; an SNMP poll that fails leaves them to the API.
  - the whole summary is kept as ``opnsense_health``, from which the poll
    emits the ``FIREWALL_METRICS`` samples and raises the built-in disk and
    state table alerts (``netcontrol.integrations.opnsense.health``).
  - a poll that SNMP / SSH failed while the API answered is ``ok``: the
    firewall is up.

The same session also reads the VPN counters when the source's
``include_vpn`` option is on (``collector.collect_vpn``: the IPsec
connections and their installed child SAs, the WireGuard peers, the
OpenVPN sessions; not the configured child SAs) and stores the tunnels'
traffic rates since their last reading (``topology_traffic.record_poll_traffic``),
so a rate survives an IPsec rekey: readings every poll interval, not every
collection. A failed VPN read loses only that part.

With the ``include_ids_alerts`` option on, the session also reads the
intrusion detection alerts newer than the newest one stored and stores
them as security events of the source, with their alerts
(``netcontrol.routes.opnsense_ids``), so an IDS alert arrives within a
poll interval. A source whose last read found the IDS disabled is skipped
until a collection finds it enabled. A failed IDS read loses only that part.

Which host belongs to which source is kept in memory: refreshed from the
newest snapshot of each source (its summary's ``inventory_host_id``, written
by ``record_inventory_host`` at every collection) at most every
``SOURCES_TTL_SECONDS``, and at once when a collection stores it. A source
whose ``include_health``, ``include_vpn`` and ``include_ids_alerts`` options are all off, whose
automatic collection is off or that has no key is not read. Best-effort: a failure is logged and the
poll goes on without it.

The same snapshot summary answers ``source_of_host`` (``inventory_hosts``,
whatever the options): the source a backup policy downloads a firewall's
config.xml from (``netcontrol.routes.opnsense_backup``).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

import routes.database as db

from netcontrol.client_cache import ClientCache, fingerprint
from netcontrol.integrations.http_common import guard_api_host
from netcontrol.integrations.opnsense.client import OpnsenseApiError, OpnsenseClient
from netcontrol.integrations.opnsense.collector import (
    POLL_HEALTH_PARTS,
    call_reader,
    collect_health,
    collect_vpn,
    sanitize_options,
)
from netcontrol.integrations.opnsense.normalize import PROVIDER, health_summary, vpn_traffic_blocks
from netcontrol.integrations.traffic import parse_time
from netcontrol.routes import opnsense_ids
from netcontrol.routes.topology_traffic import record_poll_traffic
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.opnsense")

SOURCES_TTL_SECONDS = 600.0
# One health read of the poll: each call, and its single retry.
POLL_TIMEOUT_SECONDS = 15.0
# The poll fields the API fills where SNMP left them empty.
POLL_FIELDS = ("cpu_percent", "memory_percent", "memory_used_mb", "memory_total_mb", "uptime_seconds")
SUMMARY_KEY = "inventory_host_id"

# host_id -> org_ref of its OPNsense source, and when it was read.
_HOST_SOURCES: dict[int, int] = {}
_loaded_at = 0.0
_lock = asyncio.Lock()


def _eligible(org: dict) -> bool:
    options = sanitize_options(org.get("options"))
    return (
        str(org.get("provider") or "") == PROVIDER
        and bool(org.get("has_api_key"))
        and bool(org.get("auto_collect", True))
        and bool(options["include_health"] or options["include_vpn"] or options["include_ids_alerts"])
    )


async def inventory_hosts(orgs: list[dict]) -> dict[int, int]:
    """host_id -> org_ref of the firewall of each OPNsense source in
    ``orgs``, from the summary of its newest snapshot (``SUMMARY_KEY``,
    written by ``record_inventory_host``). Other providers are skipped."""
    found: dict[int, int] = {}
    for org in orgs:
        if str(org.get("provider") or "") != PROVIDER:
            continue
        rows = await db.list_meraki_snapshots(int(org["id"]), 1)
        host_id = (rows[0].get("summary") or {}).get(SUMMARY_KEY) if rows else None
        if host_id:
            found[int(host_id)] = int(org["id"])
    return found


async def source_of_host(host_id: int) -> dict | None:
    """The OPNsense source whose firewall is inventory host ``host_id`` (as
    its newest collection matched it), whatever its health, VPN and IDS
    options; ``None`` when there is none. A backup policy backs the
    firewall up over this source's API key."""
    orgs = await db.list_meraki_orgs()
    org_ref = (await inventory_hosts(orgs)).get(int(host_id))
    return next((org for org in orgs if int(org["id"]) == org_ref), None)


async def _host_sources() -> dict[int, int]:
    """host_id -> org_ref of every source whose health the poll reads."""
    global _loaded_at
    if time.monotonic() - _loaded_at < SOURCES_TTL_SECONDS:
        return _HOST_SOURCES
    async with _lock:
        if time.monotonic() - _loaded_at < SOURCES_TTL_SECONDS:
            return _HOST_SOURCES
        found = await inventory_hosts([org for org in await db.list_meraki_orgs() if _eligible(org)])
        _HOST_SOURCES.clear()
        _HOST_SOURCES.update(found)
        _loaded_at = time.monotonic()
    return _HOST_SOURCES


def forget_sources() -> None:
    """Read the host map again at the next poll (tests, a source deleted),
    and the IDS of every source too."""
    global _loaded_at
    _loaded_at = 0.0
    _HOST_SOURCES.clear()
    opnsense_ids.forget()


def record_inventory_host(snapshot: dict, org_ref: int, host: dict | None) -> None:
    """Note the inventory host of a collection's firewall in its summary
    (read back by ``_host_sources``) and in the host map at once."""
    host_id = int(host["id"]) if host and host.get("id") else None
    snapshot.setdefault("summary", {})[SUMMARY_KEY] = host_id
    for known, source in list(_HOST_SOURCES.items()):
        if source == int(org_ref) and known != host_id:
            _HOST_SOURCES.pop(known, None)
    if host_id is not None:
        _HOST_SOURCES[host_id] = int(org_ref)


def merge_health(result: dict, summary: dict[str, Any]) -> None:
    """Merge a firewall health summary into a poll result (see the module
    docstring). Pure."""
    for key in POLL_FIELDS:
        if result.get(key) is None and summary.get(key) is not None:
            result[key] = summary[key]
    result["opnsense_health"] = summary
    if result.get("poll_status") == "error":
        result["poll_status"] = "ok"
        result["poll_error"] = ""


# The poll's API clients, one per source, reused from poll to poll so a poll
# does not load a new TLS context. Keyed by event loop and source; a changed
# base URL, TLS choice or API key (or client factory) builds a new client and
# closes the old one.
_POLL_CLIENTS: ClientCache[OpnsenseClient] = ClientCache(
    "opnsense_health",
    max_entries=256,
    max_idle_s=2 * 3600.0,
    close=lambda client: client.close(),
)


async def _poll_client(
    org: dict, secret: str, options: dict[str, Any], factory: Callable[..., OpnsenseClient]
) -> OpnsenseClient:
    """The cached poll client of ``org`` (built with ``factory``, the
    topology module's client helper). A reused client runs the outbound
    address guard again first, as a new one does before it connects; a
    refusal raises ``OpnsenseApiError``."""
    built: list[OpnsenseClient] = []

    def build() -> OpnsenseClient:
        client = factory(org, secret, options, max_retries=1, timeout=POLL_TIMEOUT_SECONDS)
        built.append(client)
        return client

    client = _POLL_CLIENTS.get(
        (asyncio.get_running_loop(), int(org["id"])),
        (str(org.get("base_url") or ""), bool(options.get("verify_tls", True)), fingerprint(secret), factory),
        build,
    )
    if not built:
        await guard_api_host(client.base_url, "OPNsense", lambda message: OpnsenseApiError(message, transport=True))
    return client


async def read_firewall(
    org: dict, secret: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, tuple[dict[str, Any], dict[str, Any]] | None]:
    """``(health summary, VPN payloads, (IDS read, its state))`` of one
    source's firewall, read in one session: each ``None`` when its option
    is off or nothing of it answered. Raises ``OpnsenseApiError`` for a
    rejected key or an unreachable firewall during the health read; a
    failure of the VPN or IDS read only loses that part."""
    # Imported here: meraki_topology imports the routes of every source.
    from netcontrol.routes.meraki_topology import _opnsense_client

    options = sanitize_options(org.get("options"))
    errors: list[dict[str, Any]] = []
    summary: dict[str, Any] | None = None
    vpn: dict[str, Any] | None = None
    ids: tuple[dict[str, Any], dict[str, Any]] | None = None
    client = await _poll_client(org, secret, options, _opnsense_client)
    if options["include_health"]:
        raw, answered = await collect_health(client, errors, POLL_HEALTH_PARTS)
        summary = health_summary(raw) if answered else None
    if options["include_vpn"]:
        try:
            vpn = await collect_vpn(call_reader(client, errors), configured=False)
        except Exception as exc:  # noqa: BLE001 - the health part stands on its own
            LOGGER.warning(
                "opnsense vpn counters: %s not read: %s", org.get("name") or org.get("id"), type(exc).__name__
            )
    if options["include_ids_alerts"] and opnsense_ids.poll_wanted(int(org["id"])):
        try:
            found, state = await opnsense_ids.read_in_session(client, int(org["id"]), errors)
            ids = (found, state) if found is not None else None
        except Exception as exc:  # noqa: BLE001 - the health part stands on its own
            LOGGER.warning("opnsense ids alerts: %s not read: %s", org.get("name") or org.get("id"), type(exc).__name__)
    for error in errors:
        if not error.get("info"):
            LOGGER.debug("opnsense poll: %s", redact_value(str(error.get("message") or "")))
    return summary, vpn, ids


async def _record_vpn(org_ref: int, vpn: dict[str, Any]) -> int:
    """Store the tunnels' traffic rates of a poll's VPN read. Never raises."""
    try:
        at = parse_time(vpn.get("vpn_read_at"))
        if at is None:
            return 0
        return await record_poll_traffic(PROVIDER, org_ref, vpn_traffic_blocks(vpn), at)
    except Exception as exc:  # noqa: BLE001 - the poll goes on without it
        LOGGER.warning("opnsense vpn counters: source %s not recorded: %s", org_ref, type(exc).__name__)
        return 0


async def add_to_poll(host: dict, result: dict) -> bool:
    """Read the health of ``host`` when it is the firewall of an OPNsense
    source and merge it into its poll ``result``, and store its tunnels'
    traffic rates and its IDS alerts. Returns whether the health was
    merged. Never raises."""
    try:
        org_ref = (await _host_sources()).get(int(host["id"]))
        if org_ref is None:
            return False
        org = await db.get_meraki_org(org_ref)
        if not org or not _eligible(org):
            return False
        secret = await db.get_meraki_org_api_key(org_ref)
        if not secret:
            return False
        summary, vpn, ids = await read_firewall(org, secret)
    except OpnsenseApiError as exc:
        LOGGER.warning(
            "opnsense health: %s not read: %s", host.get("hostname") or host.get("id"), redact_value(str(exc))
        )
        return False
    except Exception as exc:  # noqa: BLE001 - the poll goes on without it
        LOGGER.warning("opnsense health: %s not read: %s", host.get("hostname") or host.get("id"), type(exc).__name__)
        return False
    if vpn is not None:
        await _record_vpn(int(org_ref), vpn)
    if ids is not None:
        await opnsense_ids.record(int(org_ref), str(org.get("name") or ""), ids[0], host, ids[1])
    if summary is None:
        return False
    merge_health(result, summary)
    return True
