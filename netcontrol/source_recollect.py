"""Immediate re-collection of an OPNsense topology source, asked for by syslog.

An OPNsense firewall's gateways, CARP roles, VPN tunnels and config.xml
reach Plexus through the collection of its topology source (hourly by
default). When the firewall logs that one of them just changed (a gateway
alarm, a CARP transition, a tunnel coming up or going down, a configuration
save: ``netcontrol.syslog_rules.recollect_reason``), the source is collected
again within seconds, through the same path the schedule and "Collect now"
use (``meraki_topology.collect_source_now``). The availability tracker then
raises or resolves its gateway, tunnel and CARP alerts from the fresh
snapshot, and a configuration change gets its config.xml backup and drift
check right away. The messages never raise alerts of their own: the tracker
owns those conditions (persistence, SLA, mutes).

- **Source resolution.** The message's source address is mapped to the
  OPNsense source(s) of that firewall: by the inventory host it resolved to
  (the host the newest snapshot matched the firewall to) and by the
  firewall's own addresses from its newest snapshot (API address, interface
  addresses, CARP VIPs: ``normalize.snapshot_addresses``), so a firewall
  that is no inventory host triggers too. The map is cached for
  ``MAP_TTL_SECONDS`` and rebuilt only when a trigger message arrives; the
  messages themselves cause no database reads.
- **Debounce and rate limit.** A run starts ``DELAY_SECONDS`` after the
  first message (the state settles, a burst becomes one run), at most once
  per source every ``MIN_INTERVAL_SECONDS`` counted from the last run's
  start; messages during the cooldown or during a run leave one trailing run.
  At most ``MAX_RUNS_PER_HOUR`` runs per source in any hour: syslog is
  unauthenticated UDP, so a flapping gateway or a forged message must not
  keep a firewall's API busy or push its kept snapshots out one a minute.
  The scheduled collection is not affected.
  A source whose collection is already running (scheduled or by hand) is
  retried after ``BUSY_RETRY_SECONDS``: two collections of one source never
  run at once.
- **IDS alerts.** A Suricata alert line (reason ``ids``) does not collect
  the source: it reads only its IDS alerts
  (``netcontrol.routes.opnsense_ids.read_source_now``), with the same
  debounce and interval, but outside the hour's ``MAX_RUNS_PER_HOUR``
  (``READ_ONLY_REASONS``), so an attack logging an alert a second neither
  re-collects the firewall nor uses up the runs a gateway alarm needs.
- **Failure.** A failed collection is logged (and recorded on the source
  like any failed build); it never touches the stored syslog events.

The switch is ``recollect_trigger`` in ``state.EVENT_RECEIVER_CONFIG``
(``netcontrol.syslog_rules.process_recollect_batch`` reads it).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import routes.database as db

from netcontrol.integrations.opnsense.normalize import PROVIDER, snapshot_addresses
from netcontrol.monitoring_repoll import keep_task

LOGGER = logging.getLogger("plexus.source_recollect")

# Recorded as the user of the collections this module starts.
RECOLLECT_USER = "syslog"
DELAY_SECONDS = 5.0
MIN_INTERVAL_SECONDS = 60.0
# The most runs of one source in any HOUR_SECONDS; a run asked for beyond
# that waits until the oldest of them is an hour old.
MAX_RUNS_PER_HOUR = 6
HOUR_SECONDS = 3600.0
BUSY_RETRY_SECONDS = 15.0
MAP_TTL_SECONDS = 60.0
# A map that could not be built is retried after this long.
MAP_RETRY_SECONDS = 10.0
# The most addresses mapped (a firewall with thousands of VLAN addresses
# must not grow the map without bound).
MAP_MAX_ADDRESSES = 8192
_LAST_RUN_MAX = 1024
# Reasons that read one part of the source instead of collecting it (the
# IDS alerts): such a run waits for the debounce and the interval like any
# other, but is not one of the hour's MAX_RUNS_PER_HOUR collections.
READ_ONLY_REASONS = frozenset({"ids"})

# Monotonic clock and sleep, replaced in tests.
_clock: Callable[[], float] = time.monotonic
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


# ── Source resolution ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SourceMap:
    """Which OPNsense sources a syslog source belongs to: by address and by
    inventory host id."""

    by_ip: dict[str, frozenset[int]] = field(default_factory=dict)
    by_host: dict[int, frozenset[int]] = field(default_factory=dict)

    def sources_for(self, source_ip: str, host_id: int | None) -> frozenset[int]:
        found = set(self.by_ip.get(_canonical(source_ip), frozenset()))
        if host_id is not None:
            found |= self.by_host.get(int(host_id), frozenset())
        return frozenset(found)


def _canonical(text: str) -> str:
    try:
        return str(ipaddress.ip_address(str(text or "").strip()))
    except ValueError:
        return ""


def _url_address(url: str) -> str:
    """The host of a source's API URL when it is an address (a name is not
    resolved: the snapshot's addresses cover the firewall)."""
    try:
        return _canonical(urlsplit(str(url or "")).hostname or "")
    except ValueError:
        return ""


def snapshot_host_ids(snapshot: dict) -> set[int]:
    """The inventory hosts an OPNsense snapshot tied its firewall to: the
    firewall node's inventory match and the host its rule counters belong
    to (``opnsense_collection.attach_rule_stats``)."""
    found: set[int] = set()
    for node in snapshot.get("nodes") or []:
        if isinstance(node, dict) and node.get("kind") == "appliance":
            host_id = (node.get("inventory") or {}).get("host_id")
            if isinstance(host_id, int):
                found.add(host_id)
    stats = snapshot.get("rule_stats")
    if isinstance(stats, dict) and isinstance(stats.get("host_id"), int):
        found.add(int(stats["host_id"]))
    return found


async def build_source_map() -> SourceMap:
    """Map the addresses and inventory hosts of every OPNsense source with a
    stored API key to the source, from the source row and its newest
    snapshot."""
    from netcontrol.routes import meraki_topology as topology
    from netcontrol.routes.opnsense_collection import matching_host

    by_ip: dict[str, set[int]] = {}
    by_host: dict[int, set[int]] = {}
    hosts: list[dict] | None = None
    for org in await db.list_meraki_orgs():
        if topology._provider_of(org) != PROVIDER or not org.get("has_api_key"):
            continue
        org_ref = int(org["id"])
        addresses = [_url_address(org.get("base_url") or "")]
        host_ids: set[int] = set()
        found = await topology.latest_snapshot_of(org_ref)
        if found is not None:
            snapshot = found[1]
            addresses.extend(snapshot_addresses(snapshot))
            host_ids |= snapshot_host_ids(snapshot)
            if hosts is None:
                hosts = await db.get_all_hosts()
            # The firewall may have been imported after its newest snapshot.
            host = await matching_host(snapshot, hosts)
            if host is not None:
                host_ids.add(int(host["id"]))
        for address in addresses:
            if address and (address in by_ip or len(by_ip) < MAP_MAX_ADDRESSES):
                by_ip.setdefault(address, set()).add(org_ref)
        for host_id in host_ids:
            by_host.setdefault(host_id, set()).add(org_ref)
    return SourceMap(
        by_ip={k: frozenset(v) for k, v in by_ip.items()},
        by_host={k: frozenset(v) for k, v in by_host.items()},
    )


_map: SourceMap | None = None
_map_expires = 0.0


async def source_map() -> SourceMap:
    """The cached source map, rebuilt when older than ``MAP_TTL_SECONDS``. A
    failed rebuild keeps the previous map (or an empty one) and is retried
    after ``MAP_RETRY_SECONDS``. Called by the receiver's single batch
    writer, so no lock: two rebuilds at once would only repeat the work."""
    global _map, _map_expires
    now = _clock()
    if _map is not None and now < _map_expires:
        return _map
    try:
        _map = await build_source_map()
        _map_expires = now + MAP_TTL_SECONDS
    except Exception as exc:  # noqa: BLE001 - a lookup failure must not stop the receiver
        LOGGER.warning("syslog re-collect: source map not built: %s", type(exc).__name__)
        _map = _map or SourceMap()
        _map_expires = now + MAP_RETRY_SECONDS
    return _map


def invalidate_source_map() -> None:
    global _map, _map_expires
    _map = None
    _map_expires = 0.0


# ── Scheduling ───────────────────────────────────────────────────────────────

# org_ref -> monotonic time its pending run is due.
_due: dict[int, float] = {}
# org_ref -> why the pending run was asked for (gateway, carp, vpn, config).
_reasons: dict[int, set[str]] = {}
# org_ref -> monotonic time its last run started.
_last_run: dict[int, float] = {}
# org_ref -> monotonic start times of its last MAX_RUNS_PER_HOUR runs.
_run_times: dict[int, deque[float]] = {}
_tasks: dict[int, asyncio.Task] = {}


def note_recollect(org_ref: int, reason: str) -> bool:
    """A trigger message for source ``org_ref``: schedule its re-collection
    ``DELAY_SECONDS`` from now, but not sooner than ``MIN_INTERVAL_SECONDS``
    after its last run started, nor before the hour's ``MAX_RUNS_PER_HOUR``
    allows another. True when this scheduled a run, False when it joined
    one already pending (one pending run per source)."""
    _reasons.setdefault(org_ref, set()).add(reason)
    if org_ref in _due:
        return False
    now = _clock()
    due = now + DELAY_SECONDS
    last = _last_run.get(org_ref)
    if last is not None:
        due = max(due, last + MIN_INTERVAL_SECONDS)
    recent = _run_times.get(org_ref)
    read_only = _reasons[org_ref] <= READ_ONLY_REASONS
    if recent is not None and len(recent) >= MAX_RUNS_PER_HOUR and not read_only:
        due = max(due, recent[0] + HOUR_SECONDS)
    _due[org_ref] = due
    task = _tasks.get(org_ref)
    if task is None or task.done():
        _tasks[org_ref] = keep_task(asyncio.ensure_future(_waiter(org_ref)))
    return True


async def _waiter(org_ref: int) -> None:
    try:
        while org_ref in _due:
            wait = _due[org_ref] - _clock()
            if wait > 0:
                await _sleep(wait)
                continue
            del _due[org_ref]
            reasons = _reasons.pop(org_ref, set())
            used = _run_times.get(org_ref)
            if (
                not reasons <= READ_ONLY_REASONS
                and used is not None
                and len(used) >= MAX_RUNS_PER_HOUR
                and used[0] + HOUR_SECONDS > _clock()
            ):
                # A collection joined a pending read while the hour's runs
                # are used up: it waits for the hour, the read runs now.
                _reasons.setdefault(org_ref, set()).update(reasons - READ_ONLY_REASONS)
                _due[org_ref] = used[0] + HOUR_SECONDS
                reasons = reasons & READ_ONLY_REASONS
                if not reasons:
                    continue
            previous = _last_run.get(org_ref)
            # Counted from the start: messages logged during the run leave
            # one trailing run a full interval after this one started.
            started = _last_run[org_ref] = _clock()
            recent = _run_times.setdefault(org_ref, deque(maxlen=MAX_RUNS_PER_HOUR))
            if not (reasons and reasons <= READ_ONLY_REASONS):
                recent.append(started)  # a read is not one of the hour's runs
            try:
                outcome = await run_recollect(org_ref, reasons)
            except Exception as exc:  # noqa: BLE001 - one source's run must not stop the waiter
                LOGGER.warning("syslog re-collect: collection of source %s failed: %s", org_ref, type(exc).__name__)
                outcome = "failed"
            if outcome == "busy":
                # Another collection of the source is running; it may have
                # read the state before the event, so try again after it.
                if previous is None:
                    _last_run.pop(org_ref, None)
                else:
                    _last_run[org_ref] = previous
                if recent and recent[-1] == started:
                    recent.pop()  # nothing was collected: not one of the hour's runs
                _reasons.setdefault(org_ref, set()).update(reasons)
                _due.setdefault(org_ref, _clock() + BUSY_RETRY_SECONDS)
    finally:
        _tasks.pop(org_ref, None)
        _prune()


def _prune() -> None:
    if len(_last_run) <= _LAST_RUN_MAX:
        return
    cutoff = _clock() - HOUR_SECONDS
    for org_ref, at in list(_last_run.items()):
        if at < cutoff and org_ref not in _due:
            _last_run.pop(org_ref, None)
            _run_times.pop(org_ref, None)


async def run_recollect(org_ref: int, reasons: set[str]) -> str:
    """Collect source ``org_ref`` now. Returns the collection's status,
    ``busy`` when one is already running, or ``skipped`` when the source is
    gone, is no OPNsense source or has no API key. With ``READ_ONLY_REASONS``
    alone (a Suricata alert line), only the source's IDS alerts are read
    (``opnsense_ids.read_source_now``)."""
    from netcontrol.routes import meraki_topology as topology

    if reasons and reasons <= READ_ONLY_REASONS:
        # A Suricata alert line: only the IDS alerts are read, not the source.
        from netcontrol.routes.opnsense_ids import read_source_now

        return await read_source_now(org_ref)
    org = await db.get_meraki_org(org_ref)
    if not org or topology._provider_of(org) != PROVIDER or not org.get("has_api_key"):
        return "skipped"
    why = ", ".join(sorted(reasons)) or "syslog"
    LOGGER.info("syslog re-collect: collecting source %s (%s)", org["name"], why)
    status = await topology.collect_source_now(org, RECOLLECT_USER)
    if status is None:
        return "busy"
    if status == "failed":
        LOGGER.warning("syslog re-collect: collection of source %s failed (see the source's last result)", org["name"])
    return status


async def schedule_for_events(events: Iterable[tuple[str, int | None, str]]) -> int:
    """Schedule the re-collections ``(source_ip, host_id, reason)`` events
    ask for. Returns how many runs were newly scheduled."""
    events = list(events)
    if not events:
        return 0
    mapping = await source_map()
    scheduled = 0
    for source_ip, host_id, reason in events:
        for org_ref in sorted(mapping.sources_for(source_ip, host_id)):
            if note_recollect(org_ref, reason):
                scheduled += 1
    return scheduled


def pending() -> dict[int, list[str]]:
    """The sources with a run pending and why (tests, diagnostics)."""
    return {org_ref: sorted(_reasons.get(org_ref, set())) for org_ref in _due}


def reset_state() -> None:
    """Forget pending runs, run times and the map (tests)."""
    for task in _tasks.values():
        task.cancel()
    _tasks.clear()
    _due.clear()
    _reasons.clear()
    _last_run.clear()
    _run_times.clear()
    invalidate_source_map()
