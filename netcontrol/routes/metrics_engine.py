"""
metrics_engine.py -- Prometheus-style metrics infrastructure:
  - Data downsampling (raw → hourly → daily rollups)
  - Multi-vendor OID registry with HOST-RESOURCES-MIB fallback
  - Per-interface time-series storage with rate calculation
  - Flexible metric_samples (Prometheus data model)
  - Structured metrics query API
  - SNMP trap / syslog UDP receiver

Object scope: metric series, interface series and trap/syslog events follow
their host (a scoped caller's "all hosts" is the hosts it may read; an event
from an unknown source is visible to unrestricted callers only); the metric
names and the vendor OID registry hold no host data.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import struct
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import netcontrol.routes.state as state
from netcontrol import (
    health_checks,
    listener_sources,
    snmpv3_engine,
    syslog_rules,
    syslog_stream,
    syslog_tls,
    trap_rules,
)
from netcontrol.bounded_map import BoundedDict
from netcontrol.integrations.apc.snmp import UPS_METRICS, ups_metric_samples
from netcontrol.integrations.apc.traps import handle_apc_trap, parse_apc_trap
from netcontrol.integrations.opnsense.health import FIREWALL_METRICS, firewall_metric_samples
from netcontrol.integrations.traffic import parse_time
from netcontrol.object_scope import (
    HOST_NOT_FOUND,
    group_filter,
    readable_host_ids,
    require_object_host,
    scope_exempt,
    scoped,
)
from netcontrol.payload_cache import PayloadCache
from netcontrol.routes import opnsense_filterlog
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.snmp import decode_snmp_trap, snmp_inform_response, trap_community_matches
from netcontrol.sample_history import history_complete
from netcontrol.snmp_traps import name_trap
from netcontrol.snmpv3_traps import (
    REFUSED as SNMPV3_REFUSED,
    PendingV3Trap,
    ReplayGuard,
    V3Failure,
    V3Header,
    decode_snmpv3_inform,
    decode_snmpv3_trap,
    engine_discovery_report,
    parse_snmpv3_header,
    resolve_trap_v3_credentials,
)
from netcontrol.telemetry import configure_logging, redact_value

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.metrics_engine")

# Strong references to fire-and-forget background tasks. asyncio only holds a
# weak reference to a pending task, so without this a spike-event or trap/syslog
# store task can be garbage-collected before it runs. Tasks discard themselves
# on completion.
_bg_tasks: set[asyncio.Task] = set()


def _spawn_bg(coro) -> asyncio.Task:
    """Schedule a background coroutine, retaining a strong reference and
    logging any exception it raises instead of dropping it silently."""
    task = asyncio.ensure_future(coro)
    _bg_tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _bg_tasks.discard(t)
        if not t.cancelled():
            exc = t.exception()
            if exc is not None:
                LOGGER.error("metrics: background task failed: %s", exc, exc_info=exc)

    task.add_done_callback(_done)
    return task


# ═════════════════════════════════════════════════════════════════════════════
# 1.  VENDOR OID REGISTRY  (Multi-vendor SNMP support)
# ═════════════════════════════════════════════════════════════════════════════

_AOS_SWITCH_OIDS = {
    "vendor": "Aruba",
    "device_type": "aruba_osswitch",
    "cpu_oid": "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1",  # hpSwitchCpuStat (walked to its .0)
    "cpu_walk": 1,
    "mem_used_oid": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7",  # hpLocalMemAllocBytes
    "mem_free_oid": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6",  # hpLocalMemFreeBytes
    "mem_total_oid": "",
    "uptime_oid": "1.3.6.1.2.1.1.3",
}

# Built-in vendor OID map.  The DB table lets operators add their own.
# HOST-RESOURCES-MIB OIDs are the universal fallback.
VENDOR_OID_DEFAULTS: dict[str, dict] = {
    "cisco_ios": {
        "vendor": "Cisco",
        "device_type": "cisco_ios",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.48.1.1.1.5",
        "mem_free_oid": "1.3.6.1.4.1.9.9.48.1.1.1.6",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "cisco_nxos": {
        "vendor": "Cisco",
        "device_type": "cisco_nxos",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.48.1.1.1.5",
        "mem_free_oid": "1.3.6.1.4.1.9.9.48.1.1.1.6",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "juniper": {
        "vendor": "Juniper",
        "device_type": "juniper",
        "cpu_oid": "1.3.6.1.4.1.2636.3.1.13.1.8",  # jnxOperatingCPU
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.2636.3.1.13.1.11",  # jnxOperatingBuffer
        "mem_free_oid": "",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "arista_eos": {
        "vendor": "Arista",
        "device_type": "arista_eos",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",  # hrProcessorLoad (HOST-RESOURCES)
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",  # hrStorageUsed
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",  # hrStorageSize
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "fortinet": {
        "vendor": "Fortinet",
        "device_type": "fortinet",
        "cpu_oid": "1.3.6.1.4.1.12356.101.4.1.3.0",  # fgSysCpuUsage
        "cpu_walk": 0,
        "mem_used_oid": "1.3.6.1.4.1.12356.101.4.1.4.0",  # fgSysMemUsage (%)
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.4.1.12356.101.4.1.5.0",  # fgSysMemCapacity
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "paloalto": {
        "vendor": "Palo Alto",
        "device_type": "paloalto",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",  # hrProcessorLoad
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    # ASA and FTD share the same LINA datapath/MIBs.  CPU comes from
    # CISCO-PROCESS-MIB (cpmCPUTotal5secRev, walked because there is
    # one entry per CPU); memory from CISCO-ENHANCED-MEMPOOL-MIB
    # (cempMemPoolHCUsed/Free, walked across the "processor" pool).
    # Substring match in resolve_oids_for_device() picks the longest
    # key, so "cisco_ftd" wins over "cisco_ios" / "cisco" automatically.
    "cisco_asa": {
        "vendor": "Cisco",
        "device_type": "cisco_asa",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7",  # cpmCPUTotal5secRev
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.221.1.1.1.1.18",  # cempMemPoolHCUsed
        "mem_free_oid": "1.3.6.1.4.1.9.9.221.1.1.1.1.20",  # cempMemPoolHCFree
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "cisco_ftd": {
        "vendor": "Cisco",
        "device_type": "cisco_ftd",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7",  # cpmCPUTotal5secRev
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.221.1.1.1.1.18",  # cempMemPoolHCUsed
        "mem_free_oid": "1.3.6.1.4.1.9.9.221.1.1.1.1.20",  # cempMemPoolHCFree
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    # Aruba AOS-Switch / HP ProCurve: HP-ICF MIBs. CPU is one scalar
    # (hpSwitchCpuStat, a percentage); memory is a table with one row per
    # management module (hpLocalMemAllocBytes / hpLocalMemFreeBytes).
    # AOS-CX and Instant On have no entry and use the fallback below.
    "aruba_osswitch": _AOS_SWITCH_OIDS,
    "hp_procurve": {**_AOS_SWITCH_OIDS, "device_type": "hp_procurve"},
    "aruba_procurve": {**_AOS_SWITCH_OIDS, "device_type": "aruba_procurve"},
    # APC Smart-UPS (Network Management Card): no CPU or memory to read, so
    # the HOST-RESOURCES fallback is not walked; the UPS state (battery,
    # output, runtime) is read by netcontrol/integrations/apc/snmp.py.
    "apc_ups": {
        "vendor": "APC",
        "device_type": "apc_ups",
        "cpu_oid": "",
        "cpu_walk": 0,
        "mem_used_oid": "",
        "mem_free_oid": "",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    # Universal fallback - HOST-RESOURCES-MIB works on most Linux/SNMP agents
    "_fallback": {
        "vendor": "Generic",
        "device_type": "",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",  # hrProcessorLoad
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",  # hrStorageUsed
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",  # hrStorageSize
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
}


# Short-TTL cache for OID resolution. resolve_oids_for_device() is called once
# per host per monitoring cycle, but the result is a pure function of
# device_type (DB overrides change only via the admin vendor-OID endpoints,
# which call clear_oid_cache()). Without this, a 500-host fleet issues 500
# identical get_vendor_oid_for_host() round-trips every cycle. Keyed by
# device_type; hosts of one type polled at once share one lookup. TTL bounds
# staleness if an override write somehow misses the invalidation hook.
# Entries are never handed out: callers get a copy.
_OID_CACHE_TTL = 300.0  # seconds
_OID_CACHE: PayloadCache[dict] = PayloadCache("vendor-oids", ttl=_OID_CACHE_TTL, max_entries=1024)


def clear_oid_cache() -> None:
    """Drop the resolved-OID cache. Called when vendor-OID overrides change."""
    _OID_CACHE.clear()


async def _resolve_oids_uncached(device_type: str) -> dict:
    # 1. Check DB for operator-defined overrides
    db_entry = await db.get_vendor_oid_for_host(device_type)
    if db_entry:
        return db_entry

    # 2. Built-in map: match longest substring
    dt_lower = (device_type or "").lower()
    best_key = "_fallback"
    best_len = 0
    for key, oids in VENDOR_OID_DEFAULTS.items():
        if key == "_fallback":
            continue
        if oids["device_type"] and oids["device_type"].lower() in dt_lower:
            if len(oids["device_type"]) > best_len:
                best_key = key
                best_len = len(oids["device_type"])

    return dict(VENDOR_OID_DEFAULTS[best_key])


async def resolve_oids_for_device(device_type: str) -> dict:
    """Return the best-matching OID set for a device_type string.

    Order: DB custom entries  →  built-in vendor map  →  _fallback.
    Cached per device_type for _OID_CACHE_TTL seconds (see _OID_CACHE).
    """
    async def build() -> dict:
        return dict(await _resolve_oids_uncached(device_type))

    return dict(await _OID_CACHE.get_or_build(device_type or "", build))


# ═════════════════════════════════════════════════════════════════════════════
# 2.  INTERFACE TIME-SERIES  (rate calculation + historical storage)
# ═════════════════════════════════════════════════════════════════════════════


def _parse_db_time(value) -> datetime | None:
    """Parse a DB timestamp into an aware UTC datetime.

    ``polled_at``/``prev_polled_at`` are written by SQLite ``datetime('now')``
    as *naive* UTC strings. Parsing them yields a naive datetime; subtracting
    that from an aware ``datetime.now(UTC)`` raises ``TypeError`` — which the
    old broad ``except`` swallowed, leaving every interface rate NULL. Normalize
    to aware UTC so the arithmetic is well-defined on both stored and live
    timestamps.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError, TypeError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _counter_delta(prev: int, cur: int) -> int | None:
    """Width-aware delta between two monotonic SNMP counters.

    A negative delta is a 32-bit wrap only when both samples fit in 32 bits
    (``+2**32``). Otherwise it is a counter reset (reboot / agent restart) and
    the interval is unusable (``None``) rather than being "corrected" into a
    fabricated multi-terabit spike.
    """
    delta = cur - prev
    if delta >= 0:
        return delta
    if prev < 2**32 and cur < 2**32:
        return delta + 2**32
    return None


async def store_interface_ts_from_poll(host_id: int, if_details: list[dict]) -> int:
    """After a monitoring poll, store per-interface counters as time-series
    and compute rates by comparing with the previous interface_stats row."""
    if not if_details:
        return 0

    # Fetch previous counters from the live interface_stats table
    prev_stats = await db.get_interface_stats_for_host(host_id)
    prev_map: dict[str, dict] = {}
    for s in prev_stats:
        prev_map[str(s["if_index"])] = s

    rows: list[tuple] = []
    for i, iface in enumerate(if_details):
        if_index = iface.get("if_index") or (i + 1)
        if_name = iface.get("name", "")
        speed_mbps = iface.get("speed_mbps", 0) or 0
        in_octets = iface.get("in_octets", 0) or 0
        out_octets = iface.get("out_octets", 0) or 0

        in_rate_bps = None
        out_rate_bps = None
        utilization_pct = None

        prev = prev_map.get(str(if_index))
        t_prev = _parse_db_time(prev.get("polled_at")) if prev is not None else None
        if prev is not None and t_prev is not None:
            dt_sec = (datetime.now(UTC) - t_prev).total_seconds()
            if dt_sec > 0:
                delta_in = _counter_delta(prev.get("in_octets") or 0, in_octets)
                delta_out = _counter_delta(prev.get("out_octets") or 0, out_octets)
                # A None delta means a counter reset this interval — skip it
                # rather than emit a fabricated spike.
                if delta_in is not None and delta_out is not None:
                    in_rate_bps = (delta_in * 8) / dt_sec
                    out_rate_bps = (delta_out * 8) / dt_sec
                    if speed_mbps > 0:
                        max_bps = speed_mbps * 1_000_000
                        utilization_pct = max(in_rate_bps, out_rate_bps) / max_bps * 100
                        utilization_pct = min(utilization_pct, 100.0)

        rows.append(
            (host_id, if_index, if_name, speed_mbps, in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct)
        )

    # Update interface_stats with current counters so the *next* poll
    # can calculate deltas.  Without this, rates stay null because
    # interface_stats was only written by topology discovery.
    stat_rows: list[tuple] = []
    for iface in if_details:
        if_index = iface.get("if_index")
        if not if_index:
            continue
        stat_rows.append(
            (
                host_id,
                if_index,
                iface.get("name", ""),
                iface.get("speed_mbps", 0) or 0,
                iface.get("in_octets", 0) or 0,
                iface.get("out_octets", 0) or 0,
            )
        )
    if stat_rows:
        await db.upsert_interface_stats_batch(stat_rows)

    return await db.create_interface_ts_batch(rows)


# ═════════════════════════════════════════════════════════════════════════════
# 2b. INTERFACE ERROR/DISCARD METRICS  (counter tracking + rate + spike detection)
# ═════════════════════════════════════════════════════════════════════════════

# Spike detection thresholds
_ERROR_SPIKE_FACTOR = 5.0  # current rate must be ≥5× baseline to trigger
_ERROR_MIN_RATE = 1.0  # minimum errors/sec to consider a spike (ignore noise)
_SPIKE_COOLDOWN_SECONDS = 900  # 15 min between duplicate events per interface+metric

# In-memory cooldown tracker: (host_id, if_index, metric_name) → last event timestamp
_spike_cooldown: dict[tuple, float] = {}


async def store_interface_error_metrics_from_poll(
    host_id: int,
    if_details: list[dict],
) -> int:
    """Store interface error/discard rates as metric_samples and detect spikes.

    Computes per-second rates by comparing with the previous counters in
    interface_error_stats and stores one ``<metric>_rate`` sample per counter
    and interface. The raw counters themselves are not written as samples:
    the newest values live in interface_error_stats (which the error summary
    reads), and every chart, rollup and spike check works from the rates.
    Detects spikes by comparing current rate to recent baseline average.
    """
    if not if_details:
        return 0

    prev_stats = await db.get_interface_error_stats_for_host(host_id)
    prev_map: dict[str, dict] = {}
    for s in prev_stats:
        prev_map[str(s["if_index"])] = s

    metric_rows: list[tuple] = []
    error_stat_rows: list[tuple] = []
    counter_fields = db.INTERFACE_ERROR_COUNTERS

    for i, iface in enumerate(if_details):
        if_index = iface.get("if_index") or (i + 1)
        if_name = iface.get("name", "")
        labels = json.dumps({"if_index": if_index, "if_name": if_name})

        prev = prev_map.get(str(if_index))

        for field, metric_name in counter_fields:
            counter_val = iface.get(field, 0) or 0

            # Compute rate if we have a previous sample
            t_prev = _parse_db_time(prev.get("polled_at")) if prev is not None and prev.get("prev_polled_at") else None
            if prev is not None and t_prev is not None:
                dt_sec = (datetime.now(UTC) - t_prev).total_seconds()
                delta = _counter_delta(prev.get(field) or 0, counter_val)
                if dt_sec > 0 and delta is not None:
                    rate = delta / dt_sec

                    # Store the rate as a separate metric
                    rate_metric = f"{metric_name}_rate"
                    metric_rows.append((host_id, rate_metric, labels, rate))

                    # Spike detection: compare to baseline from previous intervals
                    prev_prev_val = prev.get(f"prev_{field}") or 0
                    prev_val = prev.get(field) or 0
                    t_pp = _parse_db_time(prev.get("prev_polled_at"))
                    t_p = _parse_db_time(prev.get("polled_at"))
                    prev_delta = _counter_delta(prev_prev_val, prev_val)
                    pp_dt = (t_p - t_pp).total_seconds() if (t_pp and t_p) else 0
                    if pp_dt > 0 and prev_delta is not None:
                        baseline_rate = prev_delta / pp_dt

                        # Check for spike
                        if (
                            rate >= _ERROR_MIN_RATE
                            and baseline_rate >= 0
                            and (baseline_rate == 0 or rate / max(baseline_rate, 0.001) >= _ERROR_SPIKE_FACTOR)
                        ):
                            cooldown_key = (host_id, if_index, metric_name)
                            now_ts = datetime.now(UTC).timestamp()
                            last_event = _spike_cooldown.get(cooldown_key, 0)
                            if now_ts - last_event >= _SPIKE_COOLDOWN_SECONDS:
                                _spike_cooldown[cooldown_key] = now_ts
                                spike_factor = rate / max(baseline_rate, 0.001)
                                severity = "critical" if spike_factor >= 20 or rate >= 100 else "warning"
                                # Trigger root-cause correlation asynchronously
                                _spawn_bg(
                                    _create_correlated_error_event(
                                        host_id=host_id,
                                        if_index=if_index,
                                        if_name=if_name,
                                        metric_name=metric_name,
                                        current_rate=rate,
                                        baseline_rate=baseline_rate,
                                        spike_factor=spike_factor,
                                        severity=severity,
                                    )
                                )

        error_stat_rows.append(
            (
                if_index,
                if_name,
                iface.get("in_errors", 0) or 0,
                iface.get("out_errors", 0) or 0,
                iface.get("in_discards", 0) or 0,
                iface.get("out_discards", 0) or 0,
            )
        )

    if error_stat_rows:
        await db.upsert_interface_error_stats_batch(host_id, error_stat_rows)

    stored = await db.create_metric_samples_batch(metric_rows) if metric_rows else 0
    return stored


async def _create_correlated_error_event(
    host_id: int,
    if_index: int,
    if_name: str,
    metric_name: str,
    current_rate: float,
    baseline_rate: float,
    spike_factor: float,
    severity: str,
) -> None:
    """Create an interface error event with root-cause correlation."""
    try:
        now = datetime.now(UTC)
        window_start = (now - timedelta(minutes=30)).isoformat()
        window_end = now.isoformat()

        # Gather correlated events within ±30 min window
        config_changes = await db.get_config_drift_events_in_range([host_id], window_start, window_end)
        deployments = await db.get_deployments_for_host_in_range(host_id, window_start, window_end)
        topology_changes = await db.get_topology_changes_in_range(host_id, window_start, window_end)
        syslog_events = await db.get_trap_syslog_events_in_range(host_id, window_start, window_end)

        # Classify root cause
        category, hint = _classify_root_cause(
            metric_name=metric_name,
            config_changes=config_changes,
            deployments=deployments,
            topology_changes=topology_changes,
            syslog_events=syslog_events,
            spike_factor=spike_factor,
        )

        correlation = {
            "config_changes": len(config_changes),
            "deployments": len(deployments),
            "topology_changes": len(topology_changes),
            "syslog_events": len(syslog_events),
            "window": {"start": window_start, "end": window_end},
        }

        await db.create_interface_error_event(
            host_id=host_id,
            if_index=if_index,
            if_name=if_name,
            event_type="spike",
            metric_name=metric_name,
            severity=severity,
            current_rate=round(current_rate, 4),
            baseline_rate=round(baseline_rate, 4),
            spike_factor=round(spike_factor, 2),
            root_cause_hint=hint,
            root_cause_category=category,
            correlation_details=json.dumps(correlation),
        )
        LOGGER.info(
            "interface_errors: spike detected host=%d if=%s metric=%s rate=%.2f/s baseline=%.2f/s (%.1f×) cause=%s",
            host_id,
            if_name,
            metric_name,
            current_rate,
            baseline_rate,
            spike_factor,
            category,
        )
    except Exception as exc:
        LOGGER.debug("interface_errors: correlation failed: %s", str(exc))


def _classify_root_cause(
    metric_name: str,
    config_changes: list[dict],
    deployments: list[dict],
    topology_changes: list[dict],
    syslog_events: list[dict],
    spike_factor: float,
) -> tuple[str, str]:
    """Heuristic root-cause classification.

    Returns (category, human-readable hint).
    Categories: config_change, deployment, topology, physical_layer,
                congestion, unknown.
    """
    # Priority 1: Recent config change or deployment
    if deployments:
        dep_names = [d.get("name", "unnamed") for d in deployments[:3]]
        return (
            "deployment",
            f"Deployment detected within 30 min: {', '.join(dep_names)}. "
            "Error spike may be caused by the deployed configuration change.",
        )

    if config_changes:
        drift_count = len(config_changes)
        return (
            "config_change",
            f"{drift_count} config change(s) detected within 30 min. "
            "Error spike correlates with configuration drift - review recent changes.",
        )

    # Priority 2: Topology change (link flap, STP change)
    if topology_changes:
        change_types = set(c.get("change_type", "") for c in topology_changes)
        return (
            "topology",
            f"Topology change(s) detected: {', '.join(change_types)}. "
            "Errors may be caused by link state transitions or reconvergence.",
        )

    # Priority 3: Syslog/trap events (e.g., link down, module reset)
    physical_keywords = {"link", "duplex", "speed", "sfp", "transceiver", "optic", "cable", "crc", "err-disabled"}
    if syslog_events:
        phys_events = [
            e for e in syslog_events if any(kw in (e.get("message", "") or "").lower() for kw in physical_keywords)
        ]
        if phys_events:
            return (
                "physical_layer",
                f"Physical layer syslog events detected ({len(phys_events)} events). "
                "Suspect cable, SFP/optic, or duplex mismatch issue.",
            )

    # Priority 4: Error type heuristics (no correlated events found)
    error_hints = {
        "if_in_errors": (
            "physical_layer",
            "Input errors (CRC, frame, runts) with no config change - "
            "suspect physical layer: check cable, SFP/optic, or duplex mismatch.",
        ),
        "if_out_errors": (
            "congestion",
            "Output errors with no config change - suspect interface congestion or speed/duplex mismatch.",
        ),
        "if_in_discards": (
            "congestion",
            "Input discards increasing - possible input queue overflow due to high traffic or slow CPU.",
        ),
        "if_out_discards": (
            "congestion",
            "Output discards increasing - suspect output queue congestion; check QoS policy and interface speed.",
        ),
    }

    if metric_name in error_hints:
        return error_hints[metric_name]

    return (
        "unknown",
        f"Error rate spike ({spike_factor:.1f}× baseline) with no correlated events. Manual investigation recommended.",
    )


# ═════════════════════════════════════════════════════════════════════════════
# 3.  METRIC SAMPLE EMITTER  (write poll results as flexible metrics)
# ═════════════════════════════════════════════════════════════════════════════


async def emit_metric_samples_from_poll(poll_result: dict) -> int:
    """Convert a monitoring poll result dict into metric_samples rows."""
    host_id = poll_result["host_id"]
    rows: list[tuple] = []

    if poll_result.get("cpu_percent") is not None:
        rows.append((host_id, "cpu_percent", "{}", poll_result["cpu_percent"]))
    if poll_result.get("memory_percent") is not None:
        rows.append((host_id, "memory_percent", "{}", poll_result["memory_percent"]))
    if poll_result.get("memory_used_mb") is not None:
        rows.append((host_id, "memory_used_mb", "{}", poll_result["memory_used_mb"]))
    if poll_result.get("memory_total_mb") is not None:
        rows.append((host_id, "memory_total_mb", "{}", poll_result["memory_total_mb"]))
    if poll_result.get("uptime_seconds") is not None:
        rows.append((host_id, "uptime_seconds", "{}", float(poll_result["uptime_seconds"])))
    if poll_result.get("response_time_ms") is not None:
        rows.append((host_id, "response_time_ms", "{}", poll_result["response_time_ms"]))
    if poll_result.get("packet_loss_pct") is not None:
        rows.append((host_id, "packet_loss_pct", "{}", poll_result["packet_loss_pct"]))

    rows.append((host_id, "if_up_count", "{}", float(poll_result.get("if_up_count", 0))))
    rows.append((host_id, "if_down_count", "{}", float(poll_result.get("if_down_count", 0))))
    rows.append((host_id, "vpn_tunnels_up", "{}", float(poll_result.get("vpn_tunnels_up", 0))))
    rows.append((host_id, "vpn_tunnels_down", "{}", float(poll_result.get("vpn_tunnels_down", 0))))
    rows.append((host_id, "route_count", "{}", float(poll_result.get("route_count", 0))))
    # The SNMP health checks (modules, power supplies, fans, temperature, BGP
    # peers, OSPF neighbors): items down, for each table the poll read.
    rows.extend(health_checks.metric_sample_rows(poll_result))
    # A UPS: battery, runtime, load and the output / battery state codes.
    rows.extend(ups_metric_samples(host_id, poll_result.get("ups") or {}))
    # An OPNsense firewall read over its API: disks, temperature, state table, load.
    rows.extend(firewall_metric_samples(host_id, poll_result.get("opnsense_health") or {}))

    return await db.create_metric_samples_batch(rows)


# ═════════════════════════════════════════════════════════════════════════════
# 4.  DOWNSAMPLING ENGINE  (raw 48h → hourly 30d → daily 1yr)
# ═════════════════════════════════════════════════════════════════════════════

# Core metrics to downsample
_DOWNSAMPLE_METRICS = [
    "cpu_percent",
    "memory_percent",
    "memory_used_mb",
    "memory_total_mb",
    "uptime_seconds",
    "response_time_ms",
    "packet_loss_pct",
    "if_up_count",
    "if_down_count",
    "vpn_tunnels_up",
    "vpn_tunnels_down",
    "route_count",
    # The raw error counters are no longer sampled (the rates below are); the
    # names stay so samples written before that change still roll up.
    "if_in_errors",
    "if_out_errors",
    "if_in_discards",
    "if_out_discards",
    "if_in_errors_rate",
    "if_out_errors_rate",
    "if_in_discards_rate",
    "if_out_discards_rate",
    *health_checks.METRICS,
    *UPS_METRICS,
    *FIREWALL_METRICS,
]


# Raw retention of the two sample tables (run_retention_cleanup); the move
# of their pre-0144 history (netcontrol.sample_history) uses the same.
RAW_SAMPLE_RETENTION_HOURS = 48
INTERFACE_TS_RETENTION_DAYS = 30


async def _downsample_window(
    time_window: str,
    period_start: str,
    period_end: str,
    *,
    history_checked: bool = False,
) -> int:
    """Aggregate raw metric_samples into a rollup row for each host+metric+labels.

    The database aggregates the window in one statement (min, avg, max and
    an interpolated 95th percentile), so no raw sample reaches Python.

    A rollup row is written once and never revised, so a window that starts
    before migration 0144 swapped the table is deferred while its older
    rows are still being moved (``history_checked`` skips the check, for
    ``roll_up_windows_around``, which runs once they all are).
    """
    if not history_checked and not await history_complete("metric_samples", period_start):
        LOGGER.info(
            "metrics: %s rollup of %s deferred until the sample history move finishes", time_window, period_start
        )
        return 0
    return await db.rollup_metric_samples(_DOWNSAMPLE_METRICS, time_window, period_start, period_end)


async def roll_up_windows_around(swapped_at: str, now: datetime | None = None) -> int:
    """Roll up the hour and the day that contain ``swapped_at`` (the swap of
    migration 0144), the only windows ``_downsample_window`` deferred: later
    windows start after the swap, earlier ones ended before this process
    started. Called once the old rows are all moved; a window that has not
    ended yet is left to the hourly and daily rollups."""
    at = parse_time(swapped_at)
    if at is None:
        return 0
    now = now or datetime.now(UTC)
    hour = at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    day = hour.replace(hour=0)
    created = 0
    for time_window, start, end in (
        ("hourly", hour, hour + timedelta(hours=1)),
        ("daily", day, day + timedelta(days=1)),
    ):
        if end <= now:
            created += await _downsample_window(
                time_window,
                start.strftime("%Y-%m-%d %H:%M:%S"),
                end.strftime("%Y-%m-%d %H:%M:%S"),
                history_checked=True,
            )
    return created


async def run_hourly_rollup() -> int:
    """Roll up the previous complete hour of raw samples."""
    now = datetime.now(UTC)
    period_end = now.replace(minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(hours=1)
    return await _downsample_window(
        "hourly",
        period_start.strftime("%Y-%m-%d %H:%M:%S"),
        period_end.strftime("%Y-%m-%d %H:%M:%S"),
    )


async def run_daily_rollup() -> int:
    """Roll up the previous complete day of hourly rollups
    (using raw samples as source for the daily aggregate)."""
    now = datetime.now(UTC)
    period_end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=1)
    return await _downsample_window(
        "daily",
        period_start.strftime("%Y-%m-%d %H:%M:%S"),
        period_end.strftime("%Y-%m-%d %H:%M:%S"),
    )


async def run_retention_cleanup() -> dict:
    """Enforce tiered retention:  raw 48h, hourly 30d, daily 365d."""
    raw_deleted = await db.delete_old_metric_samples(hours=RAW_SAMPLE_RETENTION_HOURS)
    hourly_deleted = await db.delete_old_metric_rollups("hourly", 30)
    daily_deleted = await db.delete_old_metric_rollups("daily", 365)
    ifts_deleted = await db.delete_old_interface_ts(INTERFACE_TS_RETENTION_DAYS)
    traps_deleted = await db.delete_old_trap_syslog_events(30)
    error_events_deleted = await db.delete_old_interface_error_events(90)
    filterlog_deleted = await opnsense_filterlog.delete_old_evidence()
    return {
        "raw_samples_deleted": raw_deleted,
        "hourly_rollups_deleted": hourly_deleted,
        "daily_rollups_deleted": daily_deleted,
        "interface_ts_deleted": ifts_deleted,
        "trap_events_deleted": traps_deleted,
        "error_events_deleted": error_events_deleted,
        "filterlog_evidence_deleted": filterlog_deleted,
    }


async def _downsampling_loop() -> None:
    """Background loop: hourly rollup every hour, daily rollup once per day,
    retention cleanup every 6 hours."""
    last_hourly = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    last_daily = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    last_cleanup = datetime.now(UTC)

    while True:
        try:
            await asyncio.sleep(60)  # check every minute
            now = datetime.now(UTC)

            # Hourly rollup
            current_hour = now.replace(minute=0, second=0, microsecond=0)
            if current_hour > last_hourly:
                created = await run_hourly_rollup()
                LOGGER.info("metrics: hourly rollup created %d aggregates", created)
                last_hourly = current_hour

            # Daily rollup
            current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            if current_day > last_daily:
                created = await run_daily_rollup()
                LOGGER.info("metrics: daily rollup created %d aggregates", created)
                last_daily = current_day

            # Retention cleanup every 6 hours
            if (now - last_cleanup).total_seconds() >= 6 * 3600:
                result = await run_retention_cleanup()
                LOGGER.info("metrics: retention cleanup: %s", result)
                last_cleanup = now

            # Syslog alerts that time out (a flapping link quiet again).
            # Its own guard: a failure here must not delay the rollups.
            try:
                resolved = await syslog_rules.resolve_expired_alerts()
                if resolved:
                    LOGGER.info("metrics: auto-resolved %d syslog alerts", resolved)
            except Exception as exc:
                LOGGER.warning("metrics: syslog alert auto-resolve failed: %s", redact_value(str(exc)))
            try:
                resolved = await trap_rules.resolve_expired_alerts()
                if resolved:
                    LOGGER.info("metrics: auto-resolved %d trap alerts", resolved)
            except Exception as exc:
                LOGGER.warning("metrics: trap alert auto-resolve failed: %s", redact_value(str(exc)))

            # Security event (IDS) alerts whose signature went quiet.
            try:
                from netcontrol.routes.security_events import resolve_quiet_alerts

                resolved = await resolve_quiet_alerts()
                if resolved:
                    LOGGER.info("metrics: auto-resolved %d security event alerts", resolved)
            except Exception as exc:
                LOGGER.warning("metrics: security event alert auto-resolve failed: %s", type(exc).__name__)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("metrics: downsampling loop error: %s", redact_value(str(exc)))
            await asyncio.sleep(300)


# ═════════════════════════════════════════════════════════════════════════════
# 5.  SNMP TRAP / SYSLOG UDP RECEIVER
# ═════════════════════════════════════════════════════════════════════════════


# Runs of >=6 printable ASCII chars in a trap PDU - the readable candidates
# the old byte-by-byte Python scan extracted, as a single compiled regex.
_PRINTABLE_RUN = re.compile(rb"[ -~]{6,}")


class _ReceiverStats:
    """Counters of one receiver (UDP, or a syslog TCP / TLS listener) since
    it last started. Updated on the message hot path, so only plain
    attribute writes."""

    __slots__ = ("received", "errors", "last_message_at", "started_at")

    def __init__(self) -> None:
        self.reset(0.0)

    def reset(self, started_at: float) -> None:
        self.received = 0
        self.errors = 0
        self.last_message_at = 0.0
        self.started_at = started_at


_RECEIVER_STATS: dict[str, _ReceiverStats] = {"trap": _ReceiverStats(), "syslog": _ReceiverStats()}


class _TrapSyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP listener for SNMP traps and syslog (ports from
    state.EVENT_RECEIVER_CONFIG; 10162 and 1514 by default). A datagram
    whose source the listener allowlist refuses, or over its per-source
    rate limit (``netcontrol.listener_sources``), is counted there and
    dropped before it is parsed or counted as received."""

    def __init__(self, event_type: str):
        self.event_type = event_type
        self._stats = _RECEIVER_STATS[event_type]
        self._guard = listener_sources.guard(event_type)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        # An IPv6 source in one form; an IPv4-mapped one as its IPv4 address.
        source_ip = listener_sources.canonical_address(addr[0])
        if not self._guard.admit(source_ip):
            return
        stats = self._stats
        stats.received += 1
        stats.last_message_at = time.time()
        try:
            if self.event_type == "trap":
                self._handle_trap(data, source_ip, addr)
            else:
                self._handle_syslog(data, source_ip)
        except Exception as exc:
            stats.errors += 1
            LOGGER.debug("metrics: %s parse error from %s: %s", self.event_type, source_ip, exc)

    def _acknowledge_inform(self, data: bytes, addr: tuple) -> None:
        """Send the Response an SNMPv2c InformRequest's sender waits for, to
        the address and port it came from (the datagram passed the listener
        guard). Its community is checked later, in the batch writer: the
        answer only says the inform arrived, and is no larger than it."""
        transport = getattr(self, "transport", None)
        response = snmp_inform_response(data)
        if transport is not None and response is not None:
            transport.sendto(response, addr)

    def _handle_trap(self, data: bytes, source_ip: str, addr: tuple | None = None):
        # Only the stored prefix is hexed (raw_data is capped at 2000 chars =
        # 1000 bytes anyway).
        raw_hex = data[:1000].hex()
        # An SNMPv3 datagram needs the source host's keys: only its header is
        # read here, and it is queued whole for the batch writer's keyed
        # decode (``_screen_traps``) when the source is an inventory host.
        v3_header = parse_snmpv3_header(data)
        if v3_header is not None:
            if not self._handle_v3_confirmed(data, source_ip, raw_hex, v3_header, addr):
                self._queue_v3_trap(data, source_ip, raw_hex, v3_header)
            return
        # A v1 / v2c trap (or v2c inform) is decoded, named from the trap
        # registry (netcontrol.snmp_traps) and queued with its decoded form:
        # the batch writer checks its community against the source host's
        # and runs the trap rules on it, or, for an APC UPS trap
        # (PowerNet-MIB, stored with its name and severity), the APC
        # handler. Nothing that needs the database runs outside the bounded
        # queue.
        trap = decode_snmp_trap(data)
        if trap is not None and trap.get("pdu") == "inform" and addr is not None:
            self._acknowledge_inform(data, addr)
        apc_trap = parse_apc_trap(trap)
        if apc_trap is not None:
            _queue_trap_syslog_event(
                source_ip, "trap", "", apc_trap.severity, apc_trap.trap_oid, apc_trap.message, raw_hex, trap
            )
            return
        if trap is not None:
            severity, oid, message = trap_event_fields(trap)
            _queue_trap_syslog_event(source_ip, "trap", "", severity, oid, message, raw_hex, trap)
            return
        # Not decodable (malformed): stored with its size and the last
        # readable run that looks like an OID.
        oid, message = _undecoded_trap_fields(data, source_ip)
        _queue_trap_syslog_event(source_ip, "trap", "", "info", oid, message, raw_hex, trap)

    def _handle_v3_confirmed(
        self, data: bytes, source_ip: str, raw_hex: str, header: V3Header, addr: tuple | None
    ) -> bool:
        """An SNMPv3 message with the reportable flag (an inform) from an
        inventory host while the receiver's SNMPv3 engine is started
        (``snmpv3_engine.LOCAL``): True when handled here. One for another
        engine ID (a discovery probe) is answered at once with the
        unknown-engine-ID Report (keyless, ``engine_discovery_report``) and
        not stored; one for the local engine is queued whole, with the
        address to answer, for the batch writer's keyed decode
        (``_decode_v3_row``), within ``_V3_PENDING_MAX``. Anything else
        (no engine, not reportable, not an inventory source, the pending
        limit reached) is False: stored undecoded as before."""
        global _v3_pending, _v3_replies_waiting
        engine = snmpv3_engine.LOCAL
        if engine is None or not header.reportable or addr is None:
            return False
        if listener_sources.inventory_host_id(source_ip) is None:
            return False
        if header.engine_id != engine.engine_id:
            report = engine_discovery_report(data, engine)
            if report is None:
                # Not a probe to answer (a trap sent with the reportable
                # flag set, a reply too large): the trap path takes it.
                return False
            _send_reply(report, addr)
            return True
        if _v3_pending >= _V3_PENDING_MAX:
            return False
        _v3_pending += 1
        _v3_replies_waiting += 1
        oid, message = _undecoded_trap_fields(data, source_ip)
        _queue_trap_syslog_event(
            source_ip, "trap", "", "info", oid, message, raw_hex, PendingV3Trap(bytes(data), header, tuple(addr))
        )
        return True

    def _queue_v3_trap(self, data: bytes, source_ip: str, raw_hex: str, header: V3Header) -> None:
        """Queue an SNMPv3 datagram: stored as an undecoded trap unless the
        batch writer decodes it. Its bytes ride along (``PendingV3Trap``)
        only from an inventory source and while fewer than
        ``_V3_PENDING_MAX`` wait in the buffer, so a flood holds at most
        that many datagrams; a source admitted by an extra network or the
        ``any`` policy has no SNMPv3 user to check them with."""
        global _v3_pending
        oid, message = _undecoded_trap_fields(data, source_ip)
        pending = None
        if listener_sources.inventory_host_id(source_ip) is not None and _v3_pending < _V3_PENDING_MAX:
            pending = PendingV3Trap(bytes(data), header)
            _v3_pending += 1
        _queue_trap_syslog_event(source_ip, "trap", "", "info", oid, message, raw_hex, pending)

    def _handle_syslog(self, data: bytes, source_ip: str):
        handle_syslog_message(data, source_ip)


def _undecoded_trap_fields(data: bytes, source_ip: str) -> tuple[str, str]:
    """``(oid, message)`` an undecoded trap is stored with: its size and the
    last printable run that looks like an OID."""
    message = f"SNMP trap from {source_ip} ({len(data)} bytes)"
    oid = ""
    # Last printable run that looks like an OID wins (matches the old scan)
    for m in _PRINTABLE_RUN.finditer(data):
        candidate = m.group().decode("ascii")
        if "." in candidate:
            oid = candidate
    return oid, message


def trap_event_fields(trap: dict) -> tuple[str, str, str]:
    """``(severity, oid, message)`` a decoded trap is stored with (a dict of
    ``decode_snmp_trap``'s shape, from any decoder): named by the trap
    registry, its severity set by the trap rules (``trap_rules.event_fields``)."""
    return trap_rules.event_fields(name_trap(trap))


# RFC 5424 numeric severities → Plexus taxonomy. 0-2 (Emergency/Alert/
# Critical) are critical; 3-4 (Error/Warning) map to warning so routine
# device "error" syslogs don't flood the critical tier; 5-7 (Notice/Info/
# Debug) are info.
_SYSLOG_SEVERITY = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "warning",
    4: "warning",
    5: "info",
    6: "info",
    7: "info",
}


def handle_syslog_message(data: bytes, source_ip: str, transport: str = "udp") -> None:
    """Parse one syslog message (a UDP datagram, or a TCP / TLS frame from
    ``netcontrol.syslog_stream``) and queue it, with the ``transport`` it
    arrived over, for the batch writer."""
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        text = data.hex()[:2000]

    # Parse RFC 3164 / RFC 5424 priority
    facility = ""
    severity = "info"
    message = text
    if text.startswith("<") and ">" in text[:6]:
        try:
            pri_end = text.index(">")
            pri = int(text[1:pri_end])
            facility = str((pri >> 3) & 0x1F)
            severity = _SYSLOG_SEVERITY.get(pri & 0x07, "info")
            message = text[pri_end + 1 :].strip()
        except (ValueError, IndexError) as exc:
            LOGGER.debug("metrics: syslog priority parse failed from %s: %s", source_ip, exc)

    _queue_trap_syslog_event(source_ip, "syslog", facility, severity, "", message, text[:2000], None, transport)


# ── Buffered trap/syslog persistence ─────────────────────────────────────────
#
# The old path did a host lookup plus a single-row INSERT+commit per
# datagram - two writer-lock round-trips per syslog line, so a device log
# storm on port 514 stalled the whole app. Events buffer in memory (bounded,
# drop-newest with a counter) and a single writer flushes them in batches,
# resolving source IPs through a short-lived cache.

_TRAP_EVENT_FLUSH_SECONDS = 1.0
_TRAP_EVENT_BUFFER_MAX = 10000
_HOST_IP_CACHE_TTL_SECONDS = 300.0

_HOST_IP_CACHE_MAX = 4096
# A batch holds up to _TRAP_EVENT_BUFFER_MAX events: the writer yields to
# the event loop every this many (syslog_rules._RESTORE_YIELD_EVERY, the
# restore replay's step), and hands the rule engines this many at a time.
_TRAP_EVENT_YIELD_EVERY = 1000

# (source_ip, event_type, facility, severity, oid, message, raw_data, trap,
# transport): ``trap`` is the decoded v1 / v2c trap (``decode_snmp_trap``),
# an SNMPv3 datagram waiting for the batch writer's keyed decode
# (``PendingV3Trap``), or None for syslog and for a trap that could not be
# decoded; ``transport`` is ``udp``, ``tcp`` or ``tls``.
_trap_event_buffer: list[tuple] = []
# SNMPv3 datagrams held in the buffer (``PendingV3Trap``): at most
# _V3_PENDING_MAX (16 KiB each); reset when the writer takes the buffer.
_V3_PENDING_MAX = 1000
_v3_pending = 0
# Of those, the informs waiting for their Response (the writer flushes early).
_v3_replies_waiting = 0
# The SNMPv3 timeliness / replay state of the trap receiver (RFC 3414
# 3.2.7 b), per (source, engine ID): loaded when the trap receiver starts
# and written back at most once a minute and at shutdown (snmpv3_engine).
_V3_REPLAY_GUARD = ReplayGuard()
_trap_events_dropped = 0
# Never reset (the writer resets _trap_events_dropped each flush): shown in
# the receiver settings as events dropped since Plexus started.
_trap_events_dropped_total = 0
_trap_event_writer_task: asyncio.Task | None = None


def _host_ip_entry_expired(_ip: str, entry: tuple[int | None, float], now: float) -> bool:
    return entry[1] <= now


# source_ip -> (host_id or None, expiry). Bounded: forged sources cannot grow it.
_host_ip_cache: BoundedDict = BoundedDict(_HOST_IP_CACHE_MAX, _host_ip_entry_expired, clock=time.monotonic)


def _queue_trap_syslog_event(
    source_ip,
    event_type,
    facility,
    severity,
    oid,
    message,
    raw_data,
    trap: dict | PendingV3Trap | None = None,
    transport: str = "udp",
) -> None:
    global _trap_events_dropped, _trap_events_dropped_total, _trap_event_writer_task
    if len(_trap_event_buffer) >= _TRAP_EVENT_BUFFER_MAX:
        _trap_events_dropped += 1
        _trap_events_dropped_total += 1
        return
    _trap_event_buffer.append(
        (source_ip, event_type, facility, severity, oid, message[:2000], raw_data[:2000], trap, transport)
    )
    if _trap_event_writer_task is None or _trap_event_writer_task.done():
        _trap_event_writer_task = asyncio.ensure_future(_trap_event_writer_loop())


async def _resolve_host_id_cached(source_ip: str) -> int | None:
    # The listener allowlist's inventory map (primary IPs win over interface
    # IPs, lowest host id between interface IPs, as find_host_by_ip) is
    # reloaded on every host change and at most a minute apart, fresher than
    # this cache's entries: a source in it needs no database query. It is
    # keyed in canonical form, so it also matches an IPv6 host address
    # stored in another spelling than the socket's.
    host_id = listener_sources.inventory_host_id(source_ip)
    if host_id is not None:
        return host_id
    now = time.monotonic()
    cached = _host_ip_cache.get(source_ip)
    if cached is not None and cached[1] > now:
        return cached[0]
    host_id = None
    try:
        # A device often sends from an interface other than its primary
        # address: recorded interface IPs match too.
        host = await db.find_host_by_ip(source_ip, include_aliases=True)
        if host:
            host_id = host["id"]
    except Exception as exc:
        LOGGER.debug("metrics: host lookup failed for %s: %s", source_ip, exc)
    # Bounded (BoundedDict): a scanner spraying forged sources cannot grow it.
    _host_ip_cache[source_ip] = (host_id, now + _HOST_IP_CACHE_TTL_SECONDS)
    return host_id


def _take_trap_event_batch() -> list[tuple]:
    """Everything queued, the queue emptied (the overflow count logged)."""
    global _trap_events_dropped, _v3_pending, _v3_replies_waiting
    batch = _trap_event_buffer[:]
    _trap_event_buffer.clear()
    _v3_pending = 0
    _v3_replies_waiting = 0
    if _trap_events_dropped:
        LOGGER.warning("metrics: trap/syslog buffer overflow - dropped %d events", _trap_events_dropped)
        _trap_events_dropped = 0
    return batch


# An SNMPv3 inform waits for its Response: while one is queued the writer
# looks every _TRAP_EVENT_REPLY_SECONDS instead of once a second.
_TRAP_EVENT_REPLY_SECONDS = 0.1


async def _trap_event_writer_loop() -> None:
    while True:
        waited = 0.0
        while waited < _TRAP_EVENT_FLUSH_SECONDS:
            await asyncio.sleep(_TRAP_EVENT_REPLY_SECONDS)
            waited += _TRAP_EVENT_REPLY_SECONDS
            if _v3_replies_waiting:
                break
        if not _trap_event_buffer:
            continue
        await _flush_trap_syslog_batch(_take_trap_event_batch())
        await snmpv3_engine.persist_replay(_V3_REPLAY_GUARD)


async def flush_v3_state() -> int:
    """Write the SNMPv3 replay record now (shutdown): only the process
    whose trap receiver listens holds one. Returns the rows written."""
    if snmpv3_engine.LOCAL is None:
        return 0
    return await snmpv3_engine.persist_replay(_V3_REPLAY_GUARD, force=True)


def _trap_believed(trap: dict, host: dict, v3_authenticated: bool = False) -> bool:
    """Whether a decoded trap from inventory ``host`` may be acted on: a v1
    / v2c trap carries the host's stored community; an SNMPv3 trap was
    authenticated by the batch writer with the host's SNMPv3 user
    (``v3_authenticated``, never read from the trap itself)."""
    if trap.get("version") == "v3":
        return v3_authenticated
    return trap_community_matches(trap, host)


_V3_DROP = "drop"
# An inform outside the local engine's time window that was answered with
# the usmStatsNotInTimeWindows Report: the sender's time synchronization
# (RFC 3414 section 4), neither stored nor counted as a refusal.
_V3_HANDSHAKE = "handshake"


async def _decode_v3_row(row: tuple, pending: PendingV3Trap, host: dict, credentials: dict[int, Any]) -> tuple | str | None:
    """The keyed decode of one queued SNMPv3 datagram from inventory
    ``host`` (``snmpv3_traps``): the row with the decoded trap, named, in
    its trap slot; ``_V3_DROP`` when the message is refused (not from the
    host's SNMPv3 user as configured, a replay, outside the time window);
    None to store it as an undecoded trap (a discovery probe, another PDU).
    The host's credentials are resolved once per batch.

    An inform for the local engine (``reply_to`` set) is decoded on the
    authoritative path (``decode_snmpv3_inform``) and its answer (the
    Response, or a Report) sent to ``reply_to``; one answered with the
    time-window Report is ``_V3_HANDSHAKE``."""
    host_id = int(host["id"])
    if host_id not in credentials:
        try:
            credentials[host_id] = await resolve_trap_v3_credentials(host)
        except Exception as exc:  # noqa: BLE001 - a bad stored config is "no SNMPv3 user"
            LOGGER.debug("metrics: SNMPv3 credentials of host %s not resolved: %s", host_id, exc)
            credentials[host_id] = None
    engine = snmpv3_engine.LOCAL
    if pending.reply_to is not None and engine is not None and pending.header.engine_id == engine.engine_id:
        result = decode_snmpv3_inform(
            pending.data, credentials[host_id], engine, snmpv3_engine.INFORM_REPLAY_GUARD, row[0]
        )
        if result.reply is not None:
            _send_reply(result.reply, pending.reply_to)
        if result.failure is V3Failure.NOT_IN_TIME_WINDOW and result.reply is not None:
            return _V3_HANDSHAKE
    else:
        result = decode_snmpv3_trap(pending.data, credentials[host_id], _V3_REPLAY_GUARD, row[0])
    if result.trap is None:
        LOGGER.debug("metrics: SNMPv3 message from %s not decoded: %s", row[0], result.failure)
        return _V3_DROP if result.failure in SNMPV3_REFUSED else None
    apc_trap = parse_apc_trap(result.trap)
    if apc_trap is not None:
        severity, oid, message = apc_trap.severity, apc_trap.trap_oid, apc_trap.message
    else:
        severity, oid, message = trap_event_fields(result.trap)
    return (row[0], "trap", "", severity, oid, message[:2000], row[6], result.trap, row[8])


async def _screen_traps(
    batch: list[tuple], host_ids: dict[str, int | None]
) -> tuple[list[tuple], list[tuple], list[tuple]]:
    """The batch without the decoded (v1 / v2c) traps whose source is an
    inventory host but whose community is not that host's (each counted as
    a ``community`` drop of the trap listener), the APC traps to act on
    (``(source_ip, ApcTrap, authenticated host id or None)``) and the other
    traps for the trap rules (``(host_id, trap)``), from inventory sources
    only. A trap from a source admitted only by an extra network or the
    ``any`` policy has no host whose community could be checked: it is
    stored, never acted on. An undecodable trap (malformed) is stored and
    never acted on.

    An SNMPv3 datagram (``PendingV3Trap``) from an inventory host is
    decoded here with that host's SNMPv3 poll user (``_decode_v3_row``):
    decoded, it is stored named and acted on like a believed v1 / v2c trap;
    refused, it is dropped and counted as a ``v3`` drop; anything else (a
    discovery probe, another PDU) is stored undecoded. An inform for the
    local engine is answered there too, and one that only resynchronized
    its sender's clock is neither stored nor counted. One from any other
    source is stored undecoded, never decoded."""
    trap_host_ids = sorted(
        {hid for row in batch if row[1] == "trap" and row[7] is not None and (hid := host_ids.get(row[0])) is not None}
    )
    hosts = {int(h["id"]): h for h in await db.get_hosts_by_ids(trap_host_ids)} if trap_host_ids else {}
    guard = listener_sources.guard("trap")
    credentials: dict[int, Any] = {}
    kept: list[tuple] = []
    apc: list[tuple] = []
    believed: list[tuple] = []
    for n, row in enumerate(batch, 1):
        if n % _TRAP_EVENT_YIELD_EVERY == 0:
            await asyncio.sleep(0)
        trap = row[7]
        if row[1] == "trap" and isinstance(trap, PendingV3Trap):
            host_id = host_ids.get(row[0])
            host = hosts.get(int(host_id)) if host_id is not None else None
            decoded = await _decode_v3_row(row, trap, host, credentials) if host is not None else None
            if decoded == _V3_DROP:
                guard.note_drop("v3", row[0])
                continue
            if decoded == _V3_HANDSHAKE:
                continue
            if not isinstance(decoded, tuple) or host is None or not _trap_believed(decoded[7], host, True):
                kept.append((*row[:7], None, *row[8:]))
                continue
            row, trap = decoded, decoded[7]
            apc_trap = parse_apc_trap(trap)
            if apc_trap is not None:
                apc.append((row[0], apc_trap, int(host["id"])))
            else:
                believed.append((int(host["id"]), trap))
        elif row[1] == "trap" and trap is not None:
            host_id = host_ids.get(row[0])
            if host_id is not None:
                host = hosts.get(int(host_id))
                if host is None or not _trap_believed(trap, host):
                    guard.note_drop("community", row[0])
                    continue
                apc_trap = parse_apc_trap(trap)
                if apc_trap is not None:
                    apc.append((row[0], apc_trap, None))
                else:
                    believed.append((int(host_id), trap))
        kept.append(row)
    return kept, apc, believed


async def _flush_trap_syslog_batch(batch: list[tuple]) -> None:
    """Store a batch of queued events (``_trap_event_buffer`` rows), then
    run the syslog rules on it, act on its APC traps and run the trap rules
    on its other believed traps, one after another: the work a datagram
    causes stays inside the bounded queue."""
    rows: list[tuple] = []
    apc: list[tuple] = []
    believed: list[tuple] = []
    try:
        host_ids = {ip: await _resolve_host_id_cached(ip) for ip in {row[0] for row in batch}}
        batch, apc, believed = await _screen_traps(batch, host_ids)
        rows = [
            (source_ip, host_ids.get(source_ip), event_type, facility, severity, oid, message, raw_data, transport)
            for (source_ip, event_type, facility, severity, oid, message, raw_data, _trap, transport) in batch
        ]
        # OPNsense firewall log lines are summed per rule, never stored
        # raw nor run through the syslog rules.
        rows = opnsense_filterlog.divert(rows)
        await db.create_trap_syslog_events_batch(rows)
    except Exception as exc:
        LOGGER.warning("metrics: trap/syslog batch write failed, dropping %d events: %s", len(batch), exc)
    await _evaluate_syslog_rules(rows)
    for n, (source_ip, apc_trap, authenticated_host_id) in enumerate(apc, 1):
        if n % _TRAP_EVENT_YIELD_EVERY == 0:
            await asyncio.sleep(0)
        try:
            if authenticated_host_id is None:
                await handle_apc_trap(source_ip, apc_trap)
            else:
                # SNMPv3: authenticated with that host's user, no community.
                await handle_apc_trap(source_ip, apc_trap, authenticated_host_id=authenticated_host_id)
        except Exception as exc:  # noqa: BLE001 - one trap must not stop the writer
            LOGGER.warning("metrics: handling an APC trap from %s failed: %s", source_ip, exc)
    await _evaluate_trap_rules(believed)


async def _evaluate_trap_rules(believed: list[tuple]) -> None:
    """Hand the believed traps of inventory hosts (``(host_id, trap)``, the
    trap a dict of ``decode_snmp_trap``'s shape) to the trap rule engine
    (``netcontrol.trap_rules``: alerts, re-poll and config-change triggers).
    A rule error is logged: it never touches the stored events."""
    async for chunk in _chunks(believed):
        try:
            await trap_rules.process_trap_batch([(host_id, name_trap(trap)) for host_id, trap in chunk])
        except Exception as exc:  # noqa: BLE001 - a rule failure must not stop the writer
            LOGGER.warning("metrics: trap rule evaluation failed for %d traps: %s", len(chunk), exc)


async def _chunks(rows: list) -> AsyncIterator[list]:
    """``rows`` in slices of ``_TRAP_EVENT_YIELD_EVERY``, yielding to the
    event loop between slices: the rule engines run each slice in one
    synchronous pass, and a full batch of them would stall every request
    and poller sharing the loop. The engines keep their counters between
    calls, so slices evaluate as the whole batch would, in order."""
    for start in range(0, len(rows), _TRAP_EVENT_YIELD_EVERY):
        if start:
            await asyncio.sleep(0)
        yield rows[start : start + _TRAP_EVENT_YIELD_EVERY]


async def _evaluate_syslog_rules(rows: list[tuple]) -> None:
    """Hand the syslog messages of inventory hosts in a flushed batch to the
    syslog rule engine (alerts, config-change and re-poll triggers), and
    every syslog message, with its source address, to the OPNsense
    re-collection trigger (a firewall need not be an inventory host). A
    rule or trigger error is logged: it never touches the stored events.

    Rows are ``(source_ip, host_id, event_type, facility, severity, oid,
    message, raw_data[, transport])`` (no transport: ``udp``). With the
    ``syslog_udp_actions`` switch off, a message that arrived over UDP,
    whose source address can be forged, is stored only: it reaches no rule
    and no trigger."""
    if not syslog_rules.receiver_flag("syslog_udp_actions"):
        rows = [row for row in rows if len(row) > 8 and row[8] != "udp"]
    syslog_rows = [(row[1], row[6]) for row in rows if row[2] == "syslog" and row[1] is not None]
    async for chunk in _chunks(syslog_rows):
        try:
            await syslog_rules.process_syslog_batch(chunk)
        except Exception as exc:
            LOGGER.warning("metrics: syslog rule evaluation failed for %d events: %s", len(chunk), exc)
    recollect_rows = [(row[0], row[1], row[6]) for row in rows if row[2] == "syslog"]
    async for chunk in _chunks(recollect_rows):
        try:
            await syslog_rules.process_recollect_batch(chunk)
        except Exception as exc:
            LOGGER.warning("metrics: syslog re-collect trigger failed for %d events: %s", len(chunk), exc)


# ── Receiver lifecycle ──────────────────────────────────────────────────────
#
# Settings (ports, on/off, rule-engine switches) live in
# state.EVENT_RECEIVER_CONFIG, persisted in auth_settings("event_receivers")
# and applied at startup and by PUT /api/admin/metrics/receivers/config.
# The default ports are unprivileged because the container runs as a
# non-root user; publish host 162 -> 10162 and 514 -> 1514 to use the
# standard ports.

# Listen on every interface: devices send from anywhere. Tests rebind it to
# loopback.
_RECEIVER_BIND_HOST = "0.0.0.0"  # nosec B104 - trap/syslog listener must accept devices on any interface
_RECEIVER_LABELS = {"trap": "SNMP trap", "syslog": "syslog"}
_receiver_transports: dict[str, asyncio.DatagramTransport | None] = {"trap": None, "syslog": None}
_receiver_ports: dict[str, int] = {"trap": 0, "syslog": 0}
# The receivers that also listen on IPv6, on a second socket (IPV6_V6ONLY,
# so the IPv4 socket above is unchanged) on the same port: the IPv6
# wildcard when the IPv4 bind host is the IPv4 wildcard, ::1 for loopback
# (tests), none for any other bind host. A host without IPv6 logs the
# failed bind and keeps listening on IPv4. The syslog UDP receiver is
# IPv4 only.
_IPV6_RECEIVERS: tuple[str, ...] = ("trap",)
_IPV6_BIND_HOSTS = {"0.0.0.0": "::", "127.0.0.1": "::1"}  # nosec B104 - see _RECEIVER_BIND_HOST
_receiver_transports6: dict[str, asyncio.DatagramTransport | None] = {"trap": None, "syslog": None}


def _send_reply(data: bytes, addr: tuple) -> None:
    """Send an SNMP answer (a v3 Response or Report) to ``addr`` from the
    trap receiver's socket of its address family; nothing when that socket
    is closed."""
    transport = _receiver_transports6["trap"] if len(addr) == 4 else _receiver_transports["trap"]
    if transport is None:
        return
    try:
        transport.sendto(data, addr)
    except Exception as exc:  # noqa: BLE001 - a failed answer is the sender's retry
        LOGGER.debug("metrics: SNMP answer to %s not sent: %s", addr[0], type(exc).__name__)


def _stream_handler(transport: str) -> syslog_stream.Handler:
    def handle(data: bytes, source_ip: str) -> None:
        handle_syslog_message(data, source_ip, transport)

    return handle


# Syslog over TCP and TLS (netcontrol.syslog_stream), each with its own
# counters; every message goes through handle_syslog_message as UDP does.
_STREAM_LISTENERS: dict[str, syslog_stream.StreamListener] = {
    transport: syslog_stream.StreamListener(transport, _stream_handler(transport), _ReceiverStats())
    for transport in syslog_stream.TRANSPORTS
}


def _udp_running(kind: str) -> bool:
    return _receiver_transports.get(kind) is not None


def receiver_running(kind: str) -> bool:
    """Whether the ``kind`` receiver listens; ``syslog``: on UDP, TCP or TLS."""
    if kind == "syslog" and any(listener.running for listener in _STREAM_LISTENERS.values()):
        return True
    return _udp_running(kind)


async def _start_receiver(kind: str, port: int) -> bool:
    """Bind one UDP receiver. True when it is (already) listening. A failed
    bind is logged and returns False; it never raises."""
    if _receiver_transports[kind] is not None:
        return True
    label = _RECEIVER_LABELS[kind]
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _TrapSyslogProtocol(kind),
            local_addr=(_RECEIVER_BIND_HOST, port),
        )
    except Exception as exc:
        LOGGER.warning("metrics: failed to start %s receiver on UDP port %d: %s", label, port, exc)
        return False
    _receiver_transports[kind] = transport
    _receiver_ports[kind] = port
    _RECEIVER_STATS[kind].reset(time.time())
    if kind in _IPV6_RECEIVERS:
        await _start_receiver6(kind, int(transport.get_extra_info("sockname")[1]))
    # The source allowlist needs the inventory addresses from the first datagram.
    await listener_sources.refresh_inventory()
    if kind == "trap":
        # Only the process that bound the port gets here: it alone counts
        # an engine boot and holds the SNMPv3 replay record.
        await snmpv3_engine.start()
        await snmpv3_engine.restore_replay(_V3_REPLAY_GUARD)
    LOGGER.info("metrics: %s receiver started on UDP port %d", label, port)
    return True


async def _start_receiver6(kind: str, port: int) -> bool:
    """Bind the IPv6 socket of a receiver in ``_IPV6_RECEIVERS`` on
    ``port`` (see ``_IPV6_BIND_HOSTS``). True when it listens; a failed
    bind is logged and returns False."""
    _close_receiver6(kind)
    host = _IPV6_BIND_HOSTS.get(_RECEIVER_BIND_HOST)
    if host is None or not socket.has_ipv6:
        return False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        sock.setblocking(False)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _TrapSyslogProtocol(kind), sock=sock
        )
    except Exception as exc:  # noqa: BLE001 - IPv4 keeps listening
        if sock is not None:
            sock.close()
        LOGGER.warning("metrics: %s receiver not listening on IPv6 UDP port %d: %s", _RECEIVER_LABELS[kind], port, exc)
        return False
    _receiver_transports6[kind] = transport
    LOGGER.info("metrics: %s receiver listening on IPv6 UDP port %d", _RECEIVER_LABELS[kind], port)
    return True


def _close_receiver6(kind: str) -> None:
    transport = _receiver_transports6.get(kind)
    _receiver_transports6[kind] = None
    if transport is not None:
        try:
            transport.close()
        except RuntimeError:
            pass  # its event loop is already closed


def _stop_receiver(kind: str) -> bool:
    """Close one UDP receiver. True when it was running."""
    transport = _receiver_transports[kind]
    if transport is None:
        return False
    transport.close()
    _close_receiver6(kind)
    _receiver_transports[kind] = None
    _receiver_ports[kind] = 0
    LOGGER.info("metrics: %s receiver stopped", _RECEIVER_LABELS[kind])
    return True


async def start_trap_receiver(port: int = 10162) -> bool:
    """Start the SNMP trap UDP listener (10162 by default: unprivileged)."""
    return await _start_receiver("trap", port)


async def start_syslog_receiver(port: int = 1514) -> bool:
    """Start the syslog UDP listener (1514 by default: unprivileged)."""
    return await _start_receiver("syslog", port)


def stop_trap_receiver() -> bool:
    return _stop_receiver("trap")


def stop_syslog_receiver() -> bool:
    return _stop_receiver("syslog")


def stop_receivers() -> None:
    _stop_receiver("trap")
    _stop_receiver("syslog")
    for listener in _STREAM_LISTENERS.values():
        listener.stop()


async def _apply_stream_listeners(cfg: dict) -> None:
    """Reconcile the TCP and TLS syslog listeners: each is started, stopped
    or rebound only when its own on/off or port, or (TLS) the stored
    certificate, client CA or client certificate mode, differs from what is
    running. A TLS listener without a usable certificate is logged, keeps
    the reason in its ``error`` and stays stopped. With
    ``syslog_tls_match_client_cert`` the TLS listener checks that each
    client certificate names the inventory host at its source address."""
    require_client_cert = bool(cfg.get("syslog_tls_require_client_cert"))
    match_client_cert = require_client_cert and bool(cfg.get("syslog_tls_match_client_cert"))
    for transport, listener in _STREAM_LISTENERS.items():
        enabled = bool(cfg.get(f"syslog_{transport}_enabled"))
        port = int(cfg.get(f"syslog_{transport}_port") or 0)
        key = syslog_tls.material_key(require_client_cert, match_client_cert) if transport == "tls" else ""
        if listener.running and (not enabled or listener.port != port or listener.config_key != key):
            listener.stop()
        if not enabled:
            listener.error = ""
            continue
        if listener.running:
            continue
        context = None
        peer_check = None
        if transport == "tls":
            try:
                context = syslog_tls.server_context(require_client_cert)
            except syslog_tls.TlsMaterialError as exc:
                listener.error = str(exc)
                LOGGER.warning("metrics: syslog TLS receiver not started: %s", exc)
                continue
            if match_client_cert:
                peer_check = _client_cert_names_host
        await listener.start(_RECEIVER_BIND_HOST, port, context, key, peer_check)


def _client_cert_names_host(source_ip: str, peercert: dict | None) -> str:
    """The syslog TLS peer check: "" when the client certificate names the
    sender (a SAN IP equal to ``source_ip``, or a SAN DNS name or common
    name matching the hostname of the inventory host at it), else why not."""
    return syslog_tls.peer_mismatch(peercert, source_ip, listener_sources.inventory_hostname(source_ip))


async def apply_event_receiver_config(new_cfg: dict) -> dict:
    """Make state.EVENT_RECEIVER_CONFIG ``new_cfg`` (already sanitized) and
    reconcile the listeners: a receiver is started, stopped or rebound only
    when its own on/off or port differs from what is running. Returns the
    config snapshot."""
    state.EVENT_RECEIVER_CONFIG.update(new_cfg)
    cfg = state.EVENT_RECEIVER_CONFIG
    for kind in ("syslog", "trap"):
        enabled = bool(cfg.get(f"{kind}_enabled"))
        port = int(cfg.get(f"{kind}_port") or 0)
        running = _udp_running(kind)
        if running and (not enabled or _receiver_ports[kind] != port):
            _stop_receiver(kind)
            running = False
        if enabled and not running:
            await _start_receiver(kind, port)
    await _apply_stream_listeners(cfg)
    return event_receiver_snapshot()


def _epoch_iso(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat() if value else ""


def event_receiver_snapshot() -> dict:
    """The persisted receiver config plus the live listener state and the
    counters since each receiver last started."""
    snapshot = dict(state.EVENT_RECEIVER_CONFIG)
    for kind in ("syslog", "trap"):
        stats = _RECEIVER_STATS[kind]
        running = _udp_running(kind)
        snapshot[f"{kind}_running"] = running
        snapshot[f"{kind}_listening_port"] = _receiver_ports[kind] if running else None
        snapshot[f"{kind}_received"] = stats.received
        snapshot[f"{kind}_errors"] = stats.errors
        snapshot[f"{kind}_last_message_at"] = _epoch_iso(stats.last_message_at)
        snapshot[f"{kind}_started_at"] = _epoch_iso(stats.started_at)
        # Refused by the listener allowlist / rate limit (and, for traps, a
        # wrong community or an SNMPv3 trap failing its USM checks) since
        # Plexus started.
        drops = listener_sources.guard(kind).stats()
        snapshot[f"{kind}_dropped_source"] = drops["dropped_source"]
        snapshot[f"{kind}_dropped_rate"] = drops["dropped_rate"]
        if kind == "trap":
            snapshot["trap_dropped_community"] = drops["dropped_community"]
            snapshot["trap_dropped_v3"] = drops["dropped_v3"]
            snapshot["trap_ipv6_listening"] = running and _receiver_transports6["trap"] is not None
            # The receiver's own SNMPv3 engine (informs) and its counters.
            snapshot.update(snmpv3_engine.snapshot())
    # The TCP and TLS syslog listeners share the syslog drop counters above.
    for transport, listener in _STREAM_LISTENERS.items():
        prefix = f"syslog_{transport}"
        stats = listener.stats
        snapshot[f"{prefix}_running"] = listener.running
        snapshot[f"{prefix}_listening_port"] = listener.port if listener.running else None
        snapshot[f"{prefix}_received"] = stats.received
        snapshot[f"{prefix}_errors"] = stats.errors
        snapshot[f"{prefix}_last_message_at"] = _epoch_iso(stats.last_message_at)
        snapshot[f"{prefix}_started_at"] = _epoch_iso(stats.started_at)
        snapshot[f"{prefix}_connections"] = listener.connections
        snapshot[f"{prefix}_connections_refused"] = listener.refused
        if transport == "tls":
            # Closed because the client certificate did not name the host.
            snapshot[f"{prefix}_connections_cert_refused"] = listener.cert_refused
        snapshot[f"{prefix}_error"] = listener.error
    snapshot["source_policy"] = listener_sources.CONFIG.get("policy")
    snapshot["events_dropped"] = _trap_events_dropped_total
    snapshot["events_pending"] = len(_trap_event_buffer)
    # OPNsense firewall log lines, summed per rule since Plexus started.
    snapshot.update(opnsense_filterlog.receiver_stats())
    return snapshot


# ═════════════════════════════════════════════════════════════════════════════
# 6.  API ROUTES
# ═════════════════════════════════════════════════════════════════════════════

# ── Metrics Query API ────────────────────────────────────────────────────────


async def _confine_hosts(request: Request, host_ids: list[int] | None) -> list[int] | None:
    """The host filter of a metrics query for the caller: unchanged for an
    unrestricted caller; for a scoped one, "all hosts" (``None`` or empty)
    becomes the hosts it may read and an explicit list keeps only those
    (``[-1]``, no host, when nothing is left: the readers treat an empty
    list as all)."""
    allowed = await readable_host_ids(request)
    if allowed is None:
        return host_ids
    if not host_ids:
        return sorted(allowed) or [-1]
    return [h for h in host_ids if h in allowed] or [-1]


@router.get("/api/metrics/query")
@scoped("list")
async def metrics_query(
    request: Request,
    metric: str = Query(..., description="Metric name, e.g. cpu_percent"),
    host: str = Query(default="*", description="Host ID, comma-separated IDs, or * for all"),
    range: str = Query(default="6h", description="Time range: 1h, 6h, 24h, 7d, 30d"),
    step: str = Query(default="auto", description="Resolution: raw, hourly, daily, or auto"),
    group: int | None = Query(default=None, description="Filter by inventory group ID"),
) -> dict:
    """Structured metrics query - no PromQL needed.
    Returns time-series data for the requested metric across hosts, newest
    first. ``step=auto`` aggregates on the server (``bucket_seconds``: raw
    samples averaged into buckets sized to the range, or the hourly or
    daily rollups); ``raw``, ``hourly`` and ``daily`` return the stored rows.
    ``limit`` is the row cap and ``truncated`` says when it cut the oldest
    rows."""

    # Parse host filter
    host_ids = None
    if host != "*":
        try:
            host_ids = [int(h.strip()) for h in host.split(",") if h.strip()]
        except ValueError:
            raise HTTPException(400, "Invalid host parameter - use IDs or *")

    # If group is specified and host is *, resolve host IDs from group
    if group and host == "*":
        group_hosts = await db.get_hosts_for_group(group)
        # An empty/nonexistent group must scope to no hosts, not silently fall
        # through to the whole fleet (downstream treats an empty list as "all").
        host_ids = [h["id"] for h in group_hosts] or [-1]
    host_ids = await _confine_hosts(request, host_ids)

    # Parse time range
    now = datetime.now(UTC)
    range_map = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "12h": timedelta(hours=12),
        "24h": timedelta(hours=24),
        "2d": timedelta(days=2),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
        "365d": timedelta(days=365),
    }
    delta = range_map.get(range)
    if not delta:
        raise HTTPException(400, f"Invalid range - use one of: {', '.join(range_map.keys())}")

    start_time = (now - delta).strftime("%Y-%m-%d %H:%M:%S")
    end_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Resolution: step=auto buckets on the server (_auto_resolution); an
    # explicit raw, hourly or daily step returns the stored rows, capped.
    bucket_seconds = 0
    cap = _QUERY_EXPLICIT_CAP
    if step == "auto":
        series = len(host_ids) if host_ids else await db.count_hosts()
        step, bucket_seconds = _auto_resolution(delta, series)
        cap = _QUERY_AUTO_CAP

    if step == "raw":
        data = await db.query_metric_samples(
            metric_name=metric,
            host_ids=host_ids,
            start=start_time,
            end=end_time,
            limit=cap + 1,
            bucket_seconds=bucket_seconds,
        )
    else:
        data = await db.query_metric_rollups(
            metric_name=metric,
            time_window=step,
            host_ids=host_ids,
            start=start_time,
            end=end_time,
            limit=cap + 1,
        )
    # Newest first: a capped response loses the oldest rows and says so.
    truncated = len(data) > cap
    data = data[:cap]
    return {
        "metric": metric,
        "step": step,
        "range": range,
        "bucket_seconds": bucket_seconds,
        "count": len(data),
        "limit": cap,
        "truncated": truncated,
        "data": data,
    }


# step=auto of /api/metrics/query: raw samples (kept 48 h,
# ``run_retention_cleanup``) bucketed on the server up to that span, hourly
# rollups (kept 30 d) when they give few enough points, else daily rollups.
_RAW_SAMPLE_SPAN = timedelta(hours=48)
_HOURLY_ROLLUP_SPAN = timedelta(days=30)
# Points per series step=auto aims for, and the most it allows.
_QUERY_TARGET_POINTS = 360
_QUERY_MAX_POINTS = 1000
# Rows a response holds at most (``truncated`` says when more matched).
_QUERY_AUTO_CAP = 20_000
_QUERY_EXPLICIT_CAP = 10_000
# The bucket widths step=auto picks from, in seconds (1 min to 6 h).
_QUERY_BUCKET_WIDTHS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600)


def _auto_resolution(delta: timedelta, series: int) -> tuple[str, int]:
    """``(step, bucket_seconds)`` of a step=auto query over ``delta`` for
    about ``series`` series (hosts): the points per series shrink when
    many series would pass the row cap."""
    per_series = _QUERY_AUTO_CAP // max(1, series)
    target = max(1, min(_QUERY_TARGET_POINTS, per_series))
    most = max(1, min(_QUERY_MAX_POINTS, per_series))
    span = delta.total_seconds()
    if delta <= _RAW_SAMPLE_SPAN:
        wanted = span / target
        width = next((w for w in _QUERY_BUCKET_WIDTHS if w >= wanted), _QUERY_BUCKET_WIDTHS[-1])
        return "raw", width
    if delta <= _HOURLY_ROLLUP_SPAN and span / 3600 <= most:
        return "hourly", 0
    return "daily", 0


@router.get("/api/metrics/capacity-planning")
@scoped("list")
async def capacity_planning(
    request: Request,
    metric: str = Query(..., description="Metric name, e.g. cpu_percent"),
    host: str = Query(default="*", description="Host ID, comma-separated IDs, or * for all"),
    time_range: str = Query(default="90d", alias="range", description="Time range: 30d, 90d, 365d"),
    group: int | None = Query(default=None, description="Filter by inventory group ID"),
    projection_days: int = Query(default=30, ge=1, le=365, description="Days to project forward"),
    threshold: float = Query(default=90.0, description="Capacity threshold for ETA calculation"),
):
    """Long-term capacity planning with trend projection."""

    # Resolve hosts
    host_ids = None
    if host != "*":
        try:
            host_ids = [int(h.strip()) for h in host.split(",") if h.strip()]
        except ValueError:
            raise HTTPException(400, "Invalid host parameter")
    if group and host == "*":
        group_hosts = await db.get_hosts_for_group(group)
        # An empty/nonexistent group must scope to no hosts, not silently fall
        # through to the whole fleet (downstream treats an empty list as "all").
        host_ids = [h["id"] for h in group_hosts] or [-1]
    host_ids = await _confine_hosts(request, host_ids)

    # Parse time range
    now = datetime.now(UTC)
    range_map = {
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
        "180d": timedelta(days=180),
        "365d": timedelta(days=365),
    }
    delta = range_map.get(time_range)
    if not delta:
        raise HTTPException(400, f"Invalid range - use one of: {', '.join(range_map.keys())}")

    start_time = (now - delta).strftime("%Y-%m-%d %H:%M:%S")
    end_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Query daily rollups
    data = await db.query_metric_rollups(
        metric_name=metric,
        time_window="daily",
        host_ids=host_ids,
        start=start_time,
        end=end_time,
        limit=50000,
    )

    if not data:
        return {
            "metric": metric,
            "range": time_range,
            "count": 0,
            "data": [],
            "trend": None,
            "projection": [],
            "per_host": [],
        }

    # Group data by host for per-host projections
    by_host: dict[str, list[dict]] = {}
    for d in data:
        key = d.get("hostname") or f"host-{d.get('host_id', '?')}"
        if key not in by_host:
            by_host[key] = []
        by_host[key].append(d)

    per_host_results: list[dict[str, Any]] = []

    for hostname, points in by_host.items():
        # Convert to (day_offset, value) for regression
        regression_points = []
        for p in points:
            ts_str = p.get("period_start", "")
            val = p.get("val_avg")
            if val is None or not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str).replace(tzinfo=None)
                day_offset = (ts - (now.replace(tzinfo=None) - delta)).total_seconds() / 86400
                regression_points.append((day_offset, val))
            except ValueError, TypeError:
                continue

        if len(regression_points) < 2:
            per_host_results.append(
                {
                    "hostname": hostname,
                    "trend": None,
                    "projection": [],
                    "threshold_eta": None,
                }
            )
            continue

        slope, intercept = _linear_regression(regression_points)
        total_days = delta.days

        # Generate projection points
        projection = []
        for d_offset in range(1, projection_days + 1):
            future_day = total_days + d_offset
            predicted = slope * future_day + intercept
            future_date = (now + timedelta(days=d_offset)).strftime("%Y-%m-%d")
            projection.append({"date": future_date, "value": round(predicted, 2)})

        # Calculate threshold ETA
        threshold_eta = None
        if slope > 0:
            current_val = slope * total_days + intercept
            if current_val < threshold:
                days_until = (threshold - current_val) / slope
                # A near-flat slope makes days_until astronomically large;
                # timedelta(days=days_until) overflows (uncaught 500). Only
                # render an ETA date inside a sane horizon (~100 years).
                if 0 <= days_until <= 36_500:
                    eta_date = (now + timedelta(days=days_until)).strftime("%Y-%m-%d")
                else:
                    eta_date = None
                threshold_eta = {
                    "date": eta_date,
                    "days_until": round(days_until) if days_until <= 36_500 else None,
                    "current_value": round(current_val, 2),
                }

        per_host_results.append(
            {
                "hostname": hostname,
                "trend": {"slope": round(slope, 6), "intercept": round(intercept, 2)},
                "projection": projection,
                "threshold_eta": threshold_eta,
            }
        )

    return {
        "metric": metric,
        "range": time_range,
        "threshold": threshold,
        "projection_days": projection_days,
        "count": len(data),
        "data": data,
        "per_host": per_host_results,
    }


def _linear_regression(points: list[tuple[float, float]]) -> tuple[float, float]:
    """Simple least-squares linear regression. Returns (slope, intercept)."""
    n = len(points)
    if n < 2:
        return (0.0, points[0][1] if points else 0.0)
    sum_x = sum(p[0] for p in points)
    sum_y = sum(p[1] for p in points)
    sum_xy = sum(p[0] * p[1] for p in points)
    sum_x2 = sum(p[0] ** 2 for p in points)
    denom = n * sum_x2 - sum_x**2
    if denom == 0:
        return (0.0, sum_y / n)
    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n
    return (slope, intercept)


@router.get("/api/metrics/names")
@scope_exempt("static list of metric names")
async def metrics_names():
    """List available metric names."""
    return {"metrics": _DOWNSAMPLE_METRICS}


# ── Interface Time-Series API ────────────────────────────────────────────────

# Range -> (span, bucket width in seconds; 0 = raw samples). Widths keep
# each interface at about 300-360 points: 24 h / 5 min, 7 d / 30 min,
# 30 d / 2 h. Short ranges stay raw (capped per interface in the query).
_INTERFACE_TS_RANGES: dict[str, tuple[timedelta, int]] = {
    "1h": (timedelta(hours=1), 0),
    "6h": (timedelta(hours=6), 0),
    "24h": (timedelta(hours=24), 300),
    "7d": (timedelta(days=7), 1800),
    "30d": (timedelta(days=30), 7200),
}


@router.get("/api/metrics/interfaces/{host_id}")
@scoped("host")
async def interface_timeseries(
    request: Request,
    host_id: int,
    if_index: int | None = Query(default=None),
    range: str = Query(default="6h"),
):
    """Get per-interface utilization time-series for a host.

    ``data`` covers the whole range, ordered by ``if_index`` then time.
    Ranges up to 6 h are raw samples; longer ones are bucket averages
    (``bucket_seconds``), a few hundred points per interface. ``latest``
    holds each interface's newest raw sample in the range.
    """
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    now = datetime.now(UTC)
    delta, bucket_seconds = _INTERFACE_TS_RANGES.get(range, _INTERFACE_TS_RANGES["6h"])
    start = (now - delta).strftime("%Y-%m-%d %H:%M:%S")

    series = await db.query_interface_ts_series(
        host_id,
        start,
        bucket_seconds=bucket_seconds,
        if_index=if_index,
    )
    data = series["data"]
    return {
        "host_id": host_id,
        "if_index": if_index,
        "range": range,
        "bucket_seconds": bucket_seconds,
        "count": len(data),
        "data": data,
        "latest": series["latest"],
    }


# ── Vendor OID Registry API ─────────────────────────────────────────────────


@router.get("/api/metrics/vendor-oids")
@scope_exempt("fleet-wide vendor OID registry; holds no host data")
async def vendor_oids_list():
    """List all vendor OID registry entries (built-in + custom)."""
    custom = await db.get_vendor_oid_entries()
    return {
        "builtin": VENDOR_OID_DEFAULTS,
        "custom": custom,
    }


# NOTE: create/delete live on admin_router (require_admin). Custom OID entries
# override built-ins fleet-wide, so redirecting SNMP polling to bogus OIDs would
# silently break CPU/memory monitoring for every device — an admin-only action.
@admin_router.post("/api/metrics/vendor-oids")
async def vendor_oids_create(body: dict, request: Request):
    """Add a custom vendor OID mapping."""
    vendor = body.get("vendor", "")
    device_type = body.get("device_type", "")
    if not vendor or not device_type:
        raise HTTPException(400, "vendor and device_type are required")
    try:
        cpu_walk = int(body.get("cpu_walk", 1))
    except TypeError, ValueError:
        raise HTTPException(400, "cpu_walk must be an integer")
    entry_id = await db.upsert_vendor_oid(
        vendor=vendor,
        device_type=device_type,
        cpu_oid=body.get("cpu_oid", ""),
        cpu_walk=cpu_walk,
        mem_used_oid=body.get("mem_used_oid", ""),
        mem_free_oid=body.get("mem_free_oid", ""),
        mem_total_oid=body.get("mem_total_oid", ""),
        uptime_oid=body.get("uptime_oid", "1.3.6.1.2.1.1.3"),
        notes=body.get("notes", ""),
    )
    clear_oid_cache()  # a new/updated override must take effect next poll
    return {"id": entry_id}


@admin_router.delete("/api/metrics/vendor-oids/{entry_id}")
async def vendor_oids_delete(entry_id: int):
    ok = await db.delete_vendor_oid(entry_id)
    if not ok:
        raise HTTPException(404, "Entry not found")
    clear_oid_cache()  # removing an override reverts to built-in map next poll
    return {"ok": True}


# ── Trap / Syslog Events API ────────────────────────────────────────────────


@router.get("/api/metrics/events")
@scoped("list")
async def trap_syslog_events(
    request: Request,
    event_type: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
):
    return await db.get_trap_syslog_events(event_type, host_id, severity, limit, **await group_filter(request))


# ── Admin: Receiver control ─────────────────────────────────────────────────


#
# The receivers' settings are the persisted state.EVENT_RECEIVER_CONFIG. The
# older start/stop endpoints write the same settings (both receivers on or
# off, saved), so a receiver started through the API also starts with
# Plexus and the Settings tab always shows what is running.


class EventReceiverStartRequest(BaseModel):
    """Optional ports; a port left out keeps its saved value."""

    trap_port: int | None = Field(default=None, ge=1, le=65535)
    syslog_port: int | None = Field(default=None, ge=1, le=65535)


class EventReceiverConfigRequest(BaseModel):
    """PUT body: a field left out keeps its saved value."""

    syslog_enabled: bool | None = None
    syslog_port: int | None = Field(default=None, ge=1, le=65535)
    trap_enabled: bool | None = None
    trap_port: int | None = Field(default=None, ge=1, le=65535)
    syslog_alerts: bool | None = None
    config_change_trigger: bool | None = None
    repoll_trigger: bool | None = None
    recollect_trigger: bool | None = None
    filterlog_evidence: bool | None = None
    syslog_tcp_enabled: bool | None = None
    syslog_tcp_port: int | None = Field(default=None, ge=1, le=65535)
    syslog_tls_enabled: bool | None = None
    syslog_tls_port: int | None = Field(default=None, ge=1, le=65535)
    syslog_tls_require_client_cert: bool | None = None
    syslog_tls_match_client_cert: bool | None = None
    syslog_udp_actions: bool | None = None
    trap_alerts: bool | None = None


def _receiver_config_error(cfg: dict) -> str:
    """Why a sanitized receiver config cannot be saved ("" when it can)."""
    if cfg["syslog_enabled"] and cfg["trap_enabled"] and cfg["syslog_port"] == cfg["trap_port"]:
        return "The syslog and trap receivers cannot use the same UDP port."
    tcp, tls = cfg["syslog_tcp_enabled"], cfg["syslog_tls_enabled"]
    if tcp and tls and cfg["syslog_tcp_port"] == cfg["syslog_tls_port"]:
        return "The syslog TCP and TLS receivers cannot use the same TCP port."
    if tls and not syslog_tls.has_certificate():
        return "Store or generate a server certificate before turning on the syslog TLS receiver."
    if cfg["syslog_tls_require_client_cert"] and not syslog_tls.has_client_ca():
        return "Store a client CA before requiring client certificates."
    if cfg["syslog_tls_match_client_cert"] and not cfg["syslog_tls_require_client_cert"]:
        return "Require client certificates before requiring that the certificate names the host."
    if not cfg["syslog_udp_actions"] and not (tcp or tls):
        return "Turn on the syslog TCP or TLS receiver before turning off actions on UDP messages."
    return ""


async def _save_event_receiver_config(cfg: dict, request: Request, action: str) -> dict:
    """Sanitize, persist, apply and audit a receiver config. Returns the snapshot."""
    sanitized = state._sanitize_event_receiver_config(cfg)
    error = _receiver_config_error(sanitized)
    if error:
        raise HTTPException(400, error)
    await db.set_auth_setting("event_receivers", sanitized)
    snapshot = await apply_event_receiver_config(sanitized)
    session = _get_session(request)
    await _audit(
        "system",
        action,
        user=session["user"] if session else "",
        detail=(
            f"syslog={'on' if sanitized['syslog_enabled'] else 'off'}:{sanitized['syslog_port']} "
            f"trap={'on' if sanitized['trap_enabled'] else 'off'}:{sanitized['trap_port']} "
            f"syslog_alerts={sanitized['syslog_alerts']} "
            f"config_change_trigger={sanitized['config_change_trigger']} "
            f"repoll_trigger={sanitized['repoll_trigger']} "
            f"recollect_trigger={sanitized['recollect_trigger']} "
            f"filterlog_evidence={sanitized['filterlog_evidence']} "
            f"syslog_tcp={'on' if sanitized['syslog_tcp_enabled'] else 'off'}:{sanitized['syslog_tcp_port']} "
            f"syslog_tls={'on' if sanitized['syslog_tls_enabled'] else 'off'}:{sanitized['syslog_tls_port']} "
            f"syslog_tls_require_client_cert={sanitized['syslog_tls_require_client_cert']} "
            f"syslog_tls_match_client_cert={sanitized['syslog_tls_match_client_cert']} "
            f"syslog_udp_actions={sanitized['syslog_udp_actions']} "
            f"trap_alerts={sanitized['trap_alerts']}"
        ),
        correlation_id=_corr_id(request),
    )
    return snapshot


@admin_router.post("/api/admin/metrics/receivers/start")
async def admin_start_receivers(request: Request, body: EventReceiverStartRequest | None = None):
    """Turn both UDP receivers on (optionally on new ports) and save that.
    The syslog TCP and TLS listeners are left as saved."""
    cfg = {**state.EVENT_RECEIVER_CONFIG, "syslog_enabled": True, "trap_enabled": True}
    if body is not None:
        cfg.update(body.model_dump(exclude_none=True))
    snapshot = await _save_event_receiver_config(cfg, request, "event_receivers.started")
    return {"trap_started": snapshot["trap_running"], "syslog_started": snapshot["syslog_running"], **snapshot}


@admin_router.post("/api/admin/metrics/receivers/stop")
async def admin_stop_receivers(request: Request):
    """Turn both UDP receivers off and save that, so they stay off after a
    restart. The syslog TCP and TLS listeners are left as saved."""
    cfg = {**state.EVENT_RECEIVER_CONFIG, "syslog_enabled": False, "trap_enabled": False}
    await _save_event_receiver_config(cfg, request, "event_receivers.stopped")
    return {"ok": True}


@admin_router.get("/api/admin/metrics/receivers/config")
async def admin_get_event_receiver_config():
    return event_receiver_snapshot()


@admin_router.put("/api/admin/metrics/receivers/config")
async def admin_update_event_receiver_config(body: EventReceiverConfigRequest, request: Request):
    changes = body.model_dump(exclude_none=True)
    cfg = {**state.EVENT_RECEIVER_CONFIG, **changes}
    return await _save_event_receiver_config(cfg, request, "event_receivers.config.updated")


# ── Admin: syslog TLS certificate ───────────────────────────────────────────
#
# The server certificate and client CA of the syslog TLS receiver
# (netcontrol.syslog_tls), in auth_settings("syslog_tls") with the private
# key encrypted at rest. No response, log line or audit entry carries the
# key. A change restarts a running TLS listener (open connections drop).


class SyslogTlsRequest(BaseModel):
    """PUT body. ``cert_pem`` and ``key_pem`` go together (both left out:
    the server certificate is kept); ``client_ca_pem`` on its own ("":
    removed). Sizes are checked by ``syslog_tls``, not here, so a refused
    key is never echoed in a validation error log."""

    cert_pem: str | None = None
    key_pem: str | None = None
    client_ca_pem: str | None = None


class SyslogTlsGenerateRequest(BaseModel):
    common_name: str = Field(min_length=1, max_length=syslog_tls.MAX_COMMON_NAME_CHARS)
    sans: list[str] = Field(default_factory=list, max_length=syslog_tls.MAX_SANS)
    days: int = Field(default=825, ge=syslog_tls.MIN_DAYS, le=syslog_tls.MAX_DAYS)


async def _save_syslog_tls(material: dict, request: Request, action: str, detail: str) -> dict:
    """Persist and apply the TLS material, rebuild a running TLS listener,
    audit. Returns the GET view."""
    await db.set_auth_setting(syslog_tls.SETTING_KEY, material)
    syslog_tls.apply(material)
    await apply_event_receiver_config(state.EVENT_RECEIVER_CONFIG)
    view = syslog_tls.public_view()
    fingerprint = (view["certificate"] or {}).get("sha256_fingerprint", "")
    session = _get_session(request)
    await _audit(
        "system",
        action,
        user=session["user"] if session else "",
        detail=f"{detail} certificate={fingerprint or 'none'} client_ca_certs={len(view['client_ca'])}",
        correlation_id=_corr_id(request),
    )
    return view


@admin_router.get("/api/admin/metrics/receivers/tls")
async def admin_get_syslog_tls():
    return syslog_tls.public_view()


@admin_router.put("/api/admin/metrics/receivers/tls")
async def admin_update_syslog_tls(body: SyslogTlsRequest, request: Request):
    material = dict(syslog_tls.MATERIAL)
    changed: list[str] = []
    if (body.cert_pem is None) != (body.key_pem is None):
        raise HTTPException(400, "Give the certificate and its private key together.")
    try:
        if body.cert_pem is not None and body.key_pem is not None:
            material["cert_pem"], material["key_pem"] = syslog_tls.validate_server_pair(body.cert_pem, body.key_pem)
            changed.append("certificate")
        if body.client_ca_pem is not None:
            if body.client_ca_pem.strip():
                material["client_ca_pem"] = syslog_tls.validate_client_ca(body.client_ca_pem)
            elif state.EVENT_RECEIVER_CONFIG.get("syslog_tls_require_client_cert"):
                raise HTTPException(400, "Turn off Require client certificates before removing the client CA.")
            else:
                material["client_ca_pem"] = ""
            changed.append("client_ca")
    except syslog_tls.TlsMaterialError as exc:
        raise HTTPException(400, str(exc)) from None
    if not changed:
        return syslog_tls.public_view()
    return await _save_syslog_tls(material, request, "syslog_tls.updated", f"changed={','.join(changed)}")


@admin_router.post("/api/admin/metrics/receivers/tls/generate")
async def admin_generate_syslog_tls(body: SyslogTlsGenerateRequest, request: Request):
    try:
        cert_pem, key_pem = await asyncio.to_thread(
            syslog_tls.generate_self_signed, body.common_name, body.sans, body.days
        )
    except syslog_tls.TlsMaterialError as exc:
        raise HTTPException(400, str(exc)) from None
    material = {**syslog_tls.MATERIAL, "cert_pem": cert_pem, "key_pem": key_pem}
    return await _save_syslog_tls(material, request, "syslog_tls.generated", f"days={body.days}")


@admin_router.delete("/api/admin/metrics/receivers/tls")
async def admin_delete_syslog_tls(request: Request):
    if state.EVENT_RECEIVER_CONFIG.get("syslog_tls_enabled"):
        raise HTTPException(400, "Turn off the syslog TLS receiver before removing its certificate.")
    material = {**syslog_tls.MATERIAL, "cert_pem": "", "key_pem": ""}
    return await _save_syslog_tls(material, request, "syslog_tls.deleted", "changed=certificate")


@admin_router.post("/api/admin/metrics/rollup/hourly")
async def admin_trigger_hourly_rollup():
    """Manually trigger an hourly rollup."""
    created = await run_hourly_rollup()
    return {"rollups_created": created}


@admin_router.post("/api/admin/metrics/rollup/daily")
async def admin_trigger_daily_rollup():
    """Manually trigger a daily rollup."""
    created = await run_daily_rollup()
    return {"rollups_created": created}


@admin_router.post("/api/admin/metrics/retention-cleanup")
async def admin_retention_cleanup():
    """Manually trigger retention cleanup."""
    return await run_retention_cleanup()
