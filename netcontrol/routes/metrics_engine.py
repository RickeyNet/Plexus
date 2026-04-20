"""
metrics_engine.py -- Prometheus-style metrics infrastructure:
  - Data downsampling (raw → hourly → daily rollups)
  - Multi-vendor OID registry with HOST-RESOURCES-MIB fallback
  - Per-interface time-series storage with rate calculation
  - Flexible metric_samples (Prometheus data model)
  - Structured metrics query API
  - SNMP trap / syslog UDP receiver
"""
from __future__ import annotations


import asyncio
import json
import logging
import math
import socket
import struct
from datetime import UTC, datetime, timedelta, timezone

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request

import netcontrol.routes.state as state
from netcontrol.telemetry import configure_logging, redact_value

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.metrics_engine")

# ── Late-binding auth (injected by app.py) ───────────────────────────────────
_require_auth = None
_require_admin = None


def inject_auth(auth_dep, admin_dep):
    global _require_auth, _require_admin
    _require_auth = auth_dep
    _require_admin = admin_dep


# ═════════════════════════════════════════════════════════════════════════════
# 1.  VENDOR OID REGISTRY  (Multi-vendor SNMP support)
# ═════════════════════════════════════════════════════════════════════════════

# Built-in vendor OID map.  The DB table lets operators add their own.
# HOST-RESOURCES-MIB OIDs are the universal fallback.
VENDOR_OID_DEFAULTS: dict[str, dict] = {
    "cisco_ios": {
        "vendor": "Cisco", "device_type": "cisco_ios",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.48.1.1.1.5",
        "mem_free_oid": "1.3.6.1.4.1.9.9.48.1.1.1.6",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "cisco_nxos": {
        "vendor": "Cisco", "device_type": "cisco_nxos",
        "cpu_oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.9.9.48.1.1.1.5",
        "mem_free_oid": "1.3.6.1.4.1.9.9.48.1.1.1.6",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "juniper": {
        "vendor": "Juniper", "device_type": "juniper",
        "cpu_oid": "1.3.6.1.4.1.2636.3.1.13.1.8",      # jnxOperatingCPU
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.4.1.2636.3.1.13.1.11",  # jnxOperatingBuffer
        "mem_free_oid": "",
        "mem_total_oid": "",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "arista_eos": {
        "vendor": "Arista", "device_type": "arista_eos",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",            # hrProcessorLoad (HOST-RESOURCES)
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",        # hrStorageUsed
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",       # hrStorageSize
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "fortinet": {
        "vendor": "Fortinet", "device_type": "fortinet",
        "cpu_oid": "1.3.6.1.4.1.12356.101.4.1.3.0",     # fgSysCpuUsage
        "cpu_walk": 0,
        "mem_used_oid": "1.3.6.1.4.1.12356.101.4.1.4.0",  # fgSysMemUsage (%)
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.4.1.12356.101.4.1.5.0",  # fgSysMemCapacity
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    "paloalto": {
        "vendor": "Palo Alto", "device_type": "paloalto",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",             # hrProcessorLoad
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
    # Universal fallback — HOST-RESOURCES-MIB works on most Linux/SNMP agents
    "_fallback": {
        "vendor": "Generic", "device_type": "",
        "cpu_oid": "1.3.6.1.2.1.25.3.3.1.2",             # hrProcessorLoad
        "cpu_walk": 1,
        "mem_used_oid": "1.3.6.1.2.1.25.2.3.1.6",        # hrStorageUsed
        "mem_free_oid": "",
        "mem_total_oid": "1.3.6.1.2.1.25.2.3.1.5",       # hrStorageSize
        "uptime_oid": "1.3.6.1.2.1.1.3",
    },
}


async def resolve_oids_for_device(device_type: str) -> dict:
    """Return the best-matching OID set for a device_type string.

    Order: DB custom entries  →  built-in vendor map  →  _fallback.
    """
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


# ═════════════════════════════════════════════════════════════════════════════
# 2.  INTERFACE TIME-SERIES  (rate calculation + historical storage)
# ═════════════════════════════════════════════════════════════════════════════

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
        if prev and prev.get("polled_at"):
            try:
                t_prev = datetime.fromisoformat(prev["polled_at"])
                t_now = datetime.now(UTC)
                dt_sec = (t_now - t_prev).total_seconds()
                if dt_sec > 0:
                    delta_in = in_octets - (prev.get("in_octets") or 0)
                    delta_out = out_octets - (prev.get("out_octets") or 0)
                    # Handle 64-bit counter wrap
                    if delta_in < 0:
                        delta_in += 2**64
                    if delta_out < 0:
                        delta_out += 2**64
                    in_rate_bps = (delta_in * 8) / dt_sec
                    out_rate_bps = (delta_out * 8) / dt_sec
                    if speed_mbps > 0:
                        max_bps = speed_mbps * 1_000_000
                        utilization_pct = max(in_rate_bps, out_rate_bps) / max_bps * 100
                        utilization_pct = min(utilization_pct, 100.0)
            except (ValueError, TypeError):
                pass

        rows.append((host_id, if_index, if_name, speed_mbps,
                      in_octets, out_octets, in_rate_bps, out_rate_bps, utilization_pct))

    # Update interface_stats with current counters so the *next* poll
    # can calculate deltas.  Without this, rates stay null because
    # interface_stats was only written by topology discovery.
    for iface in if_details:
        if_index = iface.get("if_index")
        if not if_index:
            continue
        await db.upsert_interface_stat(
            host_id=host_id,
            if_index=if_index,
            if_name=iface.get("name", ""),
            if_speed_mbps=iface.get("speed_mbps", 0) or 0,
            in_octets=iface.get("in_octets", 0) or 0,
            out_octets=iface.get("out_octets", 0) or 0,
        )

    return await db.create_interface_ts_batch(rows)


# ═════════════════════════════════════════════════════════════════════════════
# 2b. INTERFACE ERROR/DISCARD METRICS  (counter tracking + rate + spike detection)
# ═════════════════════════════════════════════════════════════════════════════

# Spike detection thresholds
_ERROR_SPIKE_FACTOR = 5.0       # current rate must be ≥5× baseline to trigger
_ERROR_MIN_RATE = 1.0           # minimum errors/sec to consider a spike (ignore noise)
_SPIKE_COOLDOWN_SECONDS = 900   # 15 min between duplicate events per interface+metric

# In-memory cooldown tracker: (host_id, if_index, metric_name) → last event timestamp
_spike_cooldown: dict[tuple, float] = {}


async def store_interface_error_metrics_from_poll(
    host_id: int, if_details: list[dict],
) -> int:
    """Store interface error/discard counters as metric_samples and detect spikes.

    For each interface, stores raw counter values in metric_samples with labels.
    Computes delta rates by comparing with previous counters in interface_error_stats.
    Detects spikes by comparing current rate to recent baseline average.
    """
    if not if_details:
        return 0

    prev_stats = await db.get_interface_error_stats_for_host(host_id)
    prev_map: dict[str, dict] = {}
    for s in prev_stats:
        prev_map[str(s["if_index"])] = s

    metric_rows: list[tuple] = []
    counter_fields = [
        ("in_errors", "if_in_errors"),
        ("out_errors", "if_out_errors"),
        ("in_discards", "if_in_discards"),
        ("out_discards", "if_out_discards"),
    ]

    for i, iface in enumerate(if_details):
        if_index = iface.get("if_index") or (i + 1)
        if_name = iface.get("name", "")
        labels = json.dumps({"if_index": if_index, "if_name": if_name})

        prev = prev_map.get(str(if_index))

        for field, metric_name in counter_fields:
            counter_val = iface.get(field, 0) or 0
            # Store raw counter value as a metric sample
            metric_rows.append((host_id, metric_name, labels, float(counter_val)))

            # Compute rate if we have a previous sample
            if prev and prev.get("polled_at") and prev.get("prev_polled_at"):
                try:
                    t_prev = datetime.fromisoformat(prev["polled_at"])
                    t_now = datetime.now(UTC)
                    dt_sec = (t_now - t_prev).total_seconds()
                    if dt_sec > 0:
                        prev_field = f"prev_{field}" if f"prev_{field}" in prev else field
                        delta = counter_val - (prev.get(field) or 0)
                        if delta < 0:
                            delta += 2**32  # 32-bit counter wrap
                        rate = delta / dt_sec

                        # Store the rate as a separate metric
                        rate_metric = f"{metric_name}_rate"
                        metric_rows.append((host_id, rate_metric, labels, rate))

                        # Spike detection: compare to baseline from previous intervals
                        prev_prev_val = prev.get(f"prev_{field}") or 0
                        prev_val = prev.get(field) or 0
                        prev_dt_str = prev.get("prev_polled_at")
                        polled_str = prev.get("polled_at")
                        if prev_dt_str and polled_str:
                            try:
                                t_pp = datetime.fromisoformat(prev_dt_str)
                                t_p = datetime.fromisoformat(polled_str)
                                pp_dt = (t_p - t_pp).total_seconds()
                                if pp_dt > 0:
                                    prev_delta = prev_val - prev_prev_val
                                    if prev_delta < 0:
                                        prev_delta += 2**32
                                    baseline_rate = prev_delta / pp_dt

                                    # Check for spike
                                    if (rate >= _ERROR_MIN_RATE and
                                            baseline_rate >= 0 and
                                            (baseline_rate == 0 or rate / max(baseline_rate, 0.001) >= _ERROR_SPIKE_FACTOR)):
                                        cooldown_key = (host_id, if_index, metric_name)
                                        now_ts = datetime.now(UTC).timestamp()
                                        last_event = _spike_cooldown.get(cooldown_key, 0)
                                        if now_ts - last_event >= _SPIKE_COOLDOWN_SECONDS:
                                            _spike_cooldown[cooldown_key] = now_ts
                                            spike_factor = rate / max(baseline_rate, 0.001)
                                            severity = "critical" if spike_factor >= 20 or rate >= 100 else "warning"
                                            # Trigger root-cause correlation asynchronously
                                            asyncio.create_task(_create_correlated_error_event(
                                                host_id=host_id,
                                                if_index=if_index,
                                                if_name=if_name,
                                                metric_name=metric_name,
                                                current_rate=rate,
                                                baseline_rate=baseline_rate,
                                                spike_factor=spike_factor,
                                                severity=severity,
                                            ))
                            except (ValueError, TypeError):
                                pass
                except (ValueError, TypeError):
                    pass

        # Update interface_error_stats with current counters
        await db.upsert_interface_error_stat(
            host_id=host_id,
            if_index=if_index,
            if_name=if_name,
            in_errors=iface.get("in_errors", 0) or 0,
            out_errors=iface.get("out_errors", 0) or 0,
            in_discards=iface.get("in_discards", 0) or 0,
            out_discards=iface.get("out_discards", 0) or 0,
        )

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
        config_changes = await db.get_config_drift_events_in_range(
            [host_id], window_start, window_end)
        deployments = await db.get_deployments_for_host_in_range(
            host_id, window_start, window_end)
        topology_changes = await db.get_topology_changes_in_range(
            host_id, window_start, window_end)
        syslog_events = await db.get_trap_syslog_events_in_range(
            host_id, window_start, window_end)

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
            "interface_errors: spike detected host=%d if=%s metric=%s "
            "rate=%.2f/s baseline=%.2f/s (%.1f×) cause=%s",
            host_id, if_name, metric_name, current_rate, baseline_rate,
            spike_factor, category,
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
        return ("deployment",
                f"Deployment detected within 30 min: {', '.join(dep_names)}. "
                "Error spike may be caused by the deployed configuration change.")

    if config_changes:
        drift_count = len(config_changes)
        return ("config_change",
                f"{drift_count} config change(s) detected within 30 min. "
                "Error spike correlates with configuration drift — review recent changes.")

    # Priority 2: Topology change (link flap, STP change)
    if topology_changes:
        change_types = set(c.get("change_type", "") for c in topology_changes)
        return ("topology",
                f"Topology change(s) detected: {', '.join(change_types)}. "
                "Errors may be caused by link state transitions or reconvergence.")

    # Priority 3: Syslog/trap events (e.g., link down, module reset)
    physical_keywords = {"link", "duplex", "speed", "sfp", "transceiver",
                         "optic", "cable", "crc", "err-disabled"}
    if syslog_events:
        phys_events = [e for e in syslog_events
                       if any(kw in (e.get("message", "") or "").lower() for kw in physical_keywords)]
        if phys_events:
            return ("physical_layer",
                    f"Physical layer syslog events detected ({len(phys_events)} events). "
                    "Suspect cable, SFP/optic, or duplex mismatch issue.")

    # Priority 4: Error type heuristics (no correlated events found)
    error_hints = {
        "if_in_errors": (
            "physical_layer",
            "Input errors (CRC, frame, runts) with no config change — "
            "suspect physical layer: check cable, SFP/optic, or duplex mismatch."
        ),
        "if_out_errors": (
            "congestion",
            "Output errors with no config change — "
            "suspect interface congestion or speed/duplex mismatch."
        ),
        "if_in_discards": (
            "congestion",
            "Input discards increasing — "
            "possible input queue overflow due to high traffic or slow CPU."
        ),
        "if_out_discards": (
            "congestion",
            "Output discards increasing — "
            "suspect output queue congestion; check QoS policy and interface speed."
        ),
    }

    if metric_name in error_hints:
        return error_hints[metric_name]

    return ("unknown",
            f"Error rate spike ({spike_factor:.1f}× baseline) with no correlated events. "
            "Manual investigation recommended.")


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

    return await db.create_metric_samples_batch(rows)


# ═════════════════════════════════════════════════════════════════════════════
# 4.  DOWNSAMPLING ENGINE  (raw 48h → hourly 30d → daily 1yr)
# ═════════════════════════════════════════════════════════════════════════════

# Core metrics to downsample
_DOWNSAMPLE_METRICS = [
    "cpu_percent", "memory_percent", "memory_used_mb", "memory_total_mb",
    "uptime_seconds", "response_time_ms", "packet_loss_pct",
    "if_up_count", "if_down_count", "vpn_tunnels_up", "vpn_tunnels_down",
    "route_count",
    "if_in_errors", "if_out_errors", "if_in_discards", "if_out_discards",
    "if_in_errors_rate", "if_out_errors_rate", "if_in_discards_rate", "if_out_discards_rate",
]


def _percentile(values: list[float], pct: float) -> float:
    """Compute pct-th percentile using linear interpolation."""
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


async def _downsample_window(
    time_window: str,
    period_start: str,
    period_end: str,
) -> int:
    """Aggregate raw metric_samples into a rollup row for each host+metric+labels."""
    total_created = 0

    for metric in _DOWNSAMPLE_METRICS:
        raw = await db.get_raw_samples_for_rollup(metric, period_start, period_end)
        if not raw:
            continue

        # Group by (host_id, labels_json)
        groups: dict[tuple, list[float]] = {}
        for r in raw:
            key = (r["host_id"], r.get("labels_json", "{}"))
            groups.setdefault(key, []).append(r["value"])

        for (host_id, labels_json), values in groups.items():
            await db.create_metric_rollup(
                host_id=host_id,
                metric_name=metric,
                time_window=time_window,
                period_start=period_start,
                period_end=period_end,
                val_min=min(values),
                val_avg=sum(values) / len(values),
                val_max=max(values),
                val_p95=_percentile(values, 95),
                sample_count=len(values),
                labels_json=labels_json,
            )
            total_created += 1

    return total_created


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
    raw_deleted = await db.delete_old_metric_samples(hours=48)
    hourly_deleted = await db.delete_old_metric_rollups("hourly", 30)
    daily_deleted = await db.delete_old_metric_rollups("daily", 365)
    ifts_deleted = await db.delete_old_interface_ts(30)
    traps_deleted = await db.delete_old_trap_syslog_events(30)
    error_events_deleted = await db.delete_old_interface_error_events(90)
    return {
        "raw_samples_deleted": raw_deleted,
        "hourly_rollups_deleted": hourly_deleted,
        "daily_rollups_deleted": daily_deleted,
        "interface_ts_deleted": ifts_deleted,
        "trap_events_deleted": traps_deleted,
        "error_events_deleted": error_events_deleted,
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

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("metrics: downsampling loop error: %s", redact_value(str(exc)))
            await asyncio.sleep(300)


# ═════════════════════════════════════════════════════════════════════════════
# 5.  SNMP TRAP / SYSLOG UDP RECEIVER
# ═════════════════════════════════════════════════════════════════════════════

class _TrapSyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP listener for SNMP traps (port 162) and syslog (port 514)."""

    def __init__(self, event_type: str):
        self.event_type = event_type

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        source_ip = addr[0]
        try:
            if self.event_type == "trap":
                self._handle_trap(data, source_ip)
            else:
                self._handle_syslog(data, source_ip)
        except Exception as exc:
            LOGGER.debug("metrics: %s parse error from %s: %s",
                         self.event_type, source_ip, exc)

    def _handle_trap(self, data: bytes, source_ip: str):
        # Basic SNMPv2c trap parsing — extract OID and value from the PDU.
        # Full ASN.1 parsing would need pysnmp; this extracts the readable parts.
        raw_hex = data.hex()
        message = f"SNMP trap from {source_ip} ({len(data)} bytes)"
        oid = ""
        # Try to find OID in the raw data (basic BER TLV scan)
        try:
            text_parts = []
            for i in range(len(data)):
                if 32 <= data[i] < 127:
                    text_parts.append(chr(data[i]))
                else:
                    if text_parts:
                        candidate = "".join(text_parts)
                        if "." in candidate and len(candidate) > 5:
                            oid = candidate
                        text_parts = []
            if text_parts:
                candidate = "".join(text_parts)
                if "." in candidate and len(candidate) > 5:
                    oid = candidate
        except Exception:
            pass

        asyncio.get_running_loop().create_task(
            _store_event(source_ip, "trap", "", "info", oid, message, raw_hex[:2000])
        )

    def _handle_syslog(self, data: bytes, source_ip: str):
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
                sev_num = pri & 0x07
                fac_num = (pri >> 3) & 0x1F
                facility = str(fac_num)
                _sev_map = {0: "critical", 1: "critical", 2: "critical",
                            3: "critical", 4: "warning", 5: "info",
                            6: "info", 7: "info"}
                severity = _sev_map.get(sev_num, "info")
                message = text[pri_end + 1:].strip()
            except (ValueError, IndexError):
                pass

        asyncio.get_running_loop().create_task(
            _store_event(source_ip, "syslog", facility, severity, "", message, text[:2000])
        )


async def _store_event(source_ip, event_type, facility, severity, oid, message, raw_data):
    # Try to resolve source_ip to a host_id
    host_id = None
    try:
        host = await db.find_host_by_ip(source_ip)
        if host:
            host_id = host["id"]
    except Exception:
        pass

    await db.create_trap_syslog_event(
        source_ip=source_ip,
        event_type=event_type,
        facility=facility,
        severity=severity,
        oid=oid,
        message=message[:2000],
        raw_data=raw_data[:2000],
        host_id=host_id,
    )


_trap_transport = None
_syslog_transport = None


async def start_trap_receiver(port: int = 10162) -> bool:
    """Start SNMP trap UDP listener.  Uses port 10162 by default
    (non-privileged).  Set to 162 if running as root."""
    global _trap_transport
    if _trap_transport is not None:
        return True
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _TrapSyslogProtocol("trap"),
            local_addr=("0.0.0.0", port),
        )
        _trap_transport = transport
        LOGGER.info("metrics: SNMP trap receiver started on UDP port %d", port)
        return True
    except Exception as exc:
        LOGGER.warning("metrics: failed to start trap receiver on port %d: %s", port, exc)
        return False


async def start_syslog_receiver(port: int = 10514) -> bool:
    """Start syslog UDP listener.  Uses port 10514 by default
    (non-privileged).  Set to 514 if running as root."""
    global _syslog_transport
    if _syslog_transport is not None:
        return True
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _TrapSyslogProtocol("syslog"),
            local_addr=("0.0.0.0", port),
        )
        _syslog_transport = transport
        LOGGER.info("metrics: syslog receiver started on UDP port %d", port)
        return True
    except Exception as exc:
        LOGGER.warning("metrics: failed to start syslog receiver on port %d: %s", port, exc)
        return False


def stop_receivers():
    global _trap_transport, _syslog_transport
    if _trap_transport:
        _trap_transport.close()
        _trap_transport = None
    if _syslog_transport:
        _syslog_transport.close()
        _syslog_transport = None


# ═════════════════════════════════════════════════════════════════════════════
# 6.  API ROUTES
# ═════════════════════════════════════════════════════════════════════════════

# ── Metrics Query API ────────────────────────────────────────────────────────

@router.get("/api/metrics/query")
async def metrics_query(
    metric: str = Query(..., description="Metric name, e.g. cpu_percent"),
    host: str = Query(default="*", description="Host ID, comma-separated IDs, or * for all"),
    range: str = Query(default="6h", description="Time range: 1h, 6h, 24h, 7d, 30d"),
    step: str = Query(default="auto", description="Resolution: raw, hourly, daily, or auto"),
    group: int | None = Query(default=None, description="Filter by inventory group ID"),
):
    """Structured metrics query — no PromQL needed.
    Returns time-series data for the requested metric across hosts."""

    # Parse host filter
    host_ids = None
    if host != "*":
        try:
            host_ids = [int(h.strip()) for h in host.split(",") if h.strip()]
        except ValueError:
            raise HTTPException(400, "Invalid host parameter — use IDs or *")

    # If group is specified and host is *, resolve host IDs from group
    if group and host == "*":
        group_hosts = await db.get_hosts_for_group(group)
        if group_hosts:
            host_ids = [h["id"] for h in group_hosts]

    # Parse time range
    now = datetime.now(UTC)
    range_map = {
        "1h": timedelta(hours=1), "6h": timedelta(hours=6),
        "12h": timedelta(hours=12), "24h": timedelta(hours=24),
        "2d": timedelta(days=2), "7d": timedelta(days=7),
        "30d": timedelta(days=30), "90d": timedelta(days=90),
        "365d": timedelta(days=365),
    }
    delta = range_map.get(range)
    if not delta:
        raise HTTPException(400, f"Invalid range — use one of: {', '.join(range_map.keys())}")

    start_time = (now - delta).strftime("%Y-%m-%d %H:%M:%S")
    end_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Determine step (resolution)
    if step == "auto":
        if delta <= timedelta(hours=2):
            step = "raw"
        elif delta <= timedelta(days=2):
            step = "hourly"
        else:
            step = "daily"

    if step == "raw":
        data = await db.query_metric_samples(
            metric_name=metric, host_ids=host_ids,
            start=start_time, end=end_time, limit=10000,
        )
        return {
            "metric": metric, "step": "raw", "range": range,
            "count": len(data), "data": data,
        }
    else:
        data = await db.query_metric_rollups(
            metric_name=metric, time_window=step,
            host_ids=host_ids, start=start_time, end=end_time,
            limit=10000,
        )
        return {
            "metric": metric, "step": step, "range": range,
            "count": len(data), "data": data,
        }


@router.get("/api/metrics/capacity-planning")
async def capacity_planning(
    metric: str = Query(..., description="Metric name, e.g. cpu_percent"),
    host: str = Query(default="*", description="Host ID, comma-separated IDs, or * for all"),
    range: str = Query(default="90d", description="Time range: 30d, 90d, 365d"),
    group: int | None = Query(default=None, description="Filter by inventory group ID"),
    projection_days: int = Query(default=30, description="Days to project forward"),
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
        if group_hosts:
            host_ids = [h["id"] for h in group_hosts]

    # Parse time range
    now = datetime.now(UTC)
    range_map = {
        "30d": timedelta(days=30), "90d": timedelta(days=90),
        "180d": timedelta(days=180), "365d": timedelta(days=365),
    }
    delta = range_map.get(range)
    if not delta:
        raise HTTPException(400, f"Invalid range — use one of: {', '.join(range_map.keys())}")

    start_time = (now - delta).strftime("%Y-%m-%d %H:%M:%S")
    end_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Query daily rollups
    data = await db.query_metric_rollups(
        metric_name=metric, time_window="daily",
        host_ids=host_ids, start=start_time, end=end_time,
        limit=50000,
    )

    if not data:
        return {
            "metric": metric, "range": range, "count": 0,
            "data": [], "trend": None, "projection": [], "per_host": [],
        }

    # Group data by host for per-host projections
    by_host: dict[str, list[dict]] = {}
    for d in data:
        key = d.get("hostname") or f"host-{d.get('host_id', '?')}"
        if key not in by_host:
            by_host[key] = []
        by_host[key].append(d)

    per_host_results = []

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
            except (ValueError, TypeError):
                continue

        if len(regression_points) < 2:
            per_host_results.append({
                "hostname": hostname,
                "trend": None,
                "projection": [],
                "threshold_eta": None,
            })
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
                eta_date = (now + timedelta(days=days_until)).strftime("%Y-%m-%d")
                threshold_eta = {
                    "date": eta_date,
                    "days_until": round(days_until),
                    "current_value": round(current_val, 2),
                }

        per_host_results.append({
            "hostname": hostname,
            "trend": {"slope": round(slope, 6), "intercept": round(intercept, 2)},
            "projection": projection,
            "threshold_eta": threshold_eta,
        })

    return {
        "metric": metric, "range": range, "threshold": threshold,
        "projection_days": projection_days,
        "count": len(data), "data": data,
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
    denom = n * sum_x2 - sum_x ** 2
    if denom == 0:
        return (0.0, sum_y / n)
    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n
    return (slope, intercept)


@router.get("/api/metrics/names")
async def metrics_names():
    """List available metric names."""
    return {"metrics": _DOWNSAMPLE_METRICS}


# ── Interface Time-Series API ────────────────────────────────────────────────

@router.get("/api/metrics/interfaces/{host_id}")
async def interface_timeseries(
    host_id: int,
    if_index: int | None = Query(default=None),
    range: str = Query(default="6h"),
):
    """Get per-interface utilization time-series for a host."""
    now = datetime.now(UTC)
    range_map = {
        "1h": timedelta(hours=1), "6h": timedelta(hours=6),
        "24h": timedelta(hours=24), "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = range_map.get(range, timedelta(hours=6))
    start = (now - delta).strftime("%Y-%m-%d %H:%M:%S")

    data = await db.query_interface_ts(
        host_id=host_id, if_index=if_index, start=start,
    )
    return {"host_id": host_id, "if_index": if_index, "range": range,
            "count": len(data), "data": data}


# ── Vendor OID Registry API ─────────────────────────────────────────────────

@router.get("/api/metrics/vendor-oids")
async def vendor_oids_list():
    """List all vendor OID registry entries (built-in + custom)."""
    custom = await db.get_vendor_oid_entries()
    return {
        "builtin": VENDOR_OID_DEFAULTS,
        "custom": custom,
    }


@router.post("/api/metrics/vendor-oids")
async def vendor_oids_create(body: dict, request: Request):
    """Add a custom vendor OID mapping."""
    vendor = body.get("vendor", "")
    device_type = body.get("device_type", "")
    if not vendor or not device_type:
        raise HTTPException(400, "vendor and device_type are required")
    entry_id = await db.upsert_vendor_oid(
        vendor=vendor, device_type=device_type,
        cpu_oid=body.get("cpu_oid", ""),
        cpu_walk=int(body.get("cpu_walk", 1)),
        mem_used_oid=body.get("mem_used_oid", ""),
        mem_free_oid=body.get("mem_free_oid", ""),
        mem_total_oid=body.get("mem_total_oid", ""),
        uptime_oid=body.get("uptime_oid", "1.3.6.1.2.1.1.3"),
        notes=body.get("notes", ""),
    )
    return {"id": entry_id}


@router.delete("/api/metrics/vendor-oids/{entry_id}")
async def vendor_oids_delete(entry_id: int):
    ok = await db.delete_vendor_oid(entry_id)
    if not ok:
        raise HTTPException(404, "Entry not found")
    return {"ok": True}


# ── Trap / Syslog Events API ────────────────────────────────────────────────

@router.get("/api/metrics/events")
async def trap_syslog_events(
    event_type: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=200, le=5000),
):
    return await db.get_trap_syslog_events(event_type, host_id, severity, limit)


# ── Admin: Receiver control ─────────────────────────────────────────────────

@admin_router.post("/api/admin/metrics/receivers/start")
async def admin_start_receivers(body: dict = {}):
    trap_port = int(body.get("trap_port", 10162))
    syslog_port = int(body.get("syslog_port", 10514))
    trap_ok = await start_trap_receiver(trap_port)
    syslog_ok = await start_syslog_receiver(syslog_port)
    return {"trap_started": trap_ok, "syslog_started": syslog_ok}


@admin_router.post("/api/admin/metrics/receivers/stop")
async def admin_stop_receivers():
    stop_receivers()
    return {"ok": True}


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
