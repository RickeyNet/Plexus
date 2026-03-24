"""
metrics_engine.py -- Prometheus-style metrics infrastructure:
  - Data downsampling (raw → hourly → daily rollups)
  - Multi-vendor OID registry with HOST-RESOURCES-MIB fallback
  - Per-interface time-series storage with rate calculation
  - Flexible metric_samples (Prometheus data model)
  - Structured metrics query API
  - SNMP trap / syslog UDP receiver
"""

import asyncio
import json
import logging
import math
import socket
import struct
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request

import routes.database as db
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
        if_index = i + 1  # if_details use list position as index
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
                t_now = datetime.now(timezone.utc)
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

    return await db.create_interface_ts_batch(rows)


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
    now = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
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
    return {
        "raw_samples_deleted": raw_deleted,
        "hourly_rollups_deleted": hourly_deleted,
        "daily_rollups_deleted": daily_deleted,
        "interface_ts_deleted": ifts_deleted,
        "trap_events_deleted": traps_deleted,
    }


async def _downsampling_loop() -> None:
    """Background loop: hourly rollup every hour, daily rollup once per day,
    retention cleanup every 6 hours."""
    last_hourly = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    last_daily = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    last_cleanup = datetime.now(timezone.utc)

    while True:
        try:
            await asyncio.sleep(60)  # check every minute
            now = datetime.now(timezone.utc)

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

    # Parse time range
    now = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
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
