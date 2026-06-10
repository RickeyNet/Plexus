"""Map FDM operational JSON into the monitoring poll-result dict.

The output dict has the exact shape ``_poll_host_monitoring`` in
``netcontrol/routes/monitoring.py`` produces, so an FDM result flows through
the same persistence / availability / alerting / metrics / baseline pipeline
(``_process_poll_result``) as an SNMP-polled host - no firewall-specific
alerting code anywhere downstream.

Field-path caveat (read before trusting the values)
---------------------------------------------------
The precise JSON layout of ``devices/default/operational/metrics`` and
``operational/systeminfo/default`` varies across FTD builds and is documented
authoritatively only in the on-box API Explorer.  Extraction here is therefore
deliberately *defensive*: every value is pulled via :func:`_first`, which tries
several candidate key paths and returns ``None`` when none match.  A shape
mismatch degrades to "metric unavailable" (and, for interfaces, to an empty
list / zero counts) rather than crashing the poll or inventing data.

Crucially this means a wrong/unknown shape can never manufacture a *false*
alert: missing CPU/mem just records ``None``, and an unparsed interface list
yields ``if_down_count == 0``.  Validate the candidate paths in the ``_*_PATHS``
constants against a real 7.4 device and widen them as needed - the rest of the
pipeline is shape-stable.
"""

from __future__ import annotations

from typing import Any

# Candidate key paths per metric, tried in order. Tuples are nested lookups;
# a bare string is a single top-level key. Add real-device spellings here.
_CPU_AGG_PATHS = (
    ("cpu", "percentUsed"),
    ("cpu", "usagePercent"),
    ("cpu", "load"),
    ("cpuUsage",),
    ("system", "cpu", "percentUsed"),
)
_CPU_CORES_PATHS = (("cpu", "cores"), ("cpuCores",), ("cpu", "perCore"))

_MEM_PCT_PATHS = (("memory", "percentUsed"), ("memory", "usagePercent"), ("memoryUsage",))
_MEM_USED_PATHS = (("memory", "usedBytes"), ("memory", "used"), ("memory", "usedKBytes"))
_MEM_TOTAL_PATHS = (("memory", "totalBytes"), ("memory", "total"), ("memory", "totalKBytes"))

_UPTIME_PATHS = (("uptime",), ("upTime",), ("systemUptime",), ("uptimeSeconds",))

_IFACE_LIST_PATHS = (("interfaces",), ("interfaceStats",), ("ifStats",), ("interface",))


def _deep_get(obj: Any, path: tuple) -> Any:
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def _first(obj: Any, *paths: Any, cast: Any = None) -> Any:
    """Return the first present value among ``paths`` (each a key or key-tuple).

    With ``cast`` the value is coerced; a cast failure is treated as "not this
    path" and the search continues to the next candidate.
    """
    for path in paths:
        val = _deep_get(obj, path if isinstance(path, tuple) else (path,))
        if val is None:
            continue
        if cast is None:
            return val
        try:
            return cast(val)
        except (TypeError, ValueError):
            continue
    return None


def _to_float(val: Any) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _clamp_pct(val: float | None) -> float | None:
    if val is None:
        return None
    return round(max(0.0, min(100.0, val)), 1)


def base_result(host_id: int) -> dict[str, Any]:
    """The poll-result skeleton (matches monitoring._poll_host_monitoring)."""
    return {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "memory_used_mb": None,
        "memory_total_mb": None,
        "uptime_seconds": None,
        "if_up_count": 0,
        "if_down_count": 0,
        "if_admin_down": 0,
        "if_details": [],
        "vpn_tunnels_up": 0,
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "route_count": 0,
        "route_snapshot": "",
        "poll_status": "ok",
        "poll_error": "",
        "response_time_ms": None,
        "packet_loss_pct": None,
        # FDM polling is API-based, not ICMP; leave the ICMP probe fields NULL
        # exactly as an SNMP-only host with ICMP disabled would.
        "icmp_alive": None,
        "icmp_rtt_ms": None,
    }


def error_result(host_id: int, message: str) -> dict[str, Any]:
    """A poll result marking the host unreachable/errored.

    Persisted like any other poll so the FTD shows as 'down' and availability
    tracking fires - same treatment an SNMP timeout gets.
    """
    res = base_result(host_id)
    res["poll_status"] = "error"
    res["poll_error"] = message[:500]
    return res


def _extract_cpu_percent(metrics: dict) -> float | None:
    agg = _first(metrics, *_CPU_AGG_PATHS, cast=float)
    if agg is not None:
        return _clamp_pct(agg)
    cores = _first(metrics, *_CPU_CORES_PATHS)
    if isinstance(cores, list) and cores:
        vals = []
        for core in cores:
            if isinstance(core, dict):
                vals.append(_to_float(core.get("percentUsed") or core.get("load")))
            else:
                vals.append(_to_float(core))
        vals = [v for v in vals if v is not None]
        if vals:
            return _clamp_pct(sum(vals) / len(vals))
    return None


def _extract_memory(metrics: dict) -> tuple[float | None, float | None, float | None]:
    pct = _first(metrics, *_MEM_PCT_PATHS, cast=float)
    used = _first(metrics, *_MEM_USED_PATHS, cast=float)
    total = _first(metrics, *_MEM_TOTAL_PATHS, cast=float)
    used_mb = round(used / 1048576, 1) if used is not None else None
    total_mb = round(total / 1048576, 1) if total is not None else None
    if pct is None and used is not None and total:
        pct = used / total * 100.0
    return _clamp_pct(pct), used_mb, total_mb


def _extract_interfaces(metrics: dict) -> tuple[int, int, int, list[dict]]:
    raw = _first(metrics, *_IFACE_LIST_PATHS)
    if not isinstance(raw, list):
        return 0, 0, 0, []
    up = down = admin_down = 0
    details: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or item.get("ifName")
                or item.get("hardwareName") or item.get("interface") or "")
        oper = str(item.get("operStatus") or item.get("linkState")
                   or item.get("linkStatus") or item.get("status") or "").strip().lower()
        admin_raw = item.get("adminStatus")
        if admin_raw is None:
            admin_raw = item.get("enabled")
        admin_up = _admin_is_up(admin_raw)

        is_up = oper in ("up", "true", "connected", "online")
        if admin_up is False:
            admin_down += 1
        elif is_up:
            up += 1
        else:
            down += 1
        details.append({
            "name": str(name),
            "oper_status": "up" if is_up else "down",
            "admin_status": "up" if admin_up is not False else "down",
        })
    return up, down, admin_down, details


def _admin_is_up(admin_raw: Any) -> bool | None:
    """Interpret an admin-status field. None == unknown (don't count as admin-down)."""
    if admin_raw is None:
        return None
    if isinstance(admin_raw, bool):
        return admin_raw
    text = str(admin_raw).strip().lower()
    if text in ("up", "true", "enabled", "1"):
        return True
    if text in ("down", "false", "disabled", "0"):
        return False
    return None


def _extract_uptime_seconds(systeminfo: dict, metrics: dict) -> int | None:
    for src in (systeminfo, metrics):
        if not isinstance(src, dict):
            continue
        val = _first(src, *_UPTIME_PATHS, cast=float)
        if val is not None:
            return int(val)
    return None


def build_poll_result(host_id: int, systeminfo: Any, metrics: Any) -> dict[str, Any]:
    """Normalise FDM systeminfo + operational metrics into a poll-result dict."""
    res = base_result(host_id)
    systeminfo = systeminfo if isinstance(systeminfo, dict) else {}
    metrics = metrics if isinstance(metrics, dict) else {}

    res["cpu_percent"] = _extract_cpu_percent(metrics)
    res["memory_percent"], res["memory_used_mb"], res["memory_total_mb"] = _extract_memory(metrics)
    res["uptime_seconds"] = _extract_uptime_seconds(systeminfo, metrics)
    up, down, admin_down, details = _extract_interfaces(metrics)
    res["if_up_count"] = up
    res["if_down_count"] = down
    res["if_admin_down"] = admin_down
    res["if_details"] = details
    return res
