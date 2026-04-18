"""
topology.py -- Topology visualization, discovery, and change-tracking routes.
"""

import asyncio
import json
import os

import re

import routes.database as db
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

import netcontrol.routes.state as state
from netcontrol.routes.snmp import _discover_neighbors, _infer_device_category, _snmp_walk  # noqa: F401
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.topology")

# Two routers: one for topology-feature routes, one for admin routes
router = APIRouter()
admin_router = APIRouter()


# ── Helpers ──────────────────────────────────────────────────────────────────

_IFACE_ABBREV = [
    (re.compile(r"twentyfivegige(?:thernet)?", re.I), "25g"),
    (re.compile(r"hundredgige(?:thernet)?", re.I), "100g"),
    (re.compile(r"fortygigabitethernet", re.I), "40g"),
    (re.compile(r"tengigabitethernet", re.I), "te"),
    (re.compile(r"twogigabitethernet", re.I), "2g"),
    (re.compile(r"fivegigabitethernet", re.I), "5g"),
    (re.compile(r"gigabitethernet", re.I), "gi"),
    (re.compile(r"fastethernet", re.I), "fa"),
    (re.compile(r"port-channel", re.I), "po"),
    (re.compile(r"ethernet", re.I), "eth"),
]


def _normalize_iface(name: str) -> str:
    """Canonicalize an interface name for dedup comparison.

    E.g. 'GigabitEthernet1/0/46' and 'Gi1/0/46' both become 'gi1/0/46'.
    """
    n = name.strip().lower().replace(" ", "")
    for pattern, replacement in _IFACE_ABBREV:
        n = pattern.sub(replacement, n)
    return n


def _normalize_link_key(
    source_host_id: int,
    source_interface: str,
    target_device_name: str,
    target_interface: str,
) -> tuple:
    """Normalize a link key so minor SNMP string variations don't cause false
    change detections (case, domain suffix, whitespace)."""
    # Strip domain suffixes (e.g. "switch1.domain.local" → "switch1")
    tgt = target_device_name.strip().lower().split(".")[0]
    return (
        source_host_id,
        source_interface.strip().lower(),
        tgt,
        target_interface.strip().lower(),
    )


async def _record_topology_changes(
    host: dict,
    old_link_keys: set[tuple],
    new_link_keys: set[tuple],
    new_neighbors: list[dict],
    old_links: list[dict],
) -> None:
    """Compare old vs new link keys and record added/removed changes."""
    hostname = host.get("hostname", "")

    # Links that were removed (present before, gone now)
    removed_keys = old_link_keys - new_link_keys
    for key in removed_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        # Find protocol from old links (compare normalized)
        protocol = ""
        target_ip = ""
        for ol in old_links:
            if _normalize_link_key(ol["source_host_id"], ol["source_interface"],
                                   ol["target_device_name"], ol["target_interface"]) == key:
                protocol = ol.get("protocol", "")
                target_ip = ol.get("target_ip", "")
                break
        await db.insert_topology_change(
            change_type="removed",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )

    # Links that were added (not present before, present now)
    added_keys = new_link_keys - old_link_keys
    for key in added_keys:
        _src_id, src_iface, tgt_name, tgt_iface = key
        protocol = ""
        target_ip = ""
        for n in new_neighbors:
            if _normalize_link_key(n["source_host_id"], n["local_interface"],
                                   n["remote_device_name"], n["remote_interface"]) == key:
                protocol = n.get("protocol", "")
                target_ip = n.get("remote_ip", "")
                break
        await db.insert_topology_change(
            change_type="added",
            source_host_id=host["id"],
            source_hostname=hostname,
            source_interface=src_iface,
            target_device_name=tgt_name,
            target_interface=tgt_iface,
            target_ip=target_ip,
            protocol=protocol,
        )


def _weathermap_color(utilization_pct: float) -> str:
    """Map utilization % to a hex color: green → yellow → orange → red."""
    pct = max(0, min(100, utilization_pct))
    if pct < 1:
        return "#808080"    # grey — idle / no traffic
    if pct < 25:
        return "#00cc00"    # green
    if pct < 50:
        return "#92d050"    # light green
    if pct < 60:
        return "#ffff00"    # yellow
    if pct < 70:
        return "#ffc000"    # amber
    if pct < 80:
        return "#ff8000"    # orange
    if pct < 90:
        return "#ff4000"    # red-orange
    return "#ff0000"        # red — near saturation


def _weathermap_width(utilization_pct: float) -> int:
    """Map utilization % to an edge width (1–8)."""
    pct = max(0, min(100, utilization_pct))
    if pct < 10:
        return 1
    if pct < 30:
        return 2
    if pct < 50:
        return 3
    if pct < 70:
        return 4
    if pct < 85:
        return 6
    return 8


def _calc_interface_utilization(stat: dict) -> dict | None:
    """Calculate utilization percentage from two counter snapshots."""
    if not stat.get("prev_polled_at") or not stat.get("polled_at"):
        return None
    try:
        from datetime import datetime as _dt
        t1 = _dt.fromisoformat(stat["prev_polled_at"])
        t2 = _dt.fromisoformat(stat["polled_at"])
        delta_sec = (t2 - t1).total_seconds()
        if delta_sec <= 0:
            return None
        speed_bps = (stat.get("if_speed_mbps") or 0) * 1_000_000
        if speed_bps <= 0:
            return None

        # Guard against NULL previous counters (first poll has no baseline)
        if stat.get("prev_in_octets") is None or stat.get("prev_out_octets") is None:
            return None

        in_delta = stat["in_octets"] - stat["prev_in_octets"]
        out_delta = stat["out_octets"] - stat["prev_out_octets"]
        # Handle 32/64-bit counter wraps
        if in_delta < 0:
            in_delta += 2**32
        if out_delta < 0:
            out_delta += 2**32

        in_bps = (in_delta * 8) / delta_sec
        out_bps = (out_delta * 8) / delta_sec
        in_pct = min(100.0, (in_bps / speed_bps) * 100)
        out_pct = min(100.0, (out_bps / speed_bps) * 100)
        util_pct = max(in_pct, out_pct)

        return {
            "in_bps": round(in_bps),
            "out_bps": round(out_bps),
            "in_pct": round(in_pct, 1),
            "out_pct": round(out_pct, 1),
            "utilization_pct": round(util_pct, 1),
            "speed_mbps": stat.get("if_speed_mbps", 0),
            "color": _weathermap_color(util_pct),
            "width": _weathermap_width(util_pct),
        }
    except Exception:
        return None


_STP_PORT_STATE_MAP = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}

STP_ROOT_CHANGE_LOOKBACK_MINUTES = max(1, int(os.getenv("APP_STP_ROOT_LOOKBACK_MINUTES", "30")))
STP_ROOT_CHANGE_ANOMALY_THRESHOLD = max(2, int(os.getenv("APP_STP_ROOT_CHANGE_THRESHOLD", "3")))
STP_TOPOLOGY_STORM_DELTA_THRESHOLD = max(2, int(os.getenv("APP_STP_TOPOLOGY_STORM_DELTA", "5")))
STP_TOPOLOGY_STORM_WINDOW_SECONDS = max(30, int(os.getenv("APP_STP_TOPOLOGY_STORM_WINDOW_SECONDS", "300")))
STP_SCAN_DEFAULT_MAX_VLANS = max(1, int(os.getenv("APP_STP_SCAN_MAX_VLANS", "64")))


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_stp_bridge_id(raw_value) -> str:
    """Normalize bridge IDs into compact, display-safe text."""
    text = str(raw_value).strip()
    if not text:
        return ""
    return " ".join(text.split())


def _extract_walk_scalar(table: dict[str, str], base_oid: str) -> str:
    """Extract scalar value from a walk dict (prefers <oid>.0 key)."""
    if not table:
        return ""
    direct = table.get(f"{base_oid}.0")
    if direct is not None:
        return str(direct).strip()
    for oid, value in table.items():
        if oid == base_oid or oid.startswith(base_oid + "."):
            return str(value).strip()
    return ""


def _stp_port_state_name(raw_value) -> str:
    numeric = _safe_int(raw_value, default=0)
    return _STP_PORT_STATE_MAP.get(numeric, str(raw_value).strip().lower() or "unknown")


def _stp_port_role(port_state: str, bridge_port: int, root_port: int) -> str:
    state = (port_state or "").strip().lower()
    if root_port > 0 and bridge_port == root_port:
        return "root"
    if state in {"blocking", "discarding", "disabled", "broken"}:
        return "blocked"
    if state in {"listening", "learning"}:
        return "alternate"
    if state == "forwarding":
        return "designated"
    return "unknown"


def _snmp_cfg_for_vlan(snmp_cfg: dict, vlan_id: int) -> dict:
    """Return an SNMP config adjusted for Cisco per-VLAN polling when possible."""
    cfg = dict(snmp_cfg or {})
    version = str(cfg.get("version", "2c")).strip().lower()
    if version != "2c" or vlan_id <= 1:
        return cfg

    community = str(cfg.get("community", "")).strip()
    if not community:
        return cfg
    base_community = community.split("@", 1)[0].strip()
    if not base_community:
        return cfg
    cfg["community"] = f"{base_community}@{vlan_id}"
    return cfg


async def _discover_vlan_ids_for_host(
    ip_address: str,
    snmp_cfg: dict,
    *,
    timeout_seconds: float = 5.0,
    max_vlans: int = STP_SCAN_DEFAULT_MAX_VLANS,
) -> list[int]:
    """Discover candidate VLAN IDs using Q-BRIDGE-MIB dot1qVlanStaticName."""
    version = str(snmp_cfg.get("version", "2c")).strip().lower()
    if version != "2c":
        return [1]

    base_oid = "1.3.6.1.2.1.17.7.1.4.3.1.1"
    vlan_ids: set[int] = {1}
    try:
        rows = await _snmp_walk(ip_address, timeout_seconds, snmp_cfg, base_oid, max_rows=5000)
    except Exception:
        return [1]

    for oid in rows.keys():
        suffix = oid[len(base_oid):].lstrip(".")
        vid = _safe_int(suffix, default=-1)
        if 1 <= vid <= 4094:
            vlan_ids.add(vid)

    ordered = sorted(vlan_ids)
    return ordered[: max(1, min(int(max_vlans), 256))]


async def _collect_stp_snapshot_for_host(
    host: dict,
    snmp_cfg: dict,
    *,
    vlan_id: int = 1,
    timeout_seconds: float = 5.0,
) -> dict:
    """Collect Bridge-MIB STP state for one host."""
    host_id = int(host["id"])
    ip_address = host["ip_address"]
    effective_snmp_cfg = _snmp_cfg_for_vlan(snmp_cfg, vlan_id)

    # Bridge-MIB OIDs (generic STP instance; vlan_id kept for future PVST/MST expansion)
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"
    if_descr_oid = "1.3.6.1.2.1.2.2.1.2"
    dot1d_base_port_ifindex_oid = "1.3.6.1.2.1.17.1.4.1.2"
    dot1d_stp_port_state_oid = "1.3.6.1.2.1.17.2.15.1.3"
    dot1d_stp_port_designated_bridge_oid = "1.3.6.1.2.1.17.2.15.1.8"
    dot1d_stp_designated_root_oid = "1.3.6.1.2.1.17.2.5"
    dot1d_stp_root_port_oid = "1.3.6.1.2.1.17.2.7"
    dot1d_stp_top_changes_oid = "1.3.6.1.2.1.17.2.4"
    dot1d_stp_time_since_change_oid = "1.3.6.1.2.1.17.2.3"

    async def _walk(oid: str, max_rows: int = 800) -> dict[str, str]:
        return await _snmp_walk(ip_address, timeout_seconds, effective_snmp_cfg, oid, max_rows=max_rows)

    (
        if_names,
        if_descr,
        base_port_ifindex,
        stp_port_states,
        stp_port_designated_bridge,
        designated_root_scalar,
        root_port_scalar,
        top_changes_scalar,
        time_since_change_scalar,
    ) = await asyncio.gather(
        _walk(if_name_oid),
        _walk(if_descr_oid),
        _walk(dot1d_base_port_ifindex_oid),
        _walk(dot1d_stp_port_state_oid),
        _walk(dot1d_stp_port_designated_bridge_oid),
        _walk(dot1d_stp_designated_root_oid, max_rows=8),
        _walk(dot1d_stp_root_port_oid, max_rows=8),
        _walk(dot1d_stp_top_changes_oid, max_rows=8),
        _walk(dot1d_stp_time_since_change_oid, max_rows=8),
    )

    effective_if_names = if_names or if_descr
    if_index_to_name: dict[str, str] = {}
    for oid, val in effective_if_names.items():
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            if_index_to_name[idx] = str(val).strip()

    bridge_port_to_ifindex: dict[int, int] = {}
    for oid, val in base_port_ifindex.items():
        suffix = oid[len(dot1d_base_port_ifindex_oid):].lstrip(".")
        bridge_port = _safe_int(suffix, default=-1)
        if bridge_port < 0:
            continue
        bridge_port_to_ifindex[bridge_port] = _safe_int(val, default=0)

    designated_bridge_by_port: dict[int, str] = {}
    for oid, val in stp_port_designated_bridge.items():
        suffix = oid[len(dot1d_stp_port_designated_bridge_oid):].lstrip(".")
        bridge_port = _safe_int(suffix, default=-1)
        if bridge_port < 0:
            continue
        designated_bridge_by_port[bridge_port] = _normalize_stp_bridge_id(val)

    root_bridge_id = _normalize_stp_bridge_id(
        _extract_walk_scalar(designated_root_scalar, dot1d_stp_designated_root_oid)
    )
    root_port = _safe_int(_extract_walk_scalar(root_port_scalar, dot1d_stp_root_port_oid), default=0)
    topology_change_count = _safe_int(
        _extract_walk_scalar(top_changes_scalar, dot1d_stp_top_changes_oid), default=0
    )
    time_since_topology_change = _safe_int(
        _extract_walk_scalar(time_since_change_scalar, dot1d_stp_time_since_change_oid), default=0
    )
    is_root_bridge = root_port == 0 and bool(root_bridge_id)

    port_rows: list[dict] = []
    for oid, raw_state in stp_port_states.items():
        suffix = oid[len(dot1d_stp_port_state_oid):].lstrip(".")
        bridge_port = _safe_int(suffix, default=-1)
        if bridge_port < 0:
            continue

        if_index = bridge_port_to_ifindex.get(bridge_port, 0)
        interface_name = if_index_to_name.get(str(if_index), f"bridge-port-{bridge_port}")
        port_state = _stp_port_state_name(raw_state)
        port_role = _stp_port_role(port_state, bridge_port, root_port)

        port_rows.append(
            {
                "host_id": host_id,
                "vlan_id": vlan_id,
                "bridge_port": bridge_port,
                "if_index": if_index,
                "interface_name": interface_name,
                "port_state": port_state,
                "port_role": port_role,
                "designated_bridge_id": designated_bridge_by_port.get(bridge_port, ""),
                "root_bridge_id": root_bridge_id,
                "root_port": root_port,
                "topology_change_count": topology_change_count,
                "time_since_topology_change": time_since_topology_change,
                "is_root_bridge": is_root_bridge,
            }
        )

    return {
        "host_id": host_id,
        "hostname": host.get("hostname", ""),
        "ip_address": ip_address,
        "vlan_id": vlan_id,
        "root_bridge_id": root_bridge_id,
        "root_port": root_port,
        "topology_change_count": topology_change_count,
        "time_since_topology_change": time_since_topology_change,
        "is_root_bridge": is_root_bridge,
        "ports": port_rows,
    }


async def _create_stp_monitoring_alert(
    host_id: int,
    vlan_id: int,
    *,
    alert_type: str,
    metric: str,
    message: str,
    severity: str,
    value: float | None = None,
    dedup_suffix: str = "",
) -> None:
    dedup_key = f"stp:{host_id}:vlan{vlan_id}:{dedup_suffix or metric}:{alert_type}"
    try:
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=None,
            alert_type=alert_type,
            metric=metric,
            message=message,
            severity=severity,
            value=value,
            dedup_key=dedup_key,
        )
    except Exception:
        # STP runs under topology feature; monitoring may be disabled or unavailable.
        pass


async def _record_stp_events_for_host(
    host: dict,
    vlan_id: int,
    old_rows: list[dict],
    snapshot: dict,
    *,
    expected_root_bridge_id: str = "",
    expected_root_hostname: str = "",
) -> None:
    """Derive STP events/anomalies by comparing old and new snapshots."""
    if not old_rows:
        return

    host_id = int(host["id"])
    hostname = host.get("hostname", str(host_id))
    old_by_port = {int(r.get("bridge_port", -1)): r for r in old_rows}

    old_root = str(old_rows[0].get("root_bridge_id", "")).strip() if old_rows else ""
    new_root = str(snapshot.get("root_bridge_id", "")).strip()
    expected_root = _normalize_stp_bridge_id(expected_root_bridge_id)
    expected_root_label = (expected_root_hostname or "").strip() or expected_root
    if old_root and new_root and old_root != new_root:
        await db.insert_stp_topology_event(
            host_id=host_id,
            vlan_id=vlan_id,
            event_type="root_changed",
            severity="critical",
            interface_name="",
            details=f"Root bridge changed on {hostname}",
            old_value=old_root,
            new_value=new_root,
        )
        await _create_stp_monitoring_alert(
            host_id,
            vlan_id,
            alert_type="anomaly",
            metric="stp_root_bridge",
            message=f"STP root bridge changed on {hostname} (VLAN {vlan_id}): {old_root} -> {new_root}",
            severity="critical",
            dedup_suffix="root-change",
        )

        if expected_root and new_root != expected_root:
            await db.insert_stp_topology_event(
                host_id=host_id,
                vlan_id=vlan_id,
                event_type="unexpected_root_election",
                severity="critical",
                interface_name="",
                details=(
                    f"Unexpected STP root election on {hostname} VLAN {vlan_id} "
                    f"(expected {expected_root_label}, observed {new_root})"
                ),
                old_value=expected_root,
                new_value=str(new_root),
            )
            await _create_stp_monitoring_alert(
                host_id,
                vlan_id,
                alert_type="anomaly",
                metric="stp_unexpected_root_election",
                message=(
                    f"Unexpected STP root bridge on {hostname} VLAN {vlan_id}: "
                    f"expected {expected_root_label}, observed {new_root}"
                ),
                severity="critical",
                dedup_suffix="unexpected-root",
            )

        recent_root_changes = await db.count_recent_stp_topology_events(
            host_id=host_id,
            vlan_id=vlan_id,
            event_type="root_changed",
            within_minutes=STP_ROOT_CHANGE_LOOKBACK_MINUTES,
            max_rows=1000,
        )
        if recent_root_changes == STP_ROOT_CHANGE_ANOMALY_THRESHOLD:
            await db.insert_stp_topology_event(
                host_id=host_id,
                vlan_id=vlan_id,
                event_type="root_election_instability",
                severity="critical",
                interface_name="",
                details=(
                    f"Root changed {recent_root_changes} times in "
                    f"{STP_ROOT_CHANGE_LOOKBACK_MINUTES}m on {hostname} VLAN {vlan_id}"
                ),
                old_value=str(old_root),
                new_value=str(new_root),
            )
            await _create_stp_monitoring_alert(
                host_id,
                vlan_id,
                alert_type="anomaly",
                metric="stp_root_election_instability",
                message=(
                    f"STP root election instability on {hostname} VLAN {vlan_id}: "
                    f"{recent_root_changes} root changes in {STP_ROOT_CHANGE_LOOKBACK_MINUTES}m"
                ),
                severity="critical",
                value=float(recent_root_changes),
                dedup_suffix="root-instability",
            )

    old_top_changes = max((_safe_int(r.get("topology_change_count"), 0) for r in old_rows), default=0)
    new_top_changes = _safe_int(snapshot.get("topology_change_count"), 0)
    top_change_delta = max(0, new_top_changes - old_top_changes)
    if top_change_delta > 0:
        await db.insert_stp_topology_event(
            host_id=host_id,
            vlan_id=vlan_id,
            event_type="topology_change",
            severity="warning",
            interface_name="",
            details=f"STP topology change counter incremented on {hostname}",
            old_value=str(old_top_changes),
            new_value=str(new_top_changes),
        )

        time_since_change_cs = _safe_int(snapshot.get("time_since_topology_change"), 0)
        recent_change = 0 <= time_since_change_cs <= STP_TOPOLOGY_STORM_WINDOW_SECONDS * 100
        if top_change_delta >= STP_TOPOLOGY_STORM_DELTA_THRESHOLD and recent_change:
            await db.insert_stp_topology_event(
                host_id=host_id,
                vlan_id=vlan_id,
                event_type="topology_change_storm",
                severity="critical",
                interface_name="",
                details=(
                    f"STP topology-change storm on {hostname} VLAN {vlan_id} "
                    f"(delta={top_change_delta} in <= {STP_TOPOLOGY_STORM_WINDOW_SECONDS}s)"
                ),
                old_value=str(old_top_changes),
                new_value=str(new_top_changes),
            )
            await _create_stp_monitoring_alert(
                host_id,
                vlan_id,
                alert_type="churn",
                metric="stp_topology_change_storm",
                message=(
                    f"STP topology-change storm on {hostname} VLAN {vlan_id}: "
                    f"counter +{top_change_delta} within {STP_TOPOLOGY_STORM_WINDOW_SECONDS}s"
                ),
                severity="critical",
                value=float(top_change_delta),
                dedup_suffix="topo-storm",
            )

    for row in snapshot.get("ports", []):
        bridge_port = int(row.get("bridge_port", -1))
        old = old_by_port.get(bridge_port)
        if not old:
            continue
        old_state = str(old.get("port_state", "")).strip().lower()
        new_state = str(row.get("port_state", "")).strip().lower()
        old_role = str(old.get("port_role", "")).strip().lower()
        new_role = str(row.get("port_role", "")).strip().lower()

        if old_state == new_state and old_role == new_role:
            continue

        iface = row.get("interface_name", f"bridge-port-{bridge_port}")
        await db.insert_stp_topology_event(
            host_id=host_id,
            vlan_id=vlan_id,
            event_type="port_state_change",
            severity="warning",
            interface_name=iface,
            details=f"STP port state/role changed on {iface}",
            old_value=f"{old_state}/{old_role}",
            new_value=f"{new_state}/{new_role}",
        )


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_topology_discovery_once() -> dict:
    """Run neighbor discovery across all SNMP-enabled groups."""
    if not state.TOPOLOGY_DISCOVERY_CONFIG.get("enabled"):
        return {"enabled": False, "groups_scanned": 0, "links_discovered": 0, "errors": 0}

    groups = await db.get_all_groups()
    total_links = 0
    total_errors = 0
    groups_scanned = 0

    for group in groups:
        snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
        if not snmp_cfg.get("enabled", False):
            continue
        hosts = await db.get_hosts_for_group(group["id"])
        if not hosts:
            continue

        groups_scanned += 1
        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                    )
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology scheduled: discovery failed for %s: %s",
                                   host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                total_errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    _normalize_link_key(link["source_host_id"], link["source_interface"],
                                        link["target_device_name"], link["target_interface"])
                    for link in old_links if link["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    _normalize_link_key(n["source_host_id"], n["local_interface"],
                                        n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Auto-apply interface-scope graph templates
                if if_stats:
                    try:
                        await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                    except Exception:
                        pass
                # Auto-discover SNMP data sources (interfaces, storage)
                try:
                    from netcontrol.routes.snmp import auto_discover_data_sources
                    await auto_discover_data_sources(host["id"], host["ip_address"], snmp_cfg)
                except Exception:
                    pass
                # Collect MAC/ARP tables during topology discovery
                try:
                    from netcontrol.routes.mac_tracking import collect_mac_arp_tables
                    await collect_mac_arp_tables(host["id"], host["ip_address"], snmp_cfg)
                except Exception:
                    pass
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology scheduled: DB write failed for %s: %s",
                               host["ip_address"], exc)
                total_errors += 1

    if groups_scanned > 0:
        try:
            await db.resolve_topology_target_host_ids()
        except Exception:
            pass
        LOGGER.info("topology scheduled: scanned %d groups, %d links discovered, %d errors",
                     groups_scanned, total_links, total_errors)
        increment_metric("topology.discovery.scheduled.success")

    return {
        "enabled": True,
        "groups_scanned": groups_scanned,
        "links_discovered": total_links,
        "errors": total_errors,
    }


async def _topology_discovery_loop() -> None:
    while True:
        try:
            await asyncio.sleep(int(state.TOPOLOGY_DISCOVERY_CONFIG.get(
                "interval_seconds", state.TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])))
            await _run_topology_discovery_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("topology discovery loop failure: %s", redact_value(str(exc)))
            increment_metric("topology.discovery.scheduled.failed")
            await asyncio.sleep(state.TOPOLOGY_DISCOVERY_DEFAULTS["interval_seconds"])


async def _stp_discovery_loop() -> None:
    while True:
        try:
            await asyncio.sleep(
                int(
                    state.STP_DISCOVERY_CONFIG.get(
                        "interval_seconds",
                        state.STP_DISCOVERY_DEFAULTS["interval_seconds"],
                    )
                )
            )
            cfg = state._sanitize_stp_discovery_config(state.STP_DISCOVERY_CONFIG)
            state.STP_DISCOVERY_CONFIG = cfg
            result = await _run_stp_discovery_once(
                vlan_id=int(cfg.get("vlan_id", 1)),
                all_vlans=bool(cfg.get("all_vlans", False)),
                max_vlans=int(cfg.get("max_vlans", STP_SCAN_DEFAULT_MAX_VLANS)),
                require_enabled=True,
            )
            if result.get("enabled"):
                LOGGER.info(
                    "topology stp scheduled: scanned %d groups, %d hosts, %d ports, %d errors",
                    int(result.get("groups_scanned", 0)),
                    int(result.get("hosts_scanned", 0)),
                    int(result.get("ports_collected", 0)),
                    int(result.get("errors", 0)),
                )
                increment_metric("topology.stp.discovery.scheduled.success")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("topology stp discovery loop failure: %s", redact_value(str(exc)))
            increment_metric("topology.stp.discovery.scheduled.failed")
            await asyncio.sleep(state.STP_DISCOVERY_DEFAULTS["interval_seconds"])


# ══════════════════════════════════════════════════════════════════════════════
# Admin routes (admin_router — registered with require_admin dependency)
# ══════════════════════════════════════════════════════════════════════════════


@admin_router.get("/api/admin/topology-discovery")
async def admin_get_topology_discovery_config():
    return state.TOPOLOGY_DISCOVERY_CONFIG


@admin_router.put("/api/admin/topology-discovery")
async def admin_update_topology_discovery_config(body: dict):
    state.TOPOLOGY_DISCOVERY_CONFIG = state._sanitize_topology_discovery_config(body)
    await db.set_auth_setting("topology_discovery", state.TOPOLOGY_DISCOVERY_CONFIG)
    return state.TOPOLOGY_DISCOVERY_CONFIG


@admin_router.post("/api/admin/topology-discovery/run-now")
async def admin_run_topology_discovery_now():
    result = await _run_topology_discovery_once()
    return {"ok": True, "result": result}


@admin_router.get("/api/admin/topology-stp-discovery")
async def admin_get_topology_stp_discovery_config():
    return state.STP_DISCOVERY_CONFIG


@admin_router.put("/api/admin/topology-stp-discovery")
async def admin_update_topology_stp_discovery_config(body: dict):
    state.STP_DISCOVERY_CONFIG = state._sanitize_stp_discovery_config(body)
    await db.set_auth_setting("topology_stp_discovery", state.STP_DISCOVERY_CONFIG)
    return state.STP_DISCOVERY_CONFIG


@admin_router.post("/api/admin/topology-stp-discovery/run-now")
async def admin_run_topology_stp_discovery_now():
    cfg = state._sanitize_stp_discovery_config(state.STP_DISCOVERY_CONFIG)
    state.STP_DISCOVERY_CONFIG = cfg
    result = await _run_stp_discovery_once(
        vlan_id=int(cfg.get("vlan_id", 1)),
        all_vlans=bool(cfg.get("all_vlans", False)),
        max_vlans=int(cfg.get("max_vlans", STP_SCAN_DEFAULT_MAX_VLANS)),
        require_enabled=True,
    )
    return {"ok": True, "result": result}


@admin_router.get("/api/admin/topology-stp-root-policies")
async def admin_get_topology_stp_root_policies(
    group_id: int | None = Query(default=None),
    vlan_id: int | None = Query(default=None),
    enabled_only: bool = Query(default=False),
    limit: int = Query(default=2000, ge=1, le=10000),
):
    rows = await db.get_stp_root_policies(
        group_id=group_id,
        vlan_id=vlan_id,
        enabled_only=enabled_only,
        limit=limit,
    )
    return {"policies": rows, "count": len(rows)}


@admin_router.put("/api/admin/topology-stp-root-policies")
async def admin_upsert_topology_stp_root_policy(body: dict):
    group_id = _safe_int(body.get("group_id"), default=0)
    if group_id <= 0:
        raise HTTPException(status_code=400, detail="group_id is required")
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    vlan_id = max(1, min(4094, _safe_int(body.get("vlan_id"), default=1)))
    expected_root_bridge_id = _normalize_stp_bridge_id(body.get("expected_root_bridge_id"))
    if not expected_root_bridge_id:
        raise HTTPException(status_code=400, detail="expected_root_bridge_id is required")

    expected_root_hostname = str(body.get("expected_root_hostname", "")).strip()
    enabled = _as_bool(body.get("enabled"), default=True)

    await db.upsert_stp_root_policy(
        group_id=group_id,
        vlan_id=vlan_id,
        expected_root_bridge_id=expected_root_bridge_id,
        expected_root_hostname=expected_root_hostname,
        enabled=enabled,
    )
    policy = await db.get_stp_root_policy(group_id, vlan_id)
    return {"ok": True, "policy": policy}


@admin_router.delete("/api/admin/topology-stp-root-policies/{policy_id}")
async def admin_delete_topology_stp_root_policy(policy_id: int):
    deleted = await db.delete_stp_root_policy(policy_id)
    if deleted <= 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deleted": deleted}


# ══════════════════════════════════════════════════════════════════════════════
# Topology-feature routes (router — registered with require_auth + require_feature("topology"))
# ══════════════════════════════════════════════════════════════════════════════


@router.get("/api/topology")
async def get_topology(group_id: int | None = Query(default=None)):
    """Return topology graph data (nodes + edges) for vis-network rendering."""
    try:
        links = await db.get_topology_links(group_id)

        # Build node set from hosts in groups + external neighbors
        nodes_by_id: dict[str | int, dict] = {}
        edges: list[dict] = []

        # Gather all host IDs referenced as sources
        source_host_ids = {link["source_host_id"] for link in links}
        # Also gather resolved target host IDs
        target_host_ids = {link["target_host_id"] for link in links if link.get("target_host_id")}
        all_host_ids = source_host_ids | target_host_ids

        # Fetch all referenced inventory hosts
        if all_host_ids:
            hosts = await db.get_hosts_by_ids(list(all_host_ids))
        else:
            hosts = []

        # Also resolve external neighbor IPs to inventory hosts that were
        # manually added (target_host_id is NULL but the host exists by IP).
        existing_ids = {h["id"] for h in hosts}
        ext_ips = {
            link["target_ip"].strip()
            for link in links
            if link.get("target_ip") and not link.get("target_host_id")
        }
        if ext_ips:
            _db = await db.get_db()
            placeholders = ",".join("?" * len(ext_ips))
            rows = await _db.execute_fetchall(
                f"SELECT * FROM hosts WHERE ip_address IN ({placeholders})",
                list(ext_ips),
            )
            for row in rows:
                h = dict(row)
                if h["id"] not in existing_ids:
                    hosts.append(h)
                    existing_ids.add(h["id"])

        # If filtering by group, also include all hosts in that group as nodes
        if group_id is not None:
            group_hosts = await db.get_hosts_for_group(group_id)
            for h in group_hosts:
                if h["id"] not in {hh["id"] for hh in hosts}:
                    hosts.append(h)

        # Fetch group names
        groups = await db.get_all_groups()
        group_name_map = {g["id"]: g["name"] for g in groups}

        # Build inventory nodes
        for h in hosts:
            nodes_by_id[h["id"]] = {
                "id": h["id"],
                "label": h["hostname"],
                "ip": h["ip_address"],
                "device_type": h["device_type"],
                "device_category": h.get("device_category", ""),
                "model": h.get("model", ""),
                "group_id": h["group_id"],
                "group_name": group_name_map.get(h["group_id"], ""),
                "status": h["status"],
                "in_inventory": True,
            }

        # Fetch interface stats for utilization overlay
        all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
        # Build lookup: (host_id, if_name) -> utilization data
        util_map: dict[tuple[int, str], dict] = {}
        for stat in all_stats:
            util = _calc_interface_utilization(stat)
            if util:
                util_map[(stat["host_id"], stat["if_name"])] = util

        # Fetch unacknowledged change count
        change_count = await db.get_topology_changes_count(unacknowledged_only=True)

        # Build edges + external nodes
        # Deduplicate bidirectional links: when both A→B and B→A are
        # discovered via CDP, keep only the first occurrence.  We normalise
        # interface names so "GigabitEthernet1/0/46" and "Gi1/0/46" match.
        #
        # Because target_host_id may not always be resolved (CDP-reported
        # hostname can include domain suffixes the DB resolver doesn't match),
        # one direction may use int host IDs while the reverse uses "ext_..."
        # string IDs for the same physical device.  We build a mapping from
        # ext_ keys → inventory host IDs so the dedup key is consistent.
        #
        # We also handle duplicate inventory hosts (same hostname, different
        # DB IDs) by mapping all IDs to the lowest canonical ID.
        _ext_to_host: dict[str, int] = {}
        _dup_host_map: dict[int, int] = {}  # duplicate host_id -> canonical host_id
        _hostname_to_canonical: dict[str, int] = {}
        _ip_to_host: dict[str, int] = {}  # IP address -> host_id
        for nid, ndata in nodes_by_id.items():
            if isinstance(nid, int):
                norm = ndata["label"].strip().lower().split(".")[0]
                ext_key_for = f"ext_{norm}"
                _ext_to_host[ext_key_for] = nid
                # Build IP lookup for resolving external nodes
                host_ip = (ndata.get("ip") or "").strip()
                if host_ip:
                    _ip_to_host[host_ip] = nid
                # Track duplicate inventory hosts by hostname
                if norm in _hostname_to_canonical:
                    canonical = _hostname_to_canonical[norm]
                    _dup_host_map[nid] = canonical
                else:
                    _hostname_to_canonical[norm] = nid

        # Remove duplicate inventory nodes (keep the canonical one)
        for dup_id in _dup_host_map:
            nodes_by_id.pop(dup_id, None)

        def _canonical_id(node_id) -> str:
            """Map ext_ and duplicate-host nodes to canonical host ID."""
            if isinstance(node_id, int) and node_id in _dup_host_map:
                return str(_dup_host_map[node_id])
            if isinstance(node_id, str) and node_id in _ext_to_host:
                return str(_ext_to_host[node_id])
            return str(node_id)

        seen_edge_keys: set[tuple] = set()

        for link in links:
            src_id = link["source_host_id"]
            tgt_host_id = link.get("target_host_id")
            tgt_name = link.get("target_device_name", "")
            tgt_ip = link.get("target_ip", "")

            if tgt_host_id and tgt_host_id in nodes_by_id:
                tgt_id = tgt_host_id
            else:
                # External neighbor -- normalize to prevent duplicate nodes
                # from minor SNMP string variations (case, domain suffix, whitespace)
                norm_name = tgt_name.strip().lower().split(".")[0] if tgt_name else ""
                norm_ip = tgt_ip.strip() if tgt_ip else ""
                ext_key = f"ext_{norm_name}" if norm_name else f"ext_{norm_ip}"

                # Check if this external neighbor matches an inventory host
                # by hostname or by IP address
                matched_host_id = _ext_to_host.get(ext_key)
                if not matched_host_id and norm_ip:
                    matched_host_id = _ip_to_host.get(norm_ip)
                if matched_host_id and matched_host_id in nodes_by_id:
                    tgt_id = matched_host_id
                else:
                    tgt_id = ext_key
                    if ext_key not in nodes_by_id:
                        tgt_platform = link.get("target_platform", "")
                        ext_category = _infer_device_category(tgt_platform, "", "unknown")
                        nodes_by_id[ext_key] = {
                            "id": ext_key,
                            "label": tgt_name or tgt_ip or "unknown",
                            "ip": tgt_ip,
                            "device_type": "unknown",
                            "device_category": ext_category,
                            "model": tgt_platform,
                            "group_id": None,
                            "group_name": "",
                            "status": "unknown",
                            "in_inventory": False,
                            "platform": tgt_platform,
                        }

            src_iface = link.get("source_interface", "")
            tgt_iface = link.get("target_interface", "")

            # Build a direction-independent key for dedup: sort the two
            # endpoint tuples so A→B and B→A produce the same key.
            norm_src_iface = _normalize_iface(src_iface)
            norm_tgt_iface = _normalize_iface(tgt_iface)
            endpoint_a = (_canonical_id(src_id), norm_src_iface)
            endpoint_b = (_canonical_id(tgt_id), norm_tgt_iface)
            edge_key = (min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b))
            if edge_key in seen_edge_keys:
                continue
            seen_edge_keys.add(edge_key)

            label_parts = []
            if src_iface:
                label_parts.append(src_iface)
            if tgt_iface:
                label_parts.append(tgt_iface)
            edge_label = " -- ".join(label_parts) if label_parts else ""

            # Remap duplicate host IDs to canonical IDs so edges
            # reference nodes that exist in the output node list.
            eff_src = _dup_host_map.get(src_id, src_id)
            eff_tgt = _dup_host_map.get(tgt_id, tgt_id) if isinstance(tgt_id, int) else tgt_id

            edge_data = {
                "id": link["id"],
                "from": eff_src,
                "to": eff_tgt,
                "label": edge_label,
                "protocol": link.get("protocol", "cdp"),
                "source_interface": src_iface,
                "target_interface": tgt_iface,
            }

            # Attach utilization + weathermap data (use source interface stats)
            util = util_map.get((src_id, src_iface))
            if util:
                edge_data["utilization"] = util
                edge_data["color"] = util.get("color", "#808080")
                edge_data["width"] = util.get("width", 1)
            else:
                edge_data["color"] = "#808080"
                edge_data["width"] = 1

            edges.append(edge_data)

        return {
            "nodes": list(nodes_by_id.values()),
            "edges": edges,
            "unacknowledged_changes": change_count,
        }
    except Exception as exc:
        LOGGER.error("topology: failed to build graph: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to build topology graph")


@router.get("/api/topology/utilization")
async def get_topology_utilization(group_id: int | None = Query(None)):
    """Return lightweight utilization data for all topology edges."""
    all_host_ids = set()
    links = await db.get_topology_links()
    for link in links:
        all_host_ids.add(link["source_host_id"])
        if link.get("target_host_id"):
            all_host_ids.add(link["target_host_id"])

    if group_id is not None:
        hosts = await db.get_hosts_for_group(group_id)
        all_host_ids = {h["id"] for h in hosts}

    all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
    util_map: dict[tuple[int, str], dict] = {}
    for stat in all_stats:
        util = _calc_interface_utilization(stat)
        if util:
            util_map[(stat["host_id"], stat["if_name"])] = util

    edges = []
    for link in links:
        src_id = link["source_host_id"]
        src_iface = link.get("source_interface", "")
        util_data = util_map.get((src_id, src_iface))
        edges.append({
            "source_host_id": src_id,
            "target_host_id": link.get("target_host_id"),
            "source_interface": src_iface,
            "utilization": util_data,
        })

    return {"edges": edges}


@router.get("/api/topology/utilization/stream")
async def stream_topology_utilization(
    group_id: int | None = Query(None),
    interval: int = Query(30, ge=5, le=300),
):
    """SSE endpoint that pushes utilization updates at regular intervals."""
    async def _event_gen():
        try:
            while True:
                all_host_ids = set()
                links = await db.get_topology_links()
                for link in links:
                    all_host_ids.add(link["source_host_id"])
                    if link.get("target_host_id"):
                        all_host_ids.add(link["target_host_id"])

                if group_id is not None:
                    hosts = await db.get_hosts_for_group(group_id)
                    all_host_ids = {h["id"] for h in hosts}

                all_stats = await db.get_interface_stats_by_hosts(list(all_host_ids)) if all_host_ids else []
                util_map: dict[tuple[int, str], dict] = {}
                for stat in all_stats:
                    util = _calc_interface_utilization(stat)
                    if util:
                        util_map[(stat["host_id"], stat["if_name"])] = util

                edges = []
                for link in links:
                    src_id = link["source_host_id"]
                    src_iface = link.get("source_interface", "")
                    util_data = util_map.get((src_id, src_iface))
                    if util_data:
                        edges.append({
                            "source_host_id": src_id,
                            "target_host_id": link.get("target_host_id"),
                            "source_interface": src_iface,
                            "utilization": util_data,
                        })

                payload = json.dumps({"edges": edges})
                yield f"data: {payload}\n\n"
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

    return StreamingResponse(_event_gen(), media_type="text/event-stream")


@router.post("/api/topology/discover/stream")
async def discover_topology_stream():
    """Run neighbor discovery on all groups, streaming progress via SSE."""

    async def _event_generator():
        try:
            groups = await db.get_all_groups()
            # Collect all (group, hosts, snmp_cfg) tuples for enabled groups
            work: list[tuple[dict, list[dict], dict]] = []
            for group in groups:
                snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
                if not snmp_cfg.get("enabled", False):
                    continue
                hosts = await db.get_hosts_for_group(group["id"])
                if hosts:
                    work.append((group, hosts, snmp_cfg))

            total_hosts = sum(len(hosts) for _, hosts, _ in work)
            yield f"data: {json.dumps({'type': 'start', 'total_hosts': total_hosts, 'total_groups': len(work)})}\n\n"

            if total_hosts == 0:
                yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': 0, 'links_discovered': 0, 'errors': 0})}\n\n"
                return

            scanned = 0
            total_links = 0
            total_errors = 0
            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

            for group, hosts, snmp_cfg in work:
                group_name = group.get("name", f"Group {group['id']}")
                yield f"data: {json.dumps({'type': 'group_start', 'group': group_name, 'host_count': len(hosts)})}\n\n"

                # Phase 1: concurrent SNMP walks with per-host progress
                walk_results: list[tuple[dict, list[dict] | None, list[dict]]] = []

                async def _walk_host(host: dict, _cfg=snmp_cfg):
                    async with semaphore:
                        try:
                            neighbors, if_stats = await _discover_neighbors(
                                host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                            )
                            return host, neighbors, if_stats
                        except Exception as exc:
                            LOGGER.warning("topology: neighbor discovery failed for %s: %s",
                                           host["ip_address"], exc)
                            return host, None, []

                tasks = [asyncio.create_task(_walk_host(h)) for h in hosts]
                for coro in asyncio.as_completed(tasks):
                    host, neighbors, if_stats = await coro
                    walk_results.append((host, neighbors, if_stats))
                    scanned += 1
                    neighbor_count = len(neighbors) if neighbors is not None else 0
                    yield f"data: {json.dumps({'type': 'host_walked', 'scanned': scanned, 'total_hosts': total_hosts, 'hostname': host['hostname'], 'ip': host['ip_address'], 'neighbors': neighbor_count, 'ok': neighbors is not None})}\n\n"

                # Phase 2: sequential DB writes
                yield f"data: {json.dumps({'type': 'db_write_start', 'group': group_name, 'host_count': len(walk_results)})}\n\n"

                group_links = 0
                for host, neighbors, if_stats in walk_results:
                    if neighbors is None:
                        total_errors += 1
                        continue
                    try:
                        old_links = await db.get_topology_links_for_host(host["id"])
                        old_link_keys = {
                            _normalize_link_key(link["source_host_id"], link["source_interface"],
                                                link["target_device_name"], link["target_interface"])
                            for link in old_links if link["source_host_id"] == host["id"]
                        }
                        new_link_keys = {
                            _normalize_link_key(n["source_host_id"], n["local_interface"],
                                                n["remote_device_name"], n["remote_interface"])
                            for n in neighbors
                        }
                        await db.delete_topology_links_for_host(host["id"])
                        for n in neighbors:
                            await db.upsert_topology_link(
                                source_host_id=n["source_host_id"],
                                source_ip=n["source_ip"],
                                source_interface=n["local_interface"],
                                target_host_id=None,
                                target_ip=n.get("remote_ip", ""),
                                target_device_name=n["remote_device_name"],
                                target_interface=n["remote_interface"],
                                protocol=n["protocol"],
                                target_platform=n.get("remote_platform", ""),
                            )
                        for stat in if_stats:
                            await db.upsert_interface_stat(**stat)
                        if old_link_keys:
                            await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                        group_links += len(neighbors)
                    except Exception as exc:
                        LOGGER.warning("topology: DB write failed for %s: %s",
                                       host["ip_address"], exc)
                        total_errors += 1

                total_links += group_links
                yield f"data: {json.dumps({'type': 'group_done', 'group': group_name, 'links': group_links})}\n\n"

            # Resolve target host IDs
            yield f"data: {json.dumps({'type': 'resolving'})}\n\n"
            resolved = await db.resolve_topology_target_host_ids()

            yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': scanned, 'links_discovered': total_links, 'targets_resolved': resolved, 'errors': total_errors})}\n\n"
        except Exception as exc:
            LOGGER.error("topology: streaming discovery error: %s", exc, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'message': 'An internal error occurred during discovery.'})}\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@router.post("/api/topology/discover/{group_id}")
async def discover_topology_for_group(group_id: int):
    """Run CDP/LLDP neighbor discovery on all hosts in a group."""
    try:
        group = await db.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        hosts = await db.get_hosts_for_group(group_id)
        if not hosts:
            return {"hosts_scanned": 0, "links_discovered": 0, "errors": 0}

        snmp_cfg = state._resolve_snmp_discovery_config(group_id)
        if not snmp_cfg.get("enabled", False):
            raise HTTPException(status_code=400,
                                detail="SNMP is not enabled for this group. Configure an SNMP profile first.")

        LOGGER.info("topology: starting discovery for group %d (%s) -- %d hosts",
                     group_id, group.get("name", "?"), len(hosts))

        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
        errors = 0
        total_links = 0

        # Phase 1: concurrent SNMP walks (no DB writes)
        async def _walk_host(host: dict) -> tuple[dict, list[dict] | None, list[dict]]:
            async with semaphore:
                try:
                    LOGGER.info("topology: walking %s (%s)...", host["hostname"], host["ip_address"])
                    neighbors, if_stats = await _discover_neighbors(
                        host["id"], host["ip_address"], snmp_cfg, timeout_seconds=5.0,
                    )
                    LOGGER.info("topology: %s done -- %d neighbors, %d if_stats",
                                host["hostname"], len(neighbors), len(if_stats))
                    return host, neighbors, if_stats
                except Exception as exc:
                    LOGGER.warning("topology: neighbor discovery failed for %s (%s): %s",
                                   host["hostname"], host["ip_address"], exc)
                    return host, None, []

        walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])
        LOGGER.info("topology: all SNMP walks complete, writing results to DB...")

        # Phase 2: sequential DB writes (avoids "database is locked")
        for host, neighbors, if_stats in walk_results:
            if neighbors is None:
                errors += 1
                continue
            try:
                # Snapshot old links for change detection
                old_links = await db.get_topology_links_for_host(host["id"])
                old_link_keys = {
                    _normalize_link_key(link["source_host_id"], link["source_interface"],
                                        link["target_device_name"], link["target_interface"])
                    for link in old_links if link["source_host_id"] == host["id"]
                }
                new_link_keys = {
                    _normalize_link_key(n["source_host_id"], n["local_interface"],
                                        n["remote_device_name"], n["remote_interface"])
                    for n in neighbors
                }

                await db.delete_topology_links_for_host(host["id"])
                for n in neighbors:
                    await db.upsert_topology_link(
                        source_host_id=n["source_host_id"],
                        source_ip=n["source_ip"],
                        source_interface=n["local_interface"],
                        target_host_id=None,
                        target_ip=n.get("remote_ip", ""),
                        target_device_name=n["remote_device_name"],
                        target_interface=n["remote_interface"],
                        protocol=n["protocol"],
                        target_platform=n.get("remote_platform", ""),
                    )
                # Store interface stats
                for stat in if_stats:
                    await db.upsert_interface_stat(**stat)
                # Auto-apply interface-scope graph templates
                if if_stats:
                    try:
                        await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                    except Exception:
                        pass
                # Record topology changes (only if there were previous links)
                if old_link_keys:
                    await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                total_links += len(neighbors)
            except Exception as exc:
                LOGGER.warning("topology: DB write failed for %s (%s): %s",
                               host["hostname"], host["ip_address"], exc)
                errors += 1

        # Resolve target host IDs against inventory
        resolved = await db.resolve_topology_target_host_ids()
        LOGGER.info("topology: discovered %d links from %d hosts (group %d), resolved %d targets, %d errors",
                     total_links, len(hosts), group_id, resolved, errors)

        return {
            "hosts_scanned": len(hosts),
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": errors,
        }
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: discovery error for group %d: %s", group_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during topology discovery.")


@router.post("/api/topology/discover")
async def discover_topology_all():
    """Run CDP/LLDP neighbor discovery on all groups."""
    try:
        groups = await db.get_all_groups()
        total_hosts = 0
        total_links = 0
        total_errors = 0

        for group in groups:
            snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
            if not snmp_cfg.get("enabled", False):
                continue
            hosts = await db.get_hosts_for_group(group["id"])
            if not hosts:
                continue

            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

            # Phase 1: concurrent SNMP walks (no DB writes)
            async def _walk_host(host: dict, _cfg=snmp_cfg) -> tuple[dict, list[dict] | None, list[dict]]:
                async with semaphore:
                    try:
                        neighbors, if_stats = await _discover_neighbors(
                            host["id"], host["ip_address"], _cfg, timeout_seconds=5.0,
                        )
                        return host, neighbors, if_stats
                    except Exception as exc:
                        LOGGER.warning("topology: neighbor discovery failed for %s: %s",
                                       host["ip_address"], exc)
                        return host, None, []

            walk_results = await asyncio.gather(*[_walk_host(h) for h in hosts])

            # Phase 2: sequential DB writes (avoids "database is locked")
            for host, neighbors, if_stats in walk_results:
                if neighbors is None:
                    total_errors += 1
                    continue
                try:
                    # Snapshot old links for change detection
                    old_links = await db.get_topology_links_for_host(host["id"])
                    old_link_keys = {
                        _normalize_link_key(link["source_host_id"], link["source_interface"],
                                            link["target_device_name"], link["target_interface"])
                        for link in old_links if link["source_host_id"] == host["id"]
                    }
                    new_link_keys = {
                        _normalize_link_key(n["source_host_id"], n["local_interface"],
                                            n["remote_device_name"], n["remote_interface"])
                        for n in neighbors
                    }

                    await db.delete_topology_links_for_host(host["id"])
                    for n in neighbors:
                        await db.upsert_topology_link(
                            source_host_id=n["source_host_id"],
                            source_ip=n["source_ip"],
                            source_interface=n["local_interface"],
                            target_host_id=None,
                            target_ip=n.get("remote_ip", ""),
                            target_device_name=n["remote_device_name"],
                            target_interface=n["remote_interface"],
                            protocol=n["protocol"],
                            target_platform=n.get("remote_platform", ""),
                        )
                    # Store interface stats
                    for stat in if_stats:
                        await db.upsert_interface_stat(**stat)
                    # Auto-apply interface-scope graph templates
                    if if_stats:
                        try:
                            await db.apply_interface_graph_templates_to_host(host["id"], if_stats)
                        except Exception:
                            pass
                    # Record topology changes (only if there were previous links)
                    if old_link_keys:
                        await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                    total_links += len(neighbors)
                except Exception as exc:
                    LOGGER.warning("topology: DB write failed for %s: %s",
                                   host["ip_address"], exc)
                    total_errors += 1
            total_hosts += len(hosts)

        resolved = await db.resolve_topology_target_host_ids()
        return {
            "hosts_scanned": total_hosts,
            "links_discovered": total_links,
            "targets_resolved": resolved,
            "errors": total_errors,
        }
    except Exception as exc:
        LOGGER.error("topology: full discovery error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during topology discovery.")


@router.post("/api/topology/discover/{group_id}/stream")
async def discover_topology_for_group_stream(group_id: int):
    """Run neighbor discovery on a single group, streaming progress via SSE."""

    # Validate upfront before starting the stream
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)
    if not snmp_cfg.get("enabled", False):
        raise HTTPException(status_code=400,
                            detail="SNMP is not enabled for this group. Configure an SNMP profile first.")
    hosts = await db.get_hosts_for_group(group_id)

    async def _event_generator():
        try:
            group_name = group.get("name", f"Group {group_id}")
            total_hosts = len(hosts) if hosts else 0
            yield f"data: {json.dumps({'type': 'start', 'total_hosts': total_hosts, 'total_groups': 1})}\n\n"

            if not hosts:
                yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': 0, 'links_discovered': 0, 'errors': 0})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'group_start', 'group': group_name, 'host_count': total_hosts})}\n\n"

            semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
            scanned = 0
            total_links = 0
            errors = 0

            # Phase 1: concurrent SNMP walks
            walk_results: list[tuple[dict, list[dict] | None, list[dict]]] = []

            async def _walk_host(host: dict):
                async with semaphore:
                    try:
                        neighbors, if_stats = await _discover_neighbors(
                            host["id"], host["ip_address"], snmp_cfg, timeout_seconds=5.0,
                        )
                        return host, neighbors, if_stats
                    except Exception as exc:
                        LOGGER.warning("topology: neighbor discovery failed for %s (%s): %s",
                                       host["hostname"], host["ip_address"], exc)
                        return host, None, []

            tasks = [asyncio.create_task(_walk_host(h)) for h in hosts]
            for coro in asyncio.as_completed(tasks):
                host, neighbors, if_stats = await coro
                walk_results.append((host, neighbors, if_stats))
                scanned += 1
                neighbor_count = len(neighbors) if neighbors is not None else 0
                yield f"data: {json.dumps({'type': 'host_walked', 'scanned': scanned, 'total_hosts': total_hosts, 'hostname': host['hostname'], 'ip': host['ip_address'], 'neighbors': neighbor_count, 'ok': neighbors is not None})}\n\n"

            # Phase 2: sequential DB writes
            yield f"data: {json.dumps({'type': 'db_write_start', 'group': group_name, 'host_count': len(walk_results)})}\n\n"

            for host, neighbors, if_stats in walk_results:
                if neighbors is None:
                    errors += 1
                    continue
                try:
                    old_links = await db.get_topology_links_for_host(host["id"])
                    old_link_keys = {
                        _normalize_link_key(link["source_host_id"], link["source_interface"],
                                            link["target_device_name"], link["target_interface"])
                        for link in old_links if link["source_host_id"] == host["id"]
                    }
                    new_link_keys = {
                        _normalize_link_key(n["source_host_id"], n["local_interface"],
                                            n["remote_device_name"], n["remote_interface"])
                        for n in neighbors
                    }
                    await db.delete_topology_links_for_host(host["id"])
                    for n in neighbors:
                        await db.upsert_topology_link(
                            source_host_id=n["source_host_id"],
                            source_ip=n["source_ip"],
                            source_interface=n["local_interface"],
                            target_host_id=None,
                            target_ip=n.get("remote_ip", ""),
                            target_device_name=n["remote_device_name"],
                            target_interface=n["remote_interface"],
                            protocol=n["protocol"],
                            target_platform=n.get("remote_platform", ""),
                        )
                    for stat in if_stats:
                        await db.upsert_interface_stat(**stat)
                    if old_link_keys:
                        await _record_topology_changes(host, old_link_keys, new_link_keys, neighbors, old_links)
                    total_links += len(neighbors)
                except Exception as exc:
                    LOGGER.warning("topology: DB write failed for %s (%s): %s",
                                   host["hostname"], host["ip_address"], exc)
                    errors += 1

            yield f"data: {json.dumps({'type': 'group_done', 'group': group_name, 'links': total_links})}\n\n"

            # Resolve target host IDs
            yield f"data: {json.dumps({'type': 'resolving'})}\n\n"
            resolved = await db.resolve_topology_target_host_ids()

            yield f"data: {json.dumps({'type': 'done', 'hosts_scanned': scanned, 'links_discovered': total_links, 'targets_resolved': resolved, 'errors': errors})}\n\n"
        except Exception as exc:
            LOGGER.error("topology: streaming discovery error for group %d: %s", group_id, exc, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'message': 'An internal error occurred during discovery.'})}\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@router.get("/api/topology/host/{host_id}")
async def get_host_topology(host_id: int):
    """Return topology links for a specific host."""
    try:
        host = await db.get_host(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        links = await db.get_topology_links_for_host(host_id)
        return {"host": host, "links": links}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology: host topology error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.get("/api/topology/changes")
async def get_topology_changes(unacknowledged: bool = Query(default=True),
                               limit: int = Query(default=100, ge=1, le=10000)):
    """Return recent topology changes (added/removed links)."""
    try:
        changes = await db.get_topology_changes(
            unacknowledged_only=unacknowledged, limit=limit)
        count = await db.get_topology_changes_count(unacknowledged_only=True)
        return {"changes": changes, "unacknowledged_count": count}
    except Exception as exc:
        LOGGER.error("topology: changes error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.post("/api/topology/changes/acknowledge")
async def acknowledge_topology_changes():
    """Mark all topology changes as acknowledged."""
    try:
        count = await db.acknowledge_topology_changes()
        return {"acknowledged": count}
    except Exception as exc:
        LOGGER.error("topology: acknowledge error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


async def _run_stp_discovery_once(
    *,
    group_id: int | None = None,
    vlan_id: int = 1,
    all_vlans: bool = False,
    max_vlans: int = STP_SCAN_DEFAULT_MAX_VLANS,
    require_enabled: bool = False,
) -> dict:
    """Run STP snapshot collection across one group or all SNMP-enabled groups."""
    if require_enabled and not state.STP_DISCOVERY_CONFIG.get("enabled"):
        return {
            "enabled": False,
            "groups_scanned": 0,
            "hosts_scanned": 0,
            "hosts_updated": 0,
            "ports_collected": 0,
            "errors": 0,
            "vlan_id": None,
            "all_vlans": False,
            "vlans_scanned": [],
            "unacknowledged_events": await db.get_stp_topology_events_count(unacknowledged_only=True),
        }

    group_filter = group_id if (group_id is not None and int(group_id) > 0) else None
    vlan_id_int = max(0, min(4094, _safe_int(vlan_id, default=1)))
    max_vlans_int = max(1, min(256, _safe_int(max_vlans, default=STP_SCAN_DEFAULT_MAX_VLANS)))
    all_vlans_flag = _as_bool(all_vlans, default=False)

    if group_filter is not None:
        group = await db.get_group(int(group_filter))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        groups = [group]
    else:
        groups = await db.get_all_groups()

    try:
        policy_rows = await db.get_stp_root_policies(enabled_only=True, limit=10000)
    except Exception:
        policy_rows = []
    policy_by_group_vlan: dict[tuple[int, int], dict] = {
        (int(row.get("group_id", 0)), int(row.get("vlan_id", 0))): row
        for row in policy_rows
    }

    total_hosts = 0
    updated_hosts = 0
    total_ports = 0
    total_errors = 0
    groups_scanned = 0
    vlan_ids_seen: set[int] = set()

    for group in groups:
        snmp_cfg = state._resolve_snmp_discovery_config(group["id"])
        if not snmp_cfg.get("enabled", False):
            continue

        hosts = await db.get_hosts_for_group(group["id"])
        if not hosts:
            continue

        groups_scanned += 1
        total_hosts += len(hosts)
        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _collect_host(host: dict, _cfg=snmp_cfg):
            async with semaphore:
                target_vlans: list[int]
                if all_vlans_flag or vlan_id_int == 0:
                    target_vlans = await _discover_vlan_ids_for_host(
                        host["ip_address"],
                        _cfg,
                        timeout_seconds=5.0,
                        max_vlans=max_vlans_int,
                    )
                else:
                    target_vlans = [vlan_id_int]

                snapshots: list[dict] = []
                host_errors = 0
                for vid in target_vlans:
                    try:
                        snap = await _collect_stp_snapshot_for_host(
                            host, _cfg, vlan_id=vid, timeout_seconds=5.0
                        )
                        snapshots.append(snap)
                    except Exception:
                        host_errors += 1

                return host, snapshots, host_errors

        collect_results = await asyncio.gather(*[_collect_host(h) for h in hosts])

        for host, snapshots, err_count in collect_results:
            if not snapshots:
                total_errors += max(1, int(err_count or 0))
                LOGGER.warning(
                    "topology stp: collection failed for %s (%s): %s",
                    host.get("hostname", ""),
                    host.get("ip_address", ""),
                    "no STP snapshots collected",
                )
                continue

            host_updated = False
            for snapshot in snapshots:
                snapshot_vlan = _safe_int(snapshot.get("vlan_id"), default=1)
                vlan_ids_seen.add(snapshot_vlan)
                try:
                    old_rows = await db.get_stp_port_states(
                        host_id=host["id"],
                        vlan_id=snapshot_vlan,
                        limit=5000,
                    )
                    await db.delete_stp_port_states_for_host(host["id"], vlan_id=snapshot_vlan)
                    for row in snapshot.get("ports", []):
                        await db.upsert_stp_port_state(
                            host_id=row["host_id"],
                            vlan_id=row["vlan_id"],
                            bridge_port=row["bridge_port"],
                            if_index=row["if_index"],
                            interface_name=row["interface_name"],
                            port_state=row["port_state"],
                            port_role=row["port_role"],
                            designated_bridge_id=row["designated_bridge_id"],
                            root_bridge_id=row["root_bridge_id"],
                            root_port=row["root_port"],
                            topology_change_count=row["topology_change_count"],
                            time_since_topology_change=row["time_since_topology_change"],
                            is_root_bridge=bool(row["is_root_bridge"]),
                        )

                    policy = policy_by_group_vlan.get((int(group["id"]), int(snapshot_vlan)), {})
                    await _record_stp_events_for_host(
                        host,
                        snapshot_vlan,
                        old_rows,
                        snapshot,
                        expected_root_bridge_id=str(policy.get("expected_root_bridge_id", "")),
                        expected_root_hostname=str(policy.get("expected_root_hostname", "")),
                    )
                    total_ports += len(snapshot.get("ports", []))
                    host_updated = True
                except Exception as exc:
                    total_errors += 1
                    LOGGER.warning(
                        "topology stp: DB write failed for %s (%s) vlan=%d: %s",
                        host.get("hostname", ""),
                        host.get("ip_address", ""),
                        snapshot_vlan,
                        redact_value(str(exc)),
                    )

            if host_updated:
                updated_hosts += 1
            total_errors += int(err_count or 0)

    unacknowledged = await db.get_stp_topology_events_count(unacknowledged_only=True)
    return {
        "enabled": True,
        "groups_scanned": groups_scanned,
        "hosts_scanned": total_hosts,
        "hosts_updated": updated_hosts,
        "ports_collected": total_ports,
        "errors": total_errors,
        "vlan_id": vlan_id_int if vlan_id_int > 0 else None,
        "all_vlans": bool(all_vlans_flag or vlan_id_int == 0),
        "max_vlans": max_vlans_int,
        "vlans_scanned": sorted(vlan_ids_seen),
        "unacknowledged_events": unacknowledged,
    }


@router.post("/api/topology/stp/discover")
async def discover_topology_stp(
    group_id: int | None = Query(default=None),
    vlan_id: int = Query(default=1, ge=0, le=4094),
    all_vlans: bool = Query(default=False),
    max_vlans: int = Query(default=STP_SCAN_DEFAULT_MAX_VLANS, ge=1, le=256),
):
    """Poll Bridge-MIB STP state for all SNMP-enabled hosts (or one group)."""
    try:
        group_id_int = _safe_int(group_id, default=0) if group_id is not None else 0
        return await _run_stp_discovery_once(
            group_id=group_id_int if group_id_int > 0 else None,
            vlan_id=max(0, min(4094, _safe_int(vlan_id, default=1))),
            all_vlans=_as_bool(all_vlans, default=False),
            max_vlans=max(1, min(256, _safe_int(max_vlans, default=STP_SCAN_DEFAULT_MAX_VLANS))),
            require_enabled=False,
        )
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.error("topology stp: discovery error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during STP discovery.")


@router.get("/api/topology/stp")
async def get_topology_stp_state(
    group_id: int | None = Query(default=None),
    host_id: int | None = Query(default=None),
    vlan_id: int = Query(default=1, ge=1, le=4094),
    limit: int = Query(default=5000, ge=1, le=20000),
):
    """Return latest STP state rows for topology overlay."""
    try:
        rows = await db.get_stp_port_states(
            group_id=group_id,
            host_id=host_id,
            vlan_id=vlan_id,
            limit=limit,
        )

        by_state: dict[str, int] = {}
        root_bridges: list[dict] = []
        seen_roots: set[tuple[int, int]] = set()
        for row in rows:
            state_name = (row.get("port_state") or "unknown").strip().lower() or "unknown"
            by_state[state_name] = by_state.get(state_name, 0) + 1
            if row.get("is_root_bridge"):
                key = (int(row.get("host_id", 0)), int(row.get("vlan_id", vlan_id)))
                if key not in seen_roots:
                    seen_roots.add(key)
                    root_bridges.append(
                        {
                            "host_id": row.get("host_id"),
                            "hostname": row.get("hostname"),
                            "ip_address": row.get("ip_address"),
                            "vlan_id": row.get("vlan_id"),
                            "root_bridge_id": row.get("root_bridge_id", ""),
                        }
                    )

        unacknowledged = await db.get_stp_topology_events_count(unacknowledged_only=True)
        return {
            "vlan_id": vlan_id,
            "count": len(rows),
            "states": rows,
            "summary": {
                "by_state": by_state,
                "root_bridges": root_bridges,
            },
            "unacknowledged_events": unacknowledged,
        }
    except Exception as exc:
        LOGGER.error("topology stp: state query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch STP state")


@router.get("/api/topology/stp/events")
async def get_topology_stp_events(
    unacknowledged: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=5000),
):
    """Return recent STP events (root/state/topology changes)."""
    try:
        events = await db.get_stp_topology_events(
            unacknowledged_only=unacknowledged,
            limit=limit,
        )
        count = await db.get_stp_topology_events_count(unacknowledged_only=True)
        return {"events": events, "unacknowledged_count": count}
    except Exception as exc:
        LOGGER.error("topology stp: events query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.post("/api/topology/stp/events/acknowledge")
async def acknowledge_topology_stp_events():
    """Mark all unacknowledged STP events as acknowledged."""
    try:
        count = await db.acknowledge_stp_topology_events()
        return {"acknowledged": count}
    except Exception as exc:
        LOGGER.error("topology stp: acknowledge failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.get("/api/topology/positions")
async def get_topology_positions():
    """Return saved node positions."""
    try:
        return await db.get_topology_positions()
    except Exception as exc:
        LOGGER.error("topology: get positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.put("/api/topology/positions")
async def save_topology_positions(payload: dict):
    """Save/update node positions. Body: {positions: {nodeId: {x, y}}}."""
    try:
        positions = payload.get("positions", {})
        count = await db.save_topology_positions(positions)
        return {"saved": count}
    except Exception as exc:
        LOGGER.error("topology: save positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")


@router.delete("/api/topology/positions")
async def delete_topology_positions():
    """Delete all saved node positions (reset layout)."""
    try:
        count = await db.delete_topology_positions()
        return {"deleted": count}
    except Exception as exc:
        LOGGER.error("topology: delete positions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred.")
