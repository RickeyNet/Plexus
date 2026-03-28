"""
mac_tracking.py -- MacTrack-style MAC/ARP/port tracking

Provides:
  - SNMP-based MAC address table collection (dot1dTpFdbTable, dot1qTpFdbTable)
  - SNMP-based ARP table collection (ipNetToMediaTable)
  - MAC/ARP search and history API endpoints
  - Background collection loop integration
"""

import asyncio
import json
import socket

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.snmp import _build_snmp_auth, _snmp_walk, _snmp_str
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.mac_tracking")


# ═════════════════════════════════════════════════════════════════════════════
# SNMP OIDs for MAC/ARP Collection
# ═════════════════════════════════════════════════════════════════════════════

# Bridge forwarding table (standard)
DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"   # dot1dTpFdbAddress
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort
DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"    # dot1dTpFdbStatus

# VLAN-aware forwarding table (Q-BRIDGE-MIB)
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # dot1qTpFdbPort

# Bridge port to ifIndex mapping
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex

# ARP table
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"     # ipNetToMediaPhysAddress
IP_NET_TO_MEDIA_NET = "1.3.6.1.2.1.4.22.1.3"       # ipNetToMediaNetAddress
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"      # ipNetToMediaType

# ifName for port resolution
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"

# Status type mapping
FDB_STATUS_MAP = {
    "1": "other", "2": "invalid", "3": "learned",
    "4": "self", "5": "mgmt",
}

ARP_TYPE_MAP = {
    "1": "other", "2": "invalid", "3": "dynamic", "4": "static",
}


def _format_mac(raw_value) -> str:
    """Convert SNMP binary MAC address to colon-separated hex string."""
    try:
        raw_bytes = bytes(raw_value)
        if len(raw_bytes) == 6:
            return ":".join(f"{b:02x}" for b in raw_bytes)
        # Some implementations return hex string directly
        s = str(raw_value).strip()
        if len(s) == 12 and all(c in "0123456789abcdefABCDEF" for c in s):
            return ":".join(s[i:i+2].lower() for i in range(0, 12, 2))
        return s
    except Exception:
        return str(raw_value)


def _extract_mac_from_oid_suffix(suffix: str) -> str:
    """Extract MAC address from OID suffix (6 decimal octets)."""
    parts = suffix.split(".")
    if len(parts) >= 6:
        mac_parts = parts[-6:]
        try:
            return ":".join(f"{int(p):02x}" for p in mac_parts)
        except (ValueError, TypeError):
            pass
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# SNMP Collection Functions
# ═════════════════════════════════════════════════════════════════════════════


async def collect_mac_arp_tables(host_id: int, ip_address: str,
                                  snmp_config: dict,
                                  timeout_seconds: float = 5.0) -> dict:
    """Walk MAC and ARP tables from a device via SNMP.

    Returns {"macs_found": int, "arps_found": int, "errors": [str]}.
    """
    result = {"macs_found": 0, "arps_found": 0, "errors": []}

    def _walk(oid):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows=2000)

    try:
        # Walk all tables in parallel
        (fdb_addr, fdb_port, fdb_status,
         q_fdb_port, bridge_port_map,
         arp_phys, arp_net, arp_type,
         if_names,
        ) = await asyncio.gather(
            _walk(DOT1D_TP_FDB_ADDRESS), _walk(DOT1D_TP_FDB_PORT), _walk(DOT1D_TP_FDB_STATUS),
            _walk(DOT1Q_TP_FDB_PORT), _walk(DOT1D_BASE_PORT_IF_INDEX),
            _walk(IP_NET_TO_MEDIA_PHYS), _walk(IP_NET_TO_MEDIA_NET), _walk(IP_NET_TO_MEDIA_TYPE),
            _walk(IF_NAME_OID),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed: {str(exc)}")
        return result

    # Build bridge port -> ifIndex -> ifName maps
    bp_to_if_index: dict[str, str] = {}
    for oid, val in bridge_port_map.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if bp:
            bp_to_if_index[bp] = str(val)

    if_index_to_name: dict[str, str] = {}
    for oid, val in if_names.items():
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            if_index_to_name[idx] = _snmp_str(val)

    def _resolve_port(bridge_port: str) -> tuple[str, int]:
        """Resolve bridge port number to (port_name, if_index)."""
        if_idx = bp_to_if_index.get(bridge_port, bridge_port)
        port_name = if_index_to_name.get(if_idx, f"port-{bridge_port}")
        try:
            return port_name, int(if_idx)
        except (ValueError, TypeError):
            return port_name, 0

    # ── Process standard bridge FDB (dot1dTpFdbTable) ──
    for oid, mac_val in fdb_addr.items():
        suffix = oid[len(DOT1D_TP_FDB_ADDRESS):].lstrip(".")
        mac = _format_mac(mac_val)
        if not mac or len(mac) < 12:
            mac = _extract_mac_from_oid_suffix(suffix)
        if not mac:
            continue

        port_oid = DOT1D_TP_FDB_PORT + "." + suffix
        status_oid = DOT1D_TP_FDB_STATUS + "." + suffix
        bridge_port = str(fdb_port.get(port_oid, "0"))
        status = FDB_STATUS_MAP.get(str(fdb_status.get(status_oid, "")), "dynamic")

        port_name, port_index = _resolve_port(bridge_port)

        try:
            await db.upsert_mac_entry(
                host_id=host_id, mac_address=mac, vlan=0,
                port_name=port_name, port_index=port_index,
                entry_type=status,
            )
            await db.record_mac_history(mac, host_id, port_name, vlan=0)
            result["macs_found"] += 1
        except Exception:
            pass

    # ── Process Q-BRIDGE VLAN-aware FDB (dot1qTpFdbTable) ──
    for oid, port_val in q_fdb_port.items():
        suffix = oid[len(DOT1Q_TP_FDB_PORT):].lstrip(".")
        parts = suffix.split(".")
        # Format: <vlan>.<mac_octet1>.<mac_octet2>...<mac_octet6>
        if len(parts) >= 7:
            try:
                vlan = int(parts[0])
            except (ValueError, TypeError):
                vlan = 0
            mac = _extract_mac_from_oid_suffix(".".join(parts[1:7]))
        else:
            vlan = 0
            mac = _extract_mac_from_oid_suffix(suffix)

        if not mac:
            continue

        bridge_port = str(port_val)
        port_name, port_index = _resolve_port(bridge_port)

        try:
            await db.upsert_mac_entry(
                host_id=host_id, mac_address=mac, vlan=vlan,
                port_name=port_name, port_index=port_index,
                entry_type="dynamic",
            )
            await db.record_mac_history(mac, host_id, port_name, vlan=vlan)
            result["macs_found"] += 1
        except Exception:
            pass

    # ── Process ARP table (ipNetToMediaTable) ──
    for oid, mac_val in arp_phys.items():
        suffix = oid[len(IP_NET_TO_MEDIA_PHYS):].lstrip(".")
        mac = _format_mac(mac_val)
        if not mac:
            continue

        # Extract IP: suffix format is <if_index>.<ip_a>.<ip_b>.<ip_c>.<ip_d>
        parts = suffix.split(".")
        if len(parts) >= 5:
            ip_addr = ".".join(parts[1:5])
            if_idx = parts[0]
        else:
            ip_addr = ""
            if_idx = ""

        iface_name = if_index_to_name.get(if_idx, "")
        type_oid = IP_NET_TO_MEDIA_TYPE + "." + suffix
        arp_type = ARP_TYPE_MAP.get(str(arp_type.get(type_oid, "")), "dynamic")

        try:
            await db.upsert_arp_entry(
                host_id=host_id, ip_address=ip_addr, mac_address=mac,
                interface_name=iface_name,
            )
            # Cross-reference: update MAC entry IP if we have it
            if ip_addr:
                mac_entries = await db.search_mac_tracking(mac)
                for entry in mac_entries:
                    if entry.get("host_id") == host_id and not entry.get("ip_address"):
                        await db.upsert_mac_entry(
                            host_id=host_id, mac_address=mac,
                            vlan=entry.get("vlan", 0),
                            port_name=entry.get("port_name", ""),
                            port_index=entry.get("port_index", 0),
                            ip_address=ip_addr,
                            entry_type=entry.get("entry_type", "dynamic"),
                        )
            result["arps_found"] += 1
        except Exception:
            pass

    LOGGER.info("mac_tracking: host %s (%s) — %d MACs, %d ARPs collected",
                host_id, ip_address, result["macs_found"], result["arps_found"])
    return result


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/mac-tracking/search")
async def search_mac(query: str = Query("", min_length=1), limit: int = Query(100, le=500)):
    """Search across MAC/ARP tables by MAC address, IP, or port name."""
    return await db.search_mac_tracking(query, limit)


@router.get("/api/mac-tracking/host/{host_id}")
async def get_host_mac_arp(host_id: int):
    """Get MAC and ARP tables for a specific device."""
    macs = await db.get_mac_table_for_host(host_id)
    arps = await db.get_arp_table_for_host(host_id)
    return {"mac_table": macs, "arp_table": arps}


@router.get("/api/mac-tracking/history/{mac_address:path}")
async def get_mac_movement_history(mac_address: str, limit: int = Query(100, le=500)):
    """Get port movement history for a specific MAC address."""
    return await db.get_mac_history(mac_address, limit)


@router.get("/api/mac-tracking/port/{host_id}/{port_name:path}")
async def get_port_macs(host_id: int, port_name: str):
    """Get all MACs learned on a specific port."""
    return await db.get_macs_on_port(host_id, port_name)


@router.post("/api/mac-tracking/collect")
async def trigger_mac_collection(host_id: int | None = Query(None)):
    """Trigger immediate MAC/ARP collection.
    If host_id is provided, collect from that host only.
    Otherwise, collect from all hosts with SNMP enabled.
    """
    from netcontrol.routes.state import _resolve_snmp_discovery_config

    if host_id is not None:
        host = await db.get_host(host_id)
        if not host:
            raise HTTPException(404, "Host not found")
        snmp_cfg = _resolve_snmp_discovery_config(host.get("group_id"))
        if not snmp_cfg.get("enabled"):
            raise HTTPException(400, "SNMP not enabled for this host's group")
        result = await collect_mac_arp_tables(host_id, host["ip_address"], snmp_cfg)
        return result

    # Collect from all groups
    groups = await db.get_all_groups()
    total = {"macs_found": 0, "arps_found": 0, "hosts_collected": 0, "errors": []}
    sem = asyncio.Semaphore(4)

    for group in groups:
        snmp_cfg = _resolve_snmp_discovery_config(group["id"])
        if not snmp_cfg.get("enabled"):
            continue
        hosts = await db.get_hosts_for_group(group["id"])

        async def _collect_one(h, cfg):
            async with sem:
                return await collect_mac_arp_tables(h["id"], h["ip_address"], cfg)

        tasks = [asyncio.create_task(_collect_one(h, snmp_cfg)) for h in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for h, res in zip(hosts, results):
            if isinstance(res, Exception):
                total["errors"].append(f"{h.get('hostname', '?')}: {str(res)}")
                continue
            total["macs_found"] += res["macs_found"]
            total["arps_found"] += res["arps_found"]
            total["hosts_collected"] += 1

    return total


@router.post("/api/mac-tracking/cleanup")
async def cleanup_stale_entries(days: int = Query(30, ge=1)):
    """Remove MAC entries not seen in the specified number of days."""
    removed = await db.cleanup_stale_mac_entries(days)
    return {"removed": removed}
