"""
mac_tracking.py -- MacTrack-style MAC/ARP/port tracking

Provides:
  - SNMP-based MAC address table collection (dot1dTpFdbTable, dot1qTpFdbTable)
  - SNMP-based ARP table collection (ipNetToMediaTable)
  - MAC/ARP search and history API endpoints
  - Background collection loop integration
"""
from __future__ import annotations


import asyncio
import json
import socket

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.shared import _get_session
from netcontrol.routes.snmp import _build_snmp_auth, _snmp_walk, _snmp_str
from netcontrol.routes.topology import _discover_vlan_ids_for_host, _snmp_cfg_for_vlan
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

    Cisco IOS exposes the bridge/Q-BRIDGE FDB per-VLAN via community-string
    indexing (`<community>@<vlan_id>`). A single walk with the base community
    only returns VLAN 1 (or nothing on some releases), so we discover the
    device's VLANs and walk the FDB once per VLAN. ARP and ifName tables are
    global and only need a single walk.

    Returns {"macs_found": int, "arps_found": int, "errors": [str]}.
    """
    result = {"macs_found": 0, "arps_found": 0, "errors": []}

    def _walk_with(cfg: dict, oid: str, max_rows: int = 2000):
        return _snmp_walk(ip_address, timeout_seconds, cfg, oid, max_rows=max_rows)

    # ── Pass 1: global tables (ARP, ifName) using the base community ──
    try:
        (arp_phys, arp_net, arp_type_rows,
         if_names,
        ) = await asyncio.gather(
            _walk_with(snmp_config, IP_NET_TO_MEDIA_PHYS),
            _walk_with(snmp_config, IP_NET_TO_MEDIA_NET),
            _walk_with(snmp_config, IP_NET_TO_MEDIA_TYPE),
            _walk_with(snmp_config, IF_NAME_OID),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed (global): {str(exc)}")
        return result

    if_index_to_name: dict[str, str] = {}
    for oid, val in if_names.items():
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            if_index_to_name[idx] = _snmp_str(val)

    # ── Pass 2: discover candidate VLANs for per-VLAN FDB walks ──
    # Both v2c (community "<c>@<vlan>") and v3 (context "vlan-<id>") support
    # per-VLAN FDB polling on Cisco IOS/IOS-XE, so discover real VLANs in
    # either case. Only fall back to a single context-less walk when there's
    # no usable credential at all (which would otherwise tag every MAC VLAN 0).
    version = str(snmp_config.get("version", "2c")).strip().lower()
    community = str(snmp_config.get("community", "")).strip()
    has_credential = (version == "2c" and community) or version.startswith("3")
    if has_credential:
        try:
            vlan_ids = await _discover_vlan_ids_for_host(
                ip_address, snmp_config, timeout_seconds=timeout_seconds,
            )
        except Exception:
            vlan_ids = [1]
    else:
        vlan_ids = [0]

    if not vlan_ids:
        vlan_ids = [1]

    # ── Pass 3: per-VLAN FDB walks ──
    async def _collect_vlan_fdb(vid: int) -> dict:
        cfg = _snmp_cfg_for_vlan(snmp_config, vid) if vid > 0 else snmp_config
        try:
            fdb_addr, fdb_port, fdb_status, q_fdb_port, bridge_port_map = await asyncio.gather(
                _walk_with(cfg, DOT1D_TP_FDB_ADDRESS),
                _walk_with(cfg, DOT1D_TP_FDB_PORT),
                _walk_with(cfg, DOT1D_TP_FDB_STATUS),
                _walk_with(cfg, DOT1Q_TP_FDB_PORT),
                _walk_with(cfg, DOT1D_BASE_PORT_IF_INDEX),
            )
        except Exception as exc:
            return {"vlan": vid, "error": str(exc)}
        return {
            "vlan": vid,
            "fdb_addr": fdb_addr, "fdb_port": fdb_port, "fdb_status": fdb_status,
            "q_fdb_port": q_fdb_port, "bridge_port_map": bridge_port_map,
        }

    vlan_walks = await asyncio.gather(*[_collect_vlan_fdb(v) for v in vlan_ids])

    # Track (mac, vlan) we've already upserted this run so the standard FDB
    # walk doesn't double-count entries the Q-BRIDGE walk already recorded.
    seen_mac_vlan: set[tuple[str, int]] = set()

    for walk in vlan_walks:
        if "error" in walk:
            result["errors"].append(f"vlan {walk['vlan']}: {walk['error']}")
            continue

        vlan_ctx = int(walk["vlan"])
        fdb_addr = walk["fdb_addr"]
        fdb_port = walk["fdb_port"]
        fdb_status = walk["fdb_status"]
        q_fdb_port = walk["q_fdb_port"]
        bridge_port_map = walk["bridge_port_map"]

        bp_to_if_index: dict[str, str] = {}
        for oid, val in bridge_port_map.items():
            bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
            if bp:
                bp_to_if_index[bp] = str(val)

        def _resolve_port(bridge_port: str) -> tuple[str, int]:
            if_idx = bp_to_if_index.get(bridge_port, bridge_port)
            port_name = if_index_to_name.get(if_idx, f"port-{bridge_port}")
            try:
                return port_name, int(if_idx)
            except (ValueError, TypeError):
                return port_name, 0

        # ── Q-BRIDGE VLAN-aware FDB (dot1qTpFdbTable) - has VLAN in OID ──
        for oid, port_val in q_fdb_port.items():
            suffix = oid[len(DOT1Q_TP_FDB_PORT):].lstrip(".")
            parts = suffix.split(".")
            if len(parts) >= 7:
                try:
                    vlan = int(parts[0])
                except (ValueError, TypeError):
                    vlan = vlan_ctx
                mac = _extract_mac_from_oid_suffix(".".join(parts[1:7]))
            else:
                vlan = vlan_ctx
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
                # record_mac_history is now change-detecting: it only writes a
                # history row + opens a mac_move_event when the MAC's
                # switch/port/vlan/ip actually changed, so this is safe to call
                # every poll without flooding the history table.
                await db.record_mac_history(mac, host_id, port_name, vlan=vlan)
                seen_mac_vlan.add((mac, vlan))
                result["macs_found"] += 1
            except Exception:
                pass

        # ── Standard bridge FDB (dot1dTpFdbTable) - no VLAN in OID ──
        # Tag with vlan_ctx (the community-string VLAN we polled under).
        for oid, mac_val in fdb_addr.items():
            suffix = oid[len(DOT1D_TP_FDB_ADDRESS):].lstrip(".")
            mac = _format_mac(mac_val)
            if not mac or len(mac) < 12:
                mac = _extract_mac_from_oid_suffix(suffix)
            if not mac:
                continue

            if (mac, vlan_ctx) in seen_mac_vlan:
                continue

            port_oid = DOT1D_TP_FDB_PORT + "." + suffix
            status_oid = DOT1D_TP_FDB_STATUS + "." + suffix
            bridge_port = str(fdb_port.get(port_oid, "0"))
            status = FDB_STATUS_MAP.get(str(fdb_status.get(status_oid, "")), "dynamic")

            port_name, port_index = _resolve_port(bridge_port)

            try:
                await db.upsert_mac_entry(
                    host_id=host_id, mac_address=mac, vlan=vlan_ctx,
                    port_name=port_name, port_index=port_index,
                    entry_type=status,
                )
                await db.record_mac_history(mac, host_id, port_name, vlan=vlan_ctx)
                seen_mac_vlan.add((mac, vlan_ctx))
                result["macs_found"] += 1
            except Exception:
                pass

    # ── ARP table (global, ipNetToMediaTable) ──
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
        arp_type = ARP_TYPE_MAP.get(str(arp_type_rows.get(type_oid, "")), "dynamic")

        try:
            await db.upsert_arp_entry(
                host_id=host_id, ip_address=ip_addr, mac_address=mac,
                interface_name=iface_name,
            )
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

    LOGGER.info(
        "mac_tracking: host %s (%s) vlans=%s - %d MACs, %d ARPs collected",
        host_id, ip_address, vlan_ids,
        result["macs_found"], result["arps_found"],
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/mac-tracking/search")
async def search_mac(query: str = Query(""), limit: int = Query(5000, le=50000)):
    """Search across MAC/ARP tables by MAC address, IP, or port name.

    A blank query returns the most recently collected entries. The default
    limit is high enough to show the full table for typical deployments so
    the list doesn't silently truncate; the cap only guards pathological
    sizes.
    """
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
        result.setdefault("hosts_collected", 1)
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


# ═════════════════════════════════════════════════════════════════════════════
# MAC move events (drift-style change tracking)
# ═════════════════════════════════════════════════════════════════════════════


class MacMoveBulkAckRequest(BaseModel):
    event_ids: list[int] = []


@router.get("/api/mac-tracking/moves")
async def list_mac_move_events(
    status: str = Query("", pattern="^(open|acknowledged)?$"),
    host_id: int | None = Query(None),
    limit: int = Query(200, le=1000),
):
    """List MAC move events (newest first).

    Optionally filter by status, and by a switch "involved" in the move
    (matches either the from- or to-side host).
    """
    return await db.get_mac_move_events(status, limit, host_id=host_id)


@router.get("/api/mac-tracking/moves/summary")
async def mac_move_event_summary():
    """Open / acknowledged / total counts for the summary cards."""
    return await db.get_mac_move_event_summary()


@router.get("/api/mac-tracking/moves/{event_id}/history")
async def mac_move_event_history(event_id: int, limit: int = Query(500, le=1000)):
    """Lifecycle timeline (detected, acknowledged) for one move event."""
    return await db.get_mac_move_event_history(event_id, limit)


@router.post("/api/mac-tracking/moves/{event_id}/acknowledge")
async def acknowledge_mac_move_event(event_id: int, request: Request):
    """Acknowledge a single open move event."""
    session = _get_session(request)
    user = session["user"] if session else ""
    ok = await db.acknowledge_mac_move_event(event_id, actor=user)
    if not ok:
        raise HTTPException(404, "Move event not found")
    return {"ok": True}


@router.post("/api/mac-tracking/moves/acknowledge-all")
async def acknowledge_all_mac_move_events(
    body: MacMoveBulkAckRequest, request: Request
):
    """Acknowledge every open move event (or a specific list of ids)."""
    session = _get_session(request)
    user = session["user"] if session else ""
    if body.event_ids:
        acked = 0
        for eid in body.event_ids:
            if await db.acknowledge_mac_move_event(eid, actor=user):
                acked += 1
        return {"ok": True, "acknowledged": acked}
    acked = await db.acknowledge_open_mac_move_events(actor=user)
    return {"ok": True, "acknowledged": acked}


# ═════════════════════════════════════════════════════════════════════════════
# Scheduled retention
# ═════════════════════════════════════════════════════════════════════════════


async def _run_mac_move_retention_once() -> dict:
    """Prune MAC move events past the retention window."""
    days = int(state.MAC_MOVE_RETENTION_CONFIG.get(
        "event_retention_days",
        state.MAC_MOVE_RETENTION_DEFAULTS["event_retention_days"]))
    removed = 0
    try:
        removed = await db.delete_old_mac_move_events(days)
    except Exception as exc:
        LOGGER.warning("mac move retention failed: %s", exc)
    if removed:
        LOGGER.info("mac move retention: pruned %d events older than %d days",
                    removed, days)
    return {"removed": removed, "retention_days": days}


async def _mac_move_retention_loop() -> None:
    """Infinite loop that prunes old MAC move events at a fixed interval."""
    while True:
        try:
            await asyncio.sleep(int(state.MAC_MOVE_RETENTION_CONFIG.get(
                "interval_seconds",
                state.MAC_MOVE_RETENTION_DEFAULTS["interval_seconds"])))
            await _run_mac_move_retention_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("mac move retention loop failure: %s", exc)
            await asyncio.sleep(
                state.MAC_MOVE_RETENTION_DEFAULTS["interval_seconds"])
