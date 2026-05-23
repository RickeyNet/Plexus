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
from netcontrol.routes.snmp import _build_snmp_auth, _snmp_str, _snmp_walk
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

# Per-port VLAN membership (used to tag MACs without per-VLAN context walks)
VM_VLAN_OID = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"          # Cisco vmVlan (access port VLAN), indexed by ifIndex
DOT1Q_PVID_OID = "1.3.6.1.2.1.17.7.1.4.5.1.1"         # dot1qPvid, indexed by dot1dBasePort

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
                                  timeout_seconds: float = 5.0,
                                  device_type: str = "") -> dict:
    """Walk MAC and ARP tables from a device via SNMP.

    Per-port VLAN membership (Cisco vmVlan / standard dot1qPvid) is walked in
    the default SNMP context. Q-BRIDGE entries that carry the VLAN in their
    OID are honoured directly; the rest fall back to the learning port's
    VLAN from that map.

    On Cisco IOS/IOS-XE the default-context FDB walk only returns VLAN 1
    entries — every other VLAN's FDB is exposed under SNMPv3 context
    ``vlan-<id>``. When ``device_type`` indicates a Cisco platform and SNMPv3
    is in use, this function discovers the in-use VLAN list from the access
    port map and re-walks the FDB once per VLAN with the matching context
    name. Walks that fail (operator not authorised for a given VLAN view,
    VLAN administratively suspended, etc.) are recorded but don't abort the
    rest. The fallback to the default-context FDB walk is kept for non-Cisco
    devices and for the rare case where no VLANs are discoverable.

    Returns {"macs_found": int, "arps_found": int, "errors": [str]}.
    """
    result = {"macs_found": 0, "arps_found": 0, "errors": []}

    def _walk(oid: str, max_rows: int = 2000):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows=max_rows)

    def _walk_with_errors(oid: str, max_rows: int = 2000):
        return _snmp_walk(
            ip_address, timeout_seconds, snmp_config, oid,
            max_rows=max_rows, return_errors=True,
        )

    # ── Single global pass: everything lives in the default context ──
    # The "critical" OIDs (FDB tables + ARP) ask for error-aware results so
    # we can tell silent-but-responsive devices from outright SNMP failures.
    # The supporting OIDs (vlan map, ifName, etc.) stay in the plain mode —
    # they're allowed to be empty without it counting as a failure.
    try:
        (arp_phys_pair,
         arp_net, arp_type_rows,
         if_names, vm_vlan, dot1q_pvid,
         fdb_addr_pair, fdb_port, fdb_status, q_fdb_port_pair, bridge_port_map,
        ) = await asyncio.gather(
            _walk_with_errors(IP_NET_TO_MEDIA_PHYS),
            _walk(IP_NET_TO_MEDIA_NET),
            _walk(IP_NET_TO_MEDIA_TYPE),
            _walk(IF_NAME_OID),
            _walk(VM_VLAN_OID),
            _walk(DOT1Q_PVID_OID),
            _walk_with_errors(DOT1D_TP_FDB_ADDRESS),
            _walk(DOT1D_TP_FDB_PORT),
            _walk(DOT1D_TP_FDB_STATUS),
            _walk_with_errors(DOT1Q_TP_FDB_PORT),
            _walk(DOT1D_BASE_PORT_IF_INDEX),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed: {str(exc)}")
        return result

    arp_phys, arp_phys_err = arp_phys_pair
    fdb_addr, fdb_addr_err = fdb_addr_pair
    q_fdb_port, q_fdb_port_err = q_fdb_port_pair

    # Record critical-walk errors verbatim. If *both* FDB walks failed with
    # the same error (almost always: timeout / auth fail / closed port), say
    # it once instead of three times.
    fdb_errors = {e for e in (fdb_addr_err, q_fdb_port_err) if e}
    if fdb_errors:
        if len(fdb_errors) == 1:
            result["errors"].append(f"FDB walk failed: {next(iter(fdb_errors))}")
        else:
            for tag, err in (("dot1dTpFdb", fdb_addr_err),
                              ("dot1qTpFdb", q_fdb_port_err)):
                if err:
                    result["errors"].append(f"{tag} walk failed: {err}")
    if arp_phys_err:
        result["errors"].append(f"ARP walk failed: {arp_phys_err}")

    # NB: the "device responded but returned no FDB entries" advisory used to
    # live here, but on Cisco the default-context walk is *expected* to be
    # near-empty — the real FDB lives in per-VLAN contexts and is collected
    # below. The advisory now runs after the per-VLAN merge so it only fires
    # when the merged result is genuinely empty.

    if_index_to_name: dict[str, str] = {}
    for oid, val in if_names.items():
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            if_index_to_name[idx] = _snmp_str(val)

    bp_to_if_index: dict[str, str] = {}
    for oid, val in bridge_port_map.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if bp:
            bp_to_if_index[bp] = str(val).strip()

    # ── Build if_index → vlan map ──
    # vmVlan (Cisco) is indexed directly by ifIndex; dot1qPvid is indexed by
    # dot1dBasePort and needs translating. vmVlan wins when both are present
    # because trunk ports report a vacuous PVID that would mislabel learned
    # MACs.
    if_index_to_vlan: dict[str, int] = {}
    for oid, val in dot1q_pvid.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if_idx = bp_to_if_index.get(bp)
        if not if_idx:
            continue
        try:
            vid = int(str(val).strip())
        except (ValueError, TypeError):
            continue
        if 1 <= vid <= 4094:
            if_index_to_vlan[if_idx] = vid
    for oid, val in vm_vlan.items():
        if_idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if not if_idx:
            continue
        try:
            vid = int(str(val).strip())
        except (ValueError, TypeError):
            continue
        if 1 <= vid <= 4094:
            if_index_to_vlan[if_idx] = vid

    def _resolve_port(bridge_port: str) -> tuple[str, int, int]:
        if_idx = bp_to_if_index.get(bridge_port, bridge_port)
        port_name = if_index_to_name.get(if_idx, f"port-{bridge_port}")
        try:
            port_index = int(if_idx)
        except (ValueError, TypeError):
            port_index = 0
        port_vlan = if_index_to_vlan.get(if_idx, 0)
        return port_name, port_index, port_vlan

    # ── Cisco SNMPv3 per-VLAN FDB walks ────────────────────────────────
    # The default-context FDB only returns VLAN 1 on IOS/IOS-XE, so without
    # this re-walk we'd see uplink-only MACs (exactly the symptom that
    # prompted this code path). Per-VLAN context is a Cisco-specific trick;
    # other vendors put VLAN-in-OID into the default-context dot1qTpFdbTable
    # already, so we skip them.
    version = str(snmp_config.get("version", "")).strip().lower()
    is_cisco = device_type.lower().startswith("cisco")
    vlans_in_use = sorted({v for v in if_index_to_vlan.values() if 1 <= v <= 4094})
    per_vlan_errors: list[str] = []
    per_vlan_attempts = 0
    per_vlan_successes = 0
    # Maps MAC → VLAN learnt during per-VLAN context walks. Used to tag
    # dot1dTpFdb entries (which carry no VLAN in their OID) with the right
    # VLAN when the Q-BRIDGE walk didn't already cover that MAC.
    dot1d_mac_context_vlan: dict[str, int] = {}
    if is_cisco and version in ("v3", "3") and vlans_in_use:
        # Walk each VLAN context sequentially. Hosts are already collected in
        # parallel at the outer layer; piling more parallelism on a single
        # Catalyst CPU has been observed to cause SNMP timeouts.
        for vid in vlans_in_use:
            per_vlan_attempts += 1
            ctx_cfg = dict(snmp_config)
            ctx_cfg["snmp_context"] = f"vlan-{vid}"
            try:
                q_rows, q_err = await _snmp_walk(
                    ip_address, timeout_seconds, ctx_cfg, DOT1Q_TP_FDB_PORT,
                    max_rows=2000, return_errors=True,
                )
                d_addr_rows, d_addr_err = await _snmp_walk(
                    ip_address, timeout_seconds, ctx_cfg, DOT1D_TP_FDB_ADDRESS,
                    max_rows=2000, return_errors=True,
                )
                d_port_rows = await _snmp_walk(
                    ip_address, timeout_seconds, ctx_cfg, DOT1D_TP_FDB_PORT,
                    max_rows=2000,
                )
                d_status_rows = await _snmp_walk(
                    ip_address, timeout_seconds, ctx_cfg, DOT1D_TP_FDB_STATUS,
                    max_rows=2000,
                )
            except Exception as exc:
                per_vlan_errors.append(f"vlan-{vid}: {type(exc).__name__}: {exc}")
                continue
            # An auth/timeout error on one VLAN context is recorded but
            # doesn't poison the run — the operator's v3 user may simply
            # lack a view on that VLAN.
            ctx_err = q_err or d_addr_err
            if ctx_err and not q_rows and not d_addr_rows:
                per_vlan_errors.append(f"vlan-{vid}: {ctx_err}")
                continue
            if q_rows or d_addr_rows:
                per_vlan_successes += 1
            # Merge into the dicts the downstream parsers already read from.
            # The dot1qTpFdbPort OID encodes the VLAN in its OID suffix, so
            # entries from different VLAN contexts coexist without colliding.
            # dot1dTpFdb* entries are bridge-scoped (no VLAN in OID), so we
            # remember which VLAN context produced each MAC so the parser
            # below can tag it with that VLAN instead of the port's PVID.
            q_fdb_port.update(q_rows)
            fdb_addr.update(d_addr_rows)
            fdb_port.update(d_port_rows)
            fdb_status.update(d_status_rows)
            for oid, mac_val in d_addr_rows.items():
                mac = _format_mac(mac_val)
                if not mac or len(mac) < 12:
                    suffix = oid[len(DOT1D_TP_FDB_ADDRESS):].lstrip(".")
                    mac = _extract_mac_from_oid_suffix(suffix)
                if mac:
                    dot1d_mac_context_vlan[mac] = vid
        if per_vlan_attempts and per_vlan_successes == 0:
            # Every VLAN context failed — the device is reachable (we got the
            # vmVlan map) but the operator can't see any FDB view. That's a
            # configuration problem on the device, surface it loudly.
            result["errors"].append(
                f"All {per_vlan_attempts} per-VLAN FDB walks failed "
                f"(SNMPv3 user likely lacks 'snmp-server group ... read' on the per-VLAN views)."
            )
        elif per_vlan_errors:
            # Some succeeded, some didn't — informational rather than fatal.
            # Cap the list so we don't dump 50 lines for a chatty device.
            preview = "; ".join(per_vlan_errors[:5])
            suffix = f" (+{len(per_vlan_errors) - 5} more)" if len(per_vlan_errors) > 5 else ""
            result["errors"].append(
                f"Per-VLAN FDB walks partially failed: {preview}{suffix}"
            )

    # Track (mac, vlan) we've already upserted this run so the standard FDB
    # walk doesn't double-count entries the Q-BRIDGE walk already recorded.
    seen_mac_vlan: set[tuple[str, int]] = set()

    # Final empty-FDB advisory — runs once the default-context AND any
    # per-VLAN context walks have all completed. Only fires when we got no
    # protocol errors but still have nothing to parse: that's the genuine
    # "this device isn't a bridge" case worth telling the operator about.
    if not fdb_errors and not per_vlan_errors and not fdb_addr and not q_fdb_port:
        result["errors"].append(
            "Device responded but returned no FDB entries "
            "(likely a router / L3-only device, or FDB hidden behind a non-default SNMPv3 context)."
        )

    # ── Q-BRIDGE VLAN-aware FDB (dot1qTpFdbTable) - has VLAN in OID ──
    # When the device populates this table (most modern bridges do via the
    # default context), the VLAN comes straight from the OID and is correct
    # for both access and trunk traffic.
    for oid, port_val in q_fdb_port.items():
        suffix = oid[len(DOT1Q_TP_FDB_PORT):].lstrip(".")
        parts = suffix.split(".")
        bridge_port = str(port_val)
        port_name, port_index, port_vlan = _resolve_port(bridge_port)

        if len(parts) >= 7:
            try:
                vlan = int(parts[0])
            except (ValueError, TypeError):
                vlan = port_vlan
            mac = _extract_mac_from_oid_suffix(".".join(parts[1:7]))
        else:
            vlan = port_vlan
            mac = _extract_mac_from_oid_suffix(suffix)

        if not mac:
            continue

        try:
            await db.upsert_mac_entry(
                host_id=host_id, mac_address=mac, vlan=vlan,
                port_name=port_name, port_index=port_index,
                entry_type="dynamic",
            )
            # record_mac_history is change-detecting: it only writes a history
            # row + opens a mac_move_event when the MAC's switch/port/vlan/ip
            # actually changed, so calling it every poll is safe.
            await db.record_mac_history(mac, host_id, port_name, vlan=vlan)
            seen_mac_vlan.add((mac, vlan))
            result["macs_found"] += 1
        except Exception:
            pass

    # ── Standard bridge FDB (dot1dTpFdbTable) - no VLAN in OID ──
    # On Cisco we walked this per-VLAN context, so prefer the context-recorded
    # VLAN; that's the authoritative source. Otherwise fall back to the
    # learning port's PVID — incorrect for trunks but it's all we have.
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

        port_name, port_index, port_vlan = _resolve_port(bridge_port)
        vlan_for_mac = dot1d_mac_context_vlan.get(mac, port_vlan)
        if (mac, vlan_for_mac) in seen_mac_vlan:
            continue

        try:
            await db.upsert_mac_entry(
                host_id=host_id, mac_address=mac, vlan=vlan_for_mac,
                port_name=port_name, port_index=port_index,
                entry_type=status,
            )
            await db.record_mac_history(mac, host_id, port_name, vlan=vlan_for_mac)
            seen_mac_vlan.add((mac, vlan_for_mac))
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
        "mac_tracking: host %s (%s) ports=%d port_vlans=%d vlan_ctx=%d/%d - %d MACs, %d ARPs collected",
        host_id, ip_address, len(if_index_to_name), len(if_index_to_vlan),
        per_vlan_successes, per_vlan_attempts,
        result["macs_found"], result["arps_found"],
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Interface inventory + VLAN definitions (audit collector)
# ═════════════════════════════════════════════════════════════════════════════
#
# Walks the standard IF-MIB + VTP MIB to feed the audit subsystem's
# port-hygiene and VLAN-consistency rules. Folded into the mac_tracking
# module (and called from the same topology-discovery hot path) so we
# don't spin up another background loop just for these tables. The OIDs
# are read-only and the writes go through the normal sqlite upsert path,
# so calling it every discovery cycle is cheap and idempotent.

# IF-MIB OIDs reused for the inventory snapshot
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"               # ifDescr (fallback name)
IF_ALIAS_OID = "1.3.6.1.2.1.31.1.1.1.18"           # ifAlias (description)
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"         # 1=up 2=down 3=testing
IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"          # 1=up 2=down ...
IF_HIGH_SPEED_OID = "1.3.6.1.2.1.31.1.1.1.15"       # Mbps
IF_SPEED_OID = "1.3.6.1.2.1.2.2.1.5"                # bps fallback
IF_LAST_CHANGE_OID = "1.3.6.1.2.1.2.2.1.9"          # sysUptime ticks at last admin/oper transition
DOT3_STATS_DUPLEX_OID = "1.3.6.1.2.1.10.7.2.1.19"   # 1=unknown 2=half 3=full

# Cisco VTP VLAN names (state.id under vtpVlanTable)
VTP_VLAN_NAME_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"   # vtpVlanName
VTP_VLAN_STATE_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # vtpVlanState (1=operational ...)

# Cisco VTP trunk allowed-VLAN bitmaps (1k/2k/3k/4k slices, 128 bytes each)
VTP_TRUNK_VLANS_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.4"      # vlans 0..1023
VTP_TRUNK_VLANS_2K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.17"   # 1024..2047
VTP_TRUNK_VLANS_3K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.18"   # 2048..3071
VTP_TRUNK_VLANS_4K_OID = "1.3.6.1.4.1.9.9.46.1.6.1.1.19"   # 3072..4094

ADMIN_STATE_MAP = {"1": "up", "2": "down", "3": "testing"}
OPER_STATE_MAP = {
    "1": "up", "2": "down", "3": "testing", "4": "unknown",
    "5": "dormant", "6": "notPresent", "7": "lowerLayerDown",
}
DUPLEX_MAP = {"1": "unknown", "2": "half", "3": "full"}
VTP_STATE_MAP = {"1": "operational", "2": "suspended"}


def _bitmap_to_vlan_list(raw_value, base_vlan: int) -> list[int]:
    """Convert a VTP allowed-VLAN bitmap octet string into a list of VLAN IDs.

    The bitmap is big-endian: byte 0 bit 7 represents ``base_vlan + 0``, byte 0
    bit 6 ``base_vlan + 1`` and so on. Unknown/short bitmaps return [].
    """
    try:
        raw_bytes = bytes(raw_value)
    except Exception:
        return []
    vlans: list[int] = []
    for byte_idx, byte_val in enumerate(raw_bytes):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                vid = base_vlan + (byte_idx * 8) + bit_idx
                if 1 <= vid <= 4094:
                    vlans.append(vid)
    return vlans


def _format_ticks_to_iso_offset(ticks_raw) -> str:
    """ifLastChange is reported as TimeTicks since sysUpTime. Without the
    device's current sysUpTime + boot timestamp we can't convert to an
    absolute datetime here -- callers store the raw tick value and the
    audit rule does the relative-age math against a freshly walked
    sysUpTime. So we just normalise to a clean string."""
    try:
        return str(int(str(ticks_raw).strip()))
    except (ValueError, TypeError):
        return ""


async def collect_interface_inventory(host_id: int, ip_address: str,
                                       snmp_config: dict,
                                       timeout_seconds: float = 5.0) -> dict:
    """Walk per-port + VLAN-definition data for a single host.

    Writes to ``interface_inventory`` (one row per ifIndex) and
    ``vlan_definitions`` (one row per VLAN). Returns counts.
    """
    result = {"ports_written": 0, "vlans_written": 0, "errors": []}

    def _walk(oid: str, max_rows: int = 2500):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows=max_rows)

    try:
        (if_names, if_descr, if_alias,
         admin_status, oper_status,
         high_speed, low_speed, last_change, duplex,
         vm_vlan, dot1q_pvid, bridge_port_map,
         vtp_names, vtp_states,
         trunk_vlans_1k, trunk_vlans_2k, trunk_vlans_3k, trunk_vlans_4k,
        ) = await asyncio.gather(
            _walk(IF_NAME_OID), _walk(IF_DESCR_OID), _walk(IF_ALIAS_OID),
            _walk(IF_ADMIN_STATUS_OID), _walk(IF_OPER_STATUS_OID),
            _walk(IF_HIGH_SPEED_OID), _walk(IF_SPEED_OID),
            _walk(IF_LAST_CHANGE_OID), _walk(DOT3_STATS_DUPLEX_OID),
            _walk(VM_VLAN_OID), _walk(DOT1Q_PVID_OID), _walk(DOT1D_BASE_PORT_IF_INDEX),
            _walk(VTP_VLAN_NAME_OID), _walk(VTP_VLAN_STATE_OID),
            _walk(VTP_TRUNK_VLANS_OID), _walk(VTP_TRUNK_VLANS_2K_OID),
            _walk(VTP_TRUNK_VLANS_3K_OID), _walk(VTP_TRUNK_VLANS_4K_OID),
        )
    except Exception as exc:
        result["errors"].append(f"SNMP walk failed: {str(exc)}")
        return result

    # ── Build ifIndex-keyed lookups ────────────────────────────────────
    def _idx_map(walk: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for oid, val in walk.items():
            idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
            if idx:
                out[idx] = _snmp_str(val)
        return out

    name_by_idx = _idx_map(if_names) or _idx_map(if_descr)
    descr_by_idx = _idx_map(if_descr)
    alias_by_idx = _idx_map(if_alias)
    admin_by_idx = _idx_map(admin_status)
    oper_by_idx = _idx_map(oper_status)
    hi_speed_by_idx = _idx_map(high_speed)
    lo_speed_by_idx = _idx_map(low_speed)
    last_change_by_idx = _idx_map(last_change)
    duplex_by_idx = _idx_map(duplex)
    vm_vlan_by_idx = _idx_map(vm_vlan)

    # dot1qPvid is indexed by dot1dBasePort -> translate to ifIndex
    bp_to_if_index: dict[str, str] = {}
    for oid, val in bridge_port_map.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if bp:
            bp_to_if_index[bp] = str(val).strip()

    pvid_by_if_index: dict[str, str] = {}
    for oid, val in dot1q_pvid.items():
        bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if_idx = bp_to_if_index.get(bp)
        if if_idx:
            pvid_by_if_index[if_idx] = str(val).strip()

    # Trunk allowed-VLAN bitmaps: indexed by ifIndex. Stored as a comma-
    # delimited string for the audit rule -- compact and easy to diff.
    def _trunk_vlans_for_idx(if_idx: str) -> str:
        vlans: list[int] = []
        for walk, base in (
            (trunk_vlans_1k, 0),
            (trunk_vlans_2k, 1024),
            (trunk_vlans_3k, 2048),
            (trunk_vlans_4k, 3072),
        ):
            raw = None
            for oid, val in walk.items():
                if oid.rsplit(".", 1)[-1] == if_idx:
                    raw = val
                    break
            if raw is not None:
                vlans.extend(_bitmap_to_vlan_list(raw, base))
        # Deduplicate + sort. Trunk bitmaps frequently span all four
        # slices for fully-open trunks; keeping order stable makes diffs
        # of the inventory row readable.
        return ",".join(str(v) for v in sorted(set(vlans))) if vlans else ""

    # ── Resolve speed (Mbps) per ifIndex ──
    def _speed_mbps(if_idx: str) -> int:
        s = hi_speed_by_idx.get(if_idx, "")
        if s:
            try:
                return int(s)
            except (ValueError, TypeError):
                pass
        s2 = lo_speed_by_idx.get(if_idx, "")
        if s2:
            try:
                return max(0, int(s2) // 1_000_000)
            except (ValueError, TypeError):
                pass
        return 0

    # ── Decide which VLAN to report for an access port ──
    def _access_vlan(if_idx: str) -> int:
        # vmVlan (Cisco) wins; dot1qPvid is a fallback. Trunks report a
        # vacuous PVID that we want to ignore, so an empty access_vlan
        # here is correct for them and the trunk_vlans column carries
        # the real info.
        for src in (vm_vlan_by_idx.get(if_idx, ""),
                    pvid_by_if_index.get(if_idx, "")):
            try:
                vid = int(src)
            except (ValueError, TypeError):
                continue
            if 1 <= vid <= 4094:
                return vid
        return 0

    # ── Write port rows ──
    all_if_indexes = set(name_by_idx) | set(admin_by_idx) | set(oper_by_idx)
    for if_idx in all_if_indexes:
        try:
            ifindex_int = int(if_idx)
        except (ValueError, TypeError):
            continue
        name = name_by_idx.get(if_idx) or descr_by_idx.get(if_idx) or f"ifIndex-{if_idx}"
        try:
            await db.upsert_interface_inventory(
                host_id=host_id,
                if_index=ifindex_int,
                name=name,
                description=alias_by_idx.get(if_idx, ""),
                admin_state=ADMIN_STATE_MAP.get(admin_by_idx.get(if_idx, ""), ""),
                oper_state=OPER_STATE_MAP.get(oper_by_idx.get(if_idx, ""), ""),
                speed_mbps=_speed_mbps(if_idx),
                duplex=DUPLEX_MAP.get(duplex_by_idx.get(if_idx, ""), ""),
                last_change=_format_ticks_to_iso_offset(last_change_by_idx.get(if_idx, "")),
                access_vlan=_access_vlan(if_idx),
                trunk_vlans=_trunk_vlans_for_idx(if_idx),
            )
            result["ports_written"] += 1
        except Exception:
            pass

    # ── Write VLAN definitions ──
    # vtpVlanName is indexed by <management-domain>.<vlan-id>; the trailing
    # numeric is the VLAN id. State map: 1=operational, 2=suspended, ...
    vlan_state_by_id: dict[int, str] = {}
    for oid, val in vtp_states.items():
        suffix = oid.rsplit(".", 1)[-1]
        try:
            vid = int(suffix)
        except (ValueError, TypeError):
            continue
        vlan_state_by_id[vid] = VTP_STATE_MAP.get(str(val).strip(), str(val).strip())

    for oid, val in vtp_names.items():
        suffix = oid.rsplit(".", 1)[-1]
        try:
            vid = int(suffix)
        except (ValueError, TypeError):
            continue
        if not (1 <= vid <= 4094):
            continue
        try:
            await db.upsert_vlan_definition(
                host_id=host_id,
                vlan_id=vid,
                name=_snmp_str(val),
                state=vlan_state_by_id.get(vid, "operational"),
            )
            result["vlans_written"] += 1
        except Exception:
            pass

    LOGGER.info(
        "interface_inventory: host %s (%s) - %d ports, %d VLANs collected",
        host_id, ip_address, result["ports_written"], result["vlans_written"],
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


@router.get("/api/mac-tracking/stats")
async def mac_tracking_stats():
    """Header counts: total rows, unique MACs, switches reporting, freshness."""
    return await db.get_mac_tracking_stats()


@router.get("/api/mac-tracking/by-host")
async def mac_tracking_by_host():
    """Per-host collection rollup. Silent hosts (mac_count == 0) sort first.

    Each row is enriched with ``snmp_enabled`` resolved from the host's group
    so the UI can tell the difference between "host has no SNMP configured"
    and "host has SNMP configured but isn't returning FDB rows" — those are
    very different debugging paths.
    """
    from netcontrol.routes.state import _resolve_snmp_discovery_config

    rows = await db.get_mac_collection_by_host()
    # Cache the SNMP-enabled decision per group_id so we don't re-resolve for
    # every host in the same group.
    snmp_by_group: dict[int | None, bool] = {}
    for row in rows:
        gid = row.get("group_id")
        if gid not in snmp_by_group:
            try:
                cfg = _resolve_snmp_discovery_config(gid)
                snmp_by_group[gid] = bool(cfg.get("enabled"))
            except Exception:
                snmp_by_group[gid] = False
        row["snmp_enabled"] = snmp_by_group[gid]
    return rows


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
        result = await collect_mac_arp_tables(
            host_id, host["ip_address"], snmp_cfg,
            device_type=host.get("device_type", ""),
        )
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
                return await collect_mac_arp_tables(
                    h["id"], h["ip_address"], cfg,
                    device_type=h.get("device_type", ""),
                )

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
