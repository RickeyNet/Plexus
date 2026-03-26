"""
snmp.py -- Shared SNMP infrastructure (no routes).

Provides pysnmp helpers, SNMP get/walk, CDP address parsing,
neighbor discovery, and vendor-OS inference used by inventory
and topology route modules.
"""

import asyncio
import re
import socket

from netcontrol.routes.state import _resolve_snmp_discovery_config  # noqa: F401
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.snmp")

# ── pysnmp imports (optional dependency) ─────────────────────────────────────

try:
    from pysnmp.hlapi.v3arch import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        walk_cmd,
    )
    PYSMNP_AVAILABLE = True
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    UsmUserData = None
    get_cmd = None
    walk_cmd = None
    usmAesCfb128Protocol = None
    usmAesCfb192Protocol = None
    usmAesCfb256Protocol = None
    usmDESPrivProtocol = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None
    usmHMAC192SHA256AuthProtocol = None
    usmHMAC384SHA512AuthProtocol = None
    PYSMNP_AVAILABLE = False


# ── Helpers ──────────────────────────────────────────────────────────────────


def _infer_vendor_os_from_text(raw_text: str) -> tuple[str, str, str]:
    lowered = (raw_text or "").lower()
    vendor = "unknown"
    detected_type = "unknown"
    os_name = "unknown"

    if "cisco" in lowered:
        vendor = "cisco"
        detected_type = "cisco_ios"
    elif "juniper" in lowered or "junos" in lowered:
        vendor = "juniper"
        detected_type = "juniper_junos"
    elif "arista" in lowered:
        vendor = "arista"
        detected_type = "arista_eos"
    elif "forti" in lowered:
        vendor = "fortinet"
        detected_type = "fortinet"

    if "ios" in lowered:
        os_name = "ios"
    elif "nx-os" in lowered or "nxos" in lowered:
        os_name = "nx-os"
    elif "junos" in lowered:
        os_name = "junos"
    elif "eos" in lowered:
        os_name = "eos"
    elif "fortios" in lowered:
        os_name = "fortios"

    return vendor, detected_type, os_name


def _parse_model_and_version(sys_descr: str) -> tuple[str, str]:
    """Extract hardware model and software version from an SNMP sysDescr string."""
    model = ""
    version = ""
    if not sys_descr:
        return model, version

    # Cisco IOS / IOS-XE: "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, ..."
    # Also handles: "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, ..."
    m = re.search(r"Version\s+([\d.()a-zA-Z]+)", sys_descr)
    if m:
        version = m.group(1)

    # Try to grab the model from the software image name in parens, e.g. "(C3750E-UNIVERSALK9-M)"
    m = re.search(r"\(([A-Z0-9][\w-]+)\)", sys_descr)
    if m:
        model = m.group(1)

    # Cisco NX-OS: "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 10.3(2), ..."
    if not model:
        m = re.search(r"Cisco\s+\S+\s+([\w-]+)", sys_descr)
        if m and m.group(1).lower() not in ("ios", "software", "nx-os(tm)"):
            model = m.group(1)

    # Juniper: "Juniper Networks, Inc. ex4300-48t ..."
    if "juniper" in sys_descr.lower():
        m = re.search(r"Juniper\s+Networks,?\s+Inc\.?\s+([\w-]+)", sys_descr, re.IGNORECASE)
        if m:
            model = m.group(1)
        m = re.search(r"JUNOS\s+([\d.A-Za-z-]+)", sys_descr)
        if m:
            version = m.group(1)

    # Arista: "Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050TX-64"
    if "arista" in sys_descr.lower():
        m = re.search(r"version\s+([\d.]+\w*)", sys_descr, re.IGNORECASE)
        if m:
            version = m.group(1)
        m = re.search(r"(DCS-[\w-]+)", sys_descr)
        if m:
            model = m.group(1)

    return model, version


# ── SNMP Get ─────────────────────────────────────────────────────────────────


async def _snmp_get(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    """Returns device info dict on success, None on no response, raises on auth/config errors."""
    if not PYSMNP_AVAILABLE:
        raise RuntimeError("pysnmp library is not available")
    assert (
        CommunityData is not None and ContextData is not None and ObjectIdentity is not None
        and ObjectType is not None and SnmpEngine is not None and UdpTransportTarget is not None
        and UsmUserData is not None and get_cmd is not None
        and usmAesCfb128Protocol is not None and usmAesCfb192Protocol is not None
        and usmAesCfb256Protocol is not None and usmDESPrivProtocol is not None
        and usmHMACMD5AuthProtocol is not None and usmHMACSHAAuthProtocol is not None
        and usmHMAC192SHA256AuthProtocol is not None and usmHMAC384SHA512AuthProtocol is not None
    )
    if not snmp_config.get("enabled", False):
        return None

    cfg = snmp_config
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = max(timeout_seconds, float(cfg.get("timeout_seconds", timeout_seconds)))

    auth_data = None
    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(str(v3.get("auth_protocol", "sha")).lower(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(str(v3.get("priv_protocol", "aes128")).lower(), usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                privKey=priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        else:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                authProtocol=auth_proto,
            )
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
    error_indication, error_status, _error_index, var_binds = await get_cmd(
        engine,
        auth_data,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
    )
    engine.close_dispatcher()
    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(f"SNMP error: {error_status.prettyPrint()}")

    values = {str(name): str(value) for name, value in var_binds}
    sys_descr = values.get("1.3.6.1.2.1.1.1.0", "")
    sys_name = values.get("1.3.6.1.2.1.1.5.0", "")

    # pysnmp returns special objects (NoSuchInstance, NoSuchObject, endOfMibView)
    # that str() converts to long descriptive strings — treat those as empty.
    if sys_name and any(m in sys_name.lower() for m in _SNMP_BAD_MARKERS):
        sys_name = ""
    if sys_descr and any(m in sys_descr.lower() for m in _SNMP_BAD_MARKERS):
        sys_descr = ""
    vendor, detected_type, os_name = _infer_vendor_os_from_text(sys_descr)
    hw_model, sw_version = _parse_model_and_version(sys_descr)
    return {
        "hostname": sys_name or f"snmp-{ip_address.replace('.', '-')}",
        "ip_address": ip_address,
        "device_type": detected_type,
        "status": "online",
        "model": hw_model,
        "software_version": sw_version,
        "discovery": {
            "protocol": f"snmpv{version}",
            "port": port,
            "vendor": vendor,
            "os": os_name,
            "sys_descr": sys_descr,
            "auth": "configured",
        },
    }


async def _probe_discovery_target_snmp(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    try:
        return await _snmp_get(ip_address, timeout_seconds, snmp_config)
    except Exception:
        return None


# ── SNMP Walk & Build Auth ───────────────────────────────────────────────────


def _build_snmp_auth(snmp_config: dict):
    """Build pysnmp auth_data from config dict. Returns (auth_data, version, port, timeout, retries) or None."""
    if not PYSMNP_AVAILABLE:
        return None
    cfg = snmp_config
    if not cfg.get("enabled", False):
        return None
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = float(cfg.get("timeout_seconds", 2.0))

    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol, "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol, "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol, "aes256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(str(v3.get("auth_protocol", "sha")).lower(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(str(v3.get("priv_protocol", "aes128")).lower(), usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(username, authKey=auth_password, privKey=priv_password,
                                    authProtocol=auth_proto, privProtocol=priv_proto)
        else:
            auth_data = UsmUserData(username, authKey=auth_password, authProtocol=auth_proto)
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    return auth_data, version, port, timeout, retries


async def _snmp_walk(ip_address: str, timeout_seconds: float, snmp_config: dict,
                     base_oid: str, max_rows: int = 500) -> dict[str, str]:
    """Walk an SNMP OID subtree and return {oid: value} dict."""
    auth_tuple = _build_snmp_auth(snmp_config)
    if auth_tuple is None:
        return {}
    auth_data, _version, port, timeout, retries = auth_tuple
    timeout = max(timeout, timeout_seconds)

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
    results: dict[str, str] = {}
    row_count = 0
    try:
        async for error_indication, error_status, _error_index, var_binds in walk_cmd(
            engine, auth_data, transport, ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for name, value in var_binds:
                oid_str = str(name)
                results[oid_str] = value
            row_count += 1
            if row_count >= max_rows:
                break
    finally:
        engine.close_dispatcher()
    return results


# ── CDP Address Parser ───────────────────────────────────────────────────────


_SNMP_BAD_MARKERS = ("no such instance", "no such object", "endofmibview")


def _snmp_str(raw_value) -> str:
    """Convert an SNMP value to a clean string, returning '' for pysnmp
    sentinel values (NoSuchInstance, NoSuchObject, endOfMibView)."""
    s = str(raw_value).strip()
    if s and any(m in s.lower() for m in _SNMP_BAD_MARKERS):
        return ""
    return s


def _parse_cdp_address(raw_value) -> str:
    """Convert CDP cdpCacheAddress (binary) to dotted IPv4 string."""
    try:
        raw_bytes = bytes(raw_value)
        if len(raw_bytes) == 4:
            return socket.inet_ntoa(raw_bytes)
        return raw_bytes.hex()
    except Exception:
        return str(raw_value)


# ── Neighbor Discovery ───────────────────────────────────────────────────────


async def _discover_neighbors(host_id: int, ip_address: str, snmp_config: dict,
                              timeout_seconds: float = 5.0) -> tuple[list[dict], list[dict]]:
    """Discover CDP/LLDP/OSPF/BGP neighbors and poll interface counters.

    Returns (neighbors_list, interface_stats_list).
    All independent SNMP walks run in parallel for speed.
    """
    neighbors: list[dict] = []
    def _walk(oid):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid)

    # ── Phase 1: Parallel walk of ALL OID groups ──
    # ifName / ifDescr (need ifName first, ifDescr as fallback)
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"
    if_descr_oid = "1.3.6.1.2.1.2.2.1.2"

    # Interface counters
    if_hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"          # ifHCInOctets (64-bit)
    if_hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"        # ifHCOutOctets (64-bit)
    if_in_octets_oid = "1.3.6.1.2.1.2.2.1.10"         # ifInOctets (32-bit fallback)
    if_out_octets_oid = "1.3.6.1.2.1.2.2.1.16"        # ifOutOctets (32-bit fallback)
    if_high_speed_oid = "1.3.6.1.2.1.31.1.1.1.15"     # ifHighSpeed (Mbps)
    if_speed_oid = "1.3.6.1.2.1.2.2.1.5"              # ifSpeed (bps)

    # CDP OIDs
    cdp_device_id_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    cdp_address_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
    cdp_port_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
    cdp_platform_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

    # LLDP OIDs
    lldp_sys_name_base = "1.0.8802.1.1.2.1.4.1.1.9"
    lldp_port_id_base = "1.0.8802.1.1.2.1.4.1.1.7"
    lldp_port_desc_base = "1.0.8802.1.1.2.1.4.1.1.8"
    lldp_sys_desc_base = "1.0.8802.1.1.2.1.4.1.1.10"
    lldp_man_addr_base = "1.0.8802.1.1.2.1.4.2.1.4"

    # OSPF OIDs
    ospf_nbr_rtr_id_base = "1.3.6.1.2.1.14.10.1.3"
    ospf_nbr_state_base = "1.3.6.1.2.1.14.10.1.6"

    # BGP OIDs
    bgp_peer_state_base = "1.3.6.1.2.1.15.3.1.2"
    bgp_peer_remote_as_base = "1.3.6.1.2.1.15.3.1.9"

    LOGGER.info("topology: starting parallel SNMP walks for %s (%s)", ip_address, host_id)

    # Fire ALL walks in parallel — one round-trip instead of 17 sequential ones
    (if_names, if_descr,
     hc_in, hc_out, lo_in, lo_out, high_speed_raw, speed_raw,
     cdp_device_ids, cdp_addresses, cdp_ports, cdp_platforms,
     lldp_names, lldp_port_ids, lldp_port_descs, lldp_sys_descs, lldp_man_addrs,
     ospf_rtr_ids, ospf_states,
     bgp_states, bgp_remote_as,
    ) = await asyncio.gather(
        _walk(if_name_oid), _walk(if_descr_oid),
        _walk(if_hc_in_oid), _walk(if_hc_out_oid),
        _walk(if_in_octets_oid), _walk(if_out_octets_oid),
        _walk(if_high_speed_oid), _walk(if_speed_oid),
        _walk(cdp_device_id_base), _walk(cdp_address_base),
        _walk(cdp_port_base), _walk(cdp_platform_base),
        _walk(lldp_sys_name_base), _walk(lldp_port_id_base),
        _walk(lldp_port_desc_base), _walk(lldp_sys_desc_base), _walk(lldp_man_addr_base),
        _walk(ospf_nbr_rtr_id_base), _walk(ospf_nbr_state_base),
        _walk(bgp_peer_state_base), _walk(bgp_peer_remote_as_base),
    )

    LOGGER.info("topology: SNMP walks complete for %s — CDP:%d LLDP:%d OSPF:%d BGP:%d ifStats:%d",
                ip_address, len(cdp_device_ids), len(lldp_names),
                len(ospf_rtr_ids), len(bgp_states), len(hc_in) or len(lo_in))

    # ── Build ifIndex -> interface name map ──
    effective_if_names = if_names or if_descr
    if_index_map: dict[str, str] = {}
    for oid, val in effective_if_names.items():
        parts = oid.rsplit(".", 1)
        if len(parts) == 2:
            if_index_map[parts[1]] = str(val)

    # ── Interface counter stats ──
    # Prefer 64-bit counters, fall back to 32-bit
    in_octets_raw = hc_in or lo_in
    out_octets_raw = hc_out or lo_out
    # Prefer ifHighSpeed (Mbps), fall back to ifSpeed (bps -> Mbps)
    if not high_speed_raw:
        effective_speed = speed_raw
    else:
        effective_speed = high_speed_raw

    if_stats: list[dict] = []
    all_if_indexes = set()
    for oid in list(in_octets_raw.keys()) + list(out_octets_raw.keys()):
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            all_if_indexes.add(idx)

    for idx in all_if_indexes:
        in_val = 0
        out_val = 0
        speed_mbps = 0
        for oid, val in in_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    in_val = int(val)
                except (ValueError, TypeError):
                    pass
                break
        for oid, val in out_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    out_val = int(val)
                except (ValueError, TypeError):
                    pass
                break
        for oid, val in effective_speed.items():
            if oid.endswith("." + idx):
                try:
                    raw_speed = int(val)
                    speed_mbps = raw_speed if high_speed_raw else raw_speed // 1_000_000
                except (ValueError, TypeError):
                    pass
                break

        if_stats.append({
            "host_id": host_id,
            "if_index": int(idx),
            "if_name": if_index_map.get(idx, f"ifIndex-{idx}"),
            "if_speed_mbps": speed_mbps,
            "in_octets": in_val,
            "out_octets": out_val,
        })

    # ── CDP Neighbor Parsing ──
    for oid, device_name_val in cdp_device_ids.items():
        suffix = oid[len(cdp_device_id_base):]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        if_index = parts[0] if parts else ""
        local_iface = if_index_map.get(if_index, f"ifIndex-{if_index}")

        remote_name = _snmp_str(device_name_val)
        if "(" in remote_name:
            remote_name = remote_name.split("(")[0].strip()

        addr_oid = cdp_address_base + suffix
        port_oid = cdp_port_base + suffix
        plat_oid = cdp_platform_base + suffix

        remote_ip = ""
        if addr_oid in cdp_addresses:
            remote_ip = _parse_cdp_address(cdp_addresses[addr_oid])

        remote_port = _snmp_str(cdp_ports.get(port_oid, ""))
        platform = _snmp_str(cdp_platforms.get(plat_oid, ""))

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": local_iface,
            "remote_device_name": remote_name,
            "remote_ip": remote_ip,
            "remote_interface": remote_port,
            "protocol": "cdp",
            "remote_platform": platform,
        })

    # ── LLDP Neighbor Parsing ──
    lldp_addr_map: dict[str, str] = {}
    for oid, val in lldp_man_addrs.items():
        suffix = oid[len(lldp_man_addr_base):]
        parts = suffix.lstrip(".").split(".")
        if len(parts) >= 3:
            key = f"{parts[0]}.{parts[1]}.{parts[2]}"
            try:
                raw = bytes(val)
                if len(raw) == 4:
                    lldp_addr_map[key] = socket.inet_ntoa(raw)
            except Exception:
                pass

    for oid, sys_name_val in lldp_names.items():
        suffix = oid[len(lldp_sys_name_base):]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        local_port_num = parts[1] if len(parts) >= 2 else ""
        lldp_key = ".".join(parts[:3]) if len(parts) >= 3 else suffix.lstrip(".")

        local_iface = if_index_map.get(local_port_num, f"port-{local_port_num}")
        remote_name = _snmp_str(sys_name_val)

        port_id_oid = lldp_port_id_base + suffix
        port_desc_oid = lldp_port_desc_base + suffix
        sys_desc_oid = lldp_sys_desc_base + suffix

        remote_port_raw = _snmp_str(lldp_port_ids.get(port_id_oid, ""))
        remote_port_desc = _snmp_str(lldp_port_descs.get(port_desc_oid, ""))
        remote_port = remote_port_desc or remote_port_raw

        sys_desc = _snmp_str(lldp_sys_descs.get(sys_desc_oid, ""))
        remote_ip = lldp_addr_map.get(lldp_key, "")

        already_found = any(
            n["remote_device_name"].lower() == remote_name.lower()
            and n["local_interface"] == local_iface
            for n in neighbors
        )
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": local_iface,
            "remote_device_name": remote_name or f"lldp-{remote_port_raw}",
            "remote_ip": remote_ip,
            "remote_interface": remote_port,
            "protocol": "lldp",
            "remote_platform": sys_desc[:200] if sys_desc else "",
        })

    # ── OSPF Neighbor Parsing ──
    for oid, rtr_id_val in ospf_rtr_ids.items():
        suffix = oid[len(ospf_nbr_rtr_id_base):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            nbr_ip = ".".join(parts[:4])
        else:
            continue

        rtr_id = _snmp_str(rtr_id_val)
        state_oid = ospf_nbr_state_base + "." + suffix
        state_val = _snmp_str(ospf_states.get(state_oid, ""))

        already_found = any(n["remote_ip"] == nbr_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": "",
            "remote_device_name": rtr_id or nbr_ip,
            "remote_ip": nbr_ip,
            "remote_interface": "",
            "protocol": "ospf",
            "remote_platform": f"OSPF state={state_val}" if state_val else "",
        })

    # ── BGP Peer Parsing ──
    for oid, state_val in bgp_states.items():
        suffix = oid[len(bgp_peer_state_base):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            peer_ip = ".".join(parts[:4])
        else:
            continue

        as_oid = bgp_peer_remote_as_base + "." + suffix
        remote_as = _snmp_str(bgp_remote_as.get(as_oid, ""))

        already_found = any(n["remote_ip"] == peer_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append({
            "source_host_id": host_id,
            "source_ip": ip_address,
            "local_interface": "",
            "remote_device_name": f"AS{remote_as}" if remote_as else peer_ip,
            "remote_ip": peer_ip,
            "remote_interface": "",
            "protocol": "bgp",
            "remote_platform": f"AS {remote_as}, state={state_val}" if remote_as else "",
        })

    return neighbors, if_stats
