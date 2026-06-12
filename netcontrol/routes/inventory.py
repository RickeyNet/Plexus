"""
inventory.py -- Inventory group/host CRUD, discovery, and SNMP profile routes.
"""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import socket
import uuid

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

import netcontrol.routes.state as state
from netcontrol.drivers import GenericDriver, get_driver
from netcontrol.routes import background_jobs
from netcontrol.routes.icmp import _probe_discovery_target_icmp
from netcontrol.routes.ipam_push import push_inventory_host_allocation
from netcontrol.routes.shared import _audit, _corr_id, _get_session, _run_show_command, require_credential_access
from netcontrol.routes.snmp import (
    PYSMNP_AVAILABLE,  # noqa: F401
    _collect_interface_ips,
    _discover_neighbors,  # noqa: F401
    _probe_discovery_target_snmp,
    _snmp_get,
    _snmp_walk,  # noqa: F401
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.inventory")

# Two routers: one for inventory-feature routes, one for admin routes
router = APIRouter()
admin_router = APIRouter()


async def _notify_flow_collector_host_changed(
    old_ip: str | None = None,
    new_ip: str | None = None,
    host_id: int | None = None,
) -> None:
    """Refresh the flow collector's in-memory exporter->host cache.

    Imported lazily to avoid a circular dependency at module load time and
    wrapped in a broad except so any inventory write that touches a host
    is never blocked by a flow-collector error.
    """
    try:
        from netcontrol.routes.flow_collector import on_host_changed
        await on_host_changed(old_ip=old_ip, new_ip=new_ip, host_id=host_id)
    except Exception as exc:
        LOGGER.debug("flow_collector cache refresh skipped: %s", type(exc).__name__)

# Reserved IP ranges that should not be added to inventory (mirrors jobs.py)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),           # "this" network
    ipaddress.ip_network("224.0.0.0/4"),         # multicast
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
]


def _validate_host_ip(ip_str: str) -> str:
    """Validate that a host IP is a valid unicast address not in reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip_str}")
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise HTTPException(400, f"IP address {ip_str} is in a reserved range and cannot be added to inventory")
    return ip_str


# ── Pydantic Models ──────────────────────────────────────────────────────────


class GroupCreate(BaseModel):
    name: str
    description: str = ""


class GroupUpdate(BaseModel):
    name: str
    description: str = ""

class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"
    vrf_name: str = ""
    vlan_id: str = ""

class HostUpdate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"
    vrf_name: str | None = None
    vlan_id: str | None = None
    # Optional - when present, the host is moved to the new group as part
    # of the update so renaming and re-grouping happen in one round-trip.
    group_id: int | None = None


class FetchSerialRequest(BaseModel):
    credential_id: int


class DiscoveryScanRequest(BaseModel):
    cidrs: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS, ge=0.05, le=5.0)
    max_hosts: int = Field(default=state.DISCOVERY_DEFAULT_MAX_HOSTS, ge=1, le=4096)
    device_type: str = "unknown"
    hostname_prefix: str = "discovered"
    use_snmp: bool = True
    use_icmp: bool = True

    model_config = ConfigDict(extra="forbid")


class DiscoverySyncRequest(DiscoveryScanRequest):
    remove_absent: bool = False


class DiscoveryOnboardRequest(BaseModel):
    discovered_hosts: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


# ── Discovery helpers ────────────────────────────────────────────────────────


def _expand_scan_targets(cidrs: list[str], max_hosts: int) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        # Reject absurdly large subnets early to avoid CPU spin
        if network.num_addresses > max(max_hosts * 10, 65536):
            raise ValueError(
                f"CIDR {cidr} contains {network.num_addresses:,} addresses - "
                f"maximum allowed is {max(max_hosts * 10, 65536):,}"
            )
        for host in network.hosts():
            ip_str = str(host)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if len(targets) >= max_hosts:
                return targets
    return targets


async def _probe_discovery_target(
    ip_address: str,
    timeout_seconds: float,
    device_type: str,
    hostname_prefix: str,
    use_snmp: bool,
    snmp_config: dict,
    use_icmp: bool = True,
) -> dict | None:
    if use_snmp:
        snmp_hit = await _probe_discovery_target_snmp(ip_address, timeout_seconds, snmp_config)
        if snmp_hit is not None:
            return snmp_hit

    detected_port = 0
    detected_protocol = ""
    banner_sample = ""
    for port in state.DISCOVERY_PROBE_PORTS:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_address, port), timeout=timeout_seconds)
            if port == 22:
                try:
                    banner = await asyncio.wait_for(reader.read(256), timeout=timeout_seconds)
                    banner_sample = banner.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner_sample = ""
            detected_port = port
            detected_protocol = "ssh" if port == 22 else "https"
            break
        except Exception:
            continue
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as exc:
                    LOGGER.debug("discovery: error closing probe connection to %s:%s: %s",
                                 ip_address, port, exc)
    if not detected_port:
        # Last-resort ICMP probe so hosts that block SNMP/22/443 but still
        # answer ping (firewalls with locked-down mgmt planes, appliances
        # without an SSH surface) surface in the discovery sweep.  The
        # caller can disable this for pure-SNMP networks.
        if use_icmp:
            icmp_hit = await _probe_discovery_target_icmp(
                ip_address, timeout_seconds, hostname_prefix,
            )
            if icmp_hit is not None:
                return icmp_hit
        return None

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        hostname = f"{hostname_prefix}-{ip_address.replace('.', '-')}"

    inferred_device_type = device_type
    inferred_os = "unknown"
    inferred_vendor = "unknown"
    if banner_sample:
        lower_banner = banner_sample.lower()
        if "cisco" in lower_banner:
            inferred_vendor = "cisco"
            # Distinguish IOS-XE from classic IOS - Catalyst 9xxx, 3850,
            # 3650, ISR 1000/4000, ASR 1000, etc. all run IOS-XE.
            # SSH banners rarely include OS detail, so also match on
            # sysDescr variants: "IOS XE", "IOS-XE", "(CAT9K_IOSXE)".
            if "ios-xe" in lower_banner or "iosxe" in lower_banner or "ios xe" in lower_banner:
                inferred_device_type = "cisco_xe"
            elif "nx-os" in lower_banner or "nxos" in lower_banner:
                inferred_device_type = "cisco_nxos"
            elif "ios-xr" in lower_banner or "iosxr" in lower_banner or "ios xr" in lower_banner:
                inferred_device_type = "cisco_xr"
            elif "firepower" in lower_banner or "ftd" in lower_banner:
                inferred_device_type = "cisco_ftd"
            elif "adaptive security" in lower_banner or "asa" in lower_banner:
                inferred_device_type = "cisco_asa"
            else:
                inferred_device_type = "cisco_ios"
        elif "juniper" in lower_banner or "junos" in lower_banner:
            inferred_vendor = "juniper"
            inferred_device_type = "juniper_junos"
        elif "arista" in lower_banner:
            inferred_vendor = "arista"
            inferred_device_type = "arista_eos"
        elif "forti" in lower_banner:
            inferred_vendor = "fortinet"
            inferred_device_type = "fortinet"

        if "ios-xe" in lower_banner or "iosxe" in lower_banner or "ios xe" in lower_banner:
            inferred_os = "ios-xe"
        elif "ios-xr" in lower_banner or "iosxr" in lower_banner or "ios xr" in lower_banner:
            inferred_os = "ios-xr"
        elif "ios" in lower_banner:
            inferred_os = "ios"
        elif "nx-os" in lower_banner or "nxos" in lower_banner:
            inferred_os = "nx-os"
        elif "junos" in lower_banner:
            inferred_os = "junos"
        elif "eos" in lower_banner:
            inferred_os = "eos"
        elif "fortios" in lower_banner:
            inferred_os = "fortios"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": inferred_device_type,
        "status": "online",
        "discovery": {
            "protocol": detected_protocol,
            "port": detected_port,
            "banner": banner_sample,
            "vendor": inferred_vendor,
            "os": inferred_os,
        },
    }


async def _discover_hosts(request: DiscoveryScanRequest, group_id: int | None = None) -> tuple[int, list[dict]]:
    targets = _expand_scan_targets(request.cidrs, request.max_hosts)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> dict | None:
        async with semaphore:
            return await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=request.timeout_seconds,
                device_type=request.device_type,
                hostname_prefix=request.hostname_prefix,
                use_snmp=request.use_snmp,
                snmp_config=snmp_cfg,
                use_icmp=request.use_icmp,
            )

    discovered_raw = await asyncio.gather(*[_scan_one(ip) for ip in targets])
    discovered = [item for item in discovered_raw if item is not None]
    discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
    return len(targets), discovered


def _is_fallback_hostname(name: str) -> bool:
    """True for discovery's synthetic names (no real sysName was learned)."""
    n = (name or "").strip()
    return n.startswith("snmp-") or n.startswith("host-")


def _norm_name(name: str) -> str:
    """Normalize a hostname for identity comparison (case + domain insensitive)."""
    return (name or "").strip().lower().split(".")[0]


def _normalize_discovered_entry(host: dict) -> dict | None:
    """Flatten a raw probe result into the fields the dedup planner needs."""
    ip = str(host.get("ip_address", "")).strip()
    if not ip:
        return None
    hostname = str(host.get("hostname") or "").strip() or f"host-{ip.replace('.', '-')}"
    # A "real" sysName is a stable per-device identity; the snmp-/host- fallback
    # names are per-IP and must NOT be used to group devices.
    explicit_sys = str(host.get("sys_name") or "").strip()
    if explicit_sys:
        sys_name = explicit_sys
    elif not _is_fallback_hostname(hostname):
        sys_name = hostname
    else:
        sys_name = ""
    probe_protocol = str(host.get("discovery", {}).get("protocol", "")).strip()
    return {
        "ip": ip,
        "hostname": hostname,
        "sys_name_norm": _norm_name(sys_name) if sys_name else "",
        "serial": str(host.get("serial_number") or "").strip(),
        "device_type": str(host.get("device_type") or "unknown").strip() or "unknown",
        "status": str(host.get("status") or "online").strip() or "online",
        "model": str(host.get("model") or "").strip(),
        "software_version": str(host.get("software_version") or "").strip(),
        "device_category": str(host.get("device_category") or "").strip(),
        "probe_protocol": probe_protocol,
        "snmp_reachable": probe_protocol.startswith("snmp"),
    }


def _build_discovery_plan(
    discovered: list[dict],
    existing_hosts: list[dict],
    existing_ip_index: dict[str, int],
    interface_ip_map: dict[str, list[str]],
) -> dict:
    """Decide adds / updates / IP-alias sets / duplicate suppressions.

    A physical device owns many interface IPs. Discovered IPs are grouped into
    one device when they share a serial number, a real sysName, or membership
    in another IP's SNMP ipAddrTable (interface_ip_map). Each device maps to at
    most one inventory host; its other IPs become aliases. Pre-existing
    duplicate host rows are suppressed (deleted) only on STRONG evidence — the
    duplicate's IP appears in the device's own ipAddrTable, or it shares the
    serial — never on a sysName match alone.

    Pure function (no I/O) so the dedup logic is unit-testable.
    """
    entries_by_ip = {e["ip"]: e for e in discovered}

    # ── Union-find over discovered IPs ────────────────────────────────────
    parent = {ip: ip for ip in entries_by_ip}

    def _find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: str, b: str) -> None:
        if a in parent and b in parent:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra

    by_serial: dict[str, str] = {}
    for e in discovered:
        if e["serial"]:
            by_serial.setdefault(e["serial"], e["ip"])
            _union(by_serial[e["serial"]], e["ip"])
    by_name: dict[str, str] = {}
    for e in discovered:
        if e["sys_name_norm"]:
            by_name.setdefault(e["sys_name_norm"], e["ip"])
            _union(by_name[e["sys_name_norm"]], e["ip"])
    for ip, iface in interface_ip_map.items():
        if ip not in parent:
            continue
        for other in iface:
            if other in parent:
                _union(ip, other)

    groups: dict[str, list[str]] = {}
    for ip in entries_by_ip:
        groups.setdefault(_find(ip), []).append(ip)

    # ── Existing-host lookups ─────────────────────────────────────────────
    existing_by_id = {h["id"]: h for h in existing_hosts}
    existing_by_serial: dict[str, dict] = {}
    existing_by_name: dict[str, dict] = {}
    for h in existing_hosts:
        s = (h.get("serial_number") or "").strip()
        if s:
            existing_by_serial.setdefault(s, h)
        hn = (h.get("hostname") or "").strip()
        if hn and not _is_fallback_hostname(hn):
            existing_by_name.setdefault(_norm_name(hn), h)

    plan: dict = {"add": [], "update": [], "delete": [], "matched": 0, "covered_ips": set()}

    for ips in groups.values():
        entries = [entries_by_ip[ip] for ip in ips]
        group_ips = set(ips)
        iface_ips: set[str] = set()
        for ip in ips:
            iface_ips.update(interface_ip_map.get(ip, []))
        full_ips = group_ips | iface_ips
        plan["covered_ips"] |= full_ips

        snmp_entries = [e for e in entries if e["snmp_reachable"]]
        any_snmp = bool(snmp_entries)
        serial = next((e["serial"] for e in entries if e["serial"]), "")
        sys_norm = next((e["sys_name_norm"] for e in entries if e["sys_name_norm"]), "")
        real_hostname = next(
            (e["hostname"] for e in entries if e["sys_name_norm"]),
            (snmp_entries or entries)[0]["hostname"],
        )
        device_type = (
            next((e["device_type"] for e in snmp_entries if e["device_type"] != "unknown"), "")
            or next((e["device_type"] for e in entries if e["device_type"] != "unknown"), "unknown")
        )
        model = next((e["model"] for e in entries if e["model"]), "")
        sw = next((e["software_version"] for e in entries if e["software_version"]), "")
        category = next((e["device_category"] for e in entries if e["device_category"]), "")
        status = next((e["status"] for e in snmp_entries), entries[0]["status"])

        # Canonical existing host: serial > known IP (primary/alias) > sysName.
        canonical = None
        if serial and serial in existing_by_serial:
            canonical = existing_by_serial[serial]
        if canonical is None:
            for ip in list(group_ips) + sorted(iface_ips):
                hid = existing_ip_index.get(ip)
                if hid is not None and hid in existing_by_id:
                    canonical = existing_by_id[hid]
                    break
        if canonical is None and sys_norm and sys_norm in existing_by_name:
            canonical = existing_by_name[sys_norm]

        canonical_id = canonical["id"] if canonical else None

        # Strong duplicates of THIS device: another existing host whose primary
        # IP is in the device's ipAddrTable, or that shares its serial.
        for h in existing_hosts:
            if canonical_id is not None and h["id"] == canonical_id:
                continue
            hip = (h.get("ip_address") or "").strip()
            hser = (h.get("serial_number") or "").strip()
            if (hser and serial and hser == serial) or (hip and hip in iface_ips):
                if h["id"] not in plan["delete"]:
                    plan["delete"].append(h["id"])

        if canonical is None:
            primary_ip = (
                snmp_entries[0]["ip"] if snmp_entries
                else sorted(group_ips, key=lambda x: ipaddress.ip_address(x))[0]
            )
            plan["add"].append({
                "hostname": real_hostname, "ip": primary_ip, "device_type": device_type,
                "status": status, "model": model, "software_version": sw,
                "device_category": category, "serial_number": serial,
                "alias_ips": sorted(full_ips - {primary_ip}),
            })
        else:
            primary_ip = (canonical.get("ip_address") or "").strip()
            eff_hostname = real_hostname if sys_norm else canonical.get("hostname")
            existing_dt = canonical.get("device_type", "unknown")
            eff_dt = device_type
            # Only an *explicit* SSH/HTTPS probe is low-confidence (its banner
            # reveals vendor but not OS variant); a blank protocol or any SNMP
            # probe is authoritative. A low-confidence probe may only fill an
            # unknown type, never overwrite an established one.
            low_confidence = (not any_snmp) and any(
                e["probe_protocol"] in ("ssh", "https") for e in entries
            )
            if low_confidence and existing_dt != "unknown" and device_type != existing_dt:
                eff_dt = existing_dt
            elif device_type == "unknown" and existing_dt != "unknown":
                eff_dt = existing_dt
            plan["update"].append({
                "host_id": canonical_id, "hostname": eff_hostname, "ip": primary_ip,
                "device_type": eff_dt, "status": status, "model": model,
                "software_version": sw, "device_category": category,
                "serial_number": serial, "alias_ips": sorted(full_ips - {primary_ip}),
            })

    # "matched" = devices reconciled this cycle (adds + updates), preserving the
    # pre-dedup meaning of "how many discovered devices were processed".
    plan["matched"] = len(plan["add"]) + len(plan["update"])
    return plan


async def _sync_group_hosts(
    group_id: int,
    discovered_hosts: list[dict],
    remove_absent: bool = False,
    *,
    interface_ip_resolver=None,
) -> dict:
    """Reconcile discovered devices into inventory, deduplicating a
    multi-interface device into a single host (see _build_discovery_plan).

    ``interface_ip_resolver`` is an injectable ``async (ip) -> list[str]`` used
    only in tests; in production the device's SNMP ipAddrTable is walked.
    """
    existing_hosts = await db.get_hosts_for_group(group_id)
    existing_by_id = {h["id"]: h for h in existing_hosts}
    existing_ip_index = await db.get_host_ip_index(group_id)

    normalized = [n for n in (_normalize_discovered_entry(h) for h in discovered_hosts) if n]

    # ── Learn each device's full interface-IP set via SNMP ipAddrTable ────
    # Walk one representative IP per device (deduped by serial/sysName) so a
    # device with many IPs isn't walked once per IP.
    interface_ip_map: dict[str, list[str]] = {}
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)
    if interface_ip_resolver is not None:
        for e in normalized:
            if e["snmp_reachable"]:
                interface_ip_map[e["ip"]] = await interface_ip_resolver(e["ip"])
    elif snmp_cfg.get("enabled"):
        reps: dict[str, str] = {}
        for e in normalized:
            if e["snmp_reachable"]:
                reps.setdefault(e["serial"] or e["sys_name_norm"] or e["ip"], e["ip"])
        targets = list(reps.values())
        sem = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _walk(ip: str) -> list[str]:
            async with sem:
                return await _collect_interface_ips(
                    ip, float(snmp_cfg.get("timeout_seconds", 2.0)), snmp_cfg,
                )

        walked = await asyncio.gather(*[_walk(ip) for ip in targets], return_exceptions=True)
        for ip, res in zip(targets, walked):
            if isinstance(res, list):
                interface_ip_map[ip] = res

    plan = _build_discovery_plan(normalized, existing_hosts, existing_ip_index, interface_ip_map)

    added = updated = removed = 0
    # Never delete a host we're keeping as a canonical update target.
    keep_ids = {u["host_id"] for u in plan["update"]}

    async def _write_device_info(host_id: int, item: dict, existing: dict | None) -> None:
        model = item.get("model", "")
        sw = item.get("software_version", "")
        category = item.get("device_category", "")
        if model or sw or category:
            await db.update_host_device_info(
                host_id,
                model or (existing or {}).get("model", ""),
                sw or (existing or {}).get("software_version", ""),
                category or (existing or {}).get("device_category", ""),
            )
        serial = item.get("serial_number", "")
        if serial and serial != (existing or {}).get("serial_number", ""):
            await db.update_host_serial(host_id, serial)
        await db.set_host_ip_aliases(host_id, item["ip"], item.get("alias_ips", []))

    # ── Updates (existing hosts first, so IDs/ordering stay stable) ───────
    for item in plan["update"]:
        existing = existing_by_id.get(item["host_id"], {})
        if (
            existing.get("hostname") != item["hostname"]
            or existing.get("device_type") != item["device_type"]
        ):
            await db.update_host(item["host_id"], item["hostname"], item["ip"], item["device_type"])
            await push_inventory_host_allocation(
                hostname=item["hostname"], ip_address=item["ip"], source_hint="discovery-update",
            )
            updated += 1
        await _write_device_info(item["host_id"], item, existing)
        await db.update_host_status(item["host_id"], item["status"])

    # ── Adds ──────────────────────────────────────────────────────────────
    for item in plan["add"]:
        _validate_host_ip(item["ip"])
        try:
            new_id = await db.add_host(group_id, item["hostname"], item["ip"], item["device_type"])
        except ValueError:
            # Race/duplicate within the payload - reconciled on the next pass.
            continue
        await db.update_host_status(new_id, item["status"])
        await push_inventory_host_allocation(
            hostname=item["hostname"], ip_address=item["ip"], source_hint="discovery-add",
        )
        await _write_device_info(new_id, item, None)
        try:
            await db.apply_graph_templates_to_host(new_id)
        except Exception as exc:
            LOGGER.debug("inventory: failed to apply graph templates to host %s: %s", new_id, exc)
        added += 1

    # ── Suppress pre-existing duplicate host rows (strong evidence only) ──
    for dup_id in plan["delete"]:
        if dup_id in keep_ids:
            continue
        await db.remove_host(dup_id)
        removed += 1

    # ── remove_absent: drop hosts no device claims this cycle ─────────────
    if remove_absent:
        covered = plan["covered_ips"]
        for h in existing_hosts:
            if h["id"] in keep_ids or h["id"] in plan["delete"]:
                continue
            if (h.get("ip_address") or "").strip() in covered:
                continue
            await db.remove_host(h["id"])
            removed += 1

    if added or updated or removed:
        await _notify_flow_collector_host_changed()

    return {
        "added": added,
        "updated": updated,
        "removed": removed,
        "matched": plan["matched"],
        "existing_before": len(existing_hosts),
        "existing_after": len(existing_hosts) + added - removed,
    }


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_discovery_sync_once() -> dict:
    DISCOVERY_SYNC_CONFIG = state.DISCOVERY_SYNC_CONFIG
    if not DISCOVERY_SYNC_CONFIG.get("enabled"):
        return {"enabled": False, "profiles": 0, "synced_groups": 0, "errors": 0}

    profiles = DISCOVERY_SYNC_CONFIG.get("profiles", [])
    synced_groups = 0
    errors = 0
    for profile in profiles:
        group_id = int(profile.get("group_id", 0))
        if group_id <= 0:
            continue
        group = await db.get_group(group_id)
        if not group:
            errors += 1
            LOGGER.warning("discovery sync: skipped missing group_id=%s", group_id)
            continue
        try:
            body = DiscoverySyncRequest.model_validate({
                "cidrs": profile.get("cidrs", []),
                "timeout_seconds": profile.get("timeout_seconds", state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS),
                "max_hosts": profile.get("max_hosts", state.DISCOVERY_DEFAULT_MAX_HOSTS),
                "device_type": profile.get("device_type", "unknown"),
                "hostname_prefix": profile.get("hostname_prefix", "discovered"),
                "use_snmp": profile.get("use_snmp", True),
                "remove_absent": profile.get("remove_absent", False),
            })
            _, discovered = await _discover_hosts(body, group_id=group_id)
            result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
            synced_groups += 1
            LOGGER.info(
                "discovery sync: group_id=%s discovered=%s added=%s updated=%s removed=%s",
                group_id,
                len(discovered),
                result["added"],
                result["updated"],
                result["removed"],
            )
            increment_metric("inventory.discovery.sync.success")
        except Exception as exc:
            errors += 1
            LOGGER.warning("discovery sync failed for group_id=%s: %s", group_id, redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.failed")

    return {
        "enabled": True,
        "profiles": len(profiles),
        "synced_groups": synced_groups,
        "errors": errors,
    }


async def _discovery_sync_loop() -> None:
    while True:
        try:
            await _run_discovery_sync_once()
            await asyncio.sleep(int(state.DISCOVERY_SYNC_CONFIG.get("interval_seconds", state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"])))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("discovery sync loop failure: %s", redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.loop.failed")
            await asyncio.sleep(state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"])


# ══════════════════════════════════════════════════════════════════════════════
# Admin routes (admin_router - registered with require_admin dependency)
# ══════════════════════════════════════════════════════════════════════════════


@admin_router.get("/api/admin/discovery-sync")
async def admin_get_discovery_sync_config():
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.put("/api/admin/discovery-sync")
async def admin_update_discovery_sync_config(body: dict):
    state.DISCOVERY_SYNC_CONFIG = state._sanitize_discovery_sync_config(body)
    await db.set_auth_setting("discovery_sync", state.DISCOVERY_SYNC_CONFIG)
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.post("/api/admin/discovery-sync/run-now")
async def admin_run_discovery_sync_now():
    result = await _run_discovery_sync_once()
    return {"ok": True, "result": result}


@admin_router.get("/api/admin/snmp-discovery")
async def admin_get_snmp_discovery_config():
    return state.SNMP_DISCOVERY_CONFIG


@admin_router.put("/api/admin/snmp-discovery")
async def admin_update_snmp_discovery_config(body: dict):
    state.SNMP_DISCOVERY_CONFIG = state._sanitize_snmp_discovery_config(body)
    await db.set_auth_setting("snmp_discovery", state.SNMP_DISCOVERY_CONFIG)
    return state.SNMP_DISCOVERY_CONFIG


@admin_router.get("/api/admin/snmp-discovery-profiles")
async def admin_get_snmp_discovery_profiles():
    return state.SNMP_DISCOVERY_PROFILES


# ── Named SNMP Profiles CRUD ─────────────────────────────────────────────────
# NOTE: GET /api/admin/snmp-profiles uses require_auth (not admin) in the original.
# It is placed on the main `router` so app.py can register it with inventory deps.


@router.get("/api/admin/snmp-profiles")
async def admin_list_snmp_profiles():
    return list(state.SNMP_PROFILES.values())


async def _validate_snmp_profile_secrets(profile: dict):
    """Check that any {{secret.NAME}} references in v3 passwords exist."""
    from routes.secret_resolver import extract_secret_names, has_secret_references
    v3 = profile.get("v3", {})
    for field_name in ("auth_password", "priv_password"):
        value = v3.get(field_name, "")
        if has_secret_references(value):
            names = extract_secret_names([value])
            for name in names:
                row = await db.get_secret_variable_by_name(name)
                if row is None:
                    raise HTTPException(400, f"Secret variable '{name}' not found. Create it in Credentials \u2192 Secret Variables first.")


@admin_router.post("/api/admin/snmp-profiles")
async def admin_create_snmp_profile(body: dict):
    profile_id = str(uuid.uuid4())
    profile = state._sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    await _validate_snmp_profile_secrets(profile)
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.put("/api/admin/snmp-profiles/{profile_id}")
async def admin_update_snmp_profile(profile_id: str, body: dict):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    profile = state._sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    await _validate_snmp_profile_secrets(profile)
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.delete("/api/admin/snmp-profiles/{profile_id}")
async def admin_delete_snmp_profile(profile_id: str):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    del state.SNMP_PROFILES[profile_id]
    # Unassign any groups using this profile
    changed = False
    for gid in list(state.GROUP_SNMP_ASSIGNMENTS):
        if state.GROUP_SNMP_ASSIGNMENTS[gid] == profile_id:
            del state.GROUP_SNMP_ASSIGNMENTS[gid]
            changed = True
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    if changed:
        await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Inventory-feature routes (router - registered with require_auth + require_feature("inventory"))
# ══════════════════════════════════════════════════════════════════════════════


# ── Group SNMP Profile Assignment ────────────────────────────────────────────


@router.get("/api/inventory/snmp-profile-assignments")
async def list_snmp_profile_assignments():
    """Return SNMP profile assignments for all inventory groups in one call."""
    assignments = []
    for group_id, profile_id in state.GROUP_SNMP_ASSIGNMENTS.items():
        profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
        assignments.append({
            "group_id": group_id,
            "snmp_profile_id": profile_id,
            "profile_name": profile["name"] if profile else "",
        })
    return {"assignments": assignments}


@router.get("/api/inventory/{group_id}/snmp-profile-assignment")
async def get_group_snmp_profile_assignment(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = state.GROUP_SNMP_ASSIGNMENTS.get(group_id, "")
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


@router.put("/api/inventory/{group_id}/snmp-profile-assignment")
async def update_group_snmp_profile_assignment(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = str(body.get("snmp_profile_id", "")).strip()
    if profile_id and profile_id not in state.SNMP_PROFILES:
        raise HTTPException(400, "SNMP profile not found")
    if profile_id:
        state.GROUP_SNMP_ASSIGNMENTS[group_id] = profile_id
    else:
        state.GROUP_SNMP_ASSIGNMENTS.pop(group_id, None)
    await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


# ── Inventory Group CRUD ─────────────────────────────────────────────────────


@router.get("/api/inventory")
async def list_groups(request: Request, include_hosts: bool = Query(default=False)):
    session = _get_session(request)
    user_id = session.get("user_id") if session else None
    if user_id is not None:
        if include_hosts:
            return await db.get_all_groups_with_hosts_for_user(int(user_id))
        return await db.get_all_groups_for_user(int(user_id))
    if include_hosts:
        return await db.get_all_groups_with_hosts()
    return await db.get_all_groups()


class GroupReorderRequest(BaseModel):
    ordered_ids: list[int]


@router.post("/api/inventory/groups/reorder")
async def reorder_groups(payload: GroupReorderRequest, request: Request):
    session = _get_session(request)
    user_id = session.get("user_id") if session else None
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    await db.set_user_group_order(int(user_id), payload.ordered_ids)
    return {"ok": True}


@router.get("/api/inventory/export/csv")
async def export_inventory_csv():
    """Export all inventory hosts as a CSV file."""
    rows = await db.get_all_hosts_for_export()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Hostname", "IP Address", "Model", "Software Version", "Device Type", "Status", "Group"])
    for r in rows:
        writer.writerow([
            r.get("hostname", ""),
            r.get("ip_address", ""),
            r.get("model", ""),
            r.get("software_version", ""),
            r.get("device_type", ""),
            r.get("status", ""),
            r.get("group_name", ""),
        ])
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventory_export.csv"},
    )


@router.post("/api/inventory", status_code=201)
async def create_group(body: GroupCreate):
    gid = await db.create_group(body.name, body.description)
    return {"id": gid, "name": body.name}


@router.put("/api/inventory/{group_id}")
async def update_group(group_id: int, body: GroupUpdate):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    await db.update_group(group_id, body.name, body.description)
    return {"ok": True}


@router.get("/api/inventory/{group_id}")
async def get_group(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    hosts = await db.get_hosts_for_group(group_id)
    return {**group, "hosts": hosts}


@router.delete("/api/inventory/{group_id}")
async def delete_group(group_id: int):
    await db.delete_group(group_id)
    return {"ok": True}


# ── Hosts ────────────────────────────────────────────────────────────────────


@router.get("/api/inventory/{group_id}/hosts")
async def list_hosts(group_id: int):
    return await db.get_hosts_for_group(group_id)


@router.post("/api/inventory/{group_id}/hosts", status_code=201)
async def add_host(group_id: int, body: HostCreate):
    _validate_host_ip(body.ip_address)
    try:
        hid = await db.add_host(
            group_id, body.hostname, body.ip_address, body.device_type,
            vrf_name=body.vrf_name or "",
            vlan_id=str(body.vlan_id or ""),
        )
    except ValueError:
        raise HTTPException(409, "A host with that IP address already exists in this group")
    # Auto-apply graph templates to manually added host
    try:
        await db.apply_graph_templates_to_host(hid)
    except Exception as exc:
        LOGGER.warning("inventory: failed to apply graph templates to host %s: %s", hid, exc)
    await push_inventory_host_allocation(
        hostname=body.hostname,
        ip_address=body.ip_address,
        source_hint="inventory-add",
    )
    await _notify_flow_collector_host_changed(new_ip=body.ip_address, host_id=hid)
    return {"id": hid}


@router.put("/api/hosts/{host_id}")
async def update_host(host_id: int, body: HostUpdate):
    if body.ip_address:
        _validate_host_ip(body.ip_address)
    prior = await db.get_host(host_id)
    prior_ip = (prior.get("ip_address") if prior else "") or ""
    await db.update_host(
        host_id, body.hostname, body.ip_address, body.device_type,
        vrf_name=body.vrf_name,
        vlan_id=body.vlan_id,
    )
    # Optional re-group as part of the same edit. The (group_id, ip_address)
    # unique key means moving to a group that already has this IP will fail
    # with an asyncpg/sqlite UniqueViolationError - surface as a clean 409.
    if body.group_id is not None:
        try:
            await db.move_hosts([host_id], int(body.group_id))
        except Exception as exc:
            msg = str(exc).lower()
            if "unique" in msg or "duplicate key" in msg:
                raise HTTPException(409, "Target group already has a host with this IP address")
            raise
    await push_inventory_host_allocation(
        hostname=body.hostname,
        ip_address=body.ip_address,
        source_hint="inventory-update",
    )
    await _notify_flow_collector_host_changed(
        old_ip=prior_ip or None,
        new_ip=body.ip_address or None,
        host_id=host_id,
    )
    return {"ok": True}


_VALID_CATEGORIES = {"router", "switch", "firewall", "wireless", "wlc", "phone", "server", ""}


@router.patch("/api/hosts/{host_id}/category")
async def update_host_category(host_id: int, body: dict):
    category = str(body.get("device_category", "")).strip().lower()
    if category not in _VALID_CATEGORIES:
        raise HTTPException(400, "Invalid device category")
    _db = await db.get_db()
    try:
        await _db.execute(
            "UPDATE hosts SET device_category = ? WHERE id = ?",
            (category, host_id),
        )
        await _db.commit()
    finally:
        await _db.close()
    return {"ok": True}


@router.delete("/api/hosts/{host_id}")
async def remove_host(host_id: int):
    prior = await db.get_host(host_id)
    prior_ip = (prior.get("ip_address") if prior else "") or ""
    await db.remove_host(host_id)
    if prior_ip:
        await _notify_flow_collector_host_changed(old_ip=prior_ip)
    return {"ok": True}


@router.post("/api/hosts/{host_id}/fetch-serial")
async def fetch_host_serial(host_id: int, body: FetchSerialRequest, request: Request):
    """SSH to the device and pull its chassis serial via the vendor driver.

    Stores the parsed serial in the DB and returns it.  Requires a stored
    credential ID so the caller selects which credential set to use.
    The show command and the parser both come from the device's driver,
    so NX-OS hosts (which print "Processor Board ID" instead of "System
    Serial Number") and future non-Cisco vendors work without branching
    here.
    """
    host = await db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    cred = await require_credential_access(body.credential_id, session=_get_session(request))

    driver = get_driver(host.get("device_type"))
    if isinstance(driver, GenericDriver):
        raise HTTPException(
            422,
            f"No driver registered for device_type={host.get('device_type')!r}; "
            "cannot fetch serial number for this vendor.",
        )

    try:
        output = await _run_show_command(
            host, cred, driver.serial_number_show_command()
        )
    except Exception:
        LOGGER.warning("fetch-serial SSH failed for host_id=%s ip=%s", host_id, host.get("ip_address"))
        raise HTTPException(502, "Could not connect to device")

    serial = driver.parse_serial_number(output) or ""

    if not serial:
        raise HTTPException(422, "Serial number not found in command output")

    await db.update_host_serial(host_id, serial)
    session = _get_session(request)
    await _audit(
        "inventory", "host.serial_fetched",
        user=session["user"] if session else "",
        detail=f"host_id={host_id} serial={serial}",
        correlation_id=_corr_id(request),
    )
    return {"host_id": host_id, "serial_number": serial}


@router.post("/api/groups/{group_id}/fetch-serials")
async def bulk_fetch_group_serials(group_id: int, body: FetchSerialRequest, request: Request):
    """Fetch serial numbers for all hosts in a group concurrently (max 5 SSH at a time)."""
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    cred = await require_credential_access(body.credential_id, session=_get_session(request))
    hosts = await db.get_hosts_for_group(group_id)
    if not hosts:
        return {"results": []}

    sem = state.device_op_semaphore()

    async def _fetch_one(host: dict) -> dict:
        async with sem:
            # Per-host driver lookup keeps the bulk-fetch generic across
            # mixed-vendor groups - an IOS host and an NX-OS host in the
            # same group both work, with each getting its own show command
            # and parser.  Unknown vendors are surfaced as a per-row error
            # rather than aborting the whole batch.
            driver = get_driver(host.get("device_type"))
            if isinstance(driver, GenericDriver):
                return {
                    "host_id": host["id"],
                    "hostname": host["hostname"],
                    "error": f"No driver for device_type={host.get('device_type')!r}",
                    "ok": False,
                }
            try:
                output = await _run_show_command(
                    host, cred, driver.serial_number_show_command()
                )
                serial = driver.parse_serial_number(output) or ""
                if serial:
                    await db.update_host_serial(host["id"], serial)
                    return {"host_id": host["id"], "hostname": host["hostname"], "serial_number": serial, "ok": True}
                return {"host_id": host["id"], "hostname": host["hostname"], "error": "Not found in output", "ok": False}
            except Exception:
                LOGGER.warning(
                    "bulk-fetch-serial SSH failed for host_id=%s ip=%s",
                    host["id"], host.get("ip_address"),
                )
                return {"host_id": host["id"], "hostname": host["hostname"], "error": "Connection failed", "ok": False}

    results = list(await asyncio.gather(*[_fetch_one(h) for h in hosts]))
    session = _get_session(request)
    ok_count = sum(1 for r in results if r.get("ok"))
    await _audit(
        "inventory", "host.serial_bulk_fetched",
        user=session["user"] if session else "",
        detail=f"group_id={group_id} total={len(hosts)} ok={ok_count}",
        correlation_id=_corr_id(request),
    )
    return {"results": results}


@router.post("/api/hosts/bulk-delete")
async def bulk_delete_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    host_ids = [int(h) for h in host_ids]
    deleted = await db.bulk_delete_hosts(host_ids)
    # Refresh the flow collector cache once for the whole batch; specific
    # exporter rows are unlinked by the ON DELETE SET NULL FK so we just
    # need the in-memory map to drop the deleted IPs.
    await _notify_flow_collector_host_changed()
    return {"deleted": deleted}


@router.post("/api/hosts/move")
async def move_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    target_group_id = body.get("target_group_id")
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    if not target_group_id:
        raise HTTPException(400, "target_group_id is required")
    target_group_id = int(target_group_id)
    group = await db.get_group(target_group_id)
    if not group:
        raise HTTPException(404, "Target group not found")
    host_ids = [int(h) for h in host_ids]
    moved = await db.move_hosts(host_ids, target_group_id)
    return {"moved": moved}


# ── Discovery routes ─────────────────────────────────────────────────────────


@router.post("/api/inventory/{group_id}/discovery/scan", status_code=202)
async def discovery_scan(group_id: int, body: DiscoveryScanRequest):
    """Launch a discovery scan as a background job.

    A full-CIDR probe (up to 4096 hosts) can run for minutes; running it
    inline held the HTTP request open the whole time. The scan now runs as a
    background task - poll GET /api/inventory/discovery/jobs/{job_id} for
    progress and the result (same payload shape the inline response had).
    The SSE variant at .../discovery/scan/stream is unchanged.
    """
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    try:
        targets = _expand_scan_targets(body.cidrs, body.max_hosts)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    job = background_jobs.create_job(
        "discovery-scan",
        {"group_id": group_id, "scanned": 0, "total": len(targets), "found": 0},
    )
    asyncio.create_task(_run_discovery_scan_job(job["job_id"], group_id, body, targets))
    return {"job_id": job["job_id"], "status": "running",
            "group_id": group_id, "total_targets": len(targets)}


async def _run_discovery_scan_job(job_id: str, group_id: int,
                                  body: DiscoveryScanRequest,
                                  targets: list[str]) -> None:
    """Background task: probe every target, tracking progress on the job."""
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> dict | None:
        async with semaphore:
            return await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=body.timeout_seconds,
                device_type=body.device_type,
                hostname_prefix=body.hostname_prefix,
                use_snmp=body.use_snmp,
                snmp_config=snmp_cfg,
                use_icmp=body.use_icmp,
            )

    tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]
    try:
        discovered: list[dict] = []
        scanned = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            scanned += 1
            if result is not None:
                discovered.append(result)
            background_jobs.update_progress(job_id, scanned=scanned, found=len(discovered))
        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
        background_jobs.finish_job(job_id, "completed", result={
            "group_id": group_id,
            "scanned_hosts": len(targets),
            "discovered_count": len(discovered),
            "discovered_hosts": discovered,
        })
    except Exception as exc:
        LOGGER.exception("inventory: discovery scan job %s failed", job_id)
        # Reap the still-pending probes so their results/exceptions are
        # consumed instead of warning "Task exception was never retrieved".
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        background_jobs.finish_job(job_id, "failed", error=str(exc))


@router.get("/api/inventory/discovery/jobs/{job_id}")
async def get_discovery_scan_job(job_id: str):
    """Poll a discovery-scan job launched by POST .../discovery/scan."""
    job = background_jobs.get_job(job_id, kind="discovery-scan")
    if job is None:
        raise HTTPException(404, "Discovery job not found (it may have expired)")
    return job


@router.post("/api/inventory/{group_id}/discovery/scan/stream")
async def discovery_scan_stream(group_id: int, body: DiscoveryScanRequest):
    """SSE streaming scan -- yields per-host results as they complete."""
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    try:
        targets = _expand_scan_targets(body.cidrs, body.max_hosts)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    total = len(targets)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
        async with semaphore:
            result = await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=body.timeout_seconds,
                device_type=body.device_type,
                hostname_prefix=body.hostname_prefix,
                use_snmp=body.use_snmp,
                snmp_config=snmp_cfg,
            )
            return ip_address, result

    async def event_generator():
        # Send initial metadata
        yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"

        scanned = 0
        discovered = []
        tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]

        for coro in asyncio.as_completed(tasks):
            ip_address, result = await coro
            scanned += 1
            if result is not None:
                discovered.append(result)
            yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
        yield f"data: {json.dumps({'type': 'done', 'scanned_hosts': total, 'discovered_count': len(discovered), 'discovered_hosts': discovered})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/inventory/{group_id}/snmp-discovery-profile")
async def get_group_snmp_discovery_profile(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = state.SNMP_DISCOVERY_PROFILES.get(group_id)
    if profile:
        return profile
    return state._sanitize_snmp_discovery_profile(group_id, {})


@router.put("/api/inventory/{group_id}/snmp-discovery-profile")
async def update_group_snmp_discovery_profile(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = state._sanitize_snmp_discovery_profile(group_id, body)
    state.SNMP_DISCOVERY_PROFILES[group_id] = profile
    await db.set_auth_setting("snmp_discovery_profiles", state.SNMP_DISCOVERY_PROFILES)
    return profile


@router.post("/api/inventory/{group_id}/snmp-discovery-profile/test")
async def test_group_snmp_profile(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    target_ip = str(body.get("target_ip", "")).strip()
    if not target_ip:
        raise HTTPException(400, "target_ip is required")
    snmp_config = state._resolve_snmp_discovery_config(group_id)
    if not snmp_config.get("enabled"):
        raise HTTPException(400, "SNMP is not enabled for this group")
    timeout = float(snmp_config.get("timeout_seconds", 1.2))
    try:
        result = await _snmp_get(target_ip, timeout, snmp_config)
    except Exception as exc:
        LOGGER.warning("SNMP test failed for %s: %s", target_ip, exc)
        return {"success": False, "target_ip": target_ip, "error": "SNMP query failed - check credentials and connectivity."}
    if result is None:
        return {"success": False, "target_ip": target_ip, "error": "SNMP query failed -- no response or bad credentials"}
    return {"success": True, "target_ip": target_ip, "result": result}


@router.post("/api/inventory/{group_id}/discovery/sync")
async def discovery_sync(group_id: int, body: DiscoverySyncRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    # If no CIDRs provided, auto-populate from the group's existing host IPs
    if not body.cidrs:
        existing_hosts = await db.get_hosts_for_group(group_id)
        host_ips = [str(h["ip_address"]) for h in existing_hosts if h.get("ip_address")]
        if not host_ips:
            raise HTTPException(400, "Group has no hosts to sync. Add hosts first or provide CIDR targets.")
        body.cidrs = host_ips

    scanned_count, discovered = await _discover_hosts(body, group_id=group_id)
    sync_result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"

    await _audit(
        "inventory",
        "discovery.sync",
        user=audit_user,
        detail=(
            f"group_id={group_id} scanned={scanned_count} discovered={len(discovered)} "
            f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
        ),
        correlation_id=_corr_id(request),
    )

    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "sync": sync_result,
    }


@router.post("/api/inventory/{group_id}/discovery/sync/stream")
async def discovery_sync_stream(group_id: int, body: DiscoverySyncRequest, request: Request):
    """SSE streaming sync -- yields per-host probe progress, then a final
    'done' event carrying the add/update/remove counts. Mirrors
    discovery_scan_stream so the frontend can reuse its progress UI."""
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    # If no CIDRs provided, auto-populate from the group's existing host IPs
    # (same behaviour as the non-streaming /discovery/sync endpoint).
    if not body.cidrs:
        existing_hosts = await db.get_hosts_for_group(group_id)
        host_ips = [str(h["ip_address"]) for h in existing_hosts if h.get("ip_address")]
        if not host_ips:
            raise HTTPException(400, "Group has no hosts to sync. Add hosts first or provide CIDR targets.")
        body.cidrs = host_ips

    try:
        targets = _expand_scan_targets(body.cidrs, body.max_hosts)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    total = len(targets)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
        async with semaphore:
            result = await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=body.timeout_seconds,
                device_type=body.device_type,
                hostname_prefix=body.hostname_prefix,
                use_snmp=body.use_snmp,
                snmp_config=snmp_cfg,
            )
            return ip_address, result

    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"
    corr_id = _corr_id(request)

    async def event_generator():
        yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"

        scanned = 0
        discovered = []
        tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]

        for coro in asyncio.as_completed(tasks):
            ip_address, result = await coro
            scanned += 1
            if result is not None:
                discovered.append(result)
            yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))

        # Persisting phase: probing is done, now reconcile with the DB.
        yield f"data: {json.dumps({'type': 'syncing', 'discovered_count': len(discovered)})}\n\n"
        sync_result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)

        await _audit(
            "inventory",
            "discovery.sync",
            user=audit_user,
            detail=(
                f"group_id={group_id} scanned={total} discovered={len(discovered)} "
                f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
            ),
            correlation_id=corr_id,
        )

        yield f"data: {json.dumps({'type': 'done', 'scanned_hosts': total, 'discovered_count': len(discovered), 'sync': sync_result})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/api/inventory/{group_id}/discovery/onboard")
async def discovery_onboard(group_id: int, body: DiscoveryOnboardRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    if not body.discovered_hosts:
        raise HTTPException(400, "No discovered hosts provided")

    sync_result = await _sync_group_hosts(group_id, body.discovered_hosts, remove_absent=False)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"
    await _audit(
        "inventory",
        "discovery.onboard",
        user=audit_user,
        detail=(
            f"group_id={group_id} provided={len(body.discovered_hosts)} "
            f"added={sync_result['added']} updated={sync_result['updated']}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "group_id": group_id,
        "provided_count": len(body.discovered_hosts),
        "sync": sync_result,
    }
