"""Which devices of a source's topology snapshot can become inventory hosts.

After a Meraki organization, Cato account, Cisco FMC, Palo Alto Panorama or
Appgate SDP collective is collected, the administrator may import the
devices it found into the inventory (``netcontrol.routes.source_import``).
This module decides, from the snapshot alone, which devices those are and
what Plexus can do with each once it is a host:

  - a device is one of the source's own devices (or, for Meraki, a CDP/LLDP
    neighbor a Meraki device reported) with a usable management address;
    WAN uplinks, VPN peers, remote users, the source's cloud/manager node
    and Cato IPsec sites (whose address is the far end of a tunnel) are not;
  - its device type is the inventory driver key of its platform, the same
    platform the software tracker gives it; a platform with no driver
    (Meraki, Cato Socket, Appgate appliance) or none known is ``icmp_only``;
  - SNMP polling works for every type but ``icmp_only`` (the monitoring
    poller skips SNMP for those and only pings them); configuration backup
    works where the driver names a capture command
    (``netcontrol.drivers.supports_config_capture``).

Pure (no I/O): the inventory is passed in.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from netcontrol.drivers import registered_device_types, supports_config_capture
from netcontrol.integrations.software.versions import DEVICE_TYPE_PLATFORMS, classify_host, snapshot_platform
from netcontrol.routes.host_identity import host_ip_problem

ICMP_ONLY = "icmp_only"

# The node ids of a provider's devices. Meraki: its devices ("d:") and the
# CDP/LLDP neighbors they report ("x:"); Cato: Sockets ("d:"; an IPsec site
# is "s:" and its address is the far end of the tunnel); FMC: its FTDs;
# Panorama: its firewalls; Appgate: the appliances of the collective ("a:").
DEVICE_NODE_PREFIXES: dict[str, tuple[str, ...]] = {
    "meraki": ("d:", "x:"),
    "cato": ("d:",),
    "fmc": ("d:",),
    "panorama": ("d:",),
    "appgate": ("a:",),
}
# Read as their current key, like the rest of the source routes.
_LEGACY_PROVIDERS = {"anyconnect": "fmc"}

# What a provider's own devices are, and why Plexus can only ping them:
# shown next to the list so the administrator knows before importing.
PROVIDER_NOTES: dict[str, str] = {
    "meraki": (
        "Meraki devices are cloud-managed: Plexus pings them, and their status, firmware and alerts "
        "come from the Meraki collection. CDP/LLDP neighbors of a known platform can be polled over SNMP."
    ),
    "cato": (
        "Cato Sockets are cloud-managed: Plexus pings their LAN address, and their status and "
        "version come from the Cato collection."
    ),
    "fmc": (
        "FTDs are polled over SNMP once an SNMP profile is assigned. Their configuration lives in "
        "the FMC, so Config Backups does not read it from the device."
    ),
    "panorama": (
        "PAN-OS firewalls are polled over SNMP once an SNMP profile is assigned. Their configuration "
        "lives in Panorama, so Config Backups does not read it from the device."
    ),
    "appgate": ("Appgate appliances are pinged; their status and version come from the Appgate collection."),
}

NO_SNAPSHOT_REASON = "This source has not been collected yet. Collect it first, then import its devices."
NO_DEVICES_REASON = "The latest collection of this source found no devices with a management address."


def _device_types_by_platform() -> dict[str, str]:
    """platform -> the inventory device type of it that has a driver."""
    registered = set(registered_device_types())
    out: dict[str, str] = {}
    for device_type, platform in DEVICE_TYPE_PLATFORMS.items():
        if device_type in registered:
            out.setdefault(platform, device_type)
    return out


def provider_key(provider: str | None) -> str:
    key = str(provider or "").strip().lower()
    return _LEGACY_PROVIDERS.get(key, key)


def device_platform(provider: str, node: dict) -> str:
    """The software platform of a device node: the tracker's platform for
    the provider's own devices, the model text for a CDP/LLDP neighbor."""
    if str(node.get("id") or "").startswith("x:"):
        return classify_host(None, node.get("model"), "")[0]
    return snapshot_platform(provider_key(provider), node)


def device_type_for(provider: str, node: dict) -> str:
    """The inventory device type a device node gets: the driver of its
    platform, or ``icmp_only``."""
    return _device_types_by_platform().get(device_platform(provider, node), ICMP_ONLY)


def capabilities(device_type: str) -> dict[str, bool]:
    """What Plexus does with a host of ``device_type`` beyond pinging it."""
    return {
        "snmp_polling": device_type != ICMP_ONLY,
        "config_backup": supports_config_capture(device_type),
    }


def _usable_ip(raw: Any) -> str:
    ip = str(raw or "").strip()
    return ip if ip and not host_ip_problem(ip) else ""


def _existing(node: dict, ip: str, hosts_by_ip: Mapping[str, dict], hosts_by_id: Mapping[int, dict]) -> dict | None:
    """The inventory host this device already is: one with its address, or
    the one the collection matched it to (by serial or another address)."""
    host = hosts_by_ip.get(ip)
    if host is None:
        ref = node.get("inventory")
        host_id = ref.get("host_id") if isinstance(ref, dict) else None
        try:
            host = hosts_by_id.get(int(host_id)) if host_id is not None else None
        except TypeError, ValueError:
            host = None
    if host is None:
        return None
    return {
        "host_id": host.get("id"),
        "hostname": str(host.get("hostname") or ""),
        "ip_address": str(host.get("ip_address") or ""),
        "group_id": host.get("group_id"),
        "group_name": str(host.get("group_name") or ""),
    }


def importable_devices(
    snapshot: dict | None,
    provider: str,
    hosts: list[dict] | None = None,
) -> dict[str, Any]:
    """The devices of ``snapshot`` (a ``provider`` source's latest
    collection) that can be imported into the inventory.

    ``hosts`` are the inventory hosts (``id``, ``hostname``, ``ip_address``,
    ``group_id`` and optionally ``group_name``). Returns ``devices``, one
    per management address (the first node wins), sorted by name, and
    ``reason``: why the list is empty, or ``""``. Each device has ``key``
    (its node id, what an import names it by), ``name``, ``ip``,
    ``model``, ``serial``, ``kind``, ``site``, ``platform``,
    ``device_type``, ``capabilities`` and ``existing`` (the inventory host
    it already is, or ``None``).
    """
    provider = provider_key(provider)
    if not snapshot:
        return {"devices": [], "reason": NO_SNAPSHOT_REASON}
    prefixes = DEVICE_NODE_PREFIXES.get(provider)
    if not prefixes:
        return {"devices": [], "reason": f"Devices of a {provider or 'this'} source cannot be imported."}
    hosts = hosts or []
    hosts_by_ip = {str(h.get("ip_address") or "").strip(): h for h in hosts if h.get("ip_address")}
    hosts_by_id = {int(h["id"]): h for h in hosts if h.get("id") is not None}
    site_names = {
        s.get("id"): str(s.get("name") or s.get("id") or "") for s in snapshot.get("sites") or [] if isinstance(s, dict)
    }
    by_ip: dict[str, dict[str, Any]] = {}
    for node in snapshot.get("nodes") or []:
        if not isinstance(node, dict) or not str(node.get("id") or "").startswith(prefixes):
            continue
        ip = _usable_ip(node.get("ip"))
        if not ip or ip in by_ip:
            continue
        device_type = device_type_for(provider, node)
        by_ip[ip] = {
            "key": str(node["id"]),
            "name": str(node.get("label") or node.get("serial") or ip),
            "ip": ip,
            "model": str(node.get("model") or ""),
            "serial": str(node.get("serial") or ""),
            "kind": str(node.get("kind") or ""),
            "site": site_names.get(node.get("site"), ""),
            "platform": device_platform(provider, node),
            "device_type": device_type,
            "capabilities": capabilities(device_type),
            "existing": _existing(node, ip, hosts_by_ip, hosts_by_id),
        }
    devices = sorted(by_ip.values(), key=lambda d: (d["name"].lower(), d["ip"]))
    return {"devices": devices, "reason": "" if devices else NO_DEVICES_REASON}
