"""VRF and VLAN records and the addresses of device interfaces: the limits
and rules, with no I/O.

A VRF is known by its name (``""`` is the global VRF and has no record); a
VLAN by its site and VLAN id. Both are filled from what Plexus collects and
curated by an admin. The addresses a device's interfaces carry are read from
its stored running configuration by the path trace configuration parsers
(``netcontrol.integrations.pathtrace.platforms``); ``bindings_from_config``
turns one parsed configuration into the rows the storage layer
(``routes.db.network_objects``) keeps.
"""

from __future__ import annotations

import ipaddress
import re

from netcontrol.custom_fields import CustomFieldError, clean_name
from netcontrol.integrations.pathtrace.device_config import RunningConfig
from netcontrol.integrations.pathtrace.route_tables import interface_key

__all__ = [
    "DESCRIPTION_MAX",
    "ORIGINS",
    "RD_MAX",
    "ROLES",
    "VID_MAX",
    "VID_MIN",
    "VLAN_NAME_MAX",
    "VRF_NAME_MAX",
    "bindings_from_config",
    "clean_description",
    "clean_rd",
    "clean_vid",
    "clean_vlan_name",
    "clean_vrf_name",
    "port_vlan_modes",
    "svi_vid",
    "vlans_of_port",
]

VRF_NAME_MAX = 64
RD_MAX = 64
VLAN_NAME_MAX = 64
DESCRIPTION_MAX = 500
VID_MIN = 1
VID_MAX = 4094

# ``manual``: made by an admin (or a host or prefix an admin wrote);
# ``discovered``: made from collected data.
ORIGINS: tuple[str, ...] = ("manual", "discovered")
# The role of an interface address, in the order an interface lists them.
ROLES: tuple[str, ...] = ("primary", "secondary", "virtual")

# ``Vlan10``, ``vlan 10``, ``vlan.10`` (Junos), ``irb.10``.
_SVI = re.compile(r"^(?:vlan\s*\.?\s*|irb\.)(\d+)$", re.IGNORECASE)


def _limited(raw: object, label: str, limit: int) -> str:
    text = raw.strip() if isinstance(raw, str) else ""
    if len(text) > limit:
        raise CustomFieldError(f"{label} must be at most {limit} characters.")
    return text


def clean_vrf_name(raw: object) -> str:
    """A VRF name trimmed; 1 to ``VRF_NAME_MAX`` characters."""
    return clean_name(raw, "VRF name", VRF_NAME_MAX)


def clean_rd(raw: object) -> str:
    """A route distinguisher trimmed; may be empty."""
    return _limited(raw, "Route distinguisher", RD_MAX)


def clean_vlan_name(raw: object) -> str:
    """A VLAN name trimmed; may be empty."""
    return _limited(raw, "VLAN name", VLAN_NAME_MAX)


def clean_description(raw: object) -> str:
    """A description trimmed; may be empty."""
    return _limited(raw, "Description", DESCRIPTION_MAX)


def clean_vid(raw: object) -> int:
    """A VLAN id, ``VID_MIN`` to ``VID_MAX``."""
    if isinstance(raw, bool) or not isinstance(raw, int) or not VID_MIN <= raw <= VID_MAX:
        raise CustomFieldError(f"VLAN id must be a number from {VID_MIN} to {VID_MAX}.")
    return raw


def svi_vid(interface_name: str) -> int:
    """The VLAN id of a VLAN interface (``Vlan10``, ``vlan 10``, ``vlan.10``,
    ``irb.10``; case ignored), else 0."""
    match = _SVI.match(str(interface_name or "").strip())
    if not match:
        return 0
    vid = int(match.group(1))
    return vid if VID_MIN <= vid <= VID_MAX else 0


def port_vlan_modes(access_vlan: int, trunk_vlans: set[int], vid: int) -> list[str]:
    """How a port carries VLAN ``vid``: ``access`` when it is the port's access
    VLAN, ``trunk`` when its trunk list (already parsed, see
    ``netcontrol.drivers.parse_vlan_ranges``) holds it; both, one or none."""
    modes: list[str] = []
    if int(access_vlan or 0) == vid:
        modes.append("access")
    if vid in trunk_vlans:
        modes.append("trunk")
    return modes


def vlans_of_port(access_vlan: int, trunk_vlans: set[int], among: set[int]) -> set[int]:
    """The VLAN ids of ``among`` a port carries either way (the rule of
    ``port_vlan_modes`` for many VLANs at once)."""
    carried = among & trunk_vlans
    if int(access_vlan or 0) in among:
        carried.add(int(access_vlan))
    return carried


def _row(name: str, key: str, address, network, vrf: str, role: str, protocol: str, vid: int) -> dict:
    return {
        "interface": name,
        "interface_key": key,
        "address": str(address),
        "prefix_length": int(network.prefixlen),
        "network": str(network),
        "vrf_name": vrf,
        "role": role,
        "protocol": protocol,
        "svi_vid": vid,
    }


def bindings_from_config(running: RunningConfig) -> tuple[list[dict], dict[str, int]]:
    """The interface address rows of a parsed running configuration and the
    VRFs the device has.

    Rows: per interface, its addresses with their network and the
    interface's VRF; the first address of each IP version is ``primary``,
    the others ``secondary``, then its HSRP / VRRP / GLBP addresses
    (``virtual``), each with the network of the interface address that
    holds it (none does: skipped). An address the parser gives without a
    usable network is skipped, and an address is listed once per interface.

    VRFs: ``name -> interface count``, counting the interfaces in the VRF
    with or without an address, plus the VRFs of static routes (count 0
    when no interface is in them).
    """
    rows: list[dict] = []
    vrfs: dict[str, int] = {}
    for conf in running.interfaces:
        name = str(conf.name or "").strip()
        if not name:
            continue
        vrf = str(conf.vrf or "").strip()
        if vrf:
            vrfs[vrf] = vrfs.get(vrf, 0) + 1
        key = interface_key(name)
        vid = svi_vid(name)
        seen: set[str] = set()
        versions: set[int] = set()
        networks: list = []
        for raw_address, raw_network in conf.addresses:
            try:
                address = ipaddress.ip_address(str(raw_address).strip())
                network = ipaddress.ip_network(str(raw_network).strip(), strict=False)
            except ValueError:
                continue
            if address.version != network.version or str(address) in seen:
                continue
            seen.add(str(address))
            role = "secondary" if address.version in versions else "primary"
            versions.add(address.version)
            networks.append(network)
            rows.append(_row(name, key, address, network, vrf, role, "", vid))
        for virtual in conf.virtual:
            try:
                address = ipaddress.ip_address(str(virtual.address).strip())
            except ValueError:
                continue
            holder = next((n for n in networks if n.version == address.version and address in n), None)
            if holder is None or str(address) in seen:
                continue
            seen.add(str(address))
            rows.append(_row(name, key, address, holder, vrf, "virtual", str(virtual.protocol or "").upper(), vid))
    for route in running.static_routes:
        vrf = str(route.vrf or "").strip()
        if vrf:
            vrfs.setdefault(vrf, 0)
    return rows, vrfs
