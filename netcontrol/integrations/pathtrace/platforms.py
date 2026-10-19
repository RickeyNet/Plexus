"""The platforms of inventory hosts: what Plexus reads of each one.

An inventory host's ``device_type`` (the Netmiko name Plexus stores:
``cisco_ios``, ``cisco_asa``, ``juniper_junos``...) picks its ``Platform``,
which names the parser of its configuration backups (``config``, a
``RunningConfig`` from the backup text; ``None``: not read, so its access
lists are not collected) and of its route table captures (``routes``, the
forwarding routes of the lines the monitoring poll stored; ``None``: not
read), and whether its rule sets are stateful (a firewall) or match the
replies again (a switch or router access list).

``platform_of`` is forgiving: it matches the vendor words of the type, and
takes an empty or unknown type as Cisco IOS, as the monitoring poll does.

Pure (no I/O).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from netcontrol.integrations.pathtrace import (  # noqa: F401  (the vendor readers register here)
    aruba_config,
    asa_config,
    fortios_config,
    ios_config,
    junos_config,
    route_tables,
)
from netcontrol.integrations.pathtrace.device_config import RunningConfig

__all__ = ["PLATFORMS", "Platform", "platform_of"]

ConfigParser = Callable[[str], RunningConfig]


@dataclass(frozen=True)
class Platform:
    key: str
    label: str
    # The words of a device type that pick this platform, in lower case.
    matches: tuple[str, ...]
    stateful: bool = False
    config: ConfigParser | None = None
    routes: route_tables.RouteParser | None = None


IOS = Platform(
    "ios",
    "Cisco IOS / IOS-XE",
    ("cisco_ios", "cisco_xe", "ios", "xe"),
    config=ios_config.parse_config,
    routes=route_tables.parse_cisco_family,
)

# Order matters: the first platform one of whose words the type holds wins,
# so the platforms whose words are part of another's come first.
PLATFORMS: tuple[Platform, ...] = (
    Platform(
        "asa",
        "Cisco ASA / FTD",
        ("asa", "ftd", "firepower"),
        stateful=True,
        config=asa_config.parse_config,
        routes=route_tables.parse_cisco_family,
    ),
    Platform(
        "xr",
        "Cisco IOS-XR",
        ("cisco_xr", "iosxr", "ios-xr", "xr"),
        config=ios_config.parse_config,
        routes=route_tables.parse_cisco_family,
    ),
    Platform(
        "nxos",
        "Cisco NX-OS",
        ("nxos", "nx-os", "nexus"),
        config=ios_config.parse_config,
        routes=route_tables.parse_cisco_family,
    ),
    Platform(
        "eos",
        "Arista EOS",
        ("arista", "eos"),
        config=ios_config.parse_config,
        routes=route_tables.parse_eos,
    ),
    Platform(
        "junos",
        "Juniper Junos",
        ("juniper", "junos", "srx"),
        stateful=True,
        config=junos_config.parse_config,
        routes=junos_config.parse_routes,
    ),
    Platform(
        "fortios",
        "Fortinet FortiOS",
        ("fortinet", "fortios", "fortigate"),
        stateful=True,
        config=fortios_config.parse_config,
        routes=fortios_config.parse_routes,
    ),
    Platform(
        "panos",
        "Palo Alto PAN-OS",
        ("paloalto", "panos", "pan-os"),
        stateful=True,
        config=None,
        routes=None,
    ),
    Platform(
        "aoscx",
        "Aruba AOS-CX",
        ("aoscx", "aos-cx", "aos_cx"),
        config=aruba_config.parse_config,
        routes=aruba_config.parse_routes,
    ),
    Platform(
        "aos-switch",
        "Aruba AOS-Switch / HP ProCurve",
        ("procurve", "osswitch", "aruba_os", "aruba_aos", "hp_procurve"),
        config=aruba_config.parse_config,
        routes=aruba_config.parse_routes,
    ),
    IOS,
)


def platform_of(device_type: str) -> Platform:
    """The platform of a device type (an empty or unknown type is Cisco IOS)."""
    flavour = str(device_type or "").strip().lower()
    for platform in PLATFORMS:
        if any(word in flavour for word in platform.matches):
            return platform
    return IOS
