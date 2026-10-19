"""What a device's running configuration says about forwarding, in one shape
for every platform.

The config backup feature stores each host's running configuration
(``config_backups.config_text``). A platform's parser (``ios_config`` for
Cisco IOS / IOS-XE / NX-OS; see ``platforms`` for the others) reads from it
what the forwarding block of an inventory host needs and the route table
capture does not give, and returns it as a ``RunningConfig``:

- the interfaces, each with its addresses, VRF, state, the security zone or
  name the platform's rules refer to it by (``zone``: an ASA ``nameif``, an
  SRX security zone, a FortiGate zone; empty when the rules name the
  interface itself), the other names the platform's commands print for it
  (``aliases``), the access lists bound to it in and out (``access_groups``)
  and its HSRP / VRRP / GLBP addresses;
- the access lists (``access_lists``), each a list of entries in forwarding
  rule terms (``netcontrol.integrations.meraki.forwarding.rule``): ``allow``
  or ``deny``, CIDRs or ``any``, port expressions such as ``80,443`` or
  ``1024-65535``. What cannot be turned into those (an object the
  configuration does not define, a wildcard mask that is not a prefix, a
  time range, DSCP or TCP flag match, an application the platform
  identifies by inspection) is kept in the entry's ``unresolved`` list, so a
  flow it matches is unknown rather than decided;
- the rule sets that are not bound to one interface (``policies``): a
  firewall's zone-pair policies, a global access list, the implicit rules of
  a security model. Their entries match by zone (``src_zones`` /
  ``dst_zones``) and they are applied to every flow;
- the NAT rules (``nat``), already in the forwarding ``nat`` shape, naming
  interfaces by their zone or name;
- the static routes, including those of VRFs; which routing protocols run;
  and what the configuration uses that is not read (``notes``, for
  not_collected).

``stateful`` says whether the interface access lists keep connection state
(a firewall: the replies of an allowed request pass) or match the replies
again (a switch or router access list); each policy says so for itself.

Pure (no I/O).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.meraki.forwarding import ANY

__all__ = [
    "AclEntry",
    "ConfigInterface",
    "ConfigPolicy",
    "RunningConfig",
    "StaticRoute",
    "VirtualAddress",
]


@dataclass
class VirtualAddress:
    """An HSRP, VRRP or GLBP address an interface answers on."""

    protocol: str  # "HSRP", "VRRP" or "GLBP"
    group: str
    address: str


@dataclass
class ConfigInterface:
    name: str
    description: str = ""
    # (address, network) pairs, the primary first.
    addresses: list[tuple[str, str]] = field(default_factory=list)
    vrf: str = ""
    shutdown: bool = False
    # "in" / "out" -> access list name.
    access_groups: dict[str, str] = field(default_factory=dict)
    virtual: list[VirtualAddress] = field(default_factory=list)
    # The name the platform's rules and route table refer to the interface
    # by when it is not the interface name (an ASA nameif, an SRX or
    # FortiGate zone); empty: the interface's own name.
    zone: str = ""
    # Other names the platform prints for the interface (an ASA nameif in
    # ``show route``), matched to the SNMP and route table names.
    aliases: list[str] = field(default_factory=list)
    # The kind of interface when the configuration says (``wan``: an
    # internet-facing interface, so a default route out of it leads to the
    # internet); empty: told by the name.
    kind: str = ""


@dataclass
class AclEntry:
    """One access list or policy entry, in forwarding rule terms."""

    sequence: int | None
    action: str  # "allow" or "deny"
    protocol: str = ANY
    src: list[str] = field(default_factory=lambda: [ANY])
    src_ports: str = ANY
    dst: list[str] = field(default_factory=lambda: [ANY])
    dst_ports: str = ANY
    established: bool = False
    comment: str = ""
    unresolved: list[str] = field(default_factory=list)
    # Policy entries: the zones (or interface names) the flow must enter by
    # and leave by; empty: any.
    name: str = ""
    src_zones: list[str] = field(default_factory=list)
    dst_zones: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class ConfigPolicy:
    """A rule set applied to every flow a device forwards (not bound to one
    interface by ``access_groups``): zone-pair policies, a global access
    list, the implicit rules of a security model. ``default`` is what a flow
    no entry matches gets: ``deny``, ``allow`` or ``unknown``."""

    name: str
    entries: list[AclEntry] = field(default_factory=list)
    kind: str = "policy"  # "policy" or "acl"
    default: str = "deny"
    # Whether the rule set keeps connection state (a firewall policy: the
    # replies of an allowed request pass) or matches the replies again.
    stateful: bool = True


@dataclass
class StaticRoute:
    prefix: str
    next_hop: str = ""
    interface: str = ""
    vrf: str = ""
    distance: int | None = None
    name: str = ""


@dataclass
class RunningConfig:
    interfaces: list[ConfigInterface] = field(default_factory=list)
    access_lists: dict[str, list[AclEntry]] = field(default_factory=dict)
    policies: list[ConfigPolicy] = field(default_factory=list)
    # Forwarding ``nat`` entries (``netcontrol.integrations.meraki.forwarding.nat``).
    nat: list[dict[str, Any]] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    # The routing protocols configured (``router ospf 1``...), by display name.
    routing: list[str] = field(default_factory=list)
    # What the configuration uses that is not read, for not_collected.
    notes: list[str] = field(default_factory=list)
    # Whether the access lists bound by ``access_groups`` keep connection
    # state (an ASA's do; a switch, router or Junos filter matches the
    # replies again). Each policy in ``policies`` says so for itself.
    stateful: bool = False
