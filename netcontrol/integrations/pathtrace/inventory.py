"""Forwarding data of a Plexus inventory host, built at trace time.

An inventory host has no integration snapshot. What Plexus stores for it is
its interfaces (SNMP), its address and aliases, the route table the
monitoring poll captures over SSH (``show ip route`` or the platform's
equivalent, with every VRF's table where the platform lists them) and, from
Config Backups, its latest running configuration. ``forwarding_for_host``
turns those into the ``forwarding`` block every integration emits
(``netcontrol.integrations.meraki.forwarding``). The host's ``device_type``
picks its platform (``platforms``): the reader of its route captures and,
when Plexus reads the platform's configuration (``device_config`` for the
shape, ``ios_config``, ``asa_config``, ``junos_config``, ``fortios_config``
and ``aruba_config`` for the readers), of its configuration backup, which
adds the access lists and policies, the interface addresses, zones and
VRFs, the virtual addresses, the NAT rules and the routes of VRFs the
capture lacks. Without a backup, or on a platform whose configuration is
not read, the access lists are not collected, so a trace reports them as
unknown. ``subnets_for_host`` lists the host's networks for the subnet
index.

``parse_route_table`` reads a capture with the platform's parser. A capture
in a format it does not recognise gives no routes and says so.

Pure (no I/O): the API handler loads the rows.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.meraki.forwarding import (
    ANY,
    canonical,
    interface,
    is_address,
    new_block,
    note,
    policy_set,
    rule,
)
from netcontrol.integrations.pathtrace.device_config import ConfigInterface, ConfigPolicy, RunningConfig
from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF, PROVIDER_INVENTORY
from netcontrol.integrations.pathtrace.platforms import Platform, platform_of
from netcontrol.integrations.pathtrace.route_tables import (
    CAPTURE_LIMIT,
    EMPTY_CAPTURE,
    LOCAL,
    NOT_RECOGNISED,
    TRUNCATED,
    interface_key,
    parse_route_table as _parse_capture,
    route_entry,
    vrf_name,
)

__all__ = [
    "ACCESS_LISTS",
    "CAPTURE_LIMIT",
    "EMPTY_CAPTURE",
    "NOT_RECOGNISED",
    "NO_CAPTURE",
    "TRUNCATED",
    "forwarding_for_host",
    "interface_key",
    "parse_route_table",
    "subnets_for_host",
]

ACCESS_LISTS = "Access lists"
NO_CAPTURE = "Route table (no SSH capture)"


def parse_route_table(text: str, device_type: str) -> tuple[list[dict], list[str]]:
    """Routes of a route table capture of a ``device_type`` host as
    forwarding routes, and the names of what could not be parsed."""
    return _parse_capture(text, platform_of(device_type).routes)


def _interface_kind(name: str, has_address: bool, conf: ConfigInterface | None = None) -> str:
    if conf is not None and conf.kind:
        return conf.kind
    key = interface_key(name)
    for prefix, kind in (("vlan", "svi"), ("loopback", "loopback"), ("tunnel", "tunnel"), ("management", "management")):
        if key.startswith(prefix):
            return kind
    return "routed" if has_address else ""


def _config(platform: Platform, config_backup: dict | None) -> RunningConfig | None:
    """The parsed configuration backup of a host whose platform is read."""
    if config_backup is None or platform.config is None:
        return None
    text = str(config_backup.get("config_text") or "")
    return platform.config(text) if text.strip() else None


def _zone(conf: ConfigInterface, names: dict[str, str]) -> str:
    """The name the rules match a configured interface by: its zone or
    nameif when the platform has them, else the interface's name."""
    return conf.zone or names.get(interface_key(conf.name), conf.name)


def _rules(entries: list, *, src_zones: list[str] | None = None, dst_zones: list[str] | None = None) -> list[dict]:
    return [
        rule(
            entry.sequence if entry.sequence is not None else position,
            entry.action,
            name=entry.name,
            enabled=entry.enabled,
            protocol=entry.protocol,
            src=entry.src,
            src_ports=entry.src_ports,
            dst=entry.dst,
            dst_ports=entry.dst_ports,
            comment=entry.comment,
            unresolved=entry.unresolved,
            established=entry.established,
            src_zones=src_zones if src_zones is not None else (entry.src_zones or None),
            dst_zones=dst_zones if dst_zones is not None else (entry.dst_zones or None),
        )
        for position, entry in enumerate(entries, start=1)
    ]


def _acl_policies(config: RunningConfig, names: dict[str, str]) -> list[dict[str, Any]]:
    """One rule set per access list binding (``ip access-group`` and its
    kin), bound to its interface and direction, ending in the implicit deny,
    then the rule sets the configuration applies to every flow (zone
    policies, a global access list). The access lists are stateless on a
    switch or router and stateful on an ASA; each policy says for itself.
    A binding to an access list the configuration does not define is
    unknown when a flow meets it."""
    policies: list[dict[str, Any]] = []
    stateful = config.stateful
    for conf in config.interfaces:
        name = names.get(interface_key(conf.name), conf.name)
        zone = _zone(conf, names)
        where = name if zone == name else f"{zone} ({name})"
        for direction in ("in", "out"):
            acl = conf.access_groups.get(direction)
            if not acl:
                continue
            src_zones = [zone] if direction == "in" else None
            dst_zones = [zone] if direction == "out" else None
            label = f"ACL {acl} {direction} on {where}"
            entries = config.access_lists.get(acl) or []
            if not entries:
                missing = f"access list {acl} (not in the configuration)"
                policies.append(
                    policy_set(
                        label,
                        "acl",
                        ANY,
                        [rule(1, "allow", unresolved=[missing], src_zones=src_zones, dst_zones=dst_zones)],
                        stateful=stateful,
                        default="unknown",
                        interface=name,
                        direction=direction,
                    )
                )
                continue
            rules = _rules(entries, src_zones=src_zones, dst_zones=dst_zones)
            policies.append(
                policy_set(
                    label, "acl", ANY, rules, stateful=stateful, default="deny", interface=name, direction=direction
                )
            )
    policies.extend(_policy(policy) for policy in config.policies)
    return policies


def _policy(policy: ConfigPolicy) -> dict[str, Any]:
    """A configured rule set applied to every flow, in forwarding terms."""
    return policy_set(
        policy.name, policy.kind, ANY, _rules(policy.entries), stateful=policy.stateful, default=policy.default
    )


def _configured_interfaces(
    name: str, conf: ConfigInterface, kind: str, vrf: str, up: bool, zone: str
) -> list[dict[str, Any]]:
    """The secondary addresses and the HSRP / VRRP / GLBP addresses of a
    configured interface, each an interface entry in the zone of the real
    one, so the flows sent to them arrive on it."""
    extra: list[dict[str, Any]] = []
    for address, cidr in conf.addresses[1:]:
        extra.append(
            interface(f"{name} (secondary {address})", kind, ip=address, cidr=cidr, zone=zone, vrf=vrf, enabled=up)
        )
    for virtual in conf.virtual:
        parsed = ipaddress.ip_address(virtual.address)
        holder = next((c for _a, c in conf.addresses if parsed in ipaddress.ip_network(c)), "")
        extra.append(
            interface(
                f"{name} ({virtual.protocol} {virtual.address})",
                kind,
                ip=virtual.address,
                cidr=holder,
                zone=zone,
                vrf=vrf,
                enabled=up,
            )
        )
    if conf.description:
        for entry in extra:
            entry["description"] = conf.description
    return extra


def forwarding_for_host(
    host: dict,
    aliases: list[str],
    route_capture: dict | None,
    interfaces: list[dict],
    *,
    config_backup: dict | None = None,
) -> dict[str, Any]:
    """The forwarding block of an inventory host: its interfaces, the routes
    of its latest SSH route capture and, from its latest configuration
    backup (``config_backup``, a ``config_backups`` row with
    ``config_text``) on Cisco IOS / IOS-XE and NX-OS, its interface access
    lists, addresses, VRFs, HSRP / VRRP addresses and the routes of the
    VRFs the capture lacks. Without a backup the access lists are not
    collected."""
    block = new_block()
    platform = platform_of(str(host.get("device_type") or ""))
    config = _config(platform, config_backup)
    if route_capture is None:
        routes: list[dict] = []
        missing = [NO_CAPTURE]
    else:
        routes, missing = _parse_capture(str(route_capture.get("routes_text") or ""), platform.routes)

    # What the connected and local routes say about each interface.
    cidr_of: dict[str, str] = {}
    ip_of: dict[str, str] = {}
    vrf_of: dict[str, str] = {}
    spelled: dict[str, str] = {}
    for item in routes:
        if item["kind"] != "connected" or not item["interface"]:
            continue
        key = interface_key(item["interface"])
        spelled.setdefault(key, item["interface"])
        vrf_of.setdefault(key, item["vrf"])
        network = ipaddress.ip_network(item["prefix"])
        if item["source"] == LOCAL and network.num_addresses == 1:
            ip_of.setdefault(key, str(network.network_address))
        elif network.num_addresses > 1:
            cidr_of.setdefault(key, item["prefix"])

    # The configuration names interfaces first, then SNMP, then the route table.
    # An interface's aliases (an ASA nameif) are the same interface.
    configured: dict[str, ConfigInterface] = {}
    for each in config.interfaces if config else []:
        for alias in (each.name, *each.aliases):
            configured.setdefault(interface_key(alias), each)
    names: dict[str, str] = {key: conf.name for key, conf in configured.items()}
    enabled: dict[str, bool] = {}
    for row in interfaces:
        name = str((row or {}).get("name") or "").strip()
        if not name or interface_key(name) in enabled:
            continue
        names.setdefault(interface_key(name), name)
        enabled[interface_key(name)] = str(row.get("admin_state") or "").strip().lower() != "down"
    for key, name in spelled.items():
        names.setdefault(key, name)

    for key, name in names.items():
        conf = configured.get(key)
        if conf is not None and key != interface_key(conf.name):
            continue  # an alias of an interface listed under its own name
        up = enabled.get(key, True) and not (conf is not None and conf.shutdown)
        if conf is not None and conf.addresses:
            ip, cidr = conf.addresses[0]
        else:
            ip, cidr = ip_of.get(key, ""), cidr_of.get(key, "")
        vrf = vrf_name(conf.vrf) if conf is not None else vrf_of.get(key, "")
        kind = _interface_kind(name, bool(ip or cidr), conf)
        # A configured interface is its own zone (or its platform's zone or
        # nameif): its access lists and the policies match by it.
        zone = _zone(conf, names) if conf is not None else ""
        entry = interface(name, kind, ip=ip, cidr=cidr, zone=zone, vrf=vrf, enabled=up)
        if conf is not None and conf.description:
            entry["description"] = conf.description
        block["interfaces"].append(entry)
        if conf is not None:
            block["interfaces"].extend(_configured_interfaces(name, conf, kind, vrf, up, zone))
    # Routes name interfaces the way the block does.
    for item in routes:
        if item["interface"]:
            item["interface"] = names.get(interface_key(item["interface"]), item["interface"])

    if config is not None:
        # The connected and static routes of every VRF the capture has no
        # table for (all of them without a capture). A VRF it has is taken
        # as captured: a configured static route missing from it is not
        # installed (a floating route, or its next hop is down).
        captured = {item["vrf"] for item in routes}
        for conf in config.interfaces:
            vrf = vrf_name(conf.vrf)
            if vrf in captured or conf.shutdown:
                continue
            name = names.get(interface_key(conf.name), conf.name)
            for _address, cidr in conf.addresses:
                routes.append(route_entry(cidr, "connected", iface=name, vrf=vrf, source=f"Connected {name}"))
        for static in config.static_routes:
            vrf = vrf_name(static.vrf)
            if vrf in captured:
                continue
            iface = names.get(interface_key(static.interface), static.interface) if static.interface else ""
            source = f"Static route {static.name}".strip()
            routes.append(
                route_entry(
                    static.prefix,
                    "static",
                    next_hop=static.next_hop,
                    iface=iface,
                    vrf=vrf,
                    metric=static.distance,
                    source=source,
                )
            )
        if route_capture is None:
            # The configuration names the routing protocols whose routes are missing.
            missing = [f"Routes learned by {protocol}" for protocol in config.routing]
        block["policies"] = _acl_policies(config, names)
        block["nat"] = list(config.nat)
    block["routes"] = routes

    # The host's own addresses: on the interface whose network holds them
    # when that interface has no address yet, else an interface of their own.
    for address in [str(host.get("ip_address") or "").strip(), *(str(a or "").strip() for a in aliases)]:
        if not is_address(address) or any(i["ip"] == address for i in block["interfaces"]):
            continue
        parsed = ipaddress.ip_address(address)
        holders = [i for i in block["interfaces"] if i["cidr"] and parsed in ipaddress.ip_network(i["cidr"])]
        if len(holders) == 1 and not holders[0]["ip"]:
            holders[0]["ip"] = address
            continue
        covering = holders[0]["cidr"] if holders else ""
        block["interfaces"].append(interface(address, "", ip=address, cidr=covering))

    if config is None:
        note(block, ACCESS_LISTS)
    else:
        for name in config.notes:
            note(block, name)
    for name in missing:
        note(block, name)
    return block


_VLAN_ID = re.compile(r"^vlan(\d+)$")


def subnets_for_host(node: dict, block: dict) -> list[dict[str, Any]]:
    """The networks of an inventory host as ``subnet_index`` rows, so they
    can be picked as path ends and swept: each interface network (``svi``,
    named ``VLAN <id> <description>``, for a VLAN interface; ``connected``,
    named by the interface and its description, for any other) and each
    static route (``static``). ``node`` is the host's graph node: its id is
    the ``node_id``, its inventory group the site. Default routes, host
    addresses, loopbacks and management interfaces are left out."""
    host_id = str(node.get("id"))
    group_id = node.get("group_id")
    found: dict[str, dict[str, Any]] = {}

    def add(cidr: str, kind: str, name: str) -> None:
        network = ipaddress.ip_network(cidr)
        if network.prefixlen == 0 or network.num_addresses == 1 or cidr in found:
            return
        found[cidr] = {
            "cidr": cidr,
            "name": name.strip(),
            "kind": kind,
            "site_id": "" if group_id is None else str(group_id),
            "site_name": str(node.get("group_name") or ""),
            "node_id": host_id,
            "in_vpn": None,
            "org_ref": INVENTORY_ORG_REF,
            "provider": PROVIDER_INVENTORY,
            "org_name": "Inventory",
        }

    for entry in block.get("interfaces") or []:
        if not isinstance(entry, dict) or not entry.get("cidr") or entry.get("kind") in ("loopback", "management"):
            continue
        base = str(entry.get("zone") or entry.get("name") or "")
        description = str(entry.get("description") or "")
        vlan = _VLAN_ID.match(interface_key(base))
        secondary = " (secondary)" if "(secondary " in str(entry.get("name") or "") else ""
        if entry.get("kind") == "svi" and vlan:
            add(entry["cidr"], "svi", f"VLAN {vlan.group(1)} {description}".strip() + secondary)
        else:
            add(entry["cidr"], "connected", f"{base} {description}".strip() + secondary)
    for item in block.get("routes") or []:
        if isinstance(item, dict) and item.get("kind") == "static" and canonical(item.get("prefix")):
            via = item.get("next_hop") or item.get("interface") or ""
            add(canonical(item["prefix"]), "static", f"Static route via {via}" if via else "Static route")

    def order(row: dict[str, Any]) -> tuple:
        network = ipaddress.ip_network(row["cidr"])
        return (network.version, int(network.network_address), network.prefixlen)

    return sorted(found.values(), key=order)
