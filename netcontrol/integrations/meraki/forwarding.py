"""The ``forwarding`` block of a snapshot node, and the Meraki side of it.

A node that forwards traffic carries ``node["forwarding"]``: its interfaces,
routes, policy-based VPN selectors, rule sets in the order the device applies
them, NAT rules in evaluation order, and what the device applies that was
not collected. Path tracing (``netcontrol.integrations.pathtrace``) walks a
flow over these blocks hop by hop. Every integration emits the same schema;
the helpers at the top of this module build its parts so they all agree.

The Meraki part reads the raw Dashboard payloads the snapshot builder holds:
an MX gets its VLANs, uplinks, static, AutoVPN, non-Meraki VPN and default
routes, its Layer 3, site-to-site VPN and inbound firewall rules and its NAT;
an L3 switch its SVIs, static routes and the network's switch ACL; a
non-Meraki VPN peer the private subnets it was configured with. Meraki
address syntax (``VLAN(30).*``, ``Any``, comma lists) is resolved here; what
cannot be turned into addresses is kept in a rule's ``unresolved`` list.

Pure (no I/O).
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

FORWARDING_VERSION = 1

ANY = "any"
# The NAT pseudo address for "the address of the egress / ingress interface".
INTERFACE = "interface"

_VLAN_ADDRESS = re.compile(r"^vlan\((\d+)\)\.(\*|\d+)$", re.IGNORECASE)
_PORT_EXPRESSION = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
_PROTOCOLS = {
    "any": ANY,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmp6": "icmpv6",
    "icmpv6": "icmpv6",
}
# Meraki NAT rules name the uplink by its internet number.
_NAT_UPLINKS = {"internet1": "wan1", "internet2": "wan2", "internet3": "wan3", "both": "", "any": ""}
_LIVE_UPLINK = ("active", "ready")
_DOWN_UPLINK = ("failed", "not connected")


# ── Schema helpers shared by every integration ───────────────────────────────


def new_block() -> dict[str, Any]:
    """An empty forwarding block: every key present."""
    return {
        "version": FORWARDING_VERSION,
        "interfaces": [],
        "routes": [],
        "vpn": [],
        "policies": [],
        "nat": [],
        "not_collected": [],
    }


def canonical(raw: Any) -> str:
    """The canonical network of ``raw`` (a host becomes /32 or /128), or
    ``""`` when it is not an address or a network."""
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return ""


def is_address(raw: Any) -> bool:
    try:
        ipaddress.ip_address(str(raw or "").strip())
        return True
    except ValueError:
        return False


def interface(
    name: str, kind: str, *, ip: str = "", cidr: str = "", zone: str = "", vrf: str = "", enabled: bool = True
) -> dict[str, Any]:
    return {
        "name": name,
        "kind": kind,
        "ip": ip if is_address(ip) else "",
        "cidr": canonical(cidr) if cidr else "",
        "zone": zone,
        "vrf": vrf,
        "enabled": bool(enabled),
    }


def route(
    prefix: str,
    kind: str,
    *,
    next_hop: str = "",
    interface: str = "",
    peer: dict | None = None,
    vrf: str = "",
    metric: int | None = None,
    enabled: bool = True,
    source: str = "",
    advertised: bool | None = None,
) -> dict[str, Any]:
    return {
        "prefix": prefix,
        "kind": kind,
        "next_hop": next_hop if is_address(next_hop) else "",
        "interface": interface,
        "peer": peer,
        "vrf": vrf,
        "metric": metric,
        "enabled": bool(enabled),
        "source": source,
        "advertised": advertised,
    }


def policy_set(
    name: str,
    kind: str,
    applies: str,
    rules: list[dict],
    *,
    stateful: bool = True,
    default: str = "allow",
    complete: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "kind": kind,
        "applies": applies,
        "stateful": stateful,
        "default": default,
        "complete": complete,
        "rules": rules,
    }


def rule(
    index: int,
    action: str,
    *,
    name: str = "",
    enabled: bool = True,
    protocol: str = ANY,
    src: list[str] | None = None,
    src_ports: str = ANY,
    dst: list[str] | None = None,
    dst_ports: str = ANY,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    comment: str = "",
    unresolved: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "index": index,
        "name": name,
        "action": action,
        "enabled": bool(enabled),
        "protocol": protocol,
        "src": list(src or [ANY]),
        "src_ports": src_ports or ANY,
        "dst": list(dst or [ANY]),
        "dst_ports": dst_ports or ANY,
        "src_zones": list(src_zones or []),
        "dst_zones": list(dst_zones or []),
        "comment": comment,
        "unresolved": list(dict.fromkeys(unresolved or [])),
    }


def nat(
    index: int,
    kind: str,
    *,
    name: str = "",
    enabled: bool = True,
    original_src: list[str] | None = None,
    original_dst: list[str] | None = None,
    translated_src: list[str] | None = None,
    translated_dst: list[str] | None = None,
    protocol: str = ANY,
    original_port: str = "",
    translated_port: str = "",
    src_interface: str = "",
    dst_interface: str = "",
    allowed_src: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "index": index,
        "kind": kind,
        "name": name,
        "enabled": bool(enabled),
        "original_src": list(original_src or [ANY]),
        "original_dst": list(original_dst or [ANY]),
        "translated_src": list(translated_src or []),
        "translated_dst": list(translated_dst or []),
        "protocol": protocol or ANY,
        "original_port": original_port,
        "translated_port": translated_port,
        "src_interface": src_interface,
        "dst_interface": dst_interface,
        "allowed_src": list(allowed_src if allowed_src is not None else [ANY]),
    }


def note(block: dict[str, Any], text: str) -> None:
    """Add ``text`` to ``not_collected`` once."""
    if text and text not in block["not_collected"]:
        block["not_collected"].append(text)


def share(block: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``block`` for another member of an HA pair or cluster."""
    return copy.deepcopy(block)


# ── Meraki values ────────────────────────────────────────────────────────────


def meraki_addresses(raw: Any, vlans: dict[str, str]) -> tuple[list[str], list[str]]:
    """``(cidrs, unresolved)`` of a Meraki address field.

    ``Any`` is every address; a comma list is resolved item by item;
    ``VLAN(30).*`` is the subnet of VLAN 30, ``VLAN(30).17`` the host 17 of
    it; an address is a /32 (or /128); a network is made canonical. An FQDN,
    a group policy, or a VLAN this network does not have is unresolved.
    """
    text = str(raw if raw is not None else "").strip()
    if not text or text.lower() == ANY:
        return [ANY], []
    cidrs: list[str] = []
    unresolved: list[str] = []
    for part in (p.strip() for p in text.split(",")):
        if not part:
            continue
        if part.lower() == ANY:
            return [ANY], []
        match = _VLAN_ADDRESS.match(part)
        if match:
            subnet = vlans.get(match.group(1))
            if not subnet:
                unresolved.append(part)
                continue
            if match.group(2) == "*":
                cidrs.append(subnet)
                continue
            network = ipaddress.ip_network(subnet)
            host = network.network_address + int(match.group(2))
            if host in network:
                cidrs.append(f"{host}/{network.max_prefixlen}")
            else:
                unresolved.append(part)
            continue
        cidr = canonical(part)
        if cidr:
            cidrs.append(cidr)
        else:
            unresolved.append(part)
    return list(dict.fromkeys(cidrs)), unresolved


def meraki_ports(raw: Any) -> tuple[str, list[str]]:
    """A Meraki port field as a port expression, and what is not one."""
    text = str(raw if raw is not None else "").strip().replace(" ", "")
    if not text or text.lower() == ANY:
        return ANY, []
    if _PORT_EXPRESSION.match(text):
        return text, []
    return ANY, [f"port {text}"]


def meraki_protocol(raw: Any) -> tuple[str, list[str]]:
    text = str(raw if raw is not None else "").strip().lower()
    if not text:
        return ANY, []
    if text in _PROTOCOLS:
        return _PROTOCOLS[text], []
    if text.isdigit():
        return text, []
    return ANY, [f"protocol {raw}"]


def _field(raw: Any, vlans: dict[str, str]) -> tuple[list[str], list[str]]:
    """An address field of a rule. A field Plexus cannot resolve in full is
    treated as matching every address, with the names kept as unresolved,
    so a flow it might cover is reported as unknown, never as allowed."""
    cidrs, unresolved = meraki_addresses(raw, vlans)
    if unresolved:
        return [ANY], unresolved
    return cidrs, []


def meraki_rules(
    rules: Any, vlans: dict[str, str], *, dst_key: str = "destCidr", dst_port_key: str = "destPort"
) -> list[dict]:
    """Dashboard firewall rules (L3, inbound, site-to-site VPN, switch ACL) as
    forwarding rules, in the Dashboard's order, its trailing default rule
    included."""
    found: list[dict] = []
    for index, item in enumerate((r for r in rules or [] if isinstance(r, dict)), start=1):
        src, unresolved_src = _field(item.get("srcCidr"), vlans)
        dst, unresolved_dst = _field(item.get(dst_key), vlans)
        src_ports, bad_src = meraki_ports(item.get("srcPort"))
        dst_ports, bad_dst = meraki_ports(item.get(dst_port_key))
        protocol, bad_protocol = meraki_protocol(item.get("protocol"))
        unresolved = unresolved_src + unresolved_dst + bad_src + bad_dst + bad_protocol
        vlan = str(item.get("vlan") if item.get("vlan") is not None else "").strip()
        if vlan and vlan.lower() != ANY:
            # A switch ACL rule limited to one VLAN: Plexus does not know the VLAN of a flow.
            unresolved.append(f"VLAN {vlan}")
        policy = str(item.get("policy") or "").strip().lower()
        found.append(
            rule(
                index,
                "allow" if policy == "allow" else "deny",
                protocol=protocol,
                src=src,
                src_ports=src_ports,
                dst=dst,
                dst_ports=dst_ports,
                comment=str(item.get("comment") or ""),
                unresolved=unresolved,
            )
        )
    return found


def _rules_of(payload: Any) -> list[dict]:
    if isinstance(payload, dict):
        payload = payload.get("rules")
    return [r for r in payload or [] if isinstance(r, dict)] if isinstance(payload, list) else []


def _allowed(values: Any) -> list[str]:
    """``allowedIps`` of a NAT rule as CIDRs (``any`` for every source)."""
    found: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if text.lower() == ANY:
            return [ANY]
        cidr = canonical(text)
        if cidr:
            found.append(cidr)
    return list(dict.fromkeys(found))


def _nat_uplink(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    return _NAT_UPLINKS.get(text, text)


def _port_text(raw: Any) -> str:
    return str(raw if raw is not None else "").strip()


# ── Meraki blocks ────────────────────────────────────────────────────────────


def _vlan_subnets(detail: dict) -> dict[str, str]:
    return {
        str(v.get("id")): canonical(v.get("subnet"))
        for v in detail.get("vlans") or []
        if isinstance(v, dict) and canonical(v.get("subnet"))
    }


def _advertised(detail: dict, vpn: dict) -> dict[str, bool]:
    """Subnet -> whether the site advertises it into AutoVPN."""
    found: dict[str, bool] = {}
    s2s = detail.get("site_to_site_vpn") or {}
    for item in s2s.get("subnets") or []:
        if isinstance(item, dict) and canonical(item.get("localSubnet")):
            found[canonical(item.get("localSubnet"))] = bool(item.get("useVpn"))
    if not found:
        for item in vpn.get("exportedSubnets") or []:
            if isinstance(item, dict) and canonical(item.get("subnet")):
                found[canonical(item.get("subnet"))] = True
    return found


def _exported(detail: dict, vpn: dict) -> list[tuple[str, str]]:
    """``(subnet, name)`` a site exports into AutoVPN."""
    exported = [
        (canonical(s.get("subnet")), str(s.get("name") or ""))
        for s in vpn.get("exportedSubnets") or []
        if isinstance(s, dict) and canonical(s.get("subnet"))
    ]
    if exported:
        return exported
    s2s = detail.get("site_to_site_vpn") or {}
    return [
        (canonical(s.get("localSubnet")), "")
        for s in s2s.get("subnets") or []
        if isinstance(s, dict) and s.get("useVpn") and canonical(s.get("localSubnet"))
    ]


def _interface_for(address: str, interfaces: list[dict]) -> str:
    """The name of the interface whose network holds ``address``."""
    if not is_address(address):
        return ""
    parsed = ipaddress.ip_address(address)
    for item in interfaces:
        if item["cidr"] and parsed in ipaddress.ip_network(item["cidr"]):
            return item["name"]
    return ""


def appliance_block(
    *,
    detail: dict,
    vpn: dict,
    vpn_by_net: dict[str, dict],
    net_details: dict[str, dict],
    net_names: dict[str, str],
    uplinks: list[dict],
    peers_cfg: dict[str, dict],
    vpn_firewall: Any,
) -> dict[str, Any]:
    """The forwarding block of a site's MX (and of its warm spare)."""
    block = new_block()
    vlans = _vlan_subnets(detail)
    advertised = _advertised(detail, vpn)

    # Interfaces: VLANs (or the single LAN) and the WAN uplinks.
    names: dict[str, str] = {}
    for vlan in detail.get("vlans") or []:
        if not isinstance(vlan, dict) or not canonical(vlan.get("subnet")):
            continue
        name = f"VLAN {vlan.get('id')}"
        names[name] = str(vlan.get("name") or "")
        block["interfaces"].append(interface(name, "vlan", ip=str(vlan.get("applianceIp") or ""), cidr=vlan["subnet"]))
    single = detail.get("single_lan") or {}
    if isinstance(single, dict) and canonical(single.get("subnet")):
        block["interfaces"].append(
            interface("LAN", "lan", ip=str(single.get("applianceIp") or ""), cidr=single["subnet"])
        )
    for uplink in uplinks:
        if not isinstance(uplink, dict) or not uplink.get("interface"):
            continue
        status = str(uplink.get("status") or "").lower()
        block["interfaces"].append(
            interface(
                str(uplink["interface"]),
                "wan",
                ip=str(uplink.get("ip") or ""),
                enabled=status not in _DOWN_UPLINK,
            )
        )

    # Routes: connected, static, exported, AutoVPN, non-Meraki VPN, WAN default.
    for item in block["interfaces"]:
        if item["kind"] in ("vlan", "lan") and item["cidr"]:
            label = f"{item['name']} {names.get(item['name'], '')}".strip()
            block["routes"].append(
                route(
                    item["cidr"],
                    "connected",
                    interface=item["name"],
                    source=f"Connected {label}",
                    advertised=advertised.get(item["cidr"]) if advertised else None,
                )
            )
    for static in detail.get("static_routes") or []:
        if not isinstance(static, dict) or not static.get("enabled", True) or not canonical(static.get("subnet")):
            continue
        gateway = str(static.get("gatewayIp") or "")
        in_vpn = static.get("inVpn")
        block["routes"].append(
            route(
                canonical(static["subnet"]),
                "static",
                next_hop=gateway,
                interface=_interface_for(gateway, block["interfaces"]),
                source=f"Static route {static.get('name') or ''}".strip(),
                advertised=bool(in_vpn) if in_vpn is not None else None,
            )
        )
    # Networks the site exports that are neither VLANs nor static routes (a
    # vMX's VPC ranges) sit behind its uplink, ahead of the same range from a peer.
    covered = [ipaddress.ip_network(r["prefix"]) for r in block["routes"] if canonical(r["prefix"])]
    # A VLAN exported under VPN NAT is the VLAN itself.
    covered += [
        ipaddress.ip_network(canonical(v.get("vpnNatSubnet")))
        for v in detail.get("vlans") or []
        if isinstance(v, dict) and canonical(v.get("vpnNatSubnet"))
    ]
    live = next(
        (
            u
            for u in uplinks
            if isinstance(u, dict)
            and str(u.get("status") or "").lower() in _LIVE_UPLINK
            and u.get("gateway")
            and u.get("interface")
        ),
        None,
    )
    for subnet, name in _exported(detail, vpn):
        network = ipaddress.ip_network(subnet)
        if any(network.version == c.version and network.subnet_of(c) for c in covered):  # type: ignore[arg-type]
            continue
        covered.append(network)
        block["routes"].append(
            route(
                subnet,
                "static",
                next_hop=str(live["gateway"]) if live else "",
                interface=str(live["interface"]) if live else "",
                source=f"Site-to-site VPN local network {name}".strip(),
                advertised=True,
            )
        )
    for peer in vpn.get("merakiVpnPeers") or []:
        if not isinstance(peer, dict) or not peer.get("networkId"):
            continue
        peer_id = str(peer["networkId"])
        peer_name = peer.get("networkName") or net_names.get(peer_id) or peer_id
        for subnet, _name in _exported(net_details.get(peer_id) or {}, vpn_by_net.get(peer_id) or {}):
            block["routes"].append(
                route(subnet, "autovpn", peer={"site": peer_id}, source=f"AutoVPN from {peer_name}", advertised=True)
            )
    s2s = detail.get("site_to_site_vpn") or {}
    for hub in s2s.get("hubs") or []:
        if isinstance(hub, dict) and hub.get("useDefaultRoute") and hub.get("hubId"):
            hub_id = str(hub["hubId"])
            block["routes"].append(
                route(
                    "0.0.0.0/0",
                    "autovpn",
                    peer={"site": hub_id},
                    source=f"AutoVPN default route via {net_names.get(hub_id) or hub_id}",
                )
            )
    for peer in vpn.get("thirdPartyVpnPeers") or []:
        if not isinstance(peer, dict):
            continue
        name = str(peer.get("name") or peer.get("publicIp") or "peer")
        for subnet in (peers_cfg.get(str(peer.get("name"))) or {}).get("privateSubnets") or []:
            if canonical(subnet):
                block["routes"].append(
                    route(
                        canonical(subnet),
                        "vpn3p",
                        peer={"org_node": f"p:{name}"},
                        source=f"Non-Meraki VPN peer {name}",
                    )
                )
    for uplink in uplinks:
        status = str((uplink or {}).get("status") or "").lower()
        if status in _LIVE_UPLINK and uplink.get("gateway") and uplink.get("interface"):
            block["routes"].append(
                route(
                    "0.0.0.0/0",
                    "default",
                    next_hop=str(uplink["gateway"]),
                    interface=str(uplink["interface"]),
                    source=f"Default route via {uplink['interface']} ({status})",
                )
            )

    # Policies, in the order the MX applies them.
    if "l3_firewall" in detail:
        block["policies"].append(
            policy_set(
                "Layer 3 firewall rules",
                "firewall",
                "lan_in",
                meraki_rules(_rules_of(detail.get("l3_firewall")), vlans),
            )
        )
    else:
        note(block, "Layer 3 firewall rules")
    mode = str(vpn.get("vpnMode") or s2s.get("mode") or "none").lower()
    if mode != "none":
        if vpn_firewall is not None:
            block["policies"].append(
                policy_set(
                    "Site-to-site VPN firewall rules",
                    "vpn_firewall",
                    "vpn_out",
                    meraki_rules(_rules_of(vpn_firewall), vlans),
                )
            )
        else:
            note(block, "Site-to-site VPN firewall rules")
    if "inbound_firewall" in detail:
        block["policies"].append(
            policy_set(
                "Inbound firewall rules",
                "inbound",
                "wan_in",
                meraki_rules(_rules_of(detail.get("inbound_firewall")), vlans),
                default="deny",
            )
        )
    else:
        note(block, "Inbound firewall rules")

    block["nat"] = _appliance_nat(detail, block)
    note(block, "Layer 7 firewall rules")
    note(block, "Group policies")
    bgp = detail.get("bgp") or {}
    if isinstance(bgp, dict) and bgp.get("enabled"):
        note(block, "Routes learned by BGP")
    return block


def _appliance_nat(detail: dict, block: dict) -> list[dict]:
    entries: list[dict] = []

    def add(kind: str, **fields: Any) -> None:
        entries.append(nat(len(entries) + 1, kind, **fields))

    if "one_to_one_nat" in detail:
        for item in _rules_of(detail.get("one_to_one_nat")):
            public, lan = canonical(item.get("publicIp")), canonical(item.get("lanIp"))
            if not public or not lan:
                continue
            allowed: list[str] = []
            for inbound in item.get("allowedInbound") or []:
                if isinstance(inbound, dict):
                    allowed += _allowed(inbound.get("allowedIps"))
            allowed = [ANY] if ANY in allowed else list(dict.fromkeys(allowed))
            add(
                "one_to_one",
                name=str(item.get("name") or ""),
                original_dst=[public],
                translated_dst=[lan],
                dst_interface=_nat_uplink(item.get("uplink")),
                allowed_src=allowed,
            )
    else:
        note(block, "1:1 NAT")
    if "port_forwarding" in detail:
        for item in _rules_of(detail.get("port_forwarding")):
            lan = canonical(item.get("lanIp"))
            if not lan:
                continue
            protocol, _bad = meraki_protocol(item.get("protocol"))
            add(
                "port_forward",
                name=str(item.get("name") or ""),
                original_dst=[INTERFACE],
                translated_dst=[lan],
                protocol=protocol,
                original_port=_port_text(item.get("publicPort")),
                translated_port=_port_text(item.get("localPort")),
                dst_interface=_nat_uplink(item.get("uplink")),
                allowed_src=_allowed(item.get("allowedIps")),
            )
    else:
        note(block, "Port forwarding")
    if "one_to_many_nat" in detail:
        for item in _rules_of(detail.get("one_to_many_nat")):
            public = canonical(item.get("publicIp"))
            if not public:
                continue
            for port_rule in item.get("portRules") or []:
                if not isinstance(port_rule, dict) or not canonical(port_rule.get("localIp")):
                    continue
                protocol, _bad = meraki_protocol(port_rule.get("protocol"))
                add(
                    "one_to_many",
                    name=str(port_rule.get("name") or ""),
                    original_dst=[public],
                    translated_dst=[canonical(port_rule["localIp"])],
                    protocol=protocol,
                    original_port=_port_text(port_rule.get("publicPort")),
                    translated_port=_port_text(port_rule.get("localPort")),
                    dst_interface=_nat_uplink(item.get("uplink")),
                    allowed_src=_allowed(port_rule.get("allowedIps")),
                )
    else:
        note(block, "1:Many NAT")
    for vlan in detail.get("vlans") or []:
        if isinstance(vlan, dict) and canonical(vlan.get("subnet")) and canonical(vlan.get("vpnNatSubnet")):
            # Applies to traffic leaving over AutoVPN only.
            add(
                "vpn_nat",
                name=f"VPN NAT VLAN {vlan.get('id')}",
                original_src=[canonical(vlan["subnet"])],
                translated_src=[canonical(vlan["vpnNatSubnet"])],
            )
    # The MX hides LAN sources behind the uplink address on the way out (WAN
    # egress only). An MX with no LAN at all is in passthrough or VPN
    # concentrator mode (a vMX in a VPC): it bridges and does not translate.
    if any(i.get("kind") in ("vlan", "lan") for i in block.get("interfaces") or []):
        add("interface_pat", name="Uplink address", original_src=[ANY], translated_src=[INTERFACE])
    return entries


def switch_block(
    *, svis: list[dict], static_routes: list[dict], acl: Any, ospf_enabled: bool, vlans: dict[str, str]
) -> dict[str, Any]:
    """The forwarding block of an L3 switch (or stack)."""
    block = new_block()
    used: set[str] = set()
    for svi in svis:
        if not isinstance(svi, dict) or not canonical(svi.get("subnet")):
            continue
        name = str(svi.get("name") or f"VLAN {svi.get('vlanId')}")
        if name in used:
            name = f"{name} (VLAN {svi.get('vlanId')})"
        used.add(name)
        block["interfaces"].append(interface(name, "svi", ip=str(svi.get("interfaceIp") or ""), cidr=svi["subnet"]))
        block["routes"].append(route(canonical(svi["subnet"]), "connected", interface=name, source=f"Connected {name}"))
    has_default = False
    for static in static_routes:
        if not isinstance(static, dict) or not canonical(static.get("subnet")):
            continue
        prefix = canonical(static["subnet"])
        has_default = has_default or prefix in ("0.0.0.0/0", "::/0")
        hop = str(static.get("nextHopIp") or "")
        block["routes"].append(
            route(
                prefix,
                "static",
                next_hop=hop,
                interface=_interface_for(hop, block["interfaces"]),
                enabled=static.get("enabled", True) is not False,
                source=f"Static route {static.get('name') or ''}".strip(),
            )
        )
    if not has_default:
        for svi in svis:
            gateway = str((svi or {}).get("defaultGateway") or "") if isinstance(svi, dict) else ""
            if is_address(gateway):
                block["routes"].append(
                    route(
                        "0.0.0.0/0",
                        "default",
                        next_hop=gateway,
                        interface=_interface_for(gateway, block["interfaces"]),
                        source="Default gateway of the switch",
                    )
                )
                break
    if acl is not None:
        block["policies"].append(
            policy_set(
                "Switch ACL",
                "acl",
                ANY,
                meraki_rules(_rules_of(acl), vlans, dst_key="dstCidr", dst_port_key="dstPort"),
                stateful=False,
            )
        )
    else:
        note(block, "Switch ACL")
    if ospf_enabled:
        note(block, "Routes learned by OSPF")
    return block


def peer_block(name: str, private_subnets: list[Any]) -> dict[str, Any]:
    """The forwarding block of a non-Meraki VPN peer: only what it was
    configured to hold."""
    block = new_block()
    for subnet in private_subnets:
        if canonical(subnet):
            block["routes"].append(route(canonical(subnet), "connected", source=f"Private subnet of {name}"))
    note(block, "Everything behind a non-Meraki VPN peer")
    return block
