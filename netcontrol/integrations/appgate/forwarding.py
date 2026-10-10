"""The ``forwarding`` block of each appliance and user of an Appgate snapshot.

Built from what the snapshot builder already read, in the schema of
``netcontrol.integrations.meraki.forwarding``:

  - every appliance: one interface per static address of each NIC with its
    connected route, and the static routes it was configured with (a route
    to ``0.0.0.0/0`` is its default route; a NIC on DHCP has a default route
    that was not read)
  - a Gateway also has the "Appgate client tunnel" interface, the networks
    of its site as ranges it delivers to, a ``/32`` route over the tunnel to
    each connected user, its source NAT (when the site translates client
    addresses to the Gateway's own), and the **Entitlements** of its site as
    a rule set applied to all traffic, first match wins, whose default
    drops what no entitlement allows. A rule's sources are the tunnel
    addresses of the connected users that hold the entitlement on this
    Gateway; without per-user access details they are any user, with
    "users granted by policy" kept unresolved so the trace says it cannot
    tell. A Gateway that only lets clients reach some networks gets an
    **Allowed destinations** rule set too
  - a user: its tunnel address, and a route over the tunnel of each Gateway
    to every network its entitlements there cover (and to the site's
    network subnets when the site routes by them, or everything when the
    site is the user's default gateway). Anything else leaves the device
    directly (split tunnel), so it has no route here.

An entitlement host that is not an address or a network (a hostname,
``dns://``, ``aws://``, ``azure://``, ``gcp://``) cannot be matched on
addresses: the rule is kept with it in ``unresolved``, so a flow it might
cover is reported as unknown. Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from netcontrol.integrations.appgate.normalize import (
    _Builder,
    _dict,
    _dicts,
    _list,
    _text,
    allowed_destinations,
    dhcp_nics,
    is_gateway,
    site_subnets,
    static_addresses,
    static_routes,
)
from netcontrol.integrations.meraki.forwarding import (
    ANY,
    INTERFACE,
    canonical,
    interface,
    nat,
    new_block,
    note,
    policy_set,
    route,
    rule,
)

TUNNEL_INTERFACE = "Appgate client tunnel"
CLIENT_INTERFACE = "Appgate Client"
ENTITLEMENTS = "Entitlements"
ALLOWED_DESTINATIONS = "Allowed destinations"
SPLIT_TUNNEL_NOTE = "Traffic no entitlement covers leaves the device directly (split tunnel)"
NO_DETAILS_NOTE = "Per-user access details were not read"
CONNECTOR_NOTE = "Connector client resources are not traced"
UNRESOLVED_USERS = "users granted by policy"
_DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")
_PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6", "ah": "ah", "esp": "esp", "gre": "gre"}
_ACTIONS = {"allow": "allow", "block": "deny", "alert": "allow"}


def pool_networks(builder: _Builder) -> tuple[list[str], list[str]]:
    """``(cidrs, ranges as text)`` of every IP pool range of the collective."""
    cidrs: list[str] = []
    texts: list[str] = []
    for pool in builder.ip_pools:
        for span in _dicts(pool.get("ranges")):
            first, last = _text(span.get("first")), _text(span.get("last"))
            try:
                start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
                blocks = list(ipaddress.summarize_address_range(start, end))
            except TypeError, ValueError:
                continue
            # A pool is usually a whole network less its first and last
            # address (10.253.0.1-10.253.3.254): that network, not 10 blocks.
            whole = ipaddress.ip_network(f"{start}/{start.max_prefixlen}").supernet(
                new_prefix=max(0, start.max_prefixlen - (int(end) - int(start) + 2).bit_length())
            )
            if int(whole.network_address) + 1 == int(start) and int(whole.broadcast_address) - 1 == int(end):
                blocks = [whole]
            cidrs += [str(n) for n in blocks]
            texts.append(f"{first}-{last}")
    return list(dict.fromkeys(cidrs)), texts


def host_targets(hosts: Any) -> tuple[list[str], list[str]]:
    """``(cidrs, unresolved)`` of an entitlement action's hosts. As with any
    address field, one host Plexus cannot resolve makes the field any
    address, with the names kept as unresolved."""
    cidrs: list[str] = []
    unresolved: list[str] = []
    for host in _list(hosts):
        cidr = canonical(host)
        if cidr:
            cidrs.append(cidr)
        elif _text(host):
            unresolved.append(f"host {_text(host)}")
    if unresolved:
        return [ANY], unresolved
    return list(dict.fromkeys(cidrs)) or [ANY], []


def _access(record: dict, gateway: str, name: str) -> bool:
    entry = record["gateways"].get(gateway) or {}
    info = _dict(_dict(entry.get("entitlementInfos")).get(name))
    return bool(info.get("access"))


class _ApplianceForwarding:
    def __init__(self, builder: _Builder, node_id: str) -> None:
        self.b = builder
        self.node_id = node_id
        self.appliance = builder.appliance_of[node_id]
        self.site_id = _text(self.appliance.get("site"))
        self.site = builder.site_by_id.get(self.site_id) or {}
        self.gateway = is_gateway(self.appliance)
        self.block = new_block()

    def interfaces_and_routes(self) -> None:
        block = self.block
        for nic, address, cidr, _snat in static_addresses(self.appliance):
            block["interfaces"].append(interface(nic, "lan", ip=address, cidr=cidr))
            block["routes"].append(route(cidr, "connected", interface=nic, source=f"Connected {nic}"))
        if self.gateway:
            block["interfaces"].append(interface(TUNNEL_INTERFACE, "tunnel"))
        has_default = False
        for prefix, gateway, nic in static_routes(self.appliance):
            default = prefix in _DEFAULT_ROUTES
            has_default = has_default or default
            block["routes"].append(
                route(
                    prefix,
                    "default" if default else "static",
                    next_hop=gateway,
                    interface=nic,
                    source=f"Static route via {gateway}" if gateway else "Static route",
                )
            )
        if not has_default:
            for nic in dhcp_nics(self.appliance):
                note(block, f"Default route of {nic} comes from DHCP and was not read")

    def gateway_routes(self) -> None:
        """The site's network subnets, and a route to each connected user."""
        block = self.block
        known = {r["prefix"] for r in block["routes"]}
        site_name = _text(self.site.get("name")) or self.site_id
        for cidr, comment in site_subnets(self.site):
            if cidr in known:
                continue
            known.add(cidr)
            name = f"Site network {cidr}"
            block["interfaces"].append(interface(name, "lan", cidr=cidr))
            block["routes"].append(
                route(cidr, "connected", interface=name, source=f"Site {site_name} network subnet {comment}".strip())
            )
        for record in self.b.users:
            address = canonical(record["tun_ip"])
            if address and self.node_id in record["gateways"]:
                block["routes"].append(
                    route(
                        address,
                        "static",
                        interface=TUNNEL_INTERFACE,
                        peer={"org_node": record["node_id"]},
                        source="Appgate client session",
                    )
                )
        via = _dict(_dict(self.site.get("vpn")).get("routeVia"))
        for key in ("ipv4", "ipv6"):
            if _text(via.get(key)):
                note(block, f"Clients are routed into the site via {_text(via[key])}")

    def gateway_nat(self) -> None:
        block = self.block
        cidrs, texts = pool_networks(self.b)
        if _dict(self.site.get("vpn")).get("snat"):
            block["nat"].append(
                nat(1, "interface_pat", name="Gateway SNAT", original_src=cidrs or [ANY], translated_src=[INTERFACE])
            )
        else:
            ranges = ", ".join(texts) or "the client IP pools"
            note(block, f"Client tunnel addresses are not translated: the site must route {ranges} back to the gateway")
        for mapping in _dicts(self.site.get("ipPoolMappings")):
            if _text(mapping.get("type")).lower() == "translation":
                note(
                    block,
                    f"Client addresses of pool {self.b.pool_name(mapping.get('from'))} are translated to "
                    f"pool {self.b.pool_name(mapping.get('to'))}",
                )

    def entitlements(self) -> None:
        block = self.block
        if not self.b.entitlements_collected:
            note(block, ENTITLEMENTS)
            return
        rules: list[dict] = []
        omitted: list[str] = []
        details = self.b.session_details_collected
        for entitlement in self.b.site_entitlements(self.site_id):
            if entitlement.get("disabled"):
                continue
            name = _text(entitlement.get("name"))
            if details:
                holders = [
                    canonical(r["tun_ip"])
                    for r in self.b.users
                    if self.node_id in r["gateways"] and canonical(r["tun_ip"]) and _access(r, self.node_id, name)
                ]
                if not holders:
                    omitted.append(name)
                    continue
                users, unresolved_users = list(dict.fromkeys(holders)), []
            else:
                users = [ANY]
                unresolved_users = [UNRESOLVED_USERS] + [f"condition {c}" for c in self.b.condition_names(entitlement)]
            for action in _dicts(entitlement.get("actions")):
                found = self._rule(len(rules) + 1, name, action, users, unresolved_users)
                if found is not None:
                    rules.append(found)
        # A Gateway drops what no entitlement allows.
        block["policies"].append(policy_set(ENTITLEMENTS, "firewall", ANY, rules, default="deny"))
        if omitted:
            note(block, f"Entitlements no connected user holds: {', '.join(omitted)}")

    @staticmethod
    def _rule(index: int, name: str, action: dict, users: list[str], unresolved_users: list[str]) -> dict | None:
        verdict = _text(action.get("action")).lower()
        if verdict not in _ACTIONS:
            return None  # exclude: not tunnelled, so never seen by the Gateway
        subtype = _text(action.get("subtype")).lower()
        base, _sep, direction = subtype.rpartition("_")
        hosts, unresolved = host_targets(action.get("hosts"))
        unresolved = [*unresolved_users, *unresolved]
        comments: list[str] = []
        if verdict == "alert":
            comments.append("alert")
        ports = ",".join(_text(p).replace(" ", "") for p in _list(action.get("ports")) if _text(p))
        if base == "http":
            protocol, ports = "tcp", ports or "80,443"
            unresolved.append("HTTP method rule")
        elif base in ("tcp", "udp"):
            protocol = base
        else:
            protocol = _PROTOCOLS.get(base, base or ANY)
            types = ", ".join(_text(t) for t in _list(action.get("types")) if _text(t))
            if base.startswith("icmp") and types:
                comments.append(f"ICMP types {types}")
            ports = ""
        src, dst = users, hosts
        if direction == "down":
            src, dst = hosts, users
            comments.append("(down: resource to client)")
        return rule(
            index,
            _ACTIONS[verdict],
            name=name,
            protocol=protocol,
            src=src,
            dst=dst,
            dst_ports=ports or ANY,
            comment=" ".join(comments),
            unresolved=unresolved,
        )

    def allowed(self) -> None:
        destinations = allowed_destinations(self.appliance)
        if not destinations:
            return
        rules = [
            rule(index, "allow", name=f"Allowed destination {cidr}", dst=[cidr])
            for index, (cidr, _nic) in enumerate(destinations, start=1)
        ]
        self.block["policies"].append(policy_set(ALLOWED_DESTINATIONS, "firewall", ANY, rules, default="deny"))

    def build(self) -> dict[str, Any]:
        self.interfaces_and_routes()
        if self.gateway:
            self.gateway_routes()
            self.gateway_nat()
            self.entitlements()
            self.allowed()
        if _dict(self.appliance.get("connector")).get("enabled"):
            note(self.block, CONNECTOR_NOTE)
        return self.block


def _user_block(builder: _Builder, record: dict) -> dict[str, Any]:
    block = new_block()
    address = canonical(record["tun_ip"])
    if address:
        block["interfaces"].append(interface(CLIENT_INTERFACE, "tunnel", ip=record["tun_ip"], cidr=address))
        block["routes"].append(
            route(address, "connected", interface=CLIENT_INTERFACE, source="Address given by Appgate")
        )
    else:
        block["interfaces"].append(interface(CLIENT_INTERFACE, "tunnel"))
    if record["detail"] is None:
        note(block, NO_DETAILS_NOTE)
        return block
    seen: set[tuple[str, str]] = set()
    has_default = False

    def add(prefix: str, gateway: str, source: str, kind: str = "static") -> None:
        if (prefix, gateway) not in seen:
            seen.add((prefix, gateway))
            block["routes"].append(route(prefix, kind, peer={"org_node": gateway}, source=source))

    for gateway, entry in record["gateways"].items():
        label = builder.nodes[gateway]["label"]
        for item in _dicts(entry.get("firewallRules")):
            if _text(item.get("action")).lower() != "allow" or _text(item.get("direction")).lower() != "up":
                continue
            for subnet in _list(item.get("subnets")):
                prefix = canonical(subnet)
                if prefix and prefix not in _DEFAULT_ROUTES:
                    add(prefix, gateway, f"Entitlement {_text(item.get('name'))} via {label}")
        site = builder.site_by_id.get(_text(builder.appliance_of[gateway].get("site"))) or {}
        site_name = _text(site.get("name"))
        if site and not site.get("entitlementBasedRouting"):
            for cidr, _comment in site_subnets(site):
                add(cidr, gateway, f"Site {site_name} network subnet")
        default = _dict(site.get("defaultGateway"))
        if default.get("enabledV4"):
            has_default = True
            add("0.0.0.0/0", gateway, f"Site {site_name} is the default gateway", "default")
            for excluded in _list(default.get("excludedSubnets")):
                if _text(excluded):
                    note(block, f"{_text(excluded)} is excluded from the default gateway {site_name}")
    if not has_default:
        note(block, SPLIT_TUNNEL_NOTE)
    return block


def build_forwarding(builder: _Builder) -> None:
    """Put the ``forwarding`` block on every appliance and user node of the
    builder. The collective forwards nothing."""
    for node_id in builder.appliance_of:
        builder.nodes[node_id]["forwarding"] = _ApplianceForwarding(builder, node_id).build()
    for record in builder.users:
        builder.nodes[record["node_id"]]["forwarding"] = _user_block(builder, record)
