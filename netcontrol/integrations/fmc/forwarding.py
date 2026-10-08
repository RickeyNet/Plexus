"""The ``forwarding`` block of each FTD of a Cisco FMC snapshot.

Built from what the snapshot builder already read (interfaces, routing,
site-to-site VPN endpoints, NAT, access control and prefilter rules), in the
schema of ``netcontrol.integrations.meraki.forwarding``:

  - interfaces by logical name, with their zone and virtual router; an
    outside interface (public address, default route egress or remote access
    VPN access interface) is ``wan``
  - connected and static routes; a static route to ``0.0.0.0/0`` or ``::/0``
    is a ``default`` route. Routes BGP, OSPF or EIGRP learn are not
    collected, nor what a policy-based route matches (an extended ACL)
  - one ``vpn`` entry per far end of each policy-based site-to-site topology
  - the prefilter rules, then the access control rules, both evaluated
    against the zones of the ingress and egress interfaces
  - NAT in evaluation order: manual before auto, auto, manual after auto

An HA pair shares the primary's block and a cluster the control unit's.
Pure (no I/O).
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.fmc.collector import DEFAULT_PREFILTER_NAME, MAX_ACCESS_RULES
from netcontrol.integrations.fmc.normalize import (
    _Builder,
    _dict,
    _dicts,
    _first,
    _ident,
    _kind,
    _name,
    _text,
    value_cidr,
)
from netcontrol.integrations.meraki.forwarding import (
    ANY,
    INTERFACE,
    interface,
    is_address,
    nat,
    new_block,
    note,
    policy_set,
    route,
    rule,
    share,
)

_PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}
_PROTOCOL_NAMES = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv4": "icmp", "icmpv6": "icmpv6", "any": ANY}
_ACCESS_ACTIONS = {
    "allow": "allow",
    "trust": "trust",
    "monitor": "monitor",
    "block": "deny",
    "blockreset": "deny",
    "blockinteractive": "deny",
    "blockresetinteractive": "deny",
    "interactiveblock": "deny",
    "interactiveblockreset": "deny",
}
_PREFILTER_ACTIONS = {"fastpath": "fastpath", "analyze": "analyze", "block": "deny"}
_DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")
_GEO_KINDS = ("geolocation", "country", "continent")


def _vrf(name: Any) -> str:
    text = _text(name)
    return "" if text.lower() in ("", "global") else text


def _protocol(raw: Any) -> str:
    text = _text(raw).lower()
    if text in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[text]
    return _PROTOCOL_NAMES.get(text, text or ANY)


class _Resolver:
    """Networks and ports of the FMC's objects, as CIDRs and port expressions."""

    def __init__(self, builder: _Builder) -> None:
        self.objects = builder.objects
        raw = _dict(builder.raw.get("objects"))
        self.ports: dict[str, dict] = {}
        for key in ("ports", "port_groups", "icmp"):
            for item in _dicts(raw.get(key)):
                if _ident(item):
                    self.ports.setdefault(_ident(item), item)
                if _text(item.get("name")):
                    self.ports.setdefault(_text(item.get("name")).lower(), item)

    def networks(self, block: Any) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of a networks block; ``["any"]`` when it is
        empty. A block Plexus cannot resolve in full matches every address,
        with the names kept as unresolved."""
        block = _dict(block) if not isinstance(block, list) else {"objects": block}
        refs = _dicts(block.get("objects")) + _dicts(block.get("networks")) + _dicts(block.get("literals"))
        if not refs:
            return [ANY], []
        cidrs: list[str] = []
        unresolved: list[str] = []
        for ref in refs:
            kind = _kind(ref.get("type"))
            if kind in _GEO_KINDS:
                unresolved.append(f"{ref.get('type')} {_name(ref)}".strip())
                continue
            if "value" in ref and not _ident(ref):
                cidr = value_cidr(ref.get("value"))
                (cidrs if cidr else unresolved).append(cidr or _text(ref.get("value")))
                continue
            if self.objects.get(ref) is None:
                unresolved.append(_name(ref) or _text(ref.get("value")) or "an object")
                continue
            for member, cidr in self.objects.expand(ref):
                (cidrs if cidr else unresolved).append(cidr or member)
        if unresolved:
            return [ANY], unresolved
        return list(dict.fromkeys(cidrs)) or [ANY], []

    def strict_networks(self, block: Any) -> list[str] | None:
        """Networks of a NAT rule: ``None`` when any of them is unresolved."""
        if not block:
            return [ANY]
        if isinstance(block, dict) and not {"objects", "networks", "literals"} & set(block):
            block = {"objects": [block]}
        elif not isinstance(block, (dict, list)):
            block = {"objects": [{"name": _text(block)}]}
        cidrs, unresolved = self.networks(block)
        return None if unresolved else cidrs

    def _port_entries(self, ref: Any, depth: int = 0) -> tuple[list[tuple[str, str]], list[str]]:
        ref = _dict(ref)
        kind = _kind(ref.get("type"))
        if "port" in ref or "icmpType" in ref or ("protocol" in ref and not _ident(ref)):
            item = ref
        else:
            item = self.ports.get(_ident(ref)) or self.ports.get(_name(ref).lower())
            if item is None:
                return [], [_name(ref) or "a port object"]
            kind = _kind(item.get("type")) or kind
        members = _dicts(item.get("objects")) + _dicts(item.get("literals"))
        if members or kind == "portobjectgroup":
            if depth > 4:
                return [], [_name(item)]
            found: list[tuple[str, str]] = []
            unresolved: list[str] = []
            for member in members:
                entries, bad = self._port_entries(member, depth + 1)
                found += entries
                unresolved += bad
            return found, unresolved
        protocol = _protocol(item.get("protocol"))
        if "icmp" in kind or protocol in ("icmp", "icmpv6"):
            icmp_type = _text(item.get("icmpType"))
            protocol = "icmpv6" if "v6" in kind or protocol == "icmpv6" else "icmp"
            unresolved = [f"ICMP type {icmp_type}"] if icmp_type and icmp_type.lower() != "any" else []
            return [(protocol, ANY)], unresolved
        port = _text(item.get("port")).replace(" ", "") or ANY
        return [(protocol, port)], []

    def ports_of(self, block: Any) -> tuple[list[tuple[str, str]], list[str]]:
        """``(protocol, port expression)`` of a ports block."""
        block = _dict(block)
        found: list[tuple[str, str]] = []
        unresolved: list[str] = []
        for ref in _dicts(block.get("objects")) + _dicts(block.get("literals")):
            entries, bad = self._port_entries(ref)
            found += entries
            unresolved += bad
        return found, unresolved

    def service(self, ref: Any) -> tuple[str, str]:
        """``(protocol, port)`` of the single port object of a NAT rule."""
        if not ref:
            return ANY, ""
        entries, _bad = self._port_entries(ref)
        if not entries:
            return ANY, ""
        protocol, port = entries[0]
        return protocol, "" if port == ANY else port


def _join(ports: list[str]) -> str:
    if not ports or ANY in ports:
        return ANY
    return ",".join(dict.fromkeys(ports))


def _split_by_protocol(src: list[tuple[str, str]], dst: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """``(protocol, src ports, dst ports)`` per protocol of a rule's ports:
    a rule whose ports mix protocols becomes one rule per protocol."""
    if not src and not dst:
        return [(ANY, ANY, ANY)]
    protocols = list(dict.fromkeys(p for p, _port in (dst or src)))
    found: list[tuple[str, str, str]] = []
    for protocol in protocols:
        src_ports = [port for p, port in src if p == protocol]
        if src and not src_ports:
            continue
        dst_ports = [port for p, port in dst if p == protocol]
        found.append((protocol, _join(src_ports), _join(dst_ports)))
    return found or [(ANY, ANY, ANY)]


def _zones(block: Any) -> list[str]:
    block = _dict(block)
    refs = _dicts(block.get("objects")) + _dicts(block.get("literals"))
    return [n for n in dict.fromkeys(_name(r) for r in refs) if n]


def _extras(item: dict) -> list[str]:
    """What an access or prefilter rule also matches on that Plexus cannot
    evaluate: applications, URLs, users, VLAN tags, security group tags."""
    found: list[str] = []
    apps = _dict(item.get("applications"))
    for key in ("applications", "applicationFilters", "inlineApplicationFilters"):
        found += [f"application {_name(a)}" for a in _dicts(apps.get(key)) if _name(a)]
    urls = _dict(item.get("urls"))
    found += [
        f"URL {_name(u) or _text(u.get('url'))}" for u in _dicts(urls.get("objects")) + _dicts(urls.get("literals"))
    ]
    found += [
        f"URL category {_name(_dict(c).get('category'))}"
        for c in _dicts(urls.get("urlCategoriesWithReputation"))
        if _name(_dict(c).get("category"))
    ]
    users = _dict(item.get("users"))
    found += [f"user {_name(u)}" for u in _dicts(users.get("objects")) if _name(u)]
    tags = _dict(item.get("vlanTags"))
    for ref in _dicts(tags.get("objects")) + _dicts(tags.get("literals")):
        value = _name(ref) or "-".join(t for t in (_text(ref.get("startTag")), _text(ref.get("endTag"))) if t)
        found.append(f"VLAN tag {value}")
    for key in ("sourceSecurityGroupTags", "destinationSecurityGroupTags"):
        for ref in _dicts(_dict(item.get(key)).get("objects")):
            found.append(f"security group tag {_name(ref)}")
    for key in ("sourceDynamicObjects", "destinationDynamicObjects"):
        for ref in _dicts(_dict(item.get(key)).get("objects")):
            found.append(f"dynamic object {_name(ref)}")
    return found


def _rules(
    items: list[dict], resolver: _Resolver, actions: dict[str, str], *, zone_keys: tuple[str, str]
) -> list[dict]:
    found: list[dict] = []
    for position, item in enumerate(items, start=1):
        if _kind(item.get("ruleType")) == "tunnel":
            # A tunnel rule matches encapsulated traffic by its outer header only.
            continue
        try:
            index = int(_dict(item.get("metadata")).get("ruleIndex") or position)
        except TypeError, ValueError:
            index = position
        src, bad_src = resolver.networks(item.get("sourceNetworks"))
        dst, bad_dst = resolver.networks(item.get("destinationNetworks"))
        src_ports, bad_sp = resolver.ports_of(item.get("sourcePorts"))
        dst_ports, bad_dp = resolver.ports_of(item.get("destinationPorts"))
        unresolved = bad_src + bad_dst + bad_sp + bad_dp + _extras(item)
        action = _kind(item.get("action"))
        src_zones = _zones(item.get(zone_keys[0]) or item.get("sourceZones"))
        dst_zones = _zones(item.get(zone_keys[1]) or item.get("destinationZones"))
        for protocol, sports, dports in _split_by_protocol(src_ports, dst_ports):
            found.append(
                rule(
                    index,
                    actions.get(action, "deny" if "block" in action else action or "deny"),
                    name=_text(item.get("name")),
                    enabled=item.get("enabled", True) is not False,
                    protocol=protocol,
                    src=src,
                    src_ports=sports,
                    dst=dst,
                    dst_ports=dports,
                    src_zones=src_zones,
                    dst_zones=dst_zones,
                    unresolved=unresolved,
                )
            )
    return found


class _DeviceForwarding:
    def __init__(self, builder: _Builder, resolver: _Resolver, device_id: str) -> None:
        self.b = builder
        self.resolver = resolver
        self.did = device_id
        self.rows = builder.rows.get(device_id) or builder._interface_rows(device_id)
        self.block = new_block()

    # Interfaces and routes

    def _iface_name(self, row: dict) -> str:
        return row["ifname"] or row["name"]

    def interfaces(self) -> None:
        for row in self.rows:
            name = self._iface_name(row)
            if not name:
                continue
            if row["management_only"]:
                kind = "management"
            elif row["type"] == "VTI":
                kind = "tunnel"
            elif row["type"] == "Loopback":
                kind = "loopback"
            elif f"w:{self.did}:{name}" in self.b.nodes:
                kind = "wan"
            else:
                kind = "routed"
            self.block["interfaces"].append(
                interface(
                    name,
                    kind,
                    ip=row["ip"],
                    cidr=row["cidr"],
                    zone=row["zone"],
                    vrf=_vrf(row["vr"]),
                    enabled=row["enabled"],
                )
            )

    def routes(self) -> None:
        for row in self.rows:
            name = self._iface_name(row)
            for cidr in [row["cidr"], *(c for _a, c in row["ipv6"])]:
                if cidr:
                    self.block["routes"].append(
                        route(cidr, "connected", interface=name, vrf=_vrf(row["vr"]), source=f"Connected {name}")
                    )
        if self.did not in self.b.routing:
            note(self.block, "Static routes and dynamic routing")
            return
        for item in self.b._route_list(self.did, "static_v4") + self.b._route_list(self.did, "static_v6"):
            hop, via = self._gateway(item)
            egress = _text(item.get("interfaceName")) or _name(item.get("interface"))
            try:
                metric: int | None = int(_first(item, "metricValue", "metric"))
            except TypeError, ValueError:
                metric = None
            refs = item.get("selectedNetworks") or item.get("networks") or []
            for ref in refs if isinstance(refs, list) else [refs]:
                for destination, cidr in self.b.objects.expand(ref) or [(_name(ref), "")]:
                    if not cidr:
                        note(self.block, f"Static route to {destination} (not an address)")
                        continue
                    source = f"Static route {destination}"
                    if via:
                        source += f" via {via}"
                    if item.get("isTunneled"):
                        source += " (tunneled)"
                    self.block["routes"].append(
                        route(
                            cidr,
                            "default" if cidr in _DEFAULT_ROUTES else "static",
                            next_hop=hop,
                            interface=egress,
                            vrf=_vrf(item.get("vr")),
                            metric=metric,
                            source=source,
                        )
                    )
        for key, label in (("bgp", "BGP"), ("ospf", "OSPF"), ("eigrp", "EIGRP")):
            if self.b._route_list(self.did, key):
                note(self.block, f"Routes learned by {label}")
        if self.b._route_list(self.did, "pbr"):
            # A policy-based route matches an extended ACL, which is not collected.
            note(self.block, "Policy-based routes")

    def _gateway(self, item: dict) -> tuple[str, str]:
        """``(next hop address, object name)``: the object name when the
        gateway is an object Plexus cannot turn into an address."""
        gateway = item.get("gateway")
        if not isinstance(gateway, dict):
            text = _text(gateway)
            return (text, "") if is_address(text) else ("", text)
        literal = _dict(gateway.get("literal"))
        if literal:
            value = _text(literal.get("value"))
            return (value, "") if is_address(value) else ("", value)
        ref = gateway.get("object")
        if ref:
            value = self.b.objects.value(ref)
            return (value, "") if is_address(value) else ("", _name(ref))
        value = _text(gateway.get("value"))
        return (value, "") if is_address(value) else ("", value or _name(gateway))

    # Site-to-site VPN

    def vpn(self, tunnels: list[tuple[dict, dict, dict, str]]) -> None:
        for topology, a, b, state in tunnels:
            if topology.get("routeBased"):
                # A route-based tunnel is a VTI: the routes say what goes over it.
                continue
            for here, there in ((a, b), (b, a)):
                if here["kind"] != "device" or self.did not in here["members"]:
                    continue
                name = _text(topology.get("name"))
                if here.get("acl"):
                    name = f"{name} (ACL {here['acl']})"
                self.block["vpn"].append(
                    {
                        "name": name,
                        "interface": here["iface"],
                        "local": list(here.get("cidrs") or []),
                        "remote": list(there.get("cidrs") or []),
                        "peer": {"org_node": there["node"]},
                        "status": state if state in ("up", "down") else "unknown",
                    }
                )

    # Policies

    def policies(self) -> None:
        b = self.b
        prefilter = b._prefilter_of(self.did)
        if prefilter:
            pid = _ident(prefilter)
            full = next((p for p in b.prefilter_policies if pid and _ident(p) == pid), prefilter)
            collected = _dict(b.raw.get("prefilter_rules"))
            if pid in collected:
                items = _dicts(collected.get(pid))[:MAX_ACCESS_RULES]
                total = _count(_dict(b.raw.get("prefilter_rule_counts")).get(pid), len(items))
                self.block["policies"].append(
                    policy_set(
                        f"Prefilter policy {_name(full)}".strip(),
                        "prefilter",
                        ANY,
                        _rules(
                            items,
                            self.resolver,
                            _PREFILTER_ACTIONS,
                            zone_keys=("sourceInterfaces", "destinationInterfaces"),
                        ),
                        default="allow",
                        complete=total <= len(items),
                    )
                )
            elif _name(full).lower() != DEFAULT_PREFILTER_NAME:
                note(self.block, "Prefilter rules")
        policy = b.device_acp.get(self.did)
        if policy:
            pid = _ident(policy)
            full = next((p for p in b.access_policies if _ident(p) == pid), policy)
            if pid in b.access_rules:
                items = _dicts(b.access_rules.get(pid))[:MAX_ACCESS_RULES]
                total = _count(b.access_rule_counts.get(pid), len(items))
                action = _text(_dict(full.get("defaultAction")).get("action")).upper()
                self.block["policies"].append(
                    policy_set(
                        f"Access control policy {_name(full)}".strip(),
                        "firewall",
                        ANY,
                        _rules(items, self.resolver, _ACCESS_ACTIONS, zone_keys=("sourceZones", "destinationZones")),
                        default="deny" if action.startswith("BLOCK") else "allow",
                        complete=total <= len(items),
                    )
                )
                if total > len(items):
                    note(self.block, f"Access control rules beyond the first {len(items)}")
            else:
                note(self.block, "Access control rules")

    # NAT

    def _zone_iface(self, ref: Any) -> str:
        """A NAT rule's interface (a zone or interface group) as the logical
        name of the one interface of this device in it, else its name."""
        if not ref:
            return ""
        zone_id, zone_name = _ident(ref), _name(ref)
        members = [
            self._iface_name(r)
            for r in self.rows
            if (zone_id and r["zone_id"] == zone_id) or (zone_name and r["zone"].lower() == zone_name.lower())
        ]
        return members[0] if len(members) == 1 else zone_name

    def nat(self) -> None:
        b = self.b
        policy = b.device_nat.get(self.did)
        if not policy:
            return
        if _ident(policy) not in b.nat_rules:
            note(self.block, "NAT rules")
            return
        before: list[dict] = []
        auto: list[dict] = []
        after: list[dict] = []
        for item in _dicts(b.nat_rules.get(_ident(policy))):
            kind = _kind(item.get("type"))
            is_auto = "auto" in kind and "manual" not in kind
            section = _kind(_first(_dict(item.get("metadata")), "section") or item.get("section"))
            (auto if is_auto else after if "after" in section else before).append(item)
        index = 0
        for group, kind in ((before, "manual_before"), (auto, "auto"), (after, "manual_after")):
            for item in group:
                index += 1
                entries = self._auto(item, index) if kind == "auto" else self._manual(item, index, kind)
                if entries is None:
                    note(self.block, f"NAT rule {index} (its networks are not all addresses)")
                    continue
                self.block["nat"].extend(entries)

    def _manual(self, item: dict, index: int, kind: str) -> list[dict] | None:
        resolver = self.resolver
        original_src = resolver.strict_networks(item.get("originalSource"))
        original_dst = resolver.strict_networks(item.get("originalDestination"))
        if item.get("interfaceInOriginalDestination"):
            original_dst = [INTERFACE]
        if item.get("interfaceInTranslatedSource"):
            translated_src: list[str] | None = [INTERFACE]
        else:
            translated_src = (
                resolver.strict_networks(item.get("translatedSource")) if item.get("translatedSource") else []
            )
        translated_dst = (
            resolver.strict_networks(item.get("translatedDestination")) if item.get("translatedDestination") else []
        )
        if original_src is None or original_dst is None or translated_src is None or translated_dst is None:
            return None
        protocol, original_port = resolver.service(item.get("originalDestinationPort"))
        translated_port = resolver.service(item.get("translatedDestinationPort"))[1]
        return [
            nat(
                index,
                kind,
                name=_text(item.get("description")) or f"Manual NAT rule {index}",
                enabled=item.get("enabled", True) is not False,
                original_src=original_src,
                original_dst=original_dst,
                translated_src=translated_src,
                translated_dst=translated_dst,
                protocol=protocol,
                original_port=original_port,
                translated_port=translated_port,
                src_interface=self._zone_iface(item.get("sourceInterface")),
                dst_interface=self._zone_iface(item.get("destinationInterface")),
            )
        ]

    def _auto(self, item: dict, index: int) -> list[dict] | None:
        resolver = self.resolver
        real = resolver.strict_networks(item.get("originalNetwork") or item.get("originalSource"))
        if item.get("interfaceInTranslatedNetwork", item.get("interfaceInTranslatedSource")):
            mapped: list[str] | None = [INTERFACE]
        else:
            mapped = resolver.strict_networks(item.get("translatedNetwork") or item.get("translatedSource"))
        if real is None or mapped is None:
            return None
        protocol = _protocol(item.get("serviceProtocol")) if item.get("serviceProtocol") else ANY
        real_port, mapped_port = _text(item.get("originalPort")), _text(item.get("translatedPort"))
        name = _text(item.get("description")) or f"Auto NAT rule {index}"
        enabled = item.get("enabled", True) is not False
        src_if = self._zone_iface(item.get("sourceInterface"))
        dst_if = self._zone_iface(item.get("destinationInterface"))
        entries = [
            # Outbound: the real source leaves translated.
            nat(
                index,
                "auto",
                name=name,
                enabled=enabled,
                original_src=real,
                translated_src=mapped,
                protocol=protocol,
                src_interface=src_if,
                dst_interface=dst_if,
            )
        ]
        if _kind(item.get("natType")) == "static":
            # Inbound to the mapped address reaches the real one.
            entries.append(
                nat(
                    index,
                    "auto",
                    name=name,
                    enabled=enabled,
                    original_dst=mapped,
                    translated_dst=real,
                    protocol=protocol,
                    original_port=mapped_port,
                    translated_port=real_port,
                    src_interface=dst_if,
                    dst_interface=src_if,
                )
            )
        return entries


def _count(raw: Any, fallback: int) -> int:
    try:
        return int(raw or fallback)
    except TypeError, ValueError:
        return fallback


def _config_owner(builder: _Builder, device_id: str) -> str:
    """The device whose configuration a member uses: the primary of an HA
    pair, the control unit of a cluster."""
    for container in (builder.pair_of.get(device_id), builder.cluster_of.get(device_id)):
        if container:
            members = builder.resolver.containers.get(_ident(container), [])
            if members:
                return members[0]
    return device_id


def build_forwarding(builder: _Builder, tunnels: list[tuple[dict, dict, dict, str]]) -> None:
    """Put the ``forwarding`` block on every FTD node of the builder."""
    resolver = _Resolver(builder)
    blocks: dict[str, dict] = {}
    for node in builder.nodes.values():
        if node["kind"] != "appliance" or not node["id"].startswith("d:"):
            continue
        device_id = node["id"].removeprefix("d:")
        owner = _config_owner(builder, device_id)
        if owner not in blocks:
            device = _DeviceForwarding(builder, resolver, owner)
            device.interfaces()
            device.routes()
            device.vpn(tunnels)
            device.policies()
            device.nat()
            blocks[owner] = device.block
        node["forwarding"] = blocks[owner] if owner == device_id else share(blocks[owner])
