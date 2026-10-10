"""The ``forwarding`` block of each firewall of a Panorama snapshot.

Built from what the snapshot builder already read (interfaces, routing,
IPsec tunnels, the security and NAT rules the firewall inherits), in the
schema of ``netcontrol.integrations.meraki.forwarding``:

  - interfaces by name, with their zone (``vsysN/zone`` when two virtual
    systems of the firewall have a zone of that name) and virtual router;
    an outside interface (public address, default route egress or
    GlobalProtect gateway interface) is ``wan``
  - connected routes from the interface addresses; the routing table the
    firewall reported when it was read (static, BGP, OSPF, RIP), else the
    configured static routes; a route to ``0.0.0.0/0`` or ``::/0`` is a
    ``default`` route, one over the tunnel interface of an IPsec tunnel
    goes to the tunnel's far end
  - one ``vpn`` entry per IPsec tunnel, on its tunnel interface: the
    proxy IDs when it has them, else the routes over the tunnel interface
  - the security policy as one rule set evaluated against the zones of the
    ingress and egress interfaces, in the order the firewall applies it
    (shared, ancestor and own device group pre-rules; post-rules the other
    way round; then the intrazone and interzone default rules)
  - the NAT rules in the same order, pre-rules then post-rules

PAN-OS matches a security rule on the destination address before NAT but
the zone after it; the tracer evaluates rules after destination NAT, so a
rule whose destination is the original address of a destination NAT rule
also lists the translated address. An application (``application-default``
included, with specific applications), a user, a URL category, an FQDN, a
dynamic address group or an address that is no object Plexus read cannot be
matched on addresses and ports alone: the rule is kept with it in
``unresolved``, so a flow it might cover is reported as unknown.

The members of an HA pair share the block of the first one. Pure (no I/O).
"""

from __future__ import annotations

from typing import Any

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
from netcontrol.integrations.panorama.collector import members
from netcontrol.integrations.panorama.normalize import _bare, _Builder, _dict, _name, _text, _yes, value_cidr

_DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")
_ACTIONS = {
    "allow": "allow",
    "deny": "deny",
    "drop": "deny",
    "reset-client": "deny",
    "reset-server": "deny",
    "reset-both": "deny",
}
_DYNAMIC_FLAGS = (("B", "BGP"), ("O", "OSPF"), ("Oi", "OSPF"), ("Oo", "OSPF"), ("O1", "OSPF"), ("O2", "OSPF"))
SECURITY_POLICY_NAME = "Security policy"
LOCAL_RULES_NOTE = "Local firewall rules"


def _vrf(name: Any) -> str:
    text = _text(name)
    return "" if text.lower() in ("", "default") else text


def _metric(raw: Any) -> int | None:
    try:
        return int(_text(raw))
    except ValueError:
        return None


def _join(ports: list[str]) -> str:
    if not ports or ANY in ports:
        return ANY
    return ",".join(dict.fromkeys(ports))


class _FirewallForwarding:
    def __init__(self, builder: _Builder, serial: str) -> None:
        self.b = builder
        self.serial = serial
        self.rows = builder.rows.get(serial) or builder.interface_rows(serial)
        self.tunnels = [t for t in builder.tunnels.get(serial, []) if not t["disabled"]]
        self.block = new_block()
        self.dnat: list[tuple[list[str], list[str]]] = []
        # Zones named alike in two virtual systems are told apart by vsys.
        vsys_of_zone: dict[str, set[str]] = {}
        for zone in builder.zones(serial):
            vsys_of_zone.setdefault(zone["zone"], set()).add(zone["vsys"])
        for row in self.rows:
            if row["zone"]:
                vsys_of_zone.setdefault(row["zone"], set()).add(row["vsys"])
        self.vsys_of_zone = vsys_of_zone
        self.duplicated = {z for z, vsys in vsys_of_zone.items() if len({v for v in vsys if v}) > 1}

    def zone_label(self, zone: str, vsys: str) -> str:
        return f"{vsys}/{zone}" if zone in self.duplicated and vsys else zone

    def rule_zones(self, names: Any) -> list[str]:
        found: list[str] = []
        for zone in members(names):
            if zone.lower() == ANY:
                return []
            if zone in self.duplicated:
                found += [f"{v}/{zone}" for v in sorted(self.vsys_of_zone[zone]) if v]
            else:
                found.append(zone)
        return list(dict.fromkeys(found))

    # Interfaces and routes

    def interfaces(self) -> None:
        for row in self.rows:
            name = row["name"]
            if not name:
                continue
            if name.lower() in ("management", "mgmt"):
                kind = "management"
            elif row["type"] == "Tunnel":
                kind = "tunnel"
            elif row["type"] == "Loopback":
                kind = "loopback"
            elif f"w:{self.serial}:{name}" in self.b.nodes:
                kind = "wan"
            else:
                kind = "routed"
            self.block["interfaces"].append(
                interface(
                    name,
                    kind,
                    ip=row["ip"],
                    cidr=row["cidr"],
                    zone=self.zone_label(row["zone"], row["vsys"]),
                    vrf=_vrf(row["vr"]),
                    enabled=row["enabled"],
                )
            )

    def _peer(self, iface: str) -> dict | None:
        tunnel = next((t for t in self.tunnels if t["iface"] and t["iface"] == iface and t["far"]), None)
        return {"org_node": tunnel["far"]} if tunnel else None

    def routes(self) -> None:
        connected: set[tuple[str, str]] = set()
        for row in self.rows:
            for cidr in [row["cidr"], *(c for _a, c in row["ipv6"])]:
                if cidr:
                    connected.add((cidr, _vrf(row["vr"])))
                    self.block["routes"].append(
                        route(
                            cidr,
                            "connected",
                            interface=row["name"],
                            vrf=_vrf(row["vr"]),
                            source=f"Connected {row['name']}",
                        )
                    )
        table = self.b.route_table(self.serial)
        if table is not None:
            self._table_routes(table, connected)
            return
        statics = self.b.static_routes(self.serial)
        if not statics and not self.b.virtual_routers(self.serial):
            note(self.block, "Static routes and dynamic routing")
            return
        for item in statics:
            cidr = item["cidr"]
            if not cidr:
                note(self.block, f"Static route to {item['destination'] or item['name']} (not an address)")
                continue
            if item["next_vr"]:
                note(self.block, f"Static route {item['name']} to virtual router {item['next_vr']}")
                continue
            source = f"Static route {item['name'] or cidr}"
            if item["gateway"]:
                source += f" via {item['gateway']}"
            self.block["routes"].append(
                route(
                    cidr,
                    "blackhole" if item["discard"] else ("default" if cidr in _DEFAULT_ROUTES else "static"),
                    next_hop=item["gateway"],
                    interface=item["interface"],
                    peer=self._peer(item["interface"]),
                    vrf=_vrf(item["vr"]),
                    metric=_metric(item["metric"]),
                    source=source,
                )
            )
        for router in self.b.virtual_routers(self.serial):
            protocol = _dict(router.get("protocol"))
            for key, label in (("bgp", "BGP"), ("ospf", "OSPF"), ("ospfv3", "OSPFv3"), ("rip", "RIP")):
                if _yes(_dict(protocol.get(key)).get("enable")):
                    note(self.block, f"Routes learned by {label}")

    def _table_routes(self, table: list[dict[str, Any]], connected: set[tuple[str, str]]) -> None:
        for entry in table:
            flags = entry["flags"].split()
            prefix = value_cidr(entry["destination"])
            if not entry["active"] or not prefix:
                continue
            vrf = _vrf(entry["vr"])
            if "H" in flags or ("C" in flags and (prefix, vrf) in connected):
                continue
            hop = entry["nexthop"]
            protocol = next((label for flag, label in _DYNAMIC_FLAGS if flag in flags), "")
            if "C" in flags:
                kind = "connected"
            elif prefix in _DEFAULT_ROUTES:
                kind = "default"
            elif protocol or "R" in flags:
                kind = "dynamic"
            else:
                kind = "static"
            if hop.lower() == "discard":
                kind = "blackhole"
            label = protocol or ("RIP" if "R" in flags else ("Connected" if "C" in flags else "Static"))
            source = f"{label} route {prefix}"
            if is_address(hop) and hop not in ("0.0.0.0", "::"):
                source += f" via {hop}"
            self.block["routes"].append(
                route(
                    prefix,
                    kind,
                    next_hop=hop if hop not in ("0.0.0.0", "::") else "",
                    interface=entry["interface"],
                    peer=self._peer(entry["interface"]),
                    vrf=vrf,
                    metric=_metric(entry["metric"]),
                    source=source,
                )
            )

    # IPsec

    def vpn(self) -> None:
        for tunnel in self.tunnels:
            if not tunnel["far"]:
                continue
            local = [value_cidr(near) or ANY for near, _far in tunnel["proxies"]]
            remote = [value_cidr(far) or ANY for _near, far in tunnel["proxies"]]
            if not remote:
                remote = [
                    r["prefix"]
                    for r in self.block["routes"]
                    if r["interface"] == tunnel["iface"]
                    and r["kind"] != "connected"
                    and r["prefix"] not in _DEFAULT_ROUTES
                ]
            self.block["vpn"].append(
                {
                    "name": tunnel["name"],
                    "interface": tunnel["iface"],
                    "local": list(dict.fromkeys(local)) or [ANY],
                    "remote": list(dict.fromkeys(remote)) or [ANY],
                    "peer": {"org_node": tunnel["far"]},
                    "status": tunnel["state"] if tunnel["state"] in ("up", "down") else "unknown",
                }
            )

    # Rule values

    def _addresses(self, names: Any, group: str, negate: bool, what: str) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of a rule's source or destination. A field
        Plexus cannot resolve in full matches every address, with the names
        kept as unresolved."""
        listed = members(names) or [ANY]
        cidrs: list[str] = []
        unresolved: list[str] = []
        for name in listed:
            found, bad = self.b.objects.addresses(name, group)
            cidrs += [c for c in found if c not in cidrs]
            unresolved += bad
        if negate:
            return [ANY], [f"negated {what} {', '.join(listed)}"]
        if unresolved:
            return [ANY], unresolved
        return (cidrs or [ANY]), []

    def _strict(self, names: Any, group: str) -> list[str] | None:
        """Addresses of a NAT rule: ``None`` when any of them is unresolved."""
        cidrs, unresolved = self._addresses(names, group, False, "")
        return None if unresolved else cidrs

    def _services(self, item: dict, group: str, apps: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
        found: list[tuple[str, str]] = []
        unresolved: list[str] = []
        for name in members(item.get("service")) or [ANY]:
            if name.lower() == "application-default":
                if apps:
                    unresolved.append("application-default ports")
                found.append((ANY, ANY))
                continue
            entries_found, bad = self.b.objects.services(name, group)
            found += entries_found
            unresolved += bad
        return found, unresolved

    @staticmethod
    def _by_protocol(services: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """``(protocol, ports)`` once per protocol."""
        if not services or any(p == ANY for p, _port in services):
            return [(ANY, ANY)]
        protocols = list(dict.fromkeys(p for p, _port in services))
        return [(p, _join([port for q, port in services if q == p])) for p in protocols]

    @staticmethod
    def _extras(item: dict) -> tuple[list[str], list[str]]:
        """``(applications, other unresolved)`` a rule also matches on."""
        apps = [a for a in members(item.get("application")) if a.lower() != ANY]
        extras = [f"application {a}" for a in apps]
        for key, label in (
            ("source-user", "user"),
            ("category", "URL category"),
            ("source-hip", "source HIP profile"),
            ("destination-hip", "destination HIP profile"),
        ):
            extras += [f"{label} {v}" for v in members(item.get(key)) if v.lower() not in (ANY, "no-hip")]
        return apps, extras

    # NAT

    def nat(self) -> None:
        b = self.b
        if not b.nat_collected:
            note(self.block, "NAT rules")
            return
        for index, (base, group, item) in enumerate(b.nat_chain(self.serial), start=1):
            entries_found = self._nat_entries(item, group, index, "pre_rule" if base.endswith(" pre") else "post_rule")
            if entries_found is None:
                note(self.block, f"NAT rule {_name(item)} (its addresses are not all resolved)")
                continue
            self.block["nat"].extend(entries_found)

    def _nat_entries(self, item: dict, group: str, index: int, kind: str) -> list[dict] | None:
        original_src = self._strict(item.get("source"), group)
        original_dst = self._strict(item.get("destination"), group)
        if original_src is None or original_dst is None:
            return None
        services, _bad = self.b.objects.services(_text(item.get("service")) or ANY, group)
        protocol, port = services[0] if services else (ANY, ANY)
        port = "" if port == ANY or "," in port else port
        translation = _dict(item.get("source-translation"))
        translated_src: list[str] | None = []
        reverse = False
        if "dynamic-ip-and-port" in translation:
            dynamic = _dict(translation.get("dynamic-ip-and-port"))
            address = _dict(dynamic.get("interface-address"))
            if address or "interface-address" in dynamic:
                ip = _bare(address.get("ip"))
                translated_src = [f"{ip}/32"] if is_address(ip) else [INTERFACE]
            else:
                translated_src = self._strict(dynamic.get("translated-address"), group)
        elif "dynamic-ip" in translation:
            translated_src = self._strict(_dict(translation.get("dynamic-ip")).get("translated-address"), group)
        elif "static-ip" in translation:
            static = _dict(translation.get("static-ip"))
            translated_src = self._strict(static.get("translated-address"), group)
            reverse = _yes(static.get("bi-directional"))
        translated_dst: list[str] | None = []
        translated_port = ""
        for key in ("destination-translation", "dynamic-destination-translation"):
            destination = _dict(item.get(key))
            if destination:
                translated_dst = self._strict(destination.get("translated-address"), group)
                translated_port = _text(destination.get("translated-port"))
        if translated_src is None or translated_dst is None:
            return None
        if not translated_src and not translated_dst:
            # A rule without translation exempts what it matches from the rules after it.
            translated_src = list(original_src)
        if translated_dst and original_dst != [ANY]:
            self.dnat.append((list(original_dst), list(translated_dst)))
        name = _name(item) or f"NAT rule {index}"
        enabled = not _yes(item.get("disabled"))
        from_zones = self.rule_zones(item.get("from")) or [""]
        to_interface = _text(item.get("to-interface"))
        to_zones = (
            [to_interface] if to_interface and to_interface.lower() != ANY else self.rule_zones(item.get("to")) or [""]
        )
        found: list[dict] = []
        for src_if in from_zones:
            for dst_if in to_zones:
                found.append(
                    nat(
                        index,
                        kind,
                        name=name,
                        enabled=enabled,
                        original_src=original_src,
                        original_dst=original_dst,
                        translated_src=translated_src,
                        translated_dst=translated_dst,
                        protocol=protocol,
                        original_port=port,
                        translated_port=translated_port,
                        src_interface=src_if,
                        dst_interface=dst_if,
                    )
                )
                if reverse and translated_src:
                    # Bi-directional: inbound to the translated address reaches the real one.
                    found.append(
                        nat(
                            index,
                            kind,
                            name=f"{name} (bi-directional)",
                            enabled=enabled,
                            original_dst=translated_src,
                            translated_dst=original_src,
                            protocol=protocol,
                            src_interface=dst_if,
                            dst_interface=src_if,
                        )
                    )
        return found

    # Security policy

    def policies(self) -> None:
        b = self.b
        if not b.security_collected:
            note(self.block, "Security rules")
            return
        found: list[dict] = []
        position = 0
        for _base, group, item in b.security_chain(self.serial):
            position += 1
            src, bad_src = self._addresses(item.get("source"), group, _yes(item.get("negate-source")), "source")
            dst, bad_dst = self._addresses(
                item.get("destination"), group, _yes(item.get("negate-destination")), "destination"
            )
            for original, translated in self.dnat:
                if any(cidr in dst for cidr in original):
                    dst += [cidr for cidr in translated if cidr not in dst]
            apps, extras = self._extras(item)
            services, bad_services = self._services(item, group, apps)
            action = _text(item.get("action")).lower()
            for protocol, ports in self._by_protocol(services):
                found.append(
                    rule(
                        position,
                        _ACTIONS.get(action, "deny"),
                        name=_name(item),
                        enabled=not _yes(item.get("disabled")),
                        protocol=protocol,
                        src=src,
                        dst=dst,
                        dst_ports=ports,
                        src_zones=self.rule_zones(item.get("from")),
                        dst_zones=self.rule_zones(item.get("to")),
                        comment=_text(item.get("description")),
                        unresolved=bad_src + bad_dst + bad_services + extras,
                    )
                )
        defaults = b.default_actions(self.serial)
        intrazone = _ACTIONS.get(defaults["intrazone-default"][0].lower(), "allow")
        interzone = _ACTIONS.get(defaults["interzone-default"][0].lower(), "deny")
        zones = sorted({i["zone"] for i in self.block["interfaces"] if i["zone"]})
        for zone in zones:
            found.append(rule(position + 1, intrazone, name="intrazone-default", src_zones=[zone], dst_zones=[zone]))
        found.append(rule(position + 2, interzone, name="interzone-default"))
        self.block["policies"].append(policy_set(SECURITY_POLICY_NAME, "firewall", ANY, found, default=interzone))
        note(self.block, LOCAL_RULES_NOTE)

    def build(self) -> dict[str, Any]:
        self.interfaces()
        self.routes()
        self.vpn()
        self.nat()
        self.policies()
        return self.block


def build_forwarding(builder: _Builder) -> None:
    """Put the ``forwarding`` block on every firewall node of the builder."""
    blocks: dict[str, dict] = {}
    for node in builder.nodes.values():
        if node["kind"] != "appliance" or not node["id"].startswith("d:"):
            continue
        serial = node["id"].removeprefix("d:")
        owner = builder.primary_of.get(serial, serial)
        if owner not in blocks:
            blocks[owner] = _FirewallForwarding(builder, owner).build()
        node["forwarding"] = blocks[owner] if owner == serial else share(blocks[owner])
