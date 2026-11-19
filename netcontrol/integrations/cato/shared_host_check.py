"""Cato shared hosts vs Azure: can the Azure virtual machines a Cato
account's Shared Hosts rules name reach a Cato Socket with their per-user
tunnel?

Cato's "User Awareness for Shared Hosts" (the Shared Hosts policy, API
``policy.terminalServer``) is for multi-session hosts such as Azure Virtual
Desktop: the Cato Client on the host tunnels each user session's traffic in
GRE (IP protocol 47) to the Cato system range (``DEFAULT_SYSTEM_RANGE`` by
default), which must be routed to a Cato Socket inside the network. Azure
drops GRE inside a VNet, so there the host must send the tunnel as GRE over
UDP (registry value ``GREOverUDP = 1``), on UDP port ``GRE_UDP_PORT``.
Plexus cannot read the registry; the check evaluates udp/4754.

A rule names the hosts (``allowedHostIP``) and the traffic kept off the
tunnel (``excludeTraffic``) as global IP ranges; the Cato snapshot carries
them resolved on the Cato Cloud node (``shared_hosts``, see
``normalize.shared_hosts_of``). ``check`` takes every collected Azure
virtual machine address inside an enabled rule's hosts and evaluates, with
the Azure reachability engine:

  a. the effective route from the host's subnet to the system range: only a
     user route to a virtual appliance (a ``0.0.0.0/0`` one included) gets
     the tunnel anywhere;
  b. the appliance at the route's next hop: a collected virtual machine
     whose interface has IP forwarding on, in a network range of a site of
     the Cato account (a vSocket's LAN);
  c. the network security groups for udp/4754: the host's (interface, then
     subnet) outbound towards the system range, then the next hop's
     (subnet, then interface) inbound from the host to the system range;
  d. the route back from the next hop's subnet to the host.

Finding kinds:

  - ``no_route`` (warning): the host's subnet sends the system range
    nowhere useful (no route, next hop None, internet, VNet local, peering)
  - ``ip_forwarding_off`` (warning): the next hop's interface does not
    forward traffic addressed to another address
  - ``nsg_blocked`` (warning): a network security group denies udp/4754
  - ``no_return_route`` (warning): the next hop's subnet has no route back
  - ``next_hop_not_cato_site`` (info): the next hop is in no range of a
    site of the account
  - ``undetermined`` (info): a gateway route, routes learned over BGP or
    ExpressRoute, a split range, a next hop that is no collected virtual
    machine, a group that decides only part of the traffic or nothing
  - ``no_host_found`` (info): a host range inside a collected Azure subnet
    holds no collected virtual machine (a stale rule entry)
  - ``hosts_not_resolved`` (info): a rule names a range that did not resolve
  - ``gre_over_udp_required`` (info): one note per account with an Azure
    host, with the excluded traffic in its detail

Findings are grouped by root cause, so many hosts behind one missing route
are one finding: the subject of the key is the host subnet (route kinds),
the next-hop virtual machine and address (forwarding, not a Cato site) or
the group, direction and rule (network security groups); the hosts are
listed in ``detail["hosts"]``. A host range outside every collected Azure
subnet says nothing (the host may be on-premises). AWS and GCP are not
checked (a documented gap). Pure: no I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from netcontrol.integrations.cato import network_rules
from netcontrol.integrations.cato.egress_check import INFO, WARNING, _listed, cato_account
from netcontrol.integrations.pathtrace.model import BLOCKED, OK, Network, contains, net, show

DEFAULT_SYSTEM_RANGE = "10.254.254.0/24"
GRE_UDP_PORT = 4754
PROVIDER = "azure"
_PROTOCOL = "udp"
_PORTS = (GRE_UDP_PORT, GRE_UDP_PORT)
_TRAFFIC = f"{_PROTOCOL}/{GRE_UDP_PORT}"

NO_ROUTE = "no_route"
IP_FORWARDING_OFF = "ip_forwarding_off"
NSG_BLOCKED = "nsg_blocked"
NO_RETURN_ROUTE = "no_return_route"
NEXT_HOP_NOT_CATO_SITE = "next_hop_not_cato_site"
UNDETERMINED = "undetermined"
NO_HOST_FOUND = "no_host_found"
HOSTS_NOT_RESOLVED = "hosts_not_resolved"
GRE_OVER_UDP = "gre_over_udp_required"

KIND_LABELS = {
    NO_ROUTE: "No route to the Cato system range",
    IP_FORWARDING_OFF: "IP forwarding off on the next hop",
    NSG_BLOCKED: "Network security group blocks the tunnel",
    NO_RETURN_ROUTE: "No return route from the next hop",
    NEXT_HOP_NOT_CATO_SITE: "Next hop is not in a Cato site",
    UNDETERMINED: "Undetermined",
    NO_HOST_FOUND: "No host at a Shared Hosts range",
    HOSTS_NOT_RESOLVED: "Shared Hosts range not resolved",
    GRE_OVER_UDP: "GRE over UDP required",
}
_WARNINGS = (NO_ROUTE, IP_FORWARDING_OFF, NSG_BLOCKED, NO_RETURN_ROUTE)

# A message: ``(affected hosts as text, how many)`` -> text.
_Text = Callable[[str, int], str]


def severity_of(kind: str) -> str:
    return WARNING if kind in _WARNINGS else INFO


# ── Findings ────────────────────────────────────────────────────────────────


class _Findings:
    """The findings of one Cato account, grouped by key: a group keeps the
    first fields and message it was given and gathers the hosts."""

    def __init__(self, org_ref: int, org_name: str) -> None:
        self.org_ref, self.org_name = org_ref, org_name
        self._groups: dict[str, dict[str, Any]] = {}

    def add(
        self,
        kind: str,
        subject: str,
        host: dict | None,
        text: _Text,
        *,
        provider: str = PROVIDER,
        hop_ip: str = "",
        detail: dict | None = None,
        **fields: str,
    ) -> None:
        key = f"shared_host:{self.org_ref}:{kind}:{subject}"
        group = self._groups.get(key)
        if group is None:
            group = self._groups[key] = {
                "kind": kind,
                "text": text,
                "provider": provider,
                "hop_ip": hop_ip,
                "fields": fields,
                "detail": dict(detail or {}),
                "hosts": [],
            }
        if host is not None and all(h["ip"] != host["ip"] or h["vnet_id"] != host["vnet_id"] for h in group["hosts"]):
            group["hosts"].append(host)

    def build(self) -> list[dict[str, Any]]:
        found = []
        for key, group in self._groups.items():
            hosts = group["hosts"]
            labels = [_host_label(h) for h in hosts]
            fields = group["fields"]
            detail = dict(group["detail"])
            if hosts:
                detail["hosts"] = [
                    {"name": h["name"], "ip": h["ip"], "subnet": h.get("subnet", ""), "rules": h["rules"]}
                    for h in hosts
                ]
                detail["rules"] = sorted({r for h in hosts for r in h["rules"]})
            # One host: its address, so an inventory host gets the alert.
            private_ip = group["hop_ip"] or (hosts[0]["ip"] if len(hosts) == 1 else "")
            kind = group["kind"]
            found.append(
                {
                    "key": key,
                    "cato_org_ref": self.org_ref,
                    "cato_org_name": self.org_name,
                    "provider": group["provider"],
                    "resource_id": fields.get("resource_id", ""),
                    "resource_name": fields.get("resource_name", ""),
                    "public_ip": "",
                    "private_ip": private_ip,
                    "protocol": fields.get("protocol", ""),
                    "ports": fields.get("ports", ""),
                    "filter": fields.get("filter", ""),
                    "rule": fields.get("rule", ""),
                    "rule_id": fields.get("rule_id", ""),
                    "kind": kind,
                    "severity": severity_of(kind),
                    "message": group["text"](_listed(labels), len(labels)),
                    "detail": detail,
                }
            )
        return found


def _around(before: str, after: str = "") -> _Text:
    """A message that is ``before``, the affected hosts, then ``after``."""
    return lambda who, n: f"{before}{who}{after}"


def _constant(text: str) -> _Text:
    """A message that names no host."""
    return lambda who, n: text


def _host_label(host: dict) -> str:
    return f"{host['name']} ({host['ip']})"


def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


# ── Hosts ───────────────────────────────────────────────────────────────────


def _hosts(engine: Any, rules: list[dict]) -> tuple[list[dict], list[dict]]:
    """``(hosts, stale)``: every collected virtual machine address inside a
    rule's host ranges, once each, and the ``(rule, range, cidr, place)`` of
    each host CIDR inside a collected subnet that holds none."""
    owners = engine.address_owners()
    hosts: dict[tuple[str, str], dict] = {}
    stale: list[dict] = []
    for rule in rules:
        label = network_rules.rule_label(rule)
        for entry in rule.get("hosts") or []:
            for cidr in entry.get("cidrs") or []:
                range_net = net(cidr)
                if range_net is None:
                    continue
                found = False
                for (vnet_id, address), (owner, interface) in owners.items():
                    address_net = net(address)
                    if owner.get("resource_type") != "vm" or address_net is None:
                        continue
                    if not contains(range_net, address_net):
                        continue
                    found = True
                    host = hosts.setdefault(
                        (vnet_id, str(address)),
                        {
                            "vnet_id": vnet_id,
                            "ip": str(address),
                            "vm": owner,
                            "interface": interface,
                            "name": str(owner.get("name") or owner.get("rid") or ""),
                            "rules": [],
                        },
                    )
                    if label not in host["rules"]:
                        host["rules"].append(label)
                if not found:
                    place = engine.locate(str(range_net))
                    if place["subnet"] is not None:
                        stale.append({"rule": label, "range": entry.get("name") or "", "cidr": cidr, "place": place})
    return list(hosts.values()), stale


# ── One host ────────────────────────────────────────────────────────────────


def _via(route: dict) -> str:
    return f"{show(route['net'])} via {route['name']}"


def _table_name(table: dict | None) -> str:
    return str(table.get("name") or table.get("rid") or "") if table else ""


class _Host:
    """The evaluation of one host: steps (a) to (d)."""

    def __init__(self, engine: Any, host: dict, system: dict, account: dict, out: _Findings) -> None:
        self.engine, self.host, self.system, self.out = engine, host, system, out
        self.sources: list[tuple[str, Network]] = account["sources"]
        self.range = show(system["net"])
        self.place: dict = {}

    def run(self) -> None:
        engine, host = self.engine, self.host
        place = engine.locate(host["ip"], host["vnet_id"])
        if place["subnet"] is None:
            self.out.add(
                UNDETERMINED,
                f"vnet:{host['vnet_id']}",
                host,
                lambda who, n: (
                    f"Undetermined. The subnet of {who} is not collected, so the route to the Cato system range "
                    f"{self.range} cannot be followed."
                ),
                resource_id=host["vnet_id"],
                resource_name=engine.vnet_name(host["vnet_id"]),
            )
            return
        self.place = place
        subnet = place["subnet"]
        host["subnet"] = engine.subnet_name(subnet)
        hop = self._route(place)
        if hop is None:
            return
        route, hop_ip = hop
        owner = engine.owner_at(hop_ip, place["vnet_id"])
        if not self._next_hop(route, hop_ip, owner):
            return
        assert owner is not None
        vm, interface = owner
        vnet_id = str((interface or {}).get("vnet_id") or vm["meta"].get("vnet_id") or "")
        hop_place = engine.locate(hop_ip, vnet_id)
        vm_label = f"{engine.owner_name(vm)} ({hop_ip})"
        if hop_place["subnet"] is None:
            self.out.add(
                UNDETERMINED,
                f"hop:{hop_ip}",
                host,
                lambda who, n: (
                    f"Undetermined. The subnet of {vm_label}, the next hop of {who} to the Cato system range "
                    f"{self.range}, is not collected: its network security groups and return route are not checked."
                ),
                hop_ip=hop_ip,
                resource_id=str(vm.get("rid") or ""),
                resource_name=engine.owner_name(vm),
            )
            return
        self._security_groups(hop_place, vm_label)
        self._return(hop_place, vm, vm_label)

    # (a) The route to the system range.

    def _route(self, place: dict) -> tuple[dict, str] | None:
        found = self.engine.effective_route(place, self.system)
        route, table = found["route"], found["table"]
        subnet = place["subnet"]
        subnet_label = self.engine.subnet_name(subnet)
        fields = {
            "resource_id": str(subnet.get("rid") or ""),
            "resource_name": subnet_label,
            "filter": f"route table {_table_name(table)}" if table else "",
            "rule": str(route["name"]) if route else "",
        }
        detail = {"route": _via(route) if route else "", "route_table": _table_name(table)}
        subject = str(subnet.get("rid") or "")
        rng = self.range

        def undetermined(why: str) -> None:
            self.out.add(
                UNDETERMINED,
                f"route:{subject}",
                self.host,
                lambda who, n: f"Undetermined. {who} in {subnet_label}: {why}",
                detail=detail,
                **fields,
            )

        if found["split"]:
            other = ", ".join(_via(r) for r in found["split"][:3])
            undetermined(
                f"part of the Cato system range {rng} is routed differently ({other}), so which Socket the tunnel of "
                "each session reaches cannot be told."
            )
            return None
        kind = route["kind"] if route else ""
        if route is not None and kind == "virtualappliance":
            hop_ip = str(route.get("next_hop_ip") or "")
            if not hop_ip:
                undetermined(
                    f"the best route to the Cato system range {rng} is {_via(route)}, with no next hop address."
                )
                return None
            return route, hop_ip
        if route is not None and kind == "virtualnetworkgateway":
            undetermined(
                f"the best route to the Cato system range {rng} is {_via(route)}: the tunnel leaves Azure through "
                "the virtual network gateway, and a Cato Socket beyond it is not collected."
            )
            return None
        if found["bgp"] and (route is None or route["net"].prefixlen == 0):
            undetermined(
                f"no collected route covers the Cato system range {rng} more closely than "
                f"{_via(route) if route else 'none'}, and gateway connection(s) {', '.join(found['bgp'])} learn routes "
                "over BGP or ExpressRoute, which are not collected."
            )
            return None
        if route is None:
            why = "no route covers it, so Azure drops the traffic"
        elif kind == "none":
            why = f"the best route is {_via(route)}, which drops the traffic (next hop None)"
        elif kind == "internet":
            why = f"the best route is {_via(route)}, so Azure sends it to the internet, where a private address goes nowhere"
        elif kind in ("vnetlocal", "virtualnetwork"):
            why = (
                f"the best route is {_via(route)}, so Azure keeps it inside "
                f"{self.engine.vnet_name(place['vnet_id'])}, where no subnet holds it"
            )
        elif kind in ("vnetpeering", "virtualnetworkpeering"):
            why = f"the best route is {_via(route)}, which only carries traffic to the addresses of the peered VNet"
        else:
            undetermined(
                f"the best route to the Cato system range {rng} is {_via(route)}, which Plexus does not follow."
            )
            return None
        table_text = (
            f"Route table {_table_name(table)} of the subnet has no user route for it to a virtual appliance"
            if table
            else "The subnet has no route table"
        )
        self.out.add(
            NO_ROUTE,
            subject,
            self.host,
            lambda who, n: (
                f"No route to the Cato system range. {who} in {subnet_label} cannot reach a Cato Socket with the "
                f"per-user tunnel to {rng}: {why}. {table_text}; add a user route for {rng} (or 0.0.0.0/0) with "
                "next hop type Virtual appliance and the LAN IP of the Cato vSocket as next hop."
            ),
            detail=detail,
            **fields,
        )
        return None

    # (b) The next hop.

    def _next_hop(self, route: dict, hop_ip: str, owner: tuple[dict, dict | None] | None) -> bool:
        """Whether the evaluation goes on past the next hop."""
        engine, rng = self.engine, self.range
        subnet_label = engine.subnet_name(self.place["subnet"])
        via = _via(route)
        if owner is None or owner[0].get("resource_type") != "vm":
            if owner is None:
                what = (
                    f"{hop_ip}, which no collected virtual machine has; whether a Cato Socket is there cannot be told"
                )
            else:
                what = (
                    f"{engine.owner_name(owner[0])} ({hop_ip}); what it does with the tunnel is decided by its "
                    "firewall policy, which is not collected"
                )
            self.out.add(
                UNDETERMINED,
                f"hop:{hop_ip}",
                self.host,
                lambda who, n: (
                    f"Undetermined. Route {via} of {subnet_label} sends the tunnel of {who} for the Cato system "
                    f"range {rng} to {what}."
                ),
                hop_ip=hop_ip,
                resource_id=str(owner[0].get("rid") or "") if owner else "",
                resource_name=engine.owner_name(owner[0]) if owner else "",
                rule=str(route["name"]),
            )
            return False
        vm, interface = owner
        vm_label = f"{engine.owner_name(vm)} ({hop_ip})"
        subject = f"{vm.get('rid')}:{hop_ip}"
        fields = {"resource_id": str(vm.get("rid") or ""), "resource_name": engine.owner_name(vm)}
        if interface is not None and interface.get("ip_forwarding") is False:
            nic = str(interface.get("name") or interface.get("id") or "")
            self.out.add(
                IP_FORWARDING_OFF,
                subject,
                self.host,
                lambda who, n: (
                    f"IP forwarding is off on the next hop. Route {via} of {subnet_label} sends the Cato system "
                    f"range {rng} to {vm_label}, but IP forwarding is off on its network interface {nic}, so Azure "
                    f"drops the traffic addressed to {rng} there. Affected {_plural(n, 'host', 'hosts')}: {who}. "
                    "Turn on IP forwarding on that interface."
                ),
                hop_ip=hop_ip,
                detail={"interface": nic, "route": via},
                **fields,
            )
        hop_net = net(hop_ip)
        if self.sources and hop_net is not None and not any(contains(src, hop_net) for _l, src in self.sources):
            org = self.out.org_name
            self.out.add(
                NEXT_HOP_NOT_CATO_SITE,
                subject,
                self.host,
                lambda who, n: (
                    f"Next hop is not in a Cato site. Route {via} of {subnet_label} sends the Cato system range "
                    f"{rng} to {vm_label}, which is in no network range of a site of {org}; the tunnel of {who} "
                    "reaches a Cato Socket only if that machine is a vSocket of another account or forwards to one."
                ),
                hop_ip=hop_ip,
                detail={"route": via},
                **fields,
            )
        return True

    # (c) Network security groups for udp/4754.

    def _security_groups(self, hop_place: dict, vm_label: str) -> None:
        engine, rng = self.engine, self.range
        sides = (
            (
                "outbound",
                engine.nsg_levels(self.place, self.system, True, _PROTOCOL, _PORTS),
                "",
            ),
            (
                "inbound",
                engine.nsg_levels(hop_place, self.place, False, _PROTOCOL, _PORTS, addressed=self.system),
                hop_place["address"],
            ),
        )
        for direction, levels, hop_ip in sides:
            for level in levels:
                step = level["step"]
                status = step.get("status")
                if status == OK:
                    continue
                where = str(step.get("where") or "")
                text = str(step.get("text") or "")
                at = f" at {vm_label}" if hop_ip else ""
                fields = {
                    "resource_id": level["nsg_id"],
                    "resource_name": level["nsg_name"],
                    "protocol": _PROTOCOL,
                    "ports": str(GRE_UDP_PORT),
                    "filter": f"network security group {level['nsg_name']}, {direction}",
                    "rule": level["rule"],
                    "rule_id": level["rule_id"],
                }
                detail = {"direction": direction, "level": level["level"], "step": text}
                if status == BLOCKED:
                    self.out.add(
                        NSG_BLOCKED,
                        f"{level['nsg_id']}:{direction}:{level['rule_id']}",
                        self.host,
                        _around(
                            f"A network security group blocks the tunnel. Network security group "
                            f"{level['nsg_name']} denies {_TRAFFIC} {direction}{at} from ",
                            f" to the Cato system range {rng} ({text.rstrip('.')}). The Cato Client sends each user "
                            f"session's tunnel there as GRE over UDP; allow {_TRAFFIC} to {rng} ahead of "
                            f"{level['rule']}.",
                        ),
                        hop_ip=hop_ip,
                        detail=detail,
                        **fields,
                    )
                else:
                    self.out.add(
                        UNDETERMINED,
                        f"nsg:{level['nsg_id'] or level['level']}:{direction}",
                        self.host,
                        _around(f"Undetermined. {where}, {_TRAFFIC} from ", f" to the Cato system range {rng}: {text}"),
                        hop_ip=hop_ip,
                        detail=detail,
                        **fields,
                    )

    # (d) The route back to the host.

    def _return(self, hop_place: dict, vm: dict, vm_label: str) -> None:
        engine = self.engine
        found = engine.effective_route(hop_place, self.place)
        if found["same_subnet"]:
            return
        route = found["route"]
        kind = route["kind"] if route else ""
        host_vnet = self.place["vnet_id"]
        if kind in ("vnetlocal", "virtualnetwork") and hop_place["vnet_id"] == host_vnet:
            return
        if kind in ("vnetpeering", "virtualnetworkpeering") and route is not None and route.get("peer") == host_vnet:
            return
        hop_subnet = hop_place["subnet"]
        hop_label = engine.subnet_name(hop_subnet)
        host_subnet = self.host.get("subnet", "")
        subject = f"{hop_subnet.get('rid')}:{self.place['subnet'].get('rid')}"
        fields = {
            "resource_id": str(hop_subnet.get("rid") or ""),
            "resource_name": hop_label,
            "filter": f"route table {_table_name(found['table'])}" if found["table"] else "",
            "rule": str(route["name"]) if route else "",
        }
        detail = {"route": _via(route) if route else "", "route_table": _table_name(found["table"])}
        hop_ip = hop_place["address"]
        if route is None or kind == "none" or (kind == "internet" and not found["bgp"]):
            why = (
                "no route covers them"
                if route is None
                else f"its best route is {_via(route)}, which "
                + ("drops the traffic (next hop None)" if kind == "none" else "sends it to the internet")
            )
            self.out.add(
                NO_RETURN_ROUTE,
                subject,
                self.host,
                lambda who, n: (
                    f"No return route from the next hop. {hop_label}, where {vm_label} is, has no route back to "
                    f"{who} in {host_subnet}: {why}. The Socket's replies to the "
                    f"{_plural(n, 'host', 'hosts')} are lost."
                ),
                hop_ip=hop_ip,
                detail=detail,
                **fields,
            )
            return
        what = _via(route) if route else "none"
        self.out.add(
            UNDETERMINED,
            f"return:{subject}",
            self.host,
            lambda who, n: (
                f"Undetermined. Replies from {vm_label} to {who} in {host_subnet}: the best route of {hop_label} is "
                f"{what}, which Plexus does not follow back to the hosts."
            ),
            hop_ip=hop_ip,
            detail=detail,
            **fields,
        )


# ── The check ───────────────────────────────────────────────────────────────


def _next_hops(engine: Any, hosts: list[dict], system: dict) -> set[str]:
    """The next-hop addresses of the user routes to a virtual appliance the
    hosts' subnets send the system range to."""
    found: set[str] = set()
    for host in hosts:
        place = engine.locate(host["ip"], host["vnet_id"])
        if place["subnet"] is None:
            continue
        route = engine.effective_route(place, system)["route"]
        if route is not None and route["kind"] == "virtualappliance" and route.get("next_hop_ip"):
            found.add(str(route["next_hop_ip"]))
    return found


def _enabled_rules(block: dict | None) -> list[dict]:
    if not isinstance(block, dict) or block.get("enabled") is False:
        return []
    return [r for r in block.get("rules") or [] if isinstance(r, dict) and r.get("enabled") is not False]


def _check_account(org_ref: int, snapshot: dict, engines: list[Any], system_range: Network) -> list[dict[str, Any]]:
    org_name = str((snapshot.get("org") or {}).get("name") or f"Cato account {org_ref}")
    account = cato_account(snapshot)
    rules = _enabled_rules(account["shared_hosts"])
    if not rules:
        return []
    out = _Findings(org_ref, org_name)
    for rule in rules:
        names = [str(n) for n in rule.get("unresolved") or [] if str(n)]
        if not names:
            continue
        label = network_rules.rule_label(rule)
        out.add(
            HOSTS_NOT_RESOLVED,
            str(rule.get("index")),
            None,
            _constant(
                f"{org_name}: {label} of the Shared Hosts policy names "
                f"{_plural(len(names), 'the global IP range', 'the global IP ranges')} {', '.join(names)}, which "
                f"did not resolve to addresses (the IP ranges were not collected, or several share the name); the "
                "hosts in them are not checked."
            ),
            provider="",
            rule=label,
            detail={"ranges": names},
        )
    azure_hosts: list[dict] = []
    for engine in engines:
        hosts, stale = _hosts(engine, rules)
        for entry in stale:
            place = entry["place"]
            where = f"{engine.subnet_name(place['subnet'])} of {engine.vnet_name(place['vnet_id'])}"
            out.add(
                NO_HOST_FOUND,
                f"{entry['rule']}:{entry['cidr']}",
                None,
                _constant(
                    f"No host at a Shared Hosts range. {entry['rule']} names {entry['range']} ({entry['cidr']}), "
                    f"inside {where}, but no collected Azure virtual machine has an address in it: the host may "
                    "have been removed or given another address."
                ),
                resource_id=str(place["subnet"].get("rid") or ""),
                resource_name=engine.subnet_name(place["subnet"]),
                rule=entry["rule"],
                detail={"range": entry["range"], "cidr": entry["cidr"]},
            )
        system = engine.locate(str(system_range))
        # The appliance the hosts route the system range to (the vSocket) is
        # no shared host, even when a rule's range covers its subnet.
        hops = _next_hops(engine, hosts, system)
        hosts = [h for h in hosts if h["ip"] not in hops]
        for host in hosts:
            _Host(engine, host, system, account, out).run()
        azure_hosts.extend(hosts)
    if azure_hosts:
        excluded = [
            {"rule": network_rules.rule_label(rule), "name": entry.get("name") or "", "cidrs": entry.get("cidrs") or []}
            for rule in rules
            for entry in rule.get("excluded") or []
        ]
        rng = show(system_range)

        def gre_text(who: str, n: int) -> str:
            text = (
                f"GRE over UDP required. Azure drops GRE (IP protocol 47) inside a VNet, so the Cato Client on "
                f"{_plural(n, 'the Azure virtual machine', f'the {n} Azure virtual machines')} the Shared Hosts rules "
                f"of {org_name} name ({who}) must send each user session's tunnel as GRE over UDP (registry value "
                f"GREOverUDP = 1), on UDP port {GRE_UDP_PORT} to {rng}. Plexus cannot read that setting; this check "
                f"evaluates {_TRAFFIC}."
            )
            if excluded:
                names = ", ".join(sorted({str(e["name"]) for e in excluded if e["name"]}))
                text += f" Traffic to {names} is excluded from the tunnel and is not attributed to a user."
            return text

        for host in azure_hosts:
            out.add(
                GRE_OVER_UDP,
                PROVIDER,
                host,
                gre_text,
                protocol=_PROTOCOL,
                ports=str(GRE_UDP_PORT),
                detail={"excluded": excluded, "system_range": rng},
            )
    return out.build()


def check(
    cato: list[tuple[int, dict]],
    clouds: list[tuple[str, Any]],
    *,
    system_range: str = DEFAULT_SYSTEM_RANGE,
) -> list[dict[str, Any]]:
    """The findings of every Cato account snapshot (``(org_ref, snapshot)``)
    against the Azure reachability engines among ``clouds`` (``(provider,
    engine)``). ``system_range`` is the Cato system range the per-user
    tunnels go to (an IPv4 network)."""
    system = net(system_range)
    if system is None or system.version != 4:
        raise ValueError(f"{system_range!r} is not an IPv4 network")
    engines = [engine for provider, engine in clouds if provider == PROVIDER]
    findings: list[dict[str, Any]] = []
    for org_ref, snapshot in cato:
        findings.extend(_check_account(org_ref, snapshot, engines, system))
    return findings


__all__ = [
    "DEFAULT_SYSTEM_RANGE",
    "GRE_UDP_PORT",
    "KIND_LABELS",
    "check",
    "severity_of",
]
