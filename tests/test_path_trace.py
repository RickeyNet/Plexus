"""Path tracing: a flow hop by hop across Meraki, FTD, Cato, inventory and
cloud devices, in both directions (``netcontrol.integrations.pathtrace``)."""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
from netcontrol.integrations.aws.reachability import Reachability
from netcontrol.integrations.cato.normalize import (
    CLOUD_NODE_ID as CATO_CLOUD_NODE_ID,
    build_snapshot as build_cato_snapshot,
)
from netcontrol.integrations.cato.sample import build_sample_raw as build_cato_sample_raw
from netcontrol.integrations.meraki.forwarding import (
    interface,
    nat,
    new_block,
    peer_block,
    policy_set,
    route,
    rule,
)
from netcontrol.integrations.meraki.unified import graph_to_snapshot, merge_meraki_into_graph
from netcontrol.integrations.pathtrace.engine import STATEFUL_REPLY, Tracer
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host
from netcontrol.integrations.pathtrace.model import FULL, NONE, PART, cover, longest_route, net, ports_match

# ── Builders ─────────────────────────────────────────────────────────────────


def _node(node_id: str, kind: str, site: str, label: str, block: dict | None = None, **fields) -> dict:
    node = {
        "id": node_id,
        "kind": kind,
        "site": site,
        "label": label,
        "status": "online",
        "x": 0.0,
        "y": 0.0,
        "sections": [],
        **fields,
    }
    if block is not None:
        node["forwarding"] = block
    return node


def _edge(edge_id: str, a: str, b: str, kind: str = "vpn", status: str = "reachable") -> dict:
    return {"id": edge_id, "a": a, "b": b, "kind": kind, "status": status, "a_port": "", "b_port": ""}


def _snapshot(name: str, nodes: list[dict], edges: list[dict], sites: dict[str, str], provider: str = "meraki"):
    return {
        "org": {"name": name},
        "provider": provider,
        "sites": [{"id": site, "name": label} for site, label in sites.items()],
        "nodes": nodes,
        "edges": edges,
    }


def _tracer(snapshots: dict, *, clouds=None, hosts=None, extra_nodes=(), extra_edges=(), subnets=()) -> Tracer:
    nodes: dict = {n["id"]: n for n in extra_nodes}
    edges: list = []
    merge_meraki_into_graph(
        nodes,
        edges,
        list(snapshots.items()),
        host_node=lambda host_id: nodes.get(host_id),
        resolve_external=lambda _name, _ip: None,
    )
    edges.extend(extra_edges)
    graph = {"nodes": list(nodes.values()), "edges": edges}
    return Tracer(graph, snapshots, clouds or {}, hosts or {}, list(subnets))


def _mx(
    vlans: dict[str, tuple[str, str]],
    *,
    routes=(),
    l3=(),
    vpn_rules=(),
    inbound=(),
    nats=(),
    wan_ip: str = "",
    gateway: str = "",
    missing=("Layer 7 firewall rules", "Group policies"),
) -> dict:
    """A Meraki MX block the way Worker A's normaliser shapes it."""
    block = new_block()
    for name, (ip, cidr) in vlans.items():
        block["interfaces"].append(interface(name, "vlan", ip=ip, cidr=cidr))
        block["routes"].append(route(cidr, "connected", interface=name, source=f"Connected {name}"))
    block["interfaces"].append(interface("wan1", "wan", ip=wan_ip))
    block["routes"].extend(routes)
    if gateway:
        block["routes"].append(
            route("0.0.0.0/0", "default", next_hop=gateway, interface="wan1", source="Default route via wan1")
        )
    block["policies"] = [
        policy_set(
            "Layer 3 firewall rules", "firewall", "lan_in", [*l3, rule(len(l3) + 1, "allow", comment="Default rule")]
        ),
        policy_set(
            "Site-to-site VPN firewall rules",
            "vpn_firewall",
            "vpn_out",
            [*vpn_rules, rule(len(vpn_rules) + 1, "allow", comment="Default rule")],
        ),
        policy_set("Inbound firewall rules", "inbound", "wan_in", list(inbound), default="deny"),
    ]
    block["nat"] = [*nats, nat(len(nats) + 1, "interface_pat", name="Uplink address", translated_src=["interface"])]
    block["not_collected"] = list(missing)
    return block


def _items(hop: dict, *, info: bool = False) -> list[tuple[str, str, str]]:
    return [(i["stage"], i["status"], i["where"]) for i in hop["items"] if info or i["status"] != "info"]


def _labels(direction: dict) -> list[str]:
    return [h["label"] for h in direction["hops"]]


# ── Matching helpers ─────────────────────────────────────────────────────────


def test_matching_helpers_are_three_valued():
    host, subnet = net("10.1.10.5"), net("10.1.0.0/16")
    assert cover(["any"], host) == FULL and cover(["10.1.10.0/24"], host) == FULL
    assert cover(["10.1.10.0/24"], subnet) == PART and cover(["10.2.0.0/16"], subnet) == NONE
    assert ports_match("any", None) == FULL and ports_match("443", None) == PART
    assert ports_match("80,443", (443, 443)) == FULL and ports_match("1000-2000", (1500, 3000)) == PART
    assert ports_match("22", (443, 443)) == NONE
    routes = [
        route("0.0.0.0/0", "default", next_hop="192.0.2.1"),
        route("10.0.0.0/8", "autovpn", peer={"site": "A"}),
        route("10.0.0.0/8", "static", next_hop="10.9.9.9", metric=5),
        route("10.0.0.0/8", "static", next_hop="10.9.9.8", metric=1),
        route("10.1.0.0/16", "static", next_hop="10.9.9.7", vrf="red"),
    ]
    best, _narrower = longest_route(routes, net("10.1.2.3"))
    assert best["next_hop"] == "10.9.9.8"  # static beats AutoVPN, then the lower metric
    assert longest_route(routes, net("10.1.2.3"), "red")[0]["next_hop"] == "10.9.9.7"


# ── Meraki AutoVPN ───────────────────────────────────────────────────────────


def _branch_and_hub(vpn_rules=()) -> dict:
    branch = _mx(
        {"VLAN 10": ("10.1.10.1", "10.1.10.0/24"), "VLAN 30": ("10.1.30.1", "10.1.30.0/24")},
        routes=[route("10.0.10.0/24", "autovpn", peer={"site": "HUB"}, source="AutoVPN from Hub 01")],
        vpn_rules=vpn_rules,
        wan_ip="198.51.100.2",
        gateway="198.51.100.1",
    )
    hub = _mx(
        {"VLAN 10": ("10.0.10.1", "10.0.10.0/24")},
        routes=[
            route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01"),
            route("10.1.30.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01"),
        ],
        wan_ip="203.0.113.2",
        gateway="203.0.113.1",
    )
    nodes = [
        _node("d:BR", "appliance", "BR", "Branch 01 MX", branch),
        _node("d:HUB", "appliance", "HUB", "Hub 01 MX", hub),
    ]
    return {1: _snapshot("Acme", nodes, [_edge("e1", "d:BR", "d:HUB")], {"BR": "Branch 01", "HUB": "Hub 01"})}


_SUBNETS = [
    {"org_ref": 1, "node_id": "d:BR", "cidr": "10.1.10.0/24"},
    {"org_ref": 1, "node_id": "d:BR", "cidr": "10.1.30.0/24"},
    {"org_ref": 1, "node_id": "d:HUB", "cidr": "10.0.10.0/24"},
]


def test_branch_vlan_to_hub_vlan_over_autovpn_is_allowed_and_the_replies_are_stateful():
    result = _tracer(_branch_and_hub(), subnets=_SUBNETS).trace("10.1.10.5", "10.0.10.20", protocol="tcp", port=443)

    assert result["applies"] and result["verdict"] == "allowed" and result["traffic"] == "tcp/443"
    assert result["source"]["node"] == "meraki:1:d:BR" and result["destination"]["label"] == "Hub 01 MX"
    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "Hub 01 MX"]
    branch, hub = request["hops"]
    assert branch["in"] == "VLAN 10" and branch["out"] == "AutoVPN to Hub 01" and branch["edge"] is None
    assert _items(branch) == [
        ("policy", "ok", "Layer 3 firewall rules"),
        ("route", "ok", "AutoVPN from Hub 01"),
        ("policy", "ok", "Site-to-site VPN firewall rules"),
        ("link", "ok", "Link to Hub 01 MX"),
    ]
    assert branch["items"][0]["rule"] == 1 and "Default rule" in branch["items"][0]["text"]
    assert hub["edge"] == "meraki:1:e1" and hub["in"] == "AutoVPN from Branch 01" and hub["out"] == "VLAN 10"
    assert _items(hub) == [("route", "ok", "Connected VLAN 10")]
    assert "delivered on VLAN 10" in hub["items"][-1]["text"]
    # What is not collected is a note: it does not change the verdict, and the summary names it.
    assert ("note", "info", "Layer 7 firewall rules") in _items(branch, info=True)
    assert request["summary"].endswith("Not checked: Layer 7 firewall rules, group policies.")

    reply = result["reply"]
    assert reply["verdict"] == "allowed" and _labels(reply) == ["Hub 01 MX", "Branch 01 MX"]
    stateful = {i["where"] for i in reply["hops"][0]["items"] if i["text"] == STATEFUL_REPLY}
    assert stateful == {"Layer 3 firewall rules", "Site-to-site VPN firewall rules"}
    assert result["asymmetric"] == {"status": "no", "text": "Replies take the same hops back."}


def test_an_autovpn_route_to_a_site_with_a_warm_spare_lands_on_the_primary():
    # Meraki reports a network's AutoVPN tunnels under its primary appliance,
    # so the map draws them from the primary only. The spare is listed first
    # and forwards like the primary, but the trace must not pick it: it has
    # no tunnel, and the path would end with "No AutoVPN tunnel that is up".
    snapshots = _branch_and_hub()
    snap = snapshots[1]
    primary = snap["nodes"][1]
    primary["site_sections"] = True
    spare = _node("d:HUB2", "appliance", "HUB", "Hub 01 MX spare", primary["forwarding"])
    snap["nodes"].insert(1, spare)
    snap["edges"].append(_edge("e2", "d:HUB2", "d:HUB", kind="lan", status="active"))
    result = _tracer(snapshots, subnets=_SUBNETS).trace("10.1.10.5", "10.0.10.20", protocol="tcp", port=443)

    assert result["verdict"] == "allowed"
    assert _labels(result["request"]) == ["Branch 01 MX", "Hub 01 MX"]
    assert _labels(result["reply"]) == ["Hub 01 MX", "Branch 01 MX"]
    assert _items(result["request"]["hops"][0])[-1] == ("link", "ok", "Link to Hub 01 MX")


def test_a_vpn_firewall_rule_that_denies_blocks_at_the_branch():
    deny = rule(1, "deny", src=["10.1.30.0/24"], dst=["10.0.0.0/8"], comment="Block guest over the VPN")
    result = _tracer(_branch_and_hub([deny]), subnets=_SUBNETS).trace("10.1.30.7", "10.0.10.20")

    assert result["verdict"] == "blocked" and result["traffic"] == "any traffic"
    assert result["summary"].startswith("Blocked at Branch 01 MX, Site-to-site VPN firewall rules: Rule 1 (deny any")
    hops = result["request"]["hops"]
    assert len(hops) == 1 and hops[0]["status"] == "blocked"
    assert _items(hops[0])[-1] == ("policy", "blocked", "Site-to-site VPN firewall rules")
    assert hops[0]["items"][-1]["rule"] == 1
    assert result["reply"]["hops"] == [] and result["asymmetric"]["status"] == "unknown"


def test_any_traffic_lists_the_ports_the_rule_sets_allow():
    only_https = [rule(1, "allow", protocol="tcp", dst_ports="443"), rule(2, "deny")]
    tracer = _tracer(_branch_and_hub(only_https), subnets=_SUBNETS)
    result = tracer.trace("10.1.10.5", "10.0.10.20")

    assert result["verdict"] == "partial"
    assert result["ports"] == {"allowed": {"tcp": "443"}, "partial": {}, "unknown": {}, "text": "allowed tcp 443"}
    assert result["request"]["ports"] == result["ports"]
    # Stateful rule sets accept every reply of an allowed request.
    assert result["reply"]["ports"]["text"] == "allowed tcp any · udp any · icmp"
    branch = result["request"]["hops"][0]
    deciding = next(i for i in branch["items"] if i["where"] == "Site-to-site VPN firewall rules")
    assert deciding["status"] == "partial" and deciding["ports"]["allowed"] == {"tcp": "443"}
    assert "ports" not in next(i for i in branch["items"] if i["stage"] == "route")

    # One port: the replies of a request that does not arrive are not traced.
    blocked = tracer.trace("10.1.10.5", "10.0.10.20", protocol="tcp", port=22)
    assert blocked["verdict"] == "blocked" and blocked["reply"]["ports"] is None
    assert blocked["ports"] == {"allowed": {}, "partial": {}, "unknown": {}, "text": "allowed none"}


def test_a_rule_set_that_is_not_collected_leaves_every_port_unknown():
    snapshots = _branch_and_hub()
    branch = snapshots[1]["nodes"][0]["forwarding"]
    branch["policies"] = [p for p in branch["policies"] if p["name"] != "Layer 3 firewall rules"]
    branch["not_collected"].append("Layer 3 firewall rules")
    result = _tracer(snapshots, subnets=_SUBNETS).trace("10.1.10.5", "10.0.10.20")

    assert result["verdict"] == "unknown"
    assert result["ports"]["allowed"] == {}
    assert result["ports"]["text"] == "allowed none; not decided tcp any · udp any · icmp"


def _with_partner(status: str) -> dict:
    snapshots = _branch_and_hub()
    snap = snapshots[1]
    branch = snap["nodes"][0]["forwarding"]
    branch["routes"].append(
        route("172.21.0.0/16", "vpn3p", peer={"org_node": "p:Partner"}, source="Non-Meraki VPN peer Partner")
    )
    snap["sites"].append({"id": "__vpn_peers__", "name": "Non-Meraki VPN peers"})
    snap["nodes"].append(
        _node("p:Partner", "vpn_peer", "__vpn_peers__", "Partner", peer_block("Partner", ["172.21.0.0/16"]))
    )
    snap["edges"].append(_edge("e2", "d:BR", "p:Partner", kind="vpn3p", status=status))
    return snapshots


def test_a_non_meraki_peer_behind_a_tunnel_that_is_down_has_no_path_at_the_link():
    tracer = _tracer(_with_partner("unreachable"), subnets=_SUBNETS)
    result = tracer.trace("10.1.10.5", "172.21.4.4", destination_node="meraki:1:p:Partner")

    # The route exists and nothing denies the flow: not blocked, unreachable.
    assert result["verdict"] == "unreachable"
    last = result["request"]["hops"][-1]
    assert last["label"] == "Branch 01 MX" and _items(last)[-1] == ("link", "blocked", "Link to Partner")
    assert last["items"][-1]["text"] == (
        "The IPsec tunnel between Branch 01 MX and Partner is down: Meraki reports it unreachable."
    )
    assert result["summary"].startswith(
        "No path at Branch 01 MX, Link to Partner: "
        "The IPsec tunnel between Branch 01 MX and Partner is down: Meraki reports it unreachable."
    )

    # Up, the flow reaches the peer, but nothing behind it is known.
    up = _tracer(_with_partner("reachable"), subnets=_SUBNETS).trace(
        "10.1.10.5", "172.21.4.4", destination_node="meraki:1:p:Partner"
    )
    assert up["request"]["verdict"] == "unknown" and _labels(up["request"]) == ["Branch 01 MX", "Partner"]
    assert ("note", "unknown", "Everything behind a non-Meraki VPN peer") in _items(up["request"]["hops"][-1])


# ── Cisco FTD and an inventory host ──────────────────────────────────────────

_IOS_CAPTURE = """\
Codes: L - local, C - connected, S - static, O - OSPF
Gateway of last resort is 10.60.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.60.0.1
      10.0.0.0/8 is variably subnetted, 4 subnets, 2 masks
C        10.60.0.0/24 is directly connected, Vlan60
L        10.60.0.254/32 is directly connected, Vlan60
C        10.70.1.0/24 is directly connected, Vlan10
L        10.70.1.1/32 is directly connected, Vlan10
"""


def _ftd_block() -> dict:
    block = new_block()
    block["interfaces"] = [
        interface("outside", "wan", ip="198.51.100.10", cidr="198.51.100.0/28", zone="outside"),
        interface("inside", "routed", ip="10.60.0.1", cidr="10.60.0.0/24", zone="inside"),
        interface("guest", "routed", ip="10.60.30.1", cidr="10.60.30.0/24", zone="guest"),
    ]
    for item in block["interfaces"]:
        block["routes"].append(
            route(item["cidr"], "connected", interface=item["name"], source=f"Connected {item['name']}")
        )
    block["routes"] += [
        route("0.0.0.0/0", "default", next_hop="198.51.100.1", interface="outside", source="Static route any-ipv4"),
        route("10.70.0.0/16", "static", next_hop="10.60.0.254", interface="inside", source="Static route DC"),
    ]
    block["policies"] = [
        policy_set(
            "Prefilter policy Corp",
            "prefilter",
            "any",
            [
                rule(
                    1,
                    "fastpath",
                    name="Fastpath-Backup",
                    protocol="tcp",
                    src=["10.60.0.0/24"],
                    dst=["10.70.0.0/16"],
                    dst_ports="873",
                    src_zones=["inside"],
                    dst_zones=["inside"],
                )
            ],
        ),
        policy_set(
            "Access control policy Corp",
            "firewall",
            "any",
            [
                rule(1, "deny", name="Block-Guest", src_zones=["guest"], dst_zones=["inside"]),
                rule(
                    2,
                    "allow",
                    name="Web",
                    protocol="tcp",
                    src=["10.60.0.0/24"],
                    dst_ports="443",
                    src_zones=["inside"],
                    dst_zones=["outside"],
                ),
                rule(
                    3,
                    "allow",
                    name="SSH-App",
                    protocol="tcp",
                    src=["10.60.0.0/24"],
                    dst=["10.70.0.0/16"],
                    dst_ports="22",
                    unresolved=["application SSH"],
                ),
                rule(
                    4,
                    "allow",
                    name="To-DC",
                    src=["10.60.0.0/24"],
                    dst=["10.70.0.0/16"],
                    src_zones=["inside"],
                    dst_zones=["inside"],
                ),
            ],
            default="deny",
        ),
    ]
    block["nat"] = [
        nat(
            1,
            "auto",
            name="Inside PAT",
            original_src=["10.60.0.0/24"],
            translated_src=["interface"],
            src_interface="inside",
            dst_interface="outside",
        ),
    ]
    return block


# The configuration backup of core-sw: its two SVIs, no access lists.
_CORE_SW_CONFIG = """\
hostname core-sw
interface Vlan10
 ip address 10.70.1.1 255.255.255.0
!
interface Vlan60
 ip address 10.60.0.254 255.255.255.0
!
end
"""


def _ftd_tracer(config: str | None = _CORE_SW_CONFIG) -> Tracer:
    snapshot = _snapshot(
        "Corp FMC",
        [_node("d:FTD", "appliance", "dev:FTD", "ftd-branch", _ftd_block())],
        [],
        {"dev:FTD": "ftd-branch"},
        provider="fmc",
    )
    host = {
        "id": 7,
        "label": "core-sw",
        "ip": "10.60.0.254",
        "in_inventory": True,
        "device_type": "cisco_ios",
        "group_name": "Core",
    }
    block = forwarding_for_host(
        {"ip_address": "10.60.0.254", "device_type": "cisco_ios"},
        [],
        {"id": 1, "routes_text": _IOS_CAPTURE},
        [{"name": "Vlan10", "admin_state": "up"}, {"name": "Vlan60", "admin_state": "up"}],
        config_backup={"id": 5, "config_text": config} if config is not None else None,
    )
    lldp = {"id": 42, "from": "meraki:2:d:FTD", "to": 7, "protocol": "lldp", "status": ""}
    subnets = [
        {"org_ref": 2, "node_id": "d:FTD", "cidr": "10.60.0.0/24"},
        {"org_ref": 2, "node_id": "d:FTD", "cidr": "10.60.30.0/24"},
    ]
    return _tracer({2: snapshot}, hosts={7: block}, extra_nodes=[host], extra_edges=[lldp], subnets=subnets)


def test_ftd_prefilter_fastpath_skips_the_access_policy_and_the_static_route_reaches_an_inventory_host():
    result = _ftd_tracer().trace("10.60.0.5", "10.70.1.5", destination_node="7", protocol="tcp", port=873)

    assert result["verdict"] == "allowed", result["summary"]
    ftd, host = result["request"]["hops"]
    assert ftd["out"] == "inside" and host["node"] == 7 and host["provider"] == "inventory"
    assert host["edge"] == 42 and host["in"] == "Vlan60" and host["out"] == "Vlan10"
    prefilter = next(i for i in ftd["items"] if i["where"] == "Prefilter policy Corp")
    assert prefilter["status"] == "ok" and prefilter["rule"] == 1 and "fastpaths it" in prefilter["text"]
    skipped = next(i for i in ftd["items"] if i["where"] == "Access control policy Corp")
    assert skipped["status"] == "info" and skipped["text"] == "Skipped: the prefilter fastpaths this flow."
    assert ("route", "ok", "Static route DC") in _items(ftd)
    # The host's configuration backup binds no access list: nothing is left unchecked.
    assert "Not checked" not in result["request"]["summary"]
    # The host is on the FTD's inside subnet: it answers the source directly.
    assert _labels(result["reply"]) == ["core-sw"]
    assert result["asymmetric"] == {
        "status": "yes",
        "text": "Replies from 10.70.1.5 end at core-sw and never pass ftd-branch, which the request did. ftd-branch "
        "has a stateful firewall that sees the request but never the replies: its connection state never "
        "completes, so the rest of the connection can be dropped there.",
    }


def test_inventory_host_without_a_configuration_backup_leaves_its_access_lists_unknown():
    result = _ftd_tracer(config=None).trace("10.60.0.5", "10.70.1.5", destination_node="7", protocol="tcp", port=873)

    assert result["verdict"] == "unknown", result["summary"]
    host = result["request"]["hops"][-1]
    decided = next(i for i in host["items"] if i["status"] == "unknown")
    assert decided["stage"] == "acl" and decided["where"] == "Access lists"
    assert decided["text"] == "Access lists are not collected: whether they allow this flow is not known."
    # Stateless: the replies meet them again.
    reply_host = result["reply"]["hops"][0]
    assert ("acl", "unknown", "Access lists") in _items(reply_host)


def test_ftd_access_policy_denies_by_zone():
    result = _ftd_tracer().trace("10.60.30.5", "10.60.0.5", protocol="tcp", port=443)

    assert result["verdict"] == "blocked"
    hop = result["request"]["hops"][0]
    assert hop["in"] == "guest" and hop["out"] == "inside"
    assert _items(hop)[-1] == ("policy", "blocked", "Access control policy Corp")
    assert hop["items"][-1]["rule"] == 1 and "zones from guest to inside" in hop["items"][-1]["text"]


def test_ftd_rule_that_also_matches_on_an_application_is_unknown():
    result = _ftd_tracer().trace("10.60.0.5", "10.70.1.5", destination_node=7, protocol="tcp", port=22)

    assert result["request"]["verdict"] == "unknown"
    decided = next(i for i in result["request"]["hops"][0]["items"] if i["status"] == "unknown")
    assert decided["rule"] == 3 and "also matches on application SSH" in decided["text"]
    assert result["summary"].startswith("Could not be decided at ftd-branch, Access control policy Corp: Rule 3")


def test_ftd_auto_nat_translates_the_source_and_the_session_translates_the_replies_back():
    result = _ftd_tracer().trace("10.60.0.5", "8.8.8.8", protocol="tcp", port=443)

    assert result["verdict"] == "allowed", result["summary"]
    ftd, internet = result["request"]["hops"]
    assert internet == {**internet, "node": None, "label": "Internet", "provider": "internet", "in": "outside"}
    translation = next(i for i in ftd["items"] if i["stage"] == "nat")
    assert translation["text"] == "Source 10.60.0.5 becomes 198.51.100.10." and translation["rule"] == 1
    assert ("policy", "ok", "Access control policy Corp") in _items(ftd)

    reply = result["reply"]
    assert _labels(reply) == ["Internet", "ftd-branch"] and reply["hops"][1]["in"] == "Internet"
    back = reply["hops"][1]["items"]
    assert back[0]["stage"] == "nat" and back[0]["status"] == "info"
    assert back[0]["text"] == "Replies to 198.51.100.10 are translated back to 10.60.0.5 by the session."
    assert {i["where"] for i in back if i["text"] == STATEFUL_REPLY} == {
        "Prefilter policy Corp",
        "Access control policy Corp",
    }
    assert any("delivered on inside" in i["text"] for i in back) and result["asymmetric"]["status"] == "no"


def _vpn_tracer(exempt: bool) -> Tracer:
    """The branch FTD with a policy-based VPN to a hub FTD that holds 10.200.10.0/24."""
    branch = _ftd_block()
    branch["vpn"] = [
        {
            "name": "To-Hub",
            "interface": "outside",
            "local": ["10.60.0.0/24"],
            "remote": ["10.200.0.0/16"],
            "peer": {"org_node": "d:HUB"},
            "status": "up",
        }
    ]
    if exempt:
        branch["nat"].insert(
            0,
            nat(
                1,
                "manual_before",
                name="No NAT towards the hub",
                original_src=["10.60.0.0/24"],
                original_dst=["10.200.0.0/16"],
                translated_src=["10.60.0.0/24"],
                translated_dst=["10.200.0.0/16"],
                src_interface="inside",
                dst_interface="outside",
            ),
        )
    hub = new_block()
    hub["interfaces"] = [
        interface("outside", "wan", ip="203.0.113.20", cidr="203.0.113.16/28", zone="outside"),
        interface("inside", "routed", ip="10.200.10.1", cidr="10.200.10.0/24", zone="inside"),
    ]
    hub["routes"] = [
        route("203.0.113.16/28", "connected", interface="outside", source="Connected outside"),
        route("10.200.10.0/24", "connected", interface="inside", source="Connected inside"),
        route("0.0.0.0/0", "default", next_hop="203.0.113.17", interface="outside", source="Static route any-ipv4"),
    ]
    hub["vpn"] = [
        {
            "name": "To-Branch",
            "interface": "outside",
            "local": ["10.200.0.0/16"],
            "remote": ["10.60.0.0/24"],
            "peer": {"org_node": "d:FTD"},
            "status": "up",
        }
    ]
    hub["policies"] = [policy_set("Access control policy Hub", "firewall", "any", [], default="allow")]
    snapshot = _snapshot(
        "Corp FMC",
        [
            _node("d:FTD", "appliance", "dev:FTD", "ftd-branch", branch),
            _node("d:HUB", "appliance", "dev:HUB", "ftd-hub", hub),
        ],
        [_edge("e1", "d:FTD", "d:HUB")],
        {"dev:FTD": "ftd-branch", "dev:HUB": "ftd-hub"},
        provider="fmc",
    )
    return _tracer({2: snapshot})


def test_ftd_vpn_selector_sees_the_source_after_nat_so_an_exemption_lets_the_flow_into_the_tunnel():
    result = _vpn_tracer(exempt=True).trace(
        "10.60.0.5",
        "10.200.10.20",
        source_node="meraki:2:d:FTD",
        destination_node="meraki:2:d:HUB",
        protocol="tcp",
        port=443,
    )

    assert result["verdict"] == "allowed", result["summary"]
    branch, hub = result["request"]["hops"]
    assert (
        branch["out"] == "VPN To-Hub to ftd-hub"
        and hub["in"] == "Tunnel from ftd-branch"
        and hub["edge"] == "meraki:2:e1"
    )
    texts = [i["text"] for i in branch["items"]]
    access = next(n for n, i in enumerate(branch["items"]) if i["where"] == "Access control policy Corp")
    exempt = texts.index("Identity NAT: the source is left unchanged.")
    tunnel = next(n for n, i in enumerate(branch["items"]) if i["where"] == "Site-to-site VPN To-Hub")
    # The access policy, then NAT, then the VPN selector, which sees the source NAT left unchanged.
    assert access < exempt < tunnel and branch["items"][tunnel]["status"] == "ok"
    # The replies go back over the hub's own selector.
    assert _labels(result["reply"]) == ["ftd-hub", "ftd-branch"] and result["asymmetric"]["status"] == "no"


def test_ftd_vpn_selector_does_not_match_a_source_translated_by_interface_pat():
    result = _vpn_tracer(exempt=False).trace(
        "10.60.0.5",
        "10.200.10.20",
        source_node="meraki:2:d:FTD",
        destination_node="meraki:2:d:HUB",
        protocol="tcp",
        port=443,
    )

    branch, internet = result["request"]["hops"]
    assert internet["node"] is None and internet["provider"] == "internet" and branch["out"] == "outside"
    texts = [i["text"] for i in branch["items"]]
    assert "Source 10.60.0.5 becomes 198.51.100.10." in texts
    missed = next(i for i in branch["items"] if i["where"] == "Site-to-site VPN To-Hub")
    assert missed["status"] == "info" and "NAT made the source 198.51.100.10" in missed["text"]
    # A private destination is not reached over the internet.
    assert result["verdict"] == "unknown"


# ── A Meraki vMX in AWS ──────────────────────────────────────────────────────


def _aws_rows() -> list[dict]:
    def row(kind: str, rid: str, name: str = "", cidr: str = "", **meta) -> dict:
        return {
            "resource_uid": f"aws:{kind}:{rid}",
            "resource_type": kind,
            "name": name or rid,
            "cidr": cidr,
            "metadata": meta,
        }

    open_acl = [
        {"rule_number": 100, "egress": False, "action": "allow", "protocol": "all", "cidr": "0.0.0.0/0"},
        {"rule_number": 100, "egress": True, "action": "allow", "protocol": "all", "cidr": "0.0.0.0/0"},
    ]
    app_rules = [
        {
            "direction": "inbound",
            "action": "allow",
            "protocol": "tcp",
            "source_selector": "10.0.0.0/8",
            "port_expression": "443",
        },
        {
            "direction": "outbound",
            "action": "allow",
            "protocol": "all",
            "destination_selector": "0.0.0.0/0",
            "port_expression": "all",
        },
    ]
    return [
        row("vpc", "vpc-1", "cloud-vpc", "10.50.0.0/16"),
        row("subnet", "subnet-a", "vmx-subnet", "10.50.1.0/24", vpc_id="vpc-1"),
        row("subnet", "subnet-b", "app-subnet", "10.50.2.0/24", vpc_id="vpc-1"),
        row(
            "route_table",
            "rtb-1",
            "main",
            vpc_id="vpc-1",
            main=True,
            associated_subnet_ids=["subnet-a", "subnet-b"],
            routes=[
                {"destination": "10.50.0.0/16", "target": "local", "state": "active"},
                {"destination": "10.1.0.0/16", "target": "eni-vmx", "state": "active"},
            ],
        ),
        row("network_acl", "acl-1", "open", vpc_id="vpc-1", subnet_ids=["subnet-a", "subnet-b"], entries=open_acl),
        row("security_group", "sg-app", "app", vpc_id="vpc-1", policy_rules=app_rules),
        row(
            "instance",
            "i-vmx",
            "vmx",
            vpc_id="vpc-1",
            private_ip="10.50.1.10",
            interfaces=[{"id": "eni-vmx", "private_ips": ["10.50.1.10"]}],
        ),
        row(
            "instance",
            "i-app",
            "app-1",
            vpc_id="vpc-1",
            private_ip="10.50.2.20",
            security_group_ids=["sg-app"],
            interfaces=[{"id": "eni-app", "private_ips": ["10.50.2.20"], "security_group_ids": ["sg-app"]}],
        ),
    ]


def _vmx_tracer(vmx: dict | None = None, rows: list[dict] | None = None, backup: dict | None = None) -> Tracer:
    graph, snapshots, aws_rows = _vmx_map(vmx, rows, backup)
    return Tracer(graph, snapshots, {-1: Reachability(aws_rows, [])}, {}, [])


def _vmx_map(
    vmx: dict | None = None, rows: list[dict] | None = None, backup: dict | None = None
) -> tuple[dict, dict, list[dict]]:
    """The graph, snapshots and AWS rows of a branch reaching a VPC through a vMX."""
    branch = _mx(
        {"VLAN 10": ("10.1.10.1", "10.1.10.0/24")},
        routes=[route("10.50.0.0/16", "autovpn", peer={"site": "CLOUD"}, source="AutoVPN from Cloud vMX")],
    )
    vmx = vmx or _mx(
        {"LAN": ("10.50.1.10", "10.50.1.0/24")},
        routes=[
            route("10.50.0.0/16", "static", next_hop="10.50.1.1", interface="LAN", source="Static route VPC"),
            route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01"),
        ],
    )
    meraki_nodes = [
        _node("d:BR", "appliance", "BR", "Branch 01 MX", branch),
        _node("d:VMX", "appliance", "CLOUD", "vMX", vmx),
    ]
    sites = {"BR": "Branch 01", "CLOUD": "Cloud vMX"}
    if backup is not None:
        meraki_nodes.append(_node("d:VMX2", "appliance", "CLOUD2", "vMX backup", backup))
        sites["CLOUD2"] = "Cloud vMX backup"
    meraki = _snapshot("Acme", meraki_nodes, [], sites)
    aws = _snapshot(
        "AWS",
        [_node("vpc:vpc-1", "vpc", "vpc-1", "cloud-vpc"), _node("i:i-vmx", "appliance", "vpc-1", "vmx")],
        [],
        {"vpc-1": "cloud-vpc"},
        provider="aws",
    )

    def ref(org_ref: int, node_id: str, site: str, kind: str, provider: str) -> dict:
        return {
            "org_ref": org_ref,
            "node_id": node_id,
            "site_id": site,
            "site_name": site,
            "kind": kind,
            "provider": provider,
        }

    nodes = [
        {"id": "meraki:1:d:BR", "label": "Branch 01 MX", "meraki": ref(1, "d:BR", "Branch 01", "appliance", "meraki")},
        {
            "id": "meraki:1:d:VMX",
            "label": "vMX",
            "meraki": ref(1, "d:VMX", "Cloud vMX", "appliance", "meraki"),
            # The AWS instance collapsed into the vMX (``unified.collapse``).
            "also_refs": [{"org_ref": -1, "node_id": "i:i-vmx", "provider": "aws"}],
        },
        {"id": "meraki:-1:vpc:vpc-1", "label": "cloud-vpc", "meraki": ref(-1, "vpc:vpc-1", "cloud-vpc", "vpc", "aws")},
    ]
    edges = [
        {
            "id": "meraki:1:e1",
            "from": "meraki:1:d:BR",
            "to": "meraki:1:d:VMX",
            "protocol": "vpn",
            "status": "reachable",
        },
        {
            "id": "meraki:-1:e1",
            "from": "meraki:1:d:VMX",
            "to": "meraki:-1:vpc:vpc-1",
            "protocol": "cloud",
            "status": "active",
        },
    ]
    if backup is not None:
        nodes.append(
            {
                "id": "meraki:1:d:VMX2",
                "label": "vMX backup",
                "meraki": ref(1, "d:VMX2", "Cloud vMX backup", "appliance", "meraki"),
            }
        )
        edges.append(
            {
                "id": "meraki:1:e2",
                "from": "meraki:1:d:VMX",
                "to": "meraki:1:d:VMX2",
                "protocol": "vpn",
                "status": "reachable",
            }
        )
    graph = {"nodes": nodes, "edges": edges}
    return graph, {1: meraki, -1: aws}, rows or _aws_rows()


def test_branch_to_a_vpc_subnet_through_a_vmx_uses_the_aws_engine_and_comes_back_through_the_vmx():
    tracer = _vmx_tracer()
    result = tracer.trace(
        "10.1.10.5",
        "10.50.2.20",
        source_node="meraki:1:d:BR",
        destination_node="meraki:-1:vpc:vpc-1",
        protocol="tcp",
        port=443,
    )

    assert result["verdict"] == "allowed", result["summary"]
    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "vMX", "cloud-vpc"]
    vmx, vpc = request["hops"][1:]
    assert vmx["in"] == "AutoVPN from Branch 01" and vmx["out"] == "LAN"
    assert ("route", "ok", "Static route VPC") in _items(vmx)
    assert vpc["provider"] == "aws" and vpc["edge"] == "meraki:-1:e1"
    stages = [(i["stage"], i["where"]) for i in vpc["items"]]
    assert stages == [
        ("route", "Route table main of subnet vmx-subnet (10.50.1.0/24)"),
        ("acl", "Network ACL open of subnet app-subnet (10.50.2.0/24), inbound"),
        ("security_group", "Security groups of instance app-1, inbound"),
    ]
    assert vpc["items"][2]["text"] == "Allowed by app: tcp 443 from 10.0.0.0/8."

    # The replies leave the VPC through the vMX's interface and return over AutoVPN.
    reply = result["reply"]
    assert reply["verdict"] == "allowed" and _labels(reply) == ["cloud-vpc", "vMX", "Branch 01 MX"]
    first = reply["hops"][0]["items"]
    assert first[0]["status"] == "info" and first[0]["text"] == "Stateful: the reply of an allowed request is accepted."
    assert "hands it to instance vmx, which is vMX" in first[-2]["text"]
    assert reply["hops"][1]["in"] == "LAN" and result["asymmetric"]["status"] == "no"

    # Reversed: a new connection from the VPC to the branch.
    back = tracer.trace("10.50.2.20", "10.1.10.5", source_node="meraki:-1:vpc:vpc-1", destination_node="meraki:1:d:BR")
    assert back["request"]["verdict"] == "allowed" and _labels(back["request"]) == ["cloud-vpc", "vMX", "Branch 01 MX"]
    assert back["request"]["hops"][0]["items"][0]["where"] == "Security groups of instance app-1, outbound"


def test_a_passthrough_vmx_hands_the_flow_to_its_own_vpc_when_another_vpc_has_the_same_subnets():
    # A vMX in VPN concentrator mode has one interface, its uplink, and
    # reaches its VPC by the default route to the VPC router. Another VPC
    # uses the same ranges (as every default VPC does): the vMX is an
    # instance of the first, so the next hop is the router of that one.
    vmx = _mx(
        {},
        routes=[route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01")],
        wan_ip="10.50.1.10",
        gateway="10.50.1.1",
    )
    vmx["nat"] = []  # a concentrator does not translate
    twin = [
        {
            "resource_uid": "aws:vpc:vpc-2",
            "resource_type": "vpc",
            "name": "twin-vpc",
            "cidr": "10.50.0.0/16",
            "metadata": {},
        },
        {
            "resource_uid": "aws:subnet:subnet-twin",
            "resource_type": "subnet",
            "name": "twin-subnet",
            "cidr": "10.50.1.0/24",
            "metadata": {"vpc_id": "vpc-2"},
        },
    ]
    result = _vmx_tracer(vmx, [*_aws_rows(), *twin]).trace(
        "10.1.10.5",
        "10.50.2.20",
        source_node="meraki:1:d:BR",
        destination_node="meraki:-1:vpc:vpc-1",
        protocol="tcp",
        port=443,
    )

    assert result["verdict"] == "allowed", result["summary"]
    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "vMX", "cloud-vpc"]
    vmx_hop, vpc = request["hops"][1:]
    assert vmx_hop["out"] == "wan1" and vmx_hop["items"][-1]["where"] == "Link to cloud-vpc"
    assert "the router of cloud-vpc" in next(i["text"] for i in vmx_hop["items"] if i["stage"] == "route")
    # The map draws the link from the vMX to its VPC, and the VPC walks the
    # flow from the vMX's own subnet.
    assert vpc["edge"] == "meraki:-1:e1"
    assert vpc["items"][0]["where"] == "Route table main of subnet vmx-subnet (10.50.1.0/24)"
    assert _labels(result["reply"]) == ["cloud-vpc", "vMX", "Branch 01 MX"]


def test_replies_to_the_uplink_address_a_vmx_hid_the_source_behind_come_back_through_it():
    # A vMX in NAT mode hides the branch behind its uplink address, which is
    # its own address in the VPC. The replies are addressed to the vMX: the
    # VPC delivers them to the instance, and the vMX translates them back
    # and sends them over AutoVPN. Routing is symmetric, not "replies end
    # at the VPC without passing the vMX".
    vmx = _mx(
        {},
        routes=[route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01")],
        wan_ip="10.50.1.10",
        gateway="10.50.1.1",
    )
    result = _vmx_tracer(vmx).trace(
        "10.1.10.5",
        "10.50.2.20",
        source_node="meraki:1:d:BR",
        destination_node="meraki:-1:vpc:vpc-1",
        protocol="tcp",
        port=443,
    )

    assert result["verdict"] == "allowed", result["summary"]
    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "vMX", "cloud-vpc"]
    assert ("nat", "ok", "Uplink NAT Uplink address") in _items(request["hops"][1])
    assert request["summary"].startswith("Every hop allows it: Branch 01 MX → vMX → cloud-vpc.")

    reply = result["reply"]
    assert reply["verdict"] == "allowed", reply["summary"]
    assert _labels(reply) == ["cloud-vpc", "vMX", "Branch 01 MX"]
    vpc, vmx_hop, branch = reply["hops"]
    assert vpc["items"][-2]["text"] == "10.50.1.10 is an address of vMX, which takes the flow from here."
    assert vpc["items"][-1]["where"] == "Link to vMX"
    assert vmx_hop["in"] == "wan1" and vmx_hop["out"] == "AutoVPN to Branch 01"
    assert vmx_hop["items"][0]["text"] == "Replies to 10.50.1.10 are translated back to 10.1.10.5 by the session."
    assert "delivered on VLAN 10" in branch["items"][-1]["text"]
    assert result["asymmetric"] == {"status": "no", "text": "Replies take the same hops back."}


def test_an_uncollected_deployment_mode_leaves_the_source_on_the_wan_unknown():
    # Whether an MX hides the source behind its uplink address depends on its
    # deployment mode, read from its network settings. When they were not
    # collected nothing is assumed: the flow leaving on the WAN is unknown
    # there, and the replies, which leave over AutoVPN, only get a note.
    vmx = _mx(
        {},
        routes=[route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01")],
        wan_ip="10.50.1.10",
        gateway="10.50.1.1",
        missing=("Layer 7 firewall rules", "Group policies", "Uplink NAT (deployment mode)"),
    )
    vmx["nat"] = []
    result = _vmx_tracer(vmx).trace(
        "10.1.10.5",
        "10.50.2.20",
        source_node="meraki:1:d:BR",
        destination_node="meraki:-1:vpc:vpc-1",
        protocol="tcp",
        port=443,
    )

    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "vMX", "cloud-vpc"]
    vmx_hop = request["hops"][1]
    assert ("nat", "unknown", "Uplink NAT (deployment mode)") in _items(vmx_hop)
    unknown = next(i for i in vmx_hop["items"] if i["stage"] == "nat")
    assert unknown["text"].startswith("The deployment mode is not collected: whether this MX is in routed mode")
    assert request["verdict"] == "unknown"
    assert request["summary"].startswith("Could not be decided at vMX, Uplink NAT (deployment mode):")
    reply_vmx = result["reply"]["hops"][1]
    assert reply_vmx["out"] == "AutoVPN to Branch 01"
    assert ("note", "info", "Uplink NAT (deployment mode)") in _items(reply_vmx, info=True)
    assert all(i["stage"] != "nat" for i in reply_vmx["items"])


def test_a_vmx_keeps_its_own_vpc_when_a_backup_vmx_exports_the_same_range():
    # Two vMXs in one VPC both export its range into AutoVPN. Each learns the
    # range from the other; its own export (routed by its uplink) must win,
    # or the flow bounces between them.
    def concentrator(peer: str, peer_name: str, wan_ip: str) -> dict:
        block = _mx(
            {},
            routes=[
                route("10.50.0.0/16", "autovpn", peer={"site": peer}, source=f"AutoVPN from {peer_name}"),
                route(
                    "10.50.0.0/16",
                    "static",
                    next_hop="10.50.1.1",
                    interface="wan1",
                    source="Site-to-site VPN local network",
                ),
                route("10.1.10.0/24", "autovpn", peer={"site": "BR"}, source="AutoVPN from Branch 01"),
            ],
            wan_ip=wan_ip,
            gateway="10.50.1.1",
        )
        block["nat"] = []  # a concentrator does not translate
        return block

    tracer = _vmx_tracer(
        concentrator("CLOUD2", "Cloud vMX backup", "10.50.1.10"),
        backup=concentrator("CLOUD", "Cloud vMX", "10.50.1.11"),
    )
    result = tracer.trace(
        "10.1.10.5",
        "10.50.2.20",
        source_node="meraki:1:d:BR",
        destination_node="meraki:-1:vpc:vpc-1",
        protocol="tcp",
        port=443,
    )

    assert result["verdict"] == "allowed", result["summary"]
    request = result["request"]
    assert _labels(request) == ["Branch 01 MX", "vMX", "cloud-vpc"]
    vmx_hop = request["hops"][1]
    assert vmx_hop["out"] == "wan1"
    assert ("route", "ok", "Site-to-site VPN local network") in _items(vmx_hop)
    texts = [i["text"] for h in request["hops"] for i in h["items"]]
    assert not any("Routing loop" in t for t in texts)


# ── Cato ─────────────────────────────────────────────────────────────────────


def _cato_tracer(raw: dict | None = None) -> Tracer:
    return _tracer({3: build_cato_snapshot(raw or build_cato_sample_raw())})


def _policies(hop: dict) -> list[tuple[str, str, str]]:
    """``(status, rule set, text)`` of every policy item of a hop."""
    return [(i["status"], i["where"], i["text"]) for i in hop["items"] if i["stage"] == "policy"]


def test_cato_site_to_site_applies_the_wan_firewall_once_at_the_ingress_pop():
    tracer = _cato_tracer()
    result = tracer.trace(
        "10.60.20.5", "10.50.10.20", source_node="meraki:3:d:5003", destination_node="meraki:3:d:5001"
    )

    request = result["request"]
    assert _labels(request) == [
        "Branch-Madison",
        "PoP New York",
        "Cato Cloud",
        "PoP Ashburn",
        "HQ-DataCenter (primary)",
    ]
    assert all(h["provider"] == "cato" for h in request["hops"])
    # A private destination: the WAN firewall, evaluated at the PoP the flow enters by, then
    # only said to be applied; never the Internet firewall.
    branch, new_york, cloud, ashburn, hq = request["hops"]
    assert _policies(branch) == _policies(hq) == []
    # Any traffic: rule 2 allows only HTTPS, and rule 3 names a users group Plexus cannot evaluate.
    [(status, name, text)] = _policies(new_york)
    assert (status, name) == ("unknown", "WAN firewall rules") and text.startswith("Rule 3 Remote users to HQ")
    already = [("info", "WAN firewall rules", "Already applied at PoP New York.")]
    assert _policies(cloud) == _policies(ashburn) == already
    assert request["verdict"] == "unknown" and result["verdict"] == "unknown"
    assert request["summary"].startswith("Could not be decided at PoP New York, WAN firewall rules: Rule 3")
    # The replies: accepted by the account's state at the first PoP they meet.
    reply = result["reply"]
    assert _labels(reply)[1] == "PoP Ashburn"
    assert _policies(reply["hops"][1]) == [("info", "WAN firewall rules", STATEFUL_REPLY)]
    assert (
        _policies(reply["hops"][2])
        == _policies(reply["hops"][3])
        == [("info", "WAN firewall rules", "Already applied at PoP Ashburn.")]
    )

    # HTTPS from the branch is what rule 2 allows.
    https = tracer.trace(
        "10.60.20.5",
        "10.50.10.20",
        source_node="meraki:3:d:5003",
        destination_node="meraki:3:d:5001",
        protocol="tcp",
        port=443,
    )
    assert https["verdict"] == "allowed"
    [(status, _name, text)] = _policies(https["request"]["hops"][1])
    assert status == "ok" and text.startswith("Rule 2 Sites to HQ servers")


def test_cato_site_to_site_on_one_pop_still_meets_the_wan_firewall():
    # HQ and the AWS IPsec site are both on PoP Ashburn: the flow never reaches the Cato Cloud.
    result = _cato_tracer().trace(
        "10.50.10.20",
        "172.21.0.5",
        source_node="meraki:3:d:5001",
        destination_node="meraki:3:s:1004",
        protocol="tcp",
        port=443,
    )

    request = result["request"]
    assert _labels(request) == ["HQ-DataCenter (primary)", "PoP Ashburn", "AWS-us-east-1"]
    [(status, name, text)] = _policies(request["hops"][1])
    assert (status, name) == ("ok", "WAN firewall rules") and text.startswith("Rule 4 Any to any")
    assert result["verdict"] == "allowed"


def test_cato_wan_firewall_rule_blocks_at_the_ingress_pop():
    # Rule 1 applies both ways: the servers may not reach Denver either.
    result = _cato_tracer().trace(
        "10.50.10.20",
        "10.61.20.5",
        source_node="meraki:3:d:5001",
        destination_node="meraki:3:d:5004",
        protocol="tcp",
        port=22,
    )

    request = result["request"]
    assert _labels(request) == ["HQ-DataCenter (primary)", "PoP Ashburn"]
    assert result["verdict"] == "blocked"
    assert _items(request["hops"][-1]) == [("policy", "blocked", "WAN firewall rules")]
    assert request["summary"].startswith(
        "Blocked at PoP Ashburn, WAN firewall rules: Rule 1 Isolate Denver from servers (return)"
    )


def test_cato_internet_traffic_leaves_from_the_cloud_through_the_internet_firewall():
    result = _cato_tracer().trace("10.60.20.5", "8.8.8.8", source_node="meraki:3:d:5003", protocol="tcp", port=443)

    request = result["request"]
    assert _labels(request) == ["Branch-Madison", "PoP New York", "Cato Cloud", "Internet"]
    assert not request["summary"].startswith("No route")
    assert all(i["status"] != "blocked" for h in request["hops"] for i in h["items"])
    branch, new_york, cloud, internet = request["hops"]
    # A public destination: the Internet firewall, at the ingress PoP; never the WAN firewall.
    # Rule 1 blocks a category of sites Plexus cannot tell 8.8.8.8 is in or not.
    [(status, name, text)] = _policies(new_york)
    assert (status, name) == ("unknown", "Internet firewall rules") and text.startswith("Rule 1 Block malware")
    assert _policies(cloud) == [("info", "Internet firewall rules", "Already applied at PoP New York.")]
    assert _policies(branch) == _policies(internet) == []
    route_item = next(i for i in cloud["items"] if i["stage"] == "route")
    assert (route_item["status"], route_item["where"]) == ("ok", "Cato internet egress")
    assert cloud["out"] == "Internet"
    # The source leaves as Cato's public address, which is not collected.
    nat_item = next(i for i in cloud["items"] if i["stage"] == "nat")
    assert nat_item["text"] == "Source 10.60.20.5 becomes the address of Internet, which was not collected."
    assert internet["node"] is None and "8.8.8.8 is on the internet" in internet["items"][0]["text"]
    assert request["verdict"] == "unknown"
    assert request["summary"].startswith(
        "Could not be decided at PoP New York, Internet firewall rules: Rule 1 Block malware category"
    )


def test_cato_firewall_not_collected_is_unknown_once():
    raw = build_cato_sample_raw()
    raw["wan_firewall"] = raw["internet_firewall"] = None
    result = _cato_tracer(raw).trace(
        "10.60.20.5", "10.50.10.20", source_node="meraki:3:d:5003", destination_node="meraki:3:d:5001"
    )

    request = result["request"]
    hops = request["hops"]
    unknown = [(h["label"], i["where"]) for h in hops for i in h["items"] if i["status"] == "unknown"]
    assert unknown == [("PoP New York", "WAN firewall rules")]
    noted = [("info", "WAN firewall rules", "Already noted at PoP New York.")]
    assert _policies(hops[2]) == _policies(hops[3]) == noted
    assert request["summary"] == (
        "Could not be decided at PoP New York, WAN firewall rules: WAN firewall rules are not collected: "
        "whether they allow this flow is not known. Not checked: Internet firewall rules."
    )
    # The Internet firewall does not apply to a private destination: one note, at the first PoP.
    notes = [(h["label"], i["where"]) for h in hops for i in h["items"] if i["stage"] == "note"]
    assert notes == [("PoP New York", "Internet firewall rules")]


def _route_item(hop: dict) -> dict:
    return next(i for i in hop["items"] if i["stage"] == "route")


def _link_item(hop: dict) -> dict:
    return next(i for i in hop["items"] if i["stage"] == "link")


_MADISON_TO_HQ = {"source_node": "meraki:3:d:5003", "destination_node": "meraki:3:d:5001"}
_HTTPS = {"protocol": "tcp", "port": 443}


def test_cato_site_with_a_bgp_peer_makes_a_default_route_lookup_unknown():
    raw = build_cato_sample_raw()
    raw["bgp_peers"] = [{"id": "b-1", "name": "Core router", "site": {"id": "1002"}, "peerIp": "10.60.20.2"}]
    result = _cato_tracer(raw).trace("10.60.20.5", "10.50.10.20", **_MADISON_TO_HQ, **_HTTPS)

    request = result["request"]
    # The rest of the trace proceeds: only the branch's lookup is in doubt.
    assert _labels(request) == [
        "Branch-Madison",
        "PoP New York",
        "Cato Cloud",
        "PoP Ashburn",
        "HQ-DataCenter (primary)",
    ]
    lookup = _route_item(request["hops"][0])
    assert (lookup["status"], lookup["where"]) == ("unknown", "Cato tunnel to PoP New York")
    assert lookup["text"] == (
        "0.0.0.0/0 over the tunnel to PoP New York. Only the default route matches 10.50.10.20; "
        "routes learned by BGP are not collected, so a more specific route may exist."
    )
    unknown = [(h["label"], i["stage"]) for h in request["hops"] for i in h["items"] if i["status"] == "unknown"]
    assert unknown == [("Branch-Madison", "route")]
    assert result["verdict"] == "unknown"
    assert request["summary"].startswith("Could not be decided at Branch-Madison, Cato tunnel to PoP New York")
    # On the reply the branch's connected range answers: the note is only information.
    last = result["reply"]["hops"][-1]
    assert ("note", "info", "Routes learned by BGP") in _items(last, info=True)


def test_cato_ranges_not_collected_make_the_pops_lookup_unknown():
    raw = build_cato_sample_raw()
    raw["ranges"] = []
    raw["errors"] = [{"scope": "account", "path": "entityLookup siteRange", "status": 403, "message": "Denied"}]
    result = _cato_tracer(raw).trace("10.60.20.5", "10.50.10.20", **_MADISON_TO_HQ, **_HTTPS)

    hops = {h["label"]: h for h in result["request"]["hops"]}
    lookup = _route_item(hops["PoP New York"])
    assert (lookup["status"], lookup["where"]) == ("unknown", "Cato backbone")
    assert lookup["text"].endswith(
        "Only the default route matches 10.50.10.20; route table (site network ranges) is not collected, "
        "so a more specific route may exist."
    )
    assert result["verdict"] == "unknown"
    # Without the ranges, whether the destination is on the WAN or the internet
    # is not known either, so neither firewall is picked: both are unknown.
    why = (
        "is not known: no route but the default covers 10.50.10.20, and route table (site network ranges) "
        "is not collected, so it may be WAN traffic or internet traffic."
    )
    assert _policies(hops["PoP New York"]) == [
        ("unknown", "WAN firewall rules", f"Whether WAN firewall rules apply {why}"),
        ("unknown", "Internet firewall rules", f"Whether Internet firewall rules apply {why}"),
    ]
    assert _policies(hops["Cato Cloud"]) == [
        ("info", "WAN firewall rules", "Already noted at PoP New York."),
        ("info", "Internet firewall rules", "Already noted at PoP New York."),
    ]


def _ipsec_trace(snapshot: dict) -> dict:
    """Branch-Madison to the AWS VPC behind the IPsec site, on HTTPS."""
    return _tracer({3: snapshot}).trace(
        "10.60.20.5", "172.21.0.5", source_node="meraki:3:d:5003", destination_node="meraki:3:s:1004", **_HTTPS
    )


def _ipsec_edges(snapshot: dict) -> list[dict]:
    return [e for e in snapshot["edges"] if e["a"] == "s:1004"]


def test_cato_ipsec_site_is_reached_over_its_primary_tunnel():
    result = _ipsec_trace(build_cato_snapshot(build_cato_sample_raw()))

    request = result["request"]
    assert _labels(request) == ["Branch-Madison", "PoP New York", "Cato Cloud", "PoP Ashburn", "AWS-us-east-1"]
    ashburn = request["hops"][3]
    assert _link_item(ashburn)["text"] == "IPsec tunnel, reachable."
    # Rule 2 allows Madison to the HQ servers only; rule 4 allows the rest.
    [(status, _name, text)] = _policies(request["hops"][1])
    assert status == "ok" and text.startswith("Rule 4 Any to any")
    assert result["verdict"] == "allowed"
    assert _link_item(result["reply"]["hops"][0])["text"] == "IPsec tunnel, reachable."


def test_cato_ipsec_site_fails_over_to_the_secondary_tunnel_then_is_cut_off():
    snapshot = build_cato_snapshot(build_cato_sample_raw())
    primary, secondary = _ipsec_edges(snapshot)
    primary["status"] = "unreachable"
    result = _ipsec_trace(snapshot)
    assert result["verdict"] == "allowed"
    ashburn = result["request"]["hops"][3]
    assert _link_item(ashburn)["text"] == "IPsec tunnel, ready."
    # The hop into the site names the edge it crossed: the secondary's.
    assert result["request"]["hops"][4]["edge"] == f"meraki:3:{secondary['id']}"

    secondary["status"] = "unreachable"
    result = _ipsec_trace(snapshot)
    request = result["request"]
    assert _labels(request) == ["Branch-Madison", "PoP New York", "Cato Cloud", "PoP Ashburn"]
    link = _link_item(request["hops"][-1])
    assert (link["status"], link["text"]) == (
        "blocked",
        "Every link between PoP Ashburn and AWS-us-east-1 is down (unreachable), as Cato reports.",
    )
    assert result["verdict"] == "unreachable"
    assert request["summary"] == (
        "No path at PoP Ashburn, Link to AWS-us-east-1: "
        "Every link between PoP Ashburn and AWS-us-east-1 is down (unreachable), as Cato reports."
    )


_DANA = {"source_node": "meraki:3:cato:user:9001"}


def test_cato_remote_user_to_a_site_meets_the_wan_firewall_at_the_users_pop():
    result = _cato_tracer().trace("10.88.0.11", "10.50.10.20", **_DANA, **_HTTPS)

    request = result["request"]
    assert _labels(request) == ["Dana Reyes", "PoP New York", "Cato Cloud", "PoP Ashburn", "HQ-DataCenter (primary)"]
    # Rule 2 names sites, not users; rule 3 names a users group Plexus cannot resolve.
    [(status, name, text)] = _policies(request["hops"][1])
    assert (status, name) == ("unknown", "WAN firewall rules") and text.startswith("Rule 3 Remote users to HQ")
    assert "users group VPN Users" in text
    assert _policies(request["hops"][2]) == [("info", "WAN firewall rules", "Already applied at PoP New York.")]
    assert result["verdict"] == "unknown"
    assert result["asymmetric"] == {"status": "no", "text": "Replies take the same hops back."}
    assert _labels(result["reply"]) == list(reversed(_labels(request)))


def test_cato_remote_user_to_the_internet_meets_the_internet_firewall_at_the_users_pop():
    result = _cato_tracer().trace("10.88.0.11", "8.8.8.8", **_DANA, **_HTTPS)

    request = result["request"]
    assert _labels(request) == ["Dana Reyes", "PoP New York", "Cato Cloud", "Internet"]
    [(status, name, text)] = _policies(request["hops"][1])
    assert (status, name) == ("unknown", "Internet firewall rules") and text.startswith("Rule 1 Block malware")
    assert _policies(request["hops"][2]) == [("info", "Internet firewall rules", "Already applied at PoP New York.")]
    assert _route_item(request["hops"][2])["where"] == "Cato internet egress"


def test_cato_remote_user_to_a_private_address_no_site_covers_says_only_the_default_route_matches():
    # A private destination that is no site's range and no user's address:
    # the Cloud's default route sends it to the internet, and the route item
    # says the table holds nothing closer, so the missing route is visible
    # at the hop that lacks it. The internet path stays unknown, not a block.
    result = _cato_tracer().trace("10.88.0.11", "10.9.0.0/24", **_DANA, **_HTTPS)

    request = result["request"]
    assert _labels(request) == ["Dana Reyes", "PoP New York", "Cato Cloud", "Internet"]
    cloud = _route_item(request["hops"][2])
    assert cloud["where"] == "Cato internet egress" and cloud["status"] == "ok"
    assert cloud["text"].endswith(": to the internet. No other route covers 10.9.0.0/24, a private address.")
    internet = request["hops"][3]["items"][0]
    assert (internet["status"], internet["where"]) == ("unknown", "Internet")
    assert request["verdict"] == "unknown"
    # Internet traffic, as Cato classes what no site range or user address
    # covers: the Internet firewall applies, never the WAN firewall, private
    # address or not.
    [(status, name, text)] = _policies(request["hops"][1])
    assert (status, name) == ("unknown", "Internet firewall rules") and text.startswith("Rule 1 Block malware")
    assert _policies(request["hops"][2]) == [("info", "Internet firewall rules", "Already applied at PoP New York.")]
    # A public destination, or one a route covers, gets no such clause.
    public = _cato_tracer().trace("10.88.0.11", "8.8.8.8", **_DANA, **_HTTPS)
    assert "No other route" not in _route_item(public["request"]["hops"][2])["text"]


def test_cato_remote_user_to_a_site_on_the_same_pop_skips_the_backbone():
    result = _cato_tracer().trace("10.88.0.11", "10.60.20.5", **_DANA, **_HTTPS)

    assert _labels(result["request"]) == ["Dana Reyes", "PoP New York", "Branch-Madison"]
    [(status, _name, text)] = _policies(result["request"]["hops"][1])
    assert status == "ok" and text.startswith("Rule 4 Any to any")
    assert result["verdict"] == "allowed"
    assert _labels(result["reply"]) == ["Branch-Madison", "PoP New York", "Dana Reyes"]


def test_cato_remote_user_is_found_by_its_address_ahead_of_a_range_that_covers_it():
    from netcontrol.integrations.meraki.subnets import subnet_index

    # The subnet box resolves a typed address to the most specific entry: the
    # user's own /32 outranks a range another source keeps for the whole
    # client pool, so the trace starts at the user without naming the node.
    snapshot = build_cato_snapshot(build_cato_sample_raw())
    subnets = [{"org_ref": 3, **s} for s in subnet_index(snapshot)]
    subnets.append({"org_ref": 3, "cidr": "10.88.0.0/16", "node_id": CATO_CLOUD_NODE_ID, "kind": "peer"})
    result = _tracer({3: snapshot}, subnets=subnets).trace("10.88.0.11", "10.50.10.20", **_HTTPS)

    assert _labels(result["request"]) == [
        "Dana Reyes",
        "PoP New York",
        "Cato Cloud",
        "PoP Ashburn",
        "HQ-DataCenter (primary)",
    ]
    # The WAN firewall is met at the user's PoP, as when the node is named.
    [(status, name, text)] = _policies(result["request"]["hops"][1])
    assert (status, name) == ("unknown", "WAN firewall rules") and text.startswith("Rule 3 Remote users to HQ")


def test_cato_site_to_site_replies_take_the_same_hops_back():
    result = _cato_tracer().trace("10.60.20.5", "10.50.10.20", **_MADISON_TO_HQ, **_HTTPS)

    assert result["verdict"] == "allowed"
    assert result["asymmetric"] == {"status": "no", "text": "Replies take the same hops back."}
    assert _labels(result["reply"]) == list(reversed(_labels(result["request"])))


def test_cato_cloud_routing_a_range_back_to_the_ingress_pop_is_a_routing_loop():
    snapshot = build_cato_snapshot(build_cato_sample_raw())
    cloud = next(n for n in snapshot["nodes"] if n["id"] == "cato:cloud")
    for entry in cloud["forwarding"]["routes"]:
        if entry["prefix"] == "10.50.10.0/24":
            entry["peer"] = {"org_node": "pop:New York"}
    result = _tracer({3: snapshot}).trace("10.60.20.5", "10.50.10.20", **_MADISON_TO_HQ, **_HTTPS)

    # PoP New York sends HQ's range over the backbone, which sends it back.
    request = result["request"]
    assert _labels(request) == ["Branch-Madison", "PoP New York", "Cato Cloud"]
    assert request["hops"][-1]["items"][-1]["where"] == "Routing loop"
    assert result["verdict"] == "unreachable"
    assert result["asymmetric"]["status"] == "unknown"


def test_cato_socket_sending_by_one_pop_and_answered_by_another_is_asymmetric():
    # Branch-Madison's second WAN link is on PoP Ashburn, so HQ's PoP answers it directly,
    # while the Socket sends by PoP New York.
    raw = build_cato_sample_raw()
    branch = next(s for s in raw["sites"] if s["id"] == "1002")
    branch["devices"][0]["interfaces"][1].update(
        {"connected": True, "popName": "Ashburn", "tunnelRemoteIP": "203.0.113.30"}
    )
    snapshot = build_cato_snapshot(raw)
    socket = next(n for n in snapshot["nodes"] if n["id"] == "d:5003")
    socket["forwarding"]["routes"][-1]["peer"] = {"org_node": "pop:New York"}
    result = _tracer({3: snapshot}).trace("10.60.20.5", "10.50.10.20", **_MADISON_TO_HQ, **_HTTPS)

    assert result["verdict"] == "allowed"
    assert _labels(result["request"]) == [
        "Branch-Madison",
        "PoP New York",
        "Cato Cloud",
        "PoP Ashburn",
        "HQ-DataCenter (primary)",
    ]
    assert _labels(result["reply"]) == ["HQ-DataCenter (primary)", "PoP Ashburn", "Branch-Madison"]
    # The account's firewall keeps one state table: PoP Ashburn, on the replies'
    # path, sees the connection, so there is no stateful warning for the PoP and
    # the Cloud the replies skip.
    assert result["asymmetric"] == {
        "status": "yes",
        "text": "Replies from 10.50.10.20 go from PoP Ashburn to Branch-Madison instead of Cato Cloud, the way the "
        "request came.",
    }


# ── Asymmetry ────────────────────────────────────────────────────────────────


def test_a_hub_whose_return_route_points_to_the_other_hub_is_asymmetric():
    spoke = _mx(
        {"VLAN 10": ("10.5.10.1", "10.5.10.0/24")},
        routes=[route("10.0.10.0/24", "autovpn", peer={"site": "H1"}, source="AutoVPN from Hub 01")],
        missing=(),
    )
    hub1 = _mx(
        {"VLAN 10": ("10.0.10.1", "10.0.10.0/24")},
        routes=[route("10.5.10.0/24", "autovpn", peer={"site": "H2"}, source="AutoVPN from Hub 02")],
        missing=(),
    )
    hub2 = _mx(
        {"VLAN 10": ("10.1.10.1", "10.1.10.0/24")},
        routes=[route("10.5.10.0/24", "autovpn", peer={"site": "S"}, source="AutoVPN from Spoke")],
        missing=(),
    )
    snap = _snapshot(
        "Acme",
        [
            _node("d:S", "appliance", "S", "Spoke MX", spoke),
            _node("d:H1", "appliance", "H1", "Hub 01 MX", hub1),
            _node("d:H2", "appliance", "H2", "Hub 02 MX", hub2),
        ],
        [_edge("e1", "d:S", "d:H1"), _edge("e2", "d:S", "d:H2"), _edge("e3", "d:H1", "d:H2")],
        {"S": "Spoke", "H1": "Hub 01", "H2": "Hub 02"},
    )
    result = _tracer({1: snap}).trace(
        "10.5.10.5", "10.0.10.20", source_node="meraki:1:d:S", destination_node="meraki:1:d:H1"
    )

    assert result["request"]["verdict"] == "allowed"
    assert _labels(result["reply"]) == ["Hub 01 MX", "Hub 02 MX", "Spoke MX"]
    asymmetric = result["asymmetric"]
    assert asymmetric["status"] == "yes"
    assert asymmetric["text"].startswith(
        "Replies from 10.0.10.20 go from Hub 01 MX to Hub 02 MX instead of Spoke MX, the way the request came."
    )
    assert (
        "Hub 02 MX has a stateful firewall that never saw the request: it would drop the replies" in asymmetric["text"]
    )
    # Hub 02's stateful VPN firewall never saw the request.
    assert ("policy", "unknown", "Site-to-site VPN firewall rules") in _items(result["reply"]["hops"][1])


# ── Loops, missing routes, devices without data, the Internet ────────────────


def _plain(vlans: dict[str, tuple[str, str]], *routes_, missing=()) -> dict:
    block = new_block()
    for name, (ip, cidr) in vlans.items():
        block["interfaces"].append(interface(name, "vlan", ip=ip, cidr=cidr))
        block["routes"].append(route(cidr, "connected", interface=name, source=f"Connected {name}"))
    block["routes"].extend(routes_)
    block["not_collected"] = list(missing)
    return block


def test_routing_loop_no_route_and_unknown_learned_routes():
    a = _plain({"VLAN 1": ("10.0.1.1", "10.0.1.0/24")}, route("10.9.0.0/16", "static", next_hop="10.0.1.2"))
    b = _plain(
        {"VLAN 1": ("10.0.1.2", "10.0.1.0/24")},
        route("10.9.0.0/16", "static", next_hop="10.0.1.1"),
        route("0.0.0.0/0", "default", next_hop="10.0.1.99"),
        missing=("Routes learned by BGP",),
    )
    snap = _snapshot(
        "Acme",
        [_node("d:A", "appliance", "A", "Router A", a), _node("d:B", "appliance", "B", "Router B", b)],
        [_edge("e1", "d:A", "d:B", kind="lan", status="")],
        {"A": "Site A", "B": "Site B"},
    )
    tracer = _tracer({1: snap})

    loop = tracer.trace("10.0.1.50", "10.9.1.1", source_node="meraki:1:d:A")
    assert loop["verdict"] == "unreachable" and _labels(loop["request"]) == ["Router A", "Router B"]
    assert loop["request"]["hops"][-1]["items"][-1]["where"] == "Routing loop"
    assert loop["summary"].startswith("No path at Router B, Routing loop: ")

    nothing = tracer.trace("10.0.1.50", "10.99.0.1", source_node="meraki:1:d:A")
    assert (
        nothing["verdict"] == "unreachable"
        and nothing["summary"] == "No path at Router A, Route table: No route to 10.99.0.1."
    )

    # Router B would learn routes over BGP: no route is not a block, a default route is not certain.
    unknown = tracer.trace("10.0.1.60", "10.98.0.1", source_node="meraki:1:d:B")
    assert unknown["request"]["verdict"] == "unknown"
    lookup = next(i for i in unknown["request"]["hops"][0]["items"] if i["stage"] == "route")
    assert lookup["status"] == "unknown" and "Only the default route matches 10.98.0.1" in lookup["text"]
    assert "routes learned by BGP are not collected" in lookup["text"]


def test_a_device_without_forwarding_data_follows_the_links_on_the_map():
    switch = _node("d:SW", "switch", "A", "Old switch")  # no forwarding block
    mx = _plain({"VLAN 1": ("10.0.1.1", "10.0.1.0/24")}, route("10.0.5.0/24", "static", next_hop="10.0.1.254"))
    current = _snapshot(
        "Acme",
        [switch, _node("d:MX", "appliance", "A", "Site MX", mx)],
        [_edge("e1", "d:SW", "d:MX", kind="lan", status="")],
        {"A": "Site A"},
    )
    old = _snapshot("Old org", [_node("d:X", "appliance", "X", "Old MX")], [_edge("e9", "d:X", "d:X")], {"X": "X"})
    tracer = _tracer(
        {1: current, 9: old},
        extra_edges=[{"id": "x1", "from": "meraki:9:d:X", "to": "meraki:1:d:SW", "protocol": "lldp", "status": ""}],
    )

    result = tracer.trace("10.0.5.5", "10.0.1.7", source_node="meraki:9:d:X", destination_node="meraki:1:d:MX")
    hops = result["request"]["hops"]
    assert _labels(result["request"]) == ["Old MX", "Old switch", "Site MX"]
    assert all(h["status"] == "unknown" and h["items"][0]["stage"] == "note" for h in hops)
    assert hops[1]["edge"] == "x1" and hops[2]["edge"] == "meraki:1:e1"
    assert result["verdict"] == "unknown" and result["asymmetric"]["status"] == "unknown"
    assert result["notes"] == ["Meraki organization Old org: the snapshot predates forwarding data; collect it again."]


def test_internet_into_a_one_to_one_nat_is_allowed_and_into_a_device_without_nat_is_blocked():
    hq = _mx(
        {"VLAN 10": ("10.0.10.1", "10.0.10.0/24")},
        inbound=[rule(1, "allow", protocol="tcp", dst=["10.0.10.80/32"], dst_ports="443", comment="Web server")],
        nats=[
            nat(
                1,
                "one_to_one",
                name="Web server",
                original_dst=["198.51.100.150/32"],
                translated_dst=["10.0.10.80/32"],
                dst_interface="wan1",
            )
        ],
        wan_ip="198.51.100.2",
        gateway="198.51.100.1",
    )
    edge = _mx({"VLAN 10": ("10.3.10.1", "10.3.10.0/24")}, wan_ip="203.0.113.3", gateway="203.0.113.1")
    snap = _snapshot(
        "Acme",
        [_node("d:HQ", "appliance", "HQ", "HQ MX", hq), _node("d:EDGE", "appliance", "EDGE", "Edge MX", edge)],
        [],
        {"HQ": "HQ", "EDGE": "Edge"},
    )
    tracer = _tracer({1: snap})

    web = tracer.trace("8.8.8.8", "198.51.100.150", protocol="tcp", port=443)
    assert web["destination"]["node"] == "meraki:1:d:HQ"  # found by its 1:1 NAT address
    assert web["verdict"] == "allowed", web["summary"]
    internet, mx = web["request"]["hops"]
    assert internet["node"] is None and internet["provider"] == "internet"
    assert mx["in"] == "Internet" and mx["out"] == "VLAN 10"
    assert _items(mx) == [
        ("nat", "ok", "1:1 NAT Web server"),
        ("policy", "ok", "Inbound firewall rules"),
        ("route", "ok", "Connected VLAN 10"),
    ]
    assert mx["items"][0]["text"] == "Destination 198.51.100.150 becomes 10.0.10.80."
    assert _labels(web["reply"]) == ["HQ MX", "Internet"]
    assert web["reply"]["hops"][0]["items"][0]["text"].startswith("Replies from 10.0.10.80 leave as 198.51.100.150")

    # Found by its WAN address; nothing translates the flow, so the inbound rules' default denies it.
    closed = tracer.trace("8.8.8.8", "203.0.113.3", protocol="tcp", port=443)
    assert closed["destination"]["node"] == "meraki:1:d:EDGE" and closed["verdict"] == "blocked"
    assert (
        closed["summary"]
        == "Blocked at Edge MX, Inbound firewall rules: No rule matches: the default action denies it."
    )


def test_errors_and_ends_that_cannot_be_placed():
    tracer = _tracer(_branch_and_hub(), subnets=_SUBNETS)
    with pytest.raises(ValueError):
        tracer.trace("10.1.10.5", "10.0.10.20", protocol="gre")
    with pytest.raises(ValueError):
        tracer.trace("nope", "10.0.10.20")
    nowhere = tracer.trace("192.0.2.1", "192.0.2.2")
    assert nowhere["applies"] is False and nowhere["verdict"] == "unknown"
    twice = _tracer(
        _branch_and_hub(), subnets=[*_SUBNETS, {"org_ref": 1, "node_id": "d:HUB", "cidr": "10.1.10.0/24"}]
    ).trace("10.1.10.5", "10.0.10.20")
    assert twice["applies"] and twice["verdict"] == "unknown" and twice["request"]["hops"] == []
    assert "is in several places" in twice["summary"]


def test_collapsed_snapshot_nodes_are_kept_as_also_refs():
    host = {"id": 5, "label": "edge-fw", "ip": "10.9.9.9", "in_inventory": True, "group_id": 1, "group_name": "Core"}
    first = _snapshot("Acme", [_node("d:A", "appliance", "A", "edge-fw", inventory={"host_id": 5})], [], {"A": "A"})
    second = _snapshot(
        "FMC", [_node("d:B", "appliance", "B", "edge-fw", inventory={"host_id": 5})], [], {"B": "B"}, provider="fmc"
    )
    nodes: dict = {5: host}
    merge_meraki_into_graph(
        nodes, [], [(1, first), (2, second)], host_node=lambda h: nodes.get(h), resolve_external=lambda _n, _i: None
    )
    assert nodes[5]["meraki"]["node_id"] == "d:A"
    assert nodes[5]["also_refs"] == [{"org_ref": 2, "node_id": "d:B", "provider": "fmc"}]
    viewer = graph_to_snapshot({"nodes": list(nodes.values()), "edges": []}, {1: first, 2: second}, {})
    assert viewer["nodes"][0]["also_refs"] == [{"org_ref": 2, "node_id": "d:B", "provider": "fmc"}]


# ── API ──────────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-path")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def forget() -> None:
        # The samples must not leak into the next test's map.
        routes_module._SNAPSHOT_CACHE.clear()
        routes_module._HOST_FORWARDING.clear()
        invalidate_topology_cache()

    forget()
    request.addfinalizer(forget)

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def test_api_traces_the_demo_flows_end_to_end(api):
    for provider in ("meraki", "fmc", "aws"):
        assert api.post(f"/api/sources/sample?provider={provider}").status_code == 201

    # The graph nodes of Branch-Atlanta's MX and HQ's (which may be an inventory host too).
    graph = api.get("/api/topology").json()["nodes"]
    label = {(n.get("meraki") or {}).get("node_id"): n["label"] for n in graph}
    branch_mx, hq_mx = label["d:Q2MX-0002-0001"], label["d:Q2MX-0000-0001"]

    # Branch-Atlanta's guest VLAN to an HQ data address: the Layer 3 rule denies it.
    blocked = api.get("/api/topology/path?source=10.2.30.10&destination=10.0.10.20")
    assert blocked.status_code == 200, blocked.text
    body = blocked.json()
    assert body["applies"] and body["verdict"] == "blocked" and body["traffic"] == "any traffic"
    assert body["source"]["label"] == branch_mx and body["destination"]["label"] == hq_mx
    first = body["request"]["hops"][0]
    assert first["label"] == branch_mx and first["items"][0]["where"] == "Layer 3 firewall rules"
    assert first["items"][0]["status"] == "blocked" and first["items"][0]["rule"] == 1

    # Branch-Atlanta's data VLAN to the same address: allowed over AutoVPN, replies symmetric.
    branch = body["source"]["node"]
    allowed = api.get(
        f"/api/topology/path?source=10.2.10.5&destination=10.0.10.20&source_node={branch}&protocol=tcp&port=443"
    ).json()
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert allowed["traffic"] == "tcp/443"
    assert _labels(allowed["request"]) == [branch_mx, hq_mx]
    assert _labels(allowed["reply"]) == [hq_mx, branch_mx]
    assert allowed["asymmetric"]["status"] == "no"
    branch_hop = allowed["request"]["hops"][0]
    assert [i["where"] for i in branch_hop["items"] if i["status"] != "info"] == [
        "Layer 3 firewall rules",
        "AutoVPN from HQ-DataCenter",
        "Site-to-site VPN firewall rules",
        f"Link to {hq_mx}",
    ]
    assert "Not checked: Layer 7 firewall rules, group policies" in allowed["summary"]

    nowhere = api.get("/api/topology/path?source=192.0.2.1&destination=192.0.2.2").json()
    assert nowhere["applies"] is False
    assert api.get("/api/topology/path?source=10.2.10.5&destination=10.0.10.20&protocol=gre").status_code == 400
    assert api.get("/api/topology/path?source=nope&destination=10.0.10.20").status_code == 400


def _export_data(response) -> dict:
    import json
    import re

    assert response.status_code == 200, response.text
    embedded = re.search(r'<script type="application/json" id="topology-data">(.*?)</script>', response.text, re.S)
    assert embedded is not None
    return json.loads(embedded.group(1))


def _export_with_path(api, path) -> dict:
    import json

    return _export_data(api.get("/api/topology/export.html", params={"path": json.dumps(path)}))


def _subnet_pick(api, address: str, meraki_node: str) -> dict:
    """The page's ``PathPick`` of ``address`` inside the subnet ``meraki_node`` owns."""
    import ipaddress

    graph = api.get("/api/topology").json()["nodes"]
    node = next(n for n in graph if (n.get("meraki") or {}).get("node_id") == meraki_node)
    ref = node["meraki"]
    subnet = next(
        s
        for s in api.get("/api/sources/subnets").json()["subnets"]
        if s["org_ref"] == ref["org_ref"]
        and s["node_id"] == meraki_node
        and ipaddress.ip_address(address) in ipaddress.ip_network(s["cidr"], strict=False)
    )
    return {
        "key": f"s:{ref['org_ref']}:{address}:{meraki_node}",
        "node": node["id"],
        "label": f"{address} · {subnet.get('site_name') or ''}",
        "subnet": subnet,
        "address": address,
    }


def test_api_html_export_carries_the_path_and_its_traces(api):
    import re

    assert api.post("/api/sources/sample").status_code == 201
    branch = _subnet_pick(api, "10.2.10.5", "d:Q2MX-0002-0001")
    hq = _subnet_pick(api, "10.0.10.20", "d:Q2MX-0000-0001")

    exported = _export_with_path(api, {"traffic": {"protocol": "TCP", "port": 443}, "picks": [branch, hq]})
    path = exported["path"]
    node_ids = {n["id"] for n in exported["nodes"]}
    assert path["traffic"] == {"protocol": "tcp", "port": 443}
    branch_id, hq_id = str(branch["node"]), str(hq["node"])
    assert [p["key"] for p in path["picks"]] == [f"s:10.2.10.5:{branch_id}", f"s:10.0.10.20:{hq_id}"]
    assert [p["node"] for p in path["picks"]] == [branch_id, hq_id]
    first = path["picks"][0]
    assert first["address"] == "10.2.10.5" and first["subnet"]["node_id"] == branch_id
    assert first["subnet"]["cidr"] == branch["subnet"]["cidr"]

    [leg] = path["legs"]
    assert (leg["from"], leg["to"]) == (path["picks"][0]["key"], path["picks"][1]["key"])
    for direction, start in (("forward", branch_id), ("backward", hq_id)):
        trace = leg[direction]
        assert trace["applies"] is True, trace["summary"]
        assert trace["traffic"] == "tcp/443"
        assert trace["source"]["node"] == start
        hops = trace["request"]["hops"] + trace["reply"]["hops"]
        assert hops
        assert all(h["node"] is None or h["node"] in node_ids for h in hops)
        assert all(h["edge"] is None or re.fullmatch(r"e\d+", h["edge"]) for h in hops)
    assert leg["forward"]["verdict"] == "allowed", leg["forward"]["summary"]
    assert leg["forward"]["request"]["hops"][0]["node"] == branch_id

    # A device pick has no subnet: no leg is traced to or from it.
    device = {"key": f"n:{branch['node']}", "node": branch["node"], "label": "Branch MX"}
    alone = _export_with_path(api, {"picks": [device, hq]})["path"]
    assert [p["key"] for p in alone["picks"]] == [f"n:{branch_id}", f"s:10.0.10.20:{hq_id}"]
    assert alone["picks"][0]["subnet"] is None and alone["legs"] == []
    assert alone["traffic"] == {"protocol": "", "port": None}

    # A pick off the exported map is dropped; the export still renders.
    gone = {"key": "n:999999", "node": 999999, "label": "gone"}
    dropped = _export_with_path(api, {"picks": [gone, branch, hq]})["path"]
    assert [p["node"] for p in dropped["picks"]] == [branch_id, hq_id] and len(dropped["legs"]) == 1
    assert "path" not in _export_with_path(api, {"picks": [gone]})

    # Without a path the export embeds none.
    assert "path" not in _export_data(api.get("/api/topology/export.html"))
    assert "path" not in _export_data(api.get("/api/topology/export.html?path="))


def test_api_html_export_rejects_a_bad_path(api):
    import json

    pick = {"key": "n:1", "node": 1, "label": "one"}
    for bad in (
        "{not json",
        json.dumps([pick]),
        json.dumps({"picks": [pick] * 7}),
        json.dumps({"picks": []}),
        json.dumps({"picks": [pick], "traffic": {"protocol": "gre"}}),
        json.dumps({"picks": [pick], "traffic": {"protocol": "tcp", "port": 70000}}),
        json.dumps({"picks": [{"key": "n:1", "label": "one"}]}),
        json.dumps({"picks": [{"key": "n:1", "node": 1, "label": ""}]}),
    ):
        response = api.get("/api/topology/export.html", params={"path": bad})
        assert response.status_code == 400, bad
        assert "path: " in response.text


def test_graph_to_snapshot_edges_carry_the_graph_edge_id():
    graph = {
        "nodes": [{"id": 1, "label": "a"}, {"id": "x", "label": "b"}],
        "edges": [{"id": "lldp:1:x", "from": 1, "to": "x", "protocol": "lldp"}],
    }
    [edge] = graph_to_snapshot(graph, {}, {})["edges"]
    assert edge["id"] == "e1" and edge["gid"] == "lldp:1:x"


# ── The export's own path tracer (pathtrace.offline) ─────────────────────────


def _offline_map() -> tuple[dict, dict, list[dict], dict]:
    """The vMX map plus an inventory host on the branch LAN, with discovery
    rows holding a datetime as database rows do."""
    import datetime

    graph, snapshots, rows = _vmx_map()
    rows = [{**row, "last_seen_at": datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)} for row in rows]
    graph["nodes"].append({"id": 7, "label": "lab-core-sw", "ip": "10.1.10.2", "in_inventory": True})
    graph["edges"].append({"id": "lldp:7:br", "from": 7, "to": "meraki:1:d:BR", "protocol": "lldp", "status": "up"})
    hosts = {7: forwarding_for_host({"ip_address": "10.1.10.2", "device_type": "cisco_ios"}, [], None, [])}
    return graph, snapshots, rows, hosts


_OFFLINE_CASES = (
    ("10.1.10.5", "10.50.2.20", "meraki:1:d:BR", "meraki:-1:vpc:vpc-1", "tcp", 443),
    ("10.50.2.20", "10.1.10.5", "meraki:-1:vpc:vpc-1", "meraki:1:d:BR", "", None),
    ("10.1.10.2", "10.50.2.20", "7", None, "udp", 53),
    ("10.1.10.5", "10.50.2.20", None, None, "icmp", None),
    ("not-an-address", "10.50.2.20", None, None, "", None),
)


def test_offline_build_and_trace_give_what_the_server_tracer_gives():
    import json

    from netcontrol.integrations.pathtrace import offline

    graph, snapshots, rows, hosts = _offline_map()
    server = Tracer(graph, snapshots, {-1: Reachability(rows, [])}, hosts, [])
    snapshot = graph_to_snapshot(graph, {}, {})
    clouds = {-1: {"provider": "aws", "resources": rows, "connections": []}}
    text = offline.dumps(offline.inputs(graph, snapshots, clouds, hosts, [], snapshot))
    rebuilt = offline.build(json.loads(text))
    node_ids, edge_ids = offline.export_ids(snapshot)

    for source, destination, source_node, destination_node, protocol, port in _OFFLINE_CASES:
        try:
            raw = server.trace(
                source,
                destination,
                source_node=int(source_node) if source_node == "7" else source_node,
                destination_node=destination_node,
                protocol=protocol,
                port=port,
            )
            expected = offline.export_trace(raw, node_ids, edge_ids)
        except ValueError as exc:
            expected = {"applies": False, "traffic": "", "verdict": "unknown", "summary": str(exc)}
        # The file passes its own (text) node ids, as the viewer does.
        got = offline.trace(
            rebuilt,
            source,
            destination,
            source_node=source_node,
            destination_node=destination_node,
            protocol=protocol,
            port=port,
            node_ids=node_ids,
            edge_ids=edge_ids,
        )
        assert json.loads(json.dumps(got)) == json.loads(json.dumps(expected)), (source, destination)

    first = offline.trace(
        rebuilt, *_OFFLINE_CASES[0][:2], source_node="meraki:1:d:BR", node_ids=node_ids, edge_ids=edge_ids
    )
    assert first["applies"] and first["request"]["hops"]
    assert all(h["node"] is None or h["node"] in node_ids for h in first["request"]["hops"])
    assert any(h["edge"] in {e["id"] for e in snapshot["edges"]} for h in first["request"]["hops"])
    assert "2026-01-02T03:04:05+00:00" in text


def test_offline_session_answers_trace_requests_as_json(tmp_path):
    import json

    from netcontrol.integrations.pathtrace import offline

    graph, snapshots, rows, hosts = _offline_map()
    snapshot = graph_to_snapshot(graph, {}, {})
    clouds = {-1: {"provider": "aws", "resources": rows, "connections": []}}
    path = tmp_path / "inputs.json"
    path.write_text(offline.dumps(offline.inputs(graph, snapshots, clouds, hosts, [], snapshot)), encoding="utf-8")
    run = offline.open_session(str(path))

    request = {"source": "10.1.10.5", "destination": "10.50.2.20", "source_node": "meraki:1:d:BR"}
    answer = json.loads(run(json.dumps({**request, "protocol": "tcp", "port": 443})))
    assert answer["applies"] is True and answer["traffic"] == "tcp/443" and answer["verdict"] == "allowed"
    assert json.loads(run(json.dumps({**request, "protocol": "gre"})))["applies"] is False


def test_offline_modules_import_with_the_standard_library_only(tmp_path):
    """The modules an export carries import alone: a server-only import
    among them would fail in the browser too."""
    import json
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    from netcontrol.integrations.pathtrace.offline import MODULES

    repo = Path(__file__).resolve().parents[1]
    for name in MODULES:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / name, tmp_path / name)
    script = (
        "import json, sys; sys.path.insert(0, '.'); import netcontrol.integrations.pathtrace.offline; "
        "print(json.dumps(sorted(m.__file__ for n, m in sys.modules.items() if n.startswith('netcontrol'))))"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr
    loaded = {Path(f).resolve().relative_to(tmp_path.resolve()).as_posix() for f in json.loads(done.stdout)}
    assert loaded == set(MODULES)


def _fake_pyodide(tmp_path, monkeypatch) -> None:
    from netcontrol.integrations.meraki import html_export

    vendor = tmp_path / "pyodide"
    vendor.mkdir()
    for name in html_export.PYODIDE_FILES:
        (vendor / name).write_bytes(f"stand-in for {name}".encode())
    (vendor / "VERSION").write_text("0.0-test\n", encoding="utf-8")
    monkeypatch.setenv("PLEXUS_PYODIDE_DIR", str(vendor))


def _unpack(html: str, block: str) -> bytes:
    import base64
    import gzip
    import re

    found = re.search(rf'<script type="text/plain" id="{block}">(.*?)</script>', html, re.S)
    assert found is not None, block
    return gzip.decompress(base64.b64decode(found.group(1)))


def test_api_html_export_carries_the_path_tracer(api, tmp_path, monkeypatch):
    import json
    import re

    from netcontrol.integrations.meraki.html_export import EXPORT_TRACER_CSP, PYODIDE_FILES
    from netcontrol.integrations.pathtrace import offline

    _fake_pyodide(tmp_path, monkeypatch)
    assert api.post("/api/sources/sample").status_code == 201
    response = api.get("/api/topology/export.html")
    exported = _export_data(response)
    html = response.text
    assert response.headers["Content-Security-Policy"] == EXPORT_TRACER_CSP
    assert "worker-src blob:" in EXPORT_TRACER_CSP and "'wasm-unsafe-eval'" in EXPORT_TRACER_CSP
    assert "sandbox allow-scripts allow-downloads" in EXPORT_TRACER_CSP and "allow-same-origin" not in EXPORT_TRACER_CSP
    assert "connect-src" not in EXPORT_TRACER_CSP
    assert (
        """http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' blob:""" in html
    )

    meta = json.loads(
        re.search(r'<script type="application/json" id="tracer-meta">(.*?)</script>', html, re.S).group(1)
    )
    assert meta == {"pyodide": "0.0-test", "files": PYODIDE_FILES}
    assert 'id="tracer-runtime">(function (scope, post)' in html
    for name in PYODIDE_FILES:
        assert f'data-tracer-file="{name}">' in html

    modules = json.loads(_unpack(html, "tracer-modules"))
    assert modules == offline.module_sources()

    inputs = json.loads(_unpack(html, "tracer-inputs"))
    assert set(inputs["export"]["nodes"]) == {n["id"] for n in exported["nodes"]}
    assert set(inputs["export"]["edges"].values()) <= {e["id"] for e in exported["edges"]}
    tracer = offline.build(inputs)
    node_ids, edge_ids = set(inputs["export"]["nodes"]), inputs["export"]["edges"]
    query = "source=10.2.10.5&destination=10.0.10.20&protocol=tcp&port=443"
    server = api.get(f"/api/topology/path?{query}").json()
    mine = offline.trace(
        tracer, "10.2.10.5", "10.0.10.20", protocol="tcp", port=443, node_ids=node_ids, edge_ids=edge_ids
    )
    assert mine["verdict"] == "allowed"
    assert json.loads(json.dumps(mine)) == offline.export_trace(server, node_ids, edge_ids)


def test_api_html_export_without_the_path_tracer(api, tmp_path, monkeypatch):
    from netcontrol.integrations.meraki.html_export import EXPORT_CSP

    assert api.post("/api/sources/sample").status_code == 201
    _fake_pyodide(tmp_path, monkeypatch)
    small = api.get("/api/topology/export.html?engine=0")
    monkeypatch.setenv("PLEXUS_PYODIDE_DIR", str(tmp_path / "not-fetched"))
    missing = api.get("/api/topology/export.html")
    for response in (small, missing):
        assert response.headers["Content-Security-Policy"] == EXPORT_CSP
        assert 'id="tracer-meta"' not in response.text and "data-tracer-file=" not in response.text
        assert """content="default-src 'none'; script-src 'unsafe-inline'; style-src""" in response.text
        assert _export_data(response)["nodes"]


# ── Reachability sweep ───────────────────────────────────────────────────────


def _row(cidr: str, name: str, kind: str = "vlan", **fields) -> dict:
    return {
        "org_ref": 1,
        "provider": "meraki",
        "cidr": cidr,
        "name": name,
        "kind": kind,
        "site_id": "BR",
        "site_name": "Branch 01",
        "node_id": "d:BR",
        "in_vpn": True,
        **fields,
    }


_SWEEP_ROWS = [
    _row("10.1.10.0/24", "VLAN 10 Data"),
    _row("10.1.20.0/24", "VLAN 20 Voice"),
    _row("10.1.30.0/24", "VLAN 30 Guest", in_vpn=False),
    _row("10.1.110.0/24", "VLAN 110 Users", kind="svi", node_id="d:SW"),
    _row("10.3.15.0/24", "Office (VLAN 115)", kind="range", org_ref=2, provider="cato", site_name="Branch C"),
    _row("10.3.99.0/24", "Static route Lab", kind="static", in_vpn=None),
    _row("172.21.0.0/16", "Behind Partner", kind="peer", site_name="", in_vpn=None),
    _row("10.0.10.0/24", "VLAN 10 Data", site_id="HUB", site_name="Hub 01", node_id="d:HUB"),
    _row("10.1.10.0/24", "VLAN 10 Data"),  # the same network of the same device again
    _row("2001:db8:10::/64", "VLAN 10 Data v6"),
]


def _picked(filters, destination: str = "10.0.10.20") -> list[str]:
    from netcontrol.integrations.pathtrace.sweep import select_rows

    return [r["cidr"] for r in select_rows(_SWEEP_ROWS, filters, destination)]


def test_sweep_filters_default_kinds_and_drop_the_destinations_own_network():
    from netcontrol.integrations.pathtrace.sweep import DEFAULT_KINDS, parse_filters, select_rows

    filters = parse_filters()
    assert filters.to_json()["kinds"] == list(DEFAULT_KINDS)
    # Static routes and peers are not default kinds; the hub's own network
    # holds the destination; the repeat and the IPv6 network are left out.
    assert _picked(filters) == ["10.1.10.0/24", "10.1.20.0/24", "10.1.30.0/24", "10.1.110.0/24", "10.3.15.0/24"]
    assert "10.0.10.0/24" in _picked(filters, "10.9.9.9")
    assert _picked(parse_filters(kinds="static,peer")) == ["10.3.99.0/24", "172.21.0.0/16"]
    assert len(_picked(parse_filters(kinds="all"))) == 7
    vlans = {r["cidr"]: r["vlan"] for r in select_rows(_SWEEP_ROWS, filters, "10.0.10.20")}
    assert vlans == {
        "10.1.10.0/24": 10,
        "10.1.20.0/24": 20,
        "10.1.30.0/24": 30,
        "10.1.110.0/24": 110,
        "10.3.15.0/24": 115,
    }


def test_sweep_filters_compose():
    from netcontrol.integrations.pathtrace.sweep import parse_filters

    assert _picked(parse_filters(vlans="10, 100-120")) == ["10.1.10.0/24", "10.1.110.0/24", "10.3.15.0/24"]
    assert _picked(parse_filters(name="data,USERS")) == ["10.1.10.0/24", "10.1.110.0/24"]
    assert _picked(parse_filters(name=r"/^VLAN \d{2} /")) == ["10.1.10.0/24", "10.1.20.0/24", "10.1.30.0/24"]
    assert _picked(parse_filters(name=r"/^VLAN (1|11)0 /,office")) == ["10.1.10.0/24", "10.1.110.0/24", "10.3.15.0/24"]
    assert _picked(parse_filters(exclude="voice,guest")) == ["10.1.10.0/24", "10.1.110.0/24", "10.3.15.0/24"]
    assert _picked(parse_filters(sites="branch c")) == ["10.3.15.0/24"]
    assert _picked(parse_filters(sources="2")) == ["10.3.15.0/24"]
    assert _picked(parse_filters(providers="Meraki", vlans="20-30")) == ["10.1.20.0/24", "10.1.30.0/24"]
    assert _picked(parse_filters(within="10.1.0.0/19,10.3.0.0/16")) == [
        "10.1.10.0/24",
        "10.1.20.0/24",
        "10.1.30.0/24",
        "10.3.15.0/24",
    ]
    assert _picked(parse_filters(in_vpn="0")) == ["10.1.30.0/24"]
    assert "10.1.30.0/24" not in _picked(parse_filters(in_vpn="1"))
    assert _picked(parse_filters(kinds="static,peer", in_vpn="1")) == []
    echoed = parse_filters(vlans="100-120,5", name="/a,b/, user").to_json()
    assert echoed["vlans"] == "100-120,5" and echoed["name"] == ["/a,b/", "user"]


def test_sweep_overlaps_filter_keeps_every_network_that_shares_an_address():
    from netcontrol.integrations.pathtrace.sweep import parse_filters, select_rows

    rows = [
        _row("10.0.0.0/8", "Static route Everything", kind="static"),  # contains the range
        _row("10.64.10.0/24", "VLAN 10 Data"),  # inside it
        _row("10.64.0.0/16", "Azure hub", kind="subnet", provider="azure"),  # the range itself
        _row("10.65.0.0/24", "VLAN 65 Disjoint"),
        _row("2001:db8::/32", "VLAN 10 Data v6"),
    ]

    def kept(**values) -> list[str]:
        return [r["cidr"] for r in select_rows(rows, parse_filters(kinds="all", **values), None)]

    assert kept(overlaps="10.64.0.0/16") == ["10.0.0.0/8", "10.64.10.0/24", "10.64.0.0/16"]
    # Within keeps only the networks inside the range; the wider route is left out.
    assert kept(within="10.64.0.0/16") == ["10.64.10.0/24", "10.64.0.0/16"]
    # Each range of a list is tried; one of either IP version matches its own.
    assert kept(overlaps="10.64.10.128/25, 2001:db8:1::/48") == [
        "10.0.0.0/8",
        "10.64.10.0/24",
        "10.64.0.0/16",
        "2001:db8::/32",
    ]
    assert kept(overlaps="192.168.0.0/16") == []
    assert parse_filters(overlaps="10.64.0.0/16").to_json()["overlaps"] == ["10.64.0.0/16"]


@pytest.mark.parametrize(
    "bad",
    [
        {"vlans": "ten"},
        {"vlans": "120-110"},
        {"vlans": "5000"},
        {"name": "/(/"},
        {"exclude": "/[a/"},
        {"kinds": "vlan,tunnel"},
        {"within": "10.0.0.0/33"},
        {"overlaps": "ten.0.0.0/8"},
        {"in_vpn": "maybe"},
        {"sources": "one"},
    ],
)
def test_sweep_filters_that_are_not_valid_are_refused(bad):
    from netcontrol.integrations.pathtrace.sweep import parse_filters

    with pytest.raises(ValueError):
        parse_filters(**bad)


def test_sweep_reports_each_networks_verdict_and_what_decided_it():
    from netcontrol.integrations.pathtrace.sweep import parse_filters, run, select_rows, summary_rows, sweep

    deny = rule(1, "deny", src=["10.1.30.0/24"], dst=["10.0.0.0/8"], comment="Block guest over the VPN")
    tracer = _tracer(_branch_and_hub([deny]), subnets=_SUBNETS)
    rows = select_rows(
        [_row("10.1.30.0/24", "VLAN 30 Guest"), _row("10.1.10.0/24", "VLAN 10 Data")], parse_filters(), "10.0.10.20"
    )
    report = run(tracer, rows, "10.0.10.20", protocol="tcp", port=445)

    assert report["traffic"] == "tcp/445" and report["destination"]["label"] == "Hub 01 MX"
    assert report["counts"] == {"allowed": 1, "blocked": 1, "unreachable": 0, "partial": 0, "unknown": 0}
    # The summary of a download: every verdict in order, its share, a total.
    assert summary_rows(report["counts"]) == [
        ["Allowed", 1, "50%"],
        ["Blocked", 1, "50%"],
        ["No path", 0, "0%"],
        ["Allowed in part", 0, "0%"],
        ["Check incomplete", 0, "0%"],
        ["Total", 2, "100%"],
    ]
    assert summary_rows({})[-1] == ["Total", 0, ""] and summary_rows({"blocked": 2, "allowed": 1})[1] == [
        "Blocked",
        2,
        "67%",
    ]
    data, guest = report["rows"]  # sorted by site, then VLAN
    assert (data["vlan"], data["verdict"], data["decided_at"], data["decided_by"]) == (10, "allowed", "", "")
    assert data["source_node"] == "meraki:1:d:BR" and data["node_label"] == "Branch 01 MX"
    assert data["traffic"] == "tcp/445" and data["site_name"] == "Branch 01"
    assert guest["verdict"] == "blocked" and guest["decided_at"] == "Branch 01 MX"
    assert guest["decided_by"].startswith("Site-to-site VPN firewall rules: Rule 1 (deny any")
    assert guest["summary"].startswith("Blocked at Branch 01 MX")
    assert "hops" not in guest and "request" not in guest
    # Each row names its destination: the address typed, and the trace's end.
    assert (data["dst_cidr"], data["dst_node_label"], data["dst_site_name"]) == ("10.0.10.20", "Hub 01 MX", "Hub 01")
    assert data["destination_node"] == "meraki:1:d:HUB" and data["dst_name"] == "" and data["dst_vlan"] is None
    assert sweep(tracer, rows, "10.0.10.20", protocol="tcp", port=445) == report["rows"]

    # A peer behind a tunnel that is down: no path, decided by the link.
    down = _tracer(_with_partner("unreachable"), subnets=_SUBNETS)
    [peer] = sweep(down, rows[1:], "172.21.4.4", destination_node="meraki:1:p:Partner")
    assert peer["verdict"] == "unreachable" and peer["decided_at"] == "Branch 01 MX"
    assert peer["decided_by"].startswith("Link to Partner: The IPsec tunnel between Branch 01 MX and Partner is down")

    # A trace the tracer refuses is reported, not raised.
    [refused] = sweep(tracer, [_row("10.1.10.0/24", "VLAN 10 Data")], "2001:db8::1")
    assert refused["verdict"] == "unknown" and "both be IPv4 or both be IPv6" in refused["summary"]


def test_api_reachability_sweep_as_json_and_csv(api):
    import csv
    import io

    from netcontrol.xlsx import XLSX_MEDIA_TYPE

    assert api.post("/api/sources/sample").status_code == 201
    graph = api.get("/api/topology").json()["nodes"]
    label = {(n.get("meraki") or {}).get("node_id"): n["label"] for n in graph}
    branch_mx = label["d:Q2MX-0002-0001"]

    query = "destination=10.0.10.20&protocol=tcp&port=443&within=10.2.0.0/16"
    response = api.get(f"/api/topology/reachability?{query}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["traffic"] == "tcp/443" and body["destination"]["address"] == "10.0.10.20"
    assert body["filters"]["within"] == ["10.2.0.0/16"] and body["filters"]["kinds"][0] == "vlan"
    assert body["candidates"] == len(body["rows"]) > 0 and body["limit"] == 20000
    assert body["mode"] == "one" and body["to_filters"] is None
    assert body["source_count"] == len(body["rows"]) and body["destination_count"] == 1
    assert sum(body["counts"].values()) == len(body["rows"])
    # Each row names its destination: the address typed, and the trace's end.
    assert {r["dst_cidr"] for r in body["rows"]} == {"10.0.10.20"}
    assert all(r["dst_node_label"] == body["destination"]["label"] for r in body["rows"])
    assert all(r["destination_node"] == body["destination"]["node"] for r in body["rows"])
    assert all(r["dst_org_ref"] is None and r["dst_vlan"] is None and r["dst_name"] == "" for r in body["rows"])
    assert all(r["cidr"].startswith("10.2.") for r in body["rows"])
    by_cidr = {r["cidr"]: r for r in body["rows"]}
    assert by_cidr["10.2.10.0/24"]["verdict"] == "allowed", by_cidr["10.2.10.0/24"]["summary"]
    guest = by_cidr["10.2.30.0/24"]
    assert guest["verdict"] == "blocked" and guest["decided_at"] == branch_mx
    assert guest["decided_by"].startswith("Layer 3 firewall rules: ")
    assert body["generated_at"].endswith("+00:00")

    csv_response = api.get(f"/api/topology/reachability?{query}&format=csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"] == "text/csv; charset=utf-8"
    assert csv_response.headers["content-disposition"] == ('attachment; filename="reachability-10.0.10.20-tcp_443.csv"')
    table = list(csv.reader(io.StringIO(csv_response.text)))
    assert table[0] == [
        "Source",
        "Provider",
        "Site",
        "Network",
        "Kind",
        "VLAN",
        "CIDR",
        "In VPN",
        "Destination site",
        "Destination network",
        "Destination CIDR",
        "Verdict",
        "Decided at",
        "Decided by",
        "Ports",
        "Summary",
    ]
    # The rows, then an empty line and the counts by verdict with a total.
    blocked = [r for r in body["rows"] if r["verdict"] == "blocked"]
    allowed = [r for r in body["rows"] if r["verdict"] == "allowed"]
    assert blocked and allowed and len(blocked) + len(allowed) <= len(body["rows"])
    lines, summary = table[: len(body["rows"]) + 1], table[len(body["rows"]) + 1 :]
    assert all(len(line) == len(table[0]) for line in lines)
    guest_line = next(line for line in lines if line[6] == "10.2.30.0/24")
    assert guest_line[11] == "Blocked" and guest_line[12] == branch_mx
    assert guest_line[10] == "10.0.10.20" and guest_line[9] == ""
    assert guest_line[8] == body["destination"]["site"]
    assert guest_line[14] == ((guest["ports"] or {}).get("text") or "")
    assert summary[:2] == [[], ["Verdict", "Networks", "Share"]]
    assert [line[:2] for line in summary[2:]] == [
        ["Allowed", str(len(allowed))],
        ["Blocked", str(len(blocked))],
        ["No path", str(body["counts"]["unreachable"])],
        ["Allowed in part", str(body["counts"]["partial"])],
        ["Check incomplete", str(body["counts"]["unknown"])],
        ["Total", str(len(body["rows"]))],
    ]
    assert summary[-1][2] == "100%" and summary[2][2] == f"{len(allowed) / len(body['rows']):.0%}"

    # A spreadsheet has the same rows, columns fitted to their text, a frozen
    # bold header and a filter, on a tab of every row and one per verdict,
    # after a Summary tab of the counts.
    import re
    import zipfile

    book_response = api.get(f"/api/topology/reachability?{query}&format=xlsx")
    assert book_response.status_code == 200
    assert book_response.headers["content-type"] == XLSX_MEDIA_TYPE
    assert book_response.headers["content-disposition"] == 'attachment; filename="reachability-10.0.10.20-tcp_443.xlsx"'
    with zipfile.ZipFile(io.BytesIO(book_response.content)) as archive:
        tabs = re.findall(r'<sheet name="([^"]+)"', archive.read("xl/workbook.xml").decode("utf-8"))
        pages = [archive.read(f"xl/worksheets/sheet{n}.xml").decode("utf-8") for n in range(1, len(tabs) + 1)]
    assert tabs == ["Summary", "All", "Allowed", "Blocked", "No path", "Allowed in part", "Check incomplete"]
    summary_tab, every, allowed_tab, blocked_tab = pages[0], pages[1], pages[2], pages[3]
    assert summary_tab.count("<row ") == 7  # the header, five verdicts and the total
    assert '<c r="A1" t="inlineStr" s="1"><is><t xml:space="preserve">Verdict</t></is></c>' in summary_tab
    assert f'<c r="B3"><v>{len(blocked)}</v></c>' in summary_tab  # counts are numbers
    assert (
        f'<c r="A7" t="inlineStr"><is><t xml:space="preserve">Total</t></is></c><c r="B7"><v>{len(body["rows"])}</v></c>'
        in summary_tab
    )
    assert every.count("<row ") == len(body["rows"]) + 1
    assert allowed_tab.count("<row ") == len(allowed) + 1 and "10.2.10.0/24" in allowed_tab
    assert blocked_tab.count("<row ") == len(blocked) + 1
    assert "10.2.30.0/24" in blocked_tab and "10.2.10.0/24" not in blocked_tab
    assert pages[4].count("<row ") == 1  # an empty verdict still has its tab, with the header
    for page in pages[1:]:
        assert page.count('customWidth="1"') == len(table[0]) and 'state="frozen"' in page
        assert '<c r="A1" t="inlineStr" s="1"><is><t xml:space="preserve">Source</t></is></c>' in page
    assert f'<autoFilter ref="A1:P{len(blocked) + 1}"/>' in blocked_tab

    # `verdict` keeps only the rows of one verdict: a single tab, named after
    # it, after the summary of the whole sweep.
    sheet_response = api.get(f"/api/topology/reachability?{query}&format=xlsx&verdict=blocked")
    assert sheet_response.status_code == 200
    assert sheet_response.headers["content-disposition"] == (
        'attachment; filename="reachability-10.0.10.20-tcp_443-blocked.xlsx"'
    )
    with zipfile.ZipFile(io.BytesIO(sheet_response.content)) as archive:
        book = archive.read("xl/workbook.xml").decode("utf-8")
        assert re.findall(r'<sheet name="([^"]+)"', book) == ["Summary", "Blocked"]
        assert archive.read("xl/worksheets/sheet1.xml").decode("utf-8") == summary_tab
        assert archive.read("xl/worksheets/sheet2.xml").decode("utf-8") == blocked_tab
    filtered_csv = api.get(f"/api/topology/reachability?{query}&format=csv&verdict=blocked")
    assert filtered_csv.headers["content-disposition"].endswith('-blocked.csv"')
    filtered_table = list(csv.reader(io.StringIO(filtered_csv.text)))
    assert len(filtered_table) == len(blocked) + 1 + len(summary)
    assert filtered_table[len(blocked) + 1 :] == summary  # the whole sweep's counts
    assert api.get(f"/api/topology/reachability?{query}&format=csv&verdict=maybe").status_code == 400

    # Narrowing to a VLAN name keeps only that network.
    named = api.get(f"/api/topology/reachability?{query}&name=/guest/").json()
    assert [r["cidr"] for r in named["rows"]] == ["10.2.30.0/24"]

    for bad in ("protocol=gre", "name=/(/", "vlans=x", "kinds=tunnel", "format=xml"):
        response = api.get(f"/api/topology/reachability?destination=10.0.10.20&{bad}")
        assert response.status_code in (400, 422), bad
    assert api.get("/api/topology/reachability?destination=nope").status_code == 400


def test_api_reachability_sweep_refuses_too_many_sources(api, monkeypatch):
    from netcontrol.integrations.pathtrace import sweep as sweep_module

    assert api.post("/api/sources/sample").status_code == 201
    monkeypatch.setattr(sweep_module, "MAX_ROWS", 1)
    response = api.get("/api/topology/reachability?destination=10.0.10.20")
    assert response.status_code == 400
    body = response.json()
    assert body["limit"] == 1 and body["count"] > 1
    assert "Narrow the filters" in body["error"]["message"]
    assert body["error"]["code"] == "too_many_sources" and "source networks match" in body["error"]["message"]

    # A matrix counts its source→destination pairs against the limit.
    monkeypatch.setattr(sweep_module, "MAX_ROWS", 3)
    matrix = api.get("/api/topology/reachability?within=10.2.0.0/16&to_within=10.0.0.0/16")
    assert matrix.status_code == 400
    refused = matrix.json()
    assert refused["ok"] is False and refused["error"]["code"] == "too_many_sources"
    assert refused["limit"] == 3 and refused["count"] > 3
    assert refused["error"]["message"] == (
        f"{refused['count']} source→destination pairs match; at most 3 are traced at once. Narrow the filters."
    )


def test_sweep_matrix_traces_every_source_network_to_every_destination_network():
    from netcontrol.integrations.pathtrace.sweep import (
        CSV_COLUMNS,
        csv_row,
        pairs,
        parse_filters,
        run_matrix,
        select_rows,
    )

    deny = rule(1, "deny", src=["10.1.30.0/24"], dst=["10.0.0.0/8"], comment="Block guest over the VPN")
    tracer = _tracer(_branch_and_hub([deny]), subnets=_SUBNETS)
    data, guest = _row("10.1.10.0/24", "VLAN 10 Data"), _row("10.1.30.0/24", "VLAN 30 Guest")
    hub = _row("10.0.10.0/24", "VLAN 10 Data", site_id="HUB", site_name="Hub 01", node_id="d:HUB", org_name="Acme")
    sources = select_rows([guest, data], parse_filters(), None)
    targets = select_rows([hub, data, _row("2001:db8:10::/64", "VLAN 10 Data v6")], parse_filters(), None)
    assert [r["cidr"] for r in targets] == ["10.0.10.0/24", "10.1.10.0/24", "2001:db8:10::/64"]

    # A network is never paired with itself, nor with another IP version.
    matrix = pairs(sources, targets)
    assert [(s["cidr"], d["cidr"]) for s, d in matrix] == [
        ("10.1.30.0/24", "10.0.10.0/24"),
        ("10.1.30.0/24", "10.1.10.0/24"),
        ("10.1.10.0/24", "10.0.10.0/24"),
    ]
    assert pairs(sources, [_row("10.1.0.0/16", "Supernet")]) == []  # overlaps both sources

    report = run_matrix(tracer, matrix)
    assert report["destination"] is None and report["traffic"] == "any traffic"
    assert sum(report["counts"].values()) == 3
    # Sorted by source site, VLAN and network, then destination site, VLAN and network.
    assert [(r["cidr"], r["dst_cidr"]) for r in report["rows"]] == [
        ("10.1.10.0/24", "10.0.10.0/24"),
        ("10.1.30.0/24", "10.1.10.0/24"),
        ("10.1.30.0/24", "10.0.10.0/24"),
    ]
    to_hub, guest_to_data, guest_to_hub = report["rows"]
    assert to_hub["verdict"] == "allowed" and to_hub["source_node"] == "meraki:1:d:BR"
    assert (to_hub["dst_name"], to_hub["dst_site_name"], to_hub["dst_vlan"]) == ("VLAN 10 Data", "Hub 01", 10)
    assert (to_hub["dst_org_ref"], to_hub["dst_org_name"], to_hub["dst_provider"]) == (1, "Acme", "meraki")
    assert (to_hub["dst_node_id"], to_hub["dst_kind"], to_hub["dst_in_vpn"]) == ("d:HUB", "vlan", True)
    assert to_hub["dst_node_label"] == "Hub 01 MX" and to_hub["destination_node"] == "meraki:1:d:HUB"
    assert guest_to_data["destination_node"] == "meraki:1:d:BR" and guest_to_data["dst_site_name"] == "Branch 01"
    assert guest_to_hub["verdict"] == "blocked" and guest_to_hub["decided_at"] == "Branch 01 MX"
    # Any traffic asked: the ports allowed end to end are the tracer's, and the Ports column.
    assert to_hub["ports"] and to_hub["ports"]["text"]
    cells = csv_row(to_hub)
    assert len(cells) == len(CSV_COLUMNS)
    assert cells[CSV_COLUMNS.index("Ports")] == to_hub["ports"]["text"]
    assert cells[CSV_COLUMNS.index("Destination CIDR")] == "10.0.10.0/24"
    assert cells[CSV_COLUMNS.index("Destination network")] == "VLAN 10 Data"
    assert cells[CSV_COLUMNS.index("Destination site")] == "Hub 01"
    assert run_matrix(tracer, matrix, protocol="tcp", port=445)["traffic"] == "tcp/445"
    with pytest.raises(ValueError):
        run_matrix(tracer, matrix, protocol="gre")


def test_api_reachability_matrix_of_cloud_and_cato_networks_to_meraki_vlans(api):
    import csv
    import io
    import ipaddress
    import re
    import zipfile

    from netcontrol.integrations.pathtrace.sweep import DEFAULT_KINDS

    for provider in ("meraki", "aws", "azure", "gcp", "cato"):
        assert api.post(f"/api/sources/sample?provider={provider}").status_code == 201, provider
    subnets = api.get("/api/sources/subnets").json()["subnets"]

    def kept(providers: tuple[str, ...], kinds: tuple[str, ...]) -> list[tuple[str, str]]:
        found: dict[tuple[str, str], None] = {}
        for s in subnets:
            if s.get("provider") in providers and s.get("kind") in kinds:
                found[(str(ipaddress.ip_network(s["cidr"], strict=False)), str(s.get("node_id") or ""))] = None
        return list(found)

    sources, targets = kept(("aws", "azure", "gcp", "cato"), DEFAULT_KINDS), kept(("meraki",), ("vlan",))
    assert sources and targets
    expected = [
        (s, d)
        for s, _ in sources
        for d, _ in targets
        if ipaddress.ip_network(s).version == ipaddress.ip_network(d).version
        and not ipaddress.ip_network(s).overlaps(ipaddress.ip_network(d))  # type: ignore[arg-type]
    ]

    query = "providers=aws,azure,gcp,cato&to_providers=meraki&to_kinds=vlan"
    response = api.get(f"/api/topology/reachability?{query}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "matrix" and body["destination"] is None and body["traffic"] == "any traffic"
    assert body["source_count"] == len(sources) and body["destination_count"] == len(targets)
    assert body["candidates"] == len(expected) == len(body["rows"]) and body["limit"] == 20000
    assert body["to_filters"]["providers"] == ["meraki"] and body["to_filters"]["kinds"] == ["vlan"]
    assert sum(body["counts"].values()) == len(body["rows"])
    meraki_vlans = {cidr for cidr, _ in targets}
    assert {r["dst_cidr"] for r in body["rows"]} <= meraki_vlans
    assert all(r["dst_provider"] == "meraki" and r["dst_kind"] == "vlan" for r in body["rows"])
    assert {r["provider"] for r in body["rows"]} <= {"aws", "azure", "gcp", "cato"}
    with_ports = [r for r in body["rows"] if r["ports"]]
    assert with_ports and all(r["ports"]["text"] for r in with_ports)

    csv_response = api.get(f"/api/topology/reachability?{query}&format=csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-disposition"] == 'attachment; filename="reachability-matrix-any_traffic.csv"'
    table = list(csv.reader(io.StringIO(csv_response.text)))
    header = table[0]
    assert header == [
        "Source",
        "Provider",
        "Site",
        "Network",
        "Kind",
        "VLAN",
        "CIDR",
        "In VPN",
        "Destination site",
        "Destination network",
        "Destination CIDR",
        "Verdict",
        "Decided at",
        "Decided by",
        "Ports",
        "Summary",
    ]
    lines = table[1 : len(body["rows"]) + 1]
    assert [line[header.index("Ports")] for line in lines] == [
        (r["ports"] or {}).get("text") or "" for r in body["rows"]
    ]
    assert [line[header.index("Destination CIDR")] for line in lines] == [r["dst_cidr"] for r in body["rows"]]
    assert any(line[header.index("Ports")] for line in lines)

    book = api.get(f"/api/topology/reachability?{query}&format=xlsx&verdict=allowed")
    assert book.status_code == 200
    assert book.headers["content-disposition"] == 'attachment; filename="reachability-matrix-any_traffic-allowed.xlsx"'
    full = api.get(f"/api/topology/reachability?{query}&format=xlsx")
    with zipfile.ZipFile(io.BytesIO(full.content)) as archive:
        tabs = re.findall(r'<sheet name="([^"]+)"', archive.read("xl/workbook.xml").decode("utf-8"))
    assert tabs == ["Summary", "All", "Allowed", "Blocked", "No path", "Allowed in part", "Check incomplete"]


def test_api_deep_search_ranks_the_most_specific_subnet_first_over_every_source(api):
    import re

    # The Panorama snapshot (a 10.0.0.0/8 summary route) is collected before
    # the Azure account (a VM at 10.231.10.21/32 in a /24), as a Cato site
    # range or a vMX VPN local network covering a VDI VNet would be.
    for provider in ("panorama", "azure"):
        assert api.post(f"/api/sources/sample?provider={provider}").status_code == 201, provider
    hits = api.get("/api/topology/search/deep?q=10.231.10.21").json()["results"]
    held = [re.search(r"Subnets: (\S+)", h["snippet"] or "") for h in hits]
    cidrs = [m.group(1) for m in held if m]
    assert cidrs and cidrs[0] == "10.231.10.21/32" and "10.0.0.0/8" in cidrs
    assert hits[0]["org_ref"] == -2 and "Virtual machine" in hits[0]["snippet"] and hits[0]["label"]
    lengths = [int(c.rsplit("/", 1)[1]) for c in cidrs]
    assert lengths == sorted(lengths, reverse=True)


def test_api_reachability_refuses_mixing_one_destination_and_many(api):
    assert api.post("/api/sources/sample").status_code == 201
    mixed = api.get("/api/topology/reachability?destination=10.0.10.20&to_providers=meraki")
    assert mixed.status_code == 400
    assert mixed.json()["error"]["message"] == (
        "to_* filters pick the destination networks; leave destination empty to use them"
    )
    for owner in ("destination_node=meraki:1:d:HUB", "destination_org_ref=1&destination_node_id=d:HUB"):
        response = api.get(f"/api/topology/reachability?to_providers=meraki&{owner}")
        assert response.status_code == 400, owner
        assert "destination_node" in response.json()["error"]["message"]
    assert api.get("/api/topology/reachability?to_vlans=x").status_code == 400


def test_sweep_traces_one_typed_source_to_one_destination_or_many():
    from netcontrol.integrations.pathtrace.sweep import (
        iter_pairs,
        parse_filters,
        run,
        run_matrix,
        select_rows,
        typed_row,
    )

    tracer = _tracer(_branch_and_hub(), subnets=_SUBNETS)
    typed = typed_row("10.1.10.50")
    assert typed == {"cidr": "10.1.10.50", "typed": True, "graph_node": None}
    with pytest.raises(ValueError, match="is not an IP address or network"):
        typed_row("nope")

    # A typed source to one destination: one Path Mode trace.
    report = run(tracer, [typed], "10.0.10.20", protocol="tcp", port=443)
    [row] = report["rows"]
    assert row["verdict"] == "allowed" and row["traffic"] == "tcp/443"
    assert (row["org_ref"], row["org_name"], row["provider"], row["site_id"]) == (None, "", "", "")
    assert (row["node_id"], row["kind"], row["vlan"], row["name"], row["in_vpn"]) == ("", "", None, "", None)
    assert row["cidr"] == "10.1.10.50" and row["site_name"] == "Branch 01"
    assert row["node_label"] == "Branch 01 MX" and row["source_node"] == "meraki:1:d:BR"
    assert row["dst_cidr"] == "10.0.10.20" and row["dst_node_label"] == "Hub 01 MX"
    assert report["source"]["node"] == "meraki:1:d:BR" and report["source"]["label"] == "Branch 01 MX"
    assert report["source"]["site"] == "Branch 01" and report["destination"]["label"] == "Hub 01 MX"
    # The owner the page picked is the node the trace starts at.
    owned = run(tracer, [typed_row("10.1.10.50", graph_node="meraki:1:d:BR")], "10.0.10.20")
    assert owned["rows"][0]["source_node"] == "meraki:1:d:BR"
    # Rows of the subnet index name no source end.
    indexed = select_rows([_row("10.1.10.0/24", "VLAN 10 Data")], parse_filters(), None)
    assert run(tracer, indexed, "10.0.10.20")["source"] is None

    # A typed source to many: its own network is skipped.
    hub = _row("10.0.10.0/24", "VLAN 10 Data", site_id="HUB", site_name="Hub 01", node_id="d:HUB")
    targets = select_rows([hub, _row("10.1.10.0/24", "VLAN 10 Data")], parse_filters(), None)
    matrix = run_matrix(tracer, iter_pairs([typed], targets))
    [to_hub] = matrix["rows"]
    assert (to_hub["cidr"], to_hub["dst_cidr"], to_hub["dst_site_name"]) == ("10.1.10.50", "10.0.10.0/24", "Hub 01")
    assert to_hub["org_ref"] is None and to_hub["site_name"] == "Branch 01" and to_hub["verdict"] == "allowed"
    assert to_hub["source_node"] == "meraki:1:d:BR" and to_hub["node_label"] == "Branch 01 MX"
    assert matrix["destination"] is None and matrix["source"]["node"] == "meraki:1:d:BR"


def test_sweep_list_rows_lists_the_networks_without_tracing_them():
    from netcontrol.integrations.pathtrace.sweep import LIST_COLUMNS, csv_row, list_rows, parse_filters, select_rows

    tracer = _tracer(_branch_and_hub(), subnets=_SUBNETS)
    hub = _row("10.0.10.0/24", "VLAN 10 Data", site_id="HUB", site_name="Hub 01", node_id="d:HUB")
    rows = select_rows([hub, *_SWEEP_ROWS[:3]], parse_filters(), None)
    listed = list_rows(tracer, rows)
    # Sorted by site, then VLAN, then network.
    assert [(r["site_name"], r["cidr"]) for r in listed] == [
        ("Branch 01", "10.1.10.0/24"),
        ("Branch 01", "10.1.20.0/24"),
        ("Branch 01", "10.1.30.0/24"),
        ("Hub 01", "10.0.10.0/24"),
    ]
    first = listed[0]
    assert set(first) == {
        "org_ref",
        "org_name",
        "provider",
        "site_id",
        "site_name",
        "node_id",
        "source_node",
        "node_label",
        "kind",
        "vlan",
        "cidr",
        "name",
        "in_vpn",
    }
    assert "verdict" not in first and "dst_cidr" not in first
    assert (first["source_node"], first["node_label"], first["vlan"]) == ("meraki:1:d:BR", "Branch 01 MX", 10)
    assert listed[-1]["source_node"] == "meraki:1:d:HUB" and listed[-1]["node_label"] == "Hub 01 MX"
    assert LIST_COLUMNS == ("Source", "Provider", "Site", "Network", "Kind", "VLAN", "CIDR", "In VPN")
    cells = csv_row(first, LIST_COLUMNS)
    assert cells == ["1", "meraki", "Branch 01", "VLAN 10 Data", "vlan", "10", "10.1.10.0/24", "Yes"]


def test_api_reachability_traces_one_typed_source(api):
    import ipaddress

    assert api.post("/api/sources/sample?provider=meraki").status_code == 201
    subnets = api.get("/api/sources/subnets").json()["subnets"]

    query = "source=10.2.10.25&destination=10.0.10.20&protocol=tcp&port=443"
    response = api.get(f"/api/topology/reachability?{query}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "one" and body["candidates"] == 1 and body["source_count"] == 1
    assert body["source"]["address"] == "10.2.10.25" and body["source"]["label"]
    [row] = body["rows"]
    assert row["cidr"] == "10.2.10.25" and row["org_ref"] is None and row["provider"] == ""
    assert row["site_name"] and row["site_name"] == body["source"]["site"]
    assert row["node_label"] == body["source"]["label"] and row["source_node"] == body["source"]["node"]
    assert row["dst_cidr"] == "10.0.10.20" and row["traffic"] == "tcp/443"
    assert body["filters"]["kinds"][0] == "vlan"  # the default source filters, echoed

    # A typed source to every Meraki VLAN it does not sit in.
    host = ipaddress.ip_network("10.2.10.25")
    vlans = {
        (str(ipaddress.ip_network(s["cidr"], strict=False)), str(s.get("node_id") or ""))
        for s in subnets
        if s.get("provider") == "meraki" and s.get("kind") == "vlan"
    }
    overlapping = [cidr for cidr, _ in vlans if ipaddress.ip_network(cidr).overlaps(host)]
    assert overlapping
    matrix = api.get("/api/topology/reachability?source=10.2.10.25&to_providers=meraki&to_kinds=vlan")
    assert matrix.status_code == 200, matrix.text
    found = matrix.json()
    assert found["mode"] == "matrix" and found["source_count"] == 1 and found["destination"] is None
    assert found["destination_count"] == len(vlans)
    assert found["candidates"] == len(vlans) - len(overlapping) == len(found["rows"])
    assert all(r["cidr"] == "10.2.10.25" for r in found["rows"])
    assert found["source"]["address"] == "10.2.10.25"

    csv_response = api.get("/api/topology/reachability?source=10.2.10.25&to_providers=meraki&to_kinds=vlan&format=csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-disposition"] == (
        'attachment; filename="reachability-from-10.2.10.25-to-matrix-any_traffic.csv"'
    )
    one_csv = api.get(f"/api/topology/reachability?{query}&format=csv")
    assert one_csv.headers["content-disposition"] == (
        'attachment; filename="reachability-from-10.2.10.25-to-10.0.10.20-tcp_443.csv"'
    )

    mixed = api.get("/api/topology/reachability?source=10.2.10.25&destination=10.0.10.20&providers=meraki")
    assert mixed.status_code == 400
    assert mixed.json()["error"]["message"] == (
        "the source filters pick the source networks; leave source empty to trace one source"
    )
    for owner in ("source_node=meraki:1:d:BR", "source_org_ref=1&source_node_id=d:BR"):
        response = api.get(f"/api/topology/reachability?destination=10.0.10.20&{owner}")
        assert response.status_code == 400, owner
        assert response.json()["error"]["message"].startswith("source_node, source_org_ref and source_node_id")
    bad = api.get("/api/topology/reachability?source=nope&destination=10.0.10.20")
    assert bad.status_code == 400 and "is not an IP address or network" in bad.json()["error"]["message"]


def test_api_reachability_lists_the_networks_the_filters_keep(api):
    import csv
    import io
    import re
    import zipfile

    assert api.post("/api/sources/sample?provider=meraki").status_code == 201
    subnets = api.get("/api/sources/subnets").json()["subnets"]
    expected = {
        (s["cidr"], str(s.get("node_id") or ""))
        for s in subnets
        if s.get("provider") == "meraki" and s.get("kind") == "vlan" and "data" in str(s.get("name") or "").lower()
    }
    assert expected

    # The source, the to_* filters and the traffic are ignored: nothing is traced.
    query = "list=1&providers=meraki&kinds=vlan&name=data"
    response = api.get(f"/api/topology/reachability?{query}&source=10.9.9.9&to_providers=aws&protocol=tcp&port=1")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "list" and body["destination"] is None and body["source"] is None
    assert body["traffic"] == "" and body["to_filters"] is None and body["destination_count"] == 0
    assert body["candidates"] == body["source_count"] == len(body["rows"]) == len(expected)
    assert set(body["counts"].values()) == {0}
    assert {(r["cidr"], r["node_id"]) for r in body["rows"]} == expected
    assert all(r["provider"] == "meraki" and r["kind"] == "vlan" and "verdict" not in r for r in body["rows"])
    assert all(r["source_node"] and r["node_label"] for r in body["rows"])

    csv_response = api.get(f"/api/topology/reachability?{query}&format=csv&verdict=blocked")
    assert csv_response.status_code == 200
    n = len(body["rows"])
    assert csv_response.headers["content-disposition"] == f'attachment; filename="networks-{n}.csv"'
    table = list(csv.reader(io.StringIO(csv_response.text)))
    assert table[0] == ["Source", "Provider", "Site", "Network", "Kind", "VLAN", "CIDR", "In VPN"]
    assert len(table) == n + 1 and all(len(line) == 8 for line in table)

    book = api.get(f"/api/topology/reachability?{query}&format=xlsx")
    assert book.status_code == 200
    assert book.headers["content-disposition"] == f'attachment; filename="networks-{n}.xlsx"'
    with zipfile.ZipFile(io.BytesIO(book.content)) as archive:
        tabs = re.findall(r'<sheet name="([^"]+)"', archive.read("xl/workbook.xml").decode("utf-8"))
    assert tabs == ["Networks"]
    assert api.get("/api/topology/reachability?list=maybe").status_code == 400


def test_api_reachability_overlaps_filter_keeps_networks_over_the_range(api):
    assert api.post("/api/sources/sample?provider=meraki").status_code == 201
    subnets = api.get("/api/sources/subnets").json()["subnets"]
    vlan = next(s for s in subnets if s.get("provider") == "meraki" and s.get("kind") == "vlan")
    inside = vlan["cidr"].split("/")[0]  # an address of the VLAN: the VLAN contains it
    response = api.get(f"/api/topology/reachability?list=1&kinds=all&overlaps={inside}/32&within={inside}/32")
    assert response.status_code == 200, response.text
    # Within keeps networks inside the /32 only; the VLAN is wider, so nothing.
    assert response.json()["rows"] == []
    response = api.get(f"/api/topology/reachability?list=1&kinds=all&overlaps={inside}/32")
    body = response.json()
    assert body["filters"]["overlaps"] == [f"{inside}/32"]
    assert vlan["cidr"] in {r["cidr"] for r in body["rows"]}
    bad = api.get("/api/topology/reachability?list=1&overlaps=nope")
    assert bad.status_code == 400 and "overlaps: 'nope' is not an IP network" in bad.json()["error"]["message"]


def test_api_summarize_reports_routes_and_their_overlaps(api):
    import ipaddress

    assert api.post("/api/sources/sample?provider=meraki").status_code == 201
    subnets = api.get("/api/sources/subnets").json()["subnets"]
    vlan = next(s for s in subnets if s.get("provider") == "meraki" and s.get("kind") == "vlan")
    hosts = [str(h) for h in list(ipaddress.ip_network(vlan["cidr"]).hosts())[:3]]
    addresses = "\n".join([*hosts, hosts[0], "192.0.2.10"])

    response = api.post("/api/topology/summarize", json={"addresses": addresses, "prefix": 16, "kinds": "all"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["input_count"] == 5 and body["unique_count"] == 4 and body["uncovered"] == []
    assert body["prefix"] == 16 and body["max_routes"] is None and body["filters"]["kinds"][0] == "vlan"
    assert body["route_count"] == len(body["routes"]) == 2
    route = next(r for r in body["routes"] if r["input_count"] == 3)
    assert route["cidr"] == str(ipaddress.ip_network(f"{hosts[0]}/16", strict=False))
    assert route["inputs"] == sorted((f"{h}/32" for h in hosts), key=lambda c: ipaddress.ip_network(c))
    hit = next(o for o in route["overlaps"] if o["cidr"] == vlan["cidr"])
    assert hit["relation"] in ("inside", "equal") and hit["provider"] == "meraki" and hit["node_label"]
    assert body["text"].splitlines() == [r["cidr"] for r in body["routes"]]

    # The filters pick what is checked: no other source is loaded, so nothing overlaps.
    others = api.post(
        "/api/topology/summarize",
        json={"addresses": addresses, "max_routes": 1, "providers": "aws,azure,cato", "kinds": "all"},
    ).json()
    assert others["route_count"] == 1 and all(r["overlaps"] == [] for r in others["routes"])

    for payload, message in (
        ({"addresses": "10.0.0.1, nope"}, "'nope' is not an IP address or network"),
        ({"addresses": "10.0.0.1", "prefix": 33}, "prefix must be from 0 to 32"),
        ({"addresses": "10.0.0.1", "max_routes": 0}, "max_routes must be at least 1"),
        ({"addresses": "10.0.0.1", "kinds": "tunnel"}, "kinds: tunnel is not one of"),
        ({"addresses": " ".join(f"10.0.{i // 256}.{i % 256}" for i in range(5001))}, "at most 5000"),
    ):
        bad = api.post("/api/topology/summarize", json=payload)
        assert bad.status_code == 400, payload
        assert message in bad.json()["error"]["message"], payload


# ── Catalyst inventory hosts: configuration backups ──────────────────────────

_CORE_CONFIG = """\
hostname core-sw1
!
object-group network SERVERS
 10.20.0.0 255.255.255.0
!
object-group service WEB
 tcp eq 443
!
interface GigabitEthernet1/0/1
 description To dc-rtr1
 no switchport
 ip address 10.0.0.1 255.255.255.252
 ip access-group UPLINK-IN in
!
interface Vlan10
 description Users
 ip address 10.1.10.2 255.255.255.0
 ip access-group USERS-IN in
 standby 10 ip 10.1.10.1
!
ip route 0.0.0.0 0.0.0.0 10.0.0.2
!
ip access-list extended USERS-IN
 remark Web to the servers
 10 permit object-group WEB 10.1.10.0 0.0.0.255 object-group SERVERS
 20 deny   tcp any any eq telnet
 30 permit icmp any any
ip access-list extended UPLINK-IN
 10 permit tcp any 10.1.10.0 0.0.0.255 established
 20 permit icmp any any
 30 deny   ip any any
!
end
"""

_ROUTER_CONFIG = """\
hostname dc-rtr1
!
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.252
!
interface Vlan100
 description Servers
 ip address 10.20.0.1 255.255.255.0
!
ip route 10.1.0.0 255.255.0.0 10.0.0.1
!
end
"""

_ROUTER_CAPTURE = """\
Codes: L - local, C - connected, S - static
Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 5 subnets, 3 masks
C        10.0.0.0/30 is directly connected, GigabitEthernet0/0
L        10.0.0.2/32 is directly connected, GigabitEthernet0/0
S        10.1.0.0/16 [1/0] via 10.0.0.1
C        10.20.0.0/24 is directly connected, Vlan100
L        10.20.0.1/32 is directly connected, Vlan100
"""

_CATALYST_NODES = [
    {
        "id": 7,
        "label": "core-sw1",
        "ip": "10.0.0.1",
        "in_inventory": True,
        "device_type": "cisco_xe",
        "group_id": 3,
        "group_name": "HQ",
    },
    {
        "id": 8,
        "label": "dc-rtr1",
        "ip": "10.0.0.2",
        "in_inventory": True,
        "device_type": "cisco_ios",
        "group_id": 3,
        "group_name": "HQ",
    },
]


def _catalyst_hosts(router_backup: bool = True) -> tuple[Tracer, list[dict]]:
    """core-sw1 (VLAN 10 with HSRP and an inbound ACL, an uplink ACL that
    lets only established TCP in) linked to dc-rtr1, which holds the server
    VLAN. Every network of both is in the subnet index."""
    from netcontrol.integrations.pathtrace.inventory import subnets_for_host

    core = forwarding_for_host(
        {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}, [], None, [], config_backup={"config_text": _CORE_CONFIG}
    )
    router = forwarding_for_host(
        {"ip_address": "10.0.0.2", "device_type": "cisco_ios"},
        [],
        {"id": 1, "routes_text": _ROUTER_CAPTURE},
        [],
        config_backup={"config_text": _ROUTER_CONFIG} if router_backup else None,
    )
    subnets = [*subnets_for_host(_CATALYST_NODES[0], core), *subnets_for_host(_CATALYST_NODES[1], router)]
    lldp = {"id": "lldp:7:8", "from": 7, "to": 8, "protocol": "lldp", "status": "up"}
    tracer = _tracer({}, hosts={7: core, 8: router}, extra_nodes=_CATALYST_NODES, extra_edges=[lldp], subnets=subnets)
    return tracer, subnets


def test_catalyst_vlan_acl_decides_and_the_uplink_acl_lets_established_replies_in():
    from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF

    tracer, _subnets = _catalyst_hosts()
    source_node = tracer.graph_of[(INVENTORY_ORG_REF, "7")]
    assert source_node == 7 and tracer.ip_owner["10.1.10.1"] == [7]

    blocked = tracer.trace("10.1.10.0/24", "10.20.0.10", source_node=source_node, protocol="tcp", port=23)
    assert blocked["verdict"] == "blocked"
    [core] = blocked["request"]["hops"]
    assert core["provider"] == "inventory" and core["in"] == "Vlan10" and core["out"] == "GigabitEthernet1/0/1"
    acl = next(i for i in core["items"] if i["status"] == "blocked")
    assert acl["stage"] == "acl" and acl["where"] == "ACL USERS-IN in on Vlan10" and acl["rule"] == 20
    assert acl["text"] == "Rule 20 (deny tcp any → any 23, zones from Vlan10): denies it."
    # The uplink's ACL binds traffic coming in on the uplink, not this flow.
    assert not any(i["where"].startswith("ACL UPLINK-IN") for i in core["items"])

    allowed = tracer.trace("10.1.10.0/24", "10.20.0.10", source_node=source_node, protocol="tcp", port=443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert _labels(allowed["request"]) == ["core-sw1", "dc-rtr1"] and _labels(allowed["reply"]) == ["dc-rtr1", "core-sw1"]
    permit = next(i for i in allowed["request"]["hops"][0]["items"] if i["where"] == "ACL USERS-IN in on Vlan10")
    assert permit["status"] == "ok" and permit["rule"] == 10 and "Web to the servers" in permit["text"]
    assert allowed["request"]["hops"][1]["in"] == "GigabitEthernet0/0"
    # The replies come in on the uplink: the established entry lets them in.
    back = allowed["reply"]["hops"][1]
    assert back["in"] == "GigabitEthernet1/0/1" and back["out"] == "Vlan10"
    uplink = next(i for i in back["items"] if i["where"] == "ACL UPLINK-IN in on GigabitEthernet1/0/1")
    assert uplink["status"] == "ok" and uplink["rule"] == 10 and "established" in uplink["text"]
    assert allowed["asymmetric"]["status"] == "no"

    # A connection opened from the servers is no established reply: the uplink ACL denies it.
    opened = tracer.trace("10.20.0.10", "10.1.10.5", protocol="tcp", port=22)
    assert opened["verdict"] == "blocked"
    denied = next(i for i in opened["request"]["hops"][1]["items"] if i["status"] == "blocked")
    assert denied["where"] == "ACL UPLINK-IN in on GigabitEthernet1/0/1" and denied["rule"] == 30

    # The HSRP address answers on core-sw1.
    gateway = tracer.trace("10.20.0.10", "10.1.10.1", protocol="icmp")
    route = next(i for i in gateway["request"]["hops"][-1]["items"] if i["stage"] == "route")
    assert route["text"] == "10.1.10.1 is an address of this device (Vlan10 (HSRP 10.1.10.1))."


def test_catalyst_host_without_a_backup_leaves_the_flow_unknown_at_its_access_lists():
    tracer, _subnets = _catalyst_hosts(router_backup=False)
    result = tracer.trace("10.1.10.0/24", "10.20.0.10", source_node=7, protocol="tcp", port=443)
    assert result["verdict"] == "unknown"
    router = result["request"]["hops"][1]
    decided = next(i for i in router["items"] if i["status"] == "unknown")
    assert decided["where"] == "Access lists" and "not collected" in decided["text"]


def test_sweep_over_inventory_networks():
    from netcontrol.integrations.pathtrace import sweep

    tracer, subnets = _catalyst_hosts()
    meraki = {"org_ref": 1, "provider": "meraki", "cidr": "10.9.0.0/24", "node_id": "d:X", "kind": "vlan", "name": "x"}
    filters = sweep.parse_filters(providers="inventory")
    rows = sweep.select_rows([*subnets, meraki], filters, "10.20.0.10")
    assert {(r["cidr"], r["node_id"]) for r in rows} == {
        ("10.0.0.0/30", "7"),
        ("10.1.10.0/24", "7"),
        ("10.0.0.0/30", "8"),
    }
    assert sweep.select_rows([*subnets, meraki], sweep.parse_filters(sources="-4"), "10.20.0.10") == rows
    report = sweep.run(tracer, rows, "10.20.0.10", protocol="tcp", port=23)
    assert report["counts"]["blocked"] == 2 and report["counts"]["allowed"] == 1
    vlan = next(r for r in report["rows"] if r["cidr"] == "10.1.10.0/24")
    assert (vlan["provider"], vlan["org_ref"], vlan["source_node"], vlan["vlan"]) == ("inventory", -4, 7, 10)
    assert (vlan["site_name"], vlan["name"], vlan["node_label"]) == ("HQ", "VLAN 10 Users", "core-sw1")
    assert vlan["verdict"] == "blocked" and vlan["decided_at"] == "core-sw1"
    assert vlan["decided_by"].startswith("ACL USERS-IN in on Vlan10: Rule 20")


def test_api_lists_and_sweeps_an_inventory_hosts_vlans(api):
    import asyncio

    import routes.database as db
    from netcontrol.routes.topology import invalidate_topology_cache

    assert api.post("/api/sources/sample").status_code == 201
    capture = (
        "Codes: L - local, C - connected, S - static\n"
        "S*    0.0.0.0/0 [1/0] via 10.0.0.2\n"
        "C        10.0.0.0/30 is directly connected, GigabitEthernet1/0/1\n"
        "L        10.0.0.1/32 is directly connected, GigabitEthernet1/0/1\n"
        "C        10.1.10.0/24 is directly connected, Vlan10\n"
        "L        10.1.10.2/32 is directly connected, Vlan10\n"
    )

    async def seed() -> int:
        group_id = await db.create_group("HQ-inventory")
        host_id = await db.add_host(group_id, "core-sw1", "192.168.77.10", "cisco_xe")
        # The whole map holds the inventory hosts that have discovered links.
        await db.upsert_topology_link(
            host_id, "192.168.77.10", "GigabitEthernet1/0/1", None, "192.168.77.99", "dc-rtr1", "Gi0/0", "lldp"
        )
        await db.create_route_snapshot(host_id, 3, capture, "hash-1")
        await db.create_config_backup(None, host_id, _CORE_CONFIG)
        return host_id

    host_id = asyncio.run(seed())
    invalidate_topology_cache()

    subnets = api.get("/api/sources/subnets").json()["subnets"]
    vlan = next(s for s in subnets if s["cidr"] == "10.1.10.0/24" and s["org_ref"] == -4)
    assert vlan == {**vlan, "node_id": str(host_id), "provider": "inventory", "kind": "svi", "name": "VLAN 10 Users"}
    assert vlan["site_name"] == "HQ-inventory"

    query = "destination=10.20.0.10&protocol=tcp&port=23"
    swept = api.get(f"/api/topology/reachability?{query}&providers=inventory")
    assert swept.status_code == 200, swept.text
    rows = swept.json()["rows"]
    assert rows and all(r["provider"] == "inventory" and r["org_name"] == "Inventory" for r in rows)
    row = next(r for r in rows if r["cidr"] == "10.1.10.0/24")
    assert row["verdict"] == "blocked" and row["decided_by"].startswith("ACL USERS-IN in on Vlan10: Rule 20")
    assert row["source_node"] == host_id
    by_source = api.get(f"/api/topology/reachability?{query}&sources=-4").json()["rows"]
    assert [r["cidr"] for r in by_source] == [r["cidr"] for r in rows]

    found = api.get("/api/topology/search/deep?q=10.1.10.50").json()["results"]
    # The HTML export's subnet picker lists it too, owned by the exported host node.
    exported = _export_data(api.get("/api/topology/export.html?engine=0"))
    assert str(host_id) in {n["id"] for n in exported["nodes"]}
    assert any(s["cidr"] == "10.1.10.0/24" and s["node_id"] == str(host_id) for s in exported["subnets"])

    hit = next(r for r in found if r["org_ref"] == -4)
    assert hit["node_id"] == str(host_id) and hit["label"] == "core-sw1"
    assert hit["snippet"] == "HQ-inventory · Subnets: 10.1.10.0/24 VLAN 10 Users"
