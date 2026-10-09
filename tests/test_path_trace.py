"""Path tracing: a flow hop by hop across Meraki, FTD, Cato, inventory and
cloud devices, in both directions (``netcontrol.integrations.pathtrace``)."""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
from netcontrol.integrations.aws.reachability import Reachability
from netcontrol.integrations.cato.normalize import build_snapshot as build_cato_snapshot
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


def _with_partner(status: str) -> dict:
    snapshots = _branch_and_hub()
    snap = snapshots[1]
    branch = snap["nodes"][0]["forwarding"]
    branch["routes"].append(
        route("172.31.0.0/16", "vpn3p", peer={"org_node": "p:Partner"}, source="Non-Meraki VPN peer Partner")
    )
    snap["sites"].append({"id": "__vpn_peers__", "name": "Non-Meraki VPN peers"})
    snap["nodes"].append(
        _node("p:Partner", "vpn_peer", "__vpn_peers__", "Partner", peer_block("Partner", ["172.31.0.0/16"]))
    )
    snap["edges"].append(_edge("e2", "d:BR", "p:Partner", kind="vpn3p", status=status))
    return snapshots


def test_a_non_meraki_peer_behind_a_tunnel_that_is_down_is_blocked_at_the_link():
    tracer = _tracer(_with_partner("unreachable"), subnets=_SUBNETS)
    result = tracer.trace("10.1.10.5", "172.31.4.4", destination_node="meraki:1:p:Partner")

    assert result["verdict"] == "blocked"
    last = result["request"]["hops"][-1]
    assert last["label"] == "Branch 01 MX" and _items(last)[-1] == ("link", "blocked", "Link to Partner")
    assert "is down (unreachable)" in last["items"][-1]["text"]

    # Up, the flow reaches the peer, but nothing behind it is known.
    up = _tracer(_with_partner("reachable"), subnets=_SUBNETS).trace(
        "10.1.10.5", "172.31.4.4", destination_node="meraki:1:p:Partner"
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


def _ftd_tracer() -> Tracer:
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
    # The host's access lists are not collected: a note, named in the summary.
    assert ("note", "info", "Access lists") in _items(host, info=True)
    assert result["request"]["summary"].endswith("Not checked: Access lists.")
    # The host is on the FTD's inside subnet: it answers the source directly.
    assert _labels(result["reply"]) == ["core-sw"]
    assert result["asymmetric"] == {
        "status": "yes",
        "text": "Replies from 10.70.1.5 end at core-sw and never pass ftd-branch, which the request did. ftd-branch "
        "has a stateful firewall that sees the request but never the replies: its connection state never "
        "completes, so the rest of the connection can be dropped there.",
    }


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
    return Tracer(graph, {1: meraki, -1: aws}, {-1: Reachability(rows or _aws_rows(), [])}, {}, [])


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
        "Branch-Cleveland",
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
        "172.31.0.5",
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
    assert _labels(request) == ["Branch-Cleveland", "PoP New York", "Cato Cloud", "Internet"]
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


_CLEVELAND_TO_HQ = {"source_node": "meraki:3:d:5003", "destination_node": "meraki:3:d:5001"}
_HTTPS = {"protocol": "tcp", "port": 443}


def test_cato_site_with_a_bgp_peer_makes_a_default_route_lookup_unknown():
    raw = build_cato_sample_raw()
    raw["bgp_peers"] = [{"id": "b-1", "name": "Core router", "site": {"id": "1002"}, "peerIp": "10.60.20.2"}]
    result = _cato_tracer(raw).trace("10.60.20.5", "10.50.10.20", **_CLEVELAND_TO_HQ, **_HTTPS)

    request = result["request"]
    # The rest of the trace proceeds: only the branch's lookup is in doubt.
    assert _labels(request) == [
        "Branch-Cleveland",
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
    assert unknown == [("Branch-Cleveland", "route")]
    assert result["verdict"] == "unknown"
    assert request["summary"].startswith("Could not be decided at Branch-Cleveland, Cato tunnel to PoP New York")
    # On the reply the branch's connected range answers: the note is only information.
    last = result["reply"]["hops"][-1]
    assert ("note", "info", "Routes learned by BGP") in _items(last, info=True)


def test_cato_ranges_not_collected_make_the_pops_lookup_unknown():
    raw = build_cato_sample_raw()
    raw["ranges"] = []
    raw["errors"] = [{"scope": "account", "path": "entityLookup siteRange", "status": 403, "message": "Denied"}]
    result = _cato_tracer(raw).trace("10.60.20.5", "10.50.10.20", **_CLEVELAND_TO_HQ, **_HTTPS)

    hops = {h["label"]: h for h in result["request"]["hops"]}
    lookup = _route_item(hops["PoP New York"])
    assert (lookup["status"], lookup["where"]) == ("unknown", "Cato backbone")
    assert lookup["text"].endswith(
        "Only the default route matches 10.50.10.20; route table (site network ranges) is not collected, "
        "so a more specific route may exist."
    )
    assert result["verdict"] == "unknown"


def _ipsec_trace(snapshot: dict) -> dict:
    """Branch-Cleveland to the AWS VPC behind the IPsec site, on HTTPS."""
    return _tracer({3: snapshot}).trace(
        "10.60.20.5", "172.31.0.5", source_node="meraki:3:d:5003", destination_node="meraki:3:s:1004", **_HTTPS
    )


def _ipsec_edges(snapshot: dict) -> list[dict]:
    return [e for e in snapshot["edges"] if e["a"] == "s:1004"]


def test_cato_ipsec_site_is_reached_over_its_primary_tunnel():
    result = _ipsec_trace(build_cato_snapshot(build_cato_sample_raw()))

    request = result["request"]
    assert _labels(request) == ["Branch-Cleveland", "PoP New York", "Cato Cloud", "PoP Ashburn", "AWS-us-east-1"]
    ashburn = request["hops"][3]
    assert _link_item(ashburn)["text"] == "IPsec tunnel, reachable."
    # Rule 2 allows Cleveland to the HQ servers only; rule 4 allows the rest.
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
    assert _labels(request) == ["Branch-Cleveland", "PoP New York", "Cato Cloud", "PoP Ashburn"]
    link = _link_item(request["hops"][-1])
    assert (link["status"], link["text"]) == (
        "blocked",
        "Every link between PoP Ashburn and AWS-us-east-1 is down (unreachable).",
    )
    assert result["verdict"] == "blocked"
    assert request["summary"] == (
        "Blocked at PoP Ashburn, Link to AWS-us-east-1: "
        "Every link between PoP Ashburn and AWS-us-east-1 is down (unreachable)."
    )


_DANA = {"source_node": "meraki:3:cato:user:9001"}


def test_cato_remote_user_to_a_site_meets_the_wan_firewall_at_the_users_pop():
    result = _cato_tracer().trace("10.41.0.11", "10.50.10.20", **_DANA, **_HTTPS)

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
    result = _cato_tracer().trace("10.41.0.11", "8.8.8.8", **_DANA, **_HTTPS)

    request = result["request"]
    assert _labels(request) == ["Dana Reyes", "PoP New York", "Cato Cloud", "Internet"]
    [(status, name, text)] = _policies(request["hops"][1])
    assert (status, name) == ("unknown", "Internet firewall rules") and text.startswith("Rule 1 Block malware")
    assert _policies(request["hops"][2]) == [("info", "Internet firewall rules", "Already applied at PoP New York.")]
    assert _route_item(request["hops"][2])["where"] == "Cato internet egress"


def test_cato_remote_user_to_a_site_on_the_same_pop_skips_the_backbone():
    result = _cato_tracer().trace("10.41.0.11", "10.60.20.5", **_DANA, **_HTTPS)

    assert _labels(result["request"]) == ["Dana Reyes", "PoP New York", "Branch-Cleveland"]
    [(status, _name, text)] = _policies(result["request"]["hops"][1])
    assert status == "ok" and text.startswith("Rule 4 Any to any")
    assert result["verdict"] == "allowed"
    assert _labels(result["reply"]) == ["Branch-Cleveland", "PoP New York", "Dana Reyes"]


def test_cato_site_to_site_replies_take_the_same_hops_back():
    result = _cato_tracer().trace("10.60.20.5", "10.50.10.20", **_CLEVELAND_TO_HQ, **_HTTPS)

    assert result["verdict"] == "allowed"
    assert result["asymmetric"] == {"status": "no", "text": "Replies take the same hops back."}
    assert _labels(result["reply"]) == list(reversed(_labels(result["request"])))


def test_cato_cloud_routing_a_range_back_to_the_ingress_pop_is_a_routing_loop():
    snapshot = build_cato_snapshot(build_cato_sample_raw())
    cloud = next(n for n in snapshot["nodes"] if n["id"] == "cato:cloud")
    for entry in cloud["forwarding"]["routes"]:
        if entry["prefix"] == "10.50.10.0/24":
            entry["peer"] = {"org_node": "pop:New York"}
    result = _tracer({3: snapshot}).trace("10.60.20.5", "10.50.10.20", **_CLEVELAND_TO_HQ, **_HTTPS)

    # PoP New York sends HQ's range over the backbone, which sends it back.
    request = result["request"]
    assert _labels(request) == ["Branch-Cleveland", "PoP New York", "Cato Cloud"]
    assert request["hops"][-1]["items"][-1]["where"] == "Routing loop"
    assert result["verdict"] == "blocked"
    assert result["asymmetric"]["status"] == "unknown"


def test_cato_socket_sending_by_one_pop_and_answered_by_another_is_asymmetric():
    # Branch-Cleveland's second WAN link is on PoP Ashburn, so HQ's PoP answers it directly,
    # while the Socket sends by PoP New York.
    raw = build_cato_sample_raw()
    branch = next(s for s in raw["sites"] if s["id"] == "1002")
    branch["devices"][0]["interfaces"][1].update(
        {"connected": True, "popName": "Ashburn", "tunnelRemoteIP": "203.0.113.30"}
    )
    snapshot = build_cato_snapshot(raw)
    socket = next(n for n in snapshot["nodes"] if n["id"] == "d:5003")
    socket["forwarding"]["routes"][-1]["peer"] = {"org_node": "pop:New York"}
    result = _tracer({3: snapshot}).trace("10.60.20.5", "10.50.10.20", **_CLEVELAND_TO_HQ, **_HTTPS)

    assert result["verdict"] == "allowed"
    assert _labels(result["request"]) == [
        "Branch-Cleveland",
        "PoP New York",
        "Cato Cloud",
        "PoP Ashburn",
        "HQ-DataCenter (primary)",
    ]
    assert _labels(result["reply"]) == ["HQ-DataCenter (primary)", "PoP Ashburn", "Branch-Cleveland"]
    # The account's firewall keeps one state table: PoP Ashburn, on the replies'
    # path, sees the connection, so there is no stateful warning for the PoP and
    # the Cloud the replies skip.
    assert result["asymmetric"] == {
        "status": "yes",
        "text": "Replies from 10.50.10.20 go from PoP Ashburn to Branch-Cleveland instead of Cato Cloud, the way the "
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
    assert "Hub 02 MX has a stateful firewall that never saw the request: it would drop the replies" in asymmetric["text"]
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
    assert loop["verdict"] == "blocked" and _labels(loop["request"]) == ["Router A", "Router B"]
    assert loop["request"]["hops"][-1]["items"][-1]["where"] == "Routing loop"

    nothing = tracer.trace("10.0.1.50", "10.99.0.1", source_node="meraki:1:d:A")
    assert (
        nothing["verdict"] == "blocked"
        and nothing["summary"] == "Blocked at Router A, Route table: No route to 10.99.0.1."
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
        assert api.post(f"/api/meraki/sample?provider={provider}").status_code == 201

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
