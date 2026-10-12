"""Port sets of a path trace: which ports of which protocol a rule set lets
through (``netcontrol.integrations.pathtrace.ports``)."""

from __future__ import annotations

import pytest
from netcontrol.integrations.meraki.forwarding import interface, new_block, policy_set, route, rule
from netcontrol.integrations.meraki.unified import merge_meraki_into_graph
from netcontrol.integrations.pathtrace.engine import Tracer
from netcontrol.integrations.pathtrace.ports import (
    BLOCKED,
    FULL,
    NONE,
    OK,
    PART,
    PARTIAL,
    UNKNOWN,
    Asked,
    Match,
    allow_list,
    combine,
    first_match,
    from_json,
    status_of,
    to_json,
    uniform,
)

ANY = Asked("")
TCP = Asked("tcp")


def _m(protocol: str, ports, action: str, cover: int = FULL, **kw) -> Match:
    return Match(cover=cover, protocol=protocol, ports=ports, action=action, **kw)


# ── Rendering ────────────────────────────────────────────────────────────────


def test_uniform_sets_render_any_and_none():
    assert to_json(uniform(OK, ANY)) == {
        "allowed": {"tcp": "any", "udp": "any", "icmp": "any"},
        "partial": {},
        "unknown": {},
        "text": "allowed tcp any · udp any · icmp",
    }
    unknown = to_json(uniform(UNKNOWN, ANY))
    assert unknown["allowed"] == {} and unknown["text"] == "allowed none; not decided tcp any · udp any · icmp"
    assert to_json(uniform(BLOCKED, ANY)) == {"allowed": {}, "partial": {}, "unknown": {}, "text": "allowed none"}


def test_port_lists_are_sorted_and_merged():
    rules = [_m("tcp", "8000-8080", "allow"), _m("tcp", "443, 80", "allow"), _m("tcp", "81-90,91", "allow")]
    found = to_json(first_match(rules, ANY, "deny"))
    assert found["allowed"] == {"tcp": "80-91, 443, 8000-8080"}
    assert found["text"] == "allowed tcp 80-91, 443, 8000-8080"
    # A list that covers every port but 0 is any.
    assert to_json(first_match([_m("udp", "1-65535", "allow")], ANY, "deny"))["allowed"] == {"udp": "any"}


def test_a_single_asked_port_renders_as_that_port():
    asked = Asked("tcp", (443, 443))
    assert to_json(first_match([_m("tcp", "80,443", "allow")], asked, "deny"))["allowed"] == {"tcp": "443"}
    assert to_json(first_match([_m("tcp", "80", "allow")], asked, "deny"))["text"] == "allowed none"


# ── Ordered rule sets ────────────────────────────────────────────────────────


def test_first_match_decides_each_port_by_the_first_rule_that_covers_it():
    rules = [
        _m("tcp", "22", "deny"),
        _m("tcp", "1-1023", "allow"),
        _m("udp", "53", "allow"),
        _m("icmp", "any", "deny"),
    ]
    found = first_match(rules, ANY, "deny")
    assert status_of(found, "tcp", 22) == BLOCKED and status_of(found, "tcp", 80) == OK
    assert status_of(found, "tcp", 1024) == BLOCKED and status_of(found, "udp", 53) == OK
    assert status_of(found, "icmp") == BLOCKED
    assert to_json(found)["text"] == "allowed tcp 1-21, 23-1023 · udp 53"


def test_monitor_rules_log_and_let_later_rules_decide():
    found = first_match([_m("any", None, "monitor"), _m("tcp", "443", "allow")], TCP, "deny")
    assert to_json(found)["allowed"] == {"tcp": "443"}


def test_an_unresolved_rule_makes_only_its_own_ports_unknown():
    rules = [_m("tcp", "8080", "allow", unresolved=True), _m("tcp", "1-9000", "allow")]
    found = to_json(first_match(rules, TCP, "deny"))
    assert found["unknown"] == {"tcp": "8080"}
    assert found["allowed"] == {"tcp": "1-8079, 8081-9000"}
    assert found["text"] == "allowed tcp 1-8079, 8081-9000; not decided tcp 8080"


def test_an_action_plexus_cannot_evaluate_is_unknown():
    assert to_json(first_match([_m("tcp", "443", "prompt")], TCP, "deny"))["unknown"] == {"tcp": "443"}


def test_a_rule_covering_part_of_the_addresses_makes_the_other_way_partial():
    rules = [_m("tcp", "80", "allow", cover=PART), _m("any", None, "deny")]
    found = to_json(first_match(rules, ANY, "allow"))
    assert found == {
        "allowed": {},
        "partial": {"tcp": "80"},
        "unknown": {},
        "text": "allowed none; in part tcp 80",
    }
    # The same way as what decides changes nothing.
    same = [_m("tcp", "80", "deny", cover=PART), _m("tcp", None, "deny")]
    assert to_json(first_match(same, TCP, "allow"))["partial"] == {}


def test_the_default_action_decides_what_no_rule_covers():
    rules = [_m("tcp", "22", "deny")]
    assert to_json(first_match(rules, TCP, "allow"))["allowed"] == {"tcp": "0-21, 23-65535"}
    assert to_json(first_match(rules, TCP, "unknown"))["unknown"] == {"tcp": "0-21, 23-65535"}
    cut = to_json(first_match([_m("tcp", "443", "allow")], ANY, "deny", complete=False))
    assert cut["allowed"] == {"tcp": "443"}
    assert cut["unknown"] == {"tcp": "0-442, 444-65535", "udp": "any", "icmp": "any"}


def test_ports_and_protocols_the_rule_cannot_be_read_on():
    # A service name: every port, covered in part.
    found = first_match([_m("tcp", "https", "allow"), _m("any", None, "deny")], TCP, "allow")
    assert to_json(found)["partial"] == {"tcp": "any"}
    # ICMP has no ports; numbered protocols are read.
    found = first_match([_m("1", "443", "allow"), _m("6", "22", "allow")], ANY, "deny")
    assert to_json(found)["allowed"] == {"tcp": "22", "icmp": "any"}


def test_the_other_side_ports_narrow_the_cover():
    asked = Asked("tcp", None, (1024, 65535))
    rules = [_m("tcp", "443", "allow", other_ports="1024-65535"), _m("tcp", "80", "allow", other_ports="53")]
    assert to_json(first_match(rules, asked, "deny"))["allowed"] == {"tcp": "443"}
    partly = first_match([_m("tcp", "80", "allow", other_ports="2000-3000"), _m("any", None, "deny")], asked, "deny")
    assert to_json(partly)["partial"] == {"tcp": "80"}


# ── Allow lists, combining ───────────────────────────────────────────────────


def test_allow_list_is_a_union_of_allows():
    rules = [
        _m("tcp", (443, 443), "allow"),
        _m("tcp", (22, None), "allow", cover=PART),
        _m("udp", (None, None), "allow"),
    ]
    found = to_json(allow_list(rules, ANY))
    assert found["allowed"] == {"tcp": "443", "udp": "any"}
    assert found["partial"] == {"tcp": "22"}
    assert found["unknown"] == {}
    missing = to_json(allow_list([_m("tcp", (443, 443), "allow", cover=NONE)], TCP, missing=True))
    assert missing["unknown"] == {"tcp": "any"} and missing["allowed"] == {}


def test_combine_keeps_the_worst_status_of_each_port():
    allow_web = first_match([_m("tcp", "80,443", "allow")], TCP, "deny")
    some_unknown = first_match([_m("tcp", "443", "allow"), _m("tcp", "80", "prompt")], TCP, "allow")
    found = to_json(combine(allow_web, some_unknown))
    assert found["allowed"] == {"tcp": "443"} and found["unknown"] == {"tcp": "80"}
    assert to_json(combine(uniform(PARTIAL, ANY), uniform(OK, ANY)))["partial"] == {
        "tcp": "any",
        "udp": "any",
        "icmp": "any",
    }


def test_json_reads_back_over_the_ports_asked():
    found = first_match([_m("tcp", "22", "deny"), _m("tcp", "1-1023", "allow")], ANY, "unknown")
    assert to_json(from_json(to_json(found), ANY)) == to_json(found)
    # One port asked about: a NAT may have changed the port a later rule set saw.
    asked = Asked("tcp", (8080, 8080))
    translated = to_json(first_match([_m("tcp", "80", "allow")], Asked("tcp", (80, 80)), "deny"))
    assert status_of(from_json(translated, asked), "tcp", 8080) == OK


# ── Agreement with the tracer ────────────────────────────────────────────────


def _tracer(l3: list[dict], *, default: str = "allow", complete: bool = True) -> Tracer:
    block = new_block()
    for name, ip, cidr in (("VLAN 10", "10.1.10.1", "10.1.10.0/24"), ("VLAN 20", "10.1.20.1", "10.1.20.0/24")):
        block["interfaces"].append(interface(name, "vlan", ip=ip, cidr=cidr))
        block["routes"].append(route(cidr, "connected", interface=name, source=f"Connected {name}"))
    block["policies"] = [
        policy_set("Layer 3 firewall rules", "firewall", "lan_in", l3, default=default, complete=complete)
    ]
    node = {
        "id": "d:MX",
        "kind": "appliance",
        "site": "S",
        "label": "Branch MX",
        "status": "online",
        "x": 0.0,
        "y": 0.0,
        "sections": [],
        "forwarding": block,
    }
    snapshots = {
        1: {
            "org": {"name": "Acme"},
            "provider": "meraki",
            "sites": [{"id": "S", "name": "Branch"}],
            "nodes": [node],
            "edges": [],
        }
    }
    nodes: dict = {}
    edges: list = []
    merge_meraki_into_graph(
        nodes, edges, list(snapshots.items()), host_node=lambda _id: None, resolve_external=lambda _n, _i: None
    )
    subnets = [{"org_ref": 1, "node_id": "d:MX", "cidr": c} for c in ("10.1.10.0/24", "10.1.20.0/24")]
    return Tracer({"nodes": list(nodes.values()), "edges": edges}, snapshots, {}, {}, subnets)


def _l3(result: dict) -> dict:
    """The item that carries the rule set's decision (after any monitor rule's)."""
    found = [i for i in result["request"]["hops"][0]["items"] if i["where"] == "Layer 3 firewall rules"]
    assert all("ports" not in i for i in found[:-1])
    return found[-1]


_RULE_SETS = {
    "web and no ssh": (
        [
            rule(1, "deny", protocol="tcp", dst=["10.0.0.0/8"], dst_ports="22"),
            rule(2, "allow", protocol="tcp", dst_ports="80,443"),
            rule(3, "deny", protocol="udp"),
            rule(4, "allow", comment="Default rule"),
        ],
        "allow",
        True,
    ),
    "part of the source": (
        [
            rule(1, "allow", protocol="tcp", src=["10.1.10.0/25"], dst_ports="443"),
            rule(2, "deny", protocol="tcp", src=["10.1.10.128/25"], dst_ports="1000-2000"),
            rule(3, "allow", protocol="tcp", dst_ports="1-1023"),
            rule(4, "allow", protocol="icmp", src=["10.1.10.0/25"]),
        ],
        "deny",
        True,
    ),
    "unresolved, monitor and cut": (
        [
            rule(1, "monitor"),
            rule(2, "allow", protocol="tcp", dst_ports="8080", unresolved=["application HTTP"]),
            rule(3, "deny", protocol="tcp", dst_ports="1-1023", src_ports="1024-65535"),
            rule(4, "allow", protocol="udp", dst_ports="53", src_ports="53"),
        ],
        "deny",
        False,
    ),
}


@pytest.mark.parametrize("name", list(_RULE_SETS))
@pytest.mark.parametrize("source", ["10.1.10.5", "10.1.10.0/24"])
def test_each_port_of_the_set_agrees_with_tracing_that_port_alone(name, source):
    rules, default, complete = _RULE_SETS[name]
    tracer = _tracer(rules, default=default, complete=complete)
    found = from_json(_l3(tracer.trace(source, "10.1.20.7"))["ports"], ANY)
    for protocol, port in [
        *((p, n) for p in ("tcp", "udp") for n in (22, 53, 80, 443, 1500, 3000, 8080)),
        ("icmp", None),
    ]:
        alone = _l3(tracer.trace(source, "10.1.20.7", protocol=protocol, port=port))
        assert alone["status"] == status_of(found, protocol, port), (protocol, port, alone["text"])
        # The single-port item carries its own set, which agrees too.
        assert (
            status_of(from_json(alone["ports"], Asked(protocol, (port, port) if port else None)), protocol, port)
            == (alone["status"])
        )
