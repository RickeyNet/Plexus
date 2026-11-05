"""Cato Network Rules: which INTERNET rule routes a flow and the address it
leaves Cato with (``netcontrol.integrations.cato.network_rules``), built
from the bundled sample account."""

from __future__ import annotations

from netcontrol.integrations.cato import network_rules
from netcontrol.integrations.cato.normalize import network_rule_policy
from netcontrol.integrations.cato.sample import _endpoint, _ref, build_sample_raw, network_rule
from netcontrol.integrations.pathtrace.model import net

_MADISON_HOST = "10.60.20.5"  # Branch-Madison's Users range
_DANA = "10.88.0.11"  # a remote user on PoP New York
_SQL = "203.0.113.60"  # the AWS sample's public SQL server


def _evaluate(raw: dict, src: str, dst: str = _SQL, protocol: str = "tcp", port: int | None = 1433) -> dict:
    ports = (port, port) if port is not None else None
    return network_rules.evaluate(network_rule_policy(raw), net(src), net(dst), protocol, ports)  # type: ignore[arg-type]


def _trace(raw: dict, src: str, dst: str = _SQL) -> dict:
    policy = network_rule_policy(raw)
    return network_rules.trace_egress(policy, net(src), net(dst), "tcp", (1433, 1433))  # type: ignore[arg-type]


def _rules(raw: dict) -> list[dict]:
    return raw["wan_network"]["rules"]


def test_the_compiled_policy_keeps_the_internet_rules_in_order():
    policy = network_rule_policy(build_sample_raw())
    assert policy["kind"] == network_rules.KIND and policy["collected"] is True
    assert [(r["index"], r["name"]) for r in policy["rules"]] == [
        (2, "Geoblocked apps egress"),
        (3, "Madison to the SQL server by address"),
        (4, "Internet Traffic - Predefined"),
    ]
    by_index = {r["index"]: r for r in policy["rules"]}
    # Sources resolve through the address book the firewall rules use.
    assert by_index[3]["src"] == ["10.60.20.0/24"] and by_index[3]["dst"] == ["203.0.113.60/32"]
    # The allocated IPs come from the collected list, with their PoP.
    assert by_index[2]["egress"]["addresses"] == [
        {"ip": "192.0.2.101", "label": "NAT IP Ashburn - 192.0.2.101", "pop": "Ashburn", "from": "allocated IP list"},
        {"ip": "192.0.2.102", "label": "NAT IP New York - 192.0.2.102", "pop": "New York", "from": "allocated IP list"},
    ]
    kinds = [(c["kind"], c["text"]) for c in by_index[2]["app"]]
    assert ("name", "custom application Payroll portal (FQDN payroll.example.com)") in kinds
    assert ("name", "custom category Geoblocked Apps (its contents are not collected)") in kinds
    assert ("name", "domain sql.example.com") in kinds


def test_an_address_rule_matches_and_a_name_only_rule_ahead_is_a_caveat():
    found = _evaluate(build_sample_raw(), _MADISON_HOST)
    assert found["state"] == "matched" and found["rule"]["index"] == 3
    [candidate] = found["candidates"]
    assert (candidate["rule"]["index"], candidate["why"]) == (2, "name")
    assert "custom category Geoblocked Apps (its contents are not collected)" in candidate["detail"]

    traced = _trace(build_sample_raw(), _MADISON_HOST)
    assert traced["addresses"] == ["192.0.2.101"] and traced["unknown"] == ""
    statuses = [(stage, status, index) for stage, status, _where, _text, index in traced["items"]]
    assert statuses == [("route", "info", 2), ("route", "ok", 3), ("nat", "ok", 3)]
    caveat = traced["items"][0][3]
    assert "matches only if Cato identifies the traffic by name" in caveat
    assert f"A connection made to the bare IP {_SQL} falls to Rule 3 Madison to the SQL server by address" in caveat
    assert traced["items"][2][3] == "Source 10.60.20.5 becomes 192.0.2.101 (NAT IP Ashburn - 192.0.2.101, PoP Ashburn)."


def test_a_bare_ip_falls_to_the_predefined_rule_and_its_shared_address():
    found = _evaluate(build_sample_raw(), _DANA)
    assert found["state"] == "matched" and found["rule"]["index"] == 4
    assert [(c["rule"]["index"], c["why"]) for c in found["candidates"]] == [(2, "name")]
    traced = _trace(build_sample_raw(), _DANA)
    assert traced["addresses"] == []
    assert traced["unknown"] == "The flow leaves Cato from the shared address of its PoP, which Cato does not report"
    rule_item = traced["items"][1]
    assert rule_item[:3] == ("route", "ok", "Network rules")
    assert rule_item[3].startswith("Rule 4 Internet Traffic - Predefined routes it: no special routing")
    assert traced["items"][2][:2] == ("nat", "info")


def test_disabled_rules_are_skipped():
    raw = build_sample_raw()
    _rules(raw)[2]["enabled"] = False  # rule 3
    assert _evaluate(raw, _MADISON_HOST)["rule"]["index"] == 4


def test_an_exception_excludes_the_flow_by_address_or_only_by_name():
    raw = build_sample_raw()
    _rules(raw)[2]["exceptions"] = [
        {"name": "Not the SQL port", "source": _endpoint(), "destination": _endpoint(ip=[_SQL]), "application": {}}
    ]
    found = _evaluate(raw, _MADISON_HOST)
    assert found["rule"]["index"] == 4
    assert [(s["rule"]["index"], s["exception"]) for s in found["skipped"]] == [(3, "Not the SQL port")]
    texts = [text for _stage, _status, _where, text, _index in _trace(raw, _MADISON_HOST)["items"]]
    assert any("its exception Not the SQL port excludes this flow" in t for t in texts)

    # An exception by domain cannot exclude a connection made to the bare IP.
    _rules(raw)[2]["exceptions"] = [
        {
            "name": "Not the portal",
            "source": _endpoint(),
            "destination": _endpoint(),
            "application": {"fqdn": ["x.example.com"]},
        }
    ]
    found = _evaluate(raw, _MADISON_HOST)
    assert found["rule"]["index"] == 3
    assert found["caveats"] == [{"exception": "Not the portal", "detail": ["FQDN x.example.com"]}]


def test_routes_other_than_nat_leave_from_an_unreported_address():
    cases = {
        "VIA": ("egress via PoP Ashburn", "ok", "shared address of PoP Ashburn"),
        "OPTIMIZED": ("optimized egress", "ok", "PoP nearest the destination"),
        "BACKHAUL": ("backhauled to HQ-DataCenter", "unknown", "through HQ-DataCenter"),
        "NONE": ("no special routing", "ok", "shared address of its PoP"),
    }
    for route, (what, status, why) in cases.items():
        raw = build_sample_raw()
        rule = network_rule(
            3,
            "Routed",
            route,
            source=_endpoint(site=[_ref("1002", "Branch-Madison")]),
            pops=[_ref("pl-1", "Ashburn")],
            sites=[_ref("1001", "HQ-DataCenter")],
        )
        _rules(raw)[2] = rule
        traced = _trace(raw, _MADISON_HOST)
        rule_item = next(i for i in traced["items"] if i[4] == 3 and i[0] == "route")
        assert what in rule_item[3] and rule_item[1] == status, route
        assert traced["addresses"] == [] and why in traced["unknown"], route


def test_an_allocated_ip_is_read_from_its_name_when_the_list_is_not_collected():
    raw = build_sample_raw()
    raw["allocated_ips"] = None
    _rules(raw)[2]["configuration"]["allocationIp"].append(_ref("aip-9", "NAT IP Denver - 192.0.2.109"))
    _rules(raw)[2]["configuration"]["allocationIp"].append(_ref("aip-x", "Spare"))
    egress = network_rule_policy(raw)["rules"][1]["egress"]
    assert [(a["ip"], a["from"]) for a in egress["addresses"]] == [
        ("192.0.2.101", "its name"),
        ("192.0.2.109", "its name"),
    ]
    assert egress["unresolved"] == ["Spare"]
    traced = _trace(raw, _MADISON_HOST)
    assert traced["addresses"] == ["192.0.2.101", "192.0.2.109"]
    assert "which one Cato uses is not reported" in traced["items"][-1][3]


def test_a_rule_that_names_objects_plexus_cannot_resolve_may_apply():
    raw = build_sample_raw()
    # All Staff: its members were not read.
    _rules(raw)[1]["source"] = _endpoint(usersGroup=[_ref("ug-4", "All Staff")])
    _rules(raw)[1]["application"] = {}
    found = _evaluate(raw, _DANA)
    assert [(c["rule"]["index"], c["why"]) for c in found["candidates"]] == [(2, "unknown")]
    assert found["candidates"][0]["detail"] == ["users group All Staff"]
    first = _trace(raw, _DANA)["items"][0]
    assert first[1] == "unknown" and first[3].startswith("Rule 2 Geoblocked apps egress may apply")


def test_address_criteria_of_the_application_field_match_on_the_ip():
    raw = build_sample_raw()
    # A custom application defined by destination IP and port.
    raw["custom_applications"][0]["criteria"] = [
        {"protocol": "TCP", "port": [1433], "portRange": [], "destination": {"destinationIp": {"ip": [_SQL]}}}
    ]
    rule = _rules(raw)[1]
    rule["application"] = {"customApp": [_ref("ca-1", "Payroll portal")]}
    assert _evaluate(raw, _DANA)["rule"]["index"] == 2
    # Another port: the custom application does not match, and nothing names the flow.
    assert _evaluate(raw, _DANA, port=443)["rule"]["index"] == 4
    # A global IP range in the application field is an address too.
    rule["application"] = {"globalIpRange": [_ref("gr-3", "Corp-Networks")]}
    assert _evaluate(raw, _DANA, dst="10.9.9.9")["rule"]["index"] == 2
    assert _evaluate(raw, _DANA)["rule"]["index"] == 4
    # A custom application whose definition was not collected may apply.
    raw["custom_applications"] = None
    rule["application"] = {"customApp": [_ref("ca-1", "Payroll portal")]}
    found = _evaluate(raw, _DANA)
    assert [(c["rule"]["index"], c["why"]) for c in found["candidates"]] == [(2, "unknown")]


def test_network_rules_not_collected_reduced_or_disabled_are_unknown():
    raw = build_sample_raw()
    raw["wan_network"] = None
    assert network_rule_policy(raw) == network_rules.not_collected()
    traced = _trace(raw, _MADISON_HOST)
    assert traced["addresses"] == [] and "not collected" in traced["unknown"]
    assert traced["items"][0][:3] == ("route", "unknown", "Network rules")

    raw = build_sample_raw()
    raw["wan_network"]["reduced"] = True
    assert _evaluate(raw, _MADISON_HOST)["state"] == "reduced"
    raw["wan_network"]["reduced"] = False
    raw["wan_network"]["enabled"] = False
    assert _evaluate(raw, _MADISON_HOST)["state"] == "disabled"
    assert _trace(raw, _MADISON_HOST)["items"][0][1] == "unknown"


def test_no_rule_matching_is_the_connected_pops_shared_address():
    raw = build_sample_raw()
    del _rules(raw)[3]  # the predefined rule
    found = _evaluate(raw, _DANA)
    assert found["state"] == "default" and found["rule"] is None
    traced = _trace(raw, _DANA)
    assert any(t.startswith("No internet network rule matches") for _s, _st, _w, t, _i in traced["items"])
    assert "shared address of its PoP" in traced["unknown"]
