"""Summarize addresses: parsing, the roll-up and merge, and each route's report."""

from __future__ import annotations

import ipaddress

import pytest
from netcontrol.integrations.pathtrace.summarize import (
    overlapping_rows,
    parse_addresses,
    relation,
    routes,
    routes_text,
    summarize,
)


def _nets(*texts: str) -> list:
    return [ipaddress.ip_network(text) for text in texts]


def _cidrs(networks) -> list[str]:
    return [str(n) for n in networks]


def test_addresses_split_on_any_separator_and_keep_repeats():
    found = parse_addresses("10.1.1.5\n10.1.1.6, 10.1.2.0/24;10.1.1.5  2001:db8::1\r\n\n")
    assert _cidrs(found) == ["10.1.1.5/32", "10.1.1.6/32", "10.1.2.0/24", "10.1.1.5/32", "2001:db8::1/128"]
    # A network with host bits set is its network.
    assert _cidrs(parse_addresses("10.1.2.7/24")) == ["10.1.2.0/24"]
    assert parse_addresses("  ") == []


def test_an_entry_that_is_not_an_address_is_named():
    with pytest.raises(ValueError, match=r"'10\.1\.1\.300' is not an IP address or network"):
        parse_addresses("10.1.1.5, 10.1.1.300, nope")


def test_exact_summary_collapses_and_keeps_versions_apart():
    networks = parse_addresses("10.1.3.0/24 10.1.2.0/24 10.1.1.6 10.1.1.5 10.1.1.5 2001:db8::1 10.1.1.4")
    assert _cidrs(summarize(networks)) == [
        "10.1.1.4/31",
        "10.1.1.6/32",
        "10.1.2.0/23",
        "2001:db8::1/128",
    ]


def test_roll_up_to_a_prefix_leaves_shorter_networks_alone():
    networks = _nets("10.1.1.5/32", "10.1.200.0/24", "10.0.0.0/8", "10.200.1.1/32", "192.168.7.9/32")
    assert _cidrs(summarize(networks, prefix=16)) == ["10.0.0.0/8", "192.168.0.0/16"]
    assert _cidrs(summarize(_nets("10.1.1.5/32", "10.1.200.0/24"), prefix=16)) == ["10.1.0.0/16"]
    assert _cidrs(summarize(_nets("2001:db8:1::1/128", "2001:db8:2::1/128"), prefix=32)) == ["2001:db8::/32"]


def test_at_most_n_routes_merges_the_cheapest_neighbours_first():
    networks = _nets("10.0.0.1/32", "10.0.0.3/32", "10.0.1.1/32", "10.8.0.1/32")
    # 10.0.0.1 + 10.0.0.3 share a /30, the cheapest merge.
    assert _cidrs(summarize(networks, max_routes=3)) == ["10.0.0.0/30", "10.0.1.1/32", "10.8.0.1/32"]
    assert _cidrs(summarize(networks, max_routes=2)) == ["10.0.0.0/23", "10.8.0.1/32"]
    assert _cidrs(summarize(networks, max_routes=1)) == ["10.0.0.0/12"]
    # The cap is per IP version.
    assert _cidrs(summarize([*networks, *_nets("2001:db8::1/128")], max_routes=1)) == [
        "10.0.0.0/12",
        "2001:db8::1/128",
    ]


def test_a_tie_merges_the_lower_pair_and_the_supernet_swallows_neighbours():
    # Both pairs share a /31-sized gap: the lower one merges first.
    networks = _nets("10.0.0.0/32", "10.0.0.2/32", "10.0.1.0/32", "10.0.1.2/32")
    assert _cidrs(summarize(networks, max_routes=3)) == ["10.0.0.0/30", "10.0.1.0/32", "10.0.1.2/32"]
    # Merging the /25 and the address makes a /24 that joins its sibling /24 into a /23.
    networks = _nets("10.0.1.0/24", "10.0.0.0/25", "10.0.0.200/32", "10.9.0.0/32")
    assert _cidrs(summarize(networks, max_routes=2)) == ["10.0.0.0/23", "10.9.0.0/32"]


@pytest.mark.parametrize(
    ("prefix", "max_routes", "message"),
    [
        (33, None, "prefix must be from 0 to 32"),
        (-1, None, "prefix must be from 0"),
        (129, None, "prefix must be from 0"),
        (None, 0, "max_routes must be at least 1"),
    ],
)
def test_a_prefix_or_cap_out_of_range_is_refused(prefix, max_routes, message):
    with pytest.raises(ValueError, match=message):
        summarize(_nets("10.0.0.1/32"), prefix=prefix, max_routes=max_routes)


def test_an_ipv6_prefix_is_allowed_with_ipv6_addresses_only():
    assert _cidrs(summarize(_nets("2001:db8::1/128"), prefix=64)) == ["2001:db8::/64"]


@pytest.mark.parametrize(
    ("collected", "expected"),
    [
        ("10.64.0.0/16", "equal"),
        ("10.64.10.0/24", "inside"),
        ("10.0.0.0/8", "contains"),
    ],
)
def test_relation_of_a_collected_network_to_a_route(collected, expected):
    assert relation(ipaddress.ip_network("10.64.0.0/16"), ipaddress.ip_network(collected)) == expected


def test_each_route_reports_its_inputs_and_what_it_overlaps():
    networks = parse_addresses("10.64.1.5 10.64.1.5 10.64.2.0/24 10.64.2.9 10.70.0.1 2001:db8::1")
    summary = summarize(networks, prefix=16)
    rows = [
        {"cidr": "10.0.0.0/8", "provider": "fmc", "name": "Static 10/8"},
        {"cidr": "10.64.2.0/24", "provider": "meraki", "name": "VLAN 2"},
        {"cidr": "10.70.0.0/16", "provider": "azure", "name": "Spoke"},
        {"cidr": "10.99.0.0/16", "provider": "aws", "name": "Elsewhere"},
        {"cidr": "2001:db8::/32", "provider": "gcp", "name": "v6"},
        {"cidr": "not a network", "provider": "cato"},
    ]
    entries = routes(networks, summary, rows)
    assert [e["cidr"] for e in entries] == ["10.64.0.0/16", "10.70.0.0/16", "2001::/16"]
    first, second, third = entries
    assert first["version"] == 4 and first["prefixlen"] == 16 and first["addresses"] == 65536
    # Distinct inputs, sorted; the address inside the /24 adds nothing.
    assert first["inputs"] == ["10.64.1.5/32", "10.64.2.0/24", "10.64.2.9/32"]
    assert first["input_count"] == 3 and first["input_addresses"] == 257
    assert [(o["name"], o["relation"]) for o in first["overlaps"]] == [
        ("Static 10/8", "contains"),
        ("VLAN 2", "inside"),
    ]
    assert [(o["name"], o["relation"]) for o in second["overlaps"]] == [("Static 10/8", "contains"), ("Spoke", "equal")]
    assert third["inputs"] == ["2001:db8::1/128"] and [o["name"] for o in third["overlaps"]] == ["v6"]
    # Every row kept by overlapping_rows is one some route reports, in the rows' order.
    assert [r["name"] for r in overlapping_rows(summary, rows)] == ["Static 10/8", "VLAN 2", "Spoke", "v6"]
    assert routes_text(entries) == "10.64.0.0/16\n10.70.0.0/16\n2001::/16"
