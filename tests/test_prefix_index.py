"""The shared longest-prefix helper (``netcontrol.prefix_index``) and its
call sites: the topology map's IPAM context, IPAM aggregates, the path
tracer's subnet holders and the Meraki VPN check. Each call site's former
linear scan is kept here as an oracle, so the helper is checked against the
behaviour it replaced, ties, IPv6 and no match included."""

from __future__ import annotations

import ipaddress
import random
import time

from netcontrol.integrations.meraki.vpn_reach import OK, UNKNOWN, VpnCarrier
from netcontrol.ipam_model import containing_aggregate
from netcontrol.prefix_index import PrefixIndex, longest_prefix_match, longest_prefix_matches
from netcontrol.routes.topology import _build_ipam_subnet_index, _match_ipam_subnet

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _n(text: str) -> Network:
    return ipaddress.ip_network(text, strict=False)


# ── Oracles: the scans the helper replaced ───────────────────────────────────


def _first_longest(target: Network, entries: list[tuple[Network, object]]) -> object | None:
    """topology / ipam_model / VPN near side: longest prefix, first on a tie."""
    best: tuple[int, object] | None = None
    for network, item in entries:
        if network.version != target.version or not network.supernet_of(target):  # type: ignore[arg-type]
            continue
        if best is None or network.prefixlen > best[0]:
            best = (network.prefixlen, item)
    return best[1] if best else None


def _all_longest(target: Network, entries: list[tuple[Network, object]]) -> list[object]:
    """path tracer / VPN far side: every item at the longest prefix, in order."""
    owners: list[object] = []
    longest = -1
    for network, item in entries:
        if network.version != target.version or not network.supernet_of(target) or network.prefixlen < longest:  # type: ignore[arg-type]
            continue
        if network.prefixlen > longest:
            owners, longest = [], network.prefixlen
        owners.append(item)
    return owners


def _vrf_best(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, subnets: list[dict], target_vrf: str) -> dict | None:
    """``/api/ipam/lookup`` before: same-VRF first, then the longest prefix."""
    best: dict | None = None
    best_prefixlen = -1
    best_vrf_match = False
    for s in subnets:
        network = ipaddress.ip_network(s["subnet"], strict=False)
        if addr not in network:
            continue
        vrf_match = bool(target_vrf) and (s.get("vrf_name") or "").strip() == target_vrf
        if (
            best is None
            or (vrf_match and not best_vrf_match)
            or (vrf_match == best_vrf_match and network.prefixlen > best_prefixlen)
        ):
            best, best_prefixlen, best_vrf_match = s, network.prefixlen, vrf_match
    return best


def _vrf_new(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, subnets: list[dict], target_vrf: str) -> dict | None:
    """The same choice as ``netcontrol/routes/ipam.py`` now makes it."""
    candidates = [(_n(s["subnet"]), s) for s in subnets]
    best = None
    if target_vrf:
        best = longest_prefix_match(addr, [(n, s) for n, s in candidates if (s.get("vrf_name") or "") == target_vrf])
    return best if best is not None else longest_prefix_match(addr, candidates)


# ── The helper ───────────────────────────────────────────────────────────────


def test_most_specific_wins_and_ties_keep_input_order() -> None:
    entries = [
        (_n("192.0.2.0/24"), "wide"),
        (_n("192.0.2.0/25"), "first"),
        (_n("192.0.2.0/25"), "second"),
        (_n("0.0.0.0/0"), "default"),
    ]
    assert longest_prefix_matches(ipaddress.ip_address("192.0.2.5"), entries) == ["first", "second"]
    assert longest_prefix_match(ipaddress.ip_address("192.0.2.5"), entries) == "first"
    assert longest_prefix_match(ipaddress.ip_address("192.0.2.200"), entries) == "wide"
    assert longest_prefix_match(ipaddress.ip_address("198.51.100.1"), entries) == "default"
    # A network wider than every entry but the default route.
    assert longest_prefix_match(_n("192.0.2.0/23"), entries) == "default"
    assert longest_prefix_match(_n("192.0.2.128/26"), entries) == "wide"


def test_ipv6_and_no_match_and_versions_kept_apart() -> None:
    index = PrefixIndex([(_n("2001:db8::/32"), "doc"), (_n("2001:db8:1::/48"), "site"), (_n("0.0.0.0/0"), "v4")])
    assert index.match(ipaddress.ip_address("2001:db8:1::1")) == "site"
    assert index.match(ipaddress.ip_address("2001:db8:2::1")) == "doc"
    assert index.match(ipaddress.ip_address("2001:db9::1")) is None
    assert index.matches(_n("2001:db8::/31")) == []
    assert PrefixIndex([]).match(ipaddress.ip_address("203.0.113.1")) is None


def test_matches_the_old_scans_on_random_tables() -> None:
    rng = random.Random(20261126)
    for _ in range(40):
        entries: list[tuple[Network, object]] = []
        for i in range(60):
            if rng.random() < 0.3:
                base = ipaddress.IPv6Address("2001:db8::") + rng.getrandbits(32) * (1 << 64)
                network: Network = ipaddress.ip_network(f"{base}/{rng.randint(32, 64)}", strict=False)
            else:
                base4 = ipaddress.IPv4Address("198.51.100.0") + rng.getrandbits(8)
                network = ipaddress.ip_network(f"{base4}/{rng.randint(24, 32)}", strict=False)
            entries.append((network, i))
            if rng.random() < 0.2:
                entries.append((network, f"dup-{i}"))
        index = PrefixIndex(entries)
        for _ in range(60):
            if rng.random() < 0.3:
                target: Network = _n(f"{ipaddress.IPv6Address('2001:db8::') + rng.getrandbits(48) * (1 << 64)}/128")
            else:
                prefix = rng.choice((32, 32, 28, 26, 24))
                target = _n(f"{ipaddress.IPv4Address('198.51.100.0') + rng.getrandbits(8)}/{prefix}")
            assert index.match(target) == _first_longest(target, entries)
            assert index.matches(target) == _all_longest(target, entries)


# ── Call sites ───────────────────────────────────────────────────────────────


def test_topology_node_gets_its_most_specific_ipam_subnet() -> None:
    subnets = [
        {"subnet": "192.0.2.0/24", "utilization_pct": 10, "source_types": ["inventory"]},
        {"subnet": "192.0.2.0/26", "utilization_pct": 40, "source_types": ["cloud"]},
        {"subnet": "192.0.2.0/26", "utilization_pct": 99, "source_types": ["dup"]},
        {"subnet": "not a subnet"},
        {"subnet": ""},
        {"subnet": "2001:db8::/64", "utilization_pct": 1, "source_types": []},
    ]
    index = _build_ipam_subnet_index(subnets)
    assert _match_ipam_subnet("192.0.2.10", index) == {
        "subnet": "192.0.2.0/26",
        "utilization_pct": 40,
        "source_types": ["cloud"],
    }
    assert _match_ipam_subnet("192.0.2.100/24", index)["subnet"] == "192.0.2.0/24"  # type: ignore[index]
    assert _match_ipam_subnet("2001:db8::5", index)["subnet"] == "2001:db8::/64"  # type: ignore[index]
    assert _match_ipam_subnet("203.0.113.1", index) is None
    assert _match_ipam_subnet("junk", index) is None
    assert _match_ipam_subnet("", index) is None


def test_ipam_lookup_prefers_the_vrf_then_the_longest_prefix() -> None:
    subnets = [
        {"subnet": "192.0.2.0/24", "vrf_name": "blue"},
        {"subnet": "192.0.2.0/25", "vrf_name": ""},
        {"subnet": "192.0.2.0/26", "vrf_name": "red"},
        {"subnet": "192.0.2.0/26", "vrf_name": "red-dup"},
        {"subnet": "2001:db8::/48", "vrf_name": "blue"},
        {"subnet": "2001:db8::/64", "vrf_name": ""},
    ]
    for address in ("192.0.2.1", "192.0.2.100", "192.0.2.200", "203.0.113.1", "2001:db8::1", "2001:db8:0:1::1"):
        addr = ipaddress.ip_address(address)
        for vrf in ("", "blue", "red", "green"):
            assert _vrf_new(addr, subnets, vrf) is _vrf_best(addr, subnets, vrf), (address, vrf)
    # The VRF's own /24 beats a longer prefix of another VRF.
    assert _vrf_new(ipaddress.ip_address("192.0.2.1"), subnets, "blue") == {
        "subnet": "192.0.2.0/24",
        "vrf_name": "blue",
    }


def test_containing_aggregate_ties_keep_the_first() -> None:
    aggregates = [{"prefix": "198.51.100.0/24", "n": 1}, {"prefix": "198.51.100.0/24", "n": 2}, {"prefix": "bad"}]
    assert containing_aggregate("198.51.100.64/26", aggregates) == {"prefix": "198.51.100.0/24", "n": 1}
    assert containing_aggregate("2001:db8::/48", aggregates) is None


def _vpn_snapshot(local_rows: list[list[str]]) -> dict:
    return {
        "nodes": [
            {"id": "mx-a", "kind": "appliance", "site": "s-a", "label": "MX A", "model": "MX"},
            {"id": "mx-b", "kind": "appliance", "site": "s-b", "label": "MX B", "model": "MX"},
        ],
        "sites": [
            {
                "id": "s-a",
                "name": "Site A",
                "sections": [{"title": "VPN local subnets", "kind": "table", "rows": local_rows}],
            },
            {"id": "s-b", "name": "Site B"},
        ],
        "edges": [{"kind": "vpn", "a": "mx-a", "b": "mx-b", "status": "reachable"}],
    }


def test_vpn_far_side_takes_every_owner_of_the_longest_prefix() -> None:
    subnets = [
        {"cidr": "198.51.100.0/24", "site_id": "s-b", "site_name": "Site B", "node_id": "mx-b", "kind": "vlan"},
        {"cidr": "198.51.100.0/25", "site_id": "s-a", "site_name": "Site A", "node_id": "mx-a", "kind": "vlan"},
    ]
    carrier = VpnCarrier(_vpn_snapshot([]), "mx-a", subnets)
    status, _where, text = carrier._far_side(_n("198.51.100.10/32"))
    assert status == OK and "own site" in text
    status, _where, text = carrier._far_side(_n("198.51.100.200/32"))
    assert "198.51.100.0/24" in text
    assert carrier._far_side(_n("2001:db8::1/128"))[0] == UNKNOWN


def test_vpn_near_side_reads_the_most_specific_advertised_row() -> None:
    rows = [["198.51.100.0/24", "Yes"], ["198.51.100.0/26", "No"], ["198.51.100.0/26", "Yes"]]
    carrier = VpnCarrier(_vpn_snapshot(rows), "mx-a", [])
    assert "excluded" in carrier._near_side(_n("198.51.100.5/32"))[2]
    assert carrier._near_side(_n("198.51.100.100/32"))[0] == OK
    assert carrier._near_side(_n("203.0.113.1/32"))[0] == UNKNOWN


def test_index_lookups_are_faster_than_the_scan_at_map_scale() -> None:
    """1,000 nodes against 3,000 subnets, the case the audit measured."""
    rng = random.Random(7)
    entries: list[tuple[Network, object]] = [
        (_n(f"2001:db8:{rng.randrange(64):x}:{rng.randrange(64):x}::/{rng.choice((48, 56, 60, 64))}"), i)
        for i in range(3000)
    ]
    targets = [
        _n(f"2001:db8:{rng.randrange(64):x}:{rng.randrange(64):x}::{rng.randrange(1, 9)}/128") for _ in range(1000)
    ]
    started = time.perf_counter()
    scanned = [_first_longest(t, entries) for t in targets]
    scan_seconds = time.perf_counter() - started
    started = time.perf_counter()
    index = PrefixIndex(entries)
    indexed = [index.match(t) for t in targets]
    index_seconds = time.perf_counter() - started
    assert indexed == scanned
    assert index_seconds < scan_seconds
