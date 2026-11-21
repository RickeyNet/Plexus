"""OPNsense live routes and addresses in the path trace.

The OPNsense collection stores the firewall's routing table and live
interface addresses as the route capture of its inventory host
(``opnsense_routes.capture_text``); the trace reads the routes from it
(``parse_routes``) and fills the addresses config.xml leaves to DHCP or
PPPoE (``opnsense_config.parse_config``). Every name and address is
invented (documentation ranges, example.com); no firewall is contacted.
"""

from __future__ import annotations

import pytest
from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import _interface, _route, build_sample_raw
from netcontrol.integrations.pathtrace import opnsense_routes
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, parse_route_table, subnets_for_host
from netcontrol.integrations.pathtrace.opnsense_config import parse_config, parse_document
from netcontrol.integrations.pathtrace.opnsense_routes import (
    capture_text,
    has_routes,
    live_interfaces,
    parse_routes,
)
from netcontrol.integrations.pathtrace.platforms import platform_of
from netcontrol.integrations.pathtrace.route_tables import LOCAL
from netcontrol.routes.opnsense_collection import live_interfaces as collected_interfaces

from test_opnsense_rules import _ISP_ROUTER, _NODES
from test_path_trace import _labels, _tracer

# A firewall whose WAN address is learned by DHCP / DHCPv6: config.xml holds
# no address and no gateway for it.
EDGE_CONFIG = """<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw-lab-1</hostname><domain>example.com</domain>
    <webgui><protocol>https</protocol></webgui>
  </system>
  <interfaces>
    <wan><enable>1</enable><if>igb0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>
    <lan><enable>1</enable><if>igb1</if><descr>LAN</descr><ipaddr>192.0.2.1</ipaddr><subnet>25</subnet></lan>
    <opt1><enable>1</enable><if>pppoe0</if><descr>BACKUP</descr><ipaddr>pppoe</ipaddr></opt1>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
      <source><network>lan</network></source><destination><any/></destination><descr>LAN out</descr>
    </rule>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>wan</network></source><destination><network>(self)</network><port>22</port></destination>
      <descr>SSH from the WAN network</descr>
    </rule>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><network>wanip</network><port>443</port></destination>
      <descr>Web GUI from the WAN</descr>
    </rule>
  </filter>
  <nat>
    <outbound><mode>automatic</mode></outbound>
    <rule>
      <interface>wan</interface><protocol>tcp</protocol><ipprotocol>inet</ipprotocol>
      <source><any/></source><destination><network>wanip</network><port>8443</port></destination>
      <target>192.0.2.10</target><local-port>443</local-port><descr>Web</descr>
      <associated-rule-id>pass</associated-rule-id>
    </rule>
  </nat>
</opnsense>
"""

INTERFACE_ROWS = [
    _interface("wan", "igb0", "WAN", ["203.0.113.2/29"], ipv6=["fe80::1%igb0/64", "2001:db8:ffff::2/64"]),
    _interface("lan", "igb1", "LAN", ["192.0.2.1/25"]),
    # Assigned, its PPPoE session down: no address.
    _interface("opt1", "pppoe0", "BACKUP", []),
    _interface("", "lo0", "Loopback", ["127.0.0.1/8"], ipv6=["::1/128"]),
]
ROUTE_ROWS = [
    _route("default", "203.0.113.1", "UGS", "igb0", "WAN"),
    _route("203.0.113.0/29", "link#1", "U", "igb0", "WAN"),
    _route("203.0.113.2", "link#1", "UHS", "lo0", "Loopback"),
    _route("192.0.2.0/25", "link#2", "U", "igb1", "LAN"),
    _route("192.0.2.1", "link#2", "UHS", "lo0", "Loopback"),
    # Learned by FRR (BGP): protocol flag 1.
    _route("198.51.100.0/24", "203.0.113.1", "UG1", "igb0", "WAN"),
    # A Null4 static route: a blackhole.
    _route("203.0.113.128/26", "127.0.0.1", "UGSB", "lo0", "Loopback"),
    _route("127.0.0.1", "link#3", "UH", "lo0", "Loopback"),
    _route("default", "fe80::1%igb0", "UG", "igb0", "WAN", proto="ipv6"),
    _route("2001:db8:ffff::/64", "link#1", "U", "igb0", "WAN", proto="ipv6"),
    _route("2001:db8:ffff::2", "link#1", "UHS", "lo0", "Loopback", proto="ipv6"),
    _route("fe80::%igb1/64", "link#2", "U", "igb1", "LAN", proto="ipv6"),
    _route("ff02::%lo0/16", "::1", "UGRS", "lo0", "Loopback", proto="ipv6"),
    _route("::ffff:0.0.0.0/96", "::1", "UGRS", "lo0", "Loopback", proto="ipv6"),
]


def _capture() -> str:
    return capture_text(ROUTE_ROWS, collected_interfaces(INTERFACE_ROWS))[0]


def _by_prefix(routes: list[dict]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for item in routes:
        found.setdefault(item["prefix"], []).append(item)
    return found


# ── The capture text ─────────────────────────────────────────────────────────


def test_capture_text_is_deterministic_and_leaves_out_volatile_fields():
    text, count = capture_text(ROUTE_ROWS, collected_interfaces(INTERFACE_ROWS))
    assert count == len(ROUTE_ROWS)
    lines = text.splitlines()
    assert lines[0] == opnsense_routes.HEADER
    assert "interface wan igb0 203.0.113.2/29 2001:db8:ffff::2/64" in lines
    assert "interface lan igb1 192.0.2.1/25" in lines
    # No usable address: no line (the PPPoE interface, the loopback).
    assert not any(" pppoe0" in line or " lo0 127" in line for line in lines if line.startswith("interface"))
    assert "route ipv4 default 203.0.113.1 UGS igb0" in lines
    # Same rows in another order, other counters: the same text.
    shuffled = [{**row, "use": "123456", "mtu": "9000", "expire": "300"} for row in reversed(ROUTE_ROWS)]
    assert capture_text(shuffled, collected_interfaces(list(reversed(INTERFACE_ROWS))))[0] == text
    # Only the fields named: no description, no interface configuration.
    assert "Loopback" not in text and "not-a-real-secret" not in text
    # A change in the routing changes it.
    changed = [*ROUTE_ROWS, _route("198.51.100.64/26", "192.0.2.2", "UGS", "igb1", "LAN")]
    assert capture_text(changed, collected_interfaces(INTERFACE_ROWS))[0] != text


def test_capture_reads_back_into_routes_and_addresses():
    text = _capture()
    assert has_routes(text) and not has_routes(capture_text([], collected_interfaces(INTERFACE_ROWS))[0])
    assert ("wan", "igb0", ["203.0.113.2/29", "2001:db8:ffff::2/64"]) in live_interfaces(text)

    routes, missing = parse_route_table(text, "opnsense")
    assert missing == []
    found = _by_prefix(routes)
    [default] = found["0.0.0.0/0"]
    assert (default["kind"], default["next_hop"], default["interface"]) == ("default", "203.0.113.1", "igb0")
    [learned] = found["198.51.100.0/24"]
    assert learned["kind"] == "dynamic" and learned["next_hop"] == "203.0.113.1"
    [blackhole] = found["203.0.113.128/26"]
    assert blackhole["kind"] == "blackhole"
    # The IPv6 default by router advertisement: learned, its next hop link-local (not kept).
    [default6] = found["::/0"]
    assert default6["kind"] == "dynamic" and default6["interface"] == "igb0" and default6["next_hop"] == ""
    # The firewall's own addresses: local on the interface their link names.
    assert {(r["interface"], r["source"]) for r in found["203.0.113.2/32"]} == {("igb0", LOCAL)}
    assert {(r["interface"], r["source"]) for r in found["2001:db8:ffff::2/128"]} == {("igb0", LOCAL)}
    assert [r["kind"] for r in found["203.0.113.0/29"]] == ["connected"]
    assert [r["interface"] for r in found["2001:db8:ffff::/64"]] == ["igb0"]
    # Loopback, link-local, multicast and the IPv4-mapped range are left out.
    assert not any(p.startswith(("127.", "fe80", "ff02", "::ffff", "::1")) for p in found)


def test_interface_addresses_without_a_route_are_connected_and_local():
    text = capture_text(
        [_route("default", "198.51.100.1", "UGS", "pppoe0", "BACKUP")],
        [("opt1", "pppoe0", ["198.51.100.50/32"]), ("opt2", "igb2", ["192.0.2.193/27"])],
    )[0]
    found = _by_prefix(parse_routes(text.splitlines()))
    assert [(r["interface"], r["source"]) for r in found["198.51.100.50/32"]] == [("pppoe0", LOCAL)]
    assert [r["source"] for r in found["192.0.2.192/27"]] == ["Connected"]
    assert [r["source"] for r in found["192.0.2.193/32"]] == [LOCAL]


def test_platform_reads_the_capture():
    platform = platform_of("opnsense")
    assert platform.routes is parse_routes and platform.config_capture is parse_config
    # Another platform keeps reading its configuration alone.
    assert platform_of("cisco_ios").config_capture is None


# ── Live addresses in config.xml ─────────────────────────────────────────────


def test_live_addresses_fill_the_dynamic_interfaces():
    without = parse_document(EDGE_CONFIG)
    assert without is not None and without.interfaces["wan"].ipv4 is None
    config = parse_document(EDGE_CONFIG, live=live_interfaces(_capture()))
    assert config is not None
    wan = config.interfaces["wan"]
    assert wan.ipv4 == ("203.0.113.2", "203.0.113.0/29") and wan.ipv6 == ("2001:db8:ffff::2", "2001:db8:ffff::/64")
    assert wan.dynamic == []
    # No live address: still learned dynamically.
    assert config.interfaces["opt1"].dynamic == ["pppoe"] and config.interfaces["opt1"].ipv4 is None

    ssh = next(r for r in config.rules if r.description == "SSH from the WAN network")
    assert ssh.source.cidrs == ["203.0.113.0/29", "2001:db8:ffff::/64"]
    assert ssh.source.unresolved == []
    # (self) is every address of the firewall: one interface still learns its address.
    assert ssh.destination.unresolved == ["addresses of this firewall learned on opt1"]
    web = next(r for r in config.rules if r.description == "Web GUI from the WAN")
    assert "203.0.113.2/32" in web.destination.cidrs and web.destination.unresolved == []
    # Without the live addresses, as before.
    old = next(r for r in without.rules if r.description == "Web GUI from the WAN")
    assert old.destination.cidrs == [ANY] and old.destination.unresolved


def test_self_resolves_when_every_interface_has_its_address():
    capture = capture_text(
        ROUTE_ROWS, [*collected_interfaces(INTERFACE_ROWS), ("opt1", "pppoe0", ["198.51.100.50/32"])]
    )[0]
    config = parse_document(EDGE_CONFIG, live=live_interfaces(capture))
    assert config is not None
    ssh = next(r for r in config.rules if r.description == "SSH from the WAN network")
    assert ssh.destination.unresolved == []
    assert {"203.0.113.2/32", "192.0.2.1/32", "198.51.100.50/32"} <= set(ssh.destination.cidrs)


def test_automatic_nat_and_notes_with_a_capture():
    running = parse_config(EDGE_CONFIG, _capture())
    automatic = [n for n in running.nat if n["name"] == "Automatic outbound NAT on wan"]
    assert automatic and automatic[0]["original_src"] == ["192.0.2.0/25"]
    assert automatic[0]["translated_src"] == [INTERFACE]
    # The capture says what is installed: no learned-route note; one
    # interface still learns its address.
    assert not any(n.startswith("Routes learned by") for n in running.notes)
    assert "Interface addresses learned dynamically (opt1: pppoe)" in running.notes
    wan = next(i for i in running.interfaces if i.name == "igb0")
    assert wan.addresses[0] == ("203.0.113.2", "203.0.113.0/29")

    # config.xml alone: as before.
    alone = parse_config(EDGE_CONFIG)
    assert alone.notes == parse_config(EDGE_CONFIG, "").notes
    assert any(n.startswith("Routes learned by DHCP or PPPoE") for n in alone.notes)
    assert "Interface addresses learned dynamically (wan: dhcp, dhcp6; opt1: pppoe)" in alone.notes


def test_a_capture_without_routes_keeps_the_route_notes():
    interfaces_only = "\n".join([opnsense_routes.HEADER, "interface wan igb0 203.0.113.2/29"])
    running = parse_config(EDGE_CONFIG, interfaces_only)
    assert any(n.startswith("Routes learned by DHCP or PPPoE") for n in running.notes)


# ── The trace ────────────────────────────────────────────────────────────────


def _trace(capture: str | None):
    route_capture = None if capture is None else {"id": 1, "routes_text": capture}
    firewall = forwarding_for_host(
        {"ip_address": "192.0.2.1", "device_type": "opnsense"},
        [],
        route_capture,
        [],
        config_backup={"config_text": EDGE_CONFIG},
    )
    router = forwarding_for_host(
        {"ip_address": "203.0.113.1", "device_type": "cisco_ios"},
        [],
        None,
        [],
        config_backup={"config_text": _ISP_ROUTER},
    )
    subnets = [*subnets_for_host(_NODES[0], firewall), *subnets_for_host(_NODES[1], router)]
    link = {"id": "lldp:31:32", "from": 31, "to": 32, "protocol": "lldp", "status": "up"}
    tracer = _tracer({}, hosts={31: firewall, 32: router}, extra_nodes=_NODES, extra_edges=[link], subnets=subnets)
    return firewall, tracer


def _route_items(hop: dict) -> list[dict]:
    return [i for i in hop["items"] if i["stage"] == "route"]


def test_without_a_capture_the_trace_is_as_before():
    firewall, tracer = _trace(None)
    assert firewall["not_collected"] == [
        "Interface addresses learned dynamically (wan: dhcp, dhcp6; opt1: pppoe)",
        "Routes learned by DHCP or PPPoE (the default gateway of wan, opt1)",
    ]
    out = tracer.trace("192.0.2.0/25", "203.0.113.100", source_node=31, protocol="tcp", port=443)
    assert out["verdict"] == "unknown"
    [route] = _route_items(out["request"]["hops"][0])
    assert route["status"] == "unknown" and "not collected" in route["text"]


def test_a_default_route_only_destination_is_decided_with_a_capture():
    firewall, tracer = _trace(_capture())
    assert not any(
        n.startswith(("Routes learned by", "Interface addresses learned dynamically (wan"))
        for n in firewall["not_collected"]
    )
    assert "Interface addresses learned dynamically (opt1: pppoe)" in firewall["not_collected"]
    wan = next(i for i in firewall["interfaces"] if i["name"] == "igb0")
    assert (wan["ip"], wan["cidr"]) == ("203.0.113.2", "203.0.113.0/29")

    out = tracer.trace("192.0.2.0/25", "203.0.113.100", source_node=31, protocol="tcp", port=443)
    hop = out["request"]["hops"][0]
    route = _route_items(hop)[0]
    assert route["status"] == "ok", route
    assert hop["out"] == "igb0"
    # The automatic outbound NAT hides the LAN behind the learned WAN address.
    snat = next(i for i in hop["items"] if i["stage"] == "nat")
    assert "203.0.113.2" in snat["text"]


def test_a_learned_route_is_followed():
    _firewall, tracer = _trace(_capture())
    out = tracer.trace("192.0.2.0/25", "198.51.100.10", source_node=31, destination_node=32, protocol="tcp", port=443)
    assert out["verdict"] == "allowed", out["summary"]
    assert _labels(out["request"]) == ["fw-lab-1", "isp-rtr"]
    hop = out["request"]["hops"][0]
    assert hop["out"] == "igb0"
    route = _route_items(hop)[0]
    assert route["status"] == "ok" and "198.51.100.0/24" in route["text"]


def test_a_blackhole_route_of_the_capture_drops_the_flow():
    _firewall, tracer = _trace(_capture())
    out = tracer.trace("192.0.2.0/25", "203.0.113.130", source_node=31, protocol="tcp", port=443)
    assert out["verdict"] != "allowed"
    [route] = _route_items(out["request"]["hops"][0])
    assert route["status"] == "blocked" and "blackhole" in route["text"]


def _wan_rules(block: dict) -> dict[str, dict]:
    policy = next(p for p in block["policies"] if p["name"] == "ACL wan in on wan (igb0)")
    return {r["name"]: r for r in policy["rules"]}


def test_rules_and_port_forwards_on_the_learned_wan_address_resolve():
    before, _tracer_ = _trace(None)
    web = _wan_rules(before)["Web GUI from the WAN"]
    assert web["unresolved"] == ["address of wan (learned by dhcp, dhcp6)"]

    firewall, _tracer_ = _trace(_capture())
    rules = _wan_rules(firewall)
    assert (
        rules["Web GUI from the WAN"]["dst"] == ["203.0.113.2/32"] and not rules["Web GUI from the WAN"]["unresolved"]
    )
    # wan net resolves; (self) still names the PPPoE interface without an address.
    assert rules["SSH from the WAN network"]["unresolved"] == ["addresses of this firewall learned on opt1"]
    [forward] = [n for n in firewall["nat"] if n["kind"] == "destination_nat"]
    assert forward["original_dst"] == ["203.0.113.2/32"] and forward["translated_dst"] == ["192.0.2.10/32"]


# ── Stored by the collection ─────────────────────────────────────────────────


async def _host(address: str = "192.0.2.1") -> int:
    import routes.database as db

    group_id = await db.create_group(f"Firewalls {address}")
    return await db.add_host(group_id, f"fw-{address}", address, device_type="opnsense")


def _section(snapshot: dict, title: str) -> dict[str, object] | None:
    firewall = next(n for n in snapshot["nodes"] if n.get("kind") == "appliance" and n["id"].startswith("d:"))
    found = next((s for s in firewall["sections"] if s.get("title") == title), None)
    return dict(found["rows"]) if found else None


@pytest.mark.asyncio
async def test_after_collection_stores_the_capture_of_a_matched_host():
    import routes.database as db
    from netcontrol.routes.opnsense_collection import SECTION_ROUTE_CAPTURE, after_collection

    host_id = await _host()
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, 901)
    stored = await db.get_latest_route_snapshot(host_id)
    assert stored is not None and stored["routes_text"].startswith(opnsense_routes.HEADER)
    assert stored["route_count"] == len(raw["routes"])
    assert stored["routes_text"] == capture_text(raw["routes"], collected_interfaces(raw["interfaces"]))[0]
    section = _section(snapshot, SECTION_ROUTE_CAPTURE)
    assert section is not None and section["Result"] == "New capture stored"

    # Unchanged: no second row.
    raw, snapshot = build_sample_raw(), build_snapshot(build_sample_raw())
    await after_collection(raw, snapshot, 901)
    assert len(await db.get_route_snapshots(host_id)) == 1
    assert _section(snapshot, SECTION_ROUTE_CAPTURE)["Result"] == "Unchanged since the newest capture"

    # The trace of that host reads its routes from it.
    block = forwarding_for_host({"ip_address": "192.0.2.1", "device_type": "opnsense"}, [], stored, [])
    assert any(r["prefix"] == "0.0.0.0/0" and r["next_hop"] == "203.0.113.1" for r in block["routes"])


@pytest.mark.asyncio
async def test_after_collection_stores_nothing_without_a_host_or_a_table():
    import routes.database as db
    from netcontrol.routes.opnsense_collection import SECTION_ROUTE_CAPTURE, after_collection, store_route_capture

    # Not an inventory host: nothing stored, the section says so.
    other = await _host("198.51.100.250")
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, 901)
    assert await db.get_latest_route_snapshot(other) is None
    assert _section(snapshot, SECTION_ROUTE_CAPTURE)["Result"].startswith("Not stored")

    # The routes call failed (or the option is off): nothing at all.
    host_id = await _host()
    raw = {**build_sample_raw(), "routes": None}
    snapshot = build_snapshot(raw)
    assert await store_route_capture(raw, snapshot) is None
    assert await db.get_latest_route_snapshot(host_id) is None
    assert _section(snapshot, SECTION_ROUTE_CAPTURE) is None


@pytest.mark.asyncio
async def test_retention_keeps_each_hosts_newest_route_snapshot():
    import routes.database as db
    from netcontrol.routes.route_capture import store_route_snapshot

    host_id = await _host()
    await store_route_snapshot(host_id, "first", 1)
    await store_route_snapshot(host_id, "second", 2)
    conn = await db.get_db()
    try:
        await conn.execute("UPDATE route_snapshots SET captured_at = datetime('now', '-90 days')")
        await conn.commit()
    finally:
        await conn.close()
    assert await db.delete_old_route_snapshots(30) == 1
    newest = await db.get_latest_route_snapshot(host_id)
    assert newest is not None and newest["routes_text"] == "second"
