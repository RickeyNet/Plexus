"""OPNsense NetFlow in the flow collector.

Covers the exporter cache resolving a flow source by a host's recorded
interface addresses (every vendor; the primary address wins), the OPNsense
collection recording the firewall's interface addresses and its kernel
interface index names, the stored exporter rows being relinked, the names
in the top interfaces API and the MCP tool, and the firewall's "Flow
export" section. Every name and address is invented (documentation ranges).
"""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import build_sample_raw
from netcontrol.integrations.pathtrace.opnsense_routes import interface_indexes, link_devices
from netcontrol.routes import flow_collector
from netcontrol.routes.opnsense_netflow import (
    SECTION_FLOW_EXPORT,
    interface_alias_addresses,
    interface_index_names,
    sync_flow_export,
)

# The sample firewall: API address 192.0.2.1 (its LAN), WAN 203.0.113.10.
FIREWALL_IP = "192.0.2.1"
WAN_IP = "203.0.113.10"


async def _host(address: str, name: str = "", device_type: str = "opnsense") -> int:
    group_id = await db.create_group(f"Group {name or address}")
    return await db.add_host(group_id, name or f"fw-{address}", address, device_type=device_type)


def _section(snapshot: dict, title: str) -> dict | None:
    firewall = next(n for n in snapshot["nodes"] if n.get("kind") == "appliance" and n["id"].startswith("d:"))
    found = next((s for s in firewall["sections"] if s.get("title") == title), None)
    return dict(found["rows"]) if found else None


def _flow(exporter_ip: str, host_id: int | None, input_if: int, output_if: int, size: int) -> tuple:
    return (
        exporter_ip,
        host_id,
        "netflow_v9",
        "192.0.2.10",
        "198.51.100.20",
        50000,
        443,
        6,
        size,
        size // 100,
        0,
        0,
        input_if,
        output_if,
        0,
        0,
        "2026-11-20T09:00:00+00:00",
        "2026-11-20T09:00:30+00:00",
    )


@pytest.fixture(autouse=True)
def _clear_cache():
    flow_collector._exporter_cache.clear()
    yield
    flow_collector._exporter_cache.clear()


# ── Pure parts ───────────────────────────────────────────────────────────────


def test_interface_indexes_come_from_the_connected_routes():
    raw = build_sample_raw()
    # Connected routes name link#1 igb0, link#2 igb1, link#5 vlan0.20; the
    # host route through lo0 and the gateway routes name no index.
    assert interface_indexes(raw["routes"]) == {1: "igb0", 2: "igb1", 5: "vlan0.20"}
    assert interface_indexes(None) == {}
    assert interface_indexes([{"gateway": "link#0", "flags": "U", "netif": "igb3"}, "junk"]) == {}
    assert link_devices([("link#4", "UG", "igb4"), ("link#6", "U", "lo0")]) == {}


def test_interface_index_names_use_the_opnsense_names():
    names = interface_index_names(build_sample_raw())
    assert names == [
        {"if_index": 1, "device": "igb0", "name": "WAN"},
        {"if_index": 2, "device": "igb1", "name": "LAN"},
        {"if_index": 5, "device": "vlan0.20", "name": "DMZ"},
    ]
    # No interface rows: the route's interface description, else the device.
    raw = {
        "interfaces": None,
        "routes": [
            {"gateway": "link#3", "flags": "U", "netif": "igb2", "intf_description": "WAN2"},
            {"gateway": "link#7", "flags": "U", "netif": "ovpns1"},
        ],
    }
    assert interface_index_names(raw) == [
        {"if_index": 3, "device": "igb2", "name": "WAN2"},
        {"if_index": 7, "device": "ovpns1", "name": "ovpns1"},
    ]


def test_interface_alias_addresses_skip_link_local():
    raw = build_sample_raw()
    raw["interfaces"][0]["ipv6"] = [{"ipaddr": "fe80::1%igb0/64"}]
    found = interface_alias_addresses(raw)
    assert WAN_IP in found and FIREWALL_IP in found and "2001:db8:10::1" in found
    assert not any(a.startswith("fe80") for a in found)


# ── Exporter cache: every vendor ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exporter_resolves_by_a_recorded_interface_address():
    router = await _host("198.51.100.1", "rtr-1", device_type="cisco_ios")
    await db.set_host_ip_aliases(router, "198.51.100.1", ["198.51.100.65", "203.0.113.33"])
    await flow_collector.refresh_exporter_cache()
    assert flow_collector._exporter_cache["198.51.100.1"] == router
    assert flow_collector._exporter_cache["203.0.113.33"] == router


@pytest.mark.asyncio
async def test_primary_address_wins_over_an_alias():
    switch = await _host("198.51.100.2", "sw-1", device_type="cisco_ios")
    router = await _host("198.51.100.3", "rtr-2", device_type="cisco_ios")
    # The router records the switch's primary address as one of its own.
    await db.set_host_ip_aliases(router, "198.51.100.3", ["198.51.100.2", "198.51.100.129"])
    other = await _host("198.51.100.4", "rtr-3", device_type="cisco_ios")
    await db.set_host_ip_aliases(other, "198.51.100.4", ["198.51.100.129"])
    mapping = await db.get_exporter_host_map()
    assert mapping["198.51.100.2"] == switch
    # Two aliases: the lowest host id, as find_host_by_ip does.
    assert mapping["198.51.100.129"] == min(router, other)
    found = await db.find_host_by_ip("198.51.100.129", include_aliases=True)
    assert found is not None and found["id"] == mapping["198.51.100.129"]


@pytest.mark.asyncio
async def test_sync_relinks_existing_exporter_rows():
    router = await _host("198.51.100.5", "rtr-4", device_type="cisco_ios")
    await db.upsert_flow_exporter("203.0.113.40", "netflow_v9", None)
    await db.upsert_flow_exporter("cloud-account-1", "cloud_aws_flow", None)
    await db.set_host_ip_aliases(router, "198.51.100.5", ["203.0.113.40"])
    assert await flow_collector.sync_exporter_hosts() == 1
    rows = {r["exporter_ip"]: r for r in await db.list_flow_exporters()}
    assert rows["203.0.113.40"]["host_id"] == router
    assert rows["cloud-account-1"]["host_id"] is None
    # The alias goes away: the exporter is unlinked.
    await db.set_host_ip_aliases(router, "198.51.100.5", [])
    await flow_collector.sync_exporter_hosts()
    rows = {r["exporter_ip"]: r for r in await db.list_flow_exporters()}
    assert rows["203.0.113.40"]["host_id"] is None


# ── The OPNsense collection ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collection_records_addresses_names_and_relinks_the_exporter():
    from netcontrol.routes.opnsense_collection import after_collection

    host_id = await _host(FIREWALL_IP)
    # Flows already arrived from the WAN address before the collection.
    await db.upsert_flow_exporter(WAN_IP, "netflow_v9", None, packets_delta=42)
    await flow_collector.refresh_exporter_cache()
    assert WAN_IP not in flow_collector._exporter_cache

    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, 902)

    # The cache resolves the WAN address now, without a host edit.
    assert flow_collector._exporter_cache[WAN_IP] == host_id
    assert flow_collector._exporter_cache[FIREWALL_IP] == host_id
    aliases = {a["ip_address"] for a in await db.get_ip_aliases_for_hosts([host_id])}
    assert WAN_IP in aliases and FIREWALL_IP not in aliases
    [exporter] = [e for e in await db.list_flow_exporters() if e["exporter_ip"] == WAN_IP]
    assert exporter["host_id"] == host_id

    names = (await db.get_flow_interface_names([host_id]))[host_id]
    assert names[1] == {"name": "WAN", "device": "igb0"}
    assert names[5] == {"name": "DMZ", "device": "vlan0.20"}

    section = _section(snapshot, SECTION_FLOW_EXPORT)
    assert section is not None
    assert section["Flows received"] == "Yes"
    assert section[f"netflow_v9 from {WAN_IP}"].startswith("42 packets")
    assert section["Interface names"] == "3 interface indexes named"


@pytest.mark.asyncio
async def test_collection_without_a_host_or_flows():
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    result = await sync_flow_export(raw, snapshot)
    assert result == {"host_id": None, "aliases": None, "interface_names": None}
    section = _section(snapshot, SECTION_FLOW_EXPORT)
    assert section is not None and section["Result"].startswith("Not linked")

    host_id = await _host(FIREWALL_IP)
    raw = {**build_sample_raw(), "routes": None}
    snapshot = build_snapshot(raw)
    result = await sync_flow_export(raw, snapshot)
    assert result["host_id"] == host_id and result["interface_names"] is None
    section = _section(snapshot, SECTION_FLOW_EXPORT)
    assert section is not None and section["Flows received"].startswith("None yet")
    assert "Interface names" not in section
    assert await db.get_flow_interface_names([host_id]) == {}


# ── Names in the flow views ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_top_interfaces_carry_names_and_keep_the_index():
    firewall = await _host(FIREWALL_IP)
    await db.replace_flow_interface_names(
        firewall, "opnsense", [{"if_index": 1, "device": "igb0", "name": "WAN"}, {"if_index": 0, "device": "x"}]
    )
    # A host polled over SNMP: interface_stats name its indexes.
    switch = await _host("198.51.100.6", "sw-2", device_type="cisco_ios")
    await db.upsert_interface_stats_batch([(switch, 10101, "Gi1/0/1", 1000, 0, 0)])
    # A host without names.
    plain = await _host("198.51.100.7", "rtr-5", device_type="cisco_ios")
    await db.create_flow_records_batch(
        [
            _flow(WAN_IP, firewall, 2, 1, 5000),
            _flow(WAN_IP, firewall, 1, 2, 1000),
            _flow("198.51.100.6", switch, 10101, 10102, 300),
            _flow("198.51.100.7", plain, 4, 5, 200),
        ]
    )

    rows = await flow_collector.api_top_interfaces(host_id=firewall, hours=1, limit=20, request=None)
    by_index = {r["if_index"]: r for r in rows}
    assert by_index[1]["if_name"] == "WAN" and by_index[1]["if_device"] == "igb0"
    assert by_index[1]["in_bytes"] == 1000 and by_index[1]["out_bytes"] == 5000
    assert by_index[2]["if_name"] is None  # no name stored for igb1 here
    assert rows[0]["if_index"] == 1  # 6000 bytes either way

    rows = await flow_collector.api_top_interfaces(host_id=switch, hours=1, limit=20, request=None)
    assert {r["if_index"]: r["if_name"] for r in rows} == {10101: "Gi1/0/1", 10102: None}

    rows = await flow_collector.api_top_interfaces(host_id=plain, hours=1, limit=20, request=None)
    assert {(r["if_index"], r["if_name"], r["if_device"]) for r in rows} == {(4, None, None), (5, None, None)}

    # The collection replaces only its own rows.
    await db.replace_flow_interface_names(firewall, "opnsense", [{"if_index": 2, "device": "igb1", "name": "LAN"}])
    assert (await db.get_flow_interface_names([firewall]))[firewall] == {2: {"name": "LAN", "device": "igb1"}}


@pytest.mark.asyncio
async def test_mcp_top_talkers_ranks_interfaces():
    from netcontrol.mcp.tools.traffic import get_top_talkers

    firewall = await _host(FIREWALL_IP)
    await db.replace_flow_interface_names(firewall, "opnsense", [{"if_index": 2, "device": "igb1", "name": "LAN"}])
    await db.upsert_flow_exporter(FIREWALL_IP, "netflow_v9", firewall)
    await db.create_flow_records_batch([_flow(FIREWALL_IP, firewall, 2, 1, 4000)])
    result = await get_top_talkers(None, {"kind": "interfaces", "exporter": FIREWALL_IP})  # type: ignore[arg-type]
    by_index = {r["if_index"]: r for r in result["items"]}
    assert by_index[2]["if_name"] == "LAN" and by_index[2]["in_bytes"] == 4000
    assert by_index[1]["if_name"] is None and by_index[1]["out_bytes"] == 4000
