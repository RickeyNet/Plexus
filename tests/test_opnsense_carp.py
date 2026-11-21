"""Tests for OPNsense CARP high availability: tracked state, failover alerts
and the CARP pair on the Topology map.

Covers, with no network access (snapshots built from ``opnsense.sample``):
  * normalize  - the snapshot's ``ha`` block: one record per interface and
                 VHID (several addresses on one VHID), the role and status of
                 MASTER, BACKUP, INIT, DISABLED, a demotion, maintenance mode,
                 CARP not collected; the CARP warning is informational
  * tracking   - CARP groups as ``link`` entities with stable ids, against
                 the database: a baseline raises nothing, INIT alerts on the
                 firewall's inventory host, recovery, removal of a VIP gone
                 at a clean collection
  * failover   - MASTER to BACKUP and back raises a warning (notification
                 channels without a host, a monitoring alert with one, not
                 duplicated while unacknowledged), first sight and a role
                 from INIT or missing raise none, mutes are honoured
  * map        - pair detection (pair, no pair, same VHID with another
                 address, three sources, one firewall added twice), the
                 merged graph (one box, one HA link and its display status,
                 the firewall collapsed into an inventory host) and the HTML
                 export conversion

Every name and address is invented (example.com, documentation ranges).
"""

from __future__ import annotations

import netcontrol.app as app_module  # noqa: F401 - the app the database belongs to
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module
from netcontrol.integrations.availability import clean_entity_types, extract_entity_states
from netcontrol.integrations.meraki.unified import graph_to_snapshot, merge_meraki_into_graph
from netcontrol.integrations.opnsense.ha import carp_pairs
from netcontrol.integrations.opnsense.normalize import build_snapshot, carp_groups
from netcontrol.integrations.opnsense.sample import build_sample_raw

T0 = "2026-01-01 00:00:00"
T1 = "2026-01-02 00:00:00"
T2 = "2026-01-03 00:00:00"
T3 = "2026-01-04 00:00:00"
T4 = "2026-01-05 00:00:00"

HOST_A = "fw-edge-1.example.com"
HOST_B = "fw-edge-2.example.com"
FW_A = f"d:{HOST_A}"
FW_B = f"d:{HOST_B}"
LAN, WAN = "carp:lan:1", "carp:wan:2"


def _raw(
    roles: tuple[str, str] = ("MASTER", "MASTER"),
    *,
    host: str = HOST_A,
    name: str = "Edge A",
    demotion: str = "0",
    maintenance: bool = False,
) -> dict:
    """The sample firewall's collection with CARP roles of its own (lan VHID
    1, wan VHID 2), host name, source name, demotion and maintenance mode."""
    raw = build_sample_raw()
    raw["system"]["name"] = host
    raw["firewall"]["name"] = name
    for row, role in zip(raw["carp"]["rows"], roles, strict=True):
        row.update(status=role, status_txt=role)
    raw["carp"]["carp"].update(demotion=demotion, maintenancemode=maintenance)
    return raw


def _snap(roles: tuple[str, str] = ("MASTER", "MASTER"), **kwargs) -> dict:
    return build_snapshot(_raw(roles, **kwargs))


def _carp(snapshot: dict, org_ref: int = 1) -> dict:
    return {e.entity_id: e for e in extract_entity_states("opnsense", org_ref, snapshot) if e.model == "CARP"}


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


# ── The ha block and the entity states ───────────────────────────────────────


def test_ha_block_holds_one_record_per_carp_group():
    snapshot = _snap(("MASTER", "BACKUP"))
    ha = snapshot["ha"]
    assert ha["protocol"] == "CARP" and ha["device"] == FW_A
    assert ha["demotion"] == 0 and ha["maintenance"] is False
    assert [(v["id"], v["addresses"], v["role"], v["status"]) for v in ha["vips"]] == [
        (LAN, ["192.0.2.3"], "MASTER", "online"),
        (WAN, ["203.0.113.11"], "BACKUP", "online"),
    ]
    assert snapshot["summary"]["carp_vips"] == 2
    # The High availability table is still there.
    titles = [s["title"] for s in _node(snapshot, FW_A)["sections"]]
    assert "High availability" in titles


@pytest.mark.parametrize(
    ("role", "state"),
    [("MASTER", "up"), ("BACKUP", "up"), ("INIT", "down"), ("DISABLED", "degraded"), ("SOMETHING", "unknown")],
)
def test_each_role_maps_to_a_state(role, state):
    entity = _carp(_snap((role, "MASTER")))[LAN]
    assert entity.state == state and entity.raw_status == role.lower()
    assert entity.meta["role"] == role.lower()


@pytest.mark.parametrize("kwargs", [{"demotion": "240"}, {"maintenance": True}])
def test_demotion_or_maintenance_degrades_master_and_backup(kwargs):
    states = {k: e.state for k, e in _carp(_snap(("MASTER", "BACKUP"), **kwargs)).items()}
    assert states == {LAN: "degraded", WAN: "degraded"}
    # INIT stays down whatever the demotion.
    assert _carp(_snap(("INIT", "BACKUP"), **kwargs))[LAN].state == "down"


def test_carp_not_collected_tracks_nothing():
    raw = _raw()
    raw["carp"] = None
    snapshot = build_snapshot(raw)
    assert "ha" not in snapshot and _carp(snapshot) == {}
    assert carp_groups(None) == [] and carp_groups({"rows": [{"vhid": ""}]}) == []


def test_several_addresses_on_one_vhid_are_one_entity():
    raw = _raw()
    raw["carp"]["rows"].append(
        {"interface": "lan", "vhid": "1", "subnet": "192.0.2.4", "status": "BACKUP", "mode": "ipalias"}
    )
    entities = _carp(build_snapshot(raw))
    assert sorted(entities) == [LAN, WAN]
    lan = entities[LAN]
    # The CARP address's role wins over the IP alias on its VHID.
    assert lan.meta["addresses"] == ["192.0.2.3", "192.0.2.4"] and lan.raw_status == "master"
    assert lan.name == f"{HOST_A} CARP lan VHID 1 (192.0.2.3, 192.0.2.4)"


def test_entities_are_links_of_the_firewall_with_stable_ids():
    first = _snap(("MASTER", "MASTER"))
    _node(first, FW_A)["inventory"] = {"host_id": 77}
    entities = _carp(first, 5)
    lan = entities[LAN]
    assert lan.entity_type == "link" and lan.model == "CARP" and lan.host_id == 77
    assert lan.site == "Edge A" and lan.meta["a"] == FW_A and lan.meta["vhid"] == "1"
    assert lan.meta["interface"] == "lan" and lan.meta["advbase"] == "1" and lan.meta["advskew"] == "0"
    # Another collection, other roles: the same ids.
    assert sorted(_carp(_snap(("BACKUP", "INIT")), 5)) == sorted(entities)


def test_carp_warning_is_informational_and_keeps_the_collection_clean():
    snapshot = _snap(("MASTER", "INIT"), demotion="240")
    warnings = [w for w in snapshot["collection"]["errors"] if w["scope"] == "ha"]
    assert len(warnings) == 2 and all(w.get("info") for w in warnings)
    assert "link" in clean_entity_types("opnsense", snapshot)


def test_failovers_compare_roles_with_the_stored_state():
    def entity(role: str, entity_id: str = LAN) -> dict:
        return {"entity_type": "link", "entity_id": entity_id, "meta": {"role": role}}

    def row(raw_status: str, entity_id: str = LAN) -> dict:
        return {"entity_type": "link", "entity_id": entity_id, "raw_status": raw_status}

    found = tracking.failovers([entity("backup"), entity("master", WAN)], [row("master"), row("master", WAN)])
    assert [(f["entity_id"], f["old_role"], f["new_role"]) for f in found] == [(LAN, "master", "backup")]
    assert tracking.failovers([entity("master")], []) == []  # first sight
    assert tracking.failovers([entity("master")], [row("init")]) == []
    assert tracking.failovers([entity("master")], [row("")]) == []  # was missing
    assert tracking.failovers([entity("init")], [row("master")]) == []
    # An entity with no role is never a failover.
    assert tracking.failovers([{"entity_type": "link", "entity_id": LAN, "meta": {}}], [row("master")]) == []


# ── Tracking against the database ────────────────────────────────────────────


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def _host(group_id: int, host_id: int) -> int:
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (?, ?)", (group_id, f"carp-{group_id}"))
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type) VALUES (?, ?, ?, ?, 'opnsense')",
            (host_id, group_id, HOST_A, "192.0.2.1"),
        )
        await db.commit()
    finally:
        await db.close()
    return host_id


def _on_host(snapshot: dict, host_id: int) -> dict:
    _node(snapshot, FW_A)["inventory"] = {"host_id": host_id}
    return snapshot


async def _states(org_ref: int) -> dict:
    return {
        r["entity_id"]: r
        for r in await db_module.list_topology_entity_states("opnsense", org_ref, "link")
        if r["model"] == "CARP"
    }


async def test_tracker_round_trip_alerts_on_the_host_recovers_and_removes(notifications):
    host_id = await _host(7101, 71011)
    org = 7101
    first = await tracking.record_snapshot_states("opnsense", org, _on_host(_snap(), host_id), now=T0)
    assert first["alerts"] == [] and notifications == []  # baseline
    assert {k: r["state"] for k, r in (await _states(org)).items()} == {LAN: "up", WAN: "up"}

    await tracking.record_snapshot_states("opnsense", org, _on_host(_snap(("MASTER", "INIT")), host_id), now=T1)
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert [(a["dedup_key"], a["severity"]) for a in alerts] == [(f"topo:opnsense:{org}:link:{WAN}", "critical")]
    assert "is down (was up)" in alerts[0]["message"] and "VHID 2" in alerts[0]["message"]

    back = await tracking.record_snapshot_states("opnsense", org, _on_host(_snap(), host_id), now=T2)
    assert [t["entity_id"] for t in back["recoveries"]] == [WAN]

    # A clean collection without the wan VIP removes it (the CARP warning
    # no longer blocks removals).
    gone = _on_host(_snap(), host_id)
    gone["ha"]["vips"] = [v for v in gone["ha"]["vips"] if v["id"] != WAN]
    result = await tracking.record_snapshot_states("opnsense", org, gone, now=T3)
    assert result["removed"] == 1 and sorted(await _states(org)) == [LAN]


async def test_init_warning_does_not_keep_a_gone_gateway(notifications):
    org = 7102
    await tracking.record_snapshot_states("opnsense", org, _snap(), now=T0)
    gone = _snap(("MASTER", "INIT"))
    gone["edges"] = [e for e in gone["edges"] if e["kind"] != "uplink" or "WAN2_GW" not in e["a"]]
    result = await tracking.record_snapshot_states("opnsense", org, gone, now=T1)
    assert result["removed"] == 1


async def test_failover_alerts_go_to_the_channels_both_ways(notifications):
    org = 7103
    await tracking.record_snapshot_states("opnsense", org, _snap(("MASTER", "MASTER")), now=T0)
    assert notifications == []
    result = await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "MASTER")), now=T1)
    assert [(f["entity_id"], f["old_role"], f["new_role"]) for f in result["failovers"]] == [(LAN, "master", "backup")]
    # Both roles are healthy: no state transition, one failover warning.
    assert result["transitions"] == [] and result["alerted"] == 1
    (event,) = notifications
    assert event["severity"] == "warning" and event["alert_type"] == "topology_availability"
    assert event["host_id"] is None and event["dedup_key"] == f"topo:opnsense:{org}:link:{LAN}:failover:backup"
    assert event["message"] == (
        f"{HOST_A} CARP lan VHID 1 (192.0.2.3) at Edge A (OPNsense Edge A) failed over: MASTER to BACKUP"
    )
    # Unchanged: nothing more. Back to MASTER: alerts again.
    await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "MASTER")), now=T2)
    assert len(notifications) == 1
    await tracking.record_snapshot_states("opnsense", org, _snap(("MASTER", "MASTER")), now=T3)
    assert [e["dedup_key"].rsplit(":", 1)[1] for e in notifications] == ["backup", "master"]
    assert "BACKUP to MASTER" in notifications[1]["message"]


async def test_first_sight_init_and_missing_raise_no_failover(notifications):
    org = 7104
    first = await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "BACKUP")), now=T0)
    assert first["failovers"] == [] and notifications == []
    # From INIT: the state alert and its recovery, never a failover.
    await tracking.record_snapshot_states("opnsense", org, _snap(("INIT", "BACKUP")), now=T1)
    assert [e["dedup_key"] for e in notifications] == [f"topo:opnsense:{org}:link:{LAN}"]
    back = await tracking.record_snapshot_states("opnsense", org, _snap(("MASTER", "BACKUP")), now=T2)
    assert back["failovers"] == [] and len(notifications) == 1
    # Missing (a failed call), then back in the other role: no failover.
    missing = _snap(("MASTER", "BACKUP"))
    missing["ha"]["vips"] = []
    missing["collection"]["errors"].append({"scope": "ha", "path": "/x", "message": "timeout"})
    await tracking.record_snapshot_states("opnsense", org, missing, now=T3)
    again = await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "MASTER")), now=T4)
    assert again["failovers"] == [] and len(notifications) == 1


async def test_muted_failover_raises_nothing(notifications):
    org = 7105
    await tracking.record_snapshot_states("opnsense", org, _snap(), now=T0)
    await db_module.create_topology_mute(
        "opnsense", org, "entity", entity_type="link", entity_id=LAN, reason="maintenance", created_by="admin"
    )
    result = await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "MASTER")), now=T1)
    assert len(result["failovers"]) == 1 and result["muted_alerts"] == 1 and notifications == []
    # Muting the firewall covers its CARP groups too (meta "a").
    await db_module.create_topology_mute(
        "opnsense", org, "entity", entity_type="device", entity_id=FW_A, reason="maintenance", created_by="admin"
    )
    result = await tracking.record_snapshot_states("opnsense", org, _snap(("BACKUP", "BACKUP")), now=T2)
    assert len(result["failovers"]) == 1 and result["muted_alerts"] == 1 and notifications == []


async def test_failover_on_a_host_is_not_duplicated_while_unacknowledged(notifications):
    host_id = await _host(7106, 71061)
    org = 7106

    async def collect(roles: tuple[str, str], now: str) -> None:
        await tracking.record_snapshot_states("opnsense", org, _on_host(_snap(roles), host_id), now=now)

    await collect(("MASTER", "MASTER"), T0)
    await collect(("BACKUP", "MASTER"), T1)
    await collect(("MASTER", "MASTER"), T2)
    await collect(("BACKUP", "MASTER"), T3)
    alerts = {a["dedup_key"]: a for a in await db_module.get_monitoring_alerts(host_id=host_id)}
    backup, master = (f"topo:opnsense:{org}:link:{LAN}:failover:{r}" for r in ("backup", "master"))
    assert sorted(alerts) == sorted([backup, master])
    assert alerts[backup]["occurrence_count"] == 2 and alerts[backup]["severity"] == "warning"
    assert notifications == []  # the monitoring alert's own hook notifies
    # Muting the entity acknowledges its open failover alerts.
    mute = await db_module.create_topology_mute(
        "opnsense", org, "entity", entity_type="link", entity_id=LAN, reason="maintenance", created_by="admin"
    )
    assert await tracking.mute_entities(mute) == 2
    assert await db_module.delete_topology_mute(mute["id"])
    # Acknowledged: the next failover into BACKUP is a new alert.
    await collect(("MASTER", "MASTER"), T4)
    await collect(("BACKUP", "MASTER"), "2026-01-06 00:00:00")
    open_alerts = [a for a in await db_module.get_monitoring_alerts(host_id=host_id) if not a["acknowledged"]]
    assert sorted(a["dedup_key"] for a in open_alerts) == sorted([backup, master])


# ── The pair on the map ──────────────────────────────────────────────────────


def _pair(roles_a=("MASTER", "MASTER"), roles_b=("BACKUP", "BACKUP")) -> list[tuple[int, dict]]:
    return [(1, _snap(roles_a)), (2, _snap(roles_b, host=HOST_B, name="Edge B"))]


def test_two_sources_sharing_a_vip_are_a_pair():
    (pair,) = carp_pairs(_pair())
    assert pair["id"] == "opnsense-ha:1:2" and pair["name"] == "Edge A / Edge B (CARP)"
    assert [(m["org_ref"], m["node_id"], m["role"]) for m in pair["members"]] == [
        (1, FW_A, "MASTER"),
        (2, FW_B, "BACKUP"),
    ]
    assert [(v["vhid"], v["address"], v["roles"]) for v in pair["vips"]] == [
        ("1", "192.0.2.3", ["MASTER", "BACKUP"]),
        ("2", "203.0.113.11", ["MASTER", "BACKUP"]),
    ]
    assert pair["status"] == "active"


@pytest.mark.parametrize(
    ("roles_a", "roles_b", "status"),
    [
        (("MASTER", "BACKUP"), ("BACKUP", "MASTER"), "active"),
        (("MASTER", "INIT"), ("BACKUP", "MASTER"), "active"),
        (("MASTER", "MASTER"), ("MASTER", "BACKUP"), "failed"),  # split brain on VHID 1
        (("BACKUP", "MASTER"), ("BACKUP", "BACKUP"), "failed"),  # no master on VHID 1
    ],
)
def test_pair_status_needs_exactly_one_master_per_vip(roles_a, roles_b, status):
    (pair,) = carp_pairs(_pair(roles_a, roles_b))
    assert pair["status"] == status


def test_no_pair_without_a_shared_vhid_and_address():
    lone = [(1, _snap())]
    assert carp_pairs(lone) == []
    other = _snap(host=HOST_B)
    for vip in other["ha"]["vips"]:
        vip["vhid"] = str(int(vip["vhid"]) + 10)
    assert carp_pairs([*lone, (2, other)]) == []
    # The same VHID with another address is another CARP group.
    moved = _snap(host=HOST_B)
    for vip in moved["ha"]["vips"]:
        vip["addresses"] = ["198.51.100.9"]
    assert carp_pairs([*lone, (2, moved)]) == []
    # One firewall added as two sources is no pair; nor is a non-OPNsense snapshot.
    assert carp_pairs([*lone, (2, _snap(("BACKUP", "BACKUP")))]) == []
    assert carp_pairs([*lone, (2, {**_snap(host=HOST_B), "provider": "meraki"})]) == []


def test_three_sources_sharing_a_vip_are_left_alone():
    three = [*_pair(), (3, _snap(host="fw-edge-3.example.com", name="Edge C"))]
    assert carp_pairs(three) == []


def _merged(snapshots, **kwargs) -> tuple[dict, list[dict]]:
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes,
        edges,
        snapshots,
        host_node=kwargs.pop("host_node", lambda _id: None),
        resolve_external=lambda *_: None,
        **kwargs,
    )
    return nodes, edges


def test_merged_graph_draws_the_pair_in_one_box_with_one_ha_link():
    snapshots = _pair(("MASTER", "MASTER"), ("MASTER", "BACKUP"))
    nodes, edges = _merged(snapshots)
    fw_a, fw_b = nodes[f"meraki:1:{FW_A}"], nodes[f"meraki:2:{FW_B}"]
    for snapshot_ref, (org_ref, snapshot) in zip((fw_a, fw_b), snapshots, strict=True):
        site = snapshot_ref["meraki"]["site_id"]
        members = [n for n in nodes.values() if n["meraki"]["org_ref"] == org_ref and n["meraki"]["site_id"] == site]
        # The firewall, its gateway stubs and OpenVPN servers.
        assert {n["meraki"]["kind"] for n in members} >= {"appliance", "wan", "vpn_server"}
        assert {(n["meraki"]["box"], n["meraki"]["box_name"]) for n in members} == {
            ("opnsense-ha:1:2", "Edge A / Edge B (CARP)")
        }
    # VPN peers keep their own box.
    assert not any(n["meraki"].get("box") for n in nodes.values() if n["meraki"]["kind"] == "vpn_peer")
    assert fw_a["meraki"]["ha_peer"] == HOST_B and fw_b["meraki"]["ha_peer"] == HOST_A
    (ha,) = [e for e in edges if e["protocol"] == "stack"]
    assert (ha["from"], ha["to"], ha["provider"]) == (fw_a["id"], fw_b["id"], "opnsense")
    # Split brain on VHID 1: shown failed (display only).
    assert ha["status"] == "failed" and ha["label"] == "MASTER -- mixed"

    _nodes, edges = _merged(_pair())
    assert [e["status"] for e in edges if e["protocol"] == "stack"] == ["active"]
    # Only one firewall of the pair is a source: nothing changes.
    nodes, edges = _merged(_pair()[:1])
    assert not any(n["meraki"].get("box") for n in nodes.values())
    assert not any(e["protocol"] == "stack" for e in edges)


def test_pair_is_drawn_when_a_firewall_is_an_inventory_host():
    host = {"id": 42, "label": HOST_A, "in_inventory": True, "group_name": "Firewalls"}
    graph_nodes: dict = {}

    def host_node(host_id: int) -> dict | None:
        if host_id != 42:
            return None
        return graph_nodes.setdefault(42, dict(host))

    edges: list[dict] = []
    merge_meraki_into_graph(
        graph_nodes,
        edges,
        _pair(),
        host_node=host_node,
        resolve_external=lambda *_: None,
        match_host=lambda org_ref, node: 42 if (org_ref, node["id"]) == (1, FW_A) else None,
    )
    collapsed = graph_nodes[42]
    assert collapsed["meraki"]["box"] == "opnsense-ha:1:2" and collapsed["meraki"]["ha_peer"] == HOST_B
    (ha,) = [e for e in edges if e["protocol"] == "stack"]
    assert {ha["from"], ha["to"]} == {42, f"meraki:2:{FW_B}"}


def test_html_export_puts_the_pair_in_one_site_with_its_ha_link():
    snapshots = _pair()
    nodes, edges = _merged(snapshots)
    exported = graph_to_snapshot({"nodes": list(nodes.values()), "edges": edges}, dict(snapshots), {})
    by_id = {n["id"]: n for n in exported["nodes"]}
    site_a, site_b = by_id[f"meraki:1:{FW_A}"]["site"], by_id[f"meraki:2:{FW_B}"]["site"]
    assert site_a == site_b == "box:opnsense-ha:1:2"
    site = next(s for s in exported["sites"] if s["id"] == site_a)
    assert site["name"] == "Edge A / Edge B (CARP)" and site["device_count"] >= 2
    assert by_id[f"meraki:1:{FW_A}"]["topo"]["meraki"]["box"] == "opnsense-ha:1:2"
    assert [e["kind"] for e in exported["edges"] if e["protocol"] == "stack"] == ["stack"]
