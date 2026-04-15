"""STP topology collection/storage tests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import routes.database as db_module

import netcontrol.routes.state as state_module
import netcontrol.routes.topology as topology_module


@pytest.fixture
async def stp_db(tmp_path, monkeypatch):
    """Create a temporary DB with one group and one host."""
    db_path = str(tmp_path / "stp_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-core-01', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stp_port_state_upsert_and_get(stp_db):
    """STP port state upsert should deduplicate by host/vlan/bridge_port."""
    await db_module.upsert_stp_port_state(
        host_id=100,
        vlan_id=1,
        bridge_port=1,
        if_index=10101,
        interface_name="GigabitEthernet1/0/1",
        port_state="forwarding",
        port_role="root",
        designated_bridge_id="0x8000001122334455",
        root_bridge_id="0x8000001122334455",
        root_port=1,
        topology_change_count=4,
        time_since_topology_change=12,
        is_root_bridge=False,
    )
    # Update same row
    await db_module.upsert_stp_port_state(
        host_id=100,
        vlan_id=1,
        bridge_port=1,
        if_index=10101,
        interface_name="Gi1/0/1",
        port_state="blocking",
        port_role="blocked",
        designated_bridge_id="0x8000001122334455",
        root_bridge_id="0x8000001122334455",
        root_port=1,
        topology_change_count=5,
        time_since_topology_change=13,
        is_root_bridge=False,
    )

    rows = await db_module.get_stp_port_states(host_id=100, vlan_id=1, limit=100)
    assert len(rows) == 1
    assert rows[0]["port_state"] == "blocking"
    assert rows[0]["port_role"] == "blocked"
    assert rows[0]["topology_change_count"] == 5


@pytest.mark.asyncio
async def test_stp_topology_events_acknowledge(stp_db):
    """STP events should be queryable and acknowledgeable."""
    await db_module.insert_stp_topology_event(
        host_id=100,
        vlan_id=1,
        event_type="root_changed",
        severity="critical",
        interface_name="",
        details="root changed",
        old_value="old",
        new_value="new",
    )
    count = await db_module.get_stp_topology_events_count(unacknowledged_only=True)
    assert count == 1

    rows = await db_module.get_stp_topology_events(unacknowledged_only=True, limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "root_changed"
    recent = await db_module.count_recent_stp_topology_events(
        host_id=100,
        vlan_id=1,
        event_type="root_changed",
        within_minutes=60,
    )
    assert recent == 1

    acked = await db_module.acknowledge_stp_topology_events()
    assert acked == 1
    count_after = await db_module.get_stp_topology_events_count(unacknowledged_only=True)
    assert count_after == 0


@pytest.mark.asyncio
async def test_collect_stp_snapshot_for_host(monkeypatch):
    """Bridge-MIB walk data should parse into STP port rows with roles/states."""
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"
    if_descr_oid = "1.3.6.1.2.1.2.2.1.2"
    base_port_ifindex_oid = "1.3.6.1.2.1.17.1.4.1.2"
    stp_port_state_oid = "1.3.6.1.2.1.17.2.15.1.3"
    stp_port_designated_bridge_oid = "1.3.6.1.2.1.17.2.15.1.8"
    designated_root_oid = "1.3.6.1.2.1.17.2.5"
    root_port_oid = "1.3.6.1.2.1.17.2.7"
    top_changes_oid = "1.3.6.1.2.1.17.2.4"
    time_since_oid = "1.3.6.1.2.1.17.2.3"

    walk_responses = {
        if_name_oid: {
            f"{if_name_oid}.10101": "GigabitEthernet1/0/1",
            f"{if_name_oid}.10102": "GigabitEthernet1/0/2",
        },
        if_descr_oid: {},
        base_port_ifindex_oid: {
            f"{base_port_ifindex_oid}.1": "10101",
            f"{base_port_ifindex_oid}.2": "10102",
        },
        stp_port_state_oid: {
            f"{stp_port_state_oid}.1": "5",  # forwarding
            f"{stp_port_state_oid}.2": "2",  # blocking
        },
        stp_port_designated_bridge_oid: {
            f"{stp_port_designated_bridge_oid}.1": "0x8000001122334455",
            f"{stp_port_designated_bridge_oid}.2": "0x8000001122334455",
        },
        designated_root_oid: {f"{designated_root_oid}.0": "0x8000001122334455"},
        root_port_oid: {f"{root_port_oid}.0": "1"},
        top_changes_oid: {f"{top_changes_oid}.0": "7"},
        time_since_oid: {f"{time_since_oid}.0": "42"},
    }

    async def fake_walk(ip, timeout_s, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(topology_module, "_snmp_walk", fake_walk)

    snapshot = await topology_module._collect_stp_snapshot_for_host(
        {"id": 100, "hostname": "sw-core-01", "ip_address": "10.0.1.1"},
        {"enabled": True, "version": "2c", "community": "public"},
        vlan_id=1,
    )

    assert snapshot["root_port"] == 1
    assert snapshot["topology_change_count"] == 7
    assert len(snapshot["ports"]) == 2

    by_bridge_port = {row["bridge_port"]: row for row in snapshot["ports"]}
    assert by_bridge_port[1]["port_state"] == "forwarding"
    assert by_bridge_port[1]["port_role"] == "root"
    assert by_bridge_port[2]["port_state"] == "blocking"
    assert by_bridge_port[2]["port_role"] == "blocked"


def test_snmp_cfg_for_vlan_appends_vlan_to_v2c_community():
    cfg = {"enabled": True, "version": "2c", "community": "public"}
    out = topology_module._snmp_cfg_for_vlan(cfg, vlan_id=20)
    assert out["community"] == "public@20"
    # original object should not be mutated
    assert cfg["community"] == "public"


@pytest.mark.asyncio
async def test_discover_vlan_ids_for_host_from_qbridge(monkeypatch):
    base_oid = "1.3.6.1.2.1.17.7.1.4.3.1.1"

    async def fake_walk(ip, timeout_s, cfg, oid, max_rows=500):
        assert oid == base_oid
        return {
            f"{base_oid}.1": "default",
            f"{base_oid}.10": "users",
            f"{base_oid}.20": "voice",
            f"{base_oid}.4095": "reserved",  # ignored
        }

    monkeypatch.setattr(topology_module, "_snmp_walk", fake_walk)
    vlans = await topology_module._discover_vlan_ids_for_host(
        "10.0.1.1",
        {"enabled": True, "version": "2c", "community": "public"},
        max_vlans=16,
    )
    assert vlans == [1, 10, 20]


@pytest.mark.asyncio
async def test_record_stp_events_creates_storm_and_root_instability(monkeypatch):
    old_rows = [
        {
            "bridge_port": 1,
            "port_state": "forwarding",
            "port_role": "root",
            "root_bridge_id": "0x8000001111111111",
            "topology_change_count": 5,
        },
    ]
    snapshot = {
        "vlan_id": 1,
        "root_bridge_id": "0x8000002222222222",
        "topology_change_count": 20,
        "time_since_topology_change": 100,  # centiseconds (1 second)
        "ports": [
            {
                "bridge_port": 1,
                "interface_name": "Gi1/0/1",
                "port_state": "blocking",
                "port_role": "blocked",
            },
        ],
    }

    insert_event_mock = AsyncMock(return_value=1)
    create_alert_mock = AsyncMock(return_value=1)
    count_recent_mock = AsyncMock(return_value=topology_module.STP_ROOT_CHANGE_ANOMALY_THRESHOLD)

    monkeypatch.setattr(topology_module.db, "insert_stp_topology_event", insert_event_mock)
    monkeypatch.setattr(topology_module.db, "create_monitoring_alert", create_alert_mock)
    monkeypatch.setattr(topology_module.db, "count_recent_stp_topology_events", count_recent_mock)

    await topology_module._record_stp_events_for_host(
        {"id": 100, "hostname": "sw-core-01"},
        vlan_id=1,
        old_rows=old_rows,
        snapshot=snapshot,
    )

    called_event_types = [call.kwargs["event_type"] for call in insert_event_mock.await_args_list]
    assert "root_changed" in called_event_types
    assert "root_election_instability" in called_event_types
    assert "topology_change" in called_event_types
    assert "topology_change_storm" in called_event_types
    assert "port_state_change" in called_event_types
    assert create_alert_mock.await_count >= 2


@pytest.mark.asyncio
async def test_discover_topology_stp_route(monkeypatch):
    """STP discovery endpoint should collect and upsert per-host rows."""
    fake_group = {"id": 1, "name": "core"}
    fake_hosts = [
        {"id": 100, "hostname": "sw-core-01", "ip_address": "10.0.1.1", "group_id": 1},
    ]
    fake_snapshot = {
        "host_id": 100,
        "hostname": "sw-core-01",
        "ip_address": "10.0.1.1",
        "vlan_id": 1,
        "root_bridge_id": "0x8000001122334455",
        "root_port": 1,
        "topology_change_count": 9,
        "time_since_topology_change": 20,
        "is_root_bridge": False,
        "ports": [
            {
                "host_id": 100,
                "vlan_id": 1,
                "bridge_port": 1,
                "if_index": 10101,
                "interface_name": "Gi1/0/1",
                "port_state": "forwarding",
                "port_role": "root",
                "designated_bridge_id": "0x8000001122334455",
                "root_bridge_id": "0x8000001122334455",
                "root_port": 1,
                "topology_change_count": 9,
                "time_since_topology_change": 20,
                "is_root_bridge": False,
            },
            {
                "host_id": 100,
                "vlan_id": 1,
                "bridge_port": 2,
                "if_index": 10102,
                "interface_name": "Gi1/0/2",
                "port_state": "blocking",
                "port_role": "blocked",
                "designated_bridge_id": "0x8000001122334455",
                "root_bridge_id": "0x8000001122334455",
                "root_port": 1,
                "topology_change_count": 9,
                "time_since_topology_change": 20,
                "is_root_bridge": False,
            },
        ],
    }

    monkeypatch.setattr(topology_module.db, "get_group", AsyncMock(return_value=fake_group))
    monkeypatch.setattr(topology_module.db, "get_hosts_for_group", AsyncMock(return_value=fake_hosts))
    monkeypatch.setattr(topology_module.db, "get_stp_port_states", AsyncMock(return_value=[]))
    monkeypatch.setattr(topology_module.db, "delete_stp_port_states_for_host", AsyncMock(return_value=0))
    upsert_mock = AsyncMock(return_value=1)
    monkeypatch.setattr(topology_module.db, "upsert_stp_port_state", upsert_mock)
    monkeypatch.setattr(topology_module.db, "get_stp_topology_events_count", AsyncMock(return_value=2))
    monkeypatch.setattr(topology_module, "_record_stp_events_for_host", AsyncMock(return_value=None))
    monkeypatch.setattr(topology_module, "_collect_stp_snapshot_for_host", AsyncMock(return_value=fake_snapshot))

    def _resolve_snmp(_group_id):
        return {"enabled": True, "version": "2c", "community": "public"}

    monkeypatch.setattr(state_module, "_resolve_snmp_discovery_config", _resolve_snmp)
    monkeypatch.setattr(topology_module.state, "_resolve_snmp_discovery_config", _resolve_snmp)

    result = await topology_module.discover_topology_stp(group_id=1, vlan_id=1)
    assert result["hosts_scanned"] == 1
    assert result["hosts_updated"] == 1
    assert result["ports_collected"] == 2
    assert result["errors"] == 0
    assert upsert_mock.await_count == 2


@pytest.mark.asyncio
async def test_discover_topology_stp_route_all_vlans(monkeypatch):
    fake_hosts = [{"id": 100, "hostname": "sw-core-01", "ip_address": "10.0.1.1", "group_id": 1}]
    monkeypatch.setattr(topology_module.db, "get_all_groups", AsyncMock(return_value=[{"id": 1, "name": "core"}]))
    monkeypatch.setattr(topology_module.db, "get_hosts_for_group", AsyncMock(return_value=fake_hosts))
    monkeypatch.setattr(topology_module.db, "get_stp_port_states", AsyncMock(return_value=[]))
    monkeypatch.setattr(topology_module.db, "delete_stp_port_states_for_host", AsyncMock(return_value=0))
    monkeypatch.setattr(topology_module.db, "upsert_stp_port_state", AsyncMock(return_value=1))
    monkeypatch.setattr(topology_module.db, "get_stp_topology_events_count", AsyncMock(return_value=0))
    monkeypatch.setattr(topology_module, "_record_stp_events_for_host", AsyncMock(return_value=None))
    monkeypatch.setattr(topology_module, "_discover_vlan_ids_for_host", AsyncMock(return_value=[1, 10]))

    async def fake_collect(host, cfg, vlan_id=1, timeout_seconds=5.0):
        return {
            "host_id": host["id"],
            "vlan_id": vlan_id,
            "topology_change_count": 1,
            "time_since_topology_change": 0,
            "ports": [
                {
                    "host_id": host["id"],
                    "vlan_id": vlan_id,
                    "bridge_port": vlan_id,  # unique per vlan for assertion stability
                    "if_index": 10000 + vlan_id,
                    "interface_name": f"Gi1/0/{vlan_id}",
                    "port_state": "forwarding",
                    "port_role": "designated",
                    "designated_bridge_id": "root",
                    "root_bridge_id": "root",
                    "root_port": 0,
                    "topology_change_count": 1,
                    "time_since_topology_change": 0,
                    "is_root_bridge": True,
                },
            ],
        }

    monkeypatch.setattr(topology_module, "_collect_stp_snapshot_for_host", fake_collect)

    def _resolve_snmp(_group_id):
        return {"enabled": True, "version": "2c", "community": "public"}

    monkeypatch.setattr(state_module, "_resolve_snmp_discovery_config", _resolve_snmp)
    monkeypatch.setattr(topology_module.state, "_resolve_snmp_discovery_config", _resolve_snmp)

    result = await topology_module.discover_topology_stp(vlan_id=1, all_vlans=True, max_vlans=16)
    assert result["hosts_scanned"] == 1
    assert result["hosts_updated"] == 1
    assert result["ports_collected"] == 2
    assert result["all_vlans"] is True
    assert result["vlans_scanned"] == [1, 10]
