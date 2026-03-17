"""Topology feature tests.

Covers:
  1. _parse_cdp_address helper (binary → IPv4, hex fallback, bad input)
  2. _build_snmp_auth with v2c and v3 configs
  3. _discover_neighbors orchestration with mocked SNMP walks
  4. Topology DB CRUD (upsert, get, delete, resolve)
  5. GET /api/topology graph response structure
  6. POST /api/topology/discover/{group_id} with serialized DB writes
  7. GET /api/topology/host/{host_id}
"""

from __future__ import annotations

import asyncio
import socket
from typing import cast
from unittest.mock import AsyncMock, patch

import netcontrol.app as app_module
import netcontrol.routes.snmp as snmp_module
import netcontrol.routes.state as state_module
import netcontrol.routes.topology as topology_module
import netcontrol.routes.inventory as inventory_module
import pytest
import routes.database as db_module
from fastapi import Request


# ── Helpers ──────────────────────────────────────────────────────────────────


class DummyRequest:
    def __init__(self):
        self.cookies = {}
        self.state = type("S", (), {"correlation_id": "test-corr"})()


# ═════════════════════════════════════════════════════════════════════════════
# 1. _parse_cdp_address
# ═════════════════════════════════════════════════════════════════════════════


def test_parse_cdp_address_ipv4():
    """4-byte binary should convert to dotted IPv4."""
    raw = bytes([10, 0, 1, 1])
    assert app_module._parse_cdp_address(raw) == "10.0.1.1"


def test_parse_cdp_address_ipv4_zeros():
    raw = bytes([0, 0, 0, 0])
    assert app_module._parse_cdp_address(raw) == "0.0.0.0"


def test_parse_cdp_address_non_4byte_returns_hex():
    """Non-4-byte binary should return hex string."""
    raw = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01])
    assert app_module._parse_cdp_address(raw) == "deadbeef01"


def test_parse_cdp_address_bad_input_returns_str():
    """Non-bytes input should return str() fallback."""
    assert app_module._parse_cdp_address("not-binary") == "not-binary"


def test_parse_cdp_address_empty_bytes():
    raw = bytes([])
    result = app_module._parse_cdp_address(raw)
    assert result == ""  # empty hex


# ═════════════════════════════════════════════════════════════════════════════
# 2. _build_snmp_auth
# ═════════════════════════════════════════════════════════════════════════════


def test_build_snmp_auth_disabled():
    result = app_module._build_snmp_auth({"enabled": False})
    assert result is None


def test_build_snmp_auth_v2c():
    cfg = {"enabled": True, "version": "2c", "community": "public", "port": 161,
           "timeout_seconds": 2.0, "retries": 1}
    result = app_module._build_snmp_auth(cfg)
    if not app_module.PYSMNP_AVAILABLE:
        assert result is None
        return
    assert result is not None
    auth_data, version, port, timeout, retries = result
    assert version == "2c"
    assert port == 161
    assert retries == 1


def test_build_snmp_auth_v2c_empty_community():
    cfg = {"enabled": True, "version": "2c", "community": "", "port": 161,
           "timeout_seconds": 2.0, "retries": 0}
    result = app_module._build_snmp_auth(cfg)
    if not app_module.PYSMNP_AVAILABLE:
        assert result is None
        return
    assert result is None


def test_build_snmp_auth_v3():
    cfg = {
        "enabled": True, "version": "3", "port": 161,
        "timeout_seconds": 2.0, "retries": 0,
        "v3": {
            "username": "admin",
            "auth_protocol": "sha",
            "auth_password": "authpass",
            "priv_protocol": "aes128",
            "priv_password": "privpass",
        },
    }
    result = app_module._build_snmp_auth(cfg)
    if not app_module.PYSMNP_AVAILABLE:
        assert result is None
        return
    assert result is not None
    _, version, _, _, _ = result
    assert version == "3"


def test_build_snmp_auth_v3_missing_username():
    cfg = {
        "enabled": True, "version": "3", "port": 161,
        "timeout_seconds": 2.0, "retries": 0,
        "v3": {"username": "", "auth_password": "pass"},
    }
    result = app_module._build_snmp_auth(cfg)
    if not app_module.PYSMNP_AVAILABLE:
        assert result is None
        return
    assert result is None


# ═════════════════════════════════════════════════════════════════════════════
# 3. _discover_neighbors (mocked SNMP walks)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_discover_neighbors_cdp(monkeypatch):
    """CDP discovery should parse ifName + CDP tables into neighbor dicts."""
    cdp_device_id_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    cdp_address_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
    cdp_port_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
    cdp_platform_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

    walk_responses = {
        "1.3.6.1.2.1.31.1.1.1.1": {
            "1.3.6.1.2.1.31.1.1.1.1.1": "GigabitEthernet0/1",
            "1.3.6.1.2.1.31.1.1.1.1.2": "GigabitEthernet0/2",
        },
        cdp_device_id_base: {
            f"{cdp_device_id_base}.1.1": "switch-b.example.com",
        },
        cdp_address_base: {
            f"{cdp_address_base}.1.1": bytes([192, 168, 1, 2]),
        },
        cdp_port_base: {
            f"{cdp_port_base}.1.1": "Gi0/1",
        },
        cdp_platform_base: {
            f"{cdp_platform_base}.1.1": "cisco WS-C3750",
        },
        # LLDP tables — empty
        "1.0.8802.1.1.2.1.4.1.1.9": {},
        "1.0.8802.1.1.2.1.4.1.1.7": {},
        "1.0.8802.1.1.2.1.4.1.1.8": {},
        "1.0.8802.1.1.2.1.4.1.1.10": {},
        "1.0.8802.1.1.2.1.4.2.1.4": {},
    }

    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=10, ip_address="10.0.0.1",
        snmp_config={"enabled": True, "version": "2c", "community": "public"},
        timeout_seconds=2.0,
    )

    assert len(neighbors) == 1
    n = neighbors[0]
    assert n["source_host_id"] == 10
    assert n["source_ip"] == "10.0.0.1"
    assert n["local_interface"] == "GigabitEthernet0/1"
    assert n["remote_device_name"] == "switch-b.example.com"
    assert n["remote_ip"] == "192.168.1.2"
    assert n["remote_interface"] == "Gi0/1"
    assert n["protocol"] == "cdp"
    assert n["remote_platform"] == "cisco WS-C3750"


@pytest.mark.asyncio
async def test_discover_neighbors_lldp(monkeypatch):
    """LLDP discovery should produce neighbor entries when CDP is empty."""
    lldp_sys_name_base = "1.0.8802.1.1.2.1.4.1.1.9"
    lldp_port_id_base = "1.0.8802.1.1.2.1.4.1.1.7"
    lldp_port_desc_base = "1.0.8802.1.1.2.1.4.1.1.8"
    lldp_sys_desc_base = "1.0.8802.1.1.2.1.4.1.1.10"

    walk_responses = {
        "1.3.6.1.2.1.31.1.1.1.1": {
            "1.3.6.1.2.1.31.1.1.1.1.3": "eth0",
        },
        # CDP — empty
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8": {},
        # LLDP entries indexed by timeMark.localPortNum.index
        lldp_sys_name_base: {
            f"{lldp_sys_name_base}.0.3.1": "router-a",
        },
        lldp_port_id_base: {
            f"{lldp_port_id_base}.0.3.1": "ge-0/0/0",
        },
        lldp_port_desc_base: {
            f"{lldp_port_desc_base}.0.3.1": "uplink",
        },
        lldp_sys_desc_base: {
            f"{lldp_sys_desc_base}.0.3.1": "Juniper JunOS",
        },
        "1.0.8802.1.1.2.1.4.2.1.4": {},
    }

    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=20, ip_address="10.0.0.2",
        snmp_config={"enabled": True},
        timeout_seconds=2.0,
    )

    assert len(neighbors) == 1
    n = neighbors[0]
    assert n["protocol"] == "lldp"
    assert n["remote_device_name"] == "router-a"
    assert n["local_interface"] == "eth0"
    # LLDP uses port_desc ("uplink") over port_id ("ge-0/0/0") when both present
    assert n["remote_interface"] == "uplink"


@pytest.mark.asyncio
async def test_discover_neighbors_empty_walks(monkeypatch):
    """No neighbors found should return empty list."""
    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return {}

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=1, ip_address="10.0.0.1",
        snmp_config={"enabled": True},
        timeout_seconds=2.0,
    )
    assert neighbors == []


@pytest.mark.asyncio
async def test_discover_neighbors_ospf(monkeypatch):
    """OSPF neighbor discovery should produce entries with protocol=ospf."""
    ospf_rtr_id_base = "1.3.6.1.2.1.14.10.1.3"
    ospf_state_base = "1.3.6.1.2.1.14.10.1.6"

    walk_responses = {
        # ifName — empty (no L2 data needed for OSPF)
        "1.3.6.1.2.1.31.1.1.1.1": {},
        # CDP — empty
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8": {},
        # LLDP — empty
        "1.0.8802.1.1.2.1.4.1.1.9": {},
        "1.0.8802.1.1.2.1.4.1.1.7": {},
        "1.0.8802.1.1.2.1.4.1.1.8": {},
        "1.0.8802.1.1.2.1.4.1.1.10": {},
        "1.0.8802.1.1.2.1.4.2.1.4": {},
        # OSPF neighbor table
        ospf_rtr_id_base: {
            f"{ospf_rtr_id_base}.10.0.0.2.0": "1.1.1.2",
        },
        ospf_state_base: {
            f"{ospf_state_base}.10.0.0.2.0": "8",
        },
        # BGP — empty
        "1.3.6.1.2.1.15.3.1.2": {},
        "1.3.6.1.2.1.15.3.1.9": {},
    }

    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=1, ip_address="10.0.0.1",
        snmp_config={"enabled": True},
        timeout_seconds=2.0,
    )

    assert len(neighbors) == 1
    n = neighbors[0]
    assert n["protocol"] == "ospf"
    assert n["remote_ip"] == "10.0.0.2"
    assert n["remote_device_name"] == "1.1.1.2"  # router ID


@pytest.mark.asyncio
async def test_discover_neighbors_bgp(monkeypatch):
    """BGP peer discovery should produce entries with protocol=bgp."""
    bgp_state_base = "1.3.6.1.2.1.15.3.1.2"
    bgp_as_base = "1.3.6.1.2.1.15.3.1.9"

    walk_responses = {
        "1.3.6.1.2.1.31.1.1.1.1": {},
        # CDP — empty
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7": {},
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8": {},
        # LLDP — empty
        "1.0.8802.1.1.2.1.4.1.1.9": {},
        "1.0.8802.1.1.2.1.4.1.1.7": {},
        "1.0.8802.1.1.2.1.4.1.1.8": {},
        "1.0.8802.1.1.2.1.4.1.1.10": {},
        "1.0.8802.1.1.2.1.4.2.1.4": {},
        # OSPF — empty
        "1.3.6.1.2.1.14.10.1.3": {},
        "1.3.6.1.2.1.14.10.1.6": {},
        # BGP peer table
        bgp_state_base: {
            f"{bgp_state_base}.172.16.0.2": "6",
        },
        bgp_as_base: {
            f"{bgp_as_base}.172.16.0.2": "65001",
        },
    }

    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=1, ip_address="10.0.0.1",
        snmp_config={"enabled": True},
        timeout_seconds=2.0,
    )

    assert len(neighbors) == 1
    n = neighbors[0]
    assert n["protocol"] == "bgp"
    assert n["remote_ip"] == "172.16.0.2"
    assert n["remote_device_name"] == "AS65001"
    assert "AS 65001" in n["remote_platform"]


@pytest.mark.asyncio
async def test_discover_neighbors_deduplicates_cdp_lldp(monkeypatch):
    """Same neighbor on same interface via both CDP and LLDP should keep CDP."""
    cdp_device_id_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    lldp_sys_name_base = "1.0.8802.1.1.2.1.4.1.1.9"

    walk_responses = {
        "1.3.6.1.2.1.31.1.1.1.1": {
            "1.3.6.1.2.1.31.1.1.1.1.1": "Gi0/1",
        },
        cdp_device_id_base: {
            f"{cdp_device_id_base}.1.1": "peer-switch",
        },
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4": {
            "1.3.6.1.4.1.9.9.23.1.2.1.1.4.1.1": bytes([10, 0, 0, 5]),
        },
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7": {
            "1.3.6.1.4.1.9.9.23.1.2.1.1.7.1.1": "Gi0/2",
        },
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8": {},
        lldp_sys_name_base: {
            f"{lldp_sys_name_base}.0.1.1": "peer-switch",
        },
        "1.0.8802.1.1.2.1.4.1.1.7": {
            "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": "Gi0/2",
        },
        "1.0.8802.1.1.2.1.4.1.1.8": {},
        "1.0.8802.1.1.2.1.4.1.1.10": {},
        "1.0.8802.1.1.2.1.4.2.1.4": {},
    }

    async def fake_snmp_walk(ip, timeout, cfg, base_oid, max_rows=500):
        return walk_responses.get(base_oid, {})

    monkeypatch.setattr(app_module, "_snmp_walk", fake_snmp_walk)
    monkeypatch.setattr(snmp_module, "_snmp_walk", fake_snmp_walk)

    neighbors, _if_stats = await app_module._discover_neighbors(
        host_id=1, ip_address="10.0.0.1",
        snmp_config={"enabled": True},
        timeout_seconds=2.0,
    )

    # Should have CDP entry; LLDP duplicate filtered out
    cdp_entries = [n for n in neighbors if n["protocol"] == "cdp"]
    lldp_entries = [n for n in neighbors if n["protocol"] == "lldp"]
    assert len(cdp_entries) >= 1
    # LLDP for same peer on same local interface should be deduplicated
    for lldp in lldp_entries:
        matching_cdp = [c for c in cdp_entries
                        if c["remote_device_name"] == lldp["remote_device_name"]
                        and c["local_interface"] == lldp["local_interface"]]
        assert len(matching_cdp) == 0, "LLDP duplicate of CDP entry should be filtered"


# ═════════════════════════════════════════════════════════════════════════════
# 4. Topology DB CRUD
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture
async def topo_db(tmp_path, monkeypatch):
    """Set up a fresh SQLite DB with schema for topology tests."""
    db_path = str(tmp_path / "topo_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    # Insert a group and two hosts for FK references
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-core-01', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (200, 1, 'sw-dist-01', '10.0.1.2', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()

    return db_path


@pytest.mark.asyncio
async def test_upsert_and_get_topology_link(topo_db):
    link_id = await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="10.0.1.2", target_device_name="sw-dist-01",
        target_interface="Gi0/1", protocol="cdp",
        target_platform="WS-C3750",
    )
    assert link_id > 0

    links = await db_module.get_topology_links()
    assert len(links) == 1
    assert links[0]["source_host_id"] == 100
    assert links[0]["target_device_name"] == "sw-dist-01"
    assert links[0]["protocol"] == "cdp"


@pytest.mark.asyncio
async def test_upsert_topology_link_deduplicates(topo_db):
    """Upserting same source+interface+target should update, not duplicate."""
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="10.0.1.2", target_device_name="sw-dist-01",
        target_interface="Gi0/1", protocol="cdp",
    )
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="10.0.1.99", target_device_name="sw-dist-01",
        target_interface="Gi0/1", protocol="lldp",
    )
    links = await db_module.get_topology_links()
    assert len(links) == 1
    # Should have the updated values
    assert links[0]["target_ip"] == "10.0.1.99"
    assert links[0]["protocol"] == "lldp"


@pytest.mark.asyncio
async def test_get_topology_links_filter_by_group(topo_db):
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="10.0.1.2", target_device_name="sw-dist-01",
        target_interface="Gi0/1",
    )
    # Group 1 should return the link
    links = await db_module.get_topology_links(group_id=1)
    assert len(links) == 1

    # Group 999 should return nothing
    links = await db_module.get_topology_links(group_id=999)
    assert len(links) == 0


@pytest.mark.asyncio
async def test_get_topology_links_for_host(topo_db):
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=200,
        target_ip="10.0.1.2", target_device_name="sw-dist-01",
        target_interface="Gi0/1",
    )
    # Source host
    links = await db_module.get_topology_links_for_host(100)
    assert len(links) == 1
    # Target host
    links = await db_module.get_topology_links_for_host(200)
    assert len(links) == 1
    # Unrelated host
    links = await db_module.get_topology_links_for_host(999)
    assert len(links) == 0


@pytest.mark.asyncio
async def test_delete_topology_links_for_host(topo_db):
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="", target_device_name="peer-a",
        target_interface="eth0",
    )
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/2", target_host_id=None,
        target_ip="", target_device_name="peer-b",
        target_interface="eth0",
    )
    deleted = await db_module.delete_topology_links_for_host(100)
    assert deleted == 2
    links = await db_module.get_topology_links()
    assert len(links) == 0


@pytest.mark.asyncio
async def test_delete_all_topology_links(topo_db):
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="", target_device_name="a",
        target_interface="eth0",
    )
    await db_module.upsert_topology_link(
        source_host_id=200, source_ip="10.0.1.2",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="", target_device_name="b",
        target_interface="eth0",
    )
    deleted = await db_module.delete_all_topology_links()
    assert deleted == 2


@pytest.mark.asyncio
async def test_resolve_topology_target_host_ids(topo_db):
    """resolve should match target_ip to hosts.ip_address."""
    await db_module.upsert_topology_link(
        source_host_id=100, source_ip="10.0.1.1",
        source_interface="Gi0/1", target_host_id=None,
        target_ip="10.0.1.2", target_device_name="sw-dist-01",
        target_interface="Gi0/1",
    )
    resolved = await db_module.resolve_topology_target_host_ids()
    assert resolved >= 1

    links = await db_module.get_topology_links()
    assert links[0]["target_host_id"] == 200


# ═════════════════════════════════════════════════════════════════════════════
# 5. GET /api/topology graph response
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_topology_builds_graph(monkeypatch):
    """get_topology should produce nodes + edges from DB links."""
    fake_links = [
        {
            "id": 1,
            "source_host_id": 10,
            "target_host_id": None,
            "target_device_name": "ext-switch",
            "target_ip": "172.16.0.1",
            "target_platform": "cisco WS-C2960",
            "source_interface": "Gi0/1",
            "target_interface": "Gi0/2",
            "protocol": "cdp",
        },
    ]
    fake_hosts = [
        {
            "id": 10, "hostname": "core-sw", "ip_address": "10.0.0.1",
            "device_type": "cisco_ios", "group_id": 1, "status": "online",
        },
    ]
    fake_groups = [{"id": 1, "name": "Core"}]

    monkeypatch.setattr(app_module.db, "get_topology_links", AsyncMock(return_value=fake_links))
    monkeypatch.setattr(app_module.db, "get_hosts_by_ids", AsyncMock(return_value=fake_hosts))
    monkeypatch.setattr(app_module.db, "get_all_groups", AsyncMock(return_value=fake_groups))
    monkeypatch.setattr(app_module.db, "get_interface_stats_by_hosts", AsyncMock(return_value=[]))
    monkeypatch.setattr(app_module.db, "get_topology_changes_count", AsyncMock(return_value=0))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    result = await topology_module.get_topology(group_id=None)

    assert "nodes" in result
    assert "edges" in result
    assert len(result["edges"]) == 1

    # Should have 2 nodes: inventory host + external neighbor
    node_ids = {n["id"] for n in result["nodes"]}
    assert 10 in node_ids
    assert "ext_ext-switch" in node_ids

    ext_node = next(n for n in result["nodes"] if n["id"] == "ext_ext-switch")
    assert ext_node["in_inventory"] is False
    assert ext_node["label"] == "ext-switch"

    inv_node = next(n for n in result["nodes"] if n["id"] == 10)
    assert inv_node["in_inventory"] is True
    assert inv_node["group_name"] == "Core"

    edge = result["edges"][0]
    assert edge["from"] == 10
    assert edge["to"] == "ext_ext-switch"
    assert edge["label"] == "Gi0/1 -- Gi0/2"


@pytest.mark.asyncio
async def test_get_topology_empty(monkeypatch):
    """Empty links should return empty nodes and edges."""
    monkeypatch.setattr(app_module.db, "get_topology_links", AsyncMock(return_value=[]))
    monkeypatch.setattr(app_module.db, "get_hosts_by_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr(app_module.db, "get_all_groups", AsyncMock(return_value=[]))
    monkeypatch.setattr(app_module.db, "get_interface_stats_by_hosts", AsyncMock(return_value=[]))
    monkeypatch.setattr(app_module.db, "get_topology_changes_count", AsyncMock(return_value=0))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    result = await topology_module.get_topology(group_id=None)
    assert result == {"nodes": [], "edges": [], "unacknowledged_changes": 0}


# ═════════════════════════════════════════════════════════════════════════════
# 6. POST /api/topology/discover/{group_id}
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_discover_topology_for_group_serializes_writes(monkeypatch):
    """Discovery should do concurrent SNMP walks then sequential DB writes."""
    fake_group = {"id": 1, "name": "core"}
    fake_hosts = [
        {"id": 100, "hostname": "sw1", "ip_address": "10.0.0.1", "device_type": "cisco_ios", "status": "online"},
        {"id": 200, "hostname": "sw2", "ip_address": "10.0.0.2", "device_type": "cisco_ios", "status": "online"},
    ]

    monkeypatch.setattr(app_module.db, "get_group", AsyncMock(return_value=fake_group))
    monkeypatch.setattr(app_module.db, "get_hosts_for_group", AsyncMock(return_value=fake_hosts))
    resolve_snmp_fn = lambda gid: {"enabled": True, "version": "2c", "community": "public"}
    monkeypatch.setattr(app_module, "_resolve_snmp_discovery_config", resolve_snmp_fn)
    monkeypatch.setattr(state_module, "_resolve_snmp_discovery_config", resolve_snmp_fn)

    # Track call order to verify sequential DB writes
    call_log = []

    async def fake_discover(host_id, ip, cfg, timeout_seconds=5.0):
        call_log.append(("discover", host_id))
        neighbors = [{"source_host_id": host_id, "source_ip": ip,
                       "local_interface": "Gi0/1", "remote_device_name": f"peer-{host_id}",
                       "remote_ip": "", "remote_interface": "eth0",
                       "protocol": "cdp", "remote_platform": ""}]
        return neighbors, []  # (neighbors, if_stats)

    async def fake_delete(host_id):
        call_log.append(("delete", host_id))
        return 0

    async def fake_upsert(**kwargs):
        call_log.append(("upsert", kwargs["source_host_id"]))
        return 1

    async def fake_resolve():
        call_log.append(("resolve",))
        return 0

    monkeypatch.setattr(app_module, "_discover_neighbors", fake_discover)
    monkeypatch.setattr(topology_module, "_discover_neighbors", fake_discover)
    monkeypatch.setattr(app_module.db, "delete_topology_links_for_host", fake_delete)
    monkeypatch.setattr(app_module.db, "upsert_topology_link", fake_upsert)
    monkeypatch.setattr(app_module.db, "resolve_topology_target_host_ids", fake_resolve)
    monkeypatch.setattr(app_module.db, "get_topology_links_for_host", AsyncMock(return_value=[]))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    result = await topology_module.discover_topology_for_group(1)

    assert result["hosts_scanned"] == 2
    assert result["links_discovered"] == 2
    assert result["errors"] == 0

    # DB writes (delete/upsert) should come AFTER all discovers
    discover_indices = [i for i, entry in enumerate(call_log) if entry[0] == "discover"]
    db_write_indices = [i for i, entry in enumerate(call_log) if entry[0] in ("delete", "upsert")]
    assert max(discover_indices) < min(db_write_indices), \
        "All SNMP walks should complete before any DB writes"


@pytest.mark.asyncio
async def test_discover_topology_for_group_handles_snmp_errors(monkeypatch):
    """Hosts that fail SNMP should be counted as errors, not crash."""
    monkeypatch.setattr(app_module.db, "get_group", AsyncMock(return_value={"id": 1, "name": "core"}))
    monkeypatch.setattr(app_module.db, "get_hosts_for_group", AsyncMock(return_value=[
        {"id": 100, "hostname": "sw1", "ip_address": "10.0.0.1", "device_type": "cisco_ios", "status": "online"},
    ]))
    resolve_snmp_fn = lambda gid: {"enabled": True, "version": "2c", "community": "public"}
    monkeypatch.setattr(app_module, "_resolve_snmp_discovery_config", resolve_snmp_fn)
    monkeypatch.setattr(state_module, "_resolve_snmp_discovery_config", resolve_snmp_fn)

    async def failing_discover(*args, **kwargs):
        raise TimeoutError("SNMP timeout")

    monkeypatch.setattr(app_module, "_discover_neighbors", failing_discover)
    monkeypatch.setattr(topology_module, "_discover_neighbors", failing_discover)
    monkeypatch.setattr(app_module.db, "resolve_topology_target_host_ids", AsyncMock(return_value=0))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    result = await topology_module.discover_topology_for_group(1)
    assert result["errors"] == 1
    assert result["links_discovered"] == 0


# ═════════════════════════════════════════════════════════════════════════════
# 7. GET /api/topology/host/{host_id}
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_host_topology(monkeypatch):
    fake_host = {"id": 100, "hostname": "sw1", "ip_address": "10.0.0.1"}
    fake_links = [
        {"id": 1, "source_host_id": 100, "target_device_name": "peer",
         "source_interface": "Gi0/1", "target_interface": "eth0", "protocol": "cdp"},
    ]

    monkeypatch.setattr(app_module.db, "get_host", AsyncMock(return_value=fake_host))
    monkeypatch.setattr(app_module.db, "get_topology_links_for_host", AsyncMock(return_value=fake_links))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    result = await topology_module.get_host_topology(100)
    assert result["host"]["hostname"] == "sw1"
    assert len(result["links"]) == 1


@pytest.mark.asyncio
async def test_get_host_topology_not_found(monkeypatch):
    monkeypatch.setattr(app_module.db, "get_host", AsyncMock(return_value=None))
    monkeypatch.setattr(topology_module, "db", app_module.db)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await topology_module.get_host_topology(999)
    assert exc.value.status_code == 404
