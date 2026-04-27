"""Tests for DHCP scope/lease integration (Phase F)."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module
from netcontrol.routes.dhcp import (
    SCOPE_EXHAUSTION_PCT,
    _correlate_leases_to_inventory,
    _scope_utilization_pct,
)
from netcontrol.routes.dhcp_adapters import (
    DhcpAdapterError,
    collect_dhcp_snapshot,
    normalize_dhcp_provider,
)


# ─────────────────────────────────────────────────────────────────────────────
# Pure-function / adapter tests
# ─────────────────────────────────────────────────────────────────────────────


def test_normalize_dhcp_provider_accepts_valid():
    assert normalize_dhcp_provider("kea") == "kea"
    assert normalize_dhcp_provider("WINDOWS") == "windows"
    assert normalize_dhcp_provider(" Infoblox ") == "infoblox"


def test_normalize_dhcp_provider_rejects_invalid():
    with pytest.raises(ValueError):
        normalize_dhcp_provider("dhcpd")


def test_scope_utilization_pct_handles_zero_total():
    assert _scope_utilization_pct({"total_addresses": 0, "used_addresses": 0}) == 0.0


def test_scope_utilization_pct_normal():
    assert _scope_utilization_pct({"total_addresses": 100, "used_addresses": 75}) == 75.0


def test_scope_utilization_threshold_is_90():
    # Sanity check on the alerting threshold
    assert SCOPE_EXHAUSTION_PCT == 90.0


def test_kea_adapter_normalizes_scopes_and_leases():
    server = {"provider": "kea", "base_url": "http://kea.example/", "auth_type": "none", "verify_tls": 1}

    async def _fake_fetch(url, *, method="GET", headers=None, params=None, json_body=None, auth=None, verify=True):
        cmd = (json_body or {}).get("command")
        if cmd == "config-get":
            return [{
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {"id": 1, "subnet": "10.0.0.0/24", "comment": "wired",
                             "pools": [{"pool": "10.0.0.10 - 10.0.0.200"}]},
                        ]
                    }
                }
            }]
        if cmd == "lease4-get-all":
            return [{
                "result": 0,
                "arguments": {
                    "leases": [
                        {"ip-address": "10.0.0.10", "hw-address": "aa:bb:cc:dd:ee:01",
                         "hostname": "host1", "subnet-id": 1, "state": 0},
                        {"ip-address": "10.0.0.11", "hw-address": "aabbccddee02",
                         "hostname": "host2", "subnet-id": 1, "state": 0},
                    ]
                }
            }]
        return {}

    snapshot = asyncio.run(collect_dhcp_snapshot(server, {}, fetch_json=_fake_fetch))
    assert snapshot["summary"]["scope_count"] == 1
    assert snapshot["summary"]["lease_count"] == 2

    scope = snapshot["scopes"][0]
    assert scope["subnet"] == "10.0.0.0/24"
    assert scope["used_addresses"] == 2
    assert scope["range_start"] == "10.0.0.10"
    assert scope["range_end"] == "10.0.0.200"

    leases_by_addr = {l["address"]: l for l in snapshot["leases"]}
    assert leases_by_addr["10.0.0.10"]["mac_address"] == "aa:bb:cc:dd:ee:01"
    # MAC normalized from compact form
    assert leases_by_addr["10.0.0.11"]["mac_address"] == "aa:bb:cc:dd:ee:02"


def test_windows_adapter_calculates_utilization_from_inuse_free():
    server = {"provider": "windows", "base_url": "https://winsrv.example", "auth_type": "none", "verify_tls": 1}

    async def _fake_fetch(url, *, method="GET", headers=None, params=None, json_body=None, auth=None, verify=True):
        if url.endswith("/scopes"):
            return [{
                "ScopeId": "192.168.1.0",
                "SubnetMask": "255.255.255.0",
                "Name": "office",
                "StartRange": "192.168.1.10",
                "EndRange": "192.168.1.250",
                "AddressesInUse": 200,
                "AddressesFree": 41,
                "State": "Active",
            }]
        if url.endswith("/leases"):
            return [{
                "IPAddress": "192.168.1.50",
                "ClientId": "11-22-33-44-55-66",
                "HostName": "laptop",
                "AddressState": "Active",
            }]
        return {}

    snapshot = asyncio.run(collect_dhcp_snapshot(server, {}, fetch_json=_fake_fetch))
    scope = snapshot["scopes"][0]
    assert scope["subnet"] == "192.168.1.0/24"
    assert scope["total_addresses"] == 241
    assert scope["used_addresses"] == 200
    assert scope["free_addresses"] == 41

    lease = snapshot["leases"][0]
    assert lease["address"] == "192.168.1.50"
    assert lease["mac_address"] == "11:22:33:44:55:66"
    assert lease["scope_subnet"] == "192.168.1.0/24"


def test_infoblox_adapter_falls_back_to_subnet_size_when_total_missing():
    server = {"provider": "infoblox", "base_url": "https://ib.example/wapi/v2.10", "auth_type": "none", "verify_tls": 1}

    async def _fake_fetch(url, *, method="GET", headers=None, params=None, json_body=None, auth=None, verify=True):
        if url.endswith("/network"):
            return [{"_ref": "network/abc", "network": "172.16.0.0/24", "comment": "lab"}]
        if url.endswith("/lease"):
            return [{
                "address": "172.16.0.5", "binding_state": "ACTIVE",
                "client_hostname": "tester", "hardware": "ab:cd:ef:01:02:03",
                "network": "172.16.0.0/24",
            }]
        return {}

    snapshot = asyncio.run(collect_dhcp_snapshot(server, {}, fetch_json=_fake_fetch))
    scope = snapshot["scopes"][0]
    # /24 has 256 addresses, minus 2 (network+broadcast) = 254
    assert scope["total_addresses"] == 254
    lease = snapshot["leases"][0]
    assert lease["address"] == "172.16.0.5"
    assert lease["scope_subnet"] == "172.16.0.0/24"


# ─────────────────────────────────────────────────────────────────────────────
# Database integration tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def dhcp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "dhcp.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-dhcp")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


def test_create_and_get_dhcp_server(dhcp_db):
    async def _go():
        server = await db_module.create_dhcp_server(
            provider="kea",
            name="Kea-DC1",
            base_url="http://kea.example/",
            auth_type="none",
            auth_config={},
            enabled=True,
            verify_tls=False,
            created_by="admin",
        )
        assert server is not None
        fetched = await db_module.get_dhcp_server(int(server["id"]))
        assert fetched["name"] == "Kea-DC1"
        assert fetched["provider"] == "kea"
        assert fetched["enabled"] is True
        assert fetched["verify_tls"] is False

    asyncio.run(_go())


def test_replace_dhcp_server_snapshot_persists_scopes_and_leases(dhcp_db):
    async def _go():
        server = await db_module.create_dhcp_server(
            provider="kea", name="Kea-Test", base_url="http://x", auth_type="none",
            auth_config={}, enabled=True,
        )
        sid = int(server["id"])
        result = await db_module.replace_dhcp_server_snapshot(
            sid,
            scopes=[
                {"external_id": "1", "subnet": "10.0.0.0/24", "name": "a",
                 "total_addresses": 254, "used_addresses": 240, "free_addresses": 14},
                {"external_id": "2", "subnet": "10.0.1.0/24", "name": "b",
                 "total_addresses": 254, "used_addresses": 50, "free_addresses": 204},
            ],
            leases=[
                {"address": "10.0.0.5", "scope_subnet": "10.0.0.0/24",
                 "mac_address": "aa:bb:cc:dd:ee:ff", "hostname": "h1", "state": "active"},
            ],
        )
        assert result == {"scopes": 2, "leases": 1}

        scopes = await db_module.list_dhcp_scopes(server_id=sid)
        assert len(scopes) == 2
        leases = await db_module.list_dhcp_leases(server_id=sid)
        assert len(leases) == 1 and leases[0]["address"] == "10.0.0.5"

        srv_after = await db_module.get_dhcp_server(sid)
        assert srv_after["last_sync_status"] == "success"
        assert srv_after["scope_count"] == 2
        assert srv_after["lease_count"] == 1

    asyncio.run(_go())


def test_replace_dhcp_snapshot_clears_previous_rows(dhcp_db):
    async def _go():
        server = await db_module.create_dhcp_server(
            provider="kea", name="Kea-X", base_url="http://x", auth_type="none",
            auth_config={}, enabled=True,
        )
        sid = int(server["id"])
        await db_module.replace_dhcp_server_snapshot(
            sid,
            scopes=[{"subnet": "10.0.0.0/24", "total_addresses": 254, "used_addresses": 1, "free_addresses": 253}],
            leases=[{"address": "10.0.0.1", "scope_subnet": "10.0.0.0/24"}],
        )
        # Replace with empty
        await db_module.replace_dhcp_server_snapshot(sid, scopes=[], leases=[])
        scopes = await db_module.list_dhcp_scopes(server_id=sid)
        leases = await db_module.list_dhcp_leases(server_id=sid)
        assert scopes == [] and leases == []

    asyncio.run(_go())


def test_correlate_leases_to_inventory_classifies_known_and_unknown(dhcp_db):
    async def _go():
        # Seed a host
        d = await db_module.get_db()
        try:
            cursor = await d.execute("INSERT INTO inventory_groups (name) VALUES ('Test')")
            gid = int(cursor.lastrowid)
            await d.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, status) VALUES (?, ?, ?, ?)",
                (gid, "known-host", "10.0.0.5", "online"),
            )
            await d.commit()
        finally:
            await d.close()

        leases = [
            {"address": "10.0.0.5", "mac_address": "aa:bb:cc:dd:ee:01", "hostname": "known-host",
             "scope_subnet": "10.0.0.0/24"},
            {"address": "10.0.0.99", "mac_address": "aa:bb:cc:dd:ee:99", "hostname": "rogue",
             "scope_subnet": "10.0.0.0/24"},
        ]
        result = await _correlate_leases_to_inventory(leases)
        assert len(result["known"]) == 1
        assert result["known"][0]["address"] == "10.0.0.5"
        assert result["known"][0]["inventory_hostname"] == "known-host"
        assert len(result["unknown"]) == 1
        assert result["unknown"][0]["address"] == "10.0.0.99"

    asyncio.run(_go())


def test_delete_dhcp_server_cascades_to_scopes_and_leases(dhcp_db):
    async def _go():
        server = await db_module.create_dhcp_server(
            provider="kea", name="Cascade", base_url="http://x", auth_type="none",
            auth_config={}, enabled=True,
        )
        sid = int(server["id"])
        await db_module.replace_dhcp_server_snapshot(
            sid,
            scopes=[{"subnet": "10.0.0.0/24", "total_addresses": 254, "used_addresses": 1, "free_addresses": 253}],
            leases=[{"address": "10.0.0.1", "scope_subnet": "10.0.0.0/24"}],
        )
        ok = await db_module.delete_dhcp_server(sid)
        assert ok is True
        scopes = await db_module.list_dhcp_scopes(server_id=sid)
        leases = await db_module.list_dhcp_leases(server_id=sid)
        assert scopes == [] and leases == []

    asyncio.run(_go())


def test_kea_adapter_rejects_missing_base_url():
    server = {"provider": "kea", "base_url": "", "auth_type": "none", "verify_tls": 1}

    async def _fake_fetch(*args, **kwargs):
        return {}

    with pytest.raises(DhcpAdapterError):
        asyncio.run(collect_dhcp_snapshot(server, {}, fetch_json=_fake_fetch))
