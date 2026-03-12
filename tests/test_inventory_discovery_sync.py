from typing import cast

import netcontrol.app as app_module
import pytest
from fastapi import HTTPException, Request


def test_expand_scan_targets_deduplicates_and_respects_limit():
    targets = app_module._expand_scan_targets(
        ["10.0.0.0/30", "10.0.0.0/29"],
        max_hosts=3,
    )

    assert targets == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


@pytest.mark.asyncio
async def test_sync_group_hosts_adds_updates_and_removes(monkeypatch):
    existing_hosts = [
        {
            "id": 1,
            "group_id": 77,
            "hostname": "old-name",
            "ip_address": "10.1.1.1",
            "device_type": "cisco_ios",
            "status": "online",
        },
        {
            "id": 2,
            "group_id": 77,
            "hostname": "to-remove",
            "ip_address": "10.1.1.2",
            "device_type": "cisco_ios",
            "status": "online",
        },
    ]

    discovered_hosts = [
        {
            "hostname": "new-name",
            "ip_address": "10.1.1.1",
            "device_type": "cisco_xe",
            "status": "online",
        },
        {
            "hostname": "brand-new",
            "ip_address": "10.1.1.3",
            "device_type": "fortinet",
            "status": "online",
        },
    ]

    calls = {
        "add": [],
        "update": [],
        "remove": [],
        "status": [],
    }

    async def fake_get_hosts_for_group(group_id):
        assert group_id == 77
        return existing_hosts

    async def fake_add_host(group_id, hostname, ip_address, device_type):
        calls["add"].append((group_id, hostname, ip_address, device_type))
        return 42

    async def fake_update_host(host_id, hostname, ip_address, device_type):
        calls["update"].append((host_id, hostname, ip_address, device_type))

    async def fake_remove_host(host_id):
        calls["remove"].append(host_id)

    async def fake_update_host_status(host_id, status):
        calls["status"].append((host_id, status))

    monkeypatch.setattr(app_module.db, "get_hosts_for_group", fake_get_hosts_for_group)
    monkeypatch.setattr(app_module.db, "add_host", fake_add_host)
    monkeypatch.setattr(app_module.db, "update_host", fake_update_host)
    monkeypatch.setattr(app_module.db, "remove_host", fake_remove_host)
    monkeypatch.setattr(app_module.db, "update_host_status", fake_update_host_status)

    result = await app_module._sync_group_hosts(77, discovered_hosts, remove_absent=True)

    assert result["added"] == 1
    assert result["updated"] == 1
    assert result["removed"] == 1
    assert result["matched"] == 2
    assert result["existing_before"] == 2
    assert result["existing_after"] == 2

    assert calls["update"] == [(1, "new-name", "10.1.1.1", "cisco_xe")]
    assert calls["add"] == [(77, "brand-new", "10.1.1.3", "fortinet")]
    assert calls["remove"] == [2]
    assert calls["status"] == [(1, "online"), (42, "online")]


def test_sanitize_discovery_sync_config_filters_invalid_profiles():
    config = app_module._sanitize_discovery_sync_config(
        {
            "enabled": True,
            "interval_seconds": 10,
            "profiles": [
                {"group_id": 4, "cidrs": ["10.20.0.0/24"], "remove_absent": True},
                {"group_id": "bad", "cidrs": ["10.30.0.0/24"]},
                {"group_id": 7, "cidrs": []},
            ],
        }
    )

    assert config["enabled"] is True
    assert config["interval_seconds"] == app_module.DISCOVERY_SYNC_MIN_INTERVAL_SECONDS
    assert len(config["profiles"]) == 1
    assert config["profiles"][0]["group_id"] == 4
    assert config["profiles"][0]["remove_absent"] is True


@pytest.mark.asyncio
async def test_run_discovery_sync_once_runs_profiles(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "DISCOVERY_SYNC_CONFIG",
        {
            "enabled": True,
            "interval_seconds": 900,
            "profiles": [{"group_id": 9, "cidrs": ["10.9.0.0/24"], "remove_absent": False}],
        },
    )

    async def fake_get_group(group_id):
        assert group_id == 9
        return {"id": 9, "name": "edge"}

    async def fake_discover(_body, group_id=None):
        assert group_id == 9
        return 2, [{"hostname": "edge-a", "ip_address": "10.9.0.10", "device_type": "unknown", "status": "online"}]

    async def fake_sync_group_hosts(group_id, discovered_hosts, remove_absent=False):
        assert group_id == 9
        assert len(discovered_hosts) == 1
        assert remove_absent is False
        return {"added": 1, "updated": 0, "removed": 0}

    monkeypatch.setattr(app_module.db, "get_group", fake_get_group)
    monkeypatch.setattr(app_module, "_discover_hosts", fake_discover)
    monkeypatch.setattr(app_module, "_sync_group_hosts", fake_sync_group_hosts)

    result = await app_module._run_discovery_sync_once()
    assert result["enabled"] is True
    assert result["profiles"] == 1
    assert result["synced_groups"] == 1
    assert result["errors"] == 0


def test_sanitize_snmp_discovery_config_bounds_and_defaults():
    cfg = app_module._sanitize_snmp_discovery_config(
        {
            "enabled": True,
            "version": "3",
            "port": 99999,
            "timeout_seconds": 0.01,
            "retries": 9,
            "v3": {
                "username": "ops",
                "auth_protocol": "invalid",
                "auth_password": "authpass",
                "priv_protocol": "invalid",
                "priv_password": "privpass",
            },
        }
    )

    assert cfg["enabled"] is True
    assert cfg["version"] == "3"
    assert cfg["port"] == 65535
    assert cfg["timeout_seconds"] >= 0.2
    assert cfg["retries"] == 5
    assert cfg["v3"]["auth_protocol"] == "sha"
    assert cfg["v3"]["priv_protocol"] == "aes128"


def test_resolve_snmp_discovery_config_prefers_group_profile(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "SNMP_DISCOVERY_CONFIG",
        app_module._sanitize_snmp_discovery_config(
            {
                "enabled": True,
                "version": "2c",
                "community": "global-public",
                "port": 161,
                "timeout_seconds": 1.2,
                "retries": 0,
            }
        ),
    )
    monkeypatch.setattr(
        app_module,
        "SNMP_DISCOVERY_PROFILES",
        {
            5: app_module._sanitize_snmp_discovery_profile(
                5,
                {
                    "enabled": True,
                    "version": "3",
                    "community": "",
                    "v3": {
                        "username": "siteops",
                        "auth_protocol": "sha",
                        "auth_password": "x",
                        "priv_protocol": "aes256",
                        "priv_password": "y",
                    },
                },
            )
        },
    )

    effective = app_module._resolve_snmp_discovery_config(5)
    assert effective["version"] == "3"
    assert effective["v3"]["username"] == "siteops"

    fallback = app_module._resolve_snmp_discovery_config(99)
    assert fallback["version"] == "2c"
    assert fallback["community"] == "global-public"


@pytest.mark.asyncio
async def test_discovery_onboard_returns_sync_summary(monkeypatch):
    async def fake_get_group(group_id):
        assert group_id == 22
        return {"id": 22, "name": "distribution"}

    async def fake_sync_group_hosts(group_id, discovered_hosts, remove_absent=False):
        assert group_id == 22
        assert remove_absent is False
        assert len(discovered_hosts) == 1
        return {"added": 1, "updated": 0, "removed": 0}

    async def fake_audit(*_args, **_kwargs):
        return None

    class DummyRequest:
        def __init__(self):
            self.cookies = {}
            self.state = type("S", (), {"correlation_id": "corr-1"})()

    monkeypatch.setattr(app_module.db, "get_group", fake_get_group)
    monkeypatch.setattr(app_module, "_sync_group_hosts", fake_sync_group_hosts)
    monkeypatch.setattr(app_module, "_audit", fake_audit)

    body = app_module.DiscoveryOnboardRequest(
        discovered_hosts=[{"hostname": "sw1", "ip_address": "10.0.0.10", "device_type": "cisco_ios"}]
    )
    result = await app_module.discovery_onboard(22, body, cast(Request, DummyRequest()))
    assert result["group_id"] == 22
    assert result["provided_count"] == 1
    assert result["sync"]["added"] == 1


@pytest.mark.asyncio
async def test_discovery_onboard_rejects_empty_payload(monkeypatch):
    async def fake_get_group(_group_id):
        return {"id": 22, "name": "distribution"}

    class DummyRequest:
        def __init__(self):
            self.cookies = {}
            self.state = type("S", (), {"correlation_id": "corr-1"})()

    monkeypatch.setattr(app_module.db, "get_group", fake_get_group)

    with pytest.raises(HTTPException) as exc:
        await app_module.discovery_onboard(
            22,
            app_module.DiscoveryOnboardRequest(discovered_hosts=[]),
            cast(Request, DummyRequest()),
        )
    assert exc.value.status_code == 400
