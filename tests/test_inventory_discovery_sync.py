from typing import cast

import netcontrol.app as app_module
import netcontrol.routes.inventory as inventory_module
import netcontrol.routes.state as state_module
import pytest
import routes.database as db_module
from fastapi import HTTPException, Request


def _norm(raw: dict) -> dict:
    return inventory_module._normalize_discovered_entry(raw)


# ── Multi-interface device dedup (planner is pure / no I/O) ──────────────────


def test_normalize_entry_identity():
    snmp = _norm({"hostname": "core-rtr", "ip_address": "10.0.0.1",
                  "serial_number": "FOC123", "discovery": {"protocol": "snmpv2c"}})
    assert snmp["sys_name_norm"] == "core-rtr"
    assert snmp["serial"] == "FOC123"
    assert snmp["snmp_reachable"] is True

    # A synthetic fallback name is per-IP, never a device identity.
    fallback = _norm({"hostname": "host-10-0-0-2", "ip_address": "10.0.0.2"})
    assert fallback["sys_name_norm"] == ""
    assert fallback["snmp_reachable"] is False

    # Explicit sys_name wins and is domain-normalized.
    explicit = _norm({"hostname": "x", "ip_address": "10.0.0.3", "sys_name": "Edge.example.com"})
    assert explicit["sys_name_norm"] == "edge"


def test_plan_groups_two_snmp_ips_with_same_sysname():
    d = [
        _norm({"hostname": "rtr", "ip_address": "10.0.0.1", "sys_name": "rtr", "discovery": {"protocol": "snmpv2c"}}),
        _norm({"hostname": "rtr", "ip_address": "10.0.0.2", "sys_name": "rtr", "discovery": {"protocol": "snmpv2c"}}),
    ]
    plan = inventory_module._build_discovery_plan(d, [], {}, {})
    assert len(plan["add"]) == 1
    add = plan["add"][0]
    assert {add["ip"], *add["alias_ips"]} == {"10.0.0.1", "10.0.0.2"}
    assert plan["delete"] == []


def test_plan_pingonly_secondary_grouped_via_interface_table():
    """A ping-only secondary IP (fallback name) is folded into the SNMP device
    because it appears in that device's ipAddrTable."""
    d = [
        _norm({"hostname": "rtr", "ip_address": "10.0.0.1", "sys_name": "rtr", "discovery": {"protocol": "snmpv2c"}}),
        _norm({"hostname": "host-10-0-0-2", "ip_address": "10.0.0.2", "discovery": {"protocol": "icmp"}}),
    ]
    iface = {"10.0.0.1": ["10.0.0.1", "10.0.0.2"]}
    plan = inventory_module._build_discovery_plan(d, [], {}, iface)
    assert len(plan["add"]) == 1
    add = plan["add"][0]
    assert add["ip"] == "10.0.0.1"  # the SNMP IP is canonical
    assert add["alias_ips"] == ["10.0.0.2"]


def test_plan_matches_existing_by_serial():
    d = [_norm({"hostname": "rtr-new", "ip_address": "10.0.0.9", "sys_name": "rtr-new",
                "serial_number": "S1", "discovery": {"protocol": "snmpv2c"}})]
    existing = [{"id": 1, "hostname": "rtr-old", "ip_address": "10.0.0.1",
                 "serial_number": "S1", "device_type": "cisco_ios"}]
    plan = inventory_module._build_discovery_plan(d, existing, {"10.0.0.1": 1}, {})
    assert plan["add"] == []
    assert [u["host_id"] for u in plan["update"]] == [1]
    assert plan["update"][0]["ip"] == "10.0.0.1"  # existing primary IP preserved
    assert "10.0.0.9" in plan["update"][0]["alias_ips"]


def test_plan_suppresses_existing_duplicate_in_interface_table():
    """The classic bug: a second host row whose IP is really a secondary
    interface of the canonical device is deleted (strong evidence)."""
    d = [_norm({"hostname": "rtr", "ip_address": "10.0.0.1", "sys_name": "rtr",
                "discovery": {"protocol": "snmpv2c"}})]
    existing = [
        {"id": 1, "hostname": "rtr", "ip_address": "10.0.0.1", "serial_number": "", "device_type": "cisco_ios"},
        {"id": 2, "hostname": "host-10-0-0-2", "ip_address": "10.0.0.2", "serial_number": "", "device_type": "unknown"},
    ]
    iface = {"10.0.0.1": ["10.0.0.1", "10.0.0.2"]}
    plan = inventory_module._build_discovery_plan(d, existing, {"10.0.0.1": 1, "10.0.0.2": 2}, iface)
    assert [u["host_id"] for u in plan["update"]] == [1]
    assert plan["delete"] == [2]


def test_plan_sysname_match_alone_never_deletes_existing():
    """Without serial or interface-table evidence, sysName similarity must not
    delete a host (default 'Router' names would wrongly merge real devices)."""
    d = [_norm({"hostname": "Router", "ip_address": "10.0.0.1", "sys_name": "Router",
                "discovery": {"protocol": "snmpv2c"}})]
    existing = [
        {"id": 1, "hostname": "Router", "ip_address": "10.0.0.1", "serial_number": "", "device_type": "cisco_ios"},
        {"id": 2, "hostname": "Router", "ip_address": "10.9.9.9", "serial_number": "", "device_type": "cisco_ios"},
    ]
    plan = inventory_module._build_discovery_plan(d, existing, {"10.0.0.1": 1, "10.9.9.9": 2}, {})
    assert plan["delete"] == []


@pytest.fixture
async def inv_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "inv_dedup.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()
    gid = await db_module.create_group("core")
    return gid


@pytest.mark.asyncio
async def test_sync_suppresses_secondary_interface_duplicate(inv_db, monkeypatch):
    """End-to-end: a pre-existing duplicate host that is really a secondary
    interface IP is removed and recorded as an alias on the next sync."""
    gid = inv_db
    canonical = await db_module.add_host(gid, "rtr", "10.0.0.1", "cisco_ios")
    dup = await db_module.add_host(gid, "host-10-0-0-2", "10.0.0.2", "unknown")

    async def fake_noop(*_a, **_k):
        return None

    monkeypatch.setattr(inventory_module, "push_inventory_host_allocation", fake_noop)
    monkeypatch.setattr(
        inventory_module.state, "_resolve_snmp_discovery_config", lambda _g: {"enabled": False}
    )

    async def resolver(_ip):
        return ["10.0.0.1", "10.0.0.2"]

    discovered = [{
        "hostname": "rtr", "ip_address": "10.0.0.1", "device_type": "cisco_ios",
        "status": "online", "sys_name": "rtr", "serial_number": "",
        "discovery": {"protocol": "snmpv2c"},
    }]
    result = await inventory_module._sync_group_hosts(
        gid, discovered, interface_ip_resolver=resolver,
    )

    assert result["removed"] == 1
    hosts = await db_module.get_hosts_for_group(gid)
    assert [h["id"] for h in hosts] == [canonical]   # duplicate gone
    assert dup not in {h["id"] for h in hosts}
    # The duplicate's IP is now resolvable to the canonical host via its alias.
    index = await db_module.get_host_ip_index(gid)
    assert index.get("10.0.0.2") == canonical


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

    async def fake_get_host_ip_index(group_id):
        return {"10.1.1.1": 1, "10.1.1.2": 2}

    async def fake_noop(*_a, **_k):
        return None

    monkeypatch.setattr(app_module.db, "get_hosts_for_group", fake_get_hosts_for_group)
    monkeypatch.setattr(app_module.db, "add_host", fake_add_host)
    monkeypatch.setattr(app_module.db, "update_host", fake_update_host)
    monkeypatch.setattr(app_module.db, "remove_host", fake_remove_host)
    monkeypatch.setattr(app_module.db, "update_host_status", fake_update_host_status)
    monkeypatch.setattr(app_module.db, "get_host_ip_index", fake_get_host_ip_index)
    monkeypatch.setattr(app_module.db, "set_host_ip_aliases", fake_noop)
    monkeypatch.setattr(app_module.db, "update_host_serial", fake_noop)
    monkeypatch.setattr(inventory_module, "push_inventory_host_allocation", fake_noop)
    monkeypatch.setattr(
        state_module, "_resolve_snmp_discovery_config", lambda _gid: {"enabled": False}
    )
    monkeypatch.setattr(inventory_module, "db", app_module.db)

    result = await inventory_module._sync_group_hosts(77, discovered_hosts, remove_absent=True)

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


@pytest.mark.asyncio
async def test_ssh_fallback_does_not_clobber_snmp_confirmed_device_type(monkeypatch):
    """SNMP-loss regression guard.

    When SNMP goes unreachable, discovery falls back to an SSH-banner
    probe.  The banner reveals vendor ("cisco") but not the OS variant,
    so _probe_discovery_target confidently mislabels an IOS-XE Catalyst
    as "cisco_ios".  That wrong-but-specific value must NOT overwrite an
    already-stored, SNMP-confirmed "cisco_xe" - if it did, the upgrade
    route would pick CiscoIOSDriver (no activate command) and every
    upgrade on that box would fail with "Activate not supported".

    Three hosts pin the full contract:
      * .1  established cisco_xe, re-probed via *ssh* as cisco_ios
             -> keep cisco_xe (the bug being fixed)
      * .2  established unknown, re-probed via *ssh* as cisco_ios
             -> accept cisco_ios (ssh may still *fill in* an unknown)
      * .3  established cisco_ios, re-probed via *snmp* as cisco_xe
             -> accept cisco_xe (SNMP is authoritative; real upgrades)
    """
    existing_hosts = [
        {"id": 1, "group_id": 5, "hostname": "cat9k-1", "ip_address": "10.2.2.1",
         "device_type": "cisco_xe", "status": "online"},
        {"id": 2, "group_id": 5, "hostname": "edge-2", "ip_address": "10.2.2.2",
         "device_type": "unknown", "status": "online"},
        {"id": 3, "group_id": 5, "hostname": "cat9k-3", "ip_address": "10.2.2.3",
         "device_type": "cisco_ios", "status": "online"},
    ]
    discovered_hosts = [
        # SNMP down -> SSH banner guessed cisco_ios. Must be ignored.
        {"hostname": "cat9k-1", "ip_address": "10.2.2.1", "device_type": "cisco_ios",
         "status": "online", "discovery": {"protocol": "ssh"}},
        # SSH guess is allowed to resolve a previously-unknown host.
        {"hostname": "edge-2", "ip_address": "10.2.2.2", "device_type": "cisco_ios",
         "status": "online", "discovery": {"protocol": "ssh"}},
        # SNMP came back and authoritatively says XE - must apply.
        {"hostname": "cat9k-3", "ip_address": "10.2.2.3", "device_type": "cisco_xe",
         "status": "online", "discovery": {"protocol": "snmpv2c"}},
    ]

    updates: list[tuple] = []

    async def fake_get_hosts_for_group(group_id):
        return existing_hosts

    async def fake_update_host(host_id, hostname, ip_address, device_type):
        updates.append((host_id, device_type))

    async def fake_noop(*_a, **_k):
        return None

    async def fake_ip_index(_group_id):
        return {"10.2.2.1": 1, "10.2.2.2": 2, "10.2.2.3": 3}

    monkeypatch.setattr(inventory_module.db, "get_hosts_for_group", fake_get_hosts_for_group)
    monkeypatch.setattr(inventory_module.db, "update_host", fake_update_host)
    monkeypatch.setattr(inventory_module.db, "update_host_status", fake_noop)
    monkeypatch.setattr(inventory_module.db, "update_host_device_info", fake_noop)
    monkeypatch.setattr(inventory_module.db, "get_host_ip_index", fake_ip_index)
    monkeypatch.setattr(inventory_module.db, "set_host_ip_aliases", fake_noop)
    monkeypatch.setattr(inventory_module.db, "update_host_serial", fake_noop)
    monkeypatch.setattr(inventory_module, "push_inventory_host_allocation", fake_noop)
    monkeypatch.setattr(
        state_module, "_resolve_snmp_discovery_config", lambda _gid: {"enabled": False}
    )

    await inventory_module._sync_group_hosts(5, discovered_hosts, remove_absent=False)

    by_id = dict(updates)
    # The bug: .1 must stay cisco_xe (no downgrade to the ssh guess).
    assert by_id.get(1, "cisco_xe") == "cisco_xe", (
        "SSH-banner cisco_ios guess clobbered an SNMP-confirmed cisco_xe")
    # .2 was unknown - ssh is allowed to fill it in.
    assert by_id.get(2) == "cisco_ios"
    # .3 - authoritative SNMP reclassification still applies.
    assert by_id.get(3) == "cisco_xe"


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
    sync_cfg = {
        "enabled": True,
        "interval_seconds": 900,
        "profiles": [{"group_id": 9, "cidrs": ["10.9.0.0/24"], "remove_absent": False}],
    }
    monkeypatch.setattr(app_module, "DISCOVERY_SYNC_CONFIG", sync_cfg)
    monkeypatch.setattr(state_module, "DISCOVERY_SYNC_CONFIG", sync_cfg)

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
    monkeypatch.setattr(inventory_module, "db", app_module.db)
    monkeypatch.setattr(app_module, "_discover_hosts", fake_discover)
    monkeypatch.setattr(inventory_module, "_discover_hosts", fake_discover)
    monkeypatch.setattr(app_module, "_sync_group_hosts", fake_sync_group_hosts)
    monkeypatch.setattr(inventory_module, "_sync_group_hosts", fake_sync_group_hosts)

    result = await inventory_module._run_discovery_sync_once()
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
    snmp_cfg = app_module._sanitize_snmp_discovery_config(
        {
            "enabled": True,
            "version": "2c",
            "community": "global-public",
            "port": 161,
            "timeout_seconds": 1.2,
            "retries": 0,
        }
    )
    monkeypatch.setattr(app_module, "SNMP_DISCOVERY_CONFIG", snmp_cfg)
    monkeypatch.setattr(state_module, "SNMP_DISCOVERY_CONFIG", snmp_cfg)
    snmp_profiles = {
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
    }
    monkeypatch.setattr(app_module, "SNMP_DISCOVERY_PROFILES", snmp_profiles)
    monkeypatch.setattr(state_module, "SNMP_DISCOVERY_PROFILES", snmp_profiles)

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
    monkeypatch.setattr(inventory_module, "db", app_module.db)
    monkeypatch.setattr(app_module, "_sync_group_hosts", fake_sync_group_hosts)
    monkeypatch.setattr(inventory_module, "_sync_group_hosts", fake_sync_group_hosts)
    monkeypatch.setattr(app_module, "_audit", fake_audit)
    monkeypatch.setattr(inventory_module, "_audit", fake_audit)

    body = app_module.DiscoveryOnboardRequest(
        discovered_hosts=[{"hostname": "sw1", "ip_address": "10.0.0.10", "device_type": "cisco_ios"}]
    )
    result = await inventory_module.discovery_onboard(22, body, cast(Request, DummyRequest()))
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
    monkeypatch.setattr(inventory_module, "db", app_module.db)

    with pytest.raises(HTTPException) as exc:
        await inventory_module.discovery_onboard(
            22,
            app_module.DiscoveryOnboardRequest(discovered_hosts=[]),
            cast(Request, DummyRequest()),
        )
    assert exc.value.status_code == 400
