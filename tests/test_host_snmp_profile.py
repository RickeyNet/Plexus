"""Tests for per-host SNMP profiles (``hosts.snmp_profile_id``).

Covers:
  * resolver - the host's own profile wins over its group's config; an
               empty or stale id falls back to the group
  * API      - create/update a host with a profile (unknown -> 400, None
               leaves it, "" clears it), the bulk assignment route, the
               host SNMP test route, deleting a profile clears its hosts
  * polling  - the monitoring targets, topology discovery and MAC collection
               use each host's effective config, including a host with its
               own profile in a group whose SNMP is disabled
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import netcontrol.routes.inventory as inventory_module
import netcontrol.routes.mac_tracking as mac_tracking
import netcontrol.routes.monitoring as monitoring
import netcontrol.routes.state as state
import netcontrol.routes.topology as topology_module
import pytest
import routes.database as db

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

GROUP_CFG = {"enabled": True, "version": "2c", "community": "group-ro"}
DISABLED_CFG = {"enabled": False}


@pytest.fixture(autouse=True)
def _fresh_snmp_state(monkeypatch):
    """SNMP profiles and their group assignments are process state: start empty."""
    monkeypatch.setattr(state, "SNMP_PROFILES", {})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_PROFILES", {})


def _host_profile(monkeypatch, pid: str = "p-host", community: str = "host-ro") -> dict:
    """Register a host profile in state and return its sanitized config."""
    profiles = dict(state.SNMP_PROFILES)
    profiles[pid] = state._sanitize_snmp_profile(pid, {"name": pid, "enabled": True, "community": community})
    monkeypatch.setattr(state, "SNMP_PROFILES", profiles)
    return state._sanitize_snmp_discovery_config(profiles[pid])


def _message(resp) -> str:
    body = resp.json()
    return str((body.get("error") or {}).get("message") or body.get("detail") or "")


# ── Resolver ─────────────────────────────────────────────────────────────────


def test_host_profile_wins_over_the_group(monkeypatch):
    own = _host_profile(monkeypatch)
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(GROUP_CFG))
    resolved = state._resolve_host_snmp_config({"id": 1, "group_id": 5, "snmp_profile_id": "p-host"})
    assert resolved == own
    assert resolved["community"] == "host-ro"


def test_empty_or_stale_host_profile_falls_back_to_the_group(monkeypatch):
    seen: list = []

    def group_cfg(gid):
        seen.append(gid)
        return dict(GROUP_CFG)

    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", group_cfg)
    assert state._resolve_host_snmp_config({"group_id": 5, "snmp_profile_id": ""}) == GROUP_CFG
    assert state._resolve_host_snmp_config({"group_id": 6, "snmp_profile_id": "gone"}) == GROUP_CFG
    assert state._resolve_host_snmp_config({"group_id": 7}) == GROUP_CFG
    assert seen == [5, 6, 7]


def test_host_profile_beats_a_group_profile_assignment(monkeypatch):
    _host_profile(monkeypatch, "p-host", "host-ro")
    _host_profile(monkeypatch, "p-group", "group-ro")
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {5: "p-group"})
    assert state._resolve_host_snmp_config({"group_id": 5, "snmp_profile_id": "p-host"})["community"] == "host-ro"
    assert state._resolve_host_snmp_config({"group_id": 5, "snmp_profile_id": ""})["community"] == "group-ro"


def test_hosts_with_snmp_config_keeps_an_overriding_host_in_a_disabled_group(monkeypatch):
    own = _host_profile(monkeypatch)
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(DISABLED_CFG))
    hosts = [{"id": 1, "snmp_profile_id": "p-host"}, {"id": 2, "snmp_profile_id": ""}]
    assert state._hosts_with_snmp_config(hosts, 9) == [(hosts[0], own)]
    every = state._hosts_with_snmp_config(hosts, 9, enabled_only=False)
    assert [cfg["enabled"] for _h, cfg in every] == [True, False]


# ── API ──────────────────────────────────────────────────────────────────────


def _profile(client, name: str) -> str:
    created = client.post("/api/admin/snmp-profiles", json={"name": name, "enabled": True, "community": "example-ro"})
    assert created.status_code == 200, created.text
    return created.json()["id"]


def _group(client, name: str = "Lab") -> int:
    resp = client.post("/api/inventory", json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _stored(client, group_id: int) -> dict[str, str]:
    hosts = client.get(f"/api/inventory/{group_id}/hosts").json()
    return {h["hostname"]: h["snmp_profile_id"] for h in hosts}


def test_create_and_update_a_host_with_its_own_profile(api):  # noqa: F811
    pid = _profile(api, "Edge")
    group = _group(api)
    sw1 = {"hostname": "sw1", "ip_address": "192.0.2.11", "device_type": "cisco_ios"}

    bad = api.post(f"/api/inventory/{group}/hosts", json={**sw1, "snmp_profile_id": "no-such-profile"})
    assert bad.status_code == 400 and _message(bad) == "SNMP profile not found"

    created = api.post(f"/api/inventory/{group}/hosts", json={**sw1, "snmp_profile_id": pid})
    assert created.status_code == 201, created.text
    hid = created.json()["id"]
    assert _stored(api, group) == {"sw1": pid}
    # The group listings carry the field too.
    one = api.get(f"/api/inventory/{group}").json()
    assert one["hosts"][0]["snmp_profile_id"] == pid
    listed = api.get("/api/inventory?include_hosts=true").json()
    assert next(g for g in listed if g["id"] == group)["hosts"][0]["snmp_profile_id"] == pid

    # Left out (None): unchanged.
    assert api.put(f"/api/hosts/{hid}", json={**sw1, "hostname": "sw1b"}).status_code == 200
    assert _stored(api, group) == {"sw1b": pid}
    # Unknown: refused, unchanged.
    bad = api.put(f"/api/hosts/{hid}", json={**sw1, "snmp_profile_id": "no-such-profile"})
    assert bad.status_code == 400
    assert _stored(api, group) == {"sw1b": pid}
    # "": back to the group's config.
    assert api.put(f"/api/hosts/{hid}", json={**sw1, "snmp_profile_id": ""}).status_code == 200
    assert _stored(api, group) == {"sw1": ""}


def test_bulk_add_rejects_an_unknown_profile_per_entry(api):  # noqa: F811
    pid = _profile(api, "Edge")
    group = _group(api)
    resp = api.post(
        f"/api/inventory/{group}/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "a", "ip_address": "192.0.2.21", "snmp_profile_id": pid},
                {"hostname": "b", "ip_address": "192.0.2.22", "snmp_profile_id": "no-such-profile"},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [a["hostname"] for a in body["added"]] == ["a"]
    assert body["errors"] == [{"hostname": "b", "ip_address": "192.0.2.22", "error": "SNMP profile not found"}]
    assert _stored(api, group) == {"a": pid}


def test_bulk_snmp_profile_route_sets_and_clears(api):  # noqa: F811
    pid = _profile(api, "Edge")
    group = _group(api)
    ids = [
        api.post(f"/api/inventory/{group}/hosts", json={"hostname": n, "ip_address": ip}).json()["id"]
        for n, ip in (("a", "192.0.2.31"), ("b", "192.0.2.32"), ("c", "192.0.2.33"))
    ]

    resp = api.post("/api/hosts/snmp-profile", json={"host_ids": ids[:2], "snmp_profile_id": pid})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "updated": 2}
    assert _stored(api, group) == {"a": pid, "b": pid, "c": ""}

    assert api.post("/api/hosts/snmp-profile", json={"host_ids": [], "snmp_profile_id": pid}).status_code == 400
    bad = api.post("/api/hosts/snmp-profile", json={"host_ids": ids, "snmp_profile_id": "no-such-profile"})
    assert bad.status_code == 400
    assert _stored(api, group) == {"a": pid, "b": pid, "c": ""}

    cleared = api.post("/api/hosts/snmp-profile", json={"host_ids": [ids[0]], "snmp_profile_id": ""})
    assert cleared.json() == {"ok": True, "updated": 1}
    assert _stored(api, group) == {"a": "", "b": pid, "c": ""}

    # Moving a host keeps its own profile.
    other = _group(api, "Other")
    assert api.post("/api/hosts/move", json={"host_ids": [ids[1]], "target_group_id": other}).status_code == 200
    assert _stored(api, other) == {"b": pid}


def test_deleting_a_profile_returns_its_hosts_to_their_group(api):  # noqa: F811
    keep = _profile(api, "Keep")
    drop = _profile(api, "Drop")
    group = _group(api)
    a = api.post(f"/api/inventory/{group}/hosts", json={"hostname": "a", "ip_address": "192.0.2.41"}).json()["id"]
    b = api.post(f"/api/inventory/{group}/hosts", json={"hostname": "b", "ip_address": "192.0.2.42"}).json()["id"]
    api.post("/api/hosts/snmp-profile", json={"host_ids": [a], "snmp_profile_id": drop})
    api.post("/api/hosts/snmp-profile", json={"host_ids": [b], "snmp_profile_id": keep})

    assert api.delete(f"/api/admin/snmp-profiles/{drop}").status_code == 200
    assert _stored(api, group) == {"a": "", "b": keep}


def test_host_snmp_test_uses_the_hosts_own_profile(api, monkeypatch):  # noqa: F811
    pid = _profile(api, "Edge")
    group = _group(api)
    hid = api.post(
        f"/api/inventory/{group}/hosts",
        json={"hostname": "a", "ip_address": "192.0.2.51", "snmp_profile_id": pid},
    ).json()["id"]
    calls: list = []

    async def fake_get(ip, _timeout, cfg):
        calls.append((ip, cfg["community"]))
        return {"sys_name": "a"}

    monkeypatch.setattr(inventory_module, "_snmp_get", fake_get)
    resp = api.post(f"/api/hosts/{hid}/snmp-profile/test")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"success": True, "target_ip": "192.0.2.51", "result": {"sys_name": "a"}}
    assert calls == [("192.0.2.51", "example-ro")]

    # Back on the group's config, which has SNMP off.
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(DISABLED_CFG))
    api.post("/api/hosts/snmp-profile", json={"host_ids": [hid], "snmp_profile_id": ""})
    off = api.post(f"/api/hosts/{hid}/snmp-profile/test")
    assert off.status_code == 400
    assert api.post("/api/hosts/999999/snmp-profile/test").status_code == 404


# ── Polling ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_monitoring_targets_carry_each_hosts_effective_config(monkeypatch):
    own = _host_profile(monkeypatch)
    hosts = [
        {"id": 1, "group_id": 3, "hostname": "own", "snmp_profile_id": "p-host"},
        {"id": 2, "group_id": 3, "hostname": "sibling", "snmp_profile_id": ""},
    ]
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(GROUP_CFG))
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    monkeypatch.setattr(db, "get_all_groups", AsyncMock(return_value=[{"id": 3, "name": "core"}]))
    monkeypatch.setattr(db, "get_hosts_for_group", AsyncMock(return_value=hosts))

    targets = await monitoring._build_poll_targets()
    assert [(h["hostname"], cfg) for h, _cred, cfg in targets] == [("own", own), ("sibling", GROUP_CFG)]


@pytest.mark.asyncio
async def test_topology_discovery_walks_an_overriding_host_in_a_disabled_group(monkeypatch):
    own = _host_profile(monkeypatch)
    hosts = [
        {"id": 100, "hostname": "sw1", "ip_address": "192.0.2.61", "snmp_profile_id": "p-host"},
        {"id": 200, "hostname": "sw2", "ip_address": "192.0.2.62", "snmp_profile_id": ""},
    ]
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(DISABLED_CFG))
    monkeypatch.setattr(db, "get_group", AsyncMock(return_value={"id": 1, "name": "core"}))
    monkeypatch.setattr(db, "get_hosts_for_group", AsyncMock(return_value=hosts))
    monkeypatch.setattr(db, "replace_topology_links_for_host", AsyncMock(return_value=0))
    monkeypatch.setattr(db, "get_topology_links_for_host", AsyncMock(return_value=[]))
    monkeypatch.setattr(db, "resolve_topology_target_host_ids", AsyncMock(return_value=0))
    walked: list = []

    async def fake_discover(host_id, ip, cfg, timeout_seconds=5.0):
        walked.append((host_id, cfg))
        return [], []

    monkeypatch.setattr(topology_module, "_discover_neighbors", fake_discover)
    result = await topology_module.discover_topology_for_group(1)
    assert result["hosts_scanned"] == 1
    assert walked == [(100, own)]

    # No host with SNMP on: the group is refused.
    monkeypatch.setattr(db, "get_hosts_for_group", AsyncMock(return_value=hosts[1:]))
    with pytest.raises(Exception) as exc:
        await topology_module.discover_topology_for_group(1)
    assert getattr(exc.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_mac_collection_uses_the_hosts_own_profile_in_a_disabled_group(monkeypatch):
    own = _host_profile(monkeypatch)
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid: dict(DISABLED_CFG))
    host = {"id": 7, "group_id": 1, "ip_address": "192.0.2.71", "device_type": "cisco_ios", "snmp_profile_id": "p-host"}
    monkeypatch.setattr(db, "get_host", AsyncMock(return_value=host))
    calls: list = []

    async def fake_collect(host_id, ip, cfg, **kwargs):
        calls.append((host_id, cfg))
        return {"macs_found": 0, "arps_found": 0, "errors": []}

    monkeypatch.setattr(mac_tracking, "collect_mac_arp_tables", fake_collect)
    result = await mac_tracking.trigger_mac_collection(host_id=7)
    assert result["hosts_collected"] == 1
    assert calls == [(7, own)]

    # Without its own profile the disabled group config applies.
    monkeypatch.setattr(db, "get_host", AsyncMock(return_value={**host, "snmp_profile_id": ""}))
    with pytest.raises(Exception) as exc:
        await mac_tracking.trigger_mac_collection(host_id=7)
    assert getattr(exc.value, "status_code", None) == 400
