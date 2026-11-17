"""Routing objects (``netcontrol.routes.routing``): autonomous systems,
routing instances, BGP peer groups and peerings; access per feature, the
field rules (ASN range, addresses and their family, address families,
router id), uniqueness and the 404 / 409 / 422 contracts; compliance against
BGP neighbors stored through the neighbor discovery path; suggestions from
observed neighbors and accepting them; change log entries and audit."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.custom_fields import CustomFieldError
from netcontrol.routes.topology import _write_links_and_stats
from netcontrol.routing import (
    clean_address,
    clean_address_families,
    clean_asn,
    clean_router_id,
    compare,
    observed_neighbor,
    same_family,
    summarize,
)
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

API = "/api/routing"
ASES = f"{API}/autonomous-systems"
INSTANCES = f"{API}/instances"
GROUPS = f"{API}/peer-groups"
PEERINGS = f"{API}/peerings"
COMPLIANCE = f"{API}/compliance"
SUGGEST = f"{API}/suggestions"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _host(admin: CsrfClient, name: str, ip: str) -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _as(admin: CsrfClient, asn, **extra) -> dict:
    return _ok(admin.post(ASES, json={"asn": asn, **extra}), 201)


def _instance(admin: CsrfClient, host_id: int, as_id: int, name: str = "default", **extra) -> dict:
    body = {"host_id": host_id, "name": name, "autonomous_system_id": as_id, **extra}
    return _ok(admin.post(INSTANCES, json=body), 201)


def _peering(admin: CsrfClient, instance_id: int, remote: str, as_id: int, **extra) -> dict:
    body = {"routing_instance_id": instance_id, "remote_address": remote, "remote_asn_id": as_id, **extra}
    return _ok(admin.post(PEERINGS, json=body), 201)


def _fields(resp) -> dict:
    assert resp.status_code == 422, resp.text
    body = resp.json()
    detail = body.get("detail") or body.get("error", {}).get("detail")
    return detail["fields"]


def _bgp(host_id: int, peer: str, asn: int | None, state: str) -> dict:
    """A BGP neighbor as SNMP discovery returns it (``_discover_neighbors``)."""
    return {
        "source_host_id": host_id,
        "source_ip": "192.0.2.1",
        "local_interface": "",
        "remote_device_name": f"AS{asn}" if asn else peer,
        "remote_ip": peer,
        "remote_interface": peer,
        "protocol": "bgp",
        "remote_platform": f"AS {asn}, state={state}" if asn else "",
    }


def _discover(host_id: int, neighbors: list[dict], stats: list[dict] | None = None) -> None:
    """Store neighbors through the discovery write path."""
    asyncio.run(_write_links_and_stats(host_id, neighbors, stats or []))


# ── Rules (no I/O) ───────────────────────────────────────────────────────────


def test_field_rules():
    assert clean_asn(65001) == 65001
    assert clean_asn("AS64512") == 64512
    assert clean_asn("1.10") == 65546
    assert clean_asn(4294967295) == 4294967295
    for bad in (0, -1, 4294967296, "x", True, None, "70000.1", 1.5):
        with pytest.raises(CustomFieldError):
            clean_asn(bad)
    assert clean_address(" 2001:DB8::1 ", "Remote") == "2001:db8::1"
    assert clean_address("", "Local", required=False) == ""
    for bad in ("", "192.0.2.300", "192.0.2.0/24"):
        with pytest.raises(CustomFieldError):
            clean_address(bad, "Remote")
    assert same_family("192.0.2.1", "192.0.2.2") and same_family("", "2001:db8::1")
    assert not same_family("192.0.2.1", "2001:db8::1")
    assert clean_router_id("") == "" and clean_router_id("192.0.2.1") == "192.0.2.1"
    with pytest.raises(CustomFieldError):
        clean_router_id("2001:db8::1")
    assert clean_address_families("ipv6-unicast, vpnv4,ipv4-unicast,ipv4-unicast") == [
        "ipv4-unicast",
        "ipv6-unicast",
        "vpnv4-unicast",
    ]
    assert clean_address_families(None) == []
    with pytest.raises(CustomFieldError):
        clean_address_families(["ipv4-bogus"])
    with pytest.raises(CustomFieldError):
        clean_address_families(5)


def test_observed_neighbor_parsing():
    link = {
        "protocol": "bgp",
        "source_host_id": 3,
        "target_ip": "192.0.2.9",
        "target_platform": "AS 65010, state=6",
        "target_device_name": "AS65010",
        "discovered_at": "2026-01-01 00:00:00",
    }
    n = observed_neighbor(link)
    assert n == {
        "host_id": 3,
        "remote_address": "192.0.2.9",
        "remote_asn": 65010,
        "state": "established",
        "established": True,
        "discovered_at": "2026-01-01 00:00:00",
    }
    idle = observed_neighbor({**link, "target_platform": "AS 65010, state=1"})
    assert idle is not None and idle["state"] == "idle" and not idle["established"]
    bare = observed_neighbor({**link, "target_platform": "", "target_device_name": "192.0.2.9"})
    assert bare is not None and bare["remote_asn"] is None and bare["state"] == ""
    assert observed_neighbor({**link, "protocol": "cdp"}) is None
    assert observed_neighbor({**link, "target_ip": "not-an-ip"}) is None


def test_compare_planned_and_disabled_peerings():
    host = {"id": 1, "hostname": "r1"}
    peerings = [
        {"id": 10, "host_id": 1, "routing_instance_id": 5, "remote_address": "192.0.2.2", "remote_asn": 65002}
        | {"status": "planned", "routing_instance_name": "default"},
        {"id": 11, "host_id": 1, "routing_instance_id": 5, "remote_address": "192.0.2.3", "remote_asn": 65003}
        | {"status": "disabled", "routing_instance_name": "default"},
    ]
    seen = {
        "host_id": 1,
        "remote_address": "192.0.2.3",
        "remote_asn": 65003,
        "state": "idle",
        "established": False,
        "discovered_at": "",
    }
    rows = compare([host], peerings, [seen], {1}, unexpected_for={1})
    # The planned one is not expected yet; the disabled one is observed (down), not unexpected.
    assert [(r["peering_id"], r["state"]) for r in rows] == [(11, "down")]
    assert summarize(rows)["down"] == 1 and summarize(rows)["missing"] == 0


# ── Access ───────────────────────────────────────────────────────────────────


def test_access_needs_routing_and_routing_write(admin):
    asys = _as(admin, 65001)
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for path in (ASES, INSTANCES, GROUPS, PEERINGS, COMPLIANCE, f"{SUGGEST}?host_id=1"):
        assert anon.get(path).status_code == 401, path
    plain = user_client(admin, "plain-user", features=["inventory"])
    assert plain.get(ASES).status_code == 403
    reader = user_client(admin, "routing-reader", features=["routing"])
    assert reader.get(ASES).status_code == 200
    assert reader.get(f"{ASES}/{asys['id']}").status_code == 200
    assert reader.post(ASES, json={"asn": 65002}).status_code == 403
    assert reader.delete(f"{ASES}/{asys['id']}").status_code == 403
    writer = user_client(admin, "routing-writer", features=["routing", "routing.write"])
    assert writer.post(ASES, json={"asn": 65002}).status_code == 201


# ── Autonomous systems ───────────────────────────────────────────────────────


def test_autonomous_system_crud_range_and_uniqueness(admin):
    created = _as(admin, "64512", description="Lab core", rir="private", comments="invented")
    assert created["asn"] == 64512 and created["description"] == "Lab core" and created["created_by"] == "admin"
    assert created["instance_count"] == 0

    assert "asn" in _fields(admin.post(ASES, json={"asn": 0}))
    assert "asn" in _fields(admin.post(ASES, json={"asn": 4294967296}))
    assert "asn" in _fields(admin.post(ASES, json={"asn": "abc"}))
    assert "tenant_id" in _fields(admin.post(ASES, json={"asn": 64513, "tenant_id": 999999}))
    assert _as(admin, 4294967295)["asn"] == 4294967295
    assert admin.post(ASES, json={"asn": 64512}).status_code == 409

    updated = _ok(admin.put(f"{ASES}/{created['id']}", json={"description": "Core AS"}))
    assert updated["description"] == "Core AS" and updated["rir"] == "private"
    # The AS number never changes.
    assert admin.put(f"{ASES}/{created['id']}", json={"asn": 64999}).status_code == 422
    assert admin.put(f"{ASES}/999999", json={"description": "x"}).status_code == 404
    assert admin.get(f"{ASES}/999999").status_code == 404

    listed = _ok(admin.get(f"{ASES}?search=core"))["autonomous_systems"]
    assert [a["asn"] for a in listed] == [64512]
    assert _ok(admin.delete(f"{ASES}/{created['id']}")) == {"ok": True}
    assert admin.delete(f"{ASES}/{created['id']}").status_code == 404


def test_autonomous_system_with_tenant_and_filter(admin):
    async def make_tenant() -> int:
        conn = await db.get_db()
        try:
            cursor = await conn.execute("INSERT INTO tenants (name) VALUES (?) RETURNING id", ("Example Tenant",))
            tid = int(cursor.lastrowid)
            await conn.commit()
            return tid
        finally:
            await conn.close()

    tid = asyncio.run(make_tenant())
    owned = _as(admin, 65100, tenant_id=tid)
    _as(admin, 65101)
    assert owned["tenant_name"] == "Example Tenant"
    listed = _ok(admin.get(f"{ASES}?tenant_id={tid}"))["autonomous_systems"]
    assert [a["asn"] for a in listed] == [65100]
    cleared = _ok(admin.put(f"{ASES}/{owned['id']}", json={"tenant_id": None}))
    assert cleared["tenant_id"] is None


def test_deleting_an_as_in_use_is_refused(admin):
    host = _host(admin, "edge-r1", "192.0.2.10")
    local = _as(admin, 65001)
    remote = _as(admin, 65002)
    instance = _instance(admin, host, local["id"])
    resp = admin.delete(f"{ASES}/{local['id']}")
    assert resp.status_code == 409
    peering = _peering(admin, instance["id"], "192.0.2.2", remote["id"])
    resp = admin.delete(f"{ASES}/{remote['id']}")
    assert resp.status_code == 409 and "in use" in resp.text
    _ok(admin.delete(f"{PEERINGS}/{peering['id']}"))
    _ok(admin.delete(f"{ASES}/{remote['id']}"))
    detail = _ok(admin.get(f"{ASES}/{local['id']}"))
    assert [i["id"] for i in detail["routing_instances"]] == [instance["id"]]


# ── Routing instances ────────────────────────────────────────────────────────


def test_routing_instance_crud_and_rules(admin):
    host = _host(admin, "edge-r1", "192.0.2.10")
    other = _host(admin, "edge-r2", "192.0.2.11")
    local = _as(admin, 65001)
    vrf = _ok(admin.post("/api/ipam/vrfs", json={"name": "BLUE"}), 201)

    created = _instance(admin, host, local["id"], router_id="192.0.2.10", vrf_id=vrf["id"])
    assert created["asn"] == 65001 and created["vrf_name"] == "BLUE" and created["status"] == "active"
    assert created["hostname"] == "edge-r1"

    errors = _fields(
        admin.post(
            INSTANCES,
            json={"host_id": 999999, "name": "", "autonomous_system_id": 999999, "router_id": "2001:db8::1"}
            | {"status": "bogus", "vrf_id": 999999},
        )
    )
    assert set(errors) >= {"host_id", "name", "autonomous_system_id", "router_id", "status", "vrf_id"}
    assert "autonomous_system_id" in _fields(admin.post(INSTANCES, json={"host_id": host, "name": "x"}))
    # Unique per device, ignoring case; the same name on another device is fine.
    assert (
        admin.post(
            INSTANCES, json={"host_id": host, "name": "DEFAULT", "autonomous_system_id": local["id"]}
        ).status_code
        == 409
    )
    second = _instance(admin, other, local["id"])
    vrf_instance = _instance(admin, host, local["id"], name="vrf-blue", status="planned")
    assert admin.put(f"{INSTANCES}/{vrf_instance['id']}", json={"name": "Default"}).status_code == 409
    assert admin.put(f"{INSTANCES}/{vrf_instance['id']}", json={"host_id": other}).status_code == 422

    updated = _ok(admin.put(f"{INSTANCES}/{created['id']}", json={"status": "decommissioned", "router_id": ""}))
    assert updated["status"] == "decommissioned" and updated["router_id"] == ""

    by_host = _ok(admin.get(f"{INSTANCES}?host_id={host}"))["routing_instances"]
    assert {i["name"] for i in by_host} == {"default", "vrf-blue"}
    assert [i["id"] for i in _ok(admin.get(f"{INSTANCES}?status=planned"))["routing_instances"]] == [vrf_instance["id"]]
    assert len(_ok(admin.get(f"{INSTANCES}?asn=65001"))["routing_instances"]) == 3
    assert _ok(admin.get(f"{INSTANCES}?asn=65009"))["routing_instances"] == []
    assert _ok(admin.get(f"{INSTANCES}?search=edge-r2"))["routing_instances"][0]["id"] == second["id"]
    assert admin.get(f"{INSTANCES}?status=bogus").status_code == 400
    assert admin.get(f"{INSTANCES}?asn=0").status_code == 400

    _ok(admin.delete(f"{INSTANCES}/{second['id']}"))
    assert admin.get(f"{INSTANCES}/{second['id']}").status_code == 404
    assert admin.delete(f"{INSTANCES}/{second['id']}").status_code == 404


# ── Peer groups and peerings ─────────────────────────────────────────────────


def test_peer_groups_and_peerings(admin):
    host = _host(admin, "edge-r1", "192.0.2.10")
    peer_host = _host(admin, "edge-r2", "192.0.2.11")
    local = _as(admin, 65001)
    remote = _as(admin, 65002)
    instance = _instance(admin, host, local["id"])
    other_instance = _instance(admin, host, local["id"], name="vrf-red")

    group = _ok(
        admin.post(
            GROUPS,
            json={"routing_instance_id": instance["id"], "name": "UPSTREAM", "remote_asn_id": remote["id"]}
            | {"import_policy": "RM-IN", "export_policy": "RM-OUT"},
        ),
        201,
    )
    assert group["remote_asn"] == 65002 and group["hostname"] == "edge-r1"
    assert admin.post(GROUPS, json={"routing_instance_id": instance["id"], "name": "upstream"}).status_code == 409
    assert "routing_instance_id" in _fields(admin.post(GROUPS, json={"routing_instance_id": 999999, "name": "x"}))
    assert "remote_asn_id" in _fields(admin.put(f"{GROUPS}/{group['id']}", json={"remote_asn_id": 999999}))

    peering = _peering(
        admin,
        instance["id"],
        "192.0.2.2",
        remote["id"],
        local_address="192.0.2.1",
        peer_group_id=group["id"],
        remote_host_id=peer_host,
        address_families=["ipv4-unicast", "vpnv4"],
        import_policy="RM-IN",
    )
    assert peering["address_families"] == ["ipv4-unicast", "vpnv4-unicast"]
    assert peering["peer_group_name"] == "UPSTREAM" and peering["remote_hostname"] == "edge-r2"
    assert peering["local_asn"] == 65001 and peering["remote_asn"] == 65002

    # Address rules: valid IPs of one family.
    errors = _fields(
        admin.post(
            PEERINGS,
            json={"routing_instance_id": instance["id"], "remote_address": "2001:db8::2", "remote_asn_id": remote["id"]}
            | {"local_address": "192.0.2.1"},
        )
    )
    assert "local_address" in errors
    errors = _fields(
        admin.post(
            PEERINGS,
            json={"routing_instance_id": instance["id"], "remote_address": "192.0.2.999", "remote_asn_id": 999999}
            | {"address_families": ["ipv4-bogus"], "status": "up", "remote_host_id": 999999},
        )
    )
    assert set(errors) >= {"remote_address", "remote_asn_id", "address_families", "status", "remote_host_id"}
    # A peer group of another instance is refused.
    assert "peer_group_id" in _fields(
        admin.post(
            PEERINGS,
            json={"routing_instance_id": other_instance["id"], "remote_address": "192.0.2.3"}
            | {"remote_asn_id": remote["id"], "peer_group_id": group["id"]},
        )
    )
    # Unique per instance by remote address (compared canonically).
    assert (
        admin.post(
            PEERINGS,
            json={
                "routing_instance_id": instance["id"],
                "remote_address": " 192.0.2.2 ",
                "remote_asn_id": remote["id"],
            },
        ).status_code
        == 409
    )
    v6 = _peering(admin, instance["id"], "2001:DB8::2", remote["id"], local_address="2001:db8::1")
    assert v6["remote_address"] == "2001:db8::2"
    # Changing only the remote address keeps the stored local address in the family check.
    assert "local_address" in _fields(admin.put(f"{PEERINGS}/{v6['id']}", json={"remote_address": "192.0.2.5"}))
    assert (
        admin.put(f"{PEERINGS}/{v6['id']}", json={"remote_address": "192.0.2.2", "local_address": ""}).status_code
        == 409
    )

    updated = _ok(admin.put(f"{PEERINGS}/{peering['id']}", json={"status": "disabled", "address_families": []}))
    assert updated["status"] == "disabled" and updated["address_families"] == []
    assert admin.put(f"{PEERINGS}/{peering['id']}", json={"routing_instance_id": 1}).status_code == 422

    assert len(_ok(admin.get(f"{PEERINGS}?host_id={host}"))["peerings"]) == 2
    assert len(_ok(admin.get(f"{PEERINGS}?asn=65002"))["peerings"]) == 2
    assert [p["id"] for p in _ok(admin.get(f"{PEERINGS}?status=disabled"))["peerings"]] == [peering["id"]]
    assert [p["id"] for p in _ok(admin.get(f"{PEERINGS}?search=upstream"))["peerings"]] == [peering["id"]]
    assert _ok(admin.get(f"{PEERINGS}?routing_instance_id={other_instance['id']}"))["peerings"] == []
    assert admin.get(f"{PEERINGS}?status=bogus").status_code == 400
    groups = _ok(admin.get(f"{GROUPS}?host_id={host}"))["peer_groups"]
    assert groups[0]["peering_count"] == 1
    detail = _ok(admin.get(f"{INSTANCES}/{instance['id']}"))
    assert len(detail["peerings"]) == 2 and len(detail["peer_groups"]) == 1

    # Deleting the group keeps its peerings without a group.
    _ok(admin.delete(f"{GROUPS}/{group['id']}"))
    assert _ok(admin.get(f"{PEERINGS}/{peering['id']}"))["peer_group_id"] is None
    assert admin.get(f"{GROUPS}/{group['id']}").status_code == 404
    _ok(admin.delete(f"{PEERINGS}/{v6['id']}"))
    assert admin.get(f"{PEERINGS}/{v6['id']}").status_code == 404
    # Deleting the instance takes its peerings.
    _ok(admin.delete(f"{INSTANCES}/{instance['id']}"))
    assert admin.get(f"{PEERINGS}/{peering['id']}").status_code == 404


# ── Compliance ───────────────────────────────────────────────────────────────


def test_compliance_states(admin):
    r1 = _host(admin, "edge-r1", "192.0.2.10")
    r2 = _host(admin, "edge-r2", "192.0.2.11")
    local = _as(admin, 65001)
    as2 = _as(admin, 65002)
    as3 = _as(admin, 65003)
    i1 = _instance(admin, r1, local["id"])
    matched = _peering(admin, i1["id"], "192.0.2.2", as2["id"])
    down = _peering(admin, i1["id"], "192.0.2.3", as2["id"])
    missing = _peering(admin, i1["id"], "192.0.2.4", as2["id"])
    mismatch = _peering(admin, i1["id"], "2001:db8::5", as3["id"])
    i2 = _instance(admin, r2, local["id"])
    no_data = _peering(admin, i2["id"], "192.0.2.9", as2["id"])

    _discover(
        r1,
        [
            _bgp(r1, "192.0.2.2", 65002, "6"),
            _bgp(r1, "192.0.2.3", 65002, "3"),
            _bgp(r1, "2001:db8::5", 65099, "6"),
            _bgp(r1, "192.0.2.7", 65007, "6"),
        ],
    )

    report = _ok(admin.get(COMPLIANCE))
    states = {(r["peering_id"], r["remote_address"]): r["state"] for r in report["rows"]}
    assert states == {
        (matched["id"], "192.0.2.2"): "matched",
        (down["id"], "192.0.2.3"): "down",
        (missing["id"], "192.0.2.4"): "missing",
        (mismatch["id"], "2001:db8::5"): "asn_mismatch",
        (None, "192.0.2.7"): "unexpected",
        (no_data["id"], "192.0.2.9"): "no_data",
    }
    assert report["summary"] == {
        "matched": 1,
        "down": 1,
        "missing": 1,
        "unexpected": 1,
        "asn_mismatch": 1,
        "no_data": 1,
    }
    hosts = {h["host_id"]: h for h in report["hosts"]}
    assert hosts[r1]["has_data"] and not hosts[r2]["has_data"] and hosts[r1]["last_discovered_at"]
    row = next(r for r in report["rows"] if r["state"] == "asn_mismatch")
    assert row["observed_remote_asn"] == 65099 and row["intended_remote_asn"] == 65003
    assert next(r for r in report["rows"] if r["state"] == "down")["observed_state"] == "active"

    only_down = _ok(admin.get(f"{COMPLIANCE}?state=down"))
    assert [r["peering_id"] for r in only_down["rows"]] == [down["id"]] and only_down["summary"]["matched"] == 1
    one = _ok(admin.get(f"{COMPLIANCE}?host_id={r2}"))
    assert [r["state"] for r in one["rows"]] == ["no_data"]
    assert admin.get(f"{COMPLIANCE}?state=bogus").status_code == 400
    assert admin.get(f"{COMPLIANCE}?host_id=999999").status_code == 404

    # Interface counters alone count as discovery: with no BGP neighbor the
    # peering is missing, not "no data".
    _discover(
        r2,
        [],
        [{"host_id": r2, "if_index": 1, "if_name": "Gi0/1", "if_speed_mbps": 1000} | {"in_octets": 1, "out_octets": 2}],
    )
    assert [r["state"] for r in _ok(admin.get(f"{COMPLIANCE}?host_id={r2}"))["rows"]] == ["missing"]


def test_compliance_of_a_host_without_instances_reports_unexpected(admin):
    r3 = _host(admin, "edge-r3", "192.0.2.12")
    _discover(r3, [_bgp(r3, "198.51.100.1", 64600, "6")])
    report = _ok(admin.get(f"{COMPLIANCE}?host_id={r3}"))
    assert [r["state"] for r in report["rows"]] == ["unexpected"]
    # Across all devices, only devices with intent are compared.
    assert _ok(admin.get(COMPLIANCE))["rows"] == []


def test_two_peers_in_one_as_are_both_stored():
    """Discovery keeps both peers of one AS (the BGP link key includes the peer)."""

    async def run() -> list[dict]:
        await db.init_db()
        gid = await db.create_group("rt-two-peers")
        hid = await db.add_host(gid, "rr1.example.com", "192.0.2.30", "cisco_ios")
        await _write_links_and_stats(
            hid, [_bgp(hid, "192.0.2.31", 65001, "6"), _bgp(hid, "192.0.2.32", 65001, "6")], []
        )
        return await db.get_topology_links_for_host(hid)

    links = asyncio.run(run())
    assert sorted(link["target_ip"] for link in links) == ["192.0.2.31", "192.0.2.32"]


# ── Suggestions ──────────────────────────────────────────────────────────────


def test_suggest_and_accept(admin):
    r1 = _host(admin, "edge-r1", "192.0.2.10")
    peer = _host(admin, "edge-r2", "192.0.2.2")
    existing = _as(admin, 65002)
    _discover(r1, [_bgp(r1, "192.0.2.2", 65002, "6"), _bgp(r1, "192.0.2.3", 65003, "2")])

    proposal = _ok(admin.get(f"{SUGGEST}?host_id={r1}"))
    assert proposal["has_data"] and proposal["routing_instances"] == []
    assert proposal["proposed_instance"] == {"name": "default", "asn": None}
    assert proposal["autonomous_systems"] == [
        {"asn": 65002, "autonomous_system_id": existing["id"]},
        {"asn": 65003, "autonomous_system_id": None},
    ]
    by_addr = {p["remote_address"]: p for p in proposal["peerings"]}
    assert by_addr["192.0.2.2"]["status"] == "active" and by_addr["192.0.2.2"]["remote_host_id"] == peer
    assert by_addr["192.0.2.3"]["status"] == "planned" and by_addr["192.0.2.3"]["observed_state"] == "connect"
    assert admin.get(f"{SUGGEST}?host_id=999999").status_code == 404

    # Nothing is created by asking; bad selections are refused as a whole.
    assert _ok(admin.get(INSTANCES))["routing_instances"] == []
    errors = _fields(
        admin.post(
            f"{SUGGEST}/accept",
            json={
                "host_id": r1,
                "new_instance": {"name": "default", "asn": 0},
                "peerings": [{"remote_address": "192.0.2.99"}],
            },
        )
    )
    assert set(errors) == {"new_instance.asn", "peerings.0.remote_address"}
    assert "routing_instance_id" in _fields(admin.post(f"{SUGGEST}/accept", json={"host_id": r1, "peerings": []}))
    assert _ok(admin.get(INSTANCES))["routing_instances"] == []

    created = _ok(
        admin.post(
            f"{SUGGEST}/accept",
            json={
                "host_id": r1,
                "new_instance": {"name": "default", "asn": 65001, "router_id": "192.0.2.10"},
                "peerings": [
                    {"remote_address": "192.0.2.2", "status": "active", "remote_host_id": peer},
                    {"remote_address": "192.0.2.3", "status": "planned"},
                ],
            },
        ),
        201,
    )
    assert created["routing_instance"]["asn"] == 65001
    assert sorted(a["asn"] for a in created["autonomous_systems"]) == [65001, 65003]
    assert {p["remote_address"]: p["status"] for p in created["peerings"]} == {
        "192.0.2.2": "active",
        "192.0.2.3": "planned",
    }
    assert created["peerings"][0]["address_families"] == ["ipv4-unicast"]

    # Accepted neighbors are no longer suggested; the device is now compared.
    again = _ok(admin.get(f"{SUGGEST}?host_id={r1}"))
    assert again["peerings"] == [] and again["proposed_instance"] is None
    states = {r["remote_address"]: r["state"] for r in _ok(admin.get(COMPLIANCE))["rows"]}
    # The planned peering is reported because its neighbor is observed.
    assert states == {"192.0.2.2": "matched", "192.0.2.3": "down"}
    # Accepting into an instance of another device is refused.
    r9 = _host(admin, "edge-r9", "192.0.2.19")
    assert "routing_instance_id" in _fields(
        admin.post(
            f"{SUGGEST}/accept",
            json={"host_id": r9, "routing_instance_id": created["routing_instance"]["id"], "peerings": []},
        )
    )


# ── Change log and audit ─────────────────────────────────────────────────────


def test_changes_are_recorded_and_audited(admin):
    host = _host(admin, "edge-r1", "192.0.2.10")
    local = _as(admin, 65001)
    remote = _as(admin, 65002)
    instance = _instance(admin, host, local["id"])
    group = _ok(admin.post(GROUPS, json={"routing_instance_id": instance["id"], "name": "IBGP"}), 201)
    peering = _peering(admin, instance["id"], "192.0.2.2", remote["id"])
    _ok(admin.put(f"{PEERINGS}/{peering['id']}", json={"description": "to edge-r2"}))
    _ok(admin.put(f"{ASES}/{local['id']}", json={"description": "Core"}))
    _ok(admin.delete(f"{GROUPS}/{group['id']}"))

    def history(kind: str, oid: int) -> list[dict]:
        return _ok(admin.get(f"/api/changes/{kind}/{oid}"))["changes"]

    as_changes = history("autonomous_system", local["id"])
    assert [c["action"] for c in as_changes] == ["update", "create"]
    assert as_changes[0]["object_label"] == "AS65001"
    assert as_changes[0]["changes"]["description"] == {"before": "", "after": "Core"}
    assert [c["action"] for c in history("routing_instance", instance["id"])] == ["create"]
    assert [c["action"] for c in history("bgp_peer_group", group["id"])] == ["delete", "create"]
    peer_changes = history("bgp_peering", peering["id"])
    assert [c["action"] for c in peer_changes] == ["update", "create"]
    assert peer_changes[0]["object_label"] == "192.0.2.2"

    # The change log of routing objects needs the routing feature.
    reader = user_client(admin, "routing-reader", features=["routing"])
    assert reader.get("/api/changes?object_type=bgp_peering").status_code == 200
    ipam = user_client(admin, "ipam-reader", features=["ipam"])
    assert ipam.get("/api/changes?object_type=bgp_peering").status_code == 403

    events = asyncio.run(db.get_audit_events(limit=200))
    actions = {e["action"] for e in events if e.get("category") == "routing"}
    assert {
        "autonomous_system_create",
        "routing_instance_create",
        "bgp_peering_update",
        "bgp_peer_group_delete",
    } <= actions
