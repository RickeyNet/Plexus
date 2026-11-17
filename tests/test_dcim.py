"""Physical DCIM: the pure rules (endpoint pairing, unit fit and overlap,
elevation, the trace walk, power maths) and the API (rack placement through
the host edit, elevation, reservations, patch panel port mapping, one cable
per endpoint, multi-hop and looping traces, circuit terminations, power
trace and rack utilisation, 409s and the change log)."""

from __future__ import annotations

import asyncio
import math

import pytest
import routes.database as db
from netcontrol.dcim import (
    CableGraph,
    elevation,
    endpoint_key,
    feed_available_power,
    pairing_error,
    placement_error,
    rack_power_summary,
    reservation_error,
    trace,
)
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client, user_client

API = "/api/dcim"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


# ── Pure rules ───────────────────────────────────────────────────────────────


def test_pairing_rules():
    assert pairing_error("interface", "front_port") is None
    assert pairing_error("rear_port", "circuit_termination", "smf") is None
    assert pairing_error("power_port", "power_outlet", "power") is None
    assert pairing_error("power_feed", "power_port") is None
    assert "power endpoints only" in pairing_error("interface", "power_port")
    assert "cannot join" in pairing_error("power_outlet", "power_outlet")
    assert "cannot join" in pairing_error("power_feed", "power_outlet")
    assert "two circuit terminations" in pairing_error("circuit_termination", "circuit_termination")
    assert "type 'power'" in pairing_error("power_port", "power_outlet", "cat6")
    assert "only join power" in pairing_error("interface", "interface", "power")
    assert "Unknown endpoint" in pairing_error("console_port", "interface")


def test_placement_fit_and_overlap():
    others = [{"name": "core-sw1", "position": 10, "height": 2}]
    reservations = [{"units": [20, 21], "description": "spare"}]
    assert placement_error(42, 1, 1, others, reservations) is None
    assert placement_error(42, 12, 2, others, reservations) is None
    assert "unit 1 or higher" in placement_error(42, 0, 1)
    assert "reaches unit 43" in placement_error(42, 41, 3)
    assert "core-sw1" in placement_error(42, 9, 2, others)
    assert "core-sw1" in placement_error(42, 11, 1, others)
    assert "reservation (spare)" in placement_error(42, 19, 2, others, reservations)
    assert reservation_error(42, [1, 2], others) is None
    assert "core-sw1" in reservation_error(42, [11], others)
    assert "between 1 and 42" in reservation_error(42, [43])
    assert "at least one" in reservation_error(42, [])


def test_elevation_blocks_top_first_and_desc_units():
    devices = [
        {"host_id": 1, "name": "sw", "position": 2, "height": 2, "face": "front"},
        {"host_id": 2, "name": "loose", "position": None, "height": 1},
        {"host_id": 3, "name": "clash", "position": 3, "height": 1},
    ]
    drawing = elevation(5, False, devices, [{"id": 9, "units": [5], "description": "future"}])
    front = drawing["faces"]["front"]
    assert [b["kind"] for b in front] == ["reservation", "empty", "device", "empty"]
    assert front[2]["units"] == [3, 2] and front[2]["height"] == 2 and front[2]["mounted_here"]
    assert drawing["faces"]["rear"][2]["mounted_here"] is False
    assert {d["name"] for d in drawing["unmounted"]} == {"loose", "clash"}
    assert drawing["used_units"] == 3 and drawing["free_units"] == 2
    desc = elevation(3, True, [{"host_id": 1, "name": "a", "position": 1, "height": 1}])
    assert desc["units"] == [1, 2, 3]
    assert desc["faces"]["front"][0]["kind"] == "device"


def _graph() -> CableGraph:
    """sw1:Gi1 - F1 | panel 1 (F1 -> R1) | R1 = trunk = R2 | panel 2 (R2 -> F2) | F2 - sw2:Gi2.
    Panel 3: an MPO rear with 2 positions (F3a pos 1, F3b pos 2) trunked to
    panel 4 (F4a, F4b)."""
    cables = {
        1: {"id": 1, "a_type": "interface", "a_host_id": 1, "a_name": "Gi1", "b_type": "front_port", "b_id": 1},
        2: {"id": 2, "a_type": "rear_port", "a_id": 1, "b_type": "rear_port", "b_id": 2},
        3: {"id": 3, "a_type": "front_port", "a_id": 2, "b_type": "interface", "b_host_id": 2, "b_name": "Gi2"},
        4: {"id": 4, "a_type": "interface", "a_host_id": 1, "a_name": "Gi3", "b_type": "front_port", "b_id": 32},
        5: {"id": 5, "a_type": "rear_port", "a_id": 3, "b_type": "rear_port", "b_id": 4},
        6: {"id": 6, "a_type": "front_port", "a_id": 42, "b_type": "interface", "b_host_id": 2, "b_name": "Gi4"},
    }
    front = {
        1: {"host_id": 10, "rear_port_id": 1, "rear_port_position": 1},
        2: {"host_id": 11, "rear_port_id": 2, "rear_port_position": 1},
        31: {"host_id": 12, "rear_port_id": 3, "rear_port_position": 1},
        32: {"host_id": 12, "rear_port_id": 3, "rear_port_position": 2},
        41: {"host_id": 13, "rear_port_id": 4, "rear_port_position": 1},
        42: {"host_id": 13, "rear_port_id": 4, "rear_port_position": 2},
    }
    rear = {1: {"positions": 1}, 2: {"positions": 1}, 3: {"positions": 2}, 4: {"positions": 2}}
    existing = {endpoint_key("front_port", i) for i in front} | {endpoint_key("rear_port", i) for i in rear}
    return CableGraph(cables=cables, front_ports=front, rear_ports=rear, existing=existing)


def test_trace_through_patch_panels_and_positions():
    graph = _graph()
    result = trace(graph, {"type": "interface", "host_id": 1, "name": "Gi1"})
    assert result["status"] == "complete" and not result["is_loop"]
    assert [s["kind"] for s in result["steps"]] == ["cable", "internal", "cable", "internal", "cable"]
    assert result["destination"]["name"] == "Gi2"
    back = trace(graph, {"type": "interface", "host_id": 2, "name": "Gi2"})
    assert back["destination"]["name"] == "Gi1"
    mpo = trace(graph, {"type": "interface", "host_id": 1, "name": "Gi3"})
    assert mpo["status"] == "complete" and mpo["destination"]["name"] == "Gi4"
    assert mpo["steps"][3]["position"] == 2
    # Entering a multi-position rear port without a position is ambiguous.
    assert trace(graph, {"type": "rear_port", "id": 3})["status"] == "ambiguous"
    assert trace(graph, {"type": "interface", "host_id": 9, "name": "x"})["status"] == "unconnected"
    graph.existing.discard(endpoint_key("front_port", 1))
    assert trace(graph, {"type": "interface", "host_id": 1, "name": "Gi1"})["status"] == "missing"


def test_trace_detects_a_loop():
    cables = {
        1: {"id": 1, "a_type": "front_port", "a_id": 1, "b_type": "front_port", "b_id": 2},
        2: {"id": 2, "a_type": "rear_port", "a_id": 2, "b_type": "rear_port", "b_id": 1},
    }
    front = {1: {"rear_port_id": 1, "rear_port_position": 1}, 2: {"rear_port_id": 2, "rear_port_position": 1}}
    rear = {1: {"positions": 1}, 2: {"positions": 1}}
    existing = {endpoint_key("front_port", 1), endpoint_key("front_port", 2)}
    existing |= {endpoint_key("rear_port", 1), endpoint_key("rear_port", 2)}
    result = trace(
        CableGraph(cables=cables, front_ports=front, rear_ports=rear, existing=existing),
        {"type": "front_port", "id": 1},
    )
    assert result["status"] == "loop" and result["is_loop"]


def test_power_maths():
    assert feed_available_power(230, 16, "single", 80) == round(230 * 16 * 0.8)
    assert feed_available_power(400, 32, "three", 100) == round(400 * 32 * math.sqrt(3))
    assert feed_available_power(-48, 50, "three", 100, supply="dc") == 2400
    summary = rack_power_summary(
        [
            {
                "id": 1,
                "name": "A",
                "type": "primary",
                "voltage": 230,
                "amperage": 10,
                "phase": "single",
                "max_utilization": 100,
            },
            {
                "id": 2,
                "name": "B",
                "type": "redundant",
                "voltage": 230,
                "amperage": 10,
                "phase": "single",
                "max_utilization": 100,
            },
        ],
        [
            {"feed_id": 1, "allocated_draw": 500, "maximum_draw": 800},
            {"feed_id": 1, "allocated_draw": None, "maximum_draw": 300},
            {"feed_id": None, "allocated_draw": 100},
        ],
    )
    assert summary["capacity"] == 2300
    assert summary["allocated_draw"] == 900 and summary["unfed_draw"] == 100
    assert summary["feeds"][0]["allocated_draw"] == 800
    assert summary["feeds"][0]["utilization"] == round(800 * 100 / 2300, 1)
    assert summary["utilization"] == round(900 * 100 / 2300, 1)


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _site(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/geo/sites", json={"name": name}), 201)["id"])


def _group(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, gid: int, name: str, ip: str, **extra) -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios", **extra}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _device_type(admin: CsrfClient, model: str, u_height: int) -> int:
    maker = admin.post(f"{API}/manufacturers", json={"name": "Examplecorp"})
    if maker.status_code == 409:
        maker_id = next(m["id"] for m in _ok(admin.get(f"{API}/manufacturers")) if m["name"] == "Examplecorp")
    else:
        maker_id = _ok(maker, 201)["id"]
    body = {"manufacturer_id": maker_id, "model": model, "u_height": u_height}
    return int(_ok(admin.post(f"{API}/device-types", json=body), 201)["id"])


def _edit_host(admin: CsrfClient, host_id: int, name: str, ip: str, **values):
    return admin.put(f"/api/hosts/{host_id}", json={"hostname": name, "ip_address": ip, **values})


def _create(admin: CsrfClient, path: str, body: dict, status: int = 201) -> dict:
    return _ok(admin.post(f"{API}/{path}", json=body), status)


def test_rack_placement_rules_elevation_and_409s(admin):
    site_a, site_b = _site(admin, "dc-east"), _site(admin, "dc-west")
    floor_b = int(_ok(admin.post(f"/api/geo/sites/{site_b}/floors", json={"name": "Hall 1"}), 201)["id"])
    gid = _group(admin, "racked")
    two_u = _device_type(admin, "EX-2U", 2)
    h1 = _host(admin, gid, "core-sw1", "192.0.2.1", site_id=site_a, device_type_id=two_u)
    h2 = _host(admin, gid, "core-sw2", "192.0.2.2", site_id=site_a)
    h3 = _host(admin, gid, "west-sw1", "192.0.2.3", site_id=site_b)
    h4 = _host(admin, gid, "spare-srv", "192.0.2.4")
    role = _create(admin, "rack-roles", {"name": "Network", "color": "blue"})
    rack = _create(admin, "racks", {"site_id": site_a, "name": "R01", "u_height": 10, "role_id": role["id"]})
    rid = rack["id"]
    assert rack["site_name"] == "dc-east" and rack["role_name"] == "Network" and rack["desc_units"] is False
    # Names are unique per site ignoring case; the same name at another site is fine.
    assert admin.post(f"{API}/racks", json={"site_id": site_a, "name": "r01"}).status_code == 409
    other = _create(admin, "racks", {"site_id": site_b, "name": "R01", "floor_id": floor_b})
    assert other["floor_name"] == "Hall 1"
    # A floor of another site is refused.
    bad_floor = admin.post(f"{API}/racks", json={"site_id": site_a, "name": "R02", "floor_id": floor_b})
    assert bad_floor.status_code == 422
    assert admin.post(f"{API}/racks", json={"site_id": 999999, "name": "R09"}).status_code == 422
    assert admin.post(f"{API}/racks", json={"site_id": site_a, "name": "R09", "u_height": 101}).status_code == 422

    # Placement through the host edit: fit, overlap, site.
    resp = _edit_host(admin, h1, "core-sw1", "192.0.2.1", rack_id=rid, rack_position=10)
    assert resp.status_code == 422 and "reaches unit 11" in resp.text
    _ok(_edit_host(admin, h1, "core-sw1", "192.0.2.1", rack_id=rid, rack_position=1, rack_face="rear"))
    host = _ok(admin.get(f"{API}/hosts/{h1}"))["placement"]
    assert host["rack_id"] == rid and host["rack_position"] == 1 and host["rack_face"] == "rear"
    resp = admin.put(f"{API}/hosts/{h2}/placement", json={"rack_id": rid, "rack_position": 2})
    assert resp.status_code == 422 and "core-sw1" in resp.text
    placed = _ok(admin.put(f"{API}/hosts/{h2}/placement", json={"rack_id": rid, "rack_position": 3}))
    assert placed["rack_face"] == "front" and placed["rack_name"] == "R01"
    resp = admin.put(f"{API}/hosts/{h3}/placement", json={"rack_id": rid, "rack_position": 5})
    assert resp.status_code == 422 and "another site" in resp.text
    # A host with no site takes the rack's.
    _ok(admin.put(f"{API}/hosts/{h4}/placement", json={"rack_id": rid, "rack_position": 5}))
    assert _ok(admin.get(f"{API}/hosts/{h4}"))["placement"]["site_id"] == site_a
    # Moving a racked host to another site in the same edit is refused.
    resp = _edit_host(admin, h2, "core-sw2", "192.0.2.2", site_id=site_b)
    assert resp.status_code == 422

    # Reservations.
    res = _create(admin, "rack-reservations", {"rack_id": rid, "units": [8, 7], "user": "ops", "description": "growth"})
    assert res["units"] == [7, 8] and res["user"] == "ops"
    assert admin.post(f"{API}/rack-reservations", json={"rack_id": rid, "units": [3]}).status_code == 422
    resp = admin.put(f"{API}/hosts/{h2}/placement", json={"rack_position": 7})
    assert resp.status_code == 422 and "reservation (growth)" in resp.text

    elev = _ok(admin.get(f"{API}/racks/{rid}/elevation"))
    assert elev["units"][0] == 10 and elev["used_units"] == 6
    front = elev["faces"]["front"]
    core = next(b for b in front if b.get("host_id") == h1)
    assert core["units"] == [2, 1] and core["mounted_here"] is False and core["face"] == "rear"
    assert any(b["kind"] == "reservation" and b["units"] == [8, 7] for b in front)

    # Rack edits that would strand devices are refused.
    assert admin.put(f"{API}/racks/{rid}", json={"u_height": 4}).status_code == 422
    assert admin.put(f"{API}/racks/{rid}", json={"site_id": site_b}).status_code == 422
    assert admin.put(f"{API}/racks/{rid}", json={"name": None}).status_code == 422
    assert _ok(admin.put(f"{API}/racks/{rid}", json={"u_height": 12, "desc_units": True}))["u_height"] == 12
    assert admin.put(f"{API}/racks/{rid}", json={"unknown": 1}).status_code == 422

    # 409s: in-use role, rack with devices, site with racks.
    assert admin.delete(f"{API}/rack-roles/{role['id']}").status_code == 409
    assert admin.delete(f"{API}/racks/{rid}").status_code == 409
    assert admin.delete(f"/api/geo/sites/{site_a}").status_code == 409
    # Taking every device out frees the rack.
    for hid in (h1, h2, h4):
        _ok(admin.put(f"{API}/hosts/{hid}/placement", json={"rack_id": None}))
    assert _ok(admin.get(f"{API}/hosts/{h1}"))["placement"]["rack_position"] is None
    _ok(admin.delete(f"{API}/racks/{rid}"))
    _ok(admin.delete(f"{API}/rack-roles/{role['id']}"))
    assert admin.get(f"{API}/rack-reservations/{res['id']}").status_code == 404

    # Change log: rack and reservation changes, and the host placement.
    changes = _ok(admin.get("/api/changes", params={"object_type": "rack", "object_id": str(rid)}))["changes"]
    assert {c["action"] for c in changes} == {"create", "update", "delete"}
    host_changes = _ok(admin.get(f"/api/changes/host/{h1}"))["changes"]
    assert any("rack_position" in (c.get("changes") or {}) for c in host_changes)
    res_changes = _ok(admin.get(f"/api/changes/rack_reservation/{res['id']}"))["changes"]
    assert res_changes and res_changes[-1]["action"] == "create"


def _panel_hosts(admin: CsrfClient) -> dict:
    gid = _group(admin, "cabling")
    return {
        "sw1": _host(admin, gid, "access-sw1", "198.51.100.1"),
        "sw2": _host(admin, gid, "access-sw2", "198.51.100.2"),
        "pp1": _host(admin, gid, "patch-a", "198.51.100.11"),
        "pp2": _host(admin, gid, "patch-b", "198.51.100.12"),
    }


def test_ports_cables_and_multi_hop_trace(admin):
    h = _panel_hosts(admin)
    r1 = _create(admin, "rear-ports", {"host_id": h["pp1"], "name": "R1", "type": "lc"})
    r2 = _create(admin, "rear-ports", {"host_id": h["pp2"], "name": "R1", "type": "lc"})
    f1 = _create(admin, "front-ports", {"host_id": h["pp1"], "name": "F1", "type": "lc", "rear_port_id": r1["id"]})
    f2 = _create(admin, "front-ports", {"host_id": h["pp2"], "name": "F1", "type": "lc", "rear_port_id": r2["id"]})
    assert f1["rear_port_name"] == "R1" and f1["cable_id"] is None
    # Mapping rules: same device, position in range, one front per position, unique names.
    other_host = {"host_id": h["pp2"], "name": "F9", "rear_port_id": r1["id"]}
    assert admin.post(f"{API}/front-ports", json=other_host).status_code == 422
    out_of_range = {"host_id": h["pp1"], "name": "F2", "rear_port_id": r1["id"], "rear_port_position": 2}
    assert admin.post(f"{API}/front-ports", json=out_of_range).status_code == 422
    taken = {"host_id": h["pp1"], "name": "F2", "rear_port_id": r1["id"]}
    assert admin.post(f"{API}/front-ports", json=taken).status_code == 409
    assert admin.post(f"{API}/front-ports", json={**taken, "name": "f1", "rear_port_position": 1}).status_code == 409
    assert admin.post(f"{API}/front-ports", json={**taken, "type": "toslink"}).status_code == 422
    assert admin.put(f"{API}/front-ports/{f1['id']}", json={"host_id": h["pp2"]}).status_code == 422

    c1 = _create(
        admin,
        "cables",
        {
            "a": {"type": "interface", "host_id": h["sw1"], "name": "Gi1/0/1"},
            "b": {"type": "front_port", "id": f1["id"]},
            "type": "smf",
            "label": "X-001",
            "color": "00aaff",
        },
    )
    assert c1["a"]["label"] == "access-sw1 / Gi1/0/1" and c1["b"]["label"] == "patch-a / F1"
    _create(admin, "cables", {"a": {"type": "rear_port", "id": r1["id"]}, "b": {"type": "rear_port", "id": r2["id"]}})
    _create(
        admin,
        "cables",
        {
            "a": {"type": "front_port", "id": f2["id"]},
            "b": {"type": "interface", "host_id": h["sw2"], "name": "Gi1/0/2"},
        },
    )
    # One cable per endpoint, whichever side.
    dup = {"a": {"type": "front_port", "id": f1["id"]}, "b": {"type": "interface", "host_id": h["sw2"], "name": "Gi9"}}
    assert admin.post(f"{API}/cables", json=dup).status_code == 409
    dup_if = {
        "a": {"type": "interface", "host_id": h["sw1"], "name": "Gi1/0/1"},
        "b": {"type": "interface", "host_id": h["sw2"], "name": "Gi8"},
    }
    assert admin.post(f"{API}/cables", json=dup_if).status_code == 409
    # Pairing, unknown records, self-loops and bad colors.
    power = _create(admin, "power-ports", {"host_id": h["sw2"], "name": "PSU1"})
    mixed = {
        "a": {"type": "interface", "host_id": h["sw2"], "name": "Gi7"},
        "b": {"type": "power_port", "id": power["id"]},
    }
    assert admin.post(f"{API}/cables", json=mixed).status_code == 422
    missing = {
        "a": {"type": "interface", "host_id": h["sw2"], "name": "Gi7"},
        "b": {"type": "front_port", "id": 999999},
    }
    assert admin.post(f"{API}/cables", json=missing).status_code == 422
    same = {
        "a": {"type": "interface", "host_id": h["sw2"], "name": "Gi7"},
        "b": {"type": "interface", "host_id": h["sw2"], "name": "Gi7"},
    }
    assert admin.post(f"{API}/cables", json=same).status_code == 422
    assert (
        admin.post(
            f"{API}/cables",
            json={**mixed, "b": {"type": "interface", "host_id": h["sw1"], "name": "x"}, "color": "red"},
        ).status_code
        == 422
    )

    result = _ok(admin.get(f"{API}/trace", params={"type": "interface", "host_id": h["sw1"], "name": "Gi1/0/1"}))
    assert result["status"] == "complete"
    assert [s["kind"] for s in result["steps"]] == ["cable", "internal", "cable", "internal", "cable"]
    assert result["destination"]["label"] == "access-sw2 / Gi1/0/2"
    assert result["steps"][0]["cable"]["label"] == "X-001"
    back = _ok(admin.get(f"{API}/trace", params={"type": "rear_port", "id": r2["id"]}))
    assert back["destination"]["host_name"] == "access-sw1"
    assert admin.get(f"{API}/trace", params={"type": "front_port", "id": 999999}).status_code == 404
    loose = _ok(admin.get(f"{API}/trace", params={"type": "interface", "host_id": h["sw1"], "name": "Gi9"}))
    assert loose["status"] == "unconnected"

    # Filters and the host summary.
    assert len(_ok(admin.get(f"{API}/cables", params={"host_id": h["sw1"]}))) == 1
    assert len(_ok(admin.get(f"{API}/cables", params={"q": "x-001"}))) == 1
    assert len(_ok(admin.get(f"{API}/front-ports", params={"host_id": h["pp1"]}))) == 1
    summary = _ok(admin.get(f"{API}/hosts/{h['sw1']}"))
    assert summary["cables"][0]["id"] == c1["id"] and summary["placement"]["rack_id"] is None
    names = _ok(admin.get(f"{API}/hosts/{h['sw1']}/interfaces"))["interfaces"]
    assert "Gi1/0/1" in names

    # Ports with cables (or front ports) cannot be deleted.
    assert admin.delete(f"{API}/front-ports/{f1['id']}").status_code == 409
    assert admin.delete(f"{API}/rear-ports/{r1['id']}").status_code == 409
    # Changing a cable's end moves its endpoint key.
    updated = _ok(
        admin.put(f"{API}/cables/{c1['id']}", json={"a": {"type": "interface", "host_id": h["sw1"], "name": "Gi1/0/5"}})
    )
    assert updated["a"]["name"] == "Gi1/0/5"
    _create(admin, "cables", dup_if)  # Gi1/0/1 is free again
    _ok(admin.delete(f"{API}/cables/{c1['id']}"))
    _ok(admin.delete(f"{API}/front-ports/{f1['id']}"))

    kinds = {c["object_type"] for c in _ok(admin.get("/api/changes", params={"limit": 200}))["changes"]}
    assert {"cable", "front_port", "rear_port", "power_port"} <= kinds


def test_trace_loop_through_panels(admin):
    h = _panel_hosts(admin)
    r1 = _create(admin, "rear-ports", {"host_id": h["pp1"], "name": "R1"})
    r2 = _create(admin, "rear-ports", {"host_id": h["pp2"], "name": "R1"})
    f1 = _create(admin, "front-ports", {"host_id": h["pp1"], "name": "F1", "rear_port_id": r1["id"]})
    f2 = _create(admin, "front-ports", {"host_id": h["pp2"], "name": "F1", "rear_port_id": r2["id"]})
    _create(admin, "cables", {"a": {"type": "front_port", "id": f1["id"]}, "b": {"type": "front_port", "id": f2["id"]}})
    _create(admin, "cables", {"a": {"type": "rear_port", "id": r2["id"]}, "b": {"type": "rear_port", "id": r1["id"]}})
    result = _ok(admin.get(f"{API}/trace", params={"type": "front_port", "id": f1["id"]}))
    assert result["status"] == "loop" and result["is_loop"]


def test_circuit_termination_endpoint(admin):
    h = _panel_hosts(admin)
    site = _site(admin, "dc-ct")
    body = {
        "a": {"type": "interface", "host_id": h["sw1"], "name": "Te1/1"},
        "b": {"type": "circuit_termination", "id": 987654},
    }
    resp = admin.post(f"{API}/cables", json=body)
    assert resp.status_code == 422 and "circuit termination" in resp.text

    async def make_termination() -> int | None:
        conn = await db.get_db()
        try:
            cursor = await conn.execute("SELECT to_regclass('circuit_terminations') IS NOT NULL AS present")
            if not (await cursor.fetchone())["present"]:
                return None
            cursor = await conn.execute("INSERT INTO circuit_providers (name) VALUES ('Example Transit') RETURNING id")
            provider = (await cursor.fetchone())["id"]
            cursor = await conn.execute("INSERT INTO circuit_types (name) VALUES ('Internet') RETURNING id")
            ctype = (await cursor.fetchone())["id"]
            cursor = await conn.execute(
                "INSERT INTO circuits (cid, provider_id, circuit_type_id) VALUES ('CID-0001', ?, ?) RETURNING id",
                (provider, ctype),
            )
            circuit = (await cursor.fetchone())["id"]
            cursor = await conn.execute(
                "INSERT INTO circuit_terminations (circuit_id, term_side, site_id) VALUES (?, 'A', ?) RETURNING id",
                (circuit, site),
            )
            term = int((await cursor.fetchone())["id"])
            await conn.commit()
            return term
        finally:
            await conn.close()

    term_id = asyncio.run(make_termination())
    if term_id is None:
        return
    cable = _create(admin, "cables", {**body, "b": {"type": "circuit_termination", "id": term_id}})
    assert cable["b"]["name"].startswith(f"Circuit termination {term_id}")
    result = _ok(admin.get(f"{API}/trace", params={"type": "interface", "host_id": h["sw1"], "name": "Te1/1"}))
    assert result["status"] == "complete" and result["destination"]["type"] == "circuit_termination"
    two = {"a": {"type": "circuit_termination", "id": term_id}, "b": {"type": "circuit_termination", "id": term_id}}
    assert admin.post(f"{API}/cables", json=two).status_code == 422


def test_power_trace_and_rack_utilisation(admin):
    site = _site(admin, "dc-power")
    gid = _group(admin, "power")
    rack = _create(admin, "racks", {"site_id": site, "name": "P01"})
    pdu = _host(admin, gid, "pdu-a", "203.0.113.10")
    srv = _host(admin, gid, "app-srv1", "203.0.113.20")
    for hid, pos in ((pdu, 1), (srv, 3)):
        _ok(admin.put(f"{API}/hosts/{hid}/placement", json={"rack_id": rack["id"], "rack_position": pos}))
    panel = _create(admin, "power-panels", {"site_id": site, "name": "MDB-1"})
    assert admin.post(f"{API}/power-panels", json={"site_id": site, "name": "mdb-1"}).status_code == 409
    feed = _create(
        admin,
        "power-feeds",
        {
            "power_panel_id": panel["id"],
            "rack_id": rack["id"],
            "name": "A",
            "voltage": 230,
            "amperage": 16,
            "max_utilization": 80,
        },
    )
    _create(
        admin,
        "power-feeds",
        {"power_panel_id": panel["id"], "rack_id": rack["id"], "name": "B", "type": "redundant"},
    )
    other_site = _site(admin, "dc-elsewhere")
    far_rack = _create(admin, "racks", {"site_id": other_site, "name": "X01"})
    assert (
        admin.post(
            f"{API}/power-feeds", json={"power_panel_id": panel["id"], "rack_id": far_rack["id"], "name": "C"}
        ).status_code
        == 422
    )
    inlet = _create(admin, "power-ports", {"host_id": pdu, "name": "Inlet", "maximum_draw": 3000})
    outlet = _create(
        admin, "power-outlets", {"host_id": pdu, "name": "Out1", "power_port_id": inlet["id"], "feed_leg": "A"}
    )
    psu1 = _create(admin, "power-ports", {"host_id": srv, "name": "PSU1", "maximum_draw": 750, "allocated_draw": 400})
    psu2 = _create(admin, "power-ports", {"host_id": srv, "name": "PSU2", "maximum_draw": 750, "allocated_draw": 200})
    assert (
        admin.post(
            f"{API}/power-ports", json={"host_id": srv, "name": "PSU3", "maximum_draw": 100, "allocated_draw": 200}
        ).status_code
        == 422
    )
    assert (
        admin.post(
            f"{API}/power-outlets", json={"host_id": srv, "name": "O9", "power_port_id": inlet["id"]}
        ).status_code
        == 422
    )
    _create(
        admin,
        "cables",
        {
            "a": {"type": "power_port", "id": psu1["id"]},
            "b": {"type": "power_outlet", "id": outlet["id"]},
            "type": "power",
        },
    )
    _create(
        admin, "cables", {"a": {"type": "power_port", "id": inlet["id"]}, "b": {"type": "power_feed", "id": feed["id"]}}
    )

    result = _ok(admin.get(f"{API}/trace", params={"type": "power_port", "id": psu1["id"]}))
    assert result["status"] == "complete" and result["destination"]["type"] == "power_feed"
    assert result["power_panel"]["name"] == "MDB-1"
    assert [s["kind"] for s in result["steps"]] == ["cable", "internal", "cable"]
    from_outlet = _ok(admin.get(f"{API}/trace", params={"type": "power_outlet", "id": outlet["id"]}))
    assert [s["kind"] for s in from_outlet["steps"]] == ["internal", "cable"]
    assert from_outlet["destination"]["name"] == "A"

    power = _ok(admin.get(f"{API}/racks/{rack['id']}/power"))
    available = round(230 * 16 * 0.8)
    assert power["capacity"] == available
    assert power["allocated_draw"] == 600 and power["unfed_draw"] == 200
    feed_a = next(f for f in power["feeds"] if f["name"] == "A")
    assert feed_a["available_power"] == available and feed_a["allocated_draw"] == 400
    assert {p["name"] for p in power["ports"]} == {"PSU1", "PSU2"}
    assert next(p for p in power["ports"] if p["name"] == "PSU1")["feed_name"] == "A"

    # A cabled feed (and its panel) cannot be deleted; an uncabled port can.
    assert admin.delete(f"{API}/power-feeds/{feed['id']}").status_code == 409
    assert admin.delete(f"{API}/power-panels/{panel['id']}").status_code == 409
    _ok(admin.delete(f"{API}/power-ports/{psu2['id']}"))
    assert admin.delete(f"/api/geo/sites/{site}").status_code == 409


def test_modules_and_feature_gate(admin):
    gid = _group(admin, "modular")
    chassis = _host(admin, gid, "chassis-1", "192.0.2.40")
    mod = _create(
        admin, "modules", {"host_id": chassis, "bay": "Slot 1", "module_type": "Line card", "serial": "SN-EX-1"}
    )
    assert mod["host_name"] == "chassis-1"
    assert admin.post(f"{API}/modules", json={"host_id": chassis, "bay": "slot 1"}).status_code == 409
    assert admin.post(f"{API}/modules", json={"host_id": chassis, "bay": "  "}).status_code == 422
    assert _ok(admin.put(f"{API}/modules/{mod['id']}", json={"status": "failed"}))["status"] == "failed"
    assert admin.get(f"{API}/modules/999999").status_code == 404
    _ok(admin.delete(f"{API}/modules/{mod['id']}"))
    choices = _ok(admin.get(f"{API}/choices"))
    assert "mpo" in choices["port_types"] and "power" in choices["cable_types"]

    reader = user_client(admin, "dcim-reader", features=["dcim"])
    assert reader.get(f"{API}/racks").status_code == 200
    assert reader.post(f"{API}/rack-roles", json={"name": "Blocked"}).status_code == 403
    outsider = user_client(admin, "dcim-outsider", features=["inventory"])
    assert outsider.get(f"{API}/racks").status_code == 403
    # The change log shows DCIM types only to callers with the feature.
    types = _ok(reader.get("/api/changes"))["object_types"]
    assert "rack" in types and "host" not in types
