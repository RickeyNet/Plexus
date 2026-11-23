"""Hardware components API (netcontrol/routes/hardware_components.py):
the host and fleet lists, the history, the CSV export, the on-demand SNMP
read, permissions and object scope. Invented data only; no device."""

from __future__ import annotations

import asyncio
import csv
import io

import netcontrol.routes.hardware_components as routes_hw
import netcontrol.routes.state as state
import pytest
from netcontrol import hardware_components as hc
from netcontrol.hardware_components import Component

from mcp_helpers import CsrfClient, admin_client, user_client
from snmp_health_fakes import Agent
from test_hardware_components import FIXED, entity

GROUPS = "/api/admin/access-groups"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str, device_type: str = "cisco_xe") -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": device_type}
    return int(_ok(admin.post(f"/api/inventory/{group_id}/hosts", json=body), 201)["id"])


def _read(host_id: int, components: list[Component], source: str = "snmp") -> dict:
    return asyncio.run(hc.apply_read(host_id, source, components))


def comp(serial: str, slot: str, category: str = "module", model: str = "EX-1") -> Component:
    return Component(category, slot, slot, f"{slot} description", model, serial)


def _scoped(admin: CsrfClient, name: str, grants: list[dict], features=("inventory", "inventory.write")) -> CsrfClient:
    import netcontrol.app as app_module
    from starlette.testclient import TestClient

    body = {
        "name": f"{name} access",
        "feature_keys": list(features),
        "object_scope": "groups",
        "inventory_scopes": grants,
    }
    group = _ok(admin.post(GROUPS, json=body), 201)
    _ok(
        admin.post("/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group["id"]]}),
        201,
    )
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": name, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


@pytest.fixture
def fleet(admin):
    east = _group(admin, "east")
    west = _group(admin, "west")
    a = _host(admin, east, "core-a", "192.0.2.11")
    b = _host(admin, west, "core-b", "198.51.100.12")
    _read(
        a,
        [
            comp("FXS0000Q0AA", "Chassis", "chassis"),
            comp("JAE0000A0AA", "Slot 1"),
            comp("ART0000C0CC", "PS1", "power_supply"),
        ],
    )
    _read(b, [comp("FOC0000X0BB", "Switch 1", "chassis"), comp("=HYPERLINK(1)", "Slot 2")])
    # Host a: the supervisor replaced, a power supply missing.
    _read(a, [comp("FXS0000Q0AA", "Chassis", "chassis"), comp("JAE0000Z0ZZ", "Slot 1")])
    return {"east": east, "west": west, "a": a, "b": b}


def test_host_hardware_and_events(admin, fleet):
    body = _ok(admin.get(f"/api/hosts/{fleet['a']}/hardware"))
    assert body["state"] == "ok" and body["source"] == "snmp" and body["collected_at"]
    by_serial = {c["serial"]: c for c in body["components"]}
    assert by_serial["JAE0000A0AA"]["status"] == "removed" and by_serial["JAE0000A0AA"]["removed_at"]
    assert by_serial["ART0000C0CC"]["status"] == "missing" and by_serial["ART0000C0CC"]["removed_at"] is None
    assert set(by_serial["FXS0000Q0AA"]) == set(routes_hw._COMPONENT_KEYS)
    assert by_serial["FXS0000Q0AA"]["hostname"] == "core-a"

    events = _ok(admin.get(f"/api/hosts/{fleet['a']}/hardware/events"))
    assert events["total"] == 2 and [e["event"] for e in events["events"]] == ["replaced", "baseline"]
    replaced = events["events"][0]
    assert (replaced["serial"], replaced["previous_serial"], replaced["changes"]) == ("JAE0000Z0ZZ", "JAE0000A0AA", {})
    assert set(replaced) == set(routes_hw._EVENT_KEYS)
    assert events["events"][1]["detail"].startswith("First hardware read: 3 components")
    # The list form of ``event``, and paging.
    only = _ok(admin.get(f"/api/hosts/{fleet['a']}/hardware/events?event=installed,replaced"))
    assert only["total"] == 1 and only["events"][0]["event"] == "replaced"
    page = _ok(admin.get(f"/api/hosts/{fleet['a']}/hardware/events?limit=1&offset=1"))
    assert page["total"] == 2 and [e["event"] for e in page["events"]] == ["baseline"]
    assert admin.get(f"/api/hosts/{fleet['a']}/hardware/events?event=exploded").status_code == 422


def test_a_host_never_read(admin, fleet):
    host_id = _host(admin, fleet["east"], "edge-c", "192.0.2.13")
    body = _ok(admin.get(f"/api/hosts/{host_id}/hardware"))
    assert (body["state"], body["collected_at"], body["source"], body["components"]) == ("never", None, "", [])
    assert admin.get("/api/hosts/999999/hardware").status_code == 404


def test_fleet_components_filters(admin, fleet):
    everything = _ok(admin.get("/api/hardware/components"))
    assert everything["total"] == 6
    assert _ok(admin.get("/api/hardware/components?search=jae0000"))["total"] == 2
    assert _ok(admin.get("/api/hardware/components?search=CORE-B"))["total"] == 2
    assert _ok(admin.get("/api/hardware/components?category=chassis"))["total"] == 2
    assert _ok(admin.get("/api/hardware/components?status=present"))["total"] == 4
    assert _ok(admin.get("/api/hardware/components?status=missing,removed"))["total"] == 2
    assert _ok(admin.get(f"/api/hardware/components?group_id={fleet['west']}"))["total"] == 2
    page = _ok(admin.get("/api/hardware/components?limit=2&offset=2"))
    assert page["total"] == 6 and len(page["components"]) == 2
    assert admin.get("/api/hardware/components?category=spaceship").status_code == 422
    assert admin.get("/api/hardware/components?limit=0").status_code == 422


def test_fleet_events_filters(admin, fleet):
    assert _ok(admin.get("/api/hardware/events"))["total"] == 3
    changes = _ok(admin.get("/api/hardware/events?event=installed,removed,replaced,moved,changed"))
    assert changes["total"] == 1 and changes["events"][0]["event"] == "replaced"
    assert _ok(admin.get("/api/hardware/events?event=baseline"))["total"] == 2
    assert _ok(admin.get("/api/hardware/events?search=jae0000a0aa"))["total"] == 1  # previous_serial
    assert _ok(admin.get(f"/api/hardware/events?host_id={fleet['b']}"))["total"] == 1
    assert _ok(admin.get("/api/hardware/events?category=module"))["total"] == 1
    assert admin.get("/api/hardware/events?event=baseline,bogus").status_code == 422


def test_csv_export(admin, fleet):
    resp = admin.get("/api/hardware/components/export?category=module")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][:3] == ["Hostname", "Category", "Slot"]
    serials = {r[6] for r in rows[1:]}
    assert serials == {"JAE0000A0AA", "JAE0000Z0ZZ", "'=HYPERLINK(1)"}  # formula guarded


def test_permissions(admin, fleet):
    plain = user_client(admin, "plain-user")
    assert plain.get(f"/api/hosts/{fleet['a']}/hardware").status_code == 403
    assert plain.get("/api/hardware/components").status_code == 403
    reader = user_client(admin, "inv-reader", features=["inventory"])
    assert reader.get(f"/api/hosts/{fleet['a']}/hardware").status_code == 200
    assert reader.get("/api/hardware/events").status_code == 200
    assert reader.post(f"/api/hosts/{fleet['a']}/hardware/refresh").status_code == 403


def test_object_scope(admin, fleet):
    scoped = _scoped(admin, "east-only", [{"inventory_group_id": fleet["east"], "can_write": False}])
    assert scoped.get(f"/api/hosts/{fleet['b']}/hardware").status_code == 404
    assert scoped.get(f"/api/hosts/{fleet['b']}/hardware/events").status_code == 404
    assert scoped.get(f"/api/hosts/{fleet['a']}/hardware").status_code == 200
    listed = _ok(scoped.get("/api/hardware/components"))
    assert listed["total"] == 4 and {c["hostname"] for c in listed["components"]} == {"core-a"}
    assert _ok(scoped.get("/api/hardware/events"))["total"] == 2
    assert scoped.get(f"/api/hardware/events?host_id={fleet['b']}").status_code == 404
    csv_rows = list(csv.reader(io.StringIO(scoped.get("/api/hardware/components/export").text)))
    assert {r[0] for r in csv_rows[1:]} == {"core-a"}
    # Read only: no refresh.
    assert scoped.post(f"/api/hosts/{fleet['a']}/hardware/refresh").status_code == 403


def _fake_snmp(monkeypatch, agent: Agent, *, enabled: bool = True):
    async def walk(_ip, _timeout, _cfg, oid, max_rows=500, return_errors=False, engine=None):
        rows, complete = await agent.walk_table(oid, max_rows)
        return rows, (None if complete else "timeout")

    async def get(_ip, _timeout, _cfg, oids, *, engine=None):
        return await agent.get(oids), None

    monkeypatch.setattr(routes_hw, "_snmp_walk", walk)
    monkeypatch.setattr(routes_hw, "_snmp_get_values", get)
    monkeypatch.setattr(routes_hw, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(state, "_resolve_host_snmp_config", lambda _host: {"enabled": enabled})


def test_refresh_reads_now(admin, fleet, monkeypatch):
    host_id = _host(admin, fleet["east"], "edge-d", "192.0.2.14")
    walk, answers = entity(FIXED)
    _fake_snmp(monkeypatch, Agent(walk, answers))
    body = _ok(admin.post(f"/api/hosts/{host_id}/hardware/refresh"))
    assert body["state"] == "ok" and [c["serial"] for c in body["components"]] == ["FOC0000Y0YY"]
    assert [e["event"] for e in body["new_events"]] == ["baseline"]
    # Read again: nothing new.
    assert _ok(admin.post(f"/api/hosts/{host_id}/hardware/refresh"))["new_events"] == []


def test_refresh_errors(admin, fleet, monkeypatch):
    host_id = _host(admin, fleet["east"], "edge-e", "192.0.2.15")
    walk, answers = entity(FIXED)
    _fake_snmp(monkeypatch, Agent(walk, answers, cut={hc.sh.ENT_PHYSICAL_SERIAL_NUM}))
    resp = admin.post(f"/api/hosts/{host_id}/hardware/refresh")
    assert resp.status_code == 502 and "did not answer" in resp.text
    assert _ok(admin.get(f"/api/hosts/{host_id}/hardware"))["state"] == "not_read"

    _fake_snmp(monkeypatch, Agent(walk, answers), enabled=False)
    resp = admin.post(f"/api/hosts/{host_id}/hardware/refresh")
    assert resp.status_code == 409 and "SNMP is not enabled" in resp.text

    ups = _host(admin, fleet["east"], "ups-1", "192.0.2.16", device_type="apc_ups")
    assert admin.post(f"/api/hosts/{ups}/hardware/refresh").status_code == 409

    hc._APPLYING.add(host_id)
    _fake_snmp(monkeypatch, Agent(walk, answers))
    assert admin.post(f"/api/hosts/{host_id}/hardware/refresh").status_code == 409
    hc._APPLYING.discard(host_id)


def test_refresh_is_refused_for_an_unconfirmed_address(admin, fleet, monkeypatch):
    host_id = _host(admin, fleet["east"], "edge-f", "192.0.2.17")

    async def unconfirm():
        import routes.database as db

        conn = await db.get_db()
        try:
            await conn.execute("UPDATE hosts SET address_confirmed = 0 WHERE id = ?", (host_id,))
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(unconfirm())
    walk, answers = entity(FIXED)
    _fake_snmp(monkeypatch, Agent(walk, answers))
    writer = _scoped(admin, "east-writer", [{"inventory_group_id": fleet["east"], "can_write": True}])
    resp = writer.post(f"/api/hosts/{host_id}/hardware/refresh")
    assert resp.status_code == 403 and "awaiting" in resp.text
    # An admin may.
    assert admin.post(f"/api/hosts/{host_id}/hardware/refresh").status_code == 200


def test_fetch_serial_stores_components(admin, fleet, monkeypatch):
    import netcontrol.routes.inventory as inventory_routes

    from test_hardware_components import SHOW_INVENTORY

    host_id = _host(admin, fleet["east"], "edge-g", "192.0.2.18")
    cred = _ok(admin.post("/api/credentials", json={"name": "lab", "username": "ops", "password": "example-pass"}), 201)

    async def run(_host, _cred, command):
        return SHOW_INVENTORY if command == "show inventory" else "System Serial Number : FXS0000Q0AA"

    monkeypatch.setattr(inventory_routes, "_run_show_command", run)
    body = _ok(admin.post(f"/api/hosts/{host_id}/fetch-serial", json={"credential_id": cred["id"]}))
    assert body["serial_number"] == "FXS0000Q0AA" and body["components"] == 8
    assert _ok(admin.get(f"/api/hosts/{host_id}/hardware"))["source"] == "ssh"
    bulk = _ok(admin.post(f"/api/groups/{fleet['east']}/fetch-serials", json={"credential_id": cred["id"]}))
    assert all("components" in row for row in bulk["results"])


def test_another_hosts_name_does_not_cross_object_scope(admin, fleet, monkeypatch):
    # A component last seen on core-b (west) is installed on core-a (east).
    _read(fleet["b"], [comp("FOC0000X0BB", "Switch 1", "chassis"), comp("MOVER00001", "Slot 7")])
    _read(
        fleet["a"],
        [comp("FXS0000Q0AA", "Chassis", "chassis"), comp("JAE0000Z0ZZ", "Slot 1"), comp("MOVER00001", "Slot 9")],
    )
    # A host of east whose next read installs a serial core-b listed.
    edge = _host(admin, fleet["east"], "edge-h", "192.0.2.19")
    _read(edge, [comp("EDGE000001", "Slot 1")])
    _read(fleet["b"], [comp("FOC0000X0BB", "Switch 1", "chassis"), comp("FOC0000Y0YY", "Slot 8")])

    def installed(events: list[dict], serial: str) -> dict:
        return next(e for e in events if e["event"] == "installed" and e["serial"] == serial)

    # Unrestricted: the other host is named in the structured fields, never in the detail.
    seen = installed(_ok(admin.get(f"/api/hosts/{fleet['a']}/hardware/events"))["events"], "MOVER00001")
    assert (seen["previous_host_id"], seen["previous_hostname"]) == (fleet["b"], "core-b")
    assert "core-b" not in seen["detail"]

    scoped = _scoped(admin, "east-rw", [{"inventory_group_id": fleet["east"], "can_write": True}])
    for url in (f"/api/hosts/{fleet['a']}/hardware/events", "/api/hardware/events"):
        hidden = installed(_ok(scoped.get(url))["events"], "MOVER00001")
        assert (hidden["previous_host_id"], hidden["previous_hostname"]) == (None, ""), url
    walk, answers = entity(FIXED)
    _fake_snmp(monkeypatch, Agent(walk, answers))
    body = _ok(scoped.post(f"/api/hosts/{edge}/hardware/refresh"))
    hidden = installed(body["new_events"], "FOC0000Y0YY")
    assert (hidden["previous_host_id"], hidden["previous_hostname"]) == (None, "")
    assert (
        installed(_ok(admin.get(f"/api/hosts/{edge}/hardware/events"))["events"], "FOC0000Y0YY")["previous_hostname"]
        == "core-b"
    )
    # A previous host the scoped caller can read stays named.
    _read(
        fleet["a"],
        [comp("FXS0000Q0AA", "Chassis", "chassis"), comp("MOVER00001", "Slot 9"), comp("EDGE000001", "Slot 4")],
    )
    shown = installed(_ok(scoped.get(f"/api/hosts/{fleet['a']}/hardware/events"))["events"], "EDGE000001")
    assert (shown["previous_host_id"], shown["previous_hostname"]) == (edge, "edge-h")
