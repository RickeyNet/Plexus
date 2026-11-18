"""Device type component templates (migration 0110,
``netcontrol.component_templates``, ``routes.db.component_templates``):
template validation, instantiation into DCIM records (explicit and on
device type assignment), idempotency, interface templates compared with the
known interfaces, console ports, and access and object scope."""

from __future__ import annotations

import pytest
from netcontrol.component_templates import missing_interfaces, plan_components

from mcp_helpers import CsrfClient, admin_client, user_client

DCIM = "/api/dcim"
TEMPLATES = f"{DCIM}/component-templates"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str, **extra) -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios", **extra}
    return int(_ok(admin.post(f"/api/inventory/{group_id}/hosts", json=body), 201)["id"])


def _device_type(admin: CsrfClient, model: str = "EX-9300") -> int:
    maker = _ok(admin.post(f"{DCIM}/manufacturers", json={"name": f"Example {model}"}), 201)
    return int(
        _ok(admin.post(f"{DCIM}/device-types", json={"manufacturer_id": maker["id"], "model": model}), 201)["id"]
    )


def _template(admin: CsrfClient, device_type_id: int, component_type: str, name: str, **extra) -> dict:
    body = {"device_type_id": device_type_id, "component_type": component_type, "name": name, **extra}
    return _ok(admin.post(TEMPLATES, json=body), 201)


def _full_set(admin: CsrfClient, device_type_id: int) -> None:
    _template(admin, device_type_id, "interface", "Gi1/0/1", type="1000base-t")
    _template(admin, device_type_id, "interface", "Gi1/0/2")
    _template(admin, device_type_id, "console_port", "Console", type="rj-45")
    _template(admin, device_type_id, "power_port", "PSU1", maximum_draw=350, allocated_draw=200)
    rear = _template(admin, device_type_id, "rear_port", "Rear1", positions=2)
    _template(admin, device_type_id, "front_port", "Front1", rear_port_template_id=rear["id"], rear_port_position=1)
    _template(admin, device_type_id, "front_port", "Front2", rear_port_template_id=rear["id"], rear_port_position=2)
    _template(admin, device_type_id, "module_bay", "Slot 1")


def _components(admin: CsrfClient, host_id: int) -> dict[str, list[str]]:
    out = {}
    for path, key in (
        ("console-ports", "name"),
        ("power-ports", "name"),
        ("rear-ports", "name"),
        ("front-ports", "name"),
        ("modules", "bay"),
    ):
        out[path] = sorted(r[key] for r in _ok(admin.get(f"{DCIM}/{path}", params={"host_id": host_id})))
    return out


# ── Rules ────────────────────────────────────────────────────────────────────


def test_plan_skips_existing_names_and_orders_rear_before_front():
    templates = [
        {"id": 2, "component_type": "front_port", "name": "F1", "rear_port_template_id": 1, "rear_port_position": 1},
        {"id": 1, "component_type": "rear_port", "name": "R1", "positions": 1, "type": "lc"},
        {"id": 3, "component_type": "module_bay", "name": "Slot 1"},
        {"id": 4, "component_type": "console_port", "name": "con0", "type": "rj-45"},
        {"id": 5, "component_type": "interface", "name": "eth0"},
    ]
    plan = plan_components(templates, {"console_port": ["CON0"], "module": []})
    assert [kind for kind, _ in plan] == ["rear_port", "front_port", "module"]
    assert plan[1][1] == {"name": "F1", "description": "", "rear_port_name": "R1", "rear_port_position": 1}
    assert plan[2][1]["bay"] == "Slot 1" and plan[2][1]["status"] == "planned"
    assert missing_interfaces(templates, ["ETH0"]) == []
    assert missing_interfaces(templates, ["eth1"]) == ["eth0"]


# ── Templates API ────────────────────────────────────────────────────────────


def test_template_validation_and_uniqueness(admin):
    dt = _device_type(admin)
    _template(admin, dt, "console_port", "Console")
    taken = admin.post(TEMPLATES, json={"device_type_id": dt, "component_type": "console_port", "name": "console"})
    assert taken.status_code == 409
    # The same name as another component type is fine.
    _template(admin, dt, "power_port", "Console")
    cases = [
        {"component_type": "console_port", "name": "C2", "type": "lc"},
        {"component_type": "rear_port", "name": "R", "type": "rj-45"},
        {"component_type": "front_port", "name": "F"},
        {"component_type": "power_port", "name": "P", "maximum_draw": 100, "allocated_draw": 200},
        {"component_type": "interface", "name": "I", "maximum_draw": 100},
        {"component_type": "module_bay", "name": "M", "type": "lc"},
        {"component_type": "interface", "name": "   "},
    ]
    for case in cases:
        resp = admin.post(TEMPLATES, json={"device_type_id": dt, **case})
        assert resp.status_code == 422, (case, resp.text)
    assert admin.post(TEMPLATES, json={"device_type_id": dt, "component_type": "fan", "name": "x"}).status_code == 422
    assert (
        admin.post(TEMPLATES, json={"device_type_id": 999, "component_type": "interface", "name": "x"}).status_code
        == 404
    )

    rear = _template(admin, dt, "rear_port", "Rear1", positions=1)
    _template(admin, dt, "front_port", "Front1", rear_port_template_id=rear["id"])
    position_taken = admin.post(
        TEMPLATES,
        json={
            "device_type_id": dt,
            "component_type": "front_port",
            "name": "Front2",
            "rear_port_template_id": rear["id"],
        },
    )
    assert position_taken.status_code == 422
    beyond = admin.post(
        TEMPLATES,
        json={
            "device_type_id": dt,
            "component_type": "front_port",
            "name": "Front3",
            "rear_port_template_id": rear["id"],
            "rear_port_position": 2,
        },
    )
    assert beyond.status_code == 422 and "positions" in beyond.text
    other = _device_type(admin, "EX-4400")
    other_rear = _template(admin, other, "rear_port", "R9")
    cross = admin.post(
        TEMPLATES,
        json={
            "device_type_id": dt,
            "component_type": "front_port",
            "name": "X",
            "rear_port_template_id": other_rear["id"],
        },
    )
    assert cross.status_code == 422 and "same device type" in cross.text
    # A rear port template a front port maps to cannot go.
    assert admin.delete(f"{TEMPLATES}/{rear['id']}").status_code == 409
    listed = _ok(admin.get(f"{DCIM}/device-types/{dt}/components"))["templates"]
    assert {(t["component_type"], t["name"]) for t in listed} == {
        ("console_port", "Console"),
        ("power_port", "Console"),
        ("rear_port", "Rear1"),
        ("front_port", "Front1"),
    }
    front = next(t for t in listed if t["component_type"] == "front_port")
    assert front["rear_port_template_name"] == "Rear1"
    renamed = _ok(admin.put(f"{TEMPLATES}/{front['id']}", json={"name": "Front-A", "description": "patch"}))
    assert renamed["name"] == "Front-A"
    assert admin.put(f"{TEMPLATES}/{front['id']}", json={"device_type_id": other}).status_code == 422
    _ok(admin.delete(f"{TEMPLATES}/{front['id']}"))
    _ok(admin.delete(f"{TEMPLATES}/{rear['id']}"))


# ── Instantiation ────────────────────────────────────────────────────────────


def test_explicit_instantiation_is_idempotent(admin):
    dt = _device_type(admin)
    _full_set(admin, dt)
    gid = _group(admin, "lab")
    host = _host(admin, gid, "sw1", "192.0.2.10")
    # No device type yet: nothing to create.
    empty = _ok(admin.post(f"/api/hosts/{host}/components/instantiate"))
    assert (empty["device_type_id"], empty["created_count"]) == (None, 0)
    # Assigning the device type later creates the components.
    _ok(admin.put(f"/api/hosts/{host}", json={"hostname": "sw1", "ip_address": "192.0.2.10", "device_type_id": dt}))
    assert _components(admin, host) == {
        "console-ports": ["Console"],
        "power-ports": ["PSU1"],
        "rear-ports": ["Rear1"],
        "front-ports": ["Front1", "Front2"],
        "modules": ["Slot 1"],
    }
    fronts = _ok(admin.get(f"{DCIM}/front-ports", params={"host_id": host}))
    assert {f["rear_port_position"] for f in fronts} == {1, 2}
    power = _ok(admin.get(f"{DCIM}/power-ports", params={"host_id": host}))[0]
    assert (power["maximum_draw"], power["allocated_draw"]) == (350, 200)
    # Running it again creates nothing and duplicates nothing.
    again = _ok(admin.post(f"/api/hosts/{host}/components/instantiate"))
    assert (again["created_count"], again["skipped"], again["errors"]) == (0, 6, [])
    assert again["interfaces"] == {"expected": ["Gi1/0/1", "Gi1/0/2"], "missing": ["Gi1/0/1", "Gi1/0/2"]}
    # A deleted component comes back; a renamed one is not touched again.
    console = _ok(admin.get(f"{DCIM}/console-ports", params={"host_id": host}))[0]
    _ok(admin.delete(f"{DCIM}/console-ports/{console['id']}"))
    third = _ok(admin.post(f"/api/hosts/{host}/components/instantiate"))
    assert third["created"] == {"console_port": ["Console"]}
    assert _components(admin, host)["console-ports"] == ["Console"]


def test_assigning_a_device_type_instantiates_once(admin):
    dt = _device_type(admin)
    _template(admin, dt, "console_port", "con0")
    _template(admin, dt, "module_bay", "Slot 1")
    gid = _group(admin, "lab")
    host = _host(admin, gid, "r1", "192.0.2.20", device_type_id=dt)
    assert _components(admin, host)["console-ports"] == ["con0"]
    # A component a person made by hand with the same name is kept, not doubled.
    second = _host(admin, gid, "r2", "192.0.2.21")
    _ok(admin.post(f"{DCIM}/console-ports", json={"host_id": second, "name": "CON0", "type": "usb-c"}), 201)
    result = _ok(admin.post("/api/hosts/bulk-edit", json={"host_ids": [host, second], "set": {"device_type_id": dt}}))
    assert result["updated"] == 2
    ports = _ok(admin.get(f"{DCIM}/console-ports", params={"host_id": second}))
    assert [(p["name"], p["type"]) for p in ports] == [("CON0", "usb-c")]
    assert _components(admin, second)["modules"] == ["Slot 1"]
    # Re-saving the same device type creates nothing new.
    _ok(admin.put(f"/api/hosts/{host}", json={"hostname": "r1", "ip_address": "192.0.2.20", "device_type_id": dt}))
    assert len(_ok(admin.get(f"{DCIM}/console-ports", params={"host_id": host}))) == 1


def test_console_ports_are_a_dcim_record(admin):
    gid = _group(admin, "lab")
    host = _host(admin, gid, "r1", "192.0.2.30")
    port = _ok(admin.post(f"{DCIM}/console-ports", json={"host_id": host, "name": "con0"}), 201)
    assert (port["type"], port["host_name"]) == ("rj-45", "r1")
    assert admin.post(f"{DCIM}/console-ports", json={"host_id": host, "name": "CON0"}).status_code == 409
    assert admin.post(f"{DCIM}/console-ports", json={"host_id": host, "name": "c1", "type": "lc"}).status_code == 422
    assert "usb-c" in _ok(admin.get(f"{DCIM}/choices"))["console_port_types"]


# ── Access and scope ─────────────────────────────────────────────────────────


def test_templates_read_by_anyone_written_by_admins(admin):
    dt = _device_type(admin)
    plain = user_client(admin, "plain-user")
    assert plain.get(f"{DCIM}/device-types/{dt}/components").status_code == 200
    resp = plain.post(TEMPLATES, json={"device_type_id": dt, "component_type": "interface", "name": "eth0"})
    assert resp.status_code == 403
    gid = _group(admin, "lab")
    host = _host(admin, gid, "r1", "192.0.2.40")
    # Instantiating needs the inventory feature.
    assert plain.post(f"/api/hosts/{host}/components/instantiate").status_code == 403


def test_instantiation_respects_object_scope(admin):
    import test_object_scope_api as scope_helpers

    dt = _device_type(admin)
    _template(admin, dt, "console_port", "con0")
    mine, theirs = _group(admin, "mine"), _group(admin, "theirs")
    readonly = _group(admin, "readonly")
    host_mine = _host(admin, mine, "a1", "192.0.2.50", device_type_id=dt)
    host_theirs = _host(admin, theirs, "b1", "192.0.2.51", device_type_id=dt)
    host_ro = _host(admin, readonly, "c1", "192.0.2.52", device_type_id=dt)
    scoped = scope_helpers._scoped(
        admin,
        "scoped-user",
        [{"inventory_group_id": mine, "can_write": True}, {"inventory_group_id": readonly}],
    )
    assert scoped.post(f"/api/hosts/{host_mine}/components/instantiate").status_code == 200
    assert scoped.post(f"/api/hosts/{host_theirs}/components/instantiate").status_code == 404
    assert scoped.post(f"/api/hosts/{host_ro}/components/instantiate").status_code == 403
    assert admin.post("/api/hosts/99999/components/instantiate").status_code == 404
