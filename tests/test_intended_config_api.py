"""Intended configuration API (``netcontrol.routes.intended_config``): access
per route, template and context CRUD with the 400 / 404 / 409 contracts,
preview, variables, generation and its counts, a host's detail, the
re-compare after a new backup, audit events and the background loop."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.intended_config as intended
import pytest
import routes.database as db
from netcontrol.routes.device_config import store_device_config
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

BASE = "/api/intended-config"
TEMPLATES = f"{BASE}/templates"
CONTEXTS = f"{BASE}/contexts"
HOSTS = f"{BASE}/hosts"
PREVIEW = f"{BASE}/preview"
GENERATE = f"{BASE}/generate"

TEMPLATE = """hostname {{ host.name }}
{% for vlan in vlans %}
vlan {{ vlan.vid }}
 name {{ vlan.name }}
{% endfor %}
{% include 'ntp' %}
"""
NTP = """{% for server in context.ntp %}
ntp server {{ server }}
{% endfor %}
"""
BACKUP = """hostname edge-r1
vlan 10
 name users
 state active
ntp server 192.0.2.1
logging host 192.0.2.30
"""


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _host(admin: CsrfClient, name: str = "edge-r1", ip: str = "192.0.2.10", group: str | None = None) -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": group or f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _template(admin: CsrfClient, name: str = "base", text: str = TEMPLATE, **extra) -> dict:
    return _ok(admin.post(TEMPLATES, json={"name": name, "kind": "device", "template_text": text, **extra}), 201)


def _context(admin: CsrfClient, name: str = "ntp", data: dict | None = None, **extra) -> dict:
    body = {"name": name, "data": data if data is not None else {"ntp": ["192.0.2.1", "192.0.2.2"]}, **extra}
    return _ok(admin.post(CONTEXTS, json=body), 201)


def _setup(admin: CsrfClient) -> int:
    host = _host(admin)
    _template(admin)
    _template(admin, "ntp", NTP, kind="snippet")
    _context(admin)
    asyncio.run(db.create_vlan(vid=10, name="users"))
    return host


async def _clear_inventory() -> None:
    """Remove the demo inventory the app seeds on first start, so counts
    over every host are this test's own."""
    conn = await db.get_db()
    try:
        await conn.execute("DELETE FROM inventory_groups")
        await conn.commit()
    finally:
        await conn.close()


def _store(host_id: int, text: str = BACKUP) -> None:
    asyncio.run(store_device_config(host_id, text, "", capture_method="topology"))


# ── Access ───────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for path in (TEMPLATES, f"{TEMPLATES}/1", CONTEXTS, f"{CONTEXTS}/1", HOSTS, f"{HOSTS}/1", f"{HOSTS}/1/variables"):
        assert anon.get(path).status_code == 401, path
    for path in (TEMPLATES, CONTEXTS, PREVIEW, GENERATE):
        assert anon.post(path, json={}).status_code in (401, 403), path


def test_reads_need_config_drift_and_writes_need_admin(admin):
    host = _setup(admin)
    template = _ok(admin.get(TEMPLATES))["templates"][0]
    context = _ok(admin.get(CONTEXTS))["contexts"][0]
    reads = (
        TEMPLATES,
        f"{TEMPLATES}/{template['id']}",
        CONTEXTS,
        f"{CONTEXTS}/{context['id']}",
        HOSTS,
        f"{HOSTS}/{host}/variables",
    )
    plain = user_client(admin, "plain-user", features=["inventory"])
    for path in reads:
        assert plain.get(path).status_code == 403, path
    assert plain.post(GENERATE, json={}).status_code == 403
    reader = user_client(admin, "drift-user", features=["config-drift", "config-drift.write"])
    for path in reads:
        assert reader.get(path).status_code == 200, path
    assert _ok(reader.post(GENERATE, json={"host_ids": [host]}))["generated"] == 1
    assert reader.get(f"{HOSTS}/{host}").status_code == 200
    writes = (
        reader.post(TEMPLATES, json={"name": "x", "kind": "device"}),
        reader.put(f"{TEMPLATES}/{template['id']}", json={"name": "x", "kind": "device"}),
        reader.delete(f"{TEMPLATES}/{template['id']}"),
        reader.post(CONTEXTS, json={"name": "x", "data": {}}),
        reader.put(f"{CONTEXTS}/{context['id']}", json={"name": "x", "data": {}}),
        reader.delete(f"{CONTEXTS}/{context['id']}"),
        reader.post(PREVIEW, json={"host_id": host}),
    )
    assert [r.status_code for r in writes] == [403] * len(writes)


# ── Templates ────────────────────────────────────────────────────────────────


def test_template_crud_and_contracts(admin):
    group = int(_ok(admin.post("/api/inventory", json={"name": "core"}), 201)["id"])
    made = _template(admin, " base ", device_type=" cisco_ios ", group_id=group, description=" d ")
    assert {k: made[k] for k in ("name", "kind", "device_type", "group_id", "description", "enabled")} == {
        "name": "base",
        "kind": "device",
        "device_type": "cisco_ios",
        "group_id": group,
        "description": "d",
        "enabled": True,
    }
    assert made["updated_by"] == "admin" and made["host_count"] == 0
    assert _ok(admin.get(f"{TEMPLATES}/{made['id']}")) == made
    resp = admin.post(TEMPLATES, json={"name": "BASE", "kind": "device"})
    assert resp.status_code == 409 and "already exists" in resp.json()["error"]["message"]

    bad = admin.post(TEMPLATES, json={"name": "broken", "kind": "device", "template_text": "a\nb\n{% if %}\n"})
    assert bad.status_code == 400
    assert bad.json()["detail"]["line"] == 3 and bad.json()["detail"]["message"]
    for body in (
        {"name": " ", "kind": "device"},
        {"name": "x" * 101, "kind": "device"},
        {"name": "x", "kind": "router"},
        {"name": "x", "kind": "device", "role_id": 999},
        {"name": "x", "kind": "device", "site_id": 999},
        {"name": "x", "kind": "device", "group_id": 999},
        {"name": "x", "kind": "device", "description": "d" * 501},
    ):
        assert admin.post(TEMPLATES, json=body).status_code == 400, body
    assert admin.post(TEMPLATES, json={"kind": "device"}).status_code == 422

    snippet = _ok(
        admin.post(TEMPLATES, json={"name": "snip", "kind": "snippet", "group_id": 999, "device_type": "x"}), 201
    )
    assert (snippet["group_id"], snippet["device_type"]) == (None, "")

    updated = _ok(admin.put(f"{TEMPLATES}/{made['id']}", json={"name": "Base", "kind": "device", "enabled": False}))
    assert (updated["name"], updated["group_id"], updated["enabled"]) == ("Base", None, False)
    assert admin.put(f"{TEMPLATES}/{made['id']}", json={"name": "snip", "kind": "device"}).status_code == 409
    assert [t["name"] for t in _ok(admin.get(TEMPLATES))["templates"]] == ["Base", "snip"]
    assert _ok(admin.delete(f"{TEMPLATES}/{made['id']}")) == {"ok": True}
    for resp in (
        admin.get(f"{TEMPLATES}/{made['id']}"),
        admin.put(f"{TEMPLATES}/{made['id']}", json={"name": "x", "kind": "device"}),
        admin.delete(f"{TEMPLATES}/{made['id']}"),
    ):
        assert resp.status_code == 404 and resp.json()["error"]["message"] == "Template not found"


# ── Contexts ─────────────────────────────────────────────────────────────────


def test_context_crud_and_contracts(admin):
    host = _host(admin)
    made = _context(admin, " ntp ", weight=5, host_id=host)
    assert {k: made[k] for k in ("name", "weight", "data", "host_id", "enabled")} == {
        "name": "ntp",
        "weight": 5,
        "data": {"ntp": ["192.0.2.1", "192.0.2.2"]},
        "host_id": host,
        "enabled": True,
    }
    _context(admin, "a", weight=5)
    _context(admin, "first", weight=1)
    assert [c["name"] for c in _ok(admin.get(CONTEXTS))["contexts"]] == ["first", "a", "ntp"]
    assert admin.post(CONTEXTS, json={"name": "NTP", "data": {}}).status_code == 409
    for body in (
        {"name": "x", "data": [1, 2]},
        {"name": "x"},
        {"name": "x", "data": {}, "weight": -1},
        {"name": "x", "data": {}, "weight": 100001},
        {"name": "x", "data": {}, "host_id": 999999},
        {"name": "x", "data": {"k": "v" * 70000}},
    ):
        resp = admin.post(CONTEXTS, json=body)
        assert resp.status_code == 400, body
    assert "JSON object" in admin.post(CONTEXTS, json={"name": "x", "data": "text"}).json()["error"]["message"]
    updated = _ok(admin.put(f"{CONTEXTS}/{made['id']}", json={"name": "ntp", "data": {"a": 1}, "enabled": False}))
    assert (updated["data"], updated["host_id"], updated["enabled"], updated["weight"]) == ({"a": 1}, None, False, 1000)
    assert _ok(admin.get(f"{CONTEXTS}/{made['id']}")) == updated
    assert admin.put(f"{CONTEXTS}/{made['id']}", json={"name": "A", "data": {}}).status_code == 409
    assert _ok(admin.delete(f"{CONTEXTS}/{made['id']}")) == {"ok": True}
    assert admin.get(f"{CONTEXTS}/{made['id']}").json()["error"]["message"] == "Context not found"
    assert admin.put(f"{CONTEXTS}/{made['id']}", json={"name": "z", "data": {}}).status_code == 404
    assert admin.delete(f"{CONTEXTS}/{made['id']}").status_code == 404


# ── Variables and preview ────────────────────────────────────────────────────


def test_variables(admin):
    host = _host(admin, group="core")
    role = asyncio.run(db.create_device_role(name="Edge"))
    site = asyncio.run(db.create_geo_site(name="Site A", description="campus", address="1 Example Way"))
    maker = asyncio.run(db.create_manufacturer(name="Example Networks"))
    hardware = asyncio.run(db.create_device_type(manufacturer_id=maker["id"], model="EX-1", part_number="EX-1-AC"))
    asyncio.run(
        db.set_host_device_fields(
            host,
            {
                "role_id": role["id"],
                "site_id": site["id"],
                "device_type_id": hardware["id"],
                "location_detail": "rack 2",
            },
        )
    )
    tag = asyncio.run(db.create_tag(name="core"))
    asyncio.run(db.set_object_data("host", str(host), [tag["id"]], {}))
    asyncio.run(db.create_vlan(vid=10, name="users", site_id=site["id"]))
    asyncio.run(db.create_vlan(vid=20, name="nowhere"))
    asyncio.run(
        db.replace_host_bindings(
            host,
            [
                {
                    "interface": "GigabitEthernet0/1",
                    "interface_key": "gigabitethernet0/1",
                    "address": "192.0.2.1",
                    "prefix_length": 24,
                    "network": "192.0.2.0/24",
                    "vrf_name": "BLUE",
                    "role": "primary",
                    "protocol": "",
                    "svi_vid": 0,
                }
            ],
            {"BLUE": 1},
        )
    )

    async def _port() -> None:
        conn = await db.get_db()
        try:
            await conn.execute(
                "INSERT INTO interface_inventory (host_id, if_index, name, access_vlan) VALUES (?, ?, ?, ?)",
                (host, 1, "GigabitEthernet0/1", 10),
            )
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(_port())
    low = _context(admin, "low", {"ntp": ["192.0.2.1"], "snmp": {"location": "a"}}, weight=1)
    high = _context(admin, "high", {"snmp": {"contact": "noc@example.com"}}, weight=2, host_id=host)
    elsewhere = asyncio.run(db.create_geo_site(name="Site B"))
    _context(admin, "other-site", {"x": 1}, site_id=elsewhere["id"])
    _context(admin, "disabled", {"x": 2}, enabled=False)
    body = _ok(admin.get(f"{HOSTS}/{host}/variables"))
    assert body["contexts"] == [
        {"id": low["id"], "name": "low", "weight": 1},
        {"id": high["id"], "name": "high", "weight": 2},
    ]
    v = body["variables"]
    assert v["host"] == {
        "id": host,
        "name": "edge-r1",
        "ip": "192.0.2.10",
        "driver": "cisco_ios",
        "model": "",
        "serial": "",
        "version": "",
        "category": "",
        "vrf": "",
        "vlan_id": "",
        "location_detail": "rack 2",
        "role": "Edge",
        "status": v["host"]["status"],
        "manufacturer": "Example Networks",
        "hardware_model": "EX-1",
        "part_number": "EX-1-AC",
        "tags": ["core"],
        "custom_fields": {},
    }
    assert v["group"]["name"] == "core" and v["group"]["tags"] == []
    assert v["site"] == {"id": site["id"], "name": "Site A", "description": "campus", "address": "1 Example Way"}
    assert v["vlans"] == [{"vid": 10, "name": "users", "description": ""}]
    assert v["vrfs"] == [{"name": "BLUE", "rd": "", "description": ""}]
    assert v["interfaces"][0]["access_vlan"] == 10
    assert v["interfaces"][0]["addresses"] == [
        {"address": "192.0.2.1", "prefix_length": 24, "network": "192.0.2.0/24", "vrf": "BLUE", "role": "primary"}
    ]
    assert v["context"] == {"ntp": ["192.0.2.1"], "snmp": {"location": "a", "contact": "noc@example.com"}}
    assert admin.get(f"{HOSTS}/999999/variables").status_code == 404


def test_host_without_site_sees_no_site_vlans(admin):
    host = _host(admin)
    site = asyncio.run(db.create_geo_site(name="Site A"))
    asyncio.run(db.create_vlan(vid=10, name="site", site_id=site["id"]))
    asyncio.run(db.create_vlan(vid=20, name="global"))
    v = _ok(admin.get(f"{HOSTS}/{host}/variables"))["variables"]
    assert v["vlans"] == [{"vid": 20, "name": "global", "description": ""}]
    assert v["site"] == {"id": None, "name": "", "description": "", "address": ""}


def test_preview(admin):
    host = _setup(admin)
    template = _ok(admin.get(TEMPLATES))["templates"][0]
    selected = _ok(admin.post(PREVIEW, json={"host_id": host}))
    assert selected == {
        "template_name": "base",
        "config_text": "hostname edge-r1\nvlan 10\n name users\nntp server 192.0.2.1\nntp server 192.0.2.2\n",
        "error": None,
    }
    assert _ok(admin.post(PREVIEW, json={"host_id": host, "template_id": template["id"]})) == selected
    text = _ok(admin.post(PREVIEW, json={"host_id": host, "template_text": "x {{ host.ip }}\n{{ nope }}"}))
    assert text == {
        "template_name": None,
        "config_text": "",
        "error": {"message": "'nope' is undefined", "template": "(preview)", "line": 2},
    }
    named = _ok(
        admin.post(PREVIEW, json={"host_id": host, "template_id": template["id"], "template_text": "{{ host.ip }}"})
    )
    assert (named["template_name"], named["config_text"]) == ("base", "192.0.2.10\n")
    syntax = _ok(admin.post(PREVIEW, json={"host_id": host, "template_text": "a\n{% for %}"}))
    assert syntax["error"]["line"] == 2
    assert asyncio.run(db.list_intended_configs()) == []
    other = _host(admin, "edge-r2", "192.0.2.11")
    asyncio.run(db.update_config_template(template["id"], {**_values(template), "device_type": "juniper_junos"}))
    none = _ok(admin.post(PREVIEW, json={"host_id": other}))
    assert none["template_name"] is None and none["error"]["message"] == "No template matches this host."
    assert admin.post(PREVIEW, json={"host_id": 999999}).status_code == 404
    assert admin.post(PREVIEW, json={"host_id": host, "template_id": 999999}).status_code == 404


def _values(template: dict) -> dict:
    keys = ("name", "kind", "device_type", "role_id", "site_id", "group_id", "template_text", "description", "enabled")
    return {k: template[k] for k in keys}


# ── Generation, rows and detail ──────────────────────────────────────────────


def test_generate_rows_detail_and_counts(admin):
    asyncio.run(_clear_inventory())
    host = _setup(admin)
    other = _host(admin, "edge-r2", "192.0.2.11")
    broken = _host(admin, "edge-r3", "192.0.2.12")
    group_of_broken = asyncio.run(db.get_host(broken))["group_id"]
    _template(admin, "broken", "hostname {{ host.name }}\n{{ host.nope }}\n", group_id=group_of_broken)
    _store(host, BACKUP + "ntp server 192.0.2.2\n")
    _template(admin, "junos only", "x", device_type="juniper_junos")
    result = _ok(admin.post(GENERATE, json={}))
    assert result == {"hosts": 3, "generated": 3, "changed": 3, "errors": 1, "no_template": 0}
    again = _ok(admin.post(GENERATE, json={}))
    assert again["changed"] == 0 and again["generated"] == result["generated"]

    listing = _ok(admin.get(HOSTS))
    counts = listing["counts"]
    assert counts == {
        "hosts": 3,
        "generated": 3,
        "errors": 1,
        "compliant": 1,
        "non_compliant": 0,
        "unknown": 2,
        "no_template": 0,
    }
    rows = {r["host_id"]: r for r in listing["rows"]}
    row = rows[host]
    assert set(row) == {
        "host_id",
        "hostname",
        "ip_address",
        "group_id",
        "group_name",
        "template_id",
        "template_name",
        "status",
        "error",
        "compliance",
        "missing_count",
        "extra_count",
        "backup_id",
        "generated_at",
        "changed_at",
        "compared_at",
    }
    assert (row["template_name"], row["status"], row["error"], row["compliance"]) == ("base", "ok", None, "compliant")
    assert (row["missing_count"], row["extra_count"]) == (0, 1)
    failed = rows[broken]
    assert failed["status"] == "error" and failed["compliance"] == "unknown"
    assert "'dict object' has no attribute 'nope'" in failed["error"] and "line 2" in failed["error"]
    assert [r["host_id"] for r in _ok(admin.get(HOSTS, params={"status": "error"}))["rows"]] == [broken]
    assert [r["host_id"] for r in _ok(admin.get(HOSTS, params={"compliance": "compliant"}))["rows"]] == [host]
    assert [r["host_id"] for r in _ok(admin.get(HOSTS, params={"group_id": row["group_id"]}))["rows"]] == [host]
    assert other in rows and rows[other]["compliance"] == "unknown"
    assert admin.get(HOSTS, params={"compliance": "maybe"}).status_code == 400
    assert admin.get(HOSTS, params={"status": "maybe"}).status_code == 400

    detail = _ok(admin.get(f"{HOSTS}/{host}"))
    assert detail["config_text"].startswith("hostname edge-r1\n")
    assert detail["lines"][0] == {"text": "hostname edge-r1", "missing": False}
    assert detail["extra"] == [{"path": ["vlan 10"], "text": "state active"}]
    assert detail["backup"]["id"] == row["backup_id"] and detail["backup"]["captured_at"]
    no_backup = _ok(admin.get(f"{HOSTS}/{broken}"))
    assert no_backup["backup"] is None and no_backup["lines"] == [] and no_backup["extra"] == []
    assert admin.get(f"{HOSTS}/999999").status_code == 404

    templates = {t["name"]: t for t in _ok(admin.get(TEMPLATES))["templates"]}
    assert templates["base"]["host_count"] == 2 and templates["broken"]["host_count"] == 1


def test_generate_scopes_and_no_template(admin):
    asyncio.run(_clear_inventory())
    host = _setup(admin)
    other = _host(admin, "edge-r2", "192.0.2.11", group="edge")
    edge_group = asyncio.run(db.get_host(other))["group_id"]
    assert _ok(admin.post(GENERATE, json={"host_ids": [host, 999999]})) == {
        "hosts": 1,
        "generated": 1,
        "changed": 1,
        "errors": 0,
        "no_template": 0,
    }
    assert _ok(admin.post(GENERATE, json={"group_id": edge_group}))["hosts"] == 1
    assert _ok(admin.post(GENERATE, json={"host_ids": []}))["hosts"] == 0
    assert admin.post(GENERATE, json={"group_id": 999999}).status_code == 404
    # Scope the template away from the second host: its row is removed.
    template = next(t for t in _ok(admin.get(TEMPLATES))["templates"] if t["name"] == "base")
    host_group = asyncio.run(db.get_host(host))["group_id"]
    _ok(admin.put(f"{TEMPLATES}/{template['id']}", json={**_values(template), "group_id": host_group}))
    result = _ok(admin.post(GENERATE, json={}))
    assert (result["hosts"], result["generated"], result["no_template"]) == (2, 1, 1)
    assert admin.get(f"{HOSTS}/{other}").status_code == 404
    counts = _ok(admin.get(HOSTS))["counts"]
    assert counts == {
        "hosts": 2,
        "generated": 1,
        "errors": 0,
        "compliant": 0,
        "non_compliant": 0,
        "unknown": 1,
        "no_template": 1,
    }


def test_new_backup_recompares_the_host(admin):
    host = _setup(admin)
    _ok(admin.post(GENERATE, json={}))
    assert _ok(admin.get(f"{HOSTS}/{host}"))["compliance"] == "unknown"
    _store(host, "hostname edge-r1\nvlan 10\n")
    row = _ok(admin.get(f"{HOSTS}/{host}"))
    assert row["compliance"] == "non_compliant" and row["missing_count"] == 3
    assert [line["text"] for line in row["lines"] if line["missing"]] == [
        " name users",
        "ntp server 192.0.2.1",
        "ntp server 192.0.2.2",
    ]
    _store(host, BACKUP + "ntp server 192.0.2.2\n")
    row = _ok(admin.get(f"{HOSTS}/{host}"))
    assert row["compliance"] == "compliant" and row["backup"]["id"] == row["backup_id"]
    # The same configuration again writes no new backup row.
    compared = row["compared_at"]
    _store(host, BACKUP + "ntp server 192.0.2.2\n")
    assert _ok(admin.get(f"{HOSTS}/{host}"))["compared_at"] == compared


def test_recompare_is_best_effort(admin, monkeypatch):
    host = _setup(admin)
    assert asyncio.run(intended.recompare_host(host)) is None  # no row yet
    _ok(admin.post(GENERATE, json={}))

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("database gone")

    monkeypatch.setattr(intended.db, "get_intended_config", _boom)
    assert asyncio.run(intended.recompare_host(host)) is None
    _store(host)  # the capture still succeeds
    assert asyncio.run(db.get_newest_host_config_backup(host)) is not None


def test_writes_and_generate_are_audited(admin):
    template = _template(admin)
    _ok(admin.put(f"{TEMPLATES}/{template['id']}", json=_values(template)))
    admin.delete(f"{TEMPLATES}/{template['id']}")
    context = _context(admin)
    _ok(admin.put(f"{CONTEXTS}/{context['id']}", json={"name": "ntp", "data": {}}))
    admin.delete(f"{CONTEXTS}/{context['id']}")
    _ok(admin.post(GENERATE, json={}))
    events = asyncio.run(db.get_audit_events(limit=50, category="config"))
    assert {e["action"] for e in events} >= {
        "intended_template_create",
        "intended_template_update",
        "intended_template_delete",
        "intended_context_create",
        "intended_context_update",
        "intended_context_delete",
        "intended_generate",
    }
    assert all(e["user"] == "admin" for e in events if e["action"].startswith("intended_"))


# ── Background loop ──────────────────────────────────────────────────────────


def test_loop_runs_first_then_on_wake(monkeypatch):
    calls: list = []
    monkeypatch.setattr(intended, "FIRST_RUN_DELAY_SECONDS", 0)
    monkeypatch.setattr(intended, "WAKE_DELAY_SECONDS", 0)
    monkeypatch.setattr(intended, "INTERVAL_SECONDS", 0.05)

    async def _generate(host_ids):
        calls.append(host_ids)
        if len(calls) == 2:
            raise RuntimeError("one failure is logged, not fatal")
        return {"hosts": 1, "generated": 1, "changed": 0, "errors": 0, "no_template": 0}

    monkeypatch.setattr(intended, "generate_for_hosts", _generate)

    async def _run() -> None:
        task = asyncio.create_task(intended.intended_config_loop())
        await asyncio.sleep(0.01)
        intended.wake_generation()
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run())
    assert len(calls) >= 3 and all(c is None for c in calls)
