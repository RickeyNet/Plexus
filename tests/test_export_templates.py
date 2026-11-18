"""Export templates: the rules (``netcontrol.export_templates``), the API
(``netcontrol.routes.export_templates``) and the storage
(``routes.db.export_templates``, migration 0112)."""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol import export_templates as et
from netcontrol.custom_fields import CustomFieldError
from netcontrol.routes import state
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

BASE = "/api/export-templates"
HOSTS_CSV = "hostname,ip\n{% for h in queryset %}{{ h.hostname }},{{ h.ip_address }}\n{% endfor %}"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _group(admin: CsrfClient, name: str) -> int:
    resp = admin.post("/api/inventory", json={"name": name})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str) -> int:
    resp = admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": name, "ip_address": ip})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _template(admin: CsrfClient, **kw) -> dict:
    body = {
        "name": "hosts csv",
        "object_type": "host",
        "template_text": HOSTS_CSV,
        "mime_type": "text/csv",
        "file_extension": "csv",
    }
    body.update(kw)
    resp = admin.post(BASE, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── Rules ────────────────────────────────────────────────────────────────────


def test_migration_is_0112_and_idempotent_ddl():
    mod = importlib.import_module("routes.migrations.0112_add_export_templates")
    assert mod.VERSION == 112
    assert "IF NOT EXISTS" in mod._TABLE
    assert all("IF NOT EXISTS" in s for s in mod._INDEXES)


@pytest.mark.parametrize(
    ("raw", "out"),
    [("text/CSV", "text/csv"), ("", "text/plain"), ("application/vnd.ms-excel", "application/vnd.ms-excel")],
)
def test_clean_mime_type(raw, out):
    assert et.clean_mime_type(raw) == out


@pytest.mark.parametrize("raw", ["text", "text/csv; charset=utf-8", "a/b/c", "text/<x>"])
def test_clean_mime_type_refuses(raw):
    with pytest.raises(CustomFieldError):
        et.clean_mime_type(raw)


def test_clean_extension():
    assert et.clean_extension(".CSV") == "csv"
    assert et.clean_extension("") == ""
    for bad in ("c.sv", "a/b", "x" * 17):
        with pytest.raises(CustomFieldError):
            et.clean_extension(bad)


def test_render_gives_queryset_now_and_type():
    now = datetime(2026, 1, 2, 3, 4, 5, 678, tzinfo=UTC)
    result = et.render(
        "{{ object_type }} {{ now.strftime('%Y') }} {{ queryset|length }}{% for o in queryset %} {{ o.name }}{% endfor %}",
        "site",
        [{"name": "a"}, {"name": "b"}],
        now,
    )
    assert result.error is None
    assert result.config_text == "site 2026 2 a b\n"


def test_render_is_sandboxed():
    result = et.render("{{ queryset.__class__.__mro__ }}", "host", [])
    assert result.error is not None
    result = et.render("{% for i in range(10**9) %}x{% endfor %}", "host", [])
    assert result.error is not None


def test_render_error_has_line():
    result = et.render("ok\n{{ missing.attr }}", "host", [])
    assert result.error is not None and result.error.line == 2


# ── API: CRUD ────────────────────────────────────────────────────────────────


def test_crud_round_trip_and_audit(admin):
    record = _template(admin, description="All hosts")
    assert record["mime_type"] == "text/csv" and record["file_extension"] == "csv" and record["as_attachment"]
    assert record["created_by"] == "admin" and len(record["created_at"]) == 19
    assert admin.get(f"{BASE}/{record['id']}").json()["name"] == "hosts csv"
    assert [t["id"] for t in admin.get(BASE, params={"object_type": "host"}).json()["templates"]] == [record["id"]]
    assert admin.get(BASE, params={"object_type": "vlan"}).json()["templates"] == []

    body = {**record, "name": "Hosts CSV", "as_attachment": False}
    updated = admin.put(f"{BASE}/{record['id']}", json=body)
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Hosts CSV" and updated.json()["as_attachment"] is False

    assert admin.delete(f"{BASE}/{record['id']}").status_code == 200
    assert admin.get(f"{BASE}/{record['id']}").status_code == 404

    actions = {e["action"] for e in asyncio.run(db.get_audit_events(limit=50, category="export_templates"))}
    assert {"export_template_create", "export_template_update", "export_template_delete"} <= actions


def test_names_unique_per_type_ignoring_case(admin):
    _template(admin)
    dup = admin.post(BASE, json={"name": "HOSTS CSV", "object_type": "host", "template_text": "x"})
    assert dup.status_code == 409
    other = admin.post(BASE, json={"name": "hosts csv", "object_type": "site", "template_text": "x"})
    assert other.status_code == 201


def test_create_validates(admin):
    bad_type = admin.post(BASE, json={"name": "x", "object_type": "nope", "template_text": ""})
    assert bad_type.status_code == 400
    bad_mime = admin.post(BASE, json={"name": "x", "object_type": "host", "mime_type": "csv"})
    assert bad_mime.status_code == 400
    syntax = admin.post(BASE, json={"name": "x", "object_type": "host", "template_text": "a\n{% for %}"})
    assert syntax.status_code == 400
    assert syntax.json()["detail"]["line"] == 2


def test_object_types_catalogue(admin):
    types = admin.get(f"{BASE}/object-types").json()["object_types"]
    assert {t["key"] for t in types} == {"host", "prefix", "ip_address", "vlan", "circuit", "site"}
    assert all(t["readable"] for t in types)


# ── API: render and preview ──────────────────────────────────────────────────


def test_render_hosts_csv_with_filters(admin):
    core = _group(admin, "core")
    edge = _group(admin, "edge")
    _host(admin, core, "core-1", "192.0.2.1")
    _host(admin, edge, "edge-1", "198.51.100.1")
    record = _template(admin)

    resp = admin.get(f"{BASE}/{record['id']}/render")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "text/csv; charset=utf-8"
    assert resp.headers["content-disposition"] == 'attachment; filename="hosts_csv.csv"'
    assert "sandbox" in resp.headers["content-security-policy"]
    assert resp.text.startswith("hostname,ip\n")
    assert "core-1,192.0.2.1\n" in resp.text and "edge-1,198.51.100.1\n" in resp.text

    only_edge = admin.get(f"{BASE}/{record['id']}/render", params={"group_id": edge})
    assert only_edge.text == "hostname,ip\nedge-1,198.51.100.1\n"
    assert admin.get(f"{BASE}/{record['id']}/render", params={"group_id": "x"}).status_code == 400


def test_render_inline_and_template_error_is_400(admin):
    record = _template(
        admin, name="broken", template_text="line1\n{{ no_such_variable.hostname }}", as_attachment=False
    )
    resp = admin.get(f"{BASE}/{record['id']}/render")
    assert resp.status_code == 400
    assert resp.json()["detail"]["line"] == 2

    empty = _group(admin, "empty")
    ok = _template(admin, name="note", template_text="{{ queryset|length }} hosts", mime_type="", file_extension="")
    resp = admin.get(f"{BASE}/{ok['id']}/render", params={"group_id": empty})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"
    assert resp.headers["content-disposition"] == 'attachment; filename="note"'
    assert resp.text == "0 hosts\n"


def test_render_vlans_and_sites_through_their_list_endpoints(admin):
    assert admin.post("/api/ipam/vlans", json={"vid": 120, "name": "users"}).status_code == 201
    assert admin.post("/api/ipam/vlans", json={"vid": 300, "name": "voice"}).status_code == 201
    vlans = _template(
        admin,
        name="vlans",
        object_type="vlan",
        template_text="{% for v in queryset %}vlan {{ v.vid }}\n name {{ v.name }}\n{% endfor %}",
    )
    resp = admin.get(f"{BASE}/{vlans['id']}/render")
    assert "vlan 120\n name users\nvlan 300\n name voice\n" in resp.text
    assert admin.get(f"{BASE}/{vlans['id']}/render", params={"vid": 300}).text == "vlan 300\n name voice\n"

    assert admin.post("/api/geo/sites", json={"name": "Branch 1"}).status_code == 201
    sites = _template(
        admin, name="sites", object_type="site", template_text="{% for s in queryset %}{{ s.name }}{% endfor %}"
    )
    assert "Branch 1" in admin.get(f"{BASE}/{sites['id']}/render").text


def test_render_prefixes(admin):
    resp = admin.post("/api/ipam/prefixes", json={"subnet": "203.0.113.0/24", "description": "lab"})
    assert resp.status_code == 201, resp.text
    record = _template(
        admin,
        name="prefixes",
        object_type="prefix",
        template_text="{% for p in queryset %}{{ p.subnet }} {{ p.description }};{% endfor %}",
    )
    assert "203.0.113.0/24 lab;" in admin.get(f"{BASE}/{record['id']}/render").text


def test_preview_renders_first_n_and_reports_errors(admin):
    group = _group(admin, "core")
    for n in range(3):
        _host(admin, group, f"sw-{n}", f"192.0.2.{n + 1}")
    # The preview takes the same filters as a render, in its query string.
    resp = admin.post(
        f"{BASE}/preview?group_id={group}",
        json={
            "object_type": "host",
            "template_text": "{% for h in queryset %}{{ h.hostname }} {% endfor %}",
            "limit": 2,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["output"] == "sw-0 sw-1\n" and body["count"] == 2 and body["total"] == 3 and body["error"] is None

    bad = admin.post(f"{BASE}/preview", json={"object_type": "host", "template_text": "{{ nope.x }}"}).json()
    assert bad["error"]["line"] == 1 and bad["output"] == ""


# ── Access ───────────────────────────────────────────────────────────────────


def test_non_admin_reads_and_renders_by_feature_but_cannot_write(admin):
    group = _group(admin, "core")
    _host(admin, group, "core-1", "192.0.2.1")
    hosts = _template(admin)
    vlans = _template(admin, name="vlans", object_type="vlan", template_text="x")

    user = user_client(admin, "inv-user", features=["inventory"])
    listed = user.get(BASE).json()["templates"]
    assert [t["id"] for t in listed] == [hosts["id"]]
    assert user.get(f"{BASE}/{vlans['id']}").status_code == 404
    assert user.get(f"{BASE}/{vlans['id']}/render").status_code == 404
    rendered = user.get(f"{BASE}/{hosts['id']}/render", params={"group_id": group})
    assert rendered.text == "hostname,ip\ncore-1,192.0.2.1\n"

    assert user.post(BASE, json={"name": "x", "object_type": "host"}).status_code == 403
    assert user.put(f"{BASE}/{hosts['id']}", json={"name": "x", "object_type": "host"}).status_code == 403
    assert user.delete(f"{BASE}/{hosts['id']}").status_code == 403
    assert user.post(f"{BASE}/preview", json={"object_type": "host"}).status_code == 403


def test_signed_out_is_refused():
    client = TestClient(app_module.app, raise_server_exceptions=False)
    assert client.get(BASE).status_code == 401


def test_scoped_user_renders_only_their_hosts_and_no_prefixes(admin):
    a = _group(admin, "site-a")
    b = _group(admin, "site-b")
    _host(admin, a, "edge-a", "192.0.2.10")
    _host(admin, b, "edge-b", "198.51.100.20")
    hosts = _template(admin)
    prefixes = _template(admin, name="p", object_type="prefix", template_text="x")

    group = admin.post(
        "/api/admin/access-groups",
        json={
            "name": "a only",
            "feature_keys": ["inventory", "ipam"],
            "object_scope": "groups",
            "inventory_scopes": [{"inventory_group_id": a}],
        },
    )
    assert group.status_code == 201, group.text
    made = admin.post(
        "/api/admin/users", json={"username": "east", "password": "password123", "group_ids": [group.json()["id"]]}
    )
    assert made.status_code == 201, made.text
    client = TestClient(app_module.app, raise_server_exceptions=False)
    login = client.post("/api/auth/login", json={"username": "east", "password": "password123"})
    scoped = CsrfClient(client, login.json()["csrf_token"])

    assert scoped.get(f"{BASE}/{hosts['id']}/render").text == "hostname,ip\nedge-a,192.0.2.10\n"
    # Refused either way: 403 when the scoped account keeps the ipam feature
    # (prefix rows carry no tenant to scope by), 404 when its scope drops ipam.
    assert scoped.get(f"{BASE}/{prefixes['id']}/render").status_code in (403, 404)
