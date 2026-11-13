"""Custom fields and tags API (``netcontrol.routes.custom_fields``) and the
inline data, filters and CSV columns it adds to the inventory and IPAM lists."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

FIELDS = "/api/custom-fields"
TAGS = "/api/tags"
PREFIX = "/api/ipam/prefix-custom-data"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _group(admin: CsrfClient, name: str = "core") -> int:
    resp = admin.post("/api/inventory", json={"name": name})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _host(admin: CsrfClient, group_id: int, name: str = "edge-sw1", ip: str = "192.0.2.10") -> int:
    resp = admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": name, "ip_address": ip})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _field(admin: CsrfClient, **kw) -> dict:
    body = {"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
    body.update(kw)
    resp = admin.post(FIELDS, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _tag(admin: CsrfClient, name: str = "core", **kw) -> dict:
    resp = admin.post(TAGS, json={"name": name, **kw})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _host_data(client: CsrfClient, host_id: int) -> dict:
    resp = client.get(f"/api/hosts/{host_id}/custom-data")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _put_host(client: CsrfClient, host_id: int, tag_ids=(), fields=None):
    return client.put(f"/api/hosts/{host_id}/custom-data", json={"tag_ids": list(tag_ids), "fields": fields or {}})


# ── Task 4: access ───────────────────────────────────────────────────────────


def test_definitions_need_admin_to_write(admin):
    user = user_client(admin)
    assert (
        user.post(
            FIELDS, json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
        ).status_code
        == 403
    )
    assert user.get(FIELDS).status_code == 200
    field = _field(admin)
    assert user.put(f"{FIELDS}/{field['id']}", json={"label": "x"}).status_code == 403
    assert user.delete(f"{FIELDS}/{field['id']}").status_code == 403
    tag = _tag(admin)
    assert user.put(f"{TAGS}/{tag['id']}", json={"name": "y"}).status_code == 403
    assert user.delete(f"{TAGS}/{tag['id']}").status_code == 403
    assert user.post(TAGS, json={"name": "edge"}).status_code == 403
    assert user.get(TAGS).status_code == 200


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get(TAGS).status_code == 401
    assert anon.get(FIELDS).status_code == 401
    assert anon.get(f"{PREFIX}?subnet=192.0.2.0/24").status_code == 401


def test_user_without_inventory_cannot_touch_host_data(admin):
    host = _host(admin, _group(admin))
    user = user_client(admin, "no-inventory")
    assert user.get(f"/api/hosts/{host}/custom-data").status_code == 403
    assert _put_host(user, host).status_code == 403


def test_user_with_inventory_can_tag_and_create_tags(admin):
    gid = _group(admin)
    host = _host(admin, gid)
    user = user_client(admin, "operator", features=["inventory"])
    created = user.post(TAGS, json={"name": "edge", "color": "teal"})
    assert created.status_code == 201, created.text
    tag = created.json()
    assert tag == {"id": tag["id"], "name": "edge", "color": "teal", "description": ""}
    resp = _put_host(user, host, [tag["id"]])
    assert resp.status_code == 200, resp.text
    assert resp.json()["tags"] == [{"id": tag["id"], "name": "edge", "color": "teal"}]
    resp = user.put(f"/api/inventory/{gid}/custom-data", json={"tag_ids": [tag["id"]], "fields": {}})
    assert resp.status_code == 200, resp.text
    assert user.get(f"/api/inventory/{gid}/custom-data").json()["tags"][0]["name"] == "edge"


def test_prefix_write_needs_admin(admin):
    reader = user_client(admin, "ipam-reader", features=["ipam"])
    writer = user_client(admin, "ipam-writer", features=["ipam", "ipam.write"])
    body = {"tag_ids": [], "fields": {}}
    url = f"{PREFIX}?subnet=192.0.2.0/24"
    assert reader.get(url).status_code == 200
    assert reader.put(url, json=body).status_code == 403
    assert writer.put(url, json=body).status_code == 403
    assert admin.put(url, json=body).status_code == 200
    assert user_client(admin, "no-ipam").get(url).status_code == 403


# ── Task 4: definitions ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"key": "Owner"},
        {"key": "1owner"},
        {"key": "o" * 51},
        {"field_type": "colour"},
        {"field_type": "select", "choices": []},
        {"field_type": "select", "choices": ["a", "a"]},
        {"field_type": "select", "choices": ["a", " "]},
        {"object_types": ["circuit"]},
        {"object_types": []},
        {"field_type": "number", "default_value": "many"},
        {"field_type": "select", "choices": ["a"], "default_value": "b"},
        {"label": "  "},
    ],
)
def test_field_create_validation(admin, body):
    base = {"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
    assert admin.post(FIELDS, json={**base, **body}).status_code == 422


def test_field_create_round_trip_and_duplicate(admin):
    field = _field(
        admin,
        key="rack_units",
        label="Rack units",
        field_type="number",
        object_types=["host", "group", "host"],
        required=True,
        default_value=" 2.0 ",
        description="Height",
        sort_order=3,
    )
    assert field == {
        "id": field["id"],
        "key": "rack_units",
        "label": "Rack units",
        "field_type": "number",
        "choices": [],
        "object_types": ["host", "group"],
        "required": True,
        "default_value": "2",
        "description": "Height",
        "sort_order": 3,
    }
    assert (
        admin.post(
            FIELDS, json={"key": "rack_units", "label": "Again", "field_type": "text", "object_types": ["host"]}
        ).status_code
        == 409
    )
    assert [f["key"] for f in admin.get(f"{FIELDS}?object_type=group").json()] == ["rack_units"]
    assert admin.get(f"{FIELDS}?object_type=prefix").json() == []
    assert admin.get(f"{FIELDS}?object_type=circuit").status_code == 400


def test_key_and_type_are_fixed(admin):
    field = _field(admin, field_type="select", choices=["net", "sec"])
    host = _host(admin, _group(admin))
    assert _put_host(admin, host, fields={"owner": "net"}).status_code == 200
    resp = admin.put(f"{FIELDS}/{field['id']}", json={"key": "team", "field_type": "number", "label": "Team"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["key"] == "owner" and resp.json()["field_type"] == "select"
    assert resp.json()["label"] == "Team" and resp.json()["choices"] == ["net", "sec"]
    assert _host_data(admin, host)["fields"] == {"owner": "net"}


def test_field_update_validation_and_404(admin):
    field = _field(admin, field_type="select", choices=["net", "sec"])
    url = f"{FIELDS}/{field['id']}"
    assert admin.put(url, json={"choices": []}).status_code == 422
    assert admin.put(url, json={"default_value": "lab"}).status_code == 422
    assert admin.put(url, json={"object_types": []}).status_code == 422
    assert admin.put(url, json={"label": " "}).status_code == 422
    assert admin.put(f"{FIELDS}/999999", json={"label": "x"}).status_code == 404
    assert admin.delete(f"{FIELDS}/999999").status_code == 404
    ok = admin.put(url, json={"default_value": "sec", "required": True, "description": "d", "sort_order": 9})
    assert ok.status_code == 200 and ok.json()["default_value"] == "sec" and ok.json()["sort_order"] == 9


def test_tag_management(admin):
    tag = _tag(admin, "PCI-Scope", color="red", description="in scope")
    assert admin.post(TAGS, json={"name": "pci-scope"}).status_code == 409
    assert admin.post(TAGS, json={"name": "  "}).status_code == 422
    assert admin.post(TAGS, json={"name": "x", "color": "pink"}).status_code == 422
    other = _tag(admin, "core")
    assert admin.put(f"{TAGS}/{other['id']}", json={"name": "pci-SCOPE"}).status_code == 409
    resp = admin.put(f"{TAGS}/{tag['id']}", json={"color": "blue"})
    assert resp.status_code == 200
    assert resp.json() == {"id": tag["id"], "name": "PCI-Scope", "color": "blue", "description": "in scope"}
    assert admin.put(f"{TAGS}/{tag['id']}", json={"name": " "}).status_code == 422
    assert admin.put(f"{TAGS}/999999", json={"name": "x"}).status_code == 404
    assert admin.delete(f"{TAGS}/999999").status_code == 404
    listed = admin.get(TAGS).json()
    assert [t["name"] for t in listed] == ["core", "PCI-Scope"]
    assert listed[0]["usage"] == {"host": 0, "group": 0, "prefix": 0}


# ── Task 4: object data ──────────────────────────────────────────────────────


def test_put_round_trip_typed(admin):
    _field(admin, key="rack_units", label="Rack units", field_type="number")
    _field(admin, key="managed", label="Managed", field_type="boolean", sort_order=1)
    _field(admin, key="eol", label="End of life", field_type="date", sort_order=2)
    host = _host(admin, _group(admin))
    resp = _put_host(admin, host, fields={"rack_units": 10.50, "managed": True, "eol": "2027-01-31"})
    assert resp.status_code == 200, resp.text
    fields = _host_data(admin, host)["fields"]
    assert fields == {"rack_units": 10.5, "managed": True, "eol": "2027-01-31"}
    assert isinstance(fields["managed"], bool)
    assert _put_host(admin, host, fields={"rack_units": "2", "managed": None, "eol": ""}).json()["fields"] == {
        "rack_units": 2
    }


def test_put_collects_all_field_errors(admin):
    _field(admin, key="rack_units", label="Rack units", field_type="number")
    _field(admin, key="site_url", label="Site URL", field_type="url")
    host = _host(admin, _group(admin))
    resp = _put_host(admin, host, fields={"rack_units": "many", "site_url": "ftp://example.com"})
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert set(detail["fields"]) == {"rack_units", "site_url"}
    assert detail["fields"]["rack_units"].startswith("Rack units")
    assert detail["message"]
    assert _host_data(admin, host) == {"tags": [], "fields": {}}


def test_required_enforced_only_on_custom_data_save(admin):
    field = _field(admin, required=True)
    host = _host(admin, _group(admin))
    resp = _put_host(admin, host)
    assert resp.status_code == 400 and "owner" in resp.json()["detail"]["fields"]
    rename = admin.put(f"/api/hosts/{host}", json={"hostname": "edge-sw2", "ip_address": "192.0.2.10"})
    assert rename.status_code == 200, rename.text
    assert admin.put(f"{FIELDS}/{field['id']}", json={"default_value": "net"}).status_code == 200
    assert _put_host(admin, host).status_code == 200
    assert _host_data(admin, host)["fields"] == {}


def test_required_ignores_fields_of_other_object_types(admin):
    _field(admin, required=True, object_types=["group"])
    host = _host(admin, _group(admin))
    assert _put_host(admin, host).status_code == 200


def test_stale_select_value_is_shown_then_rejected(admin):
    field = _field(admin, label="Environment", field_type="select", choices=["prod", "lab"])
    host = _host(admin, _group(admin))
    assert _put_host(admin, host, fields={"owner": "lab"}).status_code == 200
    assert admin.put(f"{FIELDS}/{field['id']}", json={"choices": ["prod"]}).status_code == 200
    assert _host_data(admin, host)["fields"] == {"owner": "lab"}
    resp = _put_host(admin, host, fields={"owner": "lab"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["fields"]["owner"].startswith("Environment")


def test_unknown_field_key_or_tag_id_rejects_whole_save(admin):
    _field(admin)
    _field(admin, key="group_only", label="Group only", object_types=["group"])
    good = _tag(admin, "core")
    host = _host(admin, _group(admin))
    assert _put_host(admin, host, [good["id"]], {"owner": "net"}).status_code == 200
    before = _host_data(admin, host)
    resp = _put_host(admin, host, [good["id"], 999999], {"gone": "x", "group_only": "y", "owner": "sec"})
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "999999" in detail["message"]
    assert set(detail["fields"]) == {"gone", "group_only"}
    assert _host_data(admin, host) == before


def test_removing_object_type_needs_confirm(admin):
    field = _field(admin, object_types=["host", "group"])
    gid = _group(admin)
    assert (
        admin.put(f"/api/inventory/{gid}/custom-data", json={"tag_ids": [], "fields": {"owner": "net"}}).status_code
        == 200
    )
    url = f"{FIELDS}/{field['id']}"
    resp = admin.put(url, json={"object_types": ["host"]})
    assert resp.status_code == 409
    assert resp.json()["detail"]["affected"] == 1 and resp.json()["detail"]["message"]
    # The app's usual error envelope is kept beside the structured detail.
    assert resp.json()["error"]["message"] == resp.json()["detail"]["message"]
    assert admin.get(f"/api/inventory/{gid}/custom-data").json()["fields"] == {"owner": "net"}
    resp = admin.put(f"{url}?confirm=true", json={"object_types": ["host"]})
    assert resp.status_code == 200 and resp.json()["object_types"] == ["host"]
    assert admin.get(f"/api/inventory/{gid}/custom-data").json()["fields"] == {}


def test_delete_reports_removed_count(admin):
    field = _field(admin)
    tag = _tag(admin)
    gid = _group(admin)
    hosts = [_host(admin, gid, f"sw{i}", f"192.0.2.{20 + i}") for i in range(2)]
    for h in hosts:
        assert _put_host(admin, h, [tag["id"]], {"owner": "net"}).status_code == 200
    assert admin.get(TAGS).json()[0]["usage"]["host"] == 2
    _field(admin, key="unused", label="Unused")
    listed = admin.get(FIELDS).json()
    assert isinstance(listed, list)
    assert {f["key"]: f["value_count"] for f in listed} == {"owner": 2, "unused": 0}
    assert admin.get(f"{FIELDS}?object_type=host").json()[0]["value_count"] == 2
    assert admin.delete(f"{FIELDS}/{field['id']}").json() == {"ok": True, "removed": 2}
    assert admin.delete(f"{TAGS}/{tag['id']}").json() == {"ok": True, "removed": 2}
    assert _host_data(admin, hosts[0]) == {"tags": [], "fields": {}}


def test_bulk_tags(admin):
    gid = _group(admin)
    hosts = [_host(admin, gid, f"sw{i}", f"192.0.2.{30 + i}") for i in range(3)]
    core = _tag(admin, "core")
    edge = _tag(admin, "edge")
    assert _put_host(admin, hosts[0], [edge["id"]]).status_code == 200
    body = {"host_ids": hosts[:2] + [999999], "add_tag_ids": [core["id"]], "remove_tag_ids": [edge["id"]]}
    resp = admin.post("/api/hosts/bulk-tags", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "updated": 2}
    assert [t["name"] for t in _host_data(admin, hosts[0])["tags"]] == ["core"]
    assert [t["name"] for t in _host_data(admin, hosts[1])["tags"]] == ["core"]
    assert _host_data(admin, hosts[2])["tags"] == []
    bad = admin.post("/api/hosts/bulk-tags", json={"host_ids": hosts, "add_tag_ids": [999999]})
    assert bad.status_code == 400 and "999999" in bad.json()["detail"]["message"]
    too_many = admin.post("/api/hosts/bulk-tags", json={"host_ids": list(range(1, 5002)), "add_tag_ids": [core["id"]]})
    assert too_many.status_code == 422
    user = user_client(admin, "viewer")
    assert user.post("/api/hosts/bulk-tags", json=body).status_code == 403


def test_missing_objects_404_and_bad_subnet_400(admin):
    assert admin.get("/api/hosts/999999/custom-data").status_code == 404
    assert _put_host(admin, 999999).status_code == 404
    assert admin.get("/api/inventory/999999/custom-data").status_code == 404
    assert admin.put("/api/inventory/999999/custom-data", json={}).status_code == 404
    assert admin.get(f"{PREFIX}?subnet=not-a-subnet").status_code == 400
    assert admin.put(f"{PREFIX}?subnet=not-a-subnet", json={}).status_code == 400


def test_prefix_key_spellings_share_data(admin):
    _field(admin, key="circuit", label="Circuit", object_types=["prefix"])
    tag = _tag(admin, "wan")
    resp = admin.put(
        f"{PREFIX}?subnet=192.0.2.5/24&vrf=blue", json={"tag_ids": [tag["id"]], "fields": {"circuit": "C-1"}}
    )
    assert resp.status_code == 200, resp.text
    same = admin.get(f"{PREFIX}?subnet=192.0.2.0/24&vrf=%20blue").json()
    assert same == {"tags": [{"id": tag["id"], "name": "wan", "color": "gray"}], "fields": {"circuit": "C-1"}}
    assert admin.get(f"{PREFIX}?subnet=192.0.2.0/24").json() == {"tags": [], "fields": {}}
    admin.put(f"{PREFIX}?subnet=2001:DB8::/32", json={"tag_ids": [tag["id"]]})
    assert admin.get(f"{PREFIX}?subnet=2001:db8::/32").json()["tags"][0]["name"] == "wan"


def test_writes_are_audited(admin):
    field = _field(admin)
    tag = _tag(admin)
    host = _host(admin, _group(admin))
    _put_host(admin, host, [tag["id"]])
    admin.post("/api/hosts/bulk-tags", json={"host_ids": [host], "remove_tag_ids": [tag["id"]]})
    admin.put(f"{FIELDS}/{field['id']}", json={"label": "Team"})
    admin.put(f"{TAGS}/{tag['id']}", json={"color": "red"})
    admin.delete(f"{FIELDS}/{field['id']}")
    admin.delete(f"{TAGS}/{tag['id']}")
    events = asyncio.run(db.get_audit_events(limit=50, category="custom_fields"))
    assert {e["action"] for e in events} == {
        "field_create",
        "field_update",
        "field_delete",
        "tag_create",
        "tag_update",
        "tag_delete",
        "object_update",
        "bulk_tags",
    }
    assert all(e["user"] == "admin" for e in events)


# ── Task 5: inline data and filters on the list endpoints ────────────────────


def _two_hosts(admin: CsrfClient) -> tuple[int, int, int, dict]:
    """A group with two hosts; the first is tagged ``core`` with rack_units 10.5."""
    _field(admin, key="rack_units", label="Rack units", field_type="number", object_types=["host", "group"])
    gid = _group(admin, "dc1")
    h1 = _host(admin, gid, "dc1-sw1", "192.0.2.61")
    h2 = _host(admin, gid, "dc1-sw2", "192.0.2.62")
    core = _tag(admin, "core", color="blue")
    assert _put_host(admin, h1, [core["id"]], {"rack_units": "10.50"}).status_code == 200
    return gid, h1, h2, core


def test_inventory_lists_carry_inline_data(admin):
    gid, h1, h2, core = _two_hosts(admin)
    other = _group(admin, "dc2")
    assert (
        admin.put(f"/api/inventory/{gid}/custom-data", json={"tag_ids": [core["id"]], "fields": {}}).status_code == 200
    )
    ref = {"id": core["id"], "name": "core", "color": "blue"}

    groups = {g["id"]: g for g in admin.get("/api/inventory").json()}
    assert groups[gid]["tags"] == [ref] and groups[gid]["custom_fields"] == {}
    assert groups[other]["tags"] == [] and groups[other]["custom_fields"] == {}

    full = {g["id"]: g for g in admin.get("/api/inventory?include_hosts=true").json()}
    hosts = {h["id"]: h for h in full[gid]["hosts"]}
    assert hosts[h1]["tags"] == [ref] and hosts[h1]["custom_fields"] == {"rack_units": 10.5}
    assert hosts[h2]["tags"] == [] and hosts[h2]["custom_fields"] == {}
    assert full[gid]["tags"] == [ref]

    listed = {h["id"]: h for h in admin.get(f"/api/inventory/{gid}/hosts").json()}
    assert listed[h1]["custom_fields"] == {"rack_units": 10.5} and listed[h2]["tags"] == []

    detail = admin.get(f"/api/inventory/{gid}").json()
    assert detail["tags"] == [ref]
    assert {h["id"]: h["tags"] for h in detail["hosts"]} == {h1: [ref], h2: []}


def test_inventory_tag_and_field_filters(admin):
    gid, h1, h2, _core = _two_hosts(admin)
    _group(admin, "empty")
    resp = admin.get("/api/inventory?include_hosts=true&tag=core")
    assert resp.status_code == 200, resp.text
    groups = resp.json()
    assert [g["id"] for g in groups] == [gid]
    assert [h["id"] for h in groups[0]["hosts"]] == [h1]
    assert [h["id"] for h in admin.get(f"/api/inventory/{gid}/hosts?tag=CORE").json()] == [h1]
    assert admin.get(f"/api/inventory/{gid}/hosts?tag=core&tag=edge").json() == []
    # Without hosts, only groups matching by their own data are listed.
    assert admin.get("/api/inventory?tag=core").json() == []
    admin.put(f"/api/inventory/{gid}/custom-data", json={"tag_ids": [_core["id"]], "fields": {"rack_units": 4}})
    assert [g["id"] for g in admin.get("/api/inventory?cf.rack_units=4").json()] == [gid]


def test_filter_values_are_canonicalised(admin):
    gid, h1, _h2, _core = _two_hosts(admin)
    assert [h["id"] for h in admin.get(f"/api/inventory/{gid}/hosts?cf.rack_units=10.50").json()] == [h1]
    assert admin.get(f"/api/inventory/{gid}/hosts?cf.rack_units=11").json() == []


def test_unknown_filter_key_is_400(admin):
    gid = _group(admin)
    for url in (
        "/api/inventory?cf.nope=x",
        f"/api/inventory/{gid}/hosts?cf.nope=x",
        "/api/ipam/overview?include_cloud=false&include_topology=false&cf.nope=x",
    ):
        resp = admin.get(url)
        assert resp.status_code == 400, url
        assert "nope" in resp.json()["detail"]["fields"]
    _field(admin, key="rack_units", label="Rack units", field_type="number")
    bad = admin.get(f"/api/inventory/{gid}/hosts?cf.rack_units=many")
    assert bad.status_code == 400 and bad.json()["detail"]["fields"]["rack_units"].startswith("Rack units")
    assert admin.get(f"/api/inventory/{gid}/hosts?cf.rack_units=").status_code == 400


def _ipam_subnets(admin: CsrfClient, query: str = "") -> dict[str, dict]:
    resp = admin.get(f"/api/ipam/overview?include_cloud=false&include_topology=false{query}")
    assert resp.status_code == 200, resp.text
    return {s["subnet"]: s for s in resp.json()["subnets"]}


def test_ipam_overview_and_subnet_detail_carry_inline_data(admin):
    gid = _group(admin)
    _host(admin, gid, "a1", "192.0.2.10")
    _host(admin, gid, "b1", "198.51.100.10")
    _field(admin, key="circuit", label="Circuit", object_types=["prefix"])
    wan = _tag(admin, "wan")
    put = admin.put(f"{PREFIX}?subnet=192.0.2.0/24&vrf=", json={"tag_ids": [wan["id"]], "fields": {"circuit": "C-7"}})
    assert put.status_code == 200, put.text
    subnets = _ipam_subnets(admin)
    assert subnets["192.0.2.0/24"]["tags"] == [{"id": wan["id"], "name": "wan", "color": "gray"}]
    assert subnets["192.0.2.0/24"]["custom_fields"] == {"circuit": "C-7"}
    assert subnets["198.51.100.0/24"]["tags"] == [] and subnets["198.51.100.0/24"]["custom_fields"] == {}
    detail = admin.get("/api/ipam/subnets/192.0.2.0/24").json()
    assert detail["tags"][0]["name"] == "wan" and detail["custom_fields"] == {"circuit": "C-7"}
    assert admin.get("/api/ipam/subnets/192.0.2.0/24?vrf=blue").json()["tags"] == []


def test_ipam_overview_tag_filter(admin):
    gid = _group(admin)
    _host(admin, gid, "a1", "192.0.2.10")
    _host(admin, gid, "b1", "198.51.100.10")
    wan = _tag(admin, "wan")
    admin.put(f"{PREFIX}?subnet=198.51.100.0/24", json={"tag_ids": [wan["id"]]})
    assert set(_ipam_subnets(admin, "&tag=wan")) == {"198.51.100.0/24"}
    assert _ipam_subnets(admin, "&tag=lan") == {}


# ── Task 6: CSV export ───────────────────────────────────────────────────────


def _csv_rows(admin: CsrfClient) -> list[list[str]]:
    import csv
    import io

    resp = admin.get("/api/inventory/export/csv")
    assert resp.status_code == 200, resp.text
    return list(csv.reader(io.StringIO(resp.text)))


def test_csv_has_tags_and_field_columns(admin):
    _field(admin, key="rack_units", label="Rack units", field_type="number", sort_order=2)
    _field(admin, key="owner", label="Owner", sort_order=1)
    _field(admin, key="site_code", label="Site code", object_types=["group"])
    gid = _group(admin)
    h1 = _host(admin, gid, "sw1", "192.0.2.71")
    _host(admin, gid, "sw2", "192.0.2.72")
    core = _tag(admin, "core")
    edge = _tag(admin, "edge")
    assert _put_host(admin, h1, [edge["id"], core["id"]], {"owner": "net", "rack_units": 2}).status_code == 200
    header, *rows = _csv_rows(admin)
    assert header[-5:] == ["Status", "Group", "Tags", "Owner", "Rack units"]
    assert "Site code" not in header
    by_name = {r[0]: r for r in rows}
    assert by_name["sw1"][-3:] == ["core; edge", "net", "2"]
    assert by_name["sw2"][-3:] == ["", "", ""]


def test_csv_cells_cannot_start_a_formula(admin):
    _field(admin, key="note", label="Note")
    _field(admin, key="delta", label="Delta", field_type="number", sort_order=1)
    gid = _group(admin)
    h = _host(admin, gid, "guard-sw1", "192.0.2.81")
    bad = _tag(admin, "=cmd")
    assert _put_host(admin, h, [bad["id"]], {"note": "@SUM(A1)", "delta": -5}).status_code == 200
    _header, *rows = _csv_rows(admin)
    (row,) = [r for r in rows if r[0] == "guard-sw1"]
    assert row[-3:] == ["'=cmd", "'@SUM(A1)", "-5"]
