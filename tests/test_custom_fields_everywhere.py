"""Custom fields and tags on every object type of the registry, computed
fields and user-defined relationships (``netcontrol.custom_fields``,
``netcontrol.routes.custom_fields``, migration 0109)."""

from __future__ import annotations

import asyncio
import logging

import pytest
import routes.database as db
from netcontrol.custom_fields import (
    COMPUTED_OUTPUT_MAX,
    GENERIC_TYPES,
    OBJECT_TYPE_SPECS,
    OBJECT_TYPES,
    purge_trigger_sql,
    unknown_object_types,
)
from netcontrol.routes.custom_fields import object_custom_data_bulk, render_computed

from mcp_helpers import CsrfClient, admin_client, user_client

FIELDS = "/api/custom-fields"
TAGS = "/api/tags"
COMPUTED = "/api/computed-fields"
RELS = "/api/relationships"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _vrf(admin: CsrfClient, name: str = "blue") -> int:
    return int(_ok(admin.post("/api/ipam/vrfs", json={"name": name, "rd": ""}), 201)["id"])


def _provider(admin: CsrfClient, name: str = "Example Transit") -> int:
    return int(_ok(admin.post("/api/circuits/providers", json={"name": name}), 201)["id"])


def _tenant(admin: CsrfClient, name: str = "Example Tenant") -> int:
    return int(_ok(admin.post("/api/organization/tenants", json={"name": name}), 201)["id"])


def _manufacturer(admin: CsrfClient, name: str = "Example Networks") -> int:
    return int(_ok(admin.post("/api/dcim/manufacturers", json={"name": name}), 201)["id"])


def _field(admin: CsrfClient, **kw) -> dict:
    body = {"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["vrf"]}
    body.update(kw)
    return _ok(admin.post(FIELDS, json=body), 201)


def _data(client: CsrfClient, object_type: str, object_id: int):
    return client.get(f"/api/objects/{object_type}/{object_id}/custom-data")


def _put(client: CsrfClient, object_type: str, object_id: int, tag_ids=(), fields=None):
    return client.put(
        f"/api/objects/{object_type}/{object_id}/custom-data",
        json={"tag_ids": list(tag_ids), "fields": fields or {}},
    )


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registry_keeps_the_original_types_and_covers_the_new_ones():
    assert OBJECT_TYPES[:3] == ("host", "group", "prefix")
    for key in (
        "vrf",
        "vlan",
        "site",
        "region",
        "tenant",
        "manufacturer",
        "device_type",
        "device_role",
        "circuit_provider",
        "circuit",
        "cluster",
        "virtual_machine",
        "autonomous_system",
        "bgp_peering",
        "rack",
        "cable",
    ):
        assert key in OBJECT_TYPE_SPECS and key in GENERIC_TYPES
    assert "prefix" not in GENERIC_TYPES
    assert unknown_object_types(["vrf", "spaceship"]) == ["spaceship"]
    drop, create = purge_trigger_sql(OBJECT_TYPE_SPECS["rack"])
    assert drop.startswith("DROP TRIGGER IF EXISTS trg_racks_purge_object_data ON racks")
    assert "plexus_purge_object_data('rack', 'id')" in create


async def test_every_registered_table_exists_and_has_its_purge_trigger():
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute(
            "SELECT event_object_table AS t FROM information_schema.triggers WHERE trigger_name LIKE ?",
            ("trg_%_purge_object_data",),
        )
        triggered = {r["t"] for r in await cursor.fetchall()}
        cursor = await conn.execute(
            "SELECT table_name AS t FROM information_schema.tables WHERE table_schema = current_schema()"
        )
        tables = {r["t"] for r in await cursor.fetchall()}
    finally:
        await conn.close()
    for spec in OBJECT_TYPE_SPECS.values():
        assert spec.table in tables, spec.key
        if spec.generic:
            assert spec.table in triggered, spec.key


def test_object_type_catalogue(admin):
    types = {t["key"]: t for t in _ok(admin.get("/api/custom-object-types"))}
    assert types["vrf"] == {"key": "vrf", "label": "VRF", "generic": True, "readable": True, "writable": True}
    user = user_client(admin, "circuit-reader", features=["circuits"])
    seen = {t["key"]: t for t in _ok(user.get("/api/custom-object-types"))}
    assert seen["circuit"]["readable"] and not seen["circuit"]["writable"]
    assert not seen["vrf"]["readable"]
    assert seen["manufacturer"]["readable"] and not seen["manufacturer"]["writable"]


# ── Definitions and validation per type ──────────────────────────────────────


def test_field_definitions_accept_registered_types_only(admin):
    field = _field(admin, object_types=["vrf", "circuit", "rack", "host"])
    assert field["object_types"] == ["vrf", "circuit", "rack", "host"]
    bad = admin.post(FIELDS, json={"key": "x", "label": "X", "field_type": "text", "object_types": ["spaceship"]})
    assert bad.status_code == 422
    assert admin.get(f"{FIELDS}?object_type=rack").json()[0]["key"] == "owner"
    assert admin.get(f"{FIELDS}?object_type=spaceship").status_code == 400


@pytest.mark.parametrize(
    ("field_type", "extra", "good", "stored", "bad"),
    [
        ("text", {}, "  net ops ", "net ops", 12),
        ("number", {}, "4.50", 4.5, "many"),
        ("boolean", {}, "yes", True, "maybe"),
        ("date", {}, "2026-01-31", "2026-01-31", "2026-02-30"),
        ("url", {}, "https://example.com/x", "https://example.com/x", "ftp://example.com"),
        ("select", {"choices": ["gold", "silver"]}, "gold", "gold", "bronze"),
    ],
)
def test_every_field_type_validates_on_new_object_types(admin, field_type, extra, good, stored, bad):
    _field(admin, key="attr", label="Attr", field_type=field_type, object_types=["circuit_provider"], **extra)
    provider = _provider(admin)
    saved = _ok(_put(admin, "circuit_provider", provider, fields={"attr": good}))
    assert saved["fields"] == {"attr": stored}
    resp = _put(admin, "circuit_provider", provider, fields={"attr": bad})
    assert resp.status_code == 400
    assert "attr" in resp.json()["detail"]["fields"]
    assert _ok(_data(admin, "circuit_provider", provider))["fields"] == {"attr": stored}


def test_required_and_other_type_fields(admin):
    _field(admin, key="owner", required=True)
    _field(admin, key="rackonly", label="Rack only", object_types=["rack"])
    vrf = _vrf(admin)
    resp = _put(admin, "vrf", vrf)
    assert resp.status_code == 400 and "owner" in resp.json()["detail"]["fields"]
    resp = _put(admin, "vrf", vrf, fields={"owner": "net", "rackonly": "x"})
    assert resp.status_code == 400
    assert "does not apply" in resp.json()["detail"]["fields"]["rackonly"]


def test_validation_rules_cover_vrf_custom_fields(admin):
    _field(admin)
    rule = {
        "name": "owner lowercase",
        "object_type": "vrf",
        "field": "cf.owner",
        "rule_type": "regex",
        "params": {"pattern": "[a-z]+"},
        "message": "Owner must be lowercase.",
    }
    _ok(admin.post("/api/validation-rules", json=rule), 201)
    vrf = _vrf(admin)
    resp = _put(admin, "vrf", vrf, fields={"owner": "NET"})
    assert resp.status_code == 422, resp.text
    assert set(resp.json()["detail"]["fields"]) == {"owner"}
    _ok(_put(admin, "vrf", vrf, fields={"owner": "net"}))


# ── Lists and details ────────────────────────────────────────────────────────


def test_lists_carry_and_filter_custom_data(admin):
    _field(admin)
    tag = _ok(admin.post(TAGS, json={"name": "core"}), 201)
    blue, red = _vrf(admin, "blue"), _vrf(admin, "red")
    _ok(_put(admin, "vrf", blue, [tag["id"]], {"owner": "net"}))
    _ok(_put(admin, "vrf", red, [], {"owner": "sec"}))
    rows = {r["name"]: r for r in _ok(admin.get("/api/ipam/vrfs"))["vrfs"]}
    assert rows["blue"]["tags"] == [{"id": tag["id"], "name": "core", "color": "gray"}]
    assert rows["red"]["custom_fields"] == {"owner": "sec"}
    assert [r["name"] for r in _ok(admin.get("/api/ipam/vrfs?tag=CORE"))["vrfs"]] == ["blue"]
    assert [r["name"] for r in _ok(admin.get("/api/ipam/vrfs?cf.owner=sec"))["vrfs"]] == ["red"]
    assert admin.get("/api/ipam/vrfs?cf.nope=1").status_code == 400
    providers = _ok(admin.get("/api/circuits/providers?tag=core"))["providers"]
    assert providers == []
    tenant = _tenant(admin)
    _ok(admin.put(f"/api/objects/tenant/{tenant}/custom-data", json={"tag_ids": [tag["id"]], "fields": {}}))
    assert [t["id"] for t in _ok(admin.get("/api/organization/tenants?tag=core"))["tenants"]] == [tenant]
    assert _ok(admin.get("/api/dcim/manufacturers"))[0:0] == []


def test_detail_responses_include_custom_and_computed_fields(admin):
    _field(admin)
    vrf = _vrf(admin, "blue")
    _ok(_put(admin, "vrf", vrf, fields={"owner": "net"}))
    _ok(
        admin.post(
            COMPUTED,
            json={"key": "display", "label": "Display", "object_type": "vrf", "template": "{{ obj.name | upper }}"},
        ),
        201,
    )
    detail = _ok(admin.get(f"/api/ipam/vrfs/{vrf}"))
    assert detail["custom_fields"] == {"owner": "net"}
    assert detail["tags"] == []
    assert detail["computed_fields"] == {"display": "BLUE"}
    provider = _provider(admin)
    detail = _ok(admin.get(f"/api/circuits/providers/{provider}"))
    assert detail["custom_fields"] == {} and detail["computed_fields"] == {} and "networks" in detail


# ── Computed fields ──────────────────────────────────────────────────────────


def test_computed_fields_render_over_attributes_and_custom_data(admin):
    _field(admin)
    vrf = _vrf(admin, "blue")
    tag = _ok(admin.post(TAGS, json={"name": "core"}), 201)
    _ok(_put(admin, "vrf", vrf, [tag["id"]], {"owner": "net"}))
    template = "{{ obj.name }}/{{ custom_fields.owner }}/{{ tags | join(',') }}"
    created = _ok(
        admin.post(COMPUTED, json={"key": "summary", "label": "Summary", "object_type": "vrf", "template": template}),
        201,
    )
    data = _ok(_data(admin, "vrf", vrf))
    assert data["computed_fields"] == {"summary": "blue/net/core"}
    _ok(admin.put(f"{COMPUTED}/{created['id']}", json={"template": "{{ obj.id }}"}))
    assert _ok(_data(admin, "vrf", vrf))["computed_fields"] == {"summary": str(vrf)}
    assert [c["key"] for c in _ok(admin.get(f"{COMPUTED}?object_type=vrf"))] == ["summary"]
    preview = _ok(
        admin.post(f"{COMPUTED}/preview", json={"object_type": "vrf", "object_id": vrf, "template": "{{ obj.nope }}"})
    )
    assert preview["value"] == "" and preview["error"]
    _ok(admin.delete(f"{COMPUTED}/{created['id']}"))
    assert _ok(_data(admin, "vrf", vrf))["computed_fields"] == {}


@pytest.mark.parametrize(
    "body",
    [
        {"key": "Bad"},
        {"object_type": "prefix"},
        {"object_type": "spaceship"},
        {"template": "{% if %}"},
        {"template": "   "},
        {"label": " "},
    ],
)
def test_computed_field_definition_validation(admin, body):
    base = {"key": "display", "label": "Display", "object_type": "vrf", "template": "{{ obj.name }}"}
    assert admin.post(COMPUTED, json={**base, **body}).status_code == 422


def test_computed_field_errors_render_empty_and_never_fail(admin, caplog):
    vrf = _vrf(admin, "blue")
    for key, template in (("broken", "{{ obj.nope.deeper }}"), ("boom", "{{ 1 // 0 }}")):
        _ok(admin.post(COMPUTED, json={"key": key, "label": key, "object_type": "vrf", "template": template}), 201)
    _ok(
        admin.post(
            COMPUTED,
            json={
                "key": "long",
                "label": "Long",
                "object_type": "vrf",
                "template": "{% for i in range(400) %}abcd{% endfor %}",
            },
        ),
        201,
    )
    with caplog.at_level(logging.WARNING, logger="plexus.custom_fields"):
        data = _ok(_data(admin, "vrf", vrf))
        detail = _ok(admin.get(f"/api/ipam/vrfs/{vrf}"))
    assert data["computed_fields"]["broken"] == "" and data["computed_fields"]["boom"] == ""
    assert len(data["computed_fields"]["long"]) == COMPUTED_OUTPUT_MAX
    assert detail["computed_fields"]["broken"] == ""
    assert any("computed field broken" in r.getMessage() for r in caplog.records)


def test_render_computed_directly():
    fields = [{"key": "a", "template": "{{ obj.name }}"}, {"key": "b", "template": "{{ obj.__class__ }}"}]
    out = render_computed(fields, {"obj": {"name": "x"}, "custom_fields": {}, "tags": []})
    assert out["a"] == "x"
    assert "class" not in out["b"].lower() or out["b"] == ""


# ── Relationships ────────────────────────────────────────────────────────────


def _rel(admin: CsrfClient, key: str, source: str, destination: str, cardinality: str) -> dict:
    body = {
        "key": key,
        "label": key.replace("_", " ").title(),
        "source_type": source,
        "destination_type": destination,
        "cardinality": cardinality,
    }
    return _ok(admin.post(RELS, json=body), 201)


def _link(client: CsrfClient, object_type: str, object_id: int, rel_id: int, peer: int, side=None):
    body = {"relationship_id": rel_id, "peer_id": peer}
    if side:
        body["side"] = side
    return client.post(f"/api/objects/{object_type}/{object_id}/relationships", json=body)


def test_one_to_many_cardinality_and_both_sides_list(admin):
    rel = _rel(admin, "transit_vrfs", "circuit_provider", "vrf", "one-to-many")
    p1, p2 = _provider(admin, "Transit A"), _provider(admin, "Transit B")
    v1, v2 = _vrf(admin, "blue"), _vrf(admin, "red")
    _ok(_link(admin, "circuit_provider", p1, rel["id"], v1), 201)
    _ok(_link(admin, "circuit_provider", p1, rel["id"], v2), 201)
    resp = _link(admin, "circuit_provider", p2, rel["id"], v1)
    assert resp.status_code == 409 and "destination already" in resp.text
    assert _link(admin, "circuit_provider", p1, rel["id"], v1).status_code == 409
    # From the destination side too.
    assert _link(admin, "vrf", v1, rel["id"], p2).status_code == 409
    groups = _ok(_data(admin, "circuit_provider", p1))["relationships"]
    assert len(groups) == 1 and groups[0]["side"] == "source" and groups[0]["peer_type"] == "vrf"
    assert sorted(link["peer_label"] for link in groups[0]["links"]) == ["blue", "red"]
    (back,) = _ok(_data(admin, "vrf", v1))["relationships"]
    assert back["side"] == "destination"
    assert back["links"] == [{"id": back["links"][0]["id"], "peer_id": p1, "peer_label": "Transit A"}]
    assert _ok(admin.get(RELS))[0]["link_count"] == 2


def test_one_to_one_and_many_to_many(admin):
    one = _rel(admin, "pair", "vrf", "tenant", "one-to-one")
    many = _rel(admin, "serves", "vrf", "tenant", "many-to-many")
    v1, v2 = _vrf(admin, "blue"), _vrf(admin, "red")
    t1, t2 = _tenant(admin, "Tenant A"), _tenant(admin, "Tenant B")
    _ok(_link(admin, "vrf", v1, one["id"], t1), 201)
    assert _link(admin, "vrf", v1, one["id"], t2).status_code == 409
    assert _link(admin, "vrf", v2, one["id"], t1).status_code == 409
    _ok(_link(admin, "vrf", v2, one["id"], t2), 201)
    for v in (v1, v2):
        for t in (t1, t2):
            _ok(_link(admin, "vrf", v, many["id"], t), 201)
    # Wrong types and unknown peers.
    assert _link(admin, "circuit_provider", _provider(admin), many["id"], t1).status_code == 400
    assert _link(admin, "vrf", v1, many["id"], 999999).status_code == 404
    assert _link(admin, "vrf", v1, 999999, t1).status_code == 404


def test_same_type_relationship_and_link_delete(admin):
    rel = _rel(admin, "backup_of", "vrf", "vrf", "one-to-one")
    v1, v2 = _vrf(admin, "blue"), _vrf(admin, "red")
    assert _link(admin, "vrf", v1, rel["id"], v1).status_code == 409
    link = _ok(_link(admin, "vrf", v2, rel["id"], v1, side="destination"), 201)
    assert link["source_key"] == str(v1) and link["destination_key"] == str(v2)
    groups = _ok(_data(admin, "vrf", v1))["relationships"]
    assert [g["side"] for g in groups] == ["source", "destination"]
    assert groups[0]["links"][0]["peer_id"] == v2 and groups[1]["links"] == []
    assert admin.delete(f"/api/objects/vrf/{v1}/relationships/999999").status_code == 404
    _ok(admin.delete(f"/api/objects/vrf/{v2}/relationships/{link['id']}"))
    assert _ok(_data(admin, "vrf", v1))["relationships"][0]["links"] == []


@pytest.mark.parametrize(
    "body",
    [
        {"key": "Bad"},
        {"source_type": "prefix"},
        {"destination_type": "spaceship"},
        {"cardinality": "some-to-some"},
    ],
)
def test_relationship_definition_validation(admin, body):
    base = {"key": "rel", "label": "Rel", "source_type": "vrf", "destination_type": "tenant"}
    assert admin.post(RELS, json={**base, **body}).status_code == 422


def test_relationship_update_and_delete_removes_links(admin):
    rel = _rel(admin, "serves", "vrf", "tenant", "many-to-many")
    assert admin.post(RELS, json={**rel, "id": None}).status_code == 409
    v, t = _vrf(admin), _tenant(admin)
    _ok(_link(admin, "vrf", v, rel["id"], t), 201)
    updated = _ok(admin.put(f"{RELS}/{rel['id']}", json={"label": "Serves tenant", "cardinality": "one-to-one"}))
    assert updated["label"] == "Serves tenant" and updated["cardinality"] == "many-to-many"
    assert _ok(admin.delete(f"{RELS}/{rel['id']}"))["removed"] == 1
    assert _ok(_data(admin, "vrf", v))["relationships"] == []


def test_lookup_lists_objects_by_label(admin):
    _vrf(admin, "blue"), _vrf(admin, "red")
    found = _ok(admin.get("/api/objects/vrf/lookup?q=BL"))
    assert [f["label"] for f in found] == ["blue"]
    assert admin.get("/api/objects/spaceship/lookup").status_code == 404
    assert admin.get("/api/objects/prefix/lookup").status_code == 404


# ── Permissions and scope ────────────────────────────────────────────────────


def test_feature_permissions_per_type(admin):
    provider = _provider(admin)
    manufacturer = _manufacturer(admin)
    vrf = _vrf(admin)
    nobody = user_client(admin, "plain")
    assert _data(nobody, "circuit_provider", provider).status_code == 403
    assert _data(nobody, "manufacturer", manufacturer).status_code == 200
    assert _put(nobody, "manufacturer", manufacturer).status_code == 403
    reader = user_client(admin, "circuit-reader", features=["circuits"])
    assert _data(reader, "circuit_provider", provider).status_code == 200
    assert _put(reader, "circuit_provider", provider).status_code == 403
    writer = user_client(admin, "circuit-writer", features=["circuits", "circuits.write"])
    assert _put(writer, "circuit_provider", provider).status_code == 200
    ipam = user_client(admin, "ipam-writer", features=["ipam", "ipam.write"])
    assert _data(ipam, "vrf", vrf).status_code == 200
    assert _put(ipam, "vrf", vrf).status_code == 403  # VRF writes are admin only
    # Linking needs write on the object and read on the peer.
    rel = _rel(admin, "provider_vrf", "circuit_provider", "vrf", "many-to-many")
    assert _link(writer, "circuit_provider", provider, rel["id"], vrf).status_code == 403
    assert _link(reader, "circuit_provider", provider, rel["id"], vrf).status_code == 403
    # Definitions are admin only to change.
    body = {"key": "d", "label": "D", "object_type": "vrf", "template": "x"}
    assert writer.post(COMPUTED, json=body).status_code == 403
    assert writer.get(COMPUTED).status_code == 200
    assert (
        writer.post(RELS, json={"key": "r", "label": "R", "source_type": "vrf", "destination_type": "vrf"}).status_code
        == 403
    )
    assert _data(admin, "spaceship", 1).status_code == 404
    assert _data(admin, "prefix", 1).status_code == 404
    assert _data(admin, "vrf", 999999).status_code == 404


def _scoped_user(
    admin: CsrfClient,
    name: str,
    group_id: int | None,
    features=("inventory", "inventory.write", "ipam", "circuits"),
    rules: list[dict] | None = None,
) -> CsrfClient:
    import netcontrol.app as app_module
    from starlette.testclient import TestClient

    grants = [] if group_id is None else [{"inventory_group_id": group_id, "can_write": True}]
    group = _ok(
        admin.post(
            "/api/admin/access-groups",
            json={
                "name": f"{name} access",
                "feature_keys": list(features),
                "object_scope": "groups",
                "inventory_scopes": grants,
            },
        ),
        201,
    )
    if rules is not None:
        _ok(admin.put(f"/api/admin/access-groups/{group['id']}/scope-rules", json={"rules": rules}))
    _ok(
        admin.post("/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group["id"]]}),
        201,
    )
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": name, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json().get("csrf_token", ""))


def test_object_scope_is_respected(admin):
    mine = int(_ok(admin.post("/api/inventory", json={"name": "site-a"}), 201)["id"])
    other = int(_ok(admin.post("/api/inventory", json={"name": "site-b"}), 201)["id"])
    h_mine = _ok(admin.post(f"/api/inventory/{mine}/hosts", json={"hostname": "a1", "ip_address": "192.0.2.1"}), 201)
    h_other = _ok(admin.post(f"/api/inventory/{other}/hosts", json={"hostname": "b1", "ip_address": "192.0.2.2"}), 201)
    vrf = _vrf(admin)
    scoped = _scoped_user(admin, "scoped-op", mine)
    assert _data(scoped, "host", h_mine["id"]).status_code == 200
    assert _put(scoped, "host", h_mine["id"]).status_code == 200
    assert _data(scoped, "host", h_other["id"]).status_code == 404
    assert _data(scoped, "group", other).status_code == 404
    # A VRF of no tenant is shared reference data: readable, changed by admins only.
    assert _data(scoped, "vrf", vrf).status_code == 200
    assert _put(scoped, "vrf", vrf).status_code == 403
    labels = [o["label"] for o in _ok(scoped.get("/api/objects/host/lookup"))]
    assert labels == ["a1"]


def test_scope_rules_reach_circuits_by_tenant(admin):
    mine, other = _tenant(admin, "Tenant A"), _tenant(admin, "Tenant B")
    provider = _provider(admin)
    ctype = int(_ok(admin.post("/api/circuits/circuit-types", json={"name": "Transit"}), 201)["id"])

    def circuit(cid: str, tenant: int) -> int:
        body = {"cid": cid, "provider_id": provider, "circuit_type_id": ctype, "tenant_id": tenant}
        return int(_ok(admin.post("/api/circuits/circuits", json=body), 201)["id"])

    in_scope, out_of_scope = circuit("CID-100", mine), circuit("CID-200", other)
    _field(admin, object_types=["circuit", "circuit_provider"])
    rel = _rel(admin, "carries", "circuit_provider", "circuit", "many-to-many")
    for c in (in_scope, out_of_scope):
        _ok(_link(admin, "circuit_provider", provider, rel["id"], c), 201)

    scoped = _scoped_user(
        admin,
        "tenant-op",
        None,
        features=("circuits", "circuits.write"),
        rules=[{"model": "circuit", "attribute": "tenant", "value_id": mine, "can_write": True}],
    )
    # In scope: read and write.
    assert _ok(_put(scoped, "circuit", in_scope, fields={"owner": "net"}))["fields"] == {"owner": "net"}
    assert _ok(_data(scoped, "circuit", in_scope))["fields"] == {"owner": "net"}
    # Out of scope: answers like an unknown id, for reads and writes.
    assert _data(scoped, "circuit", out_of_scope).status_code == 404
    assert _put(scoped, "circuit", out_of_scope).status_code == 404
    assert _data(scoped, "circuit", 999999).status_code == 404
    assert [o["label"] for o in _ok(scoped.get("/api/objects/circuit/lookup"))] == ["CID-100"]
    # The provider is shared: readable, but only an unrestricted caller changes it,
    # and its relationship lists only the circuit the caller reads.
    (group,) = _ok(_data(scoped, "circuit_provider", provider))["relationships"]
    assert [link["peer_id"] for link in group["links"]] == [in_scope]
    assert _put(scoped, "circuit_provider", provider).status_code == 403
    assert len(_ok(_data(admin, "circuit_provider", provider))["relationships"][0]["links"]) == 2
    # Linking needs read on the peer: an out-of-scope circuit is not found.
    assert _link(scoped, "circuit", in_scope, rel["id"], provider).status_code in (201, 409)
    assert _link(scoped, "circuit", out_of_scope, rel["id"], provider).status_code == 404


# ── Deletion, change log, bulk read ──────────────────────────────────────────


async def _counts(object_type: str, key: str) -> tuple[int, int, int]:
    conn = await db.get_db(read_only=True)
    try:
        out = []
        for sql in (
            "SELECT COUNT(*) AS n FROM tag_assignments WHERE object_type = ? AND object_key = ?",
            "SELECT COUNT(*) AS n FROM custom_field_values WHERE object_type = ? AND object_key = ?",
            "SELECT COUNT(*) AS n FROM relationship_links WHERE (source_type = ? AND source_key = ?)"
            " OR (destination_type = ? AND destination_key = ?)",
        ):
            params = (object_type, key) * (2 if "relationship_links" in sql else 1)
            cursor = await conn.execute(sql, params)
            out.append(int((await cursor.fetchone())["n"]))
        return out[0], out[1], out[2]
    finally:
        await conn.close()


def test_deleting_an_object_removes_its_data_and_links(admin):
    _field(admin, object_types=["vrf", "tenant"])
    tag = _ok(admin.post(TAGS, json={"name": "core"}), 201)
    rel = _rel(admin, "serves", "vrf", "tenant", "many-to-many")
    vrf, tenant = _vrf(admin), _tenant(admin)
    _ok(_put(admin, "vrf", vrf, [tag["id"]], {"owner": "net"}))
    _ok(_put(admin, "tenant", tenant, [tag["id"]], {"owner": "sec"}))
    _ok(_link(admin, "vrf", vrf, rel["id"], tenant), 201)
    assert asyncio.run(_counts("vrf", str(vrf))) == (1, 1, 1)
    _ok(admin.delete(f"/api/ipam/vrfs/{vrf}"))
    assert asyncio.run(_counts("vrf", str(vrf))) == (0, 0, 0)
    assert asyncio.run(_counts("tenant", str(tenant))) == (1, 1, 0)
    assert _ok(_data(admin, "tenant", tenant))["relationships"][0]["links"] == []


def test_custom_data_changes_reach_the_change_log(admin):
    _field(admin)
    vrf = _vrf(admin)
    _ok(_put(admin, "vrf", vrf, fields={"owner": "net"}))
    history = _ok(admin.get(f"/api/changes/vrf/{vrf}"))["changes"]
    update = next(c for c in history if c["action"] == "update")
    assert update["changes"]["custom_fields"] == {"before": {}, "after": {"owner": "net"}}
    count = len(history)
    _ok(_put(admin, "vrf", vrf, fields={"owner": "net"}))  # no change, no row
    assert len(_ok(admin.get(f"/api/changes/vrf/{vrf}"))["changes"]) == count


def test_bulk_reader_for_other_consumers(admin):
    _field(admin)
    v1, v2 = _vrf(admin, "blue"), _vrf(admin, "red")
    _ok(_put(admin, "vrf", v1, fields={"owner": "net"}))
    rel = _rel(admin, "pair", "vrf", "vrf", "many-to-many")
    _ok(_link(admin, "vrf", v1, rel["id"], v2), 201)
    rows = [{"id": v1, "name": "blue"}, {"id": v2, "name": "red"}]
    out = asyncio.run(object_custom_data_bulk("vrf", rows, relationships=True))
    assert out[str(v1)]["custom_fields"] == {"owner": "net"}
    assert out[str(v2)]["custom_fields"] == {}
    assert out[str(v1)]["relationships"][0]["links"][0]["peer_label"] == "red"
    assert out[str(v2)]["relationships"][1]["links"][0]["peer_id"] == v1
