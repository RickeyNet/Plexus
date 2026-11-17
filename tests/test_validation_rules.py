"""Data validation rules: the admin API (``netcontrol.routes.validation_rules``),
the rule logic (``netcontrol.data_validation``) and enforcement on the
inventory, IPAM, VLAN, VRF and custom data write routes."""

from __future__ import annotations

import asyncio

import pytest
from netcontrol import data_validation as dv
from netcontrol.object_scope import UNRESTRICTED, ObjectScope

from mcp_helpers import CsrfClient, admin_client, user_client

RULES = "/api/validation-rules"


@pytest.fixture(autouse=True)
def _fresh_rule_cache():
    # Each test gets a new database: never carry cached rules across tests.
    dv.invalidate_rules_cache()
    yield
    dv.invalidate_rules_cache()


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _rule(admin: CsrfClient, **kw) -> dict:
    body = {
        "name": "hostname pattern",
        "object_type": "host",
        "field": "hostname",
        "rule_type": "regex",
        "params": {"pattern": r"sw-[0-9]+"},
    }
    body.update(kw)
    resp = admin.post(RULES, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str = "core") -> int:
    resp = admin.post("/api/inventory", json={"name": name})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _add_host(admin: CsrfClient, group_id: int, hostname: str, ip: str):
    return admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": hostname, "ip_address": ip})


def _fields(resp) -> dict:
    return resp.json()["detail"]["fields"]


# ── Pure rule logic ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("rule_type", "params", "value", "ok"),
    [
        ("regex", {"pattern": "sw-[0-9]+"}, "sw-12", True),
        ("regex", {"pattern": "sw-[0-9]+"}, "sw-12x", False),  # whole value
        ("regex", {"pattern": "sw-[0-9]+"}, "SW-12", False),  # case sensitive
        ("regex", {"pattern": "sw-[0-9]+"}, "", True),  # empty passes
        ("length", {"min": 2, "max": 4}, "abc", True),
        ("length", {"min": 2, "max": 4}, "abcde", False),
        ("length", {"min": 2}, "a", False),
        ("numeric", {"min": 100, "max": 199}, 150, True),
        ("numeric", {"min": 100, "max": 199}, "99", False),
        ("numeric", {"max": 10}, "ten", False),
        ("required", {}, "  ", False),
        ("required", {}, None, False),
        ("required", {}, "x", True),
    ],
)
def test_check_value(rule_type, params, value, ok):
    rule = {"name": "r", "field": "f", "rule_type": rule_type, "params": params, "error_message": ""}
    assert (dv.check_value(rule, value) is None) is ok


def test_custom_error_message_is_used():
    rule = {"name": "r", "field": "f", "rule_type": "required", "params": {}, "error_message": "Fill it in."}
    assert dv.check_value(rule, "") == "Fill it in."


@pytest.mark.parametrize("pattern", ["(?=a)b", "(?!a)b", "(?<=a)b", r"(a)\1", "a("])
def test_clean_params_refuses_what_re2_cannot_run(pattern):
    with pytest.raises(dv.RuleError) as exc:
        dv.clean_params("regex", {"pattern": pattern})
    assert "params.pattern" in exc.value.fields


@pytest.mark.parametrize(
    ("rule_type", "params"),
    [("length", {}), ("length", {"min": 5, "max": 2}), ("length", {"min": -1}), ("numeric", {"min": "x"}), ("x", {})],
)
def test_clean_params_refuses_bad_bounds(rule_type, params):
    with pytest.raises(dv.RuleError):
        dv.clean_params(rule_type, params)


def test_merged_values_keep_stored_value_for_none():
    rules = [{"name": "rd", "field": "rd", "rule_type": "required", "params": {}, "error_message": ""}]
    assert dv.violations_of(rules, dv._merged({"rd": None}, {"rd": ""})) == [
        {"field": "rd", "rule": "rd", "message": "rd is required."}
    ]
    assert dv.violations_of(rules, dv._merged({"rd": None}, {"rd": "65000:1"})) == []
    # A field in neither is not checked.
    assert dv.violations_of(rules, {"description": ""}) == []


def test_validate_object_and_require_valid(admin):
    _rule(admin)
    assert asyncio.run(dv.validate_object("host", {"hostname": "sw-1"})) == []
    found = asyncio.run(dv.validate_object("host", {"hostname": "core"}))
    assert found == [{"field": "hostname", "rule": "hostname pattern", "message": found[0]["message"]}]
    with pytest.raises(dv.ValidationFailed) as exc:
        asyncio.run(dv.require_valid("host", {"hostname": "core"}))
    assert exc.value.violations == found
    # An update checks the merged result.
    assert asyncio.run(dv.validate_object("host", {"ip_address": "192.0.2.1"}, existing={"hostname": "bad"}))
    with pytest.raises(ValueError):
        asyncio.run(dv.validate_object("circuit", {}))


# ── Admin API ────────────────────────────────────────────────────────────────


def test_rule_crud_round_trip(admin):
    rule = _rule(admin, error_message="Hostnames look like sw-<n>.", description="naming")
    assert rule["params"] == {"pattern": "sw-[0-9]+"}
    assert rule["enabled"] is True and rule["created_by"] == "admin"
    assert admin.get(RULES).json()["rules"] == [rule]
    assert admin.get(f"{RULES}?object_type=vlan").json()["rules"] == []
    assert admin.get(f"{RULES}?object_type=circuit").status_code == 400
    assert admin.get(f"{RULES}/{rule['id']}").json() == rule

    resp = admin.put(f"{RULES}/{rule['id']}", json={"enabled": False, "rule_type": "length", "params": {"max": 20}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False and resp.json()["params"] == {"max": 20}
    assert resp.json()["name"] == "hostname pattern"

    assert admin.post(RULES, json={**rule, "name": "HOSTNAME PATTERN"}).status_code == 409
    assert admin.delete(f"{RULES}/{rule['id']}").json() == {"ok": True}
    assert admin.get(f"{RULES}/{rule['id']}").status_code == 404
    assert admin.delete(f"{RULES}/{rule['id']}").status_code == 404


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"name": " "}, "name"),
        ({"object_type": "circuit"}, "object_type"),
        ({"field": "serial"}, "field"),
        ({"field": "cf.owner"}, "field"),
        ({"object_type": "vlan", "field": "cf.owner"}, "field"),
        ({"rule_type": "regex", "params": {"pattern": "(?=sw)sw-1"}}, "params.pattern"),
        ({"rule_type": "regex", "params": {"pattern": r"(sw)-\1"}}, "params.pattern"),
        ({"rule_type": "length", "params": {"min": 9, "max": 1}}, "params.max"),
        ({"rule_type": "colour"}, "rule_type"),
    ],
)
def test_rule_create_validation(admin, body, field):
    base = {"name": "r", "object_type": "host", "field": "hostname", "rule_type": "required"}
    resp = admin.post(RULES, json={**base, **body})
    assert resp.status_code == 422, resp.text
    assert field in _fields(resp)


def test_rules_are_admin_only(admin):
    rule = _rule(admin)
    user = user_client(admin, "operator", features=["inventory", "ipam"])
    assert user.get(RULES).status_code == 403
    assert user.get(f"{RULES}/fields").status_code == 403
    assert user.get(f"{RULES}/violations").status_code == 403
    assert user.post(RULES, json={"name": "x"}).status_code == 403
    assert user.put(f"{RULES}/{rule['id']}", json={"enabled": False}).status_code == 403
    assert user.delete(f"{RULES}/{rule['id']}").status_code == 403
    assert user.post(f"{RULES}/test", json={"rule_id": rule["id"], "value": "x"}).status_code == 403


def test_test_endpoint(admin):
    rule = _rule(admin, error_message="Use sw-<n>.")
    assert admin.post(f"{RULES}/test", json={"rule_id": rule["id"], "value": "sw-9"}).json() == {
        "valid": True,
        "message": None,
    }
    assert admin.post(f"{RULES}/test", json={"rule_id": rule["id"], "value": "core"}).json() == {
        "valid": False,
        "message": "Use sw-<n>.",
    }
    inline = {"rule_type": "numeric", "params": {"min": 1, "max": 4094}, "field": "vid"}
    assert admin.post(f"{RULES}/test", json={**inline, "value": 5000}).json()["valid"] is False
    assert admin.post(f"{RULES}/test", json={**inline, "value": "10"}).json()["valid"] is True
    bad = admin.post(f"{RULES}/test", json={"rule_type": "regex", "params": {"pattern": "(?!x)y"}, "value": "y"})
    assert bad.status_code == 422 and "params.pattern" in _fields(bad)
    assert admin.post(f"{RULES}/test", json={"rule_id": 999, "value": "x"}).status_code == 404


def test_fields_lists_custom_fields(admin):
    resp = admin.post(
        "/api/custom-fields", json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
    )
    assert resp.status_code == 201, resp.text
    body = admin.get(f"{RULES}/fields").json()
    assert body["object_types"] == list(dv.OBJECT_TYPES)
    host_fields = [f["field"] for f in body["fields"]["host"]]
    assert "hostname" in host_fields and "cf.owner" in host_fields
    assert "cf.owner" not in [f["field"] for f in body["fields"]["group"]]


# ── Enforcement ──────────────────────────────────────────────────────────────


def test_host_create_and_update(admin):
    gid = _group(admin)
    _rule(admin, error_message="Hostnames look like sw-<n>.")
    bad = _add_host(admin, gid, "core_1", "192.0.2.10")
    assert bad.status_code == 422, bad.text
    detail = bad.json()["detail"]
    assert detail["fields"] == {"hostname": "Hostnames look like sw-<n>."}
    assert detail["violations"][0]["rule"] == "hostname pattern"
    assert bad.json()["error"]["message"] == "Hostnames look like sw-<n>."

    good = _add_host(admin, gid, "sw-1", "192.0.2.11")
    assert good.status_code == 201, good.text
    hid = good.json()["id"]
    upd = admin.put(f"/api/hosts/{hid}", json={"hostname": "renamed", "ip_address": "192.0.2.11"})
    assert upd.status_code == 422 and "hostname" in _fields(upd)
    assert admin.put(f"/api/hosts/{hid}", json={"hostname": "sw-2", "ip_address": "192.0.2.11"}).status_code == 200


def test_host_update_validates_the_merged_result(admin):
    gid = _group(admin)
    hid = _add_host(admin, gid, "sw-1", "192.0.2.10").json()["id"]
    _rule(admin, name="vrf set", field="vrf_name", rule_type="required", params={})
    # vrf_name left out keeps the stored (empty) value, which the rule refuses.
    resp = admin.put(f"/api/hosts/{hid}", json={"hostname": "sw-1", "ip_address": "192.0.2.10"})
    assert resp.status_code == 422 and "vrf_name" in _fields(resp)
    resp = admin.put(f"/api/hosts/{hid}", json={"hostname": "sw-1", "ip_address": "192.0.2.10", "vrf_name": "blue"})
    assert resp.status_code == 200, resp.text
    # Now stored: an edit that leaves it out passes.
    assert admin.put(f"/api/hosts/{hid}", json={"hostname": "sw-1", "ip_address": "192.0.2.10"}).status_code == 200


def test_disabled_rule_is_not_enforced_and_changes_apply_at_once(admin):
    gid = _group(admin)
    rule = _rule(admin)
    assert _add_host(admin, gid, "core", "192.0.2.10").status_code == 422
    admin.put(f"{RULES}/{rule['id']}", json={"enabled": False})
    assert _add_host(admin, gid, "core", "192.0.2.10").status_code == 201
    admin.put(f"{RULES}/{rule['id']}", json={"enabled": True})
    assert _add_host(admin, gid, "edge", "192.0.2.11").status_code == 422
    admin.delete(f"{RULES}/{rule['id']}")
    assert _add_host(admin, gid, "edge", "192.0.2.11").status_code == 201


def test_bulk_add_reports_rule_failures_per_entry(admin):
    gid = _group(admin)
    _rule(admin, error_message="Use sw-<n>.")
    resp = admin.post(
        "/api/inventory/hosts/bulk",
        json={
            "group_id": gid,
            "hosts": [
                {"hostname": "sw-1", "ip_address": "192.0.2.10"},
                {"hostname": "bad", "ip_address": "192.0.2.11"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [h["hostname"] for h in body["added"]] == ["sw-1"]
    assert body["errors"] == [{"hostname": "bad", "ip_address": "192.0.2.11", "error": "Use sw-<n>."}]


def test_group_create_and_update(admin):
    _rule(admin, name="group names", object_type="group", field="name", params={"pattern": "[A-Z][a-z]+"})
    resp = admin.post("/api/inventory", json={"name": "lower"})
    assert resp.status_code == 422 and "name" in _fields(resp)
    gid = _group(admin, "Core")
    _rule(admin, name="desc", object_type="group", field="description", rule_type="length", params={"max": 5})
    resp = admin.put(f"/api/inventory/{gid}", json={"name": "Core", "description": "far too long"})
    assert resp.status_code == 422 and "description" in _fields(resp)
    assert admin.put(f"/api/inventory/{gid}", json={"name": "Core", "description": "ok"}).status_code == 200


def test_prefix_and_address_create(admin):
    _rule(admin, name="prefix desc", object_type="prefix", field="description", rule_type="required", params={})
    resp = admin.post("/api/ipam/prefixes", json={"subnet": "198.51.100.0/24"})
    assert resp.status_code == 422 and "description" in _fields(resp)
    resp = admin.post("/api/ipam/prefixes", json={"subnet": "198.51.100.0/24", "description": "lab"})
    assert resp.status_code == 201, resp.text

    _rule(
        admin, name="dns", object_type="ip_address", field="hostname", params={"pattern": r"[a-z0-9-]+\.example\.com"}
    )
    url = "/api/ipam/subnets/198.51.100.0/24/allocations"
    resp = admin.post(url, json={"address": "198.51.100.5", "hostname": "printer"})
    assert resp.status_code == 422 and "hostname" in _fields(resp)
    resp = admin.post(url, json={"address": "198.51.100.5", "hostname": "printer.example.com"})
    assert resp.status_code == 201, resp.text


def test_vlan_and_vrf_create_and_update(admin):
    _rule(admin, name="vid range", object_type="vlan", field="vid", rule_type="numeric", params={"min": 100})
    resp = admin.post("/api/ipam/vlans", json={"vid": 10})
    assert resp.status_code == 422 and "vid" in _fields(resp)
    vlan = admin.post("/api/ipam/vlans", json={"vid": 110, "name": "users"}).json()
    _rule(admin, name="vlan names", object_type="vlan", field="name", params={"pattern": "[a-z]+"})
    resp = admin.put(f"/api/ipam/vlans/{vlan['id']}", json={"name": "Users 2"})
    assert resp.status_code == 422 and "name" in _fields(resp)
    assert admin.put(f"/api/ipam/vlans/{vlan['id']}", json={"name": "staff"}).status_code == 200

    vrf = admin.post("/api/ipam/vrfs", json={"name": "blue"}).json()
    _rule(admin, name="rd set", object_type="vrf", field="rd", rule_type="required", params={})
    # The stored rd is empty: an edit of the description alone is refused.
    resp = admin.put(f"/api/ipam/vrfs/{vrf['id']}", json={"description": "tenant"})
    assert resp.status_code == 422 and "rd" in _fields(resp)
    assert admin.put(f"/api/ipam/vrfs/{vrf['id']}", json={"rd": "65000:1"}).status_code == 200
    assert admin.post("/api/ipam/vrfs", json={"name": "red"}).status_code == 422


def test_custom_field_target(admin):
    resp = admin.post(
        "/api/custom-fields", json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
    )
    assert resp.status_code == 201, resp.text
    _rule(admin, name="owner email", field="cf.owner", params={"pattern": r"[a-z]+@example\.com"})
    _rule(admin, name="owner set", field="cf.owner", rule_type="required", params={}, error_message="Set an owner.")
    gid = _group(admin)
    # Creating the host does not check its custom fields (they are saved apart).
    hid = _add_host(admin, gid, "sw-1", "192.0.2.10").json()["id"]
    url = f"/api/hosts/{hid}/custom-data"
    resp = admin.put(url, json={"tag_ids": [], "fields": {"owner": "Bob"}})
    assert resp.status_code == 422, resp.text
    assert set(_fields(resp)) == {"owner"}
    resp = admin.put(url, json={"tag_ids": [], "fields": {}})
    assert resp.status_code == 422 and _fields(resp) == {"owner": "Set an owner."}
    resp = admin.put(url, json={"tag_ids": [], "fields": {"owner": "bob@example.com"}})
    assert resp.status_code == 200, resp.text
    # A rule on a custom field does not block an edit of the host itself.
    assert admin.put(f"/api/hosts/{hid}", json={"hostname": "sw-1", "ip_address": "192.0.2.10"}).status_code == 200


def test_rule_on_deleted_custom_field_can_still_be_turned_off(admin):
    field = admin.post(
        "/api/custom-fields", json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]}
    ).json()
    rule = _rule(admin, field="cf.owner", rule_type="required", params={})
    admin.delete(f"/api/custom-fields/{field['id']}")
    resp = admin.put(f"{RULES}/{rule['id']}", json={"enabled": False})
    assert resp.status_code == 200, resp.text


# ── Check existing data ──────────────────────────────────────────────────────


def test_violations_report_and_scope(admin):
    g1, g2 = _group(admin, "one"), _group(admin, "two")
    h1 = _add_host(admin, g1, "core-a", "192.0.2.10").json()["id"]
    h2 = _add_host(admin, g2, "core-b", "192.0.2.11").json()["id"]
    h3 = _add_host(admin, g2, "sw-3", "192.0.2.12").json()["id"]
    vlan = admin.post("/api/ipam/vlans", json={"vid": 20, "name": "Bad Name"}).json()
    assert admin.get(f"{RULES}/violations").json() == {"objects": [], "checked": 0, "truncated": False}

    _rule(admin)
    _rule(admin, name="vlan names", object_type="vlan", field="name", params={"pattern": "[a-z]+"})
    body = admin.get(f"{RULES}/violations").json()
    assert body["checked"] >= 4 and body["truncated"] is False
    found = {(o["object_type"], o["object_id"]) for o in body["objects"]}
    assert {("host", h1), ("host", h2), ("vlan", vlan["id"])} <= found
    assert ("host", h3) not in found
    entry = next(o for o in body["objects"] if o["object_id"] == h1 and o["object_type"] == "host")
    assert entry["label"] == "core-a (192.0.2.10)"
    assert entry["violations"][0]["field"] == "hostname"
    vlans = admin.get(f"{RULES}/violations?object_type=vlan").json()
    assert {o["object_type"] for o in vlans["objects"]} == {"vlan"}
    assert admin.get(f"{RULES}/violations?object_type=circuit").status_code == 400

    scoped = ObjectScope(unrestricted=False, read_groups=frozenset({g1}), write_groups=frozenset())
    mine = asyncio.run(dv.find_violations(scoped, "host"))
    assert [o["object_id"] for o in mine["objects"]] == [h1]
    assert mine["checked"] == 1
    everyone = {o["object_id"] for o in asyncio.run(dv.find_violations(UNRESTRICTED, "host"))["objects"]}
    assert {h1, h2} <= everyone


def test_violations_report_includes_custom_fields(admin):
    admin.post(
        "/api/custom-fields", json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["group"]}
    )
    gid = _group(admin, "edge")
    _rule(admin, name="group owner", object_type="group", field="cf.owner", rule_type="required", params={})
    objects = admin.get(f"{RULES}/violations?object_type=group").json()["objects"]
    assert (gid, "cf.owner") in [(o["object_id"], o["violations"][0]["field"]) for o in objects]
    resp = admin.put(f"/api/inventory/{gid}/custom-data", json={"tag_ids": [], "fields": {"owner": "netops"}})
    assert resp.status_code == 200, resp.text
    objects = admin.get(f"{RULES}/violations?object_type=group").json()["objects"]
    assert gid not in [o["object_id"] for o in objects]
