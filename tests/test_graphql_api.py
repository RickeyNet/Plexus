"""Read-only GraphQL API (``/api/graphql``): authentication and feature
gates, object scope, nested relations, query limits, secrets, GraphiQL and
the admin settings."""

from __future__ import annotations

import asyncio
import json

import netcontrol.app as app_module
import pytest
import routes.database as db
from graphql import parse
from netcontrol import object_scope
from netcontrol.graphql_api import limits
from netcontrol.graphql_api.schema import schema
from netcontrol.routes import state
from netcontrol.routes.device_config import store_device_config
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

URL = "/api/graphql"
SETTINGS = "/api/admin/graphql/settings"
SECRET_COMMUNITY = "Zq9-community-not-for-graphql"
SECRET_TOKEN = "Zq9-ipam-token-not-for-graphql"

IOS = f"""hostname edge-r1
snmp-server community {SECRET_COMMUNITY} RO
interface Vlan10
 vrf forwarding BLUE
 ip address 192.0.2.2 255.255.255.0
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.252
!
"""


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _gql(client: CsrfClient, query: str, variables: dict | None = None, status: int = 200) -> dict:
    return _ok(client.post(URL, json={"query": query, "variables": variables}), status)


def _group(admin: CsrfClient, name: str, parent_id: int | None = None) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name, "parent_id": parent_id}), 201)["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str) -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{group_id}/hosts", json=body), 201)["id"])


def _login(username: str) -> CsrfClient:
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


def _scoped_user(admin: CsrfClient, name: str, group_id: int, features: list[str]) -> CsrfClient:
    body = {
        "name": f"{name} access",
        "feature_keys": features,
        "object_scope": "groups",
        "inventory_scopes": [{"inventory_group_id": group_id}],
    }
    group = _ok(admin.post("/api/admin/access-groups", json=body), 201)
    user = {"username": name, "password": "password123", "group_ids": [group["id"]]}
    _ok(admin.post("/api/admin/users", json=user), 201)
    return _login(name)


@pytest.fixture
def world(admin) -> dict:
    """Two sites with a host each; site-a's host has a stored configuration
    (interface addresses, VRF BLUE), an interface, a VLAN record, a tag and
    a custom field; an IPAM source holds 192.0.2.0/24 (VRF BLUE, VLAN 10),
    its child 192.0.2.0/26 and an address."""
    w: dict = {}
    w["a"] = _group(admin, "site-a")
    w["a1"] = _group(admin, "floor-1", w["a"])
    w["b"] = _group(admin, "site-b")
    w["ha"] = _host(admin, w["a1"], "edge-r1", "192.0.2.10")
    w["hb"] = _host(admin, w["b"], "edge-r2", "198.51.100.20")

    async def seed() -> None:
        await store_device_config(w["ha"], IOS, "", capture_method="topology")
        await db.upsert_interface_inventory(w["ha"], 10, "Vlan10", "users", "up", "up", 1000, "full", "", 0, "")
        w["vlan"] = (await db.create_vlan(vid=10, name="users"))["id"]
        source = await db.create_ipam_source(
            provider="netbox", name="lab ipam", base_url="https://ipam.example.com", auth_config={"token": SECRET_TOKEN}
        )
        assert source is not None
        await db.replace_ipam_source_snapshot(
            int(source["id"]),
            [
                {"id": 1, "subnet": "192.0.2.0/24", "vrf": "BLUE", "vlan": "10", "metadata": {"token": SECRET_TOKEN}},
                {"id": 2, "subnet": "192.0.2.0/26", "vrf": "BLUE"},
                {"id": 3, "subnet": "198.51.100.0/24"},
            ],
            [{"address": "192.0.2.5", "prefix_subnet": "192.0.2.0/24", "dns_name": "app.example.com"}],
        )
        tag = await db.create_tag(name="core", color="blue")
        field = await db.create_custom_field(
            key="rack",
            label="Rack",
            field_type="text",
            choices=[],
            object_types=["host"],
            required=False,
            default_value="",
            description="",
            sort_order=0,
            created_by="admin",
        )
        await db.set_object_data("host", str(w["ha"]), [int(tag["id"])], {int(field["id"]): "R1"})

    asyncio.run(seed())
    return w


# ── Authentication and features ──────────────────────────────────────────────


def test_anonymous_and_ungated_callers_are_refused(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.post(URL, json={"query": "{ hosts { id } }"}).status_code == 401
    assert anon.get(URL).status_code == 401

    plain = user_client(admin, "no-graphql", features=["inventory"])
    assert plain.post(URL, json={"query": "{ hosts { id } }"}).status_code == 403

    # A session POST without the CSRF header is refused like any other write.
    assert admin.raw.post(URL, json={"query": "{ hosts { id } }"}).status_code == 403


def test_each_field_needs_the_feature_of_its_rest_route(admin, world):
    reader = user_client(admin, "gql-reader", features=["graphql", "inventory"])
    body = _gql(
        reader,
        '{ hosts(name: "edge-") { hostname interfaces { name } latestConfigBackup { id } } prefixes { prefix } }',
    )
    assert body["data"]["prefixes"] is None
    assert {h["hostname"] for h in body["data"]["hosts"]} == {"edge-r1", "edge-r2"}
    assert all(h["interfaces"] is None and h["latestConfigBackup"] is None for h in body["data"]["hosts"])
    messages = {e["message"] for e in body["errors"]}
    assert messages == {
        "Access denied for feature 'ipam'",
        "Access denied for feature 'reports'",
        "Access denied for feature 'config-backups'",
    }


# ── Object scope ─────────────────────────────────────────────────────────────


def test_graphql_is_scope_enforced():
    assert "graphql" in object_scope.SCOPE_ENFORCED_FEATURES
    assert "netcontrol.routes.graphql:router" in object_scope.SCOPE_ENFORCED_ROUTERS


def test_scope_hides_out_of_scope_hosts_and_groups(admin, world):
    scoped = _scoped_user(admin, "east-ops", world["a"], ["graphql", "inventory", "config-backups", "ipam"])
    query = """query($a: Int!, $b: Int!) {
        hosts { id hostname group { name parent { name } } latestConfigBackup { status } }
        groups { id name hosts(limit: 20) { hostname } }
        visible: host(id: $a) { hostname }
        hidden: host(id: $b) { hostname }
        groupB: group(id: $b2) { name }
        prefixes { prefix }
    }""".replace("$b2", str(world["b"]))
    body = _gql(scoped, query, {"a": world["ha"], "b": world["hb"]})
    data = body["data"]
    assert [h["hostname"] for h in data["hosts"]] == ["edge-r1"]
    assert data["hosts"][0]["group"] == {"name": "floor-1", "parent": {"name": "site-a"}}
    assert data["hosts"][0]["latestConfigBackup"] == {"status": "success"}
    assert {g["name"] for g in data["groups"]} == {"site-a", "floor-1"}
    assert data["visible"] == {"hostname": "edge-r1"}
    assert data["hidden"] is None and data["groupB"] is None
    # IPAM is filtered by the scope model registry: a prefix of no tenant is
    # not one a scoped caller reaches.
    assert data["prefixes"] == []
    assert "errors" not in body

    # A grant on the sub-group only: its parent reads null.
    floor = _scoped_user(admin, "floor-ops", world["a1"], ["graphql", "inventory"])
    data = _gql(floor, "{ groups { name parent { name } } hosts { hostname } }")["data"]
    assert data["groups"] == [{"name": "floor-1", "parent": None}]
    assert [h["hostname"] for h in data["hosts"]] == ["edge-r1"]


# ── Relations ────────────────────────────────────────────────────────────────


def test_nested_query_across_inventory_and_ipam(admin, world):
    query = """query($id: Int!) {
      host(id: $id) {
        hostname ipAddress
        group { name path parent { name } children { name } }
        interfaces { name operState speedMbps addresses { address prefixLength vrfName } }
        interfaceAddresses { interface address role vrf { name } vlan { vid name } }
        vrf { name }
        latestConfigBackup { status captureMethod configLength }
        tags { name color }
        customFields { key value }
      }
      groups(name: "site") { name children { name hosts(limit: 20) { hostname } } }
      prefixes(within: "192.0.2.0/24") {
        prefix vrfName vrf { name } vlan { vid name }
        parent { prefix }
        children(limit: 20) { prefix }
        ipAddresses(limit: 20) { address dnsName source vrf { name } }
      }
      vlans(vid: 10) { name prefixes(limit: 20) { prefix } }
      vrfs(name: "BLUE") { name prefixes(limit: 20) { prefix } }
      ipAddresses(address: "192.0.2.5") { address prefixSubnet sourceName }
    }"""
    body = _gql(admin, query, {"id": world["ha"]})
    assert "errors" not in body, body
    host = body["data"]["host"]
    assert host["hostname"] == "edge-r1" and host["ipAddress"] == "192.0.2.10"
    assert host["group"] == {
        "name": "floor-1",
        "path": "site-a / floor-1",
        "parent": {"name": "site-a"},
        "children": [],
    }
    assert host["interfaces"] == [
        {
            "name": "Vlan10",
            "operState": "up",
            "speedMbps": 1000.0,
            "addresses": [{"address": "192.0.2.2", "prefixLength": 24, "vrfName": "BLUE"}],
        }
    ]
    by_if = {a["interface"]: a for a in host["interfaceAddresses"]}
    assert by_if["Vlan10"]["vrf"] == {"name": "BLUE"}
    assert by_if["Vlan10"]["vlan"] == {"vid": 10, "name": "users"}
    assert by_if["GigabitEthernet0/1"]["vrf"] is None
    assert host["vrf"] is None
    assert host["latestConfigBackup"]["status"] == "success"
    assert host["latestConfigBackup"]["configLength"] > 0
    assert host["tags"] == [{"name": "core", "color": "blue"}]
    assert host["customFields"] == [{"key": "rack", "value": "R1"}]

    groups = body["data"]["groups"]
    assert [g["name"] for g in groups] == ["site-a", "site-b"]
    assert groups[0]["children"] == [{"name": "floor-1", "hosts": [{"hostname": "edge-r1"}]}]

    prefixes = {p["prefix"]: p for p in body["data"]["prefixes"]}
    assert set(prefixes) == {"192.0.2.0/24", "192.0.2.0/26"}
    top = prefixes["192.0.2.0/24"]
    assert top["vrf"] == {"name": "BLUE"} and top["vlan"] == {"vid": 10, "name": "users"}
    assert top["parent"] is None and top["children"] == [{"prefix": "192.0.2.0/26"}]
    assert top["ipAddresses"] == [
        {"address": "192.0.2.5", "dnsName": "app.example.com", "source": "netbox", "vrf": {"name": "BLUE"}}
    ]
    assert prefixes["192.0.2.0/26"]["parent"] == {"prefix": "192.0.2.0/24"}
    assert body["data"]["vlans"] == [{"name": "users", "prefixes": [{"prefix": "192.0.2.0/24"}]}]
    assert body["data"]["vrfs"] == [
        {"name": "BLUE", "prefixes": [{"prefix": "192.0.2.0/24"}, {"prefix": "192.0.2.0/26"}]}
    ]
    assert body["data"]["ipAddresses"] == [
        {"address": "192.0.2.5", "prefixSubnet": "192.0.2.0/24", "sourceName": "lab ipam"}
    ]


def test_filters_and_paging(admin, world):
    data = _gql(
        admin,
        """query($b: Int!) {
          byIp: hosts(ip: "198.51.100.0/24") { hostname }
          byExactIp: hosts(ip: "192.0.2.10") { hostname }
          byGroup: hosts(group: "site-a / floor-1") { hostname }
          byGroupId: hosts(groupId: $b) { hostname }
          byTag: hosts(tags: ["CORE"]) { hostname }
          byName: hosts(name: "EDGE-R2") { hostname }
          paged: hosts(name: "edge-", limit: 1, offset: 1) { hostname }
          containing: prefixes(contains: "192.0.2.5") { prefix }
          globalVrf: prefixes(vrf: "") { prefix }
          exact: prefixes(prefix: "192.0.2.9/24") { prefix }
        }""",
        {"b": world["b"]},
    )["data"]
    assert data["byIp"] == [{"hostname": "edge-r2"}]
    assert data["byExactIp"] == [{"hostname": "edge-r1"}]
    assert data["byGroup"] == [{"hostname": "edge-r1"}]
    assert data["byGroupId"] == [{"hostname": "edge-r2"}]
    assert data["byTag"] == [{"hostname": "edge-r1"}]
    assert data["byName"] == [{"hostname": "edge-r2"}]
    assert data["paged"] == [{"hostname": "edge-r2"}]
    assert data["containing"] == [{"prefix": "192.0.2.0/24"}, {"prefix": "192.0.2.0/26"}]
    assert data["globalVrf"] == [{"prefix": "198.51.100.0/24"}]
    assert data["exact"] == [{"prefix": "192.0.2.0/24"}]

    body = _gql(admin, '{ a: hosts(limit: 0) { id } b: hosts(ip: "nope") { id } c: hosts(offset: -1) { id } }')
    assert body["data"] == {"a": None, "b": None, "c": None}
    assert {e["message"] for e in body["errors"]} == {
        "limit must be between 1 and 1000",
        "ip must be an IP address or a network",
        "offset must be 0 or more",
    }


# ── Limits ───────────────────────────────────────────────────────────────────


def test_depth_alias_cost_and_introspection_limits(admin, world):
    deep = "{ groups { " + "parent { " * 8 + "id" + " }" * 8 + " } }"
    body = _gql(admin, deep, status=400)
    assert body["data"] is None
    assert "exceeds maximum operation depth of 8" in body["errors"][0]["message"]
    assert "errors" not in _gql(admin, "{ groups { " + "parent { " * 6 + "id" + " }" * 6 + " } }")

    aliases = "{ " + " ".join(f"h{i}: hosts {{ id }}" for i in range(16)) + " }"
    assert "aliases" in _gql(admin, aliases, status=400)["errors"][0]["message"]

    costly = "{ groups(limit: 1000) { hosts(limit: 1000) { id } } }"
    assert "too complex" in _gql(admin, costly, status=400)["errors"][0]["message"]
    by_variable = "query($n: Int!) { groups(limit: $n) { hosts(limit: $n) { id } } }"
    assert "too complex" in _gql(admin, by_variable, {"n": 1000}, status=400)["errors"][0]["message"]
    assert "errors" not in _gql(admin, by_variable, {"n": 10})

    assert "introspection" in _gql(admin, "{ __schema { types { name } } }", status=400)["errors"][0]["message"]
    assert _gql(admin, "{ __typename }")["data"] == {"__typename": "Query"}

    _ok(admin.put(SETTINGS, json={"introspection": True, "max_depth": 3}))
    assert _gql(admin, '{ __type(name: "Host") { name } }')["data"] == {"__type": {"name": "Host"}}
    assert (
        "depth of 3"
        in _gql(admin, "{ hosts { group { parent { parent { id } } } } }", status=400)["errors"][0]["message"]
    )

    assert (
        "too long" in _gql(admin, "{ hosts { id } }" + " " * limits.MAX_QUERY_CHARS, status=400)["errors"][0]["message"]
    )
    assert _gql(admin, "{ hosts { id ", status=400)["errors"][0]["message"].startswith("Syntax Error")
    assert _gql(admin, "{ nope }", status=400)["errors"][0]["message"].startswith("Cannot query field")


def test_cost_estimate_counts_rows_fragments_and_defaults():
    gql_schema = schema._schema
    doc = parse("{ groups(limit: 10) { hosts(limit: 5) { id } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (10 + 50, False)
    # Root lists default to 100 rows; nested lists without limit to the estimate.
    doc = parse("{ hosts { interfaces { name } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (100 + 100 * limits.UNBOUNDED_LIST_ESTIMATE, False)
    doc = parse("query { ...F } fragment F on Query { vrfs(limit: 2) { ... on VRF { name } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (2, False)
    assert limits.estimate_cost(gql_schema, doc, None, 1) == (2, True)


def test_mutations_and_bad_requests_are_refused(admin):
    assert admin.post(URL, content=b"not json", headers={"Content-Type": "application/json"}).status_code == 400
    assert _gql(admin, "", status=400)["errors"][0]["message"] == "query must be a non-empty string"
    assert admin.post(URL, json=[1]).status_code == 400
    assert admin.post(URL, json={"query": "{ hosts { id } }", "variables": [1]}).status_code == 400
    assert admin.post(URL, json={"query": "{ hosts { id } }", "operationName": 5}).status_code == 400
    # No mutation type exists: a mutation fails validation.
    body = _gql(admin, "mutation { deleteHost(id: 1) }", status=400)
    assert "mutation" in body["errors"][0]["message"].lower()
    # An unknown operation name is a request error.
    resp = admin.post(URL, json={"query": "query A { hosts { id } }", "operationName": "B"})
    assert resp.status_code == 400
    two = "query A { hosts(limit: 1) { id } } query B { groups(limit: 1) { id } }"
    assert "operationName" in _gql(admin, two, status=400)["errors"][0]["message"]
    picked = _ok(admin.post(URL, json={"query": two, "operationName": "B"}))
    assert list(picked["data"]) == ["groups"]


# ── Secrets ──────────────────────────────────────────────────────────────────

_SECRET_WORDS = ("password", "secret", "community", "credential", "token", "configtext", "metadata", "snmp", "key")


def test_schema_declares_no_secret_fields():
    sdl = str(schema).lower()
    for line in sdl.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(('"', "type ", "schema", "}")):
            continue
        name = stripped.split("(")[0].split(":")[0]
        if name == "key":  # CustomFieldValue.key: the field's key name
            continue
        assert not any(word in name for word in _SECRET_WORDS), stripped


def test_secrets_never_reach_a_response(admin, world):
    query = """{
      hosts { hostname ipAddress model serialNumber interfaces { name description }
              interfaceAddresses { interface address } latestConfigBackup { id errorMessage configLength }
              customFields { key value } }
      prefixes { prefix description sourceName ipAddresses(limit: 20) { address description } }
      ipAddresses { address dnsName description }
    }"""
    resp = admin.post(URL, json={"query": query})
    assert resp.status_code == 200, resp.text
    assert "errors" not in resp.json()
    assert SECRET_COMMUNITY not in resp.text and SECRET_TOKEN not in resp.text
    for field in ("configText", "credentialId", "authConfig", "metadataJson", "snmpProfileId", "fdmCredentialId"):
        body = _gql(admin, "{ hosts { " + field + " } }", status=400)
        assert body["errors"][0]["message"].startswith("Cannot query field"), field


# ── GraphiQL and settings ────────────────────────────────────────────────────


def test_graphiql_is_served_only_when_enabled(admin):
    assert admin.get(URL).status_code == 404
    _ok(admin.put(SETTINGS, json={"graphiql": True}))
    resp = admin.get(URL)
    assert resp.status_code == 200
    assert "graphiql" in resp.text and "integrity=" in resp.text
    csp = resp.headers["content-security-policy"]
    assert "script-src https://unpkg.com 'sha256-" in csp and "unsafe-eval" not in csp
    # A GET never runs a query.
    assert admin.get(URL + "?query={hosts{id}}").text == resp.text


def test_settings_are_admin_only_validated_and_audited(admin):
    assert _ok(admin.get(SETTINGS)) == {
        "graphiql": False,
        "introspection": False,
        "max_depth": 8,
        "max_aliases": 15,
        "max_complexity": 50_000,
        "max_limit": 1000,
    }
    for bad in ({"max_depth": 1}, {"graphiql": "yes"}, {"nope": 1}, {"max_limit": True}):
        assert admin.put(SETTINGS, json=bad).status_code == 422, bad
    merged = _ok(admin.put(SETTINGS, json={"max_limit": 50}))
    assert merged["max_limit"] == 50
    assert "limit must be between 1 and 50" in json.dumps(_gql(admin, "{ hosts(limit: 60) { id } }"))

    plain = user_client(admin, "gql-user", features=["graphql"])
    assert plain.get(SETTINGS).status_code == 403
    assert plain.put(SETTINGS, json={"graphiql": True}).status_code == 403
    events = asyncio.run(db.get_audit_events(limit=20, category="graphql"))
    assert any(e["action"] == "settings_update" and '"max_limit": 50' in e["detail"] for e in events)


def test_api_token_is_unrestricted(admin, monkeypatch, world):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "graphql-test-token")
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post(
        URL,
        json={"query": '{ hosts(name: "edge-") { hostname } prefixes(limit: 1) { prefix } }'},
        headers={"X-API-Token": "graphql-test-token"},
    )
    body = _ok(resp)
    assert {h["hostname"] for h in body["data"]["hosts"]} == {"edge-r1", "edge-r2"}
    assert body["data"]["prefixes"] == [{"prefix": "192.0.2.0/24"}]
