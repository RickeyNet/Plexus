"""Object-level permissions over HTTP: the admin access group API, the
``object_scope`` of the status and login responses, the fail-closed feature
reduction (incl. MCP), and the enforcement in the inventory routers
(``inventory``, the custom field and device model inventory routers, the
Ansible inventory). Ends with the completeness test and the out-of-scope
GET sweep of the design."""

from __future__ import annotations

import re

import netcontrol.app as app_module
import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute, _IncludedRouter
from netcontrol import object_scope
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client, create_token, enable_mcp, user_client

GROUPS = "/api/admin/access-groups"


def _error(message: str) -> dict:
    """The body of an HTTPException on an /api/ path."""
    return {"ok": False, "error": {"code": "http_error", "message": message}}


READ_ONLY = _error("Read-only access to this inventory group")
GROUP_404 = _error("Group not found")
HOST_404 = _error("Host not found")


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _group(admin: CsrfClient, name: str, parent_id: int | None = None) -> int:
    resp = admin.post("/api/inventory", json={"name": name, "parent_id": parent_id})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str) -> int:
    resp = admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": name, "ip_address": ip})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


@pytest.fixture
def tree(admin) -> dict[str, int]:
    """site-a > floor-1 > rack-1, and site-b; one host in each."""
    t: dict[str, int] = {}
    t["a"] = _group(admin, "site-a")
    t["a1"] = _group(admin, "floor-1", t["a"])
    t["a11"] = _group(admin, "rack-1", t["a1"])
    t["b"] = _group(admin, "site-b")
    t["ha"] = _host(admin, t["a"], "edge-a", "192.0.2.10")
    t["ha1"] = _host(admin, t["a1"], "edge-a1", "192.0.2.11")
    t["ha11"] = _host(admin, t["a11"], "edge-a11", "192.0.2.12")
    t["hb"] = _host(admin, t["b"], "edge-b", "198.51.100.20")
    return t


def _access_group(admin: CsrfClient, name: str, grants: list[dict] | None, features=("inventory",)) -> dict:
    body: dict = {"name": name, "feature_keys": list(features)}
    if grants is not None:
        body.update(object_scope="groups", inventory_scopes=grants)
    resp = admin.post(GROUPS, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _login(username: str) -> tuple[CsrfClient, dict]:
    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"]), resp.json()


def _scoped(admin: CsrfClient, name: str, grants: list[dict], features=("inventory",)) -> CsrfClient:
    group = _access_group(admin, f"{name} access", grants, features)
    resp = admin.post("/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group["id"]]})
    assert resp.status_code == 201, resp.text
    return _login(name)[0]


def _ids(rows: list[dict]) -> set[int]:
    return {int(r["id"]) for r in rows}


# ── Admin API ────────────────────────────────────────────────────────────────


def test_access_group_api_round_trip_validation_and_audit(admin, tree):
    created = _access_group(
        admin,
        "east",
        [{"inventory_group_id": tree["a"], "can_write": True}, {"inventory_group_id": tree["b"]}],
    )
    assert created["object_scope"] == "groups"
    assert created["inventory_scopes"] == [
        {"inventory_group_id": tree["a"], "can_write": True},
        {"inventory_group_id": tree["b"], "can_write": False},
    ]
    listed = next(g for g in admin.get(GROUPS).json() if g["id"] == created["id"])
    assert listed["inventory_scopes"] == created["inventory_scopes"]

    bad = admin.post(
        GROUPS, json={"name": "ghost", "object_scope": "groups", "inventory_scopes": [{"inventory_group_id": 999999}]}
    )
    assert bad.status_code == 400
    assert "inventory groups" in bad.json()["error"]["message"]
    assert admin.post(GROUPS, json={"name": "odd", "object_scope": "sites"}).status_code == 400

    # An update that leaves object_scope out keeps the grants (older clients).
    kept = admin.put(f"{GROUPS}/{created['id']}", json={"name": "east", "feature_keys": ["inventory"]})
    assert kept.status_code == 200, kept.text
    assert kept.json()["inventory_scopes"] == created["inventory_scopes"]
    # "all" ignores and clears the grants.
    cleared = admin.put(
        f"{GROUPS}/{created['id']}",
        json={"name": "east", "object_scope": "all", "inventory_scopes": [{"inventory_group_id": tree["a"]}]},
    )
    assert cleared.json()["object_scope"] == "all"
    assert cleared.json()["inventory_scopes"] == []
    plain = admin.post(GROUPS, json={"name": "plain"}).json()
    assert plain["object_scope"] == "all"
    assert admin.delete(f"{GROUPS}/{plain['id']}").status_code == 200

    events = admin.get("/api/admin/audit-events?limit=50").json()
    details = {(e["action"], e["detail"]) for e in events}
    assert any(a == "access_group.create" and "object_scope=groups" in d for a, d in details)
    assert any(a == "access_group.update" and "object_scope=groups" in d and "-> object_scope=all" in d for a, d in details)
    assert any(a == "access_group.delete" for a, _ in details)


def test_status_login_and_admin_user_payload(admin, tree):
    scoped = _scoped(admin, "east-ops", [{"inventory_group_id": tree["a1"], "can_write": True}])
    _, login = _login("east-ops")
    expected = {"restricted": True, "write_group_ids": sorted([tree["a1"], tree["a11"]])}
    assert login["object_scope"] == expected
    assert scoped.get("/api/auth/status").json()["object_scope"] == expected
    assert admin.get("/api/auth/status").json()["object_scope"] == {"restricted": False, "write_group_ids": []}

    _access_group(admin, "everyone", None)
    users = {u["username"]: u for u in admin.get("/api/admin/users").json()}
    assert users["east-ops"]["object_scope_restricted"] is True
    assert users["admin"]["object_scope_restricted"] is False


# ── Fail closed ──────────────────────────────────────────────────────────────


def test_scoped_user_keeps_only_enforced_features(admin, tree):
    features = ["dashboard", "inventory", "inventory.write", "jobs", "ipam"]
    scoped = _scoped(admin, "scoped-many", [{"inventory_group_id": tree["a"]}], features)
    assert scoped.get("/api/auth/status").json()["feature_access"] == ["inventory", "inventory.write"]
    for url in ("/api/jobs", "/api/dashboard", "/api/ipam/subnets", "/api/ipam/vrfs"):
        assert scoped.get(url).status_code == 403, url
    assert scoped.get("/api/inventory").status_code == 200

    # The same features with access to all devices: unchanged.
    everyone = user_client(admin, "everyone-many", features=features)
    status = everyone.get("/api/auth/status").json()
    assert set(status["feature_access"]) == set(features)
    assert status["object_scope"] == {"restricted": False, "write_group_ids": []}
    assert everyone.get("/api/jobs").status_code == 200
    assert everyone.get("/api/dashboard").status_code == 200


def test_mcp_token_of_scoped_owner_is_refused(admin, tree, monkeypatch):
    from starlette.testclient import TestClient

    _scoped(admin, "scoped-ai", [{"inventory_group_id": tree["a"]}])
    owner = next(u["id"] for u in admin.get("/api/admin/users").json() if u["username"] == "scoped-ai")
    enable_mcp(admin)
    token = create_token(admin, owner=owner, categories=("inventory",))
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.portal = admin.raw.portal
    resp = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"
    assert "inventory groups" in resp.json()["message"]


# ── Inventory reads ──────────────────────────────────────────────────────────


def test_lists_show_only_readable_groups_and_hosts(admin, tree):
    scoped = _scoped(admin, "reader-a1", [{"inventory_group_id": tree["a1"]}])
    groups = scoped.get("/api/inventory").json()
    assert _ids(groups) == {tree["a1"], tree["a11"]}
    floor = next(g for g in groups if g["id"] == tree["a1"])
    # The hidden parent is not named: floor-1 is a top-level group here.
    assert floor["parent_id"] is None
    assert floor["path"] == "floor-1"
    rack = next(g for g in groups if g["id"] == tree["a11"])
    assert rack["parent_id"] == tree["a1"]
    assert rack["path"] == "floor-1 / rack-1"

    with_hosts = scoped.get("/api/inventory?include_hosts=true").json()
    assert {h["id"] for g in with_hosts for h in g["hosts"]} == {tree["ha1"], tree["ha11"]}
    one = scoped.get(f"/api/inventory/{tree['a1']}").json()
    assert one["parent_id"] is None
    assert one["path"] == "floor-1"
    assert _ids(one["hosts"]) == {tree["ha1"]}

    # Out of scope answers exactly like an unknown id.
    assert scoped.get(f"/api/inventory/{tree['a']}").json() == GROUP_404
    assert scoped.get("/api/inventory/999999").json() == GROUP_404
    assert scoped.get(f"/api/inventory/{tree['a']}").status_code == 404
    assert scoped.get(f"/api/hosts/{tree['hb']}/custom-data").json() == HOST_404
    assert scoped.get(f"/api/hosts/{tree['ha1']}/custom-data").status_code == 200

    csv_text = scoped.get("/api/inventory/export/csv").text
    assert "edge-a1" in csv_text and "edge-a11" in csv_text
    assert "edge-b" not in csv_text and "edge-a," not in csv_text

    ansible = scoped.get("/api/ansible/inventory").json()
    assert sorted(ansible["all"]["hosts"]) == ["edge-a1", "edge-a11"]
    assert scoped.get("/api/ansible/inventory/host/edge-b").status_code == 404
    assert scoped.get("/api/ansible/inventory/host/edge-a1").status_code == 200


def test_no_grants_sees_nothing(admin, tree):
    scoped = _scoped(admin, "nothing", [])
    assert scoped.get("/api/inventory").json() == []
    assert scoped.get("/api/ansible/inventory").json()["all"]["hosts"] == []
    assert scoped.get(f"/api/inventory/{tree['a']}/hosts").status_code == 404


def test_unrestricted_user_sees_everything(admin, tree):
    everyone = user_client(admin, "all-devices", features=["inventory"])
    assert {tree["a"], tree["a1"], tree["a11"], tree["b"]} <= _ids(everyone.get("/api/inventory").json())
    assert "edge-b" in everyone.get("/api/inventory/export/csv").text
    assert everyone.put(f"/api/inventory/{tree['b']}", json={"name": "site-b"}).status_code == 200


# ── Inventory writes ─────────────────────────────────────────────────────────


def test_read_only_and_writable_groups(admin, tree):
    scoped = _scoped(
        admin,
        "mixed-rw",
        [{"inventory_group_id": tree["a"]}, {"inventory_group_id": tree["a1"], "can_write": True}],
    )
    # Read only on site-a itself.
    resp = scoped.put(f"/api/inventory/{tree['a']}", json={"name": "renamed"})
    assert (resp.status_code, resp.json()) == (403, READ_ONLY)
    resp = scoped.post(f"/api/inventory/{tree['a']}/hosts", json={"hostname": "x", "ip_address": "192.0.2.50"})
    assert (resp.status_code, resp.json()) == (403, READ_ONLY)
    assert scoped.put(f"/api/hosts/{tree['ha']}", json={"hostname": "x", "ip_address": "192.0.2.10"}).status_code == 403
    assert scoped.delete(f"/api/hosts/{tree['ha']}").status_code == 403
    assert scoped.put(f"/api/hosts/{tree['ha']}/custom-data", json={"tag_ids": [], "fields": {}}).status_code == 403
    # Outside the scope: 404 on writes too.
    assert scoped.delete(f"/api/inventory/{tree['b']}").status_code == 404
    assert scoped.delete(f"/api/hosts/{tree['hb']}").status_code == 404
    # Writable floor-1 and its rack.
    added = scoped.post(f"/api/inventory/{tree['a11']}/hosts", json={"hostname": "new", "ip_address": "192.0.2.51"})
    assert added.status_code == 201, added.text
    assert scoped.put(f"/api/inventory/{tree['a1']}", json={"name": "floor-one"}).status_code == 200
    resp = scoped.raw.patch(
        f"/api/hosts/{tree['ha1']}/category",
        json={"device_category": "switch"},
        headers={"X-CSRF-Token": scoped._csrf},
    )
    assert resp.status_code == 200, resp.text


def test_group_create_and_move_rules(admin, tree):
    scoped = _scoped(
        admin,
        "builder",
        [{"inventory_group_id": tree["a"]}, {"inventory_group_id": tree["a1"], "can_write": True}],
    )
    top = scoped.post("/api/inventory", json={"name": "rogue"})
    assert top.status_code == 403
    assert scoped.post("/api/inventory", json={"name": "rack-2", "parent_id": tree["a1"]}).status_code == 201
    assert scoped.post("/api/inventory", json={"name": "x", "parent_id": tree["a"]}).json() == READ_ONLY
    assert scoped.post("/api/inventory", json={"name": "x", "parent_id": tree["b"]}).status_code == 404
    # Moving rack-1 needs write on its parent (yes) and the destination.
    assert scoped.put(f"/api/inventory/{tree['a11']}", json={"name": "rack-1", "parent_id": tree["a"]}).status_code == 403
    assert scoped.put(f"/api/inventory/{tree['a11']}", json={"name": "rack-1", "parent_id": None}).status_code == 403
    # floor-1 is a granted root: its parent is read only, so it cannot move.
    assert scoped.put(f"/api/inventory/{tree['a1']}", json={"name": "floor-1", "parent_id": None}).status_code == 403
    # A rename that keeps the parent is fine.
    resp = scoped.put(f"/api/inventory/{tree['a11']}", json={"name": "rack-1b", "parent_id": tree["a1"]})
    assert resp.status_code == 200, resp.text

    # Hosts: moving needs write on source and destination.
    move = scoped.post("/api/hosts/move", json={"host_ids": [tree["ha1"]], "target_group_id": tree["b"]})
    assert (move.status_code, move.json()) == (404, _error("Target group not found"))
    move = scoped.post("/api/hosts/move", json={"host_ids": [tree["ha1"]], "target_group_id": tree["a"]})
    assert move.status_code == 403
    move = scoped.post("/api/hosts/move", json={"host_ids": [tree["ha"]], "target_group_id": tree["a1"]})
    assert move.status_code == 403
    move = scoped.post("/api/hosts/move", json={"host_ids": [tree["ha1"]], "target_group_id": tree["a11"]})
    assert move.status_code == 200, move.text
    edit = scoped.put(
        f"/api/hosts/{tree['ha1']}", json={"hostname": "edge-a1", "ip_address": "192.0.2.11", "group_id": tree["b"]}
    )
    assert edit.status_code == 404


def test_bulk_operations_check_every_id(admin, tree):
    scoped = _scoped(admin, "bulk", [{"inventory_group_id": tree["a1"], "can_write": True}])
    resp = scoped.post("/api/hosts/bulk-delete", json={"host_ids": [tree["ha1"], tree["hb"]]})
    assert resp.status_code == 404
    assert admin.get(f"/api/hosts/{tree['ha1']}/custom-data").status_code == 200  # nothing deleted

    tag = admin.post("/api/tags", json={"name": "core"}).json()
    resp = scoped.post("/api/hosts/bulk-tags", json={"host_ids": [tree["ha1"], tree["ha"]], "add_tag_ids": [tag["id"]]})
    assert resp.status_code == 404
    resp = scoped.post("/api/hosts/bulk-tags", json={"host_ids": [tree["ha1"], tree["ha11"]], "add_tag_ids": [tag["id"]]})
    assert resp.status_code == 200, resp.text

    role = admin.post("/api/dcim/roles", json={"name": "access"})
    assert role.status_code == 201, role.text
    body = {"values": {"role_id": role.json()["id"]}}
    resp = scoped.post("/api/hosts/bulk-edit", json={**body, "host_ids": [tree["ha1"], tree["hb"]]})
    assert resp.status_code == 404
    resp = scoped.post("/api/hosts/bulk-edit", json={**body, "host_ids": [tree["ha1"]]})
    assert resp.status_code == 200, resp.text

    grouped = scoped.post(
        "/api/inventory/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "n1", "ip_address": "192.0.2.61", "group_id": tree["a1"]},
                {"hostname": "n2", "ip_address": "192.0.2.62", "group_id": tree["b"]},
                {"hostname": "n3", "ip_address": "192.0.2.63", "group_path": ["new-site"]},
                {"hostname": "dup", "ip_address": "198.51.100.20", "group_id": tree["a1"]},
            ]
        },
    )
    assert grouped.status_code == 200, grouped.text
    result = grouped.json()
    assert [h["hostname"] for h in result["added"]] == ["n1"]
    assert {e["hostname"]: e["error"] for e in result["errors"]} == {
        "n2": "Group not found",
        "n3": "Only accounts with access to all devices can place a group at the top level",
    }
    # The existing host of a hidden group is not named.
    assert result["skipped"][0]["host_id"] is None
    assert result["skipped"][0]["group_id"] is None
    assert scoped.post(f"/api/inventory/{tree['b']}/hosts/bulk", json={"hosts": []}).status_code == 404


def test_snmp_assignments_and_discovery_job_are_scoped(admin, tree, monkeypatch):
    from netcontrol.routes import background_jobs

    monkeypatch.setitem(state.SNMP_PROFILES, "p1", {"id": "p1", "name": "lab"})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {tree["a1"]: "p1", tree["b"]: "p1"})
    scoped = _scoped(admin, "snmp", [{"inventory_group_id": tree["a1"]}])
    listed = scoped.get("/api/inventory/snmp-profile-assignments").json()["assignments"]
    assert [a["group_id"] for a in listed] == [tree["a1"]]
    assert scoped.put(f"/api/inventory/{tree['a1']}/snmp-profile-assignment", json={}).status_code == 403
    assert scoped.put(f"/api/inventory/{tree['a1']}/snmp-discovery-profile", json={}).status_code == 403

    hidden = background_jobs.create_job("discovery-scan", {"group_id": tree["b"]})
    mine = background_jobs.create_job("discovery-scan", {"group_id": tree["a1"]})
    assert scoped.get(f"/api/inventory/discovery/jobs/{hidden['job_id']}").status_code == 404
    assert scoped.get(f"/api/inventory/discovery/jobs/{mine['job_id']}").status_code == 200
    assert admin.get(f"/api/inventory/discovery/jobs/{hidden['job_id']}").status_code == 200


# ── Completeness and the out-of-scope GET sweep ──────────────────────────────


def _feature_keys(dependency) -> set[str]:
    """The feature keys a require_feature / require_feature_method gate checks."""
    keys = set()
    for cell in getattr(dependency, "__closure__", None) or ():
        if isinstance(cell.cell_contents, str):
            keys.add(cell.cell_contents)
    return keys


def _included_routers():
    for route in app_module.app.routes:
        if isinstance(route, _IncludedRouter):
            yield route.original_router, [d.dependency for d in route.include_context.dependencies]


def test_every_route_of_an_enforced_feature_is_marked():
    enforced = object_scope.enforced_routers()
    enforced_ids = {id(r) for r in enforced}
    for router, deps in _included_routers():
        names = [getattr(d, "__qualname__", "") for d in deps]
        if any("require_admin" in n for n in names):
            continue  # admins are unrestricted
        gated = set()
        for dep, name in zip(deps, names):
            if "require_feature" in name:
                gated |= _feature_keys(dep)
        if gated & object_scope.SCOPE_ENFORCED_FEATURES:
            assert id(router) in enforced_ids, f"router with {sorted(gated)} is not in SCOPE_ENFORCED_ROUTERS"
    # HTTP and WebSocket routes alike (WebSocket handlers check scope themselves).
    unmarked = [
        f"{sorted(getattr(r, 'methods', None) or ['WS'])} {r.path}"
        for router in enforced
        for r in router.routes
        if isinstance(r, (APIRoute, APIWebSocketRoute)) and object_scope.scope_marker(r.endpoint) is None
    ]
    assert unmarked == [], "routes without @scoped or @scope_exempt"
    websockets = [r for router in enforced for r in router.routes if isinstance(r, APIWebSocketRoute)]
    assert {r.path for r in websockets} >= {"/ws/config-capture/{job_id}", "/ws/config-revert/{job_id}"}


def test_every_websocket_of_an_enforced_feature_is_enforced():
    """WebSocket routers are registered without HTTP dependencies, so the
    feature walk above cannot see them: every WebSocket route of a module
    that owns an enforced router must itself be in an enforced router."""
    enforced = object_scope.enforced_routers()
    enforced_ids = {id(r) for r in enforced}
    modules = {getattr(r.routes[0].endpoint, "__module__", "") for r in enforced if r.routes}
    for router, _deps in _included_routers():
        sockets = [r for r in router.routes if isinstance(r, APIWebSocketRoute)]
        if any(getattr(r.endpoint, "__module__", "") in modules for r in sockets):
            assert id(router) in enforced_ids, [r.path for r in sockets]


def test_scoped_get_routes_answer_404_out_of_scope(admin, tree):
    features = sorted(object_scope.SCOPE_ENFORCED_FEATURES)
    scoped = _scoped(admin, "sweeper", [{"inventory_group_id": tree["a1"], "can_write": True}], features)
    # An intended configuration for the in-scope host and the hidden one.
    template = {"name": "sweep", "kind": "device", "template_text": "hostname {{ host.name }}\n"}
    assert admin.post("/api/intended-config/templates", json=template).status_code == 201
    generated = admin.post("/api/intended-config/generate", json={"host_ids": [tree["ha1"], tree["hb"]]})
    assert generated.json()["generated"] == 2, generated.text
    driven = []
    for router in object_scope.enforced_routers():
        for route in router.routes:
            marker = object_scope.scope_marker(route.endpoint)
            if not isinstance(route, APIRoute) or "GET" not in route.methods or not marker or marker[0] != "scoped":
                continue
            params = set(re.findall(r"{(\w+)}", route.path))
            if not params & {"group_id", "host_id"}:
                continue
            url = route.path.replace("{group_id}", str(tree["b"])).replace("{host_id}", str(tree["hb"]))
            resp = scoped.get(url)
            assert resp.status_code == 404, (url, resp.status_code, resp.text)
            ok = route.path.replace("{group_id}", str(tree["a1"])).replace("{host_id}", str(tree["ha1"]))
            assert scoped.get(ok).status_code == 200, ok
            driven.append(route.path)
    assert len(driven) >= 6
    assert {"/api/intended-config/hosts/{host_id}", "/api/intended-config/hosts/{host_id}/variables"} <= set(driven)
