"""Object scopes on every feature: the model registry and its row helpers
(``netcontrol.object_scope``), the per-model scope rules (migration 0111,
``routes.db.object_scope`` and the admin API), and an authorization matrix
that walks the enrolled features with scoped users (read and read-write
grants, in-scope and out-of-scope objects, list / detail / write).

Every name and address here is invented (documentation ranges only)."""

from __future__ import annotations

import importlib

import netcontrol.app as app_module
import pytest
import routes.database as db
import routes.db.object_scope as scope_db
from fastapi import HTTPException
from netcontrol import object_scope
from netcontrol.object_scope import ObjectScope, ScopeRule
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client

_migration = importlib.import_module("routes.migrations.0111_saml_and_scope_rules")


# ── Data ─────────────────────────────────────────────────────────────────────


async def _world() -> dict[str, int]:
    """Two customers: east (group a, tenant ta, site sa) and west (group b,
    tenant tb, site sb). Host ha (tenant ta) is placed on a floor of sa; hb
    (tenant tb) on a floor of sb."""
    w: dict[str, int] = {}
    w["a"] = await db.create_group("east")
    w["b"] = await db.create_group("west")
    w["ta"] = (await db.create_tenant(name="east-co"))["id"]
    w["tb"] = (await db.create_tenant(name="west-co"))["id"]
    w["sa"] = (await db.create_geo_site("east-site"))["id"]
    w["sb"] = (await db.create_geo_site("west-site"))["id"]
    w["ha"] = await db.add_host(w["a"], "edge-east", "192.0.2.10")
    w["hb"] = await db.add_host(w["b"], "edge-west", "198.51.100.10")
    conn = await db.get_db()
    try:
        await conn.execute("UPDATE hosts SET tenant_id = ? WHERE id = ?", (w["ta"], w["ha"]))
        await conn.execute("UPDATE hosts SET tenant_id = ? WHERE id = ?", (w["tb"], w["hb"]))
        await conn.commit()
    finally:
        await conn.close()
    for site, host in (("sa", "ha"), ("sb", "hb")):
        floor = await db.create_geo_floor(w[site], "floor-1")
        await db.upsert_geo_placement(floor["id"], w[host], 0.5, 0.5)
    return w


def _scope(w, *, read=("a",), write=(), rules=()) -> ObjectScope:
    return ObjectScope(
        unrestricted=False,
        read_groups=frozenset(w[g] for g in read) | frozenset(w[g] for g in write),
        write_groups=frozenset(w[g] for g in write),
        rules=tuple(rules),
    )


# ── Registry and row helpers ─────────────────────────────────────────────────


async def test_migration_is_idempotent():
    conn = await db.get_db()
    try:
        await _migration.up(conn)
        await _migration.up(conn)
    finally:
        await conn.close()


async def test_reach_follows_hosts_tenants_and_sites():
    w = await _world()
    reach = await _scope(w, write=("a",)).reach()
    assert reach.read_hosts == {w["ha"]} and reach.write_hosts == {w["ha"]}
    assert reach.read_tenants == {w["ta"]} and reach.write_tenants == {w["ta"]}
    assert reach.read_sites == {w["sa"]}
    # Read-only grant: nothing writable.
    reader = await _scope(w).reach()
    assert reader.read_hosts == {w["ha"]} and reader.write_hosts == frozenset()
    assert await object_scope.UNRESTRICTED.reach() == object_scope.ScopeReach()


async def test_rows_by_host_tenant_site_and_shared():
    w = await _world()
    scope = _scope(w, write=("a",))
    rows = [{"id": 1, "host_id": w["ha"]}, {"id": 2, "host_id": w["hb"]}, {"id": 3, "host_id": None}]
    assert [r["id"] for r in await object_scope.filter_rows("host_record", rows, scope)] == [1]
    prefixes = [{"id": 1, "tenant_id": w["ta"]}, {"id": 2, "tenant_id": w["tb"]}, {"id": 3, "tenant_id": None}]
    assert [r["id"] for r in await object_scope.filter_rows("ipam_prefix", prefixes, scope)] == [1]
    # VRFs are shared: an untenanted VRF is read by everyone, changed by no scoped user.
    vrfs = [{"id": 1, "tenant_id": None}, {"id": 2, "tenant_id": w["tb"]}]
    assert [r["id"] for r in await object_scope.filter_rows("vrf", vrfs, scope)] == [1]
    assert not await object_scope.can_access(scope, "vrf", vrfs[0], write=True)
    # A site reached through a host is readable, not writable.
    racks = [{"id": 1, "site_id": w["sa"], "tenant_id": None}, {"id": 2, "site_id": w["sb"], "tenant_id": None}]
    assert [r["id"] for r in await object_scope.filter_rows("rack", racks, scope)] == [1]
    assert not await object_scope.can_access(scope, "rack", racks[0], write=True)
    # The tenant of a writable host is writable.
    assert await object_scope.can_access(scope, "rack", {"site_id": w["sb"], "tenant_id": w["ta"]}, write=True)
    # List keys (derived fields): any id counts.
    circuit = {"tenant_id": None, "scope_site_ids": [w["sb"], w["sa"]], "scope_host_ids": []}
    assert await object_scope.can_access(scope, "circuit", circuit)
    # Unrestricted: everything, as given.
    assert await object_scope.filter_rows("host_record", rows, object_scope.UNRESTRICTED) == rows


async def test_scope_rules_add_tenants_and_sites_per_model():
    w = await _world()
    rules = (
        ScopeRule("rack", "site", w["sb"], can_write=True),
        ScopeRule("*", "tenant", w["tb"], can_write=False),
    )
    scope = _scope(w, rules=rules)
    rack_b = {"site_id": w["sb"], "tenant_id": None}
    assert await object_scope.can_access(scope, "rack", rack_b, write=True)
    # The site rule is for racks only.
    assert not await object_scope.can_access(scope, "power_panel", {"site_id": w["sb"]})
    # The tenant rule is for every model, read only.
    assert await object_scope.can_access(scope, "circuit", {"tenant_id": w["tb"]})
    assert not await object_scope.can_access(scope, "circuit", {"tenant_id": w["tb"]}, write=True)
    assert not scope.read_only


async def test_require_helpers_and_sql_condition():
    w = await _world()
    scope = _scope(w)
    row = {"id": 5, "tenant_id": w["ta"]}
    assert await object_scope.require_row(scope, "ipam_prefix", row) is row
    for target, write, status in ((row, True, 403), ({"tenant_id": w["tb"]}, False, 404), (None, False, 404)):
        with pytest.raises(HTTPException) as exc:
            await object_scope.require_row(scope, "ipam_prefix", target, write=write, not_found="Prefix not found")
        assert exc.value.status_code == status
    with pytest.raises(HTTPException) as exc:
        await object_scope.require_new_row(scope, "ipam_prefix", {"tenant_id": None})
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException):
        await object_scope.require_model_write(scope)
    await object_scope.require_model_write(object_scope.UNRESTRICTED)
    with pytest.raises(HTTPException) as exc:
        await object_scope.require_host_ids(scope, [w["ha"], w["hb"]])
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        await object_scope.require_host_ids(scope, [w["ha"]], write=True)
    assert exc.value.status_code == 403
    assert await object_scope.readable_host_ids(scope) == {w["ha"]}
    assert await object_scope.readable_host_ids(object_scope.UNRESTRICTED) is None

    sql, params = await object_scope.sql_condition("vlan", scope, alias="v")
    assert sql == "(v.tenant_id IN (?) OR v.site_id IN (?) OR (v.tenant_id IS NULL AND v.site_id IS NULL))"
    assert params == (w["ta"], w["sa"])
    assert await object_scope.sql_condition("vlan", object_scope.UNRESTRICTED) == ("", ())
    assert await object_scope.sql_condition("ipam_prefix", object_scope.NO_ACCESS) == ("1 = 0", ())
    # The condition really selects the rows filter_rows keeps.
    conn = await db.get_db(read_only=True)
    try:
        sql, params = await object_scope.sql_condition("host", scope, alias="h")
        cursor = await conn.execute(f"SELECT h.id FROM hosts h WHERE {sql}", params)  # noqa: S608
        assert {int(r[0]) for r in await cursor.fetchall()} == {w["ha"]}
    finally:
        await conn.close()


def test_registry_rejects_unknown_attributes_and_lists_models():
    with pytest.raises(ValueError):
        object_scope.ScopeModel("bad", {"owner": "owner_id"})
    with pytest.raises(KeyError):
        object_scope.get_model("no-such-model")
    names = {m["name"] for m in object_scope.model_catalog()}
    assert {"host_record", "ipam_prefix", "circuit", "rack", "virtual_machine"} <= names


# ── Scope rules storage and admin API ────────────────────────────────────────


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _login(username: str) -> CsrfClient:
    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


def _scoped_user(admin: CsrfClient, name: str, grants: list[dict], features: list[str], rules=None) -> CsrfClient:
    body = {"name": f"{name} access", "feature_keys": features, "object_scope": "groups", "inventory_scopes": grants}
    group = admin.post("/api/admin/access-groups", json=body)
    assert group.status_code == 201, group.text
    if rules is not None:
        saved = admin.put(f"/api/admin/access-groups/{group.json()['id']}/scope-rules", json={"rules": rules})
        assert saved.status_code == 200, saved.text
    resp = admin.post(
        "/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group.json()["id"]]}
    )
    assert resp.status_code == 201, resp.text
    return _login(name)


async def test_rule_storage_round_trip_and_validation():
    w = await _world()
    gid = await db.create_access_group("rules", "", ["circuits"], object_scope="groups", inventory_scopes=[])
    saved = await scope_db.set_access_group_scope_rules(
        gid,
        [
            {"model": "circuit", "attribute": "tenant", "value_id": w["tb"], "can_write": False},
            {"model": "circuit", "attribute": "tenant", "value_id": w["tb"], "can_write": True},
            {"model": "*", "attribute": "site", "value_id": w["sa"]},
        ],
    )
    assert saved == [
        {"model": "*", "attribute": "site", "value_id": w["sa"], "can_write": False},
        {"model": "circuit", "attribute": "tenant", "value_id": w["tb"], "can_write": True},
    ]
    with pytest.raises(ValueError):
        await scope_db.set_access_group_scope_rules(gid, [{"model": "*", "attribute": "tenant", "value_id": 999999}])
    with pytest.raises(ValueError):
        await scope_db.set_access_group_scope_rules(gid, [{"model": "*", "attribute": "owner", "value_id": 1}])
    assert len(await scope_db.get_access_group_scope_rules(gid)) == 2  # unchanged
    uid = await db.create_user("ruled", "hash", "salt")
    await db.set_user_groups(uid, [gid])
    assert len(await scope_db.get_user_scope_rules(uid)) == 2
    scope = await object_scope.scope_for_user({"id": uid, "role": "user"})
    assert {r.model for r in scope.rules} == {"*", "circuit"}
    await db.delete_access_group(gid)
    assert await scope_db.get_access_group_scope_rules(gid) == []


def test_admin_scope_rule_api(admin):
    tenant = admin.post("/api/organization/tenants", json={"name": "north-co"})
    assert tenant.status_code == 201, tenant.text
    tid = tenant.json()["id"]
    group = admin.post("/api/admin/access-groups", json={"name": "north", "object_scope": "groups"}).json()
    url = f"/api/admin/access-groups/{group['id']}/scope-rules"
    assert admin.get(url).json() == []
    body = {"rules": [{"model": "circuit", "attribute": "tenant", "value_id": tid, "can_write": True}]}
    assert admin.put(url, json=body).json() == [body["rules"][0]]
    assert admin.get(url).json() == [body["rules"][0]]
    bad = [
        {"model": "no-such", "attribute": "tenant", "value_id": tid},
        {"model": "ipam_prefix", "attribute": "site", "value_id": tid},  # prefixes have no site
        {"model": "*", "attribute": "region", "value_id": tid},
        {"model": "*", "attribute": "tenant", "value_id": 999999},
    ]
    for rule in bad:
        assert admin.put(url, json={"rules": [rule]}).status_code == 400, rule
    assert admin.get("/api/admin/access-groups/999999/scope-rules").status_code == 404
    models = admin.get("/api/admin/object-scope/models").json()
    assert next(m for m in models if m["name"] == "circuit")["rule_attributes"] == ["tenant", "site"]
    events = admin.get("/api/admin/audit-events?limit=20").json()
    assert any(e["action"] == "access_group.scope_rules" for e in events)
    # Admin only.
    user = _scoped_user(admin, "rules-peek", [], ["inventory"])
    assert user.get(url).status_code == 403
    assert user.get("/api/auth/status").json()["object_scope"]["read_only"] is True


# ── Authorization matrix over the enrolled features ──────────────────────────

ALL_FEATURES = sorted(object_scope.SCOPE_ENFORCED_FEATURES)


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def _rows(body, key: str) -> list[dict]:
    return body if isinstance(body, list) else body.get(key, [])


@pytest.fixture
def estate(admin) -> dict[str, int]:
    """Groups A and B with one host each; tenants tA/tB on the hosts; sites
    sA/sB holding them (floor plan placement)."""
    e: dict[str, int] = {}
    for key, name in (("A", "east"), ("B", "west")):
        resp = admin.post("/api/inventory", json={"name": name})
        assert resp.status_code == 201, resp.text
        e[key] = int(resp.json()["id"])
    for key, group, name, ip in (("hA", "A", "edge-east", "192.0.2.10"), ("hB", "B", "edge-west", "198.51.100.10")):
        resp = admin.post(f"/api/inventory/{e[group]}/hosts", json={"hostname": name, "ip_address": ip})
        assert resp.status_code == 201, resp.text
        e[key] = int(resp.json()["id"])
    for key, name in (("tA", "east-co"), ("tB", "west-co")):
        resp = admin.post("/api/organization/tenants", json={"name": name})
        assert resp.status_code == 201, resp.text
        e[key] = int(resp.json()["id"])

    async def _seed() -> None:
        conn = await db.get_db()
        try:
            for host, tenant in (("hA", "tA"), ("hB", "tB")):
                await conn.execute("UPDATE hosts SET tenant_id = ? WHERE id = ?", (e[tenant], e[host]))
            await conn.commit()
        finally:
            await conn.close()
        for site, host, name in (("sA", "hA", "east-site"), ("sB", "hB", "west-site")):
            e[site] = (await db.create_geo_site(name))["id"]
            floor = await db.create_geo_floor(e[site], "floor-1")
            await db.upsert_geo_placement(floor["id"], e[host], 0.5, 0.5)

    _run(_seed())
    return e


@pytest.fixture
def writer(admin, estate) -> CsrfClient:
    """Read and write on group A."""
    return _scoped_user(admin, "east-writer", [{"inventory_group_id": estate["A"], "can_write": True}], ALL_FEATURES)


@pytest.fixture
def reader(admin, estate) -> CsrfClient:
    """Read only on group A."""
    return _scoped_user(admin, "east-reader", [{"inventory_group_id": estate["A"]}], ALL_FEATURES)


def test_scoped_users_keep_every_feature(writer, reader):
    status = writer.get("/api/auth/status").json()
    assert set(status["feature_access"]) == object_scope.SCOPE_ENFORCED_FEATURES
    assert status["object_scope"]["read_only"] is False
    assert reader.get("/api/auth/status").json()["object_scope"]["read_only"] is True


def test_monitoring_alerts_and_rules(admin, estate, writer, reader):
    alerts = {
        key: _run(db.create_monitoring_alert(estate[key], None, "threshold", "cpu", f"cpu high {key}"))
        for key in ("hA", "hB")
    }
    rows = _rows(writer.get("/api/monitoring/alerts").json(), "alerts")
    assert {r["host_id"] for r in rows} == {estate["hA"]}
    assert len(_rows(admin.get("/api/monitoring/alerts").json(), "alerts")) >= 2
    assert writer.post(f"/api/monitoring/alerts/{alerts['hB']}/acknowledge").status_code == 404
    assert reader.post(f"/api/monitoring/alerts/{alerts['hA']}/acknowledge").status_code == 403
    assert writer.post(f"/api/monitoring/alerts/{alerts['hA']}/acknowledge").status_code == 200
    # Per-host history: a hidden host answers like an unknown one.
    assert writer.get(f"/api/monitoring/polls/{estate['hB']}/history").status_code == 404
    assert writer.get(f"/api/monitoring/polls/{estate['hA']}/history").status_code == 200
    # Alert rules: a global rule is for unrestricted callers; a group rule needs write on the group.
    assert writer.post("/api/monitoring/rules", json={"name": "cpu", "metric": "cpu"}).status_code == 403
    rule = {"name": "cpu-east", "metric": "cpu", "group_id": estate["A"]}
    assert writer.post("/api/monitoring/rules", json=rule).status_code in (200, 201)
    assert reader.post("/api/monitoring/rules", json={**rule, "name": "cpu-east-2"}).status_code == 403
    assert writer.post("/api/monitoring/rules", json={**rule, "group_id": estate["B"]}).status_code == 403


def test_jobs_follow_their_targets(admin, estate, writer):
    playbook = _run(db.create_playbook("scope-pb", "scope_pb.py"))
    visible = _run(db.create_job(playbook, estate["A"], host_ids=[estate["hA"]], launched_by="east-writer"))
    hidden = _run(db.create_job(playbook, estate["B"], host_ids=[estate["hB"]], launched_by="east-writer"))
    mixed = _run(db.create_job(playbook, estate["A"], host_ids=[estate["hA"], estate["hB"]], launched_by="east-writer"))
    ids = {j["id"] for j in _rows(writer.get("/api/jobs").json(), "jobs")}
    assert visible in ids and hidden not in ids and mixed not in ids
    assert writer.get(f"/api/jobs/{hidden}").status_code == 404
    assert writer.get(f"/api/jobs/{visible}").status_code == 200
    assert {visible, hidden, mixed} <= {j["id"] for j in _rows(admin.get("/api/jobs").json(), "jobs")}


def test_shared_catalogues_are_read_only(writer):
    assert writer.get("/api/templates").status_code == 200
    assert writer.post("/api/templates", json={"name": "t", "content": "x"}).status_code == 403
    assert writer.get("/api/compliance/profiles").status_code == 200
    assert writer.post("/api/circuits/providers", json={"name": "carrier"}).status_code == 403
    assert writer.post("/api/virtualization/cluster-types", json={"name": "kvm"}).status_code == 403
    assert writer.get("/api/dcim/rack-roles").status_code == 200


def test_host_addressed_routes_hide_other_hosts(estate, writer):
    for url in (
        "/api/topology/host/{}",
        "/api/mac-tracking/host/{}",
        "/api/lifecycle/hosts/{}",
        "/api/dcim/hosts/{}",
        "/api/circuits/hosts/{}/circuits",
        "/api/hosts/{}/interface-addresses",
    ):
        assert writer.get(url.format(estate["hB"])).status_code == 404, url
        assert writer.get(url.format(estate["hA"])).status_code == 200, url
    assert writer.post("/api/mac-tracking/cleanup").status_code == 403


def test_organization_by_tenant_and_site(estate, writer):
    assert writer.get(f"/api/organization/tenants/{estate['tB']}").status_code == 404
    assert writer.get(f"/api/organization/tenants/{estate['tA']}").status_code == 200
    sites = _rows(writer.get("/api/organization/sites").json(), "sites")
    assert {s["id"] for s in sites} == {estate["sA"]}
    assert writer.get(f"/api/geo/sites/{estate['sA']}").status_code == 200
    assert writer.get(f"/api/geo/sites/{estate['sB']}").status_code == 404


def test_circuits_by_termination_tenant_and_scope_rule(admin, estate, writer):
    provider = admin.post("/api/circuits/providers", json={"name": "carrier-1"}).json()["id"]
    ctype = admin.post("/api/circuits/circuit-types", json={"name": "internet"}).json()["id"]

    def circuit(cid: str, **extra) -> int:
        body = {"cid": cid, "provider_id": provider, "circuit_type_id": ctype, **extra}
        resp = admin.post("/api/circuits/circuits", json=body)
        assert resp.status_code == 201, resp.text
        return int(resp.json()["id"])

    east = circuit("C-EAST", terminations=[{"term_side": "A", "site_id": estate["sA"], "host_id": estate["hA"]}])
    west = circuit("C-WEST", terminations=[{"term_side": "A", "site_id": estate["sB"], "host_id": estate["hB"]}])
    tenant_b = circuit("C-TB", tenant_id=estate["tB"])
    assert writer.get(f"/api/circuits/circuits/{east}").status_code == 200
    assert writer.get(f"/api/circuits/circuits/{west}").status_code == 404
    assert writer.get(f"/api/circuits/circuits/{tenant_b}").status_code == 404
    # A circuit with no tenant and no termination would belong to no scope.
    body = {"cid": "C-NEW", "provider_id": provider, "circuit_type_id": ctype}
    assert writer.post("/api/circuits/circuits", json=body).status_code == 403
    assert writer.post("/api/circuits/circuits", json={**body, "tenant_id": estate["tA"]}).status_code == 201

    # A read scope rule on tenant B for circuits shows that circuit, read only.
    ruled = _scoped_user(
        admin,
        "east-ruled",
        [{"inventory_group_id": estate["A"]}],
        ALL_FEATURES,
        rules=[{"model": "circuit", "attribute": "tenant", "value_id": estate["tB"], "can_write": False}],
    )
    assert ruled.get(f"/api/circuits/circuits/{tenant_b}").status_code == 200
    assert ruled.delete(f"/api/circuits/circuits/{tenant_b}").status_code == 403


def test_global_actions_are_refused(writer):
    assert writer.get("/api/sync/jobs").status_code == 200
    assert writer.get("/api/secrets-providers").status_code == 200
    assert writer.post("/api/software/refresh").status_code == 403
    assert writer.put("/api/lifecycle/settings", json={}).status_code in (403, 422)
    assert writer.post("/api/lifecycle/check").status_code == 403


def test_dashboard_counts_the_scope_only(admin, estate, writer):
    stats = writer.get("/api/dashboard").json()["stats"]
    assert stats["total_hosts"] == 1
    assert stats["total_groups"] == 1
    assert admin.get("/api/dashboard").json()["stats"]["total_hosts"] >= 2


def test_unrestricted_user_sees_everything(admin, estate):
    from mcp_helpers import user_client

    everyone = user_client(admin, "noc-all", features=ALL_FEATURES)
    for url in ("/api/topology/host/{}", "/api/lifecycle/hosts/{}", "/api/dcim/hosts/{}"):
        assert everyone.get(url.format(estate["hB"])).status_code == 200, url
    assert everyone.get(f"/api/organization/tenants/{estate['tB']}").status_code == 200
    assert everyone.get("/api/dashboard").json()["stats"]["total_hosts"] >= 2
