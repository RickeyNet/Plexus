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


# ── DCIM and virtualization ──────────────────────────────────────────────────
#
# A writable grant reaches its hosts and their tenants; a site is reached read
# only. So a record is writable through its tenant or host, never its site.

DCIM = "/api/dcim"
VIRT = "/api/virtualization"


def _made(client: CsrfClient, url: str, body: dict) -> dict:
    resp = client.post(url, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _listed(client: CsrfClient, url: str, key: str = "") -> set[int]:
    resp = client.get(url)
    assert resp.status_code == 200, resp.text
    return {int(r["id"]) for r in _rows(resp.json(), key)}


def test_dcim_racks_power_and_host_records(admin, estate, writer, reader):
    e = estate
    role = _made(admin, f"{DCIM}/rack-roles", {"name": "Network"})["id"]
    rack = {
        key: _made(admin, f"{DCIM}/racks", body)["id"]
        for key, body in {
            "east": {"site_id": e["sA"], "name": "A01", "tenant_id": e["tA"], "role_id": role},
            "west": {"site_id": e["sB"], "name": "B01", "tenant_id": e["tB"], "role_id": role},
            # In the west site for the east tenant: reached through the tenant only.
            "lent": {"site_id": e["sB"], "name": "B02", "tenant_id": e["tA"]},
        }.items()
    }
    panel = {
        key: _made(admin, f"{DCIM}/power-panels", {"site_id": e[site], "name": f"MDB-{key}"})["id"]
        for key, site in (("east", "sA"), ("west", "sB"))
    }
    feed = {
        key: _made(admin, f"{DCIM}/power-feeds", {"power_panel_id": panel[key], "rack_id": rack[key], "name": "A"})[
            "id"
        ]
        for key in ("east", "west")
    }
    rear = {
        key: _made(admin, f"{DCIM}/rear-ports", {"host_id": e[host], "name": "R1"})["id"]
        for key, host in (("east", "hA"), ("west", "hB"))
    }
    reservations = f"{DCIM}/rack-reservations"
    hidden = {"rack_id": rack["lent"], "units": [5], "user": "west-ops", "description": "west growth"}
    own = {"rack_id": rack["lent"], "units": [6], "tenant_id": e["tA"], "description": "east growth"}
    res = {"hidden": _made(admin, reservations, hidden)["id"], "own": _made(admin, reservations, own)["id"]}
    spare = _made(admin, f"/api/inventory/{e['B']}/hosts", {"hostname": "spare-west", "ip_address": "198.51.100.11"})
    for host, body in (
        (e["hA"], {"rack_id": rack["east"], "rack_position": 1}),
        (e["hB"], {"rack_id": rack["lent"], "rack_position": 1}),
        (int(spare["id"]), {"rack_id": rack["lent"]}),  # in the rack, not mounted
    ):
        assert admin.put(f"{DCIM}/hosts/{host}/placement", json=body).status_code == 200, body
    _made(admin, f"{DCIM}/power-ports", {"host_id": e["hB"], "name": "PSU1", "maximum_draw": 500})

    # Lists keep the caller's records; a hidden one answers like an unknown id.
    assert _listed(writer, f"{DCIM}/racks") == {rack["east"], rack["lent"]}
    assert writer.get(f"{DCIM}/racks/{rack['west']}").status_code == 404
    assert writer.get(f"{DCIM}/racks/{rack['east']}").json()["name"] == "A01"
    assert _listed(writer, f"{DCIM}/power-panels") == {panel["east"]}
    assert _listed(writer, f"{DCIM}/power-feeds") == {feed["east"]}
    assert _listed(writer, f"{DCIM}/rear-ports") == {rear["east"]}
    assert _listed(writer, reservations) == {res["own"]}
    # A shared rack role counts the caller's racks only.
    assert [r["rack_count"] for r in writer.get(f"{DCIM}/rack-roles").json()] == [1]
    assert [r["rack_count"] for r in admin.get(f"{DCIM}/rack-roles").json()] == [2]

    # A new record must be writable: by its tenant or host, not by its site alone.
    new_rack = {"site_id": e["sA"], "name": "A02"}
    assert writer.post(f"{DCIM}/racks", json=new_rack).status_code == 403
    assert writer.post(f"{DCIM}/racks", json={**new_rack, "tenant_id": e["tB"]}).status_code == 403
    assert reader.post(f"{DCIM}/racks", json={**new_rack, "tenant_id": e["tA"]}).status_code == 403
    assert writer.post(f"{DCIM}/racks", json={**new_rack, "tenant_id": e["tA"]}).status_code == 201
    assert writer.post(f"{DCIM}/rack-roles", json={"name": "Storage"}).status_code == 403
    assert writer.post(f"{DCIM}/power-panels", json={"site_id": e["sA"], "name": "MDB-2"}).status_code == 403
    new_feed = {"power_panel_id": panel["east"], "name": "B"}
    assert writer.post(f"{DCIM}/power-feeds", json=new_feed).status_code == 403
    assert writer.post(f"{DCIM}/rear-ports", json={"host_id": e["hB"], "name": "R9"}).status_code == 403
    assert writer.post(f"{DCIM}/rear-ports", json={"host_id": e["hA"], "name": "R2"}).status_code == 201
    # A reference to a record the caller may not read answers like an unknown id.
    for path, body, field_name in (
        ("power-feeds", {**new_feed, "power_panel_id": panel["west"]}, "power_panel_id"),
        ("rack-reservations", {"rack_id": rack["west"], "units": [9], "tenant_id": e["tA"]}, "rack_id"),
        ("front-ports", {"host_id": e["hA"], "name": "F1", "rear_port_id": rear["west"]}, "rear_port_id"),
    ):
        refused = writer.post(f"{DCIM}/{path}", json=body)
        assert refused.status_code == 422 and f"Unknown id: {field_name}" in refused.text, path
    _made(writer, reservations, {"rack_id": rack["east"], "units": [9], "tenant_id": e["tA"]})

    # An edit needs a writable record that stays writable under its new keys.
    east = f"{DCIM}/racks/{rack['east']}"
    assert reader.put(east, json={"comments": "checked"}).status_code == 403
    assert writer.put(east, json={"comments": "checked"}).json()["comments"] == "checked"
    assert writer.put(east, json={"tenant_id": e["tB"]}).status_code == 403
    assert writer.delete(f"{DCIM}/racks/{rack['west']}").status_code == 404
    assert reader.delete(east).status_code == 403

    # Elevation: other devices are anonymous occupied units, other reservations lose their text.
    lent = writer.get(f"{DCIM}/racks/{rack['lent']}/elevation").json()
    blocks = lent["faces"]["front"]
    assert [(b["host_id"], b["name"]) for b in blocks if b["kind"] == "device"] == [(None, "")]
    shown = {b["reservation_id"]: (b["description"], b["user"]) for b in blocks if b["kind"] == "reservation"}
    assert shown == {None: ("", ""), res["own"]: ("east growth", "")}
    assert [r["id"] for r in lent["reservations"]] == [res["own"]] and lent["unmounted"] == []
    full = admin.get(f"{DCIM}/racks/{rack['lent']}/elevation").json()
    assert e["hB"] in {b.get("host_id") for b in full["faces"]["front"]}
    assert len(full["unmounted"]) == 1 and len(full["reservations"]) == 2
    mine = writer.get(f"{DCIM}/racks/{rack['east']}/elevation").json()
    assert e["hA"] in {b.get("host_id") for b in mine["faces"]["front"]}
    assert writer.get(f"{DCIM}/racks/{rack['west']}/elevation").status_code == 404
    # Rack power: the ports of readable devices only.
    assert writer.get(f"{DCIM}/racks/{rack['lent']}/power").json()["ports"] == []
    assert len(admin.get(f"{DCIM}/racks/{rack['lent']}/power").json()["ports"]) == 1
    assert writer.get(f"{DCIM}/racks/{rack['west']}/power").status_code == 404

    # Placement: a writable host, into a rack the caller may read.
    place = f"{DCIM}/hosts/{e['hA']}/placement"
    assert writer.put(place, json={"rack_id": rack["west"], "rack_position": 3}).status_code == 422
    assert reader.put(place, json={"rack_position": 2}).status_code == 403
    assert writer.put(place, json={"rack_position": 2}).json()["rack_position"] == 2
    assert writer.put(f"{DCIM}/hosts/{e['hB']}/placement", json={"rack_id": None}).status_code == 404


def test_dcim_cables_and_traces_stop_at_the_scope(admin, estate, writer, reader):
    e = estate
    cables = f"{DCIM}/cables"

    def interface(host: str, name: str) -> dict:
        return {"type": "interface", "host_id": e[host], "name": name}

    def cable(a: dict, b: dict) -> int:
        return int(_made(admin, cables, {"a": a, "b": b})["id"])

    def trace(client: CsrfClient, **params):
        return client.get(f"{DCIM}/trace", params=params)

    feed = {}
    for key, site in (("east", "sA"), ("west", "sB")):
        panel = _made(admin, f"{DCIM}/power-panels", {"site_id": e[site], "name": f"MDB-{key}"})["id"]
        feed[key] = _made(admin, f"{DCIM}/power-feeds", {"power_panel_id": panel, "name": "A"})["id"]
    psu1, psu2 = (
        {"type": "power_port", "id": _made(admin, f"{DCIM}/power-ports", {"host_id": e["hA"], "name": name})["id"]}
        for name in ("PSU1", "PSU2")
    )
    provider = _made(admin, "/api/circuits/providers", {"name": "carrier-1"})["id"]
    ctype = _made(admin, "/api/circuits/circuit-types", {"name": "internet"})["id"]
    circuit = _made(
        admin,
        "/api/circuits/circuits",
        {
            "cid": "C-WEST",
            "provider_id": provider,
            "circuit_type_id": ctype,
            "tenant_id": e["tB"],
            "terminations": [{"term_side": "A", "site_id": e["sB"]}],
        },
    )
    termination = {"type": "circuit_termination", "id": circuit["terminations"][0]["id"]}

    local = cable(interface("hA", "Gi1"), interface("hA", "Gi2"))
    cross = cable(interface("hA", "Gi3"), interface("hB", "Gi3"))
    far = cable(interface("hB", "Gi4"), interface("hB", "Gi5"))
    fed = cable(psu1, {"type": "power_feed", "id": feed["east"]})
    uplink = cable(interface("hA", "Gi6"), termination)

    # A cable is the caller's when one of its ends is; the scope keys stay internal.
    assert _listed(writer, cables) == {local, cross, fed, uplink}
    assert far in _listed(admin, cables)
    assert writer.get(f"{cables}/{far}").status_code == 404
    shown = writer.get(f"{cables}/{local}").json()
    assert shown["id"] == local and "scope_host_ids" not in shown and "scope_site_ids" not in shown

    # A new end the caller may not see answers like an unknown endpoint.
    hidden_host = writer.post(cables, json={"a": interface("hA", "Gi7"), "b": interface("hB", "Gi7")})
    assert hidden_host.status_code == 422 and "Unknown endpoint on side B" in hidden_host.text
    hidden_feed = writer.post(cables, json={"a": psu2, "b": {"type": "power_feed", "id": feed["west"]}})
    assert hidden_feed.status_code == 422 and "Unknown endpoint on side B" in hidden_feed.text
    own = {"a": interface("hA", "Gi8"), "b": interface("hA", "Gi9")}
    assert reader.post(cables, json=own).status_code == 403
    assert writer.post(cables, json=own).status_code == 201
    assert reader.put(f"{cables}/{local}", json={"label": "L-1"}).status_code == 403
    assert writer.put(f"{cables}/{local}", json={"label": "L-1"}).json()["label"] == "L-1"
    moved = writer.put(f"{cables}/{local}", json={"b": interface("hB", "Gi9")})
    assert moved.status_code == 422 and "Unknown endpoint on side B" in moved.text
    assert writer.delete(f"{cables}/{far}").status_code == 404
    assert reader.delete(f"{cables}/{local}").status_code == 403

    # A trace ends ``restricted`` before the first endpoint the caller may not see.
    assert trace(writer, type="interface", host_id=e["hA"], name="Gi1").json()["status"] == "complete"
    powered = trace(writer, type="power_port", id=psu1["id"]).json()
    assert powered["status"] == "complete" and powered["destination"]["type"] == "power_feed"
    for name in ("Gi3", "Gi6"):
        cut = trace(writer, type="interface", host_id=e["hA"], name=name).json()
        assert (cut["status"], cut["steps"], cut["destination"]) == ("restricted", [], None), name
        assert trace(admin, type="interface", host_id=e["hA"], name=name).json()["status"] == "complete", name
    assert trace(writer, type="interface", host_id=e["hB"], name="Gi4").status_code == 404
    assert writer.delete(f"{cables}/{local}").status_code == 200


def test_virtualization_clusters_and_virtual_machines(admin, estate, writer, reader):
    e = estate
    clusters, machines = f"{VIRT}/clusters", f"{VIRT}/virtual-machines"
    ctype = _made(admin, f"{VIRT}/cluster-types", {"name": "kvm"})["id"]

    def cluster(name: str, **extra) -> int:
        return int(_made(admin, clusters, {"name": name, "cluster_type_id": ctype, **extra})["id"])

    def machine(cluster_id: int, name: str, **extra) -> int:
        return int(_made(admin, machines, {"name": name, "cluster_id": cluster_id, **extra})["id"])

    east = cluster("cl-east", tenant_id=e["tA"], site_id=e["sA"])
    west = cluster("cl-west", tenant_id=e["tB"], site_id=e["sB"])
    hosted = cluster("cl-hosted")  # no tenant or site: reached through its member host
    for host in ("hA", "hB"):
        _made(admin, f"{clusters}/{hosted}/hosts", {"host_id": e[host]})
    vm_east = machine(east, "web-east", tenant_id=e["tA"])
    vm_west = machine(west, "web-west")
    vm_lent = machine(west, "db-east", tenant_id=e["tA"])  # in a hidden cluster, for the east tenant

    # Lists and details keep the caller's clusters, hosts and VMs, and count only those.
    listed = {c["id"]: c for c in writer.get(clusters).json()["clusters"]}
    assert set(listed) == {east, hosted} and listed[hosted]["host_count"] == 1
    assert [t["cluster_count"] for t in writer.get(f"{VIRT}/cluster-types").json()["cluster_types"]] == [2]
    assert [t["cluster_count"] for t in admin.get(f"{VIRT}/cluster-types").json()["cluster_types"]] == [3]
    assert writer.get(f"{clusters}/{west}").status_code == 404
    detail = writer.get(f"{clusters}/{hosted}").json()
    assert [h["id"] for h in detail["hosts"]] == [e["hA"]] and detail["host_count"] == 1 and detail["vm_count"] == 0
    assert [v["id"] for v in writer.get(f"{clusters}/{east}").json()["virtual_machines"]] == [vm_east]
    assert _listed(writer, machines, "virtual_machines") == {vm_east, vm_lent}
    assert _listed(admin, machines, "virtual_machines") == {vm_east, vm_west, vm_lent}
    assert writer.get(f"{machines}/{vm_west}").status_code == 404
    assert writer.get(f"{machines}/{vm_lent}").json()["name"] == "db-east"
    assert writer.get(f"{VIRT}/tenants").json()["tenants"] == [{"id": e["tA"], "name": "east-co"}]
    assert writer.get(f"{VIRT}/hosts/{e['hB']}/clusters").status_code == 404
    assert [c["id"] for c in writer.get(f"{VIRT}/hosts/{e['hA']}/clusters").json()["clusters"]] == [hosted]

    # A new VM must be writable: by its tenant or a member host of its cluster.
    new_vm = {"name": "app-01", "cluster_id": west}
    assert writer.post(machines, json=new_vm).status_code == 403
    assert writer.post(machines, json={**new_vm, "cluster_id": east}).status_code == 403
    assert reader.post(machines, json={**new_vm, "cluster_id": hosted}).status_code == 403
    assert writer.post(machines, json={**new_vm, "cluster_id": hosted}).status_code == 201
    assert writer.put(f"{machines}/{vm_east}", json={"tenant_id": e["tB"]}).status_code == 403
    assert writer.put(f"{machines}/{vm_east}", json={"description": "front end"}).status_code == 200
    assert reader.delete(f"{machines}/{vm_east}").status_code == 403

    # Clusters: the same rule, and member hosts only from the caller's own.
    new_cluster = {"name": "cl-new", "cluster_type_id": ctype, "site_id": e["sA"]}
    assert writer.post(clusters, json=new_cluster).status_code == 403
    assert writer.post(clusters, json={**new_cluster, "tenant_id": e["tA"]}).status_code == 201
    assert writer.put(f"{clusters}/{east}", json={"tenant_id": e["tB"]}).status_code == 403
    assert writer.put(f"{clusters}/{east}", json={"description": "east hall"}).status_code == 200
    assert reader.put(f"{clusters}/{east}", json={"description": "x"}).status_code == 403
    assert writer.post(f"{clusters}/{east}/hosts", json={"host_id": e["hB"]}).status_code == 422
    assert writer.post(f"{clusters}/{east}/hosts", json={"host_id": e["hA"]}).status_code == 201
    assert writer.delete(f"{clusters}/{hosted}/hosts/{e['hB']}").status_code == 404
    assert writer.delete(f"{clusters}/{hosted}/hosts/{e['hA']}").status_code == 200
    assert writer.get(f"{clusters}/{hosted}").status_code == 404  # no member host of theirs is left
