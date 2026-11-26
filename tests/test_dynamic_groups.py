"""Dynamic groups (saved host filters): filter validation, every criterion,
the RE2 refusal, object scope on members and preview, CRUD permissions, and
job targeting resolved when the job starts."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol import object_scope
from netcontrol.dynamic_groups import (
    DynamicGroupFilterError,
    resolve_hosts,
    scope_for_launcher,
    validate_filter,
)
from netcontrol.object_scope import NO_ACCESS, UNRESTRICTED, ObjectScope
from netcontrol.routes import state
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook

from mcp_helpers import CsrfClient, admin_client

API = "/api/dynamic-groups"


@register_playbook
class _DynamicGroupEcho(BasePlaybook):
    filename = "dynamic_group_echo_test.py"
    display_name = "Dynamic group echo (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message=f"hosts={len(hosts)}")


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


# ── Direct: validation and resolution ────────────────────────────────────────


async def _seed() -> dict:
    """site-a > floor-1, and site-b; hosts with platforms, statuses, a tag,
    a custom field and a role."""
    await db_module.init_db()
    t: dict = {}
    t["a"] = await db_module.create_group("dg-site-a")
    t["a1"] = await db_module.create_group("dg-floor-1", parent_id=t["a"])
    t["b"] = await db_module.create_group("dg-site-b")
    t["core"] = await db_module.add_host(t["a"], "core-sw1.example.com", "192.0.2.1", "cisco_xe")
    t["acc"] = await db_module.add_host(t["a1"], "access-sw1.example.com", "192.0.2.65", "cisco_ios")
    t["edge"] = await db_module.add_host(t["b"], "edge-fw1.example.com", "198.51.100.1", "fortinet")
    t["v6"] = await db_module.add_host(t["b"], "v6-rtr.example.com", "2001:db8::1", "juniper_junos")
    await db_module.update_host_status(t["edge"], "down")
    await db_module.update_host_status(t["core"], "up")
    tag = await db_module.create_tag(name="dg-pci")
    t["tag"] = int(tag["id"])
    field = await db_module.create_custom_field(
        key="dg_tier",
        label="Tier",
        field_type="select",
        choices=["gold", "silver"],
        object_types=["host"],
        required=False,
        default_value="",
        description="",
        sort_order=0,
        created_by="admin",
    )
    t["field"] = int(field["id"])
    t["tag2"] = int((await db_module.create_tag(name="dg-core"))["id"])
    await db_module.set_object_data("host", str(t["core"]), [t["tag"], t["tag2"]], {t["field"]: "gold"})
    await db_module.set_object_data("host", str(t["acc"]), [t["tag2"]], {})
    await db_module.set_object_data("host", str(t["edge"]), [t["tag"]], {t["field"]: "silver"})
    role = await db_module.create_device_role(name="dg-access")
    t["role"] = int(role["id"])
    await db_module.bulk_set_host_device_fields([t["acc"]], {"role_id": t["role"]})
    return t


def _ids(rows: list[dict]) -> set[int]:
    return {int(r["id"]) for r in rows}


async def _match(filter_raw: dict, scope: ObjectScope = UNRESTRICTED) -> set[int]:
    return _ids(await resolve_hosts(await validate_filter(filter_raw, scope), scope))


async def test_each_criterion_resolves():
    t = await _seed()
    assert await _match({"groups": [t["a"]]}) == {t["core"], t["acc"]}
    assert await _match({"groups": [t["a"]], "include_subgroups": False}) == {t["core"]}
    assert await _match({"platforms": ["CISCO_XE", "fortinet"]}) == {t["core"], t["edge"]}
    assert await _match({"statuses": ["down"]}) == {t["edge"]}
    assert await _match({"tag_ids": [t["tag"]]}) == {t["core"], t["edge"]}
    assert await _match({"tag_ids": [t["tag"], t["tag2"]]}) == {t["core"], t["edge"], t["acc"]}
    assert await _match({"tag_ids": [t["tag"], t["tag2"]], "tag_match": "all"}) == {t["core"]}
    assert await _match({"custom_fields": {"dg_tier": ["gold"]}}) == {t["core"]}
    assert await _match({"custom_fields": {"dg_tier": ["gold", "silver"]}}) == {t["core"], t["edge"]}
    assert await _match({"custom_fields": {"dg_tier": ["*"]}}) == {t["core"], t["edge"]}
    assert await _match({"role_id": [t["role"]]}) == {t["acc"]}
    assert t["acc"] not in await _match({"role_id": [None], "groups": [t["a"]]})
    assert await _match({"search": {"mode": "contains", "value": "ACCESS-"}}) == {t["acc"]}
    assert await _match({"search": {"mode": "contains", "value": "198.51.100."}}) == {t["edge"]}
    assert await _match({"search": {"mode": "regex", "value": r"^(core|edge)-"}}) == {t["core"], t["edge"]}
    assert await _match({"prefixes": ["192.0.2.64/26"]}) == {t["acc"]}
    assert await _match({"prefixes": ["192.0.2.0/24", "2001:db8::/32"]}) == {t["core"], t["acc"], t["v6"]}
    # Criteria combine with AND.
    assert await _match({"groups": [t["a"]], "tag_ids": [t["tag"]]}) == {t["core"]}


async def test_validation_normalises_and_rejects():
    t = await _seed()
    clean = await validate_filter(
        {"groups": [t["a"], t["a"]], "platforms": [" Cisco_IOS "], "prefixes": ["192.0.2.7/24"], "role_id": [None]}
    )
    assert clean["groups"] == [t["a"]]
    assert clean["platforms"] == ["cisco_ios"]
    assert clean["prefixes"] == ["192.0.2.0/24"]
    assert clean["role_id"] == [None]
    assert clean["include_subgroups"] is True

    bad_cases = [
        ({}, "filter"),
        ({"bogus": 1}, "bogus"),
        ({"groups": [999999]}, "groups"),
        ({"groups": ["x"]}, "groups"),
        ({"tag_ids": [999999]}, "tag_ids"),
        ({"tag_ids": [t["tag"]], "tag_match": "some"}, "tag_match"),
        ({"prefixes": ["not-a-net"]}, "prefixes"),
        ({"custom_fields": {"no_such": ["x"]}}, "custom_fields.no_such"),
        ({"custom_fields": {"dg_tier": ["bronze"]}}, "custom_fields.dg_tier"),
        ({"role_id": ["abc"]}, "role_id"),
        ({"search": {"mode": "glob", "value": "x"}}, "search"),
    ]
    for raw, key in bad_cases:
        with pytest.raises(DynamicGroupFilterError) as exc:
            await validate_filter(raw)
        assert key in exc.value.fields, (raw, exc.value.fields)


async def test_regex_runs_on_re2_and_refuses_lookarounds():
    await _seed()
    for pattern in (r"(?=core)", r"(a)\1", r"(?<!x)y"):
        with pytest.raises(DynamicGroupFilterError) as exc:
            await validate_filter({"search": {"mode": "regex", "value": pattern}})
        assert "regular expression" in exc.value.fields["search"]


async def test_resolution_applies_object_scope():
    t = await _seed()
    scoped = ObjectScope(unrestricted=False, read_groups=frozenset({t["a"], t["a1"]}))
    assert await _match({"platforms": ["cisco_xe", "fortinet", "cisco_ios"]}, scoped) == {t["core"], t["acc"]}
    # A group outside the scope counts as unknown.
    with pytest.raises(DynamicGroupFilterError):
        await validate_filter({"groups": [t["b"]]}, scoped)
    # A saved definition naming it still resolves to nothing for this caller.
    assert await resolve_hosts({"groups": [t["b"]]}, scoped) == []
    assert await resolve_hosts({"platforms": ["fortinet"]}, NO_ACCESS) == []


async def _ensure_admin(name: str = "dg-admin") -> str:
    if not await db_module.get_user_by_username(name):
        await db_module.create_user(name, "x", "x", role="admin")
    return name


async def test_scope_for_launcher_fails_closed():
    await db_module.init_db()
    assert (await scope_for_launcher(await _ensure_admin())).unrestricted
    assert (await scope_for_launcher("api-token")).unrestricted
    assert await scope_for_launcher("no-such-user") is NO_ACCESS
    assert await scope_for_launcher(None) is NO_ACCESS


async def test_job_with_dynamic_group_resolves_at_run_time():
    from netcontrol.routes.jobs import _resolve_job_hosts

    t = await _seed()
    group = await db_module.create_dynamic_group(name="dg-gold", description="", filter_def={"tag_ids": [t["tag"]]})
    playbook = await db_module.create_playbook("dg-pb", "dg_pb.txt")
    launcher = await _ensure_admin()
    job_id = await db_module.create_job(playbook, None, launched_by=launcher, dynamic_group_id=int(group["id"]))
    job = await db_module.get_job(job_id)
    assert job["dynamic_group_id"] == group["id"]
    assert job["dynamic_group_name"] == "dg-gold"
    assert job["host_ids"] is None

    # A host tagged after launch is a target when the job starts.
    late = await db_module.add_host(t["b"], "late-sw.example.com", "203.0.113.9")
    await db_module.set_object_data("host", str(late), [t["tag"]], {})
    assert _ids(await _resolve_job_hosts(job)) == {t["core"], t["edge"], late}

    # The launcher's scope applies at run time; an unknown launcher gets nothing.
    assert await _resolve_job_hosts({**job, "launched_by": "ghost"}) == []

    # Deleting the group leaves the job with no target (fails, never widens).
    await db_module.delete_dynamic_group(int(group["id"]))
    job = await db_module.get_job(job_id)
    assert job["dynamic_group_id"] is None
    assert await _resolve_job_hosts(job) == []


# ── HTTP: CRUD, permissions, scope ───────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _login(username: str) -> CsrfClient:
    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


def _user(admin: CsrfClient, name: str, features: list[str], grants: list[dict] | None = None) -> CsrfClient:
    body: dict = {"name": f"{name} access", "feature_keys": features}
    if grants is not None:
        body.update(object_scope="groups", inventory_scopes=grants)
    group = admin.post("/api/admin/access-groups", json=body)
    assert group.status_code == 201, group.text
    resp = admin.post(
        "/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group.json()["id"]]}
    )
    assert resp.status_code == 201, resp.text
    return _login(name)


def _tree(admin: CsrfClient) -> dict[str, int]:
    t: dict[str, int] = {}
    for key, name in (("a", "dg-http-a"), ("b", "dg-http-b")):
        resp = admin.post("/api/inventory", json={"name": name})
        assert resp.status_code == 201, resp.text
        t[key] = int(resp.json()["id"])
    for key, group, name, ip in (
        ("ha", "a", "sw-a.example.com", "192.0.2.10"),
        ("hb", "b", "sw-b.example.com", "198.51.100.10"),
    ):
        resp = admin.post(f"/api/inventory/{t[group]}/hosts", json={"hostname": name, "ip_address": ip})
        assert resp.status_code == 201, resp.text
        t[key] = int(resp.json()["id"])
    return t


def test_crud_round_trip(admin):
    t = _tree(admin)
    created = admin.post(
        API, json={"name": "All sw", "description": "switches", "filter": {"search": {"value": "sw-"}}}
    )
    assert created.status_code == 201, created.text
    dg = created.json()
    assert dg["filter"]["search"] == {"mode": "contains", "value": "sw-"}

    assert admin.post(API, json={"name": "all SW", "filter": {"platforms": ["x"]}}).status_code == 409
    bad = admin.post(API, json={"name": "empty", "filter": {}})
    assert bad.status_code == 400
    assert "at least one criterion" in bad.text

    listed = {g["id"]: g for g in admin.get(API).json()}
    assert listed[dg["id"]]["member_count"] == 2

    members = admin.get(f"{API}/{dg['id']}/members").json()
    assert {h["id"] for h in members["hosts"]} == {t["ha"], t["hb"]}
    assert set(members["hosts"][0]) >= {"hostname", "ip_address", "group_name"}
    assert "snmp_profile_id" not in members["hosts"][0]

    updated = admin.put(f"{API}/{dg['id']}", json={"filter": {"groups": [t["a"]]}})
    assert updated.status_code == 200, updated.text
    assert admin.get(f"{API}/{dg['id']}").json()["member_count"] == 1

    preview = admin.post(f"{API}/preview", json={"filter": {"prefixes": ["198.51.100.0/24"]}})
    assert preview.status_code == 200, preview.text
    assert [h["id"] for h in preview.json()["hosts"]] == [t["hb"]]

    assert admin.delete(f"{API}/{dg['id']}").status_code == 200
    assert admin.get(f"{API}/{dg['id']}").status_code == 404


def test_permissions_and_scope(admin):
    t = _tree(admin)
    dg = admin.post(API, json={"name": "every sw", "filter": {"search": {"value": "sw-"}}}).json()

    reader = _user(admin, "dg-reader", ["inventory"])
    assert reader.get(API).status_code == 200
    assert reader.post(API, json={"name": "x", "filter": {"platforms": ["a"]}}).status_code == 403
    assert reader.put(f"{API}/{dg['id']}", json={"name": "y"}).status_code == 403

    outsider = _user(admin, "dg-outsider", ["dashboard"])
    assert outsider.get(API).status_code == 403

    scoped = _user(admin, "dg-scoped", ["inventory", "inventory.write"], [{"inventory_group_id": t["a"]}])
    members = scoped.get(f"{API}/{dg['id']}/members").json()
    assert {h["id"] for h in members["hosts"]} == {t["ha"]}
    assert members["count"] == 1
    listed = {g["id"]: g for g in scoped.get(API).json()}
    assert listed[dg["id"]]["member_count"] == 1
    preview = scoped.post(f"{API}/preview", json={"filter": {"search": {"value": "sw-"}}}).json()
    assert {h["id"] for h in preview["hosts"]} == {t["ha"]}
    # A group outside the scope is unknown to a scoped preview.
    assert scoped.post(f"{API}/preview", json={"filter": {"groups": [t["b"]]}}).status_code == 400
    # Scoped users cannot change shared definitions (they are job targets).
    assert scoped.post(API, json={"name": "mine", "filter": {"groups": [t["a"]]}}).status_code == 403
    assert scoped.delete(f"{API}/{dg['id']}").status_code == 403


def test_router_is_scope_enforced():
    assert "netcontrol.routes.dynamic_groups:router" in object_scope.SCOPE_ENFORCED_ROUTERS


def test_job_launch_with_dynamic_group_stores_the_group(admin, monkeypatch):
    from netcontrol.routes import jobs as jobs_module

    async def _no_queue():
        return None

    monkeypatch.setattr(jobs_module, "_process_job_queue", _no_queue)
    t = _tree(admin)
    dg = admin.post(API, json={"name": "site a", "filter": {"groups": [t["a"]]}}).json()
    empty = admin.post(API, json={"name": "nothing", "filter": {"platforms": ["no_such_driver"]}}).json()

    async def _setup() -> tuple[int, int]:
        user = await db_module.get_user_by_username("admin")
        cred = await db_module.create_credential("dg-cred", "dev", encrypt("pw"), owner_id=user["id"])
        playbook = await db_module.create_playbook("dg-echo", _DynamicGroupEcho.filename)
        return cred, int(playbook)

    cred, playbook = asyncio.run(_setup())
    body = {"playbook_id": playbook, "credential_id": cred, "dry_run": True}
    resp = admin.post("/api/jobs/launch", json={**body, "dynamic_group_id": dg["id"]})
    assert resp.status_code == 201, resp.text
    job = asyncio.run(db_module.get_job(resp.json()["job_id"]))
    assert job["dynamic_group_id"] == dg["id"]
    assert job["host_ids"] is None

    assert admin.post("/api/jobs/launch", json={**body, "dynamic_group_id": empty["id"]}).status_code == 400
    assert admin.post("/api/jobs/launch", json={**body, "dynamic_group_id": 999999}).status_code == 404


def test_graphql_dynamic_groups_members_are_scope_filtered(admin):
    t = _tree(admin)
    admin.post(API, json={"name": "gql sw", "filter": {"search": {"value": "sw-"}}})
    query = '{ dynamicGroups(name: "gql") { name members(limit: 20) { id } } }'

    full = admin.post("/api/graphql", json={"query": query})
    assert full.status_code == 200, full.text
    groups = full.json()["data"]["dynamicGroups"]
    assert [g["name"] for g in groups] == ["gql sw"]
    assert {int(m["id"]) for m in groups[0]["members"]} == {t["ha"], t["hb"]}

    scoped = _user(admin, "dg-gql", ["inventory", "graphql"], [{"inventory_group_id": t["a"]}])
    limited = scoped.post("/api/graphql", json={"query": query})
    assert limited.status_code == 200, limited.text
    members = limited.json()["data"]["dynamicGroups"][0]["members"]
    assert {int(m["id"]) for m in members} == {t["ha"]}


def test_list_reads_the_host_table_once(admin, monkeypatch):
    _tree(admin)
    for name in ("once-a", "once-b", "once-c"):
        resp = admin.post(API, json={"name": name, "filter": {"search": {"value": "sw-"}}})
        assert resp.status_code == 201, resp.text
    real = db_module.get_all_hosts
    calls = 0

    async def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return await real(*args, **kwargs)

    monkeypatch.setattr(db_module, "get_all_hosts", counting)
    listed = admin.get(API)
    assert listed.status_code == 200, listed.text
    assert calls == 1
    counts = {g["name"]: g["member_count"] for g in listed.json()}
    assert [counts[name] for name in ("once-a", "once-b", "once-c")] == [2, 2, 2]
