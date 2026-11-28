"""The object scope of a request is built once (the feature gate and the
scoped routes share it), and a user's granted group subtrees are read in one
query that matches the per-group walk it replaced.

Every name here is invented."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import routes.database as db
from netcontrol import object_scope
from netcontrol.routes import state
from routes.db.dynamic_groups import get_group_subtree_ids
from routes.db.inventory import GROUP_SUBTREE_SQL, group_subtrees_sql
from starlette.requests import Request

from mcp_helpers import admin_client, user_client


async def _tree() -> dict[str, int]:
    """east > east-1 > east-1a, east > east-2; west > west-1; north (alone)."""
    t: dict[str, int] = {}
    t["east"] = await db.create_group("east")
    t["east-1"] = await db.create_group("east-1", parent_id=t["east"])
    t["east-1a"] = await db.create_group("east-1a", parent_id=t["east-1"])
    t["east-2"] = await db.create_group("east-2", parent_id=t["east"])
    t["west"] = await db.create_group("west")
    t["west-1"] = await db.create_group("west-1", parent_id=t["west"])
    t["north"] = await db.create_group("north")
    return t


async def _single_root(group_id: int) -> set[int]:
    """The per-root walk the subtree readers used to run once per grant."""
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute(f"SELECT id FROM inventory_groups WHERE id IN {GROUP_SUBTREE_SQL}", (group_id,))  # noqa: S608
        return {int(r[0]) for r in await cursor.fetchall()}
    finally:
        await conn.close()


# ── Multi-root subtree query ─────────────────────────────────────────────────


async def test_multi_root_query_equals_the_union_of_single_roots():
    t = await _tree()
    # Nested (east and east-1) and overlapping roots, plus an unknown id.
    roots = [t["east"], t["east-1"], t["east-1a"], t["west-1"], 999999]
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute(group_subtrees_sql(len(roots)), tuple(roots))
        rows = [(int(r[0]), int(r[1])) for r in await cursor.fetchall()]
    finally:
        await conn.close()
    for root in roots:
        assert {gid for r, gid in rows if r == root} == await _single_root(root), root
    union: set[int] = set()
    for root in roots:
        union |= await _single_root(root)
    assert {gid for _, gid in rows} == union
    assert t["north"] not in union and t["west"] not in union
    assert await get_group_subtree_ids(roots) == union
    assert await get_group_subtree_ids([]) == set()
    with pytest.raises(ValueError):
        group_subtrees_sql(0)


async def test_user_object_scope_keeps_write_per_covering_grant():
    t = await _tree()
    # east read only, east-1 writable (nested), east-1a read only again
    # (covered by the writable east-1), west-1 writable in a second group.
    first = await db.create_access_group(
        "east ops",
        "",
        ["inventory"],
        object_scope="groups",
        inventory_scopes=[
            {"inventory_group_id": t["east"], "can_write": False},
            {"inventory_group_id": t["east-1"], "can_write": True},
        ],
    )
    second = await db.create_access_group(
        "west ops",
        "",
        ["inventory"],
        object_scope="groups",
        inventory_scopes=[
            {"inventory_group_id": t["east-1a"], "can_write": False},
            {"inventory_group_id": t["west-1"], "can_write": True},
        ],
    )
    uid = await db.create_user("scoped-ops", "hash", "salt")
    await db.set_user_groups(uid, [first, second])
    scope = await db.get_user_object_scope(uid)
    assert scope["unrestricted"] is False
    read = (
        await _single_root(t["east"])
        | await _single_root(t["east-1"])
        | await _single_root(t["east-1a"])
        | await _single_root(t["west-1"])
    )
    write = await _single_root(t["east-1"]) | await _single_root(t["west-1"])
    assert scope["read_group_ids"] == sorted(read)
    assert scope["write_group_ids"] == sorted(write)
    assert set(scope["write_group_ids"]) == {t["east-1"], t["east-1a"], t["west-1"]}
    # No grants: scoped, sees nothing.
    empty = await db.create_access_group("nothing", "", ["inventory"], object_scope="groups", inventory_scopes=[])
    nobody = await db.create_user("scoped-none", "hash", "salt")
    await db.set_user_groups(nobody, [empty])
    assert await db.get_user_object_scope(nobody) == {
        "unrestricted": False,
        "read_group_ids": [],
        "write_group_ids": [],
    }


# ── One scope per request ────────────────────────────────────────────────────


def _request(session: dict | None, user: dict | None) -> Request:
    request = Request({"type": "http", "method": "GET", "path": "/api/x", "headers": [], "query_string": b""})
    if session is not None:
        request.state.auth_session = session
    if user is not None:
        request.state.auth_user = user
    return request


async def test_scope_for_request_user_shares_only_the_request_users_scope(monkeypatch):
    calls: list[int] = []

    async def fake_scope(user_id: int) -> dict:
        calls.append(user_id)
        return {"unrestricted": False, "read_group_ids": [user_id], "write_group_ids": []}

    async def no_rules(user_id: int) -> list:
        return []

    # Within one request only: the cross-request cache (tests/test_authz_cache.py) is off.
    monkeypatch.setenv("APP_AUTHZ_CACHE_TTL", "0")
    monkeypatch.setattr(db, "get_user_object_scope", fake_scope)
    monkeypatch.setattr(object_scope.scope_db, "get_user_scope_rules", no_rules)
    user = {"id": 7, "role": "user"}

    # The request's own user (the cached row): built once, cached on the request.
    request = _request({"user": "u", "user_id": 7}, user)
    first = await object_scope.scope_for_request_user(user, request)
    assert request.state.object_scope is first
    assert await object_scope.request_scope(request) is first
    assert first == await object_scope.scope_for_user(user)
    assert calls == [7, 7]  # the second from the direct scope_for_user above

    # A reloaded row of the same user, another user, an API token session or
    # no request: computed afresh, never stored on the request.
    calls.clear()
    for req, who in (
        (_request({"user": "u", "user_id": 7}, user), dict(user)),
        (_request({"user": "u", "user_id": 7}, user), {"id": 8, "role": "user"}),
        (_request({"user": "api-token", "user_id": 0, "auth_mode": "token"}, user), user),
        (_request(None, user), user),
        (SimpleNamespace(state=SimpleNamespace()), user),
        (None, user),
    ):
        scope = await object_scope.scope_for_request_user(who, req)
        assert scope == await object_scope.scope_for_user(who)
        assert getattr(getattr(req, "state", None), "object_scope", None) is None
    assert len(calls) == 12
    # Admins and missing users keep their fixed scopes.
    admin = {"id": 1, "role": "admin"}
    as_admin = _request({"user_id": 1}, admin)
    assert await object_scope.scope_for_request_user(admin, as_admin) is object_scope.UNRESTRICTED
    assert await object_scope.scope_for_request_user(None, _request({"user_id": 1}, None)) is object_scope.NO_ACCESS


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


def test_scoped_request_builds_its_scope_once(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    group = admin.post("/api/inventory", json={"name": "east"})
    assert group.status_code == 201, group.text
    gid = int(group.json()["id"])
    other = int(admin.post("/api/inventory", json={"name": "west"}).json()["id"])
    user = user_client(admin, "east-viewer", features=["inventory"], read_groups=[gid])

    # Within one request only: the cross-request cache (tests/test_authz_cache.py) is off.
    monkeypatch.setenv("APP_AUTHZ_CACHE_TTL", "0")
    real = db.get_user_object_scope
    calls: list[int] = []

    async def counting(user_id: int) -> dict:
        calls.append(user_id)
        return await real(user_id)

    monkeypatch.setattr(db, "get_user_object_scope", counting)
    resp = user.get("/api/inventory")
    assert resp.status_code == 200, resp.text
    ids = {int(g["id"]) for g in resp.json()}
    assert gid in ids and other not in ids
    # The feature gate (which keeps only enforced features for a scoped user)
    # and the route's request_scope share one build.
    assert len(calls) == 1
