"""The auth path's cross-request cache (``netcontrol.authz_cache``): user
rows, features and object scopes are reused between requests, and every
write that can change them is seen by the very next request.

The writes are made through the ``routes.db`` functions directly where the
admin route would also end the user's sessions, so each test shows the
cache itself being dropped, not the session epoch doing the work. Every
name here is invented."""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

import netcontrol.app as app_module
import pytest
import routes.database as db
import routes.db.object_scope as scope_db
from netcontrol import authz_cache, object_scope
from netcontrol.routes import auth as auth_module, state
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client

PASSWORD = "password123"
# Tables the auth path reads before a handler runs.
AUTH_TABLES = ("users", "user_group_memberships", "access_group")


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    monkeypatch.delenv("APP_AUTHZ_CACHE_TTL", raising=False)


def _access_group(admin: CsrfClient, name: str, features: list[str], read_groups: list[int] | None = None) -> int:
    body: dict = {"name": name, "feature_keys": features}
    if read_groups is not None:
        body["object_scope"] = "groups"
        body["inventory_scopes"] = [{"inventory_group_id": g, "can_write": False} for g in read_groups]
    resp = admin.post("/api/admin/access-groups", json=body)
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _user(admin: CsrfClient, username: str, group_ids: list[int], role: str = "user") -> tuple[int, CsrfClient]:
    resp = admin.post(
        "/api/admin/users",
        json={"username": username, "password": PASSWORD, "role": role, "group_ids": group_ids},
    )
    assert resp.status_code == 201, resp.text
    client = TestClient(app_module.app, raise_server_exceptions=False)
    login = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return int(resp.json()["id"]), CsrfClient(client, login.json().get("csrf_token", ""))


def _group(admin: CsrfClient, name: str, parent_id: int | None = None) -> int:
    resp = admin.post("/api/inventory", json={"name": name, "parent_id": parent_id})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _visible_groups(client: CsrfClient) -> set[int]:
    resp = client.get("/api/inventory")
    assert resp.status_code == 200, resp.text
    return {int(g["id"]) for g in resp.json()}


def _call(admin: CsrfClient, fn, *args, **kwargs):
    async def run():
        return await fn(*args, **kwargs)

    return admin.raw.portal.call(run)


def _count_auth_reads(monkeypatch) -> list[str]:
    """Record every statement on the auth tables from now on."""
    seen: list[str] = []
    real = db._PostgresConnectionCompat.execute

    async def counting(self, query, params=()):
        text = " ".join(query.split())
        if any(t in text for t in AUTH_TABLES):
            seen.append(text)
        return await real(self, query, params)

    monkeypatch.setattr(db._PostgresConnectionCompat, "execute", counting)
    return seen


# ── Writes are seen by the next request ──────────────────────────────────────


def test_feature_and_membership_writes_apply_to_the_next_request(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    jobs_and_inventory = _access_group(admin, "ops staff", ["inventory", "jobs"])
    uid, user = _user(admin, "cache-ops", [jobs_and_inventory])
    assert user.get("/api/jobs").status_code == 200
    assert user.get("/api/jobs").status_code == 200  # served from the cache

    # A feature revoked from the access group: 403 at once.
    resp = admin.put(
        f"/api/admin/access-groups/{jobs_and_inventory}",
        json={"name": "ops staff", "feature_keys": ["inventory"]},
    )
    assert resp.status_code == 200, resp.text
    assert user.get("/api/jobs").status_code == 403
    assert user.get("/api/inventory").status_code == 200

    # Granted back, then the membership removed in the database layer (as a
    # directory sign-in sync does): the feature goes with it.
    _call(admin, db.update_access_group, jobs_and_inventory, "ops staff", "", ["inventory", "jobs"])
    assert user.get("/api/jobs").status_code == 200
    _call(admin, db.set_user_groups, uid, [])
    assert user.get("/api/jobs").status_code == 403
    _call(admin, db.set_user_groups, uid, [jobs_and_inventory])
    assert user.get("/api/jobs").status_code == 200

    # The access group deleted: its features are gone.
    _call(admin, db.delete_access_group, jobs_and_inventory)
    assert user.get("/api/jobs").status_code == 403


def test_account_writes_apply_to_the_next_request(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    staff = _access_group(admin, "staff", ["inventory"])
    uid, user = _user(admin, "cache-acct", [staff])
    assert user.get("/api/inventory").status_code == 200

    # Disabled (without the epoch bump the admin route adds): 401.
    _call(admin, db.update_user_admin, uid, disabled=True)
    assert user.get("/api/inventory").status_code == 401
    _call(admin, db.update_user_admin, uid, disabled=False)
    assert user.get("/api/inventory").status_code == 200

    # A forced password change: 403 until it is changed.
    _call(admin, db.update_user_password, uid, "hash", "salt", must_change_password=True)
    resp = user.get("/api/inventory")
    assert resp.status_code == 403 and "Password change required" in resp.text

    # Sessions revoked (sign-out everywhere, password change, admin reset).
    _call(admin, db.bump_user_session_epoch, uid)
    assert user.get("/api/inventory").status_code == 401


def test_sign_out_ends_the_cached_session(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    staff = _access_group(admin, "staff", ["inventory"])
    _, user = _user(admin, "cache-out", [staff])
    assert user.get("/api/inventory").status_code == 200
    cookie = user.raw.cookies.get("session")
    assert user.post("/api/auth/logout").status_code == 200
    replay = TestClient(app_module.app, raise_server_exceptions=False)
    replay.cookies.set("session", cookie)
    assert replay.get("/api/inventory").status_code == 401


def test_deleted_user_and_role_changes_apply_to_the_next_request(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    staff = _access_group(admin, "staff", ["inventory"])
    second_admin_id, second_admin = _user(admin, "cache-admin2", [], role="admin")
    assert second_admin.get("/api/admin/users").status_code == 200
    # Demoted in the database layer: no longer an admin on the next request.
    _call(admin, db.update_user_admin, second_admin_id, role="user")
    assert second_admin.get("/api/admin/users").status_code == 403
    # The same demotion through the admin API also ends the sessions.
    _call(admin, db.update_user_admin, second_admin_id, role="admin")
    assert second_admin.get("/api/admin/users").status_code == 200
    resp = admin.put(f"/api/admin/users/{second_admin_id}", json={"role": "user"})
    assert resp.status_code == 200, resp.text
    assert second_admin.get("/api/admin/users").status_code == 401

    uid, user = _user(admin, "cache-gone", [staff])
    assert user.get("/api/inventory").status_code == 200
    assert admin.delete(f"/api/admin/users/{uid}").status_code == 200
    assert user.get("/api/inventory").status_code == 401


def test_scope_grant_and_group_tree_writes_apply_to_the_next_request(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    east = _group(admin, "east")
    west = _group(admin, "west")
    access = _access_group(admin, "east viewers", ["inventory"], read_groups=[east])
    uid, user = _user(admin, "cache-scope", [access])
    assert _visible_groups(user) == {east}

    # A sub-group created under a granted group is visible at once; moved
    # out from under it, it is hidden at once.
    east_a = _group(admin, "east-a", parent_id=east)
    assert _visible_groups(user) == {east, east_a}
    resp = admin.put(f"/api/inventory/{east_a}", json={"name": "east-a", "parent_id": west})
    assert resp.status_code == 200, resp.text
    assert _visible_groups(user) == {east}
    # A group path created by an import under the granted group.
    levels = _call(admin, db.get_or_create_group_path, ["east", "east-b"])
    assert _visible_groups(user) == {east, int(levels[-1]["id"])}
    _call(admin, db.delete_group, int(levels[-1]["id"]))
    assert _visible_groups(user) == {east}

    # The grant moved from east to west.
    resp = admin.put(
        f"/api/admin/access-groups/{access}",
        json={
            "name": "east viewers",
            "feature_keys": ["inventory"],
            "object_scope": "groups",
            "inventory_scopes": [{"inventory_group_id": west, "can_write": False}],
        },
    )
    assert resp.status_code == 200, resp.text
    assert _visible_groups(user) == {west, east_a}

    # Every device (object_scope all): unrestricted at once.
    _call(admin, db.update_access_group, access, "east viewers", "", ["inventory"], object_scope="all")
    assert {east, west, east_a} <= _visible_groups(user)

    # A second membership in a scoped group does not narrow an "all" member;
    # removing the "all" membership does.
    narrow = _access_group(admin, "west only", ["inventory"], read_groups=[west])
    _call(admin, db.set_user_groups, uid, [narrow])
    assert _visible_groups(user) == {west, east_a}


async def test_every_authz_write_drops_the_cache():
    """Each ``routes.db`` writer of a table the auth path caches drops the
    cache, even when the write changes nothing."""
    gid = await db.create_group("tree")
    access = await db.create_access_group("readers", "", ["inventory"])
    uid = await db.create_user("cache-unit", "hash", "salt")
    writes = [
        lambda: db.create_user("cache-unit-2", "hash", "salt"),
        lambda: db.update_user_password(uid, "hash2", "salt2"),
        lambda: db.bump_user_session_epoch(uid),
        lambda: db.set_user_auth_provider(uid, ""),
        lambda: db.set_user_external_id(uid, ""),
        lambda: db.update_user_profile(uid, display_name="Unit"),
        lambda: db.update_user_admin(uid, display_name="Unit 2"),
        lambda: db.set_user_groups(uid, [access]),
        lambda: db.create_access_group("writers", "", []),
        lambda: db.update_access_group(access, "readers", "", ["inventory"]),
        lambda: scope_db.set_access_group_scope_rules(access, []),
        lambda: db.create_group("leaf", parent_id=gid),
        lambda: db.update_group(gid, "tree", ""),
        lambda: db.get_or_create_group_path(["tree", "leaf-2"]),
        lambda: db.delete_user(uid),
    ]
    for write in writes:
        authz_cache._CACHE.set(("probe",), ("stale",), 60)
        await write()
        assert authz_cache._CACHE.get(("probe",)) is None, write

    other = await db.create_user("cache-unit-3", "hash", "salt")
    for write in (
        lambda: db.delete_user_guarded(other),
        lambda: db.delete_access_group(access),
        lambda: db.delete_group(gid),
    ):
        authz_cache._CACHE.set(("probe",), ("stale",), 60)
        try:
            await write()
        except ValueError:
            pass  # the group still has sub-groups: refused, cache dropped all the same
        assert authz_cache._CACHE.get(("probe",)) is None, write


_AUTHZ_WRITE = re.compile(
    r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(users|user_group_memberships|access_groups|access_group_features"
    r"|access_group_inventory_scopes|access_group_scope_rules|inventory_groups)\b"
)
# Helpers that write in their caller's transaction, called only from
# decorated writers (create_access_group, update_access_group).
_IN_CALLER_TRANSACTION = {"_replace_inventory_scopes"}
# inventory_groups columns that do not shape the group tree.
_NOT_TREE = re.compile(r"UPDATE\s+inventory_groups\s+SET\s+(discovery_credential_id|environment)\s*=")


def _writers(path: Path):
    text = path.read_text(encoding="utf-8")
    if not _AUTHZ_WRITE.search(text):
        return
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            source = ast.get_source_segment(text, node) or ""
            writes = [m for m in _AUTHZ_WRITE.finditer(source) if not _NOT_TREE.match(source, m.start())]
            if writes:
                yield node, source


def test_every_writer_of_an_authz_table_drops_the_cache():
    """A new ``routes.db`` writer of a table the auth path caches must
    carry ``@invalidates``; app code must not write these tables itself."""
    root = Path(__file__).resolve().parent.parent
    missing = []
    for path in sorted((root / "routes" / "db").glob("*.py")):
        for node, _ in _writers(path):
            decorators = {ast.unparse(d) for d in node.decorator_list}
            if "invalidates" not in decorators and node.name not in _IN_CALLER_TRANSACTION:
                missing.append(f"{path.name}:{node.name}")
    assert missing == []

    outside = []
    for folder in ("netcontrol", "templates"):
        for path in sorted((root / folder).rglob("*.py")):
            for node, source in _writers(path):
                if "authz_cache.invalidate()" not in source:
                    outside.append(f"{path.relative_to(root)}:{node.name}")
    assert outside == []


# ── The cache saves the reads ────────────────────────────────────────────────


def test_repeat_requests_skip_the_auth_reads(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    east = _group(admin, "east")
    access = _access_group(admin, "east viewers", ["inventory"], read_groups=[east])
    _, user = _user(admin, "cache-hit", [access])
    # Fill the cache for both users.
    assert _visible_groups(user) == {east}
    assert admin.get("/api/inventory").status_code == 200

    seen = _count_auth_reads(monkeypatch)
    assert _visible_groups(user) == {east}
    assert admin.get("/api/inventory").status_code == 200
    assert seen == []

    # Turned off: every request reads again.
    monkeypatch.setenv("APP_AUTHZ_CACHE_TTL", "0")
    assert _visible_groups(user) == {east}
    assert len(seen) >= 4


# ── Unit behaviour ───────────────────────────────────────────────────────────


async def test_entries_expire_after_the_ttl(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(authz_cache._CACHE, "clock", lambda: now[0])
    monkeypatch.setenv("APP_AUTHZ_CACHE_TTL", "15")
    loads: list[int] = []

    async def load():
        loads.append(1)
        return ("v", len(loads))

    assert await authz_cache.get_or_load(("k",), load) == ("v", 1)
    now[0] += 14
    assert await authz_cache.get_or_load(("k",), load) == ("v", 1)
    now[0] += 2
    assert await authz_cache.get_or_load(("k",), load) == ("v", 2)
    assert len(loads) == 2


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 20.0), ("", 20.0), ("5", 5.0), ("0", 0.0), ("-3", 0.0), ("9999", 300.0), ("soon", 20.0), ("nan", 20.0)],
)
def test_ttl_setting(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("APP_AUTHZ_CACHE_TTL", raising=False)
    else:
        monkeypatch.setenv("APP_AUTHZ_CACHE_TTL", raw)
    assert authz_cache.ttl_seconds() == expected


async def test_a_load_overtaken_by_a_write_is_not_stored():
    async def load_during_write():
        await asyncio.sleep(0)
        authz_cache.invalidate()  # a write commits while the read runs
        return ("old",)

    assert await authz_cache.get_or_load(("race",), load_during_write) == ("old",)

    async def fresh():
        return ("new",)

    assert await authz_cache.get_or_load(("race",), fresh) == ("new",)


async def test_a_broken_cache_reads_the_database(monkeypatch):
    def broken(key):
        raise RuntimeError("cache unavailable")

    monkeypatch.setattr(authz_cache._CACHE, "get", broken)

    async def load():
        return ("from-db",)

    assert await authz_cache.get_or_load(("k",), load) == ("from-db",)


async def test_callers_get_copies_they_may_change():
    uid = await db.create_user("cache-copy", "hash", "salt")
    access = await db.create_access_group("copy readers", "", ["inventory", "jobs"])
    await db.set_user_groups(uid, [access])
    session = {"user": "cache-copy", "user_id": uid, "session_epoch": 0}

    first = await app_module._cached_user_row(session)
    assert first is not None and first["role"] == "user"
    first["role"] = "admin"
    first["disabled"] = 1
    second = await app_module._cached_user_row(session)
    assert second == {**first, "role": "user", "disabled": 0}
    assert second is not first

    features = await auth_module._get_user_features(second)
    features.append("admin-only")
    assert "admin-only" not in await auth_module._get_user_features(second)

    group = await db.create_group("copy-east")
    await db.update_access_group(
        access,
        "copy readers",
        "",
        ["inventory"],
        object_scope="groups",
        inventory_scopes=[{"inventory_group_id": group, "can_write": False}],
    )
    scope = await object_scope.scope_for_user(second)
    again = await object_scope.scope_for_user(second)
    # A new scope per call (its host/tenant reach is loaded per request) built
    # from the same immutable grants.
    assert scope is not again and scope == again
    assert scope.read_groups == frozenset({group}) and isinstance(scope.read_groups, frozenset)
