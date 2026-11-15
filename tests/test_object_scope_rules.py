"""Object-level permission rules (``netcontrol.object_scope``) without a
database: the ``ObjectScope`` checks and filters, the feature reduction of
the fail-closed rule, the route markers and the request scope resolution."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from netcontrol import object_scope
from netcontrol.object_scope import NO_ACCESS, UNRESTRICTED, ObjectScope
from starlette.requests import Request

SCOPED = ObjectScope(unrestricted=False, read_groups=frozenset({1, 2, 3}), write_groups=frozenset({2}))


def test_unrestricted_reads_and_writes_everything():
    assert UNRESTRICTED.can_read_group(99)
    assert UNRESTRICTED.can_write_group(99)
    assert UNRESTRICTED.can_read_group(None)
    assert UNRESTRICTED.can_write_group(None)
    assert not UNRESTRICTED.restricted
    rows = [{"id": 1}, {"id": 7}]
    assert UNRESTRICTED.filter_groups(rows) is rows
    assert UNRESTRICTED.filter_hosts(rows) is rows


def test_scoped_read_and_write_sets():
    assert SCOPED.restricted
    assert SCOPED.can_read_group(1)
    assert SCOPED.can_read_group("3")
    assert not SCOPED.can_read_group(4)
    assert SCOPED.can_write_group(2)
    assert not SCOPED.can_write_group(1)
    # A row with no group is for unrestricted callers only.
    assert not SCOPED.can_read_group(None)
    assert not SCOPED.can_write_group(None)


def test_no_access_sees_nothing():
    assert NO_ACCESS.restricted
    assert not NO_ACCESS.can_read_group(1)
    assert NO_ACCESS.filter_groups([{"id": 1}]) == []


def test_filters_use_the_given_key():
    groups = [{"id": 1}, {"id": 4}, {"gid": 2}]
    assert SCOPED.filter_groups(groups) == [{"id": 1}]
    assert SCOPED.filter_groups(groups, key="gid") == [{"gid": 2}]
    hosts = [{"id": 10, "group_id": 3}, {"id": 11, "group_id": 5}, {"id": 12, "group_id": None}]
    assert SCOPED.filter_hosts(hosts) == [{"id": 10, "group_id": 3}]
    assert SCOPED.filter_hosts([{"g": 1}], key="g") == [{"g": 1}]


def test_status_payload():
    assert UNRESTRICTED.status() == {"restricted": False, "write_group_ids": []}
    scope = ObjectScope(unrestricted=False, read_groups=frozenset({5, 9}), write_groups=frozenset({9, 5}))
    assert scope.status() == {"restricted": True, "write_group_ids": [5, 9]}


def test_enforced_features_keep_only_enrolled_keys():
    assert object_scope.enforced_features(["dashboard", "inventory", "jobs", "inventory.write", "ipam"]) == [
        "inventory",
        "inventory.write",
    ]
    assert object_scope.SCOPE_ENFORCED_FEATURES == {
        "inventory",
        "inventory.write",
        "config-backups",
        "config-backups.write",
        "config-drift",
        "config-drift.write",
        "credentials",
        "credentials.write",
    }


def test_group_ids_condition():
    from routes.db.inventory import group_ids_condition

    assert group_ids_condition("h.group_id", None) == ("", ())
    assert group_ids_condition("h.group_id", frozenset()) == ("1 = 0", ())
    assert group_ids_condition("h.group_id", [5, 2, 5]) == ("h.group_id IN (?,?)", (2, 5))


def test_group_filter_and_object_host_for_scoped_and_unrestricted(monkeypatch):
    import asyncio

    scoped = ObjectScope(unrestricted=False, read_groups=frozenset({1, 2}), write_groups=frozenset({2}))
    hosts = {10: {"id": 10, "group_id": 1}, 20: {"id": 20, "group_id": 2}, 30: {"id": 30, "group_id": 3}}

    async def get_host(host_id):
        return hosts.get(host_id)

    monkeypatch.setattr(object_scope.db, "get_host", get_host)

    async def run(scope):
        async def fixed(_request):
            return scope

        monkeypatch.setattr(object_scope, "request_scope", fixed)
        results = [await object_scope.group_filter(None), await object_scope.group_filter(None, write=True)]
        for host_id, write in ((10, False), (20, True), (10, True), (30, False), (None, False), (99, False)):
            try:
                await object_scope.require_object_host(None, host_id, write=write, not_found="Thing not found")
                results.append("ok")
            except HTTPException as exc:
                results.append((exc.status_code, exc.detail))
        return results

    assert asyncio.run(run(scoped)) == [
        {"group_ids": frozenset({1, 2})},
        {"group_ids": frozenset({2})},
        "ok",
        "ok",
        (403, object_scope.READ_ONLY_DETAIL),
        (404, "Thing not found"),
        (404, "Thing not found"),
        (404, "Thing not found"),
    ]
    assert asyncio.run(run(UNRESTRICTED)) == [{}, {}, "ok", "ok", "ok", "ok", "ok", "ok"]


def test_markers():
    @object_scope.scoped("group")
    async def a():
        return None

    @object_scope.scope_exempt("no host data")
    async def b():
        return None

    async def c():
        return None

    assert object_scope.scope_marker(a) == ("scoped", "group")
    assert object_scope.scope_marker(b) == ("exempt", "no host data")
    assert object_scope.scope_marker(c) is None
    with pytest.raises(ValueError):
        object_scope.scoped("")
    with pytest.raises(ValueError):
        object_scope.scope_exempt("  ")


def test_enforced_routers_resolve():
    routers = object_scope.enforced_routers()
    assert len(routers) == len(object_scope.SCOPE_ENFORCED_ROUTERS)
    assert all(hasattr(r, "routes") for r in routers)


async def test_scope_for_user_without_database():
    assert await object_scope.scope_for_user(None, token=True) is UNRESTRICTED
    assert await object_scope.scope_for_user(None) is NO_ACCESS
    assert await object_scope.scope_for_user({"id": 1, "role": "admin"}) is UNRESTRICTED


class _DuckRequest:
    """A route function called directly, as some tests do."""

    cookies: dict = {}


def _request(state: dict | None = None) -> Request:
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    for key, value in (state or {}).items():
        setattr(request.state, key, value)
    return request


async def test_request_scope_resolution():
    # Not a request and no session cookie: counts as the API token.
    assert await object_scope.request_scope(_DuckRequest()) is UNRESTRICTED
    # A real request require_auth resolved to the API token.
    token = _request({"auth_session": {"user": "api-token", "user_id": 0, "auth_mode": "token"}})
    assert await object_scope.request_scope(token) is UNRESTRICTED
    assert token.state.object_scope is UNRESTRICTED
    # A real request with no session at all: nothing.
    assert await object_scope.request_scope(_request()) is NO_ACCESS
    # A cached scope is reused.
    cached = _request({"object_scope": SCOPED})
    assert await object_scope.request_scope(cached) is SCOPED
    # The cached session user (an admin) is used without a lookup.
    admin = _request({"auth_session": {"user": "root", "user_id": 4}, "auth_user": {"id": 4, "role": "admin"}})
    assert await object_scope.request_scope(admin) is UNRESTRICTED
    # A session without a user id: nothing.
    assert await object_scope.ws_scope({"user": "x"}) is NO_ACCESS
    assert await object_scope.ws_scope({}) is NO_ACCESS
    assert await object_scope.ws_scope({"auth_mode": "token"}) is UNRESTRICTED


async def test_require_helpers_with_cached_scope(monkeypatch):
    groups = {1: {"id": 1, "name": "a"}, 2: {"id": 2, "name": "b"}, 4: {"id": 4, "name": "d"}}
    hosts = {10: {"id": 10, "group_id": 1}, 11: {"id": 11, "group_id": 2}, 12: {"id": 12, "group_id": 4}}

    async def get_group(gid):
        return groups.get(gid)

    async def get_host(hid):
        return hosts.get(hid)

    async def get_hosts_by_ids(ids):
        return [hosts[h] for h in ids if h in hosts]

    monkeypatch.setattr(object_scope.db, "get_group", get_group)
    monkeypatch.setattr(object_scope.db, "get_host", get_host)
    monkeypatch.setattr(object_scope.db, "get_hosts_by_ids", get_hosts_by_ids)
    request = _request({"object_scope": SCOPED})

    assert (await object_scope.require_group(request, 1))["name"] == "a"
    assert (await object_scope.require_group(request, 2, write=True))["name"] == "b"
    for gid, write, status in ((1, True, 403), (4, False, 404), (9, False, 404)):
        with pytest.raises(HTTPException) as exc:
            await object_scope.require_group(request, gid, write=write)
        assert exc.value.status_code == status
    with pytest.raises(HTTPException) as exc:
        await object_scope.require_group(request, 4)
    assert exc.value.detail == object_scope.GROUP_NOT_FOUND

    assert (await object_scope.require_host(request, 11, write=True))["id"] == 11
    for hid, write, status in ((10, True, 403), (12, False, 404), (99, False, 404)):
        with pytest.raises(HTTPException) as exc:
            await object_scope.require_host(request, hid, write=write)
        assert exc.value.status_code == status

    assert [h["id"] for h in await object_scope.require_hosts(request, [10, 11, 10])] == [10, 11]
    for ids, write, status in (([10, 11], True, 403), ([11, 12], False, 404), ([11, 99], False, 404)):
        with pytest.raises(HTTPException) as exc:
            await object_scope.require_hosts(request, ids, write=write)
        assert exc.value.status_code == status
    # Unrestricted: unknown ids are skipped.
    assert [h["id"] for h in await object_scope.require_hosts(_DuckRequest(), [12, 99], write=True)] == [12]

    await object_scope.refuse_scoped(_DuckRequest())
    with pytest.raises(HTTPException) as exc:
        await object_scope.refuse_scoped(request)
    assert exc.value.status_code == 403
