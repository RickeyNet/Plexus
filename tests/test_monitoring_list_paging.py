"""The latest poll per host and the alert list, searched, paged and counted
in SQL: past the default page of 200 every host can be listed, found and
counted, the object scope narrows the list, the search and the total alike,
and the dashboard's ``device_health`` holds the whole polled fleet.

Every name and address here is invented (documentation ranges only)."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client, user_client

HOSTS = 250  # more than the default page of 200


def _address(i: int) -> str:
    return f"192.0.2.{i + 1}" if i < 200 else f"198.51.100.{i - 199}"


async def _sql_many(query: str, rows: list[tuple]) -> None:
    conn = await db.get_db()
    try:
        await conn.executemany(query, rows)
        await conn.commit()
    finally:
        await conn.close()


async def _world() -> dict:
    """Two groups, east (even hosts) and west (odd), ``HOSTS`` polled hosts
    ``dev-000`` .. ``dev-249`` plus one whose name holds LIKE wildcards, one
    host never polled, and per host an open alert (``cpu`` on even hosts,
    ``route_churn`` on odd ones; every tenth is critical) and, on every
    fifth host, an acknowledged one."""
    east = await db.create_group("east")
    west = await db.create_group("west")
    hosts = [((east if i % 2 == 0 else west), f"dev-{i:03d}.example.com", _address(i)) for i in range(HOSTS)]
    hosts.append((east, "lab_a%b.example.com", "203.0.113.5"))
    await _sql_many("INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)", hosts)
    await db.add_host(east, "unpolled.example.com", "203.0.113.9")
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT id, hostname FROM hosts ORDER BY hostname")
        ids = {r["hostname"]: r["id"] for r in db.rows_to_list(await cursor.fetchall())}
    finally:
        await conn.close()
    polled = [ids[h[1]] for h in hosts]
    await _sql_many(
        "INSERT INTO monitoring_polls (host_id, poll_status, polled_at) VALUES (?, 'ok', datetime('now'))",
        [(hid,) for hid in polled],
    )
    alerts = []
    for i, hid in enumerate(polled[:HOSTS]):
        metric = "cpu" if i % 2 == 0 else "route_churn"
        severity = "critical" if i % 10 == 0 else "warning"
        alerts.append((hid, metric, f"{metric} alert on dev-{i:03d}", severity, 0, f"k{i}"))
        if i % 5 == 0:
            alerts.append((hid, metric, f"old {metric} alert on dev-{i:03d}", "warning", 1, f"old{i}"))
    await _sql_many(
        """INSERT INTO monitoring_alerts (host_id, metric, message, severity, acknowledged, dedup_key)
           VALUES (?, ?, ?, ?, ?, ?)""",
        alerts,
    )
    return {"east": east, "west": west, "ids": ids, "polled": polled}


def _names(rows: list[dict]) -> list[str]:
    return [r["hostname"] for r in rows]


# ── Latest polls ─────────────────────────────────────────────────────────────


async def test_latest_polls_page_search_and_total():
    await _world()
    default = await db.get_latest_monitoring_polls()
    assert len(default) == 200
    everything = await db.get_latest_monitoring_polls(limit=None)
    assert len(everything) == HOSTS + 1  # the unpolled host is not listed
    assert await db.count_latest_monitoring_polls() == HOSTS + 1
    assert _names(everything) == sorted(_names(everything))

    # The last host by name and by address, both past the first page.
    assert _names(await db.get_latest_monitoring_polls(search="DEV-249")) == ["dev-249.example.com"]
    assert _names(await db.get_latest_monitoring_polls(search="198.51.100.50")) == ["dev-249.example.com"]
    assert await db.count_latest_monitoring_polls(search="dev-24") == 10

    # Wildcards in the search are literal characters.
    assert _names(await db.get_latest_monitoring_polls(search="_")) == ["lab_a%b.example.com"]
    assert _names(await db.get_latest_monitoring_polls(search="%")) == ["lab_a%b.example.com"]
    assert await db.count_latest_monitoring_polls(search="a%b") == 1
    assert await db.count_latest_monitoring_polls(search="dev_") == 0

    # Pages do not overlap and together are the whole list.
    pages = [await db.get_latest_monitoring_polls(limit=100, offset=o) for o in (0, 100, 200)]
    assert [len(p) for p in pages] == [100, 100, HOSTS + 1 - 200]
    assert sum((_names(p) for p in pages), []) == _names(everything)


async def test_latest_polls_scope_narrows_list_search_and_total():
    w = await _world()
    east = [w["east"]]
    rows = await db.get_latest_monitoring_polls(limit=None, group_ids=east)
    assert {r["group_id"] for r in rows} == {w["east"]}
    assert len(rows) == HOSTS // 2 + 1
    assert await db.count_latest_monitoring_polls(group_ids=east) == HOSTS // 2 + 1
    # dev-249 is a west host: a scoped search finds nothing and counts nothing.
    assert await db.get_latest_monitoring_polls(search="dev-249", group_ids=east) == []
    assert await db.count_latest_monitoring_polls(search="dev-249", group_ids=east) == 0
    assert _names(await db.get_latest_monitoring_polls(search="dev-248", group_ids=east)) == ["dev-248.example.com"]
    assert await db.count_latest_monitoring_polls(search="dev-24", group_ids=east) == 5
    assert await db.count_latest_monitoring_polls(group_ids=[]) == 0
    assert await db.get_latest_monitoring_polls(group_ids=[]) == []


# ── Alerts ───────────────────────────────────────────────────────────────────


async def test_alerts_filters_page_and_total():
    w = await _world()
    open_alerts = await db.get_monitoring_alerts(acknowledged=False, limit=None)
    assert len(open_alerts) == HOSTS
    assert await db.count_monitoring_alerts(acknowledged=False) == HOSTS
    assert len(await db.get_monitoring_alerts(acknowledged=False)) == 200

    churn = await db.get_monitoring_alerts(acknowledged=False, metric="route_churn", limit=None)
    assert len(churn) == HOSTS // 2 and {a["metric"] for a in churn} == {"route_churn"}
    assert await db.count_monitoring_alerts(acknowledged=False, metric="route_churn") == HOSTS // 2
    assert await db.count_monitoring_alerts(acknowledged=False, severity="critical") == HOSTS // 10
    assert await db.count_monitoring_alerts(acknowledged=True) == HOSTS // 5

    # Search on the hostname, the message or the metric.
    by_host = await db.get_monitoring_alerts(acknowledged=False, search="dev-249.example")
    assert [a["host_id"] for a in by_host] == [w["ids"]["dev-249.example.com"]]
    assert await db.count_monitoring_alerts(search="old cpu") == HOSTS // 10
    assert await db.count_monitoring_alerts(acknowledged=False, search="ROUTE_CHURN") == HOSTS // 2
    # Wildcards are literal: no message holds a percent sign.
    assert await db.count_monitoring_alerts(search="%") == 0

    pages = [await db.get_monitoring_alerts(acknowledged=False, limit=100, offset=o) for o in (0, 100, 200)]
    ids = [a["id"] for p in pages for a in p]
    assert len(ids) == len(set(ids)) == HOSTS
    assert ids == [a["id"] for a in open_alerts]


async def test_alerts_scope_narrows_list_search_and_total():
    w = await _world()
    east = [w["east"]]
    east_hosts = {w["polled"][i] for i in range(0, HOSTS, 2)}
    rows = await db.get_monitoring_alerts(limit=None, group_ids=east)
    assert rows and {a["host_id"] for a in rows} <= east_hosts
    assert await db.count_monitoring_alerts(group_ids=east) == len(rows)
    # Every east host has an even index: no route churn alert is in scope.
    assert await db.count_monitoring_alerts(metric="route_churn", group_ids=east) == 0
    assert await db.get_monitoring_alerts(metric="route_churn", group_ids=east) == []
    assert await db.count_monitoring_alerts(search="dev-249", group_ids=east) == 0
    assert await db.count_monitoring_alerts(acknowledged=False, severity="critical", group_ids=east) == HOSTS // 10
    assert await db.count_monitoring_alerts(acknowledged=True, search="old", group_ids=east) == HOSTS // 10
    assert await db.count_monitoring_alerts(group_ids=[]) == 0


# ── HTTP ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    app_module._dashboard_cache.clear()
    request.addfinalizer(app_module._dashboard_cache.clear)
    return admin_client(monkeypatch, request)


def _world_sync(admin: CsrfClient) -> dict:
    """``_world`` once the app (``admin``) is up."""
    assert admin is not None
    return asyncio.run(_world())


def test_polls_endpoint_bare_array_and_with_total(admin):
    _world_sync(admin)
    bare = admin.get("/api/monitoring/polls")
    assert bare.status_code == 200, bare.text
    assert isinstance(bare.json(), list) and len(bare.json()) == 200

    page = admin.get("/api/monitoring/polls", params={"q": "dev-249", "with_total": "true"}).json()
    assert page["total"] == 1 and _names(page["polls"]) == ["dev-249.example.com"]
    second = admin.get("/api/monitoring/polls", params={"offset": 200, "with_total": "true"}).json()
    assert second["total"] == HOSTS + 1 and len(second["polls"]) == HOSTS + 1 - 200
    assert admin.get("/api/monitoring/polls", params={"q": "x" * 201}).status_code == 422
    assert admin.get("/api/monitoring/polls", params={"offset": -1}).status_code == 422


def test_alerts_endpoint_bare_array_and_with_total(admin):
    _world_sync(admin)
    bare = admin.get("/api/monitoring/alerts", params={"acknowledged": "false"})
    assert isinstance(bare.json(), list) and len(bare.json()) == 200
    page = admin.get(
        "/api/monitoring/alerts",
        params={"acknowledged": "false", "metric": "route_churn", "q": "dev-24", "with_total": "true"},
    ).json()
    assert page["total"] == 5 and {a["metric"] for a in page["alerts"]} == {"route_churn"}
    older = admin.get(
        "/api/monitoring/alerts", params={"acknowledged": "false", "offset": 200, "with_total": "true"}
    ).json()
    assert older["total"] == HOSTS and len(older["alerts"]) == HOSTS - 200


def test_scoped_caller_sees_and_counts_only_their_groups(admin):
    w = _world_sync(admin)
    east_hosts = {w["polled"][i] for i in range(0, HOSTS, 2)} | {w["ids"]["lab_a%b.example.com"]}
    user = user_client(admin, "east-viewer", features=["dashboard", "monitoring"], read_groups=[w["east"]])

    polls = user.get("/api/monitoring/polls", params={"limit": 10000, "with_total": "true"}).json()
    assert polls["total"] == len(east_hosts) and {p["host_id"] for p in polls["polls"]} == east_hosts
    found = user.get("/api/monitoring/polls", params={"q": "dev-249", "with_total": "true"}).json()
    assert found == {"polls": [], "total": 0}
    assert user.get("/api/monitoring/polls", params={"q": "dev-24", "with_total": "true"}).json()["total"] == 5

    alerts = user.get("/api/monitoring/alerts", params={"limit": 10000, "with_total": "true"}).json()
    assert alerts["alerts"] and {a["host_id"] for a in alerts["alerts"]} <= east_hosts
    assert alerts["total"] == len(alerts["alerts"])
    churn = user.get("/api/monitoring/alerts", params={"metric": "route_churn", "with_total": "true"}).json()
    assert churn == {"alerts": [], "total": 0}
    critical = user.get(
        "/api/monitoring/alerts",
        params={"acknowledged": "false", "severity": "critical", "q": "cpu", "with_total": "true"},
    ).json()
    assert critical["total"] == HOSTS // 10

    # The dashboard: every polled host in scope, none outside it.
    board = user.get("/api/dashboard").json()
    assert {d["host_id"] for d in board["device_health"]} == east_hosts
    assert board["critical_open_alerts"] == HOSTS // 10


def test_dashboard_device_health_holds_every_polled_host(admin):
    w = _world_sync(admin)
    board = admin.get("/api/dashboard")
    assert board.status_code == 200, board.text
    body = board.json()
    assert {d["host_id"] for d in body["device_health"]} == set(w["polled"])
    assert len(body["open_alerts"]) == 50
    assert body["critical_open_alerts"] == HOSTS // 10
