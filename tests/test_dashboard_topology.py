"""Tests for the topology section of GET /api/dashboard.

Covers, with no network access:
  * db filter   - ``list_topology_entity_states`` state filter, worst-first
                  ordering and limit; ``count_topology_entity_states``
  * aggregate   - ``dashboard_topology_summary`` counts per state, per
                  provider and per source and entity type, problem rows
                  (labels, ordering, cap)
  * HTTP API    - the ``topology`` section of /api/dashboard, and its gate
                  on the monitoring feature (the cache is shared, the gate is
                  per user)

All names are invented.
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module

T0 = "2026-01-01 00:00:00"
T1 = "2026-01-02 00:00:00"
T2 = "2026-01-03 00:00:00"


def _entity(provider: str, org_ref: int, entity_type: str, entity_id: str, state: str, **extra) -> dict:
    return {
        "provider": provider,
        "org_ref": org_ref,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "name": extra.pop("name", f"{entity_type}-{entity_id}"),
        "state": state,
        "raw_status": extra.pop("raw_status", state),
        "site": extra.pop("site", ""),
        "model": "",
        "host_id": extra.pop("host_id", None),
        "meta": {},
    }


async def _seed() -> None:
    """Cato org 11: three sites, all up at T0; site a down and b degraded at
    T1; c down too at T2. AWS org 21: one VPN connection up, one unknown."""
    cato = lambda a, b, c: [  # noqa: E731
        _entity("cato", 11, "site", "a", a, name="Branch A"),
        _entity("cato", 11, "site", "b", b, name="Branch B"),
        _entity("cato", 11, "tunnel", "c", c, name="Tunnel C", site="Branch A"),
    ]
    await db_module.apply_topology_entity_states("cato", 11, cato("up", "up", "up"), org_name="Example Cato", now=T0)
    await db_module.apply_topology_entity_states(
        "cato", 11, cato("down", "degraded", "up"), org_name="Example Cato", now=T1
    )
    await db_module.apply_topology_entity_states(
        "cato", 11, cato("down", "degraded", "down"), org_name="Example Cato", now=T2
    )
    await db_module.apply_topology_entity_states(
        "aws",
        21,
        [_entity("aws", 21, "vpn_connection", "vpn-1", "up"), _entity("aws", 21, "vpn_connection", "vpn-2", "unknown")],
        now=T0,
    )


# ── db filter ────────────────────────────────────────────────────────────────


async def test_list_states_filters_orders_worst_first_and_limits():
    await _seed()
    rows = await db_module.list_topology_entity_states(states=("down", "degraded"), worst_first=True)
    assert [(r["entity_id"], r["state"], r["state_since"]) for r in rows] == [
        ("c", "down", T2),
        ("a", "down", T1),
        ("b", "degraded", T1),
    ]
    limited = await db_module.list_topology_entity_states(states=["down", "degraded"], worst_first=True, limit=2)
    assert [r["entity_id"] for r in limited] == ["c", "a"]
    only_down = await db_module.list_topology_entity_states(provider="cato", states=["down"])
    assert sorted(r["entity_id"] for r in only_down) == ["a", "c"]
    assert await db_module.list_topology_entity_states(states=[]) == []
    # Unfiltered behaviour is unchanged: every entity, provider order.
    every = await db_module.list_topology_entity_states()
    assert [r["provider"] for r in every] == ["aws", "aws", "cato", "cato", "cato"]


async def test_count_states_groups_by_source_type_and_state():
    await _seed()
    rows = await db_module.count_topology_entity_states()
    assert [(r["provider"], r["org_ref"], r["entity_type"], r["state"], r["count"]) for r in rows] == [
        ("aws", 21, "vpn_connection", "unknown", 1),
        ("aws", 21, "vpn_connection", "up", 1),
        ("cato", 11, "site", "degraded", 1),
        ("cato", 11, "site", "down", 1),
        ("cato", 11, "tunnel", "down", 1),
    ]


async def test_count_states_keeps_two_orgs_of_one_provider_apart():
    await _seed()
    await db_module.apply_topology_entity_states(
        "cato", 12, [_entity("cato", 12, "site", "z", "up", name="Branch Z")], org_name="Other Cato", now=T0
    )
    rows = await db_module.count_topology_entity_states()
    sites = {
        (r["org_ref"], r["state"]): r["count"] for r in rows if r["provider"] == "cato" and r["entity_type"] == "site"
    }
    assert sites == {(11, "degraded"): 1, (11, "down"): 1, (12, "up"): 1}


# ── aggregate ────────────────────────────────────────────────────────────────


async def test_dashboard_summary_counts_and_problems():
    await _seed()
    summary = await tracking.dashboard_topology_summary()
    assert summary["entity_counts"] == {"up": 1, "degraded": 1, "down": 2, "unknown": 1, "total": 5}
    assert summary["by_provider"] == {
        "aws": {"up": 1, "degraded": 0, "down": 0, "unknown": 1},
        "cato": {"up": 0, "degraded": 1, "down": 2, "unknown": 0},
    }
    assert summary["by_source"] == [
        {
            "provider": "aws",
            "org_ref": 21,
            "entity_type": "vpn_connection",
            "up": 1,
            "degraded": 0,
            "down": 0,
            "unknown": 1,
        },
        {"provider": "cato", "org_ref": 11, "entity_type": "site", "up": 0, "degraded": 1, "down": 1, "unknown": 0},
        {"provider": "cato", "org_ref": 11, "entity_type": "tunnel", "up": 0, "degraded": 0, "down": 1, "unknown": 0},
    ]
    assert summary["problem_count"] == 3
    first = summary["problems"][0]
    assert first == {
        "provider": "cato",
        "provider_label": tracking.PROVIDER_LABELS["cato"],
        "org_ref": 11,
        "org_name": "Example Cato",
        "entity_type": "tunnel",
        "type_label": tracking.TYPE_LABELS["tunnel"],
        "entity_id": "c",
        "name": "Tunnel C",
        "site": "Branch A",
        "host_id": None,
        "state": "down",
        "raw_status": "down",
        "since": T2,
    }
    assert [p["entity_id"] for p in summary["problems"]] == ["c", "a", "b"]


async def test_dashboard_summary_caps_problems_but_not_counts():
    await _seed()
    summary = await tracking.dashboard_topology_summary(limit=1)
    assert [p["entity_id"] for p in summary["problems"]] == ["c"]
    assert summary["problem_count"] == 3


async def test_dashboard_summary_empty():
    summary = await tracking.dashboard_topology_summary()
    assert summary == {
        "entity_counts": {"up": 0, "degraded": 0, "down": 0, "unknown": 0, "total": 0},
        "by_provider": {},
        "by_source": [],
        "problem_count": 0,
        "problems": [],
    }


# ── HTTP API ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-dashboard-topology")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    # The dashboard cache is module state shared by every test.
    monkeypatch.setitem(app_module._dashboard_cache, "data", None)
    monkeypatch.setitem(app_module._dashboard_cache, "expires", 0.0)

    from starlette.testclient import TestClient

    test_client = TestClient(app_module.app, raise_server_exceptions=False)
    test_client.__enter__()
    request.addfinalizer(lambda: test_client.__exit__(None, None, None))
    asyncio.run(_seed())
    resp = test_client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200, resp.text
    return test_client, resp.json().get("csrf_token", "")


def _login_user(test_client, csrf: str, username: str, features: list[str]) -> None:
    """Create a non-admin user with exactly ``features`` and log in as them."""
    group_id = asyncio.run(db_module.create_access_group(f"{username} group", "", features))
    resp = test_client.post(
        "/api/admin/users",
        json={"username": username, "password": "password123", "role": "user", "group_ids": [group_id]},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201, resp.text
    resp = test_client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text


def test_dashboard_includes_topology_for_admin(client):
    test_client, _csrf = client
    resp = test_client.get("/api/dashboard")
    assert resp.status_code == 200, resp.text
    topology = resp.json()["topology"]
    assert topology["entity_counts"]["down"] == 2
    assert topology["problem_count"] == 3
    assert [p["entity_id"] for p in topology["problems"]] == ["c", "a", "b"]
    assert {(r["provider"], r["org_ref"], r["entity_type"]) for r in topology["by_source"]} == {
        ("aws", 21, "vpn_connection"),
        ("cato", 11, "site"),
        ("cato", 11, "tunnel"),
    }


def test_dashboard_omits_topology_without_monitoring_feature(client):
    test_client, csrf = client
    # Warm the shared cache as admin first: the gate must apply after it.
    assert "topology" in test_client.get("/api/dashboard").json()
    _login_user(test_client, csrf, "viewer", ["dashboard"])
    resp = test_client.get("/api/dashboard")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "topology" not in body
    assert "device_health" in body and "open_alerts" in body
    # The cached object itself still carries the section for other users.
    assert "topology" in app_module._dashboard_cache["data"]


def test_dashboard_includes_topology_with_monitoring_feature(client):
    test_client, csrf = client
    _login_user(test_client, csrf, "operator", ["dashboard", "monitoring"])
    resp = test_client.get("/api/dashboard")
    assert resp.status_code == 200, resp.text
    assert resp.json()["topology"]["entity_counts"]["total"] == 5
