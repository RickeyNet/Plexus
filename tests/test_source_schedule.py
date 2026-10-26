"""Tests for scheduled collection of the integration sources.

Covers, with no network access:
  * due rules    - never collected, stale, fresh, per-source interval,
                   auto-collect off, no API key, demo entry, build running,
                   scheduling turned off
  * scheduler    - a pass builds every due source as the "scheduler" user,
                   one after the other, and a failing source does not stop it
  * manual build - resets the clock, so the source is not due again
  * HTTP API     - the admin-only schedule config (clamping, persistence) and
                   the new fields of a source and of /api/topology/sources
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import netcontrol.routes.meraki_topology as topology
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from netcontrol.integrations.meraki.sample import build_sample_raw
from netcontrol.routes import background_jobs

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _schedule(monkeypatch):
    """Hourly scheduling on, and no build left running by another test."""
    monkeypatch.setattr(state, "SOURCE_COLLECTION_SYNC_CONFIG", {"enabled": True, "interval_seconds": 3600})
    monkeypatch.setattr(topology, "_running_builds", {})


def _org(**fields) -> dict:
    org = {
        "id": 7,
        "name": "Acme",
        "has_api_key": True,
        "auto_collect": True,
        "collect_interval_seconds": 0,
        "last_build_at": None,
    }
    org.update(fields)
    return org


def _ago(**delta) -> str:
    return (NOW - timedelta(**delta)).isoformat()


# ── Due rules ────────────────────────────────────────────────────────────────


def test_a_source_never_collected_is_due_now():
    assert topology.collection_due(_org(), NOW)
    assert topology.next_collection_at(_org(), NOW) == NOW


def test_a_stale_source_is_due_and_a_fresh_one_is_not():
    assert topology.collection_due(_org(last_build_at=_ago(minutes=61)), NOW)
    fresh = _org(last_build_at=_ago(minutes=10))
    assert not topology.collection_due(fresh, NOW)
    assert topology.next_collection_at(fresh, NOW) == NOW + timedelta(minutes=50)


def test_a_stamp_without_a_zone_is_read_as_utc():
    naive = (NOW - timedelta(minutes=61)).replace(tzinfo=None).isoformat(sep=" ")
    assert topology.collection_due(_org(last_build_at=naive), NOW)


def test_the_source_interval_overrides_the_global_one():
    collected = _ago(minutes=20)
    assert topology.collection_due(_org(last_build_at=collected, collect_interval_seconds=900), NOW)
    assert not topology.collection_due(_org(last_build_at=_ago(hours=2), collect_interval_seconds=86400), NOW)
    # Out-of-range overrides are clamped to the global bounds.
    assert topology.collection_interval(_org(collect_interval_seconds=10)) == 300
    assert topology.collection_interval(_org(collect_interval_seconds=10**9)) == 86400


def test_the_global_interval_applies_without_an_override(monkeypatch):
    monkeypatch.setattr(state, "SOURCE_COLLECTION_SYNC_CONFIG", {"enabled": True, "interval_seconds": 7200})
    assert not topology.collection_due(_org(last_build_at=_ago(minutes=90)), NOW)
    assert topology.collection_due(_org(last_build_at=_ago(minutes=121)), NOW)


@pytest.mark.parametrize(
    "fields",
    [
        {"auto_collect": False},
        {"has_api_key": False},
        {"name": topology.SAMPLE_CATO_NAME, "has_api_key": False},
    ],
    ids=["auto-collect-off", "no-api-key", "demo"],
)
def test_sources_the_scheduler_leaves_alone(fields):
    org = _org(**fields)
    assert not topology.collection_due(org, NOW)
    assert topology.next_collection_at(org, NOW) is None


def test_a_source_being_collected_is_not_due(monkeypatch):
    monkeypatch.setitem(topology._running_builds, 7, "job")
    assert not topology.collection_due(_org(), NOW)


def test_nothing_is_due_with_scheduling_off(monkeypatch):
    monkeypatch.setattr(state, "SOURCE_COLLECTION_SYNC_CONFIG", {"enabled": False, "interval_seconds": 3600})
    assert not topology.collection_due(_org(), NOW)
    assert topology.next_collection_at(_org(), NOW) is None


# ── Scheduler pass ───────────────────────────────────────────────────────────


async def _source(name: str, *, api_key: str = "k", last_build_at: str | None = None, **fields) -> dict:
    org = await db_module.create_meraki_org(name, api_key=api_key, org_id="sample", **fields)
    assert org
    if last_build_at:
        org = await db_module.update_meraki_org(org["id"], last_build_at=last_build_at)
    assert org
    return org


async def test_a_pass_builds_every_due_source_one_at_a_time_as_the_scheduler(monkeypatch):
    stale = await _source("Stale", last_build_at=_ago(hours=2))
    never = await _source("Never")
    failing = await _source("Failing")
    await _source("Fresh", last_build_at=_ago(minutes=5))
    await _source("Opted out", auto_collect=False)
    await _source("No key", api_key="")
    await db_module.create_meraki_org(topology.SAMPLE_ORG_NAME)

    calls: list[tuple[int, str]] = []
    active = {"n": 0, "max": 0}

    async def _fake_build(job_id, org, user):
        active["n"] += 1
        active["max"] = max(active["max"], active["n"])
        assert topology._running_builds[org["id"]] == job_id
        await asyncio.sleep(0)
        calls.append((org["id"], user))
        topology._running_builds.pop(org["id"], None)
        active["n"] -= 1
        if org["id"] == failing["id"]:
            background_jobs.finish_job(job_id, "failed", error="boom")
            raise RuntimeError("boom")
        background_jobs.finish_job(job_id, "completed", result={})

    monkeypatch.setattr(topology, "_run_build", _fake_build)
    counts = await topology.run_scheduled_collections(NOW)

    assert counts == {"sources": 7, "due": 3, "started": 3, "skipped": 4, "errors": 1}
    assert sorted(calls) == sorted(
        [(stale["id"], "scheduler"), (never["id"], "scheduler"), (failing["id"], "scheduler")]
    )
    assert active["max"] == 1
    assert topology._running_builds == {}


async def test_a_source_collected_by_hand_during_the_pass_is_skipped(monkeypatch):
    first = await _source("First")
    second = await _source("Second")
    built: list[int] = []

    async def _fake_build(job_id, org, user):
        built.append(org["id"])
        topology._running_builds.pop(org["id"], None)
        # Someone clicks Collect on the other source meanwhile.
        other = second["id"] if org["id"] == first["id"] else first["id"]
        await db_module.update_meraki_org(other, last_build_at=NOW.isoformat())
        background_jobs.finish_job(job_id, "completed", result={})

    monkeypatch.setattr(topology, "_run_build", _fake_build)
    counts = await topology.run_scheduled_collections(NOW)
    assert counts["due"] == 2 and counts["started"] == 1 and counts["skipped"] == 1
    assert len(built) == 1


async def test_the_real_build_path_records_a_failure_without_stopping_the_pass(monkeypatch):
    async def _boom(*_args, **_kwargs):
        raise ValueError("Set the Organization ID")

    monkeypatch.setattr(topology, "_resolve_org_id", _boom)
    org = await _source("Acme")
    counts = await topology.run_scheduled_collections()
    assert counts["started"] == 1 and counts["errors"] == 1
    stored = await db_module.get_meraki_org(org["id"])
    assert stored and stored["last_build_status"] == "failed" and stored["last_build_at"]
    # A failed collection also resets the clock: no retry on every pass.
    assert not topology.collection_due(stored)


# ── HTTP API ─────────────────────────────────────────────────────────────────


def test_a_manual_build_resets_the_clock(api, monkeypatch):  # noqa: F811
    async def _fake_collect(_client, _org_id, _options, _progress):
        return build_sample_raw(branches=2)

    monkeypatch.setattr(topology, "collect_organization", _fake_collect)
    org = api.post("/api/sources", json={"name": "Acme", "api_key": "k", "org_id": "sample"}).json()["org"]
    assert org["auto_collect"] is True and org["collect_interval_seconds"] == 0
    assert org["next_collection_at"]

    job_id = api.post(f"/api/sources/{org['id']}/build").json()["job_id"]
    for _ in range(200):
        if api.get(f"/api/sources/builds/{job_id}").json()["status"] != "running":
            break
    stored = asyncio.run(db_module.get_meraki_org(org["id"]))
    assert stored and stored["last_build_status"] == "success"
    assert not topology.collection_due(stored)
    due_at = datetime.fromisoformat(api.get("/api/sources").json()["orgs"][0]["next_collection_at"])
    assert due_at - datetime.fromisoformat(stored["last_build_at"]) == timedelta(hours=1)


def test_schedule_config_is_clamped_and_persisted(api):  # noqa: F811
    current = api.get("/api/sources/schedule")
    assert current.status_code == 200, current.text
    assert current.json()["config"] == {"enabled": True, "interval_seconds": 3600}
    assert current.json()["min_interval_seconds"] == 300 and current.json()["max_interval_seconds"] == 86400

    low = api.put("/api/sources/schedule", json={"interval_seconds": 5})
    assert low.status_code == 200 and low.json()["config"]["interval_seconds"] == 300
    high = api.put("/api/sources/schedule", json={"enabled": False, "interval_seconds": 10**7})
    assert high.json()["config"] == {"enabled": False, "interval_seconds": 86400}
    assert state.SOURCE_COLLECTION_SYNC_CONFIG == {"enabled": False, "interval_seconds": 86400}
    stored = asyncio.run(db_module.get_auth_setting("source_collection_sync"))
    assert stored == {"enabled": False, "interval_seconds": 86400}

    assert api.put("/api/sources/schedule", json={"interval_seconds": "soon"}).status_code == 422


def test_schedule_config_is_admin_only(api):  # noqa: F811
    group = api.post("/api/admin/access-groups", json={"name": "Topology editors", "feature_keys": ["topology"]})
    assert group.status_code == 201, group.text
    user = api.post(
        "/api/admin/users",
        json={"username": "editor", "password": "editor-password", "group_ids": [group.json()["id"]]},
    )
    assert user.status_code == 201, user.text
    login = api._c.post("/api/auth/login", json={"username": "editor", "password": "editor-password"})
    assert login.status_code == 200, login.text
    editor = _CsrfClient(api._c, login.json().get("csrf_token", ""))
    assert editor.get("/api/sources/schedule").status_code == 403
    assert editor.put("/api/sources/schedule", json={"enabled": False}).status_code == 403
    assert state.SOURCE_COLLECTION_SYNC_CONFIG["enabled"] is True


def test_source_settings_and_the_sources_list_carry_the_schedule(api):  # noqa: F811
    created = api.post(
        "/api/sources",
        json={"name": "Acme", "api_key": "k", "auto_collect": False, "collect_interval_seconds": 60},
    )
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["auto_collect"] is False and org["collect_interval_seconds"] == 300
    assert org["next_collection_at"] is None

    updated = api.put(f"/api/sources/{org['id']}", json={"auto_collect": True, "collect_interval_seconds": 0})
    assert updated.status_code == 200
    assert updated.json()["org"]["auto_collect"] is True and updated.json()["org"]["collect_interval_seconds"] == 0
    assert api.put(f"/api/sources/{org['id']}", json={"collect_interval_seconds": -1}).status_code == 422

    assert api.post("/api/sources/sample?provider=cato").status_code == 201
    sources = {s["name"]: s for s in api.get("/api/topology/sources").json()["sources"]}
    acme = sources["Acme"]
    assert acme["auto_collect"] is True and acme["collect_interval_seconds"] == 0
    assert acme["next_collection_at"] is not None  # never collected: due now
    demo = sources[topology.SAMPLE_CATO_NAME]
    assert demo["demo"] is True and demo["next_collection_at"] is None
