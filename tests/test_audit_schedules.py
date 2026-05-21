"""Tests for the audit-run scheduler (migration 0043 + phase 5 wiring).

Covers:
  * Migration creates `audit_schedules` and adds `audit_runs.schedule_id`.
  * Schedule CRUD round-trips (create / get / list / update / delete).
  * `_is_schedule_due` returns True only when enabled AND interval elapsed.
  * Disabled schedules are skipped by the sweep.
  * Unparseable cadences are not due.
  * The sweep inserts one queued audit_runs row per due schedule, stamped
    with `trigger='scheduled'` and the originating `schedule_id`, and
    advances `last_run_at` so the next sweep doesn't double-fire.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module
from netcontrol.routes import audit as audit_router


async def _init_clean_db(tmp_path, monkeypatch) -> str:
    """Stand up a fresh sqlite DB with every migration applied."""
    db_path = str(tmp_path / "audit_schedules.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _table_columns(table: str) -> list[str]:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(f"PRAGMA table_info({table})")
        rows = await cursor.fetchall()
        return [r[1] for r in rows]
    finally:
        await conn.close()


# ── Migration shape ────────────────────────────────────────────────────────

async def test_migration_0043_creates_schedule_table(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    cols = await _table_columns("audit_schedules")
    expected = {
        "id", "name", "schedule", "enabled",
        "last_run_at", "created_by", "created_at", "updated_at",
    }
    assert expected.issubset(set(cols)), (
        f"audit_schedules missing columns: {expected - set(cols)}"
    )


async def test_migration_0043_adds_schedule_id_to_runs(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    cols = await _table_columns("audit_runs")
    assert "schedule_id" in cols, (
        "audit_runs.schedule_id missing -- migration 0043 did not run"
    )


# ── CRUD round-trip ────────────────────────────────────────────────────────

async def test_schedule_crud_roundtrip(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    created = await audit_router._create_schedule(
        name="Nightly sweep",
        schedule="@daily",
        enabled=True,
        created_by="alice",
    )
    assert created["name"] == "Nightly sweep"
    assert created["schedule"] == "@daily"
    assert created["enabled"] is True
    assert created["created_by"] == "alice"
    assert created["last_run_at"] in (None, "", )

    sid = int(created["id"])
    fetched = await audit_router._get_schedule(sid)
    assert fetched is not None
    assert fetched["id"] == sid
    assert fetched["name"] == "Nightly sweep"

    listed = await audit_router._list_schedules()
    assert any(s["id"] == sid for s in listed)

    updated = await audit_router._update_schedule(
        sid, name="Nightly compliance", schedule=None, enabled=False,
    )
    assert updated is not None
    assert updated["name"] == "Nightly compliance"
    # Schedule string unchanged because we passed None.
    assert updated["schedule"] == "@daily"
    assert updated["enabled"] is False

    deleted = await audit_router._delete_schedule(sid)
    assert deleted is True
    # Second delete is a no-op (returns False).
    assert (await audit_router._delete_schedule(sid)) is False
    assert (await audit_router._get_schedule(sid)) is None


# ── Due-detection ──────────────────────────────────────────────────────────

def test_is_schedule_due_when_never_ran():
    sched = {
        "id": 1, "name": "x", "schedule": "@daily", "enabled": True,
        "last_run_at": None,
    }
    now = datetime.now(UTC)
    assert audit_router._is_schedule_due(sched, now) is True


def test_is_schedule_due_when_interval_elapsed():
    now = datetime.now(UTC)
    # @daily = 86400s. Last ran 25 hours ago -> elapsed > interval.
    last_run = (now - timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")
    sched = {
        "id": 1, "name": "x", "schedule": "@daily", "enabled": True,
        "last_run_at": last_run,
    }
    assert audit_router._is_schedule_due(sched, now) is True


def test_is_schedule_not_due_when_interval_recent():
    now = datetime.now(UTC)
    last_run = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    sched = {
        "id": 1, "name": "x", "schedule": "@daily", "enabled": True,
        "last_run_at": last_run,
    }
    assert audit_router._is_schedule_due(sched, now) is False


def test_disabled_schedule_is_never_due():
    sched = {
        "id": 1, "name": "x", "schedule": "@hourly", "enabled": False,
        "last_run_at": None,
    }
    assert audit_router._is_schedule_due(sched, datetime.now(UTC)) is False


def test_unparseable_schedule_is_never_due():
    sched = {
        "id": 1, "name": "x", "schedule": "garbage", "enabled": True,
        "last_run_at": None,
    }
    assert audit_router._is_schedule_due(sched, datetime.now(UTC)) is False


def test_empty_schedule_is_never_due():
    sched = {
        "id": 1, "name": "x", "schedule": "", "enabled": True,
        "last_run_at": None,
    }
    assert audit_router._is_schedule_due(sched, datetime.now(UTC)) is False


# ── Sweep / queue integration ──────────────────────────────────────────────

async def _fetch_runs() -> list[dict]:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, status, trigger, schedule_id FROM audit_runs "
            "ORDER BY id ASC"
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "status": r[1], "trigger": r[2], "schedule_id": r[3]}
            for r in rows
        ]
    finally:
        await conn.close()


async def test_sweep_enqueues_due_schedule_and_advances_last_run(
    tmp_path, monkeypatch,
):
    """A due schedule should produce exactly one queued audit_runs row
    and the schedule's last_run_at must advance so a second sweep is a
    no-op."""
    await _init_clean_db(tmp_path, monkeypatch)

    s = await audit_router._create_schedule(
        name="Hourly check", schedule="@hourly", enabled=True, created_by="",
    )
    sid = int(s["id"])

    # First sweep: schedule never ran, should fire.
    enqueued = await audit_router._enqueue_due_scheduled_runs()
    assert enqueued == 1

    runs = await _fetch_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "queued"
    assert runs[0]["trigger"] == "scheduled"
    assert runs[0]["schedule_id"] == sid

    # last_run_at must now be populated.
    s_after = await audit_router._get_schedule(sid)
    assert s_after is not None
    assert s_after["last_run_at"]

    # Second sweep immediately after: not due yet (1h cadence, ~0s elapsed).
    enqueued2 = await audit_router._enqueue_due_scheduled_runs()
    assert enqueued2 == 0
    assert len(await _fetch_runs()) == 1


async def test_sweep_skips_disabled_schedule(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    await audit_router._create_schedule(
        name="Paused", schedule="@hourly", enabled=False, created_by="",
    )

    enqueued = await audit_router._enqueue_due_scheduled_runs()
    assert enqueued == 0
    assert (await _fetch_runs()) == []


async def test_claim_queued_picks_up_scheduled_row(tmp_path, monkeypatch):
    """Scheduled rows go on the same queue the on-demand path uses, so
    `_claim_queued_run` must pick them up unchanged."""
    await _init_clean_db(tmp_path, monkeypatch)

    s = await audit_router._create_schedule(
        name="x", schedule="@hourly", enabled=True, created_by="",
    )
    await audit_router._enqueue_due_scheduled_runs()
    runs_before = await _fetch_runs()
    assert len(runs_before) == 1
    queued_id = runs_before[0]["id"]

    claimed = await audit_router._claim_queued_run()
    assert claimed == queued_id

    runs_after = await _fetch_runs()
    # Status flipped to running; schedule linkage preserved.
    assert runs_after[0]["status"] == "running"
    assert runs_after[0]["schedule_id"] == int(s["id"])

    # Queue is empty so a second claim returns None.
    assert (await audit_router._claim_queued_run()) is None


async def test_enqueue_scheduled_run_records_schedule_id(tmp_path, monkeypatch):
    """The explicit run-now path must also stamp schedule_id on the row."""
    await _init_clean_db(tmp_path, monkeypatch)

    s = await audit_router._create_schedule(
        name="x", schedule="@daily", enabled=True, created_by="",
    )
    run_id = await audit_router._enqueue_scheduled_run(int(s["id"]))
    assert run_id > 0

    runs = await _fetch_runs()
    assert runs[-1]["id"] == run_id
    assert runs[-1]["status"] == "queued"
    assert runs[-1]["trigger"] == "scheduled"
    assert runs[-1]["schedule_id"] == int(s["id"])


# ── Payload validation ─────────────────────────────────────────────────────

def test_validate_schedule_payload_rejects_empty_name():
    with pytest.raises(Exception) as ei:
        audit_router._validate_schedule_payload("", "@daily")
    assert "name" in str(ei.value).lower()


def test_validate_schedule_payload_rejects_unparseable_cadence():
    with pytest.raises(Exception) as ei:
        audit_router._validate_schedule_payload("x", "not-a-cadence")
    assert "schedule" in str(ei.value).lower()


def test_validate_schedule_payload_accepts_empty_cadence():
    # Empty cadence is allowed (paused / draft) so it doesn't raise.
    audit_router._validate_schedule_payload("x", "")
