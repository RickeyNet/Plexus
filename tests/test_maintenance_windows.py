"""Tests for maintenance window time logic and the change gate.

Covers:
  * window_is_active for one-shot, daily, weekly and disabled windows
  * evaluate_change_gate precedence rules (allow > active block > inactive
    block > inactive warn > default allow)
  * scope filtering: a window scoped to group A does not block changes
    targeting group B
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module
from netcontrol.routes.maintenance_windows import (
    evaluate_change_gate,
    window_is_active,
)

# ── Pure time logic (no DB) ──────────────────────────────────────────────────


def _window(**overrides) -> dict:
    base = {
        "enabled": 1,
        "start_at": "2026-05-14T10:00:00+00:00",
        "end_at": "2026-05-14T12:00:00+00:00",
        "recurrence": "none",
        "weekday_mask": 0,
        "policy": "block_outside_window",
    }
    base.update(overrides)
    return base


def test_one_shot_window_is_active_inside():
    w = _window()
    now = datetime(2026, 5, 14, 11, 0, tzinfo=UTC)
    assert window_is_active(w, now) is True


def test_one_shot_window_is_inactive_before():
    w = _window()
    now = datetime(2026, 5, 14, 9, 59, tzinfo=UTC)
    assert window_is_active(w, now) is False


def test_one_shot_window_is_inactive_after():
    w = _window()
    now = datetime(2026, 5, 14, 12, 1, tzinfo=UTC)
    assert window_is_active(w, now) is False


def test_disabled_window_is_never_active():
    w = _window(enabled=0)
    now = datetime(2026, 5, 14, 11, 0, tzinfo=UTC)
    assert window_is_active(w, now) is False


def test_daily_recurrence_active_each_day():
    w = _window(recurrence="daily")
    # Tomorrow at 11:00 -- should still be inside the daily band.
    now = datetime(2026, 5, 15, 11, 0, tzinfo=UTC)
    assert window_is_active(w, now) is True
    # Tomorrow at 09:00 -- before the band.
    now = datetime(2026, 5, 15, 9, 0, tzinfo=UTC)
    assert window_is_active(w, now) is False


def test_daily_recurrence_not_yet_started():
    """Daily windows still respect the original start_at as the
    earliest activation date."""
    w = _window(
        recurrence="daily",
        start_at="2030-01-01T10:00:00+00:00",
        end_at="2030-01-01T12:00:00+00:00",
    )
    now = datetime(2026, 5, 14, 11, 0, tzinfo=UTC)
    assert window_is_active(w, now) is False


def test_weekly_recurrence_only_on_chosen_weekdays():
    # 2026-05-14 is a Thursday (weekday=3 -> bit 3 = 8).
    w = _window(recurrence="weekly", weekday_mask=1 << 3)
    thursday_in_band = datetime(2026, 5, 14, 11, 0, tzinfo=UTC)
    friday_in_band = datetime(2026, 5, 15, 11, 0, tzinfo=UTC)
    assert window_is_active(w, thursday_in_band) is True
    assert window_is_active(w, friday_in_band) is False


def test_window_crossing_midnight():
    """A window like 22:00..02:00 should treat duration as 4h and
    activate during the wrapped band."""
    w = _window(
        recurrence="daily",
        start_at="2026-05-14T22:00:00+00:00",
        end_at="2026-05-14T02:00:00+00:00",
    )
    # 23:00 same day -- inside.
    assert window_is_active(w, datetime(2026, 5, 14, 23, 0, tzinfo=UTC)) is True
    # 01:00 next day -- still inside (wrapped band from previous day).
    assert window_is_active(w, datetime(2026, 5, 15, 1, 0, tzinfo=UTC)) is True
    # 03:00 next day -- outside.
    assert window_is_active(w, datetime(2026, 5, 15, 3, 0, tzinfo=UTC)) is False


# ── DB-backed gate evaluation ────────────────────────────────────────────────


async def _init_clean_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "windows.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


async def test_gate_allows_when_no_windows(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    verdict = await evaluate_change_gate([1])
    assert verdict["allowed"] is True
    assert verdict["window"] is None


async def test_gate_blocks_outside_window_for_scoped_group(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod-edge")
    # Window opens in 1h, lasts 1h, only covers our group.
    future_start = datetime.now(UTC) + timedelta(hours=1)
    future_end = future_start + timedelta(hours=1)
    await db_module.create_maintenance_window(
        name="weekly-prod",
        start_at=_iso(future_start),
        end_at=_iso(future_end),
        policy="block_outside_window",
        group_ids=[group_id],
    )
    verdict = await evaluate_change_gate([group_id])
    assert verdict["allowed"] is False
    assert "weekly-prod" in verdict["reason"]


async def test_gate_ignores_window_scoped_to_other_group(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    prod_group = await db_module.create_group("prod-edge")
    lab_group = await db_module.create_group("lab")
    future_start = datetime.now(UTC) + timedelta(hours=1)
    future_end = future_start + timedelta(hours=1)
    await db_module.create_maintenance_window(
        name="prod-only",
        start_at=_iso(future_start),
        end_at=_iso(future_end),
        policy="block_outside_window",
        group_ids=[prod_group],
    )
    # Targeting only the lab group -- the prod-only window must not apply.
    verdict = await evaluate_change_gate([lab_group])
    assert verdict["allowed"] is True


async def test_gate_allows_when_inside_block_window(tmp_path, monkeypatch):
    """A block_outside_window that is currently active means we ARE in
    maintenance and should be allowed to change."""
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod")
    start = datetime.now(UTC) - timedelta(minutes=10)
    end = datetime.now(UTC) + timedelta(minutes=10)
    await db_module.create_maintenance_window(
        name="now",
        start_at=_iso(start),
        end_at=_iso(end),
        policy="block_outside_window",
        group_ids=[group_id],
    )
    verdict = await evaluate_change_gate([group_id])
    assert verdict["allowed"] is True


async def test_gate_warns_when_outside_warn_window(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod")
    future_start = datetime.now(UTC) + timedelta(hours=1)
    future_end = future_start + timedelta(hours=1)
    await db_module.create_maintenance_window(
        name="advisory",
        start_at=_iso(future_start),
        end_at=_iso(future_end),
        policy="warn_outside_window",
        group_ids=[group_id],
    )
    verdict = await evaluate_change_gate([group_id])
    assert verdict["allowed"] is True
    assert verdict["warning"]
    assert "advisory" in verdict["warning"]


async def test_global_window_blocks_any_group(tmp_path, monkeypatch):
    """A window with no scope rows applies globally."""
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("anything")
    future_start = datetime.now(UTC) + timedelta(hours=1)
    future_end = future_start + timedelta(hours=1)
    await db_module.create_maintenance_window(
        name="global-freeze",
        start_at=_iso(future_start),
        end_at=_iso(future_end),
        policy="block_outside_window",
        group_ids=[],
    )
    verdict = await evaluate_change_gate([group_id])
    assert verdict["allowed"] is False
    assert "global-freeze" in verdict["reason"]


async def test_disabled_window_does_not_block(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    group_id = await db_module.create_group("prod")
    future_start = datetime.now(UTC) + timedelta(hours=1)
    future_end = future_start + timedelta(hours=1)
    await db_module.create_maintenance_window(
        name="off",
        start_at=_iso(future_start),
        end_at=_iso(future_end),
        policy="block_outside_window",
        enabled=False,
        group_ids=[group_id],
    )
    verdict = await evaluate_change_gate([group_id])
    assert verdict["allowed"] is True
