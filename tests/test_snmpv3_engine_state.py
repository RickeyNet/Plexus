"""The trap receiver's stored SNMPv3 state (``netcontrol.snmpv3_engine``,
``routes.db.snmp_engine``): the engine ID kept and the boots counted at
every start, and the trap replay record written back (rate limited,
bounded, forward only) and restored after a restart, so the time window
holds across it.

Engine IDs are invented; addresses are from the documentation ranges.
"""

from __future__ import annotations

import netcontrol.snmpv3_engine as se
import netcontrol.snmpv3_traps as v3
import pytest
import routes.database as db
from routes.db import snmp_engine as engine_db

from test_snmpv3_traps import ENGINE, SOURCE, Clock, decode, message


class WallClock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _fresh_engine():
    se.reset()
    yield
    se.reset()


# ── Engine ID and boots ──────────────────────────────────────────────────────


async def test_boots_increment_at_every_start_and_the_engine_id_is_kept():
    await db.init_db()
    first = await se.start()
    second = await se.start()
    assert first is not None and second is not None
    assert first.engine_id == second.engine_id and len(first.engine_id) == 17
    assert (first.boots, second.boots) == (1, 2)
    assert se.LOCAL is second
    snapshot = se.snapshot()
    assert snapshot["trap_engine_id"] == second.engine_id.hex() and snapshot["trap_engine_boots"] == 2


async def test_boots_stop_at_the_maximum(caplog):
    await db.init_db()
    await se.start()
    conn = await db.get_db()
    try:
        await conn.execute("UPDATE snmp_local_engine SET boots = ?", (v3.MAX_ENGINE_VALUE,))
        await conn.commit()
    finally:
        await conn.close()
    engine = await se.start()
    assert engine is not None and engine.boots == v3.MAX_ENGINE_VALUE and engine.latched
    assert "maximum" in caplog.text


async def test_a_start_without_the_database_leaves_no_engine(monkeypatch):
    async def broken(_engine_id):
        raise RuntimeError("database down")

    monkeypatch.setattr(engine_db, "start_snmp_local_engine", broken)
    assert await se.start() is None and se.LOCAL is None
    assert se.snapshot()["trap_engine_id"] == "" and se.snapshot()["trap_engine_boots"] is None


# ── The replay record ────────────────────────────────────────────────────────


def _guard(clock: Clock | None = None, wall: WallClock | None = None, **kwargs) -> v3.ReplayGuard:
    return v3.ReplayGuard(clock=clock or Clock(), wall_clock=wall or WallClock(), **kwargs)


def test_only_timelines_that_moved_are_taken():
    guard = _guard()
    assert decode(message(boots=5, engine_time=1000), guard=guard).ok
    rows = guard.take_changed()
    assert rows == [(SOURCE, ENGINE.hex(), 5, 1000, "2027-01-15 08:00:00")]
    assert guard.take_changed() == []
    # A reordered (older) message does not move the timeline.
    assert decode(message(boots=5, engine_time=990), guard=guard).ok
    assert guard.take_changed() == []
    assert decode(message(boots=5, engine_time=1010), guard=guard).ok
    assert [row[3] for row in guard.take_changed()] == [1010]


def test_seen_at_is_when_the_engine_had_that_time():
    clock, wall = Clock(), WallClock()
    guard = _guard(clock, wall)
    assert decode(message(boots=5, engine_time=1000), guard=guard).ok
    clock.now += 30
    wall.now += 30
    ((*_head, seen_at),) = guard.take_changed()
    assert seen_at == "2027-01-15 08:00:00"


def test_a_restart_keeps_the_time_window():
    """The record restored after a restart: an older boot and a message
    more than 150 s behind the engine's clock (which ran on meanwhile) are
    refused; a newer message is accepted."""
    wall = WallClock()
    before = _guard(wall=wall)
    old = message(boots=5, engine_time=1000)
    assert decode(old, guard=before).ok
    rows = [dict(zip(("source", "engine_id", "boots", "engine_time", "seen_at"), row)) for row in before.take_changed()]
    wall.now += 600  # ten minutes later, a new process
    after = _guard(wall=wall)
    assert after.restore(rows) == 1
    assert decode(old, guard=after).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    assert decode(message(boots=4, engine_time=9000), guard=after).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    assert decode(message(boots=5, engine_time=1600), guard=after).ok


def test_the_residual_window_after_a_quick_restart():
    """Within 150 s of the recorded time an exact copy is accepted once
    more after a restart (the recent digests are not stored)."""
    wall = WallClock()
    before = _guard(wall=wall)
    data = message(boots=5, engine_time=1000)
    assert decode(data, guard=before).ok
    rows = [dict(zip(("source", "engine_id", "boots", "engine_time", "seen_at"), row)) for row in before.take_changed()]
    wall.now += 20
    after = _guard(wall=wall)
    after.restore(rows)
    assert decode(data, guard=after).ok
    assert decode(data, guard=after).failure is v3.V3Failure.REPLAYED


def test_restore_skips_bad_rows_keeps_live_ones_and_stays_bounded():
    wall = WallClock()
    guard = _guard(wall=wall, max_engines=2)
    assert guard.admit("192.0.2.1", ENGINE, 3, 50, b"d") is None
    good = {
        "source": "198.51.100.1",
        "engine_id": ENGINE.hex(),
        "boots": 1,
        "engine_time": 5,
        "seen_at": "2027-01-15 07:00:00",
    }
    held = {**good, "source": "192.0.2.1", "boots": 9, "engine_time": 9}
    assert guard.restore([held, good]) == 1
    assert guard.size == 2
    # The live timeline was kept, not replaced by the stored one.
    assert guard.admit("192.0.2.1", ENGINE, 3, 60, b"e") is None
    bad = [
        {**good, "engine_id": "zz"},
        {**good, "engine_id": "8000"},  # too short
        {**good, "boots": -1},
        {**good, "seen_at": "yesterday"},
        {"source": "203.0.113.1"},
    ]
    assert _guard(wall=wall).restore(bad) == 0
    # At most max_engines rows are read: the newest (first) ones.
    bounded = _guard(wall=wall, max_engines=2)
    rows = [{**good, "source": f"203.0.113.{i}"} for i in range(3)]
    assert bounded.restore(rows) == 2 and bounded.size == 2
    assert bounded.admit("203.0.113.2", ENGINE, 1, 5, b"d") is None  # not loaded: starts a new timeline
    assert bounded.size == 2


def test_a_clock_set_back_does_not_run_the_engine_backwards():
    wall = WallClock()
    guard = _guard(wall=wall)
    row = {
        "source": SOURCE,
        "engine_id": ENGINE.hex(),
        "boots": 5,
        "engine_time": 1000,
        "seen_at": "2027-01-15 09:00:00",
    }
    assert guard.restore([row]) == 1  # seen "in the future"
    assert decode(message(boots=5, engine_time=860), guard=guard).ok


async def test_the_record_is_written_rate_limited_and_restored(monkeypatch):
    await db.init_db()
    clock = Clock()
    monkeypatch.setattr(se, "_clock", clock)
    guard = _guard()
    assert decode(message(boots=5, engine_time=1000), guard=guard).ok
    assert await se.persist_replay(guard) == 1
    assert decode(message(boots=5, engine_time=1100), guard=guard).ok
    assert await se.persist_replay(guard) == 0  # within the interval
    clock.now += se.REPLAY_PERSIST_SECONDS
    assert await se.persist_replay(guard) == 1
    assert await se.persist_replay(guard, force=True) == 0  # nothing moved
    restored = _guard()
    assert await se.restore_replay(restored) == 1
    # More than 150 s behind the last time written (1100): refused after the restore.
    assert decode(message(boots=5, engine_time=900), guard=restored).failure is v3.V3Failure.NOT_IN_TIME_WINDOW


async def test_the_stored_record_moves_forward_only_and_is_bounded():
    await db.init_db()
    newer = ("192.0.2.1", ENGINE.hex(), 6, 10, "2027-01-15 08:00:00")
    older = ("192.0.2.1", ENGINE.hex(), 5, 9000, "2027-01-15 08:05:00")
    await engine_db.save_snmpv3_replay_state([newer], keep=10)
    await engine_db.save_snmpv3_replay_state([older], keep=10)
    (row,) = await engine_db.load_snmpv3_replay_state(10)
    assert (row["boots"], row["engine_time"]) == (6, 10)
    rows = [(f"198.51.100.{i}", ENGINE.hex(), 1, i, f"2027-01-15 08:00:{i:02d}") for i in range(5)]
    await engine_db.save_snmpv3_replay_state(rows, keep=3)
    kept = await engine_db.load_snmpv3_replay_state(10)
    assert [r["source"] for r in kept] == ["198.51.100.4", "198.51.100.3", "198.51.100.2"]


async def test_database_failures_are_logged_not_raised(monkeypatch, caplog):
    async def broken(*_a, **_k):
        raise RuntimeError("database down")

    monkeypatch.setattr(engine_db, "load_snmpv3_replay_state", broken)
    monkeypatch.setattr(engine_db, "save_snmpv3_replay_state", broken)
    guard = _guard()
    assert await se.restore_replay(guard) == 0
    assert decode(message(), guard=guard).ok
    assert await se.persist_replay(guard, force=True) == 0
    assert "not loaded" in caplog.text and "not written" in caplog.text
