"""Regression tests for interface rate calculation.

The rate math parsed ``polled_at`` (a naive UTC string written by SQLite
``datetime('now')``) and subtracted it from an *aware* ``datetime.now(UTC)``.
That raises ``TypeError``, which a broad ``except (ValueError, TypeError)``
swallowed at DEBUG — so every interface rate silently stayed NULL and the
bandwidth dashboard was permanently empty. ``_parse_db_time`` normalizes the
stored timestamp to aware UTC; ``_counter_delta`` is width-aware so a counter
reset no longer fabricates a spike.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
import routes.database as db_module
from netcontrol.routes.metrics_engine import (
    _counter_delta,
    _parse_db_time,
    store_interface_ts_from_poll,
)


@pytest.fixture
def rate_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "metrics_rate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-metrics-rate")
    asyncio.run(db_module.init_db())
    return db_path


def test_parse_db_time_naive_string_is_aware():
    """A naive DB timestamp parses to an aware UTC datetime that can be
    subtracted from datetime.now(UTC) without TypeError."""
    parsed = _parse_db_time("2020-01-01 00:00:00")
    assert parsed is not None
    assert parsed.tzinfo is not None
    # The exact operation the old code failed on:
    delta = (datetime.now(UTC) - parsed).total_seconds()
    assert delta > 0


def test_parse_db_time_handles_empty_and_bad():
    assert _parse_db_time("") is None
    assert _parse_db_time(None) is None
    assert _parse_db_time("not-a-date") is None


def test_counter_delta_normal():
    assert _counter_delta(100, 500) == 400


def test_counter_delta_32bit_wrap():
    # Both samples < 2**32 and cur < prev → treat as a 32-bit wrap.
    assert _counter_delta(2**32 - 10, 5) == 15


def test_counter_delta_64bit_reset_is_none():
    # A negative delta on 64-bit-range samples is a reset, not a wrap.
    assert _counter_delta(5_000_000_000, 1_000_000) is None


async def _seed_prev_stat(host_id: int, if_index: int, polled_at: str,
                          in_octets: int, out_octets: int) -> None:
    db = await db_module.get_db()
    try:
        await db.execute(
            """INSERT INTO interface_stats
               (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets, polled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (host_id, if_index, "Gi0/1", 1000, in_octets, out_octets, polled_at),
        )
        await db.commit()
    finally:
        await db.close()


async def _add_host(hostname: str) -> int:
    db = await db_module.get_db()
    try:
        await db.execute("INSERT OR IGNORE INTO inventory_groups (name) VALUES ('rate')")
        cur = await db.execute("SELECT id FROM inventory_groups WHERE name='rate'")
        gid = int((await cur.fetchone())[0])
        cur2 = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, '10.0.0.1')",
            (gid, hostname),
        )
        await db.commit()
        return int(cur2.lastrowid)
    finally:
        await db.close()


def test_rates_are_computed_from_naive_prev_timestamp(rate_db):
    """End-to-end guard: a prev interface_stats row with a naive polled_at must
    yield a non-NULL rate (the old code produced NULL for every interface)."""
    async def _go():
        host_id = await _add_host("rate-host")
        # Prev counters an hour ago; a naive timestamp exactly like datetime('now').
        await _seed_prev_stat(host_id, 1, "2020-01-01 00:00:00", 1_000, 2_000)
        stored = await store_interface_ts_from_poll(
            host_id,
            [{"if_index": 1, "name": "Gi0/1", "speed_mbps": 1000,
              "in_octets": 1_000_000, "out_octets": 2_000_000}],
        )
        assert stored == 1
        rows = await db_module.query_interface_ts(host_id, if_index=1)
        assert rows, "expected an interface_ts row"
        assert rows[0]["in_rate_bps"] is not None
        assert rows[0]["in_rate_bps"] > 0
        assert rows[0]["out_rate_bps"] is not None

    asyncio.run(_go())


def test_counter_reset_yields_null_rate_not_spike(rate_db):
    """A reboot (counters drop into the 64-bit range from a huge value) must
    skip the interval rather than fabricate a multi-terabit spike."""
    async def _go():
        host_id = await _add_host("reset-host")
        await _seed_prev_stat(host_id, 2, "2020-01-01 00:00:00",
                              5_000_000_000, 5_000_000_000)
        await store_interface_ts_from_poll(
            host_id,
            [{"if_index": 2, "name": "Gi0/2", "speed_mbps": 1000,
              "in_octets": 1_000_000, "out_octets": 1_000_000}],
        )
        rows = await db_module.query_interface_ts(host_id, if_index=2)
        assert rows
        assert rows[0]["in_rate_bps"] is None

    asyncio.run(_go())
