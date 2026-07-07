"""Tests for get_sla_summary jitter computation.

The per-host jitter was previously computed with one extra query per host (an
N+1 that issued 500 queries for a 500-host summary). It is now folded into the
main GROUP BY via AVG(response_time_ms^2). This verifies the folded stddev
matches the population standard deviation of the sampled response times.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def sla_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "sla.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-sla")
    asyncio.run(db_module.init_db())
    return db_path


async def _seed_host_with_polls(hostname: str, rts: list[float]) -> int:
    db = await db_module.get_db()
    try:
        await db.execute("INSERT OR IGNORE INTO inventory_groups (name) VALUES ('sla')")
        cur = await db.execute("SELECT id FROM inventory_groups WHERE name='sla'")
        gid = int((await cur.fetchone())[0])
        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, '10.0.0.1')",
            (gid, hostname),
        )
        host_id = int(cur.lastrowid)
        for rt in rts:
            await db.execute(
                "INSERT INTO monitoring_polls (host_id, poll_status, response_time_ms, "
                "packet_loss_pct, polled_at) VALUES (?, 'ok', ?, 0, datetime('now'))",
                (host_id, rt),
            )
        await db.commit()
        return host_id
    finally:
        await db.close()


def _population_stddev(values: list[float]) -> float:
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return variance ** 0.5


def test_jitter_matches_population_stddev(sla_db):
    async def _go():
        rts = [10.0, 20.0, 30.0, 40.0, 50.0]
        await _seed_host_with_polls("sw-jitter", rts)
        summary = await db_module.get_sla_summary()
        host = next(h for h in summary["hosts"] if h["hostname"] == "sw-jitter")
        expected = round(_population_stddev(rts), 2)
        assert host["jitter_ms"] == pytest.approx(expected, abs=0.05)

    asyncio.run(_go())


def test_jitter_zero_for_constant_latency(sla_db):
    async def _go():
        await _seed_host_with_polls("sw-flat", [25.0, 25.0, 25.0])
        summary = await db_module.get_sla_summary()
        host = next(h for h in summary["hosts"] if h["hostname"] == "sw-flat")
        assert host["jitter_ms"] == 0.0

    asyncio.run(_go())


def test_jitter_none_when_no_latency_samples(sla_db):
    async def _go():
        db = await db_module.get_db()
        try:
            await db.execute("INSERT OR IGNORE INTO inventory_groups (name) VALUES ('sla')")
            cur = await db.execute("SELECT id FROM inventory_groups WHERE name='sla'")
            gid = int((await cur.fetchone())[0])
            cur = await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, 'sw-null', '10.0.0.2')",
                (gid,),
            )
            hid = int(cur.lastrowid)
            # A poll with NULL response_time_ms (device unreachable).
            await db.execute(
                "INSERT INTO monitoring_polls (host_id, poll_status, response_time_ms, polled_at) "
                "VALUES (?, 'error', NULL, datetime('now'))",
                (hid,),
            )
            await db.commit()
        finally:
            await db.close()
        summary = await db_module.get_sla_summary()
        host = next(h for h in summary["hosts"] if h["hostname"] == "sw-null")
        assert host["jitter_ms"] is None

    asyncio.run(_go())
