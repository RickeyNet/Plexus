"""Regression test for query_interface_ts_multi (dashboard bandwidth N+1 fix).

The dashboard bandwidth-trend panel used to fetch each top interface's series
with its own query_interface_ts call (N+1). query_interface_ts_multi pulls all
requested (host_id, if_index) pairs in one windowed query. This pins the
grouping, the per-pair cap, and ascending-by-time ordering.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def ts_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "ts.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ts-multi")
    asyncio.run(db_module.init_db())


def test_multi_groups_caps_and_orders(ts_db):
    async def _go():
        gid = await db_module.create_group("g")
        h1 = await db_module.add_host(gid, "sw1", "10.0.0.1")
        h2 = await db_module.add_host(gid, "sw2", "10.0.0.2")
        # 4 samples each for (h1,if10), (h1,if11), (h2,if10)
        for i in range(4):
            await db_module.create_interface_ts_sample(
                h1, 10, "Gi0/1", 1000, 100 * i, 200 * i,
                in_rate_bps=float(i), out_rate_bps=float(i))
            await db_module.create_interface_ts_sample(
                h1, 11, "Gi0/2", 1000, 300 * i, 400 * i,
                in_rate_bps=float(10 + i), out_rate_bps=float(i))
            await db_module.create_interface_ts_sample(
                h2, 10, "Gi0/1", 1000, 500 * i, 600 * i,
                in_rate_bps=float(20 + i), out_rate_bps=float(i))

        res = await db_module.query_interface_ts_multi(
            [(h1, 10), (h1, 11), (h2, 10)],
            start="2000-01-01 00:00:00", limit_per=2)

        # One entry per requested pair.
        assert set(res.keys()) == {(h1, 10), (h1, 11), (h2, 10)}
        for pair, rows in res.items():
            assert len(rows) == 2, pair                       # per-pair cap honored
            ts = [r["sampled_at"] for r in rows]
            assert ts == sorted(ts), pair                     # ascending by time

        # Empty input returns empty dict (no query).
        assert await db_module.query_interface_ts_multi([], start="2000-01-01 00:00:00") == {}

        # A pair with no samples simply doesn't appear.
        res2 = await db_module.query_interface_ts_multi(
            [(h1, 10), (h1, 999)], start="2000-01-01 00:00:00", limit_per=10)
        assert (h1, 10) in res2 and (h1, 999) not in res2

    asyncio.run(_go())
