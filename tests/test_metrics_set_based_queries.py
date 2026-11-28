"""Set-based metrics reads and writes (performance audit, batch 2).

The availability summary and the per-port utilization summary used to run
three queries per host / per interface, the metric rollup fetched raw samples
into Python to aggregate them, and the interface tab read at most 2,000 raw
rows (a few hours of a 48-port switch, whatever range was asked for). These
tests pin the results the old code produced and the bounded query counts.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module
from netcontrol import sample_history
from netcontrol.routes import metrics_engine

FMT = "%Y-%m-%d %H:%M:%S"


def _ts(dt: datetime) -> str:
    return dt.strftime(FMT)


def _stored(dt: datetime) -> str:
    """``dt`` as a TIMESTAMPTZ column reads back (PostgreSQL's UTC text)."""
    return _ts(dt) + "+00"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


async def _exec(sql: str, params: tuple = ()) -> None:
    db = await db_module.get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
    finally:
        await db.close()


async def _execmany(sql: str, rows: list[tuple]) -> None:
    db = await db_module.get_db()
    try:
        await db.executemany(sql, rows)
        await db.commit()
    finally:
        await db.close()


async def _rows(sql: str, params: tuple = ()) -> list[dict]:
    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return db_module.rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


@pytest.fixture
def count_queries(monkeypatch):
    """Count statements sent through the compat layer."""
    calls: list[str] = []
    original = db_module._PostgresConnectionCompat.execute

    async def _counting(self, query, params=()):
        calls.append(query)
        return await original(self, query, params)

    monkeypatch.setattr(db_module._PostgresConnectionCompat, "execute", _counting)
    return calls


async def _transition(host_id: int, new_state: str, at: datetime, old_state: str = "unknown") -> None:
    await _exec(
        "INSERT INTO availability_transitions (host_id, entity_type, entity_id, old_state, new_state, transition_at)"
        " VALUES (?, 'host', '', ?, ?, ?)",
        (host_id, old_state, new_state, _ts(at)),
    )


# ── Availability summary ─────────────────────────────────────────────────────


async def test_availability_summary_matches_per_host_walk(count_queries):
    now = _now()
    gid = await db_module.create_group("avail-group")
    other_gid = await db_module.create_group("avail-other")
    quiet = await db_module.add_host(gid, "avail-a.example.com", "192.0.2.10")
    flappy = await db_module.add_host(gid, "avail-b.example.com", "192.0.2.11")
    dark = await db_module.add_host(gid, "avail-c.example.com", "192.0.2.12")
    elsewhere = await db_module.add_host(other_gid, "avail-d.example.com", "192.0.2.13")

    # Down before the window, back up inside it, then one full-day outage.
    # The walk does not count the time from the window start to the first
    # in-window transition, so only the one day is down time.
    await _transition(flappy, "down", now - timedelta(days=40))
    await _transition(flappy, "up", now - timedelta(days=10))
    await _transition(flappy, "down", now - timedelta(days=5))
    await _transition(flappy, "up", now - timedelta(days=4))
    # Down before the window and never back: the whole window is down.
    await _transition(dark, "down", now - timedelta(days=40))
    await _transition(elsewhere, "down", now - timedelta(days=2))

    count_queries.clear()
    summary = await db_module.get_availability_summary(gid, 30)
    # Two statements whatever the host count (was 1 + 3 per host).
    assert len(count_queries) == 2

    assert summary["period_days"] == 30
    assert summary["host_count"] == 3
    by_id = {h["host_id"]: h for h in summary["hosts"]}
    assert [h["hostname"] for h in summary["hosts"]] == [
        "avail-a.example.com",
        "avail-b.example.com",
        "avail-c.example.com",
    ]

    assert by_id[quiet]["uptime_pct"] == 100.0
    assert by_id[quiet]["down_seconds"] == 0
    assert by_id[quiet]["outage_count"] == 0
    assert by_id[quiet]["last_outage"] is None

    assert by_id[flappy]["down_seconds"] == 86400
    assert by_id[flappy]["uptime_pct"] == round((1 - 86400 / (30 * 86400)) * 100, 3)
    assert by_id[flappy]["outage_count"] == 1
    assert by_id[flappy]["last_outage"] == {
        "down_at": _ts(now - timedelta(days=5)),
        "up_at": _ts(now - timedelta(days=4)),
    }

    assert by_id[dark]["down_seconds"] == 30 * 86400
    assert by_id[dark]["uptime_pct"] == 0.0
    assert by_id[dark]["outage_count"] == 0
    assert by_id[dark]["last_outage"] == {"down_at": _ts(now - timedelta(days=40)), "up_at": None}

    assert set(by_id[quiet]) == {
        "host_id",
        "hostname",
        "ip_address",
        "group_id",
        "current_state",
        "uptime_pct",
        "outage_count",
        "down_seconds",
        "last_outage",
    }
    assert summary["total_outages"] == 1
    assert summary["avg_uptime_pct"] == round((100.0 + by_id[flappy]["uptime_pct"] + 0.0) / 3, 3)

    # Object scope and an ongoing outage measured to now.
    scoped = await db_module.get_availability_summary(None, 30, group_ids=[other_gid])
    assert [h["host_id"] for h in scoped["hosts"]] == [elsewhere]
    ongoing = scoped["hosts"][0]
    assert 2 * 86400 <= ongoing["down_seconds"] <= 2 * 86400 + 120
    assert ongoing["last_outage"] == {"down_at": _ts(now - timedelta(days=2)), "up_at": None}

    # More hosts, same statement count.
    for i in range(5):
        await db_module.add_host(gid, f"avail-extra-{i}.example.com", f"192.0.2.{20 + i}")
    count_queries.clear()
    bigger = await db_module.get_availability_summary(gid, 30)
    assert bigger["host_count"] == 8
    assert len(count_queries) == 2


async def test_availability_summary_without_hosts():
    gid = await db_module.create_group("avail-empty")
    summary = await db_module.get_availability_summary(gid, 7)
    assert summary == {
        "period_days": 7,
        "host_count": 0,
        "avg_uptime_pct": 0.0,
        "total_outages": 0,
        "currently_down": 0,
        "hosts": [],
    }


# ── Per-port utilization summary ─────────────────────────────────────────────

_IFTS_INSERT = (
    "INSERT INTO interface_ts (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets,"
    " in_rate_bps, out_rate_bps, utilization_pct, sampled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def test_interface_utilization_summary_one_query(count_queries):
    now = _now()
    gid = await db_module.create_group("util-group")
    host = await db_module.add_host(gid, "util-sw.example.com", "198.51.100.10")
    rows: list[tuple] = []
    # if 1: 20 samples. The old nearest-rank p95 took 0-based index
    # int(20 * 0.95) = 19, the top value; percentile_disc would take 18.
    for i in range(1, 21):
        at = _ts(now - timedelta(minutes=i))
        rows.append((host, 1, "Gi0/1", 1000, 0, 0, i * 100.0, i * 10.0, float(i), at))
    # A sample without an inbound rate: left out of the averages and peaks,
    # kept in the utilization percentile (21 values, index 19 -> 20.0).
    rows.append((host, 1, "Gi0/1", 1000, 0, 0, None, None, 50.0, _ts(now - timedelta(minutes=30))))
    # Outside the one-day window.
    rows.append((host, 1, "Gi0/1", 1000, 0, 0, 99999.0, 99999.0, 99.0, _ts(now - timedelta(days=2))))
    # if 2: never has an inbound rate, so it is not listed.
    rows.append((host, 2, "Gi0/2", 1000, 0, 0, None, 5.0, 5.0, _ts(now - timedelta(minutes=5))))
    # if 3: rates but no utilization, so no percentiles at all.
    for i in range(1, 4):
        rows.append((host, 3, "Gi0/0", 100, 0, 0, float(i), float(i), None, _ts(now - timedelta(minutes=i))))
    # if 4: odd values to pin rounding to two places.
    rows.append((host, 4, "Te1/1", 10000, 0, 0, 1.23456, 2.34567, 3.45678, _ts(now - timedelta(minutes=1))))
    await _execmany(_IFTS_INSERT, rows)

    count_queries.clear()
    result = await db_module.get_interface_utilization_summary(host, 1)
    assert len(count_queries) == 1  # was 1 + 3 per interface

    assert result == [
        {
            "if_index": 3,
            "if_name": "Gi0/0",
            "if_speed_mbps": 100,
            "sample_count": 3,
            "avg_in_bps": 2.0,
            "avg_out_bps": 2.0,
            "peak_in_bps": 3.0,
            "peak_out_bps": 3.0,
            "avg_util": None,
            "peak_util": None,
            "p95_util": None,
            "p95_in_bps": None,
            "p95_out_bps": None,
        },
        {
            "if_index": 1,
            "if_name": "Gi0/1",
            "if_speed_mbps": 1000,
            "sample_count": 20,
            "avg_in_bps": 1050.0,
            "avg_out_bps": 105.0,
            "peak_in_bps": 2000.0,
            "peak_out_bps": 200.0,
            "avg_util": 10.5,
            "peak_util": 20.0,
            "p95_util": 20.0,
            "p95_in_bps": 2000.0,
            "p95_out_bps": 200.0,
        },
        {
            "if_index": 4,
            "if_name": "Te1/1",
            "if_speed_mbps": 10000,
            "sample_count": 1,
            "avg_in_bps": 1.23,
            "avg_out_bps": 2.35,
            "peak_in_bps": 1.23,
            "peak_out_bps": 2.35,
            "avg_util": 3.46,
            "peak_util": 3.46,
            "p95_util": 3.46,
            "p95_in_bps": 1.23,
            "p95_out_bps": 2.35,
        },
    ]
    assert list(result[0]) == list(result[1])  # same key order as before


async def test_interface_utilization_summary_nearest_rank_for_many_counts():
    """The SQL index matches Python's ``int(n * 0.95)`` for every n."""
    now = _now()
    gid = await db_module.create_group("util-rank")
    host = await db_module.add_host(gid, "util-rank.example.com", "198.51.100.11")
    rows: list[tuple] = []
    counts = list(range(1, 61))
    for if_index in counts:
        for i in range(if_index):
            value = float((i * 37) % 101)  # unsorted, with repeats
            rows.append((host, if_index, f"Eth{if_index:03d}", 1000, 0, 0, value, value, value, _ts(now)))
    await _execmany(_IFTS_INSERT, rows)

    result = {r["if_index"]: r for r in await db_module.get_interface_utilization_summary(host, 1)}
    for n in counts:
        values = sorted(float((i * 37) % 101) for i in range(n))
        expected = round(values[min(int(n * 0.95), n - 1)], 2)
        assert result[n]["p95_util"] == expected, n
        assert result[n]["p95_in_bps"] == expected, n


# ── Metric rollups ───────────────────────────────────────────────────────────


def _reference_percentile(values: list[float], pct: float) -> float:
    """The linear-interpolation percentile the Python rollup used."""
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


_SAMPLE_INSERT = (
    "INSERT INTO metric_samples (host_id, metric_name, labels_json, value, sampled_at) VALUES (?, ?, ?, ?, ?)"
)


async def test_rollup_matches_python_aggregation_and_is_idempotent(count_queries):
    gid = await db_module.create_group("rollup-group")
    h1 = await db_module.add_host(gid, "rollup-a.example.com", "203.0.113.10")
    h2 = await db_module.add_host(gid, "rollup-b.example.com", "203.0.113.11")
    start = "2026-03-01 10:00:00"
    end = "2026-03-01 11:00:00"
    seeded: list[tuple] = []
    series = {
        (h1, "cpu_percent", "{}"): [12.5, 40.0, 7.25, 99.0, 55.5, 13.0, 61.75],
        (h1, "cpu_percent", '{"core": "1"}'): [1.0, 2.0],
        (h1, "memory_percent", "{}"): [70.0],
        (h2, "cpu_percent", "{}"): [3.0, 5.0, 4.0, 8.0, 1.0, 9.0, 2.0, 6.0, 7.0, 10.0, 0.5],
        (h2, "response_time_ms", "{}"): [0.1, 0.2, 0.30000000000000004],
    }
    for (host_id, metric, labels), values in series.items():
        for i, value in enumerate(values):
            seeded.append((host_id, metric, labels, value, f"2026-03-01 10:{i:02d}:00"))
    # Outside the window (end is exclusive) and a metric that is not rolled up.
    seeded.append((h1, "cpu_percent", "{}", 1000.0, end))
    seeded.append((h1, "cpu_percent", "{}", 1000.0, "2026-03-01 09:59:59"))
    seeded.append((h1, "not_a_rolled_up_metric", "{}", 1.0, "2026-03-01 10:30:00"))
    await _execmany(_SAMPLE_INSERT, seeded)
    # The rollup first checks once per process that no pre-0144 history is
    # still moving in (netcontrol.sample_history); done here, not counted.
    assert await sample_history.history_complete("metric_samples")

    count_queries.clear()
    created = await metrics_engine._downsample_window("hourly", start, end)
    assert created == len(series)
    assert len(count_queries) == 1  # one INSERT ... SELECT (was one SELECT per metric + the batch)

    stored = await _rows(
        "SELECT host_id, metric_name, labels_json, time_window, period_start, period_end,"
        " val_min, val_avg, val_max, val_p95, sample_count FROM metric_rollups ORDER BY id"
    )
    assert len(stored) == len(series)
    for row in stored:
        values = series[(row["host_id"], row["metric_name"], row["labels_json"])]
        assert row["time_window"] == "hourly"
        assert row["period_start"] == start
        assert row["period_end"] == end
        assert row["val_min"] == min(values)
        assert row["val_max"] == max(values)
        assert row["sample_count"] == len(values)
        # Same definitions; summation order may differ in the last bit.
        assert row["val_avg"] == pytest.approx(sum(values) / len(values), rel=1e-12)
        assert row["val_p95"] == pytest.approx(_reference_percentile(values, 95), rel=1e-12)

    # Re-running the window writes nothing and changes nothing.
    assert await metrics_engine._downsample_window("hourly", start, end) == 0
    again = await _rows(
        "SELECT host_id, metric_name, labels_json, time_window, period_start, period_end,"
        " val_min, val_avg, val_max, val_p95, sample_count FROM metric_rollups ORDER BY id"
    )
    assert again == stored

    # The daily window over the same samples is a separate set of rows.
    daily = await metrics_engine._downsample_window("daily", "2026-03-01 00:00:00", "2026-03-02 00:00:00")
    assert daily == len(series)


async def test_rollup_of_empty_window_writes_nothing():
    assert await metrics_engine._downsample_window("hourly", "2026-03-01 10:00:00", "2026-03-01 11:00:00") == 0
    assert await db_module.rollup_metric_samples([], "hourly", "2026-03-01 10:00:00", "2026-03-01 11:00:00") == 0
    assert await _rows("SELECT id FROM metric_rollups") == []


# ── Interface tab series ─────────────────────────────────────────────────────


async def test_interface_series_30d_covers_whole_range_bounded_and_ordered(count_queries):
    now = _now()
    gid = await db_module.create_group("ifts-group")
    host = await db_module.add_host(gid, "ifts-sw.example.com", "198.51.100.20")
    span, bucket = metrics_engine._INTERFACE_TS_RANGES["30d"]
    interfaces = 24
    step = timedelta(minutes=30)
    rows: list[tuple] = []
    sample_count = int(span / step)
    for if_index in range(1, interfaces + 1):
        for i in range(sample_count):
            at = now - span + timedelta(minutes=5) + i * step
            rows.append(
                (host, if_index, f"Gi1/0/{if_index}", 1000, i * 1000, i * 2000, float(i), float(2 * i), 1.0, _ts(at))
            )
    await _execmany(_IFTS_INSERT, rows)
    assert len(rows) > 2000 * 10  # far past the old 2,000-row cap

    start = _ts(now - span)
    count_queries.clear()
    result = await db_module.query_interface_ts_series(host, start, bucket_seconds=bucket)
    assert len(count_queries) == 2  # buckets + one newest-sample read

    data = result["data"]
    by_if: dict[int, list[dict]] = {}
    for row in data:
        by_if.setdefault(row["if_index"], []).append(row)
    assert list(by_if) == list(range(1, interfaces + 1))  # ordered by interface
    max_points = int(span.total_seconds() // bucket) + 1
    for if_index, points in by_if.items():
        times = [p["sampled_at"] for p in points]
        assert times == sorted(times), if_index
        assert len(points) <= max_points, if_index
        # The series spans the whole range, not the last few hours.
        assert datetime.strptime(times[0], FMT) <= now - span + timedelta(seconds=bucket)
        assert datetime.strptime(times[-1], FMT) >= now - timedelta(seconds=2 * bucket)
        assert sum(p["sample_count"] for p in points) == sample_count

    # A bucket holds the average of its samples, starts on a bucket edge,
    # and keeps the highest counter reading.
    first = by_if[1][1]
    edge = datetime.strptime(first["sampled_at"], FMT)
    assert int((edge - datetime(1970, 1, 1)).total_seconds()) % bucket == 0
    bucket_end = edge + timedelta(seconds=bucket)
    members = [r for r in rows if r[1] == 1 and edge <= datetime.strptime(r[9], FMT) < bucket_end]
    assert first["sample_count"] == len(members) == 4
    assert first["in_rate_bps"] == pytest.approx(sum(r[6] for r in members) / len(members))
    assert first["out_rate_bps"] == pytest.approx(sum(r[7] for r in members) / len(members))
    assert first["in_octets"] == max(r[4] for r in members)

    # The newest raw sample per interface, for the current-rate table.
    latest = result["latest"]
    assert [r["if_index"] for r in latest] == list(range(1, interfaces + 1))
    assert latest[0]["in_rate_bps"] == float(sample_count - 1)

    # One interface only.
    single = await db_module.query_interface_ts_series(host, start, bucket_seconds=bucket, if_index=3)
    assert {r["if_index"] for r in single["data"]} == {3}
    assert [r["if_index"] for r in single["latest"]] == [3]


async def test_interface_series_short_range_is_raw():
    now = _now()
    gid = await db_module.create_group("ifts-raw")
    host = await db_module.add_host(gid, "ifts-raw.example.com", "198.51.100.21")
    span, bucket = metrics_engine._INTERFACE_TS_RANGES["1h"]
    assert bucket == 0
    assert metrics_engine._INTERFACE_TS_RANGES["6h"][1] == 0
    rows: list[tuple] = []
    for if_index in (2, 1):
        for i in range(12):
            at = now - timedelta(minutes=5 * i)
            rows.append((host, if_index, f"Gi0/{if_index}", 1000, i, i, float(i), float(i), float(i), _ts(at)))
    rows.append((host, 1, "Gi0/1", 1000, 0, 0, 7.0, 7.0, 7.0, _ts(now - timedelta(hours=2))))
    await _execmany(_IFTS_INSERT, rows)

    start = _ts(now - span)
    result = await db_module.query_interface_ts_series(host, start)
    raw = await db_module.query_interface_ts(host, start=start, limit=10_000)
    # The same raw rows, now ordered by interface then time.
    assert sorted(result["data"], key=lambda r: r["id"]) == sorted(raw, key=lambda r: r["id"])
    assert [(r["if_index"], r["sampled_at"]) for r in result["data"]] == sorted(
        (r["if_index"], r["sampled_at"]) for r in raw
    )
    assert [r["if_index"] for r in result["latest"]] == [1, 2]
    assert [r["sampled_at"] for r in result["latest"]] == [_stored(now), _stored(now)]

    # The raw path caps each interface to its newest samples.
    capped = await db_module.query_interface_ts_series(host, start, raw_limit_per=3)
    assert len(capped["data"]) == 6
    assert [r["sampled_at"] for r in capped["data"][:3]] == [
        _stored(now - timedelta(minutes=10)),
        _stored(now - timedelta(minutes=5)),
        _stored(now),
    ]
