"""Native time and BIGINT keys for the sample tables (migration 0144).

``metric_samples`` and ``interface_ts`` store ``sampled_at`` as TIMESTAMPTZ
and all three swapped tables (with ``flow_records``) take BIGINT keys. The
pool binds and reads ``timestamptz`` as text, so callers pass and get the
same strings as before. An upgraded database swaps each old table for a new
one at startup without copying a row; ``netcontrol.sample_history`` moves
the old rows afterwards, and jobs that store aggregates of the raw history
wait for it.
"""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol import sample_history
from netcontrol.routes import baseline_alerting, billing, graph_export, metrics_engine

import pg_raw

migration = importlib.import_module("routes.migrations.0144_sample_tables_bigint_timestamptz")

TABLES = ("metric_samples", "interface_ts", "flow_records")
FMT = "%Y-%m-%d %H:%M:%S"


@pytest.fixture(autouse=True)
def _fresh_move_state(monkeypatch):
    monkeypatch.setattr(sample_history, "_complete", set())
    monkeypatch.setattr(sample_history, "BATCH_PAUSE_SECONDS", 0)
    monkeypatch.setattr(sample_history, "RETRY_SECONDS", 0.05)


async def _host(name: str = "ts-sw.example.com", address: str = "192.0.2.10") -> int:
    groups = {g["name"]: g["id"] for g in await db_module.get_all_groups()}
    gid = groups.get("ts-group") or await db_module.create_group("ts-group")
    return await db_module.add_host(gid, name, address)


async def _fetch(sql: str, params: tuple = ()) -> list[dict]:
    db = await db_module.get_db()
    try:
        cursor = await db.execute(sql, params)
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def _exec(sql: str, params: tuple = ()) -> None:
    db = await db_module.get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
    finally:
        await db.close()


async def _migrate() -> None:
    db = await db_module.get_db()
    try:
        await migration.up(db)
    finally:
        await db.close()


async def _shape(table: str) -> dict:
    """Columns, indexes and constraints of ``table`` as the catalog has them."""
    columns = [
        tuple(r)
        for r in await pg_raw.fetch(
            """SELECT column_name, data_type, column_default, is_nullable FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position""",
            table,
        )
    ]
    indexes = {
        r["indexname"]: r["indexdef"]
        for r in await pg_raw.fetch(
            "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1",
            table,
        )
    }
    constraints = {
        r["conname"]: r["def"]
        for r in await pg_raw.fetch(
            "SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid = to_regclass($1)",
            table,
        )
    }
    return {"columns": columns, "indexes": indexes, "constraints": constraints}


# The three tables as a database from before migration 0144 has them: SERIAL
# keys, TEXT time, int4 flow counters, the foreign keys init_db names, the
# indexes of SCHEMA and the older migrations (0142 dropped the flow src/dst
# ones; one is left here, as a database that skipped it would have it).
_LEGACY_DDL = (
    "DROP TABLE metric_samples",
    "DROP TABLE interface_ts",
    "DROP TABLE flow_records",
    """CREATE TABLE metric_samples (
        id SERIAL PRIMARY KEY, host_id INTEGER NOT NULL, metric_name TEXT NOT NULL,
        labels_json TEXT NOT NULL DEFAULT '{}', value DOUBLE PRECISION NOT NULL,
        sampled_at TEXT NOT NULL DEFAULT NOW())""",
    "ALTER TABLE metric_samples ADD CONSTRAINT fk_metric_samples_host_id_hosts "
    "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE",
    "CREATE INDEX idx_metric_samples_lookup ON metric_samples (metric_name, sampled_at)",
    "CREATE INDEX idx_metric_samples_host ON metric_samples (host_id, metric_name, sampled_at)",
    "CREATE INDEX idx_metric_samples_sampled_at ON metric_samples (sampled_at)",
    """CREATE TABLE interface_ts (
        id SERIAL PRIMARY KEY, host_id INTEGER NOT NULL, if_index INTEGER NOT NULL,
        if_name TEXT NOT NULL DEFAULT '', if_speed_mbps INTEGER DEFAULT 0,
        in_octets BIGINT DEFAULT 0, out_octets BIGINT DEFAULT 0,
        in_rate_bps DOUBLE PRECISION DEFAULT NULL, out_rate_bps DOUBLE PRECISION DEFAULT NULL,
        utilization_pct DOUBLE PRECISION DEFAULT NULL, sampled_at TEXT NOT NULL DEFAULT NOW())""",
    "ALTER TABLE interface_ts ADD CONSTRAINT fk_interface_ts_host_id_hosts "
    "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE",
    "CREATE INDEX idx_interface_ts_lookup ON interface_ts (host_id, if_index, sampled_at)",
    "CREATE INDEX idx_interface_ts_sampled_at ON interface_ts (sampled_at)",
    """CREATE TABLE flow_records (
        id SERIAL PRIMARY KEY, exporter_ip TEXT NOT NULL, host_id INTEGER,
        flow_type TEXT NOT NULL DEFAULT 'netflow', src_ip TEXT NOT NULL DEFAULT '',
        dst_ip TEXT NOT NULL DEFAULT '', src_port INTEGER DEFAULT 0, dst_port INTEGER DEFAULT 0,
        protocol INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,
        src_as INTEGER DEFAULT 0, dst_as INTEGER DEFAULT 0, input_if INTEGER DEFAULT 0,
        output_if INTEGER DEFAULT 0, tos INTEGER DEFAULT 0, tcp_flags INTEGER DEFAULT 0,
        start_time TEXT NOT NULL DEFAULT NOW(), end_time TEXT NOT NULL DEFAULT NOW(),
        received_at TEXT NOT NULL DEFAULT NOW())""",
    "ALTER TABLE flow_records ADD CONSTRAINT fk_flow_records_host_id_hosts "
    "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL",
    "CREATE INDEX idx_flow_received ON flow_records(received_at)",
    "CREATE INDEX idx_flow_exporter ON flow_records(exporter_ip, received_at)",
    "CREATE INDEX idx_flow_records_flow_type_received ON flow_records(flow_type, received_at)",
    "CREATE INDEX idx_flow_host_received ON flow_records(host_id, received_at)",
    "CREATE INDEX idx_flow_src ON flow_records(src_ip, received_at)",
)


async def _make_legacy() -> None:
    for stmt in _LEGACY_DDL:
        await pg_raw.execute(stmt)


def _forms(now: datetime) -> dict[str, tuple[str, datetime | None]]:
    """Old time texts and the instant each stands for (None: deleted)."""
    a, b, c = now - timedelta(hours=1), now - timedelta(hours=2), now - timedelta(hours=3)
    return {
        "pg": (a.strftime(FMT) + ".123456+00", a + timedelta(microseconds=123456)),
        "naive": (b.strftime(FMT), b),
        "iso": (c.strftime("%Y-%m-%dT%H:%M:%S+00:00"), c),
        "garbage": ("not a time", None),
        "no_such_day": ("2026-02-30 10:00:00", None),
    }


async def _seed_legacy(host_id: int, now: datetime) -> dict:
    """Old rows in every table; returns {table: {id: expected instant or None}}."""
    expected: dict[str, dict[int, datetime | None]] = {t: {} for t in TABLES}
    forms = _forms(now)
    ids = (10, 20, 30, 40, 50)
    for i, (text, at) in zip(ids, forms.values(), strict=True):
        await pg_raw.execute(
            "INSERT INTO metric_samples (id, host_id, metric_name, labels_json, value, sampled_at) "
            "VALUES ($1, $2, 'cpu_percent', '{}', $3, $4)",
            i,
            host_id,
            float(i),
            text,
        )
        expected["metric_samples"][i] = at
        await pg_raw.execute(
            "INSERT INTO interface_ts (id, host_id, if_index, if_name, in_rate_bps, sampled_at) "
            "VALUES ($1, $2, 1, 'Gi0/1', $3, $4)",
            i,
            host_id,
            float(i),
            text,
        )
        expected["interface_ts"][i] = at
        await pg_raw.execute(
            "INSERT INTO flow_records (id, exporter_ip, host_id, src_ip, dst_ip, bytes, received_at) "
            "VALUES ($1, '192.0.2.10', $2, '198.51.100.1', '203.0.113.1', $3, $4)",
            i,
            host_id,
            i * 1000,
            text,
        )
        expected["flow_records"][i] = at
    # Past retention: metric samples 48 h, interface samples 30 d, flows 48 h.
    expired = {
        "metric_samples": now - timedelta(hours=72),
        "interface_ts": now - timedelta(days=40),
        "flow_records": now - timedelta(hours=72),
    }
    await pg_raw.execute(
        "INSERT INTO metric_samples (id, host_id, metric_name, value, sampled_at) VALUES (60, $1, 'cpu_percent', 1, $2)",
        host_id,
        expired["metric_samples"].strftime(FMT),
    )
    await pg_raw.execute(
        "INSERT INTO interface_ts (id, host_id, if_index, sampled_at) VALUES (60, $1, 1, $2)",
        host_id,
        expired["interface_ts"].strftime(FMT),
    )
    await pg_raw.execute(
        "INSERT INTO flow_records (id, exporter_ip, received_at) VALUES (60, '192.0.2.10', $1)",
        expired["flow_records"].strftime(FMT),
    )
    for table in TABLES:
        expected[table][60] = None
        # Ids up to 100 were handed out (later rows deleted): new ids start above.
        await pg_raw.execute(f"SELECT setval('{table}_id_seq', 100)")  # noqa: S608 - fixed names
    return expected


async def _run_move() -> dict:
    return await sample_history.move_sample_history()


# ── The codec ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "printed"),
    [
        ("2026-01-02 03:04:05", "2026-01-02 03:04:05+00"),
        ("2026-01-02 03:04:05.123456+00", "2026-01-02 03:04:05.123456+00"),
        ("2026-01-02T05:04:05+02:00", "2026-01-02 03:04:05+00"),
        (datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "2026-01-02 03:04:05+00"),
        (datetime(2026, 1, 2, 3, 4, 5), "2026-01-02 03:04:05+00"),
    ],
)
async def test_timestamptz_binds_str_and_datetime_and_reads_postgres_text(value, printed):
    rows = await _fetch("SELECT CAST(? AS TIMESTAMPTZ) AS at", (value,))
    assert rows[0]["at"] == printed


async def test_timestamptz_text_is_the_text_now_wrote_into_text_columns():
    rows = await _fetch("SELECT NOW() AS native, NOW()::text AS text")
    assert rows[0]["native"] == rows[0]["text"]


async def test_codec_survives_pooled_connection_reuse_and_full_reset():
    pool = await asyncpg.create_pool(
        db_module.APP_DATABASE_URL,
        min_size=1,
        max_size=1,
        server_settings={"timezone": "UTC"},
        **db_module._pool_connection_options(),
    )
    try:
        async with pool.acquire() as conn:
            first_pid = conn.get_server_pid()
            assert await conn.fetchval("SELECT $1::timestamptz", "2026-01-02 03:04:05") == "2026-01-02 03:04:05+00"
            # A session-state statement makes the release run the full reset.
            conn.plexus_mark_session_state()
            await conn.execute("SET application_name = 'plexus-ts-test'")
        async with pool.acquire() as conn:
            assert conn.get_server_pid() == first_pid
            assert await conn.fetchval("SELECT $1::timestamptz", datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == (
                "2026-01-02 03:04:05+00"
            )
    finally:
        await pool.close()


async def test_a_time_bound_postgres_cannot_read_is_a_client_error():
    from netcontrol.db_errors import BAD_TIME, client_error_for

    with pytest.raises(asyncpg.InvalidDatetimeFormatError) as caught:
        await db_module.query_interface_ts(1, start="yesterday-ish")
    assert client_error_for(caught.value) == BAD_TIME


# ── Fresh database ───────────────────────────────────────────────────────────


async def test_fresh_database_has_the_new_types_and_migration_leaves_it_alone():
    before = {t: await _shape(t) for t in TABLES}
    types = {(t, c[0]): c[1] for t in TABLES for c in before[t]["columns"] if c[0] in ("id", "sampled_at", "bytes")}
    assert types == {
        ("metric_samples", "id"): "bigint",
        ("metric_samples", "sampled_at"): "timestamp with time zone",
        ("interface_ts", "id"): "bigint",
        ("interface_ts", "sampled_at"): "timestamp with time zone",
        ("flow_records", "id"): "bigint",
        ("flow_records", "bytes"): "bigint",
    }
    await _migrate()
    assert {t: await _shape(t) for t in TABLES} == before
    for table in TABLES:
        assert not await pg_raw.table_exists(f"{table}{migration.OLD_SUFFIX}")
    assert migration.OLD_SUFFIX == db_module.SAMPLE_TABLE_MOVES["metric_samples"].old_table[len("metric_samples") :]


# ── Legacy database: swap, then move ─────────────────────────────────────────


async def test_legacy_database_swaps_then_moves_every_row_and_matches_a_fresh_one():
    fresh = {t: await _shape(t) for t in TABLES}
    host_id = await _host()
    await _make_legacy()
    now = datetime.now(UTC).replace(microsecond=0)
    expected = await _seed_legacy(host_id, now)

    await _migrate()
    # The swap is catalog-only: the old rows wait in the renamed table, which
    # keeps only its primary key.
    for table in TABLES:
        old = f"{table}{migration.OLD_SUFFIX}"
        assert await pg_raw.fetchval(f"SELECT COUNT(*) FROM {old}") == 6  # noqa: S608 - fixed names
        assert await pg_raw.fetchval(f"SELECT COUNT(*) FROM {table}") == 0  # noqa: S608
        assert set((await _shape(old))["indexes"]) == {f"{old}_pkey"}
        assert "swapped_at=" in await pg_raw.fetchval("SELECT obj_description(to_regclass($1), 'pg_class')", old)
    # A second run is a no-op.
    swapped = await db_module.get_sample_move_swapped_at("metric_samples")
    await _migrate()
    assert await db_module.get_sample_move_swapped_at("metric_samples") == swapped
    assert await pg_raw.fetchval("SELECT COUNT(*) FROM metric_samples_pre0144") == 6
    # The next start re-applies SCHEMA (tables, indexes, foreign keys) over
    # the swapped tables without a change.
    shapes = {t: await _shape(t) for t in TABLES}
    await db_module.init_db()
    assert {t: await _shape(t) for t in TABLES} == shapes

    # New rows go to the new table, above every id the old one handed out.
    new_sample = await db_module.create_metric_sample(host_id, "cpu_percent", 99.0)
    new_iface = await db_module.create_interface_ts_sample(host_id, 1, "Gi0/1", 1000, 0, 0, 5.0, 5.0, 1.0)
    assert new_sample == 101 and new_iface == 101
    # Interface counters past int4 are stored now.
    await _exec(
        "INSERT INTO flow_records (exporter_ip, bytes, packets, src_as, input_if) VALUES (?, ?, ?, ?, ?)",
        ("192.0.2.10", 5_000_000_000, 4_294_967_295, 4_200_000_000, 4_294_967_295),
    )

    totals = await _run_move()
    assert totals == {t: {"moved": 3, "dropped": 3} for t in TABLES}
    for table in TABLES:
        assert not await pg_raw.table_exists(f"{table}{migration.OLD_SUFFIX}")
        assert await _shape(table) == fresh[table], table

    keep = {i: at for i, at in expected["metric_samples"].items() if at is not None}
    rows = await _fetch("SELECT id, sampled_at, value FROM metric_samples WHERE id < 100 ORDER BY id")
    assert {r["id"]: datetime.fromisoformat(r["sampled_at"]) for r in rows} == keep
    assert [r["value"] for r in rows] == [10.0, 20.0, 30.0]
    rows = await _fetch("SELECT id, sampled_at FROM interface_ts WHERE id < 100 ORDER BY id")
    assert {r["id"]: datetime.fromisoformat(r["sampled_at"]) for r in rows} == keep
    # Flow times stay TEXT: moved as they were written.
    texts = {i: text for i, (text, _at) in zip((10, 20, 30, 40, 50), _forms(now).values(), strict=True)}
    rows = await _fetch("SELECT id, received_at, bytes FROM flow_records WHERE id < 100 ORDER BY id")
    assert {r["id"]: r["received_at"] for r in rows} == {i: texts[i] for i in keep}
    assert [r["bytes"] for r in rows] == [10_000, 20_000, 30_000]

    # Readers see the moved and the new rows alike, in time order.
    series = await db_module.query_interface_ts(host_id, if_index=1)
    assert [r["id"] for r in series] == [101, 10, 20, 30]
    # The move is done: nothing left to do on the next start.
    assert await _run_move() == {}


async def test_two_movers_at_once_move_each_row_once(monkeypatch):
    monkeypatch.setattr(sample_history, "BATCH_ROWS", 1)
    host_id = await _host()
    await _make_legacy()
    now = datetime.now(UTC).replace(microsecond=0)
    await _seed_legacy(host_id, now)
    await _migrate()
    first, second = await asyncio.gather(_run_move(), _run_move())
    for table in TABLES:
        moved = first.get(table, {}).get("moved", 0) + second.get(table, {}).get("moved", 0)
        assert moved == 3, (table, first, second)
        assert await pg_raw.fetchval(f"SELECT COUNT(*) FROM {table}") == 3  # noqa: S608 - fixed names
        assert not await pg_raw.table_exists(f"{table}{migration.OLD_SUFFIX}")


async def test_migration_drops_an_old_table_that_has_no_rows():
    await _make_legacy()
    await _migrate()
    for table in TABLES:
        assert not await pg_raw.table_exists(f"{table}{migration.OLD_SUFFIX}")
        assert await db_module.get_sample_move_swapped_at(table) is None
    assert await sample_history.history_complete("metric_samples", "2000-01-01 00:00:00")


# ── Derived data waits for the history ───────────────────────────────────────


async def _legacy_with_pending_history(host_id: int) -> datetime:
    """A swapped database whose old metric/interface rows are not moved
    yet; returns the swap instant."""
    await _make_legacy()
    await pg_raw.execute(
        "INSERT INTO metric_samples (host_id, metric_name, value, sampled_at) VALUES ($1, 'cpu_percent', 1, $2)",
        host_id,
        (datetime.now(UTC) - timedelta(hours=30)).strftime(FMT),
    )
    await pg_raw.execute(
        "INSERT INTO interface_ts (host_id, if_index, in_rate_bps, sampled_at) VALUES ($1, 1, 1, $2)",
        host_id,
        (datetime.now(UTC) - timedelta(hours=30)).strftime(FMT),
    )
    await _migrate()
    swapped = await db_module.get_sample_move_swapped_at("metric_samples")
    assert swapped is not None
    return datetime.fromisoformat(swapped)


async def test_rollup_of_a_window_before_the_swap_waits_for_the_move():
    host_id = await _host()
    swapped = await _legacy_with_pending_history(host_id)
    hour = swapped.replace(minute=0, second=0, microsecond=0)
    # Two old samples of the swap's hour are still in the old table, one new
    # sample (written at the swap) is in the new one. (Put in after the swap,
    # to know its hour, with ids below the old table's.)
    for row_id, value in ((-2, 1.0), (-1, 3.0)):
        await pg_raw.execute(
            "INSERT INTO metric_samples_pre0144 (id, host_id, metric_name, value, sampled_at) "
            "VALUES ($1, $2, 'cpu_percent', $3, $4)",
            row_id,
            host_id,
            value,
            hour.strftime(FMT),
        )
    await _exec(
        "INSERT INTO metric_samples (host_id, metric_name, value, sampled_at) VALUES (?, ?, ?, ?)",
        (host_id, "cpu_percent", 5.0, swapped),
    )
    start, end = hour.strftime(FMT), (hour + timedelta(hours=1)).strftime(FMT)

    assert await metrics_engine._downsample_window("hourly", start, end) == 0
    assert await db_module.query_metric_rollups("cpu_percent", time_window="hourly") == []
    # A window that starts at or after the swap has all its rows already.
    assert await sample_history.history_complete("metric_samples", swapped)
    assert not await sample_history.history_complete("metric_samples", swapped - timedelta(seconds=1))

    # The move rolls the deferred window up once every old row is in.
    real = metrics_engine.roll_up_windows_around
    calls = []

    async def _rollups_after_move(at):
        calls.append(at)
        return await real(at, now=hour + timedelta(hours=1, minutes=1))

    import unittest.mock

    with unittest.mock.patch.object(metrics_engine, "roll_up_windows_around", _rollups_after_move):
        await _run_move()
    assert len(calls) == 1
    rows = await db_module.query_metric_rollups("cpu_percent", time_window="hourly")
    assert [(r["period_start"], r["sample_count"], r["val_min"], r["val_max"]) for r in rows] == [(start, 3, 1.0, 5.0)]
    # The regular rollup of the same window, now allowed, adds nothing.
    assert await metrics_engine._downsample_window("hourly", start, end) == 0
    assert len(await db_module.query_metric_rollups("cpu_percent", time_window="hourly")) == 1


async def test_baselines_billing_and_interface_reports_wait_for_the_move():
    host_id = await _host()
    await _legacy_with_pending_history(host_id)
    at = datetime.now(UTC).replace(minute=5, second=0, microsecond=0) - timedelta(hours=1)
    for minutes in (0, 10, 20):
        await _exec(
            "INSERT INTO metric_samples (host_id, metric_name, value, sampled_at) VALUES (?, ?, ?, ?)",
            (host_id, "cpu_percent", 10.0 + minutes, (at + timedelta(minutes=minutes)).strftime(FMT)),
        )

    assert await baseline_alerting.compute_baselines_for_host(host_id, "cpu_percent", 14) == 0
    assert await db_module.get_baselines_for_host(host_id, "cpu_percent") == []
    circuit = {"id": 1, "host_id": host_id, "if_index": 1, "billing_day": 1, "billing_cycle": "monthly"}
    with pytest.raises(HTTPException) as refused:
        await billing.generate_billing_for_circuit(circuit, "2026-01-01T00:00:00", "2026-02-01T00:00:00")
    assert refused.value.status_code == 503
    assert not await sample_history.history_complete("interface_ts")

    await _run_move()
    # The old sample (30 h old) moved; the baselines see all four.
    assert await baseline_alerting.compute_baselines_for_host(host_id, "cpu_percent", 14) > 0
    stored = await db_module.get_baselines_for_host(host_id, "cpu_percent")
    assert max(b["sample_count"] for b in stored) >= 3
    assert await sample_history.history_complete("interface_ts")


# ── Statements on the converted tables ───────────────────────────────────────


async def _sample_rows(host_id: int) -> datetime:
    now = datetime.now(UTC).replace(microsecond=0)
    for hours, value in ((1, 10.0), (2, 20.0), (60, 30.0)):
        await _exec(
            "INSERT INTO metric_samples (host_id, metric_name, labels_json, value, sampled_at) VALUES (?, ?, ?, ?, ?)",
            (host_id, "cpu_percent", "{}", value, now - timedelta(hours=hours)),
        )
    for days, rate in ((0, 100.0), (2, 200.0), (40, 300.0)):
        await _exec(
            "INSERT INTO interface_ts (host_id, if_index, if_name, if_speed_mbps, in_rate_bps, out_rate_bps, "
            "utilization_pct, sampled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                host_id,
                1,
                "Gi0/1",
                1000,
                rate,
                rate / 2,
                rate / 10,
                (now - timedelta(days=days, minutes=5)).strftime(FMT),
            ),
        )
    return now


async def test_retention_deletes_use_native_time_and_the_time_index():
    host_id = await _host()
    await _sample_rows(host_id)
    assert await db_module.delete_old_metric_samples(hours=48) == 1
    assert await db_module.delete_old_interface_ts(30) == 1
    assert [r["value"] for r in await _fetch("SELECT value FROM metric_samples ORDER BY value")] == [10.0, 20.0]
    assert len(await _fetch("SELECT id FROM interface_ts")) == 2

    # The chunked retention delete can use the sampled_at index (seq scans
    # off: on a few rows the planner would read the table anyway).
    for table, unit, index in (
        ("metric_samples", "hours", "idx_metric_samples_sampled_at"),
        ("interface_ts", "days", "idx_interface_ts_sampled_at"),
    ):
        where = f"sampled_at < {db_module._now_minus_expr(unit)}"
        sql = db_module._convert_qmark_to_dollar_params(
            f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {where} LIMIT ?)"  # noqa: S608
        )
        conn = await pg_raw.connect()
        try:
            await conn.execute("SET enable_seqscan = off")
            plan = "\n".join(r[0] for r in await conn.fetch(f"EXPLAIN {sql}", 48, 5000))
        finally:
            await conn.close()
        assert index in plan, plan


async def test_readers_of_the_converted_tables_filter_by_native_time():
    host_id = await _host()
    now = await _sample_rows(host_id)

    summary = await db_module.get_interface_error_summary(host_id, days=1)
    assert summary == []
    util = await db_module.get_interface_utilization_summary(host_id, days=1)
    assert [(u["if_index"], u["sample_count"], u["peak_in_bps"]) for u in util] == [(1, 1, 100.0)]
    report = await db_module.generate_interface_report_data(host_id=host_id, days=3)
    assert [(r["if_index"], r["samples"], r["peak_in_bps"]) for r in report] == [(1, 2, 200.0)]
    start = (now - timedelta(days=3)).strftime(FMT)
    top = await db_module.get_top_interfaces_by_bandwidth(start=start, limit=5)
    assert [(t["host_id"], t["if_index"], t["peak_bps"]) for t in top] == [(host_id, 1, 200.0)]
    detail = await db_module.get_port_detail_ts(host_id, 1, start=start, end=now.isoformat())
    assert detail["summary"]["sample_count"] == 2
    assert [s["in_rate_bps"] for s in detail["samples"]] == [200.0, 100.0]
    # Text bounds in the ISO form compare as instants, not as text.
    iso_start = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S")
    samples = await db_module.query_metric_samples("cpu_percent", host_ids=[host_id], start=iso_start)
    assert [s["value"] for s in samples] == [10.0, 20.0]
    assert all(datetime.fromisoformat(s["sampled_at"]).tzinfo is not None for s in samples)

    # Graph export reads metric_samples, then interface_ts for an interface graph.
    data = await graph_export._fetch_metric_data(host_id, "cpu_percent", "", 24)
    assert [p["value"] for p in data] == [20.0, 10.0]
    data = await graph_export._fetch_metric_data(host_id, "if_in_bps", "1", 24)
    assert [p["value"] for p in data] == [100.0]
