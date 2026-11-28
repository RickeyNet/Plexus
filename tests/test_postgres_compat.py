"""Unit tests for the Postgres compat layer that don't need a real database.

These exercise ``_PostgresConnectionCompat`` and the SQL-dialect helpers with a
fake asyncpg connection, pinning the fixes for:
  * ``rollback()`` existing (its absence turned every expected integrity error
    into an AttributeError → 500 on pg)
  * hand-written ``RETURNING`` inserts being fetched (not discarded)
  * allowlisted inserts getting ``RETURNING id`` appended for lastrowid
  * strftime/printf and julianday query sites getting a Postgres branch
"""

from __future__ import annotations

import pytest
import routes.database as db_module
from routes.database import _PostgresConnectionCompat


class _FakeRecord(dict):
    """Stand-in for asyncpg.Record: dict-like with keys()/__getitem__."""


class _FakeTx:
    """Stand-in for asyncpg's Transaction (BEGIN at depth 0, SAVEPOINT below)."""

    def __init__(self, conn):
        self._conn = conn
        self.kind = "tx" if conn.tx_depth == 0 else "savepoint"

    async def start(self):
        self._conn.tx_depth += 1
        self._conn.calls.append((f"{self.kind}.start",))

    async def commit(self):
        self._conn.tx_depth -= 1
        self._conn.calls.append((f"{self.kind}.commit",))

    async def rollback(self):
        self._conn.tx_depth -= 1
        self._conn.calls.append((f"{self.kind}.rollback",))


class _FakeConn:
    def __init__(self):
        self.calls = []
        self.tx_depth = 0
        self.fail_queries: set[str] = set()

    def transaction(self):
        return _FakeTx(self)

    async def fetch(self, query, *params):
        self.calls.append(("fetch", query, params))
        if query in self.fail_queries:
            raise RuntimeError("boom")
        up = query.strip().upper()
        if "RETURNING" in up or up.startswith("SELECT") or up.startswith("WITH"):
            return [_FakeRecord(id=42)]
        return []

    async def execute(self, query, *params):
        self.calls.append(("execute", query, params))
        if query in self.fail_queries:
            raise RuntimeError("boom")
        return "INSERT 0 1"

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_rollback_exists_and_is_noop():
    conn = _PostgresConnectionCompat(_FakeConn())
    # Must not raise AttributeError.
    assert await conn.rollback() is None


@pytest.mark.asyncio
async def test_explicit_returning_insert_is_fetched():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT INTO metric_baselines (host_id) VALUES (?) RETURNING id", (1,))
    assert cur.lastrowid == 42
    row = await cur.fetchone()
    assert row["id"] == 42
    # It must have gone through fetch(), not execute() (which discards rows).
    assert any(c[0] == "fetch" for c in fake.calls)


@pytest.mark.asyncio
async def test_allowlisted_insert_appends_returning_id():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT INTO dashboards (name) VALUES (?)", ("d",))
    assert cur.lastrowid == 42
    fetched_sql = [c[1] for c in fake.calls if c[0] == "fetch"][0]
    assert "RETURNING id" in fetched_sql


@pytest.mark.asyncio
async def test_non_allowlisted_insert_has_no_lastrowid():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, 2))
    assert cur.lastrowid is None
    assert cur.rowcount == 1
    # Should use execute() (status-tag rowcount), not fetch().
    assert any(c[0] == "execute" for c in fake.calls)


@pytest.mark.asyncio
async def test_write_opens_transaction_and_commit_ends_it():
    """DML must run inside a real transaction: BEGIN on first write, COMMIT
    on db.commit() — multi-statement writes were previously autocommit
    (non-atomic) on pg while being atomic on SQLite."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("DELETE FROM t WHERE id = ?", (1,))
    await conn.execute("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, 2))
    assert fake.tx_depth == 1  # one outer tx open across both statements
    await conn.commit()
    assert fake.tx_depth == 0
    assert ("tx.start",) in fake.calls and ("tx.commit",) in fake.calls


@pytest.mark.asyncio
async def test_rollback_undoes_open_transaction():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("DELETE FROM t WHERE id = ?", (1,))
    await conn.rollback()
    assert fake.tx_depth == 0
    assert ("tx.rollback",) in fake.calls
    # A second rollback with nothing open stays a no-op.
    assert await conn.rollback() is None


@pytest.mark.asyncio
async def test_select_only_section_opens_no_transaction():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("SELECT * FROM t WHERE id = ?", (1,))
    assert fake.tx_depth == 0
    assert not any(c[0].startswith("tx.") for c in fake.calls)


@pytest.mark.asyncio
async def test_failed_statement_rolls_back_savepoint_not_transaction():
    """The unique-violation upsert-fallback pattern: a failed statement inside
    the transaction must only undo its own savepoint (SQLite parity — a failed
    statement never aborts the implicit transaction)."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("DELETE FROM t WHERE id = ?", (1,))

    fake.fail_queries.add("UPDATE t SET a = $1")
    with pytest.raises(RuntimeError):
        await conn.execute("UPDATE t SET a = ?", (2,))
    assert ("execute", "ROLLBACK TO SAVEPOINT plexus_stmt", ()) in fake.calls
    assert fake.tx_depth == 1  # outer transaction survives

    # ...and the section can keep writing, then commit atomically.
    await conn.execute("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, 2))
    await conn.commit()
    assert fake.tx_depth == 0


def _sql_calls(fake) -> list:
    """The calls a section sent, as (kind, sql) with transaction events kept."""
    return [c if c[0].startswith(("tx.", "savepoint.")) else (c[0], c[1]) for c in fake.calls]


@pytest.mark.asyncio
async def test_single_write_runs_without_a_savepoint():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("DELETE FROM t WHERE id = ?", (1,))
    await conn.commit()
    assert _sql_calls(fake) == [("tx.start",), ("execute", "DELETE FROM t WHERE id = $1"), ("tx.commit",)]


@pytest.mark.asyncio
async def test_later_statements_share_one_savepoint_round_trip():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("DELETE FROM t WHERE id = ?", (1,))
    await conn.execute("DELETE FROM t WHERE id = ?", (2,))
    await conn.execute("SELECT a FROM t")
    await conn.commit()
    assert _sql_calls(fake) == [
        ("tx.start",),
        ("execute", "DELETE FROM t WHERE id = $1"),
        ("execute", "SAVEPOINT plexus_stmt"),
        ("execute", "DELETE FROM t WHERE id = $1"),
        ("execute", "RELEASE SAVEPOINT plexus_stmt; SAVEPOINT plexus_stmt"),
        ("fetch", "SELECT a FROM t"),
        ("tx.commit",),
    ]


@pytest.mark.asyncio
async def test_failed_first_statement_discards_the_fresh_transaction():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    fake.fail_queries.add("DELETE FROM t WHERE id = $1")
    with pytest.raises(RuntimeError):
        await conn.execute("DELETE FROM t WHERE id = ?", (1,))
    assert fake.tx_depth == 0 and not conn.in_transaction
    assert ("tx.rollback",) in fake.calls
    # Nothing to commit, and the next write opens a new transaction.
    await conn.commit()
    await conn.execute("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, 2))
    assert fake.tx_depth == 1
    await conn.commit()
    assert fake.tx_depth == 0


@pytest.mark.asyncio
async def test_reads_outside_a_transaction_stay_bare():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute("SELECT a FROM t")
    await conn.execute("SELECT b FROM t")
    assert _sql_calls(fake) == [("fetch", "SELECT a FROM t"), ("fetch", "SELECT b FROM t")]


def test_minute_bucket_expr_uses_native_postgres_sql():
    pg = db_module._minute_bucket_expr("received_at", 5)
    assert "to_char" in pg and "extract(minute" in pg.lower()
    assert "strftime" not in pg and "printf" not in pg


def test_minute_bucket_expr_rejects_bad_column():
    with pytest.raises(ValueError):
        db_module._minute_bucket_expr("received_at; DROP TABLE x", 5)


def test_minutes_between_expr_uses_extract_epoch():
    pg = db_module._minutes_between_expr("a.acknowledged_at", "a.created_at")
    assert "EXTRACT(EPOCH" in pg and "julianday" not in pg


@pytest.mark.asyncio
async def test_datetime_modifier_int_param_is_bound_as_text():
    """``datetime('now', '-' || ? || ' days')`` becomes ``$1::text || ' days'``;
    asyncpg infers text for ``$1::text`` and rejects an int ("expected str,
    got int"), so the facade must bind the day count as its string form."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    await conn.execute(
        "DELETE FROM meraki_compliance_results WHERE scanned_at < datetime('now', '-' || ? || ' days') AND id > ?",
        (90, 5),
    )
    sql, params = next((c[1], c[2]) for c in fake.calls if c[0] == "execute")
    assert "$1::text" in sql
    assert params == ("90", 5)  # only the text-cast parameter is converted


@pytest.mark.asyncio
async def test_executemany_binds_text_cast_params_as_text():
    calls = []

    class _ManyConn(_FakeConn):
        async def executemany(self, query, rows):
            calls.append((query, rows))

    conn = _PostgresConnectionCompat(_ManyConn())
    await conn.executemany(
        "DELETE FROM t WHERE ts < datetime('now', '-' || ? || ' hours') AND kind = ?",
        [(1, "a"), (None, "b"), ("3", "c")],
    )
    assert calls[0][1] == [("1", "a"), (None, "b"), ("3", "c")]


def test_coerce_text_cast_params_leaves_other_params_alone():
    assert db_module._coerce_text_cast_params("SELECT $1, $2", (1, 2.5)) == (1, 2.5)
    assert db_module._coerce_text_cast_params("SELECT $2::text", (1, 2.5)) == (1, "2.5")


@pytest.mark.parametrize(
    "table",
    ["meraki_compliance_assignments", "meraki_compliance_results", "software_alerts"],
)
@pytest.mark.asyncio
async def test_new_tables_read_for_lastrowid_get_returning_id(table):
    """Their create helpers return ``cursor.lastrowid``: without the
    allowlist entry it is None on Postgres."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute(f"INSERT INTO {table} (a) VALUES (?)", (1,))
    assert cur.lastrowid == 42


@pytest.mark.parametrize(
    "table",
    [
        "ipam_subnet_utilization",
        "ipam_reconciliation_diffs",
        "interface_ts",
        "trap_syslog_events",
        "interface_inventory",
        "vlan_definitions",
    ],
)
@pytest.mark.asyncio
async def test_lastrowid_reader_tables_are_allowlisted(table):
    """Each table's create helper reads ``cursor.lastrowid`` after INSERT."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute(f"INSERT INTO {table} (a) VALUES (?)", (1,))
    assert cur.lastrowid == 42


@pytest.mark.asyncio
async def test_insert_or_ignore_appends_returning_id():
    """``INSERT OR IGNORE INTO`` must be recognised as an insert into the
    allowlisted table, so it gets ``ON CONFLICT DO NOTHING RETURNING id``."""
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT OR IGNORE INTO ipam_allocations (address) VALUES (?)", ("10.0.0.1",))
    assert cur.lastrowid == 42
    fetched_sql = [c[1] for c in fake.calls if c[0] == "fetch"][0]
    assert "INSERT INTO ipam_allocations" in fetched_sql
    assert fetched_sql.rstrip().endswith("ON CONFLICT DO NOTHING RETURNING id")


@pytest.mark.parametrize(
    ("query", "table"),
    [
        ("INSERT INTO hosts (a) VALUES (1)", "hosts"),
        ("  insert or ignore into Hosts (a) VALUES (1)", "Hosts"),
        ("INSERT OR REPLACE INTO hosts (a) VALUES (1)", "hosts"),
        ("INSERT\n   OR   IGNORE\n INTO hosts(a) VALUES (1)", "hosts"),
    ],
)
def test_insert_table_regex_accepts_conflict_clauses(query, table):
    m = db_module._INSERT_TABLE_RE.match(query)
    assert m is not None and m.group(1) == table


@pytest.mark.asyncio
async def test_ignored_insert_or_ignore_has_no_lastrowid():
    """A skipped ``ON CONFLICT DO NOTHING ... RETURNING id`` returns no rows:
    lastrowid is None and rowcount 0, so callers see the insert was ignored."""

    class _NoRowsConn(_FakeConn):
        async def fetch(self, query, *params):
            self.calls.append(("fetch", query, params))
            return []

    conn = _PostgresConnectionCompat(_NoRowsConn())
    cur = await conn.execute("INSERT OR IGNORE INTO ipam_allocations (address) VALUES (?)", ("10.0.0.1",))
    assert cur.lastrowid is None
    assert cur.rowcount == 0


def test_real_columns_map_to_double_precision():
    ddl = "CREATE TABLE t (\n    cvss REAL NOT NULL DEFAULT 0,\n    lat  REAL,\n    lng REAL)"
    for convert in (db_module._convert_sqlite_ddl_to_postgres, db_module._convert_sqlite_schema_to_postgres):
        out = convert(ddl)
        assert "REAL" not in out
        assert out.count("DOUBLE PRECISION") == 3
    alter = db_module._convert_sqlite_ddl_to_postgres("ALTER TABLE t ADD COLUMN score REAL")
    assert alter == "ALTER TABLE t ADD COLUMN score DOUBLE PRECISION"


def test_real_mapping_leaves_identifiers_alone():
    ddl = "CREATE TABLE t (real_ip TEXT, is_real INTEGER, surreal REAL)"
    out = db_module._convert_sqlite_ddl_to_postgres(ddl)
    assert out == "CREATE TABLE t (real_ip TEXT, is_real INTEGER, surreal DOUBLE PRECISION)"


def test_postgres_schema_has_no_float4_columns():
    assert db_module._REAL_TYPE_RE.search(db_module.POSTGRES_SCHEMA) is None


# -- Statement translation cache -------------------------------------------------


def _legacy_translate(query: str, params: tuple) -> tuple[str, str, tuple]:
    """The per-call translation ``execute()`` did before it was cached:
    (asyncpg method, SQL, bound params)."""
    params = db_module._strip_nuls_from_params(tuple(params))
    stripped = query.strip()
    upper = stripped.upper()
    if upper.startswith("CREATE") or upper.startswith("ALTER"):
        query = db_module._convert_sqlite_ddl_to_postgres(query)
    converted = db_module._convert_qmark_to_dollar_params(query)
    params = db_module._coerce_text_cast_params(converted, params)
    if upper.startswith("SELECT") or upper.startswith("WITH"):
        return "fetch", converted, params
    has_returning = "RETURNING" in upper
    if upper.startswith("INSERT") and not has_returning:
        m = db_module._INSERT_TABLE_RE.match(stripped)
        if (m.group(1).lower() if m else "") in db_module._INSERT_ID_TABLES:
            converted = f"{converted.rstrip()} RETURNING id"
            has_returning = True
    return ("fetch" if has_returning else "execute"), converted, params


_TRANSLATION_CASES = [
    ("SELECT * FROM hosts WHERE id = ?", (1,)),
    ("SELECT name FROM t WHERE note = 'why?' AND id = ? AND tag = 'a''?b'", (7,)),
    ("  with x AS (SELECT ? AS v) SELECT v FROM x", ("192.0.2.1",)),
    ("SELECT id FROM t WHERE created_at::timestamptz > NOW() - INTERVAL '1 day' AND id = ?", (3,)),
    ("DELETE FROM t WHERE created_at < datetime('now', '-' || ? || ' days')", (30,)),
    ("DELETE FROM t WHERE ts < datetime('now', ? || ' hours') AND kind = ?", (-4, "a")),
    ("SELECT * FROM t WHERE ts > datetime('now', '-7 days')", ()),
    ("SELECT * FROM t WHERE ts > datetime('now', ?)", ("-1 hours",)),
    ("UPDATE t SET due = datetime(started_at, '+' || ttl || ' seconds') WHERE id = ?", (2,)),
    ("UPDATE t SET seen = datetime('now'), note = ? WHERE id = ?", ("x\x00y", 9)),
    ("INSERT INTO hosts (hostname, ip_address) VALUES (?, ?)", ("sw1.example.com", "192.0.2.10")),
    ("INSERT OR IGNORE INTO ipam_allocations (address) VALUES (?)", ("198.51.100.4",)),
    ("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, None)),
    ("INSERT INTO metric_baselines (host_id) VALUES (?) RETURNING id", (1,)),
    (
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY AUTOINCREMENT, v REAL, at TEXT DEFAULT (datetime('now')))",
        (),
    ),
    ("ALTER TABLE t ADD COLUMN blob_col BLOB", ()),
    ("CREATE INDEX IF NOT EXISTS idx_t_open ON t(k) WHERE acknowledged = 0", ()),
    ("DROP INDEX IF EXISTS idx_t_old", ()),
]


@pytest.mark.parametrize(("query", "params"), _TRANSLATION_CASES)
@pytest.mark.asyncio
async def test_cached_translation_matches_uncached_path(query, params):
    expected = _legacy_translate(query, params)
    db_module._plan_statement.cache_clear()
    for _ in range(2):  # a miss, then a cache hit
        fake = _FakeConn()
        conn = _PostgresConnectionCompat(fake)
        await conn.execute(query, params)
        sent = next(c for c in fake.calls if c[0] in ("fetch", "execute"))
        assert sent == expected
    assert db_module._plan_statement.cache_info().hits >= 1


@pytest.mark.asyncio
async def test_cached_plan_rebinds_params_per_call():
    """The plan holds only text-derived positions; each call's own values
    are coerced, so a None or str on one call never leaks into the next."""
    sql = "DELETE FROM t WHERE ts < datetime('now', '-' || ? || ' days') AND id = ?"
    sent = []
    for params in ((5, 1), (None, 2), ("7", 3)):
        fake = _FakeConn()
        await _PostgresConnectionCompat(fake).execute(sql, params)
        sent.append(next(c[2] for c in fake.calls if c[0] == "execute"))
    assert sent == [("5", 1), (None, 2), ("7", 3)]


def test_executemany_plan_matches_uncached_path():
    sql = "INSERT INTO t (a, b, seen) VALUES (?, ?, datetime('now', ? || ' hours'))"
    converted, casts = db_module._plan_executemany(sql)
    assert converted == db_module._convert_qmark_to_dollar_params(sql)
    assert db_module._apply_text_casts(casts, (1, 2, 3)) == db_module._coerce_text_cast_params(converted, (1, 2, 3))


def test_statement_cache_is_bounded():
    assert db_module._plan_statement.cache_parameters()["maxsize"] == db_module._STATEMENT_CACHE_SIZE
    assert db_module._plan_executemany.cache_parameters()["maxsize"] == db_module._STATEMENT_CACHE_SIZE


# -- Pool settings ---------------------------------------------------------------


_POOL_ENV = ("APP_DB_POOL_MAX", "APP_DB_POOL_MIN", "APP_DB_POOL_ACQUIRE_TIMEOUT", "APP_DB_STATEMENT_CACHE_SIZE")


def test_pool_settings_defaults(monkeypatch):
    for name in _POOL_ENV:
        monkeypatch.delenv(name, raising=False)
    assert db_module._db_pool_settings() == {
        "min_size": 2,
        "max_size": 30,
        "acquire_timeout": 30.0,
        "statement_cache_size": 500,
    }


def test_pool_settings_read_env(monkeypatch):
    monkeypatch.setenv("APP_DB_POOL_MAX", "40")
    monkeypatch.setenv("APP_DB_POOL_MIN", "5")
    monkeypatch.setenv("APP_DB_POOL_ACQUIRE_TIMEOUT", "12")
    monkeypatch.setenv("APP_DB_STATEMENT_CACHE_SIZE", "0")
    assert db_module._db_pool_settings() == {
        "min_size": 5,
        "max_size": 40,
        "acquire_timeout": 12.0,
        "statement_cache_size": 0,
    }


def test_pool_settings_clamp_and_ignore_garbage(monkeypatch):
    monkeypatch.setenv("APP_DB_POOL_MAX", "5000")
    monkeypatch.setenv("APP_DB_POOL_MIN", "999")
    monkeypatch.setenv("APP_DB_POOL_ACQUIRE_TIMEOUT", "0")
    monkeypatch.setenv("APP_DB_STATEMENT_CACHE_SIZE", "lots")
    settings = db_module._db_pool_settings()
    assert settings["max_size"] == db_module._DB_POOL_MAX_LIMIT < 100
    assert settings["min_size"] == settings["max_size"]  # min never exceeds max
    assert settings["acquire_timeout"] == 1.0
    assert settings["statement_cache_size"] == 500

    monkeypatch.setenv("APP_DB_POOL_MAX", "-3")
    assert db_module._db_pool_settings()["max_size"] == 1
