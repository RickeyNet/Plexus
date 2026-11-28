"""
Migration 0144: BIGINT keys and native time for the three biggest tables.

``metric_samples`` and ``interface_ts`` get ``id BIGSERIAL`` and
``sampled_at TIMESTAMPTZ`` (the TEXT they held, ``NOW()::text``, took about
29 bytes in the heap and in every index on it, against 8, and range scans
parsed it per row). ``flow_records`` gets ``id BIGSERIAL`` and BIGINT byte,
packet, AS and interface columns (unsigned 32-bit or wider on the wire);
its time columns stay TEXT. A SERIAL key stops at 2,147,483,647 and deleted
rows do not give values back.

Changing the types in place rewrites each table at startup, which on a
large fleet takes longer than the container health check allows. So the
migration swaps tables instead, catalog-only, in one transaction:

  * the table is renamed to ``<table>_pre0144``, with its sequence and
    primary key; its other indexes are dropped (the background mover only
    reads it by primary key); its comment records when the swap happened;
  * a new table with the standard name, columns, foreign key, indexes and
    index names a fresh database has takes its place;
  * the new sequence starts above the old table's highest id, so a row
    written from now on sorts after every old row, and moved rows keep
    their ids.

No row is copied here: ``netcontrol.sample_history`` moves the old rows in
the background, newest first, and drops each old table when it is empty
(an old table without rows is dropped here). A table that already has the
new types (a fresh database, whose SCHEMA has them, or a second run) is
left alone.
"""

from __future__ import annotations

VERSION = 144
DESCRIPTION = "Swap metric_samples, interface_ts and flow_records for BIGINT/TIMESTAMPTZ tables; history moves later"

OLD_SUFFIX = "_pre0144"

# One entry per table: the column whose type tells an old table from a new
# one (and the type it has in an old one), the new table's columns in the
# SQLite-style dialect of SCHEMA (the foreign key apart, added under the
# name init_db gives it), and the index set of a fresh database (SCHEMA
# plus migrations 0036, 0060, 0062, 0063, 0121 and 0142).
TABLES: tuple[dict, ...] = (
    {
        "table": "metric_samples",
        "marker": ("sampled_at", "text"),
        "columns": """
            id              BIGINT PRIMARY KEY AUTOINCREMENT,
            host_id         INTEGER NOT NULL,
            metric_name     TEXT    NOT NULL,
            labels_json     TEXT    NOT NULL DEFAULT '{}',
            value           REAL    NOT NULL,
            sampled_at      TIMESTAMPTZ NOT NULL DEFAULT (datetime('now'))""",
        "foreign_key": ("host_id", "CASCADE"),
        "indexes": (
            ("idx_metric_samples_lookup", "metric_name, sampled_at"),
            ("idx_metric_samples_host", "host_id, metric_name, sampled_at"),
            ("idx_metric_samples_sampled_at", "sampled_at"),
        ),
    },
    {
        "table": "interface_ts",
        "marker": ("sampled_at", "text"),
        "columns": """
            id              BIGINT PRIMARY KEY AUTOINCREMENT,
            host_id         INTEGER NOT NULL,
            if_index        INTEGER NOT NULL,
            if_name         TEXT    NOT NULL DEFAULT '',
            if_speed_mbps   INTEGER DEFAULT 0,
            in_octets       BIGINT  DEFAULT 0,
            out_octets      BIGINT  DEFAULT 0,
            in_rate_bps     REAL    DEFAULT NULL,
            out_rate_bps    REAL    DEFAULT NULL,
            utilization_pct REAL    DEFAULT NULL,
            sampled_at      TIMESTAMPTZ NOT NULL DEFAULT (datetime('now'))""",
        "foreign_key": ("host_id", "CASCADE"),
        "indexes": (
            ("idx_interface_ts_lookup", "host_id, if_index, sampled_at"),
            ("idx_interface_ts_sampled_at", "sampled_at"),
        ),
    },
    {
        "table": "flow_records",
        "marker": ("bytes", "integer"),
        "columns": """
            id              BIGINT PRIMARY KEY AUTOINCREMENT,
            exporter_ip     TEXT    NOT NULL,
            host_id         INTEGER,
            flow_type       TEXT    NOT NULL DEFAULT 'netflow',
            src_ip          TEXT    NOT NULL DEFAULT '',
            dst_ip          TEXT    NOT NULL DEFAULT '',
            src_port        INTEGER DEFAULT 0,
            dst_port        INTEGER DEFAULT 0,
            protocol        INTEGER DEFAULT 0,
            bytes           BIGINT  DEFAULT 0,
            packets         BIGINT  DEFAULT 0,
            src_as          BIGINT  DEFAULT 0,
            dst_as          BIGINT  DEFAULT 0,
            input_if        BIGINT  DEFAULT 0,
            output_if       BIGINT  DEFAULT 0,
            tos             INTEGER DEFAULT 0,
            tcp_flags       INTEGER DEFAULT 0,
            start_time      TEXT    NOT NULL DEFAULT (datetime('now')),
            end_time        TEXT    NOT NULL DEFAULT (datetime('now')),
            received_at     TEXT    NOT NULL DEFAULT (datetime('now'))""",
        "foreign_key": ("host_id", "SET NULL"),
        "indexes": (
            ("idx_flow_received", "received_at"),
            ("idx_flow_exporter", "exporter_ip, received_at"),
            ("idx_flow_records_flow_type_received", "flow_type, received_at"),
            ("idx_flow_host_received", "host_id, received_at"),
        ),
    },
)


async def _fetchval(db, sql: str, params: tuple = ()):
    cursor = await db.execute(sql, params)
    row = await cursor.fetchone()
    return None if row is None else row[0]


async def _is_old(db, table: str, column: str, old_type: str) -> bool:
    data_type = await _fetchval(
        db,
        """SELECT data_type FROM information_schema.columns
           WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?""",
        (table, column),
    )
    return data_type == old_type


async def _swap(db, spec: dict) -> None:
    table = spec["table"]
    old = f"{table}{OLD_SUFFIX}"
    sequence = await _fetchval(db, "SELECT pg_get_serial_sequence(?, 'id')", (table,))
    primary_key = await _fetchval(
        db,
        "SELECT conname FROM pg_constraint WHERE conrelid = to_regclass(?) AND contype = 'p'",
        (table,),
    )
    cursor = await db.execute(
        """SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
           WHERE i.indrelid = to_regclass(?) AND NOT i.indisprimary
           ORDER BY c.relname""",
        (table,),
    )
    secondary = [row[0] for row in await cursor.fetchall()]

    # Identifiers below are fixed names from TABLES or read from the catalog
    # of those tables, quoted; no value from outside reaches the SQL.
    for index in secondary:
        await db.execute(f'DROP INDEX IF EXISTS "{index}"')
    await db.execute(f"ALTER TABLE {table} RENAME TO {old}")
    if sequence:
        await db.execute(f"ALTER SEQUENCE {sequence} RENAME TO {old}_id_seq")
    if primary_key:
        await db.execute(f'ALTER TABLE {old} RENAME CONSTRAINT "{primary_key}" TO {old}_pkey')
    await db.execute(
        "DO $$ BEGIN EXECUTE format('COMMENT ON TABLE %I IS %L', "
        f"'{old}', 'plexus-0144 swapped_at=' || NOW()::text); END $$"
    )

    await db.execute(f"CREATE TABLE {table} ({spec['columns']}\n)")
    column, on_delete = spec["foreign_key"]
    await db.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT fk_{table}_{column}_hosts "
        f"FOREIGN KEY ({column}) REFERENCES hosts(id) ON DELETE {on_delete}"
    )
    for name, columns in spec["indexes"]:
        await db.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")

    highest = await _fetchval(db, f"SELECT MAX(id) FROM {old}")  # nosec B608 - fixed table name
    issued = await _fetchval(db, f"SELECT last_value FROM {old}_id_seq") if sequence else None  # nosec B608
    start = max(int(highest or 0), int(issued or 0))
    if start > 0:
        await db.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), {start})")
    if highest is None:
        await db.execute(f"DROP TABLE {old}")


async def up(db) -> None:
    for spec in TABLES:
        column, old_type = spec["marker"]
        if await _is_old(db, spec["table"], column, old_type):
            await _swap(db, spec)
    await db.commit()
