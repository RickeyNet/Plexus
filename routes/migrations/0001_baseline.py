"""
Baseline migration — consolidates all pre-framework inline ALTER TABLE
migrations that previously ran inside ``init_db()``.

For **new** databases (created from the current SCHEMA), every column and
table already exists so each step is a no-op.  For **existing** databases
upgraded from older versions, the idempotent checks ensure each change is
only applied once.

This migration is marked as version 1 and is automatically recorded as
applied when the framework is first initialised (see ``_bootstrap_baseline``
in ``runner.py``).  All future schema changes go in 0002+.
"""

from __future__ import annotations

import os

VERSION = 1
DESCRIPTION = "Baseline: consolidate pre-framework inline migrations"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


# ── Helpers ─────────────────────────────────────────────────────────────────

async def _sqlite_columns(db, table: str) -> list[str]:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in await cursor.fetchall()]


async def _sqlite_add_column_if_missing(db, table: str, column: str, definition: str) -> None:
    cols = await _sqlite_columns(db, table)
    if column not in cols:
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        await db.commit()


# ── Postgres path ───────────────────────────────────────────────────────────

async def _up_postgres(db) -> None:
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS content TEXT DEFAULT ''")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS updated_at TEXT")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'python'")
    await db.execute("UPDATE playbooks SET updated_at = NOW()::text WHERE updated_at IS NULL")

    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT ''")
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'")
    await db.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0"
    )

    await db.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id)")

    await db.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS host_ids TEXT DEFAULT NULL")
    await db.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS ad_hoc_ips TEXT DEFAULT NULL")
    # Postgres supports ALTER COLUMN ... DROP NOT NULL natively
    await db.execute("ALTER TABLE jobs ALTER COLUMN inventory_group_id DROP NOT NULL")

    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS model TEXT DEFAULT ''")
    await db.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS software_version TEXT DEFAULT ''")

    # Assign orphaned credentials
    cursor = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
    row = await cursor.fetchone()
    orphan_count = row[0] if row else 0
    if orphan_count > 0:
        admin_cursor = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_row = await admin_cursor.fetchone()
        if admin_row:
            await db.execute("UPDATE credentials SET owner_id = $1 WHERE owner_id IS NULL", (admin_row[0],))

    await db.commit()


# ── SQLite path ─────────────────────────────────────────────────────────────

async def _up_sqlite(db) -> None:
    # playbooks columns
    await _sqlite_add_column_if_missing(db, "playbooks", "content", "TEXT DEFAULT ''")
    await _sqlite_add_column_if_missing(db, "playbooks", "updated_at", "TEXT")
    await db.execute("UPDATE playbooks SET updated_at = datetime('now') WHERE updated_at IS NULL")
    await db.commit()
    await _sqlite_add_column_if_missing(db, "playbooks", "type", "TEXT NOT NULL DEFAULT 'python'")

    # users columns
    await _sqlite_add_column_if_missing(db, "users", "display_name", "TEXT DEFAULT ''")
    await _sqlite_add_column_if_missing(db, "users", "role", "TEXT DEFAULT 'user'")
    await _sqlite_add_column_if_missing(db, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")

    # credentials: add owner_id, drop UNIQUE on name
    cred_cols = await _sqlite_columns(db, "credentials")
    if "owner_id" not in cred_cols:
        await db.execute("ALTER TABLE credentials RENAME TO old_credentials")
        await db.commit()
        await db.execute("""
            CREATE TABLE credentials (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                password    TEXT    NOT NULL,
                secret      TEXT    NOT NULL DEFAULT '',
                owner_id    INTEGER REFERENCES users(id),
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        await db.commit()
        await db.execute("""
            INSERT INTO credentials (id, name, username, password, secret, created_at)
            SELECT id, name, username, password, secret, created_at FROM old_credentials
        """)
        await db.commit()
        await db.execute("DROP TABLE old_credentials")
        await db.commit()

    # Assign orphaned credentials to the first admin
    cursor2 = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
    orphan_count = (await cursor2.fetchall())[0][0]
    if orphan_count > 0:
        cursor3 = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_row = await cursor3.fetchone()
        if admin_row:
            await db.execute("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL", (admin_row[0],))
            await db.commit()

    # jobs columns
    for col_name, col_def in [
        ("queued_at", "TEXT"),
        ("cancelled_at", "TEXT"),
        ("cancelled_by", "TEXT DEFAULT ''"),
        ("priority", "INTEGER NOT NULL DEFAULT 2"),
        ("depends_on", "TEXT NOT NULL DEFAULT '[]'"),
        ("launched_by", "TEXT DEFAULT 'admin'"),
        ("host_ids", "TEXT DEFAULT NULL"),
        ("ad_hoc_ips", "TEXT DEFAULT NULL"),
    ]:
        await _sqlite_add_column_if_missing(db, "jobs", col_name, col_def)

    # Make inventory_group_id nullable in jobs (SQLite table recreation)
    cursor = await db.execute("PRAGMA table_info(jobs)")
    cols = await cursor.fetchall()
    igid_col = next((c for c in cols if c[1] == "inventory_group_id"), None)
    if igid_col and igid_col[3] == 1:  # notnull == 1
        await db.execute("PRAGMA foreign_keys=OFF")
        await db.execute("ALTER TABLE jobs RENAME TO jobs_old")
        await db.execute("""
            CREATE TABLE jobs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id     INTEGER NOT NULL REFERENCES playbooks(id),
                inventory_group_id INTEGER REFERENCES inventory_groups(id),
                credential_id   INTEGER REFERENCES credentials(id),
                template_id     INTEGER REFERENCES templates(id),
                dry_run         INTEGER NOT NULL DEFAULT 1,
                status          TEXT    NOT NULL DEFAULT 'pending',
                priority        INTEGER NOT NULL DEFAULT 2,
                depends_on      TEXT    NOT NULL DEFAULT '[]',
                queued_at       TEXT,
                started_at      TEXT,
                finished_at     TEXT,
                cancelled_at    TEXT,
                cancelled_by    TEXT    DEFAULT '',
                host_ids        TEXT    DEFAULT NULL,
                ad_hoc_ips      TEXT    DEFAULT NULL,
                hosts_ok        INTEGER DEFAULT 0,
                hosts_failed    INTEGER DEFAULT 0,
                hosts_skipped   INTEGER DEFAULT 0,
                launched_by     TEXT    DEFAULT 'admin'
            )
        """)
        await db.execute("""
            INSERT INTO jobs (id, playbook_id, inventory_group_id, credential_id,
                template_id, dry_run, status, priority, depends_on, queued_at,
                started_at, finished_at, cancelled_at, cancelled_by, host_ids,
                hosts_ok, hosts_failed, hosts_skipped, launched_by)
            SELECT id, playbook_id, inventory_group_id, credential_id,
                template_id, dry_run, status, priority, depends_on, queued_at,
                started_at, finished_at, cancelled_at, cancelled_by, host_ids,
                hosts_ok, hosts_failed, hosts_skipped, launched_by
            FROM jobs_old
        """)
        await db.execute("DROP TABLE jobs_old")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.commit()

    # Repair job_events FK if it still references jobs_old
    cursor = await db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='job_events'"
    )
    row = await cursor.fetchone()
    if row and "jobs_old" in (row[0] or ""):
        await db.execute("PRAGMA foreign_keys=OFF")
        await db.execute("ALTER TABLE job_events RENAME TO job_events_old")
        await db.execute("""
            CREATE TABLE job_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
                level       TEXT    NOT NULL DEFAULT 'info',
                host        TEXT    DEFAULT '',
                message     TEXT    NOT NULL DEFAULT ''
            )
        """)
        await db.execute("""
            INSERT INTO job_events (id, job_id, timestamp, level, host, message)
            SELECT id, job_id, timestamp, level, host, message FROM job_events_old
        """)
        await db.execute("DROP TABLE job_events_old")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.commit()

    # hosts columns
    await _sqlite_add_column_if_missing(db, "hosts", "model", "TEXT DEFAULT ''")
    await _sqlite_add_column_if_missing(db, "hosts", "software_version", "TEXT DEFAULT ''")


# ── Entry point ─────────────────────────────────────────────────────────────

async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
