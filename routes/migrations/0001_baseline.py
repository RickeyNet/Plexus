"""
Baseline migration - consolidates all pre-framework inline ALTER TABLE
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

VERSION = 1
DESCRIPTION = "Baseline: consolidate pre-framework inline migrations"


async def up(db) -> None:
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS content TEXT DEFAULT ''")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS updated_at TEXT")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'python'")
    await db.execute("UPDATE playbooks SET updated_at = NOW()::text WHERE updated_at IS NULL")

    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT ''")
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'")
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0")

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
