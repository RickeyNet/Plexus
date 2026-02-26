"""
database.py — Async SQLite database layer for Plexus.

Tables:
    inventory_groups  — device groups (name, description)
    hosts             — individual devices linked to a group
    playbooks         — registered automation scripts
    templates         — reusable config snippets
    credentials       — encrypted SSH credentials per inventory group
    jobs              — execution history
    job_events        — per-host log lines for each job
"""

import os
import json
import aiosqlite
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "netcontrol.db")

# ── Schema ───────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
    hostname    TEXT    NOT NULL,
    ip_address  TEXT    NOT NULL,
    device_type TEXT    NOT NULL DEFAULT 'cisco_ios',
    status      TEXT    NOT NULL DEFAULT 'unknown',
    last_seen   TEXT,
    UNIQUE(group_id, ip_address)
);

CREATE TABLE IF NOT EXISTS playbooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    filename    TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    tags        TEXT    DEFAULT '[]',
    content     TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    content     TEXT    NOT NULL DEFAULT '',
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    secret      TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id     INTEGER NOT NULL REFERENCES playbooks(id),
    inventory_group_id INTEGER NOT NULL REFERENCES inventory_groups(id),
    credential_id   INTEGER REFERENCES credentials(id),
    template_id     INTEGER REFERENCES templates(id),
    dry_run         INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT 'pending',
    started_at      TEXT,
    finished_at     TEXT,
    hosts_ok        INTEGER DEFAULT 0,
    hosts_failed    INTEGER DEFAULT 0,
    hosts_skipped   INTEGER DEFAULT 0,
    launched_by     TEXT    DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS job_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    level       TEXT    NOT NULL DEFAULT 'info',
    host        TEXT    DEFAULT '',
    message     TEXT    NOT NULL DEFAULT ''
);
"""


async def get_db() -> aiosqlite.Connection:
    """Open a connection with row_factory enabled."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Create all tables if they don't exist."""
    db = await get_db()
    try:
        await db.executescript(SCHEMA)
        await db.commit()
        
        # Migration: Add content and updated_at columns to playbooks if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(playbooks)")
            columns = [row[1] for row in await cursor.fetchall()]
            
            if 'content' not in columns:
                print("[migration] Adding 'content' column to playbooks table...")
                await db.execute("ALTER TABLE playbooks ADD COLUMN content TEXT DEFAULT ''")
                await db.commit()
                print("[migration] Added 'content' column successfully")
            
            if 'updated_at' not in columns:
                print("[migration] Adding 'updated_at' column to playbooks table...")
                # SQLite doesn't allow non-constant defaults, so add column without default
                await db.execute("ALTER TABLE playbooks ADD COLUMN updated_at TEXT")
                await db.commit()
                # Update existing rows with current timestamp
                await db.execute("UPDATE playbooks SET updated_at = datetime('now') WHERE updated_at IS NULL")
                await db.commit()
                print("[migration] Added 'updated_at' column successfully")
        except Exception as e:
            print(f"[migration] Error during migration: {e}")
            import traceback
            traceback.print_exc()
    finally:
        await db.close()


# ── Helper: row → dict ──────────────────────────────────────────────────────

def row_to_dict(row) -> dict:
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows) -> list[dict]:
    return [dict(r) for r in rows]


# ═════════════════════════════════════════════════════════════════════════════
# Inventory Groups
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_groups() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT g.*, COUNT(h.id) AS host_count
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            GROUP BY g.id ORDER BY g.name
        """)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_group(group_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM inventory_groups WHERE id = ?", (group_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_group(name: str, description: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO inventory_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_group(group_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM inventory_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Hosts
# ═════════════════════════════════════════════════════════════════════════════

async def get_hosts_for_group(group_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE group_id = ? ORDER BY ip_address", (group_id,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def add_host(group_id: int, hostname: str, ip_address: str,
                   device_type: str = "cisco_ios") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type) VALUES (?,?,?,?)",
            (group_id, hostname, ip_address, device_type),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def remove_host(host_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        await db.commit()
    finally:
        await db.close()


async def update_host(host_id: int, hostname: str, ip_address: str,
                      device_type: str = "cisco_ios"):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE hosts SET hostname=?, ip_address=?, device_type=? WHERE id=?",
            (hostname, ip_address, device_type, host_id),
        )
        await db.commit()
    finally:
        await db.close()


async def update_host_status(host_id: int, status: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE hosts SET status = ?, last_seen = ? WHERE id = ?",
            (status, datetime.now(timezone.utc).isoformat(), host_id),
        )
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Playbooks
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_playbooks() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT p.*,
                   (SELECT j.status FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_status,
                   (SELECT j.started_at FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_run
            FROM playbooks p ORDER BY p.name
        """)
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            r["tags"] = json.loads(r.get("tags") or "[]")
        return rows
    finally:
        await db.close()


async def get_playbook(playbook_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM playbooks WHERE id = ?", (playbook_id,))
        row = row_to_dict(await cursor.fetchone())
        if row:
            row["tags"] = json.loads(row.get("tags") or "[]")
        return row
    finally:
        await db.close()


async def create_playbook(name: str, filename: str, description: str = "",
                          tags: list[str] | None = None, content: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO playbooks (name, filename, description, tags, content) VALUES (?,?,?,?,?)",
            (name, filename, description, json.dumps(tags or []), content),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        # If it's a unique constraint error, re-raise it
        if "UNIQUE constraint" in str(e) or "UNIQUE" in str(e):
            raise
        raise
    finally:
        await db.close()


async def sync_playbook_filename(name: str, filename: str):
    """Update the filename for an existing playbook by name."""
    db = await get_db()
    try:
        # Check if updated_at column exists
        try:
            cursor = await db.execute("PRAGMA table_info(playbooks)")
            columns = [row[1] for row in await cursor.fetchall()]
            if 'updated_at' in columns:
                await db.execute(
                    "UPDATE playbooks SET filename = ?, updated_at = datetime('now') WHERE name = ?",
                    (filename, name)
                )
            else:
                await db.execute(
                    "UPDATE playbooks SET filename = ? WHERE name = ?",
                    (filename, name)
                )
        except Exception:
            # Fallback if we can't check columns
            await db.execute(
                "UPDATE playbooks SET filename = ? WHERE name = ?",
                (filename, name)
            )
        await db.commit()
    finally:
        await db.close()


async def update_playbook(playbook_id: int, name: str = None, filename: str = None,
                          description: str = None, tags: list[str] | None = None,
                          content: str = None):
    """Update playbook fields. None values are not updated."""
    db = await get_db()
    try:
        updates = []
        params = []
        
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if filename is not None:
            updates.append("filename = ?")
            params.append(filename)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        
        if updates:
            # Check if updated_at column exists before trying to update it
            try:
                cursor = await db.execute("PRAGMA table_info(playbooks)")
                columns = [row[1] for row in await cursor.fetchall()]
                if 'updated_at' in columns:
                    updates.append("updated_at = datetime('now')")
            except Exception:
                pass  # If we can't check, just skip updated_at
            
            params.append(playbook_id)
            await db.execute(
                f"UPDATE playbooks SET {', '.join(updates)} WHERE id = ?",
                params
            )
            await db.commit()
    finally:
        await db.close()


async def delete_playbook(playbook_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_templates() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates ORDER BY name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_template(template_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates WHERE id = ?", (template_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_template(name: str, content: str, description: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO templates (name, content, description) VALUES (?,?,?)",
            (name, content, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_template(template_id: int, name: str, content: str,
                          description: str = ""):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE templates SET name=?, content=?, description=?,
               updated_at=datetime('now') WHERE id=?""",
            (name, content, description, template_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_template(template_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Credentials (encrypted externally before storage)
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_credentials() -> list[dict]:
    """Return credentials with passwords masked."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT id, name, username, created_at FROM credentials ORDER BY name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_credential_raw(cred_id: int) -> dict | None:
    """Return full credential including encrypted password/secret."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_credential(name: str, username: str, enc_password: str,
                            enc_secret: str = "") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret) VALUES (?,?,?,?)",
            (name, username, enc_password, enc_secret),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_credential(cred_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        await db.commit()
    finally:
        await db.close()


async def update_credential(
    cred_id: int,
    *,
    name: str | None = None,
    username: str | None = None,
    enc_password: str | None = None,
    enc_secret: str | None = None,
):
    """Update credential fields. Omit or None means leave unchanged."""
    updates = []
    args = []
    if name is not None:
        updates.append("name = ?")
        args.append(name)
    if username is not None:
        updates.append("username = ?")
        args.append(username)
    if enc_password is not None:
        updates.append("password = ?")
        args.append(enc_password)
    if enc_secret is not None:
        updates.append("secret = ?")
        args.append(enc_secret)
    if not updates:
        return
    args.append(cred_id)
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?",
            tuple(args),
        )
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Jobs
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_jobs(limit: int = 50) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            JOIN inventory_groups g ON g.id = j.inventory_group_id
            ORDER BY j.id DESC LIMIT ?
        """, (limit,))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_job(job_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT j.*, p.name AS playbook_name, g.name AS group_name
            FROM jobs j
            JOIN playbooks p ON p.id = j.playbook_id
            JOIN inventory_groups g ON g.id = j.inventory_group_id
            WHERE j.id = ?
        """, (job_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_job(playbook_id: int, inventory_group_id: int,
                     credential_id: int | None = None,
                     template_id: int | None = None,
                     dry_run: bool = True,
                     launched_by: str = "admin") -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO jobs
               (playbook_id, inventory_group_id, credential_id, template_id,
                dry_run, status, started_at, launched_by)
               VALUES (?,?,?,?,?,?,?,?)""",
            (playbook_id, inventory_group_id, credential_id, template_id,
             1 if dry_run else 0, "running",
             datetime.now(timezone.utc).isoformat(), launched_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def finish_job(job_id: int, status: str, hosts_ok: int = 0,
                     hosts_failed: int = 0, hosts_skipped: int = 0):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE jobs SET status=?, finished_at=?, hosts_ok=?,
               hosts_failed=?, hosts_skipped=? WHERE id=?""",
            (status, datetime.now(timezone.utc).isoformat(),
             hosts_ok, hosts_failed, hosts_skipped, job_id),
        )
        await db.commit()
    finally:
        await db.close()


async def add_job_event(job_id: int, level: str, message: str, host: str = ""):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO job_events (job_id, level, host, message) VALUES (?,?,?,?)",
            (job_id, level, host, message),
        )
        await db.commit()
    finally:
        await db.close()


async def get_job_events(job_id: int) -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM job_events WHERE job_id = ? ORDER BY id", (job_id,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard Stats
# ═════════════════════════════════════════════════════════════════════════════

async def get_dashboard_stats() -> dict:
    db = await get_db()
    try:
        total_hosts = (await (await db.execute("SELECT COUNT(*) FROM hosts")).fetchone())[0]
        total_groups = (await (await db.execute("SELECT COUNT(*) FROM inventory_groups")).fetchone())[0]
        total_playbooks = (await (await db.execute("SELECT COUNT(*) FROM playbooks")).fetchone())[0]
        total_jobs = (await (await db.execute("SELECT COUNT(*) FROM jobs")).fetchone())[0]
        running_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='running'"
        )).fetchone())[0]
        successful_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='success'"
        )).fetchone())[0]
        completed_jobs = (await (await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('success','failed')"
        )).fetchone())[0]
        success_rate = round(successful_jobs / completed_jobs * 100) if completed_jobs > 0 else 0

        return {
            "total_hosts": total_hosts,
            "total_groups": total_groups,
            "total_playbooks": total_playbooks,
            "total_jobs": total_jobs,
            "running_jobs": running_jobs,
            "success_rate": success_rate,
        }
    finally:
        await db.close()
