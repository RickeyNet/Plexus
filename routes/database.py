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
    audit_events      — immutable audit trail for auth, CRUD, and operational actions
"""

import json
import os
import re
from datetime import UTC, datetime

import aiosqlite
try:
    import asyncpg
except Exception:  # pragma: no cover - optional dependency for postgres mode
    asyncpg = None

from netcontrol.telemetry import configure_logging

_LOGGER = configure_logging("plexus.db")

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"
APP_DATABASE_URL = os.getenv("APP_DATABASE_URL", "").strip()
_VALID_DB_ENGINES = {"sqlite", "postgres"}

DB_PATH = os.getenv(
    "APP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "netcontrol.db"),
)
SQLITE_CONNECT_TIMEOUT = float(os.getenv("APP_SQLITE_CONNECT_TIMEOUT", "30"))
SQLITE_BUSY_TIMEOUT_MS = int(os.getenv("APP_SQLITE_BUSY_TIMEOUT_MS", "5000"))

_INSERT_ID_TABLES = {
    "users",
    "access_groups",
    "inventory_groups",
    "hosts",
    "playbooks",
    "templates",
    "credentials",
    "jobs",
    "audit_events",
}

# ── Schema ───────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    password_hash TEXT  NOT NULL,
    salt        TEXT    NOT NULL,
    display_name TEXT   DEFAULT '',
    role        TEXT    NOT NULL DEFAULT 'user',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_group_features (
    group_id    INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    feature_key TEXT    NOT NULL,
    PRIMARY KEY (group_id, feature_key)
);

CREATE TABLE IF NOT EXISTS user_group_memberships (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id    INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS auth_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

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
    name        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    secret      TEXT    NOT NULL DEFAULT '',
    owner_id    INTEGER REFERENCES users(id),
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

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    category        TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    user            TEXT    NOT NULL DEFAULT '',
    detail          TEXT    DEFAULT '',
    correlation_id  TEXT    DEFAULT ''
);
"""


def _convert_sqlite_schema_to_postgres(sqlite_schema: str) -> str:
    converted = sqlite_schema
    converted = converted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("DEFAULT (datetime('now'))", "DEFAULT NOW()")
    return converted


POSTGRES_SCHEMA = _convert_sqlite_schema_to_postgres(SCHEMA)


def _split_sql_statements(schema: str) -> list[str]:
    return [stmt.strip() for stmt in schema.split(";") if stmt.strip()]


def _convert_qmark_to_dollar_params(query: str) -> str:
    out: list[str] = []
    in_single_quote = False
    param_index = 1
    for ch in query:
        if ch == "'":
            in_single_quote = not in_single_quote
            out.append(ch)
            continue
        if ch == "?" and not in_single_quote:
            out.append(f"${param_index}")
            param_index += 1
            continue
        out.append(ch)
    converted = "".join(out)
    converted = converted.replace("datetime('now')", "NOW()")
    return converted


def _parse_rowcount(status: str) -> int:
    try:
        return int(status.rsplit(" ", 1)[-1])
    except Exception:
        return 0


def _is_unique_violation(exc: Exception) -> bool:
    message = str(exc).lower()
    return "unique constraint" in message or "duplicate key value violates unique constraint" in message


def _is_foreign_key_violation(exc: Exception) -> bool:
    message = str(exc).lower()
    return "foreign key constraint failed" in message or "violates foreign key constraint" in message


class _PostgresCursorCompat:
    def __init__(self, rows=None, *, lastrowid: int | None = None, rowcount: int = 0):
        self._rows = rows or []
        self._idx = 0
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    async def fetchone(self):
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    async def fetchall(self):
        return list(self._rows)


class _PostgresConnectionCompat:
    def __init__(self, conn):
        self._conn = conn
        self.row_factory = None

    async def execute(self, query: str, params=()):
        params = tuple(params or ())
        query_stripped = query.strip()
        query_upper = query_stripped.upper()
        converted = _convert_qmark_to_dollar_params(query)

        if query_upper.startswith("SELECT") or query_upper.startswith("WITH"):
            rows = await self._conn.fetch(converted, *params)
            return _PostgresCursorCompat(rows=rows, rowcount=len(rows))

        if query_upper.startswith("INSERT"):
            m = re.match(r"^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", query_stripped, re.IGNORECASE)
            table = m.group(1).lower() if m else ""
            if table in _INSERT_ID_TABLES and "RETURNING" not in query_upper:
                returning_query = f"{converted.rstrip()} RETURNING id"
                row = await self._conn.fetchrow(returning_query, *params)
                lastrowid = row["id"] if row is not None and "id" in row else None
                return _PostgresCursorCompat(lastrowid=lastrowid, rowcount=1 if row else 0)

            status = await self._conn.execute(converted, *params)
            return _PostgresCursorCompat(rowcount=_parse_rowcount(status))

        status = await self._conn.execute(converted, *params)
        return _PostgresCursorCompat(rowcount=_parse_rowcount(status))

    async def executescript(self, script: str):
        for stmt in _split_sql_statements(script):
            await self._conn.execute(stmt)

    async def commit(self):
        # asyncpg uses autocommit when no explicit transaction is active.
        return None

    async def close(self):
        await self._conn.close()


async def get_db():
    """Open a backend connection using APP_DB_ENGINE."""
    if DB_ENGINE not in _VALID_DB_ENGINES:
        raise RuntimeError(
            f"Unsupported APP_DB_ENGINE '{DB_ENGINE}'. Supported values: {', '.join(sorted(_VALID_DB_ENGINES))}"
        )

    if DB_ENGINE == "postgres":
        if asyncpg is None:
            raise RuntimeError("APP_DB_ENGINE=postgres requires the 'asyncpg' package")
        if not APP_DATABASE_URL:
            raise RuntimeError("APP_DB_ENGINE=postgres requires APP_DATABASE_URL")
        conn = await asyncpg.connect(APP_DATABASE_URL)
        return _PostgresConnectionCompat(conn)

    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    db = await aiosqlite.connect(DB_PATH, timeout=SQLITE_CONNECT_TIMEOUT)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def _init_postgres(db) -> None:
    for stmt in _split_sql_statements(POSTGRES_SCHEMA):
        await db.execute(stmt)

    # Idempotent startup migrations for already-created databases.
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS content TEXT DEFAULT ''")
    await db.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS updated_at TEXT")
    await db.execute("UPDATE playbooks SET updated_at = NOW()::text WHERE updated_at IS NULL")

    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT ''")
    await db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'")
    await db.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0"
    )

    await db.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id)")

    cursor = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
    orphan_count_row = await cursor.fetchone()
    orphan_count = orphan_count_row[0] if orphan_count_row else 0
    if orphan_count > 0:
        admin_cursor = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_row = await admin_cursor.fetchone()
        if admin_row:
            await db.execute("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL", (admin_row[0],))
            _LOGGER.info(
                "migration(postgres): assigned %s orphaned credential(s) to admin user (id=%s)",
                orphan_count,
                admin_row[0],
            )
        else:
            _LOGGER.warning("migration(postgres): no admin user found to assign orphaned credentials")

    await db.commit()


async def init_db():
    """Create all tables if they don't exist."""
    db = await get_db()
    try:
        if DB_ENGINE == "postgres":
            await _init_postgres(db)
            return

        await db.executescript(SCHEMA)
        await db.commit()
        
        # Migration: Add content and updated_at columns to playbooks if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(playbooks)")
            columns = [row[1] for row in await cursor.fetchall()]
            
            if 'content' not in columns:
                _LOGGER.info("migration: adding 'content' column to playbooks table")
                await db.execute("ALTER TABLE playbooks ADD COLUMN content TEXT DEFAULT ''")
                await db.commit()
                _LOGGER.info("migration: added 'content' column successfully")
            
            if 'updated_at' not in columns:
                _LOGGER.info("migration: adding 'updated_at' column to playbooks table")
                await db.execute("ALTER TABLE playbooks ADD COLUMN updated_at TEXT")
                await db.commit()
                await db.execute("UPDATE playbooks SET updated_at = datetime('now') WHERE updated_at IS NULL")
                await db.commit()
                _LOGGER.info("migration: added 'updated_at' column successfully")
        except Exception as e:
            _LOGGER.error("migration: playbooks migration error: %s", e, exc_info=True)

        # Migration: Add display_name and role columns to users if they don't exist
        try:
            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in await cursor.fetchall()]

            if 'display_name' not in columns:
                _LOGGER.info("migration: adding 'display_name' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''")
                await db.commit()
                _LOGGER.info("migration: added 'display_name' column successfully")
            
            if 'role' not in columns:
                _LOGGER.info("migration: adding 'role' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
                await db.commit()
                _LOGGER.info("migration: added 'role' column successfully")

        except Exception as e:
            _LOGGER.error("migration: users table migration error: %s", e, exc_info=True)

        # Migration: Add owner_id column to credentials, drop UNIQUE on name
        try:
            cursor = await db.execute("PRAGMA table_info(credentials)")
            columns = [row[1] for row in await cursor.fetchall()]

            if 'owner_id' not in columns:
                _LOGGER.info("migration: migrating 'credentials' table to add 'owner_id' and drop UNIQUE on name")
                
                # 1. Rename existing table
                await db.execute("ALTER TABLE credentials RENAME TO old_credentials")
                await db.commit()

                # 2. Create new table with updated schema (no UNIQUE on name)
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

                # 3. Copy data from old table to new table
                await db.execute("""
                    INSERT INTO credentials (id, name, username, password, secret, created_at)
                    SELECT id, name, username, password, secret, created_at FROM old_credentials
                """)
                await db.commit()

                # 4. Drop old table
                await db.execute("DROP TABLE old_credentials")
                await db.commit()
                _LOGGER.info("migration: 'credentials' table migration complete")
            else:
                _LOGGER.info("migration: 'owner_id' column already exists in 'credentials' table, skipping")


            # Assign orphaned credentials to the first admin user (newly created or existing)
            cursor2 = await db.execute("SELECT COUNT(*) FROM credentials WHERE owner_id IS NULL")
            orphan_count = (await cursor2.fetchall())[0][0]
            if orphan_count > 0:
                cursor3 = await db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
                admin_row = await cursor3.fetchone()
                if admin_row:
                    admin_id = admin_row[0]
                    await db.execute("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL", (admin_id,))
                    await db.commit()
                    _LOGGER.info("migration: assigned %s orphaned credential(s) to admin user (id=%s)", orphan_count, admin_id)
                else:
                    _LOGGER.warning("migration: no admin user found to assign orphaned credentials to")
        except Exception as e:
            _LOGGER.error("migration: credentials migration error: %s", e, exc_info=True)

        # Migration: Add must_change_password column to users if it doesn't exist
        try:
            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in await cursor.fetchall()]
            if 'must_change_password' not in columns:
                _LOGGER.info("migration: adding 'must_change_password' column to users table")
                await db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
                await db.commit()
                _LOGGER.info("migration: added 'must_change_password' column successfully")
        except Exception as e:
            _LOGGER.error("migration: must_change_password migration error: %s", e, exc_info=True)
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
# Users
# ═════════════════════════════════════════════════════════════════════════════

async def get_user_by_username(username: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_user_by_id(user_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_user(username: str, password_hash: str, salt: str,
                      display_name: str = "", role: str = "user",
                      must_change_password: bool = False) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, salt, display_name, role, must_change_password) VALUES (?,?,?,?,?,?)",
            (username, password_hash, salt, display_name, role, int(must_change_password)),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError(f"Username '{username}' already exists.")
        raise
    finally:
        await db.close()


async def update_user_password(user_id: int, password_hash: str, salt: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE id = ?",
            (password_hash, salt, user_id),
        )
        await db.commit()
    finally:
        await db.close()


async def update_user_profile(user_id: int, display_name: str = None):
    db = await get_db()
    try:
        if display_name is not None:
            await db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
            await db.commit()
    finally:
        await db.close()


async def update_user_admin(user_id: int, username: str = None, display_name: str = None, role: str = None):
    db = await get_db()
    try:
        fields = []
        values = []
        if username is not None:
            fields.append("username = ?")
            values.append(username)
        if display_name is not None:
            fields.append("display_name = ?")
            values.append(display_name)
        if role is not None:
            fields.append("role = ?")
            values.append(role)
        if not fields:
            return
        values.append(user_id)
        await db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", tuple(values))
        await db.commit()
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Username already exists")
        raise
    finally:
        await db.close()


async def get_all_users() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, created_at FROM users ORDER BY username"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_user(user_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE owner_id = ?", (user_id,))
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_group_ids(user_id: int) -> list[int]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT group_id FROM user_group_memberships WHERE user_id = ? ORDER BY group_id",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [int(r[0]) for r in rows]
    finally:
        await db.close()


async def set_user_groups(user_id: int, group_ids: list[int]):
    db = await get_db()
    try:
        await db.execute("DELETE FROM user_group_memberships WHERE user_id = ?", (user_id,))
        for gid in sorted(set(group_ids)):
            await db.execute(
                "INSERT INTO user_group_memberships (user_id, group_id) VALUES (?, ?)",
                (user_id, gid),
            )
        await db.commit()
    except Exception as e:
        if _is_foreign_key_violation(e):
            raise ValueError("One or more selected groups do not exist")
        raise
    finally:
        await db.close()


async def get_all_access_groups() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.id, g.name, g.description, g.created_at, COUNT(m.user_id) AS member_count
            FROM access_groups g
            LEFT JOIN user_group_memberships m ON m.group_id = g.id
            GROUP BY g.id
            ORDER BY g.name
            """
        )
        groups = rows_to_list(await cursor.fetchall())

        for group in groups:
            fcur = await db.execute(
                "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
                (group["id"],),
            )
            group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        return groups
    finally:
        await db.close()


async def get_access_group(group_id: int) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, description, created_at FROM access_groups WHERE id = ?",
            (group_id,),
        )
        group = row_to_dict(await cursor.fetchone())
        if not group:
            return None

        fcur = await db.execute(
            "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
            (group_id,),
        )
        mcur = await db.execute(
            "SELECT COUNT(*) FROM user_group_memberships WHERE group_id = ?",
            (group_id,),
        )
        group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        group["member_count"] = int((await mcur.fetchone())[0])
        return group
    finally:
        await db.close()


async def create_access_group(name: str, description: str, feature_keys: list[str]) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO access_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        group_id = cursor.lastrowid
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
        return int(group_id)
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def update_access_group(group_id: int, name: str, description: str, feature_keys: list[str]):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE access_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.execute("DELETE FROM access_group_features WHERE group_id = ?", (group_id,))
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def delete_access_group(group_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM access_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_effective_features(user_id: int) -> list[str]:
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT DISTINCT f.feature_key
            FROM access_group_features f
            INNER JOIN user_group_memberships m ON m.group_id = f.group_id
            WHERE m.user_id = ?
            ORDER BY f.feature_key
            """,
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]
    finally:
        await db.close()


async def set_auth_setting(key: str, value: dict):
    db = await get_db()
    try:
        payload = json.dumps(value)
        await db.execute(
            """
            INSERT INTO auth_settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now')
            """,
            (key, payload),
        )
        await db.commit()
    finally:
        await db.close()


async def get_auth_setting(key: str) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        await db.close()


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


async def get_all_groups_with_hosts() -> list[dict]:
    """Return all groups with embedded host arrays using a single query."""
    db = await get_db()
    try:
        cursor = await db.execute("""
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                h.id AS host_id,
                h.group_id AS host_group_id,
                h.hostname AS host_hostname,
                h.ip_address AS host_ip_address,
                h.device_type AS host_device_type,
                h.status AS host_status,
                h.last_seen AS host_last_seen
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            ORDER BY g.name, h.ip_address
        """)
        rows = await cursor.fetchall()
    finally:
        await db.close()

    groups: list[dict] = []
    by_group_id: dict[int, dict] = {}
    for row in rows:
        gid = int(row["group_id"])
        group = by_group_id.get(gid)
        if group is None:
            group = {
                "id": gid,
                "name": row["group_name"],
                "description": row["group_description"] or "",
                "host_count": 0,
                "hosts": [],
            }
            by_group_id[gid] = group
            groups.append(group)

        host_id = row["host_id"]
        if host_id is None:
            continue
        group["hosts"].append({
            "id": host_id,
            "group_id": row["host_group_id"],
            "hostname": row["host_hostname"],
            "ip_address": row["host_ip_address"],
            "device_type": row["host_device_type"],
            "status": row["host_status"],
            "last_seen": row["host_last_seen"],
        })
        group["host_count"] += 1

    return groups


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


async def update_group(group_id: int, name: str, description: str = ""):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE inventory_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.commit()
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


async def get_hosts_by_ids(host_ids: list[int]) -> list[dict]:
    """Get multiple hosts by their IDs."""
    if not host_ids:
        return []
    db = await get_db()
    try:
        placeholders = ','.join('?' * len(host_ids))
        cursor = await db.execute(
            f"SELECT * FROM hosts WHERE id IN ({placeholders}) ORDER BY ip_address",
            tuple(host_ids)
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
            (status, datetime.now(UTC).isoformat(), host_id),
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
        if _is_unique_violation(e):
            raise
        raise
    finally:
        await db.close()


async def sync_playbook_filename(name: str, filename: str):
    """Update the filename for an existing playbook by name."""
    db = await get_db()
    try:
        if DB_ENGINE == "postgres":
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = NOW()::text WHERE name = ?",
                (filename, name),
            )
        else:
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = datetime('now') WHERE name = ?",
                (filename, name),
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
            updates.append("updated_at = NOW()::text" if DB_ENGINE == "postgres" else "updated_at = datetime('now')")

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

async def get_all_credentials(owner_id: int | None = None) -> list[dict]:
    """Return credentials with passwords masked. Filter by owner if provided."""
    db = await get_db()
    try:
        if owner_id is not None:
            cursor = await db.execute(
                "SELECT id, name, username, owner_id, created_at FROM credentials WHERE owner_id = ? ORDER BY name",
                (owner_id,))
        else:
            cursor = await db.execute("SELECT id, name, username, owner_id, created_at FROM credentials ORDER BY name")
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
                            enc_secret: str = "", owner_id: int | None = None) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret, owner_id) VALUES (?,?,?,?,?)",
            (name, username, enc_password, enc_secret, owner_id),
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
             datetime.now(UTC).isoformat(), launched_by),
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
            (status, datetime.now(UTC).isoformat(),
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


async def delete_expired_jobs(retention_days: int) -> int:
    """Delete completed jobs older than retention_days and return deleted row count."""
    db = await get_db()
    try:
        safe_days = max(1, int(retention_days))
        if DB_ENGINE == "postgres":
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed')
                  AND started_at IS NOT NULL
                  AND COALESCE(finished_at, started_at)::timestamp <= (NOW() - (?::int * INTERVAL '1 day'))
                """,
                (safe_days,),
            )
        else:
            cursor = await db.execute(
                """
                DELETE FROM jobs
                WHERE status IN ('success', 'failed')
                  AND started_at IS NOT NULL
                  AND julianday(COALESCE(finished_at, started_at)) <= julianday('now') - ?
                """,
                (safe_days,),
            )
        await db.commit()
        return cursor.rowcount or 0
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


# ═════════════════════════════════════════════════════════════════════════════
# Audit Events
# ═════════════════════════════════════════════════════════════════════════════


async def add_audit_event(
    category: str,
    action: str,
    user: str = "",
    detail: str = "",
    correlation_id: str = "",
) -> int:
    """Insert an immutable audit record and return its ID."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            """INSERT INTO audit_events (category, action, user, detail, correlation_id)
               VALUES (?, ?, ?, ?, ?)""",
            (category, action, user, detail, correlation_id),
        )
        await conn.commit()
        return cursor.lastrowid
    finally:
        await conn.close()


async def get_audit_events(
    limit: int = 100,
    category: str | None = None,
) -> list[dict]:
    """Return recent audit events, optionally filtered by category."""
    conn = await get_db()
    try:
        if category:
            cursor = await conn.execute(
                "SELECT * FROM audit_events WHERE category = ? ORDER BY id DESC LIMIT ?",
                (category, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()
