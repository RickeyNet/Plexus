"""
Migration runner - discovers, orders, and applies schema migrations.

The ``schema_migrations`` table stores the version number, description,
and timestamp of every migration that has been applied.  On each startup
``run_migrations`` compares the set of migration files against the
recorded versions and applies any that are missing, in order.

Concurrency safety: ``pg_advisory_lock`` ensures only one process migrates
at a time.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time
from pathlib import Path

from netcontrol.telemetry import configure_logging

_LOGGER = configure_logging("plexus.migrations")

_ADVISORY_LOCK_ID = 0x504C5853  # "PLXS" as a 32-bit int


# ── Discovery ───────────────────────────────────────────────────────────────


def _discover_migrations(package: str = "routes.migrations") -> list[dict]:
    """Return a sorted list of ``{version, description, module}`` dicts.

    ``package`` is the core migrations package by default; a plugin's
    migrations package (``run_plugin_migrations``) is read the same way.
    """
    if package == "routes.migrations":
        search_path = [str(Path(__file__).resolve().parent)]
    else:
        search_path = list(getattr(importlib.import_module(package), "__path__", []))
    found: list[dict] = []

    for info in pkgutil.iter_modules(search_path):
        name = info.name
        if name.startswith("_") or name == "runner":
            continue
        # Expect filenames like "0001_add_playbook_columns.py"
        parts = name.split("_", 1)
        if not parts[0].isdigit():
            continue
        version = int(parts[0])
        mod = importlib.import_module(f"{package}.{name}")
        if not hasattr(mod, "up") or not hasattr(mod, "VERSION"):
            _LOGGER.warning("migration file %s missing VERSION or up(); skipping", name)
            continue
        found.append(
            {
                "version": mod.VERSION,
                "description": getattr(mod, "DESCRIPTION", name),
                "up": mod.up,
                "module": mod,
                "filename": name,
            }
        )

    found.sort(key=lambda m: m["version"])

    # Sanity: no duplicate versions
    seen: set[int] = set()
    for m in found:
        if m["version"] in seen:
            raise RuntimeError(f"Duplicate migration version {m['version']} (file: {m['filename']})")
        seen.add(m["version"])

    return found


# ── Schema table bootstrap ──────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT    NOT NULL DEFAULT '',
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def _ensure_migrations_table(db) -> None:
    await db.execute(_CREATE_TABLE)
    await db.commit()


async def _applied_versions(db) -> set[int]:
    cursor = await db.execute("SELECT version FROM schema_migrations")
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def _bootstrap_baseline(db) -> None:
    """Record migrations 1–32 as already applied on any DB that has the v1.0.0
    SCHEMA already in place.

    Two scenarios this handles:
      * **Fresh deploy**: ``init_db`` just ran and SCHEMA contains every table
        that migrations 0003–0032 originally added (folded in for v1.0.0). No
        migration needs to actually run; we simply mark them applied.
      * **Pre-framework upgrade**: a database that predates this framework
        (created by the old inline ``init_db``). The old ALTER TABLE work has
        already happened so 0001 is also a no-op.

    In both cases, the discriminator is "does the ``users`` table exist?"
    Future schema work happens at version 33+.
    """
    applied = await _applied_versions(db)
    if applied:
        return  # framework already in use

    cursor = await db.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'users' LIMIT 1")
    row = await cursor.fetchone()
    if row is None:
        return  # truly empty DB; SCHEMA hasn't been applied yet

    _LOGGER.info("schema: marking v1.0.0 baseline migrations 1–32 as applied")
    for mig in _discover_migrations():
        if mig["version"] <= 32:
            await _record_migration(db, mig["version"], mig["description"])


async def _record_migration(db, version: int, description: str) -> None:
    await db.execute(
        "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
        (version, description),
    )
    await db.commit()


# ── Public API ──────────────────────────────────────────────────────────────


async def run_migrations(db) -> int:
    """Apply any pending migrations.  Returns the count of newly applied ones.

    ``db`` is an open connection from ``routes.database.get_db()`` (a
    ``_PostgresConnectionCompat``); migrations are written in the portable
    SQLite-style dialect and translated by it.
    """
    await db.execute(f"SELECT pg_advisory_lock({_ADVISORY_LOCK_ID})")
    try:
        await _ensure_migrations_table(db)
        await _bootstrap_baseline(db)
        applied = await _applied_versions(db)
        pending = [m for m in _discover_migrations() if m["version"] not in applied]

        if not pending:
            _LOGGER.debug("schema: no pending migrations")
            return 0

        _LOGGER.info("schema: %d pending migration(s) to apply", len(pending))
        return await _apply_pending(db, pending, _record_migration, "schema")

    finally:
        await _release_lock(db)


async def _apply_pending(db, pending: list[dict], record, label: str, up_db=None) -> int:
    """Apply ``pending`` in order, recording each with ``record(db, version,
    description)``. ``up_db`` is the connection handed to each ``up()``
    (``db`` itself unless a guard wraps it)."""
    for mig in pending:
        ver = mig["version"]
        desc = mig["description"]
        _LOGGER.info("%s: applying migration %04d - %s", label, ver, desc)
        t0 = time.monotonic()
        try:
            await mig["up"](up_db if up_db is not None else db)
            await record(db, ver, desc)
            elapsed = (time.monotonic() - t0) * 1000
            _LOGGER.info("%s: migration %04d applied (%.0f ms)", label, ver, elapsed)
        except Exception:
            _LOGGER.error(
                "%s: migration %04d FAILED - database may need manual repair",
                label,
                ver,
                exc_info=True,
            )
            raise
    return len(pending)


async def _release_lock(db) -> None:
    try:
        await db.execute(f"SELECT pg_advisory_unlock({_ADVISORY_LOCK_ID})")
    except Exception as exc:
        _LOGGER.warning(
            "Migration cleanup failed: could not release Postgres advisory lock %s: %s",
            _ADVISORY_LOCK_ID,
            exc,
        )


# ── Plugin migrations ───────────────────────────────────────────────────────
#
# A plugin's migrations live in its own package and are tracked in
# ``plugin_schema_migrations`` keyed by (plugin, version), so plugin version
# numbers never collide with core ones or with another plugin's. They are
# applied under the same advisory lock as core migrations.

_CREATE_PLUGIN_TABLE = """
CREATE TABLE IF NOT EXISTS plugin_schema_migrations (
    plugin      TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (plugin, version)
);
"""

_SQL_STRING = re.compile(r"'(?:[^']|'')*'")
_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_IDENT = r'"?(?:[A-Za-z_][A-Za-z0-9_]*"?\.)?"?([A-Za-z_][A-Za-z0-9_]*)"?'
# The objects a statement creates, changes or writes to. Each must carry the
# plugin's table prefix. References (FOREIGN KEY ... REFERENCES hosts) and
# reads are not restricted.
_GUARDED_TARGETS = [
    re.compile(r"\bCREATE\s+(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?" + _IDENT, re.I),
    re.compile(r"\bALTER\s+(?:TABLE|INDEX|SEQUENCE|VIEW)\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?" + _IDENT, re.I),
    re.compile(r"\bDROP\s+(?:TABLE|INDEX|SEQUENCE|VIEW|TYPE)\s+(?:IF\s+EXISTS\s+)?" + _IDENT, re.I),
    # CREATE INDEX [name] ON table: both the index name and the table.
    re.compile(
        r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?:"
        + _IDENT
        + r"\s+)?ON\s+(?:ONLY\s+)?"
        + _IDENT,
        re.I,
    ),
    re.compile(
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?(?:VIEW|SEQUENCE|TYPE|FUNCTION|TRIGGER)\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?" + _IDENT,
        re.I,
    ),
    re.compile(r"^\s*INSERT\s+INTO\s+" + _IDENT, re.I),
    re.compile(r"^\s*UPDATE\s+(?:ONLY\s+)?" + _IDENT, re.I),
    re.compile(r"^\s*DELETE\s+FROM\s+(?:ONLY\s+)?" + _IDENT, re.I),
    re.compile(r"^\s*TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?" + _IDENT, re.I),
]


def plugin_statement_violations(sql: str, prefix: str) -> list[str]:
    """Names a plugin migration statement creates, alters or writes that do
    not start with ``prefix`` (lower-cased)."""
    text = _SQL_COMMENT.sub(" ", _SQL_STRING.sub("''", sql))
    bad: list[str] = []
    for pattern in _GUARDED_TARGETS:
        for match in pattern.finditer(text):
            for group in match.groups():
                name = (group or "").lower()
                if name and not name.startswith(prefix) and name not in bad:
                    bad.append(name)
    return bad


class PluginMigrationGuard:
    """The connection a plugin migration's ``up(db)`` receives: the real one,
    refusing any statement that creates, alters or writes an object outside
    the plugin's ``plugin_<name>_`` namespace. A guard against mistakes and
    collisions, not a sandbox: plugin code runs in-process and is trusted."""

    def __init__(self, db, prefix: str):
        self._db = db
        self._prefix = prefix

    async def execute(self, sql: str, *args, **kwargs):
        bad = plugin_statement_violations(sql, self._prefix)
        if bad:
            raise PermissionError(
                f"plugin migration may only create or change objects named {self._prefix}*; refused: {', '.join(bad)}"
            )
        return await self._db.execute(sql, *args, **kwargs)

    async def executescript(self, sql: str):
        for stmt in sql.split(";"):
            if stmt.strip():
                await self.execute(stmt)

    def __getattr__(self, name: str):
        return getattr(self._db, name)


async def _plugin_applied_versions(db, plugin: str) -> set[int]:
    cursor = await db.execute("SELECT version FROM plugin_schema_migrations WHERE plugin = ?", (plugin,))
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def run_plugin_migrations(db, plugin: str, package: str, table_prefix: str) -> int:
    """Apply the pending migrations of one plugin from ``package``.

    Tracked per plugin in ``plugin_schema_migrations``; every ``up(db)``
    receives a ``PluginMigrationGuard`` that holds it to ``table_prefix``.
    Returns the count of newly applied migrations; raises on the first
    failure (the caller marks the plugin failed).
    """
    await db.execute(f"SELECT pg_advisory_lock({_ADVISORY_LOCK_ID})")
    try:
        await db.execute(_CREATE_PLUGIN_TABLE)
        await db.commit()
        applied = await _plugin_applied_versions(db, plugin)
        pending = [m for m in _discover_migrations(package) if m["version"] not in applied]
        if not pending:
            return 0

        async def _record(conn, version: int, description: str) -> None:
            await conn.execute(
                "INSERT INTO plugin_schema_migrations (plugin, version, description) VALUES (?, ?, ?)",
                (plugin, version, description),
            )
            await conn.commit()

        label = f"plugin {plugin}"
        _LOGGER.info("%s: %d pending migration(s) to apply", label, len(pending))
        return await _apply_pending(db, pending, _record, label, up_db=PluginMigrationGuard(db, table_prefix))
    finally:
        await _release_lock(db)
