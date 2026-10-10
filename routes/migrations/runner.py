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
import time
from pathlib import Path

from netcontrol.telemetry import configure_logging

_LOGGER = configure_logging("plexus.migrations")

_ADVISORY_LOCK_ID = 0x504C5853  # "PLXS" as a 32-bit int


# ── Discovery ───────────────────────────────────────────────────────────────


def _discover_migrations() -> list[dict]:
    """Return a sorted list of ``{version, description, module}`` dicts."""
    pkg_dir = Path(__file__).resolve().parent
    found: list[dict] = []

    for info in pkgutil.iter_modules([str(pkg_dir)]):
        name = info.name
        if name.startswith("_") or name == "runner":
            continue
        # Expect filenames like "0001_add_playbook_columns.py"
        parts = name.split("_", 1)
        if not parts[0].isdigit():
            continue
        version = int(parts[0])
        mod = importlib.import_module(f"routes.migrations.{name}")
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

        for mig in pending:
            ver = mig["version"]
            desc = mig["description"]
            _LOGGER.info("schema: applying migration %04d - %s", ver, desc)
            t0 = time.monotonic()
            try:
                await mig["up"](db)
                await _record_migration(db, ver, desc)
                elapsed = (time.monotonic() - t0) * 1000
                _LOGGER.info("schema: migration %04d applied (%.0f ms)", ver, elapsed)
            except Exception:
                _LOGGER.error(
                    "schema: migration %04d FAILED - database may need manual repair",
                    ver,
                    exc_info=True,
                )
                raise

        return len(pending)

    finally:
        try:
            await db.execute(f"SELECT pg_advisory_unlock({_ADVISORY_LOCK_ID})")
        except Exception as exc:
            _LOGGER.warning(
                "Migration cleanup failed: could not release Postgres advisory lock %s: %s",
                _ADVISORY_LOCK_ID,
                exc,
            )
