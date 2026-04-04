"""
Schema migration framework for Plexus.

Provides versioned, forward-only migrations with:
  - A ``schema_migrations`` table that tracks applied versions.
  - Automatic ordering by integer version number.
  - Advisory locking (Postgres) / file locking (SQLite) to prevent
    concurrent startup races.
  - Full audit logging of each migration step.

Usage:
    from routes.migrations import run_migrations
    await run_migrations(db, engine="sqlite")   # or "postgres"

Add new migrations as ``routes/migrations/NNNN_short_description.py``
where ``NNNN`` is a zero-padded, monotonically increasing version number.
Each file must expose:

    VERSION: int          — unique version number matching the filename prefix
    DESCRIPTION: str      — human-readable summary
    async def up(db):     — apply the migration (receives an open db connection)
"""

from routes.migrations.runner import run_migrations

__all__ = ["run_migrations"]
