"""Example plugin migration 0001: the spare-parts table."""

from __future__ import annotations

VERSION = 1
DESCRIPTION = "Create plugin_example_spares"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS plugin_example_spares (
            id          SERIAL PRIMARY KEY,
            part        TEXT    NOT NULL,
            site        TEXT    NOT NULL DEFAULT '',
            quantity    INTEGER NOT NULL DEFAULT 0,
            created_by  TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS plugin_example_spares_part ON plugin_example_spares (part)")
