"""
Migration 0107: tool history (path traces, reachability sweeps, summaries).

Adds:

  - tool_history - the last runs of each user in Path Mode, the
    Reachability sweep and Summarize, so one can be opened again with a
    click: ``user_id`` (deleted with the user), ``kind`` (``path``,
    ``reachability`` or ``summarize``), ``signature`` (what makes two runs
    the same, unique per user and kind: running the same one again moves it
    to the top instead of adding a second row, under a new id, since the
    list is ordered by id), ``data`` (the inputs as JSONB, as the page sent
    them) and ``used_at``. Plexus keeps the newest ``TOOL_HISTORY_LIMIT``
    rows per user and kind (``routes.db.tool_history``).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 107
DESCRIPTION = "Add tool history (the last path traces, reachability sweeps and summaries of each user)"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS tool_history (
            id        SERIAL  PRIMARY KEY,
            user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            kind      TEXT    NOT NULL,
            signature TEXT    NOT NULL,
            data      JSONB   NOT NULL DEFAULT '{}'::jsonb,
            used_at   TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_history_user_kind_signature "
        "ON tool_history (user_id, kind, signature)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_tool_history_user_kind_id ON tool_history (user_id, kind, id)")
    await db.commit()
