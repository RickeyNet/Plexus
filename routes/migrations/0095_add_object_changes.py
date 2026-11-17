"""
Migration 0095: the per-object change log.

Adds:

  - object_changes - one row per create, update or delete of a tracked
    object (``routes.db.change_events``): the object (``object_type``,
    ``object_id`` and ``object_label``, a display name kept so a deleted
    object still reads well), the ``action``, the acting ``username``, the
    request ``correlation_id`` (``X-Correlation-ID``; empty outside a
    request), ``changed_at`` (UTC ``YYYY-MM-DD HH:MM:SS`` text, like the other
    Plexus timestamps), the field-by-field ``changes_json`` of an update
    (``{"field": {"before": x, "after": y}}``) and the ``before_json`` /
    ``after_json`` snapshots (secrets removed and masked before they are
    written). ``scope_group_id`` is the inventory group the object belonged
    to (a host's group, a group's own id, a config backup's host's group) so
    object-level permissions can filter the log; NULL for every other type.
    Purged after the change log retention (Settings > System).

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 95
DESCRIPTION = "Add the per-object change log (object_changes)"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS object_changes (
            id             SERIAL PRIMARY KEY,
            object_type    TEXT    NOT NULL,
            object_id      TEXT    NOT NULL,
            object_label   TEXT    NOT NULL DEFAULT '',
            action         TEXT    NOT NULL,
            username       TEXT    NOT NULL DEFAULT '',
            correlation_id TEXT    NOT NULL DEFAULT '',
            changed_at     TEXT    NOT NULL DEFAULT '',
            scope_group_id INTEGER,
            changes_json   TEXT    NOT NULL DEFAULT '{}',
            before_json    TEXT,
            after_json     TEXT
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_object_changes_object ON object_changes (object_type, object_id, changed_at)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_object_changes_changed_at ON object_changes (changed_at)")
    await db.commit()
