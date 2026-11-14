"""
Migration 0087: intended configuration generation.

Reshapes and adds:

  - config_templates - reserved (and empty) since migration 0042. Becomes
    the Jinja2 templates of intended configurations: ``kind`` (``device``,
    rendered for hosts, or ``snippet``, only included by other templates),
    a scope (``device_type`` with ``''`` for any driver, and ``role_id``,
    ``site_id``, ``group_id`` with NULL for any; plain integers, no foreign
    key), ``enabled`` and ``updated_by``. The old ``UNIQUE (name,
    device_type)`` is dropped; names are unique ignoring case.
  - config_contexts - JSON data (an object as text) merged by ``weight``
    into one ``context`` per device, scoped like the templates plus one
    ``host_id``.
  - intended_configs - one row per host that has a matching template: the
    rendered text, its status and error, and the comparison with the host's
    newest configuration backup. Deleted with the host.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

VERSION = 87
DESCRIPTION = "Add intended configuration templates, config contexts and intended configurations"

_TEMPLATE_COLUMNS = (
    "kind        TEXT    NOT NULL DEFAULT 'device'",
    "role_id     INTEGER",
    "site_id     INTEGER",
    "group_id    INTEGER",
    "enabled     INTEGER NOT NULL DEFAULT 1",
    "updated_by  TEXT    NOT NULL DEFAULT ''",
)


async def _reshape_templates(db) -> None:
    # Created by 0042; created here too so the migration stands on its own.
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_templates (
            id              BIGSERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            device_type     TEXT NOT NULL DEFAULT '',
            template_text   TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT '',
            updated_at      TEXT NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("ALTER TABLE config_templates DROP CONSTRAINT IF EXISTS config_templates_name_device_type_key")
    for column in _TEMPLATE_COLUMNS:
        await db.execute(f"ALTER TABLE config_templates ADD COLUMN IF NOT EXISTS {column}")
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_config_templates_name_lower ON config_templates (lower(name))"
    )


async def _create_tables(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_contexts (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            weight      INTEGER NOT NULL DEFAULT 1000,
            data        TEXT    NOT NULL DEFAULT '{}',
            description TEXT    NOT NULL DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            device_type TEXT    NOT NULL DEFAULT '',
            role_id     INTEGER,
            site_id     INTEGER,
            group_id    INTEGER,
            host_id     INTEGER,
            created_at  TEXT    NOT NULL DEFAULT '',
            updated_at  TEXT    NOT NULL DEFAULT '',
            updated_by  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_config_contexts_name_lower ON config_contexts (lower(name))"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS intended_configs (
            host_id       INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
            template_id   INTEGER,
            template_name TEXT    NOT NULL DEFAULT '',
            status        TEXT    NOT NULL DEFAULT 'ok',
            error         TEXT    NOT NULL DEFAULT '',
            config_text   TEXT    NOT NULL DEFAULT '',
            generated_at  TEXT    NOT NULL DEFAULT '',
            changed_at    TEXT    NOT NULL DEFAULT '',
            compliance    TEXT    NOT NULL DEFAULT 'unknown',
            backup_id     INTEGER,
            missing_count INTEGER NOT NULL DEFAULT 0,
            extra_count   INTEGER NOT NULL DEFAULT 0,
            compared_at   TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_intended_configs_template ON intended_configs (template_id)")


async def up(db) -> None:
    await _reshape_templates(db)
    await _create_tables(db)
    await db.commit()
