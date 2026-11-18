"""
Migration 0112: export templates.

Adds:

  - export_templates - a Jinja2 template that renders a list of objects of
    one type (``host``, ``prefix``, ``ip_address``, ``vlan``, ``circuit``
    or ``site``) into a file: ``name`` (unique per object type, ignoring
    case), ``object_type``, ``description``, ``template_text``,
    ``mime_type`` (default ``text/plain``), ``file_extension`` (without the
    dot, default ``txt``), ``as_attachment`` (1: the download is offered as
    a file; 0: shown in the browser) and the stamps.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 112
DESCRIPTION = "Add export templates"

_TABLE = """
    CREATE TABLE IF NOT EXISTS export_templates (
        id             SERIAL PRIMARY KEY,
        name           TEXT NOT NULL,
        object_type    TEXT NOT NULL,
        description    TEXT NOT NULL DEFAULT '',
        template_text  TEXT NOT NULL DEFAULT '',
        mime_type      TEXT NOT NULL DEFAULT 'text/plain',
        file_extension TEXT NOT NULL DEFAULT 'txt',
        as_attachment  INTEGER NOT NULL DEFAULT 1,
        created_by     TEXT NOT NULL DEFAULT '',
        created_at     TEXT NOT NULL DEFAULT '',
        updated_at     TEXT NOT NULL DEFAULT '',
        updated_by     TEXT NOT NULL DEFAULT ''
    )
"""

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_export_templates_type_name ON export_templates (object_type, lower(name))",
)


async def up(db) -> None:
    await db.execute(_TABLE)
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
