"""
Migration 0105: ChatOps - Slack, Webex and Microsoft Teams bots.

Adds:

  - chatops_bots - one bot per platform (``slack``, ``webex``, ``teams``):
    display name, enabled flag, the request-signing secret (Slack signing
    secret, Webex webhook secret, Teams outgoing-webhook security token) and
    the bot token used to post replies (Slack ``xoxb-`` token, Webex bot
    access token; Teams replies in the HTTP response and has none), both
    encrypted with ``routes.crypto``; the commands the bot accepts (a JSON
    list; write commands are off until an admin adds them) and the stamps.
  - chatops_user_mappings - a chat identity (platform and the user id or
    e-mail the platform sends) mapped to the Plexus user whose permissions
    its commands run with; deleted with the user. One mapping per chat
    identity (platform, lower(chat_user_id)).
  - chatops_job_presets - the allowlist of jobs chat may launch: a name
    (unique ignoring case), description, the launch spec copied from a
    finished job (JSON: playbook, targets, credential, template, inputs),
    whether it runs with commit (else a dry run), an enabled flag and the
    stamps.
  - chatops_command_log - one row per command received: platform, chat
    identity and name, the Plexus user it ran as (``''`` when unmapped),
    the command and its arguments, the outcome (``ok``, ``denied``,
    ``unmapped``, ``error``, ``unknown``, ``rate_limited``), a short detail
    and the duration. Pruned by age by the application.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 105
DESCRIPTION = "Add ChatOps bots, user mappings, job presets and command log"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TABLES: tuple[tuple[str, str], ...] = (
    (
        "chatops_bots",
        f"""
            id                 SERIAL PRIMARY KEY,
            platform           TEXT NOT NULL UNIQUE,
            name               TEXT NOT NULL DEFAULT '',
            enabled            INTEGER NOT NULL DEFAULT 1,
            signing_secret_enc TEXT NOT NULL DEFAULT '',
            bot_token_enc      TEXT NOT NULL DEFAULT '',
            allowed_commands   TEXT NOT NULL DEFAULT '[]',
            {_STAMPS}
        """,
    ),
    (
        "chatops_user_mappings",
        """
            id            SERIAL PRIMARY KEY,
            platform      TEXT NOT NULL,
            chat_user_id  TEXT NOT NULL,
            chat_label    TEXT NOT NULL DEFAULT '',
            user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_by    TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT ''
        """,
    ),
    (
        "chatops_job_presets",
        f"""
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            spec        TEXT NOT NULL DEFAULT '{{}}',
            source_job_id INTEGER,
            playbook_name TEXT NOT NULL DEFAULT '',
            commit_mode INTEGER NOT NULL DEFAULT 0,
            enabled     INTEGER NOT NULL DEFAULT 1,
            {_STAMPS}
        """,
    ),
    (
        "chatops_command_log",
        """
            id             SERIAL PRIMARY KEY,
            created_at     TEXT NOT NULL DEFAULT '',
            platform       TEXT NOT NULL DEFAULT '',
            chat_user_id   TEXT NOT NULL DEFAULT '',
            chat_user_name TEXT NOT NULL DEFAULT '',
            username       TEXT NOT NULL DEFAULT '',
            command        TEXT NOT NULL DEFAULT '',
            arguments      TEXT NOT NULL DEFAULT '',
            outcome        TEXT NOT NULL DEFAULT '',
            detail         TEXT NOT NULL DEFAULT '',
            duration_ms    INTEGER NOT NULL DEFAULT 0
        """,
    ),
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_chatops_mappings_identity "
    "ON chatops_user_mappings (platform, lower(chat_user_id))",
    "CREATE INDEX IF NOT EXISTS idx_chatops_mappings_user ON chatops_user_mappings (user_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_chatops_presets_name ON chatops_job_presets (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_chatops_command_log_created ON chatops_command_log (created_at)",
)


async def up(db) -> None:
    for table, columns in _TABLES:
        await db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")  # nosec B608 - fixed DDL
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
