"""
Migration 0111: SAML assertion replay cache (and object scope rules).

Adds:

  - saml_assertion_ids - the ID of every SAML assertion Plexus accepted,
    with ``expires_at`` (the assertion's ``NotOnOrAfter``, epoch seconds).
    A second sign-in with an ID already present is refused as a replay,
    across every worker process. Rows past ``expires_at`` are pruned by
    ``routes.db.saml``; an assertion past that time is refused anyway.
  - access_group_scope_rules - per-model object scope rules (by tenant or
    site) for records with no inventory group (see the block at the end).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 111
DESCRIPTION = "Add the SAML assertion replay cache and object scope rules"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS saml_assertion_ids (
            assertion_id TEXT    PRIMARY KEY,
            expires_at   BIGINT  NOT NULL,
            created_at   TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_saml_assertion_ids_expires_at ON saml_assertion_ids (expires_at)")

    # ── Object scope rules (netcontrol.object_scope) ─────────────────────
    # access_group_scope_rules - extra grants of an access group whose
    # ``object_scope`` is ``groups``, for records with no inventory group:
    # ``model`` (a name of the object scope model registry, or ``*`` for
    # every model), ``attribute`` (``tenant`` or ``site``), ``value_id``
    # (the tenant or site id) and ``can_write`` (0: read only, 1: read and
    # write). Deleted with the access group; a rule whose tenant or site is
    # gone matches nothing.
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS access_group_scope_rules (
            id              SERIAL PRIMARY KEY,
            access_group_id INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
            model           TEXT    NOT NULL,
            attribute       TEXT    NOT NULL,
            value_id        INTEGER NOT NULL,
            can_write       INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_access_group_scope_rules_unique "
        "ON access_group_scope_rules (access_group_id, model, attribute, value_id)"
    )
    await db.commit()
