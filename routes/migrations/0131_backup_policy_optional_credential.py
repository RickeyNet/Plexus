"""
Migration 0131: a config backup policy's credential is optional.

Changes:

  - config_backup_policies.credential_id - nullable. A policy without a
    credential backs up only the devices read over an API (an OPNsense
    firewall: its config.xml over the API key of its OPNsense topology
    source); a device read over SSH gets an error row that says the policy
    has no credential. The reference to ``credentials`` and its
    ``ON DELETE CASCADE`` stay as they are.

Every step is idempotent: dropping NOT NULL from a nullable column is a
no-op in Postgres.
"""

from __future__ import annotations

VERSION = 131
DESCRIPTION = "Make the credential of a config backup policy optional"


async def up(db) -> None:
    await db.execute("ALTER TABLE config_backup_policies ALTER COLUMN credential_id DROP NOT NULL")
    await db.commit()
