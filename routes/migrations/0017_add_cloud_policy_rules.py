"""
Migration 0017: Add cloud policy rule visibility table.

Adds:
  - cloud_policy_rules (AWS SG / Azure NSG / GCP firewall rules discovered per account)
"""

from __future__ import annotations

VERSION = 17
DESCRIPTION = "Add cloud policy rule visibility table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_policy_rules (
            id                   SERIAL PRIMARY KEY,
            account_id           INTEGER NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            provider             TEXT    NOT NULL,
            resource_uid         TEXT    NOT NULL,
            rule_uid             TEXT    NOT NULL,
            rule_name            TEXT    NOT NULL DEFAULT '',
            direction            TEXT    NOT NULL DEFAULT '',
            action               TEXT    NOT NULL DEFAULT '',
            protocol             TEXT    NOT NULL DEFAULT '',
            source_selector      TEXT    NOT NULL DEFAULT '',
            destination_selector TEXT    NOT NULL DEFAULT '',
            port_expression      TEXT    NOT NULL DEFAULT '',
            priority             INTEGER,
            metadata_json        TEXT    NOT NULL DEFAULT '{}',
            discovered_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(account_id, rule_uid)
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_policy_rules_account_resource
        ON cloud_policy_rules (account_id, resource_uid)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cloud_policy_rules_provider_action
        ON cloud_policy_rules (provider, action, direction)
        """
    )
    await db.commit()
