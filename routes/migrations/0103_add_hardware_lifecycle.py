"""
Migration 0103: hardware lifecycle - end-of-life notices and support
contracts.

Adds:

  - hardware_notices - a vendor's end-of-life notice for a hardware model:
    exactly one of ``device_type_id`` (a ``device_types`` row of the device
    model catalogue; the notice is deleted with it, one notice per device
    type) or ``part_number`` (unique ignoring case; matches device types by
    part number or model and DCIM modules by part number), the milestones
    ``end_of_sale``, ``end_of_sw_maintenance``, ``end_of_security_fixes``
    and ``end_of_support`` (``YYYY-MM-DD`` text, ``''`` when unknown),
    ``documentation_url``, ``comments`` and the stamps.
  - support_contracts - a support contract: ``provider`` (vendor or
    reseller) and ``contract_id`` (unique per provider ignoring case),
    ``start_date`` and ``end_date`` (``YYYY-MM-DD``, ``''`` when open),
    ``cost`` (NUMERIC, NULL when unset) and ``currency`` (ISO 4217 code or
    ``''``), ``support_level``, ``description``, ``comments`` and the stamps.
  - support_contract_hosts - the devices (``hosts``) a contract covers,
    many to many; a link goes with its contract or its host.
  - hardware_lifecycle_settings - key/value settings of the lifecycle alert
    check (on/off, warning windows, last run).
  - hardware_lifecycle_alerts - the lifecycle conditions an alert was raised
    for (``dedup_key`` of the monitoring alert, its host and kind), so a
    condition alerts once while it lasts, also after the alert is
    acknowledged, and its alert is resolved when it clears. Deleted with the
    host.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 103
DESCRIPTION = "Add hardware lifecycle: end-of-life notices and support contracts"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TABLES: tuple[tuple[str, str], ...] = (
    (
        "hardware_notices",
        f"""
            id                    SERIAL PRIMARY KEY,
            device_type_id        INTEGER REFERENCES device_types(id) ON DELETE CASCADE,
            part_number           TEXT NOT NULL DEFAULT '',
            end_of_sale           TEXT NOT NULL DEFAULT '',
            end_of_sw_maintenance TEXT NOT NULL DEFAULT '',
            end_of_security_fixes TEXT NOT NULL DEFAULT '',
            end_of_support        TEXT NOT NULL DEFAULT '',
            documentation_url     TEXT NOT NULL DEFAULT '',
            comments              TEXT NOT NULL DEFAULT '',
            {_STAMPS},
            CHECK ((device_type_id IS NULL) <> (part_number = ''))
        """,
    ),
    (
        "support_contracts",
        f"""
            id            SERIAL PRIMARY KEY,
            provider      TEXT NOT NULL,
            contract_id   TEXT NOT NULL,
            start_date    TEXT NOT NULL DEFAULT '',
            end_date      TEXT NOT NULL DEFAULT '',
            cost          NUMERIC(14, 2) CHECK (cost IS NULL OR cost >= 0),
            currency      TEXT NOT NULL DEFAULT '',
            support_level TEXT NOT NULL DEFAULT '',
            description   TEXT NOT NULL DEFAULT '',
            comments      TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "support_contract_hosts",
        """
            contract_id INTEGER NOT NULL REFERENCES support_contracts(id) ON DELETE CASCADE,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (contract_id, host_id)
        """,
    ),
    (
        "hardware_lifecycle_settings",
        """
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        """,
    ),
    (
        "hardware_lifecycle_alerts",
        """
            dedup_key  TEXT PRIMARY KEY,
            host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            kind       TEXT NOT NULL,
            message    TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL DEFAULT '',
            last_seen  TEXT NOT NULL DEFAULT ''
        """,
    ),
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_notices_device_type ON hardware_notices (device_type_id)"
    " WHERE device_type_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_notices_part_number ON hardware_notices (lower(part_number))"
    " WHERE part_number <> ''",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_support_contracts_provider_id"
    " ON support_contracts (lower(provider), lower(contract_id))",
    "CREATE INDEX IF NOT EXISTS idx_support_contracts_end_date ON support_contracts (end_date)",
    "CREATE INDEX IF NOT EXISTS idx_support_contract_hosts_host ON support_contract_hosts (host_id)",
    "CREATE INDEX IF NOT EXISTS idx_hardware_lifecycle_alerts_host ON hardware_lifecycle_alerts (host_id)",
)


async def up(db) -> None:
    for table, columns in _TABLES:
        await db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")  # nosec B608 - fixed DDL
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
