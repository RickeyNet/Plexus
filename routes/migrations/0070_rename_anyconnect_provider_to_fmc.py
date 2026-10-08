"""
Migration 0070: the "anyconnect" topology provider becomes "fmc".

The integration that read one Cisco FMC for its remote access VPN now reads
the whole FMC (every FTD, routing, NAT, policies, site-to-site VPN), so its
provider key is renamed:

  - meraki_orgs.provider "anyconnect" -> "fmc"
  - software_versions.source "anyconnect" -> "fmc"
  - the software tracker's device keys (``{provider}:{org_ref}:{serial or
    node}``) in software_versions, software_version_history and
    software_alerts (the tables of 0067 that hold one): "anyconnect:..." ->
    "fmc:...", so a tracked FTD keeps its version history and alerts

Stored snapshots are left as they are: the routes read a snapshot whose
``provider`` is "anyconnect" as "fmc". A row whose new key is already taken
(impossible before this release, but the unique constraints must never
fail the upgrade) is dropped in favour of the existing one.
"""

from __future__ import annotations

VERSION = 70
DESCRIPTION = "Rename the anyconnect topology provider to fmc"


# 'anyconnect:' is 11 characters: the rest of the key starts at 12. The same
# SQL runs on SQLite and PostgreSQL (substr and || are common to both).
_NEW_KEY = "'fmc:' || substr({column}, 12)"
_IS_OLD = "{column} LIKE 'anyconnect:%'"

_STATEMENTS = (
    "UPDATE meraki_orgs SET provider = 'fmc' WHERE provider = 'anyconnect'",
    # software_versions.device_key is unique.
    "DELETE FROM software_versions WHERE "
    + _IS_OLD.format(column="device_key")
    + " AND "
    + _NEW_KEY.format(column="device_key")
    + " IN (SELECT device_key FROM software_versions)",
    "UPDATE software_versions SET source = 'fmc' WHERE source = 'anyconnect'",
    "UPDATE software_versions SET device_key = "
    + _NEW_KEY.format(column="device_key")
    + " WHERE "
    + _IS_OLD.format(column="device_key"),
    "UPDATE software_version_history SET device_key = "
    + _NEW_KEY.format(column="device_key")
    + " WHERE "
    + _IS_OLD.format(column="device_key"),
    # software_alerts is unique on (device_key, advisory_id).
    "DELETE FROM software_alerts WHERE "
    + _IS_OLD.format(column="device_key")
    + " AND EXISTS (SELECT 1 FROM software_alerts AS other WHERE other.device_key = "
    + _NEW_KEY.format(column="software_alerts.device_key")
    + " AND other.advisory_id = software_alerts.advisory_id)",
    "UPDATE software_alerts SET device_key = "
    + _NEW_KEY.format(column="device_key")
    + " WHERE "
    + _IS_OLD.format(column="device_key"),
)


async def up(db) -> None:
    for statement in _STATEMENTS:
        await db.execute(statement)
    await db.commit()
