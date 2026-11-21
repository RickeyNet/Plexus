"""The last byte counter reading of each tunnel (migration 0125).

``topology_traffic_counters`` keeps, per source and traffic key, the
counters of the last reading and when it was taken, and the tracked entity
the key belongs to. A stored collection and a monitoring poll of the
firewall each compute the rate since that reading
(``netcontrol.integrations.traffic``) and then replace it
(``netcontrol.routes.topology_traffic``). A reading is only written over
an older one, so a late writer never moves the store back in time. The
rows of a source go with it (``delete_meraki_org``) and with the monitoring
retention (``purge_topology_entity_metrics``).
"""

from __future__ import annotations

import json
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "get_topology_traffic_counters",
    "save_topology_traffic_counters",
]


def _counters(text: Any) -> dict | None:
    if not text:
        return None
    try:
        found = json.loads(str(text))
    except ValueError:
        return None
    return found if isinstance(found, dict) else None


async def get_topology_traffic_counters(provider: str, org_ref: int) -> dict[str, dict[str, Any]]:
    """The last reading of every key of one source: ``{key: {"entity_type",
    "entity_id", "counters" (``None`` when not known), "read_at"}}``."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT traffic_key, entity_type, entity_id, counters_json, read_at FROM topology_traffic_counters
               WHERE provider = ? AND org_ref = ?""",
            (str(provider), int(org_ref)),
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    return {
        str(r["traffic_key"]): {
            "entity_type": str(r["entity_type"] or ""),
            "entity_id": str(r["entity_id"] or ""),
            "counters": _counters(r["counters_json"]),
            "read_at": str(r["read_at"] or ""),
        }
        for r in rows
    }


async def save_topology_traffic_counters(
    provider: str,
    org_ref: int,
    readings: list[dict[str, Any]],
    read_at: str,
    *,
    replace: bool = False,
) -> int:
    """Store the readings (``{"key", "entity_type", "entity_id",
    "counters"}``) of one source taken at ``read_at``, each over its key's
    older reading only. ``replace`` (a collection, which lists every key the
    source has): drop the keys not in ``readings``. Returns the rows
    written."""
    rows = [
        (
            str(provider),
            int(org_ref),
            str(r["key"]),
            str(r.get("entity_type") or ""),
            str(r.get("entity_id") or ""),
            json.dumps(r["counters"], sort_keys=True) if isinstance(r.get("counters"), dict) else None,
            read_at,
        )
        for r in readings
    ]
    db = await _dbcore.get_db()
    try:
        if rows:
            await db.executemany(
                """INSERT INTO topology_traffic_counters
                   (provider, org_ref, traffic_key, entity_type, entity_id, counters_json, read_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (provider, org_ref, traffic_key) DO UPDATE SET
                       entity_type = excluded.entity_type,
                       entity_id = excluded.entity_id,
                       counters_json = excluded.counters_json,
                       read_at = excluded.read_at
                   WHERE topology_traffic_counters.read_at <= excluded.read_at""",
                rows,
            )
        if replace:
            keys = [row[2] for row in rows]
            marks = ", ".join("?" for _ in keys)
            await db.execute(
                "DELETE FROM topology_traffic_counters WHERE provider = ? AND org_ref = ?"
                + (f" AND traffic_key NOT IN ({marks})" if keys else ""),
                (str(provider), int(org_ref), *keys),
            )
        await db.commit()
    finally:
        await db.close()
    return len(rows)
