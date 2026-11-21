"""OPNsense firewall log evidence: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0120 (``opnsense_filterlog_hits``,
``opnsense_filterlog_flows``). The parser and the in-memory aggregate live
in ``netcontrol.integrations.opnsense.filterlog``; the receiver glue, the
rule view and the path trace evidence in
``netcontrol.routes.opnsense_filterlog``. Rows are written by a batched
upsert per flush (never per log line); the flows are trimmed to the
newest few per host, rule and action.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

from collections.abc import Iterable

import routes.database as _dbcore
from routes.db.device_model import _select

__all__ = [
    "delete_old_opnsense_filterlog",
    "get_opnsense_filterlog_flows",
    "get_opnsense_filterlog_last_seen",
    "get_opnsense_filterlog_rule_summary",
    "hosts_with_opnsense_filterlog",
    "upsert_opnsense_filterlog",
]

_UPSERT_HITS = """
INSERT INTO opnsense_filterlog_hits
    (host_id, bucket, rule_key, action, interface, direction, hits, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (host_id, bucket, rule_key, action, interface, direction) DO UPDATE SET
    hits = opnsense_filterlog_hits.hits + excluded.hits,
    last_seen = CASE WHEN excluded.last_seen > opnsense_filterlog_hits.last_seen
                     THEN excluded.last_seen ELSE opnsense_filterlog_hits.last_seen END
"""
_UPSERT_FLOWS = """
INSERT INTO opnsense_filterlog_flows
    (host_id, rule_key, action, source, destination, protocol, destination_port, hits, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (host_id, rule_key, action, source, destination, protocol, destination_port) DO UPDATE SET
    hits = opnsense_filterlog_flows.hits + excluded.hits,
    last_seen = CASE WHEN excluded.last_seen > opnsense_filterlog_flows.last_seen
                     THEN excluded.last_seen ELSE opnsense_filterlog_flows.last_seen END
"""
# The flows beyond the newest ``?`` of each host, rule and action.
_TRIM_FLOWS = """
DELETE FROM opnsense_filterlog_flows WHERE id IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY host_id, rule_key, action ORDER BY last_seen DESC, id DESC
        ) AS place
        FROM opnsense_filterlog_flows WHERE host_id IN ({hosts})
    ) ranked WHERE place > ?
)
"""


def _marks(count: int) -> str:
    return ", ".join("?" for _ in range(count))


async def upsert_opnsense_filterlog(hits: list[tuple], flows: list[tuple], flows_per_rule: int = 25) -> int:
    """Add a flush of the aggregate in one transaction: ``hits`` rows
    ``(host_id, bucket, rule_key, action, interface, direction, hits,
    last_seen)`` and ``flows`` rows ``(host_id, rule_key, action, source,
    destination, protocol, destination_port, hits, last_seen)`` are summed
    into what is stored; then each host's flows are trimmed to the newest
    ``flows_per_rule`` per rule and action. Returns the rows written."""
    if not hits and not flows:
        return 0
    db = await _dbcore.get_db()
    try:
        if hits:
            await db.executemany(_UPSERT_HITS, hits)
        if flows:
            await db.executemany(_UPSERT_FLOWS, flows)
            hosts = sorted({int(row[0]) for row in flows})
            await db.execute(
                _TRIM_FLOWS.format(hosts=_marks(len(hosts))),  # nosec B608 - placeholders only
                (*hosts, int(flows_per_rule)),
            )
        await db.commit()
        return len(hits) + len(flows)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def hosts_with_opnsense_filterlog(host_ids: Iterable[int], since: str) -> set[int]:
    """The hosts of ``host_ids`` with evidence received since ``since``."""
    wanted = sorted({int(h) for h in host_ids})
    if not wanted:
        return set()
    rows = await _select(
        f"SELECT DISTINCT host_id FROM opnsense_filterlog_hits WHERE host_id IN ({_marks(len(wanted))})"  # nosec B608 - placeholders only
        " AND last_seen >= ?",
        (*wanted, since),
    )
    return {int(r["host_id"]) for r in rows}


async def get_opnsense_filterlog_last_seen(host_id: int) -> str:
    """When the newest evidence of a host was received ("" when never, or
    no longer kept)."""
    rows = await _select(
        "SELECT MAX(last_seen) AS last_seen FROM opnsense_filterlog_hits WHERE host_id = ?", (host_id,)
    )
    return str((rows[0] if rows else {}).get("last_seen") or "")


async def get_opnsense_filterlog_rule_summary(host_id: int, since: str, recent: str) -> list[dict]:
    """The hits of each rule and action of a host since ``since`` (and
    since ``recent``, a later time) by bucket start, with the interfaces
    and directions they were logged on and when the last one came."""
    rows = await _select(
        """
        SELECT rule_key, action, interface, direction,
               SUM(hits) AS hits,
               SUM(CASE WHEN bucket >= ? THEN hits ELSE 0 END) AS recent_hits,
               MAX(last_seen) AS last_seen
        FROM opnsense_filterlog_hits
        WHERE host_id = ? AND bucket >= ?
        GROUP BY rule_key, action, interface, direction
        """,
        (recent, int(host_id), since),
    )
    return [
        {
            "rule_key": r["rule_key"],
            "action": r["action"],
            "interface": r["interface"] or "",
            "direction": r["direction"] or "",
            "hits": int(r["hits"] or 0),
            "recent_hits": int(r["recent_hits"] or 0),
            "last_seen": r["last_seen"] or "",
        }
        for r in rows
    ]


async def get_opnsense_filterlog_flows(
    host_id: int, since: str, rule_keys: Iterable[str] | None = None, limit: int = 2000
) -> list[dict]:
    """The logged flows of a host seen since ``since``, newest first;
    ``rule_keys`` keeps those of these rules."""
    params: list = [int(host_id), since]
    where = ""
    if rule_keys is not None:
        keys = sorted(set(rule_keys))
        if not keys:
            return []
        where = f" AND rule_key IN ({_marks(len(keys))})"
        params.extend(keys)
    params.append(int(limit))
    rows = await _select(
        "SELECT rule_key, action, source, destination, protocol, destination_port, hits, last_seen"
        " FROM opnsense_filterlog_flows WHERE host_id = ? AND last_seen >= ?"
        + where  # nosec B608 - placeholders only
        + " ORDER BY last_seen DESC, id DESC LIMIT ?",
        tuple(params),
    )
    return [
        {
            "rule_key": r["rule_key"],
            "action": r["action"],
            "source": r["source"],
            "destination": r["destination"],
            "protocol": r["protocol"] or "",
            "destination_port": int(r["destination_port"] or 0) or None,
            "hits": int(r["hits"] or 0),
            "last_seen": r["last_seen"] or "",
        }
        for r in rows
    ]


async def delete_old_opnsense_filterlog(retention_days: int) -> int:
    """Remove the buckets and flows older than ``retention_days``."""
    cutoff = "datetime('now', '-' || ? || ' days')"
    deleted = await _dbcore.chunked_delete("opnsense_filterlog_hits", f"bucket < {cutoff}", (retention_days,))
    deleted += await _dbcore.chunked_delete("opnsense_filterlog_flows", f"last_seen < {cutoff}", (retention_days,))
    return deleted
