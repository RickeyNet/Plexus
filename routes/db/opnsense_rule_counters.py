"""OPNsense rule counter history: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0127 (``opnsense_rule_counters``). The collection reads the
filter rule counters (``netcontrol.integrations.opnsense.collector``,
``firewall/filter_util/rule_stats``) and records them here for the
firewall's inventory host
(``netcontrol.routes.opnsense_collection.attach_rule_stats``); the rule
views read them back (``netcontrol.routes.opnsense_rules``) and
``netcontrol.integrations.opnsense.rules.analyze`` turns them into each
rule's history.

pf resets its counters at a reboot and at every filter reload, so the
growth of a counter since the previous read is ``current - previous`` when
it did not go down, else ``current`` (it restarted from zero). The packets
and bytes grown are summed into ``total_packets`` / ``total_bytes``, and
``last_hit_at`` is the read at which the packet counter last grew (a label
first seen with packets already counted: that read). One batched upsert per
collection; a label the firewall has not reported for
``RULE_COUNTER_RETENTION_DAYS`` (the rule was deleted, or edited into a new
label) is removed. Rows go with their host.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import routes.database as _dbcore
from routes.db.device_model import _select

__all__ = [
    "RULE_COUNTER_RETENTION_DAYS",
    "get_opnsense_rule_counters",
    "record_opnsense_rule_counters",
]

# How long the history of a label the firewall no longer reports is kept.
RULE_COUNTER_RETENTION_DAYS = 30

_COUNTERS = ("evaluations", "packets", "bytes", "states", "pf_rules")
_STORED_TIME = "%Y-%m-%d %H:%M:%S"

# ``excluded`` is this read, the table's columns the previous one. The
# growth of a counter: current - previous, or current after a reset (or
# without a previous value); 0 when this read lacks the counter.
_UPSERT = """
INSERT INTO opnsense_rule_counters
    (host_id, label, evaluations, packets, bytes, states, pf_rules,
     total_packets, total_bytes, first_seen_at, last_seen_at, last_hit_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (host_id, label) DO UPDATE SET
    total_packets = opnsense_rule_counters.total_packets + COALESCE(
        CASE WHEN excluded.packets >= opnsense_rule_counters.packets
             THEN excluded.packets - opnsense_rule_counters.packets ELSE excluded.packets END, 0),
    total_bytes = opnsense_rule_counters.total_bytes + COALESCE(
        CASE WHEN excluded.bytes >= opnsense_rule_counters.bytes
             THEN excluded.bytes - opnsense_rule_counters.bytes ELSE excluded.bytes END, 0),
    last_hit_at = CASE WHEN COALESCE(
        CASE WHEN excluded.packets >= opnsense_rule_counters.packets
             THEN excluded.packets - opnsense_rule_counters.packets ELSE excluded.packets END, 0) > 0
        THEN excluded.last_seen_at ELSE opnsense_rule_counters.last_hit_at END,
    evaluations = excluded.evaluations,
    packets = excluded.packets,
    bytes = excluded.bytes,
    states = excluded.states,
    pf_rules = excluded.pf_rules,
    last_seen_at = excluded.last_seen_at
WHERE excluded.last_seen_at > opnsense_rule_counters.last_seen_at
"""


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return max(int(value), 0)


def _cutoff(read_at: str, days: int) -> str | None:
    try:
        return (datetime.strptime(read_at, _STORED_TIME) - timedelta(days=days)).strftime(_STORED_TIME)
    except ValueError:
        return None


async def record_opnsense_rule_counters(
    host_id: int,
    counters: dict[str, dict[str, int]],
    read_at: str,
    retention_days: int = RULE_COUNTER_RETENTION_DAYS,
) -> dict[str, int]:
    """Add one read of a host's rule counters (``{label: {"evaluations",
    "packets", "bytes", "states", "pf_rules"}}``, as
    ``rules.parse_rule_stats`` gives them) read at ``read_at`` (UTC text),
    then remove the labels not reported for ``retention_days``. A read
    older than, or as old as, a label's last one changes nothing of it.
    An empty read stores and removes nothing. Returns ``{"rules",
    "removed"}``."""
    rows = []
    for label, found in counters.items():
        name = str(label or "").strip()
        if not name or not isinstance(found, dict):
            continue
        values = [_count(found.get(counter)) for counter in _COUNTERS]
        packets, size = values[1], values[2]
        rows.append(
            (
                int(host_id),
                name,
                *values,
                packets or 0,
                size or 0,
                read_at,
                read_at,
                read_at if packets else "",
            )
        )
    if not rows:
        return {"rules": 0, "removed": 0}
    cutoff = _cutoff(read_at, retention_days)
    db = await _dbcore.get_db()
    try:
        await db.executemany(_UPSERT, rows)
        removed = 0
        if cutoff is not None:
            cursor = await db.execute(
                "DELETE FROM opnsense_rule_counters WHERE host_id = ? AND last_seen_at < ?",
                (int(host_id), cutoff),
            )
            removed = cursor.rowcount or 0
        await db.commit()
        return {"rules": len(rows), "removed": removed}
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_opnsense_rule_counters(host_id: int) -> dict[str, dict]:
    """``label -> {"first_seen_at", "last_seen_at", "last_hit_at",
    "total_packets", "total_bytes", "counters": {...}}`` of a host
    (``last_hit_at`` '' when the packet counter never grew)."""
    rows = await _select(
        "SELECT label, evaluations, packets, bytes, states, pf_rules, total_packets, total_bytes,"
        " first_seen_at, last_seen_at, last_hit_at FROM opnsense_rule_counters WHERE host_id = ?",
        (int(host_id),),
    )
    return {
        str(r["label"]): {
            "first_seen_at": str(r.get("first_seen_at") or ""),
            "last_seen_at": str(r.get("last_seen_at") or ""),
            "last_hit_at": str(r.get("last_hit_at") or ""),
            "total_packets": int(r.get("total_packets") or 0),
            "total_bytes": int(r.get("total_bytes") or 0),
            "counters": {c: int(r[c]) for c in _COUNTERS if r.get(c) is not None},
        }
        for r in rows
    }
