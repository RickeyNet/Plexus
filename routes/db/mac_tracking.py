"""Mac Tracking persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "upsert_mac_entry",
    "upsert_arp_entry",
    "enrich_mac_ip",
    "record_mac_history",
    "record_mac_sightings_batch",
    "upsert_arp_entries_batch",
    "get_mac_move_events",
    "get_mac_move_event_summary",
    "get_mac_move_event_history",
    "acknowledge_mac_move_event",
    "acknowledge_open_mac_move_events",
    "delete_old_mac_move_events",
    "delete_old_mac_history",
    "search_mac_tracking",
    "get_mac_collection_by_host",
    "get_mac_tracking_stats",
    "get_mac_history",
    "get_mac_table_for_host",
    "get_arp_table_for_host",
    "get_macs_on_port",
    "cleanup_stale_mac_entries",
]

# ═════════════════════════════════════════════════════════════════════════════
# MAC / ARP TRACKING  (MacTrack-style endpoint location)
# ═════════════════════════════════════════════════════════════════════════════


async def upsert_mac_entry(host_id: int, mac_address: str, vlan: int,
                            port_name: str = "", port_index: int = 0,
                            ip_address: str = "", entry_type: str = "dynamic") -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO mac_address_table
               (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, mac_address, vlan) DO UPDATE SET
                port_name = excluded.port_name,
                port_index = excluded.port_index,
                -- Preserve the previously enriched IP when this upsert carries
                -- none. The FDB passes always pass ip_address='' (the L2 switch
                -- doesn't know the IP); the ARP enrichment pass fills it in
                -- later. Without this guard every FDB poll would wipe the IP
                -- and the ARP pass would have to re-set it each cycle.
                ip_address = CASE
                    WHEN excluded.ip_address <> '' THEN excluded.ip_address
                    ELSE mac_address_table.ip_address
                END,
                entry_type = excluded.entry_type,
                last_seen = datetime('now')
               RETURNING id""",
            (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type),
        )
        row = await cursor.fetchone()
        await db.commit()
        return int(row[0])
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def upsert_arp_entry(host_id: int, ip_address: str, mac_address: str,
                            interface_name: str = "", vrf: str = "") -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO arp_table
               (host_id, ip_address, mac_address, interface_name, vrf)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(host_id, ip_address, vrf) DO UPDATE SET
                mac_address = excluded.mac_address,
                interface_name = excluded.interface_name,
                last_seen = datetime('now')
               RETURNING id""",
            (host_id, ip_address, mac_address, interface_name, vrf),
        )
        row = await cursor.fetchone()
        await db.commit()
        return int(row[0])
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def enrich_mac_ip(mac_address: str, ip_address: str) -> int:
    """Stamp an ARP-learned IP onto MAC-table rows that don't have one yet.

    ARP lives on the L3 device (router/SVI) while the MAC's forwarding entry
    lives on the access switch - different host_id - so enrichment matches by
    MAC across every host, not just the ARP holder. Only rows with no IP are
    touched, so a real IP is never silently overwritten. Uses idx_mac_table_mac
    instead of the old per-row ``search_mac_tracking`` LIKE scan.

    Returns the number of rows updated.
    """
    if not mac_address or not ip_address:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE mac_address_table
               SET ip_address = ?
               WHERE mac_address = ? AND (ip_address IS NULL OR ip_address = '')""",
            (ip_address, mac_address),
        )
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def record_mac_history(mac_address: str, host_id: int, port_name: str,
                              vlan: int = 0, ip_address: str = "",
                              is_uplink: bool = False) -> int | None:
    """Record a MAC sighting on a switch, but only when its location changed.

    Change detection is **per switch**: the comparison is against the last
    sighting of this MAC *on this same host_id*, not against the MAC's last
    sighting anywhere. A MAC is legitimately present on many switches at once
    (its access switch plus every uplink between here and there), so a
    different host is NOT a move - it's just another vantage point. Only a
    change of port, VLAN, or IP binding *on the same switch* is a real
    relocation (e.g. someone repatched the cable), and that's what opens a
    mac_move_event.

    ``is_uplink`` sightings (a MAC seen on a trunk/uplink port that carries
    many MACs) are skipped entirely: they aren't access-edge locations, and
    recording them would reintroduce the cross-switch flapping this function
    exists to avoid.

    Returns the new history row id, or None when there was no change (or the
    sighting was on an uplink).
    """
    if is_uplink:
        return None
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT port_name, vlan, ip_address
               FROM mac_tracking_history
               WHERE mac_address = ? AND host_id = ?
               ORDER BY seen_at DESC, id DESC LIMIT 1""",
            (mac_address, host_id),
        )
        prev = await cursor.fetchone()

        if prev is not None:
            p = prev if isinstance(prev, tuple) else (
                prev["port_name"], prev["vlan"], prev["ip_address"])
            prev_port, prev_vlan, prev_ip = p[0] or "", p[1] or 0, p[2] or ""

            changed = []
            if (prev_port or "") != (port_name or ""):
                changed.append("port")
            if (prev_vlan or 0) != (vlan or 0):
                changed.append("vlan")
            # Only treat an IP change as a move once a binding exists on both
            # sides - going from "" to a freshly-learned IP is enrichment of
            # the same location, not a move.
            if prev_ip and ip_address and prev_ip != ip_address:
                changed.append("ip")

            if not changed:
                return None

            await db.execute(
                """INSERT INTO mac_tracking_history
                   (mac_address, ip_address, host_id, port_name, vlan)
                   VALUES (?, ?, ?, ?, ?)""",
                (mac_address, ip_address, host_id, port_name, vlan),
            )
            cursor = await db.execute(
                """INSERT INTO mac_move_events
                   (mac_address, status, change_kind,
                    from_host_id, from_port, from_vlan, from_ip,
                    to_host_id, to_port, to_vlan, to_ip)
                   VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (mac_address, ",".join(changed),
                 host_id, prev_port, prev_vlan, prev_ip,
                 host_id, port_name, vlan, ip_address),
            )
            event_id = cursor.lastrowid
            await db.execute(
                """INSERT INTO mac_move_event_history
                   (event_id, mac_address, action, from_status, to_status,
                    actor, details)
                   VALUES (?, ?, 'detected', '', 'open', 'system', ?)""",
                (event_id, mac_address,
                 f"{'+'.join(changed)} changed on switch {host_id}: "
                 f"port {prev_port or '-'}->{port_name or '-'}, "
                 f"vlan {prev_vlan}->{vlan}"),
            )
            await db.commit()
            return event_id

        # First time we've seen this MAC on this switch - baseline sighting.
        cursor = await db.execute(
            """INSERT INTO mac_tracking_history
               (mac_address, ip_address, host_id, port_name, vlan)
               VALUES (?, ?, ?, ?, ?)""",
            (mac_address, ip_address, host_id, port_name, vlan),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def record_mac_sightings_batch(host_id: int, sightings: list[dict]) -> dict:
    """Persist one host's deduplicated FDB sightings in a single transaction.

    Each sighting: ``{mac, vlan, port_name, port_index, entry_type, is_uplink}``.
    Replaces the per-MAC ``upsert_mac_entry`` + ``record_mac_history`` loop -
    two awaited round-trips (each opening and closing a connection) per MAC
    became tens of thousands of connection cycles on a fleet collection. This
    runs the same upserts/inserts over one connection with one commit.

    Move semantics match ``record_mac_history`` exactly, including the
    sequential in-batch behavior: the "last known location" view is seeded
    from the DB once, then updated in memory as each sighting is processed,
    so two same-MAC sightings in one batch compare against each other just as
    they would have across two sequential calls. Uplink sightings get their
    FDB row upserted but are skipped for history/move purposes.

    Returns ``{"macs": upserted, "history": rows added, "moves": events opened}``.
    """
    if not sightings:
        return {"macs": 0, "history": 0, "moves": 0}
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO mac_address_table
               (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, mac_address, vlan) DO UPDATE SET
                port_name = excluded.port_name,
                port_index = excluded.port_index,
                ip_address = CASE
                    WHEN excluded.ip_address <> '' THEN excluded.ip_address
                    ELSE mac_address_table.ip_address
                END,
                entry_type = excluded.entry_type,
                last_seen = datetime('now')""",
            [(host_id, s["mac"], s["vlan"], s.get("port_name", ""),
              s.get("port_index", 0), "", s.get("entry_type", "dynamic"))
             for s in sightings],
        )

        # Latest known location per MAC on this switch, one query for the
        # whole batch (id is monotonic, so MAX(id) is the newest sighting).
        cursor = await db.execute(
            """SELECT h.mac_address, h.port_name, h.vlan, h.ip_address
               FROM mac_tracking_history h
               JOIN (SELECT mac_address, MAX(id) AS max_id
                     FROM mac_tracking_history
                     WHERE host_id = ?
                     GROUP BY mac_address) latest ON latest.max_id = h.id""",
            (host_id,),
        )
        rows = await cursor.fetchall()
        last: dict[str, tuple[str, int, str]] = {}
        for row in rows:
            r = row if isinstance(row, tuple) else (
                row["mac_address"], row["port_name"], row["vlan"], row["ip_address"])
            last[r[0]] = (r[1] or "", r[2] or 0, r[3] or "")

        history_rows: list[tuple] = []
        moves = 0
        for s in sightings:
            if s.get("is_uplink"):
                continue
            mac = s["mac"]
            port_name = s.get("port_name", "") or ""
            vlan = s.get("vlan", 0) or 0
            prev = last.get(mac)
            if prev is None:
                # First sighting on this switch - baseline, no move event.
                history_rows.append((mac, "", host_id, port_name, vlan))
                last[mac] = (port_name, vlan, "")
                continue
            prev_port, prev_vlan, prev_ip = prev
            changed = []
            if prev_port != port_name:
                changed.append("port")
            if prev_vlan != vlan:
                changed.append("vlan")
            # The FDB pass never carries an IP, so the IP-change clause of
            # record_mac_history can't fire here (it needs an IP on both sides).
            if not changed:
                continue
            history_rows.append((mac, "", host_id, port_name, vlan))
            cursor = await db.execute(
                """INSERT INTO mac_move_events
                   (mac_address, status, change_kind,
                    from_host_id, from_port, from_vlan, from_ip,
                    to_host_id, to_port, to_vlan, to_ip)
                   VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (mac, ",".join(changed),
                 host_id, prev_port, prev_vlan, prev_ip,
                 host_id, port_name, vlan, ""),
            )
            event_id = cursor.lastrowid
            await db.execute(
                """INSERT INTO mac_move_event_history
                   (event_id, mac_address, action, from_status, to_status,
                    actor, details)
                   VALUES (?, ?, 'detected', '', 'open', 'system', ?)""",
                (event_id, mac,
                 f"{'+'.join(changed)} changed on switch {host_id}: "
                 f"port {prev_port or '-'}->{port_name or '-'}, "
                 f"vlan {prev_vlan}->{vlan}"),
            )
            moves += 1
            last[mac] = (port_name, vlan, prev_ip)

        if history_rows:
            await db.executemany(
                """INSERT INTO mac_tracking_history
                   (mac_address, ip_address, host_id, port_name, vlan)
                   VALUES (?, ?, ?, ?, ?)""",
                history_rows,
            )
        await db.commit()
        return {"macs": len(sightings), "history": len(history_rows), "moves": moves}
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def upsert_arp_entries_batch(host_id: int, entries: list[dict]) -> int:
    """Persist one host's ARP table in a single transaction.

    Each entry: ``{ip_address, mac_address, interface_name}``. Mirrors the
    per-entry ``upsert_arp_entry`` + ``enrich_mac_ip`` loop (two awaited
    round-trips per ARP row) as two ``executemany`` passes over one
    connection with one commit. Enrichment keeps ``enrich_mac_ip``'s
    semantics: cross-host by MAC, and only rows with no IP are touched.

    Returns the number of ARP entries written.
    """
    if not entries:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            """INSERT INTO arp_table
               (host_id, ip_address, mac_address, interface_name, vrf)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(host_id, ip_address, vrf) DO UPDATE SET
                mac_address = excluded.mac_address,
                interface_name = excluded.interface_name,
                last_seen = datetime('now')""",
            [(host_id, e["ip_address"], e["mac_address"],
              e.get("interface_name", ""), e.get("vrf", ""))
             for e in entries],
        )
        enrich_rows = [(e["ip_address"], e["mac_address"])
                       for e in entries if e["ip_address"] and e["mac_address"]]
        if enrich_rows:
            await db.executemany(
                """UPDATE mac_address_table
                   SET ip_address = ?
                   WHERE mac_address = ? AND (ip_address IS NULL OR ip_address = '')""",
                enrich_rows,
            )
        await db.commit()
        return len(entries)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── MAC move events (drift-style) ───────────────────────────────────────────

async def get_mac_move_events(status: str = "", limit: int = 200,
                               host_id: int | None = None) -> list[dict]:
    """List MAC move events, newest first.

    Optionally filter by status, and by a switch "involved" in the move -
    host_id matches when the device is on either the from- or to-side, since
    a move is inherently a between-devices event.
    """
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("e.status = ?")
            params.append(status)
        if host_id is not None:
            clauses.append("(e.from_host_id = ? OR e.to_host_id = ?)")
            params.extend([host_id, host_id])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.*, fh.hostname AS from_hostname,
                       th.hostname AS to_hostname
                FROM mac_move_events e
                LEFT JOIN hosts fh ON fh.id = e.from_host_id
                LEFT JOIN hosts th ON th.id = e.to_host_id
                {where}
                ORDER BY e.detected_at DESC, e.id DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_move_event_summary() -> dict:
    """Counts by status for the summary cards."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT status, COUNT(*) AS n FROM mac_move_events GROUP BY status"
        )
        rows = rows_to_list(await cursor.fetchall())
        by_status = {r["status"]: r["n"] for r in rows}
        return {
            "open": by_status.get("open", 0),
            "acknowledged": by_status.get("acknowledged", 0),
            "total": sum(by_status.values()),
        }
    finally:
        await db.close()


async def get_mac_move_event_history(event_id: int, limit: int = 500) -> list[dict]:
    """Lifecycle timeline for a single move event, newest first."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM mac_move_event_history
               WHERE event_id = ?
               ORDER BY created_at DESC, id DESC LIMIT ?""",
            (event_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def acknowledge_mac_move_event(event_id: int, actor: str = "") -> bool:
    """Move an open event to acknowledged and append a history row."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT mac_address, status FROM mac_move_events WHERE id = ?",
            (event_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False
        r = row if isinstance(row, tuple) else (row["mac_address"], row["status"])
        mac_address, cur_status = r[0], r[1]
        if cur_status == "acknowledged":
            return True
        await db.execute(
            """UPDATE mac_move_events
               SET status = 'acknowledged',
                   acknowledged_at = datetime('now'),
                   acknowledged_by = ?
               WHERE id = ?""",
            (actor, event_id),
        )
        await db.execute(
            """INSERT INTO mac_move_event_history
               (event_id, mac_address, action, from_status, to_status,
                actor, details)
               VALUES (?, ?, 'acknowledged', ?, 'acknowledged', ?, '')""",
            (event_id, mac_address, cur_status, actor or "operator"),
        )
        await db.commit()
        return True
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def acknowledge_open_mac_move_events(actor: str = "") -> int:
    """Bulk-acknowledge every open event. Returns the number acknowledged."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, mac_address FROM mac_move_events WHERE status = 'open'"
        )
        open_rows = rows_to_list(await cursor.fetchall())
        for ev in open_rows:
            await db.execute(
                """UPDATE mac_move_events
                   SET status = 'acknowledged',
                       acknowledged_at = datetime('now'),
                       acknowledged_by = ?
                   WHERE id = ?""",
                (actor, ev["id"]),
            )
            await db.execute(
                """INSERT INTO mac_move_event_history
                   (event_id, mac_address, action, from_status, to_status,
                    actor, details)
                   VALUES (?, ?, 'acknowledged', 'open', 'acknowledged', ?, 'bulk')""",
                (ev["id"], ev["mac_address"], actor or "operator"),
            )
        await db.commit()
        return len(open_rows)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def delete_old_mac_move_events(retention_days: int) -> int:
    """Prune move events older than retention_days. Cascades to history."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM mac_move_events "
            "WHERE detected_at < datetime('now', ? || ' days')",
            (f"-{int(retention_days)}",),
        )
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0
    finally:
        await db.close()


async def delete_old_mac_history(retention_days: int) -> int:
    """Prune MAC movement-history rows older than retention_days.

    The history table is the per-switch sighting log behind move detection; it
    grows every time a MAC relocates, so it needs the same retention treatment
    as the move events themselves (which were the only thing pruned before).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM mac_tracking_history "
            "WHERE seen_at < datetime('now', ? || ' days')",
            (f"-{int(retention_days)}",),
        )
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0
    finally:
        await db.close()


async def search_mac_tracking(query: str, limit: int = 100) -> list[dict]:
    """Search MAC/ARP tables by MAC address, IP address, or port name.

    An empty/blank query returns the most recently seen entries so the UI can
    show what was just collected without requiring a search term.

    MAC queries are normalized: ``aabb.ccdd.eeff``, ``AA-BB-CC-DD-EE-FF`` and
    ``aabbccddeeff`` all match the canonical ``aa:bb:cc:dd:ee:ff`` storage
    form. Pure-hex fragments of 6+ characters also match — handy for paging
    through an OUI prefix or a tail like ``deadbeef``.
    """
    db = await _dbcore.get_db()
    try:
        raw = query.strip()
        if raw:
            ip_port_pattern = f"%{raw}%"
            normalized = (
                raw.lower()
                .replace(":", "")
                .replace("-", "")
                .replace(".", "")
                .replace(" ", "")
            )
            hex_only = normalized and all(c in "0123456789abcdef" for c in normalized)
            if hex_only and len(normalized) >= 6:
                mac_pattern = f"%{normalized}%"
                cursor = await db.execute(
                    """SELECT m.*, h.hostname, h.ip_address as host_ip
                       FROM mac_address_table m
                       LEFT JOIN hosts h ON h.id = m.host_id
                       WHERE REPLACE(LOWER(m.mac_address), ':', '') LIKE ?
                          OR m.ip_address LIKE ?
                          OR m.port_name LIKE ?
                       ORDER BY m.last_seen DESC LIMIT ?""",
                    (mac_pattern, ip_port_pattern, ip_port_pattern, limit),
                )
            else:
                cursor = await db.execute(
                    """SELECT m.*, h.hostname, h.ip_address as host_ip
                       FROM mac_address_table m
                       LEFT JOIN hosts h ON h.id = m.host_id
                       WHERE m.mac_address LIKE ? OR m.ip_address LIKE ? OR m.port_name LIKE ?
                       ORDER BY m.last_seen DESC LIMIT ?""",
                    (ip_port_pattern, ip_port_pattern, ip_port_pattern, limit),
                )
        else:
            cursor = await db.execute(
                """SELECT m.*, h.hostname, h.ip_address as host_ip
                   FROM mac_address_table m
                   LEFT JOIN hosts h ON h.id = m.host_id
                   ORDER BY m.last_seen DESC LIMIT ?""",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_collection_by_host() -> list[dict]:
    """Per-host MAC/ARP collection rollup, including silent hosts.

    Returns one row for every host (hostname, ip_address, group name) with
    counts joined in from ``mac_address_table`` and ``arp_table``. Hosts that
    never returned anything still appear with zero counts so the UI can call
    out which devices aren't contributing — this is the diagnostic for
    "Switches Reporting (23/27)".
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT h.id              AS host_id,
                      h.hostname        AS hostname,
                      h.ip_address      AS ip_address,
                      h.device_type     AS device_type,
                      h.group_id        AS group_id,
                      g.name            AS group_name,
                      COALESCE(m.mac_count, 0)        AS mac_count,
                      COALESCE(m.unique_macs, 0)      AS unique_macs,
                      m.last_mac_seen                 AS last_mac_seen,
                      COALESCE(a.arp_count, 0)        AS arp_count,
                      a.last_arp_seen                 AS last_arp_seen
               FROM hosts h
               LEFT JOIN inventory_groups g ON g.id = h.group_id
               LEFT JOIN (
                   SELECT host_id,
                          COUNT(*)                    AS mac_count,
                          COUNT(DISTINCT mac_address) AS unique_macs,
                          MAX(last_seen)              AS last_mac_seen
                   FROM mac_address_table
                   GROUP BY host_id
               ) m ON m.host_id = h.id
               LEFT JOIN (
                   SELECT host_id,
                          COUNT(*)       AS arp_count,
                          MAX(last_seen) AS last_arp_seen
                   FROM arp_table
                   GROUP BY host_id
               ) a ON a.host_id = h.id
               ORDER BY mac_count ASC, h.hostname ASC"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_tracking_stats() -> dict:
    """Summary counts for the MAC tracking header.

    Returns total rows (one per host/MAC/VLAN), unique MAC addresses across
    all switches, the number of switches that contributed any entry, and the
    most recent ``last_seen`` timestamp (interpreted by the UI as the freshest
    collection time).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT COUNT(*)                          AS total_entries,
                      COUNT(DISTINCT mac_address)       AS unique_macs,
                      COUNT(DISTINCT host_id)           AS switches_reporting,
                      MAX(last_seen)                    AS last_collected_at
               FROM mac_address_table"""
        )
        row = await cursor.fetchone()
        if not row:
            return {
                "total_entries": 0,
                "unique_macs": 0,
                "switches_reporting": 0,
                "last_collected_at": None,
            }
        as_dict = dict(row)
        return {
            "total_entries": int(as_dict.get("total_entries") or 0),
            "unique_macs": int(as_dict.get("unique_macs") or 0),
            "switches_reporting": int(as_dict.get("switches_reporting") or 0),
            "last_collected_at": as_dict.get("last_collected_at"),
        }
    finally:
        await db.close()


async def get_mac_history(mac_address: str, limit: int = 100) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT mh.*, h.hostname, h.ip_address as host_ip
               FROM mac_tracking_history mh
               LEFT JOIN hosts h ON h.id = mh.host_id
               WHERE mh.mac_address = ?
               ORDER BY mh.seen_at DESC LIMIT ?""",
            (mac_address, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_mac_table_for_host(host_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM mac_address_table WHERE host_id = ? ORDER BY vlan, port_name",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_arp_table_for_host(host_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM arp_table WHERE host_id = ? ORDER BY ip_address",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_macs_on_port(host_id: int, port_name: str) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM mac_address_table WHERE host_id = ? AND port_name = ? ORDER BY mac_address",
            (host_id, port_name),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def cleanup_stale_mac_entries(days: int = 30) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM mac_address_table WHERE last_seen < datetime('now', ? || ' days')",
            (f"-{int(days)}",),
        )
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0
    finally:
        await db.close()


