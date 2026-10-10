"""Meraki topology persistence helpers.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "create_meraki_org",
    "get_meraki_org",
    "get_meraki_org_by_name",
    "list_meraki_orgs",
    "update_meraki_org",
    "delete_meraki_org",
    "get_meraki_org_api_key",
    "create_meraki_snapshot",
    "list_meraki_snapshots",
    "get_latest_meraki_snapshot_ids",
    "get_meraki_snapshot",
    "delete_meraki_snapshot",
    "prune_meraki_snapshots",
    "upsert_meraki_clients",
    "search_meraki_clients",
    "get_meraki_client_stats",
    "cleanup_stale_meraki_clients",
]

# Columns safe to hand to callers: everything except the encrypted API key.
_ORG_COLUMNS = (
    "id, name, provider, org_id, base_url, options_json, last_build_at, last_build_status, "
    "last_build_message, created_by, created_at, updated_at, "
    "(api_key_enc <> '') AS has_api_key"
)
_SNAPSHOT_META_COLUMNS = "id, org_ref, summary_json, warning_count, duration_seconds, built_by, created_at"


def _encrypt_key(api_key: str) -> str:
    if not api_key:
        return ""
    from routes.crypto import encrypt

    return encrypt(api_key)


def _stamp_param(value: str) -> str | datetime:
    """Bind an ISO-8601 stamp: a TIMESTAMPTZ column wants a datetime
    (naive means UTC)."""
    stamp = datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def _iso_stamps(row: dict, *columns: str) -> None:
    """Postgres returns TIMESTAMPTZ columns as datetimes; hand out ISO strings."""
    for column in columns:
        if isinstance(row.get(column), datetime):
            row[column] = row[column].isoformat()


def _org_row(row) -> dict | None:
    org = row_to_dict(row)
    if org is None:
        return None
    _iso_stamps(org, "last_build_at", "created_at", "updated_at")
    org["has_api_key"] = bool(org.get("has_api_key"))
    try:
        org["options"] = json.loads(org.pop("options_json", None) or "{}")
    except TypeError, ValueError:
        org["options"] = {}
    return org


def _snapshot_meta(row: dict) -> dict:
    _iso_stamps(row, "created_at")
    try:
        row["summary"] = json.loads(row.pop("summary_json", None) or "{}")
    except TypeError, ValueError:
        row["summary"] = {}
    return row


async def create_meraki_org(
    name: str,
    *,
    provider: str = "meraki",
    org_id: str = "",
    base_url: str = "",
    api_key: str = "",
    options: dict | None = None,
    created_by: str = "",
) -> dict | None:
    """Insert a Meraki organization (``provider`` "meraki"), a Cato account
    ("cato"), a Cisco FMC ("fmc"), a Palo Alto Panorama ("panorama") or an
    Appgate SDP collective ("appgate").
    Returns ``None`` when the name is taken."""
    db = await _dbcore.get_db()
    try:
        try:
            cursor = await db.execute(
                """INSERT INTO meraki_orgs
                   (name, provider, org_id, base_url, api_key_enc, options_json, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (name, provider, org_id, base_url, _encrypt_key(api_key), json.dumps(options or {}), created_by),
            )
        except Exception as exc:
            if _is_unique_violation(exc):
                return None
            raise
        await db.commit()
        new_id = cursor.lastrowid
    finally:
        await db.close()
    return await get_meraki_org(new_id)


async def get_meraki_org(org_ref: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT {_ORG_COLUMNS} FROM meraki_orgs WHERE id = ?", (org_ref,))
        return _org_row(await cursor.fetchone())
    finally:
        await db.close()


async def get_meraki_org_by_name(name: str) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT {_ORG_COLUMNS} FROM meraki_orgs WHERE name = ?", (name,))
        return _org_row(await cursor.fetchone())
    finally:
        await db.close()


async def list_meraki_orgs() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT {_ORG_COLUMNS},
                       (SELECT COUNT(*) FROM meraki_topology_snapshots s WHERE s.org_ref = meraki_orgs.id) AS snapshot_count
                FROM meraki_orgs ORDER BY name"""
        )
        return [org for org in (_org_row(r) for r in await cursor.fetchall()) if org]
    finally:
        await db.close()


async def update_meraki_org(org_ref: int, **kwargs) -> dict | None:
    """Update the given fields. ``api_key`` is encrypted; ``options`` is
    JSON-encoded. A ``None`` value means "leave unchanged"."""
    column_for = {
        "name": "name",
        "org_id": "org_id",
        "base_url": "base_url",
        "api_key": "api_key_enc",
        "options": "options_json",
        "last_build_at": "last_build_at",
        "last_build_status": "last_build_status",
        "last_build_message": "last_build_message",
    }
    sets: list[str] = []
    vals: list = []
    for key, value in kwargs.items():
        if key not in column_for or value is None:
            continue
        if key == "api_key":
            value = _encrypt_key(value)
        elif key == "options":
            value = json.dumps(value)
        elif key == "last_build_at":
            value = _stamp_param(value)
        sets.append(f"{column_for[key]} = ?")
        vals.append(value)
    if not sets:
        return await get_meraki_org(org_ref)
    sets.append("updated_at = NOW()")
    db = await _dbcore.get_db()
    try:
        sql, params = _safe_dynamic_update("meraki_orgs", sets, vals, "id = ?", org_ref)
        try:
            await db.execute(sql, params)
        except Exception as exc:
            if _is_unique_violation(exc):
                return None
            raise
        await db.commit()
    finally:
        await db.close()
    return await get_meraki_org(org_ref)


async def delete_meraki_org(org_ref: int) -> bool:
    db = await _dbcore.get_db()
    try:
        # Explicit child delete: SQLite only cascades with foreign_keys=ON.
        await db.execute("DELETE FROM meraki_topology_snapshots WHERE org_ref = ?", (org_ref,))
        await db.execute("DELETE FROM meraki_clients WHERE org_ref = ?", (org_ref,))
        cursor = await db.execute("DELETE FROM meraki_orgs WHERE id = ?", (org_ref,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_meraki_org_api_key(org_ref: int) -> str:
    """Decrypted Dashboard API key for collectors. Never returned by the API."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT api_key_enc FROM meraki_orgs WHERE id = ?", (org_ref,))
        row = await cursor.fetchone()
    finally:
        await db.close()
    stored = str(row[0] or "") if row else ""
    if not stored:
        return ""
    from routes.crypto import decrypt

    try:
        return decrypt(stored) or ""
    except Exception:
        _LOGGER.warning("meraki: could not decrypt stored API key for org %s", org_ref)
        return ""


async def create_meraki_snapshot(
    org_ref: int,
    snapshot: dict,
    *,
    built_by: str = "",
    duration_seconds: float = 0.0,
) -> int:
    summary = snapshot.get("summary") or {}
    warnings = len((snapshot.get("collection") or {}).get("errors") or [])
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO meraki_topology_snapshots
               (org_ref, summary_json, snapshot_json, warning_count, duration_seconds, built_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                org_ref,
                json.dumps(summary, separators=(",", ":")),
                json.dumps(snapshot, separators=(",", ":")),
                warnings,
                float(duration_seconds),
                built_by,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_meraki_snapshots(org_ref: int | None = None, limit: int = 100) -> list[dict]:
    """Snapshot metadata, newest first. Never loads the snapshot body."""
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE s.org_ref = ?" if org_ref is not None else ""
        params: tuple = (org_ref, limit) if org_ref is not None else (limit,)
        cursor = await db.execute(
            f"""SELECT {", ".join("s." + c.strip() for c in _SNAPSHOT_META_COLUMNS.split(","))}, o.name AS org_name
                FROM meraki_topology_snapshots s
                JOIN meraki_orgs o ON o.id = s.org_ref
                {where}
                ORDER BY s.id DESC LIMIT ?""",
            params,
        )
        return [_snapshot_meta(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def get_latest_meraki_snapshot_ids() -> list[tuple[int, int]]:
    """``(org_ref, snapshot_id)`` of the newest snapshot of every organization."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT org_ref, MAX(id) FROM meraki_topology_snapshots GROUP BY org_ref ORDER BY org_ref"
        )
        return [(int(row[0]), int(row[1])) for row in await cursor.fetchall()]
    finally:
        await db.close()


async def get_meraki_snapshot(snapshot_id: int, *, include_body: bool = True) -> dict | None:
    columns = _SNAPSHOT_META_COLUMNS + (", snapshot_json" if include_body else "")
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT {columns} FROM meraki_topology_snapshots WHERE id = ?", (snapshot_id,))
        row = row_to_dict(await cursor.fetchone())
    finally:
        await db.close()
    if row is None:
        return None
    row = _snapshot_meta(row)
    if include_body:
        try:
            row["snapshot"] = json.loads(row.pop("snapshot_json", None) or "{}")
        except TypeError, ValueError:
            row["snapshot"] = {}
    return row


async def delete_meraki_snapshot(snapshot_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM meraki_topology_snapshots WHERE id = ?", (snapshot_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def prune_meraki_snapshots(org_ref: int, keep: int) -> int:
    """Delete all but the newest ``keep`` snapshots of an organization."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id FROM meraki_topology_snapshots WHERE org_ref = ? ORDER BY id DESC",
            (org_ref,),
        )
        stale = [row[0] for row in await cursor.fetchall()][max(1, int(keep)) :]
        for snapshot_id in stale:
            await db.execute("DELETE FROM meraki_topology_snapshots WHERE id = ?", (snapshot_id,))
        if stale:
            await db.commit()
        return len(stale)
    finally:
        await db.close()


# ── Clients (MAC tracking) ───────────────────────────────────────────────────

_CLIENT_FIELDS = (
    "network_id",
    "network_name",
    "mac_address",
    "ip_address",
    "vlan",
    "device_serial",
    "device_name",
    "port_name",
    "description",
    "manufacturer",
    "ssid",
    "status",
    "first_seen",
    "last_seen",
)


async def upsert_meraki_clients(org_ref: int, clients: list[dict]) -> int:
    """Record the clients of one collection in a single transaction.

    One row per (organization, network, MAC): a client seen again has its
    location and ``last_seen`` refreshed while ``first_seen`` is kept, and a
    client missing from this collection is left as it was.
    """
    if not clients:
        return 0
    columns = ", ".join(_CLIENT_FIELDS)
    marks = ", ".join("?" for _ in _CLIENT_FIELDS)
    refreshed = ("network_name", "vlan", "device_serial", "device_name", "port_name", "manufacturer", "ssid", "status")
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            f"""INSERT INTO meraki_clients (org_ref, {columns})
                VALUES (?, {marks})
                ON CONFLICT(org_ref, network_id, mac_address) DO UPDATE SET
                 {", ".join(f"{c} = excluded.{c}" for c in refreshed)},
                 ip_address = CASE
                     WHEN excluded.ip_address <> '' THEN excluded.ip_address
                     ELSE meraki_clients.ip_address
                 END,
                 description = CASE
                     WHEN excluded.description <> '' THEN excluded.description
                     ELSE meraki_clients.description
                 END,
                 last_seen = CASE
                     WHEN excluded.last_seen > meraki_clients.last_seen THEN excluded.last_seen
                     ELSE meraki_clients.last_seen
                 END""",
            [(org_ref, *(client[f] for f in _CLIENT_FIELDS)) for client in clients],
        )
        await db.commit()
        return len(clients)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def search_meraki_clients(query: str, limit: int = 100) -> list[dict]:
    """Clients matching a MAC (any format), IP, port, client name or device
    name. A blank query returns the most recently seen clients."""
    raw = query.strip()
    where = ""
    params: list = []
    if raw:
        pattern = f"%{raw.lower()}%"
        normalized = raw.lower().replace(":", "").replace("-", "").replace(".", "").replace(" ", "")
        hex_only = bool(normalized) and all(c in "0123456789abcdef" for c in normalized)
        if hex_only and len(normalized) >= 6:
            mac_clause, mac_pattern = "REPLACE(c.mac_address, ':', '') LIKE ?", f"%{normalized}%"
        else:
            mac_clause, mac_pattern = "c.mac_address LIKE ?", pattern
        where = f"""WHERE {mac_clause}
                       OR c.ip_address LIKE ?
                       OR LOWER(c.port_name) LIKE ?
                       OR LOWER(c.description) LIKE ?
                       OR LOWER(c.device_name) LIKE ?"""
        params = [mac_pattern, pattern, pattern, pattern, pattern]
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT c.*, o.name AS org_name
                FROM meraki_clients c
                JOIN meraki_orgs o ON o.id = c.org_ref
                {where}
                ORDER BY c.last_seen DESC, c.id DESC LIMIT ?""",
            (*params, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_meraki_client_stats() -> dict:
    """Counts for the MAC tracking header. ``unique_macs`` spans both the
    Meraki clients and the inventory hosts' forwarding tables."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT COUNT(*), COUNT(DISTINCT device_serial), MAX(last_seen) FROM meraki_clients")
        row = await cursor.fetchone()
        entries = int(row[0] or 0) if row else 0
        stats = {
            "entries": entries,
            "devices": int(row[1] or 0) if row else 0,
            "last_seen": row[2] if row else None,
            "unique_macs": 0,
        }
        if entries:
            cursor = await db.execute(
                """SELECT COUNT(*) FROM (
                       SELECT mac_address FROM mac_address_table
                       UNION
                       SELECT mac_address FROM meraki_clients
                   ) AS tracked"""
            )
            row = await cursor.fetchone()
            stats["unique_macs"] = int(row[0] or 0) if row else 0
        return stats
    finally:
        await db.close()


async def cleanup_stale_meraki_clients(days: int = 30) -> int:
    """Remove clients not seen in the given number of days."""
    cutoff = (datetime.now(UTC) - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM meraki_clients WHERE last_seen < ?", (cutoff,))
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0
    finally:
        await db.close()
