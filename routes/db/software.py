"""Software version tracking persistence helpers.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0067): ``software_versions`` (the current version of
every tracked device), ``software_version_history`` (every version a
device was seen on and when), ``software_advisories`` (what to check
versions against), ``software_alerts`` (which device matches which
advisory) and ``software_settings`` (key/value).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import row_to_dict, rows_to_list

__all__ = [
    "list_hosts_for_software",
    "replace_software_versions",
    "list_software_versions",
    "list_recent_version_changes",
    "get_software_history",
    "list_software_advisories",
    "get_software_advisory",
    "upsert_software_advisory",
    "delete_software_advisory",
    "sync_software_alerts",
    "list_software_alerts",
    "acknowledge_software_alert",
    "count_open_alerts_by_device",
    "software_alert_summary",
    "get_software_settings",
    "set_software_settings",
]

_DEVICE_FIELDS = (
    "source",
    "org_ref",
    "host_id",
    "name",
    "model",
    "serial",
    "site",
    "org_name",
    "platform",
    "version",
    "raw_version",
)
_ADVISORY_LISTS = ("affected_versions", "fixed_versions", "cves")
_ADVISORY_FIELDS = (
    "source",
    "title",
    "severity",
    "cvss",
    "platform",
    "product_match",
    "affected_versions_json",
    "fixed_versions_json",
    "cves_json",
    "url",
    "published",
    "summary",
    "enabled",
)
_SEVERITY_CASE = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _device_values(entry: dict) -> tuple:
    return tuple(
        (int(entry.get(field) or 0) if field == "org_ref" else entry.get(field))
        if field in ("org_ref", "host_id")
        else str(entry.get(field) or "")
        for field in _DEVICE_FIELDS
    )


# ── Versions ─────────────────────────────────────────────────────────────────


async def list_hosts_for_software() -> list[dict]:
    """Every inventory host with the fields the tracker classifies on."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT h.id, h.hostname, h.ip_address, h.device_type, h.model, h.software_version,
                      h.serial_number, g.name AS group_name
               FROM hosts h
               LEFT JOIN inventory_groups g ON g.id = h.group_id
               ORDER BY h.hostname, h.id"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def replace_software_versions(entries: list[dict]) -> dict:
    """Make ``entries`` the complete set of tracked devices, in one
    transaction.

    A device seen again keeps its ``first_seen``; one whose version differs
    from last time records the previous version and the moment of change
    and gets a new history row (the old one is closed); a device that is
    no longer reported is removed and its history closed. Returns the
    counts and the list of version changes.
    """
    now = _now()
    wanted: dict[str, dict] = {}
    for entry in entries:
        key = str(entry.get("device_key") or "")
        if key:
            wanted[key] = entry
    added = changed = removed = 0
    changes: list[dict] = []
    columns = ", ".join(_DEVICE_FIELDS)
    marks = ", ".join("?" for _ in _DEVICE_FIELDS)
    assignments = ", ".join(f"{field} = ?" for field in _DEVICE_FIELDS)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT device_key, version, name, platform FROM software_versions")
        existing = {row["device_key"]: row for row in rows_to_list(await cursor.fetchall())}
        for key, entry in wanted.items():
            values = _device_values(entry)
            old = existing.get(key)
            if old is None:
                await db.execute(
                    f"INSERT INTO software_versions (device_key, {columns}, first_seen, last_seen) VALUES (?, {marks}, ?, ?)",
                    (key, *values, now, now),
                )
                await _open_history(db, key, entry, now)
                added += 1
            elif old["version"] != str(entry.get("version") or ""):
                await db.execute(
                    f"UPDATE software_versions SET {assignments}, previous_version = ?, changed_at = ?, last_seen = ? "
                    "WHERE device_key = ?",
                    (*values, old["version"], now, now, key),
                )
                await db.execute(
                    "UPDATE software_version_history SET seen_until = ? WHERE device_key = ? AND seen_until = ''",
                    (now, key),
                )
                await _open_history(db, key, entry, now)
                changed += 1
                changes.append(
                    {
                        "device_key": key,
                        "name": str(entry.get("name") or ""),
                        "platform": str(entry.get("platform") or ""),
                        "from_version": old["version"],
                        "to_version": str(entry.get("version") or ""),
                    }
                )
            else:
                await db.execute(
                    f"UPDATE software_versions SET {assignments}, last_seen = ? WHERE device_key = ?",
                    (*values, now, key),
                )
        for key in set(existing) - set(wanted):
            await db.execute("DELETE FROM software_versions WHERE device_key = ?", (key,))
            await db.execute(
                "UPDATE software_version_history SET seen_until = ? WHERE device_key = ? AND seen_until = ''",
                (now, key),
            )
            removed += 1
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return {
        "devices": len(wanted),
        "added": added,
        "changed": changed,
        "removed": removed,
        "changes": changes,
        "refreshed_at": now,
    }


async def _open_history(db, key: str, entry: dict, now: str) -> None:
    await db.execute(
        "INSERT INTO software_version_history (device_key, name, platform, version, seen_from, seen_until) "
        "VALUES (?, ?, ?, ?, ?, '')",
        (key, str(entry.get("name") or ""), str(entry.get("platform") or ""), str(entry.get("version") or ""), now),
    )


async def list_software_versions(platform: str = "", source: str = "", search: str = "") -> list[dict]:
    """Every tracked device, by name. ``search`` matches name, model,
    serial, site, organization or version."""
    clauses: list[str] = []
    params: list = []
    if platform:
        clauses.append("platform = ?")
        params.append(platform)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if search.strip():
        pattern = f"%{search.strip().lower()}%"
        clauses.append(
            "(LOWER(name) LIKE ? OR LOWER(model) LIKE ? OR LOWER(serial) LIKE ? OR LOWER(site) LIKE ? "
            "OR LOWER(org_name) LIKE ? OR LOWER(version) LIKE ?)"
        )
        params.extend([pattern] * 6)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT * FROM software_versions {where} ORDER BY LOWER(name), device_key", tuple(params)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def list_recent_version_changes(limit: int = 50) -> list[dict]:
    """Devices whose version changed, most recent change first."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT device_key, name, platform, model, site, source, previous_version, version, changed_at "
            "FROM software_versions WHERE changed_at <> '' ORDER BY changed_at DESC, name LIMIT ?",
            (max(1, int(limit)),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_software_history(device_key: str, limit: int = 100) -> list[dict]:
    """The versions one device was seen on, newest first."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT version, platform, seen_from, seen_until FROM software_version_history "
            "WHERE device_key = ? ORDER BY seen_from DESC, id DESC LIMIT ?",
            (device_key, max(1, int(limit))),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Advisories ───────────────────────────────────────────────────────────────


def _parse_list(raw) -> list[str]:
    try:
        items = json.loads(raw or "[]")
    except TypeError, ValueError:
        return []
    return [str(item) for item in items if str(item).strip()] if isinstance(items, list) else []


def _advisory_row(row) -> dict | None:
    advisory = row_to_dict(row)
    if advisory is None:
        return None
    for name in _ADVISORY_LISTS:
        advisory[name] = _parse_list(advisory.pop(f"{name}_json", "[]"))
    advisory["enabled"] = bool(advisory.get("enabled"))
    return advisory


def _advisory_values(advisory: dict) -> tuple:
    values = []
    for field in _ADVISORY_FIELDS:
        if field.endswith("_json"):
            values.append(json.dumps(list(advisory.get(field[:-5]) or [])))
        elif field == "cvss":
            values.append(advisory.get("cvss"))
        elif field == "enabled":
            values.append(1 if advisory.get("enabled", True) else 0)
        else:
            values.append(str(advisory.get(field) or ""))
    return tuple(values)


async def list_software_advisories(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT * FROM software_advisories {'WHERE enabled = 1' if enabled_only else ''} "
            f"ORDER BY {_SEVERITY_CASE}, published DESC, advisory_id"
        )
        return [a for a in (_advisory_row(row) for row in await cursor.fetchall()) if a]
    finally:
        await db.close()


async def get_software_advisory(advisory_id: str) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM software_advisories WHERE advisory_id = ?", (advisory_id,))
        return _advisory_row(await cursor.fetchone())
    finally:
        await db.close()


async def upsert_software_advisory(advisory: dict, *, merge_lists: bool = False) -> dict | None:
    """Create or replace an advisory by ``advisory_id``.

    With ``merge_lists`` the affected versions, fixed versions and CVEs
    already stored are kept and the new ones added, which is how a PSIRT
    sync accumulates the versions Cisco answered for one advisory.
    """
    advisory = dict(advisory)
    advisory_id = str(advisory.get("advisory_id") or "").strip()
    if not advisory_id:
        return None
    advisory["advisory_id"] = advisory_id
    now = _now()
    if merge_lists:
        existing = await get_software_advisory(advisory_id)
        if existing:
            for name in _ADVISORY_LISTS:
                merged = list(existing.get(name) or [])
                merged.extend(item for item in advisory.get(name) or [] if item not in merged)
                advisory[name] = merged
            advisory.setdefault("enabled", existing.get("enabled", True))
    columns = ", ".join(_ADVISORY_FIELDS)
    marks = ", ".join("?" for _ in _ADVISORY_FIELDS)
    updates = ", ".join(f"{field} = excluded.{field}" for field in _ADVISORY_FIELDS)
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"""INSERT INTO software_advisories (advisory_id, {columns}, created_at, updated_at)
                VALUES (?, {marks}, ?, ?)
                ON CONFLICT(advisory_id) DO UPDATE SET {updates}, updated_at = excluded.updated_at""",
            (advisory_id, *_advisory_values(advisory), now, now),
        )
        await db.commit()
    finally:
        await db.close()
    return await get_software_advisory(advisory_id)


async def delete_software_advisory(advisory_id: str) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM software_advisories WHERE advisory_id = ?", (advisory_id,))
        await db.execute("DELETE FROM software_alerts WHERE advisory_id = ?", (advisory_id,))
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


# ── Alerts ───────────────────────────────────────────────────────────────────


async def sync_software_alerts(matches: list[dict]) -> dict:
    """Make ``matches`` (``device_key``, ``advisory_id``, ``severity``) the
    set of open alerts: a new match opens an alert, a match that was
    resolved earlier reopens it (unacknowledged again), and an open alert
    that no longer matches is resolved. Returns what changed."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, device_key, advisory_id, severity, resolved_at, acknowledged_at FROM software_alerts"
        )
        existing = {(row["device_key"], row["advisory_id"]): row for row in rows_to_list(await cursor.fetchall())}
        new: list[dict] = []
        reopened: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for match in matches:
            key = (str(match["device_key"]), str(match["advisory_id"]))
            if key in seen:
                continue
            seen.add(key)
            severity = str(match.get("severity") or "medium")
            row = existing.get(key)
            if row is None:
                cursor = await db.execute(
                    "INSERT INTO software_alerts (device_key, advisory_id, severity, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (*key, severity, now, now),
                )
                new.append({"id": cursor.lastrowid, "device_key": key[0], "advisory_id": key[1], "severity": severity})
            elif row["resolved_at"]:
                await db.execute(
                    "UPDATE software_alerts SET resolved_at = '', acknowledged_at = '', acknowledged_by = '', "
                    "severity = ?, last_seen = ? WHERE id = ?",
                    (severity, now, row["id"]),
                )
                reopened.append({"id": row["id"], "device_key": key[0], "advisory_id": key[1], "severity": severity})
            else:
                await db.execute(
                    "UPDATE software_alerts SET severity = ?, last_seen = ? WHERE id = ?", (severity, now, row["id"])
                )
        resolved = 0
        for key, row in existing.items():
            if key not in seen and not row["resolved_at"]:
                await db.execute("UPDATE software_alerts SET resolved_at = ? WHERE id = ?", (now, row["id"]))
                resolved += 1
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return {"new": new, "reopened": reopened, "resolved": resolved, "open": len(seen)}


async def list_software_alerts(include_resolved: bool = False, limit: int = 500) -> list[dict]:
    """Alerts with their advisory and device, most severe and newest first."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT a.id, a.device_key, a.advisory_id, a.severity, a.first_seen, a.last_seen,
                       a.acknowledged_at, a.acknowledged_by, a.resolved_at,
                       adv.title, adv.url, adv.cvss, adv.source AS advisory_source,
                       adv.fixed_versions_json, adv.cves_json,
                       v.name AS device_name, v.model, v.version, v.platform, v.site, v.org_name,
                       v.source AS device_source, v.host_id
                FROM software_alerts a
                LEFT JOIN software_advisories adv ON adv.advisory_id = a.advisory_id
                LEFT JOIN software_versions v ON v.device_key = a.device_key
                {"" if include_resolved else "WHERE a.resolved_at = ''"}
                ORDER BY {_SEVERITY_CASE.replace("severity", "a.severity")}, a.first_seen DESC, a.id DESC
                LIMIT ?""",
            (max(1, int(limit)),),
        )
        alerts = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    for alert in alerts:
        alert["fixed_versions"] = _parse_list(alert.pop("fixed_versions_json", "[]"))
        alert["cves"] = _parse_list(alert.pop("cves_json", "[]"))
        alert["title"] = alert.get("title") or alert["advisory_id"]
        alert["acknowledged"] = bool(alert.get("acknowledged_at"))
        alert["resolved"] = bool(alert.get("resolved_at"))
    return alerts


async def acknowledge_software_alert(alert_id: int, user: str) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE software_alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND resolved_at = ''",
            (_now(), str(user or ""), int(alert_id)),
        )
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


async def count_open_alerts_by_device() -> dict[str, dict]:
    """``device_key`` -> open alert count and worst severity."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT device_key, severity, acknowledged_at FROM software_alerts WHERE resolved_at = '' "
            f"ORDER BY {_SEVERITY_CASE}"
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    counts: dict[str, dict] = {}
    for row in rows:
        entry = counts.setdefault(row["device_key"], {"count": 0, "worst": row["severity"], "unacknowledged": 0})
        entry["count"] += 1
        if not row["acknowledged_at"]:
            entry["unacknowledged"] += 1
    return counts


async def software_alert_summary() -> dict:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT severity, COUNT(*) AS n, SUM(CASE WHEN acknowledged_at = '' THEN 1 ELSE 0 END) AS unacked "
            "FROM software_alerts WHERE resolved_at = '' GROUP BY severity"
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    by_severity = {row["severity"]: int(row["n"] or 0) for row in rows}
    return {
        "open": sum(by_severity.values()),
        "unacknowledged": sum(int(row["unacked"] or 0) for row in rows),
        "by_severity": by_severity,
    }


# ── Settings ─────────────────────────────────────────────────────────────────


async def get_software_settings() -> dict[str, str]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT key, value FROM software_settings")
        return {row["key"]: row["value"] for row in rows_to_list(await cursor.fetchall())}
    finally:
        await db.close()


async def set_software_settings(values: dict[str, str]) -> None:
    if not values:
        return
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            "INSERT INTO software_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(str(key), str(value if value is not None else "")) for key, value in values.items()],
        )
        await db.commit()
    finally:
        await db.close()
