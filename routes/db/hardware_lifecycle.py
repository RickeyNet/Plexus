"""Hardware lifecycle: end-of-life notices, support contracts and the devices
they cover, the settings and the alert state of the lifecycle check.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0103. Notice and contract mutations are tracked
(``tracks_changes``, object types ``hardware_notice`` and
``support_contract``) so the change log and webhooks see them; the stamps
take the acting user of the request. The row plumbing (insert with stamps,
update, delete, select) is shared with ``routes.db.circuits``. The callers
(``netcontrol.routes.hardware_lifecycle``) validate the values first; a
duplicate device type, part number or contract id raises ``ValueError``.

Which notices apply to a device (``hardware_notice_matches``): a notice of
its device type, a part-number notice whose part number is its device
type's part number or model, or the part number of one of its modules,
ignoring case.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal
from typing import Any

import routes.database as _dbcore
from routes.db.change_events import tracks_changes
from routes.db.circuits import _delete, _insert, _select, _update
from routes.db.custom_fields import _marks, _now
from routes.db.device_model import _must

__all__ = [
    "HARDWARE_NOTICE_FIELDS",
    "SUPPORT_CONTRACT_FIELDS",
    "add_lifecycle_alert_state",
    "create_hardware_notice",
    "create_support_contract",
    "delete_hardware_notice",
    "delete_lifecycle_alert_states",
    "delete_support_contract",
    "get_hardware_notice",
    "get_lifecycle_settings",
    "get_support_contract",
    "hardware_notice_hosts",
    "hardware_notice_matches",
    "lifecycle_hosts",
    "list_hardware_notices",
    "list_lifecycle_alert_states",
    "list_support_contracts",
    "missing_host_ids",
    "set_lifecycle_settings",
    "support_contracts_by_host",
    "touch_lifecycle_alert_states",
    "update_hardware_notice",
    "update_support_contract",
]

HARDWARE_NOTICE_FIELDS: tuple[str, ...] = (
    "device_type_id",
    "part_number",
    "end_of_sale",
    "end_of_sw_maintenance",
    "end_of_security_fixes",
    "end_of_support",
    "documentation_url",
    "comments",
)
SUPPORT_CONTRACT_FIELDS: tuple[str, ...] = (
    "provider",
    "contract_id",
    "start_date",
    "end_date",
    "cost",
    "currency",
    "support_level",
    "description",
    "comments",
)

# (notice id, host id, how it applies) for every notice and device it
# applies to; a pair may appear once per way.
_MATCHES = """
    SELECT n.id AS notice_id, h.id AS host_id, 'device_type' AS via
    FROM hardware_notices n JOIN hosts h ON h.device_type_id = n.device_type_id
    UNION ALL
    SELECT n.id, h.id, 'part_number'
    FROM hardware_notices n
    JOIN device_types dt ON n.part_number <> ''
         AND (lower(dt.part_number) = lower(n.part_number) OR lower(dt.model) = lower(n.part_number))
    JOIN hosts h ON h.device_type_id = dt.id
    UNION ALL
    SELECT n.id, m.host_id, 'module'
    FROM hardware_notices n JOIN modules m ON n.part_number <> '' AND lower(m.part_number) = lower(n.part_number)
"""


# ── Notices ──────────────────────────────────────────────────────────────────

_NOTICE_SELECT = f"""
    SELECT n.*, dt.model AS device_type_model, dt.part_number AS device_type_part_number,
           mf.name AS manufacturer_name, COALESCE(c.n, 0) AS host_count
    FROM hardware_notices n
    LEFT JOIN device_types dt ON dt.id = n.device_type_id
    LEFT JOIN manufacturers mf ON mf.id = dt.manufacturer_id
    LEFT JOIN (SELECT notice_id, COUNT(DISTINCT host_id) AS n FROM ({_MATCHES}) x GROUP BY notice_id) c
           ON c.notice_id = n.id
"""  # nosec B608 - fixed SQL
_NOTICE_ORDER = " ORDER BY lower(COALESCE(mf.name, '')), lower(COALESCE(dt.model, n.part_number)), n.id"


def _notice(row: dict) -> dict:
    return {**row, "host_count": int(row.get("host_count") or 0)}


async def list_hardware_notices(*, device_type_id: int | None = None, search: str | None = None) -> list[dict]:
    """Notices by manufacturer then model or part number; ``search`` is a
    case-blind substring of the model, part number or comments."""
    clauses: list[str] = []
    params: list[Any] = []
    if device_type_id is not None:
        clauses.append("n.device_type_id = ?")
        params.append(int(device_type_id))
    if search:
        clauses.append(
            "(strpos(lower(COALESCE(dt.model, '')), lower(?)) > 0"
            " OR strpos(lower(n.part_number), lower(?)) > 0 OR strpos(lower(n.comments), lower(?)) > 0)"
        )
        params.extend([search, search, search])
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = await _select(_NOTICE_SELECT + where + _NOTICE_ORDER, tuple(params))  # nosec B608 - fixed clauses
    return [_notice(r) for r in rows]


async def get_hardware_notice(notice_id: int) -> dict | None:
    rows = await _select(_NOTICE_SELECT + " WHERE n.id = ?", (int(notice_id),))
    return _notice(rows[0]) if rows else None


def _notice_taken(values: dict) -> str:
    if values.get("device_type_id") is not None:
        return "The device type already has a notice."
    return f"A notice for part number '{values.get('part_number')}' already exists."


@tracks_changes("hardware_notice", "create")
async def create_hardware_notice(values: dict[str, Any]) -> dict:
    new_id = await _insert("hardware_notices", HARDWARE_NOTICE_FIELDS, values, _notice_taken(values))
    return await _must(get_hardware_notice(new_id))


@tracks_changes("hardware_notice", "update", id_arg="notice_id")
async def update_hardware_notice(notice_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update("hardware_notices", notice_id, HARDWARE_NOTICE_FIELDS, values, _notice_taken(values))
    return await get_hardware_notice(notice_id) if found else None


@tracks_changes("hardware_notice", "delete", id_arg="notice_id")
async def delete_hardware_notice(notice_id: int) -> bool:
    return await _delete("hardware_notices", notice_id, "The notice is in use.")


async def hardware_notice_matches(host_ids: Iterable[int] | None = None) -> list[dict]:
    """``{notice_id, host_id, via}`` for each notice and device it applies to
    (``via``: ``device_type``, ``part_number`` or ``module``); only those
    devices with ``host_ids``."""
    if host_ids is None:
        return await _select(f"SELECT * FROM ({_MATCHES}) x ORDER BY notice_id, host_id")  # nosec B608 - fixed SQL
    ids = [int(h) for h in host_ids]
    if not ids:
        return []
    return await _select(
        f"SELECT * FROM ({_MATCHES}) x WHERE host_id IN ({_marks(ids)}) ORDER BY notice_id, host_id",  # nosec B608 - placeholders only
        tuple(ids),
    )


async def hardware_notice_hosts(notice_id: int) -> list[dict]:
    """The devices a notice applies to: ``{id, hostname, ip_address, via}``
    (``via`` lists every way it applies), by name."""
    rows = await _select(
        f"""SELECT x.host_id AS id, h.hostname, h.ip_address, x.via
            FROM ({_MATCHES}) x JOIN hosts h ON h.id = x.host_id
            WHERE x.notice_id = ? ORDER BY lower(h.hostname), h.id""",  # nosec B608 - fixed SQL
        (int(notice_id),),
    )
    out: dict[int, dict] = {}
    for row in rows:
        host = out.setdefault(
            int(row["id"]), {"id": int(row["id"]), "hostname": row["hostname"], "ip_address": row["ip_address"]}
        )
        host.setdefault("via", [])
        if row["via"] not in host["via"]:
            host["via"].append(row["via"])
    return list(out.values())


# ── Contracts ────────────────────────────────────────────────────────────────

_CONTRACT_SELECT = """
    SELECT c.*, (SELECT COUNT(*) FROM support_contract_hosts l WHERE l.contract_id = c.id) AS host_count
    FROM support_contracts c
"""
_CONTRACT_ORDER = " ORDER BY lower(c.provider), lower(c.contract_id), c.id"


def _contract(row: dict) -> dict:
    cost = row.get("cost")
    return {
        **row,
        "cost": str(cost) if isinstance(cost, Decimal) else (None if cost is None else str(cost)),
        "host_count": int(row.get("host_count") or 0),
    }


async def _with_hosts(contracts: list[dict]) -> list[dict]:
    """Each contract with ``hosts``: ``[{id, hostname, ip_address}]`` by name."""
    if not contracts:
        return contracts
    ids = [int(c["id"]) for c in contracts]
    rows = await _select(
        f"""SELECT l.contract_id, h.id, h.hostname, h.ip_address
            FROM support_contract_hosts l JOIN hosts h ON h.id = l.host_id
            WHERE l.contract_id IN ({_marks(ids)}) ORDER BY lower(h.hostname), h.id""",  # nosec B608 - placeholders only
        tuple(ids),
    )
    by_contract: dict[int, list[dict]] = {cid: [] for cid in ids}
    for row in rows:
        by_contract[int(row["contract_id"])].append(
            {"id": int(row["id"]), "hostname": row["hostname"], "ip_address": row["ip_address"]}
        )
    return [{**c, "hosts": by_contract[int(c["id"])]} for c in contracts]


async def list_support_contracts(*, host_id: int | None = None, search: str | None = None) -> list[dict]:
    """Contracts with their ``hosts`` by provider then contract id;
    ``host_id`` keeps those covering the device, ``search`` is a case-blind
    substring of the provider, contract id or support level."""
    clauses: list[str] = []
    params: list[Any] = []
    if host_id is not None:
        clauses.append("EXISTS (SELECT 1 FROM support_contract_hosts l WHERE l.contract_id = c.id AND l.host_id = ?)")
        params.append(int(host_id))
    if search:
        clauses.append(
            "(strpos(lower(c.provider), lower(?)) > 0 OR strpos(lower(c.contract_id), lower(?)) > 0"
            " OR strpos(lower(c.support_level), lower(?)) > 0)"
        )
        params.extend([search, search, search])
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = await _select(_CONTRACT_SELECT + where + _CONTRACT_ORDER, tuple(params))  # nosec B608 - fixed clauses
    return await _with_hosts([_contract(r) for r in rows])


async def get_support_contract(contract_id: int) -> dict | None:
    rows = await _select(_CONTRACT_SELECT + " WHERE c.id = ?", (int(contract_id),))
    if not rows:
        return None
    return (await _with_hosts([_contract(rows[0])]))[0]


def _contract_row(values: dict[str, Any]) -> dict[str, Any]:
    """The values as columns: the cost text as a ``Decimal`` for NUMERIC."""
    cost = values.get("cost")
    return {**values, "cost": None if cost is None or cost == "" else Decimal(str(cost))}


def _contract_taken(values: dict) -> str:
    return f"{values.get('provider')} already has a contract '{values.get('contract_id')}'."


async def _set_contract_hosts(contract_id: int, host_ids: Iterable[int]) -> None:
    """Replace the devices a contract covers (one transaction)."""
    ids = sorted({int(h) for h in host_ids})
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM support_contract_hosts WHERE contract_id = ?", (int(contract_id),))
        if ids:
            await db.executemany(
                "INSERT INTO support_contract_hosts (contract_id, host_id) VALUES (?, ?)",
                [(int(contract_id), h) for h in ids],
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


@tracks_changes("support_contract", "create")
async def create_support_contract(values: dict[str, Any], host_ids: Iterable[int] = ()) -> dict:
    new_id = await _insert("support_contracts", SUPPORT_CONTRACT_FIELDS, _contract_row(values), _contract_taken(values))
    await _set_contract_hosts(new_id, host_ids)
    return await _must(get_support_contract(new_id))


@tracks_changes("support_contract", "update", id_arg="contract_id")
async def update_support_contract(
    contract_id: int, values: dict[str, Any], host_ids: Iterable[int] | None = None
) -> dict | None:
    """Set the contract's fields; ``host_ids`` (when given) replaces the
    devices it covers."""
    found = await _update(
        "support_contracts", contract_id, SUPPORT_CONTRACT_FIELDS, _contract_row(values), _contract_taken(values)
    )
    if not found:
        return None
    if host_ids is not None:
        await _set_contract_hosts(contract_id, host_ids)
    return await get_support_contract(contract_id)


@tracks_changes("support_contract", "delete", id_arg="contract_id")
async def delete_support_contract(contract_id: int) -> bool:
    """Delete a contract and its device links."""
    return await _delete("support_contracts", contract_id, "The contract is in use.")


async def missing_host_ids(host_ids: Iterable[int]) -> list[int]:
    """The ids of ``host_ids`` that name no device."""
    ids = sorted({int(h) for h in host_ids})
    if not ids:
        return []
    rows = await _select(f"SELECT id FROM hosts WHERE id IN ({_marks(ids)})", tuple(ids))  # nosec B608 - placeholders only
    found = {int(r["id"]) for r in rows}
    return [h for h in ids if h not in found]


async def support_contracts_by_host(host_ids: Iterable[int] | None = None) -> dict[int, list[dict]]:
    """Device id -> the contracts linked to it (id, provider, contract id,
    dates, support level), by end date; only those devices with
    ``host_ids``."""
    sql = """SELECT l.host_id, c.id, c.provider, c.contract_id, c.start_date, c.end_date, c.support_level
             FROM support_contract_hosts l JOIN support_contracts c ON c.id = l.contract_id"""
    params: tuple = ()
    if host_ids is not None:
        ids = [int(h) for h in host_ids]
        if not ids:
            return {}
        sql += f" WHERE l.host_id IN ({_marks(ids)})"
        params = tuple(ids)
    out: dict[int, list[dict]] = {}
    for row in await _select(sql + " ORDER BY c.end_date, c.id", params):  # nosec B608 - placeholders only
        host_id = int(row.pop("host_id"))
        out.setdefault(host_id, []).append(row)
    return out


async def lifecycle_hosts(host_id: int | None = None) -> list[dict]:
    """The devices the lifecycle status is reported for (every inventory
    host, or one): id, hostname, ip_address, serial_number, model and their
    device type, manufacturer and lifecycle status names, by name."""
    sql = """SELECT h.id, h.hostname, h.ip_address, h.serial_number, h.model, h.device_type_id,
                    dt.model AS device_type_model, dt.part_number AS device_type_part_number,
                    mf.name AS manufacturer_name, hs.name AS lifecycle_status_name
             FROM hosts h
             LEFT JOIN device_types dt ON dt.id = h.device_type_id
             LEFT JOIN manufacturers mf ON mf.id = dt.manufacturer_id
             LEFT JOIN host_statuses hs ON hs.id = h.lifecycle_status_id"""
    if host_id is not None:
        return await _select(sql + " WHERE h.id = ?", (int(host_id),))
    return await _select(sql + " ORDER BY lower(h.hostname), h.id")


# ── Settings ─────────────────────────────────────────────────────────────────


async def get_lifecycle_settings() -> dict[str, str]:
    rows = await _select("SELECT key, value FROM hardware_lifecycle_settings")
    return {row["key"]: row["value"] for row in rows}


async def set_lifecycle_settings(values: dict[str, Any]) -> None:
    if not values:
        return
    db = await _dbcore.get_db()
    try:
        await db.executemany(
            "INSERT INTO hardware_lifecycle_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(str(key), str(value if value is not None else "")) for key, value in values.items()],
        )
        await db.commit()
    finally:
        await db.close()


# ── Alert state ──────────────────────────────────────────────────────────────


async def list_lifecycle_alert_states() -> dict[str, dict]:
    """``dedup_key`` -> the condition an alert was raised for."""
    rows = await _select("SELECT * FROM hardware_lifecycle_alerts")
    return {row["dedup_key"]: row for row in rows}


async def add_lifecycle_alert_state(dedup_key: str, host_id: int, kind: str, message: str) -> None:
    now = _now()
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO hardware_lifecycle_alerts (dedup_key, host_id, kind, message, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(dedup_key) DO UPDATE SET message = excluded.message, last_seen = excluded.last_seen""",
            (dedup_key, int(host_id), kind, message, now, now),
        )
        await db.commit()
    finally:
        await db.close()


async def touch_lifecycle_alert_states(keys: Iterable[str]) -> int:
    """Stamp ``last_seen`` on conditions that still hold."""
    items = list(keys)
    if not items:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"UPDATE hardware_lifecycle_alerts SET last_seen = ? WHERE dedup_key IN ({_marks(items)})",  # nosec B608 - placeholders only
            (_now(), *items),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


async def delete_lifecycle_alert_states(keys: Iterable[str]) -> int:
    """Forget conditions that cleared."""
    items = list(keys)
    if not items:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"DELETE FROM hardware_lifecycle_alerts WHERE dedup_key IN ({_marks(items)})",  # nosec B608 - placeholders only
            tuple(items),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()
