"""Circuits: providers, provider networks, circuit types, circuits and their
A / Z terminations.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0099. Every mutation is tracked (``tracks_changes``) so the
change log and webhooks see it; the stamps (``created_by``/``updated_by``)
take the acting user of the request (``current_actor``). The callers
(``netcontrol.routes.circuits``) validate the values first; a duplicate name
or circuit id raises ``ValueError``, a delete that something still points at
raises ``CircuitInUseError``.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from typing import Any

import routes.database as _dbcore
from routes.database import _is_foreign_key_violation, _is_unique_violation, _safe_dynamic_update, rows_to_list
from routes.db.change_events import current_actor, tracks_changes
from routes.db.custom_fields import _marks, _now
from routes.db.device_model import _must

__all__ = [
    "CIRCUIT_PROVIDER_FIELDS",
    "CIRCUIT_TERMINATION_FIELDS",
    "CIRCUIT_FIELDS",
    "CircuitInUseError",
    "circuit_missing_refs",
    "circuit_provider_usage",
    "circuit_type_usage",
    "create_circuit",
    "create_circuit_provider",
    "create_circuit_termination",
    "create_circuit_type",
    "create_provider_network",
    "delete_circuit",
    "delete_circuit_provider",
    "delete_circuit_termination",
    "delete_circuit_type",
    "delete_provider_network",
    "get_circuit",
    "get_circuit_provider",
    "get_circuit_termination",
    "get_circuit_type",
    "get_provider_network",
    "list_circuit_providers",
    "list_circuit_types",
    "list_circuits",
    "list_provider_networks",
    "provider_network_usage",
    "update_circuit",
    "update_circuit_provider",
    "update_circuit_termination",
    "update_circuit_type",
    "update_provider_network",
]

CIRCUIT_PROVIDER_FIELDS: tuple[str, ...] = (
    "name",
    "account",
    "portal_url",
    "noc_contact",
    "admin_contact",
    "comments",
)
_PROVIDER_NETWORK_FIELDS: tuple[str, ...] = ("name", "description")
_CIRCUIT_TYPE_FIELDS: tuple[str, ...] = ("name", "description")
CIRCUIT_FIELDS: tuple[str, ...] = (
    "cid",
    "provider_id",
    "circuit_type_id",
    "status",
    "tenant_id",
    "install_date",
    "termination_date",
    "commit_rate_kbps",
    "description",
    "comments",
    "billing_circuit_id",
)
CIRCUIT_TERMINATION_FIELDS: tuple[str, ...] = (
    "site_id",
    "provider_network_id",
    "host_id",
    "interface_name",
    "port_speed_kbps",
    "upstream_speed_kbps",
    "xconnect_id",
    "pp_info",
    "description",
)
_STAMPS = ("created_by", "created_at", "updated_at", "updated_by")

# A reference field of a request -> the table its id names (fixed names).
_REF_TABLES: dict[str, str] = {
    "provider_id": "circuit_providers",
    "circuit_type_id": "circuit_types",
    "tenant_id": "tenants",
    "billing_circuit_id": "billing_circuits",
    "site_id": "geo_sites",
    "provider_network_id": "provider_networks",
    "host_id": "hosts",
}


class CircuitInUseError(Exception):
    """A delete refused because another row still points at the record."""


# ── Plumbing ─────────────────────────────────────────────────────────────────


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


def _actor() -> str:
    return current_actor.get() or "system"


async def _insert(table: str, fields: tuple[str, ...], values: dict[str, Any], taken: str) -> int:
    """Insert one row of ``table`` (fixed name) with the ``fields`` that
    ``values`` holds (the others take their column default) and the stamps;
    ``ValueError(taken)`` on a unique clash."""
    now, user = _now(), _actor()
    given = tuple(f for f in fields if f in values)
    columns = (*given, *_STAMPS)
    params = (*(values[f] for f in given), user, now, now, user)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed table and columns
            params,
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
        return new_id
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(taken) from exc
        raise
    finally:
        await db.close()


async def _update(table: str, row_id: int, fields: tuple[str, ...], values: dict[str, Any], taken: str) -> bool:
    """Set ``fields`` of one row from ``values`` (and the update stamps).
    ``False`` when the row does not exist."""
    exprs = [f"{f} = ?" for f in fields] + ["updated_at = ?", "updated_by = ?"]
    sql, params = _safe_dynamic_update(
        table, exprs, [values.get(f) for f in fields] + [_now(), _actor()], "id = ?", int(row_id)
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(taken) from exc
        raise
    finally:
        await db.close()


async def _delete(table: str, row_id: int, in_use: str) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(row_id),))  # nosec B608 - fixed table
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_foreign_key_violation(exc):
            raise CircuitInUseError(in_use) from exc
        raise
    finally:
        await db.close()


async def _count(sql: str, params: tuple) -> int:
    rows = await _select(sql, params)
    return int(rows[0]["n"]) if rows else 0


async def circuit_missing_refs(refs: dict[str, int | None]) -> list[str]:
    """The reference fields of ``refs`` (``provider_id``, ``site_id``,
    ``host_id``...) whose id names no row; ``None`` values are skipped."""
    missing: list[str] = []
    for field, value in refs.items():
        table = _REF_TABLES.get(field)
        if table is None or value is None:
            continue
        found = await _select(f"SELECT 1 AS x FROM {table} WHERE id = ?", (int(value),))  # nosec B608 - fixed tables
        if not found:
            missing.append(field)
    return missing


# ── Providers ────────────────────────────────────────────────────────────────

_PROVIDER_SELECT = """
    SELECT p.*,
           (SELECT COUNT(*) FROM circuits c WHERE c.provider_id = p.id) AS circuit_count,
           (SELECT COUNT(*) FROM provider_networks n WHERE n.provider_id = p.id) AS network_count
    FROM circuit_providers p
"""


async def list_circuit_providers() -> list[dict]:
    return await _select(_PROVIDER_SELECT + " ORDER BY lower(p.name), p.id")


async def get_circuit_provider(provider_id: int) -> dict | None:
    rows = await _select(_PROVIDER_SELECT + " WHERE p.id = ?", (int(provider_id),))
    return rows[0] if rows else None


def _provider_taken(values: dict) -> str:
    return f"A provider named '{values.get('name')}' already exists."


@tracks_changes("circuit_provider", "create")
async def create_circuit_provider(values: dict[str, Any]) -> dict:
    new_id = await _insert("circuit_providers", CIRCUIT_PROVIDER_FIELDS, values, _provider_taken(values))
    return await _must(get_circuit_provider(new_id))


@tracks_changes("circuit_provider", "update", id_arg="provider_id")
async def update_circuit_provider(provider_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update("circuit_providers", provider_id, CIRCUIT_PROVIDER_FIELDS, values, _provider_taken(values))
    return await get_circuit_provider(provider_id) if found else None


async def circuit_provider_usage(provider_id: int) -> dict[str, int]:
    """``circuits``: circuits of the provider; ``terminations``: terminations
    in one of its provider networks."""
    pid = int(provider_id)
    return {
        "circuits": await _count("SELECT COUNT(*) AS n FROM circuits WHERE provider_id = ?", (pid,)),
        "terminations": await _count(
            """SELECT COUNT(*) AS n FROM circuit_terminations t
               JOIN provider_networks n ON n.id = t.provider_network_id WHERE n.provider_id = ?""",
            (pid,),
        ),
    }


@tracks_changes("circuit_provider", "delete", id_arg="provider_id")
async def delete_circuit_provider(provider_id: int) -> bool:
    """Delete a provider and its provider networks (the caller checks
    ``circuit_provider_usage`` first)."""
    return await _delete("circuit_providers", provider_id, "The provider is in use.")


# ── Provider networks ────────────────────────────────────────────────────────

_NETWORK_SELECT = """
    SELECT n.*, p.name AS provider_name,
           (SELECT COUNT(*) FROM circuit_terminations t WHERE t.provider_network_id = n.id) AS termination_count
    FROM provider_networks n JOIN circuit_providers p ON p.id = n.provider_id
"""


async def list_provider_networks(provider_id: int | None = None) -> list[dict]:
    if provider_id is None:
        return await _select(_NETWORK_SELECT + " ORDER BY lower(p.name), lower(n.name), n.id")
    return await _select(_NETWORK_SELECT + " WHERE n.provider_id = ? ORDER BY lower(n.name), n.id", (int(provider_id),))


async def get_provider_network(network_id: int) -> dict | None:
    rows = await _select(_NETWORK_SELECT + " WHERE n.id = ?", (int(network_id),))
    return rows[0] if rows else None


def _network_taken(values: dict) -> str:
    return f"The provider already has a network named '{values.get('name')}'."


@tracks_changes("provider_network", "create")
async def create_provider_network(provider_id: int, values: dict[str, Any]) -> dict:
    new_id = await _insert(
        "provider_networks",
        ("provider_id", *_PROVIDER_NETWORK_FIELDS),
        {**values, "provider_id": int(provider_id)},
        _network_taken(values),
    )
    return await _must(get_provider_network(new_id))


@tracks_changes("provider_network", "update", id_arg="network_id")
async def update_provider_network(network_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update("provider_networks", network_id, _PROVIDER_NETWORK_FIELDS, values, _network_taken(values))
    return await get_provider_network(network_id) if found else None


async def provider_network_usage(network_id: int) -> int:
    """Terminations in the provider network."""
    return await _count(
        "SELECT COUNT(*) AS n FROM circuit_terminations WHERE provider_network_id = ?", (int(network_id),)
    )


@tracks_changes("provider_network", "delete", id_arg="network_id")
async def delete_provider_network(network_id: int) -> bool:
    return await _delete("provider_networks", network_id, "The provider network is in use.")


# ── Circuit types ────────────────────────────────────────────────────────────

_TYPE_SELECT = """
    SELECT ct.*, (SELECT COUNT(*) FROM circuits c WHERE c.circuit_type_id = ct.id) AS circuit_count
    FROM circuit_types ct
"""


async def list_circuit_types() -> list[dict]:
    return await _select(_TYPE_SELECT + " ORDER BY lower(ct.name), ct.id")


async def get_circuit_type(type_id: int) -> dict | None:
    rows = await _select(_TYPE_SELECT + " WHERE ct.id = ?", (int(type_id),))
    return rows[0] if rows else None


def _type_taken(values: dict) -> str:
    return f"A circuit type named '{values.get('name')}' already exists."


@tracks_changes("circuit_type", "create")
async def create_circuit_type(values: dict[str, Any]) -> dict:
    new_id = await _insert("circuit_types", _CIRCUIT_TYPE_FIELDS, values, _type_taken(values))
    return await _must(get_circuit_type(new_id))


@tracks_changes("circuit_type", "update", id_arg="type_id")
async def update_circuit_type(type_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update("circuit_types", type_id, _CIRCUIT_TYPE_FIELDS, values, _type_taken(values))
    return await get_circuit_type(type_id) if found else None


async def circuit_type_usage(type_id: int) -> int:
    """Circuits of the type."""
    return await _count("SELECT COUNT(*) AS n FROM circuits WHERE circuit_type_id = ?", (int(type_id),))


@tracks_changes("circuit_type", "delete", id_arg="type_id")
async def delete_circuit_type(type_id: int) -> bool:
    return await _delete("circuit_types", type_id, "The circuit type is in use.")


# ── Circuits ─────────────────────────────────────────────────────────────────

_CIRCUIT_SELECT = """
    SELECT c.*, p.name AS provider_name, ct.name AS circuit_type_name, tn.name AS tenant_name,
           bc.name AS billing_circuit_name, bc.customer AS billing_customer
    FROM circuits c
    JOIN circuit_providers p ON p.id = c.provider_id
    JOIN circuit_types ct ON ct.id = c.circuit_type_id
    LEFT JOIN tenants tn ON tn.id = c.tenant_id
    LEFT JOIN billing_circuits bc ON bc.id = c.billing_circuit_id
"""
_CIRCUIT_ORDER = " ORDER BY lower(p.name), lower(c.cid), c.id"

_TERMINATION_SELECT = """
    SELECT t.*, s.name AS site_name, n.name AS provider_network_name, h.hostname
    FROM circuit_terminations t
    LEFT JOIN geo_sites s ON s.id = t.site_id
    LEFT JOIN provider_networks n ON n.id = t.provider_network_id
    LEFT JOIN hosts h ON h.id = t.host_id
"""


async def _with_terminations(circuits: list[dict]) -> list[dict]:
    """Each circuit with its ``terminations`` (A first)."""
    if not circuits:
        return circuits
    ids = [int(c["id"]) for c in circuits]
    rows = await _select(
        _TERMINATION_SELECT + f" WHERE t.circuit_id IN ({_marks(ids)}) ORDER BY t.circuit_id, t.term_side",  # nosec B608 - placeholders only
        tuple(ids),
    )
    by_circuit: dict[int, list[dict]] = {cid: [] for cid in ids}
    for row in rows:
        by_circuit[int(row["circuit_id"])].append(row)
    return [{**c, "terminations": by_circuit[int(c["id"])]} for c in circuits]


async def list_circuits(
    *,
    provider_id: int | None = None,
    circuit_type_id: int | None = None,
    status: str | None = None,
    tenant_id: int | None = None,
    site_id: int | None = None,
    host_id: int | None = None,
    search: str | None = None,
) -> list[dict]:
    """Circuits with their terminations, filtered: ``site_id`` / ``host_id``
    match a circuit with a termination there; ``search`` is a case-blind
    substring of the circuit id or the description."""
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("c.provider_id", provider_id),
        ("c.circuit_type_id", circuit_type_id),
        ("c.status", status),
        ("c.tenant_id", tenant_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    for column, value in (("site_id", site_id), ("host_id", host_id)):
        if value is not None:
            clauses.append(
                f"EXISTS (SELECT 1 FROM circuit_terminations t WHERE t.circuit_id = c.id AND t.{column} = ?)"
            )
            params.append(int(value))
    if search:
        clauses.append("(strpos(lower(c.cid), lower(?)) > 0 OR strpos(lower(c.description), lower(?)) > 0)")
        params.extend([search, search])
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = await _select(_CIRCUIT_SELECT + where + _CIRCUIT_ORDER, tuple(params))  # nosec B608 - fixed clauses
    return await _with_terminations(rows)


async def get_circuit(circuit_id: int) -> dict | None:
    rows = await _select(_CIRCUIT_SELECT + " WHERE c.id = ?", (int(circuit_id),))
    if not rows:
        return None
    return (await _with_terminations(rows))[0]


def _circuit_taken(values: dict) -> str:
    return f"The provider already has a circuit with ID '{values.get('cid')}'."


@tracks_changes("circuit", "create")
async def create_circuit(values: dict[str, Any]) -> dict:
    new_id = await _insert("circuits", CIRCUIT_FIELDS, values, _circuit_taken(values))
    return await _must(get_circuit(new_id))


@tracks_changes("circuit", "update", id_arg="circuit_id")
async def update_circuit(circuit_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update("circuits", circuit_id, CIRCUIT_FIELDS, values, _circuit_taken(values))
    return await get_circuit(circuit_id) if found else None


@tracks_changes("circuit", "delete", id_arg="circuit_id")
async def delete_circuit(circuit_id: int) -> bool:
    """Delete a circuit and its terminations."""
    return await _delete("circuits", circuit_id, "The circuit is in use.")


# ── Terminations ─────────────────────────────────────────────────────────────


async def get_circuit_termination(termination_id: int) -> dict | None:
    rows = await _select(_TERMINATION_SELECT + " WHERE t.id = ?", (int(termination_id),))
    return rows[0] if rows else None


def _side_taken(values: dict) -> str:
    return f"The circuit's {values.get('term_side')} side already has a termination."


@tracks_changes("circuit_termination", "create")
async def create_circuit_termination(circuit_id: int, term_side: str, values: dict[str, Any]) -> dict:
    row = {**values, "circuit_id": int(circuit_id), "term_side": term_side}
    new_id = await _insert(
        "circuit_terminations",
        ("circuit_id", "term_side", *CIRCUIT_TERMINATION_FIELDS),
        row,
        _side_taken(row),
    )
    return await _must(get_circuit_termination(new_id))


@tracks_changes("circuit_termination", "update", id_arg="termination_id")
async def update_circuit_termination(termination_id: int, values: dict[str, Any]) -> dict | None:
    found = await _update(
        "circuit_terminations", termination_id, CIRCUIT_TERMINATION_FIELDS, values, "The termination clashes."
    )
    return await get_circuit_termination(termination_id) if found else None


@tracks_changes("circuit_termination", "delete", id_arg="termination_id")
async def delete_circuit_termination(termination_id: int) -> bool:
    return await _delete("circuit_terminations", termination_id, "The termination is in use.")
