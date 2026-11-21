"""OPNsense alias tables: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0123 (``opnsense_alias_tables``). The collector reads the
tables (``netcontrol.integrations.opnsense.collector``), the collection
stores them for the firewall's inventory host
(``netcontrol.routes.opnsense_collection.store_alias_tables``) and the path
trace and the rule views read them back. Each collection replaces a host's
rows as a whole; rows go with their host.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable

import routes.database as _dbcore
from routes.db.device_model import _select
from routes.db.opnsense_filterlog import _marks

__all__ = [
    "get_opnsense_alias_table_versions",
    "get_opnsense_alias_tables",
    "replace_opnsense_alias_tables",
]

_INSERT = """
INSERT INTO opnsense_alias_tables (host_id, name, entries, entry_count, total, truncated, read_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


async def replace_opnsense_alias_tables(host_id: int, tables: list[dict], read_at: str) -> int:
    """Replace the alias tables of ``host_id`` with ``tables`` (each
    ``{name, entries: [str], total, truncated}``), read at ``read_at``.
    Returns the number of tables stored."""
    rows: dict[str, tuple] = {}
    for table in tables:
        name = str(table.get("name") or "").strip()
        if not name:
            continue
        entries = [str(e).strip() for e in table.get("entries") or [] if str(e).strip()]
        total = max(int(table.get("total") or 0), len(entries))
        rows[name] = (
            int(host_id),
            name,
            "\n".join(entries),
            len(entries),
            total,
            1 if table.get("truncated") else 0,
            read_at,
        )
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM opnsense_alias_tables WHERE host_id = ?", (int(host_id),))
        if rows:
            await db.executemany(_INSERT, list(rows.values()))
        await db.commit()
        return len(rows)
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_opnsense_alias_table_versions(host_ids: Iterable[int]) -> dict[int, str]:
    """``host_id -> read_at`` of the hosts of ``host_ids`` with alias tables
    (a cheap check of whether they changed since last read)."""
    wanted = sorted({int(h) for h in host_ids})
    if not wanted:
        return {}
    rows = await _select(
        "SELECT host_id, MAX(read_at) AS read_at, COUNT(*) AS tables FROM opnsense_alias_tables"
        f" WHERE host_id IN ({_marks(len(wanted))}) GROUP BY host_id",  # nosec B608 - placeholders only
        tuple(wanted),
    )
    return {int(r["host_id"]): f"{r['read_at'] or ''}#{int(r['tables'] or 0)}" for r in rows}


async def get_opnsense_alias_tables(host_ids: Iterable[int], *, with_entries: bool = True) -> dict[int, dict]:
    """``host_id -> {"read_at", "tables": {name: {"name", "entries",
    "entry_count", "total", "truncated"}}}`` of the hosts of ``host_ids``
    with alias tables. ``with_entries`` false leaves the entries out (the
    counts only)."""
    wanted = sorted({int(h) for h in host_ids})
    if not wanted:
        return {}
    columns = "host_id, name, entry_count, total, truncated, read_at" + (", entries" if with_entries else "")
    rows = await _select(
        f"SELECT {columns} FROM opnsense_alias_tables"  # nosec B608 - fixed columns and placeholders only
        f" WHERE host_id IN ({_marks(len(wanted))}) ORDER BY host_id, name",
        tuple(wanted),
    )
    found: dict[int, dict] = {}
    for row in rows:
        host = found.setdefault(int(row["host_id"]), {"read_at": "", "tables": {}})
        read_at = str(row.get("read_at") or "")
        host["read_at"] = max(host["read_at"], read_at)
        host["tables"][str(row["name"])] = {
            "name": str(row["name"]),
            "entries": str(row.get("entries") or "").split("\n") if with_entries and row.get("entries") else [],
            "entry_count": int(row.get("entry_count") or 0),
            "total": int(row.get("total") or 0),
            "truncated": bool(row.get("truncated")),
            "read_at": read_at,
        }
    return found
