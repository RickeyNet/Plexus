"""Software end-of-life entries: the end-of-life date of a release series.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: ``software_eol_entries`` (migration 0130), one row per platform and
series. The callers (``netcontrol.routes.software_eol``) validate the
values first. Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import row_to_dict, rows_to_list

__all__ = [
    "SOFTWARE_EOL_FIELDS",
    "create_software_eol_entry",
    "delete_software_eol_entry",
    "find_software_eol_entry",
    "get_software_eol_entry",
    "list_software_eol_entries",
    "update_software_eol_entry",
]

# The columns an administrator sets.
SOFTWARE_EOL_FIELDS = ("platform", "series", "eol_date", "release_date", "url", "notes", "source", "enabled")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _entry(row) -> dict | None:
    entry = row_to_dict(row)
    if entry is not None:
        entry["enabled"] = bool(entry.get("enabled"))
    return entry


def _values(entry: dict) -> tuple:
    return tuple(
        (1 if entry.get(field, True) else 0) if field == "enabled" else str(entry.get(field) or "")
        for field in SOFTWARE_EOL_FIELDS
    )


async def list_software_eol_entries(enabled_only: bool = False) -> list[dict]:
    """Every entry, by platform and series."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT * FROM software_eol_entries {'WHERE enabled = 1' if enabled_only else ''} "
            "ORDER BY platform, series, id"
        )
        return [e for e in (_entry(row) for row in await cursor.fetchall()) if e]
    finally:
        await db.close()


async def get_software_eol_entry(entry_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM software_eol_entries WHERE id = ?", (int(entry_id),))
        return _entry(await cursor.fetchone())
    finally:
        await db.close()


async def find_software_eol_entry(platform: str, series: str) -> dict | None:
    """The entry of ``platform`` and ``series``, or ``None``."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT * FROM software_eol_entries WHERE platform = ? AND series = ?", (platform, series)
        )
        return _entry(await cursor.fetchone())
    finally:
        await db.close()


async def create_software_eol_entry(entry: dict, user: str = "") -> dict | None:
    now = _now()
    columns = ", ".join(SOFTWARE_EOL_FIELDS)
    marks = ", ".join("?" for _ in SOFTWARE_EOL_FIELDS)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"""INSERT INTO software_eol_entries ({columns}, created_at, created_by, updated_at, updated_by)
                VALUES ({marks}, ?, ?, ?, ?) RETURNING id""",
            (*_values(entry), now, user, now, user),
        )
        new_id = cursor.lastrowid
        await db.commit()
    finally:
        await db.close()
    return await get_software_eol_entry(int(new_id or 0))


async def update_software_eol_entry(entry_id: int, entry: dict, user: str = "") -> dict | None:
    assignments = ", ".join(f"{field} = ?" for field in SOFTWARE_EOL_FIELDS)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"UPDATE software_eol_entries SET {assignments}, updated_at = ?, updated_by = ? WHERE id = ?",
            (*_values(entry), _now(), user, int(entry_id)),
        )
        await db.commit()
        if not cursor.rowcount:
            return None
    finally:
        await db.close()
    return await get_software_eol_entry(entry_id)


async def delete_software_eol_entry(entry_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM software_eol_entries WHERE id = ?", (int(entry_id),))
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()
