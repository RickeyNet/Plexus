"""Geolocation persistence helpers.

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
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "list_geo_sites",
    "get_geo_site",
    "create_geo_site",
    "update_geo_site",
    "delete_geo_site",
    "list_geo_floors",
    "get_geo_floor",
    "create_geo_floor",
    "update_geo_floor",
    "delete_geo_floor",
    "get_geo_placements",
    "upsert_geo_placement",
    "delete_geo_placement",
    "get_geo_overview",
]

# ═════════════════════════════════════════════════════════════════════════════
# Geolocation - Sites, Floors, Placements
# ═════════════════════════════════════════════════════════════════════════════

async def list_geo_sites() -> list:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      COUNT(DISTINCT f.id)                                AS floor_count,
                      COUNT(DISTINCT p.id)                                AS placed_device_count
               FROM geo_sites s
               LEFT JOIN geo_floors f ON f.site_id = s.id
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               GROUP BY s.id
               ORDER BY s.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_geo_site(site_id: int) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_geo_site(name: str, description: str = "", address: str = "",
                          lat: float | None = None, lng: float | None = None,
                          created_by: str = "") -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO geo_sites (name, description, address, lat, lng, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, address, lat, lng, created_by),
        )
        await db.commit()
        site_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor2.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"Site name '{name}' already exists.")
        raise
    finally:
        await db.close()


async def update_geo_site(site_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "address", "lat", "lng"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return await get_geo_site(site_id)
    updates["updated_at"] = "datetime('now')"
    set_exprs = [f"{k} = ?" for k in updates if k != "updated_at"]
    set_exprs.append("updated_at = datetime('now')")
    vals = [v for k, v in updates.items() if k != "updated_at"]
    sql, params = _safe_dynamic_update("geo_sites", set_exprs, vals, "id = ?", site_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM geo_sites WHERE id = ?", (site_id,))
        return row_to_dict(await cursor.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError("Site name already exists.")
        raise
    finally:
        await db.close()


async def delete_geo_site(site_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM geo_sites WHERE id = ?", (site_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def list_geo_floors(site_id: int) -> list:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT f.*,
                      COUNT(p.id) AS placed_device_count
               FROM geo_floors f
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               WHERE f.site_id = ?
               GROUP BY f.id
               ORDER BY f.floor_number, f.name""",
            (site_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_geo_floor(floor_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_geo_floor(site_id: int, name: str, floor_number: int = 0) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO geo_floors (site_id, name, floor_number)
               VALUES (?, ?, ?)""",
            (site_id, name, floor_number),
        )
        await db.commit()
        floor_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor2.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"Floor name '{name}' already exists in this site.")
        raise
    finally:
        await db.close()


async def update_geo_floor(floor_id: int, **kwargs) -> dict | None:
    allowed = {"name", "floor_number", "image_filename", "image_width", "image_height"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_geo_floor(floor_id)
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    vals = list(updates.values())
    sql, params = _safe_dynamic_update("geo_floors", set_exprs, vals, "id = ?", floor_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM geo_floors WHERE id = ?", (floor_id,))
        return row_to_dict(await cursor.fetchone())
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError("Floor name already exists in this site.")
        raise
    finally:
        await db.close()


async def delete_geo_floor(floor_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM geo_floors WHERE id = ?", (floor_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_geo_placements(floor_id: int) -> list:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.id, p.floor_id, p.host_id, p.x_pct, p.y_pct,
                      h.hostname, h.ip_address, h.status
               FROM geo_placements p
               JOIN hosts h ON h.id = p.host_id
               WHERE p.floor_id = ?
               ORDER BY h.hostname""",
            (floor_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def upsert_geo_placement(floor_id: int, host_id: int,
                               x_pct: float, y_pct: float) -> dict:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO geo_placements (floor_id, host_id, x_pct, y_pct)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(floor_id, host_id)
               DO UPDATE SET x_pct = excluded.x_pct,
                             y_pct = excluded.y_pct,
                             updated_at = datetime('now')""",
            (floor_id, host_id, x_pct, y_pct),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT * FROM geo_placements WHERE floor_id = ? AND host_id = ?",
            (floor_id, host_id),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_geo_placement(floor_id: int, host_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM geo_placements WHERE floor_id = ? AND host_id = ?",
            (floor_id, host_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_geo_overview() -> list:
    """Return all sites enriched with floor count and device status counts."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT s.id, s.name, s.description, s.address, s.lat, s.lng,
                      s.created_by, s.created_at, s.updated_at,
                      COUNT(DISTINCT f.id)   AS floor_count,
                      COUNT(DISTINCT p.id)   AS placed_device_count,
                      SUM(CASE WHEN h.status = 'up'      THEN 1 ELSE 0 END) AS online_count,
                      SUM(CASE WHEN h.status = 'down'    THEN 1 ELSE 0 END) AS offline_count,
                      SUM(CASE WHEN h.status NOT IN ('up','down') OR h.status IS NULL
                               THEN 1 ELSE 0 END) AS unknown_count
               FROM geo_sites s
               LEFT JOIN geo_floors f    ON f.site_id = s.id
               LEFT JOIN geo_placements p ON p.floor_id = f.id
               LEFT JOIN hosts h          ON h.id = p.host_id
               GROUP BY s.id
               ORDER BY s.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


