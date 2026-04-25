"""
Migration 0020: add geolocation and floor plan mapping tables.

Adds:
  - geo_sites      (physical sites with lat/lng)
  - geo_floors     (floors/areas within a site, optional floor plan image)
  - geo_placements (device pin positions on a floor plan)
"""

from __future__ import annotations

import os

VERSION = 20
DESCRIPTION = "Add geolocation and floor plan mapping tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS geo_sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    address     TEXT    NOT NULL DEFAULT '',
    lat         REAL    DEFAULT NULL,
    lng         REAL    DEFAULT NULL,
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS geo_floors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES geo_sites(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    floor_number    INTEGER NOT NULL DEFAULT 0,
    image_filename  TEXT    DEFAULT NULL,
    image_width     INTEGER NOT NULL DEFAULT 1200,
    image_height    INTEGER NOT NULL DEFAULT 800,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(site_id, name)
);

CREATE TABLE IF NOT EXISTS geo_placements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    floor_id   INTEGER NOT NULL REFERENCES geo_floors(id) ON DELETE CASCADE,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    x_pct      REAL    NOT NULL DEFAULT 0.5,
    y_pct      REAL    NOT NULL DEFAULT 0.5,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(floor_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_geo_floors_site
    ON geo_floors(site_id);
CREATE INDEX IF NOT EXISTS idx_geo_placements_floor
    ON geo_placements(floor_id);
CREATE INDEX IF NOT EXISTS idx_geo_placements_host
    ON geo_placements(host_id);
"""

_POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS geo_sites (
    id          SERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    address     TEXT    NOT NULL DEFAULT '',
    lat         DOUBLE PRECISION DEFAULT NULL,
    lng         DOUBLE PRECISION DEFAULT NULL,
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (NOW()::TEXT),
    updated_at  TEXT    NOT NULL DEFAULT (NOW()::TEXT)
);

CREATE TABLE IF NOT EXISTS geo_floors (
    id              SERIAL PRIMARY KEY,
    site_id         INTEGER NOT NULL REFERENCES geo_sites(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    floor_number    INTEGER NOT NULL DEFAULT 0,
    image_filename  TEXT    DEFAULT NULL,
    image_width     INTEGER NOT NULL DEFAULT 1200,
    image_height    INTEGER NOT NULL DEFAULT 800,
    created_at      TEXT    NOT NULL DEFAULT (NOW()::TEXT),
    updated_at      TEXT    NOT NULL DEFAULT (NOW()::TEXT),
    UNIQUE(site_id, name)
);

CREATE TABLE IF NOT EXISTS geo_placements (
    id         SERIAL PRIMARY KEY,
    floor_id   INTEGER NOT NULL REFERENCES geo_floors(id) ON DELETE CASCADE,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    x_pct      DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    y_pct      DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    created_at TEXT    NOT NULL DEFAULT (NOW()::TEXT),
    updated_at TEXT    NOT NULL DEFAULT (NOW()::TEXT),
    UNIQUE(floor_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_geo_floors_site
    ON geo_floors(site_id);
CREATE INDEX IF NOT EXISTS idx_geo_placements_floor
    ON geo_placements(floor_id);
CREATE INDEX IF NOT EXISTS idx_geo_placements_host
    ON geo_placements(host_id);
"""


async def _up_sqlite(db) -> None:
    await db.executescript(_SQLITE_DDL)
    await db.commit()


async def _up_postgres(db) -> None:
    for stmt in _POSTGRES_DDL.strip().split(";"):
        stmt = stmt.strip()
        if stmt:
            await db.execute(stmt)
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
