"""Example Plexus plugin: a spare-parts list.

Shows every hook of the plugin framework (docs/plugin-development.md):

- a table created by the plugin's own migration (``plugin_example_spares``);
- a router, mounted by Plexus at ``/api/plugins/example/`` behind the
  ``plugin:example`` feature (``plugin:example.write`` to add a spare);
- a sidebar entry and a declarative page with a form and a table;
- startup and shutdown hooks and one background task.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import routes.database as db
from fastapi import APIRouter, Request
from netcontrol.plugins import PlexusPlugin
from netcontrol.routes.shared import _session_user
from pydantic import BaseModel, Field

router = APIRouter()

# Set by the startup hook, cleared by shutdown; the tests read it.
STATE: dict = {"started": False, "ticks": 0}


class SpareIn(BaseModel):
    part: str = Field(min_length=1, max_length=80)
    site: str = Field(default="", max_length=80)
    quantity: int = Field(default=1, ge=0, le=100000)


@router.get("/spares")
async def list_spares() -> list[dict]:
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute(
            "SELECT id, part, site, quantity, created_by, created_at FROM plugin_example_spares ORDER BY part, id"
        )
        return db.rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


@router.post("/spares", status_code=201)
async def add_spare(body: SpareIn, request: Request) -> dict:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    user = _session_user(request)
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "INSERT INTO plugin_example_spares (part, site, quantity, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?) RETURNING id",
            (body.part, body.site, body.quantity, user, now),
        )
        await conn.commit()
        spare_id = int(cursor.lastrowid)
    finally:
        await conn.close()
    return {"id": spare_id, **body.model_dump(), "created_by": user, "created_at": now}


async def _startup() -> None:
    STATE["started"] = True


async def _shutdown() -> None:
    STATE["started"] = False


async def _tick() -> None:
    while True:
        STATE["ticks"] += 1
        await asyncio.sleep(3600)


plugin = PlexusPlugin(
    name="example",
    version="0.1.0",
    label="Spare Parts",
    description="Example plugin: a list of spare parts kept per site.",
    min_plexus_version="1.0.0",
    router=router,
    migrations="plexus_plugin_example.migrations",
    navigation=[{"label": "Spare Parts", "page": "spares"}],
    pages=[
        {
            "id": "spares",
            "title": "Spare Parts",
            "description": "Spare hardware on hand at each site.",
            "blocks": [
                {
                    "type": "form",
                    "id": "add-spare",
                    "title": "Add a spare",
                    "submit": "spares",
                    "submit_label": "Add spare",
                    "fields": [
                        {"name": "part", "label": "Part", "required": True},
                        {"name": "site", "label": "Site"},
                        {"name": "quantity", "label": "Quantity", "type": "number"},
                    ],
                    "refreshes": ["spares-table"],
                },
                {
                    "type": "table",
                    "id": "spares-table",
                    "title": "On hand",
                    "source": "spares",
                    "columns": [
                        {"key": "part", "label": "Part"},
                        {"key": "site", "label": "Site"},
                        {"key": "quantity", "label": "Quantity"},
                        {"key": "created_by", "label": "Added by"},
                    ],
                    "empty_text": "No spares recorded yet.",
                },
            ],
        }
    ],
    startup=_startup,
    shutdown=_shutdown,
    background_tasks=[_tick],
)
