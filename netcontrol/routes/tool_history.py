"""Tool history: the last runs each user made of Path Mode (Topology), the
Reachability sweep and Summarize (Network Tools), so one can be opened
again with a click.

The page sends a run's inputs as ``data`` (kept as sent) and optionally a
``key`` saying what makes two runs the same; without one the inputs
themselves are the key. Running the same one again moves it to the top. The
server keeps the newest ``TOOL_HISTORY_LIMIT`` per user and kind
(``routes.db.tool_history``).

Endpoints (the ``topology`` feature; every user sees only their own;
``kind`` is ``path``, ``reachability`` or ``summarize``):

- ``GET /api/topology/history/{kind}``: the runs, newest first.
- ``POST /api/topology/history/{kind}``: record one (``data``, ``key``).
- ``DELETE /api/topology/history/{kind}/{entry_id}``: forget one.
- ``DELETE /api/topology/history/{kind}``: forget them all.
"""

from __future__ import annotations

import json
from typing import Literal

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from netcontrol.routes.shared import _session_user_id

router = APIRouter(prefix="/api/topology/history")

ToolKind = Literal["path", "reachability", "summarize"]

# A run's inputs: Path Mode picks carry their subnet records, a summary its
# address list. A larger run (a very long address list) is not kept.
MAX_DATA_CHARS = 64_000


class ToolHistoryEntry(BaseModel):
    data: dict
    key: str = Field(default="", max_length=2000)

    @field_validator("data")
    @classmethod
    def _small(cls, data: dict) -> dict:
        if not data:
            raise ValueError("data is empty")
        if len(json.dumps(data)) > MAX_DATA_CHARS:
            raise ValueError(f"data is over {MAX_DATA_CHARS} characters")
        return data


def signature(entry: ToolHistoryEntry) -> str:
    """What makes two runs the same: the page's key, else the inputs."""
    return entry.key or json.dumps(entry.data, sort_keys=True, separators=(",", ":"))


@router.get("/{kind}")
async def list_tool_history(kind: ToolKind, request: Request) -> dict:
    return {"entries": await db.list_tool_history(_session_user_id(request), kind), "limit": db.TOOL_HISTORY_LIMIT}


@router.post("/{kind}")
async def record_tool_history(kind: ToolKind, payload: ToolHistoryEntry, request: Request) -> dict:
    return await db.record_tool_history(_session_user_id(request), kind, signature(payload), payload.data)


@router.delete("/{kind}/{entry_id}")
async def delete_tool_history(kind: ToolKind, entry_id: int, request: Request) -> dict:
    if not await db.delete_tool_history(_session_user_id(request), kind, entry_id):
        raise HTTPException(status_code=404, detail="No such entry in your history")
    return {"ok": True}


@router.delete("/{kind}")
async def clear_tool_history(kind: ToolKind, request: Request) -> dict:
    return {"ok": True, "removed": await db.clear_tool_history(_session_user_id(request), kind)}
