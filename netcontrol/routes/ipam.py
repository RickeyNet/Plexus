"""ipam.py -- Lightweight IP address management overview routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

import routes.database as db

router = APIRouter()


@router.get("/api/ipam/overview")
async def ipam_overview_api(
    group_id: int | None = Query(default=None),
    include_cloud: bool = Query(default=True),
):
    if group_id is not None and group_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid inventory group id")
    return await db.get_ipam_overview(group_id=group_id, include_cloud=include_cloud)