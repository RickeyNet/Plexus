"""geolocation.py — Site, floor plan, and device placement API routes."""

from __future__ import annotations

import hashlib
import os
import re

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import routes.database as db
from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()

# ── Floor plan image storage ─────────────────────────────────────────────────
# Images are stored in a directory outside the web-served static tree and
# served via the /api/geo/floors/{id}/image endpoint to prevent path traversal.

_DEFAULT_IMAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "floor_plans",
)
_IMAGE_DIR = os.getenv("GEO_FLOOR_PLAN_DIR", _DEFAULT_IMAGE_DIR)

_ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}
_MAX_IMAGE_BYTES = 20 * 1024 * 1024  # 20 MB


# ── Pydantic models ───────────────────────────────────────────────────────────

class GeoSiteCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    address: str = ""
    lat: float | None = None
    lng: float | None = None


class GeoSiteUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    address: str | None = None
    lat: float | None = None
    lng: float | None = None


class GeoFloorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    floor_number: int = 0


class GeoFloorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    floor_number: int | None = None


class GeoPlacementUpsert(BaseModel):
    x_pct: float = Field(..., ge=0.0, le=1.0)
    y_pct: float = Field(..., ge=0.0, le=1.0)


# ── Overview ──────────────────────────────────────────────────────────────────

@router.get("/api/geo/overview")
async def geo_overview_api():
    return await db.get_geo_overview()


# ── Sites ─────────────────────────────────────────────────────────────────────

@router.get("/api/geo/sites")
async def list_geo_sites_api():
    return await db.list_geo_sites()


@router.post("/api/geo/sites", status_code=201)
async def create_geo_site_api(body: GeoSiteCreate, request: Request):
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"
    if body.lat is not None and not (-90 <= body.lat <= 90):
        raise HTTPException(400, "lat must be between -90 and 90")
    if body.lng is not None and not (-180 <= body.lng <= 180):
        raise HTTPException(400, "lng must be between -180 and 180")
    try:
        site = await db.create_geo_site(
            name=body.name,
            description=body.description,
            address=body.address,
            lat=body.lat,
            lng=body.lng,
            created_by=user,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    await _audit(request, "geo_site_create", f"Created site '{body.name}'")
    return site


@router.get("/api/geo/sites/{site_id}")
async def get_geo_site_api(site_id: int):
    site = await db.get_geo_site(site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    floors = await db.list_geo_floors(site_id)
    return {**site, "floors": floors}


@router.put("/api/geo/sites/{site_id}")
async def update_geo_site_api(site_id: int, body: GeoSiteUpdate, request: Request):
    existing = await db.get_geo_site(site_id)
    if not existing:
        raise HTTPException(404, "Site not found")
    if body.lat is not None and not (-90 <= body.lat <= 90):
        raise HTTPException(400, "lat must be between -90 and 90")
    if body.lng is not None and not (-180 <= body.lng <= 180):
        raise HTTPException(400, "lng must be between -180 and 180")
    updates = body.model_dump(exclude_none=True)
    try:
        site = await db.update_geo_site(site_id, **updates)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    await _audit(request, "geo_site_update", f"Updated site id={site_id}")
    return site


@router.delete("/api/geo/sites/{site_id}")
async def delete_geo_site_api(site_id: int, request: Request):
    existing = await db.get_geo_site(site_id)
    if not existing:
        raise HTTPException(404, "Site not found")
    # Clean up floor plan images for all floors in this site
    floors = await db.list_geo_floors(site_id)
    for floor in floors:
        _remove_floor_image(floor.get("image_filename"))
    await db.delete_geo_site(site_id)
    await _audit(request, "geo_site_delete", f"Deleted site '{existing.get('name')}'")
    return {"ok": True}


# ── Floors ────────────────────────────────────────────────────────────────────

@router.post("/api/geo/sites/{site_id}/floors", status_code=201)
async def create_geo_floor_api(site_id: int, body: GeoFloorCreate, request: Request):
    site = await db.get_geo_site(site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    try:
        floor = await db.create_geo_floor(
            site_id=site_id,
            name=body.name,
            floor_number=body.floor_number,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    await _audit(request, "geo_floor_create", f"Created floor '{body.name}' in site id={site_id}")
    return floor


@router.get("/api/geo/floors/{floor_id}")
async def get_geo_floor_api(floor_id: int):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    return floor


@router.put("/api/geo/floors/{floor_id}")
async def update_geo_floor_api(floor_id: int, body: GeoFloorUpdate, request: Request):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    updates = body.model_dump(exclude_none=True)
    try:
        updated = await db.update_geo_floor(floor_id, **updates)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    await _audit(request, "geo_floor_update", f"Updated floor id={floor_id}")
    return updated


@router.delete("/api/geo/floors/{floor_id}")
async def delete_geo_floor_api(floor_id: int, request: Request):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    _remove_floor_image(floor.get("image_filename"))
    await db.delete_geo_floor(floor_id)
    await _audit(request, "geo_floor_delete", f"Deleted floor id={floor_id}")
    return {"ok": True}


# ── Floor plan image upload / download ───────────────────────────────────────

def _floor_image_path(filename: str) -> str:
    """Return the safe absolute path for a floor plan image filename."""
    safe = os.path.basename(filename)
    return os.path.realpath(os.path.join(_IMAGE_DIR, safe))


def _remove_floor_image(filename: str | None) -> None:
    if not filename:
        return
    try:
        path = _floor_image_path(filename)
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


@router.post("/api/geo/floors/{floor_id}/image")
async def upload_floor_image_api(
    floor_id: int,
    request: Request,
    file: UploadFile = File(...),
):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")

    content_type = (file.content_type or "").split(";")[0].strip()
    if content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(400, "Unsupported image type — use JPEG, PNG, GIF, WebP, or SVG")

    # Derive a safe extension from content type
    _ext_map = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "image/svg+xml": ".svg",
    }
    ext = _ext_map.get(content_type, ".bin")

    os.makedirs(_IMAGE_DIR, exist_ok=True)

    # Read, enforce size limit, and compute hash for filename uniqueness
    chunks = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_IMAGE_BYTES:
            raise HTTPException(413, "Image exceeds 20 MB limit")
        chunks.append(chunk)
    data = b"".join(chunks)

    digest = hashlib.sha256(data).hexdigest()[:16]
    filename = f"floor_{floor_id}_{digest}{ext}"
    dest = _floor_image_path(filename)

    # Confirm path is confined to the image directory
    if not dest.startswith(os.path.realpath(_IMAGE_DIR)):
        raise HTTPException(400, "Invalid filename")

    # Remove old image if different
    old_filename = floor.get("image_filename")
    if old_filename and old_filename != filename:
        _remove_floor_image(old_filename)

    with open(dest, "wb") as f:
        f.write(data)

    await db.update_geo_floor(floor_id, image_filename=filename)
    await _audit(request, "geo_floor_image_upload", f"Uploaded floor plan for floor id={floor_id}")
    return {"ok": True, "filename": filename}


@router.get("/api/geo/floors/{floor_id}/image")
async def get_floor_image_api(floor_id: int):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    filename = floor.get("image_filename")
    if not filename:
        raise HTTPException(404, "No floor plan image uploaded")
    path = _floor_image_path(filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Floor plan image file not found")

    # Derive media type from extension
    ext = os.path.splitext(filename)[1].lower()
    _media_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
    }
    media_type = _media_map.get(ext, "application/octet-stream")
    return FileResponse(path, media_type=media_type)


# ── Device placements ─────────────────────────────────────────────────────────

@router.get("/api/geo/floors/{floor_id}/placements")
async def get_floor_placements_api(floor_id: int):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    return await db.get_geo_placements(floor_id)


@router.put("/api/geo/floors/{floor_id}/placements/{host_id}")
async def upsert_floor_placement_api(
    floor_id: int,
    host_id: int,
    body: GeoPlacementUpsert,
    request: Request,
):
    floor = await db.get_geo_floor(floor_id)
    if not floor:
        raise HTTPException(404, "Floor not found")
    host = await db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    placement = await db.upsert_geo_placement(floor_id, host_id, body.x_pct, body.y_pct)
    await _audit(request, "geo_placement_upsert",
                 f"Placed host id={host_id} on floor id={floor_id} at ({body.x_pct:.3f}, {body.y_pct:.3f})")
    return placement


@router.delete("/api/geo/floors/{floor_id}/placements/{host_id}")
async def delete_floor_placement_api(floor_id: int, host_id: int, request: Request):
    removed = await db.delete_geo_placement(floor_id, host_id)
    if not removed:
        raise HTTPException(404, "Placement not found")
    await _audit(request, "geo_placement_delete",
                 f"Removed host id={host_id} from floor id={floor_id}")
    return {"ok": True}
