"""software_eol.py -- Software end of life per release series.

What runs what:

* The entries (``/api/software/eol-entries``) give one release series of
  one platform its end-of-life date. Entered by hand or imported as JSON;
  for OPNsense an entry overrides the built-in estimate
  (``netcontrol.integrations.software.lifecycle``).
* :func:`sync_lifecycle_advisories` runs in every software refresh (on the
  schedule, after each topology collection, on **Refresh**) and after
  every entry change: each series that is ending or end of life and runs
  on a tracked device becomes a generated advisory of the source
  ``lifecycle`` (``lifecycle:<platform>:<series>``), which the tracker
  matches, alerts and notifies on like any other advisory; a series that
  is supported again, or that no device runs any more, has its advisory
  withdrawn (no affected versions), which resolves its alerts.
* :func:`device_statuses` gives the status of every tracked device for the
  overview, the MCP tools and the OPNsense node details.

Permissions: under the software router, so the ``software`` feature reads
and ``software.write`` changes the entries, as the advisories; a caller
limited to inventory groups reads them (a shared catalogue) and cannot
change them.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from netcontrol.circuits import clean_date, clean_url
from netcontrol.custom_fields import CustomFieldError
from netcontrol.integrations.software.lifecycle import (
    ADVISORY_SOURCE,
    WARN_DAYS_SETTING,
    fleet_statuses,
    lifecycle_advisories,
    series_spec,
    warn_days_setting,
)
from netcontrol.integrations.software.versions import PLATFORMS, validate_version_spec
from netcontrol.object_scope import require_model_write, scope_exempt, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.software")

_MAX_IMPORT = 1000
_SERIES_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._()-")
_NOT_FOUND = "End-of-life entry not found"


class EolEntryBody(BaseModel):
    platform: str = Field(min_length=1, max_length=40)
    series: str = Field(min_length=1, max_length=40)
    eol_date: str = Field(default="", max_length=20)
    release_date: str = Field(default="", max_length=20)
    url: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=2000)
    enabled: bool = True


class EolImportBody(BaseModel):
    entries: list[EolEntryBody] = Field(max_length=_MAX_IMPORT)


def _today() -> date:
    return datetime.now(UTC).date()


def _clean_entry(body: EolEntryBody, source: str = "manual") -> dict[str, Any]:
    platform = body.platform.strip().lower()
    if platform not in PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unknown platform {platform!r}")
    series = body.series.strip()
    if not set(series) <= _SERIES_CHARS or validate_version_spec(series_spec(series)):
        raise HTTPException(status_code=400, detail=f"Series {series!r} is not a version such as 25.1 or 17.9")
    try:
        eol_date = clean_date(body.eol_date, "End-of-life date")
        release_date = clean_date(body.release_date, "Release date")
        url = clean_url(body.url, "URL")
    except CustomFieldError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not eol_date:
        raise HTTPException(status_code=400, detail="End-of-life date is required")
    if release_date and release_date > eol_date:
        raise HTTPException(status_code=400, detail="Release date must not be after the end-of-life date")
    return {
        "platform": platform,
        "series": series,
        "eol_date": eol_date,
        "release_date": release_date,
        "url": url,
        "notes": body.notes.strip(),
        "source": source,
        "enabled": body.enabled,
    }


# ── Status ───────────────────────────────────────────────────────────────────


async def _warn_days() -> int:
    return warn_days_setting((await db.get_software_settings()).get(WARN_DAYS_SETTING))


async def device_statuses(devices: list[dict], *, all_devices: list[dict] | None = None) -> dict[str, dict]:
    """``device_key -> status`` of ``devices`` on today's date.
    ``all_devices``: the whole tracked set when ``devices`` is part of it
    (one firewall's report of a newer major series counts for its series)."""
    statuses = fleet_statuses(
        all_devices if all_devices is not None else devices,
        await db.list_software_eol_entries(),
        _today(),
        warn_days=await _warn_days(),
    )
    return {d["device_key"]: statuses[d["device_key"]] for d in devices if d.get("device_key") in statuses}


async def sync_lifecycle_advisories() -> dict[str, int]:
    """Bring the generated ``lifecycle`` advisories up to date with the
    tracked devices and the entries. An administrator's enabled switch and
    severity are kept; a severity nobody edited follows the status (low
    while ending, high once end of life)."""
    devices = await db.list_software_versions()
    found = lifecycle_advisories(devices, await db.list_software_eol_entries(), _today(), warn_days=await _warn_days())
    current = {a["advisory_id"] for a in found}
    upserted = withdrawn = 0
    for advisory in found:
        advisory.pop("status")
        existing = await db.get_software_advisory(advisory["advisory_id"])
        if existing:
            advisory["enabled"] = existing.get("enabled", True)
        # The upsert keeps a severity an administrator set.
        await db.upsert_software_advisory(advisory)
        upserted += 1
    for existing in await db.list_software_advisories():
        if existing.get("source") != ADVISORY_SOURCE or existing["advisory_id"] in current:
            continue
        if existing.get("affected_versions"):
            # Kept with no affected versions, as an OPNsense audit finding no
            # firewall reports: its alerts resolve, its settings stay.
            await db.upsert_software_advisory({**existing, "affected_versions": []})
            withdrawn += 1
    return {"upserted": upserted, "withdrawn": withdrawn}


async def _after_change() -> dict[str, Any]:
    # Imported here: the software routes include this router.
    from netcontrol.routes.software import evaluate_software_alerts

    await sync_lifecycle_advisories()
    return await evaluate_software_alerts(notify=True)


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/api/software/eol-entries")
@scope_exempt("the shared end-of-life catalogue: no host or inventory group data")
async def list_eol_entries_api():
    return {"entries": await db.list_software_eol_entries(), "warn_days": await _warn_days()}


@router.post("/api/software/eol-entries", status_code=201)
@scoped("catalog")
async def create_eol_entry_api(body: EolEntryBody, request: Request):
    await require_model_write(request)
    entry = _clean_entry(body)
    if await db.find_software_eol_entry(entry["platform"], entry["series"]):
        raise HTTPException(status_code=409, detail="An entry for this platform and series already exists")
    user = _session_user(request)
    stored = await db.create_software_eol_entry(entry, user)
    alerts = await _after_change()
    await _audit(
        "software",
        "eol_entry_create",
        user=user,
        detail=f"platform={entry['platform']} series={entry['series']} eol={entry['eol_date']}",
        correlation_id=_corr_id(request),
    )
    return {"entry": stored, "alerts": alerts}


@router.put("/api/software/eol-entries/{entry_id}")
@scoped("catalog")
async def update_eol_entry_api(entry_id: int, body: EolEntryBody, request: Request):
    await require_model_write(request)
    existing = await db.get_software_eol_entry(entry_id)
    if not existing:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    entry = _clean_entry(body, existing.get("source") or "manual")
    other = await db.find_software_eol_entry(entry["platform"], entry["series"])
    if other and other["id"] != entry_id:
        raise HTTPException(status_code=409, detail="An entry for this platform and series already exists")
    user = _session_user(request)
    stored = await db.update_software_eol_entry(entry_id, entry, user)
    alerts = await _after_change()
    await _audit(
        "software",
        "eol_entry_update",
        user=user,
        detail=f"id={entry_id} platform={entry['platform']} series={entry['series']} eol={entry['eol_date']}",
        correlation_id=_corr_id(request),
    )
    return {"entry": stored, "alerts": alerts}


@router.delete("/api/software/eol-entries/{entry_id}")
@scoped("catalog")
async def delete_eol_entry_api(entry_id: int, request: Request):
    await require_model_write(request)
    existing = await db.get_software_eol_entry(entry_id)
    if not existing or not await db.delete_software_eol_entry(entry_id):
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    alerts = await _after_change()
    await _audit(
        "software",
        "eol_entry_delete",
        user=_session_user(request),
        detail=f"id={entry_id} platform={existing['platform']} series={existing['series']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "alerts": alerts}


@router.post("/api/software/eol-entries/import")
@scoped("catalog")
async def import_eol_entries_api(body: EolImportBody, request: Request):
    """Create or replace entries by platform and series (source ``import``)."""
    await require_model_write(request)
    if not body.entries:
        raise HTTPException(status_code=400, detail="No entries to import")
    cleaned = [_clean_entry(item, "import") for item in body.entries]
    user = _session_user(request)
    for entry in cleaned:
        existing = await db.find_software_eol_entry(entry["platform"], entry["series"])
        if existing:
            await db.update_software_eol_entry(existing["id"], entry, user)
        else:
            await db.create_software_eol_entry(entry, user)
    alerts = await _after_change()
    await _audit(
        "software",
        "eol_entry_import",
        user=user,
        detail=f"count={len(cleaned)}",
        correlation_id=_corr_id(request),
    )
    return {"imported": len(cleaned), "alerts": alerts}
