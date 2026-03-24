"""
reporting.py -- Report generation and CSV export for availability,
compliance, and interface utilization data.
"""

import csv
import io
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import routes.database as db
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.reporting")


class ReportDefinitionCreate(BaseModel):
    name: str
    report_type: str = "availability"
    parameters_json: str = "{}"
    schedule: str = ""


# ── Report Definitions CRUD ──────────────────────────────────────────────────


@router.get("/api/reports")
async def list_reports():
    return {"reports": await db.list_report_definitions()}


@router.post("/api/reports", status_code=201)
async def create_report(payload: ReportDefinitionCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    report = await db.create_report_definition(
        name=payload.name,
        report_type=payload.report_type,
        parameters_json=payload.parameters_json,
        schedule=payload.schedule,
        created_by=owner,
    )
    LOGGER.info("Report created: %s (id=%s)", payload.name, report.get("id"))
    return report


@router.delete("/api/reports/{report_id}")
async def delete_report(report_id: int):
    deleted = await db.delete_report_definition(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted"}


@router.get("/api/reports/runs")
async def list_report_runs(
    report_id: int | None = Query(default=None),
    limit: int = Query(default=50),
):
    return {"runs": await db.get_report_runs(report_id, limit)}


# ── Report Generation ────────────────────────────────────────────────────────


@router.post("/api/reports/generate")
async def generate_report(body: dict, request: Request):
    """Generate a report and return results as JSON."""
    report_type = body.get("report_type", "availability")
    params = body.get("parameters", {})
    group_id = params.get("group_id")
    days = params.get("days", 30)
    host_id = params.get("host_id")

    # Create a run record
    run = await db.create_report_run(
        report_id=body.get("report_id"),
        report_type=report_type,
        parameters_json=json.dumps(params),
    )

    try:
        if report_type == "availability":
            rows = await db.generate_availability_report_data(group_id, days)
        elif report_type == "compliance":
            rows = await db.generate_compliance_report_data(group_id)
        elif report_type == "interface":
            rows = await db.generate_interface_report_data(host_id, group_id, days)
        else:
            await db.complete_report_run(run["id"], "{}", 0, "error")
            raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}")

        await db.complete_report_run(
            run["id"], json.dumps(rows, default=str), len(rows), "completed"
        )
        return {"run_id": run["id"], "report_type": report_type, "row_count": len(rows), "rows": rows}
    except HTTPException:
        raise
    except Exception as exc:
        await db.complete_report_run(run["id"], json.dumps({"error": str(exc)}), 0, "error")
        raise HTTPException(status_code=500, detail=str(exc))


# ── CSV Export ───────────────────────────────────────────────────────────────


def _rows_to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@router.get("/api/reports/export/availability")
async def export_availability_csv(
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
):
    rows = await db.generate_availability_report_data(group_id, days)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=availability_report.csv"},
    )


@router.get("/api/reports/export/compliance")
async def export_compliance_csv(
    group_id: int | None = Query(default=None),
):
    rows = await db.generate_compliance_report_data(group_id)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance_report.csv"},
    )


@router.get("/api/reports/export/interface")
async def export_interface_csv(
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    days: int = Query(default=1),
):
    rows = await db.generate_interface_report_data(host_id, group_id, days)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=interface_report.csv"},
    )


@router.get("/api/reports/runs/{run_id}")
async def get_report_run_detail(run_id: int):
    run = await db.get_report_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Report run not found")
    return run


@router.get("/api/reports/runs/{run_id}/csv")
async def export_report_run_csv(run_id: int):
    """Export a previously-generated report run as CSV."""
    run = await db.get_report_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Report run not found")
    try:
        rows = json.loads(run.get("result_json", "[]"))
    except Exception:
        rows = []
    if not isinstance(rows, list):
        rows = []
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_{run_id}.csv"},
    )


# ── Custom OID Profiles Routes ──────────────────────────────────────────────


class OidProfileCreate(BaseModel):
    name: str
    vendor: str = ""
    device_type: str = ""
    description: str = ""
    oids_json: str = "[]"
    is_default: int = 0


class OidProfileUpdate(BaseModel):
    name: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    description: str | None = None
    oids_json: str | None = None
    is_default: int | None = None


@router.get("/api/oid-profiles")
async def list_oid_profiles(vendor: str | None = Query(default=None)):
    return {"profiles": await db.get_custom_oid_profiles(vendor)}


@router.get("/api/oid-profiles/{profile_id}")
async def get_oid_profile(profile_id: int):
    profile = await db.get_custom_oid_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return profile


@router.post("/api/oid-profiles", status_code=201)
async def create_oid_profile(payload: OidProfileCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    profile = await db.create_custom_oid_profile(
        name=payload.name,
        vendor=payload.vendor,
        device_type=payload.device_type,
        description=payload.description,
        oids_json=payload.oids_json,
        is_default=payload.is_default,
        created_by=owner,
    )
    return profile


@router.put("/api/oid-profiles/{profile_id}")
async def update_oid_profile(profile_id: int, payload: OidProfileUpdate):
    updated = await db.update_custom_oid_profile(
        profile_id,
        name=payload.name,
        vendor=payload.vendor,
        device_type=payload.device_type,
        description=payload.description,
        oids_json=payload.oids_json,
        is_default=payload.is_default,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return updated


@router.delete("/api/oid-profiles/{profile_id}")
async def delete_oid_profile(profile_id: int):
    deleted = await db.delete_custom_oid_profile(profile_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return {"status": "deleted"}
