"""
meraki_compliance.py -- Compliance scans of Meraki organizations.

A compliance profile may carry rules of type ``meraki`` that name a check
from ``netcontrol.integrations.meraki.compliance`` (the Meraki equivalents of
DHCP snooping, port security, BPDU guard, storm control, IPS/AMP, SSID
security, dashboard login security, ...). Those rules are evaluated against
the Dashboard API configuration of an organization registered on the
Topology page, with its stored API key, read-only - never against an
inventory host. This module provides:

  - the check catalog for the profile editor
  - the Meraki organizations a profile can be assigned to
  - assignments (profile x organization, on a schedule) and their CRUD
  - on-demand scans as background jobs with pollable progress
  - stored results per target (organization / network / switch) and the
    latest status per target

Mounted under the ``compliance`` feature next to the host compliance routes.
The scheduled loop in ``compliance.py`` calls :func:`run_due_assignments`.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.integrations.meraki.client import DEFAULT_BASE_URL, MerakiApiError, MerakiClient
from netcontrol.integrations.meraki.collector import sanitize_options
from netcontrol.integrations.meraki.compliance import (
    CATEGORIES,
    CHECKS,
    build_sample_compliance_raw,
    catalog,
    collect_compliance_data,
    evaluate_profile,
    is_meraki_rule,
    meraki_rules,
    rule_template,
    summarise_results,
)
from netcontrol.routes import background_jobs
from netcontrol.routes.shared import _audit, _corr_id, _get_session, supervise_task
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

router = APIRouter()
LOGGER = configure_logging("plexus.compliance.meraki")

_JOB_KIND = "meraki-compliance-scan"
# A scheduled scan of a large organization is bounded so one stuck
# collection cannot hold the compliance loop forever.
_SCHEDULED_SCAN_TIMEOUT_SECONDS = 1800
# org_ref -> job_id of the scan currently running for that organization.
_running_scans: dict[int, str] = {}


# ── Models ────────────────────────────────────────────────────────────────────


class MerakiAssignmentCreate(BaseModel):
    profile_id: int
    org_ref: int
    interval_seconds: int = 86400


class MerakiAssignmentUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None


class MerakiScanRequest(BaseModel):
    profile_id: int
    org_ref: int


# ── Helpers ───────────────────────────────────────────────────────────────────


def _session_user(request: Request) -> str:
    session = _get_session(request)
    return session["user"] if session else ""


def _profile_rules(profile: dict) -> list:
    rules = profile.get("rules") or "[]"
    if isinstance(rules, str):
        try:
            rules = json.loads(rules)
        except json.JSONDecodeError:
            return []
    return rules if isinstance(rules, list) else []


def validate_meraki_rules(rules: Any) -> str | None:
    """Error text when a ``meraki`` rule is malformed, else ``None``."""
    for rule in rules if isinstance(rules, list) else []:
        if not is_meraki_rule(rule):
            continue
        check_id = str(rule.get("check") or "")
        if check_id not in CHECKS:
            return f"Unknown Meraki check '{check_id}'"
        params = rule.get("params")
        if params is not None and not isinstance(params, dict):
            return f"Meraki rule '{rule.get('name') or check_id}': params must be an object"
    return None


def _is_meraki_org(org: dict) -> bool:
    return str(org.get("provider") or "meraki") == "meraki"


def _is_sample_org(org: dict) -> bool:
    return str(org.get("org_id") or "") == "sample" and not org.get("has_api_key")


def _clamp_interval(seconds: int) -> int:
    return max(state.COMPLIANCE_ASSIGNMENT_MIN_INTERVAL, min(state.COMPLIANCE_ASSIGNMENT_MAX_INTERVAL, int(seconds)))


async def _get_org_or_404(org_ref: int) -> dict:
    org = await db.get_meraki_org(org_ref)
    if not org or not _is_meraki_org(org):
        raise HTTPException(status_code=404, detail="Meraki organization not found")
    return org


async def _get_profile_or_404(profile_id: int) -> dict:
    profile = await db.get_compliance_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    return profile


def _api_error_message(exc: MerakiApiError) -> str:
    if exc.status_code in (401, 403):
        return "The Meraki API key was rejected or lacks access to this organization"
    if exc.status_code == 404:
        return "Organization not found with this API key"
    if exc.status_code == 429:
        return "Meraki API rate limit exceeded; try again later"
    if exc.status_code and exc.status_code >= 500:
        return f"Meraki API error (HTTP {exc.status_code})"
    return "Could not reach the Meraki API"


# ── Scan runner ───────────────────────────────────────────────────────────────


async def run_meraki_compliance_scan(
    org: dict,
    profile: dict,
    *,
    assignment_id: int | None = None,
    user: str = "",
    progress=None,
) -> dict[str, Any]:
    """Collect what the profile's Meraki rules need, evaluate, store.

    The demo organization (no API key) is evaluated against bundled sample
    configuration. Raises ``ValueError`` for a profile without Meraki rules or
    an organization without a key, ``MerakiApiError`` when the organization
    inventory cannot be read.
    """
    rules = meraki_rules(_profile_rules(profile))
    if not rules:
        raise ValueError('This profile has no Meraki rules (type "meraki")')
    started = time.monotonic()

    def report(fields: dict) -> None:
        if progress is not None:
            progress(fields)

    if _is_sample_org(org):
        report({"phase": "sample"})
        raw = build_sample_compliance_raw()
    else:
        api_key = await db.get_meraki_org_api_key(org["id"])
        if not api_key:
            raise ValueError("No API key is stored for this organization")
        options = sanitize_options(org.get("options"))
        async with MerakiClient(
            api_key,
            base_url=org.get("base_url") or DEFAULT_BASE_URL,
            max_concurrency=options["max_concurrency"],
            requests_per_second=options["requests_per_second"],
        ) as client:
            from netcontrol.routes.meraki_topology import _resolve_org_id

            org_id = await _resolve_org_id(client, org)
            raw = await collect_compliance_data(client, org_id, rules, options, report)

    report({"phase": "evaluating"})
    results = evaluate_profile(rules, raw)
    counts = summarise_results(results)
    scan_id = uuid.uuid4().hex
    report({"phase": "saving"})
    await db.store_meraki_compliance_results(
        scan_id=scan_id,
        assignment_id=assignment_id,
        profile_id=profile["id"],
        org_ref=org["id"],
        results=results,
    )
    warnings = len(raw.get("errors") or [])
    status = "non-compliant" if counts["non_compliant"] else ("error" if counts["errors"] else "compliant")
    message = f"{counts['targets']} targets, {counts['non_compliant']} non-compliant, {counts['errors']} unreadable" + (
        f", {warnings} collection warning(s)" if warnings else ""
    )
    if assignment_id is not None:
        await db.record_meraki_compliance_assignment_scan(assignment_id, status, message)
    await _audit(
        "compliance",
        "meraki.scan",
        user=user,
        detail=f"org={org['name']} profile={profile['name']} {message}",
    )
    increment_metric("compliance.meraki.scan.success")
    return {
        "scan_id": scan_id,
        "org_ref": org["id"],
        "org_name": org["name"],
        "profile_id": profile["id"],
        "profile_name": profile["name"],
        "status": status,
        "message": message,
        "collection_warnings": warnings,
        "duration_seconds": round(time.monotonic() - started, 1),
        **counts,
    }


async def _run_scan_job(job_id: str, org: dict, profile: dict, assignment_id: int | None, user: str) -> None:
    def progress(fields: dict) -> None:
        background_jobs.update_progress(job_id, **fields)

    error: str | None = None
    try:
        result = await run_meraki_compliance_scan(
            org, profile, assignment_id=assignment_id, user=user, progress=progress
        )
        background_jobs.finish_job(job_id, "partial" if result["collection_warnings"] else "completed", result=result)
        return
    except MerakiApiError as exc:
        error = _api_error_message(exc)
        LOGGER.warning("meraki compliance: scan failed for org %s: %s", org["name"], redact_value(str(exc)))
    except ValueError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 - job must always reach a terminal state
        error = "Meraki compliance scan failed; see the server log for details"
        LOGGER.exception("meraki compliance: scan crashed for org %s: %s", org["name"], type(exc).__name__)
    finally:
        _running_scans.pop(org["id"], None)
    increment_metric("compliance.meraki.scan.failed")
    if assignment_id is not None:
        try:
            await db.record_meraki_compliance_assignment_scan(assignment_id, "failed", error or "")
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("meraki compliance: could not record failed scan: %s", type(exc).__name__)
    background_jobs.finish_job(job_id, "failed", error=error)


def _start_scan(org: dict, profile: dict, assignment_id: int | None, user: str) -> dict:
    if not meraki_rules(_profile_rules(profile)):
        raise HTTPException(status_code=400, detail='This profile has no Meraki rules (type "meraki")')
    if not org.get("has_api_key") and not _is_sample_org(org):
        raise HTTPException(status_code=400, detail="No API key is stored for this organization")
    # Check-then-set with no await in between: atomic under asyncio.
    if org["id"] in _running_scans:
        raise HTTPException(status_code=409, detail="A compliance scan is already running for this organization")
    job = background_jobs.create_job(
        _JOB_KIND,
        {"phase": "starting", "org_ref": org["id"], "org_name": org["name"], "profile_id": profile["id"]},
    )
    _running_scans[org["id"]] = job["job_id"]
    supervise_task(
        asyncio.create_task(_run_scan_job(job["job_id"], org, profile, assignment_id, user)),
        "meraki-compliance-scan",
    )
    return {"job_id": job["job_id"], "status": "running"}


async def run_due_assignments() -> dict[str, int]:
    """Run every enabled Meraki assignment whose interval has elapsed.

    Called by the compliance loop. Assignments run one after another: they
    share an organization's API rate budget, and a scan is already
    concurrent inside. Never raises.
    """
    stats = {"assignments_run": 0, "targets_scanned": 0, "violations": 0, "errors": 0}
    try:
        due = await db.get_meraki_compliance_assignments_due()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("meraki compliance: could not list due assignments: %s", type(exc).__name__)
        return stats
    for assignment in due:
        org_ref = assignment["org_ref"]
        if org_ref in _running_scans:
            continue
        try:
            org = await db.get_meraki_org(org_ref)
            profile = await db.get_compliance_profile(assignment["profile_id"])
            if not org or not profile or not _is_meraki_org(org):
                stats["errors"] += 1
                continue
            if not org.get("has_api_key") and not _is_sample_org(org):
                await db.record_meraki_compliance_assignment_scan(assignment["id"], "failed", "No API key stored")
                stats["errors"] += 1
                continue
            _running_scans[org_ref] = "scheduled"
            try:
                result = await asyncio.wait_for(
                    run_meraki_compliance_scan(
                        org,
                        profile,
                        assignment_id=assignment["id"],
                        user=assignment.get("assigned_by") or "scheduler",
                    ),
                    timeout=_SCHEDULED_SCAN_TIMEOUT_SECONDS,
                )
            finally:
                _running_scans.pop(org_ref, None)
            stats["assignments_run"] += 1
            stats["targets_scanned"] += result["targets"]
            stats["violations"] += result["non_compliant"]
            stats["errors"] += result["errors"]
        except TimeoutError:
            stats["errors"] += 1
            await db.record_meraki_compliance_assignment_scan(assignment["id"], "failed", "Scan timed out")
            LOGGER.warning("meraki compliance: scheduled scan timed out for assignment %s", assignment["id"])
        except MerakiApiError as exc:
            stats["errors"] += 1
            await db.record_meraki_compliance_assignment_scan(assignment["id"], "failed", _api_error_message(exc))
            LOGGER.warning("meraki compliance: scheduled scan failed: %s", redact_value(str(exc)))
        except Exception as exc:  # noqa: BLE001 - one assignment must not stop the loop
            stats["errors"] += 1
            LOGGER.warning("meraki compliance: assignment %s failed: %s", assignment["id"], type(exc).__name__)
            try:
                await db.record_meraki_compliance_assignment_scan(assignment["id"], "failed", type(exc).__name__)
            except Exception:  # noqa: BLE001
                pass
    return stats


# ── Catalog and organizations ────────────────────────────────────────────────


@router.get("/api/compliance/meraki/checks")
async def list_meraki_checks_api():
    """The Meraki check catalog, with the rule JSON that selects each check."""
    checks = catalog()
    for item in checks:
        item["rule"] = rule_template(item["id"])
    return {"checks": checks, "categories": CATEGORIES}


@router.get("/api/compliance/meraki/orgs")
async def list_meraki_compliance_orgs_api():
    """Meraki organizations a profile can be scanned against (no credentials)."""
    orgs = []
    for org in await db.list_meraki_orgs():
        if not _is_meraki_org(org):
            continue
        orgs.append(
            {
                "id": org["id"],
                "name": org["name"],
                "org_id": org.get("org_id") or "",
                "has_api_key": bool(org.get("has_api_key")),
                "is_sample": _is_sample_org(org),
                "scanning": org["id"] in _running_scans,
                "last_build_at": org.get("last_build_at"),
            }
        )
    return orgs


# ── Assignments ──────────────────────────────────────────────────────────────


@router.get("/api/compliance/meraki/assignments")
async def list_meraki_assignments_api(
    profile_id: int | None = Query(default=None),
    org_ref: int | None = Query(default=None),
):
    items = await db.list_meraki_compliance_assignments(profile_id=profile_id, org_ref=org_ref)
    for item in items:
        item["scanning"] = item["org_ref"] in _running_scans
    return items


@router.post("/api/compliance/meraki/assignments", status_code=201)
async def create_meraki_assignment_api(body: MerakiAssignmentCreate, request: Request):
    profile = await _get_profile_or_404(body.profile_id)
    org = await _get_org_or_404(body.org_ref)
    if not meraki_rules(_profile_rules(profile)):
        raise HTTPException(status_code=400, detail='This profile has no Meraki rules (type "meraki")')
    user = _session_user(request)
    assignment_id = await db.create_meraki_compliance_assignment(
        body.profile_id,
        body.org_ref,
        interval_seconds=_clamp_interval(body.interval_seconds),
        assigned_by=user,
    )
    if assignment_id is None:
        raise HTTPException(status_code=409, detail="This profile is already assigned to that organization")
    await _audit(
        "compliance",
        "meraki.assignment.created",
        user=user,
        detail=f"assignment_id={assignment_id} profile={profile['name']} org={org['name']}",
        correlation_id=_corr_id(request),
    )
    return {"id": assignment_id}


@router.put("/api/compliance/meraki/assignments/{assignment_id}")
async def update_meraki_assignment_api(assignment_id: int, body: MerakiAssignmentUpdate, request: Request):
    assignment = await db.get_meraki_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    updates: dict[str, Any] = {}
    if body.enabled is not None:
        updates["enabled"] = 1 if body.enabled else 0
    if body.interval_seconds is not None:
        updates["interval_seconds"] = _clamp_interval(body.interval_seconds)
    await db.update_meraki_compliance_assignment(assignment_id, **updates)
    await _audit(
        "compliance",
        "meraki.assignment.updated",
        user=_session_user(request),
        detail=f"assignment_id={assignment_id} fields={list(updates)}",
        correlation_id=_corr_id(request),
    )
    return await db.get_meraki_compliance_assignment(assignment_id)


@router.delete("/api/compliance/meraki/assignments/{assignment_id}")
async def delete_meraki_assignment_api(assignment_id: int, request: Request):
    assignment = await db.get_meraki_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    await db.delete_meraki_compliance_assignment(assignment_id)
    await _audit(
        "compliance",
        "meraki.assignment.deleted",
        user=_session_user(request),
        detail=f"assignment_id={assignment_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/compliance/meraki/assignments/{assignment_id}/scan-now", status_code=202)
async def scan_meraki_assignment_now_api(assignment_id: int, request: Request):
    """Start a scan of one assignment. Poll ``/api/compliance/meraki/scans/{job_id}``."""
    assignment = await db.get_meraki_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    org = await _get_org_or_404(assignment["org_ref"])
    profile = await _get_profile_or_404(assignment["profile_id"])
    return _start_scan(org, profile, assignment_id, _session_user(request))


# ── On-demand scan ───────────────────────────────────────────────────────────


@router.post("/api/compliance/meraki/scan", status_code=202)
async def run_meraki_scan_api(body: MerakiScanRequest, request: Request):
    """Start a scan of an organization against a profile. Poll ``/api/compliance/meraki/scans/{job_id}``."""
    profile = await _get_profile_or_404(body.profile_id)
    org = await _get_org_or_404(body.org_ref)
    return _start_scan(org, profile, None, _session_user(request))


@router.get("/api/compliance/meraki/scans/{job_id}")
async def get_meraki_scan_job_api(job_id: str):
    job = background_jobs.get_job(job_id, kind=_JOB_KIND)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found (it may have expired)")
    return job


# ── Results and status ───────────────────────────────────────────────────────


@router.get("/api/compliance/meraki/results")
async def list_meraki_results_api(
    org_ref: int | None = Query(default=None),
    profile_id: int | None = Query(default=None),
    assignment_id: int | None = Query(default=None),
    scan_id: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, max_length=20),
    target_kind: str | None = Query(default=None, max_length=20),
    limit: int = Query(default=200, ge=1, le=2000),
):
    return await db.list_meraki_compliance_results(
        org_ref=org_ref,
        profile_id=profile_id,
        assignment_id=assignment_id,
        scan_id=scan_id,
        status=status,
        target_kind=target_kind,
        limit=limit,
    )


@router.get("/api/compliance/meraki/results/{result_id}")
async def get_meraki_result_api(result_id: int):
    result = await db.get_meraki_compliance_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    try:
        result["findings"] = json.loads(result.get("findings") or "[]")
    except json.JSONDecodeError:
        result["findings"] = []
    return result


@router.delete("/api/compliance/meraki/results/{result_id}")
async def delete_meraki_result_api(result_id: int, request: Request):
    result = await db.get_meraki_compliance_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    await db.delete_meraki_compliance_result(result_id)
    await _audit(
        "compliance",
        "meraki.result.deleted",
        user=_session_user(request),
        detail=f"result_id={result_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.get("/api/compliance/meraki/status")
async def get_meraki_status_api(
    profile_id: int | None = Query(default=None),
    org_ref: int | None = Query(default=None),
):
    """Latest status per (target, profile)."""
    return await db.get_meraki_compliance_status(profile_id=profile_id, org_ref=org_ref)


@router.get("/api/compliance/meraki/summary")
async def get_meraki_summary_api():
    summary = await db.get_meraki_compliance_summary()
    summary["scans_running"] = len(_running_scans)
    return summary
