"""
compliance.py -- Compliance profile CRUD, assignment management, scan execution,
admin scheduling, and background compliance check loop.
"""

import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _capture_running_config, _corr_id, _get_session
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.compliance")

# ── Late-binding auth dependencies (injected by app.py) ──────────────────────

_require_auth = None
_require_feature = None
_require_admin = None


def init_compliance(require_auth, require_feature, require_admin):
    global _require_auth, _require_feature, _require_admin
    _require_auth = require_auth
    _require_feature = require_feature
    _require_admin = require_admin


def _compliance_deps():
    return [Depends(_require_auth), Depends(_require_feature("compliance"))]


def _admin_deps():
    return [Depends(_require_admin)]


# ── Models ────────────────────────────────────────────────────────────────────


class ComplianceProfileCreate(BaseModel):
    name: str
    description: str = ""
    rules: list[dict] = []
    severity: str = "medium"


class ComplianceProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rules: list[dict] | None = None
    severity: str | None = None


class ComplianceAssignmentCreate(BaseModel):
    profile_id: int
    group_id: int
    credential_id: int
    interval_seconds: int = 86400


class ComplianceAssignmentUpdate(BaseModel):
    enabled: bool | None = None
    credential_id: int | None = None
    interval_seconds: int | None = None


class ComplianceScanRequest(BaseModel):
    host_id: int
    profile_id: int
    credential_id: int


# ── Helpers ───────────────────────────────────────────────────────────────────


def _evaluate_rule(rule: dict, config_text: str) -> dict:
    """Evaluate a single compliance rule against running config.

    Rule types:
      - must_contain: config must contain the pattern (substring or regex)
      - must_not_contain: config must NOT contain the pattern
      - regex_match: config must match the regex pattern
    """
    import re as _re

    rule_type = rule.get("type", "must_contain")
    pattern = rule.get("pattern", "")
    name = rule.get("name", pattern[:60])
    result = {"name": name, "type": rule_type, "pattern": pattern, "passed": False, "detail": ""}

    if not pattern:
        result["passed"] = True
        result["detail"] = "Empty pattern — auto-pass"
        return result

    if rule_type == "must_contain":
        found = pattern.lower() in config_text.lower()
        result["passed"] = found
        result["detail"] = "Pattern found" if found else f"Missing: {pattern}"
    elif rule_type == "must_not_contain":
        found = pattern.lower() in config_text.lower()
        result["passed"] = not found
        result["detail"] = "Pattern absent (good)" if not found else f"Prohibited pattern found: {pattern}"
    elif rule_type == "regex_match":
        try:
            match = _re.search(pattern, config_text, _re.MULTILINE | _re.IGNORECASE)
            result["passed"] = match is not None
            result["detail"] = "Regex matched" if match else f"Regex not matched: {pattern}"
        except _re.error as e:
            result["passed"] = False
            result["detail"] = f"Invalid regex: {e}"
    else:
        result["passed"] = False
        result["detail"] = f"Unknown rule type: {rule_type}"

    return result


async def _evaluate_host_compliance(host: dict, profile: dict, credentials: dict) -> dict:
    """Evaluate a host against a compliance profile's rules.

    Returns {status, total_rules, passed_rules, failed_rules, findings, config_snippet}.
    """
    try:
        config_text = await _capture_running_config(host, credentials)
    except Exception as exc:
        return {
            "status": "error",
            "total_rules": 0,
            "passed_rules": 0,
            "failed_rules": 0,
            "findings": json.dumps([{"name": "config_capture", "passed": False, "detail": str(exc)}]),
            "config_snippet": "",
        }

    rules_json = profile.get("rules") or profile.get("profile_rules") or "[]"
    if isinstance(rules_json, str):
        try:
            rules = json.loads(rules_json)
        except json.JSONDecodeError:
            rules = []
    else:
        rules = rules_json

    findings = []
    passed = 0
    failed = 0
    for rule in rules:
        result = _evaluate_rule(rule, config_text)
        findings.append(result)
        if result["passed"]:
            passed += 1
        else:
            failed += 1

    total = len(rules)
    status = "compliant" if failed == 0 else "non-compliant"
    # Truncate config snippet for storage
    snippet = config_text[:2000] if len(config_text) > 2000 else config_text

    return {
        "status": status,
        "total_rules": total,
        "passed_rules": passed,
        "failed_rules": failed,
        "findings": json.dumps(findings),
        "config_snippet": snippet,
    }


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_compliance_check_once() -> dict:
    """Run compliance scans for all due assignments."""
    import asyncio

    if not state.COMPLIANCE_CHECK_CONFIG.get("enabled"):
        return {"enabled": False, "assignments_run": 0, "hosts_scanned": 0, "violations": 0, "errors": 0}

    due_assignments = await db.get_compliance_assignments_due()
    assignments_run = 0
    hosts_scanned = 0
    violations = 0
    errors = 0

    sem = asyncio.Semaphore(4)

    for assignment in due_assignments:
        try:
            hosts = await db.get_hosts_for_group(assignment["group_id"])
            cred = await db.get_credential_raw(assignment["credential_id"])
            if not cred:
                LOGGER.warning("compliance: credential %s not found for assignment %s",
                               assignment["credential_id"], assignment["id"])
                errors += 1
                continue

            profile = await db.get_compliance_profile(assignment["profile_id"])
            if not profile:
                errors += 1
                continue

            async def _scan_host(h, prof, cred_data, asgn_id, prof_id):
                async with sem:
                    try:
                        result = await _evaluate_host_compliance(h, prof, cred_data)
                        await db.create_compliance_scan_result(
                            assignment_id=asgn_id,
                            profile_id=prof_id,
                            host_id=h["id"],
                            **result,
                        )
                        return result["status"]
                    except Exception as exc:
                        LOGGER.warning("compliance: scan failed host_id=%s: %s", h["id"], exc)
                        return "error"

            tasks = [_scan_host(h, profile, cred, assignment["id"], assignment["profile_id"]) for h in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, str):
                    hosts_scanned += 1
                    if r == "non-compliant":
                        violations += 1
                    elif r == "error":
                        errors += 1
                else:
                    errors += 1

            await db.update_compliance_assignment_last_scan(assignment["id"])
            assignments_run += 1

        except Exception as exc:
            errors += 1
            LOGGER.warning("compliance: assignment %s failed: %s", assignment["id"], exc)

    # Retention cleanup
    retention_days = int(state.COMPLIANCE_CHECK_CONFIG.get("retention_days", state.COMPLIANCE_CHECK_DEFAULTS["retention_days"]))
    try:
        await db.delete_old_compliance_scan_results(retention_days)
    except Exception:
        pass

    if assignments_run > 0:
        LOGGER.info("compliance: ran %d assignments, scanned %d hosts, %d violations, %d errors",
                     assignments_run, hosts_scanned, violations, errors)
        increment_metric("compliance.check.scheduled.success")

    return {
        "enabled": True,
        "assignments_run": assignments_run,
        "hosts_scanned": hosts_scanned,
        "violations": violations,
        "errors": errors,
    }


async def _compliance_check_loop() -> None:
    """Infinite loop that checks for due compliance scans."""
    import asyncio

    while True:
        try:
            await asyncio.sleep(int(state.COMPLIANCE_CHECK_CONFIG.get(
                "interval_seconds", state.COMPLIANCE_CHECK_DEFAULTS["interval_seconds"])))
            await _run_compliance_check_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("compliance check loop failure: %s", redact_value(str(exc)))
            increment_metric("compliance.check.scheduled.failed")
            await asyncio.sleep(state.COMPLIANCE_CHECK_DEFAULTS["interval_seconds"])


# ── Compliance Profile CRUD ──────────────────────────────────────────────────


@router.get("/api/compliance/profiles")
async def list_compliance_profiles():
    return await db.get_compliance_profiles()


@router.post("/api/compliance/profiles", status_code=201)
async def create_compliance_profile(body: ComplianceProfileCreate, request: Request):
    if body.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="Severity must be low, medium, high, or critical")
    session = _get_session(request)
    profile_id = await db.create_compliance_profile(
        name=body.name,
        description=body.description,
        rules=json.dumps(body.rules),
        severity=body.severity,
        created_by=session["user"] if session else "",
    )
    await _audit(
        "compliance", "profile.created",
        user=session["user"] if session else "",
        detail=f"profile_id={profile_id} name={body.name} rules={len(body.rules)}",
        correlation_id=_corr_id(request),
    )
    return {"id": profile_id}


@router.get("/api/compliance/profiles/{profile_id}")
async def get_compliance_profile(profile_id: int):
    profile = await db.get_compliance_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    return profile


@router.put("/api/compliance/profiles/{profile_id}")
async def update_compliance_profile(profile_id: int, body: ComplianceProfileUpdate, request: Request):
    profile = await db.get_compliance_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.description is not None:
        updates["description"] = body.description
    if body.rules is not None:
        updates["rules"] = json.dumps(body.rules)
    if body.severity is not None:
        if body.severity not in ("low", "medium", "high", "critical"):
            raise HTTPException(status_code=400, detail="Severity must be low, medium, high, or critical")
        updates["severity"] = body.severity
    await db.update_compliance_profile(profile_id, **updates)
    session = _get_session(request)
    await _audit(
        "compliance", "profile.updated",
        user=session["user"] if session else "",
        detail=f"profile_id={profile_id} fields={list(updates.keys())}",
        correlation_id=_corr_id(request),
    )
    return await db.get_compliance_profile(profile_id)


@router.delete("/api/compliance/profiles/{profile_id}")
async def delete_compliance_profile(profile_id: int, request: Request):
    profile = await db.get_compliance_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    await db.delete_compliance_profile(profile_id)
    session = _get_session(request)
    await _audit(
        "compliance", "profile.deleted",
        user=session["user"] if session else "",
        detail=f"profile_id={profile_id} name={profile['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Compliance Assignments ──────────────────────────────────────────────────


@router.get("/api/compliance/assignments")
async def list_compliance_assignments(
    profile_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
):
    return await db.get_compliance_assignments(profile_id=profile_id, group_id=group_id)


@router.post("/api/compliance/assignments", status_code=201)
async def create_compliance_assignment(body: ComplianceAssignmentCreate, request: Request):
    profile = await db.get_compliance_profile(body.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    group = await db.get_group(body.group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Inventory group not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    interval = max(state.COMPLIANCE_ASSIGNMENT_MIN_INTERVAL, min(state.COMPLIANCE_ASSIGNMENT_MAX_INTERVAL, body.interval_seconds))
    session = _get_session(request)
    assignment_id = await db.create_compliance_assignment(
        profile_id=body.profile_id,
        group_id=body.group_id,
        credential_id=body.credential_id,
        interval_seconds=interval,
        assigned_by=session["user"] if session else "",
    )
    await _audit(
        "compliance", "assignment.created",
        user=session["user"] if session else "",
        detail=f"assignment_id={assignment_id} profile={body.profile_id} group={body.group_id}",
        correlation_id=_corr_id(request),
    )
    return {"id": assignment_id}


@router.put("/api/compliance/assignments/{assignment_id}")
async def update_compliance_assignment(assignment_id: int, body: ComplianceAssignmentUpdate, request: Request):
    assignment = await db.get_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    updates = {}
    if body.enabled is not None:
        updates["enabled"] = 1 if body.enabled else 0
    if body.credential_id is not None:
        updates["credential_id"] = body.credential_id
    if body.interval_seconds is not None:
        updates["interval_seconds"] = max(state.COMPLIANCE_ASSIGNMENT_MIN_INTERVAL,
                                          min(state.COMPLIANCE_ASSIGNMENT_MAX_INTERVAL, body.interval_seconds))
    await db.update_compliance_assignment(assignment_id, **updates)
    session = _get_session(request)
    await _audit(
        "compliance", "assignment.updated",
        user=session["user"] if session else "",
        detail=f"assignment_id={assignment_id} fields={list(updates.keys())}",
        correlation_id=_corr_id(request),
    )
    return await db.get_compliance_assignment(assignment_id)


@router.delete("/api/compliance/assignments/{assignment_id}")
async def delete_compliance_assignment(assignment_id: int, request: Request):
    assignment = await db.get_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    await db.delete_compliance_assignment(assignment_id)
    session = _get_session(request)
    await _audit(
        "compliance", "assignment.deleted",
        user=session["user"] if session else "",
        detail=f"assignment_id={assignment_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Compliance Scan Results ──────────────────────────────────────────────────


@router.get("/api/compliance/results")
async def list_compliance_scan_results(
    host_id: int | None = Query(default=None),
    profile_id: int | None = Query(default=None),
    assignment_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=200, le=1000),
):
    return await db.get_compliance_scan_results(
        host_id=host_id, profile_id=profile_id,
        assignment_id=assignment_id, status=status, limit=limit,
    )


@router.get("/api/compliance/results/{result_id}")
async def get_compliance_scan_result(result_id: int):
    result = await db.get_compliance_scan_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return result


@router.delete("/api/compliance/results/{result_id}")
async def delete_compliance_scan_result(result_id: int, request: Request):
    result = await db.get_compliance_scan_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    await db.delete_compliance_scan_result(result_id)
    session = _get_session(request)
    await _audit(
        "compliance", "result.deleted",
        user=session["user"] if session else "",
        detail=f"result_id={result_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Compliance Host Status & Summary ─────────────────────────────────────────


@router.get("/api/compliance/status")
async def get_compliance_host_status(profile_id: int | None = Query(default=None)):
    """Get latest compliance status per host."""
    return await db.get_compliance_host_status(profile_id=profile_id)


@router.get("/api/compliance/summary")
async def get_compliance_summary():
    """Return compliance summary stats."""
    return await db.get_compliance_summary()


# ── On-demand Compliance Scan ────────────────────────────────────────────────


@router.post("/api/compliance/scan")
async def run_compliance_scan(body: ComplianceScanRequest, request: Request):
    """Run an on-demand compliance scan for a single host against a profile."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    profile = await db.get_compliance_profile(body.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    result = await _evaluate_host_compliance(host, profile, cred)
    result_id = await db.create_compliance_scan_result(
        assignment_id=None,
        profile_id=body.profile_id,
        host_id=body.host_id,
        **result,
    )
    session = _get_session(request)
    await _audit(
        "compliance", "scan.manual",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} profile_id={body.profile_id} status={result['status']}",
        correlation_id=_corr_id(request),
    )
    return {"id": result_id, **result}


# ── Admin Compliance Schedule ────────────────────────────────────────────────


@admin_router.get("/api/admin/compliance")
async def admin_get_compliance_config():
    return state.COMPLIANCE_CHECK_CONFIG


@admin_router.put("/api/admin/compliance")
async def admin_update_compliance_config(body: dict, request: Request):
    state.COMPLIANCE_CHECK_CONFIG = state._sanitize_compliance_check_config(body)
    await db.set_auth_setting("compliance_check", state.COMPLIANCE_CHECK_CONFIG)
    session = _get_session(request)
    await _audit(
        "compliance", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={state.COMPLIANCE_CHECK_CONFIG['enabled']} interval={state.COMPLIANCE_CHECK_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return state.COMPLIANCE_CHECK_CONFIG


@admin_router.post("/api/admin/compliance/run-now")
async def admin_run_compliance_check_now(request: Request):
    result = await _run_compliance_check_once()
    session = _get_session(request)
    await _audit(
        "compliance", "check.manual",
        user=session["user"] if session else "",
        detail=f"assignments_run={result.get('assignments_run', 0)} hosts_scanned={result.get('hosts_scanned', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}
