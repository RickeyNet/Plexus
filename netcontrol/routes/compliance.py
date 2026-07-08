"""
compliance.py -- Compliance profile CRUD, assignment management, scan execution,
admin scheduling, and background compliance check loop.
"""
from __future__ import annotations

import functools
import json
import re

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.shared import (
    _audit,
    _capture_running_config,
    _corr_id,
    _get_session,
    _push_config_to_device,
    require_credential_access,
)
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


class ComplianceBulkScanRequest(BaseModel):
    profile_id: int
    credential_id: int
    host_ids: list[int] = []   # empty = scan all hosts


class ComplianceRemediateRequest(BaseModel):
    result_id: int
    rule_name: str
    credential_id: int
    dry_run: bool = True


# ── Helpers ───────────────────────────────────────────────────────────────────


def _config_has_directive(config_text: str, pattern: str) -> bool:
    """Line-anchored presence test for a config directive.

    A naive substring check is wrong because a disabled feature still contains
    the bare directive text: ``"service password-encryption" in
    "no service password-encryption"`` is True, which would report a device
    that has the feature *turned off* as compliant. Here a line whose stripped
    form begins with ``no `` counts as an explicit negation and does NOT satisfy
    an affirmative pattern. If the pattern itself is a ``no ...`` directive, a
    matching ``no ...`` line does satisfy it (the operator wants it present).
    """
    pat = pattern.strip().lower()
    if not pat:
        return False
    pat_is_negation = pat.startswith("no ")
    for raw in config_text.splitlines():
        line = raw.strip().lower()
        if not line or pat not in line:
            continue
        if pat_is_negation:
            return True
        if line.startswith("no "):
            # Feature explicitly disabled — the "no ..." line contains the bare
            # directive but must not count as present.
            continue
        return True
    return False


@functools.lru_cache(maxsize=512)
def _compile_rule_regex(pattern: str) -> re.Pattern:
    """Compile (and cache) a compliance regex. A bulk scan evaluates the same
    rule against every host, so caching avoids recompiling the pattern per host.
    Raises re.error for invalid patterns (not cached); callers handle it."""
    return re.compile(pattern, re.MULTILINE | re.IGNORECASE)


def _evaluate_rule(rule: dict, config_text: str) -> dict:
    """Evaluate a single compliance rule against running config.

    Rule types:
      - must_contain: config must contain the pattern (substring or regex)
      - must_not_contain: config must NOT contain the pattern
      - regex_match: config must match the regex pattern
    """
    _re = re

    rule_type = rule.get("type", "must_contain")
    pattern = rule.get("pattern", "")
    name = rule.get("name", pattern[:60])
    remediation = rule.get("remediation")  # list of IOS commands or None
    result = {"name": name, "type": rule_type, "pattern": pattern, "passed": False, "detail": "",
              "remediation": remediation}

    if not pattern:
        result["passed"] = True
        result["detail"] = "Empty pattern - auto-pass"
        return result

    if rule_type == "must_contain":
        found = _config_has_directive(config_text, pattern)
        result["passed"] = found
        result["detail"] = "Pattern found" if found else f"Missing: {pattern}"
    elif rule_type == "must_not_contain":
        found = _config_has_directive(config_text, pattern)
        result["passed"] = not found
        result["detail"] = "Pattern absent (good)" if not found else f"Prohibited pattern found: {pattern}"
    elif rule_type == "regex_match":
        try:
            compiled = _compile_rule_regex(pattern)
            # Guard against catastrophic backtracking by capping the searched
            # length. 2MB comfortably covers large chassis configs while still
            # bounding worst-case regex cost.
            _MAX_SEARCH = 2_000_000
            search_text = config_text[:_MAX_SEARCH]
            truncated = len(config_text) > _MAX_SEARCH
            match = compiled.search(search_text)
            result["passed"] = match is not None
            if match:
                result["detail"] = "Regex matched"
            elif truncated:
                # Distinguish a genuine miss from a truncation artifact so a
                # large config isn't silently reported non-compliant.
                result["detail"] = (
                    f"Regex not matched in first {_MAX_SEARCH // 1000}KB "
                    f"(config truncated for search): {pattern}"
                )
            else:
                result["detail"] = f"Regex not matched: {pattern}"
        except _re.error as e:
            result["passed"] = False
            result["detail"] = f"Invalid regex: {e}"
    else:
        result["passed"] = False
        result["detail"] = f"Unknown rule type: {rule_type}"

    return result


# Maximum seconds to wait for a config capture before giving up.
_SCAN_TIMEOUT_SECONDS = 120


async def _evaluate_host_compliance(host: dict, profile: dict, credentials: dict) -> dict:
    """Evaluate a host against a compliance profile's rules.

    Returns {status, total_rules, passed_rules, failed_rules, findings, config_snippet}.
    """
    import asyncio as _aio

    try:
        config_text = await _aio.wait_for(
            _capture_running_config(host, credentials),
            timeout=_SCAN_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return {
            "status": "error",
            "total_rules": 0,
            "passed_rules": 0,
            "failed_rules": 0,
            "findings": json.dumps([{"name": "config_capture", "passed": False,
                                      "detail": f"Timed out after {_SCAN_TIMEOUT_SECONDS}s connecting to {host.get('ip_address', '?')}"}]),
            "config_snippet": "",
        }
    except Exception as exc:
        return {
            "status": "error",
            "total_rules": 0,
            "passed_rules": 0,
            "failed_rules": 0,
            "findings": json.dumps([{"name": "config_capture", "passed": False, "detail": str(exc)[:500]}]),
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


async def _run_compliance_check_once(*, force: bool = False) -> dict:
    """Run compliance scans for all due assignments.

    Args:
        force: If True, bypass the 'enabled' check (used for manual admin triggers).
    """
    import asyncio

    if not force and not state.COMPLIANCE_CHECK_CONFIG.get("enabled"):
        return {"enabled": False, "assignments_run": 0, "hosts_scanned": 0, "violations": 0, "errors": 0}

    due_assignments = await db.get_compliance_assignments_due()
    assignments_run = 0
    hosts_scanned = 0
    violations = 0
    errors = 0

    sem = state.device_op_semaphore()

    for assignment in due_assignments:
        try:
            hosts = await db.get_hosts_for_group(assignment["group_id"])
            try:
                # Re-validate the stored credential against whoever assigned it
                # so the scan can't keep running with a credential the assigner
                # no longer owns (or after the assigner account is removed).
                cred = await require_credential_access(
                    assignment["credential_id"],
                    submitter_username=assignment.get("assigned_by") or None,
                    allow_service=True,
                )
            except HTTPException as exc:
                LOGGER.warning(
                    "compliance: credential %s rejected for assignment %s (assigned_by=%r): %s",
                    assignment["credential_id"], assignment["id"],
                    assignment.get("assigned_by"), exc.detail,
                )
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
    except Exception as exc:
        LOGGER.warning("compliance: retention cleanup failed: %s", exc)

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
    await require_credential_access(
        body.credential_id, session=_get_session(request), allow_service=True,
    )
    # Prevent duplicate (profile_id, group_id) - DB has UNIQUE constraint but give a clean error
    existing = await db.get_compliance_assignments(profile_id=body.profile_id, group_id=body.group_id)
    if existing:
        raise HTTPException(status_code=409, detail="This profile is already assigned to that group")
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
        await require_credential_access(
            body.credential_id, session=_get_session(request), allow_service=True,
        )
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
    limit: int = Query(default=200, ge=1, le=1000),
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


@router.post("/api/compliance/assignments/{assignment_id}/scan-now")
async def scan_assignment_now(assignment_id: int, request: Request):
    """Run an on-demand compliance scan for all hosts in a specific assignment."""
    import asyncio

    assignment = await db.get_compliance_assignment(assignment_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    profile = await db.get_compliance_profile(assignment["profile_id"])
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")

    cred = await require_credential_access(
        assignment["credential_id"], session=_get_session(request), allow_service=True,
    )

    hosts = await db.get_hosts_for_group(assignment["group_id"])
    if not hosts:
        raise HTTPException(status_code=400, detail="No hosts in the assigned group")

    sem = state.device_op_semaphore()
    hosts_scanned = 0
    violations = 0
    errors = 0

    async def _scan_host(h):
        async with sem:
            try:
                result = await _evaluate_host_compliance(h, profile, cred)
                await db.create_compliance_scan_result(
                    assignment_id=assignment_id,
                    profile_id=assignment["profile_id"],
                    host_id=h["id"],
                    **result,
                )
                return result["status"]
            except Exception as exc:
                LOGGER.warning("compliance: scan-now failed host_id=%s: %s", h["id"], exc)
                return "error"

    tasks = [_scan_host(h) for h in hosts]
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

    await db.update_compliance_assignment_last_scan(assignment_id)

    session = _get_session(request)
    await _audit(
        "compliance", "assignment.scan_now",
        user=session["user"] if session else "",
        detail=f"assignment_id={assignment_id} hosts_scanned={hosts_scanned} violations={violations} errors={errors}",
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "assignment_id": assignment_id,
        "hosts_scanned": hosts_scanned,
        "violations": violations,
        "errors": errors,
    }


@router.post("/api/compliance/scan")
async def run_compliance_scan(body: ComplianceScanRequest, request: Request):
    """Run an on-demand compliance scan for a single host against a profile."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    profile = await db.get_compliance_profile(body.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    cred = await require_credential_access(body.credential_id, session=_get_session(request))

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


# ── Bulk / All-Hosts Scan ─────────────────────────────────────────────────


@router.post("/api/compliance/scan-bulk")
async def run_compliance_scan_bulk(body: ComplianceBulkScanRequest, request: Request):
    """Run an on-demand compliance scan against multiple (or all) hosts.

    If host_ids is empty, every host in the inventory is scanned.
    Returns aggregate stats plus a per-host result list.
    """
    import asyncio

    profile = await db.get_compliance_profile(body.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    cred = await require_credential_access(body.credential_id, session=_get_session(request))

    if body.host_ids:
        hosts = await db.get_hosts_by_ids(body.host_ids)
    else:
        hosts = await db.get_all_hosts()

    if not hosts:
        raise HTTPException(status_code=400, detail="No hosts found to scan")

    sem = state.device_op_semaphore()
    host_results = []

    async def _scan_host(h):
        async with sem:
            try:
                result = await _evaluate_host_compliance(h, profile, cred)
                result_id = await db.create_compliance_scan_result(
                    assignment_id=None,
                    profile_id=body.profile_id,
                    host_id=h["id"],
                    **result,
                )
                return {
                    "host_id": h["id"],
                    "hostname": h["hostname"],
                    "status": result["status"],
                    "passed_rules": result["passed_rules"],
                    "failed_rules": result["failed_rules"],
                    "total_rules": result["total_rules"],
                    "result_id": result_id,
                }
            except Exception as exc:
                LOGGER.warning("compliance: bulk scan failed host_id=%s: %s", h["id"], exc)
                return {
                    "host_id": h["id"],
                    "hostname": h.get("hostname", "?"),
                    "status": "error",
                    "passed_rules": 0,
                    "failed_rules": 0,
                    "total_rules": 0,
                    "result_id": None,
                }

    host_results = await asyncio.gather(*[_scan_host(h) for h in hosts])

    hosts_scanned = len(host_results)
    violations = sum(1 for r in host_results if r["status"] == "non-compliant")
    errors = sum(1 for r in host_results if r["status"] == "error")

    session = _get_session(request)
    await _audit(
        "compliance", "scan.bulk",
        user=session["user"] if session else "",
        detail=(
            f"profile_id={body.profile_id} hosts_scanned={hosts_scanned} "
            f"violations={violations} errors={errors} "
            f"scope={'selected' if body.host_ids else 'all'}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "hosts_scanned": hosts_scanned,
        "violations": violations,
        "errors": errors,
        "results": list(host_results),
    }


# ── Compliance Remediation ─────────────────────────────────────────────────


@router.post("/api/compliance/remediate")
async def remediate_compliance_finding(body: ComplianceRemediateRequest, request: Request):
    """Push remediation config for a specific failed compliance rule.

    Looks up the scan result, finds the matching failed rule and its
    remediation commands, then SSHes into the device and applies them.
    Supports dry-run mode to preview commands before pushing.
    After a live push, automatically re-scans the host against the same
    profile and returns updated results.
    """
    # Load scan result
    scan_result = await db.get_compliance_scan_result(body.result_id)
    if not scan_result:
        raise HTTPException(404, "Scan result not found")

    # Find the host
    host = await db.get_host(scan_result["host_id"])
    if not host:
        raise HTTPException(404, "Host not found")

    # Find the profile and its rules
    profile = await db.get_compliance_profile(scan_result["profile_id"])
    if not profile:
        raise HTTPException(404, "Compliance profile not found")

    rules_json = profile.get("rules") or "[]"
    if isinstance(rules_json, str):
        try:
            rules = json.loads(rules_json)
        except json.JSONDecodeError:
            rules = []
    else:
        rules = rules_json

    # Find the specific rule by name
    target_rule = None
    for rule in rules:
        if rule.get("name") == body.rule_name:
            target_rule = rule
            break

    if not target_rule:
        raise HTTPException(404, f"Rule '{body.rule_name}' not found in profile")

    remediation_cmds = target_rule.get("remediation")
    if not remediation_cmds:
        raise HTTPException(400, f"Rule '{body.rule_name}' has no remediation commands defined - this issue requires manual intervention")

    # Verify the rule actually failed in this scan
    findings = []
    try:
        findings = json.loads(scan_result.get("findings", "[]"))
    except json.JSONDecodeError as exc:
        LOGGER.warning("compliance: failed to parse findings for scan %s (host %s): %s",
                       body.result_id, host["id"], exc)

    rule_finding = None
    for f in findings:
        if f.get("name") == body.rule_name:
            rule_finding = f
            break

    if rule_finding and rule_finding.get("passed"):
        raise HTTPException(400, f"Rule '{body.rule_name}' already passes - no remediation needed")

    # Load credential - ownership enforced so a user cannot remediate with
    # another user's credential (this was the last unvalidated IDOR path).
    session = _get_session(request)
    cred = await require_credential_access(body.credential_id, session=session)

    if body.dry_run:
        # Dry-run: just return what would be pushed
        await _audit(
            "compliance", "remediate.dryrun",
            user=session["user"] if session else "",
            detail=f"host_id={host['id']} rule={body.rule_name} commands={len(remediation_cmds)}",
            correlation_id=_corr_id(request),
        )
        return {
            "dry_run": True,
            "host": host["hostname"],
            "ip_address": host["ip_address"],
            "rule": body.rule_name,
            "commands": remediation_cmds,
            "message": f"Would push {len(remediation_cmds)} command(s) to {host['hostname']}",
        }

    # Live push (with timeout to prevent indefinite hangs)
    import asyncio as _aio
    try:
        output = await _aio.wait_for(
            _push_config_to_device(host, cred, remediation_cmds),
            timeout=_SCAN_TIMEOUT_SECONDS,
        )
    except TimeoutError as exc:
        await _audit(
            "compliance", "remediate.failed",
            user=session["user"] if session else "",
            detail=f"host_id={host['id']} rule={body.rule_name} error=timeout after {_SCAN_TIMEOUT_SECONDS}s",
            correlation_id=_corr_id(request),
        )
        LOGGER.error("Remediation timed out for host %s rule %s",
                     host["ip_address"], body.rule_name)
        raise HTTPException(500, f"Remediation timed out after {_SCAN_TIMEOUT_SECONDS}s - the device may not have responded")
    except Exception as exc:
        await _audit(
            "compliance", "remediate.failed",
            user=session["user"] if session else "",
            detail=f"host_id={host['id']} rule={body.rule_name} error={str(exc)[:200]}",
            correlation_id=_corr_id(request),
        )
        LOGGER.error("Remediation failed for host %s rule %s: %s",
                     host["ip_address"], body.rule_name, exc)
        raise HTTPException(500, "Remediation failed - see server logs for details")

    await _audit(
        "compliance", "remediate.applied",
        user=session["user"] if session else "",
        detail=f"host_id={host['id']} rule={body.rule_name} commands={len(remediation_cmds)}",
        correlation_id=_corr_id(request),
    )

    # Re-scan the host to check if the fix worked
    rescan = await _evaluate_host_compliance(host, profile, cred)
    rescan_id = await db.create_compliance_scan_result(
        assignment_id=None,
        profile_id=scan_result["profile_id"],
        host_id=host["id"],
        **rescan,
    )

    # Find the specific rule in the new findings
    new_findings = []
    try:
        new_findings = json.loads(rescan.get("findings", "[]"))
    except json.JSONDecodeError as exc:
        LOGGER.warning("compliance: failed to parse rescan findings for scan %s (host %s): %s",
                       rescan_id, host["id"], exc)
    rule_now_passes = False
    for f in new_findings:
        if f.get("name") == body.rule_name and f.get("passed"):
            rule_now_passes = True
            break

    return {
        "dry_run": False,
        "host": host["hostname"],
        "ip_address": host["ip_address"],
        "rule": body.rule_name,
        "commands": remediation_cmds,
        "output": output,
        "rule_now_passes": rule_now_passes,
        "rescan_id": rescan_id,
        "rescan_status": rescan["status"],
        "rescan_passed": rescan["passed_rules"],
        "rescan_total": rescan["total_rules"],
        "message": f"Remediation applied to {host['hostname']}. "
                   f"{'Rule now PASSES.' if rule_now_passes else 'Rule still failing - review output.'} "
                   f"New score: {rescan['passed_rules']}/{rescan['total_rules']}",
    }


# ── Load Built-in Compliance Profiles ────────────────────────────────────────


@router.post("/api/compliance/profiles/load-builtin")
async def load_builtin_compliance_profiles(request: Request):
    """Load all built-in compliance profiles, creating new ones and updating existing ones."""
    from routes.builtin_compliance_profiles import BUILTIN_PROFILES

    session = _get_session(request)
    loaded = 0
    updated = 0
    existing = await db.get_compliance_profiles()
    existing_by_name = {p["name"]: p for p in existing}

    for name, description, severity, rules in BUILTIN_PROFILES:
        rules_json = json.dumps(rules)
        if name in existing_by_name:
            await db.update_compliance_profile(
                existing_by_name[name]["id"],
                description=description,
                rules=rules_json,
                severity=severity,
            )
            updated += 1
        else:
            await db.create_compliance_profile(
                name=name,
                description=description,
                rules=rules_json,
                severity=severity,
                created_by=session["user"] if session else "system",
            )
            loaded += 1

    await _audit(
        "compliance", "profiles.builtin_loaded",
        user=session["user"] if session else "",
        detail=f"loaded={loaded} updated={updated} total_available={len(BUILTIN_PROFILES)}",
        correlation_id=_corr_id(request),
    )
    return {"loaded": loaded, "updated": updated, "total_available": len(BUILTIN_PROFILES)}


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
    result = await _run_compliance_check_once(force=True)
    session = _get_session(request)
    await _audit(
        "compliance", "check.manual",
        user=session["user"] if session else "",
        detail=f"assignments_run={result.get('assignments_run', 0)} hosts_scanned={result.get('hosts_scanned', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}
