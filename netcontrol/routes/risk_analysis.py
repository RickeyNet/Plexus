"""
risk_analysis.py -- Pre-change risk analysis engine and API routes.

Object scope (model ``risk_analysis``): an analysis is placed by its host
and inventory group; an account limited to selected inventory groups sees
the analyses of its readable hosts and groups, analyzes only writable
targets and approves or deletes only writable analyses. Offline analyses
(no host or group) are visible to unrestricted callers only.
"""

from __future__ import annotations

import asyncio
import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.object_scope import (
    ScopeModel,
    register_model,
    request_scope,
    require_group,
    require_host,
    require_host_ids,
    require_row,
    scope_exempt,
    scoped,
    sql_condition,
)
from netcontrol.routes.config_visibility import mask_commands, mask_config_rows, mask_config_text
from netcontrol.routes.device_config import ON_DEMAND_MAX_AGE_SECONDS, get_device_config
from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
    _get_session,
    require_credential_access,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.risk_analysis")

_ANALYSIS_NOT_FOUND = "Risk analysis not found"
register_model(
    ScopeModel(
        "risk_analysis",
        {"group": "group_id", "host": "host_id"},
        not_found=_ANALYSIS_NOT_FOUND,
        description="Risk analyses (by their host and inventory group)",
    )
)


# The fields that hold (a diff of) a host's running configuration.
_CONFIG_FIELDS = ("current_config", "simulated_config", "proposed_diff")


def _masked_detail(detail: object) -> object:
    """The ``analysis`` of a row (a dict, or the JSON text stored for it)
    with the commands quoted under its affected areas masked. Text that is
    not JSON is masked as configuration text."""
    if isinstance(detail, str):
        if not detail:
            return detail
        try:
            return json.dumps(_masked_detail(json.loads(detail)))
        except ValueError:
            return mask_config_text(detail)
    if isinstance(detail, dict):
        for area in detail.get("affected_areas") or []:
            if isinstance(area, dict) and isinstance(area.get("matched_commands"), list):
                area["matched_commands"] = mask_commands(area["matched_commands"])
    return detail


def _mask_proposed_commands(row: dict) -> None:
    """Mask the commands an analysis was run for, in place: the
    ``proposed_commands`` text and the copies quoted in ``analysis``. They
    are configuration for the host (``enable secret``, a community, a
    key), read under the same rule as the configuration it returned."""
    commands = row.get("proposed_commands")
    if isinstance(commands, str) and commands:
        row["proposed_commands"] = "\n".join(mask_commands(commands.split("\n")))
    if row.get("analysis"):
        row["analysis"] = _masked_detail(row["analysis"])


async def _masked_analyses(request: Request, rows: list[dict]) -> list[dict]:
    """Analyses with the configuration their host returned, and the commands
    proposed for it, masked under the rule of
    ``netcontrol.routes.config_visibility``. An offline analysis (no host)
    holds text its author supplied and is returned as it is."""
    await mask_config_rows(
        request,
        [r for r in rows if r.get("host_id") is not None],
        *_CONFIG_FIELDS,
        keep_lines=True,
        also=_mask_proposed_commands,
    )
    return rows


async def require_risk_analysis(request: Request, analysis_id: int, *, write: bool = False) -> dict:
    """The analysis; 404 when unknown or outside the caller's read scope,
    403 on ``write`` when not writable."""
    return await require_row(
        request, "risk_analysis", await db.get_risk_analysis(analysis_id), write=write, not_found=_ANALYSIS_NOT_FOUND
    )


# ── Models ────────────────────────────────────────────────────────────────────


class RiskAnalysisRequest(BaseModel):
    """Request to analyze risk of proposed configuration changes."""

    change_type: str = "template"  # template, manual, policy, route, nat
    host_id: int | None = None
    group_id: int | None = None
    host_ids: list[int] | None = None
    credential_id: int
    proposed_commands: list[str] = []
    template_id: int | None = None


# ── Constants ─────────────────────────────────────────────────────────────────

# Keywords that indicate high-impact config sections
_CRITICAL_PATTERNS = {
    "routing": {
        "keywords": [
            "router ospf",
            "router bgp",
            "router eigrp",
            "router rip",
            "ip route",
            "ipv6 route",
            "network ",
            "redistribute",
            "route-map",
            "prefix-list",
            "as-path",
        ],
        "label": "Routing",
        "weight": 0.25,
    },
    "acl_policy": {
        "keywords": [
            "access-list",
            "ip access-list",
            "permit ",
            "deny ",
            "access-group",
            "policy-map",
            "class-map",
            "service-policy",
        ],
        "label": "ACL / Policy",
        "weight": 0.20,
    },
    "nat": {
        "keywords": [
            "ip nat ",
            "nat ",
            "object network",
            "nat (",
            "static (",
            "pat-pool",
            "xlate",
        ],
        "label": "NAT",
        "weight": 0.20,
    },
    "interface": {
        "keywords": [
            "interface ",
            "shutdown",
            "no shutdown",
            "ip address",
            "switchport",
            "channel-group",
            "vlan ",
        ],
        "label": "Interface",
        "weight": 0.15,
    },
    "security": {
        "keywords": [
            "crypto ",
            "ipsec ",
            "ikev2",
            "tunnel ",
            "aaa ",
            "radius",
            "tacacs",
            "enable secret",
            "username ",
            "snmp-server community",
            "line vty",
            "ssh ",
        ],
        "label": "Security / AAA",
        "weight": 0.20,
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _classify_change_areas(commands: list[str]) -> list[dict]:
    """Classify proposed commands into affected infrastructure areas."""
    areas = []
    commands_lower = [c.lower().strip() for c in commands]

    for area_key, area_def in _CRITICAL_PATTERNS.items():
        matched_commands = []
        for i, cmd_lower in enumerate(commands_lower):
            for kw in area_def["keywords"]:
                if kw in cmd_lower:
                    matched_commands.append(commands[i])
                    break
        if matched_commands:
            areas.append(
                {
                    "area": area_key,
                    "label": area_def["label"],
                    "weight": area_def["weight"],
                    "matched_count": len(matched_commands),
                    "matched_commands": matched_commands[:10],  # cap for storage
                }
            )
    return areas


def _simulate_config_change(current_config: str, commands: list[str]) -> str:
    """Simulate applying commands to a config by appending them.

    This is a best-effort simulation - real device behavior may differ.
    For 'no <command>' lines, we attempt to remove the matching line.
    """
    lines = current_config.splitlines()
    result_lines = list(lines)

    for cmd in commands:
        stripped = cmd.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue

        if stripped.lower().startswith("no "):
            # Try to remove the matching positive form
            positive = stripped[3:].strip()
            result_lines = [line for line in result_lines if positive.lower() not in line.lower().strip()]
        else:
            # Append the command (simplified - real IOS merges into sections)
            result_lines.append(stripped)

    return "\n".join(result_lines)


def _compute_risk_score(
    commands: list[str],
    affected_areas: list[dict],
    diff_added: int,
    diff_removed: int,
    compliance_violations: int,
) -> tuple[float, str]:
    """Compute a 0.0-1.0 risk score and risk level.

    Factors:
      - Volume of changes (more lines = higher risk)
      - Critical areas touched (routing, NAT, security = higher weight)
      - Lines removed (destructive changes are riskier)
      - Compliance violations introduced
    """
    score = 0.0

    # Volume factor (0-0.2): more commands = more risk
    cmd_count = len(commands)
    if cmd_count > 50:
        score += 0.20
    elif cmd_count > 20:
        score += 0.15
    elif cmd_count > 10:
        score += 0.10
    elif cmd_count > 5:
        score += 0.05

    # Critical area factor (0-0.4): weighted by area importance
    area_score = sum(a["weight"] * min(1.0, a["matched_count"] / 3.0) for a in affected_areas)
    score += min(0.40, area_score)

    # Destructive change factor (0-0.2): removals are riskier
    if diff_removed > 20:
        score += 0.20
    elif diff_removed > 10:
        score += 0.15
    elif diff_removed > 5:
        score += 0.10
    elif diff_removed > 0:
        score += 0.05

    # Compliance violation factor (0-0.2)
    if compliance_violations > 5:
        score += 0.20
    elif compliance_violations > 2:
        score += 0.15
    elif compliance_violations > 0:
        score += 0.10

    score = min(1.0, score)

    if score >= 0.7:
        level = "critical"
    elif score >= 0.5:
        level = "high"
    elif score >= 0.3:
        level = "medium"
    else:
        level = "low"

    return round(score, 3), level


async def _run_risk_analysis_for_host(
    host: dict,
    commands: list[str],
    credentials: dict,
    change_type: str = "template",
) -> dict:
    """Run a full risk analysis for proposed commands against a single host.

    Steps:
      1. Current running config (a backup up to 15 minutes old, else read)
      2. Classify affected areas
      3. Simulate the config change
      4. Compute diff between current and simulated
      5. Check compliance impact (run assigned profiles against simulated config)
      6. Calculate risk score
    """
    # Lazy import to avoid circular imports
    from netcontrol.routes.compliance import _evaluate_rule

    # 1. Capture current config
    try:
        current_config = (
            await get_device_config(
                host, credentials, capture_method="risk-analysis", max_age_seconds=ON_DEMAND_MAX_AGE_SECONDS
            )
        ).config_text
    except Exception as exc:
        return {
            "host_id": host["id"],
            "hostname": host.get("hostname", ""),
            "status": "error",
            "error": f"Failed to capture config: {exc}",
            "risk_level": "unknown",
            "risk_score": 0.0,
        }

    # 2. Classify affected areas
    affected_areas = _classify_change_areas(commands)

    # 3. Simulate config change
    simulated_config = _simulate_config_change(current_config, commands)

    # 4. Compute diff
    diff_text, diff_added, diff_removed = _compute_config_diff(
        current_config,
        simulated_config,
        baseline_label="current",
        actual_label="after-change",
    )

    # 5. Check compliance impact
    compliance_impact = []
    compliance_violations = 0
    try:
        host_obj = await db.get_host(host["id"])
        if host_obj and host_obj.get("group_id"):
            assignments = await db.get_compliance_assignments(group_id=host_obj["group_id"])
            for assignment in assignments:
                if not assignment.get("enabled"):
                    continue
                profile = await db.get_compliance_profile(assignment["profile_id"])
                if not profile:
                    continue
                rules_json = profile.get("rules") or "[]"
                if isinstance(rules_json, str):
                    try:
                        rules = json.loads(rules_json)
                    except json.JSONDecodeError:
                        rules = []
                else:
                    rules = rules_json

                # Evaluate rules against current and simulated configs
                findings_before = []
                findings_after = []
                for rule in rules:
                    before_result = _evaluate_rule(rule, current_config)
                    after_result = _evaluate_rule(rule, simulated_config)
                    findings_before.append(before_result)
                    findings_after.append(after_result)

                before_failures = sum(1 for f in findings_before if not f["passed"])
                after_failures = sum(1 for f in findings_after if not f["passed"])
                new_violations = after_failures - before_failures

                if new_violations > 0:
                    compliance_violations += new_violations

                changed_rules = []
                for i, rule in enumerate(rules):
                    before = findings_before[i]["passed"]
                    after = findings_after[i]["passed"]
                    if before != after:
                        changed_rules.append(
                            {
                                "name": rule.get("name", rule.get("pattern", "?")),
                                "before": "pass" if before else "fail",
                                "after": "pass" if after else "fail",
                                "impact": "regression" if before and not after else "improvement",
                            }
                        )

                if changed_rules:
                    compliance_impact.append(
                        {
                            "profile_name": profile["name"],
                            "profile_id": profile["id"],
                            "before_failures": before_failures,
                            "after_failures": after_failures,
                            "new_violations": max(0, new_violations),
                            "improvements": sum(1 for c in changed_rules if c["impact"] == "improvement"),
                            "changed_rules": changed_rules,
                        }
                    )
    except Exception as exc:
        LOGGER.warning("risk-analysis: compliance impact check failed for host %s: %s", host["id"], exc)

    # 6. Calculate risk score
    risk_score, risk_level = _compute_risk_score(
        commands,
        affected_areas,
        diff_added,
        diff_removed,
        compliance_violations,
    )

    analysis_detail = {
        "change_volume": {
            "total_commands": len(commands),
            "diff_lines_added": diff_added,
            "diff_lines_removed": diff_removed,
        },
        "affected_areas": affected_areas,
        "compliance_impact": compliance_impact,
        "compliance_violations_introduced": compliance_violations,
        "risk_factors": [],
    }

    # Build human-readable risk factors
    if affected_areas:
        area_labels = [a["label"] for a in affected_areas]
        analysis_detail["risk_factors"].append(f"Touches critical areas: {', '.join(area_labels)}")
    if diff_removed > 0:
        analysis_detail["risk_factors"].append(f"Removes {diff_removed} line(s) from running config")
    if compliance_violations > 0:
        analysis_detail["risk_factors"].append(f"Introduces {compliance_violations} new compliance violation(s)")
    if len(commands) > 20:
        analysis_detail["risk_factors"].append(f"Large change set ({len(commands)} commands)")

    return {
        "host_id": host["id"],
        "hostname": host.get("hostname", ""),
        "ip_address": host.get("ip_address", ""),
        "status": "analyzed",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "proposed_diff": diff_text,
        "current_config": current_config[:3000],
        "simulated_config": simulated_config[:3000],
        "analysis": analysis_detail,
        "compliance_impact": compliance_impact,
        "affected_areas": [a["label"] for a in affected_areas],
    }


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/api/risk-analysis/analyze")
@scoped("hosts")
async def run_risk_analysis(body: RiskAnalysisRequest, request: Request):
    """Run pre-change risk analysis for proposed commands against target
    hosts (a scoped caller: every target host and the group writable)."""
    session = _get_session(request)
    if (await request_scope(request)).restricted:
        if body.group_id is not None:
            await require_group(request, body.group_id, write=True)
        if body.host_ids:
            await require_host_ids(request, body.host_ids, write=True)
        elif body.host_id:
            await require_host(request, body.host_id, write=True)

    # Resolve credentials: the stored row, which the SSH helpers decrypt.
    credentials = await require_credential_access(body.credential_id, session=session)

    # Resolve proposed commands - from body or from template
    commands = list(body.proposed_commands)
    if body.template_id and not commands:
        tpl = await db.get_template(body.template_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="Template not found")
        commands = [
            line.rstrip() for line in tpl["content"].splitlines() if line.strip() and not line.strip().startswith("#")
        ]
    if not commands:
        raise HTTPException(status_code=400, detail="No proposed commands provided")

    # Resolve target hosts
    hosts = []
    group_id = body.group_id
    if body.host_ids and len(body.host_ids) > 0:
        hosts = await db.get_hosts_by_ids(body.host_ids)
        if hosts and not group_id:
            group_id = hosts[0].get("group_id")
    elif body.host_id:
        host = await db.get_host(body.host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        hosts = [host]
        if not group_id:
            group_id = host.get("group_id")
    elif body.group_id:
        hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=400, detail="No target hosts found")

    # Run analysis for each host (with bounded concurrency)
    sem = state.device_op_semaphore()
    results = []

    async def _analyze_one(h):
        async with sem:
            return await _run_risk_analysis_for_host(h, commands, credentials, body.change_type)

    tasks = [_analyze_one(h) for h in hosts]
    host_results = await asyncio.gather(*tasks, return_exceptions=True)

    max_risk_score = 0.0
    max_risk_level = "low"
    total_compliance_violations = 0
    all_affected_areas = set()

    for r in host_results:
        if isinstance(r, Exception):
            LOGGER.warning("risk-analysis: host analysis failed: %s", r)
            results.append(
                {"status": "error", "error": "Analysis failed for host", "risk_level": "unknown", "risk_score": 0.0}
            )
        else:
            results.append(r)
            if r.get("risk_score", 0) > max_risk_score:
                max_risk_score = r["risk_score"]
                max_risk_level = r.get("risk_level", "low")
            for ci in r.get("compliance_impact", []):
                total_compliance_violations += ci.get("new_violations", 0)
            for area in r.get("affected_areas", []):
                all_affected_areas.add(area)

    # Persist the analysis for the first host as the primary record
    first = results[0] if results else {}
    analysis_id = await db.create_risk_analysis(
        change_type=body.change_type,
        host_id=body.host_id or (hosts[0]["id"] if hosts else None),
        group_id=group_id,
        risk_level=max_risk_level,
        risk_score=max_risk_score,
        proposed_commands="\n".join(commands),
        proposed_diff=first.get("proposed_diff", "")[:10000],
        current_config=first.get("current_config", "")[:5000],
        simulated_config=first.get("simulated_config", "")[:5000],
        analysis=json.dumps(first.get("analysis", {})),
        compliance_impact=json.dumps(first.get("compliance_impact", [])),
        affected_areas=json.dumps(list(all_affected_areas)),
        created_by=session["user"] if session else "",
    )

    await _audit(
        "risk-analysis",
        "analysis.created",
        user=session["user"] if session else "",
        detail=f"id={analysis_id} hosts={len(hosts)} risk={max_risk_level} score={max_risk_score}",
        correlation_id=_corr_id(request),
    )

    return {
        "id": analysis_id,
        "risk_level": max_risk_level,
        "risk_score": max_risk_score,
        "hosts_analyzed": len(results),
        "total_compliance_violations": total_compliance_violations,
        "affected_areas": list(all_affected_areas),
        "host_results": await _masked_analyses(request, results),
    }


@router.get("/api/risk-analysis")
@scoped("list")
async def list_risk_analyses(
    request: Request,
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    scope_kwargs = await _scope_kwargs(request)
    rows = await db.get_risk_analyses(
        host_id=host_id, group_id=group_id, risk_level=risk_level, limit=limit, **scope_kwargs
    )
    return await _masked_analyses(request, rows)


async def _scope_kwargs(request: Request) -> dict:
    """``{}`` for an unrestricted caller, else the SQL scope condition."""
    cond = await sql_condition("risk_analysis", request, alias="r")
    return {"scope_condition": cond} if cond[0] else {}


@router.get("/api/risk-analysis/summary")
@scoped("list")
async def get_risk_analysis_summary_endpoint(request: Request):
    return await db.get_risk_analysis_summary(**await _scope_kwargs(request))


@router.get("/api/risk-analysis/{analysis_id}")
@scoped("risk_analysis")
async def get_risk_analysis(analysis_id: int, request: Request):
    return (await _masked_analyses(request, [await require_risk_analysis(request, analysis_id)]))[0]


@router.post("/api/risk-analysis/{analysis_id}/approve")
@scoped("risk_analysis")
async def approve_risk_analysis(analysis_id: int, request: Request):
    analysis = await require_risk_analysis(request, analysis_id, write=True)
    session = _get_session(request)
    user = session["user"] if session else ""
    await db.approve_risk_analysis(analysis_id, approved_by=user)
    await _audit(
        "risk-analysis",
        "analysis.approved",
        user=user,
        detail=f"id={analysis_id} risk_level={analysis['risk_level']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/risk-analysis/{analysis_id}")
@scoped("risk_analysis")
async def delete_risk_analysis(analysis_id: int, request: Request):
    await require_risk_analysis(request, analysis_id, write=True)
    await db.delete_risk_analysis(analysis_id)
    session = _get_session(request)
    await _audit(
        "risk-analysis",
        "analysis.deleted",
        user=session["user"] if session else "",
        detail=f"id={analysis_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Offline Risk Analysis (no device connection) ────────────────────────────


@router.post("/api/risk-analysis/analyze-offline")
@scope_exempt("analyzes configuration text the caller supplies; touches no host or inventory group")
async def run_offline_risk_analysis(request: Request):
    """Analyze risk without connecting to devices - uses provided config text."""
    body = await request.json()
    commands = body.get("proposed_commands", [])
    current_config = body.get("current_config", "")
    if not commands:
        raise HTTPException(status_code=400, detail="No proposed commands provided")
    if not current_config:
        raise HTTPException(status_code=400, detail="No current config provided")

    affected_areas = _classify_change_areas(commands)
    simulated_config = _simulate_config_change(current_config, commands)
    diff_text, diff_added, diff_removed = _compute_config_diff(
        current_config,
        simulated_config,
        baseline_label="current",
        actual_label="after-change",
    )

    risk_score, risk_level = _compute_risk_score(
        commands,
        affected_areas,
        diff_added,
        diff_removed,
        0,
    )

    analysis = {
        "change_volume": {
            "total_commands": len(commands),
            "diff_lines_added": diff_added,
            "diff_lines_removed": diff_removed,
        },
        "affected_areas": affected_areas,
        "risk_factors": [],
    }

    if affected_areas:
        analysis["risk_factors"].append(f"Touches critical areas: {', '.join(a['label'] for a in affected_areas)}")
    if diff_removed > 0:
        analysis["risk_factors"].append(f"Removes {diff_removed} line(s) from running config")
    if len(commands) > 20:
        analysis["risk_factors"].append(f"Large change set ({len(commands)} commands)")

    session = _get_session(request)
    analysis_id = await db.create_risk_analysis(
        change_type=body.get("change_type", "manual"),
        risk_level=risk_level,
        risk_score=risk_score,
        proposed_commands="\n".join(commands),
        proposed_diff=diff_text[:10000],
        current_config=current_config[:5000],
        simulated_config=simulated_config[:5000],
        analysis=json.dumps(analysis),
        affected_areas=json.dumps([a["label"] for a in affected_areas]),
        created_by=session["user"] if session else "",
    )

    await _audit(
        "risk-analysis",
        "analysis.offline",
        user=session["user"] if session else "",
        detail=f"id={analysis_id} risk={risk_level} score={risk_score}",
        correlation_id=_corr_id(request),
    )

    return {
        "id": analysis_id,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "proposed_diff": diff_text,
        "simulated_config": simulated_config[:3000],
        "analysis": analysis,
        "affected_areas": [a["label"] for a in affected_areas],
    }
