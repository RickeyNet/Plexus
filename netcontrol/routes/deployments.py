"""
deployments.py -- Deployment orchestration with rollback support.

Includes deployment creation, execution with pre/post checkpoints,
rollback via pre-deployment snapshots, and WebSocket streaming.

Object scope: an account limited to selected inventory groups sees a
deployment (lists, summary, detail, job output) when its inventory group and
every target host are readable, and plans, executes, rolls back or deletes
one only when its targets are writable (``_deployment_visible``).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from routes.crypto import decrypt

import netcontrol.routes.state as state
from netcontrol.approvals import ApprovalDecision, decision_audit_detail, require_different_approver
from netcontrol.object_scope import (
    READ_ONLY_DETAIL,
    ObjectScope,
    group_filter,
    request_scope,
    require_group,
    require_host_ids,
    scoped,
    ws_scope,
)
from netcontrol.routes.config_drift import _analyze_drift_for_host
from netcontrol.routes.device_config import get_device_config
from netcontrol.routes.intended_config import RemediationTargets, remediation_for_hosts, resolve_remediation_targets
from netcontrol.routes.maintenance_windows import evaluate_change_gate
from netcontrol.routes.risk_analysis import require_risk_analysis
from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
    _get_session,
    _push_config_to_device,
    require_credential_access,
    require_owner_or_admin,
    supervise_task,
    verify_ws_session,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
ws_router = APIRouter()  # WebSocket routes - registered without HTTP auth dependency
LOGGER = configure_logging("plexus.deployments")

VERIFICATION_METRICS = ["cpu_percent", "memory_percent", "packet_loss_pct", "response_time_ms"]
VERIFICATION_DELAY_SECONDS = 60

# ── Late-binding auth dependencies (injected by app.py) ──────────────────────
# Route-level auth comes from app.py's include_router dependencies; only the
# WebSocket session check needs late-bound callables here.

_verify_session_token: Callable[[str], dict | None] | None = None
_get_user_features: Callable[[dict], Awaitable[list[str]]] | None = None


def init_deployments(verify_session_token_fn=None, get_user_features_fn=None):
    global _verify_session_token, _get_user_features
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


# ── Models ────────────────────────────────────────────────────────────────────


class DeploymentCreate(BaseModel):
    """Create a new deployment with rollback support."""

    name: str = Field(max_length=200)
    description: str = Field(default="", max_length=2000)
    group_id: int
    credential_id: int
    change_type: str = Field(default="template", max_length=50)
    # Bound both the number of commands and each command's length: these are
    # concatenated and pushed to devices, so an unbounded payload is a memory
    # and device-safety risk.
    proposed_commands: list[Annotated[str, Field(max_length=4000)]] = Field(default_factory=list, max_length=10000)
    template_id: int | None = None
    risk_analysis_id: int | None = None
    host_ids: list[int] = Field(default_factory=list, max_length=100000)


class DeploymentExecute(BaseModel):
    """Execute a planned deployment."""

    deployment_id: int


class DeploymentRollback(BaseModel):
    """Roll back a deployment to pre-deployment state."""

    deployment_id: int


class DeploymentApprovalDecision(ApprovalDecision):
    """Approve or reject a pending deployment approval."""


# Risk levels that auto-require human approval before execute.
_AUTO_APPROVAL_RISK_LEVELS = {"high", "critical"}


# ── Module-level state ────────────────────────────────────────────────────────

_deployment_jobs: dict[str, dict] = {}
_deployment_job_sockets: dict[str, list] = {}
_deployment_sockets_lock = asyncio.Lock()
_deployment_jobs_lock = asyncio.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_revert_commands(diff_text: str, baseline_text: str = "") -> list[str]:
    """Parse a unified diff and build the minimal set of config commands to revert drift.

    In the diff (baseline -> running-config):
      - Lines starting with '-' (not '---') = in baseline but missing from device -> re-add them
      - Lines starting with '+' (not '+++') = on device but not in baseline -> negate with 'no' prefix

    Context lines (unchanged, starting with ' ') are tracked so that indented
    sub-commands are emitted inside their correct config section (e.g.
    'interface GigabitEthernet0/1').  The optional *baseline_text* provides a
    fallback section lookup when the diff context window is too small.
    """
    # Build a section map from baseline text: indented line -> parent section header
    _section_map: dict[str, str] = {}
    if baseline_text:
        _cur = None
        for bline in baseline_text.splitlines():
            s = bline.strip()
            if not s or s.startswith("!") or s == "end":
                continue
            if not bline[0:1].isspace():
                _cur = bline.rstrip()
            elif _cur:
                _section_map[s] = _cur

    commands: list[str] = []
    current_section: str | None = None
    section_emitted = False

    def _ensure_section(cmd: str) -> None:
        """Emit the section header before an indented sub-command if needed."""
        nonlocal current_section, section_emitted
        if not (cmd and cmd[0].isspace()):
            return
        section = current_section or _section_map.get(cmd.strip())
        if section and not section_emitted:
            commands.append(section)
            section_emitted = True
            if not current_section:
                current_section = section

    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            current_section = None
            section_emitted = False
            continue

        # Context line - track section headers for proper config hierarchy
        if line.startswith(" "):
            ctx = line[1:]  # strip the leading diff space
            if ctx and not ctx[0].isspace():
                current_section = ctx.rstrip()
                section_emitted = False
            continue

        if line.startswith("-"):
            # Missing from device - re-add the baseline line
            cmd = line[1:]  # strip the leading '-'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            # A non-indented command is itself a section header
            if not cmd[0:1].isspace():
                current_section = cmd.rstrip()
                section_emitted = True  # the command itself enters the section
            else:
                _ensure_section(cmd)
            commands.append(cmd.rstrip())
        elif line.startswith("+"):
            # Present on device but not in baseline - negate it
            cmd = line[1:]  # strip the leading '+'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            _ensure_section(cmd)
            # Add 'no' prefix to remove the line, preserving indentation
            indent = cmd[: len(cmd) - len(cmd.lstrip())]
            if stripped.startswith("no "):
                # "no ..." line was added - removing it means re-adding without "no"
                commands.append(indent + stripped[3:])
            else:
                commands.append(indent + "no " + stripped)
    return commands


_MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB cap on in-memory output


async def _broadcast_deploy_line(job_id: str, line: str):
    job = _deployment_jobs[job_id]
    if len(job["output"]) < _MAX_OUTPUT_SIZE:
        job["output"] += line
    elif not job["output"].endswith("[output truncated]\n"):
        job["output"] += "[output truncated]\n"
    async with _deployment_sockets_lock:
        sockets = list(_deployment_job_sockets.get(job_id, []))
    dead = []
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json({"type": "line", "data": line}), timeout=5)
        except Exception:
            LOGGER.debug("deploy broadcast: dropping dead WS for job %s", job_id)
            dead.append(ws)
    if dead:
        async with _deployment_sockets_lock:
            for ws in dead:
                try:
                    _deployment_job_sockets[job_id].remove(ws)
                except (ValueError, KeyError) as exc:
                    LOGGER.debug("deploy broadcast: dead WS already removed for job %s: %s", job_id, exc)


async def _finish_deploy_job(job_id: str, status: str = "completed"):
    _deployment_jobs[job_id]["status"] = status
    async with _deployment_sockets_lock:
        sockets = list(_deployment_job_sockets.pop(job_id, []))
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json({"type": "job_complete", "status": status}), timeout=5)
        except Exception:
            LOGGER.debug("deploy finish: dropping dead WS for job %s", job_id)

    # Schedule cleanup of in-memory job state after 5 minutes
    async def _deferred_cleanup():
        await asyncio.sleep(300)
        async with _deployment_jobs_lock:
            _deployment_jobs.pop(job_id, None)

    asyncio.ensure_future(_deferred_cleanup())


async def _run_post_deployment_verification(
    job_id: str,
    deployment_id: int,
    hosts: list[dict],
    user: str,
):
    """Background task: wait, then run drift checks and metric health checks on deployed hosts."""
    try:
        await db.update_deployment_status(deployment_id, "verifying")
        await _broadcast_deploy_line(
            job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-deployment verification: "
            f"waiting {VERIFICATION_DELAY_SECONDS}s for metrics to settle...\n",
        )
        await asyncio.sleep(VERIFICATION_DELAY_SECONDS)

        # Retrieve pre-deployment metric baselines
        all_checkpoints = await db.get_deployment_checkpoints(deployment_id)
        baselines_by_host: dict[int, dict] = {}
        for cp in all_checkpoints:
            if cp.get("check_type") == "metric_baseline" and cp.get("phase") == "pre":
                try:
                    baselines_by_host[cp["host_id"]] = json.loads(cp.get("result", "{}"))
                except (json.JSONDecodeError, TypeError) as exc:
                    LOGGER.warning(
                        "deployment %s: failed to parse metric baseline for host %s: %s",
                        deployment_id,
                        cp.get("host_id"),
                        exc,
                    )

        all_passed = True
        now_iso = datetime.now(UTC).isoformat()
        five_min_ago = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()

        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            host_passed = True

            # Drift check
            drift_cp_id = None
            try:
                drift_cp_id = await db.create_deployment_checkpoint(
                    deployment_id,
                    phase="verify",
                    check_name=f"drift_check_{hostname}",
                    check_type="drift_check",
                    host_id=host["id"],
                )
                drift_result = await _analyze_drift_for_host(host["id"])
                status = "passed" if not drift_result.get("drifted") else "failed"
                if drift_result.get("drifted"):
                    host_passed = False
                await db.update_deployment_checkpoint(drift_cp_id, status, json.dumps(drift_result))
                label = "compliant" if status == "passed" else f"DRIFTED ({drift_result.get('diff_summary', '')})"
                await _broadcast_deploy_line(
                    job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift check for {hostname}: {label}\n"
                )
            except Exception as exc:
                if drift_cp_id is not None:
                    await db.update_deployment_checkpoint(drift_cp_id, "failed", json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(
                    job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift check failed for {hostname}: {exc}\n"
                )
                host_passed = False

            # Metric health check
            mh_cp_id = None
            try:
                mh_cp_id = await db.create_deployment_checkpoint(
                    deployment_id,
                    phase="verify",
                    check_name=f"metric_health_{hostname}",
                    check_type="metric_health",
                    host_id=host["id"],
                )
                baseline = baselines_by_host.get(host["id"], {})
                post_metrics: dict[str, float | None] = {}
                metric_details: list[dict] = []

                for metric_name in VERIFICATION_METRICS:
                    samples = await db.query_metric_samples(
                        metric_name,
                        host_ids=[host["id"]],
                        start=five_min_ago,
                        end=now_iso,
                        limit=50,
                    )
                    if samples:
                        avg_val = round(sum(s["value"] for s in samples) / len(samples), 2)
                        post_metrics[metric_name] = avg_val
                    else:
                        post_metrics[metric_name] = None

                    pre_val = baseline.get(metric_name)
                    post_val = post_metrics[metric_name]
                    delta = round(post_val - pre_val, 2) if pre_val is not None and post_val is not None else None
                    # Flag concern: >20% absolute increase for percentage metrics, >50% relative for others
                    concern = False
                    if delta is not None and pre_val is not None:
                        if metric_name.endswith("_pct") or metric_name.endswith("_percent"):
                            concern = delta > 20
                        elif pre_val > 0:
                            concern = delta / pre_val > 0.5
                    metric_details.append(
                        {
                            "metric": metric_name,
                            "pre": pre_val,
                            "post": post_val,
                            "delta": delta,
                            "concern": concern,
                        }
                    )

                any_concern = any(m["concern"] for m in metric_details)
                if any_concern:
                    host_passed = False
                mh_status = "passed" if not any_concern else "failed"
                await db.update_deployment_checkpoint(
                    mh_cp_id,
                    mh_status,
                    json.dumps({"baseline": baseline, "post": post_metrics, "details": metric_details}),
                )

                detail_str = (
                    ", ".join(
                        f"{m['metric']}={m['post']}" + (f" (+{m['delta']}!)" if m["concern"] else "")
                        for m in metric_details
                        if m["post"] is not None
                    )
                    or "no metrics available"
                )
                icon = "OK" if not any_concern else "CONCERN"
                await _broadcast_deploy_line(
                    job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Metric health for {hostname}: {icon} - {detail_str}\n",
                )
            except Exception as exc:
                if mh_cp_id is not None:
                    await db.update_deployment_checkpoint(mh_cp_id, "failed", json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(
                    job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Metric health check failed for {hostname}: {exc}\n",
                )
                host_passed = False

            if not host_passed:
                all_passed = False

        final_status = "verified" if all_passed else "verification_failed"
        await db.update_deployment_status(deployment_id, final_status)

        action = "deployment.verification.passed" if all_passed else "deployment.verification.failed"
        await _audit("deployments", action, user=user, detail=f"id={deployment_id} hosts={len(hosts)}")

        icon = "All checks passed" if all_passed else "Some checks flagged concerns"
        await _broadcast_deploy_line(
            job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Verification complete: {icon}. "
            f"Status set to '{final_status}'.\n",
        )

    except Exception as exc:
        LOGGER.error("post-deployment verification failed for deployment %d: %s", deployment_id, exc)
        await _broadcast_deploy_line(job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Verification error: {exc}\n")
        await db.update_deployment_status(deployment_id, "verification_failed")


async def _run_deployment_job(
    job_id: str,
    deployment_id: int,
    hosts: list[dict],
    commands: list[str],
    credentials: dict,
    user: str,
):
    """Background task: pre-check -> execute -> post-check deployment with checkpoint tracking."""
    try:
        await db.update_deployment_status(deployment_id, "pre-check")
        await _broadcast_deploy_line(
            job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting pre-deployment checks for {len(hosts)} host(s)...\n",
        )

        # ── Pre-deployment checkpoints: capture config snapshots ─────────
        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            cp_id = await db.create_deployment_checkpoint(
                deployment_id,
                phase="pre",
                check_name=f"config_capture_{hostname}",
                check_type="config_capture",
                host_id=host["id"],
            )
            try:
                await _broadcast_deploy_line(
                    job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing pre-deployment config for {hostname}...\n",
                )
                config_text = (await get_device_config(host, credentials, capture_method="deployment")).config_text
                await db.create_deployment_snapshot(deployment_id, host["id"], "pre", config_text)
                await db.update_deployment_checkpoint(cp_id, "passed", json.dumps({"config_length": len(config_text)}))

                # Capture metric baseline for post-deployment verification
                try:
                    now_iso = datetime.now(UTC).isoformat()
                    five_min_ago = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
                    baseline_metrics: dict[str, float | None] = {}
                    for metric_name in VERIFICATION_METRICS:
                        samples = await db.query_metric_samples(
                            metric_name,
                            host_ids=[host["id"]],
                            start=five_min_ago,
                            end=now_iso,
                            limit=50,
                        )
                        if samples:
                            avg_val = sum(s["value"] for s in samples) / len(samples)
                            baseline_metrics[metric_name] = round(avg_val, 2)
                        else:
                            baseline_metrics[metric_name] = None
                    mb_cp_id = await db.create_deployment_checkpoint(
                        deployment_id,
                        phase="pre",
                        check_name=f"metric_baseline_{hostname}",
                        check_type="metric_baseline",
                        host_id=host["id"],
                    )
                    await db.update_deployment_checkpoint(mb_cp_id, "passed", json.dumps(baseline_metrics))
                except Exception as mb_exc:
                    LOGGER.warning(
                        "deployment %d: metric baseline capture failed for %s: %s", deployment_id, hostname, mb_exc
                    )

                await _broadcast_deploy_line(
                    job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-check passed for {hostname} ({len(config_text)} chars captured).\n",
                )
            except Exception as exc:
                await db.update_deployment_checkpoint(cp_id, "failed", json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(
                    job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-check FAILED for {hostname}: {exc}\n"
                )
                await db.update_deployment_status(deployment_id, "failed")
                await _broadcast_deploy_line(
                    job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment aborted - pre-check failure.\n"
                )
                await _finish_deploy_job(job_id, "failed")
                return

        # ── Execute deployment ───────────────────────────────────────────
        await db.update_deployment_status(deployment_id, "executing")
        await _broadcast_deploy_line(
            job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-checks passed. Pushing config to {len(hosts)} host(s)...\n",
        )
        await _broadcast_deploy_line(
            job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Commands ({len(commands)}):\n"
        )
        for cmd in commands:
            await _broadcast_deploy_line(job_id, f"  {cmd}\n")

        failed_hosts = []
        successful_hosts = []
        sem = state.device_op_semaphore()

        async def _deploy_one(h):
            async with sem:
                hname = h.get("hostname", h["ip_address"])
                try:
                    await _broadcast_deploy_line(
                        job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pushing config to {hname}...\n"
                    )
                    await _push_config_to_device(h, credentials, commands)
                    await _broadcast_deploy_line(
                        job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Config pushed successfully to {hname}.\n"
                    )
                    successful_hosts.append(h)
                except Exception as exc:
                    await _broadcast_deploy_line(
                        job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] FAILED to push config to {hname}: {exc}\n"
                    )
                    failed_hosts.append(h)

        tasks = [_deploy_one(h) for h in hosts]
        await asyncio.gather(*tasks)

        if failed_hosts:
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {len(failed_hosts)} host(s) failed during execution.\n",
            )

        # ── Post-deployment checkpoints: re-capture and diff ─────────────
        await db.update_deployment_status(deployment_id, "post-check")
        await _broadcast_deploy_line(
            job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Running post-deployment checks...\n"
        )

        post_check_failures = 0
        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            cp_id = await db.create_deployment_checkpoint(
                deployment_id,
                phase="post",
                check_name=f"config_verify_{hostname}",
                check_type="config_verify",
                host_id=host["id"],
            )
            try:
                await _broadcast_deploy_line(
                    job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing post-deployment config for {hostname}...\n",
                )
                post_config = (await get_device_config(host, credentials, capture_method="deployment")).config_text
                await db.create_deployment_snapshot(deployment_id, host["id"], "post", post_config)

                # Get pre-snapshot for diff
                pre_snaps = await db.get_deployment_snapshots(deployment_id, phase="pre")
                pre_text = ""
                for s in pre_snaps:
                    if s["host_id"] == host["id"]:
                        pre_text = s.get("config_text", "")
                        break

                diff_text, diff_added, diff_removed = _compute_config_diff(
                    pre_text,
                    post_config,
                    baseline_label="pre-deployment",
                    actual_label="post-deployment",
                )
                changes_detected = diff_added + diff_removed
                result = {
                    "config_length": len(post_config),
                    "diff_lines_added": diff_added,
                    "diff_lines_removed": diff_removed,
                    "changes_detected": changes_detected,
                }
                if changes_detected > 0:
                    await db.update_deployment_checkpoint(cp_id, "passed", json.dumps(result))
                    await _broadcast_deploy_line(
                        job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check passed for {hostname}: +{diff_added}/-{diff_removed} lines changed.\n",
                    )
                else:
                    await db.update_deployment_checkpoint(cp_id, "passed", json.dumps(result))
                    await _broadcast_deploy_line(
                        job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check for {hostname}: no config diff detected (commands may already be present).\n",
                    )
            except Exception as exc:
                post_check_failures += 1
                await db.update_deployment_checkpoint(cp_id, "failed", json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(
                    job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check FAILED for {hostname}: {exc}\n"
                )

        # ── Final status ─────────────────────────────────────────────────
        if failed_hosts:
            final_status = "failed"
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment completed with errors. "
                f"{len(successful_hosts)} succeeded, {len(failed_hosts)} failed. "
                f"Rollback available from the deployment detail view.\n",
            )
        else:
            final_status = "completed"
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment completed successfully. "
                f"All {len(hosts)} host(s) updated. Pre/post snapshots saved for rollback.\n",
            )

        await db.update_deployment_status(deployment_id, final_status)
        await _finish_deploy_job(job_id, final_status)

        # Schedule post-deployment verification for successful deployments
        if final_status == "completed" and successful_hosts:
            supervise_task(
                asyncio.create_task(
                    _run_post_deployment_verification(
                        job_id,
                        deployment_id,
                        successful_hosts,
                        user,
                    )
                ),
                f"deployment post-verify {job_id}",
            )

    except Exception as exc:
        LOGGER.error("deployment job %s failed: %s", job_id, exc)
        await _broadcast_deploy_line(job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] DEPLOYMENT FAILED: {exc}\n")
        await db.update_deployment_status(deployment_id, "failed")
        await _finish_deploy_job(job_id, "failed")


async def _run_rollback_job(
    job_id: str,
    deployment_id: int,
    hosts: list[dict],
    credentials: dict,
    user: str,
):
    """Background task: restore pre-deployment configs to roll back a deployment."""
    try:
        await db.update_deployment_status(deployment_id, "rolling-back", rollback_status="in_progress")
        await _broadcast_deploy_line(
            job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting rollback for deployment #{deployment_id}...\n"
        )

        pre_snapshots = await db.get_deployment_snapshots(deployment_id, phase="pre")
        snap_by_host = {s["host_id"]: s for s in pre_snapshots}

        if not pre_snapshots:
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No pre-deployment snapshots found. Cannot rollback.\n",
            )
            await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
            await _finish_deploy_job(job_id, "failed")
            return

        rollback_failures = 0
        sem = state.device_op_semaphore()

        async def _rollback_one(host):
            nonlocal rollback_failures
            async with sem:
                hostname = host.get("hostname", host["ip_address"])
                snap = snap_by_host.get(host["id"])
                if not snap or not snap.get("config_text"):
                    await _broadcast_deploy_line(
                        job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No pre-deployment snapshot for {hostname}, skipping.\n",
                    )
                    return

                cp_id = await db.create_deployment_checkpoint(
                    deployment_id,
                    phase="rollback",
                    check_name=f"rollback_{hostname}",
                    check_type="config_restore",
                    host_id=host["id"],
                )

                try:
                    # Capture current config and compute diff to find what to revert
                    await _broadcast_deploy_line(
                        job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing current config for {hostname}...\n",
                    )
                    current_config = (
                        await get_device_config(host, credentials, capture_method="deployment")
                    ).config_text

                    diff_text, _, _ = _compute_config_diff(
                        snap["config_text"],
                        current_config,
                        baseline_label="pre-deployment",
                        actual_label="current",
                    )
                    revert_commands = _build_revert_commands(diff_text, snap.get("config_text", ""))

                    if not revert_commands:
                        await _broadcast_deploy_line(
                            job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: no differences to revert.\n",
                        )
                        await db.update_deployment_checkpoint(
                            cp_id, "passed", json.dumps({"message": "no changes needed"})
                        )
                        return

                    await _broadcast_deploy_line(
                        job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Reverting {len(revert_commands)} line(s) on {hostname}...\n",
                    )
                    await _push_config_to_device(host, credentials, revert_commands)

                    # Verify rollback
                    verify_config = (
                        await get_device_config(host, credentials, capture_method="deployment")
                    ).config_text
                    verify_diff, va, vr = _compute_config_diff(
                        snap["config_text"],
                        verify_config,
                        baseline_label="pre-deployment",
                        actual_label="after-rollback",
                    )
                    remaining = va + vr
                    if remaining == 0:
                        await _broadcast_deploy_line(
                            job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: rollback verified - config matches pre-deployment state.\n",
                        )
                        await db.update_deployment_checkpoint(
                            cp_id, "passed", json.dumps({"reverted_lines": len(revert_commands), "verified": True})
                        )
                    else:
                        await _broadcast_deploy_line(
                            job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: rollback applied but {remaining} diff line(s) remain.\n",
                        )
                        await db.update_deployment_checkpoint(
                            cp_id,
                            "passed",
                            json.dumps(
                                {"reverted_lines": len(revert_commands), "verified": False, "remaining_diff": remaining}
                            ),
                        )
                except Exception as exc:
                    rollback_failures += 1
                    await _broadcast_deploy_line(
                        job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ROLLBACK FAILED for {hostname}: {exc}\n"
                    )
                    await db.update_deployment_checkpoint(cp_id, "failed", json.dumps({"error": str(exc)}))

        tasks = [_rollback_one(h) for h in hosts]
        await asyncio.gather(*tasks)

        if rollback_failures > 0:
            await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Rollback completed with {rollback_failures} failure(s).\n",
            )
            await _finish_deploy_job(job_id, "failed")
        else:
            await db.update_deployment_status(deployment_id, "rolled-back", rollback_status="completed")
            await _broadcast_deploy_line(
                job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Rollback completed successfully. All hosts restored.\n",
            )
            await _finish_deploy_job(job_id, "completed")

    except Exception as exc:
        LOGGER.error("rollback job %s failed: %s", job_id, exc)
        await _broadcast_deploy_line(job_id, f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ROLLBACK FAILED: {exc}\n")
        await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
        await _finish_deploy_job(job_id, "failed")


# ── Routes ────────────────────────────────────────────────────────────────────


_DEPLOYMENT_NOT_FOUND = "Deployment not found"


def _deployment_host_ids(dep: dict) -> list[int]:
    """The deployment's stored target host ids (empty: its whole group)."""
    try:
        raw = json.loads(dep.get("host_ids") or "[]")
    except json.JSONDecodeError, TypeError:
        return []
    return [int(h) for h in raw if h is not None] if isinstance(raw, list) else []


async def _deployment_visible(scope: ObjectScope, dep: dict, *, write: bool = False) -> bool:
    """Whether a caller with ``scope`` may see ``dep`` (``write``: run, roll
    back or delete it): its inventory group and every target host must be
    readable; to change it, its target hosts (its group, when it names no
    hosts) must be writable. The SQL form of the read rule is
    ``routes.db.topology.deployment_scope_condition``."""
    if scope.unrestricted:
        return True
    if not scope.can_read_group(dep.get("group_id")):
        return False
    host_ids = set(_deployment_host_ids(dep))
    reach = await scope.reach()
    if not host_ids <= reach.read_hosts:
        return False
    if not write:
        return True
    return host_ids <= reach.write_hosts if host_ids else scope.can_write_group(dep.get("group_id"))


async def _require_deployment(request: Request, deployment_id: int, *, write: bool = False) -> dict:
    """The deployment; 404 when unknown or (scoped caller) not visible, 403
    on ``write`` when its targets are not writable."""
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail=_DEPLOYMENT_NOT_FOUND)
    scope = await request_scope(request)
    if scope.restricted:
        if not await _deployment_visible(scope, dep):
            raise HTTPException(status_code=404, detail=_DEPLOYMENT_NOT_FOUND)
        if write and not await _deployment_visible(scope, dep, write=True):
            raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)
    return dep


async def _resolve_deployment_credential(dep: dict, session: dict | None) -> dict:
    """Resolve and authorize the credential bound to a deployment.

    A deployment binds its credential at creation (validated there against the
    creator), so execute/rollback validate against the deployment's *creator*
    rather than whoever triggers the action — the approval workflow routinely
    has a different operator (or an admin) run a plan someone else created.
    allow_service=True lets a deployment use a shared service credential, the
    same as the unattended collectors. Legacy deployments with no recorded
    creator fall back to the live session.
    """
    created_by = (dep.get("created_by") or "").strip()
    if created_by and created_by.lower() != "unknown":
        return await require_credential_access(
            dep["credential_id"],
            submitter_username=created_by,
            allow_service=True,
        )
    return await require_credential_access(
        dep["credential_id"],
        session=session,
        allow_service=True,
    )


@router.post("/api/deployments")
@scoped("create")
async def create_deployment(body: DeploymentCreate, request: Request):
    """Create a new deployment plan (a scoped caller: the target hosts, or
    the group when no hosts are named, must be writable)."""
    session = _get_session(request)
    user = session["user"] if session else ""
    if (await request_scope(request)).restricted:
        await require_group(request, body.group_id, write=not body.host_ids)
        await require_host_ids(request, body.host_ids, write=True)
        if body.risk_analysis_id:
            await require_risk_analysis(request, body.risk_analysis_id)

    # Resolve commands from template if needed
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

    # Bind-time IDOR gate: the creator must own (or, for a service credential,
    # be an admin able to use) the credential they're attaching to this plan.
    await require_credential_access(body.credential_id, session=session, allow_service=True)

    return await plan_deployment(
        request,
        name=body.name,
        description=body.description,
        group_id=body.group_id,
        credential_id=body.credential_id,
        change_type=body.change_type,
        commands=commands,
        host_ids=body.host_ids,
        user=user,
        template_id=body.template_id,
        risk_analysis_id=body.risk_analysis_id,
    )


async def plan_deployment(
    request: Request,
    *,
    name: str,
    description: str,
    group_id: int,
    credential_id: int,
    change_type: str,
    commands: list[str],
    host_ids: list[int],
    user: str,
    template_id: int | None = None,
    risk_analysis_id: int | None = None,
) -> dict:
    """Store a deployment plan (status ``planning``), flag it for approval
    when its group or the group of any target host is a production group, or
    its risk analysis is high or critical, and audit it. The caller has
    checked the credential. Every route that creates a deployment (the
    deployments API, intended-config remediation, lab promote) goes here."""
    deployment_id = await db.create_deployment(
        name=name,
        description=description,
        group_id=group_id,
        credential_id=credential_id,
        change_type=change_type,
        proposed_commands="\n".join(commands),
        template_id=template_id,
        risk_analysis_id=risk_analysis_id,
        host_ids=json.dumps(host_ids),
        created_by=user,
    )

    # Auto-flag approval when (a) target group is marked production, or
    # (b) the linked risk analysis is high/critical. Flip approval_status
    # to 'pending' so the UI surfaces the gate immediately.
    require = False
    reason_bits: list[str] = []
    # The groups of the hosts actually targeted count, not only the named
    # group: hosts may be listed from another group.
    if await _production_groups(await _target_group_ids(group_id, host_ids)):
        require = True
        reason_bits.append("production group")
    if risk_analysis_id:
        analysis = await db.get_risk_analysis(risk_analysis_id)
        if analysis and (analysis.get("risk_level") or "").lower() in _AUTO_APPROVAL_RISK_LEVELS:
            require = True
            reason_bits.append(f"risk={analysis['risk_level']}")
    if require:
        await db.set_deployment_approval(
            deployment_id,
            requires_approval=True,
            approval_status="pending",
            request=True,
        )

    await _audit(
        "deployments",
        "deployment.created",
        user=user,
        detail=(
            f"id={deployment_id} name={name} group_id={group_id}"
            + (f" requires_approval=1 ({', '.join(reason_bits)})" if require else "")
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "id": deployment_id,
        "status": "planning",
        "requires_approval": require,
        "approval_status": "pending" if require else "not_required",
    }


async def _target_group_ids(group_id: int | None, host_ids: list[int] | None) -> list[int]:
    """The inventory groups a deployment touches: its named group and the
    group of every target host."""
    ids: list[int] = [int(group_id)] if group_id is not None else []
    for host in await db.get_hosts_by_ids([int(h) for h in host_ids]) if host_ids else []:
        if host.get("group_id") is not None:
            ids.append(int(host["group_id"]))
    return list(dict.fromkeys(ids))


async def _production_groups(group_ids: list[int]) -> list[int]:
    """The ids among ``group_ids`` of groups marked production."""
    production: list[int] = []
    for gid in group_ids:
        group = await db.get_group(gid)
        if group and (group.get("environment") or "").lower() == "production":
            production.append(gid)
    return production


def _stored_host_ids(dep: dict) -> list[int]:
    """A deployment row's ``host_ids`` JSON as a list (empty: the group)."""
    try:
        value = json.loads(dep.get("host_ids") or "[]")
    except TypeError, ValueError:
        return []
    return [int(h) for h in value] if isinstance(value, list) else []


async def _require_feature_too(request: Request, feature_key: str) -> None:
    """403 unless the caller (already past this router's ``deployments``
    gate) also holds ``feature_key``. Admins and the API token always do."""
    user = getattr(request.state, "auth_user", None)
    if not isinstance(user, dict) or user.get("role") == "admin":
        return  # the API token (no user record) or an admin
    features = getattr(request.state, "auth_features", None)
    if features is None and _get_user_features is not None:
        features = await _get_user_features(user)
    if feature_key not in (features or []):
        raise HTTPException(status_code=403, detail=f"Access denied for feature '{feature_key}'")


INTENDED_REMEDIATION_CHANGE_TYPE = "intended-remediation"


class IntendedRemediationDeploymentCreate(RemediationTargets):
    """Deployments from intended configuration remediation: one per host."""

    credential_id: int
    name: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=2000)


def _remediation_skip(row: dict, host: dict) -> str | None:
    """Why a host gets no deployment, or ``None``."""
    if row["state"] != "ok":
        return row["reason"]
    if not row["commands"]:
        return "The device already matches its intended configuration."
    if host.get("group_id") is None:
        return "The host is in no inventory group; a deployment targets one."
    if len(row["commands"]) > 10000 or any(len(c) > 4000 for c in row["commands"]):
        return "The remediation is too large for one deployment."
    return None


@router.post("/api/deployments/intended-remediation")
@scoped("hosts")
async def create_intended_remediation_deployments(body: IntendedRemediationDeploymentCreate, request: Request):
    """Plan one deployment per host from the remediation of its intended
    configuration (``netcontrol.routes.intended_config.remediation_for_hosts``).
    Needs Config Drift access too, and write on every host. The plans go
    through the usual pre-check, approval, execute and rollback flow; hosts
    with nothing to push, an unsupported driver or no comparison are
    skipped with the reason."""
    await _require_feature_too(request, "config-drift")
    session = _get_session(request)
    user = session["user"] if session else ""
    hosts = await resolve_remediation_targets(request, body, write=True)
    await require_credential_access(body.credential_id, session=session, allow_service=True)
    rows = await remediation_for_hosts(hosts)
    created: list[dict] = []
    skipped: list[dict] = []
    for host, row in zip(hosts, rows, strict=True):
        ref = {"host_id": row["host_id"], "hostname": row["hostname"]}
        reason = _remediation_skip(row, host)
        if reason is not None:
            skipped.append({**ref, "reason": reason})
            continue
        base = body.name.strip() or "Intended remediation"
        plan = await plan_deployment(
            request,
            name=(f"{base}: {row['hostname']}" if len(hosts) > 1 or not body.name.strip() else base)[:200],
            description=body.description
            or (
                f"Remediation of {row['hostname']} to its intended configuration "
                f"(template {row['template_name']}, backup {row['backup']['id']}): "
                f"{row['added']} added, {row['removed']} removed."
            ),
            group_id=int(host["group_id"]),
            credential_id=body.credential_id,
            change_type=INTENDED_REMEDIATION_CHANGE_TYPE,
            commands=row["commands"],
            host_ids=[row["host_id"]],
            user=user,
        )
        created.append({**ref, **plan, "commands": len(row["commands"])})
    await _audit(
        "deployments",
        "deployment.intended_remediation",
        user=user,
        detail=f"hosts={len(hosts)} created={len(created)} skipped={len(skipped)}",
        correlation_id=_corr_id(request),
    )
    return {"deployments": created, "skipped": skipped}


@router.get("/api/deployments")
@scoped("list")
async def list_deployments(
    request: Request,
    status: str | None = Query(default=None),
    group_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    return await db.get_deployments(status=status, group_id=group_id, limit=limit, **await group_filter(request))


@router.get("/api/deployments/summary")
@scoped("list")
async def get_deployment_summary_endpoint(request: Request):
    return await db.get_deployment_summary(**await group_filter(request))


@router.get("/api/deployments/{deployment_id}")
@scoped("deployment")
async def get_deployment_detail(deployment_id: int, request: Request):
    dep = await _require_deployment(request, deployment_id)
    await require_owner_or_admin(request, dep.get("created_by"))
    checkpoints = await db.get_deployment_checkpoints(deployment_id)
    snapshots = await db.get_deployment_snapshots(deployment_id)
    return {**dep, "checkpoints": checkpoints, "snapshots": snapshots}


@router.get("/api/deployments/{deployment_id}/correlation")
@scoped("deployment")
async def get_deployment_correlation(deployment_id: int, request: Request):
    """Return correlated events (drift, alerts, audit trail) around a deployment."""
    dep = await _require_deployment(request, deployment_id)
    await require_owner_or_admin(request, dep.get("created_by"))

    started = dep.get("started_at") or dep.get("created_at")
    finished = dep.get("finished_at")
    window_start = (datetime.fromisoformat(started) - timedelta(minutes=5)).isoformat() if started else None
    window_end = (
        (datetime.fromisoformat(finished) + timedelta(minutes=30)).isoformat()
        if finished
        else datetime.now(UTC).isoformat()
    )

    host_ids: list[int] = []
    try:
        host_ids = json.loads(dep.get("host_ids") or "[]")
    except (json.JSONDecodeError, TypeError) as exc:
        LOGGER.warning("deployment %s: failed to parse host_ids: %s", deployment_id, exc)

    checkpoints = await db.get_deployment_checkpoints(deployment_id)
    drift_events = (
        await db.get_config_drift_events_in_range(host_ids, window_start, window_end)
        if host_ids and window_start
        else []
    )
    alerts = (
        await db.get_monitoring_alerts_in_range(host_ids, window_start, window_end) if host_ids and window_start else []
    )
    audit_trail = (
        await db.get_audit_events_for_deployment(deployment_id, window_start, window_end) if window_start else []
    )

    return {
        "deployment": dep,
        "checkpoints": checkpoints,
        "drift_events": drift_events,
        "alerts": alerts,
        "audit_trail": audit_trail,
        "time_window": {"start": window_start, "end": window_end},
    }


@router.post("/api/deployments/{deployment_id}/execute")
@scoped("deployment")
async def execute_deployment(deployment_id: int, request: Request):
    """Execute a planned deployment with pre/post checkpoints."""
    dep = await _require_deployment(request, deployment_id, write=True)
    if dep["status"] not in ("planning", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot execute deployment in '{dep['status']}' status")

    await require_owner_or_admin(request, dep.get("created_by"))
    session = _get_session(request)
    user = session["user"] if session else ""

    # The groups of the hosts this run touches (see plan_deployment). A host
    # moved into a production group after planning still needs approval.
    target_groups = await _target_group_ids(dep["group_id"], _stored_host_ids(dep))
    if not dep.get("requires_approval") and await _production_groups(target_groups):
        await db.set_deployment_approval(deployment_id, requires_approval=True, approval_status="pending", request=True)
        await _audit(
            "deployments",
            "deployment.execute_blocked",
            user=user,
            detail=f"id={deployment_id} reason=production_target approval_requested=1",
            correlation_id=_corr_id(request),
        )
        raise HTTPException(
            status_code=403,
            detail="Deployment targets a production group and requires approval before execute (status=pending)",
        )

    # ── Approval gate ────────────────────────────────────────────────────────
    if dep.get("requires_approval"):
        status = dep.get("approval_status") or "pending"
        if status != "approved":
            await _audit(
                "deployments",
                "deployment.execute_blocked",
                user=user,
                detail=f"id={deployment_id} reason=approval_status={status}",
                correlation_id=_corr_id(request),
            )
            raise HTTPException(
                status_code=403,
                detail=f"Deployment requires approval before execute (status={status})",
            )

    # ── Maintenance window gate ──────────────────────────────────────────────
    verdict = await evaluate_change_gate(target_groups)
    if not verdict["allowed"]:
        await _audit(
            "deployments",
            "deployment.execute_blocked",
            user=user,
            detail=f"id={deployment_id} reason=maintenance_window window_id={verdict['window']['id'] if verdict.get('window') else ''}",
            correlation_id=_corr_id(request),
        )
        raise HTTPException(status_code=409, detail=verdict["reason"])
    if verdict.get("warning"):
        await _audit(
            "deployments",
            "deployment.execute_outside_window",
            user=user,
            detail=f"id={deployment_id} warning={verdict['warning']}",
            correlation_id=_corr_id(request),
        )

    # Resolve credentials against the deployment's creator (see helper).
    cred = await _resolve_deployment_credential(dep, session)
    credentials = {
        "username": cred["username"],
        "password": decrypt(cred["password"]),
        "secret": decrypt(cred["secret"]) if cred["secret"] else "",
    }

    # Resolve hosts
    host_ids = json.loads(dep.get("host_ids", "[]") or "[]")
    if host_ids:
        hosts = await db.get_hosts_by_ids(host_ids)
    else:
        hosts = await db.get_hosts_for_group(dep["group_id"])
    if not hosts:
        raise HTTPException(status_code=400, detail="No target hosts found")

    commands = [line for line in dep["proposed_commands"].splitlines() if line.strip()]

    # Atomically claim the deployment so two concurrent execute calls cannot
    # both push commands to the devices (TOCTOU on the status check above).
    if not await db.claim_deployment_for_execute(deployment_id):
        raise HTTPException(
            status_code=409,
            detail="Deployment is already executing or was just executed",
        )

    job_id = str(uuid.uuid4())
    _deployment_jobs[job_id] = {
        "status": "running",
        "output": "",
        "deployment_id": deployment_id,
        "action": "execute",
    }
    _deployment_job_sockets[job_id] = []

    supervise_task(
        asyncio.create_task(_run_deployment_job(job_id, deployment_id, hosts, commands, credentials, user)),
        f"deployment job {job_id}",
    )

    await _audit(
        "deployments",
        "deployment.executed",
        user=user,
        detail=f"id={deployment_id} job_id={job_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "deployment_id": deployment_id}


@router.post("/api/deployments/{deployment_id}/request-approval")
@scoped("deployment")
async def request_deployment_approval(deployment_id: int, request: Request):
    """Flip an unflagged deployment into the approval workflow. Useful
    when ops decides post-hoc that a deployment needs four-eyes review
    even though no auto-rule fired."""
    dep = await _require_deployment(request, deployment_id, write=True)
    if dep["status"] not in ("planning", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot request approval in '{dep['status']}' status")
    if dep.get("approval_status") == "pending":
        return {"ok": True, "approval_status": "pending"}
    await db.set_deployment_approval(
        deployment_id,
        requires_approval=True,
        approval_status="pending",
        request=True,
    )
    session = _get_session(request)
    user = session["user"] if session else ""
    await _audit(
        "deployments",
        "deployment.approval_requested",
        user=user,
        detail=f"id={deployment_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "approval_status": "pending"}


@router.post("/api/deployments/{deployment_id}/approve")
@scoped("deployment")
async def approve_deployment(deployment_id: int, body: DeploymentApprovalDecision, request: Request):
    """Approve a deployment. The approver must be different from the
    deployment's creator (four-eyes)."""
    dep = await _require_deployment(request, deployment_id)
    if not dep.get("requires_approval"):
        raise HTTPException(status_code=400, detail="Deployment does not require approval")
    if dep.get("approval_status") != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot approve deployment with approval_status='{dep.get('approval_status')}'",
        )
    # Approval is a privileged change-control action: require admin (or the
    # server API token). This closes the gap where any deployments-feature
    # holder could approve a deployment they had no part in.
    await require_owner_or_admin(request, None)
    session = _get_session(request)
    user = session["user"] if session else ""
    require_different_approver(user, dep.get("created_by"))
    await db.set_deployment_approval(
        deployment_id,
        approval_status="approved",
        approved_by=user,
        approval_comment=body.comment,
    )
    await _audit(
        "deployments",
        "deployment.approved",
        user=user,
        detail=decision_audit_detail(f"id={deployment_id}", body.comment),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "approval_status": "approved"}


@router.post("/api/deployments/{deployment_id}/reject")
@scoped("deployment")
async def reject_deployment(deployment_id: int, body: DeploymentApprovalDecision, request: Request):
    """Reject a deployment's approval request. The deployment stays in
    'planning' but cannot be executed until a fresh approval request is
    raised."""
    dep = await _require_deployment(request, deployment_id)
    if not dep.get("requires_approval"):
        raise HTTPException(status_code=400, detail="Deployment does not require approval")
    if dep.get("approval_status") != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reject deployment with approval_status='{dep.get('approval_status')}'",
        )
    await require_owner_or_admin(request, None)
    session = _get_session(request)
    user = session["user"] if session else ""
    await db.set_deployment_approval(
        deployment_id,
        approval_status="rejected",
        approved_by=user,
        approval_comment=body.comment,
    )
    await _audit(
        "deployments",
        "deployment.approval_rejected",
        user=user,
        detail=decision_audit_detail(f"id={deployment_id}", body.comment),
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "approval_status": "rejected"}


@router.post("/api/deployments/{deployment_id}/rollback")
@scoped("deployment")
async def rollback_deployment(deployment_id: int, request: Request):
    """Roll back a deployment using pre-deployment snapshots."""
    dep = await _require_deployment(request, deployment_id, write=True)
    if dep["status"] not in ("completed", "failed", "post-check"):
        raise HTTPException(status_code=400, detail=f"Cannot rollback deployment in '{dep['status']}' status")

    await require_owner_or_admin(request, dep.get("created_by"))
    session = _get_session(request)
    user = session["user"] if session else ""

    cred = await _resolve_deployment_credential(dep, session)
    credentials = {
        "username": cred["username"],
        "password": decrypt(cred["password"]),
        "secret": decrypt(cred["secret"]) if cred["secret"] else "",
    }

    host_ids = json.loads(dep.get("host_ids", "[]") or "[]")
    if host_ids:
        hosts = await db.get_hosts_by_ids(host_ids)
    else:
        hosts = await db.get_hosts_for_group(dep["group_id"])
    if not hosts:
        raise HTTPException(status_code=400, detail="No target hosts found")

    job_id = str(uuid.uuid4())
    _deployment_jobs[job_id] = {
        "status": "running",
        "output": "",
        "deployment_id": deployment_id,
        "action": "rollback",
    }
    _deployment_job_sockets[job_id] = []

    supervise_task(
        asyncio.create_task(_run_rollback_job(job_id, deployment_id, hosts, credentials, user)),
        f"rollback job {job_id}",
    )

    await _audit(
        "deployments",
        "deployment.rollback",
        user=user,
        detail=f"id={deployment_id} job_id={job_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "deployment_id": deployment_id}


@router.delete("/api/deployments/{deployment_id}")
@scoped("deployment")
async def delete_deployment_endpoint(deployment_id: int, request: Request):
    dep = await _require_deployment(request, deployment_id, write=True)
    if dep["status"] in ("executing", "pre-check", "post-check", "rolling-back"):
        raise HTTPException(status_code=400, detail="Cannot delete an active deployment")
    await require_owner_or_admin(request, dep.get("created_by"))
    await db.delete_deployment(deployment_id)
    session = _get_session(request)
    await _audit(
        "deployments",
        "deployment.deleted",
        user=session["user"] if session else "",
        detail=f"id={deployment_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.get("/api/deployments/job/{job_id}/status")
@scoped("deployment")
async def get_deployment_job_status(job_id: str, request: Request):
    job = _deployment_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Deployment job not found")
    scope = await request_scope(request)
    if scope.restricted:
        dep = await db.get_deployment(job["deployment_id"]) if job.get("deployment_id") else None
        if not dep or not await _deployment_visible(scope, dep):
            raise HTTPException(status_code=404, detail="Deployment job not found")
    return {
        "job_id": job_id,
        "status": job["status"],
        "output": job["output"],
        "deployment_id": job.get("deployment_id"),
        "action": job.get("action", "execute"),
    }


@ws_router.websocket("/ws/deployment/{job_id}")
@scoped("deployment")
async def ws_deployment(websocket: WebSocket, job_id: str):
    """WebSocket for streaming deployment/rollback job output."""
    token = websocket.cookies.get("session")
    if not token:
        await websocket.close(code=1008)
        return
    session = await verify_ws_session(token)
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user) if _get_user_features else []
    if user.get("role") != "admin" and "deployments" not in features:
        await websocket.close(code=1008)
        return

    # Object-level authorization: non-admins may only stream deployments they
    # created. The stream carries device config push/rollback output.
    if user.get("role") != "admin":
        deployment_id = (_deployment_jobs.get(job_id, {}) or {}).get("deployment_id")
        dep = await db.get_deployment(deployment_id) if deployment_id else None
        if not dep or dep.get("created_by") != session.get("user"):
            await websocket.close(code=1008)
            return
        # Object scope: every target of the deployment must be readable.
        if not await _deployment_visible(await ws_scope(session), dep):
            await websocket.close(code=1008)
            return

    await websocket.accept()
    async with _deployment_sockets_lock:
        if job_id not in _deployment_job_sockets:
            _deployment_job_sockets[job_id] = []
        _deployment_job_sockets[job_id].append(websocket)

    # Send any existing output
    job = _deployment_jobs.get(job_id, {})
    if job.get("output"):
        try:
            await websocket.send_json({"type": "line", "data": job["output"]})
        except Exception as exc:
            LOGGER.debug("deploy WS: failed to send buffered output for job %s: %s", job_id, exc)
    if job.get("status") in ("completed", "failed"):
        try:
            await websocket.send_json({"type": "job_complete", "status": job["status"]})
        except Exception as exc:
            LOGGER.debug("deploy WS: failed to send job_complete for job %s: %s", job_id, exc)

    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=120)
            except TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect as exc:
        LOGGER.debug("deploy WS: client disconnected for job %s: %s", job_id, exc)
    finally:
        async with _deployment_sockets_lock:
            if job_id in _deployment_job_sockets:
                try:
                    _deployment_job_sockets[job_id].remove(websocket)
                except ValueError as exc:
                    LOGGER.debug("deploy WS: socket already removed for job %s: %s", job_id, exc)
