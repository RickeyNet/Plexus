"""
deployments.py -- Deployment orchestration with rollback support.

Includes deployment creation, execution with pre/post checkpoints,
rollback via pre-deployment snapshots, and WebSocket streaming.
"""

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from routes.crypto import decrypt

from netcontrol.routes.shared import (
    _audit,
    _capture_running_config,
    _compute_config_diff,
    _corr_id,
    _get_session,
    _push_config_to_device,
)
from netcontrol.routes.config_drift import _analyze_drift_for_host
from netcontrol.telemetry import configure_logging

router = APIRouter()
ws_router = APIRouter()  # WebSocket routes — registered without HTTP auth dependency
LOGGER = configure_logging("plexus.deployments")

VERIFICATION_METRICS = ["cpu_percent", "memory_percent", "packet_loss_pct", "response_time_ms"]
VERIFICATION_DELAY_SECONDS = 60

# ── Late-binding auth dependencies (injected by app.py) ──────────────────────

_require_auth = None
_require_feature = None
_verify_session_token = None
_get_user_features = None


def init_deployments(require_auth, require_feature, verify_session_token_fn=None, get_user_features_fn=None):
    global _require_auth, _require_feature, _verify_session_token, _get_user_features
    _require_auth = require_auth
    _require_feature = require_feature
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


# ── Models ────────────────────────────────────────────────────────────────────


class DeploymentCreate(BaseModel):
    """Create a new deployment with rollback support."""
    name: str
    description: str = ""
    group_id: int
    credential_id: int
    change_type: str = "template"
    proposed_commands: list[str] = []
    template_id: int | None = None
    risk_analysis_id: int | None = None
    host_ids: list[int] = []


class DeploymentExecute(BaseModel):
    """Execute a planned deployment."""
    deployment_id: int


class DeploymentRollback(BaseModel):
    """Roll back a deployment to pre-deployment state."""
    deployment_id: int


# ── Module-level state ────────────────────────────────────────────────────────

_deployment_jobs: dict[str, dict] = {}
_deployment_job_sockets: dict[str, list] = {}


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

        # Context line — track section headers for proper config hierarchy
        if line.startswith(" "):
            ctx = line[1:]  # strip the leading diff space
            if ctx and not ctx[0].isspace():
                current_section = ctx.rstrip()
                section_emitted = False
            continue

        if line.startswith("-"):
            # Missing from device — re-add the baseline line
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
            # Present on device but not in baseline — negate it
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
                # "no ..." line was added — removing it means re-adding without "no"
                commands.append(indent + stripped[3:])
            else:
                commands.append(indent + "no " + stripped)
    return commands


async def _broadcast_deploy_line(job_id: str, line: str):
    _deployment_jobs[job_id]["output"] += line
    for ws in list(_deployment_job_sockets.get(job_id, [])):
        try:
            await ws.send_json({"type": "line", "data": line})
        except Exception:
            _deployment_job_sockets[job_id].remove(ws)


async def _finish_deploy_job(job_id: str, status: str = "completed"):
    _deployment_jobs[job_id]["status"] = status
    for ws in list(_deployment_job_sockets.get(job_id, [])):
        try:
            await ws.send_json({"type": "job_complete", "status": status})
        except Exception:
            pass


async def _run_post_deployment_verification(
    job_id: str, deployment_id: int, hosts: list[dict], user: str,
):
    """Background task: wait, then run drift checks and metric health checks on deployed hosts."""
    try:
        await db.update_deployment_status(deployment_id, "verifying")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-deployment verification: "
            f"waiting {VERIFICATION_DELAY_SECONDS}s for metrics to settle...\n")
        await asyncio.sleep(VERIFICATION_DELAY_SECONDS)

        # Retrieve pre-deployment metric baselines
        all_checkpoints = await db.get_deployment_checkpoints(deployment_id)
        baselines_by_host: dict[int, dict] = {}
        for cp in all_checkpoints:
            if cp.get("check_type") == "metric_baseline" and cp.get("phase") == "pre":
                try:
                    baselines_by_host[cp["host_id"]] = json.loads(cp.get("result", "{}"))
                except (json.JSONDecodeError, TypeError):
                    pass

        all_passed = True
        now_iso = datetime.now(UTC).isoformat()
        five_min_ago = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()

        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            host_passed = True

            # Drift check
            try:
                drift_cp_id = await db.create_deployment_checkpoint(
                    deployment_id, phase="verify", check_name=f"drift_check_{hostname}",
                    check_type="drift_check", host_id=host["id"],
                )
                drift_result = await _analyze_drift_for_host(host["id"])
                status = "passed" if not drift_result.get("drifted") else "failed"
                if drift_result.get("drifted"):
                    host_passed = False
                await db.update_deployment_checkpoint(drift_cp_id, status, json.dumps(drift_result))
                label = "compliant" if status == "passed" else f"DRIFTED ({drift_result.get('diff_summary', '')})"
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift check for {hostname}: {label}\n")
            except Exception as exc:
                await db.update_deployment_checkpoint(drift_cp_id, "failed",
                    json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift check failed for {hostname}: {exc}\n")
                host_passed = False

            # Metric health check
            try:
                mh_cp_id = await db.create_deployment_checkpoint(
                    deployment_id, phase="verify", check_name=f"metric_health_{hostname}",
                    check_type="metric_health", host_id=host["id"],
                )
                baseline = baselines_by_host.get(host["id"], {})
                post_metrics: dict[str, float | None] = {}
                metric_details: list[dict] = []

                for metric_name in VERIFICATION_METRICS:
                    samples = await db.query_metric_samples(
                        metric_name, host_ids=[host["id"]], start=five_min_ago, end=now_iso, limit=50,
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
                    metric_details.append({
                        "metric": metric_name, "pre": pre_val, "post": post_val,
                        "delta": delta, "concern": concern,
                    })

                any_concern = any(m["concern"] for m in metric_details)
                if any_concern:
                    host_passed = False
                mh_status = "passed" if not any_concern else "failed"
                await db.update_deployment_checkpoint(mh_cp_id, mh_status,
                    json.dumps({"baseline": baseline, "post": post_metrics, "details": metric_details}))

                detail_str = ", ".join(
                    f"{m['metric']}={m['post']}" + (f" (+{m['delta']}!)" if m["concern"] else "")
                    for m in metric_details if m["post"] is not None
                ) or "no metrics available"
                icon = "OK" if not any_concern else "CONCERN"
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Metric health for {hostname}: {icon} — {detail_str}\n")
            except Exception as exc:
                await db.update_deployment_checkpoint(mh_cp_id, "failed",
                    json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Metric health check failed for {hostname}: {exc}\n")
                host_passed = False

            if not host_passed:
                all_passed = False

        final_status = "verified" if all_passed else "verification_failed"
        await db.update_deployment_status(deployment_id, final_status)

        action = "deployment.verification.passed" if all_passed else "deployment.verification.failed"
        await _audit("deployments", action, user=user,
                     detail=f"id={deployment_id} hosts={len(hosts)}")

        icon = "All checks passed" if all_passed else "Some checks flagged concerns"
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Verification complete: {icon}. "
            f"Status set to '{final_status}'.\n")

    except Exception as exc:
        LOGGER.error("post-deployment verification failed for deployment %d: %s", deployment_id, exc)
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Verification error: {exc}\n")
        await db.update_deployment_status(deployment_id, "verification_failed")


async def _run_deployment_job(
    job_id: str, deployment_id: int, hosts: list[dict],
    commands: list[str], credentials: dict, user: str,
):
    """Background task: pre-check -> execute -> post-check deployment with checkpoint tracking."""
    try:
        await db.update_deployment_status(deployment_id, "pre-check")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting pre-deployment checks for {len(hosts)} host(s)...\n")

        # ── Pre-deployment checkpoints: capture config snapshots ─────────
        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            cp_id = await db.create_deployment_checkpoint(
                deployment_id, phase="pre", check_name=f"config_capture_{hostname}",
                check_type="config_capture", host_id=host["id"],
            )
            try:
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing pre-deployment config for {hostname}...\n")
                config_text = await _capture_running_config(host, credentials)
                await db.create_deployment_snapshot(deployment_id, host["id"], "pre", config_text)
                await db.update_deployment_checkpoint(cp_id, "passed",
                    json.dumps({"config_length": len(config_text)}))

                # Capture metric baseline for post-deployment verification
                try:
                    now_iso = datetime.now(UTC).isoformat()
                    five_min_ago = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
                    baseline_metrics: dict[str, float | None] = {}
                    for metric_name in VERIFICATION_METRICS:
                        samples = await db.query_metric_samples(
                            metric_name, host_ids=[host["id"]], start=five_min_ago, end=now_iso, limit=50,
                        )
                        if samples:
                            avg_val = sum(s["value"] for s in samples) / len(samples)
                            baseline_metrics[metric_name] = round(avg_val, 2)
                        else:
                            baseline_metrics[metric_name] = None
                    mb_cp_id = await db.create_deployment_checkpoint(
                        deployment_id, phase="pre", check_name=f"metric_baseline_{hostname}",
                        check_type="metric_baseline", host_id=host["id"],
                    )
                    await db.update_deployment_checkpoint(mb_cp_id, "passed", json.dumps(baseline_metrics))
                except Exception as mb_exc:
                    LOGGER.warning("deployment %d: metric baseline capture failed for %s: %s",
                                   deployment_id, hostname, mb_exc)

                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-check passed for {hostname} ({len(config_text)} chars captured).\n")
            except Exception as exc:
                await db.update_deployment_checkpoint(cp_id, "failed",
                    json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-check FAILED for {hostname}: {exc}\n")
                await db.update_deployment_status(deployment_id, "failed")
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment aborted — pre-check failure.\n")
                await _finish_deploy_job(job_id, "failed")
                return

        # ── Execute deployment ───────────────────────────────────────────
        await db.update_deployment_status(deployment_id, "executing")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pre-checks passed. Pushing config to {len(hosts)} host(s)...\n")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Commands ({len(commands)}):\n")
        for cmd in commands:
            await _broadcast_deploy_line(job_id, f"  {cmd}\n")

        failed_hosts = []
        successful_hosts = []
        sem = asyncio.Semaphore(4)

        async def _deploy_one(h):
            async with sem:
                hname = h.get("hostname", h["ip_address"])
                try:
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Pushing config to {hname}...\n")
                    await _push_config_to_device(h, credentials, commands)
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Config pushed successfully to {hname}.\n")
                    successful_hosts.append(h)
                except Exception as exc:
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] FAILED to push config to {hname}: {exc}\n")
                    failed_hosts.append(h)

        tasks = [_deploy_one(h) for h in hosts]
        await asyncio.gather(*tasks)

        if failed_hosts:
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {len(failed_hosts)} host(s) failed during execution.\n")

        # ── Post-deployment checkpoints: re-capture and diff ─────────────
        await db.update_deployment_status(deployment_id, "post-check")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Running post-deployment checks...\n")

        post_check_failures = 0
        for host in hosts:
            hostname = host.get("hostname", host["ip_address"])
            cp_id = await db.create_deployment_checkpoint(
                deployment_id, phase="post", check_name=f"config_verify_{hostname}",
                check_type="config_verify", host_id=host["id"],
            )
            try:
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing post-deployment config for {hostname}...\n")
                post_config = await _capture_running_config(host, credentials)
                await db.create_deployment_snapshot(deployment_id, host["id"], "post", post_config)

                # Get pre-snapshot for diff
                pre_snaps = await db.get_deployment_snapshots(deployment_id, phase="pre")
                pre_text = ""
                for s in pre_snaps:
                    if s["host_id"] == host["id"]:
                        pre_text = s.get("config_text", "")
                        break

                diff_text, diff_added, diff_removed = _compute_config_diff(
                    pre_text, post_config,
                    baseline_label="pre-deployment", actual_label="post-deployment",
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
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check passed for {hostname}: +{diff_added}/-{diff_removed} lines changed.\n")
                else:
                    await db.update_deployment_checkpoint(cp_id, "passed", json.dumps(result))
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check for {hostname}: no config diff detected (commands may already be present).\n")
            except Exception as exc:
                post_check_failures += 1
                await db.update_deployment_checkpoint(cp_id, "failed",
                    json.dumps({"error": str(exc)}))
                await _broadcast_deploy_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Post-check FAILED for {hostname}: {exc}\n")

        # ── Final status ─────────────────────────────────────────────────
        if failed_hosts:
            final_status = "failed"
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment completed with errors. "
                f"{len(successful_hosts)} succeeded, {len(failed_hosts)} failed. "
                f"Rollback available from the deployment detail view.\n")
        else:
            final_status = "completed"
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment completed successfully. "
                f"All {len(hosts)} host(s) updated. Pre/post snapshots saved for rollback.\n")

        await db.update_deployment_status(deployment_id, final_status)
        await _finish_deploy_job(job_id, final_status)

        # Schedule post-deployment verification for successful deployments
        if final_status == "completed" and successful_hosts:
            asyncio.create_task(_run_post_deployment_verification(
                job_id, deployment_id, successful_hosts, user,
            ))

    except Exception as exc:
        LOGGER.error("deployment job %s failed: %s", job_id, exc)
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] DEPLOYMENT FAILED: {exc}\n")
        await db.update_deployment_status(deployment_id, "failed")
        await _finish_deploy_job(job_id, "failed")


async def _run_rollback_job(
    job_id: str, deployment_id: int, hosts: list[dict], credentials: dict, user: str,
):
    """Background task: restore pre-deployment configs to roll back a deployment."""
    try:
        await db.update_deployment_status(deployment_id, "rolling-back", rollback_status="in_progress")
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting rollback for deployment #{deployment_id}...\n")

        pre_snapshots = await db.get_deployment_snapshots(deployment_id, phase="pre")
        snap_by_host = {s["host_id"]: s for s in pre_snapshots}

        if not pre_snapshots:
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No pre-deployment snapshots found. Cannot rollback.\n")
            await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
            await _finish_deploy_job(job_id, "failed")
            return

        rollback_failures = 0
        sem = asyncio.Semaphore(4)

        async def _rollback_one(host):
            nonlocal rollback_failures
            async with sem:
                hostname = host.get("hostname", host["ip_address"])
                snap = snap_by_host.get(host["id"])
                if not snap or not snap.get("config_text"):
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No pre-deployment snapshot for {hostname}, skipping.\n")
                    return

                cp_id = await db.create_deployment_checkpoint(
                    deployment_id, phase="rollback", check_name=f"rollback_{hostname}",
                    check_type="config_restore", host_id=host["id"],
                )

                try:
                    # Capture current config and compute diff to find what to revert
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capturing current config for {hostname}...\n")
                    current_config = await _capture_running_config(host, credentials)

                    diff_text, _, _ = _compute_config_diff(
                        snap["config_text"], current_config,
                        baseline_label="pre-deployment", actual_label="current",
                    )
                    revert_commands = _build_revert_commands(diff_text, snap.get("config_text", ""))

                    if not revert_commands:
                        await _broadcast_deploy_line(job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: no differences to revert.\n")
                        await db.update_deployment_checkpoint(cp_id, "passed",
                            json.dumps({"message": "no changes needed"}))
                        return

                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Reverting {len(revert_commands)} line(s) on {hostname}...\n")
                    await _push_config_to_device(host, credentials, revert_commands)

                    # Verify rollback
                    verify_config = await _capture_running_config(host, credentials)
                    verify_diff, va, vr = _compute_config_diff(
                        snap["config_text"], verify_config,
                        baseline_label="pre-deployment", actual_label="after-rollback",
                    )
                    remaining = va + vr
                    if remaining == 0:
                        await _broadcast_deploy_line(job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: rollback verified — config matches pre-deployment state.\n")
                        await db.update_deployment_checkpoint(cp_id, "passed",
                            json.dumps({"reverted_lines": len(revert_commands), "verified": True}))
                    else:
                        await _broadcast_deploy_line(job_id,
                            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {hostname}: rollback applied but {remaining} diff line(s) remain.\n")
                        await db.update_deployment_checkpoint(cp_id, "passed",
                            json.dumps({"reverted_lines": len(revert_commands), "verified": False, "remaining_diff": remaining}))
                except Exception as exc:
                    rollback_failures += 1
                    await _broadcast_deploy_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ROLLBACK FAILED for {hostname}: {exc}\n")
                    await db.update_deployment_checkpoint(cp_id, "failed",
                        json.dumps({"error": str(exc)}))

        tasks = [_rollback_one(h) for h in hosts]
        await asyncio.gather(*tasks)

        if rollback_failures > 0:
            await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Rollback completed with {rollback_failures} failure(s).\n")
            await _finish_deploy_job(job_id, "failed")
        else:
            await db.update_deployment_status(deployment_id, "rolled-back", rollback_status="completed")
            await _broadcast_deploy_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Rollback completed successfully. All hosts restored.\n")
            await _finish_deploy_job(job_id, "completed")

    except Exception as exc:
        LOGGER.error("rollback job %s failed: %s", job_id, exc)
        await _broadcast_deploy_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ROLLBACK FAILED: {exc}\n")
        await db.update_deployment_status(deployment_id, "failed", rollback_status="failed")
        await _finish_deploy_job(job_id, "failed")


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/api/deployments")
async def create_deployment(body: DeploymentCreate, request: Request):
    """Create a new deployment plan."""
    session = _get_session(request)
    user = session["user"] if session else ""

    # Resolve commands from template if needed
    commands = list(body.proposed_commands)
    if body.template_id and not commands:
        tpl = await db.get_template(body.template_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="Template not found")
        commands = [
            line.rstrip() for line in tpl["content"].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    if not commands:
        raise HTTPException(status_code=400, detail="No proposed commands provided")

    deployment_id = await db.create_deployment(
        name=body.name,
        description=body.description,
        group_id=body.group_id,
        credential_id=body.credential_id,
        change_type=body.change_type,
        proposed_commands="\n".join(commands),
        template_id=body.template_id,
        risk_analysis_id=body.risk_analysis_id,
        host_ids=json.dumps(body.host_ids),
        created_by=user,
    )

    await _audit(
        "deployments", "deployment.created",
        user=user,
        detail=f"id={deployment_id} name={body.name} group_id={body.group_id}",
        correlation_id=_corr_id(request),
    )
    return {"id": deployment_id, "status": "planning"}


@router.get("/api/deployments")
async def list_deployments(
    status: str | None = Query(default=None),
    group_id: int | None = Query(default=None),
    limit: int = Query(default=100, le=500),
):
    return await db.get_deployments(status=status, group_id=group_id, limit=limit)


@router.get("/api/deployments/summary")
async def get_deployment_summary_endpoint():
    return await db.get_deployment_summary()


@router.get("/api/deployments/{deployment_id}")
async def get_deployment_detail(deployment_id: int):
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    checkpoints = await db.get_deployment_checkpoints(deployment_id)
    snapshots = await db.get_deployment_snapshots(deployment_id)
    return {**dep, "checkpoints": checkpoints, "snapshots": snapshots}


@router.get("/api/deployments/{deployment_id}/correlation")
async def get_deployment_correlation(deployment_id: int):
    """Return correlated events (drift, alerts, audit trail) around a deployment."""
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")

    started = dep.get("started_at") or dep.get("created_at")
    finished = dep.get("finished_at")
    window_start = (datetime.fromisoformat(started) - timedelta(minutes=5)).isoformat() if started else None
    window_end = (datetime.fromisoformat(finished) + timedelta(minutes=30)).isoformat() if finished else datetime.now(UTC).isoformat()

    host_ids: list[int] = []
    try:
        host_ids = json.loads(dep.get("host_ids") or "[]")
    except (json.JSONDecodeError, TypeError):
        pass

    checkpoints = await db.get_deployment_checkpoints(deployment_id)
    drift_events = await db.get_config_drift_events_in_range(host_ids, window_start, window_end) if host_ids and window_start else []
    alerts = await db.get_monitoring_alerts_in_range(host_ids, window_start, window_end) if host_ids and window_start else []
    audit_trail = await db.get_audit_events_for_deployment(deployment_id, window_start, window_end) if window_start else []

    return {
        "deployment": dep,
        "checkpoints": checkpoints,
        "drift_events": drift_events,
        "alerts": alerts,
        "audit_trail": audit_trail,
        "time_window": {"start": window_start, "end": window_end},
    }


@router.post("/api/deployments/{deployment_id}/execute")
async def execute_deployment(deployment_id: int, request: Request):
    """Execute a planned deployment with pre/post checkpoints."""
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    if dep["status"] not in ("planning", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot execute deployment in '{dep['status']}' status")

    session = _get_session(request)
    user = session["user"] if session else ""

    # Resolve credentials
    cred = await db.get_credential_raw(dep["credential_id"])
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
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

    job_id = str(uuid.uuid4())
    _deployment_jobs[job_id] = {
        "status": "running", "output": "", "deployment_id": deployment_id, "action": "execute",
    }
    _deployment_job_sockets[job_id] = []

    asyncio.create_task(_run_deployment_job(job_id, deployment_id, hosts, commands, credentials, user))

    await _audit(
        "deployments", "deployment.executed",
        user=user,
        detail=f"id={deployment_id} job_id={job_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "deployment_id": deployment_id}


@router.post("/api/deployments/{deployment_id}/rollback")
async def rollback_deployment(deployment_id: int, request: Request):
    """Roll back a deployment using pre-deployment snapshots."""
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    if dep["status"] not in ("completed", "failed", "post-check"):
        raise HTTPException(status_code=400, detail=f"Cannot rollback deployment in '{dep['status']}' status")

    session = _get_session(request)
    user = session["user"] if session else ""

    cred = await db.get_credential_raw(dep["credential_id"])
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
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
        "status": "running", "output": "", "deployment_id": deployment_id, "action": "rollback",
    }
    _deployment_job_sockets[job_id] = []

    asyncio.create_task(_run_rollback_job(job_id, deployment_id, hosts, credentials, user))

    await _audit(
        "deployments", "deployment.rollback",
        user=user,
        detail=f"id={deployment_id} job_id={job_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "deployment_id": deployment_id}


@router.delete("/api/deployments/{deployment_id}")
async def delete_deployment_endpoint(deployment_id: int, request: Request):
    dep = await db.get_deployment(deployment_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    if dep["status"] in ("executing", "pre-check", "post-check", "rolling-back"):
        raise HTTPException(status_code=400, detail="Cannot delete an active deployment")
    await db.delete_deployment(deployment_id)
    session = _get_session(request)
    await _audit(
        "deployments", "deployment.deleted",
        user=session["user"] if session else "",
        detail=f"id={deployment_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.get("/api/deployments/job/{job_id}/status")
async def get_deployment_job_status(job_id: str):
    job = _deployment_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Deployment job not found")
    return {
        "job_id": job_id,
        "status": job["status"],
        "output": job["output"],
        "deployment_id": job.get("deployment_id"),
        "action": job.get("action", "execute"),
    }


@ws_router.websocket("/ws/deployment/{job_id}")
async def ws_deployment(websocket: WebSocket, job_id: str):
    """WebSocket for streaming deployment/rollback job output."""
    token = websocket.cookies.get("session")
    session = _verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "deployments" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    if job_id not in _deployment_job_sockets:
        _deployment_job_sockets[job_id] = []
    _deployment_job_sockets[job_id].append(websocket)

    # Send any existing output
    job = _deployment_jobs.get(job_id, {})
    if job.get("output"):
        try:
            await websocket.send_json({"type": "line", "data": job["output"]})
        except Exception:
            pass
    if job.get("status") in ("completed", "failed"):
        try:
            await websocket.send_json({"type": "job_complete", "status": job["status"]})
        except Exception:
            pass

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if job_id in _deployment_job_sockets:
            try:
                _deployment_job_sockets[job_id].remove(websocket)
            except ValueError:
                pass
