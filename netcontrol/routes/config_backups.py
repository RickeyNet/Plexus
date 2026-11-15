"""
config_backups.py -- Config backup routes: policies, backup records, restore, admin schedule.
"""

from __future__ import annotations

import asyncio
import io
import re as _re
import zipfile
from datetime import UTC, datetime, timezone
from typing import Literal

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.drivers import get_driver
from netcontrol.object_scope import (
    group_filter,
    request_scope,
    require_group,
    require_object_host,
    scoped,
)
from netcontrol.routes.device_config import get_device_config
from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
    _get_session,
    require_credential_access,
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.config_backups")

router = APIRouter()

# Track which policies are currently running to prevent concurrent runs
_running_policies: set[int] = set()


# ── Pydantic Models ──────────────────────────────────────────────────────────


class ConfigBackupPolicyCreate(BaseModel):
    name: str
    group_id: int
    credential_id: int
    interval_seconds: int = 86400
    retention_days: int = 30


class ConfigBackupPolicyUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    credential_id: int | None = None
    interval_seconds: int | None = None
    retention_days: int | None = None


class ConfigBackupRestoreRequest(BaseModel):
    backup_id: int
    credential_id: int


# ── Backup Policy CRUD ───────────────────────────────────────────────────────
#
# A policy is a global record that targets one inventory group: a caller
# limited to selected inventory groups sees a policy only when its group is
# readable and changes or runs it only when the group is writable.

_POLICY_NOT_FOUND = "Policy not found"
_BACKUP_NOT_FOUND = "Backup not found"


async def _require_policy(request: Request | None, policy_id: int, *, write: bool = False) -> dict:
    """The policy; 404 when unknown or (scoped caller) its inventory group is
    not readable, 403 on ``write`` when the group is read only."""
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=_POLICY_NOT_FOUND)
    if (await request_scope(request)).restricted:
        await require_group(request, policy["group_id"], write=write, not_found=_POLICY_NOT_FOUND)
    return policy


async def _require_backup(request: Request | None, backup_id: int, *, write: bool = False) -> dict:
    """The backup; 404 when unknown or (scoped caller) its host is not
    readable, 403 on ``write`` when the host's group is read only."""
    backup = await db.get_config_backup(backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail=_BACKUP_NOT_FOUND)
    await require_object_host(request, backup.get("host_id"), write=write, not_found=_BACKUP_NOT_FOUND)
    return backup


@router.get("/api/config-backups/policies")
@scoped("list")
async def list_config_backup_policies(request: Request, group_id: int | None = Query(default=None)):
    policies = await db.get_config_backup_policies(group_id)
    return (await request_scope(request)).filter_groups(policies, key="group_id")


async def create_backup_policy(body: ConfigBackupPolicyCreate, request: Request) -> dict:
    """Create a backup policy for an inventory group, as the requesting
    user: the group must exist (and be writable for a caller limited to
    selected inventory groups) and the user may use the credential (or it
    is the service credential); the interval and retention are clamped to
    their bounds. Audited. Returns the stored policy."""
    await require_group(request, body.group_id, write=True, not_found="Inventory group not found")
    session = _get_session(request)
    await require_credential_access(body.credential_id, session=session, allow_service=True)
    interval = max(
        state.CONFIG_BACKUP_POLICY_MIN_INTERVAL, min(state.CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds)
    )
    retention = max(
        state.CONFIG_BACKUP_POLICY_MIN_RETENTION, min(state.CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days)
    )
    policy_id = await db.create_config_backup_policy(
        name=body.name,
        group_id=body.group_id,
        credential_id=body.credential_id,
        interval_seconds=interval,
        retention_days=retention,
        created_by=session["user"] if session else "",
    )
    await _audit(
        "config-backups",
        "policy.created",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@router.post("/api/config-backups/policies", status_code=201)
@scoped("group")
async def create_config_backup_policy(body: ConfigBackupPolicyCreate, request: Request):
    return await create_backup_policy(body, request)


@router.get("/api/config-backups/policies/{policy_id}")
@scoped("policy")
async def get_config_backup_policy(policy_id: int, request: Request):
    return await _require_policy(request, policy_id)


@router.put("/api/config-backups/policies/{policy_id}")
@scoped("policy")
async def update_config_backup_policy(policy_id: int, body: ConfigBackupPolicyUpdate, request: Request):
    await _require_policy(request, policy_id, write=True)
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.enabled is not None:
        updates["enabled"] = 1 if body.enabled else 0
    if body.credential_id is not None:
        await require_credential_access(
            body.credential_id,
            session=_get_session(request),
            allow_service=True,
        )
        updates["credential_id"] = body.credential_id
    if body.interval_seconds is not None:
        updates["interval_seconds"] = max(
            state.CONFIG_BACKUP_POLICY_MIN_INTERVAL, min(state.CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds)
        )
    if body.retention_days is not None:
        updates["retention_days"] = max(
            state.CONFIG_BACKUP_POLICY_MIN_RETENTION, min(state.CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days)
        )
    await db.update_config_backup_policy(policy_id, **updates)
    session = _get_session(request)
    await _audit(
        "config-backups",
        "policy.updated",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@router.delete("/api/config-backups/policies/{policy_id}")
@scoped("policy")
async def delete_config_backup_policy_route(policy_id: int, request: Request):
    policy = await _require_policy(request, policy_id, write=True)
    await db.delete_config_backup_policy(policy_id)
    session = _get_session(request)
    await _audit(
        "config-backups",
        "policy.deleted",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={policy['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Records ───────────────────────────────────────────────────────────


@router.get("/api/config-backups")
@scoped("list")
async def list_config_backups(
    request: Request,
    host_id: int | None = Query(default=None),
    policy_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    status: Literal["success", "error"] | None = Query(default=None),
):
    return await db.get_config_backups(
        host_id=host_id, policy_id=policy_id, limit=limit, status=status, **await group_filter(request)
    )


@router.get("/api/config-backups/summary")
@scoped("list")
async def get_config_backup_summary(request: Request):
    return await db.get_config_backup_summary(**await group_filter(request))


@router.get("/api/config-backups/latest-per-host")
@scoped("list")
async def list_latest_config_backups_per_host(request: Request):
    return await db.get_latest_config_backups_per_host(**await group_filter(request))


@router.get("/api/config-backups/search")
@scoped("list")
async def search_config_backup_records(
    q: str = Query(..., min_length=1, max_length=400),
    mode: str = Query(default="fulltext"),
    limit: int = Query(default=50, ge=1, le=200),
    context_lines: int = Query(default=1, ge=0, le=5),
    request: Request = None,
):
    try:
        return await db.search_config_backups(
            q,
            mode=mode,
            limit=limit,
            context_lines=context_lines,
            **await group_filter(request),
        )
    except ValueError as exc:
        code = (exc.args[0] if exc.args else "").strip().lower()
        if code == "invalid_regex":
            raise HTTPException(status_code=400, detail="Invalid regex pattern") from exc
        if code == "regex_needs_literal":
            raise HTTPException(
                status_code=400,
                detail=(
                    "Regex search needs at least 3 literal characters in the pattern "
                    "(e.g. 'snmp-server .*public'); use substring or fulltext mode "
                    "for broader queries"
                ),
            ) from exc
        if code == "invalid_mode":
            raise HTTPException(status_code=400, detail="Unsupported search mode") from exc
        raise HTTPException(status_code=400, detail="Invalid search query") from exc


@router.get("/api/config-backups/{backup_id}/diff")
@scoped("backup")
async def get_config_backup_diff(backup_id: int, request: Request = None):
    current = await _require_backup(request, backup_id)
    if current.get("status") != "success" or not current.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup does not contain a successful config capture")

    previous = await db.get_previous_successful_config_backup(backup_id)
    if not previous or not previous.get("config_text"):
        raise HTTPException(status_code=404, detail="No previous successful backup available for diff")

    diff_text, added, removed = _compute_config_diff(
        previous["config_text"],
        current["config_text"],
        baseline_label=f"backup-{previous['id']}",
        actual_label=f"backup-{current['id']}",
    )
    return {
        "backup_id": current["id"],
        "previous_backup_id": previous["id"],
        "host_id": current.get("host_id"),
        "hostname": current.get("hostname"),
        "ip_address": current.get("ip_address"),
        "captured_at": current.get("captured_at"),
        "previous_captured_at": previous.get("captured_at"),
        "diff_text": diff_text,
        "diff_lines_added": added,
        "diff_lines_removed": removed,
    }


# ── Backup Downloads ─────────────────────────────────────────────────────────
#
# Two flavours: a single backup as plain text (for "save the running-config of
# this device"), and a zip of many backups (filtered by host or policy) for
# bulk archival / offsite copies.  This replaces the standalone
# ``config_backup.py`` playbook that used to write timestamped .txt files to
# ``./backups/``.


def _safe_filename(text: str) -> str:
    """Sanitize a string for use inside a filename (no path separators)."""
    cleaned = _re.sub(r"[^A-Za-z0-9._-]+", "_", (text or "").strip())
    return cleaned.strip("._-") or "device"


def _backup_filename(backup: dict) -> str:
    """Render the ``hostname_ip_YYYYMMDD_HHMMSS.txt`` filename for a backup row.

    Mirrors the naming convention the legacy playbook produced so anyone
    automating around the old format keeps working.
    """
    host_part = _safe_filename(backup.get("hostname") or backup.get("ip_address") or "device")
    ip_part = _safe_filename(backup.get("ip_address") or "")
    captured_raw = backup.get("captured_at") or ""
    try:
        # captured_at is stored without a tz suffix; treat as UTC.
        dt = datetime.fromisoformat(str(captured_raw).replace("Z", "")).replace(tzinfo=UTC)
        date_part = dt.strftime("%Y%m%d_%H%M%S")
    except Exception:  # noqa: BLE001 - fall back to a wall-clock stamp
        date_part = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    parts = [p for p in (host_part, ip_part, date_part) if p]
    return "_".join(parts) + ".txt"


@router.get("/api/config-backups/download")
@scoped("list")
async def download_config_backups_bulk(
    request: Request,
    host_id: int | None = Query(default=None),
    policy_id: int | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return a ZIP of one ``.txt`` file per successful backup matching the filter.

    Declared *before* ``/api/config-backups/{backup_id}`` so the literal
    ``download`` path segment doesn't get parsed as an integer ID.
    """
    rows = await db.get_config_backups(host_id=host_id, policy_id=policy_id, limit=limit, **await group_filter(request))
    # Only successful captures have config_text worth exporting.
    successful = [r for r in rows if r.get("status") == "success"]
    if not successful:
        raise HTTPException(status_code=404, detail="No successful backups match the filter")

    buf = io.BytesIO()
    used_names: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # The list endpoint omits config_text for performance - re-fetch each
        # row's text individually.  500-row cap on the query keeps this bounded.
        for row in successful:
            full = await db.get_config_backup(row["id"])
            if not full or not full.get("config_text"):
                continue
            name = _backup_filename(full)
            # Disambiguate if two backups happen to render the same filename.
            base, ext = name.rsplit(".", 1)
            counter = 2
            while name in used_names:
                name = f"{base}_{counter}.{ext}"
                counter += 1
            used_names.add(name)
            zf.writestr(name, full["config_text"])

    buf.seek(0)
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    fname = f"config_backups_{stamp}.zip"

    session = _get_session(request)
    await _audit(
        "config-backups",
        "download.bulk",
        user=session["user"] if session else "",
        detail=f"host_id={host_id} policy_id={policy_id} count={len(used_names)}",
        correlation_id=_corr_id(request),
    )
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/api/config-backups/{backup_id}/download")
@scoped("backup")
async def download_config_backup(backup_id: int, request: Request):
    """Return a single backup as a plain ``.txt`` attachment."""
    backup = await _require_backup(request, backup_id)
    if backup.get("status") != "success" or not backup.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup does not contain a successful config capture")

    fname = _backup_filename(backup)
    session = _get_session(request)
    await _audit(
        "config-backups",
        "download.single",
        user=session["user"] if session else "",
        detail=f"backup_id={backup_id} host_id={backup.get('host_id')}",
        correlation_id=_corr_id(request),
    )
    return Response(
        content=backup["config_text"],
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/api/config-backups/{backup_id}")
@scoped("backup")
async def get_config_backup_detail(backup_id: int, request: Request):
    return await _require_backup(request, backup_id)


@router.delete("/api/config-backups/{backup_id}")
@scoped("backup")
async def delete_config_backup_route(backup_id: int, request: Request):
    backup = await _require_backup(request, backup_id, write=True)
    await db.delete_config_backup(backup_id)
    session = _get_session(request)
    await _audit(
        "config-backups",
        "backup.deleted",
        user=session["user"] if session else "",
        detail=f"backup_id={backup_id} host_id={backup['host_id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Actions ───────────────────────────────────────────────────────────


@router.post("/api/config-backups/policies/{policy_id}/run-now")
@scoped("policy")
async def run_config_backup_policy_now(policy_id: int, request: Request):
    """Trigger an immediate backup run for a specific policy (its group must
    be writable for a caller limited to selected inventory groups)."""
    if (await request_scope(request)).restricted:
        # Before the running check, so a hidden policy is not revealed by 409.
        await _require_policy(request, policy_id, write=True)
    # Prevent concurrent runs of the same policy
    if policy_id in _running_policies:
        raise HTTPException(status_code=409, detail="This backup policy is already running")
    _running_policies.add(policy_id)

    try:
        policy = await db.get_config_backup_policy(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        hosts = await db.get_hosts_for_group(policy["group_id"])
        cred = await require_credential_access(
            policy["credential_id"],
            session=_get_session(request),
            allow_service=True,
        )

        backed_up = 0
        skipped = 0
        errs = 0
        sem = state.device_op_semaphore()

        async def _do_backup(host):
            nonlocal backed_up, skipped, errs
            async with sem:
                try:
                    # An unchanged config writes no new row (the host's
                    # newest backup is marked re-checked instead).
                    stored = await get_device_config(host, cred, capture_method="manual", policy_id=policy_id)
                    if not stored.created:
                        skipped += 1
                        return
                    backed_up += 1
                except Exception as exc:
                    await db.create_config_backup(
                        policy_id=policy_id,
                        host_id=host["id"],
                        config_text="",
                        capture_method="manual",
                        status="error",
                        error_message=str(exc)[:1000],
                    )
                    errs += 1

        await asyncio.gather(*[_do_backup(h) for h in hosts], return_exceptions=True)
        await db.update_config_backup_policy_last_run(policy_id)

        session = _get_session(request)
        await _audit(
            "config-backups",
            "policy.run-now",
            user=session["user"] if session else "",
            detail=f"policy_id={policy_id} backed_up={backed_up} skipped={skipped} errors={errs}",
            correlation_id=_corr_id(request),
        )
        return {"ok": True, "backed_up": backed_up, "skipped": skipped, "errors": errs}
    finally:
        _running_policies.discard(policy_id)


@router.post("/api/config-backups/restore")
@scoped("backup")
async def restore_config_from_backup(body: ConfigBackupRestoreRequest, request: Request):
    """Restore configuration from a backup and validate (pushes to the
    device: the host's group must be writable)."""
    backup = await _require_backup(request, body.backup_id, write=True)
    if not backup.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup has no config text")
    host = await db.get_host(backup["host_id"])
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    if not get_driver(host.get("device_type")).cli:
        raise HTTPException(status_code=400, detail="This device type has no command line: nothing can be pushed to it")
    cred = await require_credential_access(body.credential_id, session=_get_session(request))

    # Push config
    import netmiko
    from routes.crypto import decrypt

    def _push_config():
        device = {
            "device_type": host.get("device_type", "cisco_ios"),
            "host": host["ip_address"],
            "username": cred["username"],
            "password": decrypt(cred["password"]),
            "secret": decrypt(cred.get("secret", "")),
        }
        net_connect = netmiko.ConnectHandler(**device)
        try:
            if device["secret"]:
                net_connect.enable()
            config_lines = backup["config_text"].splitlines()
            net_connect.send_config_set(config_lines)
        finally:
            net_connect.disconnect()

    try:
        await asyncio.to_thread(_push_config)
    except Exception as exc:
        LOGGER.error("Config restore push failed for host %s backup %s: %s", host["ip_address"], body.backup_id, exc)
        raise HTTPException(status_code=502, detail="Config push failed - see server logs for details")

    # Re-capture and validate
    validated = False
    diff_text = ""
    lines_changed = 0
    try:
        current = await get_device_config(host, cred, capture_method="restore")
        diff_text, added, removed = _compute_config_diff(
            backup["config_text"],
            current.config_text,
            baseline_label="backup",
            actual_label="current",
        )
        lines_changed = added + removed
        validated = lines_changed == 0
    except Exception as exc:
        LOGGER.warning("Validation capture failed for backup %s: %s", body.backup_id, exc)
        diff_text = "Validation capture failed - see server logs for details."

    session = _get_session(request)
    await _audit(
        "config-backups",
        "restore",
        user=session["user"] if session else "",
        detail=f"backup_id={body.backup_id} host={host['ip_address']} validated={validated} lines_changed={lines_changed}",
        correlation_id=_corr_id(request),
    )
    return {
        "restored": True,
        "validated": validated,
        "diff_text": diff_text,
        "lines_changed": lines_changed,
        "host_id": host["id"],
        "hostname": host["hostname"],
    }


# ── Background Loop ──────────────────────────────────────────────────────────

# How often the scheduler wakes to check for due policies. Actual backup cadence
# is driven by each policy's interval_seconds via get_config_backup_policies_due().
_POLL_INTERVAL_SECONDS = 60


async def _run_config_backups_once() -> dict:
    """Run backups for all due policies."""
    due_policies = await db.get_config_backup_policies_due()
    policies_run = 0
    hosts_backed_up = 0
    errors = 0

    sem = state.device_op_semaphore()

    for policy in due_policies:
        try:
            hosts = await db.get_hosts_for_group(policy["group_id"])
            try:
                # Re-validate the stored credential against the policy creator so
                # a policy can never keep running with a credential its creator
                # no longer owns (or after the creator account is removed).
                cred = await require_credential_access(
                    policy["credential_id"],
                    submitter_username=policy.get("created_by") or None,
                    allow_service=True,
                )
            except HTTPException as exc:
                LOGGER.warning(
                    "config-backup: credential %s rejected for policy %s (created_by=%r): %s",
                    policy["credential_id"],
                    policy["id"],
                    policy.get("created_by"),
                    exc.detail,
                )
                errors += 1
                continue

            async def _backup_host(host, cred_data, pol_id):
                async with sem:
                    try:
                        # An unchanged config writes no new row (the host's
                        # newest backup is marked re-checked instead).
                        stored = await get_device_config(host, cred_data, capture_method="scheduled", policy_id=pol_id)
                        return True if stored.created else "skipped"
                    except Exception as exc:
                        await db.create_config_backup(
                            policy_id=pol_id,
                            host_id=host["id"],
                            config_text="",
                            capture_method="scheduled",
                            status="error",
                            error_message=str(exc)[:1000],
                        )
                        return False

            tasks = [_backup_host(h, cred, policy["id"]) for h in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r is True:
                    hosts_backed_up += 1
                elif r == "skipped":
                    pass  # unchanged config, not an error
                else:
                    errors += 1

            await db.update_config_backup_policy_last_run(policy["id"])
            policies_run += 1

            # Retention cleanup for this policy
            try:
                await db.delete_old_config_backups(policy["retention_days"])
            except Exception as exc:
                LOGGER.warning("config-backup: retention cleanup failed for policy %s: %s", policy["id"], exc)

        except Exception as exc:
            errors += 1
            LOGGER.warning("config-backup: policy %s failed: %s", policy["id"], exc)

    if policies_run > 0:
        LOGGER.info(
            "config-backup: ran %d policies, backed up %d hosts, %d errors", policies_run, hosts_backed_up, errors
        )
        increment_metric("config_backup.scheduled.success")

    return {
        "policies_run": policies_run,
        "hosts_backed_up": hosts_backed_up,
        "errors": errors,
    }


async def _config_backup_loop() -> None:
    """Infinite loop that checks for due backup policies."""
    while True:
        try:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            await _run_config_backups_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("config backup loop failure: %s", redact_value(str(exc)))
            increment_metric("config_backup.scheduled.failed")
