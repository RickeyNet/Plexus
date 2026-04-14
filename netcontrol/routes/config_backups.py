"""
config_backups.py -- Config backup routes: policies, backup records, restore, admin schedule.
"""

import asyncio

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.shared import (
    _audit,
    _capture_running_config,
    _compute_config_diff,
    _corr_id,
    _get_session,
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.config_backups")

router = APIRouter()

# Track which policies are currently running to prevent concurrent runs
_running_policies: set[int] = set()

# ── Late-binding auth dependencies ────────────────────────────────────────────

_require_auth = None
_require_feature = None
_require_admin = None
_verify_session_token = None
_get_user_features = None


def init_config_backups(require_auth_fn, require_feature_fn, require_admin_fn,
                        verify_session_token_fn, get_user_features_fn):
    global _require_auth, _require_feature, _require_admin
    global _verify_session_token, _get_user_features
    _require_auth = require_auth_fn
    _require_feature = require_feature_fn
    _require_admin = require_admin_fn
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


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


@router.get("/api/config-backups/policies")
async def list_config_backup_policies(group_id: int | None = Query(default=None)):
    return await db.get_config_backup_policies(group_id)


@router.post("/api/config-backups/policies", status_code=201)
async def create_config_backup_policy(body: ConfigBackupPolicyCreate, request: Request):
    group = await db.get_group(body.group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Inventory group not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    interval = max(state.CONFIG_BACKUP_POLICY_MIN_INTERVAL,
                   min(state.CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds))
    retention = max(state.CONFIG_BACKUP_POLICY_MIN_RETENTION,
                    min(state.CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days))
    session = _get_session(request)
    policy_id = await db.create_config_backup_policy(
        name=body.name, group_id=body.group_id, credential_id=body.credential_id,
        interval_seconds=interval, retention_days=retention,
        created_by=session["user"] if session else "",
    )
    await _audit(
        "config-backups", "policy.created",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@router.get("/api/config-backups/policies/{policy_id}")
async def get_config_backup_policy(policy_id: int):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/api/config-backups/policies/{policy_id}")
async def update_config_backup_policy(policy_id: int, body: ConfigBackupPolicyUpdate, request: Request):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.enabled is not None:
        updates["enabled"] = 1 if body.enabled else 0
    if body.credential_id is not None:
        cred = await db.get_credential_raw(body.credential_id)
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        updates["credential_id"] = body.credential_id
    if body.interval_seconds is not None:
        updates["interval_seconds"] = max(state.CONFIG_BACKUP_POLICY_MIN_INTERVAL,
                                          min(state.CONFIG_BACKUP_POLICY_MAX_INTERVAL, body.interval_seconds))
    if body.retention_days is not None:
        updates["retention_days"] = max(state.CONFIG_BACKUP_POLICY_MIN_RETENTION,
                                       min(state.CONFIG_BACKUP_POLICY_MAX_RETENTION, body.retention_days))
    await db.update_config_backup_policy(policy_id, **updates)
    session = _get_session(request)
    await _audit(
        "config-backups", "policy.updated",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id}",
        correlation_id=_corr_id(request),
    )
    return await db.get_config_backup_policy(policy_id)


@router.delete("/api/config-backups/policies/{policy_id}")
async def delete_config_backup_policy_route(policy_id: int, request: Request):
    policy = await db.get_config_backup_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete_config_backup_policy(policy_id)
    session = _get_session(request)
    await _audit(
        "config-backups", "policy.deleted",
        user=session["user"] if session else "",
        detail=f"policy_id={policy_id} name={policy['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Records ───────────────────────────────────────────────────────────


@router.get("/api/config-backups")
async def list_config_backups(
    host_id: int | None = Query(default=None),
    policy_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    return await db.get_config_backups(host_id=host_id, policy_id=policy_id, limit=limit)


@router.get("/api/config-backups/summary")
async def get_config_backup_summary():
    return await db.get_config_backup_summary()


@router.get("/api/config-backups/search")
async def search_config_backup_records(
    q: str = Query(..., min_length=1, max_length=400),
    mode: str = Query(default="fulltext"),
    limit: int = Query(default=50, ge=1, le=200),
    context_lines: int = Query(default=1, ge=0, le=5),
):
    try:
        return await db.search_config_backups(
            q,
            mode=mode,
            limit=limit,
            context_lines=context_lines,
        )
    except ValueError as exc:
        code = (exc.args[0] if exc.args else "").strip().lower()
        if code == "invalid_regex":
            raise HTTPException(status_code=400, detail="Invalid regex pattern") from exc
        if code == "invalid_mode":
            raise HTTPException(status_code=400, detail="Unsupported search mode") from exc
        raise HTTPException(status_code=400, detail="Invalid search query") from exc


@router.get("/api/config-backups/{backup_id}/diff")
async def get_config_backup_diff(backup_id: int):
    current = await db.get_config_backup(backup_id)
    if not current:
        raise HTTPException(status_code=404, detail="Backup not found")
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


@router.get("/api/config-backups/{backup_id}")
async def get_config_backup_detail(backup_id: int):
    backup = await db.get_config_backup(backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    return backup


@router.delete("/api/config-backups/{backup_id}")
async def delete_config_backup_route(backup_id: int, request: Request):
    backup = await db.get_config_backup(backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    await db.delete_config_backup(backup_id)
    session = _get_session(request)
    await _audit(
        "config-backups", "backup.deleted",
        user=session["user"] if session else "",
        detail=f"backup_id={backup_id} host_id={backup['host_id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Backup Actions ───────────────────────────────────────────────────────────


@router.post("/api/config-backups/policies/{policy_id}/run-now")
async def run_config_backup_policy_now(policy_id: int, request: Request):
    """Trigger an immediate backup run for a specific policy."""
    # Prevent concurrent runs of the same policy
    if policy_id in _running_policies:
        raise HTTPException(status_code=409, detail="This backup policy is already running")
    _running_policies.add(policy_id)

    try:
        policy = await db.get_config_backup_policy(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        hosts = await db.get_hosts_for_group(policy["group_id"])
        cred = await db.get_credential_raw(policy["credential_id"])
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")

        backed_up = 0
        skipped = 0
        errs = 0
        sem = asyncio.Semaphore(4)

        async def _do_backup(host):
            nonlocal backed_up, skipped, errs
            async with sem:
                try:
                    config_text = await _capture_running_config(host, cred)
                    # Deduplicate: skip if config is identical to the last backup
                    last = await db.get_latest_config_backup(policy_id, host["id"])
                    if last and last.get("config_text") == config_text:
                        skipped += 1
                        return
                    await db.create_config_backup(
                        policy_id=policy_id, host_id=host["id"],
                        config_text=config_text, capture_method="manual",
                        status="success", error_message="",
                    )
                    backed_up += 1
                except Exception as exc:
                    await db.create_config_backup(
                        policy_id=policy_id, host_id=host["id"],
                        config_text="", capture_method="manual",
                        status="error", error_message=str(exc)[:1000],
                    )
                    errs += 1

        await asyncio.gather(*[_do_backup(h) for h in hosts], return_exceptions=True)
        await db.update_config_backup_policy_last_run(policy_id)

        session = _get_session(request)
        await _audit(
            "config-backups", "policy.run-now",
            user=session["user"] if session else "",
            detail=f"policy_id={policy_id} backed_up={backed_up} skipped={skipped} errors={errs}",
            correlation_id=_corr_id(request),
        )
        return {"ok": True, "backed_up": backed_up, "skipped": skipped, "errors": errs}
    finally:
        _running_policies.discard(policy_id)


@router.post("/api/config-backups/restore")
async def restore_config_from_backup(body: ConfigBackupRestoreRequest, request: Request):
    """Restore configuration from a backup and validate."""
    backup = await db.get_config_backup(body.backup_id)
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    if not backup.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup has no config text")
    host = await db.get_host(backup["host_id"])
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

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
        if device["secret"]:
            net_connect.enable()
        config_lines = backup["config_text"].splitlines()
        net_connect.send_config_set(config_lines)
        net_connect.disconnect()

    try:
        await asyncio.to_thread(_push_config)
    except Exception as exc:
        LOGGER.error("Config restore push failed for host %s backup %s: %s",
                     host["ip_address"], body.backup_id, exc)
        raise HTTPException(status_code=502, detail="Config push failed — see server logs for details")

    # Re-capture and validate
    validated = False
    diff_text = ""
    lines_changed = 0
    try:
        current_config = await _capture_running_config(host, cred)
        diff_text, added, removed = _compute_config_diff(
            backup["config_text"], current_config,
            baseline_label="backup", actual_label="current",
        )
        lines_changed = added + removed
        validated = lines_changed == 0
    except Exception as exc:
        LOGGER.warning("Validation capture failed for backup %s: %s", body.backup_id, exc)
        diff_text = "Validation capture failed — see server logs for details."

    session = _get_session(request)
    await _audit(
        "config-backups", "restore",
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


# ── Admin Config Backup Schedule ─────────────────────────────────────────────


@router.get("/api/admin/config-backups")
async def admin_get_config_backup_config():
    return state.CONFIG_BACKUP_CONFIG


@router.put("/api/admin/config-backups")
async def admin_update_config_backup_config(body: dict, request: Request):
    state.CONFIG_BACKUP_CONFIG = state._sanitize_config_backup_config(body)
    await db.set_auth_setting("config_backup", state.CONFIG_BACKUP_CONFIG)
    session = _get_session(request)
    await _audit(
        "config-backups", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={state.CONFIG_BACKUP_CONFIG['enabled']} interval={state.CONFIG_BACKUP_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return state.CONFIG_BACKUP_CONFIG


@router.post("/api/admin/config-backups/run-now")
async def admin_run_config_backups_now(request: Request):
    result = await _run_config_backups_once()
    session = _get_session(request)
    await _audit(
        "config-backups", "scheduled.manual",
        user=session["user"] if session else "",
        detail=f"policies_run={result.get('policies_run', 0)} hosts_backed_up={result.get('hosts_backed_up', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}


# ── Background Loop ──────────────────────────────────────────────────────────


async def _run_config_backups_once() -> dict:
    """Run backups for all due policies."""
    if not state.CONFIG_BACKUP_CONFIG.get("enabled"):
        return {"enabled": False, "policies_run": 0, "hosts_backed_up": 0, "errors": 0}

    due_policies = await db.get_config_backup_policies_due()
    policies_run = 0
    hosts_backed_up = 0
    errors = 0

    sem = asyncio.Semaphore(4)

    for policy in due_policies:
        try:
            hosts = await db.get_hosts_for_group(policy["group_id"])
            cred = await db.get_credential_raw(policy["credential_id"])
            if not cred:
                LOGGER.warning("config-backup: credential %s not found for policy %s", policy["credential_id"], policy["id"])
                errors += 1
                continue

            async def _backup_host(host, cred_data, pol_id):
                async with sem:
                    try:
                        config_text = await _capture_running_config(host, cred_data)
                        # Deduplicate: skip if config is identical to the last backup
                        last = await db.get_latest_config_backup(pol_id, host["id"])
                        if last and last.get("config_text") == config_text:
                            return "skipped"
                        await db.create_config_backup(
                            policy_id=pol_id, host_id=host["id"],
                            config_text=config_text, capture_method="scheduled",
                            status="success", error_message="",
                        )
                        return True
                    except Exception as exc:
                        await db.create_config_backup(
                            policy_id=pol_id, host_id=host["id"],
                            config_text="", capture_method="scheduled",
                            status="error", error_message=str(exc)[:1000],
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
            except Exception:
                pass

        except Exception as exc:
            errors += 1
            LOGGER.warning("config-backup: policy %s failed: %s", policy["id"], exc)

    if policies_run > 0:
        LOGGER.info("config-backup: ran %d policies, backed up %d hosts, %d errors",
                     policies_run, hosts_backed_up, errors)
        increment_metric("config_backup.scheduled.success")

    return {
        "enabled": True,
        "policies_run": policies_run,
        "hosts_backed_up": hosts_backed_up,
        "errors": errors,
    }


async def _config_backup_loop() -> None:
    """Infinite loop that checks for due backup policies."""
    while True:
        try:
            await asyncio.sleep(int(state.CONFIG_BACKUP_CONFIG.get(
                "interval_seconds", state.CONFIG_BACKUP_DEFAULTS["interval_seconds"])))
            await _run_config_backups_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("config backup loop failure: %s", redact_value(str(exc)))
            increment_metric("config_backup.scheduled.failed")
