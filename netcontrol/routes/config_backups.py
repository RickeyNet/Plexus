"""
config_backups.py -- Config backup routes: policies, backup records, restore, admin schedule.

Device secrets: a backup is the device's full configuration, passwords,
SNMP communities and keys included. A caller with ``config-backups.write``
(or an admin, or the API token) whose object scope may change the device
sees it as captured, and may download it. Any other reader (read-only
``config-backups``) gets the view, diff and search with the secrets masked by
``netcontrol.mcp.redact.redact_config_text`` (``secrets_masked: true``) and
no raw download. A restore runs on the server and always uses the stored
text. OPNsense config.xml is masked for everyone, as before: it is stored
masked, with the raw file encrypted beside it
(``netcontrol.routes.opnsense_backup_encryption``), which only the raw
download decrypts.
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
from routes.db.topology import _compile_config_backup_regex

import netcontrol.routes.state as state
from netcontrol.drivers import get_driver
from netcontrol.mcp.redact import redact_config_text
from netcontrol.object_scope import (
    group_filter,
    request_scope,
    require_group,
    require_object_host,
    scoped,
)
from netcontrol.routes import opnsense_masking
from netcontrol.routes.config_visibility import has_raw_config_feature, sees_raw_config
from netcontrol.routes.device_config import get_device_config
from netcontrol.routes.opnsense_backup import backup_firewall
from netcontrol.routes.opnsense_backup_encryption import (
    KEY_MISMATCH_MESSAGE,
    RawBackupUnavailable,
    raw_backup_text,
    raw_text_of,
)
from netcontrol.routes.shared import (
    _audit,
    _corr_id,
    _get_session,
    compute_config_diff_async,
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
    # None: the policy backs up API-read devices only (OPNsense firewalls).
    credential_id: int | None = None
    interval_seconds: int = 86400
    retention_days: int = 30


class ConfigBackupPolicyUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    # Left out: unchanged; null: cleared (API-read devices only).
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
_RAW_DOWNLOAD_DENIED = (
    "Downloading a config backup needs config-backups.write: it holds the device's secrets. "
    "The view shows it with the secrets masked."
)

# Who reads a backup as captured: one rule for every page that returns
# device configuration (``netcontrol.routes.config_visibility``).
_has_raw_feature = has_raw_config_feature
_sees_raw = sees_raw_config


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
    is the service credential). Without a credential the policy backs up
    the devices read over an API only (OPNsense firewalls). The interval
    and retention are clamped to their bounds. Audited. Returns the stored
    policy."""
    await require_group(request, body.group_id, write=True, not_found="Inventory group not found")
    session = _get_session(request)
    if body.credential_id is not None:
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
    elif "credential_id" in body.model_fields_set:
        updates["credential_id"] = None  # an explicit null clears it
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
        found = await db.search_config_backups(
            q,
            mode=mode,
            limit=limit,
            context_lines=context_lines,
            **await group_filter(request),
        )
        masked_ids = await _search_rows_to_mask(request, found)
        return _mask_search_results(found, q, mode, masked_ids)
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


_SEARCH_LINE_FIELDS = ("match_line", "context_before", "context_after", "match_context")
_SEARCH_LIST_FIELDS = ("context_before_lines", "context_after_lines")


def _still_matches(line: str, query: str, mode: str) -> bool:
    """Whether a masked match line still matches the search: a hit only on
    a secret value is dropped, so a search cannot confirm a guessed one."""
    if mode == "regex":
        try:
            return _compile_config_backup_regex(query).search(line) is not None
        except ValueError:
            return False
    lowered = line.lower()
    terms = query.lower().split() if mode == "fulltext" else [query.lower()]
    return all(term in lowered for term in terms)


async def _search_rows_to_mask(request: Request | None, found: dict) -> frozenset:
    """The ``backup_id`` of each search hit the caller may not see raw."""
    results = found.get("results") or []
    if not await _has_raw_feature(request):
        return frozenset(row.get("backup_id") for row in results)
    if (await request_scope(request)).unrestricted:
        return frozenset()
    # One answer per host; a list, not a generator: ``await`` in a generator
    # expression makes it asynchronous, which frozenset() cannot read.
    raw_hosts = {host_id: await _sees_raw(request, host_id) for host_id in {row.get("host_id") for row in results}}
    return frozenset([row.get("backup_id") for row in results if not raw_hosts[row.get("host_id")]])


def _mask_search_results(found: dict, query: str, mode: str, masked_ids: frozenset = frozenset()) -> dict:
    """Mask the matched lines of OPNsense backups (config.xml holds password
    hashes, keys and pre-shared keys) and of the backups in ``masked_ids``
    (the caller may not see their secrets), and drop a hit that only matched
    a secret. Other backups are returned as they are."""
    results = found.get("results") or []
    kept = []
    for row in results:
        if row.get("backup_id") in masked_ids:
            mask = redact_config_text
        elif opnsense_masking.is_opnsense_text(
            row.get("match_line"), device_type=row.get("device_type"), capture_method=row.get("capture_method")
        ):
            mask = opnsense_masking.mask_text
        else:
            kept.append(row)
            continue
        masked_line = mask(str(row.get("match_line") or ""))
        if masked_line != row.get("match_line") and not _still_matches(masked_line, query, mode):
            continue
        for field in _SEARCH_LINE_FIELDS:
            if isinstance(row.get(field), str):
                row[field] = mask(row[field])
        for field in _SEARCH_LIST_FIELDS:
            if isinstance(row.get(field), list):
                row[field] = [mask(str(line)) for line in row[field]]
        row["secrets_masked"] = True
        kept.append(row)
    if len(kept) != len(results):
        found = {**found, "results": kept, "count": len(kept)}
    return found


@router.get("/api/config-backups/{backup_id}/diff")
@scoped("backup")
async def get_config_backup_diff(backup_id: int, request: Request = None):
    current = await _require_backup(request, backup_id)
    if current.get("status") != "success" or not current.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup does not contain a successful config capture")

    previous = await db.get_previous_successful_config_backup(backup_id)
    if not previous or not previous.get("config_text"):
        raise HTTPException(status_code=404, detail="No previous successful backup available for diff")

    previous_text, current_text = previous["config_text"], current["config_text"]
    # An OPNsense config.xml is compared in its normalized form with secrets
    # masked: a changed secret shows as a changed fingerprint, never its
    # value, and the <revision> stamp of every save is shown apart.
    opnsense = opnsense_masking.is_opnsense_text(
        current_text, device_type=current.get("device_type"), capture_method=current.get("capture_method")
    )
    extra: dict = {}
    if opnsense:
        extra = {
            "secrets_masked": True,
            "revision": opnsense_masking.revision_of(current_text),
            "previous_revision": opnsense_masking.revision_of(previous_text),
        }
        previous_text = opnsense_masking.drift_form(previous_text)
        current_text = opnsense_masking.drift_form(current_text)
    elif not await _sees_raw(request, current.get("host_id")):
        # A changed secret shows as a changed (masked) line, never its value.
        extra = {"secrets_masked": True}
        previous_text = redact_config_text(previous_text, keep_lines=True)
        current_text = redact_config_text(current_text, keep_lines=True)
    diff_text, added, removed = await compute_config_diff_async(
        previous_text,
        current_text,
        baseline_label=f"backup-{previous['id']}",
        actual_label=f"backup-{current['id']}",
    )
    return {
        **extra,
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


# Backups read per query by the bulk download: bounded queries, and at most
# this many configurations in memory beside the zip.
_ZIP_READ_BATCH = 100


def _zip_backups(zf: zipfile.ZipFile, rows: list[dict], used_names: set[str], undecryptable: list[int]) -> None:
    """Write one ``.txt`` per row of ``get_config_backup_downloads`` into
    ``zf``: the raw file a single download returns (``raw_text_of``),
    an OPNsense config.xml decrypted. A row whose encrypted copy cannot be
    decrypted is added to ``undecryptable`` instead. Decrypting and
    deflating are CPU work: runs in a worker thread."""
    for row in rows:
        if not row.get("config_text"):
            continue
        try:
            content = raw_text_of(row, str(row.get("config_text_enc") or ""))
        except RawBackupUnavailable:
            undecryptable.append(int(row["id"]))
            continue
        name = _backup_filename(row)
        # Disambiguate if two backups happen to render the same filename.
        base, ext = name.rsplit(".", 1)
        counter = 2
        while name in used_names:
            name = f"{base}_{counter}.{ext}"
            counter += 1
        used_names.add(name)
        zf.writestr(name, content)


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

    The files are the raw captures (device secrets included; an OPNsense
    config.xml decrypted): the caller needs ``config-backups.write`` (or
    admin), and a caller limited to inventory groups gets the devices of
    the groups it may change. A backup whose encrypted copy cannot be
    decrypted is left out and named in ``NOT-INCLUDED.txt``.
    """
    if not await _has_raw_feature(request):
        raise HTTPException(status_code=403, detail=_RAW_DOWNLOAD_DENIED)
    scope_filter = await group_filter(request, write=True)
    rows = await db.get_config_backups(host_id=host_id, policy_id=policy_id, limit=limit, **scope_filter)
    # Only successful captures have config_text worth exporting.
    successful = [int(r["id"]) for r in rows if r.get("status") == "success"]
    if not successful:
        raise HTTPException(status_code=404, detail="No successful backups match the filter")

    buf = io.BytesIO()
    used_names: set[str] = set()
    undecryptable: list[int] = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # The list omits config_text: read the texts a batch at a time (the
        # same group scope applied again) and zip each batch in a thread, so
        # neither the queries nor the decrypt and deflate run per row on the
        # event loop. The thread is awaited before the next batch, so only
        # one thread touches ``zf`` at a time.
        for start in range(0, len(successful), _ZIP_READ_BATCH):
            batch = await db.get_config_backup_downloads(successful[start : start + _ZIP_READ_BATCH], **scope_filter)
            await asyncio.to_thread(_zip_backups, zf, batch, used_names, undecryptable)
        if undecryptable:
            ids = ", ".join(str(i) for i in undecryptable)
            zf.writestr("NOT-INCLUDED.txt", f"Backups not included: {ids}\n\n{KEY_MISMATCH_MESSAGE}\n")

    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    fname = f"config_backups_{stamp}.zip"

    session = _get_session(request)
    await _audit(
        "config-backups",
        "download.bulk",
        user=session["user"] if session else "",
        detail=f"host_id={host_id} policy_id={policy_id} count={len(used_names)} undecryptable={len(undecryptable)}",
        correlation_id=_corr_id(request),
    )
    return Response(
        # The buffer itself, not getvalue()'s copy of the whole zip.
        content=buf.getbuffer(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/api/config-backups/{backup_id}/download")
@scoped("backup")
async def download_config_backup(backup_id: int, request: Request):
    """Return a single backup as a plain ``.txt`` attachment: the raw
    capture, device secrets included (an OPNsense config.xml decrypted), so
    the caller needs ``config-backups.write`` (or admin) and write access
    to the device. 409 when the encrypted copy cannot be decrypted."""
    backup = await _require_backup(request, backup_id)
    if not await _sees_raw(request, backup.get("host_id")):
        raise HTTPException(status_code=403, detail=_RAW_DOWNLOAD_DENIED)
    if backup.get("status") != "success" or not backup.get("config_text"):
        raise HTTPException(status_code=400, detail="Backup does not contain a successful config capture")
    try:
        content = await raw_backup_text(backup)
    except RawBackupUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None

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
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/api/config-backups/{backup_id}")
@scoped("backup")
async def get_config_backup_detail(backup_id: int, request: Request):
    """A backup with its text; an OPNsense config.xml with its secrets
    masked (``secrets_masked``) and its ``<revision>`` given apart. For a
    caller without ``config-backups.write`` every backup's secrets are
    masked. An OPNsense backup is stored masked already; masking it again
    changes nothing and covers one stored in plain text by an older
    release."""
    backup = await _require_backup(request, backup_id)
    raw = str(backup.get("config_text") or "")
    masked = opnsense_masking.mask_record(backup, "config_text", "config_text_full")
    if masked and masked.get("secrets_masked"):
        masked["revision"] = opnsense_masking.revision_of(raw)
    elif masked and not await _sees_raw(request, backup.get("host_id")):
        for field in ("config_text", "config_text_full"):
            if isinstance(masked.get(field), str):
                masked[field] = redact_config_text(masked[field])
        masked["secrets_masked"] = True
    return masked


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

# The failed hosts a Run Now answer names with their reason (``errors`` counts
# them all); every failure is also an error row of the backup history.
_RUN_NOW_MAX_FAILURES = 25


@router.post("/api/config-backups/policies/{policy_id}/run-now")
@scoped("policy")
async def run_config_backup_policy_now(policy_id: int, request: Request):
    """Trigger an immediate backup run for a specific policy (its group must
    be writable for a caller limited to selected inventory groups). The
    answer counts the hosts backed up, unchanged and failed, and names the
    failed ones (``failures``, by hostname, at most ``_RUN_NOW_MAX_FAILURES``)
    with the reason stored on their error row."""
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
        # Without a credential only the OPNsense hosts are backed up (over
        # their source's API); an SSH host gets an error row that says so.
        cred = None
        if policy.get("credential_id") is not None:
            cred = await require_credential_access(
                policy["credential_id"],
                session=_get_session(request),
                allow_service=True,
            )

        backed_up = 0
        skipped = 0
        errs = 0
        failures: list[dict] = []
        sem = state.device_op_semaphore()

        async def _do_backup(host):
            nonlocal backed_up, skipped, errs
            async with sem:
                result, reason = await backup_host_outcome(host, cred, policy_id=policy_id, capture_method="manual")
            if result is True:
                backed_up += 1
            elif result == "skipped":
                skipped += 1
            else:
                errs += 1
                failures.append(
                    {
                        "host_id": host["id"],
                        "hostname": host.get("hostname") or "",
                        "ip_address": host.get("ip_address") or "",
                        "error": reason,
                    }
                )

        await asyncio.gather(*[_do_backup(h) for h in hosts], return_exceptions=True)
        await db.update_config_backup_policy_last_run(policy_id)
        failures.sort(key=lambda f: (f["hostname"], f["host_id"]))

        session = _get_session(request)
        await _audit(
            "config-backups",
            "policy.run-now",
            user=session["user"] if session else "",
            detail=f"policy_id={policy_id} backed_up={backed_up} skipped={skipped} errors={errs}",
            correlation_id=_corr_id(request),
        )
        return {
            "ok": True,
            "backed_up": backed_up,
            "skipped": skipped,
            "errors": errs,
            "failures": failures[:_RUN_NOW_MAX_FAILURES],
        }
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
    if opnsense_masking.is_opnsense_host(host) or opnsense_masking.is_opnsense_text(
        backup["config_text"], capture_method=backup.get("capture_method")
    ):
        raise HTTPException(status_code=400, detail=opnsense_masking.RESTORE_REFUSED_MESSAGE)
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
        diff_text, added, removed = await compute_config_diff_async(
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


NO_CREDENTIAL_MESSAGE = (
    "This backup policy has no credential: a device backed up over SSH needs one. "
    "Choose a credential for the policy; without one it backs up API-read devices (OPNsense) only"
)


async def backup_host_outcome(
    host: dict, cred: dict | None, *, policy_id: int, capture_method: str, deferred: bool = False
) -> tuple[bool | str, str]:
    """Back up one host of a backup policy. The result, and for a failed
    capture the reason stored on its error row (``""`` otherwise). The
    result is True when a new backup row was stored, ``"skipped"`` when the
    config is unchanged (no new row: the host's newest backup is marked
    re-checked instead), False when the capture failed (recorded as an
    error row). ``capture_method`` is stored on the row: ``scheduled``,
    ``manual``, ``syslog`` (a configuration change message from the device).

    An OPNsense firewall is backed up over the API key of its OPNsense
    source (``opnsense_backup.backup_firewall``: no SSH, ``cred`` unused);
    any other host over SSH with ``cred``, and with none (a policy without
    a credential) it gets an error row that says so. ``deferred``: the run
    is not the credential owner's own request (the schedule, a syslog
    trigger), so a personal credential goes only to an address its owner
    set or an admin confirmed (``managed_targets``); a refused host gets an
    error row with the reason."""
    try:
        if opnsense_masking.is_opnsense_host(host):
            stored = await backup_firewall(host, policy_id=policy_id, capture_method=capture_method)
        elif cred is None:
            raise RuntimeError(NO_CREDENTIAL_MESSAGE)
        else:
            stored = await get_device_config(
                host, cred, capture_method=capture_method, policy_id=policy_id, deferred=deferred
            )
        return (True if stored.created else "skipped"), ""
    except Exception as exc:
        reason = str(exc)[:1000]
        await db.create_config_backup(
            policy_id=policy_id,
            host_id=host["id"],
            config_text="",
            capture_method=capture_method,
            status="error",
            error_message=reason,
        )
        return False, reason


async def backup_host(
    host: dict, cred: dict | None, *, policy_id: int, capture_method: str, deferred: bool = False
) -> bool | str:
    """The result of ``backup_host_outcome``, without the reason."""
    result, _reason = await backup_host_outcome(
        host, cred, policy_id=policy_id, capture_method=capture_method, deferred=deferred
    )
    return result


async def _policy_credential(policy: dict) -> dict | None:
    """The credential a scheduled run of ``policy`` uses, or None when the
    policy has none or (logged) it is rejected. The stored credential is
    re-validated against the policy creator so a policy can never keep
    running with a credential its creator no longer owns (or after the
    creator account is removed)."""
    if policy.get("credential_id") is None:
        return None
    try:
        return await require_credential_access(
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
        return None


async def host_backup_policy(host: dict) -> tuple[dict, dict | None] | None:
    """The enabled backup policy of ``host``'s inventory group to back it up
    with outside the schedule, and that policy's credential: the first one
    by name whose credential is accepted. An OPNsense firewall needs no
    credential (``backup_host`` reads it over the API): the first enabled
    policy, with its credential when accepted, else None. None when there
    is no such policy."""
    if host.get("group_id") is None:
        return None
    opnsense = opnsense_masking.is_opnsense_host(host)
    for policy in await db.get_config_backup_policies(int(host["group_id"])):
        if not policy.get("enabled"):
            continue
        cred = await _policy_credential(policy)
        if cred is not None or opnsense:
            return policy, cred
    return None


async def _run_config_backups_once() -> dict:
    """Run backups for all due policies. A policy without a credential
    backs up its OPNsense hosts and writes an error row for each SSH host.
    A policy whose credential is rejected counts one error and backs up
    its OPNsense hosts only (its SSH hosts get no row); with none it is
    retried at the next wake-up, as before."""
    due_policies = await db.get_config_backup_policies_due()
    policies_run = 0
    hosts_backed_up = 0
    errors = 0

    sem = state.device_op_semaphore()

    for policy in due_policies:
        try:
            hosts = await db.get_hosts_for_group(policy["group_id"])
            cred = await _policy_credential(policy)
            if cred is None and policy.get("credential_id") is not None:
                errors += 1
                hosts = [h for h in hosts if opnsense_masking.is_opnsense_host(h)]
                if not hosts:
                    continue

            async def _backup_host(host, cred_data, pol_id):
                async with sem:
                    return await backup_host(
                        host, cred_data, policy_id=pol_id, capture_method="scheduled", deferred=True
                    )

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
