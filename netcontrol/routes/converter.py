import asyncio
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import UTC, datetime
from io import BytesIO

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from routes.database import add_audit_event

from netcontrol.telemetry import configure_logging, increment_metric, observe_timing, redact_value


async def _safe_audit(category: str, action: str, user: str, detail: str, correlation_id: str) -> None:
    """Fire-and-forget audit write.  Never propagates to the caller."""
    try:
        await add_audit_event(category, action, user, detail, correlation_id)
    except Exception:
        LOGGER.debug("Audit write failed for %s/%s (non-fatal)", category, action)

router = APIRouter()
LOGGER = configure_logging("plexus.converter")

# Bounded concurrency for heavy import/cleanup operations
_MAX_CONCURRENT_IMPORTS = int(os.environ.get("APP_MAX_CONCURRENT_IMPORTS", "3"))
_import_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_IMPORTS)

# Persistent directory for converted config files (lives inside the app, gitignored)
SESSIONS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../converter_sessions'))
os.makedirs(SESSIONS_DIR, exist_ok=True)

# In-memory session store: session_id -> {session_dir, base, created_at, target_model}
_sessions: dict = {}
SESSION_TTL = 7200  # 2 hours

CONVERTER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/converter_v2/fortigate_converter_v2.py'))
IMPORTER_PATH  = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py'))
CLEANUP_PATH   = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/FortiGateToFTDTool/ftd_api_cleanup.py'))


def _normalize_correlation_id(correlation_id: str = "", session_id: str = "") -> str:
    corr = correlation_id if isinstance(correlation_id, str) else ""
    sess = session_id if isinstance(session_id, str) else ""
    value = (corr or "").strip() or (sess or "").strip()
    return value or str(uuid.uuid4())


def _log_event(level: str, event: str, **fields) -> None:
    payload = {k: v for k, v in fields.items() if v is not None and v != ""}
    details = " ".join(f"{k}={payload[k]}" for k in sorted(payload.keys()))
    message = f"event={event} {details}".strip()
    log_fn = getattr(LOGGER, level, LOGGER.info)
    log_fn(message)


def _metric_key_fragment(label: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
    return cleaned or "unknown"


def _emit_import_phase_metrics(import_output: str) -> None:
    if not import_output:
        return
    pattern = re.compile(r"^(.+?)\s+([0-9]+(?:\.[0-9]+)?)s\s+\[(OK|FAIL)\]$", re.MULTILINE)
    for match in pattern.finditer(import_output):
        label = match.group(1).strip()
        seconds = float(match.group(2))
        status = match.group(3)
        key = _metric_key_fragment(label)
        observe_timing(f"converter.import.phase.{key}.duration_ms", seconds * 1000)
        increment_metric(f"converter.import.phase.{key}.{status.lower()}")


_CHECKPOINT_FILE = "_checkpoint.json"


def _read_checkpoint(session_dir: str) -> dict:
    """Read the import checkpoint file for a session, if it exists."""
    path = os.path.join(session_dir, _CHECKPOINT_FILE)
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _write_checkpoint(session_dir: str, import_output: str) -> dict:
    """Parse the timing summary from import output and persist checkpoint state.

    Each phase is recorded with its status (ok/fail) so that a subsequent
    import can skip already-completed stages.
    """
    checkpoint: dict = {"completed_stages": [], "failed_stages": [], "updated_at": datetime.now(UTC).isoformat()}
    pattern = re.compile(r"^(.+?)\s+([0-9]+(?:\.[0-9]+)?)s\s+\[(OK|FAIL)\]$", re.MULTILINE)
    for match in pattern.finditer(import_output or ""):
        label = match.group(1).strip()
        status = match.group(3)
        if status == "OK":
            checkpoint["completed_stages"].append(label)
        else:
            checkpoint["failed_stages"].append(label)

    path = os.path.join(session_dir, _CHECKPOINT_FILE)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2)
    except OSError as exc:
        LOGGER.warning("Could not write checkpoint file %s: %s", path, exc)
    return checkpoint


def _conversion_output_path(session_dir: str, base: str) -> str:
    return os.path.join(session_dir, f"{base}_conversion_output.log")


def _cleanup_old_sessions():
    now = time.time()
    for sid in list(_sessions.keys()):
        session_dir = _sessions[sid].get('session_dir', '')
        if not session_dir or not os.path.isdir(session_dir) or now - _sessions[sid]['created_at'] > SESSION_TTL:
            # In-memory cache eviction only; on-disk retention is handled by
            # scheduled pruning with configurable retention days.
            del _sessions[sid]


def prune_converter_sessions(session_retention_days: int, backup_retention_days: int) -> dict:
    """Prune old converter session folders and old backup snapshots.

    Args:
        session_retention_days: Remove entire session folders older than this.
        backup_retention_days: Remove snapshot folders older than this.

    Returns:
        Summary counters for observability/logging.
    """
    now = time.time()
    session_cutoff = now - (max(1, int(session_retention_days)) * 86400)
    backup_cutoff = now - (max(1, int(backup_retention_days)) * 86400)

    summary = {
        "sessions_deleted": 0,
        "snapshots_deleted": 0,
        "sessions_kept": 0,
    }

    if not os.path.isdir(SESSIONS_DIR):
        return summary

    for sid in os.listdir(SESSIONS_DIR):
        session_dir = os.path.join(SESSIONS_DIR, sid)
        if not os.path.isdir(session_dir):
            continue

        session_mtime = os.path.getmtime(session_dir)
        if session_mtime < session_cutoff:
            shutil.rmtree(session_dir, ignore_errors=True)
            _sessions.pop(sid, None)
            summary["sessions_deleted"] += 1
            continue

        summary["sessions_kept"] += 1
        backups_dir = os.path.join(session_dir, "backups")
        if not os.path.isdir(backups_dir):
            continue

        for snapshot in os.listdir(backups_dir):
            snapshot_dir = os.path.join(backups_dir, snapshot)
            if not os.path.isdir(snapshot_dir):
                continue
            if os.path.getmtime(snapshot_dir) < backup_cutoff:
                shutil.rmtree(snapshot_dir, ignore_errors=True)
                summary["snapshots_deleted"] += 1

    # Evict stale in-memory entries that no longer exist on disk.
    for sid in list(_sessions.keys()):
        session_dir = _sessions[sid].get('session_dir', '')
        if not session_dir or not os.path.isdir(session_dir):
            _sessions.pop(sid, None)

    return summary


def _load_session_from_disk(session_id: str):
    """Rebuild session metadata from files on disk if memory state is missing."""
    session_dir = os.path.join(SESSIONS_DIR, session_id)
    if not os.path.isdir(session_dir):
        return None

    metadata_path = os.path.join(session_dir, 'ftd_config_metadata.json')
    target_model = ''
    base = 'ftd_config'
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                meta = json.load(f)
                target_model = meta.get('target_model', '') or ''
                base = meta.get('output_basename', 'ftd_config') or 'ftd_config'
        except Exception:
            pass
    created_at = os.path.getmtime(session_dir)

    _sessions[session_id] = {
        'session_dir':  session_dir,
        'base':         base,
        'created_at':   created_at,
        'target_model': target_model,
    }
    return _sessions[session_id]


def _get_session(session_id: str):
    session = _sessions.get(session_id)
    if session:
        return session
    return _load_session_from_disk(session_id)


def _resolve_session_file(session_dir: str, base: str, filename: str):
    """Ensure the requested file stays inside the session directory and matches the expected prefix."""
    if not filename.startswith(base) or not filename.endswith('.json'):
        raise HTTPException(status_code=400, detail='Invalid file name.')
    abs_session = os.path.abspath(session_dir)
    path = os.path.abspath(os.path.join(session_dir, filename))
    if not path.startswith(abs_session):
        raise HTTPException(status_code=400, detail='Invalid file path.')
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='File not found.')
    return path


def _session_backup_root(session_dir: str) -> str:
    path = os.path.join(session_dir, "backups")
    os.makedirs(path, exist_ok=True)
    return path


def _create_timestamped_snapshot(session_dir: str, base: str) -> str:
    """Store a point-in-time copy of generated converter files for rollback/diff."""
    snapshot_name = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    snapshot_dir = os.path.join(_session_backup_root(session_dir), snapshot_name)
    os.makedirs(snapshot_dir, exist_ok=True)

    for fname in os.listdir(session_dir):
        if fname.startswith(base) and fname.endswith('.json'):
            shutil.copy2(os.path.join(session_dir, fname), os.path.join(snapshot_dir, fname))
    return snapshot_name


def _latest_snapshot_with_file(session_dir: str, filename: str) -> str | None:
    backups_dir = _session_backup_root(session_dir)
    if not os.path.isdir(backups_dir):
        return None

    candidate_snapshots = []
    for snapshot in os.listdir(backups_dir):
        snapshot_dir = os.path.join(backups_dir, snapshot)
        file_path = os.path.join(snapshot_dir, filename)
        if os.path.isdir(snapshot_dir) and os.path.isfile(file_path):
            candidate_snapshots.append((snapshot, file_path))
    if not candidate_snapshots:
        return None
    candidate_snapshots.sort(key=lambda item: item[0], reverse=True)
    return candidate_snapshots[0][1]


def _pretty_json_text(path: str) -> str:
    with open(path, encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    return json.dumps(data, indent=2, sort_keys=True)


def _load_summary_file(session_dir: str, base: str) -> dict:
    summary_path = os.path.join(session_dir, f"{base}_summary.json")
    if not os.path.exists(summary_path):
        return {}
    try:
        with open(summary_path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _load_conversion_output(session_dir: str, base: str) -> str:
    output_path = _conversion_output_path(session_dir, base)
    if not os.path.exists(output_path):
        return ''
    try:
        with open(output_path, encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''


def _cleanup_reported_progress(output_text: str) -> bool:
    """Return True when cleanup output indicates at least one deletion/reset succeeded."""
    if not output_text:
        return False

    # Match lines like "Summary: 3 deleted, 1 failed" from cleanup phases.
    for match in re.finditer(r"Summary:\s*(\d+)\s+deleted", output_text, flags=re.IGNORECASE):
        try:
            if int(match.group(1)) > 0:
                return True
        except (TypeError, ValueError):
            continue

    # Fallback markers used by the cleanup script for successful actions.
    lowered = output_text.lower()
    return "[deleted]" in lowered or "[destroyed]" in lowered or "[thrown" in lowered


@router.post('/api/convert-only')
async def convert_only(
    yaml_file: UploadFile = File(...),
    target_model: str = Form(default=''),
    source_model: str = Form(default=''),
    correlation_id: str = Form(default='')
):
    """
    Step 1: Convert a FortiGate YAML config to FTD JSON files.
    Returns a session_id, conversion output text, and a summary dict.
    """
    started = time.perf_counter()
    _cleanup_old_sessions()
    session_id = str(uuid.uuid4())
    corr_id = _normalize_correlation_id(correlation_id, session_id)
    session_dir = os.path.join(SESSIONS_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    try:
        _log_event("info", "converter.convert.start", session_id=session_id, correlation_id=corr_id)
        filename = yaml_file.filename or 'input.yaml'
        yaml_path = os.path.join(session_dir, filename)
        parse_started = time.perf_counter()
        with open(yaml_path, 'wb') as f:
            f.write(await yaml_file.read())
        observe_timing("converter.parse.duration_ms", (time.perf_counter() - parse_started) * 1000)

        effective_model = target_model.strip() if target_model else 'ftd-3120'
        # Always use 'ftd_config' as the output base name so the importer can reliably find the files
        BASE_NAME = 'ftd_config'

        cmd = [
            sys.executable, CONVERTER_PATH, yaml_path,
            '--target-model', effective_model,
            '--output', BASE_NAME
        ]

        convert_started = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=session_dir, capture_output=True, text=True
        )
        observe_timing("converter.convert.stage.duration_ms", (time.perf_counter() - convert_started) * 1000)
        if proc.returncode != 0:
            increment_metric("converter.convert.failure")
            observe_timing("converter.convert.duration_ms", (time.perf_counter() - started) * 1000)
            LOGGER.error("Conversion failed for session %s: %s", session_id, redact_value(proc.stderr or proc.stdout))
            shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(status_code=500, detail="Conversion failed. Check server logs for details.")

        write_started = time.perf_counter()
        summary = _load_summary_file(session_dir, BASE_NAME)
        with open(_conversion_output_path(session_dir, BASE_NAME), 'w', encoding='utf-8') as f:
            f.write(proc.stdout or '')

        _sessions[session_id] = {
            'session_dir':  session_dir,
            'base':         BASE_NAME,
            'created_at':   time.time(),
            'target_model': effective_model
        }
        snapshot_id = _create_timestamped_snapshot(session_dir, BASE_NAME)
        observe_timing("converter.write_artifacts.duration_ms", (time.perf_counter() - write_started) * 1000)
        increment_metric("converter.convert.success")
        observe_timing("converter.convert.duration_ms", (time.perf_counter() - started) * 1000)
        _log_event(
            "info",
            "converter.convert.complete",
            session_id=session_id,
            correlation_id=corr_id,
            target_model=effective_model,
            snapshot_id=snapshot_id,
        )
        await _safe_audit("converter", "convert.complete", "", f"session={session_id} model={effective_model}", corr_id)

        return JSONResponse({
            'ok': True,
            'session_id': session_id,
            'correlation_id': corr_id,
            'conversion_output': proc.stdout,
            'summary': summary,
            'target_model': effective_model,
            'snapshot_id': snapshot_id,
        })
    except HTTPException:
        raise
    except Exception as e:
        increment_metric("converter.convert.failure")
        observe_timing("converter.convert.duration_ms", (time.perf_counter() - started) * 1000)
        LOGGER.error("Unexpected conversion error for session %s: %s", session_id, redact_value(str(e)))
        shutil.rmtree(session_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Conversion failed due to an unexpected server error")


class ImportRequest(BaseModel):
    session_id: str
    correlation_id: str = ''
    ftd_host: str
    ftd_username: str
    ftd_password: str
    deploy: bool = False
    debug: bool = False
    only_flags: list[str] = []
    workers: int = 6
    workers_address_objects: int | None = None
    workers_service_objects: int | None = None
    workers_subinterfaces: int | None = None
    retry_attempts: int | None = None
    retry_attempts_address_objects: int | None = None
    retry_attempts_service_objects: int | None = None
    retry_attempts_subinterfaces: int | None = None
    retry_backoff: float | None = None
    retry_backoff_address_objects: float | None = None
    retry_backoff_service_objects: float | None = None
    retry_backoff_subinterfaces: float | None = None
    retry_jitter_max: float = 0.25


@router.post('/api/import-fortigate')
async def import_fortigate(req: ImportRequest):
    """
    Step 2: Import previously converted FTD JSON files into a live FTD device.
    """
    started = time.perf_counter()
    corr_id = _normalize_correlation_id(req.correlation_id, req.session_id)
    session = _get_session(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found. Please run Convert again.')

    session_dir = session['session_dir']
    base        = session['base']

    async with _import_semaphore:
        _log_event("info", "converter.import.start", session_id=req.session_id, correlation_id=corr_id)

        import_args = [
            sys.executable, '-u', IMPORTER_PATH,
            '--host',     req.ftd_host,
            '--username', req.ftd_username,
            '--password', req.ftd_password,
            '--base',     base
        ]
        if req.deploy:
            import_args.append('--deploy')
        if req.debug:
            import_args.append('--debug')
        import_args += ['--workers', str(max(1, req.workers))]
        if req.workers_address_objects is not None:
            import_args += ['--workers-address-objects', str(max(1, req.workers_address_objects))]
        if req.workers_service_objects is not None:
            import_args += ['--workers-service-objects', str(max(1, req.workers_service_objects))]
        if req.workers_subinterfaces is not None:
            import_args += ['--workers-subinterfaces', str(max(1, req.workers_subinterfaces))]

        if req.retry_attempts is not None:
            import_args += ['--retry-attempts', str(max(1, req.retry_attempts))]
        if req.retry_attempts_address_objects is not None:
            import_args += ['--retry-attempts-address-objects', str(max(1, req.retry_attempts_address_objects))]
        if req.retry_attempts_service_objects is not None:
            import_args += ['--retry-attempts-service-objects', str(max(1, req.retry_attempts_service_objects))]
        if req.retry_attempts_subinterfaces is not None:
            import_args += ['--retry-attempts-subinterfaces', str(max(1, req.retry_attempts_subinterfaces))]

        if req.retry_backoff is not None:
            import_args += ['--retry-backoff', str(max(0.0, req.retry_backoff))]
        if req.retry_backoff_address_objects is not None:
            import_args += ['--retry-backoff-address-objects', str(max(0.0, req.retry_backoff_address_objects))]
        if req.retry_backoff_service_objects is not None:
            import_args += ['--retry-backoff-service-objects', str(max(0.0, req.retry_backoff_service_objects))]
        if req.retry_backoff_subinterfaces is not None:
            import_args += ['--retry-backoff-subinterfaces', str(max(0.0, req.retry_backoff_subinterfaces))]
        import_args += ['--retry-jitter-max', str(max(0.0, req.retry_jitter_max))]
        for flag in req.only_flags:
            import_args.append(f'--{flag}')

        proc = subprocess.run(import_args, cwd=session_dir, capture_output=True, text=True)

        # Keep session files so cleanup/rollback can still reference them; TTL handles eventual removal
        if proc.returncode != 0:
            _write_checkpoint(session_dir, proc.stdout or "")
            increment_metric("converter.import.failure")
            observe_timing("converter.import.duration_ms", (time.perf_counter() - started) * 1000)
            LOGGER.error("Import failed for session %s: %s", req.session_id, redact_value(proc.stderr or proc.stdout))
            raise HTTPException(status_code=500, detail="Import failed. Check server logs for details.")

        _emit_import_phase_metrics(proc.stdout or "")
        checkpoint = _write_checkpoint(session_dir, proc.stdout or "")
        increment_metric("converter.import.success")
        observe_timing("converter.import.duration_ms", (time.perf_counter() - started) * 1000)
        _log_event("info", "converter.import.complete", session_id=req.session_id, correlation_id=corr_id)
        await _safe_audit("converter", "import.complete", "", f"session={req.session_id} host={req.ftd_host} deploy={req.deploy}", corr_id)

        return JSONResponse({'ok': True, 'correlation_id': corr_id, 'import_output': proc.stdout, 'checkpoint': checkpoint})


@router.post('/api/import-fortigate-stream')
async def import_fortigate_stream(req: ImportRequest):
    """Stream import output live to the frontend."""
    corr_id = _normalize_correlation_id(req.correlation_id, req.session_id)
    session = _sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found. Please run Convert again.')

    session_dir = session['session_dir']
    base        = session['base']
    _log_event("info", "converter.import.stream.start", session_id=req.session_id, correlation_id=corr_id)

    import_args = [
        sys.executable, IMPORTER_PATH,
        '--host',     req.ftd_host,
        '--username', req.ftd_username,
        '--password', req.ftd_password,
        '--base',     base
    ]
    if req.deploy:
        import_args.append('--deploy')
    if req.debug:
        import_args.append('--debug')
    import_args += ['--workers', str(max(1, req.workers))]
    if req.workers_address_objects is not None:
        import_args += ['--workers-address-objects', str(max(1, req.workers_address_objects))]
    if req.workers_service_objects is not None:
        import_args += ['--workers-service-objects', str(max(1, req.workers_service_objects))]
    if req.workers_subinterfaces is not None:
        import_args += ['--workers-subinterfaces', str(max(1, req.workers_subinterfaces))]

    if req.retry_attempts is not None:
        import_args += ['--retry-attempts', str(max(1, req.retry_attempts))]
    if req.retry_attempts_address_objects is not None:
        import_args += ['--retry-attempts-address-objects', str(max(1, req.retry_attempts_address_objects))]
    if req.retry_attempts_service_objects is not None:
        import_args += ['--retry-attempts-service-objects', str(max(1, req.retry_attempts_service_objects))]
    if req.retry_attempts_subinterfaces is not None:
        import_args += ['--retry-attempts-subinterfaces', str(max(1, req.retry_attempts_subinterfaces))]

    if req.retry_backoff is not None:
        import_args += ['--retry-backoff', str(max(0.0, req.retry_backoff))]
    if req.retry_backoff_address_objects is not None:
        import_args += ['--retry-backoff-address-objects', str(max(0.0, req.retry_backoff_address_objects))]
    if req.retry_backoff_service_objects is not None:
        import_args += ['--retry-backoff-service-objects', str(max(0.0, req.retry_backoff_service_objects))]
    if req.retry_backoff_subinterfaces is not None:
        import_args += ['--retry-backoff-subinterfaces', str(max(0.0, req.retry_backoff_subinterfaces))]
    import_args += ['--retry-jitter-max', str(max(0.0, req.retry_jitter_max))]
    for flag in req.only_flags:
        import_args.append(f'--{flag}')

    proc = await asyncio.create_subprocess_exec(
        *import_args,
        cwd=session_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    async def stream_lines():
        try:
            assert proc.stdout is not None
            async for line in proc.stdout:
                yield line.decode('utf-8', errors='replace')
            rc = await proc.wait()
            if rc != 0:
                yield f"\n[ERROR] Import failed (exit {rc}).\n"
        finally:
            # No explicit close needed; StreamReader lacks close() and the subprocess pipes
            # are cleaned up when the process exits.
            pass

    return StreamingResponse(stream_lines(), media_type='text/plain')


class CleanupRequest(BaseModel):
    session_id: str = ''
    correlation_id: str = ''
    ftd_host: str
    ftd_username: str
    ftd_password: str
    dry_run: bool = False
    deploy: bool = False
    debug: bool = False
    delete_flags: list[str] = []


@router.post('/api/cleanup-ftd')
async def cleanup_ftd(req: CleanupRequest):
    """
    Step 3 (Optional): Delete / rollback objects previously imported to FTD.
    """
    started = time.perf_counter()
    corr_id = _normalize_correlation_id(req.correlation_id, req.session_id)
    if not req.delete_flags:
        raise HTTPException(status_code=400, detail='Must select at least one item to delete.')

    session = _get_session(req.session_id) if req.session_id else None
    session_dir  = session['session_dir'] if session else SESSIONS_DIR
    target_model = session.get('target_model', '') if session else ''
    _log_event("info", "converter.cleanup.start", session_id=req.session_id, correlation_id=corr_id)

    cmd = [
        sys.executable, CLEANUP_PATH,
        '--host',     req.ftd_host,
        '--username', req.ftd_username,
        '--password', req.ftd_password,
        '--yes',  # skip interactive prompt; UI provides confirmation
    ]
    if req.dry_run:
        cmd.append('--dry-run')
    if req.deploy:
        cmd.append('--deploy')
    if req.debug:
        cmd.append('--debug')
    if target_model:
        cmd += ['--appliance-model', target_model]
    if session and session.get('session_dir'):
        metadata_path = os.path.join(session['session_dir'], f"{session['base']}_metadata.json")
        if os.path.exists(metadata_path):
            cmd += ['--metadata-file', metadata_path]
    for flag in req.delete_flags:
        cmd.append(f'--{flag}')

    proc = subprocess.run(cmd, cwd=session_dir, capture_output=True, text=True)
    if proc.returncode != 0:
        cleanup_output = proc.stdout or proc.stderr or ""
        if _cleanup_reported_progress(cleanup_output):
            increment_metric("converter.cleanup.partial")
            observe_timing("converter.cleanup.duration_ms", (time.perf_counter() - started) * 1000)
            LOGGER.warning(
                "Cleanup completed with warnings for session %s (exit %s)",
                req.session_id,
                proc.returncode,
            )
            _log_event("warning", "converter.cleanup.partial", session_id=req.session_id, correlation_id=corr_id)
            return JSONResponse({'ok': True, 'partial': True, 'correlation_id': corr_id, 'cleanup_output': cleanup_output})

        increment_metric("converter.cleanup.failure")
        observe_timing("converter.cleanup.duration_ms", (time.perf_counter() - started) * 1000)
        LOGGER.error("Cleanup failed for session %s: %s", req.session_id, redact_value(proc.stderr or proc.stdout))
        raise HTTPException(status_code=500, detail="Cleanup failed. Check server logs for details.")

    increment_metric("converter.cleanup.success")
    observe_timing("converter.cleanup.duration_ms", (time.perf_counter() - started) * 1000)
    _log_event("info", "converter.cleanup.complete", session_id=req.session_id, correlation_id=corr_id)
    await _safe_audit("converter", "cleanup.complete", "", f"session={req.session_id} host={req.ftd_host} dry_run={req.dry_run}", corr_id)

    return JSONResponse({'ok': True, 'correlation_id': corr_id, 'cleanup_output': proc.stdout})


@router.post('/api/cleanup-ftd-stream')
async def cleanup_ftd_stream(req: CleanupRequest):
    """Stream cleanup output live to the frontend."""
    corr_id = _normalize_correlation_id(req.correlation_id, req.session_id)
    if not req.delete_flags:
        raise HTTPException(status_code=400, detail='Must select at least one item to delete.')

    session = _get_session(req.session_id) if req.session_id else None
    session_dir  = session['session_dir'] if session else SESSIONS_DIR
    target_model = session.get('target_model', '') if session else ''
    _log_event("info", "converter.cleanup.stream.start", session_id=req.session_id, correlation_id=corr_id)

    cmd = [
        sys.executable, CLEANUP_PATH,
        '--host',     req.ftd_host,
        '--username', req.ftd_username,
        '--password', req.ftd_password,
        '--yes',
    ]
    if req.dry_run:
        cmd.append('--dry-run')
    if req.deploy:
        cmd.append('--deploy')
    if req.debug:
        cmd.append('--debug')
    if target_model:
        cmd += ['--appliance-model', target_model]
    if session and session.get('session_dir'):
        metadata_path = os.path.join(session['session_dir'], f"{session['base']}_metadata.json")
        if os.path.exists(metadata_path):
            cmd += ['--metadata-file', metadata_path]
    for flag in req.delete_flags:
        cmd.append(f'--{flag}')

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=session_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    async def stream_lines():
        collected = []
        try:
            assert proc.stdout is not None
            async for line in proc.stdout:
                text_line = line.decode('utf-8', errors='replace')
                collected.append(text_line)
                yield text_line
            rc = await proc.wait()
            if rc != 0:
                full_output = "".join(collected)
                if _cleanup_reported_progress(full_output):
                    yield f"\n[WARN] Cleanup completed with warnings (exit {rc}).\n"
                else:
                    yield f"\n[ERROR] Cleanup failed (exit {rc}).\n"
        finally:
            pass

    return StreamingResponse(stream_lines(), media_type='text/plain')


class ResetRequest(BaseModel):
    session_id: str = ''


@router.post('/api/reset-session')
async def reset_session(req: ResetRequest):
    """Delete a session's files when the user clicks Start Over."""
    session = _sessions.pop(req.session_id, None)
    if session:
        shutil.rmtree(session['session_dir'], ignore_errors=True)
    else:
        # Also handle cases where the session wasn't in memory (e.g., after reload) but exists on disk
        session_dir = os.path.join(SESSIONS_DIR, req.session_id)
        if os.path.isdir(session_dir):
            shutil.rmtree(session_dir, ignore_errors=True)
    return JSONResponse({'ok': True})


@router.get('/api/converter-sessions/{session_id}/checkpoint')
async def get_import_checkpoint(session_id: str):
    """Return the import checkpoint for a session (completed/failed stages)."""
    session_dir = os.path.join(SESSIONS_DIR, session_id)
    if not os.path.isdir(session_dir):
        raise HTTPException(status_code=404, detail='Session not found.')
    checkpoint = _read_checkpoint(session_dir)
    return JSONResponse({'ok': True, 'checkpoint': checkpoint})


@router.get('/api/converter-sessions')
async def list_converter_sessions():
    """List on-disk converter sessions for re-use after page reload."""
    sessions = []
    for sid in os.listdir(SESSIONS_DIR):
        session_dir = os.path.join(SESSIONS_DIR, sid)
        if not os.path.isdir(session_dir):
            continue
        meta_path = os.path.join(session_dir, 'ftd_config_metadata.json')
        summary_path = os.path.join(session_dir, 'ftd_config_summary.json')
        target_model = ''
        base = 'ftd_config'
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                    target_model = meta.get('target_model', '') or ''
                    base = meta.get('output_basename', 'ftd_config') or 'ftd_config'
            except Exception:
                pass
        created_at = os.path.getmtime(session_dir)
        sessions.append({
            'session_id': sid,
            'target_model': target_model,
            'base': base,
            'created_at': created_at,
            'created_at_iso': datetime.fromtimestamp(created_at).isoformat(),
            'has_summary': os.path.exists(summary_path),
            'has_metadata': os.path.exists(meta_path),
        })
    # Sort newest first
    sessions.sort(key=lambda x: x['created_at'], reverse=True)
    return JSONResponse({'ok': True, 'sessions': sessions})


@router.get('/api/converter-session-files')
async def converter_session_files(session_id: str):
    """List generated config files for a session (names and sizes only)."""
    session = _get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found.')

    session_dir = session['session_dir']
    base = session['base']
    files = []
    for fname in os.listdir(session_dir):
        if fname.startswith(base) and fname.endswith('.json'):
            path = os.path.join(session_dir, fname)
            files.append({
                'name': fname,
                'size': os.path.getsize(path),
                'updated_at': os.path.getmtime(path)
            })
    files.sort(key=lambda x: x['name'])

    return JSONResponse({
        'ok': True,
        'session_id': session_id,
        'target_model': session.get('target_model', ''),
        'base': base,
        'files': files
    })


@router.get('/api/converter-session-file')
async def converter_session_file(session_id: str, filename: str):
    """Return the full contents of a generated config file for preview purposes."""
    session = _get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found.')

    session_dir = session['session_dir']
    base = session['base']
    path = _resolve_session_file(session_dir, base, filename)

    with open(path, encoding='utf-8', errors='ignore') as f:
        content = f.read()

    return JSONResponse({
        'ok': True,
        'session_id': session_id,
        'filename': filename,
        'content': content
    })


@router.get('/api/converter-session-state')
async def converter_session_state(session_id: str):
    """Return persisted conversion summary/output for a session after page reload."""
    session = _get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found.')

    session_dir = session['session_dir']
    base = session['base']
    summary = _load_summary_file(session_dir, base)
    conversion_output = _load_conversion_output(session_dir, base)

    return JSONResponse({
        'ok': True,
        'session_id': session_id,
        'target_model': session.get('target_model', ''),
        'base': base,
        'summary': summary,
        'conversion_output': conversion_output,
    })


@router.get('/api/converter-session-diff')
async def converter_session_diff(session_id: str, filename: str, compare_session_id: str = ''):
    """Generate a unified diff between this session and a baseline session/snapshot."""
    session = _get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found.')

    session_dir = session['session_dir']
    base = session['base']
    current_path = _resolve_session_file(session_dir, base, filename)

    previous_path = None
    if compare_session_id:
        compare_session = _get_session(compare_session_id)
        if not compare_session:
            raise HTTPException(status_code=404, detail='compare_session_id not found.')
        previous_path = _resolve_session_file(compare_session['session_dir'], compare_session['base'], filename)
    else:
        previous_path = _latest_snapshot_with_file(session_dir, filename)
    if not previous_path:
        raise HTTPException(status_code=404, detail='No snapshot available for diff.')

    current_text = _pretty_json_text(current_path).splitlines(keepends=True)
    previous_text = _pretty_json_text(previous_path).splitlines(keepends=True)
    diff_text = ''.join(
        difflib.unified_diff(
            previous_text,
            current_text,
            fromfile='snapshot',
            tofile='current',
            n=3,
        )
    )

    return JSONResponse({
        'ok': True,
        'session_id': session_id,
        'compare_session_id': compare_session_id or None,
        'filename': filename,
        'diff': diff_text,
        'has_changes': bool(diff_text.strip()),
    })


@router.get('/api/converter-session-download')
async def converter_session_download(session_id: str):
    """Download all generated converter artifacts for a session as a zip file."""
    session = _get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail='Session not found.')

    session_dir = session['session_dir']
    base = session['base']

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(session_dir):
            if fname.startswith(base) and fname.endswith('.json'):
                zf.write(os.path.join(session_dir, fname), arcname=fname)

    memory_file.seek(0)
    timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
    headers = {
        'Content-Disposition': f'attachment; filename="plexus_converter_{session_id}_{timestamp}.zip"'
    }
    return StreamingResponse(memory_file, media_type='application/zip', headers=headers)
