import json
import os
import time
import zipfile
from io import BytesIO
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from netcontrol.routes import converter


@pytest.mark.asyncio
async def test_convert_only_success(monkeypatch, tmp_path):
    def fake_run(cmd, cwd, capture_output, text):
        summary_path = os.path.join(cwd, "ftd_config_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump({"ok": True}, f)
        return SimpleNamespace(returncode=0, stdout="converted ok", stderr="")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    upload = UploadFile(filename="sample.yaml", file=BytesIO(b"config: value"))

    resp = await converter.convert_only(upload, target_model="ftd-3110", source_model="")
    data = json.loads(resp.body)

    assert data["ok"] is True
    assert data["summary"] == {"ok": True}
    assert data["target_model"] == "ftd-3110"
    assert "snapshot_id" in data
    assert data["session_id"] in converter._sessions

    snapshot_path = os.path.join(
        converter._sessions[data["session_id"]]["session_dir"],
        "backups",
        data["snapshot_id"],
        "ftd_config_summary.json",
    )
    assert os.path.isfile(snapshot_path)


@pytest.mark.asyncio
async def test_import_fortigate_builds_args(monkeypatch, tmp_path):
    session_id = "abc123"
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    converter._sessions[session_id] = {
        "session_dir": str(session_dir),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }

    captured = {}

    def fake_run(args, cwd, capture_output, text):
        captured["args"] = args
        captured["cwd"] = cwd
        return SimpleNamespace(returncode=0, stdout="import ok", stderr="")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    req = converter.ImportRequest(
        session_id=session_id,
        correlation_id="corr-abc",
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        deploy=True,
        debug=True,
        only_flags=["addresses", "services"],
    )

    resp = await converter.import_fortigate(req)
    data = json.loads(resp.body)

    assert data["ok"] is True
    args = captured["args"]
    assert "--host" in args and "1.2.3.4" in args
    assert "--deploy" in args
    assert "--debug" in args
    assert "--addresses" in args and "--services" in args
    assert captured["cwd"] == str(session_dir)


@pytest.mark.asyncio
async def test_import_fortigate_includes_stage_performance_controls(monkeypatch, tmp_path):
    session_id = "perf-args"
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    converter._sessions[session_id] = {
        "session_dir": str(session_dir),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }

    captured = {}

    def fake_run(args, cwd, capture_output, text):
        captured["args"] = args
        captured["cwd"] = cwd
        return SimpleNamespace(returncode=0, stdout="import ok", stderr="")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    req = converter.ImportRequest(
        session_id=session_id,
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        workers=12,
        workers_address_objects=10,
        workers_service_objects=8,
        workers_subinterfaces=4,
        retry_attempts=6,
        retry_attempts_subinterfaces=4,
        retry_backoff=0.4,
        retry_backoff_subinterfaces=0.2,
        retry_jitter_max=0.15,
    )

    resp = await converter.import_fortigate(req)
    data = json.loads(resp.body)

    assert data["ok"] is True
    args = captured["args"]
    assert "--workers" in args and "12" in args
    assert "--workers-address-objects" in args and "10" in args
    assert "--workers-service-objects" in args and "8" in args
    assert "--workers-subinterfaces" in args and "4" in args
    assert "--retry-attempts" in args and "6" in args
    assert "--retry-attempts-subinterfaces" in args and "4" in args
    assert "--retry-backoff" in args and "0.4" in args
    assert "--retry-backoff-subinterfaces" in args and "0.2" in args
    assert "--retry-jitter-max" in args and "0.15" in args


@pytest.mark.asyncio
async def test_converter_session_diff_between_sessions(tmp_path):
    session_a = "session-a"
    session_b = "session-b"
    dir_a = tmp_path / session_a
    dir_b = tmp_path / session_b
    dir_a.mkdir()
    dir_b.mkdir()

    file_name = "ftd_config_service_objects.json"
    with open(dir_a / file_name, "w", encoding="utf-8") as f:
        json.dump({"items": [{"name": "svc-a"}]}, f)
    with open(dir_b / file_name, "w", encoding="utf-8") as f:
        json.dump({"items": [{"name": "svc-b"}]}, f)

    converter._sessions[session_a] = {
        "session_dir": str(dir_a),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }
    converter._sessions[session_b] = {
        "session_dir": str(dir_b),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }

    resp = await converter.converter_session_diff(
        session_id=session_b,
        filename=file_name,
        compare_session_id=session_a,
    )
    body = json.loads(resp.body)

    assert body["ok"] is True
    assert body["has_changes"] is True
    assert "svc-a" in body["diff"]
    assert "svc-b" in body["diff"]


@pytest.mark.asyncio
async def test_converter_session_download_returns_zip(tmp_path):
    session_id = "zip-session"
    session_dir = tmp_path / session_id
    session_dir.mkdir()

    with open(session_dir / "ftd_config_summary.json", "w", encoding="utf-8") as f:
        json.dump({"ok": True}, f)
    with open(session_dir / "ftd_config_service_objects.json", "w", encoding="utf-8") as f:
        json.dump({"items": []}, f)

    converter._sessions[session_id] = {
        "session_dir": str(session_dir),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }

    response = await converter.converter_session_download(session_id=session_id)
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    zipped_bytes = b"".join(chunks)

    with zipfile.ZipFile(BytesIO(zipped_bytes), "r") as archive:
        names = archive.namelist()

    assert "ftd_config_summary.json" in names
    assert "ftd_config_service_objects.json" in names


@pytest.mark.asyncio
async def test_converter_session_state_returns_persisted_summary_and_output(tmp_path):
    session_id = "state-session"
    session_dir = tmp_path / session_id
    session_dir.mkdir()

    with open(session_dir / "ftd_config_summary.json", "w", encoding="utf-8") as f:
        json.dump({"conversion_summary": {"address_objects": 7}}, f)
    with open(session_dir / "ftd_config_conversion_output.log", "w", encoding="utf-8") as f:
        f.write("conversion stdout lines")

    converter._sessions[session_id] = {
        "session_dir": str(session_dir),
        "base": "ftd_config",
        "created_at": time.time(),
        "target_model": "ftd-3110",
    }

    resp = await converter.converter_session_state(session_id=session_id)
    data = json.loads(resp.body)

    assert data["ok"] is True
    assert data["summary"]["conversion_summary"]["address_objects"] == 7
    assert "conversion stdout lines" in data["conversion_output"]


def _write_minimal_artifacts(session_dir: str, base: str = "ftd_config") -> None:
    list_artifacts = {
        "address_objects": [],
        "address_groups": [],
        "service_objects": [],
        "service_groups": [],
        "access_rules": [],
        "static_routes": [],
        "physical_interfaces": [],
        "subinterfaces": [],
        "etherchannels": [],
        "bridge_groups": [],
        "security_zones": [],
    }
    for suffix, payload in list_artifacts.items():
        with open(os.path.join(session_dir, f"{base}_{suffix}.json"), "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    with open(os.path.join(session_dir, f"{base}_summary.json"), "w", encoding="utf-8") as handle:
        json.dump({"conversion_summary": {"access_rules": {"total": 0}}}, handle)

    with open(os.path.join(session_dir, f"{base}_metadata.json"), "w", encoding="utf-8") as handle:
        json.dump({"target_model": "ftd-3110", "output_basename": base, "schema_version": 1}, handle)


@pytest.mark.asyncio
async def test_converter_pipeline_convert_import_cleanup_mocked(monkeypatch):
    calls = []

    def fake_run(args, cwd, capture_output, text):
        calls.append((args, cwd))
        if converter.CONVERTER_PATH in args:
            _write_minimal_artifacts(cwd)
            return SimpleNamespace(returncode=0, stdout="converted ok", stderr="")
        if converter.IMPORTER_PATH in args:
            return SimpleNamespace(returncode=0, stdout="import ok", stderr="")
        if converter.CLEANUP_PATH in args:
            return SimpleNamespace(returncode=0, stdout="cleanup ok", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unknown tool")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    upload = UploadFile(filename="sample.yaml", file=BytesIO(b"config: value"))
    convert_resp = await converter.convert_only(upload, target_model="ftd-3110", source_model="")
    convert_data = json.loads(convert_resp.body)
    session_id = convert_data["session_id"]

    import_req = converter.ImportRequest(
        session_id=session_id,
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        deploy=False,
        debug=True,
        only_flags=["addresses"],
    )
    import_resp = await converter.import_fortigate(import_req)
    import_data = json.loads(import_resp.body)

    cleanup_req = converter.CleanupRequest(
        session_id=session_id,
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        dry_run=True,
        deploy=False,
        debug=True,
        delete_flags=["delete-all"],
    )
    cleanup_resp = await converter.cleanup_ftd(cleanup_req)
    cleanup_data = json.loads(cleanup_resp.body)

    assert convert_data["ok"] is True
    assert import_data["ok"] is True
    assert cleanup_data["ok"] is True

    session_dir = converter._sessions[session_id]["session_dir"]
    base = converter._sessions[session_id]["base"]

    required_list_suffixes = [
        "address_objects",
        "address_groups",
        "service_objects",
        "service_groups",
        "access_rules",
        "static_routes",
        "physical_interfaces",
        "subinterfaces",
        "etherchannels",
        "bridge_groups",
        "security_zones",
    ]
    for suffix in required_list_suffixes:
        path = os.path.join(session_dir, f"{base}_{suffix}.json")
        assert os.path.exists(path)
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        assert isinstance(payload, list)

    with open(os.path.join(session_dir, f"{base}_metadata.json"), encoding="utf-8") as handle:
        metadata = json.load(handle)
    assert metadata["target_model"] == "ftd-3110"
    assert metadata["output_basename"] == "ftd_config"
    assert isinstance(metadata["schema_version"], int)

    with open(os.path.join(session_dir, f"{base}_summary.json"), encoding="utf-8") as handle:
        summary = json.load(handle)
    assert isinstance(summary, dict)
    assert isinstance(summary.get("conversion_summary"), dict)

    import_args = next(args for args, _ in calls if converter.IMPORTER_PATH in args)
    cleanup_args = next(args for args, _ in calls if converter.CLEANUP_PATH in args)
    assert "--addresses" in import_args
    assert "--dry-run" in cleanup_args
    assert "--delete-all" in cleanup_args
    assert "--metadata-file" in cleanup_args


@pytest.mark.asyncio
async def test_converter_pipeline_convert_diff_import_with_artifact_validation(monkeypatch):
    def fake_run(args, cwd, capture_output, text):
        if converter.CONVERTER_PATH in args:
            _write_minimal_artifacts(cwd)
            return SimpleNamespace(returncode=0, stdout="converted ok", stderr="")
        if converter.IMPORTER_PATH in args:
            import_output = (
                "Service Objects 0.40s [OK]\n"
                "Service Groups 0.20s [OK]\n"
            )
            return SimpleNamespace(returncode=0, stdout=import_output, stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    upload = UploadFile(filename="sample.yaml", file=BytesIO(b"config: value"))
    convert_resp = await converter.convert_only(upload, target_model="ftd-3110", source_model="")
    convert_data = json.loads(convert_resp.body)
    session_id = convert_data["session_id"]
    session_dir = converter._sessions[session_id]["session_dir"]
    base = converter._sessions[session_id]["base"]

    service_objects_path = os.path.join(session_dir, f"{base}_service_objects.json")
    with open(service_objects_path, "w", encoding="utf-8") as handle:
        json.dump([{"name": "svc-week6", "protocol": "tcp"}], handle)

    diff_resp = await converter.converter_session_diff(
        session_id=session_id,
        filename=f"{base}_service_objects.json",
    )
    diff_data = json.loads(diff_resp.body)

    assert diff_data["ok"] is True
    assert diff_data["has_changes"] is True
    assert "svc-week6" in diff_data["diff"]

    import_req = converter.ImportRequest(
        session_id=session_id,
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        only_flags=["services"],
    )
    import_resp = await converter.import_fortigate(import_req)
    import_data = json.loads(import_resp.body)

    assert import_data["ok"] is True
    assert "checkpoint" in import_data
    assert "Service Objects" in import_data["checkpoint"]["completed_stages"]

    download_resp = await converter.converter_session_download(session_id=session_id)
    chunks = []
    async for chunk in download_resp.body_iterator:
        chunks.append(chunk)
    archive_bytes = b"".join(chunks)

    with zipfile.ZipFile(BytesIO(archive_bytes), "r") as archive:
        names = archive.namelist()
        assert f"{base}_metadata.json" in names
        assert f"{base}_service_objects.json" in names
        archived_service_objects = json.loads(archive.read(f"{base}_service_objects.json").decode("utf-8"))

    assert archived_service_objects[0]["name"] == "svc-week6"


@pytest.mark.asyncio
async def test_convert_only_returns_500_on_converter_failure(monkeypatch):
    def fake_run(_args, _cwd, capture_output, text):
        return SimpleNamespace(returncode=1, stdout="", stderr="bad yaml")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)
    upload = UploadFile(filename="broken.yaml", file=BytesIO(b"::: not yaml :::"))

    with pytest.raises(HTTPException) as exc:
        await converter.convert_only(upload, target_model="ftd-3110", source_model="")

    assert exc.value.status_code == 500
    assert "Conversion failed" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_cleanup_ftd_requires_delete_flags():
    req = converter.CleanupRequest(
        session_id="",
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        delete_flags=[],
    )

    with pytest.raises(HTTPException) as exc:
        await converter.cleanup_ftd(req)

    assert exc.value.status_code == 400
    assert "Must select at least one item to delete" in str(exc.value.detail)


def test_cleanup_reported_progress_detects_deleted_summary():
    text = "Summary: 2 deleted, 1 failed\nCLEANUP FAILED\n"
    assert converter._cleanup_reported_progress(text) is True


@pytest.mark.asyncio
async def test_cleanup_ftd_returns_partial_success_on_nonzero_with_progress(monkeypatch):
    def fake_run(_args, cwd=None, capture_output=None, text=None):
        stdout = "Summary: 3 deleted, 1 failed\nCLEANUP FAILED\n"
        return SimpleNamespace(returncode=1, stdout=stdout, stderr="")

    monkeypatch.setattr(converter.subprocess, "run", fake_run)

    req = converter.CleanupRequest(
        session_id="",
        correlation_id="corr-cleanup",
        ftd_host="1.2.3.4",
        ftd_username="admin",
        ftd_password="pass",
        dry_run=False,
        deploy=False,
        debug=False,
        delete_flags=["delete-all"],
    )

    resp = await converter.cleanup_ftd(req)
    body = json.loads(resp.body)

    assert body["ok"] is True
    assert body["partial"] is True
    assert body["correlation_id"] == "corr-cleanup"
    assert "3 deleted" in body["cleanup_output"]


def test_emit_import_phase_metrics_parses_timing_summary(monkeypatch):
    observed = []
    counters = []

    monkeypatch.setattr(converter, "observe_timing", lambda name, value: observed.append((name, value)))
    monkeypatch.setattr(converter, "increment_metric", lambda name: counters.append(name))

    output = """
TIMING SUMMARY (seconds)
============================================================
Physical Interfaces                 1.25s [OK]
Subinterfaces (physical parents)    3.50s [FAIL]
------------------------------------------------------------
Total                               4.75s
"""
    converter._emit_import_phase_metrics(output)

    assert ("converter.import.phase.physical_interfaces.duration_ms", 1250.0) in observed
    assert ("converter.import.phase.subinterfaces_physical_parents.duration_ms", 3500.0) in observed
    assert "converter.import.phase.physical_interfaces.ok" in counters
    assert "converter.import.phase.subinterfaces_physical_parents.fail" in counters


def test_cleanup_old_sessions_evicts_memory_only(tmp_path):
    sid = "old-memory-only"
    session_dir = tmp_path / sid
    session_dir.mkdir()

    converter._sessions[sid] = {
        "session_dir": str(session_dir),
        "base": "ftd_config",
        "created_at": time.time() - converter.SESSION_TTL - 5,
        "target_model": "ftd-3110",
    }

    converter._cleanup_old_sessions()

    assert sid not in converter._sessions
    assert session_dir.exists()


def test_prune_converter_sessions_removes_old_sessions_and_backups(tmp_path):
    sessions_root = converter.SESSIONS_DIR
    old_session = os.path.join(sessions_root, "old-session")
    keep_session = os.path.join(sessions_root, "keep-session")
    os.makedirs(old_session, exist_ok=True)
    os.makedirs(keep_session, exist_ok=True)

    backups_dir = os.path.join(keep_session, "backups")
    old_backup = os.path.join(backups_dir, "20200101_000000")
    keep_backup = os.path.join(backups_dir, "29990101_000000")
    os.makedirs(old_backup, exist_ok=True)
    os.makedirs(keep_backup, exist_ok=True)

    now = time.time()
    os.utime(old_session, (now - 5 * 86400, now - 5 * 86400))
    os.utime(keep_session, (now, now))
    os.utime(old_backup, (now - 5 * 86400, now - 5 * 86400))
    os.utime(keep_backup, (now, now))

    converter._sessions["old-session"] = {
        "session_dir": str(old_session),
        "base": "ftd_config",
        "created_at": now - 5 * 86400,
        "target_model": "ftd-3110",
    }
    converter._sessions["keep-session"] = {
        "session_dir": str(keep_session),
        "base": "ftd_config",
        "created_at": now,
        "target_model": "ftd-3110",
    }

    summary = converter.prune_converter_sessions(session_retention_days=2, backup_retention_days=2)

    assert summary["sessions_deleted"] == 1
    assert summary["snapshots_deleted"] == 1
    assert not os.path.exists(old_session)
    assert os.path.exists(keep_session)
    assert not os.path.exists(old_backup)
    assert os.path.exists(keep_backup)
    assert "old-session" not in converter._sessions
    assert "keep-session" in converter._sessions
