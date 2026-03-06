import json
import os
import time
from io import BytesIO
from types import SimpleNamespace
import zipfile

import pytest
from fastapi import UploadFile

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
