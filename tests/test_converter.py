import json
import os
import time
from io import BytesIO
from types import SimpleNamespace

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
    assert data["session_id"] in converter._sessions


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
