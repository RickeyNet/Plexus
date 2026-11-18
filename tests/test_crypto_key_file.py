"""The encryption key file is created once, whole, even when several
processes start together with no key yet (parallel test workers importing
the app, several app workers on a fresh install)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import routes.crypto as crypto

_REPO_ROOT = Path(__file__).resolve().parent.parent

_PRINT_KEY = "import routes.crypto as c, sys; sys.stdout.write(c._key_b64.decode())"


def test_creates_a_key_file_and_reads_it_back(tmp_path, monkeypatch) -> None:
    key_file = tmp_path / "keys" / "netcontrol.key"
    monkeypatch.setattr(crypto, "KEY_FILE", str(key_file))

    created = crypto._load_or_create_key()

    assert len(created) == 44
    assert key_file.read_bytes() == created
    assert crypto._load_or_create_key() == created
    # Only the key itself is left behind, no temporary file.
    assert [p.name for p in key_file.parent.iterdir()] == ["netcontrol.key"]


def test_processes_starting_together_share_one_whole_key(tmp_path) -> None:
    key_file = tmp_path / "netcontrol.key"
    env = {**os.environ, "APP_ENCRYPTION_KEY_FILE": str(key_file), "PYTHONPATH": str(_REPO_ROOT)}
    procs = [
        subprocess.Popen(  # nosec B603
            [sys.executable, "-c", _PRINT_KEY],
            cwd=_REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(8)
    ]
    results = [p.communicate(timeout=120) for p in procs]

    errors = [err.decode() for (_, err), p in zip(results, procs, strict=True) if p.returncode != 0]
    assert errors == []
    keys = {out.decode() for out, _ in results}
    assert keys == {key_file.read_text()}
    assert len(key_file.read_bytes()) == 44
    assert [p.name for p in tmp_path.iterdir()] == ["netcontrol.key"]
