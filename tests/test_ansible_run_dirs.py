"""Ansible run directories.

Each Ansible run writes its playbook and an inventory holding the device
password into a private run directory (mode 0700) that is removed when the
run ends. A run killed hard leaves it behind, so starting a run first removes
earlier run directories: only this code's (its name prefix), owned by the
service user, not in use by this process and older than any run can be.

``ansible_runner`` does not import on every platform (it needs ``fcntl``),
so the backend module is loaded with a stand-in when the real one fails.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import sys
import types

import pytest

_BACKEND = pathlib.Path(__file__).resolve().parent.parent / "routes" / "ansible_runner_backend.py"


@pytest.fixture
def backend(monkeypatch):
    try:
        import ansible_runner  # noqa: F401
    except Exception:
        monkeypatch.setitem(sys.modules, "ansible_runner", types.ModuleType("ansible_runner"))
    spec = importlib.util.spec_from_file_location("ansible_backend_under_test", _BACKEND)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_run_dir(parent: pathlib.Path, name: str, age_seconds: float, now: float) -> pathlib.Path:
    path = parent / name
    (path / "inventory").mkdir(parents=True)
    (path / "inventory" / "hosts.json").write_text('{"all": {}}', encoding="utf-8")
    os.utime(path, (now - age_seconds, now - age_seconds))
    return path


def test_sweep_removes_only_old_run_directories_of_this_code(backend, tmp_path):
    now = 1_900_000_000.0
    stale = _make_run_dir(tmp_path, backend.RUN_DIR_PREFIX + "old", backend.STALE_RUN_DIR_SECONDS + 60, now)
    fresh = _make_run_dir(tmp_path, backend.RUN_DIR_PREFIX + "new", 60, now)
    other = _make_run_dir(tmp_path, "someone_else_old", backend.STALE_RUN_DIR_SECONDS + 60, now)
    plain_file = tmp_path / (backend.RUN_DIR_PREFIX + "file")
    plain_file.write_text("not a directory", encoding="utf-8")
    os.utime(plain_file, (now - backend.STALE_RUN_DIR_SECONDS - 60,) * 2)

    removed = backend.sweep_stale_run_dirs(str(tmp_path), now=now)

    assert removed == [str(stale)]
    assert not stale.exists()
    assert fresh.exists() and other.exists() and plain_file.exists()


def test_sweep_skips_a_run_directory_in_use(backend, tmp_path, monkeypatch):
    now = 1_900_000_000.0
    running = _make_run_dir(tmp_path, backend.RUN_DIR_PREFIX + "running", backend.STALE_RUN_DIR_SECONDS + 60, now)
    monkeypatch.setattr(backend, "_ACTIVE_RUN_DIRS", {os.path.abspath(str(running))})
    assert backend.sweep_stale_run_dirs(str(tmp_path), now=now) == []
    assert running.exists()


def test_new_run_dir_is_private_swept_first_and_released(backend, tmp_path, monkeypatch):
    monkeypatch.setattr(backend.tempfile, "tempdir", str(tmp_path))
    now = backend.time.time()
    stale = _make_run_dir(tmp_path, backend.RUN_DIR_PREFIX + "crashed", backend.STALE_RUN_DIR_SECONDS + 60, now)

    path = backend.new_run_dir()
    try:
        assert not stale.exists()
        assert os.path.basename(path).startswith(backend.RUN_DIR_PREFIX)
        assert path in backend._ACTIVE_RUN_DIRS
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
            assert os.stat(path).st_uid == os.getuid()
    finally:
        backend.remove_run_dir(path)
    assert not os.path.exists(path)
    assert path not in backend._ACTIVE_RUN_DIRS


async def test_a_run_reads_its_events_and_files_off_the_event_loop(backend, tmp_path, monkeypatch):
    import threading

    monkeypatch.setattr(backend.tempfile, "tempdir", str(tmp_path))
    loop_thread = threading.get_ident()
    event_threads: list[int] = []

    class _Runner:
        status = "successful"

        @property
        def events(self):
            event_threads.append(threading.get_ident())
            yield {"event": "runner_on_ok", "event_data": {"host": "sw-a", "task": "t", "res": {}}}

    def fake_run(**kwargs):
        assert os.path.exists(os.path.join(kwargs["private_data_dir"], "project", "playbook.yml"))
        return _Runner()

    monkeypatch.setattr(backend.ansible_runner, "run", fake_run, raising=False)
    result = await backend.execute_ansible_playbook(
        "- hosts: all\n", [{"ip_address": "192.0.2.5", "hostname": "sw-a"}], {"username": "u", "password": "p"}
    )
    assert result.status == "success" and result.hosts_ok == 1
    assert event_threads and event_threads[0] != loop_thread
    assert not backend._ACTIVE_RUN_DIRS
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(backend.RUN_DIR_PREFIX)]
