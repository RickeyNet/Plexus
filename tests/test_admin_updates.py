"""Tests for the in-app update apply/rollback/progress routes.

The app only writes request.json into the handoff directory; the host
updater (deploy/plexus-updater.sh) does the work. These tests point
PLEXUS_UPDATES_DIR at tmp_path and call the route functions directly with
the config + audit layers monkeypatched, so they need no Docker host.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import netcontrol.routes.admin_updates as au
import pytest
from fastapi import HTTPException


class _FakeRequest:
    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.state = SimpleNamespace(correlation_id="corr-1")


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Handoff dir in tmp_path, in-memory config, captured audit events."""
    monkeypatch.setenv("PLEXUS_UPDATES_DIR", str(tmp_path))
    store: dict[str, Any] = {}
    audits: list[tuple[str, str, str]] = []

    async def _get(key):
        return store.get(key)

    async def _set(key, value):
        store[key] = value

    async def _audit(category, action, user="", detail="", correlation_id=""):
        audits.append((category, action, detail))

    monkeypatch.setattr(au.db, "get_auth_setting", _get)
    monkeypatch.setattr(au.db, "set_auth_setting", _set)
    monkeypatch.setattr(au, "_audit", _audit)
    monkeypatch.setattr(au, "_get_session", lambda request: {"user": "alice"})
    au._last_check_cache.clear()
    yield SimpleNamespace(dir=tmp_path, store=store, audits=audits)
    au._last_check_cache.clear()


def _configure(env, **overrides):
    cfg = dict(au._DEFAULT_CONFIG)
    cfg.update(overrides)
    env.store[au._SETTING_KEY] = cfg
    return cfg


def _install_agent(env):
    (env.dir / ".agent-installed").write_text("", encoding="utf-8")


def _seed_check(channel: str, latest: str, newer: bool = True, ok: bool = True):
    au._last_check_cache[channel] = {"ok": ok, "is_newer": newer, "latest_version": latest, "channel": channel}


def _status(exc_info) -> int:
    return exc_info.value.status_code


# ── _sanitize_config ─────────────────────────────────────────────────────


def test_sanitize_accepts_edge_and_normalizes_image_repo():
    out = au._sanitize_config({"channel": "EDGE", "image_repo": "GHCR.io/RickeyNet/Plexus"})
    assert out["channel"] == "edge"
    assert out["image_repo"] == "ghcr.io/rickeynet/plexus"


def test_sanitize_defaults_image_repo():
    out = au._sanitize_config({"channel": "release"})
    assert out["image_repo"] == "ghcr.io/rickeynet/plexus"


@pytest.mark.parametrize(
    "bad",
    [
        "plexus",  # no registry/owner
        "ghcr.io/rickeynet/plexus:latest",  # tag not allowed
        "ghcr.io/rickeynet/plexus;rm -rf /",
        "ghcr.io/ rickeynet/plexus",
        "ghcr.io/rickeynet/plexus/",
        "",
    ],
)
def test_sanitize_rejects_bad_image_repo(bad):
    with pytest.raises(HTTPException) as exc:
        au._sanitize_config({"channel": "release", "image_repo": bad})
    assert _status(exc) == 400


def test_sanitize_rejects_unknown_channel():
    with pytest.raises(HTTPException):
        au._sanitize_config({"channel": "nightly"})


# ── apply guards ─────────────────────────────────────────────────────────


def test_apply_requires_prior_check(env):
    _configure(env, channel="release")
    _install_agent(env)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))
    assert _status(exc) == 409
    assert not (env.dir / "request.json").exists()


def test_apply_rejects_target_mismatch_and_not_newer(env):
    _configure(env, channel="release")
    _install_agent(env)
    _seed_check("release", "v9.9.9")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.8"}, _FakeRequest()))
    assert _status(exc) == 409

    _seed_check("release", "v9.9.9", newer=False)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))
    assert _status(exc) == 409


@pytest.mark.parametrize("target", ["", "v1.2.3;rm", "../etc", "a" * 129, "v1 2"])
def test_apply_rejects_invalid_target(env, target):
    _configure(env, channel="release")
    _install_agent(env)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": target}, _FakeRequest()))
    assert _status(exc) == 400


def test_apply_requires_agent(env):
    _configure(env, channel="release")
    _seed_check("release", "v9.9.9")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))
    assert _status(exc) == 409
    assert "bootstrap" in exc.value.detail


def test_apply_refused_when_disabled(env):
    _configure(env, channel="disabled")
    _install_agent(env)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))
    assert _status(exc) == 409


@pytest.mark.parametrize(
    "existing",
    [
        ("request.json", "{}"),
        ("request.inprogress.json", "{}"),
        ("result.json", json.dumps({"status": "running"})),
    ],
)
def test_apply_refused_while_busy(env, existing):
    _configure(env, channel="release")
    _install_agent(env)
    _seed_check("release", "v9.9.9")
    name, body = existing
    (env.dir / name).write_text(body, encoding="utf-8")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))
    assert _status(exc) == 409
    assert env.audits == []


def test_apply_release_writes_request(env):
    _configure(env, channel="release", image_repo="ghcr.io/rickeynet/plexus")
    _install_agent(env)
    (env.dir / "result.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")
    _seed_check("release", "v9.9.9")

    req = asyncio.run(au.apply_update({"target": "v9.9.9"}, _FakeRequest()))

    on_disk = json.loads((env.dir / "request.json").read_text(encoding="utf-8"))
    assert on_disk == req
    assert req["action"] == "upgrade"
    assert req["mode"] == "image"
    assert req["image"] == "ghcr.io/rickeynet/plexus:v9.9.9"
    assert req["channel"] == "release"
    assert req["target_version"] == "v9.9.9"
    assert req["requested_by"] == "alice"
    assert req["id"] and req["requested_at"]
    # No temp files left behind for the PathExists watcher to trip on.
    assert sorted(p.name for p in env.dir.iterdir()) == [".agent-installed", "request.json", "result.json"]
    assert env.audits and env.audits[0][:2] == ("admin_updates", "apply.requested")


def test_apply_edge_and_git_plans(env):
    _configure(env, channel="edge")
    _install_agent(env)
    _seed_check("edge", "abcdef123456")
    req = asyncio.run(au.apply_update({"target": "abcdef123456"}, _FakeRequest()))
    assert req["mode"] == "image"
    assert req["image"] == "ghcr.io/rickeynet/plexus:edge"

    (env.dir / "request.json").unlink()
    _configure(env, channel="git", git_branch="main")
    _seed_check("git", "0123456789ab")
    req = asyncio.run(au.apply_update({"target": "0123456789ab"}, _FakeRequest()))
    assert req["mode"] == "git"
    assert req["ref"] == "main"
    assert "image" not in req


# ── rollback ─────────────────────────────────────────────────────────────


def test_rollback_requires_target(env):
    _configure(env, channel="release")
    _install_agent(env)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.rollback_update(_FakeRequest()))
    assert _status(exc) == 409

    (env.dir / "rollback.json").write_text(json.dumps({"available": False}), encoding="utf-8")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.rollback_update(_FakeRequest()))
    assert _status(exc) == 409


def test_rollback_requires_agent(env):
    _configure(env, channel="release")
    (env.dir / "rollback.json").write_text(json.dumps({"available": True}), encoding="utf-8")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.rollback_update(_FakeRequest()))
    assert _status(exc) == 409


def test_rollback_writes_request(env):
    _configure(env, channel="release")
    _install_agent(env)
    (env.dir / "rollback.json").write_text(
        json.dumps({"available": True, "mode": "image", "target": "ghcr.io/rickeynet/plexus:v1.0.0"}),
        encoding="utf-8",
    )
    req = asyncio.run(au.rollback_update(_FakeRequest()))
    on_disk = json.loads((env.dir / "request.json").read_text(encoding="utf-8"))
    assert on_disk["action"] == "rollback"
    assert on_disk["mode"] == "image"
    assert on_disk["target_version"] == "ghcr.io/rickeynet/plexus:v1.0.0"
    assert req["id"] == on_disk["id"]
    assert env.audits[-1][:2] == ("admin_updates", "rollback.requested")

    # A second click while the first is queued is refused.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(au.rollback_update(_FakeRequest()))
    assert _status(exc) == 409


# ── progress ─────────────────────────────────────────────────────────────


def test_progress_with_no_files(env):
    snap = asyncio.run(au.get_progress())
    assert snap["agent_installed"] is False
    assert snap["pending"] is None
    assert snap["in_progress"] is None
    assert snap["result"] is None
    assert snap["log_tail"] == ""
    assert snap["rollback_available"] is False
    assert set(snap["current"]) == {"version", "git_sha"}


def test_progress_missing_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("PLEXUS_UPDATES_DIR", str(tmp_path / "does-not-exist"))
    snap = asyncio.run(au.get_progress())
    assert snap["agent_installed"] is False
    assert snap["result"] is None


def test_progress_tolerates_corrupt_json(env):
    _install_agent(env)
    (env.dir / "request.json").write_text("{not json", encoding="utf-8")
    (env.dir / "result.json").write_text("[1, 2, 3]", encoding="utf-8")
    (env.dir / "rollback.json").write_bytes(b"\xff\xfe\x00garbage")
    snap = asyncio.run(au.get_progress())
    assert snap["agent_installed"] is True
    assert snap["pending"] is None
    assert snap["result"] is None
    assert snap["rollback_available"] is False


def test_progress_reports_state(env):
    _install_agent(env)
    (env.dir / "request.inprogress.json").write_text(json.dumps({"id": "x", "action": "upgrade"}), encoding="utf-8")
    (env.dir / "result.json").write_text(json.dumps({"id": "x", "status": "running"}), encoding="utf-8")
    (env.dir / "rollback.json").write_text(json.dumps({"available": True, "target": "abc"}), encoding="utf-8")
    snap = asyncio.run(au.get_progress())
    assert snap["in_progress"]["id"] == "x"
    assert snap["result"]["status"] == "running"
    assert snap["rollback_available"] is True


def test_progress_log_tail_is_capped(env):
    lines = [f"line {i:06d} " + "x" * 100 for i in range(5000)]
    (env.dir / "upgrade.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tail = asyncio.run(au.get_progress())["log_tail"]
    out = tail.splitlines()
    assert len(out) == au._LOG_TAIL_LINES
    assert out[-1] == lines[-1]
    assert len(tail.encode("utf-8")) <= au._LOG_TAIL_BYTES

    # Lines longer than the byte cap: the partial first line is dropped.
    (env.dir / "upgrade.log").write_text("a" * (au._LOG_TAIL_BYTES * 2) + "\nlast\n", encoding="utf-8")
    assert asyncio.run(au.get_progress())["log_tail"] == "last"


# ── edge channel ─────────────────────────────────────────────────────────


def _fake_github(monkeypatch, payload, status=200):
    async def _get(url, not_found):
        _get.url = url
        if status != 200:
            return None, {"ok": False, "error": not_found}
        return payload, None

    monkeypatch.setattr(au, "_github_get", _get)
    return _get


def test_edge_newer_when_sha_differs(monkeypatch):
    monkeypatch.setattr(au, "APP_GIT_SHA", "111111111111")
    fake = _fake_github(
        monkeypatch,
        {
            "sha": "abcdef1234567890abcdef1234567890abcdef12",
            "html_url": "https://github.com/RickeyNet/Plexus/commit/abcdef1",
            "commit": {"message": "feat: thing", "committer": {"date": "2026-10-01T00:00:00Z"}},
        },
    )
    cfg = dict(au._DEFAULT_CONFIG, channel="edge")
    res = asyncio.run(au._check_edge_channel(cfg))
    assert fake.url.endswith("/repos/RickeyNet/Plexus/commits/main")
    assert res["ok"] is True
    assert res["is_newer"] is True
    assert res["latest_version"] == "abcdef123456"
    assert res["release_notes"] == "feat: thing"


@pytest.mark.parametrize("local", ["abcdef123456", "ABCDEF1", "abcdef1234567890abcdef1234567890abcdef12"])
def test_edge_not_newer_when_sha_matches(monkeypatch, local):
    monkeypatch.setattr(au, "APP_GIT_SHA", local)
    _fake_github(monkeypatch, {"sha": "abcdef1234567890abcdef1234567890abcdef12", "commit": {}})
    res = asyncio.run(au._check_edge_channel(dict(au._DEFAULT_CONFIG, channel="edge")))
    assert res["is_newer"] is False


def test_edge_rejects_missing_sha(monkeypatch):
    _fake_github(monkeypatch, {"sha": "not-a-sha"})
    res = asyncio.run(au._check_edge_channel(dict(au._DEFAULT_CONFIG, channel="edge")))
    assert res["ok"] is False


def test_edge_propagates_github_error(monkeypatch):
    _fake_github(monkeypatch, None, status=404)
    res = asyncio.run(au._check_edge_channel(dict(au._DEFAULT_CONFIG, channel="edge")))
    assert res["ok"] is False
    assert "not found" in res["error"]


def test_check_route_caches_edge_result(env, monkeypatch):
    _configure(env, channel="edge")
    monkeypatch.setattr(au, "APP_GIT_SHA", "")
    _fake_github(monkeypatch, {"sha": "abcdef1234567890abcdef1234567890abcdef12", "commit": {}})
    res = asyncio.run(au.check_for_updates(_FakeRequest()))
    assert res["channel"] == "edge"
    assert au._last_check_cache["edge"]["latest_version"] == "abcdef123456"
