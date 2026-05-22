"""Admin self-update routes.

Layer 3, v1 (read-only). Exposes:

  GET  /api/admin/updates/status   - current version + channel config
  POST /api/admin/updates/check    - poll the configured channel for a newer
                                     release; returns availability + notes
  GET  /api/admin/updates/config   - channel + repo settings
  PUT  /api/admin/updates/config   - update channel + repo settings

Channels:
  release   - GitHub Releases API (api.github.com/repos/<owner>/<repo>/releases/latest)
  git       - git ls-remote on the configured remote; reports HEAD of the
              tracked branch and how many commits ahead it is. Useful for
              edge deploys following main.
  disabled  - check is a no-op; status returns the local version only.
              Use this for air-gapped deploys that upgrade via manual
              `bash deploy/upgrade.sh --image ...`.

Apply + rollback are NOT in this PR. The watcher/sentinel design from the
Layer 3 doc lands separately once the read-side is proven.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Any

import httpx
import routes.database as db
from fastapi import APIRouter, HTTPException, Request

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging
from netcontrol.version import APP_GIT_SHA, APP_VERSION

router = APIRouter()
LOGGER = configure_logging("plexus.admin_updates")

# ── Late-binding auth deps (not used directly; admin gate is applied at
#    router-include time, matching the monitoring/admin pattern). ───────────

_require_admin = None


def init_admin_updates(require_admin):
    global _require_admin
    _require_admin = require_admin


# ── Config ────────────────────────────────────────────────────────────────

# Stored as a JSON blob in auth_settings under key "updates".
_SETTING_KEY = "updates"

_DEFAULT_CONFIG: dict[str, Any] = {
    "channel": "release",  # release | git | disabled
    "repo": "RickeyNet/Plexus",  # owner/name for release channel
    "git_remote": "origin",  # remote name for git channel
    "git_branch": "main",  # branch tracked by git channel
}

_VALID_CHANNELS = {"release", "git", "disabled"}
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

# How long to cache the last check result. Channel API calls are cheap but
# the GH API has a 60/hr unauth rate limit, so we don't want the UI to
# hammer it on every page mount.
_CHECK_TTL_SECONDS = 60

_HTTP_TIMEOUT = 10.0


async def _load_config() -> dict[str, Any]:
    stored = await db.get_auth_setting(_SETTING_KEY)
    if not stored:
        return dict(_DEFAULT_CONFIG)
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(stored)
    return cfg


def _sanitize_config(body: dict[str, Any]) -> dict[str, Any]:
    out = dict(_DEFAULT_CONFIG)
    channel = str(body.get("channel", out["channel"])).strip().lower()
    if channel not in _VALID_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail=f"channel must be one of {sorted(_VALID_CHANNELS)}",
        )
    out["channel"] = channel

    repo = str(body.get("repo", out["repo"])).strip()
    if not _REPO_RE.match(repo):
        raise HTTPException(
            status_code=400,
            detail="repo must be 'owner/name' with alphanumerics, dots, dashes, underscores",
        )
    out["repo"] = repo

    remote = str(body.get("git_remote", out["git_remote"])).strip()
    if not _REF_RE.match(remote):
        raise HTTPException(status_code=400, detail="git_remote contains invalid characters")
    out["git_remote"] = remote

    branch = str(body.get("git_branch", out["git_branch"])).strip()
    if not _REF_RE.match(branch):
        raise HTTPException(status_code=400, detail="git_branch contains invalid characters")
    out["git_branch"] = branch

    return out


# ── Version helpers ───────────────────────────────────────────────────────


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    """Parse '1.2.3' or 'v1.2.3' into a tuple; return None if not semver.

    Pre-release suffixes ('1.2.3-rc1') are accepted but the suffix is dropped
    for comparison purposes. This is intentionally lenient: we only need a
    consistent ordering for "is there a newer version?", not full SemVer 2.0
    precedence rules.
    """
    s = v.strip()
    if s.startswith("v") or s.startswith("V"):
        s = s[1:]
    s = s.split("-", 1)[0].split("+", 1)[0]
    parts = s.split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _is_newer(remote: str, local: str) -> bool:
    rt = _parse_semver(remote)
    lt = _parse_semver(local)
    if rt is None or lt is None:
        # Fall back to string inequality; better than reporting "no update"
        # when versions don't parse but clearly differ.
        return remote.strip().lstrip("vV") != local.strip().lstrip("vV")
    return rt > lt


# ── Channel implementations ───────────────────────────────────────────────


async def _check_release_channel(cfg: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{cfg['repo']}/releases/latest"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "plexus-update-check",
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return {"ok": False, "error": "timeout contacting api.github.com"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"network error: {exc}"}

    if resp.status_code == 404:
        return {"ok": False, "error": f"repo {cfg['repo']!r} has no releases or is private"}
    if resp.status_code == 403:
        # GH rate-limits unauthenticated callers to 60/hr per IP.
        return {"ok": False, "error": "github API rate-limited; try again later"}
    if resp.status_code != 200:
        return {"ok": False, "error": f"github API returned {resp.status_code}"}

    data = resp.json()
    tag = str(data.get("tag_name", "")).strip()
    if not tag:
        return {"ok": False, "error": "release has no tag_name"}

    return {
        "ok": True,
        "latest_version": tag,
        "latest_name": data.get("name") or tag,
        "release_notes": data.get("body") or "",
        "published_at": data.get("published_at"),
        "html_url": data.get("html_url"),
        "is_newer": _is_newer(tag, APP_VERSION),
    }


def _run_git(args: list[str], cwd: Path, timeout: float = 10.0) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


async def _check_git_channel(cfg: dict[str, Any]) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent.parent
    if not (repo_root / ".git").exists():
        return {
            "ok": False,
            "error": "not a git checkout; switch to 'release' channel or install via image",
        }

    remote = cfg["git_remote"]
    branch = cfg["git_branch"]
    ref = f"{remote}/{branch}"

    def _do() -> dict[str, Any]:
        rc, _, err = _run_git(["fetch", "--quiet", remote, branch], repo_root, timeout=15.0)
        if rc != 0:
            return {"ok": False, "error": f"git fetch failed: {err or 'unknown error'}"}
        rc, head, err = _run_git(["rev-parse", "--short=12", "HEAD"], repo_root)
        if rc != 0:
            return {"ok": False, "error": f"git rev-parse HEAD failed: {err}"}
        rc, remote_sha, err = _run_git(["rev-parse", "--short=12", ref], repo_root)
        if rc != 0:
            return {"ok": False, "error": f"git rev-parse {ref} failed: {err}"}
        rc, count, err = _run_git(["rev-list", "--count", f"HEAD..{ref}"], repo_root)
        if rc != 0:
            return {"ok": False, "error": f"git rev-list failed: {err}"}
        rc, log, _ = _run_git(
            ["log", "--oneline", f"HEAD..{ref}", "-n", "20"], repo_root
        )
        try:
            ahead = int(count)
        except ValueError:
            ahead = 0
        return {
            "ok": True,
            "latest_version": remote_sha,
            "latest_name": f"{ref} ({remote_sha})",
            "release_notes": log if ahead > 0 else "Already at the latest commit.",
            "is_newer": ahead > 0,
            "commits_behind": ahead,
            "local_sha": head,
        }

    return await asyncio.to_thread(_do)


# ── Status + history ──────────────────────────────────────────────────────


# In-memory cache of the last check, per channel. Cleared on config change.
# We don't persist this; a process restart drops it, which is fine - it just
# means the first /status after restart is a freshly-rendered local snapshot.
_last_check_cache: dict[str, dict[str, Any]] = {}


def _local_version_payload() -> dict[str, Any]:
    return {
        "version": APP_VERSION,
        "git_sha": APP_GIT_SHA or None,
    }


@router.get("/api/admin/updates/status")
async def get_status() -> dict[str, Any]:
    cfg = await _load_config()
    return {
        "current": _local_version_payload(),
        "channel": cfg["channel"],
        "repo": cfg["repo"],
        "last_check": _last_check_cache.get(cfg["channel"]),
    }


@router.get("/api/admin/updates/config")
async def get_config() -> dict[str, Any]:
    return await _load_config()


@router.put("/api/admin/updates/config")
async def update_config(body: dict[str, Any], request: Request) -> dict[str, Any]:
    new_cfg = _sanitize_config(body)
    await db.set_auth_setting(_SETTING_KEY, new_cfg)
    # Different channel/repo means previous check result is meaningless.
    _last_check_cache.clear()
    session = _get_session(request)
    await _audit(
        "admin_updates",
        "config.updated",
        user=session["user"] if session else "",
        detail=f"channel={new_cfg['channel']} repo={new_cfg['repo']}",
        correlation_id=_corr_id(request),
    )
    return new_cfg


@router.post("/api/admin/updates/check")
async def check_for_updates(request: Request) -> dict[str, Any]:
    cfg = await _load_config()
    channel = cfg["channel"]

    if channel == "disabled":
        result: dict[str, Any] = {
            "ok": True,
            "is_newer": False,
            "latest_version": APP_VERSION,
            "release_notes": "Update check disabled for this instance.",
        }
    elif channel == "release":
        result = await _check_release_channel(cfg)
    elif channel == "git":
        result = await _check_git_channel(cfg)
    else:
        # _sanitize_config blocks anything else from being stored, but guard
        # against a stale row from an earlier schema.
        raise HTTPException(status_code=500, detail=f"unknown channel {channel!r}")

    result["channel"] = channel
    result["current"] = _local_version_payload()
    _last_check_cache[channel] = result

    session = _get_session(request)
    await _audit(
        "admin_updates",
        "check",
        user=session["user"] if session else "",
        detail=(
            f"channel={channel} ok={result.get('ok')} "
            f"newer={result.get('is_newer')} latest={result.get('latest_version', '')}"
        ),
        correlation_id=_corr_id(request),
    )
    return result
