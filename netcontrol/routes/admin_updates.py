"""Admin self-update routes.

Exposes:

  GET  /api/admin/updates/status   - current version + channel config
  POST /api/admin/updates/check    - poll the configured channel for a newer
                                     release; returns availability + notes
  GET  /api/admin/updates/config   - channel + repo settings
  PUT  /api/admin/updates/config   - update channel + repo settings
  POST /api/admin/updates/apply    - queue an upgrade to the version the last
                                     successful check reported
  POST /api/admin/updates/rollback - queue a rollback to the previous version
  GET  /api/admin/updates/progress - host updater state (polled by the UI)

Channels:
  release   - GitHub Releases API (api.github.com/repos/<owner>/<repo>/releases/latest).
              Apply pulls the image ``<image_repo>:<tag>``.
  edge      - GitHub commits API for the tracked branch; compares its HEAD
              to the running build's git SHA. Apply pulls ``<image_repo>:edge``,
              which CI publishes on every green push to main.
  git       - git fetch on the configured remote/branch; reports how many
              commits HEAD is behind. Apply runs upgrade.sh in git mode
              (fetch + local image build on the host).
  disabled  - check is a no-op; status returns the local version only.
              Use this for air-gapped deploys that upgrade via manual
              `bash deploy/upgrade.sh --image ...`.

Apply never shells out from the app. The app (unprivileged, no Docker
socket) only writes a JSON request into the handoff directory
(PLEXUS_UPDATES_DIR, bind-mounted from <install>/state/updates on the
host). A systemd path unit on the host (deploy/systemd/plexus-updater.*)
picks it up and runs deploy/plexus-updater.sh, which validates the request
and runs deploy/upgrade.sh (DB snapshot, health gate, rollback record).
Files in the handoff directory:

  request.json             - written by the app, consumed by the updater
  request.inprogress.json  - the request while the updater runs it
  result.json              - last run's status (running/success/failed)
  upgrade.log              - upgrade.sh output of the last run
  rollback.json            - rollback target mirrored from state/.upgrade-previous
  .agent-installed         - created by deploy/bootstrap.sh with the units
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import uuid
from datetime import UTC, datetime
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


# ── Config ────────────────────────────────────────────────────────────────

# Stored as a JSON blob in auth_settings under key "updates".
_SETTING_KEY = "updates"

_DEFAULT_CONFIG: dict[str, Any] = {
    "channel": "release",  # release | edge | git | disabled
    "repo": "RickeyNet/Plexus",  # owner/name for release + edge channels
    "git_remote": "origin",  # remote name for git channel
    "git_branch": "main",  # branch tracked by edge + git channels
    "image_repo": "ghcr.io/rickeynet/plexus",  # registry image for release + edge
}

_VALID_CHANNELS = {"release", "edge", "git", "disabled"}
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_IMAGE_REPO_RE = re.compile(r"^[a-z0-9.-]+(/[a-z0-9._-]+)+$")
# A tag / short SHA accepted by /apply. deploy/plexus-updater.sh re-validates
# the resulting image ref against the same character set on the host.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")

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

    # Registry refs are lowercase; normalize a pasted "ghcr.io/Owner/Name".
    image_repo = str(body.get("image_repo", out["image_repo"])).strip().lower()
    if len(image_repo) > 255 or not _IMAGE_REPO_RE.match(image_repo):
        raise HTTPException(
            status_code=400,
            detail="image_repo must look like 'registry/owner/name' (lowercase, no tag)",
        )
    out["image_repo"] = image_repo

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


def _sha_matches(remote_sha: str, local_sha: str) -> bool:
    """True when two git SHAs name the same commit (either may be abbreviated)."""
    r = remote_sha.strip().lower()
    loc = local_sha.strip().lower()
    if not r or not loc:
        return False
    return r.startswith(loc) or loc.startswith(r)


# ── Channel implementations ───────────────────────────────────────────────


async def _github_get(url: str, not_found: str) -> tuple[Any, dict[str, Any] | None]:
    """GET a GitHub API URL. Returns (json, None) or (None, error result)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "plexus-update-check",
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return None, {"ok": False, "error": "timeout contacting api.github.com"}
    except httpx.HTTPError as exc:
        return None, {"ok": False, "error": f"network error: {exc}"}

    if resp.status_code in (404, 422):
        return None, {"ok": False, "error": not_found}
    if resp.status_code == 403:
        # GH rate-limits unauthenticated callers to 60/hr per IP.
        return None, {"ok": False, "error": "github API rate-limited; try again later"}
    if resp.status_code != 200:
        return None, {"ok": False, "error": f"github API returned {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return None, {"ok": False, "error": "github API returned invalid JSON"}
    if not isinstance(data, dict):
        return None, {"ok": False, "error": "unexpected github API response"}
    return data, None


async def _check_release_channel(cfg: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{cfg['repo']}/releases/latest"
    data, err = await _github_get(url, f"repo {cfg['repo']!r} has no releases or is private")
    if err is not None:
        return err

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


async def _check_edge_channel(cfg: dict[str, Any]) -> dict[str, Any]:
    branch = cfg["git_branch"]
    url = f"https://api.github.com/repos/{cfg['repo']}/commits/{branch}"
    data, err = await _github_get(url, f"branch {branch!r} not found in {cfg['repo']!r}")
    if err is not None:
        return err

    sha = str(data.get("sha") or "").strip().lower()
    if not _SHA_RE.match(sha):
        return {"ok": False, "error": "commit response has no valid sha"}
    commit = data.get("commit")
    commit = commit if isinstance(commit, dict) else {}
    committer = commit.get("committer")
    committer = committer if isinstance(committer, dict) else {}
    short = sha[:12]
    # An unknown local SHA (dev checkout without git) cannot be compared;
    # report newer so the operator can still move onto a known edge build.
    newer = not _sha_matches(sha, APP_GIT_SHA)
    return {
        "ok": True,
        "latest_version": short,
        "latest_name": f"{branch} ({short})",
        "release_notes": str(commit.get("message") or ""),
        "published_at": committer.get("date"),
        "html_url": data.get("html_url"),
        "is_newer": newer,
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
        rc, log, _ = _run_git(["log", "--oneline", f"HEAD..{ref}", "-n", "20"], repo_root)
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
        detail=f"channel={new_cfg['channel']} repo={new_cfg['repo']} image_repo={new_cfg['image_repo']}",
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
    elif channel == "edge":
        result = await _check_edge_channel(cfg)
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


# ── Apply / rollback / progress ───────────────────────────────────────────

_REQUEST_FILE = "request.json"
_INPROGRESS_FILE = "request.inprogress.json"
_RESULT_FILE = "result.json"
_LOG_FILE = "upgrade.log"
_ROLLBACK_FILE = "rollback.json"
_AGENT_MARKER = ".agent-installed"

_LOG_TAIL_LINES = 200
_LOG_TAIL_BYTES = 64 * 1024

# Serializes the busy check + write so two concurrent clicks cannot both
# queue a request (the host updater handles one at a time).
_apply_lock = asyncio.Lock()


def _updates_dir() -> Path:
    return Path(os.environ.get("PLEXUS_UPDATES_DIR", "/app/state/updates"))


def _read_json(path: Path) -> dict[str, Any] | None:
    """Read a JSON object; None when missing, unreadable, or not an object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return None
    return data if isinstance(data, dict) else None


def _read_log_tail(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            start = max(0, size - _LOG_TAIL_BYTES)
            fh.seek(start)
            raw = fh.read(_LOG_TAIL_BYTES)
    except OSError:
        return ""
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        # The byte cap cut into the first line; drop the partial line.
        lines = lines[1:]
    return "\n".join(lines[-_LOG_TAIL_LINES:])


def _empty_progress() -> dict[str, Any]:
    return {
        "agent_installed": False,
        "pending": None,
        "in_progress": None,
        "result": None,
        "log_tail": "",
        "rollback_available": False,
        "rollback": None,
    }


def _read_progress(d: Path) -> dict[str, Any]:
    rollback = _read_json(d / _ROLLBACK_FILE)
    return {
        "agent_installed": (d / _AGENT_MARKER).is_file(),
        "pending": _read_json(d / _REQUEST_FILE),
        "in_progress": _read_json(d / _INPROGRESS_FILE),
        "result": _read_json(d / _RESULT_FILE),
        "log_tail": _read_log_tail(d / _LOG_FILE),
        "rollback_available": bool(rollback and rollback.get("available") is True),
        "rollback": rollback,
    }


def _busy_reason(d: Path) -> str | None:
    if (d / _REQUEST_FILE).exists():
        return "An update request is already queued"
    if (d / _INPROGRESS_FILE).exists():
        return "An update is already in progress"
    result = _read_json(d / _RESULT_FILE)
    if result and result.get("status") == "running":
        return "An update is already in progress"
    return None


def _write_request(d: Path, req: dict[str, Any]) -> None:
    # Write-then-rename so the host's PathExists watcher never sees a
    # half-written request.json.
    tmp = d / f".{_REQUEST_FILE}.{req['id']}.tmp"
    tmp.write_text(json.dumps(req, indent=2), encoding="utf-8")
    os.replace(tmp, d / _REQUEST_FILE)


def _plan_for(cfg: dict[str, Any], channel: str, target: str) -> dict[str, Any]:
    """Map a channel + checked version to an upgrade.sh mode."""
    if channel == "release":
        return {"mode": "image", "image": f"{cfg['image_repo']}:{target}"}
    if channel == "edge":
        return {"mode": "image", "image": f"{cfg['image_repo']}:edge"}
    if channel == "git":
        return {"mode": "git", "ref": cfg["git_branch"]}
    raise HTTPException(status_code=409, detail=f"channel {channel!r} cannot apply updates")


async def _preflight(cfg: dict[str, Any]) -> Path:
    """Guards shared by apply + rollback. Returns the handoff directory."""
    if cfg["channel"] == "disabled":
        raise HTTPException(
            status_code=409,
            detail="Updates are disabled for this instance; choose a channel first",
        )
    d = _updates_dir()
    installed = await asyncio.to_thread((d / _AGENT_MARKER).is_file)
    if not installed:
        raise HTTPException(
            status_code=409,
            detail="Host updater not installed - run deploy/bootstrap.sh on the server",
        )
    return d


async def _queue_request(d: Path, req: dict[str, Any], request: Request, action: str, detail: str) -> dict[str, Any]:
    async with _apply_lock:
        reason = await asyncio.to_thread(_busy_reason, d)
        if reason:
            raise HTTPException(status_code=409, detail=reason)
        try:
            await asyncio.to_thread(_write_request, d, req)
        except OSError as exc:
            LOGGER.error("admin_updates: cannot write update request: %s", type(exc).__name__)
            raise HTTPException(status_code=500, detail="Could not write the update request") from None
    await _audit(
        "admin_updates",
        action,
        user=req["requested_by"],
        detail=detail,
        correlation_id=_corr_id(request),
    )
    return req


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _session_user(request: Request) -> str:
    session = _get_session(request)
    return str(session.get("user", "")) if session else ""


@router.post("/api/admin/updates/apply", status_code=202)
async def apply_update(body: dict[str, Any], request: Request) -> dict[str, Any]:
    target = str(body.get("target", "")).strip()
    if not _TARGET_RE.match(target):
        raise HTTPException(status_code=400, detail="target must be a tag or commit SHA")

    cfg = await _load_config()
    d = await _preflight(cfg)
    channel = cfg["channel"]

    # Only the version the last check reported can be installed, so a
    # crafted request cannot point the host at an arbitrary ref.
    last = _last_check_cache.get(channel)
    if not last or not last.get("ok"):
        raise HTTPException(status_code=409, detail="Run a successful update check first")
    if not last.get("is_newer"):
        raise HTTPException(status_code=409, detail="The last check found no newer version")
    if str(last.get("latest_version", "")) != target:
        raise HTTPException(
            status_code=409,
            detail="target does not match the version from the last check; check again",
        )

    req: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "action": "upgrade",
        **_plan_for(cfg, channel, target),
        "channel": channel,
        "target_version": target,
        "requested_by": _session_user(request),
        "requested_at": _now_iso(),
    }
    where = req.get("image") or f"ref={req.get('ref')}"
    return await _queue_request(d, req, request, "apply.requested", f"channel={channel} target={target} {where}")


@router.post("/api/admin/updates/rollback", status_code=202)
async def rollback_update(request: Request) -> dict[str, Any]:
    cfg = await _load_config()
    d = await _preflight(cfg)
    rollback = await asyncio.to_thread(_read_json, d / _ROLLBACK_FILE)
    if not rollback or rollback.get("available") is not True:
        raise HTTPException(status_code=409, detail="No rollback target recorded on the host")

    mode = rollback.get("mode")
    req: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "action": "rollback",
        "mode": mode if mode in ("image", "git") else "",
        "channel": cfg["channel"],
        "target_version": str(rollback.get("target") or ""),
        "requested_by": _session_user(request),
        "requested_at": _now_iso(),
    }
    return await _queue_request(d, req, request, "rollback.requested", f"target={req['target_version']}")


@router.get("/api/admin/updates/progress")
async def get_progress() -> dict[str, Any]:
    try:
        snap = await asyncio.to_thread(_read_progress, _updates_dir())
    except OSError:
        snap = _empty_progress()
    snap["current"] = _local_version_payload()
    return snap
