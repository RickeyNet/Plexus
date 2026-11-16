"""Git data sources: CRUD, "Sync now", the periodic sync loop and the guard
that keeps records a source owns read-only.

``router`` is registered in ``app.py`` behind ``require_admin``. A sync
clones or fetches the source's branch into ``<state dir>/git_sources/<id>``
(``PLEXUS_GIT_SOURCES_DIR`` overrides the folder), records the HEAD SHA and
imports ``templates/``, ``playbooks/`` and ``config_contexts/`` into the
existing stores, owned by the source: created or updated when a file is
added or changed, removed when it leaves the repository (or the source no
longer provides its type, or the source is deleted). Rules for remotes, git
and files live in ``netcontrol.git_sources``, storage in
``routes.db.git_sources``. See ``docs/git-data-sources.md``.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from routes.crypto import decrypt

from netcontrol import git_sources as gs
from netcontrol.routes.net_guard import OutboundRequestError, validate_outbound_host
from netcontrol.routes.shared import _audit, _corr_id, _session_user, resolve_state_root
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.git_sources")

router = APIRouter()

PREFIX = "/api/git-sources"
# Background sync: first check after start, then how often due sources are
# looked for (each source has its own interval).
FIRST_RUN_DELAY_SECONDS = 120
CHECK_INTERVAL_SECONDS = 60
_RAW_MAX = 4096
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# One sync at a time per source, within this process.
_locks: dict[int, asyncio.Lock] = {}


class SourceBody(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    remote_url: str = Field(max_length=_RAW_MAX)
    branch: str = Field(default="main", max_length=_RAW_MAX)
    credential_id: int | None = Field(default=None, ge=1, le=2_147_483_647)
    provides: list[str] = Field(default_factory=lambda: list(gs.CONTENT_TYPES), max_length=10)
    sync_interval_minutes: int = Field(default=0, ge=0, le=10_000_000)
    enabled: bool = True


# ── Helpers ──────────────────────────────────────────────────────────────────


def sources_root() -> str:
    """The folder each source's working copy lives under."""
    override = os.getenv("PLEXUS_GIT_SOURCES_DIR", "").strip()
    if override:
        return override
    return os.path.join(resolve_state_root() or os.path.join(_REPO_ROOT, "state"), "git_sources")


def _workdir(source_id: int) -> str:
    return os.path.join(sources_root(), str(int(source_id)))


def _bad(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _found(record: dict | None) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail="Git source not found")
    return record


async def _audit_write(request: Request | None, action: str, detail: str, user: str = "") -> None:
    await _audit(
        "config",
        action,
        user=_session_user(request) if request is not None else user,
        detail=detail,
        correlation_id=_corr_id(request) if request is not None else "",
    )


def reject_git_owned(record: dict | None, what: str) -> None:
    """409 when ``record`` is owned by a Git source: it is changed in the
    repository, not in Plexus."""
    if record and record.get("git_source_id") is not None:
        source = record.get("git_source_name") or f"#{record['git_source_id']}"
        raise HTTPException(
            status_code=409,
            detail=f"This {what} is managed by the Git source '{source}' ({record.get('git_path') or 'repository'}); "
            "change it in the repository and sync.",
        )


async def _check_credential(credential_id: int | None) -> None:
    if credential_id is None:
        return
    cred = await db.get_credential_raw(credential_id)
    if not cred or not cred.get("is_service"):
        raise HTTPException(status_code=400, detail=f"Unknown service credential id {credential_id}.")


async def _values(body: SourceBody) -> dict:
    try:
        remote = gs.parse_remote(body.remote_url)
        values = {
            "name": gs.clean_source_name(body.name),
            "remote_url": remote.url,
            "branch": gs.clean_branch(body.branch),
            "credential_id": body.credential_id,
            "provides": gs.clean_provides(body.provides),
            "sync_interval_minutes": gs.clean_interval(body.sync_interval_minutes),
            "enabled": body.enabled,
        }
    except gs.GitSourceError as exc:
        raise _bad(exc) from exc
    await _check_credential(body.credential_id)
    return values


def _remote_for(source: dict) -> gs.Remote:
    """The validated remote of a stored source (checked again at every
    sync: the rules may have tightened since it was saved)."""
    return gs.parse_remote(source["remote_url"])


async def _auth_for(source: dict, remote: gs.Remote) -> gs.GitAuth | None:
    if source["credential_id"] is None:
        return None
    cred = await db.get_credential_raw(source["credential_id"])
    if not cred:
        raise gs.GitSourceError("The source's credential no longer exists.")
    try:
        secret = decrypt(cred["password"])
    except RuntimeError as exc:
        raise gs.GitSourceError(str(exc)) from exc
    if remote.kind == "ssh":
        return gs.GitAuth(username=cred["username"], private_key=secret)
    return gs.GitAuth(username=cred["username"], password=secret)


# ── Import ───────────────────────────────────────────────────────────────────


class _Lookups:
    """Group and host names a context's ``_metadata`` may use, and the scope
    ids it may name, checked once per sync."""

    def __init__(self) -> None:
        self._groups: dict[str, list[int]] | None = None

    async def group_id(self, name: str) -> int:
        if self._groups is None:
            self._groups = {}
            for g in await db.get_all_groups():
                self._groups.setdefault(str(g["name"]).lower(), []).append(int(g["id"]))
        ids = self._groups.get(name.lower(), [])
        if len(ids) != 1:
            raise ValueError(f"group '{name}' {'is ambiguous' if ids else 'does not exist'}")
        return ids[0]

    @staticmethod
    async def host_id(name: str) -> int:
        hosts = await db.find_hosts_by_hostname(name)
        if len(hosts) != 1:
            raise ValueError(f"host '{name}' {'is ambiguous' if hosts else 'does not exist'}")
        return int(hosts[0]["id"])


async def _context_values(item: gs.Item, lookups: _Lookups, source: dict) -> dict:
    """The stored values of a context item: group and host names resolved,
    scope ids checked. ``ValueError`` names what is wrong."""
    values = dict(item.values)
    if "group" in values:
        name = values.pop("group")
        if values.get("group_id") is None:
            values["group_id"] = await lookups.group_id(name)
    if "host" in values:
        name = values.pop("host")
        if values.get("host_id") is None:
            values["host_id"] = await lookups.host_id(name)
    if values.get("group_id") is not None and await db.get_group(values["group_id"]) is None:
        raise ValueError(f"group id {values['group_id']} does not exist")
    if values.get("host_id") is not None and await db.get_host(values["host_id"]) is None:
        raise ValueError(f"host id {values['host_id']} does not exist")
    refs = {k: values[k] for k in ("role_id", "site_id") if values.get(k) is not None}
    if refs:
        errors = await db.check_device_refs(refs)
        if errors:
            raise ValueError("unknown " + ", ".join(sorted(errors)))
    values["updated_by"] = f"git:{source['name']}"
    return values


async def _import(source: dict, commit: str, collected: gs.Collected) -> dict:
    """Write the collected records owned by the source and remove the ones
    it no longer provides. Returns the counts and warnings."""
    counts = {k: {"created": 0, "updated": 0, "unchanged": 0, "removed": 0, "detached": 0} for k in gs.CONTENT_TYPES}
    warnings = list(collected.warnings)
    lookups = _Lookups()
    for kind in gs.CONTENT_TYPES:
        kept: set[int] = set()
        for item in collected.items.get(kind, []):
            try:
                values = await _context_values(item, lookups, source) if kind == "config_contexts" else item.values
                outcome, record_id = await db.upsert_git_owned(kind, source["id"], values, item.path, commit)
            except db.GitOwnedConflict as exc:
                warnings.append({"path": item.path, "message": f"Skipped: {exc}"})
                continue
            except ValueError as exc:
                warnings.append({"path": item.path, "message": f"Skipped: {exc}."})
                continue
            kept.add(record_id)
            counts[kind][outcome] += 1
        owned = (await db.list_git_owned(source["id"], kind))[kind]
        for row in owned:
            if int(row["id"]) in kept:
                continue
            outcome = await db.delete_git_owned(kind, int(row["id"]))
            counts[kind]["removed" if outcome == "deleted" else "detached"] += 1
    return {"commit": commit, "counts": counts, "warnings": warnings}


async def _remove_owned(source_id: int) -> dict[str, int]:
    removed = {"removed": 0, "detached": 0}
    for kind, rows in (await db.list_git_owned(source_id)).items():
        for row in rows:
            outcome = await db.delete_git_owned(kind, int(row["id"]))
            removed["removed" if outcome == "deleted" else "detached"] += 1
    return removed


def _contexts_changed(summary: dict) -> bool:
    counts = summary.get("counts", {}).get("config_contexts", {})
    return any(counts.get(k) for k in ("created", "updated", "removed", "detached"))


async def sync_git_source(source_id: int, user: str = "") -> dict:
    """Sync one source now: fetch and check out its branch, import its files
    and record the outcome. Returns ``{ok, source, result}``; ``result`` is
    the import summary, or ``None`` when the sync failed (the error is on the
    source, and the records it owned are left as they were).
    ``LookupError`` when the source does not exist; ``RuntimeError`` when a
    sync of it is already running."""
    lock = _locks.setdefault(int(source_id), asyncio.Lock())
    if lock.locked():
        raise RuntimeError("A sync of this source is already running.")
    async with lock:
        source = await db.get_git_source(source_id)
        if source is None:
            raise LookupError("Git source not found")
        await db.claim_git_source_attempt(source_id)
        summary: dict | None = None
        try:
            remote = _remote_for(source)
            try:
                await asyncio.to_thread(validate_outbound_host, remote.host)
            except OutboundRequestError as exc:
                raise gs.GitSourceError(f"Remote host refused: {exc}.") from exc
            auth = await _auth_for(source, remote)
            known_hosts = os.path.join(sources_root(), "known_hosts")
            commit = await asyncio.to_thread(
                gs.fetch_checkout, _workdir(source_id), remote, source["branch"], auth, known_hosts
            )
            workdir = _workdir(source_id)
            collected = await asyncio.to_thread(gs.collect_items, workdir, source["provides"])
            if "playbooks" in source["provides"]:
                for path in await asyncio.to_thread(gs.ignored_python_playbooks, workdir):
                    collected.warn(path, "Skipped: Python playbooks are not imported from Git.")
            summary = await _import(source, commit, collected)
            status = "warning" if summary["warnings"] else "ok"
            await db.set_git_source_result(source_id, status=status, commit=commit, summary=summary)
        except gs.GitSourceError as exc:
            await db.set_git_source_result(source_id, status="error", error=str(exc))
            LOGGER.warning("git source %s sync failed: %s", source_id, exc)
        except Exception as exc:
            await db.set_git_source_result(source_id, status="error", error=f"Sync failed ({type(exc).__name__}).")
            LOGGER.exception("git source %s sync failed", source_id)
    detail = f"id={source_id} name={source['name']}"
    if summary is not None:
        detail += f" commit={summary['commit'][:12]} warnings={len(summary['warnings'])}"
        if _contexts_changed(summary):
            from netcontrol.routes.intended_config import wake_generation

            wake_generation()
    else:
        detail += " failed"
    await _audit_write(None, "git_source_sync", detail, user=user or "system")
    record = await db.get_git_source(source_id)
    return {"ok": summary is not None, "source": record, "result": summary}


def _due(source: dict, now: datetime) -> bool:
    interval = int(source["sync_interval_minutes"])
    if not source["enabled"] or interval <= 0:
        return False
    last = source["last_attempt_at"]
    if not last:
        return True
    try:
        at = datetime.strptime(last, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return True
    return now - at >= timedelta(minutes=interval)


async def sync_due_sources(now: datetime | None = None) -> list[int]:
    """Sync every enabled source whose interval has passed since its last
    attempt; the ids synced."""
    now = now or datetime.now(UTC)
    synced: list[int] = []
    for source in await db.list_git_sources():
        if not _due(source, now) or _locks.get(source["id"], asyncio.Lock()).locked():
            continue
        try:
            await sync_git_source(source["id"], "system")
            synced.append(source["id"])
        except LookupError, RuntimeError:
            continue
    return synced


async def git_sources_loop() -> None:
    """Sync due sources ``FIRST_RUN_DELAY_SECONDS`` after start, then check
    every ``CHECK_INTERVAL_SECONDS``."""
    await asyncio.sleep(FIRST_RUN_DELAY_SECONDS)
    while True:
        try:
            await sync_due_sources()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("git source sync loop failed: %s", type(exc).__name__)
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get(PREFIX)
async def list_sources() -> dict:
    return {"sources": await db.list_git_sources(), "content_types": list(gs.CONTENT_TYPES)}


@router.get(f"{PREFIX}/{{source_id}}")
async def get_source(source_id: int) -> dict:
    return _found(await db.get_git_source(source_id))


@router.get(f"{PREFIX}/{{source_id}}/objects")
async def get_source_objects(source_id: int) -> dict:
    _found(await db.get_git_source(source_id))
    return {"objects": await db.list_git_owned(source_id)}


@router.post(PREFIX, status_code=201)
async def create_source(body: SourceBody, request: Request) -> dict:
    values = await _values(body)
    try:
        record = await db.create_git_source(values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(
        request, "git_source_create", f"id={record['id']} name={record['name']} url={record['remote_url']}"
    )
    return record


@router.put(f"{PREFIX}/{{source_id}}")
async def update_source(source_id: int, body: SourceBody, request: Request) -> dict:
    old = _found(await db.get_git_source(source_id))
    values = await _values(body)
    try:
        record = _found(await db.update_git_source(source_id, values, _session_user(request)))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if old["remote_url"] != record["remote_url"]:
        # A new repository starts from a fresh working copy.
        await asyncio.to_thread(gs.remove_workdir, _workdir(source_id))
    await _audit_write(request, "git_source_update", f"id={source_id} name={record['name']} url={record['remote_url']}")
    return record


@router.delete(f"{PREFIX}/{{source_id}}")
async def delete_source(source_id: int, request: Request) -> dict:
    record = _found(await db.get_git_source(source_id))
    lock = _locks.setdefault(int(source_id), asyncio.Lock())
    if lock.locked():
        raise HTTPException(status_code=409, detail="A sync of this source is running; delete it when it ends.")
    async with lock:
        removed = await _remove_owned(source_id)
        await db.delete_git_source(source_id)
        await asyncio.to_thread(gs.remove_workdir, _workdir(source_id))
    _locks.pop(int(source_id), None)
    if removed["removed"] or removed["detached"]:
        from netcontrol.routes.intended_config import wake_generation

        wake_generation()
    await _audit_write(
        request,
        "git_source_delete",
        f"id={source_id} name={record['name']} removed={removed['removed']} detached={removed['detached']}",
    )
    return {"ok": True, **removed}


@router.post(f"{PREFIX}/{{source_id}}/sync")
async def sync_source(source_id: int, request: Request) -> dict:
    try:
        return await sync_git_source(source_id, _session_user(request))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
