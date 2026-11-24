"""
playbooks.py -- Playbook CRUD routes and file management.

Object scope: playbooks are a shared catalogue (no host or group): accounts
limited to selected inventory groups read them and run them through jobs
(which check the targets); only unrestricted callers change them.

Two routers:

- ``router`` (the ``playbooks`` feature; changes need ``playbooks.write``):
  read the catalogue, edit a playbook's name, description, tags and inputs.
  Changing its code (``content``, ``type`` or ``filename``) is refused
  unless the caller is an admin.
- ``admin_router`` (admin): create and delete playbooks. A Python playbook
  is imported into the Plexus server process and an Ansible playbook runs
  on the controller, so writing playbook code is an admin action.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from routes.secret_resolver import require_usable_secret_references

from netcontrol import job_inputs
from netcontrol.object_scope import require_model_write, scope_exempt, scoped
from netcontrol.routes.git_sources import reject_git_owned
from netcontrol.routes.shared import _audit, _corr_id, _get_session, require_owner_or_admin
from netcontrol.telemetry import configure_logging

router = APIRouter()
admin_router = APIRouter()
LOGGER = configure_logging("plexus.playbooks")

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Models ───────────────────────────────────────────────────────────────────


class PlaybookCreate(BaseModel):
    name: str
    filename: str
    description: str = ""
    tags: list[str] = []
    content: str = ""
    type: str = "python"  # "python" or "ansible"
    # Typed run-dialog inputs (netcontrol/job_inputs.py). Empty: use the
    # schema the Python class declares in code, if any.
    input_schema: list | None = None
    # Who may run / commit the job; admin only to set.
    permissions: dict | None = None
    # Jobs from this playbook wait for approval (jobs.approve) before they
    # are queued; admin only to change.
    approval_required: bool | None = None


class PlaybookUpdate(BaseModel):
    name: str | None = None
    filename: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    content: str | None = None
    type: str | None = None
    input_schema: list | None = None
    permissions: dict | None = None
    approval_required: bool | None = None


class InputSchemaBody(BaseModel):
    schema_: list = Field(default_factory=list, alias="schema")


class PermissionsBody(BaseModel):
    run: dict | None = None
    commit: dict | None = None


# ── Filename sanitizers ──────────────────────────────────────────────────────

_PLAYBOOK_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")
_PLAYBOOK_ALLOWED_EXT = ".py"


def _sanitize_playbook_filename(filename: str) -> str:
    """Validate and normalise a playbook filename."""
    name = filename.strip()
    if name.endswith(_PLAYBOOK_ALLOWED_EXT):
        name = name[: -len(_PLAYBOOK_ALLOWED_EXT)]
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Invalid playbook filename: path separators are not allowed")
    if not _PLAYBOOK_FILENAME_RE.match(name):
        raise ValueError(
            f"Invalid playbook filename '{filename}': only letters, digits, underscores and hyphens are allowed"
        )
    return name + _PLAYBOOK_ALLOWED_EXT


def _sanitize_ansible_filename(filename: str) -> str:
    """Validate and normalise an Ansible playbook filename."""
    name = filename.strip()
    for ext in (".yml", ".yaml"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Invalid playbook filename: path separators are not allowed")
    if not _PLAYBOOK_FILENAME_RE.match(name):
        raise ValueError(
            f"Invalid playbook filename '{filename}': only letters, digits, underscores and hyphens are allowed"
        )
    return name + ".yml"


# The playbook modules that ship with Plexus (templates/playbooks). The API
# never writes over one, so an edit cannot plant code in a module admins
# run as a built-in; save a changed copy under a new filename instead.
BUILTIN_PLAYBOOK_FILES = frozenset(
    {
        "netflow_enable.py",
        "ntp_audit.py",
        "snmpv3_configurator.py",
        "template_configurator.py",
        "vlan1_destroyer.py",
    }
)


def write_playbook_file(filename: str, content: str, *, overwrite: bool = False) -> str:
    """Write a Python playbook's module and import it so its class registers.

    The file is created exclusively (``FileExistsError`` if it is there)
    unless ``overwrite`` is set, which the caller does only for the module
    of the playbook row being edited. A built-in module is never written.

    Only the written module is imported (its ``@register_playbook`` makes it
    runnable without a restart); the rest of the package is not reloaded.
    Callers are admin-only routes.
    """
    playbooks_dir = os.path.join(project_root, "templates", "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)
    safe_filename = _sanitize_playbook_filename(filename)
    if safe_filename in BUILTIN_PLAYBOOK_FILES:
        raise FileExistsError(f"'{safe_filename}' is a built-in playbook module")
    file_path = os.path.normpath(os.path.join(playbooks_dir, safe_filename))
    if not file_path.startswith(os.path.normpath(playbooks_dir)):
        raise ValueError("Invalid playbook filename: resulting path escapes the playbooks directory")
    with open(file_path, "w" if overwrite else "x", encoding="utf-8") as f:
        f.write(content)
    module_name = f"templates.playbooks.{safe_filename[:-3]}"
    try:
        sys.modules.pop(module_name, None)
        importlib.import_module(module_name)
    except Exception as e:
        LOGGER.warning("Failed to import playbook module %s: %s", module_name, e)
    return file_path


async def _require_playbook_file_free(safe_filename: str, playbook_id: int | None) -> None:
    """Refuse (409) a module filename that is a built-in's or another
    playbook row's: writing it would replace that playbook's code."""
    if safe_filename in BUILTIN_PLAYBOOK_FILES:
        raise HTTPException(409, f"'{safe_filename}' is a built-in playbook; save your copy under another filename")
    for other in await db.get_all_playbooks():
        if other.get("filename") == safe_filename and other.get("id") != playbook_id:
            raise HTTPException(409, f"'{safe_filename}' belongs to another playbook ('{other.get('name')}')")


def _write_playbook_module(safe_filename: str, content: str, *, overwrite: bool) -> None:
    """``write_playbook_file`` with its refusals as HTTP errors."""
    try:
        write_playbook_file(safe_filename, content, overwrite=overwrite)
    except FileExistsError:
        raise HTTPException(409, f"A playbook file named '{safe_filename}' already exists; choose another filename")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


async def _require_admin_for_code(request: Request | None) -> None:
    """Changing a playbook's code (content, type or filename) needs an admin:
    a Python playbook runs inside the Plexus server and an Ansible playbook
    on the controller."""
    if request is None:
        return
    try:
        await require_owner_or_admin(request, None)
    except HTTPException as exc:
        raise HTTPException(
            status_code=403, detail="Only an admin can change a playbook's code, type or filename"
        ) from exc


def _same_text(a: str | None, b: str | None) -> bool:
    """Equal ignoring line-ending style (the editor normalises to ``\\n``)."""
    return (a or "").replace("\r\n", "\n") == (b or "").replace("\r\n", "\n")


async def sync_playbooks_from_registry():
    """Sync playbooks from the registry to the database."""
    from routes.database import sync_playbook_filename
    from routes.runner import list_registered_playbooks

    registered = list_registered_playbooks()
    db_playbooks = await db.get_all_playbooks()
    db_filenames = {pb["filename"] for pb in db_playbooks}

    for pb in registered:
        if pb["filename"] not in db_filenames:
            existing = next((p for p in db_playbooks if p["name"] == pb["name"]), None)
            if existing:
                try:
                    await sync_playbook_filename(pb["name"], pb["filename"])
                    LOGGER.info("sync: updated filename for '%s' to '%s'", pb["name"], pb["filename"])
                except Exception as e:
                    LOGGER.warning("sync: error syncing filename for '%s': %s", pb["name"], e)
            else:
                try:
                    await db.create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
                    LOGGER.info("sync: added missing playbook '%s' (%s)", pb["name"], pb["filename"])
                except Exception as e:
                    LOGGER.warning("sync: error adding playbook '%s': %s", pb["name"], e)


def effective_input_schema(playbook: dict) -> tuple[list[dict], str]:
    """The typed input schema a run of ``playbook`` validates against, and
    where it comes from: ``stored`` (the playbook row), ``code`` (the Python
    class's ``parameters_schema``) or ``none``."""
    from routes.runner import get_playbook_class

    stored = playbook.get("input_schema") or []
    if stored:
        try:
            return job_inputs.normalize_schema(stored), "stored"
        except job_inputs.JobInputError as exc:
            LOGGER.warning("playbook %s: stored input schema is not valid: %s", playbook.get("id"), exc.fields)
            return [], "none"
    if playbook.get("type", "python") == "python":
        cls = get_playbook_class(playbook.get("filename", ""))
        code = getattr(cls, "parameters_schema", None) if cls is not None else None
        if code:
            try:
                return job_inputs.normalize_schema(code), "code"
            except job_inputs.JobInputError as exc:
                LOGGER.warning("playbook %s: code input schema is not valid: %s", playbook.get("filename"), exc.fields)
    return [], "none"


def playbook_supports_dry_run(playbook: dict) -> bool:
    """Ansible always previews (``--check --diff``); a Python class opts out
    with ``supports_dry_run = False``."""
    from routes.runner import get_playbook_class

    if playbook.get("type", "python") == "ansible":
        return True
    cls = get_playbook_class(playbook.get("filename", ""))
    return bool(getattr(cls, "supports_dry_run", True)) if cls is not None else True


def playbook_permissions(playbook: dict) -> dict:
    """The playbook's run/commit rules; a stored value that no longer
    validates is treated as unrestricted rather than breaking the list."""
    try:
        return job_inputs.normalize_permissions(playbook.get("permissions") or {})
    except job_inputs.JobInputError:
        LOGGER.warning("playbook %s: stored permissions are not valid", playbook.get("id"))
        return job_inputs.normalize_permissions({})


def _attach_parameters_schema(playbook: dict, caller: tuple[str, list[int]] | None = None) -> dict:
    """Decorate a playbook dict with its effective typed input schema, the
    dry-run capability and, given the caller's role and access groups,
    whether they may run and commit it - so the run dialog needs no second
    round-trip. ``parameters_schema`` is the same schema under its old key."""
    schema, source = effective_input_schema(playbook)
    permissions = playbook_permissions(playbook)
    playbook["input_schema"] = schema
    playbook["parameters_schema"] = schema
    playbook["input_schema_source"] = source
    playbook["supports_dry_run"] = playbook_supports_dry_run(playbook)
    playbook["permissions"] = permissions
    if caller is not None:
        role, group_ids = caller
        playbook["can_run"] = job_inputs.is_allowed(permissions, "run", role=role, group_ids=group_ids)
        playbook["can_commit"] = job_inputs.is_allowed(permissions, "commit", role=role, group_ids=group_ids)
    return playbook


def _unprocessable(exc: job_inputs.JobInputError) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": exc.message, "fields": exc.fields})


def _clean_schema(raw: list | None) -> list[dict] | None:
    if raw is None:
        return None
    try:
        return job_inputs.normalize_schema(raw)
    except job_inputs.JobInputError as exc:
        raise _unprocessable(exc)


async def _require_schema_secrets(
    schema: list[dict] | None, request: Request | None, stored: list | None = None
) -> None:
    """A secret input's default (a bare secret name) and any
    ``{{secret.NAME}}`` in the schema may name only secret variables the
    saving user may use: a launch that leaves the field blank resolves the
    default for whoever runs the job. Saving the ``stored`` schema again
    unchanged (the editor sends every field) is not checked."""
    if not schema or schema == stored:
        return
    defaults = [str(f.get("default")) for f in schema if f.get("type") == "secret" and f.get("default")]
    await require_usable_secret_references(request, [json.dumps(schema)], names=defaults)


async def _clean_permissions(raw: dict | None, request: Request | None) -> dict | None:
    """Validate permissions and require an admin to set them (a user who
    could edit them could grant themselves commit)."""
    if raw is None:
        return None
    if request is not None:
        await require_owner_or_admin(request, None)
    try:
        permissions = job_inputs.normalize_permissions(raw)
    except job_inputs.JobInputError as exc:
        raise _unprocessable(exc)
    missing = await job_inputs.unknown_access_groups({g for rule in permissions.values() for g in rule["groups"]})
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "The permissions name access groups that do not exist.",
                "fields": {"groups": f"Unknown access group id(s): {', '.join(map(str, missing))}"},
            },
        )
    return permissions


async def _clean_approval_required(wanted: bool | None, current: bool, request: Request | None) -> bool | None:
    """The ``approval_required`` to store, or ``None`` to leave it. Changing
    it needs an admin, like the run and commit permissions: a user who could
    clear it could run the job without approval."""
    if wanted is None or bool(wanted) == bool(current):
        return None
    if request is not None:
        await require_owner_or_admin(request, None)
    return bool(wanted)


async def _caller(request: Request | None) -> tuple[str, list[int]] | None:
    if request is None:
        return None
    return await job_inputs.user_permissions(_get_session(request))


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/api/playbooks/{playbook_id}")
@scope_exempt("shared playbook catalogue: no host or inventory group data")
async def get_playbook(playbook_id: int, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    content = playbook.get("content")
    if content is None:
        content = ""

    if (not content or content.strip() == "") and playbook.get("type", "python") == "python":
        playbooks_dir = os.path.join(project_root, "templates", "playbooks")
        filename = playbook["filename"]
        if not filename.endswith(".py"):
            filename += ".py"
        file_path = os.path.normpath(os.path.join(playbooks_dir, filename))
        if not file_path.startswith(os.path.normpath(playbooks_dir)):
            raise HTTPException(400, "Invalid playbook filename")
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding="utf-8") as f:
                    file_content = f.read()
                    playbook["content"] = file_content
                await db.update_playbook(playbook_id, content=file_content)
                LOGGER.info("Loaded playbook content from file: %s (%s chars)", filename, len(file_content))
            except Exception as e:
                LOGGER.warning("Failed to read playbook file %s: %s", file_path, e)
                playbook["content"] = ""
        else:
            LOGGER.warning("Playbook file not found: %s", file_path)
            playbook["content"] = ""
    else:
        LOGGER.debug("Using playbook content from database (length: %s)", len(content))

    if "content" not in playbook:
        playbook["content"] = ""

    return _attach_parameters_schema(playbook, await _caller(request))


@router.get("/api/playbooks")
@scope_exempt("shared playbook catalogue: no host or inventory group data")
async def list_playbooks(request: Request = None):
    await sync_playbooks_from_registry()
    playbooks = await db.get_all_playbooks()
    caller = await _caller(request)
    return [_attach_parameters_schema(pb, caller) for pb in playbooks]


@router.get("/api/playbooks/{playbook_id}/input-schema")
@scope_exempt("shared playbook catalogue: no host or inventory group data")
async def get_playbook_input_schema(playbook_id: int, request: Request = None):
    """The run-dialog form: typed fields, dry-run support and whether the
    caller may run and commit this playbook."""
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    pb = _attach_parameters_schema(playbook, await _caller(request))
    return {
        "playbook_id": playbook_id,
        "schema": pb["input_schema"],
        "source": pb["input_schema_source"],
        "supports_dry_run": pb["supports_dry_run"],
        "permissions": pb["permissions"],
        "can_run": pb.get("can_run", True),
        "can_commit": pb.get("can_commit", True),
    }


@router.put("/api/playbooks/{playbook_id}/input-schema")
@scoped("catalog")
async def put_playbook_input_schema(playbook_id: int, body: InputSchemaBody, request: Request = None):
    """Replace the stored input schema. ``[]`` falls back to the schema the
    Python class declares in code."""
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await require_model_write(request)
    schema = _clean_schema(body.schema_) or []
    await _require_schema_secrets(schema, request, playbook.get("input_schema"))
    await db.update_playbook(playbook_id, input_schema=schema)
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "playbook.input_schema",
        user=session["user"] if session else "",
        detail=f"set {len(schema)} input field(s) on playbook {playbook_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "schema": schema}


@router.put("/api/playbooks/{playbook_id}/permissions")
@scoped("catalog")
async def put_playbook_permissions(playbook_id: int, body: PermissionsBody, request: Request = None):
    """Replace who may run and commit the playbook (admin only)."""
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await require_model_write(request)
    permissions = await _clean_permissions({"run": body.run, "commit": body.commit}, request) or {}
    await db.update_playbook(playbook_id, permissions=permissions)
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "playbook.permissions",
        user=session["user"] if session else "",
        detail=f"set run/commit permissions on playbook {playbook_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "permissions": permissions}


@admin_router.post("/api/playbooks", status_code=201)
@scoped("catalog")
async def create_playbook(body: PlaybookCreate, request: Request = None):
    await require_model_write(request)
    pb_type = body.type if body.type in ("python", "ansible") else "python"
    try:
        if pb_type == "ansible":
            filename = _sanitize_ansible_filename(body.filename)
        else:
            filename = _sanitize_playbook_filename(body.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    input_schema = _clean_schema(body.input_schema)
    await _require_schema_secrets(input_schema, request)
    permissions = await _clean_permissions(body.permissions, request)
    approval_required = await _clean_approval_required(body.approval_required, False, request)
    await _require_playbook_file_free(filename, None)
    if pb_type == "python" and body.content:
        _write_playbook_module(filename, body.content, overwrite=False)
    pid = await db.create_playbook(
        body.name,
        filename,
        body.description,
        body.tags,
        body.content,
        type=pb_type,
        input_schema=input_schema,
        permissions=permissions,
        approval_required=bool(approval_required),
    )
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "playbook.create",
        user=session["user"] if session else "",
        detail=f"created {pb_type} playbook '{body.name}'" + (" approval_required=1" if approval_required else ""),
        correlation_id=_corr_id(request),
    )
    return {"id": pid}


@router.put("/api/playbooks/{playbook_id}")
@scoped("catalog")
async def update_playbook(playbook_id: int, body: PlaybookUpdate, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await require_model_write(request)
    if any(v is not None for v in (body.name, body.filename, body.description, body.tags, body.content, body.type)):
        # A Git source's playbook changes in its repository; inputs and permissions stay editable.
        reject_git_owned(playbook, "playbook")
    current_type = playbook.get("type", "python")
    pb_type = body.type if body.type in ("python", "ansible") else current_type
    update_filename = None
    if body.filename is not None:
        try:
            if pb_type == "ansible":
                update_filename = _sanitize_ansible_filename(body.filename)
            else:
                update_filename = _sanitize_playbook_filename(body.filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    # The editor sends every field on save; only a value that differs from
    # the stored one is a change. Code changes are admin only.
    content_changed = body.content is not None and not _same_text(body.content, playbook.get("content"))
    type_changed = pb_type != current_type
    filename_changed = update_filename is not None and update_filename != playbook.get("filename")
    code_changed = content_changed or type_changed or filename_changed
    if code_changed:
        await _require_admin_for_code(request)
    input_schema = _clean_schema(body.input_schema)
    await _require_schema_secrets(input_schema, request, playbook.get("input_schema"))
    permissions = await _clean_permissions(body.permissions, request)
    approval_required = await _clean_approval_required(
        body.approval_required, bool(playbook.get("approval_required")), request
    )
    target_filename = update_filename or playbook["filename"]
    if filename_changed:
        await _require_playbook_file_free(target_filename, playbook_id)
    if pb_type == "python" and code_changed and body.content is not None:
        # Overwrite only the module this (python) row already owns; a new
        # filename, or a row switching from Ansible, creates its file.
        own_module = not filename_changed and current_type == "python"
        if own_module:
            await _require_playbook_file_free(target_filename, playbook_id)
        _write_playbook_module(target_filename, body.content, overwrite=own_module)
    await db.update_playbook(
        playbook_id,
        name=body.name,
        filename=update_filename if filename_changed else None,
        description=body.description,
        tags=body.tags,
        content=body.content if content_changed else None,
        type=pb_type if type_changed else None,
        input_schema=input_schema,
        permissions=permissions,
        approval_required=approval_required,
    )
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "playbook.update",
        user=session["user"] if session else "",
        detail=f"updated playbook {playbook_id}"
        + (" code_changed=1" if code_changed else "")
        + (f" approval_required={int(approval_required)}" if approval_required is not None else ""),
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@admin_router.delete("/api/playbooks/{playbook_id}")
@scoped("catalog")
async def delete_playbook(playbook_id: int, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await require_model_write(request)
    reject_git_owned(playbook, "playbook")
    await db.delete_playbook(playbook_id)
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "playbook.delete",
        user=session["user"] if session else "",
        detail=f"deleted playbook {playbook_id} ('{playbook['name']}')",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}
