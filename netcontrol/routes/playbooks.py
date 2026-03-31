"""
playbooks.py -- Playbook CRUD routes and file management.
"""

import importlib
import os
import re
import sys

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
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

class PlaybookUpdate(BaseModel):
    name: str | None = None
    filename: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    content: str | None = None
    type: str | None = None


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
            f"Invalid playbook filename '{filename}': "
            "only letters, digits, underscores and hyphens are allowed"
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
            f"Invalid playbook filename '{filename}': "
            "only letters, digits, underscores and hyphens are allowed"
        )
    return name + ".yml"


def write_playbook_file(filename: str, content: str) -> str:
    """Write playbook content to a file and reload the module."""
    playbooks_dir = os.path.join(project_root, "templates", "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)
    safe_filename = _sanitize_playbook_filename(filename)
    file_path = os.path.normpath(os.path.join(playbooks_dir, safe_filename))
    if not file_path.startswith(os.path.normpath(playbooks_dir)):
        raise ValueError("Invalid playbook filename: resulting path escapes the playbooks directory")
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    module_name = f"templates.playbooks.{safe_filename[:-3]}"
    try:
        if module_name in sys.modules:
            del sys.modules[module_name]
        if 'templates.playbooks' in sys.modules:
            importlib.reload(sys.modules['templates.playbooks'])
        else:
            importlib.import_module('templates.playbooks')
    except Exception as e:
        LOGGER.warning("Failed to reload playbook module %s: %s", module_name, e)
    return file_path


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
                    LOGGER.info("sync: updated filename for '%s' to '%s'", pb['name'], pb['filename'])
                except Exception as e:
                    LOGGER.warning("sync: error syncing filename for '%s': %s", pb['name'], e)
            else:
                try:
                    await db.create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
                    LOGGER.info("sync: added missing playbook '%s' (%s)", pb['name'], pb['filename'])
                except Exception as e:
                    LOGGER.warning("sync: error adding playbook '%s': %s", pb['name'], e)


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/api/playbooks/{playbook_id}")
async def get_playbook(playbook_id: int):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    content = playbook.get("content")
    if content is None:
        content = ""

    if (not content or content.strip() == "") and playbook.get("type", "python") == "python":
        playbooks_dir = os.path.join(project_root, "templates", "playbooks")
        filename = playbook["filename"]
        if not filename.endswith('.py'):
            filename += '.py'
        file_path = os.path.normpath(os.path.join(playbooks_dir, filename))
        if not file_path.startswith(os.path.normpath(playbooks_dir)):
            raise HTTPException(400, "Invalid playbook filename")
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding='utf-8') as f:
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

    return playbook


@router.get("/api/playbooks")
async def list_playbooks():
    await sync_playbooks_from_registry()
    return await db.get_all_playbooks()


@router.post("/api/playbooks", status_code=201)
async def create_playbook(body: PlaybookCreate, request: Request = None):
    pb_type = body.type if body.type in ("python", "ansible") else "python"
    try:
        if pb_type == "ansible":
            filename = _sanitize_ansible_filename(body.filename)
        else:
            filename = _sanitize_playbook_filename(body.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if pb_type == "python" and body.content:
        write_playbook_file(filename, body.content)
    pid = await db.create_playbook(body.name, filename, body.description, body.tags, body.content, type=pb_type)
    session = _get_session(request) if request else None
    await _audit("config", "playbook.create", user=session["user"] if session else "", detail=f"created {pb_type} playbook '{body.name}'", correlation_id=_corr_id(request))
    return {"id": pid}


@router.put("/api/playbooks/{playbook_id}")
async def update_playbook(playbook_id: int, body: PlaybookUpdate, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    pb_type = body.type if body.type in ("python", "ansible") else playbook.get("type", "python")
    update_filename = None
    if body.filename is not None:
        try:
            if pb_type == "ansible":
                update_filename = _sanitize_ansible_filename(body.filename)
            else:
                update_filename = _sanitize_playbook_filename(body.filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if pb_type == "python" and body.content is not None:
        target_filename = update_filename or playbook["filename"]
        write_playbook_file(target_filename, body.content)
    await db.update_playbook(
        playbook_id,
        name=body.name,
        filename=update_filename,
        description=body.description,
        tags=body.tags,
        content=body.content,
        type=body.type,
    )
    session = _get_session(request) if request else None
    await _audit("config", "playbook.update", user=session["user"] if session else "", detail=f"updated playbook {playbook_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: int, request: Request = None):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await db.delete_playbook(playbook_id)
    session = _get_session(request) if request else None
    await _audit("config", "playbook.delete", user=session["user"] if session else "", detail=f"deleted playbook {playbook_id} ('{playbook['name']}')", correlation_id=_corr_id(request))
    return {"ok": True}
