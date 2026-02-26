"""
app.py — Plexus FastAPI Application

REST API for inventory, playbooks, templates, credentials, and jobs.
WebSocket endpoint for real-time job output streaming.
Session-based authentication with signed cookies.
"""

import sys
import os
import json
import asyncio
import hashlib
import secrets
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Request, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import routes.database as db
from routes.crypto import encrypt, decrypt
from routes.runner import get_playbook_class, execute_playbook, LogEvent
import importlib

# Auto-register all playbooks
from templates import playbooks  # noqa: F401


def write_playbook_file(filename: str, content: str) -> str:
    """
    Write playbook content to a file and reload the module.
    Returns the file path.
    """
    playbooks_dir = os.path.join(project_root, "templates", "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)
    
    file_path = os.path.join(playbooks_dir, filename)
    
    # Ensure filename ends with .py
    if not filename.endswith('.py'):
        file_path += '.py'
        filename += '.py'
    
    # Write the file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Reload the playbook module to pick up changes
    module_name = f"templates.playbooks.{filename[:-3]}"
    try:
        # Remove from cache if exists
        if module_name in sys.modules:
            del sys.modules[module_name]
        
        # Reload the playbooks package to re-import all modules
        if 'templates.playbooks' in sys.modules:
            importlib.reload(sys.modules['templates.playbooks'])
        else:
            importlib.import_module('templates.playbooks')
    except Exception as e:
        # If reload fails, log but don't fail - module will be loaded on next server restart
        print(f"[warning] Failed to reload playbook module {module_name}: {e}")
    
    return file_path


# ═════════════════════════════════════════════════════════════════════════════
# Authentication
# ═════════════════════════════════════════════════════════════════════════════

AUTH_FILE = os.path.join(os.path.dirname(__file__), "..", "routes", "auth.json")
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "routes", "session.key")
SESSION_MAX_AGE = 86400  # 24 hours


def _load_or_create_secret_key() -> str:
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(key)
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


_secret_key = _load_or_create_secret_key()
_serializer = URLSafeTimedSerializer(_secret_key)


def _hash_password(password: str, salt: str = "") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def _load_users() -> dict:
    if os.path.isfile(AUTH_FILE):
        with open(AUTH_FILE, "r") as f:
            return json.load(f)
    # Create default admin user on first run
    salt = secrets.token_hex(16)
    users = {
        "admin": {
            "password_hash": _hash_password("netcontrol", salt),
            "salt": salt,
            "role": "admin"
        }
    }
    with open(AUTH_FILE, "w") as f:
        json.dump(users, f, indent=2)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass
    print("[auth] Created default user: admin / netcontrol  — CHANGE THIS PASSWORD!")
    return users


def _save_users(users: dict):
    with open(AUTH_FILE, "w") as f:
        json.dump(users, f, indent=2)


def verify_user(username: str, password: str) -> bool:
    users = _load_users()
    user = users.get(username)
    if not user:
        return False
    return _hash_password(password, user["salt"]) == user["password_hash"]


def create_session_token(username: str) -> str:
    return _serializer.dumps({"user": username})


def verify_session_token(token: str) -> str | None:
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("user")
    except (BadSignature, SignatureExpired):
        return None


PUBLIC_PATHS = {"/", "/api/auth/login", "/api/auth/status", "/favicon.ico", "/docs", "/openapi.json", "/redoc"}


async def require_auth(request: Request):
    """Dependency that checks for a valid session cookie."""
    path = request.url.path
    if path.startswith("/static/"):
        return None
    if path in PUBLIC_PATHS:
        return None

    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = verify_session_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired")
    return username


# ═════════════════════════════════════════════════════════════════════════════
# App Lifecycle
# ═════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and seed on startup."""
    await db.init_db()
    # Auto-seed if empty
    check = await db.get_all_groups()
    if not check:
        from routes.seed import seed
        await seed()
    yield


app = FastAPI(title="Plexus API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═════════════════════════════════════════════════════════════════════════════
# Auth Routes
# ═════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/auth/login")
async def login(body: LoginRequest):
    if not verify_user(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_session_token(body.username)
    response = JSONResponse({"ok": True, "username": body.username})
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
        secure=False,  # Set True when using HTTPS
    )
    return response


@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response


@app.get("/api/auth/status")
async def auth_status(request: Request):
    token = request.cookies.get("session")
    if not token:
        return {"authenticated": False}
    username = verify_session_token(token)
    if not username:
        return {"authenticated": False}
    return {"authenticated": True, "username": username}


@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest, request: Request):
    token = request.cookies.get("session")
    username = verify_session_token(token) if token else None
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not verify_user(username, body.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    users = _load_users()
    salt = secrets.token_hex(16)
    users[username]["password_hash"] = _hash_password(body.new_password, salt)
    users[username]["salt"] = salt
    _save_users(users)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════

class GroupCreate(BaseModel):
    name: str
    description: str = ""

class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"

class HostUpdate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"

class PlaybookCreate(BaseModel):
    name: str
    filename: str
    description: str = ""
    tags: list[str] = []
    content: str = ""

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    filename: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    content: Optional[str] = None

class TemplateCreate(BaseModel):
    name: str
    content: str
    description: str = ""

class TemplateUpdate(BaseModel):
    name: str
    content: str
    description: str = ""

class CredentialCreate(BaseModel):
    name: str
    username: str
    password: str
    secret: str = ""


class CredentialUpdate(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = None


class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: Optional[int] = None  # Optional for backward compatibility
    host_ids: Optional[list[int]] = None  # List of specific host IDs to target
    credential_id: Optional[int] = None
    template_id: Optional[int] = None
    dry_run: bool = True
    
    class Config:
        # Allow extra fields to be ignored (for backward compatibility)
        extra = "forbid"


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard", dependencies=[Depends(require_auth)])
async def dashboard():
    stats = await db.get_dashboard_stats()
    recent_jobs = await db.get_all_jobs(limit=5)
    groups = await db.get_all_groups()
    return {"stats": stats, "recent_jobs": recent_jobs, "groups": groups}


# ═════════════════════════════════════════════════════════════════════════════
# Inventory Groups
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/inventory", dependencies=[Depends(require_auth)])
async def list_groups():
    return await db.get_all_groups()


@app.post("/api/inventory", status_code=201, dependencies=[Depends(require_auth)])
async def create_group(body: GroupCreate):
    gid = await db.create_group(body.name, body.description)
    return {"id": gid, "name": body.name}


@app.get("/api/inventory/{group_id}", dependencies=[Depends(require_auth)])
async def get_group(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    hosts = await db.get_hosts_for_group(group_id)
    return {**group, "hosts": hosts}


@app.delete("/api/inventory/{group_id}", dependencies=[Depends(require_auth)])
async def delete_group(group_id: int):
    await db.delete_group(group_id)
    return {"ok": True}


# ── Hosts ────────────────────────────────────────────────────────────────────

@app.get("/api/inventory/{group_id}/hosts", dependencies=[Depends(require_auth)])
async def list_hosts(group_id: int):
    return await db.get_hosts_for_group(group_id)


@app.post("/api/inventory/{group_id}/hosts", status_code=201, dependencies=[Depends(require_auth)])
async def add_host(group_id: int, body: HostCreate):
    hid = await db.add_host(group_id, body.hostname, body.ip_address, body.device_type)
    return {"id": hid}


@app.put("/api/hosts/{host_id}", dependencies=[Depends(require_auth)])
async def update_host(host_id: int, body: HostUpdate):
    await db.update_host(host_id, body.hostname, body.ip_address, body.device_type)
    return {"ok": True}


@app.delete("/api/hosts/{host_id}", dependencies=[Depends(require_auth)])
async def remove_host(host_id: int):
    await db.remove_host(host_id)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Playbooks
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth)])
async def get_playbook(playbook_id: int):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # Ensure content is always a string (handle None case)
    content = playbook.get("content")
    if content is None:
        content = ""
    
    # If content is empty, try to load it from the file
    if not content or content.strip() == "":
        playbooks_dir = os.path.join(project_root, "templates", "playbooks")
        filename = playbook["filename"]
        if not filename.endswith('.py'):
            filename += '.py'
        file_path = os.path.join(playbooks_dir, filename)
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    playbook["content"] = file_content
                # Sync it back to the database
                await db.update_playbook(playbook_id, content=file_content)
                print(f"[info] Loaded playbook content from file: {filename} ({len(file_content)} chars)")
            except Exception as e:
                print(f"[warning] Failed to read playbook file {file_path}: {e}")
                playbook["content"] = ""
        else:
            print(f"[warning] Playbook file not found: {file_path}")
            playbook["content"] = ""
    else:
        print(f"[info] Using playbook content from database (length: {len(content)})")
    
    # Ensure content is always set (even if empty)
    if "content" not in playbook:
        playbook["content"] = ""
    
    return playbook


@app.get("/api/playbooks", dependencies=[Depends(require_auth)])
async def list_playbooks():
    # Sync registered playbooks that might be missing from database
    await sync_playbooks_from_registry()
    return await db.get_all_playbooks()


async def sync_playbooks_from_registry():
    """Sync playbooks from the registry to the database - add any missing ones."""
    from routes.runner import list_registered_playbooks
    from routes.database import sync_playbook_filename
    
    registered = list_registered_playbooks()
    db_playbooks = await db.get_all_playbooks()
    db_filenames = {pb["filename"] for pb in db_playbooks}
    
    for pb in registered:
        if pb["filename"] not in db_filenames:
            # Check if a playbook with the same name exists (might have different filename)
            existing = next((p for p in db_playbooks if p["name"] == pb["name"]), None)
            if existing:
                # Update the filename
                try:
                    await sync_playbook_filename(pb["name"], pb["filename"])
                    print(f"[sync] Updated filename for '{pb['name']}' to '{pb['filename']}'")
                except Exception as e:
                    print(f"[sync] Error syncing filename for '{pb['name']}': {e}")
            else:
                # Create new playbook
                try:
                    await db.create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
                    print(f"[sync] Added missing playbook '{pb['name']}' ({pb['filename']})")
                except Exception as e:
                    print(f"[sync] Error adding playbook '{pb['name']}': {e}")


@app.post("/api/playbooks", status_code=201, dependencies=[Depends(require_auth)])
async def create_playbook(body: PlaybookCreate):
    # Ensure filename ends with .py
    filename = body.filename if body.filename.endswith('.py') else body.filename + '.py'
    
    # Write the playbook file
    if body.content:
        write_playbook_file(filename, body.content)
    
    pid = await db.create_playbook(body.name, filename, body.description, body.tags, body.content)
    return {"id": pid}


@app.put("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth)])
async def update_playbook(playbook_id: int, body: PlaybookUpdate):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # If content is being updated, write the file
    if body.content is not None:
        filename = body.filename if body.filename else playbook["filename"]
        if not filename.endswith('.py'):
            filename += '.py'
        write_playbook_file(filename, body.content)
    
    # Update filename if provided
    update_filename = body.filename
    if update_filename and not update_filename.endswith('.py'):
        update_filename += '.py'
    
    await db.update_playbook(
        playbook_id,
        name=body.name,
        filename=update_filename,
        description=body.description,
        tags=body.tags,
        content=body.content
    )
    return {"ok": True}


@app.delete("/api/playbooks/{playbook_id}", dependencies=[Depends(require_auth)])
async def delete_playbook(playbook_id: int):
    playbook = await db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    
    # Optionally delete the file (but keep it for now in case of rollback)
    await db.delete_playbook(playbook_id)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/templates", dependencies=[Depends(require_auth)])
async def list_templates():
    return await db.get_all_templates()


@app.post("/api/templates", status_code=201, dependencies=[Depends(require_auth)])
async def create_template(body: TemplateCreate):
    tid = await db.create_template(body.name, body.content, body.description)
    return {"id": tid}


@app.get("/api/templates/{template_id}", dependencies=[Depends(require_auth)])
async def get_template(template_id: int):
    tpl = await db.get_template(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl


@app.put("/api/templates/{template_id}", dependencies=[Depends(require_auth)])
async def update_template(template_id: int, body: TemplateUpdate):
    await db.update_template(template_id, body.name, body.content, body.description)
    return {"ok": True}


@app.delete("/api/templates/{template_id}", dependencies=[Depends(require_auth)])
async def delete_template(template_id: int):
    await db.delete_template(template_id)
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Credentials
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/credentials", dependencies=[Depends(require_auth)])
async def list_credentials():
    return await db.get_all_credentials()


@app.post("/api/credentials", status_code=201, dependencies=[Depends(require_auth)])
async def create_credential(body: CredentialCreate):
    cid = await db.create_credential(
        body.name, body.username,
        encrypt(body.password),
        encrypt(body.secret) if body.secret else encrypt(body.password),
    )
    return {"id": cid}


@app.delete("/api/credentials/{cred_id}", dependencies=[Depends(require_auth)])
async def delete_credential(cred_id: int):
    await db.delete_credential(cred_id)
    return {"ok": True}


@app.put("/api/credentials/{cred_id}", dependencies=[Depends(require_auth)])
async def update_credential(cred_id: int, body: CredentialUpdate):
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.username is not None:
        updates["username"] = body.username
    if body.password is not None and body.password != "":
        updates["enc_password"] = encrypt(body.password)
    if body.secret is not None and body.secret != "":
        updates["enc_secret"] = encrypt(body.secret)
    if not updates:
        return {"ok": True}
    await db.update_credential(
        cred_id,
        name=updates.get("name"),
        username=updates.get("username"),
        enc_password=updates.get("enc_password"),
        enc_secret=updates.get("enc_secret"),
    )
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# Jobs
# ═════════════════════════════════════════════════════════════════════════════

# Active WebSocket connections keyed by job_id
_job_sockets: dict[int, list[WebSocket]] = {}


@app.get("/api/jobs", dependencies=[Depends(require_auth)])
async def list_jobs(limit: int = Query(50, ge=1, le=200)):
    return await db.get_all_jobs(limit=limit)


@app.get("/api/jobs/{job_id}", dependencies=[Depends(require_auth)])
async def get_job(job_id: int):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/jobs/{job_id}/events", dependencies=[Depends(require_auth)])
async def get_job_events(job_id: int):
    return await db.get_job_events(job_id)


@app.post("/api/jobs/launch", status_code=201, dependencies=[Depends(require_auth)])
async def launch_job(body: JobLaunch):
    """
    Launch a playbook execution as a background task.
    Returns the job ID immediately. Connect to the WebSocket
    at /ws/jobs/{job_id} to stream real-time output.
    """
    print(f"[debug] JobLaunch request: playbook_id={body.playbook_id}, host_ids={body.host_ids}, inventory_group_id={body.inventory_group_id}")
    
    # Validate playbook exists
    playbook = await db.get_playbook(body.playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Get hosts - either from selected host_ids or from inventory_group_id
    hosts = []
    inventory_group_id = None
    
    if body.host_ids and len(body.host_ids) > 0:
        # Use selected host IDs
        hosts = await db.get_hosts_by_ids(body.host_ids)
        if not hosts:
            raise HTTPException(400, "No valid hosts selected")
        # Use the group_id from the first host (for job record)
        if hosts:
            inventory_group_id = hosts[0].get("group_id")
    elif body.inventory_group_id:
        # Use all hosts from the group (backward compatibility)
        group = await db.get_group(body.inventory_group_id)
        if not group:
            raise HTTPException(404, "Inventory group not found")
        hosts = await db.get_hosts_for_group(body.inventory_group_id)
        if not hosts:
            raise HTTPException(400, "No hosts in inventory group")
        inventory_group_id = body.inventory_group_id
    else:
        raise HTTPException(400, "Must specify either host_ids or inventory_group_id")

    # Get credentials
    credentials = {"username": "netadmin", "password": "cisco123", "secret": "cisco123"}
    if body.credential_id:
        cred = await db.get_credential_raw(body.credential_id)
        if cred:
            credentials = {
                "username": cred["username"],
                "password": decrypt(cred["password"]),
                "secret": decrypt(cred["secret"]) if cred["secret"] else "",
            }

    # Get template commands
    template_commands = []
    if body.template_id:
        tpl = await db.get_template(body.template_id)
        if tpl:
            template_commands = [
                line.rstrip() for line in tpl["content"].splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    # Find the playbook runner class
    pb_class = get_playbook_class(playbook["filename"])
    if not pb_class:
        raise HTTPException(400, f"No runner registered for '{playbook['filename']}'")

    # Create job record (use inventory_group_id from hosts if not provided)
    job_id = await db.create_job(
        body.playbook_id, inventory_group_id,
        body.credential_id, body.template_id,
        body.dry_run,
    )

    # Launch as background task
    asyncio.create_task(_run_job(
        job_id, pb_class, hosts, credentials, template_commands, body.dry_run
    ))

    return {"job_id": job_id, "status": "running"}


async def _run_job(
    job_id: int,
    pb_class: type,
    hosts: list[dict],
    credentials: dict,
    template_commands: list[str],
    dry_run: bool,
):
    """Background task: execute playbook, store events, broadcast via WebSocket."""
    hosts_ok = 0
    hosts_failed = 0

    async def on_event(event: LogEvent):
        nonlocal hosts_ok, hosts_failed

        # Persist event
        await db.add_job_event(job_id, event.level, event.message, event.host)

        # Track host results
        if event.level == "success" and "Finished processing" in event.message:
            hosts_ok += 1
        elif event.level == "error" and event.host:
            hosts_failed += 1

        # Broadcast to WebSocket subscribers
        sockets = _job_sockets.get(job_id, [])
        dead = []
        for ws in sockets:
            try:
                await ws.send_json(event.to_dict())
            except Exception:
                dead.append(ws)
        for ws in dead:
            sockets.remove(ws)

    try:
        result = await execute_playbook(
            pb_class, hosts, credentials, template_commands, dry_run, on_event
        )
        await db.finish_job(
            job_id,
            status=result.status,
            hosts_ok=hosts_ok,
            hosts_failed=hosts_failed,
            hosts_skipped=result.hosts_skipped,
        )
    except Exception as e:
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
        await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

    # Notify WebSocket clients that job is done
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
    sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass


# ── WebSocket for live job streaming ─────────────────────────────────────────

@app.websocket("/ws/jobs/{job_id}")
async def websocket_job(websocket: WebSocket, job_id: int):
    """
    Stream job events in real-time.

    1. Client connects to /ws/jobs/{job_id}
    2. Server immediately sends all existing events for the job
    3. Server streams new events as they arrive
    4. Server sends {"type": "job_complete"} when done
    """
    await websocket.accept()

    # Send historical events first
    events = await db.get_job_events(job_id)
    for event in events:
        await websocket.send_json({
            "level": event["level"],
            "message": event["message"],
            "host": event["host"],
            "timestamp": event["timestamp"],
        })

    # Check if job is already done
    job = await db.get_job(job_id)
    if job and job["status"] not in ("running", "pending"):
        await websocket.send_json({
            "type": "job_complete", "job_id": job_id, "status": job["status"]
        })
        await websocket.close()
        return

    # Subscribe to live events
    if job_id not in _job_sockets:
        _job_sockets[job_id] = []
    _job_sockets[job_id].append(websocket)

    try:
        # Keep connection alive until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in _job_sockets and websocket in _job_sockets[job_id]:
            _job_sockets[job_id].remove(websocket)


# ═════════════════════════════════════════════════════════════════════════════
# Static Frontend (served at root)
# ═════════════════════════════════════════════════════════════════════════════

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_FILE = os.path.join(STATIC_DIR, "index.html")

# Mount static files directory
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_frontend():
    """Serve the frontend index.html or redirect to API docs."""
    if os.path.isfile(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    # If no frontend, redirect to API docs
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")

@app.get("/favicon.ico")
async def favicon():
    """Handle favicon requests gracefully."""
    return {"detail": "No favicon"}
