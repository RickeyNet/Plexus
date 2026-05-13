"""
credentials.py -- Credential CRUD routes.
"""
from __future__ import annotations


import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from routes.crypto import encrypt

from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()


def _can_modify(cred: dict, session: dict | None) -> bool:
    """Return True if the session user may modify/delete *cred* via the
    per-user endpoints.

    User credentials are strictly per-owner: only the creator may view,
    modify, delete, or use them. The admin role does not grant access to
    other users' credentials. API-token callers (server-level auth)
    bypass the check by design.

    Service credentials (is_service=1) are explicitly excluded - they
    have their own admin-only endpoints under /api/credentials/service.
    """
    if not session:
        return False
    if cred.get("is_service"):
        return False
    if session.get("auth_mode") == "token":
        return True
    owner = cred.get("owner_id")
    if owner is None:
        return False
    return owner == session["user_id"]


async def _require_admin_session(session: dict | None) -> dict:
    """Return *session* if it represents an admin caller. Raises 401/403."""
    if not session:
        raise HTTPException(401, "Not authenticated")
    if session.get("auth_mode") == "token":
        return session
    user = await db.get_user_by_id(session["user_id"])
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return session


class CredentialCreate(BaseModel):
    name: str
    username: str
    password: str
    secret: str = ""


class CredentialUpdate(BaseModel):
    name: str | None = None
    username: str | None = None
    password: str | None = None
    secret: str | None = None


# ── Service credentials ─────────────────────────────────────────────────────
#
# Service credentials are owned by Plexus itself, not by any user. They are
# used for monitoring polls, scheduled SNMP discovery, and other background
# work where there is no interactive user submitter. Admin-only on read and
# write so a regular user can never select one through the UI.
#
# Registered before the per-user /{cred_id} routes so the literal `service`
# path segment is matched first; otherwise FastAPI tries the int-typed
# {cred_id} route first, fails Pydantic validation on the string, and
# returns 422 instead of falling through.


@router.get("/api/credentials/service")
async def list_service_credentials(request: Request):
    session = _get_session(request)
    await _require_admin_session(session)
    return await db.get_service_credentials()


@router.post("/api/credentials/service", status_code=201)
async def create_service_credential(body: CredentialCreate, request: Request):
    session = _get_session(request)
    await _require_admin_session(session)
    cid = await db.create_credential(
        body.name, body.username,
        encrypt(body.password),
        encrypt(body.secret) if body.secret else encrypt(body.password),
        owner_id=None,
        is_service=True,
    )
    await _audit(
        "config", "service_credential.create",
        user=session["user"],
        detail=f"created service credential '{body.name}'",
        correlation_id=_corr_id(request),
    )
    return {"id": cid}


@router.put("/api/credentials/service/{cred_id}")
async def update_service_credential(cred_id: int, body: CredentialUpdate, request: Request):
    session = _get_session(request)
    await _require_admin_session(session)
    cred = await db.get_credential_raw(cred_id)
    if not cred or not cred.get("is_service"):
        raise HTTPException(404, "Service credential not found")
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
    await _audit(
        "config", "service_credential.update",
        user=session["user"],
        detail=f"updated service credential {cred_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/credentials/service/{cred_id}")
async def delete_service_credential(cred_id: int, request: Request):
    session = _get_session(request)
    await _require_admin_session(session)
    cred = await db.get_credential_raw(cred_id)
    if not cred or not cred.get("is_service"):
        raise HTTPException(404, "Service credential not found")
    await db.delete_credential(cred_id)
    await _audit(
        "config", "service_credential.delete",
        user=session["user"],
        detail=f"deleted service credential {cred_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── User credentials ────────────────────────────────────────────────────────


@router.get("/api/credentials")
async def list_credentials(request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    # Credentials are strictly per-owner: every user (including admins)
    # sees only the credentials they created. API-token callers see all.
    if session.get("auth_mode") == "token":
        return await db.get_all_credentials(owner_id=None)
    return await db.get_all_credentials(owner_id=session["user_id"])


@router.post("/api/credentials", status_code=201)
async def create_credential(body: CredentialCreate, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    owner_id = session["user_id"]
    cid = await db.create_credential(
        body.name, body.username,
        encrypt(body.password),
        encrypt(body.secret) if body.secret else encrypt(body.password),
        owner_id=owner_id,
    )
    await _audit("config", "credential.create", user=session["user"], detail=f"created credential '{body.name}'", correlation_id=_corr_id(request))
    return {"id": cid}


@router.delete("/api/credentials/{cred_id}")
async def delete_credential(cred_id: int, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if not _can_modify(cred, session):
        raise HTTPException(403, "You can only delete your own credentials")
    await db.delete_credential(cred_id)
    await _audit("config", "credential.delete", user=session["user"], detail=f"deleted credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.put("/api/credentials/{cred_id}")
async def update_credential(cred_id: int, body: CredentialUpdate, request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if not _can_modify(cred, session):
        raise HTTPException(403, "You can only edit your own credentials")
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
    await _audit("config", "credential.update", user=session["user"], detail=f"updated credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}
