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


async def _is_admin(session: dict | None) -> bool:
    """Check whether the session user has the admin role."""
    if not session:
        return False
    if session.get("auth_mode") == "token":
        return True  # API-token callers are treated as admin
    user = await db.get_user_by_id(session["user_id"])
    return bool(user and user.get("role") == "admin")


def _can_modify(cred: dict, session: dict | None, is_admin: bool) -> bool:
    """Return True if the session user may modify/delete *cred*.

    Rules:
      - Admins can modify any credential.
      - Owners can modify their own credentials.
      - Unowned credentials (owner_id is NULL) require admin.
    """
    if is_admin:
        return True
    if not session:
        return False
    owner = cred.get("owner_id")
    if owner is None:
        return False  # unowned → admin-only
    return owner == session["user_id"]


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


@router.get("/api/credentials")
async def list_credentials(request: Request):
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    # Admins see every credential; regular users see only their own
    if await _is_admin(session):
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
    if not _can_modify(cred, session, await _is_admin(session)):
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
    if not _can_modify(cred, session, await _is_admin(session)):
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
