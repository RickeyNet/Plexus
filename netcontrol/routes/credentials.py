"""
credentials.py -- Credential CRUD routes.
"""

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from routes.crypto import encrypt

from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()


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
    owner_id = session["user_id"] if session else None
    return await db.get_all_credentials(owner_id=owner_id)


@router.post("/api/credentials", status_code=201)
async def create_credential(body: CredentialCreate, request: Request):
    session = _get_session(request)
    owner_id = session["user_id"] if session else None
    cid = await db.create_credential(
        body.name, body.username,
        encrypt(body.password),
        encrypt(body.secret) if body.secret else encrypt(body.password),
        owner_id=owner_id,
    )
    await _audit("config", "credential.create", user=session["user"] if session else "", detail=f"created credential '{body.name}'", correlation_id=_corr_id(request))
    return {"id": cid}


@router.delete("/api/credentials/{cred_id}")
async def delete_credential(cred_id: int, request: Request):
    session = _get_session(request)
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
        raise HTTPException(403, "You can only delete your own credentials")
    await db.delete_credential(cred_id)
    await _audit("config", "credential.delete", user=session["user"] if session else "", detail=f"deleted credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.put("/api/credentials/{cred_id}")
async def update_credential(cred_id: int, body: CredentialUpdate, request: Request):
    session = _get_session(request)
    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")
    if cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
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
    await _audit("config", "credential.update", user=session["user"] if session else "", detail=f"updated credential {cred_id}", correlation_id=_corr_id(request))
    return {"ok": True}
