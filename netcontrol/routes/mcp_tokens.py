"""Admin API for AI access: the ``/mcp`` endpoint settings and its tokens.

Every route is admin-only (the router is registered with ``require_admin``).
A token's plaintext is returned once, by the create route, and is never
written to the database, a log line or an audit event.
"""

from __future__ import annotations

import re
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from netcontrol.mcp import auth as mcp_auth, settings as mcp_settings
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter(prefix="/api/admin/mcp")

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    owner_user_id: int
    categories: list[str] = Field(min_length=1, max_length=len(mcp_auth.CATEGORIES))
    expires_at: str = Field(default="", max_length=10)


def _unprocessable(message: str) -> HTTPException:
    return HTTPException(status_code=422, detail=message)


@router.get("/settings")
async def get_settings() -> dict[str, Any]:
    return await mcp_settings.load_settings()


@router.put("/settings")
async def update_settings(body: dict[str, Any], request: Request) -> dict[str, Any]:
    try:
        merged = await mcp_settings.save_settings(body)
    except ValueError as exc:
        raise _unprocessable(str(exc)) from exc
    await _audit(
        "mcp",
        "settings_update",
        user=_session_user(request),
        detail=", ".join(f"{key}={merged[key]}" for key in sorted(body)),
        correlation_id=_corr_id(request),
    )
    return merged


@router.get("/tokens")
async def list_tokens() -> dict[str, Any]:
    return {"tokens": await db.list_mcp_tokens(), "categories": list(mcp_auth.CATEGORIES)}


@router.post("/tokens")
async def create_token(body: TokenCreate, request: Request) -> dict[str, Any]:
    name = body.name.strip()
    if not name:
        raise _unprocessable("Enter a name for the token.")
    categories = list(dict.fromkeys(body.categories))
    unknown = sorted(set(categories) - set(mcp_auth.CATEGORIES))
    if unknown:
        raise _unprocessable(f"Unknown category: {', '.join(unknown)}")
    expires_at = body.expires_at.strip()
    if expires_at and not _DATE_RE.fullmatch(expires_at):
        raise _unprocessable("Expiry must be a date in the form YYYY-MM-DD.")
    owner = await db.get_user_by_id(body.owner_user_id)
    if not owner:
        raise _unprocessable("The selected owner does not exist.")
    if "audit" in categories and owner.get("role") != "admin":
        raise _unprocessable("The audit category needs an owner who is an admin.")

    plaintext, token_hash, prefix = mcp_auth.generate_token()
    try:
        token_id = await db.create_mcp_token(
            name=name,
            token_hash=token_hash,
            token_prefix=prefix,
            owner_user_id=int(owner["id"]),
            categories=categories,
            expires_at=expires_at,
            created_by=_session_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(
        "mcp",
        "token_create",
        user=_session_user(request),
        detail=f"token={name} owner={owner['username']} categories={','.join(categories)}",
        correlation_id=_corr_id(request),
    )
    record = next((t for t in await db.list_mcp_tokens() if t["id"] == token_id), None)
    return {"token": plaintext, "record": record}


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: int, request: Request) -> dict[str, bool]:
    row = await db.get_mcp_token(token_id)
    if not row or not await db.revoke_mcp_token(token_id):
        raise HTTPException(status_code=404, detail="Token not found or already revoked.")
    await _audit(
        "mcp",
        "token_revoke",
        user=_session_user(request),
        detail=f"token={row['name']}",
        correlation_id=_corr_id(request),
    )
    return {"revoked": True}
