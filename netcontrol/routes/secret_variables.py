"""
secret_variables.py — CRUD routes for encrypted secret variables.

Secret variables are referenced in config templates via {{secret.NAME}}
and resolved at job execution time.  Values are AES-256-GCM encrypted at rest.
Only admins can create/update/delete secret variables.
"""
from __future__ import annotations


import re

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from routes.crypto import encrypt

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging


async def _require_admin_session(request: Request) -> dict:
    """Extract session and verify admin role. Raises 401/403."""
    session = _get_session(request)
    if not session:
        raise HTTPException(401, "Not authenticated")
    if session.get("auth_mode") == "token":
        return session
    user = await db.get_user_by_id(session["user_id"])
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return session

LOGGER = configure_logging("plexus.secret_variables")

router = APIRouter()

# ── Late-binding auth ─────────────────────────────────────────────────────────

_require_auth = None
_require_admin = None


def init_secret_variables(require_auth_fn, require_admin_fn):
    global _require_auth, _require_admin
    _require_auth = require_auth_fn
    _require_admin = require_admin_fn


# ── Validation ────────────────────────────────────────────────────────────────

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


def _validate_name(name: str) -> str:
    name = name.strip()
    if not _NAME_RE.fullmatch(name):
        raise HTTPException(
            400,
            "Secret name must start with a letter or underscore, contain only "
            "alphanumeric/underscore/hyphen, and be 1-64 characters.",
        )
    return name


# ── Pydantic models ──────────────────────────────────────────────────────────


class SecretVariableCreate(BaseModel):
    name: str
    value: str
    description: str = ""


class SecretVariableUpdate(BaseModel):
    value: str | None = None
    description: str | None = None


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/api/secret-variables")
async def list_secret_variables():
    """Return all secret variable metadata (names, descriptions — never values)."""
    return await db.get_all_secret_variables()


@router.get("/api/secret-variables/{var_id}")
async def get_secret_variable(var_id: int):
    """Return metadata for a single secret variable (never the value)."""
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")
    return sv


@router.post("/api/secret-variables", status_code=201)
async def create_secret_variable(body: SecretVariableCreate, request: Request):
    """Create a new secret variable. Requires admin role."""
    session = await _require_admin_session(request)
    name = _validate_name(body.name)
    if not body.value:
        raise HTTPException(400, "Value must not be empty")

    # Check for duplicate name
    existing = await db.get_secret_variable_by_name(name)
    if existing:
        raise HTTPException(409, f"Secret variable '{name}' already exists")

    enc_value = encrypt(body.value)
    var_id = await db.create_secret_variable(
        name=name,
        enc_value=enc_value,
        description=body.description,
        created_by=session["user"],
    )
    await _audit(
        "config", "secret_variable.create",
        user=session["user"],
        detail=f"created secret variable '{name}'",
        correlation_id=_corr_id(request),
    )
    LOGGER.info("Secret variable created: '%s' by %s", name, session["user"])
    return {"id": var_id, "name": name}


@router.put("/api/secret-variables/{var_id}")
async def update_secret_variable(var_id: int, body: SecretVariableUpdate, request: Request):
    """Update an existing secret variable. Requires admin role."""
    session = await _require_admin_session(request)
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")

    enc_value = encrypt(body.value) if body.value else None
    updated = await db.update_secret_variable(
        var_id,
        enc_value=enc_value,
        description=body.description,
    )
    if not updated:
        raise HTTPException(404, "Secret variable not found")

    what = []
    if body.value is not None:
        what.append("value")
    if body.description is not None:
        what.append("description")
    await _audit(
        "config", "secret_variable.update",
        user=session["user"],
        detail=f"updated secret variable '{sv['name']}' ({', '.join(what)})",
        correlation_id=_corr_id(request),
    )
    LOGGER.info("Secret variable updated: '%s' by %s", sv["name"], session["user"])
    return {"ok": True}


@router.delete("/api/secret-variables/{var_id}")
async def delete_secret_variable(var_id: int, request: Request):
    """Delete a secret variable. Requires admin role."""
    session = await _require_admin_session(request)
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")

    await db.delete_secret_variable(var_id)
    await _audit(
        "config", "secret_variable.delete",
        user=session["user"],
        detail=f"deleted secret variable '{sv['name']}'",
        correlation_id=_corr_id(request),
    )
    LOGGER.info("Secret variable deleted: '%s' by %s", sv["name"], session["user"])
    return {"ok": True}


@router.get("/api/secret-variables/names")
async def list_secret_variable_names():
    """Return just the names — for template editor autocomplete."""
    variables = await db.get_all_secret_variables()
    return [{"name": v["name"], "description": v.get("description", "")} for v in variables]
