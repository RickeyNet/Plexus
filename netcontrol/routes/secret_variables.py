"""
secret_variables.py - CRUD routes for encrypted secret variables.

Secret variables are referenced in config templates via {{secret.NAME}}
and resolved at job execution time.  Values are AES-256-GCM encrypted at rest,
or live in an external secrets provider (``external``: provider, path, key;
docs/secrets-providers.md).  Only admins can create/update/delete secret
variables; values are never returned.
"""

from __future__ import annotations

import re

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from routes.crypto import encrypt
from routes.secret_resolver import normalize_secret_name

from netcontrol.routes.shared import _audit, _corr_id, admin_session
from netcontrol.secrets_providers.base import check_reference
from netcontrol.secrets_providers.service import reference_provider
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.secret_variables")

router = APIRouter()


# ── Validation ────────────────────────────────────────────────────────────────

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


def _validate_name(name: str) -> str:
    name = normalize_secret_name(name)
    if not _NAME_RE.fullmatch(name):
        raise HTTPException(
            400,
            f"Invalid secret name '{name}'. Enter just the name (e.g. "
            "snmp_v3_auth_key, not {{secret.snmp_v3_auth_key}}): it must start "
            "with a letter or underscore, contain only letters, digits, "
            "underscore or hyphen, and be 1-64 characters.",
        )
    return name


# ── Pydantic models ──────────────────────────────────────────────────────────


class ExternalSecretReference(BaseModel):
    provider_id: int
    path: str
    key: str = ""


class SecretVariableCreate(BaseModel):
    name: str
    value: str = ""
    description: str = ""
    external: ExternalSecretReference | None = None


class SecretVariableUpdate(BaseModel):
    """A new ``value`` replaces an external reference; ``external``
    replaces the stored value."""

    value: str | None = None
    description: str | None = None
    external: ExternalSecretReference | None = None


async def _checked_reference(ref: ExternalSecretReference) -> dict:
    """The reference as stored; 400 for a bad path or key, 404 for an
    unknown provider."""
    try:
        check_reference(ref.path, ref.key)
        await reference_provider(ref.provider_id, personal=False)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"provider_id": ref.provider_id, "path": ref.path.strip(), "key": ref.key.strip()}


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/api/secret-variables")
async def list_secret_variables(request: Request):
    """Return all secret variable metadata (names, descriptions - never values).

    Admin-only: even though values are never returned, leaking the set of
    variable names exposes which integrations and external services are
    wired up, which is information a regular user shouldn't need.
    """
    await admin_session(request)
    return await db.get_all_secret_variables()


# Registered before /{var_id} so the literal `names` segment matches first;
# otherwise FastAPI tries the int-typed {var_id} route first, fails Pydantic
# validation on the string, and returns 422.
@router.get("/api/secret-variables/names")
async def list_secret_variable_names(request: Request):
    """Return just the names - for template editor autocomplete.

    Admin-only for the same reason as list_secret_variables.
    """
    await admin_session(request)
    variables = await db.get_all_secret_variables()
    return [{"name": v["name"], "description": v.get("description", "")} for v in variables]


@router.get("/api/secret-variables/{var_id}")
async def get_secret_variable(var_id: int, request: Request):
    """Return metadata for a single secret variable (never the value)."""
    await admin_session(request)
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")
    return sv


@router.post("/api/secret-variables", status_code=201)
async def create_secret_variable(body: SecretVariableCreate, request: Request):
    """Create a new secret variable. Requires admin role."""
    session = await admin_session(request)
    name = _validate_name(body.name)
    external = await _checked_reference(body.external) if body.external is not None else None
    if not body.value and external is None:
        raise HTTPException(400, "Value must not be empty")

    # Check for duplicate name
    existing = await db.get_secret_variable_by_name(name)
    if existing:
        raise HTTPException(409, f"Secret variable '{name}' already exists")

    enc_value = "" if external else encrypt(body.value)
    var_id = await db.create_secret_variable(
        name=name,
        enc_value=enc_value,
        description=body.description,
        created_by=session["user"],
        external=external,
    )
    await _audit(
        "config",
        "secret_variable.create",
        user=session["user"],
        detail=f"created secret variable '{name}'"
        + (f" (external reference: provider {external['provider_id']})" if external else ""),
        correlation_id=_corr_id(request),
    )
    # Log neither the name nor the id: CodeQL treats anything returned by
    # create_secret_variable as secret (py/clear-text-logging-sensitive-data).
    # The audit row above records which variable was created.
    LOGGER.info("Secret variable created by %s", session["user"])
    return {"id": var_id, "name": name}


@router.put("/api/secret-variables/{var_id}")
async def update_secret_variable(var_id: int, body: SecretVariableUpdate, request: Request):
    """Update an existing secret variable. Requires admin role."""
    session = await admin_session(request)
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")

    external = await _checked_reference(body.external) if body.external is not None else None
    enc_value = encrypt(body.value) if body.value and external is None else None
    updated = await db.update_secret_variable(
        var_id,
        enc_value=enc_value,
        description=body.description,
        external=external,
    )
    if not updated:
        raise HTTPException(404, "Secret variable not found")

    what = []
    if external is not None:
        what.append(f"external reference: provider {external['provider_id']}")
    elif body.value:
        what.append("value")
    if body.description is not None:
        what.append("description")
    await _audit(
        "config",
        "secret_variable.update",
        user=session["user"],
        detail=f"updated secret variable '{sv['name']}' ({', '.join(what)})",
        correlation_id=_corr_id(request),
    )
    LOGGER.info("Secret variable %s updated by %s", var_id, session["user"])
    return {"ok": True}


@router.delete("/api/secret-variables/{var_id}")
async def delete_secret_variable(var_id: int, request: Request):
    """Delete a secret variable. Requires admin role."""
    session = await admin_session(request)
    sv = await db.get_secret_variable(var_id)
    if not sv:
        raise HTTPException(404, "Secret variable not found")

    await db.delete_secret_variable(var_id)
    await _audit(
        "config",
        "secret_variable.delete",
        user=session["user"],
        detail=f"deleted secret variable '{sv['name']}'",
        correlation_id=_corr_id(request),
    )
    LOGGER.info("Secret variable %s deleted by %s", var_id, session["user"])
    return {"ok": True}
