"""External secrets providers API: HashiCorp Vault, AWS Secrets Manager and
Azure Key Vault (docs/secrets-providers.md).

``router`` is registered in ``app.py`` behind ``require_auth`` and
``require_feature_method("secrets-providers")``: read with
``secrets-providers``, change and test with ``secrets-providers.write``
(admins have both). Object scope: providers are global configuration with
no host data, so accounts limited to selected inventory groups may read
them but never change or test them (403).

A provider's own auth secrets (Vault token or AppRole secret id, AWS secret
access key and session token, Azure client secret) are write-only: they are
stored encrypted with ``routes.crypto``, a blank or missing one on update
keeps the stored value, and reads list only which are set
(``secrets_set``). The test endpoint resolves one reference and answers
success or failure (with the error code and a message naming the provider,
path and key), never the value.

Every change and test is audited (category ``secrets_providers``);
resolution failures are audited by ``netcontrol.secrets_providers.service``.
Errors: 404 unknown provider, 409 a taken name or a delete of a provider
still referenced, 400 bad input.
"""

from __future__ import annotations

import json
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from netcontrol.object_scope import refuse_scoped, scope_exempt, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.secrets_providers.base import SecretsProviderError, invalidate
from netcontrol.secrets_providers.service import (
    CACHE_TTL_MAX,
    prepare_provider,
    provider_types,
    public_provider,
    resolve_reference,
)

router = APIRouter()

API = "/api/secrets-providers"
NAME_MAX = 100
DESCRIPTION_MAX = 500


class ProviderCreate(BaseModel):
    name: str
    provider_type: str
    description: str = ""
    enabled: bool = True
    allow_user_credentials: bool = False
    cache_ttl: int = Field(300, ge=0, le=CACHE_TTL_MAX)
    config: dict[str, Any] = {}
    secrets: dict[str, str | None] = {}


class ProviderUpdate(BaseModel):
    name: str | None = None
    provider_type: str | None = None
    description: str | None = None
    enabled: bool | None = None
    allow_user_credentials: bool | None = None
    cache_ttl: int | None = Field(None, ge=0, le=CACHE_TTL_MAX)
    config: dict[str, Any] | None = None
    secrets: dict[str, str | None] | None = None


class ReferenceTest(BaseModel):
    path: str
    key: str = ""


def _name(value: str) -> str:
    name = (value or "").strip()
    if not 1 <= len(name) <= NAME_MAX:
        raise HTTPException(400, f"The name is 1 to {NAME_MAX} characters")
    return name


def _description(value: str) -> str:
    text = (value or "").strip()
    if len(text) > DESCRIPTION_MAX:
        raise HTTPException(400, f"The description is at most {DESCRIPTION_MAX} characters")
    return text


def _prepared(provider_type: str, config: Any, secrets: Any, stored: str = "") -> tuple[dict, str]:
    try:
        return prepare_provider(provider_type, config, secrets, stored)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


async def _provider(provider_id: int, *, with_secret: bool = False) -> dict:
    row = await db.get_secrets_provider(provider_id, with_secret=with_secret)
    if not row:
        raise HTTPException(404, "Secrets provider not found")
    return row


def _changed_secrets(secrets: dict | None) -> str:
    names = sorted(k for k, v in (secrets or {}).items() if v)
    return f" secrets changed: {', '.join(names)}" if names else ""


async def _audit_change(request: Request, action: str, detail: str) -> None:
    await _audit(
        "secrets_providers",
        f"secrets_provider.{action}",
        user=_session_user(request),
        detail=detail,
        correlation_id=_corr_id(request),
    )


@router.get(API)
@scope_exempt("global provider settings; no host, tenant or site data")
async def list_providers():
    """Every provider (settings, which secrets are set, usage, SDK status)
    and the supported provider types."""
    rows = await db.list_secrets_providers(with_secret=True)
    return {"providers": [public_provider(r) for r in rows], "types": provider_types()}


@router.get(API + "/{provider_id}")
@scope_exempt("global provider settings; no host, tenant or site data")
async def get_provider(provider_id: int):
    return public_provider(await _provider(provider_id, with_secret=True))


@router.post(API, status_code=201)
@scoped("refused")
async def create_provider(body: ProviderCreate, request: Request):
    await refuse_scoped(request)
    name = _name(body.name)
    config, secret_enc = _prepared(body.provider_type, body.config, body.secrets)
    fields = {
        "name": name,
        "provider_type": body.provider_type,
        "description": _description(body.description),
        "enabled": int(body.enabled),
        "allow_user_credentials": int(body.allow_user_credentials),
        "cache_ttl": body.cache_ttl,
        "config_json": json.dumps(config, sort_keys=True),
        "secret_enc": secret_enc,
    }
    try:
        provider_id = await db.create_secrets_provider(fields, _session_user(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    await _audit_change(
        request,
        "create",
        f"created secrets provider '{name}' (id={provider_id}, type={body.provider_type})"
        + _changed_secrets(body.secrets),
    )
    return {"id": provider_id}


@router.put(API + "/{provider_id}")
@scoped("refused")
async def update_provider(provider_id: int, body: ProviderUpdate, request: Request):
    await refuse_scoped(request)
    row = await _provider(provider_id, with_secret=True)
    if body.provider_type is not None and body.provider_type != row["provider_type"]:
        raise HTTPException(400, "The provider type cannot change; create a new provider")
    fields: dict[str, Any] = {}
    if body.name is not None:
        fields["name"] = _name(body.name)
    if body.description is not None:
        fields["description"] = _description(body.description)
    if body.enabled is not None:
        fields["enabled"] = int(body.enabled)
    if body.allow_user_credentials is not None:
        fields["allow_user_credentials"] = int(body.allow_user_credentials)
    if body.cache_ttl is not None:
        fields["cache_ttl"] = body.cache_ttl
    if body.config is not None or body.secrets is not None:
        stored_config = json.loads(row.get("config_json") or "{}")
        config, secret_enc = _prepared(
            row["provider_type"],
            body.config if body.config is not None else stored_config,
            body.secrets,
            str(row.get("secret_enc") or ""),
        )
        fields["config_json"] = json.dumps(config, sort_keys=True)
        fields["secret_enc"] = secret_enc
    try:
        await db.update_secrets_provider(provider_id, fields, _session_user(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    invalidate(provider_id)
    changed = ", ".join(sorted(k for k in fields if k != "secret_enc")) or "nothing"
    await _audit_change(
        request,
        "update",
        f"updated secrets provider '{fields.get('name', row['name'])}' (id={provider_id}): {changed}"
        + _changed_secrets(body.secrets),
    )
    return {"ok": True}


@router.delete(API + "/{provider_id}")
@scoped("refused")
async def delete_provider(provider_id: int, request: Request):
    await refuse_scoped(request)
    row = await _provider(provider_id)
    try:
        await db.delete_secrets_provider(provider_id)
    except db.ProviderInUseError as exc:
        raise HTTPException(409, str(exc)) from exc
    invalidate(provider_id)
    await _audit_change(request, "delete", f"deleted secrets provider '{row['name']}' (id={provider_id})")
    return {"ok": True}


@router.post(API + "/{provider_id}/test")
@scoped("refused")
async def test_reference(provider_id: int, body: ReferenceTest, request: Request):
    """Resolve one reference without the cache. Success or failure only:
    the value is never returned or logged."""
    await refuse_scoped(request)
    row = await _provider(provider_id)
    try:
        await resolve_reference(
            provider_id,
            body.path,
            body.key,
            context="test",
            actor=_session_user(request),
            use_cache=False,
        )
    except SecretsProviderError as exc:
        await _audit_change(
            request, "test", f"tested secrets provider '{row['name']}' (id={provider_id}): failed ({exc.code})"
        )
        return {"ok": False, "code": exc.code, "message": exc.message}
    await _audit_change(request, "test", f"tested secrets provider '{row['name']}' (id={provider_id}): ok")
    return {"ok": True}
