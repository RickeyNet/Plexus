"""Provider settings and the one place external references are resolved.

``materialize_credential`` (called by ``routes.db.credentials
.get_credential_raw`` and ``netcontrol.routes.shared
.require_credential_access``) and ``secret_variable_plaintext`` (called by
``routes.secret_resolver``) are the choke points: every consumer that reads
a credential or a ``{{secret.NAME}}`` value goes through them, so none needs
code of its own for external secrets.

A credential with a reference comes back with ``password`` and ``secret``
encrypted afresh from the resolved values, so consumers keep calling
``routes.crypto.decrypt``. When resolution fails (and the caller did not ask
for ``strict``), both hold a ``routes.crypto.unavailable`` stand-in and
``decrypt`` raises ``RuntimeError`` with the reason at the point of use: an
SNMP poll that never opens SSH is not stopped by a Vault outage.

Every failure is logged and audited (``secrets_providers`` /
``secrets_provider.resolve_failed``); a repeat of the same failure for the
same reference within ``FAILURE_AUDIT_INTERVAL`` seconds is logged only, so
a poll loop cannot flood the audit chain. Values are never logged, audited
or returned by the API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import routes.database as db
from routes.crypto import decrypt, encrypt, unavailable

from netcontrol.secrets_providers.aws import AwsSecretsManagerProvider
from netcontrol.secrets_providers.azure import AzureKeyVaultProvider
from netcontrol.secrets_providers.base import (
    DISABLED,
    INVALID_CONFIG,
    INVALID_REFERENCE,
    PROVIDER_MISSING,
    SDK_NOT_INSTALLED,
    SecretsProvider,
    SecretsProviderError,
    TTLCache,
    check_reference,
    invalidate,
)
from netcontrol.secrets_providers.vault import VaultProvider

LOGGER = logging.getLogger("plexus.secrets_providers")

PROVIDER_CLASSES: dict[str, type[SecretsProvider]] = {
    cls.provider_type: cls for cls in (VaultProvider, AwsSecretsManagerProvider, AzureKeyVaultProvider)
}
CACHE_TTL_MAX = 3600
FAILURE_AUDIT_INTERVAL = 300
_FAILURES_AUDITED = TTLCache(max_entries=512)

__all__ = [
    "PROVIDER_CLASSES",
    "SecretsProviderError",
    "build_provider",
    "invalidate",
    "materialize_credential",
    "prepare_provider",
    "provider_types",
    "public_provider",
    "resolve_reference",
    "sdk_status",
    "secret_variable_plaintext",
]


def provider_class(provider_type: str) -> type[SecretsProvider]:
    cls = PROVIDER_CLASSES.get(provider_type)
    if cls is None:
        raise ValueError(f"provider_type must be one of: {', '.join(sorted(PROVIDER_CLASSES))}")
    return cls


def decode_secrets(secret_enc: str) -> dict[str, str]:
    """The provider's own auth secrets from their stored ciphertext."""
    if not secret_enc:
        return {}
    data = json.loads(decrypt(secret_enc))
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def prepare_provider(provider_type: str, config: Any, secrets: Any, stored_secret_enc: str = "") -> tuple[dict, str]:
    """Validate a create or update: ``(config, secret_enc)`` to store.

    A secret left out or blank keeps the stored one; secrets the settings
    do not use (a Vault token after a switch to AppRole) are dropped.
    Raises ``ValueError`` with the reason."""
    cls = provider_class(provider_type)
    if secrets is None:
        secrets = {}
    if not isinstance(secrets, dict):
        raise ValueError("secrets must be an object")
    merged = {k: v for k, v in decode_secrets(stored_secret_enc).items() if k in cls.SECRETS}
    for name, value in secrets.items():
        if name not in cls.SECRETS:
            raise ValueError(f"Unknown secret '{name}' for {cls.label}")
        if value in (None, ""):
            continue
        if not isinstance(value, str) or len(value) > 65536:
            raise ValueError(f"{name} must be text of at most 65536 characters")
        merged[name] = value
    normalized = cls.validate(config if isinstance(config, dict) else {}, merged)
    kept = {k: v for k, v in merged.items() if k in cls.used_secrets(normalized)}
    return normalized, encrypt(json.dumps(kept, sort_keys=True)) if kept else ""


def build_provider(row: dict) -> SecretsProvider:
    """The provider object for a stored row (with ``secret_enc``)."""
    cls = provider_class(str(row["provider_type"]))
    try:
        config = json.loads(row.get("config_json") or "{}")
        secrets = decode_secrets(str(row.get("secret_enc") or ""))
    except (ValueError, RuntimeError) as exc:
        raise SecretsProviderError(
            INVALID_CONFIG, f"{row['name']}: the stored settings cannot be read; save the provider again"
        ) from exc
    return cls(
        config,
        secrets,
        provider_id=int(row["id"]),
        version=str(row.get("updated_at") or ""),
        cache_ttl=int(row.get("cache_ttl") or 0),
        name=str(row["name"]),
    )


def sdk_status(provider_type: str, config: dict) -> dict:
    """``{"status": "ok" | "sdk_not_installed", "missing": [dist, ...]}``."""
    missing = provider_class(provider_type).sdk_missing(config)
    return {"status": SDK_NOT_INSTALLED if missing else "ok", "missing": missing}


def provider_types() -> list[dict]:
    """The supported types with their settings, secrets and SDK needs."""
    out = []
    for key, cls in sorted(PROVIDER_CLASSES.items()):
        out.append(
            {
                "type": key,
                "label": cls.label,
                "settings": [{"name": s.name, "kind": s.kind, "default": s.default} for s in cls.SETTINGS],
                "secrets": list(cls.SECRETS),
                "sdk": {
                    "status": SDK_NOT_INSTALLED if cls.sdk_missing({"auth_method": "default"}) else "ok",
                    "missing": cls.sdk_missing({"auth_method": "default"}),
                },
            }
        )
    return out


def public_provider(row: dict) -> dict:
    """A provider row as the API shows it: settings, the names of the
    stored secrets (never their values), usage counts and SDK status."""
    try:
        config = json.loads(row.get("config_json") or "{}")
    except ValueError:
        config = {}
    out = {k: v for k, v in row.items() if k not in ("config_json", "secret_enc")}
    out["enabled"] = bool(row.get("enabled"))
    out["allow_user_credentials"] = bool(row.get("allow_user_credentials"))
    out["config"] = config
    if "secret_enc" in row:
        try:
            out["secrets_set"] = sorted(decode_secrets(str(row.get("secret_enc") or "")))
        except ValueError, RuntimeError:
            out["secrets_set"] = []
    out["sdk"] = sdk_status(str(row["provider_type"]), config)
    return out


async def _audit_failure(provider_id: int, context: str, exc: SecretsProviderError, actor: str) -> None:
    LOGGER.warning("External secret resolution failed: provider=%s %s code=%s", provider_id, context, exc.code)
    throttle_key = (provider_id, context, exc.code)
    if _FAILURES_AUDITED.get(throttle_key):
        return
    _FAILURES_AUDITED.set(throttle_key, True, FAILURE_AUDIT_INTERVAL)
    from netcontrol.routes.shared import _audit

    await _audit(
        "secrets_providers",
        "secrets_provider.resolve_failed",
        user=actor or "system",
        detail=f"provider_id={provider_id} {context} code={exc.code}: {exc.message}",
    )


async def resolve_reference(
    provider_id: int,
    path: str,
    key: str = "",
    *,
    context: str = "",
    actor: str = "",
    use_cache: bool = True,
) -> str:
    """The value a reference points at. Raises ``SecretsProviderError``
    (audited) when it cannot be resolved."""
    try:
        try:
            reference = check_reference(path, key)
        except ValueError as exc:
            raise SecretsProviderError(INVALID_REFERENCE, str(exc)) from exc
        row = await db.get_secrets_provider(int(provider_id), with_secret=True)
        if not row:
            raise SecretsProviderError(PROVIDER_MISSING, f"Secrets provider {provider_id} does not exist")
        if not row.get("enabled"):
            raise SecretsProviderError(DISABLED, f"{row['name']}: the provider is disabled")
        return await build_provider(row).resolve(reference, use_cache=use_cache)
    except SecretsProviderError as exc:
        await _audit_failure(int(provider_id or 0), context, exc, actor)
        raise


async def materialize_credential(row: dict | None, *, strict: bool = False, actor: str = "") -> dict | None:
    """``row`` with ``password``/``secret`` encrypted from its external
    reference (unchanged when it has none).

    ``strict`` raises ``SecretsProviderError`` on failure; otherwise both
    fields hold an ``unavailable`` stand-in that ``decrypt`` refuses."""
    if not row or not row.get("ext_provider_id"):
        return row
    out = dict(row)
    provider_id = int(row["ext_provider_id"])
    context = f"credential_id={row.get('id')}"
    try:
        password = await resolve_reference(
            provider_id, row.get("ext_path") or "", row.get("ext_key") or "", context=context, actor=actor
        )
        secret_key = row.get("ext_secret_key") or ""
        secret = (
            await resolve_reference(provider_id, row.get("ext_path") or "", secret_key, context=context, actor=actor)
            if secret_key
            else password
        )
    except SecretsProviderError as exc:
        if strict:
            raise
        reason = f"The external secret of credential {row.get('id')} could not be resolved: {exc.message}"
        out["password"] = out["secret"] = unavailable(reason)
        return out
    out["password"] = encrypt(password)
    out["secret"] = encrypt(secret)
    return out


async def secret_variable_plaintext(row: dict, *, actor: str = "") -> str:
    """The value of a secret variable row: its external reference resolved,
    or its stored ciphertext decrypted. Raises ``SecretsProviderError``."""
    if row.get("ext_provider_id"):
        return await resolve_reference(
            int(row["ext_provider_id"]),
            row.get("ext_path") or "",
            row.get("ext_key") or "",
            context=f"secret_variable_id={row.get('id')}",
            actor=actor,
        )
    return decrypt(row.get("enc_value") or "")


async def reference_provider(provider_id: Any, *, personal: bool) -> dict:
    """The provider a new reference names. Raises ``LookupError`` when it
    does not exist and ``PermissionError`` when ``personal`` (a non-admin's
    own credential) and the provider is not open to personal credentials."""
    try:
        pid = int(provider_id)
    except TypeError, ValueError:
        raise LookupError("Secrets provider not found") from None
    row = await db.get_secrets_provider(pid)
    if not row:
        raise LookupError("Secrets provider not found")
    if personal and not row.get("allow_user_credentials"):
        raise PermissionError("This secrets provider is not open to personal credentials; ask an admin")
    return row
