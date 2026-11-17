"""External secrets providers storage (migration 0106).

Star re-exported by routes/database.py. A provider row keeps its non-secret
settings in ``config_json`` and its own auth secrets in ``secret_enc``
(encrypted by the caller with ``routes.crypto``); reads leave ``secret_enc``
out unless ``with_secret=True``. A provider referenced by a credential or a
secret variable cannot be deleted (``ProviderInUseError``, the API's 409).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list
from routes.db.custom_fields import _now

__all__ = [
    "ProviderInUseError",
    "count_secrets_provider_usage",
    "create_secrets_provider",
    "delete_secrets_provider",
    "get_secrets_provider",
    "list_secrets_providers",
    "update_secrets_provider",
]

_PUBLIC_COLUMNS = (
    "id, name, provider_type, description, enabled, allow_user_credentials, cache_ttl, config_json, "
    "created_by, created_at, updated_at, updated_by"
)
_USAGE_COLUMNS = (
    "(SELECT COUNT(*) FROM credentials c WHERE c.ext_provider_id = p.id) AS credential_count, "
    "(SELECT COUNT(*) FROM secret_variables v WHERE v.ext_provider_id = p.id) AS secret_variable_count"
)
# Columns a create or update may set (the rest are stamps).
_WRITABLE = (
    "name",
    "provider_type",
    "description",
    "enabled",
    "allow_user_credentials",
    "cache_ttl",
    "config_json",
    "secret_enc",
)


class ProviderInUseError(ValueError):
    """The provider is referenced by credentials or secret variables."""


async def list_secrets_providers(*, with_secret: bool = False) -> list[dict]:
    """Every provider with usage counts; ``secret_enc`` only with ``with_secret``."""
    columns = f"{_PUBLIC_COLUMNS}, secret_enc" if with_secret else _PUBLIC_COLUMNS
    conn = await _dbcore.get_db(read_only=True)
    try:
        cursor = await conn.execute(
            f"SELECT {columns}, {_USAGE_COLUMNS} FROM secrets_providers p ORDER BY lower(name)"  # nosec B608 - fixed column lists
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


async def get_secrets_provider(provider_id: int, *, with_secret: bool = False) -> dict | None:
    """One provider; ``secret_enc`` only with ``with_secret``."""
    columns = f"{_PUBLIC_COLUMNS}, secret_enc" if with_secret else _PUBLIC_COLUMNS
    conn = await _dbcore.get_db(read_only=True)
    try:
        cursor = await conn.execute(
            f"SELECT {columns}, {_USAGE_COLUMNS} FROM secrets_providers p WHERE id = ?",  # nosec B608 - fixed column lists
            (provider_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def count_secrets_provider_usage(provider_id: int) -> dict[str, int]:
    """How many credentials and secret variables reference the provider."""
    row = await get_secrets_provider(provider_id)
    if not row:
        return {"credentials": 0, "secret_variables": 0}
    return {"credentials": int(row["credential_count"]), "secret_variables": int(row["secret_variable_count"])}


async def create_secrets_provider(fields: dict, user: str = "") -> int:
    """Insert a provider. Raises ``ValueError`` for a taken name."""
    values = {k: fields[k] for k in _WRITABLE if k in fields}
    now = _now()
    values.update(created_by=user, updated_by=user, created_at=now, updated_at=now)
    columns = list(values)
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            f"INSERT INTO secrets_providers ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)}) "  # nosec B608 - fixed column names
            "RETURNING id",
            tuple(values[c] for c in columns),
        )
        await conn.commit()
        return int(cursor.lastrowid)
    except Exception as exc:
        await conn.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"A secrets provider named '{fields.get('name')}' already exists") from exc
        raise
    finally:
        await conn.close()


async def update_secrets_provider(provider_id: int, fields: dict, user: str = "") -> bool:
    """Update the given columns. Raises ``ValueError`` for a taken name."""
    updates = [f"{k} = ?" for k in _WRITABLE if k in fields]
    args = [fields[k] for k in _WRITABLE if k in fields]
    updates += ["updated_by = ?", "updated_at = ?"]
    args += [user, _now()]
    sql, params = _safe_dynamic_update("secrets_providers", updates, args, "id = ?", provider_id)
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(sql, params)
        await conn.commit()
        return cursor.rowcount > 0
    except Exception as exc:
        await conn.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"A secrets provider named '{fields.get('name')}' already exists") from exc
        raise
    finally:
        await conn.close()


async def delete_secrets_provider(provider_id: int) -> bool:
    """Delete a provider. Raises ``ProviderInUseError`` while referenced."""
    usage = await count_secrets_provider_usage(provider_id)
    if usage["credentials"] or usage["secret_variables"]:
        raise ProviderInUseError(
            f"The provider is used by {usage['credentials']} credential(s) and "
            f"{usage['secret_variables']} secret variable(s); point them elsewhere first"
        )
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute("DELETE FROM secrets_providers WHERE id = ?", (provider_id,))
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()
