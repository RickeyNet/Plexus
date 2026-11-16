"""Plugin manifest API and the mounting of plugin routers.

- ``GET /api/plugins`` (any signed-in user): the plugins the caller may use,
  with their navigation and declarative pages, for the frontend to render.
  Admins (and API-token callers) get every plugin, including disabled and
  failed ones, with status, source, version bounds and errors.
- Each registered plugin's router is mounted at ``/api/plugins/<name>`` with
  the core auth dependencies: a signed-in session, the plugin's feature key
  ``plugin:<name>`` (``plugin:<name>.write`` for POST/PUT/PATCH/DELETE; admins
  and API tokens pass), and a gate that answers 503 until the plugin is
  ``active`` (and 404 once it is no longer registered).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request

from netcontrol.plugins.registry import STATUS_ACTIVE, PluginRecord, PluginRegistry, registry
from netcontrol.routes.auth import _get_user_features
from netcontrol.routes.shared import _get_session

router = APIRouter()

# app id -> {plugin name -> id(router)} of what has been mounted, so a second
# mount call (tests, a late registration) never adds a router twice.
_mounted: dict[int, dict[str, int]] = {}


def _plugin_gate(name: str, plugins: PluginRegistry) -> Callable:
    async def _dependency() -> None:
        record = plugins.get(name)
        if record is None or record.plugin is None:
            raise HTTPException(status_code=404, detail=f"Plugin '{name}' is not installed")
        if record.status != STATUS_ACTIVE:
            raise HTTPException(status_code=503, detail=f"Plugin '{name}' is {record.status}")

    return _dependency


def mount_plugin_routers(
    app: FastAPI,
    feature_dependency: Callable[[str], Callable],
    plugins: PluginRegistry = registry,
) -> list[str]:
    """Include every registered plugin router not yet mounted on ``app``.

    ``feature_dependency`` is app.py's ``require_feature_method`` (it also
    enforces the session). Returns the names mounted by this call."""
    done = _mounted.setdefault(id(app), {})
    mounted: list[str] = []
    for record in plugins.records():
        plugin = record.plugin
        if plugin is None or plugin.router is None:
            continue
        if record.name in done:
            continue
        app.include_router(
            plugin.router,
            prefix=f"/api/plugins/{record.name}",
            dependencies=[
                Depends(feature_dependency(record.feature_key)),
                Depends(_plugin_gate(record.name, plugins)),
            ],
        )
        done[record.name] = id(plugin.router)
        mounted.append(record.name)
    return mounted


async def _caller(request: Request) -> tuple[bool, set[str]]:
    """(is admin, feature keys) of the authenticated caller."""
    session = _get_session(request)
    if session is None or session.get("auth_mode") == "token":
        # require_auth already passed, so no cookie means the API token:
        # admin-equivalent by design.
        return True, set()
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="Session user not found")
    if user.get("role") == "admin":
        return True, set()
    return False, set(await _get_user_features(user))


def _public_entry(record: PluginRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "label": record.label or record.name,
        "version": record.version,
        "description": record.description,
        "status": record.status,
        "feature": record.feature_key,
        "navigation": [n.model_dump() for n in record.navigation],
        "pages": [p.model_dump() for p in record.pages],
    }


def _admin_entry(record: PluginRecord) -> dict[str, Any]:
    plugin = record.plugin
    return {
        **_public_entry(record),
        "source": record.source,
        "min_plexus_version": record.min_plexus_version,
        "max_plexus_version": record.max_plexus_version,
        "errors": list(record.errors),
        "has_router": bool(plugin is not None and plugin.router is not None),
        "migrations": plugin.migrations if plugin is not None else None,
        "migrations_applied": record.migrations_applied,
        "background_tasks": len(record.tasks),
    }


def build_manifest(plugins: PluginRegistry, *, is_admin: bool, features: set[str]) -> dict[str, Any]:
    if is_admin:
        return {"admin": True, "plugins": [_admin_entry(r) for r in plugins.records()]}
    visible = [_public_entry(r) for r in plugins.records() if r.status == STATUS_ACTIVE and r.feature_key in features]
    return {"admin": False, "plugins": visible}


@router.get("/api/plugins")
async def list_plugins(request: Request) -> dict[str, Any]:
    is_admin, features = await _caller(request)
    return build_manifest(registry, is_admin=is_admin, features=features)
