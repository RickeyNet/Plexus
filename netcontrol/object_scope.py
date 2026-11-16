"""Object-level permissions: which inventory groups a user may see and change.

An access group either covers every device (``object_scope='all'``, the
default) or only the inventory groups it grants (``object_scope='groups'``),
each read only or read and write; a grant covers the group and all of its
sub-groups. A user is **unrestricted** when they are an admin, call with the
server API token, or belong to any access group whose scope is ``all``;
otherwise they are **scoped** to the union of their groups' grants (no
grants: they see nothing).

Scope is enforced module by module. A module enforces it by checking every
route of its routers (``require_group``/``require_host``/``require_hosts``
and the ``filter_*`` helpers), marking each route ``@scoped(kind)`` or
``@scope_exempt(reason)``, and listing its routers in
``SCOPE_ENFORCED_ROUTERS``. Until a module does, a scoped user must not reach
it: ``netcontrol.routes.auth._get_user_features`` keeps only the keys in
``SCOPE_ENFORCED_FEATURES`` for a scoped user, so every other feature gate
answers 403, and MCP tokens owned by a scoped user are refused.

Responses: a group or host outside the caller's read scope answers 404 with
the body an unknown id gets (no existence leak); a write to one that is
readable but not writable answers 403 ``READ_ONLY_DETAIL``. A row whose group
id is NULL is visible to unrestricted users only.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import routes.database as db
from fastapi import HTTPException
from starlette.requests import HTTPConnection

from netcontrol.routes.shared import _get_session

# Feature keys a scoped user keeps. Enrolling a module: enforce scope in all
# of its routes, add its feature key (and ``<key>.write`` when the catalog
# has one) here and its routers to ``SCOPE_ENFORCED_ROUTERS``. Intended
# configuration shares the ``config-drift`` feature.
SCOPE_ENFORCED_FEATURES: frozenset[str] = frozenset(
    {
        "inventory",
        "inventory.write",
        "config-backups",
        "config-backups.write",
        "config-drift",
        "config-drift.write",
        # Credentials are per owner and hold no host or inventory group data;
        # device actions in the modules above need one.
        "credentials",
        "credentials.write",
        # GraphQL resolvers filter hosts and groups by the caller's scope.
        "graphql",
    }
)

# Every router registered under a feature in SCOPE_ENFORCED_FEATURES, as
# ``"module:attribute"``, plus the config drift WebSocket router (registered
# without HTTP dependencies; its handlers check the feature and the scope
# themselves). The completeness test (tests/test_object_scope_api.py)
# requires each of their HTTP and WebSocket routes to carry ``@scoped`` or
# ``@scope_exempt``. Admin routers are not listed: admins are unrestricted.
SCOPE_ENFORCED_ROUTERS: tuple[str, ...] = (
    "netcontrol.routes.inventory:router",
    "netcontrol.routes.custom_fields:inventory_router",
    "netcontrol.routes.device_model:inventory_router",
    "netcontrol.routes.ansible_inventory:router",
    "netcontrol.routes.config_backups:router",
    "netcontrol.routes.config_drift:router",
    "netcontrol.routes.config_drift:ws_router",
    "netcontrol.routes.intended_config:router",
    "netcontrol.routes.credentials:router",
    "netcontrol.routes.graphql:router",
)

READ_ONLY_DETAIL = "Read-only access to this inventory group"
GROUP_NOT_FOUND = "Group not found"
HOST_NOT_FOUND = "Host not found"
# Why an MCP token is refused (and the 403 for routes that refuse scoped users).
MCP_SCOPED_DETAIL = (
    "AI access is not available to accounts limited to selected inventory groups: "
    "the token's owner has object-level restrictions"
)
SCOPED_REFUSED_DETAIL = "Not available to accounts limited to selected inventory groups"


@dataclass(frozen=True)
class ObjectScope:
    """The inventory groups a caller may read and write (ids expanded with
    their sub-groups); ``unrestricted`` callers may read and write all."""

    unrestricted: bool
    read_groups: frozenset[int] = field(default_factory=frozenset)
    write_groups: frozenset[int] = field(default_factory=frozenset)

    @property
    def restricted(self) -> bool:
        return not self.unrestricted

    def can_read_group(self, group_id: int | None) -> bool:
        if self.unrestricted:
            return True
        return group_id is not None and int(group_id) in self.read_groups

    def can_write_group(self, group_id: int | None) -> bool:
        if self.unrestricted:
            return True
        return group_id is not None and int(group_id) in self.write_groups

    def filter_groups(self, groups: list[dict], key: str = "id") -> list[dict]:
        """The groups (rows with the group id under ``key``) the caller may read."""
        if self.unrestricted:
            return groups
        return [g for g in groups if self.can_read_group(g.get(key))]

    def filter_hosts(self, hosts: list[dict], key: str = "group_id") -> list[dict]:
        """The hosts (rows with their group id under ``key``) the caller may read."""
        if self.unrestricted:
            return hosts
        return [h for h in hosts if self.can_read_group(h.get(key))]

    def status(self) -> dict:
        """The ``object_scope`` of ``/api/auth/status`` and the login response."""
        return {
            "restricted": self.restricted,
            "write_group_ids": [] if self.unrestricted else sorted(self.write_groups),
        }


UNRESTRICTED = ObjectScope(unrestricted=True)
# A scoped caller with no grants: sees nothing.
NO_ACCESS = ObjectScope(unrestricted=False)


async def scope_for_user(user: dict | None, *, token: bool = False) -> ObjectScope:
    """The scope of ``user`` (a ``users`` row). ``token``: the caller used the
    server API token (unrestricted). No user: nothing is visible."""
    if token:
        return UNRESTRICTED
    if not user:
        return NO_ACCESS
    if user.get("role") == "admin":
        return UNRESTRICTED
    data = await db.get_user_object_scope(int(user["id"]))
    if data["unrestricted"]:
        return UNRESTRICTED
    return ObjectScope(
        unrestricted=False,
        read_groups=frozenset(int(g) for g in data["read_group_ids"]),
        write_groups=frozenset(int(g) for g in data["write_group_ids"]),
    )


async def _session_scope(session: dict, cached_user: Any = None) -> ObjectScope:
    if session.get("auth_mode") == "token":
        return UNRESTRICTED
    user_id = session.get("user_id")
    if user_id is None:
        return NO_ACCESS
    user = cached_user
    if not isinstance(user, dict) or int(user.get("id") or -1) != int(user_id):
        user = await db.get_user_by_id(int(user_id))
    return await scope_for_user(user)


async def request_scope(request: Any) -> ObjectScope:
    """The scope of the caller of an HTTP request, resolved once per request
    and cached on ``request.state`` (next to ``auth_session``/``auth_user``).

    The identity is the session ``require_auth`` resolved for this request
    (an API token is unrestricted). A real request with no session is
    refused everything. An object that is not a request (a route function
    called directly) and carries no session cookie counts as the API token,
    as ``shared.require_owner_or_admin`` does.
    """
    if not isinstance(request, HTTPConnection):
        session = _get_session(request) if hasattr(request, "cookies") else None
        return UNRESTRICTED if session is None else await _session_scope(session)
    cached = getattr(request.state, "object_scope", None)
    if isinstance(cached, ObjectScope):
        return cached
    session = getattr(request.state, "auth_session", None) or _get_session(request)
    if not session:
        scope = NO_ACCESS
    else:
        scope = await _session_scope(session, getattr(request.state, "auth_user", None))
    request.state.object_scope = scope
    return scope


async def ws_scope(session: dict) -> ObjectScope:
    """The scope of a WebSocket caller (``session`` from ``verify_ws_session``)."""
    if not session:
        return NO_ACCESS
    return await _session_scope(session)


def _check(scope: ObjectScope, group_id: int | None, *, write: bool, not_found: str) -> None:
    if not scope.can_read_group(group_id):
        raise HTTPException(status_code=404, detail=not_found)
    if write and not scope.can_write_group(group_id):
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)


async def require_group(request: Any, group_id: int, *, write: bool = False, not_found: str = GROUP_NOT_FOUND) -> dict:
    """The inventory group row; 404 ``not_found`` when unknown or outside the
    caller's read scope, 403 on ``write`` when it is not writable. A route
    whose unknown group answers another message passes it as ``not_found``."""
    group = await db.get_group(int(group_id))
    if not group:
        raise HTTPException(status_code=404, detail=not_found)
    _check(await request_scope(request), group["id"], write=write, not_found=not_found)
    return group


async def require_host(request: Any, host_id: int, *, write: bool = False, not_found: str = HOST_NOT_FOUND) -> dict:
    """The host row; 404 ``not_found`` when unknown or outside the caller's
    read scope, 403 on ``write`` when its group is not writable."""
    host = await db.get_host(int(host_id))
    if not host:
        raise HTTPException(status_code=404, detail=not_found)
    _check(await request_scope(request), host.get("group_id"), write=write, not_found=not_found)
    return host


async def require_hosts(
    request: Any, host_ids: Iterable[int], *, write: bool = False, not_found: str = HOST_NOT_FOUND
) -> list[dict]:
    """The host rows of ``host_ids`` (duplicates removed). For an
    unrestricted caller unknown ids are skipped; for a scoped caller every
    id must be readable (else 404 ``not_found``, naming none) and, on
    ``write``, writable (else 403)."""
    ids = list(dict.fromkeys(int(h) for h in host_ids))
    hosts = await db.get_hosts_by_ids(ids)
    scope = await request_scope(request)
    if scope.unrestricted:
        return hosts
    if len(hosts) != len(ids):
        raise HTTPException(status_code=404, detail=not_found)
    for host in hosts:
        _check(scope, host.get("group_id"), write=write, not_found=not_found)
    return hosts


async def require_object_host(request: Any, host_id: int | None, *, not_found: str, write: bool = False) -> None:
    """For a record addressed by its own id (a backup, a baseline, a
    snapshot, a drift event) that belongs to host ``host_id``: 404
    ``not_found`` (the answer an unknown record id gets) when the host is
    unknown, ``None`` or outside the caller's read scope; 403 on ``write``
    when its group is not writable. Nothing is read for an unrestricted
    caller."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return
    host = await db.get_host(int(host_id)) if host_id is not None else None
    _check(scope, host.get("group_id") if host else None, write=write, not_found=not_found)


async def group_filter(request: Any, *, write: bool = False) -> dict[str, frozenset[int]]:
    """Keyword arguments for the ``routes.db`` readers that take
    ``group_ids`` (keep only rows of hosts in those inventory groups): ``{}``
    for an unrestricted caller, so the reader runs exactly as before; else
    ``{"group_ids": <the readable (on ``write``: writable) groups>}``."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return {}
    return {"group_ids": scope.write_groups if write else scope.read_groups}


async def refuse_scoped(request: Any) -> None:
    """403 for a scoped caller: for actions that cannot be confined to the
    caller's inventory groups."""
    if (await request_scope(request)).restricted:
        raise HTTPException(status_code=403, detail=SCOPED_REFUSED_DETAIL)


# ── Route markers ─────────────────────────────────────────────────────────────

_MARKER = "__plexus_object_scope__"
_F = TypeVar("_F", bound=Callable[..., Any])


def scoped(kind: str) -> Callable[[_F], _F]:
    """Mark a route as checking object scope. ``kind`` names how (``group``,
    ``host``, ``hosts``, ``list``, ``create``, ``refused`` ...); the GET
    sweep test drives every scoped GET route with a ``group_id`` or
    ``host_id`` path parameter with an out-of-scope id."""
    if not kind:
        raise ValueError("scoped() needs a kind")

    def mark(fn: _F) -> _F:
        setattr(fn, _MARKER, ("scoped", kind))
        return fn

    return mark


def scope_exempt(reason: str) -> Callable[[_F], _F]:
    """Mark a route as returning and changing no host or inventory group data."""
    if not reason or not reason.strip():
        raise ValueError("scope_exempt() needs a reason")

    def mark(fn: _F) -> _F:
        setattr(fn, _MARKER, ("exempt", reason))
        return fn

    return mark


def scope_marker(endpoint: Callable[..., Any]) -> tuple[str, str] | None:
    """``("scoped", kind)``, ``("exempt", reason)`` or None for an unmarked route."""
    marker = getattr(endpoint, _MARKER, None)
    return marker if isinstance(marker, tuple) else None


def enforced_routers() -> list[Any]:
    """The router objects named in ``SCOPE_ENFORCED_ROUTERS``."""
    routers = []
    for ref in SCOPE_ENFORCED_ROUTERS:
        module_name, attr = ref.split(":", 1)
        routers.append(getattr(importlib.import_module(module_name), attr))
    return routers


def enforced_features(features: Iterable[str]) -> list[str]:
    """``features`` without the keys a scoped user may not use (order kept)."""
    return [f for f in features if f in SCOPE_ENFORCED_FEATURES]
