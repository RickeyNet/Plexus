"""Structured object-change events.

Audit events carry free text (``detail``), so nothing downstream can tell
reliably which object changed or how. This module gives the DB facade a
structured event instead: the mutation helpers of the tracked object types
are wrapped with ``tracks_changes``, which reads the row before and after the
call and hands every subscriber one event per changed object::

    {
        "event": "host.update",
        "object_type": "host",
        "action": "update",          # create | update | delete
        "object_id": "12",
        "timestamp": "2026-01-01T00:00:00Z",
        "user": "alice",             # "system" outside a request
        "before": {...} | None,
        "after": {...} | None,
        "changes": {"hostname": {"before": "a", "after": "b"}},
    }

Emitting from the facade (not the routes) covers every caller: the REST API,
jobs, discovery, imports and the MCP tools alike. The acting user comes from
``current_actor``, which the auth dependency sets for the request; a task
started from a request inherits it.

Subscribers register with ``add_object_change_hook``. A subscriber may pass a
``wants(object_type)`` predicate; when no subscriber wants a type, the
wrapper calls straight through without the extra reads, so tracking costs
nothing until someone listens. Hooks are fire-and-forget: an exception is
logged and never reaches the caller, whose write is already committed.

Secrets never enter an event: credential password/secret columns, bulky
config text and job parameters are dropped here, and the webhook dispatcher
masks the rest with the shared redaction before sending.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from typing import Any, ParamSpec, TypeVar

import routes.database as _dbcore
from routes.database import _LOGGER, row_to_dict

__all__ = [
    "CHANGE_ACTIONS",
    "CHANGE_OBJECT_TYPES",
    "add_object_change_hook",
    "current_actor",
    "emit_object_change",
    "fetch_object_snapshot",
    "remove_object_change_hook",
    "tracks_changes",
    "wants_object_type",
]

# object type -> table. The table names are fixed; never user input.
_OBJECT_TABLES: dict[str, str] = {
    "host": "hosts",
    "group": "inventory_groups",
    "prefix": "ipam_prefixes",
    "ip_address": "ipam_allocations",
    "vlan": "vlans",
    "vrf": "vrfs",
    "credential": "credentials",
    "config_backup": "config_backups",
    "job": "jobs",
}
CHANGE_OBJECT_TYPES: tuple[str, ...] = tuple(_OBJECT_TABLES)
CHANGE_ACTIONS: tuple[str, ...] = ("create", "update", "delete")

# Columns that never leave this module: secrets, bulky text and free-form
# job input (which can hold a secret under any key).
_DROP_COLUMNS: dict[str, frozenset[str]] = {
    "credential": frozenset({"password", "secret"}),
    "config_backup": frozenset({"config_text", "config_text_full"}),
    "job": frozenset({"parameters"}),
}
# JSON stored as text, decoded so subscribers (and the redaction walk) see
# structure rather than a string.
_JSON_COLUMNS = frozenset({"host_ids", "ad_hoc_ips", "depends_on", "metadata_json"})

current_actor: contextvars.ContextVar[str] = contextvars.ContextVar("plexus_change_actor", default="")

ChangeHook = Callable[[dict], Awaitable[None]]
_hooks: list[tuple[ChangeHook, Callable[[str], bool] | None]] = []


def add_object_change_hook(hook: ChangeHook, wants: Callable[[str], bool] | None = None) -> None:
    """Subscribe ``hook(event)``. ``wants(object_type)``, when given, limits
    which types are read and delivered to it. Adding a hook twice is a no-op."""
    if any(h is hook for h, _ in _hooks):
        return
    _hooks.append((hook, wants))


def remove_object_change_hook(hook: ChangeHook) -> None:
    _hooks[:] = [(h, w) for h, w in _hooks if h is not hook]


def _subscriber_wants(wants: Callable[[str], bool] | None, object_type: str) -> bool:
    if wants is None:
        return True
    try:
        return bool(wants(object_type))
    except Exception:
        return False


def wants_object_type(object_type: str) -> bool:
    """Whether any subscriber listens for this object type."""
    return any(_subscriber_wants(w, object_type) for _, w in _hooks)


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _clean_row(object_type: str, row: dict) -> dict:
    drop = _DROP_COLUMNS.get(object_type, frozenset())
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key in drop or isinstance(value, (bytes, bytearray, memoryview)):
            continue
        if key in _JSON_COLUMNS and isinstance(value, str) and value:
            try:
                value = json.loads(value)
            except ValueError:
                pass
        out[key] = value
    return _json_safe(out)


async def fetch_object_snapshot(object_type: str, object_id: Any) -> dict | None:
    """The row of a tracked object as an event carries it (secrets and bulky
    columns removed), or ``None`` when it does not exist."""
    table = _OBJECT_TABLES.get(object_type)
    if table is None:
        return None
    try:
        key = int(object_id)
    except TypeError, ValueError:
        return None
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT * FROM {table} WHERE id = ?", (key,))  # nosec B608 - fixed table names
        row = row_to_dict(await cursor.fetchone())
    finally:
        await db.close()
    return _clean_row(object_type, row) if row else None


def _changes(before: dict | None, after: dict | None) -> dict:
    if not before or not after:
        return {}
    keys = sorted(set(before) | set(after))
    return {k: {"before": before.get(k), "after": after.get(k)} for k in keys if before.get(k) != after.get(k)}


async def emit_object_change(
    object_type: str,
    action: str,
    object_id: Any,
    *,
    before: dict | None = None,
    after: dict | None = None,
    user: str | None = None,
) -> None:
    """Hand one structured event to every subscriber that wants the type."""
    targets = [h for h, w in _hooks if _subscriber_wants(w, object_type)]
    if not targets:
        return
    event = {
        "event": f"{object_type}.{action}",
        "object_type": object_type,
        "action": action,
        "object_id": str(object_id),
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user": user if user is not None else (current_actor.get() or "system"),
        "before": before,
        "after": after,
        "changes": _changes(before, after) if action == "update" else {},
    }
    for hook in targets:
        try:
            await hook(event)
        except Exception as exc:
            _LOGGER.warning(
                "object change hook dropped %s id=%s: %s",
                event["event"],
                event["object_id"],
                type(exc).__name__,
            )


P = ParamSpec("P")
R = TypeVar("R")


def _id_of(result: Any) -> Any:
    if isinstance(result, dict):
        return result.get("id")
    if isinstance(result, int) and not isinstance(result, bool):
        return result
    return None


def _ids_from_call(
    sig: inspect.Signature, args: tuple, kwargs: dict, id_arg: str | None, ids_arg: str | None
) -> list[Any]:
    try:
        bound = sig.bind_partial(*args, **kwargs)
    except TypeError:
        return []
    if id_arg is not None and bound.arguments.get(id_arg) is not None:
        return [bound.arguments[id_arg]]
    if ids_arg is not None:
        raw = bound.arguments.get(ids_arg) or []
        return list(raw) if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)) else []
    return []


def tracks_changes(
    object_type: str,
    action: str,
    *,
    id_arg: str | None = None,
    ids_arg: str | None = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Wrap a facade mutation so it emits an object-change event.

    ``create``: the new id is the return value (an int, or a dict's ``id``).
    ``update`` / ``delete``: the id is the ``id_arg`` argument (or each item
    of ``ids_arg``). An update emits only when the row changed; a delete only
    when the row existed before and is gone after. The wrapped call's result
    and exceptions pass through untouched.
    """
    if object_type not in _OBJECT_TABLES or action not in CHANGE_ACTIONS:
        raise ValueError(f"untracked change {object_type}.{action}")

    def decorate(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            if not wants_object_type(object_type):
                return await fn(*args, **kwargs)
            ids: list[Any] = []
            before: dict[str, dict | None] = {}
            if action != "create":
                ids = _ids_from_call(sig, args, kwargs, id_arg, ids_arg)
                for oid in ids:
                    try:
                        before[str(oid)] = await fetch_object_snapshot(object_type, oid)
                    except Exception:
                        before[str(oid)] = None
            result = await fn(*args, **kwargs)
            try:
                if action == "create":
                    new_id = _id_of(result)
                    if new_id is not None:
                        after = await fetch_object_snapshot(object_type, new_id)
                        if after is not None:
                            await emit_object_change(object_type, "create", new_id, after=after)
                else:
                    for oid in ids:
                        prior = before.get(str(oid))
                        if prior is None:
                            continue
                        after = await fetch_object_snapshot(object_type, oid)
                        if action == "delete" and after is None:
                            await emit_object_change(object_type, "delete", oid, before=prior)
                        elif action == "update" and after is not None and after != prior:
                            await emit_object_change(object_type, "update", oid, before=prior, after=after)
            except Exception as exc:
                _LOGGER.warning("object change tracking failed for %s.%s: %s", object_type, action, type(exc).__name__)
            return result

        return wrapper

    return decorate
