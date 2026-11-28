"""Cross-request cache of what the auth path reads per user.

Every authenticated request of a non-admin user used to read, before its
handler ran: the user row (``require_auth``), the access-group features
(``_get_user_features``) and the object scope (``object_scope.scope_for_user``:
the access-group scopes, the granted inventory group subtrees and the scope
rules), 4 to 7 statements per request. This module keeps those reads for a
short time (``APP_AUTHZ_CACHE_TTL`` seconds, default 20; ``0`` turns the cache
off) in one :class:`~netcontrol.secrets_providers.base.TTLCache`.

Correctness comes from invalidation, not from the TTL. Every ``routes.db``
function that writes a table the answer depends on (``users``,
``user_group_memberships``, ``access_groups``, ``access_group_features``,
``access_group_inventory_scopes``, ``access_group_scope_rules``, the
``inventory_groups`` tree) carries :func:`invalidates`, which drops the whole
cache once the write returns (committed) or fails. A read that started before
a write and finishes after it is not stored (the generation counter), so it
cannot put the old answer back. The TTL bounds only what the app cannot see:
a write made outside it (direct SQL, another process).

Callers store immutable values only (tuples, frozensets, frozen dataclasses)
and hand out copies, so a handler that changes what it got cannot change the
cache. On any cache error the loader runs and its result is returned
uncached.
"""

from __future__ import annotations

import functools
import logging
import os
from collections.abc import Awaitable, Callable, Hashable
from typing import Any

from netcontrol.secrets_providers.base import TTLCache

LOGGER = logging.getLogger("plexus.authz_cache")

# Seconds an entry lives (``APP_AUTHZ_CACHE_TTL``); 0 turns the cache off.
DEFAULT_TTL = 20.0
MAX_TTL = 300.0

# One entry per user and kind; more users than this are evicted oldest first.
_CACHE = TTLCache(max_entries=4096)
# Bumped by every invalidation: a load that saw another generation when it
# started is returned but not stored.
_generation = 0


def ttl_seconds() -> float:
    """``APP_AUTHZ_CACHE_TTL`` clamped to 0..300 (read per call, so a test
    or an operator's restart picks it up); malformed values use the default."""
    raw = os.environ.get("APP_AUTHZ_CACHE_TTL", "").strip()
    if not raw:
        return DEFAULT_TTL
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TTL
    if value != value:  # NaN
        return DEFAULT_TTL
    return max(0.0, min(MAX_TTL, value))


def invalidate() -> None:
    """Forget every cached entry. Called after each write that can change
    a user's row, features or object scope."""
    global _generation
    _generation += 1
    _CACHE.clear()


def invalidates[F: Callable[..., Awaitable[Any]]](func: F) -> F:
    """Decorate a ``routes.db`` write so the cache is dropped when it
    returns or raises (a failed write may still have committed part)."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await func(*args, **kwargs)
        finally:
            invalidate()

    return wrapper  # type: ignore[return-value]


async def get_or_load(key: Hashable, loader: Callable[[], Awaitable[Any]]) -> Any:
    """The cached value of ``key``, else ``await loader()`` (stored unless
    an invalidation ran meanwhile). The value must be immutable."""
    ttl = ttl_seconds()
    if ttl <= 0:
        return await loader()
    try:
        hit = _CACHE.get(key)
    except Exception:  # fail open to the database, never to a stale answer
        LOGGER.debug("authz cache read failed for %r", key, exc_info=True)
        return await loader()
    if hit is not None:
        return hit[0]
    generation = _generation
    value = await loader()
    if generation == _generation:
        try:
            _CACHE.set(key, (value,), ttl)
        except Exception:
            LOGGER.debug("authz cache write failed for %r", key, exc_info=True)
    return value
