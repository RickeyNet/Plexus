"""Bounded caches of long-lived API clients, transports and SDK sessions.

Building a client per call is not free: an ``httpx`` client loads the CA
bundle into a new ``SSLContext``, a cloud SDK builds its session, endpoint
tables and credential chain. A :class:`ClientCache` keeps one per key and
hands it back while it still fits:

- each entry carries a *fingerprint* of everything it was built from (base
  URL, TLS choice, a hash of the credential, the approved addresses...);
  a lookup with another fingerprint closes the old entry and builds anew, so
  a changed setting or secret never reuses a client built with the old one.
- at most ``max_entries`` entries (least recently used dropped first), each
  dropped after ``max_idle_s`` without use, and optionally after
  ``max_age_s`` from its creation (short-lived cloud credentials).
- a dropped entry is closed with ``close``. A close that returns an awaitable
  (an ``httpx`` client) is run as a task on the running loop.

Lookups are thread-safe, so an SDK client can be built and fetched inside a
worker thread. ``close_all_caches`` closes every cache's entries; the app
lifespan calls it at shutdown.

``fingerprint`` hashes secrets for a fingerprint, so no cache key or
fingerprint holds a secret in clear.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Any

from netcontrol.telemetry import configure_logging

__all__ = ["ClientCache", "close_all_caches", "fingerprint"]

LOGGER = configure_logging("plexus.client_cache")

CloseFn = Callable[[Any], "Awaitable[Any] | Any"]


def fingerprint(*parts: object) -> str:
    """A SHA-256 over ``parts`` (each ``repr``-ed, so ``None``, ``""`` and
    ``False`` differ): the identity of a credential or a TLS bundle without
    keeping it in clear."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(repr(part).encode("utf-8", "surrogatepass"))
        digest.update(b"\x00")
    return digest.hexdigest()


@dataclass
class _Entry[V]:
    value: V
    fingerprint: Hashable
    created: float
    used: float
    max_age_s: float | None


_CACHES: weakref.WeakSet[ClientCache[Any]] = weakref.WeakSet()


class ClientCache[V]:
    """One reusable value per key; see the module docstring."""

    def __init__(
        self,
        name: str,
        *,
        max_entries: int,
        max_idle_s: float,
        close: CloseFn | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.name = name
        self.max_entries = max_entries
        self.max_idle_s = max_idle_s
        self._close = close
        self._clock = clock
        self._entries: OrderedDict[Hashable, _Entry[V]] = OrderedDict()
        self._lock = threading.Lock()
        # Close tasks in flight, kept so they are not garbage collected.
        self._closing: set[asyncio.Task[Any]] = set()
        _CACHES.add(self)

    def __len__(self) -> int:
        return len(self._entries)

    def _stale(self, entry: _Entry[V], now: float) -> bool:
        if now - entry.used > self.max_idle_s:
            return True
        return entry.max_age_s is not None and now - entry.created > entry.max_age_s

    def get(
        self,
        key: Hashable,
        fingerprint: Hashable,
        factory: Callable[[], V],
        *,
        max_age_s: float | None = None,
    ) -> V:
        """The cached value of ``key`` when it was built with ``fingerprint``
        and is neither idle nor old past its limits; else ``factory()``,
        cached (and the old value closed).

        ``factory`` runs outside the cache lock (building a cloud session
        may call the network), so two threads missing the same key at once
        may both build: the first stored wins and the other is closed."""
        dropped: list[V] = []
        with self._lock:
            now = self._clock()
            for other_key in [k for k, e in self._entries.items() if self._stale(e, now)]:
                dropped.append(self._entries.pop(other_key).value)
            hit = self._hit(key, fingerprint, now)
            if hit is None:
                stale = self._entries.pop(key, None)
                if stale is not None:
                    dropped.append(stale.value)
        self._dispose_all(dropped)
        if hit is not None:
            return hit[0]
        value = factory()
        dropped = []
        with self._lock:
            now = self._clock()
            hit = self._hit(key, fingerprint, now)
            if hit is not None:  # another thread built it meanwhile
                dropped.append(value)
                value = hit[0]
            else:
                stale = self._entries.pop(key, None)
                if stale is not None:
                    dropped.append(stale.value)
                self._entries[key] = _Entry(value, fingerprint, now, now, max_age_s)
                while len(self._entries) > self.max_entries:
                    dropped.append(self._entries.popitem(last=False)[1].value)
        self._dispose_all(dropped)
        return value

    def _hit(self, key: Hashable, fingerprint: Hashable, now: float) -> tuple[V] | None:
        """``(value,)`` of a usable entry for ``key`` (marked used), else
        ``None``. Called under the lock."""
        entry = self._entries.get(key)
        if entry is None or entry.fingerprint != fingerprint or self._stale(entry, now):
            return None
        entry.used = now
        self._entries.move_to_end(key)
        return (entry.value,)

    def discard(self, match: Callable[[Hashable], bool] | None = None) -> int:
        """Drop (and close) every entry whose key ``match`` accepts, or all
        of them. The number dropped."""
        with self._lock:
            keys = [k for k in self._entries if match is None or match(k)]
            dropped = [self._entries.pop(k).value for k in keys]
        self._dispose_all(dropped)
        return len(dropped)

    async def aclose(self) -> None:
        """Drop every entry and wait for their closes."""
        with self._lock:
            dropped = [e.value for e in self._entries.values()]
            self._entries.clear()
        for value in dropped:
            await self._close_one(value)
        if self._closing:
            await asyncio.gather(*list(self._closing), return_exceptions=True)

    async def _close_one(self, value: V) -> None:
        if self._close is None:
            return
        try:
            result = self._close(value)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:  # noqa: BLE001 - closing is best effort
            LOGGER.debug("%s: closing a cached client failed: %s", self.name, type(exc).__name__)

    def _dispose_all(self, values: list[V]) -> None:
        for value in values:
            self._dispose(value)

    def _dispose(self, value: V) -> None:
        """Close a dropped value now, or as a task when its close is async."""
        if self._close is None:
            return
        try:
            result = self._close(value)
        except Exception as exc:  # noqa: BLE001 - closing is best effort
            LOGGER.debug("%s: closing a cached client failed: %s", self.name, type(exc).__name__)
            return
        if not inspect.isawaitable(result):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop in this thread (a worker thread): nothing can await it.
            if inspect.iscoroutine(result):
                result.close()
            return
        task = loop.create_task(self._await_close(result))
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def _await_close(self, result: Awaitable[Any]) -> None:
        try:
            await result
        except Exception as exc:  # noqa: BLE001 - closing is best effort
            LOGGER.debug("%s: closing a cached client failed: %s", self.name, type(exc).__name__)


async def close_all_caches() -> None:
    """Close the entries of every ``ClientCache`` (app shutdown)."""
    for cache in list(_CACHES):
        await cache.aclose()
