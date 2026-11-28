"""Short-lived caches of built payloads, and conditional JSON responses.

:class:`PayloadCache` is the one cache behind the read paths that build an
expensive answer and serve it for a few seconds: the topology graph and its
utilization map, the dashboard, the cloud topology, the software overview
and the resolved vendor OIDs. It keeps:

- a TTL per entry and at most ``max_entries`` entries, the oldest dropped
  first (a :class:`~netcontrol.secrets_providers.base.TTLCache` inside);
- one build per key at a time: concurrent callers that miss the same key
  wait for the first one's build and get its result (per-key locks, so a
  slow build of one key never holds up another);
- explicit invalidation of one key, of every key that starts with a prefix,
  or of everything;
- a generation counter bumped by every invalidation: a build that started
  before an invalidation is returned to its own callers but not stored, so a
  read that raced a write cannot put the old answer back;
- no stored failure: a build that raises stores nothing, and the next caller
  waiting on the key runs the build itself;
- an injectable clock for tests.

Values are shared by every caller of a key and must not be changed by them.
A key must hold everything the value depends on that differs between callers
(the caller's readable groups for a scoped payload, for example).

:class:`JsonPayload` holds a value with its JSON body and an ``ETag``,
serialized once and reused by every cache hit. :func:`json_response` turns a
payload into the response of a GET: ``200`` with the body, or ``304 Not
Modified`` without one when the caller's ``If-None-Match`` names the body it
already holds. The ``ETag`` is weak (``W/"..."``) because the compression
middleware (and nginx) re-encode the body after the handler, which a strong
tag would not survive; ``If-None-Match`` compares weakly anyway. The tag is
a hash of the exact body this caller is answered with, so two callers with
different views of the data never share a tag and a ``304`` is only sent for
the body the caller is allowed to see. ``Cache-Control: private, no-cache``
lets the browser keep the body and revalidate it on every use, and keeps
shared caches from storing it.

:func:`clear_all` empties every cache (the test suite calls it per test).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import weakref
from collections.abc import Awaitable, Callable, Hashable
from typing import Any

from fastapi.encoders import jsonable_encoder
from pydantic import TypeAdapter
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response

from netcontrol.secrets_providers.base import TTLCache

__all__ = [
    "API_CACHE_CONTROL",
    "JsonPayload",
    "PayloadCache",
    "clear_all",
    "direct_json",
    "encoded_json",
    "json_response",
]

# Revalidate on every use, and only in the caller's own browser.
API_CACHE_CONTROL = "private, no-cache"

_CACHES: weakref.WeakSet[PayloadCache[Any]] = weakref.WeakSet()


class PayloadCache[V]:
    """Built values per key for ``ttl`` seconds; see the module docstring."""

    def __init__(
        self,
        name: str,
        *,
        ttl: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.name = name
        self.ttl = ttl
        self._entries = TTLCache(max_entries=max_entries, clock=clock)
        self._locks: weakref.WeakValueDictionary[Hashable, asyncio.Lock] = weakref.WeakValueDictionary()
        self._generation = 0
        _CACHES.add(self)

    @property
    def generation(self) -> int:
        """Bumped by every invalidation."""
        return self._generation

    def peek(self, key: Hashable) -> V | None:
        """The live value of ``key``, or ``None``; never builds."""
        hit = self._entries.get(key)
        return None if hit is None else hit[0]

    async def get_or_build(self, key: Hashable, build: Callable[[], Awaitable[V]]) -> V:
        """The live value of ``key``, else the result of ``await build()``,
        which concurrent callers of the same key share."""
        hit = self._entries.get(key)
        if hit is not None:
            return hit[0]
        lock = self._locks.get(key)
        if lock is None:
            lock = self._locks[key] = asyncio.Lock()
        async with lock:
            # A caller that held the lock ahead of this one may have built it.
            hit = self._entries.get(key)
            if hit is not None:
                return hit[0]
            generation = self._generation
            value = await build()
            if generation == self._generation:
                self._entries.set(key, (value,), self.ttl)
            return value

    def invalidate(self, key: Hashable) -> None:
        """Drop one key."""
        self._generation += 1
        self._entries.discard(lambda k: k == key)

    def invalidate_prefix(self, prefix: tuple[Any, ...] | str) -> None:
        """Drop every key that starts with ``prefix``: tuple keys whose first
        items equal a tuple ``prefix``, string keys that start with a string."""
        self._generation += 1
        if isinstance(prefix, str):
            self._entries.discard(lambda k: isinstance(k, str) and k.startswith(prefix))
        else:
            size = len(prefix)
            self._entries.discard(lambda k: isinstance(k, tuple) and k[:size] == prefix)

    def clear(self) -> None:
        """Drop every key."""
        self._generation += 1
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def clear_all() -> None:
    """Empty every :class:`PayloadCache` of the process."""
    for cache in list(_CACHES):
        cache.clear()


# ── JSON bodies ──────────────────────────────────────────────────────────────

_ADAPTERS: dict[Any, TypeAdapter[Any]] = {}
_JSON_RENDERER = JSONResponse.__new__(JSONResponse)


def direct_json(value: Any, annotation: Any = dict) -> bytes:
    """``value`` as FastAPI writes the result of a handler annotated
    ``-> annotation`` (validated, then dumped by pydantic in one step)."""
    adapter = _ADAPTERS.get(annotation)
    if adapter is None:
        adapter = _ADAPTERS[annotation] = TypeAdapter(annotation)
    return adapter.dump_json(adapter.validate_python(value, from_attributes=True), by_alias=True)


def encoded_json(value: Any) -> bytes:
    """``value`` as FastAPI writes the result of a handler without a return
    annotation (``jsonable_encoder``, then ``JSONResponse``)."""
    return _JSON_RENDERER.render(jsonable_encoder(value))


class JsonPayload:
    """A value with its JSON body and weak ``ETag``, both computed on first
    use and then reused. ``encode`` must write what the handler's own return
    path writes: :func:`direct_json` for a handler with a return annotation
    (the default), :func:`encoded_json` for one without."""

    __slots__ = ("_body", "_encode", "_etag", "value")

    def __init__(self, value: Any, encode: Callable[[Any], bytes] = direct_json) -> None:
        self.value = value
        self._encode = encode
        self._body: bytes | None = None
        self._etag = ""

    @property
    def body(self) -> bytes:
        if self._body is None:
            self._body = self._encode(self.value)
            self._etag = f'W/"{hashlib.sha256(self._body).hexdigest()}"'
        return self._body

    @property
    def etag(self) -> str:
        if self._body is None:
            _ = self.body
        return self._etag


def _etag_matches(if_none_match: str, etag: str) -> bool:
    """Weak comparison of ``etag`` with an ``If-None-Match`` list."""
    opaque = etag.removeprefix("W/")
    for candidate in if_none_match.split(","):
        candidate = candidate.strip()
        if candidate == "*" or candidate.removeprefix("W/") == opaque:
            return True
    return False


def json_response(request: Any, payload: JsonPayload) -> Response:
    """The response of a GET for ``payload``: ``304`` without a body when
    the caller's ``If-None-Match`` names its ``ETag``, else ``200`` with the
    body. Call it only after every authorization check of the handler."""
    headers = {"ETag": payload.etag, "Cache-Control": API_CACHE_CONTROL}
    if isinstance(request, HTTPConnection) and request.scope.get("method") in ("GET", "HEAD"):
        if_none_match = request.headers.get("if-none-match")
        if if_none_match and _etag_matches(if_none_match, payload.etag):
            # The 200 goes through the compression middleware, which adds
            # this Vary; a 304 carries the headers its 200 would.
            return Response(status_code=304, headers={**headers, "Vary": "Accept-Encoding"})
    return Response(content=payload.body, media_type="application/json", headers=headers)
