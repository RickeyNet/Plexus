"""The shared payload cache (``netcontrol.payload_cache``): one build per key
for concurrent callers, TTL, size bound, invalidation by key, prefix or all,
no stored result for a build that raced an invalidation or raised, and the
JSON body and ETag of a payload."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from decimal import Decimal

import pytest
from fastapi.encoders import jsonable_encoder
from netcontrol import payload_cache
from netcontrol.payload_cache import JsonPayload, PayloadCache, direct_json, encoded_json
from starlette.responses import JSONResponse


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _counting_build(calls: list[str], value: str, *, wait: asyncio.Event | None = None):
    async def build() -> str:
        calls.append(value)
        if wait is not None:
            await wait.wait()
        return value

    return build


async def test_concurrent_callers_share_one_build():
    cache: PayloadCache[dict] = PayloadCache("t-single", ttl=10, max_entries=8)
    calls: list[int] = []
    release = asyncio.Event()

    async def build() -> dict:
        calls.append(1)
        await release.wait()
        return {"n": len(calls)}

    tasks = [asyncio.create_task(cache.get_or_build("k", build)) for _ in range(5)]
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(*tasks)
    assert calls == [1]
    assert all(result is results[0] for result in results)


async def test_a_slow_key_does_not_hold_up_another():
    cache: PayloadCache[str] = PayloadCache("t-keys", ttl=10, max_entries=8)
    release = asyncio.Event()
    calls: list[str] = []
    slow = asyncio.create_task(cache.get_or_build("slow", _counting_build(calls, "slow", wait=release)))
    await asyncio.sleep(0)
    assert await asyncio.wait_for(cache.get_or_build("fast", _counting_build(calls, "fast")), timeout=2) == "fast"
    release.set()
    assert await slow == "slow"


async def test_entries_expire_after_the_ttl():
    clock = _Clock()
    cache: PayloadCache[str] = PayloadCache("t-ttl", ttl=15, max_entries=8, clock=clock)
    calls: list[str] = []
    await cache.get_or_build("k", _counting_build(calls, "a"))
    clock.now += 14.9
    assert await cache.get_or_build("k", _counting_build(calls, "b")) == "a"
    clock.now += 0.2
    assert await cache.get_or_build("k", _counting_build(calls, "c")) == "c"
    assert calls == ["a", "c"]


async def test_invalidation_by_key_prefix_and_all():
    cache: PayloadCache[str] = PayloadCache("t-inv", ttl=60, max_entries=16)
    calls: list[str] = []
    for key in [(1, "aws"), (1, "azure"), (2, "aws"), "group:7", "group:8", "other"]:
        await cache.get_or_build(key, _counting_build(calls, str(key)))
    assert len(cache) == 6

    cache.invalidate((2, "aws"))
    assert cache.peek((2, "aws")) is None and cache.peek((1, "aws")) is not None
    cache.invalidate_prefix((1,))
    assert cache.peek((1, "aws")) is None and cache.peek((1, "azure")) is None
    cache.invalidate_prefix("group:")
    assert cache.peek("group:7") is None and cache.peek("other") == "other"
    generation = cache.generation
    cache.clear()
    assert len(cache) == 0 and cache.generation > generation


async def test_a_build_overtaken_by_an_invalidation_is_not_stored():
    cache: PayloadCache[str] = PayloadCache("t-gen", ttl=60, max_entries=8)

    async def build_racing_a_write() -> str:
        cache.invalidate("k")  # a write lands while the build reads
        return "old"

    # Its own caller still gets it; the next caller does not.
    assert await cache.get_or_build("k", build_racing_a_write) == "old"
    assert cache.peek("k") is None
    calls: list[str] = []
    assert await cache.get_or_build("k", _counting_build(calls, "new")) == "new"
    assert cache.peek("k") == "new"


async def test_a_caller_after_an_invalidation_does_not_join_the_old_build():
    cache: PayloadCache[str] = PayloadCache("t-join", ttl=60, max_entries=8)
    release = asyncio.Event()
    calls: list[str] = []
    old = asyncio.create_task(cache.get_or_build("k", _counting_build(calls, "old", wait=release)))
    await asyncio.sleep(0)
    cache.clear()
    new = asyncio.create_task(cache.get_or_build("k", _counting_build(calls, "new")))
    await asyncio.sleep(0)
    release.set()
    assert await old == "old"
    assert await new == "new"
    assert cache.peek("k") == "new"


async def test_the_oldest_entry_is_dropped_past_the_size_bound():
    cache: PayloadCache[str] = PayloadCache("t-size", ttl=60, max_entries=2)
    calls: list[str] = []
    for key in ("a", "b", "c"):
        await cache.get_or_build(key, _counting_build(calls, key))
    assert len(cache) == 2
    assert cache.peek("a") is None and cache.peek("c") == "c"
    with pytest.raises(ValueError):
        PayloadCache("t-bad", ttl=1, max_entries=0)


async def test_a_failed_build_is_not_cached_and_waiters_build_again():
    cache: PayloadCache[str] = PayloadCache("t-fail", ttl=60, max_entries=8)
    release = asyncio.Event()
    attempts: list[int] = []

    async def build() -> str:
        attempts.append(1)
        if len(attempts) == 1:
            await release.wait()
            raise RuntimeError("database went away")
        return "ok"

    first = asyncio.create_task(cache.get_or_build("k", build))
    waiter = asyncio.create_task(cache.get_or_build("k", build))
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(RuntimeError):
        await first
    assert await waiter == "ok"
    assert cache.peek("k") == "ok"
    assert len(attempts) == 2


async def test_clear_all_empties_every_cache():
    one: PayloadCache[str] = PayloadCache("t-all-1", ttl=60, max_entries=4)
    two: PayloadCache[str] = PayloadCache("t-all-2", ttl=60, max_entries=4)
    calls: list[str] = []
    await one.get_or_build("k", _counting_build(calls, "1"))
    await two.get_or_build("k", _counting_build(calls, "2"))
    payload_cache.clear_all()
    assert one.peek("k") is None and two.peek("k") is None


# ── JSON bodies ──────────────────────────────────────────────────────────────

_SAMPLE = {
    "when": dt.datetime(2026, 11, 27, 12, 30, 5, 123456, tzinfo=dt.UTC),
    "naive": dt.datetime(2026, 11, 27, 12, 30),
    "day": dt.date(2026, 11, 27),
    "amount": Decimal("12.50"),
    "ratio": 0.1,
    "big": 10**18,
    "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
    "name": "core-sw.example.com é",
    "nested": [{"ip": "192.0.2.10", "tags": ("a", "b")}, None, True],
}


def test_encoded_json_is_what_a_handler_without_annotation_writes():
    expected = JSONResponse(jsonable_encoder(_SAMPLE)).body
    assert encoded_json(_SAMPLE) == expected


def test_payload_body_and_etag_are_computed_once():
    payload = JsonPayload(_SAMPLE)
    body = payload.body
    assert body == direct_json(_SAMPLE)
    assert payload.body is body
    assert payload.etag.startswith('W/"') and payload.etag.endswith('"')
    assert JsonPayload(dict(_SAMPLE)).etag == payload.etag
    assert JsonPayload({**_SAMPLE, "ratio": 0.2}).etag != payload.etag


@pytest.mark.parametrize(
    ("header", "matches"),
    [
        ('W/"abc"', True),
        ('"abc"', True),
        ('W/"x", W/"abc"', True),
        ("*", True),
        ('W/"abd"', False),
        ("", False),
    ],
)
def test_if_none_match_compares_weakly(header, matches):
    assert payload_cache._etag_matches(header, 'W/"abc"') is matches
