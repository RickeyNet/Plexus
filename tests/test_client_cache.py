"""Bounded client caches (``netcontrol.client_cache``) and the cloud SDK
sessions built on them (``netcontrol.cloud_sdk``)."""

from __future__ import annotations

import asyncio
import threading

import pytest
from netcontrol import client_cache, cloud_sdk
from netcontrol.client_cache import ClientCache, fingerprint


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Client:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _cache(clock: _Clock, **kwargs) -> ClientCache[_Client]:
    return ClientCache(
        "test", max_entries=kwargs.pop("max_entries", 4), max_idle_s=60.0, close=_Client.close, clock=clock, **kwargs
    )


def test_a_key_is_built_once_and_rebuilt_when_its_fingerprint_changes():
    clock = _Clock()
    cache = _cache(clock)
    first = cache.get("org-1", "fp-a", lambda: _Client("a"))
    assert cache.get("org-1", "fp-a", lambda: _Client("unused")) is first

    second = cache.get("org-1", "fp-b", lambda: _Client("b"))
    assert second.name == "b" and first.closed
    assert len(cache) == 1


def test_count_idle_age_and_max_age_bound_the_cache():
    clock = _Clock()
    cache = _cache(clock, max_entries=2)
    a = cache.get("a", 1, lambda: _Client("a"))
    b = cache.get("b", 1, lambda: _Client("b"))
    cache.get("a", 1, lambda: _Client("unused"))  # a is now the most recent
    c = cache.get("c", 1, lambda: _Client("c"))
    assert b.closed and not a.closed and len(cache) == 2

    clock.now += 61
    d = cache.get("d", 1, lambda: _Client("d"))
    assert a.closed and c.closed and len(cache) == 1

    aged = cache.get("e", 1, lambda: _Client("e"), max_age_s=30)
    clock.now += 20
    assert cache.get("e", 1, lambda: _Client("unused")) is aged
    clock.now += 20  # used 20 s ago, but built 40 s ago
    assert cache.get("e", 1, lambda: _Client("e2")).name == "e2" and aged.closed
    assert not d.closed


def test_a_failing_build_caches_nothing():
    cache = _cache(_Clock())

    def broken() -> _Client:
        raise ValueError("bad base URL")

    with pytest.raises(ValueError):
        cache.get("org-1", "fp", broken)
    assert len(cache) == 0


async def test_an_async_close_runs_on_the_loop_and_close_all_waits_for_it():
    closed: list[str] = []

    class _AsyncClient(_Client):
        async def aclose(self) -> None:
            await asyncio.sleep(0)
            closed.append(self.name)

    cache: ClientCache[_AsyncClient] = ClientCache(
        "test-async", max_entries=4, max_idle_s=60, close=_AsyncClient.aclose
    )
    cache.get("k", 1, lambda: _AsyncClient("old"))
    cache.get("k", 2, lambda: _AsyncClient("new"))
    await asyncio.sleep(0.01)
    assert closed == ["old"]

    await client_cache.close_all_caches()
    assert closed == ["old", "new"] and len(cache) == 0


def test_fingerprint_hides_the_secret_and_tells_values_apart():
    digest = fingerprint("example-secret-0001")
    assert "example-secret" not in digest and len(digest) == 64
    assert fingerprint(None) != fingerprint("") != fingerprint(False)
    assert fingerprint("a", "b") != fingerprint("ab")


# ── Cloud SDK sessions ───────────────────────────────────────────────────────


class _Session:
    """A boto3 session stand-in: records the clients it builds and the
    thread that built them."""

    region_name = "us-east-1"

    def __init__(self, auth: dict) -> None:
        self.auth = auth
        self.built: list[tuple[str, str | None, str]] = []

    def client(self, service, region_name=None, config=None):
        self.built.append((service, region_name, threading.current_thread().name))
        return _Client(f"{service}@{region_name}")


@pytest.fixture
def sessions():
    built: list[_Session] = []

    def build(auth: dict) -> _Session:
        built.append(_Session(auth))
        return built[-1]

    cloud_sdk._SDK_CLIENTS.discard()
    yield build, built
    cloud_sdk._SDK_CLIENTS.discard()


def test_an_account_keeps_one_session_and_one_client_per_region(sessions):
    build, built = sessions
    auth = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "example-secret-0001"}

    first = cloud_sdk.aws_account("flow", 7, auth, build)
    logs = first.client("logs", region_name="eu-west-1")
    again = cloud_sdk.aws_account("flow", 7, dict(auth), build)

    assert again is first and len(built) == 1
    assert again.client("logs", region_name="eu-west-1") is logs
    assert again.client("logs", region_name="us-east-1") is not logs
    assert [b[:2] for b in built[0].built] == [("logs", "eu-west-1"), ("logs", "us-east-1")]
    # Another puller gets its own session of the same account.
    assert cloud_sdk.aws_account("metrics", 7, auth, build) is not first


def test_changed_credentials_rebuild_the_session_and_close_its_clients(sessions):
    build, built = sessions
    first = cloud_sdk.aws_account("flow", 7, {"secret_access_key": "example-secret-0001"}, build)
    logs = first.client("logs", region_name="eu-west-1")

    second = cloud_sdk.aws_account("flow", 7, {"secret_access_key": "example-secret-0002"}, build)

    assert second is not first and len(built) == 2 and logs.closed


def test_an_assumed_role_session_is_rebuilt_before_its_credentials_expire(sessions, monkeypatch):
    build, built = sessions
    clock = _Clock()
    monkeypatch.setattr(cloud_sdk._SDK_CLIENTS, "_clock", clock)
    auth = {"role_arn": "arn:aws:iam::000000000000:role/example-reader"}

    first = cloud_sdk.aws_account("flow", 7, auth, build)
    clock.now += cloud_sdk.ROLE_SESSION_MAX_AGE_SECONDS - 60
    assert cloud_sdk.aws_account("flow", 7, auth, build) is first
    clock.now += 120
    assert cloud_sdk.aws_account("flow", 7, auth, build) is not first
    assert len(built) == 2


def test_forget_account_drops_only_that_account(sessions):
    build, built = sessions
    seven = cloud_sdk.aws_account("flow", 7, {}, build)
    eight = cloud_sdk.aws_account("flow", 8, {}, build)
    cloud_sdk.forget_account("flow", 7)
    assert cloud_sdk.aws_account("flow", 7, {}, build) is not seven
    assert cloud_sdk.aws_account("flow", 8, {}, build) is eight


def test_aws_error_code():
    class _Err(Exception):
        response = {"Error": {"Code": "ExpiredToken"}}

    assert cloud_sdk.aws_error_code(_Err()) in cloud_sdk.EXPIRED_CREDENTIAL_CODES
    assert cloud_sdk.aws_error_code(ValueError()) == ""
