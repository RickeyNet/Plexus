"""Dedicated pools for long blocking work (``netcontrol.executors``)."""

from __future__ import annotations

import asyncio
import contextvars
import threading

import pytest
from netcontrol import executors

_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("test_request_id", default="")


@pytest.fixture(autouse=True)
def _fresh_pools():
    executors.shutdown_pools()
    yield
    executors.shutdown_pools()


async def test_long_work_runs_on_its_own_pool_with_the_callers_context():
    _REQUEST_ID.set("req-0001")

    def work(a: int, *, b: int) -> tuple[str, str, int]:
        return threading.current_thread().name, _REQUEST_ID.get(), a + b

    name, seen, total = await executors.run_long_blocking("ansible", work, 2, b=3)

    assert name.startswith("plexus-ansible")
    assert seen == "req-0001"
    assert total == 5


async def test_long_work_does_not_hold_the_default_executor():
    """A pool full of long work leaves ``asyncio.to_thread`` free."""
    executors.configure_pool("cloud", 1)
    release = threading.Event()
    try:
        busy = asyncio.ensure_future(executors.run_long_blocking("cloud", release.wait, 5))
        await asyncio.sleep(0.05)
        name = await asyncio.wait_for(asyncio.to_thread(lambda: threading.current_thread().name), 2)
        assert not name.startswith("plexus-cloud")
    finally:
        release.set()
        assert await busy is True
        executors.configure_pool("cloud", executors._DEFAULT_SIZES["cloud"])


async def test_an_error_in_the_work_reaches_the_caller():
    def fail() -> None:
        raise ValueError("bad playbook")

    with pytest.raises(ValueError, match="bad playbook"):
        await executors.run_long_blocking("ssh", fail)


async def test_pools_are_sized_and_recreated_after_shutdown():
    executors.configure_pool("ssh", 3)
    try:
        assert executors.pool_size("ssh") == 3
        first = executors._executor("ssh")
        assert first._max_workers == 3
        executors.shutdown_pools()
        assert await executors.run_long_blocking("ssh", lambda: 7) == 7
        assert executors._executor("ssh") is not first
    finally:
        executors.configure_pool("ssh", executors._DEFAULT_SIZES["ssh"])
    executors.configure_pool("ssh", 10_000)
    assert executors.pool_size("ssh") == 256
    executors.configure_pool("ssh", executors._DEFAULT_SIZES["ssh"])
    with pytest.raises(ValueError):
        executors.configure_pool("nope", 2)  # type: ignore[arg-type]
