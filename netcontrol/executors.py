"""Dedicated thread pools for long blocking work.

``asyncio.to_thread`` runs on the loop's default executor, which also serves
password hashing and every short blocking call (file reads, DNS, the SSRF
guard). Work that holds a thread for seconds to minutes (an SSH poll, a whole
Ansible run, a CloudWatch Logs Insights wait) gets a pool of its own here, so
a burst of it queues behind itself instead of delaying a login.

``await run_long_blocking(pool, fn, *args, **kwargs)`` is ``to_thread`` on the
named pool: the caller's ``contextvars`` (correlation id, request context)
are copied into the thread the same way. Pools are created on first use and
closed by ``shutdown_pools`` in the app lifespan; a pool used after that is
created again (tests start several app lifespans in one process).
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

__all__ = ["LongPool", "configure_pool", "pool_size", "run_long_blocking", "shutdown_pools"]

LongPool = Literal["ssh", "ansible", "cloud"]

# Workers per pool until ``configure_pool`` sets another size:
# - ssh: one per concurrent device poll (the lifespan sets it to the
#   monitoring ``poll_concurrency``).
# - ansible: one per running playbook (the lifespan sets it to the job
#   concurrency limit, ``APP_MAX_CONCURRENT_JOBS``).
# - cloud: the CloudWatch Insights waits; the flow puller runs at most four
#   accounts at once, and a manual pull may overlap the scheduled one.
_DEFAULT_SIZES: dict[str, int] = {"ssh": 16, "ansible": 4, "cloud": 8}
_MAX_WORKERS = 256

_sizes: dict[str, int] = dict(_DEFAULT_SIZES)
_pools: dict[str, ThreadPoolExecutor] = {}
_lock = threading.Lock()


def configure_pool(pool: LongPool, max_workers: int) -> None:
    """Size ``pool`` (1 to 256 workers). Takes effect when the pool is next
    created: call it before first use, as the lifespan does."""
    if pool not in _DEFAULT_SIZES:
        raise ValueError(f"unknown executor pool: {pool}")
    with _lock:
        _sizes[pool] = max(1, min(_MAX_WORKERS, int(max_workers)))


def pool_size(pool: LongPool) -> int:
    """The worker count ``pool`` has, or will have when it is created."""
    return _sizes[pool]


def _executor(pool: LongPool) -> ThreadPoolExecutor:
    with _lock:
        executor = _pools.get(pool)
        if executor is None:
            if pool not in _DEFAULT_SIZES:
                raise ValueError(f"unknown executor pool: {pool}")
            executor = ThreadPoolExecutor(max_workers=_sizes[pool], thread_name_prefix=f"plexus-{pool}")
            _pools[pool] = executor
        return executor


async def run_long_blocking[**P, R](pool: LongPool, fn: Callable[P, R], /, *args: P.args, **kwargs: P.kwargs) -> R:
    """Run ``fn(*args, **kwargs)`` on the dedicated ``pool`` and return its
    result, like ``asyncio.to_thread`` (context variables included)."""
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    call = functools.partial(ctx.run, fn, *args, **kwargs)
    return await loop.run_in_executor(_executor(pool), call)


def shutdown_pools() -> None:
    """Close every pool without waiting: queued work is cancelled, and a
    thread still running (an Ansible run past the shutdown grace) finishes on
    its own. Sizes set by ``configure_pool`` are kept."""
    with _lock:
        pools = list(_pools.values())
        _pools.clear()
    for executor in pools:
        executor.shutdown(wait=False, cancel_futures=True)
