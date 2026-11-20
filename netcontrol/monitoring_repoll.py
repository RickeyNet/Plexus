"""Immediate monitoring re-polls of one host, asked for by an event.

A device event that says its state just changed (an APC UPS trap, a syslog
link-down or reload message) is followed by a monitoring poll of that host
within seconds, through the scheduled cycle's code
(``netcontrol.routes.monitoring.poll_host_now``), so its stored state,
history and alerts catch up without waiting for the next poll.

- A burst of events is one re-poll: a host already waiting for one is not
  scheduled again (the poll will see the state of every event in the burst).
- ``min_interval`` keeps a chatty source from polling a host more often
  than that, counted from the last re-poll scheduled for the host.
- The waiting tasks are held with strong references (asyncio keeps only a
  weak one) and a failed poll is logged, never raised.
"""

from __future__ import annotations

import asyncio
import logging
import time

LOGGER = logging.getLogger(__name__)

# Hosts with a re-poll scheduled that has not started yet.
_repoll_waiting: set[int] = set()
# host_id -> monotonic time the host's last re-poll was scheduled.
_last_scheduled: dict[int, float] = {}
_LAST_SCHEDULED_MAX = 4096
_background: set[asyncio.Task] = set()


def keep_task(task: asyncio.Task) -> asyncio.Task:
    """Hold a strong reference to ``task`` until it is done."""
    _background.add(task)
    task.add_done_callback(_background.discard)
    return task


async def _repoll(host_id: int, delay: float) -> None:
    try:
        await asyncio.sleep(delay)
    finally:
        _repoll_waiting.discard(host_id)
    try:
        from netcontrol.routes.monitoring import poll_host_now

        await poll_host_now(host_id)
    except Exception as exc:  # noqa: BLE001 - a background re-poll must not crash the loop
        LOGGER.warning("monitoring: re-poll of host %s failed: %s", host_id, exc)


def _prune(now: float, keep_seconds: float) -> None:
    if len(_last_scheduled) <= _LAST_SCHEDULED_MAX:
        return
    for host_id, at in list(_last_scheduled.items()):
        if now - at >= keep_seconds:
            _last_scheduled.pop(host_id, None)


def schedule_repoll(host_id: int, delay: float, *, min_interval: float = 0.0) -> bool:
    """Poll ``host_id`` once after ``delay`` seconds. False when a re-poll of
    the host is already waiting, or when one was scheduled less than
    ``min_interval`` seconds ago."""
    if host_id in _repoll_waiting:
        return False
    now = time.monotonic()
    last = _last_scheduled.get(host_id)
    if min_interval > 0 and last is not None and now - last < min_interval:
        return False
    _repoll_waiting.add(host_id)
    _last_scheduled[host_id] = now
    _prune(now, max(min_interval, 3600.0))
    keep_task(asyncio.ensure_future(_repoll(host_id, delay)))
    return True
