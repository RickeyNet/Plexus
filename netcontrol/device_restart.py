"""A device restart told from its polled uptime.

The monitoring poll reads sysUpTime (the OID map's ``uptime_oid``) and
stores it with each poll (``monitoring_polls.uptime_seconds``). A device
that reboots faster than the ICMP down threshold, and sends neither a trap
nor a syslog message, is found here: the poll compares the uptime it read
with the last stored poll of the host that has one, and raises one
``device_restarted`` event alert (warning, one per host, resolved
``RESOLVE_MINUTES`` after the last restart it saw).

The rule, with ``previous`` the stored uptime, ``elapsed`` the seconds from
that poll's ``polled_at`` to now, and ``uptime`` the new reading (all in
seconds):

* a restart when the uptime went back, ``uptime < previous -
  DECREASE_SLACK_SECONDS``, or when the device came up after the previous
  reading was taken, ``uptime + BOOT_SLACK_SECONDS < elapsed`` (a reboot
  while polls were failing, after which the uptime may be past the old
  one). The slacks cover the poll's own duration between the reading and
  its stored time;
* except a wrap of the 32-bit TimeTicks counter (sysUpTime wraps after
  2^32 hundredths of a second, about 497 days): when ``previous +
  elapsed`` reached ``WRAP_SECONDS`` and the new reading is where the
  wrapped counter would be (``previous + elapsed - WRAP_SECONDS``, within
  ``WRAP_SLACK_SECONDS``). Without an elapsed time, a previous reading in
  the counter's last day and a new one in its first day is a wrap;
* nothing on the first poll of a host (no previous reading), or when the
  poll read no uptime.

sysUpTime is the SNMP agent's time since it (re)initialized: an agent
restarted on a device that kept running reads the same, so the alert says
"device or SNMP agent". HOST-RESOURCES-MIB ``hrSystemUptime`` would tell
the two apart on hosts that have it; it is not read (the network platforms
polled here mostly do not implement it).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

METRIC = "device_restarted"
ALERT_TYPE = "event"
SEVERITY = "warning"
# An open restart alert resolves this long after the last restart seen.
RESOLVE_MINUTES = 60

WRAP_SECONDS = 2**32 / 100
DECREASE_SLACK_SECONDS = 60
BOOT_SLACK_SECONDS = 300
WRAP_SLACK_SECONDS = 600
_DAY = 86400


def is_wrap(previous: int, uptime: int, elapsed: float | None) -> bool:
    """Whether a lower reading is the TimeTicks counter wrapping."""
    if elapsed is None:
        return previous >= WRAP_SECONDS - _DAY and uptime < _DAY
    expected = previous + elapsed
    if expected < WRAP_SECONDS - WRAP_SLACK_SECONDS:
        return False
    return abs(uptime - (expected - WRAP_SECONDS)) <= WRAP_SLACK_SECONDS


def restarted(previous: int | None, uptime: int | None, elapsed: float | None) -> bool:
    """Whether the device (or its agent) restarted between two readings
    (see the module docstring)."""
    if previous is None or uptime is None or previous < 0 or uptime < 0:
        return False
    went_back = uptime < previous - DECREASE_SLACK_SECONDS
    came_up_since = elapsed is not None and uptime + BOOT_SLACK_SECONDS < elapsed
    if not (went_back or came_up_since):
        return False
    return not is_wrap(previous, uptime, elapsed)


def detect(
    previous: dict[str, Any] | None, uptime: int | None, now: datetime, polled_at: datetime | None
) -> dict[str, Any] | None:
    """The restart a poll's uptime shows against the previous stored poll
    (``uptime_seconds``; ``polled_at`` parsed by the caller, None when it
    could not be): ``{"uptime_seconds", "previous_uptime_seconds",
    "restarted_at"}`` (UTC, approximate), or None."""
    raw = (previous or {}).get("uptime_seconds")
    if raw is None or uptime is None:
        return None
    try:
        before = int(raw)
    except TypeError, ValueError:
        return None
    elapsed = (now - polled_at).total_seconds() if polled_at is not None else None
    if not restarted(before, uptime, elapsed):
        return None
    return {
        "uptime_seconds": uptime,
        "previous_uptime_seconds": before,
        "restarted_at": (now - timedelta(seconds=uptime)).strftime("%Y-%m-%d %H:%M UTC"),
    }


def alert_check(host_id: int, restart: dict[str, Any] | None) -> dict[str, Any] | None:
    """The poll's built-in event alert of a restart; None for none. One per
    host: a second restart within the hour counts on the open alert."""
    if not restart:
        return None
    minutes = int(restart["uptime_seconds"]) // 60
    return {
        "metric": METRIC,
        "alert_type": ALERT_TYPE,
        "message": (
            f"Device or SNMP agent restarted about {restart['restarted_at']} "
            f"(uptime {minutes} min, was {int(restart['previous_uptime_seconds']) // 60} min at the previous poll)"
        ),
        "severity": SEVERITY,
        "value": float(restart["uptime_seconds"]),
        "threshold": None,
        "dedup_key": f"{host_id}:{METRIC}:event",
    }
