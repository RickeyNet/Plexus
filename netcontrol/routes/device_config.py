"""
device_config.py -- The one way features get an inventory device's config.

Every capture of a device's running configuration goes through here and is
stored in Config Backups, so a backup policy, the topology collection, drift,
compliance, risk analysis, deployments and the upgrade prestage all read and
write the same records instead of each keeping its own copy:

  - One SSH session reads the plain configuration and, where the platform
    has one, the form with default settings included
    (``show running-config all``). Both go into one ``config_backups`` row:
    ``config_text`` (plain: diffs, pushes, parsers) and
    ``config_text_full`` (backup search).
  - A capture that matches the host's newest backup writes no new row; it
    marks that row as re-checked (``checked_at``).
  - ``max_age_seconds`` lets an on-demand feature reuse a backup the device
    confirmed within that window (``ON_DEMAND_MAX_AGE_SECONDS``) instead of
    opening a session. ``0`` always reads the device: a scheduled job, or a
    step that needs the state after a change it just made.
  - One capture per host at a time. A caller that arrives while another
    capture of the same host runs waits for it and takes its result when
    that capture started after the caller asked, so the result is at least
    as new as one the caller would have read itself.

Lab runtime nodes are not inventory hosts and keep ``_capture_running_config``.
"""

from __future__ import annotations

import asyncio
import itertools
from dataclasses import dataclass

import routes.database as db

from netcontrol.routes.shared import _capture_device_configs

# How old a stored configuration an on-demand action (a compliance scan, a
# risk analysis) accepts before it reads the device again.
ON_DEMAND_MAX_AGE_SECONDS = 15 * 60

# host_id -> lock serializing captures of that host.
_host_locks: dict[int, asyncio.Lock] = {}
# Orders requests and capture starts (a clock can tie two of them).
_sequence = itertools.count()
# host_id -> (sequence number of the last capture's start, its backup id).
_last_capture: dict[int, tuple[int, int]] = {}


@dataclass(frozen=True)
class DeviceConfig:
    """A device configuration as stored in Config Backups."""

    backup_id: int
    config_text: str
    config_text_full: str
    created: bool  # a new backup row was written (the config changed)
    reused: bool  # no session was opened: a stored backup was recent enough


def _from_row(row: dict, *, created: bool, reused: bool) -> DeviceConfig:
    return DeviceConfig(
        backup_id=int(row["id"]),
        config_text=str(row.get("config_text") or ""),
        config_text_full=str(row.get("config_text_full") or ""),
        created=created,
        reused=reused,
    )


async def store_device_config(
    host_id: int,
    config_text: str,
    config_text_full: str,
    *,
    capture_method: str,
    policy_id: int | None = None,
) -> DeviceConfig:
    """Store a configuration read from a device: a new backup row, or, when
    it matches the host's newest backup, a re-check of that row. For callers
    that read the configuration over a session of their own (the topology
    collection, the upgrade prestage); others use ``get_device_config``."""
    newest = await db.get_newest_host_config_backup(host_id)
    if (
        newest is not None
        and newest.get("config_text") == config_text
        and (newest.get("config_text_full") or "") == config_text_full
    ):
        await db.mark_config_backup_checked(int(newest["id"]))
        return _from_row(newest, created=False, reused=False)
    backup_id = await db.create_config_backup(
        policy_id=policy_id,
        host_id=host_id,
        config_text=config_text,
        config_text_full=config_text_full,
        capture_method=capture_method,
        status="success",
        error_message="",
    )
    return DeviceConfig(
        backup_id=int(backup_id),
        config_text=config_text,
        config_text_full=config_text_full,
        created=True,
        reused=False,
    )


async def get_device_config(
    host: dict,
    credentials: dict,
    *,
    capture_method: str,
    max_age_seconds: int = 0,
    policy_id: int | None = None,
) -> DeviceConfig:
    """An inventory host's configuration, from Config Backups when the
    device confirmed one within ``max_age_seconds``, otherwise read from the
    device and stored. Raises what the SSH capture raises."""
    host_id = int(host["id"])
    asked = next(_sequence)
    lock = _host_locks.setdefault(host_id, asyncio.Lock())
    async with lock:
        last = _last_capture.get(host_id)
        if last is not None and last[0] > asked:
            row = await db.get_config_backup(last[1])
            if row is not None and row.get("status") == "success":
                return _from_row(row, created=False, reused=True)
        if max_age_seconds > 0:
            row = await db.get_newest_host_config_backup(host_id, max_age_seconds=max_age_seconds)
            if row is not None:
                return _from_row(row, created=False, reused=True)
        started = next(_sequence)
        config_text, config_text_full = await _capture_device_configs(host, credentials)
        stored = await store_device_config(
            host_id,
            config_text,
            config_text_full,
            capture_method=capture_method,
            policy_id=policy_id,
        )
        _last_capture[host_id] = (started, stored.backup_id)
        return stored
