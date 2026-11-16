"""The ``mcp_access`` admin setting: the endpoint switch and its limits."""

from __future__ import annotations

from typing import Any

from netcontrol import admin_settings

SETTING_KEY = "mcp_access"

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "max_result_bytes": 100_000,
    "max_rows": 200,
    "calls_per_minute": 120,
}

# Inclusive (low, high) for each numeric setting.
BOUNDS: dict[str, tuple[int, int]] = {
    "max_result_bytes": (10_000, 1_000_000),
    "max_rows": (10, 1000),
    "calls_per_minute": (1, 600),
}
_BOOL_KEYS = ("enabled",)


async def load_settings() -> dict[str, Any]:
    """The stored setting over the defaults. Invalid stored values are ignored."""
    return await admin_settings.load(SETTING_KEY, DEFAULTS, bool_keys=_BOOL_KEYS, bounds=BOUNDS)


async def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Validate ``values`` (any subset of the keys), store, return the result.

    Raises ``ValueError`` naming the first key that is unknown or out of bounds.
    """
    return await admin_settings.save(SETTING_KEY, DEFAULTS, values, bool_keys=_BOOL_KEYS, bounds=BOUNDS)
