"""The ``mcp_access`` admin setting: the endpoint switch and its limits."""

from __future__ import annotations

from typing import Any

import routes.database as db

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


def _validated(values: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in values.items():
        if key == "enabled":
            if not isinstance(value, bool):
                raise ValueError("enabled must be true or false")
            clean[key] = value
        elif key in BOUNDS:
            low, high = BOUNDS[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} must be a whole number")
            if not low <= value <= high:
                raise ValueError(f"{key} must be between {low} and {high}")
            clean[key] = value
        else:
            raise ValueError(f"Unknown setting: {key}")
    return clean


async def load_settings() -> dict[str, Any]:
    """The stored setting over the defaults. Invalid stored values are ignored."""
    merged = dict(DEFAULTS)
    stored = await db.get_auth_setting(SETTING_KEY)
    if isinstance(stored, dict):
        for key, value in stored.items():
            try:
                merged.update(_validated({key: value}))
            except ValueError:
                continue
    return merged


async def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Validate ``values`` (any subset of the keys), store, return the result.

    Raises ``ValueError`` naming the first key that is unknown or out of bounds.
    """
    clean = _validated(values)
    merged = {**await load_settings(), **clean}
    await db.set_auth_setting(SETTING_KEY, merged)
    return merged
