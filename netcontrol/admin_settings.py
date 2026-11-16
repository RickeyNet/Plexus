"""Admin settings stored as one JSON object under an ``auth_settings`` key.

A setting holds booleans and bounded whole numbers. ``validate`` checks a
subset of its keys, ``load`` merges the stored value over the defaults
(ignoring stored keys that no longer validate) and ``save`` validates,
merges and stores. Used by the AI access (``mcp_access``) and GraphQL API
(``graphql_api``) settings.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

import routes.database as db


def validate(
    values: Mapping[str, Any], *, bool_keys: Collection[str], bounds: Mapping[str, tuple[int, int]]
) -> dict[str, Any]:
    """``values`` checked against the keys of the setting: each key in
    ``bool_keys`` must be a boolean, each key in ``bounds`` a whole number
    within its inclusive ``(low, high)``. Raises ``ValueError`` naming the
    first key that is unknown or invalid."""
    clean: dict[str, Any] = {}
    for key, value in values.items():
        if key in bool_keys:
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
            clean[key] = value
        elif key in bounds:
            low, high = bounds[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} must be a whole number")
            if not low <= value <= high:
                raise ValueError(f"{key} must be between {low} and {high}")
            clean[key] = value
        else:
            raise ValueError(f"Unknown setting: {key}")
    return clean


async def load(
    setting_key: str,
    defaults: Mapping[str, Any],
    *,
    bool_keys: Collection[str],
    bounds: Mapping[str, tuple[int, int]],
) -> dict[str, Any]:
    """The stored setting over ``defaults``. Invalid stored values are ignored."""
    merged = dict(defaults)
    stored = await db.get_auth_setting(setting_key)
    if isinstance(stored, dict):
        for key, value in stored.items():
            try:
                merged.update(validate({key: value}, bool_keys=bool_keys, bounds=bounds))
            except ValueError:
                continue
    return merged


async def save(
    setting_key: str,
    defaults: Mapping[str, Any],
    values: Mapping[str, Any],
    *,
    bool_keys: Collection[str],
    bounds: Mapping[str, tuple[int, int]],
) -> dict[str, Any]:
    """Validate ``values`` (any subset of the keys), store the merged
    setting and return it. Raises ``ValueError`` as ``validate`` does."""
    clean = validate(values, bool_keys=bool_keys, bounds=bounds)
    merged = {**await load(setting_key, defaults, bool_keys=bool_keys, bounds=bounds), **clean}
    await db.set_auth_setting(setting_key, merged)
    return merged
