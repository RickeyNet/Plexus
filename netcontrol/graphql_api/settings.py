"""The ``graphql_api`` admin setting: GraphiQL, introspection and the query limits."""

from __future__ import annotations

from typing import Any

from netcontrol import admin_settings

SETTING_KEY = "graphql_api"

DEFAULTS: dict[str, Any] = {
    # Serve the GraphiQL page on GET /api/graphql (loads GraphiQL from unpkg).
    "graphiql": False,
    # Answer __schema / __type queries (GraphiQL needs it for completion).
    "introspection": False,
    # Deepest selection nesting a query may have (the operation root is 0).
    "max_depth": 8,
    # Most field aliases one document may use.
    "max_aliases": 15,
    # Most estimated fields a query may resolve (see limits.estimate_cost).
    "max_complexity": 50_000,
    # Largest ``limit`` a list argument accepts.
    "max_limit": 1000,
}

# Inclusive (low, high) for each numeric setting.
BOUNDS: dict[str, tuple[int, int]] = {
    "max_depth": (2, 20),
    "max_aliases": (0, 200),
    "max_complexity": (100, 1_000_000),
    "max_limit": (10, 10_000),
}
_BOOL_KEYS = ("graphiql", "introspection")


async def load_settings() -> dict[str, Any]:
    """The stored setting over the defaults. Invalid stored values are ignored."""
    return await admin_settings.load(SETTING_KEY, DEFAULTS, bool_keys=_BOOL_KEYS, bounds=BOUNDS)


async def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Validate ``values`` (any subset of the keys), store, return the result.

    Raises ``ValueError`` naming the first key that is unknown or out of bounds.
    """
    return await admin_settings.save(SETTING_KEY, DEFAULTS, values, bool_keys=_BOOL_KEYS, bounds=BOUNDS)
