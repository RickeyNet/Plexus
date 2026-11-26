"""Shared SQL for "newest row per key" reads.

Not star re-exported by ``routes.database``: the fragment is an internal
building block of the domain modules' queries, not part of the facade.
"""

from __future__ import annotations

__all__: list[str] = []


def latest_row_lateral(table: str, match_sql: str, alias: str) -> str:
    """A ``CROSS JOIN LATERAL`` that joins, as ``alias``, the newest
    (highest ``id``) row of ``table`` matching ``match_sql`` to each outer
    row; ``match_sql`` ties the inner row to the outer one, e.g.
    ``"host_id = h.id"``.

    Driving from the (small, often filtered) outer table and probing an
    index that leads with the key and ends with ``id`` reads one index
    entry per outer row, where joining ``GROUP BY key`` / ``MAX(id)``
    aggregates the whole history table first. An outer row with no match
    is left out, as with that inner join. All three arguments are trusted
    SQL fragments from db helpers, never user input.
    """
    return (
        f"CROSS JOIN LATERAL (SELECT * FROM {table} WHERE {match_sql} "  # nosec B608 - trusted fragments
        f"ORDER BY id DESC LIMIT 1) {alias}"
    )
