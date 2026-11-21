"""CSV cells that are safe to open in a spreadsheet.

Kept free of other Plexus imports so any exporter (routes, integrations,
bulk import) can use it.
"""

from __future__ import annotations

from typing import Any

# A cell starting with one of these is read as a formula by spreadsheet apps.
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_text_cell(value: object) -> str:
    """A user-entered text cell made safe to open in a spreadsheet: a leading
    apostrophe stops a value such as ``=cmd`` or ``@SUM(A1)`` running as a
    formula."""
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(CSV_FORMULA_PREFIXES) else text


def csv_text_row(row: dict[str, Any]) -> dict[str, Any]:
    """``row`` for a ``csv.DictWriter`` with every text value guarded by
    ``csv_text_cell``; numbers and other values are written as they are."""
    return {key: csv_text_cell(value) if isinstance(value, str) else value for key, value in row.items()}
