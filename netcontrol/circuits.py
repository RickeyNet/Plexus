"""Circuits: the limits and rules, with no I/O.

A circuit is a carrier service (``cid``, the provider's id for it) of a
provider and a circuit type, with an A and a Z termination. Each termination
ends either at a site (``geo_sites``) or in a provider network, never both,
and may name the device (``hosts``) and port it lands on. Storage lives in
``routes.db.circuits``, the API in ``netcontrol.routes.circuits``; see
``docs/circuits.md``.

``FieldErrors`` collects the per-field messages of one request so the API
answers a single 422 whose ``fields`` the forms show under their inputs.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text

__all__ = [
    "CID_MAX",
    "COMMENTS_MAX",
    "DESCRIPTION_MAX",
    "KBPS_MAX",
    "NAME_MAX",
    "STATUSES",
    "TERM_SIDES",
    "TEXT_MAX",
    "URL_MAX",
    "FieldErrors",
    "clean_date",
    "clean_kbps",
    "clean_status",
    "clean_term_side",
    "clean_url",
]

NAME_MAX = 100
CID_MAX = 100
TEXT_MAX = 200
URL_MAX = 500
DESCRIPTION_MAX = 500
COMMENTS_MAX = 10_000
# 10 Tbps, in kbps: far above any real port, small enough for a BIGINT.
KBPS_MAX = 10_000_000_000

STATUSES: tuple[str, ...] = ("planned", "provisioning", "active", "offline", "deprovisioning", "decommissioned")
TERM_SIDES: tuple[str, ...] = ("A", "Z")

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)


def clean_date(raw: object, label: str) -> str:
    """A calendar date as ``YYYY-MM-DD``, or ``''`` for none."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return ""
    if not _DATE.match(text):
        raise CustomFieldError(f"{label} must be a date as YYYY-MM-DD.")
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise CustomFieldError(f"{label} is not a real date.") from exc
    return text


def clean_url(raw: object, label: str = "Portal URL") -> str:
    """An ``http`` or ``https`` URL, or ``''``. ``label`` starts the error
    message (hardware lifecycle notices reuse it for their documentation
    link)."""
    text = clean_text(raw, label, URL_MAX)
    if text and not _URL.match(text):
        raise CustomFieldError(f"{label} must start with http:// or https://.")
    return text


def clean_kbps(raw: object, label: str) -> int | None:
    """A rate in kbps (a whole number, 0 to ``KBPS_MAX``) or ``None``."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise CustomFieldError(f"{label} must be a whole number of kbps.")
    if raw < 0 or raw > KBPS_MAX:
        raise CustomFieldError(f"{label} must be from 0 to {KBPS_MAX} kbps.")
    return int(raw)


def clean_status(raw: object) -> str:
    text = raw.strip().lower() if isinstance(raw, str) else ""
    if text not in STATUSES:
        raise CustomFieldError(f"Status must be one of {', '.join(STATUSES)}.")
    return text


def clean_term_side(raw: object) -> str:
    text = raw.strip().upper() if isinstance(raw, str) else ""
    if text not in TERM_SIDES:
        raise CustomFieldError("Termination side must be A or Z.")
    return text


class FieldErrors:
    """The per-field messages of one request; the first message per field wins."""

    def __init__(self) -> None:
        self.fields: dict[str, str] = {}

    def add(self, field: str, message: str) -> None:
        self.fields.setdefault(field, message)

    def check(self, field: str, fn: Any, *args: Any) -> Any:
        """``fn(*args)``; a ``CustomFieldError`` is recorded under ``field``
        and ``None`` returned."""
        try:
            return fn(*args)
        except CustomFieldError as exc:
            self.add(field, str(exc))
            return None

    def name(self, field: str, raw: object, label: str, limit: int = NAME_MAX) -> str:
        return self.check(field, clean_name, raw, label, limit) or ""

    def text(self, field: str, raw: object, label: str, limit: int = TEXT_MAX) -> str:
        return self.check(field, clean_text, raw, label, limit) or ""

    def __bool__(self) -> bool:
        return bool(self.fields)

    def message(self) -> str:
        return next(iter(self.fields.values()), "Check the fields and try again.")
