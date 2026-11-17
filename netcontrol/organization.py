"""Rules of the location hierarchy and tenancy (regions, sites, tenant
groups, tenants): limits, site statuses and the value cleaners shared by the
organization routes and the site routes of ``netcontrol.routes.geolocation``.

Storage lives in ``routes.db.organization``; see docs/locations-and-tenancy.md.
"""

from __future__ import annotations

import functools
import zoneinfo

NAME_MAX = 100
DESCRIPTION_MAX = 1000
COMMENTS_MAX = 10000
FACILITY_MAX = 100
TIME_ZONE_MAX = 64

# A site's lifecycle, in the order the UI offers it.
SITE_STATUSES: tuple[str, ...] = ("active", "planned", "staging", "decommissioning", "retired")


class OrganizationValueError(ValueError):
    """A value that is not valid, naming the field it belongs to."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


@functools.cache
def _time_zones() -> frozenset[str]:
    return frozenset(zoneinfo.available_timezones())


def clean_name(raw: str | None, field: str = "name", limit: int = NAME_MAX) -> str:
    """The trimmed name; refuses an empty or too long one."""
    name = (raw or "").strip()
    if not name:
        raise OrganizationValueError(field, "Name is required.")
    if len(name) > limit:
        raise OrganizationValueError(field, f"Name is longer than {limit} characters.")
    return name


def clean_text(raw: str | None, field: str, limit: int) -> str:
    """Trimmed free text of at most ``limit`` characters."""
    text = (raw or "").strip()
    if len(text) > limit:
        raise OrganizationValueError(field, f"Longer than {limit} characters.")
    return text


def clean_site_status(raw: str | None) -> str:
    status = (raw or "").strip().lower()
    if status not in SITE_STATUSES:
        raise OrganizationValueError("status", "Status must be one of " + ", ".join(SITE_STATUSES) + ".")
    return status


def clean_time_zone(raw: str | None) -> str:
    """An IANA time zone name (``Europe/Amsterdam``), or ``""`` for none."""
    zone = (raw or "").strip()
    if not zone:
        return ""
    if len(zone) > TIME_ZONE_MAX or zone not in _time_zones():
        raise OrganizationValueError("time_zone", f"'{zone[:TIME_ZONE_MAX]}' is not an IANA time zone.")
    return zone
