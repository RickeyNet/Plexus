"""Software end of life: the release series of a version and whether that
series still gets security fixes, with no I/O.

A **series** is the release line a version belongs to. OPNsense names it in
the version itself: the year and the month of the major release
(``25.1.4_1`` -> ``25.1``, business edition ``24.10.2`` -> ``24.10``; the
firmware status calls it ``product_series``). For every other platform the
series is what an administrator's entry names: an entry ``17.9`` covers
``17.9.4a`` but not ``17.90.1`` (a prefix on a version component boundary,
as the advisory specification ``17.9.*``), and the longest matching entry
wins.

An **entry** (``software_eol_entries``) gives one series of one platform its
end-of-life date: the day security fixes stop. It is how every platform
gets a status, and for OPNsense it overrides the built-in estimate.

OPNsense needs no entry. Its release engineering (``Makefile`` of
opnsense/core, ``CORE_NEXT``) knows two major series a year per edition:
community ``YY.1`` -> ``YY.7`` -> ``YY+1.1`` and business ``YY.4`` ->
``YY.10`` -> ``YY+1.4``, and a series is maintained until its successor is
released. The successor's release day is not known in advance, but every
community major so far shipped inside its month (between the 2nd and the
31st, most in the last week), so the **estimate** is the last day of the
successor's release month: never early (a firewall on the newest series is
not called end of life before its successor exists), at most about a month
late. The ``ending`` window warns before it. A firewall that reports a
newer major release as available (``upgrade_major_version`` of
``core/firmware/status``, carried as ``major_upgrade``) **reports** its
series superseded, which makes it end of life on the day the successor is
offered, before the estimated date (its ``date`` stays the estimate, so
``days`` may still be positive; the basis says why). An administrator's
entry wins over both.

``evaluate`` folds this into one status per device: ``supported``,
``ending`` (the date is within the warning window), ``end_of_life`` (the
date has come) or ``unknown`` (no entry and no built-in rule); the source
is ``entry``, ``estimate`` or ``reported``. ``lifecycle_advisories`` turns
the series that are ending or end of life into generated advisories of the
source ``lifecycle`` that the software tracker matches, alerts and notifies
on like any other (``netcontrol.routes.software_eol``).
"""

from __future__ import annotations

import calendar
import re
from datetime import date
from typing import Any

from netcontrol.hardware_lifecycle import MAX_WARN_DAYS, days_until
from netcontrol.integrations.software.versions import PLATFORMS, canonical_version, compare_versions, version_matches

__all__ = [
    "ADVISORY_PREFIX",
    "ADVISORY_SOURCE",
    "DEFAULT_WARN_DAYS",
    "ENTRY_SOURCES",
    "MAX_WARN_DAYS",
    "STATUSES",
    "WARN_DAYS_SETTING",
    "evaluate",
    "fleet_statuses",
    "lifecycle_advisories",
    "lifecycle_advisory_id",
    "opnsense_estimate",
    "opnsense_successor",
    "series_evidence",
    "series_matches",
    "series_of",
    "series_spec",
    "status_counts",
    "status_text",
    "warn_days_setting",
]

STATUSES = ("supported", "ending", "end_of_life", "unknown")
ENTRY_SOURCES = ("manual", "import")
DEFAULT_WARN_DAYS = 60
# The software setting that holds the warning window.
WARN_DAYS_SETTING = "eol_warn_days"
ADVISORY_SOURCE = "lifecycle"
ADVISORY_PREFIX = f"{ADVISORY_SOURCE}:"
OPNSENSE = "opnsense"
OPNSENSE_RELEASES_URL = "https://docs.opnsense.org/releases.html"

# A major release's minor number -> (its successor's minor number, years
# to add), as ``CORE_NEXT`` of opnsense/core's Makefile computes it.
_OPNSENSE_SUCCESSOR = {1: (7, 0), 7: (1, 1), 4: (10, 0), 10: (4, 1)}
_OPNSENSE_SERIES = re.compile(r"^(\d{2})\.(\d{1,2})(?!\d)")
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9._\-]+")
# What the title of an end-of-life advisory says (an ending one says
# "reaches end of life").
_EOL_TITLE = " is end of life"


# ── Series ───────────────────────────────────────────────────────────────────


def series_matches(version: Any, series: str) -> bool:
    """Whether ``version`` belongs to ``series``: the series is a prefix of
    the version on a component boundary (``17.9`` covers ``17.9.4a``, not
    ``17.90.1``)."""
    return bool(str(series or "").strip()) and version_matches(version, series_spec(series))


def series_spec(series: str) -> str:
    """The version specification of every version of ``series``."""
    return f"{str(series).strip()}.*"


def _opnsense_series(version: Any) -> str:
    match = _OPNSENSE_SERIES.match(canonical_version(version))
    return f"{int(match.group(1))}.{int(match.group(2))}" if match else ""


def series_of(platform: str, version: Any, entries: list[dict] | None = None) -> str:
    """The release series of ``version`` on ``platform`` (``""`` when there
    is none): OPNsense by its own rule, every other platform by the longest
    enabled entry of the platform the version belongs to."""
    if platform == OPNSENSE:
        return _opnsense_series(version)
    best = ""
    for entry in entries or []:
        series = str(entry.get("series") or "").strip()
        if (
            entry.get("platform") == platform
            and entry.get("enabled", True)
            and len(series) > len(best)
            and series_matches(version, series)
        ):
            best = series
    return best


def opnsense_successor(series: str) -> str:
    """The OPNsense major series released after ``series`` (``""`` for a
    series that is not ``YY.1``, ``YY.4``, ``YY.7`` or ``YY.10``)."""
    match = _OPNSENSE_SERIES.match(str(series or ""))
    if not match:
        return ""
    year, minor = int(match.group(1)), int(match.group(2))
    if minor not in _OPNSENSE_SUCCESSOR:
        return ""
    next_minor, years = _OPNSENSE_SUCCESSOR[minor]
    return f"{year + years}.{next_minor}"


def opnsense_estimate(series: str) -> str:
    """The estimated end of life of an OPNsense series as ``YYYY-MM-DD``:
    the last day of its successor's release month (``""`` when the series
    has no known successor). Never early, at most about a month late; the
    firewall's own report of the new major release ends the series on the
    exact day, earlier."""
    successor = opnsense_successor(series)
    if not successor:
        return ""
    year_text, month_text = successor.split(".")
    year, month = 2000 + int(year_text), int(month_text)
    return date(year, month, calendar.monthrange(year, month)[1]).isoformat()


def _newer_series(platform: str, series: str, reported: Any) -> str:
    """The series of a reported major release when it is newer than
    ``series`` (``""`` otherwise)."""
    found = series_of(platform, reported)
    if not found or not series or found == series:
        return ""
    return found if compare_versions(found, series) > 0 else ""


# ── Status ───────────────────────────────────────────────────────────────────


def warn_days_setting(raw: Any) -> int:
    """The warning window of the software settings, in days (the default
    when unset or out of range)."""
    try:
        days = int(raw)
    except TypeError, ValueError:
        return DEFAULT_WARN_DAYS
    return days if 1 <= days <= MAX_WARN_DAYS else DEFAULT_WARN_DAYS


def _entry_for(platform: str, series: str, entries: list[dict] | None) -> dict | None:
    if not series:
        return None
    return next(
        (
            e
            for e in entries or []
            if e.get("platform") == platform and str(e.get("series") or "").strip() == series and e.get("enabled", True)
        ),
        None,
    )


def evaluate(
    platform: str,
    version: Any,
    today: date,
    entries: list[dict] | None = None,
    *,
    reported: Any = "",
    warn_days: int = DEFAULT_WARN_DAYS,
) -> dict[str, Any]:
    """The end-of-life status of one device on ``today``.

    ``entries``: the administrator's entries (any platform); ``reported``:
    a newer major release the device itself reports as available.
    Returns ``series``, ``status`` (one of ``STATUSES``), ``date`` (the end
    of life, ``YYYY-MM-DD``, or ``None``), ``days`` (to that date; negative
    once passed), ``source`` (``entry``, ``estimate``, ``reported`` or
    ``""``), ``estimate`` (whether the date is an estimate), ``basis`` (one
    line saying why), ``successor`` (the series that supersedes it, when
    known) and the entry's ``url`` and ``release_date``.
    """
    series = series_of(platform, version, entries)
    result: dict[str, Any] = {
        "series": series,
        "status": "unknown",
        "date": None,
        "days": None,
        "source": "",
        "estimate": False,
        "basis": "",
        "successor": "",
        "url": "",
        "release_date": "",
    }
    if not series:
        result["basis"] = "No end-of-life entry covers this version."
        return result
    label = PLATFORMS.get(platform, PLATFORMS["other"])["label"]
    entry = _entry_for(platform, series, entries)
    if entry and entry.get("eol_date"):
        result.update(
            date=str(entry["eol_date"]),
            source="entry",
            url=str(entry.get("url") or ""),
            release_date=str(entry.get("release_date") or ""),
            basis=f"Administrator entry: {label} {series} ends on {entry['eol_date']}.",
        )
    elif platform == OPNSENSE:
        estimate = opnsense_estimate(series)
        successor = _newer_series(platform, series, reported)
        result["successor"] = successor or opnsense_successor(series)
        result["url"] = OPNSENSE_RELEASES_URL
        if successor:
            result.update(
                date=estimate or None,
                source="reported",
                basis=f"The firewall reports major release {canonical_version(reported)} is available: "
                f"{label} {series} is superseded.",
            )
        elif estimate:
            result.update(
                date=estimate,
                source="estimate",
                estimate=True,
                basis=f"Estimate: {label} {series} is maintained until {result['successor']} is released, "
                f"due in {date.fromisoformat(estimate).strftime('%B %Y')}.",
            )
        else:
            result["basis"] = f"{label} {series} is not a known major series."
            return result
    else:
        result["basis"] = f"No end-of-life entry for {label} {series}."
        return result
    days = days_until(result["date"], today)
    result["days"] = days
    if result["source"] == "reported" or (days is not None and days <= 0):
        result["status"] = "end_of_life"
    elif days is not None and days <= warn_days:
        result["status"] = "ending"
    elif days is not None:
        result["status"] = "supported"
    return result


def status_text(status: dict[str, Any]) -> str:
    """One line for a status: ``End of life since 2026-01-31 (estimate)``,
    ``Ends on 2026-12-01, in 10 days (entry)``."""
    when, days = status.get("date"), status.get("days")
    kind = status.get("status")
    if kind == "end_of_life":
        if status.get("source") == "reported":
            return f"End of life: {str(status.get('basis') or '').rstrip('.')}"
        text = f"End of life since {when}"
    elif kind == "ending":
        text = f"Ends on {when}, in {days} day{'s' if days != 1 else ''}"
    elif kind == "supported":
        text = f"Supported until {when}"
    else:
        return "Unknown: " + str(status.get("basis") or "no end-of-life information").rstrip(".")
    return f"{text} ({'estimate' if status.get('estimate') else 'administrator entry'})"


def series_evidence(devices: list[dict]) -> dict[tuple[str, str], str]:
    """``(platform, series) -> the newest major release`` any device of that
    series reports as available. A newer major series is a fact about the
    series, so one firewall's report counts for every device on it."""
    found: dict[tuple[str, str], str] = {}
    for device in devices:
        reported = canonical_version(device.get("major_upgrade"))
        platform = str(device.get("platform") or "")
        if not reported or platform != OPNSENSE:
            continue
        key = (platform, series_of(platform, device.get("version")))
        if key[1] and (key not in found or compare_versions(reported, found[key]) > 0):
            found[key] = reported
    return found


def fleet_statuses(
    devices: list[dict], entries: list[dict], today: date, *, warn_days: int = DEFAULT_WARN_DAYS
) -> dict[str, dict[str, Any]]:
    """``device_key -> evaluate(...)`` for every tracked device."""
    evidence = series_evidence(devices)
    statuses: dict[str, dict[str, Any]] = {}
    for device in devices:
        platform = str(device.get("platform") or "")
        series = series_of(platform, device.get("version"), entries)
        statuses[str(device.get("device_key") or "")] = evaluate(
            platform,
            device.get("version"),
            today,
            entries,
            reported=evidence.get((platform, series), ""),
            warn_days=warn_days,
        )
    return statuses


def status_counts(statuses: list[dict[str, Any]]) -> dict[str, int]:
    """How many of ``statuses`` are in each of ``STATUSES``."""
    counts = dict.fromkeys(STATUSES, 0)
    for status in statuses:
        counts[status.get("status") or "unknown"] += 1
    return counts


# ── Generated advisories ─────────────────────────────────────────────────────


def lifecycle_advisory_id(platform: str, series: str) -> str:
    """``lifecycle:<platform>:<series>`` (characters an advisory id cannot
    hold become ``-``)."""
    return f"{ADVISORY_PREFIX}{platform}:{_ID_UNSAFE.sub('-', series)}"[:120]


def lifecycle_advisories(
    devices: list[dict], entries: list[dict], today: date, *, warn_days: int = DEFAULT_WARN_DAYS
) -> list[dict[str, Any]]:
    """One advisory per series that is ending or end of life and runs on at
    least one tracked device: ``high`` once end of life (no more security
    fixes), ``low`` while ending. It matches every version of the series
    on the platform (``<series>.*``), names no CVE, and carries the status
    it was generated for as ``status``."""
    statuses = fleet_statuses(devices, entries, today, warn_days=warn_days)
    by_series: dict[tuple[str, str], dict[str, Any]] = {}
    for device in devices:
        status = statuses.get(str(device.get("device_key") or ""))
        if not status or status["status"] not in ("ending", "end_of_life"):
            continue
        by_series.setdefault((str(device.get("platform") or ""), status["series"]), status)
    advisories: list[dict[str, Any]] = []
    for (platform, series), status in sorted(by_series.items()):
        label = PLATFORMS.get(platform, PLATFORMS["other"])["label"]
        ended = status["status"] == "end_of_life"
        when = status["date"] or ""
        if ended:
            title = f"{label} {series}{_EOL_TITLE}"
        else:
            title = f"{label} {series} reaches end of life on {when}" + (" (estimate)" if status["estimate"] else "")
        successor = status.get("successor") or ""
        advisories.append(
            {
                "advisory_id": lifecycle_advisory_id(platform, series),
                "source": ADVISORY_SOURCE,
                "title": title,
                "severity": "high" if ended else "low",
                "cvss": None,
                "platform": platform,
                "product_match": "",
                "affected_versions": [series_spec(series)],
                "fixed_versions": [successor] if successor else [],
                "cves": [],
                "device_keys": [],
                "url": status.get("url") or "",
                "published": when,
                "summary": f"{status_text(status)}. {status['basis']}"
                + (" No more security fixes are released for this series." if ended else ""),
                "enabled": True,
                "status": status["status"],
            }
        )
    return advisories
