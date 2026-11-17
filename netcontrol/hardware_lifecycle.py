"""Hardware lifecycle: end-of-life notices and support contracts, the rules
and the per-device status, with no I/O.

A **notice** is a vendor's end-of-life announcement for a hardware model:
it names either a device type of the device model catalogue
(``device_types``) or a part number, and up to four milestones (dates as
``YYYY-MM-DD``, ``''`` when unknown), in the order they fall due::

    end_of_sale -> end_of_sw_maintenance -> end_of_security_fixes -> end_of_support

A part-number notice applies to every device whose device type has that
part number or model, and to every device with a module (DCIM) of that part
number, ignoring case. A **support contract** (provider, contract id, start
and end dates, optional cost and support level) covers the devices linked
to it.

``host_status`` folds the notices and contracts of one device into its
lifecycle stage (the furthest milestone passed by any notice that applies),
the next milestone with the days to it, and its contract coverage;
``alert_conditions`` turns that status into the server-side alerts the
lifecycle check raises (``netcontrol.routes.hardware_lifecycle``). Storage:
``routes.db.hardware_lifecycle``; docs: ``docs/hardware-lifecycle.md``.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from netcontrol.custom_fields import CustomFieldError

__all__ = [
    "ALERT_TYPE",
    "COVERAGE_STATES",
    "CURRENCY_RE",
    "DEFAULT_CONTRACT_WARN_DAYS",
    "DEFAULT_SUPPORT_WARN_DAYS",
    "MAX_COST",
    "MAX_WARN_DAYS",
    "MILESTONES",
    "PART_NUMBER_MAX",
    "STAGES",
    "alert_conditions",
    "clean_cost",
    "clean_currency",
    "clean_part_number",
    "clean_warn_days",
    "contract_state",
    "days_until",
    "fleet_summary",
    "host_status",
    "milestone_order_errors",
    "notice_state",
]

# (column, label), in the order the milestones fall due.
MILESTONES: tuple[tuple[str, str], ...] = (
    ("end_of_sale", "End of sale"),
    ("end_of_sw_maintenance", "End of software maintenance"),
    ("end_of_security_fixes", "End of security fixes"),
    ("end_of_support", "Last date of support"),
)
_MILESTONE_LABELS = dict(MILESTONES)
# A device's stage, least to most severe: no notice applies, a notice
# applies but no milestone has passed, then the furthest milestone passed.
STAGES: tuple[str, ...] = ("none", "supported", *(key for key, _ in MILESTONES))
_STAGE_RANK = {stage: rank for rank, stage in enumerate(STAGES)}

# Coverage of a device by its support contracts.
COVERAGE_STATES: tuple[str, ...] = ("covered", "expiring", "expired", "not_started", "none")

PART_NUMBER_MAX = 100
MAX_COST = Decimal("1000000000000")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
DEFAULT_CONTRACT_WARN_DAYS = 60
DEFAULT_SUPPORT_WARN_DAYS = 180
MAX_WARN_DAYS = 3650

ALERT_TYPE = "hardware_lifecycle"


# ── Field rules ──────────────────────────────────────────────────────────────


def clean_part_number(raw: object) -> str:
    """A part number trimmed (may be empty); at most ``PART_NUMBER_MAX``
    characters, no whitespace inside."""
    text = raw.strip() if isinstance(raw, str) else ""
    if len(text) > PART_NUMBER_MAX:
        raise CustomFieldError(f"Part number must be at most {PART_NUMBER_MAX} characters.")
    if any(ch.isspace() for ch in text):
        raise CustomFieldError("Part number must not contain spaces.")
    return text


def clean_currency(raw: object) -> str:
    """An ISO 4217 code (three letters, upper-cased) or ``''``."""
    text = raw.strip().upper() if isinstance(raw, str) else ""
    if text and not CURRENCY_RE.match(text):
        raise CustomFieldError("Currency must be a three-letter code such as USD or EUR.")
    return text


def clean_cost(raw: object) -> str | None:
    """A cost (0 to ``MAX_COST``, at most two decimals) as text, or
    ``None``. Text keeps the exact amount through JSON and the database."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise CustomFieldError("Cost must be a number.")
    try:
        value = Decimal(str(raw).strip())
    except InvalidOperation as exc:
        raise CustomFieldError("Cost must be a number.") from exc
    if not value.is_finite() or value < 0 or value >= MAX_COST:
        raise CustomFieldError("Cost must be from 0 to 999,999,999,999.99.")
    if value != value.quantize(Decimal("0.01")):
        raise CustomFieldError("Cost takes at most two decimals.")
    return str(value.quantize(Decimal("0.01")))


def clean_warn_days(raw: object, label: str) -> int:
    """A warning window in days, 1 to ``MAX_WARN_DAYS``."""
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= MAX_WARN_DAYS:
        raise CustomFieldError(f"{label} must be a whole number of days from 1 to {MAX_WARN_DAYS}.")
    return raw


def milestone_order_errors(values: dict[str, Any]) -> dict[str, str]:
    """Per field, a milestone set before an earlier milestone that is set
    (dates as ``YYYY-MM-DD``; empty ones are skipped)."""
    errors: dict[str, str] = {}
    previous: tuple[str, str] | None = None
    for key, label in MILESTONES:
        value = values.get(key) or ""
        if not value:
            continue
        if previous and value < previous[1]:
            errors[key] = f"{label} must not be before {_MILESTONE_LABELS[previous[0]].lower()} ({previous[1]})."
        else:
            previous = (key, value)
    return errors


# ── Status ───────────────────────────────────────────────────────────────────


def days_until(value: str | None, today: date) -> int | None:
    """Days from ``today`` to a ``YYYY-MM-DD`` date (negative: passed), or
    ``None`` for no or a bad date."""
    if not value:
        return None
    try:
        return (date.fromisoformat(value) - today).days
    except ValueError:
        return None


def notice_state(notice: dict[str, Any], today: date) -> dict[str, Any]:
    """The stage a notice puts a device in on ``today`` (a milestone is
    passed on its date) and its next milestone (``None`` when all set ones
    have passed)."""
    stage = "supported"
    upcoming: dict[str, Any] | None = None
    for key, label in MILESTONES:
        days = days_until(notice.get(key), today)
        if days is None:
            continue
        if days <= 0:
            stage = key
        elif upcoming is None:
            upcoming = {"milestone": key, "label": label, "date": notice[key], "days": days}
    return {"stage": stage, "next": upcoming}


def contract_state(contract: dict[str, Any], today: date, warn_days: int) -> str:
    """``not_started`` before its start, ``expired`` after its end (the end
    date is the last day covered), ``expiring`` within ``warn_days`` of the
    end, else ``covered`` (also for a contract without an end date)."""
    start = days_until(contract.get("start_date"), today)
    if start is not None and start > 0:
        return "not_started"
    end = days_until(contract.get("end_date"), today)
    if end is None:
        return "covered"
    if end < 0:
        return "expired"
    return "expiring" if end <= warn_days else "covered"


def _coverage(contracts: list[dict[str, Any]], today: date, warn_days: int) -> dict[str, Any]:
    if not contracts:
        return {"coverage": "none", "coverage_end": None, "coverage_days": None}
    states = [(contract_state(c, today, warn_days), c) for c in contracts]
    current = [c for s, c in states if s in ("covered", "expiring")]
    if current:
        if any(not c.get("end_date") for c in current):
            return {"coverage": "covered", "coverage_end": None, "coverage_days": None}
        end = max(str(c["end_date"]) for c in current)
        days = days_until(end, today)
        coverage = "expiring" if days is not None and days <= warn_days else "covered"
        return {"coverage": coverage, "coverage_end": end, "coverage_days": days}
    if any(s == "not_started" for s, _ in states):
        start = min(str(c.get("start_date") or "") for s, c in states if s == "not_started")
        return {"coverage": "not_started", "coverage_end": None, "coverage_days": days_until(start, today)}
    end = max(str(c.get("end_date") or "") for c in contracts)
    return {"coverage": "expired", "coverage_end": end, "coverage_days": days_until(end, today)}


def host_status(
    notices: list[dict[str, Any]],
    contracts: list[dict[str, Any]],
    today: date,
    *,
    contract_warn_days: int = DEFAULT_CONTRACT_WARN_DAYS,
) -> dict[str, Any]:
    """The lifecycle status of one device from the notices that apply to it
    and the contracts linked to it.

    ``stage``: the most severe stage of its notices (``none`` without one);
    ``next``: the nearest milestone still to come; ``end_of_sale`` /
    ``end_of_support``: the earliest such date of its notices with
    ``days_to_end_of_sale`` / ``days_to_end_of_support``; ``coverage`` (one
    of ``COVERAGE_STATES``) with ``coverage_end`` (the latest end of the
    contracts in force, ``None`` when one has no end) and ``coverage_days``;
    ``contracts`` each with its own ``state``."""
    stage = "none"
    upcoming: dict[str, Any] | None = None
    earliest: dict[str, str] = {}
    for notice in notices:
        state = notice_state(notice, today)
        if _STAGE_RANK[state["stage"]] > _STAGE_RANK[stage]:
            stage = state["stage"]
        nxt = state["next"]
        if nxt and (upcoming is None or nxt["days"] < upcoming["days"]):
            upcoming = {**nxt, "notice_id": notice.get("id")}
        for key in ("end_of_sale", "end_of_support"):
            value = notice.get(key) or ""
            if value and (key not in earliest or value < earliest[key]):
                earliest[key] = value
    return {
        "stage": stage,
        "next": upcoming,
        "end_of_sale": earliest.get("end_of_sale"),
        "days_to_end_of_sale": days_until(earliest.get("end_of_sale"), today),
        "end_of_support": earliest.get("end_of_support"),
        "days_to_end_of_support": days_until(earliest.get("end_of_support"), today),
        **_coverage(contracts, today, contract_warn_days),
        "contracts": [
            {
                "id": c.get("id"),
                "provider": c.get("provider"),
                "contract_id": c.get("contract_id"),
                "end_date": c.get("end_date"),
                "state": contract_state(c, today, contract_warn_days),
            }
            for c in contracts
        ],
    }


def alert_conditions(status: dict[str, Any], *, support_warn_days: int) -> list[dict[str, Any]]:
    """The alerts one device's status calls for, each ``{kind, severity,
    message}``: ``end_of_support`` (passed, warning) or
    ``end_of_support_soon`` (within ``support_warn_days``, info), and
    ``contract_expired`` (warning) or ``contract_expiring`` (info). The
    message leaves out the device name; the caller adds it."""
    out: list[dict[str, Any]] = []
    days = status.get("days_to_end_of_support")
    if days is not None and days <= 0:
        out.append(
            {
                "kind": "end_of_support",
                "severity": "warning",
                "message": f"passed its last date of support ({status['end_of_support']}).",
            }
        )
    elif days is not None and days <= support_warn_days:
        out.append(
            {
                "kind": "end_of_support_soon",
                "severity": "info",
                "message": f"reaches its last date of support on {status['end_of_support']} (in {days} days).",
            }
        )
    coverage = status.get("coverage")
    if coverage == "expired":
        out.append(
            {
                "kind": "contract_expired",
                "severity": "warning",
                "message": f"has no support contract in force; the last one ended on {status['coverage_end']}.",
            }
        )
    elif coverage == "expiring":
        out.append(
            {
                "kind": "contract_expiring",
                "severity": "info",
                "message": (
                    f"support contract coverage ends on {status['coverage_end']} (in {status['coverage_days']} days)."
                ),
            }
        )
    return out


def fleet_summary(statuses: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts over the per-device statuses: ``by_stage``, ``by_coverage``,
    ``devices``, ``with_notice`` and ``past_end_of_support``."""
    by_stage = dict.fromkeys(STAGES, 0)
    by_coverage = dict.fromkeys(COVERAGE_STATES, 0)
    for status in statuses:
        by_stage[status["stage"]] += 1
        by_coverage[status["coverage"]] += 1
    return {
        "devices": len(statuses),
        "with_notice": len(statuses) - by_stage["none"],
        "past_end_of_support": by_stage["end_of_support"],
        "by_stage": by_stage,
        "by_coverage": by_coverage,
    }
