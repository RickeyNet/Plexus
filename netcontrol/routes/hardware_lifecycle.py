"""Hardware lifecycle API: end-of-life notices, support contracts, the
lifecycle status of every device and of one, a CSV report, the alert check
settings and the alert check itself.

One router (``router``), registered in ``app.py`` behind the ``lifecycle``
feature: reads need ``lifecycle``, writes ``lifecycle.write`` (admins and
the API token pass both). Object scope: a caller limited to selected
inventory groups sees the status of the hosts of those groups and the
support contracts that cover one of them (each listing only those hosts),
changes a contract through a host it can change, reads the shared notice
catalogue, which only unrestricted callers change, and cannot change the
settings or run the check (both cover every device). Every write is validated here
(422 with per-field ``fields``; 409 on a duplicate device type, part number
or contract id; 404 on an unknown id) and audited under the ``lifecycle``
category; notices and contracts are recorded in the change log by the
storage layer.

Alerting: ``run_lifecycle_check`` (scheduled by ``_lifecycle_check_loop``,
and on demand with ``POST /api/lifecycle/check``) evaluates every device
and raises a ``monitoring_alerts`` row (alert type ``hardware_lifecycle``)
for a device past or near its last date of support and for one whose
support contracts expire or have expired. The alert-created hook hands a
new alert to the notification channels. A condition alerts once while it
lasts (``hardware_lifecycle_alerts``), and its alert is resolved when it
clears. Rules: ``netcontrol.hardware_lifecycle``; storage:
``routes.db.hardware_lifecycle``; docs: ``docs/hardware-lifecycle.md``.
"""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import UTC, date, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.bulk_import import csv_text_cell
from netcontrol.circuits import CID_MAX, COMMENTS_MAX, DESCRIPTION_MAX, TEXT_MAX, FieldErrors, clean_date, clean_url
from netcontrol.hardware_lifecycle import (
    ALERT_TYPE,
    COVERAGE_STATES,
    DEFAULT_CONTRACT_WARN_DAYS,
    DEFAULT_SUPPORT_WARN_DAYS,
    MILESTONES,
    STAGES,
    alert_conditions,
    clean_cost,
    clean_currency,
    clean_part_number,
    clean_warn_days,
    contract_state,
    fleet_summary,
    host_status,
    milestone_order_errors,
    notice_state,
)
from netcontrol.object_scope import (
    ScopeModel,
    filter_rows,
    readable_host_ids,
    refuse_scoped,
    register_model,
    request_scope,
    require_host,
    require_model_write,
    require_new_row,
    require_row,
    scope_exempt,
    scoped,
)
from netcontrol.routes.circuits import _conflict, _found, _merged, _raise_if
from netcontrol.routes.reporting import _csv_download_response
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.hardware_lifecycle")

PREFIX = "/api/lifecycle"
# Longest text a body accepts before the real limits are checked.
_RAW_MAX = COMMENTS_MAX + 100
MAX_CONTRACT_HOSTS = 10_000

CHECK_INTERVAL = 6 * 60 * 60
INITIAL_CHECK_DELAY = 180
_check_lock = asyncio.Lock()
_METRIC = "hardware lifecycle"

# A support contract reaches the object scope through the devices it covers
# (``scope_host_ids``, put on the row by ``_scoped_contract``).
CONTRACT_MODEL = register_model(
    ScopeModel(
        "support_contract",
        {"host": "scope_host_ids"},
        not_found="Contract not found",
        description="Hardware support contracts (by the devices they cover)",
    )
)

SETTING_DEFAULTS: dict[str, str] = {
    "alerts_enabled": "true",
    "contract_warn_days": str(DEFAULT_CONTRACT_WARN_DAYS),
    "support_warn_days": str(DEFAULT_SUPPORT_WARN_DAYS),
}


# ── Request bodies ───────────────────────────────────────────────────────────
# Fields left out of a PUT keep their value; the merged record is validated.


class NoticeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_type_id: int | None = None
    part_number: str | None = Field(default=None, max_length=_RAW_MAX)
    end_of_sale: str | None = Field(default=None, max_length=40)
    end_of_sw_maintenance: str | None = Field(default=None, max_length=40)
    end_of_security_fixes: str | None = Field(default=None, max_length=40)
    end_of_support: str | None = Field(default=None, max_length=40)
    documentation_url: str | None = Field(default=None, max_length=_RAW_MAX)
    comments: str | None = Field(default=None, max_length=_RAW_MAX)


class ContractBody(BaseModel):
    """``host_ids``: left out of a PUT keeps the devices the contract
    covers; a list replaces them."""

    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, max_length=_RAW_MAX)
    contract_id: str | None = Field(default=None, max_length=_RAW_MAX)
    start_date: str | None = Field(default=None, max_length=40)
    end_date: str | None = Field(default=None, max_length=40)
    cost: float | str | None = None
    currency: str | None = Field(default=None, max_length=40)
    support_level: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=_RAW_MAX)
    comments: str | None = Field(default=None, max_length=_RAW_MAX)
    host_ids: list[int] | None = Field(default=None, max_length=MAX_CONTRACT_HOSTS)


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts_enabled: bool | None = None
    contract_warn_days: int | None = None
    support_warn_days: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("lifecycle", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _today() -> date:
    return datetime.now(UTC).date()


def _int_setting(raw: dict[str, str], key: str, default: int) -> int:
    try:
        return clean_warn_days(int(raw.get(key) or default), key)
    except TypeError, ValueError:
        return default


async def lifecycle_settings() -> dict[str, Any]:
    """The alert check settings with their defaults, and the last run."""
    raw = {**SETTING_DEFAULTS, **await db.get_lifecycle_settings()}
    return {
        "alerts_enabled": str(raw.get("alerts_enabled")).lower() in ("1", "true", "yes", "on"),
        "contract_warn_days": _int_setting(raw, "contract_warn_days", DEFAULT_CONTRACT_WARN_DAYS),
        "support_warn_days": _int_setting(raw, "support_warn_days", DEFAULT_SUPPORT_WARN_DAYS),
        "last_check_at": raw.get("last_check_at") or "",
        "last_check_alerts": int(raw.get("last_check_alerts") or 0),
    }


def _notice_label(notice: dict) -> str:
    if notice.get("device_type_id") is not None:
        return f"device_type_id={notice['device_type_id']}"
    return f"part_number={notice.get('part_number')}"


# ── Notices ──────────────────────────────────────────────────────────────────


async def _notice_values(raw: dict) -> dict:
    errors = FieldErrors()
    values: dict[str, Any] = {
        "device_type_id": raw.get("device_type_id"),
        "part_number": errors.check("part_number", clean_part_number, raw.get("part_number")) or "",
        "documentation_url": errors.check(
            "documentation_url", clean_url, raw.get("documentation_url"), "Documentation URL"
        )
        or "",
        "comments": errors.text("comments", raw.get("comments"), "Comments", COMMENTS_MAX),
    }
    for key, label in MILESTONES:
        values[key] = errors.check(key, clean_date, raw.get(key), label) or ""
    has_type = values["device_type_id"] is not None
    if has_type == bool(values["part_number"]):
        message = "Choose a device type or enter a part number, not both."
        errors.add("device_type_id", message)
        errors.add("part_number", message)
    elif has_type and await db.get_device_type(int(values["device_type_id"])) is None:
        errors.add("device_type_id", "The device type does not exist.")
    for field, message in milestone_order_errors(values).items():
        errors.add(field, message)
    _raise_if(errors)
    return values


def _notice_out(notice: dict, today: date | None = None) -> dict:
    return {**notice, **notice_state(notice, today or _today())}


@router.get(f"{PREFIX}/notices")
@scope_exempt("the shared end-of-life notice catalogue: no host or inventory group data")
async def list_notices(
    device_type_id: int | None = Query(default=None), q: str | None = Query(default=None, max_length=200)
) -> dict:
    today = _today()
    notices = await db.list_hardware_notices(device_type_id=device_type_id, search=q)
    return {"notices": [_notice_out(n, today) for n in notices]}


@router.get(f"{PREFIX}/notices/{{notice_id}}")
@scoped("catalog")
async def get_notice(notice_id: int, request: Request = None) -> dict:  # type: ignore[assignment]
    """A notice (shared) and the devices it applies to (a scoped caller:
    those it can read)."""
    notice = _found(await db.get_hardware_notice(notice_id), "Notice")
    hosts = await db.hardware_notice_hosts(notice_id)
    readable = await readable_host_ids(request)
    if readable is not None:
        hosts = [h for h in hosts if int(h["id"]) in readable]
    return {**_notice_out(notice), "hosts": hosts}


@router.post(f"{PREFIX}/notices", status_code=201)
@scoped("catalog")
async def create_notice(body: NoticeBody, request: Request) -> dict:
    await require_model_write(request)
    values = await _notice_values(_merged(None, body, db.HARDWARE_NOTICE_FIELDS))
    try:
        record = await db.create_hardware_notice(values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "notice_create", f"id={record['id']} {_notice_label(values)}")
    return _notice_out(record)


@router.put(f"{PREFIX}/notices/{{notice_id}}")
@scoped("catalog")
async def update_notice(notice_id: int, body: NoticeBody, request: Request) -> dict:
    await require_model_write(request)
    current = _found(await db.get_hardware_notice(notice_id), "Notice")
    values = await _notice_values(_merged(current, body, db.HARDWARE_NOTICE_FIELDS))
    try:
        record = await db.update_hardware_notice(notice_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Notice")
    await _audit_write(request, "notice_update", f"id={notice_id} {_notice_label(values)}")
    return _notice_out(record)


@router.delete(f"{PREFIX}/notices/{{notice_id}}")
@scoped("catalog")
async def delete_notice(notice_id: int, request: Request) -> dict:
    await require_model_write(request)
    record = _found(await db.get_hardware_notice(notice_id), "Notice")
    await db.delete_hardware_notice(notice_id)
    await _audit_write(request, "notice_delete", f"id={notice_id} {_notice_label(record)}")
    return {"ok": True}


# ── Contracts ────────────────────────────────────────────────────────────────


async def _contract_values(raw: dict) -> dict:
    errors = FieldErrors()
    values: dict[str, Any] = {
        "provider": errors.name("provider", raw.get("provider"), "Provider"),
        "contract_id": errors.name("contract_id", raw.get("contract_id"), "Contract ID", CID_MAX),
        "start_date": errors.check("start_date", clean_date, raw.get("start_date"), "Start date") or "",
        "end_date": errors.check("end_date", clean_date, raw.get("end_date"), "End date") or "",
        "cost": errors.check("cost", clean_cost, raw.get("cost")),
        "currency": errors.check("currency", clean_currency, raw.get("currency")) or "",
        "support_level": errors.text("support_level", raw.get("support_level"), "Support level", TEXT_MAX),
        "description": errors.text("description", raw.get("description"), "Description", DESCRIPTION_MAX),
        "comments": errors.text("comments", raw.get("comments"), "Comments", COMMENTS_MAX),
    }
    if values["start_date"] and values["end_date"] and values["end_date"] < values["start_date"]:
        errors.add("end_date", "End date must not be before the start date.")
    _raise_if(errors)
    return values


async def _contract_hosts(host_ids: list[int] | None, request: Request | None = None) -> list[int] | None:
    """The devices a contract body names (sorted); 422 naming the unknown
    ones (for a scoped caller, the ones it cannot read too), 403 for a
    scoped caller when one is not writable."""
    if host_ids is None:
        return None
    missing = await db.missing_host_ids(host_ids)
    readable = await readable_host_ids(request)
    if readable is not None:
        missing = sorted({*missing, *(int(h) for h in host_ids if int(h) not in readable)})
    if missing:
        message = f"Unknown device id(s): {', '.join(str(h) for h in missing[:10])}."
        raise HTTPException(status_code=422, detail={"message": message, "fields": {"host_ids": message}})
    if readable is not None and host_ids:
        await require_new_row(request, CONTRACT_MODEL.name, {"scope_host_ids": list(host_ids)})
    return sorted(set(host_ids))


def _scoped_contract(contract: dict) -> dict:
    """The contract with ``scope_host_ids`` (the devices it covers)."""
    return {**contract, "scope_host_ids": [int(h["id"]) for h in contract.get("hosts") or []]}


def _visible_contract(contract: dict, readable: frozenset[int] | None) -> dict:
    """What a caller sees of a contract: for a scoped one (``readable``),
    only the devices it can read."""
    if readable is None:
        return contract
    hosts = [h for h in contract.get("hosts") or [] if int(h["id"]) in readable]
    return {**contract, "hosts": hosts, "host_count": len(hosts)}


async def _require_contract(request: Request | None, contract_id: int, *, write: bool = False) -> dict:
    """The contract; 404 when unknown or (scoped caller) it covers no device
    the caller can read, 403 on ``write`` when it covers none it can change."""
    contract = _found(await db.get_support_contract(contract_id), "Contract")
    if (await request_scope(request)).restricted:
        await require_row(
            request, CONTRACT_MODEL.name, _scoped_contract(contract), write=write, not_found="Contract not found"
        )
    return contract


async def _contract_out(contract: dict, today: date | None = None, warn_days: int | None = None) -> dict:
    if warn_days is None:
        warn_days = (await lifecycle_settings())["contract_warn_days"]
    return {**contract, "state": contract_state(contract, today or _today(), warn_days)}


@router.get(f"{PREFIX}/contracts")
@scoped("list")
async def list_contracts(
    host_id: int | None = Query(default=None),
    state: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=200),
    request: Request = None,  # type: ignore[assignment]
) -> dict:
    readable = await readable_host_ids(request)
    if readable is not None and host_id is not None:
        await require_host(request, host_id)
    today, warn_days = _today(), (await lifecycle_settings())["contract_warn_days"]
    rows = await db.list_support_contracts(host_id=host_id, search=q)
    if readable is not None:
        rows = [
            _visible_contract(c, readable)
            for c in await filter_rows(CONTRACT_MODEL.name, [_scoped_contract(c) for c in rows], request)
        ]
        for c in rows:
            c.pop("scope_host_ids", None)
    contracts = [await _contract_out(c, today, warn_days) for c in rows]
    if state:
        contracts = [c for c in contracts if c["state"] == state]
    return {"contracts": contracts}


@router.get(f"{PREFIX}/contracts/{{contract_id}}")
@scoped("contract")
async def get_contract(contract_id: int, request: Request = None) -> dict:  # type: ignore[assignment]
    contract = await _require_contract(request, contract_id)
    return await _contract_out(_visible_contract(contract, await readable_host_ids(request)))


@router.post(f"{PREFIX}/contracts", status_code=201)
@scoped("create")
async def create_contract(body: ContractBody, request: Request) -> dict:
    values = await _contract_values(_merged(None, body, db.SUPPORT_CONTRACT_FIELDS))
    if (await request_scope(request)).restricted and not body.host_ids:
        # A contract that covers no device would be visible to no scoped caller.
        await require_new_row(request, CONTRACT_MODEL.name, {"scope_host_ids": []})
    hosts = await _contract_hosts(body.host_ids, request) or []
    try:
        record = await db.create_support_contract(values, hosts)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(
        request,
        "contract_create",
        f"id={record['id']} provider={values['provider']} contract_id={values['contract_id']} hosts={len(hosts)}",
    )
    return _visible_contract(await _contract_out(record), await readable_host_ids(request))


@router.put(f"{PREFIX}/contracts/{{contract_id}}")
@scoped("contract")
async def update_contract(contract_id: int, body: ContractBody, request: Request) -> dict:
    current = await _require_contract(request, contract_id, write=True)
    values = await _contract_values(_merged(current, body, db.SUPPORT_CONTRACT_FIELDS))
    hosts = await _contract_hosts(body.host_ids, request)
    writable = await readable_host_ids(request, write=True)
    if hosts is not None and writable is not None:
        # A scoped caller replaces the devices it can change; the others stay.
        kept = [int(h["id"]) for h in current.get("hosts") or [] if int(h["id"]) not in writable]
        hosts = sorted({*hosts, *kept})
    try:
        record = await db.update_support_contract(contract_id, values, hosts)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Contract")
    detail = f"id={contract_id} provider={values['provider']} contract_id={values['contract_id']}"
    if hosts is not None:
        detail += f" hosts={len(hosts)}"
    await _audit_write(request, "contract_update", detail)
    return _visible_contract(await _contract_out(record), await readable_host_ids(request))


@router.delete(f"{PREFIX}/contracts/{{contract_id}}")
@scoped("contract")
async def delete_contract(contract_id: int, request: Request) -> dict:
    record = await _require_contract(request, contract_id, write=True)
    await db.delete_support_contract(contract_id)
    await _audit_write(
        request,
        "contract_delete",
        f"id={contract_id} provider={record['provider']} contract_id={record['contract_id']}",
    )
    return {"ok": True}


# ── Status ───────────────────────────────────────────────────────────────────


async def device_statuses(host_id: int | None = None, settings: dict[str, Any] | None = None) -> list[dict]:
    """The lifecycle status of every device (or one): its identity, the
    ids of the notices that apply and ``host_status``."""
    settings = settings or await lifecycle_settings()
    today = _today()
    hosts = await db.lifecycle_hosts(host_id)
    if not hosts:
        return []
    scope = None if host_id is None else [host_id]
    notices = {int(n["id"]): n for n in await db.list_hardware_notices()}
    notice_ids: dict[int, list[int]] = {}
    for match in await db.hardware_notice_matches(scope):
        ids = notice_ids.setdefault(int(match["host_id"]), [])
        if int(match["notice_id"]) not in ids:
            ids.append(int(match["notice_id"]))
    contracts = await db.support_contracts_by_host(scope)
    out: list[dict] = []
    for host in hosts:
        hid = int(host["id"])
        applied = [notices[n] for n in notice_ids.get(hid, []) if n in notices]
        status = host_status(applied, contracts.get(hid, []), today, contract_warn_days=settings["contract_warn_days"])
        out.append({**host, "host_id": hid, "notice_ids": [int(n["id"]) for n in applied], **status})
    return out


def _filter_statuses(rows: list[dict], stage: str | None, coverage: str | None, q: str | None) -> list[dict]:
    if stage:
        rows = [r for r in rows if r["stage"] == stage]
    if coverage:
        rows = [r for r in rows if r["coverage"] == coverage]
    if q:
        needle = q.lower()
        rows = [
            r
            for r in rows
            if any(needle in str(r.get(k) or "").lower() for k in ("hostname", "ip_address", "device_type_model"))
        ]
    return rows


def _check_choice(value: str | None, allowed: tuple[str, ...], name: str) -> None:
    if value and value not in allowed:
        raise HTTPException(status_code=422, detail=f"{name} must be one of {', '.join(allowed)}")


async def _readable_statuses(request: Request | None, settings: dict[str, Any] | None = None) -> list[dict]:
    """``device_statuses`` of the devices the caller can read."""
    return await filter_rows("host_record", await device_statuses(settings=settings), request)


@router.get(f"{PREFIX}/status")
@scoped("list")
async def fleet_status(
    stage: str | None = Query(default=None, max_length=40),
    coverage: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=200),
    request: Request = None,  # type: ignore[assignment]
) -> dict:
    """Every device's lifecycle status (filtered) and the fleet summary (of
    every device, unfiltered; a scoped caller: of the devices it can read)."""
    _check_choice(stage, STAGES, "stage")
    _check_choice(coverage, COVERAGE_STATES, "coverage")
    settings = await lifecycle_settings()
    rows = await _readable_statuses(request, settings)
    return {
        "summary": fleet_summary(rows),
        "devices": _filter_statuses(rows, stage, coverage, q),
        "settings": await _caller_settings(request, settings, rows),
        "stages": list(STAGES),
        "coverage_states": list(COVERAGE_STATES),
    }


_CSV_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Hostname", "hostname"),
    ("IP Address", "ip_address"),
    ("Manufacturer", "manufacturer_name"),
    ("Device Type", "device_type_model"),
    ("Serial", "serial_number"),
    ("Stage", "stage"),
    ("End of Sale", "end_of_sale"),
    ("Days to End of Sale", "days_to_end_of_sale"),
    ("Last Date of Support", "end_of_support"),
    ("Days to End of Support", "days_to_end_of_support"),
    ("Next Milestone", "next_label"),
    ("Next Milestone Date", "next_date"),
    ("Coverage", "coverage"),
    ("Coverage End", "coverage_end"),
    ("Contracts", "contract_list"),
)


@router.get(f"{PREFIX}/status/export")
@scoped("list")
async def export_status_csv(
    stage: str | None = Query(default=None, max_length=40),
    coverage: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=200),
    request: Request = None,  # type: ignore[assignment]
) -> Response:
    """The device statuses as CSV (the filters of ``GET /status``); text a
    person entered is guarded against spreadsheet formulas."""
    _check_choice(stage, STAGES, "stage")
    _check_choice(coverage, COVERAGE_STATES, "coverage")
    rows = _filter_statuses(await _readable_statuses(request), stage, coverage, q)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([header for header, _ in _CSV_COLUMNS])
    for row in rows:
        nxt = row.get("next") or {}
        flat = {
            **row,
            "next_label": nxt.get("label") or "",
            "next_date": nxt.get("date") or "",
            "contract_list": "; ".join(f"{c['provider']} {c['contract_id']}" for c in row["contracts"]),
        }
        writer.writerow([csv_text_cell(flat.get(key)) for _, key in _CSV_COLUMNS])
    return _csv_download_response(output.getvalue(), "hardware_lifecycle.csv")


@router.get(f"{PREFIX}/hosts/{{host_id}}")
@scoped("host")
async def host_lifecycle(host_id: int, request: Request = None) -> dict:  # type: ignore[assignment]
    """One device's lifecycle: its status, the notices that apply (with how
    and their own stage) and its contracts (with their state)."""
    readable = await readable_host_ids(request)
    if readable is not None:
        await require_host(request, host_id, not_found="Device not found")
    settings = await lifecycle_settings()
    rows = await device_statuses(host_id, settings)
    if not rows:
        raise HTTPException(status_code=404, detail="Device not found")
    today = _today()
    via: dict[int, list[str]] = {}
    for match in await db.hardware_notice_matches([host_id]):
        ways = via.setdefault(int(match["notice_id"]), [])
        if match["via"] not in ways:
            ways.append(match["via"])
    notices = [
        {**_notice_out(n, today), "via": via[int(n["id"])]}
        for n in await db.list_hardware_notices()
        if int(n["id"]) in via
    ]
    contracts = [
        await _contract_out(_visible_contract(c, readable), today, settings["contract_warn_days"])
        for c in await db.list_support_contracts(host_id=host_id)
    ]
    return {"host_id": host_id, "status": rows[0], "notices": notices, "contracts": contracts}


@router.get(f"{PREFIX}/choices")
@scoped("list")
async def choices(request: Request = None) -> dict:  # type: ignore[assignment]
    """What the dialogs' pickers offer: devices and device types (id and
    name only), so a user with the lifecycle feature alone can pick them (a
    scoped caller: the devices it can read)."""
    hosts = (await request_scope(request)).filter_hosts(await db.get_all_hosts())
    types = await db.list_device_types()
    return {
        "hosts": [{"id": h["id"], "hostname": h["hostname"], "ip_address": h.get("ip_address") or ""} for h in hosts],
        "device_types": [
            {"id": t["id"], "manufacturer": t["manufacturer"], "model": t["model"], "part_number": t["part_number"]}
            for t in types
        ],
        "milestones": [{"key": key, "label": label} for key, label in MILESTONES],
    }


# ── Settings and the alert check ─────────────────────────────────────────────


async def _caller_settings(
    request: Request | None, settings: dict[str, Any], rows: list[dict] | None = None
) -> dict[str, Any]:
    """The settings as the caller sees them: for a scoped caller the last
    check's alert count covers the devices it can read (``rows``: their
    statuses, when already read)."""
    if (await request_scope(request)).unrestricted:
        return settings
    if rows is None:
        rows = await _readable_statuses(request, settings)
    count = 0
    if settings["alerts_enabled"]:
        count = sum(len(alert_conditions(r, support_warn_days=settings["support_warn_days"])) for r in rows)
    return {**settings, "last_check_alerts": count}


@router.get(f"{PREFIX}/settings")
@scoped("list")
async def get_settings(request: Request = None) -> dict:  # type: ignore[assignment]
    return await _caller_settings(request, await lifecycle_settings())


@router.put(f"{PREFIX}/settings")
@scoped("refused")
async def update_settings(body: SettingsBody, request: Request) -> dict:
    await refuse_scoped(request)
    errors = FieldErrors()
    values: dict[str, Any] = {}
    if body.alerts_enabled is not None:
        values["alerts_enabled"] = "true" if body.alerts_enabled else "false"
    for key, label in (("contract_warn_days", "Contract warning"), ("support_warn_days", "Support warning")):
        raw = getattr(body, key)
        if raw is not None:
            values[key] = errors.check(key, clean_warn_days, raw, label)
    _raise_if(errors)
    await db.set_lifecycle_settings(values)
    await _audit_write(request, "settings_update", " ".join(f"{k}={v}" for k, v in sorted(values.items())))
    return await lifecycle_settings()


def alert_key(kind: str, host_id: int) -> str:
    return f"lifecycle:{kind}:{host_id}"


async def run_lifecycle_check(trigger: str = "manual") -> dict[str, Any]:
    """Evaluate every device and bring the lifecycle alerts up to date: raise
    one for each new condition, resolve the alerts of conditions that
    cleared. With alerts off, every open lifecycle alert is resolved. Never
    raises; a failure is reported in ``error``."""
    async with _check_lock:
        try:
            settings = await lifecycle_settings()
            wanted: dict[str, tuple[dict, dict]] = {}
            if settings["alerts_enabled"]:
                for row in await device_statuses(settings=settings):
                    for cond in alert_conditions(row, support_warn_days=settings["support_warn_days"]):
                        wanted[alert_key(cond["kind"], row["host_id"])] = (row, cond)
            known = await db.list_lifecycle_alert_states()
            raised = 0
            for key, (row, cond) in wanted.items():
                if key in known:
                    continue
                name = row.get("hostname") or row.get("ip_address") or f"host {row['host_id']}"
                message = f"{name} {cond['message']}"
                await db.create_monitoring_alert(
                    host_id=int(row["host_id"]),
                    poll_id=None,
                    alert_type=ALERT_TYPE,
                    metric=f"{_METRIC}: {cond['kind']}",
                    message=message,
                    severity=cond["severity"],
                    dedup_key=key,
                    hostname=str(row.get("hostname") or ""),
                )
                await db.add_lifecycle_alert_state(key, int(row["host_id"]), cond["kind"], message)
                raised += 1
            cleared = [key for key in known if key not in wanted]
            resolved = 0
            for key in cleared:
                resolved += await db.resolve_monitoring_alerts(key)
            await db.delete_lifecycle_alert_states(cleared)
            await db.touch_lifecycle_alert_states([k for k in wanted if k in known])
            await db.set_lifecycle_settings(
                {
                    "last_check_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_check_alerts": str(len(wanted)),
                }
            )
        except Exception as exc:  # noqa: BLE001 - the scheduler must survive
            LOGGER.warning("lifecycle check (%s) failed: %s", trigger, type(exc).__name__, exc_info=True)
            return {"ok": False, "error": type(exc).__name__, "conditions": 0, "raised": 0, "cleared": 0}
    if raised or cleared:
        LOGGER.info(
            "lifecycle check (%s): %d condition(s), %d raised, %d cleared", trigger, len(wanted), raised, len(cleared)
        )
    return {"ok": True, "conditions": len(wanted), "raised": raised, "cleared": len(cleared), "resolved": resolved}


@router.post(f"{PREFIX}/check")
@scoped("refused")
async def check_now(request: Request) -> dict:
    # Evaluates every device.
    await refuse_scoped(request)
    result = await run_lifecycle_check("manual")
    if not result["ok"]:
        raise HTTPException(status_code=500, detail="The lifecycle check failed; see the server log.")
    await _audit_write(request, "check", f"conditions={result['conditions']} raised={result['raised']}")
    return result


async def _lifecycle_check_loop() -> None:
    """Run the lifecycle alert check on a fixed interval."""
    await asyncio.sleep(INITIAL_CHECK_DELAY)
    while True:
        await run_lifecycle_check("scheduled")
        await asyncio.sleep(CHECK_INTERVAL)
