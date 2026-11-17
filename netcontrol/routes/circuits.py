"""Circuits API: providers, provider networks, circuit types, circuits with
their A / Z terminations, and the circuits that land on a device.

One router (``router``), registered in ``app.py`` behind the ``circuits``
feature: reads need ``circuits``, writes ``circuits.write`` (admins and the
API token pass both). Every write is validated here (422 with per-field
``fields``; 409 on a duplicate name or circuit id, or a delete of a record in
use; 404 on an unknown id) and audited under the ``circuits`` category. The
storage is ``routes.db.circuits``, the rules ``netcontrol.circuits``. See
``docs/circuits.md``.

Utilisation: a circuit with a committed rate and a termination on a device
port reports the port's latest in / out rate from the interface counters the
topology poller already stores (``interface_stats``); nothing new is polled.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.circuits import (
    CID_MAX,
    COMMENTS_MAX,
    DESCRIPTION_MAX,
    STATUSES,
    TERM_SIDES,
    TEXT_MAX,
    FieldErrors,
    clean_date,
    clean_kbps,
    clean_status,
    clean_term_side,
    clean_url,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.routes.topology import _calc_interface_utilization

router = APIRouter()

PREFIX = "/api/circuits"
# Longest text a body accepts before the real limits are checked.
_RAW_MAX = COMMENTS_MAX + 100

# What a missing reference is called in its 422 message.
_REF_LABELS = {
    "provider_id": "The provider",
    "circuit_type_id": "The circuit type",
    "tenant_id": "The tenant",
    "billing_circuit_id": "The billing circuit",
    "site_id": "The site",
    "provider_network_id": "The provider network",
    "host_id": "The device",
}


# ── Request bodies ───────────────────────────────────────────────────────────
# Fields left out of a PUT keep their value; the merged record is validated.


class ProviderBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    account: str | None = Field(default=None, max_length=_RAW_MAX)
    portal_url: str | None = Field(default=None, max_length=_RAW_MAX)
    noc_contact: str | None = Field(default=None, max_length=_RAW_MAX)
    admin_contact: str | None = Field(default=None, max_length=_RAW_MAX)
    comments: str | None = Field(default=None, max_length=_RAW_MAX)


class ProviderNetworkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: int | None = None
    name: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=_RAW_MAX)


class CircuitTypeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=_RAW_MAX)


class TerminationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    term_side: str | None = Field(default=None, max_length=8)
    site_id: int | None = None
    provider_network_id: int | None = None
    host_id: int | None = None
    interface_name: str | None = Field(default=None, max_length=_RAW_MAX)
    port_speed_kbps: int | None = None
    upstream_speed_kbps: int | None = None
    xconnect_id: str | None = Field(default=None, max_length=_RAW_MAX)
    pp_info: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=_RAW_MAX)


class CircuitBody(BaseModel):
    """``terminations``: left out keeps the circuit's terminations; a list
    replaces them (a side not listed is deleted)."""

    model_config = ConfigDict(extra="forbid")

    cid: str | None = Field(default=None, max_length=_RAW_MAX)
    provider_id: int | None = None
    circuit_type_id: int | None = None
    status: str | None = Field(default=None, max_length=40)
    tenant_id: int | None = None
    install_date: str | None = Field(default=None, max_length=40)
    termination_date: str | None = Field(default=None, max_length=40)
    commit_rate_kbps: int | None = None
    description: str | None = Field(default=None, max_length=_RAW_MAX)
    comments: str | None = Field(default=None, max_length=_RAW_MAX)
    billing_circuit_id: int | None = None
    terminations: list[TerminationBody] | None = Field(default=None, max_length=2)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


def _raise_if(errors: FieldErrors) -> None:
    if errors:
        raise HTTPException(status_code=422, detail={"message": errors.message(), "fields": errors.fields})


def _merged(current: dict | None, body: BaseModel, fields: tuple[str, ...]) -> dict:
    """The record a write leaves: ``current`` (``None`` for a create) with
    the fields the body sets."""
    base = {f: (current or {}).get(f) for f in fields}
    return {**base, **{k: v for k, v in body.model_dump(exclude_unset=True).items() if k in fields}}


async def _check_refs(errors: FieldErrors, refs: dict[str, int | None], prefix: str = "") -> None:
    for field in await db.circuit_missing_refs(refs):
        errors.add(f"{prefix}{field}", f"{_REF_LABELS[field]} does not exist.")


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("circuits", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


def _in_use(message: str, usage: dict[str, int]) -> HTTPException:
    return HTTPException(status_code=409, detail={"message": message, "affected": sum(usage.values()), "usage": usage})


# ── Providers ────────────────────────────────────────────────────────────────


async def _provider_values(raw: dict) -> dict:
    errors = FieldErrors()
    values = {
        "name": errors.name("name", raw.get("name"), "Name"),
        "account": errors.text("account", raw.get("account"), "Account"),
        "portal_url": errors.check("portal_url", clean_url, raw.get("portal_url")) or "",
        "noc_contact": errors.text("noc_contact", raw.get("noc_contact"), "NOC contact", DESCRIPTION_MAX),
        "admin_contact": errors.text("admin_contact", raw.get("admin_contact"), "Admin contact", DESCRIPTION_MAX),
        "comments": errors.text("comments", raw.get("comments"), "Comments", COMMENTS_MAX),
    }
    _raise_if(errors)
    return values


@router.get(f"{PREFIX}/providers")
async def list_providers() -> dict:
    return {"providers": await db.list_circuit_providers()}


@router.get(f"{PREFIX}/providers/{{provider_id}}")
async def get_provider(provider_id: int) -> dict:
    provider = _found(await db.get_circuit_provider(provider_id), "Provider")
    return {**provider, "networks": await db.list_provider_networks(provider_id)}


@router.post(f"{PREFIX}/providers", status_code=201)
async def create_provider(body: ProviderBody, request: Request) -> dict:
    values = await _provider_values(_merged(None, body, db.CIRCUIT_PROVIDER_FIELDS))
    try:
        record = await db.create_circuit_provider(values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "provider_create", f"id={record['id']} name={values['name']}")
    return record


@router.put(f"{PREFIX}/providers/{{provider_id}}")
async def update_provider(provider_id: int, body: ProviderBody, request: Request) -> dict:
    current = _found(await db.get_circuit_provider(provider_id), "Provider")
    values = await _provider_values(_merged(current, body, db.CIRCUIT_PROVIDER_FIELDS))
    try:
        record = await db.update_circuit_provider(provider_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Provider")
    await _audit_write(request, "provider_update", f"id={provider_id} name={values['name']}")
    return record


@router.delete(f"{PREFIX}/providers/{{provider_id}}")
async def delete_provider(provider_id: int, request: Request) -> dict:
    record = _found(await db.get_circuit_provider(provider_id), "Provider")
    usage = await db.circuit_provider_usage(provider_id)
    if sum(usage.values()):
        raise _in_use(
            f"Provider {record['name']} has {usage['circuits']} circuits and {usage['terminations']} "
            "terminations in its networks; it cannot be deleted.",
            usage,
        )
    try:
        await db.delete_circuit_provider(provider_id)
    except db.CircuitInUseError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "provider_delete", f"id={provider_id} name={record['name']}")
    return {"ok": True}


# ── Provider networks ────────────────────────────────────────────────────────


async def _network_values(raw: dict) -> dict:
    errors = FieldErrors()
    values = {
        "name": errors.name("name", raw.get("name"), "Name"),
        "description": errors.text("description", raw.get("description"), "Description", DESCRIPTION_MAX),
    }
    _raise_if(errors)
    return values


@router.get(f"{PREFIX}/provider-networks")
async def list_provider_networks(provider_id: int | None = Query(default=None)) -> dict:
    return {"provider_networks": await db.list_provider_networks(provider_id)}


@router.get(f"{PREFIX}/provider-networks/{{network_id}}")
async def get_provider_network(network_id: int) -> dict:
    return _found(await db.get_provider_network(network_id), "Provider network")


@router.post(f"{PREFIX}/provider-networks", status_code=201)
async def create_provider_network(body: ProviderNetworkBody, request: Request) -> dict:
    errors = FieldErrors()
    if body.provider_id is None:
        errors.add("provider_id", "Choose a provider.")
    else:
        await _check_refs(errors, {"provider_id": body.provider_id})
    _raise_if(errors)
    values = await _network_values(_merged(None, body, ("name", "description")))
    provider_id = int(body.provider_id or 0)
    try:
        record = await db.create_provider_network(provider_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(
        request, "provider_network_create", f"id={record['id']} provider_id={provider_id} name={values['name']}"
    )
    return record


@router.put(f"{PREFIX}/provider-networks/{{network_id}}")
async def update_provider_network(network_id: int, body: ProviderNetworkBody, request: Request) -> dict:
    current = _found(await db.get_provider_network(network_id), "Provider network")
    if body.provider_id is not None and body.provider_id != current["provider_id"]:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "A provider network cannot move to another provider.",
                "fields": {"provider_id": "A provider network cannot move to another provider."},
            },
        )
    values = await _network_values(_merged(current, body, ("name", "description")))
    try:
        record = await db.update_provider_network(network_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Provider network")
    await _audit_write(request, "provider_network_update", f"id={network_id} name={values['name']}")
    return record


@router.delete(f"{PREFIX}/provider-networks/{{network_id}}")
async def delete_provider_network(network_id: int, request: Request) -> dict:
    record = _found(await db.get_provider_network(network_id), "Provider network")
    used = await db.provider_network_usage(network_id)
    if used:
        raise _in_use(
            f"Provider network {record['name']} has {used} circuit terminations; it cannot be deleted.",
            {"terminations": used},
        )
    try:
        await db.delete_provider_network(network_id)
    except db.CircuitInUseError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "provider_network_delete", f"id={network_id} name={record['name']}")
    return {"ok": True}


# ── Circuit types ────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/circuit-types")
async def list_circuit_types() -> dict:
    return {"circuit_types": await db.list_circuit_types()}


@router.get(f"{PREFIX}/circuit-types/{{type_id}}")
async def get_circuit_type(type_id: int) -> dict:
    return _found(await db.get_circuit_type(type_id), "Circuit type")


@router.post(f"{PREFIX}/circuit-types", status_code=201)
async def create_circuit_type(body: CircuitTypeBody, request: Request) -> dict:
    values = await _network_values(_merged(None, body, ("name", "description")))
    try:
        record = await db.create_circuit_type(values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "circuit_type_create", f"id={record['id']} name={values['name']}")
    return record


@router.put(f"{PREFIX}/circuit-types/{{type_id}}")
async def update_circuit_type(type_id: int, body: CircuitTypeBody, request: Request) -> dict:
    current = _found(await db.get_circuit_type(type_id), "Circuit type")
    values = await _network_values(_merged(current, body, ("name", "description")))
    try:
        record = await db.update_circuit_type(type_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Circuit type")
    await _audit_write(request, "circuit_type_update", f"id={type_id} name={values['name']}")
    return record


@router.delete(f"{PREFIX}/circuit-types/{{type_id}}")
async def delete_circuit_type(type_id: int, request: Request) -> dict:
    record = _found(await db.get_circuit_type(type_id), "Circuit type")
    used = await db.circuit_type_usage(type_id)
    if used:
        raise _in_use(
            f"Circuit type {record['name']} is used by {used} circuits; it cannot be deleted.", {"circuits": used}
        )
    try:
        await db.delete_circuit_type(type_id)
    except db.CircuitInUseError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "circuit_type_delete", f"id={type_id} name={record['name']}")
    return {"ok": True}


# ── Validation of circuits and terminations ──────────────────────────────────


async def _circuit_values(raw: dict, errors: FieldErrors) -> dict:
    values: dict[str, Any] = {
        "cid": errors.name("cid", raw.get("cid"), "Circuit ID", CID_MAX),
        "provider_id": raw.get("provider_id"),
        "circuit_type_id": raw.get("circuit_type_id"),
        "status": errors.check("status", clean_status, raw.get("status") or "active") or "active",
        "tenant_id": raw.get("tenant_id"),
        "install_date": errors.check("install_date", clean_date, raw.get("install_date"), "Install date") or "",
        "termination_date": errors.check(
            "termination_date", clean_date, raw.get("termination_date"), "Termination date"
        )
        or "",
        "commit_rate_kbps": errors.check("commit_rate_kbps", clean_kbps, raw.get("commit_rate_kbps"), "Commit rate"),
        "description": errors.text("description", raw.get("description"), "Description", DESCRIPTION_MAX),
        "comments": errors.text("comments", raw.get("comments"), "Comments", COMMENTS_MAX),
        "billing_circuit_id": raw.get("billing_circuit_id"),
    }
    if values["provider_id"] is None:
        errors.add("provider_id", "Choose a provider.")
    if values["circuit_type_id"] is None:
        errors.add("circuit_type_id", "Choose a circuit type.")
    if values["install_date"] and values["termination_date"] and values["termination_date"] < values["install_date"]:
        errors.add("termination_date", "Termination date must not be before the install date.")
    await _check_refs(
        errors, {k: values[k] for k in ("provider_id", "circuit_type_id", "tenant_id", "billing_circuit_id")}
    )
    return values


async def _termination_values(raw: dict, side: str, errors: FieldErrors) -> dict:
    """The stored fields of one termination; errors are keyed
    ``terminations.<side>.<field>``."""
    prefix = f"terminations.{side}."
    values: dict[str, Any] = {
        "site_id": raw.get("site_id"),
        "provider_network_id": raw.get("provider_network_id"),
        "host_id": raw.get("host_id"),
        "interface_name": errors.text(prefix + "interface_name", raw.get("interface_name"), "Interface", TEXT_MAX),
        "port_speed_kbps": errors.check(
            prefix + "port_speed_kbps", clean_kbps, raw.get("port_speed_kbps"), "Port speed"
        ),
        "upstream_speed_kbps": errors.check(
            prefix + "upstream_speed_kbps", clean_kbps, raw.get("upstream_speed_kbps"), "Upstream speed"
        ),
        "xconnect_id": errors.text(prefix + "xconnect_id", raw.get("xconnect_id"), "Cross-connect ID"),
        "pp_info": errors.text(prefix + "pp_info", raw.get("pp_info"), "Patch panel / port"),
        "description": errors.text(prefix + "description", raw.get("description"), "Description", DESCRIPTION_MAX),
    }
    has_site = values["site_id"] is not None
    has_network = values["provider_network_id"] is not None
    if has_site == has_network:
        message = (
            "Choose a site or a provider network, not both."
            if has_site
            else "Choose a site or a provider network for the termination."
        )
        errors.add(prefix + "site_id", message)
    if values["interface_name"] and values["host_id"] is None:
        errors.add(prefix + "interface_name", "Choose the device the interface belongs to.")
    await _check_refs(errors, {k: values[k] for k in ("site_id", "provider_network_id", "host_id")}, prefix=prefix)
    return values


async def _terminations_of(body: list[TerminationBody], errors: FieldErrors) -> dict[str, dict]:
    """``side -> stored fields`` of a circuit body's terminations."""
    found: dict[str, dict] = {}
    for index, term in enumerate(body):
        raw = term.model_dump()
        side = errors.check(f"terminations.{index}.term_side", clean_term_side, raw.get("term_side"))
        if side is None:
            continue
        if side in found:
            errors.add(f"terminations.{side}.term_side", f"A circuit has one {side} termination.")
            continue
        found[side] = await _termination_values(raw, side, errors)
    return found


async def _apply_terminations(circuit_id: int, wanted: dict[str, dict], current: list[dict]) -> None:
    """Make the circuit's terminations ``wanted`` (sides not in it go)."""
    by_side = {t["term_side"]: t for t in current}
    for side in TERM_SIDES:
        existing = by_side.get(side)
        if side in wanted:
            if existing is None:
                await db.create_circuit_termination(circuit_id, side, wanted[side])
            else:
                await db.update_circuit_termination(int(existing["id"]), wanted[side])
        elif existing is not None:
            await db.delete_circuit_termination(int(existing["id"]))


# ── Utilisation ──────────────────────────────────────────────────────────────


def _stat_for(stats: list[dict], interface_name: str) -> dict | None:
    """The interface counters row of ``interface_name`` (exact name first,
    then ignoring case)."""
    for row in stats:
        if row.get("if_name") == interface_name:
            return row
    wanted = interface_name.lower()
    for row in stats:
        if str(row.get("if_name") or "").lower() == wanted:
            return row
    return None


async def _with_utilisation(circuits: list[dict]) -> list[dict]:
    """Each circuit with ``utilisation``: per termination on a device port,
    the port's latest in / out rate and its share of the committed rate.
    Empty without a committed rate or without counters for the port."""
    stats_cache: dict[int, list[dict]] = {}
    out = []
    for circuit in circuits:
        found: list[dict] = []
        commit = circuit.get("commit_rate_kbps")
        for term in circuit.get("terminations", []):
            host_id, name = term.get("host_id"), term.get("interface_name") or ""
            if not commit or host_id is None or not name:
                continue
            if host_id not in stats_cache:
                stats_cache[host_id] = await db.get_interface_stats_for_host(int(host_id))
            stat = _stat_for(stats_cache[host_id], name)
            rate = _calc_interface_utilization(stat) if stat else None
            if rate is None:
                continue
            commit_bps = int(commit) * 1000
            found.append(
                {
                    "term_side": term["term_side"],
                    "host_id": host_id,
                    "interface_name": name,
                    "in_bps": rate["in_bps"],
                    "out_bps": rate["out_bps"],
                    "polled_at": stat.get("polled_at") if stat else None,
                    "commit_rate_kbps": int(commit),
                    "in_pct_of_commit": round(rate["in_bps"] * 100 / commit_bps, 1),
                    "out_pct_of_commit": round(rate["out_bps"] * 100 / commit_bps, 1),
                }
            )
        out.append({**circuit, "utilisation": found})
    return out


# ── Circuits ─────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/circuits")
async def list_circuits(
    provider_id: int | None = Query(default=None),
    circuit_type_id: int | None = Query(default=None),
    status: str | None = Query(default=None, max_length=40),
    tenant_id: int | None = Query(default=None),
    site_id: int | None = Query(default=None),
    host_id: int | None = Query(default=None),
    q: str | None = Query(default=None, max_length=CID_MAX),
) -> dict:
    """``q``: part of the circuit id or the description, ignoring case."""
    if status is not None and status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {', '.join(STATUSES)}")
    circuits = await db.list_circuits(
        provider_id=provider_id,
        circuit_type_id=circuit_type_id,
        status=status,
        tenant_id=tenant_id,
        site_id=site_id,
        host_id=host_id,
        search=(q or "").strip() or None,
    )
    return {"circuits": circuits}


@router.get(f"{PREFIX}/circuits/{{circuit_id}}")
async def get_circuit(circuit_id: int) -> dict:
    circuit = _found(await db.get_circuit(circuit_id), "Circuit")
    return (await _with_utilisation([circuit]))[0]


@router.post(f"{PREFIX}/circuits", status_code=201)
async def create_circuit(body: CircuitBody, request: Request) -> dict:
    errors = FieldErrors()
    values = await _circuit_values(_merged(None, body, db.CIRCUIT_FIELDS), errors)
    terminations = await _terminations_of(body.terminations or [], errors)
    _raise_if(errors)
    try:
        record = await db.create_circuit(values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _apply_terminations(int(record["id"]), terminations, [])
    await _audit_write(
        request, "circuit_create", f"id={record['id']} cid={values['cid']} provider_id={values['provider_id']}"
    )
    return _found(await db.get_circuit(int(record["id"])), "Circuit")


@router.put(f"{PREFIX}/circuits/{{circuit_id}}")
async def update_circuit(circuit_id: int, body: CircuitBody, request: Request) -> dict:
    current = _found(await db.get_circuit(circuit_id), "Circuit")
    errors = FieldErrors()
    values = await _circuit_values(_merged(current, body, db.CIRCUIT_FIELDS), errors)
    replace = "terminations" in body.model_fields_set
    terminations = await _terminations_of(body.terminations or [], errors) if replace else {}
    _raise_if(errors)
    try:
        await db.update_circuit(circuit_id, values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    if replace:
        await _apply_terminations(circuit_id, terminations, current["terminations"])
    await _audit_write(request, "circuit_update", f"id={circuit_id} cid={values['cid']}")
    return _found(await db.get_circuit(circuit_id), "Circuit")


@router.delete(f"{PREFIX}/circuits/{{circuit_id}}")
async def delete_circuit(circuit_id: int, request: Request) -> dict:
    record = _found(await db.get_circuit(circuit_id), "Circuit")
    for term in record["terminations"]:
        await db.delete_circuit_termination(int(term["id"]))
    await db.delete_circuit(circuit_id)
    await _audit_write(request, "circuit_delete", f"id={circuit_id} cid={record['cid']}")
    return {"ok": True}


def _side(raw: str) -> str:
    errors = FieldErrors()
    side = errors.check("term_side", clean_term_side, raw)
    _raise_if(errors)
    return str(side)


@router.put(f"{PREFIX}/circuits/{{circuit_id}}/terminations/{{side}}")
async def put_termination(circuit_id: int, side: str, body: TerminationBody, request: Request) -> dict:
    """Create or replace the circuit's ``side`` (A or Z) termination."""
    term_side = _side(side)
    circuit = _found(await db.get_circuit(circuit_id), "Circuit")
    existing = next((t for t in circuit["terminations"] if t["term_side"] == term_side), None)
    raw = body.model_dump(exclude_unset=True)
    if existing is not None:
        raw = {**{f: existing.get(f) for f in db.CIRCUIT_TERMINATION_FIELDS}, **raw}
    errors = FieldErrors()
    values = await _termination_values(raw, term_side, errors)
    _raise_if(errors)
    if existing is None:
        record = await db.create_circuit_termination(circuit_id, term_side, values)
    else:
        record = _found(await db.update_circuit_termination(int(existing["id"]), values), "Termination")
    await _audit_write(request, "termination_save", f"circuit_id={circuit_id} cid={circuit['cid']} side={term_side}")
    return record


@router.delete(f"{PREFIX}/circuits/{{circuit_id}}/terminations/{{side}}")
async def delete_termination(circuit_id: int, side: str, request: Request) -> dict:
    term_side = _side(side)
    circuit = _found(await db.get_circuit(circuit_id), "Circuit")
    existing = _found(next((t for t in circuit["terminations"] if t["term_side"] == term_side), None), "Termination")
    await db.delete_circuit_termination(int(existing["id"]))
    await _audit_write(request, "termination_delete", f"circuit_id={circuit_id} cid={circuit['cid']} side={term_side}")
    return {"ok": True}


# ── Devices ──────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/hosts/{{host_id}}/circuits")
async def host_circuits(host_id: int) -> dict:
    """The circuits with a termination on the device, with utilisation."""
    _found(await db.get_host(host_id), "Host")
    circuits = await db.list_circuits(host_id=host_id)
    return {"host_id": host_id, "circuits": await _with_utilisation(circuits)}


@router.get(f"{PREFIX}/hosts/{{host_id}}/interfaces")
async def host_interfaces(host_id: int) -> dict:
    """The interface names Plexus knows for the device (interface inventory,
    interface counters, cables), for the termination's interface picker."""
    _found(await db.get_host(host_id), "Host")
    return {"host_id": host_id, "interfaces": await db.list_host_interface_names(host_id)}


@router.get(f"{PREFIX}/choices")
async def choices() -> dict:
    """What the circuit dialog's pickers offer: devices, sites and tenants
    (id and name only), so a user with the circuits feature alone can pick
    them."""
    hosts = await db.get_all_hosts()
    sites = await db.list_geo_sites()
    tenants = await db.list_tenants()
    return {
        "hosts": [{"id": h["id"], "hostname": h["hostname"], "ip_address": h.get("ip_address") or ""} for h in hosts],
        "sites": sorted(
            ({"id": s["id"], "name": s["name"]} for s in sites), key=lambda s: (str(s["name"]).lower(), s["id"])
        ),
        "tenants": [{"id": t["id"], "name": t["name"]} for t in tenants],
    }
