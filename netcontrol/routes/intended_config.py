"""Intended configuration generation: templates, config contexts, the
rendered intended configuration of each host and its comparison with the
host's newest configuration backup.

Two routers, each registered in ``app.py``:

- ``router`` (signed-in user with the ``config-drift`` feature): read the
  templates, contexts, rows, a host's detail and variables; generate.
- ``admin_router`` (admin): create, change and delete templates and
  contexts; preview a template against a host.

``generate_for_hosts`` renders and compares; ``recompare_host`` compares a
host's stored intended configuration again (``store_device_config`` calls it
when a capture stores a new backup); ``intended_config_loop`` regenerates
every host hourly and shortly after any template or context write. Nothing
here opens a device session. Rules live in ``netcontrol.intended_config``,
storage in ``routes.db.intended_config``. See ``docs/intended-config.md``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.custom_fields import CustomFieldError
from netcontrol.device_model import MAX_ID
from netcontrol.integrations.pathtrace.route_tables import interface_key
from netcontrol.intended_config import (
    COMPLIANCE_STATES,
    STATUSES,
    TEMPLATE_TEXT_MAX,
    Renderer,
    clean_context_data,
    clean_description,
    clean_device_type,
    clean_kind,
    clean_name_value,
    clean_template_text,
    clean_weight,
    compare_configs,
    merge_contexts,
    select_template,
    verdict,
)
from netcontrol.object_scope import (
    group_filter,
    request_scope,
    require_group,
    require_host,
    require_hosts,
    require_object_host,
    scoped,
)
from netcontrol.routes.custom_fields import attach_custom_data
from netcontrol.routes.device_model import check_device_values
from netcontrol.routes.git_sources import reject_git_owned
from netcontrol.routes.shared import _audit, _corr_id, _session_user

LOGGER = logging.getLogger("plexus.intended_config")

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/intended-config"
# Background generation: first run after start, the hourly interval, and the
# pause after a template or context write so a burst of writes runs once.
FIRST_RUN_DELAY_SECONDS = 180
INTERVAL_SECONDS = 3600
WAKE_DELAY_SECONDS = 5
# The name a preview of unsaved text renders under when no template is named.
PREVIEW_NAME = "(preview)"
# Longest text a body accepts before trimming; the real limits are checked
# after trimming and answer 400.
_RAW_MAX = 1000
_ID = Field(default=None, ge=1, le=MAX_ID)

# Set by ``intended_config_loop`` on its own event loop; a write sets it.
_wake: asyncio.Event | None = None


# ── Request bodies ───────────────────────────────────────────────────────────


class TemplateBody(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    kind: str = Field(max_length=20)
    device_type: str = Field(default="", max_length=_RAW_MAX)
    role_id: int | None = _ID
    site_id: int | None = _ID
    group_id: int | None = _ID
    template_text: str = Field(default="", max_length=TEMPLATE_TEXT_MAX * 2)
    description: str = Field(default="", max_length=_RAW_MAX * 4)
    enabled: bool = True


class ContextBody(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    weight: int = 1000
    data: Any = None
    description: str = Field(default="", max_length=_RAW_MAX * 4)
    enabled: bool = True
    device_type: str = Field(default="", max_length=_RAW_MAX)
    role_id: int | None = _ID
    site_id: int | None = _ID
    group_id: int | None = _ID
    host_id: int | None = _ID


class PreviewBody(BaseModel):
    host_id: int = Field(ge=1, le=MAX_ID)
    template_id: int | None = _ID
    template_text: str | None = Field(default=None, max_length=TEMPLATE_TEXT_MAX * 2)


class GenerateBody(BaseModel):
    host_ids: list[int] | None = Field(default=None, max_length=100_000)
    group_id: int | None = _ID


# ── Helpers ──────────────────────────────────────────────────────────────────


def _clean(fn, raw):
    """Run a ``netcontrol.intended_config`` validator; 400 with its message."""
    try:
        return fn(raw)
    except CustomFieldError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("config", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def wake_generation() -> None:
    """Ask the background loop to regenerate soon (a write changed what
    hosts render)."""
    if _wake is not None:
        try:
            _wake.set()
        except RuntimeError:  # pragma: no cover - the loop that made it is gone
            pass


async def _check_scope(body: TemplateBody | ContextBody) -> None:
    """400 when a scope id names no record."""
    refs = {k: getattr(body, k) for k in ("role_id", "site_id") if getattr(body, k) is not None}
    if refs:
        await check_device_values(refs)
    if body.group_id is not None and await db.get_group(body.group_id) is None:
        raise HTTPException(status_code=400, detail=f"Unknown group id {body.group_id}.")
    host_id = getattr(body, "host_id", None)
    if host_id is not None and await db.get_host(host_id) is None:
        raise HTTPException(status_code=400, detail=f"Unknown host id {host_id}.")


async def _template_values(body: TemplateBody) -> dict:
    kind = _clean(clean_kind, body.kind)
    values = {
        "name": _clean(clean_name_value, body.name),
        "kind": kind,
        "device_type": _clean(clean_device_type, body.device_type),
        "role_id": body.role_id,
        "site_id": body.site_id,
        "group_id": body.group_id,
        "template_text": _clean(clean_template_text, body.template_text),
        "description": _clean(clean_description, body.description),
        "enabled": body.enabled,
    }
    if kind == "snippet":
        # A snippet is only included by other templates: it has no scope.
        values.update(device_type="", role_id=None, site_id=None, group_id=None)
    else:
        await _check_scope(body)
    issue = Renderer().check(values["template_text"], values["name"])
    if issue is not None:
        raise HTTPException(status_code=400, detail={"message": issue.message, "line": issue.line})
    return values


async def _context_values(body: ContextBody) -> dict:
    values = {
        "name": _clean(clean_name_value, body.name),
        "weight": _clean(clean_weight, body.weight),
        "data": _clean(clean_context_data, body.data),
        "description": _clean(clean_description, body.description),
        "enabled": body.enabled,
        "device_type": _clean(clean_device_type, body.device_type),
        "role_id": body.role_id,
        "site_id": body.site_id,
        "group_id": body.group_id,
        "host_id": body.host_id,
    }
    await _check_scope(body)
    return values


def _taken(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


# ── Template variables ───────────────────────────────────────────────────────


def _id_key(row: dict) -> str:
    return str(row["id"])


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _interfaces(rows: list[dict], addresses: list[dict]) -> list[dict]:
    by_key: dict[str, list[dict]] = {}
    for a in addresses:
        by_key.setdefault(str(a["interface_key"] or interface_key(a["interface"])), []).append(
            {
                "address": a["address"],
                "prefix_length": int(a["prefix_length"] or 0),
                "network": a["network"] or "",
                "vrf": a["vrf_name"] or "",
                "role": a["role"] or "",
            }
        )
    return [
        {
            "name": r["name"] or "",
            "description": r["description"] or "",
            "admin_state": r["admin_state"] or "",
            "oper_state": r["oper_state"] or "",
            "speed_mbps": int(r["speed_mbps"] or 0),
            "access_vlan": int(r["access_vlan"] or 0),
            "trunk_vlans": r["trunk_vlans"] or "",
            "addresses": by_key.get(interface_key(r["name"] or ""), []),
        }
        for r in rows
    ]


async def build_variables(hosts: list[dict], contexts: list[dict]) -> dict[int, tuple[dict, list[dict]]]:
    """``host id -> (variables, contexts used)`` for every host, from a fixed
    number of bulk reads whatever the number of hosts (see
    ``docs/intended-config.md`` for the variables)."""
    if not hosts:
        return {}
    ids = [int(h["id"]) for h in hosts]
    display = await db.get_device_display_objects(hosts)
    groups = {int(g["id"]): g for g in await db.get_all_groups()}
    host_data: list[dict[str, Any]] = [{"id": i} for i in ids]
    await attach_custom_data("host", host_data, _id_key)
    group_data: list[dict[str, Any]] = [
        {"id": gid} for gid in sorted({int(h["group_id"]) for h in hosts if h.get("group_id") is not None})
    ]
    await attach_custom_data("group", group_data, _id_key)
    group_custom = {g["id"]: g for g in group_data}
    vlan_records = await db.list_vlan_records()
    vrfs = await db.get_vrfs_for_hosts(ids)
    interfaces, addresses = await db.get_interfaces_for_hosts(ids)

    out: dict[int, tuple[dict, list[dict]]] = {}
    for host, custom in zip(hosts, host_data, strict=True):
        host_id = int(host["id"])
        hardware = display["hardware"].get(int(host["device_type_id"])) if host.get("device_type_id") else None
        role = display["role"].get(int(host["role_id"])) if host.get("role_id") else None
        status = (
            display["lifecycle_status"].get(int(host["lifecycle_status_id"]))
            if host.get("lifecycle_status_id")
            else None
        )
        site = display["site"].get(int(host["site_id"])) if host.get("site_id") else None
        group_id = int(host["group_id"]) if host.get("group_id") is not None else None
        group = groups.get(group_id) if group_id is not None else None
        site_id = int(site["id"]) if site else None
        variables = {
            "host": {
                "id": host_id,
                "name": _text(host.get("hostname")),
                "ip": _text(host.get("ip_address")),
                "driver": _text(host.get("device_type")),
                "model": _text(host.get("model")),
                "serial": _text(host.get("serial_number")),
                "version": _text(host.get("software_version")),
                "category": _text(host.get("device_category")),
                "vrf": _text(host.get("vrf_name")),
                "vlan_id": _text(host.get("vlan_id")),
                "location_detail": _text(host.get("location_detail")),
                "role": _text(role["name"]) if role else "",
                "status": _text(status["name"]) if status else "",
                "manufacturer": _text(hardware["manufacturer"]) if hardware else "",
                "hardware_model": _text(hardware["model"]) if hardware else "",
                "part_number": _text(hardware.get("part_number")) if hardware else "",
                "tags": [t["name"] for t in custom["tags"]],
                "custom_fields": custom["custom_fields"],
            },
            "group": {
                "id": group_id,
                "name": _text(group["name"]) if group else "",
                "description": _text(group.get("description")) if group else "",
                "tags": [t["name"] for t in group_custom[group_id]["tags"]] if group_id in group_custom else [],
                "custom_fields": group_custom[group_id]["custom_fields"] if group_id in group_custom else {},
            },
            "site": {
                "id": site_id,
                "name": _text(site["name"]) if site else "",
                "description": _text(site.get("description")) if site else "",
                "address": _text(site.get("address")) if site else "",
            },
            "vlans": [
                {"vid": v["vid"], "name": v["name"], "description": v["description"]}
                for v in vlan_records
                if v["site_id"] == site_id
            ],
            "vrfs": vrfs.get(host_id, []),
            "interfaces": _interfaces(interfaces.get(host_id, []), addresses.get(host_id, [])),
        }
        context, used = merge_contexts(contexts, host)
        variables["context"] = context
        out[host_id] = (variables, used)
    return out


# ── Generation ───────────────────────────────────────────────────────────────


async def _compare(host_id: int, status: str, config_text: str) -> dict:
    """The comparison fields of a row against the host's newest backup."""
    backup = await db.get_newest_host_config_backup(host_id) if status == "ok" else None
    comparison = compare_configs(config_text, str(backup.get("config_text") or "")) if backup else None
    return {
        "compliance": verdict(status, backup is not None, comparison),
        "backup_id": int(backup["id"]) if backup else None,
        "missing_count": comparison.missing_count if comparison else 0,
        "extra_count": comparison.extra_count if comparison else 0,
    }


async def generate_for_hosts(host_ids: list[int] | None = None) -> dict[str, int]:
    """Render and compare the hosts (``None``: every host). A host no
    template matches loses its row. Returns ``{hosts, generated, changed,
    errors, no_template}``: hosts looked at, rows written (``errors`` of
    them failed to render), rows whose text changed, hosts with no
    template."""
    if host_ids is None:
        hosts = await db.get_all_hosts()
    else:
        hosts = await db.get_hosts_by_ids(sorted({int(h) for h in host_ids})) if host_ids else []
    counts = {"hosts": len(hosts), "generated": 0, "changed": 0, "errors": 0, "no_template": 0}
    if not hosts:
        return counts
    templates = await db.list_config_templates()
    contexts = await db.list_config_contexts()
    renderer = Renderer({t["name"]: t["template_text"] for t in templates})
    variables = await build_variables(hosts, contexts)
    unmatched: list[int] = []
    for host in hosts:
        host_id = int(host["id"])
        template = select_template(templates, host)
        if template is None:
            counts["no_template"] += 1
            unmatched.append(host_id)
            continue
        result = await asyncio.to_thread(renderer.render, template["name"], variables[host_id][0])
        status = "ok" if result.ok else "error"
        values = {
            "template_id": template["id"],
            "template_name": template["name"],
            "status": status,
            "error": result.error.as_text() if result.error else "",
            "config_text": result.config_text,
            **await _compare(host_id, status, result.config_text),
        }
        changed = await db.save_intended_config(host_id, values)
        if changed is None:  # the host was deleted meanwhile
            continue
        counts["generated"] += 1
        counts["changed"] += int(changed)
        counts["errors"] += int(status == "error")
    if unmatched:
        await db.delete_intended_configs(unmatched)
    return counts


async def recompare_host(host_id: int) -> str | None:
    """Compare the host's stored intended configuration with its newest
    backup again; the new compliance, or ``None`` when the host has no
    intended configuration or the comparison failed (logged; never raised,
    so a capture never fails here)."""
    try:
        row = await db.get_intended_config(int(host_id))
        if row is None:
            return None
        fields = await _compare(int(host_id), row["status"], row["config_text"])
        await db.set_intended_comparison(int(host_id), **fields)
        return str(fields["compliance"])
    except Exception as exc:
        LOGGER.warning("intended config: host %s not compared: %s", host_id, exc)
        return None


async def intended_config_loop() -> None:
    """Regenerate every host ``FIRST_RUN_DELAY_SECONDS`` after start, then
    hourly, and ``WAKE_DELAY_SECONDS`` after a template or context write
    (writes during the pause coalesce into one run)."""
    global _wake
    _wake = asyncio.Event()
    await asyncio.sleep(FIRST_RUN_DELAY_SECONDS)
    while True:
        _wake.clear()
        try:
            result = await generate_for_hosts(None)
            if result["generated"]:
                LOGGER.info(
                    "intended config: %s hosts generated, %s changed, %s errors",
                    result["generated"],
                    result["changed"],
                    result["errors"],
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("intended config generation failed: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(_wake.wait(), timeout=INTERVAL_SECONDS)
            await asyncio.sleep(WAKE_DELAY_SECONDS)
        except TimeoutError:
            pass


# ── Templates ────────────────────────────────────────────────────────────────


# Templates and contexts are global records, not host data. For a caller
# limited to selected inventory groups, a template's ``host_count`` counts
# only the hosts it may read, and a template or context that targets an
# inventory group (or, a context, a host) it may not read is hidden.


async def _visible_records(request: Request, records: list[dict]) -> list[dict]:
    """The templates or contexts the caller may see: every one for an
    unrestricted caller; else those whose ``group_id`` (and ``host_id``'s
    group) is unset or readable."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return records
    host_ids = sorted({int(r["host_id"]) for r in records if r.get("host_id") is not None})
    host_groups = {int(h["id"]): h.get("group_id") for h in await db.get_hosts_by_ids(host_ids)} if host_ids else {}

    def visible(record: dict) -> bool:
        if record.get("group_id") is not None and not scope.can_read_group(record["group_id"]):
            return False
        host_id = record.get("host_id")
        return host_id is None or scope.can_read_group(host_groups.get(int(host_id)))

    return [r for r in records if visible(r)]


async def _visible_record(request: Request, record: dict | None, what: str) -> dict:
    """``record`` when the caller may see it; 404 like an unknown id otherwise."""
    record = _found(record, what)
    return _found(next(iter(await _visible_records(request, [record])), None), what)


@router.get(f"{PREFIX}/templates")
@scoped("list")
async def list_templates(request: Request) -> dict:
    templates = await db.list_config_templates(**await group_filter(request))
    return {"templates": await _visible_records(request, templates)}


@router.get(f"{PREFIX}/templates/{{template_id}}")
@scoped("template")
async def get_template(template_id: int, request: Request) -> dict:
    return await _visible_record(
        request, await db.get_config_template(template_id, **await group_filter(request)), "Template"
    )


@admin_router.post(f"{PREFIX}/templates", status_code=201)
async def create_template(body: TemplateBody, request: Request) -> dict:
    values = await _template_values(body)
    try:
        record = await db.create_config_template(values, _session_user(request))
    except ValueError as exc:
        raise _taken(exc) from exc
    await _audit_write(request, "intended_template_create", f"id={record['id']} name={record['name']}")
    wake_generation()
    return record


@admin_router.put(f"{PREFIX}/templates/{{template_id}}")
async def update_template(template_id: int, body: TemplateBody, request: Request) -> dict:
    _found(await db.get_config_template(template_id), "Template")
    values = await _template_values(body)
    try:
        record = await db.update_config_template(template_id, values, _session_user(request))
    except ValueError as exc:
        raise _taken(exc) from exc
    record = _found(record, "Template")
    await _audit_write(request, "intended_template_update", f"id={template_id} name={record['name']}")
    wake_generation()
    return record


@admin_router.delete(f"{PREFIX}/templates/{{template_id}}")
async def delete_template(template_id: int, request: Request) -> dict:
    record = _found(await db.get_config_template(template_id), "Template")
    await db.delete_config_template(template_id)
    await _audit_write(request, "intended_template_delete", f"id={template_id} name={record['name']}")
    wake_generation()
    return {"ok": True}


# ── Contexts ─────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/contexts")
@scoped("list")
async def list_contexts(request: Request) -> dict:
    return {"contexts": await _visible_records(request, await db.list_config_contexts())}


@router.get(f"{PREFIX}/contexts/{{context_id}}")
@scoped("context")
async def get_context(context_id: int, request: Request) -> dict:
    return await _visible_record(request, await db.get_config_context(context_id), "Context")


@admin_router.post(f"{PREFIX}/contexts", status_code=201)
async def create_context(body: ContextBody, request: Request) -> dict:
    values = await _context_values(body)
    try:
        record = await db.create_config_context(values, _session_user(request))
    except ValueError as exc:
        raise _taken(exc) from exc
    await _audit_write(request, "intended_context_create", f"id={record['id']} name={record['name']}")
    wake_generation()
    return record


@admin_router.put(f"{PREFIX}/contexts/{{context_id}}")
async def update_context(context_id: int, body: ContextBody, request: Request) -> dict:
    reject_git_owned(_found(await db.get_config_context(context_id), "Context"), "context")
    values = await _context_values(body)
    try:
        record = await db.update_config_context(context_id, values, _session_user(request))
    except ValueError as exc:
        raise _taken(exc) from exc
    record = _found(record, "Context")
    await _audit_write(request, "intended_context_update", f"id={context_id} name={record['name']}")
    wake_generation()
    return record


@admin_router.delete(f"{PREFIX}/contexts/{{context_id}}")
async def delete_context(context_id: int, request: Request) -> dict:
    record = _found(await db.get_config_context(context_id), "Context")
    reject_git_owned(record, "context")
    await db.delete_config_context(context_id)
    await _audit_write(request, "intended_context_delete", f"id={context_id} name={record['name']}")
    wake_generation()
    return {"ok": True}


# ── Preview and variables ────────────────────────────────────────────────────


async def _host_variables(host_id: int) -> tuple[dict, dict, list[dict]]:
    host = _found(await db.get_host(host_id), "Host")
    built = await build_variables([host], await db.list_config_contexts())
    variables, used = built[int(host["id"])]
    return host, variables, used


@admin_router.post(f"{PREFIX}/preview")
async def preview(body: PreviewBody) -> dict:
    """Render a template for a host without storing anything: the given
    text (under the named template's name when ``template_id`` is given
    too), else the named template, else the template the host selects."""
    host, variables, _used = await _host_variables(body.host_id)
    templates = await db.list_config_templates()
    texts = {t["name"]: t["template_text"] for t in templates}
    named = _found(await db.get_config_template(body.template_id), "Template") if body.template_id else None
    if body.template_text is not None:
        name = named["name"] if named else PREVIEW_NAME
        texts[name] = _clean(clean_template_text, body.template_text)
        template_name: str | None = named["name"] if named else None
    else:
        chosen = named or select_template(templates, host)
        if chosen is None:
            return {
                "template_name": None,
                "config_text": "",
                "error": {"message": "No template matches this host.", "template": None, "line": None},
            }
        name = template_name = chosen["name"]
    result = await asyncio.to_thread(Renderer(texts).render, name, variables)
    return {
        "template_name": template_name,
        "config_text": result.config_text,
        "error": result.error.as_dict() if result.error else None,
    }


@router.get(f"{PREFIX}/hosts/{{host_id}}/variables")
@scoped("host")
async def host_variables(host_id: int, request: Request) -> dict:
    if (await request_scope(request)).restricted:
        await require_host(request, host_id)
    _host, variables, used = await _host_variables(host_id)
    return {
        "variables": variables,
        "contexts": [{"id": c["id"], "name": c["name"], "weight": c["weight"]} for c in used],
    }


# ── Hosts ────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/hosts")
@scoped("list")
async def list_hosts(
    request: Request,
    group_id: int | None = Query(default=None, ge=1, le=MAX_ID),
    compliance: str | None = Query(default=None, max_length=20),
    status: str | None = Query(default=None, max_length=20),
) -> dict:
    if compliance is not None and compliance not in COMPLIANCE_STATES:
        raise HTTPException(status_code=400, detail=f"compliance must be one of: {', '.join(COMPLIANCE_STATES)}.")
    if status is not None and status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(STATUSES)}.")
    scope_filter = await group_filter(request)
    return {
        "rows": await db.list_intended_configs(group_id=group_id, compliance=compliance, status=status, **scope_filter),
        "counts": await db.summarize_intended_configs(**scope_filter),
    }


_INTENDED_NOT_FOUND = "Intended configuration not found"


@router.get(f"{PREFIX}/hosts/{{host_id}}")
@scoped("host")
async def get_host_detail(host_id: int, request: Request) -> dict:
    """The row with its text, each intended line marked when the compared
    backup lacks it, the backup's extra lines, and that backup."""
    await require_object_host(request, host_id, not_found=_INTENDED_NOT_FOUND)
    row = _found(await db.get_intended_config(host_id), "Intended configuration")
    backup = await db.get_config_backup(row["backup_id"]) if row["backup_id"] else None
    if backup is not None and int(backup.get("host_id") or 0) != host_id:
        backup = None
    comparison = compare_configs(row["config_text"], str(backup.get("config_text") or "")) if backup else None
    return {
        **row,
        "lines": comparison.lines if comparison else [{"text": t, "missing": False} for t in _lines(row)],
        "extra": comparison.extra if comparison else [],
        "backup": {"id": int(backup["id"]), "captured_at": backup.get("captured_at") or ""} if backup else None,
    }


def _lines(row: dict) -> list[str]:
    text = row["config_text"]
    return text[:-1].split("\n") if text.endswith("\n") else (text.split("\n") if text else [])


@router.post(f"{PREFIX}/generate")
@scoped("hosts")
async def generate(body: GenerateBody, request: Request) -> dict:
    """Render and compare now: ``host_ids``, else the hosts of ``group_id``,
    else every host. Storing a host's intended configuration is a write: a
    caller limited to selected inventory groups needs write on each host
    or the group named, and "every host" means every host it may write."""
    restricted = (await request_scope(request)).restricted
    if body.host_ids is not None:
        scope = f"hosts={len(body.host_ids)}"
        if restricted:
            await require_hosts(request, body.host_ids, write=True)
        result = await generate_for_hosts(body.host_ids)
    elif body.group_id is not None:
        if restricted:
            await require_group(request, body.group_id, write=True)
        else:
            _found(await db.get_group(body.group_id), "Group")
        scope = f"group_id={body.group_id}"
        result = await generate_for_hosts([int(h["id"]) for h in await db.get_hosts_for_group(body.group_id)])
    elif restricted:
        scope = "all writable"
        writable = (await request_scope(request)).write_groups
        result = await generate_for_hosts(
            [int(h["id"]) for h in await db.get_all_hosts() if h.get("group_id") in writable]
        )
    else:
        scope = "all"
        result = await generate_for_hosts(None)
    await _audit_write(
        request,
        "intended_generate",
        f"{scope} generated={result['generated']} changed={result['changed']} errors={result['errors']}",
    )
    return result
