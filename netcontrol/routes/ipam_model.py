"""IPAM namespaces, route targets, VLAN groups, RIRs and aggregates.

Two routers, registered in ``app.py`` next to the VRF and VLAN routers (and
like them before the IPAM router, whose greedy
``/api/ipam/subnets/{subnet:path}`` must never shadow these paths):

- ``router`` (signed-in user with the ``ipam`` feature): read.
- ``admin_router`` (admin): create, change and delete, like every IPAM
  write.

Object scope (``netcontrol.object_scope``, models ``namespace``, ``rir``,
``route_target``, ``aggregate``, ``vlan_group``): namespaces and RIRs are
reference data every IPAM reader sees; a route target or an aggregate is
read by a scoped caller when it is of one of their tenants or of no tenant;
a VLAN group when its site (or a site of its region) is theirs or it has no
scope. A detail lists only the VRFs, prefixes and VLANs the caller may
read. Counts and an aggregate's usage are totals over every prefix, like
the address space they describe. Writes are admin only.
Errors: 404 unknown record, 409 a taken name or a record in use, 422 a value
a rule refuses (``{"message", "fields"}`` for a field), 400 an unknown
tenant or site id (the device model's contract). Every write is audited
(category ``ipam_model``) and recorded in the change log by the storage
layer. Rules: ``netcontrol.ipam_model``; storage: ``routes.db.ipam_model``;
docs: ``docs/ipam.md``, ``docs/vrfs-and-vlans.md``.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError
from netcontrol.ipam_model import (
    DESCRIPTION_MAX,
    GLOBAL_NAMESPACE_ID,
    clean_aggregate_prefix,
    clean_date,
    clean_description,
    clean_record_name,
    clean_route_target,
    clean_vid_range,
)
from netcontrol.network_objects import clean_vrf_name
from netcontrol.object_scope import filter_rows, request_scope, require_row, scoped
from netcontrol.routes.device_model import check_device_values
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/ipam"
_RAW_MAX = 200
# Most route targets one side of a VRF takes.
VRF_RT_MAX = 500


# ── Request bodies ───────────────────────────────────────────────────────────


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NamespaceBody(_Strict):
    name: str = Field(max_length=_RAW_MAX)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class NamespaceUpdate(_Strict):
    name: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class RouteTargetBody(_Strict):
    name: str = Field(max_length=_RAW_MAX)
    tenant_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class RouteTargetUpdate(_Strict):
    name: str | None = Field(default=None, max_length=_RAW_MAX)
    tenant_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class VrfRouteTargets(_Strict):
    import_ids: list[int] = Field(default_factory=list, max_length=VRF_RT_MAX)
    export_ids: list[int] = Field(default_factory=list, max_length=VRF_RT_MAX)


class VlanGroupBody(_Strict):
    name: str = Field(max_length=_RAW_MAX)
    site_id: int | None = None
    region_id: int | None = None
    min_vid: int = 1
    max_vid: int = 4094
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class VlanGroupUpdate(_Strict):
    name: str | None = Field(default=None, max_length=_RAW_MAX)
    site_id: int | None = None
    region_id: int | None = None
    min_vid: int | None = None
    max_vid: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class RirBody(_Strict):
    name: str = Field(max_length=_RAW_MAX)
    is_private: bool = False
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class RirUpdate(_Strict):
    name: str | None = Field(default=None, max_length=_RAW_MAX)
    is_private: bool | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class AggregateBody(_Strict):
    prefix: str = Field(max_length=_RAW_MAX)
    rir_id: int
    date_added: str = Field(default="", max_length=20)
    tenant_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class AggregateUpdate(_Strict):
    prefix: str | None = Field(default=None, max_length=_RAW_MAX)
    rir_id: int | None = None
    date_added: str | None = Field(default=None, max_length=20)
    tenant_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class PrefixNamespace(_Strict):
    namespace_id: int


# ── Helpers ──────────────────────────────────────────────────────────────────


def _invalid(message: str, field: str | None = None) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": message, "fields": {field: message} if field else {}})


def _clean(field: str, fn, *args):
    """Run a validator; 422 naming ``field`` with its message."""
    try:
        return fn(*args)
    except CustomFieldError as exc:
        raise _invalid(str(exc), field) from exc


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("ipam_model", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


async def _write(call):
    """Run a storage write: 409 for a taken name, 422 for a broken rule."""
    try:
        return await call
    except db.DcimRuleError as exc:
        raise _invalid(str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _delete(kind: str, label: str, record_id: int, request: Request, describe: str) -> dict:
    usage = await db.count_dcim_usage(kind, record_id)
    if usage:
        what = ", ".join(f"{n} {name}" for name, n in usage.items())
        raise HTTPException(
            status_code=409,
            detail={"message": f"{label} is in use ({what}); it cannot be deleted.", "usage": usage},
        )
    await db.delete_dcim_record(kind, record_id)
    await _audit_write(request, f"{kind}_delete", f"id={record_id} {describe}")
    return {"ok": True}


def _sent(body: BaseModel) -> dict[str, Any]:
    return {k: getattr(body, k) for k in body.model_fields_set}


async def check_namespace(namespace_id: int) -> None:
    """400 naming ``namespace_id`` when it names no namespace."""
    if await db.get_dcim_record("namespace", namespace_id) is None:
        message = f"No record with id {namespace_id}."
        raise HTTPException(
            status_code=400, detail={"message": "Unknown id: namespace_id.", "fields": {"namespace_id": message}}
        )


async def resolve_prefix_namespace(namespace_id: int | None, vrf: str) -> int:
    """The namespace a new prefix in ``vrf`` goes to: the given one (400
    when it names no namespace), else the VRF record's, else Global. A VRF
    record lives in one namespace: 422 when the given one is another."""
    vrf_namespace = await db.vrf_namespace_id(vrf.strip()) if vrf.strip() else None
    if namespace_id is None:
        return vrf_namespace if vrf_namespace is not None else GLOBAL_NAMESPACE_ID
    await check_namespace(namespace_id)
    if vrf_namespace is not None and vrf_namespace != int(namespace_id):
        raise _invalid(f"VRF {vrf.strip()} is in another namespace.", "namespace_id")
    if vrf.strip() and vrf_namespace is None and int(namespace_id) != GLOBAL_NAMESPACE_ID:
        # The VRF record the prefix write would create goes to the
        # prefix's namespace, not Global.
        try:
            await db.create_vrf(name=clean_vrf_name(vrf), namespace_id=int(namespace_id))
        except CustomFieldError, ValueError:
            pass
    return int(namespace_id)


async def _check_region(region_id: int | None) -> None:
    if region_id is not None and await db.get_region(region_id) is None:
        message = f"No record with id {region_id}."
        raise HTTPException(
            status_code=400, detail={"message": "Unknown id: region_id.", "fields": {"region_id": message}}
        )


# ── Namespaces ───────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/namespaces")
@scoped("list")
async def list_namespaces(request: Request, q: str = Query("", max_length=200)) -> dict:
    return {
        "namespaces": await filter_rows("namespace", await db.list_dcim_records("namespace", {}, q.strip()), request)
    }


@router.get(f"{PREFIX}/namespaces/{{namespace_id}}")
@scoped("object")
async def get_namespace(namespace_id: int, request: Request) -> dict:
    """The namespace with the VRFs and prefixes the caller may read."""
    detail = await require_row(request, "namespace", await db.get_namespace_detail(namespace_id))
    detail["vrfs"] = await filter_rows("vrf", detail["vrfs"], request)
    detail["prefixes"] = await filter_rows("ipam_prefix", detail["prefixes"], request)
    return detail


@admin_router.post(f"{PREFIX}/namespaces", status_code=201)
async def create_namespace(body: NamespaceBody, request: Request) -> dict:
    values = {
        "name": _clean("name", clean_record_name, body.name, "Namespace name"),
        "description": _clean("description", clean_description, body.description),
    }
    record = await _write(db.create_dcim_record("namespace", values, _session_user(request)))
    await _audit_write(request, "namespace_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/namespaces/{{namespace_id}}")
async def update_namespace(namespace_id: int, body: NamespaceUpdate, request: Request) -> dict:
    _found(await db.get_dcim_record("namespace", namespace_id), "Namespace")
    values: dict[str, Any] = {}
    if body.name is not None:
        values["name"] = _clean("name", clean_record_name, body.name, "Namespace name")
    if body.description is not None:
        values["description"] = _clean("description", clean_description, body.description)
    record = _found(
        await _write(db.update_dcim_record("namespace", namespace_id, values, _session_user(request))), "Namespace"
    )
    await _audit_write(request, "namespace_update", f"id={namespace_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/namespaces/{{namespace_id}}")
async def delete_namespace(namespace_id: int, request: Request) -> dict:
    record = _found(await db.get_dcim_record("namespace", namespace_id), "Namespace")
    if int(namespace_id) == GLOBAL_NAMESPACE_ID:
        raise HTTPException(status_code=409, detail="The Global namespace cannot be deleted.")
    return await _delete("namespace", f"Namespace {record['name']}", namespace_id, request, f"name={record['name']}")


@admin_router.put(f"{PREFIX}/prefixes/{{prefix_id}}/namespace")
async def set_prefix_namespace(prefix_id: int, body: PrefixNamespace, request: Request) -> dict:
    """Move a prefix to another namespace (409 when that namespace has the
    prefix in its VRF already; 422 when the prefix's VRF record lives in
    another namespace: move the VRF instead)."""
    await check_namespace(body.namespace_id)
    current = _found(await db.get_ipam_prefix(prefix_id), "IPAM prefix")
    vrf = str(current.get("vrf") or "").strip()
    vrf_namespace = await db.vrf_namespace_id(vrf) if vrf else None
    if vrf_namespace is not None and vrf_namespace != body.namespace_id:
        raise _invalid(f"VRF {vrf} is in another namespace; move the VRF instead.", "namespace_id")
    try:
        prefix = await db.set_prefix_namespace(prefix_id, body.namespace_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    prefix = _found(prefix, "IPAM prefix")
    await _audit_write(request, "prefix_namespace", f"prefix_id={prefix_id} namespace_id={body.namespace_id}")
    return {"ok": True, "prefix": prefix}


# ── Route targets ────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/route-targets")
@scoped("list")
async def list_route_targets(
    request: Request,
    tenant_id: int | None = Query(default=None),
    vrf_id: int | None = Query(default=None),
    q: str = Query("", max_length=200),
) -> dict:
    """``tenant_id``, ``vrf_id`` (imported or exported by the VRF) and ``q``
    (name or description) narrow the list."""
    rows = await db.list_dcim_records("route_target", {"tenant_id": tenant_id, "vrf_id": vrf_id}, q.strip())
    return {"route_targets": await filter_rows("route_target", rows, request)}


@router.get(f"{PREFIX}/route-targets/{{rt_id}}")
@scoped("object")
async def get_route_target(rt_id: int, request: Request) -> dict:
    """The route target with the VRFs (the caller may read) that import or export it."""
    record = await require_row(request, "route_target", await db.get_dcim_record("route_target", rt_id))
    return {**record, "vrfs": await filter_rows("vrf", await db.list_route_target_vrfs(rt_id), request)}


@admin_router.post(f"{PREFIX}/route-targets", status_code=201)
async def create_route_target(body: RouteTargetBody, request: Request) -> dict:
    values = {
        "name": _clean("name", clean_route_target, body.name),
        "tenant_id": body.tenant_id,
        "description": _clean("description", clean_description, body.description),
    }
    await check_device_values({"tenant_id": body.tenant_id})
    record = await _write(db.create_dcim_record("route_target", values, _session_user(request)))
    await _audit_write(request, "route_target_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/route-targets/{{rt_id}}")
async def update_route_target(rt_id: int, body: RouteTargetUpdate, request: Request) -> dict:
    _found(await db.get_dcim_record("route_target", rt_id), "Route target")
    values = _sent(body)
    if values.get("name") is not None:
        values["name"] = _clean("name", clean_route_target, values["name"])
    elif "name" in values:
        raise _invalid("A value is required.", "name")
    if values.get("description") is not None:
        values["description"] = _clean("description", clean_description, values["description"])
    elif "description" in values:
        values["description"] = ""
    await check_device_values({"tenant_id": values.get("tenant_id")})
    record = _found(
        await _write(db.update_dcim_record("route_target", rt_id, values, _session_user(request))), "Route target"
    )
    await _audit_write(request, "route_target_update", f"id={rt_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/route-targets/{{rt_id}}")
async def delete_route_target(rt_id: int, request: Request) -> dict:
    record = _found(await db.get_dcim_record("route_target", rt_id), "Route target")
    return await _delete("route_target", f"Route target {record['name']}", rt_id, request, f"name={record['name']}")


@router.get(f"{PREFIX}/vrfs/{{vrf_id}}/route-targets")
@scoped("object")
async def get_vrf_route_targets(vrf_id: int, request: Request) -> dict:
    await require_row(request, "vrf", await db.get_vrf(vrf_id), not_found="VRF not found")
    return {"vrf_id": vrf_id, **await readable_vrf_route_targets(vrf_id, request)}


async def readable_vrf_route_targets(vrf_id: int, request: Request) -> dict[str, list[dict]]:
    """The VRF's ``import`` and ``export`` route targets the caller may read
    (shared with the VRF detail of ``netcontrol.routes.network_objects``)."""
    found = await db.get_vrf_route_targets(vrf_id)
    return {side: await filter_rows("route_target", rows, request) for side, rows in found.items()}


@admin_router.put(f"{PREFIX}/vrfs/{{vrf_id}}/route-targets")
async def set_vrf_route_targets(vrf_id: int, body: VrfRouteTargets, request: Request) -> dict:
    """Replace the route targets the VRF imports and exports."""
    vrf = _found(await db.get_vrf(vrf_id), "VRF")
    missing = await db.set_vrf_route_targets(vrf_id, body.import_ids, body.export_ids)
    if missing:
        message = "No route target with id " + ", ".join(str(m) for m in missing) + "."
        raise HTTPException(status_code=400, detail={"message": message, "fields": {"route_target_ids": message}})
    await _audit_write(
        request,
        "vrf_route_targets",
        f"id={vrf_id} name={vrf['name']} import={sorted(set(body.import_ids))} export={sorted(set(body.export_ids))}",
    )
    return {"vrf_id": vrf_id, **await db.get_vrf_route_targets(vrf_id)}


# ── VLAN groups ──────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/vlan-groups")
@scoped("list")
async def list_vlan_groups(
    request: Request,
    site_id: int | None = Query(default=None),
    region_id: int | None = Query(default=None),
    q: str = Query("", max_length=200),
) -> dict:
    rows = await db.list_dcim_records("vlan_group", {"site_id": site_id, "region_id": region_id}, q.strip())
    return {"vlan_groups": await _readable_groups(rows, request)}


async def _readable_groups(rows: list[dict], request: Request) -> list[dict]:
    """The VLAN groups the caller may read (``scope_site_ids`` added to
    check, not answered)."""
    if (await request_scope(request)).unrestricted:
        return rows
    keyed = await filter_rows("vlan_group", await db.with_vlan_group_scope(rows), request)
    return [{k: v for k, v in g.items() if k != "scope_site_ids"} for g in keyed]


async def _require_group(vlan_group_id: int, request: Request) -> dict:
    found = await _readable_groups(
        [_found(await db.get_dcim_record("vlan_group", vlan_group_id), "VLAN group")], request
    )
    return _found(found[0] if found else None, "VLAN group")


@router.get(f"{PREFIX}/vlan-groups/{{vlan_group_id}}")
@scoped("object")
async def get_vlan_group(vlan_group_id: int, request: Request) -> dict:
    """The group with the VLANs the caller may read (``available`` and
    ``next_vid`` count every VLAN of the group: an id another tenant holds
    is still taken)."""
    await _require_group(vlan_group_id, request)
    detail = _found(await db.get_vlan_group_detail(vlan_group_id), "VLAN group")
    detail["vlans"] = await filter_rows("vlan", detail["vlans"], request)
    return detail


@router.get(f"{PREFIX}/vlan-groups/{{vlan_group_id}}/next-vid")
@scoped("object")
async def next_vlan_group_vid(vlan_group_id: int, request: Request) -> dict:
    """The lowest free VLAN id of the group (``vid`` null: the group is full)."""
    await _require_group(vlan_group_id, request)
    try:
        vid = await db.next_vlan_group_vid(vlan_group_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="VLAN group not found") from exc
    return {"vlan_group_id": vlan_group_id, "vid": vid}


async def _group_values(values: dict, current: dict | None = None) -> dict:
    if values.get("name") is not None:
        values["name"] = _clean("name", clean_record_name, values["name"], "VLAN group name")
    elif "name" in values:
        raise _invalid("A value is required.", "name")
    if "description" in values:
        values["description"] = _clean("description", clean_description, values["description"] or "")
    if "min_vid" in values or "max_vid" in values:
        merged = {**(current or {}), **values}
        if merged.get("min_vid") is None or merged.get("max_vid") is None:
            raise _invalid("A value is required.", "min_vid" if merged.get("min_vid") is None else "max_vid")
        values["min_vid"], values["max_vid"] = _clean("min_vid", clean_vid_range, merged["min_vid"], merged["max_vid"])
    merged = {**(current or {}), **values}
    if merged.get("site_id") is not None and merged.get("region_id") is not None:
        raise _invalid("Scope a VLAN group to a site or a region, not both.", "site_id")
    if values.get("site_id") is not None:
        await check_device_values({"site_id": values["site_id"]})
    await _check_region(values.get("region_id"))
    return values


@admin_router.post(f"{PREFIX}/vlan-groups", status_code=201)
async def create_vlan_group(body: VlanGroupBody, request: Request) -> dict:
    values = await _group_values(body.model_dump())
    record = await _write(db.create_dcim_record("vlan_group", values, _session_user(request)))
    await _audit_write(
        request,
        "vlan_group_create",
        f"id={record['id']} name={record['name']} vids={values['min_vid']}-{values['max_vid']}",
    )
    return record


@admin_router.put(f"{PREFIX}/vlan-groups/{{vlan_group_id}}")
async def update_vlan_group(vlan_group_id: int, body: VlanGroupUpdate, request: Request) -> dict:
    current = _found(await db.get_dcim_record("vlan_group", vlan_group_id), "VLAN group")
    values = await _group_values(_sent(body), current)
    record = _found(
        await _write(db.update_dcim_record("vlan_group", vlan_group_id, values, _session_user(request))), "VLAN group"
    )
    await _audit_write(request, "vlan_group_update", f"id={vlan_group_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/vlan-groups/{{vlan_group_id}}")
async def delete_vlan_group(vlan_group_id: int, request: Request) -> dict:
    """The group's VLANs stay, in no group."""
    record = _found(await db.get_dcim_record("vlan_group", vlan_group_id), "VLAN group")
    return await _delete("vlan_group", f"VLAN group {record['name']}", vlan_group_id, request, f"name={record['name']}")


async def check_vlan_group(group_id: int | None, vid: int, site_id: int | None) -> None:
    """For a VLAN write: 400 when ``group_id`` names no group, 422 when the
    VLAN id is outside the group's range or its site outside the group's
    scope, 409 when the group has the VLAN id already is left to the
    storage (unique per group)."""
    if group_id is None:
        return
    group = await db.get_dcim_record("vlan_group", group_id)
    if group is None:
        message = f"No record with id {group_id}."
        raise HTTPException(
            status_code=400, detail={"message": "Unknown id: vlan_group_id.", "fields": {"vlan_group_id": message}}
        )
    conn = await db.get_db(read_only=True)
    try:
        problem = await db.vlan_group_problem(conn, group, [{"vid": vid, "site_id": site_id}])
    finally:
        await conn.close()
    if problem:
        raise _invalid(problem, "vlan_group_id")


# ── RIRs ─────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/rirs")
@scoped("list")
async def list_rirs(
    request: Request, is_private: bool | None = Query(default=None), q: str = Query("", max_length=200)
) -> dict:
    private = None if is_private is None else int(is_private)
    return {
        "rirs": await filter_rows("rir", await db.list_dcim_records("rir", {"is_private": private}, q.strip()), request)
    }


@router.get(f"{PREFIX}/rirs/{{rir_id}}")
@scoped("object")
async def get_rir(rir_id: int, request: Request) -> dict:
    return await require_row(request, "rir", await db.get_dcim_record("rir", rir_id))


@admin_router.post(f"{PREFIX}/rirs", status_code=201)
async def create_rir(body: RirBody, request: Request) -> dict:
    values = {
        "name": _clean("name", clean_record_name, body.name, "RIR name"),
        "is_private": body.is_private,
        "description": _clean("description", clean_description, body.description),
    }
    record = await _write(db.create_dcim_record("rir", values, _session_user(request)))
    await _audit_write(request, "rir_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/rirs/{{rir_id}}")
async def update_rir(rir_id: int, body: RirUpdate, request: Request) -> dict:
    _found(await db.get_dcim_record("rir", rir_id), "RIR")
    values: dict[str, Any] = {}
    if body.name is not None:
        values["name"] = _clean("name", clean_record_name, body.name, "RIR name")
    if body.is_private is not None:
        values["is_private"] = body.is_private
    if body.description is not None:
        values["description"] = _clean("description", clean_description, body.description)
    record = _found(await _write(db.update_dcim_record("rir", rir_id, values, _session_user(request))), "RIR")
    await _audit_write(request, "rir_update", f"id={rir_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/rirs/{{rir_id}}")
async def delete_rir(rir_id: int, request: Request) -> dict:
    record = _found(await db.get_dcim_record("rir", rir_id), "RIR")
    return await _delete("rir", f"RIR {record['name']}", rir_id, request, f"name={record['name']}")


# ── Aggregates ───────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/aggregates")
@scoped("list")
async def list_aggregates(
    request: Request,
    rir_id: int | None = Query(default=None),
    tenant_id: int | None = Query(default=None),
    q: str = Query("", max_length=200),
) -> dict:
    """Each aggregate with how much of it the IPAM prefixes cover."""
    rows = await db.list_aggregates_with_usage({"rir_id": rir_id, "tenant_id": tenant_id}, q.strip())
    return {"aggregates": await filter_rows("aggregate", rows, request)}


@router.get(f"{PREFIX}/aggregates/containing")
@scoped("object")
async def aggregate_containing(request: Request, subnet: str = Query(..., max_length=_RAW_MAX)) -> dict:
    """The aggregate that holds ``subnet`` (null: none, or one the caller may not read)."""
    found = await filter_rows("aggregate", [a for a in [await db.aggregate_for_subnet(subnet.strip())] if a], request)
    return {"subnet": subnet, "aggregate": found[0] if found else None}


@router.get(f"{PREFIX}/aggregates/{{aggregate_id}}")
@scoped("object")
async def get_aggregate(aggregate_id: int, request: Request) -> dict:
    """The aggregate with its usage and the prefixes inside it the caller may read."""
    detail = await require_row(request, "aggregate", await db.get_aggregate_detail(aggregate_id))
    detail["prefixes"] = await filter_rows("ipam_prefix", detail["prefixes"], request)
    return detail


async def _aggregate_values(values: dict) -> dict:
    if "prefix" in values:
        if values["prefix"] is None:
            raise _invalid("A value is required.", "prefix")
        values["prefix"] = _clean("prefix", clean_aggregate_prefix, values["prefix"])
    if "date_added" in values:
        values["date_added"] = _clean("date_added", clean_date, values["date_added"] or "", "Date added")
    if "description" in values:
        values["description"] = _clean("description", clean_description, values["description"] or "")
    if "rir_id" in values:
        if values["rir_id"] is None:
            raise _invalid("A value is required.", "rir_id")
        if await db.get_dcim_record("rir", values["rir_id"]) is None:
            message = f"No record with id {values['rir_id']}."
            raise HTTPException(
                status_code=400, detail={"message": "Unknown id: rir_id.", "fields": {"rir_id": message}}
            )
    await check_device_values({"tenant_id": values.get("tenant_id")})
    return values


@admin_router.post(f"{PREFIX}/aggregates", status_code=201)
async def create_aggregate(body: AggregateBody, request: Request) -> dict:
    values = await _aggregate_values(body.model_dump())
    record = await _write(db.create_dcim_record("aggregate", values, _session_user(request)))
    await _audit_write(request, "aggregate_create", f"id={record['id']} prefix={record['prefix']}")
    return record


@admin_router.put(f"{PREFIX}/aggregates/{{aggregate_id}}")
async def update_aggregate(aggregate_id: int, body: AggregateUpdate, request: Request) -> dict:
    _found(await db.get_dcim_record("aggregate", aggregate_id), "Aggregate")
    values = await _aggregate_values(_sent(body))
    record = _found(
        await _write(db.update_dcim_record("aggregate", aggregate_id, values, _session_user(request))), "Aggregate"
    )
    await _audit_write(request, "aggregate_update", f"id={aggregate_id} prefix={record['prefix']}")
    return record


@admin_router.delete(f"{PREFIX}/aggregates/{{aggregate_id}}")
async def delete_aggregate(aggregate_id: int, request: Request) -> dict:
    record = _found(await db.get_dcim_record("aggregate", aggregate_id), "Aggregate")
    return await _delete(
        "aggregate", f"Aggregate {record['prefix']}", aggregate_id, request, f"prefix={record['prefix']}"
    )
