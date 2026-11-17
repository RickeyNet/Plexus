"""Routing objects: autonomous systems, routing instances, BGP peer groups and
BGP peerings (the intended BGP state of devices), their comparison with the
BGP neighbors Plexus already discovers, and suggestions from those
neighbors.

``router`` is registered in ``app.py`` behind ``require_feature_method
("routing")``: reads need ``routing``, writes ``routing.write``. Every write
is audited (category ``routing``) and recorded in the change log by the
facade (``routes.db.routing``). Field rules live in ``netcontrol.routing``.
A bad value answers 422 with ``{"message", "fields"}``, a duplicate 409, an
unknown id 404, and deleting an AS still in use 409 with the usage.

The observed side is read, never polled: the ``topology_links`` rows with
``protocol = 'bgp'`` that SNMP neighbor discovery stores. A device whose
neighbors were never discovered is ``no_data``, not ``missing``. See
``docs/routing.md``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from functools import partial as bind
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError, clean_text
from netcontrol.network_objects import DESCRIPTION_MAX, clean_description
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.routing import (
    COMPLIANCE_STATES,
    INSTANCE_STATUSES,
    PEERING_STATUSES,
    RIR_MAX,
    TEXT_MAX,
    clean_address,
    clean_address_families,
    clean_asn,
    clean_instance_name,
    clean_policy,
    clean_router_id,
    clean_status,
    compare,
    join_families,
    observed_neighbor,
    same_family,
    summarize,
)

router = APIRouter()

PREFIX = "/api/routing"
_RAW_MAX = 300
_SEARCH_MAX = 100


# ── Request bodies ───────────────────────────────────────────────────────────
# Values are typed loosely so the field rules (``netcontrol.routing``) give
# the 422 with a message per field.


class AutonomousSystemCreate(BaseModel):
    asn: Any = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + 50)
    tenant_id: int | None = None
    rir: str = Field(default="", max_length=_RAW_MAX)
    comments: str = Field(default="", max_length=TEXT_MAX + 50)


class AutonomousSystemUpdate(BaseModel):
    """The AS number never changes: an ``asn`` key is refused."""

    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 50)
    tenant_id: int | None = None
    rir: str | None = Field(default=None, max_length=_RAW_MAX)
    comments: str | None = Field(default=None, max_length=TEXT_MAX + 50)


class InstanceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    vrf_id: int | None = None
    autonomous_system_id: int | None = None
    router_id: str | None = Field(default=None, max_length=_RAW_MAX)
    status: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 50)


class InstanceCreate(InstanceBody):
    host_id: int


class PeerGroupBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=_RAW_MAX)
    remote_asn_id: int | None = None
    import_policy: str | None = Field(default=None, max_length=_RAW_MAX)
    export_policy: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 50)


class PeerGroupCreate(PeerGroupBody):
    routing_instance_id: int


class PeeringBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    peer_group_id: int | None = None
    local_address: str | None = Field(default=None, max_length=_RAW_MAX)
    remote_address: str | None = Field(default=None, max_length=_RAW_MAX)
    remote_asn_id: int | None = None
    remote_host_id: int | None = None
    status: str | None = Field(default=None, max_length=_RAW_MAX)
    address_families: Any = None
    import_policy: str | None = Field(default=None, max_length=_RAW_MAX)
    export_policy: str | None = Field(default=None, max_length=_RAW_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 50)


class PeeringCreate(PeeringBody):
    routing_instance_id: int


class SuggestedInstance(BaseModel):
    name: str = Field(default="default", max_length=_RAW_MAX)
    asn: Any = None
    router_id: str = Field(default="", max_length=_RAW_MAX)
    status: str = Field(default="active", max_length=_RAW_MAX)


class SuggestedPeering(BaseModel):
    remote_address: str = Field(max_length=_RAW_MAX)
    remote_asn: Any = None
    status: str = Field(default="active", max_length=_RAW_MAX)
    remote_host_id: int | None = None


class SuggestionAccept(BaseModel):
    """Create the selected suggestions for ``host_id``: the peerings go into
    ``routing_instance_id`` or, when it is left out, into ``new_instance``
    (created first). Missing AS numbers are created."""

    model_config = ConfigDict(extra="forbid")

    host_id: int
    routing_instance_id: int | None = None
    new_instance: SuggestedInstance | None = None
    peerings: list[SuggestedPeering] = Field(default_factory=list, max_length=500)


# ── Helpers ──────────────────────────────────────────────────────────────────


class _Fields:
    """Collects the per-field errors of one body; ``raise_if_any`` answers
    422 with ``{"message", "fields"}``."""

    def __init__(self) -> None:
        self.errors: dict[str, str] = {}

    def run(self, field: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except CustomFieldError as exc:
            self.errors.setdefault(field, str(exc))
            return None

    def add(self, field: str, message: str) -> None:
        self.errors.setdefault(field, message)

    def raise_if_any(self) -> None:
        if self.errors:
            first = next(iter(self.errors.values()))
            raise HTTPException(status_code=422, detail={"message": first, "fields": dict(self.errors)})


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


def _conflict(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("routing", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _search(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None


def _status_filter(value: str | None, allowed: tuple[str, ...]) -> str | None:
    if not value:
        return None
    if value not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {', '.join(allowed)}")
    return value


def _asn_filter(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return clean_asn(value)
    except CustomFieldError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _check_as(fields: _Fields, field: str, as_id: int | None) -> dict | None:
    if as_id is None:
        return None
    record = await db.get_autonomous_system(as_id)
    if record is None:
        fields.add(field, "No autonomous system has this id.")
    return record


async def _check_host(fields: _Fields, field: str, host_id: int | None) -> dict | None:
    if host_id is None:
        return None
    host = await db.get_host(int(host_id))
    if host is None:
        fields.add(field, "No device has this id.")
    return host


# ── Autonomous systems ───────────────────────────────────────────────────────


@router.get(f"{PREFIX}/autonomous-systems")
async def list_autonomous_systems(
    tenant_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=_SEARCH_MAX),
) -> dict:
    return {"autonomous_systems": await db.list_autonomous_systems(tenant_id=tenant_id, search=_search(search))}


@router.get(f"{PREFIX}/autonomous-systems/{{as_id}}")
async def get_autonomous_system(as_id: int) -> dict:
    record = _found(await db.get_autonomous_system(as_id), "Autonomous system")
    return {
        **record,
        "routing_instances": await db.list_routing_instances(asn=record["asn"]),
        "peerings": await db.list_bgp_peerings(asn=record["asn"]),
    }


async def _as_values(body: AutonomousSystemCreate | AutonomousSystemUpdate, fields: _Fields, partial: bool) -> dict:
    values: dict[str, Any] = {}
    sent = body.model_fields_set
    if not partial or "description" in sent:
        values["description"] = fields.run("description", lambda: clean_description(body.description))
    if not partial or "rir" in sent:
        values["rir"] = fields.run("rir", lambda: clean_text(body.rir, "RIR", RIR_MAX))
    if not partial or "comments" in sent:
        values["comments"] = fields.run("comments", lambda: clean_text(body.comments, "Comments", TEXT_MAX))
    if not partial or "tenant_id" in sent:
        if body.tenant_id is not None and await db.get_tenant(body.tenant_id) is None:
            fields.add("tenant_id", "No tenant has this id.")
        values["tenant_id"] = body.tenant_id
    return values


@router.post(f"{PREFIX}/autonomous-systems", status_code=201)
async def create_autonomous_system(body: AutonomousSystemCreate, request: Request) -> dict:
    fields = _Fields()
    asn = fields.run("asn", lambda: clean_asn(body.asn))
    values = await _as_values(body, fields, partial=False)
    fields.raise_if_any()
    try:
        record = await db.create_autonomous_system(asn=asn, user=_session_user(request), **values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "autonomous_system_create", f"id={record['id']} asn={asn}")
    return record


@router.put(f"{PREFIX}/autonomous-systems/{{as_id}}")
async def update_autonomous_system(as_id: int, body: AutonomousSystemUpdate, request: Request) -> dict:
    current = _found(await db.get_autonomous_system(as_id), "Autonomous system")
    fields = _Fields()
    values = await _as_values(body, fields, partial=True)
    fields.raise_if_any()
    record = _found(
        await db.update_autonomous_system(as_id, values=values, user=_session_user(request)), "Autonomous system"
    )
    await _audit_write(request, "autonomous_system_update", f"id={as_id} asn={current['asn']}")
    return record


@router.delete(f"{PREFIX}/autonomous-systems/{{as_id}}")
async def delete_autonomous_system(as_id: int, request: Request) -> dict:
    record = _found(await db.get_autonomous_system(as_id), "Autonomous system")
    usage = await db.autonomous_system_usage(as_id)
    blocking = usage["routing_instances"] + usage["bgp_peerings"]
    if blocking:
        parts = [
            f"{usage['routing_instances']} routing instances" if usage["routing_instances"] else "",
            f"{usage['bgp_peerings']} BGP peerings" if usage["bgp_peerings"] else "",
        ]
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"AS {record['asn']} is in use ({', '.join(p for p in parts if p)}); it cannot be deleted.",
                "affected": blocking,
                "usage": usage,
            },
        )
    await db.delete_autonomous_system(as_id)
    await _audit_write(request, "autonomous_system_delete", f"id={as_id} asn={record['asn']}")
    return {"ok": True}


# ── Routing instances ────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/instances")
async def list_routing_instances(
    host_id: int | None = Query(default=None),
    asn: str | None = Query(default=None, max_length=20),
    status: str | None = Query(default=None, max_length=20),
    tenant_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=_SEARCH_MAX),
) -> dict:
    return {
        "routing_instances": await db.list_routing_instances(
            host_id=host_id,
            asn=_asn_filter(asn),
            status=_status_filter(status, INSTANCE_STATUSES),
            tenant_id=tenant_id,
            search=_search(search),
        )
    }


@router.get(f"{PREFIX}/instances/{{instance_id}}")
async def get_routing_instance(instance_id: int) -> dict:
    record = _found(await db.get_routing_instance(instance_id), "Routing instance")
    return {
        **record,
        "peer_groups": await db.list_bgp_peer_groups(routing_instance_id=instance_id),
        "peerings": await db.list_bgp_peerings(routing_instance_id=instance_id),
    }


async def _instance_values(body: InstanceBody, fields: _Fields, partial: bool) -> dict:
    sent = body.model_fields_set
    values: dict[str, Any] = {}
    if not partial or "name" in sent:
        values["name"] = fields.run("name", lambda: clean_instance_name(body.name))
    if not partial or "autonomous_system_id" in sent:
        if body.autonomous_system_id is None:
            fields.add("autonomous_system_id", "Choose the local autonomous system.")
        else:
            await _check_as(fields, "autonomous_system_id", body.autonomous_system_id)
        values["autonomous_system_id"] = body.autonomous_system_id
    if not partial or "vrf_id" in sent:
        if body.vrf_id is not None and await db.get_vrf(body.vrf_id) is None:
            fields.add("vrf_id", "No VRF has this id.")
        values["vrf_id"] = body.vrf_id
    if not partial or "router_id" in sent:
        values["router_id"] = fields.run("router_id", lambda: clean_router_id(body.router_id))
    if not partial or "status" in sent:
        values["status"] = fields.run("status", lambda: clean_status(body.status or "active", INSTANCE_STATUSES))
    if not partial or "description" in sent:
        values["description"] = fields.run("description", lambda: clean_description(body.description))
    return values


@router.post(f"{PREFIX}/instances", status_code=201)
async def create_routing_instance(body: InstanceCreate, request: Request) -> dict:
    fields = _Fields()
    await _check_host(fields, "host_id", body.host_id)
    values = await _instance_values(body, fields, partial=False)
    fields.raise_if_any()
    try:
        record = await db.create_routing_instance(host_id=body.host_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(
        request, "routing_instance_create", f"id={record['id']} host_id={body.host_id} name={values['name']}"
    )
    return record


@router.put(f"{PREFIX}/instances/{{instance_id}}")
async def update_routing_instance(instance_id: int, body: InstanceBody, request: Request) -> dict:
    _found(await db.get_routing_instance(instance_id), "Routing instance")
    fields = _Fields()
    values = await _instance_values(body, fields, partial=True)
    fields.raise_if_any()
    try:
        record = await db.update_routing_instance(instance_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Routing instance")
    await _audit_write(request, "routing_instance_update", f"id={instance_id} name={record['name']}")
    return record


@router.delete(f"{PREFIX}/instances/{{instance_id}}")
async def delete_routing_instance(instance_id: int, request: Request) -> dict:
    record = _found(await db.get_routing_instance(instance_id), "Routing instance")
    await db.delete_routing_instance(instance_id)
    await _audit_write(
        request,
        "routing_instance_delete",
        f"id={instance_id} host_id={record['host_id']} name={record['name']} peerings={record['peering_count']}",
    )
    return {"ok": True}


# ── BGP peer groups ──────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/peer-groups")
async def list_bgp_peer_groups(
    routing_instance_id: int | None = Query(default=None),
    host_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=_SEARCH_MAX),
) -> dict:
    return {
        "peer_groups": await db.list_bgp_peer_groups(
            routing_instance_id=routing_instance_id, host_id=host_id, search=_search(search)
        )
    }


@router.get(f"{PREFIX}/peer-groups/{{group_id}}")
async def get_bgp_peer_group(group_id: int) -> dict:
    return _found(await db.get_bgp_peer_group(group_id), "Peer group")


async def _group_values(body: PeerGroupBody, fields: _Fields, partial: bool) -> dict:
    sent = body.model_fields_set
    values: dict[str, Any] = {}
    if not partial or "name" in sent:
        values["name"] = fields.run("name", lambda: clean_instance_name(body.name))
    if not partial or "remote_asn_id" in sent:
        await _check_as(fields, "remote_asn_id", body.remote_asn_id)
        values["remote_asn_id"] = body.remote_asn_id
    for key, label in (("import_policy", "Import policy"), ("export_policy", "Export policy")):
        if not partial or key in sent:
            values[key] = fields.run(key, bind(clean_policy, getattr(body, key), label))
    if not partial or "description" in sent:
        values["description"] = fields.run("description", lambda: clean_description(body.description))
    return values


@router.post(f"{PREFIX}/peer-groups", status_code=201)
async def create_bgp_peer_group(body: PeerGroupCreate, request: Request) -> dict:
    fields = _Fields()
    if await db.get_routing_instance(body.routing_instance_id) is None:
        fields.add("routing_instance_id", "No routing instance has this id.")
    values = await _group_values(body, fields, partial=False)
    fields.raise_if_any()
    try:
        record = await db.create_bgp_peer_group(
            routing_instance_id=body.routing_instance_id, values=values, user=_session_user(request)
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "bgp_peer_group_create", f"id={record['id']} name={values['name']}")
    return record


@router.put(f"{PREFIX}/peer-groups/{{group_id}}")
async def update_bgp_peer_group(group_id: int, body: PeerGroupBody, request: Request) -> dict:
    _found(await db.get_bgp_peer_group(group_id), "Peer group")
    fields = _Fields()
    values = await _group_values(body, fields, partial=True)
    fields.raise_if_any()
    try:
        record = await db.update_bgp_peer_group(group_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Peer group")
    await _audit_write(request, "bgp_peer_group_update", f"id={group_id} name={record['name']}")
    return record


@router.delete(f"{PREFIX}/peer-groups/{{group_id}}")
async def delete_bgp_peer_group(group_id: int, request: Request) -> dict:
    record = _found(await db.get_bgp_peer_group(group_id), "Peer group")
    await db.delete_bgp_peer_group(group_id)
    await _audit_write(request, "bgp_peer_group_delete", f"id={group_id} name={record['name']}")
    return {"ok": True}


# ── BGP peerings ─────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/peerings")
async def list_bgp_peerings(
    host_id: int | None = Query(default=None),
    routing_instance_id: int | None = Query(default=None),
    asn: str | None = Query(default=None, max_length=20),
    status: str | None = Query(default=None, max_length=20),
    tenant_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=_SEARCH_MAX),
) -> dict:
    return {
        "peerings": await db.list_bgp_peerings(
            host_id=host_id,
            routing_instance_id=routing_instance_id,
            asn=_asn_filter(asn),
            status=_status_filter(status, PEERING_STATUSES),
            tenant_id=tenant_id,
            search=_search(search),
        )
    }


@router.get(f"{PREFIX}/peerings/{{peering_id}}")
async def get_bgp_peering(peering_id: int) -> dict:
    return _found(await db.get_bgp_peering(peering_id), "BGP peering")


async def _peering_values(body: PeeringBody, fields: _Fields, instance_id: int, current: dict | None) -> dict:
    """The validated columns of a create (``current`` None) or an update
    (only the keys sent). The addresses are checked as a pair, with the
    stored one standing in for a key not sent."""
    sent = body.model_fields_set
    partial = current is not None
    values: dict[str, Any] = {}
    if not partial or "remote_address" in sent:
        values["remote_address"] = fields.run(
            "remote_address", lambda: clean_address(body.remote_address, "Remote address")
        )
    if not partial or "local_address" in sent:
        values["local_address"] = fields.run(
            "local_address", lambda: clean_address(body.local_address, "Local address", required=False)
        )
    local = values.get("local_address", (current or {}).get("local_address", ""))
    remote = values.get("remote_address", (current or {}).get("remote_address", ""))
    if local and remote and not same_family(local, remote):
        fields.add("local_address", "Local and remote addresses must both be IPv4 or both be IPv6.")
    if not partial or "remote_asn_id" in sent:
        if body.remote_asn_id is None:
            fields.add("remote_asn_id", "Choose the remote autonomous system.")
        else:
            await _check_as(fields, "remote_asn_id", body.remote_asn_id)
        values["remote_asn_id"] = body.remote_asn_id
    if not partial or "peer_group_id" in sent:
        if body.peer_group_id is not None:
            group = await db.get_bgp_peer_group(body.peer_group_id)
            if group is None or group["routing_instance_id"] != instance_id:
                fields.add("peer_group_id", "The peer group must belong to the same routing instance.")
        values["peer_group_id"] = body.peer_group_id
    if not partial or "remote_host_id" in sent:
        await _check_host(fields, "remote_host_id", body.remote_host_id)
        values["remote_host_id"] = body.remote_host_id
    if not partial or "status" in sent:
        values["status"] = fields.run("status", lambda: clean_status(body.status or "active", PEERING_STATUSES))
    if not partial or "address_families" in sent:
        families = fields.run("address_families", lambda: clean_address_families(body.address_families))
        values["address_families"] = join_families(families or [])
    for key, label in (("import_policy", "Import policy"), ("export_policy", "Export policy")):
        if not partial or key in sent:
            values[key] = fields.run(key, bind(clean_policy, getattr(body, key), label))
    if not partial or "description" in sent:
        values["description"] = fields.run("description", lambda: clean_description(body.description))
    return values


@router.post(f"{PREFIX}/peerings", status_code=201)
async def create_bgp_peering(body: PeeringCreate, request: Request) -> dict:
    fields = _Fields()
    if await db.get_routing_instance(body.routing_instance_id) is None:
        fields.add("routing_instance_id", "No routing instance has this id.")
    values = await _peering_values(body, fields, body.routing_instance_id, None)
    fields.raise_if_any()
    try:
        record = await db.create_bgp_peering(
            routing_instance_id=body.routing_instance_id, values=values, user=_session_user(request)
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(
        request,
        "bgp_peering_create",
        f"id={record['id']} instance_id={body.routing_instance_id} remote={values['remote_address']}",
    )
    return record


@router.put(f"{PREFIX}/peerings/{{peering_id}}")
async def update_bgp_peering(peering_id: int, body: PeeringBody, request: Request) -> dict:
    current = _found(await db.get_bgp_peering(peering_id), "BGP peering")
    fields = _Fields()
    values = await _peering_values(body, fields, current["routing_instance_id"], current)
    fields.raise_if_any()
    try:
        record = await db.update_bgp_peering(peering_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "BGP peering")
    await _audit_write(request, "bgp_peering_update", f"id={peering_id} remote={record['remote_address']}")
    return record


@router.delete(f"{PREFIX}/peerings/{{peering_id}}")
async def delete_bgp_peering(peering_id: int, request: Request) -> dict:
    record = _found(await db.get_bgp_peering(peering_id), "BGP peering")
    await db.delete_bgp_peering(peering_id)
    await _audit_write(request, "bgp_peering_delete", f"id={peering_id} remote={record['remote_address']}")
    return {"ok": True}


# ── Intended vs observed ─────────────────────────────────────────────────────


async def _observed(host_ids: list[int]) -> list[dict]:
    """The observed BGP neighbors of the hosts, from the stored neighbor
    discovery links (the topology readers; nothing is polled)."""
    wanted = set(host_ids)
    if len(host_ids) == 1:
        links = await db.get_topology_links_for_host(host_ids[0])
    else:
        links = await db.get_topology_links()
    neighbors = []
    for link in links:
        if int(link.get("source_host_id") or 0) not in wanted:
            continue
        neighbor = observed_neighbor(link)
        if neighbor is not None:
            neighbors.append(neighbor)
    return neighbors


async def compliance_report(host_id: int | None = None) -> dict:
    """Every intended peering against the observed neighbors: one row per
    peering (and per unexpected neighbor), the counts per state and per
    device. ``host_id``: one device, whose unexpected neighbors are reported
    even when it has no routing instance; otherwise every device with a
    routing instance."""
    if host_id is not None:
        host = _found(await db.get_host(host_id), "Host")
        hosts: list[dict[str, Any]] = [{"id": int(host["id"]), "hostname": host.get("hostname") or ""}]
    else:
        seen: dict[int, str] = {}
        for instance in await db.list_routing_instances():
            seen.setdefault(instance["host_id"], instance["hostname"])
        hosts = [{"id": hid, "hostname": name} for hid, name in seen.items()]
    ids = [int(h["id"]) for h in hosts]
    peerings = await db.list_bgp_peerings(host_ids=ids)
    neighbors = await _observed(ids) if ids else []
    discovered = await db.hosts_with_neighbor_discovery(ids)
    rows = compare(hosts, peerings, neighbors, set(discovered), unexpected_for=set(ids))
    per_host = []
    for h in hosts:
        own = [r for r in rows if r["host_id"] == h["id"]]
        per_host.append(
            {
                "host_id": h["id"],
                "hostname": h["hostname"],
                "has_data": h["id"] in discovered,
                "last_discovered_at": discovered.get(h["id"], ""),
                "counts": summarize(own),
            }
        )
    return {"rows": rows, "summary": summarize(rows), "hosts": per_host}


@router.get(f"{PREFIX}/compliance")
async def compliance(
    host_id: int | None = Query(default=None),
    state: str | None = Query(default=None, max_length=20),
) -> dict:
    """``state``: only the rows in this compliance state (the counts stay
    whole)."""
    if state and state not in COMPLIANCE_STATES:
        raise HTTPException(status_code=400, detail=f"state must be one of {', '.join(COMPLIANCE_STATES)}")
    report = await compliance_report(host_id)
    if state:
        report["rows"] = [r for r in report["rows"] if r["state"] == state]
    return report


# ── Suggestions from observed neighbors ──────────────────────────────────────


async def _unclaimed_neighbors(host_id: int) -> list[dict]:
    """The observed neighbors of a host that no peering of the host names."""
    intended = {p["remote_address"] for p in await db.list_bgp_peerings(host_id=host_id)}
    return [n for n in await _observed([host_id]) if n["remote_address"] not in intended]


@router.get(f"{PREFIX}/suggestions")
async def suggestions(host_id: int = Query()) -> dict:
    """What to record for a device from its observed neighbors: the
    neighbors without a peering, the AS numbers they name (and whether a
    record exists), and a ``default`` instance when the device has none.
    Nothing is created here."""
    host = _found(await db.get_host(host_id), "Host")
    discovered = await db.hosts_with_neighbor_discovery([host_id])
    neighbors = await _unclaimed_neighbors(host_id)
    instances = await db.list_routing_instances(host_id=host_id)
    asns: dict[int, int | None] = {}
    peerings = []
    for n in neighbors:
        if n["remote_asn"] is not None and n["remote_asn"] not in asns:
            existing = await db.get_autonomous_system_by_asn(n["remote_asn"])
            asns[n["remote_asn"]] = existing["id"] if existing else None
        peer_host = await db.find_host_by_ip(n["remote_address"])
        peerings.append(
            {
                "remote_address": n["remote_address"],
                "remote_asn": n["remote_asn"],
                "observed_state": n["state"],
                "established": n["established"],
                "status": "active" if n["established"] else "planned",
                "remote_host_id": int(peer_host["id"]) if peer_host else None,
                "remote_hostname": (peer_host or {}).get("hostname") or "",
            }
        )
    return {
        "host_id": host_id,
        "hostname": host.get("hostname") or "",
        "has_data": host_id in discovered,
        "routing_instances": [{"id": i["id"], "name": i["name"], "asn": i["asn"]} for i in instances],
        "proposed_instance": None if instances else {"name": "default", "asn": None},
        "autonomous_systems": [{"asn": a, "autonomous_system_id": i} for a, i in sorted(asns.items())],
        "peerings": peerings,
    }


async def _ensure_as(asn: int, user: str, created: list[dict]) -> int:
    existing = await db.get_autonomous_system_by_asn(asn)
    if existing:
        return int(existing["id"])
    try:
        record = await db.create_autonomous_system(asn=asn, description="Added from observed BGP neighbors", user=user)
    except ValueError:
        # Created meanwhile by someone else.
        return int(_found(await db.get_autonomous_system_by_asn(asn), "Autonomous system")["id"])
    created.append(record)
    return int(record["id"])


@router.post(f"{PREFIX}/suggestions/accept", status_code=201)
async def accept_suggestions(body: SuggestionAccept, request: Request) -> dict:
    """Create the selected suggestions. Each peering's remote address must
    be an observed neighbor of the device without a peering; its status is
    ``planned`` or ``active``. Everything is checked before anything is
    created."""
    fields = _Fields()
    host = _found(await db.get_host(body.host_id), "Host")
    user = _session_user(request)
    instance: dict | None = None
    if body.routing_instance_id is not None:
        instance = await db.get_routing_instance(body.routing_instance_id)
        if instance is None or instance["host_id"] != body.host_id:
            fields.add("routing_instance_id", "Choose a routing instance of this device.")
    elif body.new_instance is None:
        fields.add("routing_instance_id", "Choose a routing instance, or describe a new one.")
    new_instance: dict[str, Any] = {}
    if body.routing_instance_id is None and body.new_instance is not None:
        spec = body.new_instance
        new_instance = {
            "name": fields.run("new_instance.name", lambda: clean_instance_name(spec.name)),
            "asn": fields.run("new_instance.asn", lambda: clean_asn(spec.asn, "Local ASN")),
            "router_id": fields.run("new_instance.router_id", lambda: clean_router_id(spec.router_id)),
            "status": fields.run("new_instance.status", lambda: clean_status(spec.status, ("planned", "active"))),
        }
    observed = {n["remote_address"]: n for n in await _unclaimed_neighbors(body.host_id)}
    chosen: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(body.peerings):
        key = f"peerings.{index}"
        address = fields.run(f"{key}.remote_address", bind(clean_address, item.remote_address, "Remote address"))
        if address is None:
            continue
        if address not in observed or address in seen:
            fields.add(f"{key}.remote_address", f"{address} is not an observed neighbor without a peering.")
            continue
        seen.add(address)
        raw_asn = item.remote_asn if item.remote_asn not in (None, "") else observed[address]["remote_asn"]
        asn = fields.run(f"{key}.remote_asn", bind(clean_asn, raw_asn, "Remote ASN"))
        status = fields.run(f"{key}.status", bind(clean_status, item.status, ("planned", "active")))
        await _check_host(fields, f"{key}.remote_host_id", item.remote_host_id)
        chosen.append({"remote_address": address, "asn": asn, "status": status, "remote_host_id": item.remote_host_id})
    if not body.peerings and instance is not None:
        fields.add("peerings", "Select at least one suggestion.")
    fields.raise_if_any()

    created_as: list[dict] = []
    created_instance = None
    if instance is None:
        as_id = await _ensure_as(new_instance["asn"], user, created_as)
        try:
            created_instance = await db.create_routing_instance(
                host_id=body.host_id,
                values={
                    "name": new_instance["name"],
                    "autonomous_system_id": as_id,
                    "router_id": new_instance["router_id"],
                    "status": new_instance["status"],
                    "description": "",
                },
                user=user,
            )
        except ValueError as exc:
            raise _conflict(exc) from exc
        instance = created_instance
    created_peerings = []
    for pick in chosen:
        remote_as = await _ensure_as(pick["asn"], user, created_as)
        try:
            created_peerings.append(
                await db.create_bgp_peering(
                    routing_instance_id=instance["id"],
                    values={
                        "remote_address": pick["remote_address"],
                        "remote_asn_id": remote_as,
                        "remote_host_id": pick["remote_host_id"],
                        "status": pick["status"],
                        "local_address": "",
                        "address_families": join_families(
                            [
                                "ipv4-unicast"
                                if ipaddress.ip_address(pick["remote_address"]).version == 4
                                else "ipv6-unicast"
                            ]
                        ),
                        "description": "Added from observed BGP neighbors",
                    },
                    user=user,
                )
            )
        except ValueError:
            continue  # recorded meanwhile; nothing to add
    await _audit_write(
        request,
        "routing_suggestions_accept",
        f"host_id={body.host_id} hostname={host.get('hostname') or ''} instance_id={instance['id']} "
        f"autonomous_systems={len(created_as)} peerings={len(created_peerings)}",
    )
    return {
        "autonomous_systems": created_as,
        "routing_instance": created_instance,
        "peerings": created_peerings,
    }
