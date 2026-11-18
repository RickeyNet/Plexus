"""Physical DCIM API: rack roles, racks, rack reservations, device placement
and elevation, patch panel front/rear ports, modules, power panels, feeds,
ports and outlets, cables, cable traces and rack power.

``router`` is registered in ``app.py`` behind ``require_auth`` and
``require_feature_method("dcim")``: read with ``dcim``, change with
``dcim.write``. Object scope (``netcontrol.object_scope``): rack roles are
shared; racks, reservations, power panels and feeds follow their tenant and
site, cables their tenant and the hosts and sites of their ends, and ports,
modules, outlets and placements their host. A scoped caller's rack
elevation shows other devices as anonymous occupied units, a trace stops
(``status`` ``restricted``) before an endpoint they may not see, and a
reference to a record they may not see answers like an unknown id.

Placing a device also works through the host edit (``PUT
/api/hosts/{id}`` with ``rack_id``/``rack_position``/``rack_face``), which
shares ``check_host_placement`` with this router.

Every write is audited (category ``dcim``) and recorded in the change log
by the storage layer. Errors: 404 unknown record, 409 a taken name or an
endpoint that already has a cable or a record still in use, 422 bad input
(``{"message", "fields"}`` for field problems). Rules: ``netcontrol.dcim``;
storage: ``routes.db.dcim`` and ``routes.db.dcim_cables``; docs:
``docs/dcim.md``.
"""

import copy
from dataclasses import dataclass, field
from typing import Any, Optional

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, create_model

from netcontrol.custom_fields import OBJECT_TYPE_SPECS, TEXT_MAX, TagColor
from netcontrol.dcim import (
    CABLE_STATUSES,
    CABLE_TYPES,
    CONSOLE_PORT_TYPES,
    ENDPOINT_TYPES,
    FACES,
    FEED_LEGS,
    FEED_PHASES,
    FEED_STATUSES,
    FEED_SUPPLIES,
    FEED_TYPES,
    LENGTH_UNITS,
    MODULE_STATUSES,
    PORT_TYPES,
    RACK_STATUSES,
    RACK_WIDTHS,
    CableStatus,
    CableType,
    ConsolePortType,
    EndpointType,
    Face,
    FeedLeg,
    FeedPhase,
    FeedStatus,
    FeedSupply,
    FeedType,
    LengthUnit,
    ModuleStatus,
    PortType,
    RackStatus,
    RackWidth,
    pairing_error,
)
from netcontrol.object_scope import (
    can_access,
    filter_rows,
    readable_host_ids,
    request_scope,
    require_host,
    require_new_row,
    require_row,
    scope_exempt,
    scoped,
)
from netcontrol.routes.custom_fields import custom_list, with_custom_data
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()

PREFIX = "/api/dcim"
NAME_MAX = 100
SHORT_MAX = 100
INTERFACE_NAME_MAX = 64
UNITS_MAX = 100

_Name = Field(max_length=NAME_MAX)
_Text = Field(default="", max_length=TEXT_MAX)
_Short = Field(default="", max_length=SHORT_MAX)


# ── Request bodies ───────────────────────────────────────────────────────────


class RackRoleCreate(BaseModel):
    name: str = _Name
    color: TagColor = "gray"
    description: str = _Text


class RackCreate(BaseModel):
    site_id: int
    floor_id: int | None = None
    name: str = _Name
    facility_id: str = _Short
    status: RackStatus = "active"
    role_id: int | None = None
    tenant_id: int | None = None
    u_height: int = Field(default=42, ge=1, le=100)
    desc_units: bool = False
    width: RackWidth = 19
    serial: str = _Short
    asset_tag: str = _Short
    description: str = _Text
    comments: str = Field(default="", max_length=10 * TEXT_MAX)


class RackReservationCreate(BaseModel):
    rack_id: int
    units: list[int] = Field(min_length=1, max_length=UNITS_MAX)
    user: str = _Short
    description: str = _Text
    tenant_id: int | None = None


class RearPortCreate(BaseModel):
    host_id: int
    name: str = _Name
    type: PortType = "8p8c"
    positions: int = Field(default=1, ge=1, le=1024)
    description: str = _Text


class FrontPortCreate(BaseModel):
    host_id: int
    name: str = _Name
    type: PortType = "8p8c"
    rear_port_id: int
    rear_port_position: int = Field(default=1, ge=1, le=1024)
    description: str = _Text


class ModuleCreate(BaseModel):
    host_id: int
    bay: str = _Name
    module_type: str = _Short
    part_number: str = _Short
    serial: str = _Short
    asset_tag: str = _Short
    status: ModuleStatus = "active"
    description: str = _Text


class PowerPanelCreate(BaseModel):
    site_id: int
    floor_id: int | None = None
    name: str = _Name
    description: str = _Text


class PowerFeedCreate(BaseModel):
    power_panel_id: int
    rack_id: int | None = None
    name: str = _Name
    status: FeedStatus = "active"
    type: FeedType = "primary"
    supply: FeedSupply = "ac"
    phase: FeedPhase = "single"
    voltage: int = Field(default=230, ge=-1000, le=1000)
    amperage: int = Field(default=16, ge=1, le=10000)
    max_utilization: int = Field(default=80, ge=1, le=100)
    description: str = _Text


class PowerPortCreate(BaseModel):
    host_id: int
    name: str = _Name
    maximum_draw: int | None = Field(default=None, ge=1, le=1_000_000)
    allocated_draw: int | None = Field(default=None, ge=1, le=1_000_000)
    description: str = _Text


class PowerOutletCreate(BaseModel):
    host_id: int
    name: str = _Name
    power_port_id: int | None = None
    feed_leg: FeedLeg = ""
    description: str = _Text


class ConsolePortCreate(BaseModel):
    host_id: int
    name: str = _Name
    type: ConsolePortType = "rj-45"
    description: str = _Text


class Endpoint(BaseModel):
    """One end of a cable: ``type`` with ``id`` (a port, outlet, feed or
    circuit termination record) or, for an interface, ``host_id`` and
    ``name``."""

    model_config = ConfigDict(extra="forbid")

    type: EndpointType
    id: int | None = None
    host_id: int | None = None
    name: str = Field(default="", max_length=INTERFACE_NAME_MAX)


class CableCreate(BaseModel):
    a: Endpoint
    b: Endpoint
    status: CableStatus = "connected"
    type: CableType = ""
    label: str = _Short
    color: str = Field(default="", pattern=r"^([0-9a-fA-F]{6})?$")
    length: float | None = Field(default=None, ge=0, le=100_000)
    length_unit: LengthUnit = ""
    tenant_id: int | None = None
    description: str = _Text


PLACEMENT_FIELDS: tuple[str, ...] = ("rack_id", "rack_position", "rack_face")


class HostPlacementValues(BaseModel):
    """A device's place in a rack, as a host edit sends it: a key left out
    keeps its value; ``rack_id`` null takes the device out of its rack,
    ``rack_position`` null leaves it in the rack unmounted."""

    rack_id: int | None = None
    rack_position: int | None = Field(default=None, ge=1, le=100)
    rack_face: Face | None = None


class PlacementBody(HostPlacementValues):
    model_config = ConfigDict(extra="forbid")


def sent_placement_values(body: BaseModel) -> dict:
    """The placement keys a body sent (``model_fields_set``)."""
    return {k: getattr(body, k) for k in PLACEMENT_FIELDS if k in body.model_fields_set}


def _optional(model: type[BaseModel], fixed: tuple[str, ...] = ()) -> type[BaseModel]:
    """The update body of a create body: every field optional (left out:
    unchanged), the ``fixed`` ones refused, unknown keys refused."""
    fields: dict[str, Any] = {}
    for name, info in model.model_fields.items():
        if name in fixed:
            continue
        relaxed = copy.copy(info)
        relaxed.default = None
        relaxed.default_factory = None
        fields[name] = (Optional[info.annotation], relaxed)  # noqa: UP045 - a runtime type, maybe None
    return create_model(
        model.__name__.replace("Create", "Update"), __config__=ConfigDict(extra="forbid"), **fields
    )


def _nullable(model: type[BaseModel]) -> frozenset[str]:
    return frozenset(
        name
        for name, info in model.model_fields.items()
        if info.annotation is not None and type(None) in getattr(info.annotation, "__args__", ())
    )


# ── Helpers ──────────────────────────────────────────────────────────────────


def _invalid(message: str, fields: dict[str, str] | None = None) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": message, "fields": fields or {}})


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("dcim", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _clean_names(values: dict, names: tuple[str, ...]) -> None:
    """Trim the text values; 422 when a name field is empty."""
    for key, value in list(values.items()):
        if isinstance(value, str):
            values[key] = value.strip()
    for key in names:
        if key in values and not values[key]:
            raise _invalid(f"{key.replace('_', ' ').capitalize()} must not be empty.", {key: "Required."})


async def _check_refs(values: dict) -> None:
    errors = await db.missing_dcim_refs(values)
    if errors:
        raise _invalid("Unknown id: " + ", ".join(sorted(errors)) + ".", errors)


async def _write(call):
    """Run a storage write: 409 for a taken name or endpoint, 422 for a
    broken rule."""
    try:
        return await call
    except db.DcimRuleError as exc:
        raise _invalid(str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _validate_power_port(values: dict, current: dict | None = None) -> None:
    merged = {**(current or {}), **values}
    maximum, allocated = merged.get("maximum_draw"), merged.get("allocated_draw")
    if maximum is not None and allocated is not None and int(allocated) > int(maximum):
        raise _invalid("The allocated draw cannot exceed the maximum draw.", {"allocated_draw": "Above the maximum."})


# ── Object scope ─────────────────────────────────────────────────────────────

# The scope model of each record kind (``netcontrol.object_scope``); a kind
# with a ``host_id`` follows its host.
_SCOPE_MODELS: dict[str, str] = {
    "rack_role": "rack_role",
    "rack": "rack",
    "rack_reservation": "rack_reservation",
    "power_panel": "power_panel",
    "power_feed": "power_feed",
}
# Reference fields whose record a scoped caller must be able to read.
_SCOPED_REFS: dict[str, tuple[str, str]] = {
    "rack_id": ("rack", "rack"),
    "power_panel_id": ("power_panel", "power_panel"),
    "rear_port_id": ("rear_port", "host_record"),
    "power_port_id": ("power_port", "host_record"),
}


def _scope_model(kind: str) -> str:
    return _SCOPE_MODELS.get(kind, "host_record")


async def _check_ref_scope(request: Request, values: dict) -> None:
    """For a scoped caller: 422 (as for an unknown id) when ``values``
    names a rack, panel, rear port or power port they may not read."""
    if (await request_scope(request)).unrestricted:
        return
    errors: dict[str, str] = {}
    for key, (kind, model) in _SCOPED_REFS.items():
        value = values.get(key)
        if value is None:
            continue
        if not await can_access(request, model, await db.get_dcim_record(kind, int(value))):
            errors[key] = f"No record with id {value}."
    if errors:
        raise _invalid("Unknown id: " + ", ".join(sorted(errors)) + ".", errors)


async def _scope_keys_of(kind: str, values: dict) -> dict:
    """The scope key fields of a ``kind`` record holding ``values`` (a
    reservation takes its rack's site, a feed its panel's)."""
    if kind == "rack_reservation":
        rack = await db.get_dcim_record("rack", int(values["rack_id"])) if values.get("rack_id") else None
        return {"tenant_id": values.get("tenant_id"), "site_id": (rack or {}).get("site_id")}
    if kind == "power_feed":
        panel_id = values.get("power_panel_id")
        panel = await db.get_dcim_record("power_panel", int(panel_id)) if panel_id else None
        return {"site_id": (panel or {}).get("site_id")}
    if kind == "rack":
        return {"tenant_id": values.get("tenant_id"), "site_id": values.get("site_id")}
    if kind == "power_panel":
        return {"site_id": values.get("site_id")}
    if kind == "rack_role":
        return {}
    return {"host_id": values.get("host_id")}


async def _scope_any_of(request: Request, model: str) -> dict[str, frozenset[int]]:
    """``list_dcim_records(any_of=...)`` for a scoped caller: the readable
    ids of each key of ``model`` as its ``<key>_id`` filter."""
    allowed = await (await request_scope(request)).keys(model)
    return {f"{attr}_id": ids for attr, ids in allowed.items()}


async def _scoped_rack_roles(request: Request, roles: list[dict]) -> list[dict]:
    """For a scoped caller: each role's ``rack_count`` over the racks they may read."""
    racks = await db.list_dcim_records("rack", any_of=await _scope_any_of(request, "rack"))
    counts: dict[int, int] = {}
    for rack in racks:
        if rack.get("role_id") is not None:
            counts[int(rack["role_id"])] = counts.get(int(rack["role_id"]), 0) + 1
    for role in roles:
        role["rack_count"] = counts.get(int(role["id"]), 0)
    return roles


class _EndpointScope:
    """Which cable endpoints a scoped caller may see (``None`` scope: all),
    with the site of feed and circuit termination ends, cached per request."""

    def __init__(self, request: Request, hosts: frozenset[int] | None) -> None:
        self.request = request
        self.hosts = hosts
        self._visible: dict[tuple, bool] = {}
        self._sites: dict[tuple, int | None] = {}

    async def site_of(self, endpoint: dict) -> int | None:
        kind, rid = endpoint.get("type"), endpoint.get("id")
        if rid is None or kind not in ("power_feed", "circuit_termination"):
            return None
        key = (kind, int(rid))
        if key not in self._sites:
            if kind == "power_feed":
                row = await db.get_dcim_record("power_feed", int(rid))
            else:
                row = await db.get_circuit_termination(int(rid))
            site = (row or {}).get("site_id")
            self._sites[key] = int(site) if site is not None else None
        return self._sites[key]

    async def visible(self, endpoint: dict | None) -> bool:
        if self.hosts is None:
            return True
        if not endpoint:
            return False
        if endpoint.get("host_id") is not None:
            return int(endpoint["host_id"]) in self.hosts
        kind, rid = endpoint.get("type"), endpoint.get("id")
        if rid is None:
            return False
        key = (kind, int(rid))
        if key not in self._visible:
            if kind == "power_feed":
                row = await db.get_dcim_record("power_feed", int(rid))
                ok = await can_access(self.request, "power_feed", row)
            elif kind == "circuit_termination":
                row = await db.get_circuit_termination(int(rid))
                if row is not None and "circuit_tenant_id" not in row:
                    circuit = await db.get_circuit(int(row["circuit_id"])) if row.get("circuit_id") else None
                    row = {**row, "circuit_tenant_id": (circuit or {}).get("tenant_id")}
                ok = await can_access(self.request, "circuit_termination", row)
            else:
                ok = False
            self._visible[key] = ok
        return self._visible[key]

    async def cable_keys(self, cable: dict) -> dict:
        """``cable`` with ``scope_host_ids`` and ``scope_site_ids`` from its ends."""
        hosts, sites = [], []
        for side in ("a", "b"):
            end = cable.get(side) or {
                "type": cable.get(f"{side}_type"),
                "id": cable.get(f"{side}_id"),
                "host_id": cable.get(f"{side}_host_id"),
            }
            if end.get("host_id") is not None:
                hosts.append(int(end["host_id"]))
            site = await self.site_of(end)
            if site is not None:
                sites.append(site)
        return {**cable, "scope_host_ids": hosts, "scope_site_ids": sites}


async def _endpoint_scope(request: Request) -> _EndpointScope:
    return _EndpointScope(request, await readable_host_ids(request))


def _strip_cable_keys(cable: dict) -> dict:
    cable.pop("scope_host_ids", None)
    cable.pop("scope_site_ids", None)
    return cable


async def _visible_cables(request: Request, cables: list[dict]) -> list[dict]:
    """The cables a scoped caller may read (all for an unrestricted caller)."""
    scope = await _endpoint_scope(request)
    if scope.hosts is None:
        return cables
    keyed = [await scope.cable_keys(c) for c in cables]
    return [_strip_cable_keys(c) for c in await filter_rows("cable", keyed, request)]


async def _require_cable(request: Request, cable: dict | None, *, write: bool = False) -> dict:
    """The cable; 404 when unknown or outside the caller's read scope, 403
    on ``write`` when not writable."""
    if cable is None or (await request_scope(request)).unrestricted:
        return _found(cable, "Cable")
    keyed = await (await _endpoint_scope(request)).cable_keys(cable)
    await require_row(request, "cable", keyed, write=write, not_found="Cable not found")
    return cable


async def _check_new_cable(request: Request, values: dict, current: dict | None) -> None:
    """For a scoped caller: 422 (as for an unknown record) when a new end of
    the cable is one they may not see; 403 unless they may change a cable
    with the resulting tenant and ends."""
    scope = await _endpoint_scope(request)
    if scope.hosts is None:
        return
    for side in ("a", "b"):
        if side in values and not await scope.visible(values[side]):
            raise _invalid(f"Unknown endpoint on side {side.upper()}.", {side: "Unknown endpoint."})
    merged = {**(current or {}), **values}
    if "tenant_id" not in values and current is not None:
        merged["tenant_id"] = current.get("tenant_id")
    keyed = await scope.cable_keys({"a": merged.get("a") or {}, "b": merged.get("b") or {}})
    await require_new_row(request, "cable", {**keyed, "tenant_id": merged.get("tenant_id")})


def _hide_device(block: dict) -> None:
    block["host_id"] = None
    block["name"] = ""


async def _scoped_elevation(request: Request, drawing: dict) -> dict:
    """For a scoped caller: devices they may not read become anonymous
    occupied units (no ``host_id`` or name), unmounted ones are left out,
    and reservations they may not read lose their user and description."""
    hosts = await readable_host_ids(request)
    if hosts is None:
        return drawing
    rack = drawing.get("rack") or {}
    records = await db.list_dcim_records("rack_reservation", {"rack_id": rack.get("id")})
    readable = {int(r["id"]) for r in await filter_rows("rack_reservation", records, request)}
    for blocks in (drawing.get("faces") or {}).values():
        for block in blocks:
            if block.get("kind") == "device" and (block.get("host_id") is None or int(block["host_id"]) not in hosts):
                _hide_device(block)
            elif block.get("kind") == "reservation" and int(block.get("reservation_id") or 0) not in readable:
                block.update({"reservation_id": None, "description": "", "user": ""})
    drawing["unmounted"] = [
        d for d in drawing.get("unmounted") or [] if d.get("host_id") is not None and int(d["host_id"]) in hosts
    ]
    drawing["reservations"] = [r for r in drawing.get("reservations") or [] if int(r.get("id") or 0) in readable]
    return drawing


async def _scoped_trace(request: Request, result: dict) -> dict:
    """For a scoped caller: the trace up to (not including) the first hop
    that touches an endpoint they may not see; it then ends ``restricted``
    with no destination."""
    scope = await _endpoint_scope(request)
    if scope.hosts is None:
        return result
    for index, step in enumerate(result.get("steps") or []):
        if not (await scope.visible(step.get("near")) and await scope.visible(step.get("far"))):
            result["steps"] = result["steps"][:index]
            result.update({"status": "restricted", "is_loop": False, "destination": None})
            result.pop("power_panel", None)
            break
    else:
        if result.get("destination") is not None and not await scope.visible(result["destination"]):
            result.update({"status": "restricted", "destination": None})
            result.pop("power_panel", None)
    return result


# ── Resources ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Resource:
    kind: str
    path: str
    label: str
    create: type[BaseModel]
    names: tuple[str, ...] = ("name",)
    fixed: tuple[str, ...] = ()
    filters: tuple[str, ...] = ()
    describe: tuple[str, ...] = ("name",)
    update: type[BaseModel] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "update", _optional(self.create, self.fixed))


_RESOURCES: tuple[_Resource, ...] = (
    _Resource("rack_role", "rack-roles", "Rack role", RackRoleCreate),
    _Resource(
        "rack",
        "racks",
        "Rack",
        RackCreate,
        filters=("site_id", "floor_id", "role_id", "tenant_id", "status"),
    ),
    _Resource(
        "rack_reservation",
        "rack-reservations",
        "Rack reservation",
        RackReservationCreate,
        names=(),
        fixed=("rack_id",),
        filters=("rack_id", "tenant_id", "site_id"),
        describe=("rack_id", "units"),
    ),
    _Resource("rear_port", "rear-ports", "Rear port", RearPortCreate, fixed=("host_id",), filters=("host_id", "type")),
    _Resource(
        "front_port",
        "front-ports",
        "Front port",
        FrontPortCreate,
        fixed=("host_id",),
        filters=("host_id", "type", "rear_port_id"),
    ),
    _Resource(
        "module",
        "modules",
        "Module",
        ModuleCreate,
        names=("bay",),
        fixed=("host_id",),
        filters=("host_id", "status"),
        describe=("bay",),
    ),
    _Resource(
        "power_panel",
        "power-panels",
        "Power panel",
        PowerPanelCreate,
        fixed=("site_id",),
        filters=("site_id", "floor_id"),
    ),
    _Resource(
        "power_feed",
        "power-feeds",
        "Power feed",
        PowerFeedCreate,
        fixed=("power_panel_id",),
        filters=("power_panel_id", "rack_id", "site_id", "status"),
    ),
    _Resource("power_port", "power-ports", "Power port", PowerPortCreate, fixed=("host_id",), filters=("host_id",)),
    _Resource(
        "power_outlet",
        "power-outlets",
        "Power outlet",
        PowerOutletCreate,
        fixed=("host_id",),
        filters=("host_id", "power_port_id"),
    ),
    _Resource(
        "console_port",
        "console-ports",
        "Console port",
        ConsolePortCreate,
        fixed=("host_id",),
        filters=("host_id", "type"),
    ),
)

_INT_FILTERS = frozenset(
    {
        "site_id",
        "floor_id",
        "role_id",
        "tenant_id",
        "rack_id",
        "host_id",
        "rear_port_id",
        "power_panel_id",
        "power_port_id",
    }
)


def _filters_of(request: Request, allowed: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in allowed:
        raw = request.query_params.get(key)
        if raw is None or raw == "":
            continue
        if key in _INT_FILTERS:
            try:
                out[key] = int(raw)
            except ValueError as exc:
                raise _invalid(f"{key} must be an id.", {key: "Not an id."}) from exc
        else:
            out[key] = raw
    return out


def _summary(res: _Resource, record: dict) -> str:
    parts = [f"id={record.get('id')}"]
    parts.extend(f"{k}={record.get(k)}" for k in res.describe)
    return f"{res.kind} " + " ".join(parts)


def _register(res: _Resource) -> None:
    create_model_ = res.create
    update_model = res.update
    nullable = _nullable(res.create)
    base = f"{PREFIX}/{res.path}"

    model = _scope_model(res.kind)
    not_found = f"{res.label} not found"
    key_fields = ("tenant_id", "site_id", "rack_id", "power_panel_id", "host_id")

    @scoped("list")
    async def list_records(request: Request, q: str = Query("", max_length=200)) -> list[dict]:
        filters = _filters_of(request, res.filters)
        if (await request_scope(request)).unrestricted:
            rows = await db.list_dcim_records(res.kind, filters, q.strip())
        elif model == "host_record":
            rows = await db.list_dcim_records(res.kind, filters, q.strip(), host_ids=await readable_host_ids(request))
        elif model == "rack_role":
            rows = await _scoped_rack_roles(request, await db.list_dcim_records(res.kind, filters, q.strip()))
        else:
            rows = await db.list_dcim_records(res.kind, filters, q.strip(), any_of=await _scope_any_of(request, model))
        return await custom_list(res.kind, rows, request) if res.kind in OBJECT_TYPE_SPECS else rows

    async def _record(request: Request, record_id: int, *, write: bool = False) -> dict:
        record = _found(await db.get_dcim_record(res.kind, record_id), res.label)
        if (await request_scope(request)).unrestricted:
            return record
        return await require_row(request, model, record, write=write, not_found=not_found)

    @scoped(model)
    async def get_record(record_id: int, request: Request) -> dict:
        record = await _record(request, record_id)
        return await with_custom_data(res.kind, record) if res.kind in OBJECT_TYPE_SPECS else record

    @scoped("create")
    async def create_record(body: create_model_, request: Request) -> dict:  # type: ignore[valid-type]
        values = body.model_dump()  # type: ignore[attr-defined]
        _clean_names(values, res.names)
        if res.kind == "power_port":
            _validate_power_port(values)
        await _check_refs(values)
        if (await request_scope(request)).restricted:
            await _check_ref_scope(request, values)
            await require_new_row(request, model, await _scope_keys_of(res.kind, values))
        record = await _write(db.create_dcim_record(res.kind, values, _session_user(request)))
        await _audit_write(request, f"{res.kind}.create", _summary(res, record))
        return record

    @scoped(model)
    async def update_record(record_id: int, body: update_model, request: Request) -> dict:  # type: ignore[valid-type]
        current = await _record(request, record_id, write=True)
        values = body.model_dump(exclude_unset=True)  # type: ignore[attr-defined]
        nulls = [k for k, v in values.items() if v is None and k not in nullable]
        if nulls:
            raise _invalid("A value is required.", {k: "Required." for k in nulls})
        _clean_names(values, res.names)
        if res.kind == "power_port":
            _validate_power_port(values, current)
        await _check_refs(values)
        if (await request_scope(request)).restricted:
            await _check_ref_scope(request, values)
            if any(k in values and values[k] != current.get(k) for k in key_fields):
                await require_new_row(request, model, await _scope_keys_of(res.kind, {**current, **values}))
        record = _found(
            await _write(db.update_dcim_record(res.kind, record_id, values, _session_user(request))), res.label
        )
        await _audit_write(request, f"{res.kind}.update", _summary(res, record))
        return record

    @scoped(model)
    async def delete_record(record_id: int, request: Request) -> dict:
        current = await _record(request, record_id, write=True)
        usage = await db.count_dcim_usage(res.kind, record_id)
        if usage:
            what = ", ".join(f"{n} {label}" for label, n in usage.items())
            raise HTTPException(status_code=409, detail=f"{res.label} is in use ({what}).")
        await db.delete_dcim_record(res.kind, record_id)
        await _audit_write(request, f"{res.kind}.delete", _summary(res, current))
        return {"ok": True}

    router.add_api_route(base, list_records, methods=["GET"], name=f"list_{res.kind}")
    router.add_api_route(base, create_record, methods=["POST"], status_code=201, name=f"create_{res.kind}")
    router.add_api_route(f"{base}/{{record_id}}", get_record, methods=["GET"], name=f"get_{res.kind}")
    router.add_api_route(f"{base}/{{record_id}}", update_record, methods=["PUT"], name=f"update_{res.kind}")
    router.add_api_route(f"{base}/{{record_id}}", delete_record, methods=["DELETE"], name=f"delete_{res.kind}")


# Fixed paths first so ``/racks/{record_id}`` never shadows them.


@router.get(f"{PREFIX}/choices")
@scope_exempt("static choice lists")
async def dcim_choices() -> dict:
    """The fixed choice sets of every DCIM field, for forms and filters."""
    return {
        "rack_statuses": list(RACK_STATUSES),
        "rack_widths": list(RACK_WIDTHS),
        "faces": list(FACES),
        "port_types": list(PORT_TYPES),
        "module_statuses": list(MODULE_STATUSES),
        "feed_statuses": list(FEED_STATUSES),
        "feed_types": list(FEED_TYPES),
        "feed_supplies": list(FEED_SUPPLIES),
        "feed_phases": list(FEED_PHASES),
        "feed_legs": list(FEED_LEGS),
        "cable_statuses": list(CABLE_STATUSES),
        "cable_types": list(CABLE_TYPES),
        "length_units": list(LENGTH_UNITS),
        "endpoint_types": list(ENDPOINT_TYPES),
        "console_port_types": list(CONSOLE_PORT_TYPES),
    }


@router.get(f"{PREFIX}/trace")
@scoped("trace")
async def trace_endpoint(
    request: Request,
    type: EndpointType = Query(...),  # noqa: A002 - the API's parameter name
    id: int | None = Query(None),  # noqa: A002
    host_id: int | None = Query(None),
    name: str = Query("", max_length=INTERFACE_NAME_MAX),
) -> dict:
    """Follow the cables from an endpoint through patch panels (and, for
    power, outlets up to their PDU inlet) to the far end; see
    ``netcontrol.dcim.trace`` for the result."""
    endpoint = await db.resolve_cable_endpoint({"type": type, "id": id, "host_id": host_id, "name": name.strip()})
    if endpoint is None or not await (await _endpoint_scope(request)).visible(endpoint):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return await _scoped_trace(request, await db.trace_cable_endpoint(endpoint))


@router.get(f"{PREFIX}/racks/{{rack_id}}/elevation")
@scoped("rack")
async def rack_elevation(rack_id: int, request: Request) -> dict:
    """Each face of the rack unit by unit: devices, reservations and empty
    units, top first."""
    drawing = _found(await db.get_rack_elevation(rack_id), "Rack")
    if (await request_scope(request)).unrestricted:
        return drawing
    await require_row(request, "rack", drawing.get("rack"), not_found="Rack not found")
    return await _scoped_elevation(request, drawing)


@router.get(f"{PREFIX}/racks/{{rack_id}}/power")
@scoped("rack")
async def rack_power(rack_id: int, request: Request) -> dict:
    """The rack's feeds (available watts) against the draw of the devices
    in it. A scoped caller gets the rack's totals but only the ports of
    devices they may read."""
    rack = _found(await db.get_dcim_record("rack", rack_id), "Rack")
    hosts = await readable_host_ids(request)
    if hosts is None:
        return await db.get_rack_power(rack_id)
    await require_row(request, "rack", rack, not_found="Rack not found")
    power = await db.get_rack_power(rack_id)
    power["ports"] = [p for p in power.get("ports") or [] if int(p.get("host_id") or 0) in hosts]
    return power


@router.get(f"{PREFIX}/hosts/{{host_id}}")
@scoped("host")
async def host_dcim(host_id: int, request: Request) -> dict:
    """A device's rack placement, cables and DCIM record counts."""
    await require_host(request, host_id)
    return _found(await db.get_host_dcim_summary(host_id), "Host")


@router.get(f"{PREFIX}/hosts/{{host_id}}/interfaces")
@scoped("host")
async def host_interfaces(host_id: int, request: Request) -> dict:
    """The interface names known for a device (for cable endpoint pickers)."""
    await require_host(request, host_id)
    _found(await db.get_host_placement(host_id), "Host")
    return {"interfaces": await db.list_host_interface_names(host_id)}


async def check_host_placement(host_id: int, values: dict, site_id: Any = None, *, site_sent: bool = False) -> None:
    """422 when ``values`` (any of ``rack_id``, ``rack_position``,
    ``rack_face``) cannot be the host's placement; with ``site_sent`` the
    host's site is taken as ``site_id`` (a host edit that also moves it)."""
    if values.get("rack_id") is not None:
        await _check_refs({"rack_id": values["rack_id"]})
    if site_sent:
        problem = await db.host_placement_error(host_id, values, site_id)
    else:
        problem = await db.host_placement_error(host_id, values)
    if problem:
        raise _invalid(problem, {"rack_position" if "unit" in problem.lower() else "rack_id": problem})


async def apply_host_placement(host_id: int, values: dict) -> bool:
    """Write a checked placement (``routes.db.set_host_placement``); 422 if
    it stopped fitting in between. ``True`` when the host changed."""
    if not values:
        return False
    try:
        return bool(await db.set_host_placement(host_id, values))
    except db.DcimRuleError as exc:
        raise _invalid(str(exc)) from exc


@router.put(f"{PREFIX}/hosts/{{host_id}}/placement")
@scoped("host")
async def place_host(host_id: int, body: PlacementBody, request: Request) -> dict:
    """Mount a device in a rack, move it or take it out (``rack_id`` null)."""
    await require_host(request, host_id, write=True)
    _found(await db.get_host_placement(host_id), "Host")
    values = body.model_dump(exclude_unset=True)
    await _check_ref_scope(request, {"rack_id": values.get("rack_id")})
    await check_host_placement(host_id, values)
    await apply_host_placement(host_id, values)
    placement = _found(await db.get_host_placement(host_id), "Host")
    await _audit_write(
        request,
        "host.place",
        f"host={host_id} rack={placement['rack_id']} position={placement['rack_position']} face={placement['rack_face']}",
    )
    return placement


# ── Cables ───────────────────────────────────────────────────────────────────


async def _resolve(side: str, endpoint: Endpoint) -> dict:
    raw = endpoint.model_dump()
    raw["name"] = (raw.get("name") or "").strip()
    if raw["type"] == "interface" and (raw.get("host_id") is None or not raw["name"]):
        raise _invalid("An interface endpoint needs host_id and name.", {side: "Choose a device and an interface."})
    if raw["type"] != "interface" and raw.get("id") is None:
        raise _invalid(f"A {raw['type'].replace('_', ' ')} endpoint needs id.", {side: "Choose a record."})
    resolved = await db.resolve_cable_endpoint(raw)
    if resolved is None:
        what = "circuit termination" if raw["type"] == "circuit_termination" else raw["type"].replace("_", " ")
        raise _invalid(f"Unknown {what} on side {side.upper()}.", {side: f"Unknown {what}."})
    return resolved


async def _cable_values(body: BaseModel, current: dict | None) -> dict:
    values = body.model_dump(exclude_unset=current is not None)
    for key in ("label", "description"):
        if isinstance(values.get(key), str):
            values[key] = values[key].strip()
    for side in ("a", "b"):
        if side in values:
            if values[side] is None:
                raise _invalid("A cable needs both ends.", {side: "Required."})
            values[side] = await _resolve(side, getattr(body, side))
    a = values.get("a") or (current or {}).get("a")
    b = values.get("b") or (current or {}).get("b")
    cable_type = values.get("type", (current or {}).get("type", "")) or ""
    if a and b:
        if (
            a["type"] == b["type"]
            and a.get("id") == b.get("id")
            and a.get("host_id") == b.get("host_id")
            and a.get("name") == b.get("name")
        ):
            raise _invalid("A cable cannot join an endpoint to itself.", {"b": "Same as side A."})
        problem = pairing_error(a["type"], b["type"], cable_type)
        if problem:
            raise _invalid(problem, {"b": problem})
    for key in ("status", "type", "length_unit"):
        if key in values and values[key] is None:
            raise _invalid("A value is required.", {key: "Required."})
    if values.get("tenant_id") is not None:
        await _check_refs({"tenant_id": values["tenant_id"]})
    return values


CableUpdate = _optional(CableCreate)


def _cable_summary(cable: dict) -> str:
    return f"cable id={cable['id']} {cable['a'].get('label') or cable['a_type']} <-> {cable['b'].get('label') or cable['b_type']}"


@router.get(f"{PREFIX}/cables")
@scoped("list")
async def list_cables(
    request: Request,
    host_id: int | None = Query(None),
    type: str | None = Query(None, max_length=40),  # noqa: A002 - the API's parameter name
    status: str | None = Query(None, max_length=40),
    tenant_id: int | None = Query(None),
    endpoint_type: str | None = Query(None, max_length=40),
    q: str = Query("", max_length=200),
) -> list[dict]:
    filters = {
        "host_id": host_id,
        "type": type,
        "status": status,
        "tenant_id": tenant_id,
        "endpoint_type": endpoint_type,
    }
    host_ids = await readable_host_ids(request)
    if host_ids is None:
        cables = await db.list_cables(filters, q.strip())
    else:
        cables = await _visible_cables(request, await db.list_cables(filters, q.strip(), host_ids=host_ids))
    return await custom_list("cable", cables, request)


@router.get(f"{PREFIX}/cables/{{cable_id}}")
@scoped("cable")
async def get_cable(cable_id: int, request: Request) -> dict:
    return await with_custom_data("cable", await _require_cable(request, await db.get_cable(cable_id)))


@router.post(f"{PREFIX}/cables", status_code=201)
@scoped("create")
async def create_cable(body: CableCreate, request: Request) -> dict:
    values = await _cable_values(body, None)
    await _check_new_cable(request, values, None)
    cable_id = await _write(db.create_cable(values, _session_user(request)))
    cable = _found(await db.get_cable(cable_id), "Cable")
    await _audit_write(request, "cable.create", _cable_summary(cable))
    return cable


@router.put(f"{PREFIX}/cables/{{cable_id}}")
@scoped("cable")
async def update_cable(cable_id: int, body: CableUpdate, request: Request) -> dict:  # type: ignore[valid-type]
    current = await _require_cable(request, await db.get_cable(cable_id), write=True)
    values = await _cable_values(body, current)
    if values:
        await _check_new_cable(request, values, current)
    if values:
        await _write(db.update_cable(cable_id, values, _session_user(request)))
    cable = _found(await db.get_cable(cable_id), "Cable")
    await _audit_write(request, "cable.update", _cable_summary(cable))
    return cable


@router.delete(f"{PREFIX}/cables/{{cable_id}}")
@scoped("cable")
async def delete_cable(cable_id: int, request: Request) -> dict:
    current = await _require_cable(request, await db.get_cable(cable_id), write=True)
    await db.delete_cable(cable_id)
    await _audit_write(request, "cable.delete", _cable_summary(current))
    return {"ok": True}


for _res in _RESOURCES:
    _register(_res)
