"""Physical DCIM API: rack roles, racks, rack reservations, device placement
and elevation, patch panel front/rear ports, modules, power panels, feeds,
ports and outlets, cables, cable traces and rack power.

``router`` is registered in ``app.py`` behind ``require_auth`` and
``require_feature_method("dcim")``: read with ``dcim``, change with
``dcim.write``. DCIM is not enrolled in object scope (see
``netcontrol.object_scope``), so accounts limited to selected inventory
groups never reach it. Placing a device also works through the host edit
(``PUT /api/hosts/{id}`` with ``rack_id``/``rack_position``/``rack_face``),
which shares ``check_host_placement`` with this router.

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

from netcontrol.custom_fields import TEXT_MAX, TagColor
from netcontrol.dcim import (
    CABLE_STATUSES,
    CABLE_TYPES,
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

    async def list_records(request: Request, q: str = Query("", max_length=200)) -> list[dict]:
        return await db.list_dcim_records(res.kind, _filters_of(request, res.filters), q.strip())

    async def get_record(record_id: int) -> dict:
        return _found(await db.get_dcim_record(res.kind, record_id), res.label)

    async def create_record(body: create_model_, request: Request) -> dict:  # type: ignore[valid-type]
        values = body.model_dump()  # type: ignore[attr-defined]
        _clean_names(values, res.names)
        if res.kind == "power_port":
            _validate_power_port(values)
        await _check_refs(values)
        record = await _write(db.create_dcim_record(res.kind, values, _session_user(request)))
        await _audit_write(request, f"{res.kind}.create", _summary(res, record))
        return record

    async def update_record(record_id: int, body: update_model, request: Request) -> dict:  # type: ignore[valid-type]
        current = _found(await db.get_dcim_record(res.kind, record_id), res.label)
        values = body.model_dump(exclude_unset=True)  # type: ignore[attr-defined]
        nulls = [k for k, v in values.items() if v is None and k not in nullable]
        if nulls:
            raise _invalid("A value is required.", {k: "Required." for k in nulls})
        _clean_names(values, res.names)
        if res.kind == "power_port":
            _validate_power_port(values, current)
        await _check_refs(values)
        record = _found(
            await _write(db.update_dcim_record(res.kind, record_id, values, _session_user(request))), res.label
        )
        await _audit_write(request, f"{res.kind}.update", _summary(res, record))
        return record

    async def delete_record(record_id: int, request: Request) -> dict:
        current = _found(await db.get_dcim_record(res.kind, record_id), res.label)
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
    }


@router.get(f"{PREFIX}/trace")
async def trace_endpoint(
    type: EndpointType = Query(...),  # noqa: A002 - the API's parameter name
    id: int | None = Query(None),  # noqa: A002
    host_id: int | None = Query(None),
    name: str = Query("", max_length=INTERFACE_NAME_MAX),
) -> dict:
    """Follow the cables from an endpoint through patch panels (and, for
    power, outlets up to their PDU inlet) to the far end; see
    ``netcontrol.dcim.trace`` for the result."""
    endpoint = await db.resolve_cable_endpoint({"type": type, "id": id, "host_id": host_id, "name": name.strip()})
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return await db.trace_cable_endpoint(endpoint)


@router.get(f"{PREFIX}/racks/{{rack_id}}/elevation")
async def rack_elevation(rack_id: int) -> dict:
    """Each face of the rack unit by unit: devices, reservations and empty
    units, top first."""
    return _found(await db.get_rack_elevation(rack_id), "Rack")


@router.get(f"{PREFIX}/racks/{{rack_id}}/power")
async def rack_power(rack_id: int) -> dict:
    """The rack's feeds (available watts) against the draw of the devices
    in it."""
    _found(await db.get_dcim_record("rack", rack_id), "Rack")
    return await db.get_rack_power(rack_id)


@router.get(f"{PREFIX}/hosts/{{host_id}}")
async def host_dcim(host_id: int) -> dict:
    """A device's rack placement, cables and DCIM record counts."""
    return _found(await db.get_host_dcim_summary(host_id), "Host")


@router.get(f"{PREFIX}/hosts/{{host_id}}/interfaces")
async def host_interfaces(host_id: int) -> dict:
    """The interface names known for a device (for cable endpoint pickers)."""
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
async def place_host(host_id: int, body: PlacementBody, request: Request) -> dict:
    """Mount a device in a rack, move it or take it out (``rack_id`` null)."""
    _found(await db.get_host_placement(host_id), "Host")
    values = body.model_dump(exclude_unset=True)
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
async def list_cables(
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
    return await db.list_cables(filters, q.strip())


@router.get(f"{PREFIX}/cables/{{cable_id}}")
async def get_cable(cable_id: int) -> dict:
    return _found(await db.get_cable(cable_id), "Cable")


@router.post(f"{PREFIX}/cables", status_code=201)
async def create_cable(body: CableCreate, request: Request) -> dict:
    values = await _cable_values(body, None)
    cable_id = await _write(db.create_cable(values, _session_user(request)))
    cable = _found(await db.get_cable(cable_id), "Cable")
    await _audit_write(request, "cable.create", _cable_summary(cable))
    return cable


@router.put(f"{PREFIX}/cables/{{cable_id}}")
async def update_cable(cable_id: int, body: CableUpdate, request: Request) -> dict:  # type: ignore[valid-type]
    current = _found(await db.get_cable(cable_id), "Cable")
    values = await _cable_values(body, current)
    if values:
        await _write(db.update_cable(cable_id, values, _session_user(request)))
    cable = _found(await db.get_cable(cable_id), "Cable")
    await _audit_write(request, "cable.update", _cable_summary(cable))
    return cable


@router.delete(f"{PREFIX}/cables/{{cable_id}}")
async def delete_cable(cable_id: int, request: Request) -> dict:
    current = _found(await db.get_cable(cable_id), "Cable")
    await db.delete_cable(cable_id)
    await _audit_write(request, "cable.delete", _cable_summary(current))
    return {"ok": True}


for _res in _RESOURCES:
    _register(_res)
