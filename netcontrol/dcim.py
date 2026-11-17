"""Physical DCIM rules with no I/O: the choice sets, cable endpoint pairing,
rack unit maths (fit, overlap, elevation), the cable trace walk and the
power capacity maths.

Storage lives in ``routes.db.dcim``, the API in ``netcontrol.routes.dcim``;
both import from here so the rules exist once. See ``docs/dcim.md``.

Depth: every device is treated as full depth, so a device mounted on one
face occupies its units on both faces; the face only says which side it is
mounted from. Reservations hold their units on both faces too.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, get_args

__all__ = [
    "CableStatus",
    "CableType",
    "EndpointType",
    "Face",
    "FeedLeg",
    "FeedPhase",
    "FeedStatus",
    "FeedSupply",
    "FeedType",
    "LengthUnit",
    "ModuleStatus",
    "PortType",
    "RackStatus",
    "RackWidth",
    "CABLE_STATUSES",
    "CABLE_TYPES",
    "DATA_ENDPOINTS",
    "ENDPOINT_TYPES",
    "FACES",
    "FEED_LEGS",
    "FEED_PHASES",
    "FEED_STATUSES",
    "FEED_SUPPLIES",
    "FEED_TYPES",
    "HOST_ENDPOINTS",
    "LENGTH_UNITS",
    "MAX_TRACE_STEPS",
    "MODULE_STATUSES",
    "PORT_TYPES",
    "POWER_ENDPOINTS",
    "RACK_STATUSES",
    "RACK_WIDTHS",
    "CableGraph",
    "device_height",
    "draw_of",
    "elevation",
    "endpoint_key",
    "feed_available_power",
    "pairing_error",
    "placement_error",
    "rack_power_summary",
    "reservation_error",
    "trace",
    "unit_span",
]

RackStatus = Literal["active", "planned", "reserved", "available", "deprecated"]
RACK_STATUSES: tuple[str, ...] = get_args(RackStatus)
RackWidth = Literal[19, 23]
RACK_WIDTHS: tuple[int, ...] = get_args(RackWidth)
Face = Literal["front", "rear"]
FACES: tuple[str, ...] = get_args(Face)
PortType = Literal[
    "8p8c",
    "8p6c",
    "110-punch",
    "bnc",
    "f",
    "n",
    "fc",
    "lc",
    "lc-apc",
    "lsh",
    "mpo",
    "mtrj",
    "sc",
    "sc-apc",
    "st",
    "cs",
    "sn",
    "splice",
    "other",
]
PORT_TYPES: tuple[str, ...] = get_args(PortType)
ModuleStatus = Literal["active", "planned", "staged", "offline", "failed", "decommissioning"]
MODULE_STATUSES: tuple[str, ...] = get_args(ModuleStatus)
FeedStatus = Literal["active", "planned", "offline", "failed"]
FEED_STATUSES: tuple[str, ...] = get_args(FeedStatus)
FeedType = Literal["primary", "redundant"]
FEED_TYPES: tuple[str, ...] = get_args(FeedType)
FeedSupply = Literal["ac", "dc"]
FEED_SUPPLIES: tuple[str, ...] = get_args(FeedSupply)
FeedPhase = Literal["single", "three"]
FEED_PHASES: tuple[str, ...] = get_args(FeedPhase)
FeedLeg = Literal["", "A", "B", "C"]
FEED_LEGS: tuple[str, ...] = get_args(FeedLeg)
CableStatus = Literal["connected", "planned", "decommissioning"]
CABLE_STATUSES: tuple[str, ...] = get_args(CableStatus)
CableType = Literal[
    "",
    "cat3",
    "cat5",
    "cat5e",
    "cat6",
    "cat6a",
    "cat7",
    "cat8",
    "dac-active",
    "dac-passive",
    "mrj21-trunk",
    "coaxial",
    "mmf",
    "mmf-om1",
    "mmf-om2",
    "mmf-om3",
    "mmf-om4",
    "mmf-om5",
    "smf",
    "smf-os1",
    "smf-os2",
    "aoc",
    "power",
]
CABLE_TYPES: tuple[str, ...] = get_args(CableType)
LengthUnit = Literal["", "m", "cm", "ft", "in"]
LENGTH_UNITS: tuple[str, ...] = get_args(LengthUnit)

EndpointType = Literal[
    "interface", "front_port", "rear_port", "circuit_termination", "power_port", "power_outlet", "power_feed"
]
ENDPOINT_TYPES: tuple[str, ...] = get_args(EndpointType)
DATA_ENDPOINTS: tuple[str, ...] = ENDPOINT_TYPES[:4]
POWER_ENDPOINTS: tuple[str, ...] = ENDPOINT_TYPES[4:]
# Endpoint types that belong to a host (the cable is deleted with the host).
HOST_ENDPOINTS: frozenset[str] = frozenset({"interface", "front_port", "rear_port", "power_port", "power_outlet"})

# Power endpoint pairs a cable may join (either order).
_POWER_PAIRS: frozenset[frozenset[str]] = frozenset(
    {frozenset({"power_port", "power_outlet"}), frozenset({"power_port", "power_feed"})}
)

# The longest trace walked before it is cut off as a loop.
MAX_TRACE_STEPS = 256


# ── Cable endpoints ──────────────────────────────────────────────────────────


def endpoint_key(endpoint_type: str, endpoint_id: int | None = None, host_id: int | None = None, name: str = "") -> str:
    """The unique key of an endpoint: ``interface:<host id>:<name>`` for an
    interface, ``<type>:<id>`` for everything else."""
    if endpoint_type == "interface":
        return f"interface:{int(host_id or 0)}:{name}"
    return f"{endpoint_type}:{int(endpoint_id or 0)}"


def pairing_error(a_type: str, b_type: str, cable_type: str = "") -> str | None:
    """Why a cable may not join ``a_type`` to ``b_type`` (with cable type
    ``cable_type``), or ``None`` when it may. Power joins only power (a power
    port to an outlet or a feed), data only data (never two circuit
    terminations), and a ``power`` cable only power endpoints."""
    for t in (a_type, b_type):
        if t not in ENDPOINT_TYPES:
            return f"Unknown endpoint type '{t}'."
    a_power, b_power = a_type in POWER_ENDPOINTS, b_type in POWER_ENDPOINTS
    if a_power != b_power:
        return "A cable joins power endpoints only to power endpoints and data endpoints only to data endpoints."
    if a_power:
        if frozenset({a_type, b_type}) not in _POWER_PAIRS:
            return f"A power cable cannot join a {a_type.replace('_', ' ')} to a {b_type.replace('_', ' ')}."
        if cable_type not in ("", "power"):
            return "A cable between power endpoints must have type 'power'."
        return None
    if a_type == b_type == "circuit_termination":
        return "A cable cannot join two circuit terminations."
    if cable_type == "power":
        return "A 'power' cable can only join power endpoints."
    return None


# ── Rack units ───────────────────────────────────────────────────────────────


def device_height(u_height: int | None) -> int:
    """Units a device takes: its device type's height, 1 when unknown (0)."""
    try:
        value = int(u_height or 0)
    except TypeError, ValueError:
        value = 0
    return value if value > 0 else 1


def unit_span(position: int, height: int) -> list[int]:
    """The units from ``position`` (the lowest) up, ``height`` of them."""
    return list(range(int(position), int(position) + max(1, int(height))))


def _occupancy(devices: Iterable[Mapping[str, Any]], reservations: Iterable[Mapping[str, Any]]) -> dict[int, str]:
    """Unit -> what holds it, for mounted devices (full depth: both faces)
    and reservations."""
    held: dict[int, str] = {}
    for device in devices:
        if device.get("position") is None:
            continue
        for unit in unit_span(int(device["position"]), device_height(device.get("height"))):
            held.setdefault(unit, f"device '{device.get('name') or device.get('host_id')}'")
    for reservation in reservations:
        for unit in reservation.get("units") or []:
            label = str(reservation.get("description") or "").strip()
            held.setdefault(int(unit), f"a reservation ({label})" if label else "a reservation")
    return held


def placement_error(
    u_height: int,
    position: int,
    height: int,
    others: Iterable[Mapping[str, Any]] = (),
    reservations: Iterable[Mapping[str, Any]] = (),
) -> str | None:
    """Why a device of ``height`` units cannot be mounted at ``position`` in
    a rack of ``u_height`` units, given the ``others`` mounted there
    (``position``, ``height``, ``name``; the device itself excluded) and the
    rack's ``reservations`` (``units``); ``None`` when it fits."""
    height = max(1, int(height))
    if position < 1:
        return "The position must be unit 1 or higher."
    top = position + height - 1
    if top > u_height:
        return f"A {height}U device at unit {position} reaches unit {top}; the rack has {u_height} units."
    held = _occupancy(others, reservations)
    for unit in unit_span(position, height):
        if unit in held:
            return f"Unit {unit} is taken by {held[unit]}."
    return None


def reservation_error(
    u_height: int,
    units: Iterable[int],
    devices: Iterable[Mapping[str, Any]] = (),
    others: Iterable[Mapping[str, Any]] = (),
) -> str | None:
    """Why ``units`` cannot be reserved in a rack of ``u_height`` units with
    the mounted ``devices`` and the ``other`` reservations; ``None`` when
    they can."""
    wanted = sorted({int(u) for u in units})
    if not wanted:
        return "Reserve at least one unit."
    if wanted[0] < 1 or wanted[-1] > u_height:
        return f"Units must be between 1 and {u_height}."
    held = _occupancy(devices, others)
    for unit in wanted:
        if unit in held:
            return f"Unit {unit} is taken by {held[unit]}."
    return None


def elevation(
    u_height: int,
    desc_units: bool,
    devices: Iterable[Mapping[str, Any]],
    reservations: Iterable[Mapping[str, Any]] = (),
) -> dict:
    """The drawing of a rack: for each face, blocks in display order (top
    of the rack first). A block is a mounted device (``kind`` ``device``,
    ``host_id``, ``name``, ``face`` it is mounted from, ``mounted_here``
    False on the opposite face of a full-depth device), a reservation
    (``kind`` ``reservation``) or one empty unit; each has the ``units`` it
    covers (in display order) and ``height``. Devices with no position, or
    one that would fall outside the rack, are listed in ``unmounted``."""
    devices = list(devices)
    reservations = list(reservations)
    display = list(range(1, u_height + 1)) if desc_units else list(range(u_height, 0, -1))
    owner: dict[int, tuple[str, int]] = {}
    unmounted: list[dict] = []
    for index, device in enumerate(devices):
        position = device.get("position")
        height = device_height(device.get("height"))
        span = unit_span(int(position), height) if position is not None else []
        if not span or span[0] < 1 or span[-1] > u_height or any(u in owner for u in span):
            unmounted.append(dict(device))
            continue
        for unit in span:
            owner[unit] = ("device", index)
    for index, reservation in enumerate(reservations):
        for unit in reservation.get("units") or []:
            if 1 <= int(unit) <= u_height:
                owner.setdefault(int(unit), ("reservation", index))

    faces: dict[str, list[dict]] = {}
    for face in FACES:
        blocks: list[dict] = []
        for unit in display:
            hold = owner.get(unit)
            if blocks and hold is not None and blocks[-1].get("_hold") == hold:
                blocks[-1]["units"].append(unit)
                blocks[-1]["height"] += 1
                continue
            if hold is None:
                blocks.append({"kind": "empty", "units": [unit], "height": 1, "_hold": None})
            elif hold[0] == "device":
                device = devices[hold[1]]
                mounted = str(device.get("face") or "front")
                blocks.append(
                    {
                        "kind": "device",
                        "host_id": device.get("host_id"),
                        "name": device.get("name") or "",
                        "position": int(device["position"]),
                        "face": mounted,
                        "mounted_here": mounted == face,
                        "units": [unit],
                        "height": 1,
                        "_hold": hold,
                    }
                )
            else:
                reservation = reservations[hold[1]]
                blocks.append(
                    {
                        "kind": "reservation",
                        "reservation_id": reservation.get("id"),
                        "description": reservation.get("description") or "",
                        "user": reservation.get("user") or "",
                        "units": [unit],
                        "height": 1,
                        "_hold": hold,
                    }
                )
        for block in blocks:
            block.pop("_hold", None)
        faces[face] = blocks
    used = len(owner)
    return {
        "u_height": u_height,
        "desc_units": bool(desc_units),
        "units": display,
        "faces": faces,
        "unmounted": unmounted,
        "used_units": used,
        "free_units": u_height - used,
    }


# ── Cable trace ──────────────────────────────────────────────────────────────


@dataclass
class CableGraph:
    """What a trace walks: cables by endpoint key, the patch panel and PDU
    mappings, and display data. Built by ``routes.db.dcim`` from the stored
    rows; any map may hold only the records a trace can reach.

    ``cables``: id -> row with ``a_*``/``b_*`` endpoint columns.
    ``front_ports``: id -> row with ``rear_port_id``, ``rear_port_position``.
    ``rear_ports``: id -> row with ``positions``.
    ``power_outlets``: id -> row with ``power_port_id``.
    ``power_feeds``: id -> row with ``power_panel_id`` (and panel display data).
    ``existing``: endpoint keys of records that exist (others are missing).
    ``labels``: endpoint key -> display fields merged into the endpoint.
    """

    cables: dict[int, dict] = field(default_factory=dict)
    front_ports: dict[int, dict] = field(default_factory=dict)
    rear_ports: dict[int, dict] = field(default_factory=dict)
    power_outlets: dict[int, dict] = field(default_factory=dict)
    power_feeds: dict[int, dict] = field(default_factory=dict)
    existing: set[str] = field(default_factory=set)
    labels: dict[str, dict] = field(default_factory=dict)
    _by_endpoint: dict[str, tuple[int, str]] = field(default_factory=dict, init=False, repr=False)
    _front_by_rear: dict[tuple[int, int], int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        for cable_id, cable in self.cables.items():
            for side in ("a", "b"):
                key = endpoint_key(
                    cable[f"{side}_type"],
                    cable.get(f"{side}_id"),
                    cable.get(f"{side}_host_id"),
                    cable.get(f"{side}_name") or "",
                )
                self._by_endpoint[key] = (int(cable_id), side)
        for front_id, front in self.front_ports.items():
            self._front_by_rear[(int(front["rear_port_id"]), int(front["rear_port_position"]))] = int(front_id)

    def cable_at(self, endpoint: Mapping[str, Any]) -> tuple[dict, dict] | None:
        """The cable on ``endpoint`` and the endpoint at its other end."""
        found = self._by_endpoint.get(_key(endpoint))
        if found is None:
            return None
        cable = self.cables[found[0]]
        far = "b" if found[1] == "a" else "a"
        return cable, _endpoint_from(cable, far)

    def front_at(self, rear_port_id: int, position: int) -> int | None:
        return self._front_by_rear.get((int(rear_port_id), int(position)))

    def describe(self, endpoint: Mapping[str, Any]) -> dict:
        key = _key(endpoint)
        out = {
            "type": endpoint["type"],
            "id": endpoint.get("id"),
            "host_id": endpoint.get("host_id"),
            "name": endpoint.get("name") or "",
            "missing": endpoint["type"] != "interface" and key not in self.existing,
        }
        out.update(self.labels.get(key, {}))
        return out


def _key(endpoint: Mapping[str, Any]) -> str:
    return endpoint_key(endpoint["type"], endpoint.get("id"), endpoint.get("host_id"), endpoint.get("name") or "")


def _endpoint_from(cable: Mapping[str, Any], side: str) -> dict:
    return {
        "type": cable[f"{side}_type"],
        "id": cable.get(f"{side}_id"),
        "host_id": cable.get(f"{side}_host_id"),
        "name": cable.get(f"{side}_name") or "",
    }


def _cable_summary(cable: Mapping[str, Any]) -> dict:
    return {k: cable.get(k) for k in ("id", "label", "type", "status", "color", "length", "length_unit") if k in cable}


def trace(graph: CableGraph, start: Mapping[str, Any]) -> dict:
    """Follow the cables from ``start`` (an endpoint: ``type``, ``id`` or
    ``host_id`` + ``name``) to where the path ends.

    A front port passes through to its rear port position, a rear port back
    to the front port of the position it was entered on (a single-position
    rear port to its one front port), and a power outlet up to the power port
    that feeds it (a trace from an outlet starts with that hop). The walk
    ends at an interface, a circuit termination, a power port or a power
    feed (``status`` ``complete``), at an endpoint with no cable
    (``unconnected`` at the start, else ``dead_end``), at a deleted record
    (``missing``), at a multi-position rear port entered without a position
    (``ambiguous``), or when it reaches a state it has been in (``loop``).

    ``steps`` lists, in order, ``{"kind": "cable", "near", "cable", "far"}``
    and ``{"kind": "internal", "near", "far", "position"}`` hops.
    """
    steps: list[dict] = []
    stack: list[int] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()
    current: dict = {k: start.get(k) for k in ("type", "id", "host_id", "name")}
    current["name"] = current.get("name") or ""
    status = "complete"

    def finish(state: str, destination: Mapping[str, Any] | None) -> dict:
        result = {
            "start": graph.describe(start),
            "steps": steps,
            "status": state,
            "is_loop": state == "loop",
            "destination": graph.describe(destination) if destination is not None else None,
        }
        if destination is not None and destination["type"] == "power_feed":
            feed = graph.power_feeds.get(int(destination.get("id") or 0)) or {}
            result["power_panel"] = (
                {"id": feed.get("power_panel_id"), "name": feed.get("power_panel_name", "")} if feed else None
            )
        return result

    if current["type"] == "power_outlet":
        hop = _outlet_hop(graph, current)
        if hop is None:
            return finish("dead_end", current)
        steps.append(
            {"kind": "internal", "near": graph.describe(current), "far": graph.describe(hop), "position": None}
        )
        current = hop

    while True:
        state = (_key(current), tuple(stack))
        if state in seen or len(steps) >= MAX_TRACE_STEPS:
            return finish("loop", current)
        seen.add(state)
        found = graph.cable_at(current)
        if found is None:
            return finish("unconnected" if not steps else "dead_end", current)
        cable, far = found
        steps.append(
            {
                "kind": "cable",
                "near": graph.describe(current),
                "cable": _cable_summary(cable),
                "far": graph.describe(far),
            }
        )
        far_type = far["type"]
        if far_type != "interface" and _key(far) not in graph.existing:
            return finish("missing", far)
        if far_type in ("interface", "circuit_termination", "power_port", "power_feed"):
            return finish(status, far)
        nxt: dict | None
        position: int | None = None
        if far_type == "power_outlet":
            nxt = _outlet_hop(graph, far)
        elif far_type == "front_port":
            front = graph.front_ports[int(far["id"])]
            rear = graph.rear_ports.get(int(front["rear_port_id"])) or {}
            position = int(front["rear_port_position"])
            if int(rear.get("positions") or 1) > 1:
                stack.append(position)
            nxt = _port("rear_port", int(front["rear_port_id"]), rear)
        else:  # rear_port
            rear = graph.rear_ports[int(far["id"])]
            if int(rear.get("positions") or 1) > 1:
                if not stack:
                    return finish("ambiguous", far)
                position = stack.pop()
            else:
                position = 1
            front_id = graph.front_at(int(far["id"]), position)
            nxt = _port("front_port", front_id, graph.front_ports.get(front_id) or {}) if front_id else None
        if nxt is None:
            return finish("dead_end", far)
        steps.append(
            {"kind": "internal", "near": graph.describe(far), "far": graph.describe(nxt), "position": position}
        )
        current = nxt


def _port(endpoint_type: str, port_id: int, row: Mapping[str, Any]) -> dict:
    return {"type": endpoint_type, "id": port_id, "host_id": row.get("host_id"), "name": ""}


def _outlet_hop(graph: CableGraph, outlet: Mapping[str, Any]) -> dict | None:
    row = graph.power_outlets.get(int(outlet.get("id") or 0)) or {}
    port_id = row.get("power_port_id")
    if not port_id:
        return None
    return {"type": "power_port", "id": int(port_id), "host_id": row.get("host_id"), "name": ""}


# ── Power ────────────────────────────────────────────────────────────────────


def feed_available_power(voltage: int, amperage: int, phase: str, max_utilization: int, supply: str = "ac") -> int:
    """Usable watts of a feed: volts x amps (x sqrt 3 for three-phase AC) x
    the maximum utilisation. Power factor 1 (watts = volt-amperes)."""
    factor = math.sqrt(3) if phase == "three" and supply != "dc" else 1.0
    return int(round(abs(int(voltage)) * int(amperage) * factor * int(max_utilization) / 100))


def draw_of(port: Mapping[str, Any]) -> int:
    """The draw a power port counts for: its allocated draw, else its
    maximum draw, else 0."""
    for key in ("allocated_draw", "maximum_draw"):
        value = port.get(key)
        if value is not None:
            return int(value)
    return 0


def _pct(part: float, whole: float) -> float | None:
    return round(part * 100.0 / whole, 1) if whole > 0 else None


def rack_power_summary(feeds: Iterable[Mapping[str, Any]], ports: Iterable[Mapping[str, Any]]) -> dict:
    """The power of a rack: each of its ``feeds`` with its available watts
    and the draw of the ``ports`` that trace to it (``feed_id``), and the
    totals. ``ports`` are the device power ports in the rack (PDU inlets
    excluded, they pass the same draw on). Capacity counts the primary
    feeds only: a redundant feed backs up a primary one."""
    ports = list(ports)
    out_feeds: list[dict] = []
    capacity = 0
    for feed in feeds:
        available = feed_available_power(
            int(feed.get("voltage") or 0),
            int(feed.get("amperage") or 0),
            str(feed.get("phase") or "single"),
            int(feed.get("max_utilization") or 0),
            str(feed.get("supply") or "ac"),
        )
        allocated = sum(draw_of(p) for p in ports if p.get("feed_id") == feed.get("id"))
        if feed.get("type", "primary") == "primary" and feed.get("status", "active") != "offline":
            capacity += available
        out_feeds.append(
            {
                "id": feed.get("id"),
                "name": feed.get("name") or "",
                "type": feed.get("type") or "primary",
                "status": feed.get("status") or "active",
                "available_power": available,
                "allocated_draw": allocated,
                "utilization": _pct(allocated, available),
            }
        )
    allocated_total = sum(draw_of(p) for p in ports)
    unfed = sum(draw_of(p) for p in ports if p.get("feed_id") is None)
    return {
        "feeds": out_feeds,
        "capacity": capacity,
        "allocated_draw": allocated_total,
        "unfed_draw": unfed,
        "utilization": _pct(allocated_total, capacity),
        "port_count": len(ports),
    }
