"""Hardware components with a serial, per host, and the history of their
changes (replaced, installed, removed, moved, changed).

What is read (docs/hardware-inventory.md has the per-vendor table):

* SNMP, ENTITY-MIB (RFC 6933) ``entPhysicalTable``, for every SNMP-polled
  device type. A bounded read: one walk of ``entPhysicalSerialNum``
  (``.11``, capped at ``WALK_MAX_ROWS``), the rows with a real serial kept
  (``routes.snmp.real_serial``: no placeholder, no zeros), then GETs of the
  other columns for those rows only (descr ``.2``, containedIn ``.4``,
  class ``.5``, parentRelPos ``.6``, name ``.7``, hardwareRev ``.8``,
  firmwareRev ``.9``, softwareRev ``.10``, modelName ``.13``, isFRU
  ``.16``), and of the class and name of their parents, in requests of
  ``snmp_health.OIDS_PER_GET``.
* SNMP, JUNIPER-MIB ``jnxContentsTable`` (1.3.6.1.4.1.2636.3.1.8.1) for
  Junos, read first, with the box scalars ``jnxBoxDescr`` / ``jnxBoxSerialNo``
  / ``jnxBoxRevision`` as the chassis and ``jnxFruType`` (same index) for
  the category; ENTITY-MIB when the Juniper table lists nothing.
* SSH, ``show inventory`` on the Cisco platforms
  (``netcontrol.drivers.show_inventory``), when an operator runs the fetch
  serial action.

A read has three outcomes, as the poll's health checks: not read (a walk
cut short by a timeout or the row cap, a GET unanswered, more than
``MAX_COMPONENTS`` serials) changes nothing; read with components; read
with none (a walk to its end that lists no serial).

Identity: a component is its serial on a host (``serial_key``: trimmed,
upper case); ``entPhysicalIndex`` may be renumbered after a reload, so it
is not kept. Two rows of one read with the same serial (a fixed switch
whose built-in module carries the chassis serial) are one component: the
row of the first category in ``CATEGORIES`` order (chassis first), a field
replaceable unit before one that is not, else the first in MIB order.

Category (ENTITY-MIB ``entPhysicalClass``, IANA-ENTITY-MIB): chassis(3) is
``chassis``, powerSupply(6) ``power_supply``, fan(7) ``fan``; a port(10)
with a serial, a row contained in a port, or a row whose text names an
optic (``show_inventory.is_transceiver_text``: model or description
starting SFP / QSFP / GLC- ..., "transceiver", an interface name) is a
``transceiver``; module(9) is ``module``; any other class ``other``.

``slot``: the row's ``entPhysicalName``, else its parent's name, else its
description.

Change detection (``diff_components``, pure): see docs/hardware-inventory.md.

SNMP and SSH do not take turns on a host: an SSH read is not stored for a
host with a recent complete SNMP read (``collect_over_ssh``).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as db

from netcontrol import health_checks, module_health, monitoring_repoll, snmp_health as sh
from netcontrol.drivers.show_inventory import category_of, is_transceiver_text, parse_show_inventory
from netcontrol.routes.snmp import oid_sort_key, real_serial, snmp_int

LOGGER = logging.getLogger("plexus.hardware_components")

CHASSIS = "chassis"
MODULE = "module"
POWER_SUPPLY = "power_supply"
FAN = "fan"
TRANSCEIVER = "transceiver"
OTHER = "other"
# Also the preference order of the rows of one serial.
CATEGORIES: tuple[str, ...] = (CHASSIS, MODULE, POWER_SUPPLY, FAN, TRANSCEIVER, OTHER)

PRESENT = "present"
MISSING = "missing"
REMOVED = "removed"
STATUSES: tuple[str, ...] = (PRESENT, MISSING, REMOVED)

BASELINE = "baseline"
INSTALLED = "installed"
REPLACED = "replaced"
MOVED = "moved"
CHANGED = "changed"
EVENTS: tuple[str, ...] = (BASELINE, INSTALLED, REMOVED, REPLACED, MOVED, CHANGED)

SNMP = "snmp"
SSH = "ssh"
SOURCES: tuple[str, ...] = (SNMP, SSH)

# Collection state of a host (``hardware_collection_state.result``).
STATE_OK = "ok"
STATE_NEVER = "never"
STATE_NOT_READ = "not_read"

# A host's components are read by the poll at most this often...
COLLECT_INTERVAL_SECONDS = 6 * 3600
# ...a read that came back not read is tried again after this long...
NOT_READ_RETRY_SECONDS = 1800
# ...and at the next poll that reaches the device while a component is
# missing, an empty read waits for confirmation, or an event marked the
# host (``monitoring_repoll.mark_hardware_stale``).

# The rows the serial column walk may return: every entity of the device,
# with or without a serial (a large chassis lists several thousand ports,
# sensors and containers), so more than the health walks' cap.
WALK_MAX_ROWS = 20000
# The most components (rows with a serial) one read takes; a device listing
# more is not read.
MAX_COMPONENTS = 2000
# Complete reads with no component, in a row, before a host that has
# components is taken at its word (a device just after a reload may list
# none).
EMPTY_CONFIRM_READS = 3
# A component missing from complete reads becomes removed only once it has
# been missing this long (a line card still booting after a chassis reload
# fills its entity rows in over several minutes, and a host with a missing
# component is read again at every poll).
REMOVE_CONFIRM_SECONDS = 1800
# A new serial in a slot whose component was removed this recently is a
# replacement of it (a swap slower than REMOVE_CONFIRM_SECONDS).
REPLACE_WINDOW_SECONDS = 30 * 24 * 3600

# Fields compared for a ``changed`` event.
COMPARED_FIELDS: tuple[str, ...] = ("model", "hardware_rev", "firmware_rev", "software_rev")
_TEXT_FIELDS: tuple[str, ...] = ("slot", "name", "description", "model", "hardware_rev", "firmware_rev", "software_rev")
_TEXT_MAX = 255

# ENTITY-MIB columns GET for each row with a serial, and for their parents.
_ENTITY_COLUMNS: tuple[str, ...] = (
    sh.ENT_PHYSICAL_DESCR,
    sh.ENT_PHYSICAL_CONTAINED_IN,
    sh.ENT_PHYSICAL_CLASS,
    sh.ENT_PHYSICAL_PARENT_REL_POS,
    sh.ENT_PHYSICAL_NAME,
    sh.ENT_PHYSICAL_HARDWARE_REV,
    sh.ENT_PHYSICAL_FIRMWARE_REV,
    sh.ENT_PHYSICAL_SOFTWARE_REV,
    sh.ENT_PHYSICAL_MODEL,
    sh.ENT_PHYSICAL_IS_FRU,
)
_PARENT_COLUMNS: tuple[str, ...] = (sh.ENT_PHYSICAL_CLASS, sh.ENT_PHYSICAL_NAME)

# JUNIPER-MIB (jnxBoxAnatomy = 1.3.6.1.4.1.2636.3.1): the box scalars and
# the jnxContentsTable columns, indexed by jnxContentsContainerIndex.L1.L2.L3
# (the index of jnxFruTable too).
JNX_BOX_DESCR = "1.3.6.1.4.1.2636.3.1.2.0"
JNX_BOX_SERIAL = "1.3.6.1.4.1.2636.3.1.3.0"
JNX_BOX_REVISION = "1.3.6.1.4.1.2636.3.1.4.0"
JNX_CONTENTS_DESCR = "1.3.6.1.4.1.2636.3.1.8.1.6"
JNX_CONTENTS_SERIAL = "1.3.6.1.4.1.2636.3.1.8.1.7"
JNX_CONTENTS_REVISION = "1.3.6.1.4.1.2636.3.1.8.1.8"
JNX_CONTENTS_PART_NO = "1.3.6.1.4.1.2636.3.1.8.1.10"
JNX_CONTENTS_CHASSIS_DESCR = "1.3.6.1.4.1.2636.3.1.8.1.12"
JNX_CONTENTS_MODEL = "1.3.6.1.4.1.2636.3.1.8.1.14"
_JNX_COLUMNS: tuple[str, ...] = (
    JNX_CONTENTS_DESCR,
    JNX_CONTENTS_REVISION,
    JNX_CONTENTS_PART_NO,
    JNX_CONTENTS_CHASSIS_DESCR,
    JNX_CONTENTS_MODEL,
    module_health.JNX_FRU_TYPE,
)

# ``walk_table(oid, max_rows) -> (rows, ran to its end)``: the poll's walker.
WalkTable = Callable[[str, int], Awaitable[tuple[dict, bool]]]

# Hosts with a read being stored (the poll and a refresh do not store one
# host's reads at the same time).
_APPLYING: set[int] = set()


class HardwareReadBusy(RuntimeError):
    """A read of the host is being stored already."""


def forget_all() -> None:
    """Drop every per-process memory (tests; host ids restart with the database)."""
    _APPLYING.clear()
    monitoring_repoll.forget_hardware_stale()


# ── Components ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Component:
    """One hardware component of a read."""

    category: str
    slot: str
    name: str
    description: str
    model: str
    serial: str
    hardware_rev: str = ""
    firmware_rev: str = ""
    software_rev: str = ""
    fru: bool = True

    def values(self) -> dict[str, str]:
        out = {k: _clip(getattr(self, k)) for k in _TEXT_FIELDS}
        out["category"] = self.category
        out["serial"] = _clip(self.serial)
        return out


def _clip(value: Any) -> str:
    return str(value or "").strip()[:_TEXT_MAX]


def serial_key(serial: str) -> str:
    """The identity of a serial: trimmed, upper case (one agent may print it
    in another case than ``show inventory``)."""
    return str(serial or "").strip().upper()


def dedupe(components: Iterable[Component]) -> list[Component]:
    """One component per serial: the row of the first category in
    ``CATEGORIES`` order, a field replaceable unit before one that is not,
    else the first read. Kept in the order each serial first appeared."""
    best: dict[str, tuple[int, Component]] = {}
    order: list[str] = []
    for position, comp in enumerate(components):
        key = serial_key(comp.serial)
        if not key:
            continue
        if key not in best:
            order.append(key)
            best[key] = (position, comp)
            continue
        current = best[key][1]
        if _rank(comp) < _rank(current):
            best[key] = (best[key][0], comp)
    return [best[key][1] for key in order]


def _rank(comp: Component) -> tuple[int, int]:
    category = CATEGORIES.index(comp.category) if comp.category in CATEGORIES else len(CATEGORIES)
    return category, 0 if comp.fru else 1


# ── SNMP: ENTITY-MIB ─────────────────────────────────────────────────────────


def entity_category(values: dict[str, Any], parent_class: int | None) -> str:
    """A component's category from its entPhysicalTable row and its
    parent's class (see the module docstring)."""
    klass = snmp_int(values.get(sh.ENT_PHYSICAL_CLASS))
    if klass == sh.PHYSICAL_CLASS_CHASSIS:
        return CHASSIS
    if klass == sh.PHYSICAL_CLASS_POWER_SUPPLY:
        return POWER_SUPPLY
    if klass == sh.PHYSICAL_CLASS_FAN:
        return FAN
    name = sh.text(values.get(sh.ENT_PHYSICAL_NAME))
    descr = sh.text(values.get(sh.ENT_PHYSICAL_DESCR))
    model = sh.text(values.get(sh.ENT_PHYSICAL_MODEL))
    if (
        klass == sh.PHYSICAL_CLASS_PORT
        or parent_class == sh.PHYSICAL_CLASS_PORT
        or is_transceiver_text(name, descr, model)
    ):
        return TRANSCEIVER
    if klass == sh.PHYSICAL_CLASS_MODULE:
        return MODULE
    return OTHER


def parse_entity_rows(
    serials: dict[str, str], values: dict[str, Any], parents: dict[str, Any] | None = None
) -> list[Component]:
    """The components of an entPhysicalTable read: ``serials`` ``{index:
    real serial}``, ``values`` the GET answers of the rows' columns,
    ``parents`` those of their parents' class and name. In MIB order, one
    per serial (``dedupe``)."""
    parents = parents or {}
    out: list[Component] = []
    for index in sorted(serials, key=oid_sort_key):
        row = sh.instance_values(_ENTITY_COLUMNS, index, values)
        parent = str(snmp_int(row.get(sh.ENT_PHYSICAL_CONTAINED_IN)) or "")
        parent_row: dict[str, Any] = {}
        if parent and parent != "0":
            if parent in serials:
                parent_row = sh.instance_values(_PARENT_COLUMNS, parent, values)
            else:
                parent_row = sh.instance_values(_PARENT_COLUMNS, parent, parents)
        name = sh.text(row.get(sh.ENT_PHYSICAL_NAME))
        descr = sh.text(row.get(sh.ENT_PHYSICAL_DESCR))
        slot = name or sh.text(parent_row.get(sh.ENT_PHYSICAL_NAME)) or descr
        out.append(
            Component(
                category=entity_category(row, snmp_int(parent_row.get(sh.ENT_PHYSICAL_CLASS))),
                slot=slot,
                name=name or descr,
                description=descr,
                model=sh.text(row.get(sh.ENT_PHYSICAL_MODEL)),
                serial=serials[index],
                hardware_rev=sh.text(row.get(sh.ENT_PHYSICAL_HARDWARE_REV)),
                firmware_rev=sh.text(row.get(sh.ENT_PHYSICAL_FIRMWARE_REV)),
                software_rev=sh.text(row.get(sh.ENT_PHYSICAL_SOFTWARE_REV)),
                fru=snmp_int(row.get(sh.ENT_PHYSICAL_IS_FRU)) != sh.TRUTH_FALSE,
            )
        )
    return dedupe(out)


async def _serial_column(walk_table: WalkTable, oid: str) -> dict[str, str] | None:
    """``{index: real serial}`` of a walked serial column; None when the
    walk was not read or lists more than ``MAX_COMPONENTS`` serials."""
    rows, complete = await walk_table(oid, WALK_MAX_ROWS)
    if not complete:
        return None
    walked = {str(k).lstrip("."): v for k, v in rows.items()}
    serials = {index: real_serial(raw) for index, raw in sh.rows_by_index(walked, oid).items()}
    serials = {index: serial for index, serial in serials.items() if serial}
    if len(serials) > MAX_COMPONENTS:
        LOGGER.warning("hardware components: %d serials listed, more than %d: not read", len(serials), MAX_COMPONENTS)
        return None
    return serials


async def read_entity(get: sh.Get, walk_table: WalkTable) -> list[Component] | None:
    """The components ENTITY-MIB lists; ``[]`` for none, None when not read
    (the walk cut short, or the GET of the rows' columns unanswered). A GET
    of the parents that goes unanswered keeps the components, located by
    their own name or description."""
    serials = await _serial_column(walk_table, sh.ENT_PHYSICAL_SERIAL_NUM)
    if serials is None:
        return None
    if not serials:
        return []
    indices = sorted(serials, key=oid_sort_key)
    values = await sh.get_all(get, [f"{oid}.{index}" for index in indices for oid in _ENTITY_COLUMNS])
    if values is None:
        return None
    wanted: set[str] = set()
    for index in indices:
        parent = snmp_int(values.get(f"{sh.ENT_PHYSICAL_CONTAINED_IN}.{index}"))
        if parent and str(parent) not in serials:
            wanted.add(str(parent))
    parents: dict[str, Any] = {}
    if wanted:
        oids = [f"{oid}.{index}" for index in sorted(wanted, key=oid_sort_key) for oid in _PARENT_COLUMNS]
        parents = await sh.get_all(get, oids) or {}
    return parse_entity_rows(serials, values, parents)


# ── SNMP: JUNIPER-MIB ────────────────────────────────────────────────────────


def juniper_category(fru_type: int | None, descr: str, model: str) -> str:
    """A jnxContentsTable row's category: its jnxFruType (the module, power
    and fan sets of ``module_health``), else an optic named by its text,
    else ``other``."""
    if fru_type in module_health.JUNIPER_MODULE_TYPES:
        return MODULE
    if fru_type in module_health.JUNIPER_POWER_TYPES:
        return POWER_SUPPLY
    if fru_type in module_health.JUNIPER_FAN_TYPES:
        return FAN
    if is_transceiver_text(descr, descr, model):
        return TRANSCEIVER
    return OTHER


def parse_juniper_rows(serials: dict[str, str], values: dict[str, Any]) -> list[Component]:
    """The components of a jnxContentsTable read (the box first, as the
    chassis, when it has a serial), one per serial (``dedupe``)."""
    out: list[Component] = []
    box_serial = real_serial(values.get(JNX_BOX_SERIAL))
    if box_serial:
        box = sh.text(values.get(JNX_BOX_DESCR))
        out.append(
            Component(
                category=CHASSIS,
                slot="Chassis",
                name=box or "Chassis",
                description=box,
                model=box,
                serial=box_serial,
                hardware_rev=sh.text(values.get(JNX_BOX_REVISION)),
            )
        )
    for index in sorted(serials, key=oid_sort_key):
        row = sh.instance_values(_JNX_COLUMNS, index, values)
        descr = sh.text(row.get(JNX_CONTENTS_DESCR))
        model = sh.text(row.get(JNX_CONTENTS_MODEL)) or sh.text(row.get(JNX_CONTENTS_PART_NO))
        chassis = sh.text(row.get(JNX_CONTENTS_CHASSIS_DESCR))
        out.append(
            Component(
                category=juniper_category(snmp_int(row.get(module_health.JNX_FRU_TYPE)), descr, model),
                slot=descr or index,
                name=descr or index,
                description=f"{descr} ({chassis})" if chassis and chassis != descr else descr,
                model=model,
                serial=serials[index],
                hardware_rev=sh.text(row.get(JNX_CONTENTS_REVISION)),
            )
        )
    return dedupe(out)


async def read_juniper(get: sh.Get, walk_table: WalkTable) -> list[Component] | None:
    """The components JUNIPER-MIB lists; ``[]`` when its contents table
    lists no serial, None when not read."""
    serials = await _serial_column(walk_table, JNX_CONTENTS_SERIAL)
    if serials is None:
        return None
    if not serials:
        return []
    oids = [JNX_BOX_DESCR, JNX_BOX_SERIAL, JNX_BOX_REVISION]
    oids += [f"{oid}.{index}" for index in sorted(serials, key=oid_sort_key) for oid in _JNX_COLUMNS]
    values = await sh.get_all(get, oids)
    if values is None:
        return None
    return parse_juniper_rows(serials, values)


Reader = Callable[[sh.Get, WalkTable], Awaitable[list[Component] | None]]
_JUNIPER_TYPES = frozenset({"juniper", "juniper_junos"})


def readers_for(device_type: str | None) -> tuple[Reader, ...]:
    """The SNMP sources a device type is read from, tried in order: Junos
    JUNIPER-MIB then ENTITY-MIB; every other SNMP-polled type ENTITY-MIB;
    none for a type the poll's health checks do not read either (an APC
    UPS, a ping-only host)."""
    key = str(device_type or "").strip().lower()
    if key in health_checks.NOT_READ:
        return ()
    if key in _JUNIPER_TYPES:
        return (read_juniper, read_entity)
    return (read_entity,)


def reads_hardware(device_type: str | None) -> bool:
    return bool(readers_for(device_type))


async def read_snmp(device_type: str | None, get: sh.Get, walk_table: WalkTable) -> list[Component] | None:
    """The components of the first source that lists any; ``[]`` when every
    source lists none; None when a source was not read (no fall back past
    a source cut short)."""
    for reader in readers_for(device_type):
        components = await reader(get, walk_table)
        if components is None:
            return None
        if components:
            return components
    return []


# ── SSH: show inventory ──────────────────────────────────────────────────────


def components_from_inventory(output: str | None) -> list[Component]:
    """The components of a Cisco ``show inventory`` output (``slot`` and
    ``name``: its NAME; ``model``: PID; ``hardware_rev``: VID)."""
    return dedupe(
        Component(
            category=category_of(block.name, block.descr, block.pid),
            slot=block.name,
            name=block.name,
            description=block.descr,
            model=block.pid,
            serial=block.serial,
            hardware_rev=block.vid,
        )
        for block in parse_show_inventory(output)
    )


# ── Cadence ──────────────────────────────────────────────────────────────────

_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _parse(stamp: str | None) -> datetime | None:
    try:
        return datetime.strptime(str(stamp or ""), _FMT).replace(tzinfo=UTC)
    except ValueError:
        return None


def is_due(state: dict | None, now: datetime, *, stale: bool = False) -> bool:
    """Whether the poll reads a host's components now: marked stale by an
    event, waiting on a missing component or an empty read
    (``recheck``), its last read older than ``COLLECT_INTERVAL_SECONDS``
    (or never), and a not-read attempt older than ``NOT_READ_RETRY_SECONDS``."""
    if stale or not state:
        return True
    if int(state.get("recheck") or 0):
        return True
    attempted = _parse(state.get("attempted_at"))
    if state.get("result") == STATE_NOT_READ and attempted is not None:
        if now - attempted < timedelta(seconds=NOT_READ_RETRY_SECONDS):
            return False
    collected = _parse(state.get("collected_at"))
    return collected is None or now - collected >= timedelta(seconds=COLLECT_INTERVAL_SECONDS)


def snmp_read_recently(state: dict | None, now: datetime) -> bool:
    """Whether a host's last complete read was over SNMP and is not older
    than ``2 * COLLECT_INTERVAL_SECONDS``."""
    if not state or state.get("result") != STATE_OK or state.get("source") != SNMP:
        return False
    collected = _parse(state.get("collected_at"))
    return collected is not None and now - collected <= timedelta(seconds=2 * COLLECT_INTERVAL_SECONDS)


# ── Change detection ─────────────────────────────────────────────────────────


@dataclass
class Plan:
    """What one read changes: ``inserts`` (new rows), ``updates`` (stored
    rows, with their ``id``, the new values, ``status`` and ``seen`` /
    ``removed`` flags), ``events``."""

    inserts: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    baseline: bool = False


def _event(kind: str, comp: dict[str, Any], **extra: Any) -> dict[str, Any]:
    out = {
        "event": kind,
        "category": comp.get("category", ""),
        "slot": comp.get("slot", ""),
        "name": comp.get("name", ""),
        "model": comp.get("model", ""),
        "serial": comp.get("serial", ""),
        "previous_serial": "",
        "previous_model": "",
        "previous_slot": "",
        "previous_host_id": None,
        "previous_hostname": "",
        "changes": {},
        "detail": "",
    }
    out.update(extra)
    return out


def _merged(row: dict[str, Any], comp: Component, source: str) -> dict[str, Any]:
    """A stored row with a read's values: a value the read left blank keeps
    the stored one."""
    values = comp.values()
    merged = {"id": row["id"], "category": values["category"], "serial": values["serial"], "source": source}
    for name in _TEXT_FIELDS:
        merged[name] = values[name] or str(row.get(name) or "")
    return merged


def _changes(row: dict[str, Any], comp: Component) -> dict[str, dict[str, str]]:
    """The compared fields whose value differs, both sides set (a value
    that appears or goes blank is stored without an event)."""
    values = comp.values()
    out: dict[str, dict[str, str]] = {}
    for name in COMPARED_FIELDS:
        before, after = str(row.get(name) or ""), values[name]
        if before and after and before != after:
            out[name] = {"before": before, "after": after}
    return out


def diff_components(
    stored: list[dict[str, Any]],
    read: list[Component],
    source: str,
    *,
    now: datetime,
    elsewhere: dict[str, dict[str, Any]] | None = None,
) -> Plan:
    """What a complete read of a host at ``now`` changes, against its stored
    rows (every status). ``elsewhere``: ``{serial_key: {host_id, hostname,
    slot}}`` of the read's new serials last seen on another host.

    * No stored row: a baseline, one ``baseline`` event, no per-component
      event.
    * Identity is the serial (``serial_key``).
    * A new serial in a slot whose present or missing component is not in
      the read: ``replaced`` at once (the old row removed). In a slot whose
      component was removed within ``REPLACE_WINDOW_SECONDS``: ``replaced``
      too, naming the most recently removed one. Else ``installed`` (the
      host it was last seen on, if any, in the structured fields only).
    * A known serial in another slot: ``moved``; with another model or
      revision: ``changed``.
    * A stored component absent: ``missing`` (``missing_since`` set, no
      event); ``removed`` when absent from a complete read once it has been
      missing for ``REMOVE_CONFIRM_SECONDS``; back before that: present, no
      event.
    * A read from another source than the stored components (SNMP vs SSH)
      matches by serial only: slot names are not comparable, so no
      ``replaced`` or ``moved``, and no ``changed`` either (the sources
      word models and revisions differently); the read's values are stored.
    """
    elsewhere = elsewhere or {}
    read = dedupe(read)
    plan = Plan()
    stamp = now.strftime(_FMT)
    if not stored:
        plan.baseline = True
        plan.inserts = [{**c.values(), "source": source} for c in read]
        if read:
            noun = "component" if len(read) == 1 else "components"
            plan.events.append(
                _event(
                    BASELINE,
                    {"category": "", "slot": "", "name": "", "model": "", "serial": ""},
                    detail=f"First hardware read: {len(read)} {noun} with a serial.",
                )
            )
        return plan
    by_key = {serial_key(r["serial"]): r for r in stored}
    active = [r for r in stored if r.get("status") in (PRESENT, MISSING)]
    comparable = all((r.get("source") or source) == source for r in active)
    read_keys = {serial_key(c.serial) for c in read}
    gone = [r for r in active if serial_key(r["serial"]) not in read_keys]
    gone_by_slot: dict[str, list[dict[str, Any]]] = {}
    removed_by_slot: dict[str, list[dict[str, Any]]] = {}
    if comparable:
        for gone_row in gone:
            if gone_row.get("slot"):
                gone_by_slot.setdefault(str(gone_row["slot"]), []).append(gone_row)
        window = timedelta(seconds=REPLACE_WINDOW_SECONDS)
        for old_row in stored:
            removed_at = _parse(old_row.get("removed_at"))
            if old_row.get("status") == REMOVED and old_row.get("slot") and removed_at and now - removed_at <= window:
                removed_by_slot.setdefault(str(old_row["slot"]), []).append(old_row)
        for rows in removed_by_slot.values():
            rows.sort(key=lambda r: str(r.get("removed_at") or ""), reverse=True)
    replaced: set[int] = set()
    for comp in read:
        values = comp.values()
        key = serial_key(comp.serial)
        row = by_key.get(key)
        if row is not None and row.get("status") != REMOVED:
            if comparable:
                old_slot = str(row.get("slot") or "")
                if values["slot"] and old_slot and values["slot"] != old_slot:
                    plan.events.append(
                        _event(
                            MOVED, values, previous_slot=old_slot, detail=f"Moved from {old_slot} to {values['slot']}."
                        )
                    )
                changes = _changes(row, comp)
                if changes:
                    plan.events.append(
                        _event(CHANGED, values, changes=changes, detail="Changed: " + ", ".join(changes) + ".")
                    )
            plan.updates.append(
                {**_merged(row, comp, source), "status": PRESENT, "seen": True, "removed": False, "missing_since": None}
            )
            continue
        old = next((r for r in gone_by_slot.get(values["slot"], []) if r["id"] not in replaced), None)
        earlier = None
        if old is None:
            earlier = next(
                (
                    r
                    for r in removed_by_slot.get(values["slot"], [])
                    if r["id"] not in replaced and serial_key(r["serial"]) != key
                ),
                None,
            )
        if old is not None:
            replaced.add(old["id"])
            plan.updates.append({**old, "status": REMOVED, "seen": False, "removed": True, "missing_since": None})
            plan.events.append(
                _replaced(values, old, f"{old.get('serial')} replaced by {comp.serial} in {values['slot']}.")
            )
        elif earlier is not None:
            replaced.add(earlier["id"])
            plan.events.append(
                _replaced(
                    values,
                    earlier,
                    f"{earlier.get('serial')} replaced by {comp.serial} in {values['slot']}; "
                    f"{earlier.get('serial')} was removed at {earlier.get('removed_at')} UTC.",
                )
            )
        else:
            seen = elsewhere.get(key)
            detail = f"Installed in {values['slot']}." if values["slot"] else "Installed."
            extra: dict[str, Any] = {}
            if seen:
                # The other host is named in the structured fields only: the
                # API clears them for a caller who cannot read that host.
                detail += " It was last seen on another host."
                extra = {"previous_host_id": seen.get("host_id"), "previous_hostname": seen.get("hostname") or ""}
            plan.events.append(_event(INSTALLED, values, detail=detail, **extra))
        if row is not None:  # removed from this host earlier, back now
            plan.updates.append(
                {**_merged(row, comp, source), "status": PRESENT, "seen": True, "removed": False, "missing_since": None}
            )
        else:
            plan.inserts.append({**values, "source": source})
    confirm = timedelta(seconds=REMOVE_CONFIRM_SECONDS)
    for row in gone:
        if row["id"] in replaced:
            continue
        since = _parse(row.get("missing_since"))
        if row.get("status") == PRESENT or since is None:
            plan.updates.append({**row, "status": MISSING, "seen": False, "removed": False, "missing_since": stamp})
        elif now - since < confirm:
            plan.updates.append({**row, "status": MISSING, "seen": False, "removed": False})
        else:
            plan.updates.append({**row, "status": REMOVED, "seen": False, "removed": True, "missing_since": None})
            minutes = int((now - since).total_seconds() // 60)
            plan.events.append(
                _event(
                    REMOVED,
                    row,
                    detail=f"Not listed in any complete read for {minutes} minutes (missing since {row.get('missing_since')} UTC).",
                )
            )
    return plan


def _replaced(values: dict[str, Any], old: dict[str, Any], detail: str) -> dict[str, Any]:
    return _event(
        REPLACED,
        values,
        previous_serial=str(old.get("serial") or ""),
        previous_model=str(old.get("model") or ""),
        previous_slot=str(old.get("slot") or ""),
        detail=detail,
    )


# ── Storing a read ───────────────────────────────────────────────────────────


def _count(n: int) -> str:
    return f"{n} component" + ("" if n == 1 else "s")


async def apply_read(host_id: int, source: str, components: list[Component] | None, *, failure: str = "") -> dict:
    """Store one read of a host: ``components`` None is not read (only the
    attempt is recorded), else the read is compared (``diff_components``)
    and stored. Returns ``{"state", "message", "new_events", "components"}``
    (``components``: the number the read listed), or ``{}`` for a host
    that is not in the inventory."""
    host = await db.get_host(int(host_id))
    if not host:
        return {}
    now = _now()
    if components is None:
        message = failure or "The device did not answer the hardware read completely; nothing was changed."
        await db.record_hardware_attempt(host_id, now=now, source=source, message=message)
        return {"state": STATE_NOT_READ, "message": message, "new_events": [], "components": 0}
    stored = await db.list_host_hardware(host_id)
    state = await db.get_hardware_state(host_id) or {}
    active = [r for r in stored if r.get("status") in (PRESENT, MISSING)]
    empty_reads = 0
    if not components and active:
        empty_reads = int(state.get("empty_reads") or 0) + 1
        if empty_reads < EMPTY_CONFIRM_READS:
            message = (
                f"The device listed no hardware component ({empty_reads} of {EMPTY_CONFIRM_READS} reads in a row "
                "before that is believed); the stored components are kept."
            )
            await db.record_hardware_attempt(host_id, now=now, source=source, message=message, empty_reads=empty_reads)
            return {"state": STATE_NOT_READ, "message": message, "new_events": [], "components": 0}
    active_keys = {serial_key(r["serial"]) for r in active}
    new_serials = [c.serial for c in components if serial_key(c.serial) not in active_keys]
    elsewhere = await db.hardware_seen_elsewhere(host_id, new_serials) if new_serials else {}
    plan = diff_components(stored, components, source, now=_parse(now) or datetime.now(UTC), elsewhere=elsewhere)
    message = f"Read {_count(len(components))} over {source.upper()}."
    events = await db.save_hardware_read(
        host_id,
        str(host.get("hostname") or ""),
        source,
        plan,
        now=now,
        message=message,
        empty_reads=empty_reads,
        chassis_serial=next((c.serial for c in components if c.category == CHASSIS), ""),
    )
    monitoring_repoll.clear_hardware_stale(host_id)
    return {"state": STATE_OK, "message": message, "new_events": events, "components": len(components)}


async def _guarded(host_id: int, read: Callable[[], Awaitable[dict]]) -> dict:
    if host_id in _APPLYING:
        raise HardwareReadBusy(f"A hardware read of host {host_id} is being stored")
    _APPLYING.add(host_id)
    try:
        return await read()
    finally:
        _APPLYING.discard(host_id)


async def collect_in_poll(host: dict, device_type: str | None, get: sh.Get, walk_table: WalkTable) -> dict | None:
    """The monitoring poll's hardware read of a host that answered SNMP:
    read and stored when due (``is_due``); None when not due, not read for
    the device type, or it failed (logged, never raised)."""
    host_id = int(host["id"])
    if not reads_hardware(device_type) or host_id in _APPLYING:
        return None
    try:
        state = await db.get_hardware_state(host_id)
        if not is_due(state, datetime.now(UTC), stale=monitoring_repoll.hardware_stale(host_id)):
            return None

        async def _read() -> dict:
            return await apply_read(host_id, SNMP, await read_snmp(device_type, get, walk_table))

        return await _guarded(host_id, _read)
    except Exception as exc:  # noqa: BLE001 - the poll goes on without it
        LOGGER.warning("hardware components: read of host %s failed: %s", host.get("hostname") or host_id, exc)
        return None


async def refresh_over_snmp(host: dict, get: sh.Get, walk_table: WalkTable) -> dict:
    """An operator's read of one host now (``POST .../hardware/refresh``).
    Raises ``HardwareReadBusy`` while another read of the host is stored."""
    host_id = int(host["id"])

    async def _read() -> dict:
        components = await read_snmp(host.get("device_type"), get, walk_table)
        outcome = await apply_read(host_id, SNMP, components)
        return {**outcome, "answered": components is not None}

    return await _guarded(host_id, _read)


async def collect_over_ssh(host: dict, run: Callable[[str], Awaitable[str]]) -> int:
    """Read and store a host's components over SSH with the driver's
    ``show inventory`` (``run(command) -> output``, the caller's session).
    The number stored; 0 when the driver has no such command, the command
    failed, it listed nothing (an empty SSH read changes nothing), or the
    host has a complete SNMP read within ``2 * COLLECT_INTERVAL_SECONDS``
    (``snmp_read_recently``): SNMP is the source of a host it works on, SSH
    of a host it does not, so the two never compare their slot names."""
    from netcontrol.drivers import DriverCapabilityError, get_driver

    try:
        command = get_driver(host.get("device_type")).show_inventory_command()
    except DriverCapabilityError:
        return 0
    host_id = int(host["id"])
    if snmp_read_recently(await db.get_hardware_state(host_id), datetime.now(UTC)):
        LOGGER.debug("hardware components: host %s is read over SNMP; show inventory not stored", host_id)
        return 0
    try:
        components = components_from_inventory(await run(command))
        if not components:
            return 0

        async def _read() -> dict:
            return await apply_read(host_id, SSH, components)

        outcome = await _guarded(host_id, _read)
    except Exception as exc:  # noqa: BLE001 - the serial fetch reports its own result
        LOGGER.warning("hardware components: show inventory of host %s failed: %s", host_id, type(exc).__name__)
        return 0
    return int(outcome.get("components") or 0)
