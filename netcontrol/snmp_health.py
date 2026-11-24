"""State-based SNMP health checks of the monitoring poll: the shared shape.

A check (``HealthCheck``) turns the items of one kind (modules, power
supplies, fans, temperature sensors, BGP peers, OSPF neighbors) that a poll
read from a device into built-in alerts, one per item that is down, each
with a dedup key of its own (``{host_id}:<metric>:<index>``). An alert
resolves when its item reads OK or disabled by an operator, or is no longer
in a table the poll read completely. A poll that read no table raises and
resolves nothing. The number of items down is the check's metric sample and
alert rule metric (only when the poll read the table).

A read has three outcomes, kept apart all the way through: not read (a walk
cut short, or the GET that tells the kinds of the rows unanswered: the
walk callable returns None, a source returns None), read with rows (a
table), and read with no row (a walk that ran to its end empty: the walk
returns ``{}``, a source returns ``empty_table``). When an empty table
counts as "no items" (and clears the check's open alerts) is
``health_checks``'s decision.

A table (``TableSource``) is one status column of a vendor MIB, walked
once per poll; the per-row objects are read with GETs only for the rows
that need them: the rows not OK when a row's kind is not known from the
column alone (``filter_oids``), and the names and details of the rows
down. One table may hold rows of several kinds (Juniper's FRU table holds
modules, power supplies and fans; an HPE sensor table holds power, fan and
temperature sensors), so one read serves several checks.

Item classes: ``ok`` never alerts and resolves; ``transitional`` neither
raises nor resolves (on its way somewhere, or not known); ``admin_down``
(disabled by an operator) is not an alert and resolves one; ``down``
raises.

The vendor tables are in ``module_health``, ``environment_health``,
``routing_health`` and ``ha_health``; which ones a device type reads is
``health_checks``. Where one check reads several tables of a device (HA:
the redundancy peer and the stack members), ``merge`` makes one state of
them.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from netcontrol.routes.snmp import _snmp_str, oid_sort_key, snmp_int

OK = "ok"
TRANSITIONAL = "transitional"
ADMIN_DOWN = "admin_down"
DOWN = "down"

# Instances asked for in one GET.
OIDS_PER_GET = 20

# ENTITY-MIB (RFC 6933) entPhysicalTable columns: the names of the items
# indexed by entPhysicalIndex, and their class (IANA-ENTITY-MIB
# PhysicalClass: powerSupply(6), fan(7), sensor(8), module(9)).
ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_PHYSICAL_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_PHYSICAL_PARENT_REL_POS = "1.3.6.1.2.1.47.1.1.1.1.6"
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_PHYSICAL_HARDWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.8"
ENT_PHYSICAL_FIRMWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.9"
ENT_PHYSICAL_SOFTWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.10"
ENT_PHYSICAL_SERIAL_NUM = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_PHYSICAL_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
ENT_PHYSICAL_IS_FRU = "1.3.6.1.2.1.47.1.1.1.1.16"
PHYSICAL_CLASS_CHASSIS = 3
PHYSICAL_CLASS_CONTAINER = 5
PHYSICAL_CLASS_POWER_SUPPLY = 6
PHYSICAL_CLASS_FAN = 7
PHYSICAL_CLASS_SENSOR = 8
PHYSICAL_CLASS_MODULE = 9
PHYSICAL_CLASS_PORT = 10
# TruthValue (SNMPv2-TC): entPhysicalIsFRU false(2).
TRUTH_FALSE = 2

# IF-MIB (RFC 2863): ifIndex (the row pointer an entAliasMappingIdentifier
# names), ifAdminStatus down(2), ifOperStatus up(1), ifName.
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ADMIN_DOWN = 2
IF_OPER_UP = 1

Get = Callable[[tuple[str, ...]], Awaitable[dict]]
# A walk of one column: its rows, ``{}`` when it ran to its end with no row,
# None when it was not read (cut short).
Walk = Callable[[str], Awaitable[dict | None]]


class Source(Protocol):
    """Anything the poll reads items from: a ``TableSource``, or a reader
    of its own shape (CISCO-ENTITY-SENSOR-MIB thresholds)."""

    @property
    def key(self) -> str: ...

    @property
    def kinds(self) -> frozenset[str]: ...

    async def read(self, get: Get, walk: Walk, host_id: int) -> dict[str, Any] | None: ...


def text(raw: Any) -> str:
    """An SNMP value as text; "" for a missing value or a pysnmp sentinel."""
    return _snmp_str(raw) if raw is not None else ""


def entity_name(values: dict[str, Any]) -> str:
    """An entPhysicalTable row's name: entPhysicalName, else its descr."""
    return text(values.get(ENT_PHYSICAL_NAME)) or text(values.get(ENT_PHYSICAL_DESCR))


def octets(raw: Any) -> bytes | None:
    """An OCTET STRING / BITS value as bytes; None for a missing value or a
    pysnmp sentinel."""
    if raw is None or any(m in str(raw).lower() for m in ("no such", "endofmibview")):
        return None
    if isinstance(raw, bytes | bytearray):
        return bytes(raw)
    as_octets = getattr(raw, "asOctets", None)
    if callable(as_octets):
        return bytes(as_octets())
    value = str(raw).strip()
    if value.lower().startswith("0x"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            return None
    return None


def bit_set(data: bytes, bit: int) -> bool:
    """Whether a BITS value (bit 0 is the high bit of the first octet) has
    ``bit`` set."""
    byte = bit // 8
    return byte < len(data) and bool(data[byte] & (0x80 >> (bit % 8)))


def _no_name(_values: dict[str, Any]) -> str:
    return ""


def _not_admin_off(_values: dict[str, Any]) -> bool:
    return False


def _no_extra(_values: dict[str, Any]) -> dict[str, Any]:
    return {}


@dataclass(frozen=True)
class TableSource:
    """One vendor status table."""

    key: str
    vendor: str
    state_oid: str
    # state value: (label, class)
    states: dict[int, tuple[str, str]]
    # The kinds of item the table's rows are (``"module"``, ``"power"`` ...).
    kinds: frozenset[str]
    # States that mean the slot is empty: such a row is not an item.
    absent: frozenset[int] = frozenset()
    # Read to tell a row's kind (and whether it is an item at all).
    filter_oids: tuple[str, ...] = ()
    # Read the filter for the OK rows too. When False, an OK row of unknown
    # kind is left out: it raises nothing, and a key of its index clears
    # either way (OK, or not in the table).
    filter_ok_rows: bool = True
    # The kind of a row from its filter values; None: not an item.
    kind_of: Callable[[dict[str, Any]], str | None] | None = None
    # The kind of a row from its index alone (a table indexed by a type, as
    # CISCO-FIREWALL-MIB cfwHardwareStatusTable); None: not an item.
    index_kind: Callable[[str], str | None] | None = None
    # Read for the rows classed down: names, and the admin-off check.
    detail_oids: tuple[str, ...] = ()
    admin_off: Callable[[dict[str, Any]], bool] = field(default=_not_admin_off)
    name: Callable[[dict[str, Any]], str] = field(default=_no_name)
    model: Callable[[dict[str, Any]], str] = field(default=_no_name)
    # The name from the row index alone (BGP peers, OSPF neighbors).
    index_name: Callable[[str], str] | None = None
    # More fields of a row not OK, from its details (BGP: the counter of
    # times established).
    row_fields: Callable[[dict[str, Any]], dict[str, Any]] = field(default=_no_extra)
    # state value: the severity the device gives it (temperature).
    severities: dict[int, str] = field(default_factory=dict)
    # How a raw column value becomes a state (default: an integer).
    state_of: Callable[[Any], int | None] = field(default=snmp_int)

    def single_kind(self) -> str | None:
        if len(self.kinds) != 1 or self.kind_of is not None or self.index_kind is not None:
            return None
        return next(iter(self.kinds))

    async def read(self, get: Get, walk: Walk, host_id: int) -> dict[str, Any] | None:
        """Read and parse the table: see :func:`read_table`. ``host_id`` is
        for the tables that keep per-host memory (routing_health)."""
        return await read_table(self, get, walk)


# ── Reading a table ──────────────────────────────────────────────────────────


def rows_by_index(rows: dict[str, Any], column_oid: str) -> dict[str, Any]:
    """``{index: value}`` of one walked table column (``{oid: value}``)."""
    prefix = column_oid.rstrip(".") + "."
    out: dict[str, Any] = {}
    for oid, value in rows.items():
        oid = str(oid).lstrip(".")
        if oid.startswith(prefix) and len(oid) > len(prefix):
            out[oid[len(prefix) :]] = value
    return out


def _states(source: TableSource, state_rows: dict[str, Any]) -> dict[str, int]:
    """The present rows of a walked status column: ``{index: state}``."""
    states: dict[str, int] = {}
    for index, raw in rows_by_index(state_rows, source.state_oid).items():
        state = source.state_of(raw)
        if state is not None and state not in source.absent:
            states[index] = state
    return states


def instance_values(oids: Iterable[str], index: str, values: dict[str, Any]) -> dict[str, Any]:
    """The GET answers of one row: ``{column oid: value}``."""
    return {oid: values.get(f"{oid}.{index}") for oid in oids}


def class_of(source: TableSource, state: int) -> tuple[str, str]:
    # A value the MIB revision we know does not list: neither raise nor clear.
    return source.states.get(state, (f"state {state}", TRANSITIONAL))


def _needs_filter(source: TableSource, state: int) -> bool:
    return bool(source.filter_oids) and (source.filter_ok_rows or class_of(source, state)[1] != OK)


def filter_instances(source: TableSource, state_rows: dict[str, Any]) -> list[str]:
    """The instance OIDs read to tell the kind of the rows."""
    states = _states(source, state_rows)
    return [
        f"{oid}.{index}"
        for index in sorted(states, key=oid_sort_key)
        if _needs_filter(source, states[index])
        for oid in source.filter_oids
    ]


def _kinds(source: TableSource, states: dict[str, int], values: dict[str, Any]) -> dict[str, str]:
    """``{index: kind}`` of the rows that are items, in MIB order."""
    kinds: dict[str, str] = {}
    single = source.single_kind()
    for index in sorted(states, key=oid_sort_key):
        if single is not None and not source.filter_oids:
            kinds[index] = single
            continue
        if source.index_kind is not None:
            kind = source.index_kind(index)
            if kind is not None and kind in source.kinds:
                kinds[index] = kind
            continue
        if not _needs_filter(source, states[index]):
            continue  # an OK row of unknown kind: left out
        filter_values = instance_values(source.filter_oids, index, values)
        kind = source.kind_of(filter_values) if source.kind_of is not None else single
        if kind is not None and kind in source.kinds:
            kinds[index] = kind
    return kinds


def detail_instances(source: TableSource, state_rows: dict[str, Any], values: dict[str, Any]) -> list[str]:
    """The instance OIDs read for the items whose state is down."""
    states = _states(source, state_rows)
    return [
        f"{oid}.{index}"
        for index in _kinds(source, states, values)
        if class_of(source, states[index])[1] == DOWN
        for oid in source.detail_oids
    ]


def parse_table(source: TableSource, state_rows: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """The items of a device's table from its walked status column
    (``{oid: value}``) and the GET answers of the per-row objects
    (``{instance oid: value}``). ``{}`` when the walk returned no row
    (nothing read). Each item: ``index``, ``kind``, ``name`` (may be "":
    the check names it), ``model``, ``status`` (its state's label),
    ``state`` (the raw value), ``class`` and ``severity`` (the device's,
    or None)."""
    if not rows_by_index(state_rows, source.state_oid):
        return {}
    states = _states(source, state_rows)
    items: list[dict[str, Any]] = []
    for index, kind in _kinds(source, states, values).items():
        label, klass = class_of(source, states[index])
        # The row's filter answers and details together (a name may be either).
        details = instance_values(source.filter_oids + source.detail_oids, index, values)
        if klass == DOWN and source.admin_off(details):
            klass = ADMIN_DOWN
        name = source.name(details) or (source.index_name(index) if source.index_name else "")
        item = {
            "index": index,
            "kind": kind,
            "name": name,
            "model": source.model(details),
            "status": label,
            "state": states[index],
            "class": klass,
            "severity": source.severities.get(states[index]),
        }
        if klass != OK:
            item.update(source.row_fields(details))
        items.append(item)
    return {"source": source.key, "vendor": source.vendor, "items": items}


async def get_all(get: Get, oids: list[str]) -> dict | None:
    """GET ``oids`` in requests of ``OIDS_PER_GET``; None when a request
    went unanswered."""
    answers: dict = {}
    for start in range(0, len(oids), OIDS_PER_GET):
        answer = await get(tuple(oids[start : start + OIDS_PER_GET]))
        if not answer:
            return None
        answers.update({str(oid).lstrip("."): value for oid, value in answer.items()})
    return answers


async def walk_column(walk: Walk, oid: str) -> dict[str, Any] | None:
    """One walked column, its OIDs without a leading dot; None when the
    walk was not read."""
    rows = await walk(oid)
    if rows is None:
        return None
    return {str(k).lstrip("."): v for k, v in rows.items()}


def empty_table(key: str, vendor: str) -> dict[str, Any]:
    """A table read to its end with no row."""
    return {"source": key, "vendor": vendor, "items": [], "empty": True}


def is_empty(table: dict[str, Any] | None) -> bool:
    """Whether a source read returned ``empty_table``."""
    return table is not None and bool(table.get("empty"))


async def read_table(source: TableSource, get: Get, walk: Walk) -> dict[str, Any] | None:
    """Read and parse a table with the monitoring poll's SNMP requests:
    ``walk(oid)`` for the status column (``{oid: value}``; ``{}`` for a walk
    that ran to its end with no row, None for one cut short),
    ``get(instance oids) -> {oid: value}`` for the rows that need more.
    None when the table was not read (the walk cut short, or the GET that
    tells the kinds of the rows unanswered); ``empty_table`` when it has no
    row. A GET of names that goes unanswered keeps the items, unnamed."""
    state_rows = await walk_column(walk, source.state_oid)
    if state_rows is None:
        return None
    if not rows_by_index(state_rows, source.state_oid):
        return empty_table(source.key, source.vendor)
    values: dict = {}
    wanted = filter_instances(source, state_rows)
    if wanted:
        answers = await get_all(get, wanted)
        if answers is None:
            return None
        values.update(answers)
    wanted = detail_instances(source, state_rows, values)
    if wanted:
        values.update(await get_all(get, wanted) or {})
    return parse_table(source, state_rows, values)


def _first_index_part(item: dict[str, Any]) -> str:
    return str(item["index"]).split(".")[0]


async def interface_details(
    items: list[dict[str, Any]],
    get: Get,
    if_index_of: Callable[[dict[str, Any]], str] = _first_index_part,
    *,
    rename: bool = True,
    link_down: str | None = None,
) -> None:
    """For the items down that sit on an interface (``if_index_of(item)``,
    "" for none): admin down when an operator shut the interface (IF-MIB
    ifAdminStatus down(2)), and with ``rename`` the interface's name added
    to the item's (``"<name> on <ifName>"``). With ``link_down`` (a class),
    an item on an interface that is not admin down and whose ifOperStatus
    is not up(1) takes that class: its state follows from the link being
    down, which the interface check reports. A GET unanswered changes
    nothing."""
    down = [i for i in items if i["class"] == DOWN and if_index_of(i)]
    if_indexes = sorted({if_index_of(i) for i in down}, key=oid_sort_key)
    if not if_indexes:
        return
    columns = (
        *((IF_NAME,) if rename else ()),
        IF_ADMIN_STATUS,
        *((IF_OPER_STATUS,) if link_down is not None else ()),
    )
    answers = await get_all(get, [f"{oid}.{i}" for i in if_indexes for oid in columns]) or {}
    for item in down:
        if_index = if_index_of(item)
        if_name = text(answers.get(f"{IF_NAME}.{if_index}"))
        if rename and if_name:
            item["name"] = f"{item['name']} on {if_name}"
        if snmp_int(answers.get(f"{IF_ADMIN_STATUS}.{if_index}")) == IF_ADMIN_DOWN:
            item["class"] = ADMIN_DOWN
            item["status"] = f"{item['status']}, interface admin down"
            continue
        oper = snmp_int(answers.get(f"{IF_OPER_STATUS}.{if_index}")) if link_down is not None else None
        if link_down is not None and oper is not None and oper != IF_OPER_UP:
            item["class"] = link_down
            item["status"] = f"{item['status']}, link down"


# ── Checks: alerts, clearing, counts ─────────────────────────────────────────


@dataclass(frozen=True)
class HealthCheck:
    """One built-in alert per item of a kind that is down."""

    metric: str
    # The poll result key that holds the check's state.
    result_key: str
    # The kind of table row the check takes.
    kind: str
    severity: str
    # Names an item that has none: ``f"{noun} {index}"``.
    noun: str
    alert_type: str = "status"
    # Take the severity the device gives the item's state, when it gives one.
    severity_from_device: bool = False
    # The key of the item list in the check's state.
    items_key: str = "items"


def select(check: HealthCheck, table: dict[str, Any] | None) -> dict[str, Any]:
    """The check's state from a parsed table: the items of its kind, named.
    ``{}`` when the table was not read. An empty table (``empty_table``) is
    a state with no item and no count: it clears the check's open alerts and
    writes no metric sample."""
    if not table:
        return {}
    if table.get("empty"):
        return {
            "source": table.get("source", ""),
            "vendor": table.get("vendor", ""),
            check.items_key: [],
            "down_count": None,
            "empty": True,
        }
    items = []
    for row in table.get("items") or []:
        if row.get("kind") != check.kind:
            continue
        item = {k: v for k, v in row.items() if k != "kind"}
        item["name"] = item.get("name") or f"{check.noun} {item['index']}"
        items.append(item)
    return {
        "source": table.get("source", ""),
        "vendor": table.get("vendor", ""),
        check.items_key: items,
        "down_count": sum(1 for i in items if i["class"] == DOWN),
    }


def merge(check: HealthCheck, states: list[dict[str, Any]]) -> dict[str, Any]:
    """One check's state from the states of several tables of its kind
    (the redundancy peer and the stack members of one switch), whose item
    indexes are kept apart by the tables. ``{}`` when one of them was not
    read: a state missing a table's items would clear that table's open
    alerts. Empty tables add no item; all empty is an empty state."""
    if len(states) == 1:
        return states[0]
    if not states or any(not s for s in states):
        return {}
    read = [s for s in states if not s.get("empty")]
    if not read:
        return states[0]
    items = [item for s in read for item in s.get(check.items_key) or []]
    return {
        "source": ", ".join(s.get("source", "") for s in read),
        "vendor": ", ".join(dict.fromkeys(s.get("vendor", "") for s in read)),
        check.items_key: items,
        "down_count": sum(1 for i in items if i["class"] == DOWN),
    }


def alert_dedup_key(check: HealthCheck, host_id: int, index: str) -> str:
    """The dedup key of one item's alert: distinct per item, so a second
    item failing is an alert (and a notification) of its own."""
    return f"{host_id}:{check.metric}:{index}"


def index_of_key(check: HealthCheck, host_id: int, key: str) -> str | None:
    """The item index of one of this host's item alert keys; None for any
    other key, such as a user rule's on the same metric (``...:rule:<id>``)."""
    prefix = f"{host_id}:{check.metric}:"
    if not key.startswith(prefix):
        return None
    index = key[len(prefix) :]
    return index if index and all(part.isdigit() for part in index.split(".")) else None


def _message(item: dict[str, Any]) -> str:
    model = f" ({item['model']})" if item.get("model") else ""
    return f"{item['name']}{model} is {item['status']}"


def alert_checks(check: HealthCheck, host_id: int, status: dict[str, Any]) -> list[dict[str, Any]]:
    """The built-in alerts a check's state raises, one per item classed
    down, in the shape of the poll's built-in checks plus their own
    ``dedup_key``. An empty state raises none."""
    checks: list[dict[str, Any]] = []
    for item in (status or {}).get(check.items_key) or []:
        if item.get("class") != DOWN:
            continue
        severity = (item.get("severity") if check.severity_from_device else None) or check.severity
        checks.append(
            {
                "metric": check.metric,
                "alert_type": check.alert_type,
                "message": _message(item),
                "severity": severity,
                "value": float(item["state"]),
                "threshold": None,
                "dedup_key": alert_dedup_key(check, host_id, str(item["index"])),
            }
        )
    return checks


def cleared_keys(check: HealthCheck, host_id: int, status: dict[str, Any], open_keys: list[str]) -> list[str]:
    """Of a host's open alerts of the check (their dedup keys), the ones a
    poll's state clears: the item reads OK or disabled by an operator, or
    it is no longer in the table. An item in a transitional state, or still
    down, keeps its alert. None for an empty state (the poll read nothing)."""
    if not status:
        return []
    classes = {str(i["index"]): i["class"] for i in status.get(check.items_key) or []}
    cleared: list[str] = []
    for key in open_keys:
        index = index_of_key(check, host_id, key)
        if index is None:
            continue
        klass = classes.get(index)
        if klass is None or klass in (OK, ADMIN_DOWN):
            cleared.append(key)
    return cleared


def down_count(status: dict[str, Any] | None) -> float | None:
    """The number of items classed down; None when the poll read no table,
    or read it empty."""
    if not status or status.get("empty"):
        return None
    return float(status.get("down_count") or 0)
