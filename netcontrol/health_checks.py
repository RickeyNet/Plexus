"""Which state-based SNMP health checks the monitoring poll runs per device
type, the reading of them, and their metric values.

The checks (``snmp_health.HealthCheck``): ``module_down``
(``module_health``), ``power_supply_down``, ``fan_down``,
``temperature_alarm`` (``environment_health``), ``bgp_peer_down`` and
``ospf_neighbor_down`` (``routing_health``).

A device type's plan is a list of chains; a chain is the tables that can
answer some kinds of item, tried in order: the first that has rows is the
one read (Cisco: CISCO-ENVMON-MIB, else CISCO-ENTITY-FRU-CONTROL-MIB, as on
NX-OS). A chain whose walk was cut short reads nothing, and does not fall
back. The chains of a poll run at the same time.

Empty tables, for every table of every check alike. The memory is kept
per host and column in the server process (a restart starts it over):

* A walk that ran to its end with no row is counted; a row resets the
  count, and marks the column as one that has answered rows on the host.
  A walk cut short (a timeout, or ``WALK_MAX_ROWS`` reached) counts for
  nothing.
* Until a chain's tables have all been empty at ``EMPTY_CONFIRM_POLLS``
  (3) walks in a row, an empty chain is "not read": it raises and resolves
  nothing (a device just after a reload may answer a hardware table empty
  before it fills it). From then on it is "read, no items": it clears every
  open alert of its checks on the host and writes no metric sample.
* A column that has never answered rows on the host and is confirmed empty
  is not walked again for ``EMPTY_TABLE_SECONDS`` (an hour): a device
  without a MIB costs one walk of it per hour. A column that has answered
  rows is walked at every poll.
* The OSPF neighbor table is dynamic: when a host has neighbors in memory,
  an empty walk is a reading at once (``routing_health.settle_ospf``).

The standard tables (BGP4-MIB, OSPF-MIB) are read for any SNMP-polled
device type, except an APC UPS (read by its own module).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netcontrol import environment_health as env, module_health, routing_health as routing, snmp_health as sh

CHECKS: tuple[sh.HealthCheck, ...] = (module_health.CHECK, *env.CHECKS, *routing.CHECKS)
METRICS: dict[str, sh.HealthCheck] = {check.metric: check for check in CHECKS}

# Empty walks in a row that make a table "read, no items".
EMPTY_CONFIRM_POLLS = 3
# How long a column never answered and confirmed empty is not walked.
EMPTY_TABLE_SECONDS = 3600.0
# The rows a health walk may return; one that reaches it is cut short
# (ENTITY-STATE and sensor threshold columns list every entity).
WALK_MAX_ROWS = 5000


def walk_complete(rows: dict, error: str | None, max_rows: int = WALK_MAX_ROWS) -> bool:
    """Whether a walk capped at ``max_rows`` ran to its end: no error, and
    the cap not reached (the walk stops there without an error)."""
    return not error and len(rows) < max_rows


@dataclass
class _Column:
    empty_walks: int = 0
    answered: bool = False
    skip_until: float = 0.0


# ``{(host_id, column oid): its memory}``
_COLUMNS: dict[tuple[int, str], _Column] = {}

WalkTable = Callable[[str], Awaitable[tuple[dict, bool]]]


@dataclass(frozen=True)
class Chain:
    """Tables answering the same kinds of item, tried in order."""

    kinds: frozenset[str]
    sources: tuple[sh.Source, ...]


def _chain(*sources: sh.Source, kinds: set[str] | None = None) -> Chain:
    return Chain(frozenset(kinds) if kinds is not None else sources[0].kinds, tuple(sources))


_P, _F, _T = env.KIND_POWER, env.KIND_FAN, env.KIND_TEMPERATURE

_OSPF = _chain(routing.OSPF_NEIGHBORS)
STANDARD_ROUTING = (_chain(routing.BGP4_PEERS), _OSPF)
_CISCO = (
    _chain(env.CISCO_ENVMON_SUPPLY, env.CISCO_FRU_POWER),
    _chain(env.CISCO_ENVMON_FAN, env.CISCO_FAN_TRAY),
    _chain(env.CISCO_ENVMON_TEMPERATURE, env.CISCO_SENSOR_THRESHOLDS),
    _chain(routing.CISCO_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
)
_CISCO_MODULE = (_chain(module_health.CISCO),)
_JUNIPER = (
    _chain(module_health.JUNIPER),
    _chain(routing.JUNIPER_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
)
_ARISTA = (
    _chain(env.ENTITY_STATE_POWER),
    _chain(env.ARISTA_FAN),
    _chain(env.ENTITY_STATE_TEMPERATURE),
    _chain(routing.ARISTA_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
)
_PALOALTO = (_chain(env.ENTITY_STATE_POWER_FAN), _chain(env.ENTITY_STATE_TEMPERATURE), *STANDARD_ROUTING)
_AOS_SWITCH = (_chain(env.AOS_SWITCH_SENSORS), *STANDARD_ROUTING)

DEVICE_PLANS: dict[str, tuple[Chain, ...]] = {
    "cisco_ios": (*_CISCO_MODULE, *_CISCO),
    "cisco_xe": (*_CISCO_MODULE, *_CISCO),
    "cisco_nxos": (*_CISCO_MODULE, *_CISCO),
    "cisco_nxos_ssh": _CISCO,
    "cisco_xr": (*_CISCO_MODULE, *_CISCO),
    "cisco_asa": _CISCO,
    "cisco_ftd": _CISCO,
    "juniper": _JUNIPER,
    "juniper_junos": _JUNIPER,
    "arista_eos": _ARISTA,
    "paloalto": _PALOALTO,
    "paloalto_panos": _PALOALTO,
    "fortinet": (_chain(env.FORTINET_SENSORS), *STANDARD_ROUTING),
    "aruba_osswitch": _AOS_SWITCH,
    "aruba_procurve": _AOS_SWITCH,
    "hp_procurve": _AOS_SWITCH,
    "aruba_aoscx": (_chain(env.AOSCX_POWER), _chain(env.AOSCX_FAN), *STANDARD_ROUTING),
    "netgear_prosafe": (
        _chain(env.NETGEAR_POWER),
        _chain(env.NETGEAR_FAN),
        _chain(env.NETGEAR_TEMPERATURE),
        *STANDARD_ROUTING,
    ),
}
# Device types not read at all: a UPS (its own reader), a ping-only host.
NOT_READ = frozenset({"apc_ups", "icmp_only"})


def plan_for_device(device_type: str | None) -> tuple[Chain, ...]:
    """The chains a device type reads; the standard routing tables for a
    type without a plan of its own."""
    key = str(device_type or "").strip().lower()
    if key in NOT_READ:
        return ()
    return DEVICE_PLANS.get(key, STANDARD_ROUTING)


def forget_all() -> None:
    """Drop every per-host memory (tests; host ids restart with the database)."""
    _COLUMNS.clear()
    routing.forget_all()


async def _read_chain(chain: Chain, host_id: int, get: sh.Get, walk_table: WalkTable) -> dict[str, Any] | None:
    """The table of the first source of the chain that has rows; None when
    not read (a walk cut short, a kind GET unanswered, or every source empty
    but not yet confirmed); an empty table when every source is confirmed
    empty."""
    # Whether each column walked empty in this read is confirmed empty.
    confirmed: list[bool] = []

    async def walk(oid: str) -> dict | None:
        column = _COLUMNS.setdefault((host_id, oid), _Column())
        now = time.monotonic()
        if column.skip_until > now:
            confirmed.append(True)
            return {}
        rows, complete = await walk_table(oid)
        if not complete:
            return None
        if rows:
            column.answered = True
            column.empty_walks = 0
            column.skip_until = 0.0
            return rows
        column.empty_walks += 1
        sure = column.empty_walks >= EMPTY_CONFIRM_POLLS
        if sure and not column.answered:
            column.skip_until = now + EMPTY_TABLE_SECONDS
        confirmed.append(sure)
        return {}

    empty: dict[str, Any] | None = None
    for source in chain.sources:
        table = await source.read(get, walk, host_id)
        if table is None:
            return None
        if not sh.is_empty(table):
            return table
        empty = empty or table
    return empty if confirmed and all(confirmed) else None


async def read_health(host_id: int, device_type: str | None, get: sh.Get, walk_table: WalkTable) -> dict[str, Any]:
    """The poll result entries of every check the device type runs:
    ``{check.result_key: state}``, ``{}`` for a check whose table was not
    read. ``walk_table(oid) -> (rows, complete)``; ``get(oids) -> {oid:
    value}``."""
    plan = plan_for_device(device_type)
    tables = await asyncio.gather(*(_read_chain(chain, host_id, get, walk_table) for chain in plan))
    out: dict[str, Any] = {}
    for chain, table in zip(plan, tables, strict=True):
        for check in CHECKS:
            if check.kind in chain.kinds:
                out[check.result_key] = sh.select(check, table)
    return out


def metric_value(res: dict, metric: str) -> float | None:
    """A check's count of items down in a poll result; None when the poll
    read no table for it (or the metric is not a check's)."""
    check = METRICS.get(metric)
    return sh.down_count(res.get(check.result_key)) if check else None


def metric_sample_rows(res: dict, checks: tuple[sh.HealthCheck, ...] = CHECKS) -> list[tuple]:
    """The metric sample rows of a poll result: one per check whose table
    the poll read."""
    rows: list[tuple] = []
    for check in checks:
        value = sh.down_count(res.get(check.result_key))
        if value is not None:
            rows.append((res["host_id"], check.metric, "{}", value))
    return rows
