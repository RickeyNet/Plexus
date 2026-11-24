"""Which state-based SNMP health checks the monitoring poll runs per device
type, the reading of them, and their metric values.

The checks (``snmp_health.HealthCheck``): ``module_down``
(``module_health``), ``power_supply_down``, ``fan_down``,
``temperature_alarm``, ``optic_level_alarm`` (``environment_health``),
``poe_port_fault``, ``poe_supply_down``, ``poe_budget_high``
(``poe_health``), ``bgp_peer_down``, ``ospf_neighbor_down``,
``eigrp_neighbor_down``, ``isis_adjacency_down``, ``ip_sla_down``
(``routing_health``), ``ha_peer_down``, ``ha_link_down`` and
``fhrp_group_down`` (``ha_health``).

A device type's plan is a list of chains; a chain is the tables that can
answer some kinds of item, tried in order: the first that has rows is the
one read (Cisco: CISCO-ENVMON-MIB, else CISCO-ENTITY-FRU-CONTROL-MIB, as on
NX-OS). A chain whose walk was cut short reads nothing, and does not fall
back. The chains of a poll run at the same time. Where several chains
answer one check (a Catalyst's redundancy peer and stack members), their
states are merged (``snmp_health.merge``): the check is not read when one
of them was not. A source in two chains of a plan (the Cisco sensor
threshold table: temperature, and optics) is read once per poll.

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

The standard tables (BGP4-MIB, OSPF-MIB, ISIS-MIB, VRRP: VRRPV3-MIB else
VRRP-MIB, and POWER-ETHERNET-MIB) are read for any SNMP-polled device type,
except an APC UPS (read by its own module); PAN-OS and the Cisco firewalls,
which run no VRRP and have no PoE ports, are asked for neither; of the
other Cisco types only IOS and IOS XE (Catalyst switches) are asked for
PoE.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netcontrol import (
    environment_health as env,
    ha_health as ha,
    module_health,
    poe_health as poe,
    routing_health as routing,
    snmp_health as sh,
)

CHECKS: tuple[sh.HealthCheck, ...] = (
    module_health.CHECK,
    *env.CHECKS,
    *poe.CHECKS,
    *routing.CHECKS,
    *ha.CHECKS,
)
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


_OSPF = _chain(routing.OSPF_NEIGHBORS)
_ISIS = _chain(routing.ISIS_ADJACENCIES)
STANDARD_ROUTING = (_chain(routing.BGP4_PEERS), _OSPF, _ISIS)
# VRRP: VRRPV3-MIB, else VRRP-MIB (RFC 2787).
_VRRP = _chain(ha.VRRPV3_GROUPS, ha.VRRP_GROUPS)
# PoE ports and power sources (POWER-ETHERNET-MIB).
_POE = (_chain(poe.POE_PORTS), _chain(poe.MAIN_PSE))
# What any SNMP platform without a plan of its own reads.
STANDARD = (*STANDARD_ROUTING, _VRRP, *_POE)
_CISCO = (
    _chain(env.CISCO_ENVMON_SUPPLY, env.CISCO_FRU_POWER),
    _chain(env.CISCO_ENVMON_FAN, env.CISCO_FAN_TRAY),
    _chain(env.CISCO_ENVMON_TEMPERATURE, env.CISCO_SENSOR_THRESHOLDS),
    # The sensor threshold table again, for its optics (read once per poll).
    _chain(env.CISCO_SENSOR_THRESHOLDS, kinds={env.KIND_OPTICS}),
    _chain(routing.CISCO_BGP_VRF_PEERS, routing.CISCO_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
    _chain(routing.EIGRP_PEERS),
    _chain(routing.ISIS_ADJACENCIES, routing.CISCO_ISIS_ADJACENCIES),
    _chain(routing.IP_SLA_PROBES),
)
_CISCO_MODULE = (_chain(module_health.CISCO),)
# Supervisor and stack redundancy, first hop redundancy (routers, switches).
_CISCO_HA = (
    _chain(ha.CISCO_RF_PEER),
    _chain(ha.CISCO_STACK_MEMBERS),
    _chain(ha.CISCO_STACK_RING),
    _chain(ha.CISCO_STACK_PORTS),
    _chain(ha.HSRP_GROUPS),
    _VRRP,
)
_CISCO_ROUTER = (*_CISCO_MODULE, *_CISCO, *_CISCO_HA)
# IOS and IOS XE: the Catalyst switches too, with PoE.
_CISCO_IOS = (*_CISCO_ROUTER, *_POE)
_CISCO_FIREWALL = (*_CISCO, _chain(ha.CISCO_FAILOVER))
_JUNIPER = (
    _chain(module_health.JUNIPER),
    _chain(env.JUNIPER_DOM),
    _chain(routing.JUNIPER_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
    _ISIS,
    _chain(ha.JUNIPER_REDUNDANCY),
    _chain(ha.JUNIPER_VC_PORTS),
    _VRRP,
    *_POE,
)
_ARISTA = (
    _chain(env.ENTITY_STATE_POWER),
    _chain(env.ARISTA_FAN),
    _chain(env.ENTITY_STATE_SENSORS),
    _chain(routing.ARISTA_BGP_PEERS, routing.BGP4_PEERS),
    _OSPF,
    _ISIS,
    _VRRP,
    *_POE,
)
_PALOALTO = (
    _chain(env.ENTITY_STATE_POWER_FAN),
    _chain(env.ENTITY_STATE_SENSORS),
    *STANDARD_ROUTING,
    _chain(ha.PANOS_HA),
)
_AOS_SWITCH = (_chain(env.AOS_SWITCH_SENSORS), _chain(env.AOS_SWITCH_DOM), *STANDARD)

DEVICE_PLANS: dict[str, tuple[Chain, ...]] = {
    "cisco_ios": _CISCO_IOS,
    "cisco_xe": _CISCO_IOS,
    "cisco_nxos": _CISCO_ROUTER,
    "cisco_nxos_ssh": (*_CISCO, *_CISCO_HA),
    "cisco_xr": _CISCO_ROUTER,
    "cisco_asa": _CISCO_FIREWALL,
    "cisco_ftd": _CISCO_FIREWALL,
    "juniper": _JUNIPER,
    "juniper_junos": _JUNIPER,
    "arista_eos": _ARISTA,
    "paloalto": _PALOALTO,
    "paloalto_panos": _PALOALTO,
    "fortinet": (_chain(env.FORTINET_SENSORS), *STANDARD, _chain(ha.FORTIGATE_HA)),
    "aruba_osswitch": _AOS_SWITCH,
    "aruba_procurve": _AOS_SWITCH,
    "hp_procurve": _AOS_SWITCH,
    "aruba_aoscx": (
        _chain(env.AOSCX_POWER),
        _chain(env.AOSCX_FAN),
        *STANDARD,
        _chain(ha.ARUBA_VSF_MEMBERS),
        _chain(ha.ARUBA_VSX),
    ),
    "netgear_prosafe": (
        _chain(env.NETGEAR_POWER),
        _chain(env.NETGEAR_FAN),
        _chain(env.NETGEAR_TEMPERATURE),
        *STANDARD,
    ),
}
# Device types not read at all: a UPS (its own reader), a ping-only host.
NOT_READ = frozenset({"apc_ups", "icmp_only"})


def plan_for_device(device_type: str | None) -> tuple[Chain, ...]:
    """The chains a device type reads; the standard routing and VRRP tables
    for a type without a plan of its own."""
    key = str(device_type or "").strip().lower()
    if key in NOT_READ:
        return ()
    return DEVICE_PLANS.get(key, STANDARD)


def forget_all() -> None:
    """Drop every per-host memory (tests; host ids restart with the database)."""
    _COLUMNS.clear()
    routing.forget_all()
    ha.forget_all()


# A source's read in one poll: its table, and whether each column it walked
# empty is confirmed empty.
SourceRead = tuple[dict[str, Any] | None, list[bool]]


async def _read_source(source: sh.Source, host_id: int, get: sh.Get, walk_table: WalkTable) -> SourceRead:
    """One source's read, with the empty-table memory of its columns."""
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

    return await source.read(get, walk, host_id), confirmed


async def _read_chain(
    chain: Chain,
    host_id: int,
    get: sh.Get,
    walk_table: WalkTable,
    shared: dict[int, asyncio.Future[SourceRead]] | None = None,
) -> dict[str, Any] | None:
    """The table of the first source of the chain that has rows; None when
    not read (a walk cut short, a kind GET unanswered, or every source empty
    but not yet confirmed); an empty table when every source is confirmed
    empty. ``shared``: the reads of one poll, so a source in two chains
    (the Cisco sensor thresholds: temperature and optics) is read once."""
    confirmed: list[bool] = []
    empty: dict[str, Any] | None = None
    for source in chain.sources:
        if shared is None:
            table, flags = await _read_source(source, host_id, get, walk_table)
        else:
            if id(source) not in shared:
                shared[id(source)] = asyncio.ensure_future(_read_source(source, host_id, get, walk_table))
            table, flags = await shared[id(source)]
        confirmed.extend(flags)
        if table is None:
            return None
        if not sh.is_empty(table):
            return table
        empty = empty or table
    return empty if confirmed and all(confirmed) else None


async def read_health(host_id: int, device_type: str | None, get: sh.Get, walk_table: WalkTable) -> dict[str, Any]:
    """The poll result entries of every check the device type runs:
    ``{check.result_key: state}``, ``{}`` for a check whose table was not
    read; and the HA role changes its tables saw
    (``ha_health.ROLE_CHANGES_KEY``, when any). ``walk_table(oid) -> (rows,
    complete)``; ``get(oids) -> {oid: value}``."""
    plan = plan_for_device(device_type)
    shared: dict[int, asyncio.Future[SourceRead]] = {}
    tables = await asyncio.gather(*(_read_chain(chain, host_id, get, walk_table, shared) for chain in plan))
    states: dict[str, list[dict[str, Any]]] = {}
    role_changes: list[dict[str, str]] = []
    seen_tables: set[int] = set()
    for chain, table in zip(plan, tables, strict=True):
        for check in CHECKS:
            if check.kind in chain.kinds:
                states.setdefault(check.result_key, []).append(sh.select(check, table))
        if table is not None and id(table) not in seen_tables:
            seen_tables.add(id(table))
            role_changes.extend(table.get("role_changes") or [])
    out: dict[str, Any] = {
        check.result_key: sh.merge(check, states[check.result_key]) for check in CHECKS if check.result_key in states
    }
    if role_changes:
        out[ha.ROLE_CHANGES_KEY] = role_changes
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
