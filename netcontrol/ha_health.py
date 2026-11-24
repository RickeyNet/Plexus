"""High availability and redundancy state read by the monitoring poll.

Three checks on the shared ``snmp_health`` shape, so a firewall pair, a
redundant supervisor or a stack that has run degraded since a trap or a
syslog message was lost is still found:

* ``ha_peer_down`` (critical): a unit of a failover pair, a redundancy peer
  (standby supervisor, routing engine), a stack or VSF member, or an HA
  cluster member that is down, out of sync or missing.
* ``ha_link_down`` (warning): a link that keeps the redundancy together
  (the ASA failover LAN interface, a Cisco stack port shut by the stack
  manager or a stack that is no longer a redundant ring, a Juniper Virtual
  Chassis port, the AOS-CX VSX ISL and keepalive).
* ``fhrp_group_down`` (warning): a VRRP or HSRP group stuck in its initial
  state while its interface is admin up.

One alert per item, dedup key per item, resolved when it reads OK (or
disabled by an operator, or is no longer in a table read completely); a
poll that read no table raises and resolves nothing; the empty-table rules
are ``health_checks``'s. Which tables a device type reads is
``health_checks.DEVICE_PLANS``.

Several tables answer one check on a device (a Catalyst: the redundancy
peer and the stack members), so each table's rows get a prefix of their
own in the item index (``HaRules.prefix``): ``{host}:ha_peer_down:2.1001``
is stack member entity 1001. ``snmp_health.merge`` makes one state of them.

Roles are not faults: an active / standby, master / backup or primary /
secondary unit is OK whichever role it holds. A role that changed between
two polls (a failover, a VRRP master moving) is reported on the table
(``role_changes``) and raised by the poll as one ``ha_role_change`` event
alert per host (warning, resolved an hour after the last change).

The rules on top of the states (``HaRules``):

* ``seen``: states that are only a fault for a row this process has seen
  OK. A chassis that never had a standby supervisor reads its peer as
  disabled, a single switch reads its stack as not a redundant ring and its
  Virtual Chassis ports as down: never alerted. Once seen OK, the row in
  that state is down until it reads OK again, or until
  ``HA_MEMORY_SECONDS`` (7 days) after it was last seen OK; then it is
  forgotten and its alert resolves (as for a row no longer in the table).
* ``gone``: a row seen OK that left a table read completely is down ("gone
  from the table") for the same memory (a stack member pulled out, a
  routing engine removed). Used by the tables of units (``ha_peer_down``).
* ``confirm``: states that alert only when seen at two polls in a row (a
  VRRP group in its initial state just after an interface came up, a
  cluster member resyncing after a configuration change).
* ``interface``: the row index starts with an ifIndex; for the rows down,
  the interface's name and admin status are read (IF-MIB ``ifName``,
  ``ifAdminStatus``): a group on an interface shut by an operator is not an
  alert.

The memory is the server process's: a restart forgets it. An open alert of
a row in a ``seen`` state then neither raises nor resolves until the row
reads OK; a row that is gone at that moment has its alert resolved at the
next poll; a role change across a restart is not reported.

Sources, checked against the MIB texts (OIDs worked out from the
MODULE-IDENTITY and OBJECT IDENTIFIER chain of each module):

  CISCO-FIREWALL-MIB (ciscoFirewallMIB 1.3.6.1.4.1.9.9.147), cfwHardwareStatusTable
  .1.2.1.1 indexed by cfwHardwareType (Hardware: netInterface(4) is the
  failover LAN interface, primaryUnit(6), secondaryUnit(7)):
    cfwHardwareInformation  .2   cfwHardwareStatusValue .3   cfwHardwareStatusDetail .4
    HardwareStatus: other(1) up(2) down(3) error(4) overTemp(5) busy(6)
                    noMedia(7) backup(8) active(9) standby(10)
  CISCO-RF-MIB (ciscoRFMIB 1.3.6.1.4.1.9.9.176), cRFStatus .1.1 scalars:
    cRFStatusPeerUnitState  .1.1.4  RFState notKnown(1) disabled(2)
                            initialization(3) negotiation(4) standbyCold(5)
                            standbyColdConfig(6) standbyColdFileSys(7)
                            standbyColdBulk(8) standbyHot(9) activeFast(10)
                            ... active(14) ... standbyWarm(17)
  CISCO-STACKWISE-MIB (ciscoStackWiseMIB 1.3.6.1.4.1.9.9.500):
    cswRingRedundant        .1.1.3      TruthValue
    cswSwitchState          .1.2.1.1.6  indexed by entPhysicalIndex
    cswStackPortOperStatus  .1.2.2.1.1  indexed by ifIndex: up(1) down(2) forcedDown(3)
  JUNIPER-MIB jnxRedundancyTable (jnxBoxAnatomy 14, 1.3.6.1.4.1.2636.3.1.14.1):
    jnxRedundancyDescr .5, jnxRedundancyState .7  unknown(1) master(2) backup(3) disabled(4)
  JUNIPER-VIRTUALCHASSIS-MIB (jnxVirtualChassisMemberMIB 1.3.6.1.4.1.2636.3.40.1.4.1),
  jnxVirtualChassisPortTable .2.1 indexed by member (FPC) id and port name:
    jnxVirtualChassisPortAdminStatus .3, jnxVirtualChassisPortOperStatus .4
    up(1) down(2) unknown(3)
  FORTINET-FORTIGATE-MIB (fnFortiGateMib 1.3.6.1.4.1.12356.101), fgHighAvailability .13:
    fgHaSystemMode      .13.1.1        FgHaMode standalone(1) activeActive(2) activePassive(3)
    fgHaStatsHostname   .13.2.1.1.11   (fgHaStatsTable, one row per cluster member)
    fgHaStatsSyncStatus .13.2.1.1.12   unsynchronized(0) synchronized(1)
  PAN-COMMON-MIB (panSys 1.3.6.1.4.1.25461.2.1.2.1), DisplayString scalars:
    panSysHAState .11, panSysHAPeerState .12, panSysHAMode .13 ("disabled",
    "active-passive", "active-active"); the state words are PAN-OS's HA
    states (the MIB does not list them): initial, active, passive,
    active-primary, active-secondary, tentative, non-functional, suspended,
    unknown
  ARUBAWIRED-VSX-MIB (arubaWiredVsxMIB 1.3.6.1.4.1.47196.4.1.1.3.7):
    arubaWiredVsxDeviceRole       .1.4.1  primary(1) secondary(2) notConfigured(3)
    arubaWiredVsxIslOperState     .2.1.1  init(1) outSync(2) inSync(3)
    arubaWiredVsxKeepAliveOperState .2.2.1  init(1) configured(2) inSyncEstablished(3)
                                  outofSyncEstablished(4) initEstablished(5) failed(6) stopped(7)
  ARUBAWIRED-VSF-MIB (arubaWiredVsfMIB 1.3.6.1.4.1.47196.4.1.1.3.10):
    arubaWiredVsfMemberStatus .0.3.1.3  DisplayString: not_present, booting,
                              ready, version_mismatch, communication_failure,
                              in_other_fragment
  VRRPV3-MIB (RFC 6527, vrrpv3MIB 1.3.6.1.2.1.207), vrrpv3OperationsTable
  .1.1.1.1 indexed by ifIndex, VRID, address type:
    vrrpv3OperationsStatus .6  initialize(1) backup(2) master(3)
    vrrpv3OperationsRowStatus .13  notInService(2)
  VRRP-MIB (RFC 2787, vrrpMIB 1.3.6.1.2.1.68), vrrpOperTable .1.3.1 indexed by
  ifIndex, VRID:
    vrrpOperState .3  initialize(1) backup(2) master(3); vrrpOperAdminState .4 down(2)
  CISCO-HSRP-MIB (ciscoHsrpMIB 1.3.6.1.4.1.9.9.106), cHsrpGrpTable .1.2.1.1
  indexed by ifIndex, group number:
    cHsrpGrpStandbyState .15  HsrpState initial(1) learn(2) listen(3) speak(4)
                              standby(5) active(6)

Not read (docs/vendor-monitoring-coverage.md): Arista MLAG (no public MIB),
Juniper SRX chassis cluster, the AOS-CX VSFv2 tables, the RF local unit
state and progression (a standby stuck in a cold sub-state), OPNsense CARP
(read over syslog), Netgear and AOS-Switch stacking.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from netcontrol import snmp_health as sh
from netcontrol.routes.snmp import snmp_int
from netcontrol.snmp_health import ADMIN_DOWN, DOWN, OK, TRANSITIONAL, HealthCheck, TableSource

KIND_PEER = "ha_peer"
KIND_LINK = "ha_link"
KIND_FHRP = "fhrp_group"

PEER = HealthCheck(
    metric="ha_peer_down",
    result_key="ha_peer_health",
    kind=KIND_PEER,
    severity="critical",
    noun="HA unit",
)
LINK = HealthCheck(
    metric="ha_link_down",
    result_key="ha_link_health",
    kind=KIND_LINK,
    severity="warning",
    noun="HA link",
)
FHRP = HealthCheck(
    metric="fhrp_group_down",
    result_key="fhrp_health",
    kind=KIND_FHRP,
    severity="warning",
    noun="Gateway group",
)
CHECKS = (PEER, LINK, FHRP)

# The event alert of a role change: one per host, resolved an hour after
# the last change (``netcontrol.routes.monitoring``).
ROLE_CHANGE_METRIC = "ha_role_change"
ROLE_CHANGE_SEVERITY = "warning"
# The poll result key of a poll's role changes.
ROLE_CHANGES_KEY = "ha_role_changes"

# How long a row seen OK is remembered (for ``seen`` and ``gone``).
HA_MEMORY_SECONDS = 7 * 24 * 3600
GONE_STATE = 0
GONE_STATUS = "gone from the table"

# IF-MIB, for the groups indexed by an interface.
IF_ADMIN_STATUS = sh.IF_ADMIN_STATUS
IF_NAME = sh.IF_NAME
IF_ADMIN_DOWN = sh.IF_ADMIN_DOWN


@dataclass(frozen=True)
class HaRules:
    """The rules on top of a table's states (see the module docstring)."""

    # Keeps the table's rows apart from the other tables of the same check.
    prefix: int
    seen: frozenset[int] = frozenset()
    gone: bool = False
    confirm: frozenset[int] = frozenset()
    # OK state: its role, for the role change alert.
    roles: dict[int, str] = field(default_factory=dict)
    interface: bool = False


# Per-host memory of this process, by ``(host_id, table key)``: the rows
# seen OK ``{index: (name, monotonic time)}``, the rows in a ``confirm``
# state at the last poll, the role of each row, and (FortiGate) the largest
# cluster seen ``(members, monotonic time last seen that large)``.
_SEEN: dict[tuple[int, str], dict[str, tuple[str, float]]] = {}
_PENDING: dict[tuple[int, str], set[str]] = {}
_ROLES: dict[tuple[int, str], dict[str, str]] = {}
_MEMBERS: dict[tuple[int, str], tuple[int, float]] = {}


def forget_all() -> None:
    """Drop the per-host memory (tests; host ids restart with the database)."""
    _SEEN.clear()
    _PENDING.clear()
    _ROLES.clear()
    _MEMBERS.clear()


def _remembered(seen: dict[str, tuple[str, float]], index: str, now: float) -> bool:
    known = seen.get(index)
    if known is None:
        return False
    if now - known[1] > HA_MEMORY_SECONDS:
        del seen[index]
        return False
    return True


def _item(index: str, kind: str, name: str, status: str, state: int, klass: str) -> dict[str, Any]:
    return {
        "index": index,
        "kind": kind,
        "name": name,
        "model": "",
        "status": status,
        "state": state,
        "class": klass,
        "severity": None,
    }


def settle(
    key: str, rules: HaRules, host_id: int, table: dict[str, Any] | None, now: float | None = None
) -> dict[str, Any] | None:
    """Apply ``rules`` to a read table (see the module docstring), prefix its
    indexes, and note its role changes (``role_changes``: name, from, to).
    A table not read, or read empty, passes as it is."""
    if not table or sh.is_empty(table):
        return table
    now = time.monotonic() if now is None else now
    memo = (host_id, key)
    seen = _SEEN.setdefault(memo, {})
    pending = _PENDING.get(memo, set())
    roles = _ROLES.setdefault(memo, {})
    kept: list[dict[str, Any]] = []
    changes: list[dict[str, str]] = []
    in_confirm: set[str] = set()
    present: set[str] = set()
    for item in table.get("items") or []:
        index = str(item["index"])
        present.add(index)
        if item["class"] == OK:
            seen[index] = (item["name"], now)
            role = rules.roles.get(item["state"])
            before = roles.pop(index, None)
            if role:
                roles[index] = role
                if before and before != role:
                    changes.append({"name": item["name"], "from": before, "to": role})
            kept.append(item)
            continue
        roles.pop(index, None)
        if item["class"] == DOWN and item["state"] in rules.seen and not _remembered(seen, index, now):
            continue  # never seen working (no standby, a single switch): not an item
        if item["class"] == DOWN and item["state"] in rules.confirm:
            in_confirm.add(index)
            if index not in pending:
                item["class"] = TRANSITIONAL
        kept.append(item)
    if rules.gone:
        for index, (name, last_seen) in list(seen.items()):
            if index in present:
                continue
            if now - last_seen > HA_MEMORY_SECONDS:
                del seen[index]
                continue
            roles.pop(index, None)
            kept.append(_item(index, KIND_PEER, name, GONE_STATUS, GONE_STATE, DOWN))
    _PENDING[memo] = in_confirm
    for item in kept:
        item["index"] = f"{rules.prefix}.{item['index']}"
    table["items"] = kept
    if changes:
        table["role_changes"] = changes
    return table


@dataclass(frozen=True)
class HaTable(TableSource):
    """A redundancy table: the shared read, then its rules."""

    rules: HaRules = field(default_factory=lambda: HaRules(prefix=0))

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        table = await sh.read_table(self, get, walk)
        if not table or sh.is_empty(table):
            return table
        if self.rules.interface:
            await sh.interface_details(table.get("items") or [], get)
        return settle(self.key, self.rules, host_id, table)


# ── Cisco ASA / FTD failover: CISCO-FIREWALL-MIB ────────────────────────────

CFW_HW_INFORMATION = "1.3.6.1.4.1.9.9.147.1.2.1.1.1.2"
CFW_HW_STATUS_VALUE = "1.3.6.1.4.1.9.9.147.1.2.1.1.1.3"
CFW_HW_STATUS_DETAIL = "1.3.6.1.4.1.9.9.147.1.2.1.1.1.4"
# cfwHardwareType (the row index): netInterface(4) is the failover LAN
# interface on an ASA; primaryUnit(6) and secondaryUnit(7) the pair.
CFW_FAILOVER_LAN = "4"
CFW_UNITS = frozenset({"6", "7"})
CFW_UNIT_NAMES = {"4": "Failover LAN interface", "6": "Primary unit", "7": "Secondary unit"}
# HardwareStatus. backup(8), active(9) and standby(10) are a working unit
# in one role or the other; up(2) a working link.
CFW_STATES: dict[int, tuple[str, str]] = {
    1: ("other", TRANSITIONAL),
    2: ("up", OK),
    3: ("down", DOWN),
    4: ("in error", DOWN),
    5: ("overheating", DOWN),
    6: ("busy", TRANSITIONAL),
    7: ("without its media", DOWN),
    8: ("backup", OK),
    9: ("active", OK),
    10: ("standby", OK),
}
# The detail an ASA gives the rows of a device without failover ("Failover
# Off" on the units, "not Configured" on the LAN interface: ASA's wording,
# not the MIB's): not a fault, and resolves an open alert.
CFW_NOT_CONFIGURED = ("failover off", "not configured")


def _cfw_kind(index: str) -> str | None:
    if index == CFW_FAILOVER_LAN:
        return KIND_LINK
    return KIND_PEER if index in CFW_UNITS else None


def _cfw_name(values: dict[str, Any]) -> str:
    return sh.text(values.get(CFW_HW_INFORMATION))


def _cfw_off(values: dict[str, Any]) -> bool:
    detail = sh.text(values.get(CFW_HW_STATUS_DETAIL)).lower()
    return any(word in detail for word in CFW_NOT_CONFIGURED)


CISCO_FAILOVER = HaTable(
    key="cisco_firewall_failover",
    vendor="Cisco",
    state_oid=CFW_HW_STATUS_VALUE,
    states=CFW_STATES,
    kinds=frozenset({KIND_PEER, KIND_LINK}),
    index_kind=_cfw_kind,
    detail_oids=(CFW_HW_INFORMATION, CFW_HW_STATUS_DETAIL),
    admin_off=_cfw_off,
    name=_cfw_name,
    index_name=lambda i: CFW_UNIT_NAMES.get(i, f"Failover row {i}"),
    model=lambda v: sh.text(v.get(CFW_HW_STATUS_DETAIL)),
    rules=HaRules(prefix=1, roles={9: "active", 10: "standby"}),
)

# ── Cisco IOS XE / NX-OS / IOS: CISCO-RF-MIB redundancy peer ────────────────

RF_PEER_UNIT_STATE = "1.3.6.1.4.1.9.9.176.1.1.4"
RF_DISABLED = 2
# RFState of the peer unit. The standby sub-states on their way to hot, and
# negotiation, pass; standbyCold(5) is the steady standby of RPR mode.
RF_STATES: dict[int, tuple[str, str]] = {
    1: ("not known", TRANSITIONAL),
    2: ("disabled (not present or not running)", DOWN),
    3: ("initializing", TRANSITIONAL),
    4: ("negotiating", TRANSITIONAL),
    5: ("standby cold", OK),
    6: ("standby cold, syncing configuration", TRANSITIONAL),
    7: ("standby cold, syncing file system", TRANSITIONAL),
    8: ("standby cold, bulk syncing", TRANSITIONAL),
    9: ("standby hot", OK),
    10: ("active (switching over)", OK),
    11: ("active (draining)", OK),
    12: ("active (before configuration)", OK),
    13: ("active (after configuration)", OK),
    14: ("active", OK),
    15: ("active (extra load)", OK),
    16: ("active (handing back)", OK),
    17: ("standby warm", OK),
}

CISCO_RF_PEER = HaTable(
    key="cisco_rf_peer",
    vendor="Cisco",
    state_oid=RF_PEER_UNIT_STATE,
    states=RF_STATES,
    kinds=frozenset({KIND_PEER}),
    index_name=lambda _i: "Redundancy peer (standby supervisor or switch)",
    rules=HaRules(prefix=2, seen=frozenset({RF_DISABLED})),
)

# ── Cisco stacks: CISCO-STACKWISE-MIB ───────────────────────────────────────

CSW_RING_REDUNDANT = "1.3.6.1.4.1.9.9.500.1.1.3"
CSW_SWITCH_STATE = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"
CSW_STACK_PORT_OPER = "1.3.6.1.4.1.9.9.500.1.2.2.1.1"
CSW_PROVISIONED = 9
CSW_REMOVED = 11
# cswSwitchState per member (each a chassis entity; the module check reads
# the module entities of cefcModuleTable, not these).
CSW_SWITCH_STATES: dict[int, tuple[str, str]] = {
    1: ("waiting for the other members", TRANSITIONAL),
    2: ("electing or checking", TRANSITIONAL),
    3: ("added", TRANSITIONAL),
    4: ("ready", OK),
    5: ("SDM template mismatch", DOWN),
    6: ("software version mismatch", DOWN),
    7: ("feature mismatch", DOWN),
    8: ("waiting for the new master", TRANSITIONAL),
    9: ("provisioned, not an active member", DOWN),
    10: ("in an invalid state", DOWN),
    11: ("removed from the stack", DOWN),
}
# cswStackPortOperStatus. down(2) is "not connected or administratively
# down": a cable pulled from a ring is told by cswRingRedundant (one alert
# per stack rather than one per port end); forcedDown(3), shut by the stack
# manager for a mismatch or errors, is the port's own fault.
CSW_PORT_STATES: dict[int, tuple[str, str]] = {
    1: ("up", OK),
    2: ("down (not connected or shut down)", ADMIN_DOWN),
    3: ("shut down by the stack manager", DOWN),
}
CSW_RING_STATES: dict[int, tuple[str, str]] = {
    1: ("a redundant ring", OK),
    2: ("no longer a redundant ring", DOWN),
}

CISCO_STACK_MEMBERS = HaTable(
    key="cisco_stack_members",
    vendor="Cisco",
    state_oid=CSW_SWITCH_STATE,
    states=CSW_SWITCH_STATES,
    kinds=frozenset({KIND_PEER}),
    detail_oids=(sh.ENT_PHYSICAL_NAME, sh.ENT_PHYSICAL_DESCR),
    name=sh.entity_name,
    index_name=lambda i: f"Stack member (entity {i})",
    rules=HaRules(prefix=3, seen=frozenset({CSW_PROVISIONED, CSW_REMOVED}), gone=True),
)
CISCO_STACK_PORTS = HaTable(
    key="cisco_stack_ports",
    vendor="Cisco",
    state_oid=CSW_STACK_PORT_OPER,
    states=CSW_PORT_STATES,
    kinds=frozenset({KIND_LINK}),
    detail_oids=(IF_NAME,),
    name=lambda v: f"Stack port {sh.text(v.get(IF_NAME))}" if sh.text(v.get(IF_NAME)) else "",
    index_name=lambda i: f"Stack port (ifIndex {i})",
    rules=HaRules(prefix=4),
)
CISCO_STACK_RING = HaTable(
    key="cisco_stack_ring",
    vendor="Cisco",
    state_oid=CSW_RING_REDUNDANT,
    states=CSW_RING_STATES,
    kinds=frozenset({KIND_LINK}),
    index_name=lambda _i: "Stack ring",
    rules=HaRules(prefix=5, seen=frozenset({2})),
)

# ── Juniper: JUNIPER-MIB jnxRedundancyTable, Virtual Chassis ports ──────────

JNX_REDUNDANCY_DESCR = "1.3.6.1.4.1.2636.3.1.14.1.5"
JNX_REDUNDANCY_STATE = "1.3.6.1.4.1.2636.3.1.14.1.7"
# jnxRedundancyState. disabled(4) after the component was seen master or
# backup is lost redundancy; a component that leaves the table (a routing
# engine pulled: its FRU reads empty, which the module check does not take
# as a module) is gone. An offline routing engine is the module check's
# module_down (jnxFruState offline); this table then reads it disabled
# too, which raises its own ha_peer_down (redundancy lost) beside it.
JNX_REDUNDANCY_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("master", OK),
    3: ("backup", OK),
    4: ("disabled", DOWN),
}

JUNIPER_REDUNDANCY = HaTable(
    key="juniper_redundancy",
    vendor="Juniper",
    state_oid=JNX_REDUNDANCY_STATE,
    states=JNX_REDUNDANCY_STATES,
    kinds=frozenset({KIND_PEER}),
    detail_oids=(JNX_REDUNDANCY_DESCR,),
    name=lambda v: sh.text(v.get(JNX_REDUNDANCY_DESCR)),
    index_name=lambda i: f"Redundant component {i}",
    rules=HaRules(prefix=6, seen=frozenset({4}), gone=True, roles={2: "master", 3: "backup"}),
)

JNX_VC_PORT_ADMIN = "1.3.6.1.4.1.2636.3.40.1.4.1.2.1.3"
JNX_VC_PORT_OPER = "1.3.6.1.4.1.2636.3.40.1.4.1.2.1.4"
JNX_VC_PORT_STATES: dict[int, tuple[str, str]] = {
    1: ("up", OK),
    2: ("down", DOWN),
    3: ("unknown", TRANSITIONAL),
}


def vc_port_name(index: str) -> str:
    """jnxVirtualChassisFpcId.jnxVirtualChassisPortName (a length-prefixed
    string) as ``member 1 vcp-255/1/0``."""
    parts = [int(p) for p in index.split(".") if p.isdigit()]
    if len(parts) < 2 or len(parts) != parts[1] + 2 or any(not 32 <= c < 127 for c in parts[2:]):
        return f"Virtual Chassis port {index}"
    return f"Virtual Chassis member {parts[0]} port {bytes(parts[2:]).decode('ascii')}"


JUNIPER_VC_PORTS = HaTable(
    key="juniper_vc_ports",
    vendor="Juniper",
    state_oid=JNX_VC_PORT_OPER,
    states=JNX_VC_PORT_STATES,
    kinds=frozenset({KIND_LINK}),
    detail_oids=(JNX_VC_PORT_ADMIN,),
    admin_off=lambda v: snmp_int(v.get(JNX_VC_PORT_ADMIN)) == 2,
    index_name=vc_port_name,
    rules=HaRules(prefix=7, seen=frozenset({2})),
)

# ── First hop redundancy: VRRP (v3, v2) and Cisco HSRP ──────────────────────

VRRPV3_STATUS = "1.3.6.1.2.1.207.1.1.1.1.6"
VRRPV3_ROW_STATUS = "1.3.6.1.2.1.207.1.1.1.1.13"
VRRP_OPER_STATE = "1.3.6.1.2.1.68.1.3.1.3"
VRRP_OPER_ADMIN_STATE = "1.3.6.1.2.1.68.1.3.1.4"
HSRP_STANDBY_STATE = "1.3.6.1.4.1.9.9.106.1.2.1.1.15"
# initialize(1): waiting for a startup event, which on a group that is
# enabled means its interface is down or it is misconfigured. Backup and
# master are roles.
VRRP_STATES: dict[int, tuple[str, str]] = {
    1: ("initializing", DOWN),
    2: ("backup", OK),
    3: ("master", OK),
}
VRRP_ROLES = {2: "backup", 3: "master"}
# RowStatus notInService(2); VRRP-MIB vrrpOperAdminState down(2).
ROW_NOT_IN_SERVICE = 2
# HsrpState: initial(1) is the group not running; learn(2) and speak(4)
# pass; listen(3) is a third router's healthy role.
HSRP_STATES: dict[int, tuple[str, str]] = {
    1: ("initial", DOWN),
    2: ("learning", TRANSITIONAL),
    3: ("listen", OK),
    4: ("speaking", TRANSITIONAL),
    5: ("standby", OK),
    6: ("active", OK),
}
HSRP_ROLES = {3: "listen", 5: "standby", 6: "active"}


def _group_name(protocol: str):
    def name(index: str) -> str:
        parts = index.split(".")
        group = parts[1] if len(parts) > 1 else index
        return f"{protocol} group {group}"

    return name


VRRPV3_GROUPS = HaTable(
    key="vrrpv3",
    vendor="VRRPV3-MIB",
    state_oid=VRRPV3_STATUS,
    states=VRRP_STATES,
    kinds=frozenset({KIND_FHRP}),
    detail_oids=(VRRPV3_ROW_STATUS,),
    admin_off=lambda v: snmp_int(v.get(VRRPV3_ROW_STATUS)) == ROW_NOT_IN_SERVICE,
    index_name=_group_name("VRRP"),
    rules=HaRules(prefix=8, confirm=frozenset({1}), roles=VRRP_ROLES, interface=True),
)
VRRP_GROUPS = HaTable(
    key="vrrp",
    vendor="VRRP-MIB",
    state_oid=VRRP_OPER_STATE,
    states=VRRP_STATES,
    kinds=frozenset({KIND_FHRP}),
    detail_oids=(VRRP_OPER_ADMIN_STATE,),
    admin_off=lambda v: snmp_int(v.get(VRRP_OPER_ADMIN_STATE)) == 2,
    index_name=_group_name("VRRP"),
    rules=HaRules(prefix=9, confirm=frozenset({1}), roles=VRRP_ROLES, interface=True),
)
HSRP_GROUPS = HaTable(
    key="cisco_hsrp",
    vendor="Cisco",
    state_oid=HSRP_STANDBY_STATE,
    states=HSRP_STATES,
    kinds=frozenset({KIND_FHRP}),
    index_name=_group_name("HSRP"),
    rules=HaRules(prefix=10, confirm=frozenset({1}), roles=HSRP_ROLES, interface=True),
)

# ── HPE Aruba AOS-CX: VSF members, VSX ──────────────────────────────────────

VSF_MEMBER_STATUS = "1.3.6.1.4.1.47196.4.1.1.3.10.0.3.1.3"
VSF_CODES = {
    "not_present": 1,
    "booting": 2,
    "ready": 3,
    "version_mismatch": 4,
    "communication_failure": 5,
    "in_other_fragment": 6,
}
VSF_STATES: dict[int, tuple[str, str]] = {
    0: ("in an unknown state", TRANSITIONAL),
    1: ("not present", DOWN),
    2: ("booting", TRANSITIONAL),
    3: ("ready", OK),
    4: ("version mismatch", DOWN),
    5: ("not communicating with the conductor", DOWN),
    6: ("in another fragment (stack split)", DOWN),
}


def _vsf_state(raw: Any) -> int | None:
    value = sh.text(raw).strip().lower()
    return VSF_CODES.get(value, 0) if value else None


ARUBA_VSF_MEMBERS = HaTable(
    key="aruba_vsf_members",
    vendor="HPE Aruba",
    state_oid=VSF_MEMBER_STATUS,
    states=VSF_STATES,
    kinds=frozenset({KIND_PEER}),
    state_of=_vsf_state,
    index_name=lambda i: f"VSF member {i}",
    rules=HaRules(prefix=11, seen=frozenset({1}), gone=True),
)

VSX_DEVICE_ROLE = "1.3.6.1.4.1.47196.4.1.1.3.7.1.4.1"
VSX_ISL_OPER_STATE = "1.3.6.1.4.1.47196.4.1.1.3.7.2.1.1.0"
VSX_KEEPALIVE_OPER_STATE = "1.3.6.1.4.1.47196.4.1.1.3.7.2.2.1.0"
VSX_NOT_CONFIGURED = 3
VSX_ISL_STATES: dict[int, tuple[str, str]] = {
    1: ("initializing", TRANSITIONAL),
    2: ("out of sync", DOWN),
    3: ("in sync", OK),
}
VSX_KEEPALIVE_STATES: dict[int, tuple[str, str]] = {
    1: ("initializing", TRANSITIONAL),
    2: ("configured, not established", TRANSITIONAL),
    3: ("established, in sync", OK),
    4: ("established, out of sync", DOWN),
    5: ("established, initializing", TRANSITIONAL),
    6: ("failed", DOWN),
    7: ("stopped", TRANSITIONAL),
}


@dataclass(frozen=True)
class ArubaVsx:
    """VSX on AOS-CX: the device role (one walk; not configured: no
    items), then the ISL and keepalive states in one GET."""

    key: str = "aruba_vsx"
    vendor: str = "HPE Aruba"
    kinds: frozenset[str] = frozenset({KIND_LINK})
    rules: HaRules = field(default_factory=lambda: HaRules(prefix=12, confirm=frozenset({2, 4, 6})))

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, VSX_DEVICE_ROLE)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, VSX_DEVICE_ROLE)
        if not rows:
            return sh.empty_table(self.key, self.vendor)
        table: dict[str, Any] = {"source": self.key, "vendor": self.vendor, "items": []}
        if snmp_int(next(iter(rows.values()))) == VSX_NOT_CONFIGURED:
            return table
        answers = await sh.get_all(get, [VSX_ISL_OPER_STATE, VSX_KEEPALIVE_OPER_STATE])
        if answers is None:
            return None
        for index, name, oid, states in (
            ("1", "VSX ISL", VSX_ISL_OPER_STATE, VSX_ISL_STATES),
            ("2", "VSX keepalive", VSX_KEEPALIVE_OPER_STATE, VSX_KEEPALIVE_STATES),
        ):
            state = snmp_int(answers.get(oid))
            if state is None:
                continue
            label, klass = states.get(state, (f"state {state}", TRANSITIONAL))
            table["items"].append(_item(index, KIND_LINK, name, label, state, klass))
        return settle(self.key, self.rules, host_id, table)


ARUBA_VSX = ArubaVsx()

# ── Fortinet FortiGate HA: FORTINET-FORTIGATE-MIB ───────────────────────────

FG_HA_SYSTEM_MODE = "1.3.6.1.4.1.12356.101.13.1.1.0"
FG_HA_STATS_HOSTNAME = "1.3.6.1.4.1.12356.101.13.2.1.1.11"
FG_HA_STATS_SYNC_STATUS = "1.3.6.1.4.1.12356.101.13.2.1.1.12"
FG_STANDALONE = 1
FG_UNSYNCHRONIZED = 0
FG_MEMBERS_MISSING = 2
FG_STATES: dict[int, tuple[str, str]] = {
    FG_UNSYNCHRONIZED: ("out of sync", DOWN),
    1: ("in sync", OK),
}


def _cluster_size(host_id: int, key: str, members: int, now: float) -> int | None:
    """The largest cluster this process has seen on the host when it now
    has fewer members (and was that large within the memory); else None,
    remembering this size."""
    memo = (host_id, key)
    known = _MEMBERS.get(memo)
    if known is None or members >= known[0] or now - known[1] > HA_MEMORY_SECONDS:
        _MEMBERS[memo] = (members, now)
        return None
    return known[0]


@dataclass(frozen=True)
class FortiGateHa:
    """The cluster members of fgHaStatsTable (one walk of the sync status;
    the table also has the one row of a standalone unit), the HA mode and
    the names of the members out of sync in one GET. Standalone: no items.
    A cluster with fewer members than it had is down too ("1 of 2
    members"). Out of sync and a member missing alert at the second poll
    in a row (a member resyncing after a change, a member rebooting)."""

    key: str = "fortigate_ha"
    vendor: str = "Fortinet"
    kinds: frozenset[str] = frozenset({KIND_PEER})
    rules: HaRules = field(
        default_factory=lambda: HaRules(prefix=13, confirm=frozenset({FG_UNSYNCHRONIZED, FG_MEMBERS_MISSING}))
    )

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int, now: float | None = None) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, FG_HA_STATS_SYNC_STATUS)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, FG_HA_STATS_SYNC_STATUS)
        if not rows:
            return sh.empty_table(self.key, self.vendor)
        states = {index: snmp_int(raw) for index, raw in rows.items()}
        unsynced = [i for i, s in states.items() if s != 1]
        answers = await sh.get_all(get, [FG_HA_SYSTEM_MODE, *(f"{FG_HA_STATS_HOSTNAME}.{i}" for i in unsynced)])
        mode = snmp_int((answers or {}).get(FG_HA_SYSTEM_MODE))
        if answers is None or mode is None:
            return None
        table: dict[str, Any] = {"source": self.key, "vendor": self.vendor, "items": []}
        if mode == FG_STANDALONE:
            _MEMBERS.pop((host_id, self.key), None)
            return table
        for index in sorted(states, key=int):
            state = states[index]
            if state is None:
                continue
            label, klass = FG_STATES.get(state, (f"state {state}", TRANSITIONAL))
            name = sh.text(answers.get(f"{FG_HA_STATS_HOSTNAME}.{index}")) or f"Cluster member {index}"
            table["items"].append(_item(index, KIND_PEER, name, label, state, klass))
        now = time.monotonic() if now is None else now
        size = _cluster_size(host_id, self.key, len(rows), now)
        if size is not None:
            status = f"{len(rows)} of {size} members"
            table["items"].append(_item("0", KIND_PEER, "HA cluster", status, FG_MEMBERS_MISSING, DOWN))
        return settle(self.key, self.rules, host_id, table, now)


FORTIGATE_HA = FortiGateHa()

# ── Palo Alto PAN-OS HA: PAN-COMMON-MIB ─────────────────────────────────────

PAN_SYS_HA_STATE = "1.3.6.1.4.1.25461.2.1.2.1.11.0"
PAN_SYS_HA_PEER_STATE = "1.3.6.1.4.1.25461.2.1.2.1.12.0"
PAN_SYS_HA_MODE = "1.3.6.1.4.1.25461.2.1.2.1.13"
PAN_CODES = {
    "initial": 1,
    "active": 2,
    "passive": 3,
    "active-primary": 4,
    "active-secondary": 5,
    "tentative": 6,
    "non-functional": 7,
    "suspended": 8,
    "unknown": 9,
}
PAN_UNKNOWN = 9
# The firewall's own state: unknown passes. The peer's: unknown is a peer
# the firewall does not hear (HA1 down, the peer off), down at the second
# poll in a row.
PAN_LOCAL_STATES: dict[int, tuple[str, str]] = {
    0: ("in an unknown state", TRANSITIONAL),
    1: ("initial", TRANSITIONAL),
    2: ("active", OK),
    3: ("passive", OK),
    4: ("active-primary", OK),
    5: ("active-secondary", OK),
    6: ("tentative", TRANSITIONAL),
    7: ("non-functional", DOWN),
    8: ("suspended", DOWN),
    9: ("unknown", TRANSITIONAL),
}
PAN_PEER_STATES = {**PAN_LOCAL_STATES, PAN_UNKNOWN: ("unknown (not heard)", DOWN)}
PAN_ROLES = {2: "active", 3: "passive", 4: "active-primary", 5: "active-secondary"}


def pan_state(raw: Any) -> int:
    """A PAN-OS HA state word as one of ``PAN_CODES`` (0: another word)."""
    return PAN_CODES.get(sh.text(raw).strip().lower(), 0)


@dataclass(frozen=True)
class PanOsHa:
    """PAN-OS HA: the mode (one walk; "disabled": no items), then the
    firewall's and its peer's state in one GET."""

    key: str = "paloalto_ha"
    vendor: str = "Palo Alto"
    kinds: frozenset[str] = frozenset({KIND_PEER})
    rules: HaRules = field(
        default_factory=lambda: HaRules(prefix=14, confirm=frozenset({PAN_UNKNOWN}), roles=PAN_ROLES)
    )

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, PAN_SYS_HA_MODE)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, PAN_SYS_HA_MODE)
        if not rows:
            return sh.empty_table(self.key, self.vendor)
        table: dict[str, Any] = {"source": self.key, "vendor": self.vendor, "items": []}
        mode = sh.text(next(iter(rows.values()))).strip().lower()
        if mode in ("", "disabled"):
            return table
        answers = await sh.get_all(get, [PAN_SYS_HA_STATE, PAN_SYS_HA_PEER_STATE])
        if answers is None:
            return None
        for index, name, oid, states in (
            ("1", "This firewall's HA state", PAN_SYS_HA_STATE, PAN_LOCAL_STATES),
            ("2", "HA peer", PAN_SYS_HA_PEER_STATE, PAN_PEER_STATES),
        ):
            state = pan_state(answers.get(oid))
            label, klass = states[state]
            table["items"].append(_item(index, KIND_PEER, name, label, state, klass))
        return settle(self.key, self.rules, host_id, table)


PANOS_HA = PanOsHa()


def role_changes_message(changes: list[dict[str, str]]) -> str:
    """The role change alert's message: ``HA role changed: Primary unit
    standby -> active; ...`` (at most 5 named)."""
    shown = "; ".join(f"{c['name']} {c['from']} -> {c['to']}" for c in changes[:5])
    more = f"; {len(changes) - 5} more" if len(changes) > 5 else ""
    return f"HA role changed: {shown}{more}"


def role_change_check(host_id: int, changes: list[dict[str, str]]) -> dict[str, Any] | None:
    """The poll's built-in event alert of a poll's role changes; None when
    there is none. One per host: a second failover within the hour counts
    on the open alert."""
    if not changes:
        return None
    return {
        "metric": ROLE_CHANGE_METRIC,
        "alert_type": "event",
        "message": role_changes_message(changes),
        "severity": ROLE_CHANGE_SEVERITY,
        "value": float(len(changes)),
        "threshold": None,
        "dedup_key": f"{host_id}:{ROLE_CHANGE_METRIC}:event",
    }
