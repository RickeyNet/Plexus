"""Hardware module health read by the monitoring poll over SNMP.

Each monitoring poll (``netcontrol/routes/monitoring.py``) of a device type
listed in ``DEVICE_SOURCES`` walks the vendor's module status table, reads
the names of the modules that are not working, and raises one built-in
``module_down`` alert per such module into ``monitoring_alerts``. The alert
resolves when the module reads OK again, is disabled by an operator, or is
no longer in the table. A poll that read no table (SNMP off or timed out,
a device type not read, a device without the MIB) raises nothing and
resolves nothing.

This is the state-based backstop of the module syslog messages: a message
only marks a transition, while the poll also finds a module that never came
up after a reload, or whose message was lost.

The read is bounded: one walk of the status column, then GETs (in requests
of ``OIDS_PER_GET``) only for the rows that need more than their state: the
names of the modules that are down, and on Juniper the FRU type of each
present row (the FRU table also lists fans and power supplies, which the
same read hands to ``environment_health``). The table reading, alerts and
clearing are the shared ``snmp_health`` shape.

Sources, checked against the MIB texts:

  Cisco IOS, IOS XE, NX-OS, IOS XR: CISCO-ENTITY-FRU-CONTROL-MIB
    cefcModuleAdminStatus  1.3.6.1.4.1.9.9.117.1.2.1.1.1  ModuleAdminType
    cefcModuleOperStatus   1.3.6.1.4.1.9.9.117.1.2.1.1.2  ModuleOperType
    (cefcModuleTable has a row per entPhysicalTable entry of class
    module(9), indexed by entPhysicalIndex), names from ENTITY-MIB:
    entPhysicalDescr       1.3.6.1.2.1.47.1.1.1.1.2
    entPhysicalName        1.3.6.1.2.1.47.1.1.1.1.7
    entPhysicalModelName   1.3.6.1.2.1.47.1.1.1.1.13

  Juniper Junos: JUNIPER-MIB (jnxBoxAnatomy) jnxFruTable, indexed by
    jnxFruContentsIndex.jnxFruL1Index.jnxFruL2Index.jnxFruL3Index:
    jnxFruName             1.3.6.1.4.1.2636.3.1.15.1.5
    jnxFruType             1.3.6.1.4.1.2636.3.1.15.1.6
    jnxFruState            1.3.6.1.4.1.2636.3.1.15.1.8
    jnxFruOfflineReason    1.3.6.1.4.1.2636.3.1.15.1.10

Not read (see docs/vendor-monitoring-coverage.md): other vendors, and a
module that left the table without ever reading not-OK (needs a stored
baseline). Stack members (CISCO-STACKWISE-MIB) and supervisor redundancy
(CISCO-RF-MIB) are read by the HA checks (``ha_health``), not here.
"""

from __future__ import annotations

from typing import Any

from netcontrol import snmp_health as sh
from netcontrol.routes.snmp import snmp_int
from netcontrol.snmp_health import (  # re-exported: callers and tests use them from here
    ADMIN_DOWN as ADMIN_DOWN,
    DOWN as DOWN,
    ENT_PHYSICAL_DESCR as ENT_PHYSICAL_DESCR,
    ENT_PHYSICAL_MODEL as ENT_PHYSICAL_MODEL,
    ENT_PHYSICAL_NAME as ENT_PHYSICAL_NAME,
    OIDS_PER_GET as OIDS_PER_GET,
    OK as OK,
    TRANSITIONAL as TRANSITIONAL,
    Get,
    TableSource,
    Walk,
)

# The built-in alert, its type and severity.
ALERT_METRIC = "module_down"
ALERT_TYPE = "status"
ALERT_SEVERITY = "critical"

# The row kinds of the tables below.
KIND_MODULE = "module"
KIND_POWER = "power"
KIND_FAN = "fan"

CHECK = sh.HealthCheck(
    metric=ALERT_METRIC,
    result_key="module_health",
    kind=KIND_MODULE,
    severity=ALERT_SEVERITY,
    noun="Module",
    alert_type=ALERT_TYPE,
    items_key="modules",
)

# A module table (kept as a name: a module source is a TableSource).
ModuleSource = TableSource

# ── Cisco: CISCO-ENTITY-FRU-CONTROL-MIB ─────────────────────────────────────

CEFC_MODULE_ADMIN_STATUS = "1.3.6.1.4.1.9.9.117.1.2.1.1.1"
CEFC_MODULE_OPER_STATUS = "1.3.6.1.4.1.9.9.117.1.2.1.1.2"

# ModuleOperType: (label, class). The class of each value follows its
# DESCRIPTION in the MIB:
#   unknown(1)                 catch-all, state not known: neither raise nor clear
#   ok(2)                      operational
#   disabled(3)                administratively disabled
#   okButDiagFailed(4)         operational, diagnostics reported something: the
#                              module works, so not a module-down alert
#   boot(5), selfTest(6)       coming up
#   failed(7)                  failed (any failure not listed elsewhere)
#   missing(8)                 provisioned but not present
#   mismatchWithParent(9)      incompatible with its parent (chassis/slot)
#   mismatchConfig(10)         incompatible with the configuration
#   diagFailed(11)             a diagnostic test failed: not in service
#   dormant(12)                waiting for an event to become operational
#   outOfServiceAdmin(13)      powered but held out of service by an operator
#   outOfServiceEnvTemp(14)    out of service for temperature
#   poweredDown(15)            powered down; an operator's power-off is told
#                              apart by cefcModuleAdminStatus (below)
#   poweredUp(16)              powered up, not yet operational
#   powerDenied(17)            not enough power budget to power it
#   powerCycled(18)            being power cycled
#   okButPowerOverWarning(19)  operational, drawing more than allocated
#   okButPowerOverCritical(20) operational, drawing more than designed for
#   syncInProgress(21)         standby synchronising with the active
#   upgrading(22)              upgrade in progress
#   okButAuthFailed(23)        operational, failed hardware integrity check
#   mdr(24)                    minimum disruptive restart (upgrade) in progress
#   fwMismatchFound(25)        firmware does not match the system image
#   fwDownloadSuccess(26)      firmware downloaded, about to come up
#   fwDownloadFailure(27)      firmware download failed
# The ``okBut...`` states are operational modules: they are not module-down
# alerts (power and integrity are other checks).
CISCO_OPER_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("ok", OK),
    3: ("disabled", ADMIN_DOWN),
    4: ("ok, diagnostics failed", OK),
    5: ("booting", TRANSITIONAL),
    6: ("in self test", TRANSITIONAL),
    7: ("failed", DOWN),
    8: ("missing", DOWN),
    9: ("mismatched with its parent", DOWN),
    10: ("mismatched with the configuration", DOWN),
    11: ("diagnostics failed", DOWN),
    12: ("dormant", TRANSITIONAL),
    13: ("out of service (admin)", ADMIN_DOWN),
    14: ("out of service (temperature)", DOWN),
    15: ("powered down", DOWN),
    16: ("powered up", TRANSITIONAL),
    17: ("power denied", DOWN),
    18: ("power cycling", TRANSITIONAL),
    19: ("ok, power over warning", OK),
    20: ("ok, power over critical", OK),
    21: ("syncing", TRANSITIONAL),
    22: ("upgrading", TRANSITIONAL),
    23: ("ok, authentication failed", OK),
    24: ("in minimal disruptive restart", TRANSITIONAL),
    25: ("firmware mismatch", DOWN),
    26: ("firmware downloaded", TRANSITIONAL),
    27: ("firmware download failed", DOWN),
}
# ModuleAdminType: disabled(2), outOfServiceAdmin(4). A down module whose
# admin status is one of these was taken down by an operator.
CISCO_ADMIN_OFF = frozenset({2, 4})

# ── Juniper: JUNIPER-MIB jnxFruTable ────────────────────────────────────────

JNX_FRU_NAME = "1.3.6.1.4.1.2636.3.1.15.1.5"
JNX_FRU_TYPE = "1.3.6.1.4.1.2636.3.1.15.1.6"
JNX_FRU_STATE = "1.3.6.1.4.1.2636.3.1.15.1.8"
JNX_FRU_OFFLINE_REASON = "1.3.6.1.4.1.2636.3.1.15.1.10"

# jnxFruState: (label, class).
#   unknown(1)         not known: neither raise nor clear
#   empty(2)           nothing in the slot: not a module (left out)
#   present(3), ready(4), announceOnline(5)   on the way online
#   online(6)          operational
#   anounceOffline(7)  on the way offline
#   offline(8)         offline; an operator's offline is told apart by
#                      jnxFruOfflineReason (below)
#   diagnostic(9)      in diagnostic mode
#   standby(10)        a healthy standby (routing engine, control board)
JUNIPER_FRU_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    3: ("present", TRANSITIONAL),
    4: ("ready", TRANSITIONAL),
    5: ("coming online", TRANSITIONAL),
    6: ("online", OK),
    7: ("going offline", TRANSITIONAL),
    8: ("offline", DOWN),
    9: ("in diagnostics", TRANSITIONAL),
    10: ("standby", OK),
}
JUNIPER_FRU_EMPTY = 2
# jnxFruType values that are modules: FPC(3), SFM(4), control board(5),
# routing engine(6), SIB(9), SPMB(10), PIC(11), line card chassis(14),
# FEB(15), SFB(19), adapter card(20).
JUNIPER_MODULE_TYPES = frozenset({3, 4, 5, 6, 9, 10, 11, 14, 15, 19, 20})
# The power FRUs: powerEntryModule(7), powerDistributionUnit(17),
# powerSupplyModule(18); and fan(13). Read by environment_health.
JUNIPER_POWER_TYPES = frozenset({7, 17, 18})
JUNIPER_FAN_TYPES = frozenset({13})
# jnxFruOfflineReason values that mean an operator took the FRU offline:
# configPowerOff(5), configHoldInReset(6), cliCommand(7), buttonPress(8),
# fruConfigOffline(34).
JUNIPER_ADMIN_OFFLINE = frozenset({5, 6, 7, 8, 34})


def _juniper_kind(values: dict[str, Any]) -> str | None:
    fru_type = snmp_int(values.get(JNX_FRU_TYPE))
    if fru_type in JUNIPER_MODULE_TYPES:
        return KIND_MODULE
    if fru_type in JUNIPER_POWER_TYPES:
        return KIND_POWER
    if fru_type in JUNIPER_FAN_TYPES:
        return KIND_FAN
    return None


CISCO = TableSource(
    key="cisco_entity_fru",
    vendor="Cisco",
    state_oid=CEFC_MODULE_OPER_STATUS,
    states=CISCO_OPER_STATES,
    kinds=frozenset({KIND_MODULE}),
    detail_oids=(ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR, ENT_PHYSICAL_MODEL, CEFC_MODULE_ADMIN_STATUS),
    admin_off=lambda v: snmp_int(v.get(CEFC_MODULE_ADMIN_STATUS)) in CISCO_ADMIN_OFF,
    name=sh.entity_name,
    model=lambda v: sh.text(v.get(ENT_PHYSICAL_MODEL)),
)

# One read of the FRU table serves the module, power supply and fan checks.
JUNIPER = TableSource(
    key="juniper_fru",
    vendor="Juniper",
    state_oid=JNX_FRU_STATE,
    states=JUNIPER_FRU_STATES,
    kinds=frozenset({KIND_MODULE, KIND_POWER, KIND_FAN}),
    absent=frozenset({JUNIPER_FRU_EMPTY}),
    filter_oids=(JNX_FRU_TYPE,),
    kind_of=_juniper_kind,
    detail_oids=(JNX_FRU_NAME, JNX_FRU_OFFLINE_REASON),
    admin_off=lambda v: snmp_int(v.get(JNX_FRU_OFFLINE_REASON)) in JUNIPER_ADMIN_OFFLINE,
    name=lambda v: sh.text(v.get(JNX_FRU_NAME)),
)

# The device types whose modules the poll reads. Any other type is not read
# (no SNMP request at all).
DEVICE_SOURCES: dict[str, TableSource] = {
    "cisco_ios": CISCO,
    "cisco_xe": CISCO,
    "cisco_nxos": CISCO,
    "cisco_xr": CISCO,
    "juniper": JUNIPER,
    "juniper_junos": JUNIPER,
}


def source_for_device(device_type: str | None) -> TableSource | None:
    """The module status table of a device type, None when it is not read."""
    return DEVICE_SOURCES.get(str(device_type or "").strip().lower())


def parse_module_status(source: TableSource, state_rows: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """The module state of a device from its walked status column
    (``{oid: value}``) and the GET answers of the per-row objects
    (``{instance oid: value}``). ``{}`` when the walk returned no row
    (nothing read). Each module: ``index``, ``name``, ``model``, ``status``
    (its state's label), ``state`` (the raw value) and ``class``."""
    return sh.select(CHECK, sh.parse_table(source, state_rows, values))


async def read_module_status(source: TableSource, get: Get, walk: Walk) -> dict[str, Any]:
    """Read and parse a device's module state with the monitoring poll's SNMP
    requests (see :func:`netcontrol.snmp_health.read_table`). ``{}`` when
    the table was not read or had no row: whether an empty table counts as
    "no modules" is the poll's decision (``health_checks``)."""
    table = await sh.read_table(source, get, walk)
    return {} if table is None or sh.is_empty(table) else sh.select(CHECK, table)


def alert_dedup_key(host_id: int, index: str) -> str:
    """The dedup key of one module's alert."""
    return sh.alert_dedup_key(CHECK, host_id, index)


def module_alert_checks(host_id: int, status: dict[str, Any]) -> list[dict[str, Any]]:
    """The built-in alerts a module state raises, one per module down."""
    return sh.alert_checks(CHECK, host_id, status)


def module_cleared_keys(host_id: int, status: dict[str, Any], open_keys: list[str]) -> list[str]:
    """Of a host's open module alerts, the ones a poll's module state clears."""
    return sh.cleared_keys(CHECK, host_id, status, open_keys)


def module_down_count(status: dict[str, Any] | None) -> float | None:
    """The number of modules classed down; None when the poll read no table."""
    return sh.down_count(status)
