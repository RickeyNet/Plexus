"""Power supply, fan and temperature state read by the monitoring poll.

Three checks on the shared ``snmp_health`` shape: ``power_supply_down``
(critical, as the built-in power supply syslog rule), ``fan_down``
(warning, as the fan syslog rule) and ``temperature_alarm`` (warning or
critical as the device's own sensor state or threshold says). One alert per
supply, fan or fan tray, or sensor, resolved when it reads OK, is disabled
by an operator, or is gone from a table the poll read completely. Which
tables a device type reads is ``health_checks.DEVICE_PLANS``.

Sources, each checked against the MIB text (OIDs worked out from the
MODULE-IDENTITY and OBJECT IDENTIFIER chain of the module):

  CISCO-ENVMON-MIB (ciscoEnvMonMIB 1.3.6.1.4.1.9.9.13), CiscoEnvMonState
  normal(1) warning(2) critical(3) shutdown(4) notPresent(5) notFunctioning(6):
    ciscoEnvMonSupplyState        .1.5.1.3   ciscoEnvMonSupplyStatusDescr  .1.5.1.2
    ciscoEnvMonFanState           .1.4.1.3   ciscoEnvMonFanStatusDescr     .1.4.1.2
    ciscoEnvMonTemperatureState   .1.3.1.6   ciscoEnvMonTemperatureStatusDescr .1.3.1.2,
                                             ciscoEnvMonTemperatureStatusValue .1.3.1.3
  CISCO-ENTITY-FRU-CONTROL-MIB (1.3.6.1.4.1.9.9.117), where ENVMON has no rows:
    cefcFRUPowerAdminStatus .1.1.2.1.1  PowerAdminType (off(2))
    cefcFRUPowerOperStatus  .1.1.2.1.2  PowerOperType; the table lists every
                                        power-controllable entity, so the rows not
                                        on are kept only when entPhysicalClass is
                                        powerSupply(6)
    cefcFanTrayOperStatus   .1.4.1.1.1  unknown(1) up(2) down(3) warning(4)
  CISCO-ENTITY-SENSOR-MIB (1.3.6.1.4.1.9.9.91), temperature where ENVMON has
  no rows (NX-OS, IOS XR, ASA, FTD):
    entSensorType                 .1.1.1.1.1  celsius(8)
    entSensorThresholdSeverity    .1.2.1.1.2  minor(10) major(20) critical(30)
    entSensorThresholdEvaluation  .1.2.1.1.5  true(1) / false(2)
  ENTITY-STATE-MIB (RFC 4268, 1.3.6.1.2.1.131), with ENTITY-MIB entPhysicalClass
  and ENTITY-SENSOR-MIB (RFC 3433) entPhySensorType 1.3.6.1.2.1.99.1.1.1.1:
    entStateAdmin  .1.1.1.2  locked(2)
    entStateOper   .1.1.1.3  unknown(1) disabled(2) enabled(3) testing(4)
    entStateAlarm  .1.1.1.5  BITS critical(2) major(3) minor(4) warning(5)
  ARISTA-ENTITY-SENSOR-MIB (aristaEntSensorMIB 1.3.6.1.4.1.30065.3.12):
    aristaFanStateOper  .1.2.1.2  unknown(1) disabled(2) enabled(3) testing(4)
                                  notInstalled(5)
  FORTINET-FORTIGATE-MIB (fnFortiGateMib 1.3.6.1.4.1.12356.101):
    fgHwSensorEntName         .4.3.2.1.2
    fgHwSensorEntAlarmStatus  .4.3.2.1.4  false(0) true(1)
  HP-ICF-CHASSIS (hpicfChassis 1.3.6.1.4.1.11.2.14.11.1.2):
    hpicfSensorObjectId  .6.1.2  HP-ICF-OID icfPowerSupplySensor
                                 1.3.6.1.4.1.11.2.3.7.8.3.1, icfFanSensor .3.2,
                                 icfTemperatureSensor .3.3
    hpicfSensorStatus    .6.1.4  unknown(1) bad(2) warning(3) good(4) notPresent(5)
    hpicfSensorDescr     .6.1.7
  ARUBAWIRED-POWERSUPPLY-MIB / ARUBAWIRED-FAN-MIB (arubaWiredChassisMIB
  1.3.6.1.4.1.47196.4.1.1.3.11):
    arubaWiredPSUName       .2.1.1.3   arubaWiredPSUStateEnum  .2.1.1.11
    arubaWiredFanName       .5.1.1.4   arubaWiredFanStateEnum  .5.1.1.10
  NETGEAR-BOXSERVICES-PRIVATE-MIB (fastPathBoxServices 1.3.6.1.4.1.4526.10.43):
    boxServicesFanItemState        .1.6.1.3
    boxServicesPowSupplyItemState  .1.7.1.3
    boxServicesTempSensorState     .1.8.1.4

Not read (docs/vendor-monitoring-coverage.md): Juniper temperature
(JUNIPER-MIB gives readings, no per-sensor threshold or state), AOS-CX
temperature (arubaWiredTempSensorState is a free string the MIB does not
enumerate), Aruba Instant On and Netgear smart switches (no MIB reference
for their tables), APC (its own reader), OPNsense (temperature read over
its API).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from netcontrol import module_health, snmp_health as sh
from netcontrol.routes.snmp import oid_sort_key, snmp_int
from netcontrol.snmp_health import (
    ADMIN_DOWN,
    DOWN,
    ENT_PHYSICAL_CLASS,
    ENT_PHYSICAL_DESCR,
    ENT_PHYSICAL_MODEL,
    ENT_PHYSICAL_NAME,
    OK,
    TRANSITIONAL,
    HealthCheck,
    TableSource,
)

KIND_POWER = module_health.KIND_POWER
KIND_FAN = module_health.KIND_FAN
KIND_TEMPERATURE = "temperature"

POWER = HealthCheck(
    metric="power_supply_down",
    result_key="power_supply_health",
    kind=KIND_POWER,
    severity="critical",
    noun="Power supply",
)
FAN = HealthCheck(
    metric="fan_down",
    result_key="fan_health",
    kind=KIND_FAN,
    severity="warning",
    noun="Fan",
)
TEMPERATURE = HealthCheck(
    metric="temperature_alarm",
    result_key="temperature_health",
    kind=KIND_TEMPERATURE,
    severity="warning",
    noun="Temperature sensor",
    severity_from_device=True,
)
CHECKS = (POWER, FAN, TEMPERATURE)

_ENTITY_NAMES = (ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR, ENT_PHYSICAL_MODEL)


def _entity_model(values: dict[str, Any]) -> str:
    return sh.text(values.get(ENT_PHYSICAL_MODEL))


# ── Cisco: CISCO-ENVMON-MIB ─────────────────────────────────────────────────

ENVMON_TEMPERATURE_DESCR = "1.3.6.1.4.1.9.9.13.1.3.1.2"
ENVMON_TEMPERATURE_VALUE = "1.3.6.1.4.1.9.9.13.1.3.1.3"
ENVMON_TEMPERATURE_STATE = "1.3.6.1.4.1.9.9.13.1.3.1.6"
ENVMON_FAN_DESCR = "1.3.6.1.4.1.9.9.13.1.4.1.2"
ENVMON_FAN_STATE = "1.3.6.1.4.1.9.9.13.1.4.1.3"
ENVMON_SUPPLY_DESCR = "1.3.6.1.4.1.9.9.13.1.5.1.2"
ENVMON_SUPPLY_STATE = "1.3.6.1.4.1.9.9.13.1.5.1.3"

# CiscoEnvMonState for a supply or a fan: anything but normal is a fault;
# notPresent(5) is an empty bay (not an item).
ENVMON_STATES: dict[int, tuple[str, str]] = {
    1: ("normal", OK),
    2: ("warning", DOWN),
    3: ("critical", DOWN),
    4: ("shutdown", DOWN),
    6: ("not functioning", DOWN),
}
# For a temperature sensor notFunctioning(6) is a broken sensor, not a
# temperature: neither raise nor clear.
ENVMON_TEMPERATURE_STATES = {**ENVMON_STATES, 6: ("not functioning", TRANSITIONAL)}
ENVMON_TEMPERATURE_SEVERITIES = {2: "warning", 3: "critical", 4: "critical"}
ENVMON_NOT_PRESENT = frozenset({5})


def _celsius(raw: Any) -> str:
    value = snmp_int(raw)
    return f"{value} C" if value is not None else ""


CISCO_ENVMON_SUPPLY = TableSource(
    key="cisco_envmon_supply",
    vendor="Cisco",
    state_oid=ENVMON_SUPPLY_STATE,
    states=ENVMON_STATES,
    kinds=frozenset({KIND_POWER}),
    absent=ENVMON_NOT_PRESENT,
    detail_oids=(ENVMON_SUPPLY_DESCR,),
    name=lambda v: sh.text(v.get(ENVMON_SUPPLY_DESCR)),
)
CISCO_ENVMON_FAN = TableSource(
    key="cisco_envmon_fan",
    vendor="Cisco",
    state_oid=ENVMON_FAN_STATE,
    states=ENVMON_STATES,
    kinds=frozenset({KIND_FAN}),
    absent=ENVMON_NOT_PRESENT,
    detail_oids=(ENVMON_FAN_DESCR,),
    name=lambda v: sh.text(v.get(ENVMON_FAN_DESCR)),
)
CISCO_ENVMON_TEMPERATURE = TableSource(
    key="cisco_envmon_temperature",
    vendor="Cisco",
    state_oid=ENVMON_TEMPERATURE_STATE,
    states=ENVMON_TEMPERATURE_STATES,
    kinds=frozenset({KIND_TEMPERATURE}),
    absent=ENVMON_NOT_PRESENT,
    detail_oids=(ENVMON_TEMPERATURE_DESCR, ENVMON_TEMPERATURE_VALUE),
    name=lambda v: sh.text(v.get(ENVMON_TEMPERATURE_DESCR)),
    model=lambda v: _celsius(v.get(ENVMON_TEMPERATURE_VALUE)),
    severities=ENVMON_TEMPERATURE_SEVERITIES,
)

# ── Cisco: CISCO-ENTITY-FRU-CONTROL-MIB ─────────────────────────────────────

CEFC_FRU_POWER_ADMIN = "1.3.6.1.4.1.9.9.117.1.1.2.1.1"
CEFC_FRU_POWER_OPER = "1.3.6.1.4.1.9.9.117.1.1.2.1.2"
CEFC_FAN_TRAY_OPER = "1.3.6.1.4.1.9.9.117.1.4.1.1.1"

# PowerOperType: on(2) is the only state of a working supply; offAdmin(3)
# is an operator's; every other value is off or degraded for a reason
# (offEnvOther(1), offDenied(4), offEnvPower(5), offEnvTemp(6),
# offEnvFan(7), failed(8), onButFanFail(9), offCooling(10),
# offConnectorRating(11), onButInlinePowerFail(12)).
CEFC_POWER_STATES: dict[int, tuple[str, str]] = {
    1: ("off (environment)", DOWN),
    2: ("on", OK),
    3: ("off (admin)", ADMIN_DOWN),
    4: ("off (power denied)", DOWN),
    5: ("off (power problem)", DOWN),
    6: ("off (temperature)", DOWN),
    7: ("off (fan problem)", DOWN),
    8: ("failed", DOWN),
    9: ("on, fan failed", DOWN),
    10: ("off (cooling)", DOWN),
    11: ("off (connector rating)", DOWN),
    12: ("on, inline power failed", DOWN),
}
# PowerAdminType off(2): an operator turned it off.
CEFC_POWER_ADMIN_OFF = 2
CEFC_FAN_TRAY_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("up", OK),
    3: ("down", DOWN),
    4: ("partially failed", DOWN),
}


def _entity_kind(*, power: bool = False, fan: bool = False):
    """A row's kind from its entPhysicalClass."""

    def kind_of(values: dict[str, Any]) -> str | None:
        klass = snmp_int(values.get(ENT_PHYSICAL_CLASS))
        if power and klass == sh.PHYSICAL_CLASS_POWER_SUPPLY:
            return KIND_POWER
        if fan and klass == sh.PHYSICAL_CLASS_FAN:
            return KIND_FAN
        return None

    return kind_of


CISCO_FRU_POWER = TableSource(
    key="cisco_entity_fru_power",
    vendor="Cisco",
    state_oid=CEFC_FRU_POWER_OPER,
    states=CEFC_POWER_STATES,
    kinds=frozenset({KIND_POWER}),
    filter_oids=(ENT_PHYSICAL_CLASS,),
    filter_ok_rows=False,
    kind_of=_entity_kind(power=True),
    detail_oids=(*_ENTITY_NAMES, CEFC_FRU_POWER_ADMIN),
    admin_off=lambda v: snmp_int(v.get(CEFC_FRU_POWER_ADMIN)) == CEFC_POWER_ADMIN_OFF,
    name=sh.entity_name,
    model=_entity_model,
)
CISCO_FAN_TRAY = TableSource(
    key="cisco_entity_fru_fan",
    vendor="Cisco",
    state_oid=CEFC_FAN_TRAY_OPER,
    states=CEFC_FAN_TRAY_STATES,
    kinds=frozenset({KIND_FAN}),
    detail_oids=_ENTITY_NAMES,
    name=sh.entity_name,
    model=_entity_model,
)

# ── Cisco: CISCO-ENTITY-SENSOR-MIB thresholds ───────────────────────────────

ENT_SENSOR_TYPE = "1.3.6.1.4.1.9.9.91.1.1.1.1.1"
ENT_SENSOR_THRESHOLD_SEVERITY = "1.3.6.1.4.1.9.9.91.1.2.1.1.2"
ENT_SENSOR_THRESHOLD_EVALUATION = "1.3.6.1.4.1.9.9.91.1.2.1.1.5"
SENSOR_TYPE_CELSIUS = 8
THRESHOLD_TRUE = 1
# SensorThresholdSeverity: minor(10) is a warning; major(20) and
# critical(30) are critical; other(1) is taken as a warning.
SENSOR_STATES: dict[int, tuple[str, str]] = {
    0: ("normal", OK),
    1: ("over a threshold", DOWN),
    10: ("over its minor threshold", DOWN),
    20: ("over its major threshold", DOWN),
    30: ("over its critical threshold", DOWN),
}
SENSOR_SEVERITIES = {1: "warning", 10: "warning", 20: "critical", 30: "critical"}


@dataclass(frozen=True)
class CiscoSensorThresholds:
    """The temperature sensors of entSensorThresholdTable: a sensor is in
    alarm while one of its thresholds evaluates true, at the highest
    severity among them. One walk of the evaluation column; then, only for
    the sensors with a threshold true, their type and those thresholds'
    severities, then the names of the celsius ones."""

    key: str = "cisco_entity_sensor"
    vendor: str = "Cisco"
    kinds: frozenset[str] = frozenset({KIND_TEMPERATURE})

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, ENT_SENSOR_THRESHOLD_EVALUATION)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, ENT_SENSOR_THRESHOLD_EVALUATION)
        if not rows:
            return sh.empty_table(self.key, self.vendor)
        true_rows: dict[str, list[str]] = {}
        sensors: list[str] = []
        for index, raw in sorted(rows.items(), key=lambda kv: oid_sort_key(kv[0])):
            sensor, _, _threshold = index.partition(".")
            if sensor not in sensors:
                sensors.append(sensor)
            if snmp_int(raw) == THRESHOLD_TRUE:
                true_rows.setdefault(sensor, []).append(index)
        wanted = [f"{ENT_SENSOR_TYPE}.{s}" for s in true_rows]
        wanted += [f"{ENT_SENSOR_THRESHOLD_SEVERITY}.{i}" for indices in true_rows.values() for i in indices]
        values: dict[str, Any] = {}
        if wanted:
            answers = await sh.get_all(get, wanted)
            if answers is None:
                return None
            values.update(answers)
        states: dict[str, int] = {}
        for sensor in sensors:
            if sensor not in true_rows:
                continue  # all thresholds false: OK (and of a type not read)
            if snmp_int(values.get(f"{ENT_SENSOR_TYPE}.{sensor}")) != SENSOR_TYPE_CELSIUS:
                continue
            severities = [snmp_int(values.get(f"{ENT_SENSOR_THRESHOLD_SEVERITY}.{i}")) for i in true_rows[sensor]]
            known = [s for s in severities if s in SENSOR_SEVERITIES]
            states[sensor] = max(known) if known else 1
        names = [f"{oid}.{s}" for s in states for oid in (ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR)]
        if names:
            values.update(await sh.get_all(get, names) or {})
        items = []
        for sensor in sensors:
            if sensor in true_rows and sensor not in states:
                continue  # in alarm, not a temperature sensor
            state = states.get(sensor, 0)
            label, klass = SENSOR_STATES[state]
            items.append(
                {
                    "index": sensor,
                    "kind": KIND_TEMPERATURE,
                    "name": sh.entity_name(sh.instance_values((ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR), sensor, values)),
                    "model": "",
                    "status": label,
                    "state": state,
                    "class": klass,
                    "severity": SENSOR_SEVERITIES.get(state),
                }
            )
        return {"source": self.key, "vendor": self.vendor, "items": items}


CISCO_SENSOR_THRESHOLDS = CiscoSensorThresholds()

# ── ENTITY-STATE-MIB (Arista, PAN-OS) ───────────────────────────────────────

ENT_STATE_ADMIN = "1.3.6.1.2.1.131.1.1.1.2"
ENT_STATE_OPER = "1.3.6.1.2.1.131.1.1.1.3"
ENT_STATE_ALARM = "1.3.6.1.2.1.131.1.1.1.5"
ENT_PHY_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
# EntityAdminState locked(2): an operator took it out of service.
ENT_STATE_LOCKED = 2
ENT_OPER_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("disabled", DOWN),
    3: ("enabled", OK),
    4: ("testing", TRANSITIONAL),
}

# EntityAlarmStatus BITS (bit 0 is the high bit of the first octet):
# unknown(0) underRepair(1) critical(2) major(3) minor(4) warning(5)
# indeterminate(6). Read as a state: 3 critical or major, 2 minor or
# warning, 0 only unknown / indeterminate, 1 none of those (normal).
_ALARM_BIT_CRITICAL = (0x20, 0x10)
_ALARM_BIT_WARNING = (0x08, 0x04)
_ALARM_BIT_UNKNOWN = (0x80, 0x02)
ALARM_STATES: dict[int, tuple[str, str]] = {
    0: ("alarm state unknown", TRANSITIONAL),
    1: ("normal", OK),
    2: ("in a warning alarm", DOWN),
    3: ("in a critical alarm", DOWN),
}
ALARM_SEVERITIES = {2: "warning", 3: "critical"}


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


def alarm_state(raw: Any) -> int | None:
    """An entStateAlarm value as one of ``ALARM_STATES``."""
    data = octets(raw)
    if data is None:
        return None
    first = data[0] if data else 0
    if any(first & bit for bit in _ALARM_BIT_CRITICAL):
        return 3
    if any(first & bit for bit in _ALARM_BIT_WARNING):
        return 2
    if any(first & bit for bit in _ALARM_BIT_UNKNOWN):
        return 0
    return 1


def _entity_state(kinds: frozenset[str]) -> TableSource:
    return TableSource(
        key="entity_state_oper",
        vendor="ENTITY-STATE-MIB",
        state_oid=ENT_STATE_OPER,
        states=ENT_OPER_STATES,
        kinds=kinds,
        filter_oids=(ENT_PHYSICAL_CLASS,),
        filter_ok_rows=False,
        kind_of=_entity_kind(power=KIND_POWER in kinds, fan=KIND_FAN in kinds),
        detail_oids=(*_ENTITY_NAMES, ENT_STATE_ADMIN),
        admin_off=lambda v: snmp_int(v.get(ENT_STATE_ADMIN)) == ENT_STATE_LOCKED,
        name=sh.entity_name,
        model=_entity_model,
    )


ENTITY_STATE_POWER_FAN = _entity_state(frozenset({KIND_POWER, KIND_FAN}))
ENTITY_STATE_POWER = _entity_state(frozenset({KIND_POWER}))


def _celsius_sensor(values: dict[str, Any]) -> str | None:
    klass = snmp_int(values.get(ENT_PHYSICAL_CLASS))
    celsius = snmp_int(values.get(ENT_PHY_SENSOR_TYPE)) == SENSOR_TYPE_CELSIUS
    return KIND_TEMPERATURE if klass == sh.PHYSICAL_CLASS_SENSOR and celsius else None


ENTITY_STATE_TEMPERATURE = TableSource(
    key="entity_state_alarm",
    vendor="ENTITY-STATE-MIB",
    state_oid=ENT_STATE_ALARM,
    states=ALARM_STATES,
    kinds=frozenset({KIND_TEMPERATURE}),
    filter_oids=(ENT_PHYSICAL_CLASS, ENT_PHY_SENSOR_TYPE),
    filter_ok_rows=False,
    kind_of=_celsius_sensor,
    detail_oids=(ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR),
    name=sh.entity_name,
    severities=ALARM_SEVERITIES,
    state_of=alarm_state,
)

# ── Arista: ARISTA-ENTITY-SENSOR-MIB aristaFanStateTable ────────────────────

ARISTA_FAN_STATE = "1.3.6.1.4.1.30065.3.12.1.2.1.2"
ARISTA_FAN_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("disabled", DOWN),
    3: ("enabled", OK),
    4: ("testing", TRANSITIONAL),
}
ARISTA_FAN_NOT_INSTALLED = frozenset({5})

ARISTA_FAN = TableSource(
    key="arista_fan_state",
    vendor="Arista",
    state_oid=ARISTA_FAN_STATE,
    states=ARISTA_FAN_STATES,
    kinds=frozenset({KIND_FAN}),
    absent=ARISTA_FAN_NOT_INSTALLED,
    detail_oids=_ENTITY_NAMES,
    name=sh.entity_name,
    model=_entity_model,
)

# ── Fortinet: FORTINET-FORTIGATE-MIB fgHwSensorTable ────────────────────────

FG_HW_SENSOR_NAME = "1.3.6.1.4.1.12356.101.4.3.2.1.2"
FG_HW_SENSOR_ALARM = "1.3.6.1.4.1.12356.101.4.3.2.1.4"
FG_ALARM_STATES: dict[int, tuple[str, str]] = {0: ("normal", OK), 1: ("in alarm", DOWN)}

# The table gives a name, a reading and an alarm flag per sensor, and no
# type: the kind of a sensor in alarm is told from its name. A fan sensor
# of a power supply ("PS1 Fan 1") is a fan; voltage and other sensors are
# none of the three.
_FG_FAN = re.compile(r"\bfan", re.IGNORECASE)
_FG_POWER = re.compile(r"\bps\s?\d|\bpsu|power supply", re.IGNORECASE)
_FG_TEMPERATURE = re.compile(r"temp|\bdts\b|thermal", re.IGNORECASE)


def fortinet_sensor_kind(values: dict[str, Any]) -> str | None:
    name = sh.text(values.get(FG_HW_SENSOR_NAME))
    if _FG_FAN.search(name):
        return KIND_FAN
    if _FG_TEMPERATURE.search(name):
        return KIND_TEMPERATURE
    if _FG_POWER.search(name):
        return KIND_POWER
    return None


FORTINET_SENSORS = TableSource(
    key="fortinet_hw_sensor",
    vendor="Fortinet",
    state_oid=FG_HW_SENSOR_ALARM,
    states=FG_ALARM_STATES,
    kinds=frozenset({KIND_POWER, KIND_FAN, KIND_TEMPERATURE}),
    filter_oids=(FG_HW_SENSOR_NAME,),
    filter_ok_rows=False,
    kind_of=fortinet_sensor_kind,
    name=lambda v: sh.text(v.get(FG_HW_SENSOR_NAME)),
)

# ── HPE Aruba AOS-Switch: HP-ICF-CHASSIS hpicfSensorTable ───────────────────

HP_SENSOR_OBJECT_ID = "1.3.6.1.4.1.11.2.14.11.1.2.6.1.2"
HP_SENSOR_STATUS = "1.3.6.1.4.1.11.2.14.11.1.2.6.1.4"
HP_SENSOR_DESCR = "1.3.6.1.4.1.11.2.14.11.1.2.6.1.7"
# HP-ICF-OID icfSensors 1.3.6.1.4.1.11.2.3.7.8.3: power supply(1), fan(2),
# temperature(3).
HP_SENSOR_KINDS = {
    "1.3.6.1.4.1.11.2.3.7.8.3.1": KIND_POWER,
    "1.3.6.1.4.1.11.2.3.7.8.3.2": KIND_FAN,
    "1.3.6.1.4.1.11.2.3.7.8.3.3": KIND_TEMPERATURE,
}
HP_SENSOR_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    2: ("bad", DOWN),
    3: ("warning", DOWN),
    4: ("good", OK),
}
HP_SENSOR_NOT_PRESENT = frozenset({5})

AOS_SWITCH_SENSORS = TableSource(
    key="hp_icf_sensor",
    vendor="HPE Aruba",
    state_oid=HP_SENSOR_STATUS,
    states=HP_SENSOR_STATES,
    kinds=frozenset({KIND_POWER, KIND_FAN, KIND_TEMPERATURE}),
    absent=HP_SENSOR_NOT_PRESENT,
    filter_oids=(HP_SENSOR_OBJECT_ID,),
    filter_ok_rows=False,
    kind_of=lambda v: HP_SENSOR_KINDS.get(sh.text(v.get(HP_SENSOR_OBJECT_ID)).lstrip(".")),
    detail_oids=(HP_SENSOR_DESCR,),
    name=lambda v: sh.text(v.get(HP_SENSOR_DESCR)),
    severities={2: "critical", 3: "warning"},
)

# ── HPE Aruba AOS-CX: ARUBAWIRED-POWERSUPPLY-MIB, ARUBAWIRED-FAN-MIB ────────

AOSCX_PSU_NAME = "1.3.6.1.4.1.47196.4.1.1.3.11.2.1.1.3"
AOSCX_PSU_STATE = "1.3.6.1.4.1.47196.4.1.1.3.11.2.1.1.11"
AOSCX_FAN_NAME = "1.3.6.1.4.1.47196.4.1.1.3.11.5.1.1.4"
AOSCX_FAN_STATE = "1.3.6.1.4.1.47196.4.1.1.3.11.5.1.1.10"
# arubaWiredPSUStateEnum: ok(1); faultAbsent(2) and empty(12) are taken as
# an empty bay (not an item); unknown(8) and init(11) are passing; every
# other value (faultInput, faultOutput, faultPOE, faultNoRecov, alert,
# unsupported, warning, faultAirflow, faultRedundancy, faultMixedInput,
# overvoltage, undervoltage) is a fault.
AOSCX_PSU_STATES: dict[int, tuple[str, str]] = {
    1: ("ok", OK),
    3: ("input fault", DOWN),
    4: ("output fault", DOWN),
    5: ("PoE fault", DOWN),
    6: ("unrecoverable fault", DOWN),
    7: ("alert", DOWN),
    8: ("unknown", TRANSITIONAL),
    9: ("unsupported", DOWN),
    10: ("warning", DOWN),
    11: ("initializing", TRANSITIONAL),
    13: ("airflow fault", DOWN),
    14: ("redundancy fault", DOWN),
    15: ("mixed input fault", DOWN),
    16: ("overvoltage", DOWN),
    17: ("undervoltage", DOWN),
}
# arubaWiredFanStateEnum: unknown(1) empty(2) uninitialized(3) ok(4) fault(5).
AOSCX_FAN_STATES: dict[int, tuple[str, str]] = {
    1: ("unknown", TRANSITIONAL),
    3: ("uninitialized", TRANSITIONAL),
    4: ("ok", OK),
    5: ("fault", DOWN),
}

AOSCX_POWER = TableSource(
    key="aoscx_power_supply",
    vendor="HPE Aruba",
    state_oid=AOSCX_PSU_STATE,
    states=AOSCX_PSU_STATES,
    kinds=frozenset({KIND_POWER}),
    absent=frozenset({2, 12}),
    detail_oids=(AOSCX_PSU_NAME,),
    name=lambda v: sh.text(v.get(AOSCX_PSU_NAME)),
)
AOSCX_FAN = TableSource(
    key="aoscx_fan",
    vendor="HPE Aruba",
    state_oid=AOSCX_FAN_STATE,
    states=AOSCX_FAN_STATES,
    kinds=frozenset({KIND_FAN}),
    absent=frozenset({2}),
    detail_oids=(AOSCX_FAN_NAME,),
    name=lambda v: sh.text(v.get(AOSCX_FAN_NAME)),
)

# ── Netgear managed switches: NETGEAR-BOXSERVICES-PRIVATE-MIB ───────────────

NETGEAR_FAN_STATE = "1.3.6.1.4.1.4526.10.43.1.6.1.3"
NETGEAR_PSU_STATE = "1.3.6.1.4.1.4526.10.43.1.7.1.3"
NETGEAR_TEMP_STATE = "1.3.6.1.4.1.4526.10.43.1.8.1.4"
# boxServicesFanItemState / boxServicesPowSupplyItemState: notpresent(1)
# operational(2) failed(3) powering(4) nopower(5: present, no AC)
# notpowering(6) incompatible(7).
NETGEAR_ITEM_STATES: dict[int, tuple[str, str]] = {
    2: ("operational", OK),
    3: ("failed", DOWN),
    4: ("powering", OK),
    5: ("no input power", DOWN),
    6: ("not powering", DOWN),
    7: ("incompatible", DOWN),
}
# BoxsTemperatureStatus: low(0) normal(1) warning(2) critical(3)
# shutdown(4) notpresent(5) notoperational(6).
NETGEAR_TEMP_STATES: dict[int, tuple[str, str]] = {
    0: ("below its range", DOWN),
    1: ("normal", OK),
    2: ("warning", DOWN),
    3: ("critical", DOWN),
    4: ("shutdown", DOWN),
    6: ("not operational", TRANSITIONAL),
}


def _unit_name(noun: str):
    """Names a row indexed by unit and item number: ``"Fan 2 (unit 1)"``."""

    def name(index: str) -> str:
        unit, _, item = index.partition(".")
        return f"{noun} {item} (unit {unit})" if item else f"{noun} {unit}"

    return name


NETGEAR_FAN = TableSource(
    key="netgear_box_fan",
    vendor="Netgear",
    state_oid=NETGEAR_FAN_STATE,
    states=NETGEAR_ITEM_STATES,
    kinds=frozenset({KIND_FAN}),
    absent=frozenset({1}),
    index_name=_unit_name("Fan"),
)
NETGEAR_POWER = TableSource(
    key="netgear_box_power",
    vendor="Netgear",
    state_oid=NETGEAR_PSU_STATE,
    states=NETGEAR_ITEM_STATES,
    kinds=frozenset({KIND_POWER}),
    absent=frozenset({1}),
    index_name=_unit_name("Power supply"),
)
NETGEAR_TEMPERATURE = TableSource(
    key="netgear_box_temperature",
    vendor="Netgear",
    state_oid=NETGEAR_TEMP_STATE,
    states=NETGEAR_TEMP_STATES,
    kinds=frozenset({KIND_TEMPERATURE}),
    absent=frozenset({5}),
    index_name=_unit_name("Temperature sensor"),
    severities={0: "warning", 2: "warning", 3: "critical", 4: "critical"},
)
