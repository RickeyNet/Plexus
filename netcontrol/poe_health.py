"""Power over Ethernet state read by the monitoring poll.

Three checks on the shared ``snmp_health`` shape, from the standard
POWER-ETHERNET-MIB (RFC 3621, any SNMP-polled switch that implements it):

* ``poe_port_fault`` (warning): a PoE port whose detection reads
  ``fault(4)`` or ``otherFault(6)``, one alert per port. A port with PoE
  disabled (``pethPsePortAdminEnable`` false, or detection ``disabled(1)``)
  is not an alert and resolves one; ``searching(2)`` (nothing powered) and
  ``deliveringPower(3)`` are OK; ``test(5)`` neither raises nor resolves.
* ``poe_supply_down`` (critical): a power source (``pethMainPseTable``, one
  row per stack member or module) whose operational status is
  ``faulty(3)``: every powered device on it may lose power. ``off(2)`` is
  not an alert (a source switched off, or with no power for PoE).
* ``poe_budget_high`` (warning): a power source that is on and whose
  measured consumption has reached its usage threshold: the device's own
  ``pethMainPseUsageThreshold`` (percent of the nominal power) where it
  answers one, else ``DEFAULT_USAGE_THRESHOLD`` (90%). The alert's value is
  the percent used; it resolves once the use is below the threshold.

One alert per item, resolved when it reads OK, is disabled, or is no longer
in a table read completely; the empty-table rules are ``health_checks``'s
(a switch without PoE costs one walk of each table per hour once
confirmed). Which device types read the tables is
``health_checks.DEVICE_PLANS``.

Source, checked against the MIB text (powerEthernetMIB 1.3.6.1.2.1.105,
pethObjects .1):

  pethPsePortTable .1.1.1, indexed by pethPsePortGroupIndex.pethPsePortIndex
  (the group is the stack member or module; 1 on a fixed switch):
    pethPsePortAdminEnable      .1.1.1.3  TruthValue
    pethPsePortDetectionStatus  .1.1.1.6  disabled(1) searching(2)
                                          deliveringPower(3) fault(4) test(5)
                                          otherFault(6)
  pethMainPseTable .1.3.1.1, indexed by pethMainPseGroupIndex:
    pethMainPsePower             .1.3.1.1.2  nominal power, Watts
    pethMainPseOperStatus        .1.3.1.1.3  on(1) off(2) faulty(3)
    pethMainPseConsumptionPower  .1.3.1.1.4  measured use, Watts
    pethMainPseUsageThreshold    .1.3.1.1.5  percent (1..99)

The MIB does not map a PoE port to its interface: a port is named by its
group and port number ("PoE port 5 (unit 1)").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from netcontrol import environment_health as env, snmp_health as sh
from netcontrol.routes.snmp import oid_sort_key, snmp_int
from netcontrol.snmp_health import ADMIN_DOWN, DOWN, OK, TRANSITIONAL, HealthCheck, TableSource

KIND_POE_PORT = "poe_port"
KIND_POE_SUPPLY = "poe_supply"
KIND_POE_BUDGET = "poe_budget"

PORT = HealthCheck(
    metric="poe_port_fault",
    result_key="poe_port_health",
    kind=KIND_POE_PORT,
    severity="warning",
    noun="PoE port",
)
SUPPLY = HealthCheck(
    metric="poe_supply_down",
    result_key="poe_supply_health",
    kind=KIND_POE_SUPPLY,
    severity="critical",
    noun="PoE power source",
)
BUDGET = HealthCheck(
    metric="poe_budget_high",
    result_key="poe_budget_health",
    kind=KIND_POE_BUDGET,
    severity="warning",
    noun="PoE power source",
    alert_type="threshold",
)
CHECKS = (PORT, SUPPLY, BUDGET)

PSE_PORT_ADMIN_ENABLE = "1.3.6.1.2.1.105.1.1.1.3"
PSE_PORT_DETECTION_STATUS = "1.3.6.1.2.1.105.1.1.1.6"
MAIN_PSE_POWER = "1.3.6.1.2.1.105.1.3.1.1.2"
MAIN_PSE_OPER_STATUS = "1.3.6.1.2.1.105.1.3.1.1.3"
MAIN_PSE_CONSUMPTION = "1.3.6.1.2.1.105.1.3.1.1.4"
MAIN_PSE_USAGE_THRESHOLD = "1.3.6.1.2.1.105.1.3.1.1.5"

# The budget level where the device answers no usage threshold.
DEFAULT_USAGE_THRESHOLD = 90

PORT_STATES: dict[int, tuple[str, str]] = {
    1: ("disabled", ADMIN_DOWN),
    2: ("searching", OK),
    3: ("delivering power", OK),
    4: ("faulty", DOWN),
    5: ("in test mode", TRANSITIONAL),
    6: ("faulty (error condition)", DOWN),
}
SUPPLY_ON = 1
SUPPLY_STATES: dict[int, tuple[str, str]] = {
    SUPPLY_ON: ("on", OK),
    2: ("off", ADMIN_DOWN),
    3: ("faulty", DOWN),
}

POE_PORTS = TableSource(
    key="power_ethernet_port",
    vendor="POWER-ETHERNET-MIB",
    state_oid=PSE_PORT_DETECTION_STATUS,
    states=PORT_STATES,
    kinds=frozenset({KIND_POE_PORT}),
    detail_oids=(PSE_PORT_ADMIN_ENABLE,),
    admin_off=lambda v: snmp_int(v.get(PSE_PORT_ADMIN_ENABLE)) == sh.TRUTH_FALSE,
    index_name=env.unit_name("PoE port"),
)


def usage_threshold(raw: Any) -> int:
    """The device's usage threshold (1..99 %), else the default."""
    value = snmp_int(raw)
    return value if value is not None and 1 <= value <= 99 else DEFAULT_USAGE_THRESHOLD


def budget_item(index: str, power: Any, consumption: Any, threshold: Any) -> dict[str, Any] | None:
    """A power source's budget item; None when the device answers no
    nominal power or no consumption."""
    nominal = snmp_int(power)
    used = snmp_int(consumption)
    if not nominal or nominal <= 0 or used is None:
        return None
    level = usage_threshold(threshold)
    percent = round(used * 100 / nominal)
    return {
        "index": index,
        "kind": KIND_POE_BUDGET,
        "name": "",
        "model": "",
        "status": f"using {used} W of {nominal} W ({percent}%, threshold {level}%)",
        "state": percent,
        "class": DOWN if percent >= level else OK,
        "severity": None,
    }


@dataclass(frozen=True)
class MainPseTable:
    """pethMainPseTable: one walk of the operational status, then one GET
    of the power, consumption and threshold of the sources that are on.
    Each row is a ``poe_supply`` item, and a source that is on a
    ``poe_budget`` item too. A GET unanswered reads nothing: a table
    without its budget items would clear their alerts."""

    key: str = "power_ethernet_main_pse"
    vendor: str = "POWER-ETHERNET-MIB"
    kinds: frozenset[str] = frozenset({KIND_POE_SUPPLY, KIND_POE_BUDGET})

    async def read(self, get: sh.Get, walk: sh.Walk, host_id: int) -> dict[str, Any] | None:
        walked = await sh.walk_column(walk, MAIN_PSE_OPER_STATUS)
        if walked is None:
            return None
        rows = sh.rows_by_index(walked, MAIN_PSE_OPER_STATUS)
        if not rows:
            return sh.empty_table(self.key, self.vendor)
        states = {index: snmp_int(raw) for index, raw in rows.items()}
        on = [i for i in sorted(states, key=oid_sort_key) if states[i] == SUPPLY_ON]
        values: dict[str, Any] = {}
        if on:
            columns = (MAIN_PSE_POWER, MAIN_PSE_CONSUMPTION, MAIN_PSE_USAGE_THRESHOLD)
            answers = await sh.get_all(get, [f"{oid}.{i}" for i in on for oid in columns])
            if answers is None:
                return None
            values.update(answers)
        items: list[dict[str, Any]] = []
        for index in sorted(states, key=oid_sort_key):
            state = states[index]
            if state is None:
                continue
            label, klass = SUPPLY_STATES.get(state, (f"state {state}", TRANSITIONAL))
            items.append(
                {
                    "index": index,
                    "kind": KIND_POE_SUPPLY,
                    "name": "",
                    "model": "",
                    "status": label,
                    "state": state,
                    "class": klass,
                    "severity": None,
                }
            )
            if state == SUPPLY_ON:
                budget = budget_item(
                    index,
                    values.get(f"{MAIN_PSE_POWER}.{index}"),
                    values.get(f"{MAIN_PSE_CONSUMPTION}.{index}"),
                    values.get(f"{MAIN_PSE_USAGE_THRESHOLD}.{index}"),
                )
                if budget is not None:
                    items.append(budget)
        return {"source": self.key, "vendor": self.vendor, "items": items}


MAIN_PSE = MainPseTable()
