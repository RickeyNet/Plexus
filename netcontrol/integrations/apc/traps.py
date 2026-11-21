"""APC Smart-UPS SNMP traps (PowerNet-MIB, enterprise 318).

The card sends a trap the moment the UPS changes state. The SNMP trap
receiver (``netcontrol/routes/metrics_engine.py``) queues every trap it
accepts in its bounded event buffer; its batch writer stores them in
``trap_syslog_events`` and, for an APC trap whose source is an inventory
host, hands the trap to ``handle_apc_trap`` here. When the trap belongs to
an ``apc_ups`` host and carries that host's stored SNMP community
(``snmp.trap_community_matches``), the handler

- raises or resolves the built-in UPS alert the trap names, under the same
  dedup key the monitoring poll uses (``snmp.alert_dedup_key``), so a trap
  and a poll deduplicate and resolve each other, and
- schedules an immediate monitoring poll of the host, so its stored state,
  history and alerts catch up within seconds instead of at the next poll.

The poll that follows stays authoritative: it re-raises what the UPS still
reports and resolves what it no longer does.

Trap numbers, checked against the TRAP-TYPE definitions of PowerNet-MIB
(ENTERPRISE apc; an SNMPv2c card sends them as ``1.3.6.1.4.1.318.0.N``, a
v1 card as enterprise ``1.3.6.1.4.1.318`` with specific-trap N). Each
carries ``mtrapargsString`` (``1.3.6.1.4.1.318.2.3.3.0``), the card's text.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

import routes.database as db

from netcontrol.integrations.apc import snmp as apc_snmp
from netcontrol.monitoring_repoll import schedule_repoll

LOGGER = logging.getLogger(__name__)

APC_ENTERPRISE = "1.3.6.1.4.1.318"
_APC_TRAP_PREFIX = APC_ENTERPRISE + ".0."
MTRAPARGS_STRING = "1.3.6.1.4.1.318.2.3.3.0"

RAISE = "raise"
RESOLVE = "resolve"

# A burst of traps (on battery, then low battery) is one re-poll: a host
# already waiting for one is not scheduled again. The short wait lets the
# card's SNMP objects settle on the new state first.
REPOLL_DELAY_SECONDS = 5.0


@dataclass(frozen=True)
class TrapKind:
    """One PowerNet-MIB trap: its MIB name, the event severity it is stored
    with (the MIB's SEVERE / WARNING / INFORMATIONAL), what it says, and the
    built-in alert it raises or resolves (none: the re-poll decides)."""

    name: str
    severity: str
    text: str
    alert: str = ""
    action: str = ""
    alert_severity: str = "warning"


_ON_BATTERY, _BATTERY, _OUTPUT = apc_snmp.ALERT_ON_BATTERY, apc_snmp.ALERT_BATTERY, apc_snmp.ALERT_OUTPUT
_OVERLOAD, _COMMUNICATION = apc_snmp.ALERT_OVERLOAD, apc_snmp.ALERT_COMMUNICATION

# Temperature traps (53/54, 353/354) only trigger the re-poll: the card's
# own threshold is not Plexus's, and the battery temperature alert is
# evaluated by the poll against ``apc_snmp.BATTERY_TEMPERATURE_C``. Same for
# the self-test and discharge traps, whose state the poll reads itself.
APC_UPS_TRAPS: dict[int, TrapKind] = {
    1: TrapKind("communicationLost", "critical", "Communication with the UPS lost", _COMMUNICATION, RAISE, "critical"),
    2: TrapKind("upsOverload", "critical", "UPS overloaded", _OVERLOAD, RAISE, "critical"),
    3: TrapKind("upsDiagnosticsFailed", "critical", "UPS self-test failed"),
    4: TrapKind("upsDischarged", "critical", "UPS batteries discharged"),
    5: TrapKind("upsOnBattery", "warning", "UPS on battery", _ON_BATTERY, RAISE, "warning"),
    7: TrapKind("lowBattery", "critical", "UPS battery low", _BATTERY, RAISE, "critical"),
    8: TrapKind("communicationEstablished", "info", "Communication with the UPS established", _COMMUNICATION, RESOLVE),
    9: TrapKind("powerRestored", "info", "Utility power restored", _ON_BATTERY, RESOLVE),
    10: TrapKind("upsDiagnosticsPassed", "info", "UPS self-test passed"),
    11: TrapKind("returnFromLowBattery", "info", "UPS returned from low battery", _BATTERY, RESOLVE),
    12: TrapKind("upsTurnedOff", "warning", "UPS output turned off", _OUTPUT, RAISE, "critical"),
    13: TrapKind("upsSleeping", "warning", "UPS output sleeping", _OUTPUT, RAISE, "critical"),
    14: TrapKind("upsWokeUp", "info", "UPS returned from sleep", _OUTPUT, RESOLVE),
    15: TrapKind("upsRebootStarted", "warning", "UPS reboot started"),
    17: TrapKind("upsBatteryNeedsReplacement", "critical", "UPS battery needs replacing", _BATTERY, RAISE, "warning"),
    20: TrapKind("hardwareFailureBypass", "critical", "UPS on bypass: hardware failure", _OUTPUT, RAISE, "critical"),
    21: TrapKind("softwareBypass", "warning", "UPS on bypass: software", _OUTPUT, RAISE, "warning"),
    22: TrapKind("switchedBypass", "warning", "UPS on bypass: switched", _OUTPUT, RAISE, "warning"),
    23: TrapKind("returnFromBypass", "info", "UPS returned from bypass", _OUTPUT, RESOLVE),
    30: TrapKind("upsTurnedOn", "info", "UPS output turned on", _OUTPUT, RESOLVE),
    33: TrapKind("upsOverloadCleared", "info", "UPS overload cleared", _OVERLOAD, RESOLVE),
    36: TrapKind("upsBatteryReplaced", "info", "UPS battery fault cleared", _BATTERY, RESOLVE),
    38: TrapKind("dischargeCleared", "info", "UPS discharge cleared"),
    53: TrapKind("batteryOverTemperature", "warning", "UPS battery over temperature"),
    54: TrapKind("batteryOverTemperatureCleared", "info", "UPS battery over temperature cleared"),
    80: TrapKind("noBatteries", "warning", "UPS has no batteries attached", _BATTERY, RAISE, "critical"),
    81: TrapKind("noBatteriesCleared", "info", "UPS batteries attached", _BATTERY, RESOLVE),
    353: TrapKind("upsInternalOverTemperature", "warning", "UPS internal over temperature"),
    354: TrapKind("upsInternalOverTemperatureCleared", "info", "UPS internal over temperature cleared"),
    733: TrapKind(
        "onbatterycommunicationLost",
        "critical",
        "Communication with the UPS lost while on battery",
        _COMMUNICATION,
        RAISE,
        "critical",
    ),
}


@dataclass(frozen=True)
class ApcTrap:
    """A decoded APC trap: its number, its kind (None when not one of
    ``APC_UPS_TRAPS``), the card's text, the trap's agent address and the
    decoded trap itself (``trap``: the SNMP community is checked on it)."""

    number: int
    kind: TrapKind | None
    detail: str
    trap_oid: str
    agent_address: str = ""
    trap: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def severity(self) -> str:
        return self.kind.severity if self.kind else "info"

    @property
    def message(self) -> str:
        title = f"APC {self.kind.name}: {self.kind.text}" if self.kind else f"APC trap {self.number}"
        return f"{title} ({self.detail})" if self.detail else title


def parse_apc_trap(trap: dict | None) -> ApcTrap | None:
    """The APC trap in a decoded trap (``decode_snmp_trap``), None when it is
    not an enterprise-318 trap."""
    trap_oid = str((trap or {}).get("trap_oid") or "")
    if not trap_oid.startswith(_APC_TRAP_PREFIX):
        return None
    number_text = trap_oid[len(_APC_TRAP_PREFIX) :]
    if not number_text.isdigit():
        return None
    number = int(number_text)
    detail = next((text for oid, text in (trap or {}).get("varbinds") or [] if oid == MTRAPARGS_STRING), "")
    return ApcTrap(
        number=number,
        kind=APC_UPS_TRAPS.get(number),
        detail=" ".join(str(detail).split())[:200],
        trap_oid=trap_oid,
        agent_address=str((trap or {}).get("agent_address") or ""),
        trap=dict(trap or {}),
    )


def _unspecified(address: str) -> bool:
    """An unset address (a v1 agent address of 0.0.0.0), or not an address."""
    try:
        return ipaddress.ip_address(address).is_unspecified
    except ValueError:
        return True


def _ups(host: dict | None) -> dict | None:
    return host if host is not None and host.get("device_type") == apc_snmp.STATUS_KIND else None


async def find_ups_host(source_ip: str, agent_address: str = "") -> dict | None:
    """The ``apc_ups`` inventory host a trap came from: the host whose
    address (primary IP or a recorded interface IP) is the datagram's source.
    A v1 trap's agent address (a field of the packet, as forgeable as the
    rest of it) picks the host only when the source itself is an inventory
    host that is not a UPS (a relay or NAT device in inventory). None when no
    APC UPS host is found that way."""
    if not source_ip or _unspecified(source_ip):
        return None
    source_host = await db.find_host_by_ip(source_ip, include_aliases=True)
    if source_host is None:
        return None
    if _ups(source_host) is not None:
        return source_host
    if not agent_address or _unspecified(agent_address) or agent_address == source_ip:
        return None
    return _ups(await db.find_host_by_ip(agent_address, include_aliases=True))


# ── Acting on a trap ────────────────────────────────────────────────────────


async def handle_apc_trap(source_ip: str, trap: ApcTrap) -> dict:
    """Act on an APC trap: when it comes from an ``apc_ups`` host
    (``find_ups_host``) with that host's stored SNMP community and
    monitoring is on, raise or resolve the alert it names (unless
    suppressed) and schedule the host's re-poll. Returns what was done:
    ``{"host_id", "alert", "action", "repoll"}`` (``host_id`` None when the
    trap is not from a UPS in inventory or its community is wrong)."""
    import netcontrol.routes.state as state
    from netcontrol.routes.snmp import trap_community_matches

    outcome: dict = {"host_id": None, "alert": "", "action": "", "repoll": False}
    if not state.MONITORING_CONFIG.get("enabled"):
        return outcome
    host = await find_ups_host(source_ip, trap.agent_address)
    if host is None:
        return outcome
    if not trap_community_matches(trap.trap, host):
        LOGGER.debug("apc traps: trap from %s ignored: not the host's SNMP community", source_ip)
        return outcome
    host_id = int(host["id"])
    outcome["host_id"] = host_id
    kind = trap.kind
    if kind is not None and kind.alert:
        key = apc_snmp.alert_dedup_key(host_id, kind.alert)
        if kind.action == RESOLVE:
            await db.resolve_monitoring_alerts(key)
            outcome.update(alert=kind.alert, action=RESOLVE)
        elif not await db.is_alert_suppressed(host_id, kind.alert, host.get("group_id")):
            await db.create_monitoring_alert(
                host_id=host_id,
                poll_id=None,
                alert_type=apc_snmp.alert_type(kind.alert),
                metric=kind.alert,
                message=f"{kind.text} (SNMP trap {kind.name})",
                severity=kind.alert_severity,
                dedup_key=key,
                hostname=host.get("hostname") or "",
            )
            outcome.update(alert=kind.alert, action=RAISE)
    # A host already waiting for a re-poll is not scheduled again: that poll
    # sees this trap's state too.
    outcome["repoll"] = schedule_repoll(host_id, REPOLL_DELAY_SECONDS)
    return outcome
