"""SNMP trap alert rules: received traps acted on by the server.

The SNMP trap receiver (``netcontrol/routes/metrics_engine.py``) stores
every trap in ``trap_syslog_events``, named by ``netcontrol.snmp_traps``.
Its batch writer then hands the traps it believes (the source is an
inventory host and the v1 / v2c community is that host's stored one) to
``process_trap_batch`` here, which

- matches them against the built-in trap rules below and raises or
  resolves monitoring alerts (``alert_type`` ``trap``, ``metric``
  ``trap_<rule key>``) under a dedup key per rule, host and *instance* (the
  interface, module, power supply, peer ... the trap names),
- starts the configuration backup and drift check of a host whose trap
  says its configuration changed, through the syslog configuration-change
  trigger (``syslog_rules.note_config_change``: the same debounce and
  per-host cooldown), and
- schedules the immediate monitoring re-poll of a host whose trap names a
  state change (``netcontrol.monitoring_repoll``, the syslog re-poll
  delays and per-host interval), and
- runs the syslog line a CISCO-SYSLOG-MIB ``clogMessageGenerated`` trap
  carries (``clog_syslog_line``: ``%FACILITY-SEVERITY-MNEMONIC: text``)
  through the syslog rules and triggers (``process_syslog_batch``): its
  alerts are syslog alerts, under the same dedup key as the same message
  received as syslog, so the two paths meet in one alert.

The rule engine is the syslog one (``netcontrol.syslog_rules``): these rules
are ``Rule`` objects with ``source`` ``trap``, counted, raised, resolved,
auto-resolved, enabled / disabled and given a severity override exactly as
the built-in syslog rules are (the override row is stored in
``syslog_alert_rules`` under ``builtin_key`` ``trap_<key>``). The operator's
custom trap rules (a trap OID, OID prefix or name, varbind conditions, an
instance varbind and an optional clearing trap) are rows of the same table
with ``source`` ``trap``; their metric is ``trap_custom_<id>``. Trap alerts
are their own family: no syslog or polled alert suppresses, resolves or is
resolved by them.

Switches (``state.EVENT_RECEIVER_CONFIG``, on when unset): ``trap_alerts``
(the alerts), ``repoll_trigger`` and ``config_change_trigger`` (shared with
syslog); a ``clogMessageGenerated`` line follows the syslog switches
(``syslog_alerts`` for its alerts), not ``trap_alerts``. Alerts and re-polls
also need monitoring to be on.

The threshold counters live in memory; ``restore_state`` rebuilds them at
startup from the stored traps that would have been acted on.

``docs/snmp-traps.md`` describes the rules, the traps each one takes, and
the gaps.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import partial

import routes.database as db
from routes.user_regex import compile_user_regex

import netcontrol.routes.state as state
from netcontrol import syslog_rules as engine
from netcontrol.integrations.apc.traps import parse_apc_trap
from netcontrol.monitoring_repoll import mark_hardware_stale, schedule_repoll
from netcontrol.routes.snmp import decode_snmp_trap, trap_community_matches
from netcontrol.snmp_traps import OBJECTS, TRAPS_BY_OID, NamedTrap, Varbind, name_trap
from netcontrol.syslog_rules import RuleError

LOGGER = logging.getLogger("plexus.trap_rules")

SOURCE = "trap"
RAISE = "raise"
CLEAR = "clear"

# An instance function: the instance a matching trap names ("" for the
# device), or None when the trap does not match (wrong state, ...).
InstanceFn = Callable[[NamedTrap], str | None]


# ── Instances ────────────────────────────────────────────────────────────────


def _device(_named: NamedTrap) -> str:
    return ""


def _index(obj: str, prefix: str) -> InstanceFn:
    """``<prefix> <instance index of obj>`` (the device when it is absent)."""

    def instance(named: NamedTrap) -> str:
        found = named.index(obj)
        return f"{prefix} {found}" if found else ""

    return instance


def _value(obj: str, prefix: str = "") -> InstanceFn:
    """The value of ``obj`` (with ``prefix``); the device when absent."""

    def instance(named: NamedTrap) -> str:
        found = named.label(obj)
        if not found:
            return ""
        return f"{prefix} {found}" if prefix else found

    return instance


def _interface(named: NamedTrap) -> str:
    """``ifIndex <n>``: the ifIndex value, else the index of its varbinds."""
    value = named.label("ifIndex")
    if value:
        return f"ifIndex {value}"
    for obj in ("ifOperStatus", "ifAdminStatus", "ifIndex"):
        found = named.index(obj)
        if found:
            return f"ifIndex {found}"
    return ""


def _address_from_index(index: str) -> str:
    """The peer address in a BGP table index: ``a.b.c.d`` (BGP4-MIB), or an
    ``InetAddressType.length.octets`` tail (CISCO-BGP4-MIB cbgpPeer2Table,
    ARISTA-BGP4V2-MIB). The index itself when neither fits."""
    parts = index.split(".")
    if not all(p.isdigit() for p in parts):
        return index
    nums = [int(p) for p in parts]
    for start in range(len(nums) - 2, -1, -1):
        kind, length, octets = nums[start], nums[start + 1], nums[start + 2 :]
        if kind in (1, 2) and length in (4, 16) and len(octets) == length and all(o < 256 for o in octets):
            return _address(bytes(octets))
    return index


def _address(raw: bytes) -> str:
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    return raw.hex()


def _peer_index(obj: str) -> InstanceFn:
    def instance(named: NamedTrap) -> str:
        found = named.index(obj)
        return _address_from_index(found) if found else ""

    return instance


def _peer_value(obj: str) -> InstanceFn:
    """A peer address held as an octet-string value (``0x...``) or text."""

    def instance(named: NamedTrap) -> str:
        found = named.get(obj)
        if found is None:
            return ""
        text = found.value
        if text.startswith("0x"):
            try:
                return _address(bytes.fromhex(text[2:]))
            except ValueError:
                return text
        return found.label

    return instance


# PAN-OS system log description of a routed BGP event: "... peer IP: <x>"
# (the syslog rule's form, docs/syslog-rules.md).
_PAN_PEER = re.compile(engine._PAN_BGP_PEER)


def _pan_peer(named: NamedTrap) -> str:
    found = _PAN_PEER.search(named.label("panSystemDescription"))
    return found.group(1) if found else ""


def _first_of(*fns: InstanceFn) -> InstanceFn:
    def instance(named: NamedTrap) -> str:
        for fn in fns:
            found = fn(named)
            if found:
                return found
        return ""

    return instance


# ── Conditions ───────────────────────────────────────────────────────────────


def _when(obj: str, values: Iterable[int], instance: InstanceFn, *, missing: bool = False) -> InstanceFn:
    """``instance`` when the number of ``obj`` is one of ``values`` (or
    ``obj`` is absent and ``missing``), else None."""
    wanted = frozenset(values)

    def match(named: NamedTrap) -> str | None:
        number = named.number(obj)
        if number is None:
            return instance(named) if missing and named.get(obj) is None else None
        return instance(named) if number in wanted else None

    return match


def _when_text(obj: str, values: Iterable[str], instance: InstanceFn) -> InstanceFn:
    """``instance`` when the text of ``obj`` is one of ``values``."""
    wanted = frozenset(values)

    def match(named: NamedTrap) -> str | None:
        return instance(named) if named.label(obj).strip().lower() in wanted else None

    return match


def _unless(obj: str, values: Iterable[int], instance: InstanceFn) -> InstanceFn:
    """``instance`` unless the number of ``obj`` is one of ``values``."""
    refused = frozenset(values)

    def match(named: NamedTrap) -> str | None:
        return None if named.number(obj) in refused else instance(named)

    return match


def _all(*conditions: Callable[[NamedTrap], bool], instance: InstanceFn) -> InstanceFn:
    def match(named: NamedTrap) -> str | None:
        return instance(named) if all(c(named) for c in conditions) else None

    return match


# CISCO-ENVMON-MIB CiscoEnvMonState: normal(1), warning(2), critical(3),
# shutdown(4), notPresent(5), notFunctioning(6).
_ENVMON_FAILED = (3, 4, 6)
_ENVMON_HOT = (2, 3, 4)
_ENVMON_NORMAL = (1,)
# CISCO-ENTITY-FRU-CONTROL-MIB cefcModuleOperStatus: failed(7), missing(8),
# diagFailed(11), outOfServiceEnvTemp(14), poweredDown(15), powerDenied(17)
# are down; ok(2) and the okBut... states (4, 19, 20, 23) are up. disabled(3)
# and outOfServiceAdmin(13) are an operator's doing and raise nothing.
_CEFC_MODULE_DOWN = (7, 8, 11, 14, 15, 17)
_CEFC_MODULE_UP = (2, 4, 19, 20, 23)
# JUNIPER-MIB jnxFruType of the FRUs that are modules (the syslog module
# rule's set): FPC (3), SFM (4), control board (5), routing engine (6), SIB
# (9), PIC (11), line card chassis (14), FEB (15), switch fabric board (19),
# adapter card (20). jnxFruOfflineReason configPowerOff (5), cliCommand (7)
# and buttonPress (8) are an operator's doing.
_JNX_MODULE_TYPES = frozenset({3, 4, 5, 6, 9, 11, 14, 15, 19, 20})
_JNX_OPERATOR_OFFLINE = (5, 7, 8)
# ARUBAWIRED-VSF(v2)-MIB member status (DisplayString, values from the MIB).
_VSF_DOWN = ("not_present", "communication_failure", "in_other_fragment")
_VSF_UP = ("ready",)
# HP-ICF-CHASSIS hpicfPowerSupplyStatus: ok(1), inserted(2), removed(3),
# faulted(4). NETGEAR-BOXSERVICES-PRIVATE-MIB boxsItemStateChangeEvent:
# insertion(1), removal(2), becomeoperational(3), failure(4), losepower(5);
# boxsTemperatureStatus: low(0), normal(1), warning(2), critical(3),
# shutdown(4), notpresent(5), notoperational(6).
_HP_PSU_DOWN, _HP_PSU_OK = (3, 4), (1,)
# OSPF-MIB ospfNbrState: full(8), and twoWay(4), where two routers that are
# neither DR nor BDR of a broadcast segment stay for good (RFC 4750 sends
# ospfNbrStateChange for either as a terminal state). A virtual neighbor is
# point to point: full only.
_OSPF_SETTLED = (4, 8)
_BOXS_DOWN, _BOXS_UP = (2, 4, 5), (3,)
_BOXS_HOT, _BOXS_NORMAL = (2, 3, 4), (1,)


def _jnx_module(named: NamedTrap) -> bool:
    return named.number("jnxFruType") in _JNX_MODULE_TYPES


_JNX_FRU = _index("jnxFruName", "FRU")
_JNX_CONTENTS = _first_of(_value("jnxContentsDescr"), _index("jnxContentsDescr", "jnxContents"))


def _jnx_input(named: NamedTrap) -> str:
    """A power supply's input: its own instance, so an input OK does not
    resolve a failed supply."""
    return f"{_JNX_CONTENTS(named)} input".strip()


_PAN_OBJECT = _value("panSystemObject")
_CEFC_ENTITY = _index("cefcModuleOperStatus", "entPhysicalIndex")
_FRU_ENTITY = _index("entPhysicalContainedIn", "entPhysicalIndex")


def _index_part(obj: str, prefix: str, part: int = 0) -> InstanceFn:
    """``<prefix> <n>``: part ``part`` of the instance index of ``obj``
    (``ifIndex.vlan``, ``ctrl.react`` ...); the device when it is absent."""

    def instance(named: NamedTrap) -> str:
        parts = named.index(obj).split(".")
        return f"{prefix} {parts[part]}" if len(parts) > part and parts[part] else ""

    return instance


def _err_disabled_port(named: NamedTrap) -> str:
    """CISCO-ERR-DISABLE-MIB ``cErrDisableIfStatusCause`` is indexed by
    ``ifIndex.vlanIndex`` (vlan 0: the whole port): ``ifIndex <n>[ vlan
    <v>]``."""
    parts = named.index("cErrDisableIfStatusCause").split(".")
    if not parts[0]:
        return ""
    vlan = parts[1] if len(parts) > 1 and parts[1] not in ("", "0") else ""
    return f"ifIndex {parts[0]}" + (f" vlan {vlan}" if vlan else "")


def _hsrp_group(named: NamedTrap) -> str:
    """CISCO-HSRP-MIB ``cHsrpGrpStandbyState`` is indexed by ``ifIndex.group``."""
    parts = named.index("cHsrpGrpStandbyState").split(".")
    if len(parts) != 2:
        return ""
    return f"ifIndex {parts[0]} group {parts[1]}"


def _isis_neighbor(lsp_obj: str, circuit_obj: str) -> InstanceFn:
    """An IS-IS adjacency: the system ID of the neighbor (the first 6 bytes
    of the LSP ID varbind, ``xxxx.xxxx.xxxx``) and the circuit index."""

    def instance(named: NamedTrap) -> str:
        found = named.get(lsp_obj)
        system_id = ""
        if found is not None and found.value.startswith("0x") and len(found.value) >= 14:
            raw = found.value[2:14].lower()
            system_id = f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"
        circuit = named.label(circuit_obj)
        return " ".join(p for p in (system_id, f"circuit {circuit}" if circuit else "") if p)

    return instance


def _bgp_fsm(state_obj: str, prev_obj: str, instance: InstanceFn, action: str) -> InstanceFn:
    """A CISCO-BGP4-MIB FSM state change: raise when the previous state was
    established(6) and the new one is not, clear when the new one is."""

    def match(named: NamedTrap) -> str | None:
        new, old = named.number(state_obj), named.number(prev_obj)
        if action == CLEAR:
            return instance(named) if new == 6 else None
        return instance(named) if old == 6 and new is not None and new != 6 else None

    return match


# ── The rules ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrapRule:
    """A built-in trap rule: the traps (by registry name) that raise and
    clear it, each with the function naming its instance (None: this trap
    does not match), and the re-poll it starts (``repoll``: a
    ``syslog_rules.repoll_reason``-style reason, "" for none)."""

    key: str
    name: str
    description: str
    families: tuple[str, ...]
    severity: str
    raise_on: dict[str, InstanceFn]
    clear_on: dict[str, InstanceFn] = field(default_factory=dict)
    threshold_count: int = 1
    threshold_window_seconds: int = 300
    auto_resolve_minutes: int = 0
    repoll: str = ""

    def match(self, action: str, named: NamedTrap) -> str | None:
        fn = (self.raise_on if action == RAISE else self.clear_on).get(named.name)
        return fn(named) if fn is not None else None


_BGP_PEER = _peer_index("bgpPeerState")
_CBGP2_PEER = _peer_index("cbgpPeer2State")
_JNX_BGP_PEER = _peer_value("jnxBgpM2PeerRemoteAddr")
_ARISTA_BGP_PEER = _peer_index("aristaBgp4V2PeerState")
_ENVMON_SUPPLY = _index("ciscoEnvMonSupplyState", "supply")
_ENVMON_FAN = _index("ciscoEnvMonFanState", "fan")
_ENVMON_TEMP = _index("ciscoEnvMonTemperatureState", "sensor")
# CISCO-RTTMON-MIB rttMonReactVar timeout (7), connectionLoss (8),
# verifyError (9): the operation no longer reaches its target (the other
# reactions are performance thresholds). rttMonReactOccurred is indexed by
# rttMonCtrlAdminIndex.rttMonReactConfigIndex.
_SLA_UNREACHABLE = (7, 8, 9)
_SLA_PROBE = _index_part("rttMonReactOccurred", "probe")
# POWER-ETHERNET-MIB pethPsePortDetectionStatus is indexed by
# pethPsePortGroupIndex.pethPsePortIndex.
_POE_PORT = _index("pethPsePortDetectionStatus", "PoE port")
# FORTINET-FORTIGATE-MIB fgTrapVpnTunUp / Down: the remote gateway, else the
# phase 1 name.
_FGT_VPN_PEER = _first_of(_value("fgVpnTrapRemoteGateway"), _value("fgVpnTrapPhase1Name"))


def _sla_reachability(named: NamedTrap) -> bool:
    return named.number("rttMonReactVar") in _SLA_UNREACHABLE


TRAP_RULES: tuple[TrapRule, ...] = (
    TrapRule(
        key="link_down",
        name="Interface down",
        description=(
            "An interface went down (linkDown with ifAdminStatus up: not shut down by an operator); resolved by "
            "its linkUp, or after 24 hours without a new linkDown."
        ),
        families=("Every platform that sends IF-MIB linkDown / linkUp",),
        severity="warning",
        raise_on={"linkDown": _unless("ifAdminStatus", (2,), _interface)},
        clear_on={"linkUp": _interface},
        auto_resolve_minutes=1440,
        repoll="interface_down",
    ),
    TrapRule(
        key="module",
        name="Module down",
        description=(
            "A line card, supervisor, FRU or stack member failed, went offline, lost power or was removed; "
            "resolved when it is back, or after 24 hours."
        ),
        families=(
            "Cisco (CISCO-ENTITY-FRU-CONTROL-MIB, CISCO-STACKWISE-MIB)",
            "Juniper Junos (JUNIPER-MIB, Virtual Chassis)",
            "HPE Aruba AOS-CX (VSF, modules)",
            "Palo Alto PAN-OS (slots)",
        ),
        severity="critical",
        raise_on={
            "cefcModuleStatusChange": _when("cefcModuleOperStatus", _CEFC_MODULE_DOWN, _CEFC_ENTITY),
            "cefcFRURemoved": _FRU_ENTITY,
            "cswStackMemberRemoved": _value("cswSwitchNumCurrent", "switch"),
            **{
                name: _all(_jnx_module, instance=_unless("jnxFruOfflineReason", _JNX_OPERATOR_OFFLINE, _JNX_FRU))
                for name in ("jnxFruRemoval", "jnxFruPowerOff", "jnxFruFailed", "jnxFruOffline")
            },
            "jnxVccpMemberDown": _index("jnxVirtualChassisMemberSerialnumber", "member"),
            "arubaWiredVsfMemberStatusChange": _when_text(
                "arubaWiredVsfMemberStatus", _VSF_DOWN, _index("arubaWiredVsfMemberStatus", "member")
            ),
            "arubaWiredVsfv2MemberStatusChange": _when_text(
                "arubaWiredVsfv2MemberStatus", _VSF_DOWN, _index("arubaWiredVsfv2MemberStatus", "member")
            ),
            "arubaWiredModuleRemovedNotification": _value("arubaWiredModuleName"),
            "panHWSlotFailureTrap": _PAN_OBJECT,
            "panHWSlotRemovedTrap": _PAN_OBJECT,
            "panHWSlotPoweroffTrap": _PAN_OBJECT,
        },
        clear_on={
            "cefcModuleStatusChange": _when("cefcModuleOperStatus", _CEFC_MODULE_UP, _CEFC_ENTITY),
            "cefcFRUInserted": _FRU_ENTITY,
            "cswStackNewMember": _value("cswSwitchNumCurrent", "switch"),
            "jnxFruOnline": _all(_jnx_module, instance=_JNX_FRU),
            "jnxFruOK": _all(_jnx_module, instance=_JNX_FRU),
            "jnxVccpMemberUp": _index("jnxVirtualChassisMemberSerialnumber", "member"),
            "arubaWiredVsfMemberStatusChange": _when_text(
                "arubaWiredVsfMemberStatus", _VSF_UP, _index("arubaWiredVsfMemberStatus", "member")
            ),
            "arubaWiredVsfv2MemberStatusChange": _when_text(
                "arubaWiredVsfv2MemberStatus", _VSF_UP, _index("arubaWiredVsfv2MemberStatus", "member")
            ),
            "arubaWiredModuleInsertedNotification": _value("arubaWiredModuleName"),
            "panHWSlotUpTrap": _PAN_OBJECT,
        },
        auto_resolve_minutes=1440,
        repoll="module",
    ),
    TrapRule(
        key="power_supply",
        name="Power supply fault",
        description="A power supply failed, lost its input or was removed; resolved when it reports OK, or after 24 hours.",
        families=(
            "Cisco (CISCO-ENVMON-MIB)",
            "Juniper Junos",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-Switch",
            "Netgear (NETGEAR-BOXSERVICES-PRIVATE-MIB)",
        ),
        severity="critical",
        raise_on={
            "ciscoEnvMonSuppStatusChangeNotif": _when("ciscoEnvMonSupplyState", _ENVMON_FAILED, _ENVMON_SUPPLY),
            "ciscoEnvMonRedundantSupplyNotification": _when(
                "ciscoEnvMonSupplyState", _ENVMON_FAILED, _ENVMON_SUPPLY, missing=True
            ),
            "jnxPowerSupplyFailure": _JNX_CONTENTS,
            "jnxPowerSupplyInputFailure": _jnx_input,
            "panHWPsFailureTrap": _PAN_OBJECT,
            "panHWPsRemovedTrap": _PAN_OBJECT,
            "hpicfPowerSupplyStatusTrap": _when(
                "hpicfPowerSupplyStatus", _HP_PSU_DOWN, _value("hpicfPowerSupplySlotNum", "supply")
            ),
            "boxsPowSupplyStateChange": _when(
                "boxsItemStateChangeEvent", _BOXS_DOWN, _index("boxServicesPowSupplyIndex", "supply")
            ),
        },
        clear_on={
            "ciscoEnvMonSuppStatusChangeNotif": _when("ciscoEnvMonSupplyState", _ENVMON_NORMAL, _ENVMON_SUPPLY),
            "ciscoEnvMonRedundantSupplyNotification": _when("ciscoEnvMonSupplyState", _ENVMON_NORMAL, _ENVMON_SUPPLY),
            "jnxPowerSupplyOK": _JNX_CONTENTS,
            "jnxPowerSupplyInputOK": _jnx_input,
            "panHWPsInsertedTrap": _PAN_OBJECT,
            "hpicfPowerSupplyStatusTrap": _when(
                "hpicfPowerSupplyStatus", _HP_PSU_OK, _value("hpicfPowerSupplySlotNum", "supply")
            ),
            "boxsPowSupplyStateChange": _when(
                "boxsItemStateChangeEvent", _BOXS_UP, _index("boxServicesPowSupplyIndex", "supply")
            ),
        },
        auto_resolve_minutes=1440,
        repoll="module",
    ),
    TrapRule(
        key="fan",
        name="Fan fault",
        description="A fan or fan tray failed or was removed; resolved when it reports OK, or after 24 hours.",
        families=(
            "Cisco (CISCO-ENVMON-MIB, CISCO-ENTITY-FRU-CONTROL-MIB)",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "Netgear",
        ),
        severity="warning",
        raise_on={
            "ciscoEnvMonFanStatusChangeNotif": _when("ciscoEnvMonFanState", _ENVMON_FAILED, _ENVMON_FAN),
            "ciscoEnvMonFanNotification": _when("ciscoEnvMonFanState", _ENVMON_FAILED, _ENVMON_FAN, missing=True),
            "cefcFanTrayStatusChange": _when(
                "cefcFanTrayOperStatus", (3,), _index("cefcFanTrayOperStatus", "fan tray")
            ),
            "jnxFanFailure": _JNX_CONTENTS,
            "fnTrapFanFailure": _device,
            "panHWFanFailureTrap": _PAN_OBJECT,
            "panHWFanRemovedTrap": _PAN_OBJECT,
            "boxsFanStateChange": _when("boxsItemStateChangeEvent", _BOXS_DOWN, _index("boxServicesFansIndex", "fan")),
            "fanFailureTrap": _device,
        },
        clear_on={
            "ciscoEnvMonFanStatusChangeNotif": _when("ciscoEnvMonFanState", _ENVMON_NORMAL, _ENVMON_FAN),
            "cefcFanTrayStatusChange": _when(
                "cefcFanTrayOperStatus", (2,), _index("cefcFanTrayOperStatus", "fan tray")
            ),
            "jnxFanOK": _JNX_CONTENTS,
            "panHWFanInsertedTrap": _PAN_OBJECT,
            "boxsFanStateChange": _when("boxsItemStateChangeEvent", _BOXS_UP, _index("boxServicesFansIndex", "fan")),
        },
        auto_resolve_minutes=1440,
        repoll="module",
    ),
    TrapRule(
        key="temperature",
        name="Temperature alarm",
        description=(
            "A temperature sensor reached its warning or critical threshold (or the device started a thermal "
            "shutdown); resolved when it reports normal, or after 24 hours."
        ),
        families=("Cisco (CISCO-ENVMON-MIB)", "Juniper Junos", "Fortinet FortiOS", "Netgear"),
        severity="critical",
        raise_on={
            "ciscoEnvMonTempStatusChangeNotif": _when("ciscoEnvMonTemperatureState", _ENVMON_HOT, _ENVMON_TEMP),
            "ciscoEnvMonTemperatureNotification": _when(
                "ciscoEnvMonTemperatureState", _ENVMON_HOT, _ENVMON_TEMP, missing=True
            ),
            "jnxOverTemperature": _JNX_CONTENTS,
            "fnTrapTempHigh": _device,
            "boxsTemperatureStateChange": _when(
                "boxsTemperatureStatusCurrentEvent", _BOXS_HOT, _index("boxServicesTempUnitIndex", "sensor")
            ),
            "boxsThermalShutdown": _device,
        },
        clear_on={
            "ciscoEnvMonTempStatusChangeNotif": _when("ciscoEnvMonTemperatureState", _ENVMON_NORMAL, _ENVMON_TEMP),
            "jnxTemperatureOK": _JNX_CONTENTS,
            "boxsTemperatureStateChange": _when(
                "boxsTemperatureStatusCurrentEvent", _BOXS_NORMAL, _index("boxServicesTempUnitIndex", "sensor")
            ),
        },
        auto_resolve_minutes=1440,
        repoll="module",
    ),
    TrapRule(
        key="bgp_neighbor",
        name="BGP neighbor down",
        description="A BGP session left Established; resolved when it is Established again.",
        families=(
            "Every platform that sends BGP4-MIB",
            "Cisco (CISCO-BGP4-MIB)",
            "Juniper Junos (BGP4-V2-MIB-JUNIPER)",
            "Arista EOS (ARISTA-BGP4V2-MIB)",
            "Palo Alto PAN-OS (legacy routing engine)",
        ),
        severity="critical",
        raise_on={
            "bgpBackwardTransNotification": _first_of(_BGP_PEER, _value("bgpPeerRemoteAddr")),
            "bgpBackwardTransition": _BGP_PEER,
            "cbgpBackwardTransition": _BGP_PEER,
            "cbgpFsmStateChange": _bgp_fsm("bgpPeerState", "cbgpPeerPrevState", _BGP_PEER, RAISE),
            "cbgpPeer2BackwardTransNotification": _CBGP2_PEER,
            "cbgpPeer2BackwardTransition": _CBGP2_PEER,
            "cbgpPeer2FsmStateChange": _bgp_fsm("cbgpPeer2State", "cbgpPeer2PrevState", _CBGP2_PEER, RAISE),
            "jnxBgpM2BackwardTransition": _JNX_BGP_PEER,
            "aristaBgp4V2BackwardTransitionNotification": _ARISTA_BGP_PEER,
            "panROUTINGRoutedBGPPeerLeftEstablishedTrap": _pan_peer,
        },
        clear_on={
            "bgpEstablishedNotification": _first_of(_BGP_PEER, _value("bgpPeerRemoteAddr")),
            "bgpEstablished": _BGP_PEER,
            "cbgpFsmStateChange": _bgp_fsm("bgpPeerState", "cbgpPeerPrevState", _BGP_PEER, CLEAR),
            "cbgpPeer2EstablishedNotification": _CBGP2_PEER,
            "cbgpPeer2FsmStateChange": _bgp_fsm("cbgpPeer2State", "cbgpPeer2PrevState", _CBGP2_PEER, CLEAR),
            "jnxBgpM2Established": _JNX_BGP_PEER,
            "aristaBgp4V2EstablishedNotification": _ARISTA_BGP_PEER,
            "panROUTINGRoutedBGPPeerEnterEstablishedTrap": _pan_peer,
        },
        repoll="state_change",
    ),
    TrapRule(
        key="ospf_neighbor",
        name="OSPF neighbor down",
        description="An OSPF neighbor went to Down; resolved when it is back to Full (or 2-Way, on a shared segment).",
        families=("Every platform that sends OSPF-TRAP-MIB", "Palo Alto PAN-OS (legacy routing engine)"),
        severity="critical",
        raise_on={
            "ospfNbrStateChange": _when(
                "ospfNbrState", (1,), _first_of(_value("ospfNbrRtrId"), _index("ospfNbrState", "neighbor"))
            ),
            "ospfVirtNbrStateChange": _when("ospfVirtNbrState", (1,), _value("ospfVirtNbrRtrId", "virtual")),
            "panROUTINGRoutedOSPFNeighborDownTrap": _device,
        },
        clear_on={
            "ospfNbrStateChange": _when(
                "ospfNbrState", _OSPF_SETTLED, _first_of(_value("ospfNbrRtrId"), _index("ospfNbrState", "neighbor"))
            ),
            "ospfVirtNbrStateChange": _when("ospfVirtNbrState", (8,), _value("ospfVirtNbrRtrId", "virtual")),
            "panROUTINGRoutedOSPFNeighborFullTrap": _device,
        },
        repoll="state_change",
    ),
    TrapRule(
        key="ha_switchover",
        name="HA failover or switchover",
        description=(
            "A redundancy switchover, cluster failover, new stack master, VRRP master change or HA member / "
            "keepalive loss; resolves 60 minutes after the last such trap (or when the member or keepalive is back)."
        ),
        families=(
            "Cisco (CISCO-RF-MIB, CISCO-STACKWISE-MIB)",
            "Juniper Junos (redundancy, chassis cluster)",
            "Fortinet FortiOS (HA)",
            "Palo Alto PAN-OS (HA)",
            "HPE Aruba AOS-CX (VSX)",
            "Every platform that sends VRRP-MIB / VRRPV3-MIB",
        ),
        severity="warning",
        raise_on={
            "ciscoRFSwactNotif": _device,
            "cswStackNewMaster": _value("cswSwitchNumCurrent", "switch"),
            "jnxRedundancySwitchover": _value("jnxRedundancyDescr"),
            "jnxJsChassisClusterSwitchover": _value("jnxJsChClusterSwitchoverInfoRedundancyGroup", "redundancy group"),
            "fgTrapHaSwitch": _device,
            "fgTrapHaMemberDown": _value("fnSysSerial", "member"),
            "panHAStateChangeTrap": _device,
            "vrrpTrapNewMaster": _first_of(
                _index("vrrpOperMasterIpAddr", "VRRP"), _index("vrrpOperationsMasterIpAddr", "VRRP")
            ),
            "vrrpv3NewMaster": _index("vrrpv3OperationsMasterIpAddr", "VRRP"),
            "keepAliveDown": lambda _named: "VSX keepalive",
            "islDown": lambda _named: "VSX ISL",
        },
        clear_on={
            "fgTrapHaMemberUp": _value("fnSysSerial", "member"),
            "keepAliveUp": lambda _named: "VSX keepalive",
            "islUp": lambda _named: "VSX ISL",
        },
        auto_resolve_minutes=60,
        repoll="state_change",
    ),
    TrapRule(
        key="device_restart",
        name="Device or agent restarted",
        description=(
            "The device (or its SNMP agent) restarted, or announced it is going down; resolves 60 minutes after "
            "the last such trap."
        ),
        families=(
            "Every platform (SNMPv2-MIB coldStart / warmStart)",
            "net-snmp (OPNsense)",
            "Juniper Junos (dying gasp)",
            "Palo Alto PAN-OS",
        ),
        severity="warning",
        raise_on={
            name: _device
            for name in (
                "coldStart",
                "warmStart",
                "nsNotifyStart",
                "nsNotifyRestart",
                "nsNotifyShutdown",
                "ucdStart",
                "ucdShutdown",
                "jnxDyingGasp",
                "panGeneralSystemStartTrap",
                "panGeneralSystemShutdownTrap",
            )
        },
        auto_resolve_minutes=60,
        repoll="restart",
    ),
    TrapRule(
        key="snmp_auth_failure",
        name="SNMP authentication failures",
        description=(
            "5 SNMP authenticationFailure traps from one device within 5 minutes (someone is trying wrong "
            "communities or credentials); one alert per device, resolves 30 minutes after the last one."
        ),
        families=("Every platform (SNMPv2-MIB authenticationFailure)",),
        severity="warning",
        raise_on={"authenticationFailure": _device},
        threshold_count=5,
        threshold_window_seconds=300,
        auto_resolve_minutes=30,
    ),
    # ── Event rule packs (the syslog rules of the same keys) ────────────────
    TrapRule(
        key="stp_root_change",
        name="Spanning tree root changed",
        description="The device became the spanning tree root (BRIDGE-MIB newRoot); resolves 60 minutes after the last one.",
        families=("Every platform that sends BRIDGE-MIB", "Netgear (NETGEAR-SWITCHING-MIB)"),
        severity="warning",
        raise_on={"newRoot": _device, "stpInstanceNewRootTrap": _value("agentStpMstId", "instance")},
        auto_resolve_minutes=60,
    ),
    TrapRule(
        key="stp_topology_change",
        name="Spanning tree topology changes",
        description=(
            "5 BRIDGE-MIB topologyChange traps from one device within 10 minutes; resolves 30 minutes after the "
            "last one."
        ),
        families=("Every platform that sends BRIDGE-MIB", "Netgear (NETGEAR-SWITCHING-MIB)"),
        severity="warning",
        raise_on={"topologyChange": _device, "stpInstanceTopologyChangeTrap": _value("agentStpMstId", "instance")},
        threshold_count=5,
        threshold_window_seconds=600,
        auto_resolve_minutes=30,
    ),
    TrapRule(
        key="port_err_disabled",
        name="Port error-disabled",
        description="A port was put in err-disable state (the cause is in the trap); resolves 24 hours after the last one.",
        families=("Cisco (CISCO-ERR-DISABLE-MIB)",),
        severity="warning",
        raise_on={
            "cErrDisableInterfaceEvent": _err_disabled_port,
            "cErrDisableInterfaceEventRev1": _err_disabled_port,
        },
        auto_resolve_minutes=1440,
    ),
    TrapRule(
        key="port_security",
        name="Port security violation",
        description="An unknown MAC address reached a secure port; resolves 60 minutes after the last violation.",
        families=("Cisco (CISCO-PORT-SECURITY-MIB)",),
        severity="warning",
        raise_on={
            name: _first_of(_value("ifName"), _interface)
            for name in (
                "cpsSecureMacAddrViolation",
                "cpsTrunkSecureMacAddrViolation",
                "cpsIfVlanSecureMacAddrViolation",
            )
        },
        auto_resolve_minutes=60,
    ),
    TrapRule(
        key="mac_flap",
        name="MAC address flapping",
        description=(
            "3 MAC address moves in one VLAN within 10 minutes (CISCO-MAC-NOTIFICATION-MIB); resolves 30 minutes "
            "after the last move."
        ),
        families=("Cisco (CISCO-MAC-NOTIFICATION-MIB)",),
        severity="warning",
        raise_on={"cmnMacMoveNotification": _value("cmnMACMoveVlanNumber", "vlan")},
        threshold_count=3,
        threshold_window_seconds=600,
        auto_resolve_minutes=30,
    ),
    TrapRule(
        key="hsrp_state",
        name="HSRP failover",
        description=(
            "An HSRP group became active on this router or left the active or standby state; resolves 60 "
            "minutes after the last change."
        ),
        families=("Cisco (CISCO-HSRP-MIB)",),
        severity="warning",
        # The trap carries the new state only: initial (1), learn (2),
        # listen (3), speak (4) after leaving active or standby, active (6).
        # standby (5) is a router taking its normal backup role.
        raise_on={"cHsrpStateChange": _when("cHsrpGrpStandbyState", (1, 2, 3, 4, 6), _hsrp_group)},
        auto_resolve_minutes=60,
        repoll="state_change",
    ),
    TrapRule(
        key="eigrp_neighbor",
        name="EIGRP neighbor down",
        description=(
            "An EIGRP neighbor went down (CISCO-EIGRP-MIB has no neighbor up trap); resolves 24 hours after the "
            "last one."
        ),
        families=("Cisco (CISCO-EIGRP-MIB)",),
        severity="critical",
        raise_on={"cEigrpNbrDownEvent": _peer_value("cEigrpPeerAddr")},
        auto_resolve_minutes=1440,
        repoll="state_change",
    ),
    TrapRule(
        key="isis_adjacency",
        name="IS-IS adjacency down",
        description="An IS-IS adjacency went down or failed; resolved when it is up again.",
        families=("Every platform that sends ISIS-MIB", "Cisco (CISCO-IETF-ISIS-MIB)"),
        severity="critical",
        raise_on={
            "isisAdjacencyChange": _when(
                "isisAdjState", (1, 4), _isis_neighbor("isisPduLspId", "isisNotificationCircIfIndex")
            ),
            "ciiAdjacencyChange": _when("ciiAdjState", (1, 4), _isis_neighbor("ciiPduLspId", "ciiCircIfIndex")),
        },
        clear_on={
            "isisAdjacencyChange": _when(
                "isisAdjState", (3,), _isis_neighbor("isisPduLspId", "isisNotificationCircIfIndex")
            ),
            "ciiAdjacencyChange": _when("ciiAdjState", (3,), _isis_neighbor("ciiPduLspId", "ciiCircIfIndex")),
        },
        repoll="state_change",
    ),
    TrapRule(
        key="ipsec_tunnel",
        name="IPsec tunnel down",
        description="An IKE / VPN tunnel to a peer went down; resolved when a tunnel to that peer is up again.",
        families=("Cisco (CISCO-IPSEC-FLOW-MONITOR-MIB)", "Fortinet FortiOS (FORTINET-FORTIGATE-MIB)"),
        severity="critical",
        raise_on={"cikeTunnelStop": _peer_value("cikePeerRemoteAddr"), "fgTrapVpnTunDown": _FGT_VPN_PEER},
        clear_on={"cikeTunnelStart": _peer_value("cikePeerRemoteAddr"), "fgTrapVpnTunUp": _FGT_VPN_PEER},
    ),
    TrapRule(
        key="ip_sla",
        name="IP SLA probe down",
        description=(
            "An IP SLA operation reported a timeout, connection loss or verify error (CISCO-RTTMON-MIB "
            "rttMonNotification); resolved when the condition clears."
        ),
        families=("Cisco (CISCO-RTTMON-MIB)",),
        severity="warning",
        raise_on={
            "rttMonNotification": _all(_sla_reachability, instance=_when("rttMonReactOccurred", (1,), _SLA_PROBE))
        },
        clear_on={
            "rttMonNotification": _all(_sla_reachability, instance=_when("rttMonReactOccurred", (2,), _SLA_PROBE))
        },
    ),
    TrapRule(
        key="poe_fault",
        name="PoE fault",
        description=(
            "A PoE port reported a fault (POWER-ETHERNET-MIB detection status fault or otherFault); resolved when "
            "it delivers power again, or after 24 hours."
        ),
        families=("Every platform that sends POWER-ETHERNET-MIB",),
        severity="warning",
        raise_on={"pethPsePortOnOffNotification": _when("pethPsePortDetectionStatus", (4, 6), _POE_PORT)},
        clear_on={"pethPsePortOnOffNotification": _when("pethPsePortDetectionStatus", (3,), _POE_PORT)},
        auto_resolve_minutes=1440,
    ),
)

# Traps that announce the device is going down: their re-poll waits for the
# reload (the syslog reload delay), the others' does not.
_GOING_DOWN = frozenset({"nsNotifyShutdown", "ucdShutdown", "jnxDyingGasp", "panGeneralSystemShutdownTrap"})


# ── Configuration change ─────────────────────────────────────────────────────


def _always(_named: NamedTrap) -> bool:
    return True


# CISCO-CONFIG-MAN-MIB ccmHistoryEventConfigDestination running(3): the
# running configuration was changed (a copy to startup is a save, not a
# change). PAN-TRAPS panConfigTrap: a commit that succeeded (the syslog
# trigger's form: a candidate edit changes nothing yet).
CONFIG_CHANGE: dict[str, Callable[[NamedTrap], bool]] = {
    "ciscoConfigManEvent": lambda named: named.number("ccmHistoryEventConfigDestination") == 3,
    "ccmCLIRunningConfigChanged": _always,
    "jnxCmCfgChange": _always,
    "fgFmTrapConfChange": _always,
    "arubaWiredConfigurationChangeNotification": _always,
    "panConfigTrap": lambda named: (
        named.label("panConfigCmd").strip().lower() == "commit"
        and named.label("panConfigResult").strip().lower() == "succeeded"
    ),
}


def is_config_change(named: NamedTrap) -> bool:
    check = CONFIG_CHANGE.get(named.name)
    return check is not None and check(named)


# ── Evaluation ───────────────────────────────────────────────────────────────


def effects(named: NamedTrap) -> list[tuple[TrapRule, str, str]]:
    """What the built-in rules (as shipped, enabled or not) do with a trap:
    ``(rule, action, instance)``."""
    out: list[tuple[TrapRule, str, str]] = []
    if not named.name:
        return out
    for rule in TRAP_RULES:
        for action in (RAISE, CLEAR):
            instance = rule.match(action, named)
            if instance is not None:
                out.append((rule, action, instance))
                break
    return out


def repoll_delay(named: NamedTrap) -> float | None:
    """Seconds to the re-poll a trap starts (it names a state change a rule
    acts on), None for none."""
    for rule, _action, _instance in effects(named):
        if not rule.repoll:
            continue
        return engine.RELOAD_REPOLL_DELAY_SECONDS if named.name in _GOING_DOWN else engine.REPOLL_DELAY_SECONDS
    return None


# Re-poll kinds after which the hardware may have changed.
_HARDWARE_REPOLLS = frozenset({"module", "restart"})


def hardware_may_have_changed(named: NamedTrap) -> bool:
    """Whether a trap says a module went down or came online, or the device
    restarted or is going down: its hardware components are read again at
    the next poll that reaches it."""
    if named.name in _GOING_DOWN:
        return True
    return any(rule.repoll in _HARDWARE_REPOLLS for rule, _action, _instance in effects(named))


def event_fields(named: NamedTrap) -> tuple[str, str, str]:
    """``(severity, oid, message)`` a trap is stored with: a trap a rule
    raises on gets the rule's severity, one that clears a rule ``info``,
    any other the registry's severity (``info`` when unknown)."""
    severity = named.severity
    found = effects(named)
    if found:
        rule, action, _instance = found[0]
        severity = rule.severity if action == RAISE else "info"
    return severity, named.trap_oid, named.message


def _matcher(rule: TrapRule, action: str) -> Callable[[NamedTrap], str | None]:
    return partial(rule.match, action)


def _rule(rule: TrapRule, override: dict | None) -> engine.Rule:
    return engine.Rule(
        key=rule.key,
        name=rule.name,
        builtin=True,
        threshold_count=rule.threshold_count,
        threshold_window_seconds=rule.threshold_window_seconds,
        auto_resolve_minutes=rule.auto_resolve_minutes,
        raise_match=_matcher(rule, RAISE),
        clear_match=_matcher(rule, CLEAR) if rule.clear_on else None,
        description=rule.description,
        families=rule.families,
        match_type="builtin",
        tags=tuple(sorted(rule.raise_on)),
        clear_tags=tuple(sorted(rule.clear_on)),
        source=SOURCE,
        **engine.builtin_override(override, rule.severity),
    )


def merge_rules(rows: list[dict]) -> list[engine.Rule]:
    """The built-in trap rules with their stored overrides (rows of
    ``syslog_alert_rules`` whose ``builtin_key`` is ``trap_<key>``), then the
    custom trap rules (rows with ``source`` ``trap`` and no ``builtin_key``).
    A custom row that no longer compiles is skipped (logged); a custom
    syslog rule's row is not a trap rule."""
    overrides = {r["builtin_key"]: r for r in rows if r.get("builtin_key")}
    rules = [_rule(r, overrides.get(engine.metric_name(r.key, SOURCE))) for r in TRAP_RULES]
    for row in rows:
        if row.get("builtin_key") or row.get("source") != SOURCE:
            continue
        try:
            rules.append(custom_trap_rule(row))
        except (ValueError, KeyError) as exc:
            LOGGER.warning("trap rules: custom rule %s skipped: %s", row.get("id"), exc)
    return rules


async def get_rules() -> list[engine.Rule]:
    """Every trap rule, enabled or not (the stored rows are cached by the
    syslog engine, ``syslog_rules.rule_rows``)."""
    return merge_rules(await engine.rule_rows())


def _monitoring_enabled() -> bool:
    return bool(state.MONITORING_CONFIG.get("enabled"))


# ── CISCO-SYSLOG-MIB clogMessageGenerated: the syslog line it carries ────────

CLOG_TRAP = "clogMessageGenerated"
# The facility and mnemonic forms parse_syslog_message reads in a Cisco tag
# (an IOS XR facility has up to four parts: ROUTING-BGP).
_CLOG_FACILITY = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z][A-Za-z0-9_]*){0,3}")
_CLOG_MNEMONIC = re.compile(r"[A-Za-z0-9_]+")
_CLOG_TEXT_MAX = 1000


def _varbind_text(named: NamedTrap, obj: str) -> str:
    """The text of varbind ``obj``: its value as decoded (an octet string
    that is not plain text: its printable label), whitespace collapsed."""
    found = named.get(obj)
    if found is None:
        return ""
    text = found.label if found.value.startswith("0x") else found.value
    return " ".join(text.split())[:_CLOG_TEXT_MAX]


def clog_syslog_line(named: NamedTrap) -> str | None:
    """The Cisco syslog line a ``clogMessageGenerated`` trap carries,
    ``%FACILITY-SEVERITY-MNEMONIC: text`` (``clogHistFacility``,
    ``clogHistSeverity`` emergency(1) .. debug(8) as the syslog digit 0 .. 7,
    ``clogHistMsgName``, ``clogHistMsgText``), the form
    ``syslog_rules.parse_syslog_message`` reads; None for another trap or
    one whose varbinds do not make a tag."""
    if named.name != CLOG_TRAP:
        return None
    facility = _varbind_text(named, "clogHistFacility")
    mnemonic = _varbind_text(named, "clogHistMsgName")
    severity = named.number("clogHistSeverity")
    if (
        severity is None
        or not 1 <= severity <= 8
        or not _CLOG_FACILITY.fullmatch(facility)
        or not _CLOG_MNEMONIC.fullmatch(mnemonic)
    ):
        return None
    return f"%{facility}-{severity - 1}-{mnemonic}: {_varbind_text(named, 'clogHistMsgText')}"


# ── Custom trap rules ────────────────────────────────────────────────────────
#
# A custom trap rule is a row of ``syslog_alert_rules`` with ``source``
# ``trap`` (migration 0138): ``pattern`` names the traps that raise it and
# ``clear_pattern`` the ones that clear it (comma separated: a trap OID, an
# OID prefix ``<OID>.*``, or a registry name), and the JSON ``trap_match``
# holds the varbind conditions of each side and the varbind that names the
# instance. It becomes an ``engine.Rule`` (``source`` ``trap``, key
# ``custom_<id>``, metric ``trap_custom_<id>``) counted, raised, resolved
# and auto-resolved with the built-in trap rules.

MATCH_TYPE = "trap"
CONDITION_OPS: tuple[str, ...] = ("equals", "contains", "regex")
INSTANCE_PARTS: tuple[str, ...] = ("value", "index")
CONDITIONS_MAX = 10
VALUE_MAX = 200
TRAP_SPEC_MAX = 500

_OID = re.compile(r"\d+(?:\.\d+)+")
_TRAP_NAMES: dict[str, str] = {t.name.lower(): t.name for t in TRAPS_BY_OID.values()}
_OBJECT_NAMES: dict[str, str] = {name.lower(): name for name in OBJECTS}


def _trap_oid_forms(trap_oid: str) -> tuple[str, ...]:
    """A trap OID and, for a v1 trap's ``enterprise.0.specific``, the
    notification OID without the ``0`` (``snmp_traps.lookup``'s rule)."""
    oid = trap_oid.strip().lstrip(".")
    head, _sep, last = oid.rpartition(".")
    if head.endswith(".0") and last.isdigit():
        return oid, f"{head[:-2]}.{last}"
    return (oid,)


@dataclass(frozen=True)
class TrapSpec:
    """The traps a custom rule side takes: registry names, exact OIDs and
    OID prefixes (each ending with a dot)."""

    names: frozenset[str] = frozenset()
    oids: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()

    def matches(self, named: NamedTrap) -> bool:
        if named.name and named.name in self.names:
            return True
        forms = _trap_oid_forms(named.trap_oid)
        return any(f in self.oids or f.startswith(self.prefixes) for f in forms)


def _spec_token(token: str, label: str) -> str:
    """One trap of a pattern in its stored form, or ``RuleError``."""
    if token.endswith(".*"):
        oid = token[:-2].lstrip(".")
        if not _OID.fullmatch(oid):
            raise RuleError(f"The {label} has an OID prefix that is not a dotted OID: {token}")
        return f"{oid}.*"
    if token.lstrip(".")[:1].isdigit():
        oid = token.lstrip(".")
        if not _OID.fullmatch(oid):
            raise RuleError(f"The {label} has an OID that is not a dotted OID: {token}")
        return oid
    name = _TRAP_NAMES.get(token.lower())
    if name is None:
        raise RuleError(f"The {label} names a trap the registry does not know: {token}. Use its OID instead.")
    return name


def _clean_spec(raw: object, label: str, *, required: bool) -> str:
    """A pattern in its stored form (comma separated, each trap once), or
    ``RuleError``."""
    text = str(raw or "").strip()
    if len(text) > TRAP_SPEC_MAX:
        raise RuleError(f"The {label} is longer than {TRAP_SPEC_MAX} characters.")
    tokens: list[str] = []
    for token in re.split(r"[,\s]+", text):
        if token and (cleaned := _spec_token(token, label)) not in tokens:
            tokens.append(cleaned)
    if required and not tokens:
        raise RuleError(f"The rule needs a {label}: a trap OID, an OID prefix ending in .* or a trap name.")
    return ", ".join(tokens)


def _spec(stored: str) -> TrapSpec:
    names, oids, prefixes = set(), set(), []
    for token in (t.strip() for t in stored.split(",")):
        if token.endswith(".*"):
            prefixes.append(token[:-1])
        elif token[:1].isdigit():
            oids.add(token)
        elif token:
            names.add(token)
    return TrapSpec(frozenset(names), frozenset(oids), tuple(prefixes))


def _clean_object(raw: object, label: str) -> str:
    """A varbind object: a registry object name (as the registry spells it)
    or a dotted OID; ``RuleError`` otherwise."""
    text = str(raw or "").strip()
    if text.lstrip(".")[:1].isdigit():
        oid = text.lstrip(".")
        if not _OID.fullmatch(oid):
            raise RuleError(f"The {label} is not a dotted OID: {text}")
        return oid
    name = _OBJECT_NAMES.get(text.lower())
    if name is None:
        raise RuleError(f"The {label} names an object the registry does not know: {text}. Use its OID instead.")
    return name


def _clean_conditions(raw: object, label: str) -> list[dict]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RuleError(f"The {label} must be a list.")
    if len(raw) > CONDITIONS_MAX:
        raise RuleError(f"The {label} hold at most {CONDITIONS_MAX} conditions.")
    out = []
    for item in raw:
        if not isinstance(item, dict):
            raise RuleError(f"Each of the {label} must be an object.")
        op = str(item.get("op") or "equals").strip()
        if op not in CONDITION_OPS:
            raise RuleError(f"A condition's op must be one of: {', '.join(CONDITION_OPS)}.")
        value = str(item.get("value") if item.get("value") is not None else "").strip()
        if len(value) > VALUE_MAX:
            raise RuleError(f"A condition's value is longer than {VALUE_MAX} characters.")
        if op == "regex":
            try:
                compile_user_regex(value)
            except ValueError as exc:
                raise RuleError(f"A condition's value is not a valid regular expression: {exc}") from None
        elif not value:
            raise RuleError("A condition needs a value.")
        out.append({"object": _clean_object(item.get("object"), "condition's varbind"), "op": op, "value": value})
    return out


def _clean_instance_spec(raw: object) -> dict:
    if raw in (None, ""):
        return {"object": "", "part": "value"}
    if not isinstance(raw, dict):
        raise RuleError("The instance must be an object.")
    part = str(raw.get("part") or "value").strip()
    if part not in INSTANCE_PARTS:
        raise RuleError(f"The instance part must be one of: {', '.join(INSTANCE_PARTS)}.")
    text = str(raw.get("object") or "").strip()
    return {"object": _clean_object(text, "instance varbind") if text else "", "part": part}


def clean_custom_trap_rule(body: dict) -> dict:
    """The stored values of a custom trap rule from an API body, or
    ``RuleError``: the shared settings (``syslog_rules.clean_rule_settings``),
    ``pattern`` (the raising traps), ``clear_pattern`` (the clearing traps,
    optional) and ``trap_match`` (``conditions``, ``clear_conditions``: the
    varbind conditions, all of which must hold; ``instance``: ``object``, ""
    for one alert per device, and ``part``, ``value`` or ``index``). Regex
    conditions are compiled with RE2 here, never on the receive path."""
    settings = engine.clean_rule_settings(body)
    match = body.get("trap_match")
    match = {} if match is None else match
    if not isinstance(match, dict):
        raise RuleError("trap_match must be an object.")
    clear_pattern = _clean_spec(body.get("clear_pattern"), "clearing trap", required=False)
    clear_conditions = _clean_conditions(match.get("clear_conditions"), "clearing conditions")
    if clear_conditions and not clear_pattern:
        raise RuleError("Clearing conditions need a clearing trap.")
    return {
        **settings,
        "match_type": MATCH_TYPE,
        "pattern": _clean_spec(body.get("pattern"), "trap", required=True),
        "clear_pattern": clear_pattern,
        "trap_match": {
            "conditions": _clean_conditions(match.get("conditions"), "conditions"),
            "clear_conditions": clear_conditions,
            "instance": _clean_instance_spec(match.get("instance")),
        },
    }


def _under(obj: str, varbind: Varbind) -> bool:
    """Whether ``varbind`` is under ``obj`` (an object name or an OID)."""
    if obj[:1].isdigit():
        return varbind.oid.lstrip(".") == obj or varbind.oid.lstrip(".").startswith(obj + ".")
    return varbind.name == obj


def _condition(item: dict) -> Callable[[NamedTrap], bool]:
    """A condition: some varbind under its object has a value (or label)
    that equals / contains / matches (RE2, ignoring case) its value."""
    obj, op, wanted = item["object"], item["op"], str(item["value"])
    test: Callable[[str], bool]
    if op == "regex":
        compiled = compile_user_regex(wanted)
        test = lambda text: compiled.search(text) is not None  # noqa: E731 - a one-line test
    elif op == "contains":
        needle = wanted.casefold()
        test = lambda text: needle in text.casefold()  # noqa: E731
    else:
        folded = wanted.casefold()
        test = lambda text: text.casefold() == folded  # noqa: E731

    def holds(named: NamedTrap) -> bool:
        return any(_under(obj, vb) and (test(vb.label) or test(vb.value)) for vb in named.varbinds)

    return holds


def _instance_fn(spec: dict | None) -> InstanceFn:
    """The instance a custom rule names: the value (or the index, after the
    object's name) of the first varbind under its object; the device ("")
    when it has none or the trap lacks it."""
    obj = str((spec or {}).get("object") or "")
    if not obj:
        return _device
    by_index = (spec or {}).get("part") == "index"

    def instance(named: NamedTrap) -> str:
        found = next((vb for vb in named.varbinds if _under(obj, vb)), None)
        if found is None:
            return ""
        if not by_index:
            return engine._clean_instance(found.label)
        index = found.index if found.name == obj else found.oid.lstrip(".")[len(obj) + 1 :]
        return engine._clean_instance(f"{obj} {index}") if index else ""

    return instance


def _custom_side(spec: str, conditions: list[dict], instance: InstanceFn) -> Callable[[NamedTrap], str | None]:
    traps = _spec(spec)
    checks = [_condition(c) for c in conditions]

    def match(named: NamedTrap) -> str | None:
        if not traps.matches(named) or not all(check(named) for check in checks):
            return None
        return instance(named)

    return match


def _trap_matchers(row: dict) -> tuple[engine.MatchFn, engine.MatchFn | None]:
    match = row.get("trap_match") or {}
    instance = _instance_fn(match.get("instance"))
    clear = row.get("clear_pattern") or ""
    return (
        _custom_side(row["pattern"], match.get("conditions") or [], instance),
        _custom_side(clear, match.get("clear_conditions") or [], instance) if clear else None,
    )


def custom_trap_rule(row: dict, key: str | None = None) -> engine.Rule:
    """The ``engine.Rule`` of a stored (or cleaned) custom trap rule row;
    ValueError when a regex condition no longer compiles."""
    return engine.custom_rule(
        row, key, matchers=_trap_matchers, source=SOURCE, trap_match=dict(row.get("trap_match") or {})
    )


def draft_rule(body: dict) -> engine.Rule:
    """A custom trap rule from an unsaved API body (the test route), or
    ``RuleError``."""
    return custom_trap_rule({**clean_custom_trap_rule(body), "id": None}, key="draft")


async def process_trap_batch(rows: Iterable[tuple[int, NamedTrap]]) -> dict:
    """Act on received traps of inventory hosts whose community matched (or
    that an SNMPv3 user authenticated): ``rows`` of ``(host_id, NamedTrap)``.
    A ``clogMessageGenerated`` trap's syslog line then goes through the
    syslog rules (``syslog_rules.process_syslog_batch``: its alerts are
    syslog alerts, under the syslog switches). Returns counts, of both:
    ``raised`` (alerts raised or bumped), ``resolved``, ``repolls``
    (scheduled), ``config_changes``."""
    rows = list(rows)
    outcome = await _process_traps(rows)
    lines = [(host_id, line) for host_id, named in rows if (line := clog_syslog_line(named)) is not None]
    if lines:
        for key, count in (await engine.process_syslog_batch(lines)).items():
            outcome[key] = outcome.get(key, 0) + count
    return outcome


async def _process_traps(rows: list[tuple[int, NamedTrap]]) -> dict:
    """The trap rules and the trap triggers on ``rows``. A trap the registry
    does not name reaches the custom rules (by its OID) only."""
    outcome = {"raised": 0, "resolved": 0, "repolls": 0, "config_changes": 0}
    monitoring = _monitoring_enabled()
    alerts_on = monitoring and engine.receiver_flag("trap_alerts")
    repoll_on = monitoring and engine.receiver_flag("repoll_trigger")
    config_on = engine.receiver_flag("config_change_trigger")
    if not (alerts_on or repoll_on or config_on):
        return outcome
    rules = [r for r in await get_rules() if r.enabled] if alerts_on else []
    actions: list[tuple[bool, engine.Rule, int, str, NamedTrap]] = []
    for host_id, named in rows:
        now = engine._clock()
        for rule in rules:
            step = engine.track(rule, host_id, named, now)
            if step is not None:
                actions.append((step[0], rule, host_id, step[1], named))
        if repoll_on:
            if hardware_may_have_changed(named):
                mark_hardware_stale(host_id)
            delay = repoll_delay(named)
            if delay is not None and schedule_repoll(host_id, delay, min_interval=engine.REPOLL_MIN_INTERVAL_SECONDS):
                outcome["repolls"] += 1
        if config_on and is_config_change(named):
            engine.note_config_change(host_id)
            outcome["config_changes"] += 1
    if actions:
        await engine.apply_actions(actions, outcome)
    return outcome


async def resolve_expired_alerts() -> int:
    """Resolve the open trap alerts of every rule with an auto-resolve time
    that have not been seen again for that long."""
    return await engine.resolve_expired_rule_alerts(await get_rules())


# ── Test: what the rules would do with a trap ────────────────────────────────


def decode_stored_trap(raw_data: object) -> dict | None:
    """The decoded v1 / v2c trap of a stored event's ``raw_data`` (the hex
    of the datagram's first 1000 bytes), or None: an SNMPv3 datagram (its
    keys are not kept with it), one cut at 1000 bytes, or no trap."""
    try:
        data = bytes.fromhex(str(raw_data or ""))
    except ValueError:
        return None
    return decode_snmp_trap(data) if data else None


async def explain_trap(named: NamedTrap, draft: dict | None = None) -> dict:
    """What the engine would do with a trap: its name and varbinds, the trap
    rules it raises or clears (built-in and custom, enabled or not, with
    the instance), ``draft`` (an unsaved custom trap rule, ``RuleError``
    when invalid), the triggers it starts and, for a
    ``clogMessageGenerated`` trap, the syslog line it carries and what the
    syslog rules do with it (``syslog_rules.explain_message``)."""
    draft_result = None
    if draft is not None:
        draft_result = engine.evaluate_rule(draft_rule(draft), named) or {"action": "", "instance": ""}
    matches = []
    for rule in await get_rules():
        found = engine.evaluate_rule(rule, named)
        if found:
            matches.append(
                {"key": rule.key, "name": rule.name, "builtin": rule.builtin, "enabled": rule.enabled, **found}
            )
    line = clog_syslog_line(named)
    return {
        "name": named.name,
        "trap_oid": named.trap_oid,
        "message": named.message,
        "varbinds": [
            {"oid": vb.oid, "name": vb.name, "index": vb.index, "value": vb.value, "label": vb.label}
            for vb in named.varbinds
        ],
        "matches": matches,
        "draft": draft_result,
        "config_change": is_config_change(named),
        "repoll": repoll_delay(named) is not None,
        "syslog_line": line or "",
        "syslog": await engine.explain_message(line) if line else None,
    }


# ── Restart: the trap threshold counters restored ────────────────────────────


def _believed_stored_trap(row: dict, hosts: dict[int, dict]) -> NamedTrap | None:
    """The named trap of a stored trap event when the rules would have acted
    on it: decoded again from its ``raw_data``, not an APC trap (those have
    their own handler) and carrying the community stored for its inventory
    host now. The stored row does not record whether a trap was believed
    (a v1 / v2c trap with the wrong community is dropped, never stored, but
    an undecodable one and every SNMPv3 one are stored all the same), so
    each is checked again; an SNMPv3 trap, whose keys are not kept, is
    never counted."""
    host = hosts.get(int(row["host_id"]))
    trap = decode_stored_trap(row.get("raw_data"))
    if host is None or trap is None or parse_apc_trap(trap) is not None or not trap_community_matches(trap, host):
        return None
    return name_trap(trap)


async def _restore_counters(trap_rules_: list[engine.Rule], syslog_rules_: list[engine.Rule]) -> int:
    """Replay the stored believed traps of inventory hosts through the
    counters of ``trap_rules_``, and the syslog line of each
    ``clogMessageGenerated`` trap through those of ``syslog_rules_``, each
    at its age before now (``syslog_rules.replay_stored``). Returns how many
    traps were replayed."""
    window = engine.restore_window([*trap_rules_, *syslog_rules_])
    rows = await db.list_syslog_messages_since(
        window, limit=engine.RESTORE_ROWS_MAX, hosts_only=True, event_type="trap"
    )
    if not rows:
        return 0
    hosts = {int(h["id"]): h for h in await db.get_hosts_by_ids(sorted({int(r["host_id"]) for r in rows}))}

    def replay(row: dict, at: float) -> bool:
        named = _believed_stored_trap(row, hosts)
        if named is None:
            return False
        host_id = int(row["host_id"])
        engine.track_all(trap_rules_, host_id, named, at)
        line = clog_syslog_line(named) if syslog_rules_ else None
        if line is not None:
            engine.track_all(syslog_rules_, host_id, engine.parse_syslog_message(line), at)
        return True

    return await engine.replay_stored(rows, replay)


async def restore_state() -> dict:
    """Rebuild the threshold counters a restart forgot from the stored traps
    (``trap_syslog_events``): those of the enabled trap rules with a
    threshold (monitoring on and ``trap_alerts`` on) and, from the syslog
    line of a ``clogMessageGenerated`` trap, those of the syslog rules
    (``syslog_alerts`` on). Only a trap the rules would have acted on is
    counted (``_believed_stored_trap``). Called once at startup in the
    process whose trap receiver listens. Raises, resolves and schedules
    nothing; never raises (a failure is logged). Returns counts: ``traps``
    replayed."""
    outcome = {"traps": 0}
    try:
        if _monitoring_enabled():
            trap_rules_ = engine.threshold_rules(await get_rules()) if engine.receiver_flag("trap_alerts") else []
            syslog_rules_ = (
                engine.threshold_rules(await engine.get_rules()) if engine.receiver_flag("syslog_alerts") else []
            )
            if trap_rules_ or syslog_rules_:
                outcome["traps"] = await _restore_counters(trap_rules_, syslog_rules_)
    except Exception as exc:  # noqa: BLE001 - a failed restore must not block startup
        LOGGER.warning("trap rules: state restore failed: %s", exc)
    if outcome["traps"]:
        LOGGER.info("trap rules: restored threshold counters from %d stored traps", outcome["traps"])
    return outcome
