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
  delays and per-host interval).

The rule engine is the syslog one (``netcontrol.syslog_rules``): these rules
are ``Rule`` objects with ``source`` ``trap``, counted, raised, resolved,
auto-resolved, enabled / disabled and given a severity override exactly as
the built-in syslog rules are (the override row is stored in
``syslog_alert_rules`` under ``builtin_key`` ``trap_<key>``). Trap alerts are
their own family: no syslog or polled alert suppresses, resolves or is
resolved by them.

Switches (``state.EVENT_RECEIVER_CONFIG``, on when unset): ``trap_alerts``
(the alerts), ``repoll_trigger`` and ``config_change_trigger`` (shared with
syslog). Alerts and re-polls also need monitoring to be on.

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

import netcontrol.routes.state as state
from netcontrol import syslog_rules as engine
from netcontrol.monitoring_repoll import mark_hardware_stale, schedule_repoll
from netcontrol.snmp_traps import NamedTrap

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
    ``syslog_alert_rules`` whose ``builtin_key`` is ``trap_<key>``)."""
    overrides = {r["builtin_key"]: r for r in rows if r.get("builtin_key")}
    return [_rule(r, overrides.get(engine.metric_name(r.key, SOURCE))) for r in TRAP_RULES]


async def get_rules() -> list[engine.Rule]:
    """Every trap rule, enabled or not (the stored rows are cached by the
    syslog engine, ``syslog_rules.rule_rows``)."""
    return merge_rules(await engine.rule_rows())


def _monitoring_enabled() -> bool:
    return bool(state.MONITORING_CONFIG.get("enabled"))


async def process_trap_batch(rows: Iterable[tuple[int, NamedTrap]]) -> dict:
    """Act on received traps of inventory hosts whose community matched:
    ``rows`` of ``(host_id, NamedTrap)``. Returns counts: ``raised``
    (alerts raised or bumped), ``resolved``, ``repolls`` (scheduled),
    ``config_changes``."""
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
        if not named.name:
            continue
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
