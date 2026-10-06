"""Meraki security compliance - check catalog, lean collector and evaluator.

The Compliance feature audits IOS devices by matching text patterns against
the running configuration. A Meraki organization has no running config: its
configuration is the set of Dashboard API objects. This module gives the
feature the Meraki equivalents of the usual switch/firewall/wireless hardening
controls as *checks* against those objects:

  ======================================  =========================================
  IOS control                             Meraki equivalent (Dashboard API object)
  ======================================  =========================================
  ``ip dhcp snooping``                    switch DHCP server policy ``defaultPolicy: block``
  ``ip arp inspection``                   DHCP server policy ``arpInspection.enabled``
  ``switchport port-security`` / 802.1X   switch port ``accessPolicyType`` (sticky MAC,
                                          MAC allow list, 802.1X access policy)
  ``spanning-tree bpduguard``             switch port ``stpGuard: "bpdu guard"``
  ``spanning-tree guard root|loop``       switch port ``stpGuard: "root guard" | "loop guard"``
  ``storm-control``                       network storm control thresholds
  ``switchport trunk native vlan``        trunk port ``vlan`` (native VLAN)
  ``switchport trunk allowed vlan``       trunk port ``allowedVlans``
  ``shutdown`` on unused ports            disconnected port ``enabled: false``
  ``ip verify unicast source`` (uRPF)     MX firewall settings IP source guard
  IPS / AMP                               MX intrusion ``mode: prevention``, malware ``enabled``
  ``no ip http server`` / ``snmp-server`` MX firewalled services ``web`` / ``SNMP`` blocked
  ``logging host``                        network syslog servers
  SNMPv3 only                             network / organization SNMP settings
  AAA 2FA, lockout, idle timeout          organization login security and admin 2FA
  ======================================  =========================================

A profile rule that names a check looks like::

    {"name": "DHCP snooping", "type": "meraki", "check": "switch_dhcp_server_policy",
     "params": {}}

``evaluate_profile`` is pure: it takes the payloads ``collect_compliance_data``
gathered (or :func:`build_sample_compliance_raw`) and returns one result per
*target* - the organization for organization-level checks, each network for
network-level checks, each switch for port checks, each enabled SSID for
wireless checks - with a finding per check.
Plexus stays a read-only observer of the organization: there is no
remediation for Meraki findings; the finding says what to change in the
Dashboard.
"""

from __future__ import annotations

import asyncio
import copy
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.client import MerakiApiError, MerakiClient
from netcontrol.integrations.meraki.collector import _device_kind, _network_selected, sanitize_options, scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.meraki.compliance")

RULE_TYPE = "meraki"

SCOPE_ORG = "org"
SCOPE_NETWORK = "network"
SCOPE_DEVICE = "device"
SCOPE_SSID = "ssid"
SCOPES = (SCOPE_ORG, SCOPE_NETWORK, SCOPE_DEVICE, SCOPE_SSID)

CATEGORIES = {
    "switching": "Switching (MS)",
    "appliance": "Security appliance (MX)",
    "wireless": "Wireless (MR)",
    "network": "Network services",
    "organization": "Dashboard and organization",
}

_MAX_EVIDENCE = 50
_NOT_APPLICABLE_STATUSES = {400, 404}


class Unreadable:
    """Marks a payload the collector could not read (403, 5xx, transport).

    Distinct from ``None`` (endpoint not applicable to this network/device), so
    a check can report *unknown* rather than silently pass or fail."""

    __slots__ = ("message",)

    def __init__(self, message: str) -> None:
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Unreadable({self.message!r})"


# ── Endpoint catalog ─────────────────────────────────────────────────────────
#
# key -> (scope, path template, paginated, product types / device kinds it
# applies to; empty = always). Paths are relative to the API base URL and use
# ``{org}``, ``{net}`` and ``{serial}`` placeholders.

ENDPOINTS: dict[str, tuple[str, str, bool, tuple[str, ...]]] = {
    # organization
    "admins": (SCOPE_ORG, "organizations/{org}/admins", False, ()),
    "login_security": (SCOPE_ORG, "organizations/{org}/loginSecurity", False, ()),
    "org_snmp": (SCOPE_ORG, "organizations/{org}/snmp", False, ()),
    # organization-wide switch port configuration, consumed per device
    "switch_ports": (SCOPE_ORG, "organizations/{org}/switch/ports/bySwitch", True, ("switch",)),
    # network - switching
    "dhcp_server_policy": (SCOPE_NETWORK, "networks/{net}/switch/dhcpServerPolicy", False, ("switch",)),
    "stp": (SCOPE_NETWORK, "networks/{net}/switch/stp", False, ("switch",)),
    "storm_control": (SCOPE_NETWORK, "networks/{net}/switch/stormControl", False, ("switch",)),
    # network - appliance
    "firewall_settings": (SCOPE_NETWORK, "networks/{net}/appliance/firewall/settings", False, ("appliance",)),
    "intrusion": (SCOPE_NETWORK, "networks/{net}/appliance/security/intrusion", False, ("appliance",)),
    "malware": (SCOPE_NETWORK, "networks/{net}/appliance/security/malware", False, ("appliance",)),
    "firewalled_services": (
        SCOPE_NETWORK,
        "networks/{net}/appliance/firewall/firewalledServices",
        False,
        ("appliance",),
    ),
    "port_forwarding": (
        SCOPE_NETWORK,
        "networks/{net}/appliance/firewall/portForwardingRules",
        False,
        ("appliance",),
    ),
    "one_to_one_nat": (SCOPE_NETWORK, "networks/{net}/appliance/firewall/oneToOneNatRules", False, ("appliance",)),
    "l3_firewall": (SCOPE_NETWORK, "networks/{net}/appliance/firewall/l3FirewallRules", False, ("appliance",)),
    "content_filtering": (SCOPE_NETWORK, "networks/{net}/appliance/contentFiltering", False, ("appliance",)),
    # network - wireless (the SSID list; SSID checks are evaluated per enabled SSID)
    "ssids": (SCOPE_NETWORK, "networks/{net}/wireless/ssids", False, ("wireless",)),
    # SSID - one call per enabled SSID; only when a check needs it
    "ssid_l3_firewall": (
        SCOPE_SSID,
        "networks/{net}/wireless/ssids/{number}/firewall/l3FirewallRules",
        False,
        ("wireless",),
    ),
    # network - services (any product)
    "syslog": (SCOPE_NETWORK, "networks/{net}/syslogServers", False, ()),
    "net_snmp": (SCOPE_NETWORK, "networks/{net}/snmp", False, ()),
    "alerts": (SCOPE_NETWORK, "networks/{net}/alerts/settings", False, ()),
    # device - live port status (one call per switch; only when a check needs it)
    "port_statuses": (SCOPE_DEVICE, "devices/{serial}/switch/ports/statuses", False, ("switch",)),
}

Evaluator = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], tuple[bool, str, list[str]]]


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    scope: str
    category: str
    description: str
    ios_equivalent: str
    requires: tuple[str, ...]
    evaluate: Evaluator
    params: dict[str, Any] = field(default_factory=dict)
    # Network product types (network scope) or device kinds (device scope)
    # the check applies to. Empty = every network / device.
    products: tuple[str, ...] = ()
    # Payloads the check uses when available but can do without (``None`` in
    # ``data`` when not collected, not applicable or unreadable).
    optional: tuple[str, ...] = ()


CHECKS: dict[str, Check] = {}


def _check(**kwargs: Any) -> Callable[[Evaluator], Evaluator]:
    def register(fn: Evaluator) -> Evaluator:
        check = Check(evaluate=fn, **kwargs)
        if check.scope not in SCOPES:
            raise ValueError(f"check {check.id}: bad scope {check.scope}")
        for key in check.requires + check.optional:
            if key not in ENDPOINTS and key not in ("device", "ports", "network", "ssid"):
                raise ValueError(f"check {check.id}: unknown endpoint {key}")
        CHECKS[check.id] = check
        return fn

    return register


# ── Small helpers ────────────────────────────────────────────────────────────


def _cap(items: list[str]) -> list[str]:
    if len(items) <= _MAX_EVIDENCE:
        return items
    return items[:_MAX_EVIDENCE] + [f"... and {len(items) - _MAX_EVIDENCE} more"]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _lower_set(values: Any) -> set[str]:
    if isinstance(values, str):
        values = [values]
    return {str(v).strip().lower() for v in values or [] if str(v).strip()}


def _port_label(port: dict) -> str:
    pid = str(port.get("portId") or port.get("number") or "?")
    name = str(port.get("name") or "").strip()
    return f"port {pid} ({name})" if name else f"port {pid}"


def _port_enabled(port: dict) -> bool:
    return port.get("enabled") is not False


def _port_type(port: dict) -> str:
    return str(port.get("type") or "").strip().lower()


def _port_exempt(port: dict, params: dict) -> bool:
    exempt = _lower_set(params.get("exempt_tags"))
    if exempt and exempt & _lower_set(port.get("tags")):
        return True
    pattern = str(params.get("exempt_name_pattern") or "").strip()
    if pattern:
        try:
            if re.search(pattern, str(port.get("name") or ""), re.IGNORECASE):
                return True
        except re.error:
            pass
    return False


def _ports(data: dict, params: dict, kind: str) -> list[dict]:
    """Enabled, non-exempt ports of ``kind`` (``access`` / ``trunk``)."""
    return [
        p
        for p in data.get("ports") or []
        if isinstance(p, dict) and _port_enabled(p) and _port_type(p) == kind and not _port_exempt(p, params)
    ]


def _parse_iso(stamp: Any) -> datetime | None:
    text = str(stamp or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


# ── Switching: network scope ─────────────────────────────────────────────────


@_check(
    id="switch_dhcp_server_policy",
    name="DHCP server policy blocks unknown servers (DHCP snooping)",
    scope=SCOPE_NETWORK,
    category="switching",
    description=(
        "The switch DHCP server policy must block DHCP servers by default so only the "
        "allowed servers can answer clients. This is the Meraki equivalent of DHCP snooping."
    ),
    ios_equivalent="ip dhcp snooping",
    requires=("dhcp_server_policy",),
    products=("switch",),
)
def _eval_dhcp_policy(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    policy = data["dhcp_server_policy"]
    default = str(policy.get("defaultPolicy") or "").lower()
    allowed = policy.get("allowedServers") or []
    if default == "block":
        return True, f"Default policy is block; {_plural(len(allowed), 'allowed server')}", []
    return (
        False,
        f"Default policy is '{default or 'unset'}' - any device can act as a DHCP server. "
        "Set Switching > DHCP servers & ARP to Block by default and list the trusted servers.",
        [str(s) for s in allowed],
    )


@_check(
    id="switch_dhcp_rogue_alert",
    name="Rogue DHCP server alerting enabled",
    scope=SCOPE_NETWORK,
    category="switching",
    description=(
        "An alert must be sent when an unknown DHCP server is seen: either the DHCP server "
        "policy's email alert or the network's 'rogue DHCP server' alert."
    ),
    ios_equivalent="ip dhcp snooping + logging of DHCP snooping violations",
    requires=("dhcp_server_policy", "alerts"),
    products=("switch",),
)
def _eval_dhcp_alert(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    policy = data["dhcp_server_policy"]
    policy_alert = bool(((policy.get("alerts") or {}).get("email") or {}).get("enabled"))
    network_alert = False
    for alert in (data["alerts"] or {}).get("alerts") or []:
        if isinstance(alert, dict) and str(alert.get("type") or "").lower() == "roguedhcp" and alert.get("enabled"):
            network_alert = True
    if policy_alert or network_alert:
        sources = [s for s, on in (("DHCP policy email alert", policy_alert), ("network alert", network_alert)) if on]
        return True, "Enabled via " + " and ".join(sources), []
    return False, "Neither the DHCP server policy email alert nor the 'Rogue DHCP server' network alert is enabled", []


@_check(
    id="switch_arp_inspection",
    name="Dynamic ARP inspection enabled",
    scope=SCOPE_NETWORK,
    category="switching",
    description="Dynamic ARP inspection must be enabled in the switch DHCP server policy.",
    ios_equivalent="ip arp inspection vlan",
    requires=("dhcp_server_policy",),
    products=("switch",),
)
def _eval_arp_inspection(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    policy = data["dhcp_server_policy"]
    arp = policy.get("arpInspection") or {}
    if arp.get("enabled"):
        return True, "ARP inspection enabled", []
    return False, "ARP inspection is disabled (Switching > DHCP servers & ARP)", []


@_check(
    id="switch_rstp_enabled",
    name="Rapid spanning tree enabled",
    scope=SCOPE_NETWORK,
    category="switching",
    description="RSTP must be enabled on the switch network.",
    ios_equivalent="spanning-tree mode rapid-pvst",
    requires=("stp",),
    products=("switch",),
)
def _eval_rstp(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    if data["stp"].get("rstpEnabled"):
        return True, "RSTP enabled", []
    return False, "RSTP is disabled", []


@_check(
    id="switch_stp_root_pinned",
    name="Spanning tree root bridge pinned",
    scope=SCOPE_NETWORK,
    category="switching",
    description=(
        "At least one switch or stack must carry an STP bridge priority below the default "
        "(32768) so the root bridge is deliberate rather than elected by MAC address."
    ),
    ios_equivalent="spanning-tree vlan <id> priority <n>",
    requires=("stp",),
    params={"max_priority": 32767},
    products=("switch",),
)
def _eval_root_pinned(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    limit = int(params.get("max_priority", 32767))
    pinned: list[str] = []
    for entry in data["stp"].get("stpBridgePriority") or []:
        if not isinstance(entry, dict):
            continue
        try:
            priority = int(entry.get("stpPriority"))
        except TypeError, ValueError:
            continue
        if priority <= limit:
            members = (
                list(entry.get("switches") or [])
                + list(entry.get("stacks") or [])
                + list(entry.get("switchProfiles") or [])
            )
            pinned.append(f"priority {priority}: {', '.join(str(m) for m in members) or 'unassigned'}")
    if pinned:
        return True, f"{_plural(len(pinned), 'priority assignment')} below {limit + 1}", pinned
    return False, "No switch has an STP priority below the default; the root bridge is elected by MAC address", []


@_check(
    id="switch_storm_control",
    name="Storm control thresholds configured",
    scope=SCOPE_NETWORK,
    category="switching",
    description=(
        "The network's storm control must cap broadcast traffic (a threshold below 100% of "
        "port bandwidth). Multicast and unknown unicast caps can be required as well."
    ),
    ios_equivalent="storm-control broadcast level",
    requires=("storm_control",),
    params={"max_broadcast_percent": 99, "require_multicast": False, "require_unknown_unicast": False},
    products=("switch",),
)
def _eval_storm_control(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    sc = data["storm_control"]

    def _pct(key: str) -> int:
        try:
            return int(sc.get(key, 100))
        except TypeError, ValueError:
            return 100

    broadcast, multicast, unknown = (
        _pct("broadcastThreshold"),
        _pct("multicastThreshold"),
        _pct("unknownUnicastThreshold"),
    )
    problems: list[str] = []
    if broadcast > int(params.get("max_broadcast_percent", 99)):
        problems.append(f"broadcast threshold {broadcast}% (100% = disabled)")
    if params.get("require_multicast") and multicast >= 100:
        problems.append("multicast threshold disabled")
    if params.get("require_unknown_unicast") and unknown >= 100:
        problems.append("unknown unicast threshold disabled")
    summary = f"broadcast {broadcast}%, multicast {multicast}%, unknown unicast {unknown}%"
    if problems:
        return False, "Storm control not enforced: " + "; ".join(problems), [summary]
    return True, f"Storm control configured ({summary})", []


# ── Switching: device (per switch) scope ─────────────────────────────────────


@_check(
    id="switch_port_access_policy",
    name="Access ports use an access policy (port security)",
    scope=SCOPE_DEVICE,
    category="switching",
    description=(
        "Every enabled access port must have an access policy - sticky MAC allow list, MAC "
        "allow list or an 802.1X/MAB access policy - rather than 'Open'. This is the Meraki "
        "equivalent of port security / 802.1X port control. Ports carrying one of the exempt "
        "tags, or whose name matches the exempt pattern, are skipped."
    ),
    ios_equivalent="switchport port-security / authentication port-control auto",
    requires=("ports",),
    params={
        "allowed_types": ["Sticky MAC allow list", "MAC allow list", "Custom access policy"],
        "exempt_tags": [],
        "exempt_name_pattern": "",
    },
    products=("switch",),
)
def _eval_port_access_policy(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    allowed = _lower_set(params.get("allowed_types"))
    ports = _ports(data, params, "access")
    bad = [
        f"{_port_label(p)}: {p.get('accessPolicyType') or 'Open'}"
        for p in ports
        if str(p.get("accessPolicyType") or "Open").lower() not in allowed
    ]
    if not ports:
        return True, "No enabled access ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled access port')} without an access policy", _cap(bad)
    return True, f"All {_plural(len(ports), 'enabled access port')} use an access policy", []


@_check(
    id="switch_port_mac_limit",
    name="Sticky MAC limit bounded",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Access ports with a sticky MAC allow list must learn at most the configured number of addresses.",
    ios_equivalent="switchport port-security maximum",
    requires=("ports",),
    params={"max_addresses": 5, "exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_mac_limit(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    limit = int(params.get("max_addresses", 5))
    sticky = [
        p
        for p in _ports(data, params, "access")
        if str(p.get("accessPolicyType") or "").lower() == "sticky mac allow list"
    ]
    bad: list[str] = []
    for p in sticky:
        try:
            current = int(p.get("stickyMacAllowListLimit"))
        except TypeError, ValueError:
            current = 0
        if current > limit or current <= 0:
            bad.append(f"{_port_label(p)}: limit {current or 'unset'}")
    if not sticky:
        return True, "No sticky MAC ports", []
    if bad:
        return (
            False,
            f"{len(bad)} of {_plural(len(sticky), 'sticky MAC port')} allow more than {limit} addresses",
            _cap(bad),
        )
    return True, f"All {_plural(len(sticky), 'sticky MAC port')} limited to {limit} addresses or fewer", []


@_check(
    id="switch_port_bpdu_guard",
    name="BPDU guard on access ports",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Every enabled access port must have STP guard set to BPDU guard.",
    ios_equivalent="spanning-tree bpduguard enable",
    requires=("ports",),
    params={"accepted": ["bpdu guard"], "exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_bpdu_guard(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    accepted = _lower_set(params.get("accepted")) or {"bpdu guard"}
    ports = _ports(data, params, "access")
    bad = [
        f"{_port_label(p)}: {p.get('stpGuard') or 'disabled'}"
        for p in ports
        if str(p.get("stpGuard") or "disabled").lower() not in accepted
    ]
    if not ports:
        return True, "No enabled access ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled access port')} without BPDU guard", _cap(bad)
    return True, f"BPDU guard on all {_plural(len(ports), 'enabled access port')}", []


@_check(
    id="switch_port_uplink_guard",
    name="Root or loop guard on trunk ports",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Every enabled trunk port must have STP guard set to root guard or loop guard.",
    ios_equivalent="spanning-tree guard root / spanning-tree guard loop",
    requires=("ports",),
    params={"accepted": ["root guard", "loop guard"], "exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_uplink_guard(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    accepted = _lower_set(params.get("accepted")) or {"root guard", "loop guard"}
    ports = _ports(data, params, "trunk")
    bad = [
        f"{_port_label(p)}: {p.get('stpGuard') or 'disabled'}"
        for p in ports
        if str(p.get("stpGuard") or "disabled").lower() not in accepted
    ]
    if not ports:
        return True, "No enabled trunk ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled trunk port')} without root/loop guard", _cap(bad)
    return True, f"STP guard on all {_plural(len(ports), 'enabled trunk port')}", []


@_check(
    id="switch_port_native_vlan",
    name="Native VLAN is not VLAN 1",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Enabled trunk ports must not use a forbidden native VLAN (VLAN 1 by default).",
    ios_equivalent="switchport trunk native vlan <n> (n != 1)",
    requires=("ports",),
    params={"forbidden_vlans": [1], "exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_native_vlan(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    forbidden = {str(v) for v in params.get("forbidden_vlans") or [1]}
    ports = _ports(data, params, "trunk")
    bad = [f"{_port_label(p)}: native VLAN {p.get('vlan')}" for p in ports if str(p.get("vlan") or "1") in forbidden]
    if not ports:
        return True, "No enabled trunk ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled trunk port')} on a forbidden native VLAN", _cap(bad)
    return True, f"No trunk port uses VLAN {', '.join(sorted(forbidden))} as native", []


@_check(
    id="switch_port_trunk_pruned",
    name="Trunk ports restrict allowed VLANs",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Enabled trunk ports must list their allowed VLANs instead of carrying all VLANs.",
    ios_equivalent="switchport trunk allowed vlan <list>",
    requires=("ports",),
    params={"exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_trunk_pruned(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    ports = _ports(data, params, "trunk")
    bad = [_port_label(p) for p in ports if str(p.get("allowedVlans") or "all").strip().lower() == "all"]
    if not ports:
        return True, "No enabled trunk ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled trunk port')} allow all VLANs", _cap(bad)
    return True, f"All {_plural(len(ports), 'enabled trunk port')} restrict their VLANs", []


@_check(
    id="switch_port_dai_trusted",
    name="Only trunk ports are ARP-inspection trusted",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Access ports must not be marked trusted for dynamic ARP inspection.",
    ios_equivalent="ip arp inspection trust only on uplinks",
    requires=("ports",),
    params={"exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_dai_trusted(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    ports = _ports(data, params, "access")
    bad = [_port_label(p) for p in ports if p.get("daiTrusted") is True]
    if bad:
        return False, f"{_plural(len(bad), 'access port')} marked DAI trusted", _cap(bad)
    return True, "No access port is DAI trusted", []


@_check(
    id="switch_port_storm_control",
    name="Storm control enabled on access ports",
    scope=SCOPE_DEVICE,
    category="switching",
    description="Enabled access ports must have per-port storm control turned on.",
    ios_equivalent="storm-control broadcast level (per interface)",
    requires=("ports",),
    params={"exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_storm_control(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    ports = _ports(data, params, "access")
    bad = [_port_label(p) for p in ports if not p.get("stormControlEnabled")]
    if not ports:
        return True, "No enabled access ports", []
    if bad:
        return False, f"{len(bad)} of {_plural(len(ports), 'enabled access port')} without storm control", _cap(bad)
    return True, f"Storm control on all {_plural(len(ports), 'enabled access port')}", []


@_check(
    id="switch_port_unused_disabled",
    name="Unused ports are disabled",
    scope=SCOPE_DEVICE,
    category="switching",
    description=(
        "Ports with nothing connected must be administratively disabled. Uses the live port "
        "status (one API call per switch), so it reflects the moment of the scan."
    ),
    ios_equivalent="shutdown",
    requires=("ports", "port_statuses"),
    params={"exempt_tags": [], "exempt_name_pattern": ""},
    products=("switch",),
)
def _eval_port_unused(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    statuses = {str(s.get("portId")): s for s in data["port_statuses"] or [] if isinstance(s, dict)}
    bad: list[str] = []
    for p in data.get("ports") or []:
        if not isinstance(p, dict) or not _port_enabled(p) or _port_exempt(p, params):
            continue
        status = statuses.get(str(p.get("portId")))
        if status is None:
            continue
        if str(status.get("status") or "").lower() == "disconnected":
            bad.append(_port_label(p))
    if bad:
        return False, f"{_plural(len(bad), 'enabled port')} with nothing connected", _cap(bad)
    return True, "Every enabled port has a link", []


# ── Appliance: network scope ─────────────────────────────────────────────────


@_check(
    id="mx_ip_source_guard",
    name="IP source guard blocks spoofed traffic",
    scope=SCOPE_NETWORK,
    category="appliance",
    description="The MX anti-spoofing IP source guard must be in block mode.",
    ios_equivalent="ip verify unicast source reachable-via rx (uRPF)",
    requires=("firewall_settings",),
    products=("appliance",),
)
def _eval_ip_source_guard(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    mode = str(
        (((data["firewall_settings"] or {}).get("spoofingProtection") or {}).get("ipSourceGuard") or {}).get("mode")
        or ""
    )
    if mode.lower() == "block":
        return True, "IP source guard: block", []
    return (
        False,
        f"IP source guard mode is '{mode or 'unset'}' (Security & SD-WAN > Firewall > Spoofing protection)",
        [],
    )


@_check(
    id="mx_ids_prevention",
    name="Intrusion prevention enabled",
    scope=SCOPE_NETWORK,
    category="appliance",
    description="Threat protection must run in prevention mode with at least the required ruleset.",
    ios_equivalent="IPS inline (no IOS equivalent)",
    requires=("intrusion",),
    params={"min_ruleset": "balanced"},
    products=("appliance",),
)
def _eval_ids(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    rank = {"connectivity": 0, "balanced": 1, "security": 2}
    mode = str(data["intrusion"].get("mode") or "").lower()
    ruleset = str(data["intrusion"].get("idsRulesets") or "").lower()
    minimum = str(params.get("min_ruleset") or "balanced").lower()
    if mode != "prevention":
        return False, f"Intrusion detection mode is '{mode or 'disabled'}', not prevention", []
    if rank.get(ruleset, -1) < rank.get(minimum, 1):
        return False, f"Ruleset '{ruleset or 'unset'}' is weaker than required '{minimum}'", []
    return True, f"Prevention mode, ruleset {ruleset}", []


@_check(
    id="mx_amp_enabled",
    name="Advanced malware protection enabled",
    scope=SCOPE_NETWORK,
    category="appliance",
    description="AMP must be enabled on the security appliance.",
    ios_equivalent="(no IOS equivalent)",
    requires=("malware",),
    products=("appliance",),
)
def _eval_amp(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    mode = str(data["malware"].get("mode") or "").lower()
    if mode == "enabled":
        return True, "AMP enabled", []
    return False, f"AMP is '{mode or 'disabled'}'", []


@_check(
    id="mx_firewalled_services",
    name="Appliance services blocked from the WAN",
    scope=SCOPE_NETWORK,
    category="appliance",
    description=(
        "The MX's own services (web management, SNMP, ICMP) must not be reachable from any "
        "address on the WAN: access 'blocked' or 'restricted' to listed addresses."
    ),
    ios_equivalent="no ip http server / access-class on vty / snmp-server community ... ACL",
    requires=("firewalled_services",),
    params={"services": ["web", "SNMP"], "allow_restricted": True},
    products=("appliance",),
)
def _eval_firewalled_services(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    wanted = _lower_set(params.get("services")) or {"web", "snmp"}
    ok = {"blocked"} | ({"restricted"} if params.get("allow_restricted", True) else set())
    found: dict[str, str] = {}
    for svc in data["firewalled_services"] or []:
        if isinstance(svc, dict):
            found[str(svc.get("service") or "").lower()] = str(svc.get("access") or "").lower()
    bad = [f"{name}: {found.get(name) or 'not reported'}" for name in sorted(wanted) if found.get(name) not in ok]
    if bad:
        return False, f"{_plural(len(bad), 'service')} reachable from the WAN", bad
    return True, f"{', '.join(sorted(wanted))} blocked or restricted", []


@_check(
    id="mx_port_forwarding_restricted",
    name="Port forwarding rules restrict source addresses",
    scope=SCOPE_NETWORK,
    category="appliance",
    description="No port forwarding rule may accept connections from any source address.",
    ios_equivalent="ip nat inside source static ... + inbound ACL",
    requires=("port_forwarding",),
    params={"allow_any_for_ports": []},
    products=("appliance",),
)
def _eval_port_forwarding(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    allow_ports = {str(p) for p in params.get("allow_any_for_ports") or []}
    rules = (data["port_forwarding"] or {}).get("rules") or []
    bad: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if "any" in _lower_set(rule.get("allowedIps")) and str(rule.get("publicPort") or "") not in allow_ports:
            bad.append(
                f"{rule.get('name') or 'unnamed'}: {rule.get('protocol') or '?'}/{rule.get('publicPort') or '?'} "
                f"-> {rule.get('lanIp') or '?'} from any"
            )
    if bad:
        return False, f"{len(bad)} of {_plural(len(rules), 'port forwarding rule')} open to any source", _cap(bad)
    return True, f"{_plural(len(rules), 'port forwarding rule')}, none open to any source", []


@_check(
    id="mx_one_to_one_nat_restricted",
    name="1:1 NAT rules restrict inbound sources",
    scope=SCOPE_NETWORK,
    category="appliance",
    description=(
        "1:1 NAT inbound allowances must list source addresses; 'any' is permitted only on "
        "the listed destination ports (public web services by default)."
    ),
    ios_equivalent="ip nat inside source static + inbound ACL",
    requires=("one_to_one_nat",),
    params={"allow_any_for_ports": ["80", "443"]},
    products=("appliance",),
)
def _eval_one_to_one_nat(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    allow_ports = {str(p) for p in params.get("allow_any_for_ports") or []}
    rules = (data["one_to_one_nat"] or {}).get("rules") or []
    bad: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for inbound in rule.get("allowedInbound") or []:
            if not isinstance(inbound, dict) or "any" not in _lower_set(inbound.get("allowedIps")):
                continue
            ports = {str(p) for p in inbound.get("destinationPorts") or []}
            if not ports or not ports <= allow_ports:
                bad.append(
                    f"{rule.get('name') or 'unnamed'} ({rule.get('publicIp') or '?'}): "
                    f"{inbound.get('protocol') or '?'} {', '.join(sorted(ports)) or 'any'} from any"
                )
    if bad:
        return False, f"{_plural(len(bad), 'inbound allowance')} open to any source", _cap(bad)
    return True, f"{_plural(len(rules), '1:1 NAT rule')}, inbound sources restricted", []


@_check(
    id="mx_l3_firewall_logging",
    name="Outbound firewall default rule is logged",
    scope=SCOPE_NETWORK,
    category="appliance",
    description=(
        "The MX outbound L3 firewall ends in an implicit allow; syslog must be enabled on that "
        "default rule (or on every rule) so permitted flows are recorded."
    ),
    ios_equivalent="access-list ... log / logging host",
    requires=("l3_firewall",),
    params={"every_rule": False},
    products=("appliance",),
)
def _eval_l3_logging(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    rules = [r for r in (data["l3_firewall"] or {}).get("rules") or [] if isinstance(r, dict)]
    if not rules:
        return False, "No outbound firewall rules returned (not even the default rule)", []
    if params.get("every_rule"):
        bad = [r.get("comment") or f"rule {i + 1}" for i, r in enumerate(rules) if not r.get("syslogEnabled")]
        if bad:
            return False, f"{len(bad)} of {_plural(len(rules), 'rule')} without syslog", _cap([str(b) for b in bad])
        return True, f"Syslog on all {_plural(len(rules), 'rule')}", []
    default = rules[-1]
    if default.get("syslogEnabled"):
        return True, "Default rule logs to syslog", []
    return False, f"Default rule '{default.get('comment') or 'Default rule'}' does not log to syslog", []


@_check(
    id="mx_content_filtering",
    name="Content filtering blocks URL categories",
    scope=SCOPE_NETWORK,
    category="appliance",
    description="At least the configured number of URL categories must be blocked.",
    ios_equivalent="(no IOS equivalent)",
    requires=("content_filtering",),
    params={"min_categories": 1},
    products=("appliance",),
)
def _eval_content_filtering(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    categories = [c for c in (data["content_filtering"] or {}).get("blockedUrlCategories") or []]
    minimum = int(params.get("min_categories", 1))
    names = [str(c.get("name") if isinstance(c, dict) else c) for c in categories]
    if len(categories) >= minimum:
        return True, f"{_plural(len(categories), 'URL category')} blocked", _cap(names)
    return False, f"Only {_plural(len(categories), 'URL category')} blocked (minimum {minimum})", _cap(names)


# ── Wireless: SSID scope (one target per enabled SSID) ───────────────────────
#
# ``data["ssid"]`` is the SSID object from ``networks/{net}/wireless/ssids``;
# per-SSID endpoints (the SSID's own L3 firewall) are collected only for
# enabled SSIDs and only when a check asks for them. A check that does not
# concern this SSID (a guest check on a corporate SSID) returns ``None`` as
# its verdict and leaves no finding.

_OPEN_AUTH_MODES = ("open", "open-enhanced", "open-with-radius", "open-with-nac")
_GUEST_PATTERN = "guest|visitor|public"


def _ssid_is_open(ssid: dict) -> bool:
    return str(ssid.get("authMode") or "open").lower() in _OPEN_AUTH_MODES


def _ssid_matches(ssid: dict, pattern: str) -> bool:
    if not pattern:
        return False
    try:
        return re.search(pattern, str(ssid.get("name") or ""), re.IGNORECASE) is not None
    except re.error:
        return False


def _ssid_is_guest(ssid: dict, params: dict) -> bool:
    return _ssid_matches(ssid, str(params.get("guest_name_pattern") or ""))


def _lan_access_rule(l3: dict | None) -> dict | None:
    """The SSID firewall's "Wireless clients accessing LAN" rule (destination
    ``Local LAN``), or ``None`` when the payload has no such rule."""
    for rule in (l3 or {}).get("rules") or []:
        if isinstance(rule, dict) and str(rule.get("destCidr") or "").strip().lower() == "local lan":
            return rule
    return None


_NA: tuple[None, str, list[str]] = (None, "", [])


@_check(
    id="ssid_requires_auth",
    name="SSID requires authentication (not open)",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "The SSID must authenticate clients (PSK, 802.1X, identity PSK); an open SSID, even with a "
        "splash page, does not. SSIDs whose name matches the exempt pattern are skipped."
    ),
    ios_equivalent="no open WLAN",
    requires=("ssid",),
    params={"exempt_name_pattern": ""},
    products=("wireless",),
)
def _eval_ssid_auth(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if _ssid_matches(ssid, str(params.get("exempt_name_pattern") or "")):
        return _NA
    if _ssid_is_open(ssid):
        return False, f"Authentication mode is '{ssid.get('authMode') or 'open'}'", []
    return True, f"Authentication mode {ssid.get('authMode')}", []


@_check(
    id="ssid_wpa2_or_better",
    name="WPA2 or stronger encryption",
    scope=SCOPE_SSID,
    category="wireless",
    description="A secured SSID must not permit WEP or WPA1 (TKIP); 'WPA2 only' or a WPA3 mode is required by default.",
    ios_equivalent="security wpa wpa2 / wpa3",
    requires=("ssid",),
    params={"minimum": "WPA2 only"},
    products=("wireless",),
)
def _eval_ssid_wpa(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    rank = {
        "wpa1 only": 0,
        "wpa1 and wpa2": 0,
        "wpa2 only": 1,
        "wpa3 transition mode": 2,
        "wpa3 only": 3,
        "wpa3 192-bit security": 4,
    }
    ssid = data["ssid"]
    if _ssid_is_open(ssid):
        return _NA  # reported by ssid_requires_auth
    minimum_name = str(params.get("minimum") or "WPA2 only")
    minimum = rank.get(minimum_name.lower(), 1)
    if str(ssid.get("encryptionMode") or "").lower() == "wep":
        return False, "WEP encryption", []
    wpa_mode = str(ssid.get("wpaEncryptionMode") or "")
    # Meraki omits wpaEncryptionMode on some auth modes; absence is the
    # dashboard default (WPA2 only), not a weakness.
    if wpa_mode and rank.get(wpa_mode.lower(), 1) < minimum:
        return False, f"WPA mode '{wpa_mode}' is below '{minimum_name}'", []
    return True, f"WPA mode {wpa_mode or 'WPA2 only (default)'}", []


@_check(
    id="ssid_enterprise_auth",
    name="Corporate SSID uses 802.1X",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "An SSID that is not a guest SSID (name matches the guest pattern) must authenticate with "
        "802.1X (RADIUS, Meraki Cloud, local RADIUS or NAC), not a pre-shared key."
    ),
    ios_equivalent="dot1x / aaa authentication on the WLAN",
    requires=("ssid",),
    params={"guest_name_pattern": _GUEST_PATTERN},
    products=("wireless",),
)
def _eval_ssid_enterprise(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if _ssid_is_guest(ssid, params):
        return _NA
    auth = str(ssid.get("authMode") or "open")
    if auth.lower().startswith("8021x"):
        return True, f"802.1X ({auth})", []
    return False, f"Authentication mode is '{auth}'", []


@_check(
    id="ssid_radius_redundancy",
    name="802.1X SSID has redundant RADIUS servers",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "An SSID authenticating against RADIUS must list at least the configured number of RADIUS "
        "servers (two by default) so one server failing does not take the SSID down; RADIUS "
        "accounting can be required as well."
    ),
    ios_equivalent="radius server group with two servers / aaa accounting",
    requires=("ssid",),
    params={"min_servers": 2, "require_accounting": False},
    products=("wireless",),
)
def _eval_ssid_radius(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    auth = str(ssid.get("authMode") or "").lower()
    if auth not in ("8021x-radius", "ipsk-with-radius", "open-with-radius"):
        return _NA
    servers = [r for r in ssid.get("radiusServers") or [] if isinstance(r, dict)]
    minimum = int(params.get("min_servers", 2))
    listed = [f"{r.get('host')}:{r.get('port')}" for r in servers]
    problems: list[str] = []
    if len(servers) < minimum:
        problems.append(f"{_plural(len(servers), 'RADIUS server')} (minimum {minimum})")
    if params.get("require_accounting") and not ssid.get("radiusAccountingEnabled"):
        problems.append("RADIUS accounting disabled")
    if problems:
        return False, "; ".join(problems), listed
    return True, _plural(len(servers), "RADIUS server"), listed


@_check(
    id="ssid_pmf_enabled",
    name="Management frame protection (802.11w) enabled",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "A secured SSID must enable protected management frames; 'required' can be demanded for WPA3-only SSIDs."
    ),
    ios_equivalent="security pmf optional / mandatory",
    requires=("ssid",),
    params={"require_mandatory": False},
    products=("wireless",),
)
def _eval_ssid_pmf(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if _ssid_is_open(ssid):
        return _NA
    pmf = ssid.get("dot11w") or {}
    if not pmf.get("enabled"):
        return False, "802.11w is disabled", []
    if params.get("require_mandatory") and not pmf.get("required"):
        return False, "802.11w is optional, not required", []
    return True, f"802.11w {'required' if pmf.get('required') else 'enabled'}", []


@_check(
    id="ssid_splash_on_open",
    name="Open SSID has a splash page",
    scope=SCOPE_SSID,
    category="wireless",
    description="An open SSID must at least present a splash page (click-through, sponsored, sign-on) before granting access.",
    ios_equivalent="web authentication on the WLAN",
    requires=("ssid",),
    products=("wireless",),
)
def _eval_ssid_splash(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if not _ssid_is_open(ssid):
        return _NA
    splash = str(ssid.get("splashPage") or "None")
    if splash.lower() in ("none", ""):
        return False, "Open SSID without a splash page", []
    return True, f"Splash page: {splash}", []


@_check(
    id="ssid_guest_isolated",
    name="Guest SSID isolated from the LAN",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "A guest SSID (name matches the guest pattern) must keep clients off the LAN: NAT mode, LAN "
        "isolation in bridge mode, or an SSID firewall rule denying 'Local LAN'."
    ),
    ios_equivalent="guest ACL / peer-to-peer blocking on the WLAN",
    requires=("ssid",),
    optional=("ssid_l3_firewall",),
    params={"guest_name_pattern": _GUEST_PATTERN},
    products=("wireless",),
)
def _eval_ssid_guest_isolated(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if not _ssid_is_guest(ssid, params):
        return _NA
    mode = str(ssid.get("ipAssignmentMode") or "Bridge mode")
    if mode.lower().startswith("nat"):
        return True, "NAT mode", []
    if ssid.get("lanIsolationEnabled"):
        return True, f"{mode} with LAN isolation", []
    rule = _lan_access_rule(data.get("ssid_l3_firewall"))
    if rule is not None and str(rule.get("policy") or "").lower() == "deny":
        return True, f"{mode}; SSID firewall denies Local LAN", []
    return False, f"{mode} without LAN isolation" + ("" if rule is None else "; SSID firewall allows Local LAN"), []


@_check(
    id="ssid_guest_lan_firewall",
    name="Guest SSID firewall denies the LAN",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "The SSID firewall of a guest SSID must set 'Wireless clients accessing LAN' to deny "
        "(the Local LAN rule), whatever the IP assignment mode. Read per SSID."
    ),
    ios_equivalent="ip access-group on the WLAN denying internal ranges",
    requires=("ssid", "ssid_l3_firewall"),
    params={"guest_name_pattern": _GUEST_PATTERN},
    products=("wireless",),
)
def _eval_ssid_guest_lan_fw(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if not _ssid_is_guest(ssid, params):
        return _NA
    rule = _lan_access_rule(data["ssid_l3_firewall"])
    if rule is None:
        return False, "SSID firewall has no 'Local LAN' rule", []
    policy = str(rule.get("policy") or "").lower()
    if policy == "deny":
        return True, "Wireless clients accessing LAN: deny", []
    return False, f"Wireless clients accessing LAN: {policy or 'allow'}", []


@_check(
    id="ssid_mandatory_dhcp",
    name="Mandatory DHCP enabled",
    scope=SCOPE_SSID,
    category="wireless",
    description=(
        "Clients must obtain their address by DHCP (a static address is dropped), which stops a "
        "client from taking another host's IP. Applies to guest SSIDs by default, or to all."
    ),
    ios_equivalent="ip dhcp snooping + ip source guard on the WLAN",
    requires=("ssid",),
    params={"guest_only": True, "guest_name_pattern": _GUEST_PATTERN},
    products=("wireless",),
)
def _eval_ssid_mandatory_dhcp(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if params.get("guest_only", True) and not _ssid_is_guest(ssid, params):
        return _NA
    if ssid.get("mandatoryDhcpEnabled"):
        return True, "Mandatory DHCP enabled", []
    return False, "Mandatory DHCP disabled", []


@_check(
    id="ssid_guest_bandwidth_limit",
    name="Guest SSID has a per-client bandwidth limit",
    scope=SCOPE_SSID,
    category="wireless",
    description="A guest SSID must cap each client's download (and optionally upload) bandwidth.",
    ios_equivalent="QoS policing on the WLAN",
    requires=("ssid",),
    params={"guest_name_pattern": _GUEST_PATTERN, "require_upload_limit": False},
    products=("wireless",),
)
def _eval_ssid_guest_bandwidth(data: dict, params: dict, _ctx: dict) -> tuple[bool | None, str, list[str]]:
    ssid = data["ssid"]
    if not _ssid_is_guest(ssid, params):
        return _NA

    def _kbps(key: str) -> int:
        try:
            return int(ssid.get(key) or 0)
        except TypeError, ValueError:
            return 0

    down, up = _kbps("perClientBandwidthLimitDown"), _kbps("perClientBandwidthLimitUp")
    if down <= 0:
        return False, "No per-client download limit", []
    if params.get("require_upload_limit") and up <= 0:
        return False, f"Download limited to {down} kbps but upload unlimited", []
    return True, f"Per-client limit {down} kbps down" + (f", {up} kbps up" if up > 0 else ""), []


# ── Network services: network scope ──────────────────────────────────────────


@_check(
    id="net_syslog_configured",
    name="Syslog server configured",
    scope=SCOPE_NETWORK,
    category="network",
    description="The network must send to at least the configured number of syslog servers.",
    ios_equivalent="logging host",
    requires=("syslog",),
    params={"min_servers": 1},
)
def _eval_syslog(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    servers = [s for s in (data["syslog"] or {}).get("servers") or [] if isinstance(s, dict)]
    minimum = int(params.get("min_servers", 1))
    listed = [f"{s.get('host')}:{s.get('port')} ({', '.join(str(r) for r in s.get('roles') or [])})" for s in servers]
    if len(servers) >= minimum:
        return True, _plural(len(servers), "syslog server"), listed
    return False, f"{_plural(len(servers), 'syslog server')} configured (minimum {minimum})", listed


@_check(
    id="net_snmp_no_v2c",
    name="Device SNMP access is not community-based",
    scope=SCOPE_NETWORK,
    category="network",
    description="SNMP access to the network's devices must be off or SNMPv3 (users), never a v2c community string.",
    ios_equivalent="snmp-server group ... v3 priv (no snmp-server community)",
    requires=("net_snmp",),
    params={"allowed_access": ["none", "users"]},
)
def _eval_net_snmp(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    access = str((data["net_snmp"] or {}).get("access") or "none").lower()
    allowed = _lower_set(params.get("allowed_access")) or {"none", "users"}
    if access in allowed:
        return True, f"SNMP access: {access}", []
    return False, f"SNMP access is '{access}' (community string)", []


@_check(
    id="net_alerts_destination",
    name="Alert destinations configured",
    scope=SCOPE_NETWORK,
    category="network",
    description="Network alerts must have a default destination: email recipients, all admins, or a webhook.",
    ios_equivalent="snmp-server host / logging host",
    requires=("alerts",),
)
def _eval_alert_destinations(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    dest = (data["alerts"] or {}).get("defaultDestinations") or {}
    emails = [str(e) for e in dest.get("emails") or []]
    webhooks = [str(w) for w in dest.get("httpServerIds") or []]
    if emails or webhooks or dest.get("allAdmins"):
        parts = []
        if dest.get("allAdmins"):
            parts.append("all admins")
        if emails:
            parts.append(_plural(len(emails), "email"))
        if webhooks:
            parts.append(_plural(len(webhooks), "webhook"))
        return True, "Default alert destinations: " + ", ".join(parts), emails
    return False, "No default alert destination (Network-wide > Alerts)", []


# ── Organization scope ───────────────────────────────────────────────────────


def _admin_label(admin: dict) -> str:
    return f"{admin.get('name') or '?'} <{admin.get('email') or '?'}>"


@_check(
    id="org_admins_2fa",
    name="All dashboard administrators use two-factor authentication",
    scope=SCOPE_ORG,
    category="organization",
    description="Every organization administrator must have two-factor authentication enabled.",
    ios_equivalent="AAA with multi-factor authentication",
    requires=("admins",),
    params={"exempt_emails": []},
)
def _eval_admins_2fa(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    exempt = _lower_set(params.get("exempt_emails"))
    admins = [
        a for a in data["admins"] or [] if isinstance(a, dict) and str(a.get("email") or "").lower() not in exempt
    ]
    bad = [_admin_label(a) for a in admins if not a.get("twoFactorAuthEnabled")]
    if bad:
        return (
            False,
            f"{len(bad)} of {_plural(len(admins), 'administrator')} without two-factor authentication",
            _cap(bad),
        )
    return True, f"All {_plural(len(admins), 'administrator')} use two-factor authentication", []


@_check(
    id="org_admins_active",
    name="No dormant administrator accounts",
    scope=SCOPE_ORG,
    category="organization",
    description="Administrators who have not signed in within the allowed number of days must be removed.",
    ios_equivalent="(account hygiene)",
    requires=("admins",),
    params={"max_inactive_days": 90, "exempt_emails": []},
)
def _eval_admins_active(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    exempt = _lower_set(params.get("exempt_emails"))
    limit = int(params.get("max_inactive_days", 90))
    now = datetime.now(UTC)
    bad: list[str] = []
    total = 0
    for a in data["admins"] or []:
        if not isinstance(a, dict) or str(a.get("email") or "").lower() in exempt:
            continue
        total += 1
        last = _parse_iso(a.get("lastActive"))
        if last is None:
            if a.get("accountStatus") == "unverified":
                bad.append(f"{_admin_label(a)}: never signed in")
            continue
        days = (now - last).days
        if days > limit:
            bad.append(f"{_admin_label(a)}: last active {days} days ago")
    if bad:
        return False, f"{len(bad)} of {_plural(total, 'administrator')} inactive for more than {limit} days", _cap(bad)
    return True, f"All {_plural(total, 'administrator')} active within {limit} days", []


def _login_security_check(check_id: str, name: str, description: str, ios: str, params: dict, fn):
    @_check(
        id=check_id,
        name=name,
        scope=SCOPE_ORG,
        category="organization",
        description=description,
        ios_equivalent=ios,
        requires=("login_security",),
        params=params,
    )
    def _eval(data: dict, p: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
        return fn(data["login_security"] or {}, p)

    return _eval


_login_security_check(
    "org_login_2fa_enforced",
    "Two-factor authentication enforced",
    "Organization login security must enforce two-factor authentication for every administrator.",
    "AAA with multi-factor authentication",
    {},
    lambda ls, p: (
        (True, "Two-factor authentication enforced", [])
        if ls.get("enforceTwoFactorAuth")
        else (False, "Two-factor authentication is not enforced (Organization > Settings > Security)", [])
    ),
)

_login_security_check(
    "org_login_strong_passwords",
    "Strong passwords enforced",
    "Organization login security must enforce strong passwords.",
    "security passwords min-length",
    {},
    lambda ls, p: (
        (True, "Strong passwords enforced", [])
        if ls.get("enforceStrongPasswords")
        else (False, "Strong passwords are not enforced", [])
    ),
)


def _idle_timeout(ls: dict, p: dict) -> tuple[bool, str, list[str]]:
    limit = int(p.get("max_minutes", 30))
    if not ls.get("enforceIdleTimeout"):
        return False, "Idle timeout is not enforced", []
    try:
        minutes = int(ls.get("idleTimeoutMinutes"))
    except TypeError, ValueError:
        return False, "Idle timeout enforced but no value reported", []
    if minutes > limit:
        return False, f"Idle timeout is {minutes} minutes (maximum {limit})", []
    return True, f"Idle timeout {minutes} minutes", []


_login_security_check(
    "org_login_idle_timeout",
    "Idle session timeout enforced",
    "Dashboard sessions must time out after at most the configured number of idle minutes.",
    "exec-timeout",
    {"max_minutes": 30},
    _idle_timeout,
)


def _lockout(ls: dict, p: dict) -> tuple[bool, str, list[str]]:
    limit = int(p.get("max_attempts", 10))
    if not ls.get("enforceAccountLockout"):
        return False, "Account lockout is not enforced", []
    try:
        attempts = int(ls.get("accountLockoutAttempts"))
    except TypeError, ValueError:
        return False, "Account lockout enforced but no attempt count reported", []
    if attempts > limit:
        return False, f"Lockout after {attempts} attempts (maximum {limit})", []
    return True, f"Lockout after {attempts} failed attempts", []


_login_security_check(
    "org_login_lockout",
    "Account lockout enforced",
    "Accounts must lock after at most the configured number of failed sign-in attempts.",
    "login block-for / aaa authentication attempts",
    {"max_attempts": 10},
    _lockout,
)


def _password_expiration(ls: dict, p: dict) -> tuple[bool, str, list[str]]:
    limit = int(p.get("max_days", 90))
    if not ls.get("enforcePasswordExpiration"):
        return False, "Password expiration is not enforced", []
    try:
        days = int(ls.get("passwordExpirationDays"))
    except TypeError, ValueError:
        return False, "Password expiration enforced but no period reported", []
    if days > limit:
        return False, f"Passwords expire after {days} days (maximum {limit})", []
    return True, f"Passwords expire after {days} days", []


_login_security_check(
    "org_login_password_expiration",
    "Password expiration enforced",
    "Administrator passwords must expire within the configured number of days.",
    "(password policy)",
    {"max_days": 90},
    _password_expiration,
)

_login_security_check(
    "org_login_password_reuse",
    "Password reuse prevented",
    "Organization login security must prevent reuse of recent passwords.",
    "(password policy)",
    {},
    lambda ls, p: (
        (True, f"Reuse of the last {ls.get('numDifferentPasswords') or '?'} passwords prevented", [])
        if ls.get("enforceDifferentPasswords")
        else (False, "Password reuse is not prevented", [])
    ),
)

_login_security_check(
    "org_api_key_ip_restriction",
    "API keys restricted to allowed IP ranges",
    "Dashboard API keys must only be usable from the organization's allowed IP ranges.",
    "access-class on management plane",
    {},
    lambda ls, p: (
        (True, "API key IP restrictions enabled", [])
        if (((ls.get("apiAuthentication") or {}).get("ipRestrictionsForKeys") or {}).get("enabled"))
        else (False, "API keys can be used from any address", [])
    ),
)


@_check(
    id="org_snmp_v3_only",
    name="Organization SNMP is v3 only",
    scope=SCOPE_ORG,
    category="organization",
    description="SNMP polling of the Meraki cloud must not use v2c; if v3 is enabled it must use SHA and AES.",
    ios_equivalent="snmp-server group ... v3 priv",
    requires=("org_snmp",),
)
def _eval_org_snmp(data: dict, params: dict, _ctx: dict) -> tuple[bool, str, list[str]]:
    snmp = data["org_snmp"] or {}
    problems: list[str] = []
    if snmp.get("v2cEnabled"):
        problems.append("SNMPv2c enabled")
    if snmp.get("v3Enabled"):
        if str(snmp.get("v3AuthMode") or "").upper() != "SHA":
            problems.append(f"v3 auth mode {snmp.get('v3AuthMode') or 'unset'} (SHA required)")
        if not str(snmp.get("v3PrivMode") or "").upper().startswith("AES"):
            problems.append(f"v3 privacy mode {snmp.get('v3PrivMode') or 'unset'} (AES required)")
    if problems:
        return False, "; ".join(problems), []
    if snmp.get("v3Enabled"):
        return True, "SNMPv3 only (SHA / AES)", []
    return True, "SNMP disabled", []


# ── Catalog / rules ──────────────────────────────────────────────────────────


def catalog() -> list[dict[str, Any]]:
    """The check catalog for the API and the profile editor."""
    out = []
    for check in CHECKS.values():
        out.append(
            {
                "id": check.id,
                "name": check.name,
                "scope": check.scope,
                "category": check.category,
                "category_label": CATEGORIES.get(check.category, check.category),
                "description": check.description,
                "ios_equivalent": check.ios_equivalent,
                "params": copy.deepcopy(check.params),
                "products": list(check.products),
            }
        )
    return out


def rule_template(check_id: str) -> dict[str, Any]:
    """The profile rule that selects ``check_id`` with its default parameters."""
    check = CHECKS[check_id]
    rule: dict[str, Any] = {"name": check.name, "type": RULE_TYPE, "check": check.id}
    if check.params:
        rule["params"] = copy.deepcopy(check.params)
    return rule


def is_meraki_rule(rule: Any) -> bool:
    return isinstance(rule, dict) and str(rule.get("type") or "").lower() == RULE_TYPE


def meraki_rules(rules: Any) -> list[dict]:
    return [r for r in (rules if isinstance(rules, list) else []) if is_meraki_rule(r)]


def required_endpoints(rules: Any) -> set[str]:
    """Endpoint keys the checks of ``rules`` need (``switch_ports`` for port checks)."""
    needed: set[str] = set()
    for rule in meraki_rules(rules):
        check = CHECKS.get(str(rule.get("check") or ""))
        if check is None:
            continue
        if check.scope == SCOPE_SSID:
            needed.add("ssids")
        for key in check.requires + check.optional:
            if key == "ports":
                needed.add("switch_ports")
            elif key in ENDPOINTS:
                needed.add(key)
    return needed


# ── Collector ────────────────────────────────────────────────────────────────

ProgressCallback = Callable[[dict[str, Any]], None]


class _Fetcher:
    def __init__(self, client: MerakiClient, progress: ProgressCallback | None) -> None:
        self.client = client
        self.errors: list[dict[str, Any]] = []
        self.done = 0
        self.total = 0
        self.phase = "starting"
        self._progress = progress

    def report(self, **fields: Any) -> None:
        if self._progress is None:
            return
        payload = {"phase": self.phase, "calls_done": self.done, "calls_total": self.total}
        payload.update(fields)
        self._progress(payload)

    async def fetch(self, scope: str, path: str, *, paginated: bool) -> Any:
        """``None`` when not applicable, :class:`Unreadable` on failure."""
        try:
            if paginated:
                data: Any = await self.client.get_all(path, per_page=1000 if "bySwitch" not in path else 50)
            else:
                data = await self.client.get(path)
        except MerakiApiError as exc:
            if exc.status_code in _NOT_APPLICABLE_STATUSES:
                return None
            if len(self.errors) < 200:
                self.errors.append({"scope": scope, "path": path, "status": exc.status_code, "message": str(exc)})
            return Unreadable(f"HTTP {exc.status_code}" if exc.status_code else str(exc))
        finally:
            self.done += 1
            self.report()
        return scrub_secrets(data)

    async def run(self, jobs: list[tuple[dict, str, Awaitable[Any]]]) -> None:
        self.total += len(jobs)
        self.report()

        async def _one(target: dict, key: str, aw: Awaitable[Any]) -> None:
            target[key] = await aw

        await asyncio.gather(*(_one(t, k, aw) for t, k, aw in jobs))


async def collect_compliance_data(
    client: MerakiClient,
    org_id: str,
    rules: Any,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect only what the Meraki rules of a profile need.

    Returns the raw payloads keyed like the topology collector (``org``,
    ``networks_detail``, ``devices_detail``) plus ``switch_ports`` keyed by
    serial. The organization inventory (organization, networks, devices) is
    required; everything else is best-effort and marked :class:`Unreadable`
    when it fails for a reason other than "not applicable". Raises
    ``MerakiApiError`` only if the inventory cannot be read.
    """
    opts = sanitize_options(options)
    needed = required_endpoints(rules)
    fetcher = _Fetcher(client, progress)
    org_path = f"organizations/{org_id}"

    fetcher.phase = "inventory"
    fetcher.total = 3
    fetcher.report()
    organization = scrub_secrets(await client.get(org_path)) or {"id": org_id}
    fetcher.done += 1
    all_networks = scrub_secrets(await client.get_all(f"{org_path}/networks", per_page=1000))
    fetcher.done += 1
    all_devices = scrub_secrets(await client.get_all(f"{org_path}/devices", per_page=1000))
    fetcher.done += 1
    networks = [n for n in all_networks if isinstance(n, dict) and n.get("id") and _network_selected(n, opts)]
    network_ids = {n["id"] for n in networks}
    devices = [d for d in all_devices if isinstance(d, dict) and d.get("serial") and d.get("networkId") in network_ids]
    fetcher.report(networks=len(networks), devices=len(devices))

    raw: dict[str, Any] = {
        "organization": organization,
        "networks": networks,
        "devices": devices,
        "org": {},
        "networks_detail": {n["id"]: {} for n in networks},
        "devices_detail": {d["serial"]: {} for d in devices},
        "switch_ports": {},
        # network id -> SSID number (str) -> {endpoint key: payload}
        "ssids_detail": {},
        "options": opts,
    }
    has_switches = any(_device_kind(d) == "switch" for d in devices)

    fetcher.phase = "organization"
    org_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
    for key in sorted(needed):
        scope, template, paginated, products = ENDPOINTS[key]
        if scope != SCOPE_ORG:
            continue
        if products and "switch" in products and not has_switches:
            continue
        org_jobs.append((raw["org"], key, fetcher.fetch("org", template.format(org=org_id), paginated=paginated)))
    await fetcher.run(org_jobs)

    fetcher.phase = "networks"
    net_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
    for net in networks:
        products_here = set(net.get("productTypes") or [])
        detail = raw["networks_detail"][net["id"]]
        for key in sorted(needed):
            scope, template, paginated, products = ENDPOINTS[key]
            if scope != SCOPE_NETWORK:
                continue
            if products and not products_here & set(products):
                continue
            path = template.format(net=net["id"])
            net_jobs.append(
                (detail, key, fetcher.fetch(f"network:{net.get('name') or net['id']}", path, paginated=paginated))
            )
    await fetcher.run(net_jobs)

    fetcher.phase = "devices"
    dev_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
    for dev in devices:
        kind = _device_kind(dev)
        detail = raw["devices_detail"][dev["serial"]]
        for key in sorted(needed):
            scope, template, paginated, products = ENDPOINTS[key]
            if scope != SCOPE_DEVICE or (products and kind not in products):
                continue
            path = template.format(serial=dev["serial"])
            dev_jobs.append(
                (detail, key, fetcher.fetch(f"device:{dev.get('name') or dev['serial']}", path, paginated=paginated))
            )
    await fetcher.run(dev_jobs)

    # Per-SSID endpoints, for the enabled SSIDs of each wireless network only
    # (the SSID list was fetched in the network phase).
    ssid_keys = [k for k in sorted(needed) if ENDPOINTS[k][0] == SCOPE_SSID]
    if ssid_keys:
        fetcher.phase = "ssids"
        ssid_jobs: list[tuple[dict, str, Awaitable[Any]]] = []
        for net in networks:
            ssids = raw["networks_detail"][net["id"]].get("ssids")
            if not isinstance(ssids, list):
                continue
            per_net = raw["ssids_detail"].setdefault(net["id"], {})
            for ssid in ssids:
                if not isinstance(ssid, dict) or not ssid.get("enabled") or ssid.get("number") is None:
                    continue
                number = str(ssid["number"])
                detail = per_net.setdefault(number, {})
                scope = f"ssid:{net.get('name') or net['id']}/{ssid.get('name') or number}"
                for key in ssid_keys:
                    _scope, template, paginated, _products = ENDPOINTS[key]
                    path = template.format(net=net["id"], number=number)
                    ssid_jobs.append((detail, key, fetcher.fetch(scope, path, paginated=paginated)))
        await fetcher.run(ssid_jobs)

    ports_payload = raw["org"].pop("switch_ports", None)
    if isinstance(ports_payload, Unreadable):
        raw["switch_ports"] = ports_payload
    else:
        for entry in ports_payload or []:
            if isinstance(entry, dict) and entry.get("serial"):
                raw["switch_ports"][entry["serial"]] = [p for p in entry.get("ports") or [] if isinstance(p, dict)]

    fetcher.phase = "collected"
    fetcher.report()
    raw["errors"] = fetcher.errors
    raw["stats"] = dict(client.stats)
    LOGGER.info(
        "meraki compliance: collected org %s - %d networks, %d devices, %d calls, %d errors",
        org_id,
        len(networks),
        len(devices),
        client.stats["requests"],
        len(fetcher.errors),
    )
    return raw


# ── Evaluation ───────────────────────────────────────────────────────────────


def _finding(rule: dict, check: Check | None, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": str(rule.get("name") or (check.name if check else rule.get("check") or "?")),
        "type": RULE_TYPE,
        "check": str(rule.get("check") or ""),
        "scope": check.scope if check else "",
        "category": check.category if check else "",
        "ios_equivalent": check.ios_equivalent if check else "",
        "passed": None,
        "detail": "",
        "evidence": [],
        "unreadable": False,
    }
    base.update(fields)
    return base


def _resolve(check: Check, sources: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Gather the payloads a check needs. ``(None, None)`` = not applicable,
    ``(None, message)`` = unreadable, ``(data, None)`` = ready."""
    data: dict[str, Any] = {}
    for key in check.requires:
        value = sources.get(key)
        if isinstance(value, Unreadable):
            return None, f"{key}: {value.message}"
        if value is None:
            return None, None
        data[key] = value
    for key in check.optional:
        value = sources.get(key)
        data[key] = None if isinstance(value, Unreadable) else value
    return data, None


def _evaluate_target(
    rules: list[tuple[dict, Check]],
    sources: dict[str, Any],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule, check in rules:
        data, problem = _resolve(check, sources)
        if data is None:
            if problem is None:
                continue  # not applicable here
            findings.append(_finding(rule, check, passed=False, unreadable=True, detail=f"Could not read {problem}"))
            continue
        params = {**copy.deepcopy(check.params), **(rule.get("params") if isinstance(rule.get("params"), dict) else {})}
        try:
            passed, detail, evidence = check.evaluate(data, params, context)
        except Exception as exc:  # noqa: BLE001 - one broken check must not sink the scan
            LOGGER.warning("meraki compliance: check %s crashed: %s", check.id, type(exc).__name__)
            findings.append(
                _finding(rule, check, passed=False, unreadable=True, detail=f"Check failed: {type(exc).__name__}")
            )
            continue
        if passed is None:
            continue  # the check does not concern this target (e.g. a guest check on a corporate SSID)
        findings.append(
            _finding(rule, check, passed=bool(passed), detail=str(detail), evidence=[str(e) for e in evidence])
        )
    return findings


def _summarise(target: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not findings:
        return None
    failed = sum(1 for f in findings if f["passed"] is False and not f["unreadable"])
    unreadable = sum(1 for f in findings if f["unreadable"])
    passed = sum(1 for f in findings if f["passed"] is True)
    if failed:
        status = "non-compliant"
    elif unreadable:
        status = "error"
    else:
        status = "compliant"
    return {
        **target,
        "status": status,
        "total_rules": len(findings),
        "passed_rules": passed,
        "failed_rules": failed,
        "unreadable_rules": unreadable,
        "findings": findings,
    }


def evaluate_profile(rules: Any, raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate the Meraki rules of a profile against collected payloads.

    Returns one result per target that at least one check applies to:
    ``{target_kind, target_id, target_name, network_id, network_name, model,
    serial, status, total_rules, passed_rules, failed_rules, unreadable_rules,
    findings}``. The organization target comes first, then networks and
    devices in name order. A rule naming an unknown check becomes an
    unreadable finding on the organization target so the mistake is visible.
    """
    org = raw.get("organization") or {}
    org_target = {
        "target_kind": SCOPE_ORG,
        "target_id": str(org.get("id") or ""),
        "target_name": str(org.get("name") or org.get("id") or "Organization"),
        "network_id": "",
        "network_name": "",
        "model": "",
        "serial": "",
    }
    by_scope: dict[str, list[tuple[dict, Check]]] = {s: [] for s in SCOPES}
    org_findings: list[dict[str, Any]] = []
    for rule in meraki_rules(rules):
        check = CHECKS.get(str(rule.get("check") or ""))
        if check is None:
            org_findings.append(
                _finding(
                    rule, None, passed=False, unreadable=True, detail=f"Unknown Meraki check '{rule.get('check')}'"
                )
            )
            continue
        by_scope[check.scope].append((rule, check))

    results: list[dict[str, Any]] = []

    org_sources = dict(raw.get("org") or {})
    org_findings.extend(_evaluate_target(by_scope[SCOPE_ORG], org_sources, {"organization": org}))
    summary = _summarise(org_target, org_findings)
    if summary:
        results.append(summary)

    networks = sorted(
        (n for n in raw.get("networks") or [] if isinstance(n, dict) and n.get("id")),
        key=lambda n: str(n.get("name") or n.get("id")).lower(),
    )
    networks_detail = raw.get("networks_detail") or {}
    for net in networks:
        products_here = set(net.get("productTypes") or [])
        applicable = [(r, c) for r, c in by_scope[SCOPE_NETWORK] if not c.products or products_here & set(c.products)]
        if not applicable:
            continue
        sources = dict(networks_detail.get(net["id"]) or {})
        findings = _evaluate_target(applicable, sources, {"network": net, "organization": org})
        summary = _summarise(
            {
                "target_kind": SCOPE_NETWORK,
                "target_id": str(net["id"]),
                "target_name": str(net.get("name") or net["id"]),
                "network_id": str(net["id"]),
                "network_name": str(net.get("name") or net["id"]),
                "model": "",
                "serial": "",
            },
            findings,
        )
        if summary:
            results.append(summary)

    if by_scope[SCOPE_DEVICE]:
        net_names = {n["id"]: str(n.get("name") or n["id"]) for n in networks}
        devices = sorted(
            (d for d in raw.get("devices") or [] if isinstance(d, dict) and d.get("serial")),
            key=lambda d: (net_names.get(d.get("networkId"), "").lower(), str(d.get("name") or d["serial"]).lower()),
        )
        ports_by_serial = raw.get("switch_ports")
        devices_detail = raw.get("devices_detail") or {}
        for dev in devices:
            kind = _device_kind(dev)
            applicable = [(r, c) for r, c in by_scope[SCOPE_DEVICE] if not c.products or kind in c.products]
            if not applicable:
                continue
            sources: dict[str, Any] = dict(devices_detail.get(dev["serial"]) or {})
            sources["device"] = dev
            if isinstance(ports_by_serial, Unreadable):
                sources["ports"] = ports_by_serial
            else:
                sources["ports"] = (ports_by_serial or {}).get(dev["serial"])
            findings = _evaluate_target(applicable, sources, {"device": dev, "organization": org})
            summary = _summarise(
                {
                    "target_kind": SCOPE_DEVICE,
                    "target_id": str(dev["serial"]),
                    "target_name": str(dev.get("name") or dev["serial"]),
                    "network_id": str(dev.get("networkId") or ""),
                    "network_name": net_names.get(dev.get("networkId"), ""),
                    "model": str(dev.get("model") or ""),
                    "serial": str(dev["serial"]),
                },
                findings,
            )
            if summary:
                results.append(summary)

    if by_scope[SCOPE_SSID]:
        ssids_detail = raw.get("ssids_detail") or {}
        for net in networks:
            if "wireless" not in set(net.get("productTypes") or []):
                continue
            net_name = str(net.get("name") or net["id"])
            ssids = (networks_detail.get(net["id"]) or {}).get("ssids")
            base = {"network_id": str(net["id"]), "network_name": net_name, "model": "", "serial": ""}
            if isinstance(ssids, Unreadable):
                # The SSID list itself could not be read: one target says so.
                findings = [
                    _finding(
                        rule, check, passed=False, unreadable=True, detail=f"Could not read ssids: {ssids.message}"
                    )
                    for rule, check in by_scope[SCOPE_SSID]
                ]
                summary = _summarise(
                    {
                        **base,
                        "target_kind": SCOPE_SSID,
                        "target_id": f"{net['id']}:*",
                        "target_name": f"SSIDs of {net_name}",
                    },
                    findings,
                )
                if summary:
                    results.append(summary)
                continue
            if not isinstance(ssids, list):
                continue
            per_net = ssids_detail.get(net["id"]) or {}
            for ssid in sorted(
                (x for x in ssids if isinstance(x, dict) and x.get("enabled") and x.get("number") is not None),
                key=lambda x: int(x["number"]) if str(x["number"]).isdigit() else 99,
            ):
                number = str(ssid["number"])
                sources: dict[str, Any] = dict(per_net.get(number) or {})
                sources["ssid"] = ssid
                sources["network"] = net
                findings = _evaluate_target(
                    by_scope[SCOPE_SSID], sources, {"ssid": ssid, "network": net, "organization": org}
                )
                summary = _summarise(
                    {
                        **base,
                        "target_kind": SCOPE_SSID,
                        "target_id": f"{net['id']}:{number}",
                        "target_name": str(ssid.get("name") or f"SSID {number}"),
                        "model": f"SSID {number}",
                    },
                    findings,
                )
                if summary:
                    results.append(summary)
    return results


def summarise_results(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"targets": len(results), "compliant": 0, "non_compliant": 0, "errors": 0}
    for r in results:
        if r["status"] == "compliant":
            counts["compliant"] += 1
        elif r["status"] == "non-compliant":
            counts["non_compliant"] += 1
        else:
            counts["errors"] += 1
    return counts


# ── Sample data ──────────────────────────────────────────────────────────────


def build_sample_compliance_raw() -> dict[str, Any]:
    """The demo organization's configuration in the collector's shape, with a
    few deliberate findings so the feature can be previewed without an API
    key (and exercised by tests)."""
    from netcontrol.integrations.meraki.sample import build_sample_raw

    topo = build_sample_raw()
    networks = topo["networks"]
    devices = topo["devices"]
    switch_ports: dict[str, list[dict]] = {}
    for entry in topo["org"].get("switch_ports") or []:
        ports = copy.deepcopy(entry["ports"])
        for port in ports:
            if port["type"] == "trunk":
                port["stpGuard"] = "loop guard"
                port["allowedVlans"] = "10,20,30,99"
            else:
                port["accessPolicyType"] = "Sticky MAC allow list"
                port["stickyMacAllowListLimit"] = 3
                port["stormControlEnabled"] = True
            port["tags"] = []
        switch_ports[entry["serial"]] = ports
    # Branch-Boston's first switch keeps three open ports on default settings
    # and one trunk carrying every VLAN, as a freshly added switch would.
    weak = next((s for s in switch_ports if s.startswith("Q2SW-0003-0001")), None)
    if weak:
        for port in switch_ports[weak]:
            if port["portId"] in ("5", "6", "7"):
                port["accessPolicyType"] = "Open"
                port["stpGuard"] = "disabled"
                port["stormControlEnabled"] = False
            if port["portId"] == "24":
                port["allowedVlans"] = "all"
                port["vlan"] = 1

    networks_detail: dict[str, dict] = {}
    ssids_detail: dict[str, dict] = {}
    for idx, net in enumerate(networks):
        topo_detail = topo["networks_detail"].get(net["id"], {})
        is_hub = idx < 2
        weak_branch = idx == 3
        detail: dict[str, Any] = {
            "dhcp_server_policy": {
                "defaultPolicy": "allow" if weak_branch else "block",
                "allowedServers": [] if weak_branch else ["mac:e0:55:3d:00:01:01"],
                "blockedServers": [],
                "arpInspection": {"enabled": not weak_branch},
                "alerts": {"email": {"enabled": True}},
            },
            "stp": topo_detail.get("stp") or {"rstpEnabled": True, "stpBridgePriority": []},
            "storm_control": {
                "broadcastThreshold": 100 if weak_branch else 30,
                "multicastThreshold": 100,
                "unknownUnicastThreshold": 100,
            },
            "firewall_settings": {"spoofingProtection": {"ipSourceGuard": {"mode": "log" if weak_branch else "block"}}},
            "intrusion": {"mode": "detection" if weak_branch else "prevention", "idsRulesets": "balanced"},
            "malware": {"mode": "enabled", "allowedUrls": [], "allowedFiles": []},
            "firewalled_services": [
                {"service": "ICMP", "access": "unrestricted"},
                {"service": "web", "access": "blocked"},
                {"service": "SNMP", "access": "unrestricted" if weak_branch else "blocked"},
            ],
            "port_forwarding": {
                "rules": [
                    {
                        "name": "Camera NVR",
                        "lanIp": f"10.{idx}.10.40",
                        "publicPort": "8443",
                        "localPort": "443",
                        "protocol": "tcp",
                        "allowedIps": ["any"] if weak_branch else ["203.0.113.0/24"],
                        "uplink": "both",
                    }
                ]
                if is_hub or weak_branch
                else []
            },
            "one_to_one_nat": {
                "rules": [
                    {
                        "name": "Web server",
                        "publicIp": f"198.51.100.{40 + idx}",
                        "lanIp": f"10.{idx}.100.10",
                        "uplink": "internet1",
                        "allowedInbound": [{"protocol": "tcp", "destinationPorts": ["443"], "allowedIps": ["any"]}],
                    }
                ]
                if is_hub
                else []
            },
            "l3_firewall": copy.deepcopy(topo_detail.get("l3_firewall") or {"rules": []}),
            "content_filtering": {
                "blockedUrlCategories": [{"id": "meraki:contentFiltering/category/C1", "name": "Malware Sites"}],
                "blockedUrlPatterns": [],
                "allowedUrlPatterns": [],
                "urlCategoryListSize": "topSites",
            },
            "ssids": copy.deepcopy(topo_detail.get("ssids") or []),
            "syslog": {
                "servers": []
                if weak_branch
                else [{"host": "10.0.0.20", "port": 514, "roles": ["Flows", "Security events"]}]
            },
            "net_snmp": {
                "access": "community" if weak_branch else "users",
                "users": [] if weak_branch else [{"username": "plexus"}],
            },
            "alerts": {
                "defaultDestinations": {
                    "emails": ["noc@example.com"],
                    "allAdmins": False,
                    "snmp": False,
                    "httpServerIds": [],
                },
                "alerts": [{"type": "rogueDhcp", "enabled": True, "alertDestinations": {}, "filters": {}}],
            },
        }
        if detail["l3_firewall"].get("rules"):
            detail["l3_firewall"]["rules"][-1]["syslogEnabled"] = not weak_branch
        per_ssid: dict[str, dict] = {}
        for ssid in detail["ssids"]:
            ssid["mandatoryDhcpEnabled"] = True
            if ssid["name"] == "Guest":
                # Bridge mode on the weak branch (and its SSID firewall still lets guests onto the LAN)
                ssid["ipAssignmentMode"] = "Bridge mode" if weak_branch else "NAT mode"
                ssid["lanIsolationEnabled"] = False
                ssid["wpaEncryptionMode"] = "WPA2 only"
                ssid["dot11w"] = {"enabled": True, "required": False}
                ssid["perClientBandwidthLimitDown"] = 0 if weak_branch else 5000
                ssid["perClientBandwidthLimitUp"] = 0 if weak_branch else 2000
                lan_policy = "allow" if weak_branch else "deny"
            else:
                ssid["wpaEncryptionMode"] = "WPA1 and WPA2" if weak_branch else "WPA3 Transition Mode"
                ssid["dot11w"] = {"enabled": not weak_branch, "required": False}
                ssid["radiusServers"] = [{"host": "10.0.0.30", "port": 1812}] + (
                    [] if weak_branch else [{"host": "10.0.0.31", "port": 1812}]
                )
                ssid["radiusAccountingEnabled"] = not weak_branch
                lan_policy = "allow"
            per_ssid[str(ssid["number"])] = {
                "ssid_l3_firewall": {
                    "rules": [
                        {
                            "comment": "Wireless clients accessing LAN",
                            "policy": lan_policy,
                            "protocol": "Any",
                            "destPort": "Any",
                            "destCidr": "Local LAN",
                        },
                        {
                            "comment": "Default rule",
                            "policy": "allow",
                            "protocol": "Any",
                            "destPort": "Any",
                            "destCidr": "Any",
                        },
                    ]
                }
            }
        ssids_detail[net["id"]] = per_ssid
        networks_detail[net["id"]] = detail

    now = datetime.now(UTC)
    admins = [
        {
            "id": "1",
            "name": "Network Admin",
            "email": "netadmin@example.com",
            "orgAccess": "full",
            "twoFactorAuthEnabled": True,
            "accountStatus": "ok",
            "lastActive": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        {
            "id": "2",
            "name": "Helpdesk",
            "email": "helpdesk@example.com",
            "orgAccess": "read-only",
            "twoFactorAuthEnabled": True,
            "accountStatus": "ok",
            "lastActive": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        {
            "id": "3",
            "name": "Former Contractor",
            "email": "contractor@example.net",
            "orgAccess": "full",
            "twoFactorAuthEnabled": False,
            "accountStatus": "ok",
            "lastActive": "2025-01-15T09:30:00Z",
        },
    ]
    return {
        "organization": topo["organization"],
        "networks": networks,
        "devices": devices,
        "org": {
            "admins": admins,
            "login_security": {
                "enforceTwoFactorAuth": False,
                "enforceStrongPasswords": True,
                "enforceIdleTimeout": True,
                "idleTimeoutMinutes": 30,
                "enforceAccountLockout": True,
                "accountLockoutAttempts": 5,
                "enforcePasswordExpiration": False,
                "passwordExpirationDays": None,
                "enforceDifferentPasswords": True,
                "numDifferentPasswords": 5,
                "enforceLoginIpRanges": False,
                "loginIpRanges": [],
                "apiAuthentication": {"ipRestrictionsForKeys": {"enabled": False, "ranges": []}},
            },
            "org_snmp": {"v2cEnabled": False, "v3Enabled": True, "v3AuthMode": "SHA", "v3PrivMode": "AES128"},
        },
        "networks_detail": networks_detail,
        "devices_detail": {d["serial"]: {} for d in devices},
        "switch_ports": switch_ports,
        "ssids_detail": ssids_detail,
        "errors": [],
        "stats": {"requests": 0, "retries": 0, "rate_limited": 0},
        "options": {"sample": True},
    }
