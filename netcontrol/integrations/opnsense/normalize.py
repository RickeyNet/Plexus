"""Turn raw OPNsense payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index, IPAM,
the HTML export, availability tracking and the software tracker need no
OPNsense-specific code.

How a firewall maps onto the map:

  - the firewall is one ``appliance`` node (``d:<host name>``) in a site box
    named after the entry. Its "Connected subnets" (the networks of its
    interface addresses) and "Static routes" (gateway routes of its routing
    table) feed the subnet index, so they reach Path Mode and IPAM.
  - every gateway is a WAN stub node (``w:<gateway>``) joined to the
    firewall by an ``uplink`` edge whose status is the gateway's monitor
    state: ``active`` (online), ``degraded`` (latency or loss alarm),
    ``failed`` (down, or forced down) or ``unknown`` (no monitor data: the
    gateway is not monitored, or its state is pending). The loss, RTT and
    RTT deviation are in the edge's ``detail`` (display text), the stub's
    details and, as numbers, the edge's ``metrics`` (``latency_ms``,
    ``jitter_ms`` (the RTT deviation), ``loss_pct``; latency and jitter
    are left out of a gateway with 100 % loss), which availability tracking
    stores as a time series for SLA targets.
  - every IPsec connection, WireGuard peer and OpenVPN client instance is a
    ``vpn3p`` tunnel edge to a ``vpn_peer`` node in a "VPN peers" box, with
    the status ``reachable`` (up), ``degraded`` (an IPsec connection whose
    phase 1 is up while none of its configured child SAs is installed, a
    WireGuard handshake older than 5 minutes, an OpenVPN client that is
    (re)connecting) or ``unreachable`` (down). An IPsec tunnel lists its
    child SAs (phase 2) in its details. Each tunnel, and each OpenVPN
    server below (the sum of its connected clients), carries a ``traffic``
    block with its byte counters (``vpn_traffic_blocks``, which the
    monitoring poll of the firewall uses too), from which the stored
    collection gets a rate and a "Traffic" section
    (``netcontrol.integrations.traffic``, ``netcontrol.routes.topology_traffic``).
  - every OpenVPN server instance is a ``vpn_server`` node next to the
    firewall (``ovpn:server:<id>``): ``online`` when it runs, ``offline``
    when it is enabled but not running. The clients connected to it are
    listed in its details; they are users, not tunnels.

The firmware status (a pending update) and the findings of the security
audit are shown in the firewall's details and added to the collection
report as informational warnings (``info``: they do not mean the collection
was incomplete); so is an audit that did not verifiably complete ("Audit
incomplete"). The CARP virtual IPs are the firewall's "High availability"
section and the snapshot's ``ha`` block (``ha_block``: one record per CARP
group with its role and status), which availability tracking reads as
entities and the Topology map uses to draw two firewalls of a CARP pair as
one HA cluster (``netcontrol.integrations.opnsense.ha``). A VIP in ``INIT``
or a non-zero CARP demotion is an informational warning: the state itself
is carried by the tracked entity.

The health (CPU, load, memory, file systems, temperature, state table,
uptime) is the firewall's "Health" section and the snapshot's ``health``
block (``health_summary``); the services the configuration enables are the
"Services" section and the snapshot's ``services`` (one record each,
``online`` while it runs, ``offline`` when not), which availability tracking
reads as ``service`` entities of the firewall. A nearly full file system or
a state table near its limit is an informational warning.

The certificates and CAs of the trust store are the "Certificates" section
and the snapshot's ``certificates`` (``certificates.certificate_records``:
expiry, days left at the collection time, tier, whether it is tracked);
availability tracking reads the tracked ones (in use, or a CA a tracked
certificate depends on) as ``certificate`` entities of the firewall, and a
tracked certificate that expires within 30 days, or has expired, is an
informational warning.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from netcontrol.integrations.meraki.clients import normalize_mac
from netcontrol.integrations.meraki.forwarding import canonical
from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    InventoryIndex,
    _add,
    _inventory_ref,
    _layout,
    _s,
    _worst,
    kv_section,
    table_section,
)
from netcontrol.integrations.opnsense.certificates import certificate_records, days_text
from netcontrol.integrations.opnsense.collector import LEASE_BACKENDS, info_warning
from netcontrol.integrations.remote_users import DIRECTORY_KEY, directory_entry
from netcontrol.integrations.software.versions import canonical_version
from netcontrol.integrations.traffic import counter_pair, traffic_block

PROVIDER = "opnsense"
SOURCE = "OPNsense API"
DEVICE_NODE_PREFIX = "d:"
GATEWAY_NODE_PREFIX = "w:"
PEER_NODE_PREFIX = "p:"
OPENVPN_SERVER_PREFIX = "ovpn:server:"
PEERS_SITE_ID = "__opnsense_vpn_peers__"
ADVISORY_SOURCE = "opnsense-audit"

# Section titles of the firewall node (the Topology page files them into tabs).
SECTION_OVERVIEW = "Overview"
SECTION_INTERFACES = "Interfaces"
SECTION_CONNECTED = "Connected subnets"
SECTION_GATEWAYS = "Gateways"
SECTION_STATIC_ROUTES = "Static routes"
SECTION_ROUTING_TABLE = "Routing table"
SECTION_IPSEC = "IPsec tunnels"
SECTION_WIREGUARD = "WireGuard peers"
SECTION_OPENVPN = "OpenVPN instances"
SECTION_FIRMWARE = "Firmware"
SECTION_UPDATES = "Pending updates"
SECTION_AUDIT = "Security audit"
SECTION_VULNERABLE = "Vulnerable packages"
SECTION_INVENTORY = "Plexus inventory"
SECTION_HA = "High availability"
SECTION_ARP = "ARP table"
SECTION_NDP = "NDP table"
SECTION_LEASES = "DHCP leases"
SECTION_HEALTH = "Health"
SECTION_SERVICES = "Services"
SECTION_CERTIFICATES = "Certificates"
# Section titles of the gateway, tunnel peer and OpenVPN server nodes.
SECTION_GATEWAY = "Gateway"
SECTION_IPSEC_PEER = "IPsec peer"
SECTION_IPSEC_CHILDREN = "Child SAs"
SECTION_WIREGUARD_PEER = "WireGuard peer"
SECTION_OPENVPN_PEER = "OpenVPN peer"
SECTION_OPENVPN_SERVER = "OpenVPN server"
SECTION_OPENVPN_CLIENTS = "Connected clients"

MAX_ROUTE_ROWS = 2000
# The ARP, NDP and lease tables shown in the firewall's details (every row
# still reaches MAC tracking and IPAM).
MAX_CLIENT_ROWS = 2000

# Gateway monitor status (``routes/gateway/status``; dpinger) -> uplink edge
# status. "none" is OPNsense's "Online" (no alarm); see ``gateway_status``.
_GATEWAY_EDGE_STATUS = {
    "none": "active",
    "online": "active",
    "down": "failed",
    "offline": "failed",
    "force_down": "failed",
    "delay": "degraded",
    "loss": "degraded",
    "delay+loss": "degraded",
}
_EDGE_NODE_STATUS = {
    "active": "online",
    "reachable": "online",
    "degraded": "alerting",
    "failed": "offline",
    "unreachable": "offline",
}
# WireGuard ``peer-status`` (``wireguard/service/show`` on current releases;
# without it the age of the latest handshake decides).
_WIREGUARD_EDGE_STATUS = {"online": "reachable", "stale": "degraded", "offline": "unreachable"}
# A WireGuard peer is online while its latest handshake is this recent
# (OPNsense's own rule; peers shake hands about every 2 minutes).
WIREGUARD_ONLINE_SECONDS = 300
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
# strongSwan child SA states (``state`` of a ``search_phase2`` row) in which
# the SA carries traffic.
_CHILD_SA_UP = frozenset({"INSTALLED", "REKEYING", "REKEYED", "UPDATING"})


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    """The number in an OPNsense metric (``"4.2 ms"``, ``"0.0 %"``); ``None``
    for ``"~"`` (no monitor data) or anything else without one."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    match = _NUMBER.search(_text(value))
    return float(match.group(0)) if match else None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def gateway_status(item: dict) -> str:
    """The uplink edge status of a gateway: ``active``, ``degraded``,
    ``failed`` or ``unknown``. OPNsense reports ``none`` for a gateway with
    no alarm ("Online"), and also for a gateway it does not monitor (its
    loss and delay are then ``~``): that one is ``unknown``, since nothing
    says whether it is up."""
    raw = _text(item.get("status")).lower()
    edge = _GATEWAY_EDGE_STATUS.get(raw, "unknown")
    if raw == "none" and _number(item.get("delay")) is None and _number(item.get("loss")) is None:
        return "unknown"
    return edge


def wireguard_status(peer: dict, now: float | None = None) -> str:
    """``reachable`` / ``degraded`` / ``unreachable`` of a WireGuard peer:
    OPNsense's ``peer-status`` when it reports one, else from the age of
    the latest handshake."""
    found = _WIREGUARD_EDGE_STATUS.get(_text(peer.get("peer-status")).lower())
    if found:
        return found
    age = _number(peer.get("latest-handshake-age"))
    handshake = _number(peer.get("latest-handshake"))
    if age is None and handshake and now:
        age = now - handshake
    if not handshake and age is None:
        return "unreachable"
    if age is None:
        return "unknown"
    return "reachable" if age <= WIREGUARD_ONLINE_SECONDS else "degraded"


def openvpn_client_status(row: dict) -> str:
    """``reachable`` / ``degraded`` / ``unreachable`` of an OpenVPN client
    instance from its management ``state`` (``connected``, ``reconnecting``,
    ``wait``...), or ``failed`` / none when it does not run."""
    state = _text(row.get("status")).lower()
    if state == "connected":
        return "reachable"
    if not state or state in ("failed", "exiting"):
        return "unreachable"
    return "degraded"


def child_sa_installed(row: dict) -> bool:
    """Whether a child SA row of ``ipsec/sessions/search_phase2`` carries
    traffic. The rows are the SAs strongSwan has, so a row without a
    ``state`` counts as installed."""
    state = _text(row.get("state")).upper()
    return not state or state in _CHILD_SA_UP


def ipsec_status(connected: bool, installed: int | None, configured: int | None) -> str:
    """``reachable`` / ``degraded`` / ``unreachable`` of an IPsec connection:
    no SA is down; an SA with configured child SAs none of which is
    installed is degraded (phase 1 up, no traffic). Unknown counts (a call
    that did not answer, a legacy tunnel) never degrade."""
    if not connected:
        return "unreachable"
    if configured and installed == 0:
        return "degraded"
    return "reachable"


def gateway_metrics(item: dict) -> dict[str, float]:
    """The numbers of a gateway's monitor (dpinger): ``latency_ms`` (RTT),
    ``jitter_ms`` (RTT deviation) and ``loss_pct``. A gateway with 100 %
    loss has no meaningful RTT: only its loss is kept."""
    found = {
        "latency_ms": _number(item.get("delay")),
        "jitter_ms": _number(item.get("stddev")),
        "loss_pct": _number(item.get("loss")),
    }
    if (found["loss_pct"] or 0) >= 100:
        found["latency_ms"] = found["jitter_ms"] = None
    return {k: v for k, v in found.items() if v is not None}


# ── Tunnel traffic (``netcontrol.integrations.traffic``) ────────────────────
#
# "in" is what the firewall received through the tunnel, "out" what it sent.


def ipsec_traffic(key: str, row: dict, children: list[dict] | None) -> dict | None:
    """The ``traffic`` block of an IPsec connection. The phase 1 row's
    ``bytes-in`` / ``bytes-out`` are OPNsense's sums over the child SAs of
    every IKE SA of the connection (``SessionsController::searchPhase1``),
    so they are the totals; the rate is computed per child SA (``children``:
    the ``search_phase2`` rows, ``None`` when not read), keyed by strongSwan's
    ``uniqueid``, since a rekey replaces a child SA and its counters. A
    connection that is not connected has no child SA."""
    counters: dict[str, list[int]] | None = {}
    if row.get("connected"):
        if children is None:
            counters = None
        for child in children or []:
            ident = _text(child.get("uniqueid")) or _text(child.get("spi-in")) or _text(child.get("name"))
            pair = counter_pair(child.get("bytes-in"), child.get("bytes-out"))
            if counters is None or pair is None or f"sa:{ident}" in counters:
                counters = None
                break
            counters[f"sa:{ident}"] = pair
    return traffic_block(key, counter_pair(row.get("bytes-in"), row.get("bytes-out")), counters)


def wireguard_traffic(key: str, peer: dict) -> dict | None:
    """The ``traffic`` block of a WireGuard peer: ``transfer-rx`` /
    ``transfer-tx`` of ``wg show`` (bytes since the interface came up)."""
    pair = counter_pair(peer.get("transfer-rx"), peer.get("transfer-tx"))
    return traffic_block(key, pair, {"peer": pair} if pair is not None else None)


def _openvpn_session(row: dict) -> str:
    """A session's counter id: a reconnect gets a new address (port) and start time."""
    return "|".join(_text(row.get(k)) for k in ("common_name", "real_address", "connected_since"))


def openvpn_traffic(key: str, sessions: list[dict]) -> dict | None:
    """The ``traffic`` block of an OpenVPN instance from its session rows:
    the client instance's own row, or the connected clients of a server
    (``bytes_received`` / ``bytes_sent``: from the management ``status``,
    per session; a server's traffic is the sum of its clients')."""
    counters: dict[str, list[int]] = {}
    for row in sessions:
        pair = counter_pair(row.get("bytes_received"), row.get("bytes_sent"))
        if pair is None or _openvpn_session(row) in counters:
            return None
        counters[_openvpn_session(row)] = pair
    return traffic_block(key, None, counters)


def ipsec_traffic_key(row: dict) -> str:
    return f"ipsec:{_text(row.get('ikeid')) or _text(row.get('name'))}"


def wireguard_traffic_key(peer: dict) -> str:
    return f"wg:{_text(peer.get('if'))}:{_text(peer.get('public-key'))}"


def openvpn_ident(row: dict) -> str:
    """The instance id of an ``openvpn/service/search_sessions`` row."""
    return _text(row.get("service_id")).removeprefix("openvpn/") or _text(row.get("id")).split("_", 1)[0]


def openvpn_traffic_key(role: str, ident: str) -> str:
    return f"ovpn:{role}:{ident}"


def vpn_traffic_blocks(raw: dict) -> dict[str, dict]:
    """The ``traffic`` blocks of a firewall's tunnels and OpenVPN servers by
    key, from the raw VPN payloads (``collector.collect_vpn``: a collection
    or a monitoring poll). The snapshot puts each on its tunnel edge or
    server node (``_Builder``); the poll computes rates from them
    (``netcontrol.routes.opnsense_health``)."""
    blocks: dict[str, dict | None] = {}
    phase2 = raw.get("ipsec_phase2") if isinstance(raw.get("ipsec_phase2"), dict) else None
    for row in _dicts(raw.get("ipsec")):
        name = _text(row.get("name"))
        children = _dicts(phase2.get(name)) if phase2 is not None and name in phase2 else None
        blocks[ipsec_traffic_key(row)] = ipsec_traffic(ipsec_traffic_key(row), row, children)
    for row in _dicts(raw.get("wireguard")):
        if _text(row.get("type")) == "peer":
            blocks[wireguard_traffic_key(row)] = wireguard_traffic(wireguard_traffic_key(row), row)
    servers: dict[str, list[dict]] = {}
    for row in _dicts(raw.get("openvpn")):
        role = _text(row.get("type"))
        if role == "server":
            servers.setdefault(openvpn_ident(row), []).append(row)
        elif role == "client":
            key = openvpn_traffic_key("client", openvpn_ident(row))
            blocks[key] = openvpn_traffic(key, [row])
    for ident, rows in servers.items():
        key = openvpn_traffic_key("server", ident)
        blocks[key] = openvpn_traffic(key, [r for r in rows if r.get("is_client")])
    return {key: block for key, block in blocks.items() if block is not None}


# CARP role of a VIP on this firewall -> availability status of its group
# (the shared node vocabulary). A standby (``BACKUP``) is as healthy as the
# master; ``INIT``: its interface is down or CARP cannot run on it;
# ``DISABLED``: CARP is off on this node, which gives no redundancy.
_CARP_STATUS = {"MASTER": "online", "BACKUP": "online", "INIT": "offline", "DISABLED": "alerting"}


def _flag(value: Any) -> bool:
    """An OPNsense boolean (``True``, ``1``, ``"1"``, ``"true"``)."""
    return value in (True, 1, "1", "true")


def carp_groups(carp: dict | None) -> list[dict]:
    """The CARP groups of the firewall, one per interface and VHID (several
    addresses on one VHID are one group): ``id`` (``carp:<interface>:<vhid>``,
    stable across collections), ``interface``, ``vhid``, ``addresses``,
    ``role`` (``MASTER`` / ``BACKUP`` / ``INIT`` / ``DISABLED``, upper
    case), ``advbase``, ``advskew`` and ``status``: ``online`` for a master
    or a backup, ``alerting`` for one while the firewall's CARP demotion is
    not 0 or it is in maintenance mode, and for ``DISABLED``, ``offline``
    for ``INIT``, ``unknown`` for anything else. Empty when CARP was not
    read."""
    if not carp:
        return []
    state = _dict(carp.get("carp"))
    demoted = bool(_number(state.get("demotion"))) or _flag(state.get("maintenancemode"))
    groups: dict[tuple[str, str], dict] = {}
    for row in _dicts(carp.get("rows")):
        vhid = _text(row.get("vhid"))
        if not vhid:
            continue
        interface = _text(row.get("interface"))
        group = groups.setdefault(
            (interface, vhid),
            {
                "id": f"carp:{interface}:{vhid}",
                "interface": interface,
                "vhid": vhid,
                "addresses": [],
                "role": "",
                "advbase": _text(row.get("advbase")),
                "advskew": _text(row.get("advskew")),
            },
        )
        address = _text(row.get("subnet"))
        if address and address not in group["addresses"]:
            group["addresses"].append(address)
        role = _text(row.get("status")).upper()
        # The CARP address's role wins over an IP alias stacked on its VHID.
        if role and (not group["role"] or _text(row.get("mode")).lower() == "carp"):
            group["role"] = role
    for group in groups.values():
        status = _CARP_STATUS.get(group["role"], "unknown")
        group["status"] = "alerting" if status == "online" and demoted else status
    return list(groups.values())


def ha_block(carp: dict | None, device_id: str) -> dict | None:
    """The snapshot's ``ha`` block: the firewall's CARP groups
    (``carp_groups``) with its demotion and maintenance mode, for
    availability tracking and the HA pair on the map. ``None`` when CARP
    was not read."""
    if carp is None:
        return None
    state = _dict(carp.get("carp"))
    maintenance = state.get("maintenancemode")
    return {
        "protocol": "CARP",
        "device": device_id,
        "demotion": _number(state.get("demotion")),
        "maintenance": None if maintenance is None else _flag(maintenance),
        "vips": carp_groups(carp),
    }


def carp_problems(carp: dict | None) -> list[str]:
    """What is wrong with the firewall's CARP state: a VIP in ``INIT``
    (its interface is down or CARP cannot run on it), a non-zero demotion
    (the firewall gives up being master)."""
    if not carp:
        return []
    problems = [
        f"{_text(r.get('interface')) or '?'} VHID {_text(r.get('vhid')) or '?'} ({_text(r.get('subnet'))})"
        for r in _dicts(carp.get("rows"))
        if _text(r.get("status")).upper() == "INIT"
    ]
    found = [f"CARP VIP in INIT: {', '.join(problems)}"] if problems else []
    demotion = _number(_dict(carp.get("carp")).get("demotion"))
    if demotion:
        found.append(f"CARP demotion is {demotion:g} (the firewall does not take or keep the master role)")
    return found


_IPSEC_STATE_TEXT = {"reachable": "up", "degraded": "up, no child SA installed", "unreachable": "down"}


def _child_count_text(installed: int | None, configured: int | None) -> str:
    """``1 of 2 installed``, ``1 installed``, ``2 configured`` or ``""``."""
    if installed is not None and configured is not None:
        return f"{installed} of {configured} installed"
    if installed is not None:
        return f"{installed} installed"
    return f"{configured} configured" if configured is not None else ""


def _specific_peer(remote: str) -> bool:
    """Whether an IPsec remote address names one peer (not ``%any``, a list,
    or the unspecified address of a responder that accepts any peer)."""
    if not remote or remote == "%any" or "," in remote:
        return False
    try:
        return not ipaddress.ip_address(remote).is_unspecified
    except ValueError:
        return True  # a host name


def _host_part(address: str) -> str:
    """``198.51.100.40`` of ``198.51.100.40:51820`` (and of ``[2001:db8::1]:51820``)."""
    text = _text(address)
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _cidr_of(address: str) -> str:
    """The network of ``192.0.2.1/25`` (``""`` when it is not one)."""
    text = _text(address)
    return canonical(text) if "/" in text else ""


def interface_addresses(row: dict) -> list[str]:
    """Every ``address/prefix`` of an interface row."""
    found: list[str] = []
    for family in ("ipv4", "ipv6"):
        for item in _dicts(row.get(family)):
            address = _text(item.get("ipaddr"))
            if address and address not in found:
                found.append(address)
    for key in ("addr4", "addr6"):
        address = _text(row.get(key))
        if address and address not in found:
            found.append(address)
    return found


def _plain_address(text: str) -> str:
    """The canonical address of ``192.0.2.1/24``, ``2001:db8::1%vtnet0`` or
    ``198.51.100.7``, or ``""`` for something else or an address no single
    firewall owns (link-local, loopback, unspecified)."""
    text = text.strip().split("/", 1)[0].split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if address.is_link_local or address.is_loopback or address.is_unspecified:
        return ""
    return str(address)


def snapshot_addresses(snapshot: dict) -> list[str]:
    """Every address the firewall of an OPNsense snapshot owns: the
    firewall node's address, the host of its API URL when that is an
    address, the IPv4 / IPv6 columns of its "Interfaces" section and its
    CARP virtual IPs (``ha``). Plain canonical addresses, each once.

    A firewall sends syslog from whichever interface faces the receiver, so
    the syslog receiver maps a message's source address to its topology
    source through all of them (``netcontrol.source_recollect``)."""
    found: list[str] = []

    def add(text: Any) -> None:
        for part in _text(text).split(","):
            address = _plain_address(part)
            if address and address not in found:
                found.append(address)

    add(urlsplit(_text(_dict(snapshot.get("org")).get("url"))).hostname or "")
    for node in _dicts(snapshot.get("nodes")):
        if node.get("kind") != "appliance" or not _text(node.get("id")).startswith(DEVICE_NODE_PREFIX):
            continue
        add(node.get("ip"))
        for section in _dicts(node.get("sections")):
            if section.get("title") != SECTION_INTERFACES or section.get("kind") != "table":
                continue
            columns = [c for c in section.get("columns") or [] if c in ("IPv4", "IPv6")]
            indexes = [section["columns"].index(c) for c in columns]
            for row in section.get("rows") or []:
                for index in indexes:
                    if index < len(row):
                        add(row[index])
    for vip in _dicts(_dict(snapshot.get("ha")).get("vips")):
        for address in vip.get("addresses") or []:
            add(address)
    return found


def _route_is_static(route: dict) -> bool:
    """A gateway route of the routing table: ``G`` and ``S`` flags, not the
    default route, not a host route to the firewall itself."""
    flags = _text(route.get("flags"))
    destination = _text(route.get("destination"))
    return "G" in flags and "S" in flags and destination not in ("default", "") and "H" not in flags


def audit_advisories(audit: dict | None, version: str) -> list[dict[str, Any]]:
    """The findings of a security audit as software advisories for the
    ``opnsense`` platform at ``version`` (one per VuXML entry; the entry id,
    or the package and description when there is none, names it).
    ``pkg audit`` gives no severity: every advisory is ``medium``."""
    version = canonical_version(version)
    if not audit or not version:
        return []
    by_id: dict[str, dict[str, Any]] = {}
    for finding in _dicts(_dict(audit).get("findings")):
        package = _text(finding.get("package"))
        description = _text(finding.get("description"))
        key = _text(finding.get("vuxml_id")) or re.sub(r"[^a-z0-9]+", "-", f"{package} {description}".lower()).strip(
            "-"
        )
        advisory_id = f"{ADVISORY_SOURCE}:{key}"[:200]
        entry = by_id.setdefault(
            advisory_id,
            {
                "advisory_id": advisory_id,
                "source": ADVISORY_SOURCE,
                "title": f"{package}: {description}"[:300] if description else package,
                "severity": "medium",
                "cvss": None,
                "platform": PROVIDER,
                "product_match": "",
                "affected_versions": [version],
                "fixed_versions": [],
                "cves": [],
                "url": _text(finding.get("url")),
                "published": "",
                "summary": "",
                "_packages": [],
            },
        )
        entry["cves"].extend(c for c in finding.get("cves") or [] if c not in entry["cves"])
        label = f"{package}-{_text(finding.get('version'))}"
        if label not in entry["_packages"]:
            entry["_packages"].append(label)
    advisories = []
    for entry in by_id.values():
        packages = entry.pop("_packages")
        entry["summary"] = (
            "Reported by the OPNsense security audit (pkg audit) for the installed package(s) "
            f"{', '.join(packages)} on OPNsense {version}."
        )
        advisories.append(entry)
    return advisories


# ── Clients: ARP, NDP, DHCP leases ──────────────────────────────────────────


def _address(value: Any) -> str:
    """The canonical text of an IP address (``""`` when it is none: a
    delegated prefix ``2001:db8:1::/56`` is no address)."""
    try:
        return str(ipaddress.ip_address(_text(value).split("%", 1)[0]))
    except ValueError:
        return ""


def _neighbour_entries(rows: Any) -> list[dict[str, str]]:
    """ARP or NDP rows (``search_arp`` / ``get_arp`` / ``search_ndp``) as
    MAC tracking ``arp_table`` entries; incomplete entries (no MAC) and
    duplicate addresses are left out."""
    entries: dict[str, dict[str, str]] = {}
    for row in _dicts(rows):
        ip = _address(row.get("ip"))
        mac = normalize_mac(row.get("mac"))
        if not ip or not mac or ip in entries:
            continue
        entries[ip] = {
            "ip_address": ip,
            "mac_address": mac,
            "interface_name": _text(row.get("intf_description")) or _text(row.get("intf")),
            "device": _text(row.get("intf")),
            "hostname": _text(row.get("hostname")),
            "manufacturer": _text(row.get("manufacturer")),
            "type": "permanent" if row.get("permanent") in (True, "1", 1, "true") else _text(row.get("type")),
        }
    return list(entries.values())


def arp_entries(clients: Any) -> list[dict[str, str]]:
    """The ARP table of a collection's ``clients`` part (see ``_neighbour_entries``)."""
    return _neighbour_entries(_dict(clients).get("arp"))


def ndp_entries(clients: Any) -> list[dict[str, str]]:
    """The NDP (IPv6 neighbour) table of a collection's ``clients`` part."""
    return _neighbour_entries(_dict(clients).get("ndp"))


def _epoch_text(value: Any) -> str:
    """UTC ISO text of epoch seconds (``""`` for 0, nothing or not a number)."""
    number = _number(value)
    if not number or number <= 0:
        return ""
    try:
        return datetime.fromtimestamp(number, UTC).isoformat(timespec="seconds")
    except OverflowError, OSError, ValueError:
        return ""


def _lease_time(value: Any) -> str:
    """An ISC lease time (``2026/11/14 08:00:00``, UTC as dhcpd writes it)
    as ISO text; epoch seconds too; ``""`` for ``never`` or nothing."""
    text = _text(value)
    if not text or text.lower() in ("never", "infinite"):
        return ""
    if text.isdigit():
        return _epoch_text(text)
    for layout in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, layout).replace(tzinfo=UTC).isoformat(timespec="seconds")
        except ValueError:
            continue
    return text


# Kea lease ``state``: 0 default (active), 1 declined, 2 expired-reclaimed.
_KEA_LEASE_STATE = {"0": "active", "1": "declined", "2": "expired"}


def _lease(backend: str, row: dict) -> dict[str, Any] | None:
    """One lease row of ``backend`` (a ``LEASE_BACKENDS`` key) as a
    ``dhcp_leases`` record, or ``None`` when it has no address."""
    address = _address(row.get("address"))
    if not address:
        return None
    kind = _text(row.get("type")).lower()
    starts = ends = ""
    if backend.startswith("isc"):
        mac = normalize_mac(row.get("mac") or row.get("hwaddr"))
        hostname = _text(row.get("hostname")) or _text(row.get("client-hostname"))
        client_id = _text(row.get("uid")) or _text(row.get("duid"))
        state = "static" if kind == "static" else (_text(row.get("binding")) or _text(row.get("state")) or "active")
        starts, ends = _lease_time(row.get("starts")), _lease_time(row.get("ends"))
    else:
        # Kea and Dnsmasq: ``hwaddr``, ``expire`` (epoch), Kea's ``valid_lifetime``.
        mac = normalize_mac(row.get("hwaddr") or row.get("mac"))
        hostname = _text(row.get("hostname")).rstrip(".")
        client_id = _text(row.get("client_id")) or _text(row.get("duid"))
        state = _KEA_LEASE_STATE.get(_text(row.get("state")), "active") if backend.startswith("kea") else "active"
        ends = _epoch_text(row.get("expire"))
        lifetime = _number(row.get("valid_lifetime"))
        expire = _number(row.get("expire"))
        if ends and lifetime and expire:
            starts = _epoch_text(expire - lifetime)
    interface = _text(row.get("if_descr")) or _text(row.get("if"))
    return {
        "address": address,
        "scope_subnet": "",
        "mac_address": mac,
        "hostname": hostname,
        "client_id": client_id,
        "state": state.lower(),
        "starts_at": starts,
        "ends_at": ends,
        "metadata": {
            "source": PROVIDER,
            "backend": backend,
            "interface": interface,
            "type": kind,
            "description": _text(row.get("descr")),
            "online": _text(row.get("status")),
            "reserved": _text(row.get("is_reserved")).lower() in ("1", "true")
            if _text(row.get("is_reserved"))
            else None,
        },
    }


def dhcp_leases(clients: Any, interfaces: Any = None) -> list[dict[str, Any]]:
    """The DHCP leases of a collection's ``clients`` part, one per address
    (the first backend in ``LEASE_BACKENDS`` order wins), as ``dhcp_leases``
    records. ``scope_subnet`` is the network of the firewall interface the
    address is in (``interfaces``: the collection's interface rows)."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for row in _dicts(interfaces):
        for text in interface_addresses(row):
            cidr = _cidr_of(text)
            if cidr:
                networks.append(ipaddress.ip_network(cidr))
    # Most specific network first.
    networks.sort(key=lambda n: n.prefixlen, reverse=True)
    by_backend = _dict(_dict(clients).get("leases"))
    leases: dict[str, dict[str, Any]] = {}
    for backend, _name, _paths, _privilege in LEASE_BACKENDS:
        for row in _dicts(by_backend.get(backend)):
            lease = _lease(backend, row)
            if lease is None or lease["address"] in leases:
                continue
            ip = ipaddress.ip_address(lease["address"])
            lease["scope_subnet"] = next((str(n) for n in networks if n.version == ip.version and ip in n), "")
            leases[lease["address"]] = lease
    return list(leases.values())


def client_counts(clients: Any) -> dict[str, Any]:
    """The counts of a collection's ``clients`` part: ``arp`` / ``ndp``
    entries and ``dhcp_leases`` (``None`` for a part that was not read),
    and the lease count per backend that answered."""
    found = _dict(clients)
    backends = _dict(found.get("leases"))
    leases = dhcp_leases(found) if found.get("leases") is not None else None
    return {
        "arp": len(arp_entries(found)) if found.get("arp") is not None else None,
        "ndp": len(ndp_entries(found)) if found.get("ndp") is not None else None,
        "dhcp_leases": len(leases) if leases is not None else None,
        "lease_backends": {
            name: len(_dicts(backends.get(key))) for key, name, _p, _v in LEASE_BACKENDS if key in backends
        },
    }


# ── Health and services ─────────────────────────────────────────────────────

# A file system at or above this use (%) is "full", a state table at or above
# this share of its limit "near its limit": a collection warning, and the
# monitoring poll's built-in alerts (``opnsense.health``); the second value
# is the critical level.
DISK_FULL_PCT = (90.0, 95.0)
STATE_TABLE_FULL_PCT = (80.0, 95.0)
# Read-only media are always 100 % used: never "full".
_READ_ONLY_FS = frozenset({"cd9660"})
_MIB = 1024 * 1024
# ``top``'s CPU line: ``CPU:  2.0% user,  0.0% nice,  1.2% system,  0.4% interrupt, 96.4% idle``.
_CPU_IDLE = re.compile(r"([\d.]+)%\s+idle")
# ``last pid: 12345;  load averages:  0.10,  0.20,  0.15 ...``
_TOP_LOAD = re.compile(r"load averages?:\s*([\d.]+),?\s+([\d.]+),?\s+([\d.]+)")
# ``system_time``'s uptime: ``3 days, 01:02:03`` (the word is translated) or ``01:02:03``.
_UPTIME = re.compile(r"^\s*(?:(\d+)\D*,\s*)?(\d+):(\d{2}):(\d{2})\s*$")


def _cpu_percent(activity: Any) -> float | None:
    """CPU use (100 - idle) from the ``CPU:`` header line of ``top``."""
    for line in _dict(activity).get("headers") or []:
        if isinstance(line, str) and line.lstrip().startswith("CPU:"):
            match = _CPU_IDLE.search(line)
            if match:
                return round(max(0.0, min(100.0, 100.0 - float(match.group(1)))), 1)
    return None


def _load_averages(time_info: dict, activity: Any) -> list[float]:
    """The 1, 5 and 15 minute load averages: ``system_time``'s ``loadavg``
    (``0.10, 0.20, 0.15``; 25.1+), else ``top``'s first header line."""
    found = [n for part in _text(time_info.get("loadavg")).split(",") if (n := _number(part)) is not None]
    if len(found) == 3:
        return found
    for line in _dict(activity).get("headers") or []:
        match = _TOP_LOAD.search(line) if isinstance(line, str) else None
        if match:
            return [float(match.group(i)) for i in (1, 2, 3)]
    return []


def uptime_seconds(text: Any) -> int | None:
    """Seconds of a ``system_time`` uptime (``3 days, 01:02:03``)."""
    match = _UPTIME.match(_text(text))
    if not match:
        return None
    days, hours, minutes, seconds = (int(g or 0) for g in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def _memory(resources: dict) -> dict[str, float | None]:
    """Memory from ``system_resources``: total, used without the ZFS ARC
    (the cache gives itself back; OPNsense's own widget shows it apart) and
    the ARC, in MiB, and the use in %."""
    memory = _dict(resources.get("memory"))
    total, used, arc = _number(memory.get("total")), _number(memory.get("used")), _number(memory.get("arc"))
    if not total or used is None:
        return {"memory_percent": None, "memory_used_mb": None, "memory_total_mb": None, "arc_mb": None}
    used = max(0.0, used - (arc or 0.0))
    return {
        "memory_percent": round(used / total * 100, 1),
        "memory_used_mb": round(used / _MIB, 1),
        "memory_total_mb": round(total / _MIB, 1),
        "arc_mb": round(arc / _MIB, 1) if arc else None,
    }


def _disks(disk: dict) -> list[dict[str, Any]]:
    """The file systems of ``system_disk``: mount point, device, type, use
    in % and the size and use as OPNsense prints them."""
    found = []
    for row in _dicts(disk.get("devices")):
        found.append(
            {
                "mountpoint": _text(row.get("mountpoint")),
                "device": _text(row.get("device")),
                "type": _text(row.get("type")),
                "used_pct": _number(row.get("used_pct")),
                "size": _text(row.get("total")) or _text(row.get("blocks")),
                "used": _text(row.get("used")),
                "available": _text(row.get("available")),
            }
        )
    return found


def health_summary(health: Any) -> dict[str, Any]:
    """The numbers of a collection's ``health`` part (``collector.collect_health``):
    ``cpu_percent``, ``load_avg``, ``memory_*``, ``disk_percent`` (the
    fullest file system, read-only media left out) with ``disks``,
    ``temperature_c`` (the hottest sensor) with ``temperatures``,
    ``pf_states`` / ``pf_states_limit`` / ``pf_states_percent`` and
    ``uptime_seconds``. ``None`` for what was not read."""
    found = _dict(health)
    time_info = _dict(found.get("time"))
    disks = _disks(_dict(found.get("disk")))
    used = [d["used_pct"] for d in disks if d["used_pct"] is not None and d["type"] not in _READ_ONLY_FS]
    readings = [(t, c) for t in _dicts(found.get("temperature")) if (c := _number(t.get("temperature"))) is not None]
    temperatures = [
        {"sensor": _text(t.get("device")), "type": _text(t.get("type_translated")) or _text(t.get("type")), "c": c}
        for t, c in readings
    ]
    states = _dict(found.get("pf_states"))
    current, limit = _number(states.get("current")), _number(states.get("limit"))
    return {
        "cpu_percent": _cpu_percent(found.get("activity")),
        "load_avg": _load_averages(time_info, found.get("activity")),
        **_memory(_dict(found.get("resources"))),
        "disk_percent": max(used) if used else None,
        "disks": disks,
        "temperature_c": max(c for _t, c in readings) if readings else None,
        "temperatures": temperatures,
        "pf_states": current,
        "pf_states_limit": limit,
        "pf_states_percent": round(current / limit * 100, 1) if current is not None and limit else None,
        "uptime_seconds": uptime_seconds(time_info.get("uptime")),
        "uptime": _text(time_info.get("uptime")),
    }


def service_records(health: Any) -> list[dict[str, Any]] | None:
    """The services of a collection's ``health`` part: every service the
    configuration enables (``core/service/search`` lists no other), with
    ``running`` and ``locked`` as booleans. ``None`` when not read."""
    rows = _dict(health).get("services")
    if not isinstance(rows, list):
        return None
    return [
        {
            "id": _text(row.get("id")) or _text(row.get("name")),
            "name": _text(row.get("name")),
            "description": _text(row.get("description")) or _text(row.get("name")),
            "running": _flag(row.get("running")),
            "locked": _flag(row.get("locked")),
        }
        for row in _dicts(rows)
        if _text(row.get("id")) or _text(row.get("name"))
    ]


def _pct_text(value: float | None) -> str:
    return f"{value:g} %" if value is not None else ""


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.firewall_info = _dict(raw.get("firewall"))
        self.system = _dict(raw.get("system"))
        self.firmware = _dict(raw.get("firmware"))
        self.product = _dict(self.firmware.get("product"))
        self.interfaces = _dicts(raw.get("interfaces"))
        self.gateways = _dicts(raw.get("gateways"))
        self.routes = _dicts(raw.get("routes"))
        self.ipsec = _dicts(raw.get("ipsec"))
        self.ipsec_phase2 = raw.get("ipsec_phase2") if isinstance(raw.get("ipsec_phase2"), dict) else None
        self.ipsec_child_config = (
            raw.get("ipsec_child_config") if isinstance(raw.get("ipsec_child_config"), dict) else None
        )
        self.carp = raw.get("carp") if isinstance(raw.get("carp"), dict) else None
        self.wireguard = _dicts(raw.get("wireguard"))
        self.openvpn = _dicts(raw.get("openvpn"))
        # Each tunnel's and OpenVPN server's ``traffic`` block, by key.
        self.traffic = vpn_traffic_blocks(raw)
        # The remote user directory: set once an OpenVPN server is found.
        self.user_directory: dict[str, Any] | None = None
        self.audit = raw.get("audit") if isinstance(raw.get("audit"), dict) else None
        self.clients = raw.get("clients") if isinstance(raw.get("clients"), dict) else None
        self.health = raw.get("health") if isinstance(raw.get("health"), dict) else None
        self.services = service_records(self.health)
        self.certificates_raw = raw.get("certificates") if isinstance(raw.get("certificates"), dict) else None
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.warnings: list[dict] = []
        self.now: float | None
        try:
            self.now = datetime.fromisoformat(_text(raw.get("timestamp"))).timestamp()
        except ValueError:
            self.now = None

        self.hostname = _text(self.system.get("name")).strip(".")
        self.address = _text(self.firewall_info.get("address"))
        self.name = _text(self.firewall_info.get("name")) or self.hostname or self.address or "OPNsense firewall"
        self.site_id = f"opnsense:{(self.hostname or self.address or 'firewall').lower()}"
        self.firewall_id = f"{DEVICE_NODE_PREFIX}{(self.hostname or self.address or 'opnsense').lower()}"
        self.tunnel_count = 0

    # ── Graph primitives ───────────────────────────────────────────────────

    def _node(self, node_id: str, kind: str, label: str, site: str, status: str, **fields: Any) -> dict:
        node = {
            "id": node_id,
            "kind": kind,
            "label": label,
            "site": site,
            "status": status,
            "model": "",
            "serial": "",
            "mac": "",
            "ip": "",
            "sections": [],
        }
        node.update(fields)
        self.nodes[node_id] = node
        return node

    def _edge(self, a: str, b: str, kind: str, **fields: Any) -> dict | None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return None
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)
        return edge

    # ── Versions ───────────────────────────────────────────────────────────

    def version(self) -> str:
        """The OPNsense version: the firmware status's product version, else
        the first version string of the system information."""
        found = _text(self.product.get("product_version"))
        if found:
            return found
        for text in self.system.get("versions") or []:
            match = re.match(r"\s*OPNsense\s+(\S+)", _text(text), re.IGNORECASE)
            if match:
                return match.group(1).rsplit("-", 1)[0]
        return ""

    def update_pending(self) -> bool:
        status = _text(self.firmware.get("status")).lower()
        if status in ("update", "upgrade"):
            return True
        latest, current = _text(self.product.get("product_latest")), self.version()
        return bool(latest and current and canonical_version(latest) != canonical_version(current.split("_")[0]))

    # ── The firewall ───────────────────────────────────────────────────────

    def management_ip(self) -> str:
        """The address Plexus reaches the firewall at: the API host when it
        is an address, else the LAN address, else the first IPv4 address."""
        if _is_ip(self.address):
            return self.address
        rows = sorted(self.interfaces, key=lambda r: _text(r.get("identifier")) != "lan")
        for row in rows:
            for address in interface_addresses(row):
                host = address.split("/", 1)[0]
                if _is_ip(host) and ipaddress.ip_address(host).version == 4:
                    return host
        return ""

    def build_firewall(self) -> dict:
        answered = bool(self.system or self.interfaces or self.firmware)
        addresses = [a.split("/", 1)[0] for row in self.interfaces for a in interface_addresses(row)]
        ip = self.management_ip()
        node = self._node(
            self.firewall_id,
            "appliance",
            self.hostname or self.name,
            self.site_id,
            "online" if answered else "unknown",
            model=_text(self.product.get("product_name")) or "OPNsense",
            ip=ip,
            site_sections=True,
        )
        host = self.inventory.match(ips=[ip, *addresses], name=self.hostname)
        if host:
            node["inventory"] = _inventory_ref(host)
            node["_host"] = host
        return node

    def firewall_sections(self, node: dict) -> None:
        sections = node["sections"]
        version = self.version()
        versions = [_text(v) for v in self.system.get("versions") or [] if _text(v)]
        _add(
            sections,
            kv_section(
                SECTION_OVERVIEW,
                [
                    ("Name", node["label"]),
                    ("Product", self.product.get("product_name") or "OPNsense"),
                    ("Version", version),
                    ("Latest version", self.product.get("product_latest")),
                    ("Series", self.product.get("product_series")),
                    ("Architecture", self.product.get("product_arch")),
                    ("Update pending", "Yes" if self.update_pending() else ("No" if self.firmware else "")),
                    ("Host name", self.hostname),
                    ("Software", versions[1:]),
                    ("Address", node["ip"]),
                    ("API address", self.firewall_info.get("base_url")),
                    ("Snapshot time", self.raw.get("timestamp")),
                    ("Source", SOURCE),
                ],
            ),
        )
        _add(sections, self._interfaces_table())
        _add(sections, self._connected_table())
        _add(sections, self._gateways_table())
        _add(sections, self._static_routes_table())
        _add(sections, self._routing_table())
        _add(sections, self._ipsec_table())
        _add(sections, self._wireguard_table())
        _add(sections, self._openvpn_table())
        _add(sections, self._ha_table())
        _add(sections, self._health_section())
        _add(sections, self._services_table())
        _add(sections, self._certificates_table())
        for table in self._client_tables():
            _add(sections, table)
        self._firmware_sections(sections, version)
        host = node.pop("_host", None)
        if host:
            _add(
                sections,
                kv_section(
                    SECTION_INVENTORY,
                    [
                        ("Hostname", host.get("hostname")),
                        ("IP address", host.get("ip_address")),
                        ("Device type", host.get("device_type")),
                    ],
                ),
            )

    def _interfaces_table(self) -> dict | None:
        rows = []
        for row in self.interfaces:
            ipv4 = [_text(i.get("ipaddr")) for i in _dicts(row.get("ipv4"))] or [_text(row.get("addr4"))]
            ipv6 = [_text(i.get("ipaddr")) for i in _dicts(row.get("ipv6"))] or [_text(row.get("addr6"))]
            enabled = row.get("enabled")
            rows.append(
                [
                    row.get("identifier") or row.get("device"),
                    row.get("description"),
                    row.get("device"),
                    row.get("status"),
                    "" if enabled is None else bool(enabled),
                    [a for a in ipv4 if a],
                    [a for a in ipv6 if a],
                    row.get("vlan_tag"),
                    row.get("macaddr"),
                    row.get("link_type"),
                    row.get("gateways"),
                ]
            )
        return table_section(
            SECTION_INTERFACES,
            [
                "Interface",
                "Description",
                "Device",
                "Status",
                "Enabled",
                "IPv4",
                "IPv6",
                "VLAN",
                "MAC address",
                "IPv4 type",
                "Gateways",
            ],
            rows,
        )

    def connected_subnets(self) -> list[list[Any]]:
        rows: dict[str, list[Any]] = {}
        for row in self.interfaces:
            if row.get("enabled") is False:
                continue
            for address in interface_addresses(row):
                cidr = _cidr_of(address)
                if not cidr:
                    continue
                network = ipaddress.ip_network(cidr)
                if network.is_link_local or network.is_loopback or network.num_addresses == 1:
                    continue
                name = _text(row.get("description")) or _text(row.get("identifier"))
                rows.setdefault(
                    cidr,
                    [cidr, name, row.get("device"), row.get("vlan_tag"), address, row.get("status")],
                )
        return list(rows.values())

    def _connected_table(self) -> dict | None:
        return table_section(
            SECTION_CONNECTED,
            ["Subnet", "Name", "Interface", "VLAN", "Address", "Status"],
            self.connected_subnets(),
        )

    def _gateways_table(self) -> dict | None:
        rows = [
            [
                g.get("name"),
                g.get("address"),
                g.get("status_translated") or g.get("status"),
                gateway_status(g),
                g.get("monitor"),
                g.get("delay"),
                g.get("stddev"),
                g.get("loss"),
            ]
            for g in self.gateways
        ]
        return table_section(
            SECTION_GATEWAYS, ["Gateway", "Address", "Status", "State", "Monitor", "RTT", "RTTsd", "Loss"], rows
        )

    def static_routes(self) -> list[list[Any]]:
        rows = []
        for route in self.routes:
            if not _route_is_static(route):
                continue
            cidr = canonical(_text(route.get("destination")))
            if not cidr:
                continue
            rows.append([cidr, cidr, route.get("gateway"), route.get("netif"), route.get("intf_description"), "Yes"])
        return rows

    def _static_routes_table(self) -> dict | None:
        return table_section(
            SECTION_STATIC_ROUTES,
            ["Destination", "Subnet", "Gateway", "Interface", "Interface name", "Enabled"],
            self.static_routes(),
        )

    def _routing_table(self) -> dict | None:
        rows = [
            [
                r.get("proto"),
                r.get("destination"),
                r.get("gateway"),
                r.get("flags"),
                r.get("netif"),
                r.get("intf_description"),
                r.get("mtu"),
            ]
            for r in self.routes[:MAX_ROUTE_ROWS]
        ]
        return table_section(
            SECTION_ROUTING_TABLE,
            ["Protocol", "Destination", "Gateway", "Flags", "Interface", "Interface name", "MTU"],
            rows,
        )

    def _client_tables(self) -> list[dict | None]:
        """The ARP, NDP and DHCP lease tables (capped at ``MAX_CLIENT_ROWS``)."""
        neighbour_columns = ["IP address", "MAC address", "Interface", "Host name", "Manufacturer", "Type"]

        def neighbours(entries: list[dict[str, str]]) -> list[list[Any]]:
            return [
                [e["ip_address"], e["mac_address"], e["interface_name"], e["hostname"], e["manufacturer"], e["type"]]
                for e in entries[:MAX_CLIENT_ROWS]
            ]

        names = {key: name for key, name, _paths, _privilege in LEASE_BACKENDS}
        leases = dhcp_leases(self.clients, self.interfaces)
        return [
            table_section(SECTION_ARP, neighbour_columns, neighbours(arp_entries(self.clients))),
            table_section(SECTION_NDP, neighbour_columns, neighbours(ndp_entries(self.clients))),
            table_section(
                SECTION_LEASES,
                ["Address", "MAC address", "Host name", "State", "Ends", "Interface", "Subnet", "Server"],
                [
                    [
                        lease["address"],
                        lease["mac_address"],
                        lease["hostname"],
                        lease["state"],
                        lease["ends_at"],
                        lease["metadata"]["interface"],
                        lease["scope_subnet"],
                        names.get(lease["metadata"]["backend"], ""),
                    ]
                    for lease in leases[:MAX_CLIENT_ROWS]
                ],
            ),
        ]

    def ipsec_children(self, row: dict) -> tuple[list[dict], int | None, int | None]:
        """The child SA rows of one connection, how many are installed and
        how many are configured (``None`` when not known)."""
        children: list[dict] = []
        installed: int | None = None
        name = _text(row.get("name"))
        if self.ipsec_phase2 is not None and row.get("connected") and name in self.ipsec_phase2:
            children = _dicts(self.ipsec_phase2.get(name))
            installed = sum(1 for c in children if child_sa_installed(c))
        configured: int | None = None
        config = self.ipsec_child_config or {}
        ikeid = _text(row.get("ikeid"))
        if ikeid in config:
            configured = sum(1 for c in _dicts(config.get(ikeid)) if _text(c.get("enabled")) not in ("0", "False", ""))
        return children, installed, configured

    def _ipsec_table(self) -> dict | None:
        rows = []
        for r in self.ipsec:
            _children, installed, configured = self.ipsec_children(r)
            rows.append(
                [
                    r.get("phase1desc") or r.get("name"),
                    r.get("version"),
                    r.get("local-addrs"),
                    r.get("remote-addrs"),
                    r.get("remote-id"),
                    _IPSEC_STATE_TEXT[ipsec_status(bool(r.get("connected")), installed, configured)],
                    _child_count_text(installed, configured),
                    r.get("bytes-in"),
                    r.get("bytes-out"),
                ]
            )
        return table_section(
            SECTION_IPSEC,
            ["Connection", "IKE", "Local", "Remote", "Remote ID", "State", "Child SAs", "Bytes in", "Bytes out"],
            rows,
        )

    def _ha_table(self) -> dict | None:
        if self.carp is None:
            return None
        state = _dict(self.carp.get("carp"))
        maintenance = state.get("maintenancemode")
        demotion = _text(state.get("demotion"))
        rows = [
            [
                r.get("interface"),
                r.get("vhid"),
                r.get("subnet"),
                r.get("status_txt") or r.get("status"),
                r.get("advbase"),
                r.get("advskew"),
                "" if maintenance is None else ("Yes" if _flag(maintenance) else "No"),
                demotion,
            ]
            for r in _dicts(self.carp.get("rows"))
            if _text(r.get("vhid"))
        ]
        return table_section(
            SECTION_HA,
            ["Interface", "VHID", "Virtual IP", "State", "Advbase", "Advskew", "Maintenance mode", "Demotion"],
            rows,
        )

    def _wireguard_table(self) -> dict | None:
        rows = [
            [
                r.get("name") or _text(r.get("public-key"))[:12],
                r.get("ifname") or r.get("if"),
                r.get("endpoint"),
                r.get("allowed-ips"),
                r.get("latest-handshake-epoch") or r.get("latest-handshake"),
                r.get("peer-status") or wireguard_status(r, self.now),
                r.get("transfer-rx"),
                r.get("transfer-tx"),
            ]
            for r in self.wireguard
            if _text(r.get("type")) == "peer"
        ]
        return table_section(
            SECTION_WIREGUARD,
            ["Peer", "Instance", "Endpoint", "Allowed IPs", "Latest handshake", "State", "Received", "Sent"],
            rows,
        )

    def _openvpn_table(self) -> dict | None:
        rows = [
            [
                r.get("description") or r.get("id"),
                r.get("type"),
                r.get("status") or "not running",
                r.get("common_name") or "",
                r.get("real_address"),
                r.get("virtual_address"),
                r.get("connected_since"),
            ]
            for r in self.openvpn
        ]
        return table_section(
            SECTION_OPENVPN,
            ["Instance", "Role", "Status", "Client", "Real address", "Virtual address", "Connected since"],
            rows,
        )

    def _firmware_sections(self, sections: list[dict], version: str) -> None:
        updates = _dicts(self.firmware.get("updates"))
        sets = _dicts(self.firmware.get("upgrade_sets"))
        if self.firmware:
            reboot = _text(self.firmware.get("status_reboot")) == "1"
            _add(
                sections,
                kv_section(
                    SECTION_FIRMWARE,
                    [
                        ("Version", version),
                        ("Latest version", self.product.get("product_latest")),
                        ("Update pending", "Yes" if self.update_pending() else "No"),
                        ("Status", self.firmware.get("status")),
                        ("Message", self.firmware.get("status_msg")),
                        ("Packages to update", len(updates) if updates else ""),
                        ("Reboot required", "Yes" if reboot else ""),
                        ("Major upgrade available", self.firmware.get("upgrade_major_version")),
                        ("Last check", self.firmware.get("last_check")),
                        ("Licence valid to", self.product.get("license_valid_to")),
                    ],
                ),
            )
        _add(
            sections,
            table_section(
                SECTION_UPDATES,
                ["Package", "Installed", "New", "Reason"],
                [[u.get("name"), u.get("old"), u.get("new"), u.get("reason")] for u in [*updates, *sets]],
            ),
        )
        if self.audit is not None:
            findings = _dicts(self.audit.get("findings"))
            packages = sorted({f"{_text(f.get('package'))}-{_text(f.get('version'))}" for f in findings})
            complete = self.audit_completed()
            _add(
                sections,
                kv_section(
                    SECTION_AUDIT,
                    [
                        ("Result", "Completed" if complete else "Audit incomplete"),
                        ("Reason", "" if complete else self.audit.get("incomplete_reason") or "not verified"),
                        ("Ran at", self.audit.get("ran_at")),
                        ("Problems found", len(findings) if complete else f"{len(findings)} so far (partial)"),
                        ("Vulnerable packages", packages or ("None" if complete else "")),
                        ("Software advisories", "Updated" if complete else "Not changed"),
                        ("Source", "OPNsense security audit (pkg audit)"),
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    SECTION_VULNERABLE,
                    ["Package", "Version", "Issue", "CVEs", "Link"],
                    [
                        [f.get("package"), f.get("version"), f.get("description"), f.get("cves"), f.get("url")]
                        for f in findings
                    ],
                ),
            )

    def audit_completed(self) -> bool:
        """Whether the audit verifiably ran to its end (an audit result
        without the flag, from before it existed, is not trusted)."""
        return bool(self.audit and self.audit.get("completed"))

    def _health_section(self) -> dict | None:
        if self.health is None:
            return None
        summary = health_summary(self.health)
        disks = [f"{d['mountpoint']} {_pct_text(d['used_pct'])} of {d['size']}".strip() for d in summary["disks"]]
        temperatures = [f"{t['sensor']} {t['c']:g} °C" for t in summary["temperatures"]]
        memory = ""
        if summary["memory_percent"] is not None:
            memory = (
                f"{summary['memory_percent']:g} % ({summary['memory_used_mb']:.0f} of "
                f"{summary['memory_total_mb']:.0f} MiB"
                + (f", ARC {summary['arc_mb']:.0f} MiB not counted" if summary["arc_mb"] else "")
                + ")"
            )
        states = ""
        if summary["pf_states"] is not None:
            states = f"{summary['pf_states']:.0f}" + (
                f" of {summary['pf_states_limit']:.0f} ({summary['pf_states_percent']:g} %)"
                if summary["pf_states_limit"]
                else ""
            )
        stopped = [s["description"] for s in self.services or [] if not s["running"]]
        return kv_section(
            SECTION_HEALTH,
            [
                ("CPU", _pct_text(summary["cpu_percent"])),
                ("Load average", ", ".join(f"{n:g}" for n in summary["load_avg"])),
                ("Memory", memory),
                ("Disk (fullest)", _pct_text(summary["disk_percent"])),
                ("File systems", disks),
                ("Temperature (hottest)", f"{summary['temperature_c']:g} °C" if summary["temperature_c"] else ""),
                ("Sensors", temperatures),
                ("State table", states),
                ("Uptime", summary["uptime"]),
                (
                    "Services",
                    f"{len(self.services) - len(stopped)} of {len(self.services)} running"
                    if self.services is not None
                    else "",
                ),
                ("Stopped", stopped),
                ("Source", SOURCE),
            ],
        )

    def _services_table(self) -> dict | None:
        rows = [
            [s["description"], s["id"], "running" if s["running"] else "stopped", "Yes" if s["locked"] else ""]
            for s in self.services or []
        ]
        return table_section(SECTION_SERVICES, ["Service", "Name", "Status", "Locked"], rows)

    def service_states(self) -> list[dict[str, Any]] | None:
        """The snapshot's ``services``: one record per service the
        firewall's configuration enables, ``online`` while it runs and
        ``offline`` when it does not (availability tracking turns them into
        ``service`` entities of the firewall). ``None`` when not read."""
        if self.services is None:
            return None
        label = self.nodes[self.firewall_id]["label"]
        return [
            {
                "id": f"svc:{s['id']}",
                "name": f"{label} {s['description']}",
                "type": s["name"],
                "kind": "OPNsense service",
                "site": self.site_id,
                "status": "online" if s["running"] else "offline",
                "raw_status": "running" if s["running"] else "stopped",
                "device": self.firewall_id,
            }
            for s in self.services
        ]

    # ── Certificates ───────────────────────────────────────────────────────

    def certificates(self) -> list[dict[str, Any]] | None:
        """The firewall's certificates and CAs (``certificate_records`` at
        the collection time). ``None`` when not read."""
        return certificate_records(self.certificates_raw, self.now)

    def _certificates_table(self) -> dict | None:
        rows = [
            [
                c["name"],
                "CA" if c["kind"] == "authority" else c["type"],
                c["common_name"],
                c["issuer"],
                c["valid_to"][:10],
                days_text(c),
                "Yes" if c["in_use"] else ("User" if c["user"] else "No"),
                c["tier"] if c["tracked"] else f"{c['tier']} (not alerted)",
            ]
            for c in self.certificates() or []
        ]
        return table_section(
            SECTION_CERTIFICATES,
            ["Name", "Type", "Common name", "Issuer", "Expires", "Days left", "In use", "State"],
            rows,
        )

    def certificate_states(self) -> list[dict[str, Any]] | None:
        """The snapshot's ``certificates``: every record, with the firewall
        as ``device`` (availability tracking turns the tracked ones into
        ``certificate`` entities of the firewall). ``None`` when not read."""
        records = self.certificates()
        if records is None:
            return None
        return [
            {
                **c,
                "device": self.firewall_id,
                "site": self.site_id,
                "model": "OPNsense CA" if c["kind"] == "authority" else "OPNsense certificate",
            }
            for c in records
        ]

    def certificate_warnings(self) -> None:
        # Informational: the expiry is tracked as entities of its own.
        due = [
            f"{c['name']} ({days_text(c)})"
            for c in self.certificates() or []
            if c["tracked"] and c["tier"] in ("expiring", "critical", "expired")
        ]
        if due:
            self.warnings.append(
                info_warning("certificates", "/trust/cert/search", f"Certificates expiring or expired: {', '.join(due)}")
            )

    def health_warnings(self) -> None:
        # Informational: they report what the firewall said, not a failed call.
        if self.health is None:
            return
        summary = health_summary(self.health)
        full = [
            f"{d['mountpoint']} ({d['used_pct']:g} %)"
            for d in summary["disks"]
            if d["used_pct"] is not None and d["used_pct"] >= DISK_FULL_PCT[0] and d["type"] not in _READ_ONLY_FS
        ]
        if full:
            self.warnings.append(
                info_warning("health", "/diagnostics/system/system_disk", f"File system nearly full: {', '.join(full)}")
            )
        percent = summary["pf_states_percent"]
        if percent is not None and percent >= STATE_TABLE_FULL_PCT[0]:
            self.warnings.append(
                info_warning(
                    "health",
                    "/diagnostics/firewall/pf_states",
                    f"State table near its limit: {summary['pf_states']:.0f} of {summary['pf_states_limit']:.0f} "
                    f"states ({percent:g} %)",
                )
            )

    def ha_warnings(self) -> None:
        # Informational: the CARP state is tracked as entities of its own
        # (``ha_block``), so it must not stop the removal of gone entities.
        for problem in carp_problems(self.carp):
            self.warnings.append(info_warning("ha", "/diagnostics/interface/get_vip_status", problem))

    def firmware_warnings(self, version: str) -> None:
        if self.firmware and self.update_pending():
            latest = _text(self.product.get("product_latest"))
            target = f" to {latest}" if latest and latest != version else ""
            self.warnings.append(
                info_warning(
                    "firmware",
                    "/core/firmware/status",
                    f"Firmware update available: OPNsense {version or '?'}{target}. "
                    + _text(self.firmware.get("status_msg")),
                )
            )
        if self.audit is not None and not self.audit_completed():
            self.warnings.append(
                info_warning(
                    "firmware",
                    "/core/firmware/audit",
                    "Security audit incomplete: "
                    + (_text(self.audit.get("incomplete_reason")) or "its completion could not be verified")
                    + ". The software advisories were not changed.",
                )
            )
        elif self.audit is not None:
            findings = _dicts(self.audit.get("findings"))
            if findings:
                packages = sorted({f"{_text(f.get('package'))}-{_text(f.get('version'))}" for f in findings})
                cves = sorted({c for f in findings for c in f.get("cves") or []})
                self.warnings.append(
                    info_warning(
                        "firmware",
                        "/core/firmware/audit",
                        f"Security audit: {len(findings)} problem(s) in {len(packages)} package(s): "
                        f"{', '.join(packages)}" + (f" ({', '.join(cves[:10])})" if cves else ""),
                    )
                )

    # ── Gateways ───────────────────────────────────────────────────────────

    def build_gateways(self) -> None:
        for item in self.gateways:
            name = _text(item.get("name"))
            if not name:
                continue
            status = gateway_status(item)
            address = _text(item.get("address")).strip("~")
            wan = self._node(
                f"{GATEWAY_NODE_PREFIX}{name}",
                "wan",
                f"{name} {address}".strip(),
                self.site_id,
                _EDGE_NODE_STATUS.get(status, "unknown"),
                ip=address if _is_ip(address) else "",
                parent=self.firewall_id,
            )
            detail = ", ".join(
                f"{label} {item.get(key)}"
                for label, key in (("RTT", "delay"), ("RTTsd", "stddev"), ("loss", "loss"))
                if _number(item.get(key)) is not None
            )
            _add(
                wan["sections"],
                kv_section(
                    SECTION_GATEWAY,
                    [
                        ("Firewall", self.nodes[self.firewall_id]["label"]),
                        ("Gateway", name),
                        ("Address", address),
                        ("Status", item.get("status_translated") or item.get("status")),
                        ("Monitor IP", _text(item.get("monitor")).strip("~")),
                        ("RTT", _text(item.get("delay")).strip("~")),
                        ("RTTsd", _text(item.get("stddev")).strip("~")),
                        ("Loss", _text(item.get("loss")).strip("~")),
                        ("Monitoring", "" if status != "unknown" else "No monitor data (not monitored, or pending)"),
                        ("Source", SOURCE),
                    ],
                ),
            )
            self._edge(
                wan["id"],
                self.firewall_id,
                "uplink",
                b_port=name,
                status=status,
                label="Gateway",
                detail=detail,
                metrics=gateway_metrics(item),
            )

    # ── Tunnels ────────────────────────────────────────────────────────────

    def _peer(self, node_id: str, label: str, ip: str, title: str, rows: list[tuple[str, Any]]) -> dict:
        node = self.nodes.get(node_id) or self._node(
            node_id, "vpn_peer", label, PEERS_SITE_ID, "unknown", ip=ip if _is_ip(ip) else ""
        )
        _add(node["sections"], kv_section(title, [*rows, ("Source", SOURCE)]))
        return node

    def _tunnel(
        self,
        peer: dict,
        status: str,
        label: str,
        detail: str,
        a_port: str = "",
        b_port: str = "",
        traffic: dict | None = None,
    ) -> dict | None:
        edge = self._edge(
            self.firewall_id,
            peer["id"],
            "vpn3p",
            status=status,
            label=label,
            detail=detail,
            a_port=a_port,
            b_port=b_port,
            **({"traffic": traffic} if traffic is not None else {}),
        )
        if edge:
            self.tunnel_count += 1
        return edge

    def build_ipsec(self) -> None:
        for row in self.ipsec:
            name = _text(row.get("phase1desc")) or _text(row.get("name"))
            remote = _text(row.get("remote-addrs"))
            specific = _specific_peer(remote)
            key = remote if specific else _text(row.get("ikeid")) or _text(row.get("name"))
            peer = self._peer(
                f"{PEER_NODE_PREFIX}ipsec:{key}",
                remote if specific else name or key,
                remote,
                SECTION_IPSEC_PEER,
                [
                    ("Connection", name),
                    ("Remote address", remote),
                    ("Remote ID", row.get("remote-id")),
                    ("IKE version", row.get("version")),
                    ("Authentication", row.get("remote-class")),
                ],
            )
            children, installed, configured = self.ipsec_children(row)
            counts = _child_count_text(installed, configured)
            edge = self._tunnel(
                peer,
                ipsec_status(bool(row.get("connected")), installed, configured),
                "IPsec",
                name,
                a_port=_text(row.get("local-addrs")),
                traffic=self.traffic.get(ipsec_traffic_key(row)),
            )
            if edge is not None:
                edge["_children"] = (children, counts)

    def build_wireguard(self) -> None:
        for row in self.wireguard:
            if _text(row.get("type")) != "peer":
                continue
            name = _text(row.get("name")) or _text(row.get("public-key"))[:12]
            endpoint = _text(row.get("endpoint"))
            instance = _text(row.get("ifname")) or _text(row.get("if"))
            peer = self._peer(
                f"{PEER_NODE_PREFIX}wg:{_text(row.get('if'))}:{name}",
                name or _host_part(endpoint),
                _host_part(endpoint),
                SECTION_WIREGUARD_PEER,
                [
                    ("Peer", name),
                    ("Instance", instance),
                    ("Endpoint", endpoint),
                    ("Allowed IPs", row.get("allowed-ips")),
                    ("Latest handshake", row.get("latest-handshake-epoch") or row.get("latest-handshake")),
                    ("Public key", row.get("public-key")),
                ],
            )
            self._tunnel(
                peer,
                wireguard_status(row, self.now),
                "WireGuard",
                f"{instance} {name}".strip(),
                a_port=instance,
                traffic=self.traffic.get(wireguard_traffic_key(row)),
            )

    def build_openvpn(self) -> None:
        servers: dict[str, list[dict]] = {}
        for row in self.openvpn:
            ident = openvpn_ident(row)
            if _text(row.get("type")) == "server":
                servers.setdefault(ident, []).append(row)
                continue
            if _text(row.get("type")) != "client":
                continue
            description = _text(row.get("description")) or f"OpenVPN client {ident}"
            remote = _host_part(_text(row.get("real_address")))
            peer = self._peer(
                f"{PEER_NODE_PREFIX}ovpn:{ident}",
                description,
                remote,
                SECTION_OPENVPN_PEER,
                [
                    ("Instance", description),
                    ("Remote address", row.get("real_address")),
                    ("Tunnel address", row.get("virtual_address")),
                    ("State", row.get("status") or "not running"),
                    ("Connected since", row.get("connected_since")),
                ],
            )
            self._tunnel(
                peer,
                openvpn_client_status(row),
                "OpenVPN",
                description,
                traffic=self.traffic.get(openvpn_traffic_key("client", ident)),
            )
        for ident, rows in servers.items():
            description = next((_text(r.get("description")) for r in rows if _text(r.get("description"))), "")
            clients = [r for r in rows if r.get("is_client")]
            running = bool(clients) or any(_text(r.get("status")).lower() in ("ok", "connected") for r in rows)
            node = self._node(
                f"{OPENVPN_SERVER_PREFIX}{ident}",
                "vpn_server",
                description or f"OpenVPN server {ident}",
                self.site_id,
                "online" if running else "offline",
                model="OpenVPN server",
                **({"traffic": t} if (t := self.traffic.get(openvpn_traffic_key("server", ident))) else {}),
            )
            _add(
                node["sections"],
                kv_section(
                    SECTION_OPENVPN_SERVER,
                    [
                        ("Firewall", self.nodes[self.firewall_id]["label"]),
                        ("Instance", description or ident),
                        ("Status", "running" if running else "enabled, not running"),
                        ("Connected clients", len(clients)),
                        ("Source", SOURCE),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    SECTION_OPENVPN_CLIENTS,
                    ["Client", "User", "Real address", "Virtual address", "Connected since", "Received", "Sent"],
                    [
                        [
                            c.get("common_name"),
                            c.get("username"),
                            c.get("real_address"),
                            c.get("virtual_address"),
                            c.get("connected_since"),
                            c.get("bytes_received"),
                            c.get("bytes_sent"),
                        ]
                        for c in clients
                    ],
                ),
            )
            # Structural: the server's own status is tracked, not this link.
            self._edge(self.firewall_id, node["id"], "lan", label="OpenVPN server")
            self._add_users(clients)

    def _add_users(self, clients: list[dict]) -> None:
        """The clients connected to an OpenVPN server, into the remote user
        directory (see ``netcontrol.integrations.remote_users``). OPNsense
        keeps no list of the users allowed to connect, so users who are not
        connected come from earlier collections, carried forward on store.
        The directory is listed on the firewall node, which every snapshot
        draws and which spans every server instance."""
        if self.user_directory is None:
            self.user_directory = {"node_id": self.firewall_id, "users": []}
        for client in clients:
            name = _text(client.get("username")) or _text(client.get("common_name"))
            common_name = _text(client.get("common_name"))
            entry = directory_entry(
                name=name,
                connected=True,
                source="session",
                address=client.get("virtual_address"),
                public_ip=_host_part(_text(client.get("real_address"))),
                # The certificate a user connected with names their device
                # when they log in with a username of their own.
                device=common_name if common_name != name else "",
            )
            if entry is not None:
                self.user_directory["users"].append(entry)

    def build_edge_sections(self) -> None:
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            rows: list[tuple[str, Any]] = [("A end", a["label"]), ("B end", b["label"])]
            if edge.get("kind") == "uplink":
                rows += [("Gateway", edge.get("b_port")), ("Monitor", edge.get("detail"))]
            else:
                rows.append(("Tunnel", edge.get("detail")))
            children, counts = edge.pop("_children", ([], ""))
            if counts:
                rows.append(("Child SAs", counts))
            rows += [("Status", edge.get("status")), ("Discovered via", SOURCE)]
            section = kv_section(edge.get("label") or "Link", rows)
            edge["sections"] = [section] if section else []
            _add(
                edge["sections"],
                table_section(
                    SECTION_IPSEC_CHILDREN,
                    [
                        "Child SA",
                        "State",
                        "Local network",
                        "Remote network",
                        "Mode",
                        "Encryption",
                        "Bytes in",
                        "Bytes out",
                    ],
                    [
                        [
                            c.get("phase2desc") or c.get("name"),
                            c.get("state") or "installed",
                            c.get("local-ts"),
                            c.get("remote-ts"),
                            c.get("mode"),
                            c.get("encr-alg"),
                            c.get("bytes-in"),
                            c.get("bytes-out"),
                        ]
                        for c in children
                    ],
                ),
            )


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output.
    ``raw["config_xml"]`` is never read: it does not belong in a snapshot."""
    builder = _Builder(raw, inventory or InventoryIndex())
    firewall = builder.build_firewall()
    builder.build_gateways()
    builder.build_ipsec()
    builder.build_wireguard()
    builder.build_openvpn()
    builder.firewall_sections(firewall)
    version = builder.version()
    builder.firmware_warnings(version)
    builder.ha_warnings()
    builder.health_warnings()
    builder.certificate_warnings()
    certificates = builder.certificate_states()
    builder.build_edge_sections()

    site_members = [n for n in builder.nodes.values() if n["site"] == builder.site_id]
    sites: list[dict] = [
        {
            "id": builder.site_id,
            "name": builder.name,
            "tags": [],
            "vpn_mode": "hub",
            "status": _worst([n["status"] for n in site_members if n["kind"] != "wan"]),
            "device_count": sum(1 for n in site_members if n["kind"] != "wan"),
            "sections": [],
        }
    ]
    peers = [n for n in builder.nodes.values() if n["kind"] == "vpn_peer"]
    if peers:
        sites.append(
            {
                "id": PEERS_SITE_ID,
                "name": "VPN peers",
                "tags": [],
                "vpn_mode": "spoke",
                "status": "unknown",
                "device_count": len(peers),
                "sections": [],
            }
        )
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in ("wan", "vpn_peer"):
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    findings = _dicts(_dict(builder.audit).get("findings"))
    counts = client_counts(builder.clients)
    return {
        "schema": SCHEMA_VERSION,
        "provider": PROVIDER,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        # When the VPN counters were read (``netcontrol.integrations.traffic``).
        **({"traffic_read_at": raw["vpn_read_at"]} if raw.get("vpn_read_at") else {}),
        "org": {
            "id": _s(builder.hostname or builder.address),
            "name": builder.name,
            "url": _text(builder.firewall_info.get("base_url")),
        },
        "summary": {
            "sites": 1,
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": builder.tunnel_count,
            "wan_uplinks": sum(1 for e in builder.edges if e["kind"] == "uplink"),
            "vlans": len(builder.connected_subnets()),
            "gateways": len(builder.gateways),
            "version": version,
            "update_pending": builder.update_pending() if builder.firmware else None,
            "vulnerable_packages": len({_text(f.get("package")) for f in findings})
            if builder.audit_completed()
            else None,
            "audit_completed": builder.audit_completed() if builder.audit is not None else None,
            "carp_vips": len([r for r in _dicts(_dict(builder.carp).get("rows")) if _text(r.get("vhid"))])
            if builder.carp is not None
            else None,
            "arp_entries": counts["arp"],
            "ndp_entries": counts["ndp"],
            "dhcp_leases": counts["dhcp_leases"],
            "services": len(builder.services) if builder.services is not None else None,
            "services_stopped": sum(1 for s in builder.services if not s["running"])
            if builder.services is not None
            else None,
            "certificates": len(certificates) if certificates is not None else None,
            "certificates_due": sum(1 for c in certificates if c["tracked"] and c["tier"] not in ("valid", "unknown"))
            if certificates is not None
            else None,
        },
        "collection": {
            "sources": [SOURCE],
            "stats": raw.get("stats") or {},
            "errors": [*(raw.get("errors") or []), *builder.warnings],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
        **({"ha": ha} if (ha := ha_block(builder.carp, builder.firewall_id)) is not None else {}),
        **({"health": health_summary(builder.health)} if builder.health is not None else {}),
        **({"services": services} if (services := builder.service_states()) is not None else {}),
        **({"certificates": certificates} if certificates is not None else {}),
        **({DIRECTORY_KEY: builder.user_directory} if builder.user_directory is not None else {}),
    }
