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
    child SAs (phase 2) in its details.
  - every OpenVPN server instance is a ``vpn_server`` node next to the
    firewall (``ovpn:server:<id>``): ``online`` when it runs, ``offline``
    when it is enabled but not running. The clients connected to it are
    listed in its details; they are users, not tunnels.

The firmware status (a pending update) and the findings of the security
audit are shown in the firewall's details and added to the collection
report as informational warnings (``info``: they do not mean the collection
was incomplete); so is an audit that did not verifiably complete ("Audit
incomplete"). The CARP virtual IPs are the firewall's "High availability"
section; a VIP in ``INIT`` or a non-zero CARP demotion is a (non ``info``)
warning.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

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
from netcontrol.integrations.opnsense.collector import info_warning
from netcontrol.integrations.software.versions import canonical_version

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
# Section titles of the gateway, tunnel peer and OpenVPN server nodes.
SECTION_GATEWAY = "Gateway"
SECTION_IPSEC_PEER = "IPsec peer"
SECTION_IPSEC_CHILDREN = "Child SAs"
SECTION_WIREGUARD_PEER = "WireGuard peer"
SECTION_OPENVPN_PEER = "OpenVPN peer"
SECTION_OPENVPN_SERVER = "OpenVPN server"
SECTION_OPENVPN_CLIENTS = "Connected clients"

MAX_ROUTE_ROWS = 2000

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
        self.audit = raw.get("audit") if isinstance(raw.get("audit"), dict) else None
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
                "" if maintenance is None else ("Yes" if maintenance in (True, 1, "1", "true") else "No"),
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

    def ha_warnings(self) -> None:
        for problem in carp_problems(self.carp):
            self.warnings.append(
                {"scope": "ha", "path": "/diagnostics/interface/get_vip_status", "status": None, "message": problem}
            )

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
        self, peer: dict, status: str, label: str, detail: str, a_port: str = "", b_port: str = ""
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
                peer, wireguard_status(row, self.now), "WireGuard", f"{instance} {name}".strip(), a_port=instance
            )

    def build_openvpn(self) -> None:
        servers: dict[str, list[dict]] = {}
        for row in self.openvpn:
            ident = _text(row.get("service_id")).removeprefix("openvpn/") or _text(row.get("id")).split("_", 1)[0]
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
            self._tunnel(peer, openvpn_client_status(row), "OpenVPN", description)
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
    return {
        "schema": SCHEMA_VERSION,
        "provider": PROVIDER,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
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
    }
