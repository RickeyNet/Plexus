"""Turn raw FMC payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index and the
HTML export need no AnyConnect-specific code.

How an FMC maps onto the map:

  - every FTD that carries a remote access VPN policy is a headend: a site
    box holding the device, one WAN stub per access interface (the address
    AnyConnect clients connect to) and one "AnyConnect users" node with the
    connected users listed behind it (one node per user would bury the map)
  - the policy's address pools are the site's subnets, owned by the device,
    so a VPN client range can be picked in Path Mode and found by search
  - the FMC itself is one node in a box of its own, joined to each device
    by a management link that Path Mode and the tidy-tree layout ignore

A headend in AWS is matched to its instance by the private address of its
access interface, like a Meraki vMX behind a NAT gateway; one that is also
a Plexus inventory host (by serial or management address) becomes that host.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.anyconnect.collector import is_ra_vpn_policy
from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    InventoryIndex,
    _add,
    _inventory_ref,
    _is_ip,
    _layout,
    _s,
    _worst,
    kv_section,
    table_section,
)

FMC_SITE_ID = "__fmc__"
FMC_NODE_ID = "fmc"

# Kinds that stand for the management plane rather than devices at a site.
MANAGEMENT_KINDS = ("cloud",)

POOL_SECTION_TITLE = "VPN address pools"
POOL_COLUMNS = ["Subnet", "Pool", "Range", "Connection profiles"]
INTERFACES_SECTION_TITLE = "FTD interfaces"

MAX_LISTED_SESSIONS = 5000

_HEALTH = {
    "green": "online",
    "normal": "online",
    "recovered": "online",
    "yellow": "alerting",
    "warning": "alerting",
    "red": "offline",
    "critical": "offline",
    "error": "offline",
    "disabled": "dormant",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _name(value: Any) -> str:
    """A reference's display name: ``{"name": ...}`` objects, or the text."""
    if isinstance(value, dict):
        return _text(value.get("name") or value.get("id"))
    if isinstance(value, list):
        return ", ".join(n for n in (_name(v) for v in value) if n)
    return _text(value)


def _ident(value: Any) -> str:
    if isinstance(value, dict):
        return _text(value.get("id") or value.get("uuid"))
    return _text(value)


def _first(item: dict, *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _dict(value: Any) -> dict[str, Any]:
    """``value`` when it is an object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _health(raw: Any) -> str:
    return _HEALTH.get(_text(raw).lower(), "unknown")


def is_virtual_model(model: Any) -> bool:
    """A virtual firewall model (FTDv, "Threat Defense for AWS", vMX...)."""
    lowered = _text(model).lower()
    return lowered.startswith("vmx") or any(t in lowered for t in ("ftdv", "threat defense for", "virtual"))


def pool_cidr(pool: dict) -> str:
    """The network of an FMC IPv4 address pool: its range under its mask, or
    the smallest network that holds the range when no mask is given."""
    rng = _text(pool.get("ipAddressRange") or pool.get("range"))
    first, _sep, last = rng.partition("-")
    first, last = first.strip(), (last or first).strip()
    if not _is_ip(first):
        return ""
    mask = _text(pool.get("mask") or pool.get("netmask"))
    if mask:
        try:
            return str(ipaddress.ip_network(f"{first}/{mask}", strict=False))
        except ValueError:
            pass
    try:
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last if _is_ip(last) else first)
    except ValueError:
        return ""
    if start.version != end.version:
        return ""
    if int(end) < int(start):
        start, end = end, start
    for prefix in range(start.max_prefixlen, -1, -1):
        network = ipaddress.ip_network(f"{start}/{prefix}", strict=False)
        if end in network:
            return str(network)
    return ""


def _interface_cidr(address: str, mask: str) -> str:
    if not address or not mask:
        return ""
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return ""


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.options = _dict(raw.get("options"))
        self.devices = [d for d in raw.get("devices") or [] if isinstance(d, dict) and d.get("id")]
        self.policies = [
            p
            for p in raw.get("policies") or []
            if isinstance(p, dict) and p.get("id") and (is_ra_vpn_policy(p) or not p.get("type"))
        ]
        self.policy_by_id = {_text(p["id"]): p for p in self.policies}
        self.details = _dict(raw.get("policy_details"))
        self.pools = [p for p in raw.get("pools") or [] if isinstance(p, dict)]
        self.pool_by_id = {_text(p.get("id")): p for p in self.pools if p.get("id")}
        self.pool_by_name = {_text(p.get("name")).lower(): p for p in self.pools if p.get("name")}
        self.interfaces = _dict(raw.get("interfaces"))
        sessions = raw.get("sessions")
        self.sessions_collected = isinstance(sessions, list)
        self.sessions = [s for s in sessions or [] if isinstance(s, dict)]

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.pool_count = 0
        # device id -> the remote access VPN policy assigned to it.
        self.device_policy: dict[str, dict] = {}
        # policy id -> names of the devices it is assigned to.
        self.policy_devices: dict[str, list[str]] = {}
        # device id -> its sessions.
        self.device_sessions: dict[str, list[dict]] = {}
        self._map_policies()
        self._map_sessions()

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

    def _edge(self, a: str, b: str, kind: str, **fields: Any) -> None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)

    # ── Policy and session mapping ─────────────────────────────────────────

    def _map_policies(self) -> None:
        by_name = {_text(d.get("name")).lower(): _text(d["id"]) for d in self.devices}
        by_id = {_text(d["id"]): d for d in self.devices}

        def assign(policy: dict, target: Any) -> None:
            if not isinstance(target, dict):
                return
            device_id = _text(target.get("id"))
            if device_id not in by_id:
                device_id = by_name.get(_text(target.get("name")).lower(), "")
            if not device_id:
                return
            self.device_policy.setdefault(device_id, policy)
            names = self.policy_devices.setdefault(_text(policy.get("id")), [])
            device_name = _text(by_id[device_id].get("name")) or device_id
            if device_name not in names:
                names.append(device_name)

        for policy in self.policies:
            for target in policy.get("targets") or []:
                assign(policy, target)
        for assignment in self.raw.get("assignments") or []:
            if not isinstance(assignment, dict) or not is_ra_vpn_policy(assignment.get("policy")):
                continue
            ref = assignment["policy"]
            policy = self.policy_by_id.get(_ident(ref)) or {"id": _ident(ref), "name": _name(ref), "type": "RAVpn"}
            for target in assignment.get("targets") or []:
                assign(policy, target)

    def _session_device(self, session: dict) -> str:
        by_name = {_text(d.get("name")).lower(): _text(d["id"]) for d in self.devices}
        ids = {_text(d["id"]) for d in self.devices}
        device = session.get("device")
        candidates = [
            _ident(device),
            _text(_first(session, "deviceId", "deviceUUID", "deviceUuid")),
        ]
        for candidate in candidates:
            if candidate in ids:
                return candidate
        names = [_name(device), _text(_first(session, "deviceName", "hostName", "hostname", "firewall"))]
        for name in names:
            if name.lower() in by_name:
                return by_name[name.lower()]
        return ""

    def _map_sessions(self) -> None:
        for session in self.sessions:
            device_id = self._session_device(session)
            if device_id:
                self.device_sessions.setdefault(device_id, []).append(session)

    # ── Per-device data ────────────────────────────────────────────────────

    def _interface_rows(self, device_id: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for iface in self.interfaces.get(device_id) or []:
            if not isinstance(iface, dict):
                continue
            ipv4 = _dict(iface.get("ipv4"))
            static = _dict(ipv4.get("static"))
            address = _text(static.get("address"))
            mask = _text(static.get("netmask") or static.get("mask"))
            if not address:
                address = _text(_dict(ipv4.get("dhcp")).get("address"))
            zone = _dict(iface.get("securityZone"))
            name = _text(iface.get("name"))
            if iface.get("vlanId") not in (None, "") and "." not in name:
                name = f"{name}.{iface.get('subIntfId') or iface.get('vlanId')}"
            rows.append(
                {
                    "name": name,
                    "ifname": _text(iface.get("ifname")),
                    "zone_id": _text(zone.get("id")),
                    "zone": _text(zone.get("name")),
                    "ip": address if _is_ip(address) else "",
                    "cidr": _interface_cidr(address, mask) if _is_ip(address) else "",
                    "enabled": bool(iface.get("enabled", True)),
                    "mode": _text(iface.get("mode")),
                    "description": _text(iface.get("description")),
                    "management_only": bool(iface.get("managementOnly")),
                }
            )
        return rows

    def _policy_detail(self, policy: dict | None) -> dict[str, list[dict]]:
        found = _dict(self.details.get(_text(policy.get("id")))) if policy else {}
        return {
            key: [i for i in found.get(key) or [] if isinstance(i, dict)]
            for key in ("connection_profiles", "address_assignment", "access_interfaces")
        }

    def _pool(self, ref: Any) -> dict:
        pool = self.pool_by_id.get(_ident(ref)) or self.pool_by_name.get(_name(ref).lower())
        return pool if pool else {"name": _name(ref)}

    def _pool_rows(self, profiles: list[dict]) -> list[list[Any]]:
        """Address pool rows of a policy: Subnet, Pool, Range, Profiles."""
        by_pool: dict[str, tuple[dict, list[str]]] = {}
        for profile in profiles:
            refs = profile.get("ipv4AddressPool") or profile.get("ipv4AddressPools") or []
            for ref in refs if isinstance(refs, list) else [refs]:
                pool = self._pool(ref)
                key = _text(pool.get("id")) or _text(pool.get("name"))
                if not key:
                    continue
                entry = by_pool.setdefault(key, (pool, []))
                if _text(profile.get("name")) not in entry[1]:
                    entry[1].append(_text(profile.get("name")))
        rows: list[list[Any]] = []
        for pool, names in by_pool.values():
            cidr = pool_cidr(pool)
            rows.append([cidr, pool.get("name"), pool.get("ipAddressRange") or pool.get("range"), ", ".join(names)])
        return sorted(rows, key=lambda r: (r[0] == "", r[0], _text(r[1])))

    def _session_rows(self, sessions: list[dict]) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for s in sessions[:MAX_LISTED_SESSIONS]:
            rows.append(
                [
                    _name(_first(s, "username", "userName", "user")),
                    _text(
                        _first(
                            s, "assignedIp", "assignedIpv4", "assignedIpv4Address", "assignedIPv4", "clientIp", "vpnIp"
                        )
                    ),
                    _text(_first(s, "publicIp", "publicIpAddress", "publicIpv4", "remoteIp", "clientPublicIp")),
                    _name(_first(s, "connectionProfile", "tunnelGroup", "connectionProfileName")),
                    _name(_first(s, "groupPolicy", "groupPolicyName")),
                    _name(_first(s, "clientApplication", "clientVersion", "anyConnectVersion", "clientType")),
                    _name(_first(s, "clientOs", "clientOS", "osType", "clientOsType")),
                    _name(_first(s, "protocol", "encryption", "tunnelProtocol")),
                    _text(_first(s, "loginTime", "loginTimeStamp", "connectedSince")),
                    _text(_first(s, "duration", "connectionDuration", "sessionDuration")),
                    _text(_first(s, "bytesRx", "rxBytes", "bytesReceived")),
                    _text(_first(s, "bytesTx", "txBytes", "bytesTransmitted")),
                ]
            )
        return sorted(rows, key=lambda r: (str(r[0]).lower(), str(r[1])))

    # ── Headends ───────────────────────────────────────────────────────────

    def build_devices(self) -> None:
        wanted = self.raw.get("on_map")
        wanted_ids = {_text(i) for i in wanted} if isinstance(wanted, list) else None
        include_all = bool(self.options.get("include_all_devices"))
        for device in sorted(self.devices, key=lambda d: _text(d.get("name")).lower()):
            did = _text(device["id"])
            policy = self.device_policy.get(did)
            if wanted_ids is not None:
                if did not in wanted_ids and not include_all:
                    continue
            elif policy is None and not include_all:
                continue
            self._device(device, did, policy)

    def _device(self, device: dict, did: str, policy: dict | None) -> None:
        name = _text(device.get("name")) or did
        site_id = f"dev:{did}"
        status = _health(device.get("healthStatus"))
        meta = _dict(device.get("metadata"))
        serial = _text(_first(meta, "deviceSerialNumber", "serialNumber") or _first(device, "serialNumber", "serial"))
        mgmt = _text(device.get("hostName"))
        interfaces = self._interface_rows(did)
        detail = self._policy_detail(policy)
        sessions = self.device_sessions.get(did, [])

        node = self._node(
            f"d:{did}",
            "appliance",
            name,
            site_id,
            status,
            model=_text(device.get("model")),
            serial=serial,
            ip=mgmt if _is_ip(mgmt) else "",
            site_sections=True,
        )
        host = self.inventory.match(serial=serial, ips=[node["ip"], *(i["ip"] for i in interfaces if i["ip"])])
        if host:
            node["inventory"] = _inventory_ref(host)
        domain = _dict(meta.get("domain"))
        _add(
            node["sections"],
            kv_section(
                "Overview",
                [
                    ("Name", name),
                    ("Status", status),
                    ("Health", device.get("healthStatus")),
                    ("Model", node["model"]),
                    ("Software", device.get("sw_version") or device.get("softwareVersion")),
                    ("Management address", mgmt),
                    ("Serial", serial),
                    ("FMC domain", domain.get("name") or _dict(self.raw.get("fmc")).get("domain")),
                    ("Deployment status", device.get("deploymentStatus")),
                    ("Mode", device.get("ftdMode")),
                    ("Snort version", meta.get("snortVersion")),
                    ("Access control policy", _name(device.get("accessPolicy"))),
                    ("Remote access VPN policy", _name(policy) if policy else "none"),
                    ("Description", device.get("description")),
                    ("Device ID", did),
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                INTERFACES_SECTION_TITLE,
                ["Interface", "Name", "Zone", "IP address", "Subnet", "Enabled", "Mode", "Description"],
                [
                    [i["name"], i["ifname"], i["zone"], i["ip"], i["cidr"], i["enabled"], i["mode"], i["description"]]
                    for i in interfaces
                ],
            ),
        )
        if host:
            _add(
                node["sections"],
                kv_section(
                    "Plexus inventory",
                    [
                        ("Hostname", host.get("hostname")),
                        ("IP address", host.get("ip_address")),
                        ("Device type", host.get("device_type")),
                    ],
                ),
            )

        site_sections: list[dict] = []
        members = [node]
        if policy is not None:
            members += self._headend(node, did, name, policy, detail, interfaces, sessions, site_sections)

        self.sites.append(
            {
                "id": site_id,
                "name": name,
                "tags": [],
                "vpn_mode": "spoke",
                "status": _worst([m["status"] for m in members]),
                "device_count": 1,
                "sections": site_sections,
            }
        )

    def _headend(
        self,
        node: dict,
        did: str,
        name: str,
        policy: dict,
        detail: dict[str, list[dict]],
        interfaces: list[dict[str, Any]],
        sessions: list[dict],
        site_sections: list[dict],
    ) -> list[dict]:
        """The remote access VPN side of a device: its site sections, access
        interface stubs and the users node. Returns the nodes added."""
        profiles = detail["connection_profiles"]
        settings = detail["access_interfaces"]
        assignment = detail["address_assignment"][0] if detail["address_assignment"] else {}
        ports = next((s for s in settings if s.get("sslPort") or s.get("dtlsPort")), settings[0] if settings else {})
        access: list[dict] = []
        for setting in settings:
            entries = setting.get("accessInterfaceSettings") or setting.get("interfaces") or []
            access.extend(e for e in (entries if isinstance(entries, list) else [entries]) if isinstance(e, dict))
        protocols = sorted(
            {
                p
                for e in access
                for p, on in (("SSL", e.get("enableSSL")), ("IPsec IKEv2", e.get("enableIPSecIKEv2")))
                if on
            }
        )
        assignment_sources = [
            label
            for label, on in (
                ("authorization server", assignment.get("useAuthorizationServer")),
                ("DHCP", assignment.get("useDhcp")),
                ("local pools", assignment.get("useLocalPools", True if not assignment else None)),
            )
            if on
        ]
        pool_rows = self._pool_rows(profiles)
        self.pool_count += len(pool_rows)

        _add(
            site_sections,
            kv_section(
                "Remote access VPN",
                [
                    ("Policy", policy.get("name")),
                    ("Headend", name),
                    ("Description", policy.get("description")),
                    ("Connection profiles", ", ".join(_text(p.get("name")) for p in profiles)),
                    ("Access interfaces", ", ".join(_name(e.get("accessInterface")) for e in access)),
                    ("Protocols", ", ".join(protocols)),
                    ("SSL port", ports.get("sslPort")),
                    ("DTLS port", ports.get("dtlsPort")),
                    ("Address assignment", ", ".join(assignment_sources)),
                    ("Connected users", len(sessions) if self.sessions_collected else "not collected"),
                    ("Policy ID", policy.get("id")),
                ],
            ),
        )
        _add(
            site_sections,
            table_section(
                "Connection profiles",
                [
                    "Profile",
                    "Group policy",
                    "Address pools",
                    "Authentication",
                    "Authentication server",
                    "Group alias",
                    "Group URL",
                ],
                [
                    [
                        p.get("name"),
                        _name(p.get("groupPolicy")),
                        _name(p.get("ipv4AddressPool") or p.get("ipv4AddressPools")),
                        p.get("authenticationMethod"),
                        _name(p.get("primaryAuthenticationServer") or p.get("authenticationServer")),
                        ", ".join(_text(a.get("name")) for a in p.get("groupAlias") or [] if isinstance(a, dict)),
                        ", ".join(_text(u.get("url")) for u in p.get("groupUrl") or [] if isinstance(u, dict)),
                    ]
                    for p in profiles
                ],
            ),
        )
        _add(site_sections, table_section(POOL_SECTION_TITLE, POOL_COLUMNS, pool_rows))
        access_rows: list[list[Any]] = []
        added: list[dict] = []
        for index, entry in enumerate(access):
            zone = entry.get("accessInterface")
            zone_id, zone_name = _ident(zone), _name(zone)
            matched = [
                i
                for i in interfaces
                if (zone_id and i["zone_id"] == zone_id)
                or (zone_name and zone_name.lower() in (i["zone"].lower(), i["ifname"].lower(), i["name"].lower()))
            ]
            stub: dict[str, Any] = {"name": "", "ifname": zone_name, "zone": zone_name, "ip": "", "enabled": True}
            stubs = matched or [stub]
            for iface in stubs:
                label = iface["ifname"] or iface["name"] or zone_name or f"access {index + 1}"
                access_rows.append(
                    [label, zone_name, iface["ip"], bool(entry.get("enableSSL")), bool(entry.get("enableIPSecIKEv2"))]
                )
                wan_id = f"w:{did}:{iface['ifname'] or iface['name'] or index}"
                if wan_id in self.nodes:
                    continue
                wan = self._node(
                    wan_id,
                    "wan",
                    f"{label} {iface['ip']}".strip(),
                    node["site"],
                    "online" if iface["enabled"] else "offline",
                    ip=iface["ip"],
                    parent=node["id"],
                )
                _add(
                    wan["sections"],
                    kv_section(
                        "VPN access interface",
                        [
                            ("Device", name),
                            ("Interface", iface["name"]),
                            ("Name", iface["ifname"]),
                            ("Zone", zone_name),
                            ("IP address", iface["ip"]),
                            ("Subnet", iface.get("cidr")),
                            ("SSL", bool(entry.get("enableSSL"))),
                            ("IPsec IKEv2", bool(entry.get("enableIPSecIKEv2"))),
                            ("DTLS", entry.get("enableDTLS")),
                            ("SSL port", ports.get("sslPort")),
                            ("DTLS port", ports.get("dtlsPort")),
                        ],
                    ),
                )
                self._edge(
                    wan_id, node["id"], "uplink", b_port=label, status="active" if iface["enabled"] else "failed"
                )
                added.append(wan)
        _add(
            site_sections,
            table_section("Access interfaces", ["Interface", "Zone", "IP address", "SSL", "IPsec IKEv2"], access_rows),
        )
        added.append(self._users_node(node, did, name, policy, sessions))
        return added

    def _users_node(self, node: dict, did: str, name: str, policy: dict, sessions: list[dict]) -> dict:
        count = len(sessions)
        label = f"AnyConnect users ({count})" if self.sessions_collected else "AnyConnect users"
        users = self._node(
            f"u:{did}",
            "users",
            label,
            node["site"],
            "online" if count else "unknown",
            model="Cisco Secure Client",
        )
        _add(
            users["sections"],
            kv_section(
                "Remote access users",
                [
                    ("Headend", name),
                    ("Policy", policy.get("name")),
                    ("Connected now", count if self.sessions_collected else "not collected"),
                    (
                        "Source",
                        "Users connected to this device with AnyConnect / Secure Client when the collection ran"
                        if self.sessions_collected
                        else "Sessions were not collected (option off, or the FMC does not serve them)",
                    ),
                ],
            ),
        )
        _add(
            users["sections"],
            table_section(
                "Connected users",
                [
                    "User",
                    "Assigned IP",
                    "Public IP",
                    "Connection profile",
                    "Group policy",
                    "Client",
                    "OS",
                    "Protocol",
                    "Login time",
                    "Duration",
                    "Bytes in",
                    "Bytes out",
                ],
                self._session_rows(sessions),
            ),
        )
        self._edge(users["id"], node["id"], "vpn", status="reachable" if count else "", label="AnyConnect")
        return users

    # ── The FMC ────────────────────────────────────────────────────────────

    def build_fmc(self) -> None:
        fmc = _dict(self.raw.get("fmc"))
        host = _text(fmc.get("url")).removeprefix("https://").split("/", 1)[0].strip("[]")
        host_only = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        label = _text(fmc.get("name")) or (f"FMC {host_only}" if host_only else "FMC")
        node = self._node(
            FMC_NODE_ID,
            "cloud",
            label,
            FMC_SITE_ID,
            "online",
            model="Cisco Secure Firewall Management Center",
            ip=host_only if _is_ip(host_only) else "",
        )
        on_map = {n["id"].removeprefix("d:") for n in self.nodes.values() if n["kind"] == "appliance"}
        _add(
            node["sections"],
            kv_section(
                "Cisco FMC",
                [
                    ("Name", fmc.get("name")),
                    ("Address", fmc.get("url")),
                    ("Version", fmc.get("version")),
                    ("Domain", fmc.get("domain")),
                    ("Devices managed", len(self.devices)),
                    ("Devices with remote access VPN", len(self.device_policy)),
                    ("Devices on the map", len(on_map)),
                    ("Remote access VPN policies", len(self.policies)),
                    ("Address pools", len(self.pools)),
                    ("Connected users", len(self.sessions) if self.sessions_collected else "not collected"),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Managed devices",
                [
                    "Device",
                    "Model",
                    "Software",
                    "Management address",
                    "Health",
                    "Remote access VPN policy",
                    "On the map",
                ],
                [
                    [
                        d.get("name"),
                        d.get("model"),
                        d.get("sw_version") or d.get("softwareVersion"),
                        d.get("hostName"),
                        d.get("healthStatus"),
                        _name(self.device_policy.get(_text(d["id"]))),
                        _text(d["id"]) in on_map,
                    ]
                    for d in sorted(self.devices, key=lambda d: _text(d.get("name")).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Remote access VPN policies",
                ["Policy", "Devices", "Connection profiles", "Address pools"],
                [
                    [
                        p.get("name"),
                        ", ".join(self.policy_devices.get(_text(p["id"]), [])),
                        ", ".join(_text(c.get("name")) for c in self._policy_detail(p)["connection_profiles"]),
                        ", ".join(r[1] for r in self._pool_rows(self._policy_detail(p)["connection_profiles"])),
                    ]
                    for p in self.policies
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Address pools",
                ["Pool", "Range", "Mask", "Subnet", "Description"],
                [
                    [
                        p.get("name"),
                        p.get("ipAddressRange") or p.get("range"),
                        p.get("mask"),
                        pool_cidr(p),
                        p.get("description"),
                    ]
                    for p in sorted(self.pools, key=lambda p: _text(p.get("name")).lower())
                ],
            ),
        )
        for device_id in sorted(on_map):
            self._edge(FMC_NODE_ID, f"d:{device_id}", "manage", label="Managed by FMC")

    def build_edge_sections(self) -> None:
        titles = {"vpn": "AnyConnect", "uplink": "VPN access interface", "manage": "Managed by FMC"}
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            edge["sections"] = [
                s
                for s in [
                    kv_section(
                        edge.get("label") or titles.get(edge["kind"], "Link"),
                        [
                            ("A end", a["label"]),
                            ("B end", b["label"]),
                            ("B port", edge.get("b_port")),
                            ("Status", edge.get("status")),
                            ("Discovered via", "FMC API"),
                        ],
                    )
                ]
                if s
            ]


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_devices()
    builder.build_fmc()
    builder.build_edge_sections()

    sites = [
        {
            "id": FMC_SITE_ID,
            "name": "Cisco FMC",
            "tags": [],
            # Sorts the FMC ahead of the headends, like a VPN hub.
            "vpn_mode": "hub",
            "status": "online",
            "device_count": 1,
            "sections": [],
        },
        *builder.sites,
    ]
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in ("wan", "users") or node["kind"] in MANAGEMENT_KINDS:
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    fmc = _dict(raw.get("fmc"))
    return {
        "schema": SCHEMA_VERSION,
        "provider": "anyconnect",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(fmc.get("domain_uuid") or fmc.get("url")),
            "name": fmc.get("name") or "FMC",
            "url": _s(fmc.get("url")),
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": edge_counts.get("vpn", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.pool_count,
            "remote_users": len(builder.sessions) if builder.sessions_collected else 0,
        },
        "collection": {
            "sources": ["Cisco FMC REST API"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
