"""Turn raw Meraki payloads into a positioned, self-describing topology snapshot.

``build_snapshot`` is pure (no I/O): it takes the dict produced by
``collector.collect_organization`` and returns the snapshot that is stored in
the database and embedded verbatim into the HTML export.

Snapshot shape (``schema`` 1)::

    {
      "org":     {...}, "generated_at": iso, "summary": {...}, "collection": {...},
      "sites":   [{id, name, x, y, w, h, vpn_mode, status, sections}],
      "nodes":   [{id, kind, label, site, status, x, y, sections, ...}],
      "edges":   [{id, a, b, kind, a_port, b_port, status, sections}],
    }

Every detail panel is expressed as generic ``sections`` (key/value, table or
text blocks). The viewer renders and searches sections without knowing what a
VLAN or a VPN peer is, so adding a new data source here never needs a viewer
change.

Layout is computed here rather than in the browser: each network ("site")
becomes a box whose devices are arranged as a tree rooted at the security
appliance, and the boxes are shelf-packed. Fixed positions keep a
several-thousand-device map instant to open and identical for every viewer.
"""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.collector import _device_kind

SCHEMA_VERSION = 1

# Layout grid (world units == CSS pixels at zoom 1).
CELL_W = 170
CELL_H = 120
LEAF_ROW_H = 96
MAX_LEAF_COLS = 5
SITE_PAD = 36
SITE_HEADER_H = 58
SITE_GAP = 90
SITE_MIN_W = 300

VPN_PEER_SITE_ID = "__vpn_peers__"

# Client tables are capped so one busy network cannot bloat a snapshot.
MAX_DEVICE_CLIENTS = 2000
MAX_SITE_CLIENTS = 5000
CLIENT_COLUMNS = ["MAC", "IP", "VLAN", "Port", "Description", "Manufacturer", "SSID", "Status", "Last seen"]

_STATUS_RANK = {"offline": 0, "alerting": 1, "dormant": 2, "unknown": 3, "online": 4}
_UPLINK_STATUS = {
    "active": "online",
    "ready": "online",
    "connecting": "alerting",
    "failed": "offline",
}
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_MERAKI_LLDP_NAME = re.compile(r"^meraki\s+\S+\s+-\s+", re.IGNORECASE)


# ── Small value helpers ──────────────────────────────────────────────────────


def _s(value: Any) -> str:
    """Render any API value as display text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(_s(v) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_s(v)}" for k, v in value.items() if v not in (None, "", [], {}))
    return str(value)


def _norm_mac(raw: Any) -> str:
    hex_only = "".join(c for c in str(raw or "").lower() if c in "0123456789abcdef")
    return hex_only if _HEX12.match(hex_only) else ""


def _norm_port(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if text.startswith("port"):
        text = text[4:]
    return text.strip(" -_")


def _short_name(raw: Any) -> str:
    """Hostname without domain, lower-cased, for loose name matching."""
    text = _MERAKI_LLDP_NAME.sub("", str(raw or "").strip())
    return text.split(".")[0].lower() if text and not _is_ip(text) else text.lower()


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def kv_section(title: str, rows: list[tuple[str, Any]]) -> dict | None:
    cleaned = [[k, _s(v)] for k, v in rows if _s(v) != ""]
    return {"title": title, "kind": "kv", "rows": cleaned} if cleaned else None


def table_section(title: str, columns: list[str], rows: list[list[Any]]) -> dict | None:
    if not rows:
        return None
    return {"title": title, "kind": "table", "columns": columns, "rows": [[_s(c) for c in row] for row in rows]}


def _client_row(client: dict) -> list[Any]:
    return [
        client.get("mac"),
        client.get("ip"),
        client.get("vlan"),
        client.get("switchport"),
        client.get("description") or client.get("user"),
        client.get("manufacturer"),
        client.get("ssid"),
        client.get("status"),
        client.get("lastSeen"),
    ]


def _sorted_clients(clients: Any) -> list[dict]:
    rows = [c for c in clients or [] if isinstance(c, dict)]
    return sorted(rows, key=lambda c: (str(c.get("vlan") or ""), str(c.get("ip") or ""), str(c.get("mac") or "")))


def _port_vlan_rows(ports: list[dict]) -> list[list[Any]]:
    """Per-VLAN summary of a switch's port configuration."""
    by_vlan: dict[int, tuple[list[str], list[str], list[str]]] = {}

    def bucket(vlan: Any) -> tuple[list[str], list[str], list[str]] | None:
        try:
            return by_vlan.setdefault(int(vlan), ([], [], []))
        except TypeError, ValueError:
            return None

    for port in ports:
        if not isinstance(port, dict):
            continue
        port_id = str(port.get("portId") or "")
        slot = bucket(port.get("vlan"))
        if slot is not None:
            slot[2 if port.get("type") == "trunk" else 0].append(port_id)
        voice = bucket(port.get("voiceVlan"))
        if voice is not None:
            voice[1].append(port_id)
    return [[vlan, ", ".join(a), ", ".join(v), ", ".join(n)] for vlan, (a, v, n) in sorted(by_vlan.items())]


def text_section(title: str, text: str) -> dict | None:
    return {"title": title, "kind": "text", "text": text} if text and text.strip() else None


def _add(sections: list[dict], section: dict | None) -> None:
    if section:
        sections.append(section)


def _worst(statuses: list[str]) -> str:
    known = [s for s in statuses if s in _STATUS_RANK]
    return min(known, key=lambda s: _STATUS_RANK[s]) if known else "unknown"


# ── Inventory correlation ────────────────────────────────────────────────────


class InventoryIndex:
    """Lookup of Plexus inventory hosts by serial, IP (incl. aliases) and name."""

    def __init__(self, hosts: list[dict] | None = None, aliases: list[dict] | None = None) -> None:
        self._by_serial: dict[str, dict] = {}
        self._by_ip: dict[str, dict] = {}
        self._by_name: dict[str, dict] = {}
        by_id = {h.get("id"): h for h in hosts or []}
        for host in hosts or []:
            serial = str(host.get("serial_number") or "").strip().upper()
            if serial:
                self._by_serial.setdefault(serial, host)
            ip = str(host.get("ip_address") or "").strip()
            if ip:
                self._by_ip.setdefault(ip, host)
            name = _short_name(host.get("hostname"))
            if name:
                self._by_name.setdefault(name, host)
        for alias in aliases or []:
            owner = by_id.get(alias.get("host_id"))
            ip = str(alias.get("ip_address") or "").strip()
            if owner and ip:
                self._by_ip.setdefault(ip, owner)

    def match(self, *, serial: str = "", ips: list[str] | None = None, name: str = "") -> dict | None:
        if serial and serial.upper() in self._by_serial:
            return self._by_serial[serial.upper()]
        for ip in ips or []:
            if ip and ip in self._by_ip:
                return self._by_ip[ip]
        short = _short_name(name)
        if short and short in self._by_name:
            return self._by_name[short]
        return None


def _inventory_ref(host: dict) -> dict:
    return {
        "host_id": host.get("id"),
        "hostname": host.get("hostname") or "",
        "ip_address": host.get("ip_address") or "",
        "device_type": host.get("device_type") or "",
    }


# ── Snapshot builder ─────────────────────────────────────────────────────────


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.org_data: dict = raw.get("org") or {}
        self.networks: list[dict] = [n for n in raw.get("networks") or [] if n.get("id")]
        self.net_by_id = {n["id"]: n for n in self.networks}
        self.net_detail: dict[str, dict] = raw.get("networks_detail") or {}
        self.dev_detail: dict[str, dict] = raw.get("devices_detail") or {}

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._pair_edges: dict[frozenset, list[dict]] = {}
        self.device_by_mac: dict[str, str] = {}
        self.device_by_name: dict[str, str] = {}
        self.external_by_key: dict[tuple[str, str], str] = {}
        self.appliance_by_net: dict[str, str] = {}

        self.status_by_serial = {
            s.get("serial"): s for s in self.org_data.get("device_statuses") or [] if isinstance(s, dict)
        }
        self.uplinks_by_serial = {
            u.get("serial"): u for u in self.org_data.get("uplink_statuses") or [] if isinstance(u, dict)
        }
        self.vpn_by_net: dict[str, dict] = {
            str(v.get("networkId")): v for v in self.org_data.get("vpn_statuses") or [] if isinstance(v, dict)
        }
        self.ports_by_serial = {
            s.get("serial"): s.get("ports") or []
            for s in self.org_data.get("switch_ports") or []
            if isinstance(s, dict)
        }
        # Clients are attributed to the Meraki device they were last seen on.
        self.clients_by_serial: dict[str, list[dict]] = {}
        for detail in self.net_detail.values():
            for client in detail.get("clients") or []:
                if isinstance(client, dict) and client.get("recentDeviceSerial"):
                    self.clients_by_serial.setdefault(client["recentDeviceSerial"], []).append(client)
        self.stack_by_serial: dict[str, str] = {}
        for detail in self.net_detail.values():
            for stack in detail.get("stacks") or []:
                for serial in stack.get("serials") or []:
                    self.stack_by_serial[serial] = stack.get("name") or stack.get("id") or ""

    # ── Nodes ──────────────────────────────────────────────────────────────

    def _add_edge(self, a: str, b: str, kind: str, **fields: Any) -> dict | None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return None
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)
        self._pair_edges.setdefault(frozenset((a, b)), []).append(edge)
        return edge

    def build_device_nodes(self) -> None:
        for dev in self.raw.get("devices") or []:
            serial = dev.get("serial")
            net_id = dev.get("networkId")
            if not serial or net_id not in self.net_by_id:
                continue
            status_row = self.status_by_serial.get(serial) or {}
            status = str(status_row.get("status") or "unknown").lower()
            kind = _device_kind(dev)
            lan_ip = status_row.get("lanIp") or dev.get("lanIp") or ""
            node_id = f"d:{serial}"
            node = {
                "id": node_id,
                "kind": kind,
                "label": dev.get("name") or dev.get("mac") or serial,
                "site": net_id,
                "status": status if status in _STATUS_RANK else "unknown",
                "model": dev.get("model") or "",
                "serial": serial,
                "mac": dev.get("mac") or "",
                "ip": lan_ip,
                "sections": [],
            }
            host = self.inventory.match(serial=serial, ips=[lan_ip, dev.get("wan1Ip") or "", dev.get("wan2Ip") or ""])
            if host:
                node["inventory"] = _inventory_ref(host)
            self.nodes[node_id] = node
            mac = _norm_mac(dev.get("mac"))
            if mac:
                self.device_by_mac[mac] = node_id
            name = _short_name(dev.get("name"))
            if name:
                self.device_by_name.setdefault(name, node_id)
            if kind == "appliance":
                self.appliance_by_net.setdefault(net_id, node_id)

        # A VPN status row or warm-spare config names the *primary* appliance.
        for net_id, vpn in self.vpn_by_net.items():
            node_id = f"d:{vpn.get('deviceSerial')}"
            if node_id in self.nodes:
                self.appliance_by_net[net_id] = node_id
        for node_id in self.appliance_by_net.values():
            self.nodes[node_id]["site_sections"] = True

    def _external_node(self, net_id: str, *, mac: str, name: str, ip: str, info: dict) -> str:
        """Find or create the node for a non-Meraki LLDP/CDP neighbor."""
        keys = [k for k in (mac, _short_name(name), ip) if k]
        for key in keys:
            existing = self.external_by_key.get((net_id, key))
            if existing:
                node = self.nodes[existing]
                for other in keys:
                    self.external_by_key.setdefault((net_id, other), existing)
                if ip and not node.get("ip"):
                    node["ip"] = ip
                node["_info"].update({k: v for k, v in info.items() if v and not node["_info"].get(k)})
                return existing
        ident = keys[0] if keys else f"unknown{len(self.nodes)}"
        node_id = f"x:{net_id}:{ident}"
        host = self.inventory.match(ips=[ip], name=name)
        node = {
            "id": node_id,
            "kind": "external",
            "label": name or (host or {}).get("hostname") or ip or mac or "Unknown neighbor",
            "site": net_id,
            "status": "unknown",
            "model": info.get("platform") or "",
            "serial": "",
            "mac": mac,
            "ip": ip,
            "sections": [],
            "_info": dict(info),
        }
        if host:
            node["inventory"] = _inventory_ref(host)
        self.nodes[node_id] = node
        for key in keys:
            self.external_by_key[(net_id, key)] = node_id
        return node_id

    def _resolve_neighbor(self, net_id: str, *, mac: str, name: str, ip: str, info: dict) -> str:
        if mac and mac in self.device_by_mac:
            return self.device_by_mac[mac]
        short = _short_name(name)
        if short and short in self.device_by_name:
            return self.device_by_name[short]
        return self._external_node(net_id, mac=mac, name=name, ip=ip, info=info)

    # ── LAN links ──────────────────────────────────────────────────────────

    def build_link_layer_edges(self) -> None:
        for net_id, detail in self.net_detail.items():
            topo = detail.get("link_layer")
            if not isinstance(topo, dict) or net_id not in self.net_by_id:
                continue
            ll_nodes = {n.get("derivedId"): n for n in topo.get("nodes") or [] if isinstance(n, dict)}
            for link in topo.get("links") or []:
                ends = link.get("ends") or []
                if len(ends) != 2:
                    continue
                resolved: list[tuple[str, str]] = []
                for end in ends:
                    serial = (end.get("device") or {}).get("serial")
                    disc = end.get("discovered") or {}
                    lldp = disc.get("lldp") or {}
                    cdp = disc.get("cdp") or {}
                    port = lldp.get("portId") or cdp.get("portId") or ""
                    if serial and f"d:{serial}" in self.nodes:
                        resolved.append((f"d:{serial}", str(port)))
                        continue
                    derived = (end.get("node") or {}).get("derivedId") or ""
                    ll_node = ll_nodes.get(derived) or {}
                    ndisc = ll_node.get("discovered") or {}
                    nlldp = ndisc.get("lldp") or {}
                    ncdp = ndisc.get("cdp") or {}
                    mac = _norm_mac(ll_node.get("mac")) or _norm_mac(nlldp.get("chassisId"))
                    name = nlldp.get("systemName") or ncdp.get("deviceId") or ""
                    ip = nlldp.get("managementAddress") or ncdp.get("address") or ""
                    info = {
                        "platform": ncdp.get("platform") or "",
                        "description": nlldp.get("systemDescription") or ncdp.get("version") or "",
                        "capabilities": _s(nlldp.get("systemCapabilities") or ncdp.get("capabilities")),
                    }
                    if not (mac or name or ip):
                        mac = derived
                    resolved.append((self._resolve_neighbor(net_id, mac=mac, name=name, ip=ip, info=info), str(port)))
                (a, a_port), (b, b_port) = resolved
                if self._find_edge(a, b, a_port, b_port):
                    continue
                self._add_edge(
                    a,
                    b,
                    "lan",
                    a_port=a_port,
                    b_port=b_port,
                    source="linkLayer",
                    last_seen=link.get("lastReportedAt") or "",
                )

    def _find_edge(self, a: str, b: str, a_port: str, b_port: str) -> dict | None:
        for edge in self._pair_edges.get(frozenset((a, b)), []):
            ea, eb = (edge["a_port"], edge["b_port"]) if edge["a"] == a else (edge["b_port"], edge["a_port"])
            if _norm_port(ea) == _norm_port(a_port) and _norm_port(eb) == _norm_port(b_port):
                return edge
        return None

    def build_lldp_cdp(self) -> None:
        """Per-device LLDP/CDP: neighbor tables, plus edges linkLayer missed."""
        for serial, detail in self.dev_detail.items():
            node_id = f"d:{serial}"
            node = self.nodes.get(node_id)
            ports = (detail.get("lldp_cdp") or {}).get("ports")
            if not node or not isinstance(ports, dict):
                continue
            rows: list[list[Any]] = []
            for local_port, entry in sorted(ports.items(), key=lambda kv: str(kv[0])):
                if not isinstance(entry, dict):
                    continue
                lldp = entry.get("lldp") or {}
                cdp = entry.get("cdp") or {}
                if not lldp and not cdp:
                    continue
                cdp_id = str(cdp.get("deviceId") or "")
                mac = _norm_mac(lldp.get("chassisId")) or _norm_mac(cdp_id)
                name = lldp.get("systemName") or ("" if _norm_mac(cdp_id) else cdp_id)
                ip = lldp.get("managementAddress") or cdp.get("address") or ""
                remote_port = str(lldp.get("portId") or cdp.get("portId") or "")
                info = {
                    "platform": cdp.get("platform") or "",
                    "description": lldp.get("systemDescription") or cdp.get("version") or "",
                    "capabilities": _s(lldp.get("systemCapabilities") or cdp.get("capabilities")),
                }
                peer_id = self._resolve_neighbor(node["site"], mac=mac, name=str(name), ip=str(ip), info=info)
                peer = self.nodes[peer_id]
                rows.append(
                    [
                        local_port,
                        peer["label"],
                        remote_port,
                        ip,
                        "LLDP+CDP" if lldp and cdp else ("LLDP" if lldp else "CDP"),
                        info["platform"] or info["description"],
                    ]
                )
                existing = self._pair_edges.get(frozenset((node_id, peer_id)))
                if not existing:
                    self._add_edge(
                        node_id, peer_id, "lan", a_port=str(local_port), b_port=remote_port, source="lldpCdp"
                    )
                    continue
                # linkLayer already drew this adjacency; only fill port gaps.
                for edge in existing:
                    mine, theirs = ("a_port", "b_port") if edge["a"] == node_id else ("b_port", "a_port")
                    if not edge[mine] and not edge[theirs]:
                        edge[mine], edge[theirs] = str(local_port), remote_port
                        break
            node["_neighbors"] = rows

    def build_stack_edges(self) -> None:
        for detail in self.net_detail.values():
            for stack in detail.get("stacks") or []:
                members = [f"d:{s}" for s in stack.get("serials") or [] if f"d:{s}" in self.nodes]
                for a, b in zip(members, members[1:], strict=False):
                    self._add_edge(a, b, "stack", label=stack.get("name") or "stack")

    # ── WAN uplinks and VPN ────────────────────────────────────────────────

    def build_uplinks(self) -> None:
        for serial, row in self.uplinks_by_serial.items():
            node_id = f"d:{serial}"
            node = self.nodes.get(node_id)
            if not node:
                continue
            for uplink in row.get("uplinks") or []:
                raw_status = str(uplink.get("status") or "").lower()
                if raw_status in ("", "not connected"):
                    continue
                iface = str(uplink.get("interface") or "wan")
                wan_id = f"w:{serial}:{iface}"
                address = uplink.get("publicIp") or uplink.get("ip") or ""
                wan_sections: list[dict] = []
                _add(
                    wan_sections,
                    kv_section(
                        "WAN uplink",
                        [
                            ("Appliance", node["label"]),
                            ("Interface", iface),
                            ("Status", raw_status),
                            ("IP", uplink.get("ip")),
                            ("Public IP", uplink.get("publicIp")),
                            ("Gateway", uplink.get("gateway")),
                            ("Primary DNS", uplink.get("primaryDns")),
                            ("Secondary DNS", uplink.get("secondaryDns")),
                            ("IP assigned by", uplink.get("ipAssignedBy")),
                            ("Provider", uplink.get("provider")),
                            ("Signal type", uplink.get("signalType")),
                        ],
                    ),
                )
                self.nodes[wan_id] = {
                    "id": wan_id,
                    "kind": "wan",
                    "label": f"{iface.upper()} {address}".strip(),
                    "site": node["site"],
                    "status": _UPLINK_STATUS.get(raw_status, "unknown"),
                    "model": "",
                    "serial": "",
                    "mac": "",
                    "ip": str(address),
                    "parent": node_id,
                    "sections": wan_sections,
                }
                self._add_edge(wan_id, node_id, "uplink", a_port="", b_port=iface, status=raw_status)

    def build_vpn(self) -> None:
        peers_cfg = {}
        cfg = self.org_data.get("third_party_vpn_peers")
        for peer in (cfg.get("peers") if isinstance(cfg, dict) else cfg) or []:
            if isinstance(peer, dict):
                peers_cfg[str(peer.get("name") or "")] = peer

        seen: dict[frozenset, dict] = {}
        for net_id, vpn in self.vpn_by_net.items():
            a = self.appliance_by_net.get(net_id)
            if not a:
                continue
            for peer in vpn.get("merakiVpnPeers") or []:
                b = self.appliance_by_net.get(str(peer.get("networkId")))
                if not b:
                    continue
                reach = str(peer.get("reachability") or "").lower()
                key = frozenset((a, b))
                if key in seen:
                    if reach == "unreachable":
                        seen[key]["status"] = reach
                    continue
                edge = self._add_edge(a, b, "vpn", status=reach, label="AutoVPN")
                if edge:
                    seen[key] = edge
            for peer in vpn.get("thirdPartyVpnPeers") or []:
                name = str(peer.get("name") or peer.get("publicIp") or "peer")
                peer_id = f"p:{name}"
                if peer_id not in self.nodes:
                    cfg_row = peers_cfg.get(name, {})
                    sections: list[dict] = []
                    _add(
                        sections,
                        kv_section(
                            "Non-Meraki VPN peer",
                            [
                                ("Name", name),
                                ("Public IP", peer.get("publicIp") or cfg_row.get("publicIp")),
                                ("Remote ID", cfg_row.get("remoteId")),
                                ("IKE version", cfg_row.get("ikeVersion")),
                                ("Private subnets", cfg_row.get("privateSubnets")),
                                ("Network tags", cfg_row.get("networkTags")),
                                ("IPsec policy", cfg_row.get("ipsecPoliciesPreset") or cfg_row.get("ipsecPolicies")),
                            ],
                        ),
                    )
                    self.nodes[peer_id] = {
                        "id": peer_id,
                        "kind": "vpn_peer",
                        "label": name,
                        "site": VPN_PEER_SITE_ID,
                        "status": "unknown",
                        "model": "",
                        "serial": "",
                        "mac": "",
                        "ip": str(peer.get("publicIp") or cfg_row.get("publicIp") or ""),
                        "sections": sections,
                    }
                self._add_edge(a, peer_id, "vpn3p", status=str(peer.get("reachability") or "").lower(), label="IPsec")

    # ── Detail sections ────────────────────────────────────────────────────

    def build_device_sections(self) -> None:
        devices = {d.get("serial"): d for d in self.raw.get("devices") or []}
        for node in self.nodes.values():
            if node["kind"] == "external":
                self._external_sections(node)
                continue
            dev = devices.get(node.get("serial"))
            if not dev:
                continue
            serial = node["serial"]
            status_row = self.status_by_serial.get(serial) or {}
            uplink_row = self.uplinks_by_serial.get(serial) or {}
            detail = self.dev_detail.get(serial) or {}
            site = self.net_by_id.get(node["site"], {})
            sections = node["sections"]
            ha = uplink_row.get("highAvailability") or {}
            _add(
                sections,
                kv_section(
                    "Overview",
                    [
                        ("Name", dev.get("name")),
                        ("Status", node["status"]),
                        ("Model", dev.get("model")),
                        ("Serial", serial),
                        ("MAC", dev.get("mac")),
                        ("Product type", node["kind"]),
                        ("Network", site.get("name")),
                        ("LAN IP", node["ip"]),
                        ("Public IP", status_row.get("publicIp")),
                        ("Gateway", status_row.get("gateway")),
                        ("Primary DNS", status_row.get("primaryDns")),
                        ("Secondary DNS", status_row.get("secondaryDns")),
                        ("IP type", status_row.get("ipType")),
                        ("Firmware", dev.get("firmware")),
                        ("Stack", self.stack_by_serial.get(serial)),
                        ("HA role", ha.get("role") if ha.get("enabled") else ""),
                        ("Tags", dev.get("tags")),
                        ("Address", dev.get("address")),
                        ("Notes", dev.get("notes")),
                        ("Last reported", status_row.get("lastReportedAt")),
                        ("Dashboard URL", dev.get("url")),
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "WAN uplinks",
                    ["Interface", "Status", "IP", "Public IP", "Gateway", "DNS", "Assigned by"],
                    [
                        [
                            u.get("interface"),
                            u.get("status"),
                            u.get("ip"),
                            u.get("publicIp"),
                            u.get("gateway"),
                            [u.get("primaryDns"), u.get("secondaryDns")],
                            u.get("ipAssignedBy"),
                        ]
                        for u in uplink_row.get("uplinks") or []
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "Neighbors (LLDP/CDP)",
                    ["Local port", "Neighbor", "Remote port", "Address", "Protocol", "Platform"],
                    node.pop("_neighbors", []),
                ),
            )
            _add(
                sections,
                table_section(
                    "Clients (MAC/ARP)",
                    CLIENT_COLUMNS,
                    [_client_row(c) for c in _sorted_clients(self.clients_by_serial.get(serial))[:MAX_DEVICE_CLIENTS]],
                ),
            )
            if node["kind"] == "switch":
                self._switch_sections(node, detail)
            self._inventory_stub(node)

    def _switch_sections(self, node: dict, detail: dict) -> None:
        sections = node["sections"]
        statuses = {str(p.get("portId")): p for p in detail.get("port_statuses") or [] if isinstance(p, dict)}
        port_rows = []
        for port in self.ports_by_serial.get(node["serial"]) or []:
            live = statuses.get(str(port.get("portId"))) or {}
            row = [
                port.get("portId"),
                port.get("name"),
                port.get("enabled"),
                port.get("type"),
                port.get("vlan"),
                port.get("voiceVlan"),
                port.get("allowedVlans"),
                port.get("poeEnabled"),
                port.get("rstpEnabled"),
                port.get("stpGuard"),
                port.get("linkNegotiation"),
                port.get("tags"),
            ]
            if statuses:
                row += [
                    live.get("status"),
                    live.get("speed"),
                    live.get("duplex"),
                    live.get("clientCount"),
                    live.get("errors"),
                ]
            port_rows.append(row)
        columns = [
            "Port", "Name", "Enabled", "Type", "VLAN", "Voice VLAN", "Allowed VLANs",
            "PoE", "RSTP", "STP guard", "Negotiation", "Tags",
        ]  # fmt: skip
        if statuses:
            columns += ["Link", "Speed", "Duplex", "Clients", "Errors"]
        _add(sections, table_section("Switch ports", columns, port_rows))
        _add(
            sections,
            table_section(
                "VLANs on ports",
                ["VLAN", "Access ports", "Voice ports", "Native on trunks"],
                _port_vlan_rows(self.ports_by_serial.get(node["serial"]) or []),
            ),
        )

        stack = self._stack_for(node["serial"])
        interfaces = detail.get("routing_interfaces") or (stack or {}).get("routing_interfaces") or []
        routes = detail.get("routing_static_routes") or (stack or {}).get("routing_static_routes") or []
        _add(
            sections,
            table_section(
                "Layer 3 interfaces (SVIs)",
                ["Name", "VLAN", "Subnet", "Interface IP", "Default gateway", "OSPF area", "Multicast"],
                [
                    [
                        i.get("name"),
                        i.get("vlanId"),
                        i.get("subnet"),
                        i.get("interfaceIp"),
                        i.get("defaultGateway"),
                        (i.get("ospfSettings") or {}).get("area"),
                        i.get("multicastRouting"),
                    ]
                    for i in interfaces
                    if isinstance(i, dict)
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "Static routes",
                ["Name", "Subnet", "Next hop", "Advertise via OSPF", "Prefer over OSPF"],
                [
                    [
                        r.get("name"),
                        r.get("subnet"),
                        r.get("nextHopIp"),
                        r.get("advertiseViaOspfEnabled"),
                        r.get("preferOverOspfRoutesEnabled"),
                    ]
                    for r in routes
                    if isinstance(r, dict)
                ],
            ),
        )

    def _stack_for(self, serial: str) -> dict | None:
        for detail in self.net_detail.values():
            for stack in detail.get("stacks") or []:
                if serial in (stack.get("serials") or []):
                    return stack
        return None

    def _external_sections(self, node: dict) -> None:
        info = node.pop("_info", {})
        _add(
            node["sections"],
            kv_section(
                "Discovered neighbor",
                [
                    ("Name", node["label"]),
                    ("Management address", node.get("ip")),
                    ("MAC / chassis ID", node.get("mac")),
                    ("Platform", info.get("platform")),
                    ("Description", info.get("description")),
                    ("Capabilities", info.get("capabilities")),
                    ("Source", "LLDP/CDP as seen by Meraki devices (not managed in this organization)"),
                ],
            ),
        )
        self._inventory_stub(node)

    @staticmethod
    def _inventory_stub(node: dict) -> None:
        inv = node.get("inventory")
        if not inv:
            return
        _add(
            node["sections"],
            kv_section(
                "Plexus inventory",
                [
                    ("Hostname", inv.get("hostname")),
                    ("IP address", inv.get("ip_address")),
                    ("Device type", inv.get("device_type")),
                ],
            ),
        )

    # ── Sites ──────────────────────────────────────────────────────────────

    def build_sites(self) -> list[dict]:
        sites: list[dict] = []
        nodes_by_site: dict[str, list[dict]] = {}
        for node in self.nodes.values():
            nodes_by_site.setdefault(node["site"], []).append(node)

        for net in self.networks:
            net_id = net["id"]
            detail = self.net_detail.get(net_id) or {}
            vpn = self.vpn_by_net.get(net_id) or {}
            s2s = detail.get("site_to_site_vpn") or {}
            members = [n for n in nodes_by_site.get(net_id, []) if n["kind"] not in ("external", "wan")]
            sections: list[dict] = []
            counts: dict[str, int] = {}
            for member in members:
                counts[member["kind"]] = counts.get(member["kind"], 0) + 1
            _add(
                sections,
                kv_section(
                    "Site overview",
                    [
                        ("Network", net.get("name")),
                        ("Network ID", net_id),
                        ("Products", net.get("productTypes")),
                        ("Devices", ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))),
                        ("Time zone", net.get("timeZone")),
                        ("Tags", net.get("tags")),
                        ("Bound to template", net.get("isBoundToConfigTemplate")),
                        ("Notes", net.get("notes")),
                        ("Dashboard URL", net.get("url")),
                    ],
                ),
            )
            self._site_addressing(sections, detail)
            self._site_vpn(sections, net_id, detail, vpn)
            self._site_routes(sections, net_id, detail, vpn)
            self._site_security(sections, detail)
            self._site_switching(sections, detail)
            self._site_wireless(sections, detail)
            _add(
                sections,
                table_section(
                    "Network clients (MAC/ARP)",
                    CLIENT_COLUMNS + ["Seen on"],
                    [
                        _client_row(c) + [c.get("recentDeviceName") or c.get("recentDeviceSerial")]
                        for c in _sorted_clients(detail.get("clients"))[:MAX_SITE_CLIENTS]
                    ],
                ),
            )
            sites.append(
                {
                    "id": net_id,
                    "name": net.get("name") or net_id,
                    "tags": list(net.get("tags") or []),
                    "vpn_mode": str(vpn.get("vpnMode") or s2s.get("mode") or "none").lower(),
                    "status": _worst([m["status"] for m in members]) if members else "unknown",
                    "device_count": len(members),
                    "sections": sections,
                }
            )

        if nodes_by_site.get(VPN_PEER_SITE_ID):
            sites.append(
                {
                    "id": VPN_PEER_SITE_ID,
                    "name": "Non-Meraki VPN peers",
                    "tags": [],
                    "vpn_mode": "none",
                    "status": "unknown",
                    "device_count": len(nodes_by_site[VPN_PEER_SITE_ID]),
                    "sections": [],
                }
            )
        return sites

    @staticmethod
    def _site_addressing(sections: list[dict], detail: dict) -> None:
        _add(
            sections,
            table_section(
                "VLANs",
                ["VLAN", "Name", "Subnet", "Appliance IP", "DHCP", "DNS", "Group policy", "VPN NAT subnet"],
                [
                    [
                        v.get("id"),
                        v.get("name"),
                        v.get("subnet"),
                        v.get("applianceIp"),
                        v.get("dhcpHandling"),
                        v.get("dnsNameservers"),
                        v.get("groupPolicyId"),
                        v.get("vpnNatSubnet"),
                    ]
                    for v in detail.get("vlans") or []
                    if isinstance(v, dict)
                ],
            ),
        )
        single = detail.get("single_lan") or {}
        _add(
            sections,
            kv_section("Single LAN", [("Subnet", single.get("subnet")), ("Appliance IP", single.get("applianceIp"))]),
        )
        _add(
            sections,
            table_section(
                "Appliance ports",
                ["Port", "Enabled", "Type", "VLAN", "Allowed VLANs", "Drop untagged", "Access policy"],
                [
                    [
                        p.get("number"),
                        p.get("enabled"),
                        p.get("type"),
                        p.get("vlan"),
                        p.get("allowedVlans"),
                        p.get("dropUntaggedTraffic"),
                        p.get("accessPolicy"),
                    ]
                    for p in detail.get("appliance_ports") or []
                    if isinstance(p, dict)
                ],
            ),
        )

    def _site_vpn(self, sections: list[dict], net_id: str, detail: dict, vpn: dict) -> None:
        s2s = detail.get("site_to_site_vpn") or {}
        mode = vpn.get("vpnMode") or s2s.get("mode")
        if mode and str(mode).lower() != "none":
            _add(
                sections,
                kv_section(
                    "Site-to-site VPN",
                    [
                        ("Mode", mode),
                        ("Appliance status", vpn.get("deviceStatus")),
                        (
                            "Hubs",
                            [
                                f"{self.net_by_id.get(h.get('hubId'), {}).get('name') or h.get('hubId')}"
                                + (" (default route)" if h.get("useDefaultRoute") else "")
                                for h in s2s.get("hubs") or []
                            ],
                        ),
                    ],
                ),
            )
        _add(
            sections,
            table_section(
                "VPN local subnets",
                ["Subnet", "In VPN", "Name"],
                [[s.get("localSubnet"), s.get("useVpn"), ""] for s in s2s.get("subnets") or [] if isinstance(s, dict)]
                or [[s.get("subnet"), True, s.get("name")] for s in vpn.get("exportedSubnets") or []],
            ),
        )
        peer_rows = [
            [p.get("networkName") or p.get("networkId"), "AutoVPN", "", p.get("reachability")]
            for p in vpn.get("merakiVpnPeers") or []
        ] + [
            [p.get("name"), "Non-Meraki IPsec", p.get("publicIp"), p.get("reachability")]
            for p in vpn.get("thirdPartyVpnPeers") or []
        ]
        _add(sections, table_section("VPN peers", ["Peer", "Type", "Public IP", "Reachability"], peer_rows))
        bgp = detail.get("bgp") or {}
        if bgp.get("enabled"):
            _add(
                sections,
                kv_section("BGP", [("AS number", bgp.get("asNumber")), ("iBGP hold timer", bgp.get("ibgpHoldTimer"))]),
            )
            _add(
                sections,
                table_section(
                    "BGP neighbors",
                    ["Neighbor IP", "Remote AS", "Receive limit", "Allow transit", "eBGP hold timer", "eBGP multihop"],
                    [
                        [
                            n.get("ip"),
                            n.get("remoteAsNumber"),
                            n.get("receiveLimit"),
                            n.get("allowTransit"),
                            n.get("ebgpHoldTimer"),
                            n.get("ebgpMultihop"),
                        ]
                        for n in bgp.get("neighbors") or []
                        if isinstance(n, dict)
                    ],
                ),
            )

    def _site_routes(self, sections: list[dict], net_id: str, detail: dict, vpn: dict) -> None:
        static_routes = [r for r in detail.get("static_routes") or [] if isinstance(r, dict)]
        _add(
            sections,
            table_section(
                "Static routes",
                ["Name", "Subnet", "Gateway IP", "Enabled", "In VPN"],
                [
                    [r.get("name"), r.get("subnet"), r.get("gatewayIp"), r.get("enabled"), r.get("inVpn")]
                    for r in static_routes
                ],
            ),
        )

        # The Dashboard API has no "show ip route" for an MX, so assemble the
        # effective table from what it does expose: connected VLANs, static
        # routes, subnets advertised by VPN peers, and the WAN default.
        rows: list[list[Any]] = []
        for vlan in detail.get("vlans") or []:
            if isinstance(vlan, dict) and vlan.get("subnet"):
                rows.append(
                    [vlan.get("subnet"), "Connected", f"VLAN {vlan.get('id')} {vlan.get('name') or ''}".strip(), ""]
                )
        single = detail.get("single_lan") or {}
        if single.get("subnet"):
            rows.append([single.get("subnet"), "Connected", "Single LAN", ""])
        for route in static_routes:
            if route.get("enabled", True):
                rows.append([route.get("subnet"), "Static", route.get("gatewayIp"), route.get("name")])
        for peer in vpn.get("merakiVpnPeers") or []:
            peer_vpn = self.vpn_by_net.get(peer.get("networkId")) or {}
            for subnet in peer_vpn.get("exportedSubnets") or []:
                rows.append(
                    [
                        subnet.get("subnet"),
                        "AutoVPN",
                        peer.get("networkName") or peer.get("networkId"),
                        f"{subnet.get('name') or ''} ({peer.get('reachability') or 'unknown'})".strip(),
                    ]
                )
        peers_cfg = self.org_data.get("third_party_vpn_peers")
        cfg_by_name = {
            str(p.get("name")): p
            for p in ((peers_cfg.get("peers") if isinstance(peers_cfg, dict) else peers_cfg) or [])
            if isinstance(p, dict)
        }
        for peer in vpn.get("thirdPartyVpnPeers") or []:
            for subnet in (cfg_by_name.get(str(peer.get("name"))) or {}).get("privateSubnets") or []:
                rows.append([subnet, "Non-Meraki VPN", peer.get("name"), peer.get("reachability")])
        appliance = self.appliance_by_net.get(net_id)
        if appliance:
            uplinks = (self.uplinks_by_serial.get(self.nodes[appliance]["serial"]) or {}).get("uplinks") or []
            for uplink in uplinks:
                if str(uplink.get("status") or "").lower() in ("active", "ready") and uplink.get("gateway"):
                    rows.append(
                        [
                            "0.0.0.0/0",
                            "Default",
                            uplink.get("gateway"),
                            f"{uplink.get('interface')} ({uplink.get('status')})",
                        ]
                    )
        _add(
            sections,
            table_section("Effective routes (derived)", ["Destination", "Type", "Next hop / via", "Detail"], rows),
        )

    @staticmethod
    def _site_security(sections: list[dict], detail: dict) -> None:
        _add(
            sections,
            table_section(
                "Layer 3 firewall rules",
                ["#", "Policy", "Protocol", "Source", "Src port", "Destination", "Dst port", "Syslog", "Comment"],
                [
                    [
                        idx,
                        r.get("policy"),
                        r.get("protocol"),
                        r.get("srcCidr"),
                        r.get("srcPort"),
                        r.get("destCidr"),
                        r.get("destPort"),
                        r.get("syslogEnabled"),
                        r.get("comment"),
                    ]
                    for idx, r in enumerate((detail.get("l3_firewall") or {}).get("rules") or [], start=1)
                    if isinstance(r, dict)
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "Port forwarding",
                ["Name", "Uplink", "Protocol", "Public port", "LAN IP", "Local port", "Allowed IPs"],
                [
                    [
                        r.get("name"),
                        r.get("uplink"),
                        r.get("protocol"),
                        r.get("publicPort"),
                        r.get("lanIp"),
                        r.get("localPort"),
                        r.get("allowedIps"),
                    ]
                    for r in (detail.get("port_forwarding") or {}).get("rules") or []
                    if isinstance(r, dict)
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "1:1 NAT",
                ["Name", "Public IP", "LAN IP", "Uplink", "Allowed inbound"],
                [
                    [
                        r.get("name"),
                        r.get("publicIp"),
                        r.get("lanIp"),
                        r.get("uplink"),
                        [
                            f"{a.get('protocol')}/{_s(a.get('destinationPorts'))} from {_s(a.get('allowedIps'))}"
                            for a in r.get("allowedInbound") or []
                        ],
                    ]
                    for r in (detail.get("one_to_one_nat") or {}).get("rules") or []
                    if isinstance(r, dict)
                ],
            ),
        )
        spare = detail.get("warm_spare") or {}
        if spare.get("enabled"):
            _add(
                sections,
                kv_section(
                    "Warm spare (HA)",
                    [
                        ("Primary serial", spare.get("primarySerial")),
                        ("Spare serial", spare.get("spareSerial")),
                        ("Uplink mode", spare.get("uplinkMode")),
                        ("WAN1 virtual IP", (spare.get("wan1") or {}).get("ip")),
                        ("WAN2 virtual IP", (spare.get("wan2") or {}).get("ip")),
                    ],
                ),
            )

    @staticmethod
    def _site_switching(sections: list[dict], detail: dict) -> None:
        _add(
            sections,
            table_section(
                "Switch stacks",
                ["Stack", "Members"],
                [[s.get("name"), s.get("serials")] for s in detail.get("stacks") or [] if isinstance(s, dict)],
            ),
        )
        stp = detail.get("stp") or {}
        if stp:
            _add(sections, kv_section("Spanning tree", [("RSTP enabled", stp.get("rstpEnabled"))]))
            _add(
                sections,
                table_section(
                    "STP bridge priority",
                    ["Priority", "Switches", "Stacks", "Switch profiles"],
                    [
                        [p.get("stpPriority"), p.get("switches"), p.get("stacks"), p.get("switchProfiles")]
                        for p in stp.get("stpBridgePriority") or []
                        if isinstance(p, dict)
                    ],
                ),
            )
        ospf = detail.get("ospf") or {}
        if ospf.get("enabled"):
            _add(
                sections,
                kv_section(
                    "OSPF",
                    [
                        ("Hello timer (s)", ospf.get("helloTimerInSeconds")),
                        ("Dead timer (s)", ospf.get("deadTimerInSeconds")),
                        ("MD5 authentication", ospf.get("md5AuthenticationEnabled")),
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "OSPF areas",
                    ["Area", "Name", "Type"],
                    [[a.get("areaId"), a.get("areaName"), a.get("areaType")] for a in ospf.get("areas") or []],
                ),
            )

    @staticmethod
    def _site_wireless(sections: list[dict], detail: dict) -> None:
        _add(
            sections,
            table_section(
                "Wireless SSIDs",
                ["#", "SSID", "Auth mode", "Encryption", "IP assignment", "VLAN tagging", "VLAN", "Band", "Visible"],
                [
                    [
                        s.get("number"),
                        s.get("name"),
                        s.get("authMode"),
                        s.get("encryptionMode") or s.get("wpaEncryptionMode"),
                        s.get("ipAssignmentMode"),
                        s.get("useVlanTagging"),
                        s.get("defaultVlanId"),
                        s.get("bandSelection"),
                        s.get("visible"),
                    ]
                    for s in detail.get("ssids") or []
                    if isinstance(s, dict) and s.get("enabled")
                ],
            ),
        )

    # ── Edge sections ──────────────────────────────────────────────────────

    def build_edge_sections(self) -> None:
        titles = {
            "lan": "LAN link",
            "vpn": "AutoVPN tunnel",
            "vpn3p": "Non-Meraki VPN tunnel",
            "uplink": "WAN uplink",
            "stack": "Stack link",
        }
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            edge["sections"] = [
                s
                for s in [
                    kv_section(
                        titles.get(edge["kind"], "Link"),
                        [
                            ("A end", a["label"]),
                            ("A port", edge.get("a_port")),
                            ("B end", b["label"]),
                            ("B port", edge.get("b_port")),
                            ("Status", edge.get("status")),
                            ("Discovered via", edge.pop("source", "")),
                            ("Last reported", edge.pop("last_seen", "")),
                        ],
                    )
                ]
                if s
            ]


# ── Layout ───────────────────────────────────────────────────────────────────


def _layout_site(members: list[dict], edges: list[dict]) -> tuple[float, float]:
    """Assign site-relative x/y to ``members``; return the content (w, h)."""
    wan_children: dict[str, list[dict]] = {}
    tree_nodes: dict[str, dict] = {}
    for node in members:
        if node["kind"] == "wan" and node.get("parent"):
            wan_children.setdefault(node["parent"], []).append(node)
        else:
            tree_nodes[node["id"]] = node

    adjacency: dict[str, list[str]] = {nid: [] for nid in tree_nodes}
    for edge in edges:
        if edge["kind"] in ("lan", "stack") and edge["a"] in adjacency and edge["b"] in adjacency:
            adjacency[edge["a"]].append(edge["b"])
            adjacency[edge["b"]].append(edge["a"])

    kind_rank = {
        "appliance": 0,
        "firewall": 0,
        "router": 0,
        "cellularGateway": 1,
        "switch": 2,
        "external": 3,
        "wireless": 4,
    }

    def root_order(nid: str) -> tuple:
        node = tree_nodes[nid]
        return (kind_rank.get(node["kind"], 5), -len(adjacency[nid]), node["label"].lower())

    children: dict[str, list[str]] = {nid: [] for nid in tree_nodes}
    visited: set[str] = set()
    roots: list[str] = []
    loose: list[str] = []
    for candidate in sorted(tree_nodes, key=root_order):
        if candidate in visited:
            continue
        if not adjacency[candidate] and tree_nodes[candidate]["kind"] != "appliance":
            visited.add(candidate)
            loose.append(candidate)
            continue
        roots.append(candidate)
        visited.add(candidate)
        queue = [candidate]
        while queue:
            current = queue.pop(0)
            for neighbor in sorted(set(adjacency[current]), key=root_order):
                if neighbor not in visited:
                    visited.add(neighbor)
                    children[current].append(neighbor)
                    queue.append(neighbor)

    sizes: dict[str, tuple[float, float]] = {}

    def measure(nid: str) -> tuple[float, float]:
        inner = [c for c in children[nid] if children[c]]
        leaves = [c for c in children[nid] if not children[c]]
        inner_w = 0.0
        inner_h = 0.0
        for child in inner:
            cw, ch = measure(child)
            inner_w += cw
            inner_h = max(inner_h, ch)
        leaf_cols = min(len(leaves), MAX_LEAF_COLS)
        leaf_rows = math.ceil(len(leaves) / MAX_LEAF_COLS) if leaves else 0
        own_w = max(CELL_W, len(wan_children.get(nid, [])) * CELL_W)
        width = max(own_w, inner_w + leaf_cols * CELL_W)
        height = CELL_H + max(inner_h, leaf_rows * LEAF_ROW_H)
        sizes[nid] = (width, height)
        return sizes[nid]

    def place(nid: str, x0: float, y0: float) -> None:
        width, _height = sizes[nid]
        node = tree_nodes[nid]
        node["x"], node["y"] = x0 + width / 2, y0
        wans = wan_children.get(nid, [])
        for idx, wan in enumerate(sorted(wans, key=lambda w: w["label"])):
            wan["x"] = node["x"] + (idx - (len(wans) - 1) / 2) * CELL_W
            wan["y"] = y0 - CELL_H
        cursor = x0
        inner = [c for c in children[nid] if children[c]]
        leaves = [c for c in children[nid] if not children[c]]
        for child in inner:
            place(child, cursor, y0 + CELL_H)
            cursor += sizes[child][0]
        for idx, leaf in enumerate(leaves):
            leaf_node = tree_nodes[leaf]
            leaf_node["x"] = cursor + (idx % MAX_LEAF_COLS) * CELL_W + CELL_W / 2
            leaf_node["y"] = y0 + CELL_H + (idx // MAX_LEAF_COLS) * LEAF_ROW_H

    top = CELL_H if wan_children else 0.0
    cursor_x = 0.0
    content_h = 0.0
    for root in roots:
        width, height = measure(root)
        place(root, cursor_x, top)
        cursor_x += width
        content_h = max(content_h, top + height)

    if loose:
        cols = max(1, min(8, math.ceil(math.sqrt(len(loose)) * 1.5)))
        base_y = content_h
        for idx, nid in enumerate(loose):
            node = tree_nodes[nid]
            node["x"] = (idx % cols) * CELL_W + CELL_W / 2
            node["y"] = base_y + (idx // cols) * LEAF_ROW_H
        cursor_x = max(cursor_x, min(cols, len(loose)) * CELL_W)
        content_h = base_y + math.ceil(len(loose) / cols) * LEAF_ROW_H

    # Orphaned WAN stubs (parent filtered out) would otherwise have no position.
    for node in members:
        if "x" not in node:
            node["x"], node["y"] = CELL_W / 2, content_h
            content_h += LEAF_ROW_H
            cursor_x = max(cursor_x, CELL_W)

    return max(cursor_x, CELL_W), max(content_h, LEAF_ROW_H)


def _layout(sites: list[dict], nodes: dict[str, dict], edges: list[dict]) -> None:
    members_by_site: dict[str, list[dict]] = {}
    for node in nodes.values():
        members_by_site.setdefault(node["site"], []).append(node)

    for site in sites:
        members = members_by_site.get(site["id"], [])
        content_w, content_h = _layout_site(members, edges) if members else (0.0, 0.0)
        title_w = len(site["name"]) * 11 + 120
        site["w"] = max(SITE_MIN_W, content_w + 2 * SITE_PAD, title_w)
        site["h"] = SITE_HEADER_H + content_h + 2 * SITE_PAD if members else SITE_HEADER_H + 24
        site["_content_w"] = content_w

    # VPN hubs first (they anchor the tunnel fan-out), then alphabetical.
    def order(site: dict) -> tuple:
        if site["vpn_mode"] == "hub":
            rank = 0
        elif site["id"] == VPN_PEER_SITE_ID:
            rank = 1
        else:
            rank = 2
        return (rank, site["name"].lower())

    sites.sort(key=order)
    total_area = sum((s["w"] + SITE_GAP) * (s["h"] + SITE_GAP) for s in sites)
    row_limit = max(math.sqrt(total_area) * 1.5, max((s["w"] for s in sites), default=0))
    x = y = row_h = 0.0
    for site in sites:
        if x > 0 and x + site["w"] > row_limit:
            x = 0.0
            y += row_h + SITE_GAP
            row_h = 0.0
        site["x"], site["y"] = x, y
        x += site["w"] + SITE_GAP
        row_h = max(row_h, site["h"])
        offset_x = site["x"] + (site["w"] - site.pop("_content_w")) / 2
        offset_y = site["y"] + SITE_HEADER_H + SITE_PAD + 30
        for node in members_by_site.get(site["id"], []):
            node["x"] = round(node["x"] + offset_x, 1)
            node["y"] = round(node["y"] + offset_y, 1)


# ── Public API ───────────────────────────────────────────────────────────────


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_device_nodes()
    builder.build_link_layer_edges()
    builder.build_lldp_cdp()
    builder.build_stack_edges()
    builder.build_uplinks()
    builder.build_vpn()
    builder.build_device_sections()
    sites = builder.build_sites()
    builder.build_edge_sections()
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)
        node.pop("_neighbors", None)
        node.pop("_info", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in ("external", "wan", "vpn_peer"):
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1
    vlan_count = sum(len(d.get("vlans") or []) for d in builder.net_detail.values())

    organization = raw.get("organization") or {}
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": str(organization.get("id") or ""),
            "name": organization.get("name") or "Meraki organization",
            "url": organization.get("url") or "",
        },
        "summary": {
            "sites": len(builder.networks),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": sum(1 for n in nodes if n["kind"] == "external"),
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": edge_counts.get("lan", 0) + edge_counts.get("stack", 0),
            "vpn_tunnels": edge_counts.get("vpn", 0) + edge_counts.get("vpn3p", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": vlan_count,
        },
        "collection": {
            "sources": ["Meraki Dashboard API v1"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
