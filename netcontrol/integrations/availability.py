"""Availability states of the entities in a topology snapshot.

Every integration (Meraki, Cato, Cisco FMC, Palo Alto Panorama, Appgate SDP,
AWS, Azure, GCP) builds the same snapshot format (see
``netcontrol.integrations.meraki.normalize``): nodes carry a ``status`` from
the shared node vocabulary (``online`` / ``alerting`` / ``dormant`` /
``offline`` / ``unknown``) and edges that stand for a live connection carry a
link status (``active`` / ``ready`` / ``connecting`` / ``failed`` for an
uplink, ``reachable`` / ``ready`` / ``degraded`` / ``unreachable`` for a
tunnel, ``active`` / ``failed`` for a cloud attachment, peering or circuit).

``extract_entity_states`` reads one snapshot and returns what availability
tracking keeps of it: one ``EntityState`` per device, site, uplink, tunnel,
VPN connection, circuit, peering or HA / peer link, with that status mapped
to ``up`` / ``degraded`` / ``down`` / ``unknown``. Pure: no database, no
network.

What is left out, because it is no entity whose availability means anything:
WAN address nodes (their uplink edge is tracked instead), external CDP/LLDP
neighbors, third-party VPN peers (only their tunnel is known), connected users
and user groups, VPCs / VNets (containers), the synthetic manager, PoP and
backbone nodes of Cato, FMC, Panorama and Appgate (drawn ``online`` whenever
the collection worked), structural edges with no status (LAN, stack, managed
by), edges to users, and Meraki networks (their status is only the worst of
their devices', which are tracked one by one).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.aws.normalize import _LINK_LABELS as _AWS_LINK_LABELS
from netcontrol.integrations.azure.normalize import _LINK_LABELS as _AZURE_LINK_LABELS
from netcontrol.integrations.gcp.normalize import _LINK_LABELS as _GCP_LINK_LABELS
from netcontrol.integrations.meraki.normalize import _STATUS_RANK, _UPLINK_STATUS

STATES = ("up", "degraded", "down", "unknown")
ENTITY_TYPES = ("device", "site", "uplink", "tunnel", "vpn_connection", "circuit", "peering", "link")
CLOUD_PROVIDERS = ("aws", "azure", "gcp")
# Sites carry a status of their own (not one derived from their devices).
_SITE_PROVIDERS = ("cato", "appgate")

# The shared node vocabulary (``_STATUS_RANK``). A dormant Meraki device has
# not checked in for a week: it is down, not unknown.
NODE_STATES: dict[str, str] = {
    status: {"online": "up", "alerting": "degraded", "offline": "down", "dormant": "down"}.get(status, "unknown")
    for status in _STATUS_RANK
}
# Edge statuses. An uplink edge keeps the raw Meraki/Cato uplink status, read
# through the normaliser's own uplink map; tunnels and cloud links use the
# path-trace vocabulary (``ready`` is a standby tunnel: up).
EDGE_STATES: dict[str, str] = {
    **{raw: NODE_STATES[status] for raw, status in _UPLINK_STATUS.items()},
    "reachable": "up",
    "degraded": "degraded",
    "unreachable": "down",
}

_SKIPPED_NODE_KINDS = frozenset({"wan", "external", "users", "user", "vpc", "vpn_peer"})
_USER_KINDS = frozenset({"users", "user"})


def _cloud_link_type(label: str) -> str:
    text = label.lower()
    if any(word in text for word in ("direct connect", "expressroute", "interconnect")):
        return "circuit"
    if "peering" in text:
        return "peering"
    if "internet gateway" in text or "nat gateway" in text:
        return ""  # always drawn active; no state of its own
    return "link"


# Edge label of a cloud connection -> entity type ("" = not tracked). Only the
# connections the normalisers draw from discovery state are tracked; a VM in
# its VNet, a route next hop or an internet gateway is drawn ``active``
# whatever happens.
CLOUD_LINK_TYPES: dict[str, str] = {
    label: _cloud_link_type(label)
    for labels in (_AWS_LINK_LABELS, _AZURE_LINK_LABELS, _GCP_LINK_LABELS)
    for label in labels.values()
}


@dataclass(frozen=True)
class EntityState:
    provider: str
    org_ref: int
    entity_type: str
    entity_id: str
    name: str
    state: str
    raw_status: str = ""
    site: str = ""
    model: str = ""
    host_id: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "org_ref": self.org_ref,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "name": self.name,
            "state": self.state,
            "raw_status": self.raw_status,
            "site": self.site,
            "model": self.model,
            "host_id": self.host_id,
            "meta": dict(self.meta),
        }


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def node_state(status: Any) -> str:
    return NODE_STATES.get(_text(status).lower(), "unknown")


def edge_state(status: Any) -> str:
    return EDGE_STATES.get(_text(status).lower(), "unknown")


def _host_id(node: dict) -> int | None:
    try:
        host_id = int((node.get("inventory") or {}).get("host_id") or 0)
    except TypeError, ValueError:
        return None
    return host_id or None


def _section_of(edge: dict) -> dict:
    sections = edge.get("sections") or []
    return sections[0] if sections and isinstance(sections[0], dict) else {}


def _edge_label(provider: str, edge: dict) -> str:
    """The edge's label. The AWS, Azure and GCP normalisers move it (and the
    connection name) into the edge's detail section; the others keep it (an
    edge without one has a generic section title, not a label)."""
    if provider in CLOUD_PROVIDERS:
        return _text(edge.get("label")) or _text(_section_of(edge).get("title"))
    return _text(edge.get("label"))


def _edge_detail(edge: dict) -> str:
    if _text(edge.get("detail")):
        return _text(edge.get("detail"))
    for row in _section_of(edge).get("rows") or []:
        if isinstance(row, (list, tuple)) and len(row) == 2 and row[0] == "Connection":
            return _text(row[1])
    return ""


def _edge_type(provider: str, edge: dict) -> str:
    kind = _text(edge.get("kind"))
    if provider in CLOUD_PROVIDERS:
        if kind == "vpn":
            return "vpn_connection"
        if kind in ("attach", "uplink"):
            return CLOUD_LINK_TYPES.get(_edge_label(provider, edge), "")
        return ""
    if kind == "uplink":
        return "uplink"
    if kind in ("vpn", "vpn3p"):
        return "tunnel"
    if kind in ("stack", "manage"):
        return "link"  # an HA pair / cluster link, an Appgate peer link
    return ""


def _edge_name(entity_type: str, label: str, edge: dict, a: dict, b: dict) -> str:
    a_label, b_label = _text(a.get("label")) or _text(edge.get("a")), _text(b.get("label")) or _text(edge.get("b"))
    if entity_type == "uplink":
        # a is the WAN address node, b the device.
        port = _text(edge.get("b_port"))
        return f"{b_label} {port}".strip() if port else f"{b_label} - {a_label}"
    name = f"{a_label} - {b_label}"
    return f"{name} ({label})" if label else name


def extract_entity_states(provider: str, org_ref: int, snapshot: dict | None) -> list[EntityState]:
    """The tracked entities of one snapshot with their availability state."""
    snapshot = snapshot or {}
    provider = _text(provider).lower() or _text(snapshot.get("provider")).lower() or "meraki"
    sites = {_text(s.get("id")): s for s in snapshot.get("sites") or [] if isinstance(s, dict)}
    nodes = {_text(n.get("id")): n for n in snapshot.get("nodes") or [] if isinstance(n, dict)}

    def site_name(site_id: str) -> str:
        return _text((sites.get(site_id) or {}).get("name")) or site_id

    found: list[EntityState] = []
    seen: set[tuple[str, str]] = set()

    def add(entity: EntityState) -> None:
        key = (entity.entity_type, entity.entity_id)
        if key in seen:
            # Two entities may share their ends and label; keep both.
            n = 2
            while (entity.entity_type, f"{entity.entity_id}#{n}") in seen:
                n += 1
            entity = EntityState(**{**entity.__dict__, "entity_id": f"{entity.entity_id}#{n}"})
            key = (entity.entity_type, entity.entity_id)
        seen.add(key)
        found.append(entity)

    for node_id, node in nodes.items():
        kind = _text(node.get("kind"))
        if not node_id or kind in _SKIPPED_NODE_KINDS:
            continue
        if kind == "cloud" and provider not in CLOUD_PROVIDERS:
            continue
        raw = _text(node.get("status")).lower()
        add(
            EntityState(
                provider=provider,
                org_ref=org_ref,
                entity_type="device",
                entity_id=node_id,
                name=_text(node.get("label")) or node_id,
                state=node_state(raw),
                raw_status=raw,
                site=site_name(_text(node.get("site"))),
                model=_text(node.get("model")),
                host_id=_host_id(node),
                meta={k: node[k] for k in ("kind", "ip", "serial") if _text(node.get(k))},
            )
        )

    if provider in _SITE_PROVIDERS:
        for site_id, site in sites.items():
            if not site_id or site_id.startswith("__") or site.get("not_collected"):
                continue
            raw = _text(site.get("status")).lower()
            add(
                EntityState(
                    provider=provider,
                    org_ref=org_ref,
                    entity_type="site",
                    entity_id=site_id,
                    name=_text(site.get("name")) or site_id,
                    state=node_state(raw),
                    raw_status=raw,
                    site=_text(site.get("name")) or site_id,
                )
            )

    for edge in snapshot.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        raw = _text(edge.get("status")).lower()
        if not raw:
            continue  # structural: no state
        entity_type = _edge_type(provider, edge)
        if not entity_type:
            continue
        a_id, b_id = _text(edge.get("a")), _text(edge.get("b"))
        a, b = nodes.get(a_id) or {}, nodes.get(b_id) or {}
        if _text(a.get("kind")) in _USER_KINDS or _text(b.get("kind")) in _USER_KINDS:
            continue  # remote users come and go: not an outage
        # Edge ids are positional ("e12"); the ends and label are not.
        label = _edge_label(provider, edge)
        tag = label or _text(edge.get("a_port")) or _text(edge.get("b_port"))
        entity_id = f"{_text(edge.get('kind'))}:{a_id}>{b_id}" + (f":{tag}" if tag else "")
        device = b if entity_type == "uplink" else (a if a.get("kind") not in ("wan", "vpn_peer") else b)
        meta = {"kind": _text(edge.get("kind")), "a": a_id, "b": b_id}
        if _edge_detail(edge):
            meta["detail"] = _edge_detail(edge)
        add(
            EntityState(
                provider=provider,
                org_ref=org_ref,
                entity_type=entity_type,
                entity_id=entity_id,
                name=_edge_name(entity_type, label, edge, a, b),
                state=edge_state(raw),
                raw_status=raw,
                site=site_name(_text(device.get("site"))) if device else "",
                model=label,
                meta=meta,
            )
        )
    return found
