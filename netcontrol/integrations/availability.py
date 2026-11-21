"""Availability states of the entities in a topology snapshot.

Every integration (Meraki, Cato, Cisco FMC, Palo Alto Panorama, Appgate SDP,
OPNsense, AWS, Azure, GCP) builds the same snapshot format (see
``netcontrol.integrations.meraki.normalize``): nodes carry a ``status`` from
the shared node vocabulary (``online`` / ``alerting`` / ``dormant`` /
``offline`` / ``unknown``) and edges that stand for a live connection carry a
link status (``active`` / ``ready`` / ``connecting`` / ``failed`` for an
uplink (an OPNsense gateway also ``degraded`` for a latency or loss alarm
and ``unknown`` when it is not monitored), ``reachable`` / ``ready`` /
``degraded`` / ``unreachable`` for a tunnel, ``active`` / ``failed`` for a cloud attachment, peering or circuit).

``extract_entity_states`` reads one snapshot and returns what availability
tracking keeps of it: one ``EntityState`` per device, site, uplink, tunnel,
VPN connection, circuit, peering, HA / peer link, redundancy group (the
snapshot's ``ha`` block: an OPNsense firewall's CARP groups, a ``link``
each, see ``ha_entity_states``) or service
(the snapshot's ``services``, see ``cloud_services.service_states``: an
AWS, Azure or GCP database, load balancer, private endpoint...; an OPNsense
firewall's services, which name their ``device``; each with its
state already in the node vocabulary) or certificate (the snapshot's
``certificates``: an OPNsense firewall's certificates and CAs that are
tracked, see ``certificate_entity_states``), with that status mapped
to ``up`` / ``degraded`` / ``down`` / ``unknown``, and the latency / jitter /
loss / traffic rate reported for it (``metrics``, see ``METRIC_KEYS``). Pure: no
database, no network.

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

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.aws.normalize import _LINK_LABELS as _AWS_LINK_LABELS
from netcontrol.integrations.azure.normalize import _LINK_LABELS as _AZURE_LINK_LABELS
from netcontrol.integrations.gcp.normalize import _LINK_LABELS as _GCP_LINK_LABELS
from netcontrol.integrations.meraki.normalize import _STATUS_RANK, _UPLINK_STATUS

STATES = ("up", "degraded", "down", "unknown")
ENTITY_TYPES = (
    "device",
    "site",
    "uplink",
    "tunnel",
    "vpn_connection",
    "circuit",
    "peering",
    "link",
    "service",
    "certificate",
)
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

# Measurements a normaliser may put on an edge or node as ``metrics``
# (an OPNsense gateway's dpinger loss, RTT and RTT deviation; the traffic
# rate of a tunnel in bits per second, received / sent by the device,
# ``netcontrol.integrations.traffic``), and the metric name each is stored
# under in the daily rollups (SLA targets evaluate latency, jitter and loss).
METRIC_KEYS: dict[str, str] = {
    "latency_ms": "latency",
    "jitter_ms": "jitter",
    "loss_pct": "packet_loss",
    "in_bps": "traffic_in",
    "out_bps": "traffic_out",
}

# Roles of a redundancy group member (``meta["role"]`` of an ``ha`` entity)
# between which a change is a failover: the tracker alerts on it although
# both are healthy (``topology_availability.failovers``).
FAILOVER_ROLES = ("master", "backup")

# Certificate expiry (the snapshot's ``certificates``, see
# ``certificate_entity_states``): a tracked certificate is ``expiring`` from
# ``CERTIFICATE_WARNING_DAYS`` before its end (a warning), ``critical`` from
# ``CERTIFICATE_CRITICAL_DAYS`` and ``expired`` after it (both critical
# alerts). The tier is the entity's ``raw_status``; the tracker alerts on a
# tier getting worse (``topology_availability.certificate_changes``), not on
# the state. Every tier but ``valid`` is the state ``degraded``: an
# expiring or expired certificate is a problem to fix, not downtime, and
# ``degraded`` counts as available in uptime and SLA figures.
CERTIFICATE_WARNING_DAYS = 30
CERTIFICATE_CRITICAL_DAYS = 7
CERTIFICATE_TIER_RANK: dict[str, int] = {"unknown": 0, "valid": 0, "expiring": 1, "critical": 2, "expired": 3}
CERTIFICATE_TIER_SEVERITY: dict[str, str] = {"expiring": "warning", "critical": "critical", "expired": "critical"}
_CERTIFICATE_STATES = {"valid": "up", "expiring": "degraded", "critical": "degraded", "expired": "degraded"}


def certificate_tier(valid_to: float | None, now: float | None) -> str:
    """The expiry tier of a certificate valid until ``valid_to`` at ``now``
    (both Unix seconds): ``valid``, ``expiring``, ``critical``, ``expired``,
    or ``unknown`` when either is not known."""
    if valid_to is None or now is None:
        return "unknown"
    left = valid_to - now
    if left <= 0:
        return "expired"
    if left <= CERTIFICATE_CRITICAL_DAYS * 86400:
        return "critical"
    if left <= CERTIFICATE_WARNING_DAYS * 86400:
        return "expiring"
    return "valid"


def certificate_expiry_text(days_left: Any, tier: str) -> str:
    """``expires in 12 days`` / ``expires today`` / ``expired 3 days ago``
    (``days_left``: whole days to the end, negative once expired); ``""``
    without a number."""
    if not isinstance(days_left, int) or isinstance(days_left, bool):
        return ""
    if tier == "expired":
        ago = -days_left
        return "expired today" if ago <= 0 else f"expired {ago} day{'s' if ago != 1 else ''} ago"
    if days_left <= 0:
        return "expires today"
    return f"expires in {days_left} day{'s' if days_left != 1 else ''}"


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
    metrics: dict[str, float] = field(default_factory=dict)

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
            "metrics": dict(self.metrics),
        }


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def node_state(status: Any) -> str:
    return NODE_STATES.get(_text(status).lower(), "unknown")


def edge_state(status: Any) -> str:
    return EDGE_STATES.get(_text(status).lower(), "unknown")


def traffic_meta(item: dict) -> dict[str, str]:
    """``{"traffic_key": ...}`` of an edge or node that carries a
    ``traffic`` block (``netcontrol.integrations.traffic``): how the counter
    store ties a key to the entity, so a monitoring poll can file its
    samples under it."""
    found = item.get("traffic")
    key = _text(found.get("key")) if isinstance(found, dict) else ""
    return {"traffic_key": key} if key else {}


def entity_metrics(item: dict) -> dict[str, float]:
    """The numeric ``METRIC_KEYS`` values of an edge's or node's ``metrics``."""
    found = item.get("metrics")
    if not isinstance(found, dict):
        return {}
    return {
        key: float(value)
        for key, value in found.items()
        if key in METRIC_KEYS and isinstance(value, (int, float)) and not isinstance(value, bool)
    }


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


def clean_entity_types(provider: str, snapshot: dict | None) -> frozenset[str]:
    """The entity types whose absence from ``snapshot`` proves the entity is
    gone at the vendor: every call that says what exists of that type
    succeeded. Availability tracking deletes a stored entity of a clean type
    that the snapshot does not report, and keeps (``unknown``, missing) one
    of any other type.

    - No snapshot, or a site that was not collected: nothing is clean.
    - Meraki: a stored snapshot always holds the full network and device
      lists (the collector raises otherwise), so ``device`` is always clean.
      Uplinks come from ``uplinks/statuses`` and tunnels from
      ``appliance/vpn/statuses`` and ``thirdPartyVPNPeers``, all organization
      calls (error scope ``org``), so ``uplink``, ``tunnel`` and ``link`` are
      clean only when no ``org`` call failed. A failed network or device
      detail call does not feed any tracked entity.
    - Every other provider: every type when the collection reported no
      error, else none (its errors do not say which entity type they feed).
      A warning marked ``info`` (an OPNsense firmware update, audit finding
      or CARP problem) reports what the device said, not a failed call: it
      does not count.
    """
    if not snapshot:
        return frozenset()
    if any(isinstance(s, dict) and s.get("not_collected") for s in snapshot.get("sites") or []):
        return frozenset()
    errors = [
        e
        for e in (snapshot.get("collection") or {}).get("errors") or []
        if e and not (isinstance(e, dict) and e.get("info"))
    ]
    if _text(provider).lower() == "meraki":
        if any(isinstance(e, dict) and _text(e.get("scope")) == "org" for e in errors):
            return frozenset({"device"})
        return frozenset({"device", "uplink", "tunnel", "link"})
    return frozenset() if errors else frozenset(ENTITY_TYPES)


def ha_entity_states(
    provider: str, org_ref: int, snapshot: dict, nodes: dict[str, dict], site_name: Callable[[str], str]
) -> list[EntityState]:
    """The redundancy groups of the snapshot's ``ha`` block (an OPNsense
    firewall's CARP groups, see ``opnsense.normalize.ha_block``), as ``link``
    entities (the tracker's HA type): ``host_id`` and site of the device
    that reports them, ``raw_status`` and ``meta["role"]`` the lower-case
    role (which the tracker watches for failovers, ``FAILOVER_ROLES``),
    ``meta["a"]`` the device, so muting or removing it covers them."""
    ha = snapshot.get("ha")
    if not isinstance(ha, dict):
        return []
    device_id = _text(ha.get("device"))
    device = nodes.get(device_id) or {}
    label = _text(device.get("label")) or device_id
    protocol = _text(ha.get("protocol")) or "HA"
    found: list[EntityState] = []
    for vip in ha.get("vips") or []:
        if not isinstance(vip, dict) or not _text(vip.get("id")):
            continue
        addresses = [_text(a) for a in vip.get("addresses") or [] if _text(a)]
        interface, vhid = _text(vip.get("interface")), _text(vip.get("vhid"))
        role = _text(vip.get("role")).lower()
        name = f"{label} {protocol} {interface} VHID {vhid}" + (f" ({', '.join(addresses)})" if addresses else "")
        found.append(
            EntityState(
                provider=provider,
                org_ref=org_ref,
                entity_type="link",
                entity_id=_text(vip.get("id")),
                name=name.strip(),
                state=node_state(vip.get("status")),
                raw_status=role,
                site=site_name(_text(device.get("site"))) if device else "",
                model=protocol,
                host_id=_host_id(device),
                meta={
                    "kind": protocol.lower(),
                    "a": device_id,
                    "interface": interface,
                    "vhid": vhid,
                    "addresses": addresses,
                    "advbase": _text(vip.get("advbase")),
                    "advskew": _text(vip.get("advskew")),
                    "role": role,
                },
            )
        )
    return found


def certificate_entity_states(
    provider: str, org_ref: int, snapshot: dict, nodes: dict[str, dict], site_name: Callable[[str], str]
) -> list[EntityState]:
    """The tracked records of the snapshot's ``certificates`` (an OPNsense
    firewall's, see ``opnsense.certificates.certificate_records``; those
    only listed are left out) as ``certificate`` entities: state ``up``
    while valid, ``degraded`` from ``expiring`` on (``_CERTIFICATE_STATES``),
    ``unknown`` without an expiry date; ``raw_status`` the tier;
    ``host_id`` and site of the ``device`` that holds them, ``meta["a"]``
    that device, so muting or removing it covers them."""
    found: list[EntityState] = []
    for record in snapshot.get("certificates") or []:
        if not isinstance(record, dict) or not record.get("tracked") or not _text(record.get("id")):
            continue
        device_id = _text(record.get("device"))
        device = nodes.get(device_id) or {}
        label = _text(device.get("label")) or device_id
        kind = _text(record.get("kind")) or "certificate"
        tier = _text(record.get("tier")) or "unknown"
        noun = "CA" if kind == "authority" else "certificate"
        days = record.get("days_left")
        meta: dict[str, Any] = {
            "kind": kind,
            "common_name": _text(record.get("common_name")),
            "valid_to": _text(record.get("valid_to")),
            "days_left": days if isinstance(days, int) and not isinstance(days, bool) else None,
        }
        if device_id:
            meta["a"] = device_id
        found.append(
            EntityState(
                provider=provider,
                org_ref=org_ref,
                entity_type="certificate",
                entity_id=_text(record.get("id")),
                name=f"{label} {_text(record.get('name'))}".strip(),
                state=_CERTIFICATE_STATES.get(tier, "unknown"),
                raw_status=tier,
                site=site_name(_text(device.get("site"))) if device else "",
                model=_text(record.get("model")) or noun,
                host_id=_host_id(device),
                meta=meta,
            )
        )
    return found


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
                meta={k: node[k] for k in ("kind", "ip", "serial") if _text(node.get(k))} | traffic_meta(node),
                metrics=entity_metrics(node),
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
        meta = {"kind": _text(edge.get("kind")), "a": a_id, "b": b_id, **traffic_meta(edge)}
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
                metrics=entity_metrics(edge),
            )
        )

    for entity in ha_entity_states(provider, org_ref, snapshot, nodes, site_name):
        add(entity)

    for entity in certificate_entity_states(provider, org_ref, snapshot, nodes, site_name):
        add(entity)

    for service in snapshot.get("services") or []:
        if not isinstance(service, dict) or not _text(service.get("id")):
            continue
        raw = _text(service.get("status")).lower()
        # A service that runs on one device (an OPNsense firewall's unbound):
        # its host, and meta "a", so muting or removing the device covers it.
        device_id = _text(service.get("device"))
        meta = {k: _text(service.get(k)) for k in ("type", "kind", "region") if _text(service.get(k))}
        if device_id:
            meta["a"] = device_id
        add(
            EntityState(
                provider=provider,
                org_ref=org_ref,
                entity_type="service",
                entity_id=_text(service.get("id")),
                name=_text(service.get("name")) or _text(service.get("id")),
                state=node_state(raw),
                raw_status=_text(service.get("raw_status")) or raw,
                site=site_name(_text(service.get("site"))) if _text(service.get("site")) else "",
                model=_text(service.get("kind")),
                host_id=_host_id(nodes.get(device_id) or {}) if device_id else None,
                meta=meta,
            )
        )
    return found
