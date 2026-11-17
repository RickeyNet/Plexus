"""Managed cloud services with endpoints, the same way for every provider.

A managed service (an AWS RDS database or load balancer, an Azure load
balancer, application gateway or private endpoint) is not a node of the
Topology map: its network's details list it with its endpoints. The
collectors of each provider build its record's metadata with
``service_metadata`` and its endpoints with ``endpoint``; the normalizers
list the records of one network with ``service_sections``: a table per
service, then one "Service endpoints" table with a row per address, which
``netcontrol.integrations.meraki.subnets`` reads as hosts of the network.

Pure functions, no provider SDK.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from netcontrol.integrations.meraki.normalize import _STATUS_RANK, table_section

SERVICE_COLUMNS = [
    "Name",
    "Resource ID",
    "Kind",
    "Engine",
    "Version",
    "State",
    "Endpoints",
    "IP addresses",
    "Subnets",
    "Security groups",
    "Details",
]
# One row per address of every service resource of a network (an endpoint
# with none has one row with no address). ``netcontrol.integrations.meraki.subnets``
# reads it by these column names; the Service column names the host.
SERVICE_ENDPOINT_SECTION_TITLE = "Service endpoints"
SERVICE_ENDPOINT_COLUMNS = ["Service", "Name", "Resource ID", "Endpoint", "DNS name", "Port", "IP address"]


def _t(value: Any) -> str:
    # The Azure SDK answers some fields as str-mixin enums; their value is what the API says.
    if isinstance(value, Enum):
        value = value.value
    return str(value or "").strip()


# ── Records (collectors) ─────────────────────────────────────────────────────


def unique_addresses(*values: Any) -> list[str]:
    """The non-empty addresses among ``values`` (strings or lists of them), once each."""
    found: list[str] = []
    for value in values:
        for item in value if isinstance(value, list) else [value]:
            text = _t(item)
            if text and text not in found:
                found.append(text)
    return found


def endpoint(role: str, dns_name: Any = "", port: Any = None, addresses: Any = ()) -> dict | None:
    """One endpoint of a resource as ``{role, dns_name, port, ip_addresses}``
    (``port`` only when the provider gives one), or ``None`` when it has
    neither a name nor an address. ``addresses`` is a list of strings or of
    lists."""
    name = _t(dns_name)
    found = unique_addresses(*addresses) if isinstance(addresses, (list, tuple)) else unique_addresses(addresses)
    if not name and not found:
        return None
    record: dict[str, Any] = {"role": role, "dns_name": name}
    if isinstance(port, int) and not isinstance(port, bool) and port > 0:
        record["port"] = port
    record["ip_addresses"] = found
    return record


def service_metadata(
    resource_id: str,
    *,
    kind: str = "",
    engine: str = "",
    engine_version: str = "",
    vpc_id: str = "",
    subnet_ids: list[str] | None = None,
    security_group_ids: list[str] | None = None,
    endpoints: Iterable[dict | None] | None = None,
    network_interface_ids: list[str] | None = None,
    interfaces: list[dict] | None = None,
    public_ips: list[str] | None = None,
    **details: Any,
) -> dict:
    """The metadata of a service resource the map lists in its network's details.

    ``kind`` names what it is ("Application load balancer", "Private
    endpoint"); ``engine_version`` is the software version the provider
    reports. ``vpc_id`` is the network's id as the provider's subnets name
    it; a resource that names none is placed by its ``subnet_ids``.
    ``endpoints`` give the private addresses that are hosts of the network;
    ``public_ips`` are listed, not indexed as hosts. ``details`` are the
    service's own named fields."""
    return {
        "resource_id": resource_id,
        "kind": kind,
        "engine": engine,
        "engine_version": engine_version,
        "vpc_id": vpc_id,
        "subnet_ids": subnet_ids or [],
        "security_group_ids": security_group_ids or [],
        "endpoints": [e for e in endpoints or [] if e],
        "network_interface_ids": network_interface_ids or [],
        "interfaces": interfaces or [],
        "public_ips": public_ips or [],
        **details,
    }


def service_record(
    provider: str,
    uid: str,
    resource_type: str,
    resource_id: str,
    *,
    name: str = "",
    region: str = "",
    status: str = "",
    **fields: Any,
) -> dict:
    """The Cloud Visibility record of a service resource: ``uid`` and
    ``resource_type`` as the provider names them, ``fields`` as
    ``service_metadata`` takes them. The status is stored lower case."""
    return {
        "provider": provider,
        "resource_uid": uid,
        "resource_type": resource_type,
        "name": name or resource_id,
        "region": region,
        "cidr": "",
        "status": _t(status).lower(),
        "metadata": service_metadata(resource_id, **fields),
    }


# ── Availability (normalizers) ───────────────────────────────────────────────

# Service states that a provider's node vocabulary (its normaliser's
# ``_status``: ``online`` / ``unknown`` / ``offline``) does not read right.
# A database backing up or a load balancer being modified still serves; a
# private link connection reads ``approved`` / ``accepted``; a service
# starting, stopping or being created or deleted is in transition, not down.
# Anything else goes through the provider's ``_status``.
SERVICE_STATUS: dict[str, str] = {
    # Serving while the provider works on it.
    **dict.fromkeys(
        (
            "running",
            "runnable",
            "online_maintenance",
            "importing",
            "approved",
            "accepted",
            "backing-up",
            "snapshotting",
            "maintenance",
            "modifying",
            "updating",
            "upgrading",
            "upgradingengineversion",
            "updatingservicesoftware",
            "processing",
            "resizing",
            "renaming",
            "rotating-keys",
            "storage-optimization",
            "configuring-enhanced-monitoring",
            "configuring-iam-database-auth",
            "configuring-log-exports",
            "resetting-master-credentials",
        ),
        "online",
    ),
    # Serving, impaired.
    **dict.fromkeys(
        (
            "active_impaired",
            "impaired",
            "degraded",
            "healing",
            "repairing",
            "partial",
            "storage-full",
            "failing-over",
            "rebooting",
            "rebooting_broker",
            "rebooting cache cluster nodes",
            "needs_attention",
        ),
        "alerting",
    ),
    # In transition: no outage yet.
    **dict.fromkeys(
        ("creating", "starting", "stopping", "deleting", "pending", "status_unspecified", "unknown"),
        "unknown",
    ),
}
# Metadata fields holding the state of a service's private link connection
# (an Azure private endpoint's; a GCP PSC endpoint's is also its status).
SERVICE_CONNECTION_FIELDS = ("connection_state", "psc_connection_status")


def service_status(raw: Any, status: Callable[[Any], str]) -> str:
    """The node status (``online`` / ``alerting`` / ``unknown`` /
    ``offline``) of one raw service state, ``""`` when there is none.
    ``status`` is the provider normaliser's own ``_status``."""
    text = _t(raw).lower()
    if not text:
        return ""
    return SERVICE_STATUS.get(text) or status(text)


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def backend_health_status(health: Any) -> str:
    """The node status a load balancer's ``backend_health``
    (``{"healthy": n, "unhealthy": m}``) implies: ``offline`` when no
    backend is healthy and some are not, ``alerting`` when some are not,
    ``online`` when all are; ``""`` when it reports no backend."""
    if not isinstance(health, dict):
        return ""
    healthy, unhealthy = _count(health.get("healthy")), _count(health.get("unhealthy"))
    if unhealthy:
        return "alerting" if healthy else "offline"
    return "online" if healthy else ""


def service_states(
    services: Iterable[Service],
    resources: Iterable[dict],
    status: Callable[[Any], str],
    site_of: Callable[[dict], str],
) -> list[dict]:
    """What availability tracking follows of a provider's service resources
    (``netcontrol.integrations.availability``): one record per resource of
    a type of ``services`` that reports a state, with the worst of its own
    state, its private link connection's (``SERVICE_CONNECTION_FIELDS``)
    and its backends' health (``backend_health_status``), in the node
    vocabulary. ``resources`` are a normaliser's rows (``meta`` is their
    parsed metadata), ``status`` is its ``_status`` and ``site_of`` gives
    the site id (network) of a resource, ``""`` for none. A resource with
    no state at all (an AWS Classic Load Balancer) is left out."""
    labels = {s.resource_type: s.label for s in services}
    found: list[dict] = []
    for resource in resources:
        resource_type = _t(resource.get("resource_type"))
        uid = _t(resource.get("resource_uid"))
        if resource_type not in labels or not uid:
            continue
        meta = resource.get("meta") if isinstance(resource.get("meta"), dict) else resource.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        raw = _t(resource.get("status")).lower()
        parts = [raw] if raw else []
        statuses = [service_status(raw, status)]
        for key in SERVICE_CONNECTION_FIELDS:
            connection = _t(meta.get(key)).lower()
            if connection and connection != raw:
                parts.append(f"connection {connection}")
                statuses.append(service_status(connection, status))
        health = meta.get("backend_health", resource.get("backend_health"))
        statuses.append(backend_health_status(health))
        if isinstance(health, dict) and backend_health_status(health):
            healthy, unhealthy = _count(health.get("healthy")), _count(health.get("unhealthy"))
            parts.append(f"{healthy}/{healthy + unhealthy} backends healthy")
        statuses = [s for s in statuses if s]
        if not statuses:
            continue
        found.append(
            {
                "id": uid,
                "name": _t(resource.get("name")) or _t(meta.get("resource_id")) or uid,
                "type": resource_type,
                "kind": _t(meta.get("kind")) or labels[resource_type],
                "site": site_of(resource),
                "region": _t(resource.get("region")),
                "status": min(statuses, key=lambda s: _STATUS_RANK.get(s, 0)),
                "raw_status": "; ".join(parts),
            }
        )
    return sorted(found, key=lambda s: s["id"])


# ── Tables (normalizers) ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Service:
    """How a network's details list one resource type: in the table
    ``section`` (shared by the types of one service), named ``label`` when
    the resource gives no kind of its own, with ``details`` (caption,
    metadata key) in its Details cell."""

    resource_type: str
    label: str
    section: str
    details: tuple[tuple[str, str], ...] = ()


def endpoint_rows(meta: dict) -> tuple[list[tuple[str, str, Any, str]], list[str]]:
    """The ``(role, DNS name, port, address)`` rows of a resource's
    ``endpoints`` (one per address; an endpoint with none has one row with
    no address), then one per private address of its ``interfaces`` that no
    endpoint names; and every address listed, once each."""
    rows: list[tuple[str, str, Any, str]] = []
    listed: list[str] = []
    for item in meta.get("endpoints") or []:
        if not isinstance(item, dict):
            continue
        found = [_t(a) for a in item.get("ip_addresses") or [] if _t(a)]
        listed += found
        for address in found or [""]:
            rows.append((_t(item.get("role")), _t(item.get("dns_name")), item.get("port"), address))
    for interface in meta.get("interfaces") or []:
        if not isinstance(interface, dict):
            continue
        for address in interface.get("private_ips") or []:
            if _t(address) and _t(address) not in listed:
                listed.append(_t(address))
                rows.append((f"Network interface {_t(interface.get('id'))}", "", None, _t(address)))
    return rows, list(dict.fromkeys(listed))


def dns_names(meta: dict) -> list[str]:
    """``host:port`` (or ``host``) of every endpoint with a DNS name, once each."""
    names = []
    for item in meta.get("endpoints") or []:
        if isinstance(item, dict) and _t(item.get("dns_name")):
            port = item.get("port")
            names.append(f"{_t(item.get('dns_name'))}:{port}" if port else _t(item.get("dns_name")))
    return list(dict.fromkeys(names))


def service_counts(services: Iterable[Service], owned: dict[str, list[dict]]) -> list[tuple[str, Any]]:
    """Network overview rows: how many resources each service table lists."""
    counts: dict[str, int] = {}
    for service in services:
        if owned.get(service.resource_type):
            counts[service.section] = counts.get(service.section, 0) + len(owned[service.resource_type])
    return list(counts.items())


def service_sections(
    services: Iterable[Service],
    owned: dict[str, list[dict]],
    subnet_names: dict[str, str],
    max_rows: int,
    *,
    short: Callable[[str], str] = _t,
) -> list[dict | None]:
    """A table per service of one network, then the "Service endpoints"
    table with a row per address of all of them, which the subnet index
    reads as hosts of the network. ``owned`` holds the builder's items
    (``rid``, ``meta``, ``name``, ``status``) by resource type;
    ``subnet_names`` labels a subnet id, and ``short`` names a subnet or a
    security group the network does not label."""
    tables: dict[str, list[list[Any]]] = {}
    rows_of_endpoints: list[list[Any]] = []
    for service in services:
        rows = tables.setdefault(service.section, [])
        for resource in owned.get(service.resource_type, []):
            meta = resource["meta"]
            name = _t(resource.get("name")) or resource["rid"]
            kind = _t(meta.get("kind")) or service.label
            found, listed = endpoint_rows(meta)
            rows_of_endpoints += [
                [kind, name, resource["rid"], role, dns_name, port, address] for role, dns_name, port, address in found
            ]
            groups = meta.get("security_group_ids")
            rows.append(
                [
                    name,
                    resource["rid"],
                    kind,
                    meta.get("engine"),
                    meta.get("engine_version"),
                    resource.get("status"),
                    dns_names(meta),
                    list(dict.fromkeys([*listed, *[_t(a) for a in meta.get("public_ips") or []]])),
                    [subnet_names.get(_t(s)) or short(_t(s)) for s in meta.get("subnet_ids") or []],
                    [short(_t(g)) for g in groups] if isinstance(groups, list) else groups,
                    {caption: meta.get(key) for caption, key in service.details},
                ]
            )
    return [
        *[table_section(title, SERVICE_COLUMNS, rows[:max_rows]) for title, rows in tables.items()],
        table_section(SERVICE_ENDPOINT_SECTION_TITLE, SERVICE_ENDPOINT_COLUMNS, rows_of_endpoints[:max_rows]),
    ]
