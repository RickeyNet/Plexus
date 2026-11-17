"""Reshape Compute Engine API responses into Cloud Visibility records.

Pure functions: the Cloud Visibility GCP collector lists the resources with
``google-api-python-client`` and passes the items here. The Compute Engine
REST API answers with plain JSON dicts (camelCase keys) that name other
resources by self link, such as
``https://www.googleapis.com/compute/v1/projects/P/global/networks/N`` or
``.../projects/P/regions/R/subnetworks/S``. ``parse_link`` recovers the
project, region or zone and name from any of them, so a reference to a
resource of another project (a VPC peering, a Shared VPC host network, the
peer GCP gateway of an HA VPN tunnel) gets the uid that project's own
discovery gives it. A VPN tunnel is the one resource that carries a secret
(``sharedSecret``, ``sharedSecretHash``); it is never read.

Resource uids are ``gcp:<type>:<project>:[<region or zone>:]<name>``:
``gcp:vpc:<project>:<network>`` for a VPC network (networks are global),
``gcp:subnet:<project>:<region>:<name>`` for a subnet,
``gcp:instance:<project>:<zone>:<name>`` for a VM instance. A route is
``gcp:route:<project>:<name>`` and a VPC firewall rule
``gcp:firewall_policy:<project>:<name>``. A load balancer frontend
(forwarding rule) is ``gcp:load_balancer:<project>:[<region>:]<name>``, a
Private Service Connect endpoint ``gcp:psc_endpoint:...`` and a service
attachment ``gcp:service_attachment:<project>:<region>:<name>``; they are
service records (``netcontrol.integrations.cloud_services``), listed in
their network's details like the AWS services with endpoints. What follows ``gcp:<type>:`` is
unique across projects, so several accounts share one map.
"""

from __future__ import annotations

import re
from typing import Any

from netcontrol.integrations.cloud_services import endpoint, service_record
from netcontrol.integrations.gcp.normalize import (
    CLOUD_SQL_TYPE,
    DEFAULT_INTERNET_GATEWAY,
    LOAD_BALANCER_TYPE,
    MEMORYSTORE_REDIS_TYPE,
    PSC_ENDPOINT_TYPE,
    SERVICE_ATTACHMENT_TYPE,
    WARNING_TYPE,
)

PROVIDER = "gcp"

# Compute Engine collection of a self link -> record type of its uid.
_COLLECTIONS = {
    "networks": "vpc",
    "subnetworks": "subnet",
    "routers": "cloud_router",
    "vpnGateways": "ha_vpn_gateway",
    "targetVpnGateways": "target_vpn_gateway",
    "vpnTunnels": "vpn_tunnel",
    "externalVpnGateways": "external_vpn_gateway",
    "interconnectAttachments": "interconnect_attachment",
    "interconnects": "interconnect",
    "instances": "instance",
    "firewalls": "firewall_policy",
    "routes": "route",
    "firewallPolicies": "network_firewall_policy",
}
_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")


def _t(value: Any) -> str:
    return str(value or "").strip()


def _get(obj: Any, *path: str) -> Any:
    """``obj["a"]["b"]`` with ``None`` for any missing step."""
    for step in path:
        if obj is None:
            return None
        obj = obj.get(step) if isinstance(obj, dict) else getattr(obj, step, None)
    return obj


def _list(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _texts(value: Any) -> list[str]:
    return [t for t in dict.fromkeys(_t(v) for v in _list(value)) if t]


# ── Self links ───────────────────────────────────────────────────────────────


def parse_link(link: Any) -> dict[str, str]:
    """``https://www.googleapis.com/compute/v1/projects/P/regions/R/subnetworks/S``
    -> ``{"project": "P", "region": "R", "zone": "", "collection": "subnetworks", "name": "S"}``.
    A partial link (``global/networks/N``) or a bare name works too."""
    parts = [p for p in _t(link).split("?", 1)[0].split("/") if p]
    out = {"project": "", "region": "", "zone": "", "collection": "", "name": ""}
    if "projects" in parts:
        index = parts.index("projects")
        out["project"] = parts[index + 1] if index + 1 < len(parts) else ""
        rest = parts[index + 2 :]
    else:
        rest = parts[parts.index("compute") + 2 :] if "compute" in parts else parts
    while rest and rest[0] in ("global", "regions", "zones", "locations"):
        if rest[0] == "global":
            rest = rest[1:]
            continue
        if len(rest) > 1:
            if rest[0] == "regions":
                out["region"] = rest[1]
            elif rest[0] == "zones":
                out["zone"] = rest[1]
        rest = rest[2:]
    if len(rest) >= 2:
        out["collection"], out["name"] = rest[0], rest[1]
    elif len(rest) == 1:
        out["name"] = rest[0]
    return out


def link_name(link: Any) -> str:
    return parse_link(link)["name"]


def link_scope(link: Any) -> str:
    """The region or zone a self link names (``""`` for a global resource)."""
    parts = parse_link(link)
    return parts["region"] or parts["zone"]


def link_uid(link: Any, project: str = "", kind: str = "") -> str:
    """The Cloud Visibility uid of the resource a self link names, or ``""``
    for a kind the map does not keep. The project of the link wins over
    ``project`` (a peering can name another one)."""
    parts = parse_link(link)
    kind = kind or _COLLECTIONS.get(parts["collection"], "")
    project = parts["project"] or project
    if not kind or not project or not parts["name"]:
        return ""
    scope = parts["region"] or parts["zone"]
    return f"gcp:{kind}:{project}:{scope}:{parts['name']}" if scope else f"gcp:{kind}:{project}:{parts['name']}"


def rid_of(uid: str) -> str:
    """``gcp:vpc:P:hub`` -> ``P:hub``: the part that identifies the resource."""
    parts = uid.split(":", 2)
    return parts[2] if len(parts) == 3 else uid


def _rid_link(link: Any, project: str, kind: str = "") -> str:
    uid = link_uid(link, project, kind)
    return rid_of(uid) if uid else ""


def _resource(
    uid: str, resource_type: str, *, name: str, region: str, cidr: str = "", status: str = "", metadata: dict
) -> dict:
    return {
        "provider": PROVIDER,
        "resource_uid": uid,
        "resource_type": resource_type,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": metadata,
    }


def _connection(source: str, target: str, kind: str, *, state: str = "", metadata: dict | None = None) -> dict:
    return {
        "provider": PROVIDER,
        "source_resource_uid": source,
        "target_resource_uid": target,
        "connection_type": kind,
        "state": state,
        "metadata": metadata or {},
    }


def _own_uid(item: dict, kind: str, project: str, scope: str = "") -> tuple[str, str, str]:
    """``(uid, project, name)`` of an item, from its self link when it has one."""
    name = _t(_get(item, "name"))
    uid = link_uid(_get(item, "selfLink"), project, kind) if _t(_get(item, "selfLink")) else ""
    if not uid and name:
        uid = f"gcp:{kind}:{project}:{scope}:{name}" if scope else f"gcp:{kind}:{project}:{name}"
    owner = parse_link(_get(item, "selfLink"))["project"] or project
    return uid, owner, name or link_name(_get(item, "selfLink"))


def error_code(exc: BaseException) -> str:
    """The HTTP status and error reason of a failed call (``forbidden (HTTP
    403)``), else the HTTP status, else the exception type. Never the message."""
    status = _get(exc, "status_code")
    if not isinstance(status, int):
        status = _get(exc, "resp", "status")
    try:
        status = int(status) if status not in (None, "") else None
    except TypeError, ValueError:
        status = None
    reason = ""
    for detail in _list(_get(exc, "error_details")):
        candidate = _t(_get(detail, "reason"))
        if _REASON.match(candidate):
            reason = candidate
            break
    if status is not None:
        return f"{reason} (HTTP {status})" if reason else f"HTTP {status}"
    return type(exc).__name__


def warning_resource(section: str, exc: BaseException, permissions: Any = ()) -> dict:
    """Record of a detail section that could not be read, stored with the
    discovery so the map's report can say what is missing and why;
    ``permissions`` are the IAM permissions the section needs."""
    metadata: dict[str, Any] = {"section": section, "error": error_code(exc)}
    if _texts(permissions):
        metadata["permissions"] = _texts(permissions)
    return _resource(
        f"gcp:{WARNING_TYPE}:{section}",
        WARNING_TYPE,
        name=section,
        region="",
        status="skipped",
        metadata=metadata,
    )


# ── VPC networks and subnets ─────────────────────────────────────────────────


def _peering(peering: dict, project: str) -> dict:
    return {
        "name": _t(peering.get("name")),
        "network_id": _rid_link(peering.get("network"), project, "vpc"),
        "state": _t(peering.get("state")),
        "state_details": _t(peering.get("stateDetails")),
        "export_custom_routes": bool(peering.get("exportCustomRoutes")),
        "import_custom_routes": bool(peering.get("importCustomRoutes")),
        "export_subnet_routes_with_public_ip": bool(peering.get("exportSubnetRoutesWithPublicIp", True)),
        "import_subnet_routes_with_public_ip": bool(peering.get("importSubnetRoutesWithPublicIp")),
        "stack_type": _t(peering.get("stackType")),
    }


def network_resource(network: dict, project: str) -> dict | None:
    """A VPC network with its routing mode, subnet mode, peerings and the
    network firewall policy associated with it."""
    uid, owner, name = _own_uid(network, "vpc", project)
    if not name:
        return None
    if network.get("IPv4Range"):
        mode = "legacy"
    else:
        mode = "auto" if network.get("autoCreateSubnetworks") else "custom"
    return _resource(
        uid,
        "vpc",
        name=name,
        region="global",
        # Only a legacy network has a range of its own; the others have subnets.
        cidr=_t(network.get("IPv4Range")),
        status="active",
        metadata={
            "project": owner,
            "network_id": rid_of(uid),
            "routing_mode": _t(_get(network, "routingConfig", "routingMode")) or "REGIONAL",
            "subnet_mode": mode,
            "mtu": network.get("mtu"),
            "description": _t(network.get("description")),
            "subnet_count": len(_list(network.get("subnetworks"))),
            "firewall_policy": _t(network.get("firewallPolicy")),
            "firewall_policy_enforcement_order": _t(network.get("networkFirewallPolicyEnforcementOrder")),
            "peerings": [_peering(p, project) for p in _list(network.get("peerings")) if isinstance(p, dict)],
        },
    )


def peering_connections(network: dict, project: str) -> list[dict]:
    """The peerings of a VPC network, as connections to the peered network."""
    uid = _own_uid(network, "vpc", project)[0]
    found: list[dict] = []
    for raw in _list(network.get("peerings")):
        if not isinstance(raw, dict):
            continue
        peer = link_uid(raw.get("network"), project, "vpc")
        if not uid or not peer:
            continue
        peering = _peering(raw, project)
        found.append(
            _connection(
                uid,
                peer,
                "vpc_peering",
                state=peering["state"],
                metadata={"peering_name": peering["name"], **{k: v for k, v in peering.items() if k != "name"}},
            )
        )
    return found


def subnet_resource(subnet: dict, project: str) -> dict | None:
    """A subnet with its primary and secondary ranges and the network it is in."""
    region = link_scope(subnet.get("region")) or _t(subnet.get("region"))
    uid, owner, name = _own_uid(subnet, "subnet", project, region)
    if not name:
        return None
    network_id = _rid_link(subnet.get("network"), project, "vpc")
    return _resource(
        uid,
        "subnet",
        name=name,
        region=region,
        cidr=_t(subnet.get("ipCidrRange")),
        status=_t(subnet.get("state")) or "active",
        metadata={
            "project": owner,
            "subnet_name": name,
            "region": region,
            "network_id": network_id,
            "network_name": network_id.rsplit(":", 1)[-1],
            "secondary_ranges": [
                {"name": _t(r.get("rangeName")), "cidr": _t(r.get("ipCidrRange"))}
                for r in _list(subnet.get("secondaryIpRanges"))
                if isinstance(r, dict) and _t(r.get("ipCidrRange"))
            ],
            "private_google_access": bool(subnet.get("privateIpGoogleAccess")),
            "purpose": _t(subnet.get("purpose")) or "PRIVATE",
            "role": _t(subnet.get("role")),
            "stack_type": _t(subnet.get("stackType")) or "IPV4_ONLY",
            "gateway_address": _t(subnet.get("gatewayAddress")),
            "ipv6_cidr": _t(subnet.get("ipv6CidrRange")) or _t(subnet.get("externalIpv6Prefix")),
            "flow_logs": bool(_get(subnet, "logConfig", "enable")),
        },
    )


def subnet_attachment(subnet_resource_record: dict) -> dict | None:
    """The connection that places a subnet in its network."""
    network_id = _t((subnet_resource_record.get("metadata") or {}).get("network_id"))
    if not network_id:
        return None
    return _connection(
        f"gcp:vpc:{network_id}",
        subnet_resource_record["resource_uid"],
        "subnet_attachment",
        state="attached",
        metadata={"region": subnet_resource_record.get("region") or ""},
    )


# ── Routes ───────────────────────────────────────────────────────────────────

# Route field -> next hop kind, in the order GCP lets one be set.
_NEXT_HOPS = (
    ("nextHopGateway", "gateway"),
    ("nextHopIp", "ip"),
    ("nextHopInstance", "instance"),
    ("nextHopIlb", "ilb"),
    ("nextHopVpnTunnel", "vpn_tunnel"),
    ("nextHopInterconnectAttachment", "interconnect_attachment"),
    ("nextHopPeering", "peering"),
    ("nextHopNetwork", "network"),
    ("nextHopHub", "hub"),
)
_NEXT_HOP_KINDS = {
    "instance": "instance",
    "vpn_tunnel": "vpn_tunnel",
    "interconnect_attachment": "interconnect_attachment",
    "network": "vpc",
}


def route_next_hop(route: dict, project: str) -> dict:
    """Which next hop a route has: ``type`` (one of ``_NEXT_HOPS``), the raw
    ``target`` and, for a resource the map keeps, its ``rid``."""
    for field, kind in _NEXT_HOPS:
        target = _t(route.get(field))
        if not target:
            continue
        rid = ""
        if kind in _NEXT_HOP_KINDS:
            rid = _rid_link(target, project, _NEXT_HOP_KINDS[kind])
        elif kind == "gateway":
            rid = link_name(target)
        elif kind == "ilb" and "/" in target:
            rid = link_name(target)
        return {"type": kind, "target": target, "rid": rid}
    return {"type": "", "target": "", "rid": ""}


def route_resource(route: dict, project: str) -> dict | None:
    """A route of a VPC network with everything needed to evaluate it."""
    name = _t(route.get("name"))
    if not name:
        return None
    owner = parse_link(route.get("selfLink"))["project"] or project
    network_id = _rid_link(route.get("network"), project, "vpc")
    hop = route_next_hop(route, project)
    return _resource(
        f"gcp:route:{owner}:{name}",
        "route_entry",
        name=name,
        region="global",
        cidr=_t(route.get("destRange")),
        status="active",
        metadata={
            "project": owner,
            "network": network_id.rsplit(":", 1)[-1],
            "network_id": network_id,
            "priority": route.get("priority"),
            "tags": _texts(route.get("tags")),
            # The next hop as one text (what Cloud Visibility listed before).
            "next_hop": link_name(hop["target"]) if hop["type"] != "ip" else hop["target"],
            "next_hop_type": hop["type"],
            "next_hop_target": hop["target"],
            "next_hop_id": hop["rid"],
            "route_type": _t(route.get("routeType")),
            "description": _t(route.get("description")),
        },
    )


def internet_gateway_resource(route_record: dict) -> dict | None:
    """The default internet gateway of the network a route sends there: one
    per network, so the map can draw one per VPC."""
    meta = route_record.get("metadata") or {}
    if meta.get("next_hop_type") != "gateway" or meta.get("next_hop_id") != DEFAULT_INTERNET_GATEWAY:
        return None
    network_id = _t(meta.get("network_id"))
    if not network_id:
        return None
    return _resource(
        f"gcp:internet_gateway:{network_id}",
        "internet_gateway",
        name=DEFAULT_INTERNET_GATEWAY,
        region="global",
        status="active",
        metadata={"project": network_id.split(":", 1)[0], "network_id": network_id},
    )


def route_connections(route_record: dict) -> list[dict]:
    """The route in its network, and to the resource it hands traffic to."""
    meta = route_record.get("metadata") or {}
    network_id = _t(meta.get("network_id"))
    uid = route_record["resource_uid"]
    found: list[dict] = []
    if network_id:
        found.append(_connection(f"gcp:vpc:{network_id}", uid, "route_table_association", state="active"))
    target = ""
    kind, rid = _t(meta.get("next_hop_type")), _t(meta.get("next_hop_id"))
    if kind == "gateway" and rid == DEFAULT_INTERNET_GATEWAY and network_id:
        target = f"gcp:internet_gateway:{network_id}"
    elif kind in _NEXT_HOP_KINDS and rid:
        target = f"gcp:{_NEXT_HOP_KINDS[kind]}:{rid}"
    if target:
        found.append(
            _connection(uid, target, "route_next_hop", state="active", metadata={"destination": route_record["cidr"]})
        )
        if target.startswith("gcp:internet_gateway:"):
            found.append(_connection(f"gcp:vpc:{network_id}", target, "internet_gateway_attachment", state="attached"))
    return found


# ── VPC firewall rules ───────────────────────────────────────────────────────


def _join(values: list[str]) -> str:
    return ", ".join(dict.fromkeys(v for v in values if v))


def firewall_rules(fw: dict, *, resource_uid: str) -> list[dict]:
    """The rules of a VPC firewall rule, one per allowed or denied protocol,
    in the policy rule format Cloud Visibility stores."""
    rules: list[dict] = []
    direction = str(fw.get("direction") or "INGRESS").strip().lower()
    if direction == "ingress":
        normalized_direction = "inbound"
    elif direction == "egress":
        normalized_direction = "outbound"
    else:
        normalized_direction = direction

    source_selector = _join([str(item or "").strip() for item in (fw.get("sourceRanges") or [])])
    destination_selector = _join([str(item or "").strip() for item in (fw.get("destinationRanges") or [])])
    if not source_selector:
        source_selector = "any" if normalized_direction == "inbound" else "self"
    if not destination_selector:
        destination_selector = "any" if normalized_direction == "outbound" else "self"

    entries: list[tuple[str, dict]] = []
    for action, key in (("allow", "allowed"), ("deny", "denied")):
        for item in fw.get(key, []) or []:
            entries.append((action, item))
    if not entries:
        entries.append(("allow", {}))

    for idx, (action, item) in enumerate(entries):
        protocol = str(item.get("IPProtocol") or "all").strip().lower() or "all"
        ports = _join([str(port or "").strip() for port in (item.get("ports") or [])]) or "all"
        rules.append(
            {
                "rule_uid": f"{resource_uid}:{action}:{idx + 1}",
                "rule_name": str(fw.get("name") or "firewall-rule").strip(),
                "direction": normalized_direction,
                "action": action,
                "protocol": protocol,
                "source_selector": source_selector,
                "destination_selector": destination_selector,
                "port_expression": ports,
                "priority": fw.get("priority"),
                "metadata": {
                    "disabled": bool(fw.get("disabled", False)),
                    "target_tags": [str(tag).strip() for tag in (fw.get("targetTags") or []) if str(tag).strip()],
                },
            }
        )
    return rules


def _protocols(items: Any) -> list[dict]:
    return [
        {"protocol": _t(item.get("IPProtocol")).lower() or "all", "ports": _texts(item.get("ports"))}
        for item in _list(items)
        if isinstance(item, dict)
    ]


def firewall_resource(fw: dict, project: str) -> dict | None:
    """A VPC firewall rule: its policy rules for Cloud Visibility and the
    fields Path Mode evaluates (targets, sources, priority, state)."""
    uid_name = _t(fw.get("name"))
    if not uid_name:
        return None
    owner = parse_link(fw.get("selfLink"))["project"] or project
    uid = f"gcp:firewall_policy:{owner}:{uid_name}"
    network_id = _rid_link(fw.get("network"), project, "vpc")
    return _resource(
        uid,
        "firewall_policy",
        name=uid_name,
        region="global",
        status="disabled" if fw.get("disabled") else "active",
        metadata={
            "project": owner,
            "network": network_id.rsplit(":", 1)[-1],
            "network_id": network_id,
            "direction": _t(fw.get("direction")).upper() or "INGRESS",
            "priority": fw.get("priority") if fw.get("priority") is not None else 1000,
            "disabled": bool(fw.get("disabled")),
            "allowed": _protocols(fw.get("allowed")),
            "denied": _protocols(fw.get("denied")),
            "source_ranges": _texts(fw.get("sourceRanges")),
            "destination_ranges": _texts(fw.get("destinationRanges")),
            "source_tags": _texts(fw.get("sourceTags")),
            "target_tags": _texts(fw.get("targetTags")),
            "source_service_accounts": _texts(fw.get("sourceServiceAccounts")),
            "target_service_accounts": _texts(fw.get("targetServiceAccounts")),
            "logging": bool(_get(fw, "logConfig", "enable")),
            "description": _t(fw.get("description")),
            "policy_rules": firewall_rules(fw, resource_uid=uid),
        },
    )


def firewall_attachment(fw_record: dict) -> dict | None:
    network_id = _t((fw_record.get("metadata") or {}).get("network_id"))
    if not network_id:
        return None
    return _connection(f"gcp:vpc:{network_id}", fw_record["resource_uid"], "security_boundary", state="enforced")


def network_firewall_policy_resource(policy: dict, project: str) -> dict | None:
    """A network firewall policy (global or regional). Its rules are not
    evaluated; the networks it is associated with are recorded so Path Mode
    can say that their firewall is not fully known."""
    region = link_scope(policy.get("region")) or link_scope(policy.get("selfLink"))
    uid, owner, name = _own_uid(policy, "network_firewall_policy", project, region)
    if not name:
        return None
    associations = [a for a in _list(policy.get("associations")) if isinstance(a, dict)]
    return _resource(
        uid,
        "network_firewall_policy",
        name=name,
        region=region or "global",
        status="active",
        metadata={
            "project": owner,
            "network_ids": [
                rid for rid in (_rid_link(a.get("attachmentTarget"), project, "vpc") for a in associations) if rid
            ],
            "rule_count": len(_list(policy.get("rules"))),
            "description": _t(policy.get("description")),
        },
    )


# ── Cloud Router, Cloud NAT and the routes BGP learns ────────────────────────


def _nat_scope(value: str) -> str:
    return {
        "ALL_SUBNETWORKS_ALL_IP_RANGES": "all",
        "ALL_SUBNETWORKS_ALL_PRIMARY_IP_RANGES": "primary",
        "LIST_OF_SUBNETWORKS": "list",
    }.get(value, value.lower())


def _nats(router: dict, status: dict, project: str) -> list[dict]:
    status_by_name = {
        _t(s.get("name")): s for s in _list(_get(status, "natStatus")) if isinstance(s, dict) and _t(s.get("name"))
    }
    found: list[dict] = []
    for nat in _list(router.get("nats")):
        if not isinstance(nat, dict) or not _t(nat.get("name")):
            continue
        name = _t(nat.get("name"))
        state = status_by_name.get(name, {})
        found.append(
            {
                "name": name,
                "scope": _nat_scope(_t(nat.get("sourceSubnetworkIpRangesToNat"))),
                "subnets": [
                    {
                        "subnet_id": _rid_link(s.get("name"), project, "subnet"),
                        "ranges": _texts(s.get("sourceIpRangesToNat")) or ["ALL_IP_RANGES"],
                        "secondary_ranges": _texts(s.get("secondaryIpRangeNames")),
                    }
                    for s in _list(nat.get("subnetworks"))
                    if isinstance(s, dict)
                ],
                "allocation": _t(nat.get("natIpAllocateOption")),
                "nat_ip_names": [link_name(ip) for ip in _list(nat.get("natIps")) if link_name(ip)],
                "nat_ips": _texts([*_list(state.get("userAllocatedNatIps")), *_list(state.get("autoAllocatedNatIps"))]),
            }
        )
    return found


def _learned(route: dict, project: str, peers: list[dict], interfaces: list[dict]) -> dict:
    """A route the router learned over BGP, with the tunnel or attachment it goes over."""
    next_hop = _t(route.get("nextHopIp"))
    peer = next((p for p in peers if next_hop and p["peer_ip"] == next_hop), None)
    interface = next((i for i in interfaces if peer and i["name"] == peer["interface"]), None) or {}
    tunnel = _rid_link(route.get("nextHopVpnTunnel"), project, "vpn_tunnel") or _t(interface.get("vpn_tunnel"))
    attachment = _rid_link(route.get("nextHopInterconnectAttachment"), project, "interconnect_attachment") or _t(
        interface.get("interconnect_attachment")
    )
    return {
        "prefix": _t(route.get("destRange")),
        "next_hop_ip": next_hop,
        "priority": route.get("priority"),
        "peer": peer["name"] if peer else "",
        "vpn_tunnel": tunnel,
        "interconnect_attachment": attachment,
    }


def router_resource(router: dict, project: str, status: dict | None = None) -> dict | None:
    """A Cloud Router with its BGP sessions, Cloud NAT configurations and,
    when ``routers.getRouterStatus`` was read (``status`` is its
    ``result``), the state of each session and the routes it learned."""
    region = link_scope(router.get("region")) or _t(router.get("region"))
    uid, owner, name = _own_uid(router, "cloud_router", project, region)
    if not name:
        return None
    status = status if isinstance(status, dict) else {}
    peer_status = {
        _t(s.get("name")): s for s in _list(status.get("bgpPeerStatus")) if isinstance(s, dict) and _t(s.get("name"))
    }
    interfaces = [
        {
            "name": _t(i.get("name")),
            "ip_range": _t(i.get("ipRange")),
            "vpn_tunnel": _rid_link(i.get("linkedVpnTunnel"), project, "vpn_tunnel"),
            "interconnect_attachment": _rid_link(
                i.get("linkedInterconnectAttachment"), project, "interconnect_attachment"
            ),
        }
        for i in _list(router.get("interfaces"))
        if isinstance(i, dict)
    ]
    peers = []
    for peer in _list(router.get("bgpPeers")):
        if not isinstance(peer, dict):
            continue
        state = peer_status.get(_t(peer.get("name")), {})
        peers.append(
            {
                "name": _t(peer.get("name")),
                "interface": _t(peer.get("interfaceName")),
                "ip": _t(peer.get("ipAddress")),
                "peer_ip": _t(peer.get("peerIpAddress")),
                "peer_asn": peer.get("peerAsn"),
                "advertised_route_priority": peer.get("advertisedRoutePriority"),
                "enabled": _t(peer.get("enable")).upper() != "FALSE",
                "status": _t(state.get("status")),
                "state": _t(state.get("state")),
                "uptime": _t(state.get("uptime")),
                "learned_routes": state.get("numLearnedRoutes"),
            }
        )
    best = _list(status.get("bestRoutes")) or _list(status.get("bestRoutesForRouter"))
    learned = [_learned(r, project, peers, interfaces) for r in best if isinstance(r, dict) and _t(r.get("destRange"))]
    network_id = _rid_link(router.get("network"), project, "vpc")
    return _resource(
        uid,
        "cloud_router",
        name=name,
        region=region,
        status="running",
        metadata={
            "project": owner,
            "region": region,
            "network_id": network_id,
            "network_name": network_id.rsplit(":", 1)[-1],
            "bgp_asn": _get(router, "bgp", "asn"),
            "advertise_mode": _t(_get(router, "bgp", "advertiseMode")) or "DEFAULT",
            "advertised_groups": _texts(_get(router, "bgp", "advertisedGroups")),
            "advertised_ip_ranges": [
                _t(r.get("range")) for r in _list(_get(router, "bgp", "advertisedIpRanges")) if isinstance(r, dict)
            ],
            "interfaces": interfaces,
            "bgp_peers": peers,
            "nats": _nats(router, status, project),
            "status_collected": bool(status),
            "learned_routes": learned,
        },
    )


def router_attachment(router_record: dict) -> dict | None:
    network_id = _t((router_record.get("metadata") or {}).get("network_id"))
    if not network_id:
        return None
    return _connection(f"gcp:vpc:{network_id}", router_record["resource_uid"], "router_attachment", state="up")


# ── VPN ──────────────────────────────────────────────────────────────────────


def _interfaces(items: Any) -> list[dict]:
    return [
        {"id": i.get("id"), "ip_address": _t(i.get("ipAddress"))}
        for i in _list(items)
        if isinstance(i, dict) and _t(i.get("ipAddress"))
    ]


def ha_vpn_gateway_resource(gateway: dict, project: str) -> dict | None:
    """An HA VPN gateway with the public address of each of its interfaces."""
    region = link_scope(gateway.get("region")) or _t(gateway.get("region"))
    uid, owner, name = _own_uid(gateway, "ha_vpn_gateway", project, region)
    if not name:
        return None
    interfaces = _interfaces(gateway.get("vpnInterfaces"))
    network_id = _rid_link(gateway.get("network"), project, "vpc")
    return _resource(
        uid,
        "ha_vpn_gateway",
        name=name,
        region=region,
        status="up",
        metadata={
            "project": owner,
            "region": region,
            "network_id": network_id,
            "interfaces": interfaces,
            "public_ips": [i["ip_address"] for i in interfaces],
            "stack_type": _t(gateway.get("stackType")),
        },
    )


def target_vpn_gateway_resource(gateway: dict, project: str) -> dict | None:
    """A Classic VPN gateway."""
    region = link_scope(gateway.get("region")) or _t(gateway.get("region"))
    uid, owner, name = _own_uid(gateway, "target_vpn_gateway", project, region)
    if not name:
        return None
    return _resource(
        uid,
        "target_vpn_gateway",
        name=name,
        region=region,
        status=_t(gateway.get("status")) or "up",
        metadata={
            "project": owner,
            "region": region,
            "network_id": _rid_link(gateway.get("network"), project, "vpc"),
            "tunnel_ids": [
                rid for rid in (_rid_link(t, project, "vpn_tunnel") for t in _list(gateway.get("tunnels"))) if rid
            ],
        },
    )


def vpn_gateway_attachment(gateway_record: dict) -> dict | None:
    network_id = _t((gateway_record.get("metadata") or {}).get("network_id"))
    if not network_id:
        return None
    return _connection(f"gcp:vpc:{network_id}", gateway_record["resource_uid"], "vpn_gateway_attachment", state="up")


def external_vpn_gateway_resource(gateway: dict, project: str) -> dict | None:
    """The far end of an HA VPN as configured in GCP: an on-premises or
    other-cloud gateway and the public address of each of its interfaces."""
    uid, owner, name = _own_uid(gateway, "external_vpn_gateway", project)
    if not name:
        return None
    interfaces = _interfaces(gateway.get("interfaces"))
    return _resource(
        uid,
        "external_vpn_gateway",
        name=name,
        region="global",
        status="active",
        metadata={
            "project": owner,
            "redundancy_type": _t(gateway.get("redundancyType")),
            "interfaces": interfaces,
            "public_ips": [i["ip_address"] for i in interfaces],
            "description": _t(gateway.get("description")),
        },
    )


def vpn_tunnel_resource(tunnel: dict, project: str) -> dict | None:
    """A VPN tunnel. The shared secret and its hash are not read."""
    region = link_scope(tunnel.get("region")) or _t(tunnel.get("region"))
    uid, owner, name = _own_uid(tunnel, "vpn_tunnel", project, region)
    if not name:
        return None
    ha = bool(_t(tunnel.get("vpnGateway")))
    return _resource(
        uid,
        "vpn_tunnel",
        name=name,
        region=region,
        status=_t(tunnel.get("status")),
        metadata={
            "project": owner,
            "region": region,
            "peer_ip": _t(tunnel.get("peerIp")),
            "detailed_status": _t(tunnel.get("detailedStatus")),
            "ike_version": tunnel.get("ikeVersion"),
            "gateway_type": "ha" if ha else "classic",
            "gateway_id": _rid_link(tunnel.get("vpnGateway"), project, "ha_vpn_gateway")
            or _rid_link(tunnel.get("targetVpnGateway"), project, "target_vpn_gateway"),
            "gateway_interface": tunnel.get("vpnGatewayInterface"),
            "peer_external_gateway": _rid_link(tunnel.get("peerExternalGateway"), project, "external_vpn_gateway"),
            "peer_external_gateway_interface": tunnel.get("peerExternalGatewayInterface"),
            "peer_gcp_gateway": _rid_link(tunnel.get("peerGcpGateway"), project, "ha_vpn_gateway"),
            "router_id": _rid_link(tunnel.get("router"), project, "cloud_router"),
            "local_traffic_selector": _texts(tunnel.get("localTrafficSelector")),
            "remote_traffic_selector": _texts(tunnel.get("remoteTrafficSelector")),
        },
    )


def vpn_tunnel_connections(tunnel_record: dict) -> list[dict]:
    """The tunnel as a connection from the tunnel to the far end (the
    external VPN gateway, the peer GCP gateway, or the bare peer address;
    the metadata names the tunnel's own gateway), and from the tunnel to
    its Cloud Router. A connection is keyed by its two ends, so the two
    tunnels of an HA VPN between the same gateways stay two connections."""
    meta = tunnel_record.get("metadata") or {}
    project = _t(meta.get("project"))
    gateway_kind = "ha_vpn_gateway" if meta.get("gateway_type") == "ha" else "target_vpn_gateway"
    found: list[dict] = []
    if meta.get("peer_external_gateway"):
        far = f"gcp:external_vpn_gateway:{meta['peer_external_gateway']}"
    elif meta.get("peer_gcp_gateway"):
        far = f"gcp:ha_vpn_gateway:{meta['peer_gcp_gateway']}"
    elif meta.get("peer_ip"):
        far = f"gcp:vpn_peer:{project}:{meta['peer_ip']}"
    else:
        far = ""
    if meta.get("gateway_id") and far:
        found.append(
            _connection(
                tunnel_record["resource_uid"],
                far,
                "vpn_tunnel",
                state=_t(tunnel_record.get("status")),
                metadata={
                    "name": tunnel_record.get("name") or "",
                    "tunnel_id": rid_of(tunnel_record["resource_uid"]),
                    "gateway": f"gcp:{gateway_kind}:{meta['gateway_id']}",
                    "status": _t(tunnel_record.get("status")),
                    "detailed_status": meta.get("detailed_status") or "",
                    "peer_ip": meta.get("peer_ip") or "",
                    "ike_version": meta.get("ike_version"),
                    "gateway_interface": meta.get("gateway_interface"),
                    "router_id": meta.get("router_id") or "",
                },
            )
        )
    if meta.get("router_id"):
        found.append(
            _connection(
                tunnel_record["resource_uid"],
                f"gcp:cloud_router:{meta['router_id']}",
                "router_attachment",
                state=_t(tunnel_record.get("status")),
            )
        )
    return found


# ── Interconnect ─────────────────────────────────────────────────────────────


def interconnect_attachment_resource(attachment: dict, project: str) -> dict | None:
    """A VLAN attachment of a Dedicated or Partner Interconnect, with its Cloud Router."""
    region = link_scope(attachment.get("region")) or _t(attachment.get("region"))
    uid, owner, name = _own_uid(attachment, "interconnect_attachment", project, region)
    if not name:
        return None
    return _resource(
        uid,
        "interconnect_attachment",
        name=name,
        region=region,
        status=_t(attachment.get("operationalStatus")) or _t(attachment.get("state")),
        metadata={
            "project": owner,
            "region": region,
            "type": _t(attachment.get("type")),
            "bandwidth": _t(attachment.get("bandwidth")),
            "state": _t(attachment.get("state")),
            "operational_status": _t(attachment.get("operationalStatus")),
            "admin_enabled": attachment.get("adminEnabled") is not False,
            "router_id": _rid_link(attachment.get("router"), project, "cloud_router"),
            "vlan": attachment.get("vlanTag8021q"),
            "interconnect_id": _rid_link(attachment.get("interconnect"), project, "interconnect"),
            "interconnect_name": link_name(attachment.get("interconnect"))
            or _t(_get(attachment, "partnerMetadata", "interconnectName")),
            "partner": _t(_get(attachment, "partnerMetadata", "partnerName")),
            "cloud_router_ip": _t(attachment.get("cloudRouterIpAddress")),
            "customer_router_ip": _t(attachment.get("customerRouterIpAddress")),
            "edge_availability_domain": _t(attachment.get("edgeAvailabilityDomain")),
            "mtu": attachment.get("mtu"),
        },
    )


def interconnect_attachment_connections(attachment_record: dict) -> list[dict]:
    meta = attachment_record.get("metadata") or {}
    uid, state = attachment_record["resource_uid"], _t(attachment_record.get("status"))
    found: list[dict] = []
    if meta.get("router_id"):
        found.append(_connection(f"gcp:cloud_router:{meta['router_id']}", uid, "interconnect_attachment", state=state))
    if meta.get("interconnect_id"):
        found.append(_connection(uid, f"gcp:interconnect:{meta['interconnect_id']}", "interconnect_link", state=state))
    return found


def interconnect_resource(interconnect: dict, project: str) -> dict | None:
    """A Dedicated Interconnect: the physical connection to Google."""
    uid, owner, name = _own_uid(interconnect, "interconnect", project)
    if not name:
        return None
    return _resource(
        uid,
        "interconnect",
        name=name,
        region="global",
        status=_t(interconnect.get("operationalStatus")) or _t(interconnect.get("state")),
        metadata={
            "project": owner,
            "type": _t(interconnect.get("interconnectType")),
            "link_type": _t(interconnect.get("linkType")),
            "requested_link_count": interconnect.get("requestedLinkCount"),
            "provisioned_link_count": interconnect.get("provisionedLinkCount"),
            "location": link_name(interconnect.get("location")),
            "state": _t(interconnect.get("state")),
            "admin_enabled": interconnect.get("adminEnabled") is not False,
        },
    )


# ── VM instances ─────────────────────────────────────────────────────────────


def _instance_interface(nic: dict, project: str) -> dict:
    external = [
        _t(c.get("natIP")) for c in _list(nic.get("accessConfigs")) if isinstance(c, dict) and _t(c.get("natIP"))
    ]
    return {
        "name": _t(nic.get("name")),
        "network_id": _rid_link(nic.get("network"), project, "vpc"),
        "subnet_id": _rid_link(nic.get("subnetwork"), project, "subnet"),
        "private_ips": [_t(nic.get("networkIP"))] if _t(nic.get("networkIP")) else [],
        "alias_ranges": [
            _t(r.get("ipCidrRange"))
            for r in _list(nic.get("aliasIpRanges"))
            if isinstance(r, dict) and _t(r.get("ipCidrRange"))
        ],
        "public_ips": list(dict.fromkeys(external)),
        "stack_type": _t(nic.get("stackType")),
    }


def instance_resource(instance: dict, project: str) -> dict | None:
    """A VM instance with every network interface. ``nic0`` gives the
    instance its VPC, subnet and primary address."""
    zone = link_scope(instance.get("zone")) or _t(instance.get("zone"))
    uid, owner, name = _own_uid(instance, "instance", project, zone)
    if not name:
        return None
    interfaces = [
        _instance_interface(n, project) for n in _list(instance.get("networkInterfaces")) if isinstance(n, dict)
    ]
    primary = interfaces[0] if interfaces else {"network_id": "", "subnet_id": "", "private_ips": [], "public_ips": []}
    public = [ip for i in interfaces for ip in i["public_ips"]]
    return _resource(
        uid,
        "instance",
        name=name,
        region=zone.rsplit("-", 1)[0] if zone.count("-") >= 2 else zone,
        status=_t(instance.get("status")),
        metadata={
            "project": owner,
            "instance_id": rid_of(uid),
            "zone": zone,
            "machine_type": link_name(instance.get("machineType")),
            "can_ip_forward": bool(instance.get("canIpForward")),
            "network_tags": _texts(_get(instance, "tags", "items")),
            "service_accounts": _texts(
                [_get(s, "email") for s in _list(instance.get("serviceAccounts")) if isinstance(s, dict)]
            ),
            "vpc_id": primary["network_id"],
            "subnet_id": primary["subnet_id"],
            "private_ip": primary["private_ips"][0] if primary["private_ips"] else "",
            "public_ip": public[0] if public else "",
            "public_ips": list(dict.fromkeys(public)),
            "interfaces": interfaces,
        },
    )


# ── Load balancers and Private Service Connect ───────────────────────────────

# The target of a forwarding rule that is a Private Service Connect endpoint
# for Google APIs (a bundle name, not a link).
_GOOGLE_API_BUNDLES = {"all-apis": "Google APIs (all-apis)", "vpc-sc": "Google APIs (vpc-sc)"}
_EXTERNAL_SCHEMES = ("EXTERNAL", "EXTERNAL_MANAGED")
# Target proxy collection -> the load balancer family it fronts.
_PROXY_FAMILIES = {
    "targetHttpProxies": "Application",
    "targetHttpsProxies": "Application",
    "targetGrpcProxies": "Application",
    "targetTcpProxies": "proxy Network",
    "targetSslProxies": "proxy Network",
}


def link_key(link: Any, project: str = "") -> str:
    """What identifies the resource a self link names (project, region or
    zone, collection, name), so the v1, beta and partial links of one
    resource match; ``""`` for no name."""
    parts = parse_link(link)
    if not parts["name"]:
        return ""
    scope = parts["region"] or parts["zone"]
    return "/".join((parts["project"] or project, scope, parts["collection"], parts["name"]))


def _url_map_services(url_map: dict) -> list[str]:
    """Every backend service (or bucket) link a URL map sends traffic to, once each."""
    weighted = _list(_get(url_map, "defaultRouteAction", "weightedBackendServices"))
    found = [url_map.get("defaultService"), *[_get(w, "backendService") for w in weighted]]
    for matcher in _list(url_map.get("pathMatchers")):
        if not isinstance(matcher, dict):
            continue
        found.append(matcher.get("defaultService"))
        found += [r.get("service") for r in _list(matcher.get("pathRules")) if isinstance(r, dict)]
        found += [r.get("service") for r in _list(matcher.get("routeRules")) if isinstance(r, dict)]
    return _texts(found)


# ``healthState`` of a backend (``backendServices.getHealth``) -> how it counts.
_HEALTH_STATES = {"HEALTHY": "healthy", "UNHEALTHY": "unhealthy", "TIMEOUT": "unhealthy"}


def _health_counts(statuses: Any) -> dict[str, int]:
    """``{"healthy", "unhealthy", "unknown"}`` counts of ``healthStatus``
    entries; DRAINING, UNKNOWN and a missing state count as unknown."""
    counts = {"healthy": 0, "unhealthy": 0, "unknown": 0}
    for status in _list(statuses):
        if isinstance(status, dict):
            counts[_HEALTH_STATES.get(_t(status.get("healthState")).upper(), "unknown")] += 1
    return counts


def backend_health_table(results: Any, project: str) -> dict[str, list[dict]]:
    """The health of each backend group of each backend service, by the
    ``link_key`` of the service. ``results`` holds what the collector read:
    ``{"backendService": link, "group": link, "healthStatus": [...]}``, the
    ``healthStatus`` of one ``getHealth`` call per backend group."""
    table: dict[str, list[dict]] = {}
    for result in _list(results):
        if not isinstance(result, dict):
            continue
        key = link_key(result.get("backendService"), project)
        if key:
            table.setdefault(key, []).append(
                {
                    "backend_service": link_name(result.get("backendService")),
                    "group": link_name(result.get("group")),
                    **_health_counts(result.get("healthStatus")),
                }
            )
    return table


class Backends:
    """What a forwarding rule leads to, by ``link_key``: target proxies, URL
    maps, backend services, target pools, and the instance groups and
    network endpoint groups behind them (their network places a load
    balancer whose forwarding rule names none). Any of them may be missing
    (its section was not read); the forwarding rule then records what it
    names itself."""

    def __init__(
        self,
        project: str,
        *,
        backend_services: Any = (),
        url_maps: Any = (),
        target_proxies: Any = (),
        target_pools: Any = (),
        instance_groups: Any = (),
        network_endpoint_groups: Any = (),
        subnetworks: Any = (),
        backend_health: Any = (),
    ) -> None:
        self.project = project
        self.health = backend_health_table(backend_health, project)

        def by_key(items: Any) -> dict[str, dict]:
            found: dict[str, dict] = {}
            for item in items:
                key = link_key(item.get("selfLink"), project) if isinstance(item, dict) else ""
                if key:
                    found[key] = item
            return found

        self.services = by_key(backend_services)
        self.url_maps = by_key(url_maps)
        self.proxies = by_key(target_proxies)
        self.pools = by_key(target_pools)
        self.groups = by_key([*instance_groups, *network_endpoint_groups])
        self.subnet_networks: dict[str, str] = {}
        for subnet in subnetworks:
            record = subnet_resource(subnet, project) if isinstance(subnet, dict) else None
            if record and record["metadata"]["network_id"]:
                self.subnet_networks[rid_of(record["resource_uid"])] = record["metadata"]["network_id"]

    def group_network(self, link: Any) -> str:
        """The network of an instance group or network endpoint group."""
        group = self.groups.get(link_key(link, self.project)) or {}
        network = _rid_link(group.get("network"), self.project, "vpc")
        subnet = _rid_link(group.get("subnetwork"), self.project, "subnet")
        return network or self.subnet_networks.get(subnet, "")

    def resolve(self, rule: dict) -> dict:
        """The URL map, backend services, backends and networks a forwarding
        rule leads to, as far as what was collected tells."""
        target = _t(rule.get("target"))
        collection = parse_link(target)["collection"]
        url_map = ""
        services: list[str] = _texts([rule.get("backendService")])
        if not services and collection in _PROXY_FAMILIES:
            proxy = self.proxies.get(link_key(target, self.project)) or {}
            if _t(proxy.get("urlMap")):
                url_map = _t(proxy.get("urlMap"))
                services = _url_map_services(self.url_maps.get(link_key(url_map, self.project)) or {})
            else:
                services = _texts([proxy.get("service")])
        backends: list[str] = []
        networks: list[str] = []
        protocols: list[str] = []
        health: list[dict] = []
        for link in services:
            health += self.health.get(link_key(link, self.project), [])
            service = self.services.get(link_key(link, self.project)) or {}
            networks.append(_rid_link(service.get("network"), self.project, "vpc"))
            protocols.append(_t(service.get("protocol")))
            backends += [_t(b.get("group")) for b in _list(service.get("backends")) if isinstance(b, dict)]
        if collection == "targetPools":
            backends += _texts((self.pools.get(link_key(target, self.project)) or {}).get("instances"))
        networks += [self.group_network(link) for link in backends]
        resolved: dict[str, Any] = {
            "url_map": link_name(url_map),
            "backend_services": [link_name(s) for s in services if link_name(s)],
            "backend_protocols": _texts(protocols),
            "backend_count": len(dict.fromkeys(b for b in backends if b)),
            "backend_network_ids": _texts(networks),
        }
        # Only when the health was read: no health is not "nothing healthy".
        if health:
            resolved["backend_health"] = {
                state: sum(group[state] for group in health) for state in ("healthy", "unhealthy", "unknown")
            }
            resolved["backend_health_groups"] = health
        return resolved


def load_balancer_kind(rule: dict) -> str:
    """The load balancer a forwarding rule is the frontend of, by the names
    Google gives them ("Global external Application Load Balancer",
    "Internal passthrough Network Load Balancer"), from its scheme, scope
    and target."""
    scheme = _t(rule.get("loadBalancingScheme")).upper()
    collection = parse_link(rule.get("target"))["collection"]
    regional = bool(link_scope(rule.get("region")) or link_scope(rule.get("selfLink")))
    if collection == "targetInstances":
        return "Protocol forwarding"
    if scheme == "INTERNAL_SELF_MANAGED":
        return "Cloud Service Mesh forwarding rule"
    family = _PROXY_FAMILIES.get(collection)
    if family is None:
        if scheme == "INTERNAL":
            return "Internal passthrough Network Load Balancer"
        if collection == "targetPools":
            return "External passthrough Network Load Balancer (target pool)"
        return "External passthrough Network Load Balancer"
    if scheme == "EXTERNAL":
        return f"Classic {family} Load Balancer"
    if scheme == "EXTERNAL_MANAGED":
        where = "Regional external" if regional else "Global external"
    else:
        where = "Regional internal" if regional else "Cross-region internal"
    return f"{where} {family} Load Balancer"


def _ports(rule: dict) -> list[str]:
    """``["80"]``, ``["8080-8090"]``, ``["53", "443"]`` or ``["all"]``."""
    if rule.get("allPorts"):
        return ["all"]
    found = _texts(rule.get("ports"))
    port_range = _t(rule.get("portRange"))
    if port_range:
        low, _sep, high = port_range.partition("-")
        found.append(low if not high or high == low else port_range)
    return list(dict.fromkeys(found))


def _single_port(ports: list[str]) -> int | None:
    return int(ports[0]) if len(ports) == 1 and ports[0].isdigit() else None


def forwarding_rule_resource(rule: dict, project: str, backends: Backends | None = None) -> dict | None:
    """A forwarding rule: the frontend of a load balancer (``load_balancer``)
    or a Private Service Connect endpoint (``psc_endpoint``: its target is a
    service attachment or the Google APIs bundle). The forwarding rules of a
    Classic VPN gateway are left out; the gateway is collected itself.

    An internal address is an endpoint (a host of the network); an external
    one is listed in ``public_ips``. A rule that names no network (an
    external load balancer) is placed by the network of its backends."""
    target = _t(rule.get("target"))
    collection = parse_link(target)["collection"]
    if collection == "targetVpnGateways":
        return None
    psc = target in _GOOGLE_API_BUNDLES or collection == "serviceAttachments"
    resource_type = PSC_ENDPOINT_TYPE if psc else LOAD_BALANCER_TYPE
    region = link_scope(rule.get("region")) or link_scope(rule.get("selfLink"))
    uid, owner, name = _own_uid(rule, resource_type, project, region)
    if not name:
        return None
    backends = backends or Backends(project)
    resolved = {} if psc else backends.resolve(rule)
    subnet_id = _rid_link(rule.get("subnetwork"), project, "subnet")
    network_id = (
        _rid_link(rule.get("network"), project, "vpc")
        or backends.subnet_networks.get(subnet_id, "")
        or next(iter(resolved.get("backend_network_ids") or []), "")
    )
    address = _t(rule.get("IPAddress"))
    scheme = _t(rule.get("loadBalancingScheme")).upper()
    ports = _ports(rule)
    common: dict[str, Any] = {
        "project": owner,
        "ip_address": address,
        "ip_protocol": _t(rule.get("IPProtocol")),
        "ip_version": _t(rule.get("ipVersion")),
        "ports": ports,
        "network_tier": _t(rule.get("networkTier")),
        "description": _t(rule.get("description")),
    }
    if psc:
        target_rid = "" if target in _GOOGLE_API_BUNDLES else _rid_link(target, project, SERVICE_ATTACHMENT_TYPE)
        return service_record(
            PROVIDER,
            uid,
            PSC_ENDPOINT_TYPE,
            rid_of(uid),
            name=name,
            region=region or "global",
            status=_t(rule.get("pscConnectionStatus")) or "active",
            kind="Private Service Connect endpoint",
            vpc_id=network_id,
            subnet_ids=[subnet_id] if subnet_id else [],
            endpoints=[endpoint("Private Service Connect", _t(rule.get("serviceName")), None, [address])],
            psc_target=_GOOGLE_API_BUNDLES.get(target) or target_rid or target,
            psc_target_id=target_rid,
            psc_connection_status=_t(rule.get("pscConnectionStatus")),
            psc_connection_id=_t(rule.get("pscConnectionId")),
            **common,
        )
    external = scheme in _EXTERNAL_SCHEMES
    return service_record(
        PROVIDER,
        uid,
        LOAD_BALANCER_TYPE,
        rid_of(uid),
        name=name,
        region=region or "global",
        status="active",
        kind=load_balancer_kind(rule),
        vpc_id=network_id,
        subnet_ids=[subnet_id] if subnet_id else [],
        endpoints=[]
        if external
        else [endpoint("Frontend", _t(rule.get("serviceName")), _single_port(ports), [address])],
        public_ips=[address] if external and address else [],
        load_balancing_scheme=scheme,
        target=link_name(target),
        target_type=collection,
        global_access=bool(rule.get("allowGlobalAccess")),
        **resolved,
        **common,
    )


def service_attachment_resource(
    attachment: dict, project: str, rule_networks: dict[str, str] | None = None, backends: Backends | None = None
) -> dict | None:
    """The producer side of Private Service Connect: a service attachment
    publishes a load balancer (its target forwarding rule) to consumers in
    other networks through its NAT subnets. ``rule_networks`` maps the
    ``link_key`` of a forwarding rule to its network, which places the
    attachment; else its NAT subnets do."""
    region = link_scope(attachment.get("region")) or link_scope(attachment.get("selfLink"))
    uid, owner, name = _own_uid(attachment, SERVICE_ATTACHMENT_TYPE, project, region)
    if not name:
        return None
    nat_subnets = [s for s in (_rid_link(link, project, "subnet") for link in _list(attachment.get("natSubnets"))) if s]
    target = _t(attachment.get("targetService"))
    subnet_networks = backends.subnet_networks if backends else {}
    network_id = (rule_networks or {}).get(link_key(target, project), "") or next(
        (subnet_networks[s] for s in nat_subnets if s in subnet_networks), ""
    )
    connected = [c for c in _list(attachment.get("connectedEndpoints")) if isinstance(c, dict)]
    statuses = [_t(c.get("status")).upper() for c in connected]
    return service_record(
        PROVIDER,
        uid,
        SERVICE_ATTACHMENT_TYPE,
        rid_of(uid),
        name=name,
        region=region,
        status="active",
        kind="Private Service Connect service attachment",
        vpc_id=network_id,
        subnet_ids=nat_subnets,
        endpoints=[endpoint("Domain", domain) for domain in _texts(attachment.get("domainNames"))],
        project=owner,
        target_service=link_name(target),
        target_service_id=_rid_link(target, project, LOAD_BALANCER_TYPE),
        connection_preference=_t(attachment.get("connectionPreference")),
        nat_subnets=[s.rsplit(":", 1)[-1] for s in nat_subnets],
        connected_endpoints=statuses.count("ACCEPTED"),
        pending_endpoints=statuses.count("PENDING"),
        consumer_networks=_texts([_rid_link(c.get("consumerNetwork"), project, "vpc") for c in connected]),
        enable_proxy_protocol=bool(attachment.get("enableProxyProtocol")),
        description=_t(attachment.get("description")),
    )


# ── Cloud SQL and Memorystore for Redis ──────────────────────────────────────

# Cloud SQL engine (the part of ``databaseVersion`` before the first "_") -> its port.
_SQL_PORTS = {"MYSQL": 3306, "POSTGRES": 5432, "SQLSERVER": 1433}


def _version(value: Any) -> tuple[str, str]:
    """``POSTGRES_15`` -> ``("POSTGRES", "15")``, ``MYSQL_8_0`` -> ``("MYSQL", "8.0")``,
    ``SQLSERVER_2019_STANDARD`` -> ``("SQLSERVER", "2019 STANDARD")``."""
    engine, _sep, rest = _t(value).partition("_")
    return engine, rest.replace("_", " " if engine == "SQLSERVER" else ".")


def cloud_sql_resource(instance: dict, project: str) -> dict | None:
    """A Cloud SQL instance (``sqladmin`` v1 ``instances.list``): placed in
    the VPC network its private IP is on (``privateNetwork``); its PRIVATE
    address is a host of that network, its PRIMARY (public) one is listed,
    and its OUTGOING one is kept as detail. An instance reached over
    Private Service Connect only has no network of its own: its consumers'
    endpoints are collected as Private Service Connect endpoints."""
    name = _t(instance.get("name"))
    if not name:
        return None
    owner = _t(instance.get("project")) or project
    region = _t(instance.get("region"))
    uid = f"gcp:{CLOUD_SQL_TYPE}:{owner}:{region}:{name}" if region else f"gcp:{CLOUD_SQL_TYPE}:{owner}:{name}"
    ip_config = _get(instance, "settings", "ipConfiguration") or {}
    addresses: dict[str, list[str]] = {}
    for item in _list(instance.get("ipAddresses")):
        if isinstance(item, dict) and _t(item.get("ipAddress")):
            addresses.setdefault(_t(item.get("type")).upper(), []).append(_t(item.get("ipAddress")))
    engine, version = _version(instance.get("databaseVersion"))
    port = _SQL_PORTS.get(engine)
    return service_record(
        PROVIDER,
        uid,
        CLOUD_SQL_TYPE,
        rid_of(uid),
        name=name,
        region=region,
        status=_t(instance.get("state")),
        kind="Cloud SQL instance",
        engine=engine.lower(),
        engine_version=version,
        vpc_id=_rid_link(_get(ip_config, "privateNetwork"), owner, "vpc"),
        endpoints=[endpoint("Private IP", _t(instance.get("dnsName")), port, addresses.get("PRIVATE", []))],
        public_ips=addresses.get("PRIMARY", []),
        project=owner,
        database_version=_t(instance.get("databaseVersion")),
        tier=_t(_get(instance, "settings", "tier")),
        availability_type=_t(_get(instance, "settings", "availabilityType")),
        instance_type=_t(instance.get("instanceType")),
        zone=_t(instance.get("gceZone")),
        connection_name=_t(instance.get("connectionName")),
        outgoing_ips=addresses.get("OUTGOING", []),
        public_ip_enabled=bool(_get(ip_config, "ipv4Enabled")),
        psc_enabled=bool(_get(ip_config, "pscConfig", "pscEnabled")),
        psc_service_attachment=_t(instance.get("pscServiceAttachmentLink")),
    )


def _location_name(name: Any) -> tuple[str, str, str]:
    """``projects/P/locations/L/instances/N`` -> ``("P", "L", "N")``."""
    parts = _t(name).split("/")
    found = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}
    return found.get("projects", ""), found.get("locations", ""), found.get("instances", "")


def memorystore_redis_resource(instance: dict, project: str) -> dict | None:
    """A Memorystore for Redis instance (``redis`` v1
    ``projects.locations.instances.list``): placed in its authorized
    network; its primary and read endpoints are hosts of that network."""
    owner, region, name = _location_name(instance.get("name"))
    if not name:
        return None
    owner = owner or project
    kind = MEMORYSTORE_REDIS_TYPE
    uid = f"gcp:{kind}:{owner}:{region}:{name}" if region else f"gcp:{kind}:{owner}:{name}"
    _engine, version = _version(instance.get("redisVersion"))
    return service_record(
        PROVIDER,
        uid,
        MEMORYSTORE_REDIS_TYPE,
        rid_of(uid),
        name=name,
        region=region,
        status=_t(instance.get("state")),
        kind="Memorystore for Redis",
        engine="redis",
        engine_version=version,
        vpc_id=_rid_link(instance.get("authorizedNetwork"), owner, "vpc"),
        endpoints=[
            endpoint("Primary", "", instance.get("port"), [_t(instance.get("host"))]),
            endpoint("Read endpoint", "", instance.get("readEndpointPort"), [_t(instance.get("readEndpoint"))]),
        ],
        project=owner,
        display_name=_t(instance.get("displayName")),
        tier=_t(instance.get("tier")),
        connect_mode=_t(instance.get("connectMode")),
        memory_size_gb=instance.get("memorySizeGb"),
        reserved_ip_range=_t(instance.get("reservedIpRange")),
        zone=_t(instance.get("currentLocationId")) or _t(instance.get("locationId")),
        replica_count=instance.get("replicaCount"),
        transit_encryption_mode=_t(instance.get("transitEncryptionMode")),
    )


# ── A whole discovery ────────────────────────────────────────────────────────


def assemble(
    project: str,
    *,
    networks: Any = (),
    subnetworks: Any = (),
    routes: Any = (),
    firewalls: Any = (),
    routers: Any = (),
    vpn_gateways: Any = (),
    target_vpn_gateways: Any = (),
    vpn_tunnels: Any = (),
    external_vpn_gateways: Any = (),
    interconnect_attachments: Any = (),
    interconnects: Any = (),
    instances: Any = (),
    network_firewall_policies: Any = (),
    forwarding_rules: Any = (),
    global_forwarding_rules: Any = (),
    backend_services: Any = (),
    url_maps: Any = (),
    target_proxies: Any = (),
    target_pools: Any = (),
    instance_groups: Any = (),
    network_endpoint_groups: Any = (),
    service_attachments: Any = (),
    backend_health: Any = (),
    cloud_sql_instances: Any = (),
    memorystore_redis_instances: Any = (),
) -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of one project from the items each list
    call returned. ``routers`` holds ``(router, status)`` pairs, ``status``
    being the ``result`` of ``routers.getRouterStatus`` or ``None``.
    ``target_proxies`` holds the HTTP, HTTPS, TCP and SSL target proxies;
    ``backend_health`` the ``getHealth`` answer of each backend group
    (``backend_health_table``)."""
    subnetworks = list(subnetworks)
    resources: list[dict] = []
    connections: list[dict] = []

    def add(record: dict | None, links: Any = ()) -> None:
        if record:
            resources.append(record)
            connections.extend(link for link in (links(record) if callable(links) else links) if link)

    for network in networks:
        add(network_resource(network, project), peering_connections(network, project))
    for subnet in subnetworks:
        add(subnet_resource(subnet, project), lambda r: [subnet_attachment(r)])
    for route in routes:
        record = route_resource(route, project)
        add(record, route_connections)
        if record:
            add(internet_gateway_resource(record))
    for fw in firewalls:
        add(firewall_resource(fw, project), lambda r: [firewall_attachment(r)])
    for router, status in routers:
        add(router_resource(router, project, status), lambda r: [router_attachment(r)])
    for gateway in vpn_gateways:
        add(ha_vpn_gateway_resource(gateway, project), lambda r: [vpn_gateway_attachment(r)])
    for gateway in target_vpn_gateways:
        add(target_vpn_gateway_resource(gateway, project), lambda r: [vpn_gateway_attachment(r)])
    for tunnel in vpn_tunnels:
        add(vpn_tunnel_resource(tunnel, project), vpn_tunnel_connections)
    for gateway in external_vpn_gateways:
        add(external_vpn_gateway_resource(gateway, project))
    for attachment in interconnect_attachments:
        add(interconnect_attachment_resource(attachment, project), interconnect_attachment_connections)
    for interconnect in interconnects:
        add(interconnect_resource(interconnect, project))
    for instance in instances:
        add(instance_resource(instance, project))
    for policy in network_firewall_policies:
        add(network_firewall_policy_resource(policy, project))
    backends = Backends(
        project,
        backend_services=backend_services,
        url_maps=url_maps,
        target_proxies=target_proxies,
        target_pools=target_pools,
        instance_groups=instance_groups,
        network_endpoint_groups=network_endpoint_groups,
        subnetworks=subnetworks,
        backend_health=backend_health,
    )
    # Forwarding rule -> its network, which places a service attachment.
    rule_networks: dict[str, str] = {}
    for rule in [*forwarding_rules, *global_forwarding_rules]:
        record = forwarding_rule_resource(rule, project, backends)
        add(record)
        if record and record["metadata"]["vpc_id"]:
            rule_networks[link_key(rule.get("selfLink"), project)] = record["metadata"]["vpc_id"]
    for attachment in service_attachments:
        add(service_attachment_resource(attachment, project, rule_networks, backends))
    for instance in cloud_sql_instances:
        add(cloud_sql_resource(instance, project))
    for instance in memorystore_redis_instances:
        add(memorystore_redis_resource(instance, project))
    return resources, connections
