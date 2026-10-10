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
``gcp:firewall_policy:<project>:<name>``. What follows ``gcp:<type>:`` is
unique across projects, so several accounts share one map.
"""

from __future__ import annotations

import re
from typing import Any

PROVIDER = "gcp"
WARNING_TYPE = "collection_warning"
DEFAULT_INTERNET_GATEWAY = "default-internet-gateway"

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


def warning_resource(section: str, exc: BaseException) -> dict:
    """Record of a detail section that could not be read, stored with the
    discovery so the map's report can say what is missing and why."""
    return _resource(
        f"gcp:{WARNING_TYPE}:{section}",
        WARNING_TYPE,
        name=section,
        region="",
        status="skipped",
        metadata={"section": section, "error": error_code(exc)},
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
) -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of one project from the items each list
    call returned. ``routers`` holds ``(router, status)`` pairs, ``status``
    being the ``result`` of ``routers.getRouterStatus`` or ``None``."""
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
    return resources, connections
