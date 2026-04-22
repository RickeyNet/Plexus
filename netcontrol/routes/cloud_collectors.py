"""
cloud_collectors.py -- Provider-specific cloud topology collectors.

The collectors in this module are optional-runtime integrations:
  - AWS via boto3
  - Azure via azure-identity + azure-mgmt-network
  - GCP via google-auth + google-api-python-client

If SDK dependencies are unavailable, callers can fall back to sample mode.
"""

from __future__ import annotations

import json
from typing import Any

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cloud_collectors")

VALID_PROVIDERS = {"aws", "azure", "gcp"}


class CloudCollectorError(RuntimeError):
    """Base class for collector failures."""


class CloudCollectorUnavailable(CloudCollectorError):
    """Raised when required SDK dependencies are not installed."""


class CloudCollectorAuthError(CloudCollectorError):
    """Raised for provider authentication/authorization failures."""


class CloudCollectorExecutionError(CloudCollectorError):
    """Raised for provider API/runtime execution failures."""


def _parse_auth_config(account: dict) -> dict:
    raw = account.get("auth_config_json") or account.get("auth_config") or "{}"
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _parse_region_scope(region_scope: str | None) -> list[str]:
    raw = str(region_scope or "").strip()
    if not raw:
        return []
    return [r.strip() for r in raw.split(",") if r.strip()]


def _normalize_resource(
    provider: str,
    resource_uid: str,
    resource_type: str,
    *,
    name: str = "",
    region: str = "",
    cidr: str = "",
    status: str = "",
    metadata: dict | None = None,
) -> dict:
    return {
        "provider": provider,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": metadata or {},
    }


def _normalize_connection(
    provider: str,
    source_resource_uid: str,
    target_resource_uid: str,
    connection_type: str,
    *,
    state: str = "",
    metadata: dict | None = None,
) -> dict:
    return {
        "provider": provider,
        "source_resource_uid": source_resource_uid,
        "target_resource_uid": target_resource_uid,
        "connection_type": connection_type,
        "state": state,
        "metadata": metadata or {},
    }


def _join_policy_selectors(values: list[str]) -> str:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return ", ".join(out)


def _port_expression(protocol: str, from_port, to_port) -> str:
    proto = str(protocol or "").strip().lower()
    if proto in {"-1", "all", "*", ""}:
        return "all"
    if from_port in (None, "") and to_port in (None, ""):
        return "all"
    try:
        start = int(from_port)
    except Exception:
        start = None
    try:
        end = int(to_port)
    except Exception:
        end = None
    if start is None and end is None:
        return "all"
    if start is None:
        return str(end)
    if end is None or end == start:
        return str(start)
    return f"{start}-{end}"


def _aws_security_group_rules(group: dict, *, resource_uid: str) -> list[dict]:
    rules: list[dict] = []

    def _selectors(permission: dict) -> str:
        values: list[str] = []
        for item in permission.get("IpRanges", []) or []:
            cidr = str(item.get("CidrIp") or "").strip()
            if cidr:
                values.append(cidr)
        for item in permission.get("Ipv6Ranges", []) or []:
            cidr = str(item.get("CidrIpv6") or "").strip()
            if cidr:
                values.append(cidr)
        for item in permission.get("UserIdGroupPairs", []) or []:
            group_id = str(item.get("GroupId") or "").strip()
            user_id = str(item.get("UserId") or "").strip()
            if group_id:
                values.append(f"{user_id + '/' if user_id else ''}sg:{group_id}")
        for item in permission.get("PrefixListIds", []) or []:
            prefix_id = str(item.get("PrefixListId") or "").strip()
            if prefix_id:
                values.append(f"prefix:{prefix_id}")
        return _join_policy_selectors(values) or "any"

    for direction, key in (("inbound", "IpPermissions"), ("outbound", "IpPermissionsEgress")):
        for idx, permission in enumerate(group.get(key, []) or []):
            protocol = str(permission.get("IpProtocol") or "all").strip().lower()
            if protocol == "-1":
                protocol = "all"
            rules.append(
                {
                    "rule_uid": f"{resource_uid}:{direction}:{idx + 1}",
                    "rule_name": f"{direction}-{idx + 1}",
                    "direction": direction,
                    "action": "allow",
                    "protocol": protocol,
                    "source_selector": _selectors(permission) if direction == "inbound" else "self",
                    "destination_selector": _selectors(permission) if direction == "outbound" else "self",
                    "port_expression": _port_expression(protocol, permission.get("FromPort"), permission.get("ToPort")),
                    "priority": None,
                }
            )
    return rules


def _azure_selector(rule_obj, singular: str, plural: str) -> str:
    values: list[str] = []
    single = getattr(rule_obj, singular, None)
    if single not in (None, ""):
        values.append(str(single))
    for item in getattr(rule_obj, plural, None) or []:
        text = str(item or "").strip()
        if text:
            values.append(text)
    return _join_policy_selectors(values) or "any"


def _azure_nsg_rules(nsg) -> list[dict]:
    rules: list[dict] = []
    explicit = list(getattr(nsg, "security_rules", None) or [])
    default = list(getattr(nsg, "default_security_rules", None) or [])
    for rule_obj in explicit + default:
        direction = str(getattr(rule_obj, "direction", "") or "").strip().lower()
        if direction == "ingress":
            direction = "inbound"
        elif direction == "egress":
            direction = "outbound"
        action = str(getattr(rule_obj, "access", "") or "").strip().lower()
        protocol = str(getattr(rule_obj, "protocol", "all") or "all").strip().lower()
        if protocol == "*":
            protocol = "all"
        rules.append(
            {
                "rule_uid": str(getattr(rule_obj, "id", "") or getattr(rule_obj, "name", "") or "").strip(),
                "rule_name": str(getattr(rule_obj, "name", "") or "").strip(),
                "direction": direction,
                "action": action,
                "protocol": protocol,
                "source_selector": _azure_selector(rule_obj, "source_address_prefix", "source_address_prefixes"),
                "destination_selector": _azure_selector(rule_obj, "destination_address_prefix", "destination_address_prefixes"),
                "port_expression": _join_policy_selectors(
                    [str(getattr(rule_obj, "destination_port_range", "") or "").strip()]
                    + [str(item or "").strip() for item in (getattr(rule_obj, "destination_port_ranges", None) or [])]
                ) or "all",
                "priority": getattr(rule_obj, "priority", None),
                "metadata": {
                    "is_default": rule_obj in default,
                    "description": str(getattr(rule_obj, "description", "") or "").strip(),
                },
            }
        )
    return rules


def _gcp_firewall_rules(fw: dict, *, resource_uid: str) -> list[dict]:
    rules: list[dict] = []
    direction = str(fw.get("direction") or "INGRESS").strip().lower()
    if direction == "ingress":
        normalized_direction = "inbound"
    elif direction == "egress":
        normalized_direction = "outbound"
    else:
        normalized_direction = direction

    source_selector = _join_policy_selectors([str(item or "").strip() for item in (fw.get("sourceRanges") or [])])
    destination_selector = _join_policy_selectors([str(item or "").strip() for item in (fw.get("destinationRanges") or [])])
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
        ports = _join_policy_selectors([str(port or "").strip() for port in (item.get("ports") or [])]) or "all"
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


def _aws_route_target_uid(route: dict) -> str:
    nat_gateway_id = str(route.get("NatGatewayId") or "").strip()
    if nat_gateway_id:
        return f"aws:nat_gateway:{nat_gateway_id}"

    transit_gateway_id = str(route.get("TransitGatewayId") or "").strip()
    if transit_gateway_id:
        return f"aws:tgw:{transit_gateway_id}"

    gateway_id = str(route.get("GatewayId") or "").strip()
    if gateway_id:
        if gateway_id == "local":
            return ""
        if gateway_id.startswith("igw-"):
            return f"aws:internet_gateway:{gateway_id}"
        if gateway_id.startswith("vgw-"):
            return f"aws:vpn_gateway:{gateway_id}"
        if gateway_id.startswith("eigw-"):
            return f"aws:egress_only_internet_gateway:{gateway_id}"
        if gateway_id.startswith("tgw-"):
            return f"aws:tgw:{gateway_id}"

    peering_id = str(route.get("VpcPeeringConnectionId") or "").strip()
    if peering_id:
        return f"aws:vpc_peering_connection:{peering_id}"

    local_gateway_id = str(route.get("LocalGatewayId") or "").strip()
    if local_gateway_id:
        return f"aws:local_gateway:{local_gateway_id}"

    carrier_gateway_id = str(route.get("CarrierGatewayId") or "").strip()
    if carrier_gateway_id:
        return f"aws:carrier_gateway:{carrier_gateway_id}"

    return ""


def _aws_route_destination(route: dict) -> str:
    return str(
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
        or ""
    ).strip()


def _dedupe_resources(resources: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for resource in resources:
        uid = str(resource.get("resource_uid") or "").strip()
        if not uid:
            continue
        current = merged.get(uid)
        if current is None:
            merged[uid] = dict(resource)
            continue
        # Keep richer fields when present.
        for key in ("name", "region", "cidr", "status"):
            if not current.get(key) and resource.get(key):
                current[key] = resource.get(key)
        if resource.get("metadata"):
            current_meta = current.get("metadata") if isinstance(current.get("metadata"), dict) else {}
            next_meta = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
            current["metadata"] = {**current_meta, **next_meta}
    return list(merged.values())


def _dedupe_connections(connections: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for edge in connections:
        src = str(edge.get("source_resource_uid") or "").strip()
        dst = str(edge.get("target_resource_uid") or "").strip()
        ctype = str(edge.get("connection_type") or "").strip()
        if not src or not dst or not ctype:
            continue
        key = f"{src}|{dst}|{ctype}"
        if key not in merged:
            merged[key] = dict(edge)
            continue
        if not merged[key].get("state") and edge.get("state"):
            merged[key]["state"] = edge.get("state")
        if edge.get("metadata"):
            current_meta = merged[key].get("metadata") if isinstance(merged[key].get("metadata"), dict) else {}
            next_meta = edge.get("metadata") if isinstance(edge.get("metadata"), dict) else {}
            merged[key]["metadata"] = {**current_meta, **next_meta}
    return list(merged.values())


def _aws_tag_name(tags: list[dict] | None) -> str:
    if not tags:
        return ""
    for tag in tags:
        if str(tag.get("Key") or "").lower() == "name":
            return str(tag.get("Value") or "")
    return ""


def _collect_aws(account: dict) -> tuple[list[dict], list[dict]]:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except Exception as exc:
        raise CloudCollectorUnavailable("AWS collector requires boto3/botocore") from exc

    auth = _parse_auth_config(account)
    session_kwargs: dict[str, Any] = {}
    if auth.get("profile_name"):
        session_kwargs["profile_name"] = str(auth.get("profile_name"))
    if auth.get("access_key_id"):
        session_kwargs["aws_access_key_id"] = str(auth.get("access_key_id"))
    if auth.get("secret_access_key"):
        session_kwargs["aws_secret_access_key"] = str(auth.get("secret_access_key"))
    if auth.get("session_token"):
        session_kwargs["aws_session_token"] = str(auth.get("session_token"))

    try:
        session = boto3.Session(**session_kwargs)
    except Exception as exc:
        raise CloudCollectorAuthError("Failed to initialize AWS session") from exc

    role_arn = str(auth.get("role_arn") or "").strip()
    external_id = str(auth.get("external_id") or "").strip()
    if role_arn:
        try:
            sts = session.client("sts")
            assume_args = {
                "RoleArn": role_arn,
                "RoleSessionName": str(auth.get("role_session_name") or "plexus-cloud-visibility"),
            }
            if external_id:
                assume_args["ExternalId"] = external_id
            creds = sts.assume_role(**assume_args)["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        except Exception as exc:
            raise CloudCollectorAuthError("Failed to assume AWS IAM role") from exc

    regions = _parse_region_scope(str(account.get("region_scope") or ""))
    if not regions:
        regions = ["us-east-1"]

    # Validate credentials early.
    try:
        session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        raise CloudCollectorAuthError("AWS credentials are invalid or unauthorized") from exc
    except Exception as exc:
        raise CloudCollectorExecutionError("Failed to validate AWS credentials") from exc

    resources: list[dict] = []
    connections: list[dict] = []
    subnet_to_vnet: dict[str, str] = {}

    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc_id = str(vpc.get("VpcId") or "").strip()
                if not vpc_id:
                    continue
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:vpc:{vpc_id}",
                        "vpc",
                        name=_aws_tag_name(vpc.get("Tags")),
                        region=region,
                        cidr=str(vpc.get("CidrBlock") or ""),
                        status=str(vpc.get("State") or ""),
                        metadata={"is_default": bool(vpc.get("IsDefault", False))},
                    )
                )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed vpc list region=%s", region, exc_info=True)

        try:
            igws = ec2.describe_internet_gateways().get("InternetGateways", [])
            for gateway in igws:
                igw_id = str(gateway.get("InternetGatewayId") or "").strip()
                if not igw_id:
                    continue
                attachments = gateway.get("Attachments", []) or []
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:internet_gateway:{igw_id}",
                        "internet_gateway",
                        name=igw_id,
                        region=region,
                        status="available",
                        metadata={
                            "vpc_ids": [str(item.get("VpcId") or "").strip() for item in attachments if str(item.get("VpcId") or "").strip()],
                        },
                    )
                )
                for attachment in attachments:
                    vpc_id = str(attachment.get("VpcId") or "").strip()
                    if not vpc_id:
                        continue
                    connections.append(
                        _normalize_connection(
                            "aws",
                            f"aws:vpc:{vpc_id}",
                            f"aws:internet_gateway:{igw_id}",
                            "internet_gateway_attachment",
                            state=str(attachment.get("State") or "attached"),
                        )
                    )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed internet gateway list region=%s", region, exc_info=True)

        try:
            nat_gateways = ec2.describe_nat_gateways().get("NatGateways", [])
            for gateway in nat_gateways:
                nat_id = str(gateway.get("NatGatewayId") or "").strip()
                if not nat_id:
                    continue
                vpc_id = str(gateway.get("VpcId") or "").strip()
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:nat_gateway:{nat_id}",
                        "nat_gateway",
                        name=nat_id,
                        region=region,
                        status=str(gateway.get("State") or ""),
                        metadata={
                            "vpc_id": vpc_id,
                            "subnet_id": str(gateway.get("SubnetId") or "").strip(),
                            "connectivity_type": str(gateway.get("ConnectivityType") or "").strip(),
                        },
                    )
                )
                if vpc_id:
                    connections.append(
                        _normalize_connection(
                            "aws",
                            f"aws:vpc:{vpc_id}",
                            f"aws:nat_gateway:{nat_id}",
                            "nat_gateway_attachment",
                            state=str(gateway.get("State") or ""),
                        )
                    )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed nat gateway list region=%s", region, exc_info=True)

        try:
            sec_groups = ec2.describe_security_groups().get("SecurityGroups", [])
            for group in sec_groups:
                gid = str(group.get("GroupId") or "").strip()
                if not gid:
                    continue
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:sg:{gid}",
                        "security_group",
                        name=str(group.get("GroupName") or ""),
                        region=region,
                        status="active",
                        metadata={
                            "vpc_id": str(group.get("VpcId") or ""),
                            "policy_rules": _aws_security_group_rules(group, resource_uid=f"aws:sg:{gid}"),
                        },
                    )
                )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed security group list region=%s", region, exc_info=True)

        try:
            tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
            for tgw in tgws:
                tgw_id = str(tgw.get("TransitGatewayId") or "").strip()
                if not tgw_id:
                    continue
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:tgw:{tgw_id}",
                        "transit_gateway",
                        name=_aws_tag_name(tgw.get("Tags")),
                        region=region,
                        status=str(tgw.get("State") or ""),
                    )
                )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed tgw list region=%s", region, exc_info=True)

        try:
            attachments = ec2.describe_transit_gateway_attachments().get("TransitGatewayAttachments", [])
            for attachment in attachments:
                tgw_id = str(attachment.get("TransitGatewayId") or "").strip()
                res_type = str(attachment.get("ResourceType") or "").strip().lower()
                res_id = str(attachment.get("ResourceId") or "").strip()
                if not tgw_id or not res_type or not res_id:
                    continue
                source_uid = f"aws:{res_type}:{res_id}"
                target_uid = f"aws:tgw:{tgw_id}"
                connections.append(
                    _normalize_connection(
                        "aws",
                        source_uid,
                        target_uid,
                        "transit_gateway_attachment",
                        state=str(attachment.get("State") or ""),
                    )
                )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed tgw attachment list region=%s", region, exc_info=True)

        try:
            peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
            for peering in peerings:
                req = peering.get("RequesterVpcInfo") or {}
                acc = peering.get("AccepterVpcInfo") or {}
                req_vpc = str(req.get("VpcId") or "").strip()
                acc_vpc = str(acc.get("VpcId") or "").strip()
                if not req_vpc or not acc_vpc:
                    continue
                connections.append(
                    _normalize_connection(
                        "aws",
                        f"aws:vpc:{req_vpc}",
                        f"aws:vpc:{acc_vpc}",
                        "vpc_peering",
                        state=str((peering.get("Status") or {}).get("Code") or ""),
                        metadata={"peering_id": str(peering.get("VpcPeeringConnectionId") or "")},
                    )
                )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed vpc peering list region=%s", region, exc_info=True)

        try:
            vpn_gateways = ec2.describe_vpn_gateways().get("VpnGateways", [])
            for gateway in vpn_gateways:
                gateway_id = str(gateway.get("VpnGatewayId") or "").strip()
                if not gateway_id:
                    continue
                attachments = gateway.get("VpcAttachments", []) or []
                resources.append(
                    _normalize_resource(
                        "aws",
                        f"aws:vpn_gateway:{gateway_id}",
                        "vpn_gateway",
                        name=gateway_id,
                        region=region,
                        status=str(gateway.get("State") or ""),
                        metadata={
                            "availability_zone": str(gateway.get("AvailabilityZone") or "").strip(),
                            "vpc_ids": [str(item.get("VpcId") or "").strip() for item in attachments if str(item.get("VpcId") or "").strip()],
                        },
                    )
                )
                for attachment in attachments:
                    vpc_id = str(attachment.get("VpcId") or "").strip()
                    if not vpc_id:
                        continue
                    connections.append(
                        _normalize_connection(
                            "aws",
                            f"aws:vpc:{vpc_id}",
                            f"aws:vpn_gateway:{gateway_id}",
                            "vpn_gateway_attachment",
                            state=str(attachment.get("State") or gateway.get("State") or ""),
                        )
                    )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed vpn gateway list region=%s", region, exc_info=True)

        try:
            route_tables = ec2.describe_route_tables().get("RouteTables", [])
            for route_table in route_tables:
                route_table_id = str(route_table.get("RouteTableId") or "").strip()
                vpc_id = str(route_table.get("VpcId") or "").strip()
                if not route_table_id:
                    continue
                routes = route_table.get("Routes", []) or []
                associations = route_table.get("Associations", []) or []
                route_table_uid = f"aws:route_table:{route_table_id}"
                resources.append(
                    _normalize_resource(
                        "aws",
                        route_table_uid,
                        "route_table",
                        name=_aws_tag_name(route_table.get("Tags")) or route_table_id,
                        region=region,
                        status="active",
                        metadata={
                            "vpc_id": vpc_id,
                            "route_count": len(routes),
                            "association_count": len(associations),
                            "associated_subnet_ids": [
                                str(item.get("SubnetId") or "").strip()
                                for item in associations
                                if str(item.get("SubnetId") or "").strip()
                            ],
                        },
                    )
                )
                if vpc_id:
                    connections.append(
                        _normalize_connection(
                            "aws",
                            f"aws:vpc:{vpc_id}",
                            route_table_uid,
                            "route_table_association",
                            state="attached",
                            metadata={"association_count": len(associations)},
                        )
                    )
                for route in routes:
                    target_uid = _aws_route_target_uid(route)
                    if not target_uid:
                        continue
                    connections.append(
                        _normalize_connection(
                            "aws",
                            route_table_uid,
                            target_uid,
                            "route_next_hop",
                            state=str(route.get("State") or "active"),
                            metadata={
                                "destination": _aws_route_destination(route),
                                "origin": str(route.get("Origin") or "").strip(),
                            },
                        )
                    )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed route table list region=%s", region, exc_info=True)

        try:
            vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
            for vpn in vpns:
                vpn_id = str(vpn.get("VpnConnectionId") or "").strip()
                if not vpn_id:
                    continue
                vpn_uid = f"aws:vpn_connection:{vpn_id}"
                resources.append(
                    _normalize_resource(
                        "aws",
                        vpn_uid,
                        "vpn_connection",
                        name=_aws_tag_name(vpn.get("Tags")),
                        region=region,
                        status=str(vpn.get("State") or ""),
                    )
                )
                tgw_id = str(vpn.get("TransitGatewayId") or "").strip()
                vgw_id = str(vpn.get("VpnGatewayId") or "").strip()
                if tgw_id:
                    connections.append(
                        _normalize_connection(
                            "aws",
                            vpn_uid,
                            f"aws:tgw:{tgw_id}",
                            "vpn_tunnel",
                            state=str(vpn.get("State") or ""),
                        )
                    )
                if vgw_id:
                    connections.append(
                        _normalize_connection(
                            "aws",
                            vpn_uid,
                            f"aws:vpn_gateway:{vgw_id}",
                            "vpn_attachment",
                            state=str(vpn.get("State") or ""),
                        )
                    )
        except (BotoCoreError, ClientError):
            LOGGER.debug("aws collector: failed vpn list region=%s", region, exc_info=True)

    # Direct Connect API is region-bound but global data plane is in us-east-1.
    try:
        dx_region = regions[0] if regions else "us-east-1"
        dx = session.client("directconnect", region_name=dx_region)
        dx_connections = dx.describe_connections().get("connections", [])
        for dx_conn in dx_connections:
            conn_id = str(dx_conn.get("connectionId") or "").strip()
            if not conn_id:
                continue
            resources.append(
                _normalize_resource(
                    "aws",
                    f"aws:direct_connect:{conn_id}",
                    "direct_connect",
                    name=str(dx_conn.get("connectionName") or ""),
                    region=str(dx_conn.get("region") or dx_region),
                    status=str(dx_conn.get("connectionState") or ""),
                    metadata={"bandwidth": str(dx_conn.get("bandwidth") or "")},
                )
            )
    except Exception:
        LOGGER.debug("aws collector: failed direct connect list", exc_info=True)

    return _dedupe_resources(resources), _dedupe_connections(connections)


def _azure_resource_parts(resource_id: str) -> dict[str, str]:
    parts = [p for p in str(resource_id or "").strip("/").split("/") if p]
    out: dict[str, str] = {}
    for idx in range(0, len(parts) - 1, 2):
        out[parts[idx].lower()] = parts[idx + 1]
    return out


def _azure_rg_from_id(resource_id: str) -> str:
    return _azure_resource_parts(resource_id).get("resourcegroups", "")


def _azure_name_from_id(resource_id: str) -> str:
    parts = [p for p in str(resource_id or "").strip("/").split("/") if p]
    return parts[-1] if parts else ""


def _azure_vnet_uid_from_resource_id(resource_id: str, subscription_id: str) -> str:
    parts = _azure_resource_parts(resource_id)
    rg = parts.get("resourcegroups", "")
    vnet_name = parts.get("virtualnetworks", "")
    if not rg or not vnet_name:
        return ""
    return f"azure:vnet:{subscription_id}:{rg}:{vnet_name}"


def _azure_subnet_name_from_id(resource_id: str) -> str:
    return _azure_resource_parts(resource_id).get("subnets", "")


def _azure_id_to_resource_uid(resource_id: str, subscription_id: str) -> str:
    parts = _azure_resource_parts(resource_id)
    rg = parts.get("resourcegroups", "")
    if parts.get("virtualnetworkgateways"):
        return f"azure:virtual_network_gateway:{subscription_id}:{rg}:{parts['virtualnetworkgateways']}"
    if parts.get("localnetworkgateways"):
        return f"azure:local_network_gateway:{subscription_id}:{rg}:{parts['localnetworkgateways']}"
    if parts.get("routetables"):
        return f"azure:route_table:{subscription_id}:{rg}:{parts['routetables']}"
    if parts.get("networksecuritygroups"):
        return f"azure:nsg:{subscription_id}:{rg}:{parts['networksecuritygroups']}"
    if parts.get("virtualnetworks"):
        return f"azure:vnet:{subscription_id}:{rg}:{parts['virtualnetworks']}"
    if parts.get("expressroutecircuits"):
        return f"azure:expressroute:{subscription_id}:{rg}:{parts['expressroutecircuits']}"
    return ""


def _collect_azure(account: dict) -> tuple[list[dict], list[dict]]:
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
    except Exception as exc:
        raise CloudCollectorUnavailable("Azure collector requires azure-identity and azure-mgmt-network") from exc

    auth = _parse_auth_config(account)
    subscription_id = str(
        auth.get("subscription_id")
        or account.get("account_identifier")
        or ""
    ).strip()
    if not subscription_id:
        raise CloudCollectorAuthError("Azure subscription_id is required")

    tenant_id = str(auth.get("tenant_id") or "").strip()
    client_id = str(auth.get("client_id") or "").strip()
    client_secret = str(auth.get("client_secret") or "").strip()

    try:
        if tenant_id and client_id and client_secret:
            credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
        else:
            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        network_client = NetworkManagementClient(credential, subscription_id)
    except Exception as exc:
        raise CloudCollectorAuthError("Failed to initialize Azure credentials") from exc

    resources: list[dict] = []
    connections: list[dict] = []

    try:
        for vnet in network_client.virtual_networks.list_all():
            vnet_id = str(vnet.id or "")
            rg = _azure_rg_from_id(vnet_id)
            name = str(vnet.name or "")
            uid = f"azure:vnet:{subscription_id}:{rg}:{name}"
            cidr = ""
            if getattr(vnet, "address_space", None) and getattr(vnet.address_space, "address_prefixes", None):
                prefixes = [str(p) for p in (vnet.address_space.address_prefixes or []) if p]
                cidr = ",".join(prefixes)
            region = str(vnet.location or "")
            status = str(getattr(vnet, "provisioning_state", "") or "")
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "vnet",
                    name=name,
                    region=region,
                    cidr=cidr,
                    status=status,
                    metadata={"resource_group": rg},
                )
            )
            for subnet in getattr(vnet, "subnets", None) or []:
                subnet_id = str(getattr(subnet, "id", "") or "").strip()
                if subnet_id:
                    subnet_to_vnet[subnet_id.lower()] = uid

            # VNet peerings for hybrid graph edges.
            try:
                if rg and name:
                    for peering in network_client.virtual_network_peerings.list(rg, name):
                        remote_id = str(getattr(getattr(peering, "remote_virtual_network", None), "id", "") or "")
                        remote_rg = _azure_rg_from_id(remote_id)
                        remote_name = _azure_name_from_id(remote_id)
                        if not remote_name:
                            continue
                        target_uid = f"azure:vnet:{subscription_id}:{remote_rg}:{remote_name}"
                        connections.append(
                            _normalize_connection(
                                "azure",
                                uid,
                                target_uid,
                                "vnet_peering",
                                state=str(getattr(peering, "peering_state", "") or ""),
                            )
                        )
            except Exception:
                LOGGER.debug("azure collector: failed to list peerings for vnet=%s", name, exc_info=True)
    except Exception as exc:
        raise CloudCollectorAuthError("Azure network API access failed") from exc

    try:
        for circuit in network_client.express_route_circuits.list_all():
            circuit_id = str(circuit.id or "")
            rg = _azure_rg_from_id(circuit_id)
            name = str(circuit.name or "")
            uid = f"azure:expressroute:{subscription_id}:{rg}:{name}"
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "expressroute",
                    name=name,
                    region=str(circuit.location or ""),
                    status=str(getattr(circuit, "provisioning_state", "") or ""),
                )
            )
    except Exception:
        LOGGER.debug("azure collector: failed to list expressroute circuits", exc_info=True)

    try:
        for gateway in network_client.virtual_network_gateways.list_all():
            gateway_id = str(gateway.id or "")
            rg = _azure_rg_from_id(gateway_id)
            name = str(gateway.name or "")
            uid = f"azure:virtual_network_gateway:{subscription_id}:{rg}:{name}"
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "virtual_network_gateway",
                    name=name,
                    region=str(gateway.location or ""),
                    status=str(getattr(gateway, "provisioning_state", "") or ""),
                    metadata={
                        "resource_group": rg,
                        "gateway_type": str(getattr(gateway, "gateway_type", "") or "").strip(),
                        "vpn_type": str(getattr(gateway, "vpn_type", "") or "").strip(),
                    },
                )
            )
            for ip_config in getattr(gateway, "ip_configurations", None) or []:
                subnet_id = str(getattr(getattr(ip_config, "subnet", None), "id", "") or "").strip()
                if not subnet_id:
                    continue
                vnet_uid = subnet_to_vnet.get(subnet_id.lower()) or _azure_vnet_uid_from_resource_id(subnet_id, subscription_id)
                if not vnet_uid:
                    continue
                connections.append(
                    _normalize_connection(
                        "azure",
                        vnet_uid,
                        uid,
                        "virtual_network_gateway_attachment",
                        state=str(getattr(gateway, "provisioning_state", "") or "attached"),
                        metadata={"subnet_name": _azure_subnet_name_from_id(subnet_id)},
                    )
                )
                break
    except Exception:
        LOGGER.debug("azure collector: failed to list virtual network gateways", exc_info=True)

    try:
        for gateway in network_client.local_network_gateways.list_all():
            gateway_id = str(gateway.id or "")
            rg = _azure_rg_from_id(gateway_id)
            name = str(gateway.name or "")
            uid = f"azure:local_network_gateway:{subscription_id}:{rg}:{name}"
            prefixes = []
            address_space = getattr(gateway, "local_network_address_space", None)
            if address_space and getattr(address_space, "address_prefixes", None):
                prefixes = [str(item) for item in (address_space.address_prefixes or []) if item]
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "local_network_gateway",
                    name=name,
                    region=str(gateway.location or ""),
                    cidr=",".join(prefixes),
                    status=str(getattr(gateway, "provisioning_state", "") or ""),
                    metadata={
                        "resource_group": rg,
                        "gateway_ip_address": str(getattr(gateway, "gateway_ip_address", "") or "").strip(),
                    },
                )
            )
    except Exception:
        LOGGER.debug("azure collector: failed to list local network gateways", exc_info=True)

    try:
        for route_table in network_client.route_tables.list_all():
            route_table_id = str(route_table.id or "")
            rg = _azure_rg_from_id(route_table_id)
            name = str(route_table.name or "")
            uid = f"azure:route_table:{subscription_id}:{rg}:{name}"
            routes = list(getattr(route_table, "routes", None) or [])
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "route_table",
                    name=name,
                    region=str(route_table.location or ""),
                    status=str(getattr(route_table, "provisioning_state", "") or "active"),
                    metadata={
                        "resource_group": rg,
                        "route_count": len(routes),
                        "route_summaries": [
                            {
                                "name": str(getattr(route, "name", "") or "").strip(),
                                "prefix": str(getattr(route, "address_prefix", "") or "").strip(),
                                "next_hop_type": str(getattr(route, "next_hop_type", "") or "").strip(),
                            }
                            for route in routes[:20]
                        ],
                    },
                )
            )
            for subnet in getattr(route_table, "subnets", None) or []:
                subnet_id = str(getattr(subnet, "id", "") or "").strip()
                if not subnet_id:
                    continue
                vnet_uid = subnet_to_vnet.get(subnet_id.lower()) or _azure_vnet_uid_from_resource_id(subnet_id, subscription_id)
                if not vnet_uid:
                    continue
                connections.append(
                    _normalize_connection(
                        "azure",
                        vnet_uid,
                        uid,
                        "route_table_association",
                        state="attached",
                        metadata={"subnet_name": _azure_subnet_name_from_id(subnet_id)},
                    )
                )
    except Exception:
        LOGGER.debug("azure collector: failed to list route tables", exc_info=True)

    try:
        for nsg in network_client.network_security_groups.list_all():
            nsg_id = str(nsg.id or "")
            rg = _azure_rg_from_id(nsg_id)
            name = str(nsg.name or "")
            uid = f"azure:nsg:{subscription_id}:{rg}:{name}"
            resources.append(
                _normalize_resource(
                    "azure",
                    uid,
                    "network_security_group",
                    name=name,
                    region=str(nsg.location or ""),
                    status=str(getattr(nsg, "provisioning_state", "") or "active"),
                    metadata={
                        "resource_group": rg,
                        "policy_rules": _azure_nsg_rules(nsg),
                    },
                )
            )
    except Exception:
        LOGGER.debug("azure collector: failed to list nsgs", exc_info=True)

    try:
        gateway_connections = getattr(network_client, "virtual_network_gateway_connections", None)
        if gateway_connections is not None:
            for conn in gateway_connections.list_all():
                source_uid = _azure_id_to_resource_uid(
                    str(getattr(getattr(conn, "virtual_network_gateway1", None), "id", "") or ""),
                    subscription_id,
                )
                target_uid = _azure_id_to_resource_uid(
                    str(getattr(getattr(conn, "virtual_network_gateway2", None), "id", "") or "")
                    or str(getattr(getattr(conn, "local_network_gateway2", None), "id", "") or ""),
                    subscription_id,
                )
                if not source_uid or not target_uid:
                    continue
                connections.append(
                    _normalize_connection(
                        "azure",
                        source_uid,
                        target_uid,
                        str(getattr(conn, "connection_type", "gateway_connection") or "gateway_connection").strip().lower(),
                        state=str(getattr(conn, "provisioning_state", "") or ""),
                        metadata={"connection_status": str(getattr(conn, "connection_status", "") or "").strip()},
                    )
                )
    except Exception:
        LOGGER.debug("azure collector: failed to list gateway connections", exc_info=True)

    return _dedupe_resources(resources), _dedupe_connections(connections)


def _collect_gcp(account: dict) -> tuple[list[dict], list[dict]]:
    try:
        import google.auth
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except Exception as exc:
        raise CloudCollectorUnavailable("GCP collector requires google-auth and google-api-python-client") from exc

    auth = _parse_auth_config(account)
    project_id = str(auth.get("project_id") or account.get("account_identifier") or "").strip()
    if not project_id:
        raise CloudCollectorAuthError("GCP project_id is required")

    credentials = None
    try:
        svc_json = auth.get("service_account_json")
        svc_file = str(auth.get("service_account_file") or "").strip()
        if isinstance(svc_json, dict) and svc_json:
            credentials = service_account.Credentials.from_service_account_info(
                svc_json,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        elif isinstance(svc_json, str) and svc_json.strip().startswith("{"):
            parsed = json.loads(svc_json)
            credentials = service_account.Credentials.from_service_account_info(
                parsed,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        elif svc_file:
            credentials = service_account.Credentials.from_service_account_file(
                svc_file,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        else:
            credentials, default_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            if not project_id and default_project:
                project_id = str(default_project)
    except Exception as exc:
        raise CloudCollectorAuthError("Failed to initialize GCP credentials") from exc

    if not project_id:
        raise CloudCollectorAuthError("GCP project_id is required")

    try:
        compute = build("compute", "v1", credentials=credentials, cache_discovery=False)
    except Exception as exc:
        raise CloudCollectorExecutionError("Failed to initialize GCP compute client") from exc

    resources: list[dict] = []
    connections: list[dict] = []

    # Networks
    try:
        req = compute.networks().list(project=project_id)
        while req is not None:
            resp = req.execute()
            for network in resp.get("items", []) or []:
                name = str(network.get("name") or "")
                uid = f"gcp:vpc:{project_id}:{name}"
                resources.append(
                    _normalize_resource(
                        "gcp",
                        uid,
                        "vpc",
                        name=name,
                        region="global",
                        cidr=str(network.get("IPv4Range") or ""),
                        status="active",
                    )
                )
                for peering in network.get("peerings", []) or []:
                    peer_url = str(peering.get("network") or "")
                    peer_name = peer_url.split("/")[-1] if peer_url else ""
                    if peer_name:
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                uid,
                                f"gcp:vpc:{project_id}:{peer_name}",
                                "vpc_peering",
                                state=str(peering.get("state") or ""),
                                metadata={"peering_name": str(peering.get("name") or "").strip()},
                            )
                        )
            req = compute.networks().list_next(previous_request=req, previous_response=resp)
    except Exception as exc:
        raise CloudCollectorAuthError("GCP network API access failed") from exc

    # Routers
    try:
        req = compute.routers().aggregatedList(project=project_id)
        while req is not None:
            resp = req.execute()
            for scoped in (resp.get("items") or {}).values():
                for router in scoped.get("routers", []) or []:
                    name = str(router.get("name") or "")
                    region_url = str(router.get("region") or "")
                    region = region_url.split("/")[-1] if region_url else ""
                    uid = f"gcp:cloud_router:{project_id}:{region}:{name}"
                    resources.append(
                        _normalize_resource(
                            "gcp",
                            uid,
                            "cloud_router",
                            name=name,
                            region=region,
                            status="running",
                        )
                    )
                    net_url = str(router.get("network") or "")
                    net_name = net_url.split("/")[-1] if net_url else ""
                    if net_name:
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                f"gcp:vpc:{project_id}:{net_name}",
                                uid,
                                "router_attachment",
                                state="up",
                            )
                        )
            req = compute.routers().aggregatedList_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed router list", exc_info=True)

    # VPN gateways
    try:
        req = compute.vpnGateways().aggregatedList(project=project_id)
        while req is not None:
            resp = req.execute()
            for scoped in (resp.get("items") or {}).values():
                for gateway in scoped.get("vpnGateways", []) or []:
                    name = str(gateway.get("name") or "")
                    region_url = str(gateway.get("region") or "")
                    region = region_url.split("/")[-1] if region_url else ""
                    uid = f"gcp:ha_vpn_gateway:{project_id}:{region}:{name}"
                    resources.append(
                        _normalize_resource(
                            "gcp",
                            uid,
                            "ha_vpn_gateway",
                            name=name,
                            region=region,
                            status="up",
                        )
                    )
                    net_url = str(gateway.get("network") or "")
                    net_name = net_url.split("/")[-1] if net_url else ""
                    if net_name:
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                f"gcp:vpc:{project_id}:{net_name}",
                                uid,
                                "vpn_tunnel",
                                state="up",
                            )
                        )
            req = compute.vpnGateways().aggregatedList_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed vpn gateway list", exc_info=True)

    try:
        req = compute.vpnTunnels().aggregatedList(project=project_id)
        while req is not None:
            resp = req.execute()
            for scoped in (resp.get("items") or {}).values():
                for tunnel in scoped.get("vpnTunnels", []) or []:
                    name = str(tunnel.get("name") or "")
                    region_url = str(tunnel.get("region") or "")
                    region = region_url.split("/")[-1] if region_url else ""
                    uid = f"gcp:vpn_tunnel:{project_id}:{region}:{name}"
                    resources.append(
                        _normalize_resource(
                            "gcp",
                            uid,
                            "vpn_tunnel",
                            name=name,
                            region=region,
                            status=str(tunnel.get("status") or ""),
                            metadata={"peer_ip": str(tunnel.get("peerIp") or "").strip()},
                        )
                    )
                    gateway_url = str(tunnel.get("vpnGateway") or tunnel.get("targetVpnGateway") or "")
                    if gateway_url:
                        gateway_name = gateway_url.split("/")[-1]
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                f"gcp:ha_vpn_gateway:{project_id}:{region}:{gateway_name}",
                                uid,
                                "vpn_gateway_attachment",
                                state=str(tunnel.get("status") or ""),
                            )
                        )
                    router_url = str(tunnel.get("router") or "")
                    if router_url:
                        router_name = router_url.split("/")[-1]
                        router_region = router_url.split("/")[-3] if "/regions/" in router_url else region
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                uid,
                                f"gcp:cloud_router:{project_id}:{router_region}:{router_name}",
                                "router_attachment",
                                state=str(tunnel.get("status") or ""),
                            )
                        )
            req = compute.vpnTunnels().aggregatedList_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed vpn tunnel list", exc_info=True)

    try:
        req = compute.interconnectAttachments().aggregatedList(project=project_id)
        while req is not None:
            resp = req.execute()
            for scoped in (resp.get("items") or {}).values():
                for attachment in scoped.get("interconnectAttachments", []) or []:
                    name = str(attachment.get("name") or "")
                    region_url = str(attachment.get("region") or "")
                    region = region_url.split("/")[-1] if region_url else ""
                    uid = f"gcp:interconnect_attachment:{project_id}:{region}:{name}"
                    resources.append(
                        _normalize_resource(
                            "gcp",
                            uid,
                            "interconnect_attachment",
                            name=name,
                            region=region,
                            status=str(attachment.get("operationalStatus") or attachment.get("state") or ""),
                            metadata={
                                "type": str(attachment.get("type") or "").strip(),
                                "bandwidth": str(attachment.get("bandwidth") or "").strip(),
                            },
                        )
                    )
                    router_url = str(attachment.get("router") or "")
                    if router_url:
                        router_name = router_url.split("/")[-1]
                        router_region = router_url.split("/")[-3] if "/regions/" in router_url else region
                        connections.append(
                            _normalize_connection(
                                "gcp",
                                f"gcp:cloud_router:{project_id}:{router_region}:{router_name}",
                                uid,
                                "interconnect_attachment",
                                state=str(attachment.get("operationalStatus") or attachment.get("state") or ""),
                            )
                        )
            req = compute.interconnectAttachments().aggregatedList_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed interconnect attachment list", exc_info=True)

    try:
        req = compute.routes().list(project=project_id)
        while req is not None:
            resp = req.execute()
            for route in resp.get("items", []) or []:
                name = str(route.get("name") or "")
                uid = f"gcp:route:{project_id}:{name}"
                network_url = str(route.get("network") or "")
                network_name = network_url.split("/")[-1] if network_url else ""
                destination = str(route.get("destRange") or "").strip()
                next_hop = str(
                    route.get("nextHopGateway")
                    or route.get("nextHopVpnTunnel")
                    or route.get("nextHopNetwork")
                    or route.get("nextHopPeering")
                    or route.get("nextHopIlb")
                    or route.get("nextHopIp")
                    or ""
                ).strip()
                resources.append(
                    _normalize_resource(
                        "gcp",
                        uid,
                        "route_entry",
                        name=name,
                        region="global",
                        cidr=destination,
                        status="active",
                        metadata={
                            "network": network_name,
                            "priority": route.get("priority"),
                            "next_hop": next_hop,
                        },
                    )
                )
                if network_name:
                    connections.append(
                        _normalize_connection(
                            "gcp",
                            f"gcp:vpc:{project_id}:{network_name}",
                            uid,
                            "route_table_association",
                            state="active",
                        )
                    )
                target_uid = ""
                if str(route.get("nextHopVpnTunnel") or "").strip():
                    tunnel_url = str(route.get("nextHopVpnTunnel") or "")
                    tunnel_name = tunnel_url.split("/")[-1]
                    tunnel_region = tunnel_url.split("/")[-3] if "/regions/" in tunnel_url else "global"
                    target_uid = f"gcp:vpn_tunnel:{project_id}:{tunnel_region}:{tunnel_name}"
                elif str(route.get("nextHopGateway") or "").strip():
                    gateway_url = str(route.get("nextHopGateway") or "")
                    gateway_name = gateway_url.split("/")[-1]
                    target_uid = f"gcp:internet_gateway:{gateway_name}"
                    resources.append(
                        _normalize_resource(
                            "gcp",
                            target_uid,
                            "internet_gateway",
                            name=gateway_name,
                            region="global",
                            status="active",
                        )
                    )
                elif str(route.get("nextHopNetwork") or "").strip():
                    target_url = str(route.get("nextHopNetwork") or "")
                    target_name = target_url.split("/")[-1]
                    target_uid = f"gcp:vpc:{project_id}:{target_name}"
                if target_uid:
                    connections.append(
                        _normalize_connection(
                            "gcp",
                            uid,
                            target_uid,
                            "route_next_hop",
                            state="active",
                            metadata={"destination": destination},
                        )
                    )
            req = compute.routes().list_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed route list", exc_info=True)

    # Firewall policies (network firewalls)
    try:
        req = compute.firewalls().list(project=project_id)
        while req is not None:
            resp = req.execute()
            for fw in resp.get("items", []) or []:
                name = str(fw.get("name") or "")
                net_url = str(fw.get("network") or "")
                net_name = net_url.split("/")[-1] if net_url else ""
                uid = f"gcp:firewall_policy:{project_id}:{name}"
                resources.append(
                    _normalize_resource(
                        "gcp",
                        uid,
                        "firewall_policy",
                        name=name,
                        region="global",
                        status="active",
                        metadata={
                            "network": net_name,
                            "policy_rules": _gcp_firewall_rules(fw, resource_uid=uid),
                        },
                    )
                )
                if net_name:
                    connections.append(
                        _normalize_connection(
                            "gcp",
                            f"gcp:vpc:{project_id}:{net_name}",
                            uid,
                            "security_boundary",
                            state="enforced",
                        )
                    )
            req = compute.firewalls().list_next(previous_request=req, previous_response=resp)
    except Exception:
        LOGGER.debug("gcp collector: failed firewall list", exc_info=True)

    return _dedupe_resources(resources), _dedupe_connections(connections)


def collect_provider_snapshot(account: dict) -> tuple[list[dict], list[dict]]:
    provider = str(account.get("provider") or "").strip().lower()
    if provider not in VALID_PROVIDERS:
        raise CloudCollectorExecutionError("Unsupported cloud provider")
    if provider == "aws":
        return _collect_aws(account)
    if provider == "azure":
        return _collect_azure(account)
    return _collect_gcp(account)


def get_provider_capabilities() -> dict[str, dict]:
    capabilities: dict[str, dict] = {}
    for provider in sorted(VALID_PROVIDERS):
        missing_dependencies: list[str] = []
        if provider == "aws":
            try:
                import boto3  # noqa: F401
            except Exception:
                missing_dependencies = ["boto3", "botocore"]
        elif provider == "azure":
            try:
                import azure.identity  # noqa: F401
                import azure.mgmt.network  # noqa: F401
            except Exception:
                missing_dependencies = ["azure-identity", "azure-mgmt-network"]
        else:
            try:
                import google.auth  # noqa: F401
                import googleapiclient.discovery  # noqa: F401
            except Exception:
                missing_dependencies = ["google-auth", "google-api-python-client"]

        capabilities[provider] = {
            "live_supported": not missing_dependencies,
            "missing_dependencies": missing_dependencies,
        }
    return capabilities
