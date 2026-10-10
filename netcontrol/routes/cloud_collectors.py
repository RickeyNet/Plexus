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

from netcontrol.integrations.aws import collect as aws_detail
from netcontrol.integrations.azure import collect as azure_detail
from netcontrol.integrations.gcp import collect as gcp_detail
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cloud_collectors")

VALID_PROVIDERS = {"aws", "azure", "gcp"}


class CloudCollectorError(RuntimeError):
    """Base class for collector failures."""


class CloudCollectorUnavailable(CloudCollectorError):
    """Raised when required SDK dependencies are not installed."""


class CloudCollectorAuthError(CloudCollectorError):
    """Raised for provider authentication/authorization failures.

    ``user_message`` is set when Plexus can say exactly what is wrong (an
    expired session token, no credentials on the server); it is fixed text
    written here, never the provider's error message, so it is safe to show.
    """

    def __init__(self, message: str, *, user_message: str = "") -> None:
        super().__init__(message)
        self.user_message = user_message


# AWS error codes for temporary credentials past their expiry.
_AWS_EXPIRED_CODES = {"ExpiredToken", "ExpiredTokenException", "RequestExpired", "TokenRefreshRequired"}
AWS_EXPIRED_TOKEN_MESSAGE = (
    "The AWS session token has expired. Edit the account and enter a fresh access key, secret and session token."
)
AWS_SSO_EXPIRED_MESSAGE = (
    "The AWS SSO sign-in of the Plexus server has expired. Run 'aws sso login' on the server, then try again."
)
AWS_NO_CREDENTIALS_MESSAGE = (
    "No AWS credentials were found on the Plexus server. Enter credentials for the account, "
    "or configure them on the server (environment variables, ~/.aws/credentials or an SSO profile)."
)


def aws_credential_message(exc: BaseException) -> str:
    """What to tell the user about an AWS sign-in failure, or ``""`` when
    nothing more specific than "authentication failed" is known."""
    try:
        from botocore.exceptions import NoCredentialsError, SSOError, TokenRetrievalError
    except Exception:  # pragma: no cover - boto3 missing is reported elsewhere
        return ""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (SSOError, TokenRetrievalError)):
            return AWS_SSO_EXPIRED_MESSAGE
        if isinstance(current, NoCredentialsError):
            return AWS_NO_CREDENTIALS_MESSAGE
        response = getattr(current, "response", None)
        code = ((response or {}).get("Error") or {}).get("Code") if isinstance(response, dict) else None
        if code in _AWS_EXPIRED_CODES:
            return AWS_EXPIRED_TOKEN_MESSAGE
        current = current.__cause__ or current.__context__
    return ""


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


def _peering_cidrs(vpc_info: dict) -> list[str]:
    """Every IPv4 and IPv6 range one end of a VPC peering reports, the
    primary first."""
    cidrs = [str(vpc_info.get("CidrBlock") or "").strip()]
    cidrs += [str(c.get("CidrBlock") or "").strip() for c in vpc_info.get("CidrBlockSet") or []]
    cidrs += [str(c.get("Ipv6CidrBlock") or "").strip() for c in vpc_info.get("Ipv6CidrBlockSet") or []]
    return list(dict.fromkeys(c for c in cidrs if c))


def _is_all_regions(region_scope: str | None) -> bool:
    """A region scope of ``all`` (or ``*``) reads every region enabled for the account."""
    return str(region_scope or "").strip().lower() in {"all", "*"}


def _aws_enabled_regions(session, config=None) -> list[str]:
    """The regions enabled for the account of ``session`` (``ec2:DescribeRegions``)."""
    home = getattr(session, "region_name", None)
    ec2 = session.client("ec2", region_name=home if isinstance(home, str) and home else "us-east-1", config=config)
    # Without AllRegions only the regions the account can use are returned.
    listed = ec2.describe_regions().get("Regions") or []
    return sorted({str(r.get("RegionName") or "").strip() for r in listed} - {""})


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
            raw_current_meta = current.get("metadata")
            raw_next_meta = resource.get("metadata")
            current_meta = raw_current_meta if isinstance(raw_current_meta, dict) else {}
            next_meta = raw_next_meta if isinstance(raw_next_meta, dict) else {}
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
            raw_current_meta = merged[key].get("metadata")
            raw_next_meta = edge.get("metadata")
            current_meta = raw_current_meta if isinstance(raw_current_meta, dict) else {}
            next_meta = raw_next_meta if isinstance(raw_next_meta, dict) else {}
            merged[key]["metadata"] = {**current_meta, **next_meta}
    return list(merged.values())


def _aws_tag_name(tags: list[dict] | None) -> str:
    if not tags:
        return ""
    for tag in tags:
        if str(tag.get("Key") or "").lower() == "name":
            return str(tag.get("Value") or "")
    return ""


def _aws_list_all(client, operation: str, result_key: str, **kwargs) -> list[dict]:
    """Return all pages of an AWS list/describe call (paginated when supported)."""
    if client.can_paginate(operation):
        items: list[dict] = []
        for page in client.get_paginator(operation).paginate(**kwargs):
            items.extend(page.get(result_key) or [])
        return items
    resp = getattr(client, operation)(**kwargs)
    return list(resp.get(result_key) or [])


def _collect_aws_map_detail(session, ec2, region: str, cfg, resources: list[dict], connections: list[dict]) -> None:
    """Detail the Topology map uses: subnets, instances, customer gateways and
    how Direct Connect reaches a gateway.

    These sections were added after the base discovery and need permissions
    an existing read-only policy may lack (``ec2:DescribeInstances`` is not
    part of the VPC read-only policy). One that cannot be read is skipped and
    recorded as a ``collection_warning`` resource; it never fails discovery.
    """

    def optional(section: str, read) -> None:
        try:
            read()
        except Exception as exc:  # noqa: BLE001 - best-effort detail; discovery goes on
            LOGGER.warning(
                "aws collector: skipped %s region=%s: %s", section, region, aws_detail.error_code(exc), exc_info=True
            )
            resources.append(aws_detail.warning_resource(section, region, exc))

    def subnets() -> None:
        for subnet in _aws_list_all(ec2, "describe_subnets", "Subnets"):
            resource = aws_detail.subnet_resource(subnet, region)
            if resource:
                resources.append(resource)

    def instances() -> None:
        for reservation in _aws_list_all(ec2, "describe_instances", "Reservations"):
            for instance in reservation.get("Instances") or []:
                resource = aws_detail.instance_resource(instance, region)
                if resource:
                    resources.append(resource)

    def customer_gateways() -> None:
        for gateway in _aws_list_all(ec2, "describe_customer_gateways", "CustomerGateways"):
            resource = aws_detail.customer_gateway_resource(gateway, region)
            if resource:
                resources.append(resource)

    def direct_connect() -> None:
        dx = session.client("directconnect", region_name=region, config=cfg)
        for vif in _aws_list_all(dx, "describe_virtual_interfaces", "virtualInterfaces"):
            conn_id = str(vif.get("connectionId") or "").strip()
            vgw_id = str(vif.get("virtualGatewayId") or "").strip()
            dxgw_id = str(vif.get("directConnectGatewayId") or "").strip()
            target = f"aws:direct-connect-gateway:{dxgw_id}" if dxgw_id else f"aws:vpn_gateway:{vgw_id}"
            if not conn_id or not (dxgw_id or vgw_id):
                continue
            connections.append(
                _normalize_connection(
                    "aws",
                    f"aws:direct_connect:{conn_id}",
                    target,
                    "direct_connect_virtual_interface",
                    state=str(vif.get("virtualInterfaceState") or ""),
                    metadata=aws_detail.virtual_interface_metadata(vif),
                )
            )
        for gateway in _aws_list_all(dx, "describe_direct_connect_gateways", "directConnectGateways"):
            dxgw_id = str(gateway.get("directConnectGatewayId") or "").strip()
            if not dxgw_id:
                continue
            dxgw_uid = f"aws:direct-connect-gateway:{dxgw_id}"
            resources.append(
                _normalize_resource(
                    "aws",
                    dxgw_uid,
                    "direct_connect_gateway",
                    name=str(gateway.get("directConnectGatewayName") or dxgw_id),
                    # A Direct Connect gateway is global; every region lists it.
                    region="global",
                    status=str(gateway.get("directConnectGatewayState") or ""),
                    metadata={
                        "amazon_asn": str(gateway.get("amazonSideAsn") or "").strip(),
                        "owner_id": str(gateway.get("ownerAccount") or "").strip(),
                    },
                )
            )
            for association in _aws_list_all(
                dx,
                "describe_direct_connect_gateway_associations",
                "directConnectGatewayAssociations",
                directConnectGatewayId=dxgw_id,
            ):
                associated = association.get("associatedGateway") or {}
                gateway_id = str(associated.get("id") or "").strip()
                if not gateway_id:
                    continue
                kind = "tgw" if str(associated.get("type") or "") == "transitGateway" else "vpn_gateway"
                connections.append(
                    _normalize_connection(
                        "aws",
                        dxgw_uid,
                        f"aws:{kind}:{gateway_id}",
                        "direct_connect_gateway_association",
                        state=str(association.get("associationState") or ""),
                        metadata={"region": str(associated.get("region") or "").strip()},
                    )
                )

    def network_acls() -> None:
        for acl in _aws_list_all(ec2, "describe_network_acls", "NetworkAcls"):
            resource = aws_detail.network_acl_resource(acl, region)
            if resource:
                resources.append(resource)

    def transit_gateway_route_tables() -> None:
        for table in _aws_list_all(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"):
            table_id = str(table.get("TransitGatewayRouteTableId") or "").strip()
            if not table_id:
                continue
            found = ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=table_id,
                Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
                MaxResults=1000,
            )
            resource = aws_detail.transit_gateway_route_table_resource(
                table, list(found.get("Routes") or []), bool(found.get("AdditionalRoutesAvailable")), region
            )
            if resource:
                resources.append(resource)

    optional("subnets", subnets)
    optional("instances", instances)
    optional("customer_gateways", customer_gateways)
    optional("direct_connect_gateways", direct_connect)
    optional("network_acls", network_acls)
    optional("transit_gateway_route_tables", transit_gateway_route_tables)


def _collect_aws(account: dict) -> tuple[list[dict], list[dict]]:
    try:
        import boto3
        from botocore.config import Config
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

    _cfg = Config(connect_timeout=10, read_timeout=60, retries={"max_attempts": 4, "mode": "adaptive"})

    role_arn = str(auth.get("role_arn") or "").strip()
    external_id = str(auth.get("external_id") or "").strip()
    if role_arn:
        try:
            sts = session.client("sts", config=_cfg)
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
            raise CloudCollectorAuthError(
                "Failed to assume AWS IAM role", user_message=aws_credential_message(exc)
            ) from exc

    # Validate credentials early.
    try:
        session.client("sts", config=_cfg).get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        raise CloudCollectorAuthError(
            "AWS credentials are invalid or unauthorized", user_message=aws_credential_message(exc)
        ) from exc
    except Exception as exc:
        raise CloudCollectorExecutionError("Failed to validate AWS credentials") from exc

    region_scope = str(account.get("region_scope") or "")
    if _is_all_regions(region_scope):
        try:
            regions = _aws_enabled_regions(session, _cfg)
        except Exception as exc:
            raise CloudCollectorExecutionError("Failed to list the AWS regions (ec2:DescribeRegions)") from exc
        if not regions:
            raise CloudCollectorExecutionError("AWS returned no enabled regions")
    else:
        regions = _parse_region_scope(region_scope) or ["us-east-1"]

    resources: list[dict] = []
    connections: list[dict] = []
    section_errors: list[str] = []

    for region in regions:
        ec2 = session.client("ec2", region_name=region, config=_cfg)
        try:
            vpcs = _aws_list_all(ec2, "describe_vpcs", "Vpcs")
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed vpc list region=%s", region, exc_info=True)
            section_errors.append(f"vpcs:{region}")

        try:
            igws = _aws_list_all(ec2, "describe_internet_gateways", "InternetGateways")
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
                            "vpc_ids": [
                                str(item.get("VpcId") or "").strip()
                                for item in attachments
                                if str(item.get("VpcId") or "").strip()
                            ],
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed internet gateway list region=%s", region, exc_info=True)
            section_errors.append(f"internet_gateways:{region}")

        try:
            nat_gateways = _aws_list_all(ec2, "describe_nat_gateways", "NatGateways")
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
                            **aws_detail.nat_gateway_addresses(gateway),
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed nat gateway list region=%s", region, exc_info=True)
            section_errors.append(f"nat_gateways:{region}")

        try:
            sec_groups = _aws_list_all(ec2, "describe_security_groups", "SecurityGroups")
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed security group list region=%s", region, exc_info=True)
            section_errors.append(f"security_groups:{region}")

        try:
            tgws = _aws_list_all(ec2, "describe_transit_gateways", "TransitGateways")
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
                        metadata={
                            "owner_id": str(tgw.get("OwnerId") or "").strip(),
                            "amazon_asn": str((tgw.get("Options") or {}).get("AmazonSideAsn") or "").strip(),
                        },
                    )
                )
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed tgw list region=%s", region, exc_info=True)
            section_errors.append(f"transit_gateways:{region}")

        try:
            attachments = _aws_list_all(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
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
                        metadata={
                            "attachment_id": str(attachment.get("TransitGatewayAttachmentId") or "").strip(),
                            "resource_type": res_type,
                            "resource_id": res_id,
                            "resource_owner_id": str(attachment.get("ResourceOwnerId") or "").strip(),
                            # The transit gateway route table that routes what arrives here.
                            "route_table_id": str(
                                (attachment.get("Association") or {}).get("TransitGatewayRouteTableId") or ""
                            ).strip(),
                        },
                    )
                )
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed tgw attachment list region=%s", region, exc_info=True)
            section_errors.append(f"transit_gateway_attachments:{region}")

        try:
            peerings = _aws_list_all(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections")
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
                        metadata={
                            "peering_id": str(peering.get("VpcPeeringConnectionId") or ""),
                            "requester_cidr": str(req.get("CidrBlock") or ""),
                            "requester_cidrs": _peering_cidrs(req),
                            "requester_owner_id": str(req.get("OwnerId") or ""),
                            "requester_region": str(req.get("Region") or ""),
                            "accepter_cidr": str(acc.get("CidrBlock") or ""),
                            "accepter_cidrs": _peering_cidrs(acc),
                            "accepter_owner_id": str(acc.get("OwnerId") or ""),
                            "accepter_region": str(acc.get("Region") or ""),
                        },
                    )
                )
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed vpc peering list region=%s", region, exc_info=True)
            section_errors.append(f"vpc_peering_connections:{region}")

        try:
            vpn_gateways = _aws_list_all(ec2, "describe_vpn_gateways", "VpnGateways")
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
                            "vpc_ids": [
                                str(item.get("VpcId") or "").strip()
                                for item in attachments
                                if str(item.get("VpcId") or "").strip()
                            ],
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed vpn gateway list region=%s", region, exc_info=True)
            section_errors.append(f"vpn_gateways:{region}")

        try:
            route_tables = _aws_list_all(ec2, "describe_route_tables", "RouteTables")
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
                            **aws_detail.route_table_detail(route_table),
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed route table list region=%s", region, exc_info=True)
            section_errors.append(f"route_tables:{region}")

        try:
            vpns = _aws_list_all(ec2, "describe_vpn_connections", "VpnConnections")
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
                        metadata=aws_detail.vpn_connection_metadata(vpn),
                    )
                )
                tgw_id = str(vpn.get("TransitGatewayId") or "").strip()
                vgw_id = str(vpn.get("VpnGatewayId") or "").strip()
                cgw_id = str(vpn.get("CustomerGatewayId") or "").strip()
                if cgw_id:
                    connections.append(
                        _normalize_connection(
                            "aws",
                            vpn_uid,
                            f"aws:customer_gateway:{cgw_id}",
                            "customer_gateway_attachment",
                            state=str(vpn.get("State") or ""),
                        )
                    )
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
        except BotoCoreError, ClientError:
            LOGGER.warning("aws collector: failed vpn list region=%s", region, exc_info=True)
            section_errors.append(f"vpn_connections:{region}")

        # Direct Connect is region-bound; query every configured region.
        try:
            dx = session.client("directconnect", region_name=region, config=_cfg)
            dx_connections = _aws_list_all(dx, "describe_connections", "connections")
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
                        region=str(dx_conn.get("region") or region),
                        status=str(dx_conn.get("connectionState") or ""),
                        metadata={"bandwidth": str(dx_conn.get("bandwidth") or "")},
                    )
                )
        except Exception:
            LOGGER.warning("aws collector: failed direct connect list region=%s", region, exc_info=True)
            section_errors.append(f"direct_connect:{region}")

        _collect_aws_map_detail(session, ec2, region, _cfg, resources, connections)

    # A partial snapshot must not silently replace the last known-good one; the
    # discover endpoint keeps the previous snapshot and surfaces this message on failure.
    if section_errors:
        raise CloudCollectorExecutionError(
            "Partial provider discovery; failed sections: " + ", ".join(sorted(set(section_errors)))
        )

    return _dedupe_resources(resources), _dedupe_connections(connections)


def _collect_azure(account: dict) -> tuple[list[dict], list[dict]]:
    """Discover one Azure subscription with the Network API.

    The base sections (virtual networks and their subnets and peerings,
    ExpressRoute circuits, virtual and local network gateways, route tables,
    network security groups, gateway connections) fail the discovery when
    they cannot be read. The map detail (public IP addresses, NAT gateways,
    network interfaces, Azure Firewalls) is best-effort: a section that
    cannot be read is skipped and recorded as a ``collection_warning``
    resource.
    """
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
    except Exception as exc:
        raise CloudCollectorUnavailable("Azure collector requires azure-identity and azure-mgmt-network") from exc

    auth = _parse_auth_config(account)
    subscription_id = str(auth.get("subscription_id") or account.get("account_identifier") or "").strip()
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

    return _collect_azure_network(network_client, subscription_id)


def _collect_azure_network(network_client, subscription_id: str) -> tuple[list[dict], list[dict]]:
    """The discovery itself, on an initialised ``NetworkManagementClient``."""
    resources: list[dict] = []
    connections: list[dict] = []
    section_errors: list[str] = []
    public_ips: dict[str, str] = {}

    def optional(section: str, read) -> None:
        try:
            read()
        except Exception as exc:  # noqa: BLE001 - best-effort detail; discovery goes on
            LOGGER.warning("azure collector: skipped %s: %s", section, azure_detail.error_code(exc), exc_info=True)
            resources.append(azure_detail.warning_resource(section, exc))

    def public_ip_addresses() -> None:
        public_ips.update(azure_detail.public_ip_table(network_client.public_ip_addresses.list_all()))

    # Gateways, NAT gateways, firewalls and NICs name their public IPs by ID.
    optional("public_ip_addresses", public_ip_addresses)

    try:
        for vnet in network_client.virtual_networks.list_all():
            resource = azure_detail.vnet_resource(vnet, subscription_id)
            if not resource:
                continue
            resources.append(resource)
            resources.extend(azure_detail.subnet_resources(vnet, subscription_id))
            group = resource["metadata"].get("resource_group") or ""
            name = resource["name"]
            # VNet peerings for hybrid graph edges.
            try:
                if group and name:
                    for peering in network_client.virtual_network_peerings.list(group, name):
                        conn = azure_detail.peering_connection(resource["resource_uid"], peering, subscription_id)
                        if conn:
                            connections.append(conn)
            except Exception:
                LOGGER.warning("azure collector: failed to list peerings for vnet=%s", name, exc_info=True)
                section_errors.append("vnet_peerings")
    except Exception as exc:
        raise CloudCollectorAuthError("Azure network API access failed") from exc

    try:
        for circuit in network_client.express_route_circuits.list_all():
            resource = azure_detail.express_route_resource(circuit, subscription_id)
            if resource:
                resources.append(resource)
    except Exception:
        LOGGER.warning("azure collector: failed to list expressroute circuits", exc_info=True)
        section_errors.append("expressroute_circuits")

    try:
        for gateway in network_client.virtual_network_gateways.list_all():
            resource = azure_detail.virtual_network_gateway_resource(gateway, subscription_id, public_ips)
            if not resource:
                continue
            resources.append(resource)
            attachment = azure_detail.gateway_attachment(resource)
            if attachment:
                connections.append(attachment)
    except Exception:
        LOGGER.warning("azure collector: failed to list virtual network gateways", exc_info=True)
        section_errors.append("virtual_network_gateways")

    try:
        for gateway in network_client.local_network_gateways.list_all():
            resource = azure_detail.local_network_gateway_resource(gateway, subscription_id)
            if resource:
                resources.append(resource)
    except Exception:
        LOGGER.warning("azure collector: failed to list local network gateways", exc_info=True)
        section_errors.append("local_network_gateways")

    try:
        for route_table in network_client.route_tables.list_all():
            resource = azure_detail.route_table_resource(route_table, subscription_id)
            if not resource:
                continue
            resources.append(resource)
            connections.extend(azure_detail.route_table_associations(resource))
    except Exception:
        LOGGER.warning("azure collector: failed to list route tables", exc_info=True)
        section_errors.append("route_tables")

    try:
        for nsg in network_client.network_security_groups.list_all():
            resource = azure_detail.nsg_resource(nsg, subscription_id)
            if resource:
                resources.append(resource)
    except Exception:
        LOGGER.warning("azure collector: failed to list nsgs", exc_info=True)
        section_errors.append("network_security_groups")

    try:
        gateway_connections = getattr(network_client, "virtual_network_gateway_connections", None)
        if gateway_connections is not None:
            for conn in gateway_connections.list_all():
                record = azure_detail.gateway_connection(conn, subscription_id)
                if record:
                    connections.append(record)
    except Exception:
        LOGGER.warning("azure collector: failed to list gateway connections", exc_info=True)
        section_errors.append("gateway_connections")

    def nat_gateways() -> None:
        for gateway in network_client.nat_gateways.list_all():
            resource = azure_detail.nat_gateway_resource(gateway, subscription_id, public_ips)
            if resource:
                resources.append(resource)
                connections.extend(azure_detail.nat_gateway_attachments(resource))

    def virtual_machines() -> None:
        nics = list(network_client.network_interfaces.list_all())
        resources.extend(azure_detail.vm_resources(nics, subscription_id, public_ips))

    def firewalls() -> None:
        for firewall in network_client.azure_firewalls.list_all():
            resource = azure_detail.firewall_resource(firewall, subscription_id, public_ips)
            if resource:
                resources.append(resource)

    optional("nat_gateways", nat_gateways)
    optional("network_interfaces", virtual_machines)
    optional("azure_firewalls", firewalls)

    # A partial snapshot must not silently replace the last known-good one; the
    # discover endpoint keeps the previous snapshot and surfaces this message on failure.
    if section_errors:
        raise CloudCollectorExecutionError(
            "Partial provider discovery; failed sections: " + ", ".join(sorted(set(section_errors)))
        )

    return _dedupe_resources(resources), _dedupe_connections(connections)


def _collect_gcp(account: dict) -> tuple[list[dict], list[dict]]:
    """Discover one GCP project with the Compute Engine API.

    Signs in with the service account key (JSON or a file on the server) of
    the account, else with the server's application default credentials,
    and hands the built ``compute`` client to ``_collect_gcp_compute``.
    """
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

    return _collect_gcp_compute(compute, project_id)


def _gcp_pages(collection, method: str, **kwargs):
    """Every page of a Compute Engine list call (``list`` / ``aggregatedList``)."""
    request = getattr(collection, method)(**kwargs)
    while request is not None:
        response = request.execute() or {}
        yield response
        request = getattr(collection, f"{method}_next")(previous_request=request, previous_response=response)


def _gcp_list(compute, resource: str, project_id: str) -> list[dict]:
    """The items of a global (project-wide) list call, every page."""
    collection = getattr(compute, resource)()
    return [item for page in _gcp_pages(collection, "list", project=project_id) for item in page.get("items") or []]


def _gcp_aggregated(compute, resource: str, project_id: str) -> list[dict]:
    """The items of an aggregated list call across every region or zone. A
    scope with nothing in it carries a ``warning`` instead of items."""
    collection = getattr(compute, resource)()
    found: list[dict] = []
    for page in _gcp_pages(collection, "aggregatedList", project=project_id):
        for scoped in (page.get("items") or {}).values():
            found.extend(item for item in (scoped or {}).get(resource) or [] if isinstance(item, dict))
    return found


def _collect_gcp_compute(compute, project_id: str) -> tuple[list[dict], list[dict]]:
    """The discovery itself, on a built Compute Engine ``compute`` client.

    The base sections (networks with their peerings, subnetworks, routes and
    firewall rules) fail the discovery when they cannot be read. The map
    detail (Cloud Routers and their status, HA and Classic VPN gateways, VPN
    tunnels, external VPN gateways, Interconnect attachments, Interconnects,
    VM instances and network firewall policies) is best-effort: a section
    that cannot be read is skipped and recorded as a ``collection_warning``
    resource.
    """
    sections: dict[str, Any] = {}
    warnings: list[dict] = []
    section_errors: list[str] = []

    def optional(section: str, read) -> None:
        try:
            sections[section] = read()
        except Exception as exc:  # noqa: BLE001 - best-effort detail; discovery goes on
            LOGGER.warning("gcp collector: skipped %s: %s", section, gcp_detail.error_code(exc), exc_info=True)
            warnings.append(gcp_detail.warning_resource(section, exc))

    try:
        sections["networks"] = _gcp_list(compute, "networks", project_id)
    except Exception as exc:
        raise CloudCollectorAuthError("GCP network API access failed") from exc

    for section, read in (
        ("subnetworks", lambda: _gcp_aggregated(compute, "subnetworks", project_id)),
        ("routes", lambda: _gcp_list(compute, "routes", project_id)),
        ("firewalls", lambda: _gcp_list(compute, "firewalls", project_id)),
    ):
        try:
            sections[section] = read()
        except Exception:
            LOGGER.warning("gcp collector: failed %s list", section, exc_info=True)
            section_errors.append(section)

    def routers() -> list[tuple[dict, dict | None]]:
        found = _gcp_aggregated(compute, "routers", project_id)
        statuses: list[tuple[dict, dict | None]] = []
        failed: Exception | None = None
        for router in found:
            status = None
            region = gcp_detail.link_scope(router.get("region"))
            if failed is None and region and router.get("name"):
                try:
                    answer = (
                        compute.routers()
                        .getRouterStatus(project=project_id, region=region, router=router["name"])
                        .execute()
                    )
                    status = (answer or {}).get("result") or {}
                except Exception as exc:  # noqa: BLE001 - BGP state and learned routes are detail
                    failed = exc
            statuses.append((router, status))
        if failed is not None:
            LOGGER.warning("gcp collector: skipped router_status: %s", gcp_detail.error_code(failed))
            warnings.append(gcp_detail.warning_resource("router_status", failed))
        return statuses

    def network_firewall_policies() -> list[dict]:
        return _gcp_list(compute, "networkFirewallPolicies", project_id)

    optional("routers", routers)
    optional("vpn_gateways", lambda: _gcp_aggregated(compute, "vpnGateways", project_id))
    optional("target_vpn_gateways", lambda: _gcp_aggregated(compute, "targetVpnGateways", project_id))
    optional("vpn_tunnels", lambda: _gcp_aggregated(compute, "vpnTunnels", project_id))
    optional("external_vpn_gateways", lambda: _gcp_list(compute, "externalVpnGateways", project_id))
    optional("interconnect_attachments", lambda: _gcp_aggregated(compute, "interconnectAttachments", project_id))
    optional("interconnects", lambda: _gcp_list(compute, "interconnects", project_id))
    optional("instances", lambda: _gcp_aggregated(compute, "instances", project_id))
    optional("network_firewall_policies", network_firewall_policies)

    # A partial snapshot must not silently replace the last known-good one; the
    # discover endpoint keeps the previous snapshot and surfaces this message on failure.
    if section_errors:
        raise CloudCollectorExecutionError(
            "Partial provider discovery; failed sections: " + ", ".join(sorted(set(section_errors)))
        )

    resources, connections = gcp_detail.assemble(project_id, **sections)
    return _dedupe_resources(resources + warnings), _dedupe_connections(connections)


def collect_provider_snapshot(account: dict) -> tuple[list[dict], list[dict]]:
    provider = str(account.get("provider") or "").strip().lower()
    if provider not in VALID_PROVIDERS:
        raise CloudCollectorExecutionError("Unsupported cloud provider")
    if provider == "aws":
        return _collect_aws(account)
    if provider == "azure":
        return _collect_azure(account)
    return _collect_gcp(account)


def _importable(module_name: str) -> bool:
    import importlib

    try:
        importlib.import_module(module_name)
        return True
    except Exception:
        return False


# module to check -> pip distribution name, per provider feature area.
_PROVIDER_DEPENDENCIES: dict[str, dict[str, dict[str, str]]] = {
    "aws": {
        "topology": {"boto3": "boto3"},
        "flow_logs": {"boto3": "boto3"},
        "traffic_metrics": {"boto3": "boto3"},
    },
    "azure": {
        "topology": {"azure.identity": "azure-identity", "azure.mgmt.network": "azure-mgmt-network"},
        "flow_logs": {"azure.storage.blob": "azure-storage-blob"},
        "traffic_metrics": {"azure.monitor.query": "azure-monitor-query"},
    },
    "gcp": {
        "topology": {"google.auth": "google-auth", "googleapiclient.discovery": "google-api-python-client"},
        "flow_logs": {"google.cloud.logging": "google-cloud-logging"},
        "traffic_metrics": {"google.cloud.monitoring_v3": "google-cloud-monitoring"},
    },
}


def get_provider_capabilities() -> dict[str, dict]:
    capabilities: dict[str, dict] = {}
    for provider in sorted(VALID_PROVIDERS):
        deps = _PROVIDER_DEPENDENCIES.get(provider, {})
        features: dict[str, dict] = {}
        all_missing: list[str] = []
        for feature, modules in deps.items():
            missing = sorted({dist for module, dist in modules.items() if not _importable(module)})
            features[feature] = {"supported": not missing, "missing_dependencies": missing}
            all_missing.extend(missing)

        topology_missing = features.get("topology", {}).get("missing_dependencies", [])
        capabilities[provider] = {
            # Kept for backward compatibility: "live" refers to topology discovery.
            "live_supported": not topology_missing,
            "missing_dependencies": topology_missing,
            "features": features,
        }
    return capabilities
