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
from collections.abc import Callable
from typing import Any

from netcontrol.integrations.aws import collect as aws_detail
from netcontrol.integrations.aws.failures import FAILED, PERMISSION, UNAVAILABLE, OperationNotInSdk
from netcontrol.integrations.azure import collect as azure_detail
from netcontrol.integrations.gcp import collect as gcp_detail
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cloud_collectors")

VALID_PROVIDERS = {"aws", "azure", "gcp"}

# Receives progress fields (``phase`` and phase-specific counts) while a collector runs.
# Collectors run in a worker thread, so the callback must be thread-safe.
ProgressCallback = Callable[[dict[str, Any]], None]


def _report(progress: ProgressCallback | None, **fields: Any) -> None:
    """Send progress fields to the callback; a failing callback never stops discovery."""
    if progress is None:
        return
    try:
        progress(fields)
    except Exception:
        LOGGER.debug("cloud discovery progress callback failed", exc_info=True)


class CloudCollectorError(RuntimeError):
    """Base class for collector failures.

    ``user_message`` is what the UI shows: fixed text written here, the
    account's own section and region names, and the provider's error code
    and message (``provider_error_detail``, never a traceback). Discovery and
    validation are admin-only and describe the admin's own cloud account.
    """

    def __init__(self, message: str, *, user_message: str = "") -> None:
        super().__init__(message)
        self.user_message = user_message


class CloudCollectorUnavailable(CloudCollectorError):
    """Raised when required SDK dependencies are not installed."""


class CloudCollectorAuthError(CloudCollectorError):
    """Raised for provider authentication/authorization failures, e.g. an
    expired session token or no credentials on the server."""


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


_DETAIL_MAX_CHARS = 400


def provider_error_detail(exc: BaseException) -> str:
    """The provider's error code and message, for an admin to act on.

    AWS (botocore ``ClientError``) gives ``Code: Message``, e.g.
    ``AccessDeniedException: User ... is not authorized to perform:
    directconnect:DescribeConnections``. Azure and Google SDK errors give
    their first line. Anything else gives its class name and first line.
    Never the traceback; whitespace is collapsed and the text is capped.
    """
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    if isinstance(error, dict) and (error.get("Code") or error.get("Message")):
        text = ": ".join(str(part) for part in (error.get("Code"), error.get("Message")) if part)
    else:
        first_line = next((line for line in str(exc).splitlines() if line.strip()), "")
        text = f"{type(exc).__name__}: {first_line}" if first_line else type(exc).__name__
    text = " ".join(text.split())
    if len(text) > _DETAIL_MAX_CHARS:
        text = text[: _DETAIL_MAX_CHARS - 3] + "..."
    return text


def _partial_discovery_error(section_errors: list[tuple[str, str]]) -> CloudCollectorExecutionError:
    """The error for a discovery where some sections failed.

    ``section_errors`` holds ``(label, provider_error_detail)`` pairs. Labels
    that failed with the same error (one permission missing in every region)
    are grouped, so the message names each distinct problem once.
    """
    by_detail: dict[str, set[str]] = {}
    for label, detail in section_errors:
        by_detail.setdefault(detail, set()).add(label)
    labels = sorted({label for label, _detail in section_errors})
    problems = "; ".join(
        f"{', '.join(sorted(group))} ({detail})"
        for detail, group in sorted(by_detail.items(), key=lambda kv: sorted(kv[1]))
    )
    return CloudCollectorExecutionError(
        "Partial provider discovery; failed sections: " + ", ".join(labels),
        user_message=f"Live provider discovery failed reading: {problems}",
    )


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


def _aws_call(client, operation: str, **kwargs) -> dict:
    """One AWS call; an operation the installed botocore lacks is reported
    as such (``OperationNotInSdk``), not as an ``AttributeError``."""
    method = getattr(client, operation, None)
    if method is None:
        raise OperationNotInSdk(operation)
    return method(**kwargs) or {}


def _aws_list_all(client, operation: str, result_key: str, **kwargs) -> list[dict]:
    """Return all pages of an AWS list/describe call (paginated when supported)."""
    if client.can_paginate(operation):
        items: list[dict] = []
        for page in client.get_paginator(operation).paginate(**kwargs):
            items.extend(page.get(result_key) or [])
        return items
    return list(_aws_call(client, operation, **kwargs).get(result_key) or [])


# The most values one EC2 ``Describe*`` filter takes.
_AWS_FILTER_VALUES_MAX = 200
# The most domains one OpenSearch ``DescribeDomains`` call takes.
_OPENSEARCH_DESCRIBE_MAX = 5

# The best-effort AWS sections: key -> (what it adds, for the report; the IAM
# actions it calls). A section AWS refuses is skipped and reported with these
# actions, so an admin knows what to add. ``docs/aws-topology.md`` lists the
# same actions (a test keeps them in step).
AWS_OPTIONAL_SECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "subnets": ("Subnets", ("ec2:DescribeSubnets",)),
    "instances": ("EC2 instances", ("ec2:DescribeInstances",)),
    "customer_gateways": ("Customer gateways", ("ec2:DescribeCustomerGateways",)),
    "direct_connect_gateways": (
        "Direct Connect virtual interfaces and gateways",
        (
            "directconnect:DescribeVirtualInterfaces",
            "directconnect:DescribeDirectConnectGateways",
            "directconnect:DescribeDirectConnectGatewayAssociations",
        ),
    ),
    "network_acls": ("Network ACLs", ("ec2:DescribeNetworkAcls",)),
    "transit_gateway_route_tables": (
        "Transit gateway route tables",
        ("ec2:DescribeTransitGatewayRouteTables", "ec2:SearchTransitGatewayRoutes"),
    ),
    "fsx_file_systems": ("FSx file systems", ("fsx:DescribeFileSystems",)),
    "fsx_network_interfaces": ("Addresses of FSx file systems", ("ec2:DescribeNetworkInterfaces",)),
    "fsx_storage_virtual_machines": ("FSx storage virtual machines", ("fsx:DescribeStorageVirtualMachines",)),
    "rds_db_instances": ("RDS and Aurora DB instances", ("rds:DescribeDBInstances",)),
    "rds_db_clusters": ("Aurora and Multi-AZ DB clusters", ("rds:DescribeDBClusters",)),
    "rds_db_subnet_groups": ("VPCs of DB clusters", ("rds:DescribeDBSubnetGroups",)),
    "rds_db_proxies": ("RDS proxies", ("rds:DescribeDBProxies",)),
    "load_balancers": (
        "Application, Network and Gateway Load Balancers",
        ("elasticloadbalancing:DescribeLoadBalancers",),
    ),
    "classic_load_balancers": ("Classic Load Balancers", ("elasticloadbalancing:DescribeLoadBalancers",)),
    "load_balancer_network_interfaces": ("Private addresses of load balancers", ("ec2:DescribeNetworkInterfaces",)),
    "vpc_endpoints": ("VPC endpoints", ("ec2:DescribeVpcEndpoints",)),
    "vpc_endpoint_network_interfaces": ("Addresses of VPC endpoints", ("ec2:DescribeNetworkInterfaces",)),
    "efs_file_systems": ("EFS file systems", ("elasticfilesystem:DescribeFileSystems",)),
    "efs_mount_targets": ("EFS mount targets", ("elasticfilesystem:DescribeMountTargets",)),
    "elasticache_cache_clusters": ("ElastiCache clusters and nodes", ("elasticache:DescribeCacheClusters",)),
    "elasticache_replication_groups": ("ElastiCache replication groups", ("elasticache:DescribeReplicationGroups",)),
    "elasticache_subnet_groups": ("VPCs of ElastiCache clusters", ("elasticache:DescribeCacheSubnetGroups",)),
    "elasticache_serverless_caches": ("ElastiCache serverless caches", ("elasticache:DescribeServerlessCaches",)),
    "opensearch_domain_names": ("OpenSearch domains", ("es:ListDomainNames",)),
    "opensearch_domains": ("OpenSearch domain endpoints", ("es:DescribeDomains",)),
    "msk_clusters": ("MSK clusters", ("kafka:ListClustersV2",)),
    "msk_bootstrap_brokers": ("MSK bootstrap brokers", ("kafka:GetBootstrapBrokers",)),
    "msk_nodes": ("MSK broker addresses", ("kafka:ListNodes",)),
    "redshift_clusters": ("Redshift clusters", ("redshift:DescribeClusters",)),
    "redshift_serverless_workgroups": ("Redshift Serverless workgroups", ("redshift-serverless:ListWorkgroups",)),
}
# The base sections: discovery fails without them (``ec2:DescribeRegions``
# only for an account set to All regions).
AWS_REQUIRED_ACTIONS: tuple[str, ...] = (
    "ec2:DescribeVpcs",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeNatGateways",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeTransitGatewayAttachments",
    "ec2:DescribeVpcPeeringConnections",
    "ec2:DescribeVpnGateways",
    "ec2:DescribeRouteTables",
    "ec2:DescribeVpnConnections",
    "directconnect:DescribeConnections",
    "ec2:DescribeRegions",
)
# MSK clusters in these states answer no GetBootstrapBrokers / ListNodes.
_MSK_NOT_READY = ("CREATING", "DELETING", "FAILED")

# The progress steps of the map detail, in the order they are read; each is
# one step of the progress bar (``_AWS_SECTIONS_PER_REGION``).
_AWS_MAP_DETAIL_STEPS = (
    "subnets, instances and network ACLs",
    "FSx file systems",
    "RDS and Aurora databases",
    "load balancers",
    "VPC endpoints",
    "EFS file systems",
    "ElastiCache",
    "OpenSearch domains",
    "MSK clusters",
    "Redshift",
)


def _collect_aws_map_detail(
    session,
    ec2,
    region: str,
    cfg,
    resources: list[dict],
    connections: list[dict],
    step: Callable[[str], None] | None = None,
) -> None:
    """Detail the Topology map uses: subnets, instances, customer gateways,
    how Direct Connect reaches a gateway, and the services whose endpoints
    have DNS names (FSx, RDS / Aurora, load balancers, VPC endpoints, EFS,
    ElastiCache, OpenSearch, MSK, Redshift) with their endpoints.

    These sections were added after the base discovery and need permissions
    an existing read-only policy may lack (``ec2:DescribeInstances`` is not
    part of the VPC read-only policy; each service has its own). One that
    cannot be read is skipped and recorded as a ``collection_warning``
    resource with why (``failures.failure_category``) and the IAM actions it
    needs (``AWS_OPTIONAL_SECTIONS``); it never fails discovery. A service
    that is not available in the region stops at its first call.
    ``step`` is told each ``_AWS_MAP_DETAIL_STEPS`` label as it starts.
    """
    clients: dict[str, Any] = {}

    def client(name: str):
        # Created on first use, inside the section that needs it: a service the
        # installed botocore does not know fails only that section.
        if name not in clients:
            clients[name] = session.client(name, region_name=region, config=cfg)
        return clients[name]

    def optional(section: str, read) -> str:
        """Run ``read``; on failure record the warning and return its category ("" on success)."""
        try:
            read()
        except Exception as exc:  # noqa: BLE001 - best-effort detail; discovery goes on
            title, actions = AWS_OPTIONAL_SECTIONS.get(section, ("", ()))
            warning = aws_detail.warning_resource(section, region, exc, title=title, actions=actions)
            log = LOGGER.info if warning["metadata"]["category"] == UNAVAILABLE else LOGGER.warning
            log("aws collector: skipped %s region=%s: %s", section, region, aws_detail.error_code(exc), exc_info=True)
            resources.append(warning)
            return str(warning["metadata"]["category"])
        return ""

    def add(*found: dict | None) -> None:
        resources.extend(r for r in found if r)

    def network_interfaces(section: str, filter_name: str, values) -> list[dict]:
        """The ENIs whose ``filter_name`` is one of ``values``, in batches of
        ``_AWS_FILTER_VALUES_MAX``; none when ``section`` is refused. A filter,
        not ``NetworkInterfaceIds``: an ENI deleted since it was named would
        fail the whole batch."""
        wanted = sorted({str(v).strip() for v in values if str(v or "").strip()})
        found: list[dict] = []

        def read() -> None:
            for start in range(0, len(wanted), _AWS_FILTER_VALUES_MAX):
                chunk = wanted[start : start + _AWS_FILTER_VALUES_MAX]
                found.extend(
                    _aws_list_all(
                        ec2,
                        "describe_network_interfaces",
                        "NetworkInterfaces",
                        Filters=[{"Name": filter_name, "Values": chunk}],
                    )
                )

        if wanted:
            optional(section, read)
        return found

    def subnets() -> None:
        for subnet in _aws_list_all(ec2, "describe_subnets", "Subnets"):
            add(aws_detail.subnet_resource(subnet, region))

    def instances() -> None:
        for reservation in _aws_list_all(ec2, "describe_instances", "Reservations"):
            for instance in reservation.get("Instances") or []:
                add(aws_detail.instance_resource(instance, region))

    def customer_gateways() -> None:
        for gateway in _aws_list_all(ec2, "describe_customer_gateways", "CustomerGateways"):
            add(aws_detail.customer_gateway_resource(gateway, region))

    def direct_connect() -> None:
        dx = client("directconnect")
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
            add(aws_detail.network_acl_resource(acl, region))

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
            add(
                aws_detail.transit_gateway_route_table_resource(
                    table, list(found.get("Routes") or []), bool(found.get("AdditionalRoutesAvailable")), region
                )
            )

    def map_detail() -> None:
        optional("subnets", subnets)
        optional("instances", instances)
        optional("customer_gateways", customer_gateways)
        optional("direct_connect_gateways", direct_connect)
        optional("network_acls", network_acls)
        optional("transit_gateway_route_tables", transit_gateway_route_tables)

    def fsx() -> None:
        file_systems: list[dict] = []

        def read() -> None:
            file_systems.extend(_aws_list_all(client("fsx"), "describe_file_systems", "FileSystems"))

        if optional("fsx_file_systems", read):
            return
        # The ENIs give a Lustre or Windows file system its addresses. Without
        # them the file systems are kept with their endpoints alone.
        eni_ids = [i for fs in file_systems for i in aws_detail.fsx_network_interface_ids(fs)]
        interfaces = aws_detail.network_interfaces_by_id(
            network_interfaces("fsx_network_interfaces", "network-interface-id", eni_ids)
        )
        vpc_of: dict[str, str] = {}
        for file_system in file_systems:
            resource = aws_detail.fsx_file_system_resource(file_system, region, interfaces)
            if resource:
                resources.append(resource)
                vpc_of[resource["metadata"]["file_system_id"]] = resource["metadata"]["vpc_id"]

        def storage_virtual_machines() -> None:
            for svm in _aws_list_all(client("fsx"), "describe_storage_virtual_machines", "StorageVirtualMachines"):
                vpc_id = vpc_of.get(str(svm.get("FileSystemId") or "").strip(), "")
                add(aws_detail.fsx_storage_virtual_machine_resource(svm, region, vpc_id))

        # Only ONTAP file systems have storage virtual machines.
        if any(str(fs.get("FileSystemType") or "").upper() == "ONTAP" for fs in file_systems):
            optional("fsx_storage_virtual_machines", storage_virtual_machines)

    def rds() -> None:
        instances_found: list[dict] = []

        def db_instances() -> None:
            instances_found.extend(_aws_list_all(client("rds"), "describe_db_instances", "DBInstances"))
            add(*[aws_detail.rds_instance_resource(db, region) for db in instances_found])

        if optional("rds_db_instances", db_instances) == UNAVAILABLE:
            return
        # A cluster names its subnet group only; its instances give the VPC.
        groups = aws_detail.subnet_groups_by_name(
            [db.get("DBSubnetGroup") or {} for db in instances_found], "DBSubnetGroupName"
        )

        def db_clusters() -> None:
            clusters = _aws_list_all(client("rds"), "describe_db_clusters", "DBClusters")
            unknown = {str(c.get("DBSubnetGroup") or "") for c in clusters} - set(groups) - {""}
            if unknown:

                def subnet_groups() -> None:
                    listed = _aws_list_all(client("rds"), "describe_db_subnet_groups", "DBSubnetGroups")
                    groups.update(aws_detail.subnet_groups_by_name(listed, "DBSubnetGroupName"))

                optional("rds_db_subnet_groups", subnet_groups)
            add(*[aws_detail.rds_cluster_resource(c, region, groups) for c in clusters])

        def db_proxies() -> None:
            for proxy in _aws_list_all(client("rds"), "describe_db_proxies", "DBProxies"):
                add(aws_detail.rds_proxy_resource(proxy, region))

        optional("rds_db_clusters", db_clusters)
        optional("rds_db_proxies", db_proxies)

    def load_balancers() -> None:
        found: list[dict] = []

        def current() -> None:
            found.extend(_aws_list_all(client("elbv2"), "describe_load_balancers", "LoadBalancers"))

        def classic() -> None:
            found.extend(_aws_list_all(client("elb"), "describe_load_balancers", "LoadBalancerDescriptions"))

        if optional("load_balancers", current) == UNAVAILABLE:
            return
        optional("classic_load_balancers", classic)
        # AWS names a load balancer's ENIs only in their description.
        descriptions = [aws_detail.load_balancer_eni_description(lb) for lb in found]
        by_description = aws_detail.network_interfaces_by_description(
            network_interfaces("load_balancer_network_interfaces", "description", descriptions)
        )
        for lb in found:
            interfaces = by_description.get(aws_detail.load_balancer_eni_description(lb), [])
            add(aws_detail.load_balancer_resource(lb, region, interfaces))

    def vpc_endpoints() -> None:
        found: list[dict] = []

        def read() -> None:
            found.extend(_aws_list_all(ec2, "describe_vpc_endpoints", "VpcEndpoints"))

        if optional("vpc_endpoints", read):
            return
        eni_ids = [str(i) for vpce in found for i in vpce.get("NetworkInterfaceIds") or []]
        interfaces = aws_detail.network_interfaces_by_id(
            network_interfaces("vpc_endpoint_network_interfaces", "network-interface-id", eni_ids)
        )
        add(*[aws_detail.vpc_endpoint_resource(vpce, region, interfaces) for vpce in found])

    def efs() -> None:
        file_systems: list[dict] = []
        targets: dict[str, list[dict]] = {}

        def read() -> None:
            file_systems.extend(_aws_list_all(client("efs"), "describe_file_systems", "FileSystems"))

        def mount_targets() -> None:
            for fs in file_systems:
                fs_id = str(fs.get("FileSystemId") or "").strip()
                if fs_id and fs.get("NumberOfMountTargets") != 0:
                    targets[fs_id] = _aws_list_all(
                        client("efs"), "describe_mount_targets", "MountTargets", FileSystemId=fs_id
                    )

        if optional("efs_file_systems", read):
            return
        if file_systems:
            optional("efs_mount_targets", mount_targets)
        for fs in file_systems:
            add(aws_detail.efs_file_system_resource(fs, region, targets.get(str(fs.get("FileSystemId") or ""))))

    def elasticache() -> None:
        clusters: list[dict] = []
        groups: list[dict] = []
        subnet_groups: dict[str, dict] = {}

        def cache_clusters() -> None:
            clusters.extend(
                _aws_list_all(client("elasticache"), "describe_cache_clusters", "CacheClusters", ShowCacheNodeInfo=True)
            )

        def replication_groups() -> None:
            groups.extend(_aws_list_all(client("elasticache"), "describe_replication_groups", "ReplicationGroups"))

        def cache_subnet_groups() -> None:
            listed = _aws_list_all(client("elasticache"), "describe_cache_subnet_groups", "CacheSubnetGroups")
            subnet_groups.update(aws_detail.subnet_groups_by_name(listed, "CacheSubnetGroupName"))

        def serverless_caches() -> None:
            for cache in _aws_list_all(client("elasticache"), "describe_serverless_caches", "ServerlessCaches"):
                add(aws_detail.elasticache_serverless_cache_resource(cache, region))

        if optional("elasticache_cache_clusters", cache_clusters) == UNAVAILABLE:
            return
        optional("elasticache_replication_groups", replication_groups)
        if any(c.get("CacheSubnetGroupName") for c in clusters):
            optional("elasticache_subnet_groups", cache_subnet_groups)
        members: dict[str, list[dict]] = {}
        for cluster in clusters:
            group_id = str(cluster.get("ReplicationGroupId") or "").strip()
            if group_id:
                members.setdefault(group_id, []).append(cluster)
            else:
                add(aws_detail.elasticache_cache_cluster_resource(cluster, region, subnet_groups))
        for group in groups:
            group_id = str(group.get("ReplicationGroupId") or "").strip()
            add(aws_detail.elasticache_replication_group_resource(group, region, members.get(group_id), subnet_groups))
        optional("elasticache_serverless_caches", serverless_caches)

    def opensearch() -> None:
        names: list[str] = []

        def domain_names() -> None:
            listed = _aws_call(client("opensearch"), "list_domain_names").get("DomainNames") or []
            names.extend(str(d.get("DomainName") or "").strip() for d in listed if d.get("DomainName"))

        def domains() -> None:
            for start in range(0, len(names), _OPENSEARCH_DESCRIBE_MAX):
                batch = names[start : start + _OPENSEARCH_DESCRIBE_MAX]
                answer = _aws_call(client("opensearch"), "describe_domains", DomainNames=batch)
                for domain in answer.get("DomainStatusList") or []:
                    add(aws_detail.opensearch_domain_resource(domain, region))

        if optional("opensearch_domain_names", domain_names) or not names:
            return
        optional("opensearch_domains", domains)

    def msk() -> None:
        clusters: list[dict] = []
        bootstrap: dict[str, dict] = {}
        nodes: dict[str, list[dict]] = {}

        def read() -> None:
            clusters.extend(_aws_list_all(client("kafka"), "list_clusters_v2", "ClusterInfoList"))

        # The clusters that answer for their brokers, once they are listed.
        ready: list[str] = []

        def bootstrap_brokers() -> None:
            for arn in ready:
                bootstrap[arn] = _aws_call(client("kafka"), "get_bootstrap_brokers", ClusterArn=arn)

        def broker_nodes() -> None:
            for cluster in clusters:
                arn = str(cluster.get("ClusterArn") or "")
                # A serverless cluster has no nodes to list.
                if arn in ready and str(cluster.get("ClusterType") or "").upper() == "PROVISIONED":
                    nodes[arn] = _aws_list_all(client("kafka"), "list_nodes", "NodeInfoList", ClusterArn=arn)

        if optional("msk_clusters", read):
            return
        ready += [
            str(c.get("ClusterArn") or "")
            for c in clusters
            if c.get("ClusterArn") and str(c.get("State") or "").upper() not in _MSK_NOT_READY
        ]
        if ready:
            optional("msk_bootstrap_brokers", bootstrap_brokers)
            optional("msk_nodes", broker_nodes)
        for cluster in clusters:
            arn = str(cluster.get("ClusterArn") or "")
            add(aws_detail.msk_cluster_resource(cluster, region, bootstrap.get(arn), nodes.get(arn)))

    def redshift() -> None:
        def clusters() -> None:
            for cluster in _aws_list_all(client("redshift"), "describe_clusters", "Clusters"):
                add(aws_detail.redshift_cluster_resource(cluster, region))

        def workgroups() -> None:
            for workgroup in _aws_list_all(client("redshift-serverless"), "list_workgroups", "workgroups"):
                add(aws_detail.redshift_workgroup_resource(workgroup, region))

        optional("redshift_clusters", clusters)
        optional("redshift_serverless_workgroups", workgroups)

    readers = (map_detail, fsx, rds, load_balancers, vpc_endpoints, efs, elasticache, opensearch, msk, redshift)
    for label, read in zip(_AWS_MAP_DETAIL_STEPS, readers, strict=True):
        if step is not None:
            step(label)
        read()


# The sections _collect_aws reads per region (one _step each), for the progress
# total: the eleven base sections, then the map detail steps.
_AWS_SECTIONS_PER_REGION = 11 + len(_AWS_MAP_DETAIL_STEPS)


def skipped_sections_note(resources: list[dict]) -> str:
    """A sentence on the sections a discovery skipped, for its sync message,
    or ``""`` when none was. Permission problems name the IAM actions to
    add; sections not available in a region are left to the map's report.
    Works for every provider: a warning without a category (Azure, GCP) is
    counted as skipped."""
    by_category: dict[str, dict[str, set[str]]] = {}
    for resource in resources:
        if resource.get("resource_type") != aws_detail.WARNING_TYPE:
            continue
        raw_meta = resource.get("metadata")
        meta: dict = raw_meta if isinstance(raw_meta, dict) else {}
        section = str(meta.get("section") or resource.get("name") or "").strip()
        category = str(meta.get("category") or "").strip()
        bucket = by_category.setdefault(category, {})
        detail = bucket.setdefault(section, set())
        if category == PERMISSION:
            detail.update(str(a) for a in meta.get("actions") or [])
        elif category == FAILED:
            detail.add(str(meta.get("error") or ""))

    def sections(count: int) -> str:
        return f"{count} section{'' if count == 1 else 's'}"

    parts = []
    denied = by_category.get(PERMISSION, {})
    if denied:
        actions = sorted({a for found in denied.values() for a in found if a})
        parts.append(
            f"{sections(len(denied))} skipped for missing permissions" + (f": {', '.join(actions)}" if actions else "")
        )
    failed = by_category.get(FAILED, {})
    if failed:
        codes = sorted({c for found in failed.values() for c in found if c})
        parts.append(f"{sections(len(failed))} failed" + (f" ({', '.join(codes)})" if codes else ""))
    other = by_category.get("", {})
    if other:
        parts.append(f"{sections(len(other))} skipped ({', '.join(sorted(other))})")
    return f"{SKIPPED_NOTE_PREFIX}{'; '.join(parts)}." if parts else ""


# How the skipped-sections note starts, so it can be picked out of a sync message.
SKIPPED_NOTE_PREFIX = "Collected with "


def with_skipped_note(message: str, resources: list[dict]) -> str:
    """``message`` followed by ``skipped_sections_note`` when sections were skipped."""
    note = skipped_sections_note(resources)
    return f"{message}. {note}" if note else message


def skipped_note(message: str) -> str:
    """The skipped-sections note of a sync message, or ``""``."""
    text = str(message or "")
    start = text.find(SKIPPED_NOTE_PREFIX)
    return text[start:] if start >= 0 else ""


def _collect_aws(account: dict, progress: ProgressCallback | None = None) -> tuple[list[dict], list[dict]]:
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
        raise CloudCollectorAuthError(
            "Failed to initialize AWS session",
            user_message=f"Could not set up the AWS session: {provider_error_detail(exc)}",
        ) from exc

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
                "Failed to assume AWS IAM role",
                user_message=aws_credential_message(exc)
                or f"Could not assume the IAM role: {provider_error_detail(exc)}",
            ) from exc

    # Validate credentials early.
    _report(progress, phase="aws login")
    try:
        session.client("sts", config=_cfg).get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        raise CloudCollectorAuthError(
            "AWS credentials are invalid or unauthorized",
            user_message=aws_credential_message(exc) or f"AWS rejected the credentials: {provider_error_detail(exc)}",
        ) from exc
    except Exception as exc:
        raise CloudCollectorExecutionError(
            "Failed to validate AWS credentials",
            user_message=f"Could not check the AWS credentials: {provider_error_detail(exc)}",
        ) from exc

    region_scope = str(account.get("region_scope") or "")
    if _is_all_regions(region_scope):
        _report(progress, phase="aws regions")
        try:
            regions = _aws_enabled_regions(session, _cfg)
        except Exception as exc:
            raise CloudCollectorExecutionError(
                "Failed to list the AWS regions (ec2:DescribeRegions)",
                user_message=f"Could not list the AWS regions for All regions: {provider_error_detail(exc)}",
            ) from exc
        if not regions:
            raise CloudCollectorExecutionError(
                "AWS returned no enabled regions", user_message="AWS returned no enabled regions for this account."
            )
    else:
        regions = _parse_region_scope(region_scope) or ["us-east-1"]

    resources: list[dict] = []
    connections: list[dict] = []
    section_errors: list[tuple[str, str]] = []

    steps_total = len(regions) * _AWS_SECTIONS_PER_REGION
    steps_done = 0

    def _step(region: str, section: str) -> None:
        nonlocal steps_done
        _report(
            progress,
            phase="aws region",
            region=region,
            section=section,
            regions_done=region_index,
            regions_total=len(regions),
            steps_done=steps_done,
            steps_total=steps_total,
        )
        steps_done += 1

    region_index = 0
    for region_index, region in enumerate(regions):
        ec2 = session.client("ec2", region_name=region, config=_cfg)
        _step(region, "VPCs")
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
                        name=aws_detail.tag_name(vpc.get("Tags")),
                        region=region,
                        cidr=str(vpc.get("CidrBlock") or ""),
                        status=str(vpc.get("State") or ""),
                        metadata={"is_default": bool(vpc.get("IsDefault", False))},
                    )
                )
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed vpc list region=%s", region, exc_info=True)
            section_errors.append((f"vpcs:{region}", provider_error_detail(exc)))

        _step(region, "internet gateways")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed internet gateway list region=%s", region, exc_info=True)
            section_errors.append((f"internet_gateways:{region}", provider_error_detail(exc)))

        _step(region, "NAT gateways")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed nat gateway list region=%s", region, exc_info=True)
            section_errors.append((f"nat_gateways:{region}", provider_error_detail(exc)))

        _step(region, "security groups")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed security group list region=%s", region, exc_info=True)
            section_errors.append((f"security_groups:{region}", provider_error_detail(exc)))

        _step(region, "transit gateways")
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
                        name=aws_detail.tag_name(tgw.get("Tags")),
                        region=region,
                        status=str(tgw.get("State") or ""),
                        metadata={
                            "owner_id": str(tgw.get("OwnerId") or "").strip(),
                            "amazon_asn": str((tgw.get("Options") or {}).get("AmazonSideAsn") or "").strip(),
                        },
                    )
                )
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed tgw list region=%s", region, exc_info=True)
            section_errors.append((f"transit_gateways:{region}", provider_error_detail(exc)))

        _step(region, "transit gateway attachments")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed tgw attachment list region=%s", region, exc_info=True)
            section_errors.append((f"transit_gateway_attachments:{region}", provider_error_detail(exc)))

        _step(region, "VPC peerings")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed vpc peering list region=%s", region, exc_info=True)
            section_errors.append((f"vpc_peering_connections:{region}", provider_error_detail(exc)))

        _step(region, "VPN gateways")
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed vpn gateway list region=%s", region, exc_info=True)
            section_errors.append((f"vpn_gateways:{region}", provider_error_detail(exc)))

        _step(region, "route tables")
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
                        name=aws_detail.tag_name(route_table.get("Tags")) or route_table_id,
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed route table list region=%s", region, exc_info=True)
            section_errors.append((f"route_tables:{region}", provider_error_detail(exc)))

        _step(region, "VPN connections")
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
                        name=aws_detail.tag_name(vpn.get("Tags")),
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
        except (BotoCoreError, ClientError) as exc:
            LOGGER.warning("aws collector: failed vpn list region=%s", region, exc_info=True)
            section_errors.append((f"vpn_connections:{region}", provider_error_detail(exc)))

        # Direct Connect is region-bound; query every configured region.
        _step(region, "Direct Connect")
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
        except Exception as exc:
            LOGGER.warning("aws collector: failed direct connect list region=%s", region, exc_info=True)
            section_errors.append((f"direct_connect:{region}", provider_error_detail(exc)))

        _collect_aws_map_detail(
            session, ec2, region, _cfg, resources, connections, step=lambda label: _step(region, label)
        )

    # A partial snapshot must not silently replace the last known-good one; the
    # discover endpoint keeps the previous snapshot and surfaces this message on failure.
    if section_errors:
        raise _partial_discovery_error(section_errors)

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
        raise CloudCollectorAuthError(
            "Azure subscription_id is required", user_message="Azure subscription_id is required"
        )

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
        raise CloudCollectorAuthError(
            "Failed to initialize Azure credentials",
            user_message=f"Could not set up the Azure credentials: {provider_error_detail(exc)}",
        ) from exc

    # The Network API lists gateways and connections per resource group only.
    # azure-mgmt-resource (optional) names every group of the subscription;
    # without it the groups of the resources already read are used.
    list_resource_groups = None
    try:
        from azure.mgmt.resource import ResourceManagementClient
    except Exception:  # noqa: BLE001 - optional SDK
        LOGGER.info("azure collector: azure-mgmt-resource not installed; resource groups come from the resources read")
    else:

        def list_resource_groups() -> list[str]:
            resource_client = ResourceManagementClient(credential, subscription_id)
            return [str(group.name) for group in resource_client.resource_groups.list() if getattr(group, "name", "")]

    return _collect_azure_network(network_client, subscription_id, list_resource_groups)


def _azure_resource_groups(list_resource_groups, resources: list[dict], public_ips: dict[str, str]) -> list[str]:
    """The resource groups whose gateways and connections are read: those the
    Resource Manager API lists (when ``list_resource_groups`` is given and
    answers) and the group of every resource read so far, including the
    route tables, security groups, NAT gateways and public IPs the VNets and
    subnets refer to. Names are case-insensitive in Azure; the first spelling
    seen is kept."""
    groups: dict[str, str] = {}

    def add(name: Any) -> None:
        text = str(name or "").strip()
        if text and text.lower() not in groups:
            groups[text.lower()] = text

    if list_resource_groups is not None:
        try:
            for name in list_resource_groups():
                add(name)
        except Exception:  # noqa: BLE001 - fall back to the groups of the resources read
            LOGGER.warning("azure collector: failed to list resource groups", exc_info=True)
    for resource in resources:
        meta = resource.get("metadata") or {}
        add(meta.get("resource_group"))
        for key in ("route_table", "network_security_group", "nat_gateway"):
            uid = str(meta.get(key) or "")
            parts = uid.split(":")
            if len(parts) == 5 and parts[0] == "azure":
                add(parts[3])
    for public_ip_id in public_ips:
        add(azure_detail.resource_parts(public_ip_id).get("resourcegroups"))
    return list(groups.values())


def _collect_azure_network(
    network_client, subscription_id: str, list_resource_groups=None
) -> tuple[list[dict], list[dict]]:
    """The discovery itself, on an initialised ``NetworkManagementClient``.

    ``list_resource_groups`` names the resource groups of the subscription
    (``None`` when azure-mgmt-resource is not installed); the virtual network
    gateways, local network gateways and gateway connections are listed per
    group, as the Network API offers no subscription-wide call for them.
    """
    resources: list[dict] = []
    connections: list[dict] = []
    section_errors: list[tuple[str, str]] = []
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
            except Exception as exc:
                LOGGER.warning("azure collector: failed to list peerings for vnet=%s", name, exc_info=True)
                section_errors.append(("vnet_peerings", provider_error_detail(exc)))
    except Exception as exc:
        raise CloudCollectorAuthError(
            "Azure network API access failed",
            user_message=f"Azure refused the network read: {provider_error_detail(exc)}",
        ) from exc

    try:
        for circuit in network_client.express_route_circuits.list_all():
            resource = azure_detail.express_route_resource(circuit, subscription_id)
            if resource:
                resources.append(resource)
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list expressroute circuits", exc_info=True)
        section_errors.append(("expressroute_circuits", provider_error_detail(exc)))

    try:
        for route_table in network_client.route_tables.list_all():
            resource = azure_detail.route_table_resource(route_table, subscription_id)
            if not resource:
                continue
            resources.append(resource)
            connections.extend(azure_detail.route_table_associations(resource))
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list route tables", exc_info=True)
        section_errors.append(("route_tables", provider_error_detail(exc)))

    try:
        for nsg in network_client.network_security_groups.list_all():
            resource = azure_detail.nsg_resource(nsg, subscription_id)
            if resource:
                resources.append(resource)
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list nsgs", exc_info=True)
        section_errors.append(("network_security_groups", provider_error_detail(exc)))

    # Gateways and connections are listed per resource group; the Network API
    # has no list_all for them.
    groups = _azure_resource_groups(list_resource_groups, resources, public_ips)

    try:
        for group in groups:
            for gateway in network_client.virtual_network_gateways.list(group):
                resource = azure_detail.virtual_network_gateway_resource(gateway, subscription_id, public_ips)
                if not resource:
                    continue
                resources.append(resource)
                attachment = azure_detail.gateway_attachment(resource)
                if attachment:
                    connections.append(attachment)
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list virtual network gateways", exc_info=True)
        section_errors.append(("virtual_network_gateways", provider_error_detail(exc)))

    try:
        for group in groups:
            for gateway in network_client.local_network_gateways.list(group):
                resource = azure_detail.local_network_gateway_resource(gateway, subscription_id)
                if resource:
                    resources.append(resource)
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list local network gateways", exc_info=True)
        section_errors.append(("local_network_gateways", provider_error_detail(exc)))

    try:
        for group in groups:
            for conn in network_client.virtual_network_gateway_connections.list(group):
                record = azure_detail.gateway_connection(conn, subscription_id)
                if record:
                    connections.append(record)
    except Exception as exc:
        LOGGER.warning("azure collector: failed to list gateway connections", exc_info=True)
        section_errors.append(("gateway_connections", provider_error_detail(exc)))

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
        raise _partial_discovery_error(section_errors)

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
        raise CloudCollectorAuthError("GCP project_id is required", user_message="GCP project_id is required")

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
        raise CloudCollectorAuthError(
            "Failed to initialize GCP credentials",
            user_message=f"Could not set up the GCP credentials: {provider_error_detail(exc)}",
        ) from exc

    if not project_id:
        raise CloudCollectorAuthError("GCP project_id is required", user_message="GCP project_id is required")

    try:
        compute = build("compute", "v1", credentials=credentials, cache_discovery=False)
    except Exception as exc:
        raise CloudCollectorExecutionError(
            "Failed to initialize GCP compute client",
            user_message=f"Could not set up the GCP compute client: {provider_error_detail(exc)}",
        ) from exc

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
    section_errors: list[tuple[str, str]] = []

    def optional(section: str, read) -> None:
        try:
            sections[section] = read()
        except Exception as exc:  # noqa: BLE001 - best-effort detail; discovery goes on
            LOGGER.warning("gcp collector: skipped %s: %s", section, gcp_detail.error_code(exc), exc_info=True)
            warnings.append(gcp_detail.warning_resource(section, exc))

    try:
        sections["networks"] = _gcp_list(compute, "networks", project_id)
    except Exception as exc:
        raise CloudCollectorAuthError(
            "GCP network API access failed",
            user_message=f"GCP refused the network read: {provider_error_detail(exc)}",
        ) from exc

    for section, read in (
        ("subnetworks", lambda: _gcp_aggregated(compute, "subnetworks", project_id)),
        ("routes", lambda: _gcp_list(compute, "routes", project_id)),
        ("firewalls", lambda: _gcp_list(compute, "firewalls", project_id)),
    ):
        try:
            sections[section] = read()
        except Exception as exc:
            LOGGER.warning("gcp collector: failed %s list", section, exc_info=True)
            section_errors.append((section, provider_error_detail(exc)))

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
        raise _partial_discovery_error(section_errors)

    resources, connections = gcp_detail.assemble(project_id, **sections)
    return _dedupe_resources(resources + warnings), _dedupe_connections(connections)


def collect_provider_snapshot(account: dict, progress: ProgressCallback | None = None) -> tuple[list[dict], list[dict]]:
    """Discover one cloud account. ``progress`` receives AWS progress fields as the regions are read."""
    provider = str(account.get("provider") or "").strip().lower()
    if provider not in VALID_PROVIDERS:
        raise CloudCollectorExecutionError("Unsupported cloud provider")
    if provider == "aws":
        return _collect_aws(account, progress)
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
