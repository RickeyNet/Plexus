"""Tests for the AWS services whose endpoints have DNS names.

RDS / Aurora, load balancers, VPC endpoints, EFS, ElastiCache, OpenSearch,
MSK and Redshift are collected per region as optional sections and listed
in their VPC's details (never as nodes), so the Topology search finds the
VPC by an endpoint's DNS name, a resource ID or an address. Covers with no
AWS access:

  * collect   - the reshapers, and that no secret of a realistic response is kept
  * collector - every section optional: denied, not available in the region,
                an SDK without the call, failing; the shared ENI lookup
  * normalize - the per-service tables, the "Service endpoints" table, the
                subnet index, the report collapsed across regions
  * messages  - the discovery's sync message names the IAM actions to add
  * docs      - the permissions documented match what the collector calls
  * HTTP API  - deep search by DNS name, ID and address; the discover message
"""

from __future__ import annotations

import json
import pathlib
import re

import netcontrol.app as app_module
import netcontrol.routes.cloud_collectors as collectors_module
import netcontrol.routes.cloud_visibility as cloud_visibility_module
import pytest
import routes.database as db_module
from netcontrol.integrations.aws import collect, normalize as aws_normalize
from netcontrol.integrations.aws.failures import OperationNotInSdk, failure_category
from netcontrol.integrations.aws.normalize import build_snapshot
from netcontrol.integrations.aws.sample import build_sample
from netcontrol.integrations.meraki.subnets import subnet_index, subnets_containing
from netcontrol.integrations.meraki.unified import build_search_index, search_index

ACCOUNT = {"id": 1, "name": "Prod", "last_sync_at": "2026-10-01T12:00:00+00:00", "last_sync_status": "success"}
SECRET = "TOP-SECRET"


# ── Errors as botocore raises them ───────────────────────────────────────────


class _ClientError(Exception):
    """A botocore ``ClientError``: the code is in ``response``; the message
    names the caller, which must not be kept."""

    def __init__(self, code: str):
        super().__init__(f"{code}: arn:aws:iam::111122223333:user/{SECRET}")
        self.response = {"Error": {"Code": code, "Message": f"user/{SECRET} is not authorized"}}


class EndpointConnectionError(Exception):
    """botocore's error for a region where the service has no endpoint (named alike)."""


class UnknownServiceError(Exception):
    """botocore's error for a service it has no model of (named alike)."""


# ── Reshapers ────────────────────────────────────────────────────────────────


def test_endpoint_shape_and_dns_suffix():
    assert collect.endpoint("Writer", "db.example.com", 5432) == {
        "role": "Writer",
        "dns_name": "db.example.com",
        "port": 5432,
        "ip_addresses": [],
    }
    # No port where AWS gives none; addresses once each, lists flattened.
    assert collect.endpoint("Node", "", None, [["10.0.0.5", ""], "10.0.0.5", None]) == {
        "role": "Node",
        "dns_name": "",
        "ip_addresses": ["10.0.0.5"],
    }
    assert collect.endpoint("Empty", "", 443) is None
    assert collect.dns_suffix("us-east-1") == "amazonaws.com"
    assert collect.dns_suffix("cn-north-1") == "amazonaws.com.cn"


_DB_INSTANCE = {
    "DBInstanceIdentifier": "orders-1",
    "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:orders-1",
    "DBInstanceClass": "db.r6g.large",
    "Engine": "neptune",
    "EngineVersion": "1.3.2.0",
    "DBInstanceStatus": "available",
    "MasterUsername": f"{SECRET}-admin",
    "MasterUserSecret": {"SecretArn": f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{SECRET}"},
    "KmsKeyId": f"arn:aws:kms:us-east-1:111122223333:key/{SECRET}",
    "Endpoint": {"Address": "orders-1.c0example.us-east-1.neptune.amazonaws.com", "Port": 8182},
    "DBSubnetGroup": {
        "DBSubnetGroupName": "db-subnets",
        "VpcId": "vpc-1",
        "Subnets": [{"SubnetIdentifier": "subnet-1"}, {"SubnetIdentifier": "subnet-2"}],
    },
    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
    "MultiAZ": True,
    "PubliclyAccessible": False,
    "DBClusterIdentifier": "orders",
}
_DB_CLUSTER = {
    "DBClusterIdentifier": "orders",
    "DBClusterArn": "arn:aws:rds:us-east-1:111122223333:cluster:orders",
    "Engine": "aurora-mysql",
    "EngineVersion": "8.0.mysql_aurora.3.05.2",
    "Status": "available",
    "Port": 3306,
    "DBSubnetGroup": "db-subnets",
    "Endpoint": "orders.cluster-c0example.us-east-1.rds.amazonaws.com",
    "ReaderEndpoint": "orders.cluster-ro-c0example.us-east-1.rds.amazonaws.com",
    "CustomEndpoints": ["orders-reports.cluster-custom-c0example.us-east-1.rds.amazonaws.com"],
    "MasterUsername": f"{SECRET}-admin",
    "MasterUserSecret": {"SecretArn": f"arn:aws:secretsmanager:::{SECRET}"},
    "KmsKeyId": SECRET,
    "DBClusterMembers": [{"DBInstanceIdentifier": "orders-1"}],
}
_DB_PROXY = {
    "DBProxyName": "orders-proxy",
    "DBProxyArn": "arn:aws:rds:us-east-1:111122223333:db-proxy:prx-1",
    "Status": "available",
    "EngineFamily": "MYSQL",
    "VpcId": "vpc-1",
    "VpcSubnetIds": ["subnet-1"],
    "VpcSecurityGroupIds": ["sg-1"],
    "Endpoint": "orders-proxy.proxy-c0example.us-east-1.rds.amazonaws.com",
    "Auth": [{"UserName": f"{SECRET}-user", "SecretArn": f"arn:aws:secretsmanager:::{SECRET}"}],
    "RoleArn": f"arn:aws:iam::111122223333:role/{SECRET}",
}


def test_rds_resources_name_their_engine_and_keep_no_secret():
    instance = collect.rds_instance_resource(_DB_INSTANCE, "us-east-1")
    meta = instance["metadata"]
    assert instance["resource_uid"] == "aws:rds_db_instance:arn:aws:rds:us-east-1:111122223333:db:orders-1"
    # Neptune (and DocumentDB) come back from the RDS API; named by engine.
    assert meta["kind"] == "Neptune instance" and meta["engine_version"] == "1.3.2.0"
    assert meta["vpc_id"] == "vpc-1" and meta["subnet_ids"] == ["subnet-1", "subnet-2"]
    assert meta["security_group_ids"] == ["sg-1"] and meta["multi_az"] is True
    assert meta["endpoints"] == [
        {
            "role": "Instance",
            "dns_name": "orders-1.c0example.us-east-1.neptune.amazonaws.com",
            "port": 8182,
            "ip_addresses": [],
        }
    ]
    groups = collect.subnet_groups_by_name([_DB_INSTANCE["DBSubnetGroup"]], "DBSubnetGroupName")
    cluster = collect.rds_cluster_resource(_DB_CLUSTER, "us-east-1", groups)
    assert cluster["metadata"]["kind"] == "Aurora MySQL cluster"
    assert cluster["metadata"]["vpc_id"] == "vpc-1"
    assert [(e["role"], e["port"]) for e in cluster["metadata"]["endpoints"]] == [
        ("Writer", 3306),
        ("Reader", 3306),
        ("Custom", 3306),
    ]
    proxy = collect.rds_proxy_resource(_DB_PROXY, "us-east-1")
    assert proxy["metadata"]["endpoints"][0]["dns_name"].startswith("orders-proxy.proxy-")
    assert SECRET not in json.dumps([instance, cluster, proxy])
    assert collect.rds_instance_resource({**_DB_INSTANCE, "DBInstanceStatus": "deleting"}, "us-east-1") is None


_ALB = {
    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/0a1b2c3d4e5f6071",
    "LoadBalancerName": "web",
    "DNSName": "internal-web-1.us-east-1.elb.amazonaws.com",
    "Scheme": "internal",
    "VpcId": "vpc-1",
    "Type": "application",
    "State": {"Code": "active"},
    "AvailabilityZones": [{"ZoneName": "us-east-1a", "SubnetId": "subnet-1"}],
    "SecurityGroups": ["sg-1"],
}
_NLB = {
    **_ALB,
    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/edge/0a1b2c3d4e5f6072",
    "LoadBalancerName": "edge",
    "DNSName": "edge-1.elb.us-east-1.amazonaws.com",
    "Type": "network",
    "AvailabilityZones": [
        {
            "SubnetId": "subnet-1",
            "LoadBalancerAddresses": [
                {"IpAddress": "203.0.113.7", "AllocationId": "eipalloc-1", "PrivateIPv4Address": "10.0.1.7"}
            ],
        }
    ],
}
_CLASSIC = {
    "LoadBalancerName": "legacy",
    "DNSName": "legacy-1.us-east-1.elb.amazonaws.com",
    "VPCId": "vpc-1",
    "Subnets": ["subnet-1"],
    "Scheme": "internet-facing",
    "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 443}}, {"Listener": {"LoadBalancerPort": 80}}],
    "Policies": {"OtherPolicies": [SECRET]},
}


def test_load_balancers_keep_dns_name_subnets_and_addresses():
    assert collect.load_balancer_eni_description(_ALB) == "ELB app/web/0a1b2c3d4e5f6071"
    assert collect.load_balancer_eni_description(_CLASSIC) == "ELB legacy"
    enis = collect.network_interfaces_by_description(
        [{"NetworkInterfaceId": "eni-1", "Description": "ELB app/web/0a1b2c3d4e5f6071", "PrivateIpAddress": "10.0.1.9"}]
    )
    alb = collect.load_balancer_resource(_ALB, "us-east-1", enis["ELB app/web/0a1b2c3d4e5f6071"])
    assert alb["metadata"]["kind"] == "Application load balancer" and alb["status"] == "active"
    assert alb["metadata"]["network_interface_ids"] == ["eni-1"]
    assert alb["metadata"]["interfaces"][0]["private_ips"] == ["10.0.1.9"]
    nlb = collect.load_balancer_resource(_NLB, "us-east-1")
    # The private address is the endpoint's; the Elastic IP is listed, not a host of the VPC.
    assert nlb["metadata"]["endpoints"][0]["ip_addresses"] == ["10.0.1.7"]
    assert nlb["metadata"]["public_ips"] == ["203.0.113.7"]
    classic = collect.load_balancer_resource(_CLASSIC, "us-east-1")
    assert classic["resource_uid"] == "aws:load_balancer:legacy-1.us-east-1.elb.amazonaws.com"
    assert classic["metadata"]["vpc_id"] == "vpc-1" and classic["metadata"]["listener_ports"] == [80, 443]
    assert SECRET not in json.dumps([alb, nlb, classic])


def test_vpc_endpoint_keeps_dns_entries_not_its_policy():
    interfaces = collect.network_interfaces_by_id([{"NetworkInterfaceId": "eni-v1", "PrivateIpAddress": "10.0.1.20"}])
    interface = collect.vpc_endpoint_resource(
        {
            "VpcEndpointId": "vpce-1",
            "VpcEndpointType": "Interface",
            "VpcId": "vpc-1",
            "ServiceName": "com.amazonaws.us-east-1.ssm",
            "State": "available",
            "PolicyDocument": json.dumps({"Statement": [{"Sid": SECRET}]}),
            "SubnetIds": ["subnet-1"],
            "Groups": [{"GroupId": "sg-1"}],
            "NetworkInterfaceIds": ["eni-v1"],
            "PrivateDnsEnabled": True,
            "DnsEntries": [{"DnsName": "vpce-1-abc.ssm.us-east-1.vpce.amazonaws.com", "HostedZoneId": "Z1"}],
        },
        "us-east-1",
        interfaces,
    )
    meta = interface["metadata"]
    assert meta["kind"] == "Interface endpoint" and meta["service_name"] == "com.amazonaws.us-east-1.ssm"
    assert meta["endpoints"][0]["dns_name"] == "vpce-1-abc.ssm.us-east-1.vpce.amazonaws.com"
    assert meta["interfaces"][0]["private_ips"] == ["10.0.1.20"]
    gateway = collect.vpc_endpoint_resource(
        {"VpcEndpointId": "vpce-2", "VpcEndpointType": "Gateway", "VpcId": "vpc-1", "State": "available"},
        "us-east-1",
    )
    # A gateway endpoint is listed, with no DNS name and no address.
    assert gateway["metadata"]["endpoints"] == [] and gateway["metadata"]["kind"] == "Gateway endpoint"
    assert SECRET not in json.dumps([interface, gateway])
    assert collect.vpc_endpoint_resource({"VpcEndpointId": "vpce-3", "State": "Deleted"}, "us-east-1") is None


def test_efs_dns_names_are_built_for_the_partition():
    fs = {
        "FileSystemId": "fs-1",
        "Name": "shared",
        "LifeCycleState": "available",
        "KmsKeyId": SECRET,
        "CreationToken": SECRET,
    }
    targets = [
        {
            "MountTargetId": "fsmt-1",
            "SubnetId": "subnet-1",
            "VpcId": "vpc-1",
            "IpAddress": "10.0.1.30",
            "NetworkInterfaceId": "eni-e1",
            "AvailabilityZoneName": "cn-north-1a",
            "LifeCycleState": "available",
        }
    ]
    resource = collect.efs_file_system_resource(fs, "cn-north-1", targets)
    meta = resource["metadata"]
    assert [(e["role"], e["dns_name"], e["ip_addresses"]) for e in meta["endpoints"]] == [
        ("File system", "fs-1.efs.cn-north-1.amazonaws.com.cn", ["10.0.1.30"]),
        ("Mount target cn-north-1a", "cn-north-1a.fs-1.efs.cn-north-1.amazonaws.com.cn", ["10.0.1.30"]),
    ]
    assert meta["vpc_id"] == "vpc-1" and meta["network_interface_ids"] == ["eni-e1"]
    assert SECRET not in json.dumps(resource)


_CACHE_MEMBER = {
    "CacheClusterId": "sessions-001",
    "ReplicationGroupId": "sessions",
    "Engine": "redis",
    "EngineVersion": "7.1.0",
    "CacheClusterStatus": "available",
    "CacheSubnetGroupName": "cache-subnets",
    "SecurityGroups": [{"SecurityGroupId": "sg-1"}],
    "AuthTokenEnabled": True,
    "CacheNodes": [
        {"CacheNodeId": "0001", "Endpoint": {"Address": "sessions-001.c0.cache.amazonaws.com", "Port": 6379}}
    ],
}


def test_elasticache_resources_keep_endpoints_not_auth_tokens():
    groups = collect.subnet_groups_by_name(
        [{"CacheSubnetGroupName": "cache-subnets", "VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}],
        "CacheSubnetGroupName",
    )
    group = collect.elasticache_replication_group_resource(
        {
            "ReplicationGroupId": "sessions",
            "Status": "available",
            "ConfigurationEndpoint": {"Address": "clustercfg.sessions.c0.cache.amazonaws.com", "Port": 6379},
            "NodeGroups": [{"NodeGroupId": "0001"}],
            "AuthTokenEnabled": True,
            "UserGroupIds": [SECRET],
            "KmsKeyId": SECRET,
        },
        "us-east-1",
        [_CACHE_MEMBER],
        groups,
    )
    meta = group["metadata"]
    assert meta["engine_version"] == "7.1.0" and meta["vpc_id"] == "vpc-1" and meta["subnet_ids"] == ["subnet-1"]
    assert [e["role"] for e in meta["endpoints"]] == ["Configuration", "Node sessions-001/0001"]
    single = collect.elasticache_cache_cluster_resource(
        {**_CACHE_MEMBER, "ReplicationGroupId": None, "Engine": "memcached"}, "us-east-1", groups
    )
    assert single["metadata"]["engine"] == "memcached" and single["metadata"]["vpc_id"] == "vpc-1"
    serverless = collect.elasticache_serverless_cache_resource(
        {
            "ServerlessCacheName": "fast",
            "Status": "available",
            "Engine": "valkey",
            "FullEngineVersion": "8.0",
            "SubnetIds": ["subnet-1"],
            "SecurityGroupIds": ["sg-1"],
            "Endpoint": {"Address": "fast-c0.serverless.use1.cache.amazonaws.com", "Port": 6379},
            "ReaderEndpoint": {"Address": "fast-c0.serverless.use1.cache.amazonaws.com", "Port": 6380},
            "UserGroupId": SECRET,
            "KmsKeyId": SECRET,
        },
        "us-east-1",
    )
    # It names no VPC: the map places it by its subnets.
    assert serverless["metadata"]["vpc_id"] == "" and serverless["metadata"]["subnet_ids"] == ["subnet-1"]
    assert [e["port"] for e in serverless["metadata"]["endpoints"]] == [6379, 6380]
    assert SECRET not in json.dumps([group, single, serverless])


def test_opensearch_domain_keeps_only_whether_fine_grained_access_is_on():
    domain = collect.opensearch_domain_resource(
        {
            "DomainId": "111122223333/logs",
            "DomainName": "logs",
            "ARN": "arn:aws:es:us-east-1:111122223333:domain/logs",
            "EngineVersion": "Elasticsearch_7.10",
            "Endpoints": {"vpc": "vpc-logs-c0.us-east-1.es.amazonaws.com"},
            "VPCOptions": {"VPCId": "vpc-1", "SubnetIds": ["subnet-1"], "SecurityGroupIds": ["sg-1"]},
            "DomainEndpointOptions": {"CustomEndpointEnabled": True, "CustomEndpoint": "logs.example.com"},
            "AccessPolicies": json.dumps({"Statement": [{"Principal": SECRET}]}),
            "AdvancedSecurityOptions": {
                "Enabled": True,
                "SAMLOptions": {"MasterUserName": SECRET, "MasterBackendRole": SECRET},
                "JWTOptions": {"PublicKey": SECRET},
            },
            "CognitoOptions": {"UserPoolId": SECRET, "RoleArn": SECRET},
        },
        "us-east-1",
    )
    meta = domain["metadata"]
    assert (meta["engine"], meta["engine_version"]) == ("Elasticsearch", "7.10")
    assert [e["role"] for e in meta["endpoints"]] == ["VPC endpoint", "Custom endpoint"]
    assert meta["fine_grained_access_control"] is True and meta["vpc_id"] == "vpc-1"
    assert SECRET not in json.dumps(domain)
    assert collect.opensearch_domain_resource({"DomainName": "gone", "Deleted": True}, "us-east-1") is None


def test_msk_cluster_parses_bootstrap_strings_and_broker_addresses():
    endpoints = collect.msk_bootstrap_endpoints(
        {
            "BootstrapBrokerStringTls": "b-1.events.c1.kafka.us-east-1.amazonaws.com:9094,"
            "b-2.events.c1.kafka.us-east-1.amazonaws.com:9094",
            "BootstrapBrokerStringSaslIam": "b-1.events.c1.kafka.us-east-1.amazonaws.com:9098",
            "BootstrapBrokerStringPublicSaslScram": "b-1-public.events.c1.kafka.us-east-1.amazonaws.com:9196",
            "ResponseMetadata": {"RequestId": SECRET},
        }
    )
    assert [(e["role"], e["port"]) for e in endpoints] == [
        ("Bootstrap (TLS)", 9094),
        ("Bootstrap (TLS)", 9094),
        ("Bootstrap (IAM)", 9098),
        ("Bootstrap (public, SASL/SCRAM)", 9196),
    ]
    cluster = collect.msk_cluster_resource(
        {
            "ClusterArn": "arn:aws:kafka:us-east-1:111122223333:cluster/events/1",
            "ClusterName": "events",
            "ClusterType": "PROVISIONED",
            "State": "ACTIVE",
            "Provisioned": {
                "BrokerNodeGroupInfo": {"ClientSubnets": ["subnet-1"], "SecurityGroups": ["sg-1"]},
                "CurrentBrokerSoftwareInfo": {"KafkaVersion": "3.6.0"},
                "ClientAuthentication": {
                    "Sasl": {"Scram": {"Enabled": True}},
                    "Tls": {"CertificateAuthorityArnList": [SECRET]},
                },
            },
        },
        "us-east-1",
        {"BootstrapBrokerString": "b-1.events.c1.kafka.us-east-1.amazonaws.com:9092"},
        [
            {
                "BrokerNodeInfo": {
                    "BrokerId": 1.0,
                    "ClientVpcIpAddress": "10.0.1.40",
                    "AttachedENIId": "eni-k1",
                    "Endpoints": ["b-1.events.c1.kafka.us-east-1.amazonaws.com"],
                }
            }
        ],
    )
    meta = cluster["metadata"]
    assert meta["engine_version"] == "3.6.0" and meta["subnet_ids"] == ["subnet-1"] and meta["vpc_id"] == ""
    assert [(e["role"], e["ip_addresses"]) for e in meta["endpoints"]] == [
        ("Bootstrap (plaintext)", []),
        ("Broker 1", ["10.0.1.40"]),
    ]
    assert meta["network_interface_ids"] == ["eni-k1"]
    assert SECRET not in json.dumps(cluster)


def test_redshift_resources_keep_no_admin_user_or_secret():
    cluster = collect.redshift_cluster_resource(
        {
            "ClusterIdentifier": "dw",
            "ClusterStatus": "available",
            "ClusterVersion": "1.0",
            "ClusterRevisionNumber": "12345",
            "MasterUsername": f"{SECRET}-admin",
            "MasterPasswordSecretArn": f"arn:aws:secretsmanager:::{SECRET}",
            "KmsKeyId": SECRET,
            "ClusterPublicKey": SECRET,
            "VpcId": "vpc-1",
            "Endpoint": {
                "Address": "dw.c0example.us-east-1.redshift.amazonaws.com",
                "Port": 5439,
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": "vpce-r1",
                        "VpcId": "vpc-2",
                        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-r1", "PrivateIpAddress": "10.0.2.50"}],
                    }
                ],
            },
            "ClusterNodes": [
                {"NodeRole": "SHARED", "PrivateIPAddress": "10.0.1.50", "PublicIPAddress": "203.0.113.50"}
            ],
        },
        "us-east-1",
    )
    meta = cluster["metadata"]
    assert meta["engine_version"] == "1.0 (revision 12345)"
    assert [(e["role"], e.get("port"), e["ip_addresses"]) for e in meta["endpoints"]] == [
        ("Cluster", 5439, []),
        ("VPC endpoint vpce-r1", None, ["10.0.2.50"]),
        ("Shared node", None, ["10.0.1.50"]),
    ]
    assert meta["public_ips"] == ["203.0.113.50"]
    workgroup = collect.redshift_workgroup_resource(
        {
            "workgroupName": "analytics",
            "workgroupArn": "arn:aws:redshift-serverless:us-east-1:111122223333:workgroup/1",
            "status": "AVAILABLE",
            "namespaceName": "analytics-ns",
            "subnetIds": ["subnet-1"],
            "securityGroupIds": ["sg-1"],
            "configParameters": [{"parameterKey": "search_path", "parameterValue": SECRET}],
            "endpoint": {"address": "analytics.111122223333.us-east-1.redshift-serverless.amazonaws.com", "port": 5439},
        },
        "us-east-1",
    )
    assert workgroup["status"] == "available" and workgroup["metadata"]["endpoints"][0]["port"] == 5439
    assert SECRET not in json.dumps([cluster, workgroup])


# ── Why a section was not collected ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("code", "category"),
    [
        ("AccessDenied", "permission"),
        ("AccessDeniedException", "permission"),
        ("UnauthorizedOperation", "permission"),
        ("Client.UnauthorizedOperation", "permission"),
        ("AuthorizationError", "permission"),
        ("AuthFailure", "permission"),
        ("EndpointConnectionError", "unavailable"),
        ("OptInRequired", "unavailable"),
        ("UnrecognizedClientException", "unavailable"),
        ("InvalidClientTokenId", "unavailable"),
        ("UnknownServiceError", "unavailable"),
        ("OperationNotInSdk", "unavailable"),
        ("ThrottlingException", "error"),
        ("ReadTimeoutError", "error"),
        ("InternalFailure", "error"),
        ("", "error"),
    ],
)
def test_failure_category(code, category):
    assert failure_category(code) == category


def test_warning_resource_records_why_and_the_action_never_the_message():
    warning = collect.warning_resource(
        "rds_db_instances", "us-east-1", _ClientError("AccessDenied"), title="RDS", actions=("rds:DescribeDBInstances",)
    )
    assert warning["metadata"] == {
        "section": "rds_db_instances",
        "error": "AccessDenied",
        "category": "permission",
        "title": "RDS",
        "actions": ["rds:DescribeDBInstances"],
    }
    assert SECRET not in json.dumps(warning)
    unreachable = collect.warning_resource("msk_clusters", "ap-east-1", EndpointConnectionError("could not connect"))
    assert unreachable["metadata"]["category"] == "unavailable"


def test_a_call_the_sdk_lacks_is_reported_as_such():
    with pytest.raises(OperationNotInSdk):
        collectors_module._aws_call(object(), "describe_serverless_caches")


# ── The collector, against stand-in clients ──────────────────────────────────


class _Client:
    """A service client answering from a table: an exception instance is
    raised, ``_Client.MISSING`` makes the operation unknown to the SDK, and
    an operation not in the table answers nothing. Every call is recorded."""

    MISSING = object()

    def __init__(self, answers: dict, calls: list):
        self._answers = answers
        self._calls = calls

    def can_paginate(self, _operation):
        return False

    def __getattr__(self, operation):
        answer = self._answers.get(operation, {})
        if answer is _Client.MISSING:
            raise AttributeError(operation)

        def call(**kwargs):
            self._calls.append((operation, kwargs))
            if isinstance(answer, BaseException):
                raise answer
            return answer(**kwargs) if callable(answer) else answer

        return call


_SERVICE_ANSWERS: dict[str, dict] = {
    "rds": {
        "describe_db_instances": {"DBInstances": [_DB_INSTANCE]},
        "describe_db_clusters": {"DBClusters": [_DB_CLUSTER]},
        "describe_db_proxies": {"DBProxies": [_DB_PROXY]},
    },
    "elbv2": {"describe_load_balancers": {"LoadBalancers": [_ALB]}},
    "elb": {"describe_load_balancers": {"LoadBalancerDescriptions": [_CLASSIC]}},
    "efs": {
        "describe_file_systems": {"FileSystems": [{"FileSystemId": "fs-1", "LifeCycleState": "available"}]},
        "describe_mount_targets": lambda FileSystemId: {
            "MountTargets": [{"MountTargetId": "fsmt-1", "VpcId": "vpc-1", "IpAddress": "10.0.1.30"}]
        },
    },
    "elasticache": {
        "describe_cache_clusters": {"CacheClusters": [_CACHE_MEMBER]},
        "describe_replication_groups": {
            "ReplicationGroups": [{"ReplicationGroupId": "sessions", "Status": "available"}]
        },
        "describe_cache_subnet_groups": {
            "CacheSubnetGroups": [{"CacheSubnetGroupName": "cache-subnets", "VpcId": "vpc-1", "Subnets": []}]
        },
        "describe_serverless_caches": {"ServerlessCaches": []},
    },
    "opensearch": {
        "list_domain_names": {"DomainNames": [{"DomainName": f"d{n}"} for n in range(7)]},
        "describe_domains": lambda DomainNames: {
            "DomainStatusList": [{"DomainName": n, "Endpoint": f"{n}.example.com"} for n in DomainNames]
        },
    },
    "kafka": {
        "list_clusters_v2": {
            "ClusterInfoList": [
                {"ClusterArn": "arn:k:1", "ClusterName": "events", "ClusterType": "PROVISIONED", "State": "ACTIVE"},
                {"ClusterArn": "arn:k:2", "ClusterName": "new", "ClusterType": "PROVISIONED", "State": "CREATING"},
                {"ClusterArn": "arn:k:3", "ClusterName": "sls", "ClusterType": "SERVERLESS", "State": "ACTIVE"},
            ]
        },
        "get_bootstrap_brokers": lambda ClusterArn: {
            "BootstrapBrokerStringTls": f"b-1.{ClusterArn[-1]}.example.com:9094"
        },
        "list_nodes": {"NodeInfoList": []},
    },
    "redshift": {"describe_clusters": {"Clusters": [{"ClusterIdentifier": "dw", "ClusterStatus": "available"}]}},
    "redshift-serverless": {"list_workgroups": {"workgroups": [{"workgroupName": "wg", "status": "AVAILABLE"}]}},
}


class _Ec2:
    """EC2 for the map detail: the base detail answers, VPC endpoints and ENIs as given."""

    def __init__(self, calls: list, *, deny_enis: bool = False):
        self._calls = calls
        self._deny_enis = deny_enis

    def can_paginate(self, _operation):
        return False

    def describe_subnets(self):
        return {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}]}

    def describe_instances(self):
        return {"Reservations": []}

    def describe_customer_gateways(self):
        return {"CustomerGateways": []}

    def describe_network_acls(self):
        return {"NetworkAcls": []}

    def describe_transit_gateway_route_tables(self):
        return {"TransitGatewayRouteTables": []}

    def describe_vpc_endpoints(self):
        return {"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "NetworkInterfaceIds": ["eni-v1"]}]}

    def describe_network_interfaces(self, Filters):
        self._calls.append(("describe_network_interfaces", Filters[0]["Name"], list(Filters[0]["Values"])))
        if self._deny_enis:
            raise _ClientError("UnauthorizedOperation")
        return {"NetworkInterfaces": []}


class _Session:
    def __init__(self, answers: dict | None = None, *, unknown: tuple[str, ...] = ()):
        self.answers = {name: dict(table) for name, table in (answers or _SERVICE_ANSWERS).items()}
        self.calls: dict[str, list] = {}
        self.unknown = unknown

    def client(self, name, **_kwargs):
        if name in self.unknown:
            raise UnknownServiceError(name)
        return _Client(self.answers.get(name, {}), self.calls.setdefault(name, []))


def _detail(session: _Session, ec2: _Ec2 | None = None, steps: list | None = None) -> list[dict]:
    resources: list[dict] = []
    collectors_module._collect_aws_map_detail(
        session, ec2 or _Ec2([]), "us-east-1", None, resources, [], step=steps.append if steps is not None else None
    )
    return resources


def _types(resources: list[dict]) -> dict[str, int]:
    found: dict[str, int] = {}
    for resource in resources:
        found[resource["resource_type"]] = found.get(resource["resource_type"], 0) + 1
    return found


def _warnings(resources: list[dict]) -> dict[str, dict]:
    return {r["name"]: r["metadata"] for r in resources if r["resource_type"] == collect.WARNING_TYPE}


def test_map_detail_reads_every_service_and_reports_its_steps():
    steps: list[str] = []
    session = _Session()
    ec2_calls: list = []
    resources = _detail(session, _Ec2(ec2_calls), steps)
    assert _warnings(resources) == {}
    assert _types(resources) == {
        "subnet": 1,
        "rds_db_instance": 1,
        "rds_db_cluster": 1,
        "rds_db_proxy": 1,
        "load_balancer": 2,
        "vpc_endpoint": 1,
        "efs_file_system": 1,
        "elasticache_replication_group": 1,
        "opensearch_domain": 7,
        "msk_cluster": 3,
        "redshift_cluster": 1,
        "redshift_serverless_workgroup": 1,
    }
    assert steps == list(collectors_module._AWS_MAP_DETAIL_STEPS)
    # The cluster's subnet group came with its instance: no DescribeDBSubnetGroups.
    assert "describe_db_subnet_groups" not in [c[0] for c in session.calls["rds"]]
    # OpenSearch domains are described five at a time.
    assert [len(kw["DomainNames"]) for op, kw in session.calls["opensearch"] if op == "describe_domains"] == [5, 2]
    # Bootstrap brokers of the clusters that are up; nodes of the provisioned one only.
    kafka = [(op, kw.get("ClusterArn")) for op, kw in session.calls["kafka"]]
    assert ("get_bootstrap_brokers", "arn:k:2") not in kafka
    assert [arn for op, arn in kafka if op == "list_nodes"] == ["arn:k:1"]
    # One ENI lookup per kind of name: load balancers by description, VPC endpoints by ID.
    assert [(c[1], c[2]) for c in ec2_calls] == [
        ("description", ["ELB app/web/0a1b2c3d4e5f6071", "ELB legacy"]),
        ("network-interface-id", ["eni-v1"]),
    ]


def test_map_detail_with_every_service_denied_keeps_the_rest():
    denied = _ClientError("AccessDeniedException")
    session = _Session({name: {op: denied for op in table} for name, table in _SERVICE_ANSWERS.items()})
    resources = _detail(session)
    assert _types(resources)["subnet"] == 1 and _types(resources)["vpc_endpoint"] == 1
    warnings = _warnings(resources)
    assert set(warnings) == {
        "rds_db_instances",
        "rds_db_clusters",
        "rds_db_proxies",
        "load_balancers",
        "classic_load_balancers",
        "efs_file_systems",
        "elasticache_cache_clusters",
        "elasticache_replication_groups",
        "elasticache_serverless_caches",
        "opensearch_domain_names",
        "msk_clusters",
        "redshift_clusters",
        "redshift_serverless_workgroups",
    }
    assert {w["category"] for w in warnings.values()} == {"permission"}
    assert warnings["msk_clusters"]["actions"] == ["kafka:ListClustersV2"]
    assert warnings["load_balancers"]["actions"] == ["elasticloadbalancing:DescribeLoadBalancers"]


def test_map_detail_with_one_service_denied_reads_the_others():
    answers = {**_SERVICE_ANSWERS, "rds": {op: _ClientError("AccessDenied") for op in _SERVICE_ANSWERS["rds"]}}
    resources = _detail(_Session(answers))
    assert set(_warnings(resources)) == {"rds_db_instances", "rds_db_clusters", "rds_db_proxies"}
    assert not any(t.startswith("rds_") for t in _types(resources))
    assert _types(resources)["redshift_cluster"] == 1 and _types(resources)["msk_cluster"] == 3


def test_map_detail_keeps_a_service_it_cannot_fully_read():
    answers = {
        **_SERVICE_ANSWERS,
        "kafka": {**_SERVICE_ANSWERS["kafka"], "get_bootstrap_brokers": _ClientError("AccessDeniedException")},
    }
    resources = _detail(_Session(answers), _Ec2([], deny_enis=True))
    warnings = _warnings(resources)
    assert warnings["msk_bootstrap_brokers"]["actions"] == ["kafka:GetBootstrapBrokers"]
    assert warnings["load_balancer_network_interfaces"]["actions"] == ["ec2:DescribeNetworkInterfaces"]
    assert warnings["vpc_endpoint_network_interfaces"]["category"] == "permission"
    # The clusters and load balancers are kept without what was refused.
    assert _types(resources)["msk_cluster"] == 3 and _types(resources)["load_balancer"] == 2


def test_a_service_not_available_in_the_region_is_one_quiet_warning():
    unreachable = EndpointConnectionError("Could not connect to the endpoint URL")
    answers = {**_SERVICE_ANSWERS, "kafka": {op: unreachable for op in _SERVICE_ANSWERS["kafka"]}}
    answers["elasticache"] = {**answers["elasticache"], "describe_serverless_caches": _Client.MISSING}
    session = _Session(answers, unknown=("redshift-serverless",))
    resources = _detail(session)
    warnings = _warnings(resources)
    assert {k: (w["category"], w["error"]) for k, w in warnings.items()} == {
        "msk_clusters": ("unavailable", "EndpointConnectionError"),
        "elasticache_serverless_caches": ("unavailable", "OperationNotInSdk"),
        "redshift_serverless_workgroups": ("unavailable", "UnknownServiceError"),
    }
    # MSK stops at its first call.
    assert [op for op, _kw in session.calls["kafka"]] == ["list_clusters_v2"]
    assert _types(resources)["redshift_cluster"] == 1


def test_live_discovery_succeeds_with_every_optional_section_denied(monkeypatch):
    """The base EC2 sections are read; every optional one is refused."""
    import sys
    import types

    base = {
        "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.1.0.0/16", "State": "available"}]},
        "describe_route_tables": {"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Routes": []}]},
    }
    required = {
        "describe_vpcs",
        "describe_internet_gateways",
        "describe_nat_gateways",
        "describe_security_groups",
        "describe_transit_gateways",
        "describe_transit_gateway_attachments",
        "describe_vpc_peering_connections",
        "describe_vpn_gateways",
        "describe_route_tables",
        "describe_vpn_connections",
        "describe_connections",
    }

    class _AnyClient:
        def __init__(self, name):
            self.name = name

        def can_paginate(self, _operation):
            return False

        def get_caller_identity(self):
            return {"Account": "111122223333"}

        def __getattr__(self, operation):
            def call(**_kwargs):
                if operation in required:
                    return base.get(operation, {})
                raise _ClientError("AccessDenied")

            return call

    class _BotoSession:
        def __init__(self, **_kwargs):
            pass

        def client(self, name, **_kwargs):
            return _AnyClient(name)

    boto3 = types.ModuleType("boto3")
    boto3.Session = _BotoSession
    config = types.ModuleType("botocore.config")
    config.Config = lambda **_kwargs: None
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.BotoCoreError = type("BotoCoreError", (Exception,), {})
    exceptions.ClientError = _ClientError
    for name, module in (
        ("boto3", boto3),
        ("botocore", types.ModuleType("botocore")),
        ("botocore.config", config),
        ("botocore.exceptions", exceptions),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    resources, _connections = collectors_module.collect_provider_snapshot(
        {"provider": "aws", "region_scope": "us-east-1,eu-west-1", "auth_config_json": "{}"}
    )
    assert {r["resource_uid"] for r in resources if r["resource_type"] in ("vpc", "route_table")} == {
        "aws:vpc:vpc-1",
        "aws:route_table:rtb-1",
    }
    warnings = [r for r in resources if r["resource_type"] == collect.WARNING_TYPE]
    assert warnings and {w["metadata"]["category"] for w in warnings} == {"permission"}
    note = collectors_module.skipped_sections_note(resources)
    assert note.startswith("Collected with ") and "skipped for missing permissions" in note
    assert "rds:DescribeDBInstances" in note and "ec2:DescribeInstances" in note
    assert SECRET not in json.dumps(resources)


# ── The map ──────────────────────────────────────────────────────────────────


def _records() -> tuple[list[dict], list[dict]]:
    resources, connections = build_sample()
    return [{**r, "account_id": 1} for r in resources], [{**c, "account_id": 1} for c in connections]


@pytest.fixture(scope="module")
def snapshot() -> dict:
    resources, connections = _records()
    return build_snapshot([ACCOUNT], resources, connections)


def _site(snapshot: dict, site_id: str) -> dict:
    return next(s for s in snapshot["sites"] if s["id"] == site_id)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def test_snapshot_lists_each_service_in_its_vpc(snapshot):
    core = _site(snapshot, "vpc-0c0re00001")
    overview = dict(_section(core, "VPC overview")["rows"])
    assert overview["RDS and Aurora databases"] == "3" and overview["MSK clusters"] == "1"
    databases = {r[0]: r for r in _section(core, "RDS and Aurora databases")["rows"]}
    assert _section(core, "RDS and Aurora databases")["columns"] == aws_normalize.SERVICE_COLUMNS
    assert databases["core-orders"][2:5] == ["Aurora PostgreSQL cluster", "aurora-postgresql", "16.4"]
    assert "core-orders.cluster-ro-c0re0example.us-east-1.rds.amazonaws.com:5432" in databases["core-orders"][6]
    for title in (
        "Load balancers",
        "VPC endpoints",
        "EFS file systems",
        "ElastiCache",
        "OpenSearch domains",
        "Redshift",
    ):
        assert _section(core, title)["rows"], title
    # Versions are shown (and stored for every service that reports one).
    versions = {
        r[0]: r[4]
        for title in ("ElastiCache", "OpenSearch domains", "MSK clusters", "Redshift")
        for r in _section(core, title)["rows"]
    }
    assert versions == {
        "core-sessions": "8.0.1",
        "core-logs": "2.13",
        "core-events": "3.6.0",
        "core-dw": "1.0 (revision 77777)",
    }
    # The MSK cluster names only its subnets: the map places it by them.
    assert _section(core, "MSK clusters")["rows"][0][0] == "core-events"
    # Listed, not drawn: the sample's node count is unchanged.
    assert len(snapshot["nodes"]) == 13


def test_snapshot_service_endpoints_table_has_a_row_per_address(snapshot):
    core = _site(snapshot, "vpc-0c0re00001")
    table = _section(core, aws_normalize.SERVICE_ENDPOINT_SECTION_TITLE)
    assert table["columns"] == aws_normalize.SERVICE_ENDPOINT_COLUMNS
    assert [
        "Application load balancer",
        "core-api",
        "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/core-api/0c0re0a1b0000001",
        "Network interface eni-0c0re0a1b2",
        "",
        "",
        "10.200.11.80",
    ] in table["rows"]
    assert ["Redshift cluster", "core-dw"] == table["rows"][-1][:2]


def test_subnet_index_has_every_service_address(snapshot):
    index = subnet_index(snapshot)
    by_cidr = {s["cidr"]: s for s in index}
    assert (by_cidr["10.200.10.80/32"]["node_id"], by_cidr["10.200.10.80/32"]["name"]) == (
        "vpc:vpc-0c0re00001",
        "Application load balancer core-api",
    )
    assert by_cidr["10.200.11.110/32"]["name"] == "MSK cluster core-events"
    assert by_cidr["10.220.1.95/32"]["node_id"] == "vpc:vpc-0a9950003"
    # A public address is listed in the table, not indexed as a host of the VPC.
    assert "203.0.113.90/32" not in by_cidr
    found = subnets_containing(index, "10.200.20.50")
    assert [(s["cidr"], s["name"]) for s in found][0] == ("10.200.20.50/32", "Redshift cluster core-dw")


@pytest.mark.parametrize(
    ("query", "vpc"),
    [
        ("core-orders.cluster-ro-c0re0example.us-east-1.rds.amazonaws.com", "vpc-0c0re00001"),
        ("core-orders-proxy.proxy-c0re0example", "vpc-0c0re00001"),
        ("internal-core-api-0c0re0001.us-east-1.elb.amazonaws.com", "vpc-0c0re00001"),
        ("legacy-web-0ed9e0001.us-east-1.elb.amazonaws.com", "vpc-0ed9e00002"),
        ("vpce-0c0re0551-0example.ssm.us-east-1.vpce.amazonaws.com", "vpc-0c0re00001"),
        ("us-east-1b.fs-0c0re0ef5001.efs.us-east-1.amazonaws.com", "vpc-0c0re00001"),
        ("master.core-sessions.c0re01.use1.cache.amazonaws.com", "vpc-0c0re00001"),
        ("vpc-core-logs-0c0re0example.us-east-1.es.amazonaws.com", "vpc-0c0re00001"),
        ("b-2.coreevents.c0re01.c2.kafka.us-east-1.amazonaws.com", "vpc-0c0re00001"),
        ("core-dw.c0re0example.us-east-1.redshift.amazonaws.com", "vpc-0c0re00001"),
        ("apps-analytics.111122223333.us-west-2.redshift-serverless.amazonaws.com", "vpc-0a9950003"),
        ("apps-nlb-0a9950n1b0000001", "vpc-0a9950003"),
        ("fs-0c0re0ef5001", "vpc-0c0re00001"),
    ],
)
def test_search_finds_a_service_by_dns_name_or_id(snapshot, query, vpc):
    hits = search_index(build_search_index(snapshot), [query.lower()], 10)
    assert [h["node_id"] for h in hits] == [f"vpc:{vpc}"]


def test_a_service_whose_vpc_was_not_collected_is_left_off_the_map():
    resources = [
        collect.rds_instance_resource(_DB_INSTANCE, "us-east-1"),
        collect.msk_cluster_resource({"ClusterArn": "arn:k:1", "State": "ACTIVE"}, "us-east-1"),
    ]
    snap = build_snapshot([ACCOUNT], [{**r, "account_id": 1} for r in resources], [])
    assert snap["sites"] == [] and snap["nodes"] == []


def test_service_tables_are_capped(monkeypatch):
    monkeypatch.setattr(aws_normalize, "MAX_SITE_ROWS", 2)
    resources, connections = _records()
    core = _site(build_snapshot([ACCOUNT], resources, connections), "vpc-0c0re00001")
    assert len(_section(core, "RDS and Aurora databases")["rows"]) == 2
    assert len(_section(core, aws_normalize.SERVICE_ENDPOINT_SECTION_TITLE)["rows"]) == 2


# ── The report ───────────────────────────────────────────────────────────────


def _warning(section: str, region: str, code: str, **known) -> dict:
    title, actions = collectors_module.AWS_OPTIONAL_SECTIONS[section]
    warning = collect.warning_resource(section, region, _ClientError(code), title=title, actions=actions)
    return {**warning, **known, "account_id": 1}


def test_report_collapses_a_section_skipped_in_every_region():
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]
    resources = [
        *[_warning("rds_db_instances", r, "AccessDenied") for r in regions],
        # Two sections refused for the same action in the same regions share an entry.
        *[
            _warning(s, r, "UnauthorizedOperation")
            for s in ("fsx_network_interfaces", "load_balancer_network_interfaces")
            for r in regions[:2]
        ],
        _warning("msk_clusters", "ap-southeast-2", "EndpointConnectionError"),
        _warning("redshift_clusters", "eu-west-1", "ThrottlingException"),
    ]
    errors = build_snapshot([ACCOUNT], resources, [])["collection"]["errors"]
    assert [e["path"] for e in errors] == [
        "fsx_network_interfaces, load_balancer_network_interfaces (us-east-1, us-west-2)",
        "rds_db_instances (ap-southeast-2, eu-west-1, us-east-1, us-west-2)",
        "redshift_clusters (eu-west-1)",
        "msk_clusters (ap-southeast-2)",
    ]
    assert errors[1]["scope"] == "AWS account Prod"
    assert errors[1]["message"] == (
        "RDS and Aurora DB instances in ap-southeast-2, eu-west-1, us-east-1, us-west-2: not collected, "
        "AWS denied the call (AccessDenied). Add rds:DescribeDBInstances to the IAM policy of the account; "
        "the rest of the discovery is complete."
    )
    assert errors[0]["message"].startswith(
        "Addresses of FSx file systems, Private addresses of load balancers in us-east-1, us-west-2"
    )
    assert "Add ec2:DescribeNetworkInterfaces" in errors[0]["message"]
    assert "Run discovery again" in errors[2]["message"]
    assert "not available there" in errors[3]["message"]
    assert SECRET not in json.dumps(errors)


def test_report_classifies_a_warning_stored_before_categories():
    old = {**collect.warning_resource("instances", "us-east-1", _ClientError("UnauthorizedOperation")), "account_id": 1}
    old["metadata"] = {"section": "instances", "error": "UnauthorizedOperation"}
    errors = build_snapshot([ACCOUNT], [old], [])["collection"]["errors"]
    assert errors[0]["path"] == "instances (us-east-1)"
    assert "AWS denied the call (UnauthorizedOperation). The read-only policy" in errors[0]["message"]


# ── The discovery's message ──────────────────────────────────────────────────


def test_skipped_sections_note_names_the_actions_once():
    resources = [
        _warning("rds_db_instances", "us-east-1", "AccessDenied"),
        _warning("rds_db_instances", "eu-west-1", "AccessDenied"),
        _warning("msk_clusters", "us-east-1", "AccessDeniedException"),
        _warning("redshift_clusters", "us-east-1", "UnauthorizedOperation"),
        _warning("opensearch_domain_names", "ap-east-1", "OptInRequired"),
        _warning("efs_file_systems", "us-east-1", "ThrottlingException"),
    ]
    note = collectors_module.skipped_sections_note(resources)
    assert note == (
        "Collected with 3 sections skipped for missing permissions: kafka:ListClustersV2, "
        "rds:DescribeDBInstances, redshift:DescribeClusters; 1 section failed (ThrottlingException)."
    )
    message = collectors_module.with_skipped_note("Live provider discovery snapshot refreshed", resources)
    assert message == f"Live provider discovery snapshot refreshed. {note}"
    assert collectors_module.skipped_note(message) == note
    assert collectors_module.with_skipped_note("Done", []) == "Done"
    # Only a region where a service is not offered: nothing to say.
    assert collectors_module.skipped_sections_note([resources[4]]) == ""
    # Azure and GCP warnings carry no category: counted as skipped.
    azure = {
        "resource_type": "collection_warning",
        "name": "azure_firewalls",
        "metadata": {"section": "azure_firewalls"},
    }
    assert collectors_module.skipped_sections_note([azure]) == "Collected with 1 section skipped (azure_firewalls)."


# ── The permissions documented ───────────────────────────────────────────────

_DOC = pathlib.Path(__file__).resolve().parents[1] / "docs" / "aws-topology.md"
_ACTION = re.compile(r"`([a-z0-9-]+:[A-Za-z0-9]+)`")


def _permissions_doc() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.index("### Permissions")
    return text[start : text.index("\n## ", start)]


def test_documented_permissions_match_what_the_collector_calls():
    doc = _permissions_doc()
    optional = {a for _title, actions in collectors_module.AWS_OPTIONAL_SECTIONS.values() for a in actions}
    required = set(collectors_module.AWS_REQUIRED_ACTIONS)
    rows = [line for line in doc.splitlines() if line.startswith("| ") and _ACTION.search(line)]
    documented_required = {a for line in rows if "| Required |" in line for a in _ACTION.findall(line)}
    documented_optional = {a for line in rows if "| Optional |" in line for a in _ACTION.findall(line)}
    assert documented_required == required
    assert documented_optional == optional
    policy = json.loads(re.search(r"```json\n(.*?)\n```", doc, re.S).group(1))
    actions = {a for statement in policy["Statement"] for a in statement["Action"]}
    assert actions == required | optional


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-aws")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module

    routes_module._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def test_api_deep_search_finds_each_service(api):
    assert api.post("/api/sources/sample?provider=aws").status_code == 201
    ref = next(
        n["meraki"]["org_ref"]
        for n in api.get("/api/topology").json()["nodes"]
        if (n.get("meraki") or {}).get("provider") == "aws"
    )
    for query, vpc in (
        ("core-orders.cluster-c0re0example.us-east-1.rds.amazonaws.com", "vpc-0c0re00001"),
        ("internal-core-api-0c0re0001.us-east-1.elb.amazonaws.com", "vpc-0c0re00001"),
        ("vpce-0c0re0551", "vpc-0c0re00001"),
        ("fs-0c0re0ef5001.efs.us-east-1.amazonaws.com", "vpc-0c0re00001"),
        ("replica.core-sessions.c0re01.use1.cache.amazonaws.com", "vpc-0c0re00001"),
        ("vpc-core-logs-0c0re0example.us-east-1.es.amazonaws.com", "vpc-0c0re00001"),
        ("b-1.coreevents.c0re01.c2.kafka.us-east-1.amazonaws.com", "vpc-0c0re00001"),
        ("core-dw.c0re0example.us-east-1.redshift.amazonaws.com", "vpc-0c0re00001"),
        ("apps-analytics", "vpc-0a9950003"),
        # By address: a service's own address finds its VPC.
        ("10.200.11.80", "vpc-0c0re00001"),
        ("10.200.11.110", "vpc-0c0re00001"),
        ("10.220.1.95", "vpc-0a9950003"),
    ):
        response = api.get("/api/topology/search/deep", params={"q": query})
        assert response.status_code == 200, response.text
        hits = response.json()["results"]
        assert hits and hits[0]["node_id"] == f"vpc:{vpc}" and hits[0]["org_ref"] == ref, (query, hits[:2])


@pytest.mark.asyncio
async def test_discover_message_names_the_sections_skipped(monkeypatch):
    await db_module.init_db()
    account = await db_module.create_cloud_account(provider="aws", name="AWS Partial")

    def _collector(_account, _progress=None):
        return (
            [
                {
                    "provider": "aws",
                    "resource_uid": "aws:vpc:vpc-1",
                    "resource_type": "vpc",
                    "name": "core",
                    "region": "us-east-1",
                    "cidr": "10.1.0.0/16",
                    "status": "available",
                },
                _warning("rds_db_instances", "us-east-1", "AccessDenied"),
                _warning("msk_clusters", "us-east-1", "AccessDeniedException"),
            ],
            [],
        )

    monkeypatch.setattr(cloud_visibility_module, "collect_provider_snapshot", _collector)

    class _Request:
        cookies: dict = {}
        state = type("State", (), {"correlation_id": "corr"})()

    result = await cloud_visibility_module.discover_cloud_account_api(
        int(account["id"]), _Request(), cloud_visibility_module.CloudDiscoveryRequest(mode="live")
    )
    assert result["ok"] is True
    assert result["message"] == (
        "Live provider discovery snapshot refreshed. Collected with 2 sections skipped for missing permissions: "
        "kafka:ListClustersV2, rds:DescribeDBInstances."
    )
    stored = await db_module.get_cloud_account(int(account["id"]))
    assert stored["last_sync_status"] == "success" and stored["last_sync_message"] == result["message"]

    from netcontrol.routes.meraki_topology import _cloud_source

    source = _cloud_source({**stored, "id": stored["id"]})
    assert source["status"] == "success"
    assert source["message"].startswith("Collected with 2 sections skipped for missing permissions")
