"""Demo AWS discovery (no credentials needed).

The records have the shape the Cloud Visibility AWS collector returns, so
sample discovery exercises the same path to the Topology map as a live one:
three VPCs in two regions, a transit gateway with its route table, a VPC
peering, a firewall pair that forwards traffic (and a Palo Alto VM-Series
firewall the Panorama sample manages), a site-to-site VPN with one
tunnel down, a Direct Connect, the network ACLs and security groups that
decide what the database subnet accepts, a database server on a public
address whose security group admits only two partner egress addresses, and
three Amazon FSx file systems (NetApp ONTAP with a storage virtual machine,
Windows File Server, Lustre), and one of each service whose endpoints have
DNS names (an Aurora cluster with its instance and proxy, an Application,
a Network and a Classic Load Balancer, interface and gateway VPC endpoints,
an EFS file system, an ElastiCache replication group, an OpenSearch domain,
an MSK cluster, a Redshift cluster and a Redshift Serverless workgroup).
Public addresses are from the documentation ranges.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.aws import collect

_R1 = "us-east-1"
_R2 = "us-west-2"


def _res(
    uid: str, kind: str, name: str, region: str, *, cidr: str = "", status: str = "available", **meta: Any
) -> dict:
    return {
        "resource_uid": f"aws:{uid}",
        "resource_type": kind,
        "name": name,
        "region": region,
        "cidr": cidr,
        "status": status,
        "metadata": meta,
    }


def _conn(source: str, target: str, kind: str, state: str = "available", **meta: Any) -> dict:
    return {
        "source_resource_uid": f"aws:{source}",
        "target_resource_uid": f"aws:{target}",
        "connection_type": kind,
        "state": state,
        "metadata": meta,
    }


def _subnet(subnet_id: str, name: str, vpc: str, cidr: str, zone: str, region: str = _R1) -> dict:
    return _res(
        f"subnet:{subnet_id}",
        "subnet",
        name,
        region,
        cidr=cidr,
        subnet_id=subnet_id,
        vpc_id=vpc,
        availability_zone=zone,
        available_ips=180,
        map_public_ip=False,
        ipv6_cidrs=[],
    )


def _route(destination: str, target: str) -> dict:
    return {"destination": destination, "target": target, "state": "active", "origin": "CreateRoute"}


def _instance(
    instance_id: str,
    name: str,
    vpc: str,
    interfaces: list[tuple[str, str, str]],
    *,
    kind: str,
    forwards: bool,
    zone: str,
    group: tuple[str, str],
    region: str = _R1,
    status: str = "running",
) -> dict:
    """``interfaces`` are ``(subnet id, private IP, public IP)`` in device
    order; ``group`` is the ``(id, name)`` of the instance's security group."""
    return _res(
        f"instance:{instance_id}",
        "instance",
        name,
        region,
        status=status,
        instance_id=instance_id,
        vpc_id=vpc,
        subnet_id=interfaces[0][0],
        availability_zone=zone,
        instance_type=kind,
        platform="Linux/UNIX",
        private_ip=interfaces[0][1],
        public_ip=next((public for _s, _p, public in interfaces if public), ""),
        source_dest_check=not forwards,
        security_groups=[group[1]],
        security_group_ids=[group[0]],
        launched="2026-03-02T14:05:00+00:00",
        interfaces=[
            {
                "id": f"eni-{instance_id[2:]}{index}",
                "subnet_id": subnet,
                "description": "",
                "device_index": index,
                "mac": "",
                "private_ips": [private],
                "public_ips": [public] if public else [],
                "source_dest_check": not forwards,
                "security_group_ids": [group[0]],
            }
            for index, (subnet, private, public) in enumerate(interfaces)
        ],
    )


def _acl_entry(number: int, egress: bool, action: str, protocol: str = "all", cidr: str = "0.0.0.0/0", ports=None):
    return {
        "rule_number": number,
        "egress": egress,
        "action": action,
        "protocol": protocol,
        "cidr": cidr,
        "port_from": ports[0] if ports else None,
        "port_to": ports[1] if ports else None,
    }


def _acl(acl_id: str, name: str, vpc: str, subnets: list[str], entries: list[dict] | None = None, region: str = _R1):
    """A network ACL; without ``entries`` it allows everything, like a default ACL."""
    rules = entries if entries is not None else [_acl_entry(100, False, "allow"), _acl_entry(100, True, "allow")]
    # Every ACL ends in the rule that denies what nothing above it matched.
    rules = [*rules, _acl_entry(32767, False, "deny"), _acl_entry(32767, True, "deny")]
    return _res(
        f"network_acl:{acl_id}",
        "network_acl",
        name,
        region,
        status="active",
        vpc_id=vpc,
        is_default=entries is None,
        subnet_ids=subnets,
        entries=sorted(rules, key=lambda e: (e["egress"], e["rule_number"])),
    )


def _rule(group: str, direction: str, index: int, protocol: str, ports: str, peer: str) -> dict:
    inbound = direction == "inbound"
    return {
        "rule_uid": f"aws:sg:{group}:{direction}:{index}",
        "rule_name": f"{direction}-{index}",
        "direction": direction,
        "action": "allow",
        "protocol": protocol,
        "source_selector": peer if inbound else "self",
        "destination_selector": "self" if inbound else peer,
        "port_expression": ports,
        "priority": None,
    }


def _group(group: tuple[str, str], vpc: str, inbound: list[tuple[str, str, str]], region: str = _R1) -> dict:
    """A security group that lets ``inbound`` ``(protocol, ports, source)`` in and everything out."""
    rules = [_rule(group[0], "inbound", i + 1, *rule) for i, rule in enumerate(inbound)]
    rules.append(_rule(group[0], "outbound", 1, "all", "all", "0.0.0.0/0"))
    return _res(f"sg:{group[0]}", "security_group", group[1], region, status="active", vpc_id=vpc, policy_rules=rules)


def _tgw_route(destination: str, attachment: str, kind: str, resource: str, how: str = "propagated") -> dict:
    return {
        "destination": destination,
        "state": "active",
        "type": how,
        "attachments": [{"attachment_id": attachment, "resource_type": kind, "resource_id": resource}],
    }


def _eni(eni_id: str, subnet_id: str, address: str) -> dict:
    """A ``DescribeNetworkInterfaces`` item of an FSx file system."""
    return {
        "NetworkInterfaceId": eni_id,
        "SubnetId": subnet_id,
        "Description": "ENI for Amazon FSx",
        "PrivateIpAddress": address,
        "PrivateIpAddresses": [{"PrivateIpAddress": address}],
    }


def _fsx(core: str, apps: str) -> list[dict]:
    """The FSx file systems and storage virtual machine of the demo, built
    from ``DescribeFileSystems`` / ``DescribeStorageVirtualMachines`` items
    by the collector's own reshaping."""
    ontap_id, windows_id, lustre_id = "fs-0c0re0a0a7001", "fs-0c0re0w1n0001", "fs-0a995015e0001"
    ontap = {
        "FileSystemId": ontap_id,
        "FileSystemType": "ONTAP",
        "Lifecycle": "AVAILABLE",
        "OwnerId": "111122223333",
        "StorageCapacity": 1024,
        "StorageType": "SSD",
        "VpcId": core,
        "SubnetIds": ["subnet-0c0re0a"],
        "Tags": [{"Key": "Name", "Value": "core-ontap"}],
        "OntapConfiguration": {
            "DeploymentType": "SINGLE_AZ_1",
            "PreferredSubnetId": "subnet-0c0re0a",
            "ThroughputCapacity": 128,
            "Endpoints": {
                "Management": {
                    "DNSName": f"management.{ontap_id}.fsx.us-east-1.amazonaws.com",
                    "IpAddresses": ["10.200.10.50"],
                },
                "Intercluster": {
                    "DNSName": f"intercluster.{ontap_id}.fsx.us-east-1.amazonaws.com",
                    "IpAddresses": ["10.200.10.51", "10.200.10.52"],
                },
            },
        },
    }
    svm = {
        "StorageVirtualMachineId": "svm-0c0re0a0a7001",
        "FileSystemId": ontap_id,
        "Name": "core-svm1",
        "Lifecycle": "CREATED",
        "Subtype": "DEFAULT",
        "RootVolumeSecurityStyle": "MIXED",
        "ActiveDirectoryConfiguration": {"NetBiosName": "CORESVM1"},
        "Endpoints": {
            "Nfs": {
                "DNSName": f"svm-0c0re0a0a7001.{ontap_id}.fsx.us-east-1.amazonaws.com",
                "IpAddresses": ["10.200.10.60"],
            },
            "Smb": {"DNSName": "coresvm1.corp.example.com", "IpAddresses": ["10.200.10.60"]},
            "Iscsi": {
                "DNSName": f"iscsi.svm-0c0re0a0a7001.{ontap_id}.fsx.us-east-1.amazonaws.com",
                "IpAddresses": ["10.200.10.61", "10.200.10.62"],
            },
            "Management": {
                "DNSName": f"svm-0c0re0a0a7001.{ontap_id}.fsx.us-east-1.amazonaws.com",
                "IpAddresses": ["10.200.10.60"],
            },
        },
    }
    windows = {
        "FileSystemId": windows_id,
        "FileSystemType": "WINDOWS",
        "Lifecycle": "AVAILABLE",
        "OwnerId": "111122223333",
        "StorageCapacity": 300,
        "StorageType": "SSD",
        "VpcId": core,
        "SubnetIds": ["subnet-0c0re0a"],
        "NetworkInterfaceIds": ["eni-0w1n00001"],
        "DNSName": "amznfsx0w1n0001.corp.example.com",
        "Tags": [{"Key": "Name", "Value": "core-files"}],
        "WindowsConfiguration": {
            "ActiveDirectoryId": "d-0c0re00001",
            "DeploymentType": "SINGLE_AZ_2",
            "PreferredSubnetId": "subnet-0c0re0a",
            "PreferredFileServerIp": "10.200.10.70",
            "RemoteAdministrationEndpoint": "amznfsx0w1n0002.corp.example.com",
            "ThroughputCapacity": 32,
            "Aliases": [{"Name": "files.corp.example.com", "Lifecycle": "AVAILABLE"}],
        },
    }
    lustre = {
        "FileSystemId": lustre_id,
        "FileSystemType": "LUSTRE",
        "FileSystemTypeVersion": "2.15",
        "Lifecycle": "AVAILABLE",
        "OwnerId": "111122223333",
        "StorageCapacity": 1200,
        "StorageType": "SSD",
        "VpcId": apps,
        "SubnetIds": ["subnet-0a9950w"],
        "NetworkInterfaceIds": ["eni-0a9951u5e1", "eni-0a9951u5e2"],
        "DNSName": f"{lustre_id}.fsx.us-west-2.amazonaws.com",
        "Tags": [{"Key": "Name", "Value": "apps-scratch"}],
        "LustreConfiguration": {"DeploymentType": "PERSISTENT_2", "MountName": "a1b2c3d4"},
    }
    interfaces = collect.network_interfaces_by_id(
        [
            _eni("eni-0w1n00001", "subnet-0c0re0a", "10.200.10.70"),
            _eni("eni-0a9951u5e1", "subnet-0a9950w", "10.220.1.80"),
            _eni("eni-0a9951u5e2", "subnet-0a9950w", "10.220.1.81"),
        ]
    )
    found = [
        collect.fsx_file_system_resource(ontap, _R1, interfaces),
        collect.fsx_file_system_resource(windows, _R1, interfaces),
        collect.fsx_file_system_resource(lustre, _R2, interfaces),
        collect.fsx_storage_virtual_machine_resource(svm, _R1, core),
    ]
    return [resource for resource in found if resource]


def _lb_eni(eni_id: str, subnet_id: str, address: str, description: str) -> dict:
    """A ``DescribeNetworkInterfaces`` item of a load balancer (named by its description)."""
    return {**_eni(eni_id, subnet_id, address), "Description": description}


def _services(core: str, edge: str, apps: str) -> list[dict]:
    """One of each service whose endpoints have DNS names (RDS / Aurora,
    load balancers, VPC endpoints, EFS, ElastiCache, OpenSearch, MSK,
    Redshift), built from their API items by the collector's own reshaping."""
    acct = "111122223333"
    rds_arn = f"arn:aws:rds:{_R1}:{acct}"
    subnet_group = {
        "DBSubnetGroupName": "core-db-subnets",
        "VpcId": core,
        "Subnets": [{"SubnetIdentifier": "subnet-0c0re0d"}, {"SubnetIdentifier": "subnet-0c0re0b"}],
    }
    groups = collect.subnet_groups_by_name([subnet_group], "DBSubnetGroupName")
    db_instance = {
        "DBInstanceIdentifier": "core-orders-1",
        "DBInstanceArn": f"{rds_arn}:db:core-orders-1",
        "DBInstanceClass": "db.r6g.large",
        "Engine": "aurora-postgresql",
        "EngineVersion": "16.4",
        "DBInstanceStatus": "available",
        "Endpoint": {"Address": "core-orders-1.c0re0example.us-east-1.rds.amazonaws.com", "Port": 5432},
        "DBSubnetGroup": subnet_group,
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0c0re0d1", "Status": "active"}],
        "AvailabilityZone": "us-east-1a",
        "DBClusterIdentifier": "core-orders",
    }
    db_cluster = {
        "DBClusterIdentifier": "core-orders",
        "DBClusterArn": f"{rds_arn}:cluster:core-orders",
        "Engine": "aurora-postgresql",
        "EngineVersion": "16.4",
        "EngineMode": "provisioned",
        "Status": "available",
        "Port": 5432,
        "DBSubnetGroup": "core-db-subnets",
        "Endpoint": "core-orders.cluster-c0re0example.us-east-1.rds.amazonaws.com",
        "ReaderEndpoint": "core-orders.cluster-ro-c0re0example.us-east-1.rds.amazonaws.com",
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0c0re0d1"}],
        "DBClusterMembers": [{"DBInstanceIdentifier": "core-orders-1", "IsClusterWriter": True}],
    }
    db_proxy = {
        "DBProxyName": "core-orders-proxy",
        "DBProxyArn": f"{rds_arn}:db-proxy:prx-0c0re0000000001",
        "Status": "available",
        "EngineFamily": "POSTGRESQL",
        "VpcId": core,
        "VpcSubnetIds": ["subnet-0c0re0d", "subnet-0c0re0b"],
        "VpcSecurityGroupIds": ["sg-0c0re0d1"],
        "Endpoint": "core-orders-proxy.proxy-c0re0example.us-east-1.rds.amazonaws.com",
        "RequireTLS": True,
    }
    alb = {
        "LoadBalancerArn": f"arn:aws:elasticloadbalancing:{_R1}:{acct}:loadbalancer/app/core-api/0c0re0a1b0000001",
        "LoadBalancerName": "core-api",
        "DNSName": "internal-core-api-0c0re0001.us-east-1.elb.amazonaws.com",
        "Scheme": "internal",
        "VpcId": core,
        "Type": "application",
        "State": {"Code": "active"},
        "AvailabilityZones": [
            {"ZoneName": "us-east-1a", "SubnetId": "subnet-0c0re0a"},
            {"ZoneName": "us-east-1b", "SubnetId": "subnet-0c0re0b"},
        ],
        "SecurityGroups": ["sg-0c0re0a1"],
    }
    alb_enis = collect.network_interfaces_by_description(
        [
            _lb_eni("eni-0c0re0a1b1", "subnet-0c0re0a", "10.200.10.80", "ELB app/core-api/0c0re0a1b0000001"),
            _lb_eni("eni-0c0re0a1b2", "subnet-0c0re0b", "10.200.11.80", "ELB app/core-api/0c0re0a1b0000001"),
        ]
    )
    nlb = {
        "LoadBalancerArn": f"arn:aws:elasticloadbalancing:{_R2}:{acct}:loadbalancer/net/apps-nlb/0a9950n1b0000001",
        "LoadBalancerName": "apps-nlb",
        "DNSName": "apps-nlb-0a9950n1b0000001.elb.us-west-2.amazonaws.com",
        "Scheme": "internet-facing",
        "VpcId": apps,
        "Type": "network",
        "State": {"Code": "active"},
        "AvailabilityZones": [
            {
                "ZoneName": "us-west-2a",
                "SubnetId": "subnet-0a9950w",
                "LoadBalancerAddresses": [{"IpAddress": "203.0.113.90", "PrivateIPv4Address": "10.220.1.90"}],
            }
        ],
    }
    classic = {
        "LoadBalancerName": "legacy-web",
        "DNSName": "legacy-web-0ed9e0001.us-east-1.elb.amazonaws.com",
        "VPCId": edge,
        "Subnets": ["subnet-0ed9e0o"],
        "Scheme": "internet-facing",
        "SecurityGroups": ["sg-0ed9e0f1"],
        "ListenerDescriptions": [{"Listener": {"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80}}],
    }
    ssm_endpoint = {
        "VpcEndpointId": "vpce-0c0re0551",
        "VpcEndpointType": "Interface",
        "VpcId": core,
        "ServiceName": "com.amazonaws.us-east-1.ssm",
        "State": "available",
        "SubnetIds": ["subnet-0c0re0a"],
        "Groups": [{"GroupId": "sg-0c0re0a1", "GroupName": "core-app"}],
        "PrivateDnsEnabled": True,
        "NetworkInterfaceIds": ["eni-0c0re0vpce1"],
        "DnsEntries": [
            {"DnsName": "vpce-0c0re0551-0example.ssm.us-east-1.vpce.amazonaws.com"},
            {"DnsName": "ssm.us-east-1.amazonaws.com"},
        ],
        "Tags": [{"Key": "Name", "Value": "core-ssm"}],
    }
    s3_endpoint = {
        "VpcEndpointId": "vpce-0c0re053",
        "VpcEndpointType": "Gateway",
        "VpcId": core,
        "ServiceName": "com.amazonaws.us-east-1.s3",
        "State": "available",
        "RouteTableIds": ["rtb-0c0re0main"],
    }
    vpce_enis = collect.network_interfaces_by_id([_eni("eni-0c0re0vpce1", "subnet-0c0re0a", "10.200.10.90")])
    efs = {
        "FileSystemId": "fs-0c0re0ef5001",
        "Name": "core-shared",
        "OwnerId": acct,
        "LifeCycleState": "available",
        "NumberOfMountTargets": 2,
        "PerformanceMode": "generalPurpose",
        "ThroughputMode": "elastic",
    }
    mount_targets = [
        {
            "MountTargetId": "fsmt-0c0re0a",
            "FileSystemId": "fs-0c0re0ef5001",
            "SubnetId": "subnet-0c0re0a",
            "VpcId": core,
            "LifeCycleState": "available",
            "IpAddress": "10.200.10.100",
            "NetworkInterfaceId": "eni-0c0re0ef5a",
            "AvailabilityZoneName": "us-east-1a",
        },
        {
            "MountTargetId": "fsmt-0c0re0b",
            "FileSystemId": "fs-0c0re0ef5001",
            "SubnetId": "subnet-0c0re0b",
            "VpcId": core,
            "LifeCycleState": "available",
            "IpAddress": "10.200.11.100",
            "NetworkInterfaceId": "eni-0c0re0ef5b",
            "AvailabilityZoneName": "us-east-1b",
        },
    ]
    cache_groups = collect.subnet_groups_by_name(
        [
            {
                "CacheSubnetGroupName": "core-cache-subnets",
                "VpcId": core,
                "Subnets": [{"SubnetIdentifier": "subnet-0c0re0a"}, {"SubnetIdentifier": "subnet-0c0re0b"}],
            }
        ],
        "CacheSubnetGroupName",
    )
    cache_members = [
        {
            "CacheClusterId": f"core-sessions-00{n}",
            "ReplicationGroupId": "core-sessions",
            "Engine": "valkey",
            "EngineVersion": "8.0.1",
            "CacheClusterStatus": "available",
            "CacheSubnetGroupName": "core-cache-subnets",
            "SecurityGroups": [{"SecurityGroupId": "sg-0c0re0a1", "Status": "active"}],
            "CacheNodes": [
                {
                    "CacheNodeId": "0001",
                    "Endpoint": {"Address": f"core-sessions-00{n}.c0re01.0001.use1.cache.amazonaws.com", "Port": 6379},
                }
            ],
        }
        for n in (1, 2)
    ]
    cache_group = {
        "ReplicationGroupId": "core-sessions",
        "ARN": f"arn:aws:elasticache:{_R1}:{acct}:replicationgroup:core-sessions",
        "Status": "available",
        "Engine": "valkey",
        "CacheNodeType": "cache.r7g.large",
        "ClusterEnabled": False,
        "MultiAZ": "enabled",
        "NodeGroups": [
            {
                "NodeGroupId": "0001",
                "PrimaryEndpoint": {"Address": "master.core-sessions.c0re01.use1.cache.amazonaws.com", "Port": 6379},
                "ReaderEndpoint": {"Address": "replica.core-sessions.c0re01.use1.cache.amazonaws.com", "Port": 6379},
            }
        ],
    }
    domain = {
        "DomainId": f"{acct}/core-logs",
        "DomainName": "core-logs",
        "ARN": f"arn:aws:es:{_R1}:{acct}:domain/core-logs",
        "Deleted": False,
        "Processing": False,
        "EngineVersion": "OpenSearch_2.13",
        "Endpoints": {"vpc": "vpc-core-logs-0c0re0example.us-east-1.es.amazonaws.com"},
        "ClusterConfig": {"InstanceType": "r6g.large.search", "InstanceCount": 3},
        "VPCOptions": {
            "VPCId": core,
            "SubnetIds": ["subnet-0c0re0a", "subnet-0c0re0b"],
            "SecurityGroupIds": ["sg-0c0re0a1"],
        },
        "DomainEndpointOptions": {
            "EnforceHTTPS": True,
            "CustomEndpointEnabled": True,
            "CustomEndpoint": "logs.example.com",
        },
        "AdvancedSecurityOptions": {"Enabled": True, "InternalUserDatabaseEnabled": True},
    }
    msk_arn = f"arn:aws:kafka:{_R1}:{acct}:cluster/core-events/0c0re0e0-0000-0000-0000-000000000001-2"
    brokers = [f"b-{n}.coreevents.c0re01.c2.kafka.us-east-1.amazonaws.com" for n in (1, 2)]
    msk = {
        "ClusterArn": msk_arn,
        "ClusterName": "core-events",
        "ClusterType": "PROVISIONED",
        "State": "ACTIVE",
        "Provisioned": {
            "BrokerNodeGroupInfo": {
                "ClientSubnets": ["subnet-0c0re0a", "subnet-0c0re0b"],
                "SecurityGroups": ["sg-0c0re0a1"],
                "InstanceType": "kafka.m7g.large",
            },
            "CurrentBrokerSoftwareInfo": {"KafkaVersion": "3.6.0"},
            "NumberOfBrokerNodes": 2,
        },
    }
    msk_bootstrap = {"BootstrapBrokerStringTls": ",".join(f"{b}:9094" for b in brokers)}
    msk_nodes = [
        {
            "NodeType": "BROKER",
            "BrokerNodeInfo": {
                "BrokerId": float(n),
                "ClientSubnet": subnet,
                "ClientVpcIpAddress": address,
                "AttachedENIId": f"eni-0c0re0b5k{n}",
                "Endpoints": [brokers[n - 1]],
            },
        }
        for n, subnet, address in ((1, "subnet-0c0re0a", "10.200.10.110"), (2, "subnet-0c0re0b", "10.200.11.110"))
    ]
    warehouse = {
        "ClusterIdentifier": "core-dw",
        "ClusterNamespaceArn": f"arn:aws:redshift:{_R1}:{acct}:namespace:0c0re0d0-0000-0000-0000-000000000001",
        "NodeType": "ra3.xlplus",
        "NumberOfNodes": 2,
        "ClusterStatus": "available",
        "ClusterVersion": "1.0",
        "ClusterRevisionNumber": "77777",
        "VpcId": core,
        "ClusterSubnetGroupName": "core-dw-subnets",
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0c0re0d1"}],
        "Endpoint": {"Address": "core-dw.c0re0example.us-east-1.redshift.amazonaws.com", "Port": 5439},
        "ClusterNodes": [
            {"NodeRole": "LEADER", "PrivateIPAddress": "10.200.20.50"},
            {"NodeRole": "COMPUTE-0", "PrivateIPAddress": "10.200.20.51"},
        ],
    }
    workgroup = {
        "workgroupName": "apps-analytics",
        "workgroupId": "0a9950a0-0000-0000-0000-000000000001",
        "workgroupArn": f"arn:aws:redshift-serverless:{_R2}:{acct}:workgroup/0a9950a0-0000-0000-0000-000000000001",
        "namespaceName": "apps-analytics-ns",
        "status": "AVAILABLE",
        "workgroupVersion": "1.0.99",
        "baseCapacity": 8,
        "subnetIds": ["subnet-0a9950w"],
        "securityGroupIds": ["sg-0a9950a1"],
        "endpoint": {
            "address": f"apps-analytics.{acct}.us-west-2.redshift-serverless.amazonaws.com",
            "port": 5439,
            "vpcEndpoints": [
                {
                    "vpcEndpointId": "vpce-0a9950rs1",
                    "vpcId": apps,
                    "networkInterfaces": [{"networkInterfaceId": "eni-0a9950rs1", "privateIpAddress": "10.220.1.95"}],
                }
            ],
        },
    }
    found = [
        collect.rds_instance_resource(db_instance, _R1),
        collect.rds_cluster_resource(db_cluster, _R1, groups),
        collect.rds_proxy_resource(db_proxy, _R1),
        collect.load_balancer_resource(alb, _R1, alb_enis.get(collect.load_balancer_eni_description(alb))),
        collect.load_balancer_resource(nlb, _R2),
        collect.load_balancer_resource(classic, _R1),
        collect.vpc_endpoint_resource(ssm_endpoint, _R1, vpce_enis),
        collect.vpc_endpoint_resource(s3_endpoint, _R1),
        collect.efs_file_system_resource(efs, _R1, mount_targets),
        collect.elasticache_replication_group_resource(cache_group, _R1, cache_members, cache_groups),
        collect.opensearch_domain_resource(domain, _R1),
        collect.msk_cluster_resource(msk, _R1, msk_bootstrap, msk_nodes),
        collect.redshift_cluster_resource(warehouse, _R1),
        collect.redshift_workgroup_resource(workgroup, _R2),
    ]
    return [resource for resource in found if resource]


def build_sample() -> tuple[list[dict], list[dict]]:
    """``(resources, connections)`` of the demo AWS account."""
    core, edge, apps = "vpc-0c0re00001", "vpc-0ed9e00002", "vpc-0a9950003"
    tgw = "tgw-0910ba100001"
    tgw_table = "tgw-rtb-0ma1n0001"
    peering = "pcx-0c0re0a99"
    sg_edge = ("sg-0ed9e0f1", "edge-firewalls")
    sg_app = ("sg-0c0re0a1", "core-app")
    sg_db = ("sg-0c0re0d1", "core-db")
    sg_sql = ("sg-0ed9e0s1", "sql-public")
    resources = [
        _res(f"vpc:{core}", "vpc", "prod-core-vpc", _R1, cidr="10.200.0.0/16", is_default=False),
        _res(f"vpc:{edge}", "vpc", "edge-security-vpc", _R1, cidr="10.210.0.0/16", is_default=False),
        _res(f"vpc:{apps}", "vpc", "apps-west-vpc", _R2, cidr="10.220.0.0/16", is_default=False),
        _subnet("subnet-0c0re0a", "core-app-a", core, "10.200.10.0/24", "us-east-1a"),
        _subnet("subnet-0c0re0b", "core-app-b", core, "10.200.11.0/24", "us-east-1b"),
        _subnet("subnet-0c0re0d", "core-db-a", core, "10.200.20.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0o", "edge-outside-a", edge, "10.210.0.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0i", "edge-inside-a", edge, "10.210.1.0/24", "us-east-1a"),
        _subnet("subnet-0ed9e0m", "edge-mgmt-a", edge, "10.210.2.0/24", "us-east-1a"),
        _subnet("subnet-0a9950w", "apps-web-a", apps, "10.220.1.0/24", "us-west-2a", _R2),
        _res(f"tgw:{tgw}", "transit_gateway", "global-tgw", _R1, owner_id="111122223333", amazon_asn="64512"),
        _res("internet_gateway:igw-0ed9e", "internet_gateway", "igw-0ed9e", _R1, status="available", vpc_ids=[edge]),
        _res("internet_gateway:igw-0c0re", "internet_gateway", "igw-0c0re", _R1, status="available", vpc_ids=[core]),
        _res(
            "nat_gateway:nat-0c0re0a",
            "nat_gateway",
            "nat-0c0re0a",
            _R1,
            vpc_id=core,
            subnet_id="subnet-0c0re0a",
            connectivity_type="public",
            public_ips=["203.0.113.40"],
            private_ips=["10.200.10.5"],
        ),
        _res(
            "route_table:rtb-0c0re",
            "route_table",
            "core-private",
            _R1,
            status="active",
            vpc_id=core,
            route_count=4,
            association_count=3,
            associated_subnet_ids=["subnet-0c0re0a", "subnet-0c0re0b", "subnet-0c0re0d"],
            main=True,
            propagating_vgws=[],
            routes=[
                _route("10.200.0.0/16", "local"),
                _route("10.0.0.0/8", tgw),
                _route("10.220.0.0/16", peering),
                _route("0.0.0.0/0", "nat-0c0re0a"),
            ],
        ),
        _res(
            "route_table:rtb-0a995",
            "route_table",
            "apps-main",
            _R2,
            status="active",
            vpc_id=apps,
            route_count=2,
            association_count=1,
            associated_subnet_ids=[],
            main=True,
            propagating_vgws=[],
            routes=[_route("10.220.0.0/16", "local"), _route("10.200.0.0/16", peering)],
        ),
        _res(
            "route_table:rtb-0ed9e0o",
            "route_table",
            "edge-outside",
            _R1,
            status="active",
            vpc_id=edge,
            route_count=2,
            association_count=1,
            associated_subnet_ids=["subnet-0ed9e0o"],
            main=False,
            propagating_vgws=[],
            routes=[_route("10.210.0.0/16", "local"), _route("0.0.0.0/0", "igw-0ed9e")],
        ),
        _res(
            "route_table:rtb-0ed9e0i",
            "route_table",
            "edge-inside",
            _R1,
            status="active",
            vpc_id=edge,
            route_count=3,
            association_count=2,
            associated_subnet_ids=["subnet-0ed9e0i", "subnet-0ed9e0m"],
            main=True,
            propagating_vgws=[],
            routes=[
                _route("10.210.0.0/16", "local"),
                _route("10.0.0.0/8", tgw),
                _route("0.0.0.0/0", "eni-0f7d0011"),
            ],
        ),
        _instance(
            "i-0f7d001",
            "ftdv-ravpn-1",
            edge,
            [
                ("subnet-0ed9e0m", "10.210.2.11", ""),
                ("subnet-0ed9e0o", "10.210.0.11", "203.0.113.11"),
                ("subnet-0ed9e0i", "10.210.1.11", ""),
            ],
            kind="c5.xlarge",
            forwards=True,
            zone="us-east-1a",
            group=sg_edge,
        ),
        _instance(
            "i-0f7d002",
            "ftdv-ravpn-2",
            edge,
            [
                ("subnet-0ed9e0m", "10.210.2.12", ""),
                ("subnet-0ed9e0o", "10.210.0.12", "203.0.113.12"),
                ("subnet-0ed9e0i", "10.210.1.12", ""),
            ],
            kind="c5.xlarge",
            forwards=True,
            zone="us-east-1a",
            group=sg_edge,
        ),
        _instance(
            "i-0f9a001",
            "pa-vm-edge-1",
            edge,
            [
                ("subnet-0ed9e0m", "10.210.2.13", ""),
                ("subnet-0ed9e0o", "10.210.0.13", "203.0.113.13"),
                ("subnet-0ed9e0i", "10.210.1.13", ""),
            ],
            kind="m5.xlarge",
            forwards=True,
            zone="us-east-1a",
            group=sg_edge,
        ),
        _instance(
            "i-0f3c001",
            "fmc-01",
            edge,
            [("subnet-0ed9e0m", "10.210.2.20", "")],
            kind="c5.4xlarge",
            forwards=False,
            zone="us-east-1a",
            group=sg_edge,
        ),
        # A database server on a public address that only partners' egress
        # addresses may reach (the Cato sample's allocated IPs).
        _instance(
            "i-0d8b001",
            "sql-public-1",
            edge,
            [("subnet-0ed9e0o", "10.210.0.40", "203.0.113.60")],
            kind="m6i.large",
            forwards=False,
            zone="us-east-1a",
            group=sg_sql,
        ),
        _instance(
            "i-0a99001",
            "app-server-1",
            core,
            [("subnet-0c0re0a", "10.200.10.21", "")],
            kind="m6i.large",
            forwards=False,
            zone="us-east-1a",
            group=sg_app,
        ),
        _instance(
            "i-0a99002",
            "db-server-1",
            core,
            [("subnet-0c0re0d", "10.200.20.31", "")],
            kind="r6i.xlarge",
            forwards=False,
            zone="us-east-1a",
            group=sg_db,
        ),
        _res(
            "customer_gateway:cgw-0d4c0001",
            "customer_gateway",
            "hq-datacenter-edge",
            _R1,
            customer_gateway_id="cgw-0d4c0001",
            ip_address="198.51.100.10",
            bgp_asn="65010",
            device_name="hq-edge-fw",
            type="ipsec.1",
        ),
        _res(
            "vpn_connection:vpn-0d4c0001",
            "vpn_connection",
            "hq-datacenter-vpn",
            _R1,
            vpn_connection_id="vpn-0d4c0001",
            customer_gateway_id="cgw-0d4c0001",
            transit_gateway_id=tgw,
            vpn_gateway_id="",
            type="ipsec.1",
            category="VPN",
            static_routes_only=False,
            static_routes=[],
            tunnel_inside_cidrs=["169.254.21.0/30", "169.254.22.0/30"],
            tunnels=[
                {
                    "outside_ip": "203.0.113.101",
                    "status": "UP",
                    "status_message": "4 BGP ROUTES",
                    "accepted_routes": 4,
                    "last_change": "2026-09-21T08:12:00+00:00",
                },
                {
                    "outside_ip": "203.0.113.102",
                    "status": "DOWN",
                    "status_message": "IPSEC IS DOWN",
                    "accepted_routes": 0,
                    "last_change": "2026-09-30T02:40:00+00:00",
                },
            ],
        ),
        _res("direct_connect:dxcon-0pr1mary", "direct_connect", "dx-primary", _R1, bandwidth="1Gbps"),
        _res(
            "direct-connect-gateway:dxgw-0c0rp",
            "direct_connect_gateway",
            "corp-dxgw",
            "global",
            amazon_asn="64513",
            owner_id="111122223333",
        ),
        _group(sg_edge, edge, [("tcp", "443", "0.0.0.0/0"), ("all", "all", "10.0.0.0/8")]),
        _group(sg_app, core, [("tcp", "443", "10.0.0.0/8"), ("tcp", "22", "10.210.2.0/24")]),
        # Only the application servers reach the database.
        _group(sg_db, core, [("tcp", "5432", f"sg:{sg_app[0]}")]),
        _group(sg_sql, edge, [("tcp", "1433", "192.0.2.101/32"), ("tcp", "1433", "192.0.2.102/32")]),
        _acl("acl-0c0re0001", "core-default", core, ["subnet-0c0re0a", "subnet-0c0re0b"]),
        _acl(
            "acl-0c0re0db1",
            "core-db",
            core,
            ["subnet-0c0re0d"],
            [
                _acl_entry(100, False, "allow", "tcp", "10.200.0.0/16", (5432, 5432)),
                _acl_entry(110, False, "allow", "tcp", "10.210.2.0/24", (22, 22)),
                # Replies to what the database servers open themselves.
                _acl_entry(120, False, "allow", "tcp", "0.0.0.0/0", (1024, 65535)),
                _acl_entry(100, True, "allow", "tcp", "10.0.0.0/8", (1024, 65535)),
                _acl_entry(110, True, "allow", "tcp", "0.0.0.0/0", (443, 443)),
            ],
        ),
        _acl("acl-0ed9e0001", "edge-default", edge, ["subnet-0ed9e0o", "subnet-0ed9e0i", "subnet-0ed9e0m"]),
        _acl("acl-0a9950001", "apps-default", apps, ["subnet-0a9950w"], region=_R2),
        _res(
            f"tgw_route_table:{tgw_table}",
            "transit_gateway_route_table",
            "global-main",
            _R1,
            transit_gateway_id=tgw,
            default_association=True,
            default_propagation=True,
            truncated=False,
            routes=[
                _tgw_route("10.200.0.0/16", "tgw-attach-0c0re", "vpc", core),
                _tgw_route("10.210.0.0/16", "tgw-attach-0ed9e", "vpc", edge),
                # The datacenter behind the VPN, learned over BGP.
                _tgw_route("10.10.0.0/16", "tgw-attach-0d4c0", "vpn", "vpn-0d4c0001"),
                _tgw_route("0.0.0.0/0", "tgw-attach-0ed9e", "vpc", edge, "static"),
                {"destination": "10.99.0.0/16", "state": "blackhole", "type": "static", "attachments": []},
            ],
        ),
        *_fsx(core, apps),
        *_services(core, edge, apps),
    ]
    connections = [
        _conn(
            f"vpc:{core}",
            f"tgw:{tgw}",
            "transit_gateway_attachment",
            attachment_id="tgw-attach-0c0re",
            resource_type="vpc",
            resource_id=core,
            route_table_id=tgw_table,
        ),
        _conn(
            f"vpc:{edge}",
            f"tgw:{tgw}",
            "transit_gateway_attachment",
            attachment_id="tgw-attach-0ed9e",
            resource_type="vpc",
            resource_id=edge,
            route_table_id=tgw_table,
        ),
        _conn(
            "vpn:vpn-0d4c0001",
            f"tgw:{tgw}",
            "transit_gateway_attachment",
            attachment_id="tgw-attach-0d4c0",
            resource_type="vpn",
            resource_id="vpn-0d4c0001",
            route_table_id=tgw_table,
        ),
        _conn(f"vpc:{core}", f"vpc:{apps}", "vpc_peering", "active", peering_id=peering),
        _conn(f"vpc:{edge}", "internet_gateway:igw-0ed9e", "internet_gateway_attachment"),
        _conn(f"vpc:{core}", "internet_gateway:igw-0c0re", "internet_gateway_attachment"),
        _conn(f"vpc:{core}", "nat_gateway:nat-0c0re0a", "nat_gateway_attachment"),
        _conn(f"vpc:{core}", "route_table:rtb-0c0re", "route_table_association", "attached", association_count=3),
        _conn(f"vpc:{edge}", "route_table:rtb-0ed9e0o", "route_table_association", "attached", association_count=1),
        _conn(f"vpc:{edge}", "route_table:rtb-0ed9e0i", "route_table_association", "attached", association_count=2),
        _conn("route_table:rtb-0c0re", "nat_gateway:nat-0c0re0a", "route_next_hop", "active", destination="0.0.0.0/0"),
        _conn("route_table:rtb-0c0re", f"tgw:{tgw}", "route_next_hop", "active", destination="10.0.0.0/8"),
        _conn(
            "route_table:rtb-0ed9e0o",
            "internet_gateway:igw-0ed9e",
            "route_next_hop",
            "active",
            destination="0.0.0.0/0",
        ),
        _conn("vpn_connection:vpn-0d4c0001", f"tgw:{tgw}", "vpn_tunnel"),
        _conn("vpn_connection:vpn-0d4c0001", "customer_gateway:cgw-0d4c0001", "customer_gateway_attachment"),
        _conn(
            "direct_connect:dxcon-0pr1mary",
            "direct-connect-gateway:dxgw-0c0rp",
            "direct_connect_virtual_interface",
            name="corp-transit-vif",
            type="transit",
            vlan=310,
        ),
        _conn(
            "direct-connect-gateway:dxgw-0c0rp",
            f"tgw:{tgw}",
            "direct_connect_gateway_association",
            "associated",
            region=_R1,
        ),
        _conn(f"vpc:{apps}", "route_table:rtb-0a995", "route_table_association", "attached", association_count=1),
        _conn(f"vpc:{edge}", f"sg:{sg_edge[0]}", "security_boundary", "enforced"),
        _conn(f"vpc:{core}", f"sg:{sg_app[0]}", "security_boundary", "enforced"),
        _conn(f"vpc:{core}", f"sg:{sg_db[0]}", "security_boundary", "enforced"),
        _conn(f"vpc:{edge}", f"sg:{sg_sql[0]}", "security_boundary", "enforced"),
    ]
    return resources, connections
