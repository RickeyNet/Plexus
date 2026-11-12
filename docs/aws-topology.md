# AWS in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the AWS accounts that
Cloud Visibility discovers. VPCs, their subnets, internet / NAT / virtual
private gateways, transit gateways, VPC peerings, site-to-site VPN
connections, Direct Connect and the instances that forward traffic appear on
the same map as the devices Plexus discovers itself and any Meraki
organizations, Cato accounts and Cisco FMCs. They are covered by the
same search box and Path Mode, and are included in the HTML export.

AWS accounts are not managed on the Topology page. An account is added,
validated and discovered under **Cloud Visibility**; every enabled AWS
account that has been discovered joins the map, and the map follows each new
discovery. Everything in [meraki-topology.md](meraki-topology.md) about the
map, search, Path Mode and the HTML export applies; this guide covers what is
different. Azure subscriptions and GCP projects join the map the same way;
see [azure-topology.md](azure-topology.md) and [gcp-topology.md](gcp-topology.md).

- Permission: the `topology` feature to view the map; admin to manage cloud
  accounts and run discovery
- API: `/api/cloud/*` for accounts and discovery, `/api/topology` and
  `/api/sources/*` for the map

## Quick start

1. **Preview without credentials.** On the Topology page click
   **Sources**, then **Load Sample** and **AWS**. A demo AWS account is added
   to Cloud Visibility and to the map. Delete it under **Cloud Visibility →
   Accounts** when you are done.
2. **Install the AWS SDK** on the Plexus server, once:
   `pip install -r requirements-cloud.txt` (it is optional and not part of
   the base install). Without it discovery reports that its dependencies are
   not installed.
3. **Add the account.** Open **Cloud Visibility → Accounts → Add AWS
   account** (or **Sources → Add Source → AWS Account** on the Topology
   page, which opens the same dialog) and fill in:
   - *Regions*: the regions to read, comma-separated
     (`us-east-1,us-west-2`). **Left empty, only `us-east-1` is read.**
     Tick **All regions** to read every region enabled for the account
     instead (saved as the region scope `all`). Plexus asks AWS for the list
     on every run, so a region enabled later is picked up; discovery takes
     longer, because each region is read in turn.
   - *How Plexus signs in*: an access key, an IAM role, or the credentials
     of the Plexus server (see below).
   Nothing else is needed for the map; the flow log and traffic metric
   settings are optional and only feed the **Flow Logs** and **Traffic
   Metrics** tabs.
4. **Discover** (it checks the sign-in first). When discovery finishes the
   account is on the Topology map (group filter **All groups**).
   A new account is discovered as soon as it is created (when it is
   enabled), and the page says whether scheduled discovery is on, with a
   button to turn it on (it is off by default).

To refresh the map, run **Discover** again. Scheduled discovery
(`PUT /api/cloud/discovery-sync/config` with `enabled` and
`interval_seconds`) refreshes every enabled account on a timer.

### Signing in

The form has a field for each common sign-in and saves them as one settings
object, stored encrypted and never shown again. `role_session_name` has no
field: enter it as JSON under **Additional settings**. Editing an account keeps what is stored unless you
click **Change sign-in and sync settings**, which replaces all of it.

| Settings | Sign-in |
|---|---|
| `access_key_id`, `secret_access_key` (optional `session_token`) | An IAM user's access key |
| `role_arn` (optional `external_id`, `role_session_name`) | Assume an IAM role. Combine with an access key, or leave the key out to assume the role from the server's own credentials |
| `profile_name` | A named profile from the AWS configuration of the Plexus server (**Credentials of the Plexus server → Profile name**) |
| none of these | The server's own credentials (instance profile, environment variables, `~/.aws/credentials`) |

### Temporary credentials and session tokens

Temporary credentials (an access key starting with `ASIA`, as copied from the
AWS access portal or returned by STS) come with a **session token**. Enter
all three under **Access key**; the token goes in **Session token**. They
expire, usually after 1 to 12 hours, and Plexus cannot renew a token it was
given: discovery then fails with *The AWS session token has expired*, and the
account needs a fresh set (**Edit → Change sign-in and sync settings**).

When Plexus runs on your own machine, it is easier to leave the credentials
on the machine: choose **Credentials of the Plexus server**, and refresh them
the way you normally do (`aws sso login`, or new values in
`~/.aws/credentials` or the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` environment variables of the Plexus process). Every
discovery reads them again, so nothing has to be re-entered in Plexus. Put an
SSO profile's name in **Profile name**; when its sign-in has expired,
discovery says so.

For unattended discovery, prefer a role Plexus assumes itself (**IAM role**):
it gets a fresh token from STS at every discovery, so nothing expires.

One Plexus account entry reads one AWS account. To cover several AWS
accounts, add one entry per account (typically one role per account); they
are joined on the map automatically, because AWS resource IDs are unique
across accounts.

### Permissions

Discovery is read-only: it calls `Describe*`, `List*` and `Get*`
operations and one search (`ec2:SearchTransitGatewayRoutes`). Only the base
EC2 and Direct Connect reads are required. Everything else is optional:
Plexus collects whatever the account's policy allows, and a call AWS
refuses skips only the piece that needs it.

| Service | IAM action | Required | Without it |
|---|---|---|---|
| EC2 / VPC | `ec2:DescribeVpcs`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeSecurityGroups`, `ec2:DescribeTransitGateways`, `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeVpnGateways`, `ec2:DescribeRouteTables`, `ec2:DescribeVpnConnections` | Required | Discovery fails and the previous snapshot is kept |
| Direct Connect | `directconnect:DescribeConnections` | Required | Discovery fails and the previous snapshot is kept |
| EC2 | `ec2:DescribeRegions` | Required | Needed only with **All regions**: discovery fails without it |
| EC2 | `ec2:DescribeSubnets` | Optional | No subnets: Path Mode and the subnet search know only the VPC ranges |
| EC2 | `ec2:DescribeInstances` | Optional | No instances: no forwarding appliances on the map, no instance search |
| EC2 | `ec2:DescribeCustomerGateways` | Optional | VPN far ends are unnamed peers |
| Direct Connect | `directconnect:DescribeVirtualInterfaces`, `directconnect:DescribeDirectConnectGateways`, `directconnect:DescribeDirectConnectGatewayAssociations` | Optional | Direct Connect stops at the connection |
| EC2 | `ec2:DescribeNetworkAcls` | Optional | The AWS check of a path reports the ACLs as not collected |
| EC2 | `ec2:DescribeTransitGatewayRouteTables`, `ec2:SearchTransitGatewayRoutes` | Optional | The AWS check of a path reports the transit gateway routes as not collected |
| EC2 | `ec2:DescribeNetworkInterfaces` | Optional | FSx (Lustre, Windows), load balancers and VPC endpoints are listed without their private addresses |
| EC2 | `ec2:DescribeVpcEndpoints` | Optional | No VPC endpoints |
| FSx | `fsx:DescribeFileSystems` | Optional | No FSx file systems |
| FSx | `fsx:DescribeStorageVirtualMachines` | Optional | No ONTAP storage virtual machines |
| RDS (also Aurora, Neptune, DocumentDB) | `rds:DescribeDBInstances` | Optional | No DB instances; clusters then need `rds:DescribeDBSubnetGroups` for their VPC |
| RDS | `rds:DescribeDBClusters` | Optional | No cluster writer, reader and custom endpoints |
| RDS | `rds:DescribeDBSubnetGroups` | Optional | Called only for a cluster none of whose instances was read; without it that cluster is not placed in a VPC |
| RDS | `rds:DescribeDBProxies` | Optional | No RDS proxies |
| Elastic Load Balancing | `elasticloadbalancing:DescribeLoadBalancers` | Optional | No Application, Network, Gateway or Classic Load Balancers |
| EFS | `elasticfilesystem:DescribeFileSystems` | Optional | No EFS file systems |
| EFS | `elasticfilesystem:DescribeMountTargets` | Optional | EFS file systems without mount targets: no addresses, and not placed in a VPC |
| ElastiCache | `elasticache:DescribeCacheClusters` | Optional | No cache nodes or engine versions; replication groups are not placed in a VPC |
| ElastiCache | `elasticache:DescribeReplicationGroups` | Optional | No replication group primary, reader or configuration endpoints |
| ElastiCache | `elasticache:DescribeCacheSubnetGroups` | Optional | Clusters are not placed in a VPC |
| ElastiCache | `elasticache:DescribeServerlessCaches` | Optional | No serverless caches |
| OpenSearch Service | `es:ListDomainNames`, `es:DescribeDomains` | Optional | No OpenSearch domains |
| MSK | `kafka:ListClustersV2` | Optional | No MSK clusters |
| MSK | `kafka:GetBootstrapBrokers` | Optional | No bootstrap broker endpoints |
| MSK | `kafka:ListNodes` | Optional | No broker addresses |
| Redshift | `redshift:DescribeClusters` | Optional | No provisioned Redshift clusters |
| Redshift Serverless | `redshift-serverless:ListWorkgroups` | Optional | No Redshift Serverless workgroups |

The AWS managed read-only policies that cover them:
**AmazonEC2ReadOnlyAccess** (EC2, VPC endpoints, network interfaces and
Elastic Load Balancing), **AWSDirectConnectReadOnlyAccess**,
**AmazonFSxReadOnlyAccess**, **AmazonRDSReadOnlyAccess**,
**ElasticLoadBalancingReadOnly** (load balancers alone),
**AmazonElasticFileSystemReadOnlyAccess**,
**AmazonElastiCacheReadOnlyAccess**,
**AmazonOpenSearchServiceReadOnlyAccess**, **AmazonMSKReadOnlyAccess** and
**AmazonRedshiftReadOnlyAccess** (Redshift and Redshift Serverless). Check
the version of a managed policy in your account if a call is still refused:
AWS adds actions to them over time. `ec2:SearchTransitGatewayRoutes` is not
a `Describe*` action; check that the policy in use grants it.

A minimal custom policy with exactly the actions discovery calls (drop the
optional ones you do not want collected):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PlexusTopologyReadOnly",
      "Effect": "Allow",
      "Action": [
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
        "ec2:DescribeRegions",
        "directconnect:DescribeConnections",
        "ec2:DescribeSubnets",
        "ec2:DescribeInstances",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeVpcEndpoints",
        "directconnect:DescribeVirtualInterfaces",
        "directconnect:DescribeDirectConnectGateways",
        "directconnect:DescribeDirectConnectGatewayAssociations",
        "fsx:DescribeFileSystems",
        "fsx:DescribeStorageVirtualMachines",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeDBProxies",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeServerlessCaches",
        "es:ListDomainNames",
        "es:DescribeDomains",
        "kafka:ListClustersV2",
        "kafka:GetBootstrapBrokers",
        "kafka:ListNodes",
        "redshift:DescribeClusters",
        "redshift-serverless:ListWorkgroups"
      ],
      "Resource": "*"
    }
  ]
}
```

An IAM role that Plexus assumes also needs `sts:AssumeRole` on it for the
caller, and the role's trust policy must allow the caller (with the external
ID when one is set).

#### What Plexus reports when a call is refused

An optional call that fails never fails discovery. Discovery still
succeeds, the map is built without that piece, and:

- the result of **Discover** (Cloud Visibility) and **Collect Now**
  (Sources dialog), the account row and the Sources dialog say which
  sections were skipped and the IAM actions to add, for example
  *Live provider discovery snapshot refreshed. Collected with 3 sections
  skipped for missing permissions: kafka:ListClustersV2,
  rds:DescribeDBInstances, redshift:DescribeClusters.*
- the map's report (**Report** in the HTML export) has one entry per
  problem, listing the regions instead of repeating it per region, e.g.
  *RDS and Aurora DB instances in eu-west-1, us-east-1: not collected, AWS
  denied the call (AccessDenied). Add rds:DescribeDBInstances to the IAM
  policy of the account; the rest of the discovery is complete.*
- each skipped section is a `collection_warning` row among the account's
  resources, with the AWS error code (never AWS's message, which can quote
  the request), why it failed (`permission`, `unavailable` or `error`) and
  the IAM actions it needs.

A service that does not exist or is not enabled in a region (an opt-in
region, a service not launched there) or that the AWS SDK on the server is
too old to know is reported as *not available there*, once, in the map's
report only; it is not a permission problem and the discovery message
leaves it out. Throttling, timeouts and AWS-side errors are reported as
failed: run discovery again.

The base sections (VPCs, internet and NAT gateways, security groups,
transit gateways and their attachments, VPC peerings, VPN gateways, route
tables, VPN connections, Direct Connect connections) are not optional: when
one fails, the discovery fails with what was refused, and the last complete
snapshot stays on the map rather than being replaced by a partial one.

AWS returns the pre-shared keys of a site-to-site VPN inside
`DescribeVpnConnections`. Plexus does not read or store them: only the
tunnel addresses, status, routes and inside CIDRs are kept. Likewise the
Active Directory service account of an FSx file system or storage virtual
machine, the ONTAP `fsxadmin` password and the KMS key are never read, nor
the master user name or password, auth tokens, Secrets Manager ARNs, KMS
keys and access policies of an RDS, ElastiCache, OpenSearch, MSK or
Redshift resource, nor the policy document of a VPC endpoint. Only named
fields are copied.

## On the map

| On the map | What it is |
|---|---|
| Site box | One VPC, named `name (region)`; the account name is added when several accounts are on the map |
| VPC (diamond) | The VPC's own router. It owns the VPC's subnets: a path to or from a subnet starts here |
| Internet gateway (triangle) | The VPC's internet gateway, drawn like a WAN uplink |
| NAT / VGW (hexagon) | NAT gateways and the virtual private gateway of the VPC |
| Instance (firewall icon) | An instance that forwards traffic: source/destination check is off, as on firewalls, routers, SD-WAN and VPN appliances |
| **AWS transit and VPN** box | Transit gateways, Direct Connect connections and gateways, and customer gateways |
| Orange link | An attachment: VPC to transit gateway, VPC peering, NAT, Direct Connect |
| Dashed tunnel | A site-to-site VPN connection, from its transit or virtual private gateway to the customer gateway |

Not every instance is a node: a VPC with hundreds of servers would bury the
map. An instance is drawn when it forwards traffic or when it is a Plexus
inventory host. Every other instance is listed in its VPC's details (name,
ID, private and public IP, type, state, subnet) and found by the search box,
and its private address is in the subnet picker of Path Mode: typing the
address picks the VPC, even when another site declares the same range.
Amazon FSx file systems (Windows File Server, Lustre, NetApp ONTAP and
OpenZFS) and the storage virtual machines (SVMs) of an ONTAP file system are
not nodes either: their VPC lists them, with every endpoint AWS reports
(the file server, remote administration and DNS aliases of a Windows file
system, the management and intercluster endpoints of ONTAP, the NFS, SMB,
iSCSI and management endpoints of each SVM, the mount endpoint of Lustre and
OpenZFS) and the addresses of the file system's network interfaces. Each
address is in the subnet picker of Path Mode like an instance's.
The same goes for the services whose endpoints have DNS names: RDS and
Aurora DB instances, clusters and proxies (Neptune and DocumentDB too,
named by their engine), Application, Network, Gateway and Classic Load
Balancers, VPC endpoints, EFS file systems, ElastiCache replication groups,
clusters and serverless caches, OpenSearch domains, MSK clusters, Redshift
clusters and Redshift Serverless workgroups. Each service has a table in
its VPC's details (name, ID or ARN, kind, engine, version, state, endpoints
as `host:port`, addresses, subnets, security groups) and every endpoint is
a row of the **Service endpoints** table with its DNS name, port and
address; each private address is in the subnet picker like an instance's.
A public address (an NLB's Elastic IP, a Redshift node's public IP) is
listed in the service's table but is not made a host of the VPC. A
resource that names only its subnets (MSK, Redshift Serverless,
ElastiCache serverless) is placed in the VPC of those subnets. One whose
VPC was not collected, or that has none (a public OpenSearch domain), is
left off the map; Cloud Visibility still lists it among the account's
resources. They are not nodes and take no part in path tracing.
An instance that becomes an inventory host later - a host added to the
inventory, or given its instance ID, after the last discovery - is drawn as
soon as the map is next loaded; no new discovery is needed.

To see AWS alone, pick **AWS only** in the source selector of the Topology
toolbar. The map then keeps the VPCs, the transit and VPN box and the links
between them, and hides inventory, Meraki, Cato and Cisco FMC devices with
the tunnels that join them to AWS (a customer gateway that is a Meraki or
Cato appliance goes with its own integration).

A VPN connection is drawn as up when at least one of its tunnels is up, and
down (red, not used by Path Mode) when all are down. A failed or deleted
attachment is drawn down in the same way. An attachment to a VPC or transit
gateway that belongs to an account or region Plexus does not collect is kept
as a node marked *Not collected*: a VPC is drawn as a VPC in a box of its
own, named `vpc-… (us-east-2, not collected)`, so a peering looks the same
whichever account the far end is in; a transit or Direct Connect gateway
joins the **AWS transit and VPN** box. These nodes are not counted as
devices.

A VPC peering records both of its VPCs, so a peered VPC that is not
collected still shows its CIDR ranges, region and account number, why it
is not collected (its account is not in Cloud Visibility, its region is not
among the account's regions, or it has not been discovered yet), its
peerings and, on the **Routing** tab, the routes of the collected VPCs that
lead to it. Its subnets, route tables and instances can only be read from its
own account: add that account to Cloud Visibility to collect them. Every VPC
lists its peerings on the **Routing** tab.

### How AWS joins the rest of the map

- **Inventory hosts.** An instance whose private or public IP is the address
  (or an IP alias) of a Plexus inventory host becomes that host's node, so a
  firewall Plexus already manages is shown once, inside its VPC, with both
  its SNMP/SSH data and its AWS data. When the host's inventory address is
  not one AWS records (a NAT or load-balancer address, say), set its
  **AWS instance ID** (`i-…`, in the host's edit dialog or as
  `aws_instance_id` on `POST /api/inventory/{group}/hosts` and
  `PUT /api/hosts/{id}`): the instance ID is checked before any address, in
  any letter case, and a host that names one instance is never matched to
  another by address. The host's node shows which instance it is (ID,
  subnet, VPC) even when it is drawn as a Meraki or Cato device.
- **Customer gateways.** A customer gateway is the public IP of the far end
  of a VPN. When a device on the map answers on that address - a Meraki
  appliance or Cato Socket through its WAN link, or an inventory host - the
  tunnel is drawn to that device and there is no separate gateway node.
- **Virtual appliances.** An instance whose public IP is the WAN address of a
  Meraki appliance or Cato Socket is that device (a vMX or vSocket): it stays
  in its Meraki or Cato site and gains a link to its VPC. With the source
  selector on **AWS only** it is still shown, and a vSocket keeps its tunnel
  to the Cato PoP it connects to. A Cato Socket is known by the public
  addresses of its WAN links: if the Cato site query falls back to the basic
  site list (see the collection warnings), vSockets are not matched.
- **Virtual appliances behind a NAT gateway.** A vMX in a private subnet has
  no public IP of its own: Meraki knows it by the NAT gateway's address. It
  is then matched by the private IP of its WAN uplink, under conditions that
  keep a branch appliance that happens to use the same address out:
  the instance forwards traffic (source/destination check off), exactly one
  such instance and exactly one uplink have the address, and either the
  Meraki model is a vMX or the public IP Meraki reports is a NAT gateway of
  the instance's VPC. An appliance that meets none of this stays two nodes:
  the Meraki device in its site and the instance in its VPC.
- **Cisco FMC devices.** An FTDv that an FMC manages is matched the same
  way, by the private address of an outside interface (a remote access VPN
  access interface, or the egress of its default route), when its FMC model
  is a virtual one; the secondary of an HA pair is matched by its standby
  address. See [fmc-topology.md](fmc-topology.md). An FTD that is a Plexus
  inventory host collapses into that host together with its instance.
- **The same VPN seen from the other side.** A Meraki non-Meraki VPN peer,
  a Cato IPsec site or an FMC extranet VPN peer configured with an AWS
  tunnel address is joined to the AWS gateway that owns the address, and a
  customer gateway whose public address is an FTD's outside or VPN endpoint
  address is that FTD.

Apart from that one case only public addresses are used; private addresses
repeat from site to site and identify nothing on their own.

### Device details

Click a VPC for its tabs:

- **Device**: the VPC overview, the list of instances, the FSx file
  systems, storage virtual machines and endpoints (DNS name and address),
  a table per service (RDS and Aurora databases, Load balancers, VPC
  endpoints, EFS file systems, ElastiCache, OpenSearch domains, MSK
  clusters, Redshift) and the Service endpoints table
- **VLANs**: the subnets (CIDR, name, availability zone, route table, where
  the default route goes, free addresses, network ACL)
- **Routing**: every route of every route table of the VPC
- **Firewall**: the security group rules and the network ACL rules

A transit or virtual private gateway lists its attachments and VPN
connections (tunnel addresses, tunnel status, routing, static routes); a
transit gateway also lists the routes of its route tables under **Routing**.
An instance's **Overview** tab shows its instance ID, state, type, VPC,
availability zone, subnet, addresses and security groups, and its network
interfaces are listed below. An inventory host that is an instance shows
the instance ID and subnet on its Overview tab and tooltip too.

### Search and Path Mode

The toolbar search covers everything collected: VPC, subnet, instance,
FSx and service names, IDs and ARNs (`vpc-…`, `subnet-…`, `i-…`, `tgw-…`,
`fs-…`, `svm-…`, `vpce-…`), the DNS name of every FSx and service endpoint
(whole or in part), CIDRs, private and public IPs, route targets and
security group rules. An endpoint found by name or address selects its VPC.
A pasted URL, UNC path, NFS mount, JDBC URL or `host:port` endpoint searches
for its host: `https://files.example.com:443/share`,
`\\files.example.com\share` and `files.example.com:/fsx` all search for
`files.example.com`, and `jdbc:redshift://dw.example.com:5439/dev` and
`dw.example.com:5439` search for `dw.example.com`.

In **Path Mode** a VPC or one of its subnets can be picked like a Meraki
site; typing an IP address picks the subnet that contains it. A path between
two VPCs runs over their transit gateway or peering, and a path to a site
runs over the VPN or virtual appliance that joins it to AWS.

Between two subnets or addresses the path is traced hop by hop across every
device on the map, and the hops in AWS list the checks below as their items;
see [path-trace.md](path-trace.md).

### The AWS check of a path

When both ends of a path are subnets or IP addresses and at least one is in
a VPC, Plexus checks the flow against what discovery collected. In a path
trace these are the items of the VPC and transit gateway hops, with their
wording as below; `GET /api/sources/aws/reachability` still answers the AWS
part on its own. An end
picked as a device or site (a Meraki appliance clicked on the map, a VPC
picked as a site) has no address to check; the path then says which end to
add with the subnet box instead. An address in a range of a Cato vSocket or
Meraki vMX that runs in AWS is checked too, though the picker files it under
the Cato or Meraki site. Each step is allowed, blocked, allowed in part or
incomplete, with the reason, in both directions.

- **Direction and traffic.** The first of the two picks is the source. The
  **Traffic** box next to the subnet box takes `tcp/443`, `udp/53`, `443`
  (TCP), `icmp`, or nothing for any traffic. With nothing typed, rules that
  open only some ports give *allows part of it*.
- **Route tables.** The route table of the source subnet (its own, else the
  VPC's main one) is matched longest prefix first, and the reply is routed
  the same way from the other end. A missing route, a blackhole route, a
  route out of AWS for an address that is in a VPC, and a private address
  sent to an internet or NAT gateway are blocks.
- **VPC peerings.** The peering must be active and lead to the VPC that
  holds the address; a peering carries nothing beyond its two VPCs.
- **Transit gateways.** The route table associated with the attachment the
  traffic arrives on decides where it goes: to a VPC, out over a VPN (not
  when every tunnel is down) or Direct Connect, or on to a peered transit
  gateway that was also collected.
- **Network ACLs.** They are stateless, so the request and the reply are
  matched against the ACL of each subnet, rule by rule in number order, the
  reply on ports 1024-65535. Two ends in one subnet pass no ACL.
- **Security groups.** They belong to an instance. They are checked when an
  end is typed as the **IP address of a collected instance** (any instance,
  not only those drawn on the map): outbound at the source, inbound at the
  destination, including rules that name another security group. For a
  whole subnet they are not checked and the result says so.
- **An end outside AWS** (a branch subnet, an internet address) is followed
  to the gateway it leaves by, and back in through the same gateway. A NAT
  gateway accepts no connection from outside; an internet gateway only for
  an instance with a public address. In a path trace across the map, a flow
  to an instance's public address (its public or Elastic IP, as collected on
  its interfaces) enters through that internet gateway and is delivered to
  the private address behind it, and the subnet's ACL and the instance's
  security groups are matched against the address the flow left its own
  network with (a Cato allocated IP, or an unknown public address when
  Cato leaves from a PoP's shared one); see
  [path-trace.md](path-trace.md#ends-clouds-and-the-internet). Documentation
  ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) count as public
  addresses, as in the samples.
- **Through a Meraki vMX.** When the route table hands the traffic to an
  instance that is a Meraki appliance on the map, the check goes on with the
  latest Meraki collection instead of stopping: the far address must be a
  subnet of a Meraki site that advertises it into the VPN, an AutoVPN tunnel
  that is up must join the vMX to that site (through a hub if need be; a
  subnet behind a non-Meraki peer needs the vMX's own tunnel to that peer),
  and the vMX must advertise the AWS address (its **VPN local subnets**) so
  the site has a route back. The reply is then followed from the vMX's
  subnet to the AWS end. Firewall rules on the Meraki appliances are not
  matched by this check. A path trace instead makes the vMX a hop of its
  own, with its firewall rules and routes.

The check never reports as allowed what it could not look at. *Check
incomplete* means one of:

- the discovery predates this check, or the account may not read network
  ACLs or transit gateway route tables: run **Discover** again
- the route hands the traffic to a firewall or router instance that is not
  a Meraki appliance on the map, or to a gateway load balancer endpoint.
  What that appliance does with it is its own configuration, which AWS does
  not describe
- behind a vMX: the far address is in no subnet Meraki collected, or the
  vMX does not list the AWS address among its VPN local subnets (other
  sites then reach it only if they send all their traffic to the vMX)
- the transit gateway hands the traffic to a VPC that does not hold the
  address (an inspection or egress VPC); it is not followed further
- a route or rule refers to a prefix list, whose entries are not collected

Limits: only IPv4 can be typed in Path Mode. ICMP types are not told apart.
The ACLs of subnets the traffic only passes through (transit gateway
attachment and NAT gateway subnets) are not matched. The HTML export runs
the check itself when it carries the path tracer (`docs/path-trace.md`,
*Tracing inside the HTML export*); without it, it does not include the
check.

## What is collected

| Data | AWS API call |
|---|---|
| VPCs, internet / NAT / virtual private gateways, security groups | `DescribeVpcs`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeVpnGateways`, `DescribeSecurityGroups` |
| Transit gateways and their attachments, VPC peerings | `DescribeTransitGateways`, `DescribeTransitGatewayAttachments`, `DescribeVpcPeeringConnections` |
| Route tables with their routes | `DescribeRouteTables` |
| Site-to-site VPN connections and tunnel status | `DescribeVpnConnections` |
| Subnets | `DescribeSubnets` |
| Network ACLs | `DescribeNetworkAcls` |
| Transit gateway route tables with their active and blackhole routes (up to 1000 per table) and the table each attachment is associated with | `DescribeTransitGatewayRouteTables`, `SearchTransitGatewayRoutes`, `DescribeTransitGatewayAttachments` |
| Instances and their network interfaces | `DescribeInstances` |
| Customer gateways | `DescribeCustomerGateways` |
| Amazon FSx file systems and ONTAP storage virtual machines with their endpoints, and the addresses of the file systems' network interfaces | `fsx:DescribeFileSystems`, `fsx:DescribeStorageVirtualMachines`, `ec2:DescribeNetworkInterfaces` |
| RDS / Aurora DB instances (endpoint and port, subnet group, engine and version, Multi-AZ, public access, cluster), clusters (writer, reader and custom endpoints) and proxies | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBSubnetGroups` (only for a cluster with no instance read), `rds:DescribeDBProxies` |
| Application, Network, Gateway and Classic Load Balancers (DNS name, scheme, subnets, security groups, NLB addresses), with the private addresses of their network interfaces (found by their description, `ELB app/…`, `ELB net/…`, `ELB <name>`) | `elasticloadbalancing:DescribeLoadBalancers`, `ec2:DescribeNetworkInterfaces` |
| VPC endpoints (DNS entries, service, subnets, security groups) and the addresses of their network interfaces; gateway endpoints are listed without | `ec2:DescribeVpcEndpoints`, `ec2:DescribeNetworkInterfaces` |
| EFS file systems and their mount targets (address, subnet, zone). AWS returns no DNS name: `<fs-id>.efs.<region>.amazonaws.com` and `<zone>.<fs-id>.efs.<region>.amazonaws.com` are built (`amazonaws.com.cn` in the China regions) | `elasticfilesystem:DescribeFileSystems`, `elasticfilesystem:DescribeMountTargets` (one call per file system that has mount targets) |
| ElastiCache replication groups (configuration, primary and reader endpoints), cache clusters and their nodes, subnet groups (for the VPC), serverless caches | `elasticache:DescribeReplicationGroups`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheSubnetGroups`, `elasticache:DescribeServerlessCaches` |
| OpenSearch Service domains (public, VPC, dual-stack and custom endpoints, VPC options, engine version; of fine-grained access control only whether it is on) | `es:ListDomainNames`, `es:DescribeDomains` (five domains a call) |
| MSK clusters (client subnets, security groups, Kafka version), their bootstrap brokers and their broker endpoints and addresses | `kafka:ListClustersV2`, `kafka:GetBootstrapBrokers` and `kafka:ListNodes` (one call each per active cluster) |
| Redshift clusters (endpoint, managed VPC endpoints, node addresses, version) and Redshift Serverless workgroups (endpoint, VPC endpoint addresses) | `redshift:DescribeClusters`, `redshift-serverless:ListWorkgroups` |
| Direct Connect connections, virtual interfaces, gateways | `DescribeConnections`, `DescribeVirtualInterfaces`, `DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations` |

Not collected: prefix lists, load balancer listeners and target groups,
Client VPN endpoints, the addresses behind an RDS, ElastiCache or
OpenSearch DNS name (AWS reports none; the DNS name is searchable), FSx
volumes, the availability of FSx file systems and of the services above
(their state is shown, not tracked), their software versions in the
software tracker (the version is shown in the service's table), and the on-premises router behind a
Direct Connect (a Direct Connect is the edge of the map). The subnets also
appear in IPAM's cloud CIDR view, where each VPC's range is checked against
the ranges of every Meraki, Cato and Cisco FMC site under **Overlapping
Ranges** (see the [Meraki guide](meraki-topology.md#ipam)).

## Availability tracking

Each collection also records the state of what it reports, shown under **Monitoring > Availability > Integrations and cloud** with uptime, outages and alerts: the instances drawn on the map, the transit, VPN, NAT and Direct Connect gateways and the Direct Connect connections (devices), site-to-site VPN connections (up when a tunnel is UP), Direct Connect connections, virtual interfaces and gateway associations (circuits), VPC peerings, and transit gateway and VPN gateway attachments (links). VPCs and customer gateways are left out. The state mapping, alerting and retention are described in [Meraki in the Topology Map](meraki-topology.md#availability-tracking).

## API reference

| Method | Path | Notes for AWS |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "aws", "name", "region_scope", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `GET` | `/api/cloud/accounts/{id}/discover/progress` | How far a running discovery is: `running` and `progress` (`phase`; for each region `region`, `section`, `regions_done`, `regions_total`, `steps_done`, `steps_total`; Azure and GCP report `section`, `steps_done`, `steps_total` per section). A scheduled discovery reports here too, and `GET /api/topology/sources` carries the same fields as the source's `progress` (admin) |
| `POST` | `/api/sources/sample?provider=aws` | Add / refresh the demo AWS account |
| `GET` | `/api/topology` | AWS nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `aws` and whose `org_ref` is `-1` (all AWS accounts share one reference) |
| `GET` | `/api/sources/nodes?org_ref=-1&node_id=…` | Detail sections of one AWS node |
| `GET` | `/api/sources/subnets` | Includes the subnets of every VPC (`provider: "aws"`, `site_id` is the VPC ID) |
| `GET` | `/api/sources/aws/reachability?source=&destination=` | The AWS check of a flow. `source` / `destination` are IP addresses or networks; optional `protocol` (`tcp`, `udp`, `icmp`), `port`, and `source_vpc` / `destination_vpc` for a range that exists in several VPCs. Returns `applies`, `verdict` (`allowed`, `blocked`, `partial`, `unknown`), `summary` and `steps` |

## The Sources dialog

Every AWS account is a row of the **Sources** dialog on the Topology page,
next to neighbor discovery, Meraki organizations and Cato accounts, with its
last discovery. **Collect Now** runs the same discovery as **Cloud Visibility
→ Accounts → Discover** (administrators only) and **Manage** opens Cloud
Visibility, where accounts are added, edited and deleted.
