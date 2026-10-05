# AWS in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the AWS accounts that
Cloud Visibility discovers. VPCs, their subnets, internet / NAT / virtual
private gateways, transit gateways, VPC peerings, site-to-site VPN
connections, Direct Connect and the instances that forward traffic appear on
the same map as the devices Plexus discovers itself and any Meraki
organizations, Cato accounts and AnyConnect FMCs. They are covered by the
same search box and Path Mode, and are included in the HTML export.

AWS accounts are not managed on the Topology page. An account is added,
validated and discovered under **Cloud Visibility**; every enabled AWS
account that has been discovered joins the map, and the map follows each new
discovery. Everything in [meraki-topology.md](meraki-topology.md) about the
map, search, Path Mode and the HTML export applies; this guide covers what is
different.

- Permission: the `topology` feature to view the map; admin to manage cloud
  accounts and run discovery
- API: `/api/cloud/*` for accounts and discovery, `/api/topology` and
  `/api/meraki/*` for the map

## Quick start

1. **Preview without credentials.** On the Topology page click
   **Sources**, then **Load Sample** and **AWS**. A demo AWS account is added
   to Cloud Visibility and to the map. Delete it under **Cloud Visibility →
   Accounts** when you are done.
2. **Install the AWS SDK** on the Plexus server, once:
   `pip install -r requirements-cloud.txt` (it is optional and not part of
   the base install). Without it discovery reports that its dependencies are
   not installed.
3. **Add the account.** Open **Cloud Visibility → Accounts → Add Cloud
   Account**, choose AWS, and fill in:
   - *Regions*: the regions to read, comma-separated
     (`us-east-1,us-west-2`). **Left empty, only `us-east-1` is read.**
     Tick **All regions** to read every region enabled for the account
     instead (saved as the region scope `all`). Plexus asks AWS for the list
     on every run, so a region enabled later is picked up; discovery takes
     longer, because each region is read in turn.
   - *How Plexus signs in*: an access key, an IAM role, or the credentials
     of the Plexus server (see below).
   Nothing else is needed for the map; the flow log and traffic metric
   settings are optional and only feed **Pull Flow** and **Pull Traffic**.
4. **Validate**, then **Discover**. When discovery finishes the account is on
   the Topology map (group filter **All groups**).

To refresh the map, run **Discover** again. Scheduled discovery
(`PUT /api/cloud/discovery-sync/config` with `enabled` and
`interval_seconds`) refreshes every enabled account on a timer.

### Signing in

The form has a field for each common sign-in and saves them as one settings
object, stored encrypted and never shown again. `session_token`,
`role_session_name` and `profile_name` have no field: enter them as JSON under
**Additional settings**. Editing an account keeps what is stored unless you
click **Change sign-in and sync settings**, which replaces all of it.

| Settings | Sign-in |
|---|---|
| `access_key_id`, `secret_access_key` (optional `session_token`) | An IAM user's access key |
| `role_arn` (optional `external_id`, `role_session_name`) | Assume an IAM role. Combine with an access key, or leave the key out to assume the role from the server's own credentials |
| `profile_name` | A named profile from the AWS configuration of the Plexus server |
| none of these | The server's own credentials (instance profile, environment) |

One Plexus account entry reads one AWS account. To cover several AWS
accounts, add one entry per account (typically one role per account); they
are joined on the map automatically, because AWS resource IDs are unique
across accounts.

### Permissions

Discovery is read-only: it calls `Describe*` operations and one search
(`ec2:SearchTransitGatewayRoutes`). The AWS-managed policies
**AmazonEC2ReadOnlyAccess** and **AWSDirectConnectReadOnlyAccess** cover the
`Describe*` calls. For a custom policy:

| Needed | Actions |
|---|---|
| Always (discovery fails without them) | `ec2:DescribeVpcs`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeSecurityGroups`, `ec2:DescribeTransitGateways`, `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeVpnGateways`, `ec2:DescribeRouteTables`, `ec2:DescribeVpnConnections`, `directconnect:DescribeConnections` |
| With **All regions** (discovery fails without it) | `ec2:DescribeRegions` |
| For the map (skipped when denied) | `ec2:DescribeSubnets`, `ec2:DescribeInstances`, `ec2:DescribeCustomerGateways`, `directconnect:DescribeVirtualInterfaces`, `directconnect:DescribeDirectConnectGateways`, `directconnect:DescribeDirectConnectGatewayAssociations` |
| For the Path Mode check (skipped when denied) | `ec2:DescribeNetworkAcls`, `ec2:DescribeTransitGatewayRouteTables`, `ec2:SearchTransitGatewayRoutes` |

`ec2:SearchTransitGatewayRoutes` is not a `Describe*` action. Check that the
policy in use grants it; without it the transit gateway part of a path check
reports *not collected*.

A map section that AWS denies is skipped, not fatal: discovery still
succeeds, the map is built without that detail, and the skipped section is
listed with the AWS error code under **Report** in the HTML map and as a
`collection_warning` row among the account's resources.

AWS returns the pre-shared keys of a site-to-site VPN inside
`DescribeVpnConnections`. Plexus does not read or store them: only the
tunnel addresses, status, routes and inside CIDRs are kept.

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
ID, private and public IP, type, state, subnet) and found by the search box.

A VPN connection is drawn as up when at least one of its tunnels is up, and
down (red, not used by Path Mode) when all are down. A failed or deleted
attachment is drawn down in the same way. An attachment to a VPC or transit
gateway that belongs to an account or region Plexus does not collect is kept
as a node marked *Not collected*.

### How AWS joins the rest of the map

- **Inventory hosts.** An instance whose private or public IP is the address
  (or an IP alias) of a Plexus inventory host becomes that host's node, so a
  firewall Plexus already manages is shown once, inside its VPC, with both
  its SNMP/SSH data and its AWS data.
- **Customer gateways.** A customer gateway is the public IP of the far end
  of a VPN. When a device on the map answers on that address - a Meraki
  appliance or Cato Socket through its WAN link, or an inventory host - the
  tunnel is drawn to that device and there is no separate gateway node.
- **Virtual appliances.** An instance whose public IP is the WAN address of a
  Meraki appliance or Cato Socket is that device (a vMX or vSocket): it stays
  in its Meraki or Cato site and gains a link to its VPC.
- **Virtual appliances behind a NAT gateway.** A vMX in a private subnet has
  no public IP of its own: Meraki knows it by the NAT gateway's address. It
  is then matched by the private IP of its WAN uplink, under conditions that
  keep a branch appliance that happens to use the same address out:
  the instance forwards traffic (source/destination check off), exactly one
  such instance and exactly one uplink have the address, and either the
  Meraki model is a vMX or the public IP Meraki reports is a NAT gateway of
  the instance's VPC. An appliance that meets none of this stays two nodes:
  the Meraki device in its site and the instance in its VPC.
- **AnyConnect headends.** An FTDv that an FMC manages is matched the same
  way, by the private address of its VPN access interface, when its FMC
  model is a virtual one; see
  [anyconnect-topology.md](anyconnect-topology.md). A headend that is a
  Plexus inventory host collapses into that host together with its instance.
- **The same VPN seen from the other side.** A Meraki non-Meraki VPN peer or
  a Cato IPsec site configured with an AWS tunnel address is joined to the
  AWS gateway that owns the address.

Apart from that one case only public addresses are used; private addresses
repeat from site to site and identify nothing on their own.

### Device details

Click a VPC for its tabs:

- **Device**: the VPC overview and the list of instances
- **VLANs**: the subnets (CIDR, name, availability zone, route table, where
  the default route goes, free addresses, network ACL)
- **Routing**: every route of every route table of the VPC
- **Firewall**: the security group rules and the network ACL rules

A transit or virtual private gateway lists its attachments and VPN
connections (tunnel addresses, tunnel status, routing, static routes); a
transit gateway also lists the routes of its route tables under **Routing**.
A forwarding instance lists its network interfaces.

### Search and Path Mode

The toolbar search covers everything collected: VPC, subnet and instance
names, IDs (`vpc-…`, `subnet-…`, `i-…`, `tgw-…`), CIDRs, private and public
IPs, route targets and security group rules.

In **Path Mode** a VPC or one of its subnets can be picked like a Meraki
site; typing an IP address picks the subnet that contains it. A path between
two VPCs runs over their transit gateway or peering, and a path to a site
runs over the VPN or virtual appliance that joins it to AWS.

The path drawn on the map follows links, not route tables: it shows how two
places *can* be joined. Whether AWS actually carries and permits the traffic
is checked separately, below the path.

### The AWS check of a path

When both ends of a path are subnets or IP addresses and at least one is in
a VPC, Plexus checks the flow against what discovery collected and reports
**AWS allows it**, **AWS blocks it**, **AWS allows part of it** or **AWS
check incomplete**, with the reason. Open the line for every step, in both
directions.

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
  an instance with a public address.
- **Through a Meraki vMX.** When the route table hands the traffic to an
  instance that is a Meraki appliance on the map, the check goes on with the
  latest Meraki collection instead of stopping: the far address must be a
  subnet of a Meraki site that advertises it into the VPN, an AutoVPN tunnel
  that is up must join the vMX to that site (through a hub if need be; a
  subnet behind a non-Meraki peer needs the vMX's own tunnel to that peer),
  and the vMX must advertise the AWS address (its **VPN local subnets**) so
  the site has a route back. The reply is then followed from the vMX's
  subnet to the AWS end. Firewall rules on the Meraki appliances are not
  matched.

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
attachment and NAT gateway subnets) are not matched. The HTML export does
not include the check.

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
| Direct Connect connections, virtual interfaces, gateways | `DescribeConnections`, `DescribeVirtualInterfaces`, `DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations` |

Not collected: prefix lists, load balancers,
VPC endpoints, Client VPN endpoints, and the on-premises router behind a
Direct Connect (a Direct Connect is the edge of the map). The subnets also
appear in IPAM's cloud CIDR view, where each VPC's range is checked against
the ranges of every Meraki, Cato and AnyConnect site under **Overlapping
Ranges** (see the [Meraki guide](meraki-topology.md#ipam)).

## API reference

| Method | Path | Notes for AWS |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "aws", "name", "region_scope", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `POST` | `/api/meraki/sample?provider=aws` | Add / refresh the demo AWS account |
| `GET` | `/api/topology` | AWS nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `aws` and whose `org_ref` is `-1` (all AWS accounts share one reference) |
| `GET` | `/api/meraki/nodes?org_ref=-1&node_id=…` | Detail sections of one AWS node |
| `GET` | `/api/meraki/subnets` | Includes the subnets of every VPC (`provider: "aws"`, `site_id` is the VPC ID) |
| `GET` | `/api/meraki/aws/reachability?source=&destination=` | The AWS check of a flow. `source` / `destination` are IP addresses or networks; optional `protocol` (`tcp`, `udp`, `icmp`), `port`, and `source_vpc` / `destination_vpc` for a range that exists in several VPCs. Returns `applies`, `verdict` (`allowed`, `blocked`, `partial`, `unknown`), `summary` and `steps` |

## The Sources dialog

Every AWS account is a row of the **Sources** dialog on the Topology page,
next to neighbor discovery, Meraki organizations and Cato accounts, with its
last discovery. **Collect Now** runs the same discovery as **Cloud Visibility
→ Accounts → Discover** (administrators only) and **Manage** opens Cloud
Visibility, where accounts are added, edited and deleted.
