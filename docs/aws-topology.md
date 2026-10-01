# AWS in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the AWS accounts that
Cloud Visibility discovers. VPCs, their subnets, internet / NAT / virtual
private gateways, transit gateways, VPC peerings, site-to-site VPN
connections, Direct Connect and the instances that forward traffic appear on
the same map as the devices Plexus discovers itself and any Meraki
organizations and Cato accounts. They are covered by the same search box and
Path Mode, and are included in the HTML export.

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
   **Meraki / Cato**, then **Load AWS Sample**. A demo AWS account is added
   to Cloud Visibility and to the map. Delete it under **Cloud Visibility →
   Accounts** when you are done.
2. **Install the AWS SDK** on the Plexus server, once:
   `pip install -r requirements-cloud.txt` (it is optional and not part of
   the base install). Without it discovery reports that its dependencies are
   not installed.
3. **Add the account.** Open **Cloud Visibility → Accounts → Add Cloud
   Account**, choose AWS, and fill in:
   - *Region Scope*: the regions to read, comma-separated
     (`us-east-1,us-west-2`). **Left empty, only `us-east-1` is read.**
   - *Auth Config*: how discovery signs in (see below).
4. **Validate**, then **Discover**. When discovery finishes the account is on
   the Topology map (group filter **All groups**).

To refresh the map, run **Discover** again. Scheduled discovery
(`PUT /api/cloud/discovery-sync/config` with `enabled` and
`interval_seconds`) refreshes every enabled account on a timer.

### Signing in

*Auth Config* is a JSON object, stored encrypted and never shown again:

| Keys | Sign-in |
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

Discovery only calls `Describe*` operations. The AWS-managed policies
**AmazonEC2ReadOnlyAccess** and **AWSDirectConnectReadOnlyAccess** cover all
of them. For a custom policy:

| Needed | Actions |
|---|---|
| Always (discovery fails without them) | `ec2:DescribeVpcs`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeSecurityGroups`, `ec2:DescribeTransitGateways`, `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeVpnGateways`, `ec2:DescribeRouteTables`, `ec2:DescribeVpnConnections`, `directconnect:DescribeConnections` |
| For the map (skipped when denied) | `ec2:DescribeSubnets`, `ec2:DescribeInstances`, `ec2:DescribeCustomerGateways`, `directconnect:DescribeVirtualInterfaces`, `directconnect:DescribeDirectConnectGateways`, `directconnect:DescribeDirectConnectGatewayAssociations` |

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
- **The same VPN seen from the other side.** A Meraki non-Meraki VPN peer or
  a Cato IPsec site configured with an AWS tunnel address is joined to the
  AWS gateway that owns the address.

Only public addresses are used for this; private addresses repeat from site
to site and identify nothing.

### Device details

Click a VPC for its tabs:

- **Device**: the VPC overview and the list of instances
- **VLANs**: the subnets (CIDR, name, availability zone, route table, where
  the default route goes, free addresses)
- **Routing**: every route of every route table of the VPC
- **Firewall**: the security group rules

A transit or virtual private gateway lists its attachments and VPN
connections (tunnel addresses, tunnel status, routing, static routes); a
forwarding instance lists its network interfaces.

### Search and Path Mode

The toolbar search covers everything collected: VPC, subnet and instance
names, IDs (`vpc-…`, `subnet-…`, `i-…`, `tgw-…`), CIDRs, private and public
IPs, route targets and security group rules.

In **Path Mode** a VPC or one of its subnets can be picked like a Meraki
site; typing an IP address picks the subnet that contains it. A path between
two VPCs runs over their transit gateway or peering, and a path to a site
runs over the VPN or virtual appliance that joins it to AWS.

Path Mode follows the links on the map, not route tables. It shows how two
places *can* reach each other; it does not check that the VPC route tables,
transit gateway route tables or security groups actually allow it. The
VPC's route tables are in its details for that check.

## What is collected

| Data | AWS API call |
|---|---|
| VPCs, internet / NAT / virtual private gateways, security groups | `DescribeVpcs`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeVpnGateways`, `DescribeSecurityGroups` |
| Transit gateways and their attachments, VPC peerings | `DescribeTransitGateways`, `DescribeTransitGatewayAttachments`, `DescribeVpcPeeringConnections` |
| Route tables with their routes | `DescribeRouteTables` |
| Site-to-site VPN connections and tunnel status | `DescribeVpnConnections` |
| Subnets | `DescribeSubnets` |
| Instances and their network interfaces | `DescribeInstances` |
| Customer gateways | `DescribeCustomerGateways` |
| Direct Connect connections, virtual interfaces, gateways | `DescribeConnections`, `DescribeVirtualInterfaces`, `DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations` |

Not collected: transit gateway route tables, network ACLs, load balancers,
VPC endpoints, Client VPN endpoints, and the on-premises router behind a
Direct Connect (a Direct Connect is the edge of the map). The subnets also
appear in IPAM's cloud CIDR view.

## API reference

| Method | Path | Notes for AWS |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "aws", "name", "region_scope", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `POST` | `/api/meraki/sample?provider=aws` | Add / refresh the demo AWS account |
| `GET` | `/api/topology` | AWS nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `aws` and whose `org_ref` is `-1` (all AWS accounts share one reference) |
| `GET` | `/api/meraki/nodes?org_ref=-1&node_id=…` | Detail sections of one AWS node |
| `GET` | `/api/meraki/subnets` | Includes the subnets of every VPC |
