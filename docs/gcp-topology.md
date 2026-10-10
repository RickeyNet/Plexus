# GCP in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the GCP projects that
Cloud Visibility discovers. VPC networks, their subnets, VPC peerings, the
default internet gateway of each network, Cloud Routers and their Cloud
NATs, HA and Classic VPN gateways, VPN tunnels, external VPN gateways,
Interconnect attachments and Interconnects, and the VM instances that
forward traffic appear on the same map as the devices Plexus discovers
itself and any Meraki organizations, Cato accounts, Cisco FMCs, AWS
accounts and Azure subscriptions. They are covered by the same search box
and Path Mode, and are included in the HTML export.

GCP works the way AWS does on the map; [aws-topology.md](aws-topology.md)
describes the shared behavior. This guide covers what is different.

- Permission: the `topology` feature to view the map; admin to manage cloud
  accounts and run discovery
- API: `/api/cloud/*` for accounts and discovery, `/api/topology` and
  `/api/meraki/*` for the map

## Quick start

1. **Preview without credentials.** On the Topology page click
   **Sources**, then **Load Sample** and **GCP**. A demo project is added to
   Cloud Visibility and to the map. Delete it under **Cloud Visibility →
   Accounts** when you are done.
2. **Install the Google API client** on the Plexus server, once:
   `pip install -r requirements-cloud.txt`.
3. **Add the project.** Open **Cloud Visibility → Accounts → Add GCP
   project**, enter the **Project ID** and pick how Plexus signs in: the
   JSON key of a service account (**Service account key**), or the
   **Credentials of the Plexus server** (its Application Default
   Credentials). A key file already on the server can be named instead,
   with `{"service_account_file": "/etc/plexus/gcp.json"}` under
   **Additional settings (JSON, rarely needed)**.
4. **Discover** (it checks the sign-in first). When discovery finishes the
   project is on the map.

One account entry reads one project. Add one entry per project; they are
joined on the map automatically, because every resource is named by its
project, region or zone, and name. A peering with a network of another
project, a Shared VPC host network and the peer GCP gateway of an HA VPN
tunnel are named by their own project, so they join up with that project's
discovery when it is added too.

An existing GCP account that was discovered before this release needs
**Discover** run again before it appears on the map.

### Permissions

Discovery is read-only. The predefined **Compute Viewer** role
(`roles/compute.viewer`) on the project is enough; **Compute Network
Viewer** (`roles/compute.networkViewer`) covers everything but the VM
instances.

| Needed | Compute Engine API methods |
|---|---|
| Always (discovery fails without them) | `networks.list`, `subnetworks.aggregatedList`, `routes.list`, `firewalls.list` |
| For the map (skipped when denied) | `routers.aggregatedList`, `routers.getRouterStatus`, `vpnGateways.aggregatedList`, `targetVpnGateways.aggregatedList`, `vpnTunnels.aggregatedList`, `externalVpnGateways.list`, `interconnectAttachments.aggregatedList`, `interconnects.list`, `instances.aggregatedList`, `networkFirewallPolicies.list` |

A section that is denied is skipped, not fatal. It is listed with the HTTP
status and error reason GCP answered (`forbidden (HTTP 403)`) under
**Report** in the HTML map and as a `collection_warning` row among the
account's resources. `routers.getRouterStatus` gives the state of each BGP
session, the addresses of each Cloud NAT and the routes the Cloud Routers
learned; without it the routers are drawn but what they learn is not known.

VPN tunnels carry a shared secret. Plexus does not read or store it, nor its
hash.

## On the map

| On the map | What it is |
|---|---|
| Site box | One VPC network, named after the network (GCP networks are global, so no region); the project is added when several projects are on the map |
| VPC (diamond) | The network's own router. It owns the subnets of every region: a path to or from a subnet starts here |
| Internet gateway (triangle) | The default internet gateway, for a network that has a route to it |
| CR (hexagon) | A Cloud Router of the network, with its BGP sessions |
| NAT (hexagon) | A Cloud NAT, beside the Cloud Router it belongs to |
| VPN (hexagon) | An HA VPN gateway, or a Classic VPN gateway, of the network |
| VM instance (firewall icon) | An instance with IP forwarding on (`canIpForward`): firewalls, routers, SD-WAN and VPN appliances |
| **GCP VPN and Interconnect** box | External VPN gateways (one node per interface), Interconnect attachments, Interconnects, and the bare peer address of a tunnel without an external VPN gateway |
| Not collected box | A peered network of a project Plexus does not collect |
| Orange link | VPC peering, Cloud Router, Cloud NAT, VPN gateway, Interconnect attachment |
| Dashed tunnel | A VPN tunnel, from its gateway to the external VPN gateway or peer GCP gateway; red when it is not established |

A VM instance is drawn when it forwards traffic or when one of its
addresses is a Plexus inventory host. Every other instance is listed in its
network's details and found by the search box.

GCP joins the rest of the map the way AWS does: an external VPN gateway
interface becomes the device that answers on its public address, an
instance on the WAN address of a Meraki or Cato appliance is that appliance
(a vMX in GCP), and a Meraki or Cato IPsec peer configured with the public
address of an HA VPN gateway interface is joined to that gateway.

### Device details

Click a VPC network for its tabs:

- **Device**: the network overview (routing mode, subnet mode, MTU,
  regions, network firewall policies) and the list of VM instances
- **VLANs**: the subnets (primary range, region, secondary ranges, where the
  default route goes, Cloud NAT, Private Google Access, addresses in use)
- **Routing**: every route of the network with its priority, next hop and
  network tags (the subnet routes first), the dynamic routes its Cloud
  Routers learned, and its peerings
- **Firewall**: every VPC firewall rule in priority order, with the two
  implied rules last

A Cloud Router lists its interfaces, BGP sessions (peer, ASN, state) and
learned routes; an HA VPN gateway and an external VPN gateway list their
tunnels (status, peer address, IKE version, Cloud Router, BGP session). An
Interconnect attachment lists its type, bandwidth, VLAN and the addresses
of both routers.

## The GCP check of a path

When both ends of a path are subnets or IP addresses and at least one is in
a VPC network, Plexus checks the flow against what discovery collected.
Between two subnets or addresses the path is traced hop by hop across every
device on the map, and the hops in GCP list these checks as their items;
see [path-trace.md](path-trace.md). The **Traffic** box works as for AWS.
`GET /api/meraki/gcp/reachability` answers the GCP part on its own.

- **Routes.** Routing belongs to the network, not to the subnet. The
  candidate routes are the subnet routes of every range of the network
  (secondary ranges included), the subnet routes of every active peered
  network, the network's static routes, and the dynamic routes its Cloud
  Routers learned over BGP: every region's in a network with global routing,
  only the router's own region's in a network with regional routing. The
  longest prefix wins, then the lowest priority number. A route with network
  tags applies only to an instance that carries one of them; for an end that
  is a whole subnet such routes are left out, and an item says so. The reply
  is routed the same way from the other end.
- **VPC peerings.** A peering carries traffic between its two networks only;
  routes exchanged over it beyond the subnet routes are not followed.
- **VPN and BGP.** A route over a VPN tunnel, static or learned over BGP,
  leaves GCP over that tunnel only while it is established; a tunnel that is
  not is a block. Traffic coming back in enters through the tunnel the way
  out used, and the item names the route that carries it.
- **Interconnect.** A route learned over an Interconnect attachment leaves
  GCP over it while the attachment is active. The on-premises router behind
  it is the edge of the map.
- **Internet and Cloud NAT.** A route to the default internet gateway takes
  a flow to the internet from an instance with an external IP, or from a
  subnet a Cloud NAT of its region serves; an instance with neither is
  blocked. A flow from the internet reaches only an instance with an
  external IP, never through a Cloud NAT. A private address sent to the
  internet gateway is a block.
- **Appliances.** A route to an instance (`nextHopInstance` or `nextHopIp`)
  hands the flow to it. An instance with IP forwarding off drops it. A
  Meraki vMX on the map carries it on over its VPN; any other appliance ends
  what GCP can tell.
- **VPC firewall rules.** They are stateful and belong to the network,
  applied per instance. The request must pass the egress rules at the
  source and the ingress rules at the destination: the rules whose targets
  (network tags, service accounts, or none for every instance) match the
  instance, by priority (the lowest number first; on a tie a deny rule
  wins), down to the implied rules that allow all egress and deny all
  ingress. Source tags and source service accounts match instances of the
  same network. For an end typed as a whole subnet only the rules for every
  instance are applied; the rest are listed as not checked, and the result
  is *allowed in part* when one of them would decide otherwise. Type an
  **instance's IP address** to include them.

*Check incomplete* means one of:

- the route hands the traffic to an appliance that is not a Meraki
  appliance on the map, to an internal passthrough Network Load Balancer or
  to a Network Connectivity Center hub
- the address may be a range of a peered network that is not collected
- a dynamic route goes over a tunnel or attachment that was not collected
- a network firewall policy is associated with the network: its rules are
  not evaluated

Limits: only IPv4 can be typed in Path Mode. Hierarchical firewall policies
(set on the organization or a folder) and regional network firewall policies
are not collected, and the rules of global network firewall policies are not
evaluated. Private Service Connect, load balancers, Network Connectivity
Center hubs and the custom routes a peering exchanges are not collected.

## API reference

| Method | Path | Notes for GCP |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "gcp", "name", "account_identifier": "<project id>", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `POST` | `/api/meraki/sample?provider=gcp` | Add / refresh the demo project |
| `GET` | `/api/topology` | GCP nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `gcp` and whose `org_ref` is `-3` |
| `GET` | `/api/meraki/nodes?org_ref=-3&node_id=…` | Detail sections of one GCP node |
| `GET` | `/api/meraki/subnets` | Includes the subnets of every VPC network (`provider: "gcp"`, `site_id` is `project:network`) |
| `GET` | `/api/meraki/gcp/reachability?source=&destination=` | The GCP check of a flow. Optional `protocol`, `port`, and `source_network` / `destination_network` (`project:network`) for a range that exists in several networks. Same answer shape as the AWS check, with `in_gcp` on each end |
