# GCP in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the GCP projects that
Cloud Visibility discovers. VPC networks, their subnets, VPC peerings, the
default internet gateway of each network, Cloud Routers and their Cloud
NATs, HA and Classic VPN gateways, VPN tunnels, external VPN gateways,
Interconnect attachments and Interconnects, and the VM instances that
forward traffic appear on the same map as the devices Plexus discovers
itself and any Meraki organizations, Cato accounts, Cisco FMCs, AWS
accounts and Azure subscriptions. They are covered by the same search box
and Path Mode, and are included in the HTML export. Load balancers (with
the health of their backends), Private Service Connect endpoints and
service attachments, Cloud SQL instances and Memorystore for Redis
instances are listed in their network's details.

GCP works the way AWS does on the map; [aws-topology.md](aws-topology.md)
describes the shared behavior. This guide covers what is different.

- Permission: the `topology` feature to view the map; admin to manage cloud
  accounts and run discovery
- API: `/api/cloud/*` for accounts and discovery, `/api/topology` and
  `/api/sources/*` for the map

## Quick start

1. **Preview without credentials.** On the Topology page click
   **Sources**, then **Load Sample** and **GCP**. A demo project is added to
   Cloud Visibility and to the map. Delete it under **Cloud Visibility →
   Accounts** when you are done.
2. **Install the Google API client** on the Plexus server, once:
   `pip install -r requirements-cloud.txt`.
3. **Add the project.** Open **Cloud Visibility → Accounts → Add GCP
   project** (or **Sources → Add Source → GCP Project** on the Topology
   page, which opens the same dialog), enter the **Project ID** and pick how
   Plexus signs in: the
   JSON key of a service account (**Service account key**), or the
   **Credentials of the Plexus server** (its Application Default
   Credentials). A key file already on the server can be named instead,
   with `{"service_account_file": "/etc/plexus/gcp.json"}` under
   **Additional settings (JSON, rarely needed)**.
4. **Discover** (it checks the sign-in first). When discovery finishes the
   project is on the map.
   A new entry is discovered as soon as it is created (when it is enabled),
   and the page says whether scheduled discovery is on, with a button to turn
   it on (it is off by default).

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
(`roles/compute.viewer`) on the project grants every permission below;
**Compute Network Viewer** (`roles/compute.networkViewer`) lacks some of
them (VM instances among them), so check a custom role against the table.
Cloud SQL and Memorystore are read through their own APIs: add **Cloud SQL
Viewer** (`roles/cloudsql.viewer`) and **Cloud Memorystore Redis Viewer**
(`roles/redis.viewer`), and enable the Cloud SQL Admin API
(`sqladmin.googleapis.com`) and the Memorystore for Redis API
(`redis.googleapis.com`) on the project; without them those sections are
skipped. The client library ships both APIs' discovery documents, so no
other Python package is needed.

| Section | Compute Engine API methods | IAM permissions |
|---|---|---|
| **Always** (discovery fails without them) | | |
| Networks | `networks.list` | `compute.networks.list` |
| Subnets | `subnetworks.aggregatedList` | `compute.subnetworks.list` |
| Routes | `routes.list` | `compute.routes.list` |
| Firewall rules | `firewalls.list` | `compute.firewalls.list` |
| **For the map** (skipped when denied) | | |
| Cloud Routers | `routers.aggregatedList` | `compute.routers.list` |
| BGP state and learned routes (`router_status`) | `routers.getRouterStatus` | `compute.routers.get` |
| HA VPN gateways | `vpnGateways.aggregatedList` | `compute.vpnGateways.list` |
| Classic VPN gateways | `targetVpnGateways.aggregatedList` | `compute.targetVpnGateways.list` |
| VPN tunnels | `vpnTunnels.aggregatedList` | `compute.vpnTunnels.list` |
| External VPN gateways | `externalVpnGateways.list` | `compute.externalVpnGateways.list` |
| Interconnect attachments | `interconnectAttachments.aggregatedList` | `compute.interconnectAttachments.list` |
| Interconnects | `interconnects.list` | `compute.interconnects.list` |
| VM instances | `instances.aggregatedList` | `compute.instances.list` |
| Network firewall policies | `networkFirewallPolicies.list` | `compute.networkFirewallPolicies.list` |
| **Load balancers and Private Service Connect** (skipped when denied) | | |
| Forwarding rules (regional) | `forwardingRules.aggregatedList` | `compute.forwardingRules.list` |
| Forwarding rules (global) | `globalForwardingRules.list` | `compute.globalForwardingRules.list` |
| Backend services | `backendServices.aggregatedList` | `compute.backendServices.list` |
| URL maps | `urlMaps.aggregatedList` | `compute.urlMaps.list` |
| Target proxies | `targetHttpProxies.aggregatedList`, `targetHttpsProxies.aggregatedList`, `targetTcpProxies.aggregatedList`, `targetSslProxies.list` | `compute.targetHttpProxies.list`, `compute.targetHttpsProxies.list`, `compute.targetTcpProxies.list`, `compute.targetSslProxies.list` |
| Target pools | `targetPools.aggregatedList` | `compute.targetPools.list` |
| Instance groups | `instanceGroups.aggregatedList` | `compute.instanceGroups.list` |
| Network endpoint groups | `networkEndpointGroups.aggregatedList` | `compute.networkEndpointGroups.list` |
| Service attachments | `serviceAttachments.aggregatedList` | `compute.serviceAttachments.list` |
| Backend health (`backend_health`) | `backendServices.getHealth`, `regionBackendServices.getHealth` (one call per backend group, at most 200 per discovery) | `compute.backendServices.get`, `compute.regionBackendServices.get` |
| **Managed services** (skipped when denied or when the API is not enabled) | | |
| Cloud SQL instances | Cloud SQL Admin API `instances.list` | `cloudsql.instances.list` |
| Memorystore for Redis instances | Memorystore for Redis API `projects.locations.instances.list` (every location) | `redis.instances.list` |

A section that is denied is skipped, not fatal. It is listed with the HTTP
status and error reason GCP answered (`forbidden (HTTP 403)`) and the IAM
permissions it needs under **Report** in the HTML map and as a
`collection_warning` row among the account's resources. `routers.getRouterStatus` gives the state of each BGP
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
network's details and found by the search box, and its internal address is
in the subnet picker of Path Mode: typing the address picks the network.

### Load balancers, Private Service Connect, Cloud SQL and Memorystore

Load balancers, Private Service Connect, Cloud SQL and Memorystore are not drawn: like the AWS
services with endpoints ([aws-topology.md](aws-topology.md)), the network's
details list them with the same columns (kind, state, DNS names, addresses,
subnets, details), and a **Service endpoints** table has a row per internal
address, so the search box finds the network by a load balancer's name,
address or internal DNS name, and the subnet index (IPAM) lists each
internal address as a host of the network.

| Table | What it lists |
|---|---|
| Load balancers | One row per forwarding rule (the frontend of a load balancer), named by the load balancer type Google gives it: global or regional external Application Load Balancer, Classic Application Load Balancer, regional or cross-region internal Application Load Balancer, proxy Network Load Balancers, internal or external passthrough Network Load Balancer (also on a target pool), protocol forwarding, Cloud Service Mesh. Details: scheme, protocol, ports, target proxy, the backend services (through the target proxy and URL map: its default service and those of its path matchers), how many backends (instance groups, network endpoint groups, target pool instances) they have, and the backend health: how many backends of its backend services' groups are healthy, unhealthy (UNHEALTHY, TIMEOUT) or unknown (DRAINING, UNKNOWN), stored as `backend_health` with a row per backend group in `backend_health_groups`. The health of target pool instances is not read |
| Private Service Connect | Endpoints (a forwarding rule whose target is a service attachment, or the Google APIs bundle `all-apis` / `vpc-sc`) with their target and connection status; service attachments (the producer side) with their target forwarding rule, connection preference, NAT subnets and how many consumer endpoints are accepted or pending |
| Cloud SQL | Each instance with a private IP, in the network of its private services access (`privateNetwork`): engine and version, state (RUNNABLE, SUSPENDED, MAINTENANCE...), tier, availability type, connection name. Its PRIVATE address (with the engine's port) is a host of the network; its public (PRIMARY) address is listed, and its OUTGOING address kept. An instance reached only over Private Service Connect has no network of its own: the consumers' PSC endpoints are listed instead |
| Memorystore | Each Memorystore for Redis instance, in its authorized network: Redis version, state (READY, CREATING...), tier, connect mode (direct peering or private services access), memory size. Its primary and read endpoints are hosts of the network |

An internal forwarding rule is in the network and subnet it names. An
external one names no network: it is placed in the network of its backends
(the instance groups or network endpoint groups of its backend services);
one whose backends were not collected, or that has none in a VPC network
(a serverless or internet NEG, a backend bucket), is listed under Cloud
Visibility only. Its external address is listed, not a host of the
network. A service attachment is placed by its target forwarding rule, else
by its NAT subnets. The forwarding rules of a Classic VPN gateway are not
listed (the gateway is). Firewall rules apply to a load balancer's
backends, not its frontend, so the Security groups column stays empty.

GCP joins the rest of the map the way AWS does: an external VPN gateway
interface becomes the device that answers on its public address, an
instance on the WAN address of a Meraki or Cato appliance is that appliance
(a vMX in GCP), and a Meraki or Cato IPsec peer configured with the public
address of an HA VPN gateway interface is joined to that gateway.

### Device details

Click a VPC network for its tabs:

- **Device**: the network overview (routing mode, subnet mode, MTU,
  regions, network firewall policies), the list of VM instances, the load
  balancers and Private Service Connect endpoints and service attachments,
  and their service endpoints
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
`GET /api/sources/gcp/reachability` answers the GCP part on its own.

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
evaluated. Load balancers and Private Service Connect endpoints are path
trace ends: an internal forwarding rule's or endpoint's address (or its
collected DNS name) places in its subnet, the VPC firewall rules for all
instances are checked, and the hop names the service, the forwarding rule's
protocol and ports that take the flow (none: blocked) and, for an endpoint,
the service attachment it connects to. An external forwarding rule's
address ends the trace at the load balancer, in the network of its
backends, naming its backend services: a path is not followed to the
backends, which are not collected by address. The Cato egress check does
not cover GCP load balancers: their firewall rules apply at the backends.
Network Connectivity
Center hubs and the custom routes a peering exchanges are not collected.
Cloud SQL and Memorystore for Redis are collected and listed (see above),
but neither is a path trace destination; Memorystore for Redis Cluster,
Memorystore for Memcached and Valkey are not collected.

## Virtual machines

Every Compute Engine instance of a discovered project (resource type
`instance`) is also mirrored as a virtual machine under **Assets >
Virtualization**, in a cluster of type *GCP* per project and region, with
one interface per network interface (`nic0`...) and its internal and
external addresses (alias ranges are not stored). RUNNING is active,
PROVISIONING and STAGING staged, STOPPING, SUSPENDED and TERMINATED
offline. vCPUs and memory are not collected. See
[Virtualization](virtualization.md#cloud-instances-as-virtual-machines).

## Availability tracking

Each collection also records the state of what it reports, shown under **Monitoring > Availability > Integrations and cloud** with uptime, outages and alerts: the instances drawn on the map, Cloud Routers, HA VPN gateways, Cloud NAT, Interconnects and Interconnect attachments (devices), HA VPN tunnels (VPN connections), Interconnect attachments and Interconnects (circuits), VPC peerings, and the services listed in the network details (load balancers, Private Service Connect endpoints and service attachments) as services: a PSC endpoint by its connection status (ACCEPTED up, PENDING unknown, NEEDS_ATTENTION degraded, REJECTED or CLOSED down); a load balancer or service attachment, which has no state of its own, is up unless the health of its backends, when collected, says otherwise (none healthy down, some unhealthy degraded; see [Cloud managed services](meraki-topology.md#cloud-managed-services)). VPC networks and external VPN gateways are left out. The state mapping, alerting and retention are described in [Meraki in the Topology Map](meraki-topology.md#availability-tracking).

## API reference

| Method | Path | Notes for GCP |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "gcp", "name", "account_identifier": "<project id>", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `POST` | `/api/sources/sample?provider=gcp` | Add / refresh the demo project |
| `GET` | `/api/topology` | GCP nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `gcp` and whose `org_ref` is `-3` |
| `GET` | `/api/sources/nodes?org_ref=-3&node_id=…` | Detail sections of one GCP node |
| `GET` | `/api/sources/subnets` | Includes the subnets of every VPC network (`provider: "gcp"`, `site_id` is `project:network`) |
| `GET` | `/api/sources/gcp/reachability?source=&destination=` | The GCP check of a flow. Optional `protocol`, `port`, and `source_network` / `destination_network` (`project:network`) for a range that exists in several networks. Same answer shape as the AWS check, with `in_gcp` on each end |
