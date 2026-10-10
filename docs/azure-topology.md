# Azure in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) includes the Azure subscriptions
that Cloud Visibility discovers. Virtual networks, their subnets, VNet
peerings, VPN and ExpressRoute gateways, local network gateways,
site-to-site VPN connections, ExpressRoute circuits, NAT gateways, Azure
Firewalls and the virtual machines that forward traffic appear on the same
map as the devices Plexus discovers itself and any Meraki organizations,
Cato accounts, Cisco FMCs and AWS accounts. They are covered by the same
search box and Path Mode, and are included in the HTML export.

Azure works the way AWS does on the map; [aws-topology.md](aws-topology.md)
describes the shared behavior. This guide covers what is different. GCP
projects join the map the same way; see [gcp-topology.md](gcp-topology.md).

- Permission: the `topology` feature to view the map; admin to manage cloud
  accounts and run discovery
- API: `/api/cloud/*` for accounts and discovery, `/api/topology` and
  `/api/meraki/*` for the map

## Quick start

1. **Preview without credentials.** On the Topology page click
   **Sources**, then **Load Sample** and **Azure**. A demo subscription is
   added to Cloud Visibility and to the map. Delete it under **Cloud
   Visibility → Accounts** when you are done.
2. **Install the Azure SDK** on the Plexus server, once:
   `pip install -r requirements-cloud.txt`.
3. **Add the subscription.** Open **Cloud Visibility → Accounts → Add Azure
   subscription**, enter the **Subscription ID** and pick how Plexus
   signs in: a service principal (tenant ID, client ID, client secret) or
   the managed identity / environment credentials of the Plexus server.
4. **Discover** (it checks the sign-in first). When discovery finishes the
   subscription is on the map.

One account entry reads one subscription. Add one entry per subscription;
they are joined on the map automatically, because every resource is named
by its subscription, resource group and name.

### Permissions

Discovery is read-only. The built-in **Reader** role on the subscription is
enough; so is **Network Reader**-style access to `Microsoft.Network/*/read`.

| Needed | Azure resources read |
|---|---|
| Always (discovery fails without them) | Virtual networks with their subnets and peerings, ExpressRoute circuits, virtual network gateways, local network gateways, route tables, network security groups, gateway connections |
| For the map (skipped when denied) | Public IP addresses, NAT gateways, network interfaces, Azure Firewalls |

A section that is denied is skipped, not fatal. It is listed with the Azure
error code under **Report** in the HTML map and as a `collection_warning`
row among the account's resources.

Gateway connections carry a shared key. Plexus does not read or store it.

## On the map

| On the map | What it is |
|---|---|
| Site box | One VNet, named `name (region)`; the account name is added when several accounts are on the map |
| VNet (diamond) | The VNet's own router. It owns the VNet's subnets: a path to or from a subnet starts here |
| VGW / ERGW (hexagon) | The VPN gateway or ExpressRoute gateway of the VNet |
| NAT (hexagon) | A NAT gateway of the VNet |
| Azure Firewall (firewall icon) | The managed firewall of the VNet |
| Virtual machine (firewall icon) | A virtual machine with IP forwarding on: firewalls, routers, SD-WAN and VPN appliances |
| **Azure VPN and ExpressRoute** box | ExpressRoute circuits, local network gateways, and VNets of subscriptions Plexus does not collect |
| Orange link | VNet peering, gateway, NAT gateway, ExpressRoute connection |
| Dashed tunnel | A site-to-site or VNet-to-VNet connection; red when Azure reports it not connected |

Virtual machines are read from their network interfaces. A machine is drawn
when one of its interfaces forwards traffic or when it is a Plexus inventory
host. Every other machine is listed in its VNet's details and found by the
search box. The Network API does not report the power state, so virtual
machines carry no status.

Azure joins the rest of the map the way AWS does: a local network gateway
becomes the device that answers on its public address, a virtual machine on
the WAN address of a Meraki or Cato appliance is that appliance (a vMX in
Azure), and a Meraki or Cato IPsec peer configured with the public address
of an Azure VPN gateway is joined to that gateway.

### Device details

Click a VNet for its tabs:

- **Device**: the VNet overview and the list of virtual machines
- **VLANs**: the subnets (prefix, route table, where the default route
  goes, network security group, NAT gateway, delegation, addresses in use)
- **Routing**: every route of the route tables applied to the VNet's
  subnets, and the VNet's peerings
- **Firewall**: the rules of every network security group, default rules
  included

A VPN gateway and a local network gateway list their connections (status,
BGP or static, bytes in and out, remote address space). An ExpressRoute
circuit lists its provider, bandwidth and peerings.

## The Azure check of a path

When both ends of a path are subnets or IP addresses and at least one is in
a VNet, Plexus checks the flow against what discovery collected. Between two
subnets or addresses the path is traced hop by hop across every device on
the map, and the hops in Azure list these checks as their items; see
[path-trace.md](path-trace.md). The **Traffic** box works as for AWS.
`GET /api/meraki/azure/reachability` still answers the Azure part on its
own.

- **Effective routes.** Plexus rebuilds what Azure applies to the source
  subnet: the VNet's address space, the address space of every connected
  peering, the ranges behind the gateway (the VNet's own, or the hub's when
  the peering uses remote gateways), the internet, and the routes of the
  subnet's route table, which override the rest. The longest prefix wins;
  on a tie a user route beats a gateway route beats a system route. The
  reply is routed the same way from the other end.
- **VNet peerings.** A peering only carries traffic between its two VNets.
- **Gateways.** A site-to-site connection carries the address space of its
  local network gateway. A connection Azure reports as not connected is a
  block.
- **Network security groups.** They are stateful. The request must pass the
  group of the source subnet and interface outbound, then the group of the
  destination subnet and interface inbound, rule by rule in priority order,
  default rules included. `VirtualNetwork` covers the VNet, its peered VNets
  and the ranges behind its gateways; `Internet` covers public addresses.
  The interface's group is checked when an end is typed as the **IP address
  of a virtual machine**.

*Check incomplete* means one of:

- the route hands the traffic to an Azure Firewall, whose firewall policy is
  not collected, or to a virtual appliance that is not a Meraki appliance on
  the map
- the address is reached over BGP or ExpressRoute, whose learned routes are
  not collected
- a rule names a service tag other than `VirtualNetwork`, `Internet` and
  `AzureLoadBalancer`, or an application security group

Limits: only IPv4 can be typed in Path Mode. Azure Virtual WAN hubs, private
endpoints, load balancers and application gateways are not collected.

## API reference

| Method | Path | Notes for Azure |
|---|---|---|
| `POST` | `/api/cloud/accounts` | `{"provider": "azure", "name", "account_identifier": "<subscription id>", "auth_config"}` (admin) |
| `POST` | `/api/cloud/accounts/{id}/discover` | Run discovery; the map updates when it succeeds (admin) |
| `POST` | `/api/meraki/sample?provider=azure` | Add / refresh the demo subscription |
| `GET` | `/api/topology` | Azure nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `azure` and whose `org_ref` is `-2` |
| `GET` | `/api/meraki/nodes?org_ref=-2&node_id=…` | Detail sections of one Azure node |
| `GET` | `/api/meraki/subnets` | Includes the subnets of every VNet (`provider: "azure"`, `site_id` is `subscription:resource group:vnet`) |
| `GET` | `/api/meraki/azure/reachability?source=&destination=` | The Azure check of a flow. Optional `protocol`, `port`, and `source_vnet` / `destination_vnet` for a range that exists in several VNets. Same answer shape as the AWS check |
