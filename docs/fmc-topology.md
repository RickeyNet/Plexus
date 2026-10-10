# Cisco FMC in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include everything a Cisco
Secure Firewall Management Center (FMC) knows about the Firewall Threat
Defense (FTD) devices it manages: every FTD, HA pairs and clusters, their
interfaces and connected subnets, static and dynamic routing, NAT, access
control and prefilter policies, site-to-site VPN topologies with their
tunnel status, network objects and security zones, health alerts, pending
deployments, and the remote access VPN side (AnyConnect / Secure Client
headends, their address pools and the users connected right now). It is all
read over the FMC REST API, read-only, and drawn on the same map as the
devices Plexus discovers itself and any Meraki organizations, Cato accounts,
Palo Alto Panoramas ([panorama-topology.md](panorama-topology.md)), AWS
accounts and Azure subscriptions. It is covered by the same search box,
Path Mode and IPAM page, and is included in the HTML export.

An FMC is handled like a Cato account: it is added, collected and deleted
from the same **Sources** dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage FMCs and credentials
- API: `/api/meraki/*` with `provider: "fmc"` (the `anyconnect` key of
  earlier releases is still accepted, see the [API reference](#api-reference))

Only an FMC-managed deployment is supported: an ASA, or an FTD managed
on-box by Firepower Device Manager, is not read.

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without an FMC.** Click **Load Sample**, then **Cisco FMC**. A
   demo FMC is added to the map: an FTDv HA pair that terminates remote
   access VPN, a branch FTD with routing, NAT and two site-to-site VPN
   tunnels, and a two-unit cluster. Load the **AWS** sample as well to see
   the FTDv members joined to their instances. Delete the demo FMC from the
   same dialog when you are done.
3. **Add your FMC.** Click **Add Source**, then **Cisco FMC**, and enter a
   name, the FMC address, the API username and its password. Under **Data to
   collect**, untick what you do not need (see
   [What is collected](#what-is-collected)).
4. **Check the login.** Click **Test Login**. It signs in to the FMC and
   lists the domains the user can see.
5. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection until you run another.

### FMC address, domain and credentials

- **FMC address**: `https://` and the host (and port) of the FMC, nothing
  else. A bare host is taken as https; `http` and a URL with a path are
  refused, and redirects are not followed, so the credentials cannot be sent
  elsewhere. Untick **Verify the FMC certificate** for an FMC that still has
  its self-signed certificate.
- **Domain**: the FMC domain to read, by name (`Global`, `Global/Branch` or
  just `Branch`) or UUID. Blank reads the Global domain. One entry reads one
  domain; add an entry per domain to cover several.
- **API username / password**: a dedicated FMC user whose role allows REST
  API access (a read-only role such as *Security Analyst (Read Only)* is
  enough for everything except the deployment status, which needs a role
  that can see deployments). Plexus only sends `GET` requests and never
  deploys or edits anything. The password is stored encrypted and never
  returned by the API or shown in the UI again.
- **Request budget**: an FMC allows about 120 API requests per minute per
  user, and a full read takes several requests per device (nine interface
  kinds, the routing of each virtual router) and per policy, so a large FMC
  takes minutes. Give this user to Plexus alone, and untick the parts you do
  not need to shorten a collection.

## On the map

FMC data appears when the group filter is **All groups**.

| On the map | What it is |
|---|---|
| **Cisco FMC** box | The FMC itself, as one node |
| Device box | One standalone FTD, named as in the FMC |
| HA pair box | Both members of an HA pair, primary first, joined by an **HA** link (a stack link, labelled with the failover link; its status is `failed` when a unit is offline or failed) |
| Cluster box | The control unit over its data units, each joined to it by a **Cluster** link (a stack link) |
| FTD (firewall icon) | A device, with its health as the node border (red offline, amber alerting). A red health alert takes a device offline |
| WAN triangle | Each outside interface of a device: one with a public address, the egress of the IPv4 default route, or a remote access VPN access interface. It carries the interface's own address |
| **AnyConnect users (N)** (star) | The users connected to a remote access VPN headend when the collection ran, as one node per device |
| VPN tunnel between FTDs | A site-to-site VPN tunnel between two FTDs of the FMC (hub to each spoke, point to point, or every pair of a full mesh; the primary for an HA pair), drawn like any VPN tunnel (purple dashed, red when the FMC reports it down) |
| **IPsec** link to a peer | A site-to-site VPN tunnel to an extranet peer (a device the FMC does not manage), drawn like a non-Meraki IPsec peer (dotted) to a node in the **Site-to-site VPN peers** box |
| Dotted grey link | **Managed by FMC**: the FMC and each device on the map. It carries no traffic: Path Mode and the tidy-tree layout ignore it |

Every managed device is drawn by default. Untick **Every managed device** on
the entry to draw only the devices with a remote access VPN policy (the
behaviour of earlier releases); the others are still listed in the FMC
node's **Managed devices** table. **Only devices whose name contains** limits
the collection to matching devices.

Remote users are one node per headend, not one node per user: the users are
listed in the node's details (user, assigned IP, public IP, connection
profile, group policy, client, OS, protocol, login time, duration, bytes) and
found by the search box.

### How an FTD joins the rest of the map

- **Inventory hosts.** An FTD whose serial number, management address or an
  interface address is that of a Plexus inventory host becomes that host's
  node, with both its SNMP/SSH data and its FMC data.
- **AWS instances.** An FTDv in a VPC has no public address of its own: AWS
  knows it by the elastic IP mapped to its interface. It is matched to its
  instance by the private address of an outside interface, under the same
  conditions as a Meraki vMX behind a NAT gateway: the instance forwards
  traffic (source/destination check off), exactly one instance and one
  outside interface have the address, and the FMC model is a virtual one
  (FTDv, "Threat Defense for AWS"). The FTD then stays in its own box and
  gains the instance's link to its VPC. The secondary of an HA pair is
  matched by its standby addresses. See [aws-topology.md](aws-topology.md).
- **Public addresses.** An FTD whose outside interface has a public address
  is the far end of any site-to-site VPN another source configures with that
  address (an AWS customer gateway, a Meraki non-Meraki VPN peer).
- **VPN endpoint addresses.** The addresses an FTD's site-to-site VPN
  endpoints use are its tunnel addresses: a VPN peer another source draws
  with one of them becomes the FTD. The other way round, an FTD's extranet
  peer whose address is the tunnel address of an AWS VPN gateway (or any
  device another source draws) becomes that gateway, so the tunnel is drawn
  once between the two real ends.

Only public addresses join sources. The demo FMC and the demo AWS account use
documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`), which the map does
not treat as public, so their FTDv instances join (by private address) but
their VPN ends stay apart.

### Device details

Click an FTD for its tabs:

- **Device**: name, health, model, software, management address, serial,
  domain, deployment status, mode, HA pair, role and state (Active /
  Standby), cluster and role, access control, prefilter, NAT and remote
  access VPN policies, virtual routers, site-to-site VPN topologies, pending
  deployment, the number of health alerts, and the **Health alerts** table
  (severity, module, description, since)
- **Interfaces**: **FTD interfaces**, every interface kind (physical,
  sub-interface, EtherChannel, redundant, VLAN, VTI, loopback, bridge group,
  inline set) with its logical name, zone, virtual router, IPv4 and IPv6
  addresses, subnet, enabled, mode, MTU and description (a VTI shows its
  tunnel source and peer). The secondary of an HA pair shows its standby
  addresses
- **VLANs**: **Connected subnets** (every interface subnet, IPv4 and IPv6,
  with interface, logical name, zone and virtual router) and, on a remote
  access VPN headend, the **VPN address pools** of its policy
- **Routing**: **Static routes** (destination object, its subnet, interface,
  gateway, metric, virtual router, tunneled, tracked; a network group is one
  row per member, a range its covering network, IPv6 routes included),
  **Virtual routers** (when there is more than the global one), **BGP** (AS
  number, router ID, networks advertised, redistribution, graceful restart)
  and **BGP neighbors**, **OSPF** and **OSPF areas**, **EIGRP**,
  **Policy-based routes** and **ECMP zones**
- **VPN**: **Site-to-site VPN**, one row per far end of each topology
  (type, role, peer and its address, local interface and address, protected
  and peer networks, IKE version, IPsec proposals, tunnel status), and on a
  headend the remote access VPN policy, **Connection profiles** and **Access
  interfaces**
- **Firewall**: **NAT rules** of the device's NAT policy (manual rules
  before auto NAT, auto NAT, manual rules after auto NAT, with original and
  translated source, destination and service, interfaces), **Access
  control** (policy, default action, rule count, prefilter policy, logging)
  and **Access control rules** (zones, networks, ports, applications, URLs,
  users, IPS and file policy, logging)

Click the users node for the connected users. Click the FMC node for its
version and domain and the **Managed devices**, **High availability pairs**,
**Clusters**, **Access control policies**, **NAT policies**, **Site-to-site
VPN topologies** (with tunnels up / down), **Remote access VPN policies**,
**Address pools**, **Network objects**, **Network groups**, **Security
zones** (with the interfaces in each), **Health alerts** and **Pending
deployment** tables. Click a link for what it is: the failover link of an HA
pair, the topology of a VPN tunnel.

### Search and Path Mode

The toolbar search covers everything collected: device names, serials,
addresses, object and group names, routes, NAT and access rules, VPN
topologies and peers, pool names, connection profiles, and connected users
by name, assigned IP or public IP.

In **Path Mode** an FTD, one of its connected subnets, one of its static
route destinations or one of its address pools can be picked like a Meraki
site or VLAN; typing an address picks the subnet that contains it. The FTD
is the gateway of those subnets. Paths follow links: the HA and cluster
links, the site-to-site tunnels and the links other sources share with the
FTD. The link between an FTD and its FMC is never part of a path.

Between two subnets or addresses the path is also traced hop by hop through
each FTD, with its prefilter and access control rules, NAT rules, connected
and static routes and site-to-site VPN protected networks, including an FTDv
inside a VPC; see [path-trace.md](path-trace.md).

### IPAM

The connected subnets, static route destinations and address pools also
appear on the **IPAM** page as subnets of source **topology** (provider
Cisco FMC), with the devices that hold them. The address pools are owned
ranges: a pool carved out of a VPC's range, or handed out by two headends of
different boxes, is listed under **Overlapping Ranges** (see the [Meraki
guide](meraki-topology.md#ipam)). Connected subnets and routes are listed
but, like a Meraki static route, are not owned ranges, so the subnet an FTDv
sits in does not count as an overlap with its own VPC.

## What is collected

Each **Data to collect** toggle of the entry turns one part on or off.

| Data | FMC API resource | Option |
|---|---|---|
| Login and the domains the user can see | `POST /api/fmc_platform/v1/auth/generatetoken` | always |
| FMC version | `GET /api/fmc_platform/v1/info/serverversion` | always |
| Managed devices (name, model, software, health, management address, serial, deployment status) | `devices/devicerecords` | always (required) |
| HA pairs, their failover state and monitored interfaces (standby addresses) | `devicehapairs/ftddevicehapairs`, `.../{id}/monitoredinterfaces` | always |
| Clusters | `deviceclusters/ftddevicecluster` | always |
| Which devices each policy targets (a pair or cluster target stands for its members) | `assignment/policyassignments` | always |
| Network objects, hosts, ranges, FQDNs, groups, security zones, interface groups | `object/networks`, `object/hosts`, `object/ranges`, `object/fqdns`, `object/networkgroups`, `object/securityzones`, `object/interfacegroups` | always |
| Remote access VPN policies, connection profiles, address assignment, access interfaces | `policies/ravpns`, `.../{id}/connectionprofiles`, `.../addressassignmentsettings`, `.../accessinterfacesettings` | always |
| IPv4 address pools | `object/ipv4addresspools` | always |
| Interfaces of each device on the map | `devices/devicerecords/{id}/physicalinterfaces`, `subinterfaces`, `etherchannelinterfaces`, `redundantinterfaces`, `vlaninterfaces`, `virtualtunnelinterfaces`, `loopbackinterfaces`, `bridgegroupinterfaces`, `inlinesets` | Device interfaces |
| Routing of each device on the map | `devices/devicerecords/{id}/routing/virtualrouters`; per virtual router `.../virtualrouters/{vr}/ipv4staticroutes`, `ipv6staticroutes`, `bgp`, `ospfv2routes`, `eigrproutes`, `ecmpzones`; the global table at `.../routing/ipv4staticroutes`, `ipv6staticroutes`, `bgp`, `ospfv2routes`, `eigrproutes`; `.../routing/policybasedroutes` | Routing |
| NAT policies and the rules of the ones in use | `policies/ftdnatpolicies`, `.../{id}/natrules` | NAT |
| Access control policies, the rules of the ones in use, prefilter policies | `policies/accesspolicies`, `.../{id}/accessrules`, `policies/prefilterpolicies` | Access control policies |
| Site-to-site VPN topologies, their endpoints, IKE and IPsec settings, tunnel status | `policies/ftds2svpns`, `.../{id}/endpoints`, `.../ikesettings`, `.../ipsecsettings`, `health/tunnelstatuses` | Site-to-site VPN |
| Health alerts and devices with a pending deployment | `health/alerts`, `deployment/deployabledevices` | Health |
| Connected remote access users | `health/ravpnsessions` | Connected users |

All configuration resources are under `/api/fmc_config/v1/domain/{uuid}/`;
every list is read with `expanded=true`. Requests are sent one at a time and
spaced out to stay inside the FMC limit of 120 per minute; a rate-limit or
server error is retried after a pause, and an expired token is renewed once
by signing in again. The progress of a collection names the part being read
(devices, HA pairs and clusters, objects, interfaces, routing, NAT, access
control, site-to-site VPN, health, sessions).

**HA pairs are read once.** Both members of a pair share one
configuration, so the interfaces and routing are read from the primary and
reused for the secondary, whose interface rows then take the standby
addresses of the pair's monitored interfaces. If the primary answers with no
interfaces, the pair record itself is tried.

**Failures.** The login and the device list are required. Everything else is
best-effort: if a request fails, the collection finishes as **partial**, the
map is still built, and the failure with the FMC's own error message is
listed under **Report** in the HTML map. Without the policy assignments the
policies are not shown on the devices; without the interfaces a device has
no outside interfaces and is not matched to an AWS instance. An outside
interface with a private address (an FTDv in a VPC) is known as outside by
the default route, so with **Routing** off it is drawn only when it is a
remote access VPN access interface.

**Older FMC releases.** A resource the FMC release does not serve answers
404 (or 405): a newer interface kind (VTI, loopback...), virtual routers,
EIGRP, policy-based routes, ECMP zones, HA monitored interfaces, prefilter
policies, tunnel status or health alerts. That is not a failure: the part is
simply absent, the collection is not marked partial, and the path is counted
under **Unsupported resources** on the FMC node (and listed in the
snapshot's `collection.unsupported`). Without virtual routers the routing is
read at the device level. Connected users come from the health API for
remote access VPN sessions, which exists on FMC 7.3 and later; on an older
FMC that request fails, is reported, and the users nodes show **not
collected**.

**Caps.** The first 1000 access control rules of each policy are read (one
page); the policy's real rule count is kept, and when it has more the
device's details say *Showing the first 1000 of N rules*. The first 1000
NAT rules of each policy are read. The FMC node lists at most 2000 network
objects and 500 groups; up to 5000 connected users are listed per headend.

**Not collected**: access control rules beyond the first 1000, platform
settings, intrusion, file, DNS and identity policy contents, FlexConfig,
syslog and SNMP settings, licenses, IPv6 address pools, group policy
contents (split tunnelling, DNS), AnyConnect client profiles, and any
operational state of the FTDs themselves, such as the routing table learnt
at run time, BGP or OSPF neighbor state and connection counts. The FMC
answers with configuration and health, not with the devices' CLI.

**Secrets.** Every payload goes through the secret filter before anything
is stored: pre-shared keys (including the IKE settings' manual pre-shared
key), passwords, secrets and tokens are dropped.

## API reference

An FMC uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for Cisco FMC |
|---|---|---|
| `GET` | `/api/meraki/orgs` | Each entry has `provider` (`meraki`, `cato` or `fmc`); `fmc_default_options` lists the FMC collection options |
| `POST` | `/api/meraki/orgs` | `{"name", "provider": "fmc", "base_url": "https://<fmc>", "org_id": "<domain>", "api_key": "<password>", "options": {"username": ..., "verify_tls"?, "device_name_contains"?, "include_all_devices"?, "include_interfaces"?, "include_routing"?, "include_s2s_vpn"?, "include_nat"?, "include_access_policies"?, "include_health"?, "include_sessions"?, "inventory_enrich"?}}` (admin). `api_key` carries the password |
| `POST` | `/api/meraki/orgs/{id}/validate` | Signs in to the FMC; `organizations` lists the domains the user can see (admin) |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id`. Progress phases: `fmc login`, `fmc devices`, `fmc ha`, `fmc objects`, `fmc vpn policies`, `fmc pools`, `fmc interfaces`, `fmc routing`, `fmc nat`, `fmc access policies`, `fmc s2s vpn`, `fmc health`, `fmc sessions`, `collected` |
| `POST` | `/api/meraki/sample?provider=fmc` | Add / refresh the demo FMC ("Sample Cisco FMC (demo data)") |
| `GET` | `/api/topology` | FMC nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `fmc`; the FMC links have `protocol: "management"`, HA and cluster links `stack`, tunnels between FTDs `vpn`, tunnels to extranet peers `vpn-ipsec` |
| `GET` | `/api/meraki/subnets` | Includes every FTD's connected subnets (`kind: "connected"`), static route destinations (`kind: "static"`) and address pools (`kind: "pool"`), with `provider: "fmc"` |

**Earlier releases.** This integration was the `anyconnect` provider while it
only drew remote access VPN headends. The `anyconnect` key is still accepted
on input (`POST /api/meraki/orgs` stores it as `fmc`, and
`POST /api/meraki/sample?provider=anyconnect` builds the FMC sample); stored
entries were renamed by migration 0070, together with the software tracker's
rows of their devices, and a snapshot stored under `anyconnect` is served as
`fmc`. The `anyconnect_default_options` key of `GET /api/meraki/orgs` is
gone; read `fmc_default_options`.
