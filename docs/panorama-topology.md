# Palo Alto Panorama in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include everything a Palo
Alto Networks Panorama knows about the firewalls it manages: every managed
firewall and HA pair, the device group hierarchy with its address and
service objects, the security and NAT rules each firewall inherits, the
network configuration its template stack gives it (interfaces, zones,
virtual routers, static routes, BGP, OSPF, IKE gateways, IPsec tunnels,
GlobalProtect gateways), and, read from each connected firewall through
Panorama, its operational state: the real interface addresses, the routing
table, BGP peers, IPsec tunnel state, HA state and the GlobalProtect users
connected right now. It is all read over the Panorama XML API, read-only,
and drawn on the same map as the devices Plexus discovers itself and any
Meraki organizations, Cato accounts, Cisco FMCs, AWS accounts, Azure
subscriptions and GCP projects. It is covered by the same search box, Path
Mode and IPAM page, and is included in the HTML export.

A Panorama is handled like a Cisco FMC: it is added, collected and deleted
from the same **Sources** dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage Panoramas and credentials
- API: `/api/meraki/*` with `provider: "panorama"` (see the
  [API reference](#api-reference))

Only Panorama-managed firewalls are read: a standalone firewall is not, nor
anything configured on a managed firewall itself rather than pushed from
Panorama.

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without a Panorama.** Click **Load Sample**, then **Palo Alto
   Panorama**. A demo Panorama is added to the map: a PA-5220 HA pair at HQ
   with a GlobalProtect gateway and IPsec tunnels to a branch and to a
   partner, a PA-440 branch firewall, and a VM-Series in AWS. Load the
   **AWS** sample as well to see the VM-Series joined to its instance.
   Delete the demo Panorama from the same dialog when you are done.
3. **Add your Panorama.** Click **Add Source**, then **Palo Alto Panorama**,
   and enter a name, the Panorama address and either an API key or a
   username and its password. Under **Data to collect**, untick what you do
   not need (see [What is collected](#what-is-collected)).
4. **Check the login.** Click **Test Login**. It signs in to Panorama and
   lists the device groups it has.
5. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection until you run another.

### Panorama address, device group and credentials

- **Panorama address**: `https://` and the host (and port) of Panorama,
  nothing else. A bare host is taken as https; `http` and a URL with a path
  are refused, and redirects are not followed, so the credentials cannot be
  sent elsewhere. Untick **Verify the Panorama certificate** for a Panorama
  that still has its self-signed certificate.
- **Device group**: blank reads every device group; a name (in any letter
  case) reads only the firewalls of that device group and of the device
  groups below it. The objects and rules of the ancestors and of shared are
  read all the same, since those firewalls inherit them.
- **API key, or username and password**: leave **Username** blank and paste
  an API key (generated on Panorama for a dedicated admin), or give the
  admin's username and its password: Plexus then generates an API key at the
  start of each collection, keeps it in memory for that collection only, and
  generates a new one if Panorama answers that it expired. The key or the
  password is stored encrypted and never returned by the API or shown in
  the UI again. The key is sent in the `X-PAN-KEY` header, never in a URL,
  and the password in the body of a POST, so neither lands in an access log.
- **Permissions**: an admin with a role that allows the **XML API**
  (*Configuration* and *Operational Requests*) and read-only access to the
  device groups and templates is enough. A custom Panorama admin role with
  the web UI read-only and, under XML API, only *Configuration* and
  *Operational Requests* enabled is the narrowest. Plexus only sends
  `type=op` `show` commands and `type=config` `action=show` requests: it
  never commits, pushes or edits anything.
- **Request budget**: requests are sent one at a time, about four a second,
  so a collection does not load Panorama's management plane. A full read
  takes a few requests per device group and template and seven per
  connected firewall, so a large Panorama takes minutes; untick the parts
  you do not need to shorten a collection.

## On the map

Panorama data appears when the group filter is **All groups**.

| On the map | What it is |
|---|---|
| **Palo Alto Panorama** box | Panorama itself, as one node |
| Firewall box | One standalone firewall, named by its hostname |
| HA pair box | Both members of an HA pair, the active member first, joined by an **HA** link (a stack link carrying each member's HA state; its status is `failed` when a member is offline, suspended or non-functional) |
| Firewall (firewall icon) | A firewall, online when it is connected to Panorama, offline when it is not, amber when its HA state is suspended or non-functional |
| WAN triangle | Each outside interface of a firewall: one with a public address, the egress of the IPv4 default route, or a GlobalProtect gateway interface. It carries the interface's own address |
| **GlobalProtect users (N)** (star) | The users connected to a firewall's GlobalProtect gateways when the collection ran, as one node per firewall |
| VPN tunnel between firewalls | An IPsec tunnel between two firewalls of the Panorama (the active member for an HA pair), drawn like any VPN tunnel (purple dashed, red when either end reports its SA down) |
| **IPsec** link to a peer | An IPsec tunnel to a peer Panorama does not manage, drawn like a non-Meraki IPsec peer (dotted) to a node in the **Site-to-site VPN peers** box, shared by every tunnel to that address |
| Dotted grey link | **Managed by Panorama**: Panorama and each firewall on the map. It carries no traffic: Path Mode and the tidy-tree layout ignore it |

A firewall's IPsec peer is another managed firewall when the peer address of
its IKE gateway is an interface or IKE address of that firewall. **Only
firewalls whose hostname contains** limits the collection to matching
firewalls (an HA member brings its peer along: a pair is one box); the
others are still listed in the Panorama node's **Managed firewalls** table.

GlobalProtect users are one node per firewall, not one node per user: the
users are listed in the node's details (user, domain, virtual IP, public IP,
computer, client, app version, tunnel type, login time, lifetime) and found
by the search box.

### How a firewall joins the rest of the map

- **Inventory hosts.** A firewall whose serial number, management address
  or an interface address is that of a Plexus inventory host becomes that
  host's node, with both its SNMP/SSH data and its Panorama data.
- **Cloud instances.** A VM-Series in a VPC has no public address of its
  own: AWS knows it by the elastic IP mapped to its interface. It is matched
  to its instance by the private address of an outside interface, under the
  same conditions as an FTDv: the instance forwards traffic
  (source/destination check off), exactly one instance and one outside
  interface have the address, and the model is a VM-Series (`PA-VM...`).
  The firewall then stays in its own box and gains the instance's link to
  its VPC. See [aws-topology.md](aws-topology.md).
- **Public addresses.** A firewall whose outside interface has a public
  address is the far end of any VPN another source configures with that
  address (an AWS customer gateway, a Meraki non-Meraki VPN peer).
- **VPN endpoint addresses.** The local addresses of a firewall's IKE
  gateways are its tunnel addresses: a VPN peer another source draws with
  one of them becomes the firewall, so the tunnel is drawn once between the
  two real ends.

Only public addresses join sources. The demo Panorama and the demo AWS
account use documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`),
which the map does not treat as public, so the VM-Series joins its instance
(by private address) but VPN ends stay apart.

### Device details

Click a firewall for its tabs:

- **Device**: name, status, model, software, serial, management address,
  whether it is connected to Panorama, device group and the chain of device
  groups above it, template stack and its templates, virtual systems, HA
  peer, state, peer state, mode and config sync, shared policy and template
  status, pending push, app and threat versions, uptime, and whether its
  state was read
- **Interfaces**: **Firewall interfaces** (Ethernet, sub-interface,
  aggregate, VLAN, loopback and tunnel interfaces, with type and mode, zone,
  virtual router, vsys, address and subnet, link state, tag, management
  profile, comment and whether the row comes from the firewall or from the
  template) and **Zones** (zone, vsys, type, interfaces). A template
  variable the stack does not resolve is listed as a note
- **VLANs**: **Connected subnets** (every interface subnet with interface,
  comment, zone and virtual router) and, on a box with a GlobalProtect
  gateway, its **VPN address pools**. The passive member of an
  active/passive HA pair forwards nothing, so its active peer owns the
  subnets and the passive member shows a note instead
- **Routing**: **Static routes** (name, destination network, interface,
  next hop or next virtual router, metric, virtual router, over a tunnel,
  path monitored), the **Routing table** the firewall reported (destination,
  next hop, interface, metric, protocol, flags, virtual router, age),
  **Virtual routers**, **BGP** (router ID, local AS, peer groups) and **BGP
  peers** with their state, and **OSPF** (areas, type, interfaces)
- **VPN**: **IKE gateways** (version, local interface and address, peer
  address, the managed firewall at the far end), **IPsec tunnels** (tunnel
  interface, IKE gateway, peer, proxy IDs, crypto profile, state, tunnel
  monitor) and **GlobalProtect gateways** (vsys, interface and address,
  tunnel interface, address pools, connected users)
- **Firewall**: **Security policy** (device group chain, rule counts,
  disabled rules, rules that target other firewalls, the intrazone and
  interzone default actions and where they are set), **Security rules** and
  **NAT rules** in the order the firewall applies them

The rule tables show the effective order for the firewall: the shared
pre-rules, the pre-rules of each ancestor device group from the top down,
those of its own device group, then (not read: they are configured on the
firewall itself) its local rules, then its own device group's post-rules,
the ancestors' from the bottom up, the shared post-rules, and last the
**intrazone-default** and **interzone-default** rules, with an override of
the nearest device group winning. A rule whose **Target** leaves the
firewall (or all its virtual systems) out is not shown on it; a disabled
rule is shown with **Enabled** *No*. Addresses and services are resolved
through the device group hierarchy, then shared.

Click the users node for the connected users. Click the Panorama node for
its version, model and serial and the **Managed firewalls**, **High
availability pairs**, **Device groups** (parent, firewalls, rule and object
counts), **Templates**, **Template stacks** (templates in order, firewalls,
variables), **Address objects**, **Address groups** (static members or the
dynamic filter), **Services**, **Service groups** and **Pending push** (the
firewalls whose shared policy or template is out of sync) tables. Click a
link for what it is: the HA state of each member, the tunnels of a VPN
link.

### Search and Path Mode

The toolbar search covers everything collected: firewall names, serials,
addresses, object and group names, routes, security and NAT rules, tunnels
and peers, gateway and pool names, and connected users by name, virtual IP
or public IP.

In **Path Mode** a firewall, one of its connected subnets, one of its
static route destinations or one of its GlobalProtect address pools can be
picked like a Meraki site or VLAN; typing an address picks the subnet that
contains it. Paths follow links: the HA link, the tunnels and the links
other sources share with the firewall. The link between a firewall and
Panorama is never part of a path.

Between two subnets or addresses the path is also traced hop by hop through
each firewall (see [path-trace.md](path-trace.md)): destination NAT, the
security policy evaluated against the zones of the ingress and egress
interfaces, the route lookup on the routing table the firewall reported (or
its configured static routes when the state was not read), source NAT, and
the IPsec tunnel a route sends the flow into, with its state. The security
rules come in the effective order above, the two default rules last. A rule
also matches on what Plexus cannot evaluate on addresses and ports alone: a
specific application (App-ID), `application-default` with one, a user, a URL
category, a HIP profile, an FQDN or a dynamic address group. Such a rule is
kept, and a flow it matches is *unknown* rather than allowed or denied. The
rules configured on the firewall itself are not read and are listed under
**Not checked**. PAN-OS matches a security rule on the destination before
NAT and the zone after it; the trace applies the rules after destination
NAT, so a rule whose destination is the original address of a destination
NAT rule matches its translated address too. When two virtual systems of a
firewall have a zone of the same name, the zones are told apart as
`vsys1/trust` and `vsys2/trust`.

### IPAM

The connected subnets, static route destinations and GlobalProtect address
pools also appear on the **IPAM** page as subnets of source **topology**
(provider Palo Alto Panorama), with the firewalls that hold them. The
address pools are owned ranges; connected subnets and routes are listed but,
like a Meraki static route, are not owned ranges, so the subnet a VM-Series
sits in does not count as an overlap with its own VPC.

## What is collected

Each **Data to collect** toggle of the entry turns one part on or off. `<P>`
is `/config/devices/entry[@name='localhost.localdomain']`.

| Data | XML API request | Option |
|---|---|---|
| Login and the Panorama version | `type=keygen` (POST, with a username), `type=version` | always |
| Panorama hostname | `<show><system><info/></system></show>` | always |
| Managed firewalls (serial, hostname, address, model, software, connected, HA state and peer, vsys, shared policy and template status) | `<show><devices><all/></devices></show>` | always (required) |
| Device groups, their firewalls and their hierarchy | `<show><devicegroups/></show>`, `/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry` | always |
| Templates, template stacks, the stacks' template order, variables and overrides | `<show><templates/></show>`, `<show><template-stack/></show>`, `<P>/template-stack` | always |
| Address, address group, service, service group and application group objects | `/config/shared/<kind>`, `<P>/device-group/entry[@name='X']/<kind>` | always |
| Security rules and the default security rules | `.../pre-rulebase/security/rules`, `.../post-rulebase/security/rules`, `.../post-rulebase/default-security-rules/rules` of shared and each device group in use | Security policies |
| NAT rules | `.../pre-rulebase/nat/rules`, `.../post-rulebase/nat/rules` of shared and each device group in use | NAT |
| Interfaces, zones and virtual systems, template variables | `<P>/template/entry[@name='T']/config/devices/entry[@name='localhost.localdomain']/network/interface`, `.../vsys`, `<P>/template/entry[@name='T']/variable` | Interfaces |
| Virtual routers, static routes, BGP, OSPF | `.../network/virtual-router` of each template | Routing |
| IKE gateways and IPsec tunnels | `.../network/ike/gateway`, `.../network/tunnel/ipsec` of each template | VPN |
| GlobalProtect gateways | `.../network/tunnel/global-protect-gateway` (and the `vsys` read above) of each template | GlobalProtect |
| Interface addresses, zones and link state of each firewall | `<show><interface>all</interface></show>` with `target=<serial>` | Device state |
| Routing table and BGP peers of each firewall | `<show><routing><route/></routing></show>`, `<show><routing><protocol><bgp><peer/></bgp></protocol></routing></show>` with `target=<serial>` | Device state and Routing |
| IPsec tunnel state of each firewall | `<show><vpn><ipsec-sa/></vpn></show>`, `<show><vpn><flow/></vpn></show>` with `target=<serial>` | Device state and VPN |
| HA state of each firewall | `<show><high-availability><state/></high-availability></show>` with `target=<serial>` | Device state |
| Connected GlobalProtect users | `<show><global-protect-gateway><current-user/></global-protect-gateway></show>` with `target=<serial>` | Device state and GlobalProtect |

Every configuration request is `type=config&action=show`: the running
configuration Panorama last committed. A template stack's own settings win
over its templates, and its templates over each other in the stack's order;
`$variables` are resolved from the stack's variables, then the templates'.
What a firewall reports wins over its template: its interface addresses
(an address learned by DHCP, the passive member's addresses) and zones. A
rate-limit or server error is retried after a pause. The progress of a
collection names the part being read (`panorama login`, `panorama devices`,
`panorama device groups`, `panorama templates`, `panorama objects`,
`panorama policies`, `panorama nat`, `panorama network`, `panorama vpn`,
`panorama global protect`, `panorama device state`).

**HA pairs are read once.** Both members of a pair share one template
stack, so their configuration is read once; their state is read from both.

**Failures.** The login and the firewall list are required. Everything else
is best-effort: if a request fails, the collection finishes as **partial**,
the map is still built, and the failure with Panorama's own message is
listed under **Report** in the HTML map. A configuration node that does not
exist (a template with no IPsec tunnels) is no failure. A firewall that is
not connected to Panorama is not asked for its state: its details say so,
and its template configuration stands in (its configured static routes
instead of its routing table). One command a firewall refuses is reported
and the others are still read.

**Unsupported.** A firewall that runs the **Advanced Routing Engine**
answers the legacy routing commands with an error: that is not a failure,
it is listed under **Unsupported** on the Panorama node (and in the
snapshot's `collection.unsupported`), and its configured static routes stand
in for its routing table. The `advanced-routing` commands and logical
routers are not read.

**Caps.** The Panorama node lists at most 2000 address objects and services
and 500 groups; up to 5000 connected users are listed per firewall.

**Not collected**: the rules and objects configured on a firewall itself,
security profile contents (antivirus, vulnerability, URL filtering,
WildFire, file blocking), App-ID port semantics (which ports
`application-default` stands for), User-ID mappings and the members of
dynamic address groups, decryption, authentication, QoS, PBF and DoS
policies, the Advanced Routing Engine, SD-WAN, Prisma Access and Strata
Cloud Manager, log forwarding, licenses and the candidate configuration.

**Secrets.** Every payload goes through the secret filter before anything
is stored: IKE pre-shared keys, BGP and OSPF authentication keys, password
hashes, SNMP communities, secrets and passwords are dropped. The API key
(given or generated) is never stored and never logged.

**XML.** Panorama is the operator-configured management server, so its
answers are parsed with the standard library's XML parser; an answer that
declares a document type (and so could declare entities) is refused.

## API reference

A Panorama uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for Palo Alto Panorama |
|---|---|---|
| `GET` | `/api/meraki/orgs` | Each entry has `provider` (`meraki`, `cato`, `fmc` or `panorama`); `panorama_default_options` lists the Panorama collection options |
| `POST` | `/api/meraki/orgs` | `{"name", "provider": "panorama", "base_url": "https://<panorama>", "org_id": "<device group or blank>", "api_key": "<API key, or the password of options.username>", "options": {"username"?, "verify_tls"?, "device_name_contains"?, "include_interfaces"?, "include_routing"?, "include_security_policies"?, "include_nat"?, "include_vpn"?, "include_global_protect"?, "include_device_state"?, "inventory_enrich"?}}` (admin). `api_key` is the API key when `options.username` is blank, else that admin's password |
| `POST` | `/api/meraki/orgs/{id}/validate` | Signs in to Panorama; `organizations` lists its device groups (admin) |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id`. Progress phases: `panorama login`, `panorama devices`, `panorama device groups`, `panorama templates`, `panorama objects`, `panorama policies`, `panorama nat`, `panorama network`, `panorama vpn`, `panorama global protect`, `panorama device state`, `collected` |
| `POST` | `/api/meraki/sample?provider=panorama` | Add / refresh the demo Panorama ("Sample Palo Alto Panorama (demo data)") |
| `GET` | `/api/topology` | Panorama nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `panorama`; the Panorama links have `protocol: "management"`, HA links `stack`, tunnels between firewalls `vpn`, tunnels to other peers `vpn-ipsec` |
| `GET` | `/api/meraki/subnets` | Includes every firewall's connected subnets (`kind: "connected"`), static route destinations (`kind: "static"`) and GlobalProtect address pools (`kind: "pool"`), with `provider: "panorama"` |
| `GET` | `/api/topology/path` | Traces through each firewall's security policy, NAT rules, routes and IPsec tunnels; see [path-trace.md](path-trace.md) |
