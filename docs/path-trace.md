# Path trace - Usage Guide

**Path Mode** on the Topology page (**Network → Topology**) draws how the
devices, sites and subnets you pick are joined on the map. Between two
subnets or IP addresses it now also traces the flow hop by hop. At every
device on the way it lists, in the order the device applies them, the
policies, ACLs, security groups, NAT rules and route lookups the flow hits.
It does this for the request and for the replies, says whether routing is
asymmetric, and lets you reverse the source and the destination.

The trace reads what the sources on the map collected: Meraki
organizations, Cisco FMCs, Palo Alto Panoramas, Cato accounts, Appgate SDP
collectives, AWS accounts, Azure subscriptions, the routes Plexus captured from inventory devices
over SSH and, for inventory devices whose platform Plexus reads (Cisco IOS, IOS-XE, NX-OS, IOS-XR,
ASA and FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Aruba AOS-CX and AOS-Switch), the access
lists, policies, NAT rules, addresses and static routes of their latest configuration backup. It never
reports as allowed what it could not look at: what a source does not
collect is listed at that hop, and is *unknown* when the flow depends on
it.

- Permission: the `topology` feature
- API: `GET /api/topology/path`, see [API reference](#api-reference)
- To check many source networks against one destination at once, see the
  [Reachability sweep](#reachability-sweep)

## Picking the ends

Turn on **Path Mode** in the toolbar, then pick up to six ends. Every pair of
picks is a leg of the path.

- **Subnets and addresses are traced.** Choose a subnet in **Add a subnet or
  IP address**, or type an IP address or a network and press Enter. The most
  specific collected subnet that holds it is used; when several sites have
  it, pick the one you mean from the list. A typed address is kept as the
  end, so rules and security groups are matched against that address
  rather than the whole subnet. The private address of a virtual machine in
  an AWS VPC, an Azure VNet or a GCP network counts as a network of its own,
  so typing it picks that network even when a Meraki vMX site or a Cato
  site declares the same range.
- **Inventory devices are in the list.** The VLAN interfaces (SVIs, named
  `VLAN <id> <description>`), connected networks and static routes of every
  inventory device on the map are listed with the device's inventory group
  as the site, from its latest route capture and configuration backup. A
  network both an inventory device and another source hold (a transit
  network between a switch and a firewall) is in the list twice; pick the
  device you mean.
- **Devices and sites draw the path only.** A device clicked on the map or a
  site typed into **Add a site** has no address to trace. A leg between a
  subnet and a device says which end to add with the subnet box instead.
  The exception is a remote user (a person icon): it has one address, so a
  click picks it with that address and its legs are traced.
- A subnet stands for the device that owns it: the site's appliance (the
  primary of a Meraki warm-spare pair, which holds the site's AutoVPN
  tunnels), the L3 switch holding its SVI, the FTD it is connected to, the
  VPC or VNet router, the Cato Socket or the VPN peer it sits behind. A
  device that two
  sources know, such as an FTDv that is also an AWS instance, is one node on
  the map, and the subnets of both can be picked.
- A remote user connected with the Cato Client or the Appgate Client owns
  its own address as a `/32` in the list, so typing that address, or
  clicking the user on the map, starts the trace at the user rather than at
  a wider range another source keeps for the whole client pool (a non-Meraki
  VPN peer of a Meraki site that covers it, behind which nothing is
  collected).
- The first of two picks is the source of the request.

## The Traffic box

The **Traffic** box appears next to the subnet box as soon as a leg has two
subnet or address ends. It takes `tcp/443`, `udp/53`, `443` (TCP), `icmp`,
or nothing for any traffic. It applies to every traced leg. With nothing
typed, a rule that opens only some ports gives *allowed in part*, and the
trace says which ports those are (see [Which ports are
allowed](#which-ports-are-allowed)). A text the box cannot read is outlined
in red and the legs are not traced until it is fixed.

## Reading a trace

Under each traced leg, the hops of the request on one line, for example
`Branch 01 MX → Hub 01 MX → Hub 02 MX ✕ (3 hops)`, with the mark of
any hop that is not ok, in place of the path drawn over the links; then:

1. **The verdict** of the direction shown: **Allowed**, **Blocked**,
   **No path**, **Allowed in part** or **Check incomplete**, the traffic,
   and a sentence that names the first item that decided it (for an allowed
   flow, *Every hop allows it* and the hops), ending with what was not
   checked. *Blocked* means a rule denies the flow (a firewall rule, ACL,
   security group or NAT rule). *No path* means nothing denies it but the
   flow cannot get there: a device has no route to the destination, the
   route is a blackhole or loops, or every link or tunnel the route points
   at is down, as its source reports (*The IPsec tunnel between Branch 01
   MX and Partner is down: Meraki reports it unreachable*). A device that
   sends a private destination down its default route to the internet says
   so (*No other route covers 10.9.0.0/24, a private address*) and the
   check stays incomplete, since the internet path is not on the map.
2. **Reverse: trace B → A as a new connection** swaps the ends and shows the
   same traffic opened from the other side. Click it again to go back. The
   verdict of the other direction is always shown on the muted line below,
   so both are visible without clicking.
3. **Ports end to end**: the ports of the traffic asked about that every
   rule set on the way lets through, for example *allowed tcp 443 · udp 53;
   in part tcp 80*. See [Which ports are allowed](#which-ports-are-allowed).
4. **Request** and **Replies**: the hops in order, each as
   `3. Hub 01 MX · Hub 01 · in AutoVPN from Branch 01 → out VLAN 20`, with
   the items the device applied under it. Each item has a mark (✓ ok,
   ✕ blocked, ◐ partly, ? unknown, i for information), the kind of step
   (Policy, ACL, Security group, NAT, Route, Link, Note), the rule set or
   table, and what was found, naming the matching rule. An item that states
   the decision of a rule set ends with **Ports:** and the ports that rule
   set lets through. Every hop and item is listed; nothing is folded away.
   The replies are numbered from the destination back. A direction whose
   ports differ from the end-to-end line shows its own after its verdict.
5. **Asymmetric routing**, which compares the two lists above it: *no* when
   the replies take the same hops back; *yes* in amber, spelling out the way
   the request passed and the way the replies pass, then where they part
   and which stateful firewall sees only one of them; *unknown* when a walk
   could not be completed. See [Replies and asymmetry](#replies-and-asymmetry).
6. Notes about the data, such as a snapshot collected before this feature,
   are listed last.

A leg that cannot be placed says **No trace** and why, for example when an
address is in no collected subnet.

On the map, a traced leg is highlighted over the hops of the request of the
direction shown, which may differ from the shortest path over the links.
Legs that are not traced keep the drawn path.

## How a hop is evaluated

At each device the trace takes these steps in this order:

1. **Destination NAT.** A 1:1 NAT, port forward or static NAT whose public
   address matches rewrites the destination for the rest of the walk. A rule
   that does not allow the source blocks the flow there.
2. **Ingress policies.** The rule sets the device applies to traffic coming
   in on that kind of interface: from the LAN, from the WAN or from a tunnel.
3. **Route lookup.** The longest matching prefix wins. On a tie a connected
   route beats a static route, then policy-based, then VPN and dynamic
   routes, then a default route; then the lower metric. A blackhole route or
   no route at all blocks the flow.
4. **Egress policies.** The rule sets the device applies to traffic leaving
   towards the LAN, over a tunnel or on the WAN. They see the real
   addresses. FTD access control matches the security zones of the ingress
   interface and of the egress interface the route chose.
5. **Source NAT.** The first matching rule rewrites the source, for example
   to the address of the WAN uplink.
6. **Policy-based VPN.** A site-to-site VPN whose protected networks cover
   the source, as NAT left it, and the destination sends the flow to its
   peer. A tunnel that is down blocks it. A flow the selectors do not match
   follows the route, out to the internet for a default route.
7. **Link.** The link on the map to the next device. A link that is down
   blocks the flow; a next hop with no link on the map is unknown.

In a rule set the first matching rule decides. When no rule matches, the
set's default applies. A rule that also matches on something Plexus cannot
evaluate, such as an application, an FQDN or a user group, gives *unknown*.

### Which rule sets apply

The interface the flow arrives on decides the ingress rule sets: a VLAN, LAN,
SVI or routed interface is the LAN, an uplink is the WAN, a tunnel or a VPN
is a tunnel. On a Meraki appliance the Layer 3 firewall rules apply to
traffic from the LAN, the inbound firewall rules to traffic from the WAN,
and the site-to-site VPN firewall rules to traffic leaving over AutoVPN or a
non-Meraki tunnel. Rule sets a device applies to all traffic are matched
after the route lookup, when both interfaces are known: FTD prefilter and
access control rules, which match the security zones of both, and Meraki
switch ACLs. A prefilter rule that fastpaths the flow skips the access
control policy; one that analyzes it hands it on.

A rule matches on protocol, source and destination, ports and zones. A rule
that covers only part of the traffic asked about, such as a port range when
any traffic is asked, does not decide on its own: when such rules allow part
of what the deciding rule denies, or the other way round, the item is
*allowed in part*. A monitor rule is listed and the next rule decides. When
the rules were cut at collection (the first 1000 FTD rules) and none
matches, the item is *unknown*.

### Which ports are allowed

Besides the verdict, every rule set the flow meets says exactly which ports
of the traffic asked about it lets through, and the trace combines them
into the ports allowed end to end. The set covers the protocols asked about
(tcp, udp and icmp when nothing was typed in the Traffic box, else the one
typed) and the port typed, or every port. For each protocol it lists:

- **allowed**: the ports the rule set lets through for every address asked
  about, as `80, 443, 8000-8080`, or `any` for every port; icmp has no
  ports and is listed by name when it is allowed
- **in part**: ports a rule opens or closes for only some of the addresses
  asked about, as when a subnet is traced and a rule names part of it
- **not decided**: ports the rule set cannot decide: a matching rule that
  also matches on something Plexus cannot evaluate, rules cut at
  collection, or a default action that is not known

Ports listed nowhere are denied. The set is worked out the way the device
evaluates the rules: the first rule that matches a port decides it, so a
deny of tcp 22 ahead of an allow of tcp any leaves every tcp port but 22
allowed, and a rule whose ports cannot be read (a service name) leaves the
ports it may cover *in part*. AWS security groups, which only allow, give
the union of their rules; a group named but not collected makes the rest
*not decided*. In the replies, stateless rule sets (a switch ACL) are
matched on the reply's source port, which is the service port, so their
ports compare with the request's; an AWS network ACL matches the reply's
destination port, the ephemeral range, so its reply step lists no ports.

**Ports end to end** is the worst of every item of both directions, port by
port: an item with no port set counts by its status (a rule set that was
not collected makes every port *not decided*, a missing route denies every
port). A trace that is *Allowed* lists everything asked about; one that is
*Allowed in part* says exactly what passes.

### Where the flow goes next

The route lookup uses the routes of the ingress interface's VRF or virtual
router. The route then names the next device:

- an AutoVPN route goes to the appliance of that site, over a tunnel that is
  up; when there is no direct one, through hubs, each listed as a hop that
  forwards it
- a route to a non-Meraki peer, a Cato PoP or the Cato Cloud goes to that
  node, over the link between them
- a next-hop address goes to the device on the map that has that address on
  an interface: a Meraki VLAN or uplink, an FTD interface, an inventory
  host's address, alias, SVI or HSRP / VRRP / GLBP address (both members of
  a pair hold the virtual address; the one linked to the sender is taken)
- a next-hop address inside a collected VPC or VNet subnet, or a connected
  subnet that is one, goes to that VPC or VNet, where the cloud's own route
  tables take over. A device that is also an instance there (a Meraki vMX,
  whose one interface is its uplink, an FTDv) looks in its own VPC or VNet
  first, so a range that several VPCs use, as every default VPC does, still
  leads to the right one. The networks a Meraki site exports into AutoVPN
  that are not its VLANs or static routes (a vMX's VPC ranges) are routed by
  its uplink, ahead of the same range advertised by another site, so two vMXs
  in one VPC do not hand the flow back and forth
- a default route out of a WAN uplink goes to the Internet

A connected route that holds the destination delivers the flow there. A
next hop that is none of the above is *unknown*, and the trace stops at that
hop after its egress rules and NAT. A device reached twice with the same
destination is a routing loop and blocks the flow; a trace stops after 32
hops.

### NAT

Meraki 1:1 NAT, port forwarding and 1:Many NAT apply to traffic arriving on
the uplink they name. A source the rule does not allow is blocked there. The
uplink address hides LAN sources only on an MX in routed mode and only when
the flow leaves on the WAN; an MX in passthrough or VPN concentrator mode (a
vMX that bridges its VPC) does not translate. Only the collected deployment
mode (the network's appliance settings) says which: when it was not
collected, nothing is assumed, and a flow leaving on the WAN gets an unknown
NAT item there (**Uplink NAT (deployment mode)**), since the source the next
hop sees is not known. VPN subnet translation applies only when the flow
leaves over AutoVPN. FTD NAT rules match
their source and destination interfaces by name or by security zone; a
static auto NAT rule translates the source on the way out and the mapped
address back on the way in. A rule that translates to the same networks is
listed as identity NAT. A Palo Alto firewall's NAT rules match their source
zones and destination zone (or interface), pre-rules before post-rules; an
interface-address source NAT takes the egress interface's address, a
bi-directional static NAT also translates the mapped address back on the
way in, and a rule without translation is an exemption. PAN-OS matches a
security rule on the destination address before NAT but the zone after it:
since the trace applies the rules after destination NAT, a rule whose
destination is the original address of a destination NAT rule also matches
the translated address.

NAT is applied before the policy-based VPN selectors are matched, as on an
ASA or FTD: the selectors see the translated source. A flow that the
interface address hides no longer matches the protected networks and leaves
unencrypted, which is why a flow to a network behind the VPN needs an
identity NAT rule, a NAT exemption, ahead of the interface PAT. When NAT
moves the source out of the protected networks, the hop says so.

### What is not collected

What a device applies and Plexus does not collect is listed at that hop.
It changes the verdict only when the flow depends on it:

- a rule set the device would consult for this flow is *unknown*: the Layer
  3 rules for traffic from the LAN, the inbound rules or the NAT rules for
  traffic from the WAN, FTD prefilter or access control rules, Palo Alto
  security rules, a switch ACL, the access lists of an inventory device
  without a configuration backup,
  Cato WAN firewall rules for a destination a site range or a user address
  covers and internet firewall rules for any other
- routes that are not collected, such as routes learned over BGP or OSPF,
  make the route lookup *unknown* when it finds no route or only a default
  route, unless a site-to-site VPN then takes the flow: a default route and
  a tunnel whose protected networks match is how a policy-based VPN is built
- anything else, such as Layer 7 rules, group policies or the rules
  configured locally on a Panorama-managed firewall, is a note. The
  summary of each direction ends with **Not checked:** and those names, so
  you can see what an *allowed* verdict rests on

### Ends, clouds and the internet

An end is placed by the node the page passes. Without one, the most specific
collected subnet that holds the address is used (the private address of a
cloud virtual machine is one, as is the address of a remote user), then a
device that has the address on an interface, then a device whose 1:1 or
static NAT publishes it. An address in several places at the same length is
not traced. An address
that is in no collected subnet but is public starts or ends at the Internet:
a flow from the internet reaches the destination's device on its uplink,
where its NAT and inbound rules decide. Documentation ranges such as
198.51.100.0/24 count as public here, since the samples use them that way.

## What each source contributes

| Source | Traced | Not collected |
|---|---|---|
| Meraki | Layer 3 firewall rules, inbound firewall rules, site-to-site VPN firewall rules, 1:1 NAT, port forwarding, 1:Many NAT, VPN subnet translation, static and AutoVPN routes, routes to non-Meraki VPN peers, switch ACLs and SVI routes | Layer 7 firewall rules, group policies |
| Cisco FMC | Prefilter rules, access control rules, NAT rules, connected and static routes, site-to-site VPN protected networks | Routes learned by BGP, OSPF or EIGRP, access control rules beyond the first 1000 |
| Palo Alto Panorama | Security rules in the order each firewall applies them (shared, device group and ancestors, pre then post, the intrazone and interzone default rules) with their zones, addresses and services, NAT rules, connected routes, the firewall's routing table (static, BGP, OSPF) or else its configured static routes, IPsec tunnels and their state | Rules configured on the firewall itself, App-ID (a rule with applications or `application-default` is unknown when it matches), users, URL categories, FQDNs and dynamic address groups, routes learned by BGP or OSPF when the routing table was not read; see [panorama-topology.md](panorama-topology.md#search-and-path-mode) |
| Cato | The hops: Socket, PoP, Cato Cloud, PoP, Socket; the WAN firewall rules for a destination a site's range or a user's address covers (WAN traffic) and the internet firewall rules for any other destination, a private one included (internet traffic), applied once at the PoP the flow enters by | Routes learned by BGP; rule objects Plexus cannot turn into addresses (users groups, applications, categories, countries) make a rule that matches *unknown*; see [cato-topology.md](cato-topology.md#search-and-path-mode) |
| Appgate SDP | The hops: user, Gateway. Each Gateway applies the **Entitlements** of its site (sources the tunnel addresses of the connected users that hold each one, default deny) and its **Allowed destinations**, routes each user's tunnel address back over the tunnel, and translates the client pool when the site uses SNAT; a user routes what its entitlements cover to the Gateway that grants them and has no other route (split tunnel) unless a site is its default gateway | Entitlement hosts that are names (`dns://`, `aws://`...), HTTP method rules and, without the per-user access details, which users hold an entitlement; see [appgate-topology.md](appgate-topology.md#search-and-path-mode) |
| Inventory devices | The routes of the latest SSH route table capture, with every VRF's table where the platform lists them (Cisco IOS, IOS-XE, NX-OS, IOS-XR, ASA and FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Aruba AOS-CX and AOS-Switch). From the latest successful [configuration backup](#inventory-devices-and-configuration-backups) of those platforms: the access lists applied to each interface, in and out (switches and routers, Junos filters), the stateful rule sets of a firewall (ASA / FTD access groups and security levels, SRX security policies, FortiGate firewall policies), their NAT rules, the interface addresses, secondaries, zones, VRFs and HSRP / VRRP / GLBP / VARP / active-gateway addresses, and the connected and static routes of the VRFs the capture lacks | Access lists of a device without a successful configuration backup, or of a platform Plexus does not read (PAN-OS: trace it through a Panorama); objects, object groups, address books, applications, services and port names the configuration does not define, FQDN, geography and wildcard objects, wildcard masks that are not a prefix, time ranges and schedules, DSCP, TCP flag and ICMP type matches, users, identities and security groups, negated matches (a rule that uses one is *unknown* when it matches); IPv6 access lists and policies, port and MAC access lists, VLAN access maps, classifier and traffic policies, policy-based routes, zone-based firewall policies, inspection and application services, VPN tunnels, other VDOMs and contexts; without a route capture, the routes learned by the routing protocols the configuration runs |
| AWS | Route tables, transit gateways, VPC peerings, network ACLs, security groups, as in [the AWS check of a path](aws-topology.md#the-aws-check-of-a-path) | See that section |
| Azure | Effective routes and network security groups, as in [the Azure check of a path](azure-topology.md#the-azure-check-of-a-path) | See that section |
| GCP | Subnet, peering, static and dynamic routes, VPN tunnels, Cloud NAT and VPC firewall rules, as in [the GCP check of a path](gcp-topology.md#the-gcp-check-of-a-path) | See that section |

Whether what is not collected makes a hop *unknown* or is a note is
explained under [What is not collected](#what-is-not-collected). A Cato
trace between sites is decided by the WAN firewall at the PoP the flow
enters by, and is *unknown* only where a rule that names something Plexus
cannot evaluate (a users group, an application) matches.

### Inventory devices and configuration backups

The access lists, policies and NAT rules of an inventory device come from
**Config Backups**: Plexus reads the newest successful backup of the device's
running configuration, so a device needs a backup policy that has run at
least once. A new backup is read at the next trace. The device's type
(Inventory, *Device type*) picks the reader: Cisco IOS and IOS-XE, NX-OS,
IOS-XR, ASA and FTD, Arista EOS, Juniper Junos (a `display set` backup),
Fortinet FortiOS, Aruba AOS-CX and AOS-Switch (HP ProCurve). A device of
another type (Palo Alto PAN-OS, which Plexus traces through a
[Panorama](panorama-topology.md) instead) or without a backup reports
*Access lists are not collected* as *unknown* where a flow crosses it.

Every reader gives the interfaces with their addresses, secondaries, VRFs,
state and virtual addresses (HSRP, VRRP, GLBP, VARP, an AOS-CX active
gateway), which are addresses of the device. The routes are those of the
route capture; the connected and static routes of a VRF the capture holds no
table for come from the configuration, and so do all of them when there is
no capture, the routes the routing protocols learn then being *not
collected*. What the configuration uses and Plexus does not read (IPv6, MAC
and port access lists, VLAN access maps, classifier and traffic policies,
policy-based routes, zone-based firewall policies, inspection, VPN tunnels,
other VDOMs and contexts...) is listed as not collected. An entry Plexus
cannot turn into addresses, protocols and ports (an object, group, address
book, application or port name the configuration does not define, an FQDN,
geography or wildcard object, a wildcard mask that is not a prefix, a time
range or schedule, a DSCP, TCP flag or ICMP type match, a user, identity or
security group, a negated match) makes a flow it matches *unknown*, never
allowed.

**Switches and routers** (IOS, IOS-XE, NX-OS, IOS-XR, EOS, AOS-CX,
AOS-Switch, and the firewall filters of a Junos device). Each access list
binding (`ip access-group`, IOS-XR `ipv4 access-group ... ingress|egress`,
AOS-CX `apply access-list ip`, Junos `filter input|output`, a filter list
read as the one filter its filters make) is a rule set of its own, named
after the list, direction and interface (*ACL USERS-IN in on Vlan10*). It
applies only to traffic entering (`in`) or leaving (`out`) that interface,
and is matched after the route lookup with the other rule sets a device
applies to all traffic. Entries are matched in order and the first that
matches decides; when none does, the implicit deny at the end of every
access list denies the flow. A remark or comment is shown with its entry.
These rule sets are stateless, so the replies are matched again on the
interfaces they arrive on and leave by: an entry with `established` (Junos
`tcp-established`) matches TCP replies only and never lets in a request,
which opens the connection. A binding to an access list the configuration
does not define is *unknown* when a flow meets it; so is an IOS-XR entry
that sets a next hop, and a Junos term with an `except` address or
filter-based forwarding.

**Cisco ASA and FTD.** Interfaces are known by their `nameif`, in the rules,
the NAT rules and the route table alike. An access list bound with
`access-group ... in|out interface` decides for its interface, a global
access group is checked after the interface's own inbound list and before
the implicit deny, and an interface without an inbound list follows the
security levels: traffic may leave by an interface of a lower level, needs
`same-security-traffic permit` to reach the same level or go back out of the
interface it arrived on, and never passes through a management-only
interface. All these rule sets are stateful, so the replies of an allowed
request pass. Objects and object groups are resolved to addresses and ports;
a network group that holds an FQDN object matches any address, so a flow
against it is *unknown* rather than missed. NAT is read in ASA order (twice
NAT, object NAT, twice NAT after auto) and traced like FMC NAT; a rule whose
networks or services are not all addresses or single ports is listed as not
collected. On an FTD, the LINA access list is read with its `ifc` interfaces
as zones; a permit entry of a rule LINA labels other than *L4 RULE* is
*unknown*, since Snort may still decide it by application, URL or user. Not
collected: site-to-site and remote access VPN, inspection policies, multiple
context and transparent mode, policy-based routes, IPv6, EtherType and
WebVPN access lists, and the pre-8.3 `nat` / `global` / `static` syntax.

**Juniper SRX.** The security policies are one stateful rule set: the
zone-pair policies in their order, then the global policies, then the
default policy (deny unless `permit-all`), each entry matching the zones its
interfaces are in. Addresses resolve through the global and zone address
books (addresses, ranges, address sets), applications through the custom
applications, application sets and the common `junos-*` defaults. Source,
destination and static NAT are read in the order the SRX applies them.
Interfaces are the logical units (`ge-0/0/0.0`, `irb.100`), named as SNMP
and `show route` name them; a routing instance is a VRF. Not collected:
application services (IDP, UTM, AppFW) and policy-based IPsec tunnels,
security screens, IKE and IPsec VPNs, configuration groups, interface
ranges, logical systems, IPv6 and other-family filters, NAT rules whose
addresses or pools do not resolve. A backup in the hierarchical format gives
only a note: back the device up with `show configuration | display set`.

**Fortinet FortiGate.** The firewall policies, in order, are one stateful
rule set that ends in the implicit deny, each entry matching its source and
destination interfaces or zones (system zones and SD-WAN zones; `any` matches
all); a zone with `intrazone allow` adds an allow entry after them. Address
objects (subnets, ranges, interface subnets, groups) and services (custom
port ranges, including `dst:src` forms, service groups, and the predefined
services) are resolved; a VIP named as a destination matches its mapped
address, as the FortiGate matches after destination NAT. NAT: the virtual
IPs (with port forwarding), the policies with `nat enable` (to the egress
interface or an IP pool) and the central SNAT map when central NAT is on.
Only the root VDOM (or the first one) is read; the others are listed as not
collected, as are IPv6, proxy, multicast, local-in and DoS policies, IPsec
tunnels, policy routes, SD-WAN rules, load-balance and FQDN virtual IPs. In
NGFW policy-based mode the security policies are not read, so every policy
entry is *unknown*. An interface address learned by DHCP or PPPoE is not in
the configuration; the route capture supplies its network.

A device with no routing data, such as an external neighbor, is passed over
the shortest way on the map, each such hop with one unknown item, and the
asymmetry line then says *unknown*.

## Replies and asymmetry

The replies are traced from the destination back to the source, with the
addresses as the request left them. A device that translated the request
translates the reply back. A stateful firewall accepts the reply of a
request it allowed, so its rule sets show one information item in the
replies. Stateless rules, such as switch ACLs and AWS network ACLs, are
matched again with the reply's addresses and ports.

Routing is asymmetric when the replies do not pass the same devices as the
request. The line spells out both ways, then says where they part: the
replies go to one device instead of the one the request came by, they end
before a device the request passed, or they also pass a device the request
did not. A stateful firewall on one way only adds a warning, and the two
cases differ: one the replies pass but that never saw the request drops
them; one the request passed but the replies skip sees only half the
connection, so its connection state never completes and it can drop the
rest of the connection.

The replies to a source an MX hid behind its uplink address are addressed
to the MX itself: a vMX in NAT mode in a VPC gets them from the VPC,
translates them back and sends them over AutoVPN, which the trace follows
rather than ending at the VPC. A vMX in passthrough or VPN concentrator
mode (its collected deployment mode) does not translate, so the replies are
addressed to the branch host and the VPC routes them to the vMX by the route
table entry for the branch range (its target is the vMX's network
interface).

**Reverse** is a different question: it traces a new connection opened
from the destination to the source, with its own request and replies.

## Tracing inside the HTML export

The HTML export (`GET /api/topology/export.html`) carries the traces of the
path open in Path Mode when the export is made: both directions of every leg
between two subnets or addresses, for the traffic asked about.

It also carries the path tracer itself, so the file traces any other two
subnets or addresses, offline, with no server and no network access: the
Pyodide runtime (CPython 3.14 compiled to WebAssembly), the source of the
engine's Python modules (`MODULES` in
`netcontrol/integrations/pathtrace/offline.py`) and the trace inputs Plexus
gathered over the whole map (every group) at export time: the merged graph,
the latest snapshot of every source, the discovered AWS, Azure and GCP
resources and connections, the subnets and the forwarding block of every
inventory host. Each is gzip-compressed and base64-encoded in a
non-executing block of the file. In Path Mode the file shows a traffic box
(protocol and port) next to the subnet box; a leg between two subnets or
addresses is traced both ways the first time it is shown, by the same engine
and with the same result as the server would give for that data. The
embedded traces are used as they are while the traffic matches the
exported one. The runtime starts on the first trace, not when the file
opens: a few seconds, then each trace takes milliseconds. It runs in a web
worker made from the file's own blocks (a classic worker, else a module
worker, else on the page itself), and every file Pyodide asks for is
answered from the file, so nothing is fetched. The Report panel says
whether the file carries the tracer, its Pyodide version and when the data
was collected.

The file traces the data collected at export time; what changed later is
not in it. The runtime adds about 8.5 MB to the file, the engine's source
0.2 MB and the compressed inputs a few MB on a large map (inputs of about
30 MB compress to about 4 MB). `engine=0` exports without it, and an
export made when the runtime is not available (see
[Pyodide runtime](../deploy/DEPLOYMENT.md#pyodide-runtime-for-the-topology-html-export))
behaves as one without it: legs other than the exported ones show the path
over the links only.

The trace inputs are the complete collected configuration of every source
on the map (rule sets, NAT, routes, cloud security rules), most of which the
export's detail panels already show. Handle an export like the collected
data itself.

When Plexus serves the export, its Content-Security-Policy keeps `sandbox`
(no `allow-same-origin`) and a closed `connect-src`; with the tracer it adds
`blob:` and `'wasm-unsafe-eval'` to `script-src` and `worker-src blob:`
(`child-src blob:` for older engines). The saved file carries the same
additions in its own meta policy.

## Reachability sweep

Path Mode answers one question at a time. The **Reachability** tab of the
Topology page (**Network → Topology → Reachability**, `/topology/reachability`)
asks the same question of many networks at once: *which networks cannot
reach this destination with this traffic?* For example, which user VLANs
of every branch cannot reach a file server on `tcp/445`.

Enter a **Destination** (an IP address or network; the suggestions are the
collected subnets, and a picked suggestion stands for its whole subnet at its
owner) and the **Traffic** (the [Traffic box](#the-traffic-box) syntax:
`tcp/445`, `udp 53`, `icmp`, or empty for any traffic), narrow the source
networks with the filters below, and press **Run**. Plexus traces the flow
from every network the filters keep to the destination, exactly as a Path
Mode trace from that network would, and lists each one's verdict. The sweep
adds nothing of its own: every verdict, summary and deciding item is the
trace's.

### Source networks and filters

The source networks are the collected subnets of the whole map (every group),
the same list Path Mode picks subnets from, the VLANs and connected networks of
inventory devices included (their site is the device's inventory group). The filters combine: a network is
swept only when it passes all of them. In the list filters, terms are
comma-separated and any one matching is enough; a term wrapped in slashes,
such as `/^VLAN 1\d\d /`, is a regular expression; names and sites match
without regard to case.

| Filter | Query parameter | Keeps |
|---|---|---|
| Sources | `sources` | Networks of these sources (organizations, accounts, FMCs...), by id; the inventory devices are `-4` (AWS, Azure and GCP are `-1` to `-3`). Empty: every source. |
| Providers | `providers` | Networks of these providers: `meraki`, `cato`, `fmc`, `panorama`, `appgate`, `aws`, `azure`, `gcp`, `inventory` (inventory devices). Empty: every provider. |
| Kinds of network | `kinds` | Networks of these kinds. Default: `vlan,lan,svi,range,subnet,connected` (Meraki VLANs, single LANs, switch SVIs, Cato site ranges, cloud subnets and firewall interfaces: the networks endpoints live in). Also selectable: `static` (static routes), `vpn` (VPN local networks), `peer` (behind a non-Meraki VPN peer), `pool` (remote access VPN pools), `host` (cloud VM addresses), `user` (remote users). `all` selects every kind. |
| VLANs | `vlans` | Networks whose VLAN id is listed: ids and ranges, `100, 110-120` (0 to 4095). The id is read from the network name: `VLAN <id> ...` for a Meraki VLAN or an SVI, `... (VLAN <id>)` for a Cato range. A network with no VLAN id is left out when this filter is set. |
| Name contains | `name` | Networks whose name matches a term: `user, data, corp` or `/^VLAN 1\d\d /`. |
| Exclude | `exclude` | Drops networks whose name matches a term: `voice, guest, printer`. |
| Sites | `sites` | Networks whose site name matches a term. |
| Within | `within` | Networks inside one of these CIDRs: `10.0.0.0/8, 172.16.0.0/12`. |
| In VPN | `in_vpn` | `1`: networks the site advertises into the VPN; `0`: networks it does not. A network whose source does not say is kept only when this filter is not set. |

Always left out: the destination's own network (any network that overlaps the
destination), networks of the other IP version, and a repeat of the same
network on the same device.

At most **5,000** networks are swept at once. When the filters keep more, the
sweep is refused with how many matched; narrow the filters and run again. The
networks are traced one after another, a few tens of milliseconds each on a
large map: a few hundred answer within seconds, a few thousand within about a
minute.

### Reading the results

The verdicts are counted at the top, as chips: **Allowed**, **Blocked**,
**No path**, **Allowed in part** and **Check incomplete** (see [Reading a
trace](#reading-a-trace)). Click a chip to show only those networks; click it
again to show every network. **Group by site** replaces the table with one
line per site: the networks checked and how many got each verdict.

Each row of the table shows the network (site, name, VLAN, CIDR), its
verdict, **Decided at** (the device whose item decided the verdict) and
**Decided by** (that item: the rule set or table and what it found, for
example *Layer 3 firewall rules: Rule 2 (deny ...) denies it*), and the
trace's summary. An allowed network has no deciding item. **Trace** opens the
full hop-by-hop trace of that network in place, with its replies and the
Reverse button, as in Path Mode.

A **Check incomplete** row means the trace could not decide: something the
flow depends on was not collected (the deciding item names it, for example a
rule set that a source does not collect, or everything behind a non-Meraki
VPN peer), a device on the way has no forwarding data, or the destination is
in several places (pick the subnet you mean in **Destination is at**).
Collecting the named source again, or the missing data, turns it into a
verdict; the row does not say whether the flow would pass.

### Downloads

**Download Excel** saves every network of the sweep, whatever chip is
selected, with the same filters, as a spreadsheet (`format=xlsx`). Its
first tab, **Summary**, counts the networks of each verdict (Verdict,
Networks, Share of the total) with a Total row; then come **All** and a
tab for every verdict: **Allowed**, **Blocked**, **No path**, **Allowed in
part** and **Check incomplete**, each present even when it has no rows so
the tabs are always in the same place. Every tab's columns are sized to fit
their text, with a bold header row that stays put when scrolling and a
filter on every column. **Download shown rows** saves the Summary and one
tab with only the rows on screen (the selected chip's verdict,
`verdict=blocked` and so on); the Summary still counts the whole sweep.
**CSV** saves every network as plain CSV (`format=csv`), which has no
column widths, with the same counts by verdict after the rows, under an
empty line. All have the columns: Source, Provider, Site, Network, Kind,
VLAN, CIDR, In VPN, Verdict, Decided at, Decided by, Summary.

## Limits

- Only IPv4 addresses and networks can be typed in Path Mode.
- ICMP types are not told apart.
- An HTML export without the path tracer (`engine=0`, or no runtime when it
  was made) cannot trace anything other than the legs it carries: a leg
  picked inside the file shows the path over the links only. A leg with a
  device at either end is never traced, in Plexus or in a file.
- A snapshot collected before this release has no routing or policy data
  for the trace: its devices are passed over with an unknown item and the
  trace says to collect the source again.
- Routes a device learns over BGP, OSPF or EIGRP are not collected, and
  policy-based routes on an FTD only in part. Inventory devices are traced
  from their latest SSH route capture and configuration backup only. The
  monitoring poll reads the table with the device type's commands (`show
  ip route` and `show ip route vrf *` on IOS and IOS-XE, `vrf all` on
  NX-OS and EOS, `show route` on ASA, FTD, IOS-XR and Junos, `get router
  info routing-table all` on FortiOS, `show routing route` on PAN-OS; a
  type without a driver, such as Aruba, gets the IOS commands) and stores
  the first 250,000 characters of a capture (the global table, then the
  VRF tables); routes past that are *not collected*.
- A reply to an address a firewall translated the source to, when that
  address is on a transit network the next device is connected to, is
  delivered at that device and never walked back through the firewall.
- The ingress interface of a flow that arrives over a link with no address
  on the map is not known; rule sets that match on zones then match only
  in part.

## API reference

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/topology/path` | Traces a flow hop by hop. `source`, `destination`: an IP address or network, 1 to 64 characters. Optional `source_node`, `destination_node`: the map node ids of the devices that own the ends. Optional `protocol`: `tcp`, `udp`, `icmp`, `any` or empty for any traffic. Optional `port`: 0 to 65535. Returns `applies`, `traffic`, `source`, `destination`, `verdict` (`allowed`, `blocked`, `partial`, `unknown`), `summary`, `ports`, `asymmetric` (`status` `no`, `yes` or `unknown`, and `text`), `request` and `reply` (each `verdict`, `summary`, `ports` and `hops`) and `notes`. Each hop has `node`, `edge`, `label`, `site`, `provider`, `in`, `out`, `status` and `items`; each item `stage`, `status`, `where`, `text`, `rule` and, on the item that states a rule set's decision, `ports`. A `ports` value is `{"allowed": {"tcp": "80, 443", "icmp": "any"}, "partial": {"tcp": "8000-8080"}, "unknown": {}, "text": "allowed tcp 80, 443 · icmp; in part tcp 8000-8080"}`, with only the protocols asked about and only those that have ports in each list, or `null` for a direction that was not traced and for a trace that does not apply. A bad parameter returns HTTP 400 |
| `GET` | `/api/topology/reachability` | The [reachability sweep](#reachability-sweep): traces one flow to `destination` (an IP address or network) from every source network the filters keep. Optional `destination_node` (map node id of the device that owns the destination) or `destination_org_ref` + `destination_node_id` (the source and snapshot node of a picked subnet; `-4` and the host id for an inventory device); `protocol` and `port` as for `/api/topology/path`; filters `sources`, `providers`, `kinds`, `vlans`, `name`, `exclude`, `sites`, `within`, `in_vpn`; `format` `json` (default) or `csv`. JSON returns `destination` (`address`, `node`, `label`, `site`), `traffic`, `generated_at`, `filters` (the effective filters, with the default kinds), `candidates`, `limit`, `counts` (per verdict) and `rows`, each with `org_ref`, `org_name`, `provider`, `site_id`, `site_name`, `node_id`, `source_node`, `node_label`, `kind`, `vlan`, `cidr`, `name`, `in_vpn`, `verdict`, `summary`, `traffic`, `decided_at`, `decided_by` and `ports`, sorted by site, then VLAN, then network. CSV is an attachment with the columns listed in [CSV](#csv). A bad parameter returns HTTP 400; more than 5,000 matching networks returns HTTP 400 with `count` and `limit` |
| `GET` | `/api/topology/export.html` | The self-contained HTML map. Optional `group_id`, `download=1`, `path` (the Path Mode state: JSON with `traffic` and `picks`, whose legs are traced and embedded) and `engine` (default on; `engine=0` leaves out the path tracer) |
