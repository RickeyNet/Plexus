# Path trace - Usage Guide

**Path Mode** on the Topology page (**Network → Topology**) draws how the
devices, sites and subnets you pick are joined on the map. Between two
subnets or IP addresses it now also traces the flow hop by hop. At every
device on the way it lists, in the order the device applies them, the
policies, ACLs, security groups, NAT rules and route lookups the flow hits.
It does this for the request and for the replies, says whether routing is
asymmetric, and lets you reverse the source and the destination.

The trace reads what the sources on the map collected: Meraki
organizations, Cisco FMCs, Cato accounts, AWS accounts, Azure subscriptions
and the routes Plexus captured from inventory devices over SSH. It never
reports as allowed what it could not look at: what a source does not
collect is listed at that hop, and is *unknown* when the flow depends on
it.

- Permission: the `topology` feature
- API: `GET /api/topology/path`, see [API reference](#api-reference)

## Picking the ends

Turn on **Path Mode** in the toolbar, then pick up to six ends. Every pair of
picks is a leg of the path.

- **Subnets and addresses are traced.** Choose a subnet in **Add a subnet or
  IP address**, or type an IP address or a network and press Enter. The most
  specific collected subnet that holds it is used; when several sites have
  it, pick the one you mean from the list. A typed address is kept as the
  end, so rules and security groups are matched against that address
  rather than the whole subnet.
- **Devices and sites draw the path only.** A device clicked on the map or a
  site typed into **Add a site** has no address to trace. A leg between a
  subnet and a device says which end to add with the subnet box instead.
- A subnet stands for the device that owns it: the site's appliance, the L3
  switch holding its SVI, the FTD it is connected to, the VPC or VNet
  router, the Cato Socket or the VPN peer it sits behind. A device that two
  sources know, such as an FTDv that is also an AWS instance, is one node on
  the map, and the subnets of both can be picked.
- The first of two picks is the source of the request.

## The Traffic box

The **Traffic** box appears next to the subnet box as soon as a leg has two
subnet or address ends. It takes `tcp/443`, `udp/53`, `443` (TCP), `icmp`,
or nothing for any traffic. It applies to every traced leg. With nothing
typed, a rule that opens only some ports gives *allowed in part*. A text the
box cannot read is outlined in red and the legs are not traced until it is
fixed.

## Reading a trace

Under each traced leg, the hops of the request on one line, for example
`Branch 01 MX → Hub 01 MX → Corp East Backup ✕ (3 hops)`, with the mark of
any hop that is not ok, in place of the path drawn over the links; then:

1. **The verdict** of the direction shown: **Allowed**, **Blocked**,
   **Allowed in part** or **Check incomplete**, the traffic, and a sentence
   that names the first item that decided it (for an allowed flow, *Every
   hop allows it* and the hops), ending with what was not checked.
2. **Reverse: trace B → A as a new connection** swaps the ends and shows the
   same traffic opened from the other side. Click it again to go back. The
   verdict of the other direction is always shown on the muted line below,
   so both are visible without clicking.
3. **Request** and **Replies**: the hops in order, each as
   `3. Hub 01 MX · Hub 01 · in AutoVPN from Branch 01 → out VLAN 20`, with
   the items the device applied under it. Each item has a mark (✓ ok,
   ✕ blocked, ◐ partly, ? unknown, i for information), the kind of step
   (Policy, ACL, Security group, NAT, Route, Link, Note), the rule set or
   table, and what was found, naming the matching rule. Every hop and item
   is listed; nothing is folded away. The replies are numbered from the
   destination back.
4. **Asymmetric routing**, which compares the two lists above it: *no* when
   the replies take the same hops back; *yes* in amber, spelling out the way
   the request passed and the way the replies pass, then where they part
   and which stateful firewall sees only one of them; *unknown* when a walk
   could not be completed. See [Replies and asymmetry](#replies-and-asymmetry).
5. Notes about the data, such as a snapshot collected before this feature,
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
  host's address, alias or SVI
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
uplink address hides LAN sources only when the flow leaves on the WAN, and
not at all on an MX with no LAN (a vMX in passthrough or VPN concentrator
mode, which bridges its VPC); VPN subnet translation applies only when the
flow leaves over AutoVPN. FTD NAT rules match
their source and destination interfaces by name or by security zone; a
static auto NAT rule translates the source on the way out and the mapped
address back on the way in. A rule that translates to the same networks is
listed as identity NAT.

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
  traffic from the WAN, FTD prefilter or access control rules, a switch ACL,
  Cato WAN firewall rules for a private destination and internet firewall
  rules for a public one
- routes that are not collected, such as routes learned over BGP or OSPF,
  make the route lookup *unknown* when it finds no route or only a default
  route, unless a site-to-site VPN then takes the flow: a default route and
  a tunnel whose protected networks match is how a policy-based VPN is built
- anything else, such as Layer 7 rules and group policies, is a note. The
  summary of each direction ends with **Not checked:** and those names, so
  you can see what an *allowed* verdict rests on

### Ends, clouds and the internet

An end is placed by the node the page passes. Without one, the most specific
collected subnet that holds the address is used, then a device that has the
address on an interface, then a device whose 1:1 or static NAT publishes it.
An address in several places at the same length is not traced. An address
that is in no collected subnet but is public starts or ends at the Internet:
a flow from the internet reaches the destination's device on its uplink,
where its NAT and inbound rules decide. Documentation ranges such as
198.51.100.0/24 count as public here, since the samples use them that way.

## What each source contributes

| Source | Traced | Not collected |
|---|---|---|
| Meraki | Layer 3 firewall rules, inbound firewall rules, site-to-site VPN firewall rules, 1:1 NAT, port forwarding, 1:Many NAT, VPN subnet translation, static and AutoVPN routes, routes to non-Meraki VPN peers, switch ACLs and SVI routes | Layer 7 firewall rules, group policies |
| Cisco FMC | Prefilter rules, access control rules, NAT rules, connected and static routes, site-to-site VPN protected networks | Routes learned by BGP, OSPF or EIGRP, access control rules beyond the first 1000 |
| Cato | The hops: Socket, PoP, Cato Cloud, PoP, Socket | WAN and internet firewall rules |
| Inventory devices | The routes of the latest SSH route table capture: Cisco IOS and IOS-XE, NX-OS, ASA and FTD, Arista EOS | Access lists |
| AWS | Route tables, transit gateways, VPC peerings, network ACLs, security groups, as in [the AWS check of a path](aws-topology.md#the-aws-check-of-a-path) | See that section |
| Azure | Effective routes and network security groups, as in [the Azure check of a path](azure-topology.md#the-azure-check-of-a-path) | See that section |

Whether what is not collected makes a hop *unknown* or is a note is
explained under [What is not collected](#what-is-not-collected). A Cato
trace is *unknown* between sites, since the WAN firewall decides there.

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
rather than ending at the VPC. An MX with no LAN at all (a vMX in
passthrough or VPN concentrator mode) is taken not to translate.

**Reverse** is a different question: it traces a new connection opened
from the destination to the source, with its own request and replies.

## Limits

- Only IPv4 addresses and networks can be typed in Path Mode.
- ICMP types are not told apart.
- The HTML export draws paths only. It has no trace.
- A snapshot collected before this release has no routing or policy data
  for the trace: its devices are passed over with an unknown item and the
  trace says to collect the source again.
- Routes a device learns over BGP, OSPF or EIGRP are not collected, and
  policy-based routes on an FTD only in part. Inventory devices are traced
  from their latest SSH route capture only.
- The ingress interface of a flow that arrives over a link with no address
  on the map is not known; rule sets that match on zones then match only
  in part.

## API reference

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/topology/path` | Traces a flow hop by hop. `source`, `destination`: an IP address or network, 1 to 64 characters. Optional `source_node`, `destination_node`: the map node ids of the devices that own the ends. Optional `protocol`: `tcp`, `udp`, `icmp`, `any` or empty for any traffic. Optional `port`: 0 to 65535. Returns `applies`, `traffic`, `source`, `destination`, `verdict` (`allowed`, `blocked`, `partial`, `unknown`), `summary`, `asymmetric` (`status` `no`, `yes` or `unknown`, and `text`), `request` and `reply` (each `verdict`, `summary` and `hops`) and `notes`. Each hop has `node`, `edge`, `label`, `site`, `provider`, `in`, `out`, `status` and `items`; each item `stage`, `status`, `where`, `text` and `rule`. A bad parameter returns HTTP 400 |
