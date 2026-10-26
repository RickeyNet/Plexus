# Cato Networks in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include a Cato Networks
account alongside the devices Plexus discovers itself and any Meraki
organizations, Cisco FMCs, Palo Alto Panoramas, Appgate SDP collectives
([appgate-topology.md](appgate-topology.md)) and cloud accounts. Cato sites, Sockets, WAN links, the PoPs they connect to and
the connected remote users appear on the same map, are covered by the same
search box and Path Mode, and are included in the HTML export.

A Cato account is handled like a Meraki organization: it is added, collected
and deleted from the same dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage accounts and API keys
- API: `/api/sources/*` with `provider: "cato"`

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without a key.** Click **Load Sample**, then **Cato**. A demo
   account is added to the map. Delete it from the same dialog when you are done.
3. **Add your account.** Click **Add Source**, then **Cato Account**, and enter a name, the
   account ID and an API key.
4. **Check the key.** Click **Test Key**. It runs one small query against the
   account and reports what Cato answered.
5. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection until you run another.

### Account ID and API key

- **Account ID**: the numeric ID of your account. It is the number in the
  address bar of the Cato Management Application once you are logged in.
- **API key**: create one in the API key settings of the Cato Management
  Application. A key with **View** permission is sufficient: Plexus only
  sends read queries and never changes Cato configuration. If the key is
  restricted to source IP addresses, allow the Plexus server. Each policy
  may need a permission of its own on the key (the Split Tunnel policy, for
  example, needs the **SDP Split Tunnel** permission). A policy Cato refuses
  is reported as not collected (in the collection report and in the
  **Policies not collected** row of the **Cato Cloud** node) and everything
  else still loads.

The key is stored encrypted and is never returned by the API or shown in the
UI again.

Accounts hosted on a regional Cato API host are supported through the *API
URL* field (for example `https://api.us1.catonetworks.com/api/v1/graphql2`).
Only `https` hosts under `catonetworks.com` are accepted and redirects are
not followed, so the key cannot be sent elsewhere.

## On the map

Cato data appears when the group filter is **All groups**.

| On the map | What it is |
|---|---|
| Site box | One Cato site, named as in Cato |
| Socket (firewall icon) | Each Socket of the site. An HA pair shows both, labelled primary / secondary. A site with no Socket (IPsec, cloud interconnect) shows one node standing for its connection |
| WAN triangle | Each connected WAN link of a Socket, with its public IP |
| **Cato Cloud** box | The **Cato Cloud** backbone node every PoP is joined to |
| **PoP** box | A PoP that at least one site or remote user is connected to, with the remote users connected to it when the collection ran, one person icon per user, drawn as a grid under the PoP |
| Remote user (person icon) | One user connected with the Cato Client, labelled with their name, linked to their PoP |
| Dashed tunnel | A Socket's tunnel to its PoP, the remote users' links to their PoPs, and each PoP's link to the backbone |

A site that is disconnected keeps a red (down) tunnel to the **Cato Cloud**
node so it stays attached to the map.

Every connected remote user is a node of its own, in the box of its PoP. Users
Cato reports without a PoP are in a **Remote users** box tied to the backbone.
Their links to the PoP are tunnels, so like the other tunnels they show when
you select the user or the PoP (or turn on all tunnels).

Click a remote user for:

- **Remote user**: name, email, phone, user ID, connectivity and account
  status, directory and authentication method
- **Connecting from**: whether they are remote or in an office (and which
  office, when their public IP is a site's WAN address), public IP, ISP, city,
  state, country and coordinates
- **Connected to (Cato)**: PoP, VPN IP (the address Cato gave the client),
  the path into the backbone, uptime and last connection
- **Device**: device name, OS and Cato Client version
- **Recent connections**: when, how long, device, interface, PoP, public IP,
  location and ISP of their last connections
- **Split Tunnel**: the Split Tunnel rule that applies to the user (its
  number and name), or *No rule matches: all traffic to Cato*, *Office Mode*,
  *Not collected*, or *Undetermined* with the rule that may apply and why;
  for a rule, its mode (route all traffic to Cato except the exceptions,
  route only the selected destinations to Cato, off, user-defined),
  coverage, routing priority, the exceptions or selected destinations
  (global IP ranges with their subnets, domains, FQDNs, applications) and
  the DNS exclusions
- **Client policies**: the rules of the client connectivity, dynamic IP
  allocation, SDP static IP allocation, ZTNA always-on and private access
  policies that apply to the user: by name (*This user*), through a users
  group the user is a member of (*Group Engineering*), to every user (*All
  users*), or *may apply* when the rule names a users group whose members
  were not read; with each rule's settings (platforms, countries, device
  posture, allocation ranges, action...)

Click a **PoP** box for a table of all of its users, and the **Cato Cloud**
node for the account summary and every policy collected, one table each:

- **WAN firewall policy**, **Internet firewall policy**: every rule with its
  direction, source, destination, service, action and the conditions
  (applications, countries, device posture, schedule, exceptions)
- **Split Tunnel policy**: users and groups, platforms, countries, source
  network, mode, destinations, coverage and routing priority
- **Anti-malware file hash**, **Application control**, **App tenant
  restriction**, **Client connectivity**, **Dynamic IP allocation**,
  **Private access**, **Remote port forwarding**, **SDP static IP
  allocation**, **Site web proxy**, **Socket bypass**, **Socket LAN**,
  **Terminal server**, **TLS inspection**, **WAN network** and **ZTNA
  always-on**: every rule with the columns that policy has (bandwidth
  priority, route and transport for WAN network; external and internal
  addresses and ports for remote port forwarding; allocation ranges with
  their subnets for the IP allocation policies; inspection and untrusted
  certificate actions for TLS inspection; the injected headers for app
  tenant restriction; file name and SHA-256 for file hashes; and so on)

A title ends in *(disabled)* when the policy is turned off and in
*(reduced)* when Cato refused the detailed query and only each rule's
number, name and state were read. Application control and TLS inspection
add a **settings** table (their policy-wide defaults), and the WAN firewall,
Internet firewall and Socket LAN policies a **sub-policies** table. A cell
lists 20 names at most and counts the rest (`… +5`). The account summary
says which policies were **not collected** (refused by Cato), **not asked
for** (their option is off) or **read with the reduced query**.

The policies other than the two firewalls and the Split Tunnel policy are
listed, not applied: path tracing does not evaluate them, and no route,
rule or note comes of them.

With the **Site and network configuration** option the **Cato Cloud** node
also lists the **Account** (name, plan, status, tenancy, time zone), the
account's **DHCP settings**, **DHCP options** and **DHCP relay groups**, and
its **DNS settings**, **DNS forwarding rules**, **DNS server sets** and
**DNS suffix sets**.

### Device details

Click a Socket for its tabs:

- **Device**: name, status, model, serial, HA role, Socket version, PoP
- **Interfaces**: WAN links (port, PoP, public IP, provider, uptime) and the
  site's interface list with bandwidth
- **VLANs**: the site's network ranges (subnet, name, interface, VLAN)
- **VPN**: IPsec tunnel settings, for an IPsec site
- The rules of the **Socket LAN**, **Socket bypass** and **Site web proxy**
  policies that apply to the Socket's site (*... policy: rules for this
  site*): rules naming the site, a group the site is a member of, or every
  site, and *may apply* for a group whose members were not read
- The site's configuration as Cato keeps it, with the **Site and network
  configuration** option: **Site settings** (description, site type,
  location, time zone, preferred PoPs, working hours, SIP ACL, backhauling,
  the site's DNS override or *Account default*), **Socket configuration**
  (model, platform, version, serial, management IP, registration, Wi-Fi
  support; each Socket of an HA pair shows its own), **Network range
  settings** (subnet, name, type, VLAN, local IP, gateway, DHCP range, relay
  group or lease, Internet only, mDNS, translated subnet), **Static hosts**
  (name, IP, MAC), **Known hosts** (the DHCP leases and discovered hosts:
  IP, MAC, host name, identity, OS, allocation, range, lease, last
  activity; up to 1000 a site) and **Wi-Fi SSIDs** (band, subnet, DHCP,
  security mode; never a passphrase). A site without a Socket (IPsec, cloud
  interconnect) shows the same on the node that stands for it, less the
  Socket configuration, which is not asked for (Cato answers it with an
  error for such a site).

Click a PoP for the sites and the remote users connected to it (a PoP only
remote users are on has no site tunnel, just its users), and the **Cato
Cloud** node for the account summary.

### Search and Path Mode

The toolbar search covers everything collected: site names, serials, public
IPs, subnets, PoP names, and remote users by name, email, device, VPN IP or
public IP.

In **Path Mode** a Cato site or one of its subnets can be picked like a
Meraki one. A path between two Cato sites runs Socket → PoP → Cato Cloud →
PoP → Socket, and a site whose tunnel is down is not routed through.

Between two subnets or addresses the path is also traced hop by hop through
the Socket, the PoPs and the Cato Cloud, with the firewall Cato would apply:
the WAN firewall rules when a site's network range or a connected user's
address covers the destination (WAN traffic), the internet firewall rules
otherwise (internet traffic), a private destination no site claims included,
since Cato routes such a destination to its internet egress; see
[path-trace.md](path-trace.md). When the site ranges were not collected and
only the default route matches, neither firewall is picked and both are
*not decided*. A rule is matched on the addresses behind
the objects it names: sites, their network ranges and interfaces, connected
users, the account's global IP ranges (**Networking > IP Ranges**), groups
whose members are all such objects, and users groups (the VPN addresses of
their connected members), all read with the rules. A users group none of
whose members is connected stands for no address, and a rule whose source
or destination names only such objects matches no flow. An object Plexus
cannot turn into addresses (a group with a host or VLAN member, a group or
users group whose members were not read in full, an FQDN or IP range
container, a host, an application, a category, a country) makes a rule that
may match *not decided*, never allowed.

A connected remote user's VPN address is in the subnet list as a network of
its own (`10.88.0.11/32 - PoP New York - Cato Client Dana Reyes`), so typing
the address, or picking the entry, starts the trace at that user: user → PoP
(where the WAN firewall is applied) → Cato Cloud → PoP → Socket. When the
Socket is a vSocket in AWS or Azure the trace goes on into the VPC or VNet,
where its route tables and security groups are checked. The user's own
address wins over a wider range another source keeps for the whole client
pool, such as a Meraki site's non-Meraki VPN peer that covers it; picking
that range instead starts at the peer, which knows nothing of what is behind
it. Clicking the person icon in Path Mode picks the user with that address
too, so the leg is traced either way; the pick reads `Dana Reyes
(10.88.0.11) · PoP New York`.

Where a user's traffic goes first follows the account's **Split Tunnel
policy**. The rules are checked top to bottom and the first enabled one that
matches the user (by user or users group, OS, country and source network)
applies; when none does, all traffic goes to Cato. A rule naming a users
group is decided by the group's members when they were read in full. With **route all traffic to Cato
except**, a destination in one of the rule's global IP ranges leaves the
device directly (out of *Local network (direct)*, the device's own network,
which Plexus does not see) and the rest goes to the PoP. The direct
interface carries the public address the Client connects from, when it is a
public one: a private destination sent there is followed to the device on
the map that answers on that address, and the Meraki client table of its
network may give the device's local address (see
[A remote user's direct traffic](path-trace.md#a-remote-users-direct-traffic)). With **route only
selected to Cato**, only the rule's global IP ranges go to the PoP and
everything else leaves the device directly, to the internet. **Off** is all
traffic to Cato. A user connected from an office (Office Mode) is behind the
site, and the policy does not apply; the trace says so. What the trace
cannot tell from the collected data makes a lookup that only the default
route answers *not decided*, with the reason: a domain, FQDN or application
destination (not addresses), web-only coverage (non-web traffic leaves the
device directly), a user-defined routing file, a global IP range that was
not read, a rule ahead of the one that matches that may apply (it names a
users group whose members were not read in full, managed or unmanaged
networks, or an OS or country Cato did not report), and the policy itself
when it was not collected. A rule that keeps traffic for the device's local
subnet on the LAN is a note: that subnet is not collected.

Whether a device is on a managed network cannot be told from the
configuration: Cato's API has no query for the managed network definitions,
and the user snapshot has no flag for it. A rule whose source network is
*Any managed network* or *Any unmanaged network* is therefore settled by the
user's **Client report** (see *Client connection reports* below), when one
exists for the device connected now:

- *Disabled*: all traffic to Cato. The **Split Tunnel** section says the
  Client reported it, on which device and when, and which rule would
  otherwise be undetermined; the trace follows the default route to the PoP.
- *Admin Defined*: a rule with *route all traffic to Cato except* or *route
  only selected to Cato* applied. When exactly one rule that may apply (up to
  and including the first that matches) has one of those modes, that rule
  applies, its routes are followed, and the **Rule** row says it was decided
  by the Client's report. With several, the choice stays *not decided* and
  the reason names them.
- *User Defined*: the same, with a user-defined rule.

A report never overrides a rule decided from the configuration; one that
does not agree with it is a plain note on the user. Without a report for the
current device, the reason says whether the reports were not collected or
none was found for the device.

### Client connection reports

With the **Client connection reports** option (on by default, read with the
remote users), Plexus reads the latest **Client Connectivity Policy** event
of every user device in the last 7 days from Cato's `events` query. The Cato
Client emits that event each time it connects and its Client Connectivity
Policy is evaluated, and it carries what the Client applied to the
connection. A remote user's details gain a **Client report** section, after
**Device**:

- **Reported**: the time of the newest event (UTC)
- **Device**, **OS**
- **Split Tunnel**: the Split Tunnel configuration the Client applied:
  *Disabled* (no exception: no rule matched, or the rule is *Off*), *Admin
  Defined* (an *except* or *only selected* rule) or *User Defined*. The
  event does not say which rule
- **Office Mode**, **Managed Networks (Trusted Networks)** (whether that
  feature, named Trusted Networks before February 2026, is on for the
  connection)
- **Public IP** (the address the Client connects from), **PoP**
- **Note**, when the only report is from another device than the one
  connected now: it is shown, and not used for the Split Tunnel decision

*Not collected* means the option was off or Cato refused the query (listed
in the collection report); *No Client Connectivity Policy event in the last
7 days* means the reports were read and none is for this user. The events
are grouped by user, device, OS, Split Tunnel configuration, Office Mode,
Trusted Networks, public IP and PoP, newest first, 1000 groups a page and 10
pages at most (the collection report says when more were left out); Plexus
keeps the newest per user and device. The query is generally available in
Cato's API; the API key needs the **View** permission for events.

A path is only drawn over links on the map. Plexus does not know that a Cato
Socket and a Meraki switch at the same location are cabled together unless
one of them reports the other as a neighbor, so a path between a Meraki
subnet and a Cato subnet may show as "no path".

A Cato site that connects to AWS is joined to the AWS side of the map by
public address: a vSocket to its instance, an IPsec site to the AWS VPN
gateway it terminates on. See [aws-topology.md](aws-topology.md).

The network ranges of every site also appear on the **IPAM** page as subnets
of source **topology**, with their VLAN tag and site, and a range two sites
both hold, or that sits inside a VPC, is listed under **Overlapping Ranges**
(see the [Meraki guide](meraki-topology.md#ipam)).

## What is collected

| Data | Cato API query | Option |
|---|---|---|
| Sites, Sockets, WAN links, PoP, HA state | `accountSnapshot` (sites) | always |
| Connected remote users | `accountSnapshot` (users) | Remote users |
| Network ranges and LAN interface subnets | `entityLookup` (`siteRange`, `networkInterface`) | Network ranges |
| WAN and Internet firewall rules | `policy.wanFirewall`, `policy.internetFirewall` | Firewall rules |
| Split Tunnel policy (Access > Split Tunnel Policy), which needs the SDP Split Tunnel permission | `policy.splitTunnel` | Remote users |
| Latest Client Connectivity Policy event of each user device, last 7 days (Split Tunnel configuration applied, Office Mode, Trusted Networks, public IP, PoP), which needs the View permission for events | `events` (`event_sub_type` *Client Connectivity Policy*) | Client connection reports (with Remote users) |
| Global IP range objects the rules name (Networking > IP Ranges) | `object.globalIpRangeList` | Firewall rules, Remote users or All other policies |
| WAN network rules (bandwidth priority, routing, transport) | `policy.wanNetwork` | All other policies |
| Socket LAN, Socket bypass and site web proxy rules | `policy.socketLan`, `policy.socketBypass`, `policy.siteWebProxy` | All other policies |
| TLS inspection, application control, app tenant restriction, anti-malware file hash rules | `policy.tlsInspect`, `policy.applicationControl`, `policy.appTenantRestriction`, `policy.antiMalwareFileHash` | All other policies |
| Remote access: client connectivity, dynamic and SDP static IP allocation, private access, ZTNA always-on, terminal server rules | `policy.clientConnectivity`, `policy.dynamicIpAllocation`, `policy.sdpStaticIpAllocation`, `policy.privateAccess`, `policy.ztnaAlwaysOn`, `policy.terminalServer` | All other policies |
| Remote port forwarding rules | `policy.remotePortFwd` | All other policies |
| Sub-policies of the WAN firewall, Internet firewall and Socket LAN policies | `policy.<policy>.policyList` | All other policies (and that policy's own option) |
| Groups and their members (sites, ranges, hosts...) | `groups.groupList`, `groups.group.members` | All other policies |
| Users groups and their members | `user.usersGroupList`, `user.usersGroup.members` | All other policies |
| IP range and FQDN containers (name, type, size; their contents are only a file download and are not read) | `container.list` | All other policies |
| Custom applications | `customAppData.customApplicationList` | All other policies |
| Network range settings (type, VLAN, local IP, gateway, DHCP, Internet only, mDNS, NAT) | `site.networkRangeList`, per site | Site and network configuration |
| Static and known hosts (known hosts are DHCP leases and discovered hosts, up to 1000 a site) | `site.staticHostList`, `site.knownHostList`, per site | Site and network configuration |
| Socket configuration (model, version, serial, management IP, registration, Wi-Fi support) | `site.siteSocketConfiguration`, per site | Site and network configuration |
| Site settings (type, location, time zone, preferred PoPs, working hours, SIP ACL, backhauling, DNS override) | `site.siteGeneralDetails`, `site.siteBackhauling`, `networkConfig.dns.siteSettings`, per site | Site and network configuration |
| Wi-Fi SSIDs (security mode only, never a passphrase) | `site.wifiSsidList`, per site | Site and network configuration |
| Account (name, plan, status, tenancy, time zone) | `accountManagement.account` | Site and network configuration |
| DHCP settings, options and relay groups | `networkConfig.dhcp.settings`, `optionList`, `relayGroupList` | Site and network configuration |
| DNS settings, forwarding rules, server sets and suffix sets | `networkConfig.dns.settings`, `forwardingRuleList`, `serverSetList`, `suffixSetList` | Site and network configuration |

Every policy is read once, published (not a draft revision), with every rule
field Cato's schema has except secrets; all of them are `@beta` in Cato's
schema. The groups and users groups are read page by page, and then the
members of each group: Plexus reads the members of 500 groups at most, and
of a group with at most 10000 members; a group past either cap has its
members marked as not read (rules naming it stay *not decided* or *may
apply*) and the collection report says how many were read.

A collection is a few dozen queries with every option on (one per policy,
one per page of a list, one per site for the BGP peers and one or more per
group for the members), sent one at a time and spaced out to stay inside
Cato's API rate limits, so a large account takes minutes. A rate-limit
answer is retried after a pause. Turning **All other policies** off leaves
out every policy but the two firewalls and the Split Tunnel policy, and the
objects.

**Site and network configuration** costs 8 queries per site plus 8 per
account (and one more for every 100 known hosts beyond the first 100 of a
site), so it adds about 8 seconds per site; only the first 250 sites are
read, and the collection report says how many were skipped. All of these
queries are beta in Cato's API: one the key may not use, or the tenant does
not have, is recorded in the collection report, and one that fails for the
first three sites is not sent for the rest. Turn the option off for a quick
collection of a large account.

The site list is required. Everything else is best-effort: if a query fails,
the collection finishes as **partial**, the map is still built, and the
failure with Cato's own error message is listed under **Report** in the HTML
map. If Cato refuses the detailed site query, Plexus falls back to a reduced
one, so the sites still appear, without WAN links and HA state. The same goes
for the user query: the users still appear, without recent connections, state,
coordinates and phone number. And for the Split Tunnel policy: the reduced
query has no countries, domains, FQDNs, applications, coverage or routing
priority, so its rules are *not decided* for the users they may apply to.
Every other policy has a reduced query too, which reads each rule's number,
name and state only.

Only users connected at collection time are read. Their traffic (which
applications and sites they reach), the contents of containers, the
account's managed networks, the network each user's device is on (only the
Split Tunnel configuration its Client reports applying), and hosts
behind a site are not collected. Cato's API has no route table: the routes
are built from the site ranges, the BGP peers, the connected users and the
Split Tunnel policy.

## API reference

A Cato account uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for Cato |
|---|---|---|
| `GET` | `/api/sources` | Each entry has `provider` (`meraki` or `cato`); `cato_default_options` lists the Cato collection options |
| `POST` | `/api/sources` | `{"name", "provider": "cato", "org_id": "<account ID>", "api_key", "base_url"?, "options"?}` (admin) |
| `POST` | `/api/sources/{id}/validate` | Runs one query against the account (admin) |
| `POST` | `/api/sources/{id}/build` | Start a collection; returns `job_id` |
| `POST` | `/api/sources/sample?provider=cato` | Add / refresh the demo Cato account |
| `GET` | `/api/topology` | Cato nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `cato` |
