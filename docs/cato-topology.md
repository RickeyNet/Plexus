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
  restricted to source IP addresses, allow the Plexus server. Reading the
  Split Tunnel policy also needs the **SDP Split Tunnel** permission; a key
  without it still collects everything else, and the policy is reported as
  not collected.

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

Click a **PoP** box for a table of all of its users, and the **Cato Cloud**
node for the account's whole **Split Tunnel policy**: every rule with its
users and groups, platforms, countries, source network, mode, destinations,
coverage and routing priority.

### Device details

Click a Socket for its tabs:

- **Device**: name, status, model, serial, HA role, Socket version, PoP
- **Interfaces**: WAN links (port, PoP, public IP, provider, uptime) and the
  site's interface list with bandwidth
- **VLANs**: the site's network ranges (subnet, name, interface, VLAN)
- **VPN**: IPsec tunnel settings, for an IPsec site

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
users, and the account's global IP ranges (**Networking > IP Ranges**),
which are read with the rules. An object Plexus does not read (a users
group, a host, an application, a category, a country) makes a rule that may
match *not decided*, never allowed.

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
matches the user (by user, OS, country and source network) applies; when
none does, all traffic goes to Cato. With **route all traffic to Cato
except**, a destination in one of the rule's global IP ranges leaves the
device directly (out of *Local network (direct)*, the device's own network,
which Plexus does not see) and the rest goes to the PoP. With **route only
selected to Cato**, only the rule's global IP ranges go to the PoP and
everything else leaves the device directly, to the internet. **Off** is all
traffic to Cato. A user connected from an office (Office Mode) is behind the
site, and the policy does not apply; the trace says so. What the trace
cannot tell from the collected data makes a lookup that only the default
route answers *not decided*, with the reason: a domain, FQDN or application
destination (not addresses), web-only coverage (non-web traffic leaves the
device directly), a user-defined routing file, a global IP range that was
not read, a rule ahead of the one that matches that may apply (it names
users groups, managed or unmanaged networks, or an OS or country Cato did
not report: group membership and managed networks are not read), and the
policy itself when it was not collected. A rule that keeps traffic for the
device's local subnet on the LAN is a note: that subnet is not collected.

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
| Global IP range objects the rules name (Networking > IP Ranges) | `object.globalIpRangeList` | Firewall rules or Remote users |

A collection is a handful of queries, sent one at a time and spaced out to
stay inside Cato's API rate limits. A rate-limit answer is retried after a
pause.

The site list is required. Everything else is best-effort: if a query fails,
the collection finishes as **partial**, the map is still built, and the
failure with Cato's own error message is listed under **Report** in the HTML
map. If Cato refuses the detailed site query, Plexus falls back to a reduced
one, so the sites still appear, without WAN links and HA state. The same goes
for the user query: the users still appear, without recent connections, state,
coordinates and phone number. And for the Split Tunnel policy: the reduced
query has no countries, domains, FQDNs, applications, coverage or routing
priority, so its rules are *not decided* for the users they may apply to.

Only users connected at collection time are read. Their traffic (which
applications and sites they reach), the users groups' members, the
account's managed networks, the network each user's device is on, and hosts
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
