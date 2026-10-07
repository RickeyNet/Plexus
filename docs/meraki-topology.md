# Meraki in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include Cisco Meraki
organizations alongside the devices Plexus discovers itself. Meraki sites,
devices, WAN uplinks and VPN tunnels appear on the same map, are covered by
the same search box, and are included in the HTML export.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage organizations and API keys
- API: `/api/meraki/*`, `/api/topology/search/deep`, `/api/topology/export.html`

A Cato Networks account is added from the same dialog and shares the map,
search, Path Mode and export; see [cato-topology.md](cato-topology.md), as is
a Cisco FMC whose FTDs terminate AnyConnect remote access VPN; see
[anyconnect-topology.md](anyconnect-topology.md). AWS accounts and Azure
subscriptions discovered by Cloud Visibility join the map as well; see
[aws-topology.md](aws-topology.md) and [azure-topology.md](azure-topology.md).

A registered organization can also be audited by the Compliance page against
the Meraki equivalents of DHCP snooping, port security, BPDU guard and the
other hardening controls; see [meraki-compliance.md](meraki-compliance.md).

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar. The
   dialog lists everything that feeds the map (neighbor discovery of the
   inventory, Meraki organizations, Cato accounts, AnyConnect FMCs, AWS
   accounts) with its last collection; **Collect All** refreshes every source
   in one click.
2. **Preview without a key.** Click **Load Sample**, then **Meraki**. A demo
   organization is added to the map so you can see the result before
   connecting anything. Delete it from the same dialog when you are done.
3. **Add your organization.** Click **Add Source**, then **Meraki Organization**, and enter a name and
   a Meraki Dashboard API key. Leave *Organization ID* blank if the key can see
   only one organization; otherwise click **Test Key** afterwards to list the
   organization IDs the key can see, and enter the one you want.
4. **Collect.** Click **Collect Now**. Progress is shown while Plexus
   collects; when it finishes the map updates.
5. **Share.** Click **Export** in the toolbar, then **HTML map (download)** to
   download the whole map as one file, or **Open HTML map** to view it in a
   new tab.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection for each organization until you run another.

### API key

A **read-only** organization administrator key is sufficient. Plexus issues
only `GET` requests and never changes Meraki configuration. The key is stored
encrypted and is never returned by the API or shown in the UI again.

Regional clouds are supported through the *API base URL* field
(`api.meraki.com`, `api.meraki.cn`, `api.meraki.in`, `api.meraki.ca`,
`api.gov-meraki.com`). Other hosts are rejected, and redirects are followed
only within the same Meraki domain, so the key cannot be sent elsewhere.

## On the map

Meraki data appears when the group filter is **All groups** (Meraki devices
belong to no inventory group).

- The map opens in the **Tidy tree** layout, top to bottom. Each source is
  a region of its own, framed and titled, side by side from left to right: the
  inventory, then Meraki, Cato, AnyConnect, AWS and Azure. Links between
  sources are still drawn, but they do not pull a device into another
  source's region, and they go around the sources rather than through them:
  up from each end, around the other sites' boxes and devices, to a lane
  over the tops of the regions, then across and down (a vSocket to its VPC,
  for example). Links whose stretches overlap get lanes of their own, the
  shorter one lower; click one for its details as usual. Within a source each connected network is a tree growing
  down from its busiest gateway (for a hub-and-spoke VPN, the hub; for Cato,
  the backbone, then the PoPs), following cables first and VPN tunnels only
  to reach other sites. Every device gets its own spot, so nothing overlaps
  and nothing needs arranging. A device with no links (dormant, offline, or
  a sensor the API reports no neighbour for) is drawn in a small grid under
  its site's gateway, inside the site's box, after the gateway's other
  devices; only devices whose whole site has no links (and inventory
  devices in no group) are listed in a grid under the trees. An appliance's WAN uplinks (and a VPC's internet gateway) are
  drawn in a row just above it. Eight or more devices of one site with
  nothing below them (access points on a switch, remote users on a PoP) are
  drawn as a grid under their parent. A device's links to the sites hanging
  off it (a VPN hub's spokes, a VPC's peers, the Cato backbone's PoPs) are
  drawn as a comb: down from the device to a bar above the row of sites and
  a straight drop into each (beside a site's WAN uplinks, not through them).
  When the sites wrap onto several rows, a trunk down the left of the block
  carries the bar to each lower row, so no link runs through another site's
  box. The device sits in the middle of its spokes, over its own devices.
  The other layouts (physics, circular,
  hierarchical) remain in the layout menu. A node you dragged stays where
  you put it; **Reset Positions** puts every node back in the tree.
- **Large maps.** When a device's children would make one very wide row
  (hundreds of sites behind a VPN hub), they wrap onto several rows under
  it, in site name order, so the hub stays on top. The Cato PoPs are the
  exception: they stay in one row under the Cato Cloud, on one comb. With more than
  300 VPN tunnels, tunnels are not all drawn at once: click a device to see
  its tunnels, or turn on **VPN Tunnels** in the toolbar to draw them all.
  The links from the Cato Cloud to its PoPs are always drawn and are not
  counted, so the Cato backbone stays visible.
  Above roughly 600 devices the map also drops the glow behind nodes and
  links and the hover highlight, which keeps it responsive; links stay
  drawn while you pan or zoom.
  The HTML export follows the same rule: tunnels run over the site boxes
  and LAN links but under the devices, and past 300 of them only the selected site's tunnels are drawn,
  highlighted (selecting any device selects its site's tunnels;
  **Layers > All tunnels at once** draws every one).
- Each Meraki network is framed as a labelled site box. A device with
  links into other sites (a VPN hub, a VPC peered with others) sits over
  the devices of its own site, which are drawn in the middle of the sites
  hanging off it, so its box stays clear of them. A site whose devices the tree
  places in more than one spot (two networks of the site not linked to each
  other) gets a box in each spot, with the same title. Devices with no links
  do not split a site: they are drawn under its gateway, in its box (the
  unlinked customer gateways of the **AWS transit and VPN** box sit under
  its transit gateway). A box that would still enclose another site's
  devices is left out. A site title that would run into the next site's box
  (a long name over a narrow box, such as a VPC that was not collected) is
  shortened with an ellipsis; the full name is in the tooltip and the
  details panel. The HTML export follows, combs and titles included.
- You can still drag a node to pin it; right-click returns it to its place
  in the tree, and **Reset Positions** returns the whole map to the tidy
  arrangement.
- Meraki devices are green. A red border means offline, amber means alerting.
- **Path Mode** (toolbar) shows how devices or sites reach one another:
  click two or more devices on the map, or type a site name into **Add a
  site** (the site's appliance stands for it). Every pair is traced, up to
  six picks; the path is highlighted and listed hop by hop. It is the
  shortest way over the cables, uplinks and VPN tunnels that are up, with
  AutoVPN preferred over non-Meraki IPsec. The path drawn shows how the
  ends are joined, not the route each device picks; with an end in AWS or
  Azure, that cloud's route tables and rules are checked separately (see
  [AWS topology](aws-topology.md#the-aws-check-of-a-path)).
  The HTML export has the same tool under **Path**: click sites in the
  list or on the map. It draws the path only and does not run the AWS or
  Azure check.
- Path picks can also be **subnets**: choose one in **Add a subnet or IP
  address**, or type an address or network and press Enter (the most
  specific collected subnet containing it is used; if several sites have
  it, pick from the list). A subnet stands for the device that owns it -
  the site's appliance (VLANs, single LAN, static routes), the L3 switch
  holding its SVI, or the non-Meraki VPN peer it sits behind. Two subnets
  of one device are reported as routed locally. A warning is shown when
  the tunnels on the path will not carry a subnet: it is not enabled for
  VPN at its site, or it is behind a non-Meraki peer the other site has
  no tunnel of its own to. The subnet list comes from the latest
  collection (`GET /api/meraki/subnets`); IPv4 only when typing.
  When one of two subnets or addresses is in an AWS VPC, the AWS route
  tables, network ACLs and security groups are checked for that pair as
  well; see [aws-topology.md](aws-topology.md#the-aws-check-of-a-path). An
  end in an Azure VNet is checked against Azure's effective routes and
  network security groups; see
  [azure-topology.md](azure-topology.md#the-azure-check-of-a-path).
- VPN tunnels are purple dashed lines (dotted for non-Meraki IPsec peers),
  WAN uplinks are blue. A tunnel or uplink Meraki reports as down is red.
- **Device tabs.** Clicking a Meraki device opens its details, one tab per
  category of collected data: **Device** (summary), **Interfaces**
  (switch/appliance ports, WAN uplinks, SVIs, neighbors), **VLANs** (the
  site's VLANs plus a per-VLAN summary of the switch's ports), **MAC/ARP**
  (clients - MAC, IP, VLAN, port, SSID - seen on that device in the day
  before the collection; an appliance also lists every client of its site),
  **Routing**, **VPN**, **Firewall**, **Switching** and **Wireless**. A tab
  appears only when something was collected for it, so an access point shows
  fewer tabs than a security appliance. **Config**, **Errors** and **Audit**
  are not shown for Meraki-only devices - Plexus has no CLI configuration or
  SNMP data for them, and adding a Meraki device to the inventory does not
  change that. Client MACs and IPs are searchable from the toolbar search
  box.
- **One device, one node.** A Meraki device or LLDP/CDP neighbor that is also
  a Plexus inventory host is drawn once, as the inventory host, and gains
  the Meraki tabs (a tab both sources fill, such as **Interfaces**, shows the
  inventory data first and the Meraki data under it). This is what joins a
  Meraki site to the rest of the map.
  Matching is by serial number, then IP address (including interface
  aliases), then hostname for neighbors. A neighbor that matches nothing
  stays with its own site, even when another site reports a neighbor of the
  same name ("Unknown neighbor", a phone model).
- Where Plexus and Meraki both report the same link, the Plexus-discovered
  link is shown, since it carries utilization and spanning-tree state.
- The source selector narrows the map: **All sources**, **Inventory only**,
  **All integrations** (every Meraki, Cato, AnyConnect and AWS device), or
  one integration alone (**Meraki only**, **Cato only**, **AnyConnect only**,
  **AWS only**; only the integrations on the map are offered). A single
  integration keeps its own devices and the links between them; a link to
  another integration (a Cato or Meraki VPN to an AWS gateway, a headend's
  **Managed by FMC** link to an FMC in another box) is hidden with the other
  side. An inventory host matched to an integration's device counts as that
  integration.

### Device details

Click a Meraki device and pick a tab. A security appliance also shows its
site's configuration on the matching tabs: VLANs and DHCP, static and derived
routes, VPN mode and peers, firewall and NAT rules, SSIDs. Switches show
ports, SVIs, routing and stack membership; all devices show LLDP/CDP
neighbors. Use the filter box to narrow long tables. Tables wider than the
panel scroll sideways (the scrollbar stays visible), the panel's left edge can
be dragged to widen it (double-click the edge to reset; the width is
remembered), and **Expand** opens the tab in a large modal.

### Search

The toolbar search box matches device name, IP, model, serial and site as you
type. For Meraki devices it also searches everything collected: VLAN IDs and
names, subnets, routes, VPN peers, firewall rule comments, SSIDs, port names
and neighbors. A match inside a site's configuration resolves to that site's
appliance, and the result shows where the match was found.

- Click a result to jump to the device; matching rows are highlighted, and
  the tabs that contain them are marked with a yellow dot.
- Press `Enter` with several matches to highlight all of them on the map and
  dim everything else.

Search of collected detail covers Meraki data. Inventory devices are matched
by name, IP, model and group here; use **Find MAC/IP/VLAN** for their
forwarding and ARP tables.

### MAC addresses

Every collection also records the clients Meraki saw in the previous day
(MAC, IP, VLAN, port or SSID, client name, manufacturer, and the Meraki
device each was last seen on) in Plexus's MAC tracking, next to the
forwarding tables Plexus polls from inventory switches. One search covers
both:

- **Find MAC/IP/VLAN** on the Topology page lists matches from inventory
  switches and Meraki devices and highlights the devices on the map.
- **Network Tools > MAC / ARP Tracking** lists the same results in a table;
  Meraki clients are marked **Meraki** and show their network. A MAC can be
  typed in any format (`aa:bb:cc:dd:ee:ff`, `aabb.ccdd.eeff`, or a fragment
  of six or more hex digits); Meraki clients are also found by client name
  or device name.

A client keeps its first-seen and last-seen times across collections and
stays searchable after it drops out of Meraki's one-day window or its
snapshot is deleted. It is removed with its organization, or by the MAC
tracking cleanup once it has not been seen for the chosen number of days.
Meraki clients are refreshed only by a Meraki collection (**Collect Now** on
the MAC tracking page polls inventory switches), need the **Clients (MAC /
IP)** collection option (on by default), and have no move history.

### IPAM

The subnets of the latest collection of every organization also appear on
the **IPAM** page, next to the subnets inferred from inventory hosts, the
cloud CIDRs of Cloud Visibility and external IPAM prefixes: each VLAN,
single LAN, switch SVI and static route is a row with source **topology**,
its VLAN ID, and the sites that hold it in the **Preview** column (the same
goes for Cato network ranges and AnyConnect address pools). Untick **Include
Topology Subnets** to leave them out (`GET /api/ipam/overview?include_topology=false`).

**Overlapping Ranges** lists every range two sites both hold, or a site holds
inside a VPC or VNet of Cloud Visibility: the same subnet, or one inside the
other. A pair whose two sides are both advertised into the VPN is a **VPN
conflict**, the usual AutoVPN problem where two branches use the same user
VLAN and traffic for it reaches the wrong site; the summary card turns red
when there is one. Static routes and the subnets behind non-Meraki VPN peers
are listed but not checked, since a hub's summary route legitimately covers
its spokes, and the same range listed twice by one site (its VLAN and the L3
switch's SVI) is not a pair. Subnets in the overlap list carry an **N
overlaps** badge in the subnet table. The first 500 pairs are returned
(`overlaps`, VPN conflicts first); `summary.overlap_count` has the total.

### Software versions

The firmware of every device of the latest collection is also tracked on
the **Software** page (**Network → Software**), classified by product
(Meraki MX, MS, MR, ...), compared across the fleet and checked against
security advisories. See [software-versions.md](software-versions.md).

## What is collected

| Detail | Source |
|---|---|
| Sites, devices, model, serial, firmware, tags, address | Organization networks and devices |
| Online / alerting / offline status, LAN and public IP | Organization device statuses |
| LAN links and ports | Network link-layer topology, per-device LLDP/CDP |
| Non-Meraki neighbors (core switches, ISP routers) | LLDP/CDP |
| WAN uplinks (IP, gateway, DNS, status) | Organization uplink statuses |
| AutoVPN mode, hubs, peers, reachability, exported subnets | Appliance VPN statuses and site-to-site VPN settings |
| Non-Meraki VPN peers and their subnets | Third-party VPN peers (shared secrets are never collected) |
| VLANs, appliance ports, static routes, BGP | Appliance network settings |
| Effective route table per site | Derived: connected VLANs + static routes + VPN peer subnets + WAN default |
| Firewall, port forwarding, 1:1 NAT rules | Appliance firewall settings |
| Switch ports (VLAN, trunk, PoE, STP guard), optional live status | Organization switch ports, per-switch port statuses |
| Switch SVIs, static routes, OSPF, stacks, STP priorities | Switch routing and network switch settings |
| SSIDs (auth mode, VLAN) | Wireless SSIDs (pre-shared keys are never collected) |

Meraki has no API for an appliance's live routing table, so the *Effective
routes (derived)* table is assembled from the sources above and labelled as
derived.

### SSH and SNMP data

Meraki hardware is cloud-managed and has no CLI, so SSH and SNMP cannot be
used against Meraki devices themselves. They add detail where a node is
**also a Plexus inventory host**: a non-Meraki LLDP/CDP neighbor such as a
Catalyst core, or a cloud-monitored Catalyst that Plexus manages directly.

- **Correlate with Plexus inventory** (on by default) attaches what Plexus
  has already collected for the host: interfaces and VLANs (SNMP), CDP/LLDP
  neighbors, and the latest route-table snapshot (SSH, from monitoring).
- **Live SSH show commands** (off by default) additionally connects to each
  matched host during collection and records read-only show commands (routes,
  VLANs, interfaces, neighbors). It uses the Plexus service credential - the
  same one background monitoring uses - and is skipped, with a collection
  warning, if none is configured.

### Scope and speed

Meraki limits the Dashboard API to 10 requests per second per organization.
A collection needs roughly 10-15 calls per network plus 1-3 per device, so
an organization with hundreds of sites takes several minutes. To shorten it,
limit collection to networks with certain tags or names, or turn off data you
do not need (per-device LLDP/CDP and live port status are the most expensive)
in the organization's settings. Lower *API requests per second* if other
tools share the organization's API budget.

Endpoints that do not apply to a network (for example VLANs on a network with
VLANs disabled) are skipped silently. Anything else that fails - such as an
endpoint the key lacks access to - is counted as a collection warning and the
collection is marked *partial*; the rest of the data is still used.

## Collection history

Every collection is saved as a snapshot (the 10 most recent per organization
are kept), listed under **Collection history** in the Meraki dialog. The map always uses
the newest one; deleting it falls back to the one before. Viewing the map,
searching and exporting never contact Meraki.

## HTML export

**HTML** downloads the current view - inventory devices and their discovered
links plus, for *All groups*, every Meraki organization - as one
self-contained interactive file: pan and zoom, search, click-through details
for every device, site and link, layer toggles, and a build report. For
inventory devices it embeds the interfaces, VLANs, neighbors and route table
Plexus has collected.

No internet access, Plexus login, or web server is needed to open the file,
so it can be emailed or placed on a file share. It contains addressing and
firewall rules, so treat it as sensitive network documentation. It never
contains the API key, pre-shared keys, or VPN/RADIUS shared secrets.

| Action in the exported file | How |
|---|---|
| Pan / zoom | Drag the background; mouse wheel, pinch, `+` / `-` |
| Fit everything | **Fit** or `F` |
| Zoom to a site or device | Double-click it, or pick it in the Sites list |
| Open details | Click a device, link, WAN uplink, VPN peer, or site |
| Search | Type in the search box (`/` focuses it), `Enter` zooms to matches |
| Show one source | The source selector next to the counts (**All sources**, **Inventory only**, **All integrations**, **AWS only**...) |
| Show or hide link types | **Layers** |
| Light / dark | **Theme** |
| Statistics and collection warnings | **Report** |

The export is laid out like the Topology page's **Tidy tree**, by the same
code: a region per source side by side, each network a tree in boxes of its
own that do not overlap, and the links between sources routed around the
other sites and over the regions. Positions you have pinned on the Topology
page are not carried over. The layout code comes from the frontend build
(`viewer-layout.js` in `frontend/dist`); a Plexus whose frontend was never
built exports the older layout, with the sites packed in a grid.

The file always holds every source; its source selector works like the one on
the Topology page. One source is laid out again on its own, recounts the
sites, devices and tunnels in the header, and limits search and Path to what
it shows. The selector appears only when the export includes an integration.

## API reference

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/topology` | Topology graph; Meraki nodes carry `source: "meraki"` and a `meraki` reference |
| `GET` | `/api/topology/search/deep?q=` | Search collected Meraki detail; returns node references and snippets |
| `GET` | `/api/topology/export.html` | Interactive HTML map (`?group_id=`, `?download=1` to save) |
| `GET` | `/api/meraki/nodes?org_ref=&node_id=` | Detail sections for one Meraki node |
| `GET` | `/api/meraki/orgs` | List organizations and default collection options |
| `POST` | `/api/meraki/orgs` | Add an organization (admin) |
| `PUT` / `DELETE` | `/api/meraki/orgs/{id}` | Edit / delete an organization (admin) |
| `POST` | `/api/meraki/orgs/{id}/validate` | Test the stored key, list visible organizations (admin) |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id` |
| `GET` | `/api/meraki/builds/{job_id}` | Collection progress and result |
| `POST` | `/api/meraki/sample` | Add / refresh the demo organization |
| `GET` | `/api/meraki/snapshots` | List snapshots (`?org_ref=` to filter) |
| `GET` | `/api/meraki/snapshots/{id}/data` | Snapshot as JSON |
| `GET` | `/api/meraki/snapshots/{id}/warnings` | Collection warnings of a snapshot (scope, request, HTTP status, message) |
| `DELETE` | `/api/meraki/snapshots/{id}` | Delete a snapshot |
