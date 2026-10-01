# Cato Networks in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include a Cato Networks
account alongside the devices Plexus discovers itself and any Meraki
organizations. Cato sites, Sockets, WAN links, the PoPs they connect to and
the connected remote users appear on the same map, are covered by the same
search box and Path Mode, and are included in the HTML export.

A Cato account is handled like a Meraki organization: it is added, collected
and deleted from the same dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage accounts and API keys
- API: `/api/meraki/*` with `provider: "cato"`

## Quick start

1. Open **Network → Topology** and click **Meraki / Cato** in the toolbar.
2. **Preview without a key.** Click **Load Cato Sample**. A demo account is
   added to the map. Delete it from the same dialog when you are done.
3. **Add your account.** Click **Add Cato Account** and enter a name, the
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
  restricted to source IP addresses, allow the Plexus server.

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
| **Cato Cloud** box | The PoPs in use, joined to one **Cato Cloud** backbone node |
| PoP (hexagon) | A PoP that at least one site or remote user is connected to |
| **Remote users (N)** (star) | The remote users connected when the collection ran, as one node |
| Dashed tunnel | A Socket's tunnel to its PoP, and each PoP's link to the backbone |

A site that is disconnected keeps a red (down) tunnel to the **Cato Cloud**
node so it stays attached to the map.

Remote users are one node, not one node per user: the users are listed in the
node's details (name, email, device, VPN IP, public IP, PoP, location, OS,
client version) and found by the search box.

### Device details

Click a Socket for its tabs:

- **Device**: name, status, model, serial, HA role, Socket version, PoP
- **Interfaces**: WAN links (port, PoP, public IP, provider, uptime) and the
  site's interface list with bandwidth
- **VLANs**: the site's network ranges (subnet, name, interface, VLAN)
- **VPN**: IPsec tunnel settings, for an IPsec site

Click a PoP for the sites and the number of remote users connected to it, and
the **Cato Cloud** node for the account summary.

### Search and Path Mode

The toolbar search covers everything collected: site names, serials, public
IPs, subnets, PoP names, and remote users by name, email, device or VPN IP.

In **Path Mode** a Cato site or one of its subnets can be picked like a
Meraki one. A path between two Cato sites runs Socket → PoP → Cato Cloud →
PoP → Socket, and a site whose tunnel is down is not routed through.

A path is only drawn over links on the map. Plexus does not know that a Cato
Socket and a Meraki switch at the same location are cabled together unless
one of them reports the other as a neighbor, so a path between a Meraki
subnet and a Cato subnet may show as "no path".

A Cato site that connects to AWS is joined to the AWS side of the map by
public address: a vSocket to its instance, an IPsec site to the AWS VPN
gateway it terminates on. See [aws-topology.md](aws-topology.md).

## What is collected

| Data | Cato API query | Option |
|---|---|---|
| Sites, Sockets, WAN links, PoP, HA state | `accountSnapshot` (sites) | always |
| Connected remote users | `accountSnapshot` (users) | Remote users |
| Network ranges and LAN interface subnets | `entityLookup` (`siteRange`, `networkInterface`) | Network ranges |

A collection is a handful of queries, sent one at a time and spaced out to
stay inside Cato's API rate limits. A rate-limit answer is retried after a
pause.

The site list is required. Everything else is best-effort: if a query fails,
the collection finishes as **partial**, the map is still built, and the
failure with Cato's own error message is listed under **Report** in the HTML
map. If Cato refuses the detailed site query, Plexus falls back to a reduced
one, so the sites still appear, without WAN links and HA state.

Only users connected at collection time are read. Their traffic, the
firewall and routing policy of the account, and hosts behind a site are not
collected.

## API reference

A Cato account uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for Cato |
|---|---|---|
| `GET` | `/api/meraki/orgs` | Each entry has `provider` (`meraki` or `cato`); `cato_default_options` lists the Cato collection options |
| `POST` | `/api/meraki/orgs` | `{"name", "provider": "cato", "org_id": "<account ID>", "api_key", "base_url"?, "options"?}` (admin) |
| `POST` | `/api/meraki/orgs/{id}/validate` | Runs one query against the account (admin) |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id` |
| `POST` | `/api/meraki/sample?provider=cato` | Add / refresh the demo Cato account |
| `GET` | `/api/topology` | Cato nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `cato` |
