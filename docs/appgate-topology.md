# Appgate SDP in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include an Appgate SDP
collective alongside the devices Plexus discovers itself and the other
sources. The collective's sites, Gateways, Controllers, Portals, LogServers
and Connectors, and the users connected with the Appgate Client, appear on
the same map, are covered by the same search box and Path Mode, and are
included in the HTML export, IPAM and the Software page.

An Appgate collective is handled like a Palo Alto Panorama: it is added,
collected and deleted from the same dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage entries and passwords
- API: `/api/meraki/*` with `provider: "appgate"`

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without credentials.** Click **Load Sample**, then **Appgate
   SDP**. A demo collective is added to the map. Delete it from the same
   dialog when you are done.
3. **Add your collective.** Click **Add Source**, then **Appgate SDP**, and
   enter a name, the Controller address, the identity provider, the admin
   user name and its password.
4. **Check the login.** Click **Test Login**. It signs in, reads the number
   of sites and appliances, signs out and reports what the Controller
   answered (`Login OK: Appgate SDP peer v22, 3 sites, 8 appliances`).
5. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection until you run another.

### Credentials

- **Controller address**: the admin interface of any Controller of the
  collective, `https://host[:port]` (usually port 8443). Plexus adds
  `/admin`; a trailing `/admin` you type is dropped. Only `https` is
  accepted, no path or query, and redirects are never followed, so the
  password cannot be sent elsewhere. Turn off **Verify TLS** for a
  Controller with a self-signed certificate.
- **Identity provider**: the identity provider the admin user signs in
  with (`local` by default, the built-in local database).
- **Username** and **Password**: an admin user whose admin role can read
  the collective (a role with the **View** privilege on appliances, sites,
  policies, entitlements, conditions, ringfence rules, IP pools, identity
  providers, global settings, the licence and the session information is
  sufficient). Plexus only reads: it never changes the collective.
- **MFA must be disabled for this API user.** The admin login API has no
  second factor, so a user that is asked for one cannot be used: the test
  says *the API user must be exempt from admin MFA*.

The password is stored encrypted and is never returned by the API or shown
in the UI again. The token the login answers with is kept in memory for the
collection only, sent only in the `Authorization` header, and the session is
signed out when the collection ends. Plexus signs in with a device ID that
is the same for every collection of one Controller and user, so the
collective sees one admin device.

The peer API version is read from `/admin/version` and the newest one both
sides speak is used (peer v17 to v25; an older or newer Controller is refused with its version).

## On the map

Appgate data appears when the group filter is **All groups**.

| On the map | What it is |
|---|---|
| Site box | One Appgate site, named as in Appgate |
| Gateway (firewall icon) | Each Gateway of the site, by name. Gateways of a site are active/active: the first one shows the site's details and owns its network ranges in Path Mode and IPAM |
| Controller, Portal, LogServer, Connector | The other appliances of the site, in the same box (an appliance with several roles is named after all of them, `Appgate Controller / LogServer`) |
| **Appgate SDP** box | The **Appgate Collective** node, and the appliances that belong to no site |
| Management link | Each appliance's link to the collective: **Appgate Controller** for a Controller, **Appgate peer link** for the rest, red when the appliance is offline. It carries no traffic and Path Mode ignores it |
| **Appgate clients** box | One person icon per user connected with the Appgate Client when the collection ran, labelled with the user name (and the device when two sessions share a name) |
| Dashed tunnel | **Appgate tunnel**: one from each user to each Gateway it has a tunnel to |

A Gateway's colour follows its health: healthy is online, warning or busy is
alerting, error or offline is offline. A suspended Gateway (it takes no new
sessions) is alerting, and an appliance that is not activated is unknown.

Without the per-user access details (turned off, or past the
500-user cap) a user is drawn without its tunnel address and linked to the
collective node, since which Gateways it uses is not known.

### Device details

Click a Gateway for its tabs:

- **Device**: name, roles, site, health and its details, appliance and
  peer version, client and admin interface, sessions, CPU, memory and disk,
  whether it is activated or suspended
- **Interfaces**: each NIC address with its subnet, DHCP and SNAT; the
  **Allowed destinations** of a Gateway that limits where clients may go
- **Routing**: the configured static routes
- **VLANs**: the site's **Network ranges** (its network subnets, with the
  comment after `#` as the name, and the networks of its Gateways'
  interfaces), **Protected resources** (every host of the site's
  entitlements) and **Name resolution** (DNS, AWS, Azure, GCP and ESX
  resolvers)
- **Firewall**: the **Entitlements** of the site, one row per action, with
  the conditions and the policies that grant each one
- **VPN**: the **Connected users**, with their tunnel address, public
  address, client, OS, connection time and how many of their entitlements
  the Gateway grants

Click a user for who it is (identity provider, device, OS, client version),
where it connects from (public address, coordinates), which Gateways and
sites it is connected to with its tunnel address and policies, the
**Entitlement results** (which entitlements it holds, and how each condition
came out) and the **Firewall rules** each Gateway applies to it.

Click the **Appgate Collective** node for the collective summary (name,
peer version, counts, licence) and the tables of every appliance, site,
policy, entitlement, condition, ringfence rule, IP pool and identity
provider.

### Search and Path Mode

The toolbar search covers everything collected: appliance names and
addresses, site names and subnets, entitlement names, and users by name,
device, tunnel address or public address.

In **Path Mode** a site's network ranges can be picked like any subnet, and
a user like any device. A trace from a user runs **user → Gateway**: the
user routes what its entitlements cover (the subnets of its Appgate firewall
rules) to the Gateway that grants them, and the Gateway applies the
**Entitlements** rule set of its site, first match wins:

- a rule's sources are the tunnel addresses of the connected users that hold
  the entitlement on that Gateway, its destinations the entitlement's hosts,
  its protocol and ports those of the action (`tcp_up 443`); a `*_down`
  action is the same rule from the resource to the users
- what no entitlement allows is blocked (**the default action denies it**)
- a host that is a name (`intranet.acme.example`, `dns://...`, `aws://...`)
  cannot be matched on addresses: a flow it may cover is *unknown*
- an entitlement no connected user holds has no rule; the Gateway lists it
  as a note
- without the per-user access details any user may hold an entitlement: the
  rule says so (*users granted by policy*, and each condition), and the
  trace is *unknown* where it matches

The Gateway routes the replies back over the tunnel by a `/32` route to each
user's tunnel address. Traffic a user sends that no entitlement covers has
no route on the user (the Appgate Client splits the tunnel and sends it out
directly), so a trace to the internet ends at the user with *No route*,
unless a site is the user's default gateway. When a site translates client
addresses (**SNAT to gateway**), the Gateway hides the IP pool behind its
own address; when it does not, the Gateway notes that the site must route
the pool back to it. See [path-trace.md](path-trace.md).

The network ranges of every site also appear on the **IPAM** page as
subnets of source **topology**. The users, their IP pool and the collective
own no subnet. The Software page lists every appliance under platform
**Appgate SDP appliance**.

## What is collected

| Data | Admin API (`/admin/...`) | Option |
|---|---|---|
| Peer API version, sign-in | `GET /version`, `POST /login`, `POST /logout` | always |
| Appliances, their roles, NICs, routes, Connector clients | `GET /appliances` | always |
| Sites, network subnets, name resolution | `GET /sites` | always |
| Collective name, licence | `GET /global-settings`, `GET /license` | always |
| Appliance and site health, versions, sessions | `GET /appliances/status` (`/stats/appliances` before 6.3), `GET /sites/status` | Appliance health and sessions |
| Policies, entitlements, conditions, ringfence rules | `GET /policies`, `/entitlements`, `/conditions`, `/ringfence-rules` | Policies and entitlements |
| IP pools, identity providers | `GET /ip-pools`, `GET /identity-providers` | always |
| Connected users | `GET /stats/active-sessions/dn` (`/on-boarded-devices` on an older Controller) | Connected users |
| Per-user access: Gateways, tunnel address, entitlements, firewall rules | `GET /session-info/{dn}`, one call per user, 500 users at most | Per-user access details |

**Only sites named like** limits the build to the sites whose name holds
that text; the appliances of those sites, those of no site and every
Controller are kept.

Calls are sent one at a time and spaced out, so a collection does not load
the Controllers. A rate-limit or server error answer is retried after a
pause (honouring `Retry-After`); an expired token is replaced by signing in
again, once; a refusal for lack of privilege is not retried.

The version, the login, the appliances and the sites are required.
Everything else is best-effort: if a call fails, the collection finishes as
**partial**, the map is still built, and the failure with Appgate's own
error message is listed under **Report** in the HTML map. On a Controller
that has no active session list, the on-boarded devices are drawn instead,
as *registered, connection unknown*.

Secrets are never stored: appliance certificates (`httpsP12`), SSH, SNMP
and metrics exporter settings, log forwarder destinations, the credentials
of a site's cloud resolvers and the bind passwords, shared secrets, client
secrets and keys of identity providers are dropped before the snapshot is
saved. The users' traffic, the claims of their devices beyond what
`session-info` reports, and hosts behind a site are not collected.

## API reference

An Appgate collective uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for Appgate |
|---|---|---|
| `GET` | `/api/meraki/orgs` | Each entry has `provider`; `appgate_default_options` lists the Appgate collection options |
| `POST` | `/api/meraki/orgs` | `{"name", "provider": "appgate", "org_id": "<identity provider>", "base_url": "https://controller:8443", "api_key": "<password>", "options": {"username", ...}}` (admin) |
| `POST` | `/api/meraki/orgs/{id}/validate` | Signs in and counts sites and appliances (admin); needs `options.username` |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id` |
| `POST` | `/api/meraki/sample?provider=appgate` | Add / refresh the demo Appgate collective |
| `GET` | `/api/topology` | Appgate nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `appgate` |

The options are `username`, `verify_tls`, `site_name_contains`,
`include_appliance_state`, `include_entitlements`, `include_users`,
`include_session_details` and `inventory_enrich`.
