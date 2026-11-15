# OPNsense in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include an OPNsense firewall
alongside the devices Plexus discovers itself and the other sources. The
firewall, its gateways and its VPN tunnels appear on the same map, are
covered by the same search box and Path Mode subnet list, and are included
in the HTML export, IPAM, availability tracking, Config Backups and the
Software page.

An OPNsense firewall is handled like an Appgate SDP collective: it is added,
collected and deleted from the same dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

This is phase 1 of the integration: it only reads. It never changes the
firewall, and firewall rules, NAT and the hop by hop path trace through the
firewall are not part of it yet (see [Limits](#limits)).

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage entries and API keys
- API: `/api/sources/*` with `provider: "opnsense"`

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without credentials.** Click **Load Sample**, then
   **OPNsense**. A demo firewall named *Sample OPNsense firewall (demo data)*
   is added to the map. Nothing is contacted. Delete it from the same dialog
   when you are done.
3. **Create an API key** on the firewall (see [Credentials](#credentials)).
4. **Add your firewall.** Click **Add Source**, then **OPNsense**, and enter
   a name, the firewall address and the API key and secret. Adding goes on by
   itself to checking the credentials, the first collection and an offer to
   import the firewall into the inventory; see
   [After adding a source](meraki-topology.md#after-adding-a-source).
5. **Check the key.** **Test Login** reads the firewall's system
   information and reports its name and version
   (`API key OK: fw1.example.com (OPNsense 25.7.6-amd64)`).
6. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**, and on a schedule (hourly by
default) as described in [Scheduled collection](meraki-topology.md#scheduled-collection).

## Credentials

- **Address**: the firewall's web GUI, `https://host[:port]`, for example
  `https://fw1.example.com` or `https://192.0.2.1:8443`. Plexus adds `/api`;
  a trailing `/api` you type is dropped. Only `https` is accepted, no path,
  query or user name, and redirects are never followed, so the key cannot
  be sent elsewhere. Turn off **Verify TLS** for a firewall with a
  self-signed certificate.
- **API key and secret**: entered as one value, `<API key>:<API secret>`.
  Plexus splits it on the first colon; a value without a key or without a
  secret is refused. OPNsense checks them with HTTP Basic authentication
  (the key is the user name, the secret the password). The value is stored
  encrypted, is never returned by the API or shown in the UI again, and is
  sent only in the `Authorization` header. When you edit the source, leave
  the field empty to keep the stored key.
- The organization field is not used; it is stored as `local`.

### Creating the API key

1. On the firewall, open **System → Access → Users** and add a user for
   Plexus (for example `plexus-readonly`) with a long random password it
   never uses.
2. Give it only the privileges below (**Effective Privileges**, or a group
   that has them). OPNsense has no read-only API role: each privilege opens
   a page and its API calls, including the calls that change it. Plexus only
   sends the read calls listed under [What is collected](#what-is-collected),
   plus the one call that starts the security audit.
3. In the user's **API keys** section, click **+** to create a key. The
   browser downloads a file with the key and the secret. Enter them in
   Plexus as `key:secret`.

| Privilege (OPNsense name) | What Plexus reads with it |
|---|---|
| Lobby: Dashboard | system information (host name, version strings) |
| System: Firmware | firmware status, pending updates, the security audit |
| Status: Interfaces | interfaces, addresses, link state, VLAN tags |
| System: Gateways | gateway status (loss, delay, deviation) |
| Diagnostics: Routing tables | the routing table |
| Status: IPsec | IPsec connections and their state |
| VPN: WireGuard: Status | WireGuard peers and their latest handshake |
| Status: OpenVPN | OpenVPN instances and connected clients |
| Diagnostics: Configuration History | the config.xml download (only with **Config backup** on) |

Two of these privileges allow more than reading, and a stolen key could use
them:

- **System: Firmware** also allows starting an update or a reboot. Plexus
  needs it for the firmware status and the audit. Leave it out if you do not
  accept that: the version is still read from the system information, and
  the firmware status and audit become warnings.
- **Diagnostics: Configuration History** also allows reverting to an older
  configuration, and the download holds every secret of the firewall. Leave
  it out and turn **Config backup** off if you do not accept that.

A missing privilege makes its call answer HTTP 403. The collection goes on
and finishes as **partial** with a warning that names the call and says the
API user lacks the privilege, so you can add it and collect again.

### Supported releases

The calls and answers were checked against the OPNsense core source of the
24.7, 25.1 and 25.7 releases and the current development branch, and the
API reference at docs.opnsense.org. OPNsense 24.7 or later is supported.

From 25.7 OPNsense names its API calls in `snake_case`
(`diagnostics/interface/get_routes`) and its privileges match that form;
24.7 to 25.1 use `camelCase` (`getRoutes`). Plexus asks for the newer form
first and, when the firewall refuses it (403) or does not know it (404),
asks for the older one. On an older release a call that does not exist
answers 404 and becomes a warning naming that call; the rest is collected.
A call of a plugin that is not installed does the same.

## On the map

| On the map | What it is |
|---|---|
| Site box | The firewall, named after the source entry, with its gateways and OpenVPN servers |
| Firewall | The firewall itself (`d:<host name>`), with the API address when that is an IP address, else its LAN address |
| Gateway (WAN) stub | Each gateway (`w:<name>`), joined to the firewall by a **Gateway** uplink |
| OpenVPN server | Each OpenVPN server instance (`ovpn:server:<id>`): online when it runs, offline when it is enabled but not running |
| **VPN peers** box | The far end of each IPsec connection, WireGuard peer and OpenVPN client instance |
| Dashed tunnel | **IPsec**, **WireGuard** or **OpenVPN**, from the firewall to the peer |

A gateway uplink's status follows the gateway's monitor (`dpinger`):
`active` when it reports no alarm, `degraded` for a latency or loss alarm,
`failed` when the gateway is down or forced down, `unknown` when OPNsense
has no monitor data for it (monitoring off, or the state is still pending).

A tunnel is `reachable` (up), `degraded` or `unreachable` (down):

| Tunnel | Up | Degraded | Down |
|---|---|---|---|
| IPsec | the connection has an SA | | no SA |
| WireGuard | latest handshake within 5 minutes (OPNsense's *online*) | handshake older than that (*stale*) | no handshake (*offline*) |
| OpenVPN client | `connected` | any other state (reconnecting, waiting, authenticating) | not running |

A WireGuard peer that is a road warrior (a laptop or phone) is down while it
is not connected. Mute it under **Monitoring > Availability** if that is
expected (see [Muting](meraki-topology.md#muting)).

### Device details

Click the firewall for its sections:

- **Overview**: name, product, version, latest version, series,
  architecture, whether an update is pending, host name, OS and OpenSSL
  versions, address
- **Interfaces**: each interface with its description, device, status,
  enabled, IPv4 and IPv6 addresses, VLAN tag, MAC address, IPv4 type and
  gateways
- **Connected subnets**: the networks of the enabled interfaces' addresses
- **Gateways**: each gateway with its address, status, state, monitor
  address, RTT, RTT deviation and loss
- **Static routes**: the gateway routes of the routing table (flags `G` and
  `S`, not the default route)
- **Routing table**: the whole routing table, 2000 rows at most
- **IPsec tunnels**, **WireGuard peers**, **OpenVPN instances**: the tunnels
  and their state
- **Firmware**: version, latest version, whether an update is pending, the
  status message, packages to update, reboot required, major upgrade, last
  check
- **Pending updates**: the packages of the pending update
- **Security audit** and **Vulnerable packages**: the result of the audit
- **Config backup**: what the collection did with config.xml
- **Plexus inventory**: the inventory host the firewall matched

Click a gateway stub for its **Gateway** details, a peer for its **IPsec
peer**, **WireGuard peer** or **OpenVPN peer** details, and an OpenVPN
server for its **OpenVPN server** details and **Connected clients**.

### Search, Path Mode and IPAM

The connected subnets and static routes join the subnet index, so they can
be picked in **Path Mode** and appear on the **IPAM** page as subnets of
source **topology**, owned by the firewall. The firewall carries no
forwarding model yet, so a trace that reaches it stops there.

## Availability tracking

Each collection records the state of what it reports, shown under
**Monitoring > Availability > Integrations and cloud** with uptime, outages
and alerts, the same way as for every other source:

- the firewall and each OpenVPN server instance, as devices
- each gateway, as an uplink: `none` with monitor data is up, `delay`,
  `loss` and `delay+loss` are degraded, `down` and `force_down` are down,
  anything else (no monitor data, pending) is unknown
- each IPsec connection, WireGuard peer and OpenVPN client instance, as a
  tunnel, mapped as in the table above

The loss, RTT and RTT deviation of each gateway are in its details and in
the uplink's detail text at every collection. They are not stored as a
time series and no SLA target compares them. Gateway stubs and VPN peers are
not devices of their own. The state mapping, alerting, muting and retention
are described in [Meraki in the Topology Map](meraki-topology.md#availability-tracking).

A firmware update or an audit finding is added to the collection's
warnings, so the collection shows as **partial**, but such a warning does
not stop availability tracking from removing a tunnel or gateway the
firewall no longer reports.

## Config backup

With **Config backup** on (the default), each collection downloads the
firewall's `config.xml` (the newest entry of its configuration history,
which OPNsense writes at every save) and stores it as a configuration
backup of the inventory host that is this firewall. It then appears under
**Configuration > Config Backups** and in config drift like any other
backup. When the configuration has not changed since the newest backup, no
new backup is written; the newest one is marked as checked again.

The firewall is matched to its inventory host the way **Import devices**
matches it: the host with the firewall's address, or the host the
collection matched by address or name. **Import the firewall into the
inventory first** (the **Import devices** step after adding the source, or
**Sources > Import devices** later). Until then config.xml is read but not
stored, and the collection has a warning that says to import the firewall.

config.xml holds password hashes, private keys, certificates and
pre-shared keys. It is never put in the topology snapshot; it is only kept
in the Config Backups table, which is readable by users with the Config
Backups feature. Turn **Config backup** off if that is not wanted.

An imported firewall gets the device type `opnsense`. Plexus has no SSH
driver for OPNsense, so a backup policy does not read it over SSH: its
backups come from the OPNsense collection only. SNMP polling works through
the generic path once an SNMP profile is assigned to its group.

## Firmware and security audit

Each collection reads the firmware status of the last update check made on
the firewall (it never starts a new check). The firewall's version is
tracked on the **Software** page under platform **OPNsense**. When an
update is pending, the firewall's details say so and the collection gets a
warning naming the current and the latest version.

With **Firmware security audit** on (the default), each collection also
runs the firewall's built-in security audit (**System → Firmware → Status →
Run an audit**, `pkg audit -F`), waits for it (up to about 90 seconds) and
reads its result: every vulnerable installed package with its issue, CVE ids
and VuXML link. It is skipped, with a warning, when another firmware task is
running on the firewall. The findings are shown under **Security audit**
and **Vulnerable packages** and added to the collection's warnings.

Each finding also becomes a software advisory (source `opnsense-audit`,
named after its VuXML entry, platform **OPNsense**, affected version the
firewall's version, with its CVE ids and link). Repeated collections update
the same advisory instead of adding another, so the Software page raises one
alert per advisory and firewall, with the usual notifications. When the
audit no longer reports a finding, the firewall's version is taken off the
advisory and its alert resolves. `pkg audit` gives no severity, so a new
advisory is `medium`; a severity you change is kept. Two firewalls on the
same version share the advisories found on either, since advisories match
by platform and version.

## What is collected

| Data | API call (`/api/...`) | Option |
|---|---|---|
| Host name, version strings | `GET diagnostics/system/system_information` (`systemInformation`) | always |
| Product, version, pending updates | `GET core/firmware/status` | always |
| Interfaces, addresses, link state, VLAN tags | `GET interfaces/overview/interfaces_info` (`interfacesInfo`) | always |
| Gateways: status, loss, delay, deviation | `GET routes/gateway/status` | Gateways |
| IPsec connections | `GET ipsec/sessions/search_phase1` (`searchPhase1`) | VPN tunnels |
| WireGuard peers | `GET wireguard/service/show` | VPN tunnels |
| OpenVPN instances and clients | `GET openvpn/service/search_sessions` (`searchSessions`) | VPN tunnels |
| Routing table | `GET diagnostics/interface/get_routes` (`getRoutes`) | Routing table |
| Security audit | `GET core/firmware/running`, `POST core/firmware/audit`, `GET core/firmware/upgradestatus` | Firmware security audit |
| config.xml | `GET core/backup/download/this` | Config backup |

The options are `verify_tls`, `include_gateways`, `include_vpn`,
`include_routes`, `include_firmware_audit`, `config_backup` and
`inventory_enrich`, all on by default.

Calls are sent one at a time and spaced out. A rate-limit or server error
answer is retried after a pause (honouring `Retry-After`); a refused call is
not retried. A rejected key (401) or a firewall that cannot be reached fails
the collection with a message saying so. Every other failed call becomes a
warning and the rest is collected.

Secrets are never put in the snapshot: the interface rows keep only their
description, enable flag, address type, address, prefix, MTU and gateway
(not the rest of the interface configuration OPNsense attaches), the
firmware status keeps its product and update fields (the mirror and the
licence details are dropped, a business licence keeps its expiry), and
keys named like secrets, passwords or pre-shared keys are dropped
everywhere.

## Limits

Not in phase 1:

- firewall rules, aliases and NAT, and the hop by hop trace through the
  firewall in Path Mode (the firewall has no forwarding model yet)
- IPsec phase 2 entries (the per connection child SAs; the state is read
  per connection)
- loss and latency history of gateways and SLA targets on them
- CARP and high availability state
- any change to the firewall: Plexus never applies updates, reboots or
  edits anything

## API reference

An OPNsense firewall uses the source endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for OPNsense |
|---|---|---|
| `GET` | `/api/sources` | Each entry has `provider`; `opnsense_default_options` lists the OPNsense options |
| `POST` | `/api/sources` | `{"name", "provider": "opnsense", "base_url": "https://fw1.example.com", "api_key": "<key>:<secret>", "options": {...}}` (admin). 400 when the key or the secret is missing |
| `PUT` | `/api/sources/{id}` | Omit `api_key` to keep the stored one (admin) |
| `POST` | `/api/sources/{id}/validate` | Reads the system information (admin) |
| `POST` | `/api/sources/{id}/build` | Start a collection; returns `job_id` |
| `POST` | `/api/sources/sample?provider=opnsense` | Add or refresh the demo firewall |
| `GET` | `/api/topology` | OPNsense nodes carry a `meraki` reference whose `provider` is `opnsense` |
