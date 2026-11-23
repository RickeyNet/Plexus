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
  self-signed certificate. The address passes the
  [outbound address check](webhooks.md#outbound-address-check) when saved
  and when a collection connects: a cloud metadata address and a name that
  does not resolve are refused, private addresses too when
  `APP_SSRF_BLOCK_PRIVATE=true` (list the firewall in `APP_SSRF_ALLOW`). A
  refusal fails the collection like a firewall that cannot be reached.
- **API key** and **API secret**: two fields. The `apikey.txt` file
  OPNsense downloads holds them as `key=...` and `secret=...` lines; enter
  only the values, without the `key=` / `secret=` labels; **Show** beside
  each field displays what you typed so you can check it. Both are required
  when adding the source. OPNsense checks them with HTTP Basic
  authentication (the key is the user name, the secret the password).
  Plexus stores them together, encrypted, never returns them through the
  API or shows them again, and sends them only in the `Authorization`
  header. When you edit the source, leave both fields empty to keep the
  stored key. Through the API (`POST /api/sources`), the
  credential is one value, `<API key>:<API secret>`, split on the first
  colon.
- **"OPNsense rejected the API key and secret (HTTP 401)"** means the
  firewall does not recognise the pair: a `key=` / `secret=` label pasted
  in, key and secret swapped, a value cut short, or the key deleted, or its
  user disabled or expired, on the firewall. A missing privilege answers 403
  instead and is reported per call.
- The organization field is not used; it is stored as `local`.

### Creating the API key

1. On the firewall, open **System → Access → Users** and add a user for
   Plexus (for example `plexus-readonly`) with a long random password it
   never uses.
2. Give it only the privileges below (**Effective Privileges**, or a group
   that has them). OPNsense has no read-only API role: each privilege opens
   a page and its API calls, including the calls that change it. Plexus only
   sends the read calls listed under [What is collected](#what-is-collected),
   plus the one call that starts the security audit (the IPsec phase 2
   search and the IDS alert search are a `POST` too, but they only read:
   OPNsense takes the connection or the page from the request body).
3. In the user's **API keys** section, click **+** to create a key. The
   browser downloads a file with the key and the secret. Enter them in
   Plexus's **API key** and **API secret** fields.

| Privilege (OPNsense name) | What Plexus reads with it |
|---|---|
| Lobby: Dashboard | system information (host name, version strings); with **Health and services**: memory, file systems, temperature, uptime and load, the state table |
| System: Firmware | firmware status, pending updates, the security audit |
| Status: Interfaces | interfaces, addresses, link state, VLAN tags |
| System: Gateways | gateway status (loss, delay, deviation) |
| Diagnostics: Routing tables | the routing table |
| Status: IPsec | IPsec connections and their state, and their installed child SAs (phase 2) |
| VPN: IPsec: Connections | the child SAs configured for each connection (only with the "Connections" model, 23.1+) |
| Status: CARP | CARP virtual IPs, their state, demotion and maintenance mode |
| VPN: WireGuard: Status | WireGuard peers and their latest handshake |
| Status: OpenVPN | OpenVPN instances and connected clients |
| Diagnostics: Configuration History | the config.xml download: by the collection with **Config backup** on, and by a [backup policy](#config-backup) of the firewall's group whatever that option says |
| Firewall: Rules (the privilege that lists `api/firewall/filter_util/*`) | the filter rule counters (only with **Rule counters** on; 24.1+) |
| Diagnostics: PF Table IP addresses (`api/firewall/alias_util/*`) | the pf tables of the aliases `config.xml` cannot resolve, for path tracing (only with **Alias tables** and **Config backup** on) |
| Diagnostics: ARP Table | the ARP table (only with **ARP, NDP and DHCP leases** on) |
| Diagnostics: NDP Table | the NDP (IPv6 neighbour) table (same option) |
| Diagnostics: System Activity | the header lines of `top`, for the CPU use (only with **Health and services** on) |
| Status: Services | the services and whether each runs (same option) |
| System: Trust: Certificates | the certificates and their expiry (only with **Certificates** on; 24.7+) |
| System: Trust: Authorities | the certificate authorities and their expiry (same option) |
| Services: Intrusion Detection (`api/ids/*`) | whether the IDS is enabled, its alerts and the classtype of each alerting rule (only with **IDS alerts** on) |
| Status: DHCP leases / Status: DHCPv6 leases | ISC DHCP leases (same option; only if the firewall runs ISC DHCP) |
| Services: DHCP: Kea(v4) / Services: DHCP: Kea(v6) (`api/kea/leases4/*`, `api/kea/leases6/*`) | Kea DHCP leases (same option; only if the firewall runs Kea; the v6 privilege is 25.1+) |
| Services: Dnsmasq DNS/DHCP: Settings (`api/dnsmasq/*`) | Dnsmasq DHCP leases (same option; 25.1+, only if the firewall runs Dnsmasq DHCP) |

The ARP, NDP and lease privileges also allow flushing the ARP / NDP table
or deleting a lease, and **Status: Services** allows starting, stopping
and restarting a service; Plexus never sends those calls. A refused lease
call names the privilege it needs.

OPNsense has no privilege for the Kea or Dnsmasq leases alone:
**Services: DHCP: Kea(v4)**, **Services: DHCP: Kea(v6)** and
**Services: Dnsmasq DNS/DHCP: Settings** are the privileges of the whole
service, so they also allow changing its settings, subnets, reservations
and ranges and restarting it. Plexus only sends the lease search. Grant
them only for a DHCP service the firewall runs. For one it does not run
you need nothing: with **Config backup** on, Plexus reads from
`config.xml` whether Kea DHCPv4, Kea DHCPv6 and Dnsmasq DHCP are enabled
(Dnsmasq: enabled with at least one DHCP range) and drops the refused
(403) lease read of a service that is off, so it is no warning. With
**Config backup** off, or the download refused, Plexus cannot tell and the
refused read stays a warning. A refused ISC DHCP lease read always warns.

**Diagnostics: PF Table IP addresses** also allows adding an address to a
table, deleting one and flushing a table. Plexus only lists the tables and
reads their entries; it never sends those calls, nor the bogon update.
Leave the privilege out (or turn **Alias tables** off) if you do not accept
that: the aliases it would resolve stay unresolved in the trace.

**System: Trust: Certificates** and **System: Trust: Authorities** also
allow creating, importing, deleting and downloading certificates, private
keys included, and the search Plexus reads answers with every field of each
certificate, its private key too. Plexus keeps only the fields listed
under [Certificates](#certificates) and drops the rest as soon as the
answer arrives; it never sends the other calls. Leave both out (or turn
**Certificates** off) if you do not accept that: certificate expiry is then
not tracked.

**Services: Intrusion Detection** is the only IDS privilege: it also
allows changing the IDS settings and rules, updating and reloading the
rule sets, starting and stopping Suricata and deleting its alert logs.
Plexus only reads the service status, the alert search and the rule of a
signature (see [IDS alerts](#ids-alerts)); it never sends the other calls.
Leave it out (or turn **IDS alerts** off) if you do not accept that.

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
| **HA** link, shared box | The two firewalls of a CARP pair when both are sources (see [CARP pairs](#carp-pairs)) |

A gateway uplink's status follows the gateway's monitor (`dpinger`):
`active` when it reports no alarm, `degraded` for a latency or loss alarm,
`failed` when the gateway is down or forced down, `unknown` when OPNsense
has no monitor data for it (monitoring off, or the state is still pending).

A tunnel is `reachable` (up), `degraded` or `unreachable` (down):

| Tunnel | Up | Degraded | Down |
|---|---|---|---|
| IPsec | the connection has an SA | an SA, but none of the connection's configured child SAs is installed | no SA |
| WireGuard | latest handshake within 5 minutes (OPNsense's *online*) | handshake older than that (*stale*) | no handshake (*offline*) |
| OpenVPN client | `connected` | any other state (reconnecting, waiting, authenticating) | not running |

A WireGuard peer that is a road warrior (a laptop or phone) is down while it
is not connected. Mute it under **Monitoring > Availability** if that is
expected (see [Muting](meraki-topology.md#muting)).

### CARP pairs

Each firewall of a CARP pair is a source of its own. When two OPNsense
sources both report the same VHID with the same virtual address, the map
draws them as one HA cluster: the two firewalls, their gateway stubs and
OpenVPN servers share one box named after both sources (for example
`Edge A / Edge B (CARP)`), and an **HA** link joins the two firewalls. A
firewall that is also an inventory host is drawn as that host, still in the
pair's box. The link is labelled with each firewall's role across the
shared VIPs (`MASTER`, `BACKUP`, or `mixed` when it holds different roles
on different VIPs) and is shown `active` when every shared VIP has exactly
one `MASTER`, and `failed` when one has two (a split brain) or none.

That status is for display only and raises no alert: the two firewalls are
collected at different times, so their roles can disagree for a moment
without anything being wrong. Alerts come from each firewall's own CARP
groups (see [Availability tracking](#availability-tracking)). When only one
firewall of a pair is a source, nothing changes. Three or more sources that
report the same VHID and address are not drawn as a pair, and neither is
one firewall added twice. The HTML export draws the pair the same way.

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
  and their state; an IPsec connection also shows its child SAs as
  `installed of configured` (for example `1 of 2 installed`)
- **High availability**: each CARP virtual IP with its interface, VHID,
  address, state (`MASTER`, `BACKUP`, `INIT`, `DISABLED`), advertisement
  base and skew, and the firewall's maintenance mode and CARP demotion. A
  VIP in `INIT` or a demotion other than 0 is an informational collection
  warning: the state itself is tracked per CARP group (see [Availability
  tracking](#availability-tracking)). The CARP peer is a firewall of its
  own, added as another source; when both are sources, the pair is drawn
  as one HA cluster (see [CARP pairs](#carp-pairs)) and the details name
  the peer as **CARP peer**
- **Health**: CPU, load average, memory, the fullest file system and every
  file system, the hottest temperature sensor and every sensor, the state
  table, uptime, how many services run and which are stopped, and where
  the numbers are kept (see [Health and services](#health-and-services))
- **Services**: each service the firewall's configuration enables, with
  its name and whether it runs
- **Firmware**: version, latest version, whether an update is pending, the
  status message, packages to update, reboot required, major upgrade, last
  check
- **Pending updates**: the packages of the pending update
- **Security audit** and **Vulnerable packages**: the result of the audit
- **ARP table**, **NDP table**: the firewall's neighbours (address, MAC,
  interface, host name), 2000 rows each at most
- **DHCP leases**: the leases of every DHCP server on the firewall (ISC,
  Kea, Dnsmasq) with their state, end time, interface, subnet and server
- **Clients**: the ARP, NDP and lease counts (per DHCP server) and what
  the collection stored in MAC tracking and IPAM (see
  [ARP, NDP and DHCP leases](#arp-ndp-and-dhcp-leases))
- **Names and reservations**: the DNS names and DHCP reservations read from
  config.xml and what the collection stored in IPAM (see
  [DNS names and DHCP reservations](#dns-names-and-dhcp-reservations))
- **Config backup**: what the collection did with config.xml
- **Route capture**: what the collection did with the routing table and
  the interface addresses (see
  [Routing table and live addresses](#routing-table-and-live-addresses))
- **Flow export**: whether Plexus receives NetFlow from the firewall (per
  flow type and source address: packets and last seen), the state of the
  flow collector and what the collection stored for it (see
  [NetFlow](#netflow))
- **Plexus inventory**: the inventory host the firewall matched

Click a gateway stub for its **Gateway** details, a peer for its **IPsec
peer**, **WireGuard peer** or **OpenVPN peer** details, and an OpenVPN
server for its **OpenVPN server** details and **Connected clients**. An
IPsec tunnel's details list its **Child SAs**: each installed child SA with
its state, local and remote networks, mode, encryption and traffic.

When the firewall runs an OpenVPN server, the firewall node lists **All
users**: every OpenVPN user Plexus has seen connected to any of its server
instances, connected now or not. OPNsense keeps no list of the users allowed
to connect, so the clients connected at collection time are recorded (the
user name, else the certificate's common name; the tunnel address; the public
address; the common name as the device when the user logged in with a user
name of their own), and a user seen by an earlier collection stays listed as
*disconnected*, with the last addresses seen, for 180 days after they were
last seen. The search box finds a user who is not connected right now there.

The installed child SAs are read per connection that has an SA
(`ipsec/sessions/search_phase2`), the configured ones per connection of the
"Connections" model (`ipsec/connections/search_child`; a legacy tunnel has
no configured count and is never shown degraded for its child SAs). When
either call is refused or unknown it is not repeated for the next
connection: one warning, and the tunnels keep their phase 1 state.

### Search, Path Mode and IPAM

The connected subnets and static routes join the subnet index, so they can
be picked in **Path Mode** and appear on the **IPAM** page as subnets of
source **topology**, owned by the firewall; its DNS names and DHCP
reservations are allocations under them (see
[DNS names and DHCP reservations](#dns-names-and-dhcp-reservations)). Once the firewall is an
inventory host with a config backup, Path Mode traces through it with its
interfaces, filter rules and NAT read from `config.xml` and the routes of
its collected routing table (see
[Firewall rules and path trace](#firewall-rules-and-path-trace)).

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
- each CARP group (one interface and VHID; several addresses on one VHID
  are one group), as a link named after the firewall, interface, VHID and
  addresses (`carp:<interface>:<vhid>`), on this firewall alone: `MASTER`
  and `BACKUP` are up (a standby is healthy), `DISABLED` is degraded (CARP
  is off on this node, so it gives no redundancy), `INIT` is down, and
  `MASTER` or `BACKUP` while the firewall's CARP demotion is not 0 or it is
  in maintenance mode is degraded; anything else is unknown. The role is
  the entity's status. A CARP group belongs to the firewall: it is alerted
  on the firewall's inventory host when it has one, and muting or removing
  the firewall covers it
- each service the firewall's configuration enables (unbound, the DHCP
  servers, Suricata, ...), as a service named after the firewall and the
  service (`svc:<name>[/<instance>]`): up while it runs, down when it does
  not. It belongs to the firewall like a CARP group (alerted on its
  inventory host, covered by muting or removing the firewall); see
  [Health and services](#health-and-services)
- each certificate in use and each CA a tracked certificate or a service
  depends on, as a certificate named after the firewall and the
  certificate (`cert:<refid>`, `ca:<refid>`): up while valid, degraded
  from 30 days before its end and once expired (never down: an expiring
  certificate is no downtime). It belongs to the firewall like a service,
  and alerts on its expiry, not on its state; see
  [Certificates](#certificates)

When a CARP group's role changes between `MASTER` and `BACKUP` from one
collection to the next, a failover warning is raised (on the inventory
host, else to the notification channels), naming the firewall, interface,
VHID, address and both roles. A failover is an event, not an outage: the
group stays up, and after a failover that does not preempt back, the new
arrangement is simply the new normal. A group seen for the first time, or
whose role comes from `INIT`, `DISABLED` or a collection that missed it,
raises no failover warning (the state alert covers it). Mutes apply to it.

The loss, RTT and RTT deviation of each gateway are in its details, and
are stored at every collection as the uplink's loss, latency and jitter
(the RTT deviation): raw samples for the monitoring retention, and one row
per day that is kept for the SLA retention (400 days by default). A gateway
with 100 % loss stores its loss only. The window means are shown per uplink
by `GET /api/availability/topology/summary`, the history by `GET
/api/availability/topology/metrics`, and SLA targets on latency, jitter,
packet loss or uptime can cover the gateways (a target with `provider`
`opnsense` and `entity_type` `uplink`; see [SLA
monitoring](sla-monitoring.md#targets-of-integration-entities)). They are
evaluated on the server at every SLA pass and alert into the monitoring
alerts or the notification channels. Gateway stubs and VPN peers are not
devices of their own. The state mapping, alerting, muting and retention
are described in [Meraki in the Topology Map](meraki-topology.md#availability-tracking).

### Tunnel traffic

Each tunnel and each OpenVPN server also has its traffic measured, from
the byte counters the firewall reports for it with the calls a collection
already makes:

| Entity | Counters read | Counter per |
|---|---|---|
| IPsec connection | `bytes-in` / `bytes-out` of the phase 1 row (totals: OPNsense sums them over the child SAs of the connection) and of each child SA row of `search_phase2` (rate) | child SA (strongSwan unique id) |
| WireGuard peer | `transfer-rx` / `transfer-tx` of `wg show` | peer |
| OpenVPN client instance | `bytes_received` / `bytes_sent` of the instance | session (address and start time) |
| OpenVPN server instance | `bytes_received` / `bytes_sent` of each connected client, summed | client session |

"In" is what the firewall received through the tunnel, "out" what it sent.
The counters are cumulative, so Plexus keeps the last reading of each
tunnel's counters in the database (it does not matter which worker reads
them or whether Plexus restarted) and turns each new reading into the
average rate in bits per second, in each direction, since that last
reading; then the new reading replaces it. Readings come from two places:

- every stored collection (hourly by default, sooner when started by hand
  or by syslog). It also names the tracked entity of each tunnel, and a
  collection without failed calls drops the readings of tunnels the
  firewall no longer reports;
- every monitoring poll of the firewall, when the firewall is an
  inventory host (see [Stored with the monitoring poll](#stored-with-the-monitoring-poll)):
  in the same API session as the health, the poll reads the IPsec
  connections and their installed child SAs, the WireGuard peers and the
  OpenVPN sessions (`include_vpn`; not the configured child SAs), so the
  counters are read every poll interval (5 minutes by default) and not
  only hourly. A tunnel no collection has named yet is left out until one
  does. A failed VPN read loses only that part of the poll.

Each reading gives one sample covering the time since the previous one,
so collections and polls interleave without overlap. A tunnel's details
show a **Traffic** section with the totals and the rate since the
previous reading (or why there is none), and the rate is stored like a
gateway's latency: raw samples for the monitoring retention, one row per
day (`traffic_in`, `traffic_out`) for the SLA retention. The **Integrations and cloud** table shows each entity's
average traffic over the period, and **Measurements** charts its samples.

No rate is stored, rather than a wrong one, when:

- there is no previous reading of the entity (its first reading, or the
  previous one did not have its counters);
- a counter of the previous reading is gone: an IPsec child SA was rekeyed
  or deleted (by default strongSwan rekeys a child SA about every hour), an
  OpenVPN client reconnected or disconnected. What it carried after the
  previous reading is unknown;
- a counter went down: the WireGuard interface or an OpenVPN instance
  restarted, the firewall rebooted;
- the two readings are more than three hours apart, or the newer one was
  read before the stored one.

A new IPsec child SA or OpenVPN session that appeared since the previous
reading counts whole, since it started after it. A tunnel that is down has
no counters and stores a rate of 0.

The rate is an average between two readings, so bursts shorter than the
poll interval do not show. With polls every 5 minutes, an IPsec rekey (by
default about every hour) or an OpenVPN reconnect costs the one interval
it falls in. A firewall that is not an inventory host is read by its
collections only: its IPsec tunnels then rarely get a sample, since a
child SA is usually rekeyed between two hourly collections. Add the
firewall to the inventory (the steps after adding the source) for
per-poll readings.

A firmware update, an audit finding, an incomplete audit or a CARP
warning (a VIP in `INIT`, a demotion) is added to the collection's
warnings, so the collection shows as **partial**, but such a warning does
not stop availability tracking from removing a tunnel, gateway or CARP
group the firewall no longer reports. A failed call does: until a
collection without one, a missing entity turns unknown instead of being
removed. A source whose high availability part is turned off reports no
CARP groups, so its tracked groups are removed at the next clean
collection.

## Health and services

With **Health and services** on (`include_health`, the default), each
collection reads the firewall's health with the calls of the OPNsense
dashboard widgets, so no SNMP profile is needed:

- **CPU**: 100 % minus the idle share of the `CPU:` line `top` prints
  (`diagnostics/activity/get_activity`; only its header lines are kept,
  never the process list). The streaming CPU call of the dashboard is not
  used.
- **Load average** (1, 5 and 15 minutes) and **uptime**
  (`diagnostics/system/system_time`; before 25.1 the load average comes
  from the same `top` header)
- **Memory**: used and total, the ZFS ARC left out of "used" as on the
  OPNsense dashboard (the cache gives memory back when it is needed)
- **File systems**: each one with its use; the fullest (CD and DVD media,
  always full, are left out) is the disk use
- **Temperature**: every sensor; the hottest is the temperature
- **State table**: the entries in use and the limit (`pf_states`)
- **Services**: every service the firewall's configuration enables, with
  whether it runs (`core/service/search`, the list of **System →
  Diagnostics → Services**)

They are shown in the firewall's **Health** and **Services** sections. A
file system at 90 % or more and a state table at 80 % or more of its limit
are informational collection warnings. An endpoint the release does not
have (404) is skipped with one informational warning naming it.

### What alerts

Each service is tracked as a service entity of the firewall (see
[Availability tracking](#availability-tracking)): **down** when OPNsense
says it is not running, **up** when it runs. A service going down raises an
alert like any other entity, on the firewall's inventory host when it has
one, else to the notification channels; it recovers when the service runs
again. This covers unbound, the DHCP servers (ISC `dhcpd` / `dhcpd6`, Kea
`kea-dhcp/v4` and `/v6`, Dnsmasq), Suricata (`suricata`, listed as
Intrusion Detection) and every other service a plugin registers.

`core/service/search` lists only the services the configuration enables
(each plugin adds its service only when it is turned on), so a service an
administrator turned off is not listed: at the next collection without
warnings its entity is removed and any open alert on it is resolved. It
never alerts while it stays off. A service that is enabled but stopped by
hand does alert, since it is meant to run. Services OPNsense does not
check (it reports them running) never alert. When the services call fails,
the entities are kept as missing (no alert, none removed) until a
collection reads them again. Muting the firewall, or its site, mutes its
services; each service can also be muted alone.

### Stored with the monitoring poll

When the firewall is an inventory host (the host its collections match:
the firewall's **Health** section says which, as **History**), its
monitoring poll also reads the health over the source's API key at every
poll interval, without the services (the collection tracks them): memory,
file systems, temperature, uptime and load, `top`'s CPU line and the state
table, six calls. Then:

- CPU, memory and uptime are stored as the poll's own values, so the
  device's charts, the built-in CPU and memory thresholds, baseline alerts
  and SLA views work as for an SNMP host. A host that SNMP also polls
  keeps its SNMP values: the API fills only what SNMP left empty, so there
  is one sample per poll, and an SNMP poll that fails falls back to the
  API values.
- the disk use, temperature, state table and load are stored as metric
  samples `fw_disk_used_pct`, `fw_temperature_c`, `fw_pf_states`,
  `fw_pf_states_pct` and `fw_load_avg_1m`, which alert rules can name
  (see [Monitoring](monitoring.md#opnsense-firewall-metrics)).
- a file system at 90 % or more raises the built-in alert `fw_disk_full`
  (critical from 95 %), and a state table at 80 % or more of its limit the
  built-in alert `fw_state_table` (critical from 95 %); each resolves at
  the first poll below its threshold. Alert suppressions apply as for the
  other built-in checks.
- a poll whose SNMP or SSH part failed while the API answered counts as
  up: the firewall answered.
- with **VPN tunnels** on (`include_vpn`), the same session reads the
  tunnels' byte counters (IPsec connections and installed child SAs,
  WireGuard peers, OpenVPN sessions) and stores their traffic rates (see
  [Tunnel traffic](#tunnel-traffic)). A failure there loses only the
  traffic of that poll.

The source must have an API key, automatic collection on and **Health and
services** or **VPN tunnels** on (each part is read only when its option is); the host is learned from its newest collection, so a
firewall imported into the inventory is read from the collection after
the import. A firewall that is not in the inventory still shows its health
in its details and still has its services tracked, but its numbers are not
stored (import it to keep them).

## Certificates

With **Certificates** on (`include_certificates`, the default), each
collection reads the certificates and certificate authorities of **System →
Trust** (`trust/cert/search` and `trust/ca/search`, OPNsense 24.7+). Of each
it keeps the reference id (`refid`, what services point at), the
description, the common name, the issuing CA, the type (server, client),
the start and end of validity, whether it is in use and whether it is a
user's certificate, and for a CA how many places reference it. The private
key, the certificate and signing request bodies and every other field of
the answer are dropped at once and never stored.

They are shown in the firewall's **Certificates** section: name, type,
common name, issuer, expiry date, days left (at the collection time), in
use, and the state: `valid`, `expiring` (30 days or less left), `critical`
(7 days or less), `expired`, with "(not alerted)" for those only listed.

### What alerts

A certificate is alerted on when OPNsense reports it **in use**: anything
other than a user or the certificate itself references it (the web GUI,
OpenVPN, IPsec, the captive portal, a plugin). A CA is alerted on when a
certificate alerted on was issued by it (or by a CA below it), or when
something other than the certificates and CAs it issued references it (an
OpenVPN server that trusts it). Everything else is only listed: unused
certificates, user certificates no service uses, CAs nothing alerted on
depends on, and certificates waiting for a signature.

Each certificate alerted on is tracked as a certificate entity of the
firewall (see [Availability tracking](#availability-tracking)) and raises:

| When | Severity |
|---|---|
| 30 days or less before its end (`expiring`) | warning |
| 7 days or less before its end (`critical`) | critical |
| after its end (`expired`) | critical |

Each tier alerts once, on the firewall's inventory host when it has one,
else to the notification channels ("Certificate fw1 Web GUI at fw1
(OPNsense fw1) expires in 20 days (valid until 2026-12-04)"); the same tier
does not alert again at the next collections. A worse tier replaces the
open alert of the tier before it, so a certificate has one open expiry
alert at most. Unlike a state alert, a
certificate seen for the first time alerts at once when it is already in a
tier, so a firewall added with an expired certificate in use is reported.
A certificate renewed in place (reissued, or renewed by the ACME client:
same reference id, new end) goes back to `valid` and its open expiry alerts
are resolved. A certificate replaced by a new one is no longer in use: at
the next collection without warnings its entity is removed and its alerts
are resolved, and the new certificate is tracked from then on. Muting the
firewall, or its site, mutes its certificates; each can also be muted
alone. An expiring or expired certificate is degraded, never down, so it
counts as available in uptime and SLA figures. The days left are worked
out at each collection, so an alert comes with the first collection past
its threshold.

The certificates that are due are also listed as one informational
collection warning. A refused call (403) is a warning that names the
privilege; the tracked certificates are then kept as missing (no alert,
none removed) until a collection reads them again.

### Releases without the trust API

OPNsense 24.1 and older have no `trust/cert/search` (both calls answer
404). Plexus then reads the `<cert>` and `<ca>` sections of the
`config.xml` the collection downloads (with **Config backup** on): only the
public certificate is parsed, never the private key, and "in use" and the
reference counts are worked out from the configuration the way OPNsense
does. An informational warning says so. Without `config.xml`, an
informational warning says that certificate expiry is not tracked.

## IDS alerts

With **IDS alerts** on (`include_ids_alerts`, the default), Plexus reads
the alerts of the firewall's intrusion detection (**Services → Intrusion
Detection**, Suricata) and keeps them as **security events**: listed under
**Monitoring → Security**, and alerted through the normal alert pipeline.

What is read (privilege **Services: Intrusion Detection**):

1. `GET ids/service/status`: whether the IDS is enabled. A disabled IDS
   reads nothing more and the firewall's **IDS alerts** section says so; a
   release without the IDS API (404) is skipped quietly.
2. `POST ids/service/query_alerts` (`queryAlerts` before 25.7), body
   `{"rowCount": 200, "current": <page>}`: the alerts of Suricata's
   `eve.json`, newest first. It is a search that only reads: OPNsense takes
   the page from the request body. Only the alerts newer than the newest
   one already stored are read (the pages stop at the first older one), at
   most 5 pages of 200 a read; the rotated logs are not read.
3. `GET ids/settings/get_rule_info/<sid>` (`getRuleInfo`) for each new
   signature: its rule's `classtype`. The alert search drops the record's
   category and severity, so the priority comes from the classtype and
   Suricata's default `classification.config` (for example
   `trojan-activity` 1, `attempted-recon` 2, `misc-activity` 3). At most 20
   lookups a read; a signature seen before keeps the classtype stored with
   it.

Each alert becomes one event: when it happened, the signature (id, text,
category, priority), the severity (priority 1 **critical**, 2 **warning**,
3 and up **info**, no known classtype **unknown**), what Suricata did
(**blocked** in IPS mode, else **detected only**), source and destination
address and port, protocol, application protocol, interface and flow id.
The same alert read twice is stored once. Every text is cut to a bound and
stripped of control characters before it is stored: it comes from network
traffic and rule files.

When they are read:

- every collection of the source; the firewall's details get an **IDS
  alerts** section (status, what the read stored, the counts of the last 24
  hours, whether alerts go to an inventory host) and a **Newest IDS
  alerts** table (the newest 5);
- every monitoring poll, when the firewall is an inventory host, in the
  poll's API session: events arrive within one poll interval. A firewall
  whose last read found the IDS disabled is not read by the poll until a
  collection finds it enabled;
- a Suricata alert line forwarded over syslog (see [Syslog](#syslog)):
  only the IDS alerts are read, within seconds.

### What alerts

Not every event: one alert per firewall and signature, for the new events
of priority 1 (critical) and 2 (warning) that happened less than an hour
before they were read (the backlog a first read finds is stored only).
Info and unknown events are stored only. The message names the signature,
its id, classtype and priority, how many events there were, whether
Suricata **blocked** them, only **detected** them or blocked some ("2 of 5
blocked"), and the last flow.

- A firewall that is an inventory host gets a monitoring alert on that host
  (type `security_event`, metric `ids_alert`, dedup key
  `security:opnsense:<source>:ids_alert:<sid>`), counted on every read that
  brings new events of the signature while it is open.
- Another firewall's alert goes to the notification channels, once per open
  period.
- An alert ends on its own once its signature has had no new event for an
  hour (**auto-resolved (quiet)**), or when acknowledged.
- A mute of the firewall (or its site) on the Availability tab covers these
  alerts: nothing is raised while it lasts, and creating it acknowledges
  the open ones. A monitoring suppression of the host (all metrics or
  `ids_alert`) covers them too.

Events are kept as long as the monitoring retention (**Retention days**)
and at most 50,000 per source (the oldest go first), and are deleted with
their source. `GET /api/monitoring/security-events` lists them (see
[api-reference.md](api-reference.md#security-events)).

## ARP, NDP and DHCP leases

With **ARP, NDP and DHCP leases** on (`include_clients`, the default),
each collection reads the firewall's ARP and NDP tables and the leases of
its DHCP servers, read-only (`GET`; Plexus never flushes a table or deletes
a lease):

- **MAC tracking**: the ARP and NDP entries are stored as the ARP table of
  the inventory host that is this firewall (matched as for the [config
  backup](#config-backup)), shown under **MAC tracking** for that host and
  counted in its per-host rollup. Each entry also fills in the IP address of
  MAC table rows of other hosts (switches) that saw the MAC without one.
  Entries are upserted by address; an entry the firewall no longer reports
  keeps its last-seen time. Until the firewall is an inventory host the
  tables are read and shown in its details but not stored, with a warning
  that says to import it. Incomplete entries (no MAC) are left out; MACs
  are stored as `aa:bb:cc:dd:ee:ff`.
- **IPAM**: the leases are stored as the leases of a DHCP server of
  provider `opnsense`, named `<source name> (OPNsense)` and matched to the
  firewall by its API address. Plexus creates it at the first collection; it
  then shows under **IPAM > DHCP Servers**, in the lease listing and in the
  lease-to-inventory correlation like any other DHCP server. Each
  collection replaces that server's leases (a lease the firewall no longer
  reports is gone), only when at least one lease call answered. The server
  cannot be synced or added by hand (its leases come with the collection);
  disable it to stop storing them, delete it to start over. An address with
  leases on two DHCP servers of the firewall is stored once (ISC first,
  then Kea, then Dnsmasq). A delegated IPv6 prefix is not a lease address
  and is left out. The subnet of a lease is the network of the firewall
  interface its address is in.

| DHCP server | Call | Lease fields read |
|---|---|---|
| ISC DHCPv4 | `GET dhcpv4/leases/search_lease` (`searchLease`) | `address`, `mac`, `hostname`, `binding`, `type` (`static` for a reservation), `starts`, `ends`, `if_descr` |
| ISC DHCPv6 | `GET dhcpv6/leases/search_lease` (`searchLease`) | `address`, `duid`, `mac`, `state`, `starts`, `ends`, `if_descr` |
| Kea DHCPv4 / v6 | `GET kea/leases4/search`, `GET kea/leases6/search` | `address`, `hwaddr`, `hostname`, `client_id` / `duid`, `state` (0 active, 1 declined, 2 expired), `expire`, `valid_lifetime`, `if_descr` |
| Dnsmasq | `GET dnsmasq/leases/search` | `address`, `hwaddr`, `hostname`, `client_id`, `expire`, `is_reserved`, `if_descr` |

A DHCP server the firewall does not have answers 404 and is skipped without
a warning; when none answers, one informational warning says no leases
were read. A refused call (403) is a warning that names the privilege,
except the Kea or Dnsmasq lease read of a service `config.xml` shows as off
(see [Creating the API key](#creating-the-api-key)): that one is skipped
like a 404.
The ISC DHCPv4 answer and the ARP / NDP answers follow the OPNsense core
source; the Kea, Dnsmasq and ISC DHCPv6 row fields and the ISC time format
(`YYYY/MM/DD HH:MM:SS`, read as UTC) were inferred and are not verified
against a firewall. A field that is missing only leaves that column empty.

## DNS names and DHCP reservations

With **Config backup** on, each collection also reads the names and
reservations the firewall's `config.xml` holds and keeps them in IPAM. No
other call is made and no other privilege is needed; with **Config backup**
off, or the download refused, nothing is read and what IPAM holds stays.

| Read from `config.xml` | Elements | Stored as |
|---|---|---|
| Unbound host overrides and their aliases | `OPNsense/unboundplus/hosts/host` (`enabled`, `hostname`, `domain`, `rr`, `server`, `description`), `aliases/alias` (`host` names the override's uuid); the pre-21 `unbound/hosts` layout too | DNS names (A and AAAA records only) |
| Dnsmasq hosts | `dnsmasq/hosts` (`host`, `domain`, `ip`, `hwaddr`, `client_id`, `ignore`, `descr`, `aliases`) | DNS names; a reservation when the host has a hardware address or client id, Dnsmasq has a DHCP range and the host is not ignored |
| ISC DHCP static mappings | `dhcpd/<interface>/staticmap` (`mac`, `cid`, `ipaddr`, `hostname`, `domain`, `descr`), `dhcpdv6/<interface>/staticmap` (`duid`, `ipaddrv6`, `hostname`) | Reservations |
| Kea reservations | `OPNsense/Kea/dhcp4/reservations/reservation` (`ip_address`, `hw_address`, `client_id`, `hostname`, `description`), the DHCPv6 reservations (`ip_address`, `duid`) | Reservations |

Only what the firewall serves is read: Unbound, Dnsmasq and Kea entries
while that service is enabled, ISC static mappings of interfaces whose DHCP
service is enabled, enabled overrides and aliases, entries with an address.
Wildcard names (`*`), MX and TXT records, partial IPv6 addresses and the
IPv6 mappings of a `track6` interface (a suffix of a prefix `config.xml`
does not hold) are left out. A host name without a domain is qualified with
the entry's domain, else the interface's, else the system domain.

The firewall gets an IPAM source of provider `opnsense`, named
`<source name> (OPNsense)` and matched by its API address like the DHCP
server above. Plexus creates it at the first collection that has a name or
reservation to store; each collection replaces its allocations, one per
address:

- **DNS name**: the first name (an Unbound override's before a Dnsmasq
  host's, an ISC mapping's, then a Kea reservation's); the other names and
  aliases are kept with it.
- **Status**: `reserved` for a DHCP reservation, `active` for a DNS name
  only.
- **Description**, and the MAC address, DUID or client id, the DHCP
  interface (or Kea subnet) and the origins with it.
- **Subnet**: the firewall's connected subnet that holds the address (the
  one the IPAM page lists for the firewall), so the allocation shows in that
  subnet's drill-down and next-IP allocation never hands the address out.
  An address in none of the firewall's subnets is stored without one.

The source is never synced, validated, reconciled or pushed to (the scheduled
IPAM sync skips it) and cannot be added by hand or allocated into. Its name,
notes and enabled switch are yours: disable it to stop storing (what it
holds stays), delete it to start over. Reservations are not written to the
reserved ranges of **IPAM**: an allocation under the subnet already keeps
next-IP allocation off the address. The firewall's **Names and
reservations** section says what was read and stored.

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
pre-shared keys. It is never put in the topology snapshot. The Config
Backups table keeps it in two forms:

- **Masked text**, with every secret replaced by its fingerprint marker
  (see [Config drift and masked secrets](#config-drift-and-masked-secrets)).
  This is what the backup view, compare, search, the rules view, rule
  change alerts, the filter log labels, config drift, path tracing and AI
  access read. None of them needs a secret value.
- **The file as collected, encrypted** (AES-256-GCM with the Plexus
  encryption key, `netcontrol.key`), plus a keyed digest of it so an
  unchanged file is recognised without decrypting it. A file where only a
  secret changed is a new backup.

A database dump or a read of the table therefore does not give the
secrets. Only **Download** and **Download All** decrypt the file, for
users with `config-backups.write` (or admins) and write access to the
firewall's group; it comes back byte for byte as collected, ready to
restore on the firewall. Other users get no download, as for any backup.

The encryption key is needed to download a raw file. If `netcontrol.key`
is lost or replaced, the download answers `409` with a message that the
encryption key differs (**Download All** leaves those backups out and
names them in `NOT-INCLUDED.txt`); the masked text, drift and rules keep
working. Back up `netcontrol.key` together with the database. Backups an
older release stored in plain text are converted (masked, encrypted) in
the background when the server starts; nothing is lost.

Turn **Config backup** off to stop the collection from storing the file.
A backup policy of the firewall's group still backs it up (below); delete
or disable that policy too if keeping the file is not wanted.

An imported firewall gets the device type `opnsense`. Plexus has no SSH
driver for OPNsense, so a **backup policy** (**Configuration > Config
Backups**) never reads it over SSH. On every scheduled run, **Run Now** and
configuration change message, the policy downloads `config.xml` over this
source's API key and stores it the same way, with the policy and the run's
method (`scheduled`, `manual`, `syslog`). This works whatever the **Config
backup** option says, and the policy needs no credential for it: choose
**None (API-backed devices only, such as OPNsense)** for a group of
firewalls only. Plexus finds the source from the inventory host its newest
collection matched, so collect the source and import the firewall before
the first run. A failed download is an `error` backup that says why (no
such source, no API key, the download refused for want of **Diagnostics:
Configuration History**, an answer that is not a config.xml). With
**Config backup** on, the collection keeps storing a backup when
`config.xml` changed, so the rules view, drift, rule change alerts and
names stay current between policy runs.

SNMP polling works through the generic path once an SNMP profile is
assigned to its group.

## Config drift and masked secrets

An OPNsense firewall works with **Configuration > Config Drift** like any
other host, with three differences:

- **No session to the firewall.** A drift capture (**Capture**, **Capture
  group**, **Check**) of a host with device type `opnsense` takes the
  host's newest config backup, the one the OPNsense collection stored. The
  credential picked for the capture is not used. Without a backup the
  capture answers 409 and says to collect the source first. The scheduled
  drift check also takes a new snapshot from the newest backup when it
  differs from the latest snapshot, so drift that a collection brings in
  is found without a manual capture.
- **A stable form.** Snapshots, baselines and drift diffs hold the
  normalized `config.xml`: pretty-printed with two-space indents,
  attributes in name order, comments dropped, and the top-level
  `<revision>` block left out. OPNsense rewrites `<revision>` (who saved,
  when, from which page) at every save, so a save that changes nothing
  else is not drift.
- **Secrets are masked.** Every secret value is replaced by a marker with a
  fingerprint: `<pre-shared-key>[masked:1a2b3c4d]</pre-shared-key>`. The
  fingerprint is the first 8 hex digits of an HMAC-SHA256 of the value,
  keyed with a key derived from this install's encryption key
  (`netcontrol.key`), so equal values give equal markers on this install
  and a changed secret shows as a changed line, while the value never
  appears and a guessed value cannot be confirmed by hashing it. Long
  base64 or hex values (certificates, keys, encoded blobs) become
  `[masked blob:...]`.
- **No revert.** Revert answers 400: Plexus does not write to an OPNsense
  firewall. Change the firewall in its web interface, or accept the drift
  as the new baseline. Restoring a backup is refused the same way.

The masking also applies to what Config Backups shows for an OPNsense
backup: the backup view (`GET /api/config-backups/{id}`, with
`secrets_masked: true` and the `<revision>` as `revision`), the compare
with the previous backup (`GET /api/config-backups/{id}/diff`, on the
normalized form, with `revision` and `previous_revision`), and search
(matched lines are masked, and a hit only on a secret value is dropped so a
search cannot confirm one). AI access (MCP) masks the same elements with a
bare `[masked]`. The stored backup is this masked text; **Download**
decrypts the encrypted copy and returns the file as collected, so it can
be restored on the firewall (see [Config backup](#config-backup)).

Masked elements: any element named `password`, `passwd`, `pass`, `pw`,
`pwd`, `authpass`, `privpass`, `smtppassword`, `bcrypt-hash`, `md5-hash`,
`sha512-hash`, `nt-hash`, `lm-hash`, `otp_seed`, `key`, `secret`, `apikey`,
`api_key`, `api_secret`, `token`, `auth_token`, `access_token`, `prv`,
`privkey`, `privatekey`, `private-key`, `private_key`, `tls`, `tlsauth`,
`shared_key`, `sharedkey`, `static_key`, `statickey`, `psk`,
`pre-shared-key`, `presharedkey`, `rocommunity`, `rwcommunity`,
`community`, `trapcommunity`, `authkey`, `enckey`, `radius_secret`,
`radiussecret`, `ldap_bindpw`, `bindpw`, `ddnsdomainkey`, `tsig_secret`,
`tsigkey`, `passphrase` or `wpa_passphrase` (any case); any other element
whose name contains `password`, `passwd`, `passphrase`, `secret`, `token`,
`privkey`, `privatekey`, `presharedkey`, `sharedkey`, `psk`, `community`,
`bindpw`, `apikey`, `otp_seed` or `tsig`, or ends in `key`, `-hash`,
`_hash`, `_pass`, `_pw` or `_pwd` (ACME DNS API tokens, monit and
SNMPv3 passwords and keys), unless the name says it describes a secret
rather than holding one (contains `pub`, or ends in `type`, `len`, `ref`,
`id`, `name`, `mode`, `auth`, `policy` and similar: `pubkey`, `keytype`,
`certref`, `passwordauth`); any long base64 or hex value; a bcrypt or
crypt hash anywhere; and the password of a URL with credentials. The rules
are in `netcontrol/integrations/opnsense/secrets.py`.

## Firewall rules and path trace

Once the firewall is an inventory host with a config backup (see
[Config backup](#config-backup)), Plexus reads its filter rules, aliases,
NAT and configured routes from the stored `config.xml`, and the trace
takes its routes and the addresses DHCP or PPPoE assigned from the
routing table and interface addresses the collection stores (see
[Routing table and live addresses](#routing-table-and-live-addresses)).
Nothing is read from the firewall for this beyond the collection itself,
and nothing is ever written to it.

### The Rules tab

On the **Topology** map, click the firewall (it must be an inventory host:
a device with type `opnsense`) and open **Rules**. It needs the **Config
Backups** feature. The tab shows how many rules the newest backup has, how
many carry each flag, and the flagged rules. **Open rules and changes**
opens the full view:

- **Rules**: every rule in the order the firewall evaluates it, grouped by
  interface (a floating rule on every interface is listed once, under
  **Every interface**). The `#` column is the number a path trace names, so
  a trace's "Rule 7" is row #7 here. Filter by interface, by flag (click a
  flag chip) or by text (a port, an address, an alias name). Hover a source
  or destination to see the addresses its aliases resolve to.
- **Changes between backups**: pick two backups of the firewall; the view
  lists the rules added, removed and changed (a rule is matched by its
  uuid, a legacy rule without one by what it matches), the aliases added,
  removed and changed, and the NAT changes (port forwards, outbound and
  1:1 rules, and the outbound NAT mode).

The flags:

| Flag | Meaning |
|---|---|
| Any to any | An enabled pass rule from any source to any destination, any protocol and port |
| Shadowed by #n | Rule #n takes every flow this rule matches first, on every interface and direction it applies to, so this rule never decides anything. "Opposite action" when #n does the opposite (a likely mistake), else the rule is redundant. Only provable cases are flagged: both rules fully resolved, neither negated, the other rule's protocol, addresses and ports holding all of this rule's |
| Disabled | The rule is disabled in the configuration |
| Missing alias | The rule names an alias the configuration does not define (deleted or renamed) |
| Unused | The rule's counters say it matched no packet since they were last reset (a reboot or a filter reload resets them). Only with **Rule counters** on and OPNsense 24.1 or later |
| Unused 90 days | An enabled rule Plexus has tracked for at least 90 days whose packet counter did not grow in the last 90 days of that tracking, across counter resets (see [Rule counter history](#rule-counter-history)). The chip on the rule says how many days it went without a hit |

#### Rule counter history

Because pf resets the rule counters at every reboot and filter reload,
"Unused" only covers the time since the last reset. Each collection with
**Rule counters** on therefore also adds the counters to a history kept
per inventory host and rule label: when the rule was first and last read,
when its packet counter last grew (a counter that went down was reset, so
its whole value counts as new), and the packets and bytes counted across
resets. The firewall's **Rule counters** section in the topology says
whether the read was stored (the firewall must be an inventory host).

- The history starts with the first collection after the upgrade that
  added it: no rule can be flagged **Unused 90 days** before it has been
  tracked for 90 days. Until then the **Counters** column says how long the
  rule has been tracked and how many days are left; hover it for the first
  read, the last hit and the totals.
- Tracked time and idle time end at the last collection that read the
  counters, so days when the counters were not collected never count as
  idle.
- A label the firewall stops reporting (the rule was deleted, disabled, or
  edited into a new label) keeps its history for 30 days, then it is
  removed; a rule that comes back later starts a new history. The history
  goes with its inventory host.

The order follows pf: per interface and direction the first matching rule
with **Quick** set decides; a rule without Quick (a floating rule can be
one) decides only when no quick rule matches, and then the last matching
one wins. The rules of the automation / new rules model come first, then
floating rules, then interface group rules, then each interface's rules. A
flow no rule matches is blocked (OPNsense's default `block in`); what
leaves an interface passes unless a floating `out` rule says otherwise.

### Rule change alerts

Each collection that stores a **new** config backup (the configuration
changed) compares its rules with the host's previous backup and raises an
alert, on the firewall's inventory host, for every rule the change made:

| Finding | Raised when | Severity |
|---|---|---|
| Any to any | A new enabled pass rule from any to any (any protocol and port), or an existing rule widened to that or enabled | Warning |
| Shadowed, opposite action | A rule now covered by an earlier rule that does the opposite: a new rule shadowed on arrival, or a rule a new, moved or widened rule now covers | Warning |
| Shadowed, redundant | The same, with a covering rule that does the same (traffic is decided as before) | Info |

The flags are the ones the Rules tab shows; disabled rules never raise
one. The alert names the rule's number, description, interfaces, action,
source and destination and, for a shadowed rule, the number of the rule
that covers it. It holds parsed rule fields only, never the backup's text
or what an alias contains. A finding is raised once (dedup key
`opnsense-rule:<host id>:<any_any|shadowed>:<rule key>`, the rule key being
its uuid, or what it matches for a legacy rule without one): later backups that still have it raise nothing. When a later
backup no longer has it (the rule was removed, narrowed, disabled or moved
back), its open alert is resolved as `auto-resolved`. At most 25 alerts are
raised per backup.

Nothing is raised for the first backup of a host (there is nothing to
compare with), for an unchanged configuration (no new backup), or while
the firewall (or its site) is muted under **Availability** or the host has
an active alert suppression for all metrics or for `opnsense_rule_any_any`
/ `opnsense_rule_shadowed`. The alerts reach the notification channels like
other monitoring alerts (alert type `opnsense_rule_change`). The firewall's
**Config backup** section says what the last new backup brought, for
example "1 new any-to-any rule, 2 newly shadowed rules; alerts raised".
**Changes between backups** in the Rules view lists the same findings
for the two backups it compares (`findings` of the diff API).

They need **Config backup** on and the firewall imported as an inventory
host, since they are read from its backups. Config drift (see
[Config drift and masked secrets](#config-drift-and-masked-secrets)) is
separate: it opens a drift event for any difference from the baseline you
approved, raises no monitoring alert, and is cleared by accepting or
resolving the event. A rule change alert covers only these risky rule
changes between two consecutive backups, whatever the baseline, and clears
itself when the rule is fixed. A risky change usually shows in both: the
drift event says what changed, the alert says why it matters.

### Path trace through the firewall

In **Path Mode** a trace that reaches the firewall (as an inventory host)
now goes through it hop by hop:

1. **NAT in**: a 1:1 NAT or a port forward translates the destination (a
   port forward whose filter rule association is **Pass** lets the
   translated flow in by itself, as OPNsense does).
2. **Rules in**: the rules of the interface the flow arrives on, in the
   order above, ending in the default block. The item names the deciding
   rule by number and description.
3. **Route**: the routes of the collected routing table: the connected
   networks, the static and default routes, the routes DHCP, PPPoE or a
   router advertisement installed and the routes of FRR (OSPF, BGP, RIP);
   blackhole and reject routes (`Null4` / `Null6`) drop the flow. Without
   a collected table, the routes of `config.xml`: the connected networks,
   the static routes (gateways resolved to their address and interface)
   and the default gateway.
4. **Rules out**: the floating `out` rules of the egress interface, if any.
5. **NAT out**: 1:1 NAT, the source NAT and manual outbound rules (in
   **Hybrid** and **Manual** mode) and, in **Automatic** and **Hybrid**
   mode, the automatic rules: the networks of the other interfaces leave an
   upstream interface (one with a gateway, or `wan`) as its address.

Replies pass by state. A rule that names something Plexus cannot evaluate
(a negated address, a schedule, an alias of host names, a URL table or
GeoIP whose pf table was not collected) makes a flow it may match
**unknown** rather than allowed or blocked; with the alias's table
collected, the table decides (see [Alias tables](#alias-tables)). Without a collected routing table (the firewall was collected
with **Routing table** off, or not since it became an inventory host) the
routes come from `config.xml` alone, so a destination that only the
default route covers is marked **unknown** at the route step (a learned
route might be more specific) and routes learned by DHCP, PPPoE or FRR
are missing; the rules and NAT are still evaluated. A policy-based route
(a rule with a gateway) keeps such a destination **unknown** with a table
too, as the gateway the rule picks is not followed.

When the firewall sends its firewall log to Plexus (see
[Firewall log evidence](#firewall-log-evidence)), the firewall's hop in
the trace adds what the log showed in the last 24 hours: the passes and
blocks of the rule the trace names, and whether a logged flow matches the
traced one (its addresses inside the traced source and destination, the
same protocol and port) and with which action. When the log disagrees
with the trace, it says so plainly, for example *The trace allows this
flow here, but the firewall log shows it blocked 5 times*: a rule the
trace could not read, a rule changed since the backup, or a flow that
arrives on another interface. A trace through a firewall without log
lines in the window looks exactly as before.

### Firewall log evidence

The rule counters say how often a rule matched since the last filter
reload; the firewall log says what it did just now, and to which flows.
When the firewall sends its firewall log (`filterlog`) to the Plexus
syslog receiver, Plexus ties each log line to the rule that wrote it and
keeps, per rule, how many packets it passed and blocked and a few recent
flows. The **Rules** tab and path traces through the firewall show it.

Setup:

1. In Plexus, turn on the syslog receiver (Settings > Syslog & Traps; see
   [Syslog](#syslog) for the ports). **Keep OPNsense firewall log
   evidence per rule** is on by default in the same settings.
2. On the firewall, **System > Settings > Logging**, **Remote** tab, add a
   destination for the Plexus address (UDP, port 514 or 1514, RFC 5424 on
   or off). Under **Applications** pick the firewall log (`filter` /
   `filterlog`), or leave the list empty to send everything.
3. On each rule to watch, turn on **Log packets that are handled by this
   rule**: only logged rules write lines. **Firewall > Settings >
   Advanced** has the switches that log the default block rule and the
   default pass rule.
4. The firewall must be an inventory host and send from an address Plexus
   knows for it (its address or a recorded interface address): lines from
   any other address are counted and dropped.

How a line is tied to its rule: each line names the rule's pf label. For a
rule of the automation / new rules model that is its uuid; for a legacy
rule (**Firewall > Rules**), a hash OPNsense computes from the rule's
fields (`calcRuleHash`), which Plexus computes the same way from the
stored `config.xml`. The firewall's rule counters are keyed by the same
label. Lines of rules that are not in the newest backup, such as the
automatic default deny, anti-lockout, bogon and private network rules or a
rule added since the last backup, are kept under their label and listed
under **Logged by automatic or unknown rules**.

What is shown:

- **Rules tab**: when the firewall log was last received, and for each
  rule a **Log (24 h)** column with the packets passed and blocked in the
  last 24 hours; hovering it shows the last hour, when the rule was last
  logged and its most recent flows. Without any log line from the
  firewall, the tab says what to set up.
- **Path trace**: see [Path trace through the firewall](#path-trace-through-the-firewall).

What is kept, and for how long:

- Raw log lines are **never stored**: not in the syslog event list, not
  matched by the syslog alert rules. Each line is counted in memory and
  written every 30 seconds as a count per rule, action, interface and
  direction in 10-minute buckets, plus up to 25 recent distinct flows
  (source, destination, protocol, destination port) per rule and action.
- Both are kept 7 days (the metrics retention cleanup removes older ones)
  and removed with the inventory host.
- With the switch off, firewall log lines are dropped (still never stored).
  Settings > Syslog & Traps shows how many lines were counted and dropped
  since Plexus started.

Limits:

- Only rules with logging on produce evidence; a rule without lines may
  simply not log. The counts are of logged packets (pf logs the first
  packet of a connection for a pass rule that keeps state, every packet
  for a block rule).
- A busy firewall can send more than the receiver's buffer holds
  (10,000 messages a second for all devices together): the excess is
  dropped and counted with the receiver's dropped events. Up to 30
  seconds of counts are lost when Plexus stops.
- The time of a count is when Plexus received the line, not the
  timestamp in it.
- A legacy rule's label changes with any field but its description, so a
  rule edited since the newest backup is listed as unknown until the next
  backup. The label is computed as OPNsense computes it; if a release
  computes it differently, the rule's lines show up under **Logged by
  automatic or unknown rules** (the rule counters are still matched by
  uuid).
- Lines of NAT (`rdr`, `nat`, `binat`) and `match` rules are not counted.

### Routing table and live addresses

With **Routing table** on (`include_routes`, the default), each collection
of a firewall that is an inventory host stores its routing table and the
addresses of its interfaces as the route capture of that host (the
**Route capture** section says what was stored). It holds, per interface,
its key (`wan`, `lan`, `optN`), device and addresses, and per route its
family, destination, gateway, flags and interface. Counters, MTU and
expiry times are left out, so a new capture is written only when the
routing or the addressing changes; an unchanged table keeps the newest
capture, which retention never deletes. Nothing is stored when the
routing table could not be read: the trace then keeps the previous
capture, or `config.xml` alone.

The trace reads the capture this way:

- **Routes**: connected networks (`U`, no gateway), static routes (`S`,
  the default route by its destination), routes a routing daemon installed
  (flag `1`, `2` or `3`: FRR) and other gateway routes (DHCP, PPPoE, a
  router advertisement) as learned routes, blackhole (`B`) and reject
  (`R`) routes as dropping the flow. The firewall's own addresses (host
  routes through `lo0`) are addresses of the interface they belong to.
  Link-local, multicast and loopback routes are left out. With a capture,
  the static routes and default gateway of `config.xml` are not used: the
  table says what is installed.
- **Addresses**: an interface whose address `config.xml` leaves to DHCP,
  PPPoE, DHCPv6 or track6 gets its live address (matched by its key, else
  its device), so rules and NAT that name `wan address`, `wan net` or
  **This Firewall**, the automatic outbound NAT and port forwards to the
  WAN address resolve. An interface without a live address (a PPPoE
  session that is down) stays unresolved and listed under **Not
  checked**.

### Alias tables

Some aliases hold addresses only the firewall knows: URL tables, GeoIP,
ASN, dynamic IPv6 hosts, MAC and OpenVPN group aliases, a host alias that
names a host name, and the tables OPNsense fills itself (`virusprot`,
`sshlockout`). `config.xml` cannot resolve them, so without more a rule
that names one makes the flows it may match **unknown**.

With **Alias tables** on (`include_alias_tables`, the default) and
**Config backup** on, each collection reads the pf tables of the aliases
the rules and NAT of the `config.xml` it just downloaded cannot resolve
(nested ones too), and stores them for the firewall's inventory host,
replacing the previous ones as a whole, with when they were read and
whether each one is complete (the **Alias tables** section says what was
stored). The calls are `GET firewall/alias_util/aliases` (the tables pf
has loaded) and one `GET firewall/alias_util/list/<alias>` per table. A
configuration without such aliases makes no call. When the tables could
not be read (the call was refused, or the option is off) the previous ones
stay.

The trace then resolves such an alias from its table:

- An address the table holds matches the alias. An address a **complete**
  table does not hold does not match, so the rule is skipped and the next
  one decides.
- A table cut at the limits below is **truncated**: an address it holds
  still matches, any other address leaves the rule **unknown**, as an
  alias with no collected table always does.
- `!` entries (negated addresses in the table) are cut out of the networks
  that hold them, as pf's most specific match does. A negated rule source
  or destination stays unresolved, tables or not; nested aliases resolve
  through their own tables.
- A host alias that holds both addresses and host names is resolved from
  its table when it is complete (the table is what pf really matches: the
  addresses and what the host names resolved to); with a truncated table,
  what the table and the configured addresses hold matches and the rest is
  unknown.

The contents are a reading of the moment: host names resolve again and
URL tables refresh between collections. The hop says so: the rule's text
names the alias "from its pf table as read at the last collection", and a
truncated table's unknown item says how many entries it held and how many
were read. The Rules tab marks each alias resolved this way ("pf table",
with its number of entries, or "truncated") and says when the tables were
read.

Limits: at most 9,999 entries per table (what one read returns), 30,000
entries over all tables and 30 tables per collection; what is past them is
truncated or not read, and the collection gets an information warning
naming those tables. The downloaded bogon tables (`bogons`, `bogonsv6`,
100,000 entries and more) are never read, so **Block bogon networks** stays
a note. A table pf has not loaded is skipped.

### What the trace does not read

Listed under **Not checked** on the hop when the configuration uses them:
IPsec, OpenVPN and WireGuard tunnels and the rules of their interfaces,
policy-based routing (a rule with a gateway: the rule is evaluated, the
gateway is not followed), the bogon table (**Block bogon networks**),
NPTv6, interface addresses learned by DHCP, PPPoE or tracking that the
collected interface addresses do not hold (all of them without a route
capture), and port forwards or outbound rules that match on what is not
read (source ports, negations, unresolved aliases). An alias whose pf
table was not collected (the option is off, the privilege is missing, it
is past the limits or pf has not loaded it), or the part of a truncated
table that was not read, is unresolved, and so are the bogon tables;
port forwards and outbound NAT never use the collected tables. Traffic shaping, captive portal and the
firewall's own services are not modelled.

## NetFlow

The firewall can export NetFlow v5 / v9 to the Plexus flow collector
(**Reporting > NetFlow** on the firewall; the settings are in
[NetFlow / sFlow / IPFIX](flow-collector.md#opnsense-firewalls)). For a
firewall that is an inventory host, each collection prepares the flow
views for it from what it already reads, with no extra call or privilege:

- the addresses of its interfaces are recorded as the host's interface
  addresses, so flows the firewall sends from its WAN or any other
  interface are attributed to it, not to an unknown exporter (flows that
  arrived before the first collection are attributed then);
- the kernel interface index of each interface with an address is read off
  its routing table (the `link#N` gateway of the interface's connected
  route), so the **Interfaces** view of the flows names the indexes the
  records carry (`WAN (igb0)`) instead of numbers.

The firewall's **Flow export** section shows whether flows arrive. The
firewall's own NetFlow settings are not read: that needs the
"Diagnostics: Netflow configuration" privilege, which the API user does
not need otherwise.

The recorded addresses are as fresh as the last collection, and a
discovery sync or configuration collection of the same host replaces them
with what it read, so flows from an interface it did not see can show as
an unknown exporter until the next collection.

## Syslog

OPNsense can forward its logs to the Plexus syslog receiver, so a change of
gateway, CARP or VPN state, or a configuration save, is collected within
seconds instead of at the next scheduled collection.

1. In Plexus, turn on the syslog receiver (Settings > Syslog & Traps). It
   listens on UDP 1514; Docker publishes host port 514 to it as well.
2. On the firewall, **System > Settings > Logging > Remote**, add a
   destination: transport **UDP(4)** (or UDP(6)), the Plexus address as
   hostname, port **514** (or 1514), RFC 5424 on or off (Plexus reads
   both). Under **Applications** pick at least the ones below (leaving the
   list empty sends everything); **Levels** at least `info` (`notice` is
   enough for gateways and configuration saves, CARP transitions are
   `info`).
3. Send from an address Plexus knows: the address the source's API URL
   names, an interface address of the firewall (from its last
   collection), or an address of its inventory host.

| Application | What Plexus does with it |
|---|---|
| Gateways (dpinger) | A gateway alarm or recovery collects the source |
| System / kernel | A CARP transition or demotion collects the source |
| IPsec (charon) | An IKE SA established or deleted, a child SA closed, collects the source |
| OpenVPN | A site-to-site client instance (or a server instance) up, restarting or stopping collects the source |
| Configuration / audit | A configuration save collects the source (config.xml backup and drift right away); failed web GUI and SSH logins count for the **Repeated login failures** rule |
| Intrusion Detection (suricata) | An alert line (IDS **Enable syslog alerts**, `[1:<sid>:<rev>] ...`, `[Drop]` in IPS mode) or an eve alert record (**Enable eve syslog output**) reads the source's [IDS alerts](#ids-alerts) only, not a collection |

The collection is the normal one (availability tracking, config backup,
software refresh); the gateway, tunnel and CARP alerts stay the
availability tracker's, so a message never raises a second alert for the
same condition. At most one collection per firewall a minute and 6 an
hour, 5 seconds after the first message; the switch is **Re-collect OPNsense on a state
change** in the receiver settings. A Suricata alert line reads only the IDS
alerts (a few API calls), at most once a minute per firewall, and is not
one of the hour's 6 collections, so an attack that logs an alert a second
neither collects the firewall over and over nor holds back the collection
a gateway alarm asks for. Details:
[Syslog Rules](syslog-rules.md#opnsense-re-collect-trigger).

Limits:

- A collection reads every enabled part of the firewall (about 15 to 25
  API calls, more with many IPsec connections), and the firmware audit
  waits up to 90 seconds for `pkg audit`: a triggered collection takes as
  long as a scheduled one. Turn the audit option off on a source whose
  collections should be quick.
- WireGuard logs no handshake or peer state to syslog, and IPsec child SA
  (phase 2) establishment is left out because every rekey logs it: those
  changes wait for the next collection (or come along with a phase 1
  event).
- The firewall's own filter log (`filterlog`) is not a trigger; its lines
  are kept as per-rule evidence instead (see
  [Firewall log evidence](#firewall-log-evidence)).
- Syslog over UDP is not authenticated: restrict the receiver port to your
  device networks ([deploy/FIREWALL.md](../deploy/FIREWALL.md)). The rate
  limit bounds what a forged message can start.

## Firmware and security audit

Each collection reads the firmware status of the last update check made on
the firewall (it never starts a new check). The firewall's version is
tracked on the **Software** page under platform **OPNsense**. When an
update is pending, the firewall's details say so and the collection gets a
warning naming the current and the latest version.

The **Firmware** section also shows the release **Series** the firewall
runs (`25.7` for `25.7.6`; business edition `24.10`) and its **Series
status**: supported until, ending on, or end of life since a date, and how
that is known (see [software-versions.md](software-versions.md#software-end-of-life)):

- **estimate**: a series is maintained until its successor is released
  (community `YY.1` -> `YY.7` -> `YY+1.1`, business `YY.4` -> `YY.10` ->
  `YY+1.4`), so its end of life is estimated as the last day of the
  successor's release month (never early, at most about a month late);
- **reported**: the firewall offers a newer major release
  (`upgrade_major_version` of the firmware status, shown as **Major upgrade
  available**), so its series is superseded and end of life from the day
  the successor is offered;
- **administrator entry**: an end-of-life entry for platform `opnsense` and
  the series on the Software page, which overrides both.

A series that is end of life adds an informational collection warning
("Release series end of life: OPNsense 24.7 ..."), like the pending update:
it does not count as an incomplete collection, so it never holds back the
removal of gone entities. The summary carries `series`, `major_upgrade` and
`software_lifecycle`. The software tracker raises the alert for it (a
`lifecycle:opnsense:<series>` advisory: high once end of life, low while
ending, within the software warning window).

With **Firmware security audit** on (the default), each collection also
runs the firewall's built-in security audit (**System → Firmware → Status →
Run an audit**, `pkg audit -F`), waits for it (up to about 90 seconds) and
reads its result: every vulnerable installed package with its issue, CVE ids
and VuXML link. It is skipped, with a warning, when another firmware task is
running on the firewall. The findings are shown under **Security audit**
and **Vulnerable packages** and added to the collection's warnings.

An audit counts only when it verifiably completed: its log has `pkg
audit`'s result line (`N problem(s) in M package(s) found.`, printed also
when nothing is vulnerable) and no error line (the vulnerability database
could not be fetched, opened or read, for example without internet access or
DNS; the package database was locked; any other `pkg:` error). An audit
that is still running when the collection stops waiting (about 90 seconds),
that the firewall reports as failed, or whose log is cut short does not
count either. Then **Security audit** shows **Audit incomplete** with the
reason, the collection gets an informational warning, and the software
advisories are not changed: a failed fetch is never read as "nothing
vulnerable".

Each finding also becomes a software advisory (source `opnsense-audit`,
named after its VuXML entry, platform **OPNsense**, affected version the
firewall's version, with its CVE ids and link), limited to the firewall
whose audit reported it (the advisory's `device_keys`: the firewall's key on
the Software page). Repeated collections update the same advisory instead
of adding another, so the Software page raises one alert per advisory and
firewall, with the usual notifications. A second firewall on the same
version is alerted only when its own audit reports the finding, and is then
added to the same advisory. When a firewall's audit no longer reports a
finding, that firewall is taken off the advisory and its alert resolves;
the other firewalls keep theirs. `pkg audit` gives no severity, so a new
advisory starts as a default `medium` with no CVSS score. With CVE
enrichment turned on (Software settings, see
[software-versions.md](software-versions.md#cve-enrichment-nvd-and-cisa-kev)),
its CVE ids are looked up at NVD and in the CISA Known Exploited
Vulnerabilities catalogue: the advisory gets the highest CVSS score of its
CVEs, the severity of that score (at least high when a CVE is known
exploited) and the known-exploited flag, and later audits keep them. A
severity you change is kept (enrichment no longer changes it), and so is
the list of firewalls when you edit the advisory.

## What is collected

| Data | API call (`/api/...`) | Option |
|---|---|---|
| Host name, version strings | `GET diagnostics/system/system_information` (`systemInformation`) | always |
| Product, version, pending updates | `GET core/firmware/status` | always |
| Interfaces, addresses, link state, VLAN tags | `GET interfaces/overview/interfaces_info` (`interfacesInfo`) | always |
| Gateways: status, loss, delay, deviation | `GET routes/gateway/status` | Gateways |
| IPsec connections | `GET ipsec/sessions/search_phase1` (`searchPhase1`) | VPN tunnels |
| IPsec installed child SAs, per connection with an SA | `POST ipsec/sessions/search_phase2` (`searchPhase2`), body `{"id": "<connection>"}` | VPN tunnels |
| IPsec configured child SAs, per connection of the Connections model | `GET ipsec/connections/search_child?connection=<uuid>` (`searchChild`) | VPN tunnels |
| WireGuard peers, with their transfer counters | `GET wireguard/service/show` | VPN tunnels |
| OpenVPN instances and clients, with their byte counters | `GET openvpn/service/search_sessions` (`searchSessions`) | VPN tunnels |
| Routing table | `GET diagnostics/interface/get_routes` (`getRoutes`) | Routing table |
| CARP virtual IPs, demotion, maintenance mode | `GET diagnostics/interface/get_vip_status` (`getVipStatus`) | High availability |
| Security audit | `GET core/firmware/running`, `POST core/firmware/audit`, `GET core/firmware/upgradestatus` | Firmware security audit |
| config.xml | `GET core/backup/download/this` | Config backup |
| DNS names and DHCP reservations (see [DNS names and DHCP reservations](#dns-names-and-dhcp-reservations)) | none: read from the downloaded `config.xml` | Config backup |
| Filter rule counters (evaluations, packets, bytes, states per rule uuid) | `GET firewall/filter_util/rule_stats` (`ruleStats`) | Rule counters |
| Memory (total, used, ZFS ARC) | `GET diagnostics/system/system_resources` (`systemResources`) | Health and services |
| File systems | `GET diagnostics/system/system_disk` (`systemDisk`) | Health and services |
| Temperature sensors | `GET diagnostics/system/system_temperature` (`systemTemperature`) | Health and services |
| Uptime, load averages | `GET diagnostics/system/system_time` (`systemTime`) | Health and services |
| CPU use (the `CPU:` header line of `top`; the process list is dropped) | `GET diagnostics/activity/get_activity` (`getActivity`) | Health and services |
| State table: entries and limit | `GET diagnostics/firewall/pf_states` (`pfStates`) | Health and services |
| Services the configuration enables, running or not | `GET core/service/search` | Health and services |
| Certificates: name, common name, issuer, validity, in use (the private key and PEM bodies are dropped; see [Certificates](#certificates)) | `GET trust/cert/search` | Certificates |
| Certificate authorities: name, issuer, validity, reference count | `GET trust/ca/search` | Certificates |
| Whether the IDS is enabled | `GET ids/service/status` | IDS alerts |
| IDS alerts newer than the newest stored (see [IDS alerts](#ids-alerts)) | `POST ids/service/query_alerts` (`queryAlerts`), body `{"rowCount": 200, "current": <page>}` | IDS alerts |
| The classtype of each new signature | `GET ids/settings/get_rule_info/<sid>` (`getRuleInfo`) | IDS alerts |
| The pf tables of the aliases `config.xml` cannot resolve (see [Alias tables](#alias-tables)) | `GET firewall/alias_util/aliases`, then `GET firewall/alias_util/list/<alias>` per table | Alias tables (with Config backup) |
| ARP table | `GET diagnostics/interface/search_arp` (`searchArp`; `get_arp` / `getArp` on older releases) | ARP, NDP and DHCP leases |
| NDP table | `GET diagnostics/interface/search_ndp` (`searchNdp`; `get_ndp` / `getNdp`) | ARP, NDP and DHCP leases |
| DHCP leases | `GET dhcpv4/leases/search_lease`, `GET dhcpv6/leases/search_lease` (`searchLease`), `GET kea/leases4/search`, `GET kea/leases6/search`, `GET dnsmasq/leases/search` | ARP, NDP and DHCP leases |

The options are `verify_tls`, `include_gateways`, `include_vpn`,
`include_ha`, `include_routes`, `include_firmware_audit`,
`include_clients`, `include_rule_stats`, `include_health`, `include_alias_tables`,
`include_certificates`, `include_ids_alerts`, `config_backup` and `inventory_enrich`, all on by default.

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
everywhere. The certificate rows keep only the fields listed under
[Certificates](#certificates): their private keys never leave the
collector.

## Limits

Not read:

- the parts of `config.xml` listed under
  [What the trace does not read](#what-the-trace-does-not-read)
- the CARP peer of a firewall that is the only source of its pair: it is
  not drawn (add the peer as a source of its own for the HA cluster)
- the pair's status as an alert: the HA link between two sources is
  display only (their collections are not simultaneous); alerts come from
  each firewall's own CARP groups and failovers
- CARP clusters of more than two sources: they are not drawn as one box
- a check that two sources really are peers: a pair is recognised by its
  VHID and virtual address alone, so two unrelated firewalls that reuse
  the same VHID and the same private virtual address (two sites with
  overlapping addressing, each with only one firewall added) are drawn as
  one pair. The pfsync and configuration sync peers are not compared
- child SA counts of legacy IPsec tunnels (only connections of the
  "Connections" model have a configured count)
- tunnel traffic finer than the time between two readings (the
  monitoring poll of a firewall that is an inventory host, else its
  collections), and the traffic of an IPsec child SA or OpenVPN session
  that ended between two readings (that interval has no rate; see
  [Tunnel traffic](#tunnel-traffic)). A WireGuard counter that restarted
  and grew past its previous value between two readings cannot be told
  from traffic
- traffic per IPsec child SA or OpenVPN user as a time series: only the
  totals of the connection or server are stored
- alias tables past the limits of [Alias tables](#alias-tables) (9,999
  entries per table, 30,000 and 30 tables per collection) and the bogon
  tables; the shapes of the `alias_util` answers were checked against the
  OPNsense source, not against a firewall
- the health more often than the monitoring poll (or the collections, for
  a firewall that is no inventory host), swap, mbufs, per-core CPU and
  per-process use; the streaming CPU call of the dashboard is never used
- a service the configuration does not enable: `core/service/search`
  lists only enabled ones, so a service turned off on purpose is removed,
  not alerted
- certificate expiry between two collections: the days left are worked
  out at each collection, so an alert comes with the first collection past
  a threshold (30 days, 7 days, the end). The thresholds are fixed
- certificates of plugins that keep their own store (not in **System →
  Trust**), the chain of an externally issued certificate whose CA is not
  imported, revocation (CRLs, OCSP), and certificates other devices present
  to the firewall; an unused or user certificate is listed, not alerted.
  The trust answers were checked against the OPNsense source, not against
  a firewall
- IDS alerts beyond one read's 5 pages of 200 (a burst larger than that
  between two reads loses its oldest part, and the section says so), the
  rotated alert logs, alerts older than the newest one stored (an alert
  logged late with an older time), and the rest of Suricata's eve records
  (flows, HTTP, TLS, DNS, files, the payload)
- the severity Suricata logged: the alert search drops it, so the priority
  comes from the rule's classtype and Suricata's default
  `classification.config`; a custom classification file, a rule without a
  classtype or a signature past the 20 lookups of a read is **unknown**
  (stored, not alerted, until a later read looks it up for new events)
- the IDS more often than the monitoring poll for a firewall that is no
  inventory host: its collections (and a forwarded Suricata syslog line)
  read it. A firewall the poll found with the IDS disabled is read again
  by the poll only after a collection finds it enabled. The IDS answers
  were checked against the OPNsense source, not against a firewall
- any change to the firewall: Plexus never applies updates, reboots,
  starts or stops a service or edits anything

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
| `GET` | `/api/availability/topology/summary?provider=opnsense&entity_type=certificate` | The tracked certificates and CAs with their state; `raw_status` is the expiry tier (`valid`, `expiring`, `critical`, `expired`) |
| `GET` | `/api/opnsense/hosts/{host_id}/rules` | The rule view of the firewall's newest config backup (Config Backups feature), with each rule's firewall log evidence (`log_evidence`) and the sizes of the collected alias tables (`alias_tables`); see [api-reference.md](api-reference.md#opnsense-firewall-rules) |
| `GET` | `/api/monitoring/security-events` | The stored [IDS alerts](#ids-alerts) (Monitoring feature): `?hours=&severity=&action=&q=&host_id=&org_ref=&provider=&kind=&limit=&offset=`; see [api-reference.md](api-reference.md#security-events) |
| `GET` | `/api/opnsense/hosts/{host_id}/rules/diff` | Rule, alias and NAT changes between two backups (`?from_backup=&to_backup=`, default: the newest two), with the rule change `findings` (rules made any-to-any or shadowed, and those no longer flagged) |
