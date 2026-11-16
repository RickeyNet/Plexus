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
   plus the one call that starts the security audit (the IPsec phase 2
   search is a `POST` too, but it only reads: OPNsense takes its connection
   from the request body).
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
| Status: IPsec | IPsec connections and their state, and their installed child SAs (phase 2) |
| VPN: IPsec: Connections | the child SAs configured for each connection (only with the "Connections" model, 23.1+) |
| Status: CARP | CARP virtual IPs, their state, demotion and maintenance mode |
| VPN: WireGuard: Status | WireGuard peers and their latest handshake |
| Status: OpenVPN | OpenVPN instances and connected clients |
| Diagnostics: Configuration History | the config.xml download (only with **Config backup** on) |
| Firewall: Rules (the privilege that lists `api/firewall/filter_util/*`) | the filter rule counters (only with **Rule counters** on; 24.1+) |
| Diagnostics: ARP Table | the ARP table (only with **ARP, NDP and DHCP leases** on) |
| Diagnostics: NDP Table | the NDP (IPv6 neighbour) table (same option) |
| Status: DHCP leases / Status: DHCPv6 leases | ISC DHCP leases (same option; only if the firewall runs ISC DHCP) |
| the Kea DHCP leases page (v4 and v6) | Kea DHCP leases (same option; only if the firewall runs Kea) |
| the Dnsmasq DNS/DHCP leases page | Dnsmasq DHCP leases (same option; 25.1+, only if the firewall runs Dnsmasq DHCP) |

The ARP, NDP and lease privileges also allow flushing the ARP / NDP table
or deleting a lease; Plexus never sends those calls. The exact names of the
Kea and Dnsmasq lease privileges vary between releases and were not checked
against a firewall: pick the ones whose description lists
`api/kea/leases4/*`, `api/kea/leases6/*` or `api/dnsmasq/leases/*`. A
refused lease call names the privilege Plexus expects.

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
| IPsec | the connection has an SA | an SA, but none of the connection's configured child SAs is installed | no SA |
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
  and their state; an IPsec connection also shows its child SAs as
  `installed of configured` (for example `1 of 2 installed`)
- **High availability**: each CARP virtual IP with its interface, VHID,
  address, state (`MASTER`, `BACKUP`, `INIT`, `DISABLED`), advertisement
  base and skew, and the firewall's maintenance mode and CARP demotion. A
  VIP in `INIT` or a demotion other than 0 is a collection warning (not an
  informational one). Only this firewall is drawn: its CARP peer is a
  firewall of its own, added as another source
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
- **Config backup**: what the collection did with config.xml
- **Plexus inventory**: the inventory host the firewall matched

Click a gateway stub for its **Gateway** details, a peer for its **IPsec
peer**, **WireGuard peer** or **OpenVPN peer** details, and an OpenVPN
server for its **OpenVPN server** details and **Connected clients**. An
IPsec tunnel's details list its **Child SAs**: each installed child SA with
its state, local and remote networks, mode, encryption and traffic.

The installed child SAs are read per connection that has an SA
(`ipsec/sessions/search_phase2`), the configured ones per connection of the
"Connections" model (`ipsec/connections/search_child`; a legacy tunnel has
no configured count and is never shown degraded for its child SAs). When
either call is refused or unknown it is not repeated for the next
connection: one warning, and the tunnels keep their phase 1 state.

### Search, Path Mode and IPAM

The connected subnets and static routes join the subnet index, so they can
be picked in **Path Mode** and appear on the **IPAM** page as subnets of
source **topology**, owned by the firewall. Once the firewall is an
inventory host with a config backup, Path Mode traces through it with its
interfaces, filter rules, NAT and routes read from `config.xml` (see
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

A firmware update, an audit finding or an incomplete audit is added to
the collection's warnings, so the collection shows as **partial**, but such
a warning does not stop availability tracking from removing a tunnel or
gateway the firewall no longer reports. A CARP warning (a VIP in `INIT`, a
demotion) and a failed call do: until a collection without them, a missing
entity turns unknown instead of being removed.

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
were read. A refused call (403) is a warning that names the privilege.
The ISC DHCPv4 answer and the ARP / NDP answers follow the OPNsense core
source; the Kea, Dnsmasq and ISC DHCPv6 row fields and the ISC time format
(`YYYY/MM/DD HH:MM:SS`, read as UTC) were inferred and are not verified
against a firewall. A field that is missing only leaves that column empty.

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
bare `[masked]`. The stored backups themselves are kept as collected, and
**Download** returns the file as stored, so it can be restored on the
firewall.

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
NAT and routes from the stored `config.xml`. Nothing is read from the
firewall for this beyond the collection itself, and nothing is ever
written to it.

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

The order follows pf: per interface and direction the first matching rule
with **Quick** set decides; a rule without Quick (a floating rule can be
one) decides only when no quick rule matches, and then the last matching
one wins. The rules of the automation / new rules model come first, then
floating rules, then interface group rules, then each interface's rules. A
flow no rule matches is blocked (OPNsense's default `block in`); what
leaves an interface passes unless a floating `out` rule says otherwise.

### Path trace through the firewall

In **Path Mode** a trace that reaches the firewall (as an inventory host)
now goes through it hop by hop:

1. **NAT in**: a 1:1 NAT or a port forward translates the destination (a
   port forward whose filter rule association is **Pass** lets the
   translated flow in by itself, as OPNsense does).
2. **Rules in**: the rules of the interface the flow arrives on, in the
   order above, ending in the default block. The item names the deciding
   rule by number and description.
3. **Route**: the connected networks, the static routes (gateways resolved
   to their address and interface; `Null4` / `Null6` routes drop the flow)
   and the default gateway.
4. **Rules out**: the floating `out` rules of the egress interface, if any.
5. **NAT out**: 1:1 NAT, the source NAT and manual outbound rules (in
   **Hybrid** and **Manual** mode) and, in **Automatic** and **Hybrid**
   mode, the automatic rules: the networks of the other interfaces leave an
   upstream interface (one with a gateway, or `wan`) as its address.

Replies pass by state. A rule that names something Plexus cannot evaluate
(an alias of host names, a URL table, GeoIP, a negated address, a
schedule) makes a flow it may match **unknown** rather than allowed or
blocked. Plexus has no SSH route capture of an OPNsense firewall, so a
destination that only the default route covers is marked **unknown** at
the route step (a learned route might be more specific); the rules and NAT
are still evaluated.

### What the trace does not read

Listed under **Not checked** on the hop when the configuration uses them:
IPsec, OpenVPN and WireGuard tunnels and the rules of their interfaces,
policy-based routing (a rule with a gateway: the rule is evaluated, the
gateway is not followed), the bogon table (**Block bogon networks**),
NPTv6, interface addresses learned by DHCP, PPPoE or tracking, and port
forwards or outbound rules that match on what is not read (source ports,
negations, unresolved aliases). Traffic shaping, captive portal and the
firewall's own services are not modelled.

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
the other firewalls keep theirs. `pkg audit` gives no severity, and Plexus
has no CVE severity source it could look the CVE ids up in, so a new
advisory is `medium`; a severity you change is kept, and so is the list of
firewalls when you edit the advisory.

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
| WireGuard peers | `GET wireguard/service/show` | VPN tunnels |
| OpenVPN instances and clients | `GET openvpn/service/search_sessions` (`searchSessions`) | VPN tunnels |
| Routing table | `GET diagnostics/interface/get_routes` (`getRoutes`) | Routing table |
| CARP virtual IPs, demotion, maintenance mode | `GET diagnostics/interface/get_vip_status` (`getVipStatus`) | High availability |
| Security audit | `GET core/firmware/running`, `POST core/firmware/audit`, `GET core/firmware/upgradestatus` | Firmware security audit |
| config.xml | `GET core/backup/download/this` | Config backup |
| Filter rule counters (evaluations, packets, bytes, states per rule uuid) | `GET firewall/filter_util/rule_stats` (`ruleStats`) | Rule counters |
| ARP table | `GET diagnostics/interface/search_arp` (`searchArp`; `get_arp` / `getArp` on older releases) | ARP, NDP and DHCP leases |
| NDP table | `GET diagnostics/interface/search_ndp` (`searchNdp`; `get_ndp` / `getNdp`) | ARP, NDP and DHCP leases |
| DHCP leases | `GET dhcpv4/leases/search_lease`, `GET dhcpv6/leases/search_lease` (`searchLease`), `GET kea/leases4/search`, `GET kea/leases6/search`, `GET dnsmasq/leases/search` | ARP, NDP and DHCP leases |

The options are `verify_tls`, `include_gateways`, `include_vpn`,
`include_ha`, `include_routes`, `include_firmware_audit`,
`include_clients`, `include_rule_stats`, `config_backup` and
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

Not read:

- the parts of `config.xml` listed under
  [What the trace does not read](#what-the-trace-does-not-read)
- the CARP peer as a node: each firewall of a pair is a source of its own;
  the pair is not drawn as one HA cluster
- child SA counts of legacy IPsec tunnels (only connections of the
  "Connections" model have a configured count)
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
| `GET` | `/api/opnsense/hosts/{host_id}/rules` | The rule view of the firewall's newest config backup (Config Backups feature); see [api-reference.md](api-reference.md#opnsense-firewall-rules) |
| `GET` | `/api/opnsense/hosts/{host_id}/rules/diff` | Rule, alias and NAT changes between two backups (`?from_backup=&to_backup=`, default: the newest two) |
