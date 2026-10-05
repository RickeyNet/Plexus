# AnyConnect (Cisco FMC) in the Topology Map - Usage Guide

The Topology page (**Network → Topology**) can include the Cisco Secure
Firewall Threat Defense (FTD) devices that terminate AnyConnect / Secure
Client remote access VPN, read from the Firewall Management Center (FMC)
that manages them. Each VPN headend, the interface its clients connect to,
the address pools its clients get and the users connected right now appear
on the same map as the devices Plexus discovers itself and any Meraki
organizations, Cato accounts and AWS accounts. They are covered by the same
search box and Path Mode, and are included in the HTML export.

An FMC is handled like a Cato account: it is added, collected and deleted
from the same **Sources** dialog, and everything in
[meraki-topology.md](meraki-topology.md) about the map, search, collection
history and the HTML export applies to it as well. This guide covers what is
different.

- Permission: the `topology` feature to view, `topology.write` to collect or
  delete snapshots, admin to manage FMCs and credentials
- API: `/api/meraki/*` with `provider: "anyconnect"`

Only an FMC-managed deployment is supported: AnyConnect on an ASA, or on an
FTD managed on-box by Firepower Device Manager, is not read.

## Quick start

1. Open **Network → Topology** and click **Sources** in the toolbar.
2. **Preview without an FMC.** Click **Load Sample**, then **AnyConnect**. A
   demo FMC with two FTDv headends is added to the map. Load the **AWS**
   sample as well to see the headends joined to their instances. Delete the
   demo FMC from the same dialog when you are done.
3. **Add your FMC.** Click **Add Source**, then **AnyConnect (FMC)**, and
   enter a name, the FMC address, the API username and its password.
4. **Check the login.** Click **Test Login**. It signs in to the FMC and
   lists the domains the user can see.
5. **Collect.** Click **Collect Now**. When it finishes the map updates.

Collection runs when you click **Collect Now**; it is not scheduled. The map
shows the most recent collection until you run another.

### FMC address, domain and credentials

- **FMC address**: `https://` and the host (and port) of the FMC, nothing
  else. A bare host is taken as https; `http` and a URL with a path are
  refused, and redirects are not followed, so the credentials cannot be sent
  elsewhere. Untick **Verify the FMC certificate** for an FMC that still has
  its self-signed certificate.
- **Domain**: the FMC domain to read, by name (`Global`, `Global/Branch` or
  just `Branch`) or UUID. Blank reads the Global domain. One entry reads one
  domain; add an entry per domain to cover several.
- **API username / password**: a dedicated FMC user whose role allows REST
  API access. Plexus only sends `GET` requests and never deploys or edits
  anything. The password is stored encrypted and never returned by the API
  or shown in the UI again. An FMC allows about 120 API requests per minute
  per user, so give this user to Plexus alone.

## On the map

AnyConnect data appears when the group filter is **All groups**.

| On the map | What it is |
|---|---|
| Site box | One VPN headend: an FTD that has a remote access VPN policy, named as in the FMC |
| FTD (firewall icon) | The device, with its health as the node border (red offline, amber alerting) |
| WAN triangle | Each access interface of the remote access VPN policy (the zone AnyConnect clients connect to), with the device interface's address |
| **AnyConnect users (N)** (star) | The users connected to that headend when the collection ran, as one node |
| **Cisco FMC** box | The FMC itself, as one node |
| Dotted grey link | **Managed by FMC**: the FMC and each headend it manages. It carries no traffic: Path Mode and the tidy-tree layout ignore it |
| Dashed tunnel | The users node's link to its headend |

An FTD without a remote access VPN policy is not drawn (tick **Every managed
device** on the entry to draw all of them); it is still listed in the FMC
node's **Managed devices** table. Remote users are one node per headend, not
one node per user: the users are listed in the node's details (user,
assigned IP, public IP, connection profile, group policy, client, OS,
protocol, login time, duration, bytes) and found by the search box.

### How a headend joins the rest of the map

- **Inventory hosts.** A headend whose serial number or management address
  (or an interface address) is that of a Plexus inventory host becomes that
  host's node, with both its SNMP/SSH data and its FMC data. For an inventory
  FTD, the SSH enrichment already runs `show vpn-sessiondb summary`.
- **AWS instances.** An FTDv in a VPC has no public address of its own: AWS
  knows it by the elastic IP mapped to its interface. It is matched to its
  instance by the private address of its access interface, under the same
  conditions as a Meraki vMX behind a NAT gateway: the instance forwards
  traffic (source/destination check off), exactly one instance and one
  access interface have the address, and the FMC model is a virtual one
  (FTDv, "Threat Defense for AWS"). The headend then stays in its own box and
  gains the instance's link to its VPC. See [aws-topology.md](aws-topology.md).
- **Public addresses.** An on-premises headend whose access interface has a
  public address is the far end of any site-to-site VPN another source
  configures with that address (an AWS customer gateway, a Meraki non-Meraki
  VPN peer).

### Device details

Click a headend for its tabs:

- **Device**: name, health, model, software, management address, serial,
  domain, deployment status, access control policy, remote access VPN policy
- **Interfaces**: the device's physical and sub-interfaces (name, zone,
  address, subnet, enabled, mode)
- **VLANs**: the **VPN address pools** of the policy (subnet, pool, range,
  connection profiles)
- **VPN**: the remote access VPN policy (connection profiles, access
  interfaces, SSL / IPsec IKEv2, ports, address assignment, connected users),
  the **Connection profiles** table (group policy, pools, authentication
  method and server, group alias and URL) and the **Access interfaces** table

Click the users node for the connected users, the FMC node for its version,
domain, the **Managed devices**, **Remote access VPN policies** and
**Address pools** tables.

### Search and Path Mode

The toolbar search covers everything collected: device names, serials,
management and interface addresses, pool names and subnets, connection
profile and group policy names, and connected users by name, assigned IP or
public IP.

In **Path Mode** a headend or one of its address pools can be picked like a
Meraki site or VLAN; typing an address picks the pool that contains it. The
headend is the gateway of its pools. The link between a headend and its FMC
is never part of a path: two headends managed by one FMC are joined only if
something else joins them (their VPC and transit gateway, a cabled neighbor,
an inventory link).

The path drawn follows links, not route tables, and the AWS check of a path
does not follow traffic through an FTD: a flow handed to a headend inside a
VPC is reported as *check incomplete*.

The address pools also appear on the **IPAM** page as subnets of source
**topology**, with the headends that hand them out, and are checked against
every other site's ranges and every VPC: a pool that two headends share, or
that is carved out of a VPC's range, is listed under **Overlapping Ranges**
(see the [Meraki guide](meraki-topology.md#ipam)).

## What is collected

| Data | FMC API resource | Option |
|---|---|---|
| Login and the domains the user can see | `POST /api/fmc_platform/v1/auth/generatetoken` | always |
| FMC version | `GET /api/fmc_platform/v1/info/serverversion` | always |
| Managed devices (name, model, software, health, management address, serial) | `devices/devicerecords` | always (required) |
| Remote access VPN policies and which devices they target | `policies/ravpns`, `assignment/policyassignments` | always |
| Connection profiles, address assignment, access interfaces of each policy | `policies/ravpns/{id}/connectionprofiles`, `.../addressassignmentsettings`, `.../accessinterfacesettings` | always |
| IPv4 address pools | `object/ipv4addresspools` | always |
| Interfaces of each headend | `devices/devicerecords/{id}/physicalinterfaces`, `.../subinterfaces` | Device interfaces |
| Connected remote access users | `health/ravpnsessions` | Connected users |

All configuration resources are under `/api/fmc_config/v1/domain/{uuid}/`.
Requests are sent one at a time and spaced out to stay inside the FMC limit
of 120 per minute; a rate-limit or server error is retried after a pause,
and an expired token is renewed once by signing in again.

The login and the device list are required. Everything else is best-effort:
if a request fails, the collection finishes as **partial**, the map is still
built, and the failure with the FMC's own error message is listed under
**Report** in the HTML map. Without the policy assignments every device is
drawn, because Plexus cannot tell which ones are headends; without the
interfaces a headend's access interface is drawn without an address and is
not matched to an AWS instance.

Connected users come from the FMC health API for remote access VPN sessions,
which exists on FMC 7.3 and later. On an older FMC the request fails, the
users nodes show **not collected**, and the rest of the map is unaffected.
The session fields FMC returns differ between releases; the user, assigned
and public addresses, profile, group policy, client, OS, protocol, login
time, duration and byte counts are read where present.

Not collected: IPv6 address pools, group policy contents (split tunnelling,
DNS), the FTD's own routes and NAT, high-availability pairs as one unit (both
members appear if both have the policy), and the AnyConnect client profiles.
Secrets in any payload (pre-shared keys, passwords, tokens) are dropped
before anything is stored.

## API reference

An FMC uses the organization endpoints listed in
[meraki-topology.md](meraki-topology.md#api-reference):

| Method | Path | Notes for AnyConnect |
|---|---|---|
| `GET` | `/api/meraki/orgs` | Each entry has `provider` (`meraki`, `cato` or `anyconnect`); `anyconnect_default_options` lists the FMC collection options |
| `POST` | `/api/meraki/orgs` | `{"name", "provider": "anyconnect", "base_url": "https://<fmc>", "org_id": "<domain>", "api_key": "<password>", "options": {"username": ..., "verify_tls"?, "device_name_contains"?, "include_all_devices"?, "include_interfaces"?, "include_sessions"?, "inventory_enrich"?}}` (admin). `api_key` carries the password |
| `POST` | `/api/meraki/orgs/{id}/validate` | Signs in to the FMC; `organizations` lists the domains the user can see (admin) |
| `POST` | `/api/meraki/orgs/{id}/build` | Start a collection; returns `job_id` |
| `POST` | `/api/meraki/sample?provider=anyconnect` | Add / refresh the demo FMC |
| `GET` | `/api/topology` | AnyConnect nodes carry `source: "meraki"` and a `meraki` reference whose `provider` is `anyconnect`; the FMC links have `protocol: "management"` |
| `GET` | `/api/meraki/subnets` | Includes the address pools of every headend (`provider: "anyconnect"`, `kind: "pool"`) |
