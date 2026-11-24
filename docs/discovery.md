# Discovery

Discovery finds devices on your network and adds them to an inventory group.
You give it one or more address ranges. Plexus probes each address with
SNMP, a TCP connection, and ping, reads `show version` over SSH where it can,
and lists what answered. You then add the devices you want to the group, or
let a sync add, update and optionally remove hosts in one step.

## Where it is and what you need

Discovery lives on the **Inventory** page:

| Control | Where | What it does |
|---|---|---|
| **Discover Devices** | Page header | Scans ranges and lets you pick devices to add to a group you choose. |
| **Sync** | Each group's row | Scans and writes the result straight into that group. |
| **SNMP Profiles** | Page header | Lists, creates and edits the SNMP settings that discovery uses. |
| SNMP profile list | Each group's row | Chooses the SNMP profile for that group (**No SNMP Profile** for none). |

Before you start:

- You need the `inventory` feature and write access to the target group.
  See [Object-level permissions](object-permissions.md) if your account is
  limited to some groups.
- For SNMP, an admin creates an SNMP profile and you assign it to the
  group. A group with no profile uses the global SNMP setting, which is off
  by default and set through the API (`/api/admin/snmp-discovery`, admin).
  When SNMP is off for the group, discovery uses the other probes.
- For SSH `show version`, set a Plexus service credential in Settings, or
  pick a credential in the discovery dialog. If you are not an admin, the
  service credential signs in only to addresses that are already inventory
  hosts you may change (see [Rules worth knowing](#rules-worth-knowing)).

## Set up SNMP

1. Select **SNMP Profiles**, then **+ New Profile** (admins only).
2. Fill in the profile:

   | Field | Meaning |
   |---|---|
   | **Profile Name** | Required. |
   | **Enabled** | The profile is used only when this is ticked. |
   | **Version** | **SNMPv2c** or **SNMPv3**. |
   | **Port** | Default `161`. |
   | **Retries** | 0 to 5. Default `0`. |
   | **Community (v2c)** | The read community. |
   | **Timeout Seconds** | 0.2 to 10. Default `1.2`. |
   | **Enable inferred topology (FDB+ARP)** | Adds dashed links on the topology map between devices that have no CDP or LLDP, from the MAC and ARP tables. It costs extra SNMP queries on busy switches. |
   | **Username**, **Auth Protocol**, **Auth Password**, **Privacy Protocol**, **Privacy Password** | SNMPv3 settings. Auth protocols: SHA, SHA-256, SHA-512, MD5. Privacy protocols: AES128, AES192, AES256, DES. |

3. Select **Create Profile**.
4. In the group's row, choose the profile in the SNMP profile list.

A host can also have its own SNMP profile, set in the host's edit dialog
or for many hosts at once (`POST /api/hosts/snmp-profile`). Polling,
topology, MAC/ARP and data source discovery of an inventory host use, in
order: the host's own profile, the group's profile, the group's legacy
per-group profile, then the global SNMP setting. A host with its own
enabled profile is polled even when its group has SNMP off. Range scans,
syncs and onboards probe addresses, not hosts, so they always use the
group's settings.

The SNMPv3 passwords can hold a secret reference such as
`{{secret.SNMP_AUTH}}` instead of the password. The secret variable must
already exist, or saving fails.

To check the settings without scanning, open **Discover Devices**, choose
the **Target Inventory Group**, tick **Test only**, enter a **Test Target
IP** and select **Test SNMP**. The result shows the host name, device type,
protocol, vendor, OS and `sysDescr` the device returned, or "SNMP Failed".
The test sends the group's SNMP community or v3 keys to that address, so
only an admin can test any address; other users can test the address of a
host already in the group (one they may change).

## Scan and add devices

1. Select **Discover Devices**.
2. Choose the **Target Inventory Group**. You can pick only groups you may
   change.
3. Enter the **CIDR Targets**, one per line or separated by commas, for
   example `192.0.2.0/24`.
4. Check the options (see the table below) and select **Scan Network**.
5. Watch the progress: addresses scanned, devices found, the address being
   probed, and a line for each device found. **Cancel** stops the scan.
6. In **Discovered Devices**, every device is ticked. Untick the ones you do
   not want, or use **Select All** / **Deselect All**.
7. Select **Onboard Selected**. The result shows how many hosts were
   **Added** and **Updated**.

| Option | Default | Meaning |
|---|---|---|
| **Timeout Seconds** | `0.35` | Wait for each probe, 0.05 to 5 seconds. |
| **Max Hosts** | `256` | Stop after this many addresses, 1 to 4,096. |
| **Device Type** | `unknown` | The platform given to a device that answers only on TCP 22 or 443 with nothing that names it. |
| **Hostname Prefix** | `discovered` | The start of the name given to a device with no DNS name, for example `discovered-192-0-2-10`. |
| **Use SNMP discovery first** | On | Try SNMP with the group's profile before the TCP probe. |
| **Fall back to ICMP ping** | On | Ping addresses that answer neither SNMP nor TCP. |
| **Read model/serial/version over SSH** | On | Log in and read `show version` from devices that answered SNMP or TCP 22. |
| **SSH Credential** | The group's remembered credential, else the service credential | The credential used for `show version`. It is remembered for the target group (see below). |

### The group remembers its SSH credential

The credential a scan or sync of a group runs with is remembered for that
group. The next **Discovery Scan** or **Sync** of the group preselects it,
so devices with their own login (an APC UPS card, for example) keep being
read with it. It is preselected only when it is in your credential list
(your own credentials, or the service credentials an admin sees); otherwise
the service credential is preselected and the help under the list says the
group remembers one you cannot use.

- **Change it**: pick another credential and run the scan or sync.
- **Forget it**: pick the Plexus service credential (the Settings default)
  and run, or call `DELETE /api/inventory/{group_id}/discovery/credential`.
- A scan or sync sent with no `credential_id` (an API call, an older client)
  uses the group's credential when you may use it, else the service
  credential. The result's `ssh_enrichment.credential_source` says which
  (`group` or `service`), and `ssh_enrichment.note` says why the group's
  credential was not used. It never fails for that reason.
- A deleted credential is forgotten; deleting the group deletes what it
  remembers.
- Changes are written to the audit log (`inventory`,
  `group.discovery_credential`), with the credential ids only.

## Sync a group

**Sync** scans and writes the result into the group in one step. There is no
pick list.

1. Select **Sync** in the group's row.
2. **CIDR Targets** is filled in with the group's host addresses. Keep it to
   check the existing hosts, or change it to scan other ranges. If you clear
   it, Plexus uses the group's host addresses.
3. **SSH Credential** preselects the credential the group remembers from
   its last scan or sync (see
   [The group remembers its SSH credential](#the-group-remembers-its-ssh-credential)).
4. Tick **Remove hosts not found in this scan** only if hosts that do not
   answer should be deleted. Plexus asks you to confirm and names the group
   and its host count.
5. Select **Run Sync**. The result shows **Added**, **Updated** and
   **Removed**.

## How a probe works

Plexus probes each address in this order and stops at the first answer:

| Probe | What it learns |
|---|---|
| SNMP (with the group's profile) | `sysName`, `sysDescr`, vendor, OS, platform, model and serial from the entity table, software version and device category. |
| TCP 22, then TCP 443 | That the device is up. On port 22 the SSH banner can name the vendor and platform (Cisco, Juniper, Arista, Fortinet). The name comes from reverse DNS. |
| ICMP ping | That the device is up. The platform is `icmp_only`, so monitoring does not try SNMP or SSH on it. |

Then, if SSH is on and a credential is set, Plexus reads `show version` from
each device that answered SNMP or TCP 22. A platform read this way replaces
the guess from SNMP or the banner. Results marked `(SSH)` in the list come
from `show version`. A login failure does not stop the scan; the error shows
on that device and in a summary under the results.

Two cases skip or soften the login:

- A device SNMP identified as a platform without a command line Plexus drives
  (an APC Smart-UPS card, an Aruba Instant On or Netgear smart switch, an
  ICMP-only host) is not logged into: SNMP already gave its facts, and a
  Cisco-style session would only fail on it.
- When the credential has an enable secret and the device has no Cisco-style
  enable mode, discovery reads `show version` in user mode instead of failing
  the login.
- A device of unknown platform that answers `show version` with an APC
  Network Management Card status code (`E101: Command Not Found`) is asked
  `upsabout` and `about` in one more login; a card with a UPS behind it is
  added as an **APC Smart-UPS (NMC)** with its model, serial and the card's
  firmware as its software version (`docs/apc-ups.md`). A PDU or transfer
  switch card stays unknown.

## What discovery fills in on a host

| Host value | Where it comes from |
|---|---|
| Host name | The SNMP `sysName` or the name `show version` reports, else reverse DNS, else a name from the prefix and the address (`snmp-` for SNMP answers). |
| Address | The address that answered. Other addresses of the same device become aliases. |
| Platform | `show version` over SSH, then SNMP `sysDescr`, then the SSH banner, then the **Device Type** field. |
| Status | `online` for every device found. |
| Model, software version, serial, device category | SNMP and `show version`. |
| Device type and role | See [Device model](device-model.md#how-discovery-fills-it-in). |

### One device, one host

A device with several addresses becomes one host. Discovery groups the
addresses it found when they share a serial number, a real `sysName`, or
appear in one device's own interface address table (read over SNMP).

For each device, discovery looks for an existing host in the group: first by
serial number, then by address (primary or alias), then by `sysName`. A
match is updated; no match adds a new host.

Existing hosts in the group that are clearly the same device are deleted:
those with the same serial number, or whose address is in the device's
interface address table. A matching name alone never deletes a host. These
deletions count as **Removed**.

## Rules worth knowing

- **The service credential and new addresses.** The addresses of a scan
  come from you, so one of them could be a device you control. For a user
  who is not an admin, the Plexus service credential is used only when
  every address of the scan or sync is the address of an inventory host
  you may change and whose address an admin confirmed (a sync with no
  ranges re-reads the group's own hosts, so it qualifies when they are
  confirmed). Otherwise the scan or sync is refused with `403` and a
  message naming the addresses: pick one of your own credentials, untick
  **Read model/serial/version over SSH**, or ask an admin to run it. Admins and the server
  API token are not limited.
- **The group's SNMP settings and new addresses.** The communities and
  SNMPv3 keys of the group's SNMP settings are admin-only secrets. For a
  user who is not an admin, a scan or sync sends them only to the address
  of an inventory host you may change and whose address an admin
  confirmed. Every other address is still probed, without SNMP (SSH and
  HTTPS ports, and ping when **ICMP** is on), and the result says how many
  addresses were probed that way and why (`snmp_withheld` in the API: the
  scan job result, the `start` and `done` events of a streamed scan or
  sync, and the sync response). Admins, the server API token and the
  scheduled discovery sync send them to every address.
- **Hosts added by a non-admin await confirmation.** A host that a sync or
  onboard by a user who is not an admin adds, or whose address it changes,
  is marked **Awaiting admin confirmation**: Plexus sends it no service
  credential, default credential or shared SNMP secret (and does not walk
  its interface addresses with the group's SNMP profile) until an admin
  confirms the address on the Inventory page. The scheduled discovery sync
  is an admin's, so the hosts it adds are confirmed.
- **Large ranges are refused.** A range with more than 65,536 addresses, or
  more than ten times **Max Hosts** if that is larger, is rejected.
- **At most 4,096 ranges per request.** A range listed twice is scanned
  once. A list whose ranges overlap so much that more than that same number
  of addresses (65,536, or ten times **Max Hosts**) would have to be walked
  is refused with `400`; remove the overlapping entries.
- **At most 3 discovery runs per user at once.** A scan or sync (streamed,
  inline or as a background job) and a topology neighbor discovery each
  count until they finish or the browser closes the stream; the server
  runs at most 12 in all. Past either limit a new one is refused with
  `429` and a message saying which limit was hit. Admins and the server API
  token (one identity, however many clients use it) have the same limit.
  The server settings `APP_DISCOVERY_RUNS_PER_USER` and
  `APP_DISCOVERY_RUNS_TOTAL` change the numbers.
- **Closing the progress stream stops the scan.** When the browser leaves a
  streamed scan, sync or topology discovery, the probes and SSH sign-ins
  still pending are cancelled.
- **At most 64 probes run at once** by default. The server setting
  `APP_DISCOVERY_MAX_CONCURRENT_PROBES` changes it.
- **SSH reads time out after 45 seconds** per device.
- **Updated** counts hosts whose name or platform changed. Model, version and
  serial are written for every matched host.
- **A weak guess does not overwrite a platform.** A platform guessed only
  from an SSH banner or HTTPS fills an `unknown` platform but does not
  replace one the host already has.
- **Remove hosts not found** cannot be undone.
- **Push to external IPAM.** Hosts that a sync or onboard adds or renames are
  sent to external IPAM sources that have push on. See
  [IP address management](ipam.md#external-ipam-sources).
- **Scheduled discovery** can run a sync per group on a timer. It is off by
  default, runs every 15 minutes when on (1 minute to 24 hours), and signs
  in with the group's remembered credential only when that is a service
  credential: a scheduled run has no user to check a personal credential
  against, so a group that remembers a personal credential is read with
  the Plexus service credential. It is set through the API only (see
  below).
- **Deleting an SNMP profile** unassigns it from every group and host that
  uses it; those hosts go back to their group's settings.

## Who can do what

| Action | Needs |
|---|---|
| Scan, sync, onboard, test SNMP | The `inventory` feature and write access to the group (testing SNMP against an address that is not a host of the group: admin) |
| Choose a group's SNMP profile | The `inventory` feature and write access to the group |
| Choose a host's SNMP profile, test SNMP on a host | The `inventory` feature and write access to the host's group |
| See SNMP profiles | The `inventory` feature (names and settings only; the community strings and v3 keys are shown to admins only) |
| Create, change or delete SNMP profiles | Admin |
| Use a stored credential for SSH | Access to that credential (your own, or any as admin) |
| Read new addresses over SSH with the Plexus service credential | Admin (others: only addresses of inventory hosts they may change whose address an admin confirmed) |
| Probe new addresses with the group's SNMP settings | Admin (others: only addresses of inventory hosts they may change whose address an admin confirmed; other addresses are probed without SNMP) |
| Confirm a host address | Admin |
| See which credential a group remembers | The `inventory` feature and read access to the group |
| Forget a group's credential | The `inventory` feature and write access to the group |
| Set scheduled discovery | Admin |

Scans that write to the inventory are written to the audit log under the
`inventory` category (`discovery.sync`, `discovery.onboard`).

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data. See
[API reference](api-reference.md) for the full list.

```
POST /api/inventory/{group_id}/discovery/scan
GET  /api/inventory/discovery/jobs/{job_id}
POST /api/inventory/{group_id}/discovery/onboard
POST /api/inventory/{group_id}/discovery/sync
POST /api/inventory/{group_id}/snmp-discovery-profile/test
GET  /api/inventory/discovery/ssh-defaults
GET  /api/inventory/{group_id}/discovery/ssh-defaults
DELETE /api/inventory/{group_id}/discovery/credential
GET  /api/admin/snmp-profiles
PUT  /api/inventory/{group_id}/snmp-profile-assignment
POST /api/hosts/snmp-profile
POST /api/hosts/{host_id}/snmp-profile/test
GET  /api/admin/discovery-sync
PUT  /api/admin/discovery-sync
POST /api/admin/discovery-sync/run-now
```

The scan and sync endpoints also have a `/stream` form that sends progress
as server-sent events.

Start a scan:

```json
POST /api/inventory/3/discovery/scan
{
  "cidrs": ["192.0.2.0/24"],
  "timeout_seconds": 0.35,
  "max_hosts": 256,
  "use_snmp": true,
  "use_icmp": true,
  "use_ssh": true
}
```

```json
{ "job_id": "8c1d2e", "status": "running", "group_id": 3, "total_targets": 254 }
```

Add `"credential_id": 12` to sign in with a stored credential you may use;
it becomes the group's remembered credential. Without it the group's
remembered credential is used, else the service credential; send
`"use_service_credential": true` to use the service credential and make the
group forget its own. `GET /api/inventory/{group_id}/discovery/ssh-defaults`
returns the service defaults plus `group_credential_id` (null when none).

Poll the job until it is no longer `running`. Its `result.discovered_hosts`
can be sent to the onboard endpoint as `{"discovered_hosts": [...]}`.

Run a sync that removes hosts that do not answer:

```json
POST /api/inventory/3/discovery/sync
{ "cidrs": ["192.0.2.0/24"], "remove_absent": true }
```

The answer (the `ssh_enrichment` summary left out):

```json
{
  "group_id": 3,
  "scanned_hosts": 254,
  "discovered_count": 12,
  "sync": { "added": 2, "updated": 1, "removed": 1, "matched": 12, "existing_before": 11, "existing_after": 12 }
}
```

Set scheduled discovery:

```json
PUT /api/admin/discovery-sync
{
  "enabled": true,
  "interval_seconds": 3600,
  "profiles": [
    { "group_id": 3, "cidrs": ["192.0.2.0/24"], "remove_absent": false }
  ]
}
```

Unknown fields in a scan or sync request give `422`. On the scan endpoint, a
range that is too large gives `400`.
