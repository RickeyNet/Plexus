# Sync with NetBox, Nautobot and ServiceNow

Plexus can keep its records in step with another source of truth: a NetBox
or Nautobot instance, or a ServiceNow CMDB. A **sync job** says which object
types to sync over which **connection**, in which direction, and what to do
when both sides disagree. Every run (a dry run or a real one) is kept with
the change it planned for every object and what came of it, so you can see
exactly what a sync would do before it does it.

Open **Assets > Sync**. The page has three tabs: Jobs, Run history and
Connections.

## Access

Sync has its own feature key, `sync`, granted in access groups like any
other:

| Right | Can |
|---|---|
| `sync` | see connections, jobs and every run with its changes |
| `sync.write` | add, edit and delete jobs; start dry runs and runs |
| admin | add, edit, test and delete connections (a connection binds a Plexus service credential) |

A job that writes **into Plexus** (direction *Import* or *Both ways*) also
needs the rights of the records it writes, checked when the job is saved and
when it is run for real: admin for sites, manufacturers, device types, VRFs,
VLANs, prefixes and IP addresses (these are admin-managed in Plexus), and
`inventory.write` for devices. An *Export* job only needs `sync.write`. A
dry run writes nothing and needs `sync.write` only. Scheduled runs act for
the job: the change log shows them as `sync:<job name>`.

Accounts limited to selected inventory groups read jobs and runs (a run's
entries only for their own devices) and cannot add, change, delete or run
jobs (see [object-level permissions](object-permissions.md)).

## Connections

A connection is one remote instance:

| Field | Notes |
|---|---|
| System | NetBox, Nautobot (2.x) or ServiceNow CMDB |
| Address | `https://host[:port][/path]`. Plain `http`, a user in the address, a query or a fragment is refused: the address decides where the credential is sent |
| Sign-in | NetBox and Nautobot: an API token. ServiceNow: basic (username and password) or OAuth client credentials |
| Service credential | A Plexus **service credential** (Settings > Credentials). The secret is never stored on the connection: the token is the credential's password; for basic auth the username and password; for OAuth the client id is the username and the client secret the password |
| TLS | Verify the certificate (default), optionally trusting only a pasted CA bundle (PEM) |
| Timeout | 5 to 300 seconds per request |

**Test** signs in and reads one record; the outcome is shown in the list.
Every request goes through the outbound SSRF guard (no loopback, link-local
or metadata addresses) and never follows a redirect. Requests are paced and
retried on HTTP 429 and 5xx with back-off.

A connection used by jobs cannot be deleted, and its system cannot change.

## Jobs

| Field | Notes |
|---|---|
| Connection | The remote instance |
| Direction | *Import into Plexus*: the remote system is the source of truth. *Export from Plexus*: Plexus is. *Both ways*: see below |
| Conflict policy | Both ways only: *Remote wins*, *Plexus wins* or *Skip conflicts* |
| Delete records missing from the source | Import and export only. Deletes on the target the records the source does not have |
| Object types | Sites, manufacturers, device types, VRFs, VLANs, prefixes, IP addresses, devices |
| Inventory group for new devices | Where a device created in Plexus goes (a path such as `Synced / NetBox`, created on the first real run; default `Synced`) |
| Run every | Minutes between scheduled runs, 5 to 10080; 0 runs only by hand |
| Field mappings | Optional overrides of the remote paths (below) |

A run handles the object types in dependency order: sites, manufacturers,
device types, VRFs, VLANs, prefixes, IP addresses, devices. A device's site
and device type therefore exist before the device in the same run.

### How a run decides

Each object type is read from both sides into one canonical shape and the
records are paired by their **natural key**, never by a database id:

| Object type | Natural key | Fields |
|---|---|---|
| Sites | name (ignoring case) | description, status, address, latitude, longitude |
| Manufacturers | name (ignoring case) | description |
| Device types | manufacturer + model (ignoring case) | part number, height (units), description |
| VRFs | name (ignoring case) | RD, description |
| VLANs | VLAN id + site | name, description |
| Prefixes | prefix + VRF | description, site, VLAN id |
| IP addresses | address | prefix, VRF, DNS name, description |
| Devices | name (ignoring case) | primary IP, site, manufacturer, device type; role, platform and serial when turned on |

Values are normalised before they are compared (addresses and networks in
canonical form, DNS names and statuses in lower case, coordinates to 6
places). Only fields **both** sides read are compared, so a field one side
does not have is never reported as a difference.

- **Import**: a record only the remote system has is created in Plexus; a
  differing field is written to Plexus. With *delete missing*, a record only
  Plexus has is deleted from Plexus.
- **Export**: the mirror image, written to the remote system.
- **Both ways**: a record missing on either side is created there; a field
  empty on one side is filled from the other; a field with two different
  values is a **conflict**, settled by the policy: *Remote wins* writes the
  remote value to Plexus, *Plexus wins* writes Plexus's value to the remote
  system, *Skip conflicts* records a conflict entry and changes nothing.
  Both-ways runs never delete: without a baseline a record missing on one
  side cannot be told from a new one on the other.

A safety stop holds back deletes: when a run would delete more than half of
a type's records on one side (and more than 10), every delete of that type is
skipped with a message. Check the mapping or the remote filter.

### Dry run and run now

**Dry run** reads both sides and records every planned change without
writing anything. For the changes into Plexus it also runs Plexus's own
checks and puts what Plexus would refuse in the entry's message. In a dry
run the objects the same run would create earlier (a VRF before its
prefixes) do not exist yet, so a reference to one shows in those messages; a
real run creates them first.

**Run now** writes the plan (Plexus first, then the remote system) after a
confirmation. One run of a job at a time.

### Run history

Each run keeps its status (*success*; *partial* when an object failed or a
type could not be read; *failed* when the run could not start), who started
it, the counts per object type and every planned change with:

- the object, the action (*create*, *update*, *delete*, *conflict*) and the
  side it writes to;
- the outcome: *planned* (dry run), *applied*, *failed* (with the reason the
  target gave) or *skipped*;
- the per-field diff: before and after on the target, or Plexus and remote
  values for a conflict.

The last 50 runs of each job are kept; deleting a job deletes its runs. A
run that was in progress when Plexus stopped is marked failed at the next
start.

## What a synced change goes through in Plexus

Writes into Plexus use the same code paths as people do, so every rule and
record that applies to a manual change applies to a synced one:

- VRFs, VLANs, prefixes, IP addresses and devices go through the
  [bulk import](bulk-import.md) pipeline: its checks (references, field
  limits, reserved addresses) and the admin
  [data validation rules](validation-rules.md) apply, and the writes are in
  the [change log](change-log.md), the audit log and event webhooks.
  Prefixes and addresses are those of Plexus's built-in IPAM source. An
  address needs a Plexus prefix that contains it.
- Sites are written like the Organization page writes them; manufacturers
  and device types like the device catalogue.
- Every run is audited (category `sync`, actions `run` and `dry_run`, with
  the counts), and so is every change to a connection or job.

A device's serial number is read from the device, never written by a sync.

## Field mappings

Each system has a default mapping of every canonical field to a remote path
(shown in the job dialog under *Field mappings*). A job can override it per
object type with JSON:

```json
{
  "devices": {"role": true, "serial": "asset_tag", "site": false},
  "vrfs": {"_endpoint": "u_cmdb_ci_vrf"},
  "vlans": {"_create_defaults": {"status": "reserved"}}
}
```

- a **path** (dotted for a nested object, `site.name`) syncs the field at
  that path: read from it, and written to it (a nested path is written as a
  lookup, `{"site": {"name": "branch-1"}}`);
- `true` turns an optional field (device role, platform, serial) on at the
  default path;
- `false` leaves the field out of the sync. Key fields cannot be left out;
  a key field a system does not hold by default (a prefix's VRF on
  ServiceNow) reads empty there, so only records with it empty pair up and
  can be created on that side;
- `_endpoint` changes the API path (NetBox, Nautobot: `dcim/devices`) or
  table (ServiceNow); `_create_defaults` sets the values every create sends;
  `_query` (ServiceNow) an encoded query that filters the records read.

An unknown object type or field, a key field turned off, or an optional
field turned on where the system has no default path is refused when the job
is saved.

## Setting up each system

### NetBox

1. In NetBox, create an API token for a user that may read (and, for export
   or both-ways jobs, write) the object types to sync.
2. In Plexus, add a **service credential** whose password is the token (the
   username is not used).
3. Add a connection: system *NetBox*, the address (`https://netbox.example.com`),
   sign-in *API token*, the credential. Click **Test**.

Defaults: sites `dcim/sites`, manufacturers `dcim/manufacturers`, device
types `dcim/device-types`, devices `dcim/devices`, VRFs `ipam/vrfs`, VLANs
`ipam/vlans`, prefixes `ipam/prefixes`, IP addresses `ipam/ip-addresses`.
Sites, manufacturers and device types are created with a slug made from the
name; devices, VLANs, prefixes and addresses are created `active`. A device's
primary IP and its manufacturer are read only (the primary IP is an address
assigned to an interface; the manufacturer comes with the device type), and
creating a device in NetBox needs its role: turn `role` on for export jobs.
An address is read with its mask (`192.0.2.10/24` gives the address and its
prefix `192.0.2.0/24`) and written with the prefix's length or the host mask.
On NetBox 4.2 and later a prefix's site is a scope; map `site` to `false` or
to your scope path.

### Nautobot

Nautobot 2.x, set up like NetBox (an API token as a service credential's
password). Differences in the defaults:

- sites are `dcim/locations`, created with location type `Site` (change it
  with `"sites": {"_create_defaults": {"location_type": {"name": "Campus"}}}`);
- statuses are records written by name (`Active`, `Planned`);
- VRFs, prefixes and IP addresses are created in the `Global` namespace;
  a prefix's VRFs are a many-to-many in 2.x, so prefix and address VRFs are
  not mapped by default: Nautobot prefixes pair with Plexus's global
  prefixes, and a Plexus prefix in a VRF is not exported (its entry is
  skipped);
- records are read with `depth=1`, so a device's manufacturer is not read
  (the device type identifies it).

### ServiceNow CMDB

1. Create an integration user with the `itil` and `cmdb_read` roles (and
   write access to the tables for export or both-ways jobs), or an OAuth
   application registry entry for the client-credentials grant.
2. In Plexus, add a service credential: for basic auth the user's name and
   password; for OAuth the client id as username and the client secret as
   password.
3. Add a connection: system *ServiceNow CMDB*, the instance address
   (`https://example.service-now.com`), sign-in *Basic* or *OAuth*, the
   credential. Click **Test** (it reads one `cmdb_ci_netgear` record).

The adapter uses the Table API (`/api/now/table/<table>`), reads display
values (a reference such as a CI's location reads as the location's name)
and writes display values, so ServiceNow resolves a reference by name.
Default tables:

| Object type | Table | Fields |
|---|---|---|
| Sites | `cmn_location` | name, street, latitude, longitude |
| Manufacturers | `core_company` (`manufacturer=true`) | name |
| Device types | `cmdb_hardware_product_model` | manufacturer, name (model), model_number, rack_units, short_description |
| Devices | `cmdb_ci_netgear` | name, ip_address, location, manufacturer, model_id, serial_number |
| Prefixes | `cmdb_ci_ip_network` | name, short_description, location |
| IP addresses | `cmdb_ci_ip_address` | ip_address, fqdn, short_description |
| VLANs | `cmdb_ci_vlan` | vlan_id, name, short_description, location |
| VRFs | none: set `_endpoint` to your VRF class to sync them | name, short_description |

A ServiceNow network has no VRF by default, so prefixes pair with Plexus's
global prefixes and a Plexus prefix in a VRF is not exported (its entry is
skipped); map `vrf` to your field to sync them. Instances customise these
classes; change any table or field with the job mapping.

## API

See [api-reference.md](api-reference.md#sync-netbox-nautobot-servicenow).
Code: `netcontrol/sync/` (models, diff engine, adapters, runner),
`netcontrol/routes/sync.py`, storage `routes/db/sync.py`, migration 0104.
