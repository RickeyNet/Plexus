# IP address management

The IPAM page shows your address space in one list. It merges subnets from
the inventory, cloud accounts, topology collections, subnets you define in
Plexus, and external IPAM systems. For each subnet you see how many
addresses are used, reserved and free. The page also lists duplicate IP
addresses, ranges that two sites claim, drift against an external IPAM
system, and DHCP scope use.

This guide covers the **Subnets** tab. The **VRFs** and **VLANs** tabs are
described in [VRFs and VLANs](vrfs-and-vlans.md). Tags and custom fields on
a subnet are described in [Custom fields and tags](custom-fields-and-tags.md).

## Where it is and what you need

- Open **Assets > IPAM** in the sidebar. The page title is **IP Address
  Management**.
- You need the `ipam` feature to see the page.
- Every change on this page (defining subnets, reservations, allocations,
  sources, DHCP servers, reconciliation) needs an admin.
- To add an external IPAM source you need its base URL and an API token or
  a user name and password. Supported systems are NetBox, phpIPAM and
  Infoblox.
- To add a DHCP server you need its base URL and, if it asks for it, a token
  or a user name and password. Supported servers are ISC Kea, Windows DHCP
  and Infoblox.

## Where subnets come from

Each subnet row has one or more source badges in the **Sources** column:

| Source | Where the subnet comes from |
|---|---|
| `inventory` | Inventory host addresses. Plexus groups each host address into its /24 (IPv4) or /64 (IPv6). |
| `cloud` | Cloud resources with a CIDR, such as VPCs, VNets and subnets. |
| `topology` | The latest Topology collection of each Meraki organization, Cato account and Cisco FMC (VLANs, LANs, SVIs, static routes, network ranges, VPN pools). |
| `local` | Subnets an admin defined in Plexus with **+ Define Subnet**. |
| `external` | Prefixes synced from an external IPAM source. The source names show as more badges. |

A subnet is identified by its CIDR and its VRF. The same range in two VRFs
is two rows.

## Filter the list

The controls at the top of the page:

- **Inventory Group** limits inventory hosts to one group. **All Groups**
  uses every group.
- **Include Cloud CIDRs** and **Include Topology Subnets** add or remove
  those sources.
- **Filter** narrows the list by tag and custom field value. See
  [Custom fields and tags](custom-fields-and-tags.md).
- **Refresh** reloads every panel on the page.

## Define a subnet

1. Select **+ Define Subnet**.
2. Enter the **CIDR**, for example `198.51.100.0/24`. Optionally add a
   **Description** (255 characters at most) and a **VRF** (120 characters at
   most).
3. Select **Add Subnet**.

The subnet is stored in the built-in source named "Plexus (Built-in)" and
shows with the `local` badge. A VRF name that has no VRF record yet gets one.

## Inspect a subnet

Select **Drilldown** on a row. The **Subnet Drilldown** panel on the right
shows that subnet:

- The usable address count, and tiles for **Available**, **Allocated** and
  **Reserved** addresses.
- **Tags and Custom Fields** for the subnet. Admins see an **Edit** button.
- **Available Address Preview**: the first 20 free addresses.
- **Reserved Ranges**: each range, its size and its reason.
- **Allocations**: every address in use, from inventory hosts, local
  allocations and external IPAM allocations. Each one shows a badge for its
  source (`inventory`, `local` or `external`) and a **Reserved** badge when
  it is inside a reserved range. A line "On ..." names the device interfaces
  that carry the address.
- **Interface addresses**: device interface addresses in the subnet that no
  allocation lists.
- **External Prefix Context** and **Cloud Resources** when the subnet comes
  from those sources.

### Reserve a range

1. In the drill-down, select **+ Add Reservation**.
2. Enter the **Start IP**. The **End IP** is optional; without it the range
   is one address. Enter a **Reason** (default "Reserved range").
3. Select **Reserve**.

To delete a reservation, select its delete button and confirm.

### Record an allocation

1. In the drill-down, select **+ Add IP Allocation**.
2. Enter the **IP Address**. It must be inside the subnet. Optionally add a
   **Hostname / Label** and a **Description**.
3. Select **Add Allocation**.

The allocation is stored in the built-in source with the status `active`,
and the address is added to the address history.

## Read the subnet list

| Column | Meaning |
|---|---|
| **Subnet** | The CIDR, IP version, prefix length and address count. Badges show tags, the VRF, VLAN ids and the number of overlaps. |
| **Capacity** | Available, allocated and reserved addresses, and the percent used. |
| **Groups** | Inventory groups with hosts in the subnet. |
| **Sources** | Where the subnet comes from (see above). |
| **Preview** | A few host names, cloud resources, sites, external sources and free addresses. |

In the list, **allocated** counts the distinct inventory host addresses in
the subnet. Usable addresses leave out the network and broadcast addresses
for prefixes shorter than /31. Available is usable minus allocated minus
reserved. The drill-down also counts local and external allocations.

The tiles at the top of the page:

| Tile | Meaning |
|---|---|
| **Tracked Hosts** | Inventory hosts with an address. |
| **Total Subnets** | All subnet rows. |
| **Cloud CIDRs**, **Topology Subnets**, **External Subnets**, **Inventory Subnets**, **Local Subnets** | Subnets from each source. |
| **Duplicate IPs** (red) | Addresses used by hosts in more than one inventory group in the same VRF. |
| **External Allocations** | Allocations synced from external sources. |
| **Inventory / Cloud Overlaps** (yellow) | Subnets that are both an inventory subnet and a cloud CIDR. |
| **Overlapping Ranges** | Pairs of ranges two owners hold. Red when a pair is a VPN conflict. |

### Overlapping ranges

The **Overlapping Ranges** panel lists pairs of ranges held by two sites, or
by a site and a VPC or VNet. Each pair says whether one range "is the same
range as" or "contains" the other. A pair is marked **VPN conflict** (red)
when both ranges are advertised into a VPN, so traffic for one goes to the
wrong site. Other pairs are marked **Overlap** (yellow). Static routes are
listed as subnets but not checked. The panel shows at most 500 pairs.

### Duplicate IP conflicts

The **Duplicate IP Conflicts** panel lists each address that hosts in two or
more inventory groups use in the same VRF, with its VRF and the number of
inventory entries. The same address in two different VRFs is not a
conflict.

## External IPAM sources

The **External IPAM Sources** panel lists each source with its last sync
status, time and message, and its number of subnets and allocations.

1. Select **+ Add Source**.
2. Fill in the **Add IPAM Source** dialog: **Provider**, **Name** (120
   characters at most), **Base URL**, **Auth Type** (**API Token** or
   **Basic Auth**), **API Token / Password**, **Username (Basic Auth)**,
   **Sync Scope**, **Notes**, and the boxes **Enabled**, **Push host
   updates** and **Verify TLS**.
3. Select **Add Source**.
4. Select **Sync Now** to pull the source's prefixes and allocations.

When you edit a source, enter the token or password again. The field says
"Leave blank to keep existing", but saving the dialog with it blank clears
the stored secret today. The kebab menu on a source has **Reconcile**,
**Edit** and **Delete**.

**Scheduled auto-sync** syncs every enabled source on a schedule. Set the
interval in minutes (5 to 1,440) and select **Save**. The default is on,
every 30 minutes.

**Push host updates** sends inventory changes to the source. When a host is
added or edited, or a discovery sync adds or renames one, Plexus writes the
address and host name to every enabled source with push on. A failed push
does not stop the inventory change.

## Reconciliation

Reconciliation compares inventory host addresses with the allocations of
one source, as of its last sync. Choose **Reconcile** in a source's menu.

| Drift | Meaning |
|---|---|
| **Missing in IPAM** | An inventory host has the address; the source does not. |
| **Missing in Plexus** | The source has an active allocation; no inventory host has the address. |
| **Hostname mismatch** | Both have the address with different names. Case is ignored. |
| **Status mismatch** | An inventory host uses the address; the source marks it `deprecated`, `reserved`, `inactive` or `disabled`. |

**Recent Runs** shows the last 5 runs. **Open Drifts** lists each drift with
the Plexus and IPAM host names. For each drift:

- **Push to IPAM** writes the Plexus host name for the address to the
  source. It shows only when the source has push on, and not for **Missing
  in Plexus**. It asks first.
- **Accept IPAM** closes the drift. It does not change inventory hosts.
- **Ignore** closes the drift with no action.

## DHCP servers

The **DHCP Servers** panel pulls scope use and active leases.

1. Select **+ Add DHCP Server**.
2. Fill in **Provider**, **Name**, **Base URL**, **Auth Type** (**None**,
   **API Token** or **Basic Auth**), **Token / Password**, **Username**,
   **Notes**, **Enabled** and **Verify TLS**.
3. Select **Add Server**, then **Sync** on its row.

The table shows each server's **Provider**, **Name**, **Status**,
**Scopes**, **Leases** and **Last Sync**. Enabled servers also sync every 30
minutes.

**Scope Utilization Alerts** lists scopes that are 80% used or more. A scope
at 90% or more is marked **EXHAUSTED** (red); 80% to 90% is marked **near**
(yellow).

**Lease Correlation** counts leases whose address matches an inventory host
(known) and leases that match none (unknown). It lists the first 25 unknown
leases with address, MAC, host name and scope. Unknown leases can be devices
that discovery has not found.

## Rules worth knowing

- **A sync replaces the source's data.** Each sync deletes that source's
  prefixes and allocations and stores the new set.
- **Deleting a source** asks first and removes its prefixes, allocations and
  reconciliation runs. The built-in source cannot be deleted.
- **Deleting a DHCP server** removes its cached scopes and leases.
- **The sync schedule is kept in memory.** After a restart it is on, every
  30 minutes, again.
- **Sync Scope** is stored with a source. The current adapters do not use it
  to filter what they pull.
- **Tags and custom fields survive syncs.** They belong to the subnet and
  VRF, not to the source.
- **Removing a local allocation** is possible through the API only.
- **Address history and utilization snapshots** are in the API only (see
  below). Snapshots are taken when the snapshot endpoint is called.

## Who can do what

| Action | Needs |
|---|---|
| See the page, subnets, drill-down, sources, drifts and DHCP data | The `ipam` feature |
| Define subnets, add reservations and allocations | Admin |
| Add, edit, sync, reconcile or delete sources; change the schedule | Admin |
| Resolve drifts, push to IPAM | Admin |
| Add, edit, sync or delete DHCP servers | Admin |
| Change a subnet's tags and custom fields | Admin |

Changes are written to the audit log under the `ipam` and `dhcp`
categories.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data. See
[API reference](api-reference.md) for the full list.

```
GET    /api/ipam/overview[?group_id=&include_cloud=&include_external=&include_topology=]
GET    /api/ipam/subnets/{subnet}[?vrf=]
GET    /api/ipam/address/{ip}[?vrf=]
POST   /api/ipam/prefixes
POST   /api/ipam/subnets/{subnet}/reservations
DELETE /api/ipam/reservations/{reservation_id}
POST   /api/ipam/subnets/{subnet}/allocations
DELETE /api/ipam/allocations/{allocation_id}
GET    /api/ipam/sources
POST   /api/ipam/sources
POST   /api/ipam/sources/{source_id}/sync
POST   /api/ipam/sources/{source_id}/reconcile
GET    /api/ipam/reconciliation/diffs
POST   /api/ipam/reconciliation/diffs/{diff_id}/resolve
POST   /api/ipam/allocate
GET    /api/ipam/history/{address}
GET    /api/dhcp/servers
GET    /api/dhcp/exhaustion
GET    /api/dhcp/correlation
```

Define a subnet:

```json
POST /api/ipam/prefixes
{ "subnet": "198.51.100.0/24", "description": "Lab servers", "vrf": "" }
```

Reserve a range:

```json
POST /api/ipam/subnets/198.51.100.0/24/reservations
{ "start_ip": "198.51.100.1", "end_ip": "198.51.100.9", "reason": "Gateways" }
```

Take the next free address:

```json
POST /api/ipam/allocate
{ "subnet": "198.51.100.0/24", "hostname": "app-01", "ttl_seconds": 900 }
```

This holds the first free address as a pending allocation for
`ttl_seconds` (60 to 86,400, default 900). Confirm it with
`POST /api/ipam/allocate/{id}/commit` or give it back with
`POST /api/ipam/allocate/{id}/release`. A full subnet gives `409`.

Resolve a drift:

```json
POST /api/ipam/reconciliation/diffs/12/resolve
{ "resolution": "ignored" }
```

`resolution` is `accept_plexus`, `accept_ipam`, `manual_override` or
`ignored`. `accept_plexus` needs push on for the source.
