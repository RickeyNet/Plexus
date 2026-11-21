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

The search box above the subnet list narrows it as you type:

- An address, such as `192.0.2.10` or `2001:db8::10`, finds every subnet
  that contains it.
- A range, such as `192.0.2.0/23`, finds the subnets inside it and the ones
  around it.
- Other text is split into words, and each word must appear in the subnet,
  its VRF, VLANs (`vlan 10`), inventory groups, sources, previewed host,
  cloud resource and site names, or tags. A partial address such as `198.51.`
  matches as text.

Host names are searched only within each subnet's preview, so a host beyond
the preview is not found. The device page links its subnet here, already
searched (`/ipam?q=<subnet>`).

Select a **Subnet**, **Capacity** or **Groups** header to sort the list.
Subnets sort by address (IPv4 first); **Capacity** sorts by percent used,
fullest first. The list shows 200 rows at a time; **Show more** adds the
next 200.

## Define a subnet

1. Select **+ Define Subnet**.
2. Enter the **CIDR**, for example `198.51.100.0/24`. Optionally add a
   **Description** (255 characters at most) and a **VRF** (120 characters at
   most).
3. Select **Add Subnet**.

The subnet is stored in the built-in source named "Plexus (Built-in)" and
shows with the `local` badge. A VRF name that has no VRF record yet gets one.

**Namespace** (optional) picks the namespace the subnet goes to. Left empty,
it is the VRF's namespace, or **Global** for no VRF. The same subnet may be
defined once per namespace and VRF: defining it again in the same namespace
and VRF is refused, in another VRF or namespace it is a second subnet.

## Namespaces

A namespace groups VRFs and prefixes so the same address space can exist
more than once, for example a lab that reuses production ranges. Every VRF
and prefix that existed before namespaces is in **Global**, the default
namespace, which cannot be deleted; nothing about them changed.

- A VRF record is in one namespace, and its prefixes follow it: a subnet
  of a VRF must be in the VRF's namespace. Move the VRF (edit it on the
  **VRFs** tab) to move them together.
- A prefix is unique per namespace and VRF.
- A namespace that holds a VRF or a prefix cannot be deleted.

The **Namespaces** tab lists them with their VRF and prefix counts.

## Aggregates and RIRs

An aggregate is a top-level block of address space, such as the
`198.51.100.0/24` an organisation was given, with the RIR that allocated
it (a regional internet registry, or a private allocator such as
RFC 1918) and the date it was added. Aggregates do not overlap. A RIR with
aggregates cannot be deleted.

The **Aggregates** tab lists each aggregate with how many prefixes are
inside it and its **utilization**: the share of its addresses the IPAM
prefixes (of every namespace and source) cover, overlapping prefixes counted
once. A subnet's drill-down names the aggregate that holds it.

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
- The aggregate that holds the subnet and how much of it is used, under
  the address counts.

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
| **Capacity** | Available, allocated and reserved addresses, and the percent used with a bar: amber from 75%, red from 90%. |
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

An OPNsense firewall collected as a Map source with **Config backup** on
adds a source of provider `opnsense` named `<source name> (OPNsense)`: its
allocations are the firewall's DNS names and DHCP reservations (Unbound host
overrides, Dnsmasq hosts, ISC static mappings, Kea reservations), a DHCP
reservation with status `reserved`, each under the firewall subnet that
holds it, replaced with every collection of that source. It shows "Updated
by its Map source" instead of **Sync Now**; it is never synced, validated,
reconciled or pushed to, the scheduled sync skips it, and next-IP allocation
cannot commit into it. Its menu has **Disable** / **Enable** (a disabled
source keeps what it holds) and **Delete**. See the OPNsense guide's
"DNS names and DHCP reservations" section.

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

An OPNsense firewall added as a Map source appears here on its own, as a
server of provider `opnsense` named `<source name> (OPNsense)`: every
collection of the source replaces its leases (ISC, Kea and Dnsmasq) and it
has no scopes. It has no **Sync** button and cannot be added by hand;
disable it to stop storing its leases. See
[OPNsense in the Topology Map](opnsense-topology.md#arp-ndp-and-dhcp-leases).

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
| See namespaces, RIRs and aggregates | The `ipam` feature |
| Add, change or delete namespaces, RIRs and aggregates; move a prefix to another namespace | Admin |

Changes are written to the audit log under the `ipam` and `dhcp`
categories; namespaces, RIRs and aggregates under `ipam_model`.

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
GET    /api/ipam/namespaces[?q=]
POST   /api/ipam/namespaces                 {name, description?}
GET    /api/ipam/namespaces/{id}
PUT    /api/ipam/namespaces/{id}            {name?, description?}
DELETE /api/ipam/namespaces/{id}
PUT    /api/ipam/prefixes/{id}/namespace    {namespace_id}
GET    /api/ipam/rirs[?is_private=&q=]
POST   /api/ipam/rirs                       {name, is_private?, description?}
GET    /api/ipam/rirs/{id}
PUT    /api/ipam/rirs/{id}                  {name?, is_private?, description?}
DELETE /api/ipam/rirs/{id}
GET    /api/ipam/aggregates[?rir_id=&tenant_id=&q=]
POST   /api/ipam/aggregates                 {prefix, rir_id, date_added?, tenant_id?, description?}
GET    /api/ipam/aggregates/{id}
GET    /api/ipam/aggregates/containing?subnet=<cidr>
PUT    /api/ipam/aggregates/{id}            {prefix?, rir_id?, date_added?, tenant_id?, description?}
DELETE /api/ipam/aggregates/{id}
```

Define a subnet (`namespace_id` optional: the VRF's namespace, else Global):

```json
POST /api/ipam/prefixes
{ "subnet": "198.51.100.0/24", "description": "Lab servers", "vrf": "", "namespace_id": 2 }
```

The same subnet, namespace and VRF again gives `409`; a `namespace_id`
other than the VRF record's `422`; an unknown one `400`. Moving a prefix to
a namespace that has it in the same VRF gives `409`, and moving a prefix of
a VRF record away from the VRF's namespace `422`.

Namespaces answer `{"namespaces": [...]}` with `vrf_count` and
`prefix_count`; a detail adds `vrfs` and `prefixes` (at most 2,000, with
`truncated`). Deleting Global, or a namespace in use, gives `409`.

An aggregate:

```json
{
  "id": 5, "prefix": "198.51.100.0/24", "rir_id": 1, "rir_name": "RFC 5737", "rir_is_private": true,
  "date_added": "2026-01-15", "tenant_id": null, "tenant_name": null, "description": "",
  "prefix_count": 2, "total_addresses": 256, "used_addresses": 192, "utilization_pct": 75.0
}
```

A detail adds `prefixes` (`id`, `subnet`, `vrf`, `namespace_id`, `source`).
`containing` answers `{"subnet": ..., "aggregate": {...} | null}` (the most
specific aggregate that holds the subnet), and the subnet drill-down
carries the same `aggregate`. A prefix with host bits set, a `date_added`
that is not `YYYY-MM-DD` or an aggregate that overlaps another gives `422`;
an unknown `rir_id` `400`; the prefix of another aggregate `409`.

For an account limited to selected inventory groups (object scope):

- Namespaces and RIRs are reference data: every IPAM reader sees all of
  them. A namespace's detail lists only the VRFs and prefixes the account
  may read.
- An aggregate is read when it is of one of the account's tenants (an
  access group scope rule on `aggregate`, or a tenant its groups' hosts
  have) or of no tenant; another gives `404`, and `containing` answers
  `null` for it. Its detail lists only the prefixes the account may read.
- Counts and an aggregate's usage (`prefix_count`, `used_addresses`,
  `utilization_pct`) are totals over every prefix, like the address space
  they describe.
- The `aggregate` of a subnet's drill-down is reference data: it is shown
  whoever owns the aggregate, like the RIR.

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
