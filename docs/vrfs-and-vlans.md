# VRFs and VLANs

VRFs and VLANs are records in Plexus, not only text on a host or a subnet.
Each has its own entry on the IPAM page with the devices, interfaces and
subnets that use it. Plexus also keeps the addresses every device interface
carries, read from the device's running configuration, with the interface's
network and VRF.

| Record | Known by | Example |
|---|---|---|
| **VRF** | Its name | `BLUE`, route distinguisher `65000:10` |
| **VLAN** | Its site and VLAN id | VLAN 10 "users" at site HQ |
| **Interface address** | Device, interface and address | edge-r1, `Vlan10`, `192.0.2.2/24` in `BLUE` |

## VRFs

A VRF record has a name (1 to 64 characters), an optional route
distinguisher and description, and an origin: **manual** (an admin made
it) or **discovered** (Plexus made it from collected data).

- The name never changes after the record is made. The route distinguisher
  and description can be edited.
- The empty name is the global VRF. It has no record.
- Two VRFs cannot have the same name ignoring case when an admin adds one.
- Hosts, IPAM subnets and allocations still hold the VRF as text, and IPAM
  still compares that text exactly. A record belongs to that text when the
  names are the same.

A VRF record lists:

| Count | What it counts |
|---|---|
| Hosts | Hosts whose inventory VRF is the name |
| Devices | Devices with an interface or a static route in the VRF |
| Prefixes | IPAM subnets in the VRF, plus the interface networks in it that no IPAM subnet names |
| Addresses | Interface addresses in the VRF |

A VRF that anything still uses cannot be deleted. The answer names what
uses it.

A VRF lives in one IPAM namespace (**Global** unless an admin moves it; see
[IP address management](ipam.md#namespaces)). Its prefixes go to that
namespace too. The name stays unique across namespaces: hosts and IPAM still
name a VRF by its text.

### Route targets

A route target is a BGP extended community: `ASN:number` with a 2-byte ASN
and a number up to 4294967295 (`65000:100`), a 4-byte ASN with a number up
to 65535 (`4200000000:1`), or an IPv4 address with a number up to 65535
(`192.0.2.1:100`). Leading zeros are dropped; each value exists once.

The **Route targets** tab of the IPAM page lists them with how many VRFs
import and export each. A VRF's detail shows the route targets it imports
and exports; an admin picks them with **Edit route targets**. Deleting a
route target takes it off every VRF.

## VLANs

A VLAN record has a VLAN id (1 to 4094), an optional name and description,
a site or no site, and an origin. The VLAN id never changes; the name, the
site and the description can be edited. One site has one record per VLAN
id, and so do VLANs of no site.

Deleting a site deletes its VLAN records.

### VLAN groups

A VLAN group is a named pool of VLAN ids (the lowest and the highest, 1 to
4094 by default), optionally scoped to one site or one region. A VLAN may be
in one group:

- its VLAN id must be inside the group's range, and appears once in the
  group (two sites' VLAN 10 cannot both be in one group);
- in a group scoped to a site, a VLAN of another site cannot join; in a
  group scoped to a region, a VLAN of a site outside the region (or its
  sub-regions) cannot join. A VLAN of no site fits any group.

The **VLAN groups** tab lists the groups; selecting one shows its VLANs and
the **next free VLAN id**, the lowest id of the range no VLAN of the group
has. A group's range cannot shrink below its VLANs, and its scope cannot
change to one its VLANs are outside. Deleting a group keeps its VLANs, in
no group.

### Which record a device's VLAN belongs to

A device that has VLAN `v` belongs to the record of its own site and `v`
when one exists, otherwise to the record of no site and `v`. Nothing is
stored on the device for this: it is worked out each time it is read, so
adding a site record moves that site's devices to it at once.

A VLAN record lists:

| Count | What it counts |
|---|---|
| Devices | Devices whose VLAN belongs to the record |
| Ports | Their ports in the VLAN: the access VLAN, or listed on a trunk |
| Prefixes | The networks of their VLAN interfaces for that VLAN id (`Vlan10`, `vlan.10`, `irb.10`) |

A record shows a name mismatch when a device names the VLAN differently
(ignoring case; a device that gives no name never differs).

VRFs and VLANs can each belong to a tenant (the **Tenant** field of their
dialogs and the **Tenant** column of the lists); see
[locations-and-tenancy.md](locations-and-tenancy.md).

## How the records are filled

Plexus creates missing records from what it already collects. It never
changes or deletes a record it did not make just now.

- **VRFs:** when a host or an IPAM subnet is saved with a VRF (origin
  manual), when an external IPAM source syncs (discovered), and when a
  device's configuration names a VRF (discovered).
- **VLANs:** when the SNMP inventory collection or the SSH inventory
  collection stores a device's VLANs, a VLAN that belongs to no record gets
  one at the device's site (no site when the device has none), named as the
  device names it.

Upgrading creates a record for every VRF name the hosts and IPAM tables
already hold and every VLAN the devices already list.

## Interface addresses

Every time a device's running configuration is stored (a backup, the
inventory collection, an upgrade prestage), Plexus reads it with the same
parsers the path trace uses and replaces that device's interface addresses.
For each interface it keeps:

- each address with its prefix length and network; the first address of
  each IP version is the **primary**, the others are **secondary**;
- the HSRP, VRRP and GLBP addresses (**virtual**), with the network of the
  interface address that holds them;
- the interface's VRF, and its VLAN id when it is a VLAN interface.

It also keeps the VRFs the device has an interface or a static route in.

Limits:

- Only the stored running configuration is read. Platforms whose
  configuration Plexus does not parse (PAN-OS) have no interface
  addresses, and their stored ones are left as they are.
- Addresses from SNMP or from the integrations (Meraki, Cato, cloud) are
  not included.
- Interface addresses cannot be edited by hand.

After the upgrade, Plexus reads every device's newest stored configuration
once, in the background, a couple of minutes after it starts. An admin can
run the same read again with `POST /api/ipam/interface-addresses/rebuild`.

## Who can do what

| Action | Needs |
|---|---|
| See VRF, VLAN, route target and VLAN group records | The IPAM feature |
| Create, change or delete them, set a VRF's route targets, or rebuild interface addresses | Admin |
| See a device's interface addresses | The Reports feature, like its interface inventory |

Every change is written to the audit log under the `network_objects`
category; route targets, a VRF's route targets and VLAN groups under
`ipam_model`.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data.

### VRFs

```
GET    /api/ipam/vrfs
POST   /api/ipam/vrfs            {name, rd?, description?, namespace_id?}
GET    /api/ipam/vrfs/{id}
PUT    /api/ipam/vrfs/{id}       {rd?, description?, namespace_id?}
DELETE /api/ipam/vrfs/{id}
GET    /api/ipam/vrfs/{id}/route-targets
PUT    /api/ipam/vrfs/{id}/route-targets   {import_ids: [...], export_ids: [...]}
```

```json
{
  "id": 3,
  "name": "BLUE",
  "rd": "65000:10",
  "description": "Tenant network",
  "origin": "manual",
  "created_at": "2026-11-13 09:30:00",
  "host_count": 4,
  "device_count": 2,
  "prefix_count": 5,
  "address_count": 9,
  "namespace_id": 1,
  "namespace_name": "Global"
}
```

The list answers `{"vrfs": [...]}` by name. A detail adds `route_targets`
(`{"import": [...], "export": [...]}`, each `id`, `name`, `description`),
`devices`
(`host_id`, `hostname`, `interface_count`), `interfaces` (at most 2,000
interface addresses, with `truncated` when there are more) and `prefixes`
(`subnet`, and `source`: the IPAM source's provider, or `interface`).

A name taken ignoring case gives `409`. A `name` key on `PUT` gives `422`.
Deleting a VRF that is in use gives `409`:

```json
{ "detail": { "message": "VRF BLUE is in use (4 hosts, 9 interface addresses, 2 devices); it cannot be deleted.", "affected": 15 } }
```

### VLANs

```
GET    /api/ipam/vlans[?site_id=<id>|none][&vid=<n>][&vlan_group_id=<id>]
POST   /api/ipam/vlans           {vid, name?, site_id?, description?, vlan_group_id?}
GET    /api/ipam/vlans/{id}
PUT    /api/ipam/vlans/{id}      {name?, site_id?, description?, vlan_group_id?}
DELETE /api/ipam/vlans/{id}
```

```json
{
  "id": 7,
  "vid": 10,
  "name": "users",
  "site_id": 2,
  "site": { "id": 2, "name": "HQ" },
  "description": "",
  "origin": "discovered",
  "created_at": "2026-11-13 09:30:00",
  "device_count": 3,
  "interface_count": 41,
  "prefix_count": 1,
  "name_mismatch": false,
  "vlan_group_id": 4,
  "vlan_group": { "id": 4, "name": "Campus" }
}
```

The list answers `{"vlans": [...]}` by site name (no site first) then VLAN
id. A detail adds `devices` (`host_id`, `hostname`, `name` and `state` as
the device reports them, `name_matches`), `interfaces` (`host_id`,
`hostname`, `interface`, `mode`: `access` or `trunk`; at most 2,000, with
`truncated`) and `prefixes` (`network`, `vrf_name`, `host_id`, `hostname`,
`interface`, `address`).

An unknown `site_id` gives `400` naming the field:

```json
{ "detail": { "message": "Unknown id: site_id.", "fields": { "site_id": "No record with id 99." } } }
```

A VLAN id the site already has gives `409`, on create and on a move to
another site. A `vid` key on `PUT` gives `422`. On `PUT`, leaving
`site_id` out keeps the site and `null` moves the VLAN to no site. Deleting
a VLAN that devices still carry is allowed; it is made again at their next
collection.

An unknown `vlan_group_id` gives `400`; a VLAN id outside the group's range,
or a site outside its scope, `422`; a VLAN id the group has already `409`.
On `PUT`, leaving `vlan_group_id` out keeps the group and `null` takes the
VLAN out of it.

### Route targets and VLAN groups

```
GET    /api/ipam/route-targets[?tenant_id=&vrf_id=&q=]
POST   /api/ipam/route-targets           {name, tenant_id?, description?}
GET    /api/ipam/route-targets/{id}
PUT    /api/ipam/route-targets/{id}      {name?, tenant_id?, description?}
DELETE /api/ipam/route-targets/{id}
GET    /api/ipam/vlan-groups[?site_id=&region_id=&q=]
POST   /api/ipam/vlan-groups             {name, min_vid?, max_vid?, site_id?, region_id?, description?}
GET    /api/ipam/vlan-groups/{id}
PUT    /api/ipam/vlan-groups/{id}        {name?, min_vid?, max_vid?, site_id?, region_id?, description?}
DELETE /api/ipam/vlan-groups/{id}
GET    /api/ipam/vlan-groups/{id}/next-vid
```

```json
{ "id": 2, "name": "65000:100", "tenant_id": null, "tenant_name": null, "description": "Hub",
  "import_vrf_count": 3, "export_vrf_count": 1 }
```

A route target detail adds `vrfs` (`vrf_id`, `name`, `direction`). A VLAN
group answers `min_vid`, `max_vid`, `site_id`, `site_name`, `region_id`,
`region_name` and `vlan_count`; its detail adds `vlans` (`id`, `vid`,
`name`, `site_id`), `available` and `next_vid`. `next-vid` answers
`{"vlan_group_id": 4, "vid": 103}` (`vid` null when the group is full). A
route target that does not parse gives `422` naming `name`; a value taken
`409`. A group scoped to both a site and a region, a range whose lowest id
is above its highest, or a change that leaves a VLAN outside the group
gives `422`.

For an account limited to selected inventory groups (object scope), a
route target is read when it is of one of the account's tenants or of no
tenant; a VLAN group when its site, or a site of its region (and the
regions under it), is one of the account's, or when it has no scope (a
region with no site counts as no scope). Others give `404`, on the next
free VLAN id too. A VRF's detail and `/vrfs/{id}/route-targets` leave out
the route targets the account cannot read; a route target's detail lists
only the VRFs it can read; a VLAN group's detail only its readable VLANs,
while `available` and `next_vid` still count every VLAN of the group (an
id another tenant holds is taken). Scope rules on the models
`route_target` (tenant) and `vlan_group` (site) widen what an access group
reads.

### Interface addresses

```
GET  /api/hosts/{host_id}/interface-addresses
POST /api/ipam/interface-addresses/rebuild
```

An interface address:

```json
{
  "host_id": 12,
  "hostname": "edge-r1",
  "interface": "Vlan10",
  "address": "192.0.2.2",
  "prefix_length": 24,
  "network": "192.0.2.0/24",
  "vrf_name": "BLUE",
  "role": "primary",
  "protocol": "",
  "svi_vid": 10,
  "collected_at": "2026-11-13 09:30:00"
}
```

`role` is `primary`, `secondary` or `virtual`; `protocol` is `HSRP`,
`VRRP` or `GLBP` for a virtual address; `svi_vid` is 0 when the interface
is not a VLAN interface.

A host's answer is `{"host_id", "addresses", "vrfs"}`. Each address also
has `vrf_id` and `vlan_id`, the records it belongs to (`null` when there
is none); each VRF has `name`, `vrf_id` and `interface_count`.

The rebuild reads the newest stored configuration of every host again and
answers `{"ok": true, "hosts": <hosts read>, "addresses": <addresses stored>}`.

### In the IPAM answers

- `GET /api/ipam/address/{ip}` has `interfaces`: the interfaces that carry
  the address (only those of the VRF when `vrf` is given).
- `GET /api/ipam/subnets/{subnet}` has `interfaces`: the interface
  addresses inside the subnet, at most 1,024. Without `vrf` they come from
  every VRF (each row has its `vrf_name`); with `vrf`, only that VRF.
