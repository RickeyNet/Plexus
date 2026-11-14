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

## VLANs

A VLAN record has a VLAN id (1 to 4094), an optional name and description,
a site or no site, and an origin. The VLAN id never changes; the name, the
site and the description can be edited. One site has one record per VLAN
id, and so do VLANs of no site.

Deleting a site deletes its VLAN records.

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
| See VRF and VLAN records | The IPAM feature |
| Create, change or delete them, or rebuild interface addresses | Admin |
| See a device's interface addresses | The Reports feature, like its interface inventory |

Every change is written to the audit log under the `network_objects`
category.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data.

### VRFs

```
GET    /api/ipam/vrfs
POST   /api/ipam/vrfs            {name, rd?, description?}
GET    /api/ipam/vrfs/{id}
PUT    /api/ipam/vrfs/{id}       {rd?, description?}
DELETE /api/ipam/vrfs/{id}
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
  "address_count": 9
}
```

The list answers `{"vrfs": [...]}` by name. A detail adds `devices`
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
GET    /api/ipam/vlans[?site_id=<id>|none][&vid=<n>]
POST   /api/ipam/vlans           {vid, name?, site_id?, description?}
GET    /api/ipam/vlans/{id}
PUT    /api/ipam/vlans/{id}      {name?, site_id?, description?}
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
  "name_mismatch": false
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
