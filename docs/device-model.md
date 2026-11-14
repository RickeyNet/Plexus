# Device Model

Every host in the inventory can point at four managed records and a site:

| Value | What it says | Example |
|---|---|---|
| **Device type** | The hardware model, under its manufacturer | Cisco C9300-48P |
| **Role** | What the device does | Switch |
| **Lifecycle status** | Where the device is in its life | Active |
| **Site** | Where it is, with an optional rack or room | HQ, "Row 4, rack 12" |

An admin keeps the lists of manufacturers, device types, roles and statuses.
Because hosts point at those records instead of holding their own text, the
Inventory list can filter by them, a rename shows on every host at once, and
exports are consistent.

Two existing host values keep their meaning:

- **Platform** is the driver Plexus uses to talk to the device (for example
  `cisco_ios`). The Inventory page used to label it "Type"; the API still
  calls it `device_type`.
- `status` on a host in the API is whether polling can reach the device. It
  is not the lifecycle status.

## Setting it up

An admin opens **Settings > Device Model**. There are four tables.

- **Manufacturers:** a name and an optional description.
- **Device types:** a manufacturer, a model name, and optionally a part
  number, a height in rack units and a description. A model name is unique
  within its manufacturer.
- **Roles:** a name, a color and an optional description. Plexus starts with
  Router, Switch, Firewall, Wireless, WLC, Phone, Server and Unknown.
- **Statuses:** a name, a color and an optional description. Plexus starts
  with Active, Planned, Staged, Maintenance, Decommissioning and Retired.
  One status is the default; new hosts get it.

Sites are the same sites the Geolocation page manages.

## How discovery fills it in

When discovery or a vendor sync reports a model for a host, Plexus looks for
that manufacturer and device type, creates them if they are missing, and
links the host. If discovery can tell what kind of device it is and the host
has no role yet, it sets the role.

What a person sets is kept:

- Choosing a device type or a role on a host locks that value. Discovery no
  longer changes it.
- Setting the value back to "None" removes the lock, and the next discovery
  may fill it in again.

Discovery never changes the lifecycle status or the site. Placing a host on
a floor map sets its site if it has none.

The model and category text that discovery reports are still stored on the
host as before.

## Using it

- **One host:** open the host dialog in Inventory. The "Device" section has
  the device type, role, lifecycle status, site and rack or room.
- **Several hosts:** select hosts and choose **Edit…**. Values you leave on
  "leave unchanged" are not touched.
- **Filtering:** the **Filter** button on the Inventory page narrows the
  list by manufacturer, device type, role, lifecycle status and site, next
  to tags and custom fields. Several choices in one filter are alternatives;
  different filters must all match. "None" finds hosts with no value.

## Rules worth knowing

- **Deleting a record that hosts use** asks first and names how many hosts
  are affected. Those hosts are left without that value; the hosts
  themselves are not deleted.
- **Deleting a manufacturer** also deletes its device types.
- **The default status** cannot be deleted. Make another status the default
  first.
- **Lifecycle status does not change monitoring.** A Retired host is still
  polled until it is removed from the inventory.

## Who can do what

| Action | Needs |
|---|---|
| See manufacturers, device types, roles and statuses | Any signed-in user |
| Create, change or delete them | Admin |
| Set the values on a host, one or many | The Inventory feature |

Every change is written to the audit log under the `device_model` category.

## CSV export

The inventory CSV export has the columns `Manufacturer`, `Device Type`,
`Role`, `Lifecycle Status`, `Site` and `Location Detail`.

The column that holds the driver was called `Device Type` before and is now
called `Platform`, so that `Device Type` means the hardware model. A script
that reads the export by column name needs that one change.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data.

### Catalogues

```
GET    /api/dcim/manufacturers
GET    /api/dcim/device-types[?manufacturer_id=1]
GET    /api/dcim/roles
GET    /api/dcim/statuses
POST   /api/dcim/<collection>
PUT    /api/dcim/<collection>/{id}
DELETE /api/dcim/<collection>/{id}[?confirm=true]
```

```json
POST /api/dcim/device-types
{
  "manufacturer_id": 1,
  "model": "C9300-48P",
  "part_number": "C9300-48P-A",
  "u_height": 1,
  "description": "48 port PoE+ access switch"
}
```

```json
POST /api/dcim/roles
{ "name": "Load balancer", "color": "orange", "description": "" }
```

Colors: `gray`, `red`, `orange`, `yellow`, `green`, `teal`, `blue`,
`purple`.

A name that already exists gives `409`. Deleting a record that hosts still
use gives `409` with the number of hosts; repeat the request with
`?confirm=true` to go ahead:

```json
{ "detail": { "message": "3 hosts use role Switch; they lose it. Send confirm=true to go ahead.", "affected": 3 } }
```

A confirmed delete answers `{"ok": true, "affected": <hosts changed>}` and
also removes the lock on those hosts, so discovery can fill the value in
again. Deleting the default status, or taking the default flag off it, gives
`409` whatever `confirm` says.

### Hosts

Creating or updating a host accepts `device_type_id`, `role_id`,
`lifecycle_status_id`, `site_id` and `location_detail`. A key that is left
out is not changed; `null` clears the value.

Host rows from `GET /api/inventory?include_hosts=true`,
`GET /api/inventory/{group_id}` and `GET /api/inventory/{group_id}/hosts`
carry the stored ids and a display object for each:

```json
{
  "hostname": "access-sw-01",
  "ip_address": "192.0.2.10",
  "device_type": "cisco_xe",
  "status": "up",
  "device_type_id": 7,
  "role_id": 2,
  "lifecycle_status_id": 1,
  "site_id": 3,
  "location_detail": "Row 4, rack 12",
  "hardware": { "id": 7, "model": "C9300-48P", "manufacturer_id": 1, "manufacturer": "Cisco" },
  "role": { "id": 2, "name": "Switch", "color": "teal" },
  "lifecycle_status": { "id": 1, "name": "Active", "color": "green" },
  "site": { "id": 3, "name": "HQ" }
}
```

Change many hosts at once:

```json
POST /api/hosts/bulk-edit
{ "host_ids": [42, 43, 44], "set": { "lifecycle_status_id": 4, "site_id": null } }
```

Only the keys in `set` are applied. At most 5,000 hosts per request. Host
ids that do not exist are skipped; the answer is
`{"ok": true, "updated": <hosts changed>}`.

### Filters

The inventory lists accept `manufacturer_id=`, `device_type_id=`,
`role_id=`, `lifecycle_status_id=` and `site_id=`. Repeat a filter to give
alternatives; `none` matches hosts with no value. They combine with `tag=`
and `cf.<key>=`.

```
GET /api/inventory?include_hosts=true&role_id=2&role_id=3&site_id=none
```

A value that is neither a number nor `none` gives `400`.
