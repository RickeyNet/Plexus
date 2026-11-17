# DCIM: racks, cables, patch panels and power

Plexus records the physical side of the network: the racks at each site and
which device sits in which units, the patch panels and the cables between
ports, the modules in device bays, and the power chain from a device's power
supply through a PDU to a feed and its panel. A cable trace follows a path
through any number of patch panels, and the rack power summary compares what
the devices draw with what the feeds can deliver.

Open **Assets > DCIM**. The page has five tabs: Racks, Cables, Patch panels,
Power and Modules. A device's page shows its rack and the cables on its ports
(section `#dcim`) with a trace link per cable.

## Access

DCIM has its own feature key, `dcim`, granted in access groups like any
other: `dcim` reads every DCIM record and trace, `dcim.write` adds, edits and
deletes them. Admins and the API token have both. DCIM is not enrolled in
object scope, so accounts limited to selected inventory groups do not see it
(see [object-level permissions](object-permissions.md)).

Placing a device in a rack is also part of the host edit
(`PUT /api/hosts/{id}`, which needs `inventory.write` and honours object
scope); the DCIM placement endpoint does the same check with `dcim.write`.

## Records

| Record | Belongs to | Unique name | Notes |
|---|---|---|---|
| Rack role | - | name, ignoring case | colour slot like device roles |
| Rack | site (required), floor (optional) | name per site, ignoring case | status `active`, `planned`, `reserved`, `available`, `deprecated`; 1 to 100 units (42 by default); `desc_units` numbers unit 1 at the top; width 19 or 23 inches; facility id, serial, asset tag, tenant |
| Rack reservation | rack | - | a set of units held for someone (`user`, description, tenant) |
| Rear port | device | name per device | connector type, `positions` (1 to 1024) |
| Front port | device | name per device | maps to one position of a rear port of the same device; one front port per position |
| Module | device | bay per device | module type, part number, serial, asset tag, status |
| Power panel | site, floor | name per site | |
| Power feed | panel | name per panel | rack (at the panel's site), status, `primary`/`redundant`, `ac`/`dc`, `single`/`three` phase, voltage, amperage, maximum utilisation % |
| Power port | device | name per device | maximum and allocated draw in watts (allocated cannot exceed maximum) |
| Power outlet | device (a PDU) | name per device | the power port of the same device that feeds it, feed leg A/B/C |
| Cable | two endpoints | - | status `connected`, `planned`, `decommissioning`; type (`cat6`, `smf`, `mmf-om4`, `dac-passive`, `power`, ...); label, colour (hex), length and unit, tenant |

A patch panel or a PDU is an ordinary inventory device (give it a role such
as "Patch panel" or "PDU") with rear and front ports or power ports and
outlets. Interfaces are not records: an interface cable end is the device and
the interface name, and the name pickers offer the names Plexus has collected
(interface inventory and polled interface statistics).

Plexus does not collect module or entity (ENTITY-MIB) inventory today, so
modules are entered by hand; there is no import from discovery.

## Placing devices in racks

A device has `rack_id`, `rack_position` (the lowest unit it occupies) and
`rack_face` (`front` or `rear`). Its height is its device type's height in
units; a device type of height 0 (unknown) counts as 1U. Every device is
treated as **full depth**: a device mounted on the front occupies the same
units on the rear too, and the rear elevation shows it as "mounted front".
Reservations hold their units on both faces.

A placement is refused (422) when:

- the device would reach above the top unit or below unit 1;
- any of its units is taken by another device or a reservation;
- the rack is at another site than the device. A device with no site takes
  the rack's site when it is placed.

A device can also be in a rack without a position (in the rack, not
mounted); the elevation lists it under "In the rack but not mounted". Moving
a device to another rack without a position unmounts it; `rack_id: null`
takes it out of the rack. The rack row is locked while a placement is
checked and written, so two placements cannot take the same units.

A rack edit is refused when it would strand what it holds: a height below a
mounted device or a reservation, or a new site while it holds devices or
feeds of the old site. A reservation is refused when one of its units is
taken.

### Elevation

`GET /api/dcim/racks/{id}/elevation` draws each face top first (unit 1 at
the top with `desc_units`): blocks of `device` (with `host_id`, `name`,
`face` and `mounted_here`), `reservation` and single `empty` units, plus the
used and free unit counts. On the Racks tab, choose **Place here** on an
empty unit, pick a device and place it.

## Cables

A cable joins two endpoints, each one of:

| Endpoint | Identified by |
|---|---|
| `interface` | `host_id` and `name` |
| `front_port`, `rear_port` | `id` |
| `power_port`, `power_outlet`, `power_feed` | `id` |
| `circuit_termination` | `id` of a circuit termination (see [circuits](circuits.md)) |

Rules (422 when broken):

- power endpoints join only power endpoints: a power port to a power outlet
  or a power feed; data endpoints only data endpoints, and never two circuit
  terminations;
- a `power` cable joins only power endpoints, and a cable between power
  endpoints has type `power` or none;
- both ends must exist, and a cable cannot join an endpoint to itself.

An endpoint carries at most one cable, whichever end of the cable it is on
(409 otherwise). A cable whose device end is deleted with its device is
deleted too. A port, outlet or feed with a cable cannot be deleted (409);
delete the cable first.

## Cable trace

`GET /api/dcim/trace?type=interface&host_id=7&name=Gi1/0/1` (or
`type=front_port&id=12`) follows the cable on the endpoint and keeps going:

- a front port passes through to its rear port; when the rear port has more
  than one position, the position is remembered;
- a rear port passes back through to the front port of the position it was
  entered on (a one-position rear port to its single front port);
- a power outlet passes up to the power port that feeds it (a trace that
  starts at an outlet starts with that hop).

The walk ends at an interface, a circuit termination, a power port or a
power feed (`status: complete`; a feed adds its `power_panel`), at a port
with no further cable (`dead_end`; `unconnected` when the start itself has
no cable), at a deleted record (`missing`), at a multi-position rear port
entered with no position (`ambiguous`), or when it returns to a state it was
in (`loop`, `is_loop: true`). `steps` lists the hops in order: `cable` steps
(near end, cable, far end) and `internal` steps (the pass-through, with the
position). The Cables tab draws the trace as a vertical path; solid lines are
cables, dashed lines pass-throughs.

A trace does not cross a circuit to its other termination.

## Power

A feed's usable power is volts x amps (x sqrt 3 for three-phase AC) x its
maximum utilisation; power factor is taken as 1, so watts and volt-amperes
are the same. `GET /api/dcim/racks/{id}/power` lists the rack's feeds with
their usable power and the draw that traces to each, and the totals:

- the draw of a power port is its allocated draw, else its maximum draw,
  else 0;
- the ports counted are the power ports of the devices in the rack, except
  PDU inlets (power ports that feed outlets): the devices behind the PDU
  carry that draw;
- each port is traced to the feed it ends at; draw that reaches no feed is
  `unfed_draw`;
- capacity counts the primary feeds that are not offline; a redundant feed
  backs up a primary one and adds nothing.

## API

Every path is under `/api/dcim`. The record kinds share one shape: `GET
/<kind>` (filters below, `q` searches the names), `POST /<kind>` (201), `GET
/<kind>/{id}`, `PUT /<kind>/{id}` (only the keys sent change; a device, rack
or panel parent never changes), `DELETE /<kind>/{id}` (409 while in use).

| Kind path | Filters |
|---|---|
| `rack-roles` | |
| `racks` | `site_id`, `floor_id`, `role_id`, `tenant_id`, `status` |
| `rack-reservations` | `rack_id`, `tenant_id`, `site_id` |
| `rear-ports`, `front-ports` | `host_id`, `type` (front ports also `rear_port_id`) |
| `modules` | `host_id`, `status` |
| `power-panels` | `site_id`, `floor_id` |
| `power-feeds` | `power_panel_id`, `rack_id`, `site_id`, `status` |
| `power-ports` | `host_id` |
| `power-outlets` | `host_id`, `power_port_id` |
| `cables` | `host_id` (either end), `type`, `status`, `tenant_id`, `endpoint_type`, `q` |

Other paths: `GET /choices` (every fixed choice set), `GET /trace`, `GET
/racks/{id}/elevation`, `GET /racks/{id}/power`, `GET /hosts/{id}` (a
device's placement, cables and record counts), `GET /hosts/{id}/interfaces`
(interface names for pickers), `PUT /hosts/{id}/placement` (`rack_id`,
`rack_position`, `rack_face`).

Errors: 404 unknown record, 409 a taken name, an endpoint that already has a
cable, or a delete of a record in use (racks with devices, roles with racks,
ports with cables or mapped front ports, panels with cabled feeds, sites with
racks or panels), 422 bad input or a broken rule (`{"message", "fields"}`).

## Change log and audit

Racks, reservations, front and rear ports, modules, power panels, feeds,
ports and outlets, and cables are recorded in the [change log](change-log.md)
(readable with the `dcim` feature) and can be sent to [webhooks](webhooks.md).
A device's placement is a change of the host. Every write is audited under
the `dcim` category.

Storage: migration `0102_add_dcim.py`; rules in `netcontrol/dcim.py`;
storage in `routes/db/dcim.py` and `routes/db/dcim_cables.py`; API in
`netcontrol/routes/dcim.py`.
