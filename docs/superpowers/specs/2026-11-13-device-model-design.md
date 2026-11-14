# Device Model for Hosts: Design

Date: 2026-11-13
Status: implemented

## Goal

Hosts point at managed records instead of loose strings: a hardware device
type with its manufacturer, a role, a lifecycle status and a site. An admin
curates the four catalogues; discovery fills them in; the Inventory list
filters, bulk-edits and exports by them. This is the Plexus counterpart of
Nautobot's manufacturer, device type, role, status and location on a device.

## Decisions made

| Topic | Decision |
|---|---|
| Existing `hosts.device_type` | Unchanged. It is the SSH driver key used by playbooks, drivers and jobs. The UI labels it "Platform". |
| Existing `hosts.status` | Unchanged. It is polled reachability. |
| Existing `hosts.model`, `hosts.device_category` | Unchanged raw discovered text, still written by discovery. |
| Location | Reuse `geo_sites`. A host gets `site_id` plus a free-text `location_detail` (rack, room). No location tree. |
| Discovery | Finds or creates manufacturer and device type and links the host; sets the role from the guessed category only when the host has none. A value a person set is never overwritten. |
| Naming | Because `device_type` already means the driver, the nested object on a host row is called `hardware`. The catalogue itself is "device types". |
| Lifecycle status and monitoring | No effect in v1. A Retired host is still polled. |

## Out of scope

- Nested locations, racks with elevation, platform as a record.
- Interface or module templates per device type; importing a community
  device type library.
- These fields in the MCP endpoint, the Ansible inventory and the CSV import.
- Lifecycle status changing polling or alerting.

## Data model

Migration `0085_add_device_model.py`. Like 0083 and 0084 it is the only
definition of the new tables and columns (not repeated in `SCHEMA`).

`manufacturers`: `id`, `name` (1 to 100 chars, trimmed, unique index on
`lower(name)`), `description`, `created_at`.

`device_types`: `id`, `manufacturer_id` (references `manufacturers`,
cascade), `model` (1 to 100 chars, trimmed), `part_number`, `u_height`
(integer, 0 to 100, default 0), `description`, `created_at`. Unique index on
`(manufacturer_id, lower(model))`.

`device_roles`: `id`, `name` (1 to 50 chars, unique on `lower(name)`),
`color` (the tag palette: gray, red, orange, yellow, green, teal, blue,
purple), `description`, `created_at`.

`host_statuses`: `id`, `name` (as roles), `color`, `description`,
`is_default` (0 or 1; at most one row is 1), `created_at`.

New `hosts` columns, all added with `ADD COLUMN IF NOT EXISTS`:

| Column | Notes |
|---|---|
| `device_type_id` | references `device_types(id)` ON DELETE SET NULL |
| `role_id` | references `device_roles(id)` ON DELETE SET NULL |
| `lifecycle_status_id` | references `host_statuses(id)` ON DELETE SET NULL |
| `site_id` | references `geo_sites(id)` ON DELETE SET NULL |
| `location_detail` | TEXT NOT NULL DEFAULT '', at most 200 chars |
| `hardware_locked` | INTEGER NOT NULL DEFAULT 0 |
| `role_locked` | INTEGER NOT NULL DEFAULT 0 |

Indexes on each of the four id columns.

Seeds (in the migration):

- Roles: Router (blue), Switch (teal), Firewall (red), Wireless (purple),
  WLC (purple), Phone (gray), Server (orange), Unknown (gray). These match
  the categories `_infer_device_category` in `netcontrol/routes/snmp.py`
  returns, compared ignoring case.
- Statuses: Active (green, default), Planned (blue), Staged (teal),
  Maintenance (yellow), Decommissioning (orange), Retired (gray).

Backfill (in the migration, set-based SQL, not a row loop):

- Each host with a non-empty `model` gets a manufacturer and device type.
  The manufacturer is derived from the driver key prefix by the same mapping
  the runtime uses (below); hosts with no mapping go under "Unknown".
- `role_id` from `device_category` where it matches a seeded role name.
- `lifecycle_status_id` = Active for every host.
- `site_id` from the host's floor placement (`geo_placements` to
  `geo_floors.site_id`); a host on floors of several sites takes the lowest
  site id.

## Rules

- **Manufacturer from a driver key or vendor string**: one pure function,
  `manufacturer_name(vendor: str, device_type: str) -> str`, in
  `netcontrol/device_model.py`. It maps known vendor words and driver key
  prefixes to a display name (`cisco*` to Cisco, `juniper*` to Juniper,
  `arista*` to Arista, `fortinet*` to Fortinet, `paloalto*` to Palo Alto
  Networks, `meraki*` to Cisco Meraki, and the other driver packages under
  `netcontrol/drivers/`), else "Unknown". The migration carries its own copy
  of the prefix table, as migration 0013 does for categories, since
  migrations must not import runtime code that can change later.
- **Locks**: setting `device_type_id` through the API sets
  `hardware_locked = 1`; setting `role_id` sets `role_locked = 1`. Sending
  `null` clears the value and the lock, so discovery may fill it again.
- **Discovery link**: `link_host_hardware(host_id, vendor, model, category)`
  in `routes/db/device_model.py`. With a non-empty model and
  `hardware_locked = 0` it finds or creates the manufacturer and device type
  (matching ignoring case, safe when two discoveries race: insert with
  `ON CONFLICT DO NOTHING`, then select) and sets `device_type_id`. With a
  category that matches a role name and `role_id IS NULL` it sets `role_id`.
  It never sets a lock. It is called wherever the code writes
  `hosts.model` or `hosts.device_category` today (`update_host_device_info`
  and any other writer found by grep, including discovery inserts and the
  vendor importers).
- **New hosts** get the default lifecycle status when none is given.
- **Default status**: exactly one status is the default. Setting
  `is_default` on one clears it on the others in the same transaction. The
  default status cannot be deleted and cannot be un-defaulted directly; make
  another one the default instead.
- **Deleting a catalogue record in use**: answered with 409 and
  `detail = {"message", "affected"}` (`affected` = number of hosts) unless
  `?confirm=true`, the same contract as removing an object type from a
  custom field. With confirmation the hosts' references become null.
  Deleting a manufacturer counts the hosts on all its device types and
  deletes those device types.
- **Floor placement** sets the host's `site_id` to the floor's site when the
  host has none.
- Validation errors on catalogue bodies are 422 (pydantic), a duplicate name
  is 409 with a plain message, an unknown id on a host write is 400 with
  `detail = {"message", "fields": {"<field>": "<message>"}}`.

## Wire contract

Catalogue objects:

```
Manufacturer   {id, name, description, device_type_count, host_count}
DeviceType     {id, manufacturer_id, manufacturer, model, part_number,
                u_height, description, host_count}
DeviceRole     {id, name, color, description, host_count}
HostStatus     {id, name, color, description, is_default, host_count}
```

Routes in `netcontrol/routes/device_model.py`:

| Route | Access |
|---|---|
| `GET /api/dcim/manufacturers`, `/device-types[?manufacturer_id=]`, `/roles`, `/statuses` | any signed-in user |
| `POST` on each collection, `PUT` and `DELETE /{id}[?confirm=true]` | admin |
| `POST /api/hosts/bulk-edit` | `inventory` feature |

`POST /api/hosts/bulk-edit` body: `{"host_ids": [...], "set": {...}}` where
`set` may hold any of `device_type_id`, `role_id`, `lifecycle_status_id`,
`site_id` (an id or `null`) and `location_detail`. Only the keys present are
applied. At most 5,000 hosts; unknown host ids are skipped. Answer:
`{"ok": true, "updated": <hosts changed>}`.

Changes to existing endpoints:

- Host create and update bodies (`HostCreate` and the update model in
  `netcontrol/routes/inventory.py`) accept the optional keys
  `device_type_id`, `role_id`, `lifecycle_status_id`, `site_id`,
  `location_detail`. A key that is left out leaves the stored value alone.
- Every host row that the inventory endpoints return (`GET /api/inventory`
  with `include_hosts=true`, `GET /api/inventory/{group_id}`,
  `GET /api/inventory/{group_id}/hosts`) carries the five stored values plus
  display objects:

  ```
  "device_type_id": 7, "role_id": 2, "lifecycle_status_id": 1,
  "site_id": 3, "location_detail": "Row 4, rack 12",
  "hardware": {"id": 7, "model": "C9300-48P", "manufacturer_id": 1,
               "manufacturer": "Cisco"} | null,
  "role": {"id": 2, "name": "Switch", "color": "teal"} | null,
  "lifecycle_status": {"id": 1, "name": "Active", "color": "green"} | null,
  "site": {"id": 3, "name": "HQ"} | null
  ```

  The display objects come from joins or one lookup per catalogue per
  request, never one query per host.
- The same endpoints accept filters `manufacturer_id=`, `device_type_id=`,
  `role_id=`, `lifecycle_status_id=`, `site_id=`. Each is repeatable; values
  of one filter are alternatives, different filters must all match. The
  value `none` matches hosts with no value. They combine with `tag=` and
  `cf.<key>=`, and follow the same host or group semantics those filters
  have on `GET /api/inventory` (they are host filters: without
  `include_hosts=true` a group matches when it has a matching host).
- `GET /api/inventory/export/csv` gains the columns `Manufacturer`,
  `Device Type`, `Role`, `Lifecycle Status`, `Site`, `Location Detail`,
  placed before `Tags`, passed through the existing formula guard. The
  existing driver column is renamed from `Device Type` to `Platform` so the
  header has one `Device Type`.
- `GET /api/geo/sites` rows gain `host_count` (hosts whose `site_id` is the
  site).

All writes record an audit event (category `device_model`) the way the
custom fields routes do. `AUTHORIZATION_MATRIX.md` gains the routes.
`tools/coverage_gate.py` gains floors for `netcontrol/device_model.py` (95)
and `netcontrol/routes/device_model.py` (85).

## Backend layout

- `netcontrol/device_model.py`: pure helpers (`manufacturer_name`, name and
  color validation reusing the tag color constants from
  `netcontrol/custom_fields.py`).
- `routes/db/device_model.py`, re-exported through `routes/database.py`:
  catalogue CRUD with counts, `link_host_hardware`,
  `set_host_device_fields(host_id, values, lock)`,
  `bulk_set_host_device_fields`, `find_host_ids_by_device_filters`,
  `get_default_host_status_id`.
- `netcontrol/routes/device_model.py`: the routers, registered in
  `netcontrol/app.py` like the custom fields routers, reusing their
  `require_admin` wiring and the structured error detail support already in
  `http_exception_handler`.

## Frontend

- `api/deviceModel.ts`: types and TanStack Query hooks for the four
  catalogues and bulk edit. `api/inventory.ts`: the new host fields.
- Host dialog (`pages/Inventory/HostModal.tsx`): the driver select is
  labelled "Platform"; a "Device" section holds four selects (device type
  grouped by manufacturer, role, lifecycle status, site) and the location
  detail input. Saved in the same request as the host.
- `pages/Inventory/Inventory.tsx`: role and lifecycle status chips on host
  rows (reusing the chip styles of `TagChips`), the model column shows the
  linked device type and falls back to the raw `model` text, the driver
  column header reads "Platform" (the table has no reachability column to
  relabel), the existing filter popover gains the
  five facets, and the bulk bar gains "Edit…" opening a `BulkEditModal`.
- List filtering stays in the browser over the inline data, in the same
  helper that applies the tag and custom field filter.
- `pages/Settings/`: a "Device Model" tab (admin) with four tables:
  manufacturers, device types, roles, statuses, each with create, edit and
  delete, following `CustomDataTab.tsx` including the 409 confirm flow.
- Sites keep being managed on the Geolocation page; its site list shows the
  host count.

## Testing

- `tests/test_device_model_validation.py`: `manufacturer_name` and the
  validators.
- `tests/test_device_model_db.py`: catalogue CRUD and uniqueness ignoring
  case, default status rules, `link_host_hardware` (creates once, repeat is
  a no-op, respects locks, role only when empty), new host gets the default
  status, delete sets host references to null, placement sets the site.
- `tests/test_device_model_api.py`: access per route (anonymous, user
  without the feature, user with it, admin), host create and update with the
  new keys and lock behaviour, inline objects on list rows, each filter and
  `none`, bulk edit, 409 and confirm on delete, CSV columns, audit events.
- A migration test for the backfill if the suite has a pattern for testing a
  migration against prepared rows; otherwise the backfill SQL is exercised
  through a helper the migration and a test both call.
- Vitest: the filter predicate, the select option builders and the bulk
  edit payload builder.

CI steps: `ruff check`, `mypy netcontrol templates`, `bandit`, `pytest` with
the coverage gates, `npm run lint`, `npm run typecheck`, `npm test`,
`npm run build`. No new dependency.

All sample data is invented and uses the documentation address ranges.

## Documentation

- `docs/device-model.md`: the catalogues, how discovery fills them, locks,
  filters, bulk edit, the API with examples.
- README feature line and docs link.
