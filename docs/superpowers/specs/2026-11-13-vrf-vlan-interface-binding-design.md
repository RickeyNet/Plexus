# VRF and VLAN Objects with IP-to-Interface Binding: Design

Date: 2026-11-13
Status: in implementation (design calls made by the assistant, listed under
"Decisions made"; not yet reviewed by the owner)

## Goal

VRFs and VLANs become records with their own pages instead of loose strings,
and every address a device's interfaces carry is stored with the interface,
the network and the VRF it sits in. This is the Plexus counterpart of
Nautobot's VRF, VLAN and "IP address assigned to an interface". Plexus fills
the records from what it already collects; an admin curates them.

## What exists today

- `hosts.vrf_name`, `hosts.vlan_id` (text), `ipam_prefixes.vrf` / `.vlan`,
  `ipam_allocations.vrf_name` / `.vlan_id`, `ipam_pending_allocations.vrf_name`
  and the IPAM history tables hold VRF names and VLAN ids as text. IPAM keys
  subnets and conflicts on `(subnet, vrf)` by exact string; `""` is the
  global VRF.
- `vlan_definitions` (per host: `vlan_id`, `name`, `state`) and
  `interface_inventory` (per host port: `access_vlan`, `trunk_vlans`) are
  written by the SNMP collector and the SSH inventory collection.
- The path trace configuration parsers
  (`netcontrol/integrations/pathtrace/platforms.py`, `platform_of(...).config`)
  already return, per interface of a running configuration, its addresses
  with their networks, its VRF and its HSRP / VRRP / GLBP addresses
  (`ConfigInterface` in `device_config.py`). Today only the bare addresses
  are kept, as `host_ip_aliases`.
- Every configuration capture is stored through
  `netcontrol/routes/device_config.py::store_device_config`.
- The device model (migration 0085) gives a host a `site_id`.

## Decisions made

| Topic | Decision |
|---|---|
| VRF identity | The VRF name. The text columns stay and keep being the key IPAM compares; a `vrfs` record is matched to them by exact name. No foreign keys are added to the IPAM tables (external source rows are deleted and re-inserted at every sync). |
| VRF name | Immutable after creation. Description and route distinguisher are editable. |
| Global VRF | `""` stays the global VRF and has no record. |
| VRF delete | Refused with 409 while anything uses the name. |
| VLAN identity | `(site, vid)`. `site_id` is a `geo_sites` id or null (a VLAN of no site, "global"). `vid` is immutable. |
| Device VLAN to record | A device's VLAN `v` belongs to the record `(device's site, v)` when it exists, otherwise to the global record `(null, v)`. Resolved at read time; `vlan_definitions` gets no new column. |
| Discovery | Creates missing VRF and VLAN records. It never changes or deletes a record. |
| Interface addresses | Read from the stored running configuration only (v1). Replaced per host each time a configuration is stored. Not editable by hand. |
| Deleting a site | Deletes the VLAN records of that site (devices that still carry the VLANs get records again, under no site, at their next collection). |

## Out of scope (v1)

- Interface networks as subnets of the IPAM overview (next slice).
- Addresses from SNMP (`ipAddrTable`) or from integrations (Meraki, Cato,
  cloud); platforms whose configuration is not parsed (PAN-OS) have no
  interface addresses.
- Hand-made interfaces or address assignments; VLAN groups; route targets;
  VRF or VLAN in the MCP endpoint, the Ansible inventory and CSV import.
- Changing the VLAN consistency audit rule.

## Data model

Migration `0086_add_vrfs_vlans_interface_addresses.py`. It is the only
definition of the new tables (not repeated in `SCHEMA`), like 0083 to 0085.
Timestamps are UTC `YYYY-MM-DD HH:MM:SS` text written by Plexus.

`vrfs`: `id`, `name` (1 to 64 chars, trimmed, `UNIQUE`), `rd` (text, at most
64 chars, default `''`), `description` (at most 500), `origin` (`manual` or
`discovered`), `created_at`.

`vlans`: `id`, `vid` (integer, 1 to 4094), `name` (at most 64, may be empty),
`site_id` (references `geo_sites(id)` ON DELETE CASCADE, nullable),
`description` (at most 500), `origin`, `created_at`. Unique index on
`(COALESCE(site_id, 0), vid)`.

`interface_addresses`: `id`, `host_id` (references `hosts(id)` ON DELETE
CASCADE), `interface` (the name in the configuration), `interface_key` (the
name normalised by `netcontrol.integrations.pathtrace.route_tables.interface_key`),
`address` (bare IP), `prefix_length`, `network` (CIDR), `vrf_name` (default
`''`), `role` (`primary`, `secondary`, `virtual`), `protocol` (`''`, `HSRP`,
`VRRP`, `GLBP`), `svi_vid` (the VLAN id when the interface is a VLAN
interface, else 0), `collected_at`. Unique on `(host_id, interface, address)`.
Indexes on `address`, `network`, `vrf_name`.

`host_vrfs`: `host_id` (cascade), `vrf_name`, `interface_count`,
`collected_at`; primary key `(host_id, vrf_name)`. The VRFs a device has an
interface or a static route in, including interfaces without an address.

Backfill (in the migration, set-based, safe to run twice):

- `vrfs` from every distinct non-empty trimmed name in `hosts.vrf_name`,
  `ipam_prefixes.vrf`, `ipam_allocations.vrf_name`, origin `discovered`.
- `vlans` from `vlan_definitions` joined to `hosts.site_id`: one record per
  `(site or null, vid)` with `vid` between 1 and 4094, named after the lowest
  host id's name for it, origin `discovered`.

Interface addresses cannot be filled by the migration (it must not import
the parsers). At startup, once, when the setting
`interface_addresses_backfilled` is not set, a supervised background task
parses the newest stored configuration of every host and sets the setting.

## Rules

- **Pure helpers** in `netcontrol/network_objects.py`: name, rd, vid and
  description validation; `svi_vid(interface_name) -> int` (`Vlan10`,
  `vlan 10`, `vlan.10`, `irb.10`, case ignored; else 0);
  `bindings_from_config(running: RunningConfig) -> tuple[list[dict], dict[str, int]]`
  giving the `interface_addresses` rows (primary first, then secondary, then
  virtual, with the interface's VRF; an address the parser gives without a
  usable network is skipped) and `vrf_name -> interface count` for
  `host_vrfs` (interfaces with a VRF, with or without an address, plus the
  VRFs of static routes with count 0 when no interface is in them).
- **One sync point**: `sync_host_bindings(host_id, device_type, config_text)`
  parses with `platform_of(device_type).config` (none: returns without
  touching the stored rows), replaces the host's `interface_addresses` and
  `host_vrfs` in one transaction and ensures a `vrfs` record for every VRF
  name found. It is called from `store_device_config` (which looks up the
  host's device type when not given), best effort: a parser error is logged
  and never fails the capture. The inventory collection passes the device
  type its session resolved.
- **Ensuring VRF records**: `ensure_vrfs(names, origin)` inserts the missing
  names (`ON CONFLICT DO NOTHING`). Called where a VRF name is written: host
  create and update (`manual`), `create_ipam_prefix` (`manual`),
  `replace_ipam_source_snapshot` (`discovered`), bindings sync
  (`discovered`), and any other writer of those columns found by grep.
- **Ensuring VLAN records**: `ensure_vlans_for_host(host_id)` creates, for
  each `vlan_definitions` row of the host that resolves to no record, a
  record at the host's site (null when it has none) named as the device
  names it, origin `discovered`. Called wherever `vlan_definitions` rows are
  written (the SSH inventory collection and the SNMP collector).
- **VLAN membership of a port**: `access_vlan = vid`, or `trunk_vlans` lists
  it. Reuse the matching the existing
  `/api/topology/search/hosts-by-vlan` route uses; do not write a second
  trunk list parser.
- **Name mismatch**: a VLAN record has `name_mismatch = true` when a device
  that resolves to it names the VLAN differently (ignoring case, and
  ignoring devices with an empty name).
- Validation errors on bodies are 422 (pydantic); a duplicate is 409 with a
  plain message; an unknown `site_id` is 400 with
  `detail = {"message", "fields": {"site_id": "<message>"}}`, the contract
  the device model routes use.

## Wire contract

Routes in `netcontrol/routes/network_objects.py`. Reads: signed-in user with
the `ipam` feature. Writes: admin. All writes record an audit event
(category `network_objects`).

```
Vrf   {id, name, rd, description, origin, created_at,
       host_count, device_count, prefix_count, address_count}
Vlan  {id, vid, name, site_id, site: {id, name} | null, description, origin,
       created_at, device_count, interface_count, prefix_count, name_mismatch}
InterfaceAddress
      {host_id, hostname, interface, address, prefix_length, network,
       vrf_name, role, protocol, svi_vid, collected_at}
```

`host_count`: hosts whose `vrf_name` is the name. `device_count` (VRF):
`host_vrfs` rows. `prefix_count` (VRF): `ipam_prefixes` rows with the VRF
plus distinct interface networks in it that are not among them.
`address_count`: `interface_addresses` rows. `device_count` (VLAN): devices
whose VLAN resolves to the record. `interface_count`: their ports in the
VLAN. `prefix_count` (VLAN): distinct networks of VLAN interfaces
(`svi_vid = vid`) on those devices.

| Route | Answer |
|---|---|
| `GET /api/ipam/vrfs` | `{"vrfs": [Vrf]}` by name |
| `POST /api/ipam/vrfs` `{name, rd?, description?}` | 201 `Vrf`; 409 when a VRF with that name exists, ignoring case |
| `GET /api/ipam/vrfs/{id}` | `Vrf` plus `devices [{host_id, hostname, interface_count}]`, `interfaces [InterfaceAddress]` (at most 2000, `truncated` flag), `prefixes [{subnet, source}]` (`source`: the IPAM source's provider, or `interface`) |
| `PUT /api/ipam/vrfs/{id}` `{rd?, description?}` | `Vrf`; a `name` key is rejected (422) |
| `DELETE /api/ipam/vrfs/{id}` | `{"ok": true}`; 409 with `detail = {"message", "affected"}` while in use (hosts, prefixes, allocations, interface addresses, device VRFs) |
| `GET /api/ipam/vlans[?site_id=<id>\|none][&vid=<n>]` | `{"vlans": [Vlan]}` by site name then vid |
| `POST /api/ipam/vlans` `{vid, name?, site_id?, description?}` | 201 `Vlan`; 409 on a duplicate `(site, vid)` |
| `GET /api/ipam/vlans/{id}` | `Vlan` plus `devices [{host_id, hostname, name, state, name_matches}]`, `interfaces [{host_id, hostname, interface, mode}]` (`mode`: `access` or `trunk`; at most 2000, `truncated`), `prefixes [{network, vrf_name, host_id, hostname, interface, address}]` |
| `PUT /api/ipam/vlans/{id}` `{name?, site_id?, description?}` | `Vlan`; 409 when the move collides; a `vid` key is rejected (422) |
| `DELETE /api/ipam/vlans/{id}` | `{"ok": true}` (a VLAN devices still carry is created again at their next collection) |
| `GET /api/hosts/{host_id}/interface-addresses` | `{"host_id", "addresses": [InterfaceAddress + vrf_id \| null + vlan_id \| null], "vrfs": [{name, vrf_id, interface_count}]}`; gated like `GET /api/hosts/{host_id}/interface-inventory` |
| `POST /api/ipam/interface-addresses/rebuild` | admin; parses the newest stored configuration of every host again; `{"ok": true, "hosts": <parsed>, "addresses": <rows>}` |

Changes to existing endpoints:

- `GET /api/ipam/address/{ip}` gains `interfaces`: the `InterfaceAddress`
  rows of that address (of the VRF when `vrf` is given).
- `GET /api/ipam/subnets/{subnet}` gains `interfaces`: the
  `InterfaceAddress` rows whose address is inside the subnet (of the VRF
  when `vrf` is given), at most 1024.

`AUTHORIZATION_MATRIX.md` gains the routes. `tools/coverage_gate.py` gains
floors for `netcontrol/network_objects.py` (95) and
`netcontrol/routes/network_objects.py` (85).

## Backend layout

- `netcontrol/network_objects.py`: the pure helpers.
- `routes/db/network_objects.py`, re-exported through `routes/database.py`:
  VRF and VLAN CRUD with counts and details, `ensure_vrfs`,
  `ensure_vlans_for_host`, `replace_host_bindings`,
  `get_interface_addresses_for_host`, `find_interface_addresses(address, vrf)`,
  `find_interface_addresses_in_subnet(subnet, vrf, limit)`.
- `netcontrol/routes/network_objects.py`: the routers (`router`,
  `admin_router`), `sync_host_bindings`, the rebuild and the startup
  backfill; registered in `netcontrol/app.py` like the device model routers.

## Frontend

- `api/networkObjects.ts`: types and TanStack Query hooks.
- IPAM page: a tab strip "Subnets", "VRFs", "VLANs" (an existing tab
  component is reused). "Subnets" holds today's page unchanged.
  - VRFs tab: table (name, RD, origin, devices, hosts, prefixes, addresses,
    description), "Add VRF", edit, delete (the 409 message is shown), a row
    opens a detail panel with its devices, interface addresses and prefixes.
  - VLANs tab: table (VLAN id, name with a mismatch marker, site, devices,
    ports, prefixes, description), a site filter, "Add VLAN", edit, delete,
    a row opens a detail panel with devices (their name for it), ports and
    prefixes.
- Subnet drill-down: an address row that an interface carries shows the
  device and interface.
- Device interfaces (the map's node details "Interfaces" tab and the device
  detail page where it lists interfaces): an "IP addresses" table
  (interface, address/length, VRF, role, VLAN) from
  `GET /api/hosts/{id}/interface-addresses`.
- Host dialog: "VRF" and "VLAN ID" inputs with suggestions from the two
  catalogues, sent as the existing `vrf_name` and `vlan_id` keys.

## Testing

- `tests/test_network_objects_validation.py`: validators, `svi_vid`,
  `bindings_from_config` over invented configurations parsed by the real
  platform parsers (IOS with VRF, secondary and HSRP; Junos; an unparsed
  platform).
- `tests/test_network_objects_db.py`: CRUD, uniqueness, counts, the VLAN
  resolution rule (site record wins over global), `ensure_*` idempotence and
  never-overwrite, bindings replace, cascade on host delete, VRF delete
  refused in use, the migration backfill through a helper the migration and
  the test both call.
- `tests/test_network_objects_api.py`: access per route (anonymous, user
  without `ipam`, user with it, admin), every route, the 409 and 400
  contracts, audit events, the two extended IPAM answers, `store_device_config`
  filling bindings, the rebuild.
- Vitest for the pure frontend helpers and the tab components' empty, error
  and filled states.

CI steps: `ruff check .`, `mypy netcontrol templates`, `bandit`, `pytest`
with the coverage gates, `npm run lint`, `npm run typecheck`, `npm test`,
`npm run build`. No new dependency. All sample data is invented and uses the
documentation address ranges.

## Documentation

- `docs/vrfs-and-vlans.md`: the records, how they are filled, the
  resolution rule, interface addresses and their limits, the API.
- `docs/api-reference.md`, README feature line and docs link, `CHANGELOG.md`.
