# Bulk Import

Plexus imports hosts, inventory groups, IPAM prefixes, IP addresses, VLANs
and VRFs from a CSV, YAML or JSON file. Every import has two steps:

1. **Preview.** Plexus reads the file and reports, row by row, what it would
   do: **Create**, **Update** (with the change to each field), **Skip**
   (nothing to change, or the object exists in create mode), or **Error**
   (with the column and the reason). Nothing is written.
2. **Import.** Plexus reads and checks the file again (it never trusts the
   preview) and writes it.

By default an import is **all or nothing**: when any row has an error,
nothing is imported, and when a write fails part way through, every row
written before it is undone. Clear **All or nothing** to import row by row
instead: rows are written in file order and the import stops at the first
row that has an error or fails; the rows before it stay imported and the
report says how many.

## Where to find it

| Page | Button | Imports |
|---|---|---|
| Inventory | **Import** (next to Export CSV / Export YAML) | Hosts, inventory groups |
| IPAM, overview | **Import** (next to Define Subnet) | Prefixes, IP addresses, VLANs, VRFs |
| IPAM, VLANs tab | **Import** | VLANs |
| IPAM, VRFs tab | **Import** | VRFs |

The dialog offers **Download CSV template**: an empty CSV with the columns
the type expects (for hosts, the export's columns, including one column per
host custom field).

## Who may import

| Objects | Needs |
|---|---|
| Hosts, inventory groups | The **Inventory** feature with write access (`inventory.write`). An account limited to selected inventory groups imports only into the groups it may write; hosts and groups it cannot read are never matched. Only accounts with access to all devices can create a top-level group. |
| Prefixes, IP addresses, VLANs, VRFs | The **IPAM** feature to download a template; an administrator to preview or import, as for every IPAM, VLAN and VRF change. |

Every import is written to the audit log (`bulk_import`, `<type>.import`),
and every object it creates or changes raises the same object-change event
as a change made in the UI, so webhooks and the change log see imports.

## File formats

- **CSV**: a header row, then one row per object. Column names are matched
  ignoring case, spaces and punctuation, so `IP Address`, `ip_address` and
  `ip address` are the same column. Blank rows are skipped. A cell that the
  export protected against spreadsheet formulas (a leading apostrophe before
  `=`, `+`, `-` or `@`) loses that apostrophe again, so an exported file
  imports unchanged.
- **YAML** or **JSON**: a list of objects with the same keys (snake_case
  keys such as `ip_address` work too), or an object with one key holding
  that list (`hosts: [...]`). `tags` may be a list; `custom_fields` may be an
  object of values by field key or label. YAML is read with a safe loader:
  tags such as `!!python/object` are refused.

Limits: 1 MiB per file and 5,000 rows per import.

A column that is not recognised is ignored and listed in the preview, so a
misspelt column name is visible before anything is written. Columns that
name a password, secret, token, credential or SNMP community are never
imported: credentials are managed on the Credentials page only.

### Modes and matching

| Mode | A row that matches an existing object | A row that matches none |
|---|---|---|
| Create | Skipped | Created |
| Update | Updated | Error |
| Create or update | Updated | Created |

Each type matches existing objects on its key (below); hosts can match on
the hostname (ignoring case) or the IP address. Two rows with the same key
in one file are an error. A key that matches more than one host (two hosts
with the same name in different groups) is an error: match on the other key.

In an update, a column present in the file sets the field and an empty cell
clears it; a column left out of the file leaves the field as it is. **Tags**
replaces the object's tags; custom field columns change only those fields.

### References

Names are resolved ignoring case: group (its path, `Parent / Child`, or a
name that only one group has), site, role, lifecycle status, manufacturer and
device type, VRF and VLAN. A name that matches nothing is a row error; the
import never creates those records. The one exception is **tags**: a tag
name that does not exist yet is created when the import is written (any
inventory user can create tags), and the preview lists the new tags.

## Columns

### Hosts

The columns of **Export CSV** (Inventory page), so export, edit, import works:

| Column | Notes |
|---|---|
| Hostname | Required to create (defaults to the IP address when empty). |
| IP Address | Required to create. A unicast address outside the reserved ranges. A group cannot have two hosts with the same address. |
| Model, Software Version, Status | Read from the device: exported, ignored on import. |
| Platform | The SSH driver key (`cisco_ios`, `juniper_junos` ...). Empty: `cisco_ios` for a new host, unchanged for an update. |
| Group | The group's path (`Campus / Core`) or a name only one group has. Required to create; an update moves the host when it differs. |
| Manufacturer, Device Type | The device type (by model) and, when two manufacturers have the same model, its manufacturer. |
| Role, Lifecycle Status, Site, Location Detail | By name. A new host without a lifecycle status gets the default one. |
| Tags | Names separated by `; `. |
| One column per host custom field | Under its label (or key). |

Also accepted, not exported: **VRF** (a VRF record's name) and **VLAN** (the
id of a VLAN record).

Match keys: `hostname` (default) or `ip`. **Export YAML** writes the same
hosts as YAML, which imports the same way.

### Inventory groups

| Column | Notes |
|---|---|
| Name | Required. Cannot contain ` / `. |
| Parent | The parent group's path; empty for a top-level group. A parent created by an earlier row of the same file may be used. |
| Description | |
| Tags, group custom fields | As for hosts. |

Match key: `path` (Parent / Name). An update changes the description, tags
and custom fields; it never renames or moves a group.

### IPAM prefixes

Written to the built-in Plexus IPAM source (prefixes synced from an external
IPAM are not changed).

| Column | Notes |
|---|---|
| Prefix | Required. A network such as `192.0.2.0/24`; host bits are cleared (the preview says so). The built-in source defines a subnet once, in one VRF. |
| VRF | A VRF record's name; empty for the global table. |
| Description | |
| Site | A site's name. |
| VLAN | The id of a VLAN record (of that site, or one without a site). |
| Tags, prefix custom fields | As for hosts. |

Match key: `prefix` (the prefix and its VRF).

### IP addresses

Written to the built-in Plexus IPAM source.

| Column | Notes |
|---|---|
| Address | Required. |
| Prefix | An IPAM prefix (of the row's VRF) that contains the address. Empty: the most specific such prefix. A prefix must exist first. |
| VRF | A VRF record's name. |
| DNS Name | |
| Description | |

Match key: `address`.

### VLANs

| Column | Notes |
|---|---|
| VLAN ID | Required, 1 to 4094. |
| Name | |
| Site | A site's name; empty for a VLAN of no site. |
| Description | |

Match key: `vid` (the VLAN id and the site).

### VRFs

| Column | Notes |
|---|---|
| Name | Required. |
| RD | The route distinguisher. |
| Description | |

Match key: `name` (ignoring case).

Import VRFs and VLANs before the prefixes and addresses that name them.

## API

| Method | Path | |
|---|---|---|
| GET | `/api/import/inventory/{hosts\|groups}/template` | Empty CSV with the expected header |
| POST | `/api/import/inventory/{hosts\|groups}/preview` | What an import would do |
| POST | `/api/import/inventory/{hosts\|groups}/commit` | Import |
| GET | `/api/import/ipam/{prefixes\|addresses\|vlans\|vrfs}/template` | |
| POST | `/api/import/ipam/{prefixes\|addresses\|vlans\|vrfs}/preview` | |
| POST | `/api/import/ipam/{prefixes\|addresses\|vlans\|vrfs}/commit` | |
| GET | `/api/inventory/export/yaml` | The hosts of the CSV export, as YAML |

Preview and commit take a multipart form: `file` (an upload) or `text`
(pasted rows), `format` (`csv`, `yaml` or `json`), `mode` (`create`,
`update` or `upsert`), `match_key` (empty for the type's default) and, for
commit, `atomic` (`true` by default). Both return the report:

```json
{
  "object_type": "hosts",
  "summary": {"create": 1, "update": 1, "skip": 0, "error": 0, "total": 2},
  "rows": [
    {"row": 2, "key": "edge-sw1", "action": "create", "errors": [], "changes": {}, "warnings": []},
    {"row": 3, "key": "edge-sw2", "action": "update", "errors": [],
     "changes": {"IP Address": {"before": "192.0.2.10", "after": "192.0.2.11"}}, "warnings": []}
  ],
  "ignored_columns": [{"column": "model", "reason": "Read from the device; not imported."}],
  "new_tags": [],
  "committed": false,
  "applied": 0,
  "message": ""
}
```

`row` is the spreadsheet row of a CSV (the header is row 1) or the item
number in a YAML/JSON list. A commit that writes nothing because rows have
errors, or whose write failed and was rolled back, answers `422` with the
report; a file that cannot be read at all answers `400` (`413` when it is
larger than 1 MiB).

Note: in an all-or-nothing import that fails part way through, the
object-change events of the rows written before the failure have already
been handed to webhooks; the rows themselves are rolled back.
