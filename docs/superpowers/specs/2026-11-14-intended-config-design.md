# Intended configuration generation

Status: in implementation (design calls made by the assistant under the
"fewer questions, just build" rule; not yet reviewed by the owner).

## Why

Plexus already stores what a device's configuration **is** (Config Backups),
tells when it **changed** (Config Drift against a frozen capture) and grades
it against **rules** (Compliance). It cannot say what the configuration
**should be**. This adds that: Jinja2 templates plus the data Plexus holds
about a device render the device's intended configuration, which is stored
and compared with the device's newest backup. It is the counterpart of
Nautobot Golden Config's "intended" stage with config contexts.

## Goals

- Admins write Jinja2 templates and scope them to devices by driver, role,
  site and group.
- Admins write config contexts: JSON data scoped the same way (plus one
  host), merged by weight into one `context` object per device.
- Each inventory host with a matching template gets one stored intended
  configuration, regenerated on demand, after template or context changes,
  and hourly.
- Each intended configuration is compared with the host's newest stored
  configuration backup: which intended lines the device lacks.
- A page shows all of it, with a template preview against a real host.

## Not in this slice

- Pushing or remediating: nothing here opens a device session.
- Secret variables (`{{secret.NAME}}`) in intended configurations.
- History of intended configurations (one current row per host).
- Alerts or notifications on non-compliance; making the intended
  configuration the Config Drift baseline.
- Git-backed templates, tag scopes, MCP tools, CSV export.

## Anti-goals

- A template must never run arbitrary Python or reach the filesystem,
  network or process: rendering is sandboxed and bounded.
- A deleted scope record (role, site, group, host) must never widen a
  template or context to more devices.

## Data model (migration 0087)

`config_templates` exists and is empty (reserved by migration 0042). It is
reshaped:

| column | notes |
|---|---|
| `id` | existing |
| `name` | unique ignoring case (the old `UNIQUE (name, device_type)` is dropped) |
| `kind` | `device` (rendered for hosts) or `snippet` (only included by others) |
| `device_type` | driver key scope; `''` = any (existing column) |
| `role_id`, `site_id`, `group_id` | scope, `NULL` = any. Plain integers, no foreign key |
| `template_text` | existing; at most 262144 characters |
| `description` | existing; at most 500 |
| `enabled` | 0/1, default 1 |
| `created_at`, `updated_at`, `updated_by` | UTC `YYYY-MM-DD HH:MM:SS` text |

`config_contexts`: `id`, `name` (unique ignoring case), `weight` (integer
0 to 100000, default 1000), `data` (JSON object as text, at most 65536
characters), `description`, `enabled`, scope `device_type`, `role_id`,
`site_id`, `group_id`, `host_id` (same rules), timestamps, `updated_by`.

`intended_configs`: one row per host that has a matching template.
`host_id` (primary key, deleted with the host), `template_id`,
`template_name`, `status` (`ok` / `error`), `error`, `config_text`,
`generated_at`, `changed_at` (last time `config_text` changed),
`compliance` (`compliant` / `non_compliant` / `unknown`), `backup_id`
(the backup compared, or NULL), `missing_count`, `extra_count`,
`compared_at`.

Names: 1 to 100 characters, trimmed.

## Rules

**Scope.** A scope field that is set must equal the host's value; all set
fields must match. A set id that names no existing record matches nothing.
Snippets have no scope.

**Template selection.** Among enabled `device` templates that match the
host, the most specific wins: score = group 8 + site 4 + role 2 + driver 1.
Ties go to the name first in case-insensitive order. No match: the host has
no intended configuration (its row is removed).

**Context merge.** Enabled contexts that match the host, ordered by weight
ascending then name; each is deep-merged over the result so far (objects
merge key by key; any other value, lists included, replaces).

**Template variables.**

- `host`: `id`, `name`, `ip`, `driver`, `model`, `serial`, `version`,
  `category`, `vrf`, `vlan_id`, `location_detail`, `role`, `status`
  (lifecycle), `manufacturer`, `hardware_model`, `part_number` (strings,
  `''` when unset), `tags` (names), `custom_fields` (key to value).
- `group`: `id`, `name`, `description`, `tags`, `custom_fields`.
- `site`: `id`, `name`, `description`, `address`; all empty when the host
  has no site.
- `vlans`: the VLAN records of the host's site, else the no-site records:
  `vid`, `name`, `description`, ordered by `vid`.
- `vrfs`: the VRFs seen on the host: `name`, `rd`, `description`.
- `interfaces`: the host's collected interface inventory, each with
  `name`, `description`, `admin_state`, `oper_state`, `speed_mbps`,
  `access_vlan`, `trunk_vlans` (text as stored) and `addresses`
  (`address`, `prefix_length`, `network`, `vrf`, `role`). This is observed
  data, not intent; the docs say so.
- `context`: the merged config context.

**Rendering.** `jinja2.sandbox.ImmutableSandboxedEnvironment`,
`StrictUndefined`, `trim_blocks`, `lstrip_blocks`, no autoescape. `include`
and `import` resolve enabled or disabled snippets and device templates by
name. `range` is capped at 10000 items. Output is cut off with an error past
1048576 characters; a render that runs past 5 seconds between output chunks
is stopped with an error. Filters added: `netmask`, `wildcard`, `network`,
`prefixlen` (each takes `192.0.2.0/24` or `192.0.2.5/24`), `nth_host(cidr,
n)`, `ip` (strip the prefix length). An error carries a message and, when
Jinja gives one, the template name and line. Trailing whitespace is trimmed
per line and the text ends with one newline.

**Comparison.** Both texts are read as trees by indentation (blank lines
and lines that are only `!` or start with `!` or `#` are ignored; trailing
whitespace ignored). A line is identified by its text and the texts of its
ancestors. *Missing*: an intended line the backup lacks (a missing parent
makes its children missing too). *Extra*: a backup line the intended text
lacks whose parent is an intended line that has children (top-level backup
lines are never extra). `compliant` when nothing is missing;
`non_compliant` otherwise; `unknown` when the host has no successful backup
or the intended status is `error`. Extra lines are shown but do not change
the verdict. The backup is the host's newest successful `config_backups`
row, `config_text`.

**When things run.**

- `POST /generate` renders and compares the chosen hosts now.
- A background loop regenerates every host hourly, and about 5 seconds
  after any template or context write (writes wake it; bursts coalesce).
  First run 180 seconds after start.
- Storing a new backup row for a host re-compares that host (best effort,
  never fails the capture).

## Wire contract

All under the `config-drift` feature for a signed-in user; rows marked
*admin* also need an administrator. Errors are `{"detail": "..."}`; 400 for
bad input, 404 unknown id, 409 name taken.

Template object: `{id, name, kind, device_type, role_id, site_id, group_id,
template_text, description, enabled (bool), created_at, updated_at,
updated_by, host_count}`. `host_count` = hosts whose stored intended
configuration came from it.

Context object: `{id, name, weight, data (object), description, enabled,
device_type, role_id, site_id, group_id, host_id, created_at, updated_at,
updated_by}`.

| Route | Notes |
|---|---|
| `GET /api/intended-config/templates` | `{templates: [...]}` ordered by name |
| `POST /api/intended-config/templates` *admin* | body: every writable field; `name` and `kind` required. 201, the object. 400 with `detail = {message, line}` on a Jinja syntax error |
| `GET /api/intended-config/templates/{id}` | the object |
| `PUT /api/intended-config/templates/{id}` *admin* | full replace, same checks |
| `DELETE /api/intended-config/templates/{id}` *admin* | `{ok: true}` |
| `GET /api/intended-config/contexts` | `{contexts: [...]}` ordered by weight, name |
| `POST`, `GET {id}`, `PUT {id}`, `DELETE {id}` on `/api/intended-config/contexts` | as templates; `data` must be a JSON object |
| `POST /api/intended-config/preview` *admin* | body `{host_id, template_id?, template_text?}` (text wins; neither: the host's selected template). `{template_name, config_text, error}`; `error` is `null` or `{message, template, line}`. Stores nothing |
| `GET /api/intended-config/hosts/{host_id}/variables` | `{variables: {...}, contexts: [{id, name, weight}]}` in merge order |
| `GET /api/intended-config/hosts` | `?group_id=`, `?compliance=`, `?status=`. `{rows: [...], counts: {hosts, generated, errors, compliant, non_compliant, unknown, no_template}}`; counts ignore the filters |
| `GET /api/intended-config/hosts/{host_id}` | the row plus `config_text`, `lines: [{text, missing (bool)}]`, `extra: [{path: [str], text}]`, `backup: {id, captured_at}` or `null`. 404 when the host has no intended configuration |
| `POST /api/intended-config/generate` | body `{host_ids?: [int], group_id?: int}`; neither = every host. `{hosts, generated, changed, errors, no_template}` |

Row: `{host_id, hostname, ip_address, group_id, group_name, template_id,
template_name, status, error, compliance, missing_count, extra_count,
backup_id, generated_at, changed_at, compared_at}`.

Template and context writes and `generate` are audited (category
`config`).

## Frontend

Configuration page gains an **Intended** tab (`/configuration/intended`,
feature `config-drift`) with three views behind a segmented control:

- **Devices**: summary counts, a "Generate all" button, filters (group,
  compliance), and the table of rows. A row opens a dialog with the
  intended text (missing lines marked), the extra lines, the backup it was
  compared with, Copy and Regenerate.
- **Templates** (admin can edit; others read): table and a dialog with
  name, kind, scope pickers, the template text, and a preview pane: pick a
  host, render, see the text or the error with its line; "Variables" shows
  what that host's template sees.
- **Contexts**: table and a dialog with name, weight, scope pickers
  (including one host) and the JSON data, checked before saving.

## Dependency and CI

`jinja2` (and `markupsafe`) join `requirements.txt` and
`requirements-lock.txt` with hashes. New `netcontrol` modules get floors in
`tools/coverage_gate.py`.

## Docs

`docs/intended-config.md` (user guide with a worked template),
`docs/api-reference.md`, `AUTHORIZATION_MATRIX.md`, `README.md`,
`CHANGELOG.md`.
