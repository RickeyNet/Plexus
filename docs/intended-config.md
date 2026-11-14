# Intended configuration

Config Backups says what a device's configuration **is**, Config Drift says
when it **changed**, Compliance grades it against **rules**. Intended
configuration says what it **should be**: admins write Jinja2 templates,
Plexus renders one for each device from the data it already holds, stores
the result and compares it with the device's newest backup.

It is on the Configuration page, **Intended** tab
(`/configuration/intended`), with the `config-drift` feature.

| Piece | What it is |
|---|---|
| **Template** | Jinja2 text. A `device` template is rendered for the hosts its scope matches; a `snippet` is only included by other templates |
| **Config context** | A JSON object scoped to devices. All the contexts that match a host are merged into one `context` variable |
| **Intended configuration** | One per host that has a matching template: the rendered text, whether it rendered, and its comparison with the host's newest backup |

## Templates

A template has a name (1 to 100 characters, unique ignoring case), a kind,
a scope, its text (at most 262144 characters), a description (at most 500)
and an enabled flag. The text is checked when it is saved: a Jinja syntax
error is refused with its message and line.

**Scope.** A `device` template applies to hosts by:

| Field | Matches | Weight |
|---|---|---|
| Inventory group | hosts of that group | 8 |
| Site | hosts at that site | 4 |
| Role | hosts with that role | 2 |
| Driver (`device_type`, such as `cisco_ios`) | hosts with that driver | 1 |

An empty field matches any host; every field that is set must match. A
group, site or role that is later deleted matches no host, so deleting one
never widens a template to more devices. A snippet has no scope.

**Which template a host gets.** Among the enabled `device` templates that
match the host, the most specific wins: add up the weights of the fields
that are set (a template scoped to a group and a driver scores 9). A tie
goes to the name that comes first ignoring case. A host no template matches
has no intended configuration.

**Includes.** `{% include 'name' %}` and `{% import 'name' as m %}` find any
template by name, ignoring case, enabled or not, snippets and device
templates alike.

## Config contexts

A context has a name (unique ignoring case), a weight (0 to 100000, default
1000), its data (a JSON object, at most 65536 characters), a description,
an enabled flag and the same scope as a template plus one host.

For a host, every enabled context that matches is merged in order of weight
(lowest first), then name. Each one is merged over the result so far:
objects merge key by key, any other value (lists included) replaces the
earlier one. So a weight 1000 context for every device can hold defaults,
and a weight 2000 context for one site can override part of them.

Context data is stored as plain text, **not encrypted**. Do not put
passwords, keys or community strings in it; there are no secret variables
in intended configurations.

## Template variables

| Variable | Contents |
|---|---|
| `host` | `id`, `name`, `ip`, `driver`, `model`, `serial`, `version`, `category`, `vrf`, `vlan_id`, `location_detail`, `role`, `status` (lifecycle status), `manufacturer`, `hardware_model`, `part_number` (text, `""` when unset), `tags` (tag names), `custom_fields` (key to value) |
| `group` | The host's inventory group: `id`, `name`, `description`, `tags`, `custom_fields` |
| `site` | `id`, `name`, `description`, `address`; all empty (`id` null) when the host has no site |
| `vlans` | The VLAN records of the host's site, or the records of no site when the host has no site: `vid`, `name`, `description`, by VLAN id |
| `vrfs` | The VRFs seen on the host: `name`, `rd`, `description` |
| `interfaces` | The host's collected interface inventory: `name`, `description`, `admin_state`, `oper_state`, `speed_mbps`, `access_vlan`, `trunk_vlans` (text as stored), `addresses` (`address`, `prefix_length`, `network`, `vrf`, `role`) |
| `context` | The merged config context |

`interfaces` is **observed data**: what Plexus last collected from the
device (SNMP interface inventory, addresses read from its stored
configuration), not intent. A template that builds interface sections from
it reproduces what the device has; use it for names and addresses you do
not keep elsewhere, and put intent in contexts.

The Variables button on a template's preview shows exactly what one host's
template sees, and which contexts were merged, in order.

**Filters added to Jinja's own:**

| Filter | Example | Result |
|---|---|---|
| `netmask` | `'192.0.2.0/24'\|netmask` | `255.255.255.0` |
| `wildcard` | `'192.0.2.0/24'\|wildcard` | `0.0.0.255` |
| `network` | `'192.0.2.5/24'\|network` | `192.0.2.0` |
| `prefixlen` | `'192.0.2.0/24'\|prefixlen` | `24` |
| `nth_host(n)` | `'192.0.2.0/24'\|nth_host(1)` | `192.0.2.1` (negative counts from the end) |
| `ip` | `'192.0.2.5/24'\|ip` | `192.0.2.5` |

Each takes an address with or without a prefix length (`192.0.2.0/24`,
`192.0.2.5/24`, `2001:db8::1/64`).

## Worked example

A snippet named `ntp-and-snmp`:

```jinja
{% for server in context.ntp_servers %}
ntp server {{ server }}
{% endfor %}
snmp-server location {{ site.name }}
snmp-server contact {{ context.snmp.contact }}
```

A `device` template named `branch-edge`, scoped to driver `cisco_ios` and
the role Edge:

```jinja
hostname {{ host.name }}
{% for vlan in vlans %}
vlan {{ vlan.vid }}
 name {{ vlan.name }}
{% endfor %}
{% for intf in interfaces if intf.addresses %}
interface {{ intf.name }}
 description {{ intf.description or 'uplink' }}
{% for a in intf.addresses %}
 ip address {{ a.address }} {{ a.network|netmask }}
{% endfor %}
{% endfor %}
{% include 'ntp-and-snmp' %}
```

Two contexts: `defaults` (weight 1000, no scope)

```json
{"ntp_servers": ["198.51.100.10"], "snmp": {"contact": "noc@example.com"}}
```

and `branch-12` (weight 2000, scoped to the site Branch 12)

```json
{"ntp_servers": ["198.51.100.10", "198.51.100.11"]}
```

For edge-r1 at Branch 12, with VLANs 10 (users) and 20 (voice) at that
site and `192.0.2.1/24` collected on GigabitEthernet0/1, the merged context
is `{"ntp_servers": ["198.51.100.10", "198.51.100.11"], "snmp": {"contact":
"noc@example.com"}}` and the intended configuration is:

```
hostname edge-r1
vlan 10
 name users
vlan 20
 name voice
interface GigabitEthernet0/1
 description uplink
 ip address 192.0.2.1 255.255.255.0
ntp server 198.51.100.10
ntp server 198.51.100.11
snmp-server location Branch 12
snmp-server contact noc@example.com
```

If the newest backup of edge-r1 has no VLAN 20, only the first NTP server,
and `shutdown` under GigabitEthernet0/1, the result is **non-compliant**
with three missing lines (`vlan 20`, ` name voice`, `ntp server
198.51.100.11`) and one extra line (`shutdown` under `interface
GigabitEthernet0/1`).

## The comparison

Both the intended text and the backup are read as trees by indentation.
Blank lines, and lines that start with `!` or `#`, are ignored, and so is
trailing whitespace. A line is identified by its own text and the texts of
the lines it sits under, so ` description uplink` under one interface is a
different line from the same text under another.

- **Missing**: an intended line the backup does not have. When a parent
  line is missing, its children are missing too.
- **Extra**: a backup line the intended text does not have, under a parent
  the intended text has *and* gives children to. Top-level backup lines are
  never extra (a template does not have to describe the whole device).

| Verdict | When |
|---|---|
| `compliant` | Nothing is missing |
| `non_compliant` | At least one intended line is missing |
| `unknown` | The host has no successful backup, or its template failed to render |

Extra lines are listed but do not change the verdict. The backup compared is
the host's newest successful configuration backup (its plain
`config_text`).

## When it runs

- **Generate** on the Devices view (or `POST /api/intended-config/generate`)
  renders and compares the chosen hosts, a group, or every host now.
- In the background every host is regenerated 3 minutes after start, every
  hour, and about 5 seconds after any template or context change (several
  changes in a row run once).
- When a capture stores a new backup for a host (a backup policy, the
  topology collection, a compliance scan...), that host's intended
  configuration is compared with it again. This never fails the capture.

Rendering text that has not changed leaves `changed_at` alone;
`generated_at` and `compared_at` move on every run.

## Limits

Templates run in Jinja's immutable sandbox: they cannot reach Python
internals (`''.__class__` and the like are refused), change lists or
dictionaries, or touch the filesystem, the network or a process. On top of
that:

- `range` gives at most 10000 items.
- The output is cut off with an error past 1048576 characters, and so is any
  single value a template builds (repeated or joined text, padding widths).
- A render that runs 5 seconds without producing output is stopped with an
  error.
- Undefined variables are errors (`StrictUndefined`), not empty text.

A failed render stores the error (with the template name and line when
Jinja gives one) and no text; the preview shows the same error before you
save.

## What it does not do

- It never changes a device: nothing here opens a device session, pushes or
  remediates.
- No secret variables (`{{secret.NAME}}`) and no encryption of context data.
- One current intended configuration per host; no history.
- No alerts or notifications on non-compliance, and it is not used as the
  Config Drift baseline.
- No Git-backed templates, tag scopes, MCP tools or CSV export.

## Permissions and audit

Reading templates, contexts, results and variables, and **Generate**, need
the `config-drift` feature. Creating, changing and deleting templates and
contexts, and the template preview, are admin only. Template and context
changes and generation runs are written to the audit log (category
`config`). The API is in [api-reference.md](api-reference.md#intended-configuration).
