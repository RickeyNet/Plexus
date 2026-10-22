# Core Concepts

### Inventory Groups & Hosts
Device groups (e.g. "Core Switches") containing hosts with IP, hostname,
and device type. Similar to Ansible inventory groups.

#### Group hierarchy
A group can have a **parent group**, making it a sub-group: `Meraki` with a
sub-group per Meraki network, `AWS` with one per VPC. Set the parent in the
group's **Create** / **Edit** dialog (**Parent group**, *None* for a top-level
group) or with **New Sub-group** in a group's menu; changing the parent moves
the group, with its sub-groups, under another parent. A group cannot be moved
under itself or one of its own sub-groups (`PUT /api/inventory/{id}` answers
HTTP 400).

- **Path.** A group's path is the names from the top group down, joined with
  ` / ` (`Meraki / 1000 - HQ`). Group selects across the app (jobs, compliance,
  backups, monitoring, reports, ...) show the path, and `GET /api/inventory`
  returns each group's `parent_id`, `path` and `depth` (0 for a top-level
  group), listed as a tree: each parent followed by its sub-groups. The
  Inventory page indents sub-groups under their parent, and collapsing a
  group hides its sub-groups too.
- **Names** are unique among siblings: two parents can each have a `HQ`
  sub-group, but one parent cannot have two (HTTP 409), and top-level names
  stay unique among top-level groups.
- **Order.** The drag order on the Inventory page (and the name or host-count
  sorts) applies among the sub-groups of one parent; a group is dragged only
  among its siblings.
- **Hosts.** A host belongs to exactly one group. A parent's hosts are its
  *direct* hosts only: running a job, a backup policy, monitoring, discovery
  or a compliance scan against a parent group does not include its
  sub-groups' hosts, and its host count does not either.
- **Deleting.** A group that has sub-groups cannot be deleted (HTTP 409):
  delete its sub-groups or move them to another parent first.

### Playbooks
Python scripts that subclass `BasePlaybook` and register themselves with
the `@register_playbook` decorator. Each playbook is an async generator
that yields `LogEvent` objects - enabling real-time streaming to the frontend.

### Templates
Reusable config snippets (CLI commands) that playbooks can consume. Shown as
**Instructions** under Delegator; stored in the database, editable via API.

A template name can carry one body per vendor (`device_type`). A job that
selects any variant sends each host the body matching its platform, so one
"SNMPv3 Monitoring" template serves a mixed Cisco and Aruba group.

Plexus ships one SNMPv3 template, **SNMPv3 Monitoring (Read-Only)**, with
variants for Cisco IOS, IOS-XE, NX-OS, Aruba AOS-CX and Aruba AOS-Switch
(HP ProCurve). The variants are inserted once per install at startup
(`routes/builtin_templates.py`) and are then ordinary templates: edit, rename
or delete them and the change sticks across restarts. The SNMPv3 keys are
`{{secret.NAME}}` references (`snmp_v3_auth_key`, `snmp_v3_priv_key`); define
them under Delegator > Credentials > Secret Variables before running.

### Credentials
SSH username/password/enable-secret, encrypted at rest with Fernet.
Referenced by ID when launching jobs.

### Jobs
An execution of a playbook against an inventory group. Jobs run as
async background tasks. Output streams to subscribers via WebSocket.

Job history retention is configurable in `Settings > Authentication Provider` via
`Job History Retention (days)`. Completed jobs (`success`/`failed`) older than
the configured value are deleted automatically. Minimum retention is 30 days.
Cleanup runs at startup and periodically while the app is running.
