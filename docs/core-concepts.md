# Core Concepts

### Inventory Groups & Hosts
Device groups (e.g. "Core Switches") containing hosts with IP, hostname,
and device type. Similar to Ansible inventory groups.

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
