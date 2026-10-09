# Core Concepts

### Inventory Groups & Hosts
Device groups (e.g. "Core Switches") containing hosts with IP, hostname,
and device type. Similar to Ansible inventory groups.

### Playbooks
Python scripts that subclass `BasePlaybook` and register themselves with
the `@register_playbook` decorator. Each playbook is an async generator
that yields `LogEvent` objects - enabling real-time streaming to the frontend.

### Templates
Reusable config snippets (IOS commands) that playbooks can consume.
Stored in the database, editable via API.

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
