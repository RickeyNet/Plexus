# NetControl — Network Automation Hub

A Python-first network automation control center inspired by Ansible Tower / AWX.
Manage device inventories, run automation playbooks, store config templates, and
stream live job output — all through a REST API with WebSocket support.

## Architecture

```
netcontrol/
├── app.py                  # FastAPI application — all REST + WebSocket routes
├── database.py             # Async SQLite data layer (aiosqlite)
├── crypto.py               # Fernet encryption for stored credentials
├── runner.py               # BasePlaybook class + executor + registry
├── seed.py                 # Populates DB with demo inventory/playbooks/templates
├── run.py                  # Server entry point (uvicorn)
├── requirements.txt
├── netcontrol.db           # SQLite database (auto-created)
├── netcontrol.key          # Fernet encryption key (auto-created, keep safe)
├── playbooks/
│   ├── __init__.py         # Auto-imports all playbook modules
│   ├── vlan1_remediation.py  # VLAN 1 Destroyer (refactored)
│   ├── ntp_audit.py        # NTP compliance checker
│   └── config_backup.py    # Running-config backup
├── static/                 # React frontend build (optional)
└── logs/                   # Job execution logs
```

## Quick Start

```bash
cd netcontrol
pip install -r requirements.txt
python run.py
```

The server starts on `http://localhost:8080`. On first launch it auto-seeds
the database with demo inventory groups, playbooks, templates, and a
default credential.

Interactive API docs: `http://localhost:8080/docs`

## Core Concepts

### Inventory Groups & Hosts
Device groups (e.g. "Core Switches") containing hosts with IP, hostname,
and device type. Similar to Ansible inventory groups.

### Playbooks
Python scripts that subclass `BasePlaybook` and register themselves with
the `@register_playbook` decorator. Each playbook is an async generator
that yields `LogEvent` objects — enabling real-time streaming to the frontend.

### Templates
Reusable config snippets (IOS commands) that playbooks can consume.
Stored in the database, editable via API.

### Credentials
SSH username/password/enable-secret, encrypted at rest with Fernet.
Referenced by ID when launching jobs.

### Jobs
An execution of a playbook against an inventory group. Jobs run as
async background tasks. Output streams to subscribers via WebSocket.

## API Reference

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Stats, recent jobs, inventory overview |

### Inventory
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/inventory` | List all groups (with host counts) |
| POST | `/api/inventory` | Create group `{name, description}` |
| GET | `/api/inventory/{id}` | Group detail with hosts |
| DELETE | `/api/inventory/{id}` | Delete group and its hosts |
| GET | `/api/inventory/{id}/hosts` | List hosts in group |
| POST | `/api/inventory/{id}/hosts` | Add host `{hostname, ip_address, device_type}` |
| DELETE | `/api/hosts/{id}` | Remove a host |

### Playbooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/playbooks` | List all (with last run status) |
| POST | `/api/playbooks` | Register `{name, filename, description, tags}` |
| DELETE | `/api/playbooks/{id}` | Unregister |

### Templates
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/templates` | List all |
| POST | `/api/templates` | Create `{name, content, description}` |
| GET | `/api/templates/{id}` | Get one |
| PUT | `/api/templates/{id}` | Update `{name, content, description}` |
| DELETE | `/api/templates/{id}` | Delete |

### Credentials
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/credentials` | List all (passwords masked) |
| POST | `/api/credentials` | Create `{name, username, password, secret}` |
| DELETE | `/api/credentials/{id}` | Delete |

### Jobs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/jobs` | List job history |
| GET | `/api/jobs/{id}` | Job detail |
| GET | `/api/jobs/{id}/events` | All log events for a job |
| POST | `/api/jobs/launch` | Launch a job (see below) |
| WS | `/ws/jobs/{id}` | Real-time event stream |

**Launch payload:**
```json
{
  "playbook_id": 3,
  "inventory_group_id": 1,
  "credential_id": 1,
  "template_id": 1,
  "dry_run": true
}
```

## Writing a New Playbook

1. Create a file in `playbooks/`, e.g. `playbooks/my_script.py`
2. Subclass `BasePlaybook` and decorate with `@register_playbook`
3. Implement `async def run()` as an async generator yielding `LogEvent`s

```python
from runner import BasePlaybook, LogEvent, register_playbook

@register_playbook
class MyScript(BasePlaybook):
    filename = "my_script.py"
    display_name = "My Automation Script"
    description = "Does something useful"
    tags = ["example"]
    requires_template = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(f"Starting on {len(hosts)} hosts")

        for host in hosts:
            ip = host["ip_address"]
            yield self.log_info(f"Processing {ip}", host=ip)

            # Your automation logic here
            # Use credentials["username"], credentials["password"]
            # Use template_commands if requires_template = True

            yield self.log_success(f"Finished processing {ip}", host=ip)

        yield self.log_success("All done.")
```

4. Restart the server — playbooks auto-register on import
5. Register it in the DB via API:
```bash
curl -X POST http://localhost:8080/api/playbooks \
  -H "Content-Type: application/json" \
  -d '{"name": "My Script", "filename": "my_script.py", "description": "...", "tags": ["example"]}'
```

## WebSocket Usage

Connect to `/ws/jobs/{job_id}` after launching a job:

```javascript
const ws = new WebSocket("ws://localhost:8080/ws/jobs/1");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === "job_complete") {
    console.log("Job finished!");
  } else {
    console.log(`[${data.level}] ${data.host ? data.host + ": " : ""}${data.message}`);
  }
};
```

## Simulation Mode

When Netmiko is not installed, playbooks that support it (like VLAN 1
Remediation) automatically run in simulation mode with realistic fake
output. This is useful for frontend development and demos.

## Security Notes

- **netcontrol.key** — Fernet encryption key for credentials. Back it up.
  Losing it means stored passwords are unrecoverable.
- Credentials are encrypted at rest but decrypted in memory during job execution.
- The API has no authentication by default — add middleware for production use.
- Default seed credential uses `netadmin / cisco123` — change in production.
