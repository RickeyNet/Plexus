# API Reference

### Dashboard
| Method | Endpoint         | Description                                          |
|--------|------------------|------------------------------------------------------|
| GET    | `/api/dashboard` | Stats, recent jobs, inventory overview               |
| GET    | `/api/health`    | Service health + lightweight counters/timing metrics |

### Inventory
| Method | Endpoint                      | Description                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/api/inventory`              | List all groups (with host counts)               |
| POST   | `/api/inventory`              | Create group `{name, description}`               |
| GET    | `/api/inventory/{id}`         | Group detail with hosts                          |
| DELETE | `/api/inventory/{id}`         | Delete group and its hosts                       |
| GET    | `/api/inventory/{id}/hosts`   | List hosts in group                              |
| POST   | `/api/inventory/{id}/hosts`   | Add host `{hostname, ip_address, device_type}`   |
| DELETE | `/api/hosts/{id}`             | Remove a host                                    |

### Playbooks
| Method | Endpoint              | Description                                      |
|--------|-----------------------|--------------------------------------------------|
| GET    | `/api/playbooks`      | List all (with last run status)                  |
| POST   | `/api/playbooks`      | Register `{name, filename, description, tags}`   |
| DELETE | `/api/playbooks/{id}` | Unregister                                       |

### Templates
| Method | Endpoint              | Description                             |
|--------|-----------------------|-----------------------------------------|
| GET    | `/api/templates`      | List all                                |
| POST   | `/api/templates`      | Create `{name, content, description}`   |
| GET    | `/api/templates/{id}` | Get one                                 |
| PUT    | `/api/templates/{id}` | Update `{name, content, description}`   |
| DELETE | `/api/templates/{id}` | Delete                                  |

### Credentials
| Method | Endpoint                | Description                                   |
|--------|-------------------------|-----------------------------------------------|
| GET    | `/api/credentials`      | List all (passwords masked)                   |
| POST   | `/api/credentials`      | Create `{name, username, password, secret}`   |
| DELETE | `/api/credentials/{id}` | Delete                                        |

### Jobs
| Method | Endpoint                | Description                |
|--------|-------------------------|----------------------------|
| GET    | `/api/jobs`             | List job history           |
| GET    | `/api/jobs/{id}`        | Job detail                 |
| GET    | `/api/jobs/{id}/events` | All log events for a job   |
| POST   | `/api/jobs/launch`      | Launch a job (see below)   |
| WS     | `/ws/jobs/{id}`         | Real-time event stream     |

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
