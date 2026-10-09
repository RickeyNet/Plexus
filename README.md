# Plexus - Network Automation Hub

A Python-first network automation control center inspired by Ansible Tower / AWX, SolarWinds, and Catalyst Center.
Manage device inventories, run automation playbooks, store config templates, and
stream live job output - all through a REST API with WebSocket support.

**Scope (current):** FastAPI backend with playbook runner, WebSocket streaming, SNMP discovery, IPAM, topology, compliance, and digital-twin lab mode.

## Features

- **Inventory and playbooks** - device groups and hosts, Python playbooks, live job output over WebSocket.
- **Configuration management** - config templates, config backups, drift detection and compliance audits.
- **SNMP discovery and IPAM** - find devices on the network and track address space.
- **Topology** - CDP/LLDP map plus Meraki, Cato, Cisco FMC, AWS and Azure sources, with path trace across them.
- **Flow collector** - built-in NetFlow / sFlow / IPFIX receiver with traffic summaries.
- **Cloud Visibility** - discovery of AWS and Azure accounts and their networks.
- **Software upgrades** - software version inventory, vulnerability alerts and an IOS-XE upgrade tool.
- **Digital-twin lab mode** - rehearse changes against lab copies of devices.
- **Alerting** - alert rules routed to email, PagerDuty, webhook and Microsoft Teams channels.

## Quick Start

Plexus runs as a Docker compose stack. You need Docker Engine with the compose
plugin; for production hosts see `DEPLOYMENT.md` and `deploy/DEPLOYMENT.md`.

`docker-compose.yml` runs three services: `plexus` (the app, built from the
`Dockerfile` with the cloud SDKs included), `postgres` (PostgreSQL 16, data in
the `plexus-postgres` volume) and `nginx` (TLS on 443, redirect on 80).
`deploy/setup.sh` generates `.env` (random API token and Postgres password) and
a self-signed certificate in `certs/`.

1) Generate `.env` and certs:
```bash
bash deploy/setup.sh
```
2) Edit `.env`. For local use set `APP_CORS_ORIGINS=https://localhost`.
3) Build and start, then watch the app log:
```bash
docker compose up --build -d
docker compose logs -f plexus
```
4) Open `https://localhost` (accept the self-signed certificate warning), log in
as `admin` / `netcontrol` and change the password when prompted.

Rebuild the app after code changes, or reset everything (deletes the database):

```bash
docker compose up --build -d plexus
docker compose down -v
```

`.env` sets `APP_COOKIE_SECURE=true`, so logging in over plain
`http://127.0.0.1:8080` (bypassing nginx) silently fails: the browser drops
the Secure session cookie. Use `https://localhost`, or set
`APP_COOKIE_SECURE=false` in `.env` for direct access.

Compose always runs on PostgreSQL. To run the image on SQLite instead, see the
Loop A notes in [DEVSETUP.md](DEVSETUP.md).

## Other ways to run

### Local venv (Windows/Linux, SQLite)

Copy `.env.example` to `.env` and adjust values (host, port, https, defaults), then:

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # PowerShell; bash/zsh: source .venv/bin/activate
python -m pip install -r requirements.txt
# optional: PostgreSQL support (Linux/production)
python -m pip install -r requirements-postgres.txt
python templates/run.py --host 0.0.0.0 --port 8080
```

Visit `http://localhost:8080/docs`. `python templates/run.py --help` lists the
run options (`--https`, `--reload`, `--expose`, ...). On first launch the
database is seeded with demo inventory groups, playbooks, templates and a
default credential.

### WSL2 with Docker and Postgres (development)

For day-to-day development that matches the deployed stack, see
[DEVSETUP.md](DEVSETUP.md).

## Guides

**Operators**

- [DEPLOYMENT.md](DEPLOYMENT.md) - production deployment notes (firewalls, storage, systemd)
- [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md) - Ubuntu UFW firewall ruleset for the Docker stack
- [deploy/airgap/README.md](deploy/airgap/README.md) - air-gapped deployment on an offline VM
- [DATA_RETENTION.md](DATA_RETENTION.md) - how long each class of data is kept
- [RADIUS_CONFIGURATION_GUIDE.md](RADIUS_CONFIGURATION_GUIDE.md) - RADIUS login setup
- [TACACS_CONFIGURATION_GUIDE.md](TACACS_CONFIGURATION_GUIDE.md) - TACACS+ / Cisco ISE Device Admin login
- [docs/database-backends.md](docs/database-backends.md) - SQLite vs PostgreSQL and migration
- [docs/versioning-and-release.md](docs/versioning-and-release.md) - versioning and release process

**Developers**

- [DEVSETUP.md](DEVSETUP.md) - WSL2, Docker and Postgres dev loops
- [AGENTS.md](AGENTS.md) - architecture and conventions for coding agents
- [docs/core-concepts.md](docs/core-concepts.md) - inventory, playbooks, templates, credentials, jobs
- [docs/writing-playbooks.md](docs/writing-playbooks.md) - writing a playbook, simulation mode
- [docs/api-reference.md](docs/api-reference.md) - REST API endpoints
- [docs/websocket-usage.md](docs/websocket-usage.md) - streaming job output over WebSocket
- [docs/FRONTEND_MIGRATION.md](docs/FRONTEND_MIGRATION.md) - archived React frontend migration plan

**Features and integrations**

- [docs/aws-topology.md](docs/aws-topology.md) - AWS in the topology map
- [docs/azure-topology.md](docs/azure-topology.md) - Azure in the topology map
- [docs/cato-topology.md](docs/cato-topology.md) - Cato Networks in the topology map
- [docs/fmc-topology.md](docs/fmc-topology.md) - Cisco FMC in the topology map
- [docs/meraki-topology.md](docs/meraki-topology.md) - Meraki in the topology map
- [docs/meraki-compliance.md](docs/meraki-compliance.md) - Meraki security compliance audits
- [docs/path-trace.md](docs/path-trace.md) - Path Mode on the topology map
- [docs/software-versions.md](docs/software-versions.md) - software versions and vulnerability alerts
- [docs/upgrade-tool-guide.md](docs/upgrade-tool-guide.md) - Cisco Catalyst IOS-XE upgrade procedure
- [docs/network-documentation-usage.md](docs/network-documentation-usage.md) - automated network documentation reports
- [docs/flow-collector.md](docs/flow-collector.md) - NetFlow / sFlow / IPFIX collector
- [docs/alert-notification-channels.md](docs/alert-notification-channels.md) - email, PagerDuty, webhook and Teams alerts

## Repository layout

```
netcontrol/
├── app.py                  # FastAPI application entry (routers, lifespan)
├── routes/                 # API route modules and background engines
├── drivers/                # Per-vendor device drivers (IOS, NX-OS, Junos, ...)
├── integrations/           # Meraki, Cato, FMC, AWS, Azure, path trace, software
└── static/frontend/        # React + TypeScript SPA (Vite; build output in dist/)
routes/
├── database.py             # Data layer (SQLite or PostgreSQL)
├── db/                     # Per-domain database queries
├── migrations/             # Numbered schema migrations
├── crypto.py               # Fernet encryption for stored credentials
├── runner.py               # Playbook base class, executor and registry
└── seed.py                 # Demo inventory/playbooks/templates on first launch
templates/
├── run.py                  # Server entry point (uvicorn)
└── playbooks/              # Built-in playbooks (VLAN 1, NTP audit, NetFlow, SNMPv3)
tests/                      # pytest suite
deploy/                     # setup.sh, nginx.conf, backup/upgrade scripts, airgap/
docs/                       # Reference and feature guides
scripts/, tools/            # Admin scripts and release/migration tooling
docker-compose.yml          # App + PostgreSQL + nginx stack
Dockerfile                  # App image
```

## Security Notes

- **netcontrol.key** - Fernet encryption key for credentials. Back it up.
  Losing it means stored passwords are unrecoverable.
- Credentials are encrypted at rest but decrypted in memory during job execution.
- API token protection is supported via `APP_API_TOKEN`; set `APP_REQUIRE_API_TOKEN=true` to enforce token auth for API routes.
- Default seed credential uses `netadmin / cisco123` - change in production.
- License: MIT (`LICENSE`).
