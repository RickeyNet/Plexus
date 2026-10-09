# Plexus Deployment Guide (Docker)

Complete instructions for deploying Plexus on a VM with Docker, PostgreSQL, and HTTPS.

## Requirements

- VM with Ubuntu 26.04 LTS (or RHEL/Rocky 9)
- 2 CPU, 4 GB RAM, 40 GB disk
- Static IP on your management network
- DNS record (optional but recommended): e.g. `plexus.corp.local`

## Quick Start (Ubuntu, one command)

For a fresh Ubuntu box, the bootstrap script does everything in Steps 1–7
below in a single run - installs Docker, clones the repo, generates certs,
starts the stack, and opens firewall ports:

```bash
curl -fsSL https://raw.githubusercontent.com/RickeyNet/Plexus/main/deploy/bootstrap.sh | sudo bash  # one-shot install
```

Or after cloning manually:
```bash
sudo bash deploy/bootstrap.sh  # idempotent - safe to re-run
```

The script is idempotent: re-running it pulls the latest code and rebuilds.
Skip to **Step 4: Edit .env** afterward if you want to change CORS origins
or other settings. The detailed manual steps below remain authoritative for
RHEL/Rocky and for understanding what the bootstrap automates.

## Step 1: Install Docker

Plexus uses `docker compose` (v2, plugin form). Ubuntu's `docker.io` package
does **not** ship the compose plugin, and `docker-compose-plugin` is not in
Ubuntu's default repos - you must use Docker's official apt repository.

#### Ubuntu - Docker's official repo
```bash
sudo apt update  # refresh apt package index
sudo apt install -y ca-certificates curl  # prereqs for HTTPS apt repos
sudo install -m 0755 -d /etc/apt/keyrings  # create keyring dir for third-party signing keys
# Download Docker's GPG signing key
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc  # make key world-readable so apt can verify packages
# Register Docker's apt repo for your Ubuntu release codename and CPU arch
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update  # refresh index with Docker repo added
# Install engine, CLI, containerd runtime, buildx, and compose v2 plugin
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable docker && sudo systemctl start docker  # enable on boot and start now
sudo usermod -aG docker $USER  # add user to docker group so docker runs without sudo
# Log out and back in for the group change to take effect
```


###### RHEL / Rocky - Docker's official repo
```bash
sudo dnf -y install dnf-plugins-core  # install repo management plugin
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo  # register Docker's official RHEL repo
# Install engine, CLI, containerd runtime, buildx, and compose v2 plugin
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable docker && sudo systemctl start docker  # enable on boot and start now
sudo usermod -aG docker $USER  # add user to docker group so docker runs without sudo
```

Verify both pieces are present:

```bash
docker --version  # confirm Docker engine is installed
docker compose version  # confirm compose v2 plugin is installed
```

### Activate the `docker` group membership
```bash
sudo usermod -aG docker $USER  # only takes effect in **new** login sessions, so your
# current shell can't talk to the Docker socket yet. Pick one:
```
# Option A (cleanest) - log out and SSH back in

exit  # close current shell so next login picks up group change

# Option B - start a new shell with the group applied, no logout needed
newgrp docker  # spawn a subshell with the docker group already active
```

Verify it worked - `docker` should appear in the output of `groups`, and a
plain `docker ps` should run without `sudo`:

```bash
groups  # list groups your shell currently has - should include 'docker'
docker ps  # list running containers - succeeds without sudo if group is active
```

If `docker ps` still fails with "permission denied while trying to connect to
the docker API," you're still in the old session - log out fully and back in.

## Step 2: Clone the Repository

Install git first if it isn't already on the box:

```bash
sudo apt install -y git  # Ubuntu / Debian
# sudo dnf install -y git  # RHEL / Rocky
git --version  # confirm install
```

Then clone the repo:

```bash
sudo mkdir -p /opt/plexus  # create install directory (root-owned by default)
sudo chown -R $USER:$USER /opt/plexus  # give your user ownership so git can write here
cd /opt/plexus  # enter install directory
git clone https://github.com/RickeyNet/Plexus .  # clone repo contents into current directory (note trailing dot)
```

## Step 3: Run the Setup Script

```bash
bash deploy/setup.sh  # run setup helper: generates .env, creates self-signed cert, verifies Docker
```

This automatically:
- Generates `.env` with random database password and API token
- Creates a self-signed TLS certificate in `certs/`
- Verifies Docker is installed and ready

## Step 4: Edit .env

```bash
nano .env  # open the generated env file for editing
```

The only value you **must** change:

```
APP_CORS_ORIGINS=https://plexus.corp.local
```

Set this to the hostname or IP your team will use to access Plexus in their browser.

All other values (DB password, API token) were auto-generated by the setup script.

### Full .env Reference

| Variable                   | Default          | Description                        |
|----------------------------|------------------|------------------------------------|
| `APP_HOST`                 | `0.0.0.0`        | Bind address (leave as-is)         |
| `APP_PORT`                 | `8080`           | Internal app port (leave as-is)    |
| `APP_HTTPS`                | `false`          | App speaks plain HTTP to nginx, which terminates TLS |
| `APP_COOKIE_SECURE`        | `true`           | Mark cookies Secure (external scheme is HTTPS) |
| `APP_HSTS`                 | `true`           | Enable HSTS header                 |
| `APP_CORS_ORIGINS`         | (set by setup)   | Allowed browser origins            |
| `APP_REQUIRE_API_TOKEN`    | `false`          | Gate the API behind `X-API-Token` (browser sessions don't need it) |
| `APP_API_TOKEN`            | (auto-generated) | Token for API/automation access    |
| `INSTALL_CLOUD_SDKS`       | `true`           | Build arg: bake boto3/azure/google SDKs in (cloud accounts, AWS topology) |
| `PLEXUS_IMAGE`             | (unset)          | Set by `upgrade.sh --image`; run a registry image instead of the local build |
| `APP_ALLOW_SELF_REGISTER`  | `false`          | Block public registration          |
| `APP_DB_ENGINE`            | `postgres`       | Database backend                   |
| `APP_DATABASE_URL`         | (auto-generated) | PostgreSQL connection string       |
| `APP_DB_PATH`              | `/app/state/netcontrol.db` | SQLite file path (container state volume) |
| `APP_SESSION_KEY_FILE`     | `/app/state/session.key` | Session signing key location       |
| `APP_ENCRYPTION_KEY_FILE`  | `/app/state/netcontrol.key` | Credential encryption key location |
| `POSTGRES_DB`              | `plexus`         | Database name                      |
| `POSTGRES_USER`            | `plexus`         | Database user                      |
| `POSTGRES_PASSWORD`        | (auto-generated) | Database password                  |

## Step 5: Start Everything

```bash
docker compose up -d  # build images if needed and start all containers detached
```

This starts 3 containers and mounts persistent state into Docker volumes (`/app/state` and `/app/certs`):

| Container         | Purpose                | Port                        |
|-------------------|------------------------|-----------------------------|
| `plexus-app`      | Plexus application     | 8080 (internal)             |
| `plexus-postgres` | PostgreSQL 16 database | 5432 (internal)             |
| `plexus-nginx`    | HTTPS reverse proxy    | 443 (public), 80 (redirect) |

Additional UDP ports exposed on the app container:

| Port       | Purpose                       |
|------------|-------------------------------|
| `2055/udp` | NetFlow v5/v9/IPFIX collector |
| `6343/udp` | sFlow collector               |
| `162/udp`  | SNMP trap receiver            |
| `1514/udp` | Syslog receiver               |

## Step 6: Verify

```bash
docker compose ps  # check all 3 containers are running and healthy
curl -k https://localhost/api/health  # hit health endpoint (-k allows the self-signed cert)
docker compose logs -f plexus  # tail live app logs (Ctrl-C to detach; container keeps running)
```

## Step 7: Open Firewall

Minimal rules for a quick start. For source-restricted rules, the
`DOCKER-USER` hardening that actually filters traffic to published container
ports, and flow-verification steps, see [FIREWALL.md](FIREWALL.md).

```bash
sudo ufw allow 443/tcp  # HTTPS - user access
sudo ufw allow 80/tcp  # HTTP redirect to HTTPS
sudo ufw allow 2055/udp  # NetFlow from network devices
sudo ufw allow 162/udp  # SNMP traps (optional)
sudo ufw allow 1514/udp  # Syslog (optional)
```

## Step 8: First Login and Configuration

1. Browse to `https://<vm-ip-or-hostname>`
   - You will see a certificate warning (expected with self-signed cert)
   - Click through to proceed
2. Login with default credentials: `admin` / `netcontrol`
3. You will be forced to change the password on first login
4. Go to **Settings** to configure:

### Configure LDAP / Active Directory (optional)

1. Settings > Authentication Provider > select **LDAP / Active Directory**
2. Fill in:

| Field                    | Example                                               | Notes                      |
|--------------------------|-------------------------------------------------------|----------------------------|
| LDAP Server              | `dc01.corp.local`                                     | Your domain controller     |
| Port                     | `389` (or `636` for SSL)                              | Check "Use SSL" for LDAPS  |
| Service Account DN       | `CN=svc_plexus,OU=Service Accounts,DC=corp,DC=local`  | Needs read access          |
| Service Account Password | *(password)*                                          |                            |
| Base DN                  | `DC=corp,DC=local`                                    | LDAP search root           |
| User Search Filter       | `(sAMAccountName={username})`                         | Default works for AD       |
| Admin Group DN           | `CN=Network Admins,OU=Groups,DC=corp,DC=local`        | Members get admin role     |

3. Check "Enable LDAP / Active Directory authentication"
4. Save
5. Test: log out, log back in with your AD credentials

### Create User Access Groups

1. Settings > Access Groups > create groups like "Engineers", "NOC", "Read-Only"
2. Assign features to each group (inventory, monitoring, topology, etc.)
3. Assign users to groups (LDAP users are auto-provisioned on first login)

### Enable Monitoring

1. Settings > configure SNMP credentials for your device groups
2. Settings > enable Scheduled Topology Discovery
3. Settings > enable Monitoring

### Add Devices

1. Inventory > create groups (e.g., "Core", "Distribution", "Access")
2. Add hosts manually or use SNMP discovery scan

## Using Your Own TLS Certificate

If your workplace has an internal Certificate Authority, replace the
self-signed cert files generated by `setup.sh`:

```bash
# Drop your CA-signed cert and key into ./certs/ (cert.pem must be the full chain)
cp your-cert.pem ./certs/cert.pem  # full chain certificate
cp your-key.pem  ./certs/key.pem   # matching private key
chmod 600 ./certs/key.pem          # restrict key file permissions
docker compose restart nginx       # reload nginx with the new cert
```

The compose file bind-mounts `./certs` into both the app and nginx
containers, so updating the files on disk is all that's needed -
no volume copy step required. This eliminates the browser certificate
warning for your team.

## Day-to-Day Operations

### Status & Monitoring

The compose stack runs detached (`docker compose up -d`) with
`restart: unless-stopped` on every container, so the app auto-starts on
VM boot and auto-recovers from crashes. **Do not** sit on a foreground
`docker compose logs -f` session - check status on demand instead.

```bash
# Quick health snapshot - service status, ports, uptime
docker compose ps

# Live logs (Ctrl-C to detach; the container keeps running)
docker compose logs -f plexus

# Recent activity without tailing
docker compose logs --tail 50 plexus

# Just errors and warnings
docker compose logs plexus | grep -iE 'error|warning|exception'

# Container resource usage (CPU, memory, network, disk I/O)
docker stats --no-stream
```

For external monitoring (Nagios, Grafana, Prometheus blackbox, etc.),
hit the app's health endpoint:

```bash
curl -k https://<vm-ip>/api/health
# Returns 200 {"status": "ok"} when the app is up and the DB is reachable.
```

The primary status surface for operators is **the app's own dashboard**
at `https://<vm-ip>/`. The CLI commands above are for the VM operator
verifying the platform itself is healthy.

**Verify auto-restart works** after the initial deploy - reboot the VM
and confirm the stack comes back without intervention:

```bash
sudo reboot  # restart the VM to verify the stack auto-starts on boot
# Wait 60 seconds, SSH back in:
docker compose ps  # All three containers should show "Up", postgres + plexus "(healthy)"
```

### Log Rotation

Docker's default JSON log driver keeps logs forever, which over months
will fill `/var/lib/docker`. The bundled `docker-compose.yml` caps each
container's logs at 250 MB total (50 MB per file × 5 files). If you
want different limits, edit the `logging:` block under each service:

```yaml
    logging:
      driver: "json-file"
      options:
        max-size: "50m"   # Per file
        max-file: "5"     # How many rotated files to keep
```

Apply changes with `docker compose up -d` (no `--build` needed -
logging config is metadata, not part of the image).

### Update to Latest Code

```bash
cd /opt/plexus  # enter install directory
bash deploy/upgrade.sh  # snapshot DB, fast-forward current branch, rebuild, restart, wait for /api/health
```

`upgrade.sh` records the previous commit under `state/.upgrade-previous` and
keeps the last 10 pre-upgrade database dumps under `state/backups/upgrades/`.
Other forms:

```bash
bash deploy/upgrade.sh --ref v1.2.3                 # pin to a tag, branch, or commit
bash deploy/upgrade.sh --image ghcr.io/org/plexus:v1.2.3  # run a registry image (no local build)
bash deploy/upgrade.sh --dry-run                    # print the plan only
bash deploy/upgrade.sh --rollback                   # return to the previous commit / image
```

`--image` writes `PLEXUS_IMAGE=<tag>` into `.env`, which compose reads for
the service's `image:`; later `docker compose up -d` / `restart` keep using
that image. Running the default git mode again clears it and goes back to
the local build. Plain `git pull && docker compose up -d --build` still
works, it just skips the snapshot and rollback bookkeeping.

### View Logs

See **Status & Monitoring** above. Quick reference:

```bash
docker compose logs -f plexus  # follow app logs
docker compose logs --tail 100 plexus  # last 100 lines, then exit
docker compose logs -f  # all services together
```

### Restart Services

```bash
# Restart app only (no downtime for DB)
docker compose restart plexus

# Restart everything
docker compose restart
```

### Stop and Start

```bash
# Stop all containers (data preserved)
docker compose down

# Start again
docker compose up -d
```

### Backups

A backup script is provided at `deploy/backup.sh`. It dumps PostgreSQL **and**
archives the `plexus-db` state volume, which holds `netcontrol.key` (the Fernet
key for stored device credentials) and `session.key`. **Losing
`netcontrol.key` permanently breaks decryption of every stored credential**, so
do not back up the database alone.

Run on demand:

```bash
bash deploy/backup.sh  # dump postgres + archive state volume to default location
# Override destination or retention:
BACKUP_DEST=/mnt/nas/plexus RETENTION_DAYS=60 bash deploy/backup.sh  # write to NAS, keep 60 days instead of 30
```

Schedule nightly via cron:

```bash
sudo install -m 0644 deploy/plexus.cron /etc/cron.d/plexus  # install nightly backup as a system cron job
```

By default this writes `/var/backups/plexus/db-YYYYMMDD-HHMMSS.sql.gz` and
`state-YYYYMMDD-HHMMSS.tar.gz`, prunes files older than 30 days, and logs to
`/var/log/plexus-backup.log`. Push these files off-box (rsync, S3, etc.) - a
local-only backup will not survive a VM loss.

Manual ad-hoc dump (no state volume):

```bash
docker exec plexus-postgres pg_dump -U plexus plexus > backup_$(date +%Y%m%d).sql  # quick SQL-only dump (no state volume - incomplete on its own)
```

### Restore

```bash
# 1. Stop the app (leave postgres running)
docker compose stop plexus

# 2. Restore the database
gunzip -c /var/backups/plexus/db-YYYYMMDD-HHMMSS.sql.gz \
    | docker exec -i plexus-postgres psql -U plexus plexus

# 3. Restore the state volume (encryption + session keys).
#    Replace 'plexus' in the volume name with your compose project name.
docker run --rm \
    -v plexus_plexus-db:/dest \
    -v /var/backups/plexus:/src:ro \
    alpine sh -c 'cd /dest && tar xzf /src/state-YYYYMMDD-HHMMSS.tar.gz'

# 4. Start the app
docker compose start plexus
```

### Full Reset (wipes all data)

```bash
docker compose down -v  # stop containers and DELETE all volumes (data loss!)
docker compose up -d  # rebuild fresh stack from scratch
```

### Complete Uninstall (Ubuntu - wipes Docker, Plexus, and all data)

Use this when you want to test `deploy/bootstrap.sh` against a clean
Ubuntu box, or fully remove Plexus and Docker from a host. **Destructive
- removes containers, volumes, Docker engine, and the cloned repo.**

```bash
# 1. Stop and remove all Plexus containers + volumes
cd /opt/plexus 2>/dev/null && sudo docker compose down -v --remove-orphans || true

# 2. Wipe any remaining Docker state (containers, images, volumes, networks)
sudo docker system prune -a --volumes -f || true

# 3. Stop Docker and uninstall packages
sudo systemctl stop docker.socket docker.service || true
sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt-get autoremove -y --purge

# 4. Remove Docker's data dir, apt repo, and GPG key
sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker
sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc

# 5. Remove the cloned repo
sudo rm -rf /opt/plexus

# 6. Drop user from docker group (group itself stays - harmless)
sudo gpasswd -d "$USER" docker 2>/dev/null || true

# 7. Verify clean
command -v docker && echo "DOCKER STILL PRESENT" || echo "Docker removed."
ls /opt/plexus 2>/dev/null && echo "REPO STILL PRESENT" || echo "Repo removed."
```

After this, the box is back to a stock Ubuntu state. Re-run
`deploy/bootstrap.sh` (or the manual Steps 1–7) to deploy fresh.

## Troubleshooting

### `apt` sits on "Waiting for cache lock ... held by process NNNN (unattended-upgr)"

Not hung. A fresh Ubuntu starts `unattended-upgrades` a minute or two after
first boot and it holds the dpkg lock while it applies security updates,
which can take 10+ minutes on a new install. `bootstrap.sh` waits for it
automatically (up to 15 minutes). If you are running `apt` by hand, either
wait it out or stop the background run cleanly - never `kill -9` apt/dpkg:

```bash
sudo systemctl stop unattended-upgrades  # finishes the current package, then stops
sudo dpkg --configure -a                 # complete anything left half-configured
sudo apt upgrade
```

A full-screen pink dialog ("Pending kernel upgrade" / "Which services should
be restarted?") is `needrestart`, not an error - Tab to `<Ok>`, Enter.

### App won't start

```bash
# Check logs for errors
docker compose logs plexus | tail -50

# Check if postgres is healthy
docker compose ps postgres

# Manually test DB connection
docker exec plexus-app python -c "
import asyncio, routes.database as db
async def check():
    d = await db.get_db()
    print('DB OK')
    await d.close()
asyncio.run(check())
"
```

### Can't reach the web UI

```bash
# Check nginx is running
docker compose ps nginx

# Check cert files inside nginx container
docker exec plexus-nginx ls -la /etc/nginx/certs/

# Test directly bypassing nginx
curl http://localhost:8080/api/health
```

### LDAP login not working

```bash
# Check app logs for LDAP errors
docker compose logs plexus | grep -i ldap

# Common issues:
# - Wrong bind DN format (must be full DN, not just username)
# - Service account doesn't have search permissions
# - Base DN doesn't match your AD structure
# - Port 636 requires "Use SSL" checked
# - Firewall blocking VM -> domain controller on port 389/636
```

### NetFlow not receiving data

```bash
# Check collector is started (must be enabled via API or UI after startup)
curl -k https://localhost/api/flows/status

# Start the collector if not running
curl -k -X POST https://localhost/api/admin/flows/start?port=2055

# Check UDP port is listening
ss -ulnp | grep 2055

# Verify switch can reach this VM on UDP 2055
# On the switch: show flow exporter PLEXUS-EXPORT statistics
```

## Persistent state (Docker)

The compose file maps two named volumes:

- `/app/state` - SQLite DB (`netcontrol.db`) and the Fernet key
  (`netcontrol.key`). **Back this up.** Losing the key file means every
  stored credential is unrecoverable.
- `/app/certs` - TLS certificates when running with `--https`.

For PostgreSQL deployments, the SQLite file isn't used but the Fernet key
still lives in `/app/state`.

## Cloud Visibility (AWS / Azure / GCP)

The Cloud Visibility feature (topology discovery, flow-log pulls, traffic
metrics) and the AWS layer of the topology map need the provider SDKs,
which are **not** in `requirements.txt`. The compose stack
(`bootstrap.sh`, `upgrade.sh`, the air-gap bundle) builds with
`INSTALL_CLOUD_SDKS=true` by default, so they are present there; set
`INSTALL_CLOUD_SDKS=false` in `.env` for a smaller image. Published release
images are built from the hashed lock only and do not include them. For a
bare-metal install:

```bash
pip install -r requirements-cloud.txt
# or a manual Docker build:
docker build --build-arg INSTALL_CLOUD_SDKS=true .
```

Without the SDKs, account validation reports `unavailable` and the pullers
return `<sdk>_not_installed`; nothing silently pretends to work.

### Credentials

- Prefer **keyless auth**: on AWS use an instance profile or `role_arn`
  (+ optional `external_id`) in the account's auth config; on Azure,
  DefaultAzureCredential / managed identity is used when no client secret
  is provided; on GCP, Application Default Credentials are used when no
  service-account JSON is given. No secret at rest at all.
- Stored auth configs are AES-256-GCM encrypted and **write-only** — the
  API never returns them. Editing an account with a blank auth-config field
  keeps the stored credentials; pass `clear_auth_config: true` to wipe.
- Keep the encryption key (`APP_ENCRYPTION_KEY_FILE`) on a separate secret
  mount from the DB volume; co-locating them defeats at-rest encryption.
- Grant read-only IAM: AWS `ec2:Describe*`, `directconnect:Describe*`,
  `logs:StartQuery/GetQueryResults/StopQuery`, `cloudwatch:GetMetricData`,
  `sts:GetCallerIdentity`; Azure `Reader` on the subscription +
  `Storage Blob Data Reader` on the NSG flow-log storage account +
  `Monitoring Reader`; GCP `roles/compute.networkViewer`,
  `roles/logging.viewer`, `roles/monitoring.viewer`.

### Scheduling and scale

All three sync loops (flow, traffic metrics, topology discovery) run
inside the single app process with no leader election. **Do not run
multiple replicas/workers** with cloud sync enabled — every replica would
pull and ingest independently. Config changes made via the API propagate
to the running loops in the same process only.

### Cost expectations

- Flow pulls use CloudWatch Logs Insights, billed per GB scanned per
  query. At the default 300s interval that is 288 queries/day/region —
  scope `log_group_name` narrowly and prefer longer intervals on busy log
  groups. (An S3-based flow-log path is not yet implemented; S3 delivery
  is roughly half the CloudWatch ingestion price if cost becomes an issue.)
- Traffic metrics use batched `GetMetricData` (up to 500 series per call),
  so API-call cost stays low even with hundreds of `resource_ids`.
- Topology discovery uses free describe/list APIs; the scheduled refresh
  (`PUT /api/cloud/discovery-sync/config`, default hourly when enabled)
  costs nothing on the provider side.
- Local growth is bounded: cloud flow records share the NetFlow 48h
  retention (pruned by the cloud loop itself) and cloud traffic metrics
  default to 7-day retention. See DATA_RETENTION.md.

## Process supervision (non-Docker)

When running directly from a venv on a server, supervise the process with
`systemd` so it restarts on crash. A minimal unit:

```ini
[Unit]
Description=Plexus Network Automation Hub
After=network.target

[Service]
Type=simple
User=plexus
WorkingDirectory=/opt/plexus
EnvironmentFile=/opt/plexus/.env
ExecStart=/opt/plexus/.venv/bin/python templates/run.py --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The flow collector runs inside the same process - there's no separate
daemon to supervise.
