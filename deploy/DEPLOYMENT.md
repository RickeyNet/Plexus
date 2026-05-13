# Ubuntu UFW Firewall Rules

Reference ruleset for a Plexus host running the Docker stack
(`docker-compose.yml`: nginx 80/443, app 8080, NetFlow 2055/udp, sFlow
6343/udp, SNMP traps 162/udp, syslog 1514/udp). Substitute the placeholder
variables at the top for your environment, then run the block as `root`.

> **Important - Docker + UFW interaction**
> Docker bypasses UFW's `INPUT` chain by writing its own `iptables` rules
> in the `DOCKER-USER` chain. Plain `ufw allow` rules will appear to work
> against host services but **will not filter traffic to published
> container ports** unless you either (a) run with
> `DOCKER_OPTS="--iptables=false"` (not recommended), or (b) bind
> Plexus's published ports to `127.0.0.1` and let nginx (also published)
> be the only externally reachable container. The rules below assume the
> stack is unchanged from `docker-compose.yml` and that you also add the
> `DOCKER-USER` rules in the **"Hardening Docker-published ports"**
> section at the bottom - that is what actually enforces source-IP
> restrictions on 2055/6343/162/1514/8080.

## 1. Define your networks

```bash
# --- Edit these to match your environment, then paste into a root shell ---
ADMIN_NET="10.0.0.0/24"          # Operators / web UI users (HTTPS, SSH)
USER_NET="10.10.0.0/16"          # Read-only / regular UI users (HTTPS only)
DEVICE_NET="10.20.0.0/16"        # Managed network devices (telemetry sources, SSH/SNMP targets)
NETFLOW_EXPORTERS="10.20.0.0/16" # Routers/switches sending NetFlow v5/v9/IPFIX
SFLOW_EXPORTERS="10.20.0.0/16"   # Switches sending sFlow
SYSLOG_SOURCES="10.20.0.0/16"    # Devices sending syslog
SNMP_TRAP_SOURCES="10.20.0.0/16" # Devices sending SNMP traps
DNS_SERVER="10.0.0.53"           # Internal DNS used by Plexus
NTP_SERVER="10.0.0.123"          # Internal NTP used by Plexus
# Federation peers (optional - leave empty if unused)
FEDERATION_PEERS=""              # e.g. "10.30.0.10 10.30.0.11"
```

## 2. Reset and set defaults

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing      # outbound is broadly permitted; tighten further below if desired
sudo ufw logging medium
```

## 3. Inbound - management plane (TCP)

```bash
# SSH from operators only
sudo ufw allow from "$ADMIN_NET" to any port 22 proto tcp comment 'SSH (admin)'

# HTTPS web UI
sudo ufw allow from "$ADMIN_NET" to any port 443 proto tcp comment 'Plexus UI (admin)'
sudo ufw allow from "$USER_NET"  to any port 443 proto tcp comment 'Plexus UI (users)'

# HTTP -> HTTPS redirect (nginx 80). Open to the same audiences as 443.
sudo ufw allow from "$ADMIN_NET" to any port 80 proto tcp comment 'HTTP redirect (admin)'
sudo ufw allow from "$USER_NET"  to any port 80 proto tcp comment 'HTTP redirect (users)'

# Direct app port 8080: leave CLOSED externally. nginx in the same compose
# network reaches it container-to-container. Only open if you skip nginx:
# sudo ufw allow from "$ADMIN_NET" to any port 8080 proto tcp comment 'Plexus app direct (no nginx)'
```

## 4. Inbound - telemetry plane (UDP)

```bash
# NetFlow v5 / v9 / IPFIX
sudo ufw allow from "$NETFLOW_EXPORTERS" to any port 2055 proto udp comment 'NetFlow'

# sFlow
sudo ufw allow from "$SFLOW_EXPORTERS"   to any port 6343 proto udp comment 'sFlow'

# SNMP traps
sudo ufw allow from "$SNMP_TRAP_SOURCES" to any port 162  proto udp comment 'SNMP traps'

# Syslog (Plexus listens on 1514/udp - UFW lets you also publish 514 if you
# add an iptables NAT redirect; keep 1514 by default).
sudo ufw allow from "$SYSLOG_SOURCES"    to any port 1514 proto udp comment 'Syslog'
```

## 5. Inbound - federation (optional)

```bash
# If you have peer Plexus instances pulling/pushing federation data,
# expose 443 to those peers explicitly (already covered if peers live
# inside ADMIN_NET / USER_NET). Otherwise:
for peer in $FEDERATION_PEERS; do
  sudo ufw allow from "$peer" to any port 443 proto tcp comment "Federation peer $peer"
done
```

## 6. Inbound - ICMP

```bash
# Allow echo-request from admin + monitored device subnets so availability
# checks and operator pings work. UFW's default profile already permits
# most ICMP types in /etc/ufw/before.rules; this is belt-and-suspenders.
sudo ufw allow proto icmp from "$ADMIN_NET"  comment 'ICMP from admin'
sudo ufw allow proto icmp from "$DEVICE_NET" comment 'ICMP from devices'
```

## 7. Outbound - to managed devices

UFW's default `allow outgoing` already permits this; the rules below
are for environments that switch outgoing to `deny` for hardening.

```bash
# Uncomment if outgoing is set to deny:
# sudo ufw default deny outgoing

# SSH / SCP / NETCONF-over-SSH to devices
# sudo ufw allow out to "$DEVICE_NET" port 22  proto tcp comment 'SSH to devices'
# sudo ufw allow out to "$DEVICE_NET" port 830 proto tcp comment 'NETCONF to devices'

# Telnet - only if your fleet still requires it
# sudo ufw allow out to "$DEVICE_NET" port 23  proto tcp comment 'Telnet to devices'

# REST APIs on devices (Cisco DNAC, Meraki, Arista eAPI, FortiGate, etc.)
# sudo ufw allow out to "$DEVICE_NET" port 80  proto tcp comment 'HTTP REST to devices'
# sudo ufw allow out to "$DEVICE_NET" port 443 proto tcp comment 'HTTPS REST to devices'

# SNMP polling
# sudo ufw allow out to "$DEVICE_NET" port 161 proto udp comment 'SNMP poll'

# ICMP availability checks
# sudo ufw allow out proto icmp to "$DEVICE_NET" comment 'Ping devices'

# DNS + NTP
# sudo ufw allow out to "$DNS_SERVER" port 53  proto udp comment 'DNS'
# sudo ufw allow out to "$DNS_SERVER" port 53  proto tcp comment 'DNS (TCP fallback)'
# sudo ufw allow out to "$NTP_SERVER" port 123 proto udp comment 'NTP'

# DHCP visibility (IPAM): if Plexus queries DHCP servers via API, allow that.
# DHCP discovery (67/68) is rarely needed since IPAM uses vendor APIs.

# Postgres - only relevant if DB runs OUTSIDE the compose network
# sudo ufw allow out to <DB_HOST_IP>/32 port 5432 proto tcp comment 'Postgres'
```

## 8. Enable and verify

```bash
sudo ufw --force enable
sudo ufw status numbered verbose
```

## 9. Hardening Docker-published ports (required for source-IP enforcement)

`ufw` rules above filter traffic to host services, but Docker installs
its own NAT rules that bypass `ufw` for any port published in
`docker-compose.yml`. Add explicit `DOCKER-USER` rules so the
source-IP restrictions are actually enforced for the published
container ports (2055, 6343, 162, 1514, 80, 443, 8080):

```bash
# Run as root. These rules are NOT persisted by UFW - install
# `iptables-persistent` (Ubuntu) and run `netfilter-persistent save` to
# survive reboots, or wire them into a systemd unit.

sudo apt-get install -y iptables-persistent

# Allow established/related first
sudo iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# Telemetry: restrict to declared exporter/source subnets
sudo iptables -I DOCKER-USER -p udp --dport 2055 -s "$NETFLOW_EXPORTERS" -j RETURN
sudo iptables -I DOCKER-USER -p udp --dport 6343 -s "$SFLOW_EXPORTERS"   -j RETURN
sudo iptables -I DOCKER-USER -p udp --dport 162  -s "$SNMP_TRAP_SOURCES" -j RETURN
sudo iptables -I DOCKER-USER -p udp --dport 1514 -s "$SYSLOG_SOURCES"    -j RETURN

# Web UI: admin + user networks only
sudo iptables -I DOCKER-USER -p tcp --dport 443  -s "$ADMIN_NET" -j RETURN
sudo iptables -I DOCKER-USER -p tcp --dport 443  -s "$USER_NET"  -j RETURN
sudo iptables -I DOCKER-USER -p tcp --dport 80   -s "$ADMIN_NET" -j RETURN
sudo iptables -I DOCKER-USER -p tcp --dport 80   -s "$USER_NET"  -j RETURN

# Direct app port 8080 - keep blocked from outside; comment if needed.
sudo iptables -I DOCKER-USER -p tcp --dport 8080 -s "$ADMIN_NET" -j RETURN

# Drop everything else destined for the published container ports
sudo iptables -A DOCKER-USER -p udp --dport 2055 -j DROP
sudo iptables -A DOCKER-USER -p udp --dport 6343 -j DROP
sudo iptables -A DOCKER-USER -p udp --dport 162  -j DROP
sudo iptables -A DOCKER-USER -p udp --dport 1514 -j DROP
sudo iptables -A DOCKER-USER -p tcp --dport 443  -j DROP
sudo iptables -A DOCKER-USER -p tcp --dport 80   -j DROP
sudo iptables -A DOCKER-USER -p tcp --dport 8080 -j DROP

# Persist
sudo netfilter-persistent save
```

Verify with `sudo iptables -L DOCKER-USER -n -v --line-numbers`.

## 10. Optional - disable Plexus features by closing ports

If you do not use a given collector, simply omit its `ufw allow` and
`DOCKER-USER` rules and remove the port mapping from
`docker-compose.yml` so the listener is not started.

---

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
| `APP_HTTPS`                | `true`           | Tells app to set secure cookie flags |
| `APP_HSTS`                 | `true`           | Enable HSTS header                 |
| `APP_CORS_ORIGINS`         | (set by setup)   | Allowed browser origins            |
| `APP_REQUIRE_API_TOKEN`    | `true`           | Require token for API access       |
| `APP_API_TOKEN`            | (auto-generated) | Token for API/automation access    |
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
git pull  # fetch and merge the latest commits from the remote
docker compose up -d --build  # rebuild images with new code and restart containers
```

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
