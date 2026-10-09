# Ubuntu UFW Firewall Rules

Sections 1-10 are the full reference ruleset. The final section,
"Quick rules and flow verification", is a shorter version of the same
rules plus steps to confirm flow packets are reaching the collector.

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
> section (section 9) - that is what actually enforces source-IP
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

## Quick rules and flow verification

Plexus's HTTP / WebSocket endpoint runs on TCP `8080` by default (or `8443`
with `--https`). In addition, when the flow collector is enabled it binds
two UDP listeners that devices need to reach directly:

| Protocol             | UDP port | Setting               |
|----------------------|----------|-----------------------|
| NetFlow v5 / v9      | `2055`   | `APP_NETFLOW_PORT`    |
| IPFIX                | `2055`   | (same listener as v9) |
| sFlow v5             | `6343`   | `APP_SFLOW_PORT`      |

Both UDP listeners bind to `0.0.0.0`. If you change `APP_NETFLOW_PORT` /
`APP_SFLOW_PORT` from the defaults, substitute your own values below.

### UFW (Ubuntu / Debian host)

Allow the HTTP UI and the two flow collector ports from your management
network. Tighten the source range to whatever subnet your switches and
routers live in - opening UDP 2055 / 6343 to the whole internet is
pointless (and a small DoS amplifier).

```bash
# HTTP UI (or 8443 if you run with --https)
sudo ufw allow proto tcp from 10.0.0.0/8 to any port 8080 comment 'plexus ui'

# NetFlow v5 / v9 / IPFIX
sudo ufw allow proto udp from 10.0.0.0/8 to any port 2055 comment 'plexus netflow'

# sFlow v5
sudo ufw allow proto udp from 10.0.0.0/8 to any port 6343 comment 'plexus sflow'

sudo ufw reload
sudo ufw status numbered
```

If the collector is disabled (the default), you can leave the two UDP
rules out - but adding them now and toggling the collector on later is
fine; idle UDP rules cost nothing.

### Docker (DOCKER-USER chain)

When Plexus runs inside Docker, port publishes in `docker-compose.yml` /
`docker run -p ...` create `DOCKER` iptables rules that bypass your normal
`INPUT` chain. To filter what's allowed to reach the container, add rules
to the `DOCKER-USER` chain instead - Docker runs that chain before
`DOCKER` so anything you drop there never reaches the container.

```bash
# Allow the management subnet to reach the published ports.
# Replace eth0 with your real external interface.
sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -I DOCKER-USER -i eth0 -p udp --dport 2055 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -I DOCKER-USER -i eth0 -p udp --dport 6343 -s 10.0.0.0/8 -j ACCEPT

# Drop everything else inbound on the same ports - order matters,
# this must come AFTER the ACCEPT rules above.
sudo iptables -A DOCKER-USER -i eth0 -p tcp --dport 8080 -j DROP
sudo iptables -A DOCKER-USER -i eth0 -p udp --dport 2055 -j DROP
sudo iptables -A DOCKER-USER -i eth0 -p udp --dport 6343 -j DROP
```

These rules don't survive a reboot on their own - persist them via
`iptables-save > /etc/iptables/rules.v4` (Debian/Ubuntu `iptables-persistent`
package) or your distro's equivalent.

You also need the UDP ports published from the container. In
`docker-compose.yml`:

```yaml
services:
  plexus:
    ports:
      - "8080:8080"            # UI / API
      - "2055:2055/udp"        # NetFlow
      - "6343:6343/udp"        # sFlow
```

The `/udp` suffix is required - without it Docker only publishes the TCP
half of the port and the flow collector won't see any packets.

### Verifying flows are arriving

After enabling the collector and pushing exporter config to a device:

```bash
# from the Plexus host - should show flow_collector listening
sudo ss -lunp | grep -E ':(2055|6343)\b'

# from the device side - confirm it's actually exporting
# (NetFlow on a Cisco IOS-XE box, for example)
show flow exporter PLEXUS-EXPORT statistics

# or hit the Plexus API
curl http://localhost:8080/api/flows/exporters
```

The `/api/flows/exporters` response includes `packets_received` per
exporter; if that's zero after a few minutes, the packets aren't reaching
the listener - check the firewall path (host firewall → DOCKER-USER →
container) before suspecting Plexus.
