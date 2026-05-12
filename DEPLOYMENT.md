# Plexus — Deployment Notes

Operational notes for running Plexus in production. This document covers
the host-level configuration that doesn't fit cleanly in the README's
"Running with Docker" section: firewalls, persistent storage paths, and
process supervision.

## Firewall rules

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
routers live in — opening UDP 2055 / 6343 to the whole internet is
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
rules out — but adding them now and toggling the collector on later is
fine; idle UDP rules cost nothing.

### Docker (DOCKER-USER chain)

When Plexus runs inside Docker, port publishes in `docker-compose.yml` /
`docker run -p ...` create `DOCKER` iptables rules that bypass your normal
`INPUT` chain. To filter what's allowed to reach the container, add rules
to the `DOCKER-USER` chain instead — Docker runs that chain before
`DOCKER` so anything you drop there never reaches the container.

```bash
# Allow the management subnet to reach the published ports.
# Replace eth0 with your real external interface.
sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -I DOCKER-USER -i eth0 -p udp --dport 2055 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -I DOCKER-USER -i eth0 -p udp --dport 6343 -s 10.0.0.0/8 -j ACCEPT

# Drop everything else inbound on the same ports — order matters,
# this must come AFTER the ACCEPT rules above.
sudo iptables -A DOCKER-USER -i eth0 -p tcp --dport 8080 -j DROP
sudo iptables -A DOCKER-USER -i eth0 -p udp --dport 2055 -j DROP
sudo iptables -A DOCKER-USER -i eth0 -p udp --dport 6343 -j DROP
```

These rules don't survive a reboot on their own — persist them via
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

The `/udp` suffix is required — without it Docker only publishes the TCP
half of the port and the flow collector won't see any packets.

### Verifying flows are arriving

After enabling the collector and pushing exporter config to a device:

```bash
# from the Plexus host — should show flow_collector listening
sudo ss -lunp | grep -E ':(2055|6343)\b'

# from the device side — confirm it's actually exporting
# (NetFlow on a Cisco IOS-XE box, for example)
show flow exporter PLEXUS-EXPORT statistics

# or hit the Plexus API
curl http://localhost:8080/api/flows/exporters
```

The `/api/flows/exporters` response includes `packets_received` per
exporter; if that's zero after a few minutes, the packets aren't reaching
the listener — check the firewall path (host firewall → DOCKER-USER →
container) before suspecting Plexus.

## Persistent state (Docker)

The compose file maps two named volumes:

- `/app/state` — SQLite DB (`netcontrol.db`) and the Fernet key
  (`netcontrol.key`). **Back this up.** Losing the key file means every
  stored credential is unrecoverable.
- `/app/certs` — TLS certificates when running with `--https`.

For PostgreSQL deployments, the SQLite file isn't used but the Fernet key
still lives in `/app/state`.

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

The flow collector runs inside the same process — there's no separate
daemon to supervise.
