# NetFlow / sFlow / IPFIX

Plexus includes a UDP flow collector that ingests NetFlow v5, NetFlow v9,
IPFIX, and sFlow v5 records from switches and routers, then aggregates them
into top-talkers / top-applications / top-conversations / timeline views
under `Traffic Analysis` (also visible per-device on the Device Detail page's
`Flow` tab).

### Ports

| Protocol             | Default UDP port | Setting                |
|----------------------|------------------|------------------------|
| NetFlow v5/v9/IPFIX  | `2055`           | `APP_NETFLOW_PORT`     |
| sFlow v5             | `6343`           | `APP_SFLOW_PORT`       |

Both listeners bind to `0.0.0.0` so any device on the management network can
export to them. The collector is **off by default**; turn it on via
`APP_NETFLOW_ENABLED=true` in `.env` (first boot only - after that the toggle
lives in `Settings > NetFlow` in the UI).

### Enabling the collector

In the UI: `Settings > NetFlow`. Toggle `Enabled`, optionally change the
ports/retention, and click `Save`. Changes apply immediately - the UDP
listeners are rebound in-process, no restart required.

From the API:

```bash
# read current config
curl http://localhost:8080/api/admin/flows/config

# update - rebinds listeners only when enabled/ports actually change
curl -X PUT http://localhost:8080/api/admin/flows/config \
  -H "Content-Type: application/json" \
  -d '{
        "enabled": true,
        "netflow_port": 2055,
        "sflow_port": 6343,
        "retention_hours": 48,
        "summary_retention_days": 30
      }'

# status / who's exporting
curl http://localhost:8080/api/flows/status
curl http://localhost:8080/api/flows/exporters
```

### Configuring exporters on devices

The `Enable NetFlow Export` playbook (`templates/playbooks/netflow_enable.py`)
pushes platform-appropriate exporter config to selected hosts:

- **Cisco IOS** (`cisco_ios`) - classic `ip flow-export destination` plus
  per-interface `ip flow ingress/egress`.
- **Cisco IOS-XE** (`cisco_xe`) - Flexible NetFlow (`flow record` / `flow
  exporter` / `flow monitor`) with an optional `sampler` block.
- **Cisco NX-OS** (`cisco_nxos`, `cisco_nxos_ssh`) - same Flex shape with
  NX-OS syntax plus a leading `feature netflow`.

The collector destination IP resolves in priority order:

1. The job parameters `collector_ip` / `collector_port`.
2. The `PLEXUS_COLLECTOR_IP` env var + `APP_NETFLOW_PORT` env var.

If no collector IP is found the playbook fails fast with an error rather than
silently pointing devices at the wrong address. Run with `dry_run=true` first
to see the exact config lines that would be applied; live mode runs `show
running-config | include flow|ip flow-export` to capture state, applies via
`send_config_set`, verifies, and `save_config`s on success.

If you're running Plexus in Docker, devices need to reach the **host** IP on
UDP 2055/6343 - not the container IP. Make sure the host firewall allows
inbound UDP on those ports; see `deploy/FIREWALL.md`.

### Retention

- Raw flow records: 48 hours (configurable via `retention_hours`).
- Hourly aggregated summaries: 30 days (configurable via
  `summary_retention_days`).

Aggregation runs hourly. See `DATA_RETENTION.md` for details.
