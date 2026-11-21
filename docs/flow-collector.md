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
# the exporters' interfaces by traffic (index, name when known, bytes in/out)
curl "http://localhost:8080/api/flows/top-interfaces?hours=1&host_id=12"
```

### Exporters and inventory hosts

Each exporter is matched to an inventory host by the source address of its
packets: the host's primary address, else an interface address recorded
for a host (by the SNMP discovery, a collected configuration, or an
OPNsense collection). A device often exports from the interface that
routes to the collector rather than from its inventory address; once that
interface's address is recorded, its flows land on the device. A primary
address always wins over a recorded interface address of another host.
The match is cached in memory (no database read per packet) and refreshed
when hosts change, after an OPNsense collection and every aggregation
cycle (hourly); exporters already listed are relinked then. Each writer
replaces a host's recorded interface addresses as a whole, so a discovery
sync or configuration collection of a host an OPNsense collection also
records can drop the collection's addresses until the next collection
(hourly by default) writes them again.

### Interface names

Flow records name interfaces by number (`input_if`, `output_if`: the SNMP
ifIndex on most devices, the kernel interface index on OPNsense). The
**Interfaces** tab of a device's **Flow** view and
`GET /api/flows/top-interfaces` rank the device's interfaces by the
traffic that entered (`in_bytes`) and left (`out_bytes`) on them, with the
index and its name (`if_name`, `if_device`) when Plexus knows it: from the
interfaces SNMP polling records for the host, or from an OPNsense
collection. Without a name the index is shown alone. Index 0 is no
interface: traffic the device itself sent, or a flow it had no route for.
The AI tool `get_top_talkers` ranks the same with kind `interfaces`.

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

### OPNsense firewalls

OPNsense exports NetFlow from **Reporting > NetFlow** (the kernel's
`ng_netflow`, forwarded by `samplicate`). Set:

- **Listening interfaces**: the interfaces to account (usually all of them).
- **NAT interfaces** (egress only): the WAN interfaces that do source NAT,
  so their traffic is recorded from the inside (before source NAT, after
  destination NAT) and keeps the internal host addresses. Without it a
  flow through NAT is counted on both sides.
- **Version**: `v9` (v5 has no IPv6).
- **Destinations**: the Plexus collector, `<collector address>:2055` (the
  NetFlow port of `Settings > NetFlow`), and press Enter to add it.
- **Capture local** is only for OPNsense's own Insight graphs and does not
  matter to Plexus.

Allow UDP 2055 from the firewall to Plexus. The firewall sends from the
address of the interface that routes to the collector. Import the firewall
into the inventory and collect it as a topology source (see
[OPNsense in the Topology Map](opnsense-topology.md#netflow)): the
collection records its interface addresses, so those flows are attributed
to it, and its interface index names, so the **Interfaces** view shows
`WAN (igb0)` or `LAN (igb1)`. Only interfaces with an address get a name
(the index is read from the connected route of the interface); the
firewall's **Flow export** section says whether flows arrive. Traffic the
firewall itself sends has input interface 0.

### Limits on what exporters send

The listeners accept UDP from any source, so the NetFlow v9 / IPFIX decoder
caps what one packet can cost:

- A template is ignored when it has a zero-length field, more than 128
  fields, a record shorter than 4 bytes or is cut short. Real exporters send
  templates of tens of fields.
- At most 32 templates per exporter and 1024 exporters are kept (the least
  recently used are dropped; an exporter resends its templates periodically).
  The sFlow sampling rates kept are bounded the same way (1024 sources per
  exporter).
- At most 1024 flow records are decoded from one packet; exporters send
  MTU-sized packets of a few dozen records.


- Raw flow records: 48 hours (configurable via `retention_hours`).
- Hourly aggregated summaries: 30 days (configurable via
  `summary_retention_days`).

Aggregation runs hourly. See `DATA_RETENTION.md` for details.
