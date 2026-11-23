# Vendor monitoring coverage

The standard every vendor is held to is the "Vendor Monitoring Parity Standard"
section of `AGENTS.md`: one availability/SLA pipeline and one software/CVE
pipeline, fed the same way for every supported vendor, with Cisco, Cato, AWS
and Azure as the priority set. This page is the per-vendor state of that
standard. A row must never claim coverage the code does not have; update it in
the same change that adds or removes a capability.

Legend: **Yes** = implemented and tested. **Partial** = some entities or
metrics only (the cell says which). **Manual** = works only with hand-entered
or imported data. **No** = not implemented.

## Availability and SLA

Inventory hosts (anything added to Inventory, polled by SNMP/SSH/ICMP) go
through the poll pipeline in `netcontrol/routes/monitoring.py`: per-poll
availability transitions, uptime %, latency, jitter, packet loss, MTTR/MTTD,
hourly and daily rollups in `sla_metrics`, and SLA targets evaluated on the
server into `monitoring_alerts` and notification channels. API-collected
entities go through the topology availability tracker
(`netcontrol/integrations/availability.py`,
`routes/db/topology_availability.py`), which diffs every stored snapshot
against the last known state, persists transitions, computes time-weighted
uptime % and alerts on down/degraded. It also stores the latency, jitter and
loss a vendor reports for an entity, and the traffic rate (bits per second
in / out) of an entity whose vendor reports byte counters, computed between
two readings (stored collections and, for an OPNsense firewall in the inventory, its monitoring polls; `netcontrol/integrations/traffic.py`; raw samples
plus daily rollups kept for the SLA retention), and SLA targets with a `provider` are evaluated on the
server in the scheduled SLA pass for the tracked entities they cover
(uptime for every entity; latency, jitter and loss where the vendor reports
them) into `monitoring_alerts` / notification channels
(`netcontrol/routes/topology_sla.py`, `docs/sla-monitoring.md`).

| Vendor / source | Entities tracked | State source | Latency / loss / jitter | SLA targets | Notes |
|---|---|---|---|---|---|
| Cisco IOS / IOS XE / IOS XR / NX-OS / ASA (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. |
| Cisco FTD via FDM REST | host, interfaces | FDM API poll into the same pipeline | Partial (ICMP if reachable) | Yes | `netcontrol/integrations/cisco_fdm`. |
| Cisco FTD / ASA via FMC | FTDs; uplinks, site-to-site tunnels, HA and cluster links | FMC snapshot status, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Full pipeline when the FTD is an inventory host. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as `cisco_ftd` hosts polled over SNMP. Gap: an HA pair's link is tracked up / down, but a role swap (active / standby failover) raises no failover alert, unlike an OPNsense CARP group. |
| Cisco Meraki | devices (MX/MS/MR/MG/MV/MT); uplinks, AutoVPN and IPsec tunnels | `devices/statuses`, `uplinks/statuses`, `appliance/vpn/statuses` in the org snapshot, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | Loss and latency per MX uplink (`devices/uplinksLossAndLatency`): each collection reads the five-minute windows since the newest stored sample (up to 6 hours, one org call per window), one sample per uplink and window; no jitter (Meraki reports none, none derived) | Uptime, latency and packet loss (topology SLA targets, evaluated server-side) | `docs/meraki-topology.md#uplink-loss-and-latency`. Optional (`include_uplink_metrics`, on by default); a refused call is one collection warning. A source collected less often than every 6 hours keeps a gap before each read. Response shape checked against the Dashboard API reference, not a live organization. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts (ping latency, loss and SLA targets on the LAN address). Near-real-time alerts as well: assurance alerts polled every 60 s and an optional webhook receiver, persisted in `meraki_alerts` and raised server-side into `monitoring_alerts` / notification channels (`docs/meraki-alerts.md`). They alert; they do not feed the availability history or uptime %. |
| Cato Networks | sites, Sockets and IPsec sites; Socket uplinks, tunnels | `accountSnapshot` connectivityStatus / operationalStatus / tunnel state, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | RTT, jitter and loss per Socket WAN link (`accountMetrics`): each collection reads the five-minute buckets since the newest stored sample (up to 6 hours, one query per 50 sites); jitter and loss are the worse of Cato's upstream and downstream values | Uptime, latency, jitter and packet loss (topology SLA targets, evaluated server-side) | `docs/cato-topology.md#wan-link-rtt-jitter-and-loss`. Optional (`include_link_metrics`, on by default); a refused query is one collection warning. An HA pair is one in `accountMetrics` (filed under the primary Socket's links); IPsec sites get no measurement. Not checked against a live account: link matching by interface id, else name. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts, when the Socket reports a LAN address. |
| AWS | instances, Transit Gateways, NAT and Direct Connect gateways; site-to-site VPN connections, Direct Connect circuits, VPC peerings, TGW/VGW attachments; managed services (RDS / Aurora instances, clusters and proxies, load balancers, VPC endpoints, EFS, ElastiCache, OpenSearch, MSK, Redshift and Redshift Serverless) | resource state fields in the account discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | AWS Health, CloudWatch alarms and EC2 status checks are read as alerts every 5 minutes (`docs/cloud-alerts.md`, see Vendor alert feeds below); they alert, they do not change the tracked state or uptime. Managed services are tracked as `service` entities by their state (`docs/meraki-topology.md#cloud-managed-services`); Classic Load Balancers report none and are not tracked. Amazon FSx file systems and ONTAP SVMs: state collected and shown in the VPC details, not tracked (gap: they are no service records yet). |
| Azure | VMs, VPN gateways, firewalls, NAT gateways; VPN connections, ExpressRoute circuits, VNet peerings, gateway attachments; managed services (load balancers, application gateways, private endpoints) | provisioning / connection state fields in the account discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | Resource Health (Unavailable / Degraded) and fired Azure Monitor alerts (including Service Health and Resource Health alert rules) are read as alerts every 5 minutes (`docs/cloud-alerts.md`, see Vendor alert feeds below); they alert, they do not change the tracked state or uptime. Load balancers (provisioning state), application gateways (operational state) and private endpoints (provisioning and connection state): collected (each optional), shown in the VNet details and tracked as `service` entities (`docs/meraki-topology.md#cloud-managed-services`). |
| GCP | instances, Cloud Routers, HA VPN gateways, Cloud NAT, Interconnects; HA VPN tunnels, Interconnect attachments, VPC peerings; managed services (load balancers, Private Service Connect endpoints and service attachments, Cloud SQL instances, Memorystore for Redis instances) | state fields in the project discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | Load balancers (forwarding rules), Private Service Connect endpoints (connection status) and service attachments: collected (each optional), shown in the network details and tracked as `service` entities (`docs/meraki-topology.md#cloud-managed-services`). A load balancer and a service attachment have no state of their own: up while they exist unless a `backend_health` on the record says otherwise. Backend health (`backendServices.getHealth` / `regionBackendServices.getHealth`, optional section `backend_health`, at most 200 calls per discovery) is collected onto the load balancer record as `backend_health` (healthy / unhealthy / unknown) with `backend_health_groups`; target pool health is not read (gap). Cloud SQL instances (state RUNNABLE, SUSPENDED...) and Memorystore for Redis instances (state READY...) are collected (optional sections `cloud_sql_instances`, `memorystore_redis_instances`, through their own APIs) with the provider state as `status`. |
| Palo Alto via Panorama | managed firewalls; uplinks, tunnels, HA links | Panorama snapshot status, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Full pipeline when the firewall is an inventory host. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as `paloalto_panos` hosts polled over SNMP. Gap: an HA pair's link is tracked up / down, but a role swap (active / standby failover) raises no failover alert, unlike an OPNsense CARP group. |
| Appgate SDP | appliances, sites; appliance peer links | `/appliances/status` health, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts. |
| OPNsense | the firewall, OpenVPN server instances; gateways (as uplinks), IPsec connections, WireGuard peers and OpenVPN client instances (as tunnels); CARP groups, one per interface and VHID (as links); the services the configuration enables (as services); the certificates in use and the CAs they depend on (as certificates) | `routes/gateway/status` (dpinger: `none` with monitor data up, `delay` / `loss` / `delay+loss` degraded, `down` / `force_down` down, no monitor data unknown), `ipsec/sessions/search_phase1` (SA or not) with `search_phase2` / `connections/search_child` (an SA whose configured child SAs are none installed: degraded), `wireguard/service/show` (`peer-status` online / stale / offline, else handshake age), `openvpn/service/search_sessions` (client state; server running or not), `diagnostics/interface/get_vip_status` (CARP role: MASTER / BACKUP up, DISABLED degraded, INIT down, MASTER / BACKUP degraded while demoted or in maintenance mode; a MASTER / BACKUP role change raises a failover warning), `core/service/search` (an enabled service that does not run is down; a service turned off is not listed, so its entity is removed and its alert resolved), `trust/cert/search` / `trust/ca/search` (24.7+; `config.xml` on older releases: a certificate's expiry tier, valid up, expiring / critical / expired degraded, never down; alerts per tier, see Certificate expiry below), recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | Gateways: Yes (dpinger RTT as latency, RTT deviation as jitter, loss; stored per collection, raw for the monitoring retention and daily rollups for the SLA retention). Tunnels (IPsec connections, WireGuard peers, OpenVPN client instances) and OpenVPN servers: traffic in / out in bits per second, averaged between two readings of the byte counters (IPsec child SA `bytes-in` / `bytes-out`, WireGuard `transfer-rx` / `transfer-tx`, OpenVPN `bytes_received` / `bytes_sent`): every collection and, when the firewall is an inventory host, every monitoring poll (same API session as the health), against the last reading kept in `topology_traffic_counters`; no sample on a first reading, a counter reset, a rekeyed child SA or ended session (one poll interval lost), or a gap over three hours; stored the same way. Gap: a firewall that is not an inventory host is read by its hourly collections only, so its IPsec tunnels (child SAs rekeyed about hourly) rarely get a sample. No latency or loss for tunnels | Yes (topology SLA targets: uptime for every entity, latency / jitter / packet loss for gateways) | CARP VIPs (`diagnostics/interface/get_vip_status`) are shown in the firewall's details and tracked per CARP group; a VIP in INIT or a non-zero demotion is also an informational collection warning. Two sources sharing a VHID and virtual address are drawn as one HA cluster whose link status is display only (no pair-level split-brain alert: the two collections are not simultaneous). Full pipeline when the firewall is an inventory host. The firewall can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`), as an `opnsense` host polled over SNMP (no SSH driver). The ARP / NDP tables feed MAC tracking (the inventory host's ARP table) and the DHCP leases (ISC, Kea, Dnsmasq) feed IPAM as an `opnsense` DHCP server; neither is an availability entity. Health over the API, no SNMP profile needed (CPU from `top`'s CPU line, memory without the ZFS ARC, file systems, temperature, state table, uptime, load): shown in the firewall's details at every collection; for an inventory host also read at every monitoring poll (six calls, not the services) into the poll's CPU / memory / uptime (only where SNMP left them empty) and the `fw_*` metric samples, with built-in alerts for a file system at 90 % and a state table at 80 % of its limit, resolved when they clear (`docs/opnsense-topology.md#health-and-services`). Gaps: a firewall that is no inventory host keeps no health history (only collection warnings for a full disk or state table); no swap, mbuf or per-core CPU; health answer shapes checked against the OPNsense source only, not a live firewall. `docs/opnsense-topology.md`. |
| Juniper / Arista / Fortinet / PAN-OS (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. |
| HPE Aruba AOS-CX / AOS-Switch (HP ProCurve) (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. CPU and memory: HP `STATISTICS-MIB` / `NETSWITCH-MIB` on AOS-Switch, HOST-RESOURCES-MIB on AOS-CX. `docs/aruba-switches.md`. |
| HPE Aruba Instant On 1830 / 1930 / 1960 (inventory) | host, interfaces | SNMP + ICMP poll (`aruba_instant_on`, no SSH: the switch has no command line) | Yes (ICMP) | Yes | Full pipeline over SNMP. The switch answers SNMP only in local management mode (v1/v2c read-only on the 1830); a cloud-managed one is ICMP only. CPU and memory only when it answers HOST-RESOURCES-MIB. |
| Netgear managed switches (M4250 / M4300 / M4350 / M4500) (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. CPU and memory only when the switch answers HOST-RESOURCES-MIB (no built-in vendor OIDs: gap). Not run against a device yet. `docs/netgear.md`. |
| Netgear smart switches and access points (inventory) | host, interfaces | SNMP + ICMP poll (`netgear_smart`, `netgear_ap`, no SSH: no command line) | Yes (ICMP) | Yes | Full pipeline over SNMP. An access point answers SNMP only when it is enabled in standalone mode; one that offers none is ICMP only. No wireless client or radio data. |
| APC Smart-UPS through a Network Management Card (inventory) | host (the card's interface), UPS battery and output state | SNMP + ICMP poll (`apc_ups`, no SSH driver: the card's command line is used only by the Upgrades tool); PowerNet-MIB battery status, capacity, runtime, replace indicator, temperature, output status, load and voltage, input voltage and frequency, last transfer cause, and the card's temperature probe; plus the card's SNMP traps (v1 / v2c, decoded on arrival) | Yes (ICMP) | Yes | Full pipeline over SNMP. The UPS state is stored per host (`host_vendor_status`), kept as metric samples with hourly / daily rollups, and raises server-side alerts into `monitoring_alerts` / notification channels: on battery, battery low / fault / not present / needs replacing, output off or on bypass, overload, battery temperature (warning 40 °C, critical 50 °C), each resolved when it clears (`netcontrol/integrations/apc/snmp.py`). Traps: Yes. A PowerNet-MIB trap from an `apc_ups` host raises or resolves the same alerts at once (same dedup keys as the poll; communication lost / established too) and triggers an immediate re-poll of the host (`netcontrol/integrations/apc/traps.py`). No CPU or memory (none to read). A trap is acted on only with the community stored for the host and from the host's own address (the v1 agent address only through an inventory source); SNMPv3 traps are stored undecoded and never acted on. Gaps: SNMPv3 traps are not authenticated (no trap user keys); outlet groups, humidity and the per-module tables of a parallel / three-phase UPS are not read. `docs/apc-ups.md`. |
| ICMP-only hosts | host | ICMP | Yes | Yes | |

Firewall rule posture: only OPNsense is checked today. A new config.xml
backup (stored by a collection, or by a config backup policy run, which
downloads config.xml over the source's API key with no SSH and no policy
credential) compares its filter rules with the previous
backup and raises a `monitoring_alerts` alert on the firewall's inventory
host for each rule the change made any-to-any or shadowed (alert type
`opnsense_rule_change`, resolved when a later backup no longer has it;
`docs/opnsense-topology.md#rule-change-alerts`). The rule counters are
kept per host across counter resets (`opnsense_rule_counters`) and a rule
without a hit for 90 tracked days is flagged in the rule view; that flag
is view-only and raises no alert. Gap: no other vendor's rule base (Meraki
L3 rules, Cato, FMC access policies, Panorama security rules, cloud
security groups) is checked for any-to-any or shadowed rules, and none
keeps rule hit history.

IPAM names: an OPNsense collection with Config backup on also stores the
firewall's DNS names and DHCP reservations (Unbound overrides, Dnsmasq
hosts, ISC static mappings, Kea reservations, read from config.xml) as the
allocations of an `opnsense` IPAM source, next to the DHCP leases of its
`opnsense` DHCP server; both are fed by the collection and never synced or
pushed to (`docs/opnsense-topology.md#dns-names-and-dhcp-reservations`).

Tunnel traffic: only OPNsense tunnels and OpenVPN servers report traffic
today. Gap: the tunnels of Meraki (AutoVPN, third-party IPsec), Cato,
FMC, Panorama, Appgate and the AWS, Azure and GCP VPN connections store no
traffic (their collections read no per-tunnel byte counters or rates). The
pipeline is generic: a normaliser that puts a `traffic` block (byte
counters) or `in_bps` / `out_bps` metrics on an edge or node gets them
stored, rolled up and charted without further changes.

### Muting and removal of API-collected entities

Both live in the shared topology availability tracker, so they behave the
same for every source (`docs/meraki-topology.md#muting`,
`docs/meraki-topology.md#removed-entities`). Inventory hosts use
acknowledge and Suppressions instead.

| Vendor / source | Mute (entity or site, server-side, no alert or notification while muted) | Removed when gone at the source | Faster than the next collection |
|---|---|---|---|
| Cisco Meraki | Yes | Yes: devices at any stored collection; uplinks and tunnels when no organization-wide call failed | Yes, for a device that had an open Meraki alert: confirmed with one API call by the alert poll, about a minute |
| Cato Networks | Yes | Yes, at a collection with no warnings (a refused `accountMetrics` link measurement aside) and no site marked not collected | No |
| Cisco FMC, Palo Alto Panorama, Appgate SDP | Yes | Yes, at a collection with no warnings | No |
| OPNsense | Yes (muting the firewall covers its CARP groups and their failover warnings, its services, its certificates with their expiry alerts, its IDS alerts and its rule change alerts) | Yes, at a collection with no warnings other than informational ones (an incomplete security audit, a pending firmware update, audit findings, config.xml not stored, a CARP VIP in INIT or a CARP demotion, certificates expiring, certificates read from config.xml or not read on a release without the trust API) | No |
| AWS, Azure, GCP | Yes | Partly: at a discovery with no warnings and no *not collected* network (a peered VPC or VNet outside the collected accounts and regions). One failed region or account, or one such peering, keeps everything of that cloud `unknown` until the retention cleanup. Gap: removal per account and region | No |

A removal that cannot be trusted (any other collection) leaves the entity
`unknown` until the retention cleanup, as before.

### Certificate expiry

Certificates a device uses are tracked as `certificate` entities of the
device in the same tracker: `up` while valid, `degraded` from 30 days
before the end and once expired (never `down`, so expiry is no downtime in
uptime or SLA figures). The alert is on the expiry tier, server-side into
`monitoring_alerts` (the device's inventory host) or the notification
channels: a warning from 30 days, critical from 7 days and once expired,
each tier once (also on first sight), resolved by a renewal or when the
certificate is replaced and removed; mutes apply.

| Vendor / source | Certificates tracked | Source | Notes |
|---|---|---|---|
| OPNsense | Yes: certificates in use, and the CAs a tracked certificate or a service depends on; unused and user certificates are listed only | `trust/cert/search`, `trust/ca/search` (24.7+; the private keys in the answer are dropped at once), else the `<cert>` / `<ca>` of `config.xml` | Days left worked out at each collection; fixed thresholds. `docs/opnsense-topology.md#certificates`. |
| Every other vendor (Cisco, Cato, AWS, Azure, Meraki, FMC, Panorama, Appgate, GCP, inventory hosts) | No | None | Gap. Candidates: AWS Certificate Manager (`ListCertificates`, `NotAfter`, `InUseBy`), Azure Key Vault / App Service certificates, the certificates an inventory host's HTTPS or SSL VPN presents (a TLS handshake check), FMC / FDM internal certificates. |

### Hardware module health

The monitoring poll of an inventory host reads the operational state of
its hardware modules (line cards, supervisors, sub-modules) over SNMP and
raises one server-side `module_down` alert per module that is not working
into `monitoring_alerts` / notification channels (critical, suppressible by
metric), resolved when the module reads OK, is disabled by an operator, or
is gone from a table the poll read; a poll that read no table raises and
resolves nothing. The count is the `module_down` metric sample and alert
rule metric (`netcontrol/module_health.py`,
`docs/monitoring.md#hardware-module-health`). It is the state-based
backstop of the module syslog rules: it also finds a module that never came
up after a reload, or whose message was lost.

| Vendor / platform | Module health | Source | Notes |
|---|---|---|---|
| Cisco IOS / IOS XE / NX-OS / IOS XR (inventory: `cisco_ios`, `cisco_xe`, `cisco_nxos`, `cisco_xr`) | Yes | CISCO-ENTITY-FRU-CONTROL-MIB `cefcModuleOperStatus` (one walk per poll; rows of entity class module), `cefcModuleAdminStatus` to tell an operator's power-off, names and models from ENTITY-MIB `entPhysicalName` / `entPhysicalDescr` / `entPhysicalModelName` for the modules down only | Every `ModuleOperType` value classified (OK, passing, admin, down) in `netcontrol/module_health.py`; the `okBut...` states (diagnostics, power over budget, integrity check) are working modules and raise no module alert. Tested with invented rows, not a live chassis. |
| Juniper Junos (inventory: `juniper`, `juniper_junos`) | Yes | JUNIPER-MIB `jnxFruTable`: `jnxFruState` (one walk), `jnxFruType` of the present rows to keep the modules (FPC, PIC, routing engine, control, fabric and forwarding boards), `jnxFruName` and `jnxFruOfflineReason` (an operator's offline) for the modules down | Fans, power supplies and empty slots are not modules. Tested with invented rows, not a live device. |
| Cisco ASA / FTD | No | None | Gap: support for the module table not confirmed from Cisco's ASA / FTD MIB documentation; not implemented by guess. |
| Arista EOS | No | None | Gap. EOS lists ENTITY-STATE-MIB as supported, but `entStateOper` is indexed over every physical entity (ports, sensors, transceivers), so a bounded read needs the module rows first; which entity classes EOS populates is not documented. |
| HPE Aruba AOS-CX / AOS-Switch | No | None | Gap: no module operational-state object confirmed from the HPE Aruba MIB documentation yet; not implemented by guess. |
| Fortinet, PAN-OS, Netgear, Aruba Instant On, OPNsense, APC UPS, ICMP-only | No | None | Not read (no request is sent): fixed-configuration devices or no documented module state object. |
| Cato, Meraki, AWS, Azure, GCP and other API sources | n/a | n/a | No hardware modules the operator manages (device health comes from the vendor's own status, see Availability and SLA). |

Gaps for every vendor: a module that leaves the table without ever
reading not OK raises nothing (needs a stored baseline of the modules);
stack members (Cisco CISCO-STACKWISE-MIB) and supervisor redundancy state
(CISCO-RF-MIB) are not read.

### Power supplies, fans and temperature

The monitoring poll of an inventory host reads the state of its power
supplies, fans and temperature sensors over SNMP and raises one server-side
alert per item into `monitoring_alerts` / notification channels:
`power_supply_down` (critical), `fan_down` (warning), `temperature_alarm`
(the device's warning or critical), suppressible by metric. Each resolves
when the item reads OK or is turned off / locked by an operator, or is gone
from a table the poll read; a poll that read no table raises and resolves
nothing, and a table read empty counts as "no items" (its open alerts
resolve) only at the third empty poll in a row. The counts are metric
samples, with hourly and daily rollups, and alert rule metrics
(`netcontrol/environment_health.py` on `netcontrol/snmp_health.py`, the
plan per device type in `netcontrol/health_checks.py`;
`docs/monitoring.md#power-supplies-fans-and-temperature`). It is the
state-based backstop of the power supply and fan syslog rules and of the
traps. None of it has been run against a live device: every table is tested
with invented rows shaped as its MIB text defines them.

| Vendor / platform | Power supplies | Fans | Temperature | Notes |
|---|---|---|---|---|
| Cisco IOS / IOS XE / NX-OS / IOS XR / ASA / FTD | CISCO-ENVMON-MIB `ciscoEnvMonSupplyState`, else CISCO-ENTITY-FRU-CONTROL-MIB `cefcFRUPowerOperStatus` (rows not on kept when `entPhysicalClass` is powerSupply(6); `cefcFRUPowerAdminStatus` off(2) is an operator's) | `ciscoEnvMonFanState`, else `cefcFanTrayOperStatus` | `ciscoEnvMonTemperatureState` (warning, critical, shutdown), else CISCO-ENTITY-SENSOR-MIB `entSensorThresholdEvaluation` of celsius sensors (minor: warning; major, critical: critical) | Every CiscoEnvMonState, PowerOperType and fan tray value classified. Which table a model answers (ENVMON on IOS / IOS XE; FRU and sensor tables on NX-OS) is not confirmed per platform; the poll takes the first that has rows. ASA / FTD answers not confirmed. |
| Juniper Junos | JUNIPER-MIB `jnxFruState` of FRU types powerEntryModule(7), powerDistributionUnit(17), powerSupplyModule(18) | `jnxFruState` of fan(13) | Gap | One walk of `jnxFruTable` shared with module health; `jnxFruOfflineReason` tells an operator's offline. Gap: JUNIPER-MIB gives temperature readings (`jnxOperatingTemp`) but no per-sensor threshold or state. |
| Arista EOS | ENTITY-STATE-MIB `entStateOper` of entities of class powerSupply(6); `entStateAdmin` locked(2) is an operator's | ARISTA-ENTITY-SENSOR-MIB `aristaFanStateOper` | ENTITY-STATE-MIB `entStateAlarm` (critical / major: critical; minor / warning: warning) of sensors whose `entPhySensorType` is celsius | EOS lists ENTITY-STATE-MIB as supported; which entities it fills, and whether it sets `entStateAlarm` on sensors (its `aristaEntSensorAlarm` notification carries it), is not confirmed on a device. |
| PAN-OS | `entStateOper` of powerSupply(6) entities | `entStateOper` of fan(7) entities | `entStateAlarm` of celsius sensors | PAN-OS documents ENTITY-STATE-MIB on the PA-7000 and PA-5450 (PA-3400 from 11.1): other models answer nothing and raise nothing (gap). |
| Fortinet FortiOS | FORTINET-FORTIGATE-MIB `fgHwSensorEntAlarmStatus` of sensors named as a supply (`PS1`, `PSU`, `power supply`) | of sensors named as a fan | of sensors named as a temperature (`temp`, `DTS`, `thermal`) | The table has a name and an alarm flag, no type and no severity: the kind comes from the name (a convention, not the MIB) and temperature alarms are warnings. |
| HPE Aruba AOS-Switch / ProCurve | HP-ICF-CHASSIS `hpicfSensorStatus` of sensors whose `hpicfSensorObjectId` is icfPowerSupplySensor | icfFanSensor | icfTemperatureSensor (warning(3): warning; bad(2): critical) | FAN-MIB / POWERSUPPLY-MIB not read (the sensor table covers both). |
| HPE Aruba AOS-CX | ARUBAWIRED-POWERSUPPLY-MIB `arubaWiredPSUStateEnum` | ARUBAWIRED-FAN-MIB `arubaWiredFanStateEnum` | Gap | `faultAbsent(2)` is taken as an empty bay, as `empty(12)`. Gap: `arubaWiredTempSensorState` is a free string the MIB does not enumerate. Fan trays (`arubaWiredFanTrayStateEnum`) not read: the fans are. |
| Netgear managed switches (`netgear_prosafe`) | NETGEAR-BOXSERVICES-PRIVATE-MIB `boxServicesPowSupplyItemState` | `boxServicesFanItemState` | `boxServicesTempSensorState` (low, warning: warning; critical, shutdown: critical) | Gap: smart switches (`netgear_smart`, a MIB under another branch) and access points not read. |
| Aruba Instant On | Gap | Gap | Gap | No MIB reference for its environment tables found; not implemented by guess. |
| OPNsense | n/a | n/a | Over its API | The hottest sensor is the `fw_temperature_c` sample (see OPNsense firewall metrics); not read again over SNMP. |
| APC UPS | n/a | n/a | Own reader | Battery temperature and the UPS state are `netcontrol/integrations/apc/snmp.py`. |
| Cato, Meraki, AWS, Azure, GCP and other API sources | n/a | n/a | n/a | No hardware the operator monitors over SNMP. |

Gaps for every vendor: a supply pulled from its bay leaves the table and
its alert resolves (as an empty bay, it is not an item).

### BGP peers and OSPF neighbors

The monitoring poll reads the BGP peers and OSPF neighbors of every
SNMP-polled inventory host (any device type but a UPS or an ICMP-only host)
and raises one critical server-side alert per peer (`bgp_peer_down`) or
neighbor (`ospf_neighbor_down`), resolved when it is up again, stopped by
an operator, or gone from the table (`netcontrol/routing_health.py`;
`docs/monitoring.md#bgp-peers-and-ospf-neighbors`). A peer never
established (neither the device's established-transitions counter nor
Plexus has seen it up) is not alerted; an OSPF neighbor alerts after two
polls in a non-healthy state, and a neighbor seen healthy that left the
table alerts as gone for 24 hours. Not run against a live device.

| Vendor / platform | BGP | OSPF | Notes |
|---|---|---|---|
| Cisco (all inventory types) | CISCO-BGP4-MIB `cbgpPeer2State` (IPv4 and IPv6), else BGP4-MIB `bgpPeerState` | OSPF-MIB `ospfNbrState` | Gap: peers in VRFs that only an SNMP context shows. |
| Juniper Junos | BGP4-V2-MIB-JUNIPER `jnxBgpM2PeerState` (all routing instances, IPv4 and IPv6), else `bgpPeerState` | `ospfNbrState` | `jnxBgpM2PeerStatus` halted(1) is an operator's stop. |
| Arista EOS | ARISTA-BGP4V2-MIB `aristaBgp4V2PeerState`, else `bgpPeerState` | `ospfNbrState` | |
| Fortinet, PAN-OS, HPE Aruba, Netgear and any other SNMP platform | `bgpPeerState` | `ospfNbrState` | Whether each answers BGP4-MIB / OSPF-MIB is not confirmed; a device that never answers a table costs one walk of it an hour after its third empty poll. |
| APC UPS, ICMP-only | Not read | Not read | |
| Cato, Meraki, AWS, Azure, GCP and other API sources | n/a | n/a | Tunnels and peers of API sources are in their own availability tracking. |

Gaps for every vendor: OSPFv3 neighbors (OSPFV3-MIB); the memory of peers
and neighbors seen up is the server process's (lost on a restart).

## Software versions and CVE advisories

The software tracker (`netcontrol/integrations/software/versions.py`,
`netcontrol/routes/software.py`) reduces every source's version string to one
platform key and version, matches devices against advisories, and opens
`software_alerts` with notification fan-out. Advisory sources are listed per
platform. Every advisory that names CVE ids, whatever its source, can be
enriched (off by default; `netcontrol/routes/software_cve.py`) from the NVD
CVE API 2.0 (CVSS base score) and the CISA Known Exploited Vulnerabilities
catalogue (known-exploited flag, dates): a missing score is filled, a default
or enriched severity follows the score (at least high when known exploited),
a vendor's or an administrator's severity is kept, and the results are cached
per CVE (`cve_enrichment`) and persisted on the advisory. See
[software-versions.md](software-versions.md#cve-enrichment-nvd-and-cisa-kev).

| Vendor / platform | Version source | Advisory source | Status | Notes |
|---|---|---|---|---|
| Cisco IOS / IOS XE / IOS XR / NX-OS / ASA / FTD / FMC / FXOS | SNMP sysDescr, SSH `show version` at inventory discovery / sync (service credential by default; also sets model, serial and device type), FMC snapshot | Cisco PSIRT openVuln (version query), manual, import | Yes | Scheduled sync; advisories without a version match (product-family only) are not synced. |
| Cisco Meraki MX / MS / MR / MG / MV / MT | Meraki org snapshot firmware | Manual / import | Manual | Cisco PSIRT has no version query for Meraki. |
| Cato Socket | Cato `accountSnapshot` Socket version | Manual / import | Manual | Cato publishes no vulnerability API; release notes only. |
| AWS | None in the software tracker | None | No | Candidate: AWS Inspector / Security Hub findings. Virtual appliances are covered only as inventory hosts. Engine versions are collected, stored in the resource metadata (`engine_version`) and shown in the VPC details for RDS / Aurora / Neptune / DocumentDB (`EngineVersion`), ElastiCache (`EngineVersion`, serverless `FullEngineVersion`), OpenSearch (`EngineVersion`), MSK (`KafkaVersion`) and Redshift (`ClusterVersion` and revision, Serverless `workgroupVersion`), and for FSx Lustre (`FileSystemTypeVersion`), but not fed to the software tracker (gap: the tracker reads versions from snapshot nodes, and these managed services are not nodes; they also need platform keys per engine and an advisory source, for which AWS publishes no version-matched feed other than Inspector / Security Hub). ONTAP, Windows File Server and OpenZFS software is patched by AWS and no version is reported. |
| Azure | None | None | No | Candidate: Defender for Cloud assessments. Virtual appliances are covered only as inventory hosts. |
| GCP | None | None | No | |
| Palo Alto PAN-OS / Panorama | SNMP/SSH, Panorama snapshot | Manual / import | Manual | Candidate: Palo Alto security advisories feed. Discovery's SSH `show version` does not read PAN-OS (`show system info`): gap. |
| Appgate SDP | collective snapshot appliance version | Manual / import | Manual | |
| OPNsense | OPNsense snapshot: `core/firmware/status` product version (platform `opnsense`); pending update shown and warned | The firewall's own security audit (`pkg audit -F` via `core/firmware/audit`), synced at each collection as advisories of source `opnsense-audit` (one per VuXML entry, affected version the firewall's version, CVE ids, link), upserted by id, limited to the firewall(s) whose audit reported them (`device_keys`) and withdrawn per firewall when its audit no longer reports them; only an audit that verifiably completed (pkg audit's result line, no fetch / database error) changes advisories; manual / import as well | Partial | Covers vulnerable FreeBSD packages installed on the firewall, not OPNsense's own security advisories (OPNsense publishes no version-matched vulnerability API). `pkg audit` gives no severity: new advisories start as a default `medium`, which the NVD / CISA KEV enrichment of their CVE ids replaces with the score's severity (at least high when known exploited), filling the CVSS score and the known-exploited flag; later audits keep them, and an administrator's severity is kept. |
| Juniper Junos | SNMP/SSH; SSH `show version` at inventory discovery / sync (model, version, hostname; serial needs `show chassis hardware`) | Manual / import | Manual | Candidate: Juniper JSA feed. |
| Arista EOS | SNMP/SSH; SSH `show version` at inventory discovery / sync | Manual / import | Manual | |
| Fortinet FortiOS | SNMP/SSH | Manual / import | Manual | Candidate: FortiGuard PSIRT feed. Discovery's SSH `show version` does not read FortiOS (`get system status`): gap. |
| HPE Aruba AOS-CX / AOS-Switch (HP ProCurve) | SNMP sysDescr; SSH `show version` at inventory discovery / sync (platforms `aos-cx`, `aos-switch`) | Manual / import | Manual | Gap: HPE publishes security bulletins but no version-matched vulnerability API. Candidate: the HPE Aruba Networking security advisory feed, matched by product family. |
| HPE Aruba Instant On | SNMP sysDescr (platform `instant-on`) | Manual / import | Manual | Same gap. No SSH on the switch, so the version comes from SNMP only. |
| Netgear managed switches | SNMP sysDescr; SSH `show version` at inventory discovery / sync (platform `netgear-managed`) | Manual / import | Manual | Gap: Netgear publishes security advisories as web pages, with no version-matched vulnerability API. |
| Netgear smart switches and access points | SNMP sysDescr (platforms `netgear-smart`, `netgear-ap`) | Manual / import | Manual | Same gap. No SSH, so the version comes from SNMP only; an access point's sysDescr seldom carries it (gap: the version is then not tracked). |
| APC Network Management Card and Smart-UPS | Card: sysDescr `PF` firmware at discovery and every poll (platform `apc-nmc`, the host's version); a discovery that identifies the card over SSH with no SNMP answer reads it from the card's `about` instead. UPS: PowerNet-MIB `upsAdvIdentFirmwareRevision` read by the poll (platform `apc-ups`, tracked device `host:<id>:ups`) | Manual / import | Manual | Gap: Schneider Electric publishes security notifications as documents, with no version-matched vulnerability API, and Plexus does not match versions to CVEs through NVD's CPE data (the NVD client only scores the CVE ids an advisory already names, so a manual or imported card advisory with CVE ids gets its CVSS score and KEV flag). Candidate: NVD CPE matching of the card firmware (gap 6 below). An advisory's `product_match` is compared with the host model, which is the UPS model, not the card's. |

### Hardware lifecycle (end of life and support contracts)

The hardware lifecycle (`netcontrol/hardware_lifecycle.py`,
`netcontrol/routes/hardware_lifecycle.py`, [hardware-lifecycle.md](hardware-lifecycle.md))
matches end-of-life notices to inventory hosts by device type, by part
number (device type part number or model) and by DCIM module part number,
and evaluates contract coverage. A scheduled server-side check raises
`monitoring_alerts` (type `hardware_lifecycle`) for a host past or near its
last date of support and for expiring or expired coverage, once per
condition, resolved when it clears, through the notification channels.

| Vendor / platform | Hardware source | Notice source | Status | Notes |
|---|---|---|---|---|
| Every vendor with inventory hosts (Cisco, Juniper, Arista, Fortinet, Palo Alto, HPE Aruba, Netgear...) | Device type from the device model catalogue (discovery links the model), DCIM modules | Manual / API | Manual | Gap for every vendor: no notice import or sync. Candidate: Cisco's Support EoX API (needs a Cisco support API account), matched by product ID. |
| Cisco Meraki, Cato Sockets, Appgate, OPNsense, Panorama devices (API-collected) | None | None | No | Not inventory hosts, so no device type and no hardware lifecycle status. Gap: a hardware lifecycle status for topology nodes by model. Their software release series has an end-of-life status: see [Software lifecycle](#software-lifecycle-end-of-life-per-release-series) below. |
| AWS, Azure, GCP | Not applicable | Not applicable | Not applicable | Cloud services have no hardware lifecycle; retirements of instance types and engine versions are not tracked (gap). |

### Software lifecycle (end of life per release series)

The software lifecycle (`netcontrol/integrations/software/lifecycle.py`,
`netcontrol/routes/software_eol.py`, [software-versions.md](software-versions.md#software-end-of-life))
gives every tracked device the end-of-life status of the release series it
runs (`supported`, `ending` within the warning window, `end_of_life`,
`unknown`), from an administrator's entry per platform and series, or for
OPNsense from a built-in estimate. A series that is ending or end of life
becomes a generated advisory (source `lifecycle`, `high` once end of life,
`low` while ending), synced on every scheduled refresh, so its devices get
persisted `software_alerts` and notifications through the software
tracker's channels, which resolve when the device is upgraded.

| Vendor / platform | Series source | End-of-life source | Alerting | Notes |
|---|---|---|---|---|
| OPNsense | The version (`25.1.4_1` is `25.1`; business edition `24.10`) | Yes: built-in estimate by release cadence (a series ends when its successor ships; estimated as the last day of the successor's release month, never early), confirmed by the firewall's own major-upgrade report (`upgrade_major_version`), administrator entry overrides | Yes | The firewall's details show the series status and an end-of-life series is an informational collection warning. |
| Every other platform (Cisco, Juniper, Arista, Fortinet, Palo Alto, HPE Aruba, Netgear, APC, Meraki, Cato, Appgate) | Administrator entries (a version prefix on a component boundary) | Manual: administrator entries (or the import API) | Yes, once an entry exists | Gap: no automatic end-of-life source. Candidate: a public end-of-life feed such as endoflife.date, or the vendors' end-of-life bulletins (Cisco's EoX API also covers software releases). |
| AWS, Azure, GCP | Not applicable | Not applicable | Not applicable | Managed services carry no tracked software version. |

## Internet egress and cloud ingress (path trace)

How a flow that leaves one vendor to the internet is checked where it lands
in another (`netcontrol/integrations/pathtrace`, see `docs/path-trace.md`,
"Cato network rules and the egress address").

| Vendor | Egress address of a flow to the internet | Public address of a resource as a trace destination | Filtering checked against the post-NAT source | Notes |
|---|---|---|---|---|
| Cato Networks | Yes: INTERNET network rules (`policy.wanNetwork`) evaluated at the Cato Cloud; NAT gives the allocated IP (`popLocations.allocatedIpList`, else the allocated IP's name), several candidates checked each; VIA / OPTIMIZED / NONE give an unknown public address (a PoP's shared address is not reported); rules that match only by name are listed | n/a | n/a | Custom category contents are not in the API (reported as not collected); BACKHAUL egress is not traced past the site. |
| Cisco Meraki | Partial: uplink NAT when the deployment mode is collected | Yes: 1:1 NAT, port forwarding | Yes (inbound rules) | |
| OPNsense (inventory host with a config.xml backup) | Yes: automatic, hybrid and manual outbound NAT, source NAT rules and 1:1 NAT to the interface or target address | Yes: port forwards (wan address or a listed address) and 1:1 NAT | Yes: filter rules per interface in pf order (quick first, then last match), floating `out` rules | Read from the stored config.xml (`pathtrace/opnsense_config.py`); routes are the routing table the collection stores as the host's route capture (`pathtrace/opnsense_routes.py`: connected, static, DHCP / PPPoE / router advertisement, FRR, blackhole), whose live interface addresses also resolve a DHCP / PPPoE / DHCPv6 / track6 interface's address and network; before the first capture (or with the routing table option off) the configured static routes and default gateway, so a default-route-only destination is unknown; aliases config.xml cannot resolve (URL tables, GeoIP, ASN, host names, firewall-filled tables) are resolved from the pf tables the collection stores (`firewall/alias_util`, migration 0123: a complete table decides, a truncated one decides only what it holds, a missing one leaves the rule unknown; at most 9,999 entries per table, 30,000 and 30 tables per collection; bogon tables never read); policy-based routing, VPN interface rules, bogons and NPTv6 are notes. Rule views and backup-to-backup rule diffs: `docs/opnsense-topology.md`. |
| AWS | n/a | Yes: EC2 instance public / Elastic IP on its interfaces, delivered to the private address at the internet gateway | Yes: network ACL and security groups; an unknown public source is unknown unless a rule allows every address | Managed services (RDS, load balancers, VPC endpoints and the others with an address) are trace ends, by address or collected DNS name, with their own security groups and the Classic Load Balancer or endpoint port that takes the flow; a public IP on a load balancer's interface (or an NLB's one Elastic IP) is delivered to its private address. ALB / NLB listeners and targets are not collected (gap: the port is not judged, the trace ends at the load balancer). |
| Azure | n/a | Yes: VM public IP on its NIC | Yes: subnet and NIC network security groups | Load balancers (frontends, public IPs, rules), application gateways (frontends, listeners, WAF), private endpoints are trace ends with their subnet's NSG and the rule or listener that takes the port; an Azure Firewall's public address is translated by its DNAT rules (classic or firewall policy) and followed to the translated address. A public load balancer ends the trace at the load balancer: backends are not collected by address (gap). |
| GCP | n/a | Yes: instance external IP | Yes: VPC firewall rules | Load balancers (forwarding rules with their backend services), Private Service Connect endpoints and service attachments, Cloud SQL and Memorystore for Redis instances are trace ends by internal address or collected DNS name, with the forwarding rule's (or endpoint's) ports; an external forwarding rule ends the trace at the load balancer, as backends are not collected by address (gap). |

### Cato egress vs cloud allow-lists (scheduled check)

The same evaluation run on the server after every Cato collection and cloud
discovery, and on demand: cloud filter rules that admit a Cato account's
allocated IPs, checked against the network rule a flow from every Cato site
range and remote user to the protected public address matches. Findings are
persisted (`cato_egress_findings`) and warnings alert (monitoring alert on a
matched inventory host, else the notification channels); see
`docs/path-trace.md`, "The egress check".

| Cloud | Rules read | Resources checked | Status | Notes |
|---|---|---|---|---|
| AWS | Security group inbound rules (CIDR sources); admission through network ACL + security groups | EC2 instances with a public or Elastic IP; load balancers whose public IP is on their interface (or one Elastic IP with one private address), with their security groups | Yes | Public RDS instances and load balancers whose public addresses are not collected are not checked (gap). Prefix-list and security-group sources are not Cato addresses and are skipped. |
| Azure | Subnet and NIC NSG inbound rules (CIDR sources, destination covering the VM) | VMs with a public IP; application gateways with one public and one private frontend (subnet NSG); Azure Firewall DNAT rules (classic and firewall policy) whose sources name an allocated IP | Yes | Public load balancers are not checked: their filters apply at the backends, not collected by address (gap). Service tags are skipped. |
| GCP | VPC firewall ingress rules that target the instance (source ranges) | Instances with an external IP | Yes | Hierarchical / network firewall policies: not collected (an evaluation through them is unknown). External load balancers are not checked: their firewall rules apply at the backends, not collected by address (gap). |

### Cato shared hosts vs Azure (scheduled check)

Whether the hosts a Cato account's Shared Hosts rules name (multi-session
VDI hosts whose Cato Client tunnels each user session to the Cato system
range, `10.254.254.0/24` by default) can reach a Cato Socket: the route from
the host subnet to the system range, the next-hop appliance (IP forwarding,
in a Cato site range), the network security groups for GRE over UDP
(udp/4754) on both sides, and the route back. Run on the server after every
Cato collection and Azure discovery, and on demand; findings are persisted
(`cato_egress_findings`, `check_name` `shared_host`) and warnings alert
(monitoring alert on a matched inventory host, else the notification
channels). See `docs/cato-topology.md`, "Shared Hosts check (Azure)".

| Cloud | Routing read | Filters read | Status | Notes |
|---|---|---|---|---|
| Azure | Effective routes of the host subnet (user routes, system routes, peerings, gateway routes) and of the next hop's subnet for the return | Subnet and NIC NSGs, host side outbound and next-hop side inbound with the system range as the destination; NIC IP forwarding | Yes | The `GREOverUDP` registry value is not visible (reported as an informational note); routes learned over BGP or ExpressRoute are not collected (undetermined). |
| AWS | n/a | n/a | Gap | Not checked: an EC2 host would need its route table's route for the system range to the vSocket's interface, the source/destination check off on that interface and its security groups for the tunnel; not implemented. |
| GCP | n/a | n/a | Gap | Not checked: a Compute Engine host would need a custom static route for the system range to the vSocket instance, IP forwarding on it and VPC firewall rules for the tunnel; not implemented. |

## Vendor alert feeds

Near-real-time ingestion of the vendor's own alerts, separate from the
collections that feed availability: the vendor tells Plexus about a problem
within about a minute instead of the next collection seeing it. Alerts are
persisted, deduplicated and raised server-side into `monitoring_alerts` (on a
matched inventory host) or the notification channels.

| Vendor / source | Alert feed | Status | Notes |
|---|---|---|---|
| Cisco Meraki | Assurance alerts polled every 60 s (`organizations/{id}/assurance/alerts`); optional webhook receiver (`POST /api/webhooks/meraki`) | Yes | `docs/meraki-alerts.md`. One alert per device and condition across both paths; device-down is not notified twice with the topology availability tracker. |
| APC Smart-UPS (Network Management Card) | SNMP traps (PowerNet-MIB, v1 / v2c) to the Plexus trap receiver (UDP 10162) | Yes | `docs/apc-ups.md#snmp-traps`. On battery, power restored, low battery, overload, bypass, off / sleep, battery replacement, no batteries and communication lost / established raise or resolve the poll's alerts on the matched `apc_ups` host, and every APC trap re-polls the host within seconds. Accepted only from an inventory host address (listener allowlist) with the host's stored SNMP community, through the receiver's bounded queue. The receiver is turned on in Settings > Syslog & Traps and then starts with Plexus (Docker publishes host 162 to it). |
| Cato Networks | Events feed (`eventsFeed` GraphQL query) polled every 60 s per account from its stored marker, filtered to the mapped sub-types: Disconnected / Connected / Reconnected (a site, or a Socket link when the event names the interface), Alt. WAN Disconnected / Connected, HA Not Ready / Ready, LAN port disconnected / connected (listed only), Socket Fail-Over and Last-Mile Quality (one-shot, closed after 24 h) | Yes | `docs/cato-alerts.md`. Persisted in the vendor-neutral `vendor_alerts` store (migration 0132), one alert per entity and condition, raised server-side into `monitoring_alerts` (Socket serial, else the tracker's host of the site) or the notification channels, cleared by the recovery event or when a later collection shows the site and its links up. A site or link down is not notified twice with the topology availability tracker; topology mutes apply. The account must have the events feed enabled; a refusal is shown per account in the settings (hourly back-off). Not checked against a live account: the sub-types' meaning (read from their names), the record time format, the site ID matching the snapshot's site ID, and the rate limit. They alert; they do not feed the availability history or uptime %. |
| AWS | Polled every 300 s per account with the discovery credentials (no inbound receiver): CloudWatch alarms in `ALARM` (`DescribeAlarms`, metric and composite, per region), AWS Health open / upcoming issues and scheduled changes with their affected resources (`DescribeEvents`, `DescribeAffectedEntities`), impaired EC2 system / instance / attached EBS status checks and scheduled instance events (`DescribeInstanceStatus`, per region) | Yes | `docs/cloud-alerts.md`. Current-state reads through the shared `vendor_alerts` pipeline: an alert resolves when a complete read of its region and part no longer reports it; a failed or partial read resolves nothing and is shown per account without back-off. Raised server-side into `monitoring_alerts` (the tracker's host of the instance or service the alarm names) or the notification channels; topology mutes apply; an impaired status check is not notified twice with the tracker. Each part can be switched off. AWS Health needs a Business support plan or higher: without one the account shows so and Health is re-asked daily. Severity: alarms warning (critical when named so), Health issue critical / warning, status checks critical. Not checked against a live account: the `DescribeInstanceStatus` key names, the region value of a global Health event, the matching of dimensions to managed services. Log alarms, EventBridge events (VPN tunnel state, Direct Connect) are not read. |
| Azure | Polled every 300 s per subscription with the discovery credential over ARM REST (no inbound receiver): fired Azure Monitor alerts (`Microsoft.AlertsManagement/alerts`, api-version 2019-03-01: metric, log, activity log, Service Health and Resource Health alert rules) and Resource Health availability statuses (`Microsoft.ResourceHealth/availabilityStatuses`, api-version 2025-05-01) | Yes | `docs/cloud-alerts.md`. Current-state reads through the shared `vendor_alerts` pipeline: an alert resolves when a complete read no longer reports it (monitor condition `Resolved`, closed, or the resource `Available`); `Unknown` neither opens nor resolves; a failed or partial read resolves nothing. Severity `Sev0` / `Sev1` critical, `Sev2` warning, `Sev3` / `Sev4` info; `Unavailable` critical, `Degraded` warning. Raised server-side into `monitoring_alerts` (the tracker's host of the VM or service) or the notification channels; topology mutes apply; a Resource Health outage is not notified twice with the tracker. Each part can be switched off. Needs Reader or Monitoring Reader. Public cloud only. An alert fired longer than 30 days drops out of the read (`timeRange=30d`) and resolves. Not checked against a live subscription. |
| OPNsense | Syslog forwarded to the Plexus syslog receiver (UDP 1514; Docker publishes 514): gateway alarms (`dpinger`), CARP transitions and demotion (`kernel`), IPsec IKE SA up / down (`charon`), OpenVPN instance up / down, configuration saves (`config`, `audit`), Suricata alerts (`suricata`: a read of the IDS alerts only, see Security events below) | Partial | `docs/opnsense-topology.md#syslog`. Each message starts an immediate collection of the firewall's topology source (5 s after the first message, at most one per source a minute, never two at once), so the availability tracker raises or resolves its gateway, tunnel and CARP alerts within seconds and a configuration change gets its config.xml backup and drift check right away; the messages raise no alert of their own (no duplicate of the tracker's). The source is found by the firewall's inventory host or by its collected addresses (no inventory host needed, but a sending address that is not an inventory host address must be added to the listener allowlist's extra networks, `docs/administration.md#listener-sources`). Gaps: WireGuard logs no peer state; an IPsec child SA (phase 2) coming up is not a trigger (every rekey logs it); a triggered collection is the full one (tens of seconds with the firmware audit on). |
| GCP, Cisco FMC, Palo Alto Panorama, Appgate SDP | None | No | Gap. Their state reaches Plexus only through the scheduled collection (topology availability tracker); none has a push trigger that starts an immediate collection (OPNsense's syslog trigger is the model). |

### Device syslog (inventory hosts)

Syslog sent by an inventory host to the Plexus syslog receiver is matched
on the server against the syslog alert rules (raised and resolved into
`monitoring_alerts` and the notification channels), starts a config
backup and drift check on a configuration change message, and re-polls
the host on an interface-down, module down / back online, reload or
restart message (`netcontrol/syslog_rules.py`, `docs/syslog-rules.md`). Custom rules
(tag, text or RE2 regex) work on any vendor's messages; the cells below
are the built-in rules and triggers. The same intake rules apply to every
vendor: the trap, syslog and flow listeners accept only inventory host
addresses by default, plus the admin's extra networks, with a per-source
rate limit (`netcontrol/listener_sources.py`,
`docs/administration.md#listener-sources`); an SNMPv1 / v2c trap needs the
host's stored community; a syslog message resolves only a `syslog` alert of
its own host, and configuration-change backups have a per-host cooldown.

| Vendor / platform | Built-in alert rules | Config change trigger | Re-poll trigger | Status | Notes |
|---|---|---|---|---|---|
| Cisco IOS / IOS XE | Interface flapping, OSPF and BGP neighbor down, power supply and fan (IOS XE `IOSXE_PEM`, Catalyst 9000 `PLATFORM_FEP`), module down (IOS XE `IOSXE_OIR` / `SPA_OIR` card and SPA offline / removed, cleared by `ONLINECARD`; Catalyst 3750 / 2975 `STACKMGR-4-SWITCH_REMOVED` / `SWITCH_READY`; Catalyst 6500 `C6KPWR-SP-4-DISABLED`), login failures | `SYS-5-CONFIG_I` | Link down, module down / online, `SYS-5-RELOAD`, `SYS-5-RESTART`, `SYS-6-BOOTTIME` | Yes | Classic Catalyst fans (`HARDWARE-2-FAN_ERROR`, 3750-X `PLATFORM_ENV-1-FAN` / `FRU_PS_FAN_FAILED`), 3750-X power supply signal (`PLATFORM_ENV-1-FRU_PS_SIGNAL_FAULTY`) and ISR G2 fans (`ENVMON-3-FAN_FAIL` / `FAN_OK`) are built in. Gap: ISR G2 power supply messages (no Cisco reference naming the mnemonics was found); Catalyst 9000 stack member messages (`STACKMGR` is not in the IOS XE system message guides; the classic form matches the IOS XE text seen in community logs, unconfirmed); Catalyst 4500 module messages; the Catalyst 6500 module power-off has no documented recovery or admin form (resolves after 24 hours). |
| Cisco IOS XR | Interface flapping, OSPF and BGP neighbor down, login failures | `MGBL-CONFIG-6-DB_COMMIT` | Link down | Partial | Gap: power supply, fan, module (line card / RP) and reload messages (no IOS XR reference with their text was retrieved). |
| Cisco NX-OS | Interface flapping, OSPF and BGP neighbor down, power supply, fan, module down (`MODULE-2-MOD_FAIL` / `MOD_FAILURE` / `MOD_NOT_ALIVE`, `PLATFORM-2-MOD_REMOVE` / `MOD_PWRDN` / `MOD_PWRFAIL` / `MOD_PWRDENY`, fabric `XBAR_REMOVE` / `XBAR_PWRDN` / `XBAR_PWRFAIL`, cleared by `MODULE-5-MOD_OK`, `ACTIVE_SUP_OK` / `STANDBY_SUP_OK`, `XBAR_OK`), login failures | `VSHD-5-VSHD_SYSLOG_CONFIG_I` | Link down, module down / online, `PLATFORM-2-PFM_SYSTEM_RESET` | Yes | Gap: `MOD_PWRDN` does not tell a CLI power-off apart; diagnostic failures (`MOD_DIAG_FAIL`) and the lower-case `XBAR_FAIL` forms are not built in. |
| Cisco ASA | Interface flapping (`411002`), login failures (`113005`, `113015`, `605004`, `611102`) | `111008`, `111010` (not show commands) | Link down, `199001`, `199002` | Partial | Gap: ASA has no routing-neighbor rule here (OSPF / BGP on ASA log in other formats); FTD is not covered. |
| Arista EOS | Interface flapping, OSPF and BGP neighbor down, power supply (`PWRMGMT-3-PSU_STATUS_FAILED` / `OK`, `INPUT_POWER_LOSS`), fan (`ENVMON-3-FANFAILED` / `FANOK`), login failures (`sshd` `Failed password for`) | `SYS-5-CONFIG_I` | Link down | Partial | Gap: reload messages; module (line card, supervisor) messages (the Arista System Message Guide could not be retrieved). |
| Juniper Junos | Interface flapping, OSPF and BGP neighbor down, power supply and fan (`CHASSISD_SNMP_TRAP*`), module down (`CHASSISD_SNMP_TRAP*` `FRU removal` / `power off` / `failed` / `offline` of an FPC, PIC, RE, CB, SIB and other module FRUs, cleared by `FRU online`; not an operator's power off), login failures | `UI_COMMIT_COMPLETED` | Link down, module down / online, `UI_REBOOT_EVENT`, `SNMPD_TRAP_COLD_START` | Yes | Gap: chassisd's own FRU messages (`CHASSISD_FRU_*`) are not built in (their reference entries could not be retrieved); the trap forms cover the same events. |
| Fortinet FortiOS | Interface down (`FGT-0100020099`), OSPF and BGP neighbor down (`FGT-0103020302`, `FGT-0103020300`), power supply (`FGT-0100022105`, `22114` / `22104`, `22115`), fan (`FGT-0100022108` / `22151`), login failures (`FGT-0100032002`) | `FGT-0100044544` to `FGT-0100044547` (path, object and attribute configured) | Link down, `FGT-0100032138` (Device rebooted), `FGT-0100032200` (Device shutdown), `FGT-0100032009` (FortiGate started) | Partial | `docs/syslog-rules.md`. Tagged `FGT-<logid>` from the key=value format (default or RFC 5424). Log ids from the FortiOS Log Message Reference (6.4 to 7.6), not yet checked against a live firewall. Gap: the reference gives no `msg` text, so the OSPF Down / Up and link-monitor wordings are unconfirmed; `20090` (Interface link status changed) is not built in; power supply and fan alerts are per firewall; no module / slot message was found in a reference, so the module down rule does not cover FortiOS. |
| Palo Alto PAN-OS | Interface down (`link-change`), OSPF and BGP neighbor down (legacy routing engine `routed-OSPF-neighbor-down` / `-full`, `routed-BGP-peer-left-established` / `-enter-established`), power supply (`ps-failure`), fan (`fan-failure`), login failures (`auth-fail`) | A CONFIG log `commit` with result `Succeeded` (not candidate edits) | Link down | Partial | `docs/syslog-rules.md`. Tagged `PAN-SYSTEM-<event id>` / `PAN-CONFIG` / `PAN-<type>` from the default CSV format. Written from the PAN-OS syslog field descriptions and system log reference, not yet checked against a live firewall. Gap: Advanced Routing Engine events and reload / restart (the system log reference lists none), administrator logins not told apart from VPN / portal logins in `auth-fail`, custom log formats, module / slot events (none found in a reference; not covered by the module down rule). |
| HPE Aruba AOS-CX | Interface down (`AOSCX-404`), OSPF neighbor down (`AOSCX-2401`, `AOSCX-2404`), BGP neighbor down (`AOSCX-2902` / `2901`), power supply (`AOSCX-304`), fan (`AOSCX-214`), login failures (`AOSCX-5210`, `AOSCX-5216`) | None | Link down, `AOSCX-706` / `707` (system reboot), `AOSCX-1206` / `1236` (module rebooted) | Partial | `docs/syslog-rules.md`. Tagged `AOSCX-<event id>` from the `Event\|<id>\|...` format. Ids from the AOS-CX 10.17 Event Log Message Reference. Gap: no configuration change event in the reference; power supply and fan faults have no documented recovery message (resolve after 24 hours); line / management module and VSF member down events are not built in (the event log reference could not be retrieved to confirm their ids and text). |
| HPE Aruba AOS-Switch | Interface down (`AOSS-00077`), OSPF neighbor down (`AOSS-02703`), BGP neighbor down (`AOSS-03073` / `03072`, per switch), power supply (`AOSS-00071`, `AOSS-02797`), fan (`AOSS-00070`), login failures (`AOSS-00419`, `AOSS-03345`) | `AOSS-03125` (startup configuration saved) | Link down, `AOSS-00063` (SYSTEM went down), `AOSS-00066` (System Booted), `AOSS-00064` (crash reason) | Partial | `docs/syslog-rules.md`. Tagged `AOSS-<event id>` from the `<event id> <facility>:` format. Ids from the ArubaOS-Switch 16.09 Event Log Message Reference. Gap: an unsaved running configuration change logs nothing the reference lists; an administratively disabled port logs the same off-line message as a link failure; module and stack member down events are not built in (not confirmed in a retrievable reference). |
| Netgear, APC (inventory) | None | None | None | No | Gap: their syslog formats have no built-in rule or trigger; custom rules only. APC UPS state changes arrive as SNMP traps instead (row above). |
| OPNsense (topology source; inventory host or not) | Login failures (`audit` `could not authenticate for`: web GUI, SSH) | Re-collection of the source (`config-event: new_config`, `changed configuration to`): config.xml backup and drift | Re-collection of the source on a gateway alarm, CARP transition or VPN up / down (the availability tracker raises the alerts) | Yes | `docs/opnsense-topology.md#syslog`, `docs/syslog-rules.md`. Matched by program (RFC 5424 APP-NAME / RFC 3164 tag); no other built-in alert, so gateway, tunnel and CARP alerts are not duplicated. Gap: WireGuard and IPsec phase 2 establishment. |
| Cato, AWS, Azure, GCP, Cisco Meraki, Cisco FMC, Panorama, Appgate (API-collected) | Not applicable | Not applicable | Not applicable | No | API-polled platforms send no syslog to Plexus; their state comes from the scheduled collections (and Meraki's alert feed above). |

### Security events (IDS / IPS)

The intrusion detection or prevention alerts a device or cloud service
reports, kept as security events in one vendor-neutral store
(`security_events`, migration 0126: source, optional inventory host, kind,
signature, severity, action, flow; retention with the monitoring retention,
at most 50,000 per source) and alerted server-side: one alert per source and
signature for critical and warning events, counted on repeat while open,
resolved after an hour without a new event, covered by the mutes of the
source's device (`netcontrol/routes/security_events.py`). Listed under
Monitoring > Security (`GET /api/monitoring/security-events`).

| Vendor / source | Security event feed | Status | Notes |
|---|---|---|---|
| OPNsense | Suricata alerts over the API (`ids/service/status`, `POST ids/service/query_alerts`, `ids/settings/get_rule_info/<sid>`; privilege "Services: Intrusion Detection"): every collection and, for an inventory host, every monitoring poll; a forwarded Suricata syslog alert reads them within seconds | Yes | `docs/opnsense-topology.md#ids-alerts`. Only the alerts newer than the newest stored, at most 5 pages of 200 a read. Severity from the rule's classtype and Suricata's default `classification.config` (the alert search drops the logged severity): priority 1 critical, 2 warning, 3+ info (stored only). The alert says whether the traffic was blocked (IPS) or only detected. Gaps: rotated alert logs and bursts past one read's limit are not read; a custom classification file is not honoured; answer shapes checked against the OPNsense source, not a live firewall. |
| Cisco FTD (via FMC), Cisco ASA | None | No | Gap. Candidates: the intrusion events of FMC (eStreamer) or the FTD's intrusion event syslog. |
| Palo Alto (Panorama, PAN-OS) | None | No | Gap. Candidates: threat logs over the PAN-OS XML API (`type=log&log-type=threat`) or syslog. |
| Fortinet FortiOS | None | No | Gap. Candidates: IPS / UTM logs over syslog or the FortiOS REST log API. |
| Cisco Meraki | None | No | Gap. Candidates: the security events of MX appliances (`organizations/{id}/appliance/security/events`). |
| Cato Networks | IPS events (sub-type `IPS`) of the events feed, read by the same poll as the Cato alert feed (every 60 s) | Yes | `docs/cato-alerts.md#ips-events`. Stored per site with the site's inventory host (Socket serial) and its own mute (a site mute covers its IPS events, not the whole account). Severity from `risk_level` (High critical, Medium warning, Low info), else the rule's `severity`; blocked when `action` is block / prevent / drop / deny / reject; the signature is `signature_id` (a non-numeric id is grouped by a stable number derived from it). An account's sites with no inventory host share one notification per signature while it stays active. Can be turned off (`security_events` setting). Not checked against a live account: the `action` and `risk_level` values. |
| AWS | None | No | Gap. Candidates: GuardDuty and Network Firewall alert logs; AWS Inspector / Security Hub findings are the software item below. |
| Azure | None | No | Gap. Candidates: Azure Firewall IDPS logs and Defender for Cloud alerts. |
| GCP, Appgate SDP, Juniper, Arista | None | No | Gap: no IDS / IPS alert source read. |

## Known gaps, priority order

1. Latency / jitter / loss for more topology entities: OPNsense gateways,
   Meraki uplinks (no jitter: Meraki reports none) and Cato Socket WAN
   links report measurements today; Cato IPsec sites, the second Socket of
   a Cato HA pair (Cato aggregates the pair), FMC, Panorama, Appgate and
   cloud links do not.
2. Cloud security findings: AWS Inspector / Security Hub and Azure Defender
   for Cloud mapped onto the advisory and alert model.
3. Cato Socket release-note import as a `cato-socket` advisory source.
4. NVD CPE matching: finding the CVEs that affect a tracked version from
   NVD's CPE configurations (for platforms with no version-matched advisory
   source, such as the APC card firmware). Enrichment by CVE id is done:
   every advisory with CVE ids gets its CVSS score, a severity from it and
   the CISA KEV known-exploited flag (`software_cve`).
5. Public endpoints that are not instances (AWS RDS and load balancers,
   now collected with their security groups, Azure load balancers,
   application gateways and firewall DNAT rules, now collected too, GCP
   load balancers and Private Service Connect endpoints, now collected as
   well) as path trace destinations
   and egress check targets, so a Cato egress address is checked against
   their security groups too.
6. Vendor alert feeds: Meraki, Cato (events feed), AWS (CloudWatch alarms,
   AWS Health, EC2 status) and Azure (Azure Monitor alerts, Resource
   Health) are ingested between collections. Remaining: signals AWS only
   sends through EventBridge (VPN tunnel state, Direct Connect),
   CloudWatch log alarms, the sovereign clouds (AWS GovCloud and China,
   Azure Government and China), GCP, and the other vendors, which are seen
   at their next collection. The Meraki feed still keeps its own table
   beside the vendor-neutral `vendor_alerts` store.
7. The Cato Shared Hosts check for AWS and GCP hosts (route to the system
   range, the vSocket's source/destination check or IP forwarding, the
   security groups or firewall rules for the tunnel); Azure only today.
8. Security events (IDS / IPS alerts) from the other vendors into the
   `security_events` store (OPNsense Suricata and Cato IPS events today):
   Cisco FTD intrusion events first, then AWS (GuardDuty, Network
   Firewall) and Azure (Firewall IDPS, Defender for Cloud alerts).
9. Checks against live accounts: the Meraki uplink history, the Cato link
   metrics and events feed and the AWS and Azure alert feeds were built
   from the vendors' API references and sample answers; each page lists
   what was not checked against a live organization, account or
   subscription.
