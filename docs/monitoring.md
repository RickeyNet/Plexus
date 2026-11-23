# Monitoring

Monitoring polls every inventory host on a schedule, stores CPU, memory,
interface, VPN, route, response time and packet loss values, tracks when
hosts and interfaces go up and down, and raises alerts. The Monitoring page
shows the results and holds the alert configuration; the device detail page
shows one host. This guide explains how polling works and how to use both
pages.

Related guides: [SLA monitoring](sla-monitoring.md),
[Alert notification channels](alert-notification-channels.md),
[Vendor monitoring coverage](vendor-monitoring-coverage.md),
[Meraki alerts](meraki-alerts.md), [Cato alerts](cato-alerts.md), [Software versions](software-versions.md),
[NetFlow / sFlow / IPFIX](flow-collector.md) and
[Graph templates](graph-templates.md).

## Where it is and what you need

- **Observe > Monitoring** in the sidebar. The tabs are **Devices**,
  **Alerts**, **Events**, **SLA**, **Availability**, **Capacity** and
  **Configure**. **Configure** has the sub-tabs **Alert Rules**,
  **Suppressions**, **SLA Targets**, **OID Profiles**, **Graph Templates**,
  **Host Templates** and **Graph Trees**.
- You need the `monitoring` feature to see the page and `monitoring.write`
  to change anything on it.
- An admin sets up polling:
  1. **Settings > Monitoring**: tick **Enabled** and click **Save
     Monitoring Settings**. Polling is off on a new install.
  2. **Inventory > SNMP Profiles**: create an SNMP profile and assign it to
     the inventory groups to poll over SNMP. A host can have its own
     profile, which overrides its group's (see
     [Discovery](discovery.md#set-up-snmp)).
  3. **Settings > Authentication > Service Credentials**: the service
     credential is used for the SSH part of the poll (VPN and routes).

## How a host is polled

Each cycle polls every host of every inventory group, up to 16 at a time,
with a limit of 90 seconds per host. A poll has three independent parts:

| Part | When it runs | What it reads |
|---|---|---|
| SNMP | The host's effective SNMP settings are enabled: its own SNMP profile, else its group's profile, else the group's legacy profile, else the global SNMP settings | CPU, memory, uptime, interface status, speed, traffic and error counters, and the state of the hardware modules, power supplies, fans, temperature sensors, BGP peers and OSPF neighbors (see [Hardware module health](#hardware-module-health), [Power supplies, fans and temperature](#power-supplies-fans-and-temperature) and [BGP peers and OSPF neighbors](#bgp-peers-and-ospf-neighbors)) |
| SSH | A service credential is set | VPN tunnels (`show crypto isakmp sa`, or `show vpn-sessiondb summary` on an ASA) and the route table |
| ICMP | When the server can ping and ICMP is not switched off | Response time and packet loss (3 pings, 2 second timeout) |

A host that is the firewall of an OPNsense topology source also has its
health read over the source's API at every poll (CPU, memory, uptime,
file systems, temperature, state table), with no SNMP profile needed; the
API fills only what SNMP left empty (see
[OPNsense firewall metrics](#opnsense-firewall-metrics)).

Hosts with the platform `icmp_only` get the ping only. The CPU and memory
OIDs depend on the host's platform; the built-in list is on **Configure >
OID Profiles** under **Built-in Vendor OIDs**.

A poll is marked failed when the SSH session fails and SNMP returned no CPU
and no up interface, or when an ICMP-only host does not answer the ping.
When ICMP is not available, the response time is the time the poll took.

A host whose poll times out or raises an error is skipped for 1, 2, 4 and
then at most 8 cycles. **Poll Now** always polls every host.

### Metrics collected

Each poll writes these metric samples, which feed the charts, custom
dashboard panels and graph templates:

| Metric | Meaning |
|---|---|
| `cpu_percent`, `memory_percent` | CPU and memory use in % |
| `memory_used_mb`, `memory_total_mb` | Memory in MB |
| `uptime_seconds` | Device uptime |
| `response_time_ms`, `packet_loss_pct` | Ping round trip and loss |
| `if_up_count`, `if_down_count` | Interfaces up, and down but not admin down |
| `vpn_tunnels_up`, `vpn_tunnels_down` | VPN tunnels |
| `route_count` | Routes in the global table |
| `if_in_errors`, `if_out_errors`, `if_in_discards`, `if_out_discards` | Interface counters, with `_rate` versions per second |
| `module_down` | Hardware modules down (only when the poll read the module table) |
| `power_supply_down`, `fan_down`, `temperature_alarm` | Power supplies down, fans down, temperature sensors in alarm (each only when the poll read a table for it) |
| `bgp_peer_down`, `ospf_neighbor_down` | BGP peers down, OSPF neighbors down (each only when the poll read the table) |

Interface traffic is stored separately per interface and shown on the
device detail page.

### Hardware module health

The SNMP part of the poll also reads the operational state of a chassis's
modules (line cards, supervisors, sub-modules), so a module that failed,
or never came back after a reload, raises an alert even when its syslog
message was lost:

| Platform | Read |
|---|---|
| Cisco IOS, IOS XE, NX-OS, IOS XR | `cefcModuleOperStatus` (CISCO-ENTITY-FRU-CONTROL-MIB), names and models from ENTITY-MIB |
| Juniper Junos | `jnxFruState` (JUNIPER-MIB `jnxFruTable`), the FRUs that are modules (FPC, PIC, routing engine, control and fabric boards); not fans or power supplies |

Any other platform is not asked. A healthy chassis costs one SNMP walk per
poll; the names are read only for the modules that are down.

A module that is not working (Cisco: failed, missing, mismatched,
diagnostics failed, powered down, power denied, out of service for
temperature, firmware mismatch or download failure; Juniper: offline)
raises one `module_down` alert of its own, critical, with a message such
as `Slot 3 (LC-48X-EXAMPLE) is failed`, so a second module failing is a
new alert and a new notification. A module that is booting, in self test,
syncing, upgrading or in another passing state neither raises an alert nor
resolves an open one. A module an operator disabled or took offline is not
an alert. The alert is resolved (`auto-resolved`) at the first poll that
reads the module OK, disabled by an operator, or no longer in the table. A
poll that read no module table (SNMP off or timed out, a device without
the MIB) raises and resolves nothing; an empty module table resolves the
open module alerts at the third empty poll in a row (see
[Cost of the health reads](#cost-of-the-health-reads)).

Not covered: a module that leaves the table without ever reading not OK,
stack members (CISCO-STACKWISE-MIB) and supervisor redundancy
(CISCO-RF-MIB). Per platform, see
[Hardware module health](vendor-monitoring-coverage.md#hardware-module-health).

### Power supplies, fans and temperature

The SNMP part of the poll reads the state of the power supplies, fans and
temperature sensors, so a failed supply or fan, or a hot sensor, raises an
alert without a syslog message or a trap:

| Platform | Power supplies | Fans | Temperature |
|---|---|---|---|
| Cisco IOS, IOS XE, NX-OS, IOS XR, ASA, FTD | `ciscoEnvMonSupplyState` (CISCO-ENVMON-MIB), else `cefcFRUPowerOperStatus` (CISCO-ENTITY-FRU-CONTROL-MIB) of the entities of class power supply | `ciscoEnvMonFanState`, else `cefcFanTrayOperStatus` | `ciscoEnvMonTemperatureState`, else the thresholds of the celsius sensors (CISCO-ENTITY-SENSOR-MIB `entSensorThresholdEvaluation`) |
| Juniper Junos | `jnxFruState` of the power FRUs (JUNIPER-MIB `jnxFruTable`, the same walk as the modules) | `jnxFruState` of the fan FRUs | Not read |
| Arista EOS | `entStateOper` (ENTITY-STATE-MIB) of the power supply entities | `aristaFanStateOper` (ARISTA-ENTITY-SENSOR-MIB) | `entStateAlarm` (ENTITY-STATE-MIB) of the celsius sensors |
| PAN-OS | `entStateOper` of the power supply entities | `entStateOper` of the fan entities | `entStateAlarm` of the celsius sensors |
| Fortinet FortiOS | `fgHwSensorEntAlarmStatus` (FORTINET-FORTIGATE-MIB) of the sensors named as a supply | the same, sensors named as a fan | the same, sensors named as a temperature |
| HPE Aruba AOS-Switch | `hpicfSensorStatus` (HP-ICF-CHASSIS) of the power supply sensors | the same, fan sensors | the same, temperature sensors |
| HPE Aruba AOS-CX | `arubaWiredPSUStateEnum` (ARUBAWIRED-POWERSUPPLY-MIB) | `arubaWiredFanStateEnum` (ARUBAWIRED-FAN-MIB) | Not read |
| Netgear managed switches (`netgear_prosafe`) | `boxServicesPowSupplyItemState` (NETGEAR-BOXSERVICES-PRIVATE-MIB) | `boxServicesFanItemState` | `boxServicesTempSensorState` |

Any other platform is not asked. One alert per supply, fan or fan tray, or
sensor: `power_supply_down` (critical, as the power supply syslog rule),
`fan_down` (warning, as the fan syslog rule) and `temperature_alarm`
(warning or critical, as the device's sensor state or crossed threshold
says; warning where the device gives no severity, as on FortiOS). The
alert is resolved at the first poll that reads the item OK, turned off or
locked by an operator, or no longer in the table. An empty bay (not
present, empty) is not an item. A state on its way somewhere (unknown,
testing, initializing, a sensor that does not work) neither raises nor
resolves. A poll that read no table raises and resolves nothing; a table
read empty counts as "no items" only after three polls in a row (see
[Cost of the health reads](#cost-of-the-health-reads)).

Limits: a supply pulled from its bay leaves the table (its alert resolves);
FortiOS sensors are told apart by their names, as the MIB gives no type;
Juniper and AOS-CX temperatures are not read (no per-sensor state in the
MIB); Aruba Instant On and Netgear smart switches are not read. OPNsense
temperature is read over its API (see
[OPNsense firewall metrics](#opnsense-firewall-metrics)). Per platform, see
[Power supplies, fans and temperature](vendor-monitoring-coverage.md#power-supplies-fans-and-temperature).

### BGP peers and OSPF neighbors

The SNMP part of the poll reads the state of the BGP peers and OSPF
neighbors of every SNMP-polled host except a UPS: the standard BGP4-MIB
and OSPF-MIB, and where the vendor has a peer table that also lists IPv6
peers, that table first:

| Platform | BGP | OSPF |
|---|---|---|
| Cisco | `cbgpPeer2State` (CISCO-BGP4-MIB), else `bgpPeerState` (BGP4-MIB) | `ospfNbrState` (OSPF-MIB) |
| Juniper Junos | `jnxBgpM2PeerState` (BGP4-V2-MIB-JUNIPER), else `bgpPeerState` | `ospfNbrState` |
| Arista EOS | `aristaBgp4V2PeerState` (ARISTA-BGP4V2-MIB), else `bgpPeerState` | `ospfNbrState` |
| Any other SNMP platform | `bgpPeerState` | `ospfNbrState` |

One critical alert per peer (`bgp_peer_down`) or neighbor
(`ospf_neighbor_down`), as the BGP and OSPF syslog rules, with a message
such as `BGP peer 192.0.2.1 (AS 64500) is active`.

- **BGP.** A peer not established is down. A peer an operator stopped
  (`neighbor ... shutdown`) is not an alert and resolves one. A peer that
  has never been established is not alerted: neither the device's
  established-transitions counter nor Plexus has seen it up, as for a peer
  configured ahead of its turn-up or a decommissioned one left in the
  configuration. Once a peer has been up it alerts until it is established
  again, shut down, or removed from the configuration. A suppression on
  `bgp_peer_down` silences a whole host.
- **OSPF.** Full and 2-way are healthy: two routers on a broadcast segment
  that are neither designated router nor backup stay in 2-way by design,
  and the neighbor table does not say the network type, so 2-way counts as
  healthy on every link. Any other state (down, attempt, init, exchange
  start, exchange, loading) raises an alert when a neighbor is in it at two
  polls in a row. A neighbor whose adjacency drops leaves the table, so a
  neighbor Plexus has seen healthy that is gone from the table is down too
  (`gone from the neighbor table`, also after two polls). It is remembered
  for 24 hours after it was last seen healthy; then its alert resolves.

Limits: OSPFv3 neighbors, and BGP peers in Cisco VRFs that only an SNMP
context shows, are not read. Plexus's memory of the peers and neighbors it
has seen up is lost on a restart: a neighbor that is gone at that moment
has its alert resolved at the next poll.

### Cost of the health reads

Each table is one walk of its state column per poll; names and details are
read with GETs only for the items that are not OK (and, where a table mixes
kinds, the class or type of those items). Per poll and host, in walks:
Cisco IOS and IOS XE 6 (modules, supplies, fans, temperature, BGP, OSPF),
Juniper 3, Arista 5, PAN-OS 4, FortiOS and AOS-Switch 3, AOS-CX 4, Netgear
5, any other SNMP platform 2. The reads run at the same time. A health
walk may return up to 5,000 rows; one that reaches that is treated as cut
short.

Empty tables are handled the same way for every check:

- A walk cut short (a timeout, the row limit) is "not read": it raises
  and resolves nothing, and does not count as empty.
- A table read to its end with no row is "not read" too until it has been
  empty at three polls in a row (a device polled just after a reload may
  answer a hardware table empty before it fills it, so the next poll
  reads it again). From the third, it is "no items": the open alerts of
  its check on the host resolve, nothing is raised, and no metric sample
  is written.
- A table that has never had rows on the host, once empty at three polls
  in a row, is not walked again for an hour: a missing MIB (NX-OS: the
  CISCO-ENVMON-MIB tables, then read from the FRU and sensor tables)
  costs one walk an hour, and a table that starts answering (a first BGP
  peer) is read within the hour. A table that has had rows is walked at
  every poll.
- The OSPF neighbor table is read as it is: when the host's last neighbor
  leaves it, the empty table goes through the two-poll and gone rules at
  once.

The memory is kept in the server process; a restart starts it over.

### OPNsense firewall metrics

An inventory host that is the firewall of an OPNsense topology source (see
[OPNsense in the Topology Map](opnsense-topology.md#health-and-services))
gets these samples too, read over the source's API:

| Metric | Meaning |
|---|---|
| `fw_disk_used_pct` | Use of the fullest file system in % |
| `fw_temperature_c` | The hottest temperature sensor in °C |
| `fw_pf_states`, `fw_pf_states_pct` | State table entries, and their share of the limit in % |
| `fw_load_avg_1m` | Load average over 1 minute |

Two built-in alerts come with them: `fw_disk_full` when a file system is
at 90 % or more (critical from 95 %) and `fw_state_table` when the state
table is at 80 % or more of its limit (critical from 95 %). Each resolves
at the first poll below its threshold.

The same poll also reads the firewall's VPN byte counters (when the
source's **VPN tunnels** option is on) and stores the traffic rate of each
tunnel since its previous reading, under the tunnel's integration entity
(see [Tunnel traffic](opnsense-topology.md#tunnel-traffic)). So a tunnel
of a firewall in the inventory gets a traffic sample every poll, not
only every collection.

With the source's **IDS alerts** option on, the poll also reads the
firewall's intrusion detection (Suricata) alerts newer than the newest one
stored and keeps them as security events (see [Security](#security)), so
an IDS alert reaches Plexus within one poll interval.

## Using the Monitoring page

### Devices

The tiles show **Hosts**, **Avg CPU**, **Avg Mem**, **IF Up**, **IF Down**,
**VPN Up**, **VPN Down**, **Routes** and **Open Alerts**. Each host row
shows its last poll; **Detail** opens the device detail page and **History**
lists the last 50 polls. **Poll Now** polls every host now and shows the
progress per host. The tab refreshes every 60 seconds.

### Alerts

1. Filter by **Search alerts…**, severity (**Critical**, **Warning**,
   **Info**) and **Unacknowledged** / **Acknowledged** / **All**. **Route
   churn** shows only route table change alerts; their **Route history**
   button lists the stored route snapshots.
2. Click **Acknowledge** on an alert, or tick alerts and use **Acknowledge
   Selected** or **Acknowledge All** (all unacknowledged alerts the filters
   show).

A row shows the severity, **Escalated** when it was escalated, **Nx** when
the same condition was seen N times, the host, the metric, the message,
**Created** and **Last seen**, and the rule number when a rule raised it.

Alerts come from these sources:

| Source | Metric | Severity |
|---|---|---|
| CPU or memory at or above the threshold in **Settings > Monitoring** (default 90%) | `cpu`, `memory` | Warning, critical at 95% or more |
| Interfaces down but not admin down | `interface_down` | Warning |
| VPN tunnels down | `vpn_down` | Warning |
| A hardware module not working (one alert per module) | `module_down` | Critical; see [Hardware module health](#hardware-module-health) |
| A power supply or fan down, a temperature sensor in alarm (one alert per item) | `power_supply_down`, `fan_down`, `temperature_alarm` | Critical; warning; the device's; see [Power supplies, fans and temperature](#power-supplies-fans-and-temperature) |
| A BGP peer or OSPF neighbor down (one alert per peer or neighbor) | `bgp_peer_down`, `ospf_neighbor_down` | Critical; see [BGP peers and OSPF neighbors](#bgp-peers-and-ospf-neighbors) |
| Route table changed between full reads | `route_churn` | Warning, critical for a change of 10 routes or more |
| Alert rules | the rule's metric | the rule's severity |
| SLA targets (of hosts, and of integration entities such as OPNsense gateways) | `sla_<metric>` | see [SLA monitoring](sla-monitoring.md) |
| A configuration change of an OPNsense firewall that made a filter rule any-to-any or shadowed | `opnsense_rule_any_any`, `opnsense_rule_shadowed` | Warning, info for a redundant shadow; see [Rule change alerts](opnsense-topology.md#rule-change-alerts) |
| Baseline deviations, Meraki alerts, Cato egress and shared host findings, integration entities | various | see the linked guides |

While an alert is unacknowledged, the same condition on the same host only
raises its count and **Last seen**; a notification is sent only for a new
alert. After you acknowledge it, the next occurrence opens a new alert.
There is no **Resolve** button: an alert stays open until someone
acknowledges it. Hardware module alerts, Meraki alerts, Cato egress and shared host findings and integration
entities acknowledge their own alerts as `auto-resolved` when the condition
clears.

**Escalation.** When **Escalation enabled** is on, an unacknowledged alert
that is not critical becomes critical (or the rule's escalation severity)
after **Escalate after (min)**, default 30. It is escalated once.

**Muting** applies only to integration entities (sites, uplinks, tunnels,
cloud links): see [Muting](meraki-topology.md#muting). For inventory hosts
use acknowledge and suppressions.

### Alert rules (Configure > Alert Rules)

1. Click **+ New Rule**.
2. Fill in **Name**, **Metric**, **Operator** (`>=`, `>`, `<=`, `<`, `==`,
   `!=`), **Value** and **Severity** (Warning or Critical).
3. Optionally set **Scope: Group** or **Scope: Host (overrides group)**.
   Without scope the rule applies to all hosts.
4. Tick **Notification Channels**, or leave all unticked to use the default
   channel set.
5. Click **Create**. **Edit**, **Disable** / **Enable** and delete are on
   each rule.

| Metric in the form | Value compared |
|---|---|
| CPU % | CPU use |
| Memory % | Memory use |
| Interfaces Down | Interfaces down but not admin down |
| VPN Tunnels Down | VPN tunnels down |
| Hardware Modules Down | Hardware modules down (Cisco and Juniper) |
| Route Count | Routes in the global table |
| Uptime (seconds) | Device uptime |
| Firewall disk used %, temperature, state table entries, state table %, load average | The [OPNsense firewall metrics](#opnsense-firewall-metrics) |

A rule is checked against every poll of the hosts in its scope. A rule on a
metric the poll has no value for (for example CPU without SNMP) never fires.

### Suppressions (Configure > Suppressions)

Click **+ New Suppression** and fill in **Name**, **Starts At**, **Ends At**
(default: now to 2 hours from now), **Scope: Group**, **Scope: Host**,
**Metric (blank = all)** and **Reason**. While it is active, matching alerts
are not raised; the poll data is still stored. Each suppression shows
**Active**, **Scheduled** or **Expired**. Expired suppressions are deleted
by the retention cleanup.

### Events

The syslog messages and SNMP traps Plexus received, filtered by
**Severity**, **Type** (**Syslog** or **SNMP Trap**) and **Search**, with
the counts **Total Events**, **Critical+**, **Errors** and **Warnings**. The
receivers listen on UDP 1514 (syslog) and 10162 (traps). They are off until
an admin turns them on in **Settings > Syslog & Traps** (see
[administration.md](administration.md#syslog--traps)); after that they start
with Plexus. The Docker stack publishes host port 162 to the trap receiver
and 1514 to the syslog receiver; for devices that can only send syslog to
UDP 514, publish `514:1514/udp` as well. Syslog can also arrive over TCP
(1514) and TLS (6514), whose source address cannot be forged; each
event records how it arrived (`transport`: `udp`, `tcp` or `tls`, see
[syslog-rules.md](syslog-rules.md#transports)).

By default only datagrams whose source is an inventory host address are
received (the listener source allowlist, with a per-source rate limit:
[administration.md](administration.md#listener-sources)), and an SNMPv1 /
v2c trap from an inventory host is stored only when it carries the SNMP
community stored for that host (its SNMP profile, else its group's
settings), for every vendor alike; an SNMPv3 trap from an inventory host
is decoded and stored only when it passes the SNMPv3 checks with the
host's SNMPv3 poll user ([SNMP Traps](snmp-traps.md#snmpv3)).
**Upgrading:** sources that are not inventory hosts, traps whose community
differs from the host's polling community, and SNMPv3 traps from an
inventory host that fail the SNMPv3 checks (stored undecoded before) are
dropped by default; they are counted in the receiver settings
(`syslog_dropped_source`, `trap_dropped_community`, `trap_dropped_v3`,
...).

A trap is stored with its name and decoded varbinds from the trap registry
(`linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up,
ifOperStatus down`); with **Type** set to **SNMP Trap** the table shows
the trap name (its OID on hover, or the OID itself for a trap the registry
does not know, whose varbinds read `oid = value`). An SNMPv2c inform is
stored the same way and acknowledged with a Response. See
[SNMP Traps](snmp-traps.md) for the traps named per vendor.

Syslog from inventory hosts can also raise alerts, start a config backup
and drift check, and trigger an immediate re-poll: see
[Syslog Rules](syslog-rules.md). Traps from inventory hosts do the same
through the built-in trap rules, as their own alert family (metric
`trap_<rule>`): see [SNMP Traps](snmp-traps.md).

### Security

The security events integrations read from a device: today the intrusion
detection (Suricata) alerts of OPNsense firewalls
([IDS alerts](opnsense-topology.md#ids-alerts)), read with every
collection of the firewall's topology source, every monitoring poll of a
firewall that is an inventory host, and right away when the firewall
forwards a Suricata alert over syslog. Filter by **Window** (last hour,
24 hours, 7 or 30 days), **Severity** (critical: priority 1, warning:
priority 2, info: priority 3 and up, unknown), **Action** (**Blocked** or
**Detected only**) and **Search** (signature, signature id, category or
address); the tiles count the matching events by severity and how many
were blocked. The list shows 100 events a page, newest first, and
refreshes every minute.

Alerting happens on the server, not in this list: one alert per firewall
and signature for critical and warning events (alert type
`security_event`, metric `ids_alert`), on the firewall's host in the
**Alerts** tab when it is an inventory host, else to the notification
channels. It is counted on every read that brings new events of the
signature, says whether the traffic was blocked or only detected, and
resolves after an hour without a new event of the signature. A mute of the
firewall in the Availability tab, or a suppression of its host (all
metrics or `ids_alert`), covers these alerts. Events older than the
monitoring retention (**Retention days**) are deleted, and at most 50,000
are kept per source.

### Availability

Choose the **Period** (**Last 24h**, **Last 7 days**, **Last 30 days**).
**Polled hosts** shows **Hosts Tracked**, **Currently Up**, **Currently
Down**, **Avg Uptime** and **Outages**, and the sub-tabs **Hosts**,
**Outages** and **Transitions**, filtered by **Group**. Every poll records
a transition when a host (poll ok or failed) or an interface (up or down)
changes state; an outage with no end is **Ongoing**.

Below it, **Integrations and cloud** shows the same for the entities that
Meraki, Cato, FMC, Panorama, Appgate, OPNsense, AWS, Azure and GCP report; see
[Availability tracking](meraki-topology.md#availability-tracking). An
OPNsense firewall's certificates in use are listed there too (type
**Certificate**), degraded from 30 days before they expire and alerted per
expiry tier (warning from 30 days, critical from 7 days and once expired;
see [Certificates](opnsense-topology.md#certificates)). Its
**Avg traffic** column gives the mean traffic in and out of the entities
whose vendor reports byte counters (OPNsense tunnels and OpenVPN servers,
see [Tunnel traffic](opnsense-topology.md#tunnel-traffic)), and
**Measurements** opens the charts of what is measured for an entity: the
latency, jitter and loss of an OPNsense gateway, the traffic in and out of
a tunnel (an average between two readings: the monitoring polls of a
firewall in the inventory, else its collections). The
**Meraki alerts**, **Cato egress vs cloud allow-lists** and
[**Cato shared hosts vs Azure**](cato-topology.md#shared-hosts-check-azure)
panels follow.

### Capacity

Choose a **Metric** (CPU %, Memory %, Route Count, Interfaces Up, VPN
Tunnels Up), a **History** of 30, 90, 180 or 365 days, a **Group** and a
**Threshold**. Plexus fits a straight line through the daily averages of
each host, projects it forward, and lists in **Est. Date** when each rising
host reaches the threshold.

## The device detail page

Open it with **Detail** on the Devices tab or a tile on the Dashboard.
**← Devices** goes back. It uses the time range bar at the top right.

The info bar shows **Hostname**, **IP**, **Type**, **Liveness**, **CPU**,
**Memory**, **Interfaces** (up / down / admin down), **Uptime** and **Last
Poll**, and the matching IPAM subnet when there is one.

| Liveness | Meaning |
|---|---|
| Healthy (with the ping time) | Ping answered and the SNMP/SSH poll returned CPU |
| ICMP up, SNMP/SSH not responding | Ping answered, but no CPU came back: check credentials, ACLs or the SNMPv3 engine ID |
| Unreachable (no ICMP reply) | No ping reply |
| ICMP disabled | ICMP did not run |

| Tab | Shows |
|---|---|
| **Overview** | CPU %, Memory %, Response Time (ms) and Packet Loss (%) charts |
| **Interfaces** | Every interface with status, speed, in, out and utilization, traffic charts for the 12 busiest, and the interface addresses |
| **Interface Errors** | Error and discard counts, trend charts and error events |
| **Flow** | Flow records this device exported (hidden when Traffic Analysis is hidden) |
| **Alerts** | The last 50 alerts of the host; **Correlate** lists deployments and configuration drift in the 30 minutes before the alert |
| **Compliance** | The latest compliance scan results of the host |
| **Syslog** | The last 100 syslog messages from the host |

## Rules worth knowing

- **Defaults:** interval 300 seconds (60 to 86400; up to 5% random delay is
  added), CPU and memory thresholds 90%, poll history 30 days.
- **Retention:** polls, alerts and route snapshots are deleted after
  **Retention (days)** (1 to 365), checked at most once an hour after a poll
  cycle. Metric samples are kept 48 hours, hourly rollups 30 days and daily
  rollups 365 days; interface traffic and syslog / trap events 30 days;
  interface error events 90 days.
- **Poll Now** runs even when polling is not enabled.
- **One manual poll at a time.** While a **Poll Now** from any user (or
  the admin run-now) runs, another one is refused with "A manual monitoring
  poll is already running. Try again when it finishes." (`409`). The
  scheduled cycle is not affected and does not block **Poll Now**.
  A device is still polled by one of the two at a time: the poll that
  reaches it second waits for the first and uses its reading.
- **Known gaps:** the **Cooldown (min)** of a rule and of **Settings >
  Monitoring**, and a rule's **Escalate After** time, are saved but the
  poller does not read them: repeats are folded by the open alert and
  escalation uses the global wait. Custom **OID Profiles** are stored, but
  the poller reads the built-in vendor OIDs and the overrides an admin adds
  through `/api/metrics/vendor-oids`.
- **Deleting a host** deletes its polls, alerts, metric samples and host
  graphs.

## Who can do what

| Action | Needs |
|---|---|
| See every Monitoring tab and the device detail page | `monitoring` |
| Poll Now, acknowledge alerts, manage rules and suppressions, mute entities | `monitoring.write` |
| OID profiles | `monitoring` |
| Settings > Monitoring, Settings > Syslog & Traps (the syslog and trap receivers), vendor OID overrides | Admin |
| Graph templates, host templates and graph trees | `graph-templates` |
| Device detail **Compliance** and **Flow** tabs | `compliance`, `traffic-analysis` |

Acknowledging, rules, suppressions, Poll Now and settings changes are
written to the audit log under `monitoring`.

## API

The full list is in [API reference](api-reference.md).

| Method and path | Purpose |
|---|---|
| `GET /api/monitoring/summary`, `GET /api/monitoring/polls` | Tiles and the latest poll per host |
| `GET /api/monitoring/polls/{host_id}/history?limit=` | Poll history of one host |
| `GET /api/monitoring/alerts?acknowledged=&severity=&host_id=` | Alerts |
| `POST /api/monitoring/alerts/{id}/acknowledge`, `POST /api/monitoring/alerts/bulk-acknowledge` | Acknowledge one, or up to 1000 |
| `GET/POST /api/monitoring/rules`, `PUT/DELETE /api/monitoring/rules/{id}` | Alert rules |
| `GET/POST /api/monitoring/suppressions`, `DELETE /api/monitoring/suppressions/{id}` | Suppressions |
| `POST /api/monitoring/poll-now`, `POST /api/monitoring/poll-now/stream` (progress as server-sent events) | Poll every host now; `409` while another manual poll runs |
| `GET /api/availability/summary?days=`, `/outages`, `/transitions` | Host availability |
| `GET /api/monitoring/security-events?hours=&severity=&action=&q=&host_id=&limit=&offset=` | Security events (IDS alerts), newest first, with counts |
| `GET/PUT /api/admin/monitoring` | Polling settings (admin) |

Create a rule for one group:

```json
POST /api/monitoring/rules
{
  "name": "Branch CPU high",
  "metric": "cpu",
  "operator": ">=",
  "value": 85,
  "severity": "warning",
  "group_id": 3,
  "channel_ids": ["ops-email"]
}
```

The answer is `{"id": 7}`. A missing name or metric, or an unknown
operator, gives `400`. Acknowledging several alerts takes
`{"alert_ids": [101, 102, 103]}` and answers
`{"ok": true, "acknowledged": 3}`.
