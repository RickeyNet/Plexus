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
loss a vendor reports for an entity (raw samples plus daily rollups kept for
the SLA retention), and SLA targets with a `provider` are evaluated on the
server in the scheduled SLA pass for the tracked entities they cover
(uptime for every entity; latency, jitter and loss where the vendor reports
them) into `monitoring_alerts` / notification channels
(`netcontrol/routes/topology_sla.py`, `docs/sla-monitoring.md`).

| Vendor / source | Entities tracked | State source | Latency / loss / jitter | SLA targets | Notes |
|---|---|---|---|---|---|
| Cisco IOS / IOS XE / IOS XR / NX-OS / ASA (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. |
| Cisco FTD via FDM REST | host, interfaces | FDM API poll into the same pipeline | Partial (ICMP if reachable) | Yes | `netcontrol/integrations/cisco_fdm`. |
| Cisco FTD / ASA via FMC | FTDs; uplinks, site-to-site tunnels, HA and cluster links | FMC snapshot status, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Full pipeline when the FTD is an inventory host. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as `cisco_ftd` hosts polled over SNMP. |
| Cisco Meraki | devices (MX/MS/MR/MG/MV/MT); uplinks, AutoVPN and IPsec tunnels | `devices/statuses`, `uplinks/statuses`, `appliance/vpn/statuses` in the org snapshot, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No (uplink loss/latency API not collected) | Uptime only (topology SLA targets) | Candidate: `devices/uplinksLossAndLatency`. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts (ping latency, loss and SLA targets on the LAN address). Near-real-time alerts as well: assurance alerts polled every 60 s and an optional webhook receiver, persisted in `meraki_alerts` and raised server-side into `monitoring_alerts` / notification channels (`docs/meraki-alerts.md`). They alert; they do not feed the availability history or uptime %. |
| Cato Networks | sites, Sockets and IPsec sites; Socket uplinks, tunnels | `accountSnapshot` connectivityStatus / operationalStatus / tunnel state, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No (`accountMetrics` not collected) | Uptime only (topology SLA targets) | Candidate: `accountMetrics` per link for loss/latency/jitter. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts, when the Socket reports a LAN address. |
| AWS | instances, Transit Gateways, NAT and Direct Connect gateways; site-to-site VPN connections, Direct Connect circuits, VPC peerings, TGW/VGW attachments | resource state fields in the account discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | No AWS Health integration. Amazon FSx file systems and ONTAP SVMs, and the services with DNS endpoints (RDS / Aurora instances, clusters and proxies, load balancers, VPC endpoints, EFS, ElastiCache, OpenSearch, MSK, Redshift and Redshift Serverless): state collected (each optional, per region) and shown in the VPC details, not tracked (gap: they are listed, not drawn, and the availability tracker follows nodes and edges only; tracking them needs a non-node entity kind in the tracker). |
| Azure | VMs, VPN gateways, firewalls, NAT gateways; VPN connections, ExpressRoute circuits, VNet peerings, gateway attachments | provisioning / connection state fields in the account discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | No Resource Health / Service Health integration. |
| GCP | instances, Cloud Routers, HA VPN gateways, Cloud NAT, Interconnects; HA VPN tunnels, Interconnect attachments, VPC peerings | state fields in the project discovery, recorded by the hourly discovery loop | No | Uptime only (topology SLA targets) | |
| Palo Alto via Panorama | managed firewalls; uplinks, tunnels, HA links | Panorama snapshot status, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Full pipeline when the firewall is an inventory host. Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as `paloalto_panos` hosts polled over SNMP. |
| Appgate SDP | appliances, sites; appliance peer links | `/appliances/status` health, recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | No | Uptime only (topology SLA targets) | Its devices can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`, see `docs/meraki-topology.md#after-adding-a-source`), as ICMP-only hosts. |
| OPNsense | the firewall, OpenVPN server instances; gateways (as uplinks), IPsec connections, WireGuard peers and OpenVPN client instances (as tunnels) | `routes/gateway/status` (dpinger: `none` with monitor data up, `delay` / `loss` / `delay+loss` degraded, `down` / `force_down` down, no monitor data unknown), `ipsec/sessions/search_phase1` (SA or not) with `search_phase2` / `connections/search_child` (an SA whose configured child SAs are none installed: degraded), `wireguard/service/show` (`peer-status` online / stale / offline, else handshake age), `openvpn/service/search_sessions` (client state; server running or not), recorded per collection (scheduled, hourly by default, per-source interval or opt-out) | Gateways: Yes (dpinger RTT as latency, RTT deviation as jitter, loss; stored per collection, raw for the monitoring retention and daily rollups for the SLA retention). Tunnels and the firewall: none reported | Yes (topology SLA targets: uptime for every entity, latency / jitter / packet loss for gateways) | CARP VIPs (`diagnostics/interface/get_vip_status`) are shown in the firewall's details; a VIP in INIT or a non-zero demotion is a collection warning, not a tracked entity. Full pipeline when the firewall is an inventory host. The firewall can be imported into the inventory from the steps after adding the source (`/api/sources/{id}/import-devices`), as an `opnsense` host polled over SNMP (no SSH driver). The ARP / NDP tables feed MAC tracking (the inventory host's ARP table) and the DHCP leases (ISC, Kea, Dnsmasq) feed IPAM as an `opnsense` DHCP server; neither is an availability entity. `docs/opnsense-topology.md`. |
| Juniper / Arista / Fortinet / PAN-OS (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. |
| HPE Aruba AOS-CX / AOS-Switch (HP ProCurve) (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. CPU and memory: HP `STATISTICS-MIB` / `NETSWITCH-MIB` on AOS-Switch, HOST-RESOURCES-MIB on AOS-CX. `docs/aruba-switches.md`. |
| HPE Aruba Instant On 1830 / 1930 / 1960 (inventory) | host, interfaces | SNMP + ICMP poll (`aruba_instant_on`, no SSH: the switch has no command line) | Yes (ICMP) | Yes | Full pipeline over SNMP. The switch answers SNMP only in local management mode (v1/v2c read-only on the 1830); a cloud-managed one is ICMP only. CPU and memory only when it answers HOST-RESOURCES-MIB. |
| Netgear managed switches (M4250 / M4300 / M4350 / M4500) (inventory) | host, interfaces | SNMP + ICMP poll | Yes (ICMP) | Yes | Full pipeline. CPU and memory only when the switch answers HOST-RESOURCES-MIB (no built-in vendor OIDs: gap). Not run against a device yet. `docs/netgear.md`. |
| Netgear smart switches and access points (inventory) | host, interfaces | SNMP + ICMP poll (`netgear_smart`, `netgear_ap`, no SSH: no command line) | Yes (ICMP) | Yes | Full pipeline over SNMP. An access point answers SNMP only when it is enabled in standalone mode; one that offers none is ICMP only. No wireless client or radio data. |
| ICMP-only hosts | host | ICMP | Yes | Yes | |

### Muting and removal of API-collected entities

Both live in the shared topology availability tracker, so they behave the
same for every source (`docs/meraki-topology.md#muting`,
`docs/meraki-topology.md#removed-entities`). Inventory hosts use
acknowledge and Suppressions instead.

| Vendor / source | Mute (entity or site, server-side, no alert or notification while muted) | Removed when gone at the source | Faster than the next collection |
|---|---|---|---|
| Cisco Meraki | Yes | Yes: devices at any stored collection; uplinks and tunnels when no organization-wide call failed | Yes, for a device that had an open Meraki alert: confirmed with one API call by the alert poll, about a minute |
| Cato Networks | Yes | Yes, at a collection with no warnings and no site marked not collected | No |
| Cisco FMC, Palo Alto Panorama, Appgate SDP | Yes | Yes, at a collection with no warnings | No |
| OPNsense | Yes | Yes, at a collection with no warnings other than informational ones (an incomplete security audit, a pending firmware update, audit findings, config.xml not stored) | No |
| AWS, Azure, GCP | Yes | Partly: at a discovery with no warnings and no *not collected* network (a peered VPC or VNet outside the collected accounts and regions). One failed region or account, or one such peering, keeps everything of that cloud `unknown` until the retention cleanup. Gap: removal per account and region | No |

A removal that cannot be trusted (any other collection) leaves the entity
`unknown` until the retention cleanup, as before.

## Software versions and CVE advisories

The software tracker (`netcontrol/integrations/software/versions.py`,
`netcontrol/routes/software.py`) reduces every source's version string to one
platform key and version, matches devices against advisories, and opens
`software_alerts` with notification fan-out. Advisory sources are listed per
platform.

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
| OPNsense | OPNsense snapshot: `core/firmware/status` product version (platform `opnsense`); pending update shown and warned | The firewall's own security audit (`pkg audit -F` via `core/firmware/audit`), synced at each collection as advisories of source `opnsense-audit` (one per VuXML entry, affected version the firewall's version, CVE ids, link), upserted by id, limited to the firewall(s) whose audit reported them (`device_keys`) and withdrawn per firewall when its audit no longer reports them; only an audit that verifiably completed (pkg audit's result line, no fetch / database error) changes advisories; manual / import as well | Partial | Covers vulnerable FreeBSD packages installed on the firewall, not OPNsense's own security advisories (OPNsense publishes no version-matched vulnerability API). `pkg audit` gives no severity and Plexus has no CVE severity source (no NVD client): new advisories are `medium`, an administrator's severity is kept. |
| Juniper Junos | SNMP/SSH; SSH `show version` at inventory discovery / sync (model, version, hostname; serial needs `show chassis hardware`) | Manual / import | Manual | Candidate: Juniper JSA feed. |
| Arista EOS | SNMP/SSH; SSH `show version` at inventory discovery / sync | Manual / import | Manual | |
| Fortinet FortiOS | SNMP/SSH | Manual / import | Manual | Candidate: FortiGuard PSIRT feed. Discovery's SSH `show version` does not read FortiOS (`get system status`): gap. |
| HPE Aruba AOS-CX / AOS-Switch (HP ProCurve) | SNMP sysDescr; SSH `show version` at inventory discovery / sync (platforms `aos-cx`, `aos-switch`) | Manual / import | Manual | Gap: HPE publishes security bulletins but no version-matched vulnerability API. Candidate: the HPE Aruba Networking security advisory feed, matched by product family. |
| HPE Aruba Instant On | SNMP sysDescr (platform `instant-on`) | Manual / import | Manual | Same gap. No SSH on the switch, so the version comes from SNMP only. |
| Netgear managed switches | SNMP sysDescr; SSH `show version` at inventory discovery / sync (platform `netgear-managed`) | Manual / import | Manual | Gap: Netgear publishes security advisories as web pages, with no version-matched vulnerability API. |
| Netgear smart switches and access points | SNMP sysDescr (platforms `netgear-smart`, `netgear-ap`) | Manual / import | Manual | Same gap. No SSH, so the version comes from SNMP only; an access point's sysDescr seldom carries it (gap: the version is then not tracked). |

## Internet egress and cloud ingress (path trace)

How a flow that leaves one vendor to the internet is checked where it lands
in another (`netcontrol/integrations/pathtrace`, see `docs/path-trace.md`,
"Cato network rules and the egress address").

| Vendor | Egress address of a flow to the internet | Public address of a resource as a trace destination | Filtering checked against the post-NAT source | Notes |
|---|---|---|---|---|
| Cato Networks | Yes: INTERNET network rules (`policy.wanNetwork`) evaluated at the Cato Cloud; NAT gives the allocated IP (`popLocations.allocatedIpList`, else the allocated IP's name), several candidates checked each; VIA / OPTIMIZED / NONE give an unknown public address (a PoP's shared address is not reported); rules that match only by name are listed | n/a | n/a | Custom category contents are not in the API (reported as not collected); BACKHAUL egress is not traced past the site. |
| Cisco Meraki | Partial: uplink NAT when the deployment mode is collected | Yes: 1:1 NAT, port forwarding | Yes (inbound rules) | |
| OPNsense (inventory host with a config.xml backup) | Yes: automatic, hybrid and manual outbound NAT, source NAT rules and 1:1 NAT to the interface or target address | Yes: port forwards (wan address or a listed address) and 1:1 NAT | Yes: filter rules per interface in pf order (quick first, then last match), floating `out` rules | Read from the stored config.xml (`pathtrace/opnsense_config.py`); routes are the configured static routes and default gateway (no route capture, so a default-route-only destination is unknown); policy-based routing, VPN interface rules, bogons and NPTv6 are notes. Rule views and backup-to-backup rule diffs: `docs/opnsense-topology.md`. |
| AWS | n/a | Yes: EC2 instance public / Elastic IP on its interfaces, delivered to the private address at the internet gateway | Yes: network ACL and security groups; an unknown public source is unknown unless a rule allows every address | RDS, load balancers and the other services with DNS endpoints are collected and searchable (with their security group IDs and an NLB's Elastic IPs), but are not path trace destinations (gap). |
| Azure | n/a | Yes: VM public IP on its NIC | Yes: subnet and NIC network security groups | Load balancers, application gateways and Azure Firewall DNAT rules are not collected (gap). |
| GCP | n/a | Yes: instance external IP | Yes: VPC firewall rules | Load balancers are not collected (gap). |

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
| AWS | Security group inbound rules (CIDR sources); admission through network ACL + security groups | EC2 instances with a public or Elastic IP | Yes | Public RDS instances and internet-facing load balancers are collected but not checked (gap). Prefix-list and security-group sources are not Cato addresses and are skipped. |
| Azure | Subnet and NIC NSG inbound rules (CIDR sources, destination covering the VM) | VMs with a public IP | Yes | Azure Firewall DNAT, load balancers, application gateways: not collected (gap). Service tags are skipped. |
| GCP | VPC firewall ingress rules that target the instance (source ranges) | Instances with an external IP | Yes | Hierarchical / network firewall policies: not collected (an evaluation through them is unknown). Load balancers: gap. |

## Vendor alert feeds

Near-real-time ingestion of the vendor's own alerts, separate from the
collections that feed availability: the vendor tells Plexus about a problem
within about a minute instead of the next collection seeing it. Alerts are
persisted, deduplicated and raised server-side into `monitoring_alerts` (on a
matched inventory host) or the notification channels.

| Vendor / source | Alert feed | Status | Notes |
|---|---|---|---|
| Cisco Meraki | Assurance alerts polled every 60 s (`organizations/{id}/assurance/alerts`); optional webhook receiver (`POST /api/webhooks/meraki`) | Yes | `docs/meraki-alerts.md`. One alert per device and condition across both paths; device-down is not notified twice with the topology availability tracker. |
| Cato Networks | None | No | Gap. Candidates: the Cato events feed (`eventsFeed` GraphQL query, polled) and Cato's webhook / SIEM integrations. |
| AWS | None | No | Gap. Candidates: EventBridge rules (EC2 state change, VPN tunnel state, Direct Connect, AWS Health) delivered through SNS to an HTTPS receiver, or AWS Health API polling. |
| Azure | None | No | Gap. Candidates: Azure Monitor action groups (webhook action, common alert schema) for metric, activity log and Resource Health alerts; Resource Health API polling. |
| GCP, Cisco FMC, Palo Alto Panorama, Appgate SDP, OPNsense | None | No | Gap. Their state reaches Plexus only through the scheduled collection (topology availability tracker). OPNsense candidate: its monit alerts or syslog forwarding. |

## Known gaps, priority order

1. Cato `accountMetrics` (per-link loss, latency, jitter) into the topology
   availability tracker so Cato SLA targets can cover more than up/down.
2. Meraki `devices/uplinksLossAndLatency` for the same reason.
3. Latency / jitter / loss for more topology entities: SLA targets of
   topology entities exist (uptime for every entity), but only OPNsense
   gateways report measurements today (items 1 and 2 would add Cato and
   Meraki).
4. Cloud security findings: AWS Inspector / Security Hub and Azure Defender
   for Cloud mapped onto the advisory and alert model.
5. Cato Socket release-note import as a `cato-socket` advisory source.
6. NVD / CISA KEV enrichment of every advisory by CVE id (CVSS, known
   exploited flag).
7. Public endpoints that are not instances (AWS RDS and load balancers,
   now collected with their security groups, Azure load balancers and
   application gateways, GCP load balancers) as path trace destinations
   and egress check targets, so a Cato egress address is checked against
   their security groups too.
8. Vendor alert feeds for the other priority vendors: Cato (events feed),
   AWS (EventBridge / SNS / Health) and Azure (Monitor action groups /
   Resource Health). Near-real-time alert ingestion exists for Meraki
   only; everything else is seen at its next collection.
