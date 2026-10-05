# Changelog

## Unreleased

### Software
- Add a **Software** page (**Network → Software**, feature `software` / `software.write`) that tracks the software version of every device Plexus knows and alerts on vulnerable ones. The tracked set is built from inventory hosts (the version SNMP/SSH stored) and the devices of the latest topology collection of every Meraki organization (firmware per device), Cato account (Socket version) and AnyConnect FMC (FTD software, FMC version), each classified to a platform (Cisco IOS / IOS XE / IOS XR / NX-OS / ASA / FTD / FMC, Meraki MX / MS / MR / MG / MV / MT, Cato Socket, Junos, EOS, FortiOS, PAN-OS); a topology device that is an inventory host is listed once. Versions compare by their parts (`17.9.4a` > `17.9.4`, `15.2(7)E10` > `15.2(7)E8`), so **Version Spread** shows per platform how many devices run each version, the newest in the fleet and how many are behind it (**behind** badge); every rebuild records version changes with the previous version (**Recent Version Changes**, per-device **History**). **Advisories** are checked against every device: entered by hand or imported as JSON with a version specification grammar (exact, `17.9.*`, `<17.6.5`, `17.3..17.6.4`, comma-joined constraints, platform and model filters), or synced from **Cisco PSIRT openVuln** (admin; client ID and secret stored encrypted and write-only; one paced query per distinct tracked IOS/IOS XE/IOS XR/NX-OS/ASA/FTD/FMC/FXOS version, advisories stored with Cisco's severity, CVSS, CVEs, first fixed and URL; manual **Sync** as a background job or on a schedule). A device on an affected version opens a **Vulnerability Alert** (acknowledge; resolved when it no longer matches, reopened unacknowledged on a downgrade); new alerts at or above a configurable severity floor are sent to the notification channels as `software_vulnerability` alerts. The set is rebuilt every six hours (configurable), after every topology collection, and on **Refresh**. New `/api/software/*` routes and tables `software_versions`, `software_version_history`, `software_advisories`, `software_alerts`, `software_settings` (migration 0067). Guide: `docs/software-versions.md`.

### Topology
- One **Sources** button on the Topology toolbar replaces **Discover Neighbors** and **Meraki / Cato**. Its dialog lists everything that feeds the map in one table - CDP/LLDP neighbor discovery of the inventory, Meraki organizations, Cato accounts and the AWS accounts of Cloud Visibility - each with its last collection, status, warnings and a **Collect Now** button; **Collect All** refreshes every source the user may collect from, **Add Source** and **Load Sample** ask for the type first. AWS accounts are still managed under Cloud Visibility (the row links there, and discovery stays an administrator action); an AWS account that is on the map now says so on the Cloud Visibility accounts table. New `GET /api/topology/sources` returns the list (no credentials). The empty map offers the same dialog.
- Add Meraki support to the Topology map. Register a Meraki organization from the Topology toolbar (**Meraki**; Dashboard API key stored encrypted, write-only) and collect on demand: a rate-limited, read-only Dashboard API v1 collector gathers networks, devices, status, link-layer topology, LLDP/CDP, WAN uplinks, AutoVPN and non-Meraki VPN peers, VLANs, static routes, BGP/OSPF, switch ports and SVIs, firewall/NAT rules and SSIDs, with secrets (PSKs, IPsec/RADIUS secrets) scrubbed at collection. The latest collection of each organization is merged into `/api/topology` (all-groups view): Meraki devices, WAN uplinks and VPN tunnels join the existing graph as framed, pre-arranged sites, and a Meraki device or LLDP/CDP neighbor that is also an inventory host collapses into that host's node. Node details gain one tab per category of collected Meraki data (Device, Interfaces, VLANs, MAC/ARP, Routing, VPN, Firewall, Switching, Wireless), shown only when there is data for it; the toolbar search now also searches collected Meraki detail and can highlight every match on the map; a source filter narrows the map to inventory or Meraki. New **HTML** export renders the whole topology (inventory and Meraki, with collected interfaces, VLANs, neighbors and routes embedded) as one self-contained interactive file for sharing. Optional live SSH show commands (service credential) enrich inventory-matched nodes at collection time. The map now opens in a new default **Tidy tree** layout (left-to-right trees, one row per device, no physics) so it is readable without arranging anything; the previous layouts remain selectable. Large maps stay usable: sites are arranged in columns instead of one tall strip, VPN tunnels beyond 300 are drawn per selected device (toolbar **VPN Tunnels** draws all), and maps over ~600 devices drop glows and hide links while panning; the HTML export draws tunnels behind the site boxes and applies the same 300-tunnel rule. **Path Mode** now takes up to six devices, Meraki sites or subnets (picked from a list or typed as an IP address/network; a subnet stands for the appliance, L3 switch or non-Meraki VPN peer that owns it) and traces every pair hop by hop over the links that are up, warning when a tunnel on the path will not carry a picked subnet (also in the HTML export, as **Path**; new `GET /api/meraki/subnets`). MAC/ARP is filled from a per-network client collection (MAC, IP, VLAN, port, SSID; last 24 hours; option **Clients (MAC / IP)**, on by default). Collections run as background jobs with progress; a bundled sample organization previews the feature without an API key. New tables `meraki_orgs` / `meraki_topology_snapshots` (migration 0064). Guide: `docs/meraki-topology.md`.
- Show the subnets of the Topology collections on the IPAM page and find the ranges two sites both hold. `GET /api/ipam/overview` now adds the subnet index of the latest snapshot of every Meraki organization (VLANs, single LANs, switch SVIs, static routes), Cato account (network ranges) and AnyConnect FMC (address pools) as source `topology` (`include_topology=false` leaves them out; AWS is not listed twice, its VPCs and subnets stay cloud resources), with the sites that hold each subnet (`topology_sites_preview`, `topology_providers`) and Meraki/Cato VLAN IDs merged into `vlan_ids`. New `overlaps`: pairs of ranges held by two different owners (sites, or a site and a VPC/VNet) that are the same network or one inside the other, found by one sweep over the address space, with both sides, the relation and `vpn_conflict` when both sides are advertised into a VPN (the AutoVPN problem of two branches on the same user VLAN); `summary.overlap_count` / `vpn_overlap_count`, per-subnet `overlap_count`, first 500 pairs returned, VPN conflicts first. Static routes and subnets behind VPN peers are listed but not checked, and a range a site lists twice (VLAN and SVI) is not a pair. The IPAM page gains **Include Topology Subnets**, **Topology Subnets** and **Overlapping Ranges** summary cards (red when a VPN conflict exists), an **Overlapping Ranges** card, an overlap badge on subnet rows and a **Sites:** preview. The overview also now returns what the page was already rendering: cloud resource names (`cloud_resource_names_preview`, previously only a distinct CIDR count), `version`, `prefix_length`, `total_addresses`, and `allocated` / `reserved` / `available_address_count` (reservations counted), so the Subnet Inventory table no longer shows every subnet as 0 addresses with 0 available.
- Add Cisco AnyConnect remote access VPN to the Topology map, read from the FMC that manages the FTD headends. An FMC is registered from the **Sources** dialog (**Add Source → AnyConnect (FMC)**; `POST /api/meraki/orgs` with `provider: "anyconnect"`, the FMC address as `base_url`, the domain as `org_id`, the API username in `options` and the password as the write-only `api_key`, stored encrypted; `https` host only, redirects never followed, optional `verify_tls`) and collected on demand by a read-only, paced FMC REST client (token login, one sign-in per collection, retried on rate limit, 120 requests per minute respected): device records, remote access VPN policies and their policy assignments, connection profiles, address assignment and access interface settings, IPv4 address pools, the physical and sub-interfaces of each headend, and the connected sessions from `health/ravpnsessions` (FMC 7.3+, best-effort). Every FTD with a remote access VPN policy is drawn as a site box holding the device (health as the border), a WAN stub per access interface with the interface's address, and one **AnyConnect users (N)** node listing the connected users (assigned IP, public IP, profile, group policy, client, OS, login time); the policy's address pools are the site's **VPN address pools**, so they can be picked in Path Mode and are found by search. The FMC is one node in its own box, joined to each headend by a dotted **Managed by FMC** link (new edge protocol `management`) that Path Mode, the tidy-tree layout and the HTML export's path finder ignore. An FTDv in AWS is matched to its instance by the private address of its access interface, like a vMX behind a NAT gateway, when its FMC model is virtual; a headend that is an inventory host becomes that host. **Test Login** signs in and lists the domains the user can see; **Load Sample → AnyConnect** adds a demo FMC whose two headends are the FTDv instances of the demo AWS account. Guide: `docs/anyconnect-topology.md`.
- Add Cato Networks to the Topology map. A Cato account is registered from the same toolbar dialog as a Meraki organization (now **Meraki / Cato**; `POST /api/meraki/orgs` with `provider: "cato"`, account ID and API key, key stored encrypted and write-only, API host restricted to `catonetworks.com`) and collected on demand by a read-only, paced GraphQL client: `accountSnapshot` for sites, Sockets, WAN links, PoPs, HA state and connected remote users, and `entityLookup` for the network ranges of every site. The result uses the Meraki snapshot format, so it is merged into `/api/topology` and covered by node details, deep search, Path Mode (sites and subnets; paths run Socket → PoP → Cato Cloud → PoP → Socket) and the HTML export with no separate code path: each site is a framed box with its Socket(s) and WAN links, the PoPs in use and a backbone node form a **Cato Cloud** box, and connected remote users are one node with the users listed and searchable behind it. Everything but the site list is best-effort and a refused detailed query falls back to a reduced one, with Cato's error message in the collection report. New `meraki_orgs.provider` column (migration 0066); `POST /api/meraki/sample?provider=cato` adds a demo account. Guide: `docs/cato-topology.md`.
- Add AWS to the Topology map. Every enabled AWS account that Cloud Visibility has discovered is built into one snapshot in the Meraki snapshot format and merged into `/api/topology`, so it is covered by node details, deep search, Path Mode and the HTML export with no separate code path, and follows each new discovery (manual or scheduled). Each VPC is a framed site whose router node owns the VPC's subnets, with its internet, NAT and virtual private gateways; transit gateways, Direct Connect and customer gateways form an **AWS transit and VPN** box; attachments and peerings are a new link type (`protocol: "cloud"`), and a site-to-site VPN is a tunnel that is down only when all of its tunnels are. Instances are nodes only when they forward traffic (source/destination check off) or are inventory hosts; the rest are listed and searchable in their VPC. The AWS collector additionally reads subnets, instances with their interfaces, customer gateways, VPN tunnel status, route table routes and Direct Connect virtual interfaces and gateways; these map sections are best-effort (a denied call is recorded as a `collection_warning` resource and reported, not fatal), and VPN pre-shared keys are never read. Snapshots of different integrations are now joined by public IP address: a customer gateway or non-Meraki VPN peer becomes the device that answers on its address, a cloud instance becomes the Meraki or Cato virtual appliance on its public IP, and a VPN seen from both ends is one link. Path Mode can pick VPCs and their subnets. `POST /api/meraki/sample?provider=aws` (**Load AWS Sample**) adds a demo AWS account; the AWS sample discovery is now three VPCs with a transit gateway, a firewall pair, a VPN and a Direct Connect. The AWS account form explains how discovery signs in. Guide: `docs/aws-topology.md`.
- Check AWS routing and filtering in Path Mode. For a pair of subnets or IP addresses with an end in a VPC, Plexus now decides whether AWS carries and permits the flow, in both directions, and shows the verdict (**allows it**, **blocks it**, **allows part of it**, **check incomplete**) with every step under the path: the subnet's route table (longest prefix, blackhole routes), VPC peerings (active, and only between their two VPCs), the transit gateway route table associated with the arriving attachment (on to a VPC, a VPN that has a tunnel up, Direct Connect or a peered transit gateway), the stateless network ACLs of both subnets for the request and for the reply on the ephemeral ports, and the security groups of an instance when an end is typed as its IP address, including rules that name another group. A new **Traffic** box takes `tcp/443`, `udp/53`, `icmp` or nothing for any traffic. An end outside AWS is followed to the gateway it leaves by and back in. Nothing unchecked is reported as allowed: a route to a firewall instance, an inspection VPC, a prefix list, or data a discovery did not collect gives *check incomplete* with the reason. The AWS collector additionally reads network ACLs, transit gateway route tables with their routes, the route table of each transit gateway attachment and the security group IDs of instances and their interfaces (best-effort sections; new permissions `ec2:DescribeNetworkAcls`, `ec2:DescribeTransitGatewayRouteTables`, `ec2:SearchTransitGatewayRoutes`; run **Discover** again to collect them). VPC details list the network ACL rules and each subnet's ACL, a transit gateway lists its routes, and the AWS sample gains ACLs, security groups and a transit gateway route table. New `GET /api/meraki/aws/reachability`; `GET /api/meraki/subnets` entries carry `provider`.
- Recognise a Meraki vMX that sits behind a NAT gateway, and check paths through a vMX. An instance in a private subnet has no public IP for the public-address match, so it is now also matched by the private IP of the appliance's WAN uplink when that is unambiguous: the instance forwards traffic, one instance and one uplink have the address, and either the Meraki model is a vMX or the public IP Meraki reports is a NAT gateway of the instance's VPC. The match no longer depends on the order snapshots are merged in. In the AWS check of a path, a route that hands traffic to an instance that is a Meraki appliance no longer ends in *check incomplete*: the latest Meraki collection decides whether an AutoVPN tunnel that is up joins the vMX to the site owning the far subnet, whether that site advertises the subnet, and whether the vMX advertises the AWS address back; the reply is followed from the vMX's subnet. Meraki firewall rules are not matched.
- Track the MAC addresses seen on Meraki devices in MAC tracking. Each Meraki collection upserts its clients (MAC, IP, VLAN, port or SSID, client name, manufacturer, device last seen on) into the new `meraki_clients` table (migration 0065), keeping first-seen/last-seen across collections, so a client stays searchable after it leaves Meraki's one-day window or its snapshot is deleted. `GET /api/mac-tracking/search` now returns these alongside inventory forwarding-table entries (`source: "meraki"`, also matched by client or device name), `GET /api/mac-tracking/stats` counts them (`meraki_clients`, `meraki_devices`), and `POST /api/mac-tracking/cleanup` prunes them. The MAC / ARP Tracking page marks Meraki clients and shows their network; **Find MAC/IP/VLAN** on the Topology page highlights the Meraki device a client was seen on. Meraki clients have no move history.

### Authentication
- Add a TACACS+ login provider (`provider: tacacs`) alongside local/RADIUS/LDAP, aimed at Cisco ISE Device Administration. Plexus authenticates like an IOS device (ASCII or PAP inside the obfuscated TACACS+ body, TCP/49) and then sends an exec authorization (`service=shell cmd=`); the reply's `plexus-role` custom attribute or `priv-lvl` maps to the Plexus role and is re-synced on every login, so ISE policy is authoritative. Authorization FAIL is a reject, never a default role. Same fallback controls as RADIUS/LDAP; secret is redacted in the admin API. New `tacacs_plus` dependency (optional import). Settings UI gains a TACACS+ panel. Guide: `TACACS_CONFIGURATION_GUIDE.md`.

### Reliability and performance
- Run inventory discovery scans and all-hosts MAC/ARP fleet collection as background jobs instead of inline HTTP handlers: `POST .../discovery/scan` and `POST /api/mac-tracking/collect` (all-hosts mode) now return `202` with a `job_id`, pollable via `GET /api/inventory/discovery/jobs/{id}` and `GET /api/mac-tracking/collect/jobs/{id}`. The MAC Tracking page shows live collection progress; the SSE discovery stream and single-host collect are unchanged.
- Batch MAC/ARP persistence: each host's FDB sightings and ARP table now write in one transaction (`record_mac_sightings_batch`, `upsert_arp_entries_batch`) instead of two connection round-trips per MAC, eliminating tens of thousands of connection cycles per fleet collection. Move-detection semantics are unchanged.
- Cancel the audit scheduler task on app shutdown (it was the one background task never cancelled, leaking past lifespan shutdown).
- Fix cloud-metric time-window queries comparing ISO-format timestamps lexically against SQLite `datetime('now')` output, which over-included up to ~24h at the window boundary.

### Bug fixes
- Restore audit logging for geolocation and billing routes: all 14 `_audit()` calls passed the request object as the audit category, so every audit write from those routes failed silently.
- Validate site latitude/longitude in the Pydantic models (422) instead of ad-hoc 400 checks, matching the rest of the API.

### Device upgrades
- Add per-device cancellation for upgrade activation so operators can cancel selected devices that are stuck or failed in the activate step without reloading them during business hours.
- Fix Verify Upgrade version-mismatch handling so a device that is not running the expected target image marks both Verify and Activate as failed, clearing stale green Activate checks.
- Rework upgrade campaigns into a guided step sequence with clearer Prestaging, Transfer, Activate, and Verify controls.
- Surface scheduled reloads in campaign detail views and add an Upcoming reloads overview to the Campaigns tab so armed activation windows are visible before they fire.
- Improve upgrade campaign performance by indexing campaign lookups, speeding the campaign list, and bounding WebSocket event replay.
- Repair upgrade image upload/delete flows and replace browser-native upgrade confirmation/alert dialogs with themed Plexus dialogs.

### Monitoring and performance
- Speed monitoring poll storage and latest-poll lookups with new indexes and batched post-poll database writes.
- Reduce dashboard and page-load API churn by consolidating frontend requests and cache invalidation paths.
- Remove the topology mini-map from the dashboard first paint to reduce initial load cost.
- Enable performance mode by default and replace the animated starfield with a static rendering path for lower browser overhead.

### Compliance and UI
- The **Add Cloud Account** form of Cloud Visibility asks for what each provider needs instead of a free-form JSON box: a choice of sign-in (AWS access key, IAM role or the server's own credentials; Azure service principal; GCP service account key) with only the matching fields, regions for AWS only, and the flow log and traffic metric settings folded away as optional. Uncommon settings still go in as JSON under **Additional settings**. Editing an account keeps the stored sign-in until **Change sign-in and sync settings** is clicked. The API is unchanged.
- AWS cloud accounts can read **All regions**: a checkbox on the account form saves the region scope `all`, and discovery, Pull Flow and Pull Traffic then ask AWS for the regions enabled for the account (`ec2:DescribeRegions`) on every run. With all regions in scope, Pull Flow skips the regions that do not have the flow log group.
- Replace native compliance confirmation and alert dialogs with the shared themed dialog components for a more consistent operator experience.

### Deployment
- Ensure firmware image storage is writable at container startup and return clearer storage-unavailable guidance when upload/delete cannot access the image directory.
- Update Docker build context hygiene with `.dockerignore` changes and container startup fixes.

## 1.0.2 - 2026-05-27

### MAC tracking
- Switch MAC address-table collection to a CLI-first path: `show mac address-table` parsed via ntc-templates on Cisco IOS / IOS-XE / NX-OS and Arista EOS returns every MAC on every VLAN in one round-trip, sidestepping the Cisco "default-context FDB only shows VLAN 1" problem that previously left non-uplink ports invisible. SNMP remains as the automatic fallback when no SSH credential is available or the driver doesn't implement the capability.
- Add `mac_table_show_command()` / `parse_mac_table()` to the `Driver` base class with a shared cisco-style row normaliser so additional vendors can plug in their own MAC scrapers without touching the collector.
- Harden the SNMP fallback: VLAN enumeration now folds in the VTP table (Cisco) and `dot1qVlanStaticName` (standard) so trunk-only VLANs aren't skipped; per-VLAN SNMPv3 context walks run with bounded parallelism (semaphore=4) and a q-bridge fast path that skips the redundant dot1d walks when q-bridge returned rows; a 60s wall-clock budget guarantees the collector can never hang on a switch with a large VTP domain.
- Expose a `diag` block on `/api/mac-tracking/collect` responses (device_type, snmp_version, ports, port_vlans, vlans_discovered, vlan_ctx attempts/successes/skips, CLI attempted/succeeded/mac_count) so operators can diagnose collection problems without shell or log access. The structured log line gains the same fields.

### Dependencies
- Pin `ntc-templates>=7,<10` explicitly. It was already transitive via netmiko, but the new CLI collector uses `send_command(..., use_textfsm=True)` directly so the dependency is now intentional.

## 1.0.1 - 2026-05-22

### Deployment & upgrades
- Add `deploy/upgrade.sh` for one-command upgrades on deployed VMs: auto-detects SQLite vs Postgres for pre-upgrade DB snapshots, captures rollback target, supports `--ref` (git mode), `--image` (prebuilt image mode), `--dry-run`, and `--rollback`, and health-checks the new container before declaring success.
- Add `/api/version` endpoint and rework `netcontrol/version.py` to source version identity from `PLEXUS_VERSION` env > root `VERSION` file > hardcoded fallback, so containers self-identify without needing git on PATH.
- Add `PLEXUS_VERSION` and `PLEXUS_GIT_SHA` build args to the Dockerfile and thread them through the release workflow so GHCR-published images carry their real version and commit SHA.

### Monitoring & onboarding
- Add ICMP liveness probing via `icmplib`: every poll runs an unprivileged async ping in parallel with SNMP/SSH, and `icmp_alive` + `icmp_rtt_ms` are persisted alongside each poll record (migration 0045).
- Add ICMP-only onboarding: new `icmp_only` device type skips SNMP and SSH and gates host health on ping alone, useful for endpoints, printers, and gear without management protocols.
- Discovery scans now fall back to ICMP when SNMP and TCP banner probes both fail, so ping-only hosts surface during sweeps.
- Replace the placeholder `response_time_ms` (previously wall-clock poll duration) with the real ICMP RTT.

### Drivers
- Add Cisco FTD/ASA driver covering LINA-datapath polling via `CISCO-PROCESS-MIB` and `CISCO-ENHANCED-MEMPOOL-MIB`, with documented SNMPv3 engine-ID pinning guidance for ASA/FTD reboot drift.

### Audit
- Add port-hygiene and VLAN-consistency rule packs to the network audit engine.

### Dashboard
- Add Backup Status panel showing last-success-per-device and stale-backup alerts.

### Bug fixes
- Drop the dead master-switch gate in the config-backups scheduler that was silently blocking every scheduled run.

## 1.0.0 - 2026-05-06

First public release on GitHub. Earlier `0.x` versions in this changelog
are pre-release development snapshots that were not published as GitHub
releases.

### Air-gapped deployment
- Add `deploy/airgap/` toolchain for offline VM deploys: `bundle.sh` builds a self-contained `plexus-airgap.tar.gz` (Plexus image + postgres/nginx images + Docker Engine `.deb`s + XFCE/xrdp/AD-join `.deb`s + repo files); `install.sh` runs on the offline VM to install Docker from local debs, `docker load` the images, pin compose to the loaded image, and bring up the stack.
- Add `deploy/airgap/VM_SETUP.md` walkthrough for fresh Ubuntu 26.04 VMs: static-IP netplan template, hostname, chrony NTP, SSH key auth, XFCE+xrdp for RDP-with-desktop, AD domain join (realmd/sssd/adcli) with sudo-via-AD-group, ufw firewall, and Plexus-app AD provider config.

### Database
- Add PostgreSQL backend alongside the default SQLite via `APP_DB_ENGINE=postgres` and `APP_DATABASE_URL`; `requirements-postgres.txt` captures the additional `asyncpg` dependency for production deploys.
- Add `tools/migrate_sqlite_to_postgres.py` migration utility with `--dry-run`, row-count parity verification, and optional per-table checksum verification (`--with-checksums`).
- Add CI smoke job that exercises the Postgres backend end-to-end.

### Security & auth
- Add LDAPS / Active Directory authentication provider for the Plexus web UI (Settings → Authentication Provider), with admin-group DN mapping and configurable user-search filter.
- Add RADIUS authentication provider with access-group mapping and outbound syslog of auth events.
- Centralize credential ownership enforcement; close a default-credential bypass that allowed cross-tenant credential reuse.
- Replace ReDoS-prone shape-check regex with an O(n) scanner (CVE-class fix) and harden config-backup regex compilation against ReDoS.
- Drop SNMPv3 debug log that leaked secret-tainted data.
- Bound query parameters, sanitize error responses, and address CodeQL alerts across legacy frontend and Python routes.
- Tighten template handling for secrets; bump credential encryption.

### IPAM, DHCP, and provisioning
- Add IPAM bi-directional reconciliation between Plexus and external IPAM systems (migration 0023).
- Add VLAN/VRF-aware subnet scoping (Phase G, migration 0025).
- Add IPAM-driven provisioning with pending allocation lifecycle (Phase H, migration 0026).
- Add historical IP allocation tracking and subnet utilization snapshots (Phase I, migration 0027).
- Add DHCP scope/lease integration with Kea, Windows DHCP, and Infoblox (migration 0024).
- Add `APP_IPAM_PUSH_TOGGLE` and per-adapter push controls (migration 0019).

### Digital twin / lab mode
- Add digital twin / lab mode (Phase A): lab environments and cloned-from-host devices for offline config-plane simulation. Apply proposed commands or templates against a snapshot, see unified diff plus risk score, persist run history, and promote successful runs into the Deployments pipeline. Migration 0029 adds `lab_environments`, `lab_devices`, `lab_runs`. New `lab` feature flag and React page at `/frontend/lab`.
- Add containerlab single-node runtime for lab mode (Phase B-1): a twin can now back its snapshot with a real virtual NOS (Arista cEOS, Nokia SR Linux, FRR, Linux) deployed via the host's containerlab CLI. New endpoints `GET /api/lab/runtime`, `POST /api/lab/devices/{id}/runtime/{deploy,destroy,refresh}`, `GET /api/lab/devices/{id}/runtime/events`, and `POST /api/lab/devices/{id}/simulate-live` (pushes commands via Netmiko, captures the real running-config back). Strict allowlist for node kinds and image references; subprocess invoked with explicit argv. Migration 0030 adds runtime fields to `lab_devices` and a `lab_runtime_events` audit log. React Lab page gains a Runtime card and live-mode simulate toggle.
- Operationally harden Phase B-1: simulate-live and Phase A simulate now feed compliance regressions from the source host's profiles into the risk score; startup reconciles in-flight `running` rows against `containerlab inspect` so a Plexus restart no longer leaves stale state; new background TTL reaper destroys idle labs (`PLEXUS_LAB_RUNTIME_TTL_SECONDS`, default 24h, `0` to disable; `PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS` controls cadence); per-device topology workdir is removed after a successful destroy.
- Add multi-device lab topologies (Phase B-2): operators can now link N twins into a single containerlab deployment so routing/STP/LACP behaviors run end-to-end against real NOS images. Migration 0031 adds `lab_topologies`, `lab_topology_links`, and `lab_devices.topology_id`. New endpoints `GET|POST /api/lab/environments/{id}/topologies`, `GET|DELETE /api/lab/topologies/{id}`, `POST|DELETE /api/lab/topologies/{id}/devices[/{device_id}]`, `POST|DELETE /api/lab/topologies/{id}/links[/{link_id}]`, `POST /api/lab/topologies/{id}/{deploy,destroy,refresh}`. The YAML generator emits a `mgmt` subnet block when set, validates each member's kind/image, and rejects deploy when a member still has a free-standing runtime running. React Lab page gains a "Topologies (multi-device)" card with a list-based editor for members and links and runtime controls. Drag-and-drop canvas deferred to a follow-on.
- Add drift-from-twin checks (Phase B-3a): a scheduled and on-demand comparison of each twin's snapshot against the most recent production config snapshot for the host it was cloned from, so prod-side cowboy changes that silently invalidate a validated twin become visible. Migration 0032 adds `lab_drift_runs`. New endpoints `POST /api/lab/devices/{id}/drift/check`, `GET /api/lab/devices/{id}/drift/runs`, `GET /api/lab/devices/{id}/drift/latest`, `GET /api/lab/drift/runs/{id}`. Background scheduler `lab_drift_scheduler_loop` runs every `PLEXUS_LAB_DRIFT_INTERVAL_SECONDS` (default 3600, floor 60); `PLEXUS_LAB_DRIFT_ENABLED=false` disables. Reuses `_compute_config_diff` so volatile-line filtering matches the config-drift module. React Lab page adds a Drift card on each device panel.
- Add visual topology canvas to the lab UI (Phase B-2 follow-on): new `TopologyCanvas` component in the React frontend renders multi-device topologies as a SVG diagram with circular auto-layout, status-coloured nodes, hover tooltips, and click-two-nodes-to-link with an inline endpoint prompt. Editor exposes a List / Canvas view toggle; both share the same data so changes round-trip. Pure SVG keeps the bundle small (no vis-network or reactflow dep added).

### Topology, monitoring & compliance
- Add SNMP-driven device discovery and polling.
- Add topology builder with CDP/LLDP and FDB+ARP fallback inference for environments where neighbor discovery is disabled.
- Add STP multi-VLAN topology visualization, anomaly detection, and alerts.
- Add layout customization, drag-and-drop, and export options to the topology canvas.
- Add config drift detection with revertable history and event timeline.
- Add config backup search and drift event history.
- Add scheduled backup policies and retention.
- Add risk analysis for proposed config changes.
- Add observability tab with availability and capacity dashboards.
- Add compliance scans with on-demand scan buttons, scan timeouts, regex guard, and admin run-now bypass fix.
- Add data analysis tools and dashboard visualizations.

### Device upgrades
- Add device upgrade orchestration with persisted scheduled-at and task rehydration after restart.
- Various reliability and UX fixes to the upgrade flow.

### Playbooks & jobs
- Refactor netmiko helpers into shared module; replace the `config_backup` playbook with first-class in-app config-backup downloads.
- Add job orchestration with dry-run support.
- Fix scheduled-job execution and polling reliability.

### Frontend
- Begin React migration: ports of Settings, Compliance, Device Detail, Federation, Floor Plan, Network Tools, and Lab pages.
- Rebuild React shell to mirror the legacy SPA chrome for a seamless cutover.
- Drop PatternFly in favor of legacy CSS for visual consistency during migration.
- Upgrade React, Vite, and tooling to current majors.
- Break the legacy `app.js` into per-feature modules to reduce coupling and improve load time.
- Improve theme system: smoother theme switching, fixed lag, removed redundant themes.

### Inventory & UX
- Add per-user inventory group ordering, density toggle, and collapsible groups (migration 0028).
- Collapse the Network tab into a smaller set of consolidated tabs while preserving every feature.
- Add admin-controlled feature visibility for nav entries (Settings → Feature visibility).
- Smoother scrolling and corrected gutter rendering in code-editor modals.
- Align password minimum length between UI and backend.

### Documentation
- Add SQLite-to-Postgres migration runbook.
- Linux deploy hardening: backup procedures, path cleanup, and bootstrap fix.

## 0.2.0 - 2026-03-05
- Add shared semantic version constant and `python templates/run.py --version` CLI output.
- Wire API metadata version to shared app version.
- Improve deployability docs and compose persistence (named volumes, restart policy, health endpoint).
- Add operator runbook with apply flow, rollback steps, and mismatch FAQ.
- Add performance/scale limits and data retention documentation.
- Add configurable API timeout/retry/backoff for FTD importer and cleanup scripts.
- Add MIT `LICENSE`.

## 0.1.0 - 2026-03-04
- Add CI workflow (lint, type-check, tests) and pinned dependency files.
- Add Ruff, mypy, pytest, and pre-commit configs.
- Add unit tests for converter routes with fixtures.
- Add Dockerfile and docker-compose for containerized runs.
- Add .env.example for configuration and starter operator docs footprint.
