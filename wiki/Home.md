# Plexus

Plexus is a network automation hub: one web application that keeps the
device inventory, runs automation, backs up and checks configuration, maps
the network across on-premises and cloud, and watches availability and
software versions. It is a FastAPI backend with a React frontend, on
PostgreSQL, shipped as a Docker compose stack.

The same guides are inside Plexus: **Help** in the sidebar, and the
**Read the guide** link on a page's help banner.

## Start here

| I want to | Read |
|---|---|
| Install Plexus on a server | [Deployment Guide](Deployment-Guide) |
| Install it on a network with no internet | [Air-Gapped Deployment](Air-Gapped-Deployment) |
| Understand groups, hosts, playbooks, templates and jobs | [Core Concepts](Core-Concepts) |
| Run it from source and change it | [Developer Setup](Developer-Setup) |
| Call it from a script | [API Reference](API-Reference) |

The short version of an install, on a host with Docker and the compose
plugin:

```bash
bash deploy/setup.sh          # writes .env and a self-signed certificate
docker compose up --build -d  # app, PostgreSQL and nginx
```

Then open `https://localhost`, sign in as `admin` / `netcontrol` and change
the password when asked. The [Deployment Guide](Deployment-Guide) covers
production hosts, `.env`, backups and updates.

## What it does

Each guide says where the feature is in the UI, how to use it step by
step, what the results mean, who may do what, and its API.

**Inventory and addressing**

- [Core Concepts](Core-Concepts): groups, hosts, playbooks, templates,
  credentials and jobs.
- [Discovery](Discovery): scan address ranges and add what answers to the
  inventory.
- [Device Model](Device-Model): manufacturers, device types, roles,
  lifecycle statuses and sites on hosts.
- [Custom Fields and Tags](Custom-Fields-and-Tags) on hosts, groups and
  IPAM prefixes.
- [IPAM](IPAM): subnets, reservations, external IPAM sources and DHCP, and
  [VRFs and VLANs](VRFs-and-VLANs).
- [Floor Plan](Floor-Plan): sites, floors and where each host is.
- [Network Tools](Network-Tools): MAC tracking and traffic analysis.

**Configuration and change**

- [Running Jobs](Running-Jobs) and [Writing Playbooks](Writing-Playbooks).
- [Config Backups and Drift](Config-Backups-and-Drift) and
  [Intended Configuration](Intended-Configuration).
- [Compliance](Compliance): rules, scans and findings.
- [Change Management](Change-Management):
  [Risk Analysis](Risk-Analysis), [Deployments](Deployments) and
  [Maintenance Windows](Maintenance-Windows).
- [Lab Mode](Lab-Mode): rehearse a change on a copy of a device.
- [IOS-XE Upgrade Tool](IOS-XE-Upgrade-Tool).

**Topology**

- A CDP/LLDP map, with [AWS](AWS-Topology), [Azure](Azure-Topology),
  [GCP](GCP-Topology), [Meraki](Meraki-Topology), [Cato](Cato-Topology),
  [Cisco FMC](Cisco-FMC-Topology), [Panorama](Panorama-Topology),
  [Appgate SDP](Appgate-SDP-Topology) and [OPNsense](OPNsense-Topology) as sources.
- [Path Trace](Path-Trace): follow traffic from one end to the other across
  all of them.
- [Cloud Visibility](Cloud-Visibility): cloud accounts and their networks.

**Monitoring and reports**

- [Dashboard](Dashboard), [Monitoring](Monitoring) and
  [Graph Templates](Graph-Templates).
- [SLA Monitoring](SLA-Monitoring) and
  [Alert Notification Channels](Alert-Notification-Channels) (email,
  PagerDuty, webhook, Microsoft Teams).
- [Software Versions and Vulnerabilities](Software-Versions-and-Vulnerabilities).
- [Meraki Alerts](Meraki-Alerts) and [Meraki Compliance](Meraki-Compliance).
- [Flow Collector](Flow-Collector): NetFlow, sFlow and IPFIX.
- [Reports](Reports) and
  [Network Documentation Reports](Network-Documentation-Reports).
- [Vendor Monitoring Coverage](Vendor-Monitoring-Coverage): what is covered
  for each vendor.

**Sign-in and access**

- [Single Sign-On (OIDC)](Single-Sign-On-OIDC), [RADIUS](RADIUS-Login) and
  [TACACS+](TACACS-Login) login.
- [Object Permissions](Object-Permissions) and the
  [Authorization Matrix](Authorization-Matrix).
- [Audit Log](Audit-Log): what is recorded and how to verify it.

**API and AI access**

- [API Reference](API-Reference) and [WebSocket Usage](WebSocket-Usage).
- [AI Access (MCP)](AI-Access-MCP): a read-only endpoint so an AI client
  can query Plexus data.

## Operating it

- [Administration](Administration): every Settings tab, users, roles and
  API tokens.
- [Firewall Rules](Firewall-Rules) for the host.
- [Database Backends](Database-Backends) and
  [Data Retention](Data-Retention).
- [Federation](Federation): link several Plexus servers.
- [Versioning and Release](Versioning-and-Release) and the
  [Changelog](Changelog).

## About this wiki

These pages are generated from the documentation in the
[Plexus repository](https://github.com/RickeyNet/Plexus). To change a page,
edit its source file there; an edit made in the wiki is replaced by the
next publish.
