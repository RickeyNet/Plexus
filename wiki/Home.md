# Plexus

Plexus is a network automation hub: one web application that keeps the
device inventory, runs automation, backs up and checks configuration, maps
the network across on-premises and cloud, and watches availability and
software versions. It is a FastAPI backend with a React frontend, on
PostgreSQL, shipped as a Docker compose stack.

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

**Inventory and automation**

- [Core Concepts](Core-Concepts): device groups and hosts, Python playbooks,
  config templates, credentials and jobs with live output.
- [Device Model](Device-Model): manufacturers, device types, roles,
  lifecycle statuses and sites on hosts, filled in by discovery.
- [Custom Fields and Tags](Custom-Fields-and-Tags): admin-defined fields
  and tags on hosts, groups and IPAM prefixes.
- [VRFs and VLANs](VRFs-and-VLANs): VRF and VLAN records, and the addresses
  each device interface carries.
- [Intended Configuration](Intended-Configuration): Jinja2 templates and
  config contexts that render what each host's configuration should be.
- [Writing Playbooks](Writing-Playbooks) and the
  [IOS-XE Upgrade Tool](IOS-XE-Upgrade-Tool).
- [Network Documentation Reports](Network-Documentation-Reports).

**Topology**

- A CDP/LLDP map, with [AWS](AWS-Topology), [Azure](Azure-Topology),
  [GCP](GCP-Topology), [Meraki](Meraki-Topology), [Cato](Cato-Topology),
  [Cisco FMC](Cisco-FMC-Topology), [Panorama](Panorama-Topology) and
  [Appgate SDP](Appgate-SDP-Topology) as sources.
- [Path Trace](Path-Trace): follow traffic from one end to the other across
  all of them.

**Monitoring and compliance**

- [SLA Monitoring](SLA-Monitoring) and
  [Alert Notification Channels](Alert-Notification-Channels) (email,
  PagerDuty, webhook, Microsoft Teams).
- [Software Versions and Vulnerabilities](Software-Versions-and-Vulnerabilities).
- [Meraki Alerts](Meraki-Alerts) and [Meraki Compliance](Meraki-Compliance).
- [Flow Collector](Flow-Collector): NetFlow, sFlow and IPFIX.
- [Vendor Monitoring Coverage](Vendor-Monitoring-Coverage): what is covered
  for each vendor.

**Sign-in and access**

- [Single Sign-On (OIDC)](Single-Sign-On-OIDC), [RADIUS](RADIUS-Login) and
  [TACACS+](TACACS-Login) login.
- [Object Permissions](Object-Permissions) and the
  [Authorization Matrix](Authorization-Matrix).

**API and AI access**

- [API Reference](API-Reference) and [WebSocket Usage](WebSocket-Usage).
- [AI Access (MCP)](AI-Access-MCP): a read-only endpoint so an AI client
  can query Plexus data.

## Operating it

- [Firewall Rules](Firewall-Rules) for the host.
- [Database Backends](Database-Backends) and
  [Data Retention](Data-Retention).
- [Versioning and Release](Versioning-and-Release) and the
  [Changelog](Changelog).

## About this wiki

These pages are generated from the documentation in the
[Plexus repository](https://github.com/RickeyNet/Plexus). To change a page,
edit its source file there; an edit made in the wiki is replaced by the
next publish.
