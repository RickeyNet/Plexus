# Software Versions and Vulnerability Alerts - Usage Guide

The Software page (**Network → Software**) lists the software version of
every device Plexus knows, shows how versions are spread across each
platform, keeps a history of upgrades and downgrades, and raises an alert
when a device runs a version a security advisory names. Advisories can be
entered by hand, imported, or synced from Cisco PSIRT.

The page has two tabs. **Versions** is described here; **Upgrades** is the
firmware upgrade tool (campaigns, images, backups; the `upgrades` feature),
described in [upgrade-tool-guide.md](upgrade-tool-guide.md). Each tab is
shown only to users with its feature.

- Permission: the `software` feature to view, `software.write` to refresh,
  acknowledge alerts and manage advisories, admin for the settings and the
  Cisco PSIRT credentials
- API: `/api/software/*`

## Quick start

1. Make sure Plexus knows some versions. An inventory host gets its version
   from SNMP enrichment or an SSH poll (the **Software** column on the
   Inventory page); a Meraki organization, Cato account or Cisco FMC
   gets it from its topology collection (**Network → Topology → Sources**).
   **Load Sample** on the Topology page is enough to try the page.
2. Open **Network → Software**. The first visit builds the tracked set from
   what is already stored; **Refresh** rebuilds it at any time.
3. **Add an advisory** (**Advisories → + Add**): an ID, a severity, the
   platform it concerns and the versions it affects. Devices on those
   versions appear under **Vulnerability Alerts** at once.
4. Optionally **sync Cisco PSIRT** (admin): enter the client ID and secret
   of a Cisco API Console application under **Settings**, then click **Sync
   Cisco PSIRT**. Plexus asks Cisco about every Cisco version it tracks and
   stores the advisories that affect them.

## Where the versions come from

| Source | Devices | Version read | Platform |
|---|---|---|---|
| Inventory | every host with a stored software version | `software_version` of the host (SNMP sysDescr, SSH `show version`) | from the host's driver: `cisco_ios` is IOS XE when the version is 16.x or later, `cisco_nxos`, `cisco_xr`, `cisco_ftd` (ASA when the model says so), `juniper_junos`, `arista_eos`, `fortinet_fortios`, `paloalto_panos`; otherwise guessed from the text, else **Other** |
| Meraki | every device of the latest collection | the device's firmware (`wired-18-107-2` is shown as `18.107.2`) | by product: Meraki MX, MS, MR, MG, MV, MT |
| Cato | every Socket of the latest collection | the Socket version | Cato Socket |
| Cisco FMC | every managed device and the FMC of the latest collection | the FTD software version; the FMC version | Cisco Secure Firewall Threat Defense, Management Center |

A topology device that is also an inventory host is listed once, under the
collection: the controller knows the exact firmware. AWS resources carry no
software version. A device drops out of the list when its host is deleted
or its organization's snapshots are gone.

The tracked set is rebuilt every six hours (configurable), after every
topology collection, and on **Refresh**. Each rebuild compares every
device's version with the last one: a change is recorded with the previous
version and the time (**Recent Version Changes**, and the *was X* note under
the device), and every version a device has run is kept with the period it
was seen on it (**History** on a device row).

### Version spread

**Version Spread** groups the fleet by platform and shows how many devices
run each version, newest first, with the newest version seen and how many
devices are behind it. A device behind the newest version of its platform
carries a **behind** badge in the device table. "Newest" means newest in
your fleet, not newest released: Plexus does not know what Cisco or Meraki
have published, only what you run.

Versions are compared by their parts, not as text: `17.9.4a` is newer than
`17.9.4`, `17.10.1` is newer than `17.9.4a`, `15.2(7)E10` is newer than
`15.2(7)E8`, and `21.4R3-S4` is newer than `21.4R3`.

## Advisories

An advisory is what a device's version is checked against. Each one has:

- **ID** (`cisco-sa-…`, a CVE, or your own), a **title**, a **severity**
  (critical, high, medium, low, info) and an optional **CVSS** score
- a **platform** (or any platform) and optionally a **model** substring
  (`C9300`), so an advisory only concerns the devices it names
- the **affected versions**, one specification per line; a device matches
  the advisory when its version satisfies any line
- optional fixed versions, CVEs, a URL, a publication date and a summary

### Affected version specifications

| Specification | Matches |
|---|---|
| `17.9.4a` | exactly that version (`17.09.4a` and `wired-17-9-4a` are the same version) |
| `17.9.*` | every version starting with `17.9` |
| `<17.6.5`, `<=`, `>`, `>=`, `!=` | versions ordered before, after or other than the one given |
| `17.3..17.6.4` | every version from `17.3` to `17.6.4` inclusive; either bound may be left out |
| `16.12..16.12.9, !=16.12.5` | several constraints that must all hold |

### Import

**Advisories → Import** takes a JSON list (or an object with an
`advisories` list) in the shape the API uses; only `advisory_id` and
`affected_versions` are required. An advisory with the ID of a stored one
replaces it. The same payload can be posted to
`POST /api/software/advisories/import`.

### Cisco PSIRT openVuln

Cisco publishes its security advisories through the openVuln API, which can
be asked which advisories affect one version of one operating system. To
use it:

1. Sign in to the [Cisco API Console](https://apiconsole.cisco.com/) with a
   Cisco account, register an application with the **Cisco PSIRT openVuln
   API** and note its client ID and client secret.
2. On the Software page, open **Settings** (admin), enter the client ID and
   secret, and click **Save & Test Login**. The secret is stored encrypted
   and never shown again.
3. Click **Sync Cisco PSIRT**, or tick **Sync Cisco PSIRT on a schedule**.

A sync asks Cisco about every distinct version of every tracked Cisco
platform that openVuln covers: IOS, IOS XE, IOS XR, NX-OS, ASA, FTD, FMC
and FXOS (Meraki is not covered by a version query). One request is sent
per version, paced to stay inside Cisco's rate limits, so a fleet with
twenty distinct Cisco versions takes about a minute. Every advisory Cisco
answers with is stored with source **Cisco PSIRT**, the exact version it
was answered for as its affected version (later syncs add further versions
to the same advisory), Cisco's Security Impact Rating as the severity, the
CVSS base score, the CVEs, the first fixed releases and the publication
URL. The advisories are then matched like any other. A sync runs as a
background job whose progress is shown on the page; a version Cisco has no
advisory for is simply skipped, and a refused login stops the sync and is
reported.

The credentials only ever reach `id.cisco.com` (the OAuth2 token) and
`apix.cisco.com` (the API); redirects are not followed.

## Alerts

Every refresh, advisory change and PSIRT sync re-matches all devices
against all enabled advisories:

- a device that newly matches an advisory **opens** an alert;
- a device that no longer matches (it was upgraded, or the advisory was
  changed or disabled) has its alert **resolved**;
- a device that matches again after being resolved (a downgrade) has its
  alert **reopened**, unacknowledged.

Open alerts are listed under **Vulnerability Alerts**, most severe first,
with the device, its version, the advisory and the fixed versions; the
device table shows a count per device with its worst severity, and the
**Open Alerts** summary card turns red when a critical or high alert is
open. **Acknowledge** marks an alert as seen (it stays open until the
device no longer matches). Deleting an advisory removes its alerts.

A new or reopened alert at or above the severity floor in **Settings**
(default: high) is sent to the notification channels configured under
**Settings → Notifications**, like a monitoring alert: critical and high
advisories arrive as *critical*, medium as *warning*, low and info as
*info*, with alert type `software_vulnerability`, the device as the host,
the CVSS score as the value and a dedup key of
`software:<device key>:<advisory ID>`.

## API reference

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/software/overview` | `summary`, `platforms` (the spread), `platform_catalog`, `devices`, open `alerts`, `advisories`, recent `changes`, `settings` (no secrets). Query `platform`, `source` (`inventory`, `meraki`, `cato`, `fmc`) and `search` narrow `devices` only |
| `POST` | `/api/software/refresh` | Rebuild the tracked set and re-match; returns counts and the version changes (`software.write`) |
| `GET` | `/api/software/history?device_key=` | Every version one device was seen on, with `seen_from` / `seen_until` |
| `GET` | `/api/software/advisories` | All advisories |
| `POST` | `/api/software/advisories` | `{"advisory_id", "title"?, "severity"?, "cvss"?, "platform"?, "product_match"?, "affected_versions": [...], "fixed_versions"?, "cves"?, "url"?, "published"?, "summary"?, "enabled"?}`; 409 when the ID exists |
| `PUT` | `/api/software/advisories/{id}` | Replace an advisory (same body) |
| `DELETE` | `/api/software/advisories/{id}` | Delete it and its alerts |
| `POST` | `/api/software/advisories/import` | `{"advisories": [...]}`, up to 1000; replaces by ID |
| `GET` | `/api/software/alerts?include_resolved=` | Alerts with their advisory and device |
| `POST` | `/api/software/alerts/{id}/acknowledge` | Mark an open alert as seen |
| `GET` | `/api/software/settings` | Refresh interval, notification floor, PSIRT settings and last sync; `has_psirt_secret` instead of the secret (admin) |
| `PUT` | `/api/software/settings` | Any of the fields; `psirt_client_secret` is write-only, `""` clears it (admin) |
| `POST` | `/api/software/psirt/test` | Sign in to Cisco PSIRT with the stored credentials (admin) |
| `POST` | `/api/software/psirt/sync` | Start a sync; returns `job_id` (admin) |
| `GET` | `/api/software/psirt/jobs/{job_id}` | Progress and result of a sync |

Every write is recorded in the audit log under category `software`. Tables:
`software_versions`, `software_version_history`, `software_advisories`,
`software_alerts`, `software_settings` (migration 0067).

## Limits

- Plexus does not know which versions a vendor has released or declared
  end-of-life; "behind" is relative to your own fleet. Meraki firmware
  availability (the Dashboard's per-network upgrade information) is not
  read yet.
- Cisco PSIRT is the only advisory feed. Advisories for Meraki, Cato,
  Juniper, Arista, Fortinet and Palo Alto devices have to be entered or
  imported; the version specification grammar is meant to make that quick.
- A version is matched as a string of parts; an advisory that depends on a
  feature being configured (most Cisco advisories list "vulnerable
  configurations") will alert on every device running an affected version,
  whether or not the feature is in use. Read the advisory before acting.
- An inventory host whose version Plexus has not read (no SNMP enrichment,
  no SSH poll) is not tracked.
