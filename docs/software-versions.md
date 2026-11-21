# Software Versions and Vulnerability Alerts - Usage Guide

The Software page (**Network → Software**) lists the software version of
every device Plexus knows, shows how versions are spread across each
platform, keeps a history of upgrades and downgrades, and raises an alert
when a device runs a version a security advisory names. Advisories can be
entered by hand, imported, or synced from Cisco PSIRT.

The page has three tabs. **Versions** is described here; **Upgrades** is the
firmware upgrade tool (campaigns, images, backups; the `upgrades` feature),
described in [upgrade-tool-guide.md](upgrade-tool-guide.md); **Lifecycle**
is the hardware lifecycle (end-of-life notices and support contracts; the
`lifecycle` feature), described in [hardware-lifecycle.md](hardware-lifecycle.md).
Each tab is shown only to users with its feature.

- Permission: the `software` feature to view, `software.write` to refresh,
  acknowledge alerts and manage advisories and end-of-life entries, admin
  for the settings and the Cisco PSIRT credentials
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
| Inventory | every host with a stored software version | `software_version` of the host (SNMP sysDescr, or SSH `show version` read by inventory **Discover devices** / **Sync** with the Plexus service credential or a picked one; that read also sets the host's model, serial and device type, so IOS XE switches are `cisco_xe` without SNMP) | from the host's driver: `cisco_ios` is IOS XE when the version is 16.x or later, `cisco_nxos`, `cisco_xr`, `cisco_ftd` (ASA when the model says so), `juniper_junos`, `arista_eos`, `fortinet_fortios`, `paloalto_panos`, `aruba_aoscx` (AOS-CX), `aruba_osswitch` and `hp_procurve` (AOS-Switch), `aruba_instant_on` (Instant On), `netgear_prosafe`, `netgear_smart` and `netgear_ap` (Netgear managed switch, smart switch, access point), `apc_ups` (APC Network Management Card: the card's firmware); otherwise guessed from the text, else **Other** |
| Inventory (APC UPS) | every `apc_ups` host the monitoring poll has read | the UPS firmware (`upsAdvIdentFirmwareRevision`, `UPS 09.3 (ID18)` is shown as `9.3`), as a device of its own named `<host> (UPS)` | APC Smart-UPS firmware (`apc-ups`); see [apc-ups.md](apc-ups.md) |
| Meraki | every device of the latest collection | the device's firmware (`wired-18-107-2` is shown as `18.107.2`) | by product: Meraki MX, MS, MR, MG, MV, MT |
| Cato | every Socket of the latest collection | the Socket version | Cato Socket |
| Cisco FMC | every managed device and the FMC of the latest collection | the FTD software version; the FMC version | Cisco Secure Firewall Threat Defense, Management Center |

A topology device that is also an inventory host is listed once, under the
collection: the controller knows the exact firmware. AWS resources carry no
software version. A device drops out of the list when its host is deleted
or its organization's snapshots are gone.

The tracked set is rebuilt every six hours (configurable), after every
topology collection, after every inventory discovery **Sync** or onboard
(manual or scheduled), when the **Upgrades** tool verifies a device on its
target version, and on **Refresh**.

The inventory host is the one record of a device's version: the Inventory
page, this page and its alerts, reports and the API all read it. A device
upgraded with the **Upgrades** tool needs nothing further: when a device
passes verification the tool writes the version it read to the device's
inventory host, the tracked set is rebuilt and the alerts that no longer
match are resolved, and the open pages refetch. An APC UPS is polled at
that moment instead, because its UPS firmware is read by the monitoring
poll (monitoring must be enabled). A campaign device added by IP address
has no inventory host and is not tracked. After an upgrade done outside
Plexus, a **Sync** of the device's inventory group reads the new version
with the same result.

Each rebuild compares every
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

### CVE enrichment (NVD and CISA KEV)

Every advisory that lists CVE ids, whatever its source (Cisco PSIRT, the
OPNsense security audit, manual entry, import), can be enriched from two
public feeds:

- the **NVD CVE API 2.0** (`services.nvd.nist.gov`), asked once per CVE for
  the CVSS base score, severity and vector. Plexus uses the newest CVSS
  version NVD holds (4.0, then 3.1, 3.0, 2.0) and, within it, NVD's own
  `Primary` metric before a CNA's `Secondary` one;
- the **CISA Known Exploited Vulnerabilities catalogue** (one JSON file from
  `www.cisa.gov`), for the *known exploited* flag with the date CISA added
  the CVE, the remediation due date and whether it is known to be used in
  ransomware campaigns.

Only CVE ids leave Plexus (in the NVD query string); nothing about the
devices, versions or advisories is sent. Redirects are not followed.

**What changes on an advisory:**

| Field | Rule |
|---|---|
| CVSS | The highest NVD base score among its CVEs, when the advisory has no score of its own (a Cisco PSIRT score is kept). Shown as from NVD. |
| Known exploited | Set when any of its CVEs is in the KEV catalogue; the earliest date added and due date are kept with it. |
| Severity | From the score: critical from 9.0, high from 7.0, medium from 4.0, low below; raised to at least high when known exploited. Only for an advisory whose severity is a **default** one (its source gave none: the OPNsense audit, an import or a manual advisory without a severity) or was set by enrichment before. |

A severity is never changed when it is the **vendor's** (Cisco's Security
Impact Rating) or an **administrator's**: one set or changed in the advisory
dialog, sent with an advisory through the API or an import, or an OPNsense
audit advisory whose severity was edited. The dialog says where the current
severity comes from and offers **Let CVE enrichment set the severity** to
hand an administrator's severity back. A later PSIRT sync or OPNsense audit
does not reset what enrichment set. The API answers carry `severity_source`
(`default`, `enriched`, `vendor`, `admin`), `cvss_source` (`nvd` when the
score came from NVD), `known_exploited`, `kev_date_added`, `kev_due_date`
and `kev_ransomware`; the advisory and alert lists show a **Known exploited**
marker with the dates in its tooltip.

Open alerts follow the advisory: an alert's severity is its advisory's, so
the alert list, the device table and the summary show the enriched severity
at the next evaluation, which a run ends with. No notification is sent for
a severity that changes; when an advisory that was enriched before becomes
known exploited, its open alerts are sent to the notification channels once
more (subject to the severity floor; the message says *known exploited*).
The first run re-notifies nothing, and nor does the first run after a failed
KEV download.

**Settings** (admin, Software page → **Settings**):

- **Enrich advisories from NVD and CISA KEV**: off by default, since it
  needs outbound HTTPS to `services.nvd.nist.gov` and `www.cisa.gov`.
  Air-gapped deployments leave it off, or point it at internal mirrors.
- **NVD API key** (optional, from the NVD's API key request page): stored
  encrypted, never shown again, sent in the `apiKey` header. Changing the
  NVD URL to another host requires entering the key again.
- **NVD API URL** and **CISA KEV file URL**: blank for the public feeds, or
  the https address of a mirror (an NVD API 2.0 compatible endpoint, a copy
  of `known_exploited_vulnerabilities.json`). A mirror must pass the
  outbound address guard (`APP_SSRF_ALLOW`, `APP_SSRF_BLOCK_PRIVATE`), when
  saved and again on every run. An outbound proxy is honoured through the
  usual `HTTPS_PROXY` environment variable.
- **Save & Run Now** starts a run in the background; the dialog shows its
  progress and the result of the last run (time, counts, the first error).

**When it runs:** after the scheduled software refresh when it is turned on
and due (every 12 hours, or at once while the last run left CVEs for
later), and on **Save & Run Now**. A run downloads the KEV catalogue once,
then asks NVD about the CVEs that are due, never-asked first. NVD allows 5
requests per rolling 30 seconds without an API key and 50 with one; Plexus
spaces its requests evenly inside that budget and retries a refused or
failed request after a pause (honouring `Retry-After`). A run asks about at
most 100 CVEs without a key (about ten minutes) or 1000 with one; the rest
are asked on the following runs, so the first run on a large advisory set
takes several. Each answer is cached per CVE (table `cve_enrichment`): a
scored CVE is asked again after 7 days, one NVD has not scored yet (or does
not know) after 1 day. New advisories whose CVEs are already cached are
enriched as soon as they are saved, without a request.

A failed download or lookup never fails the software refresh or an OPNsense
collection: it is logged, the run's status and message say what failed, and
what is stored is kept. A rate-limit refusal (HTTP 403 or 429) or three
failed lookups in a row end the run's NVD lookups; the rest wait for the
next run. Every run is recorded in the audit log (`software` /
`cve_enrichment`).

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

## Software end of life

Besides the advisories, every tracked device has an end-of-life status for
the **release series** it runs: the day the series stops getting security
fixes. This is the software side; the hardware side (end of sale and
support of a device model) is the **Lifecycle** tab
([hardware-lifecycle.md](hardware-lifecycle.md)).

### Release series

- **OPNsense** names the series in the version: the year and month of the
  major release (`25.1.4_1` is series `25.1`, business edition `24.10.2` is
  `24.10`; the firewall reports it as `product_series`).
- **Every other platform** has the series an administrator's entry names.
  An entry covers the versions it is a prefix of on a version component
  boundary: `17.9` covers `17.9.4a` and `17.9.5`, not `17.90.1`. When two
  entries match, the longer one wins (`17.9` over `17`).

### Entries

The **Software End of Life** card on the Versions tab lists the entries:
platform, series, end-of-life date (the day security fixes stop), optional
release date, URL and notes, and an enabled switch. **+ Add Series**, **Edit**
and **Delete** need `software.write`; every user with the `software` feature
sees the list. Entries can also be imported over the API (create or replace
by platform and series, source `import`). An entry is how every platform
gets a status; for OPNsense it overrides the built-in estimate.

### The OPNsense estimate

OPNsense needs no entry. Its release engineering (the `CORE_NEXT` rule of
the opnsense/core `Makefile`) has two major series a year per edition, and a
series is maintained until its successor is released:

| Series | Successor | Estimated end of life |
|---|---|---|
| Community `YY.1` (January) | `YY.7` (July) | `20YY-07-31` |
| Community `YY.7` (July) | `YY+1.1` (January) | `20YY+1-01-31` |
| Business `YY.4` (April) | `YY.10` (October) | `20YY-10-31` |
| Business `YY.10` (October) | `YY+1.4` (April) | `20YY+1-04-30` |

The successor's release day is not known in advance, but every community
major so far shipped inside its month (between the 2nd and the 31st, most in
the last week), so the estimate is the **last day of the successor's release
month**: it is never early, so a firewall on the newest series is not called
end of life before its successor exists, and at most about a month late. The
`ending` status warns before it, and the firewall's own report (below) gives
the exact day in between. The API and the page mark such a date as an
estimate.

The firewall itself confirms it: once a newer major release is offered for
upgrade, its firmware status reports it (`upgrade_major_version` of
`core/firmware/status`, shown as **Major upgrade available** in the
firewall's details). A firewall that reports a newer major series makes its
series **end of life** at once, even before the estimated date (source
`reported`); one firewall's report counts for every firewall on that
series. Its date stays the estimate (it may still be ahead); the basis says
"the firewall reports major release ... is available". An administrator's
entry for platform `opnsense` and the series wins over both, with its
exact date.

### Statuses

| Status | When |
|---|---|
| `supported` | The end-of-life date is further away than the warning window |
| `ending` | The date is within the warning window (default 60 days, **Warning window** on the card, admin; setting `eol_warn_days`) |
| `end_of_life` | The date has come (on the date itself, security fixes have stopped), or the firewall reports a newer major series |
| `unknown` | No entry covers the version and the platform has no built-in rule |

Each device's status (series, status, date, days left or past, source
`entry` / `estimate` / `reported` and a one-line basis) is in the overview
(`devices[].lifecycle`), with a count per status (`summary.lifecycle`). The
device table shows it as a chip under the version ("End of life since
2026-01-31 (estimate)", "Ends in 23 days") and has a filter for it.

### Alerts

A series that is ending or end of life and runs on at least one tracked
device becomes a generated advisory of source `lifecycle`, ID
`lifecycle:<platform>:<series>` (for example `lifecycle:opnsense:24.7`),
titled "OPNsense 24.7 is end of life" or "... reaches end of life on
<date>", affecting every version of the series (`24.7.*`), with the
successor as the fixed version and no CVEs. It is synced on every refresh
(on the schedule, after each topology collection and on **Refresh**) and
after every entry or window change, so the alerts are raised, notified and
acknowledged like any other advisory's without anyone opening the page:

- severity **high** once the series is end of life (no more security
  fixes), **low** while it is ending, so with the default notification
  floor (high) the end of life is notified and the warning is not;
- a severity or enabled switch you change on the advisory is kept across
  syncs, also when an ending series reaches its end of life (the severity
  is then an administrator's, see [CVE enrichment](#cve-enrichment-nvd-and-cisa-kev));
  a severity nobody edited follows the status;
- when no device runs the series any more (it was upgraded) or the series is
  supported again (an entry moved the date), the advisory is withdrawn: it
  keeps its settings but affects no version, so its alerts resolve.

## API reference

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/software/overview` | `summary`, `platforms` (the spread), `platform_catalog`, `devices`, open `alerts`, `advisories`, recent `changes`, `settings` (no secrets). Query `platform`, `source` (`inventory`, `meraki`, `cato`, `fmc`) and `search` narrow `devices` only |
| `POST` | `/api/software/refresh` | Rebuild the tracked set and re-match; returns counts and the version changes (`software.write`) |
| `GET` | `/api/software/history?device_key=` | Every version one device was seen on, with `seen_from` / `seen_until` |
| `GET` | `/api/software/advisories` | All advisories |
| `POST` | `/api/software/advisories` | `{"advisory_id", "title"?, "severity"?, "cvss"?, "platform"?, "product_match"?, "affected_versions": [...], "fixed_versions"?, "cves"?, "url"?, "published"?, "summary"?, "enabled"?, "severity_source"?}`; 409 when the ID exists. `severity_source` `admin` keeps the severity from CVE enrichment, `default` lets enrichment set it; omitted, a body with a `severity` is the administrator's (on an edit: a severity that differs from the stored one) |
| `PUT` | `/api/software/advisories/{id}` | Replace an advisory (same body) |
| `DELETE` | `/api/software/advisories/{id}` | Delete it and its alerts |
| `POST` | `/api/software/advisories/import` | `{"advisories": [...]}`, up to 1000; replaces by ID |
| `GET` | `/api/software/alerts?include_resolved=` | Alerts with their advisory and device |
| `POST` | `/api/software/alerts/{id}/acknowledge` | Mark an open alert as seen |
| `GET` | `/api/software/settings` | Refresh interval, notification floor, PSIRT settings and last sync, CVE enrichment settings and last run (`cve_*`, `nvd_base_url`, `kev_url`); `has_psirt_secret` and `has_nvd_api_key` instead of the secrets (admin) |
| `PUT` | `/api/software/settings` | Any of the fields; `psirt_client_secret` and `nvd_api_key` are write-only, `""` clears them (admin) |
| `POST` | `/api/software/psirt/test` | Sign in to Cisco PSIRT with the stored credentials (admin) |
| `POST` | `/api/software/psirt/sync` | Start a sync; returns `job_id` (admin) |
| `GET` | `/api/software/psirt/jobs/{job_id}` | Progress and result of a sync |
| `POST` | `/api/software/cve-enrichment/run` | Start an NVD / CISA KEV enrichment run; returns `job_id`; 400 while it is turned off, 409 while one runs (admin) |
| `GET` | `/api/software/cve-enrichment/jobs/{job_id}` | Progress and result of a run (`counts`: `cves`, `looked_up`, `failed`, `remaining`, `known_exploited`, `advisories_updated`, `became_known_exploited`) |
| `GET` | `/api/software/eol-entries` | The end-of-life entries and the warning window (`warn_days`) |
| `POST` | `/api/software/eol-entries` | `{"platform", "series", "eol_date", "release_date"?, "url"?, "notes"?, "enabled"?}`; 409 when the platform and series exist (`software.write`) |
| `PUT` | `/api/software/eol-entries/{id}` | Replace an entry (same body) |
| `DELETE` | `/api/software/eol-entries/{id}` | Delete an entry |
| `POST` | `/api/software/eol-entries/import` | `{"entries": [...]}`, up to 1000; replaces by platform and series |

Every write is recorded in the audit log under category `software`. Tables:
`software_versions`, `software_version_history`, `software_advisories`,
`software_alerts`, `software_settings` (migration 0067), `cve_enrichment` and
the advisories' severity source and KEV columns (migration 0129), `software_eol_entries`
and `software_versions.major_upgrade` (migration 0130).

## Limits

- Plexus does not know which versions a vendor has released; "behind" is
  relative to your own fleet. End of life is known for OPNsense (estimated
  from the release cadence, confirmed by the firewall) and for the series an
  administrator enters; there is no end-of-life feed for the other vendors. Meraki firmware
  availability (the Dashboard's per-network upgrade information) is not
  read yet.
- Cisco PSIRT is the only advisory feed. Advisories for Meraki, Cato,
  Juniper, Arista, Fortinet, Palo Alto, Aruba, Netgear and APC devices have to be entered or
  imported; the version specification grammar is meant to make that quick.
- CVE enrichment adds scores and the known-exploited flag to the CVEs an
  advisory already names. It does not find CVEs for a version: matching
  versions to CVEs through NVD's CPE data is not done.
- A version is matched as a string of parts; an advisory that depends on a
  feature being configured (most Cisco advisories list "vulnerable
  configurations") will alert on every device running an affected version,
  whether or not the feature is in use. Read the advisory before acting.
- An inventory host whose version Plexus has not read (no SNMP enrichment,
  no SSH poll) is not tracked.
