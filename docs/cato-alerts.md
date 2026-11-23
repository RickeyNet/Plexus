# Cato Alerts (events feed)

Plexus learns about Cato connectivity problems within about a minute, instead
of at the next hourly topology collection, by reading each Cato account's
**events feed** (the `eventsFeed` GraphQL query). The same read stores the
account's **IPS events** as security events.

It is the first provider of the vendor-neutral alert feed store (`vendor_alerts`,
migration 0132), which the AWS and Azure alert feeds use too
([cloud-alerts.md](cloud-alerts.md)). The Meraki
alerts keep their own pipeline ([meraki-alerts.md](meraki-alerts.md)).

Contents:

- [Before you start](#before-you-start)
- [How it works](#how-it-works)
- [Events read](#events-read)
- [Raising and clearing alerts](#raising-and-clearing-alerts)
- [IPS events](#ips-events)
- [Settings reference](#settings-reference)
- [API](#api)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## Before you start

- Add the Cato account as a topology source with its account ID and an API key
  (Topology > Sources, see [cato-topology.md](cato-topology.md)). The feed uses
  the same source and key; nothing else is configured per account.
- The account must have the **events feed** enabled in the Cato management
  application. Cato's knowledge base describes this; the page could not be
  read while this feature was built, so the exact menu path and the API key
  permission the query needs are not given here. An account without it, or a
  key that may not read it, shows **Refused by the vendor** or **No access**
  with Cato's own message under Topology > Sources > Cato alerts, and is
  retried hourly. Nothing is logged again until the message changes.
- Polling is outbound only (HTTPS to the Cato API URL of the source), so it
  works in every deployment.

## How it works

Every 60 seconds (30 to 3600, configurable) Plexus reads the events feed of
each Cato source that has an API key and is not opted out:

1. **The marker.** Cato's events feed is a queue read with a marker: "If
   omitted or empty, the API returns the current position in the event queue
   and may not return any event records"; each answer returns the marker of
   the next position, and "the queue retains events for approximately three
   days" (Cato's schema description). Plexus stores the marker per account
   (table `vendor_alert_feeds`) after the events of each page are stored, so a
   restart neither replays nor skips. The first read of an account only
   positions the marker (status **Started**): enabling the feed does not
   replay the three days in the queue. A page read twice (a crash between
   storing the events and the marker) is deduplicated.
2. **Bounded.** At most 5 pages per account and poll. A backlog (Plexus was
   stopped for a while) is read over the next polls, as long as it is younger
   than Cato's three days.
3. **Filtered.** The query asks only for the mapped sub-types (an
   `event_sub_type` `in` filter) and only the fields Plexus reads
   (`records(fieldNames:)`), so a busy account's firewall and traffic events
   are never downloaded.
4. **One worker.** With several app workers, one polls an account at a time:
   it takes a lease on the account's feed row for five minutes and gives it
   back when done (a worker that dies loses it when it runs out). Back-off
   and status are stored on the same row, so every worker shows the same.
5. **Back-off.** A failure backs the account off exponentially: up to hourly
   for a refusal or rejected key, up to ten minutes for anything else (Cato
   unreachable, rate limited). The Cato client also waits and retries once
   on a rate-limit answer. Poll Now ignores the back-off.

The outbound calls go through the shared Cato client (`CatoClient`): its URL
must be an https URL under `catonetworks.com`, redirects are not followed, and
only queries are sent.

## Events read

The sub-type strings are the ones Cato's schema lists for the
`event_sub_type` filter. Cato documents no meaning per sub-type; what each
one does here is read from its name, not checked against a live account.

| Cato sub-type | Plexus condition | Entity | Severity | Closed by |
|---|---|---|---|---|
| `Disconnected` | `disconnected` | the site (no interface in the event) or the Socket link (`socket_interface`) | critical (site), warning (link) | `Connected` / `Reconnected` of the same site or link; a later collection showing it up |
| `Alt. WAN Disconnected` | `alt_wan_disconnected` | the link, else the site | warning | `Alt. WAN Connected`; a later collection showing the site's links up |
| `HA Not Ready` | `ha_not_ready` | the site | warning | `HA Ready` |
| `LAN port disconnected` | `lan_port_disconnected` | the LAN port | info (listed only) | `LAN port connected` |
| `Socket Fail-Over` | `socket_failover` | the site | warning | one-shot: closed after the open TTL (24 h) |
| `Last-Mile Quality` | `last_mile_quality` | the link, else the site | warning | one-shot: closed after the open TTL |
| `IPS` | security event | the site | from `risk_level` | see [IPS events](#ips-events) |

Left out on purpose: `Passive Connected` / `Passive Disconnected` and `BGP
Session` (their meaning and direction are not documented), the other Security
sub-types (firewall, anti-malware, DNS events are traffic logs, not alerts),
and the System, Routing, Sockets Management, Detection and Response and
Posture events. Events of a remote (SDP) user (`vpn_user_email`, or
`src_is_site_or_vpn` other than a site) are ignored: users come and go, which
is no outage.

Fields read (the `EventFieldName` values, with Cato's description):
`event_type` and `event_sub_type` (the type and sub-type), `event_message`
("Cato's description of the event"), `event_id`, `src_site_id` ("Unique
internal Cato ID for the site"), `src_site_name`, `socket_interface` ("Name for
Socket interface"), `socket_serial`, `socket_role`, `link_type`, `pop_name`,
`ISP_name`, `src_isp_ip`, `link_health_latency` / `_jitter` / `_pkt_loss`, and
for IPS events `risk_level`, `severity`, `signature_id`, `threat_name`,
`threat_type`, `rule_name`, `action`, `src_ip`, `dest_ip`, `src_port`,
`dest_port`, `ip_protocol` and `application_name`. The event time is the
record's `time` (ISO 8601, or Unix seconds or milliseconds; Cato's field
description says "Linux epoch format"). The alert keeps a bounded detail of
the link fields; nothing from an event is rendered as HTML.

## Raising and clearing alerts

The alerts are evaluated on the server, like the Meraki alerts and the
topology availability tracker:

- **One alert per entity and condition** (key
  `cato:<source>:<entity type>:<entity id>:<condition>`). An open event opens
  or refreshes it; its recovery event closes it; a closed alert reopens only
  for an event that started after it was resolved, so a replayed or late
  event never reopens it. Down and up in the same page are stored closed and
  raise nothing.
- **Raised once** for a warning or critical alert (again only if it gets
  worse): a monitoring alert (alert type `vendor_alert`, dedup key
  `vendor_alert:<key>`) on the inventory host it matches, by the Socket serial
  of the event, else the host the availability tracker matched to the entity
  or to a device of its site; otherwise straight to the notification channels.
  Info alerts are listed only.
- **Cleared** (acknowledged `auto-resolved`) when the alert closes: its
  recovery event; for a site or link down, a later collection that shows the
  site (or every uplink and tunnel of the site) up, in case the recovery
  event was missed; for a one-shot event, the open TTL.
- **No double notification with the availability tracker.** A site down
  stands for the tracker's site entity, a link down for the uplinks and
  tunnels of its site. When the tracker already alerted on what the event
  stands for, the feed alert is recorded without a notification (shown as
  **Already notified (availability)**); when the feed alert came first, the
  tracker does not notify the same site or links again. The same rule as the
  Meraki feed's device-down alerts.
- **Mutes.** A topology mute of the site (or of the entity) covers its feed
  alerts: they are stored as **Muted** and not raised; creating a mute
  acknowledges the open ones.

The alerts are listed under **Monitoring > Availability > Cato alerts**, with
the event sub-type and how Plexus alerted.

## IPS events

Events of sub-type `IPS` are stored in the vendor-neutral security event store
(kind `ids_alert`, provider `cato`) and listed under Monitoring > Security,
like OPNsense's Suricata alerts:

- one source name per site (`<account> / <site>`), with the site's inventory
  host when the Socket serial or the tracker matches one;
- severity from `risk_level` (High critical, Medium warning, Low info), else
  the rule's `severity` in the same words, else unknown (stored only);
- blocked when `action` is block, prevent, drop, deny or reject, else
  detected only;
- the signature is `signature_id`; a non-numeric id (or none, with a threat
  name) is grouped under a stable number derived from it;
- the alerting is the security event store's: one alert per account and
  signature, resolved after an hour without a new event. A site with an
  inventory host gets a monitoring alert on that host; the sites with none
  share one notification per signature while it stays active;
- a mute of the site covers its IPS events (only that site's; the unmuted
  sites are processed first).

Turn it off with **Keep IPS events as security events** (setting
`security_events`).

## Settings reference

Stored in the `vendor_alert_feeds` auth setting, one entry per provider;
changed under **Topology > Sources > Cato alerts** or with
`PUT /api/monitoring/vendor-alerts/cato/settings` (admin, audited as
`vendor_alerts.settings_updated`; Poll Now as `vendor_alerts.polled`).

| Setting | Default | Meaning |
|---|---|---|
| `poll_enabled` | `true` | Read the events feed on schedule |
| `interval_seconds` | `60` | 30 to 3600 |
| `excluded_sources` | `[]` | Source ids not read |
| `open_ttl_hours` | `24` | A one-shot alert (no recovery event) closes after this long (1 to 720) |
| `security_events` | `true` | Store the IPS events as security events |

Resolved alerts are deleted with the monitoring retention.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/monitoring/vendor-alerts?provider=cato` | Monitoring access. The alerts (`include_resolved`, `org_ref`, `limit`), each with `muted`. Object scope: a scoped caller sees only the alerts raised on hosts it may read |
| GET | `/api/monitoring/vendor-alerts/cato/settings` | Admin. `config`, the interval bounds, `status` and `sources` (per account: last poll, last success, last error, `feed_status`, whether a marker is stored, last event time, events read, next poll) |
| PUT | `/api/monitoring/vendor-alerts/cato/settings` | Admin, audited. Any of the settings above; returns the same body as GET |
| POST | `/api/monitoring/vendor-alerts/cato/poll` | Admin, audited. Read every account now, ignoring back-off and the poll switch; an account another worker is reading is skipped |

See [api-reference.md](api-reference.md#vendor-alert-feeds).

## Troubleshooting

- **Refused by the vendor.** Cato answered the query with an error for the
  account (`errorString`) or refused it; the message is Cato's. Enable the
  events feed for the account in Cato, check the API key's permissions, then
  use Poll Now.
- **No access.** Cato rejected the API key (HTTP 401 or 403), or the source
  has no key.
- **Started (reads from now on).** The first read positioned the marker;
  events from now on are read at the next poll.
- **Rate limited.** Retried at the next back-off; lower the poll rate if it
  keeps happening.
- **A site down was not notified.** It may be muted, or the availability
  tracker already notified it (the row shows **Already notified
  (availability)**).

## Limitations

- Not checked against a live Cato account: what each sub-type means (read
  from its name), the format of the record's `time`, the values of `action`
  and `risk_level`, whether `src_site_id` is the site ID the topology snapshot
  uses (it is what the tracker dedup and the clearing rule match on), the
  rate limit of `eventsFeed` and the error text of an account without the
  events feed.
- A link down event is matched to the tracker by its site (every uplink and
  tunnel of the site), not by link, since the event's interface name and the
  snapshot's link names are not known to match.
- A recovery event that names the interface differently from its down event
  does not close it; the next collection that shows the site and its links up
  does.
- Cato's webhook / SIEM push integrations are not used: the feed is polled.
- The events feed alerts; it does not feed the availability history or
  uptime % (the collections do).
