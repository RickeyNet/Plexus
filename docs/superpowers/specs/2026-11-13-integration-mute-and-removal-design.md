# Muting integration entities and removing ones that are gone

Date: 2026-11-13. Status: approved.

## Intent

Meraki appliances that are down on purpose (a site not installed yet, a
decommissioned site) fill the Dashboard and keep notifying, and nothing in
Plexus can acknowledge, dismiss or disable them. The operator wants two
things:

1. a way to say "this is expected" so the entity stops showing as a problem
   and stops notifying, and
2. an entity that has been removed from Meraki to disappear from Plexus as
   soon as possible, with no manual clean-up.

## How it works today

- `topology_entity_state` (migration 0075, `routes/db/topology_availability.py`)
  holds the current state of every device, site, uplink, tunnel and cloud
  connection each collection reports. `record_snapshot_states`
  (`netcontrol/routes/topology_availability.py`) updates it after every
  stored collection and raises an alert on a change to `degraded` / `down`.
- The Dashboard's "Integrations and cloud" list, the "Needs attention"
  counts and the Integrations cards read that table through
  `dashboard_topology_summary` (`GET /api/dashboard`). There is no
  acknowledge or mute on it.
- An entity absent from a collection becomes `unknown` with `missing = 1`
  and stays listed under Monitoring > Availability until the retention
  purge (`purge_topology_availability`). Collections are hourly by default.
- A collection that ends with warnings (`last_build_status = "partial"`)
  still calls `record_snapshot_states`, so "absent" does not prove
  "deleted".
- Meraki alerts (`netcontrol/routes/meraki_alerts.py`, table `meraki_alerts`)
  are polled every 60 seconds. An alert Meraki no longer reports is resolved.
  There is no dismiss in Plexus.
- Acknowledge and Suppressions (`alert_suppressions`) exist only for
  `monitoring_alerts`, which need an inventory host. Most integration
  entities have none.

## Goals

- Mute one entity, or a whole site, for any provider, with a reason. The
  mute lasts until it is removed.
- A muted entity is not a problem anywhere on the Dashboard, raises no
  notification from either the availability tracker or the Meraki alerts,
  and is still visible (marked "Muted") under Monitoring > Availability.
- An entity removed at the vendor is deleted from Plexus availability
  tracking at the first clean collection that no longer reports it.
- For Meraki, a removed device that had an open alert is deleted within
  about one alert-poll interval (60 seconds by default).
- Evaluated and stored on the server; the browser only displays it.

## Non-goals

- Timed mutes or maintenance windows (the existing Suppressions cover
  inventory hosts; a timed mute can be added later).
- Treating an alert dismissed in the Meraki dashboard as a mute.
- Writing anything to Meraki. Plexus stays read-only.
- Changing how inventory host alerts are acknowledged or suppressed.
- Removing nodes from the topology map (the map is drawn from the latest
  snapshot and already drops what the collection no longer reports).

## Anti-goals

- Deleting an entity that still exists because a collection was partial or
  an API call failed. When in doubt, keep it (today's `unknown` /
  "not in last collection").
- A mute that hides a problem with no trace: every mute and unmute is
  audited and every muted entity can be listed.
- A Meraki-only mechanism. Mute and removal live in the shared tracker
  (CLAUDE.md "Vendor monitoring parity").

## Approaches

**Removal speed** (the user asked for "as soon as it is gone in Meraki"):

1. Next clean collection only. Simple, no API cost, up to one collection
   interval (an hour by default) late.
2. Next clean collection, plus a confirmation call from the 60-second alert
   poll when an alert vanishes. About a minute for a device that had an
   open alert (a down appliance always has one), one extra API call only on
   polls where an alert vanished. **Picked** (Claude's call; the user chose
   the outcome and left the how).
3. A separate inventory poll every few minutes. Catches every removal in
   minutes but spends API budget constantly for a rare event.

**Mute storage:**

1. A column on `topology_entity_state`. Cannot express a site-wide mute
   that covers entities added later, and is lost if the row is recreated.
2. A separate `topology_mutes` table with entity and site scopes, joined
   when reading. **Picked.**
3. Reusing `alert_suppressions`. It is keyed by host / group / metric and
   time-windowed; integration entities have no host. Does not fit.

## Design

### Mutes

New table `topology_mutes` (next free migration number after the ones in
the tree; 0083 is taken by uncommitted work):

| Column | Meaning |
|---|---|
| `provider`, `org_ref` | the source |
| `scope` | `entity` or `site` |
| `entity_type`, `entity_id` | set for `entity` scope |
| `site` | set for `site` scope: the site name as stored in `topology_entity_state.site` |
| `reason` | free text, required, at most 500 characters |
| `created_by`, `created_at` | who and when (UTC text, like the other tables) |

Unique on (`provider`, `org_ref`, `scope`, `entity_type`, `entity_id`,
`site`). DB functions go in `routes/db/topology_availability.py` and are
re-exported through the `routes.database` facade like the existing ones.

An entity is muted when any of these holds (all Claude's calls):

- an `entity` mute matches its key;
- it is an uplink, tunnel or link and an `entity` mute matches the device
  at either end (`meta.a` / `meta.b`): muting a device covers its uplinks
  and tunnels, the same cascade the removal uses;
- a `site` mute matches its provider, org_ref and site;
- it is an uplink, tunnel or link and either end is a device at a muted
  site (a hub-to-branch tunnel is stored under the hub's site, and must
  still be covered by muting the branch).

"Site" is the site name on the entity rows (for Meraki, the network name;
Meraki has no site entity of its own). A site is keyed by name because
that is all the state table holds; a renamed site becomes unmuted, which
fails safe (it shows again). The API accepts a site mute only for a site
name that some tracked entity of that source currently has.

Effects of a mute:

- **Dashboard.** `dashboard_topology_summary` leaves muted entities out of
  `problems` and `problem_count`, and counts them under a new `muted` key
  in `entity_counts`, `by_provider` and `by_source` instead of under
  `down` / `degraded`. A muted entity that is `up` or `unknown` is counted
  as before. The frontend types and the Integrations cards accept the new
  key; cards do not show muted entities as down.
- **Availability tracker.** Transitions are still recorded (the history
  stays true). `record_snapshot_states` does not raise the alert of a
  muted entity, but the entity's `alert_state` is set as if it had been
  raised.
- **Meraki alerts.** `ingest` does not raise an alert whose device (entity
  `d:<serial>`) or network (site name equal to `network_name`) is muted; it
  records the severity in `alert_state` with `alert_via = "muted"`. The
  row is still stored and listed.
- **On mute.** Open `monitoring_alerts` of the muted entities (dedup keys
  `topo:...` and `meraki_alert:...`) are acknowledged as `muted`, using
  the existing `resolve_monitoring_alerts`.
- **On unmute.** Nothing is raised retroactively: an alert swallowed while
  muted counts as already raised. The entity shows on the Dashboard again
  at once if it is still a problem, and notifies again only when it gets
  worse, or recovers and fails again. The existing de-duplication between
  the tracker and the Meraki alerts keeps working unchanged.
- **Availability page.** Stat tiles and average uptime leave muted entities
  out. The State filter gains "Muted". A muted row shows a "Muted" badge
  with reason, who and when, and an Unmute action. The Meraki alerts panel
  marks alerts of muted devices and hides them unless "Show muted" is on.
- **Other readers.** The state table is read only by the Dashboard
  summary, the availability summary endpoints and the Meraki alerts
  lookup; all three are covered above.

API (monitoring feature, the same gate as acknowledging an alert; audited
as `monitoring` / `topology.muted` and `topology.unmuted`):

- `GET /api/availability/topology/mutes`
- `POST /api/availability/topology/mutes` with `provider`, `org_ref`,
  `scope`, (`entity_type`, `entity_id`) or `site`, `reason`
- `DELETE /api/availability/topology/mutes/{id}`

(next to the existing `/api/availability/topology/*` routes)

The availability summary rows and the Dashboard problem rows carry what
the UI needs (`muted`, mute id, reason, by, at).

UI: a "Mute" action on each row of the Dashboard's "Integrations and cloud"
list and of the Availability entities table. It opens one shared dialog:
the entity name, a choice "This device only" / "Everything at site
<name>" (the site choice only when the entity has a site), and a required
reason. Existing components are reused (dialog, badge, buttons); the
dialog is one component used from both places.

```
Mute alerts
  Device  Branch-12 MX (Meraki Example Org)
  ( ) This device only
  (o) Everything at site Branch-12
  Reason  [ Not installed yet, expected Q1            ]
                                   [Cancel] [Mute]
```

### Removal

A collection is **clean** when every call that defines what exists (the
lists of sites / networks and of devices, and for edges the calls their
entity type comes from) succeeded. A failed optional call (per-device
detail, live SSH enrichment and the like) does not make a collection
unclean; otherwise a source with one chronically failing endpoint would
never remove anything. Where one entity type's source call failed, only
that type is treated as not clean. The caller passes this to
`record_snapshot_states` / `apply_topology_entity_states`. For providers where the caller cannot tell (the builder checks
each: Meraki, Cato, FMC, Panorama, Appgate, AWS, Azure, GCP), the flag is
false and today's behaviour stays; the gap is recorded in
`docs/vendor-monitoring-coverage.md`.

- **At a clean collection.** A stored entity the collection does not
  report is deleted from `topology_entity_state`, together with its
  `entity`-scope mute. If it had an open alert, the matching
  `monitoring_alerts` are acknowledged as `auto-resolved`. No notification
  is sent for a removal. Its past transitions stay until the retention
  purge. A `site`-scope mute is deleted when the site itself is no
  longer in the snapshot's site list (the Meraki network was deleted),
  not when it merely has no devices: a site that is not installed yet, or
  is between a device swap, keeps its mute.
- **At a collection that is not clean.** Unchanged: `unknown`, `missing`.
- **Meraki fast path.** When the alert poll resolves alerts because Meraki
  no longer reports them (`resolve_missing_meraki_alerts`), and any of
  those alerts has a device serial with a tracked entity, the poll makes
  one call for that organization, `GET /organizations/{organizationId}/
  devices` filtered to those serials (chunked if there are many). A serial
  that the call succeeds on and does not return is removed: its device
  entity, and the uplink / tunnel / link entities whose `meta.a` or
  `meta.b` is that node, with the same clean-up as above. Any error means
  nothing is removed. The builder confirms against the Meraki API
  reference that this endpoint lists only devices assigned to a network
  and accepts a serial filter; if not, it uses the endpoint that does.
- A removed device that is later claimed again is a new entity (a
  baseline, no alert), unmuted unless its site is muted.

### What disappears where

| Place | After removal |
|---|---|
| Dashboard list, counts, cards | gone |
| Monitoring > Availability entities and outages | gone |
| Meraki alerts panel | resolved (as today), under "Show resolved" until retention |
| Topology map | gone at the next collection (as today) |

## Constraints

- CLAUDE.md: no commits by Claude; CI commands as in
  `.github/workflows/ci.yml`; reuse before writing; no real environment
  data (samples use invented names and documentation ranges); vendor
  parity updates in the same change.
- Docs to update in the same change: `docs/meraki-alerts.md`,
  `docs/meraki-topology.md` (availability tracking),
  `docs/vendor-monitoring-coverage.md`, `docs/api-reference.md`,
  `AUTHORIZATION_MATRIX.md`, `CHANGELOG.md`.
- Tests: `tests/test_topology_availability.py`,
  `tests/test_dashboard_topology.py`, `tests/test_meraki_alerts.py`, the
  migration tests, and the frontend unit tests next to the changed files.
- The alert poll must stay best effort: the confirmation call never fails
  the poll and honours the existing client rate limiting and back-off.

## Left to the builder

- Migration number and index choices.
- Exact response field names, and whether mute data is joined in SQL or in
  Python.
- How each provider's collection reports "clean".
- Dialog and button placement details within the existing style guide
  (`FRONTEND_STYLE.md`).
- Serial chunk size for the confirmation call.
