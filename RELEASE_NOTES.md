# Release Notes

## Unreleased changes after 1.0.2

These notes summarize the commits after the 1.0.2 changelog entry, plus the
current upgrade verification fix in the working tree.

### Upgrade Campaigns
- Added per-device activation cancellation so operators can stop selected
  devices that are stuck or failed in Activate without reloading them during
  business hours.
- Fixed Verify Upgrade version mismatches so devices that remain on the wrong
  image mark both Verify and Activate as failed.
- Reworked campaigns into a guided Prestaging -> Transfer -> Activate -> Verify
  sequence.
- Added scheduled reload visibility in campaign views and an Upcoming reloads
  overview on the Campaigns tab.
- Improved campaign list performance and bounded WebSocket event replay.
- Fixed image upload/delete handling and replaced native browser dialogs with
  Plexus-themed dialogs.

### Performance
- Added monitoring poll indexes and batched post-poll database writes.
- Folded the SLA-summary per-host jitter calculation into the main grouped
  query, removing one extra database round-trip per host (500 queries on a
  500-host summary).
- Added indexes on `config_snapshots(host_id)` and
  `config_drift_events(host_id, status)` so drift dashboards and bulk scans no
  longer full-scan ever-growing tables.
- Bounded job-event replay and audit-chain verification so a verbose job or a
  large audit log no longer loads the whole table into memory at once.
- Reduced dashboard and page-load API churn.
- Removed the dashboard topology mini-map from first paint.
- Enabled frontend performance mode by default and switched the starfield to a
  lower-overhead static path.
- SNMP table walks now use GETBULK (v2c/v3) instead of one-per-row GETNEXT,
  cutting round-trips ~25x on large tables. Every collector (monitoring,
  MAC/ARP, interface inventory, neighbor discovery) funnels through the one
  walk primitive, so all of them benefit. v1 falls back to GETNEXT.
- The topology graph (`/api/topology`) and the interface-utilization map (the
  `/utilization` endpoint + its SSE stream) are served from short-TTL,
  per-group caches with a coalescing lock, so opening several Topology tabs no
  longer re-runs the heaviest handler on every load/tick. The graph cache is
  invalidated on discovery link writes and change acknowledgement.
- The dashboard bandwidth-trend panel fetches every top interface's series in
  one windowed query instead of one query per interface (N+1 removed).
- The monitoring poll loop preloads active alert-suppressions once per cycle and
  matches them in memory instead of issuing one suppression query per firing
  check per host; vendor-OID resolution is likewise cached per device_type
  (invalidated when overrides change) instead of re-queried per host per cycle.
- Inferred-topology discovery now bounds its per-host MAC/ARP + data-source
  collection with the shared device-op semaphore, so a large subnet can't fire
  2xN heavy SNMP/CLI collectors at once.
- Charts reuse their ECharts instance via `setOption` instead of disposing and
  re-initialising the canvas on every data refresh (up to ~14 charts on a
  device's Interfaces tab).
- Federation background sync fetches all peers concurrently; the config-drift
  check loads only baselined host ids (not every baseline's full config blob);
  large floor-plan image uploads write off the event loop; compliance regexes
  are compiled once and cached; and `include_details` monitoring-poll queries
  are bounded so a wide limit can't serialise thousands of full blobs.
- Added a `compliance_scan_results(host_id, profile_id, id)` index so the
  compliance dashboard/summary no longer full-scans that table.

### Compliance and UI
- Replaced native compliance confirm/alert prompts with shared themed dialogs.
- Fixed a compliance false-pass: `must_contain` / `must_not_contain` rules now
  match config directives line-anchored and negation-aware, so a device with a
  hardening feature explicitly disabled (e.g. `no service password-encryption`)
  is no longer reported compliant. `regex_match` now searches up to 2 MB and
  flags when a large config was truncated instead of silently failing.
- Frontend now renders FastAPI request-validation (422) errors as readable
  "field: message" text instead of `[object Object]`.
- Nested modals now track the Escape-close stack by a stable per-instance
  token, so a background poll re-rendering the page can't reorder the stack and
  make Escape close the wrong (outer) dialog.
- A failed sign-out no longer bricks the account: the button re-enables, the
  CSRF token is only cleared once the server has ended the session (so a
  transient failure can't leave a live session unable to submit anything), and
  the error is surfaced with a retry.
- The IPAM Refresh button now invalidates the correct query keys, so the
  reconcile-runs and DHCP panels actually refresh (they previously no-op'd).
- Device-detail, audit, error-trending, flow, and custom-dashboard views now
  parse naive backend (UTC) timestamps through a shared helper, fixing times
  that displayed shifted by the browser's timezone offset.

### Data correctness
- Per-interface bandwidth rates are computed again. The rate math subtracted a
  naive stored timestamp from an aware "now", raising a TypeError that a broad
  except swallowed — so every interface rate stayed NULL and the bandwidth
  dashboard and error-spike detection were silently dead. Stored timestamps are
  now normalized to UTC, and the metric-engine counter delta is width-aware so a
  counter reset no longer fabricates a multi-terabit spike.
- IPAM subnet-utilization snapshots no longer enumerate the address space; an
  IPv6 /64 previously materialized 2**64 addresses and exhausted memory.
  Utilization is computed with integer membership math, and point-to-point
  `/31` and `/127` subnets now report both usable hosts instead of zero.
- Topology weathermap counter-wrap handling is now width-aware: a device
  reboot no longer fabricates a utilization spike on 64-bit interface counters
  (a reset is dropped rather than "corrected" by +2**32).
- STP root-election instability now alerts when the recent-change count meets
  or exceeds the threshold (an exact-match check previously missed rapid churn
  that jumped past the threshold between polls).
- Syslog severity 3 (Error) now maps to warning rather than critical, so
  routine device errors don't flood the critical tier.
- Juniper serial parsing no longer returns a chassis part number on models
  that populate the part-number column.

### Security and access control
- Enforced credential ownership on every operational endpoint (job launch,
  deployments, config backups/drift, compliance, upgrades, risk analysis, and
  inventory), closing a privilege-escalation issue where any user could run
  operations with another user's stored credential by supplying its id.
  Background jobs re-validate against the task's original submitter, and each
  credential use is now recorded in the audit log.
- Scoped upgrade campaign details, events, and the live output stream to the
  campaign's creator (or an admin), so device output and config captures are no
  longer readable by other users via the campaign id.
- Required HTTPS for federation peer URLs (the peer API token is
  admin-equivalent) with per-peer TLS verification on by default.
- Rejected empty-password LDAP/RADIUS binds that some directory servers treat
  as an unauthenticated bind.
- Enforced the forced-password-change gate and object ownership on WebSocket
  streams; disabled the dev-only admin bootstrap by default in production
  containers.
- Rejected non-positive `limit` values on capped list endpoints. SQLite treats
  `LIMIT -1` as unlimited, so a `?limit=-1` on an endpoint that declared only
  an upper bound previously returned the entire table (MAC search, deployments,
  audit findings, flows, syslog/trap events, risk analyses).
- Closed a deployment execute race: two concurrent `/execute` calls could both
  read `planning` status and both push commands to devices. Execution now
  atomically claims the deployment; the loser gets a 409.
- Bounded request fields that reach device commands (deployment
  `proposed_commands`, campaign `image_map`) so an unbounded payload can't be
  submitted.
- Stopped leaking raw exception text in error responses on the config-drift,
  DHCP-sync and lab-create paths (details are logged server-side).
- Campaign creation now reports host ids it could not add (unknown or
  duplicate) instead of silently building a smaller campaign than requested.
- Cloud account credentials (AWS secret keys, Azure client secrets, GCP key
  material) are no longer returned by the accounts/topology GET endpoints —
  responses expose only whether a credential is configured — and are now
  encrypted at rest with the shared key (legacy plaintext rows are read
  transparently and re-encrypted on next save), matching IPAM/DHCP sources.
- Lab topology management subnets are validated as strict CIDRs before they
  reach the containerlab YAML, closing a YAML-injection path that could run
  arbitrary nodes/binds/exec directives on the lab host.
- Custom dashboards and their panels now enforce per-owner access on read,
  update, delete, and listing (an admin still sees all), closing an IDOR where
  any dashboard user could read or overwrite another user's dashboards by id.
- Promoting a lab run to a deployment now enforces credential ownership, so a
  user can't bind another user's stored credential to a production deployment.
- Custom vendor-OID registry writes/deletes now require admin (custom entries
  override SNMP polling OIDs fleet-wide); the read-only listing stays available.
- Capacity-planning projection length is bounded (1–365 days) and the ETA
  calculation is clamped, so a huge `projection_days` can no longer freeze the
  event loop building projection points or overflow into a 500.
- Admin user create/update reject an unknown role instead of silently coercing
  it; deleting the last admin is blocked atomically (the check lives inside the
  DELETE, so concurrent deletes can't leave zero admins); a failed group
  assignment during user creation rolls the half-created account back.
- Password hashing (PBKDF2, 600k iterations) now runs off the event loop, so a
  burst of logins can no longer stall every other request; discovery reverse-DNS
  lookups were likewise moved off the loop.
- Tightened the Content-Security-Policy: `script-src` is now `'self'` only
  (dropping `'unsafe-inline'` and the CDN) since the React app ships as external
  hashed modules. The single-purpose graph-export embed page, which needs an
  inline bootstrap and CDN ECharts, carries its own scoped CSP and renders only
  escaped, data-only content.
- Admin SIEM-sink and notification-channel create/update/delete now serialize
  their read-modify-write of the in-memory config under a lock, so two
  concurrent admin edits can no longer duplicate an id or silently drop one
  edit by racing the persist.

### Database backends
- Hardened the Postgres (asyncpg) compatibility layer so the pg backend matches
  SQLite behavior: added the missing `rollback()` (its absence turned every
  expected integrity error into a 500), fetched rows for hand-written
  `RETURNING` inserts and any `RETURNING` statement (previously discarded, which
  crashed MAC/ARP upserts and baseline/data-source writes), backfilled the
  lastrowid table allowlist (dashboards, IPAM/DHCP, geo, metrics — inserts there
  had been losing their ids), and gave the flow/cloud timeline (`strftime`/
  `printf`) and SLA MTTR/MTTD (`julianday`) queries Postgres branches so they no
  longer 500.

### Reliability
- Fire-and-forget background tasks (fleet MAC/ARP collection, discovery scans,
  metric-engine event stores) now retain a strong reference and log crashes, so
  a task can't be garbage-collected mid-run — which previously could strand the
  collection lock and 409 every subsequent run.
- Jobs interrupted by a crash or restart are now reconciled on startup instead
  of staying "running" indefinitely, which previously could permanently block
  the job queue; jobs left queued also resume after a restart.
- In-flight jobs get a graceful drain window on shutdown so a firmware push or
  config deploy is not severed mid-write.
- Supervised background capture/deployment tasks so a failure can no longer
  silently strand a job or leave a stream open with no completion.
- Added an application-wide error boundary: a page that fails to load after a
  new deploy (or an unexpected render error) now shows a reload/recover prompt
  instead of a blank screen. Fixed config job output that could bleed between
  streams, and made cancel/retry refresh a job's status immediately.

### Deployment
- Ensured firmware image storage is writable at container startup.
- Improved Docker build context hygiene and container startup behavior.
- Stopped publishing the app port on all host interfaces (reachable via nginx
  with TLS/security headers, or loopback for local debugging).
- Persisted uploaded floor-plan images on the state volume (previously lost on
  container recreate); added container memory limits and a shutdown grace
  period, and documented security-relevant environment variables.

### Source commits covered
- `b75c3c7` Add per-device upgrade activation cancellation
- `fd10cd8` perf(upgrades): speed campaigns list and bound event replay
- `c9258ec` feat(compliance): replace native confirm/alert with themed dialogs
- `80baefe` feat(upgrades): add an Upcoming reloads overview to the Campaigns tab
- `9ede92d` feat(upgrades): turn campaign phases into a guided step sequence
- `2744fc7` feat(upgrades): surface scheduled reloads in campaign views
- `8a60a0c` fixing failure
- `ec37873` update .dockerignore
- `96e7df0` fix(docker): ensure firmware image storage is writable on startup
- `07534ac` fix(upgrades): repair image upload/delete and replace system dialogs
- `85f5a75` perf(monitoring): index latest polls and batch post-poll DB writes
- `7e387cd` perf(frontend): reduce dashboard and page-load API churn
- `d6c840a` perf(dashboard): remove topology mini-map from home page
- `3b5b537` perf(frontend): use static starfield and enable performance mode by default
- `5af9be8` fix(security): enforce object-level authz, session revocation, TLS & SSRF hardening
- `62bc3d9` fix(security): close remediation IDOR, require HTTPS for federation peers, audit credential use
- `3ba2052` fix: harden job lifecycle, close IDOR/WS gaps, add ErrorBoundary, ops cleanups
- Working tree: mark Activate failed when Verify Upgrade detects a version mismatch
