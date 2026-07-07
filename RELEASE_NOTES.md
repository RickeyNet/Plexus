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
- Reduced dashboard and page-load API churn.
- Removed the dashboard topology mini-map from first paint.
- Enabled frontend performance mode by default and switched the starfield to a
  lower-overhead static path.

### Compliance and UI
- Replaced native compliance confirm/alert prompts with shared themed dialogs.

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

### Reliability
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
- `2878030` Add per-device upgrade activation cancellation
- `d17fe3f` perf(upgrades): speed campaigns list and bound event replay
- `1589dd2` feat(compliance): replace native confirm/alert with themed dialogs
- `f13a019` feat(upgrades): add an Upcoming reloads overview to the Campaigns tab
- `eeadaf8` feat(upgrades): turn campaign phases into a guided step sequence
- `4f10250` feat(upgrades): surface scheduled reloads in campaign views
- `a67178d` fixing failure
- `3667c24` update .dockerignore
- `0ffecf6` fix(docker): ensure firmware image storage is writable on startup
- `1af4f58` fix(upgrades): repair image upload/delete and replace system dialogs
- `b4a3d27` perf(monitoring): index latest polls and batch post-poll DB writes
- `13e52a4` perf(frontend): reduce dashboard and page-load API churn
- `8c5d5d9` perf(dashboard): remove topology mini-map from home page
- `a9d9902` perf(frontend): use static starfield and enable performance mode by default
- Security maintenance: access-control, input-handling or resource-limit updates; detailed review notes are maintained privately.
- Security maintenance: access-control, input-handling or resource-limit updates; detailed review notes are maintained privately.
- Security maintenance: access-control, input-handling or resource-limit updates; detailed review notes are maintained privately.
- Working tree: mark Activate failed when Verify Upgrade detects a version mismatch
