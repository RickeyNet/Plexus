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

### Deployment
- Ensured firmware image storage is writable at container startup.
- Improved Docker build context hygiene and container startup behavior.

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
- Working tree: mark Activate failed when Verify Upgrade detects a version mismatch
