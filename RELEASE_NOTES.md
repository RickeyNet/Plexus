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
- Working tree: mark Activate failed when Verify Upgrade detects a version mismatch
