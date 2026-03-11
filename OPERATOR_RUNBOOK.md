# Operator Runbook

This runbook documents the standard path for converting FortiGate configs to FTD artifacts and applying them safely.

For full workflow examples and CLI/API reference see [V2_WORKFLOW_GUIDE.md](V2_WORKFLOW_GUIDE.md).

## Preconditions

- `.env` is configured and API auth is enabled for production (`APP_API_TOKEN`, `APP_REQUIRE_API_TOKEN=true`).
- Source FortiGate config file is validated and backed up.
- Target FTD has an out-of-band backup/snapshot before import.

## Standard Workflow

1. Start Plexus and verify service health:
   - `GET /api/health` returns `{"ok": true, ...}`.
2. Upload FortiGate YAML in the converter UI.
3. Run conversion and review the summary before importing.
4. Download artifacts archive for record keeping.
5. Run import against target FTD using generated JSON artifacts.
6. Validate interfaces, zones, routes, and rules on target (see checklist below).
7. Deploy changes in FTD when validation is complete.

## Post-Conversion Verification Checklist

Run these checks after Step 3 (conversion) and before triggering any import.

- [ ] `conversion_output.log` — no unexpected `[WARN]` or `[ERROR]` lines
- [ ] `address_objects.json` — object count matches expected (`jq length ftd_config_address_objects.json`)
- [ ] `address_groups.json` — spot-check that groups have non-empty member lists (empty members = unresolvable reference in source)
- [ ] `service_objects.json` — TCP + UDP totals match source policy service definitions
- [ ] `access_rules.json` — rule count and permit/deny ratio reasonable; check `conversion_summary.access_rules`
- [ ] `static_routes.json` — `converted` count is expected; `blackhole_skipped` is intentional (null-routes dropped)
- [ ] `metadata.json` — `target_model` matches the physical FTD appliance being imported into
- [ ] `subinterfaces.json` / `physical_interfaces.json` — interface names match FTD hardware naming (`Ethernet1/x`)
- [ ] No duplicate names in `address_objects.json` (`jq '[.[].name] | unique | length' ftd_config_address_objects.json`)
- [ ] Download artifacts zip and archive it before importing

## Post-Import Verification Checklist

Run these checks after import completes and before issuing a deploy.

- [ ] FTD Objects page — address object count matches `conversion_summary.address_objects`
- [ ] FTD Object Groups page — group count matches `conversion_summary.address_groups`
- [ ] FTD Service Objects page — service object count matches `conversion_summary.service_objects.total`
- [ ] FTD Interfaces page — all expected physical and subinterfaces are present with correct zones
- [ ] FTD Routing page — static route count matches `conversion_summary.static_routes.converted`
- [ ] FTD Access Control Policy — rule count matches `conversion_summary.access_rules.total`, order is preserved
- [ ] No interface is in an error/admin-down state that should be up
- [ ] No pending-deploy error indicators in FDM UI before deploying
- [ ] Test traffic path for a representative rule (if possible, on a non-production window)

## Rollback Steps

1. Stop further imports and deployments.
2. Restore target FTD from pre-change backup/snapshot.
3. Re-run import in dry-run mode and review mismatch details.
4. Correct source config or object mappings.
5. Re-apply in a maintenance window.

## SQLite to PostgreSQL Migration (Deployment Upgrade)

Use this when moving from local/dev SQLite persistence to PostgreSQL-backed runtime.

1. Stop Plexus writes (maintenance window).
2. Backup SQLite DB file (`routes/netcontrol.db`) and PostgreSQL volume/snapshot.
3. Run dry-run validation:
  - `python tools/migrate_sqlite_to_postgres.py --dry-run`
4. Run migration:
  - `python tools/migrate_sqlite_to_postgres.py --sqlite-path routes/netcontrol.db --postgres-url postgresql://plexus:plexus@localhost:5432/plexus --with-checksums`
5. Verify parity report shows `[OK]` for all tables and checksum verification shows no mismatches.
6. Set `APP_DB_ENGINE=postgres` and restart Plexus.
7. Validate `GET /api/health`, login, inventory, and recent jobs pages.

---

## Partial Import Failure Recovery Playbook

Import failures are stage-specific — only the failed stage needs to be re-run. The importer
skips objects that already exist (duplicate detection), so re-running a stage is safe.

### 1. Identify which stage failed

Import output uses a structured line format:

```
Address Objects    12.3s [OK]
Address Groups      3.1s [FAIL]
```

The first `[FAIL]` line marks the stage to resume from.

### 2. Fix the root cause before re-running

| Symptom | Likely Cause | Fix |
|---|---|---|
| `404 Not Found` on group import | Dependent address object was not imported | Re-run `--only-address-objects` first, then groups |
| `409 Conflict / already exists` | Object present from a previous partial run | Safe to ignore — importer skips duplicates by default |
| `404 Not Found` on route/rule import | Referenced interface or object missing | Import missing dependency stage first |
| `422 / hardwareName not found` | Interface name mismatch for target model | Check `metadata.json` target_model vs actual FTD hardware |
| `429 Too Many Requests` | FTD API rate limiting | Reduce `--workers`, add `--retry-backoff 1.0 --retry-attempts 6` |
| `5xx` transient errors | FTD API congestion or instability | Retry same stage with `--retry-attempts 6 --retry-backoff 0.5` |
| Stage times out completely | Network or FDM unresponsive | Check FTD management plane, increase `--api-timeout` |

### 3. Re-run only the failed stage

```bash
# Example: groups failed because objects were partially missing
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config \
    --only-address-objects   # ensure objects are complete first

python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config \
    --only-address-groups    # now re-run the failed stage
```

```bash
# Example: route import failed with transient 5xx
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config \
    --only-routes \
    --retry-attempts 6 --retry-backoff 0.5 --retry-jitter-max 0.4
```

```bash
# Example: rule import failed with 429 rate limiting
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config \
    --only-rules \
    --workers 2 --retry-attempts 8 --retry-backoff 1.0
```

### 4. Dependency order for manual re-sequencing

If you need to re-run multiple stages manually, respect this order:

```
address_objects  →  address_groups
service_objects  →  service_groups
physical_interfaces  →  etherchannels  →  security_zones  →  subinterfaces  →  bridge_groups
(all of the above)  →  routes  →  rules  →  deploy
```

Stages within the same row have no mutual dependency and can be run in any order relative to each other.

### 5. When to do a full cleanup and re-import

If the FTD state is inconsistent (partial objects from multiple runs, mismatched counts), prefer
cleanup over incremental repair:

1. Run the cleanup tool to remove all previously imported objects.
2. Re-verify the source YAML has not changed.
3. Re-run conversion to regenerate fresh artifacts.
4. Re-run a full import from scratch.

> **Do not deploy** until the post-import verification checklist above passes.

### 6. Preserving artifacts for post-mortem

Before a cleanup, archive the current session artifacts:

```bash
curl -o pre-cleanup-artifacts.zip \
  "http://localhost:8080/api/converter-session/$SESSION_ID/download" \
  -H "X-API-Token: $TOKEN"
```

---

## FAQ (Mismatch Causes)

- Object not found during route/rule import:
  - Cause: dependency order issue or renamed object.
  - Action: import object sets first, then routes/rules.

- Interface reference errors:
  - Cause: hardwareName mismatch with target model.
  - Action: review metadata target model and interface mapping.

- Duplicate object errors:
  - Cause: object already exists in FTD.
  - Action: cleanup stale objects or allow importer skip logic.

- Timeout/API transient failures:
  - Cause: FTD API congestion or intermittent connectivity.
  - Action: increase timeout/retries and rerun the failed stage.

---

## Incident Response Scenarios

Use this section for live operational incidents where immediate containment and
clear rollback paths matter more than feature delivery.

### Scenario 1: Suspected API token exposure

Symptoms:
- API requests from unknown source IPs.
- Unexpected admin/config changes in audit logs.

Immediate actions:
1. Rotate `APP_API_TOKEN` in `.env`.
2. Restart Plexus so the new token is enforced.
3. Temporarily set `APP_REQUIRE_API_TOKEN=true` if it is not already set.
4. Review `/api/admin/audit-events` for unauthorized actions.

Recovery:
1. Revoke/replace any exposed credentials used during affected window.
2. Re-run critical config operations in dry-run to verify intended state.
3. Document timeline and impacted endpoints.

### Scenario 2: Conversion/import causes production policy impact

Symptoms:
- Traffic drops after import/deploy.
- FTD policy object/rule counts diverge from conversion summary.

Immediate actions:
1. Stop additional imports/deploys.
2. Restore pre-change FTD backup/snapshot.
3. Preserve converter artifacts zip and importer logs for forensics.

Recovery:
1. Compare generated artifacts with previous known-good snapshot via diff.
2. Re-run conversion and import in dry-run mode only.
3. Re-introduce change during maintenance window after checklist re-validation.

### Scenario 3: SQLite DB lock or app instability

Symptoms:
- Intermittent `database is locked` errors.
- API latency spikes or failed writes.

Immediate actions:
1. Check host disk space and inode usage.
2. Restart Plexus process/container.
3. Verify `/api/health` and confirm job backlog status.

Recovery:
1. Archive and rotate oversized logs/artifacts if disk pressure is present.
2. Run retention cleanup endpoint (`/api/admin/retention/cleanup-now`).
3. If corruption is suspected, restore `routes/netcontrol.db` from backup.
4. For VM/shared-folder deployments, move SQLite to local VM disk via `APP_DB_PATH` and increase lock wait via `APP_SQLITE_BUSY_TIMEOUT_MS`.

### Scenario 4: Release rollout mismatch (tag/version/changelog)

Symptoms:
- Release pipeline fails validation.
- Published image tag does not match expected app version.

Immediate actions:
1. Run `python tools/check_release_consistency.py <tag>` locally.
2. Align `netcontrol/version.py` and latest `CHANGELOG.md` entry.
3. Re-tag release with correct semantic version if needed.

Recovery:
1. Re-run release workflow after metadata is aligned.
2. Verify GHCR image tags include both `vX.Y.Z` and `latest`.
3. Capture release notes update in post-incident report.
