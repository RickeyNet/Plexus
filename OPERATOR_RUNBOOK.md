# Operator Runbook

This runbook documents the standard path for converting FortiGate configs to FTD artifacts and applying them safely.

## Preconditions

- `.env` is configured and API auth is enabled for production (`APP_API_TOKEN`, `APP_REQUIRE_API_TOKEN=true`).
- Source FortiGate config file is validated and backed up.
- Target FTD has an out-of-band backup/snapshot before import.

## Standard Workflow

1. Start Plexus and verify service health:
   - `GET /api/health` returns `{"ok": true, ...}`.
2. Upload FortiGate YAML in the converter UI.
3. Run conversion with dry-run enabled first.
4. Review generated diff and conversion summary.
5. Download artifacts archive for record keeping.
6. Run import against target FTD using generated JSON artifacts.
7. Validate interfaces, zones, routes, and rules on target.
8. Deploy changes in FTD when validation is complete.

## Rollback Steps

1. Stop further imports and deployments.
2. Restore target FTD from pre-change backup/snapshot.
3. Re-run import in dry-run mode and review mismatch details.
4. Correct source config or object mappings.
5. Re-apply in a maintenance window.

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
