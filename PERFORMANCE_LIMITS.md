# Performance and Scale Notes

These are practical limits observed for current conversion/import workflows.

## Expected Ranges

- Small config: under 500 objects/rules, typically completes in minutes.
- Medium config: 500-2,000 objects/rules, expect longer API import stages.
- Large config: over 2,000 objects/rules, requires staged imports and careful review.

## Known Constraints

- Import/cleanup workflows use FTD FDM API and are bound by FTD API throughput.
- High object counts can trigger transient 429/5xx responses.
- Interface and routing dependencies require ordered imports.

## Recommended Settings for Large Imports

- Increase API timeout (`--api-timeout`) to 60-120 seconds.
- Increase retries (`--api-retries`) to 5 for unstable links.
- Use non-zero retry backoff (`--api-retry-backoff`) to reduce request bursts.
- Import by domain (objects, groups, interfaces, routes, rules) instead of all at once.

## Validation Checklist for Large Runs

- Run dry-run first and store diff artifacts.
- Keep a target firewall backup for rollback.
- Monitor `/api/health` during processing.
- Verify route/rule counts before deploy.
