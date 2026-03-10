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

### Import worker and retry controls

Use stage-scoped controls in `ftd_api_importer.py` to keep parallelism bounded and retries predictable:

- Global worker cap: `--workers` (capped at 32)
- Stage worker overrides:
	- `--workers-address-objects`
	- `--workers-service-objects`
	- `--workers-subinterfaces`
- Global retry override: `--retry-attempts`
- Stage retry overrides:
	- `--retry-attempts-address-objects`
	- `--retry-attempts-service-objects`
	- `--retry-attempts-subinterfaces`
- Global initial backoff override: `--retry-backoff`
- Stage backoff overrides:
	- `--retry-backoff-address-objects`
	- `--retry-backoff-service-objects`
	- `--retry-backoff-subinterfaces`
- Retry jitter control: `--retry-jitter-max`

Example:

```bash
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
	--host 10.10.10.10 --username admin --password '***' --base ftd_config \
	--workers 8 --workers-subinterfaces 4 \
	--retry-attempts 4 --retry-attempts-subinterfaces 3 \
	--retry-backoff 0.3 --retry-backoff-subinterfaces 0.2
```

### Large-config benchmark and profiling

Run the synthetic benchmark to profile flattening/expansion/route hotspots for 2k+ scale:

```bash
python tools/benchmark_converter_scale.py --objects 2200 --rules 2200 --routes 1200
```

This prints per-stage timings and top cumulative `cProfile` hotspots.

## Validation Checklist for Large Runs

- Run dry-run first and store diff artifacts.
- Keep a target firewall backup for rollback.
- Monitor `/api/health` during processing.
- Verify route/rule counts before deploy.
