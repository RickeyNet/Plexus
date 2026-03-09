# FortiGate → FTD Conversion: v2 Workflow Guide

This guide covers the end-to-end v2 workflow: convert a FortiGate YAML config into FTD JSON
artifacts, review what was generated, import stage-by-stage, and verify the result.

---

## Prerequisites

- Plexus service running and healthy (`GET /api/health` → `{"ok": true}`)
- `APP_API_TOKEN` set and `APP_REQUIRE_API_TOKEN=true` for production
- Source FortiGate YAML exported and validated (back it up first)
- Target FTD backed up or snapshot taken before any import
- Network access to FTD management plane (port 443, HTTPS)

---

## Step 1 — Convert

### Via API (recommended)

```bash
curl -s -X POST http://localhost:8080/api/convert-only \
  -H "X-API-Token: $TOKEN" \
  -F "yaml_file=@AT1EU-500E-Master_7-4.conf.yaml" \
  -F "target_model=ftd-3120" \
  | jq '{session_id, target_model, snapshot_id, summary}'
```

Response:

```json
{
  "session_id": "adb378b8-0ef7-4002-8242-1826665908b7",
  "target_model": "ftd-3120",
  "snapshot_id": "20260309_143022",
  "summary": {
    "conversion_summary": {
      "address_objects": 412,
      "address_groups": 87,
      "service_objects": { "total": 97, "tcp": 62, "udp": 35, "split": 4 },
      "service_groups": 23,
      "access_rules": { "total": 218, "permit": 196, "deny": 22 },
      "static_routes": { "total": 34, "converted": 31, "blackhole_skipped": 2, "other_skipped": 1 },
      "interfaces": {
        "physical_updated": 8,
        "subinterfaces_created": 14,
        "etherchannels_created": 0,
        "bridge_groups_created": 0,
        "security_zones_created": 6,
        "skipped": 2
      }
    }
  }
}
```

Save `session_id` — it is required for all subsequent import and artifact operations.

### Via CLI (direct)

```bash
python Firewall_converter/converter_v2/fortigate_converter_v2.py \
    AT1EU-500E-Master_7-4.conf.yaml \
    --target-model ftd-3120 \
    --output ftd_config \
    --pretty
```

Lists supported target models:

```bash
python Firewall_converter/converter_v2/fortigate_converter_v2.py --list-models
```

---

## Step 2 — Review Artifacts

After conversion the session directory contains these files (all prefixed `ftd_config_`):

| Artifact | Contents |
|---|---|
| `metadata.json` | Target model, output basename, HA port, schema version |
| `address_objects.json` | Network host/range/subnet objects |
| `address_groups.json` | Nested group flattened to leaf member lists |
| `service_objects.json` | TCP/UDP port objects (split services expanded) |
| `service_groups.json` | Port group objects |
| `physical_interfaces.json` | Physical interface configurations |
| `subinterfaces.json` | VLAN subinterfaces |
| `etherchannels.json` | Port-channel interfaces |
| `bridge_groups.json` | Bridge-group/BVI interfaces |
| `security_zones.json` | Interface security zones |
| `static_routes.json` | Static route objects |
| `access_rules.json` | Access control rules (ordered) |
| `summary.json` | Counts by category |
| `conversion_output.log` | Full converter stdout (warnings, skip reasons) |

### Fetch a single artifact

```bash
curl -s "http://localhost:8080/api/converter-session/$SESSION_ID/file/ftd_config_access_rules.json" \
  -H "X-API-Token: $TOKEN" | jq length
# → 218
```

### Download all artifacts as a zip

```bash
curl -o artifacts.zip \
  "http://localhost:8080/api/converter-session/$SESSION_ID/download" \
  -H "X-API-Token: $TOKEN"
```

### Things to verify before importing

- `conversion_output.log` — check for `[WARN]` or `[SKIP]` lines; skipped objects will not appear in FTD
- `access_rules.json` rule count matches expected policy size
- `address_groups.json` member lists are non-empty (empty members indicate unresolvable references)
- `static_routes.json` `blackhole_skipped` is expected (null-routes are intentionally dropped)
- `metadata.json` `target_model` matches the physical device you are importing into

---

## Step 3 — Import

The importer runs in dependency order:
`objects → groups → interfaces → routes → rules → (deploy)`

### Full import via API

```bash
curl -s -X POST http://localhost:8080/api/import-fortigate \
  -H "Content-Type: application/json" \
  -H "X-API-Token: $TOKEN" \
  -d '{
    "session_id": "adb378b8-0ef7-4002-8242-1826665908b7",
    "host": "10.10.10.10",
    "username": "admin",
    "password": "YourFDMPassword",
    "deploy": false
  }'
```

Set `"deploy": true` only after reviewing the import summary output.

### Full import via CLI

```bash
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 \
    --username admin \
    --password 'YourFDMPassword' \
    --base ftd_config \
    --workers 6
```

### Streaming import (live output)

```bash
curl -s -N -X POST http://localhost:8080/api/import-fortigate-stream \
  -H "Content-Type: application/json" \
  -H "X-API-Token: $TOKEN" \
  -d '{
    "session_id": "adb378b8-0ef7-4002-8242-1826665908b7",
    "host": "10.10.10.10",
    "username": "admin",
    "password": "YourFDMPassword",
    "deploy": false
  }'
```

### Selective stage import (resume after partial failure)

Re-run only the failed stage without touching stages that already completed:

```bash
# Re-import only address objects
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --only-address-objects

# Re-import only service objects
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --only-service-objects

# Re-import only subinterfaces
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --only-subinterfaces

# Re-import only static routes
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --only-routes

# Re-import only access rules
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --only-rules
```

Full list of `--only-*` flags:

| Flag | Stage |
|---|---|
| `--only-address-objects` | Network host/range/subnet objects |
| `--only-address-groups` | Network object groups |
| `--only-service-objects` | TCP/UDP port objects |
| `--only-service-groups` | Port group objects |
| `--only-physical-interfaces` | Physical interface config |
| `--only-etherchannels` | Port-channel interfaces |
| `--only-subinterfaces` | VLAN subinterfaces |
| `--only-bridge-groups` | Bridge-group/BVI interfaces |
| `--only-security-zones` | Security zone assignments |
| `--only-routes` | Static routes |
| `--only-rules` | Access control rules |

### Single-file selective import

```bash
# Import a specific JSON file with an explicit type
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --file ftd_config_address_objects.json \
    --type networkobject
```

### Large-config tuning

```bash
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config \
    --workers 8 \
    --workers-address-objects 8 \
    --workers-service-objects 8 \
    --workers-subinterfaces 4 \
    --retry-attempts 5 \
    --retry-backoff 0.4 \
    --retry-jitter-max 0.3
```

See [PERFORMANCE_LIMITS.md](PERFORMANCE_LIMITS.md) for full tuning reference.

---

## Step 4 — Deploy

Deploy is a separate step so you can validate FTD state before committing.

```bash
# Via CLI — add --deploy flag to any import invocation
python Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py \
    --host 10.10.10.10 --username admin --password '***' \
    --base ftd_config --deploy
```

Or via the API import request with `"deploy": true` after you have confirmed the staged config.

> **Warning:** Deploy triggers FTD to apply all pending changes. Validate interfaces, routes,
> and rule counts in FTD before deploying in production.

---

## Supported Target Models

Run the following to list all supported `--target-model` values:

```bash
python Firewall_converter/converter_v2/fortigate_converter_v2.py --list-models
```

Models are defined in `Firewall_converter/converter_v2/core/interface_converter.py` (`FTD_MODELS`).

---

## Session Lifecycle

| Event | State |
|---|---|
| `POST /api/convert-only` | Session created; in-memory + on-disk files |
| In-memory TTL | 2 hours (evicted from cache; disk files remain) |
| Disk retention | Configurable via `converter_session_retention_days` (default: 7 days) |
| Snapshot files | Retained for `converter_backup_retention_days` (default: 3 days) |
| `GET /api/converter-sessions` | Lists all active on-disk sessions |

Sessions that have been evicted from memory are reloaded from disk on first access.

---

## Related Docs

- [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md) — recovery playbook and verification checklists
- [PERFORMANCE_LIMITS.md](PERFORMANCE_LIMITS.md) — scale limits and worker/retry tuning
- [DATA_RETENTION.md](DATA_RETENTION.md) — session and backup retention configuration
- [RADIUS_CONFIGURATION_GUIDE.md](RADIUS_CONFIGURATION_GUIDE.md) — auth setup
