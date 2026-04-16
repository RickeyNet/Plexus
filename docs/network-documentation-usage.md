# Automated Network Documentation - Usage Guide

This guide explains how to use Plexus automated network documentation features:

- On-demand report generation
- Export formats: `CSV`, `SVG`, `draw.io`, `PDF`
- Scheduled report generation
- Artifact history and downloads
- Optional circuit enrichment from billing metadata

## What the Report Includes

The `network_documentation` report is generated from discovered data in Plexus and includes:

- Device inventory
- Topology links
- IP plan/subnet summary
- VLAN map
- Circuit map (when billing circuits exist)
- Summary row with counts

## Prerequisites

Before generating docs, make sure you have at least:

- Devices in inventory
- Topology data discovered (CDP/LLDP links)

Optional but recommended:

- Billing circuits linked to interfaces for circuit enrichment in topology and `circuit_map`

## UI: Generate On-Demand

1. Open `Reports & Export`.
2. In the `Generate` tab, set `Report Type` to `Network Documentation (Inventory + Topology + IP/VLAN)`.
3. (Optional) choose a Group filter.
4. Click `Generate`.
5. Use export buttons from the result panel:
   - `Export CSV`
   - `Export SVG Diagram`
   - `Export draw.io`
   - `Export PDF`

## UI: Quick Export

In `Reports & Export` -> `Quick Export`, use:

- `Network Documentation (CSV)`
- `Network Topology Diagram (SVG)`
- `Network Topology Diagram (draw.io)`
- `Network Documentation (PDF)`

## UI: Artifact History

Every completed generated run can store artifacts.

1. Go to `Reports & Export` -> `Report History`.
2. Find a completed run.
3. Click `Artifacts`.
4. Download any persisted file for that run.

## API: On-Demand Generation

Generate a run with persisted artifacts:

```http
POST /api/reports/generate
Content-Type: application/json

{
  "report_type": "network_documentation",
  "parameters": {
    "group_id": 1
  },
  "persist_artifacts": true
}
```

Response includes `run_id`, `row_count`, and artifact metadata when persisted.

## API: Direct Exports

Use these endpoints directly (optionally add `?group_id=<id>`):

- `GET /api/reports/export/network_documentation` (CSV)
- `GET /api/reports/export/network_documentation.svg`
- `GET /api/reports/export/network_documentation.drawio`
- `GET /api/reports/export/network_documentation.pdf`

## API: Scheduling

Create a scheduled network documentation definition:

```http
POST /api/reports
Content-Type: application/json

{
  "name": "Daily Network Documentation",
  "report_type": "network_documentation",
  "parameters_json": "{\"group_id\":1}",
  "schedule": "daily"
}
```

Supported schedule styles include:

- Named: `hourly`, `daily`, `weekly`, `monthly`
- Interval tokens: `15m`, `1h`, `2d`, `1w`
- Also accepted: `every 15m`, `every 1h`

Disable schedule with: `off`, `none`, `disabled`, or `manual`.

## API: Run + Artifact Retrieval

- List runs: `GET /api/reports/runs`
- Run details: `GET /api/reports/runs/{run_id}`
- List artifacts: `GET /api/reports/runs/{run_id}/artifacts`
- Download artifact: `GET /api/reports/artifacts/{artifact_id}`
- Download run CSV shortcut: `GET /api/reports/runs/{run_id}/csv`

## Notes on Export Formats

- `CSV`: best for data processing and audits.
- `SVG`: static diagram for docs/wiki embedding.
- `draw.io`: editable topology diagram for operations/design docs.
- `PDF`: printable bundle of documentation sections.

## Troubleshooting

- Empty topology diagram:
  - verify topology discovery has run and links exist.
- Missing circuits in docs:
  - verify billing circuits are mapped to host/interface.
- No scheduled runs:
  - confirm scheduler is enabled and schedule string is valid.
  - check app logs for scheduler warnings/errors.

