# Data Handling and Retention

This document describes where conversion data is stored and how long it is retained.

## Data Stored

- Uploaded FortiGate config input files.
- Converted FTD JSON artifacts.
- Conversion summaries, logs, and diff output.
- Session backup snapshots under each conversion session directory.

## Storage Locations

- Conversion session data: `netcontrol/converter_sessions/<session_id>/`
- Session backups: `netcontrol/converter_sessions/<session_id>/backups/`
- Application database (inventory, templates, metadata): `routes/netcontrol.db`
- Local encryption/session key files: `routes/session.key`, `routes/netcontrol.key`

## Retention Policy (Suggested Default)

- Keep conversion sessions for 30 days.
- Keep backup snapshots for 30 days unless legal/audit requires longer.
- Remove failed/incomplete sessions after troubleshooting is complete.

## Operational Guidance

- Restrict filesystem access to hosts running Plexus.
- Do not place plaintext device credentials in conversion files.
- Periodically prune stale session directories and old backups.
