# Potential Bugs - Python Backend

Review of `netcontrol/` and `routes/`. Companion to `potentialbugs.md` (frontend).
Severity: **high** = correctness/data-integrity/availability · **medium** = real bug, narrower blast radius · **low** = latent / edge-case.

Entries marked **[verified]** were confirmed by reading the code; others are static-review hypotheses — verify before fixing.

---

## Verified high-severity — ALL FIXED (2026-06-09)

- **[high][verified] netcontrol/routes/deployments.py:266-285, 285-340** — In `_run_post_deployment_verification`, `drift_cp_id` / `mh_cp_id` are assigned as the *first statement inside* `try`. If `create_deployment_checkpoint` itself raises: on the first host the `except` handler hits `NameError`; on later hosts the variable still holds the **previous host's checkpoint id**, so the failure is written to the wrong host's checkpoint. Fix: initialize both to `None` before each `try`, and guard `if drift_cp_id is not None:` in the handlers.
- **[high][verified] netcontrol/routes/config_backups.py:462-475** — `_push_config()` in `restore_config_from_backup` calls `ConnectHandler` → `send_config_set` → `disconnect()` linearly; any exception during the push leaves the SSH session open and the device potentially in config mode. Fix: `try/finally net_connect.disconnect()` (and consider `exit_config_mode()` in the cleanup).
- **[high][verified] netcontrol/routes/cloud_flow_pullers.py:104, cloud_metric_pullers.py:92** — `_build_boto3_session(auth)` (which performs a blocking `sts.assume_role` network call) is invoked directly inside async pull functions, blocking the event loop for up to botocore's 60s default timeout per account. The rest of these modules correctly use `asyncio.to_thread`. Fix: wrap session build in `asyncio.to_thread` and pass `botocore.config.Config(connect_timeout=…, read_timeout=…)`.
- **[high][verified] netcontrol/routes/lab_runtime.py:266-300** — Deploy path sets `runtime_status="provisioning"` then calls `_run_containerlab`. The `rc != 0` branch records the error, but an *exception* from `_run_containerlab` (e.g. binary missing, timeout) propagates without updating status — device stuck in "provisioning" forever, and the created workdir/topology file is orphaned. Fix: wrap deploy in `try/except` that sets `runtime_status="error"` + cleans the workdir before re-raising.
- **[high][verified] netcontrol/routes/audit.py:830-850** — `_claim_queued_run` is not atomic: it SELECTs the oldest queued id, UPDATEs with `AND status='queued'`, but never checks the UPDATE's rowcount. Two concurrent claimers can both return the same `run_id` (one's UPDATE matches 0 rows but it still proceeds). Single audit loop today makes this latent, not active. Fix: check `cursor.rowcount == 1` before returning, retry otherwise — or use `UPDATE … RETURNING id`.

## Verified medium

- **[medium][verified] routes/database.py:12022, 12229, 12258, 13179** — Four upsert helpers end with `row[0] if isinstance(row, tuple) else dict(row)["id"]` after a re-SELECT. `aiosqlite` rows are `sqlite3.Row` (not tuple), so the `dict(row)` branch always runs; if the row was deleted between `commit()` and the SELECT, `dict(None)` raises `TypeError`. Fix: use `INSERT … ON CONFLICT … RETURNING id` (single statement, atomic) or guard `if row is None`.
- **[medium][verified] netcontrol/routes/federation.py:148-205** — `_fetch_peer_data` correctly checks `status_code == 200`, but non-200 responses and exceptions are logged at DEBUG and the result silently keeps zeros — an unreachable/misconfigured peer is indistinguishable from an empty one in the UI. Fix: record per-section error strings in `result` and log at WARNING.
- **[medium][verified] netcontrol/routes/jobs.py:700-704** — Final `job_complete` WebSocket notify swallows all exceptions with bare `pass` and has no send timeout (other broadcasts use one); a wedged socket can stall job teardown. Fix: `asyncio.wait_for(ws.send_json(...), timeout=5)` + debug log on failure.
- **[medium][verified] netcontrol/routes/maintenance_windows.py:101** — `if not window.get("enabled", 1)` treats a NULL `enabled` column as disabled (the default only applies when the key is *missing*, not when it's `None`). Fix: `if not (window.get("enabled") if window.get("enabled") is not None else 1):` or normalize at the DB layer.

## Reported (plausible, not yet re-verified)

### Database layer (routes/database.py, routes/migrations/)
- **[medium] database.py:3445, 3518, 3565** — `except Exception: pass` around IP-assignment audit logging in `add_host`/`update_host`/bulk delete; audit-trail failures vanish. Fix: log at WARNING before continuing.
- **[medium] database.py:2963, 3038, 4387, 4409-4421** — `(await cur.fetchone())[0]` without None guards (COUNT(*) usually safe, but pattern is fragile and copy-pasted). Fix: shared `scalar(cursor, default=0)` helper.
- **[medium] routes/migrations/runner.py:235-241** — Migration failure re-raises after logging without explicit `rollback()`; partial DDL may persist (SQLite DDL is non-transactional in places, but DML steps should roll back). Fix: rollback before re-raise.

### Monitoring / telemetry
- **[medium] netcontrol/routes/metrics_engine.py:336** — Fire-and-forget `asyncio.create_task(_create_correlated_error_event(...))` with no reference or done-callback; exceptions are lost and the task can be GC'd. Fix: keep a task set + `add_done_callback` that logs.
- **[medium] netcontrol/routes/mac_tracking.py:537, 586, 620** — `except Exception: pass` inside MAC/ARP upsert loops; a dead DB connection silently drops the whole collection. Fix: count failures and surface in poll status.
- **[medium] netcontrol/routes/monitoring.py:198** — Per-host poll has an overall timeout but individual SNMP walks have none; one stuck agent eats the whole budget. Fix: per-walk timeout.
- **[medium] netcontrol/routes/flow_collector.py:591** — Up to 99 buffered flow records can be dropped on collector stop if the transport closes before a final flush. Fix: flush buffer in `stop_flow_collector` before closing.

### Config / jobs / upgrades
- **[medium] netcontrol/routes/config_drift.py:300, 836-856** — `_revert_jobs[job_id]` / `_capture_jobs[job_id]` accessed without `.get()` or lock in WebSocket paths; deferred cleanup can race a subscriber → KeyError. Fix: `.get()` + hold the lock while reading.
- **[medium] netcontrol/routes/upgrades.py:617** — Revert-job failures logged at DEBUG only; operator never sees them. Fix: log at ERROR and persist to job status.
- **[low] netcontrol/routes/upgrades.py:646-702** — Image-upload uniqueness check races a concurrent upload; second insert dies on UNIQUE constraint as a 500. Fix: catch IntegrityError → 409.

### Cloud / integrations / secrets
- **[medium] netcontrol/routes/cloud_collectors.py:457-495** — Per-region failures are logged and skipped; the result reports partial data with no indication regions were missed. Fix: include `errors: {region: msg}` in the result.
- **[medium] netcontrol/routes/notification_channels.py:496, siem_forwarder.py:527-532** — Webhook/SIEM error paths log `resp.text` (truncated) — may echo auth headers/secrets back into logs depending on receiver. Fix: sanitize/redact before logging.
- **[medium] netcontrol/integrations/cisco_fdm/collector.py:147-151** — `_process_poll_result` exception is logged but `errors` counter not incremented; poll metrics over-report success. Fix: `errors += 1` in the handler.
- **[low] routes/secret_resolver.py:83** — One DB query per secret reference; N+1 on template renders with many secrets. Fix: bulk fetch.

### IPAM / misc routes
- **[medium] netcontrol/routes/risk_analysis.py:278** — `json.loads(rules_json)` on stored profile data without try/except; one corrupt row breaks the endpoint. Fix: catch `JSONDecodeError` → skip + warn.
- **[medium] netcontrol/routes/graph_export.py:294** — `cutoff_sql = f"-{hours} hours"` relies on `_parse_range_hours` being strict; add explicit bounds check (1..8760) at the use site.
- **[low] netcontrol/routes/cdef_engine.py:119** — Numeric-string check via `.isdigit()` gymnastics; `float()`+`math.isfinite()` in try/except is both simpler and rejects `inf`/`nan`.
- **[low] netcontrol/routes/admin_updates.py:322** — Update-check cache keyed only on config; failed results cached with no TTL enforcement. Fix: store `(result, ts)` and expire.

---

## Cross-cutting error-handling improvements

1. **Silent `except Exception: pass`** — ~70 sites across the backend. Policy: never bare-pass; minimum `LOGGER.debug(..., exc_info=True)`, WARNING when data is dropped (audit events, flow records, MAC/ARP rows).
2. **Background state machines must terminalize** — every path that sets `running`/`provisioning` needs an `except`/`finally` that records `error` + message (lab_runtime deploy, deployment verification, capture/revert jobs). "Stuck running" is the recurring failure class.
3. **Fire-and-forget tasks** — add one shared helper (e.g. `shared.spawn(coro, name)`) that retains the task and logs exceptions via done-callback; replace raw `asyncio.create_task` for background work.
4. **Blocking calls in async paths** — boto3/netmiko/smtplib must go through `asyncio.to_thread` with explicit timeouts; audit for direct calls (cloud pullers' session build is the confirmed offender).
5. **Device session hygiene** — netmiko connections always in `try/finally disconnect()`; consider a small context-manager wrapper in `drivers/base.py`.
6. **DB scalar fetches** — shared `scalar()`/`fetch_id()` helpers to kill the `fetchone()[0]` / `dict(row)["id"]` crash class; prefer `RETURNING id` over commit-then-reselect in upserts.
7. **Error visibility over error suppression** — failures that today go to DEBUG logs (federation peer fetch, upgrade reverts) should land in status fields the UI already renders.

## False positives ruled out during review

- `federation.py:299` UPDATE set-clause: column names are hardcoded literals, values parameterized — not SQL injection.
- `shared.py:_audit`: failures are logged at WARNING, not swallowed.
- `flow_collector.py` NetFlow v5 record parsing: bounds-checked (`offset + 48 > len(data)`).
- `monitoring.py:296` "falsy ifIndex 0": `idx` is a string; `"0"` is truthy.
- `dashboards.py:301` uncaught `request.json()`: file is 234 lines; claim referenced a nonexistent line.
- Flow-collector "template dict races": `datagram_received` is a sync callback on a single event loop — packets are serialized, no concurrent mutation.
