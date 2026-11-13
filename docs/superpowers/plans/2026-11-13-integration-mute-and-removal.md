# Integration Mute and Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator mute an integration entity or a whole site so it stops showing as a problem and stops notifying, and delete entities from availability tracking once the vendor no longer reports them.

**Architecture:** A new `topology_mutes` table is matched against `topology_entity_state` rows by one pure index class; every reader (Dashboard summary, availability summary, tracker alerts, Meraki alert ingest) asks that index. Removal is decided in `apply_topology_entity_states` from a per-entity-type "clean" set computed from the snapshot, plus a Meraki-only confirmation call made by the alert poll.

**Tech Stack:** Python 3.14, FastAPI, asyncpg behind the `routes.database` facade, pytest; React + TypeScript, TanStack Query, vitest.

**Spec:** `docs/superpowers/specs/2026-11-13-integration-mute-and-removal-design.md`

## Global Constraints

- Never run `git commit` or `git push`. Each task ends by staging its files with `git add <named files>`; the user commits.
- Never run `ruff format` or `ruff check --fix` on a directory; only on files this plan names. The tree holds unrelated uncommitted work (custom fields, migration 0083). Do not touch it.
- No real environment data anywhere: invented names, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.com`, serials like `Q2XX-AAAA-0001`.
- Reuse before writing: `resolve_monitoring_alerts`, `_filters`, `_key`, `_state_row`, `dedup_key` (both modules), `Modal`, `ModalActions`, `Badge`, `BusyButton`, `useDialogs`. No second copy of any of them.
- Mute and removal are provider-neutral (meraki, cato, fmc, panorama, appgate, aws, azure, gcp). Only Task 6 is Meraki-specific.
- Migration number: `0084` (0083 is taken by uncommitted work).
- Mute reason: required, stripped, 1 to 500 characters.
- Mute API gate: the monitoring router (same as `POST /api/monitoring/alerts/{id}/acknowledge`), no admin dependency.
- Timestamps: UTC `YYYY-MM-DD HH:MM:SS` text.
- Python verification, CI style (`.github/workflows/ci.yml`, job `build-test`), console scripts from `.venv/Scripts/`:
  `ruff check .`, `mypy netcontrol templates` (baseline: 7 pre-existing errors in `cloud_*.py` locally), `bandit -q -c bandit.yaml -r netcontrol routes templates -ll -ii`, and `pytest <named test files> -p no:cacheprovider -rfE` with `PLEXUS_TEST_PG_URL` set to a database name unique to the worker (`plexus_mute_test` for the backend worker, `plexus_review_test` for the reviewer) and `APP_SECRET_KEY=test-secret`.
- Frontend verification (job `frontend`, in `netcontrol/static/frontend`): `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`.

## Review Focus

1. A collection that failed an inventory-defining call reports fewer entities: nothing may be deleted (Task 5 test `test_unclean_collection_keeps_missing_entities`).
2. A hub-to-branch tunnel stored under the hub's site while the branch site is muted: it must be muted (Task 1 test `test_site_mute_covers_edge_with_far_end_at_site`).
3. The Meraki confirmation call errors or times out after an alert vanished: nothing removed, poll still succeeds (Task 6 test `test_confirmation_failure_removes_nothing`).
4. A device comes back online (alert vanishes, device still exists): it must not be removed (Task 6 test `test_recovered_device_is_kept`).
5. Muting when a mute for the same target already exists: one row, reason updated, no error (Task 1 test `test_duplicate_mute_updates_reason`).

## File Structure

| File | Responsibility |
|---|---|
| `routes/migrations/0084_add_topology_mutes.py` (new) | the table |
| `routes/db/topology_availability.py` | mute CRUD, `TopologyMuteIndex`, removal in `apply_topology_entity_states`, `remove_topology_entities`, muted fields in the summary |
| `netcontrol/integrations/availability.py` | `clean_entity_types` (pure) |
| `netcontrol/routes/topology_availability.py` | tracker honours mutes, Dashboard summary, `mute_entities` / `finish_removal` |
| `netcontrol/routes/monitoring.py` | the three mute endpoints |
| `netcontrol/routes/meraki_alerts.py`, `routes/db/meraki_alerts.py` | ingest honours mutes, `muted` on listed rows, fast-path removal |
| `netcontrol/static/frontend/src/api/monitoring.ts`, `api/dashboard.ts`, `api/merakiAlerts.ts` | types and hooks |
| `netcontrol/static/frontend/src/components/MuteEntityModal.tsx` (new) | the one mute dialog |
| `pages/Dashboard/AlertsSection.tsx`, `pages/Dashboard/sourceHealth.ts`, `pages/Monitoring/TopologyAvailabilityPanel.tsx`, `pages/Monitoring/MerakiAlertsPanel.tsx` | UI |
| docs listed in Task 8 | documentation |

Execution split: Tasks 1 to 6 are one backend worker, in order (they share two files). Task 7 is a second worker and can run in parallel from the start; the API shapes it needs are fixed below. Task 8 is done by the reviewer after both.

---

### Task 1: Mute storage and matching

**Files:**
- Create: `routes/migrations/0084_add_topology_mutes.py`, `tests/test_topology_mutes.py`
- Modify: `routes/db/topology_availability.py` (add to `__all__`; `routes/database.py` already star-imports the module)

**Interfaces (produces):**

```python
MUTE_SCOPES = ("entity", "site")

async def create_topology_mute(provider: str, org_ref: int, scope: str, *, entity_type: str = "",
                               entity_id: str = "", site: str = "", reason: str, created_by: str) -> dict
# Upsert on the unique key; an existing row keeps its id and created_at, takes the new reason and created_by.
# Returns the row: id, provider, org_ref, scope, entity_type, entity_id, site, reason, created_by, created_at.
async def list_topology_mutes(provider: str | None = None, org_ref: int | None = None) -> list[dict]
async def get_topology_mute(mute_id: int) -> dict | None
async def delete_topology_mute(mute_id: int) -> bool

class TopologyMuteIndex:
    def __init__(self, mutes: list[dict], states: list[dict]) -> None
    # states: topology_entity_state rows (need provider, org_ref, entity_type, entity_id, site)
    def __bool__(self) -> bool            # False when there are no mutes
    def match(self, entity: dict) -> dict | None
    # entity: provider, org_ref, entity_type, entity_id, site, and meta (dict) or meta_json (str)
    def match_site(self, provider: str, org_ref: int, site: str) -> dict | None

async def load_topology_mute_index(provider: str | None = None, org_ref: int | None = None) -> TopologyMuteIndex
# One query for mutes; when there are none, no second query and an empty index.
```

Table `topology_mutes`: `id SERIAL PRIMARY KEY`, `provider TEXT NOT NULL`, `org_ref INTEGER NOT NULL DEFAULT 0`, `scope TEXT NOT NULL`, `entity_type TEXT NOT NULL DEFAULT ''`, `entity_id TEXT NOT NULL DEFAULT ''`, `site TEXT NOT NULL DEFAULT ''`, `reason TEXT NOT NULL DEFAULT ''`, `created_by TEXT NOT NULL DEFAULT ''`, `created_at TEXT NOT NULL DEFAULT ''`, `UNIQUE (provider, org_ref, scope, entity_type, entity_id, site)`. Follow `0075_add_topology_availability_tables.py` (`VERSION = 84`, `DESCRIPTION`, `async def up(db)`).

`match` rule, first hit wins, in this order:
1. `entity` mute with the same (provider, org_ref, entity_type, entity_id);
2. entity is an `uplink`, `tunnel` or `link`, and an `entity` mute of type `device` has `entity_id` equal to `meta["a"]` or `meta["b"]`;
3. `site` mute with the same (provider, org_ref) and `site == entity["site"]`, site not empty;
4. entity is an `uplink`, `tunnel` or `link`, and the device row whose `entity_id` is `meta["a"]` or `meta["b"]` has a site with a `site` mute.

- [ ] **Step 1: Write failing tests** in `tests/test_topology_mutes.py` (use the `db_module` fixture as `tests/test_dashboard_topology.py` does; seed states with `apply_topology_entity_states("meraki", 7, [...])`):

```python
DEVICE = {"entity_type": "device", "entity_id": "d:Q2XX-AAAA-0001", "name": "Branch-12 MX", "state": "down", "site": "Branch-12"}
UPLINK = {"entity_type": "uplink", "entity_id": "uplink:w1>d:Q2XX-AAAA-0001:wan1", "name": "Branch-12 MX wan1",
          "state": "down", "site": "Branch-12", "meta": {"kind": "uplink", "a": "w1", "b": "d:Q2XX-AAAA-0001"}}
HUB = {"entity_type": "device", "entity_id": "d:Q2XX-AAAA-0002", "name": "Hub MX", "state": "up", "site": "Hub"}
TUNNEL = {"entity_type": "tunnel", "entity_id": "vpn:d:Q2XX-AAAA-0002>d:Q2XX-AAAA-0001", "name": "Hub MX - Branch-12 MX",
          "state": "down", "site": "Hub", "meta": {"kind": "vpn", "a": "d:Q2XX-AAAA-0002", "b": "d:Q2XX-AAAA-0001"}}

async def test_entity_mute_matches_only_that_entity          # mute DEVICE: match(DEVICE) is the mute, match(HUB) is None
async def test_device_mute_covers_its_uplinks_and_tunnels    # mute DEVICE: match(UPLINK) and match(TUNNEL) are the mute
async def test_site_mute_covers_every_entity_at_site         # site "Branch-12": DEVICE, UPLINK match; HUB does not
async def test_site_mute_covers_edge_with_far_end_at_site    # site "Branch-12": match(TUNNEL) is the mute (TUNNEL.site is "Hub")
async def test_mute_is_scoped_to_its_source                  # same entity_id under org_ref 8 or provider "cato": None
async def test_duplicate_mute_updates_reason                 # second create: same id, reason "second", one row listed
async def test_delete_mute                                   # True then False; get returns None
async def test_empty_index_is_falsy_and_matches_nothing
```

- [ ] **Step 2:** Run `pytest tests/test_topology_mutes.py -p no:cacheprovider -rfE`. Expected: fails on import of `create_topology_mute`.
- [ ] **Step 3:** Write the migration, the four CRUD functions, `TopologyMuteIndex` and `load_topology_mute_index`.
- [ ] **Step 4:** Run the same command. Expected: 8 passed.
- [ ] **Step 5:** `git add routes/migrations/0084_add_topology_mutes.py routes/db/topology_availability.py tests/test_topology_mutes.py`

### Task 2: Readers and the tracker honour mutes

**Files:**
- Modify: `netcontrol/routes/topology_availability.py`, `routes/db/topology_availability.py`
- Test: `tests/test_dashboard_topology.py`, `tests/test_topology_availability.py`

**Interfaces:** consumes Task 1. Produces these response changes (Task 7 relies on them):

- `dashboard_topology_summary()`: `entity_counts`, every `by_provider` value and every `by_source` row gain `"muted": int`. A muted entity in `down` or `degraded` is counted under `muted` and not under its state; a muted entity in `up` or `unknown` is counted under its state as before. `total` is unchanged. `problem_count` and `problems` leave muted entities out. With no mutes the function makes the same two queries as today.
- `get_topology_availability_summary()`: each entity gains `"muted": bool` and `"mute": {"id", "scope", "reason", "created_by", "created_at"} | None`. Top level gains `"muted": int` (every muted entity). `up` / `degraded` / `down` / `unknown`, `avg_uptime_pct` and `total_outages` leave muted entities out. `entity_count` still counts all.
- `record_snapshot_states`: does not call `_raise_alert` for a transition whose entity the index matches. `alert_state` is already stored by `apply_topology_entity_states`, so the alert counts as raised. Result gains `"muted_alerts": int`.

- [ ] **Step 1: Write failing tests.**

`tests/test_dashboard_topology.py`:
```python
async def test_muted_problem_leaves_dashboard_counts_and_list
# 2 down devices at one source, one muted: entity_counts down == 1, muted == 1, total unchanged,
# problem_count == 1, the muted one not in problems, by_source row down == 1 and muted == 1
async def test_muted_up_entity_is_still_counted_up
async def test_site_mute_hides_every_problem_of_the_site
```
`tests/test_topology_availability.py`:
```python
async def test_muted_entity_raises_no_alert_but_records_transition
# baseline up, mute, then down: result["alerted"] == 0, result["muted_alerts"] == 1,
# transition stored, state row alert_state == "down"
async def test_unmute_does_not_alert_while_state_unchanged
# after the above: delete the mute, record the same down snapshot: alerted == 0
async def test_summary_marks_muted_and_excludes_it_from_totals
# entity["muted"] is True, entity["mute"]["reason"] == "not installed", summary["down"] == 0, summary["muted"] == 1
```
- [ ] **Step 2:** Run both files. Expected: the six new tests fail.
- [ ] **Step 3:** Implement. In the Dashboard summary, when the index is truthy, load every `down` / `degraded` row (no limit), move the muted ones between counters, then cut `problems` to `limit`.
- [ ] **Step 4:** Run both files. Expected: all pass, including the existing tests.
- [ ] **Step 5:** `git add` the four files.

### Task 3: Mute API

**Files:**
- Modify: `netcontrol/routes/monitoring.py` (next to the `/api/availability/topology/*` routes), `netcontrol/routes/topology_availability.py`, `AUTHORIZATION_MATRIX.md`
- Create: `tests/test_topology_mutes_api.py` (client and auth fixtures as in `tests/test_monitoring_api.py`)

**Interfaces (produces):**

```
GET    /api/availability/topology/mutes           -> {"mutes": [row, ...]}
POST   /api/availability/topology/mutes  (201)    -> {"mute": row, "acknowledged": int}
DELETE /api/availability/topology/mutes/{mute_id} -> {"ok": true}      404 when absent
```
POST body `TopologyMuteCreate`: `provider` (pattern `_TOPOLOGY_PROVIDER_RE`), `org_ref: int`, `scope: Literal["entity", "site"]`, `entity_type: str = ""` (pattern `_TOPOLOGY_ENTITY_RE` when set), `entity_id: str = ""` (max 500), `site: str = ""` (max 200), `reason: str`.

Rules: reason stripped, 1 to 500 characters, else 400. `entity` scope needs `entity_type` and `entity_id` and a matching state row, else 404. `site` scope needs a non-empty `site` that at least one state row of that source has, else 404. Audit `_audit("monitoring", "topology.muted" | "topology.unmuted", user=..., detail=f"{provider}:{org_ref} {scope} {entity_type}:{entity_id or site}")`; the reason is not put in the audit detail.

In `netcontrol/routes/topology_availability.py`:
```python
async def mute_entities(mute: dict) -> int
# Acknowledge as "muted" the open monitoring alerts of every state row of the mute's source that the
# index now matches: db.resolve_monitoring_alerts(dedup_key(row), "muted"). For provider "meraki", also
# the open meraki_alerts rows whose device (d:<serial>) or network_name the index matches:
# resolve_monitoring_alerts(meraki_alerts.dedup_key(alert_key), "muted") and
# db.set_meraki_alert_raised(alert_key, severity, "muted", None). Import meraki_alerts.dedup_key inside
# the function (module-level import would be circular). Returns the number acknowledged.
```

- [ ] **Step 1: Write failing tests:**
```python
async def test_create_list_delete_mute                    # 201, listed, 200 delete, then 404
async def test_reason_required_and_bounded                # "", "   ", 501 chars -> 400
async def test_unknown_entity_or_site_is_404
async def test_mute_acknowledges_open_host_alert          # entity with host_id and an open topo: alert -> acknowledged_by "muted", "acknowledged": 1
async def test_mute_requires_monitoring_feature           # a user without the feature gets 403 (as the acknowledge route does)
async def test_mute_and_unmute_are_audited
```
- [ ] **Step 2:** Run `pytest tests/test_topology_mutes_api.py -p no:cacheprovider -rfE`. Expected: 404s on the routes.
- [ ] **Step 3:** Implement the routes and `mute_entities`; add the three routes to `AUTHORIZATION_MATRIX.md` in the monitoring section.
- [ ] **Step 4:** Run the file. Expected: 6 passed.
- [ ] **Step 5:** `git add` the four files.

### Task 4: Meraki alerts honour mutes

**Files:**
- Modify: `netcontrol/routes/meraki_alerts.py`
- Test: `tests/test_meraki_alerts.py`

**Interfaces:** consumes Task 1. Produces: `GET /api/monitoring/meraki-alerts` rows gain `"muted": bool`; `alert_via` can be `"muted"`.

A Meraki alert row is muted when `index.match({"provider": "meraki", "org_ref": row["org_ref"], "entity_type": "device", "entity_id": f"d:{serial}", "site": row["network_name"], "meta": {}})` hits (serial present), or `index.match_site("meraki", org_ref, network_name)` hits. One private helper `_muted(row, index)` serves `ingest` and the list route.

In `ingest`: load the index once per call, only when `result["alerts"]` is not empty. A muted row is not raised; `set_meraki_alert_raised(key, severity, "muted", None)` is called instead and it is not counted in `alerted`.

- [ ] **Step 1: Write failing tests:**
```python
async def test_muted_device_alert_is_stored_not_raised    # no monitoring alert, no channel event, row alert_via == "muted", alert_state == severity
async def test_muted_network_alert_is_not_raised          # site mute "Branch-12", alert with network_name "Branch-12" and no serial
async def test_listed_alerts_carry_muted_flag
async def test_unmuted_open_alert_does_not_notify_until_worse   # delete mute, poll again same severity: alerted == 0
```
- [ ] **Step 2:** Run `pytest tests/test_meraki_alerts.py -p no:cacheprovider -rfE`. Expected: the four fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the file. Expected: all pass.
- [ ] **Step 5:** `git add netcontrol/routes/meraki_alerts.py tests/test_meraki_alerts.py`

### Task 5: Removal at a clean collection

**Files:**
- Modify: `netcontrol/integrations/availability.py`, `routes/db/topology_availability.py`, `netcontrol/routes/topology_availability.py`
- Test: `tests/test_topology_availability.py`

**Interfaces (produces):**

```python
# netcontrol/integrations/availability.py (pure)
def clean_entity_types(provider: str, snapshot: dict | None) -> frozenset[str]
```
Rule: errors are `snapshot["collection"]["errors"]`.
- No snapshot, or any site in `snapshot["sites"]` with `not_collected`: empty set.
- `meraki`: a stored snapshot always has the full network and device lists (the collector raises otherwise), so `device` is always clean. `uplink`, `tunnel` and `link` are clean only when no error has `scope == "org"`. Read `collect_organization` in `netcontrol/integrations/meraki/collector.py` first and confirm which scopes feed uplink and VPN edges; if a non-`org` scope feeds them, include it.
- Every other provider: all of `ENTITY_TYPES` when there are no errors, else the empty set.

```python
# routes/db/topology_availability.py
async def apply_topology_entity_states(provider, org_ref, entities, *, org_name="", snapshot_ref="", now=None,
                                       clean_types: Collection[str] = ()) -> dict
# A stored entity absent from `entities` whose entity_type is in clean_types is deleted (no transition
# written) together with its entity-scope mute. Others keep today's unknown / missing handling.
# Result gains "removed": list[dict] (the state rows as they were).
async def remove_topology_entities(provider: str, org_ref: int, device_ids: Collection[str]) -> list[dict]
# Deletes those device rows, the uplink / tunnel / link rows whose meta a or b is one of them, and
# their entity-scope mutes. Returns the deleted rows.
async def delete_topology_site_mutes_except(provider: str, org_ref: int, site_names: Collection[str]) -> int
# Deletes the site-scope mutes of that source whose site is not in site_names.

# netcontrol/routes/topology_availability.py
async def finish_removal(rows: list[dict]) -> int
# For each removed row with alert_state: db.resolve_monitoring_alerts(dedup_key(row), "auto-resolved").
# Sends no notification. Returns the number of rows.
```
`record_snapshot_states` passes `clean_types=clean_entity_types(provider, snapshot)`, calls `finish_removal(result["removed"])`, and, when `"device"` is clean, calls `delete_topology_site_mutes_except` with the names of `snapshot["sites"]` (name, else id, as `extract_entity_states` resolves them). Result gains `"removed": int`.

- [ ] **Step 1: Write failing tests:**
```python
def test_clean_types_meraki_devices_always_edges_need_org_calls
def test_clean_types_other_providers_all_or_nothing
def test_clean_types_empty_when_a_site_is_not_collected
async def test_clean_collection_removes_absent_entity_and_its_mute
# state row gone, entity mute gone, transitions of the entity still listed, result["removed"] == 1
async def test_unclean_collection_keeps_missing_entities
# same snapshot with collection.errors (non-Meraki provider): row is unknown + missing, as today
async def test_removed_entity_with_open_alert_is_auto_resolved   # monitoring alert acknowledged_by "auto-resolved"
async def test_site_mute_survives_empty_site_and_goes_with_the_site
# site still in snapshot["sites"] with no devices: mute kept; site absent from snapshot["sites"]: mute deleted
async def test_reappearing_entity_is_a_new_baseline              # removed then reported down again: no alert
```
The existing Appgate "gone, then back" test (around `tests/test_topology_availability.py:277`) asserts `unknown` / `missing` after a clean collection. Split it: keep the assertion for a snapshot with `collection.errors`, and assert removal for the clean one.
- [ ] **Step 2:** Run `pytest tests/test_topology_availability.py -p no:cacheprovider -rfE`. Expected: new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `pytest tests/test_topology_availability.py tests/test_dashboard_topology.py tests/test_meraki_alerts.py tests/test_topology_mutes.py -p no:cacheprovider -rfE`. Expected: all pass.
- [ ] **Step 5:** `git add` the four files.

### Task 6: Meraki fast-path removal

**Files:**
- Modify: `netcontrol/routes/meraki_alerts.py`
- Test: `tests/test_meraki_alerts.py`

**Interfaces:** consumes `remove_topology_entities`, `finish_removal` (Task 5).

- `ingest(...)` result gains `"vanished": list[str]`: the device serials of the rows `resolve_missing_meraki_alerts` just resolved (empty without `poll_scope`).
- New `async def remove_vanished_devices(org: dict, serials: list[str]) -> int`, called by `_poll_one` after a successful `ingest`, outside `_APPLY_LOCK`:
  1. keep the serials that have a tracked entity (`db.list_topology_entity_states("meraki", org_ref, "device")`, id `d:<serial>`); none left means no API call;
  2. one `get_all` on `organizations/{org_id}/devices` filtered to those serials, in chunks of 100, with the same client settings as `poll_source` (extract the shared client construction into one helper used by both);
  3. serials not returned are removed with `db.remove_topology_entities("meraki", org_ref, [f"d:{s}" ...])` then `finish_removal(rows)`;
  4. any exception: log the exception type at warning, return 0, remove nothing.
- `_poll_one` result gains `"removed": int`; `run_alert_poll_cycle` sums it into its result and log line.

Before coding step 2, confirm in the Meraki Dashboard API reference (`getOrganizationDevices`) that the endpoint returns only devices assigned to a network and takes a `serials[]` array filter, and check how `MerakiClient.get_all` encodes a list parameter. If either does not hold, use the endpoint and encoding that do, and say so in the report.

- [ ] **Step 1: Write failing tests** (with `httpx.MockTransport` through `meraki_alerts._TRANSPORT`, as the existing poll tests do):
```python
async def test_vanished_alert_of_removed_device_removes_it
# poll 1 reports an unreachable alert for Q2XX-AAAA-0001 (entity tracked, down); poll 2 reports none and
# the devices call returns []: device entity and its uplink entity gone, result["removed"] == 1
async def test_recovered_device_is_kept                    # devices call returns the serial: entity still there
async def test_confirmation_failure_removes_nothing        # devices call answers 500: entity there, poll result ok is True
async def test_no_confirmation_call_without_tracked_serial # transport records no /devices request
```
- [ ] **Step 2:** Run `pytest tests/test_meraki_alerts.py -p no:cacheprovider -rfE`. Expected: the four fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the backend gates from Global Constraints: the five test files named in this plan, `ruff check .`, `mypy netcontrol templates`, `bandit ...`. Expected: tests pass; ruff and bandit clean; mypy no worse than the baseline.
- [ ] **Step 5:** `git add netcontrol/routes/meraki_alerts.py tests/test_meraki_alerts.py`

### Task 7: Frontend

**Files:**
- Create: `src/components/MuteEntityModal.tsx`, `src/components/MuteEntityModal.test.tsx`
- Modify: `src/api/monitoring.ts`, `src/api/dashboard.ts`, `src/api/merakiAlerts.ts`, `src/pages/Dashboard/sourceHealth.ts` (+ `.test.ts`), `src/pages/Dashboard/AlertsSection.tsx`, `src/pages/Monitoring/TopologyAvailabilityPanel.tsx`, `src/pages/Monitoring/MerakiAlertsPanel.tsx`, and test fixtures that build `TopologyStateCounts` (`criticalIssues.test.ts`, `integrationCards.test.ts`)

(all under `netcontrol/static/frontend/`)

**Interfaces (consumes the API shapes of Tasks 2 to 4; produces):**

```ts
// api/monitoring.ts
export interface TopologyMute { id: number; provider: string; org_ref: number; scope: 'entity' | 'site';
  entity_type: string; entity_id: string; site: string; reason: string; created_by: string; created_at: string }
export interface TopologyMuteTarget { provider: string; org_ref: number; entity_type: string; entity_id: string; name: string; site: string }
// TopologyAvailabilityEntity gains: muted: boolean; mute: Pick<TopologyMute, 'id' | 'scope' | 'reason' | 'created_by' | 'created_at'> | null
// TopologyAvailabilitySummary gains: muted: number
export function useMuteTopologyEntity()    // POST /availability/topology/mutes
export function useUnmuteTopologyEntity()  // DELETE /availability/topology/mutes/{id}
// both invalidate ['topology-availability-summary'], ['dashboard'], ['meraki-alerts']

// api/dashboard.ts: TopologyStateCounts gains muted?: number (absent from older servers)
// api/merakiAlerts.ts: MerakiAlert gains muted?: boolean

// components/MuteEntityModal.tsx
export function MuteEntityModal(props: { target: TopologyMuteTarget; onClose: () => void }): JSX.Element

// pages/Dashboard/sourceHealth.ts
export type AvailabilityStateFilter = 'problem' | 'down' | 'degraded' | 'up' | 'unknown' | 'muted';
export function matchesAvailabilityState(entity: { current_state: string; muted?: boolean }, filter: AvailabilityStateFilter): boolean
// 'muted' -> entity.muted; 'problem' | 'down' | 'degraded' -> not muted and the state matches; 'up' | 'unknown' -> the state matches
```

UI copy (fixed):
- Dialog title "Mute alerts". Radio labels "This device only" (for a non-device entity: "This {type label} only") and "Everything at site {site}"; the site radio is shown only when `target.site` is not empty; default is the first. Field label "Reason", required, max 500. Buttons "Cancel" and "Mute". Help line: "Muted entities are left off the Dashboard and send no notifications until unmuted."
- Row action button "Mute" (`btn btn-sm btn-secondary`) on each "Integrations and cloud" row of `AlertsSection` and each unmuted row of the Availability entities table. Muted rows show a `Badge` "Muted" whose title is `{reason} - {created_by}, {formatted created_at}` and an "Unmute" button (confirm through `useDialogs().confirm`: "Unmute {name}?" and, for a site mute, "This unmutes everything at site {site}.").
- State filter option "Muted" appended to `AVAILABILITY_STATE_FILTERS`. A stat tile "Muted" after "Down", shown when the count is above 0.
- `MerakiAlertsPanel`: `VIA_LABELS.muted = 'Muted'`; a "Show muted" checkbox next to "Show resolved", off by default; rows with `muted` are hidden while it is off.

Follow `FRONTEND_STYLE.md`; build the dialog from `Modal` and `ModalActions` as the existing modals do.

- [ ] **Step 1: Write failing tests.**
`sourceHealth.test.ts`: `'muted' matches only muted entities`; `'problem' leaves a muted down entity out`; `parseAvailabilityState('muted') === 'muted'`.
`MuteEntityModal.test.tsx`: `Mute is disabled until a reason is typed`; `hides the site choice when the target has no site`; `posts scope "site" with the site name when that choice is picked`; `posts scope "entity" with entity_type and entity_id by default`; `shows the server error and stays open when the request fails`.
- [ ] **Step 2:** Run `npm test -- sourceHealth MuteEntityModal`. Expected: fail.
- [ ] **Step 3:** Implement types, hooks, modal, then the three pages.
- [ ] **Step 4:** Run `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`. Expected: all pass.
- [ ] **Step 5:** `git add` the files named above (not the build output unless the repo tracks it; check `git status` first).

### Task 8: Documentation

**Files:** `docs/meraki-alerts.md`, `docs/meraki-topology.md` (availability tracking section), `docs/vendor-monitoring-coverage.md`, `docs/api-reference.md`, `CHANGELOG.md`

- [ ] **Step 1:** `docs/meraki-topology.md`: add "Muting" and "Removed entities" to the availability tracking section: what a mute does and does not do (the spec's "Effects of a mute"), the clean-collection rule, and that a site mute lasts until the network is deleted or it is unmuted.
- [ ] **Step 2:** `docs/meraki-alerts.md`: "Raising alerts" gains the muted case; a new subsection "Devices removed from Meraki" describes the confirmation call and its API cost (one request per organization, only on a poll where an alert of a tracked device vanished); "Limitations" notes that a removed device with no open alert waits for the next collection; "Troubleshooting" gains "A device I muted still shows" (it shows under Availability with a Muted badge by design).
- [ ] **Step 3:** `docs/vendor-monitoring-coverage.md`: a matrix row for mute (all providers) and one for removal (per provider: the clean rule that applies; fast path Meraki only, documented as a gap for the others).
- [ ] **Step 4:** `docs/api-reference.md`: the three mute routes and the new response fields. `CHANGELOG.md`: one entry under the unreleased section, in the file's existing style.
- [ ] **Step 5:** Grep every changed and new file for identifiers seen in the session's live data (none were read in planning; repeat after execution). `git add` the five files.
