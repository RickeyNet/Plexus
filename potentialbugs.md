# Potential Bugs - React Frontend

Review of `netcontrol/static/frontend/src/`. Findings grouped by area.
Severity: **high** = correctness/data-integrity/UX-breaking · **medium** = real bug, narrower blast radius · **low** = latent / edge-case.

Each entry is a hypothesis from static review - verify before fixing.

---

## Core / App / API client / Auth

- **[high] src/App.tsx:127** - `resetSessionExpiryFlag()` is called as a side effect during render (violates React purity, double-fires under StrictMode). Fix: move into a `useEffect` keyed on `auth?.authenticated`.
- **[high] src/api/client.ts:107-112** - `sessionExpiryHandled` latch is only reset by App.tsx's render-time call; a 401 firing while not yet on an authenticated screen can leave the latch permanently stuck. Fix: reset the latch from a `useEffect` whenever `useAuthStatus` reports `authenticated: true` (and on logout).
- **[medium] src/api/client.ts:54-118** - `apiRequest` never receives or forwards `AbortSignal`; React Query callers (`useDashboard`, `useAuthStatus`, dashboard hooks, etc.) don't pass `signal`, so unmount/navigation never aborts in-flight fetches. Fix: thread `signal` through `ApiRequestOptions` and pass `({ signal }) => apiRequest(url, { signal })` in every `queryFn`.
- **[medium] src/api/client.ts:60-67,107-112** - On 401 the module clears `csrfToken`, but mutations queued after the clear can still fire without `X-CSRF-Token`. Fix: short-circuit mutations when `csrfToken` is null after expiry.
- **[medium] src/api/auth.ts:32-44** - `queryFn` doesn't forward `signal` and unconditionally calls `setCsrfToken`; a late `/auth/status` reply from a focus refetch can overwrite a fresher token. Fix: forward `signal` and only mutate module CSRF state when not aborted.
- **[medium] src/api/dashboard.ts:58,102,112,223,253** - None of the dashboard `queryFn`s forward the React Query signal. Fix: forward `signal` to `apiRequest` in each.

## Library / Shared

- **[high] src/lib/appearance.ts:52,57,62-63,68-69** - All `localStorage` access is unguarded; private-mode/sandboxed-iframe `SecurityError` thrown at module load via `initAppearance()` crashes the bundle. Fix: wrap each read/write in `try/catch`.
- **[high] src/lib/usePerformanceMode.ts:9-20** - `localStorage` read in `readInitial()` and write in the effect have no error handling; a storage failure crashes the component. Fix: wrap reads/writes in `try/catch`.
- **[high] src/main.tsx:9** - `initAppearance()` runs at module load; any localStorage exception bubbles before React mounts → blank page. Fix: harden `appearance.ts` and/or guard the call.
- **[high] src/components/Modal.tsx:23-30** - Escape handler is bound to `document`; with multiple Modals open every Escape closes all of them simultaneously. Fix: maintain a modal stack so only the topmost handles Escape.
- **[medium] src/components/ChangePasswordModal.tsx:50-51** - Catch sets `error` to `(err as Error).message`, dropping the API-supplied `body.detail` for `ApiError`. Fix: reuse Login's `errorMessage(err, fallback)` helper.
- **[medium] src/components/EditProfileModal.tsx:31-33** - Same: `body.detail` is discarded. Fix: extract API detail message from `ApiError`.
- **[medium] src/lib/spaceStarfield.ts:84-89** - `resize()` rebuilds the entire star array on every window resize, snapping all stars to fresh random positions. Fix: only rebuild when count truly changes; otherwise rescale `s.x`/`s.y` to the new dimensions.
- **[medium] src/lib/spaceStarfield.ts:200-208** - `MutationObserver` on the host's `style` attribute fires `syncRunning()` on every render-driven style write. Fix: debounce or only call `updatePalette` on `data-theme` changes.
- **[medium] src/lib/echart.tsx:50-112,128-169,184-236,256-294** - All four charts (TimeSeries/Gauge/Heatmap/Bar) dispose and re-init the echarts instance on every prop change because data array deps are fresh references each render - flicker, GPU churn. Fix: split mount-only init/dispose effect from a separate `setOption` effect that runs on data updates.
- **[medium] src/lib/echart.tsx:105-106,163-164,230-231,288-289** - Charts only resize on `window` resize, not container resize (sidebar collapse / grid changes leave canvas stale). Fix: attach a `ResizeObserver` to the wrapper element and call `chart.resize()`.

## Login

- **[high] src/pages/Login/Login.tsx:194-217** - Mode-switch "Register" / "Sign In" affordances are `<a href="#">`, polluting browser history with `#` entries and breaking back-button navigation under `BrowserRouter basename="/frontend"`. Fix: render `<button type="button">` styled as a link.

## Dashboard

- **[high] src/pages/Dashboard/Panel.tsx:53** - `groupNum && Number.isFinite(groupNum) ? groupNum : null` short-circuits when `groupNum === 0`, dropping legitimate group id 0. Fix: `groupNum != null && Number.isFinite(groupNum)`.
- **[high] src/pages/Dashboard/Panel.tsx:213-215** - `new Date(d.sampled_at ?? d.period_start ?? '').toLocaleString()` parses naive SQL timestamps as local time (timezone bug) and yields "Invalid Date" for empty strings. Fix: append `Z` if string lacks a timezone (mirror `helpers.timeAgo`) and guard empty case.
- **[high] src/pages/Dashboard/Panel.tsx:182** - Heatmap x-labels call `new Date(t).toLocaleTimeString()` without `Z` normalization. Fix: append `Z` if missing.
- **[high] src/pages/Dashboard/DashboardViewer.tsx:29** - `id ? Number(id) : null` returns `NaN` for non-numeric route params; `enabled: id != null` then evaluates truthy for NaN and the query fetches `/dashboards/NaN`. Fix: `Number.isFinite(Number(id)) ? Number(id) : null`.
- **[medium] src/pages/Dashboard/helpers.ts:67** - `${isoStr}Z` is appended whenever `Z` is missing, but a string ending in `+00:00` becomes `+00:00Z` (invalid). Fix: also skip when `/[+-]\d{2}:?\d{2}$/` matches.
- **[medium] src/pages/Dashboard/HealthSection.tsx:25** - `String(d.group_id) === groupFilter` matches `"undefined"` against devices with `group_id === undefined`. Fix: add `d.group_id != null &&` guard.
- **[medium] src/pages/Dashboard/HealthSection.tsx:198** - Row key includes loop index `i`; sort changes re-key every row and remount the entire `<tbody>` (loses focus, kills transitions). Fix: drop `i`, use stable id (e.g. `host_id`).
- **[medium] src/pages/Dashboard/PanelModal.tsx:159,170** - `parseInt(e.target.value, 10) || 6` snaps the field back to default when cleared, blocking backspace-and-retype. Fix: keep field as string state, coerce on submit.
- **[medium] src/pages/Dashboard/Panel.tsx:121,131,151,217** - `(d.val_avg ?? d.value ?? 0)` substitutes 0 for null samples inside averages and bar sums, biasing aggregates downward. Fix: filter null samples before averaging.
- **[medium] src/pages/Dashboard/DashboardViewer.tsx:34** - `useDeletePanel(dashboardId ?? 0)` hooks against id=0 when invalid, mismatching invalidation keys. Fix: validate `dashboardId` first.
- **[low] src/api/dashboard.ts:113** - `enabled: id != null` allows `id = 0` to fire `/dashboards/0`. Fix: tighten to `Number.isFinite(id) && id > 0`.

## Topology

- **[high] src/pages/Topology/AddToInventoryModal.tsx:26-28** - `setSelectedGroupId(groups[0].id)` called during render → "Cannot update during render" warning + potential re-render loop. Fix: move into `useEffect` keyed on `[isOpen, groups, selectedGroupId]`.
- **[high] src/pages/Topology/NodeDetails.tsx:108** - STP key uses `(edge.source_interface ?? '').toLowerCase()`, but the map is built via `stpPortKey()` which calls `normalizeIfaceName` (e.g. "GigabitEthernet0/1" → "gi0/1"). Lookups silently miss for any normalized interface - STP info never appears in the side panel. Fix: import and use `stpPortKey(...)` here.
- **[high] src/pages/Topology/NodeDetails.tsx:31** - `useState(node.device_category ?? '')` initialized only on mount; clicking a different node doesn't refresh `category`. Fix: key the element by `node.id` or sync via `useEffect([node.id])`.
- **[high] src/pages/Topology/Topology.tsx:613-616** - `applyUtilizationUpdate` mutates the react-query-cached `data.edges[i].utilization` directly. Fix: maintain a local `Map<edgeId, util>` or use `qc.setQueryData`.
- **[high] src/pages/Topology/Topology.tsx:1004-1015** - `target.device_category = newCategory` mutates query-cache data directly inside `onCategoryUpdated`. Fix: invalidate or `qc.setQueryData`.
- **[high] src/pages/Topology/Topology.tsx:721-726** - Path highlight uses `data.edges.find(...)` and picks only one of any parallel edges between two nodes. Fix: `filter` and add all matching edge ids.
- **[high] src/pages/Topology/Topology.tsx:243-246** - `flash()` `setTimeout` has no ref/cleanup; concurrent flashes leave dangling timers and unmount within 4s causes setState-after-unmount. Fix: ref-tracked timer.
- **[high] src/pages/Topology/Topology.tsx:888-892** - Search input `onBlur` setTimeout has no cleanup. Fix: ref-tracked timer cleared on focus/unmount.
- **[high] src/api/topology.ts:382-394** - `openUtilizationStream` reconnect: `setTimeout(open, 10000)` - when the timer fires `open()` doesn't check `stopped`, so a torn-down consumer can spawn a fresh `EventSource`. Fix: `function open() { if (stopped) return; ... }`.
- **[medium] src/pages/Topology/Topology.tsx:519-541** - Auto-fit `setTimeout(() => fit(), 50)` and `network.once('stabilizationIterationsDone', ...)` are not tracked; rapid layout changes can stack handlers / fire on a destroyed-then-recreated network. Fix: track timer in ref, remove pending listeners before destroying.
- **[medium] src/pages/Topology/DiscoveryProgressModal.tsx:118** - Effect deps include `onComplete`, passed as inline arrow on every parent render; `startedRef` guards restart but cleanup still runs (aborts controller during normal parent re-renders). Fix: wrap parent `onComplete` in `useCallback`.
- **[medium] src/pages/Topology/Topology.tsx:953** - `Math.max(1, Math.min(4094, parseInt(e.target.value, 10) || 1))` snaps VLAN field to 1 when empty, blocking edits. Fix: store as string state.
- **[medium] src/pages/Topology/Topology.tsx:259-261** - `String(e.from) < String(e.to)` mixes types; lexicographic compare of mixed numeric/string ids is fragile.
- **[medium] src/pages/Topology/Topology.tsx:209-232** - Settings effect deps `[spacing, repulsion, edgeLen]` but body branches on `layout` (eslint-disabled missing dep) - latent.
- **[medium] src/pages/Topology/ChangesModal.tsx:99-100** & **StpEventsModal.tsx:79** - `new Date((c.detected_at || '') + 'Z').toLocaleString()` blindly appends `Z`, producing invalid date if string already has timezone. Fix: only append when no timezone marker present.
- **[medium] src/api/topology.ts:303-349** - `discoverTopologyStream` reader is never `releaseLock()`-ed on AbortError. Fix: `try { ... } finally { reader.releaseLock(); }`.
- **[low] src/pages/Topology/exporters.ts:46-58** - `Object.values(positions)` for bbox doesn't filter non-finite x/y; NaN positions corrupt export math. Fix: filter `Number.isFinite`.
- **[low] src/pages/Topology/NodeDetails.tsx:104** - `allNodes.find((n) => n.id === peerId)` strict-compare across mixed numeric/string ids. Fix: `String(n.id) === String(peerId)`.

## Device Detail / TopologyCanvas

- **[high] src/pages/DeviceDetail/DevicePicker.tsx:69-92** - Per-row `key={id}` is `host_id`, but `useMonitoringPolls` returns "recent polls" which can have multiple rows per host → duplicate React keys. Fix: dedupe by host_id (most recent) or use composite key `${id}-${p.polled_at}`.
- **[high] src/pages/DeviceDetail/DeviceDetail.tsx:37,57** - `parseInt('abc', 10)` returns `NaN`; queries above the early-return get `enabled: hostId != null` which is true for NaN, firing `host=NaN`. Fix: normalize NaN → null at line 37.
- **[medium] src/pages/DeviceDetail/InterfaceTab.tsx:439-447** - `JSON.parse` is try/wrapped (good), but the non-string branch returns `if_details || []` without `Array.isArray` check. Fix: validate `Array.isArray(raw)`.
- **[medium] src/pages/DeviceDetail/InterfaceTab.tsx:51,74-77** - Sort uses `new Date(d.sampled_at).getTime()` per comparison; missing `sampled_at` → `NaN > NaN === false` leaves stale entries. Fix: parse once, validate finiteness.
- **[low] src/pages/DeviceDetail/InterfaceTab.tsx:69-71** - `Math.max(...grouped[a].map(...))` spreads potentially huge arrays into call args. Fix: use `.reduce`.

## Floor Plan

- **[high] src/pages/FloorPlan/FloorCanvas.tsx:39** - `const [cacheKey] = useState(() => Date.now())` initializes once and never updates, defeating the cache-bust intent. Fix: `useMemo(() => Date.now(), [floor.id, floor.image_filename])`.
- **[medium] src/pages/FloorPlan/FloorCanvas.tsx:127-129** - `if (!hostId || Number.isNaN(hostId)) return;` rejects host_id `0`. Fix: `if (Number.isNaN(hostId) || hostId < 0) return;`.
- **[medium] src/pages/FloorPlan/FloorPlan.tsx:111** - `placementsLoading={floor.data !== null && placements.isPending}` - while floor is fetching, `floor.data === undefined` so `undefined !== null` is true, showing loading prematurely. Fix: `floor.data != null && ...`.

## Lab

- **[high] src/pages/Lab.tsx:553-562** - `CreateDeviceModal` clone-button uses raw `fetch('/api/lab/environments/${envId}/clone-host', { ... })` bypassing `apiRequest` - no CSRF token, no consistent error handling. Fix: use the existing `useCloneHost(envId)` hook.
- **[medium] src/pages/Lab.tsx:298-302, 373-375, 425-433** - `await create.mutateAsync(...); onClose();` patterns: a mutation throw rejects the inline async handler, the modal never closes, and an unhandled rejection bubbles. Fix: wrap in try/catch.

## Configuration / Compliance

- **[high] src/pages/Compliance/Compliance.tsx:194,385,531,623** - Date strings unconditionally appended with `'Z'`. If backend returns `Z` or `+00:00`, result is "Invalid Date". Fix: `iso.endsWith('Z') || /[+-]\d\d:?\d\d$/.test(iso)` guard.
- **[high] src/pages/Compliance/FindingsModal.tsx:37** - `setCredentialId(credList[0].id)` called during render. Fix: move into `useEffect`.
- **[high] src/pages/Compliance/ProfileModals.tsx:95-107** - `EditProfileModal` calls `setName/setDescription/setSeverity/setRulesText/setHydrated` directly inside render body. Fix: move hydration into `useEffect([profile, hydrated])`.
- **[high] src/pages/Compliance/ProfileModals.tsx:184-186** - `AssignProfileModal` sets `credentialId` during render. Fix: `useEffect`.
- **[high] src/pages/Compliance/RunScanModal.tsx:40-41** - `setProfileId/setGroupId` called directly during render to default to first item. Fix: `useEffect`.
- **[medium] src/pages/Configuration/helpers.ts:5,11** - `formatStamp`/`formatRelative` only check `'Z'` or `'+'`; ISO with negative offset (`-05:00`) gets a stray `Z` appended. Fix: regex `/[+-]\d{2}:?\d{2}$/`.
- **[medium] src/pages/Configuration/ConfigJobStreamModal.tsx:62-64,76-91** - Output buffer (`setOutput((prev) => prev + ...)`) unbounded for long jobs; WS handlers also fire after cleanup `ws.close()` if a buffered message is in flight. Fix: cap buffer and detach handlers (`ws.onmessage = null` etc.) before close.
- **[medium] src/pages/Compliance/Compliance.tsx:255** & **FindingsModal.tsx:30** - `JSON.parse(... || '[]')` with no `Array.isArray(parsed)` validation; `'{}'` etc. silently flows into `.filter`/`.map`. Fix: validate parse result.
- **[medium] src/pages/Compliance/FindingsModal.tsx:99-110** - `remediateAll` sequential awaits with no unmount guard; closing modal mid-loop calls `setError`/`alert` after unmount. Fix: AbortController or `isMounted` ref.
- **[medium] src/pages/Compliance/ProfileModals.tsx:303-323** - Same pattern as above in `AssignProfileModal.onPrimary`.
- **[medium] src/pages/Compliance/Compliance.tsx:179** - `onRescan` updates resultId without resetting `previewIndex`, potentially indexing into a different findings array. Fix: reset on `resultId` change.
- **[medium] src/pages/Configuration/SetBaselineModal.tsx:62** - `name` not trimmed before submit. Fix: `name: name.trim() || undefined`.
- **[medium] src/api/configuration.ts:204** - `useConfigBackupPolicies` calls `apiRequest('/config-backups/policies?')` with stray trailing `?`.
- **[medium] src/pages/Configuration/Configuration.tsx:54-67** - `<ConfigJobStreamModal>` always mounted; effect early-returns when `!isOpen` - minor.
- **[medium] src/pages/Compliance/ProfileModals.tsx:53-72,130-152** & **RunScanModal.tsx:248** & **Federation/PeerFormModal.tsx:32-58** - Forms use button `onClick`, no `<form onSubmit>` - Enter key doesn't submit. Fix: wrap in `<form>`.
- **[low] src/pages/Configuration/DriftTab.tsx:139-143** - Bulk "Resolve All Open" loops `updateStatus.mutate(...)`; only one `isPending` reflects, multi-tap re-enqueues. Fix: bulk endpoint or local guard.
- **[low] src/pages/Configuration/SearchTab.tsx:96** - `Number(e.target.value || '50')` snaps when user types `0`. Same pattern in many other Number-coercion call sites listed below.

## Inventory / IPAM / Federation

- **[high] src/pages/Inventory/Inventory.tsx:64-65** - `useState<boolean>(loadCompactMode())` and `useState<Set<number>>(loadCollapsedSet())` invoke initializers on every render (synchronous localStorage access each time). Fix: pass functions: `useState(() => loadCompactMode())`.
- **[high] src/pages/Ipam/Ipam.tsx:75-79** - `handleRefresh` only invalidates `ipam-overview`/`ipam-subnet-detail`/`ipam-sources`; misses `reconcileRuns`, `reconcileDiffs`, `dhcpServers`, `dhcpExhaustion`, `dhcpCorrelation`. Fix: invalidate all visible panels' keys.
- **[medium] src/pages/Inventory/Inventory.tsx:140-141** - `current.filter(id => id !== dragId)` then `without.indexOf(overId)`; if `overId` is missing, `next` becomes `[dragId, ...without]` (unintended prepend). Fix: guard `if (overIdx < 0) return;`.
- **[medium] src/pages/Inventory/HostModal.tsx:35-37** - Initial `selectedGroupId` reads `host?.group_id ?? groupId ?? groups[0]?.id ?? 0`; if `groups` arrives later, dropdown stays at `0`. Fix: sync via `useEffect`.
- **[medium] src/pages/Inventory/Inventory.tsx:650-652** - Indeterminate-checkbox ref callback runs only on mount; later `indeterminate` prop changes don't update DOM. Fix: `useEffect` that writes `el.indeterminate` when prop changes.
- **[medium] src/pages/Inventory/DiscoveryModal.tsx:670** - IPv4 regex `^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$` accepts `999.999.999.999`. Fix: validate octet ranges.
- **[medium] src/pages/Inventory/DiscoveryModal.tsx:572,583** - `Number(e.target.value || 0.35)` - typing `0` falls back to `0.35` (falsy-zero). Fix: parse and check `Number.isNaN`.
- **[medium] src/pages/Inventory/DiscoveryModal.tsx:163,222** - `targetGroupId = isGlobal ? groupId : group?.id ?? groupId`; if `groups` is empty, `groupId === 0` reaches `/inventory/0/...`. Fix: require non-zero before submit.
- **[medium] src/pages/Inventory/helpers.ts:86** - `new Set((JSON.parse(raw) as unknown[]).map((v) => Number(v)))` does not filter `NaN`. Fix: filter `Number.isFinite`.
- **[medium] src/pages/Federation/Federation.tsx:406-408** - `formatDate(iso)` uses `new Date(iso)` directly without zone normalization. Fix: detect zone like `formatStamp`.
- **[low] src/pages/Configuration/SearchTab.tsx:96**, **Compliance/ProfileModals.tsx:288**, **Configuration/BackupPolicyModal.tsx:164,175**, **Inventory/SnmpProfilesModal.tsx:252,263,285**, **Ipam/SyncScheduleModal.tsx:55** - `Number(e.target.value || X)` falsy-zero pattern (`0 || X → X`). Fix: parse and check `Number.isNaN` separately.

## Deployments / Upgrades / Risk Analysis / Settings

- **[high] src/pages/Upgrades/EditImageModal.tsx:18-26** - `useEffect` deps include unstable `update` mutation object → effect re-runs on every parent render, repeatedly resetting form fields and clobbering user input. Fix: depend only on `[image]` (or `[image?.id]`).
- **[high] src/pages/Upgrades/NewImageModal.tsx:16-22** - Same pattern: `useEffect` deps include `upload` mutation. Fix: drop from deps.
- **[high] src/pages/Upgrades/CampaignFormModal.tsx:124-164** - Hydration effect lists `images` in deps; image refetches re-run hydration and overwrite user-edited rows. Fix: hydrate once, omit `images` from deps (or use `imagesQ.isPending` transition).
- **[high] src/pages/Deployments/DeploymentJobStreamModal.tsx:40-90** - On cleanup, `ws.close()` is called but `onopen`/`onmessage`/`onerror`/`onclose` are not detached; in-flight messages still call `setOutput`/`setStatus` on a new effect run or after unmount. Fix: null out handlers in cleanup before close.
- **[high] src/pages/Upgrades/CampaignViewerModal.tsx:138-208** - Same WebSocket cleanup gap: handlers stay attached after `ws.close()`. Fix: detach `ws.on*` in cleanup.
- **[medium] src/pages/Deployments/DeploymentJobStreamModal.tsx:62** & **Upgrades/CampaignViewerModal.tsx:194-198** - Output / liveLines arrays grow unbounded for long jobs (memory). Fix: cap to last N lines.
- **[medium] src/pages/RiskAnalysis/helpers.ts:20-23** - `formatStamp(iso)` always appends `'Z'` without `hasZone` check (Deployments helper does). Fix: mirror Deployments check.
- **[medium] src/pages/Deployments/DeploymentDetailModal.tsx:342-348** - `m.pre.toFixed(1)` etc. - values come from free-form JSON; if backend serializes a metric as string, `.toFixed` throws. Fix: coerce or `typeof === 'number'` guard.
- **[medium] src/pages/RiskAnalysis/NewAnalysisModal.tsx:55-72** & **OfflineAnalysisModal.tsx:22-56** - Form state never reset on close/cancel, only on success. Fix: reset on `isOpen` false transition.
- **[medium] src/pages/Deployments/NewDeploymentModal.tsx:33-99** - Same: only `reset()` on create success. Fix: reset on `isOpen` change.
- **[medium] src/pages/Settings/UserModals.tsx:196-220** - `CreateUserModal` sends `group_ids` in create payload then immediately fires `setGroups.mutate` with same list - duplicate work + race. Fix: pick one path.
- **[medium] src/pages/Settings/UserModals.tsx:301-329** - `EditUserModal` Save disabled only on `update.isPending`, not chained `setGroups.isPending` → double-submit possible. Fix: combine flags.
- **[medium] src/pages/Deployments/Deployments.tsx:271-274** & **RiskAnalysis/RiskAnalysis.tsx:230-301** - Per-row `useExecuteDeployment`/`useDeleteRiskAnalysis()` etc. - N rows × 3 mutation hooks. Fix: hoist mutations to parent.
- **[medium] src/pages/Deployments/Deployments.tsx:280-310** - Execute/Rollback/Delete each disable only their own mutation; quick succession lets two run concurrently. Fix: combine pending flags.
- **[medium] src/pages/Settings/AccessGroupsTab.tsx:78-90** & **UsersTab.tsx:97-109** - Delete buttons not disabled while `remove.isPending`; rapid click double-fires.

## Reports / Jobs / Monitoring / Cloud / NetworkTools / GraphTemplates

- **[high] src/api/monitoring.ts:316-361** vs **src/api/reports.ts:38-111** - `useAvailabilitySummary`, `useAvailabilityOutages`, `useAvailabilityTransitions`, `useCapacityPlanning` exist in both modules with the *same* queryKey prefixes (`['availability-summary',...]` etc.) but different param shapes and response types → cache cross-contamination, runtime type errors when both pages mount. Fix: namespace keys (`'reports-availability-summary'` vs `'monitoring-availability-summary'`).
- **[high] src/api/monitoring.ts:498-550** - `streamPollNow` parses SSE by splitting on single `\n` and looking for `data:` prefix; standard SSE delimits events with `\n\n` and may include `event:`/`id:`/`retry:` lines or multi-line `data:` continuations. Multi-line payloads silently dropped. Fix: split on `\n\n` and join `data:` lines per event.
- **[high] src/api/monitoring.ts:537-549** - Reader loop has no `try/finally` to `reader.releaseLock()` / `reader.cancel()` on abort/exception. Fix: wrap in `try/finally`.
- **[high] src/pages/Monitoring/DevicesTab.tsx:59-94** - `pollNow` awaits `streamPollNow` without `AbortController`; navigation mid-poll keeps invoking `setProgress`/`qc.invalidateQueries` on unmounted component. Fix: `AbortController` ref, pass `signal`, abort on unmount.
- **[high] src/pages/Monitoring/DevicesTab.tsx:90** - `setTimeout(() => setProgress(initialProgress), 8000)` has no cleanup; navigating away or starting another poll within 8s leaves a stale timer. Fix: ref-tracked timer.
- **[high] src/pages/Monitoring/SuppressionsTab.tsx:38-39** - `new Date(s.ends_at + 'Z')` unconditionally appends `Z`; if backend already returns `Z`, result is `"...ZZ"` (Invalid Date) → all suppressions appear "Expired". Fix: append only when missing.
- **[high] src/pages/Monitoring/SuppressionsTab.tsx:91-103** - `handleSubmit` does not validate `starts` non-empty; `new Date('').toISOString()` throws `RangeError`, no user feedback. Fix: validate before `toISOString()`.
- **[high] src/pages/Monitoring/SlaTab.tsx:464-465** - `parseInt(hostId, 10) || null` returns `null` for hostId `'0'` (`0 || null === null`); a real host with id 0 silently becomes global scope. Fix: `Number.isNaN`-based parse.
- **[high] src/pages/CloudVisibility/AccountsTab.tsx:284** - `useState(account?.enabled === 0 ? false : true)` - when `account.enabled` is the boolean `false`, `false === 0` is `false`, so form initializes `enabled: true`. Disabled accounts open as enabled and silently re-enable on save. Fix: `useState(account ? Boolean(account.enabled) : true)`.
- **[high] src/pages/CloudVisibility/AccountsTab.tsx:36-39**, **FlowTab.tsx:48-51**, **TrafficTab.tsx:46-49** - `flash` `setTimeout` with no cleanup; rapid actions stack timers, stale fires on unmounted component. Fix: ref-tracked timer.
- **[high] src/pages/Jobs/JobOutputModal.tsx:78-83** - `ws.onclose` calls `setWsState(...)` after cleanup `ws.close()` triggers `onclose`, mutating state for the next jobId session. Fix: detach `ws.on*` handlers before close.
- **[high] src/pages/Jobs/JobOutputModal.tsx:42-47** - Reset effect only runs on `jobId` change; close+reopen same jobId leaves stale `liveEvents`/`liveStatus`. Fix: also depend on `isOpen`.
- **[high] src/pages/Jobs/JobOutputModal.tsx:66-72** - `liveEvents` grows unbounded on long jobs. Fix: cap to last N entries.
- **[high] src/pages/Jobs/JobsTab.tsx:56** - Sort uses `localeCompare` on raw timestamp strings (locale-sensitive, unstable for missing timestamps). Fix: numeric `Date.parse`, tiebreak by `j.id`.
- **[high] src/pages/Jobs/helpers.ts:60-68** - `withinDateRange` uses `new Date(dateStr)` without `Z` normalization; non-UTC parsing skews day-boundary filtering. Fix: append `Z` if missing.
- **[high] src/pages/Reports/GenerateBillingModal.tsx:23-24** - `period_start = `${start}T00:00:00`` (no tz) for billing - backend semantics ambiguous, off-by-one-day risk. Fix: append `Z` or use date-only string.
- **[medium] src/pages/Jobs/CredentialsList.tsx:47-49** - `useState(credential.name)` initialized once; refetch updating credential silently keeps stale form values. Fix: `key={credential.id}` on the row, or `useEffect` sync.
- **[medium] src/pages/Reports/CapacityPlanningTab.tsx:115** - Hardcoded `90` in `(slope * 90 + intercept)` ignores selected `range` (7/30/90/180). Fix: derive from range.
- **[medium] src/pages/Reports/CapacityPlanningTab.tsx:39,42-46** - Per-host series keyed by `hostname`; duplicate/missing hostnames collide. Fix: include `host_id`.
- **[medium] src/pages/Reports/CircuitFormModal.tsx:64-66** - `parseFloat(commit) || 0` silently coerces invalid input to 0 commit (wrong billing data). Fix: validate `Number.isFinite`.
- **[medium] src/pages/Reports/OidProfileModal.tsx:49-54** - `JSON.parse(oidsJson)` only validates parseability, not array-of-objects shape. Fix: validate each entry's required keys.
- **[medium] src/pages/Reports/Reports.tsx:23-24** - Tab state not synced to URL; reload loses active tab (Monitoring/Jobs do sync). Fix: pathname/query sync.
- **[medium] src/pages/Monitoring/AlertsTab.tsx:15-50** - `selected` Set accumulates IDs no longer present after refetch. Fix: prune on alerts.data change.
- **[medium] src/pages/Monitoring/RoutesTab.tsx:69** - `prev = snapshots.data?.[i + 1]` assumes newest-first ordering; if backend changes, displayed delta sign flips. Fix: sort defensively before delta.
- **[medium] src/pages/Monitoring/RoutesTab.tsx:97-110** - Nested `<Modal>` (Route Table inside snapshot list); verify component supports nesting (z-index, focus trap).
- **[medium] src/pages/Monitoring/RoutesTab.tsx:104-108** - `navigator.clipboard.writeText(...)` without `.catch()` → unhandled promise rejection on failure.
- **[medium] src/pages/Monitoring/CapacityTab.tsx:113** & **SlaTab.tsx:273-274** - `Math.min/max(...values)` for very long arrays risks call-arg limit. Fix: reducing loop.
- **[medium] src/pages/Reports/CircuitFormModal.tsx:138-149**, **Jobs/PlaybookFormModal.tsx:84-98**, **Reports/OidProfileModal.tsx:30-41**, **GraphTemplates/HostTemplateModal.tsx:27-41**, **GraphTemplates/GraphTreeFormModal.tsx:25-32**, **Jobs/TemplateFormModal.tsx:26-34** - Edit-mode hydration effects depend on `[mode, query.data]` but miss the id (e.g. `circuitId`/`templateId`/`profileId`/`treeId`/`playbookId`). Switching id at edit mode shows stale fields until refetch lands. Fix: include the id in deps.
- **[medium] src/pages/CloudVisibility/AccountsTab.tsx:25,269-292** - `modalAccount` 3-state with no remount key; switching between create and edit lets previous edit's typed values bleed in. Fix: `key={account?.id ?? 'new'}` on modal.
- **[medium] src/pages/CloudVisibility/AccountsTab.tsx:147** - `computeSyncReadiness(a)` runs in `accounts.map` and re-parses `auth_config` JSON each render. Fix: `useMemo`.
- **[medium] src/pages/CloudVisibility/CloudVisibility.tsx:52-56** - `providerOptions` recomputed inline each render. Fix: `useMemo`.
- **[medium] src/pages/CloudVisibility/SyncControls.tsx:21** - Local `interval` shadows global `setInterval`; latent footgun. Fix: rename.
- **[medium] src/pages/Reports/AvailabilityTab.tsx:145-147,172-174**, **SyslogEventsTab.tsx:90**, **Reports/GenerateReportTab.tsx:158-164**, **CloudVisibility/PolicyTab.tsx:184**, **FlowTab.tsx:140,164**, **TrafficTab.tsx:132,156**, **TopologyTab.tsx:487,516** - Various lists use `key={i}` (index) for items that may reorder/refilter on refetch. Fix: composite stable keys (timestamps, ids, ip+vrf, etc.).
- **[medium] src/pages/GraphTemplates/GraphTreeDetailModal.tsx:19-23** & **GraphTemplateCreateModal.tsx:23-31** - Form state never resets when `treeId` changes / `isOpen` toggles. Fix: reset on transition.
- **[medium] src/pages/GraphTemplates/HostTemplateModal.tsx:34-37** - `JSON.parse(ht.device_types || '[]')` silent-catches malformed data with no diagnostic. Fix: log/surface.
- **[medium] src/pages/Monitoring/Monitoring.tsx:14** & **Jobs/Jobs.tsx:11** - `tabFromPath` exact-matches `pathname === t.path`; subpaths fall back to default tab. Fix: `startsWith` longest-match.
- **[medium] src/pages/Monitoring/SuppressionsTab.tsx:99-100** - Sends timestamps as `"YYYY-MM-DD HH:MM:SS"` with no tz indicator; backend semantics ambiguous. Fix: full ISO with `Z`.

## Cross-cutting smells (lower priority)

- Many forms wrap submit in button `onClick` instead of `<form onSubmit>`, so Enter doesn't submit.
- Many `Number(e.target.value || X)` patterns produce falsy-zero fallback.
- Several modals do not reset state when `isOpen` transitions false→true.
- Client-side role/feature gating in ChangeManagement and elsewhere - verify API enforces too (security smell, not bypass).
- Dashboard/Reports/Monitoring use a mix of `isLoading` (legacy) and `isPending` (TanStack v5) - stylistic inconsistency.
