# Frontend Migration Plan

Migrate Plexus's vanilla JS SPA (~33K lines across 18 modules) to a modern React + TypeScript stack, page-by-page, over ~9-12 months.

## Goals

1. **Maintainability for a solo developer** — code that one person + AI can keep healthy long-term.
2. **Enterprise reliability** — fewer bug classes (XSS, stale-state, type errors), real test coverage, predictable upgrades.
3. **Future-proofing** — alignment with the React + PatternFly stack used by AWX (the canonical Ansible-style automation platform).
4. **Zero regression during migration** — the app must keep shipping features and stay deployable at every step.

## Non-Goals

- Big-bang rewrite. Every previous big-bang frontend rewrite this author has read about has stalled. We avoid that.
- Server-side rendering, micro-frontends, or any "modern" complexity beyond what the app needs.
- Replacing the Python/FastAPI backend. The backend stays.

---

## The Stack

| Layer | Choice | Why |
|---|---|---|
| Framework | **React 18** | Already used by the developer (budgeting app); largest ecosystem; aligns with AWX |
| Language | **TypeScript (strict)** | Compile-time error detection; non-negotiable for solo + AI workflow |
| Build tool | **Vite** | Fast dev server, simple config, correct choice for SPA-backed-by-API |
| Server state | **TanStack Query (React Query)** | Replaces the manual `_groupCache` / fingerprint pattern in [app.js](netcontrol/static/js/app.js). Single biggest framework win. |
| Client state | **Zustand** | ~2KB, minimal API. Avoid Redux/MobX. |
| Component library | **PatternFly** | Red Hat's open-source design system used by AWX. Tables, wizards, job log viewers, forms, topology — all built and battle-tested. |
| Charts | **ECharts** (existing) | Already in use, no need to change. |
| Topology graph | **vis-network** (existing) | Already in use; React wrapper available. |
| Code editor | **CodeMirror** (existing) | Already in use. |
| Testing (unit) | **Vitest** | Vite-native, Jest-compatible API |
| Testing (component) | **React Testing Library** | Standard for React component tests |
| Testing (E2E) | **Playwright** | Framework-agnostic browser tests; runs against old and new pages during migration |
| Linting | **ESLint + typescript-eslint + eslint-plugin-react-hooks** | Catches React-specific bugs |
| Formatting | **Prettier** | One config, no debates |

### Rejected alternatives (decision log)

- **Vue 3** — initially considered, but the developer has shipped React before. Use the framework you can review.
- **Next.js / Remix** — SSR adds complexity. Plexus is an SPA backed by FastAPI; no SSR benefit.
- **Redux** — Zustand covers global state at 1% of the boilerplate.
- **Tailwind CSS** — conflicts with PatternFly's design system; pick one.
- **Svelte** — smaller ecosystem; fewer pre-built components for ops/network UIs.
- **htmx + server-rendered partials** — Plexus has too much real-time client state (job streams, live topology, monitoring polls) to fit htmx's CRUD-page model.

---

## Phase 0 — Foundations (Weeks 1-3)

**No frontend code is rewritten in this phase.** The goal is to make the rewrite verifiable.

### 0.1 Backend test coverage to ≥70% on API endpoints

The AI will use these tests as the contract for "did the React rewrite preserve behavior?" Without tests, behavior preservation cannot be verified.

**Tasks:**
- [ ] Run `pytest --cov=netcontrol --cov=routes --cov-report=term-missing` to baseline current coverage
- [ ] Identify endpoints under 50% coverage (likely candidates: monitoring, topology, ipam edge cases)
- [ ] Add coverage to all endpoints called by the frontend modules
- [ ] Set CI to fail if coverage drops below 70%

### 0.2 GitHub Actions CI pipeline

Every push runs:
- `pytest` (with coverage gate)
- `mypy` or `pyright` on `netcontrol/`, `routes/`, `tools/`
- `ruff check` on Python
- A smoke test: `docker compose up -d`, hit `/api/health`, expect 200
- Once frontend exists: `eslint`, `tsc --noEmit`, `vitest run`, `playwright test`

**Block merges to `main` if any check fails.**

**Tasks:**
- [ ] Create `.github/workflows/ci.yml` with the above
- [ ] Configure branch protection on `main` requiring passing checks

### 0.3 Playwright E2E tests for critical user flows

These tests are framework-agnostic and survive the migration. They tell you whether a React rewrite of a page broke anything user-visible.

**Minimum critical flows:**
- [ ] Login → land on dashboard
- [ ] Create inventory group → add host → see it in list
- [ ] Launch a playbook job → see streamed output → job completes
- [ ] View topology graph for a group
- [ ] View monitoring dashboard for a host
- [ ] Add/edit credential
- [ ] Edit auth provider settings
- [ ] Run compliance scan

Each test: ~50-150 lines of Playwright. Total effort: ~1 week.

### 0.4 Type-check the Python backend

You're a Python dev — get the same compile-time-safety on the side of the codebase you wrote.

**Tasks:**
- [ ] Add `mypy.ini` or `pyproject.toml` `[tool.mypy]` block, start with `--strict` on one module
- [ ] Expand to all modules over 1-2 weeks
- [ ] Add to CI as a blocking check

### 0.5 Write `FRONTEND_STYLE.md`

The rules the AI must follow on every PR. Without this, the AI drifts across sessions and you end up with three frameworks-within-React.

**Sections (draft):**
- Component file structure: one component per file, PascalCase, `.tsx`
- Server state: always via TanStack Query hooks in `src/api/`
- Client state: Zustand stores in `src/stores/`, one store per domain
- Styling: PatternFly components first; custom CSS only when PatternFly doesn't have it
- API calls: never `fetch()` directly in components; always through a `useXxx` query hook
- Forms: PatternFly `Form` + React Hook Form for validation
- Error handling: `<ErrorBoundary>` at route level; toasts via PatternFly `AlertGroup`
- Naming: `useGroups()`, `useCreateGroup()`, `GroupList`, `GroupDetail`, etc.
- Imports: absolute via `@/` alias, no relative `../../../`
- No `any` types except at well-documented seams
- Every component file must have a co-located `.test.tsx`

This document is referenced in every AI prompt during migration.

---

## Phase 1 — Pilot (Weeks 4-8)

Migrate **one** small, low-risk module to validate the entire pipeline end-to-end.

### Pilot target: Network Tools (230 lines)

Why this one:
- Small enough to migrate in a single PR
- Mostly forms + API calls (low UI complexity)
- Self-contained — no shared state with other modules
- Low-stakes — a bug here doesn't break inventory or job execution

### 1.1 Set up the React app

**Directory structure (new):**
```
netcontrol/static/
├── frontend/              # NEW — Vite + React app
│   ├── src/
│   │   ├── pages/
│   │   │   └── NetworkTools/
│   │   ├── components/
│   │   ├── api/           # TanStack Query hooks
│   │   ├── stores/        # Zustand stores
│   │   ├── types/         # Shared TypeScript types
│   │   └── main.tsx
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── eslint.config.js
├── js/                    # EXISTING — vanilla modules, untouched
├── index.html             # EXISTING — main SPA shell
└── ...
```

**Tasks:**
- [ ] `npm create vite@latest frontend -- --template react-ts`
- [ ] Install: `react-router-dom`, `@tanstack/react-query`, `zustand`, `@patternfly/react-core`, `@patternfly/react-table`, `react-hook-form`, `zod`
- [ ] Install dev: `vitest`, `@testing-library/react`, `@playwright/test`, `eslint-plugin-react-hooks`, `prettier`
- [ ] Configure Vite to build into `netcontrol/static/frontend/dist/`
- [ ] Update FastAPI to serve `/frontend/*` from that dist directory
- [ ] Add `npm` build to the CI pipeline and Dockerfile

### 1.2 Mount the React app on `#network-tools`

Two patterns to choose between:
- **Option A (simpler):** the legacy `index.html` redirects `#network-tools` to `/frontend/network-tools` which loads the React SPA shell with just that page.
- **Option B (more work, cleaner end state):** mount React on a `<div id="react-root">` inside the existing index.html, render only when `#network-tools` is the active hash, leave everything else untouched.

**Recommend Option B** — keeps the migration boundaries clean and lets you migrate one page at a time without touching routing globally until the end.

### 1.3 Port Network Tools to React

**Process for every page migration (codify this):**
1. Write/extend Playwright tests for the page's user flows against the *current* vanilla version
2. Confirm they pass
3. AI writes the React port, following `FRONTEND_STYLE.md`
4. Run Playwright against the React version — must pass identically
5. Run unit tests (Vitest)
6. Manual smoke test in dev
7. Code review (you read every line — required)
8. Merge behind a feature flag (`?frontend=react` query param or env var)
9. **Soak in production for 2 weeks**, gather any bug reports
10. Remove the feature flag, delete the vanilla module file
11. Move to next page

### 1.4 Pilot exit criteria

Before Phase 2 starts, **all of these must be true:**
- [ ] Network Tools is on React, in production, no incidents for 2 weeks
- [ ] CI pipeline runs all checks reliably (no flakes)
- [ ] Build pipeline works on the deploy VM (Docker image build succeeds, app boots, page loads)
- [ ] Playwright tests run green on every PR
- [ ] You can read and explain any line of the new React code

If any of these fails, **stop and fix the foundation before migrating more.**

---

## Phase 2 — Routine Migration (Months 3-9)

One module per 2-3 weeks, in order of *least* risk first. Each follows the 11-step process above.

### Migration order (proposed)

| # | Module | Lines | Risk | Reason for order |
|---|---|---|---|---|
| 1 | network-tools | 230 | Low | Pilot (Phase 1) |
| 2 | federation | 332 | Low | Small, self-contained |
| 3 | floor-plan | 546 | Low | Visualization but contained |
| 4 | device-detail | 758 | Low-Med | Read-only views, validates patterns |
| 5 | compliance | 816 | Med | Form-heavy, exercise PatternFly forms |
| 6 | settings | 979 | Med | Mostly forms + auth wiring |
| 7 | dashboard | 953 | Med | Charts (ECharts integration in React) |
| 8 | change-management | 990 | Med | Workflow patterns |
| 9 | upgrades | 1,291 | Med | Job-launch patterns |
| 10 | configuration | 1,425 | Med-High | CodeMirror integration |
| 11 | inventory | 1,430 | High | Core feature; lots of state |
| 12 | ipam | 1,424 | High | Complex domain logic |
| 13 | reports | 1,673 | High | Complex tables, exports |
| 14 | jobs | 1,584 | High | WebSocket streaming |
| 15 | monitoring | 1,561 | High | Real-time updates, charts |
| 16 | cloud-visibility | 2,019 | High | Multi-cloud integration |
| 17 | topology | 2,124 | Very High | Complex graph, real-time, last on purpose |

### Why this order

- **First 4 are reps.** Build muscle memory on small, safe modules. The AI learns your conventions; you learn what good React PRs look like in *this* codebase.
- **Forms before tables before real-time.** PatternFly forms are well-documented and forgiving. Real-time WebSocket integration is the hardest pattern; do it after you've built confidence.
- **Topology last.** It's the most complex module (2,124 lines), the most visually complex page, and the one most likely to have hidden behavioral edge cases. Do it after you've migrated 16 other modules.

### Per-module migration template prompt for AI

(Copy-paste, fill in the module name. This goes to AI on every migration.)

```
Migrate the Plexus frontend module netcontrol/static/js/modules/<MODULE>.js
to React + TypeScript + PatternFly, following all rules in FRONTEND_STYLE.md.

Constraints:
- Behavior must match the existing module exactly. Use the Playwright tests
  in tests/e2e/<MODULE>.spec.ts as the contract.
- Use TanStack Query for all server data; no fetch() in components.
- Use PatternFly components for all UI primitives; no custom CSS unless
  PatternFly has no equivalent.
- Co-locate a Vitest test file with each component.
- Output the new code under netcontrol/static/frontend/src/pages/<Module>/

Do not modify any other module. Do not modify backend code without explicitly
asking first.
```

---

## Phase 3 — Cleanup (Months 9-12)

After the last module migrates:

- [ ] Delete `netcontrol/static/js/app.js` shared utilities (each one removed when its last consumer migrates)
- [ ] Delete `netcontrol/static/js/modules/` entirely
- [ ] Delete `netcontrol/static/js/page-templates.js` (1,804 lines)
- [ ] Remove the legacy `index.html` shell; React app becomes the only frontend
- [ ] Consolidate any AI drift across modules (audit for inconsistent patterns)
- [ ] Final Playwright pass over every page
- [ ] Update `AGENTS.md` and `CLAUDE.md` to reflect the new frontend stack
- [ ] Update `README.md` architecture diagram

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| AI generates plausible-but-wrong React code | High | High | Phase 0 test coverage; Playwright tests must pass; required code review |
| Pattern drift between modules | High | Medium | `FRONTEND_STYLE.md` referenced in every prompt; cleanup audit in Phase 3 |
| Build pipeline breaks on customer deploys | Medium | High | Pilot soak in production; Docker image testing in CI; pinned dependency versions |
| Migration stalls partway through | Medium | High | Per-module merging; app stays shippable at every step; no big-bang |
| TanStack Query / PatternFly version churn | Medium | Low | Pin versions in package-lock.json; budget 1-2 days/year for updates |
| WebSocket integration regression in jobs/monitoring | Medium | High | Migrate jobs and monitoring late, after 10+ smaller reps |
| Developer time absorbed by frontend, backend stagnates | High | Medium | Cap migration to ~30% of dev time; one module per 2-3 weeks max |

---

## Success Metrics

By end of Phase 3:
- [ ] Zero `escapeHtml()` calls in the codebase (auto-escaping by framework)
- [ ] Frontend test coverage ≥60% (lines)
- [ ] All user flows have Playwright coverage
- [ ] Every PR runs typecheck + lint + tests + E2E green
- [ ] Bundle size measured and tracked (target: under 1MB gzipped main bundle)
- [ ] Page-load time measured and tracked (target: TTI under 2s on local network)
- [ ] No production XSS or state-corruption bugs reported in 90 days
- [ ] Solo dev can read any frontend file and understand it without AI assistance

---

## Decision Log

This section grows as decisions are made during the migration.

### 2026-05-01 — Initial plan
- React over Vue: developer has prior React experience (budgeting app)
- PatternFly chosen over Material UI / Chakra: AWX precedent, ops/automation UI fit
- Vite over Next.js: SPA backed by FastAPI, no SSR needed
- Migration order biased toward small/forms-heavy first, real-time/complex last

### 2026-05-02 — Drop PatternFly, reuse legacy CSS
- **Context:** Phase 1.1 + 1.3 shipped on PatternFly. The visual divergence
  from the legacy SPA's "glass-card" dark theme was jarring during the
  migration soak — old and new pages sit side-by-side and clash.
- **Considered:** (a) accept the new look, (b) heavy-theme PatternFly to
  approximate legacy, (c) drop PatternFly entirely and reuse the legacy
  stylesheet.
- **Chose:** (c). The React app loads
  `netcontrol/static/css/style.css` and uses the same class names as the
  legacy SPA (`glass-card card`, `data-table`, `btn btn-primary`,
  `form-input`, `page-header`, `empty-state`, `modal-overlay/.modal`, etc).
- **Why:** pixel-perfect visual match for free, smaller bundle, single
  design source of truth so legacy redesigns automatically apply to React
  and vice versa. The plan's "battle-tested components" argument lost to
  the immediate cost of UI inconsistency in production.
- **Reversible?** Yes, at the cost of re-converting all React pages back to
  PatternFly. Per-page conversion is mechanical (~1 hour each). Reverting
  the convention itself is a one-line change to FRONTEND_STYLE.md.
- **Status (2026-05-02):** All React pages converted —
  `Home`, `MacTracking`, `TrafficAnalysis`, `Lab`, `TopologyCanvas`.
  PatternFly fully removed from `package.json`. The React app loads only
  `/static/css/style.css`. New pages MUST use legacy CSS — see
  `FRONTEND_STYLE.md` § Styling.

### 2026-05-02 — Device Detail port + ECharts wrapper
- **Context:** Phase 1.6 — porting `device-detail.js` (758 lines).
  This is the first React page that needs charts; legacy uses
  `PlexusChart` (an ECharts wrapper in `app.js`).
- **Considered:** (a) skip charts for now and ship tables only,
  (b) write a thin SVG sparkline component for the metric cards,
  (c) install `echarts` and mirror `PlexusChart`'s options.
- **Chose:** (c). New file `src/lib/echart.tsx` exposes
  `<TimeSeriesChart>` and `<BarChart>` — same theme colors (read from
  the same CSS variables used by the legacy stylesheet), same option
  shape as legacy. Drop-in equivalent of `PlexusChart.timeSeries` /
  `PlexusChart.bar`.
- **Bundle cost:** gzipped JS jumped from ~85 KB → ~465 KB. ECharts is
  ~330 KB gz on its own. Acceptable: legacy has the same size and the
  alternative is rebuilding charts from scratch.
- **Reversible?** Yes — swap `echart.tsx` for a different chart lib;
  the call sites are <10. Bundle cost is the only meaningful blocker.

### Future entries (template)
```
### YYYY-MM-DD — <decision title>
- Context: <what prompted the decision>
- Considered: <options>
- Chose: <choice>
- Why: <rationale>
- Reversible? <yes/no, and at what cost>
```

---

## Appendix A — What stays in vanilla JS forever

Some files don't need migration:
- `js/echarts.min.js` (vendor, 45 lines wrapper)
- `js/vis-network.min.js` (vendor, 34 lines wrapper)
- `vendor/codemirror/*` (vendor)
- `js/websocket.js` (136 lines) — may be replaced by a TanStack Query subscription pattern, evaluate during jobs migration

## Appendix B — Files to delete in Phase 3

Tracked here so nothing gets forgotten:
- `js/app.js` (the shared-utilities blob)
- `js/api.js` (replaced by TanStack Query hooks)
- `js/modules/*.js` (all 18 modules)
- `js/page-templates.js`
- `js/virtual-list.js` (PatternFly tables have built-in virtualization)
- Top-level `index.html` shell once React mounts at root

## Appendix C — References

- AWX UI repo: github.com/ansible/ansible-ui (reference for React + PatternFly in an automation platform)
- PatternFly catalog: patternfly.org
- TanStack Query docs: tanstack.com/query
- Vite docs: vitejs.dev
- React docs: react.dev
