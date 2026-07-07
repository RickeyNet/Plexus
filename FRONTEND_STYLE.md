# Frontend Style Guide

Conventions for the React + TypeScript port of Plexus. **Read this before
writing or porting any frontend code.** It is referenced from every AI
migration prompt and is the single source of truth for "how do we do
things in this app."

This is a *living* document - conventions that prove themselves get
codified here. Conventions that prove wrong get replaced. Always update
this file when you change a pattern, and mention the change in the
decision log in `docs/FRONTEND_MIGRATION.md` (archived migration plan).

> Project layout: `netcontrol/static/frontend/` is the React app
> (Vite + TS). Builds to `dist/`, served by FastAPI at `/frontend/`.
> Source root is `src/`. The legacy vanilla SPA (`netcontrol/static/js/`)
> has been fully migrated and deleted; React is the only frontend.

---

## Stack (what's actually in use)

| Layer | Choice |
|---|---|
| Framework | React 19 |
| Language | TypeScript (strict) |
| Build | Vite 8 |
| Routing | react-router-dom v7, mounted under `basename="/frontend"` |
| Server state | TanStack Query v5 |
| Charts | ECharts (wrapped in `src/lib/echart.tsx`) |
| Styling | Legacy stylesheet `netcontrol/static/css/style.css` - no PatternFly, no Tailwind, no CSS-in-JS framework |
| Modals | `<Modal>` in `src/components/Modal.tsx` (portal + Escape-to-close) |
| Forms | Plain `useState` + native HTML `<input>/<select>/<textarea>` |
| Confirm dialogs | Native `confirm()` |

### Installed but currently unused

`zustand`, `react-hook-form`, `zod` are in `package.json` but **no file
imports them.** Don't reach for them on a whim - if you need one,
discuss it first and add a decision-log entry. The migration has so far
not needed cross-page client state or schema validation; if you find
yourself needing them, that's a real signal.

---

## Directory layout

```
netcontrol/static/frontend/src/
├── App.tsx              # Top-level routes + sidebar/header chrome
├── main.tsx             # Root render, QueryClient, Router
├── api/                 # One file per backend domain - TanStack Query hooks live here
│   ├── client.ts        # Fetch wrapper + CSRF + ApiError
│   ├── auth.ts
│   ├── deployments.ts
│   └── ...
├── components/          # Cross-page UI (Modal, Sidebar, UserMenu, AnimatedBackground)
├── lib/                 # Cross-page non-UI helpers (echart wrapper, hooks)
└── pages/
    └── <Module>/
        ├── <Module>.tsx       # Page component (named export)
        ├── <Sub>Modal.tsx     # One file per sub-component if non-trivial
        └── helpers.ts         # Pure functions, formatters, status maps
```

### Rules

- **One module = one folder under `pages/`.** `Lab.tsx` and
  `TopologyCanvas.tsx` are grandfathered exceptions; new modules use a
  folder.
- **One component per file.** Sub-components used in only one place can
  live in the same file as their parent (see `Deployments.tsx` →
  `DeploymentRow`, `SummaryStrip`). Once a sub-component is reused, hoist
  it to its own file.
- **Pure helpers go in `helpers.ts`** at the page level. Don't co-locate
  them in component files - it makes them invisible to neighboring
  components.
- **No `index.ts` barrel files.** Import from the concrete file. Barrel
  files break tree-shaking and add noise.

---

## Imports

- **Always use the `@/` alias** for anything outside the current folder.
  `@/api/deployments`, `@/components/Modal`, `@/lib/echart`. Never
  `../../../api/...`.
- Relative imports (`./helpers`, `./DeploymentDetailModal`) are fine for
  same-folder siblings.
- Import order (enforced by convention, not lint yet):
  1. Built-ins / node modules (`react`, `@tanstack/react-query`)
  2. Blank line
  3. `@/` imports
  4. Blank line
  5. Relative imports

Example from `App.tsx`:

```tsx
import { useState } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';

import { useAuthStatus } from '@/api/auth';
import { Sidebar } from '@/components/Sidebar';
import { Deployments } from '@/pages/Deployments/Deployments';
```

---

## Server state - TanStack Query

**All server data goes through hooks in `src/api/`. Never call `fetch()`
or `apiRequest()` directly from a component.**

### Query hook conventions

- Name: `useThing()` for a list/get, `useThings()` is fine for a list,
  `useThingDetail(id)` or `useThing(id)` for single resource.
- Query key: an array starting with the resource name. Use
  `['deployments']`, `['deployment', id]`, `['deployment-summary']`. Keep
  the names short and stable - query keys are how cache invalidation
  finds entries.
- Pass `null`/`undefined` IDs explicitly and gate with `enabled: id != null`.
- Don't add `refetchInterval` unless the legacy module had a polling
  loop; if you do, document why in a one-line comment.

```ts
export function useDeployment(id: number | null) {
  return useQuery({
    queryKey: ['deployment', id],
    queryFn: () => apiRequest<DeploymentDetail>(`/deployments/${id}`),
    enabled: id != null,
  });
}
```

### Mutation hook conventions

- Name: `useCreateThing`, `useUpdateThing`, `useDeleteThing`,
  `useExecuteThing`, etc. Verb first.
- Always invalidate the affected query keys in `onSuccess`.
- Surface errors to the component - don't swallow. The component decides
  whether to show `alert()`, a toast, or inline error UI.

```ts
export function useCreateDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: DeploymentCreatePayload) =>
      apiRequest<Deployment>('/deployments', { method: 'POST', body: payload }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['deployments'] });
      qc.invalidateQueries({ queryKey: ['deployment-summary'] });
    },
  });
}
```

### Cache sharing across modules

If two modules need the same lookup data (e.g. inventory groups,
credentials), **export the existing hook from its origin module** rather
than creating a duplicate. `Deployments` reuses `useRiskInventoryGroups`,
`useRiskCredentials`, `useRiskTemplates` from `riskAnalysis.ts` for
exactly this reason. Identical query keys → shared cache → fewer requests.

---

## Types

- TypeScript strict mode is on. **Don't disable it per-file.**
- No `any` except at well-documented seams (`unknown` is almost always
  better - force the consumer to narrow).
- Define API response shapes as `interface` next to their hook in
  `src/api/<module>.ts`. Export them so pages can re-use them.
- Backend fields can be missing - model that with `field?:` and `| null`
  where the API returns null. Be honest about absence; don't pretend.
- Status / enum-like fields: prefer string union types
  (`type DeploymentStatus = 'planning' | 'completed' | ...`) over enums.
  Allow `| string` at the boundary if the backend ever returns values
  outside the union.

---

## API client

`src/api/client.ts` exposes:

- `apiRequest<T>(endpoint, options)` - relative path under `/api`. Adds
  `Accept: application/json`, JSON-encodes object bodies, attaches CSRF
  on mutations, throws `ApiError` on non-2xx.
- `setCsrfToken` / `getCsrfToken` - managed by `useAuthStatus`. You
  shouldn't need to touch these.

**Don't bypass `apiRequest`.** It handles 401-redirect, CSRF, JSON
parsing, error wrapping. The one acceptable exception is WebSockets -
see below.

---

## WebSockets

First example: `pages/Deployments/DeploymentJobStreamModal.tsx`. The
pattern:

- Open the WS in a `useEffect` keyed on `(isOpen, jobId, ...)`. Bail
  early if not open / no id.
- Build the URL as `${protocol}//${window.location.host}/ws/<path>`,
  picking `wss:` vs `ws:` from `window.location.protocol`.
- Hold the socket in a `useRef` so cleanup can call `ws.close()` without
  re-running the effect.
- Always return a cleanup function that closes the socket.
- Parse `event.data` defensively (try/catch around `JSON.parse`).
- On terminal messages, invalidate the relevant TanStack Query keys so
  the rest of the UI refreshes - don't manually re-fetch.

---

## Styling

**Legacy CSS only.** The React app loads
`netcontrol/static/css/style.css` and reuses its class names. This is a
hard rule from the 2026-05-02 decision (see `docs/FRONTEND_MIGRATION.md`).

Common classes:

| Use for | Class |
|---|---|
| Page card / section | `card` (or `glass-card card`) |
| Page header strip | `page-header` |
| Tables | `data-table` |
| Empty states | `empty-state` |
| Buttons | `btn`, `btn-primary`, `btn-secondary`, `btn-sm`, `btn-danger`, `btn-ghost` |
| Form fields | `form-input`, `form-select`, `form-textarea`, `form-label`, `form-group` |
| Status badges | `badge`, `badge-success`, `badge-danger`, `badge-warning`, `badge-info` |
| Modal overlay (handled by `<Modal>`) | `modal-overlay`, `modal`, `modal-large` |
| Muted text | `text-muted` |

When you need a value (color, spacing) reach for the CSS custom
properties first: `var(--success)`, `var(--danger)`, `var(--warning)`,
`var(--text-muted)`, `var(--border)`, `var(--bg-secondary)`. Hard-coded
hex values should be rare and justified.

### When the legacy class doesn't fit

Inline `style={{ ... }}` is acceptable for layout primitives (flex/grid
gaps, fixed widths, max-heights for scrollable regions). Existing pages
do this freely. **Do not** introduce a new global class for a one-off.

If you find yourself writing the same inline-style block twice, hoist it
to a small component (e.g. a `<TimelineRow>`-style sub-component), not to
a new CSS rule.

### What not to use

- **No PatternFly.** It was removed in the 2026-05-02 decision.
- **No Tailwind.** Conflicts with the legacy theme.
- **No CSS Modules / styled-components / emotion.** One styling system.
- **No `pf-v6-u-*` utility classes.** They're not loaded.
- **No emojis in UI strings** unless the legacy module had them. Use the
  inline SVG icons in `Sidebar.tsx` or status glyphs the legacy uses.

---

## Components

- Named exports only: `export function MyComponent(...)`. Don't use
  `export default`.
- Props: define an `interface Props { ... }` (or named, e.g.
  `interface NewDeploymentModalProps`) right above the component. Inline
  type literals are fine for small components but the named interface
  scales better.
- One concern per component. If a function is more than ~150 lines and
  has nested local components, split them into siblings in the same file
  or break out to `helpers.ts`.
- Keep state colocated with the component that owns it. Lift to App
  level only when two siblings genuinely need to coordinate.
- No `React.FC`. No class components. No HOCs.

### Modals

Use `<Modal isOpen onClose title size?>` from `@/components/Modal`. Do
not build a new modal primitive. `size="large"` for detail/correlation
modals; default for create/edit forms.

### Confirm dialogs

`window.confirm()` (or just `confirm()`) is the current pattern for
destructive/expensive actions. See
`DeploymentDetailModal.tsx:99-106` for the canonical shape. Replace
with a real dialog only if a module specifically needs richer copy.

### Conditional rendering

Use early returns for loading / error / empty states. Don't nest the
happy path inside ternaries:

```tsx
if (query.isPending) return <p className="text-muted">Loading…</p>;
if (query.error) return <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>;
if (!query.data?.length) return <div className="empty-state">…</div>;
return <Table data={query.data} />;
```

---

## Forms

- Plain `useState` + native HTML elements. No form library.
- Submit handler: `(e: FormEvent) => { e.preventDefault(); ... }`.
- Use `useMutation` for submission; surface errors via `alert()` (matches
  legacy) or inline error text. Disable the submit button while pending.
- Required fields: rely on the native `required` attribute and the
  browser's validation. Add explicit checks before mutation only if the
  rule isn't expressible in HTML.

If you build a complex multi-step form, that's the moment to discuss
adding `react-hook-form` - but not before.

---

## Routing

- Routes live in `App.tsx`'s `<Routes>` block. Add the page import at the
  top, the route in the block, and a label entry to `BREADCRUMBS`.
- Sidebar entries live in `components/Sidebar.tsx`. Each nav item has:
  - `to` - the route path
  - `feature` - backend feature key for per-user gating
  - `visKey` - admin-side visibility key (groups multiple entries
    together when both halves of a legacy module are split)
- Use `useNavigate()` for programmatic navigation. Don't `window.location.assign`
  unless you specifically need a full page reload (e.g. session expiry).

---

## Error handling

- Network / HTTP errors surface as `ApiError` from `apiRequest`. Pages
  read `(query.error as Error).message` for display.
- For mutations, the legacy convention is `alert((e as Error).message)`
  in the `onError` callback. Match it; don't invent a toast system
  per-page.
- Don't add try/catch around `apiRequest` calls in components - let the
  query/mutation surface the error so React Query can track loading
  state correctly.
- Don't show server-internal error messages verbatim. The backend
  already returns generic messages by design (see AGENTS.md); display
  them as-is.

---

## Comments

Default to no comments. Identifiers should explain *what*. Comments are
for the *why* when it isn't obvious - a backend quirk, a workaround for
a specific bug, a non-obvious invariant. See `client.ts` (CSRF, 401
handling) and `useAuthStatus` (CSRF caching) for the bar.

Don't write headers like `// ── Types ──`. They're legacy from a couple
of early files and we're not adding more.

Never reference task numbers, PRs, or "ported from" comments. The git
log is for that.

---

## Naming

| Thing | Convention | Example |
|---|---|---|
| Component file | PascalCase | `DeploymentDetailModal.tsx` |
| Hook file | camelCase | `riskAnalysis.ts`, `usePerformanceMode.ts` |
| Helper file | lowercase / camelCase | `helpers.ts`, `client.ts` |
| Component name | PascalCase | `DeploymentRow` |
| Hook name | starts with `use` | `useDeployments`, `useCreateDeployment` |
| Boolean prop / var | `isX`, `hasX`, `canX` | `isOpen`, `hasErrors`, `canExecute` |
| Event handler prop | `onX` | `onClose`, `onExecuted`, `onShowCorrelation` |
| Internal handler | `handleX` | `handleSubmit`, `handleExecute` |
| Constant | `SCREAMING_SNAKE_CASE` | `MUTATION_METHODS`, `BREADCRUMBS` |

---

## Testing (status: in progress)

E2E tests with **Playwright** live at `tests/e2e/` (repo root, not
under `frontend/`). They run against a real backend so they cover both
React and any remaining legacy pages. See `tests/e2e/README.md` for how
to run them locally and add a new spec.

Component-level Vitest tests are *not* required on new ports yet, but
write them when you're touching tricky pure logic (status maps, filter
predicates, time formatters in `helpers.ts`). Co-locate as
`<thing>.test.ts` next to the source.

---

## Building & verifying changes

Local checks before pushing:

```
cd netcontrol/static/frontend
npm run typecheck     # tsc --noEmit
npm run build         # tsc --noEmit && vite build
```

If your change touches a UI surface, also run the dev server and click
through the affected flow:

```
npm run dev            # vite, port 5173, proxies /api to PLEXUS_BACKEND_URL
```

The dev server expects a backend at `http://127.0.0.1:8080` by default.
Override with `PLEXUS_BACKEND_URL=...`.

---

## Anti-patterns

Things to actively avoid. If you see these in a PR, push back:

- Direct `fetch()` calls in components.
- `useEffect` to fetch data - that's what TanStack Query is for.
- New global state stores. We don't have one yet, and we shouldn't add
  one without a real cross-page need.
- New CSS files. Reuse legacy classes; inline-style for one-offs.
- "Just for now" `any` types.
- Class components / HOCs / `React.FC`.
- `export default`. Named exports only.
- Comments narrating what the next line of code does.
- New dependencies without a decision-log entry.
- Re-implementing a hook that already exists in another `api/` module -
  share the cache instead.
- `dangerouslySetInnerHTML`.
- Direct DOM manipulation (`document.getElementById`, `.innerHTML =`).
- `console.log` in committed code (`console.warn` / `console.error`
  for real signals only).
- `setTimeout` / `setInterval` outside hooks with proper cleanup.

---

## When in doubt

1. Look at a recent module port (Deployments, Risk Analysis, Compliance)
   for the canonical shape.
2. Match what's there.
3. If the situation genuinely doesn't fit the existing pattern, raise it
   in the PR description and add a decision-log entry once it's settled.

---

## Changelog

Append a one-liner each time you change a rule here.

- 2026-05-07 - Replaced the original aspirational draft with a
  retrofit grounded in 8 already-migrated modules (network-tools through
  deployments). Removed PatternFly / Zustand / react-hook-form / zod /
  date-fns prescriptions that didn't match the shipped code; added the
  legacy-CSS rule, modal/confirm/form patterns actually in use, and the
  `apiRequest` + WebSocket conventions from `client.ts` and the
  Deployments port.
