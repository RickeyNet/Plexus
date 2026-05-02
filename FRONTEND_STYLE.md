# Frontend Style Guide

Rules for the Plexus React frontend. **Reference this file in every AI prompt that writes or modifies frontend code.** Without this, AI-generated code drifts across sessions and the codebase ends up with three frameworks-within-React.

This is a living document. Add to it when a new pattern emerges; correct it when a rule turns out wrong.

---

## Core Stack

| Concern | Tool | Don't use |
|---|---|---|
| Framework | React 18 | Preact, Solid |
| Language | TypeScript (strict) | Plain JavaScript |
| Build | Vite | Webpack, Next.js, Remix |
| Server state | TanStack Query (React Query) v5 | Redux + thunks, SWR, raw fetch in components |
| Client state | Zustand | Redux, MobX, Recoil, Context for global state |
| Routing | React Router v6 | TanStack Router, custom hash routing |
| Forms | React Hook Form + Zod schemas | Formik, raw `<form>` with useState |
| Component library | PatternFly v5 | Material UI, Chakra, Ant Design, custom components |
| Tables | PatternFly Table | TanStack Table standalone, custom |
| Charts | ECharts (existing) | Chart.js, Recharts |
| Icons | `@patternfly/react-icons` | FontAwesome, Heroicons |
| Code editor | CodeMirror 6 | Monaco, custom textarea |
| HTTP client | `fetch` wrapped in TanStack Query | axios |
| Dates | `date-fns` | Moment.js, day.js |
| Testing (unit/component) | Vitest + React Testing Library | Jest, Enzyme |
| Testing (E2E) | Playwright | Cypress, Selenium |
| Lint | ESLint + typescript-eslint + react-hooks plugin | TSLint |
| Format | Prettier | None |

---

## Directory Structure

```
netcontrol/static/frontend/src/
├── pages/                      # One folder per top-level route
│   ├── Inventory/
│   │   ├── InventoryPage.tsx       # Route component
│   │   ├── InventoryPage.test.tsx
│   │   ├── GroupList.tsx
│   │   ├── GroupList.test.tsx
│   │   ├── HostTable.tsx
│   │   └── index.ts                # Re-exports for clean imports
│   └── ...
├── components/                 # Shared, reusable components
│   ├── ConfirmDialog/
│   ├── ErrorBoundary/
│   └── PageHeader/
├── api/                        # TanStack Query hooks, one file per resource
│   ├── inventory.ts            # useGroups, useGroup, useCreateGroup, ...
│   ├── jobs.ts
│   ├── client.ts               # The base fetch wrapper
│   └── queryKeys.ts            # Centralized query key factory
├── stores/                     # Zustand stores, one per domain
│   ├── ui.ts                   # Toasts, modals, sidebar state
│   ├── auth.ts                 # Current user, session
│   └── preferences.ts          # User preferences, view settings
├── types/                      # Shared TypeScript types
│   ├── api.ts                  # Generated or hand-written API response types
│   └── domain.ts               # Domain types (Group, Host, Job, etc.)
├── lib/                        # Pure utility functions
│   ├── format.ts               # formatBytes, formatDuration, etc.
│   └── validation.ts           # Zod schemas
├── hooks/                      # Reusable hooks (non-API)
│   ├── useDebounce.ts
│   └── useWebSocket.ts
├── App.tsx                     # Router + providers
└── main.tsx                    # Entry point
```

### Rules

- **One component per file.** Filename matches component name in PascalCase.
- **Co-locate tests.** `Foo.tsx` and `Foo.test.tsx` live side by side.
- **Co-locate styles.** If a component needs custom CSS, `Foo.tsx` and `Foo.module.css` live side by side. Prefer PatternFly utilities over custom CSS.
- **No deeply nested folders.** Two levels max under `pages/` (e.g., `pages/Inventory/components/`).
- **Imports use the `@/` alias** (configured in `vite.config.ts` and `tsconfig.json`). Never `../../../` relative imports.

---

## TypeScript

### Strict mode is non-negotiable

`tsconfig.json` must have:

```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "exactOptionalPropertyTypes": true
  }
}
```

### Type rules

- **No `any`.** If you need an escape hatch, use `unknown` and narrow with type guards. The only exception is interop with untyped third-party code, and even there, wrap it in a typed module immediately.
- **No type assertions (`as`)** except in tests or when narrowing `unknown`. If you find yourself writing `value as Foo`, the type is wrong upstream.
- **Prefer `type` over `interface`** unless you need declaration merging. Consistency beats either-or debates.
- **Discriminated unions over boolean flags.** `type Job = { status: 'pending' } | { status: 'running'; startedAt: string } | { status: 'complete'; result: string }` beats `{ pending?: boolean; running?: boolean; ... }`.
- **Branded types for IDs** when they're easy to confuse: `type GroupId = number & { readonly __brand: 'GroupId' }`. Prevents passing a host ID where a group ID is expected.

### Server response types

Hand-write types in `src/types/api.ts` matching the FastAPI response shapes. These are the source of truth for the React app.

```ts
// src/types/api.ts
export type Group = {
  id: number;
  name: string;
  description: string | null;
  host_count: number;
  created_at: string;  // ISO 8601
};

export type Host = {
  id: number;
  group_id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
};
```

When the backend changes a response shape, **update the type first**, then let TypeScript point to every component that needs adjustment. This is the workflow that catches refactor bugs.

---

## Server State (TanStack Query)

### Rule: never call `fetch` directly in a component

All server state goes through TanStack Query hooks in `src/api/`. Components import hooks, never the underlying fetch.

### Query keys are centralized

```ts
// src/api/queryKeys.ts
export const queryKeys = {
  groups: {
    all: ['groups'] as const,
    list: (filters?: GroupFilters) => ['groups', 'list', filters] as const,
    detail: (id: GroupId) => ['groups', 'detail', id] as const,
  },
  hosts: {
    all: ['hosts'] as const,
    byGroup: (groupId: GroupId) => ['hosts', 'byGroup', groupId] as const,
  },
  // ...
};
```

This makes invalidation predictable and grep-able.

### Hook naming

- `useThing()` / `useThings()` for queries
- `useCreateThing()`, `useUpdateThing()`, `useDeleteThing()` for mutations
- One file per resource: `src/api/inventory.ts`, `src/api/jobs.ts`

### Example hook

```ts
// src/api/inventory.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './queryKeys';
import { client } from './client';
import type { Group, GroupId } from '@/types/api';

export function useGroups() {
  return useQuery({
    queryKey: queryKeys.groups.list(),
    queryFn: () => client.get<Group[]>('/api/inventory'),
  });
}

export function useGroup(id: GroupId) {
  return useQuery({
    queryKey: queryKeys.groups.detail(id),
    queryFn: () => client.get<Group>(`/api/inventory/${id}`),
    enabled: id != null,
  });
}

export function useCreateGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string; description?: string }) =>
      client.post<Group>('/api/inventory', input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.groups.all });
    },
  });
}
```

### Mutation rules

- **Always invalidate affected queries on success.** Don't manually mutate cache except for optimistic updates.
- **For optimistic updates, use `onMutate` / `onError` / `onSettled`** as a triple. Don't half-implement optimism.
- **Mutations return data; components handle UI feedback** (toasts, navigation, modal close) via `onSuccess` callbacks at the call site, not inside the hook.

### Cache settings

Defaults at the QueryClient level:

```ts
new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,        // 30s — data is fresh
      gcTime: 5 * 60_000,       // 5min — kept in cache after unmount
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        // Don't retry 4xx
        if (error instanceof HttpError && error.status >= 400 && error.status < 500) return false;
        return failureCount < 3;
      },
    },
  },
});
```

Override per-query when needed (e.g., `staleTime: Infinity` for truly immutable data, `refetchInterval: 5000` for polling).

---

## Client State (Zustand)

### Rule: Zustand is for UI state only

Server data lives in TanStack Query. Zustand stores hold:
- Toast/notification queue
- Modal open/close state (when global)
- Current user / session info
- User preferences (theme, table density, sidebar collapsed)
- Cross-page UI state (selected items, filters that should persist across navigation)

If it can be derived from a server response, it does not go in Zustand.

### One store per domain

```ts
// src/stores/ui.ts
import { create } from 'zustand';

type Toast = { id: string; level: 'success' | 'error' | 'info'; message: string };

type UIStore = {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, 'id'>) => void;
  dismissToast: (id: string) => void;
};

export const useUIStore = create<UIStore>((set) => ({
  toasts: [],
  addToast: (toast) => set((s) => ({
    toasts: [...s.toasts, { ...toast, id: crypto.randomUUID() }],
  })),
  dismissToast: (id) => set((s) => ({
    toasts: s.toasts.filter((t) => t.id !== id),
  })),
}));
```

### Selectors

Subscribe to the smallest slice you need. This avoids unnecessary re-renders.

```ts
// Good
const toasts = useUIStore((s) => s.toasts);
const addToast = useUIStore((s) => s.addToast);

// Bad — re-renders on every state change
const { toasts, addToast } = useUIStore();
```

---

## Components

### Function components only

No class components. No `React.FC` (it adds children implicitly, which is wrong more often than right).

```tsx
// Good
type GroupCardProps = {
  group: Group;
  onSelect: (id: GroupId) => void;
};

export function GroupCard({ group, onSelect }: GroupCardProps) {
  return <Card>...</Card>;
}

// Bad
const GroupCard: React.FC<GroupCardProps> = ({ group, onSelect }) => { ... };
```

### Props rules

- **Required by default; optional only when truly optional.** Don't make props optional to avoid passing them.
- **No prop drilling beyond 2 levels.** If a prop crosses 3+ components, it belongs in a Zustand store or React Context.
- **Booleans default to `false`.** Use positive names: `isLoading`, `disabled`, `expanded`. Avoid `notReady`, `hidden` (use `visible` instead).
- **Event handlers are named `onX`** (`onSelect`, `onSubmit`, `onCancel`).

### Component size

- If a component file is over **300 lines**, split it.
- If a function inside a component is over **30 lines**, extract it.
- If a component has more than **5 useState calls**, consider `useReducer` or a Zustand store.

### Hooks rules

- **Custom hooks live in `src/hooks/` or `src/api/`.** Component files don't define reusable hooks.
- **Always include exhaustive dependencies in `useEffect` / `useMemo` / `useCallback`.** ESLint enforces this; don't disable the rule.
- **Avoid `useEffect` for derived state.** Compute it during render.

```tsx
// Bad
const [fullName, setFullName] = useState('');
useEffect(() => setFullName(`${firstName} ${lastName}`), [firstName, lastName]);

// Good
const fullName = `${firstName} ${lastName}`;
```

### Conditional rendering

- **Use early returns for loading/error/empty states.** Don't nest the happy path inside ternaries.

```tsx
// Good
if (query.isLoading) return <Skeleton />;
if (query.isError) return <ErrorState error={query.error} />;
if (!query.data?.length) return <EmptyState />;
return <Table data={query.data} />;

// Bad
return query.isLoading
  ? <Skeleton />
  : query.isError
    ? <ErrorState />
    : !query.data?.length
      ? <EmptyState />
      : <Table data={query.data} />;
```

---

## PatternFly Usage

### Always reach for PatternFly first

Before writing custom UI, search the [PatternFly catalog](https://www.patternfly.org/components/all-components). It almost certainly has what you need.

Most-used components (memorize these):

| Need | PatternFly component |
|---|---|
| Page layout | `Page`, `PageSection`, `PageSidebar` |
| Header above content | `PageGroup` + custom header div, or `Toolbar` |
| Table | `Table`, `Thead`, `Tr`, `Td` from `@patternfly/react-table` |
| Form | `Form`, `FormGroup`, `TextInput`, `Select`, `Checkbox` |
| Buttons | `Button` (variants: `primary`, `secondary`, `danger`, `link`) |
| Modal | `Modal`, `ModalVariant.small/medium/large` |
| Toast | `AlertGroup`, `Alert`, `AlertActionCloseButton` |
| Confirm dialog | `Modal` with action buttons; or wrap in `<ConfirmDialog>` from `@/components` |
| Loading skeleton | `Skeleton`, or feature-specific empty state |
| Empty state | `EmptyState`, `EmptyStateBody`, `EmptyStateActions` |
| Tabs | `Tabs`, `Tab`, `TabTitleText` |
| Cards | `Card`, `CardHeader`, `CardBody`, `CardFooter` |
| Tooltip | `Tooltip` |
| Icon | from `@patternfly/react-icons` |

### Don't customize PatternFly visually

- **No CSS overrides on PatternFly classes.** If you need a different look, you're using the wrong component.
- **Use PatternFly utility classes** (`pf-v5-u-mt-md`, `pf-v5-u-text-align-center`) for spacing/alignment instead of custom CSS.
- **Custom CSS only when PatternFly has no equivalent.** Use CSS Modules (`Foo.module.css`) — never global CSS.

### Forms

Always use React Hook Form + Zod schemas. PatternFly form components plug in via `Controller`.

```tsx
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Form, FormGroup, TextInput, Button } from '@patternfly/react-core';

const schema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  description: z.string().max(500).optional(),
});

type FormValues = z.infer<typeof schema>;

export function CreateGroupForm({ onSubmit }: { onSubmit: (v: FormValues) => void }) {
  const { control, handleSubmit, formState: { errors, isSubmitting } } =
    useForm<FormValues>({ resolver: zodResolver(schema) });

  return (
    <Form onSubmit={handleSubmit(onSubmit)}>
      <FormGroup label="Name" isRequired fieldId="name"
        helperTextInvalid={errors.name?.message}
        validated={errors.name ? 'error' : 'default'}>
        <Controller name="name" control={control} render={({ field }) =>
          <TextInput {...field} id="name" />
        }/>
      </FormGroup>
      {/* ... */}
      <Button type="submit" variant="primary" isLoading={isSubmitting}>
        Create
      </Button>
    </Form>
  );
}
```

---

## Forms and Validation

- **Schema-first.** Define a Zod schema, derive the TypeScript type from it. The schema is the single source of truth for shape and validation.
- **Validate on submit, not on every keystroke** unless the field has expensive async validation (uniqueness check). The PatternFly defaults handle this.
- **Server errors are mapped back to fields** when possible. Display field-level errors via `setError(fieldName, { message })`.
- **Don't bypass the form for "just a quick text input."** It's never just one field. Use the form library from the start.

---

## API Calls

### The base client

```ts
// src/api/client.ts
class HttpError extends Error {
  constructor(public status: number, public body: unknown) {
    super(`HTTP ${status}`);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': getCsrfToken(),
    },
    credentials: 'same-origin',
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new HttpError(res.status, errorBody);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const client = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
};
```

### Rules

- **CSRF token is included automatically.** Never bypass it.
- **Errors are thrown, not returned.** TanStack Query handles them via `error` state.
- **No retry logic in the client.** TanStack Query handles retries.
- **No global interceptors that mutate auth state.** If a 401 comes back, the calling code redirects to login. Don't hide redirects in middleware.

---

## WebSockets and Streaming

The Plexus app has live job output, topology updates, and monitoring streams. Pattern:

### A typed WebSocket hook

```ts
// src/hooks/useJobStream.ts
type JobEvent =
  | { type: 'log'; level: 'info' | 'warning' | 'error'; message: string; host?: string }
  | { type: 'job_complete'; status: 'success' | 'failed' };

export function useJobStream(jobId: number, onEvent: (e: JobEvent) => void) {
  useEffect(() => {
    const ws = new WebSocket(`/ws/jobs/${jobId}`);
    ws.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as JobEvent;
      onEvent(event);
    };
    return () => ws.close();
  }, [jobId, onEvent]);
}
```

### Rules

- **WebSocket lifecycle is owned by the component that needs the data.** No singleton ws connections.
- **Events have discriminated-union types.** Never `any` for event payloads.
- **Reconnection logic is explicit.** Use exponential backoff, cap at 30s, surface "disconnected" state to the user.
- **For high-frequency streams (job logs), buffer updates** before re-rendering. Re-rendering on every message kills the browser.

---

## Error Handling

### Three layers

1. **Per-query errors** — TanStack Query's `error` state, displayed inline.
2. **Per-route errors** — `<ErrorBoundary>` at each route, catches render exceptions.
3. **Global errors** — top-level `<ErrorBoundary>` in `App.tsx`, catches everything else.

```tsx
// src/App.tsx
<ErrorBoundary fallback={<GlobalErrorPage />}>
  <Routes>
    <Route path="inventory" element={
      <ErrorBoundary fallback={<RouteErrorState />}>
        <InventoryPage />
      </ErrorBoundary>
    }/>
  </Routes>
</ErrorBoundary>
```

### User-facing error rules

- **Never show a stack trace to a user.** Show "Something went wrong" + a "Reload" button, log details to console + Sentry.
- **Never show server-internal error messages verbatim.** The backend returns generic messages by design ([AGENTS.md](AGENTS.md#L25)). Match that on the frontend.
- **Validation errors map to field-level UI.** Don't show "request failed" when the real issue is "name is too long."

---

## Routing

- **React Router v6, file-by-file route definitions in `App.tsx`.**
- **One route per page component.**
- **Lazy-load route components** with `React.lazy()` to keep initial bundle small.
- **No nested routers.** Flat route table.

```tsx
const InventoryPage = lazy(() => import('@/pages/Inventory/InventoryPage'));

<Routes>
  <Route path="/" element={<Layout />}>
    <Route index element={<Dashboard />} />
    <Route path="inventory" element={<InventoryPage />} />
    <Route path="inventory/:groupId" element={<GroupDetail />} />
    {/* ... */}
  </Route>
</Routes>
```

---

## Testing

### Unit + component tests (Vitest + RTL)

- **Every component has a test file.** No exceptions.
- **Test behavior, not implementation.** Query by accessible role/label, not by class name or test-id (unless absolutely necessary).
- **Mock at the query-hook level** — use `QueryClient` with seeded data, don't mock `fetch` directly.

```tsx
// GroupCard.test.tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { GroupCard } from './GroupCard';

test('calls onSelect with group id when clicked', async () => {
  const onSelect = vi.fn();
  render(<GroupCard group={fakeGroup} onSelect={onSelect} />);
  await userEvent.click(screen.getByRole('button', { name: /core switches/i }));
  expect(onSelect).toHaveBeenCalledWith(fakeGroup.id);
});
```

### E2E tests (Playwright)

- **Live in `tests/e2e/` at repo root, not under `frontend/`.** They test the full app, not just the React part.
- **Run against a real backend** in CI (Docker compose).
- **One spec file per major user flow.** Happy path + 1-2 critical edge cases.
- **Don't test UI details** (button colors, spacing). Test outcomes.

### Coverage targets

- Unit/component: ≥60% lines in `src/`
- E2E: every major user flow covered

---

## Performance

### Defaults that matter

- **Lazy-load every route** with `React.lazy`.
- **Memoize expensive renders** with `useMemo` / `React.memo` only after measuring. Don't pre-optimize.
- **Use PatternFly's virtualized table** for lists over 100 rows.
- **Debounce text-input filters** (300ms typical) before triggering queries.

### Bundle size

- **Watch the main bundle.** Target: under 1MB gzipped.
- **Use dynamic imports** for rarely-used heavy components (chart libraries, code editor, topology graph).
- **Don't import whole libraries** — `import { format } from 'date-fns'` not `import * as df from 'date-fns'`.

---

## Accessibility

- **All interactive elements are keyboard-reachable.** Test with Tab, Shift-Tab, Enter, Space.
- **Labels are real `<label>` elements** (or `aria-label` for icon-only buttons).
- **Focus management on modals.** PatternFly handles this if used correctly.
- **Color is never the only signal.** Status indicators have icons or text in addition to color.
- **Run axe-core** in dev (`@axe-core/react`) and fail CI on new violations.

---

## Naming Conventions

| Thing | Convention | Example |
|---|---|---|
| Component file | PascalCase | `GroupCard.tsx` |
| Hook file | camelCase, starts with `use` | `useGroups.ts` |
| Type file | camelCase | `api.ts`, `domain.ts` |
| Util file | camelCase | `format.ts` |
| Component name | PascalCase | `GroupCard` |
| Hook name | `useThing` | `useGroups`, `useDebounce` |
| Boolean variable | `isX` / `hasX` / `canX` | `isLoading`, `hasErrors`, `canEdit` |
| Event handler prop | `onX` | `onSelect`, `onSubmit` |
| Event handler internal | `handleX` | `handleClick`, `handleSubmit` |
| Constant | `SCREAMING_SNAKE_CASE` | `MAX_RETRIES`, `DEFAULT_PAGE_SIZE` |

---

## What NOT to do

A non-exhaustive list of patterns that should never appear in this codebase:

- `dangerouslySetInnerHTML` — there is no legitimate use case in Plexus
- `any` type
- `// @ts-ignore` / `// @ts-expect-error` without a comment explaining why
- `eslint-disable-next-line` without a comment explaining why
- Direct DOM manipulation (`document.getElementById`, `.innerHTML =`)
- `useState` for server data
- `useEffect` to fetch on mount (use TanStack Query)
- Inline styles (`style={{...}}`) except for dynamic values that can't be expressed in CSS
- `console.log` in committed code (use `console.warn`/`error` for real signals only)
- Class components
- HOCs (higher-order components) — use hooks
- Prop drilling more than 2 levels
- Global mutable variables outside Zustand stores
- `setTimeout`/`setInterval` outside hooks with proper cleanup
- Mixing PatternFly with another component library
- Custom modal/toast/dialog implementations when PatternFly has them

---

## When This Document Is Wrong

If a rule here causes more pain than it prevents, **update the rule** in a PR. Don't work around it silently.

If a rule isn't covered:
1. Check what existing components in `src/` do, and follow that pattern.
2. If no existing pattern, choose deliberately and add the rule here in the same PR.

The goal is consistency. A consistent codebase that's slightly suboptimal beats an inconsistent codebase that's locally optimal in each file.
