# Plexus React Frontend

The Plexus UI - a React + TypeScript SPA that replaced the legacy vanilla-JS
frontend (migration history in
[FRONTEND_MIGRATION.md](../../../FRONTEND_MIGRATION.md)). The legacy
`netcontrol/static/js/` modules have been deleted; this app is the only
frontend.

## Stack

| Concern        | Choice                                                  |
| -------------- | ------------------------------------------------------- |
| Framework      | React 19 (StrictMode)                                   |
| Language       | TypeScript (strict)                                     |
| Build          | Vite                                                    |
| Routing        | react-router-dom v7 (`basename="/frontend"`)            |
| Server state   | TanStack Query v5                                       |
| Styling        | Legacy stylesheet `/static/css/style.css` (no PatternFly) |
| Charts         | ECharts (`src/lib/echart.tsx`)                          |
| Topology       | vis-network                                             |
| Code editor    | CodeMirror 6 (`@uiw/react-codemirror`)                  |
| Unit tests     | Vitest                                                  |

## Develop

Two terminals.

```powershell
# Terminal 1 - FastAPI backend
$env:APP_ENV = "dev"
python templates/run.py --host 127.0.0.1 --port 8080
```

```powershell
# Terminal 2 - Vite dev server (HMR)
cd netcontrol/static/frontend
npm install   # one-time
npm run dev   # http://localhost:5173/frontend/
```

Vite proxies `/api` and `/static` to `127.0.0.1:8080`, so cookie-based session
auth works without CORS gymnastics.

Override the proxy target with `PLEXUS_BACKEND_URL` if the backend runs
elsewhere.

## Build (production-style)

```powershell
cd netcontrol/static/frontend
npm install
npm run build
```

Outputs `dist/` which FastAPI serves at `/frontend/` (configured in
`netcontrol/app.py`). Browse to `http://127.0.0.1:8080/frontend/`.

## Layout

```
netcontrol/static/frontend/
├── index.html
├── package.json
├── tsconfig.json
├── tsconfig.node.json
├── vite.config.ts
├── src/
│   ├── main.tsx           # entry; QueryClientProvider + Router
│   ├── App.tsx            # app shell (nav sidebar) + routes
│   ├── api/               # TanStack Query hooks (client.ts = fetch wrapper, CSRF, errors)
│   ├── components/        # shared components (modals, dialogs, panels)
│   ├── lib/               # ECharts wrapper, utilities
│   └── pages/             # one folder per page (Inventory, Jobs, Topology, ...)
└── README.md
```

## Conventions

See [`FRONTEND_STYLE.md`](../../../FRONTEND_STYLE.md) at the repo root -
this app must follow it on every PR.
