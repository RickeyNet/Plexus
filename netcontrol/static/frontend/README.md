# Plexus React Frontend

Phase 1.1 of [FRONTEND_MIGRATION.md](../../../FRONTEND_MIGRATION.md). This
folder houses the new React + TypeScript + PatternFly app that will, page by
page, replace the vanilla JS in `netcontrol/static/js/`.

Today this is a Hello World — proves the build pipeline, dev proxy, FastAPI
mount, TanStack Query wiring, and PatternFly styling all work end-to-end.

## Stack

| Concern        | Choice                              |
| -------------- | ----------------------------------- |
| Framework      | React 18 (StrictMode)               |
| Language       | TypeScript (strict)                 |
| Build          | Vite                                |
| Routing        | react-router-dom v6                 |
| Server state   | TanStack Query                      |
| UI components  | PatternFly 6                        |
| Forms          | react-hook-form + zod (added later) |
| Client state   | zustand (added later)               |

## Develop

Two terminals.

```powershell
# Terminal 1 — FastAPI backend
$env:APP_ENV = "dev"
python templates/run.py --host 127.0.0.1 --port 8080
```

```powershell
# Terminal 2 — Vite dev server (HMR)
cd netcontrol/static/frontend
npm install   # one-time
npm run dev   # http://localhost:5173/frontend/
```

Vite proxies `/api` and `/static` to `127.0.0.1:8080`, so cookie-based session
auth works without CORS gymnastics. Log in via the legacy SPA (`/`) once; the
session cookie is shared with the React app.

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
│   ├── App.tsx            # PatternFly Page shell + routes
│   ├── api/
│   │   ├── client.ts      # fetch wrapper, CSRF, errors
│   │   └── auth.ts        # useAuthStatus()
│   └── pages/
│       └── Home.tsx       # Hello-world / connectivity check
└── README.md
```

## Conventions

See [`FRONTEND_STYLE.md`](../../../FRONTEND_STYLE.md) at the repo root —
this app must follow it on every PR.
