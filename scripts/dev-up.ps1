# One-command local dev loop for Plexus on Windows (PowerShell 5.1 or 7).
#
#   .\scripts\dev-up.ps1               # Postgres + backend (--reload) + Vite
#   .\scripts\dev-up.ps1 -Port 8081    # backend on another port (8080 busy)
#   .\scripts\dev-up.ps1 -NoFrontend   # skip the Vite window
#   .\scripts\dev-up.ps1 -NoBackend    # skip the uvicorn window
#
# What it does, in order:
#   1. Checks Docker is reachable.
#   2. Starts the dev Postgres (docker-compose.dev.yml publishes it on
#      127.0.0.1:5432) and waits for its healthcheck.
#   3. Dot-sources scripts\dev-env.ps1 (APP_DB_ENGINE / APP_ENV /
#      APP_DATABASE_URL, activates .venv).
#   4. Runs `npm ci` once if node_modules is missing.
#   5. Opens one window running `python templates/run.py --reload` and one
#      running `npm run dev`, both inheriting the env from step 3.
#
# This is the "app from source" loop from DEVSETUP.md: no image build, Python
# hot-reloads on save and Vite serves the React app with HMR at
# http://localhost:5173/. Close the two windows (or Ctrl+C in each) to stop;
# Postgres keeps running until `docker compose stop postgres`.

[CmdletBinding()]
param(
    [int]$Port = 8080,
    [switch]$NoFrontend,
    [switch]$NoBackend,
    [int]$PostgresTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# 1. Docker reachable?
Write-Step "Checking Docker"
$null = & docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker daemon not reachable. Start Docker Desktop (or install it: winget install -e --id Docker.DockerDesktop) and re-run."
    return
}

# 2. Dev Postgres
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.env') -PathType Leaf)) {
    Write-Error ".env not found. Run deploy/setup.sh once from Git Bash (see DEVSETUP.md) to create it."
    return
}
Write-Step "Starting dev Postgres (127.0.0.1:5432)"
& docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
if ($LASTEXITCODE -ne 0) { Write-Error "docker compose up postgres failed"; return }

$deadline = (Get-Date).AddSeconds($PostgresTimeoutSeconds)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    $status = (& docker inspect --format '{{.State.Health.Status}}' plexus-postgres 2>$null)
    if ($status -eq 'healthy') { $healthy = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $healthy) {
    Write-Error "plexus-postgres did not report healthy within ${PostgresTimeoutSeconds}s. Check: docker compose logs postgres"
    return
}
Write-Host "    postgres healthy"

# 3. Env + venv for this session (and for the child windows, which inherit it)
Write-Step "Loading dev environment"
. (Join-Path $repoRoot 'scripts\dev-env.ps1')
if (-not $env:APP_DATABASE_URL) { return }   # dev-env.ps1 already printed the error

if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.venv\Scripts\python.exe') -PathType Leaf)) {
    Write-Error ".venv not found. Create it first (DEVSETUP.md, 'Windows: Docker Desktop + Windows venv')."
    return
}

# 4. Frontend deps
$frontendDir = Join-Path $repoRoot 'netcontrol\static\frontend'
if (-not $NoFrontend -and -not (Test-Path -LiteralPath (Join-Path $frontendDir 'node_modules') -PathType Container)) {
    Write-Step "node_modules missing - running npm ci"
    Push-Location $frontendDir
    try { & npm ci } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Write-Error "npm ci failed"; return }
}

# 5. Launch windows. Use the same PowerShell executable this script runs under.
$shell = (Get-Process -Id $PID).Path
$env:PLEXUS_BACKEND_URL = "http://127.0.0.1:$Port"

if (-not $NoBackend) {
    Write-Step "Opening backend window (uvicorn --reload on :$Port)"
    $backendCmd = "Set-Location '$repoRoot'; `$Host.UI.RawUI.WindowTitle = 'Plexus backend :$Port'; python templates/run.py --reload --port $Port"
    Start-Process -FilePath $shell -ArgumentList '-NoExit', '-Command', $backendCmd | Out-Null
}

if (-not $NoFrontend) {
    Write-Step "Opening Vite window (http://localhost:5173/)"
    $frontendCmd = "Set-Location '$frontendDir'; `$Host.UI.RawUI.WindowTitle = 'Plexus vite'; npm run dev"
    Start-Process -FilePath $shell -ArgumentList '-NoExit', '-Command', $frontendCmd | Out-Null
}

Write-Host ""
Write-Host "Plexus dev loop is up:" -ForegroundColor Green
if (-not $NoFrontend) { Write-Host "  UI (HMR):   http://localhost:5173/   (login admin / netcontrol under APP_ENV=dev)" }
if (-not $NoBackend)  { Write-Host "  API:        http://127.0.0.1:$Port/api/health" }
Write-Host "  Postgres:   127.0.0.1:5432  (docker compose stop postgres  to stop)"
Write-Host "  Checks:     .\scripts\check.ps1 -Tests tests\test_foo.py"
