# Run the same checks CI runs (.github/workflows/ci.yml), locally, before
# pushing. PowerShell 5.1 or 7, from anywhere inside the repo.
#
#   .\scripts\check.ps1                                  # ruff + mypy + eslint + tsc + vitest
#   .\scripts\check.ps1 -Tests tests\test_foo.py         # ...plus targeted pytest files
#   .\scripts\check.ps1 -Tests tests\test_a.py,tests\test_b.py
#   .\scripts\check.ps1 -SkipFrontend                    # Python side only
#   .\scripts\check.ps1 -SkipPython                      # frontend side only
#   .\scripts\check.ps1 -Build                           # also `npm run build` (what the Docker image runs)
#
# Every check runs even if an earlier one fails; a summary table prints at
# the end and the exit code is 1 if anything failed. pytest needs the dev
# Postgres (scripts\dev-up.ps1 starts it): the suite runs against a
# throwaway `plexus_test` database derived from .env, created on first use.
# Pass specific files - the full suite takes ~14 min and belongs in CI.

[CmdletBinding()]
param(
    [string[]]$Tests = @(),
    [switch]$SkipPython,
    [switch]$SkipFrontend,
    [switch]$Build
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$frontendDir = Join-Path $repoRoot 'netcontrol\static\frontend'
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'

$results = New-Object System.Collections.Generic.List[object]

function Invoke-Check {
    param(
        [string]$Name,
        [string]$Dir,
        [scriptblock]$Command
    )
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $Dir
    try {
        $global:LASTEXITCODE = 0
        & $Command
        $ok = ($LASTEXITCODE -eq 0)
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        $ok = $false
    } finally {
        Pop-Location
    }
    $sw.Stop()
    $results.Add([pscustomobject]@{
        Check  = $Name
        Result = if ($ok) { 'PASS' } else { 'FAIL' }
        Secs   = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    })
}

function Add-Fail([string]$Name) {
    $results.Add([pscustomobject]@{ Check = $Name; Result = 'FAIL'; Secs = 0 })
}

if (-not $SkipPython) {
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Write-Host ".venv\Scripts\python.exe not found - skipping Python checks (see DEVSETUP.md)" -ForegroundColor Yellow
    } else {
        Invoke-Check 'ruff check .' $repoRoot { & $python -m ruff check . }
        Invoke-Check 'mypy netcontrol templates' $repoRoot { & $python -m mypy netcontrol templates }
    }
}

if (-not $SkipFrontend) {
    if (-not (Test-Path -LiteralPath (Join-Path $frontendDir 'node_modules') -PathType Container)) {
        Invoke-Check 'npm ci' $frontendDir { & npm ci }
    }
    Invoke-Check 'eslint' $frontendDir { & npm run lint }
    Invoke-Check 'tsc --noEmit' $frontendDir { & npm run typecheck }
    Invoke-Check 'vitest' $frontendDir { & npm test }
    if ($Build) {
        Invoke-Check 'npm run build' $frontendDir { & npm run build }
    }
}

if ($Tests.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Write-Host ".venv missing - cannot run pytest" -ForegroundColor Yellow
        Add-Fail 'pytest'
    } else {
        # Build APP_DATABASE_URL from .env (dev-env.ps1), then point the suite at
        # a sibling *_test database. conftest refuses anything not ending in _test.
        . (Join-Path $repoRoot 'scripts\dev-env.ps1')
        if (-not $env:APP_DATABASE_URL) {
            Add-Fail 'pytest'
        } else {
            $env:PLEXUS_TEST_PG_URL = ($env:APP_DATABASE_URL -replace '/[^/]+$', '/plexus_test')
            if (-not $env:APP_SECRET_KEY) { $env:APP_SECRET_KEY = 'dev-check-secret' }

            $pgUp = (& docker inspect --format '{{.State.Health.Status}}' plexus-postgres 2>$null)
            if ($pgUp -ne 'healthy') {
                Write-Host "plexus-postgres is not running/healthy - start it with .\scripts\dev-up.ps1 (or: docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres)" -ForegroundColor Yellow
                Add-Fail 'pytest'
            } else {
                $pgUser = 'plexus'
                $m = [regex]::Match($env:APP_DATABASE_URL, '^postgresql://([^:]+):')
                if ($m.Success) { $pgUser = [uri]::UnescapeDataString($m.Groups[1].Value) }
                $exists = (& docker exec plexus-postgres psql -U $pgUser -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='plexus_test'" 2>$null)
                if ("$exists".Trim() -ne '1') {
                    Write-Host "Creating plexus_test database (one-time)" -ForegroundColor Cyan
                    & docker exec plexus-postgres psql -U $pgUser -d postgres -c "CREATE DATABASE plexus_test" | Out-Null
                }
                $label = 'pytest ' + ($Tests -join ' ')
                Invoke-Check $label $repoRoot { & $python -m pytest @Tests -p no:cacheprovider -rfE }
            }
        }
    }
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($failed -gt 0) {
    Write-Host "$failed check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "All checks passed" -ForegroundColor Green
exit 0
