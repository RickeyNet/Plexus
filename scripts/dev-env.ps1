# Set up a PowerShell session to run Plexus from source against the
# development Postgres container (docker-compose.dev.yml, 127.0.0.1:5432).
#
# Dot-source it from the repo root so the variables stay in your session:
#
#   . .\scripts\dev-env.ps1
#
# It reads POSTGRES_PASSWORD (and POSTGRES_USER / POSTGRES_DB, default
# plexus) from .env, sets APP_DB_ENGINE, APP_ENV and APP_DATABASE_URL, and
# activates .venv when it exists. templates/run.py does not read .env itself.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.

$plexusEnvFile = Join-Path (Get-Location) '.env'
if (-not (Test-Path -LiteralPath $plexusEnvFile -PathType Leaf)) {
    Write-Error ".env not found in $(Get-Location). Run 'bash deploy/setup.sh' from the repo root first, then dot-source this script from the repo root."
    return
}

$plexusEnv = @{}
foreach ($line in Get-Content -LiteralPath $plexusEnvFile) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $eq = $trimmed.IndexOf('=')
    if ($eq -lt 1) { continue }
    $key = $trimmed.Substring(0, $eq).Trim()
    $value = $trimmed.Substring($eq + 1).Trim()
    if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    $plexusEnv[$key] = $value
}

if (-not $plexusEnv['POSTGRES_PASSWORD']) {
    Write-Error "POSTGRES_PASSWORD is missing or empty in .env. Run 'bash deploy/setup.sh' (on a fresh checkout) or set it in .env."
    return
}

$plexusDbUser = 'plexus'
if ($plexusEnv['POSTGRES_USER']) { $plexusDbUser = $plexusEnv['POSTGRES_USER'] }
$plexusDbName = 'plexus'
if ($plexusEnv['POSTGRES_DB']) { $plexusDbName = $plexusEnv['POSTGRES_DB'] }

$plexusUserEnc = [uri]::EscapeDataString($plexusDbUser)
$plexusPassEnc = [uri]::EscapeDataString($plexusEnv['POSTGRES_PASSWORD'])
$plexusDbEnc = [uri]::EscapeDataString($plexusDbName)

$env:APP_DB_ENGINE = 'postgres'
$env:APP_ENV = 'dev'
$env:APP_DATABASE_URL = "postgresql://${plexusUserEnc}:${plexusPassEnc}@127.0.0.1:5432/${plexusDbEnc}"

$plexusVenv = 'not found'
$plexusActivate = Join-Path (Get-Location) '.venv\Scripts\Activate.ps1'
if (Test-Path -LiteralPath $plexusActivate -PathType Leaf) {
    . $plexusActivate
    $plexusVenv = 'activated'
}

Write-Host "Plexus dev env: APP_DB_ENGINE=postgres APP_ENV=dev APP_DATABASE_URL=postgresql://${plexusUserEnc}:***@127.0.0.1:5432/${plexusDbEnc} (.venv $plexusVenv)"

Remove-Variable -Name plexusEnvFile, plexusEnv, line, trimmed, eq, key, value, plexusDbUser, plexusDbName, plexusUserEnc, plexusPassEnc, plexusDbEnc, plexusVenv, plexusActivate -ErrorAction SilentlyContinue
