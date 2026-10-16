#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus host updater - applies upgrade requests queued from the web UI
#
# Run by systemd (deploy/systemd/plexus-updater.{path,service}) whenever
# the app writes state/updates/request.json. The app container has no
# Docker socket; this script is the only thing that acts on a request.
#
# Flow:
#   request.json -> request.inprogress.json -> validate -> deploy/upgrade.sh
#   -> result.json (running, then success/failed), output in upgrade.log,
#   rollback target mirrored into rollback.json.
#
# Requests are untrusted input: the action, image and ref are re-validated
# here. Image refs must live under PLEXUS_UPDATE_IMAGE_REPO from .env
# (default ghcr.io/rickeynet/plexus).
#
# Usage:
#   bash deploy/plexus-updater.sh                 # process a queued request
#   bash deploy/plexus-updater.sh --sync-rollback # only refresh rollback.json
#
# upgrade.sh runs as the owner of the install directory (the account
# bootstrap.sh set up, which is in the docker group) so git objects, .env
# and state/backups keep their ownership. JSON is handled with python3,
# which Ubuntu ships by default.
# ═══════════════════════════════════════════════════════════════════════

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${PLEXUS_INSTALL_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "${INSTALL_DIR}"

UPDATES_DIR="${INSTALL_DIR}/state/updates"
REQUEST="${UPDATES_DIR}/request.json"
INPROGRESS="${UPDATES_DIR}/request.inprogress.json"
RESULT="${UPDATES_DIR}/result.json"
LOG_FILE="${UPDATES_DIR}/upgrade.log"
ROLLBACK_JSON="${UPDATES_DIR}/rollback.json"
UPGRADE_PREVIOUS="${INSTALL_DIR}/state/.upgrade-previous"
DEFAULT_IMAGE_REPO="ghcr.io/rickeynet/plexus"

log() { echo "[plexus-updater $(date -Iseconds)] $*"; }

# Same idiom as upgrade.sh: `|| true` keeps a missing key from tripping
# pipefail.
env_get() {
    local key="$1"
    [[ -f .env ]] || return 0
    { grep -E "^${key}=" .env || true; } | head -n1 | cut -d= -f2- | tr -d '"' | tr -d "'"
}

# Write result.json atomically. Values are passed through the environment
# so nothing from the request is ever interpolated into code.
#   write_result <status> <exit_code|""> <message>
write_result() {
    R_STATUS="$1" R_EXIT="$2" R_MESSAGE="$3" \
    R_STARTED="${STARTED_AT:-}" R_FINISHED="${FINISHED_AT:-}" \
    R_REQUEST_FILE="${INPROGRESS}" R_OUT="${RESULT}" \
    python3 - <<'PY'
import json, os

def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None

req = load(os.environ["R_REQUEST_FILE"])
exit_raw = os.environ.get("R_EXIT", "")
out = {
    "id": (req or {}).get("id") if isinstance((req or {}).get("id"), str) else None,
    "status": os.environ["R_STATUS"],
    "started_at": os.environ.get("R_STARTED") or None,
    "finished_at": os.environ.get("R_FINISHED") or None,
    "exit_code": int(exit_raw) if exit_raw.lstrip("-").isdigit() else None,
    "message": os.environ.get("R_MESSAGE", ""),
    "request": req,
}
path = os.environ["R_OUT"]
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}

# Mirror state/.upgrade-previous (KEY=VALUE lines written by upgrade.sh)
# into rollback.json so the app can offer "Roll back". Parsed, never sourced.
sync_rollback() {
    RB_SRC="${UPGRADE_PREVIOUS}" RB_OUT="${ROLLBACK_JSON}" python3 - <<'PY'
import json, os

src, path = os.environ["RB_SRC"], os.environ["RB_OUT"]
vals = {}
try:
    with open(src, encoding="utf-8") as fh:
        for line in fh:
            key, sep, value = line.strip().partition("=")
            if sep:
                vals[key] = value
except OSError:
    pass
mode = vals.get("PREV_MODE", "")
target = vals.get("PREV_REF" if mode == "git" else "PREV_IMAGE", "")
out = {
    "available": bool(mode in ("git", "image") and target),
    "mode": mode or None,
    "target": target or None,
    "recorded_at": vals.get("PREV_AT") or None,
}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}

# Print action, mode, image, ref of the in-progress request, one per line.
# Non-string or multi-line values come out empty and fail validation below.
read_request() {
    REQ_FILE="${INPROGRESS}" python3 - <<'PY'
import json, os

try:
    with open(os.environ["REQ_FILE"], encoding="utf-8") as fh:
        data = json.load(fh)
except (OSError, ValueError):
    data = None
if not isinstance(data, dict):
    data = {}
for key in ("action", "mode", "image", "ref"):
    value = data.get(key)
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        value = ""
    print(value)
PY
}

# Run a command as the install dir's owner (root installs run it directly).
run_as_owner() {
    local owner owner_home
    owner="$(stat -c %U "${INSTALL_DIR}")"
    if [[ "$(id -u)" -ne 0 || "${owner}" == "root" ]]; then
        "$@"
    else
        # runuser keeps the caller's environment, so HOME would still be
        # /root (or unset under systemd). git then fails reading
        # /root/.gitconfig as the owner and docker cannot find its config;
        # point HOME at the owner's home instead.
        owner_home="$(getent passwd "${owner}" | cut -d: -f6)"
        runuser -u "${owner}" -- env HOME="${owner_home:-/tmp}" USER="${owner}" LOGNAME="${owner}" "$@"
    fi
}

command -v python3 >/dev/null || { log "python3 is required"; exit 1; }
mkdir -p "${UPDATES_DIR}"

if [[ "${1:-}" == "--sync-rollback" ]]; then
    sync_rollback
    exit 0
fi

# A leftover in-progress file means a previous run was killed (reboot,
# systemd timeout). Close it out so the UI is not stuck on "running".
if [[ -f "${INPROGRESS}" ]]; then
    log "Found stale ${INPROGRESS}; marking it failed"
    FINISHED_AT="$(date -Iseconds)"
    write_result failed "" "Updater was interrupted before this request finished; check the host and retry."
    rm -f "${INPROGRESS}"
fi

if [[ ! -f "${REQUEST}" ]]; then
    sync_rollback
    exit 0
fi

# Claim the request first so the PathExists watcher does not re-trigger.
mv -f "${REQUEST}" "${INPROGRESS}"
STARTED_AT="$(date -Iseconds)"
FINISHED_AT=""
FINALIZED=false
: > "${LOG_FILE}"
chmod 0644 "${LOG_FILE}"

finish() {
    local status="$1" code="$2" message="$3"
    FINISHED_AT="$(date -Iseconds)"
    write_result "${status}" "${code}" "${message}"
    rm -f "${INPROGRESS}"
    sync_rollback || true
    FINALIZED=true
    log "${status}: ${message}"
}

on_exit() {
    local rc=$?
    if ! ${FINALIZED}; then
        finish failed "${rc}" "Updater failed unexpectedly (exit ${rc}); see upgrade.log."
    fi
}
trap on_exit EXIT

write_result running "" "Update started"

mapfile -t FIELDS < <(read_request)
ACTION="${FIELDS[0]:-}"; ACTION="${ACTION%$'\r'}"
MODE="${FIELDS[1]:-}"; MODE="${MODE%$'\r'}"
IMAGE="${FIELDS[2]:-}"; IMAGE="${IMAGE%$'\r'}"
REF="${FIELDS[3]:-}"; REF="${REF%$'\r'}"

ARGS=()
case "${ACTION}" in
    rollback)
        ARGS=(--rollback)
        ;;
    upgrade)
        case "${MODE}" in
            image)
                ALLOWED_REPO="$(env_get PLEXUS_UPDATE_IMAGE_REPO)"
                ALLOWED_REPO="${ALLOWED_REPO:-${DEFAULT_IMAGE_REPO}}"
                TAG="${IMAGE#"${ALLOWED_REPO}:"}"
                if [[ "${IMAGE}" != "${ALLOWED_REPO}:"* || ! "${TAG}" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
                    finish failed 2 "Rejected image '${IMAGE}': must be ${ALLOWED_REPO}:<tag> (set PLEXUS_UPDATE_IMAGE_REPO in .env to allow another repository)."
                    exit 0
                fi
                ARGS=(--image "${IMAGE}")
                ;;
            git)
                if [[ ! "${REF}" =~ ^[A-Za-z0-9._/-]{1,128}$ ]]; then
                    finish failed 2 "Rejected git ref '${REF}': invalid characters."
                    exit 0
                fi
                ARGS=(--ref "${REF}")
                ;;
            *)
                finish failed 2 "Rejected request: mode must be 'image' or 'git'."
                exit 0
                ;;
        esac
        ;;
    *)
        finish failed 2 "Rejected request: action must be 'upgrade' or 'rollback'."
        exit 0
        ;;
esac

log "Running deploy/upgrade.sh ${ARGS[*]}"
{
    echo "[plexus-updater $(date -Iseconds)] deploy/upgrade.sh ${ARGS[*]}"
} >> "${LOG_FILE}"

set +e
run_as_owner bash "${INSTALL_DIR}/deploy/upgrade.sh" "${ARGS[@]}" >> "${LOG_FILE}" 2>&1 < /dev/null
RC=$?
set -e

if [[ ${RC} -eq 0 ]]; then
    if [[ "${ACTION}" == "rollback" ]]; then
        finish success 0 "Rollback completed."
    else
        finish success 0 "Upgrade completed (${ARGS[*]})."
    fi
else
    finish failed "${RC}" "deploy/upgrade.sh exited with code ${RC}; see upgrade.log. Roll back from the UI or with 'bash deploy/upgrade.sh --rollback'."
fi
