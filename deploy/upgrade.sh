#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Upgrade Script
#
# One command to upgrade a running Plexus deployment.  Two modes:
#
#   git mode (default):
#     git fetch + checkout <ref>, then docker compose build, then up -d.
#     Works on any branch / tag / commit SHA.
#
#   image mode (--image):
#     docker pull <image>, then up -d.  No local build, no git checkout.
#     Use this when consuming pre-built images from a registry.
#
# Safety:
#   • Snapshots the database before doing anything destructive.
#   • Captures the old ref / image tag and prints a one-line rollback
#     command if any step after the snapshot fails.
#   • --dry-run prints the plan without touching anything.
#   • Migrations are idempotent (routes/migrations/runner.py) and run on
#     app startup, so a partial restart will not re-apply anything.
#
# Usage:
#   bash deploy/upgrade.sh                           # latest of current branch
#   bash deploy/upgrade.sh --ref v1.2.3              # specific tag/branch/SHA
#   bash deploy/upgrade.sh --image ghcr.io/x/p:v1.2  # registry mode
#   bash deploy/upgrade.sh --dry-run                 # show plan, do nothing
#   bash deploy/upgrade.sh --rollback                # roll back to previous
#   bash deploy/upgrade.sh --skip-backup             # skip the db snapshot
# ═══════════════════════════════════════════════════════════════════════

# -E so the ERR trap below also fires for failures inside functions; without
# it a failed `compose build` in apply_git would exit silently.
set -Eeuo pipefail

# ── Project root ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Defaults ──────────────────────────────────────────────────────────
MODE="git"
REF=""
IMAGE=""
DRY_RUN=false
ROLLBACK=false
SKIP_BACKUP=false
HEALTHCHECK_TIMEOUT=120
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "${PROJECT_ROOT}")}"
ROLLBACK_FILE="${PROJECT_ROOT}/state/.upgrade-previous"
BACKUP_DIR="${PROJECT_ROOT}/state/backups/upgrades"

# ── Args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref) REF="$2"; shift 2 ;;
        --image) MODE="image"; IMAGE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --rollback) ROLLBACK=true; shift ;;
        --skip-backup) SKIP_BACKUP=true; shift ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────
log() { echo "[$(date -Iseconds)] $*"; }
run() {
    if $DRY_RUN; then
        echo "  DRY-RUN: $*"
    else
        eval "$@"
    fi
}
# `exit` does not trigger the ERR trap, so print the rollback hint here too.
die() { echo "ERROR: $*" >&2; rollback_hint 1; exit 1; }

# Read a value from .env. Returns empty string if missing. The `|| true`
# matters: grep exits 1 on no match and pipefail would turn that into a
# script-ending error under set -e.
env_get() {
    local key="$1"
    [[ -f .env ]] || return 0
    { grep -E "^${key}=" .env || true; } | head -n1 | cut -d= -f2- | tr -d '"' | tr -d "'"
}

# Set KEY=value in .env, replacing an existing line or appending. Compose
# reads .env for ${VAR} interpolation, so this is how image-mode deploys
# persist PLEXUS_IMAGE across later `docker compose up` / `restart` calls.
env_set() {
    local key="$1" value="$2"
    touch .env
    if grep -qE "^${key}=" .env; then
        # sed -i with a temp file keeps this portable across GNU/BSD sed.
        sed "s|^${key}=.*|${key}=${value}|" .env > .env.tmp && mv .env.tmp .env
    else
        printf '%s=%s\n' "${key}" "${value}" >> .env
    fi
}

compose() { docker compose "$@"; }

# ── Pre-flight ────────────────────────────────────────────────────────
preflight() {
    log "Pre-flight checks"
    [[ -f docker-compose.yml ]] || die "docker-compose.yml not found in ${PROJECT_ROOT}"
    command -v docker >/dev/null || die "docker not on PATH"
    docker compose version >/dev/null 2>&1 || die "'docker compose' plugin not installed"
    docker info >/dev/null 2>&1 || die "docker daemon not reachable (need sudo?)"

    if [[ "${MODE}" == "git" ]]; then
        [[ -d .git ]] || die "not a git repo - use --image mode for registry deploys"
    fi

    mkdir -p "${BACKUP_DIR}"
    mkdir -p "$(dirname "${ROLLBACK_FILE}")"
}

# ── Rollback flow ─────────────────────────────────────────────────────
do_rollback() {
    [[ -f "${ROLLBACK_FILE}" ]] || die "no previous upgrade recorded - nothing to roll back to"
    log "Rolling back using ${ROLLBACK_FILE}"
    # shellcheck disable=SC1090
    source "${ROLLBACK_FILE}"
    if [[ "${PREV_MODE:-}" == "git" ]]; then
        log "Restoring git ref ${PREV_REF}"
        run "git checkout ${PREV_REF}"
        run "compose build plexus"
    else
        log "Restoring image ${PREV_IMAGE}"
        # Image mode rollback assumes the previous image is still in the
        # local docker cache. Pulled tags are not auto-pruned, so this
        # holds unless the operator ran `docker image prune -a` between
        # upgrade and rollback.
        run "docker pull ${PREV_IMAGE} || true"
        if ! $DRY_RUN; then env_set PLEXUS_IMAGE "${PREV_IMAGE}"; fi
        run "compose up -d plexus"
        wait_healthy
        log "Rollback complete"
        return
    fi
    run "compose up -d plexus"
    wait_healthy
    log "Rollback complete"
}

# ── Database snapshot ─────────────────────────────────────────────────
snapshot_db() {
    if $SKIP_BACKUP; then
        log "Skipping database snapshot (--skip-backup)"
        return
    fi
    local engine
    engine="$(env_get APP_DB_ENGINE)"
    engine="${engine:-postgres}"
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"

    if [[ "${engine}" == "postgres" ]]; then
        local user db dest
        user="$(env_get POSTGRES_USER)"; user="${user:-plexus}"
        db="$(env_get POSTGRES_DB)"; db="${db:-plexus}"
        dest="${BACKUP_DIR}/db-${stamp}.sql.gz"
        log "Snapshotting Postgres → ${dest}"
        if $DRY_RUN; then
            echo "  DRY-RUN: docker exec plexus-postgres pg_dump -U ${user} ${db} | gzip > ${dest}"
        else
            docker exec plexus-postgres pg_dump -U "${user}" "${db}" | gzip > "${dest}"
            log "  $(du -h "${dest}" | cut -f1)"
        fi
    else
        # SQLite lives inside the plexus-db named volume at /app/state/netcontrol.db.
        # Copy via a throwaway container so we don't depend on the host
        # being able to read into the docker volume directly.
        local volume="${COMPOSE_PROJECT}_plexus-db"
        local dest="${BACKUP_DIR}/sqlite-${stamp}.db.gz"
        log "Snapshotting SQLite from volume ${volume} → ${dest}"
        if $DRY_RUN; then
            echo "  DRY-RUN: docker run --rm -v ${volume}:/src:ro alpine cat /src/netcontrol.db | gzip > ${dest}"
        else
            docker run --rm -v "${volume}:/src:ro" alpine \
                cat /src/netcontrol.db | gzip > "${dest}"
            log "  $(du -h "${dest}" | cut -f1)"
        fi
    fi

    # Retain the last 10 upgrade snapshots; older ones go.
    if ! $DRY_RUN; then
        ls -1t "${BACKUP_DIR}" 2>/dev/null | tail -n +11 | while read -r old; do
            rm -f "${BACKUP_DIR}/${old}"
        done
    fi
}

# ── Record rollback target ────────────────────────────────────────────
record_rollback() {
    if $DRY_RUN; then return; fi
    if [[ "${MODE}" == "git" ]]; then
        local prev_ref
        prev_ref="$(git rev-parse HEAD)"
        cat > "${ROLLBACK_FILE}" <<EOF
PREV_MODE=git
PREV_REF=${prev_ref}
PREV_AT=$(date -Iseconds)
EOF
    else
        # Capture the image tag the running container was created from.
        local prev_image
        prev_image="$(docker inspect --format='{{.Config.Image}}' plexus-app 2>/dev/null || true)"
        if [[ -z "${prev_image}" ]]; then
            log "WARN: could not determine current image - rollback will not work"
            return
        fi
        cat > "${ROLLBACK_FILE}" <<EOF
PREV_MODE=image
PREV_IMAGE=${prev_image}
PREV_AT=$(date -Iseconds)
EOF
    fi
}

# ── Apply the new code ────────────────────────────────────────────────
apply_git() {
    log "Fetching from origin"
    run "git fetch --tags --prune origin"

    if [[ -z "${REF:-}" ]]; then
        # No --ref given: fast-forward the current branch to its upstream.
        # Stay *on* the branch (merge --ff-only) rather than checking out
        # origin/<branch>, which detaches HEAD and breaks the next
        # `git pull` in bootstrap.sh.
        local branch
        branch="$(git symbolic-ref -q --short HEAD || true)"
        if [[ -z "${branch}" ]]; then
            # Detached HEAD - earlier versions of this script left repos this
            # way. Re-attach to the remote's default branch.
            branch="$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null || true)"
            branch="${branch#origin/}"
            [[ -n "${branch}" ]] || die "HEAD is detached and origin/HEAD is unset - run 'git checkout <branch>' or pass --ref"
            log "HEAD is detached - re-attaching to ${branch}"
            run "git checkout '${branch}'"
        fi
        log "No --ref given - fast-forwarding ${branch} to origin/${branch}"
        run "git merge --ff-only 'origin/${branch}'"
    else
        run "git checkout '${REF}'"
        # If --ref named a branch, also ff to its tip. A tag/SHA checkout is
        # detached by design and there is nothing to pull.
        if git symbolic-ref -q HEAD >/dev/null 2>&1; then
            run "git pull --ff-only"
        fi
    fi

    # A previous --image deploy may have pinned PLEXUS_IMAGE in .env; clear
    # it so the build below is tagged plexus-app:local and `up` uses it.
    if [[ -n "$(env_get PLEXUS_IMAGE)" ]]; then
        log "Clearing PLEXUS_IMAGE from .env (switching back to local build)"
        if ! $DRY_RUN; then env_set PLEXUS_IMAGE ""; fi
    fi

    log "Building plexus image"
    run "compose build plexus"
}

apply_image() {
    [[ -n "${IMAGE}" ]] || die "--image requires a value"
    log "Pulling ${IMAGE}"
    run "docker pull '${IMAGE}'"
    # docker-compose.yml sets `image: ${PLEXUS_IMAGE:-plexus-app:local}`.
    # Persisting the tag in .env (compose's interpolation source) means a
    # later plain `docker compose up -d` or `restart` keeps the pulled image
    # instead of falling back to a local build.
    if $DRY_RUN; then
        echo "  DRY-RUN: set PLEXUS_IMAGE=${IMAGE} in .env"
    else
        env_set PLEXUS_IMAGE "${IMAGE}"
    fi
    export PLEXUS_IMAGE="${IMAGE}"
}

# ── Cutover + health wait ─────────────────────────────────────────────
cutover() {
    log "Recreating plexus container"
    # `up -d plexus` recreates only the plexus service. Postgres and nginx
    # keep running. Compose's healthcheck (in docker-compose.yml) gates
    # nginx's dependency, so nginx briefly serves 502s during the swap.
    run "compose up -d plexus"
}

wait_healthy() {
    if $DRY_RUN; then return; fi
    log "Waiting for /api/health (up to ${HEALTHCHECK_TIMEOUT}s)"
    local elapsed=0
    while (( elapsed < HEALTHCHECK_TIMEOUT )); do
        if docker exec plexus-app python -c \
            "import urllib.request,sys; urllib.request.urlopen('http://localhost:8080/api/health', timeout=4)" \
            >/dev/null 2>&1; then
            log "  healthy after ${elapsed}s"
            return 0
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
    die "plexus did not report healthy within ${HEALTHCHECK_TIMEOUT}s - check 'docker compose logs plexus'"
}

# ── Failure handler ───────────────────────────────────────────────────
rollback_hint() {
    local rc="$1"
    # Only meaningful once record_rollback has run and we are not rolling
    # back already (a failed rollback has nothing further to offer).
    if [[ -f "${ROLLBACK_FILE}" ]] && ! $DRY_RUN && ! $ROLLBACK; then
        echo "" >&2
        echo "════════════════════════════════════════════════════════════════" >&2
        echo "  Upgrade failed (exit ${rc}). Rollback target captured at:" >&2
        echo "    ${ROLLBACK_FILE}" >&2
        echo "  To roll back:" >&2
        echo "    bash deploy/upgrade.sh --rollback" >&2
        echo "  Database snapshot for this upgrade: ${BACKUP_DIR}/" >&2
        echo "════════════════════════════════════════════════════════════════" >&2
    fi
}
on_failure() {
    local rc=$?
    rollback_hint "${rc}"
    exit "${rc}"
}
trap on_failure ERR

# ── Main ──────────────────────────────────────────────────────────────
preflight

if $ROLLBACK; then
    do_rollback
    exit 0
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Plexus Upgrade"
echo "  mode:    ${MODE}"
[[ "${MODE}" == "git" ]] && echo "  ref:     ${REF:-<latest of current branch>}"
[[ "${MODE}" == "image" ]] && echo "  image:   ${IMAGE}"
echo "  dry-run: ${DRY_RUN}"
echo "═══════════════════════════════════════════════════"
echo ""

snapshot_db
record_rollback

if [[ "${MODE}" == "git" ]]; then
    apply_git
else
    apply_image
fi

cutover
wait_healthy

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Upgrade complete"
[[ "${MODE}" == "git" ]] && echo "  now at: $(git rev-parse --short HEAD) ($(git log -1 --format=%s | head -c 80))"
[[ "${MODE}" == "image" ]] && echo "  now at: ${IMAGE}"
echo "  rollback: bash deploy/upgrade.sh --rollback"
echo "═══════════════════════════════════════════════════"
