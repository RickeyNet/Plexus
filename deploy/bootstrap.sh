#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Bootstrap - fresh Ubuntu → running stack in one command
#
# Usage (run on a clean Ubuntu 24.04 / 26.04 box):
#   curl -fsSL https://raw.githubusercontent.com/RickeyNet/Plexus/main/deploy/bootstrap.sh | sudo bash
#
# Or after `git clone`:
#   sudo bash deploy/bootstrap.sh
#
# Idempotent - safe to re-run. Skips steps already done.
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_URL="${PLEXUS_REPO_URL:-https://github.com/RickeyNet/Plexus.git}"
INSTALL_DIR="${PLEXUS_INSTALL_DIR:-/opt/plexus}"
TARGET_USER="${SUDO_USER:-${USER}}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi

if [[ "${TARGET_USER}" == "root" ]]; then
    echo "WARN: running as root user - docker group membership won't be added to a regular account."
fi

log() { printf '\n\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }

# Non-interactive apt wrapper.
#   - DPkg::Lock::Timeout: on a fresh Ubuntu, unattended-upgrades starts a
#     minute or two after boot and holds the dpkg lock. Plain apt-get fails
#     instantly on a held lock; this makes it wait up to 15 minutes instead.
#   - NEEDRESTART_MODE=a: stop needrestart from popping its "which services
#     should be restarted?" dialog and blocking the script.
#   - force-confdef/confold: keep existing config files, never prompt.
apt_ni() {
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get -o DPkg::Lock::Timeout=900 \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold \
            -y "$@"
}

# ── 1. Refresh apt and apply pending security updates ─────────────────
if pgrep -f unattended-upgr >/dev/null; then
    log "unattended-upgrades is running - waiting for it to release the dpkg lock"
fi
log "Updating apt index and upgrading existing packages"
apt_ni update
apt_ni upgrade

# ── 2. Install prereqs (curl, git, ca-certs, ufw) ─────────────────────
log "Installing base prerequisites (git, curl, ca-certificates, ufw)"
apt_ni install ca-certificates curl git ufw

# ── 2b. Swap for small hosts ──────────────────────────────────────────
# The Vite frontend build inside `docker compose build` peaks near 2 GB.
# Cloud images ship with no swap, so a 3-4 GB box can OOM-kill the build.
# Add a 2 GB swapfile when RAM < 4 GB and no swap is configured yet.
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
SWAP_MB=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
if (( MEM_MB < 4096 )) && (( SWAP_MB == 0 )) && [[ ! -f /swapfile ]]; then
    log "Host has ${MEM_MB} MB RAM and no swap - creating 2 GB /swapfile"
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ── 3. Install Docker from Docker's official apt repo ─────────────────
if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker engine + compose v2 plugin"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME}")
    ARCH=$(dpkg --print-architecture)
    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt_ni update
    apt_ni install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
else
    log "Docker already installed - skipping"
fi

# ── 4. Add invoking user to docker group ──────────────────────────────
if [[ "${TARGET_USER}" != "root" ]]; then
    if ! id -nG "${TARGET_USER}" | grep -qw docker; then
        log "Adding ${TARGET_USER} to docker group (effective on next login)"
        usermod -aG docker "${TARGET_USER}"
    fi
fi

# ── 5. Clone or update repo into INSTALL_DIR ──────────────────────────
mkdir -p "${INSTALL_DIR}"
chown -R "${TARGET_USER}:${TARGET_USER}" "${INSTALL_DIR}"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    log "Repo already cloned at ${INSTALL_DIR} - pulling latest"
    # Older upgrade.sh builds left the repo on a detached HEAD, where
    # `git pull` refuses to run. Re-attach to the remote default branch first.
    if ! sudo -u "${TARGET_USER}" git -C "${INSTALL_DIR}" symbolic-ref -q HEAD >/dev/null; then
        DEFAULT_BRANCH=$(sudo -u "${TARGET_USER}" git -C "${INSTALL_DIR}" symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null || echo "origin/main")
        DEFAULT_BRANCH="${DEFAULT_BRANCH#origin/}"
        log "HEAD is detached - checking out ${DEFAULT_BRANCH}"
        sudo -u "${TARGET_USER}" git -C "${INSTALL_DIR}" checkout "${DEFAULT_BRANCH}"
    fi
    sudo -u "${TARGET_USER}" git -C "${INSTALL_DIR}" pull --ff-only
else
    log "Cloning ${REPO_URL} into ${INSTALL_DIR}"
    sudo -u "${TARGET_USER}" git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

# ── 6. Run setup.sh (generates .env + self-signed cert) ───────────────
log "Running setup.sh (generates .env and self-signed TLS cert)"
sudo -u "${TARGET_USER}" bash deploy/setup.sh

# ── 7. Start the stack ────────────────────────────────────────────────
# If the app container dies, compose only says "dependency failed to start".
# Dump the evidence (exit code, OOM flag, app log) so the operator does not
# have to go digging - and does not need docker-group access to do it.
diagnose_failure() {
    echo "" >&2
    echo "════════════════════════════════════════════════════════════════" >&2
    echo "  Plexus stack failed to start. Diagnostics:" >&2
    echo "════════════════════════════════════════════════════════════════" >&2
    docker compose ps -a 2>&1 >&2 || true
    local exit_code oom
    exit_code=$(docker inspect --format '{{.State.ExitCode}}' plexus-app 2>/dev/null || echo "?")
    oom=$(docker inspect --format '{{.State.OOMKilled}}' plexus-app 2>/dev/null || echo "?")
    echo "" >&2
    echo "  plexus-app exit code: ${exit_code}   OOM-killed: ${oom}" >&2
    echo "  host memory: $(awk '/MemTotal/ {printf "%d MB", $2/1024}' /proc/meminfo), swap: $(awk '/SwapTotal/ {printf "%d MB", $2/1024}' /proc/meminfo)" >&2
    if [[ "${oom}" == "true" ]]; then
        echo "  -> The kernel killed the app for running out of memory. Plexus needs" >&2
        echo "     ~1 GB to start; this host is too small or swap is missing." >&2
    fi
    echo "" >&2
    echo "  Last 60 lines of the app log:" >&2
    echo "  ──────────────────────────────────────────────────────────────" >&2
    docker compose logs --no-color --tail 60 plexus 2>&1 | sed 's/^/  /' >&2 || true
    echo "  ──────────────────────────────────────────────────────────────" >&2
    echo "  Full log:  sudo docker compose -f ${INSTALL_DIR}/docker-compose.yml logs plexus" >&2
    echo "  Retry:     sudo bash ${INSTALL_DIR}/deploy/bootstrap.sh" >&2
    exit 1
}

log "Starting Plexus stack (docker compose up -d)"
if ! sudo -u "${TARGET_USER}" docker compose up -d --build; then
    diagnose_failure
fi

# `up -d` returns as soon as containers are created; make sure the app
# actually reaches healthy before declaring success (start_period is 60s).
log "Waiting for plexus-app to report healthy"
for _ in $(seq 1 40); do
    status=$(docker inspect --format '{{.State.Health.Status}}' plexus-app 2>/dev/null || echo "missing")
    running=$(docker inspect --format '{{.State.Running}}' plexus-app 2>/dev/null || echo "false")
    if [[ "${status}" == "healthy" ]]; then break; fi
    if [[ "${running}" != "true" ]]; then diagnose_failure; fi
    sleep 3
done
[[ "${status}" == "healthy" ]] || diagnose_failure

# ── 8. Open firewall (only if ufw is enabled) ─────────────────────────
if ufw status | grep -q "Status: active"; then
    log "Opening firewall ports (443, 80, 2055/udp, 6343/udp, 162/udp, 1514/udp)"
    ufw allow 443/tcp >/dev/null
    ufw allow 80/tcp >/dev/null
    ufw allow 2055/udp >/dev/null
    ufw allow 6343/udp >/dev/null
    ufw allow 162/udp >/dev/null
    ufw allow 1514/udp >/dev/null
else
    log "ufw is inactive - skipping firewall rules. Enable with: sudo ufw enable"
fi

# ── 9. Final status ───────────────────────────────────────────────────
log "Stack status:"
sudo -u "${TARGET_USER}" docker compose ps

IP=$(hostname -I | awk '{print $1}')
cat <<EOF

═══════════════════════════════════════════════════
  Plexus is up.

  Browse to:  https://${IP}
  Login:      admin / netcontrol
              You will be forced to change it at first login.
              (Initial password comes from PLEXUS_INITIAL_ADMIN_PASSWORD in .env;
              if that line was removed, the random one is in the app log:
              docker compose logs plexus | grep -A3 'default admin')

  Useful commands (run as ${TARGET_USER}). Your current shell does not yet
  have the docker group - log out and back in first, or prefix with sudo:
    cd ${INSTALL_DIR}
    docker compose ps             # status
    docker compose logs -f plexus # tail app logs
    docker compose restart        # restart all
    bash deploy/upgrade.sh        # update to latest (snapshots DB, supports --rollback)
═══════════════════════════════════════════════════
EOF
