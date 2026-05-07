#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Bootstrap — fresh Ubuntu → running stack in one command
#
# Usage (run on a clean Ubuntu 24.04 / 26.04 box):
#   curl -fsSL https://raw.githubusercontent.com/RickeyNet/Plexus/main/deploy/bootstrap.sh | sudo bash
#
# Or after `git clone`:
#   sudo bash deploy/bootstrap.sh
#
# Idempotent — safe to re-run. Skips steps already done.
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
    echo "WARN: running as root user — docker group membership won't be added to a regular account."
fi

log() { printf '\n\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }

# ── 1. Refresh apt and apply pending security updates ─────────────────
log "Updating apt index and upgrading existing packages"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# ── 2. Install prereqs (curl, git, ca-certs, ufw) ─────────────────────
log "Installing base prerequisites (git, curl, ca-certificates, ufw)"
apt-get install -y ca-certificates curl git ufw

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
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
else
    log "Docker already installed — skipping"
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
    log "Repo already cloned at ${INSTALL_DIR} — pulling latest"
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
log "Starting Plexus stack (docker compose up -d)"
sudo -u "${TARGET_USER}" docker compose up -d --build

# ── 8. Open firewall (only if ufw is enabled) ─────────────────────────
if ufw status | grep -q "Status: active"; then
    log "Opening firewall ports (443, 80, 2055/udp, 162/udp, 1514/udp)"
    ufw allow 443/tcp >/dev/null
    ufw allow 80/tcp >/dev/null
    ufw allow 2055/udp >/dev/null
    ufw allow 162/udp >/dev/null
    ufw allow 1514/udp >/dev/null
else
    log "ufw is inactive — skipping firewall rules. Enable with: sudo ufw enable"
fi

# ── 9. Final status ───────────────────────────────────────────────────
log "Stack status:"
sudo -u "${TARGET_USER}" docker compose ps

IP=$(hostname -I | awk '{print $1}')
cat <<EOF

═══════════════════════════════════════════════════
  Plexus is up.

  Browse to:  https://${IP}
  Login:      admin / netcontrol  (forced password change on first login)

  Useful commands (run as ${TARGET_USER}):
    cd ${INSTALL_DIR}
    docker compose ps             # status
    docker compose logs -f plexus # tail app logs
    docker compose restart        # restart all
    git pull && docker compose up -d --build   # update to latest
═══════════════════════════════════════════════════
EOF
