#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Air-Gapped VM Installer
# Run on the offline Ubuntu VM after extracting plexus-airgap.tar.gz.
# Must be run with sudo (apt + systemctl + docker daemon).
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/plexus}"

echo "═══════════════════════════════════════════════════"
echo "  Plexus Air-Gap Installer"
echo "  Bundle:    $BUNDLE_DIR"
echo "  Install:   $INSTALL_DIR"
echo "═══════════════════════════════════════════════════"

# ── 1. Install Docker from local .debs ───────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo ""
    echo "[1/5] Installing Docker from local .deb packages..."
    # A fresh Ubuntu runs unattended-upgrades shortly after boot (even offline
    # it starts, then times out), and dpkg errors out instantly if that holds
    # the lock. Wait for it rather than fail.
    waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if (( waited == 0 )); then echo "  dpkg lock held (unattended-upgrades?) - waiting..."; fi
        sleep 5; waited=$((waited + 5))
        if (( waited >= 900 )); then echo "ERROR: dpkg lock still held after 15 min" >&2; exit 1; fi
    done
    # dpkg installs in dependency order if you give it the whole set at once.
    # Any missing transitive deps are reported; --fix-broken won't help offline,
    # so the bundle should already include everything from apt-get install -y
    # --download-only on a fresh image.
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a dpkg -i "$BUNDLE_DIR"/debs/*.deb || {
        echo "dpkg reported missing dependencies. Listing:"
        dpkg -i "$BUNDLE_DIR"/debs/*.deb 2>&1 | grep -i 'depends' || true
        echo ""
        echo "Re-run bundle.sh on the online machine to capture the missing deps,"
        echo "or stage them manually under the debs/ directory."
        exit 1
    }
    systemctl enable --now docker
else
    echo "[1/5] Docker already installed: $(docker --version)"
fi

# ── 2. Load images ───────────────────────────────────────────────────
echo ""
echo "[2/5] Loading container images..."
for tar in "$BUNDLE_DIR"/images/*.tar; do
    echo "  - $tar"
    docker load -i "$tar"
done
docker images | head -20

# ── 3. Stage repo into INSTALL_DIR ───────────────────────────────────
echo ""
echo "[3/5] Staging compose project at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$BUNDLE_DIR"/repo/. "$INSTALL_DIR"/

# ── 4. Run setup.sh (generates .env + self-signed cert) ──────────────
echo ""
echo "[4/5] Running deploy/setup.sh..."
cd "$INSTALL_DIR"
bash deploy/setup.sh

# Pin compose to the locally-loaded image instead of trying to build.
# docker-compose.yml reads `image: ${PLEXUS_IMAGE:-plexus-app:local}`, so
# setting PLEXUS_IMAGE in .env is enough - compose only builds when the
# named image is absent. Must run after setup.sh, which only writes .env
# when the file does not exist yet.
if grep -q '^PLEXUS_IMAGE=' .env; then
    sed -i 's|^PLEXUS_IMAGE=.*|PLEXUS_IMAGE=plexus:airgap|' .env
else
    printf 'PLEXUS_IMAGE=plexus:airgap\n' >> .env
fi
echo "  Pinned plexus service to image: plexus:airgap (PLEXUS_IMAGE in .env)"

# ── 5. Bring the stack up ────────────────────────────────────────────
echo ""
echo "[5/5] Starting compose stack..."
docker compose up -d
docker compose ps

# Open firewall if ufw is active (silently skip otherwise)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo ""
    echo "Opening firewall ports (ufw is active)..."
    ufw allow 443/tcp  || true
    ufw allow 80/tcp   || true
    ufw allow 2055/udp || true
    ufw allow 6343/udp || true
    ufw allow 162/udp  || true
    ufw allow 1514/udp || true
fi

VM_HOST="$(hostname -f 2>/dev/null || hostname -I | awk '{print $1}')"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Done. Browse to: https://$VM_HOST"
echo ""
echo "  - First login: 'admin' with the one-time password printed in the"
echo "    app log. Retrieve it (forced change at first login):"
echo "      docker compose -f $INSTALL_DIR/docker-compose.yml logs plexus | grep -A3 'default admin'"
echo "  - Edit $INSTALL_DIR/.env then 'docker compose restart'"
echo "  - Logs:    docker compose -f $INSTALL_DIR/docker-compose.yml logs -f plexus"
echo "  - Stop:    docker compose -f $INSTALL_DIR/docker-compose.yml down"
echo "═══════════════════════════════════════════════════"
