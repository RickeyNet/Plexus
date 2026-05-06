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
    # dpkg installs in dependency order if you give it the whole set at once.
    # Any missing transitive deps are reported; --fix-broken won't help offline,
    # so the bundle should already include everything from apt-get install -y
    # --download-only on a fresh image.
    dpkg -i "$BUNDLE_DIR"/debs/*.deb || {
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

# Pin compose to use the locally-loaded image instead of trying to build.
# We rewrite 'build: .' to 'image: plexus:airgap' in the staged compose file.
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
if grep -q '^\s*build: \.' "$COMPOSE_FILE"; then
    sed -i 's|^\(\s*\)build: \.|\1image: plexus:airgap|' "$COMPOSE_FILE"
    echo "  Pinned plexus service to image: plexus:airgap"
fi

# ── 4. Run setup.sh (generates .env + self-signed cert) ──────────────
echo ""
echo "[4/5] Running deploy/setup.sh..."
cd "$INSTALL_DIR"
bash deploy/setup.sh

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
    ufw allow 162/udp  || true
    ufw allow 1514/udp || true
fi

VM_HOST="$(hostname -f 2>/dev/null || hostname -I | awk '{print $1}')"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Done. Browse to: https://$VM_HOST"
echo ""
echo "  - First login: admin / netcontrol (forced password change)"
echo "  - Edit $INSTALL_DIR/.env then 'docker compose restart'"
echo "  - Logs:    docker compose -f $INSTALL_DIR/docker-compose.yml logs -f plexus"
echo "  - Stop:    docker compose -f $INSTALL_DIR/docker-compose.yml down"
echo "═══════════════════════════════════════════════════"
