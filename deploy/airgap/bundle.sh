#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Air-Gapped Bundle Builder
# Run on a machine WITH internet access. Produces plexus-airgap.tar.gz
# that you transfer to the offline Ubuntu VM.
#
# Requirements on this online machine:
#   - Docker (running) with buildx enabled by default
#   - apt + dpkg (or run inside a temporary Ubuntu 26.04 amd64 container,
#     see DOCS section at the bottom of this file)
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# Resolve repo root (this script lives in deploy/airgap/)
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${OUT_DIR:-$REPO_ROOT/plexus-airgap-bundle}"
PLATFORM="${PLATFORM:-linux/amd64}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-resolute}"   # 26.04 LTS suite
PLEXUS_IMAGE_TAG="${PLEXUS_IMAGE_TAG:-plexus:airgap}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:alpine}"

echo "═══════════════════════════════════════════════════"
echo "  Plexus Air-Gap Bundle Builder"
echo "  Output:    $OUT_DIR"
echo "  Platform:  $PLATFORM"
echo "  Ubuntu:    $UBUNTU_CODENAME (apt suite name for Docker repo)"
echo "═══════════════════════════════════════════════════"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{images,debs,repo,repo/deploy}

# ── 1. Build the Plexus image for linux/amd64 ────────────────────────
echo ""
echo "[1/5] Building Plexus image ($PLEXUS_IMAGE_TAG) for $PLATFORM..."
# --load requires a single-platform build with the docker driver.
docker buildx build --platform "$PLATFORM" --load -t "$PLEXUS_IMAGE_TAG" .

# ── 2. Pull supporting images for the target platform ────────────────
echo ""
echo "[2/5] Pulling $POSTGRES_IMAGE and $NGINX_IMAGE for $PLATFORM..."
docker pull --platform "$PLATFORM" "$POSTGRES_IMAGE"
docker pull --platform "$PLATFORM" "$NGINX_IMAGE"

# ── 3. Save all images as tar files ──────────────────────────────────
echo ""
echo "[3/5] Saving images to tar files..."
docker save -o "$OUT_DIR/images/plexus.tar"   "$PLEXUS_IMAGE_TAG"
docker save -o "$OUT_DIR/images/postgres.tar" "$POSTGRES_IMAGE"
docker save -o "$OUT_DIR/images/nginx.tar"    "$NGINX_IMAGE"
ls -lh "$OUT_DIR/images/"

# ── 4. Download Docker Engine .deb packages ──────────────────────────
# We download to a scratch dir using a throwaway Ubuntu container so the
# host's apt state isn't mutated. Bind-mount the output dir for results.
echo ""
echo "[4/5] Downloading Docker Engine .deb packages (Ubuntu $UBUNTU_CODENAME, amd64)..."
# Run apt download inside an Ubuntu image whose codename matches the target VM,
# so transitive Ubuntu-archive deps (libc6, libseccomp2, etc.) are the right
# versions for resolute. Default base = ubuntu:$UBUNTU_CODENAME.
APT_BASE_IMAGE="${APT_BASE_IMAGE:-ubuntu:$UBUNTU_CODENAME}"
echo "         Using apt base image: $APT_BASE_IMAGE"
docker run --rm --platform "$PLATFORM" \
    -v "$OUT_DIR/debs":/out \
    "$APT_BASE_IMAGE" bash -c '
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu '"$UBUNTU_CODENAME"' stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update
        cd /out
        # Use download-only so we get the .deb files without installing.
        apt-get install -y --download-only \
            docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        cp /var/cache/apt/archives/*.deb /out/
        echo "Downloaded debs:"
        ls -lh /out
    '

# ── 5. Stage repo files needed at runtime ────────────────────────────
echo ""
echo "[5/5] Staging repo files..."
cp docker-compose.yml      "$OUT_DIR/repo/"
cp .env.example            "$OUT_DIR/repo/"
cp deploy/nginx.conf       "$OUT_DIR/repo/deploy/"
cp deploy/setup.sh         "$OUT_DIR/repo/deploy/"
cp deploy/backup.sh        "$OUT_DIR/repo/deploy/"
cp deploy/plexus.cron      "$OUT_DIR/repo/deploy/"
cp deploy/airgap/install.sh "$OUT_DIR/install.sh"
cp deploy/airgap/README.md  "$OUT_DIR/README.md"
chmod +x "$OUT_DIR/install.sh" "$OUT_DIR/repo/deploy/setup.sh" "$OUT_DIR/repo/deploy/backup.sh"

# ── Tar everything up ────────────────────────────────────────────────
ARCHIVE="$REPO_ROOT/plexus-airgap.tar.gz"
echo ""
echo "Creating archive: $ARCHIVE"
tar -czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"
ls -lh "$ARCHIVE"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Bundle ready: $ARCHIVE"
echo ""
echo "  Transfer it to the VM (USB / SCP / shared folder),"
echo "  then on the VM:"
echo "    tar -xzf plexus-airgap.tar.gz"
echo "    cd plexus-airgap-bundle"
echo "    sudo bash install.sh"
echo "═══════════════════════════════════════════════════"
