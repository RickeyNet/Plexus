#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Deployment Setup Script
# Run this once on the VM before 'docker compose up'
#
# Usage:
#   bash deploy/setup.sh                    # APP_API_TOKEN left empty
#   bash deploy/setup.sh --with-api-token   # also generate APP_API_TOKEN
#   PLEXUS_ENABLE_API_TOKEN=true bash deploy/setup.sh   # same as the flag
#
# APP_API_TOKEN is a static, admin-equivalent server secret: a request that
# carries it skips CSRF, the per-IP API rate limit and the session limits.
# Only generate it when automation or a federation peer needs it.
# ═══════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

WITH_API_TOKEN=false
case "${PLEXUS_ENABLE_API_TOKEN:-}" in
    1|true|TRUE|True|yes|YES|on|ON) WITH_API_TOKEN=true ;;
esac
for arg in "$@"; do
    case "${arg}" in
        --with-api-token) WITH_API_TOKEN=true ;;
        *) echo "Unknown option: ${arg} (supported: --with-api-token)" >&2; exit 2 ;;
    esac
done

echo "═══════════════════════════════════════════════════"
echo "  Plexus Deployment Setup"
echo "═══════════════════════════════════════════════════"

# ── 1. Generate .env if it doesn't exist ──────────────────────────────
if [ ! -f .env ]; then
    echo ""
    echo "[1/3] Creating .env file..."

    # The static API token is opt-in (--with-api-token or
    # PLEXUS_ENABLE_API_TOKEN=true); new installs leave it empty.
    API_TOKEN=""
    if [ "${WITH_API_TOKEN}" = "true" ]; then
        API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null || openssl rand -base64 36)
    fi

    # Generate a random DB password
    DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 18)

    cat > .env << EOF
# ── Plexus Configuration ──────────────────────────────────────────────
APP_HOST=0.0.0.0
APP_PORT=8080
# nginx terminates TLS at port 443 in the bundled compose stack, so the
# app speaks plain HTTP inside the docker network. Set APP_HTTPS=true
# only if you are running the app without the nginx reverse proxy.
APP_HTTPS=false
APP_HSTS=true
# nginx terminates TLS, so the external scheme is HTTPS even though the app
# listens on plain HTTP. Mark session/CSRF cookies Secure so they never
# traverse plaintext.
APP_COOKIE_SECURE=true
APP_RELOAD=false

# Set this to your server's hostname/URL
APP_CORS_ORIGINS=https://$(hostname -f 2>/dev/null || echo "plexus.local")

# Static server API token for automation and federation peers. Empty
# means disabled (the default). A request that sends it as X-API-Token or
# Authorization: Bearer acts as an admin and skips CSRF, the per-IP API
# rate limit and the session limits, so treat it like a root password.
# To enable it, put a long random value here (for example the output of
# python3 -c "import secrets; print(secrets.token_urlsafe(48))") and run
# docker compose up -d. APP_REQUIRE_API_TOKEN=true additionally demands it
# on every /api/ request, which breaks browser sessions; leave it false.
APP_REQUIRE_API_TOKEN=false
APP_API_TOKEN=${API_TOKEN}

# Disable public registration
APP_ALLOW_SELF_REGISTER=false

# ── First login ───────────────────────────────────────────────────────
# The bootstrap 'admin' account is created on the very first boot (when no
# admin exists yet) with the password 'netcontrol', or the value below when
# set, and is flagged must-change, so you are forced to pick a real
# password at first login. Has no effect after that - use
# PLEXUS_FORCE_ADMIN_PASSWORD_RESET=true (one restart, then remove it) to
# recover a lost admin password.
PLEXUS_INITIAL_ADMIN_USERNAME=admin
PLEXUS_INITIAL_ADMIN_PASSWORD=

# ── Database ──────────────────────────────────────────────────────────
APP_DB_ENGINE=postgres
APP_DATABASE_URL=postgresql://plexus:${DB_PASSWORD}@postgres:5432/plexus
POSTGRES_DB=plexus
POSTGRES_USER=plexus
POSTGRES_PASSWORD=${DB_PASSWORD}
EOF

    # Holds the DB password: owner-only.
    chmod 600 .env
    if [ -n "${API_TOKEN}" ]; then
        echo "  Created .env with random API token and DB password."
    else
        echo "  Created .env with random DB password."
        echo "  APP_API_TOKEN is empty (disabled); re-run with --with-api-token on a"
        echo "  new install, or set it in .env, if automation needs it."
    fi
    echo "  Edit .env to set APP_CORS_ORIGINS to your actual hostname."
else
    echo "[1/3] .env already exists - skipping."
fi

# ── 2. Generate self-signed TLS certificate ───────────────────────────
CERT_DIR="certs"
if [ ! -f "${CERT_DIR}/cert.pem" ] || [ ! -f "${CERT_DIR}/key.pem" ]; then
    echo ""
    echo "[2/3] Generating self-signed TLS certificate..."
    mkdir -p "${CERT_DIR}"

    HOSTNAME=$(hostname -f 2>/dev/null || echo "plexus.local")

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -subj "/CN=${HOSTNAME}/O=Plexus" \
        -addext "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "${CERT_DIR}/key.pem"
    echo "  Certificate generated for: ${HOSTNAME}"
    echo "  Location: ${CERT_DIR}/cert.pem and ${CERT_DIR}/key.pem"
    echo ""
    echo "  To use your own CA-signed cert, replace these files."
else
    echo "[2/3] TLS certificates already exist - skipping."
fi

# Host side of the in-app update handoff, bind-mounted into the container by
# docker-compose.yml (deploy/plexus-updater.sh reads requests from it). Its
# status twin, state/update-status, must be root-owned: deploy/bootstrap.sh
# (or Docker, on first start) creates it, never this unprivileged script.
mkdir -p state/updates

# ── 3. Verify Docker is available ─────────────────────────────────────
echo ""
echo "[3/3] Checking Docker..."
if command -v docker &> /dev/null; then
    echo "  Docker version: $(docker --version)"
    if docker compose version &> /dev/null; then
        echo "  Docker Compose: $(docker compose version)"
    else
        echo "  WARNING: 'docker compose' not found. Install docker-compose-plugin."
        exit 1
    fi
else
    echo "  ERROR: Docker not found. Install Docker Engine + Compose plugin"
    echo "  from Docker's official repository (Ubuntu's docker.io package does"
    echo "  NOT include the compose plugin):"
    echo "    https://docs.docker.com/engine/install/"
    echo "  See deploy/DEPLOYMENT.md 'Step 1: Install Docker' for the full snippet."
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Setup complete! Next steps:"
echo ""
echo "  1. Review and edit .env (set APP_CORS_ORIGINS)"
echo "  2. Run:  docker compose up -d"
echo "  3. Open: https://$(hostname -f 2>/dev/null || echo 'your-vm-ip')"
echo "  4. Login as admin / netcontrol (or PLEXUS_INITIAL_ADMIN_PASSWORD if"
echo "     you set one in .env). You will be forced to change it at first login."
echo ""
echo "  To view logs:     docker compose logs -f plexus"
echo "  To stop:          docker compose down"
echo "  To update:        bash deploy/upgrade.sh"
echo "═══════════════════════════════════════════════════"
