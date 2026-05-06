#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Deployment Setup Script
# Run this once on the VM before 'docker compose up'
# ═══════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════"
echo "  Plexus Deployment Setup"
echo "═══════════════════════════════════════════════════"

# ── 1. Generate .env if it doesn't exist ──────────────────────────────
if [ ! -f .env ]; then
    echo ""
    echo "[1/3] Creating .env file..."

    # Generate a random API token
    API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null || openssl rand -base64 36)

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
APP_RELOAD=false

# Set this to your server's hostname/URL
APP_CORS_ORIGINS=https://$(hostname -f 2>/dev/null || echo "plexus.local")

# API token for service-to-service access
APP_REQUIRE_API_TOKEN=true
APP_API_TOKEN=${API_TOKEN}

# Disable public registration
APP_ALLOW_SELF_REGISTER=false

# ── Database ──────────────────────────────────────────────────────────
APP_DB_ENGINE=postgres
APP_DATABASE_URL=postgresql://plexus:${DB_PASSWORD}@postgres:5432/plexus
POSTGRES_DB=plexus
POSTGRES_USER=plexus
POSTGRES_PASSWORD=${DB_PASSWORD}
EOF

    echo "  Created .env with random API token and DB password."
    echo "  Edit .env to set APP_CORS_ORIGINS to your actual hostname."
else
    echo "[1/3] .env already exists — skipping."
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
    echo "[2/3] TLS certificates already exist — skipping."
fi

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
echo "  4. Login: admin / netcontrol (forced password change)"
echo ""
echo "  To view logs:     docker compose logs -f plexus"
echo "  To stop:          docker compose down"
echo "  To update:        git pull && docker compose up -d --build"
echo "═══════════════════════════════════════════════════"
