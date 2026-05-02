#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Plexus Backup Script
#
# Backs up:
#   1. PostgreSQL database (pg_dump)
#   2. /app/state volume (netcontrol.key, session.key, sqlite db if used)
#
# Losing netcontrol.key permanently breaks decryption of stored device
# credentials, so the state volume is just as important as the database.
#
# Usage:
#   bash deploy/backup.sh                  # backup to default destination
#   BACKUP_DEST=/mnt/nas/plexus backup.sh  # override destination
#
# Schedule via /etc/cron.d/plexus (see deploy/plexus.cron).
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────
BACKUP_DEST="${BACKUP_DEST:-/var/backups/plexus}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# Compose project name = directory name unless overridden via COMPOSE_PROJECT_NAME.
# Volume names are <project>_<volume>.
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(cd "$(dirname "$0")/.." && pwd)")}"
STATE_VOLUME="${PROJECT}_plexus-db"

POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-plexus-postgres}"
POSTGRES_USER="${POSTGRES_USER:-plexus}"
POSTGRES_DB="${POSTGRES_DB:-plexus}"

DATE="$(date +%Y%m%d-%H%M%S)"

# ── Run ───────────────────────────────────────────────────────────────
mkdir -p "${BACKUP_DEST}"

echo "[$(date -Iseconds)] Plexus backup starting → ${BACKUP_DEST}"

# 1. Database dump
DB_FILE="${BACKUP_DEST}/db-${DATE}.sql.gz"
docker exec "${POSTGRES_CONTAINER}" pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" \
    | gzip > "${DB_FILE}"
echo "  db   → ${DB_FILE} ($(du -h "${DB_FILE}" | cut -f1))"

# 2. State volume (encryption + session keys)
STATE_FILE="${BACKUP_DEST}/state-${DATE}.tar.gz"
docker run --rm \
    -v "${STATE_VOLUME}:/src:ro" \
    -v "${BACKUP_DEST}:/dest" \
    alpine \
    tar czf "/dest/state-${DATE}.tar.gz" -C /src .
echo "  keys → ${STATE_FILE} ($(du -h "${STATE_FILE}" | cut -f1))"

# 3. Prune old backups
find "${BACKUP_DEST}" -maxdepth 1 -type f \
    \( -name 'db-*.sql.gz' -o -name 'state-*.tar.gz' \) \
    -mtime +"${RETENTION_DAYS}" -delete

echo "[$(date -Iseconds)] Plexus backup complete (retention: ${RETENTION_DAYS}d)"
