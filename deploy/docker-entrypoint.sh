#!/bin/sh

# Ensure firmware storage and the in-app update handoff directory exist.
# Only chown those directories (not all of /app/state) so we do not fail on
# keys/db files in the named volume.
mkdir -p /app/state/software_images /app/state/updates
chown -R plexus:plexus /app/state/software_images 2>/dev/null || true
chown -R plexus:plexus /app/state/updates 2>/dev/null || true

exec gosu plexus "$@"
