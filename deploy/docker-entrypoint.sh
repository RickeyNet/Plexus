#!/bin/sh

# Ensure firmware storage exists. Only chown that directory (not all of
# /app/state) so we do not fail on keys/db files in the named volume.
mkdir -p /app/state/software_images
chown -R plexus:plexus /app/state/software_images 2>/dev/null || true

exec gosu plexus "$@"
