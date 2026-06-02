#!/bin/sh
set -e

# Ensure state dirs exist and are owned by the app user. Bind mounts from the
# host (e.g. ./software_images) are often created root:root by Docker; without
# this step firmware uploads fail with 503 when the plexus user cannot write.
mkdir -p /app/state/software_images
chown -R plexus:plexus /app/state

exec su --preserve-environment -s /bin/sh plexus -c 'exec "$@"' sh "$@"
