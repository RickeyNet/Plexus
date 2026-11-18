#!/usr/bin/env bash
# Run a command, retrying (up to 3 attempts, 20s apart) only when it failed
# on a network error such as a pypi.org read timeout. Any other failure,
# for example pip-audit reporting a vulnerability, fails at once.
#
# Usage: tools/retry_on_network_error.sh <command> [args...]
set -u

attempts=3
network_error='ReadTimeout|ConnectTimeout|ConnectionError|Read timed out|Max retries exceeded|Temporary failure in name resolution|Connection reset by peer|HTTP Error 50[234]|status code 50[234]'
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

for attempt in $(seq 1 "$attempts"); do
  "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  if ! grep -Eq "$network_error" "$log"; then
    exit "$status"
  fi
  if [ "$attempt" -lt "$attempts" ]; then
    echo "::warning::network error on attempt $attempt of $attempts; retrying in 20s"
    sleep 20
  fi
done
echo "::error::still failing on network errors after $attempts attempts"
exit "$status"
