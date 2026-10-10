# Set up a bash session to run Plexus from source against the development
# Postgres container (docker-compose.dev.yml, 127.0.0.1:5432).
#
# Source it from the repo root so the variables stay in your shell:
#
#   source scripts/dev-env.sh
#
# It reads POSTGRES_PASSWORD (and POSTGRES_USER / POSTGRES_DB, default
# plexus) from .env, exports APP_DB_ENGINE, APP_ENV and APP_DATABASE_URL, and
# activates .venv when it exists. templates/run.py does not read .env itself.

_plexus_dev_env_get() {
  grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- | tr -d '\r'
}

_plexus_dev_env() {
  if [ ! -f .env ]; then
    echo "dev-env: .env not found in $(pwd). Run 'bash deploy/setup.sh' from the repo root first, then source this script from the repo root." >&2
    return 1
  fi

  local pw user db
  pw=$(_plexus_dev_env_get POSTGRES_PASSWORD)
  user=$(_plexus_dev_env_get POSTGRES_USER)
  db=$(_plexus_dev_env_get POSTGRES_DB)
  user=${user:-plexus}
  db=${db:-plexus}

  if [ -z "$pw" ]; then
    echo "dev-env: POSTGRES_PASSWORD is missing or empty in .env. Run 'bash deploy/setup.sh' (on a fresh checkout) or set it in .env." >&2
    return 1
  fi

  export APP_DB_ENGINE=postgres APP_ENV=dev
  export APP_DATABASE_URL="postgresql://${user}:${pw}@127.0.0.1:5432/${db}"

  local venv="not found"
  if [ -f .venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
    venv="activated"
  elif [ -f .venv/Scripts/activate ]; then
    # shellcheck disable=SC1091
    source .venv/Scripts/activate
    venv="activated"
  fi

  echo "Plexus dev env: APP_DB_ENGINE=postgres APP_ENV=dev APP_DATABASE_URL=postgresql://${user}:***@127.0.0.1:5432/${db} (.venv ${venv})"
}

_plexus_dev_env
unset -f _plexus_dev_env _plexus_dev_env_get
