#!/usr/bin/env bash
# Build ACME2CERTIFIER_* for CI Django jobs (DATABASE_URL instead of vendor settings.py).
#
# Usage:
#   django_ci_database_url.sh --django-db mariadb|psql|mssql|sqlite3 \
#     [--host HOST] [--password PASS] [--secret KEY] \
#     [--env-file PATH] [--github-env] [--allowed-hosts HOSTS]
#
# Writes KEY='VALUE' lines to --env-file (default: django.env in cwd).
# Single quotes survive `source` when the value contains & (MSSQL, Postgres TLS).
# With --github-env, appends unquoted lines to $GITHUB_ENV (the runner does not
# use bash source).
set -euo pipefail

DJANGO_DB=""
DB_HOST=""
DB_PASSWORD="1mmSvDFl"
SECRET_KEY=""
ENV_FILE=""
WRITE_GITHUB_ENV=0
ALLOWED_HOSTS="127.0.0.1,*"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# //;s/^#//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --django-db)
      DJANGO_DB="${2:-}"
      shift 2
      ;;
    --host)
      DB_HOST="${2:-}"
      shift 2
      ;;
    --password)
      DB_PASSWORD="${2:-}"
      shift 2
      ;;
    --secret)
      SECRET_KEY="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --allowed-hosts)
      ALLOWED_HOSTS="${2:-}"
      shift 2
      ;;
    --github-env)
      WRITE_GITHUB_ENV=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${DJANGO_DB}" ]]; then
  echo "ERROR: --django-db is required" >&2
  exit 2
fi

if [[ -z "${SECRET_KEY}" ]]; then
  SECRET_KEY="$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")"
fi

if [[ -z "${ENV_FILE}" ]]; then
  ENV_FILE="django.env"
fi

DATABASE_URL=""
case "${DJANGO_DB}" in
  sqlite3|"")
    DATABASE_URL=""
    ;;
  mariadb)
    : "${DB_HOST:=mariadbsrv.acme}"
    DATABASE_URL="mysql://acme2certifier:${DB_PASSWORD}@${DB_HOST}/acme2certifier"
    ;;
  psql)
    : "${DB_HOST:=postgresdbsrv}"
    DATABASE_URL="postgres://acme2certifier:${DB_PASSWORD}@${DB_HOST}/acme2certifier"
    ;;
  mssql)
    : "${DB_HOST:=ms-sql.acme}"
    DATABASE_URL="mssql://acme2certifier_user:${DB_PASSWORD}@${DB_HOST}:1433/acme2certifier?driver=ODBC+Driver+18+for+SQL+Server&extra_params=Encrypt%3Dno%3BTrustServerCertificate%3Dyes"
    ;;
  *)
    echo "ERROR: unsupported --django-db=${DJANGO_DB} (expected mariadb|psql|mssql|sqlite3)" >&2
    exit 2
    ;;
esac

# bash source: 'it'\''s' is the only safe quote. Values here have no newlines.
shell_quote() {
  local v="$1"
  v="${v//\'/\'\\\'\'}"
  printf "'%s'" "${v}"
}

mkdir -p "$(dirname "${ENV_FILE}")"
{
  printf 'ACME2CERTIFIER_SECRET_KEY=%s\n' "$(shell_quote "${SECRET_KEY}")"
  printf 'ACME2CERTIFIER_ALLOWED_HOSTS=%s\n' "$(shell_quote "${ALLOWED_HOSTS}")"
  if [[ -n "${DATABASE_URL}" ]]; then
    printf 'ACME2CERTIFIER_DATABASE_URL=%s\n' "$(shell_quote "${DATABASE_URL}")"
  fi
} > "${ENV_FILE}"

if [[ "${WRITE_GITHUB_ENV}" -eq 1 && -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'ACME2CERTIFIER_SECRET_KEY=%s\n' "${SECRET_KEY}"
    printf 'ACME2CERTIFIER_ALLOWED_HOSTS=%s\n' "${ALLOWED_HOSTS}"
    if [[ -n "${DATABASE_URL}" ]]; then
      printf 'ACME2CERTIFIER_DATABASE_URL=%s\n' "${DATABASE_URL}"
    fi
  } >> "${GITHUB_ENV}"
fi

echo "Wrote ${ENV_FILE} (DJANGO_DB=${DJANGO_DB})"
