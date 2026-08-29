#!/bin/bash
# Install acme2certifier on Ubuntu (Apache2 + mod_wsgi) from PyPI (or local source).
#
# Usage:
#   ./examples/install_scripts/a2c-ubuntu-apache2.sh [options]
#
# Options:
#   -m, --mode wsgi|django   DB/WSGI mode (default: wsgi)
#   -v, --version VERSION    pip pin, e.g. 0.45.dev1
#       --pre                allow pip pre-releases (--pre)
#       --from-source        pip install from current checkout (non-editable)
#   -h, --help               show help
#
# Examples:
#   ./examples/install_scripts/a2c-ubuntu-apache2.sh
#   ./examples/install_scripts/a2c-ubuntu-apache2.sh --mode django --version 0.45.dev1
#   ./examples/install_scripts/a2c-ubuntu-apache2.sh --mode wsgi --from-source
#
# Requires: run from a checkout when using --from-source; otherwise installs from PyPI.

set -euo pipefail

readonly MODE_DJANGO="django"
readonly MODE_WSGI="wsgi"
readonly DJANGO_SETTINGS="acme2certifier.django_project.settings"

MODE="wsgi"
VERSION=""
USE_PRE=0
FROM_SOURCE=0
APP_ROOT="/var/www/acme2certifier"
VENV="${APP_ROOT}/venv"
CFG="${APP_ROOT}/acme_srv.cfg"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE="${2:-}"
      shift 2
      ;;
    -v|--version)
      VERSION="${2:-}"
      shift 2
      ;;
    --pre)
      USE_PRE=1
      shift
      ;;
    --from-source|--local)
      FROM_SOURCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    wsgi|django)
      MODE="$1"
      shift
      ;;
    *)
      # Legacy CI passed the branch name as $1 and the script ignored it.
      echo "Ignoring unrecognized argument: $1"
      shift
      ;;
  esac
done

if [[ "${MODE}" != "${MODE_WSGI}" && "${MODE}" != "${MODE_DJANGO}" ]]; then
  echo "ERROR: --mode must be 'wsgi' or 'django' (got: ${MODE})" >&2
  exit 1
fi

if [[ $(id -u) -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

a2c_apache_envvar_set() {
  local key="$1" value="$2"
  printf 'export %s=%q\n' "$key" "$value" | ${SUDO} tee -a /etc/apache2/envvars >/dev/null
}

echo "==> Installing system packages"
${SUDO} apt-get update
${SUDO} apt-get install -y \
  apache2 \
  libapache2-mod-wsgi-py3 \
  apache2-data \
  python3-venv \
  python3-pip \
  curl \
  openssl \
  krb5-user \
  libgssapi-krb5-2 \
  libkrb5-3 \
  python3-gssapi

echo "==> Enabling Apache modules (wsgi, ssl)"
${SUDO} a2enmod wsgi
${SUDO} a2enmod ssl
apache2ctl -M | grep -i wsgi
apache2ctl -M | grep -i ssl

echo "==> Creating ${APP_ROOT} and venv"
${SUDO} mkdir -p "${APP_ROOT}/volume"
${SUDO} python3 -m venv "${VENV}"
${SUDO} "${VENV}/bin/pip" install -U pip

PIP_ARGS=()
if [[ "${USE_PRE}" -eq 1 ]]; then
  PIP_ARGS+=(--pre)
fi

if [[ "${FROM_SOURCE}" -eq 1 ]]; then
  if [[ ! -f "pyproject.toml" ]]; then
    echo "ERROR: --from-source requires running from the repository root" >&2
    exit 1
  fi
  # Non-editable: mod_wsgi must load the package from the venv, not a
  # checkout path (editable installs break under Apache python-home).
  if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
    echo "==> pip install '.[${MODE_DJANGO}]' (from source)"
    ${SUDO} "${VENV}/bin/pip" install ".[${MODE_DJANGO}]"
  else
    echo "==> pip install . (from source)"
    ${SUDO} "${VENV}/bin/pip" install .
  fi
else
  if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
    SPEC="acme2certifier[${MODE_DJANGO}]"
  else
    SPEC="acme2certifier"
  fi
  if [[ -n "${VERSION}" ]]; then
    SPEC="${SPEC}==${VERSION}"
  fi
  echo "==> pip install ${SPEC}"
  ${SUDO} "${VENV}/bin/pip" install "${PIP_ARGS[@]}" "${SPEC}"
fi

SHARE="$(${SUDO} "${VENV}/bin/python" -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")"
A2C_PKG="$(${SUDO} "${VENV}/bin/python" -c \
  "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")"

echo "==> Deploying config and Apache vhosts (mode=${MODE})"
${SUDO} cp "${SHARE}/acme_srv.cfg" "${CFG}"
${SUDO} mkdir -p "${APP_ROOT}/acme_srv"
${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"

# Ensure DBhandler selection matches mode
if grep -qE '^handler:' "${CFG}"; then
  ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
else
  ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
fi

if [[ "${MODE}" == "wsgi" ]]; then
  ${SUDO} cp "${SHARE}/acme2certifier_wsgi.py" "${APP_ROOT}/"
  ${SUDO} cp "${SHARE}/apache2/apache_wsgi.conf" \
    /etc/apache2/sites-available/acme2certifier.conf
  ${SUDO} cp "${SHARE}/apache2/apache_wsgi_ssl.conf" \
    /etc/apache2/sites-available/acme2certifier_ssl.conf
else
  # Apache django vhost expects DocumentRoot/.../acme2certifier/django_project/wsgi.py
  ${SUDO} ln -sfn "${A2C_PKG}" "${APP_ROOT}/acme2certifier"
  ${SUDO} cp "${SHARE}/apache2/apache_django.conf" \
    /etc/apache2/sites-available/acme2certifier.conf
  ${SUDO} cp "${SHARE}/apache2/apache_django_ssl.conf" \
    /etc/apache2/sites-available/acme2certifier_ssl.conf
fi

# ACME config path for Apache workers (mod_wsgi does not support environ= on Ubuntu)
if ! grep -q 'ACME_SRV_CONFIGFILE=' /etc/apache2/envvars 2>/dev/null; then
  echo "export ACME_SRV_CONFIGFILE=${CFG}" | ${SUDO} tee -a /etc/apache2/envvars >/dev/null
fi
if ! grep -q 'ACME2CERTIFIER_BASE_DIR=' /etc/apache2/envvars 2>/dev/null; then
  echo "export ACME2CERTIFIER_BASE_DIR=${APP_ROOT}" | ${SUDO} tee -a /etc/apache2/envvars >/dev/null
fi

echo "==> TLS certificate for Apache SSL vhost"
PEM="${APP_ROOT}/volume/acme2certifier.pem"
if [[ -f ".github/acme2certifier.pem" ]]; then
  ${SUDO} cp .github/acme2certifier.pem "${PEM}"
elif [[ -f "${PEM}" ]]; then
  echo "Using existing ${PEM}"
else
  echo "Generating self-signed ${PEM}"
  ${SUDO} openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${APP_ROOT}/volume/acme2certifier-key.pem" \
    -out "${APP_ROOT}/volume/acme2certifier-cert.pem" \
    -days 365 \
    -subj "/CN=localhost"
  ${SUDO} sh -c "cat '${APP_ROOT}/volume/acme2certifier-cert.pem' \
    '${APP_ROOT}/volume/acme2certifier-key.pem' > '${PEM}'"
fi

# Optional lab OpenSSL CA material when present in checkout
if [[ -d "test/ca" ]]; then
  echo "==> Installing example OpenSSL CA material from test/ca"
  ${SUDO} mkdir -p "${APP_ROOT}/volume/acme_ca/certs"
  ${SUDO} cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem \
    test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem \
    "${APP_ROOT}/volume/acme_ca/" || true
  if [[ -f ".github/acme_srv.openssl.cfg" ]]; then
    ${SUDO} cp .github/acme_srv.openssl.cfg "${CFG}"
    ${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"
    # re-apply handler after overwriting cfg
    if grep -qE '^handler:' "${CFG}"; then
      ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
    elif grep -q '^\[DBhandler\]' "${CFG}"; then
      ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
    else
      printf '\n[DBhandler]\nhandler: %s\n' "${MODE}" | ${SUDO} tee -a "${CFG}" >/dev/null
    fi
  fi
fi

if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
  echo "==> Django migrate + fixtures"
  export ACME_SRV_CONFIGFILE="${CFG}"
  export ACME2CERTIFIER_BASE_DIR="${APP_ROOT}"
  export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}"
  if [[ -z "${ACME2CERTIFIER_SECRET_KEY:-}" ]]; then
    export ACME2CERTIFIER_SECRET_KEY="$("${VENV}/bin/a2c-django-secret-keygen")"
  fi
  if ! grep -q 'ACME2CERTIFIER_SECRET_KEY=' /etc/apache2/envvars 2>/dev/null; then
    a2c_apache_envvar_set ACME2CERTIFIER_SECRET_KEY "${ACME2CERTIFIER_SECRET_KEY}"
  fi
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}" \
    "${VENV}/bin/a2c-manage" migrate
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}" \
    "${VENV}/bin/a2c-manage" loaddata status
fi

echo "==> Permissions and site enable"
${SUDO} chown -R www-data:www-data "${APP_ROOT}"
${SUDO} a2dissite 000-default.conf 2>/dev/null || true
${SUDO} a2dissite default-ssl.conf 2>/dev/null || true
${SUDO} a2ensite acme2certifier.conf
${SUDO} a2ensite acme2certifier_ssl.conf
${SUDO} apache2ctl configtest
${SUDO} systemctl enable apache2
${SUDO} systemctl restart apache2

echo "==> Done (mode=${MODE})"
echo "    HTTP:  http://127.0.0.1/directory"
echo "    HTTPS: https://127.0.0.1/directory  (self-signed unless you replaced ${PEM})"
echo "    Config: ${CFG}"
echo "    Check:  tail -n 50 /var/log/apache2/error.log" >&2
