#!/bin/bash
# Install acme2certifier on Ubuntu (Nginx + uWSGI) from PyPI (or local source).
#
# Usage:
#   ./examples/install_scripts/a2c-ubuntu-nginx.sh [options]
#
# Options:
#   -m, --mode wsgi|django   DB/WSGI mode (default: wsgi)
#   -v, --version VERSION    pip pin, e.g. 0.45.dev1
#       --pre                allow pip pre-releases (--pre)
#       --from-source        pip install from current checkout (non-editable)
#   -h, --help               show help
#
# Examples:
#   ./examples/install_scripts/a2c-ubuntu-nginx.sh
#   ./examples/install_scripts/a2c-ubuntu-nginx.sh --mode django --version 0.45.dev1
#   ./examples/install_scripts/a2c-ubuntu-nginx.sh --mode wsgi --from-source
#
# Requires: run from a checkout when using --from-source; otherwise installs from PyPI.

set -euo pipefail

MODE="wsgi"
VERSION=""
USE_PRE=0
FROM_SOURCE=0
APP_ROOT="/var/www/acme2certifier"
VENV="${APP_ROOT}/venv"
CFG="${APP_ROOT}/acme_srv.cfg"
UWSGI_INI="${APP_ROOT}/acme2certifier.ini"
UWSGI_SOCK="${APP_ROOT}/acme.sock"

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
      echo "Ignoring unrecognized argument: $1"
      shift
      ;;
  esac
done

if [[ "${MODE}" != "wsgi" && "${MODE}" != "django" ]]; then
  echo "ERROR: --mode must be 'wsgi' or 'django' (got: ${MODE})" >&2
  exit 1
fi

if [[ $(id -u) -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "==> Installing system packages"
${SUDO} apt-get update
${SUDO} apt-get install -y \
  nginx \
  uwsgi \
  uwsgi-plugin-python3 \
  python3-venv \
  python3-pip \
  curl \
  openssl \
  krb5-user \
  libgssapi-krb5-2 \
  libkrb5-3 \
  python3-gssapi

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
  # Non-editable so the app lives in the venv (same as PyPI installs).
  if [[ "${MODE}" == "django" ]]; then
    echo "==> pip install '.[django]' (from source)"
    ${SUDO} "${VENV}/bin/pip" install ".[django]"
  else
    echo "==> pip install . (from source)"
    ${SUDO} "${VENV}/bin/pip" install .
  fi
else
  if [[ "${MODE}" == "django" ]]; then
    SPEC="acme2certifier[django]"
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

echo "==> Deploying acme_srv.cfg (mode=${MODE})"
${SUDO} cp "${SHARE}/acme_srv.cfg" "${CFG}"
${SUDO} mkdir -p "${APP_ROOT}/acme_srv"
${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"

if grep -qE '^handler:' "${CFG}"; then
  ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
else
  ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
fi

if [[ "${MODE}" == "wsgi" ]]; then
  UWSGI_MODULE="acme2certifier_wsgi:application"
  ${SUDO} cp "${SHARE}/acme2certifier_wsgi.py" "${APP_ROOT}/"
else
  UWSGI_MODULE="acme2certifier.django_project.wsgi:application"
  ${SUDO} ln -sfn "${A2C_PKG}" "${APP_ROOT}/acme2certifier"
fi

echo "==> Writing uWSGI ini (${UWSGI_MODULE})"
${SUDO} tee "${UWSGI_INI}" >/dev/null <<EOF
[uwsgi]
plugins = python3
virtualenv = ${VENV}
chdir = ${APP_ROOT}
module = ${UWSGI_MODULE}
master = true
processes = 5
uid = www-data
gid = www-data
socket = ${UWSGI_SOCK}
chown-socket = www-data
chmod-socket = 660
vacuum = true
die-on-term = true
disable-logging = true
enable-threads = true
env = ACME_SRV_CONFIGFILE=${CFG}
env = ACME2CERTIFIER_BASE_DIR=${APP_ROOT}
EOF

echo "==> Deploying Nginx HTTP + SSL site configs"
TMP_NGINX="$(mktemp -d)"
${SUDO} cp "${SHARE}/nginx/nginx_acme_srv.conf" "${TMP_NGINX}/"
${SUDO} cp "${SHARE}/nginx/nginx_acme_srv_ssl.conf" "${TMP_NGINX}/"
# Use DocumentRoot socket path (writable by www-data)
${SUDO} sed -i "s|/run/uwsgi/acme.sock|${UWSGI_SOCK}|g" \
  "${TMP_NGINX}/nginx_acme_srv.conf" \
  "${TMP_NGINX}/nginx_acme_srv_ssl.conf"
${SUDO} cp "${TMP_NGINX}/nginx_acme_srv.conf" /etc/nginx/sites-available/acme_srv.conf
${SUDO} cp "${TMP_NGINX}/nginx_acme_srv_ssl.conf" /etc/nginx/sites-available/acme_srv_ssl.conf
${SUDO} rm -rf "${TMP_NGINX}"

${SUDO} rm -f /etc/nginx/sites-enabled/default
${SUDO} ln -sfn /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
${SUDO} ln -sfn /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf

echo "==> TLS certificate/key for Nginx SSL server"
CERT="${APP_ROOT}/volume/acme2certifier_cert.pem"
KEY="${APP_ROOT}/volume/acme2certifier_key.pem"
if [[ -f ".github/acme2certifier_cert.pem" && -f ".github/acme2certifier_key.pem" ]]; then
  ${SUDO} cp .github/acme2certifier_cert.pem "${CERT}"
  ${SUDO} cp .github/acme2certifier_key.pem "${KEY}"
elif [[ -f "${CERT}" && -f "${KEY}" ]]; then
  echo "Using existing ${CERT} / ${KEY}"
else
  echo "Generating self-signed ${CERT} / ${KEY}"
  ${SUDO} openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${KEY}" \
    -out "${CERT}" \
    -days 365 \
    -subj "/CN=localhost"
fi

# Optional lab OpenSSL CA material when present in checkout
if [[ -d "test/ca" ]]; then
  echo "==> Installing example OpenSSL CA material from test/ca"
  ${SUDO} mkdir -p "${APP_ROOT}/volume/acme_ca/certs"
  ${SUDO} cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem \
    test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem \
    "${APP_ROOT}/volume/acme_ca/" || true
  if [[ -f ".github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg" ]]; then
    ${SUDO} cp .github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg "${CFG}"
    ${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"
    if grep -qE '^handler:' "${CFG}"; then
      ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
    elif grep -q '^\[DBhandler\]' "${CFG}"; then
      ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
    else
      printf '\n[DBhandler]\nhandler: %s\n' "${MODE}" | ${SUDO} tee -a "${CFG}" >/dev/null
    fi
  fi
fi

if [[ "${MODE}" == "django" ]]; then
  echo "==> Django migrate + fixtures"
  if [[ -z "${ACME2CERTIFIER_SECRET_KEY:-}" ]]; then
    ACME2CERTIFIER_SECRET_KEY="$("${VENV}/bin/a2c-django-secret-keygen")"
  fi
  # Persist secret for the uWSGI service
  if ! grep -q 'ACME2CERTIFIER_SECRET_KEY=' "${UWSGI_INI}"; then
    echo "env = ACME2CERTIFIER_SECRET_KEY=${ACME2CERTIFIER_SECRET_KEY}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
  fi
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    "${VENV}/bin/a2c-manage" migrate
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    "${VENV}/bin/a2c-manage" loaddata status
fi

echo "==> Permissions"
${SUDO} chown -R www-data:www-data "${APP_ROOT}"

echo "==> systemd unit for uWSGI"
${SUDO} tee /etc/systemd/system/acme2certifier.service >/dev/null <<EOF
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=${APP_ROOT}
Environment=PATH=${VENV}/bin:/usr/bin
Environment=ACME_SRV_CONFIGFILE=${CFG}
Environment=ACME2CERTIFIER_BASE_DIR=${APP_ROOT}
ExecStart=/usr/bin/uwsgi --ini ${UWSGI_INI}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "==> Enable and start services"
${SUDO} nginx -t
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable acme2certifier nginx
${SUDO} systemctl restart acme2certifier
${SUDO} systemctl restart nginx

echo "==> Done (mode=${MODE})"
echo "    HTTP:  http://127.0.0.1/directory"
echo "    HTTPS: https://127.0.0.1/directory  (self-signed unless you replaced ${CERT})"
echo "    Config: ${CFG}"
echo "    uWSGI:  ${UWSGI_INI}  module=${UWSGI_MODULE}"
echo "    Check:  journalctl -u acme2certifier -n 50 --no-pager"
echo "            tail -n 50 /var/log/nginx/error.log"
