#!/bin/bash
# Install acme2certifier on RHEL/CentOS/Alma/Rocky 9 (Nginx + uWSGI) from PyPI (or local source).
#
# Install root: /opt/acme2certifier
# Requires: Python ≥ 3.7 (EL9). EL8 (Python 3.6) is not supported for this script.
#
# Usage:
#   ./examples/install_scripts/a2c-rel-nginx.sh [options]
#
# Options:
#   -m, --mode wsgi|django   DB/WSGI mode (default: wsgi)
#   -v, --version VERSION    pip pin, e.g. 0.45.dev1
#       --pre                allow pip pre-releases (--pre)
#       --from-source        pip install from current checkout (non-editable)
#   -h, --help               show help
#
# Examples:
#   ./examples/install_scripts/a2c-rel-nginx.sh
#   ./examples/install_scripts/a2c-rel-nginx.sh --mode django --version 0.45.dev1
#   ./examples/install_scripts/a2c-rel-nginx.sh --mode wsgi --from-source
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
APP_ROOT="/opt/acme2certifier"
VENV="${APP_ROOT}/venv"
CFG="${APP_ROOT}/acme_srv.cfg"
UWSGI_INI="${APP_ROOT}/acme2certifier.ini"
UWSGI_SOCK="/run/uwsgi/acme.sock"
NGINX_USER="nginx"

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
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

if [[ "${MODE}" != "${MODE_WSGI}" && "${MODE}" != "${MODE_DJANGO}" ]]; then
  echo "ERROR: --mode must be 'wsgi' or 'django' (got: ${MODE})" >&2
  exit 1
fi

if [[ $(id -u) -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

# uWSGI ini env lines: quote values so $ and (plugin) in secrets are not interpreted.
a2c_uwsgi_env_set() {
  local ini="$1" key="$2" value="$3" escaped
  escaped="$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\$/$$/g')"
  printf 'env = %s="%s"\n' "$key" "$escaped" | ${SUDO} tee -a "$ini" >/dev/null
}

if command -v dnf >/dev/null 2>&1; then
  PKG="dnf"
else
  PKG="yum"
fi

echo "==> Installing system packages (${PKG})"
${SUDO} ${PKG} install -y epel-release
${SUDO} ${PKG} install -y curl --allowerasing
${SUDO} ${PKG} install -y \
  nginx \
  uwsgi \
  uwsgi-plugin-python3 \
  python3 \
  python3-pip \
  python3-devel \
  gcc \
  tar \
  curl \
  openssl \
  policycoreutils-python-utils \
  checkpolicy \
  krb5-workstation \
  krb5-libs \
  krb5-devel \
  procps-ng

echo "==> Creating ${APP_ROOT} and venv"
${SUDO} mkdir -p "${APP_ROOT}/volume" /run/uwsgi
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

echo "==> Deploying acme_srv.cfg (mode=${MODE})"
${SUDO} cp "${SHARE}/acme_srv.cfg" "${CFG}"
${SUDO} mkdir -p "${APP_ROOT}/acme_srv"
${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"

if grep -qE '^handler:' "${CFG}"; then
  ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
else
  ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
fi

# dbfile path under APP_ROOT
if grep -qE '^dbfile:' "${CFG}"; then
  ${SUDO} sed -i "s|^dbfile:.*|dbfile: ${APP_ROOT}/acme_srv.db|" "${CFG}"
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
python-path = ${APP_ROOT}
module = ${UWSGI_MODULE}
master = true
processes = 5
uid = ${NGINX_USER}
gid = ${NGINX_USER}
socket = ${UWSGI_SOCK}
chown-socket = ${NGINX_USER}
chmod-socket = 660
vacuum = true
die-on-term = true
disable-logging = true
enable-threads = true
env = ACME_SRV_CONFIGFILE=${CFG}
env = ACME2CERTIFIER_BASE_DIR=${APP_ROOT}
EOF

echo "==> Deploying Nginx HTTP + SSL configs to /etc/nginx/conf.d/"
TMP_NGINX="$(mktemp -d)"
${SUDO} cp "${SHARE}/nginx/nginx_acme_srv.conf" "${TMP_NGINX}/"
${SUDO} cp "${SHARE}/nginx/nginx_acme_srv_ssl.conf" "${TMP_NGINX}/"
# Point TLS material and (if needed) socket at /opt layout
${SUDO} sed -i \
  -e "s|/var/www/acme2certifier|${APP_ROOT}|g" \
  -e "s|/run/uwsgi/acme.sock|${UWSGI_SOCK}|g" \
  "${TMP_NGINX}/nginx_acme_srv.conf" \
  "${TMP_NGINX}/nginx_acme_srv_ssl.conf"
${SUDO} cp "${TMP_NGINX}/nginx_acme_srv.conf" /etc/nginx/conf.d/nginx_acme_srv.conf
${SUDO} cp "${TMP_NGINX}/nginx_acme_srv_ssl.conf" /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
${SUDO} rm -rf "${TMP_NGINX}"

# RHEL default server often conflicts; drop default welcome page if present
${SUDO} rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

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
  if [[ -f ".github/acme_srv.openssl.cfg" ]]; then
    ${SUDO} cp .github/acme_srv.openssl.cfg "${CFG}"
    ${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"
    if grep -qE '^handler:' "${CFG}"; then
      ${SUDO} sed -i "s/^handler:.*/handler: ${MODE}/" "${CFG}"
    elif grep -q '^\[DBhandler\]' "${CFG}"; then
      ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
    else
      printf '\n[DBhandler]\nhandler: %s\n' "${MODE}" | ${SUDO} tee -a "${CFG}" >/dev/null
    fi
    if grep -qE '^dbfile:' "${CFG}"; then
      ${SUDO} sed -i "s|^dbfile:.*|dbfile: ${APP_ROOT}/acme_srv.db|" "${CFG}"
    fi
  fi
fi

if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
  echo "==> Django migrate + fixtures"
  if [[ -z "${ACME2CERTIFIER_SECRET_KEY:-}" ]]; then
    ACME2CERTIFIER_SECRET_KEY="$("${VENV}/bin/a2c-django-secret-keygen")"
  fi
  if ! grep -q 'ACME2CERTIFIER_SECRET_KEY=' "${UWSGI_INI}"; then
    a2c_uwsgi_env_set "${UWSGI_INI}" ACME2CERTIFIER_SECRET_KEY "${ACME2CERTIFIER_SECRET_KEY}"
  fi
  if [[ -n "${ACME2CERTIFIER_ALLOWED_HOSTS:-}" ]]; then
    ${SUDO} sed -i '/^env = ACME2CERTIFIER_ALLOWED_HOSTS=/d' "${UWSGI_INI}"
    a2c_uwsgi_env_set "${UWSGI_INI}" ACME2CERTIFIER_ALLOWED_HOSTS "${ACME2CERTIFIER_ALLOWED_HOSTS}"
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

echo "==> Permissions"
${SUDO} chown -R "${NGINX_USER}:${NGINX_USER}" "${APP_ROOT}"
${SUDO} chmod a+x "${APP_ROOT}/acme_srv"

echo "==> systemd unit for uWSGI"
${SUDO} tee /etc/systemd/system/acme2certifier.service >/dev/null <<EOF
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
RuntimeDirectory=uwsgi
User=${NGINX_USER}
Group=${NGINX_USER}
WorkingDirectory=${APP_ROOT}
Environment=PATH=${VENV}/bin:/usr/bin
Environment=ACME_SRV_CONFIGFILE=${CFG}
Environment=ACME2CERTIFIER_BASE_DIR=${APP_ROOT}
ExecStart=/usr/sbin/uwsgi --ini ${UWSGI_INI}
Restart=on-failure
Type=notify
NotifyAccess=all

[Install]
WantedBy=multi-user.target
EOF

# uwsgi binary path differs across RHEL builds
if [[ ! -x /usr/sbin/uwsgi ]] && [[ -x /usr/bin/uwsgi ]]; then
  ${SUDO} sed -i 's|/usr/sbin/uwsgi|/usr/bin/uwsgi|' /etc/systemd/system/acme2certifier.service
fi

echo "==> SELinux policy for Nginx ↔ uWSGI socket"
if command -v checkmodule >/dev/null 2>&1 && command -v semodule >/dev/null 2>&1; then
  TE_SRC="${SHARE}/nginx/acme2certifier.te"
  if [[ ! -f "${TE_SRC}" ]]; then
    TE_SRC=""
  fi
  TE_WORK="$(mktemp -d)"
  if [[ -n "${TE_SRC}" ]]; then
    ${SUDO} cp "${TE_SRC}" "${TE_WORK}/acme2certifier.te"
  else
    ${SUDO} tee "${TE_WORK}/acme2certifier.te" >/dev/null <<'EOT'
module acme2certifier 1.0;

require {
	type var_run_t;
	type initrc_t;
	type httpd_t;
	class sock_file write;
	class unix_stream_socket connectto;
}

#============= httpd_t ==============
allow httpd_t initrc_t:unix_stream_socket connectto;
allow httpd_t var_run_t:sock_file write;
EOT
  fi
  (
    cd "${TE_WORK}"
    ${SUDO} checkmodule -M -m -o acme2certifier.mod acme2certifier.te
    ${SUDO} semodule_package -o acme2certifier.pp -m acme2certifier.mod
    ${SUDO} semodule -i acme2certifier.pp || ${SUDO} semodule -u acme2certifier.pp || true
  )
  ${SUDO} rm -rf "${TE_WORK}"
else
  echo "SELinux tools not available; skipping policy install"
fi

echo "==> Enable and start services"
${SUDO} nginx -t
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable acme2certifier nginx
${SUDO} systemctl restart acme2certifier
${SUDO} systemctl restart nginx

echo "==> Done (mode=${MODE})"
echo "    App root: ${APP_ROOT}"
echo "    HTTP:     http://127.0.0.1/directory"
echo "    HTTPS:    https://127.0.0.1/directory  (self-signed unless you replaced ${CERT})"
echo "    Config:   ${CFG}"
echo "    uWSGI:    ${UWSGI_INI}  module=${UWSGI_MODULE}"
echo "    Check:    journalctl -u acme2certifier -n 50 --no-pager"
echo "              tail -n 50 /var/log/nginx/error.log" >&2
