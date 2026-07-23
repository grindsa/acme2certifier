#!/bin/bash
# Install acme2certifier from a local .rpm (Nginx + uWSGI) on EL8 / EL9.
#
# Install root: /opt/acme2certifier (RPM layout; PYTHONPATH-based, Python 3.6+).
# For PyPI/venv on EL9 only, use a2c-rel-nginx.sh instead.
#
# Usage:
#   ./examples/install_scripts/a2c-rpm.sh --rpm PATH [options]
#   ./examples/install_scripts/a2c-rpm.sh install|restart|update [options]
#
# Options:
#   -r, --rpm PATH              path to acme2certifier-*.noarch.rpm (required unless
#                               a matching .rpm is found in . / .. / data-dir)
#   -m, --mode wsgi|django      application mode (default: wsgi)
#       --restart               sync volume/cfg and restart nginx + acme2certifier
#       --update                sync volume/acme_ca only (no restart)
#       --volume-dir DIR        sync DIR into APP_ROOT/volume (default: use
#                               /tmp/acme2certifier/volume when present)
#       --data-dir DIR          search root for .rpm / MSSQL repo pkg
#                               (default: /tmp/acme2certifier when present)
#       --no-ssl                skip copying SSL nginx vhost / generating TLS material
#   -h, --help                  show help
#
# Examples:
#   ./examples/install_scripts/a2c-rpm.sh --rpm ./acme2certifier-0.45.dev1-1.0.noarch.rpm
#   ./examples/install_scripts/a2c-rpm.sh -r ../acme2certifier-*.rpm -m django
#   ./examples/install_scripts/a2c-rpm.sh install -m wsgi --no-ssl
#   ./examples/install_scripts/a2c-rpm.sh restart
#   ./examples/install_scripts/a2c-rpm.sh --update --volume-dir /tmp/acme2certifier/volume
#
# Notes:
#   - Works on AlmaLinux / RHEL / Rocky / CentOS Stream 8 and 9 (dnf or yum).
#   - Installs EPEL + nginx + uWSGI stack (soft Recommends of the RPM).
#   - EL8 may need newer cryptography/dns/jwcrypto from the A2C RPM repo; see
#     docs/install_rpm.md. CI installs those via .github/actions/rpm_prep.
#   - MSSQL (msodbcsql18 / mssql-django) is also installed by rpm_prep when
#     DJANGO_DB=mssql — not by this script.
#   - CI-only host tweaks (syslog-ng/krb5, nginx.conf trim) stay in rpm_prep, not here.

set -euo pipefail

MODE="wsgi"
ACTION="install"
RPM_PATH=""
RPM_GLOBS=()
ENABLE_SSL=1
VOLUME_DIR=""
DATA_DIR=""
APP_ROOT="/opt/acme2certifier"
CFG="${APP_ROOT}/acme_srv.cfg"
SHARE="${APP_ROOT}/share"
UWSGI_INI="${APP_ROOT}/acme2certifier.ini"
NGINX_USER="nginx"

usage() {
  sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
}

find_rpm() {
  local candidate
  local candidates=()

  if [[ ${#RPM_GLOBS[@]} -gt 1 ]]; then
    ls -1t "${RPM_GLOBS[@]}" 2>/dev/null | head -n 1
    return 0
  fi
  if [[ ${#RPM_GLOBS[@]} -eq 1 ]]; then
    candidate="${RPM_GLOBS[0]}"
    # shellcheck disable=SC2086
    if compgen -G "${candidate}" >/dev/null 2>&1; then
      # shellcheck disable=SC2086
      ls -1t ${candidate} 2>/dev/null | head -n 1
      return 0
    fi
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  elif [[ -n "${RPM_PATH}" ]]; then
    candidates+=("${RPM_PATH}")
  fi
  if [[ -n "${DATA_DIR}" ]]; then
    candidates+=("${DATA_DIR}/acme2certifier-*.noarch.rpm" "${DATA_DIR}/acme2certifier-*.rpm")
  fi
  candidates+=("./acme2certifier-*.noarch.rpm" "./acme2certifier-*.rpm")
  candidates+=("../acme2certifier-*.noarch.rpm" "../acme2certifier-*.rpm")
  candidates+=("/tmp/acme2certifier/acme2certifier-*.noarch.rpm" "/tmp/acme2certifier/acme2certifier-*.rpm")
  for candidate in "${candidates[@]}"; do
    # shellcheck disable=SC2086
    if compgen -G "${candidate}" >/dev/null 2>&1; then
      # shellcheck disable=SC2086
      ls -1t ${candidate} 2>/dev/null | head -n 1
      return 0
    fi
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

el_major() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ -n "${VERSION_ID:-}" ]]; then
      echo "${VERSION_ID%%.*}"
      return 0
    fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -E '%{rhel}' 2>/dev/null || echo "unknown"
    return 0
  fi
  echo "unknown"
}

resolve_defaults() {
  if [[ -z "${DATA_DIR}" && -d /tmp/acme2certifier ]]; then
    DATA_DIR="/tmp/acme2certifier"
  fi
  if [[ -z "${VOLUME_DIR}" ]]; then
    if [[ -n "${DATA_DIR}" && -d "${DATA_DIR}/volume" ]]; then
      VOLUME_DIR="${DATA_DIR}/volume"
    elif [[ -d /tmp/acme2certifier/volume ]]; then
      VOLUME_DIR="/tmp/acme2certifier/volume"
    fi
  fi
}

sync_volume() {
  local vol="${1:-}"
  if [[ -z "${vol}" || ! -d "${vol}" ]]; then
    echo "==> No volume dir to sync (skip)"
    return 0
  fi
  echo "==> Syncing volume from ${vol} -> ${APP_ROOT}/volume"
  ${SUDO} mkdir -p "${APP_ROOT}/volume"
  ${SUDO} cp -a "${vol}/." "${APP_ROOT}/volume/"
  if [[ -f "${vol}/acme_srv.cfg" ]]; then
    ${SUDO} cp -f "${vol}/acme_srv.cfg" "${CFG}"
  fi
}

sync_acme_ca_only() {
  local vol="${1:-}"
  if [[ -z "${vol}" || ! -d "${vol}/acme_ca" ]]; then
    echo "ERROR: --update requires ${vol:-<volume-dir>}/acme_ca" >&2
    exit 1
  fi
  echo "==> Updating acme_ca from ${vol}/acme_ca"
  ${SUDO} mkdir -p "${APP_ROOT}/volume/acme_ca"
  ${SUDO} cp -a "${vol}/acme_ca/." "${APP_ROOT}/volume/acme_ca/"
}

link_django_settings_from_volume() {
  local vol="${1:-}"
  local settings_py="${APP_ROOT}/acme2certifier/django_project/settings.py"
  local src=""
  # Prefer APP_ROOT/volume so settings survive PrivateTmp / ephemeral /tmp mounts.
  if [[ -f "${APP_ROOT}/volume/settings.py" ]]; then
    src="${APP_ROOT}/volume/settings.py"
  elif [[ -f "${APP_ROOT}/volume/acme2certifier/settings.py" ]]; then
    src="${APP_ROOT}/volume/acme2certifier/settings.py"
  elif [[ -n "${vol}" && -f "${vol}/settings.py" ]]; then
    ${SUDO} mkdir -p "${APP_ROOT}/volume"
    ${SUDO} cp -f "${vol}/settings.py" "${APP_ROOT}/volume/settings.py"
    src="${APP_ROOT}/volume/settings.py"
  elif [[ -n "${DATA_DIR}" && -f "${DATA_DIR}/acme2certifier/settings.py" ]]; then
    # rpm_prep historically staged settings under data/acme2certifier/
    ${SUDO} mkdir -p "${APP_ROOT}/volume"
    ${SUDO} cp -f "${DATA_DIR}/acme2certifier/settings.py" "${APP_ROOT}/volume/settings.py"
    src="${APP_ROOT}/volume/settings.py"
  elif [[ -f "${APP_ROOT}/examples/django/settings.py" ]]; then
    ${SUDO} cp "${APP_ROOT}/examples/django/settings.py" "${settings_py}"
    return 0
  fi
  if [[ -n "${src}" ]]; then
    echo "==> Linking Django settings from ${src}"
    ${SUDO} rm -f "${settings_py}"
    ${SUDO} ln -sfn "${src}" "${settings_py}"
  fi
}

# Set [DBhandler] handler=MODE without touching [CAhandler] handler_module.
set_dbhandler_mode() {
  local mode="$1"
  echo "==> Setting DBhandler to ${mode}"
  if ! ${SUDO} grep -q '^\[DBhandler\]' "${CFG}"; then
    printf '\n[DBhandler]\nhandler: %s\n' "${mode}" | ${SUDO} tee -a "${CFG}" >/dev/null
    return 0
  fi
  # Drop handler / handler_module only inside [DBhandler].
  ${SUDO} sed -i \
    '/^\[DBhandler\]/,/^\[/{
      /^\[DBhandler\]/b
      /^\[/b
      /^[[:space:]]*#*[[:space:]]*handler\(_module\)\?:/d
    }' "${CFG}"
  ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${mode}" "${CFG}"
}

maybe_overlay_nginx_from_data() {
  if [[ -n "${DATA_DIR}" && -d "${DATA_DIR}/nginx" ]]; then
    echo "==> Overlaying nginx configs from ${DATA_DIR}/nginx"
    ${SUDO} mkdir -p /etc/nginx
    ${SUDO} cp -a "${DATA_DIR}/nginx/." /etc/nginx/
  fi
}

restart_services() {
  echo "==> Restarting acme2certifier + nginx"
  ${SUDO} systemctl restart acme2certifier.service
  ${SUDO} systemctl restart nginx.service
}

do_restart() {
  echo "==> Restart mode (no package reinstall)"
  if [[ -z "${VOLUME_DIR}" || ! -d "${VOLUME_DIR}" ]]; then
    echo "ERROR: --restart requires a volume dir (pass --volume-dir or mount /tmp/acme2certifier/volume)" >&2
    exit 1
  fi
  if [[ -f "${VOLUME_DIR}/acme_srv.cfg" ]]; then
    ${SUDO} cp -f "${VOLUME_DIR}/acme_srv.cfg" "${CFG}"
  fi
  sync_volume "${VOLUME_DIR}"
  ${SUDO} chown -R "${NGINX_USER}:${NGINX_USER}" "${APP_ROOT}/volume" || true
  restart_services
  echo "Done. restarted nginx + acme2certifier"
}

do_update() {
  echo "==> Update mode (acme_ca only, no restart)"
  if [[ -z "${VOLUME_DIR}" || ! -d "${VOLUME_DIR}" ]]; then
    echo "ERROR: --update requires a volume dir" >&2
    exit 1
  fi
  sync_acme_ca_only "${VOLUME_DIR}"
  echo "Done. updated ${APP_ROOT}/volume/acme_ca"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|restart|update)
      ACTION="$1"
      shift
      ;;
    --restart)
      ACTION="restart"
      shift
      ;;
    --update)
      ACTION="update"
      shift
      ;;
    -r|--rpm)
      RPM_PATH="${2:-}"
      if [[ -z "${RPM_PATH}" ]]; then
        echo "ERROR: --rpm requires a path or glob (e.g. './acme2certifier-*.rpm')" >&2
        exit 1
      fi
      shift 2
      RPM_GLOBS=("${RPM_PATH}")
      while [[ $# -gt 0 && ( "$1" == *.rpm || "$1" == *.RPM ) ]]; do
        RPM_GLOBS+=("$1")
        shift
      done
      ;;
    -m|--mode)
      MODE="${2:-}"
      shift 2
      ;;
    --volume-dir)
      VOLUME_DIR="${2:-}"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="${2:-}"
      shift 2
      ;;
    --no-ssl)
      ENABLE_SSL=0
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
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 1
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

if command -v dnf >/dev/null 2>&1; then
  PKG="dnf"
else
  PKG="yum"
fi

resolve_defaults

if [[ "${ACTION}" == "restart" ]]; then
  do_restart
  exit 0
fi
if [[ "${ACTION}" == "update" ]]; then
  do_update
  exit 0
fi

EL_MAJOR="$(el_major)"
echo "==> Detected package manager: ${PKG} (EL major: ${EL_MAJOR})"

RPM_FILE="$(find_rpm)" || {
  echo "ERROR: no .rpm found. Pass --rpm /path/to/acme2certifier-*.noarch.rpm" >&2
  exit 1
}
RPM_FILE="$(readlink -f "${RPM_FILE}")"
echo "==> Using package: ${RPM_FILE}"

echo "==> Installing EPEL + Nginx/uWSGI stack"
${SUDO} ${PKG} install -y epel-release
${SUDO} ${PKG} install -y curl --allowerasing 2>/dev/null || ${SUDO} ${PKG} install -y curl || true
${SUDO} ${PKG} install -y \
  nginx \
  uwsgi \
  uwsgi-plugin-python3 \
  python3-uwsgidecorators \
  openssl \
  policycoreutils-python-utils \
  checkpolicy \
  tar \
  procps-ng

if [[ "${MODE}" == "django" ]]; then
  echo "==> Installing Django-related system packages"
  DJANGO_RPM=""
  for cand in python3-django4.2 python3-django; do
    if ${SUDO} ${PKG} install -y "${cand}" 2>/dev/null; then
      DJANGO_RPM="${cand}"
      break
    fi
  done
  if [[ -z "${DJANGO_RPM}" ]]; then
    echo "ERROR: could not install Django (tried python3-django4.2, python3-django)." >&2
    echo "       Enable EPEL / CRB and retry, or install Django manually." >&2
    exit 1
  fi
  echo "==> Installed Django package: ${DJANGO_RPM}"
  for cand in python3-pyyaml python3-mysqlclient python3-PyMySQL python3-psycopg2 python3-sqlparse; do
    ${SUDO} ${PKG} install -y "${cand}" 2>/dev/null || true
  done
  if ! ${SUDO} python3 -c "import django; print('django', django.get_version())"; then
    echo "ERROR: Django RPM installed but 'import django' failed" >&2
    exit 1
  fi
fi

echo "==> Installing ${RPM_FILE}"
${SUDO} ${PKG} localinstall -y "${RPM_FILE}"

echo "==> Verifying package import (PYTHONPATH=${APP_ROOT})"
${SUDO} env PYTHONPATH="${APP_ROOT}" python3 -c \
  "import acme2certifier.acme_srv; from acme2certifier.acme_srv.version import __version__; print('acme2certifier', __version__)"
command -v a2c-cli >/dev/null

${SUDO} mkdir -p "${APP_ROOT}/volume" /run/uwsgi

if [[ -n "${VOLUME_DIR}" && -d "${VOLUME_DIR}" ]]; then
  sync_volume "${VOLUME_DIR}"
fi

if [[ ! -e "${CFG}" ]]; then
  if [[ -f "${SHARE}/acme_srv.cfg" ]]; then
    ${SUDO} cp "${SHARE}/acme_srv.cfg" "${CFG}"
  else
    echo "ERROR: no ${CFG} and no sample under ${SHARE}" >&2
    exit 1
  fi
fi

if ! ${SUDO} grep -qE '^[[:space:]]*dbfile:' "${CFG}"; then
  if ${SUDO} grep -q '^\[DBhandler\]' "${CFG}"; then
    ${SUDO} sed -i "/^\[DBhandler\]/a dbfile: ${APP_ROOT}/acme_srv.db" "${CFG}"
  else
    printf '\n[DBhandler]\ndbfile: %s/acme_srv.db\n' "${APP_ROOT}" \
      | ${SUDO} tee -a "${CFG}" >/dev/null
  fi
else
  ${SUDO} sed -i "s|^[[:space:]]*dbfile:.*|dbfile: ${APP_ROOT}/acme_srv.db|" "${CFG}"
fi

set_dbhandler_mode "${MODE}"

echo "==> Configuring Nginx (conf.d) + uWSGI module (${MODE})"
${SUDO} cp "${SHARE}/nginx/nginx_acme_srv.conf" /etc/nginx/conf.d/nginx_acme_srv.conf
${SUDO} sed -i \
  -e "s|/var/www/acme2certifier|${APP_ROOT}|g" \
  /etc/nginx/conf.d/nginx_acme_srv.conf
${SUDO} rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

if [[ "${ENABLE_SSL}" -eq 1 ]]; then
  ${SUDO} cp "${SHARE}/nginx/nginx_acme_srv_ssl.conf" /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
  ${SUDO} sed -i \
    -e "s|/var/www/acme2certifier|${APP_ROOT}|g" \
    -e "s|/etc/nginx/acme2certifier_|${APP_ROOT}/volume/acme2certifier_|g" \
    /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
  CERT="${APP_ROOT}/volume/acme2certifier_cert.pem"
  KEY="${APP_ROOT}/volume/acme2certifier_key.pem"
  if [[ ! -f "${CERT}" || ! -f "${KEY}" ]]; then
    echo "==> Generating self-signed TLS cert/key"
    ${SUDO} openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "${KEY}" \
      -out "${CERT}" \
      -days 365 \
      -subj "/CN=localhost"
  fi
fi

maybe_overlay_nginx_from_data

# CI marker from rpm_prep: trim stock Alma nginx.conf server blocks.
if [[ -n "${DATA_DIR}" && -f "${DATA_DIR}/.a2c_ci" && -f /etc/nginx/nginx.conf ]]; then
  echo "==> CI: trimming /etc/nginx/nginx.conf (Alma systemd image)"
  ${SUDO} cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
  ${SUDO} sh -c 'head -n 37 /etc/nginx/nginx.conf.orig > /etc/nginx/nginx.conf; echo "}" >> /etc/nginx/nginx.conf'
fi

if [[ ! -f "${UWSGI_INI}" ]]; then
  ${SUDO} cp "${SHARE}/nginx/acme2certifier.ini" "${UWSGI_INI}"
fi
if [[ "${MODE}" == "django" ]]; then
  ${SUDO} sed -i \
    -e 's/module = acme2certifier_wsgi.*/module = acme2certifier.django_project.wsgi:application/' \
    -e 's/acme2certifier_wsgi:application/acme2certifier.django_project.wsgi:application/' \
    "${UWSGI_INI}"
else
  ${SUDO} sed -i \
    -e 's/module = acme2certifier\.django_project\.wsgi.*/module = acme2certifier_wsgi:application/' \
    "${UWSGI_INI}" || true
fi
grep -q '^plugins' "${UWSGI_INI}" || echo 'plugins = python3' | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
grep -q '^python-path' "${UWSGI_INI}" || echo "python-path = ${APP_ROOT}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
if ! grep -q 'ACME_SRV_CONFIGFILE' "${UWSGI_INI}"; then
  echo "env = ACME_SRV_CONFIGFILE=${CFG}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
  echo "env = ACME2CERTIFIER_BASE_DIR=${APP_ROOT}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
fi

if [[ -f /usr/lib/systemd/system/acme2certifier.service ]]; then
  if ! grep -q 'PYTHONPATH=' /usr/lib/systemd/system/acme2certifier.service; then
    ${SUDO} sed -i "/^WorkingDirectory=/a Environment=PYTHONPATH=${APP_ROOT}" \
      /usr/lib/systemd/system/acme2certifier.service
  fi
  if ! grep -q 'ACME_SRV_CONFIGFILE=' /usr/lib/systemd/system/acme2certifier.service; then
    ${SUDO} sed -i "/^WorkingDirectory=/a Environment=ACME_SRV_CONFIGFILE=${CFG}" \
      /usr/lib/systemd/system/acme2certifier.service
  fi
fi

if [[ "${MODE}" == "django" ]]; then
  link_django_settings_from_volume "${VOLUME_DIR}"
  echo "==> Django migrate + fixtures"
  SETTINGS_PY="${APP_ROOT}/acme2certifier/django_project/settings.py"
  if [[ -f "${SETTINGS_PY}" ]]; then
    ${SUDO} sed -i \
      -e 's/^USE_I18N = True/USE_I18N = False/' \
      -e 's/^USE_L10N = True/USE_L10N = False/' \
      "${SETTINGS_PY}"
  fi
  export ACME_SRV_CONFIGFILE="${CFG}"
  export ACME2CERTIFIER_BASE_DIR="${APP_ROOT}"
  export DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings"
  if [[ -z "${ACME2CERTIFIER_SECRET_KEY:-}" ]]; then
    export ACME2CERTIFIER_SECRET_KEY="$(a2c-django-secret-keygen)"
  fi
  if ! grep -q 'ACME2CERTIFIER_SECRET_KEY=' "${UWSGI_INI}"; then
    echo "env = ACME2CERTIFIER_SECRET_KEY=${ACME2CERTIFIER_SECRET_KEY}" \
      | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
  fi
  ${SUDO} env \
    PYTHONPATH="${APP_ROOT}" \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    a2c-django-update
  ${SUDO} env \
    PYTHONPATH="${APP_ROOT}" \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    a2c-manage loaddata status
fi

echo "==> Ownership and start services"
${SUDO} chown -R "${NGINX_USER}:${NGINX_USER}" "${APP_ROOT}"
${SUDO} mkdir -p /run/uwsgi
${SUDO} chown "${NGINX_USER}:${NGINX_USER}" /run/uwsgi 2>/dev/null || true

${SUDO} nginx -t
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable acme2certifier nginx
${SUDO} systemctl restart acme2certifier
${SUDO} systemctl restart nginx

echo
echo "Done. mode=${MODE} el=${EL_MAJOR}"
echo "  App root: ${APP_ROOT}"
echo "  Config:   ${CFG}"
echo "  Test:     curl -sS http://127.0.0.1/directory | head"
echo "  Next:     edit ${CFG} (CA handler), see docs/acme_srv.md"
echo "  Logs:     journalctl -u acme2certifier -n 50 --no-pager"
echo "            tail -n 50 /var/log/nginx/error.log"
if [[ "${EL_MAJOR}" == "8" ]]; then
  echo
  echo "  Note (EL8): if imports fail on cryptography/jwcrypto/dns, install"
  echo "  backports from https://github.com/grindsa/sbom (docs/install_rpm.md)."
fi
