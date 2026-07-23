#!/bin/bash
# Install acme2certifier from a local .deb (Apache2 or Nginx, WSGI or Django).
#
# Usage:
#   ./examples/install_scripts/a2c-deb.sh --deb PATH [options]
#   ./examples/install_scripts/a2c-deb.sh install|restart [apache2|nginx] [options]
#
# Options:
#   -d, --deb PATH|GLOB        path or glob to acme2certifier_*.deb (optional if
#                               a matching .deb is found in . / .. / data-dir)
#   -m, --mode wsgi|django      application mode (default: wsgi)
#   -w, --webserver apache2|nginx
#                               front-end web server (default: apache2)
#       --restart               sync volume/cfg and restart services (no reinstall)
#       --volume-dir DIR        sync DIR into APP_ROOT/volume (default: use
#                               /tmp/acme2certifier/volume when present)
#       --data-dir DIR          search root for .deb / MSSQL repo pkg
#                               (default: /tmp/acme2certifier when present)
#       --no-ssl                skip enabling SSL vhosts / generating TLS material
#       --skip-pkcs12           do not pip-install requests-pkcs12
#   -h, --help                  show help
#
# Examples:
#   ./examples/install_scripts/a2c-deb.sh --deb ../acme2certifier_0.45-1_all.deb
#   ./examples/install_scripts/a2c-deb.sh -d './acme2certifier_*.deb' -m django -w nginx
#   ./examples/install_scripts/a2c-deb.sh install nginx -m django
#   ./examples/install_scripts/a2c-deb.sh restart apache2
#   ./examples/install_scripts/a2c-deb.sh --restart -w nginx --volume-dir /tmp/acme2certifier/volume
#
# Notes:
#   - Intended for Ubuntu/Debian after building or downloading the package.
#   - The .deb already ships DEB-tuned configs under /var/www/acme2certifier/share/.
#   - For pip/venv installs use a2c-ubuntu-apache2.sh or a2c-ubuntu-nginx.sh instead.
#   - CI-only host tweaks (rsyslog/krb5, openssl legacy) stay in deb_prep, not here.

set -euo pipefail

MODE="wsgi"
WEBSRV="apache2"
ACTION="install"
DEB_PATH=""
DEB_GLOBS=()
ENABLE_SSL=1
INSTALL_PKCS12=1
VOLUME_DIR=""
DATA_DIR=""
APP_ROOT="/var/www/acme2certifier"
CFG="${APP_ROOT}/acme_srv.cfg"
SHARE="${APP_ROOT}/share"

usage() {
  sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
}

# Resolve a path or glob to one .deb (newest mtime wins if several match).
pick_deb() {
  local pattern="$1"
  local matches=()
  local f
  # shellcheck disable=SC2086
  while IFS= read -r f; do
    [[ -n "${f}" ]] && matches+=("${f}")
  done < <(compgen -G "${pattern}" 2>/dev/null | sort -r || true)
  if [[ ${#matches[@]} -eq 0 ]]; then
    if [[ -f "${pattern}" ]]; then
      printf '%s\n' "${pattern}"
      return 0
    fi
    return 1
  fi
  # shellcheck disable=SC2086
  ls -1t "${matches[@]}" 2>/dev/null | head -n 1
}

find_deb() {
  local candidate
  local candidates=()
  local picked

  if [[ ${#DEB_GLOBS[@]} -gt 1 ]]; then
    ls -1t "${DEB_GLOBS[@]}" 2>/dev/null | head -n 1
    return 0
  fi
  if [[ ${#DEB_GLOBS[@]} -eq 1 ]]; then
    if picked="$(pick_deb "${DEB_GLOBS[0]}")"; then
      printf '%s\n' "${picked}"
      return 0
    fi
  elif [[ -n "${DEB_PATH}" ]]; then
    candidates+=("${DEB_PATH}")
  fi
  if [[ -n "${DATA_DIR}" ]]; then
    candidates+=("${DATA_DIR}/acme2certifier_*.deb")
  fi
  candidates+=("./acme2certifier_*.deb" "../acme2certifier_*.deb")
  candidates+=("/tmp/acme2certifier/acme2certifier_*.deb")
  for candidate in "${candidates[@]}"; do
    if picked="$(pick_deb "${candidate}")"; then
      printf '%s\n' "${picked}"
      return 0
    fi
  done
  return 1
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

normalize_websrv() {
  case "${WEBSRV}" in
    apache2|apache) WEBSRV="apache2" ;;
    nginx) WEBSRV="nginx" ;;
    *)
      echo "ERROR: --webserver must be 'apache2' or 'nginx' (got: ${WEBSRV})" >&2
      exit 1
      ;;
  esac
}

sync_volume() {
  local vol="${1:-}"
  if [[ -z "${vol}" || ! -d "${vol}" ]]; then
    echo "==> No volume dir to sync (skip)"
    return 0
  fi
  echo "==> Syncing volume from ${vol} -> ${APP_ROOT}/volume"
  ${SUDO} mkdir -p "${APP_ROOT}/volume/acme_ca"
  ${SUDO} cp -a "${vol}/." "${APP_ROOT}/volume/"
  if [[ -f "${vol}/acme_srv.cfg" ]]; then
    ${SUDO} cp -f "${vol}/acme_srv.cfg" "${CFG}"
  fi
}

link_django_settings_from_volume() {
  local vol="${1:-}"
  local django_settings
  django_settings="$(python3 -c "import acme2certifier.django_project, pathlib; print(pathlib.Path(acme2certifier.django_project.__file__).parent / 'settings.py')" 2>/dev/null || true)"
  if [[ -z "${django_settings}" ]]; then
    django_settings="/usr/lib/python3/dist-packages/acme2certifier/django_project/settings.py"
  fi
  if [[ -n "${vol}" && -f "${vol}/acme2certifier/settings.py" ]]; then
    echo "==> Linking Django settings from ${vol}/acme2certifier/settings.py"
    ${SUDO} rm -f "${django_settings}"
    ${SUDO} ln -sfn "${vol}/acme2certifier/settings.py" "${django_settings}"
  elif [[ -n "${vol}" && -f "${vol}/settings.py" ]]; then
    echo "==> Linking Django settings from ${vol}/settings.py"
    ${SUDO} rm -f "${django_settings}"
    ${SUDO} ln -sfn "${vol}/settings.py" "${django_settings}"
  elif [[ -f "${APP_ROOT}/volume/acme2certifier/settings.py" ]]; then
    echo "==> Linking Django settings from ${APP_ROOT}/volume/acme2certifier/settings.py"
    ${SUDO} rm -f "${django_settings}"
    ${SUDO} ln -sfn "${APP_ROOT}/volume/acme2certifier/settings.py" "${django_settings}"
  elif [[ -f "${APP_ROOT}/volume/settings.py" ]]; then
    echo "==> Linking Django settings from ${APP_ROOT}/volume/settings.py"
    ${SUDO} rm -f "${django_settings}"
    ${SUDO} ln -sfn "${APP_ROOT}/volume/settings.py" "${django_settings}"
  fi
}

maybe_install_mssql() {
  local pkg=""
  if [[ -n "${DATA_DIR}" && -f "${DATA_DIR}/packages-microsoft-prod.deb" ]]; then
    pkg="${DATA_DIR}/packages-microsoft-prod.deb"
  elif [[ -f /tmp/acme2certifier/packages-microsoft-prod.deb ]]; then
    pkg="/tmp/acme2certifier/packages-microsoft-prod.deb"
  fi
  if [[ -z "${pkg}" ]]; then
    return 0
  fi
  echo "==> Installing Microsoft ODBC / mssql-django from ${pkg}"
  ${SUDO} dpkg -i "${pkg}" || true
  ${SUDO} apt-get update
  ACCEPT_EULA=Y ${SUDO} apt-get install -y msodbcsql18 python3-mssql-django || true
}

restart_services() {
  echo "==> Restarting services (${WEBSRV})"
  if [[ "${WEBSRV}" == "apache2" ]]; then
    ${SUDO} systemctl restart apache2
  else
    ${SUDO} systemctl restart nginx
    ${SUDO} systemctl restart acme2certifier
  fi
}

do_restart() {
  echo "==> Restart mode (no package reinstall)"
  if [[ -z "${VOLUME_DIR}" || ! -d "${VOLUME_DIR}" ]]; then
    echo "ERROR: --restart requires a volume dir (pass --volume-dir or mount /tmp/acme2certifier/volume)" >&2
    exit 1
  fi
  # Legacy parity: refresh cfg + acme_ca, then full volume tree.
  if [[ -f "${VOLUME_DIR}/acme_srv.cfg" ]]; then
    ${SUDO} cp -f "${VOLUME_DIR}/acme_srv.cfg" "${CFG}"
  fi
  if [[ -d "${VOLUME_DIR}/acme_ca" ]]; then
    ${SUDO} mkdir -p "${APP_ROOT}/volume/acme_ca"
    ${SUDO} cp -a "${VOLUME_DIR}/acme_ca/." "${APP_ROOT}/volume/acme_ca/"
  fi
  sync_volume "${VOLUME_DIR}"
  ${SUDO} chown -R www-data:www-data "${APP_ROOT}"
  restart_services
  echo "Done. restarted webserver=${WEBSRV}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|restart)
      ACTION="$1"
      shift
      if [[ $# -gt 0 && ( "$1" == "apache2" || "$1" == "apache" || "$1" == "nginx" ) ]]; then
        WEBSRV="$1"
        shift
      fi
      ;;
    --restart)
      ACTION="restart"
      shift
      ;;
    -d|--deb)
      DEB_PATH="${2:-}"
      if [[ -z "${DEB_PATH}" ]]; then
        echo "ERROR: --deb requires a path or glob (e.g. './acme2certifier_*.deb')" >&2
        exit 1
      fi
      shift 2
      DEB_GLOBS=("${DEB_PATH}")
      while [[ $# -gt 0 && "$1" == *.deb ]]; do
        DEB_GLOBS+=("$1")
        shift
      done
      ;;
    -m|--mode)
      MODE="${2:-}"
      shift 2
      ;;
    -w|--webserver|--websrv)
      WEBSRV="${2:-}"
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
    --skip-pkcs12)
      INSTALL_PKCS12=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
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

normalize_websrv

if [[ $(id -u) -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

resolve_defaults

if [[ "${ACTION}" == "restart" ]]; then
  do_restart
  exit 0
fi

DEB_FILE="$(find_deb)" || {
  echo "ERROR: no .deb found. Pass --deb /path/to/acme2certifier_*.deb" >&2
  exit 1
}
DEB_FILE="$(readlink -f "${DEB_FILE}")"
echo "==> Using package: ${DEB_FILE}"

echo "==> Installing system packages (${WEBSRV})"
${SUDO} apt-get update
if [[ "${WEBSRV}" == "apache2" ]]; then
  ${SUDO} apt-get install -y apache2 apache2-data libapache2-mod-wsgi-py3 curl openssl
else
  ${SUDO} apt-get install -y nginx uwsgi uwsgi-plugin-python3 curl openssl
fi

if [[ "${MODE}" == "django" ]]; then
  maybe_install_mssql
fi

echo "==> Installing ${DEB_FILE}"
${SUDO} apt-get install -y "${DEB_FILE}"

echo "==> Verifying Python package"
python3 -c "import acme2certifier.acme_srv; from acme2certifier.acme_srv.version import __version__; print('acme2certifier', __version__)"
command -v a2c-cli >/dev/null

if [[ "${INSTALL_PKCS12}" -eq 1 ]]; then
  echo "==> Installing requests-pkcs12 (optional CA handlers)"
  ${SUDO} apt-get install -y python3-pip
  ${SUDO} pip3 install --break-system-packages requests-pkcs12 || \
    ${SUDO} pip install --break-system-packages requests-pkcs12 || true
fi

${SUDO} mkdir -p "${APP_ROOT}/volume" "${APP_ROOT}/acme_srv"

# Prefer CI/lab volume overlay when present (legacy deb_tester parity).
if [[ -n "${VOLUME_DIR}" && -d "${VOLUME_DIR}" ]]; then
  sync_volume "${VOLUME_DIR}"
  if [[ -f "${VOLUME_DIR}/acme_srv.cfg" ]]; then
    ${SUDO} rm -f "${CFG}"
    ${SUDO} ln -sfn "${APP_ROOT}/volume/acme_srv.cfg" "${CFG}"
  fi
fi

# Sample config from the package if missing.
if [[ ! -e "${CFG}" ]]; then
  if [[ -f "${SHARE}/acme_srv.cfg" ]]; then
    ${SUDO} cp "${SHARE}/acme_srv.cfg" "${CFG}"
  elif [[ -f "${APP_ROOT}/examples/acme_srv.cfg" ]]; then
    ${SUDO} cp "${APP_ROOT}/examples/acme_srv.cfg" "${CFG}"
  else
    echo "ERROR: no sample acme_srv.cfg found under ${APP_ROOT}" >&2
    exit 1
  fi
fi

# Ensure SQLite path is writable by www-data (avoid default next to dist-packages).
if ! ${SUDO} grep -qE '^[[:space:]]*dbfile:' "${CFG}"; then
  if ${SUDO} grep -q '^\[DBhandler\]' "${CFG}"; then
    ${SUDO} sed -i "/^\[DBhandler\]/a dbfile: ${APP_ROOT}/acme_srv.db" "${CFG}"
  else
    printf '\n[DBhandler]\ndbfile: %s/acme_srv.db\n' "${APP_ROOT}" \
      | ${SUDO} tee -a "${CFG}" >/dev/null
  fi
fi

echo "==> Setting DBhandler to ${MODE}"
if ${SUDO} grep -qE '^handler(_module)?:' "${CFG}"; then
  ${SUDO} sed -i "s/^#* *handler:.*/handler: ${MODE}/" "${CFG}"
  ${SUDO} sed -i "/^handler_module:/d" "${CFG}" || true
else
  if ${SUDO} grep -q '^\[DBhandler\]' "${CFG}"; then
    ${SUDO} sed -i "/^\[DBhandler\]/a handler: ${MODE}" "${CFG}"
  else
    printf '\n[DBhandler]\nhandler: %s\n' "${MODE}" | ${SUDO} tee -a "${CFG}" >/dev/null
  fi
fi

${SUDO} mkdir -p "${APP_ROOT}/acme_srv"
if [[ ! -e "${APP_ROOT}/acme_srv/acme_srv.cfg" ]]; then
  ${SUDO} ln -sfn "${CFG}" "${APP_ROOT}/acme_srv/acme_srv.cfg"
fi

A2C_PKG="$(python3 -c "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")"
${SUDO} ln -sfn "${A2C_PKG}" "${APP_ROOT}/acme2certifier"

if [[ "${WEBSRV}" == "apache2" ]]; then
  echo "==> Configuring Apache2 (${MODE})"
  ${SUDO} a2enmod wsgi
  ${SUDO} a2enmod ssl || true

  if [[ "${MODE}" == "wsgi" ]]; then
    ${SUDO} cp "${SHARE}/apache2/apache_wsgi.conf" \
      /etc/apache2/sites-available/acme2certifier.conf
    if [[ "${ENABLE_SSL}" -eq 1 ]]; then
      ${SUDO} cp "${SHARE}/apache2/apache_wsgi_ssl.conf" \
        /etc/apache2/sites-available/acme2certifier_ssl.conf
    fi
  else
    ${SUDO} cp "${SHARE}/apache2/apache_django.conf" \
      /etc/apache2/sites-available/acme2certifier.conf
    if [[ "${ENABLE_SSL}" -eq 1 ]]; then
      ${SUDO} cp "${SHARE}/apache2/apache_django_ssl.conf" \
        /etc/apache2/sites-available/acme2certifier_ssl.conf
    fi
  fi

  ${SUDO} a2ensite acme2certifier
  if [[ "${ENABLE_SSL}" -eq 1 ]]; then
    ${SUDO} a2ensite acme2certifier_ssl
  fi
  ${SUDO} rm -f /etc/apache2/sites-enabled/000-default.conf

  if ! grep -q 'ACME_SRV_CONFIGFILE=' /etc/apache2/envvars 2>/dev/null; then
    echo "export ACME_SRV_CONFIGFILE=${CFG}" | ${SUDO} tee -a /etc/apache2/envvars >/dev/null
  fi
  if ! grep -q 'ACME2CERTIFIER_BASE_DIR=' /etc/apache2/envvars 2>/dev/null; then
    echo "export ACME2CERTIFIER_BASE_DIR=${APP_ROOT}" | ${SUDO} tee -a /etc/apache2/envvars >/dev/null
  fi

  if [[ "${ENABLE_SSL}" -eq 1 ]]; then
    PEM="${APP_ROOT}/volume/acme2certifier.pem"
    if [[ ! -f "${PEM}" ]]; then
      echo "==> Generating self-signed TLS bundle ${PEM}"
      ${SUDO} openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "${APP_ROOT}/volume/acme2certifier-key.pem" \
        -out "${APP_ROOT}/volume/acme2certifier-cert.pem" \
        -days 365 \
        -subj "/CN=localhost"
      ${SUDO} sh -c "cat '${APP_ROOT}/volume/acme2certifier-cert.pem' \
        '${APP_ROOT}/volume/acme2certifier-key.pem' > '${PEM}'"
    fi
  fi
else
  echo "==> Configuring Nginx + uWSGI (${MODE})"
  ${SUDO} cp "${SHARE}/nginx/nginx_acme_srv.conf" /etc/nginx/sites-available/acme_srv.conf
  ${SUDO} rm -f /etc/nginx/sites-enabled/default
  ${SUDO} ln -sfn /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf

  if [[ "${ENABLE_SSL}" -eq 1 ]]; then
    ${SUDO} cp "${SHARE}/nginx/nginx_acme_srv_ssl.conf" /etc/nginx/sites-available/acme_srv_ssl.conf
    ${SUDO} ln -sfn /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf
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

  ${SUDO} cp "${SHARE}/nginx/acme2certifier.ini" "${APP_ROOT}/acme2certifier.ini"
  if [[ "${MODE}" == "django" ]]; then
    ${SUDO} sed -i 's/acme2certifier_wsgi:application/acme2certifier.django_project.wsgi:application/g' \
      "${APP_ROOT}/acme2certifier.ini"
    ${SUDO} sed -i 's/module = acme2certifier_wsgi/module = acme2certifier.django_project.wsgi/g' \
      "${APP_ROOT}/acme2certifier.ini"
  fi
  if ! grep -q 'ACME_SRV_CONFIGFILE' "${APP_ROOT}/acme2certifier.ini"; then
    echo "env = ACME_SRV_CONFIGFILE=${CFG}" | ${SUDO} tee -a "${APP_ROOT}/acme2certifier.ini" >/dev/null
    echo "env = ACME2CERTIFIER_BASE_DIR=${APP_ROOT}" | ${SUDO} tee -a "${APP_ROOT}/acme2certifier.ini" >/dev/null
  fi

  if [[ -f "${SHARE}/nginx/acme2certifier.service" ]]; then
    ${SUDO} cp "${SHARE}/nginx/acme2certifier.service" /etc/systemd/system/acme2certifier.service
  else
    ${SUDO} tee /etc/systemd/system/acme2certifier.service >/dev/null <<EOF
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=${APP_ROOT}
Environment="PATH=${APP_ROOT}"
Environment="ACME_SRV_CONFIGFILE=${CFG}"
ExecStart=uwsgi --ini ${APP_ROOT}/acme2certifier.ini

[Install]
WantedBy=multi-user.target
EOF
  fi
  ${SUDO} systemctl daemon-reload
  ${SUDO} systemctl enable acme2certifier
  ${SUDO} systemctl restart acme2certifier
fi

if [[ "${MODE}" == "django" ]]; then
  link_django_settings_from_volume "${VOLUME_DIR}"
  echo "==> Django migrate + fixtures"
  export ACME_SRV_CONFIGFILE="${CFG}"
  export ACME2CERTIFIER_BASE_DIR="${APP_ROOT}"
  export DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings"
  if [[ -z "${ACME2CERTIFIER_SECRET_KEY:-}" ]]; then
    export ACME2CERTIFIER_SECRET_KEY="$(a2c-django-secret-keygen)"
  fi
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    a2c-django-update
  ${SUDO} env \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="acme2certifier.django_project.settings" \
    a2c-manage loaddata status
fi

echo "==> Ownership and start ${WEBSRV}"
${SUDO} chown -R www-data:www-data "${APP_ROOT}"
${SUDO} systemctl enable "${WEBSRV}"
${SUDO} systemctl restart "${WEBSRV}"

echo
echo "Done. mode=${MODE} webserver=${WEBSRV}"
echo "  Config:  ${CFG}"
echo "  Test:    curl -sS http://127.0.0.1/directory | head"
echo "  Next:    edit ${CFG} (CA handler), see docs/acme_srv.md"
if [[ "${WEBSRV}" == "apache2" ]]; then
  echo "  Logs:    /var/log/apache2/error.log"
else
  echo "  Logs:    /var/log/nginx/error.log  and  journalctl -u acme2certifier"
fi
