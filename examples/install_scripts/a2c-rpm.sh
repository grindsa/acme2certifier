#!/bin/bash
# Install acme2certifier from a local .rpm (Nginx + uWSGI) on EL8 / EL9.
#
# Install root: /opt/acme2certifier (RPM layout; PYTHONPATH-based).
# Python modules come from a flavor metapackage (see docs/architecture/rpm-el-packaging.md).
# For PyPI/venv on EL9 only, use a2c-rel-nginx.sh instead.
#
# Usage:
#   ./examples/install_scripts/a2c-rpm.sh --rpm PATH [options]
#   ./examples/install_scripts/a2c-rpm.sh install|restart|update [options]
#
# Options:
#   -r, --rpm PATH              path to main acme2certifier-*.noarch.rpm (required unless
#                               a matching .rpm is found in . / .. / data-dir). Flavor
#                               RPMs are taken from the same directory.
#   -m, --mode wsgi|django      application mode (default: wsgi)
#       --python VER|NAME       flavor: 3.9|39|python39 (EL8 default),
#                               3|python3 (EL9 default / EL8 legacy 3.6),
#                               3.6 (alias for python3 on EL8)
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
#   ./examples/install_scripts/a2c-rpm.sh install --python 3.6   # EL8 legacy
#   ./examples/install_scripts/a2c-rpm.sh restart
#   ./examples/install_scripts/a2c-rpm.sh --update --volume-dir /tmp/acme2certifier/volume
#
# Notes:
#   - Works on AlmaLinux / RHEL / Rocky / CentOS Stream 8 and 9 (dnf or yum).
#   - Default app Python is 3.9 (EL8: acme2certifier-python39, EL9: acme2certifier-python3).
#   - EL8 python39 uses uwsgi-plugin-python39 (project RPM beside the main RPM, or repos).
#   - If EL8 python39 flavor localinstall fails (missing modules), falls back to
#     acme2certifier-python3 (3.6) unless --python was set explicitly.
#   - Installs EPEL + nginx + uWSGI stack (soft Recommends of the RPM).
#   - EL8 legacy 3.6 may need cryptography/dns/jwcrypto backports; see docs/install_rpm.md.
#   - MSSQL (msodbcsql18 / mssql-django) is also installed by rpm_prep when
#     DJANGO_DB=mssql — not by this script.
#   - CI-only host tweaks (syslog-ng/krb5, nginx.conf trim) stay in rpm_prep, not here.

set -euo pipefail

readonly MODE_DJANGO="django"
readonly MODE_WSGI="wsgi"
readonly DJANGO_SETTINGS="acme2certifier.django_project.settings"
readonly FLAVOR_PYTHON39="acme2certifier-python39"
readonly FLAVOR_PYTHON3="acme2certifier-python3"

MODE="wsgi"
MODE_EXPLICIT=0
ACTION="install"
RPM_PATH=""
RPM_GLOBS=()
ENABLE_SSL=1
VOLUME_DIR=""
DATA_DIR=""
PYTHON_OPT=""
FLAVOR_PKG=""
APP_ROOT="/opt/acme2certifier"
CFG="${APP_ROOT}/acme_srv.cfg"
SHARE="${APP_ROOT}/share"
UWSGI_INI="${APP_ROOT}/acme2certifier.ini"
PYTHON_CONF="/etc/acme2certifier/python.conf"
NGINX_USER="nginx"

usage() {
  sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'
}

# Prefer the main payload RPM; skip flavor packages (acme2certifier-python*).
pick_main_rpm() {
  local f
  for f in "$@"; do
    [[ -f "${f}" ]] || continue
    case "$(basename "${f}")" in
      acme2certifier-python*) continue ;;
      acme2certifier-*.rpm|acme2certifier-*.RPM) printf '%s\n' "${f}"; return 0 ;;
      *) continue ;;
    esac
  done
  return 1
}

find_rpm() {
  local candidate
  local candidates=()
  local matches=()

  if [[ ${#RPM_GLOBS[@]} -gt 1 ]]; then
    # shellcheck disable=SC2086
    mapfile -t matches < <(ls -1t "${RPM_GLOBS[@]}" 2>/dev/null || true)
    pick_main_rpm "${matches[@]}" && return 0
  fi
  if [[ ${#RPM_GLOBS[@]} -eq 1 ]]; then
    candidate="${RPM_GLOBS[0]}"
    # shellcheck disable=SC2086
    if compgen -G "${candidate}" >/dev/null 2>&1; then
      # shellcheck disable=SC2086
      mapfile -t matches < <(ls -1t ${candidate} 2>/dev/null || true)
      pick_main_rpm "${matches[@]}" && return 0
    fi
    if [[ -f "${candidate}" ]]; then
      pick_main_rpm "${candidate}" && return 0
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
      mapfile -t matches < <(ls -1t ${candidate} 2>/dev/null || true)
      pick_main_rpm "${matches[@]}" && return 0
    fi
    if [[ -f "${candidate}" ]]; then
      pick_main_rpm "${candidate}" && return 0
    fi
  done
  return 1
}

find_flavor_rpm() {
  local flavor_name="$1"
  local main_rpm="$2"
  local dir
  dir="$(dirname "${main_rpm}")"
  local matches=()
  # shellcheck disable=SC2086
  mapfile -t matches < <(ls -1t "${dir}/${flavor_name}"-*.rpm "${dir}/${flavor_name}"-*.noarch.rpm 2>/dev/null || true)
  if [[ ${#matches[@]} -gt 0 && -f "${matches[0]}" ]]; then
    printf '%s\n' "${matches[0]}"
    return 0
  fi
  if [[ -n "${DATA_DIR}" ]]; then
    # shellcheck disable=SC2086
    mapfile -t matches < <(ls -1t "${DATA_DIR}/${flavor_name}"-*.rpm 2>/dev/null || true)
    if [[ ${#matches[@]} -gt 0 && -f "${matches[0]}" ]]; then
      printf '%s\n' "${matches[0]}"
      return 0
    fi
  fi
  return 1
}

# Locate uwsgi-plugin-python39 (or similar) next to the main RPM / data-dir.
find_named_rpm() {
  local pkg_name="$1"
  local main_rpm="${2:-}"
  local matches=()
  local dir=""
  if [[ -n "${main_rpm}" ]]; then
    dir="$(dirname "${main_rpm}")"
    # shellcheck disable=SC2086
    mapfile -t matches < <(ls -1t "${dir}/${pkg_name}"-*.rpm 2>/dev/null || true)
    if [[ ${#matches[@]} -gt 0 && -f "${matches[0]}" ]]; then
      printf '%s\n' "${matches[0]}"
      return 0
    fi
  fi
  if [[ -n "${DATA_DIR}" ]]; then
    # shellcheck disable=SC2086
    mapfile -t matches < <(ls -1t "${DATA_DIR}/${pkg_name}"-*.rpm 2>/dev/null || true)
    if [[ ${#matches[@]} -gt 0 && -f "${matches[0]}" ]]; then
      printf '%s\n' "${matches[0]}"
      return 0
    fi
  fi
  return 1
}

# Install the uWSGI Python plugin matching the selected flavor.
# python39 → uwsgi-plugin-python39 (project/local RPM preferred); else system python3 plugin.
install_uwsgi_python_plugin() {
  local flavor="$1"
  local main_rpm="${2:-}"
  local plugin_pkg plugin_file
  if [[ "${flavor}" == "${FLAVOR_PYTHON39}" ]]; then
    plugin_pkg="uwsgi-plugin-python39"
    if plugin_file="$(find_named_rpm "${plugin_pkg}" "${main_rpm}")"; then
      echo "==> Installing ${plugin_pkg} from ${plugin_file}"
      ${SUDO} ${PKG} localinstall -y "${plugin_file}"
      return 0
    fi
    echo "==> Installing ${plugin_pkg} from repos"
    if ! ${SUDO} ${PKG} install -y "${plugin_pkg}"; then
      echo "ERROR: ${plugin_pkg} not found locally or in repos." >&2
      echo "       Place ${plugin_pkg}-*.rpm next to the main RPM (project SBOM/build)." >&2
      return 1
    fi
    return 0
  fi
  plugin_pkg="uwsgi-plugin-python3"
  echo "==> Installing ${plugin_pkg} (+ python3-uwsgidecorators)"
  ${SUDO} ${PKG} install -y "${plugin_pkg}" python3-uwsgidecorators
}

uwsgi_plugins_value() {
  local flavor_name="$1"
  case "${flavor_name}" in
    "${FLAVOR_PYTHON39}") echo "python39" ;;
    *) echo "python3" ;;
  esac
}

resolve_flavor_name() {
  local el="$1"
  local opt="${2:-}"
  local normalized
  normalized="$(echo "${opt}" | tr '[:upper:]' '[:lower:]')"
  case "${normalized}" in
    "" )
      if [[ "${el}" == "8" ]]; then
        echo "${FLAVOR_PYTHON39}"
      else
        echo "${FLAVOR_PYTHON3}"
      fi
      ;;
    3.9|39|python39|"${FLAVOR_PYTHON39}")
      echo "${FLAVOR_PYTHON39}"
      ;;
    3.6|3|python3|"${FLAVOR_PYTHON3}")
      echo "${FLAVOR_PYTHON3}"
      ;;
    3.11|311|python3.11|acme2certifier-python3.11)
      echo "acme2certifier-python3.11"
      ;;
    *)
      echo "ERROR: unsupported --python value: ${opt}" >&2
      echo "       use 3.9|39|python39, 3.6|3|python3, or 3.11" >&2
      return 1
      ;;
  esac
}

selected_python_bin() {
  if [[ -r "${PYTHON_CONF}" ]]; then
    local py
    py="$(awk -F= '/^[[:space:]]*python_interpreter[[:space:]]*=/ {
      gsub(/[[:space:]]/, "", $2); print $2; exit
    }' "${PYTHON_CONF}" 2>/dev/null || true)"
    if [[ -n "${py}" && -x "${py}" ]]; then
      printf '%s\n' "${py}"
      return 0
    fi
  fi
  printf '%s\n' "/usr/bin/python3"
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

# Normalize handler / handler_module value to short name (wsgi|django) or empty.
normalize_dbhandler_mode() {
  local value="${1:-}"
  case "${value}" in
    django|*django_handler*) echo "${MODE_DJANGO}" ;;
    wsgi|*wsgi_handler*) echo "wsgi" ;;
    *) echo "${value}" ;;
  esac
}

# Read [DBhandler] handler / handler_module from cfg (short name or empty).
get_dbhandler_mode() {
  local cfg="${1:-${CFG}}"
  local raw=""
  if [[ ! -f "${cfg}" ]]; then
    echo ""
    return 0
  fi
  raw="$(${SUDO} awk '
    /^\[DBhandler\]/ { in_sec=1; next }
    /^\[/ { in_sec=0 }
    in_sec && /^[[:space:]]*#*[[:space:]]*handler(_module)?[[:space:]]*:/ {
      sub(/^[^:]*:[[:space:]]*/, "")
      gsub(/[[:space:]]/, "")
      print
      exit
    }
  ' "${cfg}" 2>/dev/null || true)"
  normalize_dbhandler_mode "${raw}"
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
  # Preserve install-time DBhandler; volume cfg often lacks [DBhandler] and would
  # otherwise fall back to default wsgi (empty SQLite) after restart.
  local prev_mode
  prev_mode="$(get_dbhandler_mode "${CFG}")"
  if [[ -f "${VOLUME_DIR}/acme_srv.cfg" ]]; then
    ${SUDO} cp -f "${VOLUME_DIR}/acme_srv.cfg" "${CFG}"
  fi
  sync_volume "${VOLUME_DIR}"
  local effective_mode=""
  if [[ "${MODE_EXPLICIT}" -eq 1 ]]; then
    effective_mode="${MODE}"
  else
    effective_mode="$(get_dbhandler_mode "${CFG}")"
    if [[ -z "${effective_mode}" ]]; then
      effective_mode="${prev_mode}"
    fi
    if [[ -z "${effective_mode}" ]]; then
      effective_mode="${MODE}"
    fi
  fi
  set_dbhandler_mode "${effective_mode}"
  ${SUDO} chown -R "${NGINX_USER}:${NGINX_USER}" "${APP_ROOT}/volume" || true
  restart_services
  echo "Done. restarted nginx + acme2certifier mode=${effective_mode}"
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
      MODE_EXPLICIT=1
      shift 2
      ;;
    --python)
      PYTHON_OPT="${2:-}"
      if [[ -z "${PYTHON_OPT}" ]]; then
        echo "ERROR: --python requires a value (e.g. 3.9, 3.6, python3)" >&2
        exit 1
      fi
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
      MODE_EXPLICIT=1
      shift
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 1
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

FLAVOR_PKG="$(resolve_flavor_name "${EL_MAJOR}" "${PYTHON_OPT}")" || exit 1
echo "==> Python flavor (requested): ${FLAVOR_PKG}"

RPM_FILE="$(find_rpm)" || {
  echo "ERROR: no main .rpm found. Pass --rpm /path/to/acme2certifier-<ver>-*.noarch.rpm" >&2
  exit 1
}
RPM_FILE="$(readlink -f "${RPM_FILE}")"
echo "==> Using package: ${RPM_FILE}"

resolve_flavor_file() {
  local flavor="$1"
  local f
  f="$(find_flavor_rpm "${flavor}" "${RPM_FILE}")" || return 1
  readlink -f "${f}"
}

FLAVOR_FILE="$(resolve_flavor_file "${FLAVOR_PKG}")" || {
  echo "ERROR: flavor RPM ${FLAVOR_PKG}-*.rpm not found next to ${RPM_FILE}" >&2
  echo "       Build/copy subpackages from the same rpmbuild (python3 / python39)." >&2
  exit 1
}
echo "==> Using flavor: ${FLAVOR_FILE}"

echo "==> Installing EPEL + Nginx/uWSGI stack"
${SUDO} ${PKG} install -y epel-release
${SUDO} ${PKG} install -y curl --allowerasing 2>/dev/null || ${SUDO} ${PKG} install -y curl || true
${SUDO} ${PKG} install -y \
  nginx \
  uwsgi \
  openssl \
  policycoreutils-python-utils \
  checkpolicy \
  tar \
  procps-ng
# Matching Python plugin is installed after flavor resolve (incl. fallback).

if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
  echo "==> Installing Django-related system packages"
  DJANGO_RPM=""
  DJANGO_CANDS=(python3-django4.2 python3-django)
  if [[ "${FLAVOR_PKG}" == "${FLAVOR_PYTHON39}" ]]; then
    DJANGO_CANDS=(python39-django python3-django4.2 python3-django)
  fi
  for cand in "${DJANGO_CANDS[@]}"; do
    if ${SUDO} ${PKG} install -y "${cand}" 2>/dev/null; then
      DJANGO_RPM="${cand}"
      break
    fi
  done
  if [[ -z "${DJANGO_RPM}" ]]; then
    echo "ERROR: could not install Django (tried: ${DJANGO_CANDS[*]})." >&2
    echo "       Enable EPEL / CRB and retry, or install Django manually." >&2
    exit 1
  fi
  echo "==> Installed Django package: ${DJANGO_RPM}"
  for cand in python3-pyyaml python3-mysqlclient python3-PyMySQL python3-psycopg2 python3-sqlparse \
              python39-pyyaml python39-mysqlclient python39-PyMySQL python39-psycopg2; do
    ${SUDO} ${PKG} install -y "${cand}" 2>/dev/null || true
  done
fi

echo "==> Installing ${RPM_FILE} + ${FLAVOR_FILE}"
if ! ${SUDO} ${PKG} localinstall -y "${RPM_FILE}" "${FLAVOR_FILE}"; then
  if [[ "${EL_MAJOR}" == "8" \
     && "${FLAVOR_PKG}" == "${FLAVOR_PYTHON39}" \
     && -z "${PYTHON_OPT}" ]]; then
    echo "==> WARN: python39 flavor install failed; falling back to ${FLAVOR_PYTHON3} (EL8 legacy 3.6)"
    FLAVOR_PKG="${FLAVOR_PYTHON3}"
    FLAVOR_FILE="$(resolve_flavor_file "${FLAVOR_PKG}")" || {
      echo "ERROR: fallback flavor RPM ${FLAVOR_PKG}-*.rpm not found" >&2
      exit 1
    }
    echo "==> Using flavor: ${FLAVOR_FILE}"
    ${SUDO} ${PKG} localinstall -y "${RPM_FILE}" "${FLAVOR_FILE}"
  else
    exit 1
  fi
fi

install_uwsgi_python_plugin "${FLAVOR_PKG}" "${RPM_FILE}" || exit 1

PY_BIN="$(selected_python_bin)"
echo "==> Verifying package import (PYTHONPATH=${APP_ROOT}, python=${PY_BIN})"
${SUDO} env PYTHONPATH="${APP_ROOT}" "${PY_BIN}" -c \
  "import acme2certifier.acme_srv; from acme2certifier.acme_srv.version import __version__; print('acme2certifier', __version__)"
command -v a2c-cli >/dev/null
if [[ "${MODE}" == "${MODE_DJANGO}" ]] \
  && ! ${SUDO} "${PY_BIN}" -c "import django; print('${MODE_DJANGO}', django.get_version())"; then
  echo "ERROR: Django installed but 'import django' failed with ${PY_BIN}" >&2
  exit 1
fi

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
    # Prefer CI-provided material from DATA_DIR (volume/ or nginx/) over self-signed.
    for src_dir in "${VOLUME_DIR}" "${DATA_DIR}/volume" "${DATA_DIR}/nginx"; do
      if [[ -n "${src_dir}" && -f "${src_dir}/acme2certifier_cert.pem" && -f "${src_dir}/acme2certifier_key.pem" ]]; then
        echo "==> Seeding TLS cert/key from ${src_dir}"
        ${SUDO} cp -f "${src_dir}/acme2certifier_cert.pem" "${CERT}"
        ${SUDO} cp -f "${src_dir}/acme2certifier_key.pem" "${KEY}"
        break
      fi
    done
  fi
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
# Idempotent: legacy rpm_install may already have closed http{} after conf.d;
# re-running `head -n 37` + `}` then injects a stray "}" (nginx: unexpected "}").
if [[ -n "${DATA_DIR}" && -f "${DATA_DIR}/.a2c_ci" && -f /etc/nginx/nginx.conf ]]; then
  if grep -qE 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf;' /etc/nginx/nginx.conf \
    && grep -qE '^[[:space:]]*server[[:space:]]*\{' /etc/nginx/nginx.conf; then
    echo "==> CI: trimming /etc/nginx/nginx.conf (Alma systemd image)"
    ${SUDO} cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
    ${SUDO} awk '
      { print }
      /include[[:space:]]+\/etc\/nginx\/conf\.d\/\*\.conf;/ { print "}"; exit }
    ' /etc/nginx/nginx.conf.orig | ${SUDO} tee /etc/nginx/nginx.conf >/dev/null
  else
    echo "==> CI: /etc/nginx/nginx.conf already trimmed; skipping"
  fi
fi

if [[ ! -f "${UWSGI_INI}" ]]; then
  ${SUDO} cp "${SHARE}/nginx/acme2certifier.ini" "${UWSGI_INI}"
fi
if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
  ${SUDO} sed -i \
    -e 's/module = acme2certifier_wsgi.*/module = acme2certifier.django_project.wsgi:application/' \
    -e 's/acme2certifier_wsgi:application/acme2certifier.django_project.wsgi:application/' \
    "${UWSGI_INI}"
else
  ${SUDO} sed -i \
    -e 's/module = acme2certifier\.django_project\.wsgi.*/module = acme2certifier_wsgi:application/' \
    "${UWSGI_INI}" || true
fi
UWSGI_PLUGIN="$(uwsgi_plugins_value "${FLAVOR_PKG}")"
if grep -q '^plugins' "${UWSGI_INI}"; then
  ${SUDO} sed -i "s|^plugins[[:space:]]*=.*|plugins = ${UWSGI_PLUGIN}|" "${UWSGI_INI}"
else
  echo "plugins = ${UWSGI_PLUGIN}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
fi
if grep -q '^python-path' "${UWSGI_INI}"; then
  ${SUDO} sed -i "s|^python-path = .*|python-path = ${APP_ROOT}|" "${UWSGI_INI}"
else
  echo "python-path = ${APP_ROOT}" | ${SUDO} tee -a "${UWSGI_INI}" >/dev/null
fi
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

if [[ "${MODE}" == "${MODE_DJANGO}" ]]; then
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
  export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}"
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
    DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}" \
    a2c-django-update
  ${SUDO} env \
    PYTHONPATH="${APP_ROOT}" \
    ACME_SRV_CONFIGFILE="${CFG}" \
    ACME2CERTIFIER_BASE_DIR="${APP_ROOT}" \
    ACME2CERTIFIER_SECRET_KEY="${ACME2CERTIFIER_SECRET_KEY}" \
    DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS}" \
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
echo "Done. mode=${MODE} el=${EL_MAJOR} flavor=${FLAVOR_PKG} python=${PY_BIN}"
echo "  App root: ${APP_ROOT}"
echo "  Config:   ${CFG}"
echo "  Python:   ${PYTHON_CONF}"
echo "  Test:     curl -sS http://127.0.0.1/directory | head"
echo "  Next:     edit ${CFG} (CA handler), see docs/acme_srv.md"
echo "  Logs:     journalctl -u acme2certifier -n 50 --no-pager"
echo "            tail -n 50 /var/log/nginx/error.log" >&2
if [[ "${EL_MAJOR}" == "8" && "${FLAVOR_PKG}" == "${FLAVOR_PYTHON3}" ]]; then
  echo
  echo "  Note (EL8 legacy 3.6): if imports fail on cryptography/jwcrypto/dns, install"
  echo "  backports from https://github.com/grindsa/sbom (docs/install_rpm.md)."
fi
