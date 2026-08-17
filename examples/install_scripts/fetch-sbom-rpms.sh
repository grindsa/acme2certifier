#!/usr/bin/env bash
# Fetch companion RPMs from grindsa/sbom (same logic as rpm_prep
# "Retrieve rpm from SBOM repo").
#
# Usage:
#   ./examples/install_scripts/fetch-sbom-rpms.sh -v 8
#   ./examples/install_scripts/fetch-sbom-rpms.sh -v 8 -s python36 -d /tmp/acme2certifier
#   ./examples/install_scripts/fetch-sbom-rpms.sh -v 9 --local-sbom ~/Development/sbom
#
# Env (optional, mirrors CI):
#   RH_VERSION, PYTHON_STACK, GH_USER, GH_SBOM_REPO_TOKEN, DEST_DIR
set -euo pipefail

RH_VERSION="${RH_VERSION:-}"
PYTHON_STACK="${PYTHON_STACK:-}"
GH_USER="${GH_USER:-grindsa}"
GH_SBOM_REPO_TOKEN="${GH_SBOM_REPO_TOKEN:-}"
DEST_DIR="${DEST_DIR:-data}"
LOCAL_SBOM=""
CLONE_DIR="${CLONE_DIR:-/tmp/sbom}"
KEEP_CLONE=0

usage() {
  cat <<'EOF'
Usage: fetch-sbom-rpms.sh -v 8|9 [options]

Options:
  -v, --rh-version N     EL major (8 or 9) [required unless RH_VERSION set]
  -s, --stack NAME       python39 (EL8 default) | python36 | python3 (EL9 default)
  -d, --dest DIR         destination directory (default: data)
  -u, --gh-user USER     GitHub user/org owning sbom (default: grindsa)
  -t, --token TOKEN      GitHub token (or GH_SBOM_REPO_TOKEN); omit for public HTTPS
      --local-sbom DIR   use existing sbom checkout instead of cloning
      --clone-dir DIR    clone target (default: /tmp/sbom)
      --keep-clone       do not rm -rf clone dir before clone
  -h, --help             show this help

Copies only *.noarch.rpm and *.<uname -m>.rpm from:
  rpm-repo/RPMs/rhel<N>/<stack>/
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--rh-version) RH_VERSION="$2"; shift 2 ;;
    -s|--stack) PYTHON_STACK="$2"; shift 2 ;;
    -d|--dest) DEST_DIR="$2"; shift 2 ;;
    -u|--gh-user) GH_USER="$2"; shift 2 ;;
    -t|--token) GH_SBOM_REPO_TOKEN="$2"; shift 2 ;;
    --local-sbom) LOCAL_SBOM="$2"; shift 2 ;;
    --clone-dir) CLONE_DIR="$2"; shift 2 ;;
    --keep-clone) KEEP_CLONE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${RH_VERSION}" ]]; then
  echo "ERROR: -v/--rh-version (or RH_VERSION) required" >&2
  usage >&2
  exit 1
fi

STACK="${PYTHON_STACK:-}"
if [[ -z "${STACK}" ]]; then
  case "${RH_VERSION}" in
    8) STACK=python39 ;;
    9) STACK=python3 ;;
    *)
      echo "ERROR: unsupported RH_VERSION=${RH_VERSION} (expected 8 or 9)" >&2
      exit 1
      ;;
  esac
fi
case "${STACK}" in
  python36|python39|python3) ;;
  *)
    echo "ERROR: PYTHON_STACK must be python36|python39|python3 (got: ${STACK})" >&2
    exit 1
    ;;
esac

LEAF="rpm-repo/RPMs/rhel${RH_VERSION}/${STACK}"
echo "SBOM leaf: ${LEAF}"

if [[ -n "${LOCAL_SBOM}" ]]; then
  SBOM_ROOT="${LOCAL_SBOM}"
  if [[ ! -d "${SBOM_ROOT}" ]]; then
    echo "ERROR: --local-sbom not a directory: ${SBOM_ROOT}" >&2
    exit 1
  fi
else
  if [[ "${KEEP_CLONE}" -eq 0 ]]; then
    rm -rf "${CLONE_DIR}"
  fi
  if [[ -n "${GH_SBOM_REPO_TOKEN}" ]]; then
    REMOTE="https://${GH_USER}:${GH_SBOM_REPO_TOKEN}@github.com/${GH_USER}/sbom"
  else
    REMOTE="https://github.com/${GH_USER}/sbom.git"
  fi
  # Partial clone + sparse checkout: only the needed RPM leaf (not whole repo / SRPMs)
  git clone --filter=blob:none --sparse --depth 1 "${REMOTE}" "${CLONE_DIR}"
  git -C "${CLONE_DIR}" sparse-checkout set "${LEAF}"
  SBOM_ROOT="${CLONE_DIR}"
fi

SRC="${SBOM_ROOT}/${LEAF}"
if [[ ! -d "${SRC}" ]]; then
  echo "ERROR: missing SBOM path ${SRC}" >&2
  ls -la "${SBOM_ROOT}/rpm-repo/RPMs/rhel${RH_VERSION}/" 2>/dev/null || true
  exit 1
fi

mkdir -p "${DEST_DIR}"
ARCH="$(uname -m)"
shopt -s nullglob
copied=0
for r in "${SRC}"/*.noarch.rpm "${SRC}"/*."${ARCH}".rpm; do
  [[ -f "${r}" ]] || continue
  cp -v "${r}" "${DEST_DIR}/"
  copied=$((copied + 1))
done
echo "Staged ${copied} companion RPM(s) for arch=${ARCH} from ${LEAF} → ${DEST_DIR}/"
ls -la "${DEST_DIR}"/*.rpm 2>/dev/null | head -50 || true
