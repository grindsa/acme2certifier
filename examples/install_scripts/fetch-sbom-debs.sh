#!/usr/bin/env bash
# Fetch companion .debs from grindsa/sbom (same logic as fetch_sbom_debs action /
# container_build).
#
# Usage:
#   ./examples/install_scripts/fetch-sbom-debs.sh -t ub26.04 -d .
#   ./examples/install_scripts/fetch-sbom-debs.sh -t ub24.04 --local-sbom ~/Development/sbom
#
# Env (optional, mirrors CI):
#   UBUNTU_TARGET, GH_USER, GH_SBOM_REPO_TOKEN, DEST_DIR
set -euo pipefail

UBUNTU_TARGET="${UBUNTU_TARGET:-}"
GH_USER="${GH_USER:-grindsa}"
GH_SBOM_REPO_TOKEN="${GH_SBOM_REPO_TOKEN:-}"
DEST_DIR="${DEST_DIR:-.}"
LOCAL_SBOM=""
CLONE_DIR="${CLONE_DIR:-/tmp/sbom-debs}"
KEEP_CLONE=0
PACKAGES="${PACKAGES:-python3-requests-gssapi python3-requests-pkcs12}"

usage() {
  cat <<'EOF'
Usage: fetch-sbom-debs.sh -t ub24.04|ub26.04 [options]

Options:
  -t, --target TARGET    Ubuntu SBOM leaf (ub24.04 or ub26.04)
                         [required unless UBUNTU_TARGET set]
  -d, --dest DIR         destination directory (default: .)
  -u, --gh-user USER     GitHub user/org owning sbom (default: grindsa)
      --token TOKEN      GitHub token (or GH_SBOM_REPO_TOKEN); omit for public HTTPS
      --local-sbom DIR   use existing sbom checkout instead of cloning
      --clone-dir DIR    clone target (default: /tmp/sbom-debs)
      --keep-clone       do not rm -rf clone dir before clone
  -h, --help             show this help

Copies companion packages from:
  deb-repo/DEBs/<target>/
Default packages: python3-requests-gssapi python3-requests-pkcs12
Override with PACKAGES="pkg1 pkg2".
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) UBUNTU_TARGET="$2"; shift 2 ;;
    -d|--dest) DEST_DIR="$2"; shift 2 ;;
    -u|--gh-user) GH_USER="$2"; shift 2 ;;
    --token) GH_SBOM_REPO_TOKEN="$2"; shift 2 ;;
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

if [[ -z "${UBUNTU_TARGET}" ]]; then
  echo "ERROR: -t/--target (or UBUNTU_TARGET) required" >&2
  usage >&2
  exit 1
fi

case "${UBUNTU_TARGET}" in
  ub24.04|ub26.04) ;;
  *)
    echo "ERROR: unsupported UBUNTU_TARGET=${UBUNTU_TARGET} (expected ub24.04 or ub26.04)" >&2
    exit 1
    ;;
esac

LEAF="deb-repo/DEBs/${UBUNTU_TARGET}"
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
  git clone --filter=blob:none --sparse --depth 1 "${REMOTE}" "${CLONE_DIR}"
  git -C "${CLONE_DIR}" sparse-checkout set "${LEAF}"
  SBOM_ROOT="${CLONE_DIR}"
fi

SRC="${SBOM_ROOT}/${LEAF}"
if [[ ! -d "${SRC}" ]]; then
  echo "ERROR: missing SBOM path ${SRC}" >&2
  ls -la "${SBOM_ROOT}/deb-repo/DEBs/" 2>/dev/null || true
  exit 1
fi

mkdir -p "${DEST_DIR}"
shopt -s nullglob
copied=0
for pkg in ${PACKAGES}; do
  matches=( "${SRC}/${pkg}"_*.deb )
  if [[ ${#matches[@]} -eq 0 ]]; then
    echo "ERROR: no ${pkg}_*.deb under ${SRC}" >&2
    ls -la "${SRC}" || true
    exit 1
  fi
  for deb in "${matches[@]}"; do
    cp -v "${deb}" "${DEST_DIR}/"
    copied=$((copied + 1))
  done
done
echo "Staged ${copied} companion .deb(s) from ${LEAF} → ${DEST_DIR}/"
ls -la "${DEST_DIR}"/python3-requests-*.deb 2>/dev/null | head -50 || true
