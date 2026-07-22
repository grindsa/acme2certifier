#!/usr/bin/env bash
# Build multi-arch acme2certifier Docker test images (amd64 + arm64).
#
# Usage:
#   ./examples/install_scripts/a2c-container-build.sh -b BRANCH [options]
#   ./examples/install_scripts/a2c-container-build.sh BRANCH [options]
#
# Options:
#   -b, --branch BRANCH           git branch to clone (required)
#   -m, --mode wsgi|django        application mode (default: wsgi)
#   -w, --webserver apache2|nginx front-end web server (default: apache2)
#   -t, --tag TAG                 image tag
#                                 (default: BRANCH-WEBSERVER-MODE)
#   -i, --image NAME              image repository without tag
#                                 (default: <DOCKERHUB_USER>/acme2certifier)
#   -r, --repo URL                git clone URL
#                                 (default: https://github.com/grindsa/acme2certifier.git)
#   -u, --upload                  push the built image to Docker Hub
#       --no-cache                pass --no-cache to docker buildx
#       --load                    load host-arch image into the local docker
#                                 daemon (only when not uploading)
#       --keep                    do not remove the work directory on exit
#   -h, --help                    show help
#
# Docker Hub credentials (required with --upload) are read from
# $HOME/.dockercredential as KEY=VALUE lines:
#   DOCKERHUB_USER=...
#   DOCKERHUB_TOKEN=...
#
# Examples:
#   ./a2c-container-build.sh -b devel -m wsgi -w apache2
#   ./a2c-container-build.sh -b devel -m django -w nginx --upload
#   ./a2c-container-build.sh devel -w nginx --load

set -euo pipefail

BRANCH=""
MODE="wsgi"
WEBSRV="apache2"
IMAGE_REPO=""
IMAGE_TAG=""
REPO_URL="https://github.com/grindsa/acme2certifier.git"
UPLOAD=0
NO_CACHE=0
LOAD_LOCAL=0
KEEP_WORK=0
CREDENTIAL_FILE="${HOME}/.dockercredential"
BUILDER_NAME="a2c-multiarch"
PLATFORMS="linux/amd64,linux/arm64"
WORK_ROOT=""

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "error: $*" >&2
  exit 1
}

cleanup() {
  local rc=$?
  if [[ "${KEEP_WORK}" -eq 0 && -n "${WORK_ROOT}" && -d "${WORK_ROOT}" ]]; then
    echo "Cleaning build artifacts under ${WORK_ROOT}"
    rm -rf "${WORK_ROOT}"
  elif [[ -n "${WORK_ROOT}" && -d "${WORK_ROOT}" ]]; then
    echo "Keeping work directory: ${WORK_ROOT}"
  fi
  exit "${rc}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

host_platform() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "linux/amd64" ;;
    aarch64|arm64) echo "linux/arm64" ;;
    *) die "unsupported host architecture: ${arch}" ;;
  esac
}

load_dockerhub_credentials() {
  local required="${1:-1}"

  if [[ ! -f "${CREDENTIAL_FILE}" ]]; then
    [[ "${required}" -eq 1 ]] && die "credential file not found: ${CREDENTIAL_FILE}"
    return 1
  fi

  # Import KEY=VALUE assignments from $HOME/.dockercredential.
  # shellcheck disable=SC1090
  set -a
  # shellcheck source=/dev/null
  source "${CREDENTIAL_FILE}"
  set +a

  if [[ "${required}" -eq 1 ]]; then
    [[ -n "${DOCKERHUB_USER:-}" ]] || die "DOCKERHUB_USER missing in ${CREDENTIAL_FILE}"
    [[ -n "${DOCKERHUB_TOKEN:-}" ]] || die "DOCKERHUB_TOKEN missing in ${CREDENTIAL_FILE}"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -b|--branch)
        BRANCH="${2:-}"
        shift 2
        ;;
      -m|--mode)
        MODE="${2:-}"
        shift 2
        ;;
      -w|--webserver|--websrv)
        WEBSRV="${2:-}"
        shift 2
        ;;
      -t|--tag)
        IMAGE_TAG="${2:-}"
        shift 2
        ;;
      -i|--image)
        IMAGE_REPO="${2:-}"
        shift 2
        ;;
      -r|--repo)
        REPO_URL="${2:-}"
        shift 2
        ;;
      -u|--upload|--push)
        UPLOAD=1
        shift
        ;;
      --no-cache)
        NO_CACHE=1
        shift
        ;;
      --load)
        LOAD_LOCAL=1
        shift
        ;;
      --keep)
        KEEP_WORK=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        die "unknown option: $1 (use --help)"
        ;;
      *)
        if [[ -z "${BRANCH}" ]]; then
          BRANCH="$1"
          shift
        else
          die "unexpected argument: $1"
        fi
        ;;
    esac
  done

  [[ -n "${BRANCH}" ]] || die "branch is required (-b/--branch)"
  case "${MODE}" in
    wsgi|django) ;;
    *) die "invalid mode '${MODE}' (expected: wsgi|django)" ;;
  esac
  case "${WEBSRV}" in
    apache2|nginx) ;;
    *) die "invalid webserver '${WEBSRV}' (expected: apache2|nginx)" ;;
  esac
}

install_build_deps() {
  echo "Installing Debian package build dependencies"
  sudo apt-get update
  sudo apt-get -y install --no-install-recommends --allow-downgrades \
    build-essential fakeroot dpkg-dev debhelper \
    dh-python pybuild-plugin-pyproject \
    python3-all python3-setuptools python3-build
}

clone_sources() {
  echo "Cloning ${REPO_URL} (branch ${BRANCH}) into ${SRC_DIR}"
  git clone --depth 1 -b "${BRANCH}" "${REPO_URL}" "${SRC_DIR}"
}

read_version() {
  local version_file="${SRC_DIR}/acme2certifier/acme_srv/version.py"
  [[ -f "${version_file}" ]] || version_file="${SRC_DIR}/acme_srv/version.py"
  [[ -f "${version_file}" ]] || die "version.py not found in cloned sources"

  VERSION="$(
    grep -i '__version__' "${version_file}" \
      | head -n 1 \
      | sed -E 's/.*__version__[[:space:]]*=[[:space:]]*//; s/[\"'\'']//g; s/[[:space:]]*$//'
  )"
  [[ -n "${VERSION}" ]] || die "could not parse __version__ from ${version_file}"
  echo "Package version: ${VERSION}"
}

build_deb() {
  echo "Building .deb package"
  (
    cd "${SRC_DIR}"
    cp -R examples/install_scripts/debian ./
    sed -i "s/__version__/${VERSION}/g" debian/changelog
    chmod +x debian/rules debian/patch_apache_for_deb.py
    dpkg-buildpackage -uc -us
  )

  local deb_src="${WORK_ROOT}/acme2certifier_${VERSION}-1_all.deb"
  [[ -f "${deb_src}" ]] || die "expected deb not found: ${deb_src}"

  # Dockerfiles COPY ./*.deb from the build context (repo root).
  cp -f "${deb_src}" "${SRC_DIR}/"
  echo "Debian package ready: ${SRC_DIR}/$(basename "${deb_src}")"
}

ensure_buildx() {
  echo "Ensuring buildx builder '${BUILDER_NAME}' (${PLATFORMS})"
  if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    docker buildx create \
      --name "${BUILDER_NAME}" \
      --driver docker-container \
      --platform "${PLATFORMS}" \
      --use
  else
    docker buildx use "${BUILDER_NAME}"
  fi
  docker buildx inspect --bootstrap >/dev/null
}

docker_login() {
  echo "Logging in to Docker Hub as ${DOCKERHUB_USER}"
  echo "${DOCKERHUB_TOKEN}" | docker login -u "${DOCKERHUB_USER}" --password-stdin
}

build_image() {
  local dockerfile="examples/Docker/${WEBSRV}/${MODE}/Dockerfile"
  local full_image="${IMAGE_REPO}:${IMAGE_TAG}"
  local -a build_cmd

  [[ -f "${SRC_DIR}/${dockerfile}" ]] || die "Dockerfile not found: ${dockerfile}"

  build_cmd=(
    docker buildx build
    --platform "${PLATFORMS}"
    -t "${full_image}"
    -f "${dockerfile}"
    .
  )
  if [[ "${NO_CACHE}" -eq 1 ]]; then
    build_cmd+=(--no-cache)
  fi

  echo "Building ${full_image} for ${PLATFORMS}"
  (
    cd "${SRC_DIR}"
    if [[ "${UPLOAD}" -eq 1 ]]; then
      # Push only this tag/manifest (never docker push -a).
      "${build_cmd[@]}" --push
    else
      # Multi-arch build validation; result stays in the buildx builder.
      "${build_cmd[@]}"
      if [[ "${LOAD_LOCAL}" -eq 1 ]]; then
        echo "Loading host-arch image ($(host_platform)) into local docker"
        local -a load_cmd=(
          docker buildx build
          --platform "$(host_platform)"
          -t "${full_image}"
          -f "${dockerfile}"
          --load
          .
        )
        if [[ "${NO_CACHE}" -eq 1 ]]; then
          load_cmd+=(--no-cache)
        fi
        "${load_cmd[@]}"
      fi
    fi
  )

  echo "Done: ${full_image}"
}

main() {
  parse_args "$@"

  require_cmd git
  require_cmd docker
  require_cmd uuidgen

  if [[ "${UPLOAD}" -eq 1 ]]; then
    load_dockerhub_credentials 1
  else
    # Optional: pick DOCKERHUB_USER for the default image repository name.
    load_dockerhub_credentials 0 || true
  fi

  if [[ -z "${IMAGE_REPO}" ]]; then
    IMAGE_REPO="${DOCKERHUB_USER:-grindsa}/acme2certifier"
  fi
  if [[ -z "${IMAGE_TAG}" ]]; then
    IMAGE_TAG="${BRANCH}-${WEBSRV}-${MODE}"
  fi

  WORK_ROOT="${TMPDIR:-/tmp}/a2c-docker-build.$(uuidgen | cut -d- -f1)"
  SRC_DIR="${WORK_ROOT}/src"
  mkdir -p "${WORK_ROOT}"
  trap cleanup EXIT

  echo "Work directory: ${WORK_ROOT}"
  echo "Image: ${IMAGE_REPO}:${IMAGE_TAG}"
  echo "Mode/webserver: ${MODE}/${WEBSRV}"
  echo "Upload: ${UPLOAD}"

  install_build_deps
  clone_sources
  read_version
  build_deb
  ensure_buildx

  if [[ "${UPLOAD}" -eq 1 ]]; then
    docker_login
  fi

  build_image
}

main "$@"
