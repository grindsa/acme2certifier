#!/usr/bin/env bash
# Resolve one-hop upgrade matrix + django multi-hop chain for deployment-upgrade CI.
#
# Requires: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_OUTPUT
# Optional overrides:
#   DJANGO_CHAIN_START  DJANGO_CHAIN_MID  DJANGO_CHAIN_END  (defaults below)
#
# Writes job outputs: app_version, n_tag, hops_{docker,rpm,deb},
# django_chain_{ok,start}, has_{docker,rpm,deb}_hops
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

DJANGO_CHAIN_START="${DJANGO_CHAIN_START:-0.33.2}"
DJANGO_CHAIN_MID="${DJANGO_CHAIN_MID:-0.38.1}"
# Skip 0.43.x: published nginx images still ship SSL conf with /etc/nginx cert
# paths; Hub 0.44+ rewrites those to the volume at image build.
DJANGO_CHAIN_END="${DJANGO_CHAIN_END:-0.44}"

# Forbid clear-text protocol downgrade on redirects (shell:S6506 / CWE-319).
CURL_HTTPS=(--proto '=https' --proto-redir '=https')

is_modern() {
  local ver="$1"
  python3 - "${ver}" <<'PY'
import re, sys
m = re.match(r"(\d+)\.(\d+)", sys.argv[1])
if not m:
    sys.exit(1)
sys.exit(0 if (int(m.group(1)), int(m.group(2))) > (0, 44) else 1)
PY
}

# Prefer GitHub Releases API (token already set). Avoid curl HEAD on
# release-asset URLs (302→CDN) and jq test("\\.rpm$") (\r / invalid escapes).
release_asset_names() {
  local tag="$1"
  gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" \
    --jq '.assets[].name' 2>/dev/null || true
}

tag_has_docker() {
  local tag="$1"
  local code websrv dbh
  for websrv in nginx apache2; do
    for dbh in wsgi django; do
      code=$(curl -sL "${CURL_HTTPS[@]}" -o /dev/null -w '%{http_code}' \
        "https://hub.docker.com/v2/repositories/grindsa/acme2certifier/tags/${tag}-${websrv}-${dbh}" \
        || echo 000)
      if [[ "${code}" == "200" ]]; then
        return 0
      fi
    done
    # Hub miss: still OK if Dockerfiles exist (ensure_container_image builds).
    # Unified layout or legacy websrv/{wsgi,django}/Dockerfile (e.g. 0.33.x).
    code=$(curl -sL "${CURL_HTTPS[@]}" -o /dev/null -w '%{http_code}' \
      "https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${tag}/examples/Docker/${websrv}/Dockerfile" \
      || echo 000)
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    for dbh in wsgi django; do
      code=$(curl -sL "${CURL_HTTPS[@]}" -o /dev/null -w '%{http_code}' \
        "https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${tag}/examples/Docker/${websrv}/${dbh}/Dockerfile" \
        || echo 000)
      if [[ "${code}" == "200" ]]; then
        return 0
      fi
    done
  done
  return 1
}

tag_has_rpm() {
  local tag="$1"
  release_asset_names "${tag}" | grep -Eq '\.noarch\.rpm$'
}

tag_has_deb() {
  local tag="$1"
  release_asset_names "${tag}" | grep -Eq '\.deb$'
}

APP_VERSION=$(grep -i __version__ acme2certifier/acme_srv/version.py | head -n1 \
  | sed 's/__version__ = //g' | sed 's/"//g' | tr -d "[:space:]")

N_TAG=$(curl -fsSL "${CURL_HTTPS[@]}" \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/releases/latest" \
  | jq -r '.tag_name')

TAGS_JSON=$(curl -fsSL "${CURL_HTTPS[@]}" \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/tags")
echo "${TAGS_JSON}" | jq -e 'type=="array"' >/dev/null

# Latest tag matching minor series MM (e.g. 43 → 0.43.x)
latest_in_minor() {
  local minor="$1"
  echo "${TAGS_JSON}" | jq -r '.[].name' \
    | grep -E "^0\.${minor}(\.|$)" | head -n1 || true
}

N_MINOR=$(echo "${N_TAG}" | awk -F. '{print $2}')
N1_TAG=$(latest_in_minor "$((N_MINOR - 1))")
N2_TAG=$(latest_in_minor "$((N_MINOR - 2))")

# Highest tag with version ≤ 0.44
PRE045_TAG=$(echo "${TAGS_JSON}" | jq -r '.[].name' | python3 -c '
import re, sys
best = None
best_t = None
for line in sys.stdin:
    tag = line.strip()
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", tag)
    if not m:
        continue
    t = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    if t > (0, 44, 999999):
        continue
    if best_t is None or t > best_t:
        best_t = t
        best = tag
print(best or "")
')

BUILD_MODERN=false
is_modern "${APP_VERSION}" && BUILD_MODERN=true || true

# candidates: id|tag|require_modern_from
# latest: skip when N ≤ 0.44 (covered by pre045)
# n1/n2: only if tag > 0.44
# pre045: always when tag exists
CANDIDATES=()
if [[ -n "${N_TAG}" ]] && is_modern "${N_TAG}"; then
  CANDIDATES+=("latest|${N_TAG}|true")
fi
if [[ -n "${N1_TAG}" ]] && is_modern "${N1_TAG}"; then
  CANDIDATES+=("n1|${N1_TAG}|true")
fi
if [[ -n "${N2_TAG}" ]] && is_modern "${N2_TAG}"; then
  CANDIDATES+=("n2|${N2_TAG}|true")
fi
if [[ -n "${PRE045_TAG}" ]]; then
  CANDIDATES+=("pre045|${PRE045_TAG}|false")
fi

HOPS_DOCKER='[]'
HOPS_RPM='[]'
HOPS_DEB='[]'

for cand in "${CANDIDATES[@]}"; do
  IFS='|' read -r HID HTAG HREQ <<< "${cand}"
  FROM_MODERN=false
  is_modern "${HTAG}" && FROM_MODERN=true || true
  if [[ "${HREQ}" == "true" && "${FROM_MODERN}" != "true" ]]; then
    continue
  fi

  MIGRATE=false
  if [[ "${FROM_MODERN}" != "true" && "${BUILD_MODERN}" == "true" ]]; then
    MIGRATE=true
  fi
  # pre045 always migrates when build is modern
  if [[ "${HID}" == "pre045" && "${BUILD_MODERN}" == "true" ]]; then
    MIGRATE=true
  fi

  hop_json=$(jq -nc \
    --arg id "${HID}" \
    --arg from_tag "${HTAG}" \
    --arg from_modern "${FROM_MODERN}" \
    --arg migrate "${MIGRATE}" \
    '{id:$id, from_tag:$from_tag, from_modern:$from_modern, migrate:$migrate}')

  if tag_has_docker "${HTAG}"; then
    HOPS_DOCKER=$(echo "${HOPS_DOCKER}" | jq -c --argjson h "${hop_json}" '. + [$h]')
  fi
  if tag_has_rpm "${HTAG}"; then
    HOPS_RPM=$(echo "${HOPS_RPM}" | jq -c --argjson h "${hop_json}" '. + [$h]')
  fi
  if tag_has_deb "${HTAG}"; then
    HOPS_DEB=$(echo "${HOPS_DEB}" | jq -c --argjson h "${hop_json}" '. + [$h]')
  fi
done

DJANGO_CHAIN_OK=false
if tag_has_docker "${DJANGO_CHAIN_START}" \
  && tag_has_docker "${DJANGO_CHAIN_MID}" \
  && tag_has_docker "${DJANGO_CHAIN_END}"; then
  DJANGO_CHAIN_OK=true
fi

HAS_DOCKER=false
HAS_RPM=false
HAS_DEB=false
[[ "$(echo "${HOPS_DOCKER}" | jq 'length')" -gt 0 ]] && HAS_DOCKER=true
[[ "$(echo "${HOPS_RPM}" | jq 'length')" -gt 0 ]] && HAS_RPM=true
[[ "$(echo "${HOPS_DEB}" | jq 'length')" -gt 0 ]] && HAS_DEB=true

{
  echo "app_version=${APP_VERSION}"
  echo "n_tag=${N_TAG}"
  echo "hops_docker=${HOPS_DOCKER}"
  echo "django_chain_ok=${DJANGO_CHAIN_OK}"
  echo "django_chain_start=${DJANGO_CHAIN_START}"
  echo "hops_rpm=${HOPS_RPM}"
  echo "hops_deb=${HOPS_DEB}"
  echo "has_docker_hops=${HAS_DOCKER}"
  echo "has_rpm_hops=${HAS_RPM}"
  echo "has_deb_hops=${HAS_DEB}"
} >> "${GITHUB_OUTPUT}"

echo "N=${N_TAG} N-1=${N1_TAG:-none} N-2=${N2_TAG:-none} pre045=${PRE045_TAG:-none} build=${APP_VERSION}"
echo "django chain: ${DJANGO_CHAIN_START} → ${DJANGO_CHAIN_MID} → ${DJANGO_CHAIN_END} → build (ok=${DJANGO_CHAIN_OK})"
if [[ -n "${PRE045_TAG}" ]]; then
  echo "pre045 probes: docker=$(tag_has_docker "${PRE045_TAG}" && echo yes || echo no) rpm=$(tag_has_rpm "${PRE045_TAG}" && echo yes || echo no) deb=$(tag_has_deb "${PRE045_TAG}" && echo yes || echo no)"
  echo "pre045 assets:"; release_asset_names "${PRE045_TAG}" | sed 's/^/  /' || true
fi
echo "docker hops: ${HOPS_DOCKER}"
echo "rpm hops:    ${HOPS_RPM}"
echo "deb hops:    ${HOPS_DEB}"
