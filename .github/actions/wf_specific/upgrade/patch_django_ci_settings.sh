#!/usr/bin/env bash
# Patch CI Django settings: MariaDB password placeholder + non-empty SECRET_KEY.
# Usage: patch_django_ci_settings.sh /path/to/settings.py [...]
set -euo pipefail

sed_inplace() {
  # GNU sed (GHA) and BSD sed (macOS): always use an explicit backup suffix.
  local expr="$1"
  local file="$2"
  sed -i.bak "${expr}" "${file}"
  rm -f "${file}.bak"
}

patch_one() {
  local f="$1"
  [[ -f "${f}" ]] || return 0
  sed_inplace 's/"XXX": "XXX"/"PASSWORD": "1mmSvDFl"/g' "${f}"
  # Drop any existing SECRET_KEY (missing or empty both break Django).
  sed_inplace '/^SECRET_KEY[[:space:]]*=/d' "${f}"
  printf '\n# CI-only secret (upgrade / handler workflows)\nSECRET_KEY = "ci-upgrade-django-secret-key-not-for-production"\n' >> "${f}"
}

if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 settings.py [settings.py ...]" >&2
  exit 2
fi

for path in "$@"; do
  patch_one "${path}"
done
