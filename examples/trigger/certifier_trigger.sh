#!/bin/bash
# Trigger script for Insta Certifier / NCM (and openssl CA handler CI).
# Expects the path to the issued certificate as $1 (Certifier publish method:
#   /path/to/certifier_trigger.sh %cert
# Import/certificate format must be PEM for interop with certifier_ca_handler.py
# and openssl_ca_handler.py).
#
# Auth: HMAC-SHA256 over the exact JSON body, sent as
#   X-A2C-Trigger-Signature: <hex>
# Configure matching secrets on the server via [Trigger] hmac_keys / hmac_keys_file.

set -euo pipefail

# URL to acme2certifier /trigger endpoint
ACME2CERTIFIER_URL="${ACME2CERTIFIER_URL:-http://192.168.14.1/trigger}"

# Shared secret (must be one of the server hmac_keys). Prefer env in production.
TRIGGER_HMAC_KEY="${TRIGGER_HMAC_KEY:-}"

# Certifier base directory (ignored when CERT_PATH is absolute)
CERTIFIER_BASE="${CERTIFIER_BASE:-/usr/local/certifier}"

CERT_FILE="${1:-}"
if [[ -z "${CERT_FILE}" ]]; then
  echo "usage: $0 <cert-relative-or-absolute-path>" >&2
  exit 1
fi

if [[ "${CERT_FILE}" = /* ]]; then
  CERT_PATH="${CERT_FILE}"
else
  CERT_PATH="${CERTIFIER_BASE}/${CERT_FILE}"
fi

if [[ ! -f "${CERT_PATH}" ]]; then
  echo "certificate file not found: ${CERT_PATH}" >&2
  exit 1
fi

if [[ -z "${TRIGGER_HMAC_KEY}" ]]; then
  echo "TRIGGER_HMAC_KEY is required (or set [Trigger] auth_disable with ACME2CERTIFIER_I_KNOW_THE_RISK on the server for testing only)" >&2
  exit 1
fi

STR_BASE64="$(base64 -w 0 < "${CERT_PATH}" 2>/dev/null || base64 < "${CERT_PATH}" | tr -d '\n')"
PAYLOAD="$(printf '{"payload":"%s"}' "${STR_BASE64}")"

if command -v openssl >/dev/null 2>&1; then
  SIGNATURE="$(printf '%s' "${PAYLOAD}" | openssl dgst -sha256 -hmac "${TRIGGER_HMAC_KEY}" | awk '{print $NF}')"
elif command -v python3 >/dev/null 2>&1; then
  SIGNATURE="$(PAYLOAD="${PAYLOAD}" TRIGGER_HMAC_KEY="${TRIGGER_HMAC_KEY}" python3 - <<'PY'
import hashlib, hmac, os
body = os.environ["PAYLOAD"].encode("utf-8")
key = os.environ["TRIGGER_HMAC_KEY"].encode("utf-8")
print(hmac.new(key, body, hashlib.sha256).hexdigest())
PY
)"
else
  echo "openssl or python3 required to compute HMAC" >&2
  exit 1
fi

curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "X-A2C-Trigger-Signature: ${SIGNATURE}" \
  -d "${PAYLOAD}" \
  "${ACME2CERTIFIER_URL}"

echo
exit 0
