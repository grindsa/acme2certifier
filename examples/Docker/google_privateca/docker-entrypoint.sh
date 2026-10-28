#!/bin/sh
set -eu

DATA_DIR="${MOCK_DATA_DIR:-/data}"
CA_DIR="${MOCK_CA_DIR:-${DATA_DIR}/ca}"
LISTEN="${MOCK_LISTEN:-0.0.0.0:8080}"
PROJECT="${MOCK_PROJECT:-demo}"
LOCATION="${MOCK_LOCATION:-europe-west1}"
POOL="${MOCK_POOL:-demo-pool}"
ISSUING_CA_ID="${MOCK_ISSUING_CA_ID:-mock-issuing-ca}"
TLS_CERT="${MOCK_TLS_CERT:-${DATA_DIR}/server-cert.pem}"
TLS_KEY="${MOCK_TLS_KEY:-${DATA_DIR}/server-key.pem}"

mkdir -p "${CA_DIR}"

if [ ! -f "${CA_DIR}/issuing-cert.pem" ]; then
  echo "No PKI in ${CA_DIR}; running bootstrap_ca.py"
  python3 /opt/google_privateca/bootstrap_ca.py \
    --output-dir "${CA_DIR}" \
    --issuing-ca-id "${ISSUING_CA_ID}" \
    --force
fi

set -- \
  python3 /opt/google_privateca/server.py \
  --listen "${LISTEN}" \
  --ca-dir "${CA_DIR}" \
  --project "${PROJECT}" \
  --location "${LOCATION}" \
  --pool "${POOL}" \
  --issuing-ca-id "${ISSUING_CA_ID}"

if [ -f "${TLS_CERT}" ] && [ -f "${TLS_KEY}" ]; then
  echo "TLS enabled (${TLS_CERT}, ${TLS_KEY})"
  set -- "$@" --tls-cert "${TLS_CERT}" --tls-key "${TLS_KEY}"
elif [ -f "${TLS_CERT}" ] || [ -f "${TLS_KEY}" ]; then
  echo "TLS incomplete: need both ${TLS_CERT} and ${TLS_KEY}; starting without TLS" >&2
else
  echo "No ${TLS_CERT} / ${TLS_KEY}; starting without TLS"
fi

exec "$@"
