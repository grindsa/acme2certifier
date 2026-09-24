#!/usr/bin/env bash
# Bootstrap openssl lab CA material under test/ca, and/or build throwaway
# append PEMs for cert_chain_link_check tests.
#
# Modes:
#   bootstrap  Create root/sub CA key+cert+CRL and sample client certs.
#   append     Cross-sign / re-issue against an existing CA dir (default).
#
# Append mode: if no root private key is present, the old root is cross-signed
# with `openssl ca -ss_cert` (subject + SPKI from the cert).
set -euo pipefail

# Git Bash / MSYS convert args that look like Unix paths (e.g. -subj "/CN=…")
# into Windows paths before openssl.exe sees them. Disable that conversion.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:-*}"

usage() {
  cat <<'EOF'
Usage: make_test_cas.sh [bootstrap|append] [options]

Modes:
  bootstrap  Write openssl lab CA into -o DIR (default: test/ca)
  append     Write new-root / cross PEMs into -o DIR (default: test/new_ca)
             using -c DIR as source (default). Alias: omit mode name.

Bootstrap writes:
  root-ca-cert.pem / root-ca-key.pem
  sub-ca-cert.pem / sub-ca-key.pem (passphrase-protected)
  sub-ca-crl.pem
  sub-ca-client.pem / sub-ca-client.txt
  root-ca-client.pem / root-ca-client.txt

Append writes:
  new-root.pem / new-root-key.pem
  sub-ca-cross.pem
  root-ca-cross.pem

Options:
  -o DIR     Output directory
  -c DIR     Source openssl CA directory (append only; default: test/ca)
  -p PASS    Passphrase for sub-ca-key (default: $SUBCA_KEY_PASS, else Test1234)
  -d DAYS    Validity in days (default: 3650)
  -h         This help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODE="append"
CA_DIR="${REPO_ROOT}/test/ca"
OUT_DIR=""
DAYS=3650
PASS="${SUBCA_KEY_PASS:-Test1234}"

if [[ "${1:-}" == "bootstrap" || "${1:-}" == "append" ]]; then
  MODE="$1"
  shift
fi

while getopts ":o:c:p:d:h" opt; do
  case "${opt}" in
    o) OUT_DIR="${OPTARG}" ;;
    c) CA_DIR="${OPTARG}" ;;
    p) PASS="${OPTARG}" ;;
    d) DAYS="${OPTARG}" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ -z "${OUT_DIR}" ]]; then
  if [[ "${MODE}" == "bootstrap" ]]; then
    OUT_DIR="${REPO_ROOT}/test/ca"
  else
    OUT_DIR="${REPO_ROOT}/test/new_ca"
  fi
fi

dn_slash() {
  # LibreSSL: "subject= /CN=sub-ca". OpenSSL 3: "subject=CN = sub-ca".
  # openssl req -subj requires /type=value[/type=value...] with no spaces.
  local cert="$1"
  local raw
  raw="$(openssl x509 -in "${cert}" -noout -subject)"
  raw="${raw#subject=}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  raw="$(printf '%s' "${raw}" | sed 's/[[:space:]]*=[[:space:]]*/=/g')"
  if [[ "${raw}" == /* ]]; then
    printf '%s\n' "${raw}"
    return
  fi
  local result="" part
  local IFS=','
  local -a parts
  read -ra parts <<< "${raw}"
  local i
  for ((i = ${#parts[@]} - 1; i >= 0; i--)); do
    part="${parts[$i]}"
    part="${part#"${part%%[![:space:]]*}"}"
    part="${part%"${part##*[![:space:]]}"}"
    [[ -n "${part}" ]] || continue
    result="${result}/${part}"
  done
  printf '%s\n' "${result}"
}

fp() {
  local cert="$1"
  openssl x509 -in "${cert}" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
}

cert_to_txt() {
  # One-line base64 DER (ACME cert field style) without PEM headers.
  local cert="$1"
  local out="$2"
  if openssl base64 -A </dev/null >/dev/null 2>&1; then
    openssl x509 -in "${cert}" -outform DER | openssl base64 -A >"${out}"
  else
    openssl x509 -in "${cert}" -outform DER | openssl base64 | tr -d '\r\n' >"${out}"
  fi
  printf '\n' >>"${out}"
}

native_path() {
  # Native Windows openssl.exe cannot open MSYS virtual paths (/tmp, /d/...).
  # With MSYS_NO_PATHCONV=1 those are passed through unchanged and fopen fails.
  # cygpath -m yields forward-slash Windows paths (C:/...) usable by both.
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m -- "${p}"
  else
    printf '%s\n' "${p}"
  fi
}

mktemp_work() {
  # Prefer a forward-slash temp root so paths embedded in openssl.cnf stay valid
  # under Git Bash on Windows (TMPDIR is often C:\Users\...\Temp).
  local prefix="$1"
  local root="/tmp"
  if [[ ! -d "${root}" ]]; then
    root="${TMPDIR:-.}"
  fi
  native_path "$(mktemp -d "${root}/${prefix}.XXXXXX")"
}

need_openssl() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl not found in PATH" >&2
    exit 1
  fi
}

bootstrap_ca() {
  need_openssl
  mkdir -p "${OUT_DIR}"
  OUT_DIR="$(native_path "$(cd "${OUT_DIR}" && pwd)")"

  local WORK
  WORK="$(mktemp_work a2c-bootstrap-cas)"
  # shellcheck disable=SC2064
  trap "rm -rf '${WORK}'" EXIT

  mkdir -p "${WORK}/newcerts" "${WORK}/crl"
  touch "${WORK}/index.txt"
  printf '01\n' >"${WORK}/serial"
  printf '01\n' >"${WORK}/crlnumber"

  local CNF="${WORK}/openssl.cnf"
  cat >"${CNF}" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${WORK}
database          = ${WORK}/index.txt
serial            = ${WORK}/serial
new_certs_dir     = ${WORK}/newcerts
certificate       = ${OUT_DIR}/root-ca-cert.pem
private_key       = ${OUT_DIR}/root-ca-key.pem
default_days      = ${DAYS}
default_md        = sha256
policy            = policy_any
x509_extensions   = v3_ca
copy_extensions   = none
unique_subject    = no
email_in_dn       = no
crlnumber         = ${WORK}/crlnumber
default_crl_days  = 3650

[ policy_any ]
commonName                = supplied
countryName               = optional
stateOrProvinceName       = optional
localityName              = optional
organizationName          = optional
organizationalUnitName    = optional
emailAddress              = optional

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = root-ca

[ v3_root ]
basicConstraints       = critical,CA:true
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash

[ v3_ca ]
basicConstraints       = critical,CA:true
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_ee ]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth,clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

  umask 077
  openssl req -new -x509 -newkey rsa:4096 -nodes \
    -keyout "${OUT_DIR}/root-ca-key.pem" \
    -out "${OUT_DIR}/root-ca-cert.pem" \
    -days "${DAYS}" \
    -subj "/CN=root-ca" \
    -sha256 \
    -config "${CNF}" \
    -extensions v3_root

  # Encrypt sub-CA key (passphrase). Use genpkey for OpenSSL 3 / Windows parity.
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -aes-256-cbc -pass "pass:${PASS}" \
    -out "${OUT_DIR}/sub-ca-key.pem" 2>/dev/null \
  || openssl genrsa -aes256 -passout "pass:${PASS}" -out "${OUT_DIR}/sub-ca-key.pem" 4096
  openssl req -new -key "${OUT_DIR}/sub-ca-key.pem" -passin "pass:${PASS}" \
    -subj "/CN=sub-ca" \
    -out "${WORK}/sub-ca.csr" \
    -sha256

  openssl x509 -req -in "${WORK}/sub-ca.csr" \
    -CA "${OUT_DIR}/root-ca-cert.pem" \
    -CAkey "${OUT_DIR}/root-ca-key.pem" \
    -CAserial "${WORK}/serial" \
    -days "${DAYS}" \
    -sha256 \
    -extfile "${CNF}" \
    -extensions v3_ca \
    -out "${OUT_DIR}/sub-ca-cert.pem"

  # Re-point CA_default at the issuing CA for CRL + client leaves.
  cat >"${CNF}" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${WORK}
database          = ${WORK}/index.txt
serial            = ${WORK}/serial
new_certs_dir     = ${WORK}/newcerts
certificate       = ${OUT_DIR}/sub-ca-cert.pem
private_key       = ${OUT_DIR}/sub-ca-key.pem
default_days      = ${DAYS}
default_md        = sha256
policy            = policy_any
x509_extensions   = v3_ee
copy_extensions   = none
unique_subject    = no
email_in_dn       = no
crlnumber         = ${WORK}/crlnumber
default_crl_days  = 3650

[ policy_any ]
commonName                = supplied
countryName               = optional
stateOrProvinceName       = optional
localityName              = optional
organizationName          = optional
organizationalUnitName    = optional
emailAddress              = optional

[ v3_ee ]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth,clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

  openssl ca -gencrl -batch \
    -config "${CNF}" \
    -passin "pass:${PASS}" \
    -out "${OUT_DIR}/sub-ca-crl.pem"

  openssl genrsa -out "${WORK}/sub-client-key.pem" 2048
  openssl req -new -key "${WORK}/sub-client-key.pem" \
    -subj "/C=DE/L=Berlin/O=Acme2Certifier/CN=client_sub-ca" \
    -out "${WORK}/sub-client.csr" \
    -sha256
  openssl x509 -req -in "${WORK}/sub-client.csr" \
    -CA "${OUT_DIR}/sub-ca-cert.pem" \
    -CAkey "${OUT_DIR}/sub-ca-key.pem" \
    -passin "pass:${PASS}" \
    -CAcreateserial \
    -days "${DAYS}" \
    -sha256 \
    -extfile "${CNF}" \
    -extensions v3_ee \
    -out "${OUT_DIR}/sub-ca-client.pem"
  cert_to_txt "${OUT_DIR}/sub-ca-client.pem" "${OUT_DIR}/sub-ca-client.txt"

  openssl genrsa -out "${WORK}/root-client-key.pem" 2048
  openssl req -new -key "${WORK}/root-client-key.pem" \
    -subj "/C=DE/L=Berlin/O=Acme2Certifier/CN=client_root-ca" \
    -out "${WORK}/root-client.csr" \
    -sha256
  openssl x509 -req -in "${WORK}/root-client.csr" \
    -CA "${OUT_DIR}/root-ca-cert.pem" \
    -CAkey "${OUT_DIR}/root-ca-key.pem" \
    -CAcreateserial \
    -days "${DAYS}" \
    -sha256 \
    -extfile "${CNF}" \
    -extensions v3_ee \
    -out "${OUT_DIR}/root-ca-client.pem"
  cert_to_txt "${OUT_DIR}/root-ca-client.pem" "${OUT_DIR}/root-ca-client.txt"

  chmod 644 \
    "${OUT_DIR}/root-ca-cert.pem" \
    "${OUT_DIR}/sub-ca-cert.pem" \
    "${OUT_DIR}/sub-ca-crl.pem" \
    "${OUT_DIR}/sub-ca-client.pem" \
    "${OUT_DIR}/sub-ca-client.txt" \
    "${OUT_DIR}/root-ca-client.pem" \
    "${OUT_DIR}/root-ca-client.txt"
  chmod 600 "${OUT_DIR}/root-ca-key.pem" "${OUT_DIR}/sub-ca-key.pem"
  rm -f "${OUT_DIR}/root-ca-cert.srl" "${OUT_DIR}/sub-ca-cert.srl"

  echo
  echo "Bootstrap wrote:"
  echo "  ${OUT_DIR}/root-ca-cert.pem"
  echo "  ${OUT_DIR}/root-ca-key.pem"
  echo "  ${OUT_DIR}/sub-ca-cert.pem"
  echo "  ${OUT_DIR}/sub-ca-key.pem"
  echo "  ${OUT_DIR}/sub-ca-crl.pem"
  echo "  ${OUT_DIR}/sub-ca-client.pem / .txt"
  echo "  ${OUT_DIR}/root-ca-client.pem / .txt"
  echo
  openssl verify -CAfile "${OUT_DIR}/root-ca-cert.pem" "${OUT_DIR}/sub-ca-cert.pem"
  openssl verify -CAfile "${OUT_DIR}/root-ca-cert.pem" -untrusted "${OUT_DIR}/sub-ca-cert.pem" \
    "${OUT_DIR}/sub-ca-client.pem"
  openssl verify -CAfile "${OUT_DIR}/root-ca-cert.pem" "${OUT_DIR}/root-ca-client.pem"
}

append_cas() {
  need_openssl
  CA_DIR="$(native_path "$(cd "${CA_DIR}" && pwd)")"
  local ROOT_CERT="${CA_DIR}/root-ca-cert.pem"
  local SUB_CERT="${CA_DIR}/sub-ca-cert.pem"
  local SUB_KEY
  if [[ -f "${CA_DIR}/sub-ca-key.pk8" ]]; then
    SUB_KEY="${CA_DIR}/sub-ca-key.pk8"
  elif [[ -f "${CA_DIR}/sub-ca-key.pem" ]]; then
    SUB_KEY="${CA_DIR}/sub-ca-key.pem"
  else
    echo "No sub-ca key in ${CA_DIR} (expected sub-ca-key.pk8 or sub-ca-key.pem)" >&2
    echo "Run: tools/make_test_cas.sh bootstrap" >&2
    exit 1
  fi

  for f in "${ROOT_CERT}" "${SUB_CERT}" "${SUB_KEY}"; do
    if [[ ! -f "${f}" ]]; then
      echo "Missing ${f}" >&2
      echo "Run: tools/make_test_cas.sh bootstrap" >&2
      exit 1
    fi
  done

  mkdir -p "${OUT_DIR}"
  OUT_DIR="$(native_path "$(cd "${OUT_DIR}" && pwd)")"

  local PASSIN=()
  if openssl pkey -in "${SUB_KEY}" -passin "pass:${PASS}" -noout >/dev/null 2>&1; then
    PASSIN=(-passin "pass:${PASS}")
  elif openssl pkey -in "${SUB_KEY}" -noout >/dev/null 2>&1; then
    PASSIN=()
  else
    echo "Failed to load ${SUB_KEY} (try -p PASS)" >&2
    exit 1
  fi

  local SUB_DN
  SUB_DN="$(dn_slash "${SUB_CERT}")"
  local WORK
  WORK="$(mktemp_work a2c-test-cas)"
  # shellcheck disable=SC2064
  trap "rm -rf '${WORK}'" EXIT

  mkdir -p "${WORK}/newcerts"
  touch "${WORK}/index.txt"
  printf '01\n' >"${WORK}/serial"

  local CNF="${WORK}/openssl.cnf"
  cat >"${CNF}" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${WORK}
database          = ${WORK}/index.txt
serial            = ${WORK}/serial
new_certs_dir     = ${WORK}/newcerts
certificate       = ${OUT_DIR}/new-root.pem
private_key       = ${OUT_DIR}/new-root-key.pem
default_days      = ${DAYS}
default_md        = sha256
policy            = policy_any
x509_extensions   = v3_ca
copy_extensions   = none
unique_subject    = no
email_in_dn       = no

[ policy_any ]
commonName                = supplied
countryName               = optional
stateOrProvinceName       = optional
localityName              = optional
organizationName          = optional
organizationalUnitName    = optional
emailAddress              = optional

[ req ]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_root

[ req_dn ]
CN = new-root

[ v3_root ]
basicConstraints       = critical,CA:true
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash

[ v3_ca ]
basicConstraints       = critical,CA:true
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

  umask 077
  openssl req -new -x509 -newkey rsa:4096 -nodes \
    -keyout "${OUT_DIR}/new-root-key.pem" \
    -out "${OUT_DIR}/new-root.pem" \
    -days "${DAYS}" \
    -subj "/CN=new-root" \
    -sha256 \
    -config "${CNF}" \
    -extensions v3_root

  openssl req -new -key "${SUB_KEY}" "${PASSIN[@]}" \
    -subj "${SUB_DN}" \
    -out "${WORK}/sub-ca.csr" \
    -sha256

  openssl x509 -req -in "${WORK}/sub-ca.csr" \
    -CA "${OUT_DIR}/new-root.pem" \
    -CAkey "${OUT_DIR}/new-root-key.pem" \
    -CAserial "${WORK}/serial" \
    -days "${DAYS}" \
    -sha256 \
    -extfile "${CNF}" \
    -extensions v3_ca \
    -out "${OUT_DIR}/sub-ca-cross.pem"

  openssl ca -batch -notext \
    -config "${CNF}" \
    -ss_cert "${ROOT_CERT}" \
    -days "${DAYS}" \
    -out "${OUT_DIR}/root-ca-cross.pem"

  local OLD_ROOT_FP OLD_SUB_FP rel_out
  OLD_ROOT_FP="$(fp "${ROOT_CERT}")"
  OLD_SUB_FP="$(fp "${SUB_CERT}")"
  rel_out="${OUT_DIR}"
  case "${OUT_DIR}" in
    "${REPO_ROOT}"/*) rel_out="${OUT_DIR#"${REPO_ROOT}"/}" ;;
    *) rel_out="${OUT_DIR}" ;;
  esac

  echo
  echo "Wrote:"
  echo "  ${OUT_DIR}/new-root.pem"
  echo "  ${OUT_DIR}/new-root-key.pem"
  echo "  ${OUT_DIR}/sub-ca-cross.pem"
  echo "  ${OUT_DIR}/root-ca-cross.pem"
  echo
  echo "openssl verify:"
  openssl verify -CAfile "${OUT_DIR}/new-root.pem" "${OUT_DIR}/sub-ca-cross.pem"
  openssl verify -CAfile "${OUT_DIR}/new-root.pem" "${OUT_DIR}/root-ca-cross.pem"
  echo
  echo "acme_srv.cfg — layout B (re-issued ICA). Skip old sub-ca + old root:"
  cat <<EOF
cert_chain_skip_list: ["${OLD_SUB_FP}", "${OLD_ROOT_FP}"]
cert_chain_append: ["${rel_out}/sub-ca-cross.pem", "${rel_out}/new-root.pem"]
# cert_chain_link_check: True
EOF
  echo
  echo "acme_srv.cfg — layout A (cross-signed old root). Skip old root only:"
  cat <<EOF
cert_chain_skip_list: ["${OLD_ROOT_FP}"]
cert_chain_append: ["${rel_out}/root-ca-cross.pem", "${rel_out}/new-root.pem"]
# cert_chain_link_check: True
EOF
  echo
  if [[ -f "${CA_DIR}/root-ca-key.pem" ]]; then
    echo "Source CA includes root-ca-key.pem; append still uses openssl ca -ss_cert for root-ca-cross."
  else
    echo "No root-ca private key required in ${CA_DIR}; root-ca-cross uses openssl ca -ss_cert."
  fi
  echo "Keep ${rel_out}/new-root-key.pem out of git (test/new_ca/ is gitignored)."
}

case "${MODE}" in
  bootstrap) bootstrap_ca ;;
  append) append_cas ;;
  *) usage >&2; exit 2 ;;
esac
