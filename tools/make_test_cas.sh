#!/usr/bin/env bash
# Build throwaway append PEMs for cert_chain_link_check tests from the
# existing openssl sub-ca key and root/sub certificates.
#
# There is no openssl root private key next to the source CA. The old root is
# cross-signed with `openssl ca -ss_cert` (subject + SPKI from the cert).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: make_test_cas.sh [options]

Writes:
  new-root.pem / new-root-key.pem   new self-signed trust anchor
  sub-ca-cross.pem                  existing sub-ca key, issued by new-root
  root-ca-cross.pem                 existing root-ca subject+key, issued by new-root

Options:
  -o DIR     Output directory (default: <repo>/test/new_ca)
  -c DIR     Existing openssl CA directory (default: <repo>/test/ca)
  -p PASS    Passphrase for sub-ca-key.pk8 / sub-ca-key.pem
             (default: $SUBCA_KEY_PASS, else Test1234)
  -d DAYS    Validity in days (default: 3650)
  -h         This help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CA_DIR="${REPO_ROOT}/test/ca"
OUT_DIR="${REPO_ROOT}/test/new_ca"
DAYS=3650
PASS="${SUBCA_KEY_PASS:-Test1234}"

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

ROOT_CERT="${CA_DIR}/root-ca-cert.pem"
SUB_CERT="${CA_DIR}/sub-ca-cert.pem"
if [[ -f "${CA_DIR}/sub-ca-key.pk8" ]]; then
  SUB_KEY="${CA_DIR}/sub-ca-key.pk8"
elif [[ -f "${CA_DIR}/sub-ca-key.pem" ]]; then
  SUB_KEY="${CA_DIR}/sub-ca-key.pem"
else
  echo "No sub-ca key in ${CA_DIR} (expected sub-ca-key.pk8 or sub-ca-key.pem)" >&2
  exit 1
fi

for f in "${ROOT_CERT}" "${SUB_CERT}" "${SUB_KEY}"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing ${f}" >&2
    exit 1
  fi
done

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

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

PASSIN=()
if openssl pkey -in "${SUB_KEY}" -passin "pass:${PASS}" -noout >/dev/null 2>&1; then
  PASSIN=(-passin "pass:${PASS}")
elif openssl pkey -in "${SUB_KEY}" -noout >/dev/null 2>&1; then
  PASSIN=()
else
  echo "Failed to load ${SUB_KEY} (try -p PASS)" >&2
  exit 1
fi

SUB_DN="$(dn_slash "${SUB_CERT}")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/a2c-test-cas.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

mkdir -p "${WORK}/newcerts"
touch "${WORK}/index.txt"
printf '01\n' >"${WORK}/serial"

CNF="${WORK}/openssl.cnf"
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
echo "No root-ca private key in ${CA_DIR}; root-ca-cross uses openssl ca -ss_cert."
echo "Keep ${rel_out}/new-root-key.pem out of git (test/new_ca/ is gitignored)."
