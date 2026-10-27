#!/usr/bin/env bash
# Bootstrap a 2-level CA hierarchy for ACM PCA / LocalStack CI:
#   openssl ROOT (CA:TRUE)  →  ACM PCA SUBORDINATE (PathLen0, CA:TRUE)
#
# LocalStack's IssueCertificate + SubordinateCACertificate_* templates omit
# basicConstraints/keyUsage on the ICA, so openssl verify fails (error 24).
# Signing the subordinate CSR with a local openssl root avoids that gap while
# still exercising ACM PCA IssueCertificate / GetCertificate / RevokeCertificate
# on the subordinate.
#
# Requires: aws CLI, openssl. LocalStack: AWS_ACCESS_KEY_ID=test /
# AWS_SECRET_ACCESS_KEY=test is enough.
#
# Usage:
#   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
#     ./bootstrap_hierarchy.sh [--endpoint-url URL] [--region REGION]
#
# Prints KEY=value lines suitable for GitHub Actions GITHUB_ENV or eval:
#   AWS_PCA_CA_ARN=...     # issuing subordinate — use as certificate_authority_arn
#   AWS_PCA_REGION=...
#
# See docs/aws_pca.md (LocalStack section).
set -euo pipefail

ENDPOINT_URL="${ACM_PCA_ENDPOINT_URL:-${AWS_ENDPOINT_URL:-}}"
REGION="${AWS_DEFAULT_REGION:-eu-central-1}"

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint-url)
      ENDPOINT_URL="${2:-}"
      shift 2
      ;;
    --region)
      REGION="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      ;;
  esac
done

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

export AWS_DEFAULT_REGION="${REGION}"
export AWS_EC2_METADATA_DISABLED="${AWS_EC2_METADATA_DISABLED:-true}"

AWS_ARGS=()
if [[ -n "${ENDPOINT_URL}" ]]; then
  AWS_ARGS+=(--endpoint-url "${ENDPOINT_URL}")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

aws_pca() {
  aws "${AWS_ARGS[@]}" acm-pca "$@"
}

assert_active() {
  local ca_arn="$1"
  local label="$2"
  local status
  status="$(
    aws_pca describe-certificate-authority \
      --certificate-authority-arn "${ca_arn}" \
      --query CertificateAuthority.Status \
      --output text
  )"
  if [[ "${status}" != "ACTIVE" ]]; then
    echo "${label} status is '${status}', expected ACTIVE (${ca_arn})" >&2
    return 1
  fi
}

assert_ca_true() {
  local pem="$1"
  local label="$2"
  if ! openssl x509 -in "${pem}" -noout -text 2>/dev/null \
    | grep -E 'CA:TRUE|CA:TRUE,' >/dev/null; then
    echo "${label} is missing basicConstraints CA:TRUE" >&2
    openssl x509 -in "${pem}" -noout -text >&2 || true
    return 1
  fi
}

echo "Creating openssl ROOT CA..." >&2
openssl genrsa -out "${WORK}/root.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes \
  -key "${WORK}/root.key" \
  -sha256 \
  -days 3650 \
  -subj "/C=DE/O=acme2certifier/OU=CI/CN=a2c-localstack-root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out "${WORK}/root.pem"
assert_ca_true "${WORK}/root.pem" "openssl ROOT"

echo "Creating ACM PCA SUBORDINATE CA..." >&2
SUB_ARN="$(
  aws_pca create-certificate-authority \
    --certificate-authority-configuration '{
      "KeyAlgorithm":"RSA_2048",
      "SigningAlgorithm":"SHA256WITHRSA",
      "Subject":{
        "Country":"DE",
        "Organization":"acme2certifier",
        "OrganizationalUnit":"CI",
        "CommonName":"a2c-localstack-sub"
      }
    }' \
    --certificate-authority-type "SUBORDINATE" \
    --query CertificateAuthorityArn \
    --output text
)"
echo "SUBORDINATE ARN: ${SUB_ARN}" >&2

aws_pca get-certificate-authority-csr \
  --certificate-authority-arn "${SUB_ARN}" \
  --output text >"${WORK}/sub.csr"

# Sign the ACM PCA CSR with the openssl root (PathLen0 → end-entity only).
cat >"${WORK}/sub_ext.cnf" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
  -in "${WORK}/sub.csr" \
  -CA "${WORK}/root.pem" \
  -CAkey "${WORK}/root.key" \
  -CAcreateserial \
  -out "${WORK}/sub.pem" \
  -days 1825 \
  -sha256 \
  -extfile "${WORK}/sub_ext.cnf" >/dev/null
assert_ca_true "${WORK}/sub.pem" "SUBORDINATE CA certificate"

aws_pca import-certificate-authority-certificate \
  --certificate-authority-arn "${SUB_ARN}" \
  --certificate "fileb://${WORK}/sub.pem" \
  --certificate-chain "fileb://${WORK}/root.pem"

assert_active "${SUB_ARN}" "SUBORDINATE CA"

echo "2-level hierarchy ready (openssl ROOT + ACM PCA subordinate)." >&2

cat <<EOF
AWS_PCA_CA_ARN=${SUB_ARN}
AWS_PCA_REGION=${REGION}
EOF
