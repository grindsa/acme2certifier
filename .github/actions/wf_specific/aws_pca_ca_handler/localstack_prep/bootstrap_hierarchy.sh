#!/usr/bin/env bash
# Bootstrap a 2-level ACM PCA hierarchy (ROOT + SUBORDINATE PathLen0).
#
# Works against LocalStack (endpoint_url) or real AWS. Requires aws CLI and
# credentials in the environment (LocalStack: AWS_ACCESS_KEY_ID=test /
# AWS_SECRET_ACCESS_KEY=test is enough).
#
# Usage:
#   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
#     ./bootstrap_hierarchy.sh [--endpoint-url URL] [--region REGION]
#
# Prints KEY=value lines for the issuing (subordinate) CA suitable for
# GitHub Actions GITHUB_ENV or `eval "$(...)"`:
#   AWS_PCA_ROOT_CA_ARN=...
#   AWS_PCA_CA_ARN=...          # use this as certificate_authority_arn in a2c
#   AWS_PCA_REGION=...
#
# See docs/aws_pca.md (LocalStack section).
set -euo pipefail

ENDPOINT_URL="${ACM_PCA_ENDPOINT_URL:-${AWS_ENDPOINT_URL:-}}"
REGION="${AWS_DEFAULT_REGION:-eu-central-1}"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
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

wait_for_certificate() {
  local ca_arn="$1"
  local cert_arn="$2"
  local out_pem="$3"
  local deadline=$((SECONDS + 60))
  : >"${out_pem}"
  while ((SECONDS < deadline)); do
    if aws_pca get-certificate \
      --certificate-authority-arn "${ca_arn}" \
      --certificate-arn "${cert_arn}" \
      --query Certificate \
      --output text >"${out_pem}" 2>/dev/null; then
      if grep -q "BEGIN CERTIFICATE" "${out_pem}"; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "Timed out waiting for certificate ${cert_arn}" >&2
  return 1
}

create_ca() {
  local ca_type="$1"
  local common_name="$2"
  aws_pca create-certificate-authority \
    --certificate-authority-configuration "{
      \"KeyAlgorithm\":\"RSA_2048\",
      \"SigningAlgorithm\":\"SHA256WITHRSA\",
      \"Subject\":{
        \"Country\":\"DE\",
        \"Organization\":\"acme2certifier\",
        \"OrganizationalUnit\":\"CI\",
        \"CommonName\":\"${common_name}\"
      }
    }" \
    --certificate-authority-type "${ca_type}" \
    --query CertificateAuthorityArn \
    --output text
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

echo "Creating ROOT CA..." >&2
ROOT_ARN="$(create_ca ROOT a2c-localstack-root)"
echo "ROOT ARN: ${ROOT_ARN}" >&2

aws_pca get-certificate-authority-csr \
  --certificate-authority-arn "${ROOT_ARN}" \
  --output text >"${WORK}/root.csr"

ROOT_CERT_ARN="$(
  aws_pca issue-certificate \
    --certificate-authority-arn "${ROOT_ARN}" \
    --csr "fileb://${WORK}/root.csr" \
    --signing-algorithm SHA256WITHRSA \
    --template-arn arn:aws:acm-pca:::template/RootCACertificate/V1 \
    --validity Value=10,Type=YEARS \
    --query CertificateArn \
    --output text
)"
echo "ROOT certificate ARN: ${ROOT_CERT_ARN}" >&2

wait_for_certificate "${ROOT_ARN}" "${ROOT_CERT_ARN}" "${WORK}/root.pem"

aws_pca import-certificate-authority-certificate \
  --certificate-authority-arn "${ROOT_ARN}" \
  --certificate "fileb://${WORK}/root.pem"

assert_active "${ROOT_ARN}" "ROOT CA"

echo "Creating SUBORDINATE CA..." >&2
SUB_ARN="$(create_ca SUBORDINATE a2c-localstack-sub)"
echo "SUBORDINATE ARN: ${SUB_ARN}" >&2

aws_pca get-certificate-authority-csr \
  --certificate-authority-arn "${SUB_ARN}" \
  --output text >"${WORK}/sub.csr"

# Parent (ROOT) issues the subordinate CA certificate (PathLen0 → end-entity only).
SUB_CERT_ARN="$(
  aws_pca issue-certificate \
    --certificate-authority-arn "${ROOT_ARN}" \
    --csr "fileb://${WORK}/sub.csr" \
    --signing-algorithm SHA256WITHRSA \
    --template-arn arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1 \
    --validity Value=5,Type=YEARS \
    --query CertificateArn \
    --output text
)"
echo "SUBORDINATE certificate ARN: ${SUB_CERT_ARN}" >&2

wait_for_certificate "${ROOT_ARN}" "${SUB_CERT_ARN}" "${WORK}/sub.pem"

# Certificate chain for import must be parents only (root), not the subordinate cert.
if ! aws_pca get-certificate \
  --certificate-authority-arn "${ROOT_ARN}" \
  --certificate-arn "${SUB_CERT_ARN}" \
  --query CertificateChain \
  --output text >"${WORK}/sub-chain.pem" 2>/dev/null \
  || ! grep -q "BEGIN CERTIFICATE" "${WORK}/sub-chain.pem"; then
  cp "${WORK}/root.pem" "${WORK}/sub-chain.pem"
fi

aws_pca import-certificate-authority-certificate \
  --certificate-authority-arn "${SUB_ARN}" \
  --certificate "fileb://${WORK}/sub.pem" \
  --certificate-chain "fileb://${WORK}/sub-chain.pem"

assert_active "${SUB_ARN}" "SUBORDINATE CA"

echo "2-level ACM PCA hierarchy ready (issuing CA = subordinate)." >&2

cat <<EOF
AWS_PCA_ROOT_CA_ARN=${ROOT_ARN}
AWS_PCA_CA_ARN=${SUB_ARN}
AWS_PCA_REGION=${REGION}
EOF
