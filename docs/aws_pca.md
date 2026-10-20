<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title: AWS Private CA Handler -->
<!-- wiki-category: CA Handlers -->

# AWS Private CA (ACM PCA) handler

## Overview

This CA handler enrolls and revokes certificates via [AWS Private Certificate Authority](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html) using the ACM PCA APIs (`IssueCertificate`, `GetCertificate`, `RevokeCertificate`).

AWS Private CA does **not** expose ACME natively; acme2certifier provides the ACME front-end.

## Prerequisites

- Python package: `boto3` (`pip install acme2certifier[aws]` or `pip install boto3`)
- An **ACTIVE** AWS Private CA (or a LocalStack / moto stand-in)
- IAM permissions (or LocalStack defaults) for:
  - `acm-pca:IssueCertificate`
  - `acm-pca:GetCertificate`
  - `acm-pca:GetCertificateAuthorityCertificate`
  - `acm-pca:DescribeCertificateAuthority`
  - `acm-pca:RevokeCertificate` (if revocation is used)

## Configuration

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.aws_pca_ca_handler
aws_region: eu-central-1
certificate_authority_arn: arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
signing_algorithm: SHA256WITHRSA
validity_days: 365
# template_arn: arn:aws:acm-pca:::template/EndEntityCertificate/V1
# endpoint_url: http://localhost:4566
# aws_profile: default
# aws_access_key_id: ...
# aws_secret_access_key: ...
# aws_access_key_id_variable: AWS_ACCESS_KEY_ID
# aws_secret_access_key_variable: AWS_SECRET_ACCESS_KEY
# poll_timeout: 60
# poll_interval: 1.0
```

| Parameter | Required | Description |
| --- | --- | --- |
| `aws_region` | yes | AWS region of the private CA |
| `certificate_authority_arn` | yes | ARN of the issuing CA |
| `signing_algorithm` | no | Default `SHA256WITHRSA` |
| `validity_days` | no | End-entity validity in days (default `365`) |
| `template_arn` | no | Optional ACM PCA certificate template ARN |
| `endpoint_url` | no | Custom endpoint (LocalStack, VPC endpoint, etc.) |
| `aws_profile` | no | Named boto3 / AWS CLI profile |
| `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token` | no | Explicit credentials (prefer env / IAM role) |
| `*_variable` | no | Read the matching credential from an environment variable |
| `poll_timeout` / `poll_interval` | no | Wait loop for `GetCertificate` after issue |

Credentials follow the normal boto3 chain when not set explicitly (env, shared config, instance/role).

When `endpoint_url` is set and no keys/profile are configured, the handler uses placeholder keys suitable for LocalStack.

## Local development / testing

### Free path: moto (recommended for CI)

Unit tests mock ACM PCA with [moto](https://github.com/getmoto/moto) — no AWS account and no LocalStack license required.

```bash
pip install boto3 moto
pytest test/test_aws_pca_handler.py
```

### LocalStack (Ultimate plan required)

[LocalStack ACM PCA](https://docs.localstack.cloud/aws/services/acm-pca/) is available starting with the **Ultimate** plan (not Hobby/Community). If you have a license:

```bash
# example
export LOCALSTACK_AUTH_TOKEN=...
docker run --rm -p 4566:4566 localstack/localstack
```

Point the handler at LocalStack:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.aws_pca_ca_handler
aws_region: eu-central-1
certificate_authority_arn: <arn from create-certificate-authority>
endpoint_url: http://localhost:4566
```

Bootstrap a ROOT CA in LocalStack with `create-certificate-authority` → `get-certificate-authority-csr` → `issue-certificate` (RootCACertificate template) → `import-certificate-authority-certificate` as described in the LocalStack ACM PCA docs. Status must be `ACTIVE` before a2c enrollment.

### Real AWS (cheap trial)

- First private CA per account/Region: **30-day CA operation trial** (issued certificates are still billed).
- Prefer **short-lived certificate mode** (~$50/month) for experiments.
- Delete the CA after testing to stop the monthly fee.

## ACME profiles / EAB

`template_arn` can be overridden via EAB profiling / ACME profiles using the mapping field `template_arn` (same pattern as other handlers).

## Revocation

Revocation maps ACME/RFC 5280 reason names to AWS `RevocationReason` values (`UNSPECIFIED`, `KEY_COMPROMISE`, …). CRL/OCSP publication depends on the CA’s revocation configuration in AWS.
