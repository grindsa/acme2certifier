<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title: AWS Private CA Handler -->
<!-- wiki-category: CA Handlers -->

# AWS Private CA (ACM PCA) handler

## Status

This handler is **experimental**. It has been developed and covered by unit tests against mocked ACM PCA HTTP responses, but it has **not** been validated against a real AWS Private CA (or LocalStack Ultimate) deployment by the maintainer.

Real-world testers are highly welcome — please report success, failures, and configuration notes via [GitHub Issues](https://github.com/grindsa/acme2certifier/issues/new) or a pull request.

## Overview

This CA handler enrolls and revokes certificates via [AWS Private Certificate Authority](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html) using the ACM PCA HTTPS JSON APIs (`IssueCertificate`, `GetCertificate`, `RevokeCertificate`) signed with [AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html).

No `boto3` dependency — only `requests` (already required by acme2certifier).

AWS Private CA does **not** expose ACME natively; acme2certifier provides the ACME front-end.

The enrollment PEM bundle is **leaf + issuing CA + parent chain (including root when returned by ACM PCA)**. `GetCertificate` often only includes the intermediate; the handler always merges `GetCertificateAuthorityCertificate` for the configured issuing CA so subordinate hierarchies return a full chain. To drop the trust anchor afterward, use [`cert_chain_skip_list`](cert_chain.md).

## Prerequisites

- An **ACTIVE** AWS Private CA (or LocalStack Ultimate stand-in)
- Static IAM credentials (access key + secret), or standard `AWS_*` environment variables
- IAM permissions for:
  - `acm-pca:IssueCertificate`
  - `acm-pca:GetCertificate`
  - `acm-pca:GetCertificateAuthorityCertificate`
  - `acm-pca:DescribeCertificateAuthority`
  - `acm-pca:RevokeCertificate` (if revocation is used)

Named AWS CLI profiles, SSO, and IMDS instance roles are **not** supported (use explicit keys / env vars).

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
# aws_access_key_id: ...
# aws_secret_access_key: ...
# aws_access_key_id_variable: AWS_ACCESS_KEY_ID
# aws_secret_access_key_variable: AWS_SECRET_ACCESS_KEY
# poll_timeout: 60
# poll_interval: 1.0
# request_timeout: 60
# ca_bundle: /path/to/custom-ca.pem
# verify: True
```

| Parameter | Required | Description |
| --- | --- | --- |
| `aws_region` | yes | AWS region of the private CA |
| `certificate_authority_arn` | yes | ARN of the issuing CA |
| `signing_algorithm` | no | Default `SHA256WITHRSA` |
| `validity_days` | no | End-entity validity in days (default `365`) |
| `template_arn` | no | Optional ACM PCA certificate template ARN |
| `endpoint_url` | no | Custom endpoint (LocalStack, VPC endpoint, etc.); `http://` or `https://` |
| `ca_bundle` | no | TLS trust for HTTPS endpoints: PEM path, `True` (system trust, default), or `False` (disable verification) |
| `verify` | no | Set `False` to disable TLS certificate verification (default `True`). Prefer `ca_bundle` over disabling verify |
| `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token` | yes\* | Explicit credentials |
| `*_variable` | no | Read the matching credential from an environment variable (direct config overwrites env, same as other handlers) |
| `poll_timeout` / `poll_interval` | no | Wait loop for `GetCertificate` after issue |
| `request_timeout` | no | HTTP timeout in seconds (default `60`) |

\*Required unless `endpoint_url` is set (LocalStack placeholder keys `test`/`test` are used), or credentials are available via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` after config load.

## Local development / testing

Unit tests mock HTTPS responses — no AWS account and no LocalStack license required:

```bash
pytest test/test_aws_pca_handler.py
```

### LocalStack (Ultimate plan required)

[LocalStack ACM PCA](https://docs.localstack.cloud/aws/services/acm-pca/) is available starting with the **Ultimate** plan (not Hobby/Community). If you have a license:

```bash
export LOCALSTACK_AUTH_TOKEN=...
docker run --rm -p 4566:4566 localstack/localstack
```

Bootstrap a **2-level hierarchy** (ROOT + SUBORDINATE PathLen0) with the shared script used by CI:

```bash
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=eu-central-1
eval "$(
  .github/actions/wf_specific/aws_pca_ca_handler/localstack_prep/bootstrap_hierarchy.sh \
    --endpoint-url http://localhost:4566 \
    --region eu-central-1
)"

# AWS_PCA_CA_ARN is the issuing subordinate CA; AWS_PCA_ROOT_CA_ARN is the root.
```

Script path: [`.github/actions/wf_specific/aws_pca_ca_handler/localstack_prep/bootstrap_hierarchy.sh`](../.github/actions/wf_specific/aws_pca_ca_handler/localstack_prep/bootstrap_hierarchy.sh).

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.aws_pca_ca_handler
aws_region: eu-central-1
certificate_authority_arn: <AWS_PCA_CA_ARN from bootstrap_hierarchy.sh>
endpoint_url: http://localhost:4566
```

Both CAs must be `ACTIVE` before a2c enrollment. Point `certificate_authority_arn` at the **subordinate** (issuing) CA so enrollment returns leaf + ICA + root.

### Real AWS (cheap trial)

- First private CA per account/Region: **30-day CA operation trial** (issued certificates are still billed).
- Prefer **short-lived certificate mode** (~$50/month) for experiments.
- Delete the CA after testing to stop the monthly fee.

## ACME profiles / EAB

`template_arn` can be overridden via EAB profiling / ACME profiles using the mapping field `template_arn` (same pattern as other handlers).

## Revocation

Revocation maps ACME/RFC 5280 reason names to AWS `RevocationReason` values (`UNSPECIFIED`, `KEY_COMPROMISE`, …). CRL/OCSP publication depends on the CA’s revocation configuration in AWS.
