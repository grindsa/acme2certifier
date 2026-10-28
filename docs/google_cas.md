





# Google Cloud Private CAS handler

## Status

This handler is **experimental**. Development and automated tests use the in-repo **Mocked Private CAS REST server** ([`examples/Docker/google_privateca`](../examples/Docker/google_privateca/)); it has **not** been validated against a real Google Cloud Certificate Authority Service deployment by the maintainer.

Real-world testers are highly welcome — please report success, failures, and configuration notes via [GitHub Issues](https://github.com/grindsa/acme2certifier/issues/new) or a pull request.

The mock implements the enrollment/revoke subset of Google’s public REST reference:

- [Certificate Authority Service REST overview](https://cloud.google.com/certificate-authority-service/docs/reference/rest)
- [certificates create / get / list / revoke](https://cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools.certificates)

## Private CAS vs Public CA (do not confuse)

| Product | ACME? | Role for acme2certifier |
| --- | --- | --- |
| **Certificate Authority Service (Private CAS)** | No native ACME on private pools | This handler — REST enroll/revoke against a CA pool |
| **Certificate Manager Public CA / Google Trust Services** | Yes (ACME + EAB) | Different product; use a generic ACME client or [`acme_ca_handler`](acme_ca.md), not this handler |

## Overview

This CA handler enrolls and revokes certificates via [Google Cloud Certificate Authority Service](https://cloud.google.com/certificate-authority-service/docs) using the Private CAS HTTPS JSON API (`CreateCertificate`, `GetCertificate`, `ListCertificates`, `RevokeCertificate`) with a Bearer token.

Transport is plain `requests` (same idea as the AWS PCA handler). Real GCP auth uses optional `google-auth` (`pip install 'acme2certifier[gcp]'`). Create is synchronous: the response includes `pemCertificate` and `pemCertificateChain` (issuer→root).

## Prerequisites

- A Private CAS **CA pool** (and issuing CA) — or the local mock
- For real GCP: a service account (or ADC) with permissions such as:
  - `privateca.certificates.create`
  - `privateca.certificates.get`
  - `privateca.certificates.list` (revocation looks up by serial)
  - `privateca.certificates.update` (revoke)
  - `privateca.certificateAuthorities.get` (optional `handler_check`)
- For real GCP auth: `acme2certifier[gcp]` / `google-auth`

There is no free LocalStack-like stand-in from Google. Live E2E needs trial credits or a paid DevOps-tier CA. Console “test certificate issuance” is not usable for a2c.

## Configuration

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.google_cas_ca_handler
project: my-gcp-project
location: europe-west1
ca_pool: my-pool
# issuing_certificate_authority_id: my-ca
# certificate_template: projects/.../locations/.../certificateTemplates/...
lifetime_days: 365
# endpoint_url: https://google-cas-mock:8080
# access_token: ...
# credentials_file: /path/to/sa.json
# credentials_file_variable: GOOGLE_APPLICATION_CREDENTIALS
# ca_bundle: /path/to/custom-ca.pem
# verify: True
# request_timeout: 60
```

| Parameter                                        | Required | Description                                                                                                                         |
| ------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `project` / `location` / `ca_pool`               | yes      | Pool identity. `ca_pool` may be the pool id or a full `projects/.../caPools/...` name (if full name, project/location are optional) |
| `issuing_certificate_authority_id`               | no       | Pin issuance to a CA in the pool (query `issuingCertificateAuthorityId`)                                                            |
| `certificate_template`                           | no       | Optional CertificateTemplate resource name; EAB/profile mapping field                                                               |
| `lifetime_days`                                  | no       | End-entity lifetime in days (default `365`) → API `lifetime` Duration                                                               |
| `endpoint_url`                                   | no       | Mock / custom base URL; with no explicit creds uses a placeholder Bearer (no `google-auth`)                                         |
| `access_token` / `access_token_variable`         | no       | Explicit Bearer (wins over file / ADC)                                                                                              |
| `credentials_file` / `credentials_file_variable` | no       | Path to a service account JSON key file                                                                                             |
| `ca_bundle`                                      | no       | TLS trust for HTTPS: PEM path, `True` (system trust, default), or `False` (disable verification)                                    |
| `verify`                                         | no       | Set `False` to disable TLS certificate verification (default `True`). Prefer `ca_bundle` over disabling verify                      |
| `request_timeout` / `request_retries`            | no       | HTTP timeout / retry on 429/5xx                                                                                                     |

Credential precedence: `access_token` → `credentials_file` → ADC (`google.auth.default`). With `endpoint_url` and no explicit credentials, a placeholder Bearer is used (local mock).

After config load, `GOOGLE_APPLICATION_CREDENTIALS` is used if `credentials_file` is unset; `GOOGLE_CAS_ACCESS_TOKEN` if `access_token` is unset.

## Service account JSON (`sa.json`)

For real Private CAS (or to exercise `google-auth` against the mock via [`check_auth.py`](../examples/Docker/google_privateca/check_auth.py)), point `credentials_file` at a **Google Cloud service account key** JSON downloaded from IAM → Service account → Keys → Create key (JSON).

Typical contents:

```json
{
  "type": "service_account",
  "project_id": "your-gcp-project",
  "private_key_id": "…",
  "private_key": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n",
  "client_email": "name@your-gcp-project.iam.gserviceaccount.com",
  "client_id": "…",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/…",
  "universe_domain": "googleapis.com"
}
```

The handler (via `google-auth`) uses this file to mint an OAuth Bearer token for scope `https://www.googleapis.com/auth/cloud-platform`. Required fields in practice: `type` = `service_account`, `client_email`, `private_key`, plus the usual Google-filled URIs.

Example:

```ini
credentials_file: /path/to/sa.json
# or
credentials_file_variable: GOOGLE_APPLICATION_CREDENTIALS
```

Do **not** commit `sa.json` to git. For the local mock with only `endpoint_url`, this file is not required.

## TLS to the API / mock

Private CAS and the mock may be reached over HTTPS. Use:

- `ca_bundle` — PEM trust bundle for the server certificate
- `verify: False` — disable server-cert checking (MITM risk; the handler logs a warning)

Prefer `ca_bundle` over turning verification off.

## Local development / testing

Mock server (HTTP or HTTPS) and curl examples: [`examples/Docker/google_privateca/README.md`](../examples/Docker/google_privateca/README.md).

Example mock-backed config:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.google_cas_ca_handler
project: demo
location: europe-west1
ca_pool: demo-pool
issuing_certificate_authority_id: mock-issuing-ca
endpoint_url: https://192.168.64.3:8080
lifetime_days: 30
ca_bundle: False
```

## ACME profiles / EAB

`certificate_template` can be overridden via EAB profiling / ACME profiles using the mapping field `certificate_template`.

## Revocation

ACME revocation supplies the certificate; the handler parses the serial, lists certificates with a serial filter, then calls `:revoke` with a mapped `RevocationReason` (`KEY_COMPROMISE`, …). CRL/OCSP publication depends on the pool’s Private CAS revocation settings.
