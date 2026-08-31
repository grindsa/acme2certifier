<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for HARICA CertManager -->
<!-- wiki-category: CA Handlers -->

# Connecting to HARICA CertManager

This handler enrolls SSL/TLS certificates through the [HARICA CertManager](https://cm.harica.gr) REST API (`RequestServerCertificate`) for enterprises with **prevalidated domains**.

Native HARICA ACME (`https://acme-v02.harica.gr/...`) is **not** covered by this handler; use the [Generic ACME Handler](acme_ca.md) with EAB credentials instead.

## Prerequisites

- Local CertManager account (email/password). Federated Academic/eduGAIN login cannot be used for the API.
- Prevalidated domains in your HARICA enterprise (same organization for all CSR SANs).
- Optional TOTP seed if 2FA is enabled on the requester account (`Login2FA`).
- For pending issuance: an **SSL Enterprise Approver** (separate user + 2FA) or enable `auto_approve` with approver credentials in config.
- Schedule [`a2c_cert_poll.py`](poll.md) when enterprise approval is manual.

API reference: [HARICA developer guides](https://guides.harica.gr/docs/Guides/Developer/3.-Request-for-SSL-Certificate-Prevalidated-Domains/) and [Swagger](https://developer.harica.gr/).

## Configuration

```config
[CAhandler]
handler_module: acme2certifier.cahandlers.harica_ca_handler
api_url: https://cm.harica.gr
email: user@example.com
password: <password>
totp_seed: <base32_secret>
transaction_type: OV
consent_same_key: True
organization_id:
auto_approve: False
approver_email:
approver_password:
approver_totp_seed:
request_timeout: 20
```

| Parameter | Required | Description |
| --- | --- | --- |
| `api_url` | Yes | CertManager base URL. Production: `https://cm.harica.gr`. Testing: `https://cm-stg.harica.gr`. |
| `email` | Yes | Local CertManager login for CSR submission and polling. |
| `password` | Yes | Password for `email`. |
| `totp_seed` | No | Base32 TOTP secret from 2FA setup. Required when the account uses 2FA. |
| `transaction_type` | No | `OV` (default) or `EV`. |
| `consent_same_key` | No | Allow HARICA key reuse (`true`/`false`, default `True`). |
| `organization_id` | No | Restrict org lookup to this HARICA organization id. |
| `auto_approve` | No | After enroll, log in as approver and call `UpdateReviews` (default `False`). |
| `approver_email` | If `auto_approve` | Separate SSL Enterprise Approver account. |
| `approver_password` | If `auto_approve` | Approver password. |
| `approver_totp_seed` | Recommended | Approver TOTP seed (2FA is required for approver role). |
| `request_timeout` | No | HTTP timeout in seconds (default `20`). |
| `ca_bundle` | No | TLS verification (`True`, path, or `False`). |

Staging credentials and enterprises are **not** mirrored from production. Use separate accounts on `https://cm-stg.harica.gr` for development.

## Enrollment flow

1. ACME client finalizes an order; acme2certifier calls `enroll(csr)`.
2. Handler logs in, resolves organization via `CheckMachingOrganization`, submits CSR.
3. If HARICA returns the certificate immediately, the ACME order becomes **valid**.
4. Otherwise the order stays **processing** with `poll_identifier` = HARICA transaction id.
5. An approver accepts the request in CertManager (or `auto_approve` runs `UpdateReviews`).
6. Cron [`a2c_cert_poll.py`](poll.md) calls `poll()` until the certificate is downloaded.

Most ACME clients time out quickly on `processing`. For long approval delays, keep polling the **same** order URL or use [acmeshell](acme-clients.md).

## Revocation

Revocation looks up the HARICA transaction by certificate serial and calls `RevokeCertificate`.

## EAB Profiling and ACME Profiles

`transaction_type` can be overridden per account via [EAB profiling](eab_profiling.md) (`profile_mapping_field: transaction_type`) or [ACME profiles](acme_profiling.md).

## Alternative: native HARICA ACME

If you already have HARICA EAB credentials and prevalidated domains, configure [acme_ca_handler](acme_ca.md) against the HARICA ACME directory URL instead of this REST handler.
