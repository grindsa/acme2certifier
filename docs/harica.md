<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for HARICA CertManager -->
<!-- wiki-category: CA Handlers -->

# Connecting to HARICA CertManager

This handler enrolls SSL/TLS certificates through the [HARICA CertManager](https://cm.harica.gr) REST API (`RequestServerCertificate`) for enterprises with **prevalidated domains**.

Native HARICA ACME (`https://acme-v02.harica.gr/...`) is **not** covered by this handler; use the [Generic ACME Handler](acme_ca.md) with EAB credentials instead.

## Prerequisites

- Local CertManager accounts (email/password). Federated Academic/eduGAIN login cannot be used for the API.
- Prevalidated domains in your HARICA enterprise (same organization for all CSR SANs).
  Domain validation has an expiry (`GetDomainsValidityByGroupId`); expired domains are rejected by `RequestServerCertificate` even though organization lookup may still succeed. Re-validate in CertManager before enrollment.
- **Requester 2FA:** If the requester account has 2FA enabled (typical for enterprise users), configure `requester_totp_seed`. Without it the handler cannot call `Login2FA` and enrollment fails.
- **Approver 2FA:** The **SSL Enterprise Approver** role requires 2FA. For `auto_approve`, configure `approver_email`, `approver_password`, and `approver_totp_seed` for a **different** user than the requester (HARICA four-eyes).
- Schedule [`a2c_cert_poll.py`](poll.md) when enterprise approval is manual.

API reference: [HARICA developer guides](https://guides.harica.gr/docs/Guides/Developer/3.-Request-for-SSL-Certificate-Prevalidated-Domains/) and [Swagger](https://developer.harica.gr/).

## Obtaining the TOTP seed (`requester_totp_seed` / `approver_totp_seed`)

The handler needs the **Base32 shared secret** from authenticator setup — not the rotating 6-digit code.

Do this once per account (requester and, if used, approver), while enabling or resetting 2FA in CertManager:

1. Log in at [cm.harica.gr](https://cm.harica.gr) or [cm-stg.harica.gr](https://cm-stg.harica.gr) (staging).
2. Open account / security settings and start **Enable two-factor authentication** (or reset 2FA if you must re-capture the seed).
3. CertManager shows a **QR code** for Google Authenticator / FreeOTP / etc. Prefer the **manual entry** / **secret key** text if the portal shows it — that string is the Base32 seed (spaces optional).
4. If only a QR is shown, decode it (phone QR app or a trusted offline decoder). The payload looks like:

   ```text
   otpauth://totp/HARICA:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=HARICA
   ```

   Copy the `secret=` value (`JBSWY3DPEHPK3PXP` in the example). That is what goes in `acme_srv.cfg`.
5. Finish enrollment in an authenticator app so CertManager accepts the first codes, then store the same seed in config:
   - Requester → `requester_totp_seed`
   - Approver → `approver_totp_seed` (separate seed from a separate 2FA enrollment)

Treat seeds like passwords. After setup you usually cannot view the seed again without resetting 2FA.

Verify a configured seed produces a working code (portal login / troubleshooting):

```bash
# requester (requester_totp_seed) — default
a2c-harica-totp -c /path/to/acme_srv.cfg
a2c-harica-totp -c /path/to/acme_srv.cfg --user

# SSL Enterprise Approver (approver_totp_seed)
a2c-harica-totp -c /path/to/acme_srv.cfg --approver

# also print account email + seconds remaining on stderr
a2c-harica-totp -c /path/to/acme_srv.cfg --approver -v
```

Stdout is the 6-digit code only. Without `-c`, the usual `acme_srv.cfg` discovery path is used.

## Configuration

```config
[CAhandler]
handler_module: acme2certifier.cahandlers.harica_ca_handler
api_url: https://cm.harica.gr
requester_email: user@example.com
requester_password: <password>
requester_totp_seed: <base32_secret>
# alternatively, load secrets from the environment:
# requester_email_variable: HARICA_REQUESTER_EMAIL
# requester_password_variable: HARICA_REQUESTER_PASSWORD
# requester_totp_seed_variable: HARICA_REQUESTER_TOTP_SEED
transaction_type: OV
consent_same_key: True
organization_id:
auto_approve: False
approver_email:
approver_password:
approver_totp_seed:
# approver_email_variable: HARICA_APPROVER_EMAIL
# approver_password_variable: HARICA_APPROVER_PASSWORD
# approver_totp_seed_variable: HARICA_APPROVER_TOTP_SEED
request_timeout: 60
```

| Parameter | Required | Description |
| --- | --- | --- |
| `api_url` | Yes | CertManager base URL. Production: `https://cm.harica.gr`. Testing: `https://cm-stg.harica.gr`. |
| `requester_email` | Yes* | Local CertManager login for CSR submission and polling. |
| `requester_email_variable` | Yes* | Name of the environment variable containing the requester email (`requester_email` takes precedence). |
| `requester_password` | Yes* | Password for `requester_email`. |
| `requester_password_variable` | Yes* | Name of the environment variable containing the requester password (`requester_password` takes precedence). |
| `requester_totp_seed` | If requester has 2FA | Base32 TOTP **seed** for the requester (see [Obtaining the TOTP seed](#obtaining-the-totp-seed-requester_totp_seed--approver_totp_seed)). Required for `Login2FA`. |
| `requester_totp_seed_variable` | If requester has 2FA | Name of the environment variable containing the requester TOTP seed (`requester_totp_seed` takes precedence). |
| `transaction_type` | No | `OV` (default) or `EV`. |
| `consent_same_key` | No | Allow HARICA key reuse (`true`/`false`, default `True`). |
| `organization_id` | No | Optional HARICA organization **UUID** from `CheckMatchingOrganization` (not NTR/VAT numbers). Leave empty to auto-detect from CSR domains. |
| `auto_approve` | No | After enroll, log in as approver and call `UpdateReviews` (default `False`). |
| `approver_email` | If `auto_approve`* | Separate SSL Enterprise Approver account (not the same as `requester_email`). |
| `approver_email_variable` | If `auto_approve`* | Name of the environment variable containing the approver email (`approver_email` takes precedence). |
| `approver_password` | If `auto_approve`* | Approver password. |
| `approver_password_variable` | If `auto_approve`* | Name of the environment variable containing the approver password (`approver_password` takes precedence). |
| `approver_totp_seed` | If `auto_approve` | Base32 TOTP **seed** for the approver. Approver accounts require 2FA. |
| `approver_totp_seed_variable` | If `auto_approve` | Name of the environment variable containing the approver TOTP seed (`approver_totp_seed` takes precedence). |
| `request_timeout` | No | HTTP timeout in seconds (default `60`). Staging `RequestServerCertificate` can be slow; raise to `120` if you see read timeouts. |
| `ca_bundle` | No | TLS verification (`True`, path, or `False`). |

\* Provide either the direct config value or the corresponding `*_variable` environment-variable name.

Staging credentials and enterprises are **not** mirrored from production. Use separate accounts on `https://cm-stg.harica.gr` for development.

## Enrollment flow

1. ACME client finalizes an order; acme2certifier calls `enroll(csr)`.
2. Handler logs in (`Login` or `Login2FA`), resolves organization via `CheckMachingOrganization`, submits CSR.
3. If HARICA returns the certificate immediately, the ACME order becomes **valid**.
4. Otherwise the order stays **processing** with `poll_identifier` = HARICA transaction id.
5. An approver accepts the request in CertManager (or `auto_approve` runs `UpdateReviews` with the approver’s 2FA login).
6. Cron [`a2c_cert_poll.py`](poll.md) calls `poll()` until the certificate is downloaded.

With `auto_approve`, CertManager approval often exceeds ~30s. Lego’s HTTP transport uses a fixed **ResponseHeaderTimeout** of ~30s (raising `--http-timeout` does **not** change that). Set `[Certificate] enrollment_timeout` below that limit (e.g. `15`) so finalize returns **processing** while enrollment continues in the background; the client then polls the order until the cert is stored. See [Certificate options](acme_srv.md).

Most ACME clients time out quickly on `processing`. For long approval delays, keep polling the **same** order URL or use [acmeshell](acme-clients.md).

## Revocation

Revocation looks up the HARICA transaction by certificate serial and calls `RevokeCertificate`.

## EAB Profiling and ACME Profiles

`transaction_type` can be overridden per account via [EAB profiling](eab_profiling.md) (`profile_mapping_field: transaction_type`) or [ACME profiles](acme_profiling.md).

## Alternative: native HARICA ACME

If you already have HARICA EAB credentials and prevalidated domains, configure [acme_ca_handler](acme_ca.md) against the HARICA ACME directory URL instead of this REST handler.
