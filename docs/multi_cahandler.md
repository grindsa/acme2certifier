<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Multi-CAhandler configuration -->
<!-- wiki-category: Features -->

# Multi-CAhandler configuration

Starting with acme2certifier 0.46, a single instance can load **several CA handler plugins** and select one per certificate lifecycle (enroll, poll, revoke) based on EAB kid profile, ACME order profile, CSR domain patterns, or a configured default.

Design reference: [`architecture/multi-cahandler-design.md`](architecture/multi-cahandler-design.md).

## When to use it

Use multi-handler mode when one ACME endpoint must talk to more than one backend CA — for example a local OpenSSL sub-CA for internal names and XCA/EJBCA for production templates.

Classical single-handler setups are unchanged: omit `multi_handler` or set it to `false`.

## Configuration overview

| Key | Section | Purpose |
| --- | --- | --- |
| `multi_handler` | `[CAhandler]` | Enable registry mode (`true` / `false`) |
| `default_handler` | `[CAhandler]` | Registry name used when nothing else matches |
| `handler_module` | `[CAhandler:<name>]` | Handler class for each named entry |
| `profile_cahandler` | `[Order]` | Map ACME profile → registry name |
| `cahandler_name` | EAB kid profile | Per-account handler override (kid level) |
| `allowed_domainlist` | `[CAhandler:<name>]` | Optional CSR domain routing (regex list) |

Process-wide flags (`profiles_sync`, `ca_error_details_forward`, …) stay on `[CAhandler]`, not on each named section.

## INI example

```ini
[CAhandler]
multi_handler: True
default_handler: openssl
ca_error_details_forward: False

[CAhandler:openssl]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
issuing_ca_key: acme_srv/ca/sub-ca-key.pk8
issuing_ca_cert: acme_srv/ca/sub-ca-cert.pem

[CAhandler:ejbca]
handler_module: acme2certifier.cahandlers.ejbca_ca_handler
api_host: https://ejbca.example
allowed_domainlist: ["\\.corp\\.example$"]

[Order]
profiles: {"short": "https://example/p/short", "long": "https://example/p/long"}
profile_cahandler: {"short": "openssl", "long": "ejbca"}
```

## YAML example

```yaml
CAhandler:
  multi_handler: true
  default_handler: openssl

CAhandler:openssl:
  handler_module: acme2certifier.cahandlers.openssl_ca_handler
  issuing_ca_key: acme_srv/ca/sub-ca-key.pk8

CAhandler:ejbca:
  handler_module: acme2certifier.cahandlers.ejbca_ca_handler
  api_host: https://ejbca.example

Order:
  profiles:
    short: https://example/p/short
    long: https://example/p/long
  profile_cahandler:
    short: openssl
    long: ejbca
```

Top-level keys such as `CAhandler:openssl:` map to INI sections `[CAhandler:openssl]`. Do **not** nest handlers under `CAhandler.openssl:` — that stays inside section `[CAhandler]`.

## Handler selection (precedence)

1. **Stored** `orders.cahandler` (revoke / poll stickiness after first enroll)
2. **EAB** `cahandler_name` on the kid profile (hard error if unknown)
3. **`profile_cahandler`** map for the order's ACME profile
4. **Domain routing** — every DNS identifier in the CSR must match the handler's `allowed_domainlist`
5. **`default_handler`**

## EAB kid profile

Add `cahandler_name` at the **kid** level (not inside the `cahandler` attribute block):

```json
{
  "keyid_01": {
    "hmac": "hmac-key",
    "cahandler_name": "ejbca",
    "cahandler": {
      "cert_profile_name": "serverShort"
    }
  }
}
```

See also [EAB profiling](eab_profiling.md). The `cahandler` block still applies attribute overrides on the **selected** handler instance.

## Directory health checks

When `multi_handler` is enabled, the directory endpoint runs `handler_check()` on:

- the `default_handler`, and
- every handler referenced by `profile_cahandler`.

The first failure returns a directory error (same severity as classical single-handler mode). This catches misconfiguration in a backend you route to via profile mapping even if it is not the default.

## Profile sync (`profiles_sync`)

If `[CAhandler] profiles_sync` is enabled, each referenced handler that implements `synchronize_profiles()` contributes to the directory `meta.profiles` map. Profiles are **merged by key**; overlapping keys log a warning and the last sync wins. Avoid using the same profile name on multiple handlers unless they intentionally share a URL.

Static profiles from `[Order] profiles` disable sync (unchanged classical behaviour).

## Database

Multi-handler mode persists the chosen registry name on `orders.cahandler` at first enroll. Existing databases are migrated automatically (WSGI schema update / Django migration `0005_order_cahandler`).

## Migration from single handler

1. Rename current handler options to `[CAhandler:yourname]` and set `handler_module`.
2. On `[CAhandler]`, set `multi_handler: True`, `default_handler: yourname`, and remove `handler_module` from `[CAhandler]` itself.
3. Add `profile_cahandler` if ACME profiles should select different handlers.
4. Restart and verify the directory responds (all referenced handlers pass `handler_check`).
5. Issue a test certificate and confirm `orders.cahandler` is populated.

## Related documentation

- [ACME profiling](acme_profiling.md) — order `profiles` and `profile_cahandler`
- [EAB profiling](eab_profiling.md) — per-account overrides and `cahandler_name`
- [Architecture design](architecture/multi-cahandler-design.md) — full algorithm and file map
