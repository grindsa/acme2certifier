<!-- markdownlint-disable MD013 -->

<!-- wiki-title Experimental ACME dns-persist-01 Challenge Support -->

# Experimental ACME dns-persist-01 Challenge Support

## Overview

This ACME server supports the experimental `dns-persist-01` challenge type, as described in the IETF draft:

- [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)

The feature is **not part of the official ACME RFC** and is subject to change as the draft evolves. It is disabled by default and must be explicitly enabled in the configuration.

## Enabling dns-persist-01

To enable support, set in your `[Challenge]` section:

```config
[Challenge]
dns_persist_01_support: True
```

Issuer domain names are sourced from `[Directory] caaidentities`.

## Wildcard Policy Control

By default, wildcard and subdomain authorization via `policy=wildcard` is **disabled**. To enable it, set:

```config
[Challenge]
dns_persist_allow_policy_wildcard: True
```

This allows a single TXT record with `policy=wildcard` to authorize issuance for both the base domain and wildcard certificates (e.g., `acme.foo.bar` and `*.acme.foo.bar`).

## Just-In-Time (JIT) Validation

When `dns_persist_jit_validation` is enabled in the `[Challenge]` section, the server will attempt to validate a dns-persist-01 authorization immediately at authorization creation time:

- If a valid `_validation-persist.<domain>` TXT record is found and matches the requesting account, the authorization is returned as `valid` immediately (no challenge required).
- If no valid record is found, the normal challenge flow is used and the client must complete the dns-persist-01 challenge as usual.
- No ACME error is returned for JIT failure; fallback is transparent to the client.

This feature is experimental and should be used with care. It is useful for automation scenarios where DNS records are managed out-of-band and can be trusted to remain accurate.

**Configuration:**

```config
[Challenge]
dns_persist_jit_validation: True
```

**Security note:** JIT validation does not bypass any account or issuer checks. All security tradeoffs of dns-persist-01 still apply.

**See also:** [draft-ietf-acme-dns-persist §4.4](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)

## Security Tradeoffs

Persistent DNS records are powerful: anyone who can set or modify them can authorize certificate issuance for the covered domains. Hence, use only in controlled environments or for specific automation scenarios.

**dns-persist-01 is less restrictive than dns-01**:

- **Persistence**: Authorization can be granted by a long-lived DNS TXT record, not just a short-lived challenge.
- **Scope Expansion**: With `policy=wildcard`, a single record can authorize many names (wildcard and subdomains), increasing risk if the record is compromised or not properly managed.
- **No automatic expiry**: Unless `persistUntil` is set, authorizations may remain valid indefinitely.
- **No proof of control freshness**: Unlike `dns-01`, there is no guarantee the party requesting the certificate currently controls the DNS zone.

**Enabling wildcard support further increases risk:**

- A single TXT record can enable issuance for all subdomains under a base domain.
- If an attacker can set or persistently control the TXT record, they can obtain wildcard certificates for the entire domain tree.

## Status

This feature is **experimental** and intended for testing, research, and closed/private deployments. Feedback and real-world experience are welcome.
