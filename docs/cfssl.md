<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for Cloudflare CFSSL -->
<!-- wiki-category: CA Handlers -->

# Connecting to Cloudflare CFSSL

This handler enrolls and revokes certificates against [CFSSL](https://github.com/cloudflare/cfssl) `cfssl serve`. CFSSL holds the CA key and signs locally (or forwards to another CFSSL). No extra Python packages are required.

## Prerequisites

- `cfssl serve` reachable from acme2certifier. The listen address inside a container must be `0.0.0.0` (the default is `127.0.0.1`).
- PEM CA certificate and unencrypted CA key passed as `-ca` and `-ca-key`.
- For revocation: `-db-config` pointing at SQLite, Postgres, or MySQL, with the [certdb schema](https://github.com/cloudflare/cfssl/tree/master/certdb) applied. Without that database, enroll still works and revoke fails. `multirootca` has no revoke endpoint.
- Optional signing config (`-config`) with a profile (`expiry`, usages, `auth_key`). Expiry is a Go duration; the finest unit is hours.

The API is `POST /api/v1/cfssl/<endpoint>` and returns `{success, result, errors, messages}`.

## Configuration

```config
[CAhandler]
handler_module: acme2certifier.cahandlers.cfssl_ca_handler
cfssl_url: http://cfssl:8888
profile: server
label:
auth_key:
chain_file:
ca_bundle: True
request_timeout: 20
request_retries: 3
request_retry_backoff: 2
```

- **cfssl_url** – base URL of `cfssl serve` (no `/api/v1/cfssl` suffix)
- **profile** – *optional* – CFSSL signing profile. Empty uses the server default. This is the ACME / header_info / EAB profile field
- **label** – *optional* – signer label for `multirootca`
- **auth_key** – *optional* – hex HMAC key. When set, enroll uses `/authsign` (standard authenticator). `auth_key_variable` reads it from the environment; a configured `auth_key` wins
- **chain_file** – *optional* – PEM file appended after the signer certificate returned by `/info` (typically the root, when CFSSL signs with an intermediate)
- **ca_bundle** – *optional* – trust store for HTTPS (`True` / `False` / PEM path; default `True`)
- **request_timeout** – *optional* – seconds (default `20`)
- **request_retries** / **request_retry_backoff** – *optional* – retries on transient HTTP failures (defaults `3` and `2`)

The handler sends the PKCS#10 CSR and does not set CFSSL `hosts` or `subject`, so the validated CSR subject and SANs are what get signed. Key usage and lifetime come from the CFSSL profile. A profile `name_whitelist`, zlint level, or `ct_log_servers` entry can still reject an issuance ACME already authorized.

`standard-ip` authentication is not supported. It binds the HMAC to the TCP peer address.

## Enrollment and revocation

Enrollment is one synchronous call. `poll` and `trigger` are not used.

The returned bundle is the leaf, the signer certificate from `POST /api/v1/cfssl/info`, then `chain_file` if configured. `bundle: true` on the CFSSL sign request is not used; that flag runs the public-trust bundler.

Revocation posts the certificate serial in decimal, the authority key identifier as lowercase hex without colons, and the ACME reason string (`unspecified`, `keyCompromise`, `superseded`, …) to `/api/v1/cfssl/revoke`.

## Passing a profile from client to server

Configure allowed profiles under `[Order]`. The selected name is sent as the CFSSL `profile`:

```config
[Order]
profiles: {"server": "http://example/profile/server", "client": "http://example/profile/client"}
```

The handler also supports [header_info_list](header_info.md) (`profile=<name>`) and [EAB profiling](eab_profiling.md). An EAB `cahandler` block can override `profile`, `label`, `cfssl_url`, or `auth_key`.

## Container

```bash
docker run --rm -p 8888:8888 \
  -v "$PWD":/cfssl \
  cfssl/cfssl:latest \
  serve -address 0.0.0.0 -port 8888 \
  -ca /cfssl/ca.pem -ca-key /cfssl/ca-key.pem \
  -config /cfssl/config.json \
  -db-config /cfssl/db.json
```

`db.json`:

```json
{"driver": "sqlite3", "data_source": "/cfssl/certs.db"}
```

CI starts this service and enrolls through acme2certifier: [`.github/workflows/cahandler-cfssl.yml`](../.github/workflows/cahandler-cfssl.yml).
