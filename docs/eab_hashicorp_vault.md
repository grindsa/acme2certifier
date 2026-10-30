<!-- markdownlint-disable MD013 -->

<!-- wiki-title: HashiCorp Vault / OpenBao EAB Handler -->
<!-- wiki-category: Features -->

# HashiCorp Vault / OpenBao EAB Handler

This EAB handler loads `kid` / MAC credentials (and optional [EAB profiling](eab_profiling.md) data) from a [HashiCorp Vault](https://developer.hashicorp.com/vault) or [OpenBao](https://openbao.org/) **KV version 2** secrets engine.

See also [External Account Binding](eab.md) for the general EAB feature, other built-in handlers, and shared options such as `eab_strict_mode`.

**Scope:** HashiCorp Vault and API-compatible OpenBao only. Other secret managers (for example AWS Secrets Manager, Azure Key Vault, or Google Secret Manager) use different APIs and are not supported by this handler.

The `acme2certifier` module is `acme2certifier.eabhandlers.hashicorp_vault_handler`. See [Configuration](#configuration) for `acme_srv.cfg` options. The sections below describe how to prepare Vault / OpenBao and how to create secrets.

## Prerequisites

- HashiCorp Vault or OpenBao installed, initialized, unsealed, and reachable from the host that will run `acme2certifier`
- KV secrets engine **version 2** enabled at a mount path of your choice (examples below use `secret`)
- A token (or other credential that yields a token) with permission to **read** the EAB secret paths; operators who create secrets also need **create** / **update** on those paths

## Enable KV v2 and choose a path layout

Enable a KV v2 mount if you do not already have one:

```bash
# HashiCorp Vault CLI
vault secrets enable -path=secret kv-v2

# OpenBao CLI (equivalent)
bao secrets enable -path=secret kv-v2
```

Store **one secret per EAB kid** under a common prefix. Recommended layout:

```text
<mount>/acme/eab/<kid>
```

Examples:

| Logical path (CLI) | KV v2 API path (read) |
| --- | --- |
| `secret/acme/eab/keyid_00` | `/v1/secret/data/acme/eab/keyid_00` |
| `secret/acme/eab/keyid_01` | `/v1/secret/data/acme/eab/keyid_01` |

The kid string in the last path segment must match the External Account Binding key identifier given to the ACME client.

## Secret value formats

Each kid secret supports two payload shapes. The handler treats them as follows:

| Stored payload | Meaning |
| --- | --- |
| A **string** | HMAC / MAC key only (Base64), same role as the [JSON Handler](eab.md#json-handler) value for that kid. No EAB profiling parameters. |
| A **JSON object** | Full kid profile: required `hmac` field plus optional profiling keys (`cahandler`, `challenge`, `authorization`, …), same shape as one entry in a [kid profile](eab_profiling.md) file or the [SQL handler](eab.md#sql-handler) `profile` column. |

KV v2 always stores a map of fields. Use a single field named `value` for the payload:

- HMAC-only: `value` is the Base64 MAC string
- Profile: `value` is a JSON object (or a JSON string that parses to that object) containing at least `hmac`

If `value` is omitted, a secret whose data is already a profile object (top-level `hmac` key) is accepted as a profile. A secret with a single string-valued field may be treated as HMAC-only.

## Create an HMAC-only secret (string)

```bash
vault kv put -mount=secret acme/eab/keyid_00 \
  value='bWFjXz...Aw'
```

OpenBao:

```bash
bao kv put -mount=secret acme/eab/keyid_00 \
  value='bWFjXz...Aw'
```

## Create a profile secret (JSON object)

Write the same object you would place under one kid in a kid-profiles file. Example body:

```json
{
  "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAx",
  "cahandler": {
    "vault-role": ["clientauth", "serverauth"],
    "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
  }
}
```

Put that object into the `value` field (CLI example using a here-document; adjust quoting for your shell):

```bash
vault kv put -mount=secret acme/eab/keyid_01 value="$(cat <<'EOF'
{
  "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAx",
  "cahandler": {
    "vault-role": ["clientauth", "serverauth"],
    "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
  }
}
EOF
)"
```

You can also write the profile fields as the secret data map itself (no `value` wrapper) when your tooling supports nested JSON, as long as a top-level `hmac` key is present.

## ACL / policy notes

Grant the runtime token least privilege: typically `read` (and `list` if the deployment lists kids under the prefix) on `secret/data/acme/eab/*` and, if required for list, `secret/metadata/acme/eab/*`. Operators who rotate credentials need `create` / `update` on the same paths.

Example policy fragment (adjust mount and prefix):

```hcl
path "secret/data/acme/eab/*" {
  capabilities = ["read"]
}

path "secret/metadata/acme/eab/*" {
  capabilities = ["list", "read"]
}
```

Do not grant broader `secret/*` access than necessary. The Vault / OpenBao token used by `acme2certifier` is itself a secret; prefer injecting it via environment (see [Configuration](#configuration) for `vault_token` / `vault_token_variable`) rather than committing it to the config file in cleartext when possible.

## Configuration

Activate the handler in the `[EABhandler]` section of `acme_srv.cfg`:

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.hashicorp_vault_handler
vault_url: https://vault.example.com:8200
vault_mount: secret
vault_prefix: acme/eab
vault_token_variable: VAULT_TOKEN
eab_profiling: True
```

Example with a token set directly in the config file (prefer `vault_token_variable` in production):

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.hashicorp_vault_handler
vault_url: https://vault.example.com:8200
vault_mount: secret
vault_prefix: acme/eab
vault_token: s.YourVaultToken
eab_profiling: True
```

Shared EAB options such as `eab_strict_mode` and `eabkid_check_disable` are documented in [External Account Binding](eab.md).

### Options

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `eab_handler_module` | yes | — | `acme2certifier.eabhandlers.hashicorp_vault_handler` |
| `vault_url` | yes | — | Base URL of the Vault / OpenBao server (no `/v1` suffix) |
| `vault_mount` | no | `secret` | KV v2 mount path |
| `vault_prefix` | no | `acme/eab` | Path under the mount that holds one secret per kid |
| `vault_token` | yes\* | — | Vault / OpenBao token used for KV reads |
| `vault_token_variable` | yes\* | — | Name of an environment variable that holds the token |
| `vault_secret_key` | no | `value` | Field name inside the KV secret that holds the string or JSON payload |
| `cache_ttl` | no | `60` | Per-kid in-process cache lifetime in seconds; `0` or negative disables caching |
| `request_timeout` | no | `20` | HTTP timeout in seconds |
| `request_retries` | no | `3` | HTTP retry count for Vault API calls |
| `request_retry_backoff` | no | `2.0` | Backoff factor between retries |
| `ca_bundle` | no | `True` | TLS verification for the Vault / OpenBao HTTPS endpoint (`True`/`False` or path to a CA bundle) |
| `eab_profiling` | no | `False` | Enable [EAB profiling](eab_profiling.md) using profile objects stored in Vault |

\* Provide either `vault_token` or `vault_token_variable` (or both). If both are set, `vault_token` overwrites the environment value (same semantics as other handlers that use `*_variable`).

Proxies for the Vault host can be configured via `[DEFAULT] proxy_server_list` as for other handlers.

### Caching

Successful per-kid KV reads are cached in memory on the handler instance for `cache_ttl` seconds (default 60). This reduces load on Vault during hot paths such as EAB kid checks and profiling lookups. The cache is not shared across processes or workers. There is no push invalidation when a secret is rotated in Vault; updates become visible after the TTL expires (or immediately if `cache_ttl` is `0` or negative). Listing kids under the prefix is not cached.

### Auth notes

- MVP authentication is **token only** (static token or token from the environment). AppRole / Kubernetes auth is not implemented in this handler.
- The token used by the [Vault PKI CA handler](vault.md) (`[CAhandler]`) is independent of the EAB handler token. You may use the same token or separate least-privilege tokens.
- OpenBao is configured the same way: point `vault_url` at the OpenBao API and use an OpenBao token.

### EAB profiling with this handler

Set `eab_profiling: True` and store JSON profile objects (with `hmac` plus optional `cahandler` / `challenge` / …) for the kids that need enrollment overrides. HMAC-only string secrets remain valid for account binding but contribute no profiling parameters. Profile field semantics are unchanged from [EAB profiling](eab_profiling.md).
