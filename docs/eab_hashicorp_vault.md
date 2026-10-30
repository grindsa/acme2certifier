<!-- markdownlint-disable MD013 -->

<!-- wiki-title: HashiCorp Vault / OpenBao EAB Handler -->
<!-- wiki-category: Features -->

# HashiCorp Vault / OpenBao EAB Handler

This EAB handler loads `kid` / MAC credentials (and optional [EAB profiling](eab_profiling.md) data) from a [HashiCorp Vault](https://developer.hashicorp.com/vault) or [OpenBao](https://openbao.org/) **KV version 2** secrets engine.

See also [External Account Binding](eab.md) for the general EAB feature, other built-in handlers, and shared options such as `eab_strict_mode`.

**Scope:** HashiCorp Vault and API-compatible OpenBao only. Other secret managers (for example AWS Secrets Manager, Azure Key Vault, or Google Secret Manager) use different APIs and are not supported by this handler.

The `acme2certifier` module is `acme2certifier.eabhandlers.hashicorp_vault_handler`. Handler configuration in `acme_srv.cfg` will be documented in [Configuration](#configuration) once the module ships; the sections below describe how to prepare Vault / OpenBao and how to create secrets.

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

`eab_handler_module: acme2certifier.eabhandlers.hashicorp_vault_handler` and the related `[EABhandler]` options will be documented in this section when the handler module is available. Until then, use the [File](eab.md#file-handler), [JSON](eab.md#json-handler), [SQL](eab.md#sql-handler), or [kid profile](eab_profiling.md) handlers for EAB credentials.
