<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Trigger -->
<!-- wiki-category: Operations -->

# `ca_handler.trigger()`

The `trigger` method allows a **CA server** to invoke specific actions on **acme2certifier**. These actions are defined by the respective **CA handler**.

This method is particularly useful in scenarios where a **CSR enters a pending state**, and the **CA server has the ability to trigger scripts** after CSR approval.

## Enable the endpoint

The `/trigger` HTTP route is **disabled by default**. All of the following are required:

- Opt-in in `acme_srv.cfg`:

```ini
[Trigger]
enabled: True
hmac_keys: ["current-shared-secret", "previous-shared-secret"]
# optional: hmac_keys_file: /etc/acme2certifier/trigger_hmac_keys.json
ca_cert: /path/to/issuing-ca.pem
# auth_disable: False
```

- The loaded CA handler must set class attribute `supports_trigger = True`. If the attribute is missing, it defaults to off. Built-in handlers that set it: **Certifier**, **OpenSSL**.

- A readable `[Trigger] ca_cert` trust file (PEM; may contain multiple certificates). Submitted leaves must chain to this trust material before the database is updated.

- Authentication material: non-empty `hmac_keys` and/or `hmac_keys_file` (JSON array or one secret per line). Without keys, the endpoint stays disabled unless `auth_disable: True` **and** `ACME2CERTIFIER_I_KNOW_THE_RISK=1` (testing only; logged at CRITICAL).

At process start, acme2certifier evaluates these conditions. Misconfiguration leaves the route disabled (warning/error logged). When disabled, the route is not registered (Django/WSGI) and `Trigger.parse()` rejects requests with HTTP 403.

### Configuration reference

| Option | Description | Default |
| :--- | :--- | :--- |
| `enabled` | Master switch for `/trigger` | `False` |
| `hmac_keys` | JSON list of shared secrets accepted for request HMAC | (none) |
| `hmac_keys_file` | Optional file with a JSON list or one secret per line (merged with `hmac_keys`) | (none) |
| `ca_cert` | PEM trust file used to verify the submitted leaf (and intermediates from the handler bundle) | (none) |
| `auth_disable` | Skip HMAC checks. Ignored unless `ACME2CERTIFIER_I_KNOW_THE_RISK=1` | `False` |

## Triggering a Request

The CA server must send an **HTTP POST** to `/trigger` with:

- JSON body: `{"payload":"<base64-encoded certificate>"}` (PEM preferred; DER also accepted by Certifier/OpenSSL handlers)
- Header: `X-A2C-Trigger-Signature: <hex(HMAC-SHA256(key, raw_body))>` using any configured key

### Example (Certifier publish script)

See [`examples/trigger/certifier_trigger.sh`](../examples/trigger/certifier_trigger.sh):

```bash
export ACME2CERTIFIER_URL="http://acme.example/trigger"
export TRIGGER_HMAC_KEY="current-shared-secret"
# Certifier: /usr/local/certifier/bin/trigger.sh %cert
./examples/trigger/certifier_trigger.sh path/relative/to/certifier/base/cert.pem
```

### Manual curl

```bash
BASE64_PAYLOAD=$(base64 -w 0 < issued.pem)
BODY=$(printf '{"payload":"%s"}' "$BASE64_PAYLOAD")
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$TRIGGER_HMAC_KEY" | awk '{print $NF}')
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-A2C-Trigger-Signature: $SIG" \
  -d "$BODY" \
  "$ACME2CERTIFIER_URL/trigger"
```

## Processing the Payload

1. HMAC authentication (unless gated `auth_disable`).
1. Payload forwarded to `ca_handler.trigger()`.
1. Leaf verified against `[Trigger] ca_cert` (using intermediates from the returned bundle when present).
1. Public key matched against CSRs of orders in status `processing`. Exactly one match is required; zero or multiple matches are rejected (no database write on ambiguity).

## Expected Return Values

The `ca_handler.trigger()` method is expected to return:

- **An error message** (if any).
- **The certificate chain** in PEM format.
- **The certificate** in ASN.1 (binary) format, **Base64-encoded** (needed for later revocation).

## Database Update

If authentication and chain verification succeed and exactly one processing order matches the certificate public key, **acme2certifier** will:

1. **Update the local database**.
1. **Set the order resource status to "valid"**.
1. **Correlate** the certificate and certificate resource by comparing the public keys of the **certificate** and **CSR**.
