<!-- markdownlint-disable MD013 -->
<!-- wiki-title CA Trigger -->
# `ca_handler.trigger()`

The `trigger` method allows a **CA server** to invoke specific actions on **acme2certifier**. These actions are defined by the respective **CA handler**.

This method is particularly useful in scenarios where a **CSR enters a pending state**, and the **CA server has the ability to trigger scripts** after CSR approval.

## Triggering a Request

The CA server must send an **HTTP POST request** to the `/trigger` endpoint, including a **base64-encoded payload** in JSON format.

### Example Request

```bash
# Modify to match your setup
BASE64_PAYLOAD=$(echo "Hello Payload" | base64)
ACME2CERTIFIER_URL="http://10.97.149.146"

# Invoke curl
curl -X POST -H "Content-Type: application/json" -d "{"payload":"$BASE64_PAYLOAD"}" "$ACME2CERTIFIER_URL/trigger"
```

## Processing the Payload

- The payload is **extracted** from the POST request.
- It is **forwarded** to the `ca_handler.trigger()` method for further processing.

## Expected Return Values

The `ca_handler.trigger()` method is expected to return:

- **An error message** (if any).
- **The certificate chain** in PEM format.
- **The certificate** in ASN.1 (binary) format, **Base64-encoded** (needed for later revocation).

## Database Update

If a **valid certificate** is returned, **acme2certifier** will:

1. **Update the local database**.
2. **Set the order resource status to "valid"**.
3. **Establish correlation** between the certificate and certificate resource by comparing the public keys of the **certificate** and **CSR** (which should already exist in the database).

