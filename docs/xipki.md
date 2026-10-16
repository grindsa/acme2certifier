<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for XiPKI -->
<!-- wiki-category: CA Handlers -->

# Connecting to XiPKI via REST

This handler enrolls and revokes certificates against the [XiPKI](https://github.com/xipki/xipki) protocol gateway using XiPKI’s own RESTful API (not XiPKI’s built-in ACME service). Use it when you want acme2certifier’s ACME features (EAB profiling, multi-CAhandler, ACME Profiles, header_info, etc.) in front of XiPKI.

## Prerequisites

- A running XiPKI **gateway** with the REST protocol enabled
- A password **requestor** allowed for REST with at least `enroll_cert` and `revoke_cert`
- A certificate **profile** the requestor may use (for example `tls`)
- The REST base URL including the CA alias, for example `https://host:8445/gw/rest/<alias>`

Authentication is HTTP Basic (`api_user` / `api_password`). TLS client-certificate requestors are not supported by this handler yet.

## Configuration

Modify `acme_srv.cfg`:

```config
[CAhandler]
handler_module: acme2certifier.cahandlers.xipki_ca_handler
api_host: https://<fqdn or ip>:8445/gw/rest/<alias>
api_user: <requestor>
api_password: <password>
ca_bundle: <True|False|filename>
profile: tls
request_timeout: 20
```

- **api_host** – XiPKI gateway REST base URL including the CA alias (no trailing slash required)
- **api_user** – REST password requestor name
- **api_password** – requestor password
- **api_password_variable** – *optional* – environment variable holding the password (a configured `api_password` wins)
- **api_user_variable** – *optional* – environment variable holding the user (a configured `api_user` wins)
- **ca_bundle** – *optional* – trust store for the gateway TLS certificate (`True` / `False` / PEM path; default `True`)
- **profile** – XiPKI certificate profile name (query parameter `profile`)
- **request_timeout** – *optional* – HTTP timeout in seconds (default `20`)

## Smoke tests

Fetch the CA certificate (public, no auth required on typical installs):

```bash
curl -sS --cacert <ca_bundle> -o /tmp/ca.der \
  "https://<host>:8445/gw/rest/<alias>/cacert"
openssl x509 -inform der -in /tmp/ca.der -noout -subject -fingerprint -sha1
```

Enroll:

```bash
curl -sS --cacert <ca_bundle> -u '<user>:<password>' \
  -H 'Content-Type: application/pkcs10' \
  --data-binary @request.csr \
  -o /tmp/leaf.der \
  "https://<host>:8445/gw/rest/<alias>/enroll-cert?profile=tls"
```

Revoke (needs issuer SHA-1 and certificate serial):

```bash
SER=$(openssl x509 -inform der -in /tmp/leaf.der -noout -serial | cut -d= -f2)
CASHA1=$(openssl x509 -inform der -in /tmp/ca.der -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
curl -sS --cacert <ca_bundle> -u '<user>:<password>' -o /dev/null -w "HTTP %{http_code}\n" \
  "https://<host>:8445/gw/rest/<alias>/revoke-cert?ca-sha1=${CASHA1}&serial-number=0x${SER}&reason=KEY_COMPROMISE"
```

## Passing a profile from client to server

acme2certifier supports the [ACME Profiles Extension](acme_profiling.md). Configure allowed profiles under `[Order]`:

```config
[Order]
profiles: {"tls": "http://example/profile/tls", "tls-c": "http://example/profile/tls-c"}
```

Clients can then select a profile (example with lego):

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego run --tls-skip-verify \
  -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http --profile tls
```

The handler also supports [header_info_list](header_info.md). Enable it and pass `profile=<name>` in the ACME client user-agent:

```config
[Order]
header_info_list: ["HTTP_USER_AGENT"]
```

## EAB profiling

Enable [EAB profiling](eab_profiling.md) to override handler attributes per account (for example `profile` or `allowed_domainlist`):

```cfg
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.kid_profile_handler
key_file: <profile_file>
eab_profiling: True
```

Example kid profile fragment:

```json
{
  "keyid_00": {
    "hmac": "...",
    "cahandler": {
      "profile": ["tls", "tls-c"],
      "allowed_domainlist": ["www.example.com", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "...",
    "cahandler": {
      "profile": "tls",
      "allowed_domainlist": ["www.example.com"]
    }
  }
}
```

## Notes

- Enrollment is synchronous; `poll` and `trigger` are not implemented.
- The leaf is returned as DER (`application/pkix-cert`); the handler builds the PEM chain from `GET /cacerts`.
- Revocation uses `GET /revoke-cert` with `ca-sha1`, `serial-number`, and `reason` (XiPKI `CrlReason` names such as `KEY_COMPROMISE` / `UNSPECIFIED`).
