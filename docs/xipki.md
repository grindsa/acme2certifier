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

## Empty CSR subjects (ACME clients)

Many ACME clients (Certbot, recent lego builds, etc.) finalize with a PKCS#10 that has an
**empty subject DN** and puts all names in `subjectAlternativeName`. That is valid ACME, but
stock XiPKI REST `enroll-cert` copies the CSR subject into the certificate template. Combined
with a profile that requires a CN, enrolments fail — or operators paper over it with a fixed
placeholder such as `CN=acme-issued.invalid`, which then appears on every leaf.

XiPKI’s **built-in ACME gateway** avoids this by setting `CN=<first DNS SAN>` after POP is
verified, then enrolling via the CA SDK with that subject plus the CSR public key and
extensions (not the empty PKCS#10 subject). Plain REST has no equivalent rewrite.

### What this project does

acme2certifier cannot resign the client CSR (no private key), so the REST handler always
forwards the PKCS#10 as received. Subject rewriting belongs on the XiPKI gateway (or in the
certprofile / client CSR), not in the Python handler.

The CI/demo docker-xipki stack therefore:

1. **Patches** `RestResponder` in `rest.war` so that after a successful POP check, an empty
   (or CN-less) CSR subject is replaced with `CN=<first DNS SAN>` — the same rule as XiPKI ACME.
2. **Relaxes** the demo `tls` certprofile: optional `C` / `O` / `OU` / `serialNumber` / `CN`
   (no fixed placeholder value), and marks SAN **critical** + required (RFC 5280 when the
   subject may be empty).

Result: an empty-subject CSR for `DNS:foo.example` yields a leaf with
`subject=CN=foo.example` and a critical SAN, instead of `CN=acme-issued.invalid`.

If the CSR already contains a CN, that CN is kept unchanged.

### Patching an existing docker-xipki stack

On a host that already runs the demo layout (`STACK_DIR` / `DATA_DIR`):

```bash
STACK_DIR=/srv/stacks/xipki DATA_DIR=/srv/data/xipki \
  ./.github/scripts/patch_xipki_cn_from_san.sh
```

The script ([`.github/scripts/patch_xipki_cn_from_san.sh`](../.github/scripts/patch_xipki_cn_from_san.sh))
updates the `tls` profile JSON (stack + data copies), rebuilds `rest.war` with the CN-from-SAN
RestResponder, and recreates the `xipki-gateway` container (set `SKIP_COMPOSE_UP=1` to skip the
recreate). [`xipki_prep`](../.github/actions/wf_specific/xipki_ca_handler/xipki_prep/action.yml)
calls the same script before the full stack `docker compose up`. Requires Docker and network
access to pull `eclipse-temurin:17-jdk` for the one-shot compile.

Smoke test (empty subject + SAN only):

```bash
TMP=$(mktemp -d)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMP/k.pem" -outform DER -out "$TMP/req.csr" \
  -subj "/" \
  -addext "subjectAltName=DNS:cn-from-san-test.example.org"
curl -sS -u 'user1:password1' \
  -H 'Content-Type: application/pkcs10' \
  --data-binary @"$TMP/req.csr" \
  -o "$TMP/leaf.der" \
  "http://127.0.0.1:8082/rest/myca/enroll-cert?profile=tls"
openssl x509 -inform der -in "$TMP/leaf.der" -noout -subject -ext subjectAltName
# expect: subject=CN = cn-from-san-test.example.org
```

### Production / stock XiPKI without the patch

Options if you cannot patch RestResponder:

- Prefer ACME clients that put `CN=<fqdn>` in the CSR, or
- Use XiPKI’s ACME service instead of REST for enrolment, or
- Configure the certprofile for optional CN + critical SAN (empty subject leaves; no fake CN).

Do **not** rely on a static overridable CN like `acme-issued.invalid` in production — every
certificate will share that subject.

## Notes

- Enrollment is synchronous; `poll` and `trigger` are not implemented.
- The leaf is returned as DER (`application/pkix-cert`); the handler builds the PEM chain from `GET /cacerts`.
- Revocation uses `GET /revoke-cert` with `ca-sha1`, `serial-number`, and `reason` (XiPKI `CrlReason` names such as `KEY_COMPROMISE` / `UNSPECIFIED`).

## CI

Draft workflow: [`.github/workflows/cahandler-xipki.yml`](../.github/workflows/cahandler-xipki.yml).

There is no maintained official XiPKI Docker Hub image for 6.x. The prep action
([`xipki_prep`](../.github/actions/wf_specific/xipki_ca_handler/xipki_prep/action.yml))
builds [changhr2013/docker-xipki](https://github.com/changhr2013/docker-xipki) at a pinned
commit, attaches it to the `acme` Docker network, restarts the CA after MySQL is ready,
loads demo CA `myca1` (alias `myca`) via mgmt-cli / karaf, applies the ACME-friendly `tls`
certprofile and RestResponder CN-from-SAN patch described above, and smokes REST enroll with
requestor `user1` / `password1` against `/rest/myca` (ports `8082` HTTP / `8445` HTTPS).

Layout used by prep (overridable via action inputs):

| Path | Contents |
| --- | --- |
| `/srv/stacks/xipki` | Compose file, Dockerfiles, build contexts, mgmt-cli |
| `/srv/data/xipki` | Persistent data (`mysql/db`, seeded `cli` / `mgmt-cli`) |
