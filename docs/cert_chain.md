<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Certificate chain rewrite -->
<!-- wiki-category: Configuration -->

# Rewriting the certificate chain

Some CAs (for example EJBCA) return a full chain including the self-signed trust anchor. RFC 8555 [`application/pem-certificate-chain`](https://www.rfc-editor.org/rfc/rfc8555.html#section-9.1) allows that root to be omitted: clients that can validate the chain already have it in their trust store. The same RFC says each following certificate SHOULD certify the previous one, which is how a replacement trust anchor is attached.

acme2certifier can rewrite the PEM bundle **after** the CA handler returns it, before the certificate is stored. This is handler-independent (enroll, poll, and trigger). It is off by default; the bundle is not parsed when both options are unset.

This does **not** replace OpenSSL/XCA `ca_cert_chain_list`, which is how those handlers *build* a chain when the CA does not return one.

Skip runs first, then append. Invalid JSON, a missing PEM file, a chain that cannot be parsed, or an appended certificate that does not certify the previous one fails enrollment (fail closed). The original CA chain is **not** stored.

The first certificate in the bundle is the end-entity certificate (RFC 8555 `MUST`) and is never dropped or replaced.

## `cert_chain_skip_list`

Optional JSON list of SHA-256 fingerprints. Any certificate in the handler bundle that matches is dropped.

- Matching uses the fingerprint, not the subject name, so re-issuing an intermediate under the same DN does not quietly change what gets filtered.
- Fingerprints are normalized (lowercase hex, colons and spaces ignored).
- Listing the end-entity certificate is a configuration error.

```config
[CAhandler]
...
cert_chain_skip_list: ["eb3178e37d34b4981108a757dd3cb42c3989dc06ad87507bb16f75973342910f"]
```

Fingerprints:

```bash
openssl x509 -in root-ca.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
```

Typical use: drop the self-signed root the CA always includes.

## `cert_chain_append`

Optional JSON list of PEM files appended after skip. Each file may contain one certificate or a chain. Relative paths are resolved against `ACME2CERTIFIER_BASE_DIR` when that variable is set. Files are read when the CA handler is bound (restart after replacing a PEM).

Each appended certificate must certify the previous one (issuer name and signature). Appending the end-entity certificate, or a certificate already in the remaining chain, is a configuration error.

```config
[CAhandler]
...
cert_chain_skip_list: ["eb3178e37d34b4981108a757dd3cb42c3989dc06ad87507bb16f75973342910f"]
cert_chain_append: ["/var/www/acme2certifier/volume/cross-signed-ica.pem", "/var/www/acme2certifier/volume/new-root.pem"]
```

Typical use: omit the CA's self-signed root, then attach a cross-signed intermediate and the replacement trust anchor.

In [multi-handler](multi_cahandler.md) mode put both options on the named section (`[CAhandler:ejbca]`), not on the registry `[CAhandler]` block.

EAB-profile overrides are not in this release.
