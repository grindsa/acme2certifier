<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Certificate chain rewrite -->
<!-- wiki-category: Configuration -->

# Rewriting the certificate chain

Some CAs (for example EJBCA) return a full chain including the self-signed trust anchor. RFC 8555 [`application/pem-certificate-chain`](https://www.rfc-editor.org/rfc/rfc8555.html#section-9.1) allows that root to be omitted: clients that can validate the chain already have it in their trust store.

acme2certifier can drop certificates from the PEM bundle **after** the CA handler returns it, before the certificate is stored. This is handler-independent (enroll, poll, and trigger). It is off by default; the bundle is not parsed when the option is unset.

This does **not** replace OpenSSL/XCA `ca_cert_chain_list`, which is how those handlers *build* a chain when the CA does not return one.

## `cert_chain_skip_list`

Optional JSON list of SHA-256 fingerprints. Any certificate in the handler bundle that matches is dropped.

- Matching uses the fingerprint, not the subject name, so re-issuing an intermediate under the same DN does not quietly change what gets filtered.
- Fingerprints are normalized (lowercase hex, colons and spaces ignored).
- The first certificate in the bundle is the end-entity certificate (RFC 8555 `MUST`) and is never dropped. Listing it is a configuration error.
- Invalid JSON, a non-list value, or a chain that cannot be parsed fails enrollment (fail closed). The original CA chain is **not** stored.

```config
[CAhandler]
...
cert_chain_skip_list: ["eb3178e37d34b4981108a757dd3cb42c3989dc06ad87507bb16f75973342910f"]
```

In [multi-handler](multi_cahandler.md) mode put the option on the named section (`[CAhandler:ejbca]`), not on the registry `[CAhandler]` block.

Fingerprints:

```bash
openssl x509 -in root-ca.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
```

Typical use: drop the self-signed root the CA always includes.

Appending a replacement certificate (`cert_chain_append`) and EAB-profile overrides are not in this release.
