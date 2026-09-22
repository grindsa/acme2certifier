<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Certificate chain rewrite -->
<!-- wiki-category: Configuration -->

# Rewriting the certificate chain

Some CAs (for example EJBCA) return a full chain including the self-signed trust anchor. RFC 8555 [`application/pem-certificate-chain`](https://www.rfc-editor.org/rfc/rfc8555.html#section-9.1) allows that root to be omitted: clients that can validate the chain already have it in their trust store. The same RFC says each following certificate SHOULD certify the previous one, which is how a replacement trust anchor is attached.

acme2certifier can rewrite the PEM bundle **after** the CA handler returns it, before the certificate is stored. This is handler-independent (enroll, poll, and trigger). It is off by default; the bundle is not parsed when both options are unset.

This does **not** replace OpenSSL/XCA `ca_cert_chain_list`, which is how those handlers *build* a chain when the CA does not return one.

The first certificate in the bundle is the end-entity certificate (RFC 8555 `MUST`) and is never dropped or replaced.

## `cert_chain_skip_list`

Optional JSON list of SHA-256 fingerprints. Any certificate in the handler bundle that matches is dropped.

Use this for a **suffix** of the chain (the self-signed root, or the issuing CA plus that root). After skip, remaining certificates must still certify the previous one (RFC 8555) unless `cert_chain_link_check` is `False`. Skipping a middle certificate while keeping what followed it (for example dropping the ICA and keeping the root) is a configuration error.

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

Each appended certificate must certify the previous one (issuer name and signature) unless `cert_chain_link_check` is `False`. Appending the end-entity certificate, or a certificate already in the remaining chain, is a configuration error.

```config
[CAhandler]
...
cert_chain_skip_list: ["eb3178e37d34b4981108a757dd3cb42c3989dc06ad87507bb16f75973342910f"]
cert_chain_append: ["/var/www/acme2certifier/volume/cross-signed-ica.pem", "/var/www/acme2certifier/volume/new-root.pem"]
```

Typical use: omit the CA's self-signed root, then attach a cross-signed intermediate and the replacement trust anchor.

Local throwaway CAs used for CI (re-uses `acme_srv/ca/sub-ca-key.pk8` and the existing root/sub certs; generates a new-root key):

```bash
tools/make_test_cas.sh
```

The script prints `cert_chain_skip_list` / `cert_chain_append` snippets. Defaults: source `test/ca`, output `test/new_ca`. There is no openssl root private key; the old root is cross-signed from its certificate.

## `cert_chain_link_check`

Default `True`: a rewritten chain where a certificate does not certify the previous one fails enrollment. This applies after skip (remaining links) and after append (join and appended certs). Set to `False` to keep the bundle anyway (unlinked extra CA, or a skip that leaves a hole). A warning is logged for each broken link.

```config
[CAhandler]
...
cert_chain_skip_list: ["0685ac595a5ee17aec01b4529249385ec7228009e7b5e9fcd804c27af6c7f7c4"]
cert_chain_append: ["/var/www/acme2certifier/volume/other-root.pem"]
cert_chain_link_check: False
```

In [multi-handler](multi_cahandler.md) mode put these options on the named section (`[CAhandler:ejbca]`), not on the registry `[CAhandler]` block.

## EAB-profile overrides

When [EAB profiling](eab_profiling.md) is enabled, a kid profile may set `cert_chain_skip_list`, `cert_chain_append`, and `cert_chain_link_check` in the `cahandler` block. Keys present in the profile replace the bound `acme_srv.cfg` values for that account (including an empty list). Omitted keys keep the bound values.

These keys are not setattr'd onto the CA handler. Skip-list fingerprints are parsed the same way as config; append paths are read when the profile is applied. `eab_profiling` must be on. Invalid overlay fails enrollment (fail closed).
