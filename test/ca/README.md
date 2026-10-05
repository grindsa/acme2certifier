# OpenSSL lab CA fixtures

Private keys and regenerable PEMs for the openssl CA handler are **not** stored in git.

Generate them:

```bash
tools/make_test_cas.sh bootstrap
```

`pytest` also bootstraps once per session via `test/conftest.py` when `sub-ca-key.pem` is missing.

Passphrase for `sub-ca-key.pem`: `Test1234` (override with `-p` / `$SUBCA_KEY_PASS`).

Checked-in (static) fixtures that are **not** produced by bootstrap:

- `acme2certifier-clean.xdb` — XCA database (separate follow-up)
- `certs.pem` / `certs.p7b` / `certs_der.p7b` — PKCS7 golden fixtures
- `certsrv_ca_certs.pem` — remote-CA TLS trust bundle
- `csr.der`, `fr1.txt`, `fr2.txt` — misc unit-test stubs

For cert-chain rewrite append PEMs (`new-root`, `*-cross`):

```bash
tools/make_test_cas.sh bootstrap   # if needed
tools/make_test_cas.sh append      # default; writes test/new_ca/
```
