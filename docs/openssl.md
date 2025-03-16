<!-- markdownlint-disable MD013 -->
<!-- wiki-title CA Handler for an OpenSSL-based CA Stored on Local File System -->
# Support for an OpenSSL-based CA Stored on Local File System

The OpenSSL CA handler is primarily intended for testing and lab environments. **It is strongly recommended not to use it in production environments without reviewing the local system configuration and hardening measures.**

## Prerequisites

You need to create a certificate authority (CA) on the local file system.

The following command generates a CA certificate and key:

```bash
openssl req -x509 -new -extensions v3_ca -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 3650
```

## Configuration

1. **Create directories** to store CA certificates, keys, and certificate revocation lists (CRLs):

```bash
mkdir -p acme_srv/ca/certs
```

2. **Move the generated key and certificate** into the CA directory:

```bash
mv ca-key.pem acme_srv/ca/
mv ca-cert.pem acme_srv/ca/
```

3. **Modify the server configuration** (`/acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/openssl_ca_handler.py
issuing_ca_key: acme_srv/ca/ca-key.pem
issuing_ca_key_passphrase: Test1234
issuing_ca_cert: acme_srv/ca/ca-cert.pem
issuing_ca_crl: acme_srv/ca/crl.pem
cert_validity_days: 30
cert_validity_adjust: True
cert_save_path: acme_srv/ca/certs
ca_cert_chain_list: []
openssl_conf: acme_srv/ca/openssl.conf
allowed_domainlist: ["foo.bar\$", "foo1.bar.local"]
blocked_domainlist: ["google.com.foo.bar\$", "host.foo.bar$", "\*.foo.bar"]
save_cert_as_hex: True
cn_enforce: True
```

### Parameter Explanations

- **issuing_ca_key** – Private key of the issuing CA (PEM format) used to sign certificates and CRLs.
- **issuing_ca_key_passphrase** – Password to access the private key.
- **issuing_ca_key_passphrase_variable** *(optional)* – Name of the environment variable containing the CA key passphrase (overridden if `issuing_ca_key_passphrase` is set in `acme_srv.cfg`).
- **issuing_ca_cert** – CA certificate in PEM format.
- **issuing_ca_crl** – CA certificate revocation list (CRL) in PEM format.
- **ca_cert_chain_list** – List of root and intermediate CA certificates to be included in the certificate chain (the issuing CA certificate should not be included).
- **cert_validity_days** *(optional)* – Certificate validity period in days (default: `365`).
- **cert_save_path** *(optional)* – Directory to store enrolled certificates.
- **openssl_conf** *(optional)* – OpenSSL configuration file (`openssl.cnf`) containing certificate extensions.
- **allowed_domainlist** *(optional)* – List of allowed common names (CNs) and Subject Alternative Names (SANs), formatted as regular expressions ([Python regex syntax](https://docs.python.org/3/library/re.html)). Stored in JSON format.
- **blocked_domainlist** *(optional)* – List of prohibited CNs and SANs, formatted as regular expressions. Stored in JSON format.
- **save_cert_as_hex** *(optional)* – If `True`, the certificate serial number will be stored in hexadecimal format as the filename (default: `False`).
- **cn_enforce** *(optional)* – If `True`, the first SAN will be used as the CN if no CN is provided in the CSR (default: `False`).
- **cert_validity_adjust** *(optional)* – If `True`, ensures that the "valid until" field of a certificate does not exceed the expiration date of any certificate in the certificate chain (default: `False`).

### Domain Allow/Block Lists

The `allowed_domainlist` and `blocked_domainlist` options can be used independently. However, **if both are used together, the blocked domain list takes precedence**.

## OpenSSL Configuration File

The `openssl_conf` file allows customization of the certificate profile. It must contain a section `[extensions]`, which specifies the certificate extensions.

If not specified, the following default extensions will be applied:

```ini
[extensions]
subjectKeyIdentifier    = hash, issuer:always
keyUsage                = digitalSignature, keyEncipherment
basicConstraints        = critical, CA:FALSE
authorityKeyIdentifier  = keyid:always, issuer:always
extendedKeyUsage        = critical, clientAuth, serverAuth
```

## Notes

- Certificates and CRLs will be signed using **SHA-256**.
- During enrollment, **all extensions included in the CSR will be copied** to the issued certificate. *(This may be a security risk, but this handler is not recommended for production use.)*
- The CRL "next update interval" is set to **7 days**.

### Enjoy enrolling and revoking certificates!
