<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for an openssl based CA stored on local file system -->
# Support for an Openssl based CA stored on local file system

The openssl CA handler is rather for testing and lab usage. I strongly recommend not to reuse it in production environments without reviewing local system configuration and hardening state

## Prerequisites

You need to create a certificate authority on the local file-system.

I did it by running the below command:

```bash
root@rlh:~# openssl req -x509 -new -extensions v3_ca -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 3650
```

## Configuration

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example/ca_handlers/openssl_ca_handler.py acme_srv/ca_handler.py
```

- create a directory to store the (ca) certificate(s), key and CRL(s)

```bash
root@rlh:~# mkdir acme_srv/ca
root@rlh:~# mkdir acme_srv/ca/certs
```

- place the above generated key and cert into the "ca" directory

```bash
root@rlh:~# mv ca-key.pem acme_srv/ca/
root@rlh:~# mv ca-cert.pem acme_srv/ca/
```

- modify the server configuration (/acme_srv/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
issuing_ca_key: acme_srv/ca/ca-key.pem
issuing_ca_key_passphrase: Test1234
issuing_ca_cert: acme_srv/ca/ca-cert.pem
issuing_ca_crl: acme_srv/ca/crl.pem
cert_validity_days: 30
cert_save_path: acme_srv/ca/certs
ca_cert_chain_list: []
openssl_conf: acme_srv/ca/openssl.conf
allowed_domainlist: ["foo.bar\\$", "foo1.bar.local"]
blocked_domainlist: ["google.com.foo.bar\\$", "host.foo.bar$", "\\*.foo.bar"]
save_cert_as_hex: True
cn_enforce: True
```

- `issuing_ca_key` - private key of the issuing CA (in PEM format) used to sign certificates and CRLs
- `issuing_ca_key_passphrase` - password to access the private key
- `issuing_ca_key_passphrase_variable` - *optional* - name of the environment variable containing the passphrase to access the CA key (a configured `issuing_ca_key_passphrase` parameter in acme_srv.cfg takes precedence)
- `issuing_ca_cert` - Certificate of issuing CA in PEM format
- `issuing_ca_crl` - CRL of issuing CA in PEM format
- `ca_cert_chain_list` - List of root and intermediate CA certificates to be added to the bundle return to an ACME-client (the issueing CA cert must not be included)
- `cert_validity_days` - *optional* - certificate lifetime in days (default 365)
- `cert_save_path` - *optional* - directory to store then enrolled certificates
- `openssl_conf` -  *optional* - file in openssl.conf format containing certificate extensions to be applied
- `allowed_domainlist` - *optional* - list of allowed common names and sans. Format per entry must follow the [regular expression syntax](https://docs.python.org/3/library/re.html)- To be stored in json format
- `blocked_domainlist` - *optional* - list of prohibited common names and sans. Format per entry must follow the [regular expression syntax](https://docs.python.org/3/library/re.html). To be stored in json format
- `save_cert_as_hex` - *optional* - serialnumber in hex format will be used as filename to save enrolled certificates - default is `False`
- `cn_enforce` - *optional* - use first SAN as CN in case there is no CN included in CSR - default is `False`

`allowed_domainlist` and `blocked_domainlist` options can be used independently from each other. When used together please note that that a positive result of a blocked_domainlist check takes precedence over the positive result of a allowed_domainlist check.

The openssl_conf file allows customization of the certificate profile and must contain a section `[extensions]` containing the certificate extensions to be inserted.
If not specified  the following extensions will be applied.

```config
[extensions]
subjectKeyIdentifier    = hash, issuer:always
keyUsage                = digitalSignature, keyEncipherment
basicConstraints        = critical, CA:FALSEerr
authorityKeyIdentifier  = keyid:always, issuer:always
extendedKeyUsage        = critical, clientAuth, serverAuth
```

Enjoy enrolling and revoking certificates

some remarks:

- certificates and CRLs will be signed with sha256
- during enrollment all extensions included in the csr will be copied to the certificate. Don’t tell me that this is a bad idea. Read the first two sentences of this page instead.
- the CRL "next update interval" is 7days
