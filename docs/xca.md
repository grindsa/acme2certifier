<!-- markdownlint-disable  MD013 -->
# Support for an XCA based Certificate Authorities

This handler can be used to store, certifcates and requests in an [XCA](https://github.com/chris2511/xca/) databse. Only SQLite is supported as backend database.

It is also possible to fetch enrollment templates from XCA an apply them to the certificate signing request.

## Prerequisites

You need to have a ready-made xca database with CA certificate and keys imported. You furhter need the `internal names` from the Certificate Authorities as show in the XCA application.

![xca-ca-list](xca-ca-list.png)

## Configuration

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example/ca_handlers/xca_ca_handler.py acme/ca_handler.py
```

- place the XCA database into a directory which is accessible by acme2certifier.

- modify the server configuration (/acme/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
xdb_file: acme/xca/acme2certifier.xdb
issuing_ca_name: sub-ca
issuing_ca_key: sub-ca-key
passphrase: test1234
ca_cert_chain_list: ["root-ca"]
template_name: XCA template to be applied to CSRs
```

- `xdb_file` - path to XCA database
- `issuing_ca_key_passphrase` - password to access the private key
- `issuing_ca_name` - XCA name of the certificate authority used to issue certificates.
- `issuing_ca_key` - XCA name of the ley used to sign certificates. If not set same value as configured in `issuing_ca_name` will be assumed.
- `passphrase` - *optional* - passphrase to access the database and decrypt the private CA Key
- `ca_cert_chain_list` - *optional* - List of root and intermediate CA certificates to be added to the bundle return to an ACME-client (the issueing CA cert must not be included)
- `template_name` - *optional* - name of the XCA template to be applied during certificate issuance

Enjoy enrolling and revoking certificates
