<!-- markdownlint-disable  MD013 -->

<!-- wiki-title CA handler using CMPv2 protocol -->

# Generic CMPv2 Protocol Handler

The CMPv2 protocol handler is not bound to a specific CA server. Certificate enrollment is done using the [CMP application from OpenSSL 3.x](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html).
This handler acts as a wrapper that calls OpenSSL with specific parameters using the `subprocess` module.
As of today, revocation operations are not supported.

The handler has been tested against [Insta Certifier](https://www.insta.fi/en/services/cyber-security/insta-certifier).

## Prerequisites

You need a system using OpenSSL 3.x or higher.

Technically, the CA handler acts as a registration authority (RA) towards the CMPv2 server. This means you need to configure a registration authority on your CMPv2 server with either Refnum/PSK or certificate authentication. Please check your CA server documentation on how to do this.

The configuration can be a bit tricky and may require fine-tuning depending on the type and setup of your CMPv2 server. I strongly suggest trying enrollment via the command line first and adapting the CA handler accordingly.

In my setup, acme2certifier authenticates via Refnum/Secret towards the CMPv2 server. Certificate-based authentication is also supported. The CA handler configuration described below maps to the following command-line command:

```shell
grindsa@ub-22:~/a2c$ openssl.exe cmp -cmd ir -server 192.168.14.137:8080 -path pkix/ -ref 1234 -secret pass:xxx -recipient "/C=DE/CN=tst_sub_ca" -cert ra_cert.pem -trusted capubs.pem -popo 0 -ignore_keyusage -extracertsout ca_certs.pem -certout test-cert.pem -csr csr.pem
```

| Parameter        | Value                 | Description                                                                                                                                                |
| :--------------- | :-------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -cmd             | ir                    | Request type "initial request"                                                                                                                             |
| -server          | 192.168.14.137:8080   | Address and port of the CMPv2 server                                                                                                                       |
| -path            | pkix/                 | Path on the CMPv2 server                                                                                                                                   |
| -ref             | 1234                  | Reference number used for authentication towards the CMPv2 server                                                                                          |
| -ref_variable    | CMPV2_REF             | Name of the environment variable containing the reference number used for authentication (a configured `ref` parameter in `acme_srv.cfg` takes precedence) |
| -secret          | pass:xxx              | Secret used for authentication towards the CMPv2 server                                                                                                    |
| -secret_variable | CMPV2_SECRET          | Name of the environment variable containing the authentication secret (a configured `secret` parameter in `acme_srv.cfg` takes precedence)                 |
| -recipient       | "/C=DE/CN=tst_sub_ca" | DN of the issuing CA                                                                                                                                       |
| -cert            | ra_cert.pem           | Public key of the local registration authority                                                                                                             |
| -trusted         | capubs.pem            | CA certificate bundle needed to verify the CMPv2 server certificate                                                                                        |
| -popo            | 0                     | Set the RA verified Set Proof-of-Possession (POPO) method to "RA verified"                                                                                 |
| -extracertsout   | ca_certs.pem          | File containing the CA certificates extracted from the CMPv2 response                                                                                      |
| -certout         | test-cert.pem         | File containing the certificate returned from the CA server                                                                                                |
| -csr             | csr.pem               | CSR to be imported                                                                                                                                         |

The latest version of the documentation for the OpenSSL CMP application can be found [here](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html).

## Installation and Configuration

- Note down the OpenSSL command line for a successful certificate enrollment.

```config
[CAhandler]
handler_file: examples/ca_handler/cmp_ca_handler.py
```

- Modify the server configuration (`/acme_srv/acme_srv.cfg`) according to your needs. Every parameter used in the OpenSSL CLI command requires a corresponding entry in the `[CAhandler]` section. The entry should be the name of the OpenSSL parameter with the prefix `cmp_`, and the value should match the parameter used in the OpenSSL CLI command. You can also customize the path to your OpenSSL 3.x binary (`cmp_openssl_bin`).

The CLI command mentioned above will result in the following configuration to be inserted into `acme_srv.cfg`:

```config
[CAhandler]
cmp_server: 192.168.14.137:8080
cmp_path: pkix/
cmp_cert: acme_srv/cmp/ra_cert.pem
cmp_ref: 1234
cmp_secret: pass:xxx
cmp_trusted: acme_srv/cmp/capubs.pem
cmp_recipient: C=DE, CN=tst_sub_ca
cmp_ignore_keyusage: True
```

The parameters `-cmp ir` and `-popo 0` are set by the CA handler, so there is no need to specify these in the config. The same applies to the `-extracertsout` and `-certout` options, which will be set by the handler at runtime.

Happy enrolling! :-)
