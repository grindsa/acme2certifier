<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler using CMPv2 protocol -->
# Generic CMPv2 protocol handler

The CMPv2 protocol handler is not bound to a specific ca server. Certificate enrollment is done by using the [cmp application from Openssl 3.x](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html).
That means that this handler just a wrapper calling openssl with special parameters by using the `subprocess` module.
As of today, revocation operations are not supported.

The handler has been tested against [Insta Certifier](https://www.insta.fi/en/services/cyber-security/insta-certifier)

## Pre-requisites

You need a system using Openssl 3.x or higher.

Technically the ca-handler acts as registration authority towards CMPv2 server. That means you need to configure a registration authority on your CMPv2 server with
either Refnum/PSK or certificate authentication. Please check your CA server documentation how to do this.

The configuration could be a bid tricky and may require finetuning depending on type and configuration of your CMPv2 server. I strongly suggest to try enrollment via
command line first and adapt the ca_handler accordingly.

In my setup acme2certifier is authenticating via refnum/secret towards CMPv2 server. Certificate based authentication is supported as well. The later described ca-handler configuration maps to the below command line.

```shell
grindsa@ub-22:~/a2c$ openssl.exe cmp -cmd ir -server 192.168.14.137:8080 -path pkix/ -ref 1234 -secret pass:xxx -recipient "/C=DE/CN=tst_sub_ca" -cert ra_cert.pem -trusted capubs.pem -popo 0 -ignore_keyusage -extracertsout ca_certs.pem -certout test-cert.pem -csr csr.pem  
```

| Parameter | Value | Description |
| :-------  | :---- | :---------- |
|-cmd | ir | request type "initial request"|
|-server| 192.168.14.137:8080| address and port of CMPv2 server|
|-path | pkix/ | path on CMPv2 server |
|-ref | 1234 | reference number used for authentication towards CMPv2 server |
|-ref_variable | CMPV2_REF | name of the environment variable containing the reference number used for authentication (a configured `ref` parameter in acme_srv.cfg takes precedence)
|-secret | pass:xxx | secret used for authentication towards CMPv2 server |
|-secret_variable | CMPV2_SECRET | name of the environment variable containing the authentication secret (a configured `secret` parameter in acme_srv.cfg takes precedence)
|-recipient | "/C=DE/CN=tst_sub_ca" | dn of issuing ca |
|-cert | ra_cert.pem | public key of local registration authority |
|-trusted | capubs.pem | ca certificate bundle needed to verify the CMPv2 server certificate |
|-popo | 0 | set the ra verified Set Proof-of-Possession (POPO) method to "raverified" |
|-extracertsout | ca_certs.pem | file containing the ca certificates extracted from the CMMPv2 response |
|-certout | test-cert.pem | file containing the certificate returned from ca server |
|-csr | csr.pem | csr to be imported

The latest version of the documentation for the openssl cmp application can be found [here](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html)

## Installation and Configuration

- note down the openssl command line for a successful certificate enrollment.

```config
[CAhandler]
handler_file: examples/ca_handler/cmp_ca_handler.py
```

- modify the server configuration (/acme_srv/acme_srv.cfg) according to your needs. every parameter used in the openssl CLI command requires a corresponding entry in the CAhandler section. The entry is the name of the openssl parameter with the prefix "cmp_", value is the parameter value used in the openssl CLI command. In addition you can to customize the path to your openssl 3.x binary (`cmp_openssl_bin`).

The above mentioned CLI commend will result in the below configuration to be inserted in acme_srv.cfg

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

The parameters `-cmp ir`, `-popo 0` are set by the ca-handler. There is not need to specify these in the config. Same applies for `-extracertsout` and `-certout` options.
They will be set by the handler at runtime.

Happy enrolling :-)
