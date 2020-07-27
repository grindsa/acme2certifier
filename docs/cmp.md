<!-- markdownlint-disable  MD013 -->
# Generic CMPv2 protocol handler

The CMPv2 protocol handler is not bound to a specific ca server. Certificate enrollment is done by calling an [openssl binary with cmpossl support](https://github.com/mpeylo/cmpossl/wiki).
That means that this handler just a wrapper calling openssl with special parameters by using the subprocess module.
As of today, revocation operations are not supported.

The handler has been tested against [Insta Certifier](https://www.insta.fi/en/services/cyber-security/insta-certifier)

## Pre-requisites

You need to patch your the local openssl version to support CMPV2. Please follow the instructions provided at the [cmpossl webstite](https://github.com/mpeylo/cmpossl/wiki/Quick-Start)
if you need further instructions  how to do so.

Pre-compiled binaries for [Ubuntu 18.04](https://github.com/grindsa/acme2certifier/raw/master/examples/ca_handler/UB18CMPOpenSSL.7z) and [Windows](https://github.com/grindsa/acme2certifier/raw/master/examples/ca_handler/WindowsCMPOpenSSL.zip) are also available for testing purposes.

Technically the ca-handler acts as registration authority towards CMPv2 server. That means you need to configure a registration authority on your CMPv2 server with
either Refnum/PSK or certificate authentication. Please consult your server configuration how to do this.

The configuration could be a bid tricky and may require finetuning depending on type and configuration of your CMPv2 server. I strongly suggest to try enrollment via
command line first and adapt the ca_handler accordingly.

In my setup acme2certifier is authenticating via refnum/secred towards CMPv2 server. The later described ca-handler configuration maps to the below commandline.

```shell
acme/cmp/WindowsCMPOpenSSL/openssl.exe cmp -cmd ir -server 192.168.14.137:8080 -path pkix/ -ref 1234 -secret pass:xxx -recipient "/C=DE/CN=tst_sub_ca" -newkey pubkey.pem -cert ra_cert.pem -trusted capubs.pem -popo 0 -subject /CN=test-cert -extracertsout ca_certs.pem -certout test-cert.pem  -ignore_keyusage -popo 0
```

| Parameter | Value | Description |
| :-------  | :---- | :---------- |
|-cmd | ir | request type "initial request"|
|-server| 192.168.14.137:8080| address and port of CMPv2 server|
|-path | pkix/ | path on CMPv2 server |
|-ref | 1234 | reference number used for authentication towards CMPv2 server |
|-secret | pass:xxx | secred used for authentication towards CMPv2 server |
|-recipient | "/C=DE/CN=tst_sub_ca" | dn of issuing ca |
|-newkey | pubkey.pem | public key extracted from CSR |
|-cert | ra_cert.pem | public key of local registration authority |
|-trusted | capubs.pem | ca certificate bundle needed to verify the CMPv2 server certificate |
|-popo | 0 | set the ra verified Set Proof-of-Possession (POPO) method to "raverified" |
|-subject | /CN=test-cert | subject name extracted from CSR |
|-extracertsout | ca_certs.pem | file containing the ca certificates extracted from the CMMPv2 response |
|-certout | test-cert.pem | file containing the certificate returned from ca server |

The latest version of the documentation for the openssl cmp CLI can be found [here](https://github.com/mpeylo/cmpossl/blob/cmp/doc/man1/openssl-cmp.pod)

## Installation and Configuration

- note down the openssl command line for a successful certificate enrollment.

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example/cmp_ca_handler.py acme/ca_handler.py
```

- modify the server configuration (/acme/acme_srv.cfg) according to your needs. every parameter used in the openssl CLI command requires a corresponding entry in the CAhandler
section. The entry is the name of the openssl parameter with the prefix "cmp_", value is the parameter value used in the openssl CLI command. In addtion you need to specify the
path to the openssl binary supporting CMPv2 (`cmp_openssl_bin`) and a temporary directory to store files (`cmp_tmp_dir`).

The above mentioned CLI commend will result in the below configuration to be inserted in acme_srv.cfg

```config
[CAhandler]
cmp_openssl_bin: acme/cmp/WindowsCMPOpenSSL/openssl.exe
cmp_tmp_dir: acme/cmp/tmp
cmp_server: 192.168.14.137:8080
cmp_path: pkix/
cmp_cert: acme/cmp/ra_cert.pem
cmp_ref: 1234
cmp_secret: pass:xxx
cmp_trusted: acme/cmp/capubs.pem
cmp_recipient: C=DE, CN=tst_sub_ca
cmp_ignore_keyusage: True
```

The parameters `-cmp ir`, `-popo 0` are set by the ca-handler. There is not need to specify these in the config. Same applies for `-subject`, `-extracertsout`, `-newkey` and `-certout` options.
They will be set by the handler at runtime.
