# Generic CMPv2 protocol handler

The CMPv2 protocol handler is not bound to a specific ca server. Certificate enrollment is done by calling an [openssl binary with cmpossl support](https://github.com/mpeylo/cmpossl/wiki).
As of today revocation operations are not supported.

The handler has been tested against [Insta Certifier](https://www.insta.fi/en/services/cyber-security/insta-certifier)

## Pre-requisites

You need to patch your the openssl version to support CMPV2. Please follow the instructions provided at the [cmpossl webstite](https://github.com/mpeylo/cmpossl/wiki/Quick-Start)
if you need furhter instructoions how do do so.

Pre-compiled binaries for [Ubuntu 18.04](UB18CMPOpenSSL.7z) and [Windows](WindowsCMPOpenSSL.zip) are also available for testing purposes.

Technically the ca-handler acts as registration authority towards CMPv2 server. That means you need to configure a registration authority on your CMPv2 server with
either Refnum/PSK or certificate authentication. Please consult your CMPv2 server configuration how to do this.

The configuration could be a bid tricky and may require fintuning depending on type  and configuration of your CMPv2 server. I strongly suggest to try enrollment via
commandline first and adapt the ca_handler accordingly.

In my setup acme2certifier is authenticating via refnum/secred towards CMPv2 server and the later described ca-handler configuration maps to the below commandline.

```
../openssl/openssl cmp -cmd ir -server 192.168.14.137:8080 -path pkix/ -ref 1234 -secret pass:xxx -recipient "/C=DE/CN=tst_sub_ca" -newkey pubkey.pem -cert ra_cert.pem -trusted capubs.pem -popo 0 -subject /CN=test-cert -extracertsout ca_certs.pem -certout test-cert.pem
```

| Parameter | Value | Description |
| :-------  | :---- | :---------- |
|-cmd | ir | request type "initial request"|
|-server| 192.168.14.137:8080| address and port of CMPv2 server|
|-path | pkix/ | path on CMPv2 server |
|-ref | 1234 | reference number used for authentication towards CMPv2 server |
|-secret | pass:xxx |  secred used for authentication towards CMPv2 server |
|-recipient | "/C=DE/CN=tst_sub_ca" | dn of issuing ca |
|-newkey | pubkey.pem | public key extracted from CSR |
|-cert | ra_cert.pem |  public key of local registration authority |
|-trusted | capubs.pem | ca certificate bundle needed to verify the CMPv2 server certificate |
|-popo | 0 | set the ra verified Set Proof-of-Possession (POPO) method to "raverified" |
|-subject | /CN=test-cert  | subject name extracted from CSR |
|-extracertsout | ca_certs.pem | file containing the ca certificates extracted from the CMMPv2 response |
|-certout | test-cert.pem | file containing the certificate returned from ca server |

The latest version of the documentation for the openssl cmp CLI can be found [here](https://github.com/mpeylo/cmpossl/blob/cmp/doc/man1/cmp.pod)


## Installation and Configuration


[CAhandler]
