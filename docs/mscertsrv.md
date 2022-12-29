<!-- markdownlint-disable  MD013 MD014 -->
<!-- wiki-title CA handler for Microsoft Certification Authority Web Enrollment Service -->
# CA handler for Microsoft Certification Authority Web Enrollment Service

This CA handler uses Microsofts [Certification Authority Web Enrollment service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)) for certificate enrollment and the python library [magnuswatn](https://github.com/magnuswatn/)/[certsrv](https://github.com/magnuswatn/certsrv) for communication with the enrollment service.

When using the handler please be aware of the following limitations:

- Authentication towards Web Enrollment Service is limited to "basic" or "ntlm". There is currently no support for ClientAuth
- Communication is limited to https
- Revocation operations are not supported

## Preparation

1. Microsoft Certification Authority Web Enrollment Service must be enabled and configured - of course :-)
2. You need to have a set of credentials with permissions to access the service and enrollment templates
3. Authentication method (basic or ntlm) to the service must be configured correctly.
4. (optional): In case you are installing from RPM and plan to use ntlm as authentication scheme you need two additonal python modules [python3-request-ntlm](https://pypi.org/project/requests_ntlm/) and [python3-ntlm-auth](https://pypi.org/project/ntlm-auth/) which are neither part of Standard nor the EPEL repo. If you have no clue from where to get these packaages feel free to use one ones being part of [the a2c github repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs)

It is helpful to verify the service access before starting the configuration of acme2certifier

- service access by using ntlm authentication towards certsrv

```bash
root@rlh:~# curl -I --ntlm --user <user>:<password> -k https://<host>/certsrv/
```

- service access by using basic authentication

```bash
root@rlh:~# curl -I --user <user>:<password> -k https://<host>/certsrv/
```

Access to the service is possible if you see the status code 200 returned as part of the response

```bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Length: 3686
Content-Type: text/html
Server: Microsoft-IIS/10.0
Set-Cookie: - removed - ; secure; path=/
X-Powered-By: ASP.NET
```

## Installation

- you need to allow the md4 algorithm in `openssl.cfg`

```bash
$ sudo sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
$ sudo sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf
```

- install [certsrv](https://github.com/magnuswatn/certsrv) via pip (module is already part of the docker images)

```bash
root@rlh:~# pip install certsrv[ntlm]
```

- modify the server configuration (/acme_srv/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/mscertsrv_ca_handler.py
host: <hostname>
user: <username>
password: <password>
ca_bundle: <filename>
auth_method: <basic|ntlm>
template: <name>
```

- host - hostname of the system providing the Web enrollment service
- host_variable - *optional* - name of the environment variable containing host address (a configured `host` parameter in acme_srv.cfg takes precedence)
- user - username used to access the service
- user_variable - *optional* - name of the environment variable containing the username used for service access (a configured `user` parameter in acme_srv.cfg takes precedence)
- password - password
- password_variable - *optional* - name of the environment variable containing the password used for service access (a configured `password` parameter in acme_srv.cfg takes precedence)
- ca_bundle - CA certificate bundle in pem format needed to validate the server certificate
- auth_method - authentication method (either "basic" or "ntlm")
- template - certificate template used for enrollment
