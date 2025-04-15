<!-- markdownlint-disable  MD013 MD014 -->
<!-- wiki-title CA handler for Microsoft Certification Authority Web Enrollment Service -->
# CA handler for Microsoft Certification Authority Web Enrollment Service

This CA handler uses Microsofts [Certification Authority Web Enrollment service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)) for certificate enrollment and modified version of the python library [magnuswatn](https://github.com/magnuswatn/)/[certsrv](https://github.com/magnuswatn/certsrv) for communication with the enrollment service.

When using the handler please be aware of the following limitations:

- Authentication towards Web Enrollment Service is limited to "basic" "ntlm" or "gssapi" Kkerberos). There is currently no support for ClientAuth
- Communication is limited to https
- Revocation operations are not supported

## Preparation

1. Microsoft Certification Authority Web Enrollment Service must be enabled and configured - of course :-)
2. You need to have a set of credentials with permissions to access the service and enrollment templates
3. Authentication method (basic or ntlm) to the service must be configured correctly.
4. (optional): In case you are installing from RPM and plan to use ntlm as authentication scheme you need two additonal python modules [python3-request-ntlm](https://pypi.org/project/requests_ntlm/) and [python3-ntlm-auth](https://pypi.org/project/ntlm-auth/) which are neither part of Standard nor the EPEL repo. If you have no clue from where to get these packaages feel free to use the ones being part of [the a2c github repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs)
5. (optional): In case you are installing from RPM and plan to use gssapi as authentication scheme you need two additonal python modules [python3-request-gssapi](https://pypi.org/project/requests-gssapi/) and [gssapi](https://pypi.org/project/gssapi/). If you have no clue from where to get these packaages feel free to use the ones being part of [the a2c github repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs)

It is helpful to verify the service access before starting the configuration of acme2certifier

- service access by using ntlm authentication towards certsrv

```bash
root@rlh:~# curl -I --ntlm --user <user>:<password> -k https://<host>/certsrv/
```

- service access by using basic authentication

```bash
root@rlh:~# curl -I --user <user>:<password> -k https://<host>/certsrv/
```

- service access by using gssapi authentication

```bash
root@rlh:~# export KRB5_CONFIG=<path>/krb5.conf
root@rlh:~# kinit <username>
root@rlh:~# curl --negotiate -u: <user>:<password> -k https://<host>/certsrv/
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
allowed_domainlist: ["example.com", "*.example2.com"]
krb5_config: <path_to_individual>/krb5.conf
eab_profiling: False
```

- host - hostname of the system providing the Web enrollment service
- host_variable - *optional* - name of the environment variable containing host address (a configured `host` parameter in acme_srv.cfg takes precedence)
- user - username used to access the service
- user_variable - *optional* - name of the environment variable containing the username used for service access (a configured `user` parameter in acme_srv.cfg takes precedence)
- password - password
- password_variable - *optional* - name of the environment variable containing the password used for service access (a configured `password` parameter in acme_srv.cfg takes precedence)
- ca_bundle - CA certificate bundle in pem format needed to validate the server certificate
- auth_method - authentication method (either "basic", "ntlm" or "gssapi")
- krb5_config - *optional* - path to individual krb5.conf
- template - certificate template used for enrollment
- allowed_domainlist - *optional* - list of domain-names allowed for enrollment in json format example: ["bar.local$, bar.foo.local]
- eab_profiling - optional - [activate eab profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list enrollment parameters not to be logged in json format example: [ "parameter1", "parameter2" ] (default: [])

## Passing a template from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify a template name to be used during certificate enrollment. This feature is disabled by default and must be activate in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the temmplate name as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent template=foo --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent template=foo -d <fqdn> --http run
```

# eab profiling

This handler can use the [eab profiling feture](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activated in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

below an example key-file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "template": ["WebServerModified", "WebServer"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.local"],
      "unknown_key": "unknown_value"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "template": "WebServerModified",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.local"],
      "unknown_key": "unknown_value"
    }
  },
  "keyid_02": {
    "hmac": "dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM",
    "cahandler": {
      "allowed_domainlist": ["www.example.com", "www.example.org"]
    }
  },
  "keyid_03": {
    "hmac": "YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr"
  }
}
```
