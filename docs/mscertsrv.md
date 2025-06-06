<!-- markdownlint-disable MD013 MD014 -->
<!-- wiki-title CA Handler for Microsoft Certification Authority Web Enrollment Service -->
# CA Handler for Microsoft Certification Authority Web Enrollment Service

This CA handler uses Microsoft's [Certification Authority Web Enrollment Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)) for certificate enrollment. It also utilizes a modified version of the Python library [magnuswatn](https://github.com/magnuswatn/)/[certsrv](https://github.com/magnuswatn/certsrv) to communicate with the enrollment service.

## Limitations

Be aware of the following limitations when using this handler:

- Authentication towards the Web Enrollment Service is limited to "basic," "NTLM," or "GSSAPI (Kerberos)." ClientAuth is not supported.
- Communication is limited to HTTPS.
- Revocation operations are not supported.

## Preparation

1. Microsoft Certification Authority Web Enrollment Service must be enabled and configured.
2. You need a set of credentials with permission to access the service and enrollment templates.
3. The authentication method (basic or NTLM) must be configured correctly.
4. *(Optional)*: If installing from RPM and using NTLM authentication, you need two additional Python modules: [python3-requests-ntlm](https://pypi.org/project/requests_ntlm/) and [python3-ntlm-auth](https://pypi.org/project/ntlm-auth/). These are not part of the standard or EPEL repositories. You can find them in the [A2C GitHub repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs).
5. *(Optional)*: If installing from RPM and using GSSAPI authentication, you need two additional Python modules: [python3-requests-gssapi](https://pypi.org/project/requests-gssapi/) and [gssapi](https://pypi.org/project/gssapi/). These are also available in the [A2C GitHub repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs).

### Verifying Service Access

Before configuring **acme2certifier**, verify access to the Web Enrollment Service:

- **NTLM authentication**:

```bash
curl -I --ntlm --user <user>:<password> -k https://<host>/certsrv/
```

- **Basic authentication**:

```bash
curl -I --user <user>:<password> -k https://<host>/certsrv/
```

- **GSSAPI authentication**:

```bash
export KRB5_CONFIG=<path>/krb5.conf
kinit <username>
curl --negotiate -u: <user>:<password> -k https://<host>/certsrv/
```

If the service is accessible, the response should return status code **200**:

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

- Allow the MD4 algorithm in `openssl.cnf`:

```bash
sudo sed -i "s/default = default_sect/\default = default_sect
legacy = legacy_sect/g" /etc/ssl/openssl.cnf && sudo sed -i "s/\[default_sect\]/\[default_sect\]
activate = 1
\[legacy_sect\]
activate = 1/g" /etc/ssl/openssl.cnf
```

- Install [certsrv](https://github.com/magnuswatn/certsrv) via pip (this module is already included in the Docker images):

```bash
pip install certsrv[ntlm]
```

- Modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/mscertsrv_ca_handler.py
host: <hostname>
user: <username>
password: <password>
ca_bundle: <filename>
auth_method: <basic|ntlm|gssapi>
template: <name>
allowed_domainlist: ["example.com", "*.example2.com"]
krb5_config: <path_to_individual>/krb5.conf
eab_profiling: False
```

### Parameter Explanations

- **host** – The hostname of the system providing the Web Enrollment Service.
- **host_variable** *(optional)* – Name of the environment variable containing the host address (overridden if `host` is set in `acme_srv.cfg`).
- **user** – Username for accessing the service.
- **user_variable** *(optional)* – Name of the environment variable containing the username (overridden if `user` is set in `acme_srv.cfg`).
- **password** – Password for authentication.
- **password_variable** *(optional)* – Name of the environment variable containing the password (overridden if `password` is set in `acme_srv.cfg`).
- **ca_bundle** – CA certificate bundle in PEM format, required for validating the server certificate.
- **auth_method** – Authentication method (`basic`, `ntlm`, or `gssapi`).
- **krb5_config** *(optional)* – Path to an individual `krb5.conf` file.
- **template** – Certificate template used for enrollment.
- **allowed_domainlist** *(optional)* – List of allowed domain names for enrollment (JSON format).
- **eab_profiling** *(optional)* – [Enable EAB profiling](eab_profiling.md) (default: `False`).
- **enrollment_config_log** *(optional)* – Log enrollment parameters (default: `False`).
- **enrollment_config_log_skip_list** *(optional)* – List of enrollment parameters to exclude from logs (JSON format).

## Passing a Template from Client to Server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `template` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"template1": "http://foo.bar/template1", "template2": "http://foo.bar/template2", "template3": "http://foo.bar/template3"}
```

Once enabled, a client can specify the template to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile template2
```

The handler supports the [header_info_list feature](header_info.md), allowing an ACME client to specify a template name during enrollment. To enable this feature, update `acme_srv.cfg`:

```ini
[Order]
header_info_list: ["HTTP_USER_AGENT"]
```

### Example Usage

- **acme.sh**:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent template=foo --debug 3 --output-insecure
```

- **lego**:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent template=foo -d <fqdn> --http run
```

## EAB Profiling

This handler supports [EAB profiling](eab_profiling.md) to allow individual enrollment configurations per ACME account, as well as restrictions on CN and SANs in the CSR. To enable it, configure `acme_srv.cfg` as follows:

```ini
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

### Example Key File

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "template": ["WebServerModified", "WebServer"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.local"]
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

This setup ensures that individual accounts can have specific enrollment configurations and domain restrictions.
