<!-- markdownlint-disable MD013 MD014 -->

<!-- wiki-title: CA Handler for Microsoft Certification Authority Web Enrollment Service -->
<!-- wiki-category: CA Handlers -->

# CA Handler for Microsoft Certification Authority Web Enrollment Service

This CA handler uses Microsoft's [Certification Authority Web Enrollment Service](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)>) for certificate enrollment. It also utilizes a modified version of the Python library [magnuswatn](https://github.com/magnuswatn/)/[certsrv](https://github.com/magnuswatn/certsrv) to communicate with the enrollment service.

## Limitations

Be aware of the following limitations when using this handler:

- Authentication towards the Web Enrollment Service is limited to "basic," "NTLM," or "GSSAPI (Kerberos)." ClientAuth is not supported.
- Communication is limited to HTTPS.
- Revocation operations are not supported.

## Preparation

1. Microsoft Certification Authority Web Enrollment Service must be enabled and configured.
1. You need a set of credentials with permission to access the service and enrollment templates.
1. The authentication method (basic or NTLM) must be configured correctly.
1. *(Optional)*: If installing from RPM and using NTLM authentication, you need two additional Python modules: [python3-requests-ntlm](https://pypi.org/project/requests_ntlm/) and [python3-ntlm-auth](https://pypi.org/project/ntlm-auth/). These are not part of the standard or EPEL repositories. You can find them in the [A2C GitHub repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs).
1. *(Optional)*: If installing from RPM and using GSSAPI authentication, you need two additional Python modules: [python3-requests-gssapi](https://pypi.org/project/requests-gssapi/) and [gssapi](https://pypi.org/project/gssapi/). These are also available in the [A2C GitHub repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs).

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
curl --negotiate -u <user>:<password> -k https://<host>/certsrv/
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

### Extended Protection for Authentication (EPA) Configuration

When using GSSAPI (Kerberos) authentication, Microsoft Certificate Services Web Enrollment may have Extended Protection for Authentication (EPA) set to **Required**. EPA/CBT support was added in [`requests-gssapi` 1.4.0](https://github.com/pythongssapi/requests-gssapi/releases/tag/v1.4.0) via [PR #57](https://github.com/pythongssapi/requests-gssapi/pull/57) as an opt-in `channel_bindings='tls-server-end-point'` parameter.

acme2certifier can enable that automatically via `gssapi_channel_bindings`:

| Value | Behavior |
|-------|----------|
| `auto` (default) | Use `tls-server-end-point` when `requests-gssapi >= 1.4.0`; otherwise continue without and log a warning |
| `on` | Require channel bindings; fail if `requests-gssapi` is too old |
| `off` | Never send channel bindings |

```ini
[CAhandler]
auth_method: gssapi
gssapi_channel_bindings: auto
```

**Distro note**: As of writing, EL9 AppStream ships `python3-requests-gssapi` 1.4.0. Ubuntu 24.04/26.04 and EL8 still ship 1.2.x, so EPA **Required** needs a newer pip/RPM package or the IIS workaround below.

**Fallback (EPA Accept)**: If channel bindings are unavailable, change Extended Protection from **Required** to **Accept** in IIS for the CertSrv application:

1. Open **Internet Information Services (IIS) Manager** on the server hosting the Certificate Services Web Enrollment Service
1. Navigate to the **Default Web Site** → **CertSrv** application
1. Double-click on **Authentication** in the Features View
1. Select **Windows Authentication** and click **Advanced Settings**
1. In the **Extended Protection** dropdown, change from **Required** to **Accept**
1. Click **OK** to apply the changes
1. Restart the IIS service or the specific application pool

For detailed information about Extended Protection for Authentication, refer to the [Microsoft documentation on Extended Protection for Authentication Overview](https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/).

## Installation

- Allow the MD4 algorithm in `openssl.cnf` (not necessary for Kerberos Auth):

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
[Order]
allowed_header_values: ["WebServer", "WebServerModified"]

[CAhandler]
handler_module: acme2certifier.cahandlers.mscertsrv_ca_handler
host: <hostname>
user: <username>
password: <password>
ca_bundle: <filename>
auth_method: <basic|ntlm|gssapi>
gssapi_channel_bindings: <auto|on|off>
template: <name>
ca_templates_check: warn
allowed_domainlist: ["example.com", "*.example2.com"]
krb5_principal: <principal@REALM>
krb5_keytab: </path/to/keytab>
krb5_cache: </path/to/ccache>
krb5_config: <path_to_individual>/krb5.conf
krb5_kinit_path: </path/to/kinit>
```

### Parameter Explanations

- **host** – The hostname of the system providing the Web Enrollment Service (FQDN/hostname without a URL scheme). When `url` is unset, requests use `https://<host>/certsrv/...`.
- **host_variable** *(optional)* – Name of the environment variable containing the host address (overridden if `host` is set in `acme_srv.cfg`).
- **url** *(optional)* – Full Web Enrollment base URL (for example `https://ca.example.com/certsrv`). When set, it overrides the default `https://<host>/certsrv` path construction. **Must use HTTPS**; `http://` is rejected.
- **url_variable** *(optional)* – Name of the environment variable containing the enrollment URL (overridden if `url` is set in `acme_srv.cfg`).
- **user** – Username for accessing the service.
- **user_variable** *(optional)* – Name of the environment variable containing the username (overridden if `user` is set in `acme_srv.cfg`).
- **password** – Password for authentication.
- **password_variable** *(optional)* – Name of the environment variable containing the password (overridden if `password` is set in `acme_srv.cfg`).
- **ca_bundle** – CA certificate bundle in PEM format used to validate the AD CS HTTPS server certificate. Prefer this over disabling verification when the enrollment endpoint uses a private/enterprise CA.
- **verify** *(optional, default `True`)* – Whether to verify the AD CS TLS server certificate. Set to `False` only as a break-glass measure (for example lab setups with untrusted certs). **Security warning:** `verify: False` disables TLS certificate validation for enrollment traffic (CSR, credentials, returned certificates) and enables man-in-the-middle attacks on the path to AD CS. Prefer `ca_bundle` / system trust instead. The handler logs a warning at config load when verification is disabled; enrollment is not blocked.
- **auth_method** – Authentication method (`basic`, `ntlm`, or `gssapi`). Default is `basic` for backwards compatibility. `basic` and `ntlm` are deprecated; the handler logs a warning at config load (including when the default is used) and recommends migrating to `gssapi`. Enrollment is not blocked.
- **gssapi_channel_bindings** *(optional)* – GSSAPI channel bindings mode for EPA/CBT: `auto` (default), `on`, or `off`. Requires `requests-gssapi >= 1.4.0` when enabled.
- **krb5_principal** *(optional, required for keytab mode)* – Kerberos principal, for example `svc-a2c-enroll@EXAMPLE.COM`.
- **krb5_principal_variable** *(optional)* – Name of the environment variable containing the Kerberos principal (overridden if `krb5_principal` is set in `acme_srv.cfg`).
- **krb5_keytab** *(optional, required for keytab mode)* – Path to the Kerberos keytab file used by the service account.
- **krb5_keytab_variable** *(optional)* – Name of the environment variable containing the keytab path (overridden if `krb5_keytab` is set in `acme_srv.cfg`).
- **krb5_cache** *(optional)* – Path to the Kerberos credential cache (ccache). In keytab mode, a temporary ccache is created if this value is omitted. If you set a shared path used by multiple worker processes or threads, concurrent `kinit`/ticket refresh can race on the same file; prefer a per-process temporary cache, or a dedicated cache with a single writer and clear operational ownership.
- **krb5_cache_variable** *(optional)* – Name of the environment variable containing the ccache path (overridden if `krb5_cache` is set in `acme_srv.cfg`).
- **krb5_config** *(optional)* – Path to an individual `krb5.conf` file. Applied to `kinit` subprocesses (keytab fallback and GSSAPI password mode) and scoped as `KRB5_CONFIG` during enrollment so SPNEGO can obtain service tickets (TGS) using the same realm/KDC map. Relative paths are resolved against the process working directory.
- **krb5_config_variable** *(optional)* – Name of the environment variable containing the `krb5.conf` path (overridden if `krb5_config` is set in `acme_srv.cfg`).
- **krb5_kinit_path** *(optional)* – Full path to the `kinit` binary used by the keytab fallback and GSSAPI password paths. Defaults to `kinit` resolved from `PATH`. If set, the value must be an **absolute** path whose basename is exactly `kinit` (for example `/usr/bin/kinit`). Symlink targets such as Debian/Ubuntu `kinit.mit` / `kinit.heimdal` are accepted after resolution. Other values are rejected and the kinit fallback fails.
- **krb5_kinit_path_variable** *(optional)* – Name of the environment variable containing the `kinit` binary path (overridden if `krb5_kinit_path` is set in `acme_srv.cfg`).
- **template** – Certificate template used for enrollment.
- **allowed_templates** *(optional, deprecated for header allowlisting)* – JSON list of ADCS templates permitted for enrollment. Prefer `[Order] allowed_header_values` (see [header_info.md](header_info.md)). When `allowed_header_values` is set, it is used instead. When only `allowed_templates` is set, a deprecation warning is logged and the list is still honored (including MS enrollment membership checks). When neither list is set, client-selected templates from `header_info` are **ignored** unless `ACME2CERTIFIER_I_KNOW_THE_RISK` is set. EAB per-account template restrictions still apply on top of this global ceiling.
- **ca_templates_check** *(optional, default `warn`)* – Compare the selected template against templates reported by ADCS Web Enrollment (`certrqxt.asp`): `warn` (log and continue), `on` (reject if missing from the CA list), or `off` (skip). The Web Enrollment dropdown is not a complete ADCS inventory; fetch failures or an empty CA list log a warning and enrollment continues. Results are cached process-wide (thread-safe).
- **allowed_domainlist** *(optional)* – List of allowed domain names for enrollment (JSON format).
- **enrollment_config_log** *(optional)* – Log enrollment parameters (default: `False`). This handler omits `password`, Kerberos credential locations (`krb5_keytab`, `krb5_cache`, `krb5_config`, `krb5_kinit_path`), and runtime GSSAPI credentials from that dump.
- **enrollment_config_log_skip_list** *(optional)* – List of enrollment parameters to exclude from logs (JSON format).

Enrollment failures against AD CS return a short handler error (`Could not get certificate from CA server`). Full exception text (HTTP status, Kerberos/GSSAPI details, etc.) is written to the server log only.

### GSSAPI Keytab Mode

When `auth_method` is set to `gssapi`, the handler supports keytab-based Kerberos authentication.
If `krb5_principal` and `krb5_keytab` are configured, the handler prepares Kerberos credentials using Python GSSAPI and falls back to `kinit` if needed.
Prepared credentials are loaded from the ccache and passed explicitly into the certsrv client; the handler does **not** mutate process-wide `KRB5CCNAME` (safe for threaded WSGI).
When `krb5_config` is set, `KRB5_CONFIG` is temporarily scoped around enrollment so MIT Kerberos can resolve the KDC for SPNEGO/TGS (ccache alone is not enough). Concurrent enrollments with different `krb5_config` values in one process are unsupported.

Example:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.mscertsrv_ca_handler
host: <hostname>
auth_method: gssapi
template: <name>
krb5_principal: svc-a2c-enroll@EXAMPLE.COM
krb5_keytab: /etc/acme2certifier/svc-a2c-enroll.keytab
krb5_cache: /var/www/acme2certifier/volume/krb5cc_a2c

krb5_config: /etc/krb5.conf
krb5_kinit_path: /usr/bin/kinit
```

### GSSAPI Password Mode

When `auth_method` is `gssapi` and `user` / `password` are configured (without keytab), the handler acquires a TGT via `kinit` in a **subprocess** with `KRB5_CONFIG` / `KRB5CCNAME` set only for that process, then loads GSSAPI credentials from the ccache and passes them explicitly to the certsrv client. Enrollment additionally scopes `KRB5_CONFIG` for SPNEGO/TGS when `krb5_config` is configured.
Bare usernames (for example `a2c`) work when `krb5_config` defines `default_realm` and KDC settings.
If password `kinit` is unavailable (binary missing or not on `PATH`), the handler falls back to in-process `acquire_cred_with_password`. That path also uses the scoped `KRB5_CONFIG` during enrollment when `krb5_config` is set.

Example:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.mscertsrv_ca_handler
host: <hostname>
user: a2c
password: <secret>
auth_method: gssapi
template: <name>
krb5_config: /etc/acme2certifier/krb5.conf
krb5_kinit_path: /usr/bin/kinit
```

## Passing a Template from Client to Server

acme2certifier supports the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md), allowing an acme-client to specify a `template` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"template1": "http://foo.bar/template1", "template2": "http://foo.bar/template2", "template3": "http://foo.bar/template3"}
```

Once enabled, a client can specify the template to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego run --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http --profile template2
```

The handler supports the [header_info_list feature](header_info.md), allowing an ACME client to specify a template name during enrollment. To enable this feature, update `acme_srv.cfg`:

```ini
[Order]
header_info_list: ["HTTP_USER_AGENT"]
allowed_header_values: ["WebServer", "WebServerModified"]
```

Configure a non-empty `allowed_header_values` list so client-selected values are accepted. Without that list (and without `ACME2CERTIFIER_I_KNOW_THE_RISK`), header-supplied templates are ignored. `[CAhandler] allowed_templates` remains a deprecated compatibility alias.

### Example Usage

- **acme.sh**:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent template=foo --debug 3 --output-insecure
```

- **lego**:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego run --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" --user-agent template=foo -d <fqdn> --http
```

## EAB Profiling

This handler supports [EAB profiling](eab_profiling.md) to allow individual enrollment configurations per ACME account, as well as restrictions on CN and SANs in the CSR. To enable it, configure `acme_srv.cfg` as follows:

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.kid_profile_handler
key_file: <profile_file>
eab_profiling: True

[CAhandler]
...
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
