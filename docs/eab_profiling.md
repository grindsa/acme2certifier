<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Enrollment profiling via external account binding -->
# Enrollment profiling via external account binding

Starting with  version 0.34 acme2certifier supports the configuration of account specific enrollment configuration. Depending on the handler to be used the feature allows the definition of individual authentication credentials, enrollment profiles or certificate authorities.

Currently the following ca-handlers have been modified and support this feature:

- [generic ACME](acme_ca.md)
- [EJBCA](ejbca.md)
- [Insta ActiveCMS](asa.md)
- [Insta certifier/NetGuard Certificate manager](certifier.md)
- [Microsoft Certificate Enrollment Web Services](mscertsrv.md)
- [Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) via RPC/DCOM](mswcce.md)
- [XCA](xca.md)

In case you need support for a different ca-handler feel free to open an [issue](https://github.com/grindsa/acme2certifier/issues/new).

## Configuration

This feature requires [external account binding](eab.md) to be enabled and a specific EAB-handler to be configured.

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: volume/kid_profiles.json
```

The `key_file` allows the specification enrollment parameters per (external) acme-account. Main identifier is the key_id to be used during account registration. Any parameter used in the \[CAhandler\] configuration section of a handler can be customized. Starting from acme2certifier v0.38 challenge validation can be disabled for a specific eab-user.

Below is an example configuration to be used for [Insta Certifier](certifier.md) with some explanation:

```json
{
  "keyid_00": {
    "hmac": "hmac-key",
    "cahandler": {
      "profile_id": "profile_1",
      "allowed_domainlist": ["*.example.com", "*.example.org", "*.example.fi"],
      "ca_name": "non_default_ca",
      "api_user": "non_default_api_user",
      "api_password": "api_password"
    }
  },
  "keyid_01": {
    "hmac": "hmac-key",
    "cahandler": {
      "profile_id": ["profile_1", "profile_2", "profile_3"],
      "allowed_domainlist": ["*.example.fi", "*.acme"]
    }
  },
  "keyid_02": {
    "hmac": "hmac-key"
  }
}
```

- ACME accounts created with keyid "keyid_00" will always use profile-id "profile_1" and specific api-user credentials for enrollment from certificate authority "non_default_ca". Further, the SANs/Common Names to be used in enrollment requests are restricted to the domains "example.com", "example.org" and "example.fi".
- ACME accounts created with keyid "keyid_01" and can specify 3 different profile_ids by using the [header_info feature](header_info.md). Enrollment requests having other profile_ids will be rejected. In case no profile_id get specified the first profile_id in the list ("profile_1") will be used. SAN/CNs to be used are restricted to "example.fi" and ".local" All other enrollment parameters will be taken from acme_srv.cfg. Furthermore the challenge validation got disabled for this user which means that acme2certifier will accept any CN/SAN matching the pattern "*.example.fi" or "*.acme".
- ACME accounts created with keyid "keyid_02" do not have any restriction. Enrolment parameters will be taken from the \[CAhandler\] section in ´acme_srv.cfg´

Starting from v0.36 acme2certifier does support profile configuration in yaml format. Below a configuration example providing the same level of functionality as the above JSON configuration

```yaml
---
{
---
keyid_00:
  hmac: "hmac-key"
  cahandler:
    profile_id: "profile_1"
    allowed_domainlist:
    - "*.example.com"
    - "*.example.org"
    - "*.example.fi"
    ca_name: "non_default_ca"
    api_user: "non_default_api_user"
    api_password: "api_password"
keyid_01:
  hmac: "hmac-key"
  cahandler:
    profile_id:
    - "profile_1"
    - "profile_2"
    - "profile_3"
    allowed_domainlist:
    - "*.example.fi"
    - "*.acme"
keyid_02:
  hmac: "hmac-key"
```

## Subject Profiling

Starting from v0.36 the eab-profiling feature can be used to check and white-list the certificate subject DN.

Attribute names must follow [RFC3039](https://www.rfc-editor.org/rfc/rfc3039.html#section-3.1.2); every RDN can be white-listed as:

- string - attribute in CSR DN must match this value
- list - attribute in CSR DN must match one of the list entries
- "\*" - any value matches as long as the attribute is present

The below example configuration will only allow CSR matching the following criteria:

- serial number can be of any value but must be included
- organizationalUnitName must be one of "acme1" or "acme2"
- organizationName must be "acme corp"
- countryName must be "AC"
- additional CSR DN attributes such as localityName or stateOrProvinceName are not allowed

```json
...
{
  "keyid_00": {
    "hmac": "hmac-key",
    "cahandler": {
      "template_name": ["template", "acme"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "subject": {
        "serialNumber": "*",
        "organizationName": "acme corp",
        "organizationalUnitName": ["acme1", "acme2"],
        "countryName": "AC"
       }
    }
  }
}
...
```

## Profile verification

The key file can be checked for consistency by using the `tools/eab_chk.py` utility.

```bash
 py /var/www/acme2certifier/tools/eab_chk.py --help
```

```bash
usage: eab_chk.py [-h] -c CONFIGFILE [-d] [-v] [-vv] [-k KEYID | -s]

eab_chk.py - verify eab keyfile

options:
  -h, --help            show this help message and exit
  -c CONFIGFILE, --configfile CONFIGFILE
                        configfile
  -d, --debug           debug mode
  -v, --verbose         verbose
  -vv, --veryverbose    show enrollment profile
  -k KEYID, --keyid KEYID
                        keyid to filter
  -s, --summary         summary
```

Below is an example output by using the above mentioned keyfile

- show a summary only

```bash
py /var/www/acme2certifier/tools/eab_chk.py  -c /var/www/acme2certifier/acme_srv/acme_srv.cfg
```

```bash
Summary: 4 entries in kid_file
```

- show keyids and hmac

```bash
 py /var/www/acme2certifier/tools/eab_chk.py  -c /var/www/acme2certifier/acme_srv/acme_srv.cfg -v
```

```bash
Summary: 4 entries in kid_file
keyid_00: V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw
keyid_01: YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg
keyid_02: dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM
keyid_03: YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr
```

- show profiles

```bash
py /var/www/acme2certifier/tools/eab_chk.py  -c /var/www/acme2certifier/acme_srv/acme_srv.cfg -vv
```

```bash
Summary: 4 entries in kid_file
keyid_00:
  cahandler:
    allowed_domainlist:
    - www.example.com
    - www.example.org
    - '*.example.fi'
    - '*.bar.local'
    profile_id:
    - '101'
    - '102'
    profile_name:
    - ACME_2
    - ACME
    template_name:
    - TLS_Server
    - acme
  hmac: V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw
keyid_01:
  cahandler:
    allowed_domainlist:
    - '*.example.fi'
    - '*.acme'
    - '*.bar.local'
    profile_id: '101'
    profile_name: ACME_2
    template_name: TLS_Server
  hmac: YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg
keyid_02:
  cahandler:
    ca_name: RSA Root CA
  hmac: dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM
keyid_03:
  hmac: YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr
```

- filter output to a single keyid

```bash
py /var/www/acme2certifier/tools/eab_chk.py  -c /var/www/acme2certifier/acme_srv/acme_srv.cfg -k keyid_01
```

```bash
Summary: 1 entries in kid_file
keyid_01:
  cahandler:
    allowed_domainlist:
    - '*.example.fi'
    - '*.acme'
    - '*.bar.local'
    profile_id: '101'
    profile_name: ACME_2
    template_name: TLS_Server
  hmac: YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg
```
