<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for XCA -->
# Support for an XCA based Certificate Authorities

This handler can be used to store, certificates and requests in an [XCA](https://github.com/chris2511/xca/) SQLite database.

It is also possible to fetch enrollment templates from XCA an apply them to certificate signing requests.

## Prerequisites

You need to have a ready-made xca database with CA certificate and keys imported. You further need the `Internal Name` from the Certificate Authorities to be used as show in the XCA application.

![xca-ca-list](xca-ca-list.png)

## Configuration

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example/ca_handlers/xca_ca_handler.py acme_srv/ca_handler.py
```

- place the XCA database into a directory which is accessible by acme2certifier.

- modify the server configuration (/acme_srv/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/xca_ca_handler.py
xdb_file: acme_srv/xca/acme2certifier.xdb
issuing_ca_name: sub-ca
issuing_ca_key: sub-ca-key
passphrase_variable: XCA_PASSPHRASE
ca_cert_chain_list: ["root-ca"]
template_name: XCA template to be applied to CSRs
```

- `xdb_file` - path to XCA database
- `issuing_ca_name` - XCA name of the certificate authority used to issue certificates.
- `issuing_ca_key` - XCA name of the ley used to sign certificates. If not set same value as configured in `issuing_ca_name` will be assumed.
- `passphrase_variable` - *optional* - name of the environment variable containing the passphrase to decrypt the CA key (a configured `passphrase` parameter takes precedence)
- `passphrase` - *optional* - passphrase to access the database and decrypt the private CA Key
- `ca_cert_chain_list` - *optional* - List of root and intermediate CA certificates to be added to the bundle return to an ACME-client (the issuing CA cert must not be included)
- `template_name` - *optional* - name of the XCA template to be applied during certificate issuance
- allowed_domainlist - optional - list of domain-names allowed for enrollment in json format example: ["bar.local$, bar.foo.local] (default: [])
- eab_profiling - optional - [activate eab profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list enrollment parameters not to be logged in json format example: [ "parameter1", "parameter2" ] (default: [])

Template support has been introduced starting from v0.13. Support is limited to the below parameters which can be applied during certificate issuance:

- Certificate validity (`validN`/`validM`)
- basicConstraints (`ca`)
- KeyUsage attributes (`keyUse`) - if not included attribute will be defaulted to `digitalSignature, nonRepudiation, keyEncipherment, keyAgreement`
- extendedKeyUsage attributes (`eKeyUse`)
- crlDistributionPoints (`crlDist`)
- Enforcement of the following DN attributes:
  - OU: OrganizationalUnit
  - O: Organization
  - L: Locality
  - S: StateOrProvinceName
  - C: CountryName

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
      "template_name": ["template", "acme"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "unknown_key": "unknown_value"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "template_name": "template",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "issuing_ca_name": "root-ca",
      "issuing_ca_key": "root-ca"
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

Enjoy enrolling and revoking certificates...
