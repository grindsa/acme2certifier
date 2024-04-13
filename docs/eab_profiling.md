<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Account profiling -->
# EAB Profiling

Starting with  version 0.34 acme2certifier supports the configuration of account specific enrollment configuration. Depending on the handler to be used the feature allows the definition of individual authentication credentials, enrollment profiles or certificate authoritzies.

Currently the following ca-handlers had been modified and do support this feature:

- [Insta certifier/NetGuard Certificate manager](certifier.md)
- [Insta ActiveCMS](asa.md)
- [XCA](xca.md)

In case you need support for a different ca-handler feel free to raise an [issue](https://github.com/grindsa/acme2certifier/issues/new).

## Configuration

This feature requires [external account binding](eab.md) to be enabled and a specific EAB-handler to be configured.

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: volume/kid_profiles.json
```

The `key_file` allows the specification enrollmenmt parameters per (external) acme-account. Main identifier is the key_id to be used during account registration. Any parameter used in the [CAhandler] configuration section of a handler can be customized. Below an example configuration to be used for [Insta Certifier](certifier.md) with some explaination:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "profile_id": "profile_1",
      "allowed_domainlist": ["*.example.com", "*.example.org", "*.example.fi"],
      "ca_name": "non_default_ca",
      "api_user": "non_default_api_user",
      "api_password": "api_password"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "profile_id": ["profile_1", "profile_2", "profile_3"],
      "allowed_domainlist": ["*.example.fi", "*.acme"],
    }
  },
  "keyid_02": {
    "hmac": "YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr"
  }
}
```

- Acme-accounts created with keyid "keyid_00" will always use profile-id "profile_1" and specific api-user credentials for enrollment from certificate authority "non_default_ca". Further, the SAN/Common names to be used in enrollment requests are restricted to the domains "example.com", "example.org" and "example.fi".
- Acme-accounts created with keyid "keyid_01" and can specify 3 different profile_ids by using the [header_info feature](header_info.md). Enrollment requests having other profile_ids will be rejected. In case no profile_id get specified the first profile_id in the list ("profile_1") will be used. SAN/CNs to be used are restricted to "example.fi" and ".local" All other enrollment paramters will be taken from acme_srv.cfg
- Acme-accounts created with keyid "keyid_02" do not have any restriction. Enrolment parameters will be taken from the [CAhandler] section in ´acme_srv.cfg`
