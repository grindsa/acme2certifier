<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- Hashicorp Vault PKI CA-handler -->

# Hashicorp Vault PKI CA-handler

## Overview

This CA-handler adds support for certificate management using [Hashicorp Vault's PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki). It provides methods integrating Vault as a backend for enrollment and revocation operations.

## Prerequisites

- **Hashicorp Vault** installed and running with the PKI secrets engine enabled.
- Vault server must be initialized, unsealed, and accessible from acme2certifier.
- The following Vault configuration items must be set up:
  - PKI secrets engine enabled at the desired path (e.g., `pki` or `pki_int`)
  - Roles and issuers configured for your use case
  - API access token for Vault with sufficient permissions
  - vault PKI needs to return the entire certificate chain (up-to rootca) in its response to an enrollment request.

## Configuration

Add a `[CAhandler]` section to your configuration file (e.g., `acme_srv.cfg`):

```ini
[CAhandler]
vault_url = http://vault-server:8200
vault_path = <pki path>
vault_role = <vault-role>
vault_token = <your-vault-token>
issuer_ref = <issuer-id>         # Optional
request_timeout = 20             # Optional, default is 20 seconds
cert_validity_days = 365         # Optional, default is 365 days
ca_bundle = <path>               # CA bundle to verify the certificate presented by Vault server
```

Other configuration options (domain lists, profiles, proxies, etc.) are loaded as in previous handlers.

## Passing a vault-role from client to server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `vault-role` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"vault-role1": "http://foo.bar/vault-role1", "vault-role2": "http://foo.bar/vault-role2", "vault-role3": "http://foo.bar/vault-role3"}
```

Once enabled, a client can specify the cert_profile_name to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile vault-role1
```

## eab profiling

This handler can use the [eab profiling feature](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activatedd in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

Below is an example key file used during regression testing:

- ACME clients using `keyid_00` can submit vault-role parameters "clientauth" or "serverauth" as part of an enrollmnet request (see above section)
- ACME clients using `keyid_01` enroll certificates from a different CA (pki-path `pki_alternate`) with the vault-role `vault-alternate`
- ACME clients using `keyid_03` are using a specific list of allowed domains
- ACME clients using `keyid_04` are using the paramters configured in `acme_srv_cfg`

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "vault-role": ["clientauth", "serverauth"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "vault-role": "clientauth_alternate",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "ca_name": "pki_alternate"
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

## Notes

- Ensure your Vault token has permissions for PKI operations.
- the [Build your own certificate authority (CA) tutorial](https://developer.hashicorp.com/vault/tutorials/pki/pki-engine) has been used to setup a vault test system. The respective configuration can be found in the [test-workflow](../.github/actions/wf_specific/vault_ca_handler/vault_prep/action.ymlL108)
