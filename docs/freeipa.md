<!-- markdownlint-disable  MD013 -->

<!-- wiki-title FreeIPA CA Handler User Documentation -->

# FreeIPA CA Handler User Documentation

## Prerequisites

- A running [FreeIPA](https://www.freeipa.org/) server with RPC-XML API access enabled.
- A user account with sufficient privileges to add hosts and manage certificates.
- The `acme2certifier` application installed and configured.
- Python 3.7+ and required dependencies (see `requirements.txt`).

## FreeIPA limitation

It seems that FreeIPA requires the presence of a Common Name (CN) in the CSR and I did not find a way around it. This will exclude the usage of ACME clients not setting a common-name, like certbot.

## FreeIPA User Permissions and Setup

A dedicated user with sufficient privileges is required for the handler to manage hosts and certificates in FreeIPA. See [the below section](#freeipa-user-permissions-and-setup) for details on how to create and configure the user.

### Creating the User and Assigning Privileges

Run the following commands as a FreeIPA administrator:

```bash
# Create the user
ipa user-add a2c --first=ACME --last=Certifier --password
ipa user-mod a2c --setattr=krbPasswordExpiration=20991231235959Z

# Create a privilege for host and certificate management
ipa privilege-add "Host-Cert API Management" --desc "Privilege to manage hosts and enroll certificates via JSON API"
ipa privilege-add-permission "Host-Cert API Management" --permissions="System: Add Hosts"
ipa privilege-add-permission "Host-Cert API Management" --permissions="System: Modify Hosts"
ipa privilege-add-permission "Host-Cert API Management" --permissions="System: Manage Host Keytab"
ipa privilege-add-permission "Host-Cert API Management" --permissions="Request Certificate"
ipa privilege-add-permission "Host-Cert API Management" --permissions="System: Manage Host Certificates"
ipa privilege-add-permission "Host-Cert API Management" --permissions="Revoke Certificate"
ipa privilege-add-permission "Host-Cert API Management" --permissions="Retrieve Certificates from the CA"

# Add permission to manage host Kerberos principals
ipa permission-add "Manage Host Kerberos Principals" \
    --right=write \
    --type=host \
    --attrs=krbprincipalname
ipa privilege-add-permission "Host-Cert API Management" --permissions="Manage Host Kerberos Principals"

# Create a role and assign the privilege to it
ipa role-add "API Provisioning Role" --desc "Role for automated host provisioning and certificate management"
ipa role-add-privilege "API Provisioning Role" --privileges="Host-Cert API Management"
ipa role-add-member "API Provisioning Role" --users=a2c
```

This will create a user `a2c` with a non-expiring password and assign all necessary permissions for host and certificate management via the FreeIPA API. The user is then added to a dedicated role for API provisioning.

## Configuration

The FreeIPA CA handler is configured via the main server configuration file, typically `acme_srv/acme_srv.cfg`. Add or update the `[CAhandler]` section as follows:

```ini
[CAhandler]
handler_file = examples/ca_handler/freeipa_ca_handler.py
api_host = https://ipa.example.com
api_user = <ipa_user>
api_password = <ipa_password>
ca_bundle = True
fqdn = <fqdn_of_this_server>
realm = EXAMPLE.COM
profile_id = <profile_id>  # Optional, see below
```

### Parameter Descriptions

- `handler_file`: Path to the FreeIPA CA handler Python file.
- `api_host`: URL of the FreeIPA server (e.g., `https://ipa.example.com`).
- `api_user`: FreeIPA user with permissions to manage hosts and certificates.
- `api_password`: Password for the FreeIPA user.
- `ca_bundle`: Path to CA bundle for server certificate validation, or `True`/`False` (default: `True`).
- `fqdn`: The FQDN of the ACME server as known to FreeIPA.
- `realm`: The FreeIPA Kerberos realm (e.g., `EXAMPLE.COM`).
- `profile_id`: (Optional) Certificate profile to use for enrollment. Can be set per-request (see below).

## Handler Features

- Host management: Ensures hosts and principals exist in FreeIPA before certificate enrollment.
- Certificate enrollment: Handles CSR parsing, host/principal creation, and certificate request.
- Revocation: Supports certificate revocation by serial number.
- EAB (External Account Binding) and profile_id support.

## Passing a profile_id from Client to Server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `profile_id` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"IECUserRoles": "http://foo.bar/profiles/IECUserRoles", "caIPAserviceCert": "http://foo.bar/profiles/caIPAservice"}
```

Once enabled, a client can specify the profile_id to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile IECUserRoles
```

# EAB Profiling

This handler can use the [eab profiling feature](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activatedd in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>
eab_profiling: True

[CAhandler]
...
```

Below is an example key-file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "profile_id": ["IECUserRoles", "caIPAserviceCert"],
      "allowed_domainlist": ["www.server.acme", "www.server.foo", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "profile_id": "IECUserRoles",
      "allowed_domainlist": ["www.server.acme", "www.server.foo", "*.acme"]
      "ca_name": "subca2"
    }
  },
  "keyid_02": {
    "hmac": "dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM",
    "cahandler": {
      "allowed_domainlist": ["www.server.acme", "www.server.foo"]
    }
  },
  "keyid_03": {
    "hmac": "YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr"
  }
}
```

## Example Workflow

1. Client sends a CSR and (optionally) a `profile_id` (via HTTP header or EAB payload).
1. Handler extracts and sets `profile_id`.
1. Handler ensures host and principals exist in FreeIPA.
1. Handler submits certificate request using the selected `profile_id`.
1. Certificate is issued and returned to the client.

## Troubleshooting

- Ensure the FreeIPA user has permissions to add hosts and manage certificates.
- Check logs for errors related to host/principal creation or certificate enrollment.
- If using a custom CA bundle, verify the path and file permissions.
- For EAB/profile_id issues, ensure the client sends the correct data and the handler extracts it properly.

______________________________________________________________________

For more details, see the handler source code in `examples/ca_handler/freeipa_ca_handler.py` and the main documentation in `docs`.
