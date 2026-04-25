<!-- markdownlint-disable  MD013 -->

<!-- wiki-title Dogtag CA Handler Documentation -->

# [Dogtag CA](https://www.dogtagpki.org/) Handler Documentation

## Prerequisites

Before using the `dogtag_ca_handler`, ensure the following prerequisites are met:

- _Dogtag CA Server_: [A Dogtag Certificate Authority (CA) server](https://www.dogtagpki.org/) must be installed, configured, and running. The handler communicates with the Dogtag CA via its REST API endpoints.
- _User Account_: An administrative user account must exist on the Dogtag CA with sufficient privileges to enroll, approve, and manage certificates.
- _Network Access_: The system running the handler must have network access to the Dogtag CA server (typically on port 8443 for HTTPS).

## Limitations

- Dogtag CA requires that all certificate signing requests (CSRs) include a Common Name (CN) in the subject. CSRs without a CN will be rejected.
- Only profiles enabled and configured on the Dogtag CA can be used for enrollment. Ensure the required profiles are available and enabled.
- The handler supports workflows where certificate requests may require approval. Ensure your Dogtag CA is configured accordingly.

## Creating a API-User and API-User Key

To interact with the Dogtag CA, you need a user and a corresponding key/certificate. The following commands demonstrate how to create a user and generate the necessary key and certificate directly on the Dogtag CA host:

Before running the commands below, define the following variables in your shell:

```sh
# Define user and password variables
ADMIN_USER="PKI Administrator for acme"
A2C_USER="api-user"
ADMIN_PASSWORD="<ADMIN_PASSWORD>"   # Replace with the actual admin password
A2C_PASSWORD="<A2C_PASSWORD>"       # Replace with the actual API user password
```

```sh
# Add a user to Dogtag CA
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-user-add "$A2C_USER" --fullName 'REST API Service Account' <<< 'y'

# Set the user's password
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-user-mod "$A2C_USER" --password "$A2C_PASSWORD"

# Enable the required profile
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-profile-enable caDirUserCert

# Generate a private key for the user
openssl genrsa -out "$A2C_USER.key" 2048

# Create a certificate signing request (CSR)
openssl req -new -key "$A2C_USER.key" -out "$A2C_USER.csr" -subj "/CN=$A2C_USER"

# Submit the CSR to Dogtag CA
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-cert-request-submit --profile caServerCert --csr-file "$A2C_USER.csr" > req_response.txt

# Approve the certificate request
# (Extracts the request ID and approves it)
REQ_ID=$(grep 'Request ID' req_response.txt | awk '{print $3}')
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-cert-request-review "$REQ_ID" --action approve > cert_response.txt

# Export the issued certificate
# (Extracts the certificate ID and exports it)
CERT_ID=$(grep 'Certificate ID' cert_response.txt | awk '{print $3}')
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-cert-export "$CERT_ID" --output-file "$A2C_USER.crt"

# Add the certificate to the user
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-user-cert-add "$A2C_USER" --input "$A2C_USER.crt"

# Verify the user certificate
pki -c "$ADMIN_PASSWORD" -n "$ADMIN_USER" ca-user-cert-find "$A2C_USER"
```

## Configuration Parameters

The `dogtag_ca_handler` is configured via a configuration file (e.g., `acme_srv.cfg`). Below are the main parameters and their descriptions:

| Parameter                | Description                                                                                 |
|--------------------------|---------------------------------------------------------------------------------------------|
| `handler_file`           | Path to the handler Python file (e.g., `examples/ca_handler/dogtag_ca_handler.py`).         |
| `api_host`               | Base URL of the Dogtag CA REST API (e.g., `https://dogtag.acme:8443`).                     |
| `client_key`             | Path to the user's private key file.                                                        |
| `client_cert`            | Path to the user's certificate file.                                                        |
| `ca_bundle`              | Path to the CA bundle file or `False` to disable CA validation.                            |
| `profile`                | Name of the Dogtag CA profile to use for enrollment (e.g., `caServerCert`).                |
| `certrequest_approve`    | Set to `True` if certificate requests require approval.                                     |
| `enrollment_config_log`  | Set to `True` to enable logging of enrollment configuration.                                |
| `allowed_domainlist`     | List of allowed domains for certificate issuance (e.g., `["*.foo.bar", "*.acme"]`).      |
| `request_timeout`        | Timeout in seconds for API requests (default: 30).                                         |
| `proxy`                  | Proxy URL if requests should be routed through a proxy.                                     |
| `eab_handler`            | Path to the EAB handler file if using External Account Binding.                             |
| `eab_profiling`          | Set to `True` to enable EAB profiling.                                                      |
| `enrollment_config_log_skip_list` | List of config log entries to skip.                                                  |

### Example Configuration

```yaml
handler_file: examples/ca_handler/dogtag_ca_handler.py
api_host: https://dogtag.acme:8443
client_key: volume/acme/a2c.key
client_cert: volume/acme/a2c.crt
ca_bundle: False
profile: caServerCert
certrequest_approve: True
enrollment_config_log: True
allowed_domainlist: ["*.foo.bar", "*.acme"]
request_timeout: 30
proxy: ""
header_info_field: False
eab_handler: ""
eab_profiling: False
enrollment_config_log_skip_list: []
profiles: {"caServerCert": "http://foo.bar/caservercert", "Webserver": "http://foo.bar/webserver"}
```

## Passing a profile from client to server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `profile` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"Webserver": "http://foo.bar/webserver", "Shorliving": "http://foo.bar/shortliving", "caServerCert": "http://foo.bar/caservercert"}
```

Once enabled, a client can specify the profile_id to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile Webserver
```

## EAB profiling

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
      "profile": ["Webserver", "caServerCert", "p102"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "profile": "caServerCert",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "ca_name": "subca2"
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

## Additional Notes

- Ensure all file paths in the configuration are accessible to the handler process.
- For production deployments, secure all credentials and sensitive files.
- Consult the Dogtag CA documentation for advanced configuration and troubleshooting.
