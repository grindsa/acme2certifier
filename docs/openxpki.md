<!-- markdownlint-disable MD013 -->

<!-- wiki-title CA Handler for OpenXPKI -->

# Connecting to OpenXPKI

This handler allows certificate enrollment from [OpenXPKI](https://www.openxpki.org/), as ACME support appears to be available only in the commercial version.

Although connecting to OpenXPKI was previously possible via the [generic EST CA handler](est.md), this dedicated handler is **preferred** because it supports revocation operations and allows specifying [certificate profiles](https://openxpki.readthedocs.io/en/develop/reference/configuration/profile.html).

## Prerequisites

To use this handler, ensure you have:

- A running [OpenXPKI](https://www.openxpki.org/) instance with an **activated [RPC server](https://openxpki.readthedocs.io/en/develop/subsystems/rpc.html)**.
- An RPC endpoint that supports `RequestCertificate`, `RevokeCertificate`, and `SearchCertificate`, as described in the [example configuration](https://github.com/openxpki/openxpki-config/blob/community/rpc/enroll.conf).
- A **client certificate and key** in PEM format for authentication with OpenXPKI.
- A [certificate profile](https://openxpki.readthedocs.io/en/develop/reference/configuration/profile.html).

## OpenXPKI Configuration

To ensure compatibility with **acme2certifier**, adjust the OpenXPKI configuration:

### 1. Return the Full Certificate Chain

By default, acme2certifier expects a full certificate chain (including the root certificate) in the response to a `RequestCertificate` call. Modify the `export_certificate` parameter in the OpenXPKI endpoint configuration file (`config.d/realm.tpl/rpc/`) as follows:

```yaml
policy:
      export_certificate: fullchain
```

### 2. Configure Approval Points

Although **certificate polling** is supported via the `polling_timeout` parameter in `acme_srv.cfg`, **manual or dual approval should be skipped** to ensure smooth enrollment operations. Set `approval_points` to `1` in `config.d/realm.tpl/rpc/`:

```yaml
policy:
      approval_points: 1
```

### 3. Handle Missing Common Names in CSRs

Some ACME clients, such as [Certbot](https://certbot.eff.org/), generate CSRs without a subject name, causing OpenXPKI to reject them. To address this, modify the OpenXPKI certificate profile (`config.d/realm.tpl/profile/`) to use the **first Subject Alternative DNS name (SAN DNS.0) as the CN** when no CN is present:

```yaml
style:
    # RPC endpoint name, e.g., "enroll"
    enroll:
        subject:
            dn: "[% IF CN.0 && CN.0 != '' %]CN=[% CN.0 %][% ELSE %]CN=[% SAN_DNS.0 %][% END %]"
```

- acme2certifier will issue certificates on behalf of the end nodes. This needs to be allowed in OpenXPKI. Please see more info on enroll modes (especially `Signer on Behalf` section) here: [Enrollment Workflow](https://openxpki.readthedocs.io/en/develop/reference/configuration/workflows/enroll.html). For this, you will need to set the client certificate as an `authorized_signer` for your RPC endpoint. You can set this in `config.d/realm.tpl/rpc/enroll.yaml`:

```yaml
authorized_signer:
    rule1:
        # Full DN
        subject: CN=cn-of-your-client-cert-here(?:,.+|$)
```

## Configuration

Modify the **acme2certifier** configuration (`acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/openxpki_ca_handler.py
host: <URL>
client_key: <filename>
client_cert: <filename>
ca_bundle: <filename>
cert_profile_name: <name>
endpoint_name: <name>
polling_timeout: <seconds>
```

### Parameter Explanations

- **host** – URL of the OpenXPKI server.
- **client_cert** – Client certificate in PEM or PKCS#12 format, used for authentication.
- **client_key** – *(Required if using PEM format)* Key file used for authentication.
- **cert_passphrase** – *(Required if using PKCS#12 format)* Passphrase for accessing the PKCS#12 container.
- **cert_passphrase_variable** *(optional)* – Environment variable containing the certificate passphrase (overridden if `cert_passphrase` is set in `acme_srv.cfg`).
- **ca_bundle** *(optional)* – CA certificate chain in PEM format needed to validate the OpenXPKI server certificate. Accepts `True`, `False`, or a filename (default: `True`).
- **cert_profile_name** – Name of the OpenXPKI certificate profile to be used.
- **endpoint_name** – Name of the OpenXPKI RPC endpoint.
- **polling_timeout** – Timeout (in seconds) for enrollment operations (default: `0`, polling disabled).
- **request_timeout** *(optional)* – Timeout (in seconds) for OpenXPKI requests (default: `5s`).
- **allowed_domainlist** *(optional)* – List of domain names allowed for enrollment (JSON format). Example: `["bar.local", "bar.foo.local"]` (default: `[]`).

## Certificate Enrollment

Use your preferred ACME client for certificate enrollment. A list of clients used in our regression testing is available in the [disclaimer section of our README](../README.md).

## Passing a profile_id from client to server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `cert_profile_name` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"profile1": "http://foo.bar/profile1", "profile2": "http://foo.bar/profile2", "profile3": "http://foo.bar/profile3"}
```

Once enabled, a client can specify the cert_profile_name to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile profile2
```

Further, this handler makes use of the [header_info_list feature](header_info.md) allowing an ACME client to specify a certificate profile to be used during certificate enrollment. This feature is disabled by default and must be activated in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The ACME client can then specify the profileID as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent cert_profile_name=acme_clt --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent cert_profile_name=acme_clt -d <fqdn> --http run
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

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "cert_profile_name": ["acmeca2", "acmeca1"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "cert_profile_name": "acmeca2",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "ca_name": "acmeca"
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
