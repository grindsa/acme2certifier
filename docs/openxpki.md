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

```
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
