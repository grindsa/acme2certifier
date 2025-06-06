<!-- markdownlint-disable MD013 -->
<!-- wiki-title CA Handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) -->
# CA Handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)

This CA handler uses the Microsoft [Windows Client Certificate Enrollment Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/446a0fca-7f27-4436-965d-191635518466). The handler incorporates code from [Certipy](https://github.com/ly4k/Certipy), a pentesting tool for Active Directory Certificate Services (AD-CS).

## Limitations

Be aware of the following limitations when using this handler:

- CA certificates cannot be fetched from the CA server and must be manually loaded via the `ca_bundle` option in `acme_srv.cfg`.
- Revocation operations are not yet supported.

## Preparation

1. Active Directory Certificate Services (AD-CS) must be enabled and properly configured.
2. The CA handler uses RPC/DCOM to communicate with the CA server, so the CA server must be accessible via **TCP port 445**.
3. *(Optional)*: If installing from RPM or DEB and planning to use Kerberos authentication, ensure you have an updated [Impacket module (version 0.11 or higher)](https://github.com/fortra/impacket), as older versions have issues handling UTF-8 encoded passwords. You can find updated packages in the [A2C GitHub repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs).
4. You need a set of credentials with sufficient permissions to access the service and enrollment templates.

## Local Installation

- Install the [Impacket](https://github.com/fortra/impacket) module.

### **Important:**

Some malware scanners, such as Microsoft Defender, classify Impacket as a hacking tool (see [Fortra Impacket Issue #1762](https://github.com/fortra/impacket/issues/1762) or [Fortra Impacket Issue #1271](https://github.com/fortra/impacket/issues/1271#issuecomment-1058729047)). These alerts are triggered mainly by example scripts included in the package, not the library itself.

To avoid issues with your security team, consider installing a stripped-down version of Impacket without flagged scripts. Pre-packaged versions are available for [RHEL 8](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-impacket-0.11.0-2grindsa.el8.noarch.rpm) and [RHEL 9](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel9/python3-impacket-0.11.0-2grindsa.el9.noarch.rpm) in the [SBOM repository](https://github.com/grindsa/sbom/tree/main/rpm-repo).

If installing from pip or source, follow these steps:

- Download the Impacket package:

```bash
pip3 download impacket --no-deps
```

- Unpack the archive:

```bash
tar xvfz impacket-0.11.0.tar.gz
```

- Remove all files and subdirectories in the `examples` directory:

```bash
rm -rf impacket-0.11.0/examples/*
```

- Install the package:

```bash
python3 setup.py install
```

## Configuration

Modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/mswcce_ca_handler.py
host: <hostname>
user: <username>
password: <password>
target_domain: <domain_name>
domain_controller: <IP_of_domain_controller>
ca_name: <ca_name>
ca_bundle: <filename>
template: <template_name>
timeout: 5
use_kerberos: False
allowed_domainlist: ["example.com", "*.example2.com"]
eab_profiling: False
```

### Parameter Explanations

- **host** – The hostname of the system providing the enrollment service. Multiple hosts can be specified as `server1, server2, server3`; a random host will be selected.
- **host_variable** *(optional)* – Environment variable containing the host address (overridden if `host` is set in `acme_srv.cfg`).
- **ca_name** – Certificate authority name. Multiple CA names can be specified as `ca1, ca2, ca3`; a random entry will be chosen.
- **user** – Username for accessing the service.
- **user_variable** *(optional)* – Environment variable containing the username (overridden if `user` is set in `acme_srv.cfg`).
- **password** – Password for authentication.
- **password_variable** *(optional)* – Environment variable containing the password (overridden if `password` is set in `acme_srv.cfg`).
- **target_domain** *(optional)* – Active Directory domain name.
- **domain_controller** *(optional)* – IP address of the domain controller/DNS server.
- **dns_server** *(optional)* – IP address of the DNS server.
- **ca_bundle** – CA certificate chain in PEM format, provided along with the client certificate.
- **template** – Certificate template used for enrollment.
- **timeout** *(optional)* – Enrollment timeout in seconds (default: `5`).
- **use_kerberos** – Use Kerberos for authentication. If `False`, authentication is done via NTLM. Due to Microsoft's [October 2023 announcement](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-evolution-of-windows-authentication/ba-p/3926848), Kerberos is recommended, but NTLM remains the default for backward compatibility.
- **allowed_domainlist** *(optional)* – List of allowed domains for enrollment (JSON format).
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

Further, this handler uses the [header_info_list feature](header_info.md), allowing an ACME client to specify a template name for certificate enrollment. To enable this feature, update `acme_srv.cfg`:

```ini
[Order]
header_info_list: ["HTTP_USER_AGENT"]
```

## Example Usage

- **acme.sh**:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent template=foo --debug 3 --output-insecure
```

- **lego**:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent template=foo -d <fqdn> --http run
```

# EAB Profiling

This handler supports [EAB profiling](eab_profiling.md), which allows individual enrollment configurations per ACME account and restricts CN/SANs in the CSR. To enable this feature, update `acme_srv.cfg`:

```ini
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

## Example Key File

```json
{
  "keyid_00": {
    "hmac": "example_hmac_value",
    "cahandler": {
      "template": ["WebServerModified", "WebServer"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "unknown_key": "unknown_value"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "template": "WebServerModified",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
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
