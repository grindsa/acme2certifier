<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) -->
# CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)

This CA handler uses the Microsoft [Windows Client Certificate Enrollment Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/446a0fca-7f27-4436-965d-191635518466). The handler is using code from [Certipy](https://github.com/ly4k/Certipy) which is a kind of pentesting tool for AD-CS.

When using the handler please be aware of the following limitations:

- CA certificates cannot be fetched from CA server and must be loaded via `ca_bundle` option configured in `acme_srv.cfg`
- Revocation operations are not (yet) supported

## Preparation

1. Active Directory Certificate Services (AD-CS) must be enabled and configured - of course :-)
2. The CA handler is using RPC/DCOM to communicate with the CA server. That means that your CA-server must be reachable via TCP port 445.
3. (optional): In case you are installing from RPM or DEB and plan to use kerberos authentication you need an updated [impacket modules of version 0.11 or higher](https://github.com/fortra/impacket) as older versions have issues with the handling of utf8-encoded passwords. If you have no clue from where to get these packaages feel free to use the one being part of [the a2c github repository](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs)
4. You need to have a set of credentials with permissions to access the service and enrollment templates

## Installation

- install the [impacket](https://github.com/SecureAuthCorp/impacket) via pip (the module is already part of the docker images)

```bash
root@rlh:~# pip install impacket
```

- modify the server configuration (acme_srv/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/mswcce_ca_handler.py
host: <hostname>
user: <username>
password: <password>
target_domain: <domain name>
domain_controller: <ip address of domain controller>
ca_name: <ca name>
ca_bundle: <filename>
template: <template name>
timeout: 5
use_kerberos: False
allowed_domainlist: ["example.com", "*.example2.com"]
```

- host - hostname of the system providing the enrollment service
- host_variable - *optional* - name of the environment variable containing host address (a configured `host` parameter in acme_srv.cfg takes precedence)
- user - username used to access the service
- user_variable - *optional* - name of the environment variable containing the username used for service access (a configured `user` parameter in acme_srv.cfg takes precedence)
- password - password
- password_variable - *optional* - name of the environment variable containing the password used for service access (a configured `password` parameter in acme_srv.cfg takes precedence)
- target_domain - *optional* - ads domain name
- domain_controller - *optional* - IP Address of the domain controller / dns server.
- dns_server - *optional* - IP Address of dns server.
- ca_name - certificate authority name
- ca_bundle - CA certificate chain in pem format delievered along with the client certificate
- template - certificate template used for enrollment
- timeout - *optional* - enrollment timeout (default: 5)
- use_kerberos - use kerboros for authentication; if set to `False` authentication will be done via NTLM. Considering a [Microsoft accouncement from October 2023](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-evolution-of-windows-authentication/ba-p/3926848) the usage of Kerberos should be preferred. Nevertheless, for backwards compatibility reasons the default setting is `False`
- allowed_domainlist - *optional* - list of domain-names allowed for enrollment in json format example: ["bar.local$, bar.foo.local]

## Passing a template from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify a template name to be used during certificate enrollment. This feature is disabled by default and must be activate in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the temmplate name as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent template=foo --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent template=foo -d <fqdn> --http run
```
