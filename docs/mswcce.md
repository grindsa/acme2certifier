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
3. You need to have a set of credentials with permissions to access the service and enrollment templates

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
```

- host - hostname of the system providing the enrollment service
- host_variable - *optional* - name of the environment variable containing host address (a configured `host` parameter in acme_srv.cfg takes precedence)
- user - username used to access the service
- user_variable - *optional* - name of the environment variable containing the username used for service access (a configured `user` parameter in acme_srv.cfg takes precedence)
- password - password
- password_variable - *optional* - name of the environment variable containing the password used for service access (a configured `password` parameter in acme_srv.cfg takes precedence)
- target_domain - *optional* - ads domain name
- domain_controller - *optional* - IP Address of the domain controller.
- ca_name: - certificate authority name
- ca_bundle - CA certificate chain in pem format delievered along with the client certificate
- template - certificate template used for enrollment
