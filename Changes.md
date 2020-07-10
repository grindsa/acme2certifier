# Acme2certifier changelog

This is a high-level summary of the most important changes. For a full list of changes, see the [git commit log](https://github.com/grindsa/acme2certifier/commits) and pick the appropriate release branch.

## Changes between 0.9 and 0.10

**Features**:
- http_x_forward header support
- configurable tos
- option to disable contact check
- option to disable tos check

**Bugfixes**:
- mscertsrv_ca_handler: #37 - pkcs#7 to pem conversion
- mscertsrv_ca_handler: CRLF to LF conversion
- #35 rfc608  compliant contact checking
- xca_handler: #38 - prevent error message leakage to client

## Changes between 0.8 and 0.9

**Features**:
- option to mandate the usage of ecc keys
- openssl_handler: "save_as_hex" option
- openssl_handler: black/whitlist support
- openssl_hanlder: option to configure customized cert extensions
- option to configure custom dns resolvers
- xca_handler
- Additional client support (lego and win-acme)

**Bugfixes**:
- updated license
- empty CRL handling
- string parsing in `b64_url_encode()`
- py3 support for est_handler
- #9 - base64-parsing of dns challenge
- openssl_handler: set correct x509 version
- openssl_handler: mandentory cert-extensions
- harmonization of apache config files
- migration support for docker_django deployment

## Changes between 0.7 and 0.8

**Features**:
- Challenge polling
- Support for CA polling and callbacks
- Certifiate profiling in openssl handler
- Ssl support
- Container deployments
- Django project with mysql as backend database
