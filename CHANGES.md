<!-- markdownlint-disable  MD013 -->
# Acme2certifier changelog

This is a high-level summary of the most important changes. For a full list of
changes, see the [git commit log](https://github.com/grindsa/acme2certifier/commits)
and pick the appropriate release branch.

## Changes in 0.13

**Features**:

- template support in `xca_handler.py`
- docker images at [ghcr.io](https://github.com/grindsa?tab=packages)

**Bugfixes/Improvements**:

- refactor `nclm_ca_handler.py`
- refactor `certifier_ca_handler.py`
- workflows for
  - code-scanning (CodeQL and Bandit)
  - ca_handler tests

## Changes in 0.12

**Upgrade notes**:

- its enough to run the upgrade script. Depending on your configuration you need to either run
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django.handler

**Features**:

- docker images containing nginx
- readymade images at [dockerhub](https://hub.docker.com/r/grindsa/acme2certifier)

**Bugfixes/Improvements**:

- several fixes in unit-tests
- unit-tests are splitted into separate files
- unittests for `certifier_ca_handler.py`
- documentation updates
- Github actions to test
  - certificate enrollment for all four containerized deployment options
  - tnauth functionality
  - image creation and dockerhup upload

## Changes in 0.11.1

**Bugfixes**:

- `cmp_ca_handler.py`- avoid crash if tmp_dir has not been specified in config-files
- `order.py` - expiry date will be added during authz creation
- `authorization.py` - corner cases handling in case authz expiry is set to 0
- `wiki-update.yml` - checkout from `grindsa/github-wiki-publish-action@customize_wiki_title`
- `*.md` - meta tag "wiki-name" added

## Changes in 0.11

**Upgrade notes**:

- take a backup of your `acme_srv.db` before doing the upgrade
- update your `db_handler.py` with the latest version from the `examples/db_handler` directory
- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django.handler
- orders and authorization expire based on (pre)configured timers
- default expiration timer is 86400 seconds and can be adjusted in `acme_srv.cfg`.
- auto expiration can be disabled in `acme_srv.cfg`. Check [docs/acme_srv.md](docs/acme_srv.md) for further information.
- the expiration checks and order/authorization invalidation will be triggered in case a client accesses an `order` or `authorization` resource.  It is recommended to run the script `tools/invalidator.py` after the upgrade to manually check and invalidate expired authorizations and orders and update issuing- and expiration date in the certificate table.

**Features**:

- ca_handler kann be specified in `acme_srv.cfg`
- certifier_ca_handler.py - handling of der encoded certificates in trigger() method
- issuing date and expiration date will be stored in the `certificate` table
- `xca_ca_handler`: new variable `issuing_ca_key`
- basic [reporting and housekeeping](docs/housekeeping.md)
- order and authorization expiration
- method to remove expired certificates from database. Check the `certificate_cleanup` method [docs/housekeeping.md](docs/housekeeping.md) for further information
- database versioning and error logging in case of version mismatch

**Bugfixes***:

- Base64 encoding `certifier_trigger.sh` (removed blanks by using `-w 0`)
- improved exception handling in case of database-errors

## Changes in 0.10

**Upgrade notes**:

- database scheme gets updated. Depending on the db_handler you need to:
  - run `py manage.py makemigrations && py manage.py migrate` in case you use the django_handler.
  - execute the `tools/db_upgrade.py` script when using the wsgi_handler

**Features**:

- http_x_forward header support
- configurable tos
- option to disable contact check
- option to disable tos check

**Bugfixes**:

- mscertsrv_ca_handler: [#37 - pkcs#7 to pem conversion](https://github.com/grindsa/acme2certifier/issues/37)
- mscertsrv_ca_handler: CRLF to LF conversion
- [#35 rfc608  compliant contact checking](https://github.com/grindsa/acme2certifier/issues/35)
- xca_handler: [#38 - prevent error message leakage to client](https://github.com/grindsa/acme2certifier/issues/38)

## Changes in 0.9

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
- [#9 - base64-parsing of dns challenge](https://github.com/grindsa/acme2certifier/issues/9)
- openssl_handler: set correct x509 version
- openssl_handler: mandentory cert-extensions
- harmonization of apache config files
- migration support for docker_django deployment

## Changes in 0.8

**Features**:

- Challenge polling
- Support for CA polling and call-backs
- Certificate profiling in openssl handler
- Ssl support
- Container deployments
- Django project with mysql as backend database

## Changes in 0.7

**Features**:

- support ECC keys
- key update and key roll-over support
- generic CMPv2 handler

## Changes in 0.6

**Features**:

- EST and certsrv support

## Changes in 0.5

**Features**:

- CSR validation against order identifiers

## Changes in 0.4

**Features**:

- experimental TNAuthList identifier and tkauth-01 challenge support
- compatibility with Python3
