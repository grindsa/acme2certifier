<!-- markdownlint-disable  MD013 -->

# Acme2certifier changelog

This is a high-level summary of the most important changes. For a full list of
changes, see the [git commit log](https://github.com/grindsa/acme2certifier/commits)
and pick the appropriate release branch.

## Changes in 0.45

**New Features**:

- [Package-first layout](docs/upgrading.md) (`acme2certifier.*`) with pip, DEB, RPM, and Docker installs; Django app and project shipped in the package
- [Custom CA/EAB/Hooks loading](docs/ca_handler.md#custom-handlers-path-or-package) via `*_module` (dotted import or filesystem path); deprecated `*_file` keys still supported until 0.48
- [DB handler selection](docs/acme_srv.md) via `[DBhandler] handler` or `ACME_SRV_DB_HANDLER` environment variable
- [`a2c-wsgi2django`](docs/migrate_wsgi_to_django.md) CLI to migrate ACME runtime data from WSGI SQLite to Django ORM via a portable JSON dump (`export`, `import`, `check`, `wipe`)
- Digicert CA handler options `request_retries` and `request_retry_backoff` for HTTP transport retries
- [EAB profiling](docs/eab_profiling.md): skip ACME profile-name validation per account via `order.profiles_check_disable`

**RPM packaging (quick reference)** — install: [install_rpm.md](docs/install_rpm.md); upgrade: [upgrading.md](docs/upgrading.md#rpm-pre-045--045)

One **noarch** payload + one **Python flavor** metapackage (mutually exclusive). Default app Python is **3.9** on EL8 and EL9.

| Package | Role |
| --- | --- |
| `acme2certifier` | Application under `/opt/acme2certifier` (no `python*-*` Requires) |
| `acme2certifier-python39` | **EL8 default** — parallel Python 3.9 (`python39-*`, `uwsgi-plugin-python39`) |
| `acme2certifier-python3` | **EL9 default** (system 3.9) / **EL8 legacy** (system 3.6) |

Companions (cryptography, jwcrypto, …) come from AppStream/EPEL or [grindsa/sbom](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs) matching the flavor prefix.

**Bug Fixes and Improvements**:

- mscertsrv: scope `KRB5_CONFIG` during GSSAPI enrollment so SPNEGO can locate the KDC when a custom `krb5_config` is used (password `kinit` alone was insufficient)
- mscertsrv: fall back to in-process GSSAPI password auth when `kinit` is missing; Debian systemd unit `PATH` now includes `/usr/bin` so packaged `krb5-user` is visible to uwsgi
- Rename MS-WCCE CA handler to [MS-ICPR](docs/msicpr.md) (`msicpr_ca_handler`); `mswcce_ca_handler` remains a deprecated alias ([#358](https://github.com/grindsa/acme2certifier/issues/358))
- Parse boolean [EAB profiling](docs/eab_profiling.md) parameters (`True`/`False` strings) correctly
- Route CA handler HTTP calls through the shared `request_operation` helper (including retry support)
- Improve ASA CA handler parsing of error responses from the CA
- Improve OpenSSL CA handler handling of absolute certificate/key paths
- Security defaults hardening:
  - `/trigger` endpoint is disabled by default and requires both `[Trigger] enabled=True` and CA handler opt-in (`supports_trigger=True`)
  - Legacy unauthenticated GET on challenge/authorization resources is disabled by default (`legacy_acme_get=False`)
  - URL generation supports canonical host override via `[DEFAULT] server_name`; startup warnings are emitted when falling back to request headers and when `server_name` is not part of `Directory.caaidentities`
  - HTTP-01 can reject non-global/private targets via `http01_block_private_ips` (opt-in)
  - `nonce_check_disable` and `signature_check_disable` are ignored unless `ACME2CERTIFIER_I_KNOW_THE_RISK=1` is set
  - Django packaged settings refuse to start with the insecure default `SECRET_KEY`; warn when `ALLOWED_HOSTS` contains `*`
  - Certificate resource names use 15-character identifiers (full `Certificate.name` column width)
- Resolve relative `acme_srv.db` paths against the deploy base directory and clarify default DB location
- Stop shipping `acme_srv.cfg` inside DEB/RPM packages; preserve handler configuration across install/restart
- Adapt Docker entrypoints and install scripts to the package layout
- Log which config file and DB/CA handler are active at startup
- Operator [logging](docs/logging.md): optional syslog (`syslog_address`) and `log_file` destinations, ACME problem WARNING/ERROR lines with `account=`, HTTP edge dump redaction (nonce/tokens/cert PEM; `log_cert_content` restores legacy cert logging)

## Changes in 0.44

**Features and Improvements**:

- Option `ca_error_details_forward` allowing to pass error messages from CA to acme-client
- Align account deactivation responses with the relevant RFC requirements
- Harmonize the formatting of JSON responses across project
- Optional GSSAPI channel bindings (`gssapi_channel_bindings`) for mscertsrv EPA/CBT support

**Bug Fixes**:

- [#345 Add missing functions for nonce cleanup to django handler](https://github.com/grindsa/acme2certifier/issues/345)
- Align the dry‑run messages between the Certificate and Order classes
- Raise an exception when a database error occurs during Authorization creation
- Skip prevalidation when identifier value is missing in \_apply_prevalidation_whitelist()
- Cover JSON parsing errors in compare_jwk()

## Changes in 0.43.2

**Bug Fixes**:

- [#345 Missing function in django_handler.py](https://github.com/grindsa/acme2certifier/issues/345)

## Changes in 0.43.1

**Bug Fixes**:

- Correction of nginx configuration in Dockerimages

## Changes in 0.43

**Features and Improvements**:

- [EAB strict mode](docs/eab.md) to allow registration of EAB and non-EAB clients at the same a2c instance
- [Experimental support for dns-persist-01 challenges](docs/dns-persist-01.md)
- [Prevalidation](docs/identifier_prevalidation.md) of IP and Email identifiers
- [FreeIPA CA Handler](docs/freeipa.md)
- [Dogtag CA Handler](docs/dogtag_ca_handler.md)
- [Dryrun Mode](docs/dryrun.md)
- Option `wildcard_certificate_disable` to prevent the ernollment of wildcard certificates globally. Can be overridden via [eab-profiling](docs/eab_profiling.md)
- Kerberos keytab support in [msicpr_ca_handler.py](docs/msicpr.md#keytab-support) and [mscertserv_ca_handler.py](docs/mscertsrv.md#gssapi-keytab-mode)

**Bug Fixes**:

- [313](https://github.com/grindsa/acme2certifier/pull/313) - Replace lstrip in WSGI path lookup
- Restrict challenges for wildcard certificate requests to `dns-01` and `dns-persist-01`
- Improved wildcard matching as part of allowed_domain_list and domain_prevalidation checks
- Validation of submitted ACME-profile against EAB profile values will be done as part of order processing

## Changes in 0.42.1

**Bug Fixes**:

- Return a valid "Location" header for account queries

## Changes in 0.42

**Features and Improvements**:

- [Experimental support of MSSQl](https://github.com/grindsa/acme2certifier/blob/devel/docs/external_database_support.md#when-using-sql-server) via django-handler
- [EAB SQL Handler](https://github.com/grindsa/acme2certifier/blob/devel/docs/eab.md#sql-handler)
- run allowed_domainlist check as part of order processing
- Refactoring of Core components completed

## Changes in 0.41.3

**Bug Fixes**:

- [#307 - cert_operations_log option is not taken into account when logging certificate issuance](https://github.com/grindsa/acme2certifier/issues/306)

## Changes in 0.41.2

**Bug Fixes**:

- [#304 - correct parsing of config files with without Challenge section](https://github.com/grindsa/acme2certifier/issues/304)
- [#302 - fix when loading allowed_domain_list parameter from config](https://github.com/grindsa/acme2certifier/issues/302)\]

## Changes in 0.41.1

**Bug Fixes**:

- [#299 Improved cert_passphrase_variable handling in EJBCA handler](https://github.com/grindsa/acme2certifier/issues/299)

## Changes in 0.41

- The database schema has been updated. Please ensure you run the appropriate update script after upgrading:
  - Use `tools/db_update.py` if you are using the `wsgi_handler`
  - Use `tools/django_update.py` if you are using the `django_handler`

**Features and Improvements**:

- [**Asynchronous Mode**](docs/async_mode.md)
- **EAB Profiling**:
  - Support of [domain prevalidation](docs/identifier_prevalidation.md)
  - challenge_validation_disable, forward_address_check and reverse_address_check parameters can be configured via[EAB-Profiling feature](docs/eab_profiling.md)
  - eab_pofiling to be enabled in the `[EABhandler]` section of `acme_srv.cfg`
- **Challenge Error Reporting**: Challange validation error status will be reported to ACME-client
- **ACME CA Handla**:
  - Option to enable periodic synchronization of profiles information from ACME server to be shown as meta-information in Directory ressource
  - Option to configure renewalinfo endpoint lookup on ACME server to obtain renewal window
  - Support pre-authorization of domain-names as done by [harica.gr](https://harica.gr)

## Changes in 0.40.1

**Bug Fixes**:

- [#281 - CAhandler' object has no attribute 'profiles'](https://github.com/grindsa/acme2certifier/issues/281)

## Changes in 0.40

**Features and Improvements**:

- **CA Handler**: A CA handler to support [Hashicorp Vault CA](https://developer.hashicorp.com/vault/tutorials/pki/pki-engine)
- **Order Processing**: [#269](https://github.com/grindsa/acme2certifier/issues/269) Added support of non-compliant order polling via finalize endpoint
- **EAB (External Account Binding)**: Improved comparison function between inner and outer JWK structures
- **EAB Profiling**: Added support for revocation operations
- **DNS Validation**: Added option for DNS reverse zone checking when challenge validation is disabled
- **Documentation**: Updated mscertsrv_handler documentation to clarify limitations when using GSSAPI authentication
- **Cryptography Support**: Added support for cryptography module versions > 44.0.0 in mscertsrv_handler.py
- **Error Messaging**: Enhanced error messages sent to clients when CN/SAN validation checks fail
- **RPM Packaging**: Minor improvements to RPM service files and RPM spec configuration

**Bug Fixes**:

- [#269](https://github.com/grindsa/acme2certifier/issues/269)
- Fixed LegacyKeyValueFormat warnings in Dockerfiles
- **EAB**: Refactored comparison function between inner and outer JWK structures for better reliability
- **Tools**: Fixed error handling in `tools/django_upgrade.py`
- **ACME CA Handler**: Improved JWK handling by stripping to minimum required fields

## Changes in 0.39.2

**Bug fixes**:

- [#269](https://github.com/grindsa/acme2certifier/issues/269) allow non-compliant order polling via finalize endpoint

## Changes in 0.39.1

**Bug fixes**:

- [#260](https://github.com/grindsa/acme2certifier/issues/260) improved method for eab key-comparison

## Changes in 0.39

**Upgrade notes**:‚

- The database schema has been updated. Please ensure you run the appropriate update script after upgrading:
  - Use `tools/db_update.py` if you are using the `wsgi_handler`
  - Use `tools/django_update.py` if you are using the `django_handler`

**Features and Improvements**:

- **RFC 8823 Support:**
  Added support for [RFC 8823](https://www.rfc-editor.org/rfc/rfc8823.html) — *Automatic Certificate Management Environment for End-User S/MIME Certificates*. This includes handling of `email` identifiers and the `email-reply-00` challenge type.
- **Source Address Check:**
  Introduced the `source_address_check` option, which can be used in combination with `challenge_validation_disable` to verify that the client IP address is registered for the FQDNs included in the order request.
- **DNS Challenge Support in acme_ca_handler:**
  Enhanced [acme_ca_handler.py](https://github.com/grindsa/acme2certifier/blob/devel/docs/acme_ca.md) to support DNS challenges.
- **Certificate Operations Logging:**
  Added the `cert_operations_log` option to enable logging of certificate issuance and revocation operations.

**Bugfixes**:

- Added documentation for the `contact_check_disable` option.
- Fixed broken links in the [OpenXPKI documentation](https://github.com/grindsa/acme2certifier/blob/master/docs/openxpki.md).
- Implemented various logging improvements for better traceability and troubleshooting.

## Changes in 0.38.1

**Bug fixes**:

- [#260](https://github.com/grindsa/acme2certifier/issues/260) improved method for eab key-comparison

## Changes in 0.38

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features and Improvements**:

- Support of [Automated Certificate Management Environment (ACME) Profiles Extension](https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/)
- [#227](https://github.com/grindsa/acme2certifier/issues/227) - Challenge validation can now be disabled using the [EAB profiling feature](docs/eab_profiling.md)
- [#226](https://github.com/grindsa/acme2certifier/issues/226) - A configuration option has been added to append the Common Name (CN) or the first Subject Alternative Name (SAN) to the eJBCA username.
- Added support for the [caaIdentities attribute](https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.1) in the directory object

**Bug fixes**:

- Addressed Bandit warnings related to potential SQL injection vulnerabilities
- Code formatting improved using [black](https://github.com/psf/black)
- Markdown linting performed using [mdformat](https://mdformat.readthedocs.io/en/stable/#)

## Changes in 0.37.1

**Bug fixes**:

- [#221](https://github.com/grindsa/acme2certifier/issues/221) - /directory redirection is broken if "url prefix" is configured

## Changes in 0.37

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features and Improvements**:

- **EAB Environments Only**:
  - Implemented a check to prevent certificate enrollment from ACME accounts without EAB credentials. This can be disabled by setting `eabkid_check_disable: True` in `acme_srv.cfg`.
  - Introduced the `invalid_eabkid_deactivate` option to deactivate ACME accounts lacking EAB credentials.
- [#213](https://github.com/grindsa/acme2certifier/issues/213) - Added support for multiple CA servers in `mscertsrv_handler`.
- Introduced the `allowed_domainlist` parameter to filter domain names permitted for enrollment.
- Developed a prototype `handler_check()` method in `XCA-handler` to reject requests when there is a handler misconfiguration.
- Added the ability to log enrollment configurations by setting the `enrollment_config_log` parameter.
- Reviewed and updated multiple documentation files.
- [#208](https://github.com/grindsa/acme2certifier/pull/209) - Updated OpenXPKI documentation with `authorized_signer` information.
- [#206](https://github.com/grindsa/acme2certifier/pull/206) - Improved OpenXPKI documentation for enhanced DN handling.
- [#200](https://github.com/grindsa/acme2certifier/issues/200) - Updated ACME Clients documentation.
- Disabled logging in Nginx and uWSGI containers.

**Bug Fixes**:

- [#210](https://github.com/grindsa/acme2certifier/issues/210) - Corrected redirection of the root endpoint to the appropriate directory.
- [#207](https://github.com/grindsa/acme2certifier/pull/207) - Fixed RPC calls in the OpenXPKI CA handler.
- Refactored allowed_domainlist_check() function to address a potential security issue
- Enhanced error handling in `xca-handler`.
- Disabled logging in Nginx and uWSGI containers.
- Improved logging in `message.py`.
- Resolved various linting issues.

## Changes in 0.36

**Features and Improvements**:

- refactored [NCLM ca handler](docs/nclm.md) using the external REST-API
- [ca handler](docs/digicert.md) using the [DigiCert CertCentral API](https://dev.digicert.com/en/certcentral-apis.html)
- [ca handler](docs/entrust.md) using the Entrust ECS Enterprise API
- [EAB Profiling support](docs/eab_profiling.md) in Microsoft CA handlers
- [#187](https://github.com/grindsa/acme2certifier/pull/187) url option for mscertsrv ca handler
- subject profiling feature
- [strip down python-impacket module](https://github.com/grindsa/acme2certifier/blob/master/docs/mswcce.md#local-installation) in docker images
- [strip down impacket RPM package](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs/rhel9)
- YAML config file format supported in [EAB-Profiling feature](docs/eab_profiling.md)
- Upgrade Container images to Ubuntu 24.04

**Bugfixes**:

- openssl-ca-handler: basicConstraints extension will not be marked as critical anymore
- openssl-ca-handler: subjectkeyidentifier extension will not be marked as critical anymore
- fall-back option to python-openssl for Redhat deployments
- detect and handle django installations on Debian/Ubuntu systems
- automated schema updates in case of RPM updates

## Changes in 0.35

**Features and Improvements**:

- [#153](https://github.com/grindsa/acme2certifier/issues/153) Kerberos support in [mscertsrv_handler](docs/mscertsrv.md)
- allowed_domainlist checking in [mswcce_handler](docs/mswcce.md)
- `timeout` parameter in [ms-wcce_handler](docs/mswcce.md) to specify an enrollment timeout
- new [tool to validate eab-files](docs/eab_profiling.md#profile-verification)
- [#165](https://github.com/grindsa/acme2certifier/issues/165) [EAB profiling](docs/eab_profiling.md#enrollment-profiling-via-external-account-binding) for ejbca_handler
- [#166](https://github.com/grindsa/acme2certifier/issues/166) [EAB profiling](docs/acme_ca.md#eab-profiling) for acme_ca_handler
- documentation for active/active setup on [Alma9](docs/a2c-alma-loadbalancing.md) and [Ubuntu 24.04](docs/a2c-ubuntu-loadbalancing.md)
- [#165](https://github.com/grindsa/acme2certifier/issues/165) documentation of [external database support](docs/external_database_support.md) via django_handler

**Bugfixes**:

- `acme_srv.cfg` will be preserved in case of RPM updates
- apache2_wsgi docker image will be tagged with `latest`
- [#166](https://github.com/grindsa/acme2certifier/issues/166) workaround for failed account lookups on smallstep-ca

## Changes in 0.34

**Features and Improvements**:

- [Enrollment profiling via external account binding](docs/eab_profiling.md)
- [#144](https://github.com/grindsa/acme2certifier/issues/144) configuration option to suppress product name
- [#143](https://github.com/grindsa/acme2certifier/issues/143) template name as part of the user-agent field in wcce/wes handler
- configuration option to limit the number of identifiers in a single order request
- `burst` parameter in example nginx.conf to ratelimit incoming requests
- [container images for arm64 platforms](https://hub.docker.com/layers/grindsa/acme2certifier/apache2-wsgi/images/sha256-9092e98ad23fa94dfb17534333a9306ec447b274c2e4b5bbaee0b8bc41c6becc?context=repo)
- regression tests on arm64 platforms

**Bugfixes**:

- [#147](https://github.com/grindsa/acme2certifier/pull/147) correct content-type for problem+json message
- updated [eab-example files](https://github.com/grindsa/acme2certifier/tree/master/acme2certifier/share/skeletons/eab_handler) as hmac must be longer than 256bits
- identifier sanitizing

## Changes in 0.33.3

**Features and Improvements**:

- some smaller modifications run flawless on Redhat8 and derivates
- Workflows to test rpm-deployment on RHEL8 and RHEL9

## Changes in 0.33.2

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Bugfixes**:

- [134](https://github.com/grindsa/acme2certifier/issues/134) - acme_srv_housekeeping" -> value too long for "name" field
- [135](https://github.com/grindsa/acme2certifier/issues/134) - acme_srv_housekeeping dbversion ist set back to 0.23.1 after container restart

## Changes in 0.33.1

**Bugfixes**:

- [132](https://github.com/grindsa/acme2certifier/issues/132) - returning serial numbers in hex-format with leading zero

## Changes in 0.33

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features and Improvements**:

- Support [draft-ietf-acme-ari-02](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/02): Renewal Information (ARI) Extension
- First version of [Insta ASA CA handler](docs/asa.md)
- [winacme renewal-info workaround](https://github.com/grindsa/acme2certifier/issues/127)
- better logging to ease troubleshootnig of eab
- code refactoring to improve [f-string handling](https://pylint.pycqa.org/en/latest/user_guide/messages/convention/consider-using-f-string.html)

## Changes in 0.32

**Features and Improvements**:

- [#114](https://github.com/grindsa/acme2certifier/issues/114) `cert_validity_adjust` parameter in openssl_ca_handler.py to limit certificate validity so that a certificate is never valid longer than any ca certificate in the certificate chain

## Changes in 0.31

**Features and Improvements**:

- refactor `opennssl_ca_handler.py` and `xca_ca_handler.py` to replace pyopenssl
- type hints for large parts of the project

## Changes in 0.30

**Upgrade notes**:

- database scheme gets updated. Please run either

  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

  **Features and Improvements**:

  - [use http-header attributes to pass data from acme-client to ca-handler](https://github.com/grindsa/acme2certifier/blob/devel/docs/header_info.md)
  - ProfileID support in `certifier_ca_handler.py`
  - [Kerberos support](https://github.com/grindsa/acme2certifier/issues/119#issuecomment-1763851071) in `mswcce_ca_handler.py`
  - [#122](https://github.com/grindsa/acme2certifier/issues/122) support of `sectigo-email-01` challenges

## Changes in 0.29.2

**Bugfixes**:

- #119 - handling of utf-8 encoded parameters in `acme_srv.cfg`
- adding `python3-requests-ntlm` dependency in control file for debian packages
- multiple smaller fixes in workflow files

## Changes to 0.29.1

- withdrawn as released by mistake

## Changes in 0.29

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features and Improvements**:

- Support [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738.html): Certificates for IP addresses
- Support [draft-ietf-acme-ari-01](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/01): Renewal Information (ARI) Extension
- Interoperability testing with [Caddy](https://caddyserver.com/docs/automatic-https) as part of regular regression

## Changes in 0.28

**Features and Improvements**:

- input validation in django deployments
- return account status when querying the account endpoint or sending a request to `new-account` with empty payload
- merge codescanning workflows into a single file

**Bugfixes**:

- [#111](https://github.com/grindsa/acme2certifier/issues/111) - Nonce handling in error responses
- [#112](https://github.com/grindsa/acme2certifier/issues/112) - Keyrollover in Posh-ACME

## Changes in 0.27

**Features and Improvements**:

- interoperability testing with [traefik](https://traefik.io/)
- refactor revocation function in openxpki_ca_handler to support revocation operation in certbot
- support pkcs7 loading in der format
- obsolete pyopenssl in various helper functions, est_ca_handler and mscertserv_ca_handler

**Bugfixes**:

- sending alpn-extension in ClientHello message during tls-alpn-01 challenge validation
- removed misleading debug messages in `openxpki_ca_handler.py`
- support existing acme-accounts in `acme_ca_hander.py`
- address codesmells in dockerfiles

## Changes in 0.26

**Features and Improvements**:

- support ClientAuthentication in `openxpki_ca_handler.py` and `est_ca_handler.py` by using pkcs12 files
- provide pkcs12 passphrases for `ejbca_ca_handler.py`, `openxpki_ca_handler.py` and `est_ca_handler.py` as environment variables

**Bugfixes**:

- conffile support in debian package to avoid overriding configuration files

## Changes in 0.25.1

**Bugfixes**:

- replace obsoleted `dns.resolver.query()` with `dns.resolver.resolve()`

## Changes in 0.25

**Features and Improvements**:

- CA handler for [EJBCA](https://www.ejbca.org/)
- CA handler for [OpenXPKI](https://www.openxpki.org/)

**Bugfixes**:

- adding missing python modules to RPM spec file
- add revocation operations to CA handler regression test suite

## Changes in 0.24

**Features and Improvements**:

- reduce number of layers in docker images
- Workflows are using checkout@v3 actions
- default nginx ssl config file in rpm package corrected
- delete seclinux configuration files after rpm installation
- delete obsolete files from repo
- rpm package tests during regression
- [sbom generation](https://github.com/grindsa/sbom/tree/main/sbom/acme2certifier) as part of [docker image create worflow](.github/workflows/main-create-release-push-images-to-dockerhub.yml)
- rpm and deb package generatation as part of [create release workflow](.github/workflows/main-create-release-push-images-to-dockerhub.yml)
- nginx django test workflows

## Changes in 0.23.2

**Features and Improvements**:

- [rpm](docs/install_rpm.md) and [deb](docs/install_deb.md) packages

## Changes in 0.23.1

**Bugfixes**:

- [#99 - Authorization.value max_length too short for SAN entries](https://github.com/grindsa/acme2certifier/issues/99)

## Changes in 0.23

**Features and Improvements**:

- Healthcheck in directory ressource [#94](https://github.com/grindsa/acme2certifier/issues/94)
- check `acme_srv.cfg` for options starting with "

**Bugfixes**:

- [#95](https://github.com/grindsa/acme2certifier/issues/95)
- workflow django psql workflow
- some more linting

## Changes in 0.22

**Features and Improvements**:

- containers got migrated to Ubuntu 22.04
- nclm handler supporting NCLM 22 and above

**Bugfixes**:

- [pycodestyle 2.9.1](https://pycodestyle.pycqa.org/en/2.9.1/intro.html) linting
- time adjustment in CMPv2 workflow to avoid race condition related timeouts
- link updates in [README.md](README.md)
- attribute type in error responses [#92](https://github.com/grindsa/acme2certifier/issues/92)

## Changes in 0.21

**Features and Improvements**:

- support of enrollment [hooks](docs/hooks.md)
- `challenge_validation_timeout` parameter in [acme_srv.cfg](docs/acme_srv.md)
- cmpv2_ca_handler using the inbuilt cmp feature from openssl 3.0
- Github action to test certificate enrollment using CMPv2 protocol
- Github action to test certificate enrollment from [NetGuard Certificate Lifecycle Manager](docs/nclm.md)

**Bugfixes**:

- RFC compliant content-type in error responses

## Changes in 0.20

**Features and Improvements**:

- [CA handler](docs/mswcce.md) using Microsoft Windows Client Certificate Enrollment Protocol
- asynchronous enrollment workflow using threading module
- option to re-use certificates enrolled within a certain time window
- workflow using [Posh-ACME](https://github.com/rmbolger/Posh-ACME)

**Bugfixes**:

- return challenge status when creating/polling Authorization resources
- remove duplicated certificate extension in openssl_ca_handler.py
- change challenge status to 'invalid' in case enrollment fails

## Changes in 0.19.3

**Features and Improvements**:

- disable TLSv1.0 and TLSv1.1 fallback when conduction TLS-ALP=1 challenge validation
- python3-cryptography will be installed via pip to fulfill dependencies from pyOpenssl
- Changed encoding detection library from chardet to charset_normalizer
- [lgtm](https://lgtm.com/projects/g/grindsa/acme2certifier/context:python) conformance

## Changes in 0.19.2

**Features and Improvements**:

- support for django 3.x
- workflow for application testing using win-acme
- additional linting and pep8 conformance checks

## Changes in 0.19.1

**Features and Improvements**:

- pep8 conformance
- time adjustments in certmanager and django workflows
- addressing code-scanning alerts from bandit and CodeQL

## Changes in 0.19

**Bugfixes**:

- [Authorization polling does not trigger challenge validation anymore](https://github.com/grindsa/acme2certifier/issues/76)
- Overcome database locking situations in django environments using sqlite3 backends

**Features and Improvements**:

- [RFC compliant Wildcard handling](https://github.com/grindsa/acme2certifier/issues/76)

## Changes in 0.18.2

**Bugfixes**:

- [Fix the disabling of SSL validation in http-01 challenge](https://github.com/grindsa/acme2certifier/pull/75)

## Changes in 0.18.1

**Features and Improvements**:

- absolute path support for CA- and EABhandler

**Bugfixes**:

- fixed race condition in push_to_docker workflow

## Changes in 0.18

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features and Improvements**:

- [proxy support](docs/proxy_support.md) for http and tls-alpn challenge validation and in several ca-handlers
- [acme_ca_handler](docs/acme_ca.md)
  - support for account registration and http_challenge validation
- [openssl_ca_handler](docs/openssl.md):
  - `cn_enforce` parameter to enforce setting a common name in certificate
  - `whitelist` parameter got renamed to `allowed_domainlist`
  - `blocklist` parameter got renamed to `blocked_domainlist`
- [xca_ca_handler](docs/xca.md):
  - `cn_enforce` parameter to enforce setting a common name in certificate

## Changes in 0.17.1

**Bugfixes**:

- python request module - version pinning to 2.25.1

## Changes in 0.17

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django_handler

**Features**:

- [Generic ACME protocol handler](docs/acme_ca.md)
- CA handler for [acme2dfn](https://github.com/pfisterer/acme2dfn)
- wsgi_db_handler: allow DB file path configuration
- allow setting config file location via environment variable

**Improvements**:

- `acme` module has been renamed to `acme_srv` to avoid naming clashes with [acme-python](https://acme-python.readthedocs.io/en/stable/)
- allow GET method for newnonce
- don't verify SSL certificate during http-01 challenge validation

## Changes in 0.16

**Features**:

- CA-Handler configuration via environment variables:
  - cmp_ca_handler: ref-num and passphrase
  - certifier_ca_handler: api_user, api_password
  - est_ca_handler: est_host, est_user, est_password
  - mscertsrv_ca_handler: host, user, password
  - nclm_ca_handler: api_user, api_password
  - openssl_ca_handler: passphrase
  - xca_ca_handler: passphrase

**Bugfixes**:

- don't overwrite group ownership for volume folder
- don't copy ca_handler file if a valid ca_handler was defined under `CAhandler` section in acme_srv.cfg
- django migrations files will get stored on volume
- avoidance of KU/EKU duplicates when using templates in xca_ca_handler
- alpn challenge handling in django deployments
- fix for handling of empty challenges
- more robust DNS challenge validation

**Other improvements**:

- [CodeCoverage measurement](https://app.codecov.io/gh/grindsa/acme2certifier/) via codecov.io
- Switch to [acme.sh:latest](https://hub.docker.com/r/neilpang/acme.sh) in CI pipeline
- Regression test-cases for django deployments using either mariadb or postgres backends
- experimental CLI framework (not yet useable)

## Changes in 0.15.3

**Upgrade notes**:

- database scheme gets updated. Please run either
  - `tools/db_update.py` when using the wsgi_handler or
  - `tools/django_update.py` in case you are using the django.handler

**Bugfixes**:

- fix for `type` field length in `Challenge` table

## Changes in 0.15.2

**Bugfixes**:

- additional fixes for dns-01 challenge validation (handling for \*.foo.bar and foo.bar in the same csr)

## Changes in 0.15.1

**Bugfixes**:

- fixes for dns-01 challenge validation
- default ku settings when using xca templates

## Changes in 0.15

**Upgrade notes**:

- You need to run the upgrade-script after updating the package

**Features**:

- support for [tls-alpn-01](https://tools.ietf.org/html/rfc8737) challenges
- eab kid logging and reporting

**Bugfixes**:

- database scheme versioning

## Changes in 0.14

**Upgrade notes**:

- You need to run the upgrade-script after updating the package

**Features**:

- support for [External Account Binding](docs/eab.md)

**Bugfixes**:

- `acme2certifier_wsgi.py`- newaccount() - initialize `Account()` class as context handler

## Changes in 0.13.1

**Upgrade notes**:

- You need to run the upgrade-script after updating the package

**Bugfixes**:

- `helper.py`- fqdn_resolve() - resolve AAAA records
- `helper.py`- url_gete() - ipv4 fallback during http challenge validation

## Changes in 0.13

**Features**:

- template support in `xca_handler.py` and `nclm_ca_handler.py`
- docker images at [ghcr.io](https://github.com/grindsa?tab=packages)

**Bugfixes/Improvements**:

- refactor `nclm_ca_handler.py`
- refactor `certifier_ca_handler.py`
- workflows for
  - code-scanning (CodeQL and Bandit)
  - ca_handler tests
  - phonito security scans

## Changes in 0.12.1

**Upgrade notes**:

- You need to run the upgrade-script after updating the package

**Bugfixes**:

- `helper.py`- fqdn_resolve() - resolve AAAA records

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
- unit-tests are split into separate files
- unittests for `certifier_ca_handler.py`
- documentation updates
- Github actions to test
  - certificate enrollment for all four containerized deployment options
  - tnauth functionality
  - image creation and dockerhub upload

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

**Bugfixes**\*:

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
- openssl_handler: mandatory cert-extensions
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
