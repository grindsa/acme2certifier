<!-- markdownlint-disable MD013 -->

# acme2certifier

![GitHub release](https://img.shields.io/github/release/grindsa/acme2certifier.svg)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/master.svg?label=last%20commit%20into%20min)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/devel.svg?label=last%20commit%20into%20min-devel)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2581/badge)](https://bestpractices.coreinfrastructure.org/projects/2581)

[![Codecov main](https://img.shields.io/codecov/c/github/grindsa/acme2certifier/master?label=test%20coverage%20master)](https://app.codecov.io/gh/grindsa/acme2certifier/tree/master)
[![Codecov devel](https://img.shields.io/codecov/c/github/grindsa/acme2certifier/devel?label=test%20coverage%20devel)](https://app.codecov.io/gh/grindsa/acme2certifier/tree/devel)

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=security_rating)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=grindsa_acme2certifier&branch=min)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=alert_status)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)

**acme2certifier** is a development project aimed at creating an **ACME protocol proxy**. Its primary goal is to enable **ACME services** for **CA servers** that do not natively support this protocol.

The project consists of two main libraries:

- **`acme_srv/*.py`** – Implements ACME server functionality based on [RFC 8555](https://tools.ietf.org/html/rfc8555).
- **`ca_handler.py`** – Provides an **interface to CA servers**, designed to be modular for easy adaptation to various CA systems.
  The currently available handlers are listed below:

## Supported CA Handlers

| Feature Support                                                                                                                                | Enrollment (E) | Revocation (R) | [EAB Profiling (P)](docs/eab_profiling.md) |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | -------------- | ------------------------------------------ |
| [DigiCert® CertCentral](docs/digicert.md)                                                                                                      | ✅             | ✅             | ✅                                         |
| [Entrust ECS Enterprise](docs/entrust.md)                                                                                                      | ✅             | ✅             | ✅                                         |
| [EJBCA](docs/ejbca.md)                                                                                                                         | ✅             | ✅             | ✅                                         |
| [Generic ACME Handler](docs/acme_ca.md) (LetsEncrypt, BuyPass.com, ZeroSSL)                                                                    | ❌             | ❌             | ✅                                         |
| [Generic CMPv2 Handler](docs/cmp.md)                                                                                                           | ✅             | ❌             | ❌                                         |
| [Generic EST Handler](docs/est.md)                                                                                                             | ✅             | ❌             | ❌                                         |
| [Hashicorp Vault](docs/vault.md)                                                                                                               | ✅             | ✅             | ✅                                         |
| [Insta ActiveCMS](docs/asa.md)                                                                                                                 | ✅             | ✅             | ✅                                         |
| [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)                                                                             | ✅             | ❌             | ✅                                         |
| [Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)](docs/mswcce.md)                                                           | ✅             | ❌             | ✅                                         |
| [NetGuard Certificate Lifecycle Manager](docs/nclm.md)                                                                                         | ✅             | ✅             | ✅                                         |
| [NetGuard Certificate Manager/Insta Certifier](docs/certifier.md)                                                                              | ✅             | ✅             | ✅                                         |
| [OpenSSL](docs/openssl.md)                                                                                                                     | ✅             | ✅             | ❌                                         |
| [OpenXPKI](docs/openxpki.md)                                                                                                                   | ✅             | ✅             | ✅                                         |
| [XCA](docs/xca.md)                                                                                                                             | ✅             | ✅             | ✅                                         |

For the latest updates and additional documentation, visit the project's homepage:
[**acme2certifier on GitHub**](https://github.com/grindsa/acme2certifier)

______________________________________________________________________

## 📌 ChangeLog

Release notes and changelogs are available at:
[**GitHub Releases**](https://github.com/grindsa/acme2certifier/releases)

______________________________________________________________________

## 🛠 ACME Client Compatibility

The following ACME clients are **regularly tested** for compatibility:

- [acme.sh](https://github.com/Neilpang/acme.sh)
- [acmeshell](https://github.com/cpu/acmeshell/)
- [Caddy](https://caddyserver.com/docs/automatic-https)
- [Certbot](https://certbot.eff.org/)
- [cert-manager](docs/cert-mgr.md)
- [dehydrated](https://www.rfc-editor.org/rfc/rfc8823.html#name-use-of-acme-for-issuing-end)
- [lego](https://github.com/go-acme/lego)
- [traefik](https://traefik.io/)
- [Posh-ACME](https://github.com/rmbolger/Posh-ACME)
- [win-acme](https://www.win-acme.com/)

Other clients are **on the list for future testing**.
If you test additional ACME clients, feel free to raise an [issue](https://github.com/grindsa/acme2certifier/issues/new) if something does not work as expected.

[List of command-line parameters used for testing](docs/rfc8823_email_identifier.md)

______________________________________________________________________

## 🚀 Features

- **ACME v2 [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html) compliant** server implementation, including:
  - [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737.html) – **TLS ALPN-01 Challenge**
  - [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738.html) – **IP Address Certificates**
  - [RFC 8823](https://www.rfc-editor.org/rfc/rfc8823.html) - **Automatic Certificate Management Environment for End-User S/MIME Certificates**
  - [RFC 9773](https://datatracker.ietf.org/doc/rfc9773/) - **ACME Renewal Information (ARI) Extension**
  - [ACME Profiles Extension](docs/acme_profiling.md)
  - **TNAuthList identifiers** ([TNAuthList Profile](docs/tnauthlist.md))
  - [RFC 9447 - Automated Certificate Management Environment (ACME) Challenges Using an Authority Token](https://www.rfc-editor.org/rfc/rfc9447)
  - [Certificate Polling](docs/poll.md) and [Callbacks](docs/trigger.md) for CA servers.

Supported challenge types:

- [http-01](https://tools.ietf.org/html/rfc8555#section-8.3)
- [dns-01](https://tools.ietf.org/html/rfc8555#section-8.4)
- [email-reply-00](https://www.rfc-editor.org/rfc/rfc8823.html#name-use-of-acme-for-issuing-end)
- [tls-alpn-01](https://tools.ietf.org/html/rfc8737)
- [tkauth-01](https://www.rfc-editor.org/rfc/rfc9447)

______________________________________________________________________

## 📦 Installation

**acme2certifier** can be installed as:

- **WSGI application** (Apache2/Nginx)
- **Django project** (allows using alternative databases)

The fastest and most convenient way to install acme2certifier is to use docker containers. There are ready made images available at [dockerhub](https://hub.docker.com/r/grindsa/acme2certifier) and [ghcr.io](https://github.com/grindsa?tab=packages&ecosystem=container) as well as [instructions to build your own container](examples/Docker/).
In addition rpm packages for AlmaLinux/CentOS Stream/Redhat EL 9 and deb packages for Ubuntu 22.04 will be provided with every release.

Installation guides:

- [RPM Installation (AlmaLinux 9)](docs/install_rpm.md)
- [DEB Installation (Ubuntu 22.04)](docs/install_deb.md)
- [Docker Build Instructions](examples/Docker/)
- [Apache2 WSGI Setup (Ubuntu 22.04)](docs/install_apache2_wsgi.md)
- [Nginx WSGI Setup (Ubuntu 22.04)](docs/install_nginx_wsgi_ub22.md)

## Software Bill Of Material

[SBOMs](https://www.linuxfoundation.org/blog/blog/what-is-an-sbom) for all containers will be automatically created during build process and stored in [my SBOM repository](https://github.com/grindsa/sbom/tree/main/sbom/acme2certifier)

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests. Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details
