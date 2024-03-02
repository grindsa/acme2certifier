<!-- markdownlint-disable  MD013 -->
# acme2certifier

![GitHub release](https://img.shields.io/github/release/grindsa/acme2certifier.svg)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/master.svg?label=last%20commit%20into%20min)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/devel.svg?label=last%20commit%20into%20min-devel)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2581/badge)](https://bestpractices.coreinfrastructure.org/projects/2581)

[![Codecov main](https://img.shields.io/codecov/c/gh/grindsa/acme2certifier/branch/master?label=test%20coverage%20min)](https://app.codecov.io/gh/grindsa/acme2certifier/tree/min)
[![Codecov devel](https://img.shields.io/codecov/c/gh/grindsa/acme2certifier/branch/devel?label=test%20coverage%20min-devel)](https://app.codecov.io/gh/grindsa/acme2certifier/tree/min-devel)

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=security_rating)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=grindsa_acme2certifier&branch=min)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=grindsa_acme2certifier&metric=alert_status)](https://sonarcloud.io/summary/overall?id=grindsa_acme2certifier&branch=min)

acme2certifier is development project to create an ACME protocol proxy. Main intention is to provide ACME services on CA servers which do not support this protocol yet. It consists of two libraries:

- acme_srv/*.py - a bunch of classes implementing ACME server functionality based
on [rfc8555](https://tools.ietf.org/html/rfc8555)
- ca_handler.py - interface towards CA server. The intention of this library
is to be modular that an [adaption to other CA servers](docs/ca_handler.md)
should be straight forward. As of today the following handlers are available:
  - [NetGuard Certificate Manager/Insta Certifier](docs/certifier.md)
  - [NetGuard Certificate Lifecycle Manager](docs/nclm.md)
  - [Insta ActiveCMS](docs/asa.md)
  - [EJBCA](docs/ejbca.md)
  - [OpenXPKI](docs/openxpki.md)
  - [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)
  - [Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) via RPC/DCOM](docs/mswcce.md)
  - [Generic ACME protocol handler supporting Letsencrypt, BuyPass.com and ZeroSSL](docs/acme_ca.md)
  - [Generic EST protocol handler](docs/est.md)
  - [Generic CMPv2 protocol handler](docs/cmp.md)
  - [Openssl](docs/openssl.md)
  - [XCA](docs/xca.md)
  - [acme2dfn](https://github.com/pfisterer/acme2dfn) (external; ACME proxy for the [German research network's PKI](https://www.pki.dfn.de/ueberblick-dfn-pki/)

For more up-to-date information and further documentation, please visit the project's home page at: [https://github.com/grindsa/acme2certifier](https://github.com/grindsa/acme2certifier)

## ChangeLog

Release notes and ChangLog can be found at [https://github.com/grindsa/acme2certifier/releases](https://github.com/grindsa/acme2certifier/releases)

## Disclaimer

Following acme-clients are used for regular testing of server functionality

- [acme.sh](https://github.com/Neilpang/acme.sh)
- [acmeshell](https://github.com/cpu/acmeshell/)
- [Caddy](https://caddyserver.com/docs/automatic-https)
- [Certbot](https://certbot.eff.org/)
- [cert-manager](docs/cert-mgr.md)
- [lego](https://github.com/go-acme/lego)
- [traefik](https://traefik.io/)
- [Posh-ACME](https://github.com/rmbolger/Posh-ACME)
- [win-acme](https://www.win-acme.com/)

Other clients are on my list for later testing. In case you are bored, feel free to test other ACME clients and raise [issues](https://github.com/grindsa/acme2certifier/issues/new) if something does not work as expected.

[Command-line parameters used for testing](docs/acme-clients.md)

I am not a professional developer. Keep this in mind while laughing about my code and don’t forget to send patches.

## Features

- ACME v2 [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html) compliant server implementation including
  - Support [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737.html): TLS Application‑Layer Protocol Negotiation (ALPN) Challenge Extension
  - Support [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738.html): Certificates for IP addresses
  - Support [draft-ietf-acme-ari-02](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/02/) and [draft-ietf-acme-ari-01](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/01/): Renewal Information (ARI) Extension
  - Support [TNAuthList identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-tnauthlist-13): [TNAuthList profile](docs/tnauthlist.md) of ACME Authority Token
  - Support [tkauth-01](https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-09) ACME Challenges Using an Authority Token
  - [Certificate polling](docs/poll.md) and [Call backs](docs/trigger.md) from CA servers. These calls are not standardized but important to use acme2certifier together with classical enterprise CA

Following challenge types are supported:

- [http-01](https://tools.ietf.org/html/rfc8555#section-8.3)
- [dns-01](https://tools.ietf.org/html/rfc8555#section-8.4)
- [tls-alpn-01](https://tools.ietf.org/html/rfc8737)
- [tkauth-01](https://tools.ietf.org/html/draft-ietf-acme-authority-token-05)

Additional functionality will be added over time. If you are badly missing a certain feature please raise an [issue](https://github.com/grindsa/acme2certifier/issues/new) to let me know.

## Installation

The proxy can run either as plain wsgi-script on either apache or nginx or as django project. Running acme2certifier as django project allows to use other database backends than SQLite.

The fastest and most convenient way to install acme2certifier is to use docker containers.  There are ready made images available at [dockerhub](https://hub.docker.com/r/grindsa/acme2certifier) and [ghcr.io](https://github.com/grindsa?tab=packages&ecosystem=container) as well as [instructions to build your own container](examples/Docker/). In addition rpm packages for AlmaLinux/CentOS Stream/Redhat EL 9 and deb packages for Ubuntu 22.04 will be provided with every release.

- [acme2certifier in Github container repository](https://github.com/grindsa?tab=packages&ecosystem=container)
- [acme2certifier repository at hub.docker.com](https://hub.docker.com/r/grindsa/acme2certifier)
- [rpm package installation on Alma Linux 9](docs/install_rpm.md)
- [deb package installation Ubuntu 22.04](docs/install_deb.md)
- [Instructions to build your own container](examples/Docker/)
- [Installation as wsgi-script running on apache2 (Ubuntu 22.04)](docs/install_apache2_wsgi.md)
- [Installation as wsgi-script running on NGINX (Ubuntu 22.04)](docs/install_nginx_wsgi_ub22.md)
- [Installation as wsgi-script running on NGINX (Alma Linux 9)](docs/install_nginx_wsgi.md)

## Software Bill Of Material

 [SBOMs](https://www.linuxfoundation.org/blog/blog/what-is-an-sbom) for all containers will be automatically created during build process and stored in [my SBOM repository](https://github.com/grindsa/sbom/tree/main/sbom/acme2certifier)

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests. Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details
