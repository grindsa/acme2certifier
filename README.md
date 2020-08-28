# acme2certifier

![GitHub release](https://img.shields.io/github/release/grindsa/acme2certifier.svg)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/master.svg?label=last%20commit%20into%20master)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/devel.svg?label=last%20commit%20into%20devel)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2581/badge)](https://bestpractices.coreinfrastructure.org/projects/2581)

acme2certifier is development project to create an ACME protocol proxy. Main
intention is to provide ACME services on CA servers which do not support this
protocol yet. It consists of two libraries:

- acme/*.py - a bunch of classes implementing ACME server functionality based
on [rfc8555](https://tools.ietf.org/html/rfc8555)
- ca_handler.py - interface towards CA server. The intention of this library
is to be modular that an [adaption to other CA servers](docs/ca_handler.md)
should be straight forward. As of today the following handlers are available:
  - [Openssl](docs/openssl.md)
  - [NetGuard Certificate Manager/Insta certifier](docs/certifier.md)
  - [NetGuard Certificate Lifecycle Manager](docs/nclm.md)
  - [Generic EST protocol handler](docs/est.md)
  - [Generic CMPv2 protocol handler](docs/cmp.md)
  - [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)
  - [XCA](docs/xca.md)

For more up-to-date information and further documentation, please visit the
project's home page at: [https://github.com/grindsa/acme2certifier](https://github.com/grindsa/acme2certifier)

## ChangeLog

Releasenotes and ChangLog can be found at [https://github.com/grindsa/acme2certifier/releases](https://github.com/grindsa/acme2certifier/releases)

## Disclaimer

I am running this project as my RnD guys told me that it won’t be possible :-)

Following acme-clients are used for regular testing of server functionality

- [acme.sh](https://github.com/Neilpang/acme.sh)
- [Certbot](https://certbot.eff.org/)
- [lego](https://github.com/go-acme/lego)
- [acmeshell](https://github.com/cpu/acmeshell/)
- [cert-manager](docs/cert-mgr.md)
- [win-acme](https://www.win-acme.com/)

Other clients are on my list for later testing. In case you are bored, feel
free to test other came ACME clients and raise [issues](https://github.com/grindsa/acme2certifier/issues/new)
if something does not work as expected.

[Command-line parameters used for testing](docs/acme-clients.md)

I am not a professional developer. Keep this in mind while laughing about my
code and don’t forget to send patches.

## Project status

As of today acme2certifier supports the below ACME functions only:

- "directory" resource [(Section 7.1.1)](https://tools.ietf.org/html/rfc8555#section-7.1.1)
- "newNonce" resource  [(Section 7.2)](https://tools.ietf.org/html/rfc8555#section-7.2)
- "newAccount" resource [(Section 7.3)](https://tools.ietf.org/html/rfc8555#section-7.3)
  - Finding an Account URL Given a Key [(Section 7.3.1)](https://tools.ietf.org/html/rfc8555#section-7.3.1)
  - Account update [(Section 7.3.2)](https://tools.ietf.org/html/rfc8555#section-7.3.2)
  - Key Rollover [(Section 7.3.5)](https://tools.ietf.org/html/rfc8555#section-7.3.5)
  - Account Deactivation [(Section 7.3.6)](https://tools.ietf.org/html/rfc8555#section-7.3.6)
- "new-order" resource [(Section 7.4)](https://tools.ietf.org/html/rfc8555#section-7.4)
- "order finalization" [(Section 7.4)](https://tools.ietf.org/html/rfc8555#section-7.4)
- "certificate download" [(Section 7.4.2)](https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.4.2)
- "authz" resource [(Section 7.5)](https://tools.ietf.org/html/rfc8555#section-7.5)
- "challenge" resource [(Section 7.5.1)](https://tools.ietf.org/html/rfc8555#section-7.5.1)
- "certificate revocation" [(Section 7.6)](https://tools.ietf.org/html/rfc8555#section-7.6)

Starting from version 0.4 acme2certifer includes experimental support for
[TNAuthList identifiers](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03)
and [tkauth-01](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03) challenges.
Check [tnauthlist.md](docs/tnauthlist.md) for further information.

Starting from version 0.8 acme2certifier supports [certificate polling](docs/poll.md)
and [call backs](docs/trigger.md) from CA servers. These calls are not standardized
but important to use acme2certifier together with classical enterprise CA
servers,

Additional functionality will be added over time. If you are badly missing a
certain feature please raise an [issue](https://github.com/grindsa/acme2certifier/issues/new)
to let me know.

## Installation

The proxy can run either as plain wsgi-script on either apache or ngix or as
django project. Running acme2certifier as django project allows to use other
database backendes than SQLite.

The fastest and most convenient way to install acme2certifier is to use docker
containers.  There are ready made images available at [dockerhub](https://hub.docker.com/r/grindsa/acme2certifier)
as well as [instructions to build your own container](examples/Docker/).

- [acme2certifier repository at hub.docker.com](https://hub.docker.com/r/grindsa/acme2certifier)
- [Instructions to build your own container](examples/Docker/)
- [Installation as wsgi-script running on apache2](docs/install_apache2_wsgi.md)
- [Installation as wsgi-script running on NGINX](docs/install_nginx_wsgi.md)

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of
conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay
in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details
