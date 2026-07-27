<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Package layout -->

# Package layout

Architecture for the pip-installable `acme2certifier` package.

## Main design principles

- Single import root: `acme2certifier.*`
- Runtime code in the package; deployment/config samples in `examples/`
- Module-based plugin loading (`*_module`); file-based keys deprecated until 0.48
- Clean wheel/sdist install (DEB, RPM, Docker, pip)

## Layout

```text
acme2certifier/
├── pyproject.toml
├── docs/
├── examples/                    # docker, apache2, nginx, install scripts, django settings template
├── acme2certifier/
│   ├── acme_srv/                # ACME server core
│   ├── cahandlers/              # CA handler implementations
│   ├── eabhandlers/
│   ├── hookhandlers/
│   ├── dbhandlers/              # wsgi / django DB backends
│   ├── django_app/              # Django app (label: acme_srv)
│   ├── django_project/          # Django project shell
│   ├── tools/                   # python3 -m acme2certifier.tools.<name>
│   └── share/                   # cfg samples, webserver configs, skeletons
└── tests/
```

## Namespaces

| Area | Package |
| --- | --- |
| ACME core | `acme2certifier.acme_srv` |
| CA handlers | `acme2certifier.cahandlers` |
| EAB handlers | `acme2certifier.eabhandlers` |
| Hooks | `acme2certifier.hookhandlers` |
| DB backends | `acme2certifier.dbhandlers` |
| Django app | `acme2certifier.django_app` |
| Django project | `acme2certifier.django_project` |
| Tools | `acme2certifier.tools` |
| Skeletons / share data | `acme2certifier/share/` |

## Plugin config

Preferred:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler

[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.file_handler

[Hooks]
hooks_module: acme2certifier.hookhandlers.email_hooks

[DBhandler]
handler: wsgi   # or django
```

Deprecated until **0.48**: `handler_file`, `eab_handler_file`, `hooks_file`, and the default `acme_srv.ca_handler` fallback.

If both `*_module` and `*_file` are set, `*_module` wins.

## Install roots

| Channel | Code root | Config |
| --- | --- | --- |
| pip / venv | site-packages (`acme2certifier`) | `/var/www/acme2certifier/acme_srv.cfg` (typical) |
| DEB | `/var/www/acme2certifier` | `/var/www/acme2certifier/acme_srv.cfg` |
| RPM | `/opt/acme2certifier` | `/opt/acme2certifier/acme_srv.cfg` |
| Docker | image + volume | `/var/www/acme2certifier/volume/acme_srv.cfg` |

## Related

- [Upgrading](../upgrading.md)
- [acme_srv.cfg](../acme_srv.md)
