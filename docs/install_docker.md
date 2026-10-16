<!-- markdownlint-disable  MD013 -->

<!-- wiki-title: Containerized installation -->
<!-- wiki-category: Installation -->

# Containerized installation using apache2/nginx as webserver and wsgi or django

See [acme2certifier in Docker](../examples/Docker/README.md).

Images are Ubuntu **26.04**-based and install from a prebuilt `.deb`. Each webserver image (`apache2`, `nginx`) includes both WSGI and Django stacks; the DB backend is selected at runtime. Upgrading or rolling back: see [Upgrading — Docker WSGI vs Django](upgrading.md#docker-wsgi-vs-django-and-rollback).

Security-disable options in `acme_srv.cfg` need `ACME2CERTIFIER_I_KNOW_THE_RISK` in the container environment — see [Security break-glass gate](security_gate.md).

Security-disable options in `acme_srv.cfg` need `ACME2CERTIFIER_I_KNOW_THE_RISK` in the container environment — see [Security break-glass gate](security_gate.md).

## Image tag vs `[DBhandler] handler:`

One Dockerfile per webserver (`examples/Docker/{apache2,nginx}/Dockerfile`).

**Hub tags**

| Tag | Meaning |
| --- | --- |
| `apache2` / `nginx` (and `VERSION-apache2` / `VERSION-nginx`) | Primary images (default handler `wsgi`). `latest` → `apache2`. |
| `*-wsgi` | Same digest as the primary webserver tag (compat alias). |
| `*-django` | Thin alias (`FROM` primary + `ENV ACME_SRV_DB_HANDLER=django`) so pull-and-run without cfg still boots Django. |

For the time being we will still publish the legacy `*-wsgi` / `*-django` tags for compatibility reasons.

They control different things:

- **Image tag (webserver)** — Apache vs nginx (how HTTP reaches Python).
- **`[DBhandler] handler:` / `ACME_SRV_DB_HANDLER`** — which database backend the ACME core uses (`wsgi` = SQLite file, `django` = Django ORM). The entrypoint also retargets the web entry (Apache site conf or uWSGI module) and bootstrap for that handler.

Precedence: `acme_srv.cfg` → `ACME_SRV_DB_HANDLER` → default `wsgi`.

**Switching handlers** requires a container restart (Apache/uWSGI already loaded). WSGI → Django data migration remains a real migration ([Migrate WSGI to Django](migrate_wsgi_to_django.md)); consolidation only removes the image barrier.

**Django schema files:** migration modules ship in the image/package. The volume needs `settings.py` (and cfg/DB/CA material), not a local `migrations/` tree. Stale `volume/migrations` from older images is ignored — see [Upgrading — Docker (Django)](upgrading.md#docker-django).
