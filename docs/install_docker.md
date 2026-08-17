<!-- markdownlint-disable  MD013 -->

<!-- wiki-title: Containerized installation -->
<!-- wiki-category: Installation -->

# Containerized installation using apache2/nginx as webserver and wsgi or django

See [acme2certifier in Docker](../examples/Docker/README.md).

Images are Ubuntu **26.04**-based and install from a prebuilt `.deb`. Variants differ by web stack (`*-wsgi` vs `*-django`, apache2/nginx). Upgrading or rolling back tags: see [Upgrading — Docker WSGI vs Django](upgrading.md#docker-wsgi-vs-django-and-rollback).

## Image tag vs `[DBhandler] handler:`

Docker images are tagged by web stack (`*-wsgi` vs `*-django`). Each image also sets `ACME_SRV_DB_HANDLER`. That can look like the same choice twice.

They control different things:

- **Image tag** — Apache/nginx and uWSGI/mod_wsgi wiring (how HTTP reaches Python).
- **`[DBhandler] handler:`** — which database backend the ACME core uses (`wsgi` = SQLite file, `django` = Django ORM).

Precedence: `acme_srv.cfg` → `ACME_SRV_DB_HANDLER` → default `wsgi`. The entrypoint and `a2c-manage` read the resolved value (for example to bootstrap Django settings and migrations).

**Today:** keep tag and `handler:` aligned. Changing only cfg does not switch the baked-in web entry. On a matching image you may omit `handler:` and rely on the image default.

**Why cfg at all:** one setting works the same on pip, DEB, RPM, and Docker — the same surface as `handler_module` for CA handlers. The long-term goal is a single image where switching WSGI ↔ Django is a cfg and migration change, not a retag. Separate tags remain until that procedure is in place.
