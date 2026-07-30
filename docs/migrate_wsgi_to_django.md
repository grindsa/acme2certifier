<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Migrate WSGI to Django -->

# Migrate WSGI to Django

Use this guide to migrate runtime data from the WSGI SQLite backend (`acme_srv.db`) to the Django ORM backend.

## Prerequisites

- Run `acme2certifier` version **0.45 or newer**.
- Keep the **same a2c version** before and after migration.
- Plan a maintenance window (stop ACME services while exporting/importing).
- Back up configuration (`acme_srv.cfg`), database (`acme_srv.db`), and CA/runtime material before changes.

## What Is Migrated

Migrated by `a2c-wsgi2django`:

- ACME runtime entities such as accounts, orders, authorizations, challenges, certificates.
- Optional operational tables used by this deployment (`cliaccount`, `cahandler`, `housekeeping`) when present.

Not migrated:

- Django framework tables (`django_migrations`, auth/session/admin tables).
- Ephemeral runtime artifacts such as nonces (unless explicitly exported/imported by tool options).

## At a Glance Flow

1. Stop ACME writers and confirm a restorable backup exists.
1. Export WSGI SQLite data to a dump file.
1. Switch runtime to Django flavor on the same a2c version (`handler: django`, Django web entry, migrations/status fixture).
1. Import dump into Django backend.
1. Run consistency check, then restart services and verify renewal.

Run exact commands only from the channel-specific sections below.

## pip Migration (Apache/Nginx)

Typical root: `/var/www/acme2certifier`.

1. Stop apache2/nginx + uWSGI/mod_wsgi for ACME service.

1. Back up:

   - `/var/www/acme2certifier/acme_srv.cfg`
   - `/var/www/acme2certifier/acme_srv.db`
   - custom handlers/settings under deploy root

1. Export:

   ```bash
   export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
   /var/www/acme2certifier/venv/bin/a2c-wsgi2django export \
     --db /var/www/acme2certifier/acme_srv.db \
     --out /var/www/acme2certifier/dump.json
   ```

1. Switch web entry to Django:

   - Apache: deploy the packaged Django vhost example from `$SHARE/apache2/` and ensure it points to `acme2certifier.django_project.wsgi.application`
   - Nginx/uWSGI: deploy the packaged Nginx/uWSGI examples from `$SHARE/nginx/` and set uWSGI `module = acme2certifier.django_project.wsgi:application`
   - For pip installs, resolve `SHARE` from the installed package (as in install guides), for example:

   ```bash
   SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
     "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
   ```

1. Set config and migrate:

   ```bash
   export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
   sed -i 's/^handler:.*/handler: django/' /var/www/acme2certifier/acme_srv.cfg
   /var/www/acme2certifier/venv/bin/a2c-manage migrate
   /var/www/acme2certifier/venv/bin/a2c-manage loaddata status
   ```

1. Import + check:

   ```bash
   /var/www/acme2certifier/venv/bin/a2c-wsgi2django import \
     --dump /var/www/acme2certifier/dump.json --wipe
   /var/www/acme2certifier/venv/bin/a2c-wsgi2django check \
     --dump /var/www/acme2certifier/dump.json
   ```

1. Restart services, then verify:

   ```bash
   curl -sS http://127.0.0.1/directory
   ```

## DEB Migration

Typical root: `/var/www/acme2certifier`.

1. Stop services and back up cfg/db/runtime files.

1. Export:

   ```bash
   export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
   a2c-wsgi2django export \
     --db /var/www/acme2certifier/acme_srv.db \
     --out /var/www/acme2certifier/dump.json
   ```

1. Switch deployment mode to Django:

   ```bash
   sudo ./examples/install_scripts/a2c-deb.sh \
     --deb ./acme2certifier_<version>-1_all.deb \
     --mode django \
     --webserver apache2
   ```

1. Ensure `/var/www/acme2certifier/acme_srv.cfg` has:

   - `[DBhandler] handler: django`
   - `*_module` keys for CA/EAB/hooks

1. Apply schema and status fixture:

   ```bash
   export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
   sudo -E a2c-manage migrate
   sudo -E a2c-manage loaddata status
   ```

1. Import + check:

   ```bash
   sudo -E a2c-wsgi2django import --dump /var/www/acme2certifier/dump.json --wipe
   sudo -E a2c-wsgi2django check --dump /var/www/acme2certifier/dump.json
   ```

1. Restart services and verify `/directory`.

## RPM Migration

Typical root: `/opt/acme2certifier`.

1. Stop services and back up cfg/db/runtime files.

1. Export:

   ```bash
   export ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
   export PYTHONPATH=/opt/acme2certifier
   a2c-wsgi2django export \
     --db /opt/acme2certifier/acme_srv.db \
     --out /opt/acme2certifier/dump.json
   ```

1. Switch deployment mode to Django:

   ```bash
   sudo ./examples/install_scripts/a2c-rpm.sh \
     --rpm ./acme2certifier-<version>-1.0.noarch.rpm \
     --mode django
   ```

1. Ensure `/opt/acme2certifier/acme_srv.cfg` has:

   - `[DBhandler] handler: django`
   - `*_module` keys for CA/EAB/hooks

1. Apply schema and status fixture:

   ```bash
   export ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
   export PYTHONPATH=/opt/acme2certifier
   sudo -E a2c-manage migrate
   sudo -E a2c-manage loaddata status
   ```

1. Import + check:

   ```bash
   sudo -E a2c-wsgi2django import --dump /opt/acme2certifier/dump.json --wipe
   sudo -E a2c-wsgi2django check --dump /opt/acme2certifier/dump.json
   ```

1. Restart services and verify `/directory`.

## Docker Migration

Use matching web stack tags; do not switch only `handler:` in cfg.

1. Stop/quiet writers and back up the full mounted volume.

1. Export from current `*-wsgi` runtime:

   ```bash
   docker compose exec <service> a2c-wsgi2django export \
     --db /var/www/acme2certifier/volume/acme_srv.db \
     --out /var/www/acme2certifier/volume/dump.json
   ```

1. Update image tag from `*-wsgi` to matching `*-django` variant.

1. In volume config:

   - set `volume/acme_srv.cfg` to `[DBhandler] handler: django`
   - ensure `volume/settings.py` references `acme2certifier.django_app.apps.AcmeSrvConfig`

1. Recreate container and run Django schema setup if needed:

   ```bash
   docker compose pull
   docker compose up -d --force-recreate
   docker compose exec <service> a2c-manage migrate
   docker compose exec <service> a2c-manage loaddata status
   ```

1. Import + check:

   ```bash
   docker compose exec <service> a2c-wsgi2django import \
     --dump /var/www/acme2certifier/volume/dump.json --wipe
   docker compose exec <service> a2c-wsgi2django check \
     --dump /var/www/acme2certifier/volume/dump.json
   ```

1. Verify endpoint:

   ```bash
   curl -sS http://127.0.0.1:<host-port>/directory
   ```

For Docker stack background and image/tag behavior, see [Containerized installation](install_docker.md).

## Post-Migration Cleanup

After successful migration and at least one confirmed renewal cycle:

1. Keep `acme_srv.cfg` (required runtime config). Do not delete it.
1. Archive migration artifacts (`dump.json`, migration logs) into your ops backup location.
1. Move old WSGI SQLite DB out of active path (for example `acme_srv.db.pre-django`) or keep it in backup storage only.
1. Remove obsolete WSGI-only web entry files/config snippets from active sites config (keep a copy in backup/history).
1. Update operational runbooks and alerts to treat Django (`handler: django`) as the production baseline (health checks, restore steps, and log triage).

## Rollback

If migration fails:

1. Stop current services/containers.
1. Restore backed-up `acme_srv.cfg`, database, and runtime material.
1. Restore previous WSGI deployment flavor:
   - pip/deb/rpm: WSGI web entry + `[DBhandler] handler: wsgi`
   - docker: previous `*-wsgi` image tag plus original volume content
1. Start services and verify `/directory`.

## Troubleshooting

- Safety flags:
  - `wipe` requires `--yes`.
  - `import --dry-run` validates and prints counts without writing.
  - `-v` / `--verbose` logs export/import/check progress to stderr.
- `Value too long` during import:
  - inspect overlong values in source data (common: account contact, housekeeping values), fix source or prune value, export again.
- Import refused because DB is not empty:
  - re-run with `--wipe` (or manually clear target data if policy requires).
- Django startup/migration errors:
  - verify Django WSGI module path and settings (`INSTALLED_APPS`, `ROOT_URLCONF`, `WSGI_APPLICATION`).
- Docker runs wrong backend after migration:
  - ensure both image tag (`*-django`) and cfg (`handler: django`) match.
